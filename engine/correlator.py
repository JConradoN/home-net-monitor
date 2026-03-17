"""
engine/correlator.py — Motor de detecção e correlação de gargalos de rede.

Implementa todas as regras de diagnóstico definidas no PRD seção 4.1-C,
correlacionando métricas de múltiplos coletores (ICMP, DNS, SNMP) para
produzir alertas com severidade e contexto acionável.

Tabela de regras (PRD seção 4.1-C):
  ┌──────────────────────────────────────────────────────┬─────────────────────────────┬──────────┐
  │ Condição Detectada                                   │ Diagnóstico                 │ Severity │
  ├──────────────────────────────────────────────────────┼─────────────────────────────┼──────────┤
  │ Ping Gateway baixo + Ping Internet alto              │ Problema na operadora        │ Critical │
  │ Ping Gateway alto via Wi-Fi                          │ Interferência / saturação    │ Warning  │
  │ DNS interno lento + DNS externo rápido               │ Roteador sobrecarregado      │ Warning  │
  │ DNS interno rápido + DNS externo lento               │ Problema de rota operadora   │ Info     │
  │ CPU Mikrotik > 80% por > 60s                         │ NAT/Firewall sobrecarregado  │ Critical │
  │ Channel Utilization > 70%                            │ Wi-Fi saturado               │ Warning  │
  │ Retries > 15%                                        │ Interferência de RF          │ Warning  │
  │ Latência alta sob carga                              │ Bufferbloat                  │ Warning  │
  │ Gateway sem resposta > 30s                           │ Queda de conexão             │ Critical │
  │ Noise Floor > -75 dBm                                │ Ruído excessivo              │ Info     │
  └──────────────────────────────────────────────────────┴─────────────────────────────┴──────────┘
"""

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)

# Thresholds ajustáveis conforme PRD seção 10 (Riscos — Falsos positivos)
THRESHOLD_GW_LATENCY_HIGH = 50.0        # ms — gateway "alto"
THRESHOLD_INTERNET_LATENCY_HIGH = 150.0 # ms — internet "alto"
THRESHOLD_DNS_SLOW = 100.0              # ms — DNS lento
THRESHOLD_DNS_FAST = 30.0              # ms — DNS rápido
THRESHOLD_CPU_CRITICAL = 80.0          # %
THRESHOLD_CPU_DURATION = 60.0          # segundos
THRESHOLD_CHANNEL_UTIL = 70.0          # %
THRESHOLD_RETRIES = 15.0               # %
THRESHOLD_NOISE_FLOOR = -75.0          # dBm
THRESHOLD_BUFFERBLOAT_DELTA = 30.0     # ms — delta que indica bufferbloat
THRESHOLD_OUTAGE_DURATION = 30.0       # segundos sem resposta


class AlertSeverity(str, Enum):
    """Severidade de alertas conforme PRD."""
    INFO = "Info"
    WARNING = "Warning"
    CRITICAL = "Critical"


@dataclass
class Alert:
    """
    Representa um alerta gerado pelo motor de correlação.

    Cada alerta tem severidade, diagnóstico legível pelo usuário (mesmo
    sem conhecimento técnico) e código interno para automação.
    """

    code: str                              # ex: "ISP_PROBLEM", "WIFI_SATURATION"
    severity: AlertSeverity
    title: str                             # Título curto para o dashboard
    description: str                       # Descrição técnica detalhada
    user_message: str                      # Mensagem em linguagem simples
    timestamp: float = field(default_factory=time.time)
    context: dict = field(default_factory=dict)   # Dados brutos que originaram o alerta
    active: bool = True

    @property
    def severity_color(self) -> str:
        """Cor CSS para o dashboard."""
        return {
            AlertSeverity.INFO: "blue",
            AlertSeverity.WARNING: "yellow",
            AlertSeverity.CRITICAL: "red",
        }.get(self.severity, "gray")


@dataclass
class CorrelationSnapshot:
    """
    Snapshot das métricas de todos os coletores em um instante.
    Passado ao Correlator.analyze() para gerar alertas.
    """

    timestamp: float = field(default_factory=time.time)

    # ICMP
    gateway_rtt_ms: Optional[float] = None
    gateway_loss: Optional[float] = None          # 0.0–1.0
    gateway_unreachable_since: Optional[float] = None  # timestamp
    internet_rtt_ms: Optional[float] = None
    internet_loss: Optional[float] = None
    is_wifi: Optional[bool] = None                # True se medição via Wi-Fi

    # DNS
    dns_internal_ms: Optional[float] = None
    dns_external_ms: Optional[float] = None

    # SNMP
    cpu_usage: Optional[float] = None
    cpu_high_since: Optional[float] = None
    channel_utilization: Optional[float] = None
    noise_floor: Optional[float] = None
    retries_percent: Optional[float] = None

    # Bufferbloat
    bufferbloat_delta_ms: Optional[float] = None
    bufferbloat_grade: Optional[str] = None


class Correlator:
    """
    Motor de detecção de gargalos por correlação de métricas.

    Recebe um CorrelationSnapshot com dados de todos os coletores
    e aplica as regras do PRD para gerar uma lista de Alerts.

    O design é plugável: cada regra é um método _rule_* separado,
    facilitando adição de novas regras sem alterar o core.

    Uso:
        correlator = Correlator()
        alerts = correlator.analyze(snapshot)
    """

    def __init__(
        self,
        thresholds: dict = None,
        event_bus=None,
    ):
        """
        Args:
            thresholds: Dicionário opcional para sobrescrever thresholds padrão.
            event_bus:  Bus de eventos para publicar alertas em tempo real (SSE).
        """
        self.thresholds = thresholds or {}
        self.event_bus = event_bus
        self._active_alerts: dict[str, Alert] = {}  # {code: Alert}
        self._alert_history: list[Alert] = []

    def _get_threshold(self, name: str, default: float) -> float:
        """Retorna threshold personalizado ou o padrão."""
        return self.thresholds.get(name, default)

    def analyze(self, snapshot: CorrelationSnapshot) -> list[Alert]:
        """
        Analisa um snapshot de métricas e aplica todas as regras de detecção.

        Args:
            snapshot: Dados coletados em um instante pelos coletores.

        Returns:
            Lista de alertas ativos gerados pelas regras.
        """
        alerts = []

        rules = [
            self._rule_outage,
            self._rule_isp_problem,
            self._rule_wifi_high_latency,
            self._rule_dns_router_overload,
            self._rule_dns_isp_route,
            self._rule_cpu_critical,
            self._rule_channel_utilization,
            self._rule_rf_interference,
            self._rule_bufferbloat,
            self._rule_noise_floor,
        ]

        for rule in rules:
            alert = rule(snapshot)
            if alert:
                alerts.append(alert)
                self._register_alert(alert)

        # Resolve alertas que não foram ativados neste ciclo
        self._resolve_inactive_alerts([a.code for a in alerts])

        return alerts

    def _register_alert(self, alert: Alert) -> None:
        """Registra ou atualiza alerta e publica no event bus."""
        is_new = alert.code not in self._active_alerts
        self._active_alerts[alert.code] = alert
        if is_new:
            self._alert_history.append(alert)
            if self.event_bus:
                # TODO: self.event_bus.publish("alert", alert)
                pass
            logger.warning("[%s] %s — %s", alert.severity.value, alert.title, alert.description)

    def _resolve_inactive_alerts(self, active_codes: list[str]) -> None:
        """Marca como resolvidos os alertas que não foram ativados neste ciclo."""
        for code in list(self._active_alerts.keys()):
            if code not in active_codes:
                resolved = self._active_alerts.pop(code)
                resolved.active = False
                logger.info("Alerta resolvido: %s", code)

    # ─── Regras de Detecção ─────────────────────────────────────────────────

    def _rule_outage(self, s: CorrelationSnapshot) -> Optional[Alert]:
        """
        Regra: Gateway sem resposta por mais de 30 segundos.
        Diagnóstico: Queda de conexão | Critical.
        """
        if s.gateway_unreachable_since is None:
            return None
        duration = time.time() - s.gateway_unreachable_since
        threshold = self._get_threshold("outage_duration", THRESHOLD_OUTAGE_DURATION)
        if duration < threshold:
            return None
        return Alert(
            code="OUTAGE",
            severity=AlertSeverity.CRITICAL,
            title="Queda de conexão detectada",
            description=f"Gateway sem resposta há {duration:.0f}s (threshold: {threshold}s)",
            user_message="Sua conexão com a internet caiu. Verifique o roteador e o cabo da operadora.",
            context={"duration_s": duration},
        )

    def _rule_isp_problem(self, s: CorrelationSnapshot) -> Optional[Alert]:
        """
        Regra: Ping gateway baixo + Ping internet alto.
        Diagnóstico: Problema na operadora | Critical.
        """
        if s.gateway_rtt_ms is None or s.internet_rtt_ms is None:
            return None
        gw_ok = s.gateway_rtt_ms < self._get_threshold("gw_latency_high", THRESHOLD_GW_LATENCY_HIGH)
        inet_high = s.internet_rtt_ms > self._get_threshold("internet_latency_high", THRESHOLD_INTERNET_LATENCY_HIGH)
        if not (gw_ok and inet_high):
            return None
        return Alert(
            code="ISP_PROBLEM",
            severity=AlertSeverity.CRITICAL,
            title="Problema na operadora",
            description=(
                f"Latência ao gateway: {s.gateway_rtt_ms:.1f}ms (OK), "
                f"internet: {s.internet_rtt_ms:.1f}ms (alta)"
            ),
            user_message="O roteador está funcionando, mas a internet da operadora está lenta ou instável.",
            context={"gateway_rtt": s.gateway_rtt_ms, "internet_rtt": s.internet_rtt_ms},
        )

    def _rule_wifi_high_latency(self, s: CorrelationSnapshot) -> Optional[Alert]:
        """
        Regra: Ping gateway alto via Wi-Fi.
        Diagnóstico: Interferência ou saturação Wi-Fi | Warning.
        """
        if s.gateway_rtt_ms is None or s.is_wifi is not True:
            return None
        threshold = self._get_threshold("gw_latency_high", THRESHOLD_GW_LATENCY_HIGH)
        if s.gateway_rtt_ms < threshold:
            return None
        return Alert(
            code="WIFI_HIGH_LATENCY",
            severity=AlertSeverity.WARNING,
            title="Latência alta no Wi-Fi",
            description=f"Latência ao gateway via Wi-Fi: {s.gateway_rtt_ms:.1f}ms (threshold: {threshold}ms)",
            user_message="O sinal Wi-Fi está lento. Tente se aproximar do roteador ou mudar de canal.",
            context={"gateway_rtt": s.gateway_rtt_ms, "is_wifi": True},
        )

    def _rule_dns_router_overload(self, s: CorrelationSnapshot) -> Optional[Alert]:
        """
        Regra: DNS interno lento + DNS externo rápido.
        Diagnóstico: Roteador da operadora sobrecarregado | Warning.
        """
        if s.dns_internal_ms is None or s.dns_external_ms is None:
            return None
        slow_threshold = self._get_threshold("dns_slow", THRESHOLD_DNS_SLOW)
        fast_threshold = self._get_threshold("dns_fast", THRESHOLD_DNS_FAST)
        if not (s.dns_internal_ms > slow_threshold and s.dns_external_ms < fast_threshold):
            return None
        return Alert(
            code="DNS_ROUTER_OVERLOAD",
            severity=AlertSeverity.WARNING,
            title="Roteador da operadora sobrecarregado",
            description=(
                f"DNS interno: {s.dns_internal_ms:.1f}ms (lento), "
                f"DNS externo: {s.dns_external_ms:.1f}ms (rápido)"
            ),
            user_message="O roteador da operadora está lento. Considere usar Cloudflare (1.1.1.1) como DNS.",
            context={"dns_internal": s.dns_internal_ms, "dns_external": s.dns_external_ms},
        )

    def _rule_dns_isp_route(self, s: CorrelationSnapshot) -> Optional[Alert]:
        """
        Regra: DNS interno rápido + DNS externo lento.
        Diagnóstico: Problema de rota da operadora | Info.
        """
        if s.dns_internal_ms is None or s.dns_external_ms is None:
            return None
        fast_threshold = self._get_threshold("dns_fast", THRESHOLD_DNS_FAST)
        slow_threshold = self._get_threshold("dns_slow", THRESHOLD_DNS_SLOW)
        if not (s.dns_internal_ms < fast_threshold and s.dns_external_ms > slow_threshold):
            return None
        return Alert(
            code="DNS_ISP_ROUTE",
            severity=AlertSeverity.INFO,
            title="Problema de rota da operadora",
            description=(
                f"DNS interno: {s.dns_internal_ms:.1f}ms (rápido), "
                f"DNS externo: {s.dns_external_ms:.1f}ms (lento)"
            ),
            user_message="A conexão com servidores externos está lenta. Pode ser um problema na rota da operadora.",
            context={"dns_internal": s.dns_internal_ms, "dns_external": s.dns_external_ms},
        )

    def _rule_cpu_critical(self, s: CorrelationSnapshot) -> Optional[Alert]:
        """
        Regra: CPU Mikrotik > 80% por mais de 60 segundos.
        Diagnóstico: NAT/Firewall sobrecarregado | Critical.
        """
        if s.cpu_usage is None or s.cpu_high_since is None:
            return None
        cpu_threshold = self._get_threshold("cpu_critical", THRESHOLD_CPU_CRITICAL)
        duration_threshold = self._get_threshold("cpu_duration", THRESHOLD_CPU_DURATION)
        duration = time.time() - s.cpu_high_since
        if s.cpu_usage < cpu_threshold or duration < duration_threshold:
            return None
        return Alert(
            code="CPU_CRITICAL",
            severity=AlertSeverity.CRITICAL,
            title="Roteador Mikrotik sobrecarregado",
            description=f"CPU em {s.cpu_usage:.1f}% há {duration:.0f}s",
            user_message="O roteador está sobrecarregado. Muitos dispositivos ou regras de firewall pesadas.",
            context={"cpu": s.cpu_usage, "duration_s": duration},
        )

    def _rule_channel_utilization(self, s: CorrelationSnapshot) -> Optional[Alert]:
        """
        Regra: Channel Utilization > 70%.
        Diagnóstico: Wi-Fi saturado | Warning.
        """
        if s.channel_utilization is None:
            return None
        threshold = self._get_threshold("channel_util", THRESHOLD_CHANNEL_UTIL)
        if s.channel_utilization <= threshold:
            return None
        return Alert(
            code="WIFI_SATURATION",
            severity=AlertSeverity.WARNING,
            title="Canal Wi-Fi saturado",
            description=f"Channel utilization: {s.channel_utilization:.1f}% (threshold: {threshold}%)",
            user_message="O canal Wi-Fi está congestionado. Tente mudar para outro canal ou para a banda 5GHz.",
            context={"channel_utilization": s.channel_utilization},
        )

    def _rule_rf_interference(self, s: CorrelationSnapshot) -> Optional[Alert]:
        """
        Regra: Retries > 15%.
        Diagnóstico: Interferência de RF | Warning.
        """
        if s.retries_percent is None:
            return None
        threshold = self._get_threshold("retries", THRESHOLD_RETRIES)
        if s.retries_percent <= threshold:
            return None
        return Alert(
            code="RF_INTERFERENCE",
            severity=AlertSeverity.WARNING,
            title="Interferência de rádio frequência",
            description=f"Retries Wi-Fi: {s.retries_percent:.1f}% (threshold: {threshold}%)",
            user_message="Há interferência no sinal Wi-Fi. Outros dispositivos ou redes podem estar causando isso.",
            context={"retries": s.retries_percent},
        )

    def _rule_bufferbloat(self, s: CorrelationSnapshot) -> Optional[Alert]:
        """
        Regra: Latência alta sob carga (bufferbloat moderado/severo).
        Diagnóstico: Bufferbloat | Warning.
        """
        if s.bufferbloat_delta_ms is None:
            return None
        threshold = self._get_threshold("bufferbloat_delta", THRESHOLD_BUFFERBLOAT_DELTA)
        if s.bufferbloat_delta_ms <= threshold:
            return None
        grade = s.bufferbloat_grade or "Moderado"
        return Alert(
            code="BUFFERBLOAT",
            severity=AlertSeverity.WARNING,
            title=f"Bufferbloat {grade}",
            description=f"Delta de latência sob carga: {s.bufferbloat_delta_ms:.1f}ms (grade: {grade})",
            user_message="A latência aumenta muito quando a rede está ocupada. Configure QoS no roteador.",
            context={"delta_ms": s.bufferbloat_delta_ms, "grade": grade},
        )

    def _rule_noise_floor(self, s: CorrelationSnapshot) -> Optional[Alert]:
        """
        Regra: Noise Floor > -75 dBm.
        Diagnóstico: Ruído excessivo | Info.
        """
        if s.noise_floor is None:
            return None
        threshold = self._get_threshold("noise_floor", THRESHOLD_NOISE_FLOOR)
        if s.noise_floor <= threshold:
            return None
        return Alert(
            code="HIGH_NOISE",
            severity=AlertSeverity.INFO,
            title="Ruído de RF elevado",
            description=f"Noise floor: {s.noise_floor:.1f} dBm (threshold: {threshold} dBm)",
            user_message="Há bastante ruído no ambiente Wi-Fi. Micro-ondas, telefones sem fio ou outros APs próximos.",
            context={"noise_floor": s.noise_floor},
        )

    # ─── Consultas ──────────────────────────────────────────────────────────

    @property
    def active_alerts(self) -> list[Alert]:
        """Retorna lista de alertas ativos ordenados por severidade."""
        order = {AlertSeverity.CRITICAL: 0, AlertSeverity.WARNING: 1, AlertSeverity.INFO: 2}
        return sorted(self._active_alerts.values(), key=lambda a: order.get(a.severity, 99))

    @property
    def alert_history(self) -> list[Alert]:
        """Retorna histórico completo de alertas."""
        return list(self._alert_history)

    def get_status(self) -> str:
        """
        Retorna status geral da rede: 'ok', 'warning' ou 'critical'.
        Usado pelo dashboard para exibir o indicador verde/amarelo/vermelho.
        """
        if any(a.severity == AlertSeverity.CRITICAL for a in self._active_alerts.values()):
            return "critical"
        if any(a.severity == AlertSeverity.WARNING for a in self._active_alerts.values()):
            return "warning"
        return "ok"
