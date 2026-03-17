"""
engine/recommender.py — Motor de recomendações acionáveis.

Baseado nos alertas gerados pelo Correlator, produz recomendações
práticas em linguagem simples com instruções técnicas opcionais.

Áreas de recomendação (PRD seção 4.1-E):
  - Mikrotik: Queue, NAT, Firewall
  - Mesh Wi-Fi: canal, posicionamento, backhaul
  - DNS: Cloudflare / Google
  - Operadora: documentação de quedas
  - Interferência Wi-Fi: canal e potência
"""

import logging
from dataclasses import dataclass, field
from typing import Optional

from .correlator import Alert, AlertSeverity

logger = logging.getLogger(__name__)


def _fmt(val, spec: str = ".1f") -> str:
    """Formata um valor numérico ou retorna '?' se não disponível."""
    if isinstance(val, (int, float)):
        return format(val, spec)
    return "?"


# Nível de detalhe da recomendação
DETAIL_SIMPLE = "simple"    # Linguagem leiga
DETAIL_TECHNICAL = "technical"  # Instruções técnicas (Mikrotik, etc.)


@dataclass
class RecommendationStep:
    """Passo de uma recomendação."""
    order: int
    description: str                    # Descrição em linguagem simples
    technical_detail: Optional[str] = None   # Detalhe técnico (ex: comando RouterOS)
    link: Optional[str] = None          # Link para documentação offline


@dataclass
class Recommendation:
    """
    Recomendação gerada para um alerta específico.

    Estruturada em passos ordenados para guiar o usuário,
    do simples ao técnico conforme seu perfil (PRD seção 3.2).
    """

    alert_code: str
    title: str
    summary: str                         # Resumo em 1-2 frases
    steps: list[RecommendationStep] = field(default_factory=list)
    category: str = "geral"              # mikrotik / wifi / dns / isp / interference
    priority: int = 0                    # Maior = mais urgente

    @property
    def has_technical_steps(self) -> bool:
        return any(s.technical_detail for s in self.steps)


class Recommender:
    """
    Gerador de recomendações baseado em alertas do Correlator.

    Mapeia cada código de alerta para uma função geradora de recomendação.
    O design é extensível: novos alertas = novo método _rec_*.

    Uso:
        recommender = Recommender()
        recommendations = recommender.generate(alerts)
    """

    def __init__(self):
        self._registry: dict = {
            "OUTAGE": self._rec_outage,
            "ISP_PROBLEM": self._rec_isp_problem,
            "WIFI_HIGH_LATENCY": self._rec_wifi_latency,
            "DNS_ROUTER_OVERLOAD": self._rec_dns_router_overload,
            "DNS_ISP_ROUTE": self._rec_dns_isp_route,
            "CPU_CRITICAL": self._rec_cpu_critical,
            "WIFI_SATURATION": self._rec_wifi_saturation,
            "RF_INTERFERENCE": self._rec_rf_interference,
            "BUFFERBLOAT": self._rec_bufferbloat,
            "HIGH_NOISE": self._rec_high_noise,
        }

    def generate(self, alerts: list[Alert]) -> list[Recommendation]:
        """
        Gera recomendações para uma lista de alertas.

        Args:
            alerts: Lista de alertas do Correlator.

        Returns:
            Lista de Recommendation ordenadas por prioridade.
        """
        recommendations = []
        for alert in alerts:
            generator = self._registry.get(alert.code)
            if generator:
                rec = generator(alert)
                if rec:
                    recommendations.append(rec)
            else:
                logger.debug("Sem recomendação cadastrada para alerta: %s", alert.code)

        recommendations.sort(key=lambda r: r.priority, reverse=True)
        return recommendations

    # ─── Geradores de Recomendação ──────────────────────────────────────────

    def _rec_outage(self, alert: Alert) -> Recommendation:
        """Recomendações para queda de conexão."""
        duration = alert.context.get("duration_s", 0)
        return Recommendation(
            alert_code="OUTAGE",
            title="Restaurar conexão com a internet",
            summary=f"Sua internet caiu há {duration:.0f} segundos. Siga os passos abaixo para diagnosticar.",
            priority=100,
            category="isp",
            steps=[
                RecommendationStep(1, "Verifique se as luzes do roteador da operadora estão normais."),
                RecommendationStep(2, "Tente desligar e ligar o roteador da operadora (aguarde 30s)."),
                RecommendationStep(3, "Verifique o cabo de fibra — não deve estar dobrado ou prensado."),
                RecommendationStep(4, "Se não resolver, ligue para o suporte da operadora e informe o horário da queda."),
                RecommendationStep(
                    5,
                    "Se você usa Mikrotik, verifique a interface WAN.",
                    technical_detail="/interface print\n/interface monitor-traffic ether1",
                ),
            ],
        )

    def _rec_isp_problem(self, alert: Alert) -> Recommendation:
        """Recomendações para problema detectado na operadora."""
        gw_rtt = alert.context.get("gateway_rtt", "?")
        inet_rtt = alert.context.get("internet_rtt", "?")
        return Recommendation(
            alert_code="ISP_PROBLEM",
            title="Problema na operadora",
            summary=(
                f"O roteador está OK (latência: {_fmt(gw_rtt)}ms), "
                f"mas a internet está lenta ({_fmt(inet_rtt)}ms). "
                "O problema está na operadora, não no seu equipamento."
            ),
            priority=90,
            category="isp",
            steps=[
                RecommendationStep(1, "Registre o horário e a duração do problema para reclamação na operadora."),
                RecommendationStep(2, "Verifique status da operadora nas redes sociais (Twitter/X)."),
                RecommendationStep(3, "Se o problema persistir, abra um chamado na operadora com os dados de latência."),
                RecommendationStep(
                    4,
                    "Verifique logs de conectividade no Mikrotik.",
                    technical_detail="/log print where topics~\"interface\"\n/ping 8.8.8.8 count=10",
                ),
            ],
        )

    def _rec_wifi_latency(self, alert: Alert) -> Recommendation:
        """Recomendações para latência alta no Wi-Fi."""
        return Recommendation(
            alert_code="WIFI_HIGH_LATENCY",
            title="Melhorar sinal Wi-Fi",
            summary="O sinal Wi-Fi está com alta latência. Pode ser distância, obstáculos ou interferência.",
            priority=60,
            category="wifi",
            steps=[
                RecommendationStep(1, "Aproxime o dispositivo do roteador ou access point."),
                RecommendationStep(2, "Evite obstáculos físicos (paredes de concreto, móveis de metal)."),
                RecommendationStep(3, "Se você tem rede mesh (Twibi, Deco), verifique se o satélite está bem posicionado."),
                RecommendationStep(4, "Prefira a banda 5GHz — é mais rápida a curta distância."),
                RecommendationStep(
                    5,
                    "No Mikrotik, verifique a força do sinal dos clientes conectados.",
                    technical_detail="/interface wireless registration-table print",
                ),
            ],
        )

    def _rec_dns_router_overload(self, alert: Alert) -> Recommendation:
        """Recomendações para roteador da operadora sobrecarregado (DNS)."""
        dns_int = alert.context.get("dns_internal", "?")
        dns_ext = alert.context.get("dns_external", "?")
        return Recommendation(
            alert_code="DNS_ROUTER_OVERLOAD",
            title="Trocar servidor DNS",
            summary=(
                f"O DNS do seu roteador está lento ({_fmt(dns_int)}ms) "
                f"enquanto o Cloudflare está rápido ({_fmt(dns_ext)}ms). "
                "Trocar o DNS vai melhorar a velocidade de abertura de sites."
            ),
            priority=50,
            category="dns",
            steps=[
                RecommendationStep(
                    1,
                    "Configure o DNS para Cloudflare (1.1.1.1) ou Google (8.8.8.8) no seu roteador.",
                ),
                RecommendationStep(
                    2,
                    "No Mikrotik, configure DNS assim:",
                    technical_detail="/ip dns set servers=1.1.1.1,8.8.8.8 allow-remote-requests=yes",
                ),
                RecommendationStep(
                    3,
                    "Em roteadores comuns, acesse o painel de administração (192.168.1.1) e procure 'DNS'.",
                ),
            ],
        )

    def _rec_dns_isp_route(self, alert: Alert) -> Recommendation:
        """Recomendações para problema de rota da operadora (DNS externo lento)."""
        return Recommendation(
            alert_code="DNS_ISP_ROUTE",
            title="Problema de roteamento da operadora",
            summary="A conexão com servidores externos está lenta. Provavelmente um problema temporário da operadora.",
            priority=30,
            category="isp",
            steps=[
                RecommendationStep(1, "Aguarde alguns minutos — problemas de rota geralmente são temporários."),
                RecommendationStep(2, "Se persistir por mais de 30 minutos, entre em contato com a operadora."),
                RecommendationStep(
                    3,
                    "Teste traceroute para identificar onde o tráfego para.",
                    technical_detail="/tool traceroute 8.8.8.8",
                ),
            ],
        )

    def _rec_cpu_critical(self, alert: Alert) -> Recommendation:
        """Recomendações para CPU crítica no Mikrotik."""
        cpu = alert.context.get("cpu", "?")
        duration = alert.context.get("duration_s", 0)
        return Recommendation(
            alert_code="CPU_CRITICAL",
            title="Reduzir carga no roteador Mikrotik",
            summary=f"CPU em {_fmt(cpu)}% há {_fmt(duration, '.0f')}s. O roteador está sobrecarregado.",
            priority=95,
            category="mikrotik",
            steps=[
                RecommendationStep(1, "Verifique quais processos estão consumindo CPU."),
                RecommendationStep(
                    2,
                    "Liste processos ativos no Mikrotik:",
                    technical_detail="/system resource print\n/tool profile",
                ),
                RecommendationStep(
                    3,
                    "Simplifique regras de firewall desnecessárias:",
                    technical_detail="/ip firewall filter print stats\n# Remova regras redundantes",
                ),
                RecommendationStep(
                    4,
                    "Configure Simple Queue para limitar tráfego e reduzir carga de NAT:",
                    technical_detail=(
                        "/queue simple add name=limit-wan max-limit=100M/100M "
                        "interface=ether1"
                    ),
                ),
                RecommendationStep(
                    5,
                    "Se usar FastTrack, verifique se está ativo:",
                    technical_detail="/ip firewall filter print where action=fasttrack-connection",
                ),
            ],
        )

    def _rec_wifi_saturation(self, alert: Alert) -> Recommendation:
        """Recomendações para saturação do canal Wi-Fi."""
        ch_util = alert.context.get("channel_utilization", "?")
        return Recommendation(
            alert_code="WIFI_SATURATION",
            title="Descongestionar canal Wi-Fi",
            summary=f"O canal Wi-Fi está em {_fmt(ch_util)}% de utilização. Muitos dispositivos ou interferentes.",
            priority=65,
            category="wifi",
            steps=[
                RecommendationStep(1, "Troque o canal Wi-Fi para um canal menos congestionado (1, 6 ou 11 na banda 2.4GHz)."),
                RecommendationStep(2, "Ative a banda 5GHz se disponível — tem muito mais canais disponíveis."),
                RecommendationStep(3, "Desconecte dispositivos que não estão em uso."),
                RecommendationStep(
                    4,
                    "No Mikrotik, altere o canal do rádio:",
                    technical_detail="/interface wireless set wlan1 channel-width=20mhz frequency=2437",
                ),
                RecommendationStep(
                    5,
                    "Em redes mesh (Deco, Twibi), certifique-se de que o backhaul usa 5GHz dedicado.",
                ),
            ],
        )

    def _rec_rf_interference(self, alert: Alert) -> Recommendation:
        """Recomendações para interferência de RF."""
        retries = alert.context.get("retries", "?")
        return Recommendation(
            alert_code="RF_INTERFERENCE",
            title="Reduzir interferência de rádio",
            summary=f"Taxa de retransmissão Wi-Fi em {_fmt(retries)}%. Há interferência no ambiente.",
            priority=55,
            category="interference",
            steps=[
                RecommendationStep(1, "Afaste micro-ondas, babás eletrônicas e telefones sem fio do roteador."),
                RecommendationStep(2, "Escaneie canais Wi-Fi vizinhos com um app como Wi-Fi Analyzer."),
                RecommendationStep(3, "Mude para um canal sem sobreposição com redes vizinhas."),
                RecommendationStep(4, "Considere usar somente 5GHz — tem menos interferentes comuns."),
                RecommendationStep(
                    5,
                    "No Mikrotik, reduza a potência de transmissão se houver APs próximos:",
                    technical_detail="/interface wireless set wlan1 tx-power=17",
                ),
            ],
        )

    def _rec_bufferbloat(self, alert: Alert) -> Recommendation:
        """Recomendações para bufferbloat."""
        grade = alert.context.get("grade", "Moderado")
        delta = alert.context.get("delta_ms", "?")
        return Recommendation(
            alert_code="BUFFERBLOAT",
            title="Corrigir Bufferbloat",
            summary=(
                f"Bufferbloat {grade} detectado (delta: {_fmt(delta)}ms). "
                "A latência aumenta muito quando a rede está carregada. "
                "Configure QoS para resolver."
            ),
            priority=70,
            category="mikrotik",
            steps=[
                RecommendationStep(
                    1,
                    "Configure Queue Tree com FQ-CoDel no Mikrotik para eliminar bufferbloat:",
                    technical_detail=(
                        "/queue type add name=fq-codel kind=fq-codel\n"
                        "/queue tree add name=WAN-Download parent=ether1 "
                        "queue=fq-codel max-limit=100M\n"
                        "/queue tree add name=WAN-Upload parent=ether1 "
                        "queue=fq-codel max-limit=20M"
                    ),
                ),
                RecommendationStep(
                    2,
                    "Configure CAKE como alternativa moderna ao FQ-CoDel "
                    "(disponível em RouterOS 7+):",
                    technical_detail=(
                        "/queue type add name=cake kind=cake\n"
                        "/queue tree add name=WAN parent=global queue=cake max-limit=100M"
                    ),
                ),
                RecommendationStep(3, "Defina o limite máximo da fila 5–10% abaixo da velocidade contratada."),
            ],
        )

    def _rec_high_noise(self, alert: Alert) -> Recommendation:
        """Recomendações para noise floor elevado."""
        noise = alert.context.get("noise_floor", "?")
        return Recommendation(
            alert_code="HIGH_NOISE",
            title="Reduzir ruído de fundo Wi-Fi",
            summary=f"Noise floor em {_fmt(noise)} dBm (normal: < -75 dBm). Muita interferência no ambiente.",
            priority=25,
            category="interference",
            steps=[
                RecommendationStep(1, "Identifique fontes de interferência: micro-ondas, monitores de bebê, lâmpadas LED baratas."),
                RecommendationStep(2, "Reposicione o access point para longe de fontes elétricas."),
                RecommendationStep(3, "Considere usar 5GHz ou 6GHz (Wi-Fi 6E) que têm menos ruído ambiente."),
                RecommendationStep(
                    4,
                    "Verifique noise floor em tempo real no Mikrotik:",
                    technical_detail="/interface wireless monitor wlan1",
                ),
            ],
        )
