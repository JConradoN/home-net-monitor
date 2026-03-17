"""
api/routes.py — Endpoints REST do Home Net Monitor.

Todos os endpoints são read-only (GET) com exceção do wizard SNMP.
A API é consumida pelo dashboard frontend via fetch/EventSource.

Endpoints:
  GET  /api/status              — Status geral da rede (ok/warning/critical)
  GET  /api/alerts              — Lista de alertas ativos
  GET  /api/metrics/icmp        — Últimas métricas ICMP (latência, perda)
  GET  /api/metrics/dns         — Últimas métricas DNS
  GET  /api/metrics/snmp        — Últimas métricas SNMP (CPU, tráfego, Wi-Fi)
  GET  /api/devices             — Lista de dispositivos descobertos
  GET  /api/history/outages     — Histórico de quedas (7 dias)
  GET  /api/history/latency     — Histórico de latência (24h)
  GET  /api/recommendations     — Recomendações ativas
  POST /api/wizard/snmp/test    — Testa conectividade SNMP (wizard)
  GET  /api/wizard/snmp/status  — Status do wizard SNMP
  GET  /api/bufferbloat         — Resultado do último teste de bufferbloat

Segurança: apenas localhost (127.0.0.1) — RNF06.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Estas importações serão ativas quando FastAPI for instalado
# from fastapi import APIRouter, HTTPException, Depends
# from pydantic import BaseModel

# ─── Request / Response Models ────────────────────────────────────────────────


class NetworkStatusResponse:
    """
    Resposta do endpoint GET /api/status.

    Campos:
      status:          'ok' | 'warning' | 'critical'
      active_alerts:   Número de alertas ativos
      last_updated:    Timestamp da última coleta
      gateway_rtt_ms:  Latência ao gateway em ms
      internet_rtt_ms: Latência à internet em ms
    """
    pass


class AlertResponse:
    """
    Resposta individual de alerta.

    Campos:
      code, severity, title, description, user_message, timestamp, context
    """
    pass


class ICMPMetricsResponse:
    """
    Métricas ICMP por alvo.

    Campos:
      targets: lista de {name, host, rtt_avg_ms, loss_percent, timestamp}
    """
    pass


class DNSMetricsResponse:
    """
    Métricas DNS por resolver.

    Campos:
      resolvers: lista de {name, ip, avg_latency_ms, success_rate}
      diagnosis: diagnóstico preliminar
      severity: severidade do diagnóstico
    """
    pass


class SNMPMetricsResponse:
    """
    Métricas SNMP do Mikrotik.

    Campos:
      host, cpu_usage, wan_in_bps, wan_out_bps, wifi_radios, uptime_seconds
    """
    pass


class DeviceResponse:
    """
    Dispositivo descoberto na rede.

    Campos:
      ip, mac, hostname, vendor, device_type, device_type_label,
      last_seen, first_seen
    """
    pass


class SNMPWizardTestRequest:
    """
    Payload para POST /api/wizard/snmp/test.

    Campos:
      host:      IP do equipamento a testar
      community: Community string SNMP (padrão: 'public')
      port:      Porta UDP (padrão: 161)
    """
    pass


class SNMPWizardTestResponse:
    """
    Resultado do teste de conectividade SNMP do wizard.

    Campos:
      success:    True se SNMP respondeu
      message:    Mensagem descritiva
      sysDescr:   Descrição do sistema (se disponível)
      detected_host: IP detectado (se auto-discovery)
    """
    pass


# ─── Router ───────────────────────────────────────────────────────────────────


def create_router(
    correlator=None,
    recommender=None,
    icmp_collector=None,
    dns_collector=None,
    snmp_collector=None,
    fingerprint_collector=None,
    db=None,
):
    """
    Cria e retorna o APIRouter com todos os endpoints configurados.

    Args:
        correlator:             Instância do Correlator para status e alertas.
        recommender:            Instância do Recommender para recomendações.
        icmp_collector:         Instância do ICMPCollector.
        dns_collector:          Instância do DNSCollector.
        snmp_collector:         Instância do SNMPCollector.
        fingerprint_collector:  Instância do FingerprintCollector.
        db:                     Repositório SQLite para histórico.

    Returns:
        fastapi.APIRouter configurado.

    Uso em main.py:
        router = create_router(correlator=corr, ...)
        app.include_router(router)
    """
    # TODO: Implementar com FastAPI quando dependências forem instaladas
    # from fastapi import APIRouter
    # router = APIRouter(prefix="/api")
    # ... definir rotas ...
    # return router

    logger.info("Criando API router")
    return None


class APIRoutes:
    """
    Classe que agrupa os handlers dos endpoints REST.

    Cada método corresponde a um endpoint e acessa os coletores/engine
    injetados via create_router().
    """

    def __init__(self, correlator=None, recommender=None,
                 icmp_collector=None, dns_collector=None,
                 snmp_collector=None, fingerprint_collector=None, db=None):
        self.correlator = correlator
        self.recommender = recommender
        self.icmp_collector = icmp_collector
        self.dns_collector = dns_collector
        self.snmp_collector = snmp_collector
        self.fingerprint_collector = fingerprint_collector
        self.db = db

    async def get_status(self) -> dict:
        """
        GET /api/status — Retorna status geral da rede.

        Combina o status do correlator com métricas recentes de ICMP
        para produzir um resumo rápido para o header do dashboard.

        Returns:
            {status, active_alerts, gateway_rtt_ms, internet_rtt_ms, last_updated}
        """
        status = "ok"
        active_alerts_count = 0
        gateway_rtt = None
        internet_rtt = None

        if self.correlator:
            status = self.correlator.get_status()
            active_alerts_count = len(self.correlator.active_alerts)

        if self.icmp_collector:
            results = self.icmp_collector.last_results
            gw = results.get("gateway")
            inet = results.get("cloudflare") or results.get("google_dns")
            gateway_rtt = gw.rtt_avg if gw else None
            internet_rtt = inet.rtt_avg if inet else None

        return {
            "status": status,
            "active_alerts": active_alerts_count,
            "gateway_rtt_ms": gateway_rtt,
            "internet_rtt_ms": internet_rtt,
        }

    async def get_alerts(self) -> list[dict]:
        """
        GET /api/alerts — Retorna lista de alertas ativos.

        Ordenados por severidade (Critical primeiro).
        Inclui user_message para exibição no dashboard sem modificação.
        """
        if not self.correlator:
            return []
        return [
            {
                "code": a.code,
                "severity": a.severity.value,
                "title": a.title,
                "description": a.description,
                "user_message": a.user_message,
                "timestamp": a.timestamp,
                "color": a.severity_color,
            }
            for a in self.correlator.active_alerts
        ]

    async def get_icmp_metrics(self) -> dict:
        """
        GET /api/metrics/icmp — Retorna últimas métricas ICMP por alvo.

        Inclui latência (min/avg/max) e perda de pacotes para cada alvo configurado.
        """
        if not self.icmp_collector:
            return {"targets": []}
        results = self.icmp_collector.last_results
        return {
            "targets": [
                {
                    "name": name,
                    "host": r.host,
                    "rtt_min_ms": r.rtt_min,
                    "rtt_avg_ms": r.rtt_avg,
                    "rtt_max_ms": r.rtt_max,
                    "loss_percent": r.loss_percent,
                    "reachable": r.is_reachable,
                    "timestamp": r.timestamp,
                }
                for name, r in results.items()
            ]
        }

    async def get_dns_metrics(self) -> dict:
        """
        GET /api/metrics/dns — Retorna últimas métricas DNS por resolver.

        Inclui latência média, taxa de sucesso e diagnóstico preliminar.
        """
        if not self.dns_collector or not self.dns_collector.last_result:
            return {"resolvers": []}
        result = self.dns_collector.last_result
        return {
            "resolvers": [
                {
                    "name": stats.name,
                    "ip": stats.ip,
                    "avg_latency_ms": stats.avg_latency_ms,
                    "success_rate": stats.success_rate,
                    "is_slow": stats.is_slow,
                    "is_fast": stats.is_fast,
                }
                for stats in result.resolvers.values()
            ],
            "diagnosis": result.diagnosis,
            "severity": result.severity,
        }

    async def get_snmp_metrics(self) -> dict:
        """
        GET /api/metrics/snmp — Retorna últimas métricas SNMP do Mikrotik.

        Inclui CPU, tráfego WAN, clientes Wi-Fi por rádio, noise floor, retries.
        """
        if not self.snmp_collector or not self.snmp_collector.last_result:
            return {}
        r = self.snmp_collector.last_result
        return {
            "host": r.host,
            "cpu_usage": r.cpu_usage,
            "wan_in_bps": r.wan_in_bps,
            "wan_out_bps": r.wan_out_bps,
            "wifi_radios": r.wifi_radios,
            "uptime_seconds": r.uptime_seconds,
            "timestamp": r.timestamp,
        }

    async def get_devices(self) -> list[dict]:
        """
        GET /api/devices — Retorna lista de dispositivos descobertos na rede.

        Inclui IP, MAC, hostname, fabricante e tipo classificado.
        """
        if not self.fingerprint_collector:
            return []
        return [
            {
                "ip": d.ip,
                "mac": d.mac_normalized,
                "hostname": d.hostname,
                "vendor": d.vendor,
                "device_type": d.device_type,
                "device_type_label": d.device_type_label,
                "display_name": d.display_name,
                "last_seen": d.last_seen,
                "first_seen": d.first_seen,
            }
            for d in self.fingerprint_collector.devices
        ]

    async def get_recommendations(self) -> list[dict]:
        """
        GET /api/recommendations — Retorna recomendações ativas.

        Geradas pelo Recommender com base nos alertas do Correlator.
        Cada recomendação contém passos ordenados do simples ao técnico.
        """
        if not self.correlator or not self.recommender:
            return []
        from engine.recommender import Recommender
        alerts = self.correlator.active_alerts
        recs = self.recommender.generate(alerts)
        return [
            {
                "alert_code": r.alert_code,
                "title": r.title,
                "summary": r.summary,
                "category": r.category,
                "priority": r.priority,
                "steps": [
                    {
                        "order": s.order,
                        "description": s.description,
                        "technical_detail": s.technical_detail,
                    }
                    for s in r.steps
                ],
            }
            for r in recs
        ]

    async def get_outage_history(self, days: int = 7) -> list[dict]:
        """
        GET /api/history/outages — Histórico de quedas dos últimos N dias.

        Args:
            days: Número de dias de histórico (padrão: 7).

        Returns:
            Lista de {start_timestamp, duration_seconds, recovered}.
        """
        if not self.db:
            return []
        # TODO: return await self.db.get_outages(days=days)
        return []

    async def get_latency_history(self, hours: int = 24) -> dict:
        """
        GET /api/history/latency — Série temporal de latência das últimas N horas.

        Usado para renderizar gráficos no dashboard (Chart.js).

        Args:
            hours: Número de horas de histórico (padrão: 24).

        Returns:
            {timestamps: [...], gateway: [...], internet: [...], dns_internal: [...]}
        """
        if not self.db:
            return {"timestamps": [], "gateway": [], "internet": []}
        # TODO: return await self.db.get_latency_series(hours=hours)
        return {"timestamps": [], "gateway": [], "internet": []}

    async def post_wizard_snmp_test(self, host: str, community: str = "public", port: int = 161) -> dict:
        """
        POST /api/wizard/snmp/test — Testa conectividade SNMP (Wizard SNMP).

        Usado pelo Wizard de Configuração SNMP (PRD seção 4.1-G) para
        validar que o Mikrotik está acessível e com SNMP habilitado.

        Args:
            host:      IP do equipamento a testar.
            community: Community string SNMP.
            port:      Porta UDP SNMP.

        Returns:
            {success, message, sysDescr}
        """
        from collectors.snmp import SNMPCollector
        collector = SNMPCollector(host=host, community=community, port=port)
        ok = await collector.test_connectivity()
        return {
            "success": ok,
            "message": "SNMP respondendo corretamente." if ok else "SNMP não respondeu. Verifique a configuração.",
            "host": host,
            "community": community,
        }
