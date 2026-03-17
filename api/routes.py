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
  GET  /api/events              — Stream SSE (text/event-stream)

Segurança: apenas localhost (127.0.0.1) — RNF06.
"""

import logging
import time
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

logger = logging.getLogger(__name__)


# ─── Request / Response Models ────────────────────────────────────────────────


class NetworkStatusResponse(BaseModel):
    status: str                              # 'ok' | 'warning' | 'critical'
    active_alerts: int
    gateway_rtt_ms: Optional[float] = None
    internet_rtt_ms: Optional[float] = None
    last_updated: float = 0.0


class AlertResponse(BaseModel):
    code: str
    severity: str
    title: str
    description: str
    user_message: str
    timestamp: float
    color: str
    context: dict = {}


class ICMPTargetMetrics(BaseModel):
    name: str
    host: str
    rtt_min_ms: Optional[float] = None
    rtt_avg_ms: Optional[float] = None
    rtt_max_ms: Optional[float] = None
    loss_percent: Optional[float] = None
    reachable: bool = True
    timestamp: float = 0.0


class ICMPMetricsResponse(BaseModel):
    targets: list[ICMPTargetMetrics]


class DNSResolverMetrics(BaseModel):
    name: str
    ip: str
    avg_latency_ms: Optional[float] = None
    success_rate: Optional[float] = None
    is_slow: bool = False
    is_fast: bool = False


class DNSMetricsResponse(BaseModel):
    resolvers: list[DNSResolverMetrics]
    diagnosis: Optional[str] = None
    severity: Optional[str] = None


class WifiRadioMetrics(BaseModel):
    ssid: Optional[str] = None
    band: Optional[str] = None
    clients: int = 0
    channel_utilization: Optional[float] = None
    noise_floor: Optional[float] = None
    retries_percent: Optional[float] = None


class SNMPMetricsResponse(BaseModel):
    host: str
    cpu_usage: Optional[float] = None
    wan_in_bps: Optional[float] = None
    wan_out_bps: Optional[float] = None
    wifi_radios: list[dict] = []
    uptime_seconds: Optional[float] = None
    timestamp: float = 0.0


class DeviceResponse(BaseModel):
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    device_type: str = "unknown"
    device_type_label: str = "Desconhecido"
    display_name: str = ""
    last_seen: float = 0.0
    first_seen: float = 0.0


class SNMPWizardTestRequest(BaseModel):
    host: str
    community: str = "public"
    port: int = 161


class SNMPWizardTestResponse(BaseModel):
    success: bool
    message: str
    host: str
    community: str


class RecommendationStepResponse(BaseModel):
    order: int
    description: str
    technical_detail: Optional[str] = None
    link: Optional[str] = None


class RecommendationResponse(BaseModel):
    alert_code: str
    title: str
    summary: str
    category: str
    priority: int
    steps: list[RecommendationStepResponse]


class OutageResponse(BaseModel):
    start_timestamp: float
    end_timestamp: Optional[float] = None
    duration_seconds: Optional[float] = None
    recovered: bool = False


class LatencyHistoryResponse(BaseModel):
    timestamps: list[float]
    gateway: list[Optional[float]]
    internet: list[Optional[float]]
    dns_internal: list[Optional[float]] = []


class BufferbloatResponse(BaseModel):
    baseline_rtt_ms: Optional[float] = None
    loaded_rtt_ms: Optional[float] = None
    delta_ms: Optional[float] = None
    grade: Optional[str] = None
    timestamp: float = 0.0


class WifiNeighborResponse(BaseModel):
    bssid: str
    ssid: Optional[str] = None
    frequency_mhz: Optional[float] = None
    channel: Optional[int] = None
    signal_dbm: Optional[float] = None
    band: Optional[str] = None


class WifiMetricsResponse(BaseModel):
    interface: str
    connected: bool = False
    ssid: Optional[str] = None
    bssid: Optional[str] = None
    frequency_mhz: Optional[float] = None
    band: Optional[str] = None
    signal_dbm: Optional[float] = None
    link_quality_pct: Optional[float] = None
    signal_quality_label: Optional[str] = None
    tx_power_dbm: Optional[float] = None
    noise_dbm: Optional[float] = None
    tx_bitrate_mbps: Optional[float] = None
    rx_bitrate_mbps: Optional[float] = None
    tx_retries: Optional[int] = None
    tx_failed: Optional[int] = None
    beacon_loss: Optional[int] = None
    neighbors: list[WifiNeighborResponse] = []
    timestamp: float = 0.0


# ─── Router ───────────────────────────────────────────────────────────────────


def create_router(
    correlator=None,
    recommender=None,
    icmp_collector=None,
    dns_collector=None,
    snmp_collector=None,
    fingerprint_collector=None,
    wifi_collector=None,
    db=None,
    event_bus=None,
) -> APIRouter:
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
        event_bus:              EventBus para o endpoint SSE.

    Returns:
        fastapi.APIRouter configurado com todos os endpoints.
    """
    router = APIRouter(prefix="/api", tags=["hnm"])
    routes = APIRoutes(
        correlator=correlator,
        recommender=recommender,
        icmp_collector=icmp_collector,
        dns_collector=dns_collector,
        snmp_collector=snmp_collector,
        fingerprint_collector=fingerprint_collector,
        wifi_collector=wifi_collector,
        db=db,
    )

    @router.get("/status", response_model=NetworkStatusResponse, summary="Status geral da rede")
    async def get_status():
        return await routes.get_status()

    @router.get("/alerts", response_model=list[AlertResponse], summary="Alertas ativos")
    async def get_alerts():
        return await routes.get_alerts()

    @router.get("/metrics/icmp", response_model=ICMPMetricsResponse, summary="Métricas ICMP")
    async def get_icmp_metrics():
        return await routes.get_icmp_metrics()

    @router.get("/metrics/dns", response_model=DNSMetricsResponse, summary="Métricas DNS")
    async def get_dns_metrics():
        return await routes.get_dns_metrics()

    @router.get("/metrics/snmp", response_model=Optional[SNMPMetricsResponse], summary="Métricas SNMP")
    async def get_snmp_metrics():
        result = await routes.get_snmp_metrics()
        if not result:
            return None
        return result

    @router.get("/devices", response_model=list[DeviceResponse], summary="Dispositivos descobertos")
    async def get_devices():
        return await routes.get_devices()

    @router.get(
        "/history/outages",
        response_model=list[OutageResponse],
        summary="Histórico de quedas (7 dias)",
    )
    async def get_outage_history(days: int = Query(7, ge=1, le=30)):
        return await routes.get_outage_history(days=days)

    @router.get(
        "/history/latency",
        response_model=LatencyHistoryResponse,
        summary="Série temporal de latência (24h)",
    )
    async def get_latency_history(hours: int = Query(24, ge=1, le=168)):
        return await routes.get_latency_history(hours=hours)

    @router.get(
        "/recommendations",
        response_model=list[RecommendationResponse],
        summary="Recomendações ativas",
    )
    async def get_recommendations():
        return await routes.get_recommendations()

    @router.post(
        "/wizard/snmp/test",
        response_model=SNMPWizardTestResponse,
        summary="Testar conectividade SNMP",
    )
    async def post_wizard_snmp_test(body: SNMPWizardTestRequest):
        return await routes.post_wizard_snmp_test(
            host=body.host,
            community=body.community,
            port=body.port,
        )

    @router.get(
        "/wizard/snmp/status",
        summary="Status do wizard SNMP",
    )
    async def get_wizard_snmp_status():
        if snmp_collector and snmp_collector.last_result:
            return {"configured": True, "host": snmp_collector.host}
        return {"configured": False, "host": None}

    @router.get("/bufferbloat", response_model=Optional[BufferbloatResponse], summary="Último teste de bufferbloat")
    async def get_bufferbloat():
        return await routes.get_bufferbloat()

    @router.get("/metrics/wifi", response_model=Optional[WifiMetricsResponse], summary="Métricas Wi-Fi local")
    async def get_wifi_metrics():
        return await routes.get_wifi_metrics()

    @router.get("/events", summary="Stream SSE de eventos em tempo real")
    async def sse_stream(request: Request):
        if event_bus is None:
            raise HTTPException(status_code=503, detail="EventBus não disponível")
        from api.sse import SSEHandler
        handler = SSEHandler(event_bus=event_bus, correlator=correlator)
        return StreamingResponse(
            handler.stream(request),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
                "Connection": "keep-alive",
            },
        )

    logger.info("API router criado — %d endpoints registrados", len(router.routes))
    return router


class APIRoutes:
    """
    Classe que agrupa os handlers dos endpoints REST.

    Cada método corresponde a um endpoint e acessa os coletores/engine
    injetados via create_router().
    """

    def __init__(self, correlator=None, recommender=None,
                 icmp_collector=None, dns_collector=None,
                 snmp_collector=None, fingerprint_collector=None,
                 wifi_collector=None, db=None):
        self.correlator = correlator
        self.recommender = recommender
        self.icmp_collector = icmp_collector
        self.dns_collector = dns_collector
        self.snmp_collector = snmp_collector
        self.fingerprint_collector = fingerprint_collector
        self.wifi_collector = wifi_collector
        self.db = db

    async def get_status(self) -> dict:
        """
        GET /api/status — Retorna status geral da rede.

        Combina o status do correlator com métricas recentes de ICMP
        para produzir um resumo rápido para o header do dashboard.
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
            "last_updated": time.time(),
        }

    async def get_alerts(self) -> list[dict]:
        """
        GET /api/alerts — Retorna lista de alertas ativos.

        Ordenados por severidade (Critical primeiro).
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
                "context": a.context,
            }
            for a in self.correlator.active_alerts
        ]

    async def get_icmp_metrics(self) -> dict:
        """
        GET /api/metrics/icmp — Retorna últimas métricas ICMP por alvo.
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

    async def get_snmp_metrics(self) -> Optional[dict]:
        """
        GET /api/metrics/snmp — Retorna últimas métricas SNMP do Mikrotik.
        """
        if not self.snmp_collector or not self.snmp_collector.last_result:
            return None
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
        """
        if not self.correlator or not self.recommender:
            return []
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
                        "link": s.link,
                    }
                    for s in r.steps
                ],
            }
            for r in recs
        ]

    async def get_outage_history(self, days: int = 7) -> list[dict]:
        """
        GET /api/history/outages — Histórico de quedas dos últimos N dias.
        """
        if not self.db:
            return []
        try:
            return await self.db.get_outages(days=days)
        except Exception:
            return []

    async def get_latency_history(self, hours: int = 24) -> dict:
        """
        GET /api/history/latency — Série temporal de latência das últimas N horas.
        """
        if not self.db:
            return {"timestamps": [], "gateway": [], "internet": [], "dns_internal": []}
        try:
            return await self.db.get_latency_series(hours=hours)
        except Exception:
            return {"timestamps": [], "gateway": [], "internet": [], "dns_internal": []}

    async def post_wizard_snmp_test(self, host: str, community: str = "public", port: int = 161) -> dict:
        """
        POST /api/wizard/snmp/test — Testa conectividade SNMP (Wizard SNMP).
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

    async def get_wifi_metrics(self) -> Optional[dict]:
        """
        GET /api/metrics/wifi — Retorna métricas da interface Wi-Fi local.
        """
        if not self.wifi_collector or not self.wifi_collector.last_result:
            return None
        r = self.wifi_collector.last_result
        return {
            "interface": r.interface,
            "connected": r.is_connected,
            "ssid": r.ssid,
            "bssid": r.bssid,
            "frequency_mhz": r.frequency_mhz,
            "band": r.band,
            "signal_dbm": r.signal_dbm,
            "link_quality_pct": r.link_quality_pct,
            "signal_quality_label": r.signal_quality_label,
            "tx_power_dbm": r.tx_power_dbm,
            "noise_dbm": r.noise_dbm,
            "tx_bitrate_mbps": r.tx_bitrate_mbps,
            "rx_bitrate_mbps": r.rx_bitrate_mbps,
            "tx_retries": r.tx_retries,
            "tx_failed": r.tx_failed,
            "beacon_loss": r.beacon_loss,
            "neighbors": [
                {
                    "bssid": n.bssid,
                    "ssid": n.ssid,
                    "frequency_mhz": n.frequency_mhz,
                    "channel": n.channel,
                    "signal_dbm": n.signal_dbm,
                    "band": n.band,
                }
                for n in r.neighbors
            ],
            "timestamp": r.timestamp,
        }

    async def get_bufferbloat(self) -> Optional[dict]:
        """
        GET /api/bufferbloat — Resultado do último teste de bufferbloat.
        """
        if not self.icmp_collector:
            return None
        result = getattr(self.icmp_collector, "last_bufferbloat", None)
        if result is None:
            return None
        return {
            "baseline_rtt_ms": result.baseline_rtt,
            "loaded_rtt_ms": result.loaded_rtt,
            "delta_ms": result.delta_ms,
            "grade": result.grade,
            "timestamp": getattr(result, "timestamp", time.time()),
        }
