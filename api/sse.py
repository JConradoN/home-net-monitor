"""
api/sse.py — Server-Sent Events para alertas em tempo real.

Implementa o canal SSE (RF13) que o frontend consome via EventSource JS.
Quando um novo alerta é gerado pelo Correlator, é publicado no EventBus
e transmitido para todos os clientes conectados instantaneamente.

Eventos emitidos:
  - alert:    Novo alerta gerado (severidade + mensagem)
  - resolve:  Alerta resolvido
  - status:   Status geral da rede atualizado (ok/warning/critical)
  - metrics:  Atualização periódica de métricas (a cada 30s)
  - ping:     Keepalive a cada 15s para manter conexão SSE ativa

Uso no frontend:
  const es = new EventSource('/api/events');
  es.addEventListener('alert', (e) => renderAlert(JSON.parse(e.data)));
  es.addEventListener('status', (e) => updateStatusBadge(JSON.parse(e.data)));
"""

import asyncio
import json
import logging
import time
from dataclasses import asdict, dataclass, field
from typing import AsyncIterator, Optional

logger = logging.getLogger(__name__)

# Intervalo de keepalive SSE (segundos)
SSE_KEEPALIVE_INTERVAL = 15.0
# Intervalo de broadcast de métricas (segundos)
SSE_METRICS_INTERVAL = 30.0


@dataclass
class SSEEvent:
    """
    Representa um evento SSE a ser enviado ao cliente.

    Formato SSE (RFC 8895):
      event: <event_type>\\n
      data: <json_payload>\\n
      id: <event_id>\\n
      \\n
    """

    event_type: str         # alert, resolve, status, metrics, ping
    data: dict              # Payload serializado como JSON
    event_id: Optional[str] = None
    retry: Optional[int] = None    # ms — retry automático do cliente

    def to_sse_string(self) -> str:
        """
        Serializa o evento no formato text/event-stream.

        Returns:
            String formatada conforme RFC 8895.
        """
        lines = []
        if self.event_id:
            lines.append(f"id: {self.event_id}")
        if self.retry:
            lines.append(f"retry: {self.retry}")
        lines.append(f"event: {self.event_type}")
        lines.append(f"data: {json.dumps(self.data, default=str)}")
        lines.append("")   # linha em branco finaliza o evento
        lines.append("")
        return "\n".join(lines)


class EventBus:
    """
    Bus de eventos assíncrono que conecta os coletores/engine ao canal SSE.

    Implementa o padrão publish-subscribe:
      - Publicadores: Correlator, coletores
      - Assinantes:   Clientes SSE conectados ao dashboard

    Thread-safety: usa asyncio.Queue internamente, seguro para uso em
    loops assíncronos single-thread (padrão FastAPI/Uvicorn).
    """

    def __init__(self, maxsize: int = 100):
        """
        Args:
            maxsize: Tamanho máximo da fila de eventos por subscriber.
                     Eventos antigos são descartados se a fila estiver cheia.
        """
        self._subscribers: list[asyncio.Queue] = []
        self._maxsize = maxsize
        self._event_counter = 0

    def subscribe(self) -> asyncio.Queue:
        """
        Registra um novo subscriber (cliente SSE conectado).

        Returns:
            asyncio.Queue que receberá os eventos publicados.
        """
        queue: asyncio.Queue = asyncio.Queue(maxsize=self._maxsize)
        self._subscribers.append(queue)
        logger.debug("Novo subscriber SSE — total: %d", len(self._subscribers))
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        """
        Remove um subscriber desconectado.

        Args:
            queue: Queue retornada por subscribe().
        """
        try:
            self._subscribers.remove(queue)
            logger.debug("Subscriber SSE removido — restantes: %d", len(self._subscribers))
        except ValueError:
            pass

    def publish(self, event_type: str, data: dict) -> None:
        """
        Publica um evento para todos os subscribers.

        Eventos em filas cheias são descartados (drop oldest não implementado
        por simplicidade — filas grandes indicam clientes lentos).

        Args:
            event_type: Tipo do evento ('alert', 'status', 'metrics', etc.).
            data:       Payload do evento como dicionário.
        """
        self._event_counter += 1
        event = SSEEvent(
            event_type=event_type,
            data=data,
            event_id=str(self._event_counter),
        )
        dead = []
        for queue in self._subscribers:
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                logger.warning("Queue SSE cheia — evento descartado para um subscriber")
                dead.append(queue)

        # Remove subscribers com filas sempre cheias (cliente parado)
        for q in dead:
            self.unsubscribe(q)

    def publish_alert(self, alert) -> None:
        """
        Atalho para publicar um alerta do Correlator.

        Args:
            alert: Instância de engine.correlator.Alert.
        """
        self.publish("alert", {
            "code": alert.code,
            "severity": alert.severity.value,
            "title": alert.title,
            "user_message": alert.user_message,
            "timestamp": alert.timestamp,
            "color": alert.severity_color,
        })

    def publish_status(self, status: str, active_alerts: int) -> None:
        """
        Publica atualização de status geral da rede.

        Args:
            status:        'ok' | 'warning' | 'critical'
            active_alerts: Número de alertas ativos.
        """
        self.publish("status", {
            "status": status,
            "active_alerts": active_alerts,
            "timestamp": time.time(),
        })

    @property
    def subscriber_count(self) -> int:
        """Número de clientes SSE conectados."""
        return len(self._subscribers)


class SSEHandler:
    """
    Handler que gera o stream SSE para um único cliente conectado.

    Usado pelo endpoint FastAPI como gerador assíncrono.

    Uso:
        @router.get("/api/events")
        async def events(request: Request):
            handler = SSEHandler(event_bus, correlator)
            return StreamingResponse(
                handler.stream(request),
                media_type="text/event-stream",
                headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
            )
    """

    def __init__(self, event_bus: EventBus, correlator=None):
        """
        Args:
            event_bus:  EventBus compartilhado.
            correlator: Correlator para enviar estado inicial ao conectar.
        """
        self.event_bus = event_bus
        self.correlator = correlator

    async def stream(self, request=None) -> AsyncIterator[str]:
        """
        Gerador assíncrono que produz eventos SSE para o cliente.

        Ao conectar, envia estado inicial (alertas ativos + status).
        Em seguida, escuta a queue de eventos e envia conforme chegam.
        Envia keepalive ping a cada SSE_KEEPALIVE_INTERVAL segundos.

        Args:
            request: Request FastAPI (usado para detectar desconexão).

        Yields:
            Strings no formato text/event-stream.
        """
        queue = self.event_bus.subscribe()

        try:
            # Estado inicial ao conectar
            yield from self._initial_state()

            last_keepalive = time.time()

            while True:
                # Verifica desconexão do cliente
                if request and await request.is_disconnected():
                    break

                try:
                    # Aguarda próximo evento com timeout para keepalive
                    event = await asyncio.wait_for(
                        queue.get(), timeout=SSE_KEEPALIVE_INTERVAL
                    )
                    yield event.to_sse_string()
                except asyncio.TimeoutError:
                    # Envia ping de keepalive
                    now = time.time()
                    if now - last_keepalive >= SSE_KEEPALIVE_INTERVAL:
                        ping = SSEEvent(
                            event_type="ping",
                            data={"timestamp": now},
                        )
                        yield ping.to_sse_string()
                        last_keepalive = now

        except asyncio.CancelledError:
            logger.debug("Stream SSE cancelado.")
        finally:
            self.event_bus.unsubscribe(queue)

    def _initial_state(self):
        """
        Gera eventos de estado inicial ao cliente recém-conectado.

        Envia status atual + alertas ativos para que o dashboard
        mostre o estado correto sem esperar o próximo ciclo de coleta.

        Yields:
            Strings SSE com status e alertas.
        """
        if self.correlator:
            # Status geral
            status_event = SSEEvent(
                event_type="status",
                data={
                    "status": self.correlator.get_status(),
                    "active_alerts": len(self.correlator.active_alerts),
                    "timestamp": time.time(),
                },
            )
            yield status_event.to_sse_string()

            # Alertas ativos
            for alert in self.correlator.active_alerts:
                alert_event = SSEEvent(
                    event_type="alert",
                    data={
                        "code": alert.code,
                        "severity": alert.severity.value,
                        "title": alert.title,
                        "user_message": alert.user_message,
                        "timestamp": alert.timestamp,
                        "color": alert.severity_color,
                    },
                )
                yield alert_event.to_sse_string()


class MetricsBroadcaster:
    """
    Task assíncrona que publica métricas periódicas no EventBus.

    Coleta dados dos coletores e publica no canal SSE a cada
    SSE_METRICS_INTERVAL segundos para manter os gráficos atualizados.
    """

    def __init__(
        self,
        event_bus: EventBus,
        icmp_collector=None,
        snmp_collector=None,
        dns_collector=None,
        interval: float = SSE_METRICS_INTERVAL,
    ):
        self.event_bus = event_bus
        self.icmp_collector = icmp_collector
        self.snmp_collector = snmp_collector
        self.dns_collector = dns_collector
        self.interval = interval
        self._running = False

    async def start(self) -> None:
        """Inicia o loop de broadcast periódico de métricas."""
        self._running = True
        logger.info("MetricsBroadcaster iniciado — intervalo: %ss", self.interval)
        while self._running:
            await asyncio.sleep(self.interval)
            try:
                await self._broadcast()
            except Exception as exc:
                logger.error("Erro no broadcast de métricas: %s", exc)

    async def stop(self) -> None:
        """Para o broadcast."""
        self._running = False

    async def _broadcast(self) -> None:
        """
        Coleta métricas recentes e publica no EventBus.

        Agrega dados de todos os coletores disponíveis em um único
        payload de métricas para minimizar mensagens SSE.
        """
        metrics = {"timestamp": time.time()}

        if self.icmp_collector:
            results = self.icmp_collector.last_results
            metrics["icmp"] = {
                name: {
                    "rtt_avg_ms": r.rtt_avg,
                    "loss_percent": r.loss_percent,
                    "reachable": r.is_reachable,
                }
                for name, r in results.items()
            }

        if self.snmp_collector and self.snmp_collector.last_result:
            r = self.snmp_collector.last_result
            metrics["snmp"] = {
                "cpu_usage": r.cpu_usage,
                "wan_in_bps": r.wan_in_bps,
                "wan_out_bps": r.wan_out_bps,
            }

        if self.dns_collector and self.dns_collector.last_result:
            result = self.dns_collector.last_result
            metrics["dns"] = {
                name: {
                    "avg_latency_ms": stats.avg_latency_ms,
                    "success_rate": stats.success_rate,
                }
                for name, stats in result.resolvers.items()
            }

        if metrics.keys() - {"timestamp"}:
            self.event_bus.publish("metrics", metrics)
