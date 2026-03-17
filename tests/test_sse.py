"""
tests/test_sse.py — Testes do EventBus e SSEEvent.

Testa publish/subscribe, formatação SSE e
comportamento com múltiplos subscribers.
"""

import asyncio
import json
import pytest

from api.sse import EventBus, SSEEvent


class TestSSEEvent:
    """Testes de serialização SSE."""

    def test_to_sse_string_format(self):
        event = SSEEvent(event_type="alert", data={"code": "OUTAGE"}, event_id="42")
        sse_str = event.to_sse_string()
        assert "id: 42" in sse_str
        assert "event: alert" in sse_str
        assert '"code": "OUTAGE"' in sse_str
        assert sse_str.endswith("\n\n")

    def test_to_sse_string_without_id(self):
        event = SSEEvent(event_type="ping", data={"ts": 1234})
        sse_str = event.to_sse_string()
        assert "id:" not in sse_str
        assert "event: ping" in sse_str

    def test_data_serialized_as_json(self):
        event = SSEEvent(event_type="status", data={"status": "ok", "count": 0})
        sse_str = event.to_sse_string()
        data_line = [l for l in sse_str.splitlines() if l.startswith("data:")][0]
        payload = json.loads(data_line.replace("data: ", ""))
        assert payload["status"] == "ok"


class TestEventBus:
    """Testes do EventBus publish/subscribe."""

    def test_subscribe_returns_queue(self):
        bus = EventBus()
        queue = bus.subscribe()
        assert isinstance(queue, asyncio.Queue)
        assert bus.subscriber_count == 1

    def test_unsubscribe_removes_subscriber(self):
        bus = EventBus()
        queue = bus.subscribe()
        bus.unsubscribe(queue)
        assert bus.subscriber_count == 0

    def test_publish_delivers_to_subscriber(self):
        bus = EventBus()
        queue = bus.subscribe()
        bus.publish("test", {"key": "value"})
        assert not queue.empty()
        event = queue.get_nowait()
        assert event.event_type == "test"
        assert event.data["key"] == "value"

    def test_publish_to_multiple_subscribers(self):
        bus = EventBus()
        q1 = bus.subscribe()
        q2 = bus.subscribe()
        bus.publish("metrics", {"rtt": 5.0})
        assert not q1.empty()
        assert not q2.empty()

    def test_publish_alert_shortcut(self):
        """publish_alert deve serializar corretamente um Alert mock."""
        from engine.correlator import Alert, AlertSeverity
        import time

        bus = EventBus()
        queue = bus.subscribe()

        alert = Alert(
            code="TEST",
            severity=AlertSeverity.WARNING,
            title="Test Alert",
            description="desc",
            user_message="msg",
        )
        bus.publish_alert(alert)

        event = queue.get_nowait()
        assert event.event_type == "alert"
        assert event.data["code"] == "TEST"
        assert event.data["severity"] == "Warning"

    def test_queue_full_drops_event(self):
        """Eventos em fila cheia devem ser descartados sem erro."""
        bus = EventBus(maxsize=1)
        queue = bus.subscribe()

        bus.publish("e1", {"n": 1})  # ocupa a fila
        bus.publish("e2", {"n": 2})  # deve ser descartado
        # Subscriber removido por fila cheia
        assert bus.subscriber_count == 0
