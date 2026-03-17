"""
tests/test_icmp.py — Testes do ICMPCollector.

Testa parsing de output de ping, classificação de resultados,
detecção de quedas e classificação de bufferbloat.
"""

import time
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from collectors.icmp import (
    ICMPCollector,
    PingResult,
    BufferbloatResult,
    DEFAULT_TARGETS,
)


class TestPingResult:
    """Testes do dataclass PingResult."""

    def test_is_reachable_with_packets_received(self):
        result = PingResult(target="gateway", host="192.168.1.1")
        result.packets_received = 3
        assert result.is_reachable is True

    def test_is_not_reachable_when_zero_packets(self):
        result = PingResult(target="gateway", host="192.168.1.1")
        result.packets_received = 0
        assert result.is_reachable is False

    def test_loss_percent_calculation(self):
        result = PingResult(target="gateway", host="192.168.1.1")
        result.packet_loss = 0.2
        assert result.loss_percent == pytest.approx(20.0)

    def test_loss_percent_zero(self):
        result = PingResult(target="gateway", host="192.168.1.1")
        result.packet_loss = 0.0
        assert result.loss_percent == 0.0


class TestICMPCollectorParsing:
    """Testes do parser de output do comando ping."""

    def setup_method(self):
        self.collector = ICMPCollector()

    def test_parse_valid_ping_output(self):
        output = (
            "5 packets transmitted, 5 received, 0% packet loss, time 4004ms\n"
            "rtt min/avg/max/mdev = 1.234/2.345/3.456/0.567 ms\n"
        )
        result = PingResult(target="test", host="8.8.8.8")
        self.collector._parse_ping_output(result, output)

        assert result.packets_sent == 5
        assert result.packets_received == 5
        assert result.packet_loss == 0.0
        assert result.rtt_min == pytest.approx(1.234)
        assert result.rtt_avg == pytest.approx(2.345)
        assert result.rtt_max == pytest.approx(3.456)
        assert result.rtt_mdev == pytest.approx(0.567)

    def test_parse_ping_with_packet_loss(self):
        output = (
            "5 packets transmitted, 4 received, 20% packet loss, time 4001ms\n"
            "rtt min/avg/max/mdev = 1.000/1.500/2.000/0.200 ms\n"
        )
        result = PingResult(target="test", host="8.8.8.8")
        self.collector._parse_ping_output(result, output)

        assert result.packets_received == 4
        assert result.packet_loss == pytest.approx(0.20)

    def test_parse_ping_100_percent_loss(self):
        output = "5 packets transmitted, 0 received, 100% packet loss, time 4000ms\n"
        result = PingResult(target="test", host="192.168.1.1")
        self.collector._parse_ping_output(result, output)

        assert result.packets_received == 0
        assert result.packet_loss == pytest.approx(1.0)
        assert result.rtt_avg is None


class TestBufferbloatResult:
    """Testes da classificação de bufferbloat."""

    def test_classify_none(self):
        result = BufferbloatResult()
        result.delta_ms = None
        result.classify()
        assert result.grade == "unknown"

    def test_classify_none_grade(self):
        result = BufferbloatResult()
        result.delta_ms = 2.0
        result.classify()
        assert result.grade == "Nenhum"

    def test_classify_leve(self):
        result = BufferbloatResult()
        result.delta_ms = 15.0
        result.classify()
        assert result.grade == "Leve"

    def test_classify_moderado(self):
        result = BufferbloatResult()
        result.delta_ms = 50.0
        result.classify()
        assert result.grade == "Moderado"

    def test_classify_severo(self):
        result = BufferbloatResult()
        result.delta_ms = 150.0
        result.classify()
        assert result.grade == "Severo"

    def test_classify_boundary_5ms(self):
        """Exatamente 5ms é 'Leve', não 'Nenhum'."""
        result = BufferbloatResult()
        result.delta_ms = 5.0
        result.classify()
        assert result.grade == "Leve"


class TestICMPCollectorOutage:
    """Testes da detecção de quedas."""

    def test_outage_start_recorded_when_gateway_unreachable(self):
        collector = ICMPCollector()
        unreachable = PingResult(target="gateway", host="192.168.1.1")
        unreachable.packets_received = 0
        unreachable.packet_loss = 1.0

        collector._check_outages({"gateway": unreachable})
        assert "gateway" in collector._outage_start

    def test_outage_cleared_when_gateway_recovers(self):
        collector = ICMPCollector()
        collector._outage_start["gateway"] = time.time() - 60

        reachable = PingResult(target="gateway", host="192.168.1.1")
        reachable.packets_received = 5
        reachable.packet_loss = 0.0

        collector._check_outages({"gateway": reachable})
        assert "gateway" not in collector._outage_start
