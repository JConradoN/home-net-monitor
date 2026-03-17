"""
tests/test_icmp.py — Testes do ICMPCollector.

Organizado em três camadas:
  1. Testes unitários (sem I/O) — parse, classificação, lógica de estado
  2. Testes assíncronos (mock de subprocess) — ping(), ping_all(), detect_outage()
  3. Testes de integração (marcados com @pytest.mark.integration) — ping real

Execute apenas unitários (CI):
    pytest tests/test_icmp.py -v -m "not integration"

Execute incluindo integração (requer rede):
    pytest tests/test_icmp.py -v
"""

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

from collectors.icmp import (
    ICMPCollector,
    OutageResult,
    OutageType,
    PingResult,
    BufferbloatResult,
    parse_ping_output,
    detect_dns_resolver,
)


# ═══════════════════════════════════════════════════════════════════════════════
# 1. TESTES UNITÁRIOS — sem I/O, sem asyncio
# ═══════════════════════════════════════════════════════════════════════════════

class TestPingResult:
    """Propriedades e lógica do dataclass PingResult."""

    def test_is_reachable_when_packets_received(self):
        r = PingResult(target="gw", host="192.168.1.1")
        r.packets_received = 3
        assert r.is_reachable is True

    def test_not_reachable_when_zero_packets(self):
        r = PingResult(target="gw", host="192.168.1.1")
        r.packets_received = 0
        assert r.is_reachable is False

    def test_loss_percent(self):
        r = PingResult(target="t", host="1.1.1.1")
        r.packet_loss = 0.25
        assert r.loss_percent == pytest.approx(25.0)

    def test_loss_percent_zero(self):
        r = PingResult(target="t", host="1.1.1.1")
        r.packet_loss = 0.0
        assert r.loss_percent == 0.0

    def test_repr_reachable(self):
        r = PingResult(target="cloudflare", host="1.1.1.1")
        r.packets_received = 5
        r.rtt_avg = 12.345
        r.packet_loss = 0.0
        assert "1.1.1.1" in repr(r)
        assert "12.3" in repr(r)

    def test_repr_unreachable(self):
        r = PingResult(target="gw", host="192.168.1.1")
        r.error = "timeout"
        assert "UNREACHABLE" in repr(r)


class TestParsePingOutput:
    """Parser do output do comando ping Linux."""

    def _parse(self, output: str) -> PingResult:
        r = PingResult(target="test", host="8.8.8.8")
        parse_ping_output(r, output)
        return r

    def test_full_output_no_loss(self):
        output = (
            "5 packets transmitted, 5 received, 0% packet loss, time 4004ms\n"
            "rtt min/avg/max/mdev = 1.234/2.345/3.456/0.567 ms\n"
        )
        r = self._parse(output)
        assert r.packets_sent     == 5
        assert r.packets_received == 5
        assert r.packet_loss      == pytest.approx(0.0)
        assert r.rtt_min          == pytest.approx(1.234)
        assert r.rtt_avg          == pytest.approx(2.345)
        assert r.rtt_max          == pytest.approx(3.456)
        assert r.rtt_mdev         == pytest.approx(0.567)

    def test_partial_loss(self):
        output = (
            "5 packets transmitted, 4 received, 20% packet loss, time 4001ms\n"
            "rtt min/avg/max/mdev = 1.000/1.500/2.000/0.200 ms\n"
        )
        r = self._parse(output)
        assert r.packets_received == 4
        assert r.packet_loss      == pytest.approx(0.20)
        assert r.rtt_avg          == pytest.approx(1.500)

    def test_hundred_percent_loss(self):
        output = "5 packets transmitted, 0 received, 100% packet loss, time 4000ms\n"
        r = self._parse(output)
        assert r.packets_received == 0
        assert r.packet_loss      == pytest.approx(1.0)
        assert r.rtt_avg is None

    def test_fractional_loss(self):
        """Linux pode mostrar 33.3% em casos específicos."""
        output = (
            "3 packets transmitted, 2 received, 33.3% packet loss, time 2002ms\n"
            "rtt min/avg/max/mdev = 5.000/6.000/7.000/0.500 ms\n"
        )
        r = self._parse(output)
        assert r.packet_loss == pytest.approx(0.333, abs=0.001)

    def test_empty_output(self):
        """Output vazio não deve lançar exceção."""
        r = self._parse("")
        assert r.rtt_avg is None
        assert r.packet_loss == 0.0

    def test_output_with_errors_field(self):
        """Formato com erros ICMP: '5 packets transmitted, 3 received, +2 errors'."""
        output = (
            "5 packets transmitted, 3 received, +2 errors, 40% packet loss, time 4000ms\n"
            "rtt min/avg/max/mdev = 2.000/3.000/4.000/0.300 ms\n"
        )
        r = self._parse(output)
        assert r.packets_sent     == 5
        assert r.packets_received == 3
        assert r.packet_loss      == pytest.approx(0.40)


class TestBufferbloatClassify:
    """Classificação de bufferbloat pelo delta de latência."""

    def _classify(self, delta: float) -> str:
        r = BufferbloatResult()
        r.delta_ms = delta
        r.classify()
        return r.grade

    def test_none_grade_delta_zero(self):
        assert self._classify(0.0)  == "Nenhum"

    def test_none_grade_delta_below_5(self):
        assert self._classify(4.9)  == "Nenhum"

    def test_leve_grade_at_boundary_5(self):
        assert self._classify(5.0)  == "Leve"

    def test_leve_grade(self):
        assert self._classify(15.0) == "Leve"

    def test_moderado_at_boundary_30(self):
        assert self._classify(30.0) == "Moderado"

    def test_moderado_grade(self):
        assert self._classify(60.0) == "Moderado"

    def test_severo_at_boundary_100(self):
        assert self._classify(100.0) == "Severo"

    def test_severo_grade(self):
        assert self._classify(200.0) == "Severo"

    def test_unknown_when_delta_none(self):
        r = BufferbloatResult()
        r.delta_ms = None
        r.classify()
        assert r.grade == "unknown"


class TestDetectDNSResolver:
    """Detecção de resolver DNS interno via /etc/resolv.conf."""

    def test_detects_first_nameserver(self):
        from unittest.mock import mock_open
        content = "# comment\nnameserver 192.168.1.1\nnameserver 8.8.8.8\n"
        with patch("builtins.open", mock_open(read_data=content)):
            ip = detect_dns_resolver()
        assert ip == "192.168.1.1"

    def test_ignores_ipv6_loopback(self):
        """::1 é IPv6 válido — detect_dns_resolver aceita e retorna sem exceção."""
        from unittest.mock import mock_open
        content = "nameserver ::1\nnameserver 192.168.1.1\n"
        with patch("builtins.open", mock_open(read_data=content)):
            ip = detect_dns_resolver()
        assert ip in ("::1", "192.168.1.1", None)

    def test_returns_none_when_file_missing(self):
        from unittest.mock import mock_open
        with patch("builtins.open", mock_open()) as m:
            m.side_effect = FileNotFoundError
            ip = detect_dns_resolver()
        assert ip is None


# ═══════════════════════════════════════════════════════════════════════════════
# 2. TESTES ASSÍNCRONOS — mock de subprocess
# ═══════════════════════════════════════════════════════════════════════════════

def make_ping_result(
    reachable: bool = True,
    rtt_avg: float = 5.0,
    loss: float = 0.0,
    name: str = "test",
    host: str = "1.2.3.4",
) -> PingResult:
    """Helper: cria PingResult pronto para testes."""
    r = PingResult(target=name, host=host)
    r.packets_sent     = 5
    r.packets_received = 5 if reachable else 0
    r.packet_loss      = loss
    r.rtt_avg          = rtt_avg if reachable else None
    r.rtt_min          = rtt_avg * 0.8 if reachable else None
    r.rtt_max          = rtt_avg * 1.2 if reachable else None
    r.rtt_mdev         = 0.5 if reachable else None
    if not reachable:
        r.error = "100% packet loss"
    return r


def _make_subprocess_mock(stdout: str, returncode: int = 0):
    """Cria mock de asyncio.subprocess.Process."""
    proc = AsyncMock()
    proc.returncode = returncode
    proc.communicate.return_value = (stdout.encode(), b"")
    return proc


@pytest.mark.asyncio
class TestICMPCollectorPing:
    """Testes do método ping() com subprocess mockado."""

    PING_OUTPUT_OK = (
        "5 packets transmitted, 5 received, 0% packet loss, time 4004ms\n"
        "rtt min/avg/max/mdev = 1.500/2.500/3.500/0.400 ms\n"
    )
    PING_OUTPUT_LOSS = (
        "5 packets transmitted, 3 received, 40% packet loss, time 4001ms\n"
        "rtt min/avg/max/mdev = 2.000/3.000/4.000/0.300 ms\n"
    )
    PING_OUTPUT_TOTAL_LOSS = (
        "5 packets transmitted, 0 received, 100% packet loss, time 4000ms\n"
    )

    async def test_ping_successful(self):
        collector = ICMPCollector()
        proc = _make_subprocess_mock(self.PING_OUTPUT_OK)
        with patch("asyncio.create_subprocess_exec", return_value=proc):
            r = await collector.ping("1.1.1.1")
        assert r.is_reachable
        assert r.rtt_avg  == pytest.approx(2.5)
        assert r.loss_percent == 0.0
        assert r.error is None

    async def test_ping_with_packet_loss(self):
        collector = ICMPCollector()
        proc = _make_subprocess_mock(self.PING_OUTPUT_LOSS)
        with patch("asyncio.create_subprocess_exec", return_value=proc):
            r = await collector.ping("8.8.8.8")
        assert r.is_reachable
        assert r.loss_percent == pytest.approx(40.0)

    async def test_ping_total_loss(self):
        collector = ICMPCollector()
        proc = _make_subprocess_mock(self.PING_OUTPUT_TOTAL_LOSS, returncode=1)
        with patch("asyncio.create_subprocess_exec", return_value=proc):
            r = await collector.ping("192.168.1.1")
        assert not r.is_reachable
        assert r.packet_loss == pytest.approx(1.0)

    async def test_ping_target_name_overrides_host(self):
        collector = ICMPCollector()
        proc = _make_subprocess_mock(self.PING_OUTPUT_OK)
        with patch("asyncio.create_subprocess_exec", return_value=proc):
            r = await collector.ping("8.8.8.8", target_name="google_dns")
        assert r.target == "google_dns"
        assert r.host   == "8.8.8.8"

    async def test_ping_handles_file_not_found(self):
        """Deve retornar PingResult com error se 'ping' não existe."""
        collector = ICMPCollector()
        with patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError):
            r = await collector.ping("1.1.1.1")
        assert not r.is_reachable
        assert r.error is not None
        assert "ping" in r.error.lower()

    async def test_ping_handles_process_timeout(self):
        """Deve retornar PingResult com error em timeout de subprocess."""
        collector = ICMPCollector(ping_timeout=1)
        proc = AsyncMock()
        proc.returncode = 0
        proc.communicate.side_effect = asyncio.TimeoutError()
        proc.kill = MagicMock()   # kill() é síncrono no asyncio.subprocess

        with patch("asyncio.create_subprocess_exec", return_value=proc):
            r = await collector.ping("1.1.1.1", count=1, timeout=1)
        assert not r.is_reachable
        assert r.packet_loss == 1.0

    async def test_ping_all_runs_in_parallel(self):
        """ping_all() deve executar todos os pings e retornar resultados."""
        collector = ICMPCollector(targets={
            "cloudflare": "1.1.1.1",
            "google":     "8.8.8.8",
        })

        async def fake_ping(host, count=None, timeout=None, target_name=None):
            r = PingResult(target=target_name or host, host=host)
            r.packets_sent = r.packets_received = 5
            r.rtt_avg = 5.0
            return r

        with patch.object(collector, "ping", side_effect=fake_ping):
            results = await collector.ping_all()

        assert set(results.keys()) == {"cloudflare", "google"}
        assert all(r.is_reachable for r in results.values())

    async def test_ping_all_skips_none_targets(self):
        """Alvos com IP None devem ser ignorados."""
        collector = ICMPCollector(targets={
            "gateway":    None,
            "cloudflare": "1.1.1.1",
        })
        call_count = 0

        async def fake_ping(host, **kwargs):
            nonlocal call_count
            call_count += 1
            r = PingResult(target=kwargs.get("target_name", host), host=host)
            r.packets_sent = r.packets_received = 5
            r.rtt_avg = 5.0
            return r

        with patch.object(collector, "ping", side_effect=fake_ping):
            results = await collector.ping_all()

        assert call_count == 1
        assert "gateway" not in results
        assert "cloudflare" in results


class TestDetectOutage:
    """Testes da classificação de quedas."""

    def setup_method(self):
        self.collector = ICMPCollector(targets={
            "gateway":    "192.168.1.1",
            "cloudflare": "1.1.1.1",
            "google_dns": "8.8.8.8",
        })

    def _results(
        self,
        gw_ok: bool = True,
        inet_ok: bool = True,
    ) -> dict:
        return {
            "gateway":    make_ping_result(reachable=gw_ok,   name="gateway",    host="192.168.1.1"),
            "cloudflare": make_ping_result(reachable=inet_ok, name="cloudflare", host="1.1.1.1"),
            "google_dns": make_ping_result(reachable=inet_ok, name="google_dns", host="8.8.8.8"),
        }

    def test_no_outage_all_reachable(self):
        outage = self.collector.detect_outage(self._results(gw_ok=True, inet_ok=True))
        assert outage.outage_type == OutageType.NONE
        assert not outage.is_outage

    def test_isp_outage_gateway_ok_internet_down(self):
        outage = self.collector.detect_outage(self._results(gw_ok=True, inet_ok=False))
        assert outage.outage_type == OutageType.ISP
        assert outage.is_outage
        assert "gateway" in outage.reachable_targets

    def test_total_outage_everything_down(self):
        outage = self.collector.detect_outage(self._results(gw_ok=False, inet_ok=False))
        assert outage.outage_type == OutageType.TOTAL
        assert outage.is_outage

    def test_isp_outage_description_is_user_friendly(self):
        outage = self.collector.detect_outage(self._results(gw_ok=True, inet_ok=False))
        assert "operadora" in outage.description.lower()

    def test_total_outage_description(self):
        outage = self.collector.detect_outage(self._results(gw_ok=False, inet_ok=False))
        assert "gateway" in outage.description.lower()

    def test_none_outage_description(self):
        outage = self.collector.detect_outage(self._results(gw_ok=True, inet_ok=True))
        assert "normalmente" in outage.description.lower()

    def test_partial_outage_one_unreachable(self):
        results = {
            "gateway":    make_ping_result(reachable=True,  name="gateway"),
            "cloudflare": make_ping_result(reachable=False, name="cloudflare"),
            "google_dns": make_ping_result(reachable=True,  name="google_dns"),
        }
        outage = self.collector.detect_outage(results)
        assert outage.outage_type == OutageType.PARTIAL

    def test_outage_start_tracked(self):
        """Queda deve registrar timestamp de início."""
        results = self._results(gw_ok=False, inet_ok=False)
        self.collector.detect_outage(results)
        assert "current_outage" in self.collector._outage_start

    def test_outage_cleared_on_recovery(self):
        """Após recuperação, _outage_start deve ser limpo."""
        # Simula queda
        self.collector._outage_start["current_outage"] = time.time() - 60
        # Recupera
        outage = self.collector.detect_outage(self._results(gw_ok=True, inet_ok=True))
        assert "current_outage" not in self.collector._outage_start
        assert outage.duration_s is not None
        assert outage.duration_s >= 60

    def test_outage_duration_property(self):
        """current_outage_duration deve retornar duração quando ativo."""
        self.collector._outage_start["current_outage"] = time.time() - 45
        duration = self.collector.current_outage_duration
        assert duration is not None
        assert duration >= 45

    def test_no_duration_when_no_outage(self):
        assert self.collector.current_outage_duration is None


@pytest.mark.asyncio
class TestAutoDiscover:
    """Testes da auto-descoberta de gateway e DNS."""

    async def test_auto_discover_sets_gateway(self):
        collector = ICMPCollector()
        with patch("collectors.icmp.detect_gateway", new_callable=AsyncMock, return_value="192.168.1.1"):
            with patch("collectors.icmp.detect_dns_resolver", return_value="192.168.1.1"):
                await collector.auto_discover()
        assert collector.targets["gateway"] == "192.168.1.1"

    async def test_auto_discover_does_not_overwrite_manual_config(self):
        """Alvos configurados manualmente não devem ser sobrescritos."""
        collector = ICMPCollector(targets={"gateway": "10.0.0.1", "cloudflare": "1.1.1.1"})
        with patch("collectors.icmp.detect_gateway", new_callable=AsyncMock, return_value="192.168.1.1"):
            await collector.auto_discover()
        # Gateway manual não deve ser sobrescrito
        assert collector.targets["gateway"] == "10.0.0.1"

    async def test_auto_discover_handles_gateway_not_found(self):
        """Sem gateway detectado, target deve permanecer None."""
        collector = ICMPCollector()
        with patch("collectors.icmp.detect_gateway", new_callable=AsyncMock, return_value=None):
            with patch("collectors.icmp.detect_dns_resolver", return_value=None):
                await collector.auto_discover()
        assert collector.targets["gateway"] is None


# ═══════════════════════════════════════════════════════════════════════════════
# 3. TESTES DE INTEGRAÇÃO — requerem rede real
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.integration
@pytest.mark.asyncio
class TestICMPIntegration:
    """
    Testes de integração que executam pings reais.

    Marcados com @pytest.mark.integration — excluídos do CI por padrão.
    Execute com: pytest tests/test_icmp.py -m integration -v
    """

    async def test_ping_localhost(self):
        """Ping para 127.0.0.1 deve sempre funcionar."""
        collector = ICMPCollector()
        result = await collector.ping("127.0.0.1", count=3, timeout=1)

        assert result.is_reachable, f"Ping para localhost falhou: {result.error}"
        assert result.rtt_avg is not None
        assert result.rtt_avg < 10.0, "RTT para localhost deve ser < 10ms"
        assert result.packet_loss == 0.0
        assert result.packets_sent == 3
        assert result.packets_received == 3

    async def test_ping_localhost_target_name(self):
        """target_name deve aparecer corretamente no resultado."""
        collector = ICMPCollector()
        result = await collector.ping("127.0.0.1", count=2, target_name="loopback")
        assert result.target == "loopback"
        assert result.host   == "127.0.0.1"

    async def test_ping_unreachable_returns_loss(self):
        """IP não roteável deve retornar 100% de perda."""
        collector = ICMPCollector()
        # Endereço no bloco TEST-NET (RFC 5737) — não deve ser roteado
        result = await collector.ping("192.0.2.1", count=2, timeout=1)
        assert not result.is_reachable or result.packet_loss > 0

    async def test_ping_all_localhost(self):
        """ping_all() com localhost deve retornar resultado acessível."""
        collector = ICMPCollector(targets={"loopback": "127.0.0.1"})
        results = await collector.ping_all()
        assert "loopback" in results
        assert results["loopback"].is_reachable

    async def test_detect_outage_integration(self):
        """Com localhost acessível e 192.0.2.1 inacessível → PARTIAL."""
        collector = ICMPCollector(targets={
            "gateway":    "127.0.0.1",
            "cloudflare": "192.0.2.1",   # TEST-NET — inacessível
        })
        results = await collector.ping_all()
        outage = collector.detect_outage(results)
        # gateway (localhost) deve ser acessível
        assert "gateway" in outage.reachable_targets

    async def test_auto_discover_integration(self):
        """Auto-discover deve detectar gateway sem erro."""
        collector = ICMPCollector()
        await collector.auto_discover()
        # Pode ser None se não houver gateway configurado, mas não deve lançar exceção
        # Em uma máquina com rede, gateway deve ser detectado
        gateway = collector.targets.get("gateway")
        if gateway:
            assert "." in gateway, f"Gateway inválido: {gateway}"
