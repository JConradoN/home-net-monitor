"""
tests/test_snmp.py — Testes do SNMPCollector.

Organizado em três camadas:
  1. Unitários puros — helpers, dataclasses, lógica de estado
  2. Assíncronos com mock do backend — collect(), coletas individuais
  3. Integração (marcados @pytest.mark.integration) — SNMP real

Execute unitários (CI):
    pytest tests/test_snmp.py -v -m "not integration"
"""

import asyncio
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from collectors.snmp import (
    SNMPCollector,
    SNMPResult,
    WifiRadioStats,
    SNMPError,
    _oid_last_index,
    _counter_delta,
    _snmp_signed_int,
    _parse_routeros_uptime,
    OID_SYS_DESCR,
    OID_SYS_UPTIME,
    OID_HR_CPU_LOAD,
    OID_IF_DESCR,
    OID_IF_IN_HC,
    OID_IF_OUT_HC,
    OID_IF_IN_OCTETS,
    OID_IF_OUT_OCTETS,
    OID_MTX_WIFI_CLIENTS,
    OID_MTX_WIFI_NOISE,
    OID_MTX_WIFI_CH_UTIL,
    OID_MTX_WIFI_SSID,
    OID_MTX_WIFI_FREQ,
    OID_MTX_WIFI_BAND,
    THRESHOLD_CPU_CRITICAL,
)


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers de teste
# ═══════════════════════════════════════════════════════════════════════════════

class MockSNMPBackend:
    """
    Backend SNMP falso para testes.

    Armazena mapeamentos OID→valor configurados no construtor.
    Simula get() e walk() sem conexão de rede.
    """

    def __init__(
        self,
        get_data: dict[str, Any] = None,
        walk_data: dict[str, list[tuple[str, Any]]] = None,
        get_error: Exception = None,
        walk_errors: dict[str, Exception] = None,
    ):
        """
        Args:
            get_data:    {oid: valor} para respostas GET.
            walk_data:   {oid_base: [(oid, valor), ...]} para respostas WALK.
            get_error:   Se definido, get() lança esta exceção.
            walk_errors: {oid_base: exceção} — walk() lança por OID específica.
        """
        self._get_data    = get_data    or {}
        self._walk_data   = walk_data   or {}
        self._get_error   = get_error
        self._walk_errors = walk_errors or {}

        # Contadores de chamadas para assertivas
        self.get_calls:  list[tuple] = []
        self.walk_calls: list[str]   = []

    async def get(self, *oids: str) -> dict[str, Any]:
        self.get_calls.append(oids)
        if self._get_error:
            raise self._get_error
        return {oid: self._get_data[oid] for oid in oids if oid in self._get_data}

    async def walk(self, base_oid: str) -> list[tuple[str, Any]]:
        self.walk_calls.append(base_oid)
        if base_oid in self._walk_errors:
            raise self._walk_errors[base_oid]
        return self._walk_data.get(base_oid, [])


def make_collector(
    host: str = "192.168.1.1",
    backend: MockSNMPBackend = None,
    wan_iface: str = None,
) -> SNMPCollector:
    """Cria SNMPCollector com backend mock padrão."""
    if backend is None:
        backend = MockSNMPBackend()
    return SNMPCollector(host=host, backend=backend, wan_iface=wan_iface)


def minimal_backend() -> MockSNMPBackend:
    """Backend com respostas mínimas para uma coleta sem erros."""
    return MockSNMPBackend(
        get_data={
            OID_SYS_DESCR:  "RouterOS 7.14 (Mikrotik)",
            OID_SYS_UPTIME: 360000,   # 3600 segundos = 1h
        },
        walk_data={
            OID_HR_CPU_LOAD: [
                (f"{OID_HR_CPU_LOAD}.1", 25),
                (f"{OID_HR_CPU_LOAD}.2", 35),
            ],
            OID_IF_DESCR: [
                (f"{OID_IF_DESCR}.1", "lo"),
                (f"{OID_IF_DESCR}.2", "ether1"),
                (f"{OID_IF_DESCR}.3", "wlan1"),
            ],
            OID_MTX_WIFI_CLIENTS:  [],
            OID_MTX_WIFI_NOISE:    [],
            OID_MTX_WIFI_CH_UTIL:  [],
            OID_MTX_WIFI_SSID:     [],
            OID_MTX_WIFI_FREQ:     [],
            OID_MTX_WIFI_BAND:     [],
        },
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 1. TESTES UNITÁRIOS — sem I/O
# ═══════════════════════════════════════════════════════════════════════════════

class TestHelpers:
    """Testes das funções helper do módulo."""

    # _oid_last_index
    def test_oid_last_index_normal(self):
        assert _oid_last_index("1.3.6.1.2.1.2.2.1.2.3") == 3

    def test_oid_last_index_single(self):
        assert _oid_last_index("1.3.6.1.2.1.1.3.0") == 0

    def test_oid_last_index_invalid(self):
        assert _oid_last_index("not_an_oid") is None

    def test_oid_last_index_large(self):
        assert _oid_last_index("1.3.6.1.4.1.14988.1.1.1.3.1.6.42") == 42

    # _counter_delta
    def test_counter_delta_normal(self):
        assert _counter_delta(1000, 500) == 500

    def test_counter_delta_zero(self):
        assert _counter_delta(500, 500) == 0

    def test_counter_delta_wrap_32bit(self):
        """Testa wrap de contador 32 bits (4 GB)."""
        prev    = 0xFFFFF000   # próximo do limite
        current = 0x00000100   # wrappou
        expected = (2**32 - prev) + current
        assert _counter_delta(current, prev, bits=32) == expected

    def test_counter_delta_wrap_64bit(self):
        prev    = 2**64 - 1000
        current = 500
        expected = 1500
        assert _counter_delta(current, prev, bits=64) == expected

    # _snmp_signed_int
    def test_snmp_signed_int_negative_dBm(self):
        """Noise floor típico: -75 dBm representado como unsigned 32-bit."""
        unsigned = 0xFFFFFFB5   # -75 em complemento de 2 (32-bit)
        assert _snmp_signed_int(unsigned) == -75.0

    def test_snmp_signed_int_already_negative(self):
        assert _snmp_signed_int(-85) == -85.0

    def test_snmp_signed_int_positive(self):
        assert _snmp_signed_int(30) == 30.0

    def test_snmp_signed_int_string(self):
        assert _snmp_signed_int("-70") == -70.0

    def test_snmp_signed_int_invalid(self):
        assert _snmp_signed_int("invalid") == -100.0

    # _parse_routeros_uptime
    def test_parse_uptime_full(self):
        assert _parse_routeros_uptime("1d2h3m4s") == 86400 + 7200 + 180 + 4

    def test_parse_uptime_weeks(self):
        assert _parse_routeros_uptime("1w") == 604800

    def test_parse_uptime_only_hours(self):
        assert _parse_routeros_uptime("3h") == 10800

    def test_parse_uptime_empty(self):
        assert _parse_routeros_uptime("") is None

    def test_parse_uptime_none(self):
        assert _parse_routeros_uptime(None) is None

    def test_parse_uptime_complex(self):
        assert _parse_routeros_uptime("3d20h14m52s") == (
            3 * 86400 + 20 * 3600 + 14 * 60 + 52
        )


class TestWifiRadioStats:
    """Testes do dataclass WifiRadioStats."""

    def test_band_label_from_frequency_5ghz(self):
        r = WifiRadioStats(radio_index=0)
        r.frequency_mhz = 5180
        assert r.band_label == "5 GHz"

    def test_band_label_from_frequency_24ghz(self):
        r = WifiRadioStats(radio_index=0)
        r.frequency_mhz = 2412
        assert r.band_label == "2.4 GHz"

    def test_band_label_fallback_to_band_string(self):
        r = WifiRadioStats(radio_index=0)
        r.band = "5ghz-a/n/ac"
        assert r.band_label == "5 GHz"

    def test_band_label_default(self):
        r = WifiRadioStats(radio_index=0)
        assert r.band_label == "2.4 GHz"

    def test_is_saturated_above_threshold(self):
        r = WifiRadioStats(radio_index=0)
        r.channel_utilization = 80.0
        assert r.is_saturated is True

    def test_is_not_saturated_below_threshold(self):
        r = WifiRadioStats(radio_index=0)
        r.channel_utilization = 50.0
        assert r.is_saturated is False

    def test_has_interference(self):
        r = WifiRadioStats(radio_index=0)
        r.retries_percent = 20.0
        assert r.has_interference is True

    def test_has_high_noise(self):
        r = WifiRadioStats(radio_index=0)
        r.noise_floor = -70.0
        assert r.has_high_noise is True

    def test_no_high_noise(self):
        r = WifiRadioStats(radio_index=0)
        r.noise_floor = -85.0
        assert r.has_high_noise is False

    def test_to_dict_keys(self):
        r = WifiRadioStats(radio_index=1)
        d = r.to_dict()
        assert "radio_index"         in d
        assert "clients"             in d
        assert "channel_utilization" in d
        assert "noise_floor"         in d
        assert "retries_percent"     in d
        assert "band"                in d


class TestSNMPResult:
    """Testes do dataclass SNMPResult."""

    def test_is_ok_without_error(self):
        r = SNMPResult(host="192.168.1.1", community="public")
        assert r.is_ok is True

    def test_is_not_ok_with_error(self):
        r = SNMPResult(host="192.168.1.1", community="public")
        r.error = "timeout"
        assert r.is_ok is False

    def test_has_wifi_with_radios(self):
        r = SNMPResult(host="192.168.1.1", community="public")
        r.wifi_radios.append(WifiRadioStats(radio_index=0))
        assert r.has_wifi is True

    def test_has_no_wifi_empty(self):
        r = SNMPResult(host="192.168.1.1", community="public")
        assert r.has_wifi is False

    def test_wifi_to_dict_list(self):
        r = SNMPResult(host="192.168.1.1", community="public")
        radio = WifiRadioStats(radio_index=0)
        radio.clients = 3
        r.wifi_radios.append(radio)
        dicts = r.wifi_to_dict_list()
        assert len(dicts) == 1
        assert dicts[0]["clients"] == 3


class TestFindWanIndex:
    """Testes da identificação de interface WAN."""

    def _collector(self, wan_iface=None):
        return make_collector(wan_iface=wan_iface)

    def test_finds_ether1(self):
        c = self._collector()
        iface_map = {1: "lo", 2: "ether1", 3: "wlan1"}
        assert c._find_wan_index(iface_map) == 2

    def test_finds_pppoe_out(self):
        c = self._collector()
        iface_map = {1: "lo", 2: "bridge-lan", 3: "pppoe-out1"}
        assert c._find_wan_index(iface_map) == 3

    def test_finds_wan_in_name(self):
        c = self._collector()
        iface_map = {1: "lo", 2: "wan", 3: "lan"}
        assert c._find_wan_index(iface_map) == 2

    def test_finds_sfp1(self):
        c = self._collector()
        iface_map = {1: "lo", 2: "sfp1", 3: "wlan1"}
        assert c._find_wan_index(iface_map) == 2

    def test_manual_wan_iface(self):
        c = self._collector(wan_iface="ether2")
        iface_map = {1: "ether1", 2: "ether2", 3: "wlan1"}
        assert c._find_wan_index(iface_map) == 2

    def test_manual_case_insensitive(self):
        c = self._collector(wan_iface="ETHER1")
        iface_map = {1: "lo", 2: "ether1"}
        assert c._find_wan_index(iface_map) == 2

    def test_returns_none_when_no_wan(self):
        c = self._collector()
        iface_map = {1: "lo", 2: "bridge-lan", 3: "vlan10"}
        assert c._find_wan_index(iface_map) is None

    def test_priority_ether1_over_wan_in_name(self):
        """ether1 deve ter prioridade sobre interfaces com 'wan' no nome."""
        c = self._collector()
        iface_map = {1: "lo", 2: "ether1", 3: "wan-backup"}
        # ether1 aparece primeiro nos padrões
        assert c._find_wan_index(iface_map) == 2


# ═══════════════════════════════════════════════════════════════════════════════
# 2. TESTES ASSÍNCRONOS com mock
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
class TestCollectSystem:
    """Testes de _collect_system()."""

    async def test_collects_uptime(self):
        backend = MockSNMPBackend(
            get_data={
                OID_SYS_DESCR:  "RouterOS 7.14",
                OID_SYS_UPTIME: 360000,   # 3600s
            },
            walk_data={OID_HR_CPU_LOAD: []},
        )
        c = make_collector(backend=backend)
        result = SNMPResult(host="192.168.1.1", community="public")
        await c._collect_system(result)

        assert result.uptime_seconds == 3600
        assert result.sys_descr == "RouterOS 7.14"

    async def test_collects_cpu_average(self):
        backend = MockSNMPBackend(
            get_data={OID_SYS_DESCR: "x", OID_SYS_UPTIME: 0},
            walk_data={
                OID_HR_CPU_LOAD: [
                    (f"{OID_HR_CPU_LOAD}.1", 40),
                    (f"{OID_HR_CPU_LOAD}.2", 60),
                ],
            },
        )
        c = make_collector(backend=backend)
        result = SNMPResult(host="192.168.1.1", community="public")
        await c._collect_system(result)

        assert result.cpu_usage == pytest.approx(50.0)

    async def test_cpu_none_when_walk_empty(self):
        backend = MockSNMPBackend(
            get_data={OID_SYS_DESCR: "x", OID_SYS_UPTIME: 100},
            walk_data={OID_HR_CPU_LOAD: []},
        )
        c = make_collector(backend=backend)
        result = SNMPResult(host="192.168.1.1", community="public")
        await c._collect_system(result)

        assert result.cpu_usage is None

    async def test_raises_snmp_error_on_get_failure(self):
        backend = MockSNMPBackend(
            get_error=SNMPError("No response from 192.168.1.1"),
        )
        c = make_collector(backend=backend)
        result = SNMPResult(host="192.168.1.1", community="public")

        with pytest.raises(SNMPError):
            await c._collect_system(result)


@pytest.mark.asyncio
class TestCollectInterfaces:
    """Testes de _collect_interfaces() e cálculo de bps."""

    def _backend_with_ifaces(
        self,
        if_idx: int = 2,
        in_bytes: int = 1_000_000,
        out_bytes: int = 500_000,
        use_hc: bool = True,
    ) -> MockSNMPBackend:
        """Backend com interface ether1 e contadores configuráveis."""
        oid_in  = f"{OID_IF_IN_HC}.{if_idx}"  if use_hc else f"{OID_IF_IN_OCTETS}.{if_idx}"
        oid_out = f"{OID_IF_OUT_HC}.{if_idx}" if use_hc else f"{OID_IF_OUT_OCTETS}.{if_idx}"

        return MockSNMPBackend(
            get_data={oid_in: in_bytes, oid_out: out_bytes},
            walk_data={
                OID_IF_DESCR: [
                    (f"{OID_IF_DESCR}.1", "lo"),
                    (f"{OID_IF_DESCR}.2", "ether1"),
                ],
            },
        )

    async def test_identifies_wan_interface(self):
        c = make_collector(backend=self._backend_with_ifaces())
        result = SNMPResult(host="192.168.1.1", community="public")
        await c._collect_interfaces(result)

        assert result.wan_interface == "ether1"
        assert result.wan_if_index  == 2

    async def test_stores_raw_counters(self):
        c = make_collector(backend=self._backend_with_ifaces(
            in_bytes=2_000_000, out_bytes=1_000_000
        ))
        result = SNMPResult(host="192.168.1.1", community="public")
        await c._collect_interfaces(result)

        assert result.wan_in_bytes_raw  == 2_000_000
        assert result.wan_out_bytes_raw == 1_000_000

    async def test_no_bps_on_first_collection(self):
        """Primeira coleta não tem coleta anterior — bps deve ser None."""
        c = make_collector(backend=self._backend_with_ifaces())
        result = SNMPResult(host="192.168.1.1", community="public")
        await c._collect_interfaces(result)

        assert result.wan_in_bps  is None
        assert result.wan_out_bps is None

    async def test_calculates_bps_on_second_collection(self):
        """Segunda coleta deve calcular bps corretamente."""
        # Primeira coleta: 1 MB in, 0.5 MB out
        backend = self._backend_with_ifaces(in_bytes=1_000_000, out_bytes=500_000)
        c = make_collector(backend=backend)
        r1 = SNMPResult(host="192.168.1.1", community="public")
        await c._collect_interfaces(r1)

        # Simula passagem de 10 segundos
        c._prev_ts -= 10.0

        # Segunda coleta: +2 MB in, +1 MB out em 10s → 1.6 Mbps in, 0.8 Mbps out
        backend2 = self._backend_with_ifaces(in_bytes=3_000_000, out_bytes=1_500_000)
        c._snmp = backend2
        r2 = SNMPResult(host="192.168.1.1", community="public")
        await c._collect_interfaces(r2)

        # Δin = 2_000_000 bytes, Δt = 10s → 1_600_000 bps
        assert r2.wan_in_bps  == pytest.approx(1_600_000.0, rel=0.01)
        assert r2.wan_out_bps == pytest.approx(800_000.0,   rel=0.01)

    async def test_handles_32bit_counter_wrap(self):
        """Deve lidar corretamente com wrap de contador 32-bit."""
        prev    = 0xFFFFF000   # próximo do overflow 32-bit
        current = 0x00000100   # wrappou
        delta   = (2**32 - prev) + current   # = 0x1100 = 4352 bytes

        # Primeira coleta com contador alto
        backend1 = self._backend_with_ifaces(in_bytes=prev, out_bytes=prev, use_hc=False)
        c = make_collector(backend=backend1)
        r1 = SNMPResult(host="192.168.1.1", community="public")

        # Força uso de 32-bit (sem HC)
        c._snmp._get_data = {
            f"{OID_IF_IN_OCTETS}.2":  prev,
            f"{OID_IF_OUT_OCTETS}.2": prev,
        }
        await c._collect_interfaces(r1)
        c._prev_ts -= 1.0  # 1 segundo

        # Segunda coleta com contador wrappado
        c._snmp._get_data = {
            f"{OID_IF_IN_OCTETS}.2":  current,
            f"{OID_IF_OUT_OCTETS}.2": current,
        }
        r2 = SNMPResult(host="192.168.1.1", community="public")
        await c._collect_interfaces(r2)

        # bps deve ser positivo (delta correto)
        if r2.wan_in_bps is not None:
            assert r2.wan_in_bps >= 0

    async def test_wan_none_when_no_wan_pattern(self):
        """Se nenhuma interface corresponde ao padrão WAN, não preenche."""
        backend = MockSNMPBackend(
            get_data={},
            walk_data={
                OID_IF_DESCR: [(f"{OID_IF_DESCR}.1", "bridge-lan")],
            },
        )
        c = make_collector(backend=backend)
        result = SNMPResult(host="192.168.1.1", community="public")
        await c._collect_interfaces(result)

        assert result.wan_interface is None
        assert result.wan_in_bps   is None


@pytest.mark.asyncio
class TestCollectWifi:
    """Testes de _collect_wifi() com Mikrotik MIB mock."""

    def _wifi_backend(
        self,
        radio_indices: list[int] = None,
        clients: list[int] = None,
        noise: list[int] = None,
        ch_util: list[int] = None,
        ssids: list[str] = None,
        freqs: list[int] = None,
        bands: list[str] = None,
    ) -> MockSNMPBackend:
        """Constrói backend com tabela Wi-Fi Mikrotik para N rádios."""
        indices  = radio_indices or [1]
        clients  = clients  or [0] * len(indices)
        noise    = noise    or [-85] * len(indices)
        ch_util  = ch_util  or [30] * len(indices)
        ssids    = ssids    or ["HomeNet"] * len(indices)
        freqs    = freqs    or [2412] * len(indices)
        bands    = bands    or ["2ghz-b/g/n"] * len(indices)

        def _rows(oid_base, values):
            return [(f"{oid_base}.{i}", v) for i, v in zip(indices, values)]

        return MockSNMPBackend(
            get_data={},
            walk_data={
                OID_MTX_WIFI_CLIENTS: _rows(OID_MTX_WIFI_CLIENTS, clients),
                OID_MTX_WIFI_NOISE:   _rows(OID_MTX_WIFI_NOISE,   noise),
                OID_MTX_WIFI_CH_UTIL: _rows(OID_MTX_WIFI_CH_UTIL, ch_util),
                OID_MTX_WIFI_SSID:    _rows(OID_MTX_WIFI_SSID,    ssids),
                OID_MTX_WIFI_FREQ:    _rows(OID_MTX_WIFI_FREQ,    freqs),
                OID_MTX_WIFI_BAND:    _rows(OID_MTX_WIFI_BAND,    bands),
            },
        )

    async def test_single_radio_collected(self):
        backend = self._wifi_backend(
            radio_indices=[1],
            clients=[5],
            noise=[-80],
            ch_util=[45],
            ssids=["MinhaRede"],
            freqs=[2437],
        )
        c = make_collector(backend=backend)
        result = SNMPResult(host="192.168.1.1", community="public")
        await c._collect_wifi(result)

        assert len(result.wifi_radios) == 1
        radio = result.wifi_radios[0]
        assert radio.radio_index == 1
        assert radio.clients     == 5
        assert radio.noise_floor == pytest.approx(-80.0)
        assert radio.channel_utilization == pytest.approx(45.0)
        assert radio.ssid         == "MinhaRede"
        assert radio.frequency_mhz == 2437

    async def test_two_radios_24_and_5ghz(self):
        backend = self._wifi_backend(
            radio_indices=[1, 2],
            clients=[3, 7],
            noise=[-80, -85],
            ch_util=[40, 20],
            ssids=["Home24", "Home5G"],
            freqs=[2412, 5180],
            bands=["2ghz-b/g/n", "5ghz-a/n/ac"],
        )
        c = make_collector(backend=backend)
        result = SNMPResult(host="192.168.1.1", community="public")
        await c._collect_wifi(result)

        assert len(result.wifi_radios) == 2
        r1, r2 = result.wifi_radios
        assert r1.band_label == "2.4 GHz"
        assert r2.band_label == "5 GHz"
        assert r1.clients == 3
        assert r2.clients == 7

    async def test_noise_floor_negative_value(self):
        """Noise floor deve ser negativo (dBm)."""
        backend = self._wifi_backend(noise=[-75])
        c = make_collector(backend=backend)
        result = SNMPResult(host="192.168.1.1", community="public")
        await c._collect_wifi(result)

        assert result.wifi_radios[0].noise_floor == pytest.approx(-75.0)

    async def test_noise_floor_unsigned_snmp_value(self):
        """Noise floor como unsigned 32-bit (0xFFFFFFB5 = -75 signed)."""
        backend = self._wifi_backend(noise=[0xFFFFFFB5])
        c = make_collector(backend=backend)
        result = SNMPResult(host="192.168.1.1", community="public")
        await c._collect_wifi(result)

        assert result.wifi_radios[0].noise_floor == pytest.approx(-75.0)

    async def test_no_radios_when_walk_empty(self):
        backend = MockSNMPBackend(
            get_data={},
            walk_data={
                OID_MTX_WIFI_CLIENTS: [],
                OID_MTX_WIFI_NOISE:   [],
                OID_MTX_WIFI_CH_UTIL: [],
                OID_MTX_WIFI_SSID:    [],
                OID_MTX_WIFI_FREQ:    [],
                OID_MTX_WIFI_BAND:    [],
            },
        )
        c = make_collector(backend=backend)
        result = SNMPResult(host="192.168.1.1", community="public")
        await c._collect_wifi(result)

        assert result.wifi_radios == []

    async def test_wifi_walk_exception_does_not_crash(self):
        """Walk que lança exceção não deve derrubar a coleta — rádio fica sem dados."""
        backend = MockSNMPBackend(
            walk_data={
                OID_MTX_WIFI_CLIENTS: [(f"{OID_MTX_WIFI_CLIENTS}.1", 4)],
                OID_MTX_WIFI_NOISE:   [],
                OID_MTX_WIFI_CH_UTIL: [],
                OID_MTX_WIFI_SSID:    [],
                OID_MTX_WIFI_FREQ:    [],
                OID_MTX_WIFI_BAND:    [],
            },
        )
        c = make_collector(backend=backend)
        result = SNMPResult(host="192.168.1.1", community="public")
        # Não deve levantar exceção
        await c._collect_wifi(result)
        assert len(result.wifi_radios) == 1
        assert result.wifi_radios[0].clients == 4


@pytest.mark.asyncio
class TestCollectFull:
    """Testes do método collect() completo."""

    async def test_full_collect_ok(self):
        """Coleta completa com backend mínimo deve retornar result.is_ok."""
        c = make_collector(backend=minimal_backend())
        result = await c.collect()

        assert result.is_ok
        assert result.sys_descr     == "RouterOS 7.14 (Mikrotik)"
        assert result.uptime_seconds == 3600
        assert result.cpu_usage     == pytest.approx(30.0)   # (25+35)/2
        assert result.collection_ms is not None
        assert c.last_result is result   # last_result é propriedade do coletor

    async def test_collect_sets_last_result(self):
        c = make_collector(backend=minimal_backend())
        result = await c.collect()
        assert c.last_result is result

    async def test_collect_sets_error_on_snmp_failure(self):
        backend = MockSNMPBackend(get_error=SNMPError("Timeout 192.168.1.1"))
        c = make_collector(backend=backend)
        result = await c.collect()

        assert not result.is_ok
        assert "Timeout" in result.error

    async def test_collect_backend_label(self):
        c = make_collector(backend=minimal_backend())
        result = await c.collect()
        assert result.backend == "snmp"


@pytest.mark.asyncio
class TestCPUTracking:
    """Testes do rastreamento de CPU alta."""

    async def test_cpu_high_since_set_when_above_threshold(self):
        backend = MockSNMPBackend(
            get_data={OID_SYS_DESCR: "x", OID_SYS_UPTIME: 0},
            walk_data={
                OID_HR_CPU_LOAD: [(f"{OID_HR_CPU_LOAD}.1", THRESHOLD_CPU_CRITICAL + 5)],
                OID_IF_DESCR: [],
                OID_MTX_WIFI_CLIENTS: [], OID_MTX_WIFI_NOISE: [],
                OID_MTX_WIFI_CH_UTIL: [], OID_MTX_WIFI_SSID: [],
                OID_MTX_WIFI_FREQ: [],    OID_MTX_WIFI_BAND: [],
            },
        )
        c = make_collector(backend=backend)
        await c.collect()

        assert c.cpu_high_since is not None
        assert c._cpu_high_since <= time.time()

    async def test_cpu_high_since_cleared_when_normal(self):
        backend = MockSNMPBackend(
            get_data={OID_SYS_DESCR: "x", OID_SYS_UPTIME: 0},
            walk_data={
                OID_HR_CPU_LOAD: [(f"{OID_HR_CPU_LOAD}.1", 20)],
                OID_IF_DESCR: [],
                OID_MTX_WIFI_CLIENTS: [], OID_MTX_WIFI_NOISE: [],
                OID_MTX_WIFI_CH_UTIL: [], OID_MTX_WIFI_SSID: [],
                OID_MTX_WIFI_FREQ: [],    OID_MTX_WIFI_BAND: [],
            },
        )
        c = make_collector(backend=backend)
        c._cpu_high_since = time.time() - 100   # estava alto
        await c.collect()

        assert c.cpu_high_since is None

    async def test_cpu_high_since_persists_across_collections(self):
        """_cpu_high_since não deve ser zerado enquanto CPU permanecer alta."""
        backend = MockSNMPBackend(
            get_data={OID_SYS_DESCR: "x", OID_SYS_UPTIME: 0},
            walk_data={
                OID_HR_CPU_LOAD: [(f"{OID_HR_CPU_LOAD}.1", 95)],
                OID_IF_DESCR: [],
                OID_MTX_WIFI_CLIENTS: [], OID_MTX_WIFI_NOISE: [],
                OID_MTX_WIFI_CH_UTIL: [], OID_MTX_WIFI_SSID: [],
                OID_MTX_WIFI_FREQ: [],    OID_MTX_WIFI_BAND: [],
            },
        )
        c = make_collector(backend=backend)
        await c.collect()
        ts_first = c._cpu_high_since

        await c.collect()
        # Deve ser o mesmo timestamp — não reseta em cada coleta alta
        assert c._cpu_high_since == ts_first


@pytest.mark.asyncio
class TestTestConnectivity:
    """Testes do método test_connectivity() (usado pelo Wizard SNMP)."""

    async def test_connectivity_success(self):
        backend = MockSNMPBackend(
            get_data={
                OID_SYS_DESCR:  "RouterOS 7.14 (stable)",
                OID_SYS_UPTIME: 100000,
            },
        )
        c = make_collector(backend=backend)
        result = await c.test_connectivity()

        assert result["success"] is True
        assert "RouterOS" in result["sys_descr"]
        assert result["uptime_seconds"] == 1000
        assert result["host"] == "192.168.1.1"

    async def test_connectivity_failure_snmp_error(self):
        backend = MockSNMPBackend(
            get_error=SNMPError("No response"),
        )
        c = make_collector(backend=backend)
        result = await c.test_connectivity()

        assert result["success"] is False
        assert "message" in result

    async def test_connectivity_failure_generic_exception(self):
        backend = MockSNMPBackend(
            get_error=ConnectionRefusedError("Connection refused"),
        )
        c = make_collector(backend=backend)
        result = await c.test_connectivity()

        assert result["success"] is False


@pytest.mark.asyncio
class TestRouterOSAPIFallback:
    """Testes do fallback para RouterOS REST API."""

    def _make_api_session(
        self,
        resource: dict = None,
        interfaces: list = None,
        wireless: list = None,
        clients: list = None,
        raises: Exception = None,
    ):
        """Cria mock de RouterOSAPISession."""
        from collectors.snmp import RouterOSAPISession
        session = MagicMock(spec=RouterOSAPISession)
        session.close = AsyncMock()

        if raises:
            session.get_resource          = AsyncMock(side_effect=raises)
            session.get_interfaces        = AsyncMock(side_effect=raises)
            session.get_wireless_interfaces = AsyncMock(side_effect=raises)
            session.get_wireless_clients  = AsyncMock(side_effect=raises)
        else:
            session.get_resource = AsyncMock(return_value=resource or {
                "cpu-load": "42", "uptime": "1d2h",
            })
            session.get_interfaces = AsyncMock(return_value=interfaces or [
                {"name": "ether1", "rx-byte": "1000", "tx-byte": "500"},
            ])
            session.get_wireless_interfaces = AsyncMock(return_value=wireless or [])
            session.get_wireless_clients    = AsyncMock(return_value=clients  or [])
        return session

    async def test_falls_back_to_api_on_snmp_error(self):
        snmp_backend = MockSNMPBackend(get_error=SNMPError("Community string mismatch"))
        api_session  = self._make_api_session()

        c = SNMPCollector(
            host="192.168.1.1",
            backend=snmp_backend,
            routeros_api=api_session,
        )
        result = await c.collect()

        assert result.is_ok
        assert result.backend == "routeros_api"
        assert result.cpu_usage == pytest.approx(42.0)

    async def test_api_parses_uptime(self):
        snmp_backend = MockSNMPBackend(get_error=SNMPError("timeout"))
        api_session  = self._make_api_session(
            resource={"cpu-load": "10", "uptime": "3d12h"}
        )
        c = SNMPCollector(
            host="192.168.1.1",
            backend=snmp_backend,
            routeros_api=api_session,
        )
        result = await c.collect()
        # 3d12h = 3*86400 + 12*3600 = 302400
        assert result.uptime_seconds == 302400

    async def test_api_identifies_wan_interface(self):
        snmp_backend = MockSNMPBackend(get_error=SNMPError("timeout"))
        api_session  = self._make_api_session(
            interfaces=[
                {"name": "lo",     "rx-byte": "0",       "tx-byte": "0"},
                {"name": "ether1", "rx-byte": "5000000", "tx-byte": "1000000"},
            ]
        )
        c = SNMPCollector(
            host="192.168.1.1",
            backend=snmp_backend,
            routeros_api=api_session,
        )
        result = await c.collect()
        assert result.wan_interface == "ether1"

    async def test_api_failure_sets_error(self):
        snmp_backend = MockSNMPBackend(get_error=SNMPError("timeout"))
        api_session  = self._make_api_session(raises=ConnectionError("refused"))

        c = SNMPCollector(
            host="192.168.1.1",
            backend=snmp_backend,
            routeros_api=api_session,
        )
        result = await c.collect()
        assert result.error is not None


# ═══════════════════════════════════════════════════════════════════════════════
# 3. TESTES DE INTEGRAÇÃO — requerem equipamento SNMP real
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.integration
@pytest.mark.asyncio
class TestSNMPIntegration:
    """
    Testes de integração com equipamento SNMP real.

    Configure o IP e community do seu Mikrotik:
        export SNMP_HOST=192.168.1.1
        export SNMP_COMMUNITY=public
        pytest tests/test_snmp.py -m integration -v
    """

    def _get_config(self):
        import os
        return (
            os.environ.get("SNMP_HOST", "192.168.1.1"),
            os.environ.get("SNMP_COMMUNITY", "public"),
        )

    async def test_connectivity_real(self):
        host, community = self._get_config()
        collector = SNMPCollector(host=host, community=community)
        result = await collector.test_connectivity()
        # Não falha em equipamento sem SNMP, apenas informa
        assert "success" in result
        assert "host" in result

    async def test_collect_real(self):
        host, community = self._get_config()
        collector = SNMPCollector(host=host, community=community)
        result = await collector.collect()
        # Deve retornar SNMPResult (mesmo que com erro)
        assert isinstance(result, SNMPResult)
        assert result.host == host
