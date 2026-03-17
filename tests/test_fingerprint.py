"""
tests/test_fingerprint.py — Testes unitários para collectors/fingerprint.py.

Execução:
    python3 -m pytest tests/test_fingerprint.py -v -m "not integration"

Cobertura:
  - OUIDatabase.lookup() — vários formatos de MAC
  - Device — display_name, mac_normalized, oui, to_dict
  - FingerprintCollector.classify_device() — 3 camadas (vendor, hostname, mDNS)
  - FingerprintCollector.detect_network() — mock subprocess
  - FingerprintCollector.arp_scan() — fallback chain mockado
  - FingerprintCollector._arp_from_neigh() — parsing de ip neigh
  - FingerprintCollector.resolve_hostname_mdns() — mock subprocess
  - FingerprintCollector.scan() — fluxo completo mockado
  - Integração: detect_network() real (marcado @pytest.mark.integration)
"""

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from collectors.fingerprint import (
    DEVICE_TYPES,
    Device,
    FingerprintCollector,
    NetworkRange,
    OUIDatabase,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_collector(**kwargs) -> FingerprintCollector:
    """Cria FingerprintCollector mínimo para testes."""
    kwargs.setdefault("network", "192.168.1.0/24")
    return FingerprintCollector(**kwargs)


def make_device(
    ip: str = "192.168.1.10",
    mac: str = "aa:bb:cc:dd:ee:ff",
    hostname: str | None = None,
    vendor: str | None = None,
    mdns_services: list | None = None,
) -> Device:
    d = Device(ip=ip, mac=mac, hostname=hostname, vendor=vendor)
    d.mdns_services = mdns_services or []
    return d


# Conteúdo de OUI fake para testes
OUI_FILE_CONTENT = """\
00-50-56   (hex)\tVMware, Inc.
B8-27-EB   (hex)\tRaspberry Pi Foundation
DC-A6-32   (hex)\tRaspberry Pi Trading Ltd
"""


# ---------------------------------------------------------------------------
# TestOUIDatabase
# ---------------------------------------------------------------------------

class TestOUIDatabase:
    def test_lookup_colon_format(self, tmp_path):
        f = tmp_path / "oui.txt"
        f.write_text(OUI_FILE_CONTENT)
        db = OUIDatabase(str(f))
        assert db.lookup("00:50:56:11:22:33") == "VMware, Inc."

    def test_lookup_dash_format(self, tmp_path):
        f = tmp_path / "oui.txt"
        f.write_text(OUI_FILE_CONTENT)
        db = OUIDatabase(str(f))
        assert db.lookup("B8-27-EB-AA-BB-CC") == "Raspberry Pi Foundation"

    def test_lookup_case_insensitive(self, tmp_path):
        f = tmp_path / "oui.txt"
        f.write_text(OUI_FILE_CONTENT)
        db = OUIDatabase(str(f))
        assert db.lookup("b8:27:eb:00:00:00") == "Raspberry Pi Foundation"

    def test_lookup_compact_format(self, tmp_path):
        f = tmp_path / "oui.txt"
        f.write_text(OUI_FILE_CONTENT)
        db = OUIDatabase(str(f))
        assert db.lookup("DCA632AABBCC") == "Raspberry Pi Trading Ltd"

    def test_lookup_unknown_returns_none(self, tmp_path):
        f = tmp_path / "oui.txt"
        f.write_text(OUI_FILE_CONTENT)
        db = OUIDatabase(str(f))
        assert db.lookup("FF:FF:FF:00:00:00") is None

    def test_empty_db_returns_none(self):
        db = OUIDatabase()
        assert db.lookup("00:50:56:11:22:33") is None

    def test_size_reflects_loaded_records(self, tmp_path):
        f = tmp_path / "oui.txt"
        f.write_text(OUI_FILE_CONTENT)
        db = OUIDatabase(str(f))
        assert db.size == 3

    def test_missing_file_does_not_crash(self):
        db = OUIDatabase("/nonexistent/path/oui.txt")
        assert db.size == 0

    def test_lookup_invalid_mac_returns_none(self):
        db = OUIDatabase()
        assert db.lookup("not-a-mac") is None


# ---------------------------------------------------------------------------
# TestDevice
# ---------------------------------------------------------------------------

class TestDevice:
    def test_display_name_uses_hostname_first(self):
        d = make_device(hostname="my-phone", vendor="Apple", ip="10.0.0.1")
        assert d.display_name == "my-phone"

    def test_display_name_falls_back_to_vendor(self):
        d = make_device(vendor="Apple", ip="10.0.0.1")
        assert d.display_name == "Apple"

    def test_display_name_falls_back_to_ip(self):
        d = make_device(ip="10.0.0.5")
        assert d.display_name == "10.0.0.5"

    def test_mac_normalized_uppercase(self):
        d = make_device(mac="aa:bb:cc:dd:ee:ff")
        assert d.mac_normalized == "AA:BB:CC:DD:EE:FF"

    def test_oui_first_three_octets(self):
        d = make_device(mac="b8:27:eb:12:34:56")
        assert d.oui == "B8:27:EB"

    def test_to_dict_contains_required_keys(self):
        d = make_device(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:ff",
                        hostname="router", vendor="MikroTik")
        d.device_type = "router"
        d.device_type_label = "Roteador / AP"
        data = d.to_dict()
        for key in ("ip", "mac", "hostname", "vendor", "device_type",
                    "device_type_label", "display_name", "last_seen"):
            assert key in data

    def test_to_dict_mac_normalized(self):
        d = make_device(mac="aa:bb:cc:dd:ee:ff")
        assert d.to_dict()["mac"] == "AA:BB:CC:DD:EE:FF"

    def test_timestamps_set_on_creation(self):
        before = time.time()
        d = Device(ip="1.2.3.4", mac="aa:bb:cc:dd:ee:ff")
        after = time.time()
        assert before <= d.first_seen <= after
        assert before <= d.last_seen <= after


# ---------------------------------------------------------------------------
# TestClassifyDevice
# ---------------------------------------------------------------------------

class TestClassifyDevice:
    def setup_method(self):
        self.c = make_collector()

    # Camada 1: Vendor
    def test_mikrotik_classified_as_router(self):
        d = make_device(vendor="MikroTik")
        assert self.c.classify_device(d) == "router"

    def test_tplink_classified_as_router(self):
        d = make_device(vendor="TP-LINK Technologies")
        assert self.c.classify_device(d) == "router"

    def test_apple_classified_as_phone(self):
        d = make_device(vendor="Apple, Inc.")
        assert self.c.classify_device(d) == "phone"

    def test_samsung_classified_as_phone(self):
        d = make_device(vendor="Samsung Electronics")
        assert self.c.classify_device(d) == "phone"

    def test_raspberry_classified_as_iot(self):
        d = make_device(vendor="Raspberry Pi Foundation")
        assert self.c.classify_device(d) == "iot"

    def test_sony_classified_as_tv(self):
        d = make_device(vendor="Sony Corporation")
        assert self.c.classify_device(d) == "tv"

    def test_epson_classified_as_printer(self):
        d = make_device(vendor="Epson Imaging Devices")
        assert self.c.classify_device(d) == "printer"

    # Camada 2: Hostname
    def test_iphone_hostname_classified_as_phone(self):
        d = make_device(hostname="Joao-iPhone")
        assert self.c.classify_device(d) == "phone"

    def test_macbook_hostname_classified_as_laptop(self):
        d = make_device(hostname="MacBook-Pro-2023")
        assert self.c.classify_device(d) == "laptop"

    def test_smarttv_hostname_classified_as_tv(self):
        d = make_device(hostname="my-smarttv")
        assert self.c.classify_device(d) == "tv"

    def test_mikrotik_hostname_classified_as_router(self):
        d = make_device(hostname="MikroTik-Home")
        assert self.c.classify_device(d) == "router"

    def test_synology_hostname_classified_as_nas(self):
        d = make_device(hostname="synology-NAS")
        assert self.c.classify_device(d) == "nas"

    def test_alexa_hostname_classified_as_iot(self):
        d = make_device(hostname="alexa-kitchen")
        assert self.c.classify_device(d) == "iot"

    # Camada 3: mDNS services
    def test_airplay_service_classified_as_tv(self):
        d = make_device(mdns_services=["_airplay._tcp.local."])
        assert self.c.classify_device(d) == "tv"

    def test_ipp_service_classified_as_printer(self):
        d = make_device(mdns_services=["_ipp._tcp.local."])
        assert self.c.classify_device(d) == "printer"

    def test_smb_service_classified_as_nas(self):
        d = make_device(mdns_services=["_smb._tcp.local."])
        assert self.c.classify_device(d) == "nas"

    def test_unknown_when_no_hints(self):
        d = make_device()   # sem vendor, hostname ou mDNS
        assert self.c.classify_device(d) == "unknown"

    def test_vendor_takes_priority_over_hostname(self):
        # Hostname sugere router mas vendor diz phone → vendor vence (ordem 1 > 2)
        d = make_device(vendor="Apple, Inc.", hostname="router-box")
        assert self.c.classify_device(d) == "phone"


# ---------------------------------------------------------------------------
# TestDetectNetwork (async)
# ---------------------------------------------------------------------------

class TestDetectNetwork:
    ROUTE_OUTPUT = (
        "8.8.8.8 via 192.168.1.1 dev eth0 src 192.168.1.100 uid 0\n"
        "    cache\n"
    ).encode()

    ADDR_OUTPUT = (
        "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
        "    link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff\n"
        "    inet 192.168.1.100/24 brd 192.168.1.255 scope global dynamic eth0\n"
    ).encode()

    def _make_proc(self, stdout: bytes, returncode: int = 0):
        proc = AsyncMock()
        proc.communicate = AsyncMock(return_value=(stdout, b""))
        proc.returncode = returncode
        return proc

    async def test_detects_network_correctly(self):
        c = FingerprintCollector()
        route_proc = self._make_proc(self.ROUTE_OUTPUT)
        addr_proc = self._make_proc(self.ADDR_OUTPUT)

        with patch("asyncio.create_subprocess_exec",
                   side_effect=[route_proc, addr_proc]):
            result = await c.detect_network()

        assert result is not None
        assert result.gateway_ip == "192.168.1.1"
        assert result.interface == "eth0"
        assert result.local_ip == "192.168.1.100"
        assert result.network == "192.168.1.0/24"
        assert result.prefix_len == 24

    async def test_returns_none_on_malformed_route_output(self):
        c = FingerprintCollector()
        proc = self._make_proc(b"no useful info here\n")

        with patch("asyncio.create_subprocess_exec", return_value=proc):
            result = await c.detect_network()

        assert result is None

    async def test_returns_none_on_exception(self):
        c = FingerprintCollector()
        with patch("asyncio.create_subprocess_exec",
                   side_effect=FileNotFoundError("ip not found")):
            result = await c.detect_network()
        assert result is None


# ---------------------------------------------------------------------------
# TestArpScan (async)
# ---------------------------------------------------------------------------

class TestArpScan:
    async def test_uses_arpscan_when_available(self):
        arpscan_output = (
            "192.168.1.1\taa:bb:cc:dd:ee:ff\tMikroTik\n"
            "192.168.1.10\t11:22:33:44:55:66\tApple\n"
        ).encode()

        proc = AsyncMock()
        proc.communicate = AsyncMock(return_value=(arpscan_output, b""))

        c = make_collector()
        with patch("asyncio.create_subprocess_exec", return_value=proc):
            hosts = await c._arp_scan_arpscan("192.168.1.0/24")

        assert len(hosts) == 2
        assert ("192.168.1.1", "aa:bb:cc:dd:ee:ff") in hosts
        assert ("192.168.1.10", "11:22:33:44:55:66") in hosts

    async def test_arpscan_returns_empty_on_not_found(self):
        c = make_collector()
        with patch("asyncio.create_subprocess_exec",
                   side_effect=FileNotFoundError):
            hosts = await c._arp_scan_arpscan("192.168.1.0/24")
        assert hosts == []

    async def test_arp_from_neigh_parses_reachable(self):
        neigh_output = (
            "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n"
            "192.168.1.10 dev eth0 lladdr 11:22:33:44:55:66 STALE\n"
            "192.168.1.20 dev eth0 lladdr 77:88:99:aa:bb:cc FAILED\n"
        ).encode()

        proc = AsyncMock()
        proc.communicate = AsyncMock(return_value=(neigh_output, b""))

        c = make_collector()
        with patch("asyncio.create_subprocess_exec", return_value=proc):
            hosts = await c._arp_from_neigh()

        assert len(hosts) == 2
        ips = [h[0] for h in hosts]
        assert "192.168.1.1" in ips
        assert "192.168.1.10" in ips
        assert "192.168.1.20" not in ips

    async def test_arp_from_neigh_returns_empty_on_exception(self):
        c = make_collector()
        with patch("asyncio.create_subprocess_exec",
                   side_effect=OSError("no ip")):
            hosts = await c._arp_from_neigh()
        assert hosts == []

    async def test_arp_scan_falls_through_to_neigh(self):
        """Se arpscan e scapy falham, cai em ip neigh show."""
        neigh_output = (
            "192.168.1.5 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n"
        ).encode()

        proc = AsyncMock()
        proc.communicate = AsyncMock(return_value=(neigh_output, b""))

        c = make_collector()
        with patch.object(c, "_arp_scan_arpscan", AsyncMock(return_value=[])), \
             patch.object(c, "_arp_scan_scapy", AsyncMock(return_value=[])), \
             patch("asyncio.create_subprocess_exec", return_value=proc):
            hosts = await c.arp_scan("192.168.1.0/24")

        assert len(hosts) == 1


# ---------------------------------------------------------------------------
# TestResolveHostname (async)
# ---------------------------------------------------------------------------

class TestResolveHostname:
    async def test_avahi_resolves_mdns(self):
        avahi_output = b"192.168.1.1\tmy-router.local\n"
        proc = AsyncMock()
        proc.communicate = AsyncMock(return_value=(avahi_output, b""))

        c = make_collector()
        with patch("asyncio.create_subprocess_exec", return_value=proc):
            hostname = await c._avahi_resolve("192.168.1.1")

        assert hostname == "my-router.local"

    async def test_avahi_returns_none_when_not_found(self):
        proc = AsyncMock()
        proc.communicate = AsyncMock(return_value=(b"", b""))

        c = make_collector()
        with patch("asyncio.create_subprocess_exec", return_value=proc):
            hostname = await c._avahi_resolve("192.168.1.1")

        assert hostname is None

    async def test_avahi_returns_none_on_not_installed(self):
        c = make_collector()
        with patch("asyncio.create_subprocess_exec",
                   side_effect=FileNotFoundError):
            hostname = await c._avahi_resolve("192.168.1.1")
        assert hostname is None

    async def test_socket_reverse_returns_hostname(self):
        c = make_collector()
        with patch("socket.getfqdn", return_value="my-device.home"):
            hostname = await c._socket_reverse_lookup("192.168.1.50")
        assert hostname == "my-device.home"

    async def test_socket_reverse_returns_none_when_same_as_ip(self):
        c = make_collector()
        with patch("socket.getfqdn", return_value="192.168.1.50"):
            hostname = await c._socket_reverse_lookup("192.168.1.50")
        assert hostname is None

    async def test_host_cmd_lookup_parses_ptr(self):
        host_output = (
            b"1.1.168.192.in-addr.arpa domain name pointer my-router.local.\n"
        )
        proc = AsyncMock()
        proc.communicate = AsyncMock(return_value=(host_output, b""))

        c = make_collector()
        with patch("asyncio.create_subprocess_exec", return_value=proc):
            hostname = await c._host_cmd_lookup("192.168.1.1")

        assert hostname == "my-router.local"

    async def test_resolve_hostname_tries_avahi_first(self):
        """avahi retorna hostname → não chama socket nem host."""
        c = make_collector()
        with patch.object(c, "_avahi_resolve",
                          AsyncMock(return_value="device.local")), \
             patch.object(c, "_socket_reverse_lookup",
                          AsyncMock(return_value="other.local")), \
             patch.object(c, "_host_cmd_lookup",
                          AsyncMock(return_value="third.local")):
            result = await c.resolve_hostname_mdns("192.168.1.1")
        assert result == "device.local"

    async def test_resolve_hostname_falls_through_to_host_cmd(self):
        c = make_collector()
        with patch.object(c, "_avahi_resolve", AsyncMock(return_value=None)), \
             patch.object(c, "_socket_reverse_lookup", AsyncMock(return_value=None)), \
             patch.object(c, "_host_cmd_lookup",
                          AsyncMock(return_value="via-host.local")):
            result = await c.resolve_hostname_mdns("192.168.1.1")
        assert result == "via-host.local"


# ---------------------------------------------------------------------------
# TestScan (async — fluxo completo)
# ---------------------------------------------------------------------------

class TestScan:
    async def test_discovers_new_device(self):
        c = make_collector(network="192.168.1.0/24")
        with patch.object(c, "arp_scan",
                          AsyncMock(return_value=[("192.168.1.5", "aa:bb:cc:dd:ee:ff")])), \
             patch.object(c, "resolve_hostname_mdns", AsyncMock(return_value=None)):
            devices = await c.scan()

        assert len(devices) == 1
        assert devices[0].ip == "192.168.1.5"
        assert devices[0].mac == "aa:bb:cc:dd:ee:ff"

    async def test_updates_existing_device_ip(self):
        c = make_collector()
        c._devices["aa:bb:cc:dd:ee:ff"] = make_device(ip="192.168.1.5")

        with patch.object(c, "arp_scan",
                          AsyncMock(return_value=[("192.168.1.99", "aa:bb:cc:dd:ee:ff")])), \
             patch.object(c, "resolve_hostname_mdns", AsyncMock(return_value=None)):
            await c.scan()

        assert c._devices["aa:bb:cc:dd:ee:ff"].ip == "192.168.1.99"

    async def test_resolves_hostname_for_new_device(self):
        c = make_collector()
        with patch.object(c, "arp_scan",
                          AsyncMock(return_value=[("192.168.1.5", "aa:bb:cc:dd:ee:ff")])), \
             patch.object(c, "resolve_hostname_mdns",
                          AsyncMock(return_value="my-laptop.local")):
            devices = await c.scan()

        assert devices[0].hostname == "my-laptop.local"

    async def test_skips_hostname_if_already_set(self):
        c = make_collector()
        c._devices["aa:bb:cc:dd:ee:ff"] = make_device(
            ip="192.168.1.5", hostname="already-set"
        )
        mock_resolve = AsyncMock(return_value="new-hostname")

        with patch.object(c, "arp_scan",
                          AsyncMock(return_value=[("192.168.1.5", "aa:bb:cc:dd:ee:ff")])), \
             patch.object(c, "resolve_hostname_mdns", mock_resolve):
            await c.scan()

        mock_resolve.assert_not_called()
        assert c._devices["aa:bb:cc:dd:ee:ff"].hostname == "already-set"

    async def test_increments_miss_count_for_absent_device(self):
        c = make_collector()
        c._devices["aa:bb:cc:dd:ee:ff"] = make_device(ip="192.168.1.5")

        with patch.object(c, "arp_scan", AsyncMock(return_value=[])):
            await c.scan()

        assert c.miss_count("aa:bb:cc:dd:ee:ff") == 1

        with patch.object(c, "arp_scan", AsyncMock(return_value=[])):
            await c.scan()

        assert c.miss_count("aa:bb:cc:dd:ee:ff") == 2

    async def test_resets_miss_count_when_device_returns(self):
        c = make_collector()
        c._devices["aa:bb:cc:dd:ee:ff"] = make_device(ip="192.168.1.5")
        c._miss_counts["aa:bb:cc:dd:ee:ff"] = 5

        with patch.object(c, "arp_scan",
                          AsyncMock(return_value=[("192.168.1.5", "aa:bb:cc:dd:ee:ff")])), \
             patch.object(c, "resolve_hostname_mdns", AsyncMock(return_value=None)):
            await c.scan()

        assert c.miss_count("aa:bb:cc:dd:ee:ff") == 0

    async def test_returns_empty_list_without_network(self):
        c = FingerprintCollector(network=None)
        with patch.object(c, "detect_network", AsyncMock(return_value=None)):
            devices = await c.scan()
        assert devices == []

    async def test_auto_detects_network_if_not_set(self):
        c = FingerprintCollector(network=None)
        net = NetworkRange("eth0", "192.168.1.100", "192.168.1.1",
                           "192.168.1.0/24", 24)
        with patch.object(c, "detect_network", AsyncMock(return_value=net)), \
             patch.object(c, "arp_scan", AsyncMock(return_value=[])):
            await c.scan()
        assert c.network == "192.168.1.0/24"

    async def test_classifies_device_type(self):
        c = make_collector()
        with patch.object(c, "arp_scan",
                          AsyncMock(return_value=[("192.168.1.1", "dc:a6:32:12:34:56")])), \
             patch.object(c, "resolve_hostname_mdns", AsyncMock(return_value=None)):
            # dc:a6:32 = Raspberry Pi (se OUI db vazia, sem vendor → unknown)
            devices = await c.scan()
        assert devices[0].device_type in DEVICE_TYPES

    async def test_saves_to_db(self):
        mock_db = AsyncMock()
        c = make_collector(db=mock_db)
        with patch.object(c, "arp_scan",
                          AsyncMock(return_value=[("192.168.1.5", "aa:bb:cc:dd:ee:ff")])), \
             patch.object(c, "resolve_hostname_mdns", AsyncMock(return_value=None)):
            await c.scan()
        mock_db.save_devices.assert_called_once()

    async def test_db_error_does_not_crash(self):
        mock_db = AsyncMock()
        mock_db.save_devices.side_effect = RuntimeError("db error")
        c = make_collector(db=mock_db)
        with patch.object(c, "arp_scan",
                          AsyncMock(return_value=[("192.168.1.5", "aa:bb:cc:dd:ee:ff")])), \
             patch.object(c, "resolve_hostname_mdns", AsyncMock(return_value=None)):
            devices = await c.scan()
        assert len(devices) == 1


# ---------------------------------------------------------------------------
# TestGetDeviceAndMissCount
# ---------------------------------------------------------------------------

class TestGetDeviceAndMissCount:
    def test_get_device_by_mac(self):
        c = make_collector()
        d = make_device(mac="aa:bb:cc:dd:ee:ff")
        c._devices["aa:bb:cc:dd:ee:ff"] = d
        assert c.get_device("AA:BB:CC:DD:EE:FF") is d

    def test_get_device_returns_none_when_missing(self):
        c = make_collector()
        assert c.get_device("00:00:00:00:00:00") is None

    def test_miss_count_zero_initially(self):
        c = make_collector()
        assert c.miss_count("aa:bb:cc:dd:ee:ff") == 0

    def test_devices_property_returns_list(self):
        c = make_collector()
        c._devices["aa:bb:cc:dd:ee:ff"] = make_device()
        c._devices["11:22:33:44:55:66"] = make_device(mac="11:22:33:44:55:66")
        assert len(c.devices) == 2


# ---------------------------------------------------------------------------
# TestIntegration — requer rede real
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestFingerprintIntegration:
    async def test_detect_network_real(self):
        """Detecta a rede local — requer sistema com ip instalado."""
        c = FingerprintCollector()
        result = await c.detect_network()
        assert result is not None, "Falha na detecção de rede — ip route disponível?"
        assert result.gateway_ip
        assert result.network
        assert "/" in result.network

    async def test_arp_from_neigh_real(self):
        """Lê cache ARP real — pelo menos gateway deve estar presente."""
        c = FingerprintCollector()
        hosts = await c._arp_from_neigh()
        # Em ambiente sem internet, pode ser vazia — apenas valida sem crash
        assert isinstance(hosts, list)
