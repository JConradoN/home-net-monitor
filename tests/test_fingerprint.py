"""
tests/test_fingerprint.py — Testes do FingerprintCollector.

Testa OUI lookup, classificação de dispositivos por heurística
e normalização de MAC addresses.
"""

import pytest
from collectors.fingerprint import (
    Device,
    FingerprintCollector,
    OUIDatabase,
    DEVICE_TYPES,
)


class TestOUIDatabase:
    """Testes do banco de dados OUI."""

    def test_lookup_returns_none_for_unknown_mac(self):
        db = OUIDatabase()
        result = db.lookup("AA:BB:CC:11:22:33")
        assert result is None

    def test_lookup_normalizes_mac_formats(self):
        db = OUIDatabase()
        db._db["AA:BB:CC"] = "TestVendor"
        assert db.lookup("AA:BB:CC:11:22:33") == "TestVendor"
        assert db.lookup("aa:bb:cc:11:22:33") == "TestVendor"
        assert db.lookup("AA-BB-CC-11-22-33") == "TestVendor"


class TestDevice:
    """Testes do dataclass Device."""

    def test_display_name_uses_hostname_first(self):
        d = Device(ip="192.168.1.10", mac="aa:bb:cc:dd:ee:ff")
        d.hostname = "my-laptop"
        d.vendor = "Apple"
        assert d.display_name == "my-laptop"

    def test_display_name_falls_back_to_vendor(self):
        d = Device(ip="192.168.1.10", mac="aa:bb:cc:dd:ee:ff")
        d.vendor = "Apple"
        assert d.display_name == "Apple"

    def test_display_name_falls_back_to_ip(self):
        d = Device(ip="192.168.1.10", mac="aa:bb:cc:dd:ee:ff")
        assert d.display_name == "192.168.1.10"

    def test_mac_normalized(self):
        d = Device(ip="1.1.1.1", mac="aa:bb:cc:dd:ee:ff")
        assert d.mac_normalized == "AA:BB:CC:DD:EE:FF"

    def test_oui_extraction(self):
        d = Device(ip="1.1.1.1", mac="aa:bb:cc:dd:ee:ff")
        assert d.oui == "AA:BB:CC"


class TestDeviceClassification:
    """Testes da classificação heurística de dispositivos."""

    def setup_method(self):
        self.collector = FingerprintCollector()

    def _make_device(self, vendor=None, hostname=None):
        d = Device(ip="192.168.1.1", mac="aa:bb:cc:00:00:01")
        d.vendor = vendor
        d.hostname = hostname
        return d

    def test_classify_mikrotik_as_router(self):
        d = self._make_device(vendor="MikroTik")
        assert self.collector.classify_device(d) == "router"

    def test_classify_tplink_as_router(self):
        d = self._make_device(vendor="TP-LINK Technologies")
        assert self.collector.classify_device(d) == "router"

    def test_classify_iphone_hostname_as_phone(self):
        d = self._make_device(hostname="iphone-joao")
        assert self.collector.classify_device(d) == "phone"

    def test_classify_samsung_as_phone(self):
        d = self._make_device(vendor="Samsung Electronics")
        assert self.collector.classify_device(d) == "phone"

    def test_classify_smarttv_hostname_as_tv(self):
        d = self._make_device(hostname="samsung-smarttv-sala")
        assert self.collector.classify_device(d) == "tv"

    def test_classify_mdns_airplay_as_tv(self):
        d = self._make_device()
        d.mdns_services = ["_airplay._tcp.local"]
        assert self.collector.classify_device(d) == "tv"

    def test_classify_printer_by_hostname(self):
        d = self._make_device(hostname="epson-printer-l3150")
        assert self.collector.classify_device(d) == "printer"

    def test_classify_unknown_when_no_hints(self):
        d = self._make_device(vendor="UnknownCorp", hostname="device-42")
        result = self.collector.classify_device(d)
        assert result == "unknown"

    def test_device_type_label_valid(self):
        d = self._make_device(vendor="MikroTik")
        dtype = self.collector.classify_device(d)
        label = DEVICE_TYPES.get(dtype)
        assert label is not None
