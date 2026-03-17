"""
tests/test_dns.py — Testes do DNSCollector.

Testa estatísticas de resolver, detecção de DNS lento/rápido
e diagnóstico preliminar de problemas.
"""

import pytest
from collectors.dns import (
    DNSCollector,
    DNSQueryResult,
    DNSResolverStats,
    DNSComparisonResult,
    THRESHOLD_SLOW_MS,
    THRESHOLD_FAST_MS,
)


class TestDNSResolverStats:
    """Testes de estatísticas de resolver."""

    def _make_stats(self, latencies, name="test", ip="1.2.3.4"):
        stats = DNSResolverStats(name=name, ip=ip)
        for ms in latencies:
            q = DNSQueryResult(resolver=name, resolver_ip=ip, domain="google.com")
            q.latency_ms = ms
            q.success = ms is not None
            stats.queries.append(q)
        return stats

    def test_avg_latency_normal(self):
        stats = self._make_stats([10.0, 20.0, 30.0])
        assert stats.avg_latency_ms == pytest.approx(20.0)

    def test_avg_latency_none_when_no_success(self):
        stats = DNSResolverStats(name="test", ip="1.2.3.4")
        q = DNSQueryResult(resolver="test", resolver_ip="1.2.3.4", domain="test.com")
        q.success = False
        q.latency_ms = None
        stats.queries.append(q)
        assert stats.avg_latency_ms is None

    def test_is_slow(self):
        stats = self._make_stats([THRESHOLD_SLOW_MS + 10.0])
        assert stats.is_slow is True

    def test_is_not_slow(self):
        stats = self._make_stats([THRESHOLD_SLOW_MS - 10.0])
        assert stats.is_slow is False

    def test_is_fast(self):
        stats = self._make_stats([THRESHOLD_FAST_MS - 5.0])
        assert stats.is_fast is True

    def test_success_rate(self):
        stats = self._make_stats([10.0, 20.0])
        # todas com success=True pois latency != None
        assert stats.success_rate == pytest.approx(1.0)

    def test_success_rate_empty(self):
        stats = DNSResolverStats(name="test", ip="1.2.3.4")
        assert stats.success_rate == 0.0


class TestDNSPreliminaryDiagnosis:
    """Testes do diagnóstico preliminar de DNS."""

    def _make_comparison(self, internal_ms, external_ms):
        comparison = DNSComparisonResult()
        interno = DNSResolverStats(name="interno", ip="192.168.1.1")
        externo = DNSResolverStats(name="cloudflare", ip="1.1.1.1")

        q_int = DNSQueryResult(resolver="interno", resolver_ip="192.168.1.1", domain="g.com")
        q_int.latency_ms = internal_ms
        q_int.success = True
        interno.queries.append(q_int)

        q_ext = DNSQueryResult(resolver="cloudflare", resolver_ip="1.1.1.1", domain="g.com")
        q_ext.latency_ms = external_ms
        q_ext.success = True
        externo.queries.append(q_ext)

        comparison.resolvers["interno"] = interno
        comparison.resolvers["cloudflare"] = externo
        return comparison

    def test_router_overload_diagnosis(self):
        """DNS interno lento + externo rápido → Warning."""
        comparison = self._make_comparison(
            internal_ms=THRESHOLD_SLOW_MS + 50,
            external_ms=THRESHOLD_FAST_MS - 5,
        )
        collector = DNSCollector()
        collector._apply_preliminary_diagnosis(comparison)
        assert comparison.severity == "Warning"
        assert "sobrecarregado" in comparison.diagnosis.lower()

    def test_isp_route_diagnosis(self):
        """DNS interno rápido + externo lento → Info."""
        comparison = self._make_comparison(
            internal_ms=THRESHOLD_FAST_MS - 5,
            external_ms=THRESHOLD_SLOW_MS + 50,
        )
        collector = DNSCollector()
        collector._apply_preliminary_diagnosis(comparison)
        assert comparison.severity == "Info"

    def test_normal_dns_no_severity(self):
        """DNS normal → sem severidade."""
        comparison = self._make_comparison(
            internal_ms=20.0,
            external_ms=15.0,
        )
        collector = DNSCollector()
        collector._apply_preliminary_diagnosis(comparison)
        assert comparison.severity is None


class TestDNSCollectorDetection:
    """Testes de detecção de resolver interno."""

    def test_detect_internal_resolver(self, tmp_path):
        resolv_conf = tmp_path / "resolv.conf"
        resolv_conf.write_text("nameserver 192.168.1.1\nnameserver 8.8.8.8\n")

        collector = DNSCollector()
        # Injeta o caminho do arquivo temporário
        import builtins
        import unittest.mock as mock

        with mock.patch("builtins.open", mock.mock_open(read_data="nameserver 192.168.1.1\n")):
            ip = collector.detect_internal_resolver()

        assert ip == "192.168.1.1"
