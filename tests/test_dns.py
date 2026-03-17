"""
tests/test_dns.py — Testes unitários para collectors/dns.py.

Execução:
    python3 -m pytest tests/test_dns.py -v -m "not integration"

Cobertura:
  - DNSQueryResult, DNSHijackResult, DNSResolverStats, DNSComparisonResult
  - DNSCollector.query() — com mock_query_func
  - DNSCollector.collect_resolver()
  - DNSCollector.detect_hijacking()
  - DNSCollector.collect() — fluxo completo
  - DNSCollector._apply_preliminary_diagnosis()
  - DNSCollector.detect_internal_resolver() — mock_open
  - Integração: query real para 1.1.1.1 (marcado @pytest.mark.integration)
"""

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, mock_open, patch

import pytest

from collectors.dns import (
    THRESHOLD_FAST_MS,
    THRESHOLD_SLOW_MS,
    DNSCollector,
    DNSComparisonResult,
    DNSHijackResult,
    DNSQueryResult,
    DNSResolverStats,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class MockQueryFunc:
    """
    Mock injetável para DNSCollector._query_func.

    Configura respostas por (resolver_ip, domain) e rastreia chamadas.
    Se a chave não for encontrada, retorna DEFAULT_ANSWERS.
    """

    DEFAULT_ANSWERS = ["1.2.3.4"]

    def __init__(
        self,
        responses: dict | None = None,    # {(ip, domain): list[str]}
        errors: dict | None = None,       # {(ip, domain): Exception}
        latency: float = 0.0,
    ):
        self.responses = responses or {}
        self.errors = errors or {}
        self.latency = latency
        self.calls: list[tuple] = []

    async def __call__(
        self, resolver_ip: str, domain: str, record_type: str = "A"
    ) -> list[str]:
        self.calls.append((resolver_ip, domain, record_type))
        if self.latency:
            await asyncio.sleep(self.latency)
        key = (resolver_ip, domain)
        if key in self.errors:
            raise self.errors[key]
        return self.responses.get(key, self.DEFAULT_ANSWERS)


def make_collector(**kwargs) -> DNSCollector:
    """Cria DNSCollector com resolvers mínimos para testes."""
    kwargs.setdefault("query_func", MockQueryFunc())
    kwargs.setdefault("resolvers", {
        "interno": "192.168.1.1",
        "cloudflare": "1.1.1.1",
    })
    kwargs.setdefault("test_domains", ["google.com", "cloudflare.com"])
    kwargs.setdefault("queries_per_resolver", 2)
    return DNSCollector(**kwargs)


def make_stats(
    name: str = "interno",
    ip: str = "192.168.1.1",
    latencies: list | None = None,
    successes: list | None = None,
) -> DNSResolverStats:
    """Cria DNSResolverStats com queries sintéticas."""
    stats = DNSResolverStats(name=name, ip=ip)
    latencies = latencies or [10.0]
    successes = successes or [True] * len(latencies)
    for lat, ok in zip(latencies, successes):
        q = DNSQueryResult(resolver=ip, resolver_ip=ip, domain="google.com")
        q.latency_ms = lat
        q.success = ok
        q.answer = "1.2.3.4" if ok else None
        q.error = None if ok else "timeout"
        stats.queries.append(q)
    return stats


# ---------------------------------------------------------------------------
# TestDNSQueryResult
# ---------------------------------------------------------------------------

class TestDNSQueryResult:
    def test_default_values(self):
        q = DNSQueryResult(resolver="1.1.1.1", resolver_ip="1.1.1.1", domain="google.com")
        assert q.success is False
        assert q.answer is None
        assert q.answers == []
        assert q.latency_ms is None

    def test_successful_result(self):
        q = DNSQueryResult(resolver="1.1.1.1", resolver_ip="1.1.1.1", domain="google.com")
        q.success = True
        q.answer = "142.250.0.1"
        q.answers = ["142.250.0.1", "142.250.0.2"]
        q.latency_ms = 15.3
        assert q.success
        assert q.answer == "142.250.0.1"
        assert len(q.answers) == 2

    def test_failed_result(self):
        q = DNSQueryResult(resolver="192.168.1.1", resolver_ip="192.168.1.1", domain="x.com")
        q.success = False
        q.error = "NXDOMAIN"
        assert not q.success
        assert q.error == "NXDOMAIN"

    def test_timestamp_set_automatically(self):
        before = time.time()
        q = DNSQueryResult(resolver="1.1.1.1", resolver_ip="1.1.1.1", domain="x.com")
        after = time.time()
        assert before <= q.timestamp <= after


# ---------------------------------------------------------------------------
# TestDNSHijackResult
# ---------------------------------------------------------------------------

class TestDNSHijackResult:
    def test_hijacked_attributes(self):
        r = DNSHijackResult(
            domain="google.com",
            internal_resolver="192.168.1.1",
            external_resolver="1.1.1.1",
            internal_answers=["1.2.3.4"],
            external_answers=["142.250.0.1"],
            is_hijacked=True,
            details="Respostas completamente diferentes",
        )
        assert r.is_hijacked
        assert r.domain == "google.com"
        assert r.internal_answers == ["1.2.3.4"]
        assert r.external_answers == ["142.250.0.1"]

    def test_not_hijacked(self):
        r = DNSHijackResult(
            domain="google.com",
            internal_resolver="192.168.1.1",
            external_resolver="1.1.1.1",
            internal_answers=["142.250.0.1"],
            external_answers=["142.250.0.1"],
            is_hijacked=False,
            details="Respostas consistentes",
        )
        assert not r.is_hijacked


# ---------------------------------------------------------------------------
# TestDNSResolverStats
# ---------------------------------------------------------------------------

class TestDNSResolverStats:
    def test_avg_latency_only_successful(self):
        stats = make_stats(latencies=[10.0, 20.0], successes=[True, True])
        assert stats.avg_latency_ms == pytest.approx(15.0)

    def test_avg_latency_excludes_failures(self):
        stats = make_stats(latencies=[10.0, 999.0], successes=[True, False])
        assert stats.avg_latency_ms == pytest.approx(10.0)

    def test_avg_latency_none_when_all_failed(self):
        stats = make_stats(latencies=[50.0, 80.0], successes=[False, False])
        assert stats.avg_latency_ms is None

    def test_avg_latency_none_when_no_queries(self):
        stats = DNSResolverStats(name="x", ip="1.1.1.1")
        assert stats.avg_latency_ms is None

    def test_success_rate_full(self):
        stats = make_stats(latencies=[10.0, 20.0], successes=[True, True])
        assert stats.success_rate == pytest.approx(1.0)

    def test_success_rate_partial(self):
        stats = make_stats(latencies=[10.0, 20.0], successes=[True, False])
        assert stats.success_rate == pytest.approx(0.5)

    def test_success_rate_zero_when_no_queries(self):
        stats = DNSResolverStats(name="x", ip="1.1.1.1")
        assert stats.success_rate == 0.0

    def test_is_slow_above_threshold(self):
        stats = make_stats(latencies=[THRESHOLD_SLOW_MS + 1.0])
        assert stats.is_slow

    def test_is_not_slow_at_threshold(self):
        stats = make_stats(latencies=[float(THRESHOLD_SLOW_MS)])
        assert not stats.is_slow

    def test_is_fast_below_threshold(self):
        stats = make_stats(latencies=[THRESHOLD_FAST_MS - 1.0])
        assert stats.is_fast

    def test_is_not_fast_at_threshold(self):
        stats = make_stats(latencies=[float(THRESHOLD_FAST_MS)])
        assert not stats.is_fast

    def test_is_not_failing_at_half(self):
        # success_rate = 0.5 — threshold é < 0.5, portanto NÃO está falhando
        stats = make_stats(latencies=[10.0, 10.0], successes=[True, False])
        assert not stats.is_failing

    def test_is_failing_zero_success(self):
        stats = make_stats(latencies=[10.0, 10.0], successes=[False, False])
        assert stats.is_failing


# ---------------------------------------------------------------------------
# TestDNSComparisonResult
# ---------------------------------------------------------------------------

class TestDNSComparisonResult:
    def test_get_internal_present(self):
        result = DNSComparisonResult()
        stats = DNSResolverStats(name="interno", ip="192.168.1.1")
        result.resolvers["interno"] = stats
        assert result.get_internal() is stats

    def test_get_internal_absent(self):
        result = DNSComparisonResult()
        assert result.get_internal() is None

    def test_get_external_fastest_picks_min(self):
        result = DNSComparisonResult()
        result.resolvers["interno"] = make_stats("interno", latencies=[20.0])
        result.resolvers["cloudflare"] = make_stats("cloudflare", "1.1.1.1", latencies=[15.0])
        result.resolvers["google"] = make_stats("google", "8.8.8.8", latencies=[25.0])
        fastest = result.get_external_fastest()
        assert fastest.name == "cloudflare"

    def test_get_external_fastest_ignores_no_latency(self):
        result = DNSComparisonResult()
        result.resolvers["cloudflare"] = make_stats("cloudflare", "1.1.1.1",
                                                    latencies=[10.0], successes=[False])
        result.resolvers["google"] = make_stats("google", "8.8.8.8", latencies=[20.0])
        fastest = result.get_external_fastest()
        assert fastest.name == "google"

    def test_get_external_fastest_none_when_no_external(self):
        result = DNSComparisonResult()
        result.resolvers["interno"] = make_stats("interno")
        assert result.get_external_fastest() is None

    def test_has_hijacking_false_by_default(self):
        result = DNSComparisonResult()
        assert not result.has_hijacking

    def test_has_hijacking_true(self):
        result = DNSComparisonResult()
        result.hijack_results = [
            DNSHijackResult("google.com", "192.168.1.1", "1.1.1.1",
                            ["1.2.3.4"], ["142.250.0.1"], True, "diferente"),
        ]
        assert result.has_hijacking

    def test_is_ok_no_severity(self):
        result = DNSComparisonResult()
        result.severity = None
        assert result.is_ok

    def test_is_ok_info(self):
        result = DNSComparisonResult()
        result.severity = "Info"
        assert result.is_ok

    def test_is_not_ok_warning(self):
        result = DNSComparisonResult()
        result.severity = "Warning"
        assert not result.is_ok

    def test_is_not_ok_critical(self):
        result = DNSComparisonResult()
        result.severity = "Critical"
        assert not result.is_ok


# ---------------------------------------------------------------------------
# TestDetectInternalResolver
# ---------------------------------------------------------------------------

class TestDetectInternalResolver:
    def test_reads_first_nameserver(self):
        content = "# comment\nnameserver 192.168.1.1\nnameserver 8.8.8.8\n"
        c = make_collector()
        with patch("builtins.open", mock_open(read_data=content)):
            ip = c.detect_internal_resolver()
        assert ip == "192.168.1.1"

    def test_skips_comment_lines(self):
        content = "# nameserver 10.0.0.1\nnameserver 172.16.0.1\n"
        c = make_collector()
        with patch("builtins.open", mock_open(read_data=content)):
            ip = c.detect_internal_resolver()
        assert ip == "172.16.0.1"

    def test_skips_invalid_ip(self):
        content = "nameserver not-an-ip\nnameserver 10.0.0.1\n"
        c = make_collector()
        with patch("builtins.open", mock_open(read_data=content)):
            ip = c.detect_internal_resolver()
        assert ip == "10.0.0.1"

    def test_returns_none_when_no_nameserver(self):
        content = "# no nameservers here\ndomain local\n"
        c = make_collector()
        with patch("builtins.open", mock_open(read_data=content)):
            ip = c.detect_internal_resolver()
        assert ip is None

    def test_returns_none_on_file_not_found(self):
        c = make_collector()
        with patch("builtins.open", side_effect=FileNotFoundError):
            ip = c.detect_internal_resolver()
        assert ip is None


# ---------------------------------------------------------------------------
# TestDNSCollectorQuery (async)
# ---------------------------------------------------------------------------

class TestDNSCollectorQuery:
    async def test_successful_query_sets_success(self):
        mock = MockQueryFunc(responses={("1.1.1.1", "google.com"): ["8.8.8.8"]})
        c = make_collector(query_func=mock)
        result = await c.query("1.1.1.1", "google.com")
        assert result.success
        assert result.answer == "8.8.8.8"
        assert result.answers == ["8.8.8.8"]
        assert result.latency_ms is not None
        assert result.latency_ms >= 0

    async def test_query_stores_multiple_answers(self):
        answers = ["1.2.3.4", "5.6.7.8"]
        mock = MockQueryFunc(responses={("8.8.8.8", "cloudflare.com"): answers})
        c = make_collector(query_func=mock)
        result = await c.query("8.8.8.8", "cloudflare.com")
        assert result.answers == answers
        assert result.answer == "1.2.3.4"

    async def test_failed_query_sets_error(self):
        mock = MockQueryFunc(errors={("192.168.1.1", "google.com"): TimeoutError("timeout")})
        c = make_collector(query_func=mock)
        result = await c.query("192.168.1.1", "google.com")
        assert not result.success
        assert "timeout" in result.error.lower()
        assert result.latency_ms >= 0   # latência medida mesmo em falha

    async def test_latency_measured_on_success(self):
        mock = MockQueryFunc(latency=0.05)
        c = make_collector(query_func=mock)
        result = await c.query("1.1.1.1", "google.com")
        assert result.latency_ms >= 40   # ≥ 40ms tolerando drift

    async def test_query_records_resolver_ip(self):
        mock = MockQueryFunc()
        c = make_collector(query_func=mock)
        result = await c.query("9.9.9.9", "uol.com.br")
        assert result.resolver_ip == "9.9.9.9"
        assert result.domain == "uol.com.br"

    async def test_query_calls_backend_with_record_type(self):
        mock = MockQueryFunc()
        c = make_collector(query_func=mock)
        await c.query("1.1.1.1", "google.com", "AAAA")
        assert mock.calls == [("1.1.1.1", "google.com", "AAAA")]


# ---------------------------------------------------------------------------
# TestCollectResolver (async)
# ---------------------------------------------------------------------------

class TestCollectResolver:
    async def test_queries_all_domains(self):
        mock = MockQueryFunc()
        c = make_collector(query_func=mock, queries_per_resolver=3)
        c.test_domains = ["a.com", "b.com", "c.com"]
        stats = await c.collect_resolver("cloudflare", "1.1.1.1")
        assert len(stats.queries) == 3

    async def test_success_rate_from_queries(self):
        mock = MockQueryFunc(
            responses={("1.1.1.1", "a.com"): ["1.2.3.4"]},
            errors={("1.1.1.1", "b.com"): Exception("fail")},
        )
        c = make_collector(query_func=mock)
        c.test_domains = ["a.com", "b.com"]
        c.queries_per_resolver = 2
        stats = await c.collect_resolver("cloudflare", "1.1.1.1")
        assert stats.success_rate == pytest.approx(0.5)

    async def test_stats_name_and_ip(self):
        c = make_collector()
        stats = await c.collect_resolver("google", "8.8.8.8")
        assert stats.name == "google"
        assert stats.ip == "8.8.8.8"

    async def test_failed_query_added_as_unsuccessful(self):
        # query() captura exceções e retorna DNSQueryResult com success=False
        mock = AsyncMock(side_effect=RuntimeError("boom"))
        c = make_collector(query_func=mock)
        c.test_domains = ["a.com"]
        stats = await c.collect_resolver("x", "1.2.3.4")
        assert len(stats.queries) == 1
        assert not stats.queries[0].success
        assert "boom" in stats.queries[0].error


# ---------------------------------------------------------------------------
# TestDetectHijacking (async)
# ---------------------------------------------------------------------------

class TestDetectHijacking:
    async def test_consistent_answers_not_hijacked(self):
        ip = "142.250.0.1"
        mock = MockQueryFunc(responses={
            ("192.168.1.1", "google.com"): [ip],
            ("1.1.1.1",     "google.com"): [ip],
        })
        c = make_collector(query_func=mock)
        results = await c.detect_hijacking("192.168.1.1", "1.1.1.1", ["google.com"])
        assert not results[0].is_hijacked
        assert results[0].details == "Respostas consistentes"

    async def test_partial_overlap_not_hijacked(self):
        """CDN retorna IPs diferentes mas há sobreposição — não é hijacking."""
        mock = MockQueryFunc(responses={
            ("192.168.1.1", "google.com"): ["1.2.3.4", "142.250.0.1"],
            ("1.1.1.1",     "google.com"): ["142.250.0.1", "5.6.7.8"],
        })
        c = make_collector(query_func=mock)
        results = await c.detect_hijacking("192.168.1.1", "1.1.1.1", ["google.com"])
        assert not results[0].is_hijacked

    async def test_no_overlap_is_hijacked(self):
        mock = MockQueryFunc(responses={
            ("192.168.1.1", "google.com"): ["1.2.3.4"],
            ("1.1.1.1",     "google.com"): ["142.250.0.1"],
        })
        c = make_collector(query_func=mock)
        results = await c.detect_hijacking("192.168.1.1", "1.1.1.1", ["google.com"])
        assert results[0].is_hijacked
        assert "completamente diferentes" in results[0].details

    async def test_failed_internal_not_flagged_as_hijack(self):
        mock = MockQueryFunc(
            errors={("192.168.1.1", "google.com"): Exception("timeout")},
            responses={("1.1.1.1", "google.com"): ["142.250.0.1"]},
        )
        c = make_collector(query_func=mock)
        results = await c.detect_hijacking("192.168.1.1", "1.1.1.1", ["google.com"])
        assert not results[0].is_hijacked
        assert "falha" in results[0].details

    async def test_multiple_domains_tested(self):
        mock = MockQueryFunc()
        c = make_collector(query_func=mock)
        results = await c.detect_hijacking("192.168.1.1", "1.1.1.1",
                                           ["a.com", "b.com", "c.com"])
        assert len(results) == 3
        assert {r.domain for r in results} == {"a.com", "b.com", "c.com"}

    async def test_result_stores_resolver_ips(self):
        mock = MockQueryFunc()
        c = make_collector(query_func=mock)
        results = await c.detect_hijacking("192.168.1.1", "1.1.1.1", ["google.com"])
        assert results[0].internal_resolver == "192.168.1.1"
        assert results[0].external_resolver == "1.1.1.1"


# ---------------------------------------------------------------------------
# TestCollect (async — fluxo completo)
# ---------------------------------------------------------------------------

class TestCollect:
    async def test_returns_comparison_result(self):
        c = make_collector()
        result = await c.collect()
        assert isinstance(result, DNSComparisonResult)

    async def test_resolvers_collected(self):
        c = make_collector()
        result = await c.collect()
        assert "interno" in result.resolvers
        assert "cloudflare" in result.resolvers

    async def test_sets_last_result(self):
        c = make_collector()
        result = await c.collect()
        assert c.last_result is result

    async def test_skips_resolver_with_no_ip(self):
        c = make_collector()
        c.resolvers = {"interno": None, "cloudflare": "1.1.1.1"}
        result = await c.collect()
        assert "interno" not in result.resolvers
        assert "cloudflare" in result.resolvers

    async def test_hijacking_detection_runs(self):
        mock = MockQueryFunc()
        c = make_collector(query_func=mock)
        result = await c.collect()
        assert isinstance(result.hijack_results, list)

    async def test_hijacking_skipped_when_no_interno(self):
        mock = MockQueryFunc()
        c = make_collector(query_func=mock)
        c.resolvers = {"cloudflare": "1.1.1.1", "google": "8.8.8.8"}
        result = await c.collect()
        assert result.hijack_results == []

    async def test_saves_to_db_when_available(self):
        mock_db = AsyncMock()
        c = make_collector(db=mock_db)
        await c.collect()
        mock_db.save_dns.assert_called_once()

    async def test_db_error_does_not_crash(self):
        mock_db = AsyncMock()
        mock_db.save_dns.side_effect = RuntimeError("db error")
        c = make_collector(db=mock_db)
        result = await c.collect()
        assert result is not None

    async def test_diagnosis_applied(self):
        c = make_collector()
        result = await c.collect()
        # diagnosis definido (qualquer valor, incluindo None quando sem externo lento)
        assert hasattr(result, "diagnosis")


# ---------------------------------------------------------------------------
# TestPreliminaryDiagnosis
# ---------------------------------------------------------------------------

class TestPreliminaryDiagnosis:
    def _apply(
        self,
        interno_lat: float | None = None,
        externo_lat: float | None = None,
        hijack: bool = False,
        failing: bool = False,
    ) -> DNSComparisonResult:
        result = DNSComparisonResult()
        if interno_lat is not None:
            if failing:
                # duas falhas → success_rate = 0 < 0.5
                result.resolvers["interno"] = make_stats(
                    "interno", latencies=[interno_lat, interno_lat],
                    successes=[False, False],
                )
            else:
                result.resolvers["interno"] = make_stats("interno", latencies=[interno_lat])
        if externo_lat is not None:
            result.resolvers["cloudflare"] = make_stats(
                "cloudflare", "1.1.1.1", latencies=[externo_lat]
            )
        if hijack:
            result.hijack_results = [
                DNSHijackResult(
                    "google.com", "192.168.1.1", "1.1.1.1",
                    ["1.2.3.4"], ["142.250.0.1"], True, "dif",
                )
            ]
        c = make_collector()
        c._apply_preliminary_diagnosis(result)
        return result

    def test_hijacking_takes_priority(self):
        r = self._apply(interno_lat=10.0, externo_lat=10.0, hijack=True)
        assert r.severity == "Critical"
        assert "hijacking" in r.diagnosis.lower()

    def test_failing_internal_critical(self):
        r = self._apply(interno_lat=10.0, externo_lat=10.0, failing=True)
        assert r.severity == "Critical"
        assert "falha" in r.diagnosis.lower() or "indispon" in r.diagnosis.lower()

    def test_slow_internal_fast_external_warning(self):
        r = self._apply(
            interno_lat=float(THRESHOLD_SLOW_MS + 50),
            externo_lat=float(THRESHOLD_FAST_MS - 5),
        )
        assert r.severity == "Warning"
        assert "sobrecarregado" in r.diagnosis.lower()

    def test_fast_internal_slow_external_info(self):
        r = self._apply(
            interno_lat=float(THRESHOLD_FAST_MS - 5),
            externo_lat=float(THRESHOLD_SLOW_MS + 50),
        )
        assert r.severity == "Info"
        assert "rota" in r.diagnosis.lower()

    def test_both_normal_no_severity(self):
        r = self._apply(interno_lat=20.0, externo_lat=20.0)
        assert r.severity is None
        assert "normal" in r.diagnosis.lower()

    def test_no_diagnosis_when_no_resolvers(self):
        result = DNSComparisonResult()
        c = make_collector()
        c._apply_preliminary_diagnosis(result)
        assert result.diagnosis is None
        assert result.severity is None

    def test_no_diagnosis_when_only_internal(self):
        result = DNSComparisonResult()
        result.resolvers["interno"] = make_stats("interno", latencies=[200.0])
        c = make_collector()
        c._apply_preliminary_diagnosis(result)
        # Sem externo para comparar — sem diagnóstico
        assert result.diagnosis is None


# ---------------------------------------------------------------------------
# TestIntegration — requer rede real
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestDNSIntegration:
    async def test_query_real_cloudflare(self):
        """Query real para 1.1.1.1 — requer internet."""
        c = DNSCollector()
        result = await c.query("1.1.1.1", "google.com")
        assert result.success, f"Query falhou: {result.error}"
        assert result.answer is not None
        assert result.latency_ms < 2000

    async def test_collect_real_resolvers(self):
        """Coleta completa com resolvers reais."""
        c = DNSCollector(
            resolvers={"cloudflare": "1.1.1.1", "google": "8.8.8.8"},
            queries_per_resolver=1,
        )
        result = await c.collect()
        assert "cloudflare" in result.resolvers
        assert result.resolvers["cloudflare"].success_rate > 0
