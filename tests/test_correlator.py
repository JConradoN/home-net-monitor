"""
tests/test_correlator.py — Testes do motor de correlação.

Testa cada regra de diagnóstico isoladamente com snapshots sintéticos.
Garante que os thresholds do PRD são respeitados e que as regras
não geram falsos positivos quando os valores estão dentro do normal.
"""

import time
import pytest

from engine.correlator import (
    Correlator,
    CorrelationSnapshot,
    Alert,
    AlertSeverity,
)


@pytest.fixture
def correlator():
    """Instância do Correlator com thresholds padrão."""
    return Correlator()


@pytest.fixture
def clean_snapshot():
    """Snapshot com todos os valores dentro do normal — sem alertas esperados."""
    return CorrelationSnapshot(
        gateway_rtt_ms=5.0,
        gateway_loss=0.0,
        internet_rtt_ms=20.0,
        internet_loss=0.0,
        is_wifi=False,
        dns_internal_ms=10.0,
        dns_external_ms=15.0,
        cpu_usage=30.0,
        cpu_high_since=None,
        channel_utilization=40.0,
        noise_floor=-85.0,
        retries_percent=5.0,
        bufferbloat_delta_ms=2.0,
        bufferbloat_grade="Nenhum",
    )


class TestCorrelatorOutage:
    """Testes da regra de queda de conexão (gateway sem resposta > 30s)."""

    def test_outage_not_triggered_below_threshold(self, correlator, clean_snapshot):
        """Não deve alertar se a queda durou menos de 30 segundos."""
        clean_snapshot.gateway_unreachable_since = time.time() - 10
        alerts = correlator.analyze(clean_snapshot)
        codes = [a.code for a in alerts]
        assert "OUTAGE" not in codes

    def test_outage_triggered_above_threshold(self, correlator, clean_snapshot):
        """Deve alertar Critical quando gateway inacessível por mais de 30s."""
        clean_snapshot.gateway_unreachable_since = time.time() - 40
        alerts = correlator.analyze(clean_snapshot)
        outage_alerts = [a for a in alerts if a.code == "OUTAGE"]
        assert len(outage_alerts) == 1
        assert outage_alerts[0].severity == AlertSeverity.CRITICAL

    def test_outage_not_triggered_when_gateway_ok(self, correlator, clean_snapshot):
        """Não deve alertar quando gateway está respondendo."""
        clean_snapshot.gateway_unreachable_since = None
        alerts = correlator.analyze(clean_snapshot)
        codes = [a.code for a in alerts]
        assert "OUTAGE" not in codes


class TestCorrelatorISP:
    """Testes da regra de problema na operadora."""

    def test_isp_problem_detected(self, correlator, clean_snapshot):
        """Deve alertar Critical: gateway OK + internet alta."""
        clean_snapshot.gateway_rtt_ms = 5.0      # baixo (OK)
        clean_snapshot.internet_rtt_ms = 200.0   # alto (problema)
        alerts = correlator.analyze(clean_snapshot)
        isp_alerts = [a for a in alerts if a.code == "ISP_PROBLEM"]
        assert len(isp_alerts) == 1
        assert isp_alerts[0].severity == AlertSeverity.CRITICAL

    def test_isp_problem_not_false_positive(self, correlator, clean_snapshot):
        """Não deve alertar quando ambas latências estão normais."""
        clean_snapshot.gateway_rtt_ms = 5.0
        clean_snapshot.internet_rtt_ms = 20.0
        alerts = correlator.analyze(clean_snapshot)
        codes = [a.code for a in alerts]
        assert "ISP_PROBLEM" not in codes

    def test_isp_problem_not_triggered_gateway_also_high(self, correlator, clean_snapshot):
        """Não deve alertar como ISP quando gateway também está alto."""
        clean_snapshot.gateway_rtt_ms = 100.0
        clean_snapshot.internet_rtt_ms = 200.0
        alerts = correlator.analyze(clean_snapshot)
        codes = [a.code for a in alerts]
        assert "ISP_PROBLEM" not in codes


class TestCorrelatorWifi:
    """Testes das regras de Wi-Fi."""

    def test_wifi_high_latency_on_wifi(self, correlator, clean_snapshot):
        """Deve alertar Warning: latência alta ao gateway via Wi-Fi."""
        clean_snapshot.gateway_rtt_ms = 100.0
        clean_snapshot.is_wifi = True
        alerts = correlator.analyze(clean_snapshot)
        wifi_alerts = [a for a in alerts if a.code == "WIFI_HIGH_LATENCY"]
        assert len(wifi_alerts) == 1
        assert wifi_alerts[0].severity == AlertSeverity.WARNING

    def test_wifi_high_latency_not_on_cable(self, correlator, clean_snapshot):
        """Não deve alertar WIFI_HIGH_LATENCY se não está em Wi-Fi."""
        clean_snapshot.gateway_rtt_ms = 100.0
        clean_snapshot.is_wifi = False
        alerts = correlator.analyze(clean_snapshot)
        codes = [a.code for a in alerts]
        assert "WIFI_HIGH_LATENCY" not in codes

    def test_channel_saturation_warning(self, correlator, clean_snapshot):
        """Deve alertar Warning: channel utilization > 70%."""
        clean_snapshot.channel_utilization = 85.0
        alerts = correlator.analyze(clean_snapshot)
        sat_alerts = [a for a in alerts if a.code == "WIFI_SATURATION"]
        assert len(sat_alerts) == 1
        assert sat_alerts[0].severity == AlertSeverity.WARNING

    def test_rf_interference_warning(self, correlator, clean_snapshot):
        """Deve alertar Warning: retries > 15%."""
        clean_snapshot.retries_percent = 20.0
        alerts = correlator.analyze(clean_snapshot)
        rf_alerts = [a for a in alerts if a.code == "RF_INTERFERENCE"]
        assert len(rf_alerts) == 1

    def test_noise_floor_info(self, correlator, clean_snapshot):
        """Deve alertar Info: noise floor > -75 dBm."""
        clean_snapshot.noise_floor = -70.0
        alerts = correlator.analyze(clean_snapshot)
        noise_alerts = [a for a in alerts if a.code == "HIGH_NOISE"]
        assert len(noise_alerts) == 1
        assert noise_alerts[0].severity == AlertSeverity.INFO


class TestCorrelatorDNS:
    """Testes das regras de DNS."""

    def test_dns_router_overload(self, correlator, clean_snapshot):
        """Deve alertar Warning: DNS interno lento + externo rápido."""
        clean_snapshot.dns_internal_ms = 200.0
        clean_snapshot.dns_external_ms = 15.0
        alerts = correlator.analyze(clean_snapshot)
        dns_alerts = [a for a in alerts if a.code == "DNS_ROUTER_OVERLOAD"]
        assert len(dns_alerts) == 1
        assert dns_alerts[0].severity == AlertSeverity.WARNING

    def test_dns_isp_route_info(self, correlator, clean_snapshot):
        """Deve alertar Info: DNS interno rápido + externo lento."""
        clean_snapshot.dns_internal_ms = 10.0
        clean_snapshot.dns_external_ms = 200.0
        alerts = correlator.analyze(clean_snapshot)
        isp_alerts = [a for a in alerts if a.code == "DNS_ISP_ROUTE"]
        assert len(isp_alerts) == 1
        assert isp_alerts[0].severity == AlertSeverity.INFO


class TestCorrelatorCPU:
    """Testes da regra de CPU crítica."""

    def test_cpu_critical_after_threshold(self, correlator, clean_snapshot):
        """Deve alertar Critical: CPU > 80% por mais de 60s."""
        clean_snapshot.cpu_usage = 90.0
        clean_snapshot.cpu_high_since = time.time() - 70
        alerts = correlator.analyze(clean_snapshot)
        cpu_alerts = [a for a in alerts if a.code == "CPU_CRITICAL"]
        assert len(cpu_alerts) == 1
        assert cpu_alerts[0].severity == AlertSeverity.CRITICAL

    def test_cpu_not_alerted_before_duration(self, correlator, clean_snapshot):
        """Não deve alertar CPU antes do tempo mínimo (60s)."""
        clean_snapshot.cpu_usage = 90.0
        clean_snapshot.cpu_high_since = time.time() - 30
        alerts = correlator.analyze(clean_snapshot)
        codes = [a.code for a in alerts]
        assert "CPU_CRITICAL" not in codes


class TestCorrelatorBufferbloat:
    """Testes da regra de bufferbloat."""

    def test_bufferbloat_warning(self, correlator, clean_snapshot):
        """Deve alertar Warning: delta de latência > 30ms."""
        clean_snapshot.bufferbloat_delta_ms = 60.0
        clean_snapshot.bufferbloat_grade = "Moderado"
        alerts = correlator.analyze(clean_snapshot)
        bb_alerts = [a for a in alerts if a.code == "BUFFERBLOAT"]
        assert len(bb_alerts) == 1
        assert bb_alerts[0].severity == AlertSeverity.WARNING

    def test_no_bufferbloat_below_threshold(self, correlator, clean_snapshot):
        """Não deve alertar bufferbloat com delta pequeno."""
        clean_snapshot.bufferbloat_delta_ms = 5.0
        alerts = correlator.analyze(clean_snapshot)
        codes = [a.code for a in alerts]
        assert "BUFFERBLOAT" not in codes


class TestCorrelatorStatus:
    """Testes do status geral da rede."""

    def test_status_ok_no_alerts(self, correlator, clean_snapshot):
        """Status deve ser 'ok' sem alertas."""
        correlator.analyze(clean_snapshot)
        assert correlator.get_status() == "ok"

    def test_status_critical_with_outage(self, correlator, clean_snapshot):
        """Status deve ser 'critical' com alerta Critical ativo."""
        clean_snapshot.gateway_unreachable_since = time.time() - 60
        correlator.analyze(clean_snapshot)
        assert correlator.get_status() == "critical"

    def test_status_warning_with_wifi_alert(self, correlator, clean_snapshot):
        """Status deve ser 'warning' com apenas alertas Warning."""
        clean_snapshot.channel_utilization = 90.0
        correlator.analyze(clean_snapshot)
        assert correlator.get_status() == "warning"
