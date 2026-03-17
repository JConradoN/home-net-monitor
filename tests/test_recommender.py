"""
tests/test_recommender.py — Testes do motor de recomendações.

Verifica que cada alerta gera a recomendação correta com
passos não-vazios e categoria adequada.
"""

import time
import pytest

from engine.correlator import Alert, AlertSeverity
from engine.recommender import Recommender


def make_alert(code, severity=AlertSeverity.WARNING, context=None):
    return Alert(
        code=code,
        severity=severity,
        title=f"Alerta {code}",
        description="Descrição de teste",
        user_message="Mensagem ao usuário.",
        context=context or {},
    )


@pytest.fixture
def recommender():
    return Recommender()


class TestRecommenderGeneration:
    """Testes de geração de recomendações por código de alerta."""

    def test_generates_recommendation_for_outage(self, recommender):
        alerts = [make_alert("OUTAGE", AlertSeverity.CRITICAL, {"duration_s": 45})]
        recs = recommender.generate(alerts)
        assert len(recs) == 1
        assert recs[0].alert_code == "OUTAGE"
        assert recs[0].category == "isp"
        assert len(recs[0].steps) > 0

    def test_generates_recommendation_for_isp_problem(self, recommender):
        alerts = [make_alert("ISP_PROBLEM", AlertSeverity.CRITICAL,
                             {"gateway_rtt": 5.0, "internet_rtt": 200.0})]
        recs = recommender.generate(alerts)
        assert any(r.alert_code == "ISP_PROBLEM" for r in recs)

    def test_generates_recommendation_for_cpu_critical(self, recommender):
        alerts = [make_alert("CPU_CRITICAL", AlertSeverity.CRITICAL,
                             {"cpu": 90.0, "duration_s": 70})]
        recs = recommender.generate(alerts)
        cpu_recs = [r for r in recs if r.alert_code == "CPU_CRITICAL"]
        assert len(cpu_recs) == 1
        assert cpu_recs[0].category == "mikrotik"
        assert cpu_recs[0].has_technical_steps is True

    def test_generates_recommendation_for_bufferbloat(self, recommender):
        alerts = [make_alert("BUFFERBLOAT", context={"grade": "Severo", "delta_ms": 120.0})]
        recs = recommender.generate(alerts)
        bb_recs = [r for r in recs if r.alert_code == "BUFFERBLOAT"]
        assert len(bb_recs) == 1
        # Deve ter comandos RouterOS como detalhe técnico
        technical = [s for s in bb_recs[0].steps if s.technical_detail]
        assert len(technical) > 0

    def test_no_recommendation_for_unknown_code(self, recommender):
        alerts = [make_alert("UNKNOWN_ALERT_XYZ")]
        recs = recommender.generate(alerts)
        assert len(recs) == 0

    def test_recommendations_ordered_by_priority(self, recommender):
        alerts = [
            make_alert("HIGH_NOISE", AlertSeverity.INFO),
            make_alert("OUTAGE", AlertSeverity.CRITICAL, {"duration_s": 60}),
            make_alert("WIFI_SATURATION", AlertSeverity.WARNING),
        ]
        recs = recommender.generate(alerts)
        priorities = [r.priority for r in recs]
        assert priorities == sorted(priorities, reverse=True)

    def test_all_alert_codes_have_recommendations(self, recommender):
        """Todos os códigos registrados devem gerar recomendação."""
        codes = list(recommender._registry.keys())
        for code in codes:
            alerts = [make_alert(code, context={"duration_s": 70, "cpu": 90,
                                                "delta_ms": 50.0, "grade": "Severo",
                                                "dns_internal": 200, "dns_external": 10,
                                                "gateway_rtt": 5.0, "internet_rtt": 200.0,
                                                "channel_utilization": 80.0,
                                                "retries": 20.0, "noise_floor": -70.0})]
            recs = recommender.generate(alerts)
            assert len(recs) >= 1, f"Nenhuma recomendação para {code}"
