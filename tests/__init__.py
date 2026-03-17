"""
tests — Suite de testes do Home Net Monitor.

Cobertura alvo: ≥ 80% (RNF10).
Execução: pytest tests/ -v --cov=. --cov-report=term-missing

Módulos de teste:
  - test_icmp.py:        Testes do ICMPCollector
  - test_dns.py:         Testes do DNSCollector
  - test_snmp.py:        Testes do SNMPCollector
  - test_fingerprint.py: Testes do FingerprintCollector
  - test_correlator.py:  Testes do motor de correlação (regras de diagnóstico)
  - test_recommender.py: Testes do motor de recomendações
  - test_api.py:         Testes dos endpoints REST
  - test_sse.py:         Testes do EventBus e SSE handler
  - test_db.py:          Testes do repositório SQLite
"""
