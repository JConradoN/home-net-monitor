"""
api — Camada de API REST e SSE do Home Net Monitor.

Expõe:
  - routes.py:  Endpoints REST para status, métricas, dispositivos, histórico e wizard SNMP.
  - sse.py:     Server-Sent Events para alertas em tempo real no dashboard.

Framework: FastAPI + Uvicorn
Exposição: apenas localhost (RNF06 — segurança).
"""
