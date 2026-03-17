"""
db — Camada de persistência SQLite do Home Net Monitor.

Armazena métricas históricas, alertas e dispositivos descobertos.
Usa WAL mode para evitar SQLite lock (PRD seção 10 — Riscos).
"""
