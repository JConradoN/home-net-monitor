"""
engine — Motor de inteligência do Home Net Monitor.

Composto por dois módulos principais:
  - correlator:   Detecta gargalos correlacionando métricas de múltiplos coletores.
  - recommender:  Gera recomendações acionáveis baseadas nos alertas gerados.
"""

from .correlator import Correlator, Alert, AlertSeverity
from .recommender import Recommender, Recommendation

__all__ = [
    "Correlator",
    "Alert",
    "AlertSeverity",
    "Recommender",
    "Recommendation",
]
