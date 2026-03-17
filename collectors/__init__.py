"""
collectors — Módulo de coleta de métricas de rede.

Cada coletor é independente e pode ser habilitado/desabilitado sem afetar os demais.
Todos expõem uma interface assíncrona compatível com asyncio.
"""

from .icmp import ICMPCollector
from .snmp import SNMPCollector
from .dns import DNSCollector
from .fingerprint import FingerprintCollector

__all__ = [
    "ICMPCollector",
    "SNMPCollector",
    "DNSCollector",
    "FingerprintCollector",
]
