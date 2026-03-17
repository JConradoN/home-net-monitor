"""
collectors/dns.py — Coletor de latência DNS.

Responsável por medir e comparar:
  - DNS interno (resolvedor do roteador, ex: 192.168.1.1)
  - DNS externo Cloudflare (1.1.1.1)
  - DNS externo Google (8.8.8.8)

Casos de diagnóstico cobertos (PRD seção 4.1-C):
  - DNS interno lento + DNS externo rápido → Roteador da operadora sobrecarregado (Warning)
  - DNS interno rápido + DNS externo lento  → Problema de rota da operadora (Info)

Requer: pip install dnspython
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# Resolvers padrão
DEFAULT_RESOLVERS = {
    "interno": None,         # Detectado via /etc/resolv.conf ou gateway
    "cloudflare": "1.1.1.1",
    "google": "8.8.8.8",
}

# Domínios usados para medir latência (escolhidos por serem amplamente cacheados)
TEST_DOMAINS = [
    "google.com",
    "cloudflare.com",
    "uol.com.br",
]

DNS_PORT = 53
DNS_TIMEOUT = 3.0       # segundos por query
QUERIES_PER_RESOLVER = 3

# Thresholds para diagnóstico
THRESHOLD_SLOW_MS = 100     # ms — DNS "lento"
THRESHOLD_FAST_MS = 30      # ms — DNS "rápido"


@dataclass
class DNSQueryResult:
    """Resultado de uma única query DNS."""

    resolver: str
    resolver_ip: str
    domain: str
    timestamp: float = field(default_factory=time.time)
    latency_ms: Optional[float] = None
    success: bool = False
    answer: Optional[str] = None      # primeiro registro A resolvido
    error: Optional[str] = None


@dataclass
class DNSResolverStats:
    """Estatísticas agregadas de um resolver DNS."""

    name: str
    ip: str
    queries: list = field(default_factory=list)   # lista de DNSQueryResult

    @property
    def avg_latency_ms(self) -> Optional[float]:
        """Latência média em ms para queries bem-sucedidas."""
        successful = [q.latency_ms for q in self.queries if q.success and q.latency_ms]
        if not successful:
            return None
        return sum(successful) / len(successful)

    @property
    def success_rate(self) -> float:
        """Taxa de sucesso (0.0–1.0)."""
        if not self.queries:
            return 0.0
        return sum(1 for q in self.queries if q.success) / len(self.queries)

    @property
    def is_slow(self) -> bool:
        avg = self.avg_latency_ms
        return avg is not None and avg > THRESHOLD_SLOW_MS

    @property
    def is_fast(self) -> bool:
        avg = self.avg_latency_ms
        return avg is not None and avg < THRESHOLD_FAST_MS


@dataclass
class DNSComparisonResult:
    """
    Resultado da comparação entre DNS interno e externo.
    Base para as regras de correlação no motor de diagnóstico.
    """

    timestamp: float = field(default_factory=time.time)
    resolvers: dict = field(default_factory=dict)   # {nome: DNSResolverStats}
    diagnosis: Optional[str] = None
    severity: Optional[str] = None    # Info / Warning / Critical

    def get_internal(self) -> Optional["DNSResolverStats"]:
        return self.resolvers.get("interno")

    def get_external_fastest(self) -> Optional["DNSResolverStats"]:
        external = {k: v for k, v in self.resolvers.items() if k != "interno"}
        if not external:
            return None
        return min(
            (v for v in external.values() if v.avg_latency_ms is not None),
            key=lambda x: x.avg_latency_ms,
            default=None,
        )


class DNSCollector:
    """
    Coletor assíncrono de latência DNS.

    Executa queries para múltiplos resolvers e domínios de teste,
    calcula estatísticas por resolver e produz DNSComparisonResult
    para o motor de correlação.

    Uso:
        collector = DNSCollector()
        result = await collector.collect()
    """

    def __init__(
        self,
        resolvers: dict[str, Optional[str]] = None,
        test_domains: list[str] = None,
        queries_per_resolver: int = QUERIES_PER_RESOLVER,
        timeout: float = DNS_TIMEOUT,
        interval: float = 60.0,
        db=None,
    ):
        """
        Args:
            resolvers:            Dicionário {nome: ip} dos resolvers a testar.
            test_domains:         Lista de domínios para queries de latência.
            queries_per_resolver: Número de queries por resolver por coleta.
            timeout:              Timeout por query DNS em segundos.
            interval:             Intervalo entre coletas (segundos).
            db:                   Repositório SQLite para persistência.
        """
        self.resolvers = resolvers or DEFAULT_RESOLVERS.copy()
        self.test_domains = test_domains or TEST_DOMAINS
        self.queries_per_resolver = queries_per_resolver
        self.timeout = timeout
        self.interval = interval
        self.db = db
        self._running = False
        self._last_result: Optional[DNSComparisonResult] = None

    async def query(
        self, resolver_ip: str, domain: str, record_type: str = "A"
    ) -> DNSQueryResult:
        """
        Executa uma query DNS contra um resolver específico e mede a latência.

        Args:
            resolver_ip:  IP do servidor DNS a consultar.
            domain:       Domínio a resolver.
            record_type:  Tipo de registro DNS (padrão: A).

        Returns:
            DNSQueryResult com latência e resposta.
        """
        result = DNSQueryResult(
            resolver=resolver_ip,
            resolver_ip=resolver_ip,
            domain=domain,
        )
        start = time.monotonic()
        try:
            # TODO: Implementar com dnspython (dns.resolver.Resolver)
            # import dns.resolver
            # resolver = dns.resolver.Resolver()
            # resolver.nameservers = [resolver_ip]
            # resolver.timeout = self.timeout
            # answer = resolver.resolve(domain, record_type)
            # result.answer = str(answer[0])
            # result.success = True
            pass
        except Exception as exc:
            result.error = str(exc)
            result.success = False
            logger.debug("Erro DNS %s → %s: %s", resolver_ip, domain, exc)
        finally:
            elapsed = time.monotonic() - start
            result.latency_ms = elapsed * 1000

        return result

    async def collect_resolver(
        self, name: str, ip: str
    ) -> DNSResolverStats:
        """
        Coleta estatísticas de um resolver executando múltiplas queries.

        Args:
            name: Nome amigável do resolver.
            ip:   Endereço IP do resolver.

        Returns:
            DNSResolverStats com média de latência e taxa de sucesso.
        """
        stats = DNSResolverStats(name=name, ip=ip)
        domains = self.test_domains[: self.queries_per_resolver]
        tasks = [self.query(ip, domain) for domain in domains]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, DNSQueryResult):
                stats.queries.append(r)
        return stats

    async def collect(self) -> DNSComparisonResult:
        """
        Executa coleta em todos os resolvers configurados em paralelo.

        Returns:
            DNSComparisonResult com estatísticas e diagnóstico preliminar.
        """
        comparison = DNSComparisonResult()

        # Filtra resolvers com IP definido
        active = {name: ip for name, ip in self.resolvers.items() if ip}

        tasks = {
            name: asyncio.create_task(self.collect_resolver(name, ip))
            for name, ip in active.items()
        }
        for name, task in tasks.items():
            try:
                comparison.resolvers[name] = await task
            except Exception as exc:
                logger.error("Erro ao coletar resolver %s: %s", name, exc)

        self._apply_preliminary_diagnosis(comparison)
        self._last_result = comparison

        if self.db:
            # TODO: self.db.save_dns(comparison)
            pass

        return comparison

    def _apply_preliminary_diagnosis(self, result: DNSComparisonResult) -> None:
        """
        Aplica diagnóstico preliminar baseado na comparação de resolvers.

        Regras (PRD seção 4.1-C):
          - Interno lento + externo rápido → 'Roteador da operadora sobrecarregado' (Warning)
          - Interno rápido + externo lento  → 'Problema de rota da operadora' (Info)

        O diagnóstico final é refinado pelo motor de correlação (engine/correlator.py).
        """
        interno = result.get_internal()
        externo = result.get_external_fastest()

        if interno is None or externo is None:
            return

        if interno.is_slow and not externo.is_slow:
            result.diagnosis = "Roteador da operadora sobrecarregado"
            result.severity = "Warning"
        elif not interno.is_slow and externo.is_slow:
            result.diagnosis = "Problema de rota da operadora"
            result.severity = "Info"
        else:
            result.diagnosis = "DNS funcionando normalmente"
            result.severity = None

    def detect_internal_resolver(self) -> Optional[str]:
        """
        Detecta o resolver DNS interno lendo /etc/resolv.conf.

        Returns:
            IP do primeiro nameserver encontrado, ou None.
        """
        try:
            with open("/etc/resolv.conf") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("nameserver"):
                        parts = line.split()
                        if len(parts) >= 2:
                            ip = parts[1]
                            logger.info("Resolver interno detectado: %s", ip)
                            return ip
        except Exception as exc:
            logger.warning("Não foi possível ler /etc/resolv.conf: %s", exc)
        return None

    async def start(self) -> None:
        """Inicia o loop de coleta periódica de DNS."""
        # Tenta detectar resolver interno automaticamente
        if self.resolvers.get("interno") is None:
            self.resolvers["interno"] = self.detect_internal_resolver()

        self._running = True
        logger.info("DNSCollector iniciado — intervalo: %ss", self.interval)
        while self._running:
            try:
                await self.collect()
            except Exception as exc:
                logger.error("Erro no ciclo DNS: %s", exc)
            await asyncio.sleep(self.interval)

    async def stop(self) -> None:
        """Para o loop de coleta."""
        self._running = False
        logger.info("DNSCollector parado.")

    @property
    def last_result(self) -> Optional[DNSComparisonResult]:
        """Retorna o último resultado de comparação DNS."""
        return self._last_result
