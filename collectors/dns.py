"""
collectors/dns.py — Coletor de latência DNS.

Responsável por medir e comparar:
  - DNS interno (resolvedor do roteador, ex: 192.168.1.1)
  - DNS externo Cloudflare (1.1.1.1)
  - DNS externo Google (8.8.8.8)

Casos de diagnóstico cobertos (PRD seção 4.1-C):
  - DNS interno lento + DNS externo rápido → Roteador da operadora sobrecarregado (Warning)
  - DNS interno rápido + DNS externo lento  → Problema de rota da operadora (Info)
  - DNS interno falhando               → DNS interno indisponível (Critical)
  - DNS hijacking detectado            → Respostas divergentes interno vs externo (Critical)

Requer: pip install dnspython
"""

import asyncio
import ipaddress
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------

DEFAULT_RESOLVERS: dict[str, Optional[str]] = {
    "interno": None,         # Detectado via /etc/resolv.conf ou gateway
    "cloudflare": "1.1.1.1",
    "google": "8.8.8.8",
}

# Domínios para medir latência (amplamente cacheados nos resolvers públicos)
TEST_DOMAINS: list[str] = [
    "google.com",
    "cloudflare.com",
    "uol.com.br",
]

# Domínios estáveis para detecção de hijacking (respostas bem conhecidas)
HIJACK_TEST_DOMAINS: list[str] = [
    "google.com",
    "cloudflare.com",
]

DNS_PORT = 53
DNS_TIMEOUT = 3.0           # segundos por query
QUERIES_PER_RESOLVER = 3

# Thresholds para diagnóstico (PRD seção 4.1-C)
THRESHOLD_SLOW_MS = 100     # ms — DNS "lento"
THRESHOLD_FAST_MS = 30      # ms — DNS "rápido"
THRESHOLD_FAIL_RATE = 0.5   # taxa de falha para considerar resolver "caindo"


# ---------------------------------------------------------------------------
# Dataclasses de resultado
# ---------------------------------------------------------------------------

@dataclass
class DNSQueryResult:
    """Resultado de uma única query DNS."""

    resolver: str
    resolver_ip: str
    domain: str
    timestamp: float = field(default_factory=time.time)
    latency_ms: Optional[float] = None
    success: bool = False
    answer: Optional[str] = None       # primeiro registro A resolvido
    answers: list = field(default_factory=list)  # todos os registros resolvidos
    error: Optional[str] = None


@dataclass
class DNSHijackResult:
    """Resultado de detecção de DNS hijacking para um domínio."""

    domain: str
    internal_resolver: str
    external_resolver: str
    internal_answers: list   # list[str] — IPs retornados pelo resolver interno
    external_answers: list   # list[str] — IPs retornados pelo resolver externo
    is_hijacked: bool
    details: str


@dataclass
class DNSResolverStats:
    """Estatísticas agregadas de um resolver DNS."""

    name: str
    ip: str
    queries: list = field(default_factory=list)   # lista de DNSQueryResult

    @property
    def avg_latency_ms(self) -> Optional[float]:
        """Latência média em ms para queries bem-sucedidas."""
        successful = [
            q.latency_ms for q in self.queries
            if q.success and q.latency_ms is not None
        ]
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

    @property
    def is_failing(self) -> bool:
        """Resolver com taxa de sucesso abaixo do limite crítico."""
        return self.success_rate < THRESHOLD_FAIL_RATE


@dataclass
class DNSComparisonResult:
    """
    Resultado da comparação entre DNS interno e externo.
    Base para as regras de correlação no motor de diagnóstico.
    """

    timestamp: float = field(default_factory=time.time)
    resolvers: dict = field(default_factory=dict)          # {nome: DNSResolverStats}
    hijack_results: list = field(default_factory=list)     # list[DNSHijackResult]
    diagnosis: Optional[str] = None
    severity: Optional[str] = None    # Info / Warning / Critical

    def get_internal(self) -> Optional[DNSResolverStats]:
        return self.resolvers.get("interno")

    def get_external_fastest(self) -> Optional[DNSResolverStats]:
        external = {k: v for k, v in self.resolvers.items() if k != "interno"}
        if not external:
            return None
        candidates = [v for v in external.values() if v.avg_latency_ms is not None]
        if not candidates:
            return None
        return min(candidates, key=lambda x: x.avg_latency_ms)

    @property
    def has_hijacking(self) -> bool:
        """True se algum domínio apresentou resposta divergente."""
        return any(r.is_hijacked for r in self.hijack_results)

    @property
    def is_ok(self) -> bool:
        """True se não há diagnóstico crítico ou warning."""
        return self.severity not in ("Warning", "Critical")


# ---------------------------------------------------------------------------
# Backend DNS (injetável para testes)
# ---------------------------------------------------------------------------

class PythonDNSBackend:
    """
    Backend DNS padrão usando dnspython rodando em thread pool.

    Importação lazy — só importa dnspython na primeira chamada.
    Pode ser substituído por um mock em testes unitários.
    """

    async def __call__(
        self, resolver_ip: str, domain: str, record_type: str = "A"
    ) -> list[str]:
        """
        Executa query DNS e retorna lista de registros resolvidos.

        Args:
            resolver_ip: IP do servidor DNS.
            domain:      Domínio a resolver.
            record_type: Tipo de registro (A, AAAA, MX…).

        Returns:
            Lista de strings com os registros resolvidos.

        Raises:
            Exception: Se a query falhar (NXDOMAIN, timeout, community errada…).
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, self._sync_query, resolver_ip, domain, record_type
        )

    @staticmethod
    def _sync_query(resolver_ip: str, domain: str, record_type: str) -> list[str]:
        import dns.resolver  # lazy import — não quebra se dnspython não instalado

        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [resolver_ip]
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT
        answer = resolver.resolve(domain, record_type)
        return [str(rdata) for rdata in answer]


# ---------------------------------------------------------------------------
# Coletor principal
# ---------------------------------------------------------------------------

class DNSCollector:
    """
    Coletor assíncrono de latência DNS.

    Executa queries para múltiplos resolvers e domínios de teste,
    calcula estatísticas por resolver, detecta DNS hijacking e
    produz DNSComparisonResult para o motor de correlação.

    Uso:
        collector = DNSCollector()
        result = await collector.collect()

    Para testes:
        async def mock_query(resolver_ip, domain, record_type="A"):
            return ["1.2.3.4"]
        collector = DNSCollector(query_func=mock_query)
    """

    def __init__(
        self,
        resolvers: Optional[dict[str, Optional[str]]] = None,
        test_domains: Optional[list[str]] = None,
        queries_per_resolver: int = QUERIES_PER_RESOLVER,
        timeout: float = DNS_TIMEOUT,
        interval: float = 60.0,
        db=None,
        query_func=None,   # callable(resolver_ip, domain, record_type) -> list[str]
    ):
        """
        Args:
            resolvers:            Dicionário {nome: ip} dos resolvers a testar.
            test_domains:         Lista de domínios para queries de latência.
            queries_per_resolver: Número de queries por resolver por coleta.
            timeout:              Timeout por query DNS em segundos.
            interval:             Intervalo entre coletas (segundos).
            db:                   Repositório SQLite para persistência.
            query_func:           Backend DNS injetável (para testes).
                                  Deve ser async callable(ip, domain, type) -> list[str].
                                  Se None, usa PythonDNSBackend (dnspython).
        """
        self.resolvers = resolvers or DEFAULT_RESOLVERS.copy()
        self.test_domains = test_domains or TEST_DOMAINS
        self.queries_per_resolver = queries_per_resolver
        self.timeout = timeout
        self.interval = interval
        self.db = db
        self._running = False
        self._last_result: Optional[DNSComparisonResult] = None
        self._query_func = query_func if query_func is not None else PythonDNSBackend()

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
            DNSQueryResult com latência, resposta e flag de sucesso.
        """
        result = DNSQueryResult(
            resolver=resolver_ip,
            resolver_ip=resolver_ip,
            domain=domain,
        )
        start = time.monotonic()
        try:
            answers = await self._query_func(resolver_ip, domain, record_type)
            result.answers = answers
            result.answer = answers[0] if answers else None
            result.success = True
        except Exception as exc:
            result.error = str(exc)
            result.success = False
            logger.debug("Erro DNS %s → %s: %s", resolver_ip, domain, exc)
        finally:
            result.latency_ms = (time.monotonic() - start) * 1000
        return result

    async def collect_resolver(self, name: str, ip: str) -> DNSResolverStats:
        """
        Coleta estatísticas de um resolver executando queries em paralelo.

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

    async def detect_hijacking(
        self,
        internal_ip: str,
        external_ip: str = "1.1.1.1",
        domains: Optional[list[str]] = None,
    ) -> list[DNSHijackResult]:
        """
        Detecta DNS hijacking comparando respostas do resolver interno vs externo.

        Hijacking é indicado quando o resolver interno retorna um conjunto de IPs
        completamente diferente do externo para domínios conhecidos.

        Nota: diferenças por geo-CDN são normais — só sinaliza quando NÃO HÁ
        nenhuma sobreposição entre as respostas, indicando redirecionamento ativo.

        Args:
            internal_ip:  IP do resolver interno (ex: gateway 192.168.1.1).
            external_ip:  IP do resolver externo confiável (ex: 1.1.1.1).
            domains:      Domínios para testar (padrão: HIJACK_TEST_DOMAINS).

        Returns:
            Lista de DNSHijackResult, um por domínio testado.
        """
        domains = domains or HIJACK_TEST_DOMAINS
        results = []

        for domain in domains:
            int_result, ext_result = await asyncio.gather(
                self.query(internal_ip, domain),
                self.query(external_ip, domain),
                return_exceptions=True,
            )

            int_ok = isinstance(int_result, DNSQueryResult) and int_result.success
            ext_ok = isinstance(ext_result, DNSQueryResult) and ext_result.success

            int_answers = int_result.answers if int_ok else []
            ext_answers = ext_result.answers if ext_ok else []

            if not int_answers or not ext_answers:
                hijacked = False
                details = "Não foi possível comparar — uma ou mais queries falharam"
            else:
                overlap = set(int_answers) & set(ext_answers)
                hijacked = len(overlap) == 0
                if hijacked:
                    details = (
                        f"Respostas completamente diferentes: "
                        f"interno={int_answers} externo={ext_answers}"
                    )
                else:
                    details = "Respostas consistentes"

            results.append(DNSHijackResult(
                domain=domain,
                internal_resolver=internal_ip,
                external_resolver=external_ip,
                internal_answers=int_answers,
                external_answers=ext_answers,
                is_hijacked=hijacked,
                details=details,
            ))

        return results

    async def collect(self) -> DNSComparisonResult:
        """
        Executa coleta em todos os resolvers configurados em paralelo.
        Inclui detecção de hijacking se interno e externo disponíveis.

        Returns:
            DNSComparisonResult com estatísticas, hijacking e diagnóstico.
        """
        comparison = DNSComparisonResult()

        active = {name: ip for name, ip in self.resolvers.items() if ip}

        # Coleta de todos os resolvers em paralelo
        tasks = {
            name: asyncio.create_task(self.collect_resolver(name, ip))
            for name, ip in active.items()
        }
        for name, task in tasks.items():
            try:
                comparison.resolvers[name] = await task
            except Exception as exc:
                logger.error("Erro ao coletar resolver %s: %s", name, exc)

        # Detecção de hijacking: só se interno e externo estiverem disponíveis
        interno_ip = active.get("interno")
        external_ip = active.get("cloudflare") or active.get("google")
        if interno_ip and external_ip:
            try:
                comparison.hijack_results = await self.detect_hijacking(
                    interno_ip, external_ip
                )
                if comparison.has_hijacking:
                    logger.warning(
                        "DNS hijacking detectado! Domínios afetados: %s",
                        [r.domain for r in comparison.hijack_results if r.is_hijacked],
                    )
            except Exception as exc:
                logger.error("Erro na detecção de hijacking: %s", exc)

        self._apply_preliminary_diagnosis(comparison)
        self._last_result = comparison

        if self.db:
            try:
                await self.db.save_dns(comparison)
            except Exception as exc:
                logger.error("Erro ao salvar DNS no banco: %s", exc)

        return comparison

    def _apply_preliminary_diagnosis(self, result: DNSComparisonResult) -> None:
        """
        Aplica diagnóstico preliminar baseado na comparação de resolvers.

        Regras por prioridade (PRD seção 4.1-C):
          1. Hijacking detectado               → Critical
          2. DNS interno falhando              → Critical
          3. Interno lento + externo rápido    → Warning (roteador sobrecarregado)
          4. Interno rápido + externo lento    → Info (problema de rota)
          5. Normal                            → None

        O diagnóstico final é refinado pelo motor de correlação (engine/correlator.py).
        """
        # Prioridade 1: hijacking
        if result.has_hijacking:
            hijacked = [r.domain for r in result.hijack_results if r.is_hijacked]
            result.diagnosis = (
                f"Possível DNS hijacking detectado para: {', '.join(hijacked)}"
            )
            result.severity = "Critical"
            return

        interno = result.get_internal()
        externo = result.get_external_fastest()

        if interno is None or externo is None:
            return

        # Prioridade 2: DNS interno falhando
        if interno.is_failing:
            result.diagnosis = "DNS interno indisponível ou com alta taxa de falha"
            result.severity = "Critical"
        # Prioridade 3: interno lento, externo rápido
        elif interno.is_slow and not externo.is_slow:
            result.diagnosis = "Roteador da operadora sobrecarregado"
            result.severity = "Warning"
        # Prioridade 4: externo lento, interno rápido
        elif not interno.is_slow and externo.is_slow:
            result.diagnosis = "Problema de rota da operadora"
            result.severity = "Info"
        # Normal
        else:
            result.diagnosis = "DNS funcionando normalmente"
            result.severity = None

    def detect_internal_resolver(self) -> Optional[str]:
        """
        Detecta o resolver DNS interno lendo /etc/resolv.conf.

        Returns:
            IP do primeiro nameserver válido encontrado, ou None.
        """
        try:
            with open("/etc/resolv.conf") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("nameserver"):
                        parts = line.split()
                        if len(parts) >= 2:
                            try:
                                ipaddress.ip_address(parts[1])
                                logger.info("Resolver interno detectado: %s", parts[1])
                                return parts[1]
                            except ValueError:
                                continue
        except Exception as exc:
            logger.warning("Não foi possível ler /etc/resolv.conf: %s", exc)
        return None

    async def start(self) -> None:
        """Inicia o loop de coleta periódica de DNS."""
        if self.resolvers.get("interno") is None:
            self.resolvers["interno"] = self.detect_internal_resolver()

        self._running = True
        logger.info("DNSCollector iniciado — intervalo: %ss", self.interval)
        while self._running:
            t_start = time.monotonic()
            try:
                await self.collect()
            except Exception as exc:
                logger.error("Erro no ciclo DNS: %s", exc)
            elapsed = time.monotonic() - t_start
            sleep_for = max(0.0, self.interval - elapsed)
            if sleep_for > 0:
                await asyncio.sleep(sleep_for)

    async def stop(self) -> None:
        """Para o loop de coleta."""
        self._running = False
        logger.info("DNSCollector parado.")

    @property
    def last_result(self) -> Optional[DNSComparisonResult]:
        """Retorna o último resultado de comparação DNS."""
        return self._last_result
