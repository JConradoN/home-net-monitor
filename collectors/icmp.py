"""
collectors/icmp.py — Coletor de latência e perda de pacotes via ICMP (ping).

Responsável por medir:
  - Latência (RTT) em milissegundos para múltiplos alvos
  - Perda de pacotes (%)
  - Detecção de quedas de conexão (gateway sem resposta > 30s)
  - Bufferbloat: diferença de latência baseline vs. sob carga

Requer privilégio de rede raw (cap_net_raw) ou execução como root.
Em produção, use: sudo setcap cap_net_raw+ep $(which python3)
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# Alvos padrão de monitoramento conforme PRD seção 4.1-A
DEFAULT_TARGETS = {
    "gateway": None,          # Detectado automaticamente via ARP
    "dns_interno": None,      # Detectado via /etc/resolv.conf
    "cloudflare": "1.1.1.1",
    "google_dns": "8.8.8.8",
    "google_public": "8.8.4.4",
}

PING_COUNT = 5                # Pacotes por medição
PING_TIMEOUT = 2.0            # Timeout por pacote (segundos)
OUTAGE_THRESHOLD = 30.0       # Segundos sem resposta para declarar queda


@dataclass
class PingResult:
    """Resultado de uma medição ICMP para um único alvo."""

    target: str
    host: str
    timestamp: float = field(default_factory=time.time)
    rtt_min: Optional[float] = None     # ms
    rtt_avg: Optional[float] = None     # ms
    rtt_max: Optional[float] = None     # ms
    rtt_mdev: Optional[float] = None    # ms — desvio padrão
    packet_loss: float = 0.0            # 0.0–1.0
    packets_sent: int = 0
    packets_received: int = 0
    error: Optional[str] = None

    @property
    def is_reachable(self) -> bool:
        """Retorna True se o host respondeu ao menos um pacote."""
        return self.packets_received > 0

    @property
    def loss_percent(self) -> float:
        """Perda de pacotes em porcentagem (0–100)."""
        return self.packet_loss * 100


@dataclass
class BufferbloatResult:
    """Resultado do teste de bufferbloat."""

    timestamp: float = field(default_factory=time.time)
    baseline_rtt: Optional[float] = None    # ms — latência sem carga
    loaded_rtt: Optional[float] = None      # ms — latência sob carga
    delta_ms: Optional[float] = None        # diferença em ms
    grade: str = "unknown"                  # Nenhum / Leve / Moderado / Severo

    def classify(self) -> None:
        """
        Classifica o bufferbloat conforme o delta de latência:
          < 5ms   → Nenhum
          5–30ms  → Leve
          30–100ms → Moderado
          > 100ms → Severo
        """
        if self.delta_ms is None:
            self.grade = "unknown"
        elif self.delta_ms < 5:
            self.grade = "Nenhum"
        elif self.delta_ms < 30:
            self.grade = "Leve"
        elif self.delta_ms < 100:
            self.grade = "Moderado"
        else:
            self.grade = "Severo"


class ICMPCollector:
    """
    Coletor assíncrono de métricas ICMP.

    Executa pings periódicos para múltiplos alvos (gateway, DNS interno,
    DNS externo, internet pública) e persiste os resultados no banco SQLite.

    Uso:
        collector = ICMPCollector(targets=DEFAULT_TARGETS, interval=30)
        await collector.start()
    """

    def __init__(
        self,
        targets: dict[str, Optional[str]] = None,
        interval: float = 30.0,
        ping_count: int = PING_COUNT,
        ping_timeout: float = PING_TIMEOUT,
        db=None,
    ):
        """
        Args:
            targets:      Dicionário {nome: ip} dos hosts a monitorar.
            interval:     Intervalo em segundos entre coletas.
            ping_count:   Número de pacotes ICMP por medição.
            ping_timeout: Timeout por pacote em segundos.
            db:           Instância do repositório SQLite para persistência.
        """
        self.targets = targets or DEFAULT_TARGETS.copy()
        self.interval = interval
        self.ping_count = ping_count
        self.ping_timeout = ping_timeout
        self.db = db
        self._running = False
        self._last_results: dict[str, PingResult] = {}
        self._outage_start: dict[str, Optional[float]] = {}

    async def ping(self, host: str, count: int = None, timeout: float = None) -> PingResult:
        """
        Executa ping assíncrono via subprocess para um único host.

        Args:
            host:    Endereço IP ou hostname do alvo.
            count:   Número de pacotes (padrão: self.ping_count).
            timeout: Timeout por pacote (padrão: self.ping_timeout).

        Returns:
            PingResult com RTT e perda de pacotes.
        """
        count = count or self.ping_count
        timeout = timeout or self.ping_timeout
        result = PingResult(target=host, host=host)

        try:
            cmd = [
                "ping",
                "-c", str(count),
                "-W", str(int(timeout)),
                "-q",   # quiet — apenas resumo
                host,
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout * count + 5
            )
            result.packets_sent = count
            self._parse_ping_output(result, stdout.decode())
        except asyncio.TimeoutError:
            result.error = "timeout"
            result.packet_loss = 1.0
        except Exception as exc:
            result.error = str(exc)
            result.packet_loss = 1.0
            logger.warning("Erro ao pingar %s: %s", host, exc)

        return result

    def _parse_ping_output(self, result: PingResult, output: str) -> None:
        """
        Extrai métricas do output do comando ping (Linux).

        Exemplo de output esperado:
          5 packets transmitted, 4 received, 20% packet loss
          rtt min/avg/max/mdev = 1.234/2.345/3.456/0.567 ms
        """
        for line in output.splitlines():
            if "packets transmitted" in line:
                parts = line.split(",")
                result.packets_sent = int(parts[0].strip().split()[0])
                result.packets_received = int(parts[1].strip().split()[0])
                loss_str = parts[2].strip().split()[0].replace("%", "")
                result.packet_loss = float(loss_str) / 100.0
            elif line.startswith("rtt"):
                stats = line.split("=")[1].strip().split()[0].split("/")
                result.rtt_min = float(stats[0])
                result.rtt_avg = float(stats[1])
                result.rtt_max = float(stats[2])
                result.rtt_mdev = float(stats[3])

    async def ping_all(self) -> dict[str, PingResult]:
        """
        Executa ping para todos os alvos configurados em paralelo.

        Returns:
            Dicionário {nome_alvo: PingResult}.
        """
        tasks = {
            name: asyncio.create_task(self.ping(host))
            for name, host in self.targets.items()
            if host is not None
        }
        results = {}
        for name, task in tasks.items():
            try:
                results[name] = await task
            except Exception as exc:
                logger.error("Falha no ping de %s: %s", name, exc)
        self._last_results = results
        self._check_outages(results)
        return results

    def _check_outages(self, results: dict[str, PingResult]) -> None:
        """
        Detecta e registra quedas de conexão.
        Marca início da queda quando gateway não responde e
        registra no banco quando a conexão é restaurada.
        """
        gateway_result = results.get("gateway")
        if gateway_result is None:
            return

        now = time.time()
        if not gateway_result.is_reachable:
            if "gateway" not in self._outage_start:
                self._outage_start["gateway"] = now
                logger.warning("Queda detectada: gateway %s sem resposta", gateway_result.host)
        else:
            if "gateway" in self._outage_start:
                duration = now - self._outage_start.pop("gateway")
                logger.info("Conexão restaurada após %.1fs", duration)
                if self.db:
                    # TODO: self.db.record_outage(start=..., duration=duration)
                    pass

    async def measure_bufferbloat(
        self, target: str = "8.8.8.8", load_duration: float = 5.0
    ) -> BufferbloatResult:
        """
        Mede bufferbloat comparando latência baseline com latência sob carga.

        A carga é simulada por múltiplos pings concorrentes.
        Em versão futura, pode ser integrada com iperf3.

        Args:
            target:        Host para medir latência (padrão: 8.8.8.8).
            load_duration: Duração do teste de carga em segundos.

        Returns:
            BufferbloatResult classificado.
        """
        result = BufferbloatResult()

        # Mede baseline (sem carga)
        baseline = await self.ping(target, count=10)
        result.baseline_rtt = baseline.rtt_avg

        if result.baseline_rtt is None:
            result.grade = "unknown"
            return result

        # Simula carga com pings concorrentes
        load_tasks = [
            asyncio.create_task(self.ping(target, count=20, timeout=1.0))
            for _ in range(4)
        ]
        loaded_pings = await asyncio.gather(*load_tasks, return_exceptions=True)
        valid = [r for r in loaded_pings if isinstance(r, PingResult) and r.rtt_avg]
        if valid:
            result.loaded_rtt = sum(r.rtt_avg for r in valid) / len(valid)
            result.delta_ms = result.loaded_rtt - result.baseline_rtt
            result.classify()

        return result

    async def start(self) -> None:
        """
        Inicia o loop de coleta assíncrona.
        Executa ping_all() a cada self.interval segundos.
        """
        self._running = True
        logger.info("ICMPCollector iniciado — intervalo: %ss", self.interval)
        while self._running:
            try:
                results = await self.ping_all()
                if self.db:
                    # TODO: self.db.save_icmp_batch(results)
                    pass
                logger.debug("Coleta ICMP concluída: %d alvos", len(results))
            except Exception as exc:
                logger.error("Erro no ciclo ICMP: %s", exc)
            await asyncio.sleep(self.interval)

    async def stop(self) -> None:
        """Para o loop de coleta."""
        self._running = False
        logger.info("ICMPCollector parado.")

    @property
    def last_results(self) -> dict[str, PingResult]:
        """Retorna o último conjunto de resultados coletados."""
        return self._last_results
