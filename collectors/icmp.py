"""
collectors/icmp.py — Coletor de latência e perda de pacotes via ICMP (ping).

Responsável por medir:
  - Latência (RTT) em milissegundos para múltiplos alvos
  - Perda de pacotes (%)
  - Detecção e classificação de quedas (local, ISP, total)
  - Bufferbloat: comparação de latência baseline vs. sob carga

Requer o binário `ping` disponível no PATH (padrão em todas as distros Linux).
Para usar ICMP raw socket diretamente (sem subprocess), execute como root ou:
    sudo setcap cap_net_raw+ep $(which python3)

Compatibilidade: Linux (usa flags -c/-W/-q do iputils-ping).
"""

import asyncio
import ipaddress
import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)

# ─── Configuração padrão ──────────────────────────────────────────────────────

# Alvos de monitoramento (PRD seção 4.1-A)
DEFAULT_TARGETS = {
    "gateway":      None,          # Auto-detectado via 'ip route'
    "dns_interno":  None,          # Auto-detectado via /etc/resolv.conf
    "cloudflare":   "1.1.1.1",
    "google_dns":   "8.8.8.8",
    "google_public":"8.8.4.4",
}

PING_COUNT   = 5      # Pacotes por medição normal
PING_TIMEOUT = 2      # Timeout por pacote (segundos, inteiro para -W)
OUTAGE_THRESHOLD  = 30.0   # Segundos sem resposta para declarar queda
BUFFERBLOAT_COUNT = 10     # Pacotes para medir baseline
BUFFERBLOAT_LOAD_STREAMS = 4  # Streams de carga simultâneos
BUFFERBLOAT_LOAD_COUNT   = 20  # Pacotes por stream de carga


# ─── Dataclasses de resultado ─────────────────────────────────────────────────

@dataclass
class PingResult:
    """Resultado de uma medição ICMP para um único alvo."""

    target: str           # Nome do alvo (ex: "gateway", "cloudflare")
    host: str             # IP ou hostname pingado
    timestamp: float = field(default_factory=time.time)

    rtt_min:  Optional[float] = None   # ms
    rtt_avg:  Optional[float] = None   # ms
    rtt_max:  Optional[float] = None   # ms
    rtt_mdev: Optional[float] = None   # ms — desvio padrão (jitter proxy)

    packet_loss:      float = 0.0   # 0.0–1.0
    packets_sent:     int   = 0
    packets_received: int   = 0

    error: Optional[str] = None    # Mensagem de erro se falhou

    @property
    def is_reachable(self) -> bool:
        """True se ao menos um pacote foi respondido."""
        return self.packets_received > 0

    @property
    def loss_percent(self) -> float:
        """Perda de pacotes em percentual (0–100)."""
        return self.packet_loss * 100

    def __repr__(self) -> str:
        if self.is_reachable:
            return (
                f"PingResult({self.target}@{self.host} "
                f"avg={self.rtt_avg:.1f}ms loss={self.loss_percent:.0f}%)"
            )
        return f"PingResult({self.target}@{self.host} UNREACHABLE err={self.error})"


class OutageType(str, Enum):
    """Tipo de queda detectada pela análise multi-host."""
    NONE      = "none"        # Sem queda
    LOCAL     = "local"       # Gateway não responde → problema local (cabo/Wi-Fi/roteador)
    ISP       = "isp"         # Gateway OK, internet não → problema na operadora
    TOTAL     = "total"       # Tudo inacessível → queda total
    PARTIAL   = "partial"     # Alguns alvos sem resposta → instabilidade


@dataclass
class OutageResult:
    """Resultado da análise de queda para um ciclo de coleta."""

    timestamp: float = field(default_factory=time.time)
    outage_type: OutageType = OutageType.NONE
    unreachable_targets: list = field(default_factory=list)
    reachable_targets:   list = field(default_factory=list)
    duration_s: Optional[float] = None   # Preenchido quando a queda termina
    description: str = ""

    @property
    def is_outage(self) -> bool:
        return self.outage_type != OutageType.NONE


@dataclass
class BufferbloatResult:
    """Resultado do teste de bufferbloat."""

    timestamp: float = field(default_factory=time.time)
    target: str = "8.8.8.8"

    baseline_rtt: Optional[float] = None   # ms — sem carga
    loaded_rtt:   Optional[float] = None   # ms — sob carga
    delta_ms:     Optional[float] = None   # diferença

    # Estatísticas complementares
    baseline_samples: int = 0
    loaded_samples:   int = 0

    grade: str = "unknown"   # Nenhum / Leve / Moderado / Severo

    def classify(self) -> None:
        """
        Classifica bufferbloat pelo delta de latência (PRD seção 4.1-D):
          delta < 5ms   → Nenhum
          5–30ms        → Leve
          30–100ms      → Moderado
          > 100ms       → Severo
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

    def __repr__(self) -> str:
        return (
            f"BufferbloatResult(grade={self.grade} "
            f"baseline={self.baseline_rtt}ms loaded={self.loaded_rtt}ms "
            f"delta={self.delta_ms}ms)"
        )


# ─── Helpers de sistema ───────────────────────────────────────────────────────

async def detect_gateway() -> Optional[str]:
    """
    Detecta o IP do gateway padrão usando 'ip route get 8.8.8.8'.

    Mais confiável que ler /proc/net/route porque resolve corretamente
    roteamento por políticas e múltiplas tabelas.

    Returns:
        IP do gateway (ex: "192.168.1.1") ou None se não detectado.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            "ip", "route", "get", "8.8.8.8",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5.0)
        output = stdout.decode()
        # Formato esperado: "8.8.8.8 via 192.168.1.1 dev eth0 ..."
        match = re.search(r"via\s+(\d+\.\d+\.\d+\.\d+)", output)
        if match:
            gw = match.group(1)
            logger.info("Gateway detectado: %s", gw)
            return gw
        # Fallback: rota direta (sem 'via'), pega 'src'
        match = re.search(r"src\s+(\d+\.\d+\.\d+\.\d+)", output)
        if match:
            logger.info("Gateway (src direto): %s", match.group(1))
            return match.group(1)
    except Exception as exc:
        logger.warning("Falha ao detectar gateway via 'ip route': %s", exc)

    # Fallback: lê /proc/net/route
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 3 and parts[1] == "00000000":  # destino default
                    # Gateway em hexadecimal little-endian
                    gw_hex = parts[2]
                    gw_bytes = bytes.fromhex(gw_hex)[::-1]
                    gw_ip = ".".join(str(b) for b in gw_bytes)
                    if gw_ip != "0.0.0.0":
                        logger.info("Gateway detectado via /proc/net/route: %s", gw_ip)
                        return gw_ip
    except Exception as exc:
        logger.warning("Falha ao ler /proc/net/route: %s", exc)

    return None


def detect_dns_resolver() -> Optional[str]:
    """
    Detecta o resolver DNS interno lendo /etc/resolv.conf.

    Returns:
        IP do primeiro nameserver (ex: "192.168.1.1") ou None.
    """
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[1]
                        # Valida que é um IP (ignora ::1, localhost, etc.)
                        try:
                            ipaddress.ip_address(ip)
                            logger.info("DNS interno detectado: %s", ip)
                            return ip
                        except ValueError:
                            continue
    except Exception as exc:
        logger.warning("Falha ao ler /etc/resolv.conf: %s", exc)
    return None


# ─── Parser de output do ping ─────────────────────────────────────────────────

def parse_ping_output(result: PingResult, output: str) -> None:
    """
    Extrai métricas do output do comando ping do Linux (iputils).

    Formatos tratados:

    Resumo de pacotes (obrigatório):
      5 packets transmitted, 4 received, 20% packet loss, time 4001ms
      5 packets transmitted, 5 received, 0% packet loss, time 4004ms

    Estatísticas RTT (ausente se 100% loss):
      rtt min/avg/max/mdev = 1.234/2.345/3.456/0.567 ms

    Args:
        result: PingResult a preencher (modificado in-place).
        output: String do stdout do ping.
    """
    for line in output.splitlines():
        line = line.strip()

        # Linha de resumo de pacotes
        if "packets transmitted" in line:
            # "5 packets transmitted, 4 received, 20% packet loss"
            # "5 packets transmitted, 5 received, +1 errors, 0% packet loss"
            try:
                sent_match = re.search(r"(\d+)\s+packets\s+transmitted", line)
                recv_match = re.search(r"(\d+)\s+received", line)
                loss_match = re.search(r"(\d+(?:\.\d+)?)\s*%\s+packet\s+loss", line)

                if sent_match:
                    result.packets_sent = int(sent_match.group(1))
                if recv_match:
                    result.packets_received = int(recv_match.group(1))
                if loss_match:
                    result.packet_loss = float(loss_match.group(1)) / 100.0
            except (ValueError, AttributeError) as exc:
                logger.debug("Falha ao parsear linha de pacotes '%s': %s", line, exc)

        # Linha de estatísticas RTT
        elif line.startswith("rtt ") and "=" in line:
            # "rtt min/avg/max/mdev = 1.234/2.345/3.456/0.567 ms"
            try:
                stats_part = line.split("=")[1].strip().split()[0]  # "1.234/2.345/3.456/0.567"
                parts = stats_part.split("/")
                if len(parts) == 4:
                    result.rtt_min  = float(parts[0])
                    result.rtt_avg  = float(parts[1])
                    result.rtt_max  = float(parts[2])
                    result.rtt_mdev = float(parts[3])
            except (ValueError, IndexError) as exc:
                logger.debug("Falha ao parsear RTT '%s': %s", line, exc)


# ─── Classe principal ─────────────────────────────────────────────────────────

class ICMPCollector:
    """
    Coletor assíncrono de métricas ICMP.

    Orquestra coletas periódicas de ping para múltiplos alvos,
    detecta quedas por análise multi-host, mede bufferbloat e
    persiste métricas no banco SQLite via repositório injetado.

    Fluxo por ciclo:
      1. ping_all()           → PingResult por alvo (paralelo)
      2. detect_outage()      → classifica tipo de queda
      3. db.save_icmp_batch() → persiste no SQLite
      4. EventBus.publish()   → notifica SSE

    Uso básico:
        collector = ICMPCollector()
        await collector.auto_discover()   # detecta gateway e DNS
        await collector.start()           # loop infinito

    Uso avançado (em tarefa separada):
        collector = ICMPCollector(targets={"gateway": "192.168.1.1"}, interval=15)
        results = await collector.ping_all()
        outage  = collector.detect_outage(results)
    """

    def __init__(
        self,
        targets: Optional[dict] = None,
        interval:      float = 30.0,
        ping_count:    int   = PING_COUNT,
        ping_timeout:  int   = PING_TIMEOUT,
        db=None,
        event_bus=None,
    ):
        """
        Args:
            targets:      {nome: ip} — None para auto-detectar gateway/DNS.
            interval:     Segundos entre ciclos de coleta.
            ping_count:   Pacotes ICMP por medição (padrão: 5).
            ping_timeout: Timeout por pacote em segundos (padrão: 2).
            db:           Repositório SQLite (db.repository.Repository).
            event_bus:    EventBus SSE para publicar métricas em tempo real.
        """
        self.targets      = targets or DEFAULT_TARGETS.copy()
        self.interval     = interval
        self.ping_count   = ping_count
        self.ping_timeout = ping_timeout
        self.db           = db
        self.event_bus    = event_bus

        self._running = False
        self._last_results: dict[str, PingResult] = {}

        # Controle de quedas: {nome_alvo: timestamp_início}
        self._outage_start: dict[str, float] = {}
        # ID do registro de queda no DB (para fechar ao restaurar)
        self._outage_db_id: dict[str, Optional[int]] = {}

    # ─── Auto-descoberta ──────────────────────────────────────────────────────

    async def auto_discover(self) -> None:
        """
        Detecta automaticamente gateway e DNS interno e preenche self.targets.

        Chamado na inicialização antes de start(). Seguro chamar múltiplas
        vezes — só sobrescreve entradas que ainda são None.
        """
        if self.targets.get("gateway") is None:
            gw = await detect_gateway()
            if gw:
                self.targets["gateway"] = gw

        if self.targets.get("dns_interno") is None:
            dns = detect_dns_resolver()
            if dns:
                self.targets["dns_interno"] = dns

        active = {k: v for k, v in self.targets.items() if v}
        logger.info(
            "Auto-discover concluído: %d alvos ativos — %s",
            len(active),
            ", ".join(f"{k}={v}" for k, v in active.items()),
        )

    # ─── Ping individual ──────────────────────────────────────────────────────

    async def ping(
        self,
        host: str,
        count: Optional[int] = None,
        timeout: Optional[int] = None,
        target_name: Optional[str] = None,
    ) -> PingResult:
        """
        Executa ping para um único host via subprocess.

        Usa o comando `ping` nativo do Linux (iputils-ping) com flags:
          -c N   número de pacotes
          -W N   timeout por pacote (segundos)
          -q     output silencioso (apenas resumo)
          -n     sem resolução reversa de DNS (mais rápido)

        Args:
            host:        IP ou hostname do alvo.
            count:       Pacotes a enviar (padrão: self.ping_count).
            timeout:     Timeout por pacote em segundos (padrão: self.ping_timeout).
            target_name: Nome para o campo PingResult.target (padrão: host).

        Returns:
            PingResult preenchido. Nunca lança exceção — erros ficam em .error.
        """
        count   = count   if count   is not None else self.ping_count
        timeout = timeout if timeout is not None else self.ping_timeout
        name    = target_name or host

        result = PingResult(target=name, host=host, packets_sent=count)

        cmd = ["ping", "-c", str(count), "-W", str(timeout), "-n", "-q", host]
        total_timeout = float(timeout * count + 5)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=total_timeout
                )
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                except Exception:
                    pass
                try:
                    await proc.communicate()
                except Exception:
                    pass
                result.error = f"processo ping excedeu timeout de {total_timeout:.0f}s"
                result.packet_loss = 1.0
                logger.debug("ping timeout para %s", host)
                return result

            stdout_str = stdout.decode(errors="replace")
            stderr_str = stderr.decode(errors="replace").strip()

            if proc.returncode not in (0, 1):
                # Código 2 = erro de rede/permissão; outros = erros graves
                result.error = stderr_str or f"ping retornou código {proc.returncode}"
                result.packet_loss = 1.0
                logger.debug("ping falhou para %s (rc=%d): %s", host, proc.returncode, result.error)
                return result

            parse_ping_output(result, stdout_str)

            # Segurança: se parse não encontrou linha de pacotes, marca como falha
            if result.packets_sent == 0:
                result.packets_sent = count
            if result.packets_received == 0 and result.packet_loss == 0.0 and not stdout_str.strip():
                result.packet_loss = 1.0
                result.error = "output vazio"

        except FileNotFoundError:
            result.error = "binário 'ping' não encontrado no PATH"
            result.packet_loss = 1.0
            logger.error("'ping' não encontrado. Instale iputils-ping.")
        except PermissionError:
            result.error = "permissão negada — execute como root ou configure cap_net_raw"
            result.packet_loss = 1.0
            logger.error("Sem permissão para ICMP. Use: sudo setcap cap_net_raw+ep $(which python3)")
        except Exception as exc:
            result.error = str(exc)
            result.packet_loss = 1.0
            logger.warning("Erro inesperado ao pingar %s: %s", host, exc)

        return result

    # ─── Ping em paralelo ─────────────────────────────────────────────────────

    async def ping_all(self) -> dict[str, PingResult]:
        """
        Executa ping para todos os alvos configurados em paralelo.

        Alvos com IP None são ignorados silenciosamente.
        Falhas individuais não cancelam os demais.

        Returns:
            {nome_alvo: PingResult} — contém apenas alvos com IP configurado.
        """
        active_targets = {
            name: host
            for name, host in self.targets.items()
            if host is not None
        }

        if not active_targets:
            logger.warning("Nenhum alvo configurado para ping_all(). Rode auto_discover() primeiro.")
            return {}

        tasks = {
            name: asyncio.create_task(
                self.ping(host, target_name=name),
                name=f"ping-{name}",
            )
            for name, host in active_targets.items()
        }

        results: dict[str, PingResult] = {}
        done = await asyncio.gather(*tasks.values(), return_exceptions=True)

        for name, outcome in zip(tasks.keys(), done):
            if isinstance(outcome, PingResult):
                results[name] = outcome
            else:
                # Exceção inesperada na task (não deveria ocorrer — ping() captura tudo)
                logger.error("Falha na task de ping para %s: %s", name, outcome)
                r = PingResult(target=name, host=active_targets[name])
                r.error = str(outcome)
                r.packet_loss = 1.0
                results[name] = r

        self._last_results = results
        return results

    # ─── Detecção de quedas ───────────────────────────────────────────────────

    def detect_outage(self, results: dict[str, PingResult]) -> OutageResult:
        """
        Analisa um conjunto de PingResults e classifica o tipo de queda.

        Lógica de classificação:
          - gateway inacessível + internet inacessível → TOTAL
          - gateway inacessível + internet acessível   → LOCAL  (impossível normalmente,
                                                                  indica rota assimétrica)
          - gateway acessível   + internet inacessível → ISP
          - gateway acessível   + algum externo falha  → PARTIAL
          - tudo acessível                             → NONE

        Também atualiza self._outage_start para rastrear duração
        e chama o repositório para registrar/fechar quedas no SQLite.

        Args:
            results: Saída de ping_all().

        Returns:
            OutageResult com tipo, alvos afetados e duração (se recuperando).
        """
        now = time.time()

        reachable   = [name for name, r in results.items() if r.is_reachable]
        unreachable = [name for name, r in results.items() if not r.is_reachable]

        gw_ok    = results.get("gateway") and results["gateway"].is_reachable
        inet_ok  = any(
            results[t].is_reachable
            for t in ("cloudflare", "google_dns", "google_public")
            if t in results
        )

        # Determina tipo
        if not unreachable:
            outage_type = OutageType.NONE
        elif not gw_ok and not inet_ok:
            outage_type = OutageType.TOTAL
        elif not gw_ok and inet_ok:
            outage_type = OutageType.LOCAL
        elif gw_ok and not inet_ok:
            outage_type = OutageType.ISP
        else:
            outage_type = OutageType.PARTIAL

        # Descrições amigáveis
        descriptions = {
            OutageType.NONE:    "Rede operando normalmente.",
            OutageType.TOTAL:   "Sem conexão: gateway e internet inacessíveis.",
            OutageType.LOCAL:   "Problema local: gateway não responde (cabo, Wi-Fi ou roteador).",
            OutageType.ISP:     "Problema na operadora: gateway OK mas internet inacessível.",
            OutageType.PARTIAL: f"Instabilidade: {', '.join(unreachable)} sem resposta.",
        }

        outage_result = OutageResult(
            outage_type=outage_type,
            reachable_targets=reachable,
            unreachable_targets=unreachable,
            description=descriptions[outage_type],
        )

        # Rastreia início e fim das quedas para persistência
        self._track_outage_lifecycle(outage_type, outage_result, now)

        if outage_type != OutageType.NONE:
            logger.warning("[OUTAGE %s] %s", outage_type.value.upper(), outage_result.description)

        return outage_result

    def _track_outage_lifecycle(
        self,
        outage_type: OutageType,
        outage_result: OutageResult,
        now: float,
    ) -> None:
        """
        Mantém o estado de início/fim das quedas e interage com o DB.

        Quando a queda começa: registra timestamp e cria registro no DB.
        Quando a queda termina: calcula duração e fecha registro no DB.
        """
        key = "current_outage"

        if outage_type != OutageType.NONE:
            if key not in self._outage_start:
                self._outage_start[key] = now
                gateway_ip = self.targets.get("gateway", "unknown")
                logger.info(
                    "Início de queda registrado [%s] gateway=%s",
                    outage_type.value, gateway_ip,
                )
                if self.db:
                    # Agenda tarefa para não bloquear método síncrono
                    asyncio.create_task(
                        self._db_record_outage_start(gateway_ip)
                    )
        else:
            if key in self._outage_start:
                duration = now - self._outage_start.pop(key)
                outage_result.duration_s = duration
                outage_id = self._outage_db_id.pop(key, None)
                logger.info("Queda encerrada — duração: %.1fs", duration)
                if self.db and outage_id:
                    asyncio.create_task(
                        self._db_record_outage_end(outage_id)
                    )

    async def _db_record_outage_start(self, gateway: str) -> None:
        """Persiste início de queda no banco de forma assíncrona."""
        try:
            outage_id = await self.db.record_outage_start(gateway)
            self._outage_db_id["current_outage"] = outage_id
        except Exception as exc:
            logger.error("Falha ao registrar início de queda no DB: %s", exc)

    async def _db_record_outage_end(self, outage_id: int) -> None:
        """Persiste fim de queda no banco de forma assíncrona."""
        try:
            await self.db.record_outage_end(outage_id)
        except Exception as exc:
            logger.error("Falha ao registrar fim de queda no DB: %s", exc)

    # ─── Propriedade de duração da queda atual ────────────────────────────────

    @property
    def current_outage_duration(self) -> Optional[float]:
        """
        Retorna a duração em segundos da queda atual, ou None se não há queda.
        Usado pelo Correlator para aplicar a regra OUTAGE_THRESHOLD.
        """
        start = self._outage_start.get("current_outage")
        return (time.time() - start) if start else None

    # ─── Bufferbloat ──────────────────────────────────────────────────────────

    async def measure_bufferbloat(
        self,
        target: str = "8.8.8.8",
        baseline_count: int = BUFFERBLOAT_COUNT,
        load_streams: int = BUFFERBLOAT_LOAD_STREAMS,
        load_count: int = BUFFERBLOAT_LOAD_COUNT,
    ) -> BufferbloatResult:
        """
        Mede bufferbloat comparando latência baseline com latência sob carga.

        Metodologia (PRD seção 4.1-D):
          1. Mede latência baseline com N pings sequenciais
          2. Aplica carga sintética com M streams de pings concorrentes
          3. Mede latência sob carga durante o período de carga
          4. Calcula delta = loaded_avg - baseline_avg
          5. Classifica: Nenhum / Leve / Moderado / Severo

        Nota: A carga sintética com pings concorrentes é uma aproximação.
        Para medição precisa de bufferbloat, use iperf3 integrado (Fase 2).

        Args:
            target:         IP para medir (padrão: 8.8.8.8).
            baseline_count: Pacotes para baseline (padrão: 10).
            load_streams:   Streams simultâneos para simular carga (padrão: 4).
            load_count:     Pacotes por stream de carga (padrão: 20).

        Returns:
            BufferbloatResult classificado com grade e delta.
        """
        result = BufferbloatResult(target=target)

        logger.debug("Iniciando teste de bufferbloat para %s", target)

        # ── Fase 1: baseline (sem carga) ──────────────────────────────────────
        baseline = await self.ping(
            target,
            count=baseline_count,
            timeout=max(self.ping_timeout, 3),
            target_name="bufferbloat-baseline",
        )

        if not baseline.is_reachable or baseline.rtt_avg is None:
            result.grade = "unknown"
            logger.warning("Bufferbloat: host %s não acessível para baseline", target)
            return result

        result.baseline_rtt = round(baseline.rtt_avg, 3)
        result.baseline_samples = baseline.packets_received

        logger.debug(
            "Bufferbloat baseline: %.2fms (mdev=%.2fms)",
            result.baseline_rtt, baseline.rtt_mdev or 0,
        )

        # ── Fase 2: carga sintética + medição sob carga ───────────────────────
        # Inicia streams de carga (pings rápidos e contínuos)
        load_tasks = [
            asyncio.create_task(
                self.ping(target, count=load_count, timeout=1, target_name=f"load-{i}"),
                name=f"bufferbloat-load-{i}",
            )
            for i in range(load_streams)
        ]

        # Mede latência enquanto os streams de carga estão rodando
        # Aguarda brevemente para a carga começar antes de medir
        await asyncio.sleep(0.2)
        loaded_probe = await self.ping(
            target,
            count=baseline_count,
            timeout=max(self.ping_timeout, 3),
            target_name="bufferbloat-loaded",
        )

        # Aguarda todos os streams terminarem
        load_results = await asyncio.gather(*load_tasks, return_exceptions=True)
        result.loaded_samples = baseline_count

        # ── Fase 3: calcula delta ─────────────────────────────────────────────
        if loaded_probe.is_reachable and loaded_probe.rtt_avg is not None:
            result.loaded_rtt = round(loaded_probe.rtt_avg, 3)
            result.delta_ms   = round(result.loaded_rtt - result.baseline_rtt, 3)
            result.classify()
        else:
            # Não conseguiu medir sob carga — pode ser saturação extrema
            result.loaded_rtt = None
            result.delta_ms   = None
            result.grade      = "Severo"
            logger.warning("Bufferbloat: sem resposta sob carga — classificado como Severo")

        logger.info(
            "Bufferbloat %s: baseline=%.1fms loaded=%s delta=%s grade=%s",
            target,
            result.baseline_rtt,
            f"{result.loaded_rtt:.1f}ms" if result.loaded_rtt else "N/A",
            f"{result.delta_ms:.1f}ms"   if result.delta_ms   else "N/A",
            result.grade,
        )

        return result

    # ─── Loop de coleta ───────────────────────────────────────────────────────

    async def start(self) -> None:
        """
        Inicia o loop de coleta periódica assíncrona.

        Por ciclo:
          1. Executa ping_all() em paralelo
          2. Analisa quedas com detect_outage()
          3. Persiste no banco se db configurado
          4. Publica no EventBus se configurado
          5. Dorme interval segundos

        Para parar: chame await stop() ou cancele a task.
        """
        await self.auto_discover()
        self._running = True

        logger.info(
            "ICMPCollector iniciado — %d alvos, intervalo=%ss",
            sum(1 for v in self.targets.values() if v),
            self.interval,
        )

        while self._running:
            cycle_start = time.monotonic()
            try:
                results = await self.ping_all()
                outage  = self.detect_outage(results)

                # Persiste no banco
                if self.db and results:
                    try:
                        await self.db.save_icmp_batch(results)
                    except Exception as exc:
                        logger.error("Falha ao salvar métricas ICMP no DB: %s", exc)

                # Publica no EventBus SSE
                if self.event_bus:
                    try:
                        self.event_bus.publish("icmp_update", {
                            "targets": {
                                name: {
                                    "rtt_avg_ms":   r.rtt_avg,
                                    "loss_percent": r.loss_percent,
                                    "reachable":    r.is_reachable,
                                }
                                for name, r in results.items()
                            },
                            "outage": outage.outage_type.value,
                            "timestamp": time.time(),
                        })
                    except Exception as exc:
                        logger.debug("Falha ao publicar no EventBus: %s", exc)

                cycle_ms = (time.monotonic() - cycle_start) * 1000
                logger.debug(
                    "Ciclo ICMP: %d alvos em %.0fms — queda: %s",
                    len(results), cycle_ms, outage.outage_type.value,
                )

            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Erro no ciclo ICMP: %s", exc, exc_info=True)

            # Dorme o tempo restante do intervalo (descontando o tempo da coleta)
            elapsed = time.monotonic() - cycle_start
            sleep_time = max(0.0, self.interval - elapsed)
            try:
                await asyncio.sleep(sleep_time)
            except asyncio.CancelledError:
                break

    async def stop(self) -> None:
        """Para o loop de coleta de forma limpa."""
        self._running = False
        logger.info("ICMPCollector parado.")

    # ─── Propriedades de acesso ───────────────────────────────────────────────

    @property
    def last_results(self) -> dict[str, PingResult]:
        """Último conjunto de resultados coletados."""
        return self._last_results

    @property
    def is_running(self) -> bool:
        """True se o loop de coleta está ativo."""
        return self._running

    def summary(self) -> dict:
        """
        Retorna um resumo compacto do estado atual para logs e debug.

        Returns:
            {target: {rtt_avg, loss_percent, reachable}}
        """
        return {
            name: {
                "rtt_avg_ms":   round(r.rtt_avg, 2) if r.rtt_avg else None,
                "loss_percent": round(r.loss_percent, 1),
                "reachable":    r.is_reachable,
            }
            for name, r in self._last_results.items()
        }
