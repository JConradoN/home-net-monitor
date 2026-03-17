"""
db/repository.py — Repositório SQLite para persistência de métricas.

Implementa todas as operações de leitura e escrita no banco de dados local.
Usa aiosqlite para operações não-bloqueantes dentro do loop asyncio.

Schema:
  - icmp_metrics:    Latência e perda por alvo (timestamp, target, rtt_avg, loss)
  - dns_metrics:     Latência DNS por resolver (timestamp, resolver, latency_ms)
  - snmp_metrics:    Métricas SNMP (timestamp, host, cpu, wan_in, wan_out)
  - wifi_metrics:    Métricas Wi-Fi por rádio (timestamp, radio, ch_util, noise, retries)
  - devices:         Dispositivos descobertos (mac, ip, hostname, vendor, type, last_seen)
  - outages:         Histórico de quedas (start_ts, end_ts, duration_s, gateway)
  - alerts:          Histórico de alertas (code, severity, title, timestamp, resolved_at)

Requer: pip install aiosqlite
"""

import asyncio
import logging
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = Path("data/home_net_monitor.db")

CREATE_TABLES_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS icmp_metrics (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   REAL NOT NULL,
    target      TEXT NOT NULL,
    host        TEXT NOT NULL,
    rtt_min_ms  REAL,
    rtt_avg_ms  REAL,
    rtt_max_ms  REAL,
    rtt_mdev_ms REAL,
    loss_pct    REAL NOT NULL DEFAULT 0,
    reachable   INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS dns_metrics (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       REAL NOT NULL,
    resolver_name   TEXT NOT NULL,
    resolver_ip     TEXT NOT NULL,
    avg_latency_ms  REAL,
    success_rate    REAL,
    diagnosis       TEXT,
    severity        TEXT
);

CREATE TABLE IF NOT EXISTS snmp_metrics (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       REAL NOT NULL,
    host            TEXT NOT NULL,
    cpu_usage       REAL,
    wan_in_bps      REAL,
    wan_out_bps     REAL,
    uptime_seconds  INTEGER
);

CREATE TABLE IF NOT EXISTS wifi_metrics (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp           REAL NOT NULL,
    host                TEXT NOT NULL,
    radio_index         INTEGER NOT NULL,
    clients             INTEGER,
    channel_util_pct    REAL,
    noise_floor_dbm     REAL,
    retries_pct         REAL
);

CREATE TABLE IF NOT EXISTS devices (
    mac             TEXT PRIMARY KEY,
    ip              TEXT NOT NULL,
    hostname        TEXT,
    vendor          TEXT,
    device_type     TEXT,
    device_label    TEXT,
    first_seen      REAL NOT NULL,
    last_seen       REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS outages (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    start_ts    REAL NOT NULL,
    end_ts      REAL,
    duration_s  REAL,
    gateway     TEXT,
    recovered   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    code        TEXT NOT NULL,
    severity    TEXT NOT NULL,
    title       TEXT NOT NULL,
    description TEXT,
    timestamp   REAL NOT NULL,
    resolved_at REAL,
    context     TEXT    -- JSON serializado
);

CREATE INDEX IF NOT EXISTS idx_icmp_timestamp ON icmp_metrics(timestamp);
CREATE INDEX IF NOT EXISTS idx_icmp_target ON icmp_metrics(target);
CREATE INDEX IF NOT EXISTS idx_dns_timestamp ON dns_metrics(timestamp);
CREATE INDEX IF NOT EXISTS idx_snmp_timestamp ON snmp_metrics(timestamp);
CREATE INDEX IF NOT EXISTS idx_outages_start ON outages(start_ts);
CREATE INDEX IF NOT EXISTS idx_alerts_code ON alerts(code);
"""


class Repository:
    """
    Repositório assíncrono para persistência de métricas no SQLite.

    Todas as operações são assíncronas (aiosqlite) e seguras para
    uso em múltiplas coroutines sem lock explícito (WAL mode).

    Uso:
        repo = Repository()
        await repo.initialize()
        await repo.save_icmp(result)
    """

    def __init__(self, db_path: Path = DEFAULT_DB_PATH):
        """
        Args:
            db_path: Caminho para o arquivo SQLite.
                     Criado automaticamente se não existir.
        """
        self.db_path = db_path
        self._db = None    # Conexão aiosqlite

    async def initialize(self) -> None:
        """
        Inicializa o banco de dados: cria arquivo, tabelas e índices.

        Deve ser chamado uma vez na inicialização da aplicação (main.py).
        Configura WAL mode para performance e segurança em gravações concorrentes.
        """
        import aiosqlite
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(str(self.db_path))
        await self._db.executescript(CREATE_TABLES_SQL)
        await self._db.commit()
        logger.info("Banco de dados inicializado: %s", self.db_path)

    async def close(self) -> None:
        """Fecha a conexão com o banco de dados."""
        if self._db:
            await self._db.close()
            logger.info("Banco de dados fechado.")

    # ─── ICMP ──────────────────────────────────────────────────────────────

    async def save_icmp_batch(self, results: dict) -> None:
        """
        Persiste um batch de resultados ICMP de uma rodada de coleta.

        Args:
            results: Dicionário {nome_alvo: PingResult} do ICMPCollector.
        """
        rows = [
            (
                r.timestamp, name, r.host,
                r.rtt_min, r.rtt_avg, r.rtt_max, r.rtt_mdev,
                r.packet_loss, int(r.is_reachable),
            )
            for name, r in results.items()
        ]
        await self._db.executemany(
            """INSERT INTO icmp_metrics
               (timestamp, target, host, rtt_min_ms, rtt_avg_ms, rtt_max_ms,
                rtt_mdev_ms, loss_pct, reachable)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            rows,
        )
        await self._db.commit()

    async def get_latency_series(self, hours: int = 24) -> dict:
        """
        Retorna série temporal de latência agregada para o dashboard.

        Coleta dados de múltiplos alvos (gateway, cloudflare/google_dns,
        dns interno) e alinha pelos timestamps mais próximos.

        Args:
            hours: Número de horas de histórico.

        Returns:
            {timestamps, gateway, internet, dns_internal} — listas paralelas.
        """
        since = time.time() - (hours * 3600)
        # Consulta pivotada: pega avg por target em intervalos de 5 min
        async with self._db.execute(
            """SELECT CAST(timestamp/300 AS INTEGER)*300 AS bucket,
                      target, AVG(rtt_avg_ms) AS rtt
               FROM icmp_metrics
               WHERE timestamp >= ?
               GROUP BY bucket, target
               ORDER BY bucket ASC""",
            (since,),
        ) as cursor:
            rows = await cursor.fetchall()

        # Reorganiza em {bucket: {target: rtt}}
        buckets: dict = {}
        for bucket, target, rtt in rows:
            if bucket not in buckets:
                buckets[bucket] = {}
            buckets[bucket][target] = rtt

        timestamps = sorted(buckets.keys())
        gateway = [buckets[t].get("gateway") for t in timestamps]
        internet = [
            buckets[t].get("cloudflare") or buckets[t].get("google_dns")
            for t in timestamps
        ]
        dns_internal = [buckets[t].get("dns_interno") for t in timestamps]

        return {
            "timestamps": timestamps,
            "gateway": gateway,
            "internet": internet,
            "dns_internal": dns_internal,
        }

    async def get_latency_series_for_target(self, target: str, hours: int = 24) -> list[dict]:
        """
        Retorna série temporal de latência para um alvo específico.

        Args:
            target: Nome do alvo (ex: 'gateway', 'cloudflare').
            hours:  Número de horas de histórico.

        Returns:
            Lista de {timestamp, rtt_avg_ms, loss_pct} ordenada por tempo.
        """
        since = time.time() - (hours * 3600)
        async with self._db.execute(
            """SELECT timestamp, rtt_avg_ms, loss_pct
               FROM icmp_metrics
               WHERE target=? AND timestamp>=?
               ORDER BY timestamp ASC""",
            (target, since),
        ) as cursor:
            rows = await cursor.fetchall()
        return [{"timestamp": r[0], "rtt_avg_ms": r[1], "loss_pct": r[2]} for r in rows]

    # ─── DNS ───────────────────────────────────────────────────────────────

    async def save_dns(self, comparison) -> None:
        """
        Persiste resultado de comparação DNS.

        Args:
            comparison: DNSComparisonResult do DNSCollector.
        """
        for name, stats in comparison.resolvers.items():
            await self._db.execute(
                """INSERT INTO dns_metrics
                   (timestamp, resolver_name, resolver_ip, avg_latency_ms,
                    success_rate, diagnosis, severity)
                   VALUES (?,?,?,?,?,?,?)""",
                (
                    comparison.timestamp, name, stats.ip,
                    stats.avg_latency_ms, stats.success_rate,
                    comparison.diagnosis, comparison.severity,
                ),
            )
        await self._db.commit()

    # ─── SNMP ──────────────────────────────────────────────────────────────

    async def save_snmp(self, result) -> None:
        """
        Persiste métricas SNMP do Mikrotik.

        Args:
            result: SNMPResult do SNMPCollector.
        """
        await self._db.execute(
            """INSERT INTO snmp_metrics
               (timestamp, host, cpu_usage, wan_in_bps, wan_out_bps, uptime_seconds)
               VALUES (?,?,?,?,?,?)""",
            (result.timestamp, result.host, result.cpu_usage,
             result.wan_in_bps, result.wan_out_bps, result.uptime_seconds),
        )
        for radio in result.wifi_radios:
            await self._db.execute(
                """INSERT INTO wifi_metrics
                   (timestamp, host, radio_index, clients, channel_util_pct,
                    noise_floor_dbm, retries_pct)
                   VALUES (?,?,?,?,?,?,?)""",
                (
                    result.timestamp, result.host,
                    radio.get("radio_index", 0),
                    radio.get("clients"), radio.get("channel_utilization"),
                    radio.get("noise_floor"), radio.get("retries_percent"),
                ),
            )
        await self._db.commit()

    # ─── Devices ───────────────────────────────────────────────────────────

    async def save_devices(self, devices: list) -> None:
        """
        Upsert de dispositivos descobertos.

        Args:
            devices: Lista de Device do FingerprintCollector.
        """
        for d in devices:
            await self._db.execute(
                """INSERT INTO devices
                   (mac, ip, hostname, vendor, device_type, device_label,
                    first_seen, last_seen)
                   VALUES (?,?,?,?,?,?,?,?)
                   ON CONFLICT(mac) DO UPDATE SET
                     ip=excluded.ip,
                     hostname=COALESCE(excluded.hostname, hostname),
                     vendor=COALESCE(excluded.vendor, vendor),
                     device_type=excluded.device_type,
                     device_label=excluded.device_label,
                     last_seen=excluded.last_seen""",
                (
                    d.mac_normalized, d.ip, d.hostname, d.vendor,
                    d.device_type, d.device_type_label,
                    d.first_seen, d.last_seen,
                ),
            )
        await self._db.commit()

    # ─── Outages ───────────────────────────────────────────────────────────

    async def record_outage_start(self, gateway: str) -> int:
        """
        Registra início de queda de conexão.

        Args:
            gateway: IP do gateway que parou de responder.

        Returns:
            ID do registro de queda criado.
        """
        cursor = await self._db.execute(
            "INSERT INTO outages (start_ts, gateway) VALUES (?,?)",
            (time.time(), gateway),
        )
        await self._db.commit()
        return cursor.lastrowid

    async def record_outage_end(self, outage_id: int) -> None:
        """
        Registra fim de queda, calculando duração.

        Args:
            outage_id: ID retornado por record_outage_start().
        """
        now = time.time()
        await self._db.execute(
            """UPDATE outages
               SET end_ts=?, duration_s=(?-start_ts), recovered=1
               WHERE id=?""",
            (now, now, outage_id),
        )
        await self._db.commit()

    async def get_outages(self, days: int = 7) -> list[dict]:
        """
        Retorna histórico de quedas dos últimos N dias.

        Args:
            days: Número de dias de histórico.

        Returns:
            Lista de {start_ts, end_ts, duration_s, gateway, recovered}.
        """
        since = time.time() - (days * 86400)
        async with self._db.execute(
            """SELECT start_ts, end_ts, duration_s, gateway, recovered
               FROM outages WHERE start_ts >= ? ORDER BY start_ts DESC""",
            (since,),
        ) as cursor:
            rows = await cursor.fetchall()
        return [
            {
                "start_ts": r[0], "end_ts": r[1],
                "duration_s": r[2], "gateway": r[3],
                "recovered": bool(r[4]),
            }
            for r in rows
        ]
