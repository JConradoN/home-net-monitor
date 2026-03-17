"""
collectors/snmp.py — Coletor de métricas via SNMP para Mikrotik e outros equipamentos.

Responsável por coletar via SNMPv2c:
  - CPU usage (%)
  - Tráfego WAN (bytes in/out, calculado como bps)
  - Clientes Wi-Fi por rádio
  - Channel Utilization (%)
  - Noise Floor (dBm)
  - Retries (%)
  - Uptime do equipamento

OIDs utilizadas são baseadas no MIB padrão (RFC 1213 + Mikrotik MIB).
Requer: pip install pysnmp
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# OIDs padrão (SNMP MIB-II + Mikrotik)
OID_SYSUPTIME = "1.3.6.1.2.1.1.3.0"
OID_SYSCPU = "1.3.6.1.2.1.25.3.3.1.2"           # hrProcessorLoad
OID_IF_IN_OCTETS = "1.3.6.1.2.1.2.2.1.10"        # ifInOctets (por interface)
OID_IF_OUT_OCTETS = "1.3.6.1.2.1.2.2.1.16"       # ifOutOctets (por interface)
OID_IF_DESCR = "1.3.6.1.2.1.2.2.1.2"             # ifDescr
OID_MIKROTIK_WIFI_CLIENTS = "1.3.6.1.4.1.14988.1.1.1.3.1.6"  # Mikrotik WIFI clients
OID_MIKROTIK_NOISE_FLOOR = "1.3.6.1.4.1.14988.1.1.1.3.1.9"   # Noise floor
OID_MIKROTIK_CHANNEL_UTIL = "1.3.6.1.4.1.14988.1.1.1.3.1.10"  # Channel utilization

DEFAULT_COMMUNITY = "public"
DEFAULT_PORT = 161
DEFAULT_TIMEOUT = 5            # segundos
SNMP_VERSION = "2c"

# Thresholds de alerta conforme PRD seção 4.1-C
THRESHOLD_CPU_CRITICAL = 80       # % — CPU Mikrotik crítico se > 80% por > 60s
THRESHOLD_CHANNEL_UTIL_WARN = 70  # % — Wi-Fi saturado
THRESHOLD_RETRIES_WARN = 15       # % — Interferência RF
THRESHOLD_NOISE_FLOOR_INFO = -75  # dBm — Ruído excessivo se > -75 dBm


@dataclass
class SNMPResult:
    """Resultado de uma coleta SNMP de um equipamento."""

    host: str
    community: str
    timestamp: float = field(default_factory=time.time)

    # Sistema
    uptime_seconds: Optional[int] = None
    cpu_usage: Optional[float] = None       # %

    # Interfaces WAN
    wan_in_bps: Optional[float] = None      # bits/s
    wan_out_bps: Optional[float] = None     # bits/s
    wan_interface: Optional[str] = None     # nome da interface WAN

    # Wi-Fi (por rádio — lista de dicts)
    wifi_radios: list = field(default_factory=list)
    # Cada item: {"radio": str, "clients": int, "channel_util": float, "noise_floor": float, "retries": float}

    error: Optional[str] = None

    @property
    def is_ok(self) -> bool:
        return self.error is None


@dataclass
class WifiRadioStats:
    """Métricas de um rádio Wi-Fi."""

    radio_index: int
    clients: int = 0
    channel_utilization: float = 0.0   # %
    noise_floor: float = -100.0        # dBm
    retries_percent: float = 0.0       # %

    @property
    def is_saturated(self) -> bool:
        return self.channel_utilization > THRESHOLD_CHANNEL_UTIL_WARN

    @property
    def has_interference(self) -> bool:
        return self.retries_percent > THRESHOLD_RETRIES_WARN

    @property
    def has_high_noise(self) -> bool:
        return self.noise_floor > THRESHOLD_NOISE_FLOOR_INFO


class SNMPCollector:
    """
    Coletor assíncrono de métricas SNMP para roteadores Mikrotik e similares.

    Realiza queries SNMP via pysnmp (wrapper assíncrono) e calcula taxa de
    tráfego WAN interpolando dois pontos no tempo (delta bytes / delta time).

    Uso:
        collector = SNMPCollector(host="192.168.1.1", community="public")
        result = await collector.collect()
    """

    def __init__(
        self,
        host: str,
        community: str = DEFAULT_COMMUNITY,
        port: int = DEFAULT_PORT,
        timeout: float = DEFAULT_TIMEOUT,
        interval: float = 60.0,
        db=None,
    ):
        """
        Args:
            host:      IP do equipamento a monitorar.
            community: SNMP community string (padrão: "public").
            port:      Porta SNMP UDP (padrão: 161).
            timeout:   Timeout por query em segundos.
            interval:  Intervalo entre coletas (segundos).
            db:        Repositório SQLite para persistência.
        """
        self.host = host
        self.community = community
        self.port = port
        self.timeout = timeout
        self.interval = interval
        self.db = db
        self._running = False
        self._last_result: Optional[SNMPResult] = None
        # Armazena contadores anteriores para calcular taxa (bps)
        self._prev_counters: dict = {}
        self._prev_timestamp: Optional[float] = None
        # Rastreia duração de CPU alta para alertas
        self._cpu_high_since: Optional[float] = None

    async def collect(self) -> SNMPResult:
        """
        Executa coleta completa de métricas SNMP do equipamento.

        Coleta em paralelo: CPU, interfaces, Wi-Fi.
        Calcula bps usando delta de contadores octets entre coletas.

        Returns:
            SNMPResult preenchido ou com campo error em caso de falha.
        """
        result = SNMPResult(host=self.host, community=self.community)
        try:
            await asyncio.gather(
                self._collect_system(result),
                self._collect_interfaces(result),
                self._collect_wifi(result),
            )
            self._last_result = result
            self._check_cpu_alert(result)
        except Exception as exc:
            result.error = str(exc)
            logger.error("Erro na coleta SNMP de %s: %s", self.host, exc)
        return result

    async def _collect_system(self, result: SNMPResult) -> None:
        """
        Coleta uptime e CPU do equipamento via hrProcessorLoad.

        OID: 1.3.6.1.2.1.25.3.3.1.2 (hrProcessorLoad)
        Retorna uso de CPU por núcleo; calcula média.
        """
        # TODO: Implementar com pysnmp
        # from pysnmp.hlapi.asyncio import getCmd, SnmpEngine, CommunityData, ...
        # Por ora, stub para estrutura e testes
        logger.debug("Coletando sistema SNMP de %s", self.host)
        # result.uptime_seconds = <valor do OID sysUpTime>
        # result.cpu_usage = <média dos valores hrProcessorLoad>

    async def _collect_interfaces(self, result: SNMPResult) -> None:
        """
        Coleta tráfego das interfaces e identifica a WAN.

        Estratégia:
          1. Busca ifDescr de todas as interfaces
          2. Identifica WAN pela descrição (ether1, wan, pppoe-out, etc.)
          3. Lê ifInOctets e ifOutOctets
          4. Calcula bps usando deltas entre coletas consecutivas

        OIDs: ifDescr (.2), ifInOctets (.10), ifOutOctets (.16)
        """
        logger.debug("Coletando interfaces SNMP de %s", self.host)
        # TODO: Implementar com pysnmp WALK nas OIDs de interface

    async def _collect_wifi(self, result: SNMPResult) -> None:
        """
        Coleta métricas Wi-Fi específicas do Mikrotik (MIB proprietária).

        OIDs Mikrotik:
          - 1.3.6.1.4.1.14988.1.1.1.3.1.6 — número de clientes por rádio
          - 1.3.6.1.4.1.14988.1.1.1.3.1.9 — noise floor (dBm)
          - 1.3.6.1.4.1.14988.1.1.1.3.1.10 — channel utilization (%)

        Para APs sem suporte SNMP (mesh Twibi, Deco), inferência é feita
        via latência ICMP conforme anotado nos riscos do PRD.
        """
        logger.debug("Coletando Wi-Fi SNMP de %s", self.host)
        # TODO: Implementar walk na MIB Mikrotik

    def _check_cpu_alert(self, result: SNMPResult) -> None:
        """
        Verifica alerta de CPU crítico: > 80% por mais de 60 segundos.

        Conforme PRD seção 4.1-C: 'CPU Mikrotik > 80% por > 60s → Critical'.
        Registra timestamp do início e emite alerta após threshold de tempo.
        """
        if result.cpu_usage is None:
            return

        now = time.time()
        if result.cpu_usage > THRESHOLD_CPU_CRITICAL:
            if self._cpu_high_since is None:
                self._cpu_high_since = now
                logger.warning("CPU alta em %s: %.1f%%", self.host, result.cpu_usage)
            elif now - self._cpu_high_since > 60:
                logger.critical(
                    "ALERTA CRÍTICO: CPU de %s acima de %d%% por %.0fs",
                    self.host, THRESHOLD_CPU_CRITICAL, now - self._cpu_high_since,
                )
        else:
            if self._cpu_high_since is not None:
                logger.info("CPU normalizada em %s: %.1f%%", self.host, result.cpu_usage)
            self._cpu_high_since = None

    async def test_connectivity(self) -> bool:
        """
        Testa se o equipamento responde SNMP corretamente.
        Usado pelo Wizard de Configuração SNMP (PRD seção 4.1-G).

        Returns:
            True se SNMP responde, False caso contrário.
        """
        try:
            # TODO: Implementar GET do OID sysDescr via pysnmp
            # OID: 1.3.6.1.2.1.1.1.0
            logger.info("Testando conectividade SNMP com %s", self.host)
            return True  # Stub
        except Exception as exc:
            logger.warning("SNMP indisponível em %s: %s", self.host, exc)
            return False

    async def start(self) -> None:
        """Inicia o loop de coleta periódica."""
        self._running = True
        logger.info("SNMPCollector iniciado para %s — intervalo: %ss", self.host, self.interval)
        while self._running:
            try:
                result = await self.collect()
                if self.db and result.is_ok:
                    # TODO: self.db.save_snmp(result)
                    pass
            except Exception as exc:
                logger.error("Erro no ciclo SNMP: %s", exc)
            await asyncio.sleep(self.interval)

    async def stop(self) -> None:
        """Para o loop de coleta."""
        self._running = False
        logger.info("SNMPCollector parado para %s.", self.host)

    @property
    def last_result(self) -> Optional[SNMPResult]:
        """Retorna o último resultado de coleta."""
        return self._last_result
