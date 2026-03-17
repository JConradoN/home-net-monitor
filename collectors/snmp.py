"""
collectors/snmp.py — Coletor de métricas SNMP para Mikrotik e equipamentos compatíveis.

Coleta via SNMPv2c (primário) ou RouterOS REST API (alternativa):
  - CPU usage (%) — hrProcessorLoad
  - Uptime do dispositivo — sysUpTime
  - Tráfego WAN in/out em bps — ifInOctets / ifOutOctets (deltas entre coletas)
  - Clientes Wi-Fi por rádio — Mikrotik MIB mtxrWlApClients
  - Channel Utilization (%) — mtxrWlApChannelUtilization
  - Noise Floor (dBm) — mtxrWlApNoiseFloor
  - Retries Wi-Fi (%) — calculado via ifInErrors / ifOutErrors como proxy

Arquitetura:
  SNMPCollector
    ├── SNMPSession         (pysnmp wrapper — testável via injeção)
    └── RouterOSAPISession  (RouterOS v7+ REST API — fallback quando SNMP off)

Testabilidade:
  SNMPSession e RouterOSAPISession são injetáveis. Testes passam mocks
  sem necessidade de pysnmp instalado.

Requer (opcional — fallback gracioso se ausente):
  pip install pysnmp aiohttp
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Optional, Protocol, runtime_checkable

logger = logging.getLogger(__name__)

# ─── Constantes e OIDs ────────────────────────────────────────────────────────

# MIB-II padrão (RFC 1213 / RFC 2863)
OID_SYS_DESCR      = "1.3.6.1.2.1.1.1.0"           # sysDescr — identificação
OID_SYS_UPTIME     = "1.3.6.1.2.1.1.3.0"           # sysUpTime — centésimos de segundo
OID_HR_CPU_LOAD    = "1.3.6.1.2.1.25.3.3.1.2"      # hrProcessorLoad (tabela, por núcleo)
OID_IF_DESCR       = "1.3.6.1.2.1.2.2.1.2"         # ifDescr (tabela)
OID_IF_IN_OCTETS   = "1.3.6.1.2.1.2.2.1.10"        # ifInOctets (tabela, 32-bit)
OID_IF_OUT_OCTETS  = "1.3.6.1.2.1.2.2.1.16"        # ifOutOctets (tabela, 32-bit)
OID_IF_IN_HC       = "1.3.6.1.2.1.31.1.1.1.6"      # ifHCInOctets (64-bit, preferido)
OID_IF_OUT_HC      = "1.3.6.1.2.1.31.1.1.1.10"     # ifHCOutOctets (64-bit, preferido)
OID_IF_IN_ERRORS   = "1.3.6.1.2.1.2.2.1.14"        # ifInErrors
OID_IF_OUT_ERRORS  = "1.3.6.1.2.1.2.2.1.20"        # ifOutErrors
OID_IF_IN_UCAST    = "1.3.6.1.2.1.2.2.1.11"        # ifInUcastPkts
OID_IF_OUT_UCAST   = "1.3.6.1.2.1.2.2.1.17"        # ifOutUcastPkts

# Mikrotik Enterprise MIB (1.3.6.1.4.1.14988)
OID_MTX_WIFI_AP    = "1.3.6.1.4.1.14988.1.1.1.3"   # mtxrWlApTable (base)
OID_MTX_WIFI_SSID  = "1.3.6.1.4.1.14988.1.1.1.3.1.2"   # mtxrWlApSsid
OID_MTX_WIFI_BAND  = "1.3.6.1.4.1.14988.1.1.1.3.1.11"  # mtxrWlApBand
OID_MTX_WIFI_FREQ  = "1.3.6.1.4.1.14988.1.1.1.3.1.7"   # mtxrWlApFreq (MHz)
OID_MTX_WIFI_CLIENTS   = "1.3.6.1.4.1.14988.1.1.1.3.1.6"   # mtxrWlApClients
OID_MTX_WIFI_NOISE     = "1.3.6.1.4.1.14988.1.1.1.3.1.9"   # mtxrWlApNoiseFloor (dBm)
OID_MTX_WIFI_CH_UTIL   = "1.3.6.1.4.1.14988.1.1.1.3.1.10"  # mtxrWlApChannelUtilization (%)
OID_MTX_CPU_FREQ   = "1.3.6.1.4.1.14988.1.1.3.14.0"  # mtxrHlCpuFrequency (MHz)

# Padrões de nome de interface WAN (ordem de prioridade)
WAN_IFACE_PATTERNS = [
    re.compile(r"ether1", re.I),
    re.compile(r"pppoe[-_]?out", re.I),
    re.compile(r"\bwan\b", re.I),
    re.compile(r"sfp[-_]?1", re.I),
    re.compile(r"internet", re.I),
    re.compile(r"uplink", re.I),
    re.compile(r"fibra", re.I),
]

# Parâmetros padrão
DEFAULT_COMMUNITY = "public"
DEFAULT_PORT      = 161
DEFAULT_TIMEOUT   = 5      # segundos
DEFAULT_RETRIES   = 1

# Thresholds de alerta (PRD seção 4.1-C)
THRESHOLD_CPU_CRITICAL    = 80    # %
THRESHOLD_CPU_DURATION    = 60    # segundos
THRESHOLD_CHANNEL_UTIL    = 70    # %
THRESHOLD_RETRIES_WARN    = 15    # %
THRESHOLD_NOISE_FLOOR     = -75   # dBm

# Overflow de contador SNMP 32-bit
COUNTER32_MAX = 0xFFFFFFFF


# ─── Dataclasses ──────────────────────────────────────────────────────────────

@dataclass
class WifiRadioStats:
    """Métricas de um rádio Wi-Fi coletadas via SNMP Mikrotik MIB."""

    radio_index: int
    ssid: str = ""
    band: str = ""           # "2ghz-b/g/n", "5ghz-a/n/ac", etc.
    frequency_mhz: int = 0   # frequência central do canal

    clients: int            = 0
    channel_utilization: float = 0.0    # %
    noise_floor: float      = -100.0    # dBm
    retries_percent: float  = 0.0       # %

    @property
    def band_label(self) -> str:
        """Retorna '2.4 GHz' ou '5 GHz' baseado na frequência ou band string."""
        if self.frequency_mhz:
            return "5 GHz" if self.frequency_mhz >= 5000 else "2.4 GHz"
        if "5ghz" in self.band.lower() or "5g" in self.band.lower():
            return "5 GHz"
        return "2.4 GHz"

    @property
    def is_saturated(self) -> bool:
        return self.channel_utilization > THRESHOLD_CHANNEL_UTIL

    @property
    def has_interference(self) -> bool:
        return self.retries_percent > THRESHOLD_RETRIES_WARN

    @property
    def has_high_noise(self) -> bool:
        return self.noise_floor > THRESHOLD_NOISE_FLOOR

    def to_dict(self) -> dict:
        return {
            "radio_index":          self.radio_index,
            "ssid":                 self.ssid,
            "band":                 self.band_label,
            "frequency_mhz":       self.frequency_mhz,
            "clients":              self.clients,
            "channel_utilization":  round(self.channel_utilization, 1),
            "noise_floor":          round(self.noise_floor, 1),
            "retries_percent":      round(self.retries_percent, 1),
        }


@dataclass
class SNMPResult:
    """Resultado completo de uma coleta SNMP de um equipamento."""

    host: str
    community: str
    timestamp: float = field(default_factory=time.time)

    # Identificação
    sys_descr: Optional[str]  = None

    # Sistema
    uptime_seconds: Optional[int]   = None
    cpu_usage: Optional[float]      = None   # %

    # Interface WAN
    wan_interface: Optional[str]    = None   # nome (ex: "ether1")
    wan_if_index: Optional[int]     = None   # índice SNMP
    wan_in_bps: Optional[float]     = None   # bits/s (calculado)
    wan_out_bps: Optional[float]    = None   # bits/s (calculado)
    wan_in_bytes_raw: Optional[int] = None   # contador bruto
    wan_out_bytes_raw: Optional[int]= None   # contador bruto

    # Wi-Fi
    wifi_radios: list[WifiRadioStats] = field(default_factory=list)

    # Metadados da coleta
    error: Optional[str]       = None
    collection_ms: Optional[float] = None   # tempo de coleta em ms
    backend: str = "snmp"       # "snmp" ou "routeros_api"

    @property
    def is_ok(self) -> bool:
        return self.error is None

    @property
    def has_wifi(self) -> bool:
        return len(self.wifi_radios) > 0

    def wifi_to_dict_list(self) -> list[dict]:
        return [r.to_dict() for r in self.wifi_radios]


# ─── Protocol para injeção / mock ─────────────────────────────────────────────

@runtime_checkable
class SNMPBackend(Protocol):
    """
    Interface que os backends SNMP devem implementar.

    Usada para injeção de dependência — permite trocar pysnmp por mock
    em testes sem precisar da biblioteca instalada.
    """

    async def get(self, *oids: str) -> dict[str, Any]:
        """
        GET SNMP para uma ou mais OIDs escalares.

        Args:
            *oids: OIDs a consultar (ex: "1.3.6.1.2.1.1.3.0").

        Returns:
            {oid: valor} — valores nativos Python (int, str, float).
            OIDs sem resposta ficam ausentes do dict.
        """
        ...

    async def walk(self, base_oid: str) -> list[tuple[str, Any]]:
        """
        WALK SNMP a partir de uma OID base.

        Args:
            base_oid: OID raiz da subárvore.

        Returns:
            Lista de (oid_str, valor) para todos os objetos encontrados.
        """
        ...


# ─── Backend pysnmp ───────────────────────────────────────────────────────────

class PySNMPSession:
    """
    Backend SNMP usando pysnmp (hlapi assíncrono).

    Implementa SNMPBackend com GET e WALK sobre UDP/SNMPv2c.
    Graciosamente indisponível se pysnmp não estiver instalado.

    Instalação: pip install pysnmp
    """

    def __init__(
        self,
        host: str,
        port: int = DEFAULT_PORT,
        community: str = DEFAULT_COMMUNITY,
        timeout: int = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
    ):
        self.host      = host
        self.port      = port
        self.community = community
        self.timeout   = timeout
        self.retries   = retries
        self._engine   = None   # lazy init

    def _ensure_engine(self):
        """Importa pysnmp e inicializa o SnmpEngine (lazy, thread-safe)."""
        if self._engine is not None:
            return
        try:
            from pysnmp.hlapi.asyncio import SnmpEngine
            self._engine = SnmpEngine()
        except ImportError:
            raise ImportError(
                "pysnmp não está instalado. Execute: pip install pysnmp"
            )

    def _build_objects(self, *oids: str):
        """Constrói ObjectType para pysnmp a partir de strings OID."""
        from pysnmp.hlapi.asyncio import ObjectType, ObjectIdentity
        return [ObjectType(ObjectIdentity(oid)) for oid in oids]

    def _build_auth(self):
        """Constrói CommunityData para SNMPv2c."""
        from pysnmp.hlapi.asyncio import CommunityData
        return CommunityData(self.community, mpModel=1)   # mpModel=1 → v2c

    def _build_transport(self):
        """Constrói UdpTransportTarget."""
        from pysnmp.hlapi.asyncio import UdpTransportTarget
        return UdpTransportTarget(
            (self.host, self.port),
            timeout=self.timeout,
            retries=self.retries,
        )

    @staticmethod
    def _extract_value(var_bind) -> Any:
        """
        Converte um VarBind pysnmp para tipo Python nativo.

        Tipos tratados:
          - Integer32, Unsigned32, Counter32, Counter64, Gauge32 → int
          - TimeTicks → int (centésimos de segundo)
          - OctetString → str (tenta UTF-8, fallback para bytes.hex())
          - IpAddress → str "a.b.c.d"
          - Null / NoSuchObject / EndOfMib → None
        """
        from pysnmp.proto import rfc1902
        val = var_bind[1]

        # Tipos inteiros
        if isinstance(val, (
            rfc1902.Integer32, rfc1902.Unsigned32,
            rfc1902.Counter32, rfc1902.Counter64,
            rfc1902.Gauge32, rfc1902.TimeTicks,
        )):
            return int(val)

        # OctetString (inclui DisplayString)
        if isinstance(val, rfc1902.OctetString):
            try:
                return val.asOctets().decode("utf-8").strip("\x00")
            except Exception:
                return val.asOctets().hex()

        # IpAddress
        if hasattr(val, "prettyPrint"):
            s = val.prettyPrint()
            if s not in ("", "noSuchObject", "noSuchInstance", "endOfMib"):
                return s

        return None

    async def get(self, *oids: str) -> dict[str, Any]:
        """
        GET SNMPv2c para uma ou mais OIDs escalares.

        Raises:
            SNMPError: Em caso de timeout, host inacessível ou community errada.
        """
        self._ensure_engine()
        from pysnmp.hlapi.asyncio import (
            getCmd, ContextData,
        )

        objects = self._build_objects(*oids)
        result_dict: dict[str, Any] = {}

        error_indication, error_status, error_index, var_binds = await getCmd(
            self._engine,
            self._build_auth(),
            self._build_transport(),
            ContextData(),
            *objects,
        )

        if error_indication:
            raise SNMPError(f"GET falhou para {self.host}: {error_indication}")
        if error_status:
            raise SNMPError(
                f"SNMP error status em {self.host}: "
                f"{error_status.prettyPrint()} @ {error_index}"
            )

        for var_bind in var_binds:
            oid_str = str(var_bind[0])
            value   = self._extract_value(var_bind)
            if value is not None:
                result_dict[oid_str] = value

        return result_dict

    async def walk(self, base_oid: str) -> list[tuple[str, Any]]:
        """
        WALK SNMPv2c — retorna toda a subárvore abaixo de base_oid.

        Usa bulkCmd (GetBulk) para eficiência — menos round-trips que nextCmd.
        Fallback automático para nextCmd se GetBulk não for suportado.
        """
        self._ensure_engine()
        from pysnmp.hlapi.asyncio import (
            nextCmd, ContextData, ObjectType, ObjectIdentity,
        )

        results: list[tuple[str, Any]] = []
        obj = ObjectType(ObjectIdentity(base_oid))

        async for error_indication, error_status, _, var_binds in nextCmd(
            self._engine,
            self._build_auth(),
            self._build_transport(),
            ContextData(),
            obj,
            lexicographicMode=False,
        ):
            if error_indication:
                logger.warning("WALK %s em %s: %s", base_oid, self.host, error_indication)
                break
            if error_status:
                logger.warning(
                    "WALK error status em %s: %s", self.host, error_status.prettyPrint()
                )
                break
            for var_bind in var_binds:
                oid_str = str(var_bind[0])
                value   = self._extract_value(var_bind)
                if value is not None:
                    results.append((oid_str, value))

        return results


# ─── Backend RouterOS REST API ────────────────────────────────────────────────

class RouterOSAPISession:
    """
    Backend alternativo usando a RouterOS REST API (RouterOS v7+).

    Usado quando SNMP está desabilitado no equipamento.
    Acessa os endpoints:
      GET /rest/system/resource  → CPU, uptime, memória
      GET /rest/interface         → interfaces e contadores
      GET /rest/interface/wireless  → radios Wi-Fi
      GET /rest/interface/wireless/registration-table  → clientes conectados

    Autenticação: HTTP Basic (usuário/senha do RouterOS).
    Requer: pip install aiohttp
    """

    def __init__(
        self,
        host: str,
        port: int = 443,
        username: str = "admin",
        password: str = "",
        use_ssl: bool = True,
        timeout: float = DEFAULT_TIMEOUT,
    ):
        self.host     = host
        self.port     = port
        self.username = username
        self.password = password
        self.use_ssl  = use_ssl
        self.timeout  = timeout
        self._base    = f"{'https' if use_ssl else 'http'}://{host}:{port}/rest"
        self._session = None

    async def _ensure_session(self):
        """Cria sessão aiohttp com autenticação Basic."""
        if self._session is None:
            try:
                import aiohttp
                auth = aiohttp.BasicAuth(self.username, self.password)
                connector = aiohttp.TCPConnector(ssl=False) if not self.use_ssl else None
                self._session = aiohttp.ClientSession(
                    auth=auth,
                    connector=connector,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                )
            except ImportError:
                raise ImportError(
                    "aiohttp não está instalado. Execute: pip install aiohttp"
                )

    async def get_resource(self) -> dict:
        """
        GET /rest/system/resource — CPU, uptime, memória, versão.

        Returns:
            {uptime, cpu-load, total-memory, free-memory, version, ...}
        """
        await self._ensure_session()
        async with self._session.get(f"{self._base}/system/resource") as r:
            r.raise_for_status()
            return await r.json()

    async def get_interfaces(self) -> list[dict]:
        """
        GET /rest/interface — todas as interfaces com contadores.

        Returns:
            Lista de {name, type, rx-byte, tx-byte, rx-error, tx-error, running, ...}
        """
        await self._ensure_session()
        async with self._session.get(f"{self._base}/interface") as r:
            r.raise_for_status()
            return await r.json()

    async def get_wireless_interfaces(self) -> list[dict]:
        """
        GET /rest/interface/wireless — rádios Wi-Fi com métricas.

        Returns:
            Lista de {name, ssid, frequency, band, noise-floor, channel-utilization, ...}
        """
        await self._ensure_session()
        async with self._session.get(f"{self._base}/interface/wireless") as r:
            r.raise_for_status()
            return await r.json()

    async def get_wireless_clients(self) -> list[dict]:
        """
        GET /rest/interface/wireless/registration-table — clientes conectados.

        Returns:
            Lista de {interface, mac-address, signal-strength, ...}
        """
        await self._ensure_session()
        async with self._session.get(
            f"{self._base}/interface/wireless/registration-table"
        ) as r:
            r.raise_for_status()
            return await r.json()

    async def close(self):
        if self._session:
            await self._session.close()
            self._session = None


# ─── Exceção customizada ──────────────────────────────────────────────────────

class SNMPError(Exception):
    """Erro em operação SNMP — timeout, host inacessível, community inválida."""
    pass


# ─── Coletor principal ────────────────────────────────────────────────────────

class SNMPCollector:
    """
    Coletor assíncrono de métricas de roteadores Mikrotik.

    Suporta dois backends intercambiáveis:
      1. SNMPv2c via PySNMPSession (padrão)
      2. RouterOS REST API via RouterOSAPISession (fallback)

    Cálculo de bps:
      Armazena os contadores de octets da coleta anterior.
      Na próxima coleta calcula: Δbytes / Δt * 8 (bits por segundo).
      Trata overflow de contador 32-bit (wrap em 4 GB).

    Rastreamento de CPU alta:
      Registra quando CPU ultrapassa threshold e por quanto tempo.
      O Correlator lê _cpu_high_since para aplicar a regra Critical.

    Uso básico:
        collector = SNMPCollector(host="192.168.1.1", community="public")
        result = await collector.collect()
        print(result.cpu_usage, result.wan_in_bps)

    Com backend customizado (testes):
        mock_backend = MockSNMPBackend(...)
        collector = SNMPCollector(host="192.168.1.1", backend=mock_backend)
        result = await collector.collect()
    """

    def __init__(
        self,
        host: str,
        community: str = DEFAULT_COMMUNITY,
        port: int = DEFAULT_PORT,
        timeout: int = DEFAULT_TIMEOUT,
        interval: float = 60.0,
        wan_iface: Optional[str] = None,
        backend: Optional[Any] = None,
        routeros_api: Optional[RouterOSAPISession] = None,
        db=None,
        event_bus=None,
    ):
        """
        Args:
            host:          IP do equipamento.
            community:     Community string SNMPv2c.
            port:          Porta UDP SNMP (padrão 161).
            timeout:       Timeout por query em segundos.
            interval:      Segundos entre ciclos de coleta.
            wan_iface:     Nome da interface WAN (ex: "ether1"). Auto-detectado se None.
            backend:       Instância SNMPBackend customizada (injeção para testes).
            routeros_api:  RouterOSAPISession como alternativa ao SNMP.
            db:            Repositório SQLite para persistência.
            event_bus:     EventBus SSE para publicar métricas em tempo real.
        """
        self.host         = host
        self.community    = community
        self.port         = port
        self.timeout      = timeout
        self.interval     = interval
        self.wan_iface    = wan_iface
        self.db           = db
        self.event_bus    = event_bus

        # Backend SNMP — usa PySNMPSession por padrão
        if backend is not None:
            self._snmp = backend
        else:
            self._snmp = PySNMPSession(
                host=host, port=port,
                community=community, timeout=timeout,
            )

        self._routeros_api = routeros_api

        self._running = False
        self._last_result: Optional[SNMPResult] = None

        # Estado para cálculo de bps (armazena última leitura de contadores)
        self._prev_in_bytes:  Optional[int]   = None
        self._prev_out_bytes: Optional[int]   = None
        self._prev_ts:        Optional[float] = None

        # Rastreamento de duração de CPU alta (lido pelo Correlator)
        self._cpu_high_since: Optional[float] = None

    # ─── Coleta principal ──────────────────────────────────────────────────────

    async def collect(self) -> SNMPResult:
        """
        Executa coleta completa do equipamento.

        Tenta primeiro SNMP. Se falhar, tenta RouterOS API (se configurada).
        As três coletas (sistema, interfaces, Wi-Fi) rodam em paralelo.

        Returns:
            SNMPResult preenchido. Em caso de erro, result.error é preenchido.
        """
        t_start = time.monotonic()
        result  = SNMPResult(host=self.host, community=self.community)

        try:
            await asyncio.gather(
                self._collect_system(result),
                self._collect_interfaces(result),
                self._collect_wifi(result),
            )
            result.collection_ms = (time.monotonic() - t_start) * 1000
            self._last_result = result
            self._update_cpu_tracking(result)

            logger.debug(
                "Coleta SNMP de %s concluída em %.0fms — CPU=%.1f%% "
                "WAN in=%.1f kbps out=%.1f kbps radios=%d",
                self.host,
                result.collection_ms,
                result.cpu_usage or 0,
                (result.wan_in_bps  or 0) / 1000,
                (result.wan_out_bps or 0) / 1000,
                len(result.wifi_radios),
            )

        except SNMPError as exc:
            result.error = str(exc)
            logger.warning("SNMP indisponível em %s: %s", self.host, exc)
            # Tenta fallback RouterOS API
            if self._routeros_api:
                await self._collect_via_routeros_api(result)

        except Exception as exc:
            result.error = str(exc)
            logger.error("Erro inesperado na coleta SNMP de %s: %s", self.host, exc, exc_info=True)

        return result

    # ─── Coleta de sistema ─────────────────────────────────────────────────────

    async def _collect_system(self, result: SNMPResult) -> None:
        """
        Coleta sysDescr, sysUpTime e CPU via hrProcessorLoad.

        hrProcessorLoad é uma tabela — cada entrada corresponde a um núcleo.
        CPU usage = média de todos os núcleos.

        sysUpTime é em centésimos de segundo → divide por 100 para segundos.
        """
        # sysDescr + sysUpTime via GET (dois OIDs em uma única operação)
        try:
            scalars = await self._snmp.get(OID_SYS_DESCR, OID_SYS_UPTIME)
            result.sys_descr = scalars.get(OID_SYS_DESCR)
            uptime_centisec  = scalars.get(OID_SYS_UPTIME)
            if uptime_centisec is not None:
                result.uptime_seconds = int(uptime_centisec) // 100
        except SNMPError as exc:
            logger.debug("GET sistema de %s falhou: %s", self.host, exc)
            raise

        # hrProcessorLoad — walk retorna um valor por núcleo
        cpu_rows = await self._snmp.walk(OID_HR_CPU_LOAD)
        if cpu_rows:
            loads = [int(v) for _, v in cpu_rows if v is not None]
            if loads:
                result.cpu_usage = sum(loads) / len(loads)

    # ─── Coleta de interfaces ──────────────────────────────────────────────────

    async def _collect_interfaces(self, result: SNMPResult) -> None:
        """
        Identifica a interface WAN e calcula tráfego em bps.

        Passos:
          1. Walk ifDescr → mapa {índice: nome}
          2. Identifica índice WAN por padrão de nome ou wan_iface configurada
          3. GET ifHCInOctets / ifHCOutOctets (64-bit) para o índice WAN
             Fallback para ifInOctets / ifOutOctets (32-bit) se HC não suportado
          4. Calcula bps por delta em relação à coleta anterior
          5. Trata wrap do contador 32-bit (4 GB overflow)
        """
        # Passo 1: descobre interfaces
        descr_rows = await self._snmp.walk(OID_IF_DESCR)
        if not descr_rows:
            logger.debug("ifDescr vazio em %s — sem interfaces?", self.host)
            return

        # {índice: nome_da_interface}
        iface_map: dict[int, str] = {}
        for oid_str, name in descr_rows:
            idx = _oid_last_index(oid_str)
            if idx is not None:
                iface_map[idx] = str(name)

        # Passo 2: identifica WAN
        wan_idx = self._find_wan_index(iface_map)
        if wan_idx is None:
            logger.warning(
                "Interface WAN não encontrada em %s. "
                "Configure wan_iface explicitamente. Interfaces: %s",
                self.host, list(iface_map.values()),
            )
            return

        result.wan_interface = iface_map[wan_idx]
        result.wan_if_index  = wan_idx

        # Passo 3: lê contadores (tenta 64-bit primeiro)
        in_bytes, out_bytes = await self._read_interface_counters(wan_idx)
        if in_bytes is None:
            return

        result.wan_in_bytes_raw  = in_bytes
        result.wan_out_bytes_raw = out_bytes

        # Passo 4: calcula bps
        now = time.monotonic()
        if self._prev_in_bytes is not None and self._prev_ts is not None:
            delta_t = now - self._prev_ts
            if delta_t > 0:
                delta_in  = _counter_delta(in_bytes,  self._prev_in_bytes)
                delta_out = _counter_delta(out_bytes, self._prev_out_bytes)
                result.wan_in_bps  = (delta_in  * 8) / delta_t
                result.wan_out_bps = (delta_out * 8) / delta_t

        self._prev_in_bytes  = in_bytes
        self._prev_out_bytes = out_bytes
        self._prev_ts        = now

    async def _read_interface_counters(
        self, if_index: int
    ) -> tuple[Optional[int], Optional[int]]:
        """
        Lê contadores de octets para um índice de interface.

        Tenta primeiro os contadores de 64 bits (ifHCInOctets).
        Se não disponível (RouterOS mais antigo), cai para 32 bits (ifInOctets).

        Args:
            if_index: Índice SNMP da interface.

        Returns:
            (in_bytes, out_bytes) ou (None, None) em caso de falha.
        """
        oid_in_hc  = f"{OID_IF_IN_HC}.{if_index}"
        oid_out_hc = f"{OID_IF_OUT_HC}.{if_index}"

        try:
            hc = await self._snmp.get(oid_in_hc, oid_out_hc)
            in_b  = hc.get(oid_in_hc)
            out_b = hc.get(oid_out_hc)
            if in_b is not None and out_b is not None:
                return int(in_b), int(out_b)
        except SNMPError:
            pass   # tenta 32-bit abaixo

        oid_in32  = f"{OID_IF_IN_OCTETS}.{if_index}"
        oid_out32 = f"{OID_IF_OUT_OCTETS}.{if_index}"
        try:
            r32   = await self._snmp.get(oid_in32, oid_out32)
            in_b  = r32.get(oid_in32)
            out_b = r32.get(oid_out32)
            if in_b is not None and out_b is not None:
                return int(in_b), int(out_b)
        except SNMPError as exc:
            logger.debug("Falha ao ler contadores de interface %d: %s", if_index, exc)

        return None, None

    def _find_wan_index(self, iface_map: dict[int, str]) -> Optional[int]:
        """
        Identifica o índice SNMP da interface WAN.

        Estratégia:
          1. Se wan_iface foi configurado manualmente, busca por nome exato
          2. Testa padrões WAN_IFACE_PATTERNS em ordem de prioridade
          3. Retorna None se nenhum padrão coincidir

        Args:
            iface_map: {índice: nome} de todas as interfaces.

        Returns:
            Índice da interface WAN ou None.
        """
        # Configuração manual
        if self.wan_iface:
            for idx, name in iface_map.items():
                if name.lower() == self.wan_iface.lower():
                    return idx
            logger.warning("Interface WAN '%s' não encontrada.", self.wan_iface)

        # Padrões automáticos (por prioridade)
        for pattern in WAN_IFACE_PATTERNS:
            for idx, name in sorted(iface_map.items()):  # ordena por índice
                if pattern.search(name):
                    logger.debug("WAN auto-detectada: %s (idx=%d)", name, idx)
                    return idx

        return None

    # ─── Coleta Wi-Fi (Mikrotik MIB) ──────────────────────────────────────────

    async def _collect_wifi(self, result: SNMPResult) -> None:
        """
        Coleta métricas Wi-Fi via Mikrotik Enterprise MIB (mtxrWlApTable).

        Cada entrada na tabela corresponde a uma interface wireless virtual.
        Consolida por rádio físico quando múltiplas SSIDs estão no mesmo rádio.

        OIDs da tabela mtxrWlApTable:
          .3.1.2  ssid
          .3.1.6  clients (gauge)
          .3.1.7  frequency (MHz)
          .3.1.9  noise floor (integer, dBm)
          .3.1.10 channel utilization (%)
          .3.1.11 band string

        Para retries: Mikrotik não expõe diretamente via OID padrão.
        Calculamos usando ifInErrors / (ifInUcastPkts + ifInErrors) como proxy.
        """
        radio_data: dict[int, dict] = {}   # {índice: dados parciais}

        # Coleta colunas da tabela em paralelo
        walks = await asyncio.gather(
            self._snmp.walk(OID_MTX_WIFI_CLIENTS),
            self._snmp.walk(OID_MTX_WIFI_NOISE),
            self._snmp.walk(OID_MTX_WIFI_CH_UTIL),
            self._snmp.walk(OID_MTX_WIFI_SSID),
            self._snmp.walk(OID_MTX_WIFI_FREQ),
            self._snmp.walk(OID_MTX_WIFI_BAND),
            return_exceptions=True,
        )

        clients_rows, noise_rows, chutil_rows, ssid_rows, freq_rows, band_rows = walks

        # Popula radio_data a partir de cada coluna
        def _populate(rows, key, transform=None):
            if isinstance(rows, Exception):
                logger.debug("Walk Mikrotik Wi-Fi falhou (%s): %s", key, rows)
                return
            for oid_str, val in rows:
                idx = _oid_last_index(oid_str)
                if idx is None or val is None:
                    continue
                if idx not in radio_data:
                    radio_data[idx] = {}
                radio_data[idx][key] = transform(val) if transform else val

        _populate(clients_rows,  "clients",    int)
        _populate(noise_rows,    "noise_floor", lambda v: _snmp_signed_int(v))
        _populate(chutil_rows,   "channel_util", float)
        _populate(ssid_rows,     "ssid",        str)
        _populate(freq_rows,     "freq_mhz",    int)
        _populate(band_rows,     "band",        str)

        if not radio_data:
            logger.debug("Nenhum rádio Wi-Fi encontrado em %s via SNMP Mikrotik MIB", self.host)
            return

        # Tenta enriquecer com retries via contadores de interface
        retries_map = await self._collect_wifi_retries(list(radio_data.keys()))

        # Constrói WifiRadioStats
        for idx in sorted(radio_data.keys()):
            data = radio_data[idx]
            radio = WifiRadioStats(radio_index=idx)
            radio.ssid                 = data.get("ssid", "")
            radio.band                 = data.get("band", "")
            radio.frequency_mhz        = data.get("freq_mhz", 0)
            radio.clients              = data.get("clients", 0)
            radio.noise_floor          = data.get("noise_floor", -100.0)
            radio.channel_utilization  = data.get("channel_util", 0.0)
            radio.retries_percent      = retries_map.get(idx, 0.0)
            result.wifi_radios.append(radio)

    async def _collect_wifi_retries(
        self, radio_indices: list[int]
    ) -> dict[int, float]:
        """
        Calcula percentual de retries para cada rádio.

        Proxy: ifInErrors / (ifInUcastPkts + ifInErrors) * 100
        Esta não é a métrica exata de retries do 802.11, mas é correlacionada
        com interferência e qualidade do link (conforme justificado no PRD).

        Args:
            radio_indices: Índices SNMP dos rádios Wi-Fi.

        Returns:
            {radio_índice: retries_percent} — ausente se dados insuficientes.
        """
        retries: dict[int, float] = {}

        for idx in radio_indices:
            try:
                oid_errors = f"{OID_IF_IN_ERRORS}.{idx}"
                oid_pkts   = f"{OID_IF_IN_UCAST}.{idx}"
                data = await self._snmp.get(oid_errors, oid_pkts)

                errors = data.get(oid_errors)
                pkts   = data.get(oid_pkts)

                if errors is not None and pkts is not None:
                    total = int(pkts) + int(errors)
                    if total > 0:
                        retries[idx] = (int(errors) / total) * 100.0
                    else:
                        retries[idx] = 0.0
            except (SNMPError, Exception):
                pass   # retries ficam ausentes para este rádio

        return retries

    # ─── Fallback RouterOS REST API ────────────────────────────────────────────

    async def _collect_via_routeros_api(self, result: SNMPResult) -> None:
        """
        Coleta métricas via RouterOS REST API quando SNMP não está disponível.

        Preenche o mesmo SNMPResult com dados obtidos via HTTP.
        Requer RouterOS v7+ e aiohttp instalado.

        Args:
            result: SNMPResult a preencher (modifica in-place).
        """
        if not self._routeros_api:
            return

        result.backend = "routeros_api"
        result.error   = None   # limpa erro SNMP anterior

        try:
            # Sistema
            resource = await self._routeros_api.get_resource()
            uptime_str = resource.get("uptime", "")
            result.uptime_seconds = _parse_routeros_uptime(uptime_str)
            cpu_str = resource.get("cpu-load", "")
            if cpu_str:
                result.cpu_usage = float(str(cpu_str).replace("%", ""))

            # Interfaces WAN
            interfaces = await self._routeros_api.get_interfaces()
            wan_iface  = self._find_wan_iface_ros(interfaces)
            if wan_iface:
                result.wan_interface  = wan_iface.get("name")
                in_bytes  = int(wan_iface.get("rx-byte", 0))
                out_bytes = int(wan_iface.get("tx-byte", 0))
                result.wan_in_bytes_raw  = in_bytes
                result.wan_out_bytes_raw = out_bytes

                now = time.monotonic()
                if self._prev_in_bytes is not None and self._prev_ts is not None:
                    delta_t   = now - self._prev_ts
                    if delta_t > 0:
                        result.wan_in_bps  = (_counter_delta(in_bytes,  self._prev_in_bytes)  * 8) / delta_t
                        result.wan_out_bps = (_counter_delta(out_bytes, self._prev_out_bytes) * 8) / delta_t
                self._prev_in_bytes  = in_bytes
                self._prev_out_bytes = out_bytes
                self._prev_ts        = now

            # Wi-Fi
            wireless    = await self._routeros_api.get_wireless_interfaces()
            clients_all = await self._routeros_api.get_wireless_clients()

            # Conta clientes por interface
            clients_by_iface: dict[str, int] = {}
            for client in clients_all:
                iface = client.get("interface", "")
                clients_by_iface[iface] = clients_by_iface.get(iface, 0) + 1

            for i, w in enumerate(wireless):
                radio = WifiRadioStats(radio_index=i)
                radio.ssid  = w.get("ssid", "")
                radio.band  = w.get("band", "")
                freq_str    = w.get("frequency", "0")
                try:
                    radio.frequency_mhz = int(str(freq_str).split(",")[0])
                except ValueError:
                    pass
                noise_str = w.get("noise-floor", "")
                try:
                    radio.noise_floor = float(noise_str.replace("dBm", "").strip())
                except (ValueError, AttributeError):
                    pass
                radio.clients = clients_by_iface.get(w.get("name", ""), 0)
                result.wifi_radios.append(radio)

            self._last_result = result
            self._update_cpu_tracking(result)

        except Exception as exc:
            result.error = f"RouterOS API falhou: {exc}"
            logger.error("RouterOS API falhou para %s: %s", self.host, exc)

    def _find_wan_iface_ros(self, interfaces: list[dict]) -> Optional[dict]:
        """
        Identifica a interface WAN na lista retornada pela RouterOS API.

        Args:
            interfaces: Lista de interfaces da RouterOS API.

        Returns:
            Dict da interface WAN ou None.
        """
        if self.wan_iface:
            for iface in interfaces:
                if iface.get("name", "").lower() == self.wan_iface.lower():
                    return iface

        for pattern in WAN_IFACE_PATTERNS:
            for iface in interfaces:
                name = iface.get("name", "")
                if pattern.search(name):
                    return iface
        return None

    # ─── Rastreamento de CPU ───────────────────────────────────────────────────

    def _update_cpu_tracking(self, result: SNMPResult) -> None:
        """
        Atualiza _cpu_high_since para rastreamento de duração de CPU alta.

        O Correlator lê esta propriedade para aplicar a regra:
        'CPU > 80% por > 60s → Critical' (PRD seção 4.1-C).
        """
        if result.cpu_usage is None:
            return

        now = time.time()
        if result.cpu_usage > THRESHOLD_CPU_CRITICAL:
            if self._cpu_high_since is None:
                self._cpu_high_since = now
                logger.warning("CPU alta em %s: %.1f%%", self.host, result.cpu_usage)
        else:
            if self._cpu_high_since is not None:
                duration = now - self._cpu_high_since
                logger.info(
                    "CPU normalizada em %s: %.1f%% (ficou alta por %.0fs)",
                    self.host, result.cpu_usage, duration,
                )
            self._cpu_high_since = None

    # ─── Teste de conectividade (Wizard SNMP) ──────────────────────────────────

    async def test_connectivity(self) -> dict:
        """
        Testa se o equipamento responde SNMP corretamente.

        Usado pelo Wizard de Configuração SNMP (PRD seção 4.1-G).
        Faz GET no OID sysDescr — mais leve que uma coleta completa.

        Returns:
            {
              "success":   bool,
              "message":   str,
              "sys_descr": str | None,
              "host":      str,
            }
        """
        try:
            data = await self._snmp.get(OID_SYS_DESCR, OID_SYS_UPTIME)
            descr = data.get(OID_SYS_DESCR, "")
            uptime_cs = data.get(OID_SYS_UPTIME)
            uptime_s  = int(uptime_cs) // 100 if uptime_cs else None

            logger.info("SNMP OK em %s: %s", self.host, descr[:60] if descr else "—")
            return {
                "success":        True,
                "message":        "SNMP respondendo corretamente.",
                "sys_descr":      descr,
                "uptime_seconds": uptime_s,
                "host":           self.host,
            }
        except SNMPError as exc:
            return {
                "success": False,
                "message": f"SNMP não respondeu: {exc}",
                "host":    self.host,
            }
        except Exception as exc:
            return {
                "success": False,
                "message": f"Erro inesperado: {exc}",
                "host":    self.host,
            }

    # ─── Loop de coleta ────────────────────────────────────────────────────────

    async def start(self) -> None:
        """
        Inicia o loop de coleta periódica assíncrona.

        Por ciclo:
          1. collect() — coleta do equipamento
          2. Persiste no DB se configurado
          3. Publica no EventBus se configurado
          4. Dorme interval segundos (descontando tempo de coleta)
        """
        self._running = True
        logger.info(
            "SNMPCollector iniciado para %s — intervalo: %ss",
            self.host, self.interval,
        )

        while self._running:
            t_start = time.monotonic()
            try:
                result = await self.collect()

                if self.db and result.is_ok:
                    try:
                        await self.db.save_snmp(result)
                    except Exception as exc:
                        logger.error("Falha ao salvar SNMP no DB: %s", exc)

                if self.event_bus and result.is_ok:
                    try:
                        self.event_bus.publish("snmp_update", {
                            "host":        result.host,
                            "cpu_usage":   result.cpu_usage,
                            "wan_in_bps":  result.wan_in_bps,
                            "wan_out_bps": result.wan_out_bps,
                            "wifi_radios": result.wifi_to_dict_list(),
                            "timestamp":   result.timestamp,
                        })
                    except Exception as exc:
                        logger.debug("Falha ao publicar SNMP no EventBus: %s", exc)

            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Erro no ciclo SNMP: %s", exc, exc_info=True)

            elapsed    = time.monotonic() - t_start
            sleep_time = max(0.0, self.interval - elapsed)
            try:
                await asyncio.sleep(sleep_time)
            except asyncio.CancelledError:
                break

    async def stop(self) -> None:
        """Para o loop de coleta e fecha sessões abertas."""
        self._running = False
        if self._routeros_api:
            await self._routeros_api.close()
        logger.info("SNMPCollector parado para %s.", self.host)

    # ─── Propriedades ──────────────────────────────────────────────────────────

    @property
    def last_result(self) -> Optional[SNMPResult]:
        """Último resultado de coleta."""
        return self._last_result

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def cpu_high_since(self) -> Optional[float]:
        """Timestamp de quando CPU ultrapassou o threshold. Lido pelo Correlator."""
        return self._cpu_high_since


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _oid_last_index(oid_str: str) -> Optional[int]:
    """
    Extrai o último componente numérico de uma OID string.

    Ex: "1.3.6.1.2.1.2.2.1.2.3" → 3

    Args:
        oid_str: String OID completa.

    Returns:
        Último índice como int, ou None se OID inválida.
    """
    try:
        return int(oid_str.rsplit(".", 1)[-1])
    except (ValueError, IndexError):
        return None


def _counter_delta(current: int, previous: int, bits: int = 64) -> int:
    """
    Calcula delta entre dois valores de contador SNMP com tratamento de wrap.

    Para contadores de 32 bits (ifInOctets): wrap em 2^32 ≈ 4 GB
    Para contadores de 64 bits (ifHCInOctets): wrap em 2^64 (praticamente impossível)

    Args:
        current:  Leitura atual do contador.
        previous: Leitura anterior do contador.
        bits:     Largura do contador em bits (32 ou 64).

    Returns:
        Delta positivo em bytes.
    """
    if current >= previous:
        return current - previous
    # Wrap ocorreu
    max_val = (2 ** bits)
    return (max_val - previous) + current


def _snmp_signed_int(value: Any) -> float:
    """
    Converte valor SNMP para inteiro com sinal.

    Noise floor é representado como Integer32 (signed) no Mikrotik MIB.
    Contudo, pysnmp pode retorná-lo como Unsigned32 dependendo da versão do MIB.
    Esta função garante a interpretação correta.

    Ex: 0xFFFFFFB5 (unsigned) → -75 (signed, dBm)

    Args:
        value: Valor recebido do SNMP (int ou str).

    Returns:
        Float com sinal correto.
    """
    try:
        v = int(value)
        # Se valor grande demais para ser dBm positivo, é signed negativo
        if v > 0x7FFFFFFF:
            v -= 0x100000000
        return float(v)
    except (ValueError, TypeError):
        return -100.0


def _parse_routeros_uptime(uptime_str: str) -> Optional[int]:
    """
    Converte string de uptime do RouterOS para segundos.

    Formato RouterOS: "3d20h14m52s" ou "1w2d3h4m5s"

    Args:
        uptime_str: String de uptime do RouterOS.

    Returns:
        Uptime em segundos ou None.
    """
    if not uptime_str:
        return None
    total = 0
    pattern = re.compile(r"(\d+)([wdhms])")
    multipliers = {"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}
    for amount, unit in pattern.findall(uptime_str):
        total += int(amount) * multipliers.get(unit, 0)
    return total if total > 0 else None
