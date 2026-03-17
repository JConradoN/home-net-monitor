"""
collectors/fingerprint.py — Descoberta e fingerprinting de dispositivos na rede.

Responsável por:
  - ARP scan para descobrir hosts ativos no range da rede
  - Resolução de hostname via mDNS (avahi-resolve-address) e DNS reverso
  - Identificação de fabricante por OUI (primeiros 3 bytes do MAC)
  - Classificação heurística de tipo de dispositivo: TV, celular, notebook, IoT, roteador

Estratégia de ARP scan (em ordem de preferência):
  1. arp-scan --localnet (requer root ou cap_net_raw)
  2. Scapy (importação lazy, requer root ou cap_net_raw)
  3. ip neigh show (cache ARP — sem scan ativo, mas sem privilégios)

Detecção de rede:
  - ip route get 8.8.8.8 → gateway + interface
  - ip addr show <iface>  → IP local + prefixo
"""

import asyncio
import ipaddress
import logging
import re
import socket
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------

DEVICE_TYPES: dict[str, str] = {
    "tv":      "TV / Smart TV",
    "phone":   "Smartphone / Tablet",
    "laptop":  "Notebook / Desktop",
    "iot":     "Dispositivo IoT",
    "router":  "Roteador / AP",
    "printer": "Impressora",
    "nas":     "NAS / Servidor",
    "unknown": "Desconhecido",
}

# Palavras-chave de fabricante (OUI) → tipo de dispositivo
OUI_DEVICE_HINTS: dict[str, str] = {
    "Apple":     "phone",
    "Samsung":   "phone",
    "Xiaomi":    "phone",
    "Motorola":  "phone",
    "Huawei":    "phone",
    "MikroTik":  "router",
    "TP-LINK":   "router",
    "Ubiquiti":  "router",
    "Netgear":   "router",
    "Cisco":     "router",
    "Google":    "iot",
    "Amazon":    "iot",
    "Raspberry": "iot",
    "Espressif": "iot",
    "Sony":      "tv",
    "LG":        "tv",
    "TCL":       "tv",
    "Hisense":   "tv",
    "Canon":     "printer",
    "Hewlett":   "printer",
    "Epson":     "printer",
    "Brother":   "printer",
    "Synology":  "nas",
    "QNAP":      "nas",
}

# Heurísticas de hostname (regex case-insensitive) → tipo
HOSTNAME_HINTS: dict[str, str] = {
    r"(iphone|ipad|android|samsung|xiaomi|motorola|redmi|pixel)": "phone",
    r"(macbook|laptop|notebook|desktop|pc\b|thinkpad|lenovo)":    "laptop",
    r"(smarttv|firetv|chromecast|appletv|roku|shield|bravia)":    "tv",
    r"(printer|epson|canon|hp-print|brother)":                    "printer",
    r"(router|gateway|mikrotik|tplink|deco|mesh|twibi|unifi)":    "router",
    r"(nas|synology|qnap|server\b|pi\b|raspberry)":               "nas",
    r"(alexa|echo\b|nest\b|ring\b|cam\b|camera|sensor|esp|ard)":  "iot",
}

# Timeout para operações de subprocess
_SUBPROCESS_TIMEOUT = 10.0
_HOSTNAME_TIMEOUT = 3.0


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class Device:
    """Representa um dispositivo descoberto na rede."""

    ip: str
    mac: str
    timestamp: float = field(default_factory=time.time)

    hostname: Optional[str] = None
    vendor: Optional[str] = None          # Fabricante via OUI
    device_type: str = "unknown"
    device_type_label: str = "Desconhecido"

    open_ports: list = field(default_factory=list)
    mdns_services: list = field(default_factory=list)
    last_seen: float = field(default_factory=time.time)
    first_seen: float = field(default_factory=time.time)

    @property
    def display_name(self) -> str:
        """Nome para exibição no dashboard."""
        return self.hostname or self.vendor or self.ip

    @property
    def mac_normalized(self) -> str:
        """MAC em formato XX:XX:XX:XX:XX:XX uppercase."""
        return self.mac.upper()

    @property
    def oui(self) -> str:
        """Primeiros 3 octetos do MAC (OUI)."""
        return self.mac_normalized[:8]

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "mac": self.mac_normalized,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "device_type": self.device_type,
            "device_type_label": self.device_type_label,
            "display_name": self.display_name,
            "last_seen": self.last_seen,
        }


@dataclass
class NetworkRange:
    """Informações sobre o range da rede local."""

    interface: str
    local_ip: str
    gateway_ip: str
    network: str       # ex: "192.168.1.0/24"
    prefix_len: int    # ex: 24


# ---------------------------------------------------------------------------
# OUI Database
# ---------------------------------------------------------------------------

class OUIDatabase:
    """
    Base de dados de fabricantes por OUI (IEEE).

    Carrega arquivo oui.txt no formato IEEE:
        00-50-56   (hex)   VMware, Inc.

    Em produção, baixar de https://standards-oui.ieee.org/oui/oui.txt
    e passar o caminho em oui_file. Sem arquivo, a base fica vazia
    (lookup retorna None).
    """

    def __init__(self, oui_file: Optional[str] = None):
        self._db: dict[str, str] = {}
        if oui_file:
            self._load_file(oui_file)

    def _load_file(self, path: str) -> None:
        """Carrega arquivo OUI no formato IEEE."""
        try:
            with open(path) as f:
                for line in f:
                    if "(hex)" in line:
                        parts = line.split("(hex)")
                        if len(parts) == 2:
                            oui = parts[0].strip().replace("-", ":").upper()
                            vendor = parts[1].strip()
                            self._db[oui] = vendor
            logger.info("OUI carregado: %d registros de %s", len(self._db), path)
        except Exception as exc:
            logger.warning("Falha ao carregar OUI de %s: %s", path, exc)

    def lookup(self, mac: str) -> Optional[str]:
        """
        Retorna o fabricante para um MAC address.

        Args:
            mac: Endereço MAC em qualquer formato (XX:XX:XX:XX:XX:XX,
                 XX-XX-XX-XX-XX-XX, XXXXXXXXXXXX).

        Returns:
            Nome do fabricante ou None se não encontrado.
        """
        normalized = mac.upper().replace("-", ":").replace(".", ":")
        # Adiciona separadores se formato compacto (AABBCCDDEEFF)
        if ":" not in normalized and len(normalized) == 12:
            normalized = ":".join(normalized[i:i+2] for i in range(0, 12, 2))
        parts = normalized.split(":")
        if len(parts) < 3:
            return None
        oui = ":".join(parts[:3])
        return self._db.get(oui)

    @property
    def size(self) -> int:
        return len(self._db)


# ---------------------------------------------------------------------------
# FingerprintCollector
# ---------------------------------------------------------------------------

class FingerprintCollector:
    """
    Coletor assíncrono de descoberta e fingerprinting de dispositivos.

    Executa ARP scan, resolve hostnames e classifica dispositivos por tipo.
    Mantém estado incremental — novos dispositivos são adicionados,
    dispositivos sem resposta por N ciclos são marcados com miss_count elevado.

    Uso:
        collector = FingerprintCollector()
        devices = await collector.scan()
    """

    def __init__(
        self,
        network: Optional[str] = None,
        oui_file: Optional[str] = None,
        interval: float = 300.0,
        offline_threshold: int = 3,
        db=None,
    ):
        """
        Args:
            network:           CIDR da rede (ex: '192.168.1.0/24').
                               Auto-detectado se None.
            oui_file:          Caminho para base OUI do IEEE.
            interval:          Intervalo entre scans em segundos.
            offline_threshold: Ciclos sem resposta para marcar como offline.
            db:                Repositório SQLite para persistência.
        """
        self.network = network
        self.oui_db = OUIDatabase(oui_file)
        self.interval = interval
        self.offline_threshold = offline_threshold
        self.db = db
        self._running = False
        self._devices: dict[str, Device] = {}     # {mac_lower: Device}
        self._miss_counts: dict[str, int] = {}    # {mac_lower: ciclos sem resposta}

    # ------------------------------------------------------------------
    # Detecção de rede
    # ------------------------------------------------------------------

    async def detect_network(self) -> Optional[NetworkRange]:
        """
        Detecta automaticamente o range da rede local.

        Estratégia:
          1. ip route get 8.8.8.8 → gateway IP e interface
          2. ip addr show <iface>  → IP local e prefixo

        Returns:
            NetworkRange com dados da rede, ou None se não detectado.
        """
        try:
            proc = await asyncio.create_subprocess_exec(
                "ip", "route", "get", "8.8.8.8",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=_SUBPROCESS_TIMEOUT
            )
            output = stdout.decode()

            via_match = re.search(r"via\s+(\d+\.\d+\.\d+\.\d+)", output)
            dev_match = re.search(r"dev\s+(\S+)", output)
            src_match = re.search(r"src\s+(\d+\.\d+\.\d+\.\d+)", output)

            if not (via_match and dev_match and src_match):
                logger.warning("ip route get: saída inesperada: %r", output)
                return None

            gateway_ip = via_match.group(1)
            iface = dev_match.group(1)
            local_ip = src_match.group(1)

            # Obtém prefixo via ip addr show
            proc2 = await asyncio.create_subprocess_exec(
                "ip", "addr", "show", iface,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout2, _ = await asyncio.wait_for(
                proc2.communicate(), timeout=_SUBPROCESS_TIMEOUT
            )
            inet_match = re.search(
                r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", stdout2.decode()
            )
            if not inet_match:
                return None

            prefix_len = int(inet_match.group(2))
            network = str(
                ipaddress.IPv4Network(f"{local_ip}/{prefix_len}", strict=False)
            )
            logger.info("Rede detectada: %s via %s (gw %s)", network, iface, gateway_ip)
            return NetworkRange(
                interface=iface,
                local_ip=local_ip,
                gateway_ip=gateway_ip,
                network=network,
                prefix_len=prefix_len,
            )

        except Exception as exc:
            logger.error("Falha ao detectar rede: %s", exc)
            return None

    # ------------------------------------------------------------------
    # ARP scan
    # ------------------------------------------------------------------

    async def arp_scan(self, network: str) -> list[tuple[str, str]]:
        """
        Executa ARP scan no range especificado.

        Tenta em ordem:
          1. arp-scan --localnet (mais completo, requer root)
          2. Scapy  (importação lazy, requer root)
          3. ip neigh show (cache ARP — sem scan ativo, sem root)

        Args:
            network: CIDR da rede (ex: '192.168.1.0/24').

        Returns:
            Lista de tuplas (ip, mac) dos hosts ativos/conhecidos.
        """
        hosts = await self._arp_scan_arpscan(network)
        if hosts:
            logger.info("arp-scan: %d hosts em %s", len(hosts), network)
            return hosts

        hosts = await self._arp_scan_scapy(network)
        if hosts:
            logger.info("scapy: %d hosts em %s", len(hosts), network)
            return hosts

        hosts = await self._arp_from_neigh()
        logger.info("ip neigh: %d hosts na cache ARP", len(hosts))
        return hosts

    async def _arp_scan_arpscan(self, network: str) -> list[tuple[str, str]]:
        """arp-scan --localnet — detecta todos os hosts na rede local."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "arp-scan", "--localnet", "--quiet",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=_SUBPROCESS_TIMEOUT * 3
            )
            hosts = []
            for line in stdout.decode().splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        ipaddress.ip_address(parts[0])
                        mac = parts[1].lower()
                        if re.match(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", mac):
                            hosts.append((parts[0], mac))
                    except ValueError:
                        continue
            return hosts
        except (FileNotFoundError, asyncio.TimeoutError, PermissionError, OSError):
            return []
        except Exception as exc:
            logger.debug("arp-scan falhou: %s", exc)
            return []

    async def _arp_scan_scapy(self, network: str) -> list[tuple[str, str]]:
        """Scapy ARP scan — importação lazy."""
        try:
            loop = asyncio.get_running_loop()
            return await asyncio.wait_for(
                loop.run_in_executor(None, self._scapy_scan_sync, network),
                timeout=_SUBPROCESS_TIMEOUT * 3,
            )
        except Exception as exc:
            logger.debug("scapy falhou: %s", exc)
            return []

    @staticmethod
    def _scapy_scan_sync(network: str) -> list[tuple[str, str]]:
        from scapy.all import ARP, Ether, srp  # noqa: PLC0415 — lazy import

        arp = ARP(pdst=network)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        result = srp(ether / arp, timeout=3, verbose=False)[0]
        return [(recv.psrc, recv.hwsrc) for _, recv in result]

    async def _arp_from_neigh(self) -> list[tuple[str, str]]:
        """Parse ip neigh show — devolve entradas REACHABLE/STALE da cache ARP."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "ip", "neigh", "show",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=_SUBPROCESS_TIMEOUT
            )
            hosts = []
            for line in stdout.decode().splitlines():
                # Formato: "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
                if "lladdr" not in line:
                    continue
                parts = line.split()
                state = parts[-1] if parts else ""
                if state not in ("REACHABLE", "STALE", "DELAY", "PROBE"):
                    continue
                try:
                    ipaddress.ip_address(parts[0])
                    idx = parts.index("lladdr")
                    mac = parts[idx + 1].lower()
                    hosts.append((parts[0], mac))
                except (ValueError, IndexError):
                    continue
            return hosts
        except Exception as exc:
            logger.debug("ip neigh show falhou: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Resolução de hostname
    # ------------------------------------------------------------------

    async def resolve_hostname_mdns(self, ip: str) -> Optional[str]:
        """
        Resolve hostname via mDNS e DNS reverso.

        Tenta em ordem:
          1. avahi-resolve-address (mDNS/Bonjour, domínio .local)
          2. socket.getfqdn() em executor (DNS reverso padrão)
          3. host <ip> via subprocess

        Args:
            ip: Endereço IP do dispositivo.

        Returns:
            Hostname resolvido ou None.
        """
        hostname = await self._avahi_resolve(ip)
        if hostname:
            return hostname

        hostname = await self._socket_reverse_lookup(ip)
        if hostname:
            return hostname

        return await self._host_cmd_lookup(ip)

    async def _avahi_resolve(self, ip: str) -> Optional[str]:
        """avahi-resolve-address — resolução mDNS (.local)."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "avahi-resolve-address", ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=_HOSTNAME_TIMEOUT
            )
            output = stdout.decode().strip()
            if output:
                parts = output.split()
                if len(parts) >= 2:
                    return parts[1].rstrip(".")
        except (FileNotFoundError, asyncio.TimeoutError):
            pass
        except Exception as exc:
            logger.debug("avahi-resolve-address %s: %s", ip, exc)
        return None

    async def _socket_reverse_lookup(self, ip: str) -> Optional[str]:
        """Resolução reversa via socket.getfqdn() em thread pool."""
        try:
            loop = asyncio.get_running_loop()
            result = await asyncio.wait_for(
                loop.run_in_executor(None, socket.getfqdn, ip),
                timeout=_HOSTNAME_TIMEOUT,
            )
            if result and result != ip:
                return result
        except Exception:
            pass
        return None

    async def _host_cmd_lookup(self, ip: str) -> Optional[str]:
        """Resolução reversa via comando `host`."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "host", ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=_HOSTNAME_TIMEOUT
            )
            output = stdout.decode()
            if "domain name pointer" in output:
                hostname = output.split("domain name pointer")[1].strip().rstrip(".")
                return hostname
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------
    # Classificação de dispositivo
    # ------------------------------------------------------------------

    def classify_device(self, device: Device) -> str:
        """
        Classifica o tipo de dispositivo por heurística multicamada:
          1. Vendor (OUI)     — ex: "MikroTik" → router
          2. Hostname         — ex: "iphone" → phone
          3. mDNS services    — ex: "_airplay" → tv, "_ipp" → printer

        Args:
            device: Dispositivo a classificar.

        Returns:
            Tipo do dispositivo (chave de DEVICE_TYPES).
        """
        # Camada 1: Vendor (OUI)
        if device.vendor:
            for keyword, dtype in OUI_DEVICE_HINTS.items():
                if keyword.lower() in device.vendor.lower():
                    return dtype

        # Camada 2: Hostname
        if device.hostname:
            hostname_lower = device.hostname.lower()
            for pattern, dtype in HOSTNAME_HINTS.items():
                if re.search(pattern, hostname_lower):
                    return dtype

        # Camada 3: mDNS services
        for svc in device.mdns_services:
            svc_lower = svc.lower()
            if "_airplay" in svc_lower or "_atv" in svc_lower:
                return "tv"
            if "_ipp" in svc_lower or "_pdl-datastream" in svc_lower:
                return "printer"
            if "_smb" in svc_lower or "_afpovertcp" in svc_lower:
                return "nas"
            if "_ssh" in svc_lower or "_http" in svc_lower:
                return "nas"

        return "unknown"

    # ------------------------------------------------------------------
    # Scan completo
    # ------------------------------------------------------------------

    async def scan(self) -> list[Device]:
        """
        Executa scan completo: ARP + resolução de hostname + fingerprint.

        Mantém estado incremental — dispositivos já conhecidos têm IP e
        last_seen atualizados. Novos dispositivos são adicionados.

        Returns:
            Lista de todos os dispositivos conhecidos.
        """
        if not self.network:
            net_range = await self.detect_network()
            if net_range:
                self.network = net_range.network

        if not self.network:
            logger.warning("Range de rede não disponível — scan abortado.")
            return list(self._devices.values())

        found_macs: set[str] = set()
        arp_results = await self.arp_scan(self.network)

        for ip, mac in arp_results:
            mac_lower = mac.lower()
            found_macs.add(mac_lower)
            now = time.time()

            if mac_lower not in self._devices:
                device = Device(ip=ip, mac=mac, first_seen=now, last_seen=now)
                device.vendor = self.oui_db.lookup(mac)
                self._devices[mac_lower] = device
                logger.info(
                    "Novo dispositivo: %s (%s) — %s",
                    ip, mac, device.vendor or "fabricante desconhecido",
                )
            else:
                device = self._devices[mac_lower]
                device.ip = ip
                device.last_seen = now

            # Resolve hostname se ainda não tiver
            if not device.hostname:
                device.hostname = await self.resolve_hostname_mdns(ip)

            # Classifica tipo
            device.device_type = self.classify_device(device)
            device.device_type_label = DEVICE_TYPES.get(device.device_type, "Desconhecido")

        # Atualiza contagem de ausências
        for mac in list(self._devices.keys()):
            if mac not in found_macs:
                self._miss_counts[mac] = self._miss_counts.get(mac, 0) + 1
            else:
                self._miss_counts[mac] = 0

        if self.db:
            try:
                await self.db.save_devices(list(self._devices.values()))
            except Exception as exc:
                logger.error("Erro ao salvar dispositivos: %s", exc)

        return list(self._devices.values())

    # ------------------------------------------------------------------
    # Loop de coleta
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Inicia o loop de scan periódico."""
        self._running = True
        logger.info("FingerprintCollector iniciado — intervalo: %ss", self.interval)
        while self._running:
            t_start = time.monotonic()
            try:
                devices = await self.scan()
                logger.debug("Scan concluído: %d dispositivos", len(devices))
            except Exception as exc:
                logger.error("Erro no scan de dispositivos: %s", exc)
            elapsed = time.monotonic() - t_start
            sleep_for = max(0.0, self.interval - elapsed)
            if sleep_for > 0:
                await asyncio.sleep(sleep_for)

    async def stop(self) -> None:
        """Para o loop de scan."""
        self._running = False
        logger.info("FingerprintCollector parado.")

    # ------------------------------------------------------------------
    # Propriedades
    # ------------------------------------------------------------------

    @property
    def devices(self) -> list[Device]:
        """Lista atual de todos os dispositivos conhecidos."""
        return list(self._devices.values())

    def get_device(self, mac: str) -> Optional[Device]:
        """Retorna dispositivo por MAC, ou None."""
        return self._devices.get(mac.lower())

    def miss_count(self, mac: str) -> int:
        """Retorna quantos ciclos consecutivos o dispositivo não respondeu."""
        return self._miss_counts.get(mac.lower(), 0)
