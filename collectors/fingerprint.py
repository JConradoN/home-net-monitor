"""
collectors/fingerprint.py — Descoberta e fingerprinting de dispositivos na rede.

Responsável por:
  - ARP scan para descobrir hosts ativos no range da rede
  - Resolução de hostname via mDNS / NetBIOS
  - Identificação de fabricante por OUI (primeiros 3 bytes do MAC)
  - Classificação heurística de tipo de dispositivo: TV, celular, notebook, IoT, roteador

Fluxo:
  1. Detecta o range da rede local (ex: 192.168.1.0/24)
  2. Executa ARP scan para listar MACs e IPs ativos
  3. Consulta base OUI para identificar fabricante
  4. Resolve hostname via mDNS (Avahi/Bonjour) e NetBIOS
  5. Classifica o dispositivo por heurística (vendor + hostname + porta)

Requer: pip install scapy netifaces zeroconf
"""

import asyncio
import ipaddress
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# Classificação de dispositivos
DEVICE_TYPES = {
    "tv": "TV / Smart TV",
    "phone": "Smartphone / Tablet",
    "laptop": "Notebook / Desktop",
    "iot": "Dispositivo IoT",
    "router": "Roteador / AP",
    "printer": "Impressora",
    "nas": "NAS / Servidor",
    "unknown": "Desconhecido",
}

# Mapeamento de OUI prefixes para tipo de dispositivo (amostra)
# Base completa carregada do arquivo oui.txt (IEEE)
OUI_DEVICE_HINTS: dict[str, str] = {
    # Apple — geralmente iPhone, iPad, MacBook
    "Apple": "phone",
    # Samsung — TV ou smartphone
    "Samsung": "phone",
    # Mikrotik — roteador
    "MikroTik": "router",
    # TP-Link — roteador / AP
    "TP-LINK": "router",
    # Google — Chromecast, Google Home
    "Google": "iot",
    # Amazon — Echo, Fire TV
    "Amazon": "iot",
    # Raspberry Pi Foundation
    "Raspberry": "iot",
    # Sony — TV ou console
    "Sony": "tv",
    # LG — TV
    "LG": "tv",
    # Canon, HP, Epson — impressoras
    "Canon": "printer",
    "Hewlett": "printer",
    "Epson": "printer",
}

# Heurísticas de hostname para classificação
HOSTNAME_HINTS: dict[str, str] = {
    r"(iphone|ipad|android|samsung|xiaomi|motorola|redmi)": "phone",
    r"(macbook|laptop|notebook|desktop|pc|thinkpad)": "laptop",
    r"(smarttv|firetv|chromecast|appletv|roku|shield)": "tv",
    r"(printer|epson|canon|hp-print)": "printer",
    r"(router|gateway|mikrotik|tplink|deco|mesh|twibi)": "router",
    r"(nas|synology|qnap|server|pi|raspberry)": "nas",
    r"(alexa|echo|home|nest|ring|camera|cam|sensor|esp|arduino)": "iot",
}


@dataclass
class Device:
    """Representa um dispositivo descoberto na rede."""

    ip: str
    mac: str
    timestamp: float = field(default_factory=time.time)

    hostname: Optional[str] = None
    vendor: Optional[str] = None          # Fabricante via OUI
    device_type: str = "unknown"          # Tipo classificado
    device_type_label: str = "Desconhecido"

    # Metadados adicionais
    open_ports: list[int] = field(default_factory=list)
    mdns_services: list[str] = field(default_factory=list)
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


@dataclass
class NetworkRange:
    """Informações sobre o range da rede local."""

    interface: str
    local_ip: str
    gateway_ip: str
    network: str           # ex: "192.168.1.0/24"
    prefix_len: int        # ex: 24


class OUIDatabase:
    """
    Base de dados de fabricantes por OUI (IEEE).

    Em produção, carrega o arquivo oui.txt do IEEE ou usa a biblioteca manuf.
    Versão offline integrada com fallback para lookup online desabilitado
    (privacidade — PRD seção 2.1).
    """

    def __init__(self, oui_file: Optional[str] = None):
        """
        Args:
            oui_file: Caminho para o arquivo oui.txt local.
                      Se None, usa base embutida mínima.
        """
        self._db: dict[str, str] = {}
        self._file = oui_file
        if oui_file:
            self._load_file(oui_file)

    def _load_file(self, path: str) -> None:
        """
        Carrega o arquivo OUI no formato IEEE:
          00-50-56   (hex)    VMware, Inc.
        """
        try:
            with open(path) as f:
                for line in f:
                    if "(hex)" in line:
                        parts = line.split("(hex)")
                        if len(parts) == 2:
                            oui = parts[0].strip().replace("-", ":").upper()
                            vendor = parts[1].strip()
                            self._db[oui] = vendor
            logger.info("OUI carregado: %d registros", len(self._db))
        except Exception as exc:
            logger.warning("Falha ao carregar OUI: %s", exc)

    def lookup(self, mac: str) -> Optional[str]:
        """
        Retorna o fabricante para um MAC address.

        Args:
            mac: Endereço MAC em qualquer formato.

        Returns:
            Nome do fabricante ou None.
        """
        normalized = mac.upper().replace("-", ":").replace(".", ":")
        oui = ":".join(normalized.split(":")[:3])
        return self._db.get(oui)


class FingerprintCollector:
    """
    Coletor assíncrono de descoberta e fingerprinting de dispositivos.

    Executa ARP scan, resolve hostnames e classifica dispositivos por tipo.
    Mantém estado incremental — novos dispositivos são adicionados,
    dispositivos sem resposta por N ciclos são marcados como offline.

    Uso:
        collector = FingerprintCollector()
        devices = await collector.scan()
    """

    def __init__(
        self,
        network: Optional[str] = None,
        oui_file: Optional[str] = None,
        interval: float = 300.0,    # 5 minutos entre scans completos
        offline_threshold: int = 3,  # ciclos sem resposta para marcar offline
        db=None,
    ):
        """
        Args:
            network:           CIDR da rede (ex: '192.168.1.0/24').
                               Auto-detectado se None.
            oui_file:          Caminho para base OUI.
            interval:          Intervalo entre scans em segundos.
            offline_threshold: Ciclos sem resposta para marcar dispositivo offline.
            db:                Repositório SQLite para persistência.
        """
        self.network = network
        self.oui_db = OUIDatabase(oui_file)
        self.interval = interval
        self.offline_threshold = offline_threshold
        self.db = db
        self._running = False
        self._devices: dict[str, Device] = {}    # {mac: Device}
        self._miss_counts: dict[str, int] = {}   # {mac: ciclos sem resposta}

    async def detect_network(self) -> Optional[NetworkRange]:
        """
        Detecta automaticamente o range da rede local usando netifaces.

        Estratégia:
          1. Lista interfaces de rede (exclui lo)
          2. Obtém IP local e máscara
          3. Consulta tabela ARP para o gateway padrão

        Returns:
            NetworkRange com dados da rede local, ou None se não detectado.
        """
        try:
            # TODO: Implementar com netifaces
            # import netifaces
            # gateways = netifaces.gateways()
            # default_gw = gateways['default'][netifaces.AF_INET]
            # gateway_ip, iface = default_gw[0], default_gw[1]
            # addrs = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]
            # local_ip = addrs['addr']
            # netmask = addrs['netmask']
            # network = str(ipaddress.IPv4Network(f"{local_ip}/{netmask}", strict=False))
            logger.info("Detectando rede local...")
        except Exception as exc:
            logger.error("Falha ao detectar rede: %s", exc)
        return None

    async def arp_scan(self, network: str) -> list[tuple[str, str]]:
        """
        Executa ARP scan no range especificado.

        Usa Scapy para enviar pacotes ARP e coletar respostas.
        Requer raw socket (cap_net_raw ou root).

        Args:
            network: CIDR da rede (ex: '192.168.1.0/24').

        Returns:
            Lista de tuplas (ip, mac) dos hosts ativos.
        """
        hosts = []
        try:
            # TODO: Implementar com scapy
            # from scapy.all import ARP, Ether, srp
            # arp = ARP(pdst=network)
            # ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            # packet = ether / arp
            # result = srp(packet, timeout=3, verbose=False)[0]
            # hosts = [(recv.psrc, recv.hwsrc) for _, recv in result]
            logger.info("ARP scan em %s: %d hosts encontrados", network, len(hosts))
        except Exception as exc:
            logger.error("Falha no ARP scan: %s", exc)
        return hosts

    async def resolve_hostname_mdns(self, ip: str) -> Optional[str]:
        """
        Resolve hostname via mDNS (Multicast DNS / Bonjour).

        Usa zeroconf para consultar o registro PTR do IP no domínio .local.
        Fallback para resolução DNS reversa convencional.

        Args:
            ip: Endereço IP do dispositivo.

        Returns:
            Hostname resolvido ou None.
        """
        try:
            # TODO: Implementar com zeroconf
            # from zeroconf import Zeroconf
            # zc = Zeroconf()
            # ...
            pass
        except Exception as exc:
            logger.debug("mDNS falhou para %s: %s", ip, exc)

        # Fallback: resolução reversa
        try:
            proc = await asyncio.create_subprocess_exec(
                "host", ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=3.0)
            output = stdout.decode()
            if "domain name pointer" in output:
                hostname = output.split("domain name pointer")[1].strip().rstrip(".")
                return hostname
        except Exception:
            pass
        return None

    def classify_device(self, device: Device) -> str:
        """
        Classifica o tipo de dispositivo por heurística multicamada:
          1. Vendor (OUI) — ex: "MikroTik" → router
          2. Hostname — ex: "iphone" → phone
          3. Portas abertas — ex: 9100 → printer
          4. mDNS services — ex: "_airplay" → tv

        Args:
            device: Dispositivo a classificar.

        Returns:
            Tipo do dispositivo (chave de DEVICE_TYPES).
        """
        # Camada 1: Vendor
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
            if "_airplay" in svc or "_atv" in svc:
                return "tv"
            if "_ipp" in svc or "_pdl-datastream" in svc:
                return "printer"
            if "_smb" in svc or "_afpovertcp" in svc:
                return "nas"

        return "unknown"

    async def scan(self) -> list[Device]:
        """
        Executa scan completo: ARP + hostname + fingerprint.

        Returns:
            Lista de Device com todos os dispositivos descobertos/atualizados.
        """
        if not self.network:
            net_range = await self.detect_network()
            if net_range:
                self.network = net_range.network

        if not self.network:
            logger.warning("Range de rede não disponível — scan abortado.")
            return list(self._devices.values())

        # ARP scan
        found_macs = set()
        arp_results = await self.arp_scan(self.network)
        for ip, mac in arp_results:
            mac_lower = mac.lower()
            found_macs.add(mac_lower)

            if mac_lower not in self._devices:
                device = Device(ip=ip, mac=mac)
                device.vendor = self.oui_db.lookup(mac)
                self._devices[mac_lower] = device
                logger.info("Novo dispositivo: %s (%s) — %s", ip, mac, device.vendor or "?")
            else:
                self._devices[mac_lower].ip = ip
                self._devices[mac_lower].last_seen = time.time()

            # Resolve hostname assincronamente
            device = self._devices[mac_lower]
            if not device.hostname:
                device.hostname = await self.resolve_hostname_mdns(ip)

            # Classifica tipo
            device.device_type = self.classify_device(device)
            device.device_type_label = DEVICE_TYPES.get(device.device_type, "Desconhecido")

        # Atualiza contagem de ausências
        for mac in self._devices:
            if mac not in found_macs:
                self._miss_counts[mac] = self._miss_counts.get(mac, 0) + 1
            else:
                self._miss_counts[mac] = 0

        if self.db:
            # TODO: self.db.save_devices(list(self._devices.values()))
            pass

        return list(self._devices.values())

    async def start(self) -> None:
        """Inicia o loop de scan periódico."""
        self._running = True
        logger.info("FingerprintCollector iniciado — intervalo: %ss", self.interval)
        while self._running:
            try:
                devices = await self.scan()
                logger.debug("Scan concluído: %d dispositivos", len(devices))
            except Exception as exc:
                logger.error("Erro no scan de dispositivos: %s", exc)
            await asyncio.sleep(self.interval)

    async def stop(self) -> None:
        """Para o loop de scan."""
        self._running = False
        logger.info("FingerprintCollector parado.")

    @property
    def devices(self) -> list[Device]:
        """Retorna a lista atual de dispositivos."""
        return list(self._devices.values())
