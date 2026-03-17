"""
collectors/wifi.py — Coletor de métricas da interface Wi-Fi local.

Coleta métricas da conexão Wi-Fi do próprio host usando `iw` e `iwconfig`:
  - SSID, BSSID, frequência e banda (2.4/5 GHz)
  - Sinal RSSI (dBm) e qualidade de link (%)
  - Bitrate TX/RX (Mbps) e TX-Power (dBm)
  - Retries, TX failed e beacon loss
  - Scan de APs vizinhos (canal e sinal)

Requer: iw, iwconfig (pacotes iw e wireless-tools no Linux).
Interface detectada automaticamente via `iw dev`.
"""

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# Frequência → banda
BAND_2G_MAX_MHZ = 2484
BAND_5G_MIN_MHZ = 5160
BAND_6G_MIN_MHZ = 5925


def _freq_to_band(freq_mhz: float) -> str:
    if freq_mhz <= BAND_2G_MAX_MHZ:
        return "2.4 GHz"
    if freq_mhz < BAND_6G_MIN_MHZ:
        return "5 GHz"
    return "6 GHz"


def _rssi_to_quality(rssi_dbm: float) -> float:
    """Converte RSSI em qualidade de link (0–100%).

    Escala linear: -50 dBm = 100%, -100 dBm = 0%.
    """
    quality = 2 * (rssi_dbm + 100)
    return max(0.0, min(100.0, quality))


# ─── Dataclasses ──────────────────────────────────────────────────────────────

@dataclass
class WifiNeighbor:
    """AP vizinho detectado no scan."""
    bssid: str
    ssid: Optional[str] = None
    frequency_mhz: Optional[float] = None
    channel: Optional[int] = None
    signal_dbm: Optional[float] = None

    @property
    def band(self) -> Optional[str]:
        return _freq_to_band(self.frequency_mhz) if self.frequency_mhz else None


@dataclass
class WifiResult:
    """Snapshot completo de métricas Wi-Fi do host."""

    interface: str
    timestamp: float = field(default_factory=time.time)

    # Conexão
    ssid: Optional[str] = None
    bssid: Optional[str] = None
    frequency_mhz: Optional[float] = None

    # Sinal
    signal_dbm: Optional[float] = None
    link_quality_pct: Optional[float] = None   # 0–100
    tx_power_dbm: Optional[float] = None
    noise_dbm: Optional[float] = None

    # Throughput
    tx_bitrate_mbps: Optional[float] = None
    rx_bitrate_mbps: Optional[float] = None

    # Confiabilidade
    tx_retries: Optional[int] = None
    tx_failed: Optional[int] = None
    beacon_loss: Optional[int] = None

    # APs vizinhos
    neighbors: list = field(default_factory=list)

    @property
    def is_connected(self) -> bool:
        return self.ssid is not None

    @property
    def band(self) -> Optional[str]:
        return _freq_to_band(self.frequency_mhz) if self.frequency_mhz else None

    @property
    def signal_quality_label(self) -> str:
        """Rótulo de qualidade de sinal para exibição."""
        if self.signal_dbm is None:
            return "Desconhecido"
        if self.signal_dbm >= -50:
            return "Excelente"
        if self.signal_dbm >= -60:
            return "Bom"
        if self.signal_dbm >= -70:
            return "Regular"
        return "Fraco"


# ─── Helpers assíncronos ──────────────────────────────────────────────────────

async def _run(cmd: str) -> tuple[str, str, int]:
    """Executa comando de shell e retorna (stdout, stderr, returncode)."""
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10.0)
        return stdout.decode(errors="replace"), stderr.decode(errors="replace"), proc.returncode
    except asyncio.TimeoutError:
        logger.warning("Timeout executando: %s", cmd)
        return "", "timeout", -1
    except Exception as exc:
        logger.debug("Erro executando '%s': %s", cmd, exc)
        return "", str(exc), -1


# ─── Parsers ─────────────────────────────────────────────────────────────────

def _parse_iw_link(output: str) -> dict:
    """Parseia saída de `iw dev <iface> link`."""
    data: dict = {}
    if "Not connected" in output or not output.strip():
        return data

    m = re.search(r"SSID:\s*(.+)", output)
    if m:
        data["ssid"] = m.group(1).strip()

    m = re.search(r"Connected to\s+([\w:]+)", output)
    if m:
        data["bssid"] = m.group(1)

    m = re.search(r"freq:\s*(\d+)", output)
    if m:
        data["frequency_mhz"] = float(m.group(1))

    m = re.search(r"signal:\s*([-\d.]+)\s*dBm", output)
    if m:
        data["signal_dbm"] = float(m.group(1))

    m = re.search(r"tx bitrate:\s*([\d.]+)", output)
    if m:
        data["tx_bitrate_mbps"] = float(m.group(1))

    m = re.search(r"rx bitrate:\s*([\d.]+)", output)
    if m:
        data["rx_bitrate_mbps"] = float(m.group(1))

    return data


def _parse_iw_station(output: str) -> dict:
    """Parseia saída de `iw dev <iface> station dump`."""
    data: dict = {}

    m = re.search(r"tx retries:\s*(\d+)", output)
    if m:
        data["tx_retries"] = int(m.group(1))

    m = re.search(r"tx failed:\s*(\d+)", output)
    if m:
        data["tx_failed"] = int(m.group(1))

    m = re.search(r"beacon loss:\s*(\d+)", output)
    if m:
        data["beacon_loss"] = int(m.group(1))

    # Sinal mais preciso (pode ter múltiplos valores: antenas)
    m = re.search(r"signal:\s*([-\d.]+)", output)
    if m:
        data["signal_dbm"] = float(m.group(1))

    m = re.search(r"tx bitrate:\s*([\d.]+)", output)
    if m:
        data["tx_bitrate_mbps"] = float(m.group(1))

    m = re.search(r"rx bitrate:\s*([\d.]+)", output)
    if m:
        data["rx_bitrate_mbps"] = float(m.group(1))

    return data


def _parse_iwconfig(output: str) -> dict:
    """Parseia saída de `iwconfig <iface>`."""
    data: dict = {}

    # Link Quality: 70/70 ou 70/100
    m = re.search(r"Link Quality=(\d+)/(\d+)", output)
    if m:
        data["link_quality_pct"] = 100.0 * int(m.group(1)) / int(m.group(2))

    m = re.search(r"Signal level=([-\d]+)\s*dBm", output)
    if m:
        data["signal_dbm"] = float(m.group(1))

    m = re.search(r"Noise level=([-\d]+)\s*dBm", output)
    if m:
        data["noise_dbm"] = float(m.group(1))

    m = re.search(r"Tx-Power=(\d+)\s*dBm", output)
    if m:
        data["tx_power_dbm"] = float(m.group(1))

    m = re.search(r'ESSID:"([^"]*)"', output)
    if m:
        data["ssid"] = m.group(1)

    m = re.search(r"Bit Rate=([\d.]+)\s*[MG]b/s", output)
    if m:
        data["tx_bitrate_mbps"] = float(m.group(1))

    return data


def _parse_iw_scan(output: str) -> list:
    """Parseia saída de `iw dev <iface> scan` em lista de WifiNeighbor."""
    neighbors = []
    current: dict = {}

    for line in output.splitlines():
        line = line.strip()

        m = re.match(r"BSS\s+([\w:]+)\(on", line)
        if m:
            if current.get("bssid"):
                neighbors.append(_build_neighbor(current))
            current = {"bssid": m.group(1)}
            continue

        if not current:
            continue

        m = re.search(r"freq:\s*(\d+)", line)
        if m:
            current["frequency_mhz"] = float(m.group(1))
            continue

        m = re.search(r"signal:\s*([-\d.]+)\s*dBm", line)
        if m:
            current["signal_dbm"] = float(m.group(1))
            continue

        m = re.search(r"SSID:\s*(.*)", line)
        if m:
            current["ssid"] = m.group(1).strip() or None
            continue

    if current.get("bssid"):
        neighbors.append(_build_neighbor(current))

    return neighbors


def _build_neighbor(data: dict) -> WifiNeighbor:
    freq = data.get("frequency_mhz")
    channel = _freq_to_channel(freq) if freq else None
    return WifiNeighbor(
        bssid=data["bssid"],
        ssid=data.get("ssid"),
        frequency_mhz=freq,
        channel=channel,
        signal_dbm=data.get("signal_dbm"),
    )


def _freq_to_channel(freq_mhz: float) -> Optional[int]:
    """Converte frequência em número de canal Wi-Fi."""
    f = int(freq_mhz)
    if 2412 <= f <= 2484:
        return (f - 2407) // 5
    if 5160 <= f <= 5885:
        return (f - 5000) // 5
    if 5925 <= f <= 7125:
        return (f - 5950) // 5
    return None


# ─── Collector ────────────────────────────────────────────────────────────────

class WiFiCollector:
    """
    Coletor de métricas Wi-Fi do host local.

    Usa `iw` e `iwconfig` para coletar informações da interface sem fio:
    sinal, qualidade, bitrate, retries e APs vizinhos.

    Uso:
        collector = WiFiCollector()
        await collector.start()         # loop assíncrono
        result = collector.last_result  # último snapshot
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        interval: float = 30.0,
        scan_neighbors: bool = False,   # scan requer cap_net_admin
    ):
        """
        Args:
            interface:       Nome da interface (ex: 'wlp1s0'). None = auto-detectar.
            interval:        Segundos entre coletas.
            scan_neighbors:  Se True, faz scan de APs vizinhos (mais lento, requer root).
        """
        self.interface = interface
        self.interval = interval
        self.scan_neighbors = scan_neighbors
        self._last_result: Optional[WifiResult] = None
        self._running = False

    @property
    def last_result(self) -> Optional[WifiResult]:
        return self._last_result

    async def start(self) -> None:
        """Loop assíncrono de coleta — roda indefinidamente."""
        self._running = True

        if self.interface is None:
            self.interface = await self._detect_interface()

        if self.interface is None:
            logger.warning("WiFiCollector: nenhuma interface Wi-Fi detectada — coletor inativo")
            return

        logger.info("WiFiCollector iniciado — interface: %s, intervalo: %ss", self.interface, self.interval)

        while self._running:
            try:
                self._last_result = await self.collect()
                if self._last_result and self._last_result.is_connected:
                    logger.debug(
                        "Wi-Fi: %s | %s | %.0f dBm | %.0f Mbps",
                        self._last_result.ssid,
                        self._last_result.band,
                        self._last_result.signal_dbm or 0,
                        self._last_result.tx_bitrate_mbps or 0,
                    )
            except Exception as exc:
                logger.error("WiFiCollector erro: %s", exc)
            await asyncio.sleep(self.interval)

    async def stop(self) -> None:
        self._running = False

    async def collect(self) -> Optional[WifiResult]:
        """Coleta snapshot completo de métricas Wi-Fi."""
        iface = self.interface
        if not iface:
            return None

        result = WifiResult(interface=iface)

        # 1. Link info via `iw dev <iface> link`
        stdout, _, rc = await _run(f"iw dev {iface} link")
        if rc == 0:
            link = _parse_iw_link(stdout)
            result.ssid = link.get("ssid")
            result.bssid = link.get("bssid")
            result.frequency_mhz = link.get("frequency_mhz")
            result.signal_dbm = link.get("signal_dbm")
            result.tx_bitrate_mbps = link.get("tx_bitrate_mbps")
            result.rx_bitrate_mbps = link.get("rx_bitrate_mbps")

        if not result.is_connected:
            return result

        # 2. Station dump via `iw dev <iface> station dump` (mais completo)
        stdout, _, rc = await _run(f"iw dev {iface} station dump")
        if rc == 0 and stdout.strip():
            station = _parse_iw_station(stdout)
            result.tx_retries = station.get("tx_retries")
            result.tx_failed = station.get("tx_failed")
            result.beacon_loss = station.get("beacon_loss")
            # Atualiza sinal/bitrate com dados mais precisos da station
            if station.get("signal_dbm") is not None:
                result.signal_dbm = station["signal_dbm"]
            if station.get("tx_bitrate_mbps") is not None:
                result.tx_bitrate_mbps = station["tx_bitrate_mbps"]
            if station.get("rx_bitrate_mbps") is not None:
                result.rx_bitrate_mbps = station["rx_bitrate_mbps"]

        # 3. iwconfig — qualidade de link, tx-power, noise
        stdout, _, rc = await _run(f"iwconfig {iface}")
        if rc == 0 and stdout.strip():
            iwcfg = _parse_iwconfig(stdout)
            result.link_quality_pct = iwcfg.get("link_quality_pct")
            result.tx_power_dbm = iwcfg.get("tx_power_dbm")
            result.noise_dbm = iwcfg.get("noise_dbm")
            # Fallback: ssid e sinal do iwconfig se iw falhou
            if result.ssid is None:
                result.ssid = iwcfg.get("ssid")
            if result.signal_dbm is None:
                result.signal_dbm = iwcfg.get("signal_dbm")
            if result.tx_bitrate_mbps is None:
                result.tx_bitrate_mbps = iwcfg.get("tx_bitrate_mbps")

        # Calcula link_quality_pct via RSSI se iwconfig não retornou
        if result.link_quality_pct is None and result.signal_dbm is not None:
            result.link_quality_pct = _rssi_to_quality(result.signal_dbm)

        # 4. Scan de APs vizinhos (opcional, requer root/cap_net_admin)
        if self.scan_neighbors:
            stdout, _, rc = await _run(f"iw dev {iface} scan")
            if rc == 0 and stdout.strip():
                result.neighbors = _parse_iw_scan(stdout)
            else:
                logger.debug("Scan Wi-Fi não disponível (requer root/cap_net_admin)")

        return result

    async def _detect_interface(self) -> Optional[str]:
        """Auto-detecta a interface Wi-Fi via `iw dev`."""
        stdout, _, rc = await _run("iw dev")
        if rc != 0:
            return None

        # Pega a primeira interface em modo managed
        interfaces = re.findall(r"Interface\s+(\w+)", stdout)
        if not interfaces:
            return None

        # Prefere interfaces com nomes padrão (wl*)
        for iface in interfaces:
            if iface.startswith("wl"):
                logger.info("WiFiCollector: interface detectada: %s", iface)
                return iface

        logger.info("WiFiCollector: interface detectada: %s", interfaces[0])
        return interfaces[0]
