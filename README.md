# Home Net Monitor

Monitor de rede doméstica com diagnóstico inteligente — 100% offline.

Coleta métricas contínuas de latência, DNS, Wi-Fi e Mikrotik, correlaciona os dados e exibe alertas acionáveis em um dashboard web em tempo real.

> **Em produção** como serviço systemd no fox-server desde março/2026.

---

## O que faz

O HNM roda em background e monitora continuamente:

- **ICMP** — latência e perda para gateway, DNS interno, DNS externo e internet pública
- **DNS** — tempo de resposta de resolvers internos e externos
- **SNMP (Mikrotik)** — CPU, tráfego WAN, channel utilization, noise floor, retries por rádio
- **Wi-Fi local** — métricas da interface local do host
- **Fingerprint** — ARP scan, vendor MAC (OUI), hostname via mDNS, classificação de dispositivos

Um **motor de correlação** cruza esses dados e produz diagnósticos precisos:

| Sintoma detectado | Diagnóstico |
|---|---|
| Gateway OK + internet lenta | Problema na operadora |
| Gateway lento via Wi-Fi | Interferência ou saturação do rádio |
| DNS interno lento + externo rápido | Roteador sobrecarregado |
| CPU Mikrotik > 80% por > 60s | NAT/Firewall saturado |
| Channel utilization > 70% | Wi-Fi saturado |
| Retries > 15% | Interferência de RF |
| Delta de latência sob carga > 30ms | Bufferbloat |
| Gateway sem resposta > 30s | Queda de conexão |
| Noise floor > −75 dBm | Ruído excessivo |

---

## Stack

- **Python 3.11+**, FastAPI, AsyncIO
- **SQLite** (WAL mode) para histórico persistente
- **Dashboard** — Tailwind CSS + Chart.js + SSE (atualizações em tempo real sem polling)
- **API REST** documentada em `/api/docs`
- **SNMP v2c** via pysnmp, **ARP scan** via Scapy, **mDNS** via zeroconf

---

## Arquitetura

```
collectors/     — Coletores independentes (icmp, dns, snmp, fingerprint, wifi)
engine/         — Correlator (10 regras) + Recommender
api/            — REST endpoints (read-only) + SSE stream
db/             — Repositório SQLite assíncrono
frontend/       — Dashboard HTML/CSS/JS (templates + static)
tests/          — pytest com alvo ≥ 80% de cobertura
```

Cada coletor é uma `asyncio.Task` independente — falha de um não derruba os outros.

---

## Instalação

### Pré-requisitos

- Python 3.11+
- Linux (testado em Ubuntu Server 24.04 e Raspberry Pi OS)
- Mikrotik com SNMP habilitado (opcional)

### Instalar como serviço systemd

```bash
git clone https://github.com/<seu-usuario>/home-net-monitor.git
cd home-net-monitor
sudo bash install.sh
```

O `install.sh` cria o virtualenv, instala dependências, concede `cap_net_raw` para ICMP sem root e habilita o serviço.

Antes de instalar, copie e ajuste o arquivo de configuração:

```bash
cp config.example.json config.json
# edite config.json com o IP do seu roteador e community SNMP
```

### Rodar manualmente (dev)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python main.py --debug
# Com SNMP:
python main.py --snmp-host 192.168.1.1
```

Dashboard disponível em `http://localhost:8080` — API docs em `http://localhost:8080/api/docs`.

### Docker

```bash
docker build -t home-net-monitor .
docker run --network host home-net-monitor
```

---

## Configuração (config.json)

```json
{
  "host": "0.0.0.0",
  "port": 8080,
  "snmp_host": "192.168.1.1",
  "snmp_community": "public",
  "icmp_interval": 30,
  "dns_interval": 60,
  "snmp_interval": 60,
  "fingerprint_interval": 300,
  "thresholds": {
    "gw_latency_high": 50,
    "internet_latency_high": 150,
    "dns_slow": 100,
    "cpu_critical": 80,
    "channel_util": 70,
    "retries": 15
  }
}
```

---

## API REST

Todos os endpoints são read-only (GET). Acesse a documentação interativa em `/api/docs`.

| Endpoint | Descrição |
|---|---|
| `GET /api/status` | Status geral (ok / warning / critical) |
| `GET /api/alerts` | Alertas ativos com severidade e mensagem |
| `GET /api/metrics/icmp` | Últimas métricas de latência e perda |
| `GET /api/metrics/dns` | Últimas métricas DNS |
| `GET /api/metrics/snmp` | CPU, tráfego, Wi-Fi via Mikrotik |
| `GET /api/devices` | Dispositivos descobertos na rede |
| `GET /api/history/outages` | Histórico de quedas (7 dias) |
| `GET /api/history/latency` | Série histórica de latência (24h) |
| `GET /api/recommendations` | Recomendações ativas com passos RouterOS |
| `GET /api/events` | Stream SSE — atualizações em tempo real |

---

## Testes

```bash
pytest tests/ -v --cov=. --cov-report=term-missing
```

---

## Licença

MIT License — Copyright (c) 2026 João Conrado
