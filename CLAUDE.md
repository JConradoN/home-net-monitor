# CLAUDE.md — Home Net Monitor

Guia de desenvolvimento para Claude Code trabalhar neste projeto.

## Visão Geral

**Home Net Monitor (HNM)** é um monitor de rede doméstica 100% offline.
Detecta gargalos de Wi-Fi, DNS, operadora e Mikrotik via correlação de métricas.
Stack: Python 3.11+, FastAPI, AsyncIO, SQLite (WAL), Tailwind CSS.

## Estrutura do Projeto

```
collectors/     — Coleta de métricas (icmp, dns, snmp, fingerprint)
engine/         — Motor de correlação (correlator) + recomendações (recommender)
api/            — REST (routes.py) + SSE (sse.py)
db/             — Repositório SQLite (repository.py)
frontend/       — Dashboard Tailwind + Chart.js
tests/          — pytest (alvo: ≥80% cobertura)
```

## Regras de Desenvolvimento

### Async-First
- Todo I/O usa `async/await` (aiosqlite, asyncio.subprocess, etc.)
- Nunca bloquear o loop: substituir `time.sleep()` por `asyncio.sleep()`
- Coletores são tasks asyncio independentes — falha de um não derruba os outros

### Coletores
- Cada coletor expõe `last_results` / `last_result` para acesso síncrono
- Coletores têm `start()` → loop assíncrono com `interval` configurável
- Fallbacks progressivos: ex. ARP: arp-scan → Scapy → ip neigh

### Engine (Correlator + Recommender)
- Cada regra é um método `_rule_*` isolado — nunca misturar lógicas
- Alertas têm `code` único (string), severidade enum, `user_message` em PT-BR leigo
- Recomendações têm `steps[]` com `technical_detail` RouterOS opcional
- Thresholds são configuráveis via `config.json` (`thresholds.*`)

### API
- Todos endpoints REST são `GET` read-only (exceto `POST /api/wizard/snmp/test`)
- Endpoint SSE em `/api/events` — usa `StreamingResponse` com `text/event-stream`
- Nunca expor a API fora de localhost (RNF06)
- Respostas usam Pydantic models para validação automática

### Banco de Dados
- WAL mode — configurado em `CREATE_TABLES_SQL` via PRAGMA
- `get_latency_series(hours)` retorna listas paralelas alinhadas por bucket de 5min
- `get_latency_series_for_target(target, hours)` retorna lista por alvo específico

### Frontend
- Tailwind CSS via CDN (dev); build local em produção
- Chart.js para gráficos de latência e tráfego
- SSE via `EventSource('/api/events')` — ver `frontend/static/js/sse.js`
- Dashboard atualiza status badge, alertas e recomendações em tempo real

## Comandos Úteis

```bash
# Instalar dependências
pip install -r requirements.txt

# Rodar (dev)
python main.py --debug

# Rodar com SNMP
python main.py --snmp-host 192.168.1.1

# Testes
pytest tests/ -v --cov=. --cov-report=term-missing

# Testes por módulo
pytest tests/test_correlator.py -v
pytest tests/test_recommender.py -v

# Instalar como serviço
sudo bash install.sh
```

## Thresholds (config.json → thresholds)

| Chave | Padrão | Descrição |
|-------|--------|-----------|
| `gw_latency_high` | 50 ms | Gateway "lento" |
| `internet_latency_high` | 150 ms | Internet "lenta" |
| `dns_slow` | 100 ms | DNS lento |
| `dns_fast` | 30 ms | DNS rápido |
| `cpu_critical` | 80 % | CPU crítica Mikrotik |
| `cpu_duration` | 60 s | Duração mínima CPU alta |
| `channel_util` | 70 % | Wi-Fi saturado |
| `retries` | 15 % | Interferência RF |
| `noise_floor` | -75 dBm | Ruído excessivo |
| `bufferbloat_delta` | 30 ms | Bufferbloat |
| `outage_duration` | 30 s | Queda confirmada |

## Códigos de Alerta

| Código | Severidade | Regra |
|--------|-----------|-------|
| `OUTAGE` | Critical | Gateway inacessível > 30s |
| `ISP_PROBLEM` | Critical | GW OK + internet lenta |
| `CPU_CRITICAL` | Critical | CPU > 80% por > 60s |
| `WIFI_HIGH_LATENCY` | Warning | RTT gateway via Wi-Fi alto |
| `DNS_ROUTER_OVERLOAD` | Warning | DNS interno lento + externo rápido |
| `WIFI_SATURATION` | Warning | Channel util > 70% |
| `RF_INTERFERENCE` | Warning | Retries > 15% |
| `BUFFERBLOAT` | Warning | Delta latência > 30ms sob carga |
| `DNS_ISP_ROUTE` | Info | DNS externo lento |
| `HIGH_NOISE` | Info | Noise floor > -75 dBm |

## Adicionando um Novo Coletor

1. Crie `collectors/meu_coletor.py` com dataclasses de resultado + classe `MeuColetor`
2. Adicione `start()` → loop + `last_result` property
3. Adicione campos no `CorrelationSnapshot` (engine/correlator.py)
4. Adicione regra `_rule_*` no `Correlator`
5. Adicione gerador `_rec_*` no `Recommender`
6. Registre em `startup()` (main.py)
7. Adicione endpoint em `create_router()` (api/routes.py)
8. Escreva testes em `tests/test_meu_coletor.py`

## Notas de Segurança

- ICMP raw requer `cap_net_raw` ou root — ver `install.sh` e `home-net-monitor.service`
- A API nunca escuta em `0.0.0.0` — apenas `127.0.0.1` (RNF06)
- Sem telemetria, sem chamadas externas (RNF05)
- SQLite sem criptografia — roda em rede local confiável
