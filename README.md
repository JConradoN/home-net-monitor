
# 🏠 **Home Net Monitor**  
Diagnóstico inteligente para redes domésticas brasileiras — 100% offline.

---

## 📌 Sobre o Projeto

O **Home Net Monitor (HNM)** é uma ferramenta local, leve e modular para diagnóstico de redes domésticas.  
Ele identifica gargalos de **Wi‑Fi**, **DNS**, **operadora**, **Mikrotik** e **redes mesh** (Twibi, Deco, Google Wi‑Fi), correlaciona métricas internas e externas e apresenta **alertas claros com recomendações práticas**.

O sistema funciona **100% offline** — nenhum dado sai da sua rede.

---

## ✨ Principais Recursos

- 🔍 **Diagnóstico automático** de problemas de rede  
- 📡 **Coleta de métricas reais** via ICMP, DNS, SNMP e RouterOS API  
- 📶 Análise de **Wi‑Fi**, interferência, saturação e backhaul  
- 🌐 Detecção de problemas na **operadora**  
- 📊 **Dashboard web** com gráficos, alertas e histórico  
- 🧠 Motor de correlação para identificar **onde está o problema**  
- 🧩 Arquitetura modular — coletores plugáveis  
- 🛡️ Funciona totalmente **offline**  
- 🧰 Compatível com **Raspberry Pi**  

---

## 🖥️ Capturas de Tela (placeholder)

> *(As imagens serão adicionadas após o primeiro build do dashboard)*

```
[ Dashboard Overview ]
[ Alertas em Tempo Real ]
[ Histórico de Latência ]
[ Lista de Dispositivos ]
```

---

## 🚀 Instalação

### Pré‑requisitos
- Python 3.11+  
- pip  
- (Opcional) Raspberry Pi 3+  

### Instalação rápida

```bash
git clone https://github.com/<seu-usuario>/home-net-monitor.git
cd home-net-monitor
pip install -r requirements.txt
python main.py
```

Acesse o dashboard em:

```
http://localhost:8000
```

---

## 🧙 Wizard de Configuração (SNMP Mikrotik)

Se você usa Mikrotik, o HNM ajuda a habilitar SNMP automaticamente.

Comando sugerido:

```bash
/snmp set enabled=yes
/snmp community add name=public addresses=192.168.1.0/24
```

O wizard testa a conectividade e valida os coletores antes de iniciar o monitoramento.

---

## 📡 O que o HNM Monitora

### 🔧 Métricas de Rede
- Latência e perda para:
  - Gateway  
  - DNS interno  
  - DNS externo  
  - Internet (Google/Cloudflare)

### 📶 Métricas Wi‑Fi (via Mikrotik)
- Channel Utilization  
- Noise Floor  
- Retries  
- Clientes por rádio  

### 🌐 Operadora
- Instabilidade  
- Perda de pacotes  
- Rota lenta  
- Bufferbloat  

### 🧩 Dispositivos
- ARP scan  
- Vendor MAC (OUI)  
- Hostname via mDNS/NetBIOS  
- Classificação heurística (TV, celular, notebook, IoT)  

---

## 🧠 Motor de Diagnóstico

O HNM correlaciona métricas para identificar a causa real do problema:

| Sintoma | Diagnóstico |
|--------|-------------|
| Ping Gateway baixo + Ping Internet alto | Problema na operadora |
| Ping Gateway alto | Problema no Wi‑Fi ou cabo |
| DNS interno lento | Roteador da operadora sobrecarregado |
| DNS externo lento | Problema de rota |
| CPU Mikrotik alta | NAT/Firewall sobrecarregado |
| Channel Utilization alto | Wi‑Fi saturado |
| Retries altos | Interferência |

---

## 📘 Documentação Completa

Toda a documentação oficial está disponível em:

👉 **`[Parece que o resultado não era seguro para exibição. Vamos mudar as coisas e tentar outra opção!]`**

Inclui:
- PRD completo  
- Requisitos funcionais e não funcionais  
- Roadmap  
- Glossário  
- Riscos e mitigações  

---

## 🛣️ Roadmap (Resumo)

- **Fase 1 — MVP**  
  ICMP, DNS, SNMP básico, dashboard simples

- **Fase 2 — Expansão**  
  Fingerprinting, métricas Wi‑Fi, gráficos, bufferbloat

- **Fase 3 — Polimento**  
  UI Tailwind, histórico de quedas, wizard SNMP, testes

---

## 🤝 Contribuindo

Contribuições são bem‑vindas!  
Sugestões, issues e PRs podem ser enviados diretamente no repositório.

---

## 🛡️ Licença

Escolha sua licença (MIT recomendado).  
Exemplo:

```
MIT License
Copyright (c) 2026
```

---

## 💬 Contato

Criado por **João Conrado**  
Para dúvidas ou sugestões, abra uma issue no GitHub.


É só pedir.
