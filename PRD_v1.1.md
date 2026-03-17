
# 🧩 **Home Net Monitor — Product Requirements Document (PRD)**  
**Versão:** 1.1  
**Data:** Março / 2026  
**Responsável:** João Conrado  
**Tipo:** Aplicação local — diagnóstico de redes domésticas  
**Status:** Aprovado para desenvolvimento  

---

# 1. Visão Geral

O **Home Net Monitor** é uma ferramenta local, leve e modular para diagnóstico inteligente de redes domésticas brasileiras. Ele identifica gargalos de Wi-Fi, DNS, operadora, Mikrotik e redes mesh (Twibi, Deco, Google Wi-Fi), correlaciona métricas internas e externas e oferece recomendações claras e acionáveis para o usuário final.

O objetivo é permitir que qualquer pessoa — mesmo sem conhecimento técnico — entenda rapidamente **por que a internet está lenta** e como resolver o problema, sem depender de suporte da operadora.

> **O sistema funciona 100% offline. Nenhum dado é transmitido para fora da rede local.**

---

# 2. Objetivos do Produto

## 2.1 Objetivos Principais
- Detectar automaticamente gargalos em redes domésticas  
- Diferenciar problemas de Wi-Fi, cabo, roteador e operadora  
- Coletar métricas reais dos equipamentos via SNMP e RouterOS API  
- Exibir alertas claros com severidade e linguagem acessível  
- Oferecer recomendações práticas e acionáveis  
- Funcionar totalmente offline  

## 2.2 Objetivos Secundários
- Interface web simples, profissional e responsiva  
- Arquitetura modular — novos coletores podem ser adicionados sem alterar o core  
- Histórico de quedas e desempenho  
- Baixo consumo de recursos — compatível com Raspberry Pi  

---

# 3. Público-Alvo

## 3.1 Usuários Finais
Residências com internet fibra (Vivo, Claro, NIO, Brisanet etc.) com:
- Roteador da operadora  
- Mikrotik como roteador principal  
- Redes mesh Wi-Fi (Twibi, Deco, Google Wi-Fi, TP-Link EAP)  

## 3.2 Perfil Técnico

| Perfil | Descrição | Expectativa |
|--------|-----------|-------------|
| Usuário leigo | Baixo conhecimento em redes. Quer saber “por que está lento”. | Diagnóstico simples e claro |
| Usuário técnico | Conhece redes, usa Mikrotik, quer métricas detalhadas. | Dados brutos, gráficos, SNMP, histórico |
| Administrador doméstico | Gerencia rede da família ou pequeno escritório. | Visão geral + alertas + dispositivos conectados |

---

# 4. Escopo do Produto

## 4.1 Funcionalidades Incluídas — MVP

### A. Coleta de Métricas

**Latência e perda de pacotes para:**
- Gateway  
- DNS interno  
- DNS externo (1.1.1.1 / 8.8.8.8)  
- Internet pública (Google, Cloudflare)  

**Métricas via SNMP / RouterOS API (Mikrotik):**
- CPU  
- Tráfego WAN (in/out)  
- Clientes Wi-Fi por rádio  
- Channel Utilization (%)  
- Noise Floor (dBm)  
- Retries (%)  

---

### B. Descoberta e Fingerprinting de Dispositivos
- Identificação por Vendor MAC (OUI)  
- Hostname via mDNS / NetBIOS  
- Classificação heurística: TV, celular, notebook, IoT  
- ARP scan automático para detectar range da rede  

---

### C. Motor de Detecção de Gargalos

| Condição Detectada | Diagnóstico | Severidade |
|--------------------|-------------|------------|
| Ping Gateway baixo + Ping Internet alto | Problema na operadora | Critical |
| Ping Gateway alto via Wi-Fi | Interferência ou saturação Wi-Fi | Warning |
| DNS interno lento + DNS externo rápido | Roteador da operadora sobrecarregado | Warning |
| DNS interno rápido + DNS externo lento | Problema de rota da operadora | Info |
| CPU Mikrotik > 80% por > 60s | NAT/Firewall sobrecarregado | Critical |
| Channel Utilization > 70% | Wi-Fi saturado | Warning |
| Retries > 15% | Interferência de RF | Warning |
| Latência alta sob carga | Bufferbloat | Warning |
| Gateway sem resposta > 30s | Queda de conexão | Critical |
| Noise Floor > -75 dBm | Ruído excessivo | Info |

---

### D. Bufferbloat Detection
- Mede latência baseline  
- Mede latência sob carga  
- Classifica: Nenhum / Leve / Moderado / Severo  
- Sugere configuração de QoS/Queue no Mikrotik  

---

### E. Motor de Recomendações
- Mikrotik: Queue, NAT, Firewall  
- Mesh Wi-Fi: canal, posicionamento, backhaul  
- DNS: Cloudflare/Google  
- Operadora: documentação de quedas  
- Interferência Wi-Fi: canal e potência  

---

### F. Dashboard Web
- Status geral da rede (verde / amarelo / vermelho)  
- Alertas em tempo real (SSE)  
- Gráficos de latência e perda (24h)  
- Histórico de quedas (7 dias)  
- Lista de dispositivos com ícones  
- Tailwind CSS  

---

### G. Wizard de Configuração SNMP

Passos:
1. Detectar gateway e range via ARP  
2. Instruções para habilitar SNMP no Mikrotik  
3. Teste de conectividade SNMP  
4. Validação dos coletores  

**Comando sugerido:**
```
/snmp set enabled=yes
/snmp community add name=public addresses=192.168.1.0/24
```

---

## 4.2 Fora do Escopo (MVP)

| Funcionalidade | Justificativa |
|----------------|---------------|
| Controle remoto do Mikrotik | Risco de indisponibilidade |
| App mobile | Complexidade |
| Integração com nuvem | Privacidade |
| Machine Learning | Pós-MVP |
| Redes corporativas | Público doméstico |
| Notificações push | Dashboard é o canal principal |

---

# 5. Requisitos Funcionais

| ID | Requisito | Descrição | Prioridade |
|----|-----------|-----------|------------|
| RF01 | Coletar latência WAN | Medir latência e perda para 8.8.8.8 | Alta |
| RF02 | Medir DNS | Comparar DNS interno e externo | Alta |
| RF03 | Coletar SNMP/API | CPU, tráfego, Wi-Fi, noise, retries | Alta |
| RF04 | Descobrir dispositivos | ARP + OUI + mDNS | Média |
| RF05 | Detectar gargalos | Regras de correlação | Alta |
| RF06 | Alertas com severidade | Info / Warning / Critical | Alta |
| RF07 | Armazenar métricas | SQLite com timestamp | Alta |
| RF08 | Diagnóstico correlacionado | Wi-Fi vs cabo vs operadora | Alta |
| RF09 | Bufferbloat Test | Latência sob carga | Média |
| RF10 | Histórico de quedas | Registrar períodos sem resposta | Média |
| RF11 | Wizard SNMP | Fluxo guiado | Alta |
| RF12 | Auto-descoberta | Detectar gateway e range | Alta |
| RF13 | SSE | Alertas em tempo real | Alta |
| RF14 | Recomendações | Sugestões por contexto | Média |

---

# 6. Requisitos Não Funcionais

| ID | Categoria | Requisito | Critério |
|----|-----------|-----------|----------|
| RNF01 | Performance | Baixo consumo | < 5% CPU |
| RNF02 | Performance | Dashboard rápido | < 1s |
| RNF03 | Confiabilidade | Resiliência | Coletores independentes |
| RNF04 | Confiabilidade | Operação contínua | 7 dias |
| RNF05 | Privacidade | Dados locais | Sem telemetria |
| RNF06 | Segurança | Exposição | Apenas localhost |
| RNF07 | Usabilidade | Clareza | Diagnóstico em < 2 min |
| RNF08 | Modularidade | Coletores plugáveis | Sem alterar core |
| RNF09 | Portabilidade | Hardware mínimo | Raspberry Pi 3+ |
| RNF10 | Manutenção | Testes | ≥ 80% cobertura |

---

# 7. Jornada do Usuário

## 7.1 Primeira Utilização
1. Instala o HNM  
2. Acessa o dashboard  
3. Wizard detecta gateway e range  
4. Wizard orienta habilitar SNMP  
5. Teste SNMP  
6. Coleta inicia  
7. Dashboard exibe status  

## 7.2 Uso Diário
- Ver status geral  
- Ver alertas  
- Ver recomendações  
- Ver histórico de quedas  
- Ver dispositivos conectados  

---

# 8. Métricas de Sucesso

| Métrica | Meta | Como medir |
|--------|------|------------|
| Identificar causa | < 2 min | Teste de usabilidade |
| Carregamento | < 1s | DevTools |
| Uptime | 7 dias | Logs |
| CPU | < 5% | htop |
| Cobertura de testes | ≥ 80% | pytest |
| Configuração inicial | < 5 min | Teste wizard |
| Falsos positivos | < 10% | Revisão |

---

# 9. Roadmap de Desenvolvimento

| Fase | Duração | Entregáveis | Dependências |
|------|----------|-------------|--------------|
| Fase 1 — MVP | 2 semanas | ICMP, DNS, SNMP básico, dashboard simples | — |
| Fase 2 — Expansão | 4 semanas | Fingerprinting, Wi-Fi, gráficos, bufferbloat | Fase 1 |
| Fase 3 — Polimento | 4 semanas | UI Tailwind, histórico, wizard SNMP, testes | Fase 2 |

### Backlog Pós-MVP
- Suporte a UniFi / TP-Link EAP  
- Relatório PDF  
- Alertas via Telegram  
- Multi-site  
- Detecção de intrusos  

---

# 10. Riscos e Mitigações

| Risco | Prob. | Impacto | Mitigação |
|-------|--------|----------|-----------|
| APs mesh sem SNMP | Alta | Médio | Inferência via latência |
| SNMP desabilitado | Média | Alto | Wizard SNMP |
| ICMP bloqueado | Baixa | Alto | Múltiplos hosts |
| IP do Mikrotik desconhecido | Alta | Médio | ARP + OUI |
| Porta 8080 ocupada | Média | Baixo | Porta configurável |
| ICMP requer root | Alta | Médio | cap_net_raw |
| Falsos positivos | Média | Médio | Thresholds ajustáveis |
| SQLite lock | Baixa | Baixo | WAL mode |

---

# 11. Entregáveis

## 11.1 Código-Fonte
- Coletores ICMP, SNMP, DNS  
- Motor de correlação  
- API REST + SSE  
- Frontend Tailwind  
- Testes (≥ 80%)  

## 11.2 Documentação
- README  
- CLAUDE.md  
- Swagger  
- Guia de coletores  
- PRD, TSD, User Stories  

## 11.3 Infraestrutura
- Dockerfile  
- Script de instalação  
- Systemd service  

---

# 12. Glossário

*(Mantido integralmente do documento original)*

---

# 13. Controle de Versões

| Versão | Data | Autor | Descrição |
|--------|-------|--------|-----------|
| 1.0 | Fev/2026 | João Conrado | Versão inicial |
| 1.1 | Mar/2026 | João Conrado | Adição de bufferbloat, wizard SNMP, fingerprinting, correlação avançada, glossário e riscos |

> **Documento aprovado para início da Fase 1. Próxima revisão ao final da Fase 2.**

