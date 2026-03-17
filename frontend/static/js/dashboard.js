/**
 * dashboard.js — Lógica principal do dashboard Home Net Monitor
 *
 * Responsabilidades:
 *   - Renderizar alertas, recomendações, dispositivos e histórico de quedas
 *   - Atualizar métricas nos cartões (gateway RTT, internet RTT, DNS, CPU)
 *   - Atualizar o status badge (verde/amarelo/vermelho)
 *   - Handler do Wizard SNMP
 *   - Polling periódico dos endpoints REST para estado inicial
 *
 * Depende de:
 *   - sse.js:    Conexão SSE (publica eventos que este módulo consome)
 *   - charts.js: Gráficos de latência e tráfego
 */

'use strict';

// ─── Constantes ─────────────────────────────────────────────────────────────

const API_BASE = '/api';
const POLL_INTERVAL_MS = 30_000;   // Refresh REST a cada 30s como fallback

// Ícones por tipo de dispositivo
const DEVICE_ICONS = {
  tv:       '📺',
  phone:    '📱',
  laptop:   '💻',
  iot:      '🔌',
  router:   '🛜',
  printer:  '🖨️',
  nas:      '🗄️',
  unknown:  '❓',
};

// ─── Status Badge ────────────────────────────────────────────────────────────

/**
 * Atualiza o badge de status no header.
 * Chamado pelo handler SSE 'status'.
 *
 * @param {string} status         - 'ok' | 'warning' | 'critical'
 * @param {number} activeAlerts   - Número de alertas ativos
 */
function updateStatusBadge(status, activeAlerts) {
  const badge = document.getElementById('status-badge');
  const text  = document.getElementById('status-text');
  if (!badge || !text) return;

  badge.className = `flex items-center gap-2 px-3 py-1 rounded-full text-sm font-medium
    transition-colors duration-300 ${status}`;

  const labels = { ok: '✓ Rede OK', warning: '⚠ Atenção', critical: '✕ Problema' };
  const alertSuffix = activeAlerts > 0 ? ` — ${activeAlerts} alerta${activeAlerts > 1 ? 's' : ''}` : '';
  text.textContent = (labels[status] || status) + alertSuffix;
}

// ─── Métricas ────────────────────────────────────────────────────────────────

/**
 * Atualiza os cartões de métricas com dados recebidos via SSE ou REST.
 * Chamado pelo handler SSE 'metrics'.
 *
 * @param {Object} metrics - Payload do evento SSE 'metrics'
 */
function updateMetrics(metrics) {
  if (metrics.icmp) {
    setMetricValue('val-gateway-rtt',  metrics.icmp.gateway?.rtt_avg_ms,  'ms');
    setMetricValue('val-internet-rtt', metrics.icmp.cloudflare?.rtt_avg_ms || metrics.icmp.google_dns?.rtt_avg_ms, 'ms');

    // Atualiza gráficos em tempo real
    if (typeof addLatencyPoint === 'function') addLatencyPoint(metrics.icmp);
  }
  if (metrics.dns) {
    setMetricValue('val-dns-internal', metrics.dns.interno?.avg_latency_ms, 'ms');
  }
  if (metrics.snmp) {
    setMetricValue('val-cpu', metrics.snmp.cpu_usage, '%');
    if (typeof addTrafficPoint === 'function') addTrafficPoint(metrics.snmp);
  }
  if (metrics.wifi) {
    updateWifi(metrics.wifi);
  }
}

/**
 * Atualiza o valor exibido em um cartão de métrica.
 *
 * @param {string} elementId   - ID do elemento HTML
 * @param {number|null} value  - Valor a exibir
 * @param {string} unit        - Unidade ('ms', '%', etc.)
 */
function setMetricValue(elementId, value, unit) {
  const el = document.getElementById(elementId);
  if (!el) return;
  if (value == null || isNaN(value)) {
    el.textContent = '—';
    return;
  }
  el.textContent = typeof value === 'number' ? value.toFixed(1) : value;
}

// ─── Alertas ─────────────────────────────────────────────────────────────────

/**
 * Renderiza ou atualiza um alerta na lista de alertas ativos.
 * Chamado pelo handler SSE 'alert'.
 *
 * @param {Object} alert - {code, severity, title, user_message, color, timestamp}
 */
function renderAlert(alert) {
  const list = document.getElementById('alert-list');
  if (!list) return;

  // Remove placeholder
  const placeholder = list.querySelector('p.italic');
  if (placeholder) placeholder.remove();

  // Remove alerta anterior com mesmo código (evita duplicatas)
  const existing = document.getElementById(`alert-${alert.code}`);
  if (existing) existing.remove();

  const severityClass = {
    Critical: 'badge-critical',
    Warning:  'badge-warning',
    Info:     'badge-info',
  }[alert.severity] || 'badge-info';

  const borderColor = {
    Critical: '#dc2626',
    Warning:  '#d97706',
    Info:     '#3b82f6',
  }[alert.severity] || '#6b7280';

  const div = document.createElement('div');
  div.id = `alert-${alert.code}`;
  div.className = `alert-item ${severityClass}`;
  div.style.borderLeftColor = borderColor;
  div.innerHTML = `
    <div class="alert-title">${escapeHtml(alert.title)}</div>
    <div class="alert-message">${escapeHtml(alert.user_message)}</div>
    <div class="text-xs opacity-50 mt-1">${formatTimestamp(alert.timestamp)}</div>
  `;

  // Critical alertas no topo
  if (alert.severity === 'Critical') {
    list.prepend(div);
  } else {
    list.appendChild(div);
  }
}

/**
 * Remove um alerta resolvido da lista.
 * @param {string} code - Código do alerta a remover
 */
function removeAlert(code) {
  const el = document.getElementById(`alert-${code}`);
  if (el) {
    el.style.opacity = '0';
    setTimeout(() => el.remove(), 300);
  }
}

// ─── Recomendações ───────────────────────────────────────────────────────────

/**
 * Carrega e renderiza recomendações via REST.
 * Chamado na inicialização e a cada POLL_INTERVAL_MS.
 */
async function loadRecommendations() {
  try {
    const res = await fetch(`${API_BASE}/recommendations`);
    const recs = await res.json();
    renderRecommendations(recs);
  } catch (err) {
    console.warn('[Dashboard] Erro ao carregar recomendações:', err);
  }
}

/**
 * Renderiza lista de recomendações.
 * @param {Array} recommendations
 */
function renderRecommendations(recommendations) {
  const list = document.getElementById('recommendation-list');
  if (!list) return;
  list.innerHTML = '';

  if (!recommendations.length) {
    list.innerHTML = '<p class="text-sm text-gray-500 italic">Nenhuma recomendação ativa.</p>';
    return;
  }

  recommendations.forEach(rec => {
    const div = document.createElement('div');
    div.className = 'rec-item';
    const stepsHtml = rec.steps.map(s => `
      <li>
        ${escapeHtml(s.description)}
        ${s.technical_detail
          ? `<div class="rec-technical">${escapeHtml(s.technical_detail)}</div>`
          : ''}
      </li>
    `).join('');

    div.innerHTML = `
      <div class="rec-title">${escapeHtml(rec.title)}</div>
      <div class="rec-summary">${escapeHtml(rec.summary)}</div>
      <ol class="rec-steps">${stepsHtml}</ol>
    `;
    list.appendChild(div);
  });
}

// ─── Dispositivos ────────────────────────────────────────────────────────────

/**
 * Carrega e renderiza lista de dispositivos via REST.
 */
async function loadDevices() {
  try {
    const res = await fetch(`${API_BASE}/devices`);
    const devices = await res.json();
    renderDevices(devices);
  } catch (err) {
    console.warn('[Dashboard] Erro ao carregar dispositivos:', err);
  }
}

/**
 * Renderiza lista de dispositivos com ícone e metadados.
 * @param {Array} devices
 */
function renderDevices(devices) {
  const list  = document.getElementById('device-list');
  const count = document.getElementById('device-count');
  if (!list) return;

  list.innerHTML = '';
  if (count) count.textContent = devices.length;

  if (!devices.length) {
    list.innerHTML = '<p class="text-sm text-gray-500 italic">Nenhum dispositivo detectado.</p>';
    return;
  }

  devices.sort((a, b) => (b.last_seen || 0) - (a.last_seen || 0));

  devices.forEach(device => {
    const icon = DEVICE_ICONS[device.device_type] || DEVICE_ICONS.unknown;
    const div = document.createElement('div');
    div.className = 'device-row';
    div.innerHTML = `
      <span class="device-icon">${icon}</span>
      <div class="flex-1 min-w-0">
        <div class="device-name truncate">${escapeHtml(device.display_name)}</div>
        <div class="device-meta">${device.ip} · ${device.vendor || device.device_type_label}</div>
      </div>
      <div class="text-xs text-gray-600 flex-shrink-0">${device.mac}</div>
    `;
    list.appendChild(div);
  });
}

// ─── Histórico de Quedas ─────────────────────────────────────────────────────

/**
 * Carrega e renderiza histórico de quedas.
 */
async function loadOutageHistory() {
  try {
    const res = await fetch(`${API_BASE}/history/outages`);
    const outages = await res.json();
    renderOutages(outages);
  } catch (err) {
    console.warn('[Dashboard] Erro ao carregar histórico de quedas:', err);
  }
}

/**
 * Renderiza histórico de quedas.
 * @param {Array} outages
 */
function renderOutages(outages) {
  const list = document.getElementById('outage-list');
  if (!list) return;
  list.innerHTML = '';

  if (!outages.length) {
    list.innerHTML = '<p class="text-sm text-gray-500 italic">Nenhuma queda registrada.</p>';
    return;
  }

  outages.forEach(o => {
    const div = document.createElement('div');
    div.className = 'flex items-center justify-between text-xs py-1.5 border-b border-gray-800';
    const duration = o.duration_s ? `${Math.round(o.duration_s)}s` : 'Em andamento';
    const recovered = o.recovered
      ? '<span class="text-green-500">Restaurada</span>'
      : '<span class="text-red-400">Ativa</span>';
    div.innerHTML = `
      <span class="text-gray-400">${formatTimestamp(o.start_ts)}</span>
      <span class="text-gray-300">${duration}</span>
      ${recovered}
    `;
    list.appendChild(div);
  });
}

// ─── Wizard SNMP ─────────────────────────────────────────────────────────────

/**
 * Testa conectividade SNMP com o Mikrotik via API.
 * Chamado pelo botão "Testar Conectividade SNMP" no wizard.
 */
async function testSNMP() {
  const host      = document.getElementById('snmp-host')?.value?.trim();
  const community = document.getElementById('snmp-community')?.value?.trim() || 'public';
  const resultDiv = document.getElementById('snmp-result');

  if (!host) {
    showSnmpResult('Por favor, informe o IP do Mikrotik.', false);
    return;
  }

  showSnmpResult('Testando...', null);

  try {
    const res = await fetch(`${API_BASE}/wizard/snmp/test`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ host, community }),
    });
    const data = await res.json();
    showSnmpResult(data.message, data.success);
  } catch (err) {
    showSnmpResult('Erro ao comunicar com o servidor.', false);
  }
}

/**
 * Exibe o resultado do teste SNMP no wizard.
 * @param {string} message
 * @param {boolean|null} success - null = loading
 */
function showSnmpResult(message, success) {
  const div = document.getElementById('snmp-result');
  if (!div) return;
  div.classList.remove('hidden');
  div.className = `text-xs mt-2 p-2 rounded-lg ${
    success === null ? 'text-gray-400 bg-gray-800' :
    success ? 'text-green-400 bg-green-950 border border-green-800' :
              'text-red-400 bg-red-950 border border-red-800'
  }`;
  div.textContent = message;
}

// ─── Wi-Fi Local ─────────────────────────────────────────────────────────────

/**
 * Atualiza o card Wi-Fi com dados do coletor local.
 * Chamado via SSE (evento 'metrics') e polling REST.
 *
 * @param {Object} wifi - {ssid, band, signal_dbm, link_quality_pct, tx_bitrate_mbps, signal_quality_label}
 */
function updateWifi(wifi) {
  const infoEl        = document.getElementById('wifi-info');
  const disconnectEl  = document.getElementById('wifi-disconnected');
  if (!infoEl || !disconnectEl) return;

  if (!wifi || !wifi.ssid) {
    infoEl.classList.add('hidden');
    disconnectEl.classList.remove('hidden');
    disconnectEl.textContent = 'Sem conexão Wi-Fi ativa.';
    return;
  }

  infoEl.classList.remove('hidden');
  disconnectEl.classList.add('hidden');

  // SSID e BSSID
  const ssidEl = document.getElementById('wifi-ssid');
  if (ssidEl) ssidEl.textContent = wifi.ssid;
  const bssidEl = document.getElementById('wifi-bssid');
  if (bssidEl) bssidEl.textContent = wifi.bssid || (wifi.band || '');

  // Sinal
  const signalEl = document.getElementById('wifi-signal-dbm');
  if (signalEl) signalEl.textContent = wifi.signal_dbm != null ? `${wifi.signal_dbm.toFixed(0)}` : '—';

  // Cor do sinal
  const dbm = wifi.signal_dbm || -100;
  const signalColor = dbm >= -50 ? 'text-green-400' : dbm >= -65 ? 'text-yellow-400' : 'text-red-400';
  if (signalEl) signalEl.className = `text-2xl font-bold ${signalColor}`;

  // Label de qualidade
  const labelEl = document.getElementById('wifi-quality-label');
  if (labelEl) labelEl.textContent = wifi.signal_quality_label || '—';

  // Barra de qualidade
  const bar = document.getElementById('wifi-quality-bar');
  if (bar) {
    const pct = wifi.link_quality_pct != null ? wifi.link_quality_pct : 0;
    bar.style.width = `${pct}%`;
    bar.className = `h-1.5 rounded-full transition-all duration-500 ${
      pct >= 70 ? 'bg-green-500' : pct >= 40 ? 'bg-yellow-500' : 'bg-red-500'
    }`;
  }

  // Badge de banda
  const bandBadge = document.getElementById('wifi-band-badge');
  if (bandBadge && wifi.band) {
    bandBadge.textContent = wifi.band;
    bandBadge.classList.remove('hidden');
  }

  // Métricas secundárias
  const txRate = document.getElementById('wifi-tx-rate');
  if (txRate) txRate.textContent = wifi.tx_bitrate_mbps != null ? wifi.tx_bitrate_mbps.toFixed(0) : '—';

  const txPower = document.getElementById('wifi-tx-power');
  if (txPower) txPower.textContent = wifi.tx_power_dbm != null ? wifi.tx_power_dbm.toFixed(0) : '—';

  const retries = document.getElementById('wifi-retries');
  if (retries) retries.textContent = wifi.tx_retries != null ? wifi.tx_retries : '—';
}

/**
 * Carrega métricas Wi-Fi via REST.
 */
async function loadWifiMetrics() {
  try {
    const res = await fetch(`${API_BASE}/metrics/wifi`);
    if (!res.ok) return;
    const wifi = await res.json();
    if (wifi) updateWifi(wifi);
  } catch (err) {
    console.warn('[Dashboard] Erro ao carregar métricas Wi-Fi:', err);
  }
}

// ─── Polling REST (fallback) ─────────────────────────────────────────────────

/**
 * Carrega o estado inicial da API REST.
 * Chamado na inicialização e periodicamente como fallback do SSE.
 */
async function loadInitialState() {
  await Promise.allSettled([
    loadDevices(),
    loadRecommendations(),
    loadOutageHistory(),
    loadCurrentMetrics(),
    loadWifiMetrics(),
  ]);
}

/**
 * Busca métricas atuais via REST e atualiza os cartões.
 */
async function loadCurrentMetrics() {
  try {
    const [statusRes, icmpRes, dnsRes, snmpRes] = await Promise.all([
      fetch(`${API_BASE}/status`),
      fetch(`${API_BASE}/metrics/icmp`),
      fetch(`${API_BASE}/metrics/dns`),
      fetch(`${API_BASE}/metrics/snmp`),
    ]);

    const status = await statusRes.json();
    updateStatusBadge(status.status, status.active_alerts);

    const icmp = await icmpRes.json();
    const targets = {};
    (icmp.targets || []).forEach(t => { targets[t.name] = t; });
    setMetricValue('val-gateway-rtt',  targets.gateway?.rtt_avg_ms, 'ms');
    setMetricValue('val-internet-rtt',
      targets.cloudflare?.rtt_avg_ms || targets.google_dns?.rtt_avg_ms, 'ms');

    const dns = await dnsRes.json();
    const interno = (dns.resolvers || []).find(r => r.name === 'interno');
    setMetricValue('val-dns-internal', interno?.avg_latency_ms, 'ms');

    const snmp = await snmpRes.json();
    setMetricValue('val-cpu', snmp.cpu_usage, '%');

  } catch (err) {
    console.warn('[Dashboard] Erro ao carregar métricas iniciais:', err);
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Escapa HTML para prevenir XSS ao inserir dados da API no DOM.
 * @param {string} str
 * @returns {string}
 */
function escapeHtml(str) {
  if (typeof str !== 'string') return String(str ?? '');
  return str.replace(/&/g,'&amp;').replace(/</g,'&lt;')
            .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

/**
 * Formata timestamp Unix para string legível.
 * @param {number} ts - Timestamp em segundos
 * @returns {string}
 */
function formatTimestamp(ts) {
  if (!ts) return '';
  return new Date(ts * 1000).toLocaleString('pt-BR', {
    day: '2-digit', month: '2-digit',
    hour: '2-digit', minute: '2-digit',
  });
}

// ─── Inicialização ───────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', async () => {
  await loadInitialState();
  // Polling periódico como fallback (complementa SSE)
  setInterval(loadInitialState, POLL_INTERVAL_MS);
});
