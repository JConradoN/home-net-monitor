/**
 * charts.js — Configuração e atualização dos gráficos Chart.js
 *
 * Gráficos implementados:
 *   - latencyChart:  Série temporal de latência RTT (24h) com 3 séries:
 *                    gateway, internet (Cloudflare), DNS interno
 *   - trafficChart:  Tráfego WAN in/out em Mbps (banda temporal)
 *
 * Atualizados em tempo real via eventos SSE 'metrics' e
 * ao carregar via fetch /api/history/latency.
 */

'use strict';

// ─── Paleta de cores ────────────────────────────────────────────────────────

const COLORS = {
  gateway:    { line: '#22c55e', fill: 'rgba(34,197,94,0.1)' },    // verde
  internet:   { line: '#3b82f6', fill: 'rgba(59,130,246,0.1)' },   // azul
  dns:        { line: '#a855f7', fill: 'rgba(168,85,247,0.1)' },   // roxo
  wan_in:     { line: '#06b6d4', fill: 'rgba(6,182,212,0.15)' },   // ciano
  wan_out:    { line: '#f97316', fill: 'rgba(249,115,22,0.15)' },  // laranja
};

const CHART_BASE_OPTIONS = {
  responsive: true,
  animation: { duration: 300 },
  plugins: {
    legend: {
      labels: { color: '#9ca3af', font: { size: 11 } }
    },
    tooltip: {
      backgroundColor: '#1f2937',
      titleColor: '#f3f4f6',
      bodyColor: '#d1d5db',
      borderColor: '#374151',
      borderWidth: 1,
    }
  },
  scales: {
    x: {
      ticks: { color: '#6b7280', maxTicksLimit: 8, font: { size: 10 } },
      grid:  { color: '#1f2937' }
    },
    y: {
      ticks: { color: '#6b7280', font: { size: 10 } },
      grid:  { color: '#1f2937' }
    }
  }
};

// ─── Latency Chart ──────────────────────────────────────────────────────────

let latencyChart = null;

/**
 * Inicializa o gráfico de latência RTT.
 * Carrega histórico de 24h via API e configura atualização em tempo real.
 */
async function initLatencyChart() {
  const ctx = document.getElementById('latency-chart');
  if (!ctx) return;

  latencyChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: [],
      datasets: [
        {
          label: 'Gateway (ms)',
          data: [],
          borderColor: COLORS.gateway.line,
          backgroundColor: COLORS.gateway.fill,
          borderWidth: 2,
          pointRadius: 0,
          fill: true,
          tension: 0.4,
        },
        {
          label: 'Internet (ms)',
          data: [],
          borderColor: COLORS.internet.line,
          backgroundColor: COLORS.internet.fill,
          borderWidth: 2,
          pointRadius: 0,
          fill: true,
          tension: 0.4,
        },
        {
          label: 'DNS Interno (ms)',
          data: [],
          borderColor: COLORS.dns.line,
          backgroundColor: COLORS.dns.fill,
          borderWidth: 1.5,
          pointRadius: 0,
          fill: false,
          tension: 0.4,
        },
      ]
    },
    options: {
      ...CHART_BASE_OPTIONS,
      scales: {
        ...CHART_BASE_OPTIONS.scales,
        y: {
          ...CHART_BASE_OPTIONS.scales.y,
          title: { display: true, text: 'RTT (ms)', color: '#6b7280' }
        }
      }
    }
  });

  await loadLatencyHistory('gateway');
}

/**
 * Carrega histórico de latência da API REST para o gráfico.
 * @param {string} target - Alvo selecionado (gateway, cloudflare, google_dns)
 */
async function loadLatencyHistory(target = 'gateway') {
  try {
    const [icmpRes, dnsRes] = await Promise.all([
      fetch('/api/history/latency?hours=24'),
      fetch('/api/metrics/dns'),
    ]);
    const icmpData = await icmpRes.json();
    const dnsData  = await dnsRes.json();

    if (!latencyChart) return;

    // Formata timestamps para exibição (HH:MM)
    const labels = (icmpData.timestamps || []).map(ts =>
      new Date(ts * 1000).toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' })
    );

    latencyChart.data.labels                 = labels;
    latencyChart.data.datasets[0].data       = icmpData.gateway  || [];
    latencyChart.data.datasets[1].data       = icmpData.internet || [];
    latencyChart.data.datasets[2].data       = icmpData.dns_internal || [];
    latencyChart.update('none');
  } catch (err) {
    console.warn('[Charts] Erro ao carregar histórico de latência:', err);
  }
}

/**
 * Troca o alvo exibido no gráfico de latência.
 * @param {string} target
 */
function switchChartTarget(target) {
  loadLatencyHistory(target);
}

/**
 * Adiciona ponto em tempo real ao gráfico de latência.
 * Chamado pelo handler SSE de métricas.
 * @param {Object} icmpData - Objeto com rtt_avg_ms por alvo
 */
function addLatencyPoint(icmpData) {
  if (!latencyChart) return;
  const now = new Date().toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' });
  const MAX_POINTS = 288; // 24h * 60min / 5min

  latencyChart.data.labels.push(now);
  latencyChart.data.datasets[0].data.push(icmpData?.gateway?.rtt_avg_ms ?? null);
  latencyChart.data.datasets[1].data.push(icmpData?.cloudflare?.rtt_avg_ms ?? null);
  latencyChart.data.datasets[2].data.push(null); // DNS vem de outra fonte

  // Remove pontos antigos para evitar crescimento ilimitado
  if (latencyChart.data.labels.length > MAX_POINTS) {
    latencyChart.data.labels.shift();
    latencyChart.data.datasets.forEach(ds => ds.data.shift());
  }

  latencyChart.update('none');
}

// ─── Traffic Chart ──────────────────────────────────────────────────────────

let trafficChart = null;

/**
 * Inicializa o gráfico de tráfego WAN.
 */
function initTrafficChart() {
  const ctx = document.getElementById('traffic-chart');
  if (!ctx) return;

  trafficChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: [],
      datasets: [
        {
          label: 'Download (Mbps)',
          data: [],
          borderColor: COLORS.wan_in.line,
          backgroundColor: COLORS.wan_in.fill,
          borderWidth: 2,
          pointRadius: 0,
          fill: true,
          tension: 0.4,
        },
        {
          label: 'Upload (Mbps)',
          data: [],
          borderColor: COLORS.wan_out.line,
          backgroundColor: COLORS.wan_out.fill,
          borderWidth: 2,
          pointRadius: 0,
          fill: true,
          tension: 0.4,
        },
      ]
    },
    options: {
      ...CHART_BASE_OPTIONS,
      scales: {
        ...CHART_BASE_OPTIONS.scales,
        y: {
          ...CHART_BASE_OPTIONS.scales.y,
          title: { display: true, text: 'Mbps', color: '#6b7280' }
        }
      }
    }
  });
}

/**
 * Adiciona ponto de tráfego em tempo real.
 * @param {Object} snmpData - {wan_in_bps, wan_out_bps}
 */
function addTrafficPoint(snmpData) {
  if (!trafficChart || !snmpData) return;
  const now = new Date().toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' });
  const MAX_POINTS = 120;

  const inMbps  = snmpData.wan_in_bps  ? (snmpData.wan_in_bps  / 1e6).toFixed(2) : null;
  const outMbps = snmpData.wan_out_bps ? (snmpData.wan_out_bps / 1e6).toFixed(2) : null;

  trafficChart.data.labels.push(now);
  trafficChart.data.datasets[0].data.push(inMbps);
  trafficChart.data.datasets[1].data.push(outMbps);

  if (trafficChart.data.labels.length > MAX_POINTS) {
    trafficChart.data.labels.shift();
    trafficChart.data.datasets.forEach(ds => ds.data.shift());
  }
  trafficChart.update('none');
}

// Inicializa gráficos após DOM pronto
document.addEventListener('DOMContentLoaded', () => {
  initLatencyChart();
  initTrafficChart();
});
