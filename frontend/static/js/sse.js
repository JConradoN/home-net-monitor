/**
 * sse.js — Client-side Server-Sent Events handler
 *
 * Gerencia a conexão com o endpoint /api/events e despacha os eventos
 * recebidos para os handlers do dashboard.
 *
 * Eventos tratados:
 *   - alert:    Novo alerta → renderAlert()
 *   - resolve:  Alerta resolvido → removeAlert()
 *   - status:   Status geral → updateStatusBadge()
 *   - metrics:  Métricas atualizadas → updateMetrics()
 *   - ping:     Keepalive (ignorado no cliente)
 *
 * Reconexão automática com backoff exponencial em caso de falha.
 */

'use strict';

const SSE_URL = '/api/events';
const RECONNECT_INITIAL_MS = 1000;
const RECONNECT_MAX_MS = 30000;

let eventSource = null;
let reconnectDelay = RECONNECT_INITIAL_MS;
let reconnectTimer = null;

/**
 * Inicializa a conexão SSE com o servidor.
 * Chamado automaticamente ao carregar o dashboard.
 */
function connectSSE() {
  if (eventSource) {
    eventSource.close();
  }

  console.log('[SSE] Conectando a', SSE_URL);
  eventSource = new EventSource(SSE_URL);

  eventSource.addEventListener('open', () => {
    console.log('[SSE] Conectado.');
    reconnectDelay = RECONNECT_INITIAL_MS;
    updateConnectionIndicator(true);
  });

  eventSource.addEventListener('error', () => {
    console.warn('[SSE] Conexão perdida. Reconectando em', reconnectDelay, 'ms...');
    updateConnectionIndicator(false);
    eventSource.close();
    scheduleReconnect();
  });

  // ─── Handlers de eventos ─────────────────────────────────────────────────

  eventSource.addEventListener('alert', (e) => {
    try {
      const alert = JSON.parse(e.data);
      renderAlert(alert);
    } catch (err) {
      console.error('[SSE] Erro ao processar evento alert:', err);
    }
  });

  eventSource.addEventListener('resolve', (e) => {
    try {
      const { code } = JSON.parse(e.data);
      removeAlert(code);
    } catch (err) {
      console.error('[SSE] Erro ao processar evento resolve:', err);
    }
  });

  eventSource.addEventListener('status', (e) => {
    try {
      const status = JSON.parse(e.data);
      updateStatusBadge(status.status, status.active_alerts);
    } catch (err) {
      console.error('[SSE] Erro ao processar evento status:', err);
    }
  });

  eventSource.addEventListener('metrics', (e) => {
    try {
      const metrics = JSON.parse(e.data);
      updateMetrics(metrics);
    } catch (err) {
      console.error('[SSE] Erro ao processar evento metrics:', err);
    }
  });

  // ping é keepalive — apenas log de debug
  eventSource.addEventListener('ping', () => {
    // console.debug('[SSE] ping recebido');
  });
}

/**
 * Agenda reconexão com backoff exponencial.
 */
function scheduleReconnect() {
  if (reconnectTimer) return;
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    reconnectDelay = Math.min(reconnectDelay * 2, RECONNECT_MAX_MS);
    connectSSE();
  }, reconnectDelay);
}

/**
 * Atualiza o indicador visual de conexão SSE no status badge.
 * @param {boolean} connected
 */
function updateConnectionIndicator(connected) {
  const badge = document.getElementById('status-badge');
  if (!connected && badge) {
    badge.classList.remove('ok', 'warning', 'critical');
    badge.classList.add('disconnected');
    document.getElementById('status-text').textContent = 'Reconectando...';
  }
}

// Inicia conexão quando o DOM estiver pronto
document.addEventListener('DOMContentLoaded', connectSSE);
