const tokenInput = document.querySelector('#token');
const connectButton = document.querySelector('#connect');
const refreshButton = document.querySelector('#refresh');
const statusNode = document.querySelector('#status');
let adminToken = '';

function status(message, kind = '') {
  statusNode.textContent = message;
  statusNode.className = `status ${kind}`.trim();
}
async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      ...(options.headers || {}),
      Authorization: `Bearer ${adminToken}`,
      ...(options.body ? { 'Content-Type': 'application/json' } : {})
    }
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.message || data.error || `HTTP ${response.status}`);
  return data;
}
function safeText(value) {
  return String(value ?? '—');
}
function dateTime(value) {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString('pt-BR');
}
function cell(text, className = '') {
  const td = document.createElement('td');
  td.textContent = text;
  if (className) td.className = className;
  return td;
}
function showAlerts(alerts) {
  const tbody = document.querySelector('#alerts');
  tbody.replaceChildren();
  if (!alerts.length) {
    const tr = document.createElement('tr');
    const td = cell('Nenhum alerta armazenado até agora.');
    td.colSpan = 5; td.className = 'empty'; tr.append(td); tbody.append(tr); return;
  }
  for (const alert of alerts) {
    const tr = document.createElement('tr');
    const risk = cell(`${alert.riskLevel || alert.severity || 'unknown'} · ${alert.riskScore ?? '—'}`, `risk ${alert.riskLevel || alert.severity || ''}`);
    const target = document.createElement('td');
    const title = document.createElement('div'); title.textContent = safeText(alert.title || alert.ruleId);
    const sub = document.createElement('div'); sub.className = 'target'; sub.textContent = safeText(alert.subject || alert.ip || alert.route);
    target.append(title, sub);
    tr.append(risk, target, cell(safeText(alert.eventCount)), cell(safeText(alert.status), 'state'));
    const actionCell = document.createElement('td');
    const select = document.createElement('select');
    select.className = 'action';
    for (const optionValue of ['open', 'investigating', 'resolved']) {
      const option = document.createElement('option'); option.value = optionValue; option.textContent = optionValue;
      option.selected = optionValue === alert.status; select.append(option);
    }
    select.addEventListener('change', async () => {
      select.disabled = true;
      try {
        await api(`/internal/security/alerts/${encodeURIComponent(alert.id)}`, {
          method: 'PATCH', body: JSON.stringify({ status: select.value })
        });
        status(`Status do alerta atualizado: ${select.value}.`, 'ok');
        await loadDashboard();
      } catch (error) { status(`Falha ao atualizar alerta: ${error.message}`, 'error'); select.disabled = false; }
    });
    actionCell.append(select); tr.append(actionCell); tbody.append(tr);
  }
}
function showEvents(events) {
  const container = document.querySelector('#events');
  container.replaceChildren();
  if (!events.length) {
    const empty = document.createElement('p'); empty.className = 'empty'; empty.textContent = 'Nenhum evento armazenado.';
    container.append(empty); return;
  }
  for (const event of events) {
    const item = document.createElement('div'); item.className = 'event';
    const top = document.createElement('div'); top.className = 'event-top';
    const type = document.createElement('span'); type.className = 'event-type'; type.textContent = safeText(event.type);
    const time = document.createElement('span'); time.className = 'event-time'; time.textContent = dateTime(event.timestamp);
    const detail = document.createElement('div'); detail.className = 'event-detail';
    detail.textContent = [event.route, event.ip, event.subject, event.metadata?.reason].filter(Boolean).join(' · ') || 'Sem detalhes adicionais';
    top.append(type, time); item.append(top, detail); container.append(item);
  }
}
async function loadDashboard() {
  if (!adminToken) { status('Informe o token administrativo para conectar.'); return; }
  refreshButton.disabled = true;
  try {
    const [stats, alertsResult, eventsResult] = await Promise.all([
      api('/internal/security/stats'),
      api('/internal/security/alerts?limit=100'),
      api('/internal/security/events?limit=20')
    ]);
    document.querySelector('#event-count').textContent = stats.storedEvents ?? 0;
    document.querySelector('#alert-count').textContent = stats.storedAlerts ?? 0;
    document.querySelector('#open-count').textContent = stats.openAlerts ?? 0;
    document.querySelector('#critical-note').textContent = `Críticos abertos: ${stats.criticalAlerts ?? 0}`;
    showAlerts(alertsResult.alerts || []);
    showEvents(eventsResult.events || []);
    status('Conectado. Telemetria administrativa carregada.', 'ok');
  } catch (error) {
    status(`Não foi possível carregar os dados: ${error.message}`, 'error');
  } finally { refreshButton.disabled = false; }
}
connectButton.addEventListener('click', async () => {
  adminToken = tokenInput.value.trim();
  await loadDashboard();
});
refreshButton.addEventListener('click', loadDashboard);
tokenInput.addEventListener('keydown', (event) => {
  if (event.key === 'Enter') connectButton.click();
});

async function loadPolicies() {
  const result = await api('/internal/policies');
  document.querySelector('#policy-json').textContent = JSON.stringify(result.policies, null, 2);
  document.querySelector('#policy-editor').value = JSON.stringify(result.policies, null, 2);
}
document.querySelector('#load-policies').addEventListener('click', async () => {
  try { await loadPolicies(); status('Políticas carregadas.', 'ok'); }
  catch (error) { status(`Falha ao carregar políticas: ${error.message}`, 'error'); }
});
document.querySelector('#save-policies').addEventListener('click', async () => {
  let policies;
  try { policies = JSON.parse(document.querySelector('#policy-editor').value); }
  catch { status('JSON inválido. Revise a sintaxe antes de salvar.', 'error'); return; }
  try {
    const result = await api('/internal/policies', { method: 'PUT', body: JSON.stringify({ policies }) });
    document.querySelector('#policy-json').textContent = JSON.stringify(result.policies, null, 2);
    status('Políticas validadas e salvas.', 'ok');
  } catch (error) { status(`Não foi possível salvar políticas: ${error.message}`, 'error'); }
});
document.querySelector('#block-button').addEventListener('click', async () => {
  const ip = document.querySelector('#block-ip').value.trim();
  const ttlSeconds = Number.parseInt(document.querySelector('#block-ttl').value, 10);
  if (!ip) { status('Informe um IP para bloquear.', 'error'); return; }
  try {
    const result = await api('/internal/policies/blocks', { method: 'POST', body: JSON.stringify({ ip, ttlSeconds, reason: 'manual_dashboard_block' }) });
    status(`Bloqueio aplicado para ${result.block.ip} por ${result.block.ttlSeconds}s.`, 'ok');
  } catch (error) { status(`Falha ao bloquear IP: ${error.message}`, 'error'); }
});
document.querySelector('#unblock-button').addEventListener('click', async () => {
  const ip = document.querySelector('#unblock-ip').value.trim();
  if (!ip) { status('Informe o IP a desbloquear.', 'error'); return; }
  try {
    const result = await api(`/internal/policies/blocks/${encodeURIComponent(ip)}`, { method: 'DELETE' });
    status(result.removed ? `Bloqueio removido para ${ip}.` : `Não havia bloqueio ativo para ${ip}.`, 'ok');
  } catch (error) { status(`Falha ao remover bloqueio: ${error.message}`, 'error'); }
});
