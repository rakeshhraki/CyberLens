document.addEventListener('DOMContentLoaded', () => {
  setCurrentDate();
  setupGlobalSearch();
  loadDashboard();
});

function setCurrentDate() {
  const date = document.getElementById('current-date');
  const sidebarDate = document.getElementById('sidebar-updated');
  const now = new Date();
  const value = now.toLocaleDateString(undefined, { weekday:'long', day:'2-digit', month:'short', year:'numeric' });
  if (date) date.textContent = value;
  if (sidebarDate) sidebarDate.textContent = now.toLocaleDateString(undefined, { day:'2-digit', month:'short', year:'numeric' });
}

async function loadDashboard() {
  try {
    const response = await fetch('/api/dashboard-stats', { headers: { Accept:'application/json' } });
    const result = await response.json();
    if (!response.ok || !result.success) throw new Error(result.error || 'Unable to load dashboard');
    const data = result.data || {};
    updateStatistics(data);
    updateRecentInvestigations(data.recent || []);
    updateRiskDistribution(data);
    updateActivity(data.recent || []);
  } catch (error) {
    console.error('Dashboard loading error:', error);
    const table = document.getElementById('investigations-table');
    const activity = document.getElementById('activity-list');
    if (table) table.innerHTML = '<tr><td colspan="5"><div class="empty-message"><strong>Unable to load investigations.</strong><span>Check the application server.</span></div></td></tr>';
    if (activity) activity.innerHTML = '<div class="empty-message"><strong>Unable to load activity.</strong></div>';
  }
}

function updateStatistics(data) {
  setText('stat-files-analyzed', data.total ?? 0);
  setText('stat-high-risk', data.high ?? 0);
  setText('stat-critical', data.critical ?? 0);
  setText('stat-avg-risk', data.average_risk ?? 0);
}

function updateRiskDistribution(data) {
  const total = Number(data.total || 0);
  const dist = data.risk_distribution || {};
  const critical = Number(dist.critical || 0);
  const high = Number(dist.high || 0);
  const medium = Number(dist.medium || 0);
  const low = Number(dist.low || 0);

  setText('risk-total', total);
  setText('risk-critical', critical); setText('risk-high', high);
  setText('risk-medium', medium); setText('risk-low', low);
  setText('risk-critical-pct', pct(critical, total));
  setText('risk-high-pct', pct(high, total));
  setText('risk-medium-pct', pct(medium, total));
  setText('risk-low-pct', pct(low, total));
  setText('risk-total-label', 'All investigations');

  const values = [critical, high, medium, low];
  const colors = ['#9E2A2B', '#D65A31', '#B8860B', '#4F6F52'];
  let cursor = 0;
  const stops = [];
  values.forEach((value, index) => {
    const next = total ? cursor + (value / total) * 100 : cursor;
    stops.push(`${colors[index]} ${cursor}% ${next}%`);
    cursor = next;
  });
  const donut = document.getElementById('risk-donut');
  if (donut) donut.style.background = total ? `conic-gradient(${stops.join(',')})` : '#e9e3d9';
}

function updateRecentInvestigations(items) {
  const table = document.getElementById('investigations-table');
  if (!table) return;
  if (!items.length) {
    table.innerHTML = '<tr><td colspan="5"><div class="empty-message"><strong>No investigations yet.</strong><span>Start by analyzing a file.</span></div></td></tr>';
    return;
  }
  table.innerHTML = items.slice(0, 7).map(item => {
    const severity = String(item.severity || 'LOW').toLowerCase();
    const type = item.file_type || 'Unknown';
    return `<tr class="click-row" onclick="window.location='/result/${Number(item.id)}'">
      <td><div class="file-cell"><span class="file-symbol">${fileGlyph(type)}</span><span><strong>${escapeHtml(item.filename || 'Unknown')}</strong><small>#${Number(item.id)}</small></span></div></td>
      <td>${escapeHtml(type)}</td>
      <td><strong class="risk-number risk-${severity}">${Number(item.risk_score) || 0}</strong></td>
      <td><span class="severity-badge severity-${severity}">${escapeHtml(item.severity || 'LOW')}</span></td>
      <td>${formatDate(item.created_at)}</td>
    </tr>`;
  }).join('');
}

function updateActivity(items) {
  const list = document.getElementById('activity-list');
  if (!list) return;
  if (!items.length) {
    list.innerHTML = '<div class="empty-message"><strong>No activity yet.</strong><span>Recent analyses will appear here.</span></div>';
    return;
  }
  list.innerHTML = items.slice(0, 5).map(item => {
    const severity = String(item.severity || 'LOW').toLowerCase();
    return `<div class="activity-item"><span class="activity-dot dot-${severity}"></span><div><strong>${escapeHtml(item.filename || 'Unknown')}</strong><span>Analysis completed · <b>${escapeHtml(item.severity || 'LOW')}</b></span></div><time>${formatTime(item.created_at)}</time></div>`;
  }).join('');
}

function setupGlobalSearch() {
  const input = document.querySelector('.topbar-search input');
  if (!input) return;
  document.addEventListener('keydown', event => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
      event.preventDefault(); input.focus();
    }
  });
  input.addEventListener('input', () => {
    const query = input.value.trim().toLowerCase();
    document.querySelectorAll('#investigations-table tr.click-row').forEach(row => {
      row.hidden = query && !row.textContent.toLowerCase().includes(query);
    });
  });
}

function fileGlyph(type) {
  const value = String(type).toLowerCase();
  if (value.includes('image')) return 'IMG';
  if (value.includes('pdf')) return 'PDF';
  if (value.includes('doc')) return 'DOC';
  if (value.includes('text')) return 'TXT';
  if (value.includes('pe') || value.includes('exe') || value.includes('executable')) return 'PE';
  return 'FILE';
}
function pct(value, total) { return total ? `${Math.round((value / total) * 100)}%` : '0%'; }
function formatDate(value) { const d = new Date(value); return Number.isNaN(d.getTime()) ? 'N/A' : d.toLocaleDateString(undefined,{day:'2-digit',month:'short',year:'numeric'}); }
function formatTime(value) { const d = new Date(value); return Number.isNaN(d.getTime()) ? 'N/A' : d.toLocaleTimeString(undefined,{hour:'numeric',minute:'2-digit'}); }
function setText(id,value){ const el=document.getElementById(id); if(el) el.textContent=value; }
function escapeHtml(value){ return String(value ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;'); }
