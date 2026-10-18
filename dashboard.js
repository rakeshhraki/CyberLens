document.addEventListener("DOMContentLoaded", () => {
  const d = new Date();
  const date = document.getElementById("current-date");
  if (date) date.textContent = d.toLocaleDateString(undefined,{weekday:"long",day:"2-digit",month:"short",year:"numeric"});
  loadDashboard();
});

async function loadDashboard(){
 try{
  const response=await fetch('/api/dashboard-stats');
  const result=await response.json();
  if(!response.ok || !result.success) throw new Error(result.error || 'Unable to load dashboard');
  const data=result.data||{};
  updateStatistics(data);
  updateRecentInvestigations(data.recent||[]);
  updateActivity(data.recent||[], data);
 }catch(error){
  console.error(error);
  document.getElementById('investigations-table').innerHTML='<tr><td colspan="5"><div class="empty-message">Unable to load investigations.</div></td></tr>';
  document.getElementById('activity-overview').innerHTML='<div class="empty-message">Unable to load activity.</div>';
 }
}
function updateStatistics(data){
 const set=(id,v)=>{const e=document.getElementById(id); if(e)e.textContent=v??0;};
 set('stat-files-analyzed',data.total); set('stat-high-risk',data.high); set('stat-critical',data.critical); set('risk-low',data.low); set('risk-medium',data.medium); set('risk-high',data.high); set('risk-critical',data.critical); set('risk-total',data.total);
 const recent=data.recent||[]; const avg=recent.length?Math.round(recent.reduce((s,a)=>s+(Number(a.risk_score)||0),0)/recent.length):0; set('stat-avg-risk',avg);
 const total=Number(data.total)||0; const values=[Number(data.low)||0,Number(data.medium)||0,Number(data.high)||0,Number(data.critical)||0];
 const pct=(v)=>total?Math.round((v/total)*100)+'%':'0%';
 [['risk-low-pct',values[0]],['risk-medium-pct',values[1]],['risk-high-pct',values[2]],['risk-critical-pct',values[3]]].forEach(([id,v])=>set(id,pct(v)));
 let angle=0; const stops=[]; values.forEach((v,i)=>{const next=angle+(total?v/total*360:0); const color=['#4F6F52','#B8860B','#D65A31','#9E2A2B'][i]; stops.push(`${color} ${angle}deg ${next}deg`); angle=next;});
 const donut=document.getElementById('risk-donut'); if(donut) donut.style.background=total?`conic-gradient(${stops.join(',')})`:'conic-gradient(#d8d0c3 0 360deg)';
}
function updateRecentInvestigations(items){
 const table=document.getElementById('investigations-table');
 if(!items.length){table.innerHTML='<tr><td colspan="5"><div class="empty-message"><strong>No investigations yet.</strong><span>Start by analyzing a file.</span></div></td></tr>';return;}
 table.innerHTML=items.slice(0,7).map(a=>{const level=String(a.severity||'LOW').toLowerCase(); const type=a.file_type||'Unknown'; return `<tr class="click-row" onclick="window.location='/result/${Number(a.id)}'"><td><div class="file-cell"><span class="file-symbol">${fileGlyph(type)}</span><span><strong>${escapeHtml(a.filename||'Unknown')}</strong><small>#${Number(a.id)}</small></span></div></td><td>${escapeHtml(type)}</td><td><strong class="risk-number risk-${level}">${Number(a.risk_score)||0}</strong></td><td><span class="severity-badge severity-${level}">${escapeHtml(a.severity||'LOW')}</span></td><td>${formatDate(a.created_at)}</td></tr>`}).join('');
}
function updateActivity(items,data){
 const el=document.getElementById('activity-overview');
 if(!items.length){el.innerHTML='<div class="empty-message"><strong>No analysis activity yet.</strong><span>Upload a file to begin.</span></div>';return;}
 el.innerHTML=items.slice(0,4).map(a=>{const level=String(a.severity||'LOW').toLowerCase(); return `<div class="activity-item"><i class="risk-dot ${level}"></i><div><strong>${escapeHtml(a.filename||'Unknown')}</strong><span>Analysis completed · <b>${escapeHtml(a.severity||'LOW')}</b></span></div><time>${shortDate(a.created_at)}</time></div>`}).join('');
}
function fileGlyph(type){const t=String(type).toLowerCase(); if(t.includes('image'))return 'IMG'; if(t.includes('pdf'))return 'PDF'; if(t.includes('doc'))return 'DOC'; if(t.includes('text'))return 'TXT'; if(t.includes('pe')||t.includes('exe'))return 'PE'; return 'FILE';}
function formatDate(v){if(!v)return 'N/A';const d=new Date(v);return Number.isNaN(d.getTime())?'N/A':d.toLocaleDateString(undefined,{day:'2-digit',month:'short',year:'numeric'});}
function shortDate(v){if(!v)return '';const d=new Date(v);return Number.isNaN(d.getTime())?'':d.toLocaleTimeString(undefined,{hour:'2-digit',minute:'2-digit'});}
function escapeHtml(v){return String(v??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;');}
