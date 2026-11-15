/* ==========================================================================
   Today — what needs you now, across every case, most urgent first.
   Built from the workspace itself: watch alerts, notes and to-dos that are
   due, indicators flagged by a lookup or your indicator store but not yet
   judged, what arrived in cases since you last opened them, open questions,
   cases that have gone quiet, and a backup that is due.
   The demo cases are left out once you have cases of your own.
   ========================================================================== */
function todayItems(){
  const out = [], now = Date.now(), today = new Date().toISOString().slice(0, 10);
  const own = DB.cases.filter(c => !c.sample), cases = (own.length ? own : DB.cases).filter(c => c.status !== 'closed'), ids = new Set(cases.map(c => c.id));
  const add = (lvl, ic, t, d, act) => out.push({lvl, ic, t, d, act});
  /* watch alerts */
  const W = DB.watch || {}, un = Object.keys(W).filter(k => W[k].unseen);
  if(un.length) add(3, 'eye', `${un.length} watched indicator${un.length > 1 ? 's' : ''} changed`, un.slice(0, 4).map(k => entSplit(k).v).join(' · '), {go:'#/watch', l:'Open the watchlist'});
  /* backup */
  if(typeof backupDue === 'function'){ const B = backupDue(); if(B.due) add(B.folder === 'paused' || B.days > 13 ? 3 : 2, 'hard-drive-download', B.folder === 'paused' ? 'Folder backup is paused' : B.last ? `Last backup ${B.days} days ago` : 'Nothing backed up yet', `${B.own} records, entries and notes live only in this browser.`, {act:'exportAll', l:'Back up now'}); }
  /* notes */
  for(const n of DB.notes || []){ if(!n.due || (n.caseId && !ids.has(n.caseId) && own.length)) continue; const open = noteTasks(n).filter(t => !t.done); if(n.due > today || (noteTasks(n).length && !open.length)) continue;
    const late = n.due < today, c = n.caseId ? theCase(n.caseId) : null;
    add(late ? 3 : 2, 'calendar-clock', `${late ? 'Overdue since ' + n.due : 'Due today'}: ${n.text.split('\n')[0].slice(0, 80)}`, (c ? c.code + ' · ' : '') + (open.length ? open.length + ' to-do' + (open.length > 1 ? 's' : '') + ' left: ' + open.slice(0, 2).map(t => t.t).join(' · ') : ''), {act:'nEdit', id:n.id, l:'Open the note'}); }
  /* indicators flagged but not judged */
  const keysIn = new Map(); for(const c of cases){ for(const k of derive(c.id).ents.keys()) if(!keysIn.has(k)) keysIn.set(k, c); }
  const looked = ((DB.intel && DB.intel.lookHist) || []).filter(h => /mal|susp/.test(h.band || '') && keysIn.has(h.k + ':' + h.v) && !verdictOf(h.k + ':' + h.v));
  if(looked.length) add(3, 'radar', `${looked.length} indicator${looked.length > 1 ? 's' : ''} a lookup flagged, with no verdict from you`, looked.slice(0, 3).map(h => `${h.v} (${h.band} ${h.score ?? ''})`).join(' · '), {act:'selEnt', id:looked[0].k + ':' + looked[0].v, caseId:keysIn.get(looked[0].k + ':' + looked[0].v).id, l:'Judge the first'});
  if(typeof ctiIocHits === 'function' && typeof CTI !== 'undefined' && CTI.iocs){ const H = ctiIocHits().filter(h => keysIn.has(h.ioc.k + ':' + h.ioc.v) && !verdictOf(h.ioc.k + ':' + h.ioc.v));
    if(H.length) add(2, 'fingerprint', `${H.length} indicator${H.length > 1 ? 's' : ''} in your cases match the indicator store`, H.slice(0, 3).map(h => h.ioc.v + (h.ioc.threat ? ' — ' + h.ioc.threat : '')).join(' · '), {go:'#/feeds', itab:'iocs', l:'See them'}); }
  /* what arrived while a case was closed */
  if(typeof caseActivity === 'function'){ const S = DB.prefs.seen || {}; for(const c of cases){ if(!S[c.id] || c.id === SEEN.open) continue; const L = caseActivity(c, S[c.id]); if(!L.length) continue;
    add(L.some(x => x.tone === 'red') ? 2 : 1, 'history', `${c.code}: ${L.length} thing${L.length > 1 ? 's' : ''} since you last looked`, L.slice(0, 3).map(x => x.t).join(' · '), {go:caseHash(c.id, 'overview'), l:'Open the case'}); } }
  /* open questions, oldest first */
  for(const c of cases){ const Q = DB.records.filter(r => r.caseId === c.id && r.type === 'lead' && !r.answer).sort((a, b) => (a.addedAt || 0) - (b.addedAt || 0)); if(!Q.length) continue;
    const age = Math.floor((now - (Q[0].addedAt || now)) / 864e5);
    add(age > 7 ? 2 : 1, 'circle-help', `${c.code}: ${Q.length} open question${Q.length > 1 ? 's' : ''}`, `Oldest${age ? ' (' + age + ' day' + (age > 1 ? 's' : '') + ')' : ''}: ${Q[0].title}`, {go:caseHash(c.id, 'analysis'), l:'Answer them'}); }
  /* cases gone quiet */
  for(const c of cases){ if(c.status !== 'active') continue; const last = Math.max(c.updated || 0, c.created || 0, ...DB.records.filter(r => r.caseId === c.id).map(r => r.addedAt || 0), ...DB.entries.filter(e => e.caseId === c.id).map(e => e.created || 0), ...(DB.notes || []).filter(n => n.caseId === c.id).map(n => n.updated || 0));
    const days = Math.floor((now - last) / 864e5); if(days >= 7) add(1, 'hourglass', `${c.code} has been quiet for ${days} days`, c.name.split(' — ')[0] + ' is still marked active. Close it, or pick it back up.', {go:caseHash(c.id, 'overview'), l:'Open the case'}); }
  return {items:out.sort((a, b) => b.lvl - a.lvl), demo:!own.length};
}
function viewToday(){
  const T = todayItems(), G = [[3, 'Now'], [2, 'Today'], [1, 'When you can']];
  const btn = a => a.act ? `<button class="btn sm" data-act="tdGo" data-v="${esc(JSON.stringify(a))}">${esc(a.l)}</button>` : `<a class="btn sm" href="${esc(a.go)}"${a.itab ? ` data-act="tdTab" data-v="${esc(a.itab)}"` : ''}>${esc(a.l)}</a>`;
  return `<div class="scroll"><div class="page">
    <div class="ph"><div><h1>Today</h1><div class="sub">${new Date().toLocaleDateString('en-GB', {weekday:'long', day:'numeric', month:'long'})} · ${T.items.length ? T.items.length + ' thing' + (T.items.length > 1 ? 's' : '') + ' waiting across your cases' : 'nothing waiting'}${T.demo ? ' · from the demo cases until you open your own' : ''}</div></div></div>
    ${T.items.length ? G.map(([l, name]) => { const L = T.items.filter(x => x.lvl === l); return L.length ? `<h2 class="td-h">${name} <span class="t3">${L.length}</span></h2><ul class="td-l card">${L.map(x => `<li><span class="td-i l${l}">${ico(x.ic,'sm')}</span><div><b>${esc(x.t)}</b>${x.d ? `<small>${esc(x.d)}</small>` : ''}</div>${btn(x.act)}</li>`).join('')}</ul>` : ''; }).join('')
      : empty('check', 'Nothing waiting', 'No alerts, nothing due, no unjudged hits and no open questions. Good time to back up, or to pick a case and dig deeper.')}
  </div></div>`;
}
const todayCount = () => { try{ return todayItems().items.filter(x => x.lvl >= 2).length || null; }catch(e){ return null; } };
const TD_ACTS = {
  tdGo:(id, v) => { let a; try{ a = JSON.parse(v); }catch(e){ return; } if(a.caseId) DB.active = a.caseId; if(a.caseId) go(caseHash(a.caseId, 'entities')); setTimeout(() => clickAct(a.act, a.id || ''), a.caseId ? 120 : 0); },
  tdTab:(id, v) => { UI.itab = v; },
};
