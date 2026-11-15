/* ==========================================================================
   Since you were last here — what changed in a case while it was closed.
   When you open a case, the time you last had it open is remembered; the
   Overview then lists what arrived since: evidence and entries (yours and
   the automations'), lookups that came back, indicator-store and news matches
   on this case's indicators, the same indicators turning up in other cases,
   and notes that fell due. Built from the workspace itself; nothing is sent.
   ========================================================================== */
const SEEN = {open:null};
/* called on every route change: entering a case remembers when it was last open */
function seenRoute(){
  const id = UI.route.area === 'case' ? DB.active : null; if(id === SEEN.open) return;
  const S = DB.prefs.seen = DB.prefs.seen && typeof DB.prefs.seen === 'object' ? DB.prefs.seen : {};
  if(SEEN.open) S[SEEN.open] = Date.now();   // leaving a case
  if(id){ UI.since = {id, at:S[id] || 0}; S[id] = Date.now(); }
  SEEN.open = id; save();
}
addEventListener('pagehide', () => { if(SEEN.open && DB.prefs.seen){ DB.prefs.seen[SEEN.open] = Date.now(); save(); } });
function caseActivity(c, since){
  const D = derive(c.id), keys = new Set(D.ents.keys()), out = [];
  if(!since) return out;
  const recs = D.recs.filter(r => (r.addedAt || 0) > since), mine = recs.filter(r => !r.addedBy || r.addedBy === 'You'), auto = recs.filter(r => r.addedBy && r.addedBy !== 'You');
  if(auto.length) out.push({ic:'wand-sparkles', tone:'accent', t:`${auto.length} event${auto.length > 1 ? 's' : ''} added by ${[...new Set(auto.map(r => r.addedBy))].slice(0, 2).join(' and ')}`, d:auto.slice(0, 3).map(r => r.title).join(' · '), act:['tlFrom', String(since), 'Show them']});
  if(mine.length) out.push({ic:'file-plus', t:`${mine.length} event${mine.length > 1 ? 's' : ''} you added`, d:mine.slice(0, 3).map(r => r.title).join(' · '), act:['tlFrom', String(since), 'Show them']});
  const ents = D.entries.filter(e => (e.created || 0) > since);
  if(ents.length) out.push({ic:'layers', t:`${ents.length} new vault entr${ents.length > 1 ? 'ies' : 'y'}`, d:ents.slice(0, 4).map(primary).join(' · '), go:caseHash(c.id, 'vault')});
  const look = ((DB.intel && DB.intel.lookHist) || []).filter(h => h.at > since && keys.has(h.k + ':' + h.v));
  const badLook = look.filter(h => /mal|susp/.test(h.band || ''));
  if(look.length) out.push({ic:'radar', tone:badLook.length ? 'red' : '', t:`${look.length} lookup${look.length > 1 ? 's' : ''} came back${badLook.length ? ` — ${badLook.length} flagged` : ''}`, d:look.slice(0, 4).map(h => `${h.v} (${h.band || 'unknown'})`).join(' · '), go:caseHash(c.id, 'entities')});
  if(typeof CTI !== 'undefined' && CTI.iocs){ const hit = CTI.iocs.filter(x => (x.added || 0) > since && keys.has(x.k + ':' + x.v));
    if(hit.length) out.push({ic:'fingerprint', tone:'red', t:`${hit.length} of this case's indicator${hit.length > 1 ? 's' : ''} now in your indicator store`, d:hit.slice(0, 4).map(x => x.v + (x.threat ? ' — ' + x.threat : '')).join(' · '), go:'#/feeds'}); }
  const news = (DB.feed || []).filter(f => (f.ts || 0) > since).map(f => ({f, k:E.extract(f.title + ' ' + f.body).map(entKey).filter(k => keys.has(k))})).filter(x => x.k.length);
  if(news.length) out.push({ic:'rss', tone:'amber', t:`${news.length} news stor${news.length > 1 ? 'ies mention' : 'y mentions'} this case's indicators`, d:news.slice(0, 2).map(x => x.f.title).join(' · '), go:'#/feeds'});
  const elsewhere = new Map(); for(const r of DB.records){ if(r.caseId === c.id || (r.addedAt || 0) <= since) continue; for(const e of r.ents){ const k = entKey(e); if(keys.has(k)){ if(!elsewhere.has(k)) elsewhere.set(k, new Set()); elsewhere.get(k).add(r.caseId); } } }
  if(elsewhere.size){ const L = [...elsewhere].slice(0, 4); out.push({ic:'git-compare-arrows', tone:'amber', t:`${elsewhere.size} of this case's indicator${elsewhere.size > 1 ? 's' : ''} turned up in another case`, d:L.map(([k, cs]) => `${entSplit(k).v} in ${[...cs].map(id => (theCase(id) || {}).code).filter(Boolean).join(', ')}`).join(' · '), go:caseHash(c.id, 'entities')}); }
  const today = new Date().toISOString().slice(0, 10), due = (DB.notes || []).filter(n => n.caseId === c.id && n.due && n.due <= today && !n.done);
  if(due.length) out.push({ic:'calendar-clock', tone:'amber', t:`${due.length} note${due.length > 1 ? 's' : ''} due`, d:due.slice(0, 3).map(n => n.text.split('\n')[0].slice(0, 80)).join(' · '), go:'#/notes'});
  return out;
}
function activityCard(c){
  const S = UI.since && UI.since.id === c.id ? UI.since : null; if(!S || !S.at || S.hide) return '';
  const L = caseActivity(c, S.at); if(!L.length) return '';
  return `<section class="card act-c" aria-label="Since you were last here"><div class="act-h"><span class="tb sm">${ico('history','sm')}</span><h3>Since you were last here <span class="t3">· ${esc(E.fmtAgo(Date.now() - S.at))}</span></h3><button class="iconbtn" data-act="actHide" aria-label="Hide">${ico('x','sm')}</button></div>
    <ul class="act-l">${L.map(x => `<li class="${x.tone || ''}"><span class="act-i">${ico(x.ic,'sm')}</span><div><b>${esc(x.t)}</b>${x.d ? `<small>${esc(x.d)}</small>` : ''}</div>${x.act ? `<button class="btn xs" data-act="${x.act[0]}" data-v="${esc(x.act[1])}">${esc(x.act[2])}</button>` : x.go ? `<a class="btn xs" href="${esc(x.go)}">Open</a>` : ''}</li>`).join('')}</ul></section>`;
}
const ACT_ACTS = {
  actHide:() => { if(UI.since) UI.since.hide = true; renderMain(); },
  tlFrom:(id, v) => { UI.facet.win = {from:+v, to:Date.now() + 864e5 * 3650, at:+v, label:'added since you were last here', added:true}; UI.tlMode = 'events'; go(caseHash(DB.active, 'timeline')); },
};
