/* ==========================================================================
   Rules × case — every rule run over one case's events (Timeline → Rules).
   Answers three questions: what did my rules catch here, what in this case
   looks suspicious but no rule caught (the blind spots, each one a draft rule
   away), and which rules fire on so much of this case that they are noise.
   Runs in small steps so the page stays responsive; the result is kept until
   the case's evidence or the rules change.
   ========================================================================== */
const CR = {sig:'', run:null, res:null};
const crSig = caseId => caseId + ':' + rev + ':' + DB.rules.length + ':' + DB.rules.reduce((m, r) => Math.max(m, r.updated || r.created || 0), 0);
/* why an event looks worth a rule: what the evidence reader recognises, technique IDs, attack-stage tags, a malicious verdict */
function crWhy(r){
  const why = [];
  try{ for(const o of E.observations(r)) if(o && o.t) why.push(o.t); }catch(e){}
  for(const e of r.ents || []){ if(e.k === 'ttp') why.push(e.v.toUpperCase()); else if(verdictOf(e.k + ':' + e.v) === 'malicious') why.push(e.v + ' is marked malicious'); }
  if(typeof CH_TAGS !== 'undefined') for(const tg of r.tags || []){ if(CH_TAGS.some(([re]) => re.test(String(tg).toLowerCase()))) why.push('tagged “' + tg + '”'); }
  return [...new Set(why)].slice(0, 4);
}
async function crRun(c){
  const sig = crSig(c.id); if(CR.run && CR.run.sig === sig) return; const me = {sig, done:0, total:DB.rules.length}; CR.run = me;
  const recs = DB.records.filter(r => r.caseId === c.id && r.type !== 'lead'), F = new Map(), field = r => { let f = F.get(r.id); if(!f){ f = recFields(r); F.set(r.id, f); } return f; };
  const yaraOk = recs.length <= 2000, rows = [], caught = new Map(); let errs = 0;
  for(let i = 0; i < DB.rules.length; i++){
    if(CR.run !== me) return;                                                     // a newer run took over
    const r = DB.rules[i]; let hits = [];
    try{ if(r.type === 'sigma'){ const p = sigmaParse(r.code); if(p.cond && Object.keys(p.det).length) hits = recs.filter(x => { try{ return sigmaEval(p, field(x)); }catch(e){ return false; } }); }
      else if(yaraOk && typeof yaraScan === 'function'){ for(const x of recs){ const res = yaraScan(r.code, new TextEncoder().encode(x.title + '\n' + x.body)); if(res.some(z => z.error)) break; if(res.some(z => z.match)) hits.push(x); } } }
    catch(e){ errs++; }
    if(hits.length){ rows.push({r, hits}); for(const h of hits){ if(!caught.has(h.id)) caught.set(h.id, []); caught.get(h.id).push(r); } }
    if(i % 20 === 19){ me.done = i + 1; crPaint(); await new Promise(res => setTimeout(res, 0)); }
  }
  const SEV = {critical:4, high:3, medium:2, low:1, informational:0};
  rows.sort((a, b) => (SEV[b.r.severity] || 0) - (SEV[a.r.severity] || 0) || b.hits.length - a.hits.length);
  const noisy = rows.filter(x => x.hits.length >= 5 && x.hits.length / Math.max(1, recs.length) > 0.2);
  const blind = recs.filter(r => !caught.has(r.id)).map(r => ({r, why:crWhy(r)})).filter(x => x.why.length).sort((a, b) => (a.r.ts || 9e15) - (b.r.ts || 9e15));
  CR.sig = sig; CR.res = {caseId:c.id, at:Date.now(), n:recs.length, rows, caught, noisy, blind, errs, yaraSkipped:!yaraOk && DB.rules.some(r => r.type === 'yara')}; CR.run = null;
  if(UI.route.area === 'case' && UI.tlMode === 'rules') renderMain();
}
function crPaint(){ const el = document.getElementById('crProg'); if(el && CR.run){ const p = Math.round(CR.run.done / Math.max(1, CR.run.total) * 100); el.setAttribute('aria-valuenow', p); el.firstElementChild.style.width = p + '%'; const t = document.getElementById('crProgT'); if(t) t.textContent = `Running ${CR.run.done} of ${CR.run.total} rules…`; } }
function caseRulesView(c){
  if(CR.sig !== crSig(c.id) || !CR.res || CR.res.caseId !== c.id){
    setTimeout(() => crRun(c), 0);
    const R = CR.run || {done:0, total:DB.rules.length};
    return `<div class="page wide"><section class="card"><div class="body"><p id="crProgT">Running ${R.done} of ${R.total} rules…</p><div class="lk-prog" id="crProg" role="progressbar" aria-label="Running rules over this case" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0"><i style="width:0%"></i></div></div></section></div>`;
  }
  const X = CR.res, f = UI.crf || 'caught', pct = X.n ? Math.round(X.caught.size / X.n * 100) : 0, tm = r => r.ts ? esc(E.fmtClock(r.ts, tz())) : '—';
  if(!X.n) return `<div class="page wide">${empty('shield-check', 'No events in this case yet', 'Add evidence or import a log, then come back to see what your rules catch.')}</div>`;
  const tab = (k, l, n) => `<button data-act="crf" data-v="${k}" aria-pressed="${f === k}">${l} <b>${n}</b></button>`;
  const ev = (r, extra) => `<li><button class="cr-ev" data-act="tlxRec" data-id="${r.id}"><span class="mono t3">${tm(r)}${r.host ? ' · ' + esc(r.host) : ''}</span><b>${esc(r.title)}</b>${extra || ''}</button></li>`;
  let body = '';
  if(f === 'caught') body = X.rows.length ? `<div class="cr-l">${X.rows.map((x, i) => `<details class="cr-r"${i < 3 ? ' open' : ''}><summary><span class="pill" style="--c:${RTYPE[x.r.type][2]}">${RTYPE[x.r.type][0]}</span>${(([sl, sc]) => `<span class="sevt" style="--c:${sc}">${sl}</span>`)(sevOf(x.r.severity))}<b>${esc(x.r.title)}</b>
      <span class="t3">${x.hits.length} event${x.hits.length > 1 ? 's' : ''} · ${tm(x.hits.slice().sort((a, b) => (a.ts || 9e15) - (b.ts || 9e15))[0])}</span>${X.noisy.includes(x) ? '<span class="chip amber sq">noisy here</span>' : ''}</summary>
      <div class="cr-rb"><button class="btn xs ghost" data-act="crRule" data-id="${esc(x.r.id)}">${ico('shield-check','sm')}Open rule</button></div><ul>${x.hits.slice(0, 12).map(r => ev(r)).join('')}</ul>${x.hits.length > 12 ? `<p class="t3 small">and ${x.hits.length - 12} more</p>` : ''}</details>`).join('')}</div>`
    : `<p class="t2">No rule fires on this case's ${X.n} events.${X.blind.length ? ' See <b>Not caught</b> for what looks suspicious.' : ''}</p>`;
  else if(f === 'blind') body = X.blind.length ? `<p class="t2" style="margin:0 0 10px">These events look suspicious — the evidence reader, a technique ID, a tag or a verdict says so — but none of your ${DB.rules.length} rules fires on them. Each one can start a draft rule.</p>
      <ul class="cr-bl">${X.blind.slice(0, 200).map(x => `<li><div><span class="mono t3">${tm(x.r)}${x.r.host ? ' · ' + esc(x.r.host) : ''}</span><button class="cr-t" data-act="tlxRec" data-id="${x.r.id}">${esc(x.r.title)}</button><small>${esc(x.why.join(' · '))}</small></div><button class="btn xs" data-act="crDraft" data-id="${x.r.id}">${ico('file-plus','sm')}Draft a rule</button></li>`).join('')}</ul>${X.blind.length > 200 ? `<p class="t3 small">and ${X.blind.length - 200} more</p>` : ''}`
    : `<p class="t2">Every event that looks suspicious in this case is caught by at least one rule.</p>`;
  else body = X.noisy.length ? `<p class="t2" style="margin:0 0 10px">These rules fire on more than a fifth of this case's events — likely too broad for it. Health in Detections suggests tuning for each.</p><ul class="cr-bl">${X.noisy.map(x => `<li><div><b>${esc(x.r.title)}</b><small>${x.hits.length} of ${X.n} events (${Math.round(x.hits.length / X.n * 100)}%)</small></div><button class="btn xs" data-act="crRule" data-id="${esc(x.r.id)}">Open rule</button></li>`).join('')}</ul>`
    : `<p class="t2">No rule fires on more than a fifth of this case.</p>`;
  return `<div class="page wide cr"><section class="card cr-sum"><div class="tlx-kpi"><div><b>${X.rows.length}</b><span>rules fired</span></div><div><b>${pct}%</b><span>of ${X.n} events caught</span></div>
      <div class="${X.blind.length ? 'r' : ''}"><b>${X.blind.length}</b><span>suspicious, not caught</span></div><div class="${X.noisy.length ? 'a' : ''}"><b>${X.noisy.length}</b><span>noisy here</span></div></div>
      <p class="t3 small" style="margin:8px 0 0">${DB.rules.length} rules run ${esc(iAgo(X.at))}${X.yaraSkipped ? ' · YARA skipped (over 2,000 events)' : ''}${X.errs ? ' · ' + X.errs + ' rule' + (X.errs > 1 ? 's' : '') + ' could not run' : ''}. Runs again by itself when the evidence or the rules change.</p></section>
    <div class="toolbar"><div class="seg" role="group" aria-label="Show">${tab('caught', 'Caught', X.rows.length)}${tab('blind', 'Not caught', X.blind.length)}${tab('noisy', 'Noisy here', X.noisy.length)}</div></div>
    ${body}</div>`;
}
const CR_ACTS = {
  crf:(id, v) => { UI.crf = v; renderMain(); },
  crRule:id => { UI.dview = 'rules'; UI.rule = id; UI.ropen = true; UI.rtab = 'rule'; go('#/detections'); },
  crDraft:id => { UI.evPick = new Set([id]); dlDraftFromPick(); },
};
