/* ==========================================================================
   How far to trust it — the Admiralty grading investigators use.
   · A source (a website, a forum, a leak file, a person, a tool) gets a
     reliability letter A–F once; it applies wherever that source appears.
   · A piece of evidence gets a credibility number 1–6 for the information
     itself. Together: "B2" — a usually reliable source, probably true.
   · What the evidence names (emails, phones, addresses, handles, domains…) is
     checked for corroboration: seen in several INDEPENDENT sources, or resting
     on one — and when that one is rated weak, or the thing is marked
     malicious on the strength of it, it is pointed out.
   Two records from the same source are one source, not two.
   ========================================================================== */
const SR_REL = [['A', 'Completely reliable'], ['B', 'Usually reliable'], ['C', 'Fairly reliable'], ['D', 'Not usually reliable'], ['E', 'Unreliable'], ['F', 'Reliability cannot be judged']];
const SR_CRED = [['1', 'Confirmed by other sources'], ['2', 'Probably true'], ['3', 'Possibly true'], ['4', 'Doubtful'], ['5', 'Improbable'], ['6', 'Truth cannot be judged']];
const SR_SKIP_KINDS = new Set(['ttp', 'eventid', 'cve', 'path', 'regkey', 'sid', 'file', 'custom']);
/* the source of a record, one name per real-world source */
function srcKey(r){
  const s = String(r.source || '').trim(), web = s.match(/^web page\s*·\s*(.+)$/i);
  if(web) return 'web: ' + web[1].toLowerCase().replace(/^www\./, '');
  if(r.source === 'attachment') return 'file: ' + (((r.att || [])[0] || r.big || {}).name || 'unnamed');
  if(/^(import|infra):/i.test(s)) return s.toLowerCase().replace(/^infra:\s*/, 'lookup: ');
  return s ? s.toLowerCase().slice(0, 120) : '';
}
/* ratings are kept for the source, in every case; checked every time they are read */
function srcRel(key){ const R = DB.srcRel && typeof DB.srcRel === 'object' ? DB.srcRel : (DB.srcRel = {}); const x = R[key]; return x && /^[A-F]$/.test(x.rel) ? x.rel : ''; }
function recCred(r){ return /^[1-6]$/.test(r.cred || '') ? r.cred : ''; }
function recGrade(r){ const k = srcKey(r), a = k ? srcRel(k) : '', b = recCred(r); return a || b ? (a || '?') + (b || '?') : ''; }
function srcIndex(caseId){
  const sig = caseId + ':' + rev + ':' + JSON.stringify(DB.srcRel || {}).length; if(SR_C.sig === sig) return SR_C.v;
  const D = derive(caseId), recs = D.recs.filter(r => r.type !== 'lead'), src = new Map();
  for(const r of recs){ const k = srcKey(r) || '(no source written down)'; let s = src.get(k); if(!s){ s = {key:k, recs:[], none:k.startsWith('(')}; src.set(k, s); } s.recs.push(r); }
  /* each thing named in the evidence: in how many independent sources */
  const ents = [];
  for(const e of D.ents.values()){ if(SR_SKIP_KINDS.has(e.k)) continue; const by = new Map(); for(const r of e.recs){ const k = srcKey(r); if(!k) continue; if(!by.has(k)) by.set(k, []); by.get(k).push(r); }
    const vd = verdictOf(e.id) || '', inVault = D.byKey && D.byKey.has(e.id); if(!by.size) continue;
    const rels = [...by.keys()].map(srcRel), weak = rels.every(x => /^[DEF]?$/.test(x) && x !== ''), unrated = rels.some(x => !x);
    ents.push({id:e.id, k:e.k, v:e.v, n:by.size, by, vd, inVault, rels, weak, unrated, matters:!!vd && vd !== 'benign' || inVault}); }
  const several = ents.filter(x => x.n >= 2).sort((a, b) => b.n - a.n || (b.matters ? 1 : 0) - (a.matters ? 1 : 0));
  const one = ents.filter(x => x.n === 1 && x.matters).sort((a, b) => (b.weak ? 1 : 0) - (a.weak ? 1 : 0) || ({malicious:2, suspicious:1}[b.vd] || 0) - ({malicious:2, suspicious:1}[a.vd] || 0));
  const v = {src:[...src.values()].sort((a, b) => b.recs.length - a.recs.length), several, one, ungraded:recs.filter(r => !recCred(r)).length, total:recs.length};
  SR_C.sig = sig; SR_C.v = v; return v;
}
const SR_C = {sig:'', v:null};
const srChip = (rel, title) => rel ? `<span class="sr-g sr-${rel}" title="${esc(title || (SR_REL.find(x => x[0] === rel) || [])[1] || '')}">${esc(rel)}</span>` : `<span class="sr-g sr-u" title="Not rated">?</span>`;
function srcView(c){
  const X = srcIndex(c.id);
  if(!X.total) return empty('badge-check', 'No evidence to grade yet', 'Once evidence is in the case, rate where it came from (A–F) and how believable each piece is (1–6); what is backed by several independent sources shows up here.');
  const sel = s => `<label class="sr">Reliability of ${esc(s.key)}</label><select data-sr="rate" data-v="${esc(s.key)}"${s.none ? ' disabled' : ''}><option value="">Not rated</option>${SR_REL.map(([k, l]) => `<option value="${k}"${srcRel(s.key) === k ? ' selected' : ''}>${k} — ${l}</option>`).join('')}</select>`;
  const thing = x => `<button class="lnk mono" data-act="srEnt" data-id="${esc(x.id)}">${esc(String(x.v).length > 60 ? String(x.v).slice(0, 58) + '…' : x.v)}</button> <span class="t3">${esc(E.LABEL[x.k] || x.k)}</span>${x.vd ? ` <span class="chip sq ${x.vd === 'malicious' ? 'red' : x.vd === 'suspicious' ? 'amber' : ''}">${esc(x.vd)}</span>` : ''}${x.inVault ? ' <span class="chip sq">in the vault</span>' : ''}`;
  const srcs = x => [...x.by.keys()].map(k => `<span class="sr-s">${srChip(srcRel(k))}<span>${esc(k)}</span></span>`).join('');
  return `<p class="t2" style="margin:4px 0 14px;max-width:820px">Rate each source once, A (completely reliable) to F (cannot be judged); it applies in every case. Rate each piece of evidence 1 (confirmed) to 6 (cannot be judged) in its panel. Two records from the same source count as one source.</p>
    <div class="sr-k card"><div class="tlx-kpi"><div><b>${X.src.filter(s => !s.none).length}</b><span>sources</span></div><div><b>${X.src.filter(s => !s.none && srcRel(s.key)).length}</b><span>rated</span></div><div><b>${X.several.length}</b><span>backed by several sources</span></div><div class="${X.one.some(x => x.weak) ? 'r' : ''}"><b>${X.one.length}</b><span>key facts on one source</span></div><div><b>${X.total - X.ungraded} of ${X.total}</b><span>evidence graded</span></div></div></div>
    ${X.one.length ? `<section class="card sr-c"><h3>Resting on one source</h3><p class="t3 small">Things you marked or added to the vault that only one source mentions. A second, independent source would make them stronger${X.one.some(x => x.weak) ? '; the ones from a source rated D, E or F come first' : ''}.</p>
      <ul class="sr-l">${X.one.slice(0, 40).map(x => `<li${x.weak ? ' class="weak"' : ''}><div>${thing(x)}</div><div class="sr-ss">${srcs(x)}${x.weak ? '<span class="t2 small">only a weak source says so</span>' : x.unrated ? '<span class="t3 small">source not rated</span>' : ''}</div></li>`).join('')}</ul></section>` : ''}
    <section class="card sr-c"><h3>Backed by several independent sources</h3>${X.several.length ? `<ul class="sr-l">${X.several.slice(0, 60).map(x => `<li><div>${thing(x)} <span class="chip sq">${x.n} sources</span></div><div class="sr-ss">${srcs(x)}</div></li>`).join('')}</ul>${X.several.length > 60 ? `<p class="t3 small">and ${X.several.length - 60} more</p>` : ''}` : '<p class="t3">Nothing yet appears in more than one source.</p>'}</section>
    <section class="card sr-c"><h3>Sources in this case</h3><div class="if-tw"><table class="sr-t"><thead><tr><th scope="col">Source</th><th scope="col">Evidence</th><th scope="col">Reliability</th><th scope="col">Graded</th></tr></thead><tbody>
      ${X.src.map(s => `<tr><td><span class="${s.none ? 't3' : 'mono'}">${esc(s.key)}</span>${s.none ? '<div class="t3 small">Write a source when you capture, so it can be rated</div>' : ''}</td><td>${s.recs.length}</td><td>${sel(s)}</td><td class="t3">${s.recs.filter(recCred).length} of ${s.recs.length}${s.recs.filter(recCred).length ? ' · ' + [...new Set(s.recs.map(recCred).filter(Boolean))].sort().join(', ') : ''}</td></tr>`).join('')}</tbody></table></div></section>`;
}
/* in the evidence panel: the grade, set where you read it */
function srcRecSection(r){
  if(!r || r.type === 'lead') return ''; const k = srcKey(r), g = recGrade(r);
  return `<div class="isec sr-rec"><h4>How far to trust it ${g ? `<span class="sr-grade" title="Source reliability, then credibility of this information">${esc(g)}</span>` : ''}</h4>
    <div class="sr-row"><label for="srRelR">Source${k ? ` <span class="t3 mono">${esc(k)}</span>` : ''}</label><select id="srRelR" data-sr="rate" data-v="${esc(k)}"${k ? '' : ' disabled title="No source written down for this evidence"'}><option value="">Not rated</option>${SR_REL.map(([x, l]) => `<option value="${x}"${k && srcRel(k) === x ? ' selected' : ''}>${x} — ${l}</option>`).join('')}</select></div>
    <div class="sr-row"><label for="srCredR">This information</label><select id="srCredR" data-sr="cred" data-id="${esc(r.id)}"><option value="">Not graded</option>${SR_CRED.map(([x, l]) => `<option value="${x}"${recCred(r) === x ? ' selected' : ''}>${x} — ${l}</option>`).join('')}</select></div></div>`;
}
/* in an indicator's panel: corroboration */
function srcEntLine(id){
  const g = typeof globalEnts === 'function' ? globalEnts().get(id) : null; if(!g) return ''; const by = new Map(); for(const r of g.recs){ const k = srcKey(r); if(k) by.set(k, srcRel(k)); }
  if(!by.size) return ''; const weak = [...by.values()].every(x => /^[DEF]$/.test(x));
  return `<div class="isec"><h4>Sources <span class="t3">${by.size} independent</span></h4><div class="sr-ss">${[...by.entries()].slice(0, 8).map(([k, rel]) => `<span class="sr-s">${srChip(rel)}<span>${esc(k)}</span></span>`).join('')}</div>${by.size === 1 ? `<p class="t3 small" style="margin:6px 0 0">Only one source mentions this${weak ? ', and it is rated weak' : ''}.</p>` : ''}</div>`;
}
function srSet(key, rel){ if(!key) return; DB.srcRel = DB.srcRel && typeof DB.srcRel === 'object' ? DB.srcRel : {}; if(rel && /^[A-F]$/.test(rel)) DB.srcRel[key.slice(0, 200)] = {rel, at:Date.now()}; else delete DB.srcRel[key]; }
/* the selects act when their value changes, not when they are clicked open */
document.addEventListener('change', ev => { const el = ev.target; if(!el || !el.dataset || !el.dataset.sr) return;
  if(el.dataset.sr === 'rate'){ const k = el.dataset.v; if(!k) return; srSet(k, el.value); mutate('rated source ' + k + ' ' + (el.value || 'unrated')); }
  else { const r = recById(el.dataset.id); if(!r) return; if(/^[1-6]$/.test(el.value)) r.cred = el.value; else delete r.cred; mutate('graded evidence ' + (el.value || 'ungraded')); }
  renderAll(); });
const SR_ACTS = {
  srEnt:id => { if(typeof clickAct === 'function') clickAct('selEnt', id); },
};
