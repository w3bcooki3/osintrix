/* ==========================================================================
   Saved hunts — a search or a rule, run across every case, that tells you
   when new evidence matches. A search uses the timeline filter's language
   (host:DC01 verdict:malicious powershell -update); a rule is any Sigma rule
   of yours. What matches when you save it counts as seen; anything matching
   later is "new" here and on Today until you mark it seen.
   ========================================================================== */
const HU_C = new Map();
function huntList(){
  const L = Array.isArray(DB.hunts) ? DB.hunts : [];
  const ok = L.filter(h => h && typeof h === 'object' && typeof h.id === 'string' && typeof h.name === 'string' && (h.kind === 'query' ? typeof h.q === 'string' && h.q.trim() : h.kind === 'rule' && typeof h.ruleId === 'string'));
  for(const h of ok){ h.name = h.name.slice(0, 120); if(!Array.isArray(h.seen)) h.seen = []; h.seen = h.seen.filter(x => typeof x === 'string').slice(-5000); }
  if(ok.length !== L.length) DB.hunts = ok; return ok;
}
function huntScope(){ const own = DB.cases.filter(c => !c.sample), cs = new Set((own.length ? own : DB.cases).map(c => c.id)); return DB.records.filter(r => r.type !== 'lead' && cs.has(r.caseId)); }
function huntMatchQuery(ast, r){ const h = (r.title + ' ' + r.body + ' ' + r.host + ' ' + r.source + ' ' + r.tags.join(' ')).toLowerCase();
  return ast.some(g => g.text.every(t => h.includes(t)) && g.neg.every(t => !h.includes(t)) && g.f.every(f => matchField(r, f) !== f.neg)); }
function huntRun(h){
  const rule = h.kind === 'rule' ? DB.rules.find(x => x.id === h.ruleId) : null, sig = h.id + ':' + rev + ':' + (h.q || '') + ':' + (rule ? rule.code.length + ':' + (rule.modified || 0) : '');
  const c = HU_C.get(h.id); if(c && c.sig === sig) return c.v;
  let matches = [], err = '';
  const recs = huntScope();
  if(h.kind === 'query'){ let ast = null; try{ ast = E.parseQuery(h.q); }catch(e){ try{ ast = parseQuery(h.q); }catch(e2){ err = 'The search could not be read'; } }
    if(ast && ast.length) matches = recs.filter(r => { try{ return huntMatchQuery(ast, r); }catch(e){ return false; } }); }
  else if(!rule) err = 'The rule was deleted';
  else if(rule.type !== 'sigma') err = 'Only Sigma rules can hunt over events';
  else { let p = null; try{ p = sigmaParse(rule.code); }catch(e){ err = 'The rule could not be read'; }
    if(p && p.cond) matches = recs.filter(r => { try{ const f = recFields(r); return sigmaMay(p, f) && sigmaEval(p, f); }catch(e){ return false; } }); }
  const seen = new Set(h.seen), fresh = matches.filter(r => !seen.has(r.id)), byCase = new Map();
  for(const r of matches){ const x = byCase.get(r.caseId) || {n:0, fresh:0}; x.n++; if(!seen.has(r.id)) x.fresh++; byCase.set(r.caseId, x); }
  const v = {matches, fresh, byCase, err, rule}; HU_C.set(h.id, {sig, v}); return v;
}
function huntsView(){
  const H = huntList();
  const card = h => { const R = huntRun(h), what = h.kind === 'query' ? `<code class="mono">${esc(h.q)}</code>` : `rule ${R.rule ? `<button class="lnk" data-act="dqOpen" data-id="${esc(R.rule.id)}">${esc(R.rule.title)}</button>` : '<i>deleted</i>'}`;
    return `<section class="card hu"><header><h3>${ico('crosshair','sm')} ${esc(h.name)}</h3>${R.fresh.length ? `<span class="chip sq red">${R.fresh.length} new</span>` : ''}<span class="t3">${R.matches.length} match${R.matches.length === 1 ? '' : 'es'}</span><span class="sp"></span>
      ${R.fresh.length ? `<button class="btn xs" data-act="huSeen" data-id="${esc(h.id)}">${ico('check','sm')}Mark seen</button>` : ''}<button class="iconbtn" data-act="huDel" data-id="${esc(h.id)}" aria-label="Delete the hunt ${esc(h.name)}">${ico('trash-2','sm')}</button></header>
      <div class="body"><p class="t2" style="margin:0 0 8px">Looks for ${what} in every case${h.lastAt ? ' · seen up to ' + esc(iAgo(h.lastAt)) : ''}.</p>${R.err ? `<p class="t2" style="color:var(--red)">${esc(R.err)}</p>` : ''}
      ${R.byCase.size ? `<ul class="hu-c">${[...R.byCase.entries()].sort((a, b) => b[1].fresh - a[1].fresh || b[1].n - a[1].n).map(([cid, x]) => { const c = theCase(cid); return c ? `<li><button class="lnk" data-act="huCase" data-id="${esc(h.id)}" data-v="${esc(cid)}"><b>${esc(c.name.split(' — ')[0])}</b></button><span class="t3">${x.n}</span>${x.fresh ? `<span class="chip sq red">${x.fresh} new</span>` : ''}</li>` : ''; }).join('')}</ul>` : '<p class="t3">No matches yet. It keeps looking as evidence arrives.</p>'}
      ${R.fresh.length ? `<h4 class="hu-h">New</h4><ul class="hu-e">${R.fresh.slice(0, 15).map(r => `<li><button class="cr-t" data-act="huRec" data-id="${r.id}">${esc(r.title)}</button><span class="mono t3">${caseNm(r.caseId) || ''} · ${r.ts ? esc(E.fmtFull(r.ts, tz())) : 'no time'}</span></li>`).join('')}</ul>${R.fresh.length > 15 ? `<p class="t3 small">and ${R.fresh.length - 15} more</p>` : ''}` : ''}</div></section>`; };
  return `<div class="hu-top"><p class="t2">A hunt is a search or one of your rules, run across every case. What it finds when you save it counts as seen; new matches show here and on Today.</p><button class="btn primary sm" data-act="huNew">${ico('plus','sm')}New hunt</button></div>
    ${H.length ? H.map(card).join('') : empty('crosshair', 'No hunts yet', 'Save a timeline filter as a hunt (the crosshair next to the filter box), or start one here from a search or a rule.')}`;
}
function huntDlg(pre){
  const rules = DB.rules.filter(r => r.type === 'sigma');
  openDlg(dhead('New hunt') + `<form data-form="hunt"><div class="in">
    <div class="field"><label for="huName">Name</label><input id="huName" maxlength="140" value="${esc(pre && pre.name || '')}" placeholder="e.g. C2 address shows up again" autocomplete="off"></div>
    <div class="seg" role="radiogroup" aria-label="Kind"><button type="button" data-act="huKind" data-v="query" aria-pressed="${!(pre && pre.ruleId)}">Search</button><button type="button" data-act="huKind" data-v="rule" aria-pressed="${!!(pre && pre.ruleId)}">Rule</button></div>
    <div class="field" data-hk="query"${pre && pre.ruleId ? ' hidden' : ''}><label for="huQ">Search <span class="t3">— the timeline filter's language</span></label><input id="huQ" class="mono" value="${esc(pre && pre.q || '')}" placeholder="203.0.113.47   or   host:DC01 verdict:malicious" autocomplete="off" spellcheck="false"></div>
    <div class="field" data-hk="rule"${pre && pre.ruleId ? '' : ' hidden'}><label for="huR">Rule</label><input id="huR" list="huRL" value="${esc(pre && pre.ruleId ? ((DB.rules.find(r => r.id === pre.ruleId) || {}).title || '') : '')}" placeholder="Type to find a Sigma rule" autocomplete="off"><datalist id="huRL">${rules.slice(0, 3000).map(r => `<option value="${esc(r.title)}">`).join('')}</datalist></div></div>
    <footer><button class="btn" type="button" data-act="dclose">Cancel</button><button class="btn primary" type="submit">Save hunt</button></footer></form>`);
  $('dlg').classList.add('narrow'); UI.huKind = pre && pre.ruleId ? 'rule' : 'query';
}
function huntSubmit(){
  const name = String($('huName').value || '').replace(/\s+/g, ' ').trim(), kind = UI.huKind === 'rule' ? 'rule' : 'query';
  if(!name) return fieldErr('huName', 'Give the hunt a name.'); if(clash(huntList(), name, 'name')) return fieldErr('huName', `A hunt called “${name}” already exists.`);
  const h = {id:uid('h'), name, kind, created:Date.now(), lastAt:Date.now(), seen:[]};
  if(kind === 'query'){ const q = String($('huQ').value || '').trim(); if(!q) return fieldErr('huQ', 'Write what to look for.'); if(q.length > 500) return fieldErr('huQ', 'Keep the search under 500 characters.'); h.q = q; }
  else { const t = normName($('huR').value), r = DB.rules.find(x => x.type === 'sigma' && normName(x.title) === t); if(!r) return fieldErr('huR', 'Pick one of your Sigma rules from the list.'); h.ruleId = r.id; }
  DB.hunts = [...huntList(), h]; h.seen = huntRun(h).matches.map(r => r.id).slice(-5000); HU_C.delete(h.id);
  closeDlg(); mutate('saved hunt ' + name); UI.dview = 'hunts'; if(UI.route.area !== 'detections') go('#/detections'); else renderMain();
  toast(`Hunt saved — ${huntRun(h).matches.length} match${huntRun(h).matches.length === 1 ? '' : 'es'} now; new ones will be flagged`);
}
const HU_ACTS = {
  huNew:() => huntDlg(), huSave:() => huntDlg({q:UI.q || '', name:''}),
  huKind:(id, v) => { UI.huKind = v; document.querySelectorAll('#dlg [data-act=huKind]').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.v === v))); document.querySelectorAll('#dlg [data-hk]').forEach(x => x.hidden = x.dataset.hk !== v); },
  huSeen:id => { const h = huntList().find(x => x.id === id); if(!h) return; h.seen = huntRun(h).matches.map(r => r.id).slice(-5000); h.lastAt = Date.now(); HU_C.delete(id); mutate('marked hunt matches seen'); renderMain(); },
  huDel:id => { const L = huntList(), h = L.find(x => x.id === id); if(!h) return; DB.hunts = L.filter(x => x.id !== id); const tx = trashPut('hunt', h.name, {h}); mutate('deleted hunt ' + h.name); renderMain(); toast('Hunt deleted — it is in the trash', 'Undo', () => { trashUndo(tx); DB.hunts = [...huntList(), h]; mutate('restored hunt'); renderMain(); }); },
  huCase:(id, v) => { const h = huntList().find(x => x.id === id); if(!h) return; DB.active = v; if(h.kind === 'query'){ UI.q = h.q; UI.ast = E.parseQuery(h.q); UI.tlMode = 'events'; } else { UI.tlMode = 'rules'; UI.crf = 'caught'; } go(caseHash(v, 'timeline')); },
  huRec:id => { const r = recById(id); if(!r) return; DB.active = r.caseId; UI.sel = {kind:'rec', id}; UI.tlMode = 'events'; UI.q = ''; UI.ast = null; go(caseHash(r.caseId, 'timeline')); },
  huOpen:() => { UI.dview = 'hunts'; go('#/detections'); },
};
