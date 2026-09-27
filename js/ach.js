/* ==========================================================================
   Hypothesis board — Analysis of Competing Hypotheses (Heuer, CIA 1999).
   List every plausible explanation, rate each piece of evidence against each,
   and rank by what CONTRADICTS a hypothesis (confirming evidence is cheap —
   it often fits several explanations). Non-diagnostic rows are flagged, and
   the evidence that alone decides the ranking is called out for re-checking.
   ========================================================================== */
const ACH_R = {NA:['n/a', '', 0, 0], II:['– –', 'red', 0, 2], I:['–', 'red', 0, 1], N:['·', '', 0, 0], C:['+', 'green', 1, 0], CC:['+ +', 'green', 2, 0]};
const ACH_CYCLE = ['N', 'C', 'CC', 'I', 'II', 'NA'];
const ACH_LABEL = {CC:'Strongly consistent', C:'Consistent', N:'Neutral / not applicable', I:'Inconsistent', II:'Strongly inconsistent', NA:'Not applicable'};
function achOf(c){ return c.ach || (c.ach = {hyps:[], ev:[], m:{}}); }
const achW = ev => (ev.cred || 2) * (ev.rel || 2) / 4;
function achScore(A){
  const sc = A.hyps.map(h => ({h, inc:0, con:0}));
  for(const ev of A.ev){ const row = A.m[ev.id] || {}, w = achW(ev); sc.forEach(s => { const r = ACH_R[row[s.h.id] || 'N']; s.inc += r[3] * w; s.con += r[2] * w; }); }
  const live = sc.filter(s => s.h.status !== 'rejected').sort((a, b) => a.inc - b.inc || b.con - a.con);
  return {sc, rank:live.concat(sc.filter(s => s.h.status === 'rejected'))};
}
function achDiag(A, ev){ const row = A.m[ev.id] || {}, vals = A.hyps.filter(h => h.status !== 'rejected').map(h => row[h.id] || 'N'); return new Set(vals).size > 1; }
function achDecisive(A){
  const top = achScore(A).rank[0]; if(!top || A.hyps.length < 2) return new Set();
  const out = new Set(); for(const ev of A.ev){ const B = {...A, ev:A.ev.filter(x => x !== ev)}; const t2 = achScore(B).rank[0]; if(t2 && t2.h.id !== top.h.id) out.add(ev.id); } return out;
}
const ACH_OPTS = [['CC','Strongly consistent','++'],['C','Consistent','+'],['N','Neutral','·'],['I','Inconsistent','−'],['II','Strongly inconsistent','−−'],['NA','Not applicable','n/a']];
const achSym = v => (ACH_OPTS.find(o => o[0] === v) || ACH_OPTS[2])[2];
const dots = (n, act, id, label) => `<button class="hb-dots" data-act="${act}" data-id="${id}" title="${label}: ${['', 'low', 'medium', 'high'][n]} — click to change" aria-label="${label} ${['', 'low', 'medium', 'high'][n]}"><span>${label[0]}</span>${[1, 2, 3].map(i => `<i class="${i <= n ? 'on' : ''}"></i>`).join('')}</button>`;
function achHTML(c, D){
  const A = achOf(c), S = achScore(A), dec = achDecisive(A), hyps = A.hyps, code = h => 'H' + (hyps.indexOf(h) + 1);
  const help = `<details class="hb-help"><summary>${ico('circle-help','sm')}How the board works</summary><div class="hb-help-b">
    <p><b>Analysis of Competing Hypotheses</b> (Heuer) makes you test every explanation against every piece of evidence, instead of collecting support for a favourite.</p>
    <ol><li>List every reasonable explanation — including the unlikely ones.</li><li>Add evidence from the case, plus your assumptions and anything you would expect to see but don't.</li>
    <li>Rate each cell. Consistent evidence fits; inconsistent evidence argues against.</li><li>Hypotheses are ranked by weighted evidence <i>against</i> them — the one hardest to disprove leads. Credibility and relevance set each row's weight.</li>
    <li>Rows that rate every hypothesis the same are <b>not diagnostic</b>. Rows marked <b>decisive</b> change the leader on their own — verify them.</li></ol></div></details>`;
  const head = `<div class="hb-head"><div><h2>Competing hypotheses</h2><p class="t3">Which explanation survives the evidence? Rank by what contradicts each one.</p></div>
    <div class="hb-acts"><button class="btn" data-act="achEvRec">${ico('file-text','sm')}Add evidence</button><button class="btn" data-act="achEvText">${ico('plus','sm')}Assumption</button><button class="btn primary" data-act="achHyp">${ico('plus','sm')}Hypothesis</button></div></div>`;
  if(!hyps.length) return `${head}${help}<div class="card hb-empty">${empty('scale', 'Start with the explanations', 'Add two or more hypotheses — who did it, how, or why — then rate the evidence against each. The board ranks them by what contradicts them.', `<button class="btn primary" data-act="achHyp">${ico('plus','sm')}Add a hypothesis</button>`)}</div>`;
  const live = S.rank.filter(s => s.h.status !== 'rejected'), lead = live[0], next = live[1], maxInc = Math.max(1, ...S.sc.map(s => s.inc)), maxCon = Math.max(1, ...S.sc.map(s => s.con));
  const gap = lead && next ? next.inc - lead.inc : null;
  const verdict = !A.ev.length ? 'Add evidence and rate it to see a ranking.' : !lead ? 'Every hypothesis is rejected.' : next == null ? 'Only one hypothesis is still open.'
    : gap < 1 ? `Too close to call — ${code(lead.h)} and ${code(next.h)} are nearly tied. Look for evidence that separates them.` : gap < 3 ? `${code(lead.h)} leads, but not by much. One or two ratings could change it.` : `${code(lead.h)} is clearly the hardest to disprove on the current evidence.`;
  const rank = `<section class="card hb-rank"><div class="hb-verdict">${ico('scale','sm')}<span>${esc(verdict)}</span></div>
    ${S.rank.map((s, i) => { const rej = s.h.status === 'rejected', isLead = lead && s === lead;
      return `<div class="hb-r${isLead ? ' lead' : ''}${rej ? ' rej' : ''}"><span class="hb-code">${code(s.h)}</span><div class="hb-rn"><button class="linkbtn" data-act="achHypEdit" data-id="${s.h.id}">${esc(s.h.t)}</button>${rej ? '<span class="hb-pill">Rejected</span>' : isLead ? '<span class="hb-pill lead">Leading</span>' : ''}${s.h.note ? `<small>${esc(s.h.note)}</small>` : ''}</div>
        <div class="hb-bars" title="Weighted evidence against ${s.inc.toFixed(1)} · for ${s.con.toFixed(1)}"><div class="hb-bar against"><i style="width:${Math.round(s.inc / maxInc * 100)}%"></i><b>${s.inc.toFixed(1)}</b><span>against</span></div><div class="hb-bar for"><i style="width:${Math.round(s.con / maxCon * 100)}%"></i><b>${s.con.toFixed(1)}</b><span>for</span></div></div></div>`; }).join('')}</section>`;
  const th = h => { const s = S.sc.find(x => x.h === h); return `<th class="hb-hc${lead && lead.h === h ? ' lead' : ''}${h.status === 'rejected' ? ' rej' : ''}"><span class="hb-code">${code(h)}</span><button class="hb-ht" data-act="achHypEdit" data-id="${h.id}" title="${esc(h.t)}">${esc(h.t)}</button></th>`; };
  const cell = (ev, h) => { const v = (A.m[ev.id] || {})[h.id] || 'N'; return `<td class="hb-c${h.status === 'rejected' ? ' rej' : ''}"><button class="hb-v v-${v}" data-act="achPick" data-id="${ev.id}" data-v="${h.id}" title="${ACH_LABEL[v]} — click to change" aria-label="${esc(ev.t || '')} vs ${code(h)}: ${ACH_LABEL[v]}">${achSym(v)}</button></td>`; };
  const rows = A.ev.map(ev => { const r = ev.rec ? recById(ev.rec) : null, diag = achDiag(A, ev), isDec = dec.has(ev.id);
    return `<tr class="${diag ? '' : 'nd'}${isDec ? ' dec' : ''}"><th class="hb-ev"><div class="hb-evt">${r ? ico('file-text','sm') : ico('lightbulb','sm')}${r ? `<button class="linkbtn" data-act="selRec" data-id="${r.id}">${esc(ev.t || r.title)}</button>` : `<span>${esc(ev.t)}</span>`}</div>
      <div class="hb-evm">${dots(ev.cred || 2, 'achCred', ev.id, 'Credibility')}${dots(ev.rel || 2, 'achRel', ev.id, 'Relevance')}${!diag && hyps.length > 1 ? '<span class="hb-tag">Not diagnostic</span>' : ''}${isDec ? '<span class="hb-tag dec">Decisive</span>' : ''}<button class="hb-x" data-act="achEvDel" data-id="${ev.id}" aria-label="Remove row" title="Remove row">${ico('x','sm')}</button></div></th>
      ${hyps.map(h => cell(ev, h)).join('')}</tr>`; }).join('');
  const foot = `<tr class="hb-foot"><th>Weighted evidence against</th>${hyps.map(h => { const s = S.sc.find(x => x.h === h); return `<td class="${lead && lead.h === h ? 'lead' : ''}">${s.inc.toFixed(1)}</td>`; }).join('')}</tr>`;
  return `${head}${help}${rank}
    <section class="card hb-matrix"><div class="hb-scroll"><table class="hb-t"><thead><tr><th class="hb-ev hb-evh">Evidence <span class="t3">${A.ev.length}</span></th>${hyps.map(th).join('')}</tr></thead>
      <tbody>${rows || `<tr><th class="hb-ev" colspan="${hyps.length + 1}"><span class="t3">Add evidence from the case, or an assumption, to start rating.</span></th></tr>`}</tbody>${A.ev.length ? `<tfoot>${foot}</tfoot>` : ''}</table></div>
      <div class="hb-legend">${ACH_OPTS.map(([k, l, sym]) => `<span><b class="hb-v v-${k}">${sym}</b>${l}</span>`).join('')}</div></section>
    <p class="heur">A ranking, not a verdict — it is only as good as the ratings and the list of hypotheses. If the true explanation is missing, the board cannot find it.</p>`;
}
function achHypDlg(id){
  const c = theCase(), A = achOf(c), h = id ? A.hyps.find(x => x.id === id) : {t:'', status:'open', note:''};
  openDlg(dhead(id ? 'Edit hypothesis' : 'New hypothesis') + `<form data-form="achHyp" data-id="${id || ''}"><div class="in">
    <div class="field"><label for="ahT">Hypothesis</label><input id="ahT" value="${esc(h.t)}" required autofocus placeholder="e.g. The operator is a former employee"></div>
    <div class="field"><label>Status</label><div class="seg">${[['open','Open'],['likely','Leading'],['rejected','Rejected']].map(([v, l]) => `<button type="button" data-act="ahStatus" data-v="${v}" aria-pressed="${h.status === v}">${l}</button>`).join('')}</div></div>
    <div class="field" style="margin:0"><label for="ahN">Note</label><input id="ahN" value="${esc(h.note || '')}" placeholder="Why it is still open, or why you rejected it"></div></div>
    <footer>${id ? `<button class="btn danger" type="button" data-act="achHypDel" data-id="${id}" style="margin-right:auto">${ico('trash-2','sm')}Delete</button>` : ''}<button class="btn" type="button" data-act="dclose">Cancel</button><button class="btn primary" type="submit">Save</button></footer></form>`);
  UI.ahStatus = h.status || 'open';
}
function achRecDlg(){
  const c = theCase(), A = achOf(c), have = new Set(A.ev.map(e => e.rec).filter(Boolean)), D = derive();
  const list = D.recs.filter(r => r.type !== 'lead' && !have.has(r.id)).sort((a, b) => (b.type === 'finding') - (a.type === 'finding') || (b.tags.includes('key-evidence')) - (a.tags.includes('key-evidence')));
  openDlg(dhead('Add evidence from this case') + `<div class="in"><div class="search-in" style="margin-bottom:10px">${ico('search')}<label class="sr" for="arQ">Search</label><input id="arQ" class="inp" placeholder="Search records…"></div><div class="pklist" id="arList">
    ${list.map(r => `<label class="pk" data-t="${esc((r.title + ' ' + r.host + ' ' + r.source).toLowerCase())}"><input type="checkbox" value="${r.id}"><span class="pkv"><span>${esc(r.title)}</span><small>${r.type === 'finding' ? '<b>Finding</b> · ' : ''}${r.tags.includes('key-evidence') ? '<b>Key evidence</b> · ' : ''}${r.ts ? esc(E.fmtFull(r.ts, tz()).slice(0, 16)) : 'no time'}${r.host ? ' · ' + esc(r.host) : ''}</small></span></label>`).join('') || '<p class="t3" style="margin:12px">Every record is already on the board.</p>'}</div></div>
    <footer><button class="btn" data-act="dclose">Cancel</button><button class="btn primary" data-act="achRecGo">Add selected</button></footer>`, true, () => {
      $('arQ').oninput = e => { const q = e.target.value.toLowerCase(); document.querySelectorAll('#arList .pk').forEach(el => el.hidden = q && !el.dataset.t.includes(q)); }; });
}
/* a starting board for the sample case, so the idea is visible straight away */
function ensureAchDemo(){
  const c = DB.cases.find(x => x.id === 'c-lantern'); if(!c || !c.sample || c.ach) return; const D = derive(c.id), find = re => (D.recs.find(r => re.test(r.title)) || {}).id;
  const h1 = uid('h'), h2 = uid('h'), h3 = uid('h');
  const ev = [[/Invoice email delivered/, 3, 3, {[h1]:'C', [h2]:'C', [h3]:'I'}], [/LNK opened/, 3, 3, {[h1]:'C', [h2]:'C', [h3]:'N'}], [/Script block downloads/, 3, 2, {[h1]:'CC', [h2]:'C', [h3]:'N'}],
    [/beacon|4444/i, 3, 3, {[h1]:'CC', [h2]:'I', [h3]:'N'}], [/svc_backup|DC01|lateral/i, 2, 3, {[h1]:'CC', [h2]:'II', [h3]:'C'}]].map(([re, cred, rel, m]) => ({id:uid('e'), rec:find(re), cred, rel, m})).filter(x => x.rec);
  if(ev.length < 3) return;
  c.ach = {hyps:[{id:h1, t:'Hands-on intrusion by the “Lamp loader” operator', status:'open', note:''}, {id:h2, t:'Commodity phishing — automated, not targeted', status:'open', note:''}, {id:h3, t:'Insider using the invoice as cover', status:'open', note:''}],
    ev:ev.map(({id, rec, cred, rel}) => ({id, rec, cred, rel})), m:Object.fromEntries(ev.map(x => [x.id, x.m]))};
  ev.push({id:uid('e'), t:'No sign the finance user had admin rights before the intrusion', cred:2, rel:2});
  c.ach.ev.push({id:ev[ev.length - 1].id, t:ev[ev.length - 1].t, cred:2, rel:2}); c.ach.m[ev[ev.length - 1].id] = {[h1]:'C', [h2]:'N', [h3]:'I'};
}
const ACH_ACTS = {
  achPick:(id, v, t) => { const r = t.getBoundingClientRect(), A = achOf(theCase()), cur = (A.m[id] || {})[v] || 'N';
    showMenu(r.left, r.bottom + 4, ACH_OPTS.map(([k, l, sym]) => ({label:l, icon:k === cur ? 'check' : 'circle-dot', fn:() => { A.m[id] = A.m[id] || {}; A.m[id][v] = k; mutate('rated evidence'); renderMain(); }})), 'Rate this evidence'); },
  achHyp:() => achHypDlg(null), achHypEdit:id => achHypDlg(id),
  ahStatus:(id, v, t) => { UI.ahStatus = v; t.parentElement.querySelectorAll('button').forEach(b => b.setAttribute('aria-pressed', String(b === t))); },
  achHypDel:id => { const c = theCase(), A = achOf(c), h = A.hyps.find(x => x.id === id), prev = JSON.parse(JSON.stringify(A)); A.hyps = A.hyps.filter(x => x !== h); for(const k in A.m) delete A.m[k][id]; closeDlg(); mutate('deleted hypothesis'); renderMain(); toast('Hypothesis deleted', 'Undo', () => { c.ach = prev; mutate('restored hypothesis'); renderMain(); }); },
  achCell:(id, v, t, ev) => { const A = achOf(theCase()); A.m[id] = A.m[id] || {}; const cur = A.m[id][v] || 'N', i = ACH_CYCLE.indexOf(cur); A.m[id][v] = ACH_CYCLE[(i + 1) % ACH_CYCLE.length]; mutate('rated evidence'); renderMain(); },
  achCred:id => { const e = achOf(theCase()).ev.find(x => x.id === id); e.cred = (e.cred || 2) % 3 + 1; mutate('credibility'); renderMain(); },
  achRel:id => { const e = achOf(theCase()).ev.find(x => x.id === id); e.rel = (e.rel || 2) % 3 + 1; mutate('relevance'); renderMain(); },
  achEvDel:id => { const A = achOf(theCase()); A.ev = A.ev.filter(x => x.id !== id); delete A.m[id]; mutate('removed evidence row'); renderMain(); },
  achEvRec:() => achRecDlg(),
  achRecGo:() => { const A = achOf(theCase()), ids = [...document.querySelectorAll('#arList input:checked')].map(x => x.value); for(const r of ids) A.ev.push({id:uid('e'), rec:r, cred:2, rel:2}); closeDlg(); mutate('added ' + ids.length + ' evidence rows'); renderMain(); },
  achEvText:() => { openDlg(dhead('Add an argument or assumption') + `<form data-form="achEv"><div class="in"><div class="field" style="margin:0"><label for="aeT">Text</label><input id="aeT" required autofocus placeholder="e.g. The attacker knew the finance team's invoice format"></div><p class="t3" style="font-size:13px;margin:10px 0 0">Assumptions and missing evidence count too — “we would expect to see X, and we don't” is often the most diagnostic row.</p></div>
    <footer><button class="btn" type="button" data-act="dclose">Cancel</button><button class="btn primary" type="submit">Add</button></footer></form>`); },
  qView:(id, v) => { UI.qView = v; renderMain(); }
};
function achSubmit(k, f){
  const c = theCase(), A = achOf(c);
  if(k === 'achHyp'){ const t = $('ahT').value.trim().replace(/\s+/g, ' '); if(!t) return fieldErr('ahT', 'Describe the hypothesis.'); if(!checkLen('ahT', t, 200, 'Hypothesis')) return; if(clash(A.hyps, t, 't', f.dataset.id || null)) return fieldErr('ahT', 'This hypothesis is already on the board.'); const vals = {t, status:UI.ahStatus || 'open', note:$('ahN').value.trim()};
    if(f.dataset.id) Object.assign(A.hyps.find(x => x.id === f.dataset.id), vals); else A.hyps.push({id:uid('h'), ...vals}); closeDlg(); mutate('saved hypothesis'); return renderMain(); }
  if(k === 'achEv'){ const t = $('aeT').value.trim().replace(/\s+/g, ' '); if(!t) return fieldErr('aeT', 'Write the assumption or piece of evidence.'); if(!checkLen('aeT', t, 300, 'Text')) return; if(A.ev.some(e => normName(e.t) === normName(t))) return fieldErr('aeT', 'This is already a row on the board.'); A.ev.push({id:uid('e'), t, cred:2, rel:2}); closeDlg(); mutate('added assumption'); return renderMain(); }
}
