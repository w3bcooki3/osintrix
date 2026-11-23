/* ==========================================================================
   Graph → focus and filters, for a case too big to read whole: show only
   what is within 1–3 steps of one entry, grow it a node at a time (Expand),
   narrow it by verdict or tag, and hide entries hanging off a single link.
   A focused view is laid out on its own around the focus and never moves
   the saved positions of the whole graph. Per case; Clear puts it all back.
   ========================================================================== */
function gvS(cid = DB.active){ const G = UI.graph, M = G.fv || (G.fv = {}); return M[cid] || (M[cid] = {focus:null, hops:1, vd:'', tag:'', leaves:false, exp:[]}); }
/* who links to whom, both ways */
function gvAdj(D){ const adj = new Map(), put = (a, b) => { let L = adj.get(a); if(!L) adj.set(a, L = []); L.push(b); }; for(const l of D.links){ put(l.a, l.b); put(l.b, l.a); } return adj; }
const gvOn = (S = gvS()) => !!(S.focus || S.vd || S.tag || S.leaves);
/* the entries to draw, or null for all of them */
function gvVisible(D){
  const S = gvS(); if(!gvOn(S)) return null;
  const hide = UI.graph.hide || new Set(), byId = new Map(D.entries.map(e => [e.id, e]));
  if(S.focus && !byId.has(S.focus)){ S.focus = null; S.exp = []; }
  const pass = e => !hide.has(TYPES[e.type].group) && (!S.tag || e.tags.includes(S.tag)) && (!S.vd || (S.vd === 'none' ? !entryVerdict(e) || entryVerdict(e) === 'unknown' : entryVerdict(e) === S.vd));
  const keep = new Set([S.focus, ...S.exp].filter(Boolean));
  const adj = gvAdj(D);
  let V;
  if(S.focus){
    /* breadth-first from the focus, only through entries the filters let through */
    V = new Set([S.focus]); let edge = [S.focus];
    for(let h = 0; h < S.hops && edge.length; h++){ const nx = []; for(const id of edge) for(const n of adj.get(id) || []){ if(V.has(n)) continue; const e = byId.get(n); if(e && pass(e)){ V.add(n); nx.push(n); } } edge = nx; }
    for(const x of S.exp) if(byId.has(x)){ V.add(x); for(const n of adj.get(x) || []){ const e = byId.get(n); if(e && pass(e)) V.add(n); } }
  } else V = new Set(D.entries.filter(pass).map(e => e.id));
  if(S.leaves){ const deg = id => (adj.get(id) || []).filter(n => V.has(n)).length; for(const id of [...V]) if(!keep.has(id) && deg(id) <= 1) V.delete(id); }
  return V;
}
/* how many hidden neighbours a node has, for "Expand" */
function gvHidden(id, D, V){ if(!V) return 0; let n = 0; for(const l of D.links){ const o = l.a === id ? l.b : l.b === id ? l.a : null; if(o && !V.has(o)) n++; } return n; }
/* the bar over the canvas */
function gvBar(D){
  const S = gvS(), big = D.entries.length > BIG_GRAPH, saved = typeof svList === 'function' ? svList('graph', DB.active).length : 0; if(!big && !gvOn(S) && !saved) return '';
  const V = gvVisible(D), shown = V ? V.size : D.entries.length, fe = S.focus && entryById(S.focus);
  const tags = countBy(D.entries.flatMap(e => e.tags), t => t);
  return `<div class="gfloat gview" role="group" aria-label="Focus and filter the graph">
    ${fe ? `<span class="gv-f">${ico('crosshair','sm')}<b title="${esc(primary(fe))}">${esc(primary(fe).length > 26 ? primary(fe).slice(0, 24) + '…' : primary(fe))}</b><button class="iconbtn xs" data-act="gvFocus" data-v="" aria-label="Stop focusing" title="Show the whole graph">${ico('x','sm')}</button></span>
      <span class="seg gv-h" role="group" aria-label="Steps from the focus">${[1, 2, 3].map(h => `<button data-act="gvHops" data-v="${h}" aria-pressed="${S.hops === h}" title="${h} step${h > 1 ? 's' : ''} away">${h}</button>`).join('')}</span>`
    : `<button class="btn xs" data-act="gvPick" title="Show only what is near one entry">${ico('crosshair','sm')}Focus on…</button>`}
    <label class="sr" for="gvVd">Verdict</label><select id="gvVd" class="gsel bord gv-s${S.vd ? ' on' : ''}" data-gvf="vd">${[['', 'Any verdict'], ['malicious', 'Malicious'], ['suspicious', 'Suspicious'], ['none', 'No verdict'], ['benign', 'Benign']].map(([v, l]) => `<option value="${v}"${S.vd === v ? ' selected' : ''}>${l}</option>`).join('')}</select>
    ${tags.length ? `<label class="sr" for="gvTag">Tag</label><select id="gvTag" class="gsel bord gv-s${S.tag ? ' on' : ''}" data-gvf="tag"><option value="">Any tag</option>${tags.slice(0, 200).map(([t, n]) => `<option value="${esc(t)}"${S.tag === t ? ' selected' : ''}>#${esc(t)} (${n})</option>`).join('')}</select>` : ''}
    <button class="btn xs ghost" data-act="gvLeaves" aria-pressed="${S.leaves}" title="Hide entries that hang off a single link">${ico(S.leaves ? 'check' : 'git-commit-horizontal','sm')}Hide single links</button>
    <span class="gv-n">${shown.toLocaleString()} of ${D.entries.length.toLocaleString()}</span>
    ${gvOn(S) ? `<button class="btn xs ghost" data-act="gvClear">Show all</button><button class="btn xs ghost" data-act="svSave" data-v="graph" title="Name this view to come back to it">${ico('bookmark','sm')}Save view</button>` : ''}${typeof svGraphSel === 'function' ? svGraphSel(DB.active) : ''}</div>`;
}
function gvSet(fn){ const S = gvS(); fn(S); UI.graph.views && delete UI.graph.views[DB.active]; renderMain(); }
const GV_ACTS = {
  gvPick:() => { openDlg(dhead('Focus on an entry') + `<div class="in"><div class="field"><label for="gvQ">Find the entry</label><input id="gvQ" autocomplete="off" spellcheck="false" placeholder="A name, domain, address…" aria-controls="gvL"></div><div id="gvL" class="gv-l" role="listbox" aria-label="Entries"></div><p class="hint">Or right-click any node → Focus here.</p></div>`); $('dlg').classList.add('narrow'); gvPickPaint(); const q = $('gvQ'); q.oninput = () => gvPickPaint(); q.onkeydown = ev => { if(ev.key === 'Enter'){ ev.preventDefault(); const b = document.querySelector('#gvL [role=option]'); if(b) b.click(); } }; q.focus(); },
  gvChoose:id => { closeDlg(); GV_ACTS.gvFocus(null, id); },
  gvFocus:(id, v) => gvSet(S => { S.focus = v || null; S.exp = []; UI.graph.mode = null; }),
  gvHops:(id, v) => gvSet(S => { S.hops = Math.max(1, Math.min(3, +v || 1)); }),
  gvLeaves:() => gvSet(S => { S.leaves = !S.leaves; }),
  gvClear:() => gvSet(S => { S.focus = null; S.exp = []; S.vd = S.tag = ''; S.leaves = false; S.hops = 1; }),
  gvExpand:id => gvSet(S => { if(!S.focus && !gvOn(S)) S.focus = id; else if(!S.exp.includes(id)) S.exp.push(id); }),
};
/* the entries matching what is typed, best connected first */
function gvPickPaint(){
  const q = ($('gvQ') && $('gvQ').value || '').trim().toLowerCase(), D = derive(), deg = new Map();
  for(const l of D.links){ deg.set(l.a, (deg.get(l.a) || 0) + 1); deg.set(l.b, (deg.get(l.b) || 0) + 1); }
  const L = D.entries.filter(e => !q || (Object.values(e.fields).join(' ') + ' ' + e.tags.join(' ')).toLowerCase().includes(q))
    .sort((a, b) => (q ? (primary(a).toLowerCase().startsWith(q) ? 0 : 1) - (primary(b).toLowerCase().startsWith(q) ? 0 : 1) : 0) || (deg.get(b.id) || 0) - (deg.get(a.id) || 0)).slice(0, 12);
  $('gvL').innerHTML = L.length ? L.map(e => `<button role="option" class="gv-o" data-act="gvChoose" data-id="${e.id}">${ico(TYPES[e.type].icon,'sm')}<span class="${MONO_TYPES.has(e.type) ? 'mono' : ''}">${esc(primary(e))}</span><small>${deg.get(e.id) || 0} link${deg.get(e.id) === 1 ? '' : 's'}</small></button>`).join('') : '<p class="t3">No entry matches.</p>';
}
function bindGraphView(){
  document.querySelectorAll('[data-gvf]').forEach(s => s.onchange = () => { gvSet(S => { S[s.dataset.gvf] = s.value; }); const n = $(s.id); if(n) n.focus(); });
}
/* the layout for a focused view: rings out from the focus, nothing saved */
function gvLayout(D){
  const S = gvS(); if(!S.focus) return null;
  const dist = new Map([[S.focus, 0]]), adj = gvAdj(D);
  let edge = [S.focus]; for(let d = 1; edge.length && d < 12; d++){ const nx = []; for(const id of edge) for(const n of adj.get(id) || []) if(!dist.has(n)){ dist.set(n, d); nx.push(n); } edge = nx; }
  return {name:'concentric', animate:false, concentric:n => 20 - (dist.has(n.id()) ? dist.get(n.id()) : 10), levelWidth:() => 1, minNodeSpacing:70, spacingFactor:1.25, padding:50, startAngle:-Math.PI / 2};
}
