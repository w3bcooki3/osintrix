/* ==========================================================================
   Graph — Cytoscape.js (MIT), bundled locally so it works offline.
   Nodes are vault entries: drag to move (positions are saved), double-click
   the canvas to add one, Connect to draw a relationship, select to edit.
   ========================================================================== */
let cy = null;
const cssVar = n => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
const nodeIcon = (icon, color) => 'data:image/svg+xml;utf8,' + encodeURIComponent(
  `<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="-6 -6 36 36" fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${LUCIDE[icon] || ''}</svg>`);

function caseGraph(c, D){
  if(!D.entries.length) return `<div class="scroll">${empty('waypoints','No entries to draw','The graph is built from the case vault. Add an entry and it appears here, ready to connect.', `<button class="btn primary" data-act="addEntry">${ico('plus','sm')}Add entry</button>`)}</div>`;
  const gm = UI.graph, hide = gm.hide || (gm.hide = new Set()), sel = !!(UI.sel && (UI.sel.kind === 'entry' || UI.sel.kind === 'link'));
  const tb = (act, icon, label, extra = '') => `<button class="gbtn" data-act="${act}" title="${label}" aria-label="${label}" ${extra}>${ico(icon,'sm')}<span>${label}</span></button>`;
  return `<div class="gwrap">
    <div class="gtools">
      <div class="gset">${tb('addEntry','plus','Add node')}${tb('gConnect', 'git-branch', gm.mode === 'connect' ? 'Connecting…' : 'Connect', gm.mode === 'connect' ? 'aria-pressed="true"' : '')}</div>
      <div class="gset">${tb('gEdit','pencil','Edit', sel ? '' : 'disabled')}${tb('gDelete','trash-2','Delete', sel ? '' : 'disabled')}</div>
      <div class="search-in gfind">${ico('search')}<label class="sr" for="gFind">Find in graph</label><input id="gFind" class="inp" placeholder="Find a node…" value="${esc(gm.find || '')}" autocomplete="off"></div>
      <span style="flex:1"></span>
      <div class="gset"><label class="sr" for="gLayout">Arrange</label><select id="gLayout" class="gsel"><option value="">Arrange…</option><option value="cose">Force-directed</option><option value="concentric">By importance</option><option value="breadthfirst">Hierarchy</option><option value="circle">Circle</option><option value="grid">Grid</option></select>
        ${tb('gCo', gm.co ? 'eye' : 'eye', 'Co-occurrence', `aria-pressed="${!!gm.co}"`)}${tb('gPng','download','PNG')}</div>
    </div>
    <div class="gcanvas"><div id="cy" role="application" aria-label="Relationship graph for ${esc(c.name)}"></div>
      ${gm.mode === 'connect' ? `<div class="gfloat gmode">${ico('git-branch','sm')}<span>${gm.first ? 'Now click the node to connect to' : 'Click the node to start from'}</span><button class="btn xs" data-act="gConnect">Cancel</button></div>` : ''}
      <div class="gfloat glegend${UI.graph.legendMin ? ' min' : ''}"><button class="caps lgtoggle" data-act="gLegend" aria-expanded="${!UI.graph.legendMin}">${ico(UI.graph.legendMin ? 'chevron-right' : 'chevron-down','sm')}Legend &amp; filters</button>
        <div class="gfilters" role="group" aria-label="Show categories">${GROUPS.filter(([g]) => D.entries.some(e => TYPES[e.type].group === g)).map(([g, l,, col]) =>
          `<button class="gchip" data-act="gHide" data-v="${g}" aria-pressed="${!hide.has(g)}" title="Show or hide ${l}"><i style="background:var(${col})"></i>${l}<b>${D.entries.filter(e => TYPES[e.type].group === g).length}</b></button>`).join('')}</div>
        <div class="gkey"><span><i></i>Your claim</span>${gm.co ? '<span><i class="d"></i>In the same evidence</span>' : ''}<span><b class="ringm"></b>Malicious</span></div></div>
      <div class="gfloat gzoom"><button class="iconbtn" data-act="gZoom" data-v="1.25" aria-label="Zoom in">${ico('zoom-in')}</button><button class="iconbtn" data-act="gZoom" data-v="0.8" aria-label="Zoom out">${ico('zoom-out')}</button><button class="iconbtn" data-act="gFit" aria-label="Fit to screen">${ico('maximize')}</button></div>
    </div></div>`;
}

function graphElements(D){
  const els = [];
  const hide = UI.graph.hide || new Set(), vis = new Set();
  for(const e of D.entries){
    if(hide.has(TYPES[e.type].group)) continue; vis.add(e.id);
    const t = TYPES[e.type], col = cssVar(t.color), v = entryVerdict(e);
    els.push({group:'nodes', data:{id:e.id, label:primary(e).length > 28 ? primary(e).slice(0, 26) + '…' : primary(e), kind:t.label, col, icon:nodeIcon(t.icon, col),
      ring:v === 'malicious' ? cssVar('--red') : v === 'suspicious' ? cssVar('--amber') : col, w:e.priority === 'critical' ? 62 : e.priority === 'high' ? 54 : 46, star:e.starred ? 1 : 0},
      position:e.pos ? {...e.pos} : undefined});
  }
  for(const l of D.links) if(vis.has(l.a) && vis.has(l.b)) els.push({group:'edges', data:{id:l.id, source:l.a, target:l.b, label:l.label, w:.8 + l.conf * .7, kind:'asserted'}});
  if(UI.graph.co){
    const pairs = new Map();
    for(const r of D.recs){ const es = [...new Set(r.ents.map(entKey))].map(k => D.byKey.get(k)).filter(e => e && vis.has(e.id));
      for(let i = 0; i < es.length; i++) for(let j = i + 1; j < es.length; j++){ const k = [es[i].id, es[j].id].sort().join('|'); pairs.set(k, (pairs.get(k) || 0) + 1); } }
    for(const [k, n] of pairs){ const [a, b] = k.split('|'); els.push({group:'edges', data:{id:'co-' + k, source:a, target:b, label:'', w:1, kind:'co', n}}); }
  }
  return els;
}

function mountGraph(){
  const el = $('cy'); if(!el || typeof cytoscape === 'undefined') return;
  const D = derive(), text = cssVar('--text'), text2 = cssVar('--text-2'), bg = cssVar('--bg'), surface = cssVar('--surface'), accent = cssVar('--accent');
  const hasPos = D.entries.every(e => e.pos);
  const muted = cssVar('--text-3');
  if(cy){ cy.destroy(); cy = null; }
  cy = cytoscape({container:el, elements:graphElements(D), minZoom:.2, maxZoom:3, boxSelectionEnabled:false,
    layout:hasPos ? {name:'preset'} : {name:'cose', animate:false, nodeRepulsion:() => 14000, idealEdgeLength:() => 95, nodeOverlap:20, padding:40, randomize:false, numIter:1500},
    style:[
      {selector:'node', style:{width:'data(w)', height:'data(w)', 'background-color':surface, 'background-image':'data(icon)', 'background-width':'62%', 'background-height':'62%',
        'border-width':2.5, 'border-color':'data(ring)', label:'data(label)', color:text, 'font-family':'Inter, sans-serif', 'font-size':14.5, 'font-weight':600, 'min-zoomed-font-size':7,
        'text-valign':'bottom', 'text-margin-y':8, 'text-background-color':bg, 'text-background-opacity':.85, 'text-background-padding':3, 'text-background-shape':'roundrectangle',
        'overlay-opacity':0, 'transition-property':'border-width, width, height', 'transition-duration':'120ms'}},
      {selector:'node[star = 1]', style:{'border-style':'double', 'border-width':5}},
      {selector:'node:selected', style:{'border-color':accent, 'border-width':4, 'underlay-color':accent, 'underlay-opacity':.22, 'underlay-padding':8, 'underlay-shape':'ellipse'}},
      {selector:'node.src', style:{'underlay-color':accent, 'underlay-opacity':.35, 'underlay-padding':10, 'underlay-shape':'ellipse'}},
      {selector:'edge', style:{width:'data(w)', 'line-color':accent, 'target-arrow-color':accent, 'target-arrow-shape':'triangle', 'arrow-scale':.9, 'curve-style':'bezier', opacity:.75,
        label:'data(label)', 'font-size':12.5, 'min-zoomed-font-size':8, 'font-family':'Inter, sans-serif', color:text2, 'text-rotation':'autorotate', 'text-background-color':bg, 'text-background-opacity':1,
        'text-background-padding':2, 'overlay-opacity':0}},
      {selector:'edge[kind = "co"]', style:{'line-style':'dashed', 'line-color':text2, 'target-arrow-shape':'none', opacity:.35, width:1.2}},
      {selector:'edge:selected', style:{'line-color':cssVar('--amber'), 'target-arrow-color':cssVar('--amber'), opacity:1, width:3}},
      {selector:'.faded', style:{opacity:.16}},
      {selector:'node.hit', style:{'underlay-color':cssVar('--amber'), 'underlay-opacity':.4, 'underlay-padding':10, 'underlay-shape':'ellipse'}},
    ]});
  if(!hasPos){ cy.nodes().forEach(n => { const e = entryById(n.id()); if(e) e.pos = {...n.position()}; }); save(); }
  const fitNice = () => { cy.resize(); cy.fit(undefined, 56); if(cy.zoom() > 1.25) { cy.zoom(1.25); cy.center(); } if(cy.zoom() < .7){ cy.zoom(.7); cy.center(); } if(!UI.graph.legendMin && cy.width() > 900) cy.panBy({x:100, y:0}); };
  const view = UI.graph.views && UI.graph.views[DB.active];
  let ready = !!view; const me = cy;
  if(view){ cy.zoom(view.z); cy.pan(view.p); } else { fitNice(); setTimeout(() => { if(cy === me){ fitNice(); ready = true; } }, 90); }
  cy.on('viewport', () => { if(!ready || cy !== me) return; (UI.graph.views || (UI.graph.views = {}))[DB.active] = {z:cy.zoom(), p:{...cy.pan()}}; });
  cy.on('dragfree', 'node', ev => { const e = entryById(ev.target.id()); if(e){ e.pos = {...ev.target.position()}; save(); } });
  cy.on('tap', 'node', ev => {
    const id = ev.target.id();
    if(UI.graph.mode === 'connect'){
      if(!UI.graph.first){ UI.graph.first = id; ev.target.addClass('src'); renderMain(); return; }
      if(UI.graph.first === id) return;
      const a = UI.graph.first; UI.graph.first = null; UI.graph.mode = null; return linkDlg({a, b:id});
    }
    selectEntry(id, true);
  });
  cy.on('tap', 'edge', ev => { const id = ev.target.id(); if(id.startsWith('co-')) return; UI.sel = {kind:'link', id}; UI.inspOpen = true; renderInsp(); refreshGraphTools(); });
  cy.on('tap', ev => { if(ev.target === cy){ if(UI.sel){ UI.sel = null; renderInsp(); refreshGraphTools(); } cy.elements().removeClass('faded'); } });
  cy.on('dbltap', ev => { if(ev.target === cy){ UI.graph.newPos = {...ev.position}; entryDlg(); } });
  const menuAt = (ev, fn) => { const oe = ev.originalEvent || {}, r = el.getBoundingClientRect(), rp = ev.renderedPosition || (ev.target.renderedPosition && ev.target.renderedPosition()) || {x:0, y:0};
    fn((oe.clientX != null ? oe.clientX : r.left + rp.x), (oe.clientY != null ? oe.clientY : r.top + rp.y)); };
  cy.on('cxttap taphold', 'node', ev => menuAt(ev, (x, y) => nodeMenu(ev.target.id(), x, y)));
  cy.on('cxttap taphold', 'edge', ev => { if(!ev.target.id().startsWith('co-')) menuAt(ev, (x, y) => edgeMenu(ev.target.id(), x, y)); });
  cy.on('cxttap taphold', ev => { if(ev.target === cy) menuAt(ev, (x, y) => canvasMenu({...ev.position}, x, y)); });
  el.oncontextmenu = e => e.preventDefault();
  el.onkeydown = e => { if((e.key === 'ContextMenu' || (e.shiftKey && e.key === 'F10')) && UI.sel && UI.sel.kind === 'entry'){ e.preventDefault(); const n = cy.getElementById(UI.sel.id), r = el.getBoundingClientRect(), p = n.renderedPosition(); nodeMenu(UI.sel.id, r.left + p.x, r.top + p.y); } };
  cy.on('mouseover', 'node', ev => { const n = ev.target, nb = n.closedNeighborhood(); cy.elements().not(nb).addClass('faded'); });
  cy.on('mouseout', 'node', () => { cy.elements().removeClass('faded'); applyFind(); });
  if(UI.sel && UI.sel.kind === 'entry'){ const n = cy.getElementById(UI.sel.id); if(n.length) n.select(); }
  if(UI.graph.first){ const n = cy.getElementById(UI.graph.first); if(n.length) n.addClass('src'); }
  applyFind();
  const gf = $('gFind'); if(gf) gf.oninput = () => { UI.graph.find = gf.value; applyFind(); };
  const lay = $('gLayout'); if(lay) lay.onchange = () => { if(!lay.value) return; runLayout(lay.value); lay.value = ''; };
}
function runLayout(name){
  const opts = {name, animate:true, animationDuration:450, padding:40, fit:true};
  if(name === 'cose') Object.assign(opts, {nodeRepulsion:() => 14000, idealEdgeLength:() => 95, nodeOverlap:20, randomize:true, numIter:1500});
  if(name === 'concentric') Object.assign(opts, {concentric:n => n.degree(), levelWidth:() => 2, minNodeSpacing:30});
  if(name === 'breadthfirst') Object.assign(opts, {directed:true, spacingFactor:1.1, roots:cy.nodes().filter(n => n.indegree() === 0 && n.outdegree() > 0).slice(0, 3)});
  const l = cy.layout(opts);
  l.on('layoutstop', () => { cy.nodes().forEach(n => { const e = entryById(n.id()); if(e) e.pos = {...n.position()}; }); mutate('re-arranged graph'); });
  l.run();
}
function refreshGraphTools(){
  const can = !!(UI.sel && (UI.sel.kind === 'entry' || UI.sel.kind === 'link'));
  document.querySelectorAll('[data-act=gEdit],[data-act=gDelete]').forEach(b => b.disabled = !can);
}

function applyFind(){
  if(!cy) return; const q = (UI.graph.find || '').toLowerCase().trim();
  cy.elements().removeClass('hit faded'); if(!q) return;
  const hits = cy.nodes().filter(n => (n.data('label') + ' ' + n.data('kind')).toLowerCase().includes(q));
  if(!hits.length) return; hits.addClass('hit'); cy.elements().not(hits.closedNeighborhood()).addClass('faded');
}

/* ==========================================================================
   Context menu (right-click, or long-press on touch) — keyboard navigable
   ========================================================================== */
let CTX = null;
function showMenu(x, y, items, title){
  hideMenu();
  const m = document.createElement('div'); m.className = 'ctx'; m.setAttribute('role', 'menu'); m.id = 'ctx';
  m.innerHTML = (title ? `<div class="ctx-title">${title}</div>` : '') + items.map((it, i) => {
    if(it.sep) return '<div class="ctx-sep" role="separator"></div>';
    if(it.seg) return `<div class="ctx-seg"><span>${esc(it.label)}</span><div>${it.seg.map((s, j) => `<button role="menuitemradio" aria-checked="${!!s.on}" data-i="${i}" data-j="${j}" class="${s.cls || ''}">${esc(s.label)}</button>`).join('')}</div></div>`;
    return `<button role="menuitem" class="ctx-it${it.danger ? ' danger' : ''}" data-i="${i}" ${it.disabled ? 'disabled' : ''}>${ico(it.icon || 'circle-dot','sm')}<span>${esc(it.label)}</span>${it.kbd ? `<kbd>${esc(it.kbd)}</kbd>` : ''}</button>`;
  }).join('');
  document.body.appendChild(m);
  const r = m.getBoundingClientRect(), W = window.innerWidth, H = window.innerHeight;
  m.style.left = Math.max(8, Math.min(x, W - r.width - 8)) + 'px'; m.style.top = Math.max(8, Math.min(y, H - r.height - 8)) + 'px';
  m.onclick = ev => { const b = ev.target.closest('button'); if(!b || b.disabled) return; const it = items[+b.dataset.i]; hideMenu();
    if(b.dataset.j != null) it.seg[+b.dataset.j].fn(); else it.fn(); };
  m.onkeydown = ev => { const bs = [...m.querySelectorAll('button:not([disabled])')], i = bs.indexOf(document.activeElement);
    if(ev.key === 'ArrowDown'){ ev.preventDefault(); bs[(i + 1) % bs.length].focus(); } else if(ev.key === 'ArrowUp'){ ev.preventDefault(); bs[(i - 1 + bs.length) % bs.length].focus(); }
    else if(ev.key === 'Escape' || ev.key === 'Tab'){ ev.preventDefault(); hideMenu(); } };
  CTX = {m, prev:document.activeElement};
  const f = m.querySelector('button:not([disabled])'); if(f) f.focus({preventScroll:true});
}
function hideMenu(){ if(CTX){ CTX.m.remove(); const p = CTX.prev; CTX = null; if(p && p.focus && document.contains(p)) p.focus({preventScroll:true}); } }
document.addEventListener('mousedown', ev => { if(CTX && !ev.target.closest('#ctx')) hideMenu(); }, true);
window.addEventListener('blur', hideMenu); window.addEventListener('resize', hideMenu);

function verdictSeg(cur, set){ return [['malicious','Malicious','m'],['suspicious','Suspicious','s'],['benign','Benign','b'],['','Unknown','u']].map(([v, l, c]) => ({label:l, on:cur === v, cls:'v-' + c, fn:() => set(v)})); }
function nodeMenu(id, x, y){
  const e = entryById(id); if(!e) return; const k = entryKey(e);
  selectEntry(id, true); const n = cy && cy.getElementById(id); if(n) { cy.nodes().unselect(); n.select(); }
  showMenu(x, y, [
    {label:'Open details', icon:'panel-right', fn:() => selectEntry(id, true)},
    {label:'Edit entry…', icon:'pencil', kbd:'E', fn:() => entryDlg(id)},
    {label:'Connect from here…', icon:'git-branch', fn:() => { UI.graph.mode = 'connect'; UI.graph.first = id; renderMain(); }},
    {label:'Add a linked entry…', icon:'plus', fn:() => { UI.graph.linkFrom = id; const p = e.pos || {x:0, y:0}; UI.graph.newPos = {x:p.x + 160, y:p.y + 40}; entryDlg(); }},
    {sep:true},
    {label:'Verdict', seg:verdictSeg(entryVerdict(e), v => { setEntryVerdict(e, v); mutate('verdict on ' + primary(e)); renderAll(); })},
    {label:'Priority', seg:['low','medium','high','critical'].map(p => ({label:p[0].toUpperCase() + p.slice(1), on:e.priority === p, fn:() => { e.priority = p; mutate('priority ' + p); renderAll(); }}))},
    {label:e.starred ? 'Unstar' : 'Star', icon:'star', fn:() => { e.starred = !e.starred; mutate('star'); renderAll(); }},
    {sep:true},
    {label:'Highlight neighbours', icon:'waypoints', fn:() => { const nb = cy.getElementById(id).closedNeighborhood(); cy.elements().removeClass('faded').not(nb).addClass('faded'); }},
    {label:'Show evidence on timeline', icon:'clock', disabled:!k, fn:() => { UI.pivot = k; UI.tlMode = 'events'; go(caseHash(DB.active, 'timeline')); }},
    {label:'Hide ' + GROUPS.find(g => g[0] === TYPES[e.type].group)[1], icon:'eye', fn:() => { (UI.graph.hide || (UI.graph.hide = new Set())).add(TYPES[e.type].group); renderMain(); }},
    {sep:true},
    {label:'Delete entry', icon:'trash-2', danger:true, kbd:'Del', fn:() => clickAct('delEntry', id)},
  ], `${ico(TYPES[e.type].icon,'sm')}${esc(primary(e).slice(0, 34))}`);
}
function edgeMenu(id, x, y){
  const l = DB.links.find(z => z.id === id); if(!l) return;
  UI.sel = {kind:'link', id}; UI.inspOpen = true; renderInsp(); refreshGraphTools();
  showMenu(x, y, [
    {label:'Edit relationship…', icon:'pencil', fn:() => linkDlg({id})},
    {label:'Reverse direction', icon:'undo-2', fn:() => { [l.a, l.b] = [l.b, l.a]; mutate('reversed ' + l.label); renderAll(); }},
    {label:'Confidence', seg:[[1,'Low'],[2,'Medium'],[3,'High']].map(([c, lab]) => ({label:lab, on:l.conf === c, fn:() => { l.conf = c; mutate('confidence'); renderAll(); }}))},
    {label:'Open evidence', icon:'file-text', disabled:!recById(l.src), fn:() => clickAct('selRec', l.src)},
    {sep:true},
    {label:'Delete relationship', icon:'trash-2', danger:true, fn:() => clickAct('delLink', id)},
  ], `${ico('git-branch','sm')}${esc(l.label)}`);
}
function canvasMenu(pos, x, y){
  showMenu(x, y, [
    {label:'Add entry here…', icon:'plus', fn:() => { UI.graph.newPos = pos; entryDlg(); }},
    {label:'Connect two entries…', icon:'git-branch', fn:() => { UI.graph.mode = 'connect'; UI.graph.first = null; renderMain(); }},
    {sep:true},
    {label:'Fit to screen', icon:'maximize', fn:() => cy.animate({fit:{padding:50}, duration:250})},
    {label:'Arrange: force-directed', icon:'waypoints', fn:() => runLayout('cose')},
    {label:'Arrange: hierarchy', icon:'git-branch', fn:() => runLayout('breadthfirst')},
    {label:'Arrange: circle', icon:'circle-dot', fn:() => runLayout('circle')},
    {label:(UI.graph.co ? 'Hide' : 'Show') + ' co-occurrence', icon:'eye', fn:() => { UI.graph.co = !UI.graph.co; renderMain(); }},
    {label:'Show all categories', icon:'layers', disabled:!(UI.graph.hide && UI.graph.hide.size), fn:() => { UI.graph.hide = new Set(); renderMain(); }},
    {sep:true},
    {label:'Export as PNG', icon:'download', fn:() => clickAct('gPng')},
  ], 'Graph');
}
function clickAct(act, id){ const b = document.createElement('button'); b.dataset.act = act; if(id) b.dataset.id = id; b.hidden = true; document.body.appendChild(b); b.click(); b.remove(); }
