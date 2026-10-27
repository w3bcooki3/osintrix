/* ==========================================================================
   Shell: the OSINTrix interface (the "Pinboard" design).
   - Cases open on their board (graph); the other tabs follow.
   - A sidebar that collapses to an icon rail (button or "[" key); the choice
     is remembered with the workspace.
   - Indicators are marked inside evidence text; picking one lights up every
     record that mentions it.
   - On the board, the next actions appear around the node you pick.
   ========================================================================== */
const SHELL_HOME = 'graph';
const NAV_STATE = {};

function applyLayout(){
  const h = document.documentElement;
  h.dataset.layout = 'pinboard'; h.classList.add('ds');
  const rail = !DB || !DB.prefs || DB.prefs.navRail !== false; h.classList.toggle('nav-rail', rail);
  try{ localStorage.setItem('osintrix:navRail', rail ? '1' : '0'); }catch(e){}
  const b = $('navCol'); if(b){ const r = h.classList.contains('nav-rail'); b.setAttribute('aria-label', r ? 'Expand sidebar' : 'Collapse sidebar'); b.title = (r ? 'Expand' : 'Collapse') + ' sidebar  [' ; b.innerHTML = ico(r ? 'chevron-right' : 'panel-left'); b.setAttribute('aria-pressed', String(r)); }
}
function toggleNavRail(){ DB.prefs.navRail = DB.prefs.navRail === false; applyLayout(); save(); if(cy) setTimeout(() => cy.resize(), 220); }

/* Case tabs: the board comes first. */
function caseTabs(){
  const tabs = CASE_TABS.map(([k, n, i]) => [k, k === 'graph' ? 'Board' : n, i]);
  return [...tabs.filter(t => t[0] === SHELL_HOME), ...tabs.filter(t => t[0] !== SHELL_HOME)];
}

/* ---------- sidebar ---------- */
function layoutNav(nv, cur){
  const r = UI.route, openQ = c => DB.records.filter(x => x.caseId === c.id && x.type === 'lead' && !x.answer).length;
  const cases = DB.cases.slice().sort((a, b) => (b.pinned ? 1 : 0) - (a.pinned ? 1 : 0) || (b.updated || 0) - (a.updated || 0));
  const mono = c => c.name.split(' — ')[0].split(/\s+/).slice(0, 2).map(w => w[0] || '').join('').toUpperCase();
  const caseLink = c => `<a class="nv case" href="${caseHash(c.id, SHELL_HOME)}"${r.area === 'case' && DB.active === c.id ? ' aria-current="page"' : ''} title="${esc(c.name)}">
      <span class="cmono" aria-hidden="true" style="--cc:${esc(c.color)}">${esc(mono(c))}</span><span class="lbl">${esc(c.name.split(' — ')[0])}</span>${openQ(c) ? `<span class="cnt" title="Open questions">${openQ(c)}</span>` : ''}</a>`;
  const group = (id, label, items) => { const open = NAV_STATE[id] == null ? true : NAV_STATE[id];
    return `<div class="navg navd${open ? '' : ' closed'}"><button class="caps navd-t" data-act="navGroup" data-v="${id}" aria-expanded="${open}">${ico('chevron-right','sm')}<span>${label}</span></button>
      <div class="navd-b">${items.map(([a, i, l, n]) => nv(a, i, l, n)).join('')}</div></div>`; };
  return `
    <div class="navg">${nv('home','layout-dashboard','Dashboard')}${nv('notes','sticky-note','Notes', (DB.notes || []).reduce((s, n) => s + noteTasks(n).filter(t => !t.done).length, 0) || null)}${nv('pad','notebook-pen','Scratchpad')}</div>
    <div class="navg"><div class="caps"><span>Cases</span><button data-act="newCase" title="New case" aria-label="New case">${ico('plus','sm')}</button></div>
      ${cases.slice(0, 8).map(caseLink).join('')}${nv('cases','folder-open', cases.length > 8 ? 'All ' + cases.length + ' cases' : 'All cases')}</div>
    ${group('kit', 'Kit', [['toolbox','wrench','Toolbox', DB.tools.length],['queries','scan-search','Query library'],['lab','file-search','Forensics kit'],['decoder','binary','Decoder'],['cloud','cloud','Cloud'],['ctf','flag','CTF'],['reference','book-open','Reference'],['playbooks','list-checks','Playbooks']])}
    ${group('intel', 'Intelligence', [['feeds','rss','Threat Intel', DB.feed.length || null],['watch','eye','Watchlist', watchHits().length || null],['detections','file-code','Detections'],['entities','fingerprint','Entities']])}
    <div class="navg navfoot">${(DB.trash || []).length ? nv('trash','trash-2','Trash', DB.trash.length) : ''}${nv('security', SEC.key ? 'lock' : 'shield-check', 'Security')}${nv('whatsnew','sparkles',"What's new")}${nv('help','circle-help','Help')}${nv('settings','settings','Settings')}</div>`;
}

/* ---------- indicators marked inside the evidence text ---------- */
const MARK_SKIP = new Set(['eventid','hostport','path','port','time']);
const markable = e => !MARK_SKIP.has(e.k) && (e.k !== 'file' || ['malicious','suspicious'].includes(verdictOf(entKey(e))));
function markEnts(text, ents, max = 1600){
  text = String(text || ''); if(text.length > max) text = text.slice(0, max) + '…';
  const seen = new Map(); for(const e of ents || []) if(e && e.v && String(e.v).length > 2 && markable(e) && !seen.has(e.v)) seen.set(e.v, e);
  const vals = [...seen.values()].sort((a, b) => b.v.length - a.v.length), hits = [];
  for(const e of vals){ let i = 0; while((i = text.indexOf(e.v, i)) !== -1){ const j = i + e.v.length; if(!hits.some(h => i < h.j && j > h.i)) hits.push({i, j, e}); i = j; } }
  if(!hits.length) return esc(text);
  hits.sort((a, b) => a.i - b.i); let out = '', p = 0; const sel = UI.sel && UI.sel.kind === 'ent' ? UI.sel.id : null;
  for(const h of hits){ const id = entKey(h.e);
    out += esc(text.slice(p, h.i)) + `<span class="ioc" data-act="selEnt" data-id="${esc(id)}" data-k="${esc(h.e.k)}" data-v="${esc(verdictOf(id) || '')}"${sel === id ? ' data-on' : ''} title="${esc((E.LABEL && E.LABEL[h.e.k]) || h.e.k)}">${esc(text.slice(h.i, h.j))}</span>`; p = h.j; }
  return out + esc(text.slice(p));
}
/* Picking an indicator lights up every record that mentions it. */
function layoutFocus(){
  const tl = document.querySelector('#main .tl'); if(!tl) return;
  const id = UI.sel && UI.sel.kind === 'ent' ? UI.sel.id : null; let n = 0;
  tl.querySelectorAll('.ioc').forEach(m => m.toggleAttribute('data-on', m.dataset.id === id));
  tl.querySelectorAll('.ev').forEach(ev => { const hit = !!id && !!ev.querySelector(`.ioc[data-id="${CSS.escape(id)}"]`); ev.classList.toggle('hit', hit); if(hit) n++; });
  tl.classList.toggle('focus', !!id && n > 0);
  const f = $('tlFocus'); if(f) f.remove();
  if(id && n){ const bar = tl.parentElement.querySelector('.tlbar'); if(bar) bar.insertAdjacentHTML('beforeend', `<span class="tlfocus" id="tlFocus">${n} record${n > 1 ? 's' : ''} mention <b class="mono">${esc(entSplit(id).v)}</b><button class="btn xs ghost" data-act="layoutUnfocus">Show all</button></span>`); }
}

/* ---------- board: actions around the selected node ---------- */
function radialHide(){ const r = $('radial'); if(r){ r.remove(); if(cy) cy.elements().removeClass('faded'); } }
function radialFor(id){
  radialHide(); if(!cy || window.innerWidth <= 760) return;
  const n = cy.getElementById(id), e = entryById(id), host = document.querySelector('.gcanvas'); if(!n.length || !e || !host) return;
  const k = entryKey(e), v = entryVerdict(e), rad = Math.max(70, n.renderedWidth() / 2 + 46);
  let p = n.renderedPosition(); const W = host.clientWidth, H = host.clientHeight, card = UI.inspOpen && window.innerWidth > 760 ? 390 : 0;
  const dx = Math.min(0, W - card - rad * 1.5 - 90 - p.x) || Math.max(0, rad * 1.5 + 90 - p.x), dy = Math.max(0, rad + 40 - p.y) || Math.min(0, H - 110 - rad - p.y);
  if(dx || dy){ cy.panBy({x:dx, y:dy}); p = n.renderedPosition(); }
  const items = [
    ['Expand from evidence', 'sparkles', () => expandNode(id), !k],
    ['Connect', 'git-branch', () => { UI.graph.mode = 'connect'; UI.graph.first = id; renderMain(); }],
    ['Find path to…', 'route', () => { UI.graph.mode = 'path'; UI.graph.first = id; UI.graph.path = null; renderMain(); }],
    [v === 'malicious' ? 'Clear verdict' : 'Mark malicious', 'shield-alert', () => { setEntryVerdict(e, v === 'malicious' ? '' : 'malicious'); mutate('verdict on ' + primary(e)); renderAll(); }],
    ['On the timeline', 'clock', () => { UI.pivot = k; UI.tlMode = 'events'; go(caseHash(DB.active, 'timeline')); }, !k],
    ['More…', 'ellipsis', () => { const r = $('cy').getBoundingClientRect(); nodeMenu(id, r.left + p.x + 30, r.top + p.y); }]];
  const wrap = document.createElement('div'); wrap.id = 'radial'; wrap.className = 'radial'; wrap.style.left = p.x + 'px'; wrap.style.top = p.y + 'px';
  wrap.innerHTML = items.map(([l, i,, dis], j) => { const a = -Math.PI / 2 + j * 2 * Math.PI / items.length, x = Math.cos(a) * rad * 1.5, y = Math.sin(a) * rad;
    return `<button type="button" data-j="${j}" style="--x:${x.toFixed(0)}px;--y:${y.toFixed(0)}px"${dis ? ' disabled' : ''}>${ico(i,'sm')}<span>${esc(l)}</span></button>`; }).join('');
  wrap.onclick = ev => { const b = ev.target.closest('button[data-j]'); if(!b || b.disabled) return; ev.stopPropagation(); radialHide(); items[+b.dataset.j][2](); };
  host.appendChild(wrap); cy.elements().not(n.closedNeighborhood()).addClass('faded'); requestAnimationFrame(() => wrap.classList.add('on'));
}

const LAYOUT_ACTS = {
  navGroup:(id, v, t) => { const open = t.getAttribute('aria-expanded') !== 'true'; NAV_STATE[v] = open; t.parentElement.classList.toggle('closed', !open); t.setAttribute('aria-expanded', open); },
  navRail:() => toggleNavRail(),
  layoutUnfocus:() => { UI.sel = null; renderInsp(); layoutFocus(); },
};
document.addEventListener('keydown', ev => {
  if(ev.key !== '[' || ev.ctrlKey || ev.metaKey || ev.altKey || /^(INPUT|TEXTAREA|SELECT)$/.test(ev.target.tagName) || ev.target.isContentEditable) return;
  if(!$('scrim').hidden || !DB) return; ev.preventDefault(); toggleNavRail();
});
