/* ==========================================================================
   Toolbox (the Intelligence Vault), Entities, Feeds, Decoder, Reference,
   Settings, and honest placeholders for modules not yet migrated.
   ========================================================================== */
const CAT_COL = {osint:'#8b5cf6', 'digital-forensics':'#0ea5a4', 'malware-analysis':'#e5484d', 'network-security':'#3b82f6', 'threat-intelligence':'#f59e0b', 'incident-response':'#f97316', 'ai-automation':'#ec4899', compliance:'#64748b', general:'#5468ff'};
const catCol = c => CAT_COL[c] || '#5468ff';
const BADGE_HUES = ['#6366f1','#0ea5a4','#e5484d','#f59e0b','#8b5cf6','#3b82f6','#ec4899','#10b981','#f97316','#06b6d4'];
const badgeCol = s => { let h = 0; for(const c of String(s)) h = (h * 31 + c.charCodeAt(0)) >>> 0; return BADGE_HUES[h % BADGE_HUES.length]; };
const mono = (t, cls = '') => `<span class="tbadge ${cls}" style="--cc:${badgeCol(t.name)}" aria-hidden="true">${esc((t.name.match(/[A-Za-z0-9]/) || ['?'])[0].toUpperCase())}</span>`;
const toolSub = t => { const cat = TOOL_CATS[t.cat] || {name:t.cat, children:{}}; return cat.children[t.sub] || cat.name; };
const toolBtns = (t, withEdit) => `<button class="tb-ic${t.starred ? ' on star' : ''}" data-act="toolStar" data-id="${t.id}" aria-label="${t.starred ? 'Remove from favourites' : 'Add to favourites'}" title="Favourite">${ico('star','sm')}</button>
  <button class="tb-ic${t.pinned ? ' on pin' : ''}" data-act="toolPin" data-id="${t.id}" aria-label="${t.pinned ? 'Remove from quick launch' : 'Add to quick launch'}" title="Quick launch">${ico('pin','sm')}</button>
  ${t.tpl ? `<button class="tb-ic run" data-act="toolRun" data-id="${t.id}" aria-label="Run ${esc(t.name)} with a value" title="Run with a value">${ico('play','sm')}</button>` : ''}
  ${withEdit ? `<button class="tb-ic" data-act="toolEdit" data-id="${t.id}" aria-label="Edit ${esc(t.name)}" title="Edit">${ico('pencil','sm')}</button>` : ''}`;
const openBtn = (t, cls = 'btn sm') => { const u = E.safeUrl(t.url); return u ? `<a class="${cls}" href="${esc(u)}" target="_blank" rel="noopener noreferrer" data-act="toolOpen" data-id="${t.id}" aria-label="Open ${esc(t.name)} in a new tab">Open ${ico('arrow-up-right','sm')}</a>` : ''; };
/* A — tool card (the classic ThreatNet card, cleaned up) */
function toolCard(t){
  const u = E.safeUrl(t.url), picked = UI.tpick && UI.tpick.has(t.id);
  return `<article class="tcard2${picked ? ' picked' : ''}">
    <div class="tc-h"><label class="tc-chk"><span class="sr">Select ${esc(t.name)}</span><input type="checkbox" data-act="toolPick" data-id="${t.id}"${picked ? ' checked' : ''}></label>${mono(t,'sm')}
      <h3 title="${esc(t.name)}">${esc(t.name)}</h3><span class="tc-badge${t.seed ? '' : ' mine'}">${t.seed ? 'Pre-added' : 'Custom'}</span></div>
    ${u ? `<a class="tc-url" href="${esc(u)}" target="_blank" rel="noopener noreferrer" data-act="toolOpen" data-id="${t.id}">${esc(u.replace(/\/$/, ''))}${ico('external-link','sm')}</a>` : `<span class="tc-url">${esc(t.url)}</span>`}
    <div class="tc-acts">
      <button class="tb-ic" data-act="toolEdit" data-id="${t.id}" aria-label="Edit ${esc(t.name)}" title="Edit">${ico('pencil','sm')}</button>
      <button class="tb-ic${t.starred ? ' on star' : ''}" data-act="toolStar" data-id="${t.id}" aria-label="${t.starred ? 'Remove from favourites' : 'Add to favourites'}" title="Favourite">${ico('star','sm')}</button>
      <button class="tb-ic${t.pinned ? ' on pin' : ''}" data-act="toolPin" data-id="${t.id}" aria-label="${t.pinned ? 'Remove from quick launch' : 'Add to quick launch'}" title="Quick launch">${ico('pin','sm')}</button>
      ${u ? `<a class="tb-ic" href="${esc(u)}" target="_blank" rel="noopener noreferrer" data-act="toolOpen" data-id="${t.id}" aria-label="Open ${esc(t.name)}" title="Open in a new tab">${ico('external-link','sm')}</a>` : ''}
      ${t.tpl ? `<button class="tb-ic run" data-act="toolRun" data-id="${t.id}" aria-label="Run ${esc(t.name)} with a value" title="Run with a value — ${esc(t.tpl)}">${ico('play','sm')}</button>` : ''}
      <button class="tb-ic del" data-act="toolDelAsk" data-id="${t.id}" aria-label="Delete ${esc(t.name)}" title="Delete">${ico('trash-2','sm')}</button>
      <span class="tc-sub">${esc(toolSub(t))}</span></div>
    <p>${esc(t.desc || 'No description yet.')}</p>
    ${t.tags.length ? `<div class="tc-tags">${t.tags.slice(0, 8).map(g => `<button data-act="toolTag" data-v="${esc(g)}" title="Show tools tagged ${esc(g)}">${esc(g.replace(/-/g, ' '))}</button>`).join('')}</div>` : ''}</article>`;
}
function paintBulk(){
  const el = $('tbulk'); if(!el) return; const n = UI.tpick ? [...UI.tpick].filter(id => DB.tools.some(t => t.id === id)).length : 0;
  el.hidden = !n; if(!n) return;
  el.innerHTML = `<b>${n} selected</b><button class="btn xs ghost" data-act="bulkAll">Select all shown</button><span style="flex:1"></span>
    <button class="btn xs" data-act="bulkStar">${ico('star','sm')}Favourite</button><button class="btn xs" data-act="bulkPin">${ico('pin','sm')}Quick launch</button><button class="btn xs" data-act="bulkExport">${ico('download','sm')}Export</button>
    <button class="btn xs dangerbtn" data-act="bulkDel">${ico('trash-2','sm')}Delete</button><button class="iconbtn" data-act="bulkClear" aria-label="Clear selection">${ico('x','sm')}</button>`;
}
/* B — directory row */
function toolRow(t){
  const u = E.safeUrl(t.url);
  return `<div class="trow2">${mono(t,'sm')}
    <div class="trow2-n">${u ? `<a href="${esc(u)}" target="_blank" rel="noopener noreferrer" data-act="toolOpen" data-id="${t.id}">${esc(t.name)}</a>` : `<b>${esc(t.name)}</b>`}<span class="dom">${esc(hostOf(t.url))}</span></div>
    <div class="trow2-d"><p>${esc(t.desc)}</p><span class="ttag" style="--cc:${catCol(t.cat)}">${esc(toolSub(t))}</span></div>
    <div class="trow2-a">${toolBtns(t, true)}${openBtn(t, 'btn xs')}</div></div>`;
}
/* C — compact chip */
function toolChip(t){
  const u = E.safeUrl(t.url);
  return `<div class="tchip" title="${esc(t.name + (t.desc ? ' — ' + t.desc : ''))}">${u ? `<a class="tchip-hit" href="${esc(u)}" target="_blank" rel="noopener noreferrer" data-act="toolOpen" data-id="${t.id}" aria-label="Open ${esc(t.name)}"></a>` : ''}
    ${mono(t,'sm')}<div class="tchip-n"><b>${esc(t.name)}</b><span>${esc(hostOf(t.url))}</span></div>
    <div class="tchip-a">${t.starred ? `<span class="tstar">${ico('star','sm')}</span>` : ''}<button class="tb-ic${t.pinned ? ' on pin' : ''}" data-act="toolPin" data-id="${t.id}" aria-label="Quick launch" title="Quick launch">${ico('pin','sm')}</button></div>
    <span class="tchip-go">${ico('arrow-up-right','sm')}</span></div>`;
}
function viewToolbox(){
  const q = UI.tq.toLowerCase(), sort = UI.tsort || 'name', view = ['tiles','list','compact'].includes(UI.tview) ? UI.tview : (DB.prefs.tview || 'tiles');
  const inCat = t => UI.tcat === 'all' ? true : UI.tcat === 'fav' ? t.starred : UI.tcat === 'pinned' ? t.pinned : t.cat === UI.tcat && (!UI.tsub || t.sub === UI.tsub);
  let list = DB.tools.filter(t => inCat(t) && (!q || (t.name + ' ' + t.desc + ' ' + t.tags.join(' ') + ' ' + hostOf(t.url)).toLowerCase().includes(q)));
  list.sort(sort === 'recent' ? (a, b) => b.added - a.added : sort === 'used' ? (a, b) => (b.uses - a.uses) || a.name.localeCompare(b.name) : (a, b) => a.name.localeCompare(b.name, undefined, {sensitivity:'base'}));
  const pinned = DB.tools.filter(t => t.pinned), cnt = c => DB.tools.filter(t => t.cat === c).length;
  const cats = Object.entries(TOOL_CATS).filter(([k]) => k !== 'general' && cnt(k));
  const title = UI.tcat === 'all' ? 'All tools' : UI.tcat === 'fav' ? 'Favourites' : UI.tcat === 'pinned' ? 'Quick launch' : (TOOL_CATS[UI.tcat].name + (UI.tsub ? ' · ' + TOOL_CATS[UI.tcat].children[UI.tsub] : ''));
  let groups = null;
  if(!q && sort === 'name'){
    if(UI.tcat === 'all') groups = cats.map(([k, c]) => ({name:c.name, col:catCol(k), items:list.filter(t => t.cat === k)})).filter(g => g.items.length);
    else if(TOOL_CATS[UI.tcat] && !UI.tsub) groups = Object.entries(TOOL_CATS[UI.tcat].children).map(([k, n]) => ({name:n, col:catCol(UI.tcat), items:list.filter(t => t.sub === k)})).filter(g => g.items.length);
  }
  const render = items => view === 'list' ? `<div class="tdir card">${items.map(toolRow).join('')}</div>` : view === 'compact' ? `<div class="tchips">${items.map(toolChip).join('')}</div>` : `<div class="tcards">${items.map(toolCard).join('')}</div>`;
  return `<div class="scroll"><div class="tbx">
    <aside class="tcats"><div class="caps" style="padding:0 10px 8px">Library</div>
      <button class="tcat" data-act="tcat" data-v="all" aria-pressed="${UI.tcat === 'all'}">${ico('layout-dashboard','sm')}All tools<span class="cnt">${DB.tools.length}</span></button>
      <button class="tcat" data-act="tcat" data-v="fav" aria-pressed="${UI.tcat === 'fav'}">${ico('star','sm')}Favourites<span class="cnt">${DB.tools.filter(t => t.starred).length}</span></button>
      <button class="tcat" data-act="tcat" data-v="pinned" aria-pressed="${UI.tcat === 'pinned'}">${ico('pin','sm')}Quick launch<span class="cnt">${pinned.length}</span></button>
      <div class="caps" style="padding:18px 10px 8px">Categories</div>
      ${cats.map(([k, c]) => `<button class="tcat" data-act="tcat" data-v="${k}" aria-pressed="${UI.tcat === k && !UI.tsub}"><span class="cdot" style="background:${catCol(k)}"></span>${esc(c.name)}<span class="cnt">${cnt(k)}</span></button>
        ${UI.tcat === k ? Object.entries(c.children).filter(([sb]) => DB.tools.some(t => t.sub === sb)).map(([sb, l]) => `<button class="tsub" data-act="tsub" data-v="${sb}" aria-pressed="${UI.tsub === sb}">${esc(l)}<span class="cnt">${DB.tools.filter(t => t.sub === sb).length}</span></button>`).join('') : ''}`).join('')}
    </aside>
    <div class="tmain">
      <header class="lhd"><div><h1>${esc(title)}</h1><p>${list.length} of ${DB.tools.length} tools · nothing loads until you open it</p></div>
        <div class="lhd-a"><button class="btn" data-act="toolImport">${ico('upload','sm')}Import</button><button class="btn primary" data-act="toolAdd">${ico('plus','sm')}Add tool</button></div></header>
      <div class="toolbar ltb"><div class="search-in">${ico('search')}<label class="sr" for="tq">Search tools</label><input id="tq" class="inp" placeholder="Search by name, purpose or tag…" value="${esc(UI.tq)}"></div>
        <label class="sr" for="tcatSel2">Category</label><select id="tcatSel2" class="gsel bord tcat-sel"><option value="all">All tools (${DB.tools.length})</option><option value="fav"${UI.tcat === 'fav' ? ' selected' : ''}>★ Favourites</option><option value="pinned"${UI.tcat === 'pinned' ? ' selected' : ''}>Quick launch</option>${cats.map(([k, c]) => `<option value="${k}"${UI.tcat === k ? ' selected' : ''}>${esc(c.name)} (${cnt(k)})</option>`).join('')}</select>
        <span style="flex:1"></span>
        <label class="sr" for="tSort">Sort</label><select id="tSort" class="gsel bord"><option value="name"${sort === 'name' ? ' selected' : ''}>Name A–Z</option><option value="recent"${sort === 'recent' ? ' selected' : ''}>Recently added</option><option value="used"${sort === 'used' ? ' selected' : ''}>Most opened</option></select>
        ${layoutSeg('tview', view, [['tiles','layout-grid','Cards'],['list','rows-3','Directory'],['compact','grid-3x3','Compact']])}</div>
      ${UI.tq ? `<div class="tfilter">${ico('search','sm')}Showing results for <b>${esc(UI.tq)}</b><button class="btn xs ghost" data-act="tqClear">Clear</button></div>` : ''}
      <div class="tbulk" id="tbulk" hidden></div>
      ${!list.length ? empty('wrench','No tools match','Try another category or search, or add the tool yourself.', `<button class="btn primary" data-act="toolAdd">${ico('plus','sm')}Add tool</button>`)
        : groups ? groups.map(g => `<section class="tgroup"><div class="tgh"><i style="background:${g.col}"></i><h2>${esc(g.name)}</h2><span>${g.items.length}</span></div>${render(g.items)}</section>`).join('') : render(list)}
    </div></div></div>`;
}
/* layout switcher shared by Toolbox, Query library and Detections */
const layoutSeg = (act, cur, opts) => `<div class="seg lseg" role="group" aria-label="Layout">${opts.map(([v, i, l]) => `<button data-act="${act}" data-v="${v}" aria-pressed="${cur === v}" title="${l} layout">${ico(i,'sm')}<span>${l}</span></button>`).join('')}</div>`;
function viewEntities(){
  const g = [...globalEnts().values()];
  const eq = (UI.entq || '').toLowerCase();
  let list = g.filter(e => (!UI.entKind || (UI.entKind === 'malicious' ? verdictOf(e.id) === 'malicious' : UI.entKind === 'cross' ? e.cases.size > 1 : true)) && (!eq || (e.v + ' ' + (E.LABEL[e.k] || e.k)).toLowerCase().includes(eq)));
  UI.entList = list;
  list.sort((a, b) => b.recs.length - a.recs.length);
  return `<div class="scroll"><div class="page">
    <div class="ph"><div><h1>Entities</h1><div class="sub">Every indicator across every case, whether you added it to a vault or it was extracted from evidence.</div></div></div>
    <div class="toolbar"><div class="search-in">${ico('search')}<label class="sr" for="entq">Search entities</label><input id="entq" class="inp" placeholder="Search values…" value="${esc(UI.entq || '')}"></div><div class="seg">${[['','All ' + g.length],['malicious','Malicious'],['cross','In 2+ cases']].map(([v, l]) => `<button data-act="entKind" data-v="${v}" aria-pressed="${(UI.entKind || '') === v}">${l}</button>`).join('')}</div><span style="flex:1"></span><span class="t3">${list.length} shown</span><button class="btn" data-act="entExport">${ico('download','sm')}Export CSV</button></div>
    <section class="card" style="overflow:hidden"><table class="tbl cardify"><thead><tr><th>Entity</th><th>Verdict</th><th style="text-align:right">Records</th><th style="text-align:right">Cases</th><th>What it is</th></tr></thead><tbody>
    ${list.slice(0, 150).map(e => { const m = E.meaning(e.k, e.v);
      return `<tr data-act="selEnt" data-id="${esc(e.id)}"><td><div style="display:flex;gap:10px;align-items:center;min-width:0">${kindBadge(e.k,'sm')}<div style="min-width:0"><div class="v">${esc(e.v)}</div><div class="t3" style="font-size:12.5px">${esc(E.LABEL[e.k] || e.k)}</div></div></div></td>
        <td>${vdLabel(verdictOf(e.id)) || '<span class="t3">—</span>'}</td><td class="n">${e.recs.length}</td><td class="n hide-m">${e.cases.size}</td><td class="t2 hide-m" style="font-size:13.5px">${m ? esc(m.t) : '—'}</td></tr>`; }).join('')}
    </tbody></table></section></div></div>`;
}

function viewFeeds(){
  const g = globalEnts();
  return `<div class="scroll"><div class="page narrow">
    <div class="ph"><div><h1>Feeds</h1><div class="sub">Intelligence items, matched against the entities in your cases.</div></div><div class="acts"><button class="btn" data-act="feedImport">${ico('upload','sm')}Import RSS / Atom file</button></div></div>
    <div class="note accent" style="margin-bottom:18px"><span class="ic">${ico('lock','sm')}</span><div><b>Offline by design.</b> OSINTrix never fetches anything. Save a feed file and import it; it is parsed in this browser. The three items below are sample data.</div></div>
    <section class="card"><div class="body flush">${DB.feed.slice().sort((a, b) => b.ts - a.ts).map(f => { const hits = E.extract(f.title + ' ' + f.body), m = hits.filter(e => g.has(entKey(e)));
      return `<button class="li" data-act="selFeed" data-id="${f.id}" style="align-items:flex-start;padding:16px 18px"><span class="tb sm" style="--c:${m.length ? 'var(--red)' : 'var(--t-file)'}">${ico('rss')}</span>
        <div class="main2"><b style="white-space:normal">${esc(f.title)}</b><small>${esc(f.source)} · ${esc(E.fmtDate(f.ts, tz()))}</small></div>
        <span class="end">${m.length ? `<span class="chip red sq">${m.length} match${m.length > 1 ? 'es' : ''}</span>` : '<span class="chip sq">No match</span>'}</span></button>`; }).join('')}</div></section></div></div>`;
}

function decodeChain(input){
  const steps = []; let cur = String(input || '').trim();
  const printable = s => s.length ? [...s].filter(c => { const k = c.charCodeAt(0); return k === 9 || k === 10 || k === 13 || (k >= 32 && k < 127) || k >= 160; }).length / s.length : 0;
  for(let n = 0; n < 6; n++){
    const t = cur.trim(); if(t.length < 8) break;
    if(/%[0-9a-f]{2}/i.test(t)){ try{ const d = decodeURIComponent(t.replace(/\+/g, ' ')); if(d !== t){ cur = d; steps.push(['URL-decode', cur]); continue; } }catch(e){} }
    let blob = t.replace(/\s+/g, ''), pre = '';
    if(!/^[A-Za-z0-9+/_-]+={0,2}$/.test(blob)){ const m = [...t.matchAll(/[A-Za-z0-9+/]{24,}={0,2}/g)].sort((a, b) => b[0].length - a[0].length)[0]; if(!m) break; blob = m[0]; pre = 'Blob from the line → '; }
    let bytes, op;
    if(/^[0-9a-f]+$/i.test(blob) && blob.length % 2 === 0 && blob.length >= 16){ bytes = new Uint8Array(blob.match(/../g).map(h => parseInt(h, 16))); op = 'hex'; }
    else { try{ bytes = Uint8Array.from(atob(blob.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)); op = 'base64'; }catch(e){ break; } }
    let out = new TextDecoder().decode(bytes);
    if(bytes.length >= 8 && bytes[1] === 0 && bytes[3] === 0){ out = new TextDecoder('utf-16le').decode(bytes); op += ' → UTF-16LE'; }
    if(printable(out) < .85) break; cur = out; steps.push([pre + op, cur]);
  }
  return steps;
}
function viewReference(){
  const q = (UI.refQ || '').toLowerCase(), R = E.REF, rows = [];
  for(const [id, [t, hot]] of Object.entries(R.EVENTIDS)) rows.push(['Windows event', id, t, hot]);
  for(const [id, [t]] of Object.entries(R.SYSMON)) rows.push(['Sysmon event', id, t.replace('Sysmon: ', ''), 0]);
  for(const [p, t] of Object.entries(R.EVIL_PORTS)) rows.push(['Port', p, t, 1]);
  for(const [p, t] of Object.entries(R.PORTS)) rows.push(['Port', p, t, 0]);
  for(const [b, t] of Object.entries(R.LOLBINS)) rows.push(['Binary', b, t, 1]);
  const list = rows.filter(r => !q || r.join(' ').toLowerCase().includes(q));
  return `<div class="scroll"><div class="page narrow">
    <div class="ph"><div><h1>Reference</h1><div class="sub">What an indicator means, offline. The same table explains entities everywhere in the app.</div></div></div>
    <div class="toolbar"><div class="search-in">${ico('search')}<label class="sr" for="refQ">Filter</label><input id="refQ" class="inp" placeholder="4698, 4444, rundll32…" value="${esc(UI.refQ || '')}"></div><span class="t3">${list.length} entries</span></div>
    <section class="card" style="overflow:hidden"><table class="tbl ref"><thead><tr><th>Type</th><th>Value</th><th>Meaning</th><th></th></tr></thead><tbody>
      ${list.map(r => `<tr style="cursor:default"><td class="t3">${esc(r[0])}</td><td class="v">${esc(r[1])}</td><td>${esc(r[2])}</td><td>${r[3] ? '<span class="chip amber sq">Worth a look</span>' : ''}</td></tr>`).join('')}</tbody></table></section></div></div>`;
}

function stub(title, sub, from, what){
  return `<div class="scroll"><div class="page narrow"><div class="ph"><div><h1>${title}</h1><div class="sub">${sub}</div></div></div>
    <section class="card"><div class="body" style="display:flex;gap:16px;align-items:flex-start"><span class="tb lg" style="--c:var(--text-3)">${ico('history')}</span>
      <div><div style="display:flex;gap:10px;align-items:center;margin-bottom:6px"><h3 style="font-size:16px">Coming soon</h3>${impl('planned')}</div>
      <p class="t2" style="margin:0 0 8px">${what}</p><p class="t3" style="margin:0;font-size:13.5px">Source: <code class="mono">${esc(from)}</code>. On the roadmap.</p></div></div></section></div></div>`;
}

function viewSettings(){
  const p = DB.prefs, seg = (k, o) => `<div class="seg">${o.map(([v, l, i]) => `<button data-act="pref" data-k="${k}" data-v="${v}" aria-pressed="${p[k] === v}">${i ? ico(i,'sm') : ''}${l}</button>`).join('')}</div>`;
  const M = [['Cases as colour-coded vaults, typed entries, add / edit forms','real'],['Toolbox with your 94 tools, categories, pin, star, add / edit','real'],['Editable graph (Cytoscape): drag, add, connect, edit, delete, layouts, PNG','real'],
    ['Evidence capture with automatic extraction','real'],['Timeline, story, questions, cited report','real'],['Feeds','mock'],['Detections, query builder, playbooks, library','planned'],['Importing your existing OSINTrix data','planned']];
  return `<div class="scroll"><div class="page"><div class="ph"><div><h1>Settings</h1><div class="sub">Stored in this browser only.</div></div></div>
    <section class="card" style="margin-bottom:18px"><div class="body" style="padding:22px"><div class="about">${logoMark(64)}<div style="flex:1;min-width:220px"><h2>${wordmark().replace('wordmark','wordmark big')}</h2>
      <div class="t2" style="margin-top:4px">${esc(BRAND.tagline)} · <span class="mono">${esc(BRAND.version)}</span></div>
      <div class="wrap"><button class="btn" data-act="showWelcome">${ico('eye','sm')}Show welcome</button></div></div>
      <p class="t3" style="margin:16px 0 0;font-size:13px">A private, browser-only OSINT workspace. Inter and JetBrains Mono (OFL 1.1) · Lucide icons (ISC) · Cytoscape.js (MIT) · jsQR (Apache-2.0) · IEEE OUI list via oui-data (BSD-2) — all bundled, nothing loads from the network. <a href="#/help">Help &amp; FAQ</a></p></div></section>
    <div class="grid cols-2" style="align-items:start">
      <section class="card"><header><h3>Appearance</h3></header><div class="body">
        <div class="field"><span class="label">Theme</span>${seg('theme', [['dark','Dark','moon'],['light','Light','sun']])}</div>
        <div class="field"><span class="label">Text size</span>${seg('size', [['s','Small'],['m','Default'],['l','Large']])}</div>
        <div class="field"><span class="label">Density</span>${seg('density', [['comfortable','Comfortable'],['compact','Compact']])}</div>
        <div class="field" style="margin:0"><label for="tzSel">Show times in</label><select id="tzSel" data-pref="tz">${['UTC','America/New_York','America/Chicago','America/Los_Angeles','Europe/London','Europe/Berlin','Asia/Kolkata','Asia/Tokyo','Australia/Sydney'].map(z => `<option${p.tz === z ? ' selected' : ''}>${z}</option>`).join('')}</select></div></div></section>
      <section class="card"><header><h3>Data</h3></header><div class="body">
        <p class="t2" style="margin:0 0 14px">Everything lives in this browser. Export regularly — see <a href="#/help">Help</a> for backup, import and reset.</p>
        <div class="wrap"><button class="btn" data-act="exportAll">${ico('download','sm')}Export everything</button>${DB.sample ? `<button class="btn" data-act="removeSample">${ico('trash-2','sm')}Remove sample data</button>` : ''}<button class="btn danger" data-act="resetDemo">${ico('undo-2','sm')}Reset to demo</button></div>
        <p class="t3" style="font-size:13px;margin:12px 0 0">${DB.prefs.lastExport ? 'Last exported ' + esc(ago(DB.prefs.lastExport)) + '.' : 'Never exported.'} <a href="#/trash">Trash &amp; restore points</a>${(DB.trash || []).length ? ' · ' + DB.trash.length + ' in trash' : ''}</p>
        <div class="isec"><h4>Recent changes</h4>${DB.log.slice(0, 6).map(l => `<div class="li" style="padding:6px 0"><div class="main2"><b style="font-weight:500;font-size:13.5px">${esc(l.what)}</b></div><span class="end mono">${esc(E.fmtClock(l.at, tz()))}</span></div>`).join('') || '<span class="t3" style="font-size:13.5px">Nothing yet.</span>'}</div></div></section>
      
    </div></div></div>`;
}

function importFeedFile(){
  pickFile('.xml,.rss,.atom,text/xml', txt => {
    const doc = new DOMParser().parseFromString(txt, 'application/xml'); if(doc.querySelector('parsererror')) return toast('Not a valid RSS or Atom file');
    const g = (el, s) => { const x = el.querySelector(s); return x ? x.textContent.trim().replace(/<[^>]*>/g, ' ').slice(0, 2000) : ''; };
    const src = g(doc, 'channel > title') || g(doc, 'feed > title') || 'Imported feed';
    const items = [...doc.querySelectorAll('item, entry')].slice(0, 200).map(it => ({id:uid('f'), source:src, title:g(it, 'title') || '(untitled)', body:g(it, 'description') || g(it, 'summary'), ts:Date.parse(g(it, 'pubDate') || g(it, 'updated')) || Date.now()}));
    if(!items.length) return toast('No items in that file');
    DB.feed.push(...items); mutate('imported ' + items.length + ' feed items'); renderAll(); toast(items.length + ' items imported');
  });
}
function pickFile(accept, cb){
  const i = document.createElement('input'); i.type = 'file'; i.accept = accept;
  i.onchange = () => { const f = i.files && i.files[0]; if(!f) return; if(f.size > 209715200) return toast('That file is over 200 MB'); const r = new FileReader(); r.onload = () => cb(String(r.result), f.name); r.readAsText(f); };
  i.click();
}

/* ---------- Help ---------- */
function viewHelp(){
  const bytes = STORE.bytes || 0, quota = STORE.quota || 0, mb = (bytes / 1048576).toFixed(2);
  const cap = STORE.idb ? (quota ? fmtBytes(quota) : 'hundreds of MB') : '≈5 MB', pct = Math.min(100, Math.round(bytes / (STORE.idb ? (quota || 5e8) : 5 * 1048576) * 100));
  const where = !storageOK ? '<b style="color:var(--red)">Not saving</b> — this browser is blocking storage (private window, blocked site data or an embedded preview). Export before you close the tab.'
    : STORE.idb ? `Saved in IndexedDB${STORE.ls ? ' with a localStorage mirror' : ''}. ${STORE.persisted ? 'Marked <b>persistent</b> — the browser will not clear it to free space.' : 'Not marked persistent — under heavy disk pressure a browser may clear it. Keep backups.'}`
    : 'Saved in localStorage (IndexedDB unavailable). About 5 MB fits.';
  const feat = (icon, col, title, body) => `<div class="hf"><span class="hf-ic" style="--c:${col}">${ico(icon)}</span><div><h3>${title}</h3><p>${body}</p></div></div>`;
  const mod = (href, icon, name, body) => `<a class="hm" href="${href}">${ico(icon,'sm')}<b>${name}</b><span>${body}</span></a>`;
  const kb = (keys, what) => `<div class="hk"><span>${keys.map(k => `<kbd>${k}</kbd>`).join(' ')}</span><span>${what}</span></div>`;
  const qa = (q, a) => `<details class="hq"><summary>${q}${ico('chevron-down','sm')}</summary><p>${a}</p></details>`;
  return `<div class="scroll"><div class="page help">
    <section class="hhero">${logoMark(56)}<div><h1>Welcome to ${esc(BRAND.name)}</h1><p class="hsub">Your personal OSINT workspace — client-side only.</p>
      <p>${esc(BRAND.name)} is a fast, private investigation workspace that runs entirely in your browser. Cases, evidence, entities, tools and notes are stored on this device and never leave it. There is no server, no account and no tracking.</p></div></section>

    <h2 class="hh">Key features &amp; things to know</h2>
    <div class="hgrid">
      ${feat('lock','#10b981','Privacy first','Everything you add is saved only in this browser (IndexedDB, with a localStorage copy). Every change is saved within a quarter of a second and survives reloads and restarts. Nothing is uploaded. The page’s security policy blocks every outside connection except one you opt into (below).')}
      ${feat('download','#3b82f6','Back up regularly','Because data lives in this browser, clearing site data, using a private window or switching browsers means starting empty. Export a JSON backup often — you can import it on another device. Deleted items wait 30 days in the trash, and a restore point is saved before every import, reset or clean-up.')}
      ${feat('rss','#f59e0b','The one network request','Threat Intel is offline until you turn on live feeds. Then only the feed addresses are sent to <span class="mono">api.rss2json.com</span>, the relay the original app used. Your cases never are.')}
      ${feat('wrench','#8b5cf6','Pre-added tools &amp; updates','Default tools come from <span class="mono">tools.json</span>. Delete one and it stays deleted. When the app ships new pre-added tools they are added to your toolbox without touching your own tools, stars or pins.')}
      ${feat('external-link','#ec4899','Opening tools and searches','Tools and query-library searches open in a new tab on the site you chose. What you type into those sites is between you and them — ' + esc(BRAND.name) + ' only logs the search to your case if you tick “Log to case”.')}
      ${feat('maximize','#06b6d4','Best on a larger screen','Everything works on a phone, but the graph, timeline and rule editor are happiest on a laptop or desktop.')}
    </div>

    <h2 class="hh">Important actions</h2>
    <section class="card hact"><div class="hact-store"><div><b>Storage used</b><span>${mb} MB · room for ${cap}</span></div><span class="bar"><i style="width:${Math.max(pct, 1)}%"></i></span></div>
      <p class="hact-note">${where}</p>
      <div class="hact-row">
        <div><h3>${ico('download','sm')}Export your data</h3><p>Downloads one JSON file with every case, note, tool, query, rule and setting.</p><button class="btn primary" data-act="exportAll">${ico('download','sm')}Export everything</button></div>
        <div><h3>${ico('upload','sm')}Import a backup</h3><p>Replaces what is in this browser with a file from “Export everything”. You can undo it right after.</p><button class="btn" data-act="importAll">${ico('upload','sm')}Import backup</button></div>
        <div class="danger"><h3>${ico('triangle-alert','sm')}Reset</h3><p>Use with care. <b>Start fresh</b> deletes all cases and notes; <b>Reset to demo</b> brings back the sample investigation. A restore point is saved first, so you can go back from <a href="#/trash">Trash &amp; restore points</a>.</p>
          <div class="wrap">${DB.sample ? `<button class="btn" data-act="removeSample">${ico('box','sm')}Remove sample data</button>` : ''}<button class="btn dangerbtn" data-act="freshStart">${ico('trash-2','sm')}Start fresh</button><button class="btn" data-act="resetDemo">${ico('undo-2','sm')}Reset to demo</button></div></div>
      </div></section>

    <h2 class="hh">Getting started</h2>
    <ol class="hsteps">
      <li><b>Open a case.</b> Each case is its own vault. Create one from Cases, or explore the demo “Op Lantern”.</li>
      <li><b>Add what you know.</b> People, usernames, emails, domains, IPs, wallets… each type has its own fields, priority and verdict.</li>
      <li><b>Capture evidence.</b> Press <kbd>N</kbd> and paste a log line, a post or a note — or drop in screenshots, files and whole CSV/JSON log exports. Indicators and timestamps are pulled out for you.</li>
      <li><b>Follow the threads.</b> The timeline orders what happened; the graph shows how things connect — drag, right-click, draw links with confidence and proof.</li>
      <li><b>Answer the questions, then report.</b> Pick a report template (full, executive, technical or CTF write-up), redact personal data if needed, and export Markdown or PDF.</li>
    </ol>

    <h2 class="hh">What’s where</h2>
    <div class="hmods">
      ${mod('#/home','layout-dashboard','Dashboard','Your open cases, activity and pinned notes at a glance.')}
      ${mod('#/cases','folder-open','Cases','Vault, timeline, graph, questions and report for each investigation.')}
      ${mod('#/notes','sticky-note','Notes','Sticky notes and to-dos, general or per case.')}
      ${mod('#/toolbox','wrench','Toolbox','Your library of OSINT and security tools, by category.')}
      ${mod('#/queries','scan-search','Query library','Saved search recipes with blanks filled from your vault.')}
      ${mod('#/playbooks','list-checks','Playbooks','Proven investigation checklists you run on a case.')}
      ${mod('#/ctf','flag','CTF','Challenges, flags and write-ups — with a flag finder across the app.')}
      ${mod('#/lab','file-search','Forensics kit','File inspector (Office, PDF, PE/ELF, ZIP, EXIF, YARA), image tools (bit planes, LSB, QR), email headers, IDs & timestamps, network, username generator.')}
      ${mod('#/decoder','binary','Decoder','Decode, encode, defang, hash, decode JWTs and extract IOCs.')}
      ${mod('#/feeds','rss','Threat Intel','Security news checked against your case entities.')}
      ${mod('#/detections','file-code','Detections','Write, keep and test Sigma and YARA rules against your evidence and files.')}
      ${mod('#/entities','fingerprint','Entities','Every indicator across every case.')}
      ${mod('#/reference','book-open','Reference','Ports, Windows and Sysmon event IDs, living-off-the-land binaries.')}
      ${mod('#/trash','trash-2','Trash & restore points','Deleted items for 30 days, and full snapshots taken before big changes.')}
    </div>

    <div class="hcols">
      <section><h2 class="hh">Keyboard shortcuts</h2><div class="card hkeys">
        ${kb(['Ctrl','K'],'Search everything — cases, IOCs, tools, notes, rules, actions')}${kb(['N'],'Capture evidence')}${kb(['E'],'Add a vault entry')}${kb(['/'],'Search everything')}
        ${kb(['1','–','6'],'Switch case tabs')}${kb(['Esc'],'Close a panel or dialog')}${kb(['Ctrl','S'],'Save the rule you are editing')}${kb(['Ctrl','Enter'],'Save a capture or note')}${kb(['Shift','F10'],'Graph menu for the selected node')}</div></section>
      <section><h2 class="hh">Search syntax</h2><div class="card hkeys">
        <p class="t2" style="margin:0 0 10px;font-size:13.5px">The filter box on a case's Timeline tab (or the top search, which offers it) narrows the records. Combine words with filters:</p>
        ${[['in:tools shodan','Search one area (cases, vault, evidence, indicators, notes, tools, queries, rules, playbooks, ctf, news)'],['case:TN-2026-014 dns','Only inside one case'],['"lamp loader" -firewall','Exact phrase, exclude a word'],['host:DC01','Records from one machine'],['verdict:malicious','Only bad indicators'],['type:finding','Findings, notes, questions…'],['tag:intel','Records with a tag'],['after:2026-09-14','Time windows (also before:)'],['source:sysmon','Where the evidence came from']].map(([c, d]) => `<div class="hk"><code class="mono">${c}</code><span>${d}</span></div>`).join('')}</div></section>
    </div>

    <h2 class="hh">Questions</h2>
    <div class="card hfaq">
      ${qa('Is any of my data sent anywhere?', 'No. Cases, entries, evidence, notes, tools, queries and rules stay in this browser. The only outbound request is the optional live-feed relay described above, which receives feed URLs only.')}
      ${qa('My changes disappeared after a refresh — why?', 'Saved data belongs to one browser <i>and</i> one address. The copy you open from your disk (file://…) and the one on GitHub Pages (https://…github.io) are two different places with separate data, and so are Chrome and Firefox, or two browser profiles. Private windows, “clear data on exit” settings and embedded previews (for example a file preview inside another app) do not keep anything. The status in the top bar says “Saved in this browser” when saving works, and a red warning appears when it does not.')}
      ${qa('I cleared my browser and everything is gone. Can I get it back?', 'Only from a backup. There is no copy anywhere else — that is the point. Export regularly, and keep backups somewhere safe.')}
      ${qa('How do I move my work to another computer?', 'Export everything here, open ' + esc(BRAND.name) + ' on the other computer, and use Import backup on this page.')}
      ${qa('How do I share a case with a colleague?', 'Export the case as JSON from its ⋯ menu or the Report tab and send the file; your colleague uses <b>Import case</b> on the Cases page. For readers, use Print / PDF or Markdown. There is deliberately no cloud sharing.')}
      ${qa('Is it safe to paste malware indicators and logs?', 'Yes — everything is shown as plain text and links only open when you click them. Nothing you paste is executed or fetched.')}
      ${qa('Where are screenshots and attached files kept?', 'In this browser’s IndexedDB, next to your cases, up to 50 MB per file. Each one is hashed (SHA-256) when you add it. They are included in “Export everything” and in case exports, so a backup carries them too.')}
      ${qa('How complete are the Sigma and YARA engines?', 'They are small, honest subsets that run in the page. Sigma: selections with field modifiers (contains, startswith, endswith, re, all), wildcards, keyword lists and conditions with and/or/not and “1 of / all of”. YARA: text, hex (with wildcards, jumps and alternatives) and regex strings with nocase/wide/ascii, counts, offsets, filesize and uintXX checks. Anything else — modules such as pe or math, for-loops, aggregations — is reported as unsupported instead of silently passing.')}
      ${qa('Does reverse image search upload my picture?', 'No. The buttons open TinEye, Google Lens, Bing and Yandex in a new tab; you drop the image there yourself. Everything else in the image tools happens in the page.')}
      ${qa('Does it work offline?', 'Yes. Fonts, icons and the graph library are bundled into the single page. Only live threat feeds need a connection — and lookups in other sites, which open in a new tab.')}
    </div>

    <p class="hfoot">${esc(BRAND.name)} ${esc(BRAND.version)} · Inter &amp; JetBrains Mono (OFL 1.1) · Lucide icons (ISC) · Cytoscape.js (MIT) · jsQR (Apache-2.0) · IEEE OUI vendor list via oui-data (BSD-2) · <a href="#/settings">Settings &amp; about</a> · <button class="linkbtn" data-act="showWelcome">Show the welcome screen</button></p>
  </div></div>`;
}
