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
/* ---------- Toolbox: one library, four ways to look at it ----------
   List (with a details panel), Table (sortable, bulk actions), Cards, Compact A–Z. */
const tmono = (t, s = 32) => { const w = String(t.name).match(/[A-Za-z0-9]+/g) || ['?']; const m = w.length > 1 ? (w[0][0] + w[1][0]).toUpperCase().replace(/^(.)(.)$/, (x, a, b) => a + b.toLowerCase()) : (w[0][0].toUpperCase() + (w[0][1] || '').toLowerCase());
  return `<span class="tmo" style="--cc:${catCol(t.cat)};--s:${s}px" aria-hidden="true">${esc(m)}</span>`; };
const tLink = (t, inner, cls = '') => { const u = E.safeUrl(t.url); return u ? `<a class="${cls}" href="${esc(u)}" target="_blank" rel="noopener noreferrer" data-act="toolOpen" data-id="${t.id}">${inner}</a>` : `<span class="${cls}">${inner}</span>`; };
const tStar = (t, cls = 'tb-ic') => `<button class="${cls}${t.starred ? ' on star' : ''}" data-act="toolStar" data-id="${t.id}" aria-label="${t.starred ? 'Remove from favourites' : 'Add to favourites'}" title="Favourite">${ico('star','sm')}</button>`;
const tGo = t => { const u = E.safeUrl(t.url); return u ? `<a class="tb-ic" href="${esc(u)}" target="_blank" rel="noopener noreferrer" data-act="toolOpen" data-id="${t.id}" aria-label="Open ${esc(t.name)} in a new tab" title="Open">${ico('arrow-up-right','sm')}</a>` : ''; };
const tAgo = t => t.last ? esc(E.fmtAgo(Math.max(0, Date.now() - t.last))) : '—';
const tPick = t => `<label class="tpk"><span class="sr">Select ${esc(t.name)}</span><input type="checkbox" data-act="toolPick" data-id="${t.id}"${UI.tpick && UI.tpick.has(t.id) ? ' checked' : ''}></label>`;
/* kept for other modules that show a tool */
function toolCard(t){ return tCard(t); }
function toolRow(t){ return tRow(t); }
function paintBulk(){
  const el = $('tbk'); if(!el) return; const n = UI.tpick ? [...UI.tpick].filter(id => DB.tools.some(t => t.id === id)).length : 0;
  el.hidden = !n; document.querySelectorAll('.tbx2').forEach(x => x.classList.toggle('picking', !!n)); if(!n) return;
  el.innerHTML = `<b>${n} selected</b><button class="btn xs" data-act="bulkAll">Select all shown</button><span class="sep"></span>
    <button class="btn xs" data-act="bulkStar">${ico('star','sm')}Favourite</button><button class="btn xs" data-act="bulkPin">${ico('pin','sm')}Quick launch</button><button class="btn xs" data-act="bulkExport">${ico('download','sm')}Export</button>
    <button class="btn xs rd" data-act="bulkDel">${ico('trash-2','sm')}Delete</button><button class="iconbtn" data-act="bulkClear" aria-label="Clear selection">${ico('x','sm')}</button>`;
}
function tRow(t){
  return `<div class="tr2-r${UI.tsel === t.id ? ' on' : ''}" data-act="toolSel" data-id="${t.id}" data-pick="${t.id}" role="button" tabindex="0" aria-label="${esc(t.name)} — show details">
    ${tPick(t)}<div class="tr2-n">${tmono(t, 32)}<div><b>${esc(t.name)}</b><small>${esc(hostOf(t.url))}</small></div></div>
    <p class="tr2-d">${esc(t.desc || '')}</p>
    <span class="tr2-c"><i class="cdot" style="background:${catCol(t.cat)}"></i>${esc(toolSub(t))}</span>
    <span class="tr2-u" title="Last opened">${tAgo(t)}</span>
    <span class="tr2-a">${t.tpl ? `<button class="tb-ic run" data-act="toolRun" data-id="${t.id}" aria-label="Look something up with ${esc(t.name)}" title="Look up a value">${ico('play','sm')}</button>` : ''}${tStar(t)}${tGo(t)}</span></div>`;
}
function tCard(t){
  return `<article class="tcd-c${UI.tpick && UI.tpick.has(t.id) ? ' picked' : ''}" data-pick="${t.id}">
    <header>${tmono(t, 40)}${tPick(t)}${tStar(t, 'tb-ic tcd-s')}</header>
    <h3>${tLink(t, esc(t.name))}</h3><span class="tcd-h">${esc(hostOf(t.url))}</span>
    <p>${esc(t.desc || 'No description yet.')}</p>
    ${t.tags.length ? `<div class="tcd-t">${t.tags.slice(0, 3).map(g => `<button data-act="toolTag" data-v="${esc(g)}" title="Show tools tagged ${esc(g)}">${esc(g.replace(/-/g, ' '))}</button>`).join('')}</div>` : ''}
    <footer><span class="tr2-c"><i class="cdot" style="background:${catCol(t.cat)}"></i>${esc(toolSub(t))}</span><span class="sp"></span>
      ${t.tpl ? `<button class="tb-ic run" data-act="toolRun" data-id="${t.id}" aria-label="Look something up with ${esc(t.name)}" title="Look up a value">${ico('play','sm')}</button>` : ''}
      <button class="tb-ic" data-act="toolMenu" data-id="${t.id}" aria-label="More actions for ${esc(t.name)}" title="More">${ico('ellipsis','sm')}</button>
      ${tLink(t, 'Open' + ico('arrow-up-right','sm'), 'tcd-o')}</footer></article>`;
}
function tTable(list, sort){
  const th = (k, l, cls = '') => `<th class="${cls}"><button class="th-s" data-act="tsortBy" data-v="${k}" aria-pressed="${sort === k}">${l}${sort === k ? ico('chevron-down','sm') : ''}</button></th>`;
  return `<div class="tblwrap tt"><table class="tbl tt-t"><thead><tr><th class="ck"><label class="tpk"><span class="sr">Select all shown</span><input type="checkbox" data-act="bulkAllT"${UI.tpick && list.length && list.every(t => UI.tpick.has(t.id)) ? ' checked' : ''}></label></th>${th('name','Name')}<th class="hide-m">Link</th><th>Category</th><th class="hide-m">Tags</th>${th('recent','Added','hide-m')}${th('last','Last used')}${th('used','Uses','n')}<th></th></tr></thead><tbody>
    ${list.map(t => `<tr class="${UI.tpick && UI.tpick.has(t.id) ? 'sel' : ''}" data-pick="${t.id}"><td class="ck">${tPick(t)}</td>
      <td class="nm"><div>${tmono(t, 26)}${tLink(t, esc(t.name))}${t.seed ? '' : '<span class="tt-cu">Custom</span>'}</div></td>
      <td class="mo hide-m">${esc(hostOf(t.url))}</td><td><span class="tr2-c"><i class="cdot" style="background:${catCol(t.cat)}"></i>${esc(toolSub(t))}</span></td>
      <td class="hide-m"><span class="tt-tg">${t.tags.slice(0, 2).map(g => `<button data-act="toolTag" data-v="${esc(g)}">${esc(g)}</button>`).join('')}</span></td>
      <td class="mo hide-m">${t.added ? esc(new Date(t.added).toISOString().slice(0, 10)) : '—'}</td><td class="mo">${tAgo(t)}</td><td class="n">${t.uses || '—'}</td>
      <td class="ac">${tStar(t)}<button class="tb-ic" data-act="toolMenu" data-id="${t.id}" aria-label="More actions for ${esc(t.name)}" title="More">${ico('ellipsis','sm')}</button></td></tr>`).join('')}</tbody></table></div>`;
}
function tCompact(list){
  const by = new Map(); list.forEach(t => { const k = /[a-z]/i.test(t.name[0]) ? t.name[0].toUpperCase() : '#'; if(!by.has(k)) by.set(k, []); by.get(k).push(t); });
  const keys = [...by.keys()].sort((a, b) => a === '#' ? -1 : b === '#' ? 1 : a.localeCompare(b));
  return `<div class="tcx">${keys.map(k => `<section><h3>${k}</h3>${by.get(k).map(t => tLink(t, `${tmono(t, 20)}<span>${esc(t.name)}</span>${t.starred ? `<i class="st">${ico('star','sm')}</i>` : ''}`, 'tcx-a')).join('')}</section>`).join('')}</div>`;
}
function tDetail(t){
  if(!t) return '';
  const u = E.safeUrl(t.url);
  return `<aside class="tdet" aria-label="${esc(t.name)} details"><div class="tdet-h">${tmono(t, 46)}<div><h2>${esc(t.name)}</h2><span class="mono">${esc(hostOf(t.url))}</span></div><button class="iconbtn" data-act="toolSelX" aria-label="Close details">${ico('x','sm')}</button></div>
    <div class="tdet-a">${u ? `<a class="btn primary" href="${esc(u)}" target="_blank" rel="noopener noreferrer" data-act="toolOpen" data-id="${t.id}">${ico('arrow-up-right','sm')}Open</a>` : ''}<button class="btn" data-act="toolCopy" data-id="${t.id}">${ico('copy','sm')}Copy link</button><button class="btn" data-act="toolEdit" data-id="${t.id}">${ico('pencil','sm')}Edit</button></div>
    <p>${esc(t.desc || 'No description yet.')}</p>
    ${t.tpl ? `<form class="tdet-q" data-form="toolRun" data-id="${t.id}"><label class="ix" for="tdV">Look up with ${esc(t.name)}</label><div class="r"><input id="tdV" class="inp mono" placeholder="Value — IP, domain, email, hash…" autocomplete="off"><button class="btn">Go</button></div><code>${esc(t.tpl)}</code></form>` : ''}
    <dl class="tdet-kv"><dt>Category</dt><dd class="blk"><i class="cdot" style="background:${catCol(t.cat)}"></i>${esc((TOOL_CATS[t.cat] || {name:t.cat}).name)} · ${esc(toolSub(t))}</dd>
      ${t.tags.length ? `<dt>Tags</dt><dd>${t.tags.map(g => `<button class="tag" data-act="toolTag" data-v="${esc(g)}">${esc(g)}</button>`).join('')}</dd>` : ''}
      <dt>Opened</dt><dd>${t.uses ? `${t.uses} time${t.uses > 1 ? 's' : ''}${t.last ? ' · last ' + tAgo(t) + ' ago' : ''}` : 'Not yet'}</dd>
      <dt>Added</dt><dd>${t.added ? esc(new Date(t.added).toISOString().slice(0, 10)) : '—'}${t.seed ? ' · pre-added' : ' · by you'}</dd></dl>
    <div class="tdet-f"><button class="btn sm${t.starred ? ' on' : ''}" data-act="toolStar" data-id="${t.id}">${ico('star','sm')}${t.starred ? 'Favourite' : 'Add to favourites'}</button><button class="btn sm${t.pinned ? ' on' : ''}" data-act="toolPin" data-id="${t.id}">${ico('pin','sm')}${t.pinned ? 'In quick launch' : 'Quick launch'}</button><span class="sp"></span><button class="btn sm tdel" data-act="toolDelAsk" data-id="${t.id}">${ico('trash-2','sm')}Delete</button></div></aside>`;
}
const TVIEWS = [['list','layout-list','List'],['table','table-2','Table'],['cards','layout-grid','Cards'],['compact','rows-3','Compact']];
const TSETS = [['all','layers','All tools'],['fav','star','Favourites'],['pinned','pin','Quick launch'],['recent','clock','Recently used'],['mine','user','Added by you']];
function viewToolbox(){
  if(UI.tcat === 'fav' || UI.tcat === 'pinned'){ UI.tset = UI.tcat; UI.tcat = 'all'; }
  const set = UI.tset || 'all', q = UI.tq.toLowerCase().trim();
  let view = UI.tview || DB.prefs.tview || 'list'; if(view === 'tiles') view = 'cards'; if(!TVIEWS.some(v => v[0] === view)) view = 'list';
  let sort = UI.tsort || (set === 'recent' ? 'last' : 'name');
  const inSet = t => set === 'fav' ? t.starred : set === 'pinned' ? t.pinned : set === 'recent' ? !!t.last : set === 'mine' ? !t.seed : true;
  const setN = k => DB.tools.filter(t => k === 'fav' ? t.starred : k === 'pinned' ? t.pinned : k === 'recent' ? !!t.last : k === 'mine' ? !t.seed : true).length;
  const base = DB.tools.filter(inSet), cnt = c => base.filter(t => t.cat === c).length;
  const cats = Object.entries(TOOL_CATS).filter(([k]) => k !== 'general' && DB.tools.some(t => t.cat === k));
  if(UI.tcat !== 'all' && !TOOL_CATS[UI.tcat]) UI.tcat = 'all';
  let list = base.filter(t => (UI.tcat === 'all' || (t.cat === UI.tcat && (!UI.tsub || t.sub === UI.tsub))) && (!q || (t.name + ' ' + t.desc + ' ' + t.tags.join(' ') + ' ' + hostOf(t.url)).toLowerCase().includes(q)));
  const byName = (a, b) => a.name.localeCompare(b.name, undefined, {sensitivity:'base'});
  list.sort(sort === 'recent' ? (a, b) => (b.added || 0) - (a.added || 0) : sort === 'used' ? (a, b) => (b.uses || 0) - (a.uses || 0) || byName(a, b) : sort === 'last' ? (a, b) => (b.last || 0) - (a.last || 0) || byName(a, b) : byName);
  const sel = view === 'list' ? DB.tools.find(t => t.id === UI.tsel) : null;
  const subs = UI.tcat !== 'all' ? Object.entries(TOOL_CATS[UI.tcat].children).filter(([sb]) => base.some(t => t.cat === UI.tcat && t.sub === sb)) : [];
  let body;
  if(!list.length) body = empty('wrench', q ? 'No tools match “' + esc(UI.tq) + '”' : 'Nothing here yet', q ? 'Check the spelling, try a tag, or add the tool yourself.' : set === 'fav' ? 'Star a tool to keep it here.' : set === 'pinned' ? 'Pin a tool to add it to quick launch.' : set === 'recent' ? 'Tools you open show up here.' : 'Add a tool or import a list.', `<button class="btn primary" data-act="toolAdd">${ico('plus','sm')}Add tool</button>`);
  else if(view === 'table') body = tTable(list, sort);
  else if(view === 'cards') body = `<div class="tcg">${list.map(tCard).join('')}</div>`;
  else if(view === 'compact') body = tCompact(list);
  else {
    const fav = !q && set === 'all' && sort === 'name' ? list.filter(t => t.starred) : [];
    const rest = fav.length ? list.filter(t => !t.starred) : list;
    body = `<div class="tlst">${fav.length ? `<div class="tr2-g ix">${ico('star','sm')}Favourites<span>${fav.length}</span></div>${fav.map(tRow).join('')}<div class="tr2-g ix">Everything else<span>${rest.length}</span></div>` : ''}${rest.map(tRow).join('')}</div>`;
  }
  const sortL = {name:'Name A–Z', last:'Last used', used:'Most opened', recent:'Recently added'};
  return `<div class="tbx2${sel ? ' has-det' : ''}">
    <header class="tbx2-h"><div class="tbx2-t"><h1>Toolbox</h1><span class="ct">${DB.tools.length}</span></div>
      <div class="search-in tbx2-q">${ico('search')}<label class="sr" for="tq">Search tools</label><input id="tq" class="inp" placeholder="Search tools by name, link or tag" value="${esc(UI.tq)}" autocomplete="off">${UI.tq ? `<button class="iconbtn" data-act="tqClear" aria-label="Clear search">${ico('x','sm')}</button>` : '<kbd>/</kbd>'}</div>
      <div class="tbx2-b"><button class="btn" data-act="toolImport">${ico('upload','sm')}<span>Import</span></button><button class="btn primary" data-act="toolAdd">${ico('plus','sm')}<span>Add tool</span></button></div></header>
    <div class="tbx2-bar"><nav class="tsets" aria-label="Tool lists">${TSETS.map(([k, i, l]) => `<button data-act="tset" data-v="${k}" aria-pressed="${set === k}">${ico(i,'sm')}${l}<small>${setN(k)}</small></button>`).join('')}</nav>
      <div class="tbx2-c"><label class="sr" for="tSort">Sort</label><span class="tsort">${ico('arrow-down-up','sm')}<select id="tSort" class="gsel">${Object.entries(sortL).map(([k, l]) => `<option value="${k}"${sort === k ? ' selected' : ''}>${l}</option>`).join('')}</select></span>
        <div class="seg tvs" role="group" aria-label="View">${TVIEWS.map(([v, i, l]) => `<button data-act="tview" data-v="${v}" aria-pressed="${view === v}" title="${l}" aria-label="${l} view">${ico(i,'sm')}</button>`).join('')}</div></div></div>
    <div class="tchp"><button data-act="tcat" data-v="all" aria-pressed="${UI.tcat === 'all'}">All<small>${base.length}</small></button>${cats.map(([k, c]) => `<button data-act="tcat" data-v="${k}" aria-pressed="${UI.tcat === k}"><i class="cdot" style="background:${catCol(k)}"></i>${esc(c.name.split(' &')[0])}<small>${cnt(k)}</small></button>`).join('')}</div>
    ${subs.length > 1 ? `<div class="tchp sub">${subs.map(([sb, l]) => `<button data-act="tsub" data-v="${sb}" aria-pressed="${UI.tsub === sb}">${esc(l)}<small>${base.filter(t => t.sub === sb).length}</small></button>`).join('')}</div>` : ''}
    <div class="tbk" id="tbk" hidden></div>
    <div class="tbx2-m"><div class="tbx2-l" id="tlist">${list.length && view !== 'compact' ? `<p class="tbx2-n">${list.length === DB.tools.length ? list.length + ' tools' : list.length + ' of ' + DB.tools.length + ' tools'}${q ? ' matching “' + esc(UI.tq) + '”' : ''} · ${sortL[sort].toLowerCase()}</p>` : ''}${body}</div>${sel ? '<div class="tdet-scrim" data-act="toolSelX" aria-hidden="true"></div>' : ''}${tDetail(sel)}</div></div>`;
}
/* layout switcher shared by Toolbox, Query library and Detections */
const layoutSeg = (act, cur, opts) => `<div class="seg lseg" role="group" aria-label="Layout">${opts.map(([v, i, l]) => `<button data-act="${act}" data-v="${v}" aria-pressed="${cur === v}" title="${l} layout">${ico(i,'sm')}<span>${l}</span></button>`).join('')}</div>`;
function viewEntities(){
  const g = [...globalEnts().values()];
  const eq = (UI.entq || '').toLowerCase();
  const ec = UI.entCase && DB.cases.some(c => c.id === UI.entCase) ? UI.entCase : '';
  let list = g.filter(e => (!ec || e.cases.has(ec)) && (!UI.entKind || (UI.entKind === 'malicious' ? verdictOf(e.id) === 'malicious' : UI.entKind === 'cross' ? e.cases.size > 1 : true)) && (!eq || (e.v + ' ' + (E.LABEL[e.k] || e.k)).toLowerCase().includes(eq)));
  UI.entList = list;
  list.sort((a, b) => b.recs.length - a.recs.length);
  return `<div class="scroll"><div class="page">
    <div class="ph"><div><h1>Entities</h1><div class="sub">Every indicator across every case, whether you added it to a vault or it was extracted from evidence. Each case also has its own Entities tab.</div></div></div>
    <div class="toolbar"><div class="search-in">${ico('search')}<label class="sr" for="entq">Search entities</label><input id="entq" class="inp" placeholder="Search values…" value="${esc(UI.entq || '')}"></div><label class="sr" for="entCase">Case</label><select id="entCase" class="gsel bord"><option value="">All cases</option>${DB.cases.map(c => `<option value="${c.id}"${ec === c.id ? ' selected' : ''}>${esc(c.code + ' · ' + c.name.split(' — ')[0])}</option>`).join('')}</select><div class="seg">${[['','All ' + g.length],['malicious','Malicious'],['cross','In 2+ cases']].map(([v, l]) => `<button data-act="entKind" data-v="${v}" aria-pressed="${(UI.entKind || '') === v}">${l}</button>`).join('')}</div><span style="flex:1"></span><span class="t3">${list.length} shown</span><button class="btn" data-act="entExport">${ico('download','sm')}Export CSV</button></div>
    <section class="card" style="overflow:hidden"><table class="tbl cardify"><thead><tr><th>Entity</th><th>Verdict</th><th style="text-align:right">Records</th><th class="hide-m">Cases</th><th>What it is</th></tr></thead><tbody>
    ${list.slice(0, 150).map(e => { const m = E.meaning(e.k, e.v);
      return `<tr data-act="selEnt" data-id="${esc(e.id)}"><td><div style="display:flex;gap:10px;align-items:center;min-width:0">${kindBadge(e.k,'sm')}<div style="min-width:0"><div class="v">${esc(e.v)}</div><div class="t3" style="font-size:12.5px">${esc(E.LABEL[e.k] || e.k)}</div></div></div></td>
        <td>${vdLabel(verdictOf(e.id)) || '<span class="t3">—</span>'}</td><td class="n">${e.recs.length}</td><td class="hide-m"><div class="wrap" style="gap:4px">${[...e.cases].filter(theCase).slice(0, 3).map(cid => { const o = theCase(cid); return `<a class="ce-case" href="${caseHash(cid, 'entities')}" style="--cc:${esc(o.color)}" title="${esc(o.name)}">${esc(o.code)}</a>`; }).join('')}${e.cases.size > 3 ? `<span class="t3">+${e.cases.size - 3}</span>` : ''}</div></td><td class="t2 hide-m" style="font-size:13.5px">${m ? esc(m.t) : '—'}</td></tr>`; }).join('')}
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
  const q = (UI.refQ || '').trim().toLowerCase(), cat = REFDATA[UI.refCat] ? UI.refCat : 'all', only = !!UI.refHot;
  const match = r => (!q || r.slice(0, 5).join(' ').toLowerCase().includes(q)) && (!only || r[5]);
  const secs = Object.entries(REFDATA).filter(([k]) => cat === 'all' || cat === k).map(([k, S]) => [k, S, S.rows.filter(match)]).filter(x => x[2].length);
  const total = Object.values(REFDATA).reduce((n, S) => n + S.rows.length, 0), shown = secs.reduce((n, x) => n + x[2].length, 0);
  const hot = Object.values(REFDATA).reduce((n, S) => n + S.rows.filter(r => r[5]).length, 0);
  const key = (k, r) => k + ':' + r[0];
  const flat = secs.flatMap(([k, S, rows]) => rows.map(r => [k, S, r]));
  let cur = flat.find(([k, S, r]) => key(k, r) === UI.refRow) || flat[0];
  const row = (k, r) => `<button class="rf2-r${cur && key(cur[0], cur[2]) === key(k, r) ? ' on' : ''}" data-act="refRow" data-v="${esc(key(k, r))}"><code>${esc(r[0])}</code><span class="rf2-t">${esc(r[1])}</span>${r[5] ? '<em>Worth a look</em>' : '<i></i>'}<span class="rf2-at">${esc(r[4] || '')}</span></button>`;
  const det = cur ? (([k, S, r]) => `<aside class="rf2-d${UI.refOpen ? ' open' : ''}" aria-label="${esc(r[0])} details">
      <div class="rf2-dh"><span class="ix">${ico(S.icon,'sm')}${esc(S.name)}</span><button class="iconbtn rf2-x" data-act="refRowX" aria-label="Close">${ico('x','sm')}</button></div>
      <div class="rf2-k">${esc(r[0])}</div><h2>${esc(r[1])}</h2>
      ${r[5] ? '<span class="rf2-hot">Worth a look</span>' : ''}
      <h5>What it means</h5><p>${esc(r[2])}</p>
      <h5>What to look for</h5><p>${esc(r[3])}</p>
      ${r[4] ? `<h5>MITRE ATT&amp;CK</h5><p><a class="rf2-att" href="https://attack.mitre.org/techniques/${esc(r[4].replace('.', '/'))}/" target="_blank" rel="noopener noreferrer">${esc(r[4])} ${ico('arrow-up-right','sm')}</a></p>` : ''}
      <div class="rf2-a"><button class="btn primary sm" data-act="refFind" data-v="${esc(r[0].replace(/^.*\\/, ''))}">${ico('search','sm')}Search my evidence</button><button class="btn sm" data-act="flagCopy" data-v="${esc(r[0])}">${ico('copy','sm')}Copy</button></div>
      <p class="rf2-note">${esc(S.note)}</p></aside>`)(cur) : '';
  return `<div class="scroll rf2-scroll"><div class="rf2">
    <section class="rf2-ink"><div class="rf2-in">
      <span class="ix">Knowledge · offline field guide</span><h1>Reference</h1><p>What an event ID, port, binary or code means — and what to check next.</p>
      <div class="search-in rf2-q">${ico('search')}<label class="sr" for="refQ">Search the reference</label><input id="refQ" class="inp" placeholder="4769, 4444, rundll32, kerberoast, T1059…" value="${esc(UI.refQ || '')}" autocomplete="off">${UI.refQ ? `<button class="iconbtn" data-act="refClear" aria-label="Clear">${ico('x','sm')}</button>` : '<kbd>/</kbd>'}</div>
      <div class="rf2-stat"><div><b>${total}</b><small>entries</small></div><div><b>${Object.keys(REFDATA).length}</b><small>sections</small></div><div><b>${hot}</b><small>worth a look</small></div></div>
      <nav class="rf2-tabs" aria-label="Sections"><button data-act="refCat" data-v="all" aria-pressed="${cat === 'all'}">Everything<small>${total}</small></button>${Object.entries(REFDATA).map(([k, S]) => `<button data-act="refCat" data-v="${k}" aria-pressed="${cat === k}">${esc(S.name)}<small>${S.rows.length}</small></button>`).join('')}</nav>
    </div></section>
    <div class="rf2-in rf2-body">
      <div class="rf2-tb"><span>${shown === total ? total + ' entries' : shown + ' of ' + total}${q ? ' matching “' + esc(UI.refQ) + '”' : ''}</span><label class="chk"><input type="checkbox" data-act="refHot" ${only ? 'checked' : ''}> Only “worth a look”</label></div>
      ${flat.length ? `<div class="rf2-g"><div class="rf2-l">${secs.map(([k, S, rows]) => `${cat === 'all' ? `<div class="rf2-sh">${ico(S.icon,'sm')}${esc(S.name)}<small>${rows.length}</small></div>` : ''}${rows.map(r => row(k, r)).join('')}`).join('')}</div>${det}</div>`
        : `<div class="hx2-empty">Nothing matches “${esc(UI.refQ || '')}”.${only ? ' Try turning off “Only worth a look”.' : ''}</div>`}
      ${UI.refOpen ? '<div class="rf2-scrim" data-act="refRowX" aria-hidden="true"></div>' : ''}
    </div></div></div>`;
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
      <div class="wrap" style="align-items:center"><button class="btn" data-act="showWelcome">${ico('eye','sm')}Show welcome</button></div></div>
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
        <p class="t3" style="font-size:13px;margin:12px 0 0">${DB.prefs.lastExport ? 'Last exported ' + esc(ago(DB.prefs.lastExport)) + '.' : 'Never exported.'} <a href="#/trash">Trash &amp; restore points</a> · <a href="#/security">Security &amp; audit</a>${(DB.trash || []).length ? ' · ' + DB.trash.length + ' in trash' : ''}</p>
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
    : STORE.idb ? `Saved in IndexedDB${STORE.ls ? ' with a localStorage mirror' : ''}. ${STORE.persisted ? 'Marked persistent — the browser will not clear it to free space.' : 'Not marked persistent — under heavy disk pressure a browser may clear it. Keep backups.'}`
    : 'Saved in localStorage (IndexedDB unavailable). About 5 MB fits.';
  const last = DB.prefs.lastExport, stale = !last || Date.now() - last > 14 * 864e5;
  const feat = (icon, col, title, body) => `<div class="hx2-k hs-i">${ico(icon,'sm')}<div><h3>${title}</h3><p>${body}</p></div></div>`;
  const kb = (keys, what) => `<div class="hk hs-i"><span>${keys.map(k => `<kbd>${k}</kbd>`).join(' ')}</span><span>${what}</span></div>`;
  const qa = (q, a) => `<details class="hq hs-i"><summary>${q}${ico('chevron-down','sm')}</summary><p>${a}</p></details>`;
  const pic = n => typeof WL_IMG !== 'undefined' ? `<img class="hx2-d" src="${WL_IMG[n + '-dark']}" alt="" loading="lazy" decoding="async"><img class="hx2-l" src="${WL_IMG[n + '-light']}" alt="" loading="lazy" decoding="async">` : '';
  const start = [['capture','dashboard','Capture your first evidence','Paste a log line, a post or a WHOIS record — indicators and times come out on their own.','2 min'],
    ['welcomeDemo','graph','Explore the demo case','Op Lantern has the timeline, link graph, map and report already filled in.','4 min'],
    ['helpWelcome','phone','Take the welcome tour','What OSINTrix is for, how your data stays private, and where everything lives.','1 min']];
  const dir = [['Investigate',[['#/home','Dashboard','Open cases, activity and pinned notes'],['#/cases','Cases','Vault, timeline, graph, questions and report'],['#/notes','Notes','Sticky notes and to-dos'],['#/entities','Entities','Every indicator across every case'],['#/trash','Trash & restore points','Deleted items and snapshots']]],
    ['Research',[['#/toolbox','Toolbox','Your library of OSINT and security tools'],['#/queries','Query library','Search recipes filled from your vault'],['#/playbooks','Playbooks','Investigation checklists for a case'],['#/feeds','Threat Intel','News checked against your entities'],['#/watch','Watchlist','Entities you track']]],
    ['Lab',[['#/lab','Forensics kit','Files, PCAP, SQLite, images, email headers'],['#/decoder','Decoder','Decode, encode, defang, hash, JWT'],['#/ctf','CTF','Challenges, flags and write-ups'],['#/detections','Detections','Sigma and YARA, tested on your evidence']]],
    ['Data & security',[['#/security','Security & audit','Encryption, audit chain, signed reports'],['#/reference','Reference','Ports, event IDs, LOLBins, ATT&CK'],['#/settings','Settings & about','Time zone, theme and version'],['#hx-data','Back up and restore','Export, import and reset this browser']]]];
  const pop = [['backup','Back up and restore'],['another computer','Move to another computer'],['encrypt','Encrypt the workspace'],['pcap','Read a packet capture'],['share','Share a case'],['offline','Works offline?']];
  return `<div class="scroll"><div class="hx2">
    <section class="hx2-hero"><div class="hx2-in">
      <span class="ix">Help · ${esc(BRAND.name)} ${esc(BRAND.version)} · works offline</span>
      <h1>How can we help?</h1><p>Guides and answers for every part of ${esc(BRAND.name)}. Nothing here leaves your browser.</p>
      <div class="search-in hx2-q">${ico('search')}<label class="sr" for="hxq">Search help</label><input id="hxq" class="inp" placeholder="Search guides and questions — try “move to another computer”" autocomplete="off"><kbd>/</kbd></div>
      <div class="hx2-pop"><span>Popular</span>${pop.map(([q, l]) => `<button data-act="helpQ" data-v="${esc(q)}">${l}</button>`).join('')}</div>
      <p class="hx2-n" id="hxqN" hidden></p></div></section>
    <div class="hx2-in hx2-body">
      <section class="hx2-sec hx2-start"><header><h2>Start here</h2><button class="linkbtn" data-act="showWelcome">Show the welcome screen ${ico('arrow-right','sm')}</button></header>
        <div class="hx2-cards">${start.map(([act, img, t, d, m]) => `<button class="hx2-c" data-act="${act}"><span class="hx2-im">${pic(img)}</span><span class="hx2-ct"><b>${t}</b><small>${d}</small><i>${m}</i></span></button>`).join('')}</div></section>
      <section class="hx2-sec hx2-dir"><header><h2>Browse by area</h2></header><div class="hx2-cols">${dir.map(([g, xs]) => `<div><span class="ix">${g}</span>${xs.map(([h, n, d]) => h[0] === '#' && h[1] !== '/' ? `<button class="hs-i" data-act="helpGo" data-v="${h.slice(1)}"><b>${n}</b><small>${d}</small></button>` : `<a class="hs-i" href="${h}"><b>${n}</b><small>${d}</small></a>`).join('')}</div>`).join('')}</div></section>
      <section class="hx2-sec hx2-strip" id="hx-data"><div class="hx2-data">
          <span class="ix">Your data · this browser</span>
          <div class="hx2-dn"><b class="mono">${mb} MB</b><span>of ${cap}</span><span class="hx2-st${stale ? ' warn' : ''}"><i></i>${last ? 'Last backup ' + esc(E.fmtAgo(Date.now() - last)) + ' ago' : 'Never backed up'}</span></div>
          <span class="bar"><i style="width:${Math.max(pct, 1)}%"></i></span>
          <p>${where}</p>
          <div class="hx2-b"><button class="btn primary sm" data-act="exportAll">${ico('download','sm')}Back up everything</button><button class="btn sm" data-act="importAll">${ico('upload','sm')}Restore a backup</button><span class="sp"></span><button class="btn sm ghost hx2-rs" data-act="helpReset">${ico('triangle-alert','sm')}Reset…</button></div></div>
        <div class="hx2-keys"><span class="ix">Keyboard</span><div class="hx2-kg">${[['Ctrl K','Search everything'],['N','Capture evidence'],['E','New vault entry'],['/','Search this page'],['1 – 8','Case tabs'],['Esc','Close a panel']].map(([k, v]) => `<kbd>${k}</kbd><span>${v}</span>`).join('')}</div><button class="linkbtn" data-act="helpGo" data-v="hx-keys">All shortcuts and search syntax ${ico('arrow-right','sm')}</button></div></section>
      <section class="hx2-sec" id="hx-faq"><header><h2>Questions</h2><span class="ix">Click to open</span></header>
    <div class="card hfaq">
      ${qa('Is any of my data sent anywhere?', 'No. Cases, entries, evidence, notes, tools, queries and rules stay in this browser. The only outbound request is the optional live-feed relay described above, which receives feed URLs only.')}
      ${qa('My changes disappeared after a refresh — why?', 'Saved data belongs to one browser <i>and</i> one address. The copy you open from your disk (file://…) and the one on GitHub Pages (https://…github.io) are two different places with separate data, and so are Chrome and Firefox, or two browser profiles. Private windows, “clear data on exit” settings and embedded previews (for example a file preview inside another app) do not keep anything. The status in the top bar says “Saved in this browser” when saving works, and a red warning appears when it does not.')}
      ${qa('I cleared my browser and everything is gone. Can I get it back?', 'Only from a backup. There is no copy anywhere else — that is the point. Export regularly, and keep backups somewhere safe.')}
      ${qa('How do I move my work to another computer?', 'Export everything here, open ' + esc(BRAND.name) + ' on the other computer, and use Import backup on this page.')}
      ${qa('How do I share a case with a colleague?', 'Export the case as JSON from its ⋯ menu or the Report tab and send the file; your colleague uses <b>Import case</b> on the Cases page. For readers, use Print / PDF or Markdown. There is deliberately no cloud sharing.')}
      ${qa('Is it safe to paste malware indicators and logs?', 'Yes — everything is shown as plain text and links only open when you click them. Nothing you paste is executed or fetched.')}
      ${qa('Where are screenshots and attached files kept?', 'In this browser’s IndexedDB, next to your cases, up to 50 MB per file. Each one is hashed (SHA-256) when you add it. They are included in “Export everything” and in case exports, so a backup carries them too.')}
      ${qa('How complete are the Sigma and YARA engines?', 'They are small, honest subsets that run in the page. Sigma: selections with field modifiers (contains, startswith, endswith, re, all), wildcards, keyword lists and conditions with and/or/not and “1 of / all of”. YARA: text, hex (with wildcards, jumps and alternatives) and regex strings with nocase/wide/ascii, counts, offsets, filesize and uintXX checks. Anything else — modules such as pe or math, for-loops, aggregations — is reported as unsupported instead of silently passing.')}
      ${qa('How safe is encryption, and what if I forget the passphrase?', 'Security → Encrypt this workspace seals your cases, notes, restore points and attached files with AES-256-GCM, using a key derived from your passphrase (PBKDF2-SHA-256, 310,000 rounds). The passphrase is never stored or sent anywhere, so nobody — including us — can recover it. Forget it and the only way forward is to erase the workspace. Keep an encrypted backup somewhere safe. The app can also lock itself after a period of inactivity.')}
      ${qa('What does the audit log prove?', 'Every change is added to a hash chain, where each entry includes the hash of the one before it. Editing, removing or reordering a past entry breaks the chain, and Verify shows where. A chain-of-custody report lists every record of a case with its SHA-256, capture time and attached files, and is signed with this workspace\'s key — anyone can check it under Security → Verify a report. It proves the report was not altered after signing. It cannot stop someone with full access to your unencrypted browser from rewriting everything before a report is made, which is another reason to turn on encryption.')}
      ${qa('How do I archive a web page?', 'Open the page in your browser and press Ctrl+S (⌘+S on a Mac). In Chrome or Edge choose “Webpage, Single File” (.mhtml); in Firefox “Web Page, HTML only”. Then open Capture and click <b>Saved web page…</b>, or drop the file into Capture. You get an evidence entry with the title, URL, author, dates, text, outbound links and entities, plus the original file with its SHA-256. Open it later from the entry’s attachments.')}
      ${qa('Can it read packet captures?', 'Yes — Forensics kit → PCAP opens .pcap and .pcapng files. You see conversations, hosts, DNS, DHCP, HTTP (with files), TLS server names and JA3 fingerprints, cleartext logins, and findings such as beacons, scans and ARP spoofing. Encrypted traffic cannot be decrypted without its keys, but its metadata is still shown. “Send events to timeline” adds the lookups, requests and connections to a case.')}
      ${qa('How do I look at browser history or phone databases?', 'Forensics kit → SQLite opens any SQLite file: Chrome, Edge, Brave, Firefox and Safari history, cookies and saved-login lists (passwords stay encrypted), Android SMS and call logs, iPhone messages, WhatsApp. Dates are converted for you. “Deleted data” shows text left on free pages by deleted rows. The file is opened as a copy, so the original never changes.')}
      ${qa('Why does a form refuse to save?', 'A red message under the field says what to fix: a required field is empty, a value is in the wrong format (email, domain, IP, URL, CVE, hash, date, ATT&amp;CK ID, regular expression), or the name is already used. Cases, tools, queries, rules, playbooks, parsers, CTF events and challenges, and hypotheses need unique names so you can tell them apart. For a likely duplicate — the same vault entry or tool address twice — you get a warning, and pressing Save again keeps both.')}
      ${qa('How can I tell a copy from the original?', 'Duplicates are named “… (copy)”, then “… (copy 2)” and so on, and appear right after the original. Imported items whose name is already taken get “(imported)”.')}
      ${qa('Does the map send my locations anywhere?', 'Not with the default outline map, which is drawn from data inside the app. Streets and light maps download tiles from CARTO, and the satellite map from Esri. Those servers see which area you are looking at (never your case), so the app asks before switching. If tiles cannot be loaded — offline, or blocked on your network — it tells you and goes back to the outline map.')}
      ${qa('Is it safe to open a saved web page?', 'Yes. A saved .html or .mhtml page is read without running it, and the original is viewed in a sandbox with scripts off. The app blocks every outside request, so tracking pixels and remote images never load. Images and SVG files you attach are shown as pictures, which cannot run code.')}
      ${qa('Why does “Open all” in the research checklist only open one tab?', 'Browsers allow one new tab per click unless you allow pop-ups for the site. Allow them once, or use “Open next”, which ticks each lookup off as you go.')}
      ${qa('Which log formats are understood?', 'JSON, CEF, LEEF, Windows event XML, Apache/Nginx access logs, IIS/W3C and Zeek (with their #Fields header), Cisco ASA, sshd/sudo, and key=value logs such as FortiGate, Sysmon text, iptables or Linux audit. Also “Label: value” blocks like WHOIS or email headers, with or without a syslog header in front. Vendor field names are mapped to common ones (src.ip, dst.port, user, action, url…), so <span class="mono">dst.port:443</span> or <span class="mono">action:deny</span> work in any timeline filter, Sigma rules see the fields, and source → destination becomes a graph relation. For anything else, open <a href="#/lab">Forensics kit → Log parser</a>: it drafts a regular expression from a sample line, you rename the groups, and your parser runs first from then on.')}
      ${qa('Why is an entity missing from the graph?', 'The graph draws vault entries, so extracted indicators stay off it until you add them — nothing clutters it without asking. The graph tells you how many are waiting. <b>Choose…</b> lets you tick the ones you want, <b>Add by rule…</b> adds by kind with filters, and the Entities tab and the capture “Add to graph” switch do the same.')}
      ${qa('How does the graph link things on its own?', 'Only when the evidence says so. A URL is linked to its domain, an email to its domain and a profile to its handle. DNS answers, Sysmon connections, email From/To/Reply-To, WHOIS registrant and name servers, and zone-file lines become relationships. So do phrases such as “resolves to”, “beacons to”, “hosted on” or “aka” placed directly between two indicators. Everything else — seen in the same record, within two minutes on one host, look-alike usernames, a shared IP or registrant — is only offered under <b>Suggested links</b>, with the reason, for you to accept or dismiss. Auto-created links are grey, and dashed when their confidence is low.')}
      ${qa('Where do the cloud, Tor and disposable-email labels come from?', 'From lists bundled with the app, so nothing is looked up online: cloud IPv4 ranges (AWS, Google Cloud, Azure, Oracle, DigitalOcean, Linode, Cloudflare, Vultr, Telegram) via lord-alfred/ipranges, Tor exit nodes via SecOps-Institute/Tor-IP-Addresses, and disposable email domains via disposable-email-domains — all snapshots from ' + esc(typeof ENR !== 'undefined' && ENR && ENR.date ? ENR.date : 'September 2026') + '. Dynamic DNS, URL shorteners, paste sites and free-hosting lists are built in. Treat them as hints, not verdicts: Tor exits and cloud ranges change daily.')}
      ${qa('Does reverse image search upload my picture?', 'No. The buttons open TinEye, Google Lens, Bing and Yandex in a new tab; you drop the image there yourself. Everything else in the image tools happens in the page.')}
      ${qa('Does it work offline?', 'Yes. Fonts, icons and every library ship with the app itself — nothing loads from a CDN. There is also a one-file offline copy you can make with tools/bundle.py. Only live threat feeds need a connection — and lookups in other sites, which open in a new tab.')}
    </div>
      </section>
      <section class="hx2-sec" id="hx-know"><header><h2>Things to know</h2></header><div class="hx2-know">
      ${feat('lock','#10b981','Privacy first','Everything you add is saved only in this browser (IndexedDB, with a localStorage copy). Every change is saved within a quarter of a second and survives reloads and restarts. Nothing is uploaded. The page’s security policy blocks every outside connection except one you opt into (below).')}
      ${feat('download','#3b82f6','Back up regularly','Because data lives in this browser, clearing site data, using a private window or switching browsers means starting empty. Export a JSON backup often — you can import it on another device. Deleted items wait 30 days in the trash, and a restore point is saved before every import, reset or clean-up.')}
      ${feat('rss','#f59e0b','The one network request','Threat Intel is offline until you turn on live feeds. Then only the feed addresses are sent to <span class="mono">api.rss2json.com</span>, the relay the original app used. Your cases never are.')}
      ${feat('wrench','#8b5cf6','Pre-added tools &amp; updates','Default tools come from <span class="mono">tools.json</span>. Delete one and it stays deleted. When the app ships new pre-added tools they are added to your toolbox without touching your own tools, stars or pins.')}
      ${feat('external-link','#ec4899','Opening tools and searches','Tools and query-library searches open in a new tab on the site you chose. What you type into those sites is between you and them — ' + esc(BRAND.name) + ' only logs the search to your case if you tick “Log to case”.')}
      ${feat('maximize','#06b6d4','Best on a larger screen','Everything works on a phone, but the graph, timeline and rule editor are happiest on a laptop or desktop.')}
      </div></section>
      <section class="hx2-sec" id="hx-keys"><div class="hcols">
      <section><h2 class="hh">Keyboard shortcuts</h2><div class="card hkeys">
        ${kb(['Ctrl','K'],'Search everything — cases, IOCs, tools, notes, rules, actions')}${kb(['N'],'Capture evidence')}${kb(['E'],'Add a vault entry')}${kb(['/'],'Search everything')}
        ${kb(['1','–','8'],'Switch case tabs')}${kb(['Esc'],'Close a panel or dialog')}${kb(['Ctrl','S'],'Save the rule you are editing')}${kb(['Ctrl','Enter'],'Save a capture or note')}${kb(['Shift','F10'],'Graph menu for the selected node')}</div></section>
      <section><h2 class="hh">Search syntax</h2><div class="card hkeys">
        <p class="t2" style="margin:0 0 10px;font-size:13.5px">The filter box on a case's Timeline tab (or the top search, which offers it) narrows the records. Combine words with filters:</p>
        ${[['in:tools shodan','Search one area (cases, vault, evidence, indicators, notes, tools, queries, rules, playbooks, ctf, news)'],['case:TN-2026-014 dns','Only inside one case'],['"lamp loader" -firewall','Exact phrase, exclude a word'],['host:DC01','Records from one machine'],['verdict:malicious','Only bad indicators'],['type:finding','Findings, notes, questions…'],['tag:intel','Records with a tag'],['after:2026-09-14','Time windows (also before:)'],['source:sysmon','Where the evidence came from']].map(([c, d]) => `<div class="hk hs-i"><code class="mono">${c}</code><span>${d}</span></div>`).join('')}</div></section>
      </div></section>
      <p class="hx2-empty" id="hxqE" hidden></p>
    <p class="hfoot">${esc(BRAND.name)} ${esc(BRAND.version)} · Inter &amp; JetBrains Mono (OFL 1.1) · Lucide icons (ISC) · Cytoscape.js (MIT) · jsQR (Apache-2.0) · IEEE OUI vendor list via oui-data (BSD-2) · cloud ranges &amp; disposable domains (CC0) · Natural Earth map (public domain) · <a href="#/settings">Settings &amp; about</a> · <button class="linkbtn" data-act="showWelcome">Show the welcome screen</button></p>
    </div></div></div>`;
}
