/* ==========================================================================
   Query library — replaces the Dork Assistant's AI-style builder with what
   analysts actually reuse: saved search templates with {{VARIABLES}} that
   fill from a vault entry, open in the right engine, and leave a research
   trail in the case. Seeded from the original dork_templates.json.
   ========================================================================== */
const ENGINES = {
  google:['Google','https://www.google.com/search?q='], bing:['Bing','https://www.bing.com/search?q='], duckduckgo:['DuckDuckGo','https://duckduckgo.com/?q='],
  shodan:['Shodan','https://www.shodan.io/search?query='], censys:['Censys','https://search.censys.io/search?resource=hosts&q='],
  github:['GitHub code','https://github.com/search?type=code&q='], zoomeye:['ZoomEye','https://www.zoomeye.hk/searchResult?q='],
  fofa:['FOFA','https://en.fofa.info/result?qbase64=', true], intelx:['Intelligence X','https://intelx.io/?s='],
};
const QCATS = {osint:['OSINT','#8b5cf6'], people:['People','#8b5cf6'], social:['Social','#ec4899'], files:['Files & documents','#0ea5a4'], 'code & files':['Code','#0ea5a4'],
  databases:['Databases','#3b82f6'], cloud:['Cloud storage','#06b6d4'], vulnerabilities:['Vulnerabilities','#f59e0b'], iot:['IoT & devices','#f97316'], network:['Network','#3b82f6'],
  login:['Login panels','#e5484d'], web:['Web','#5468ff'], government:['Government','#64748b'], 'data leaks':['Data leaks','#e5484d'], crypto:['Crypto','#eab308'],
  'dark-web':['Dark web','#6b7280'], 'remote-access':['Remote access','#f97316'], custom:['My queries','#5468ff']};
const qcat = c => QCATS[c] || [c, '#5468ff'];
const varsOf = q => [...new Set((String(q).match(/\{\{\s*([A-Z0-9_]+)\s*\}\}/gi) || []).map(v => v.replace(/[{}\s]/g, '').toUpperCase()))];
/* which vault field fills which variable */
const VAR_FILL = {DOMAIN_NAME:['domain','url','email'], COMPANY_DOMAIN:['domain','email'], TARGET_SITE:['domain','url'], EMAIL_DOMAIN:['email','domain'], FULL_NAME:['person'],
  ENTITY_NAME:['person','organization','username','alias'], CVE_ID:['vulnerability'], USERNAME:['username','social'], IP:['ip'], EMAIL:['email']};
function fillFrom(v, e){
  if(!e) return ''; let val = primary(e);
  if(/DOMAIN|SITE/.test(v)){ if(e.type === 'email') val = val.split('@')[1] || val; if(e.type === 'url') val = hostOf(val) || val; }
  if(e.type === 'username') val = val.replace(/^@/, '');
  return val;
}
function ensureQueries(){
  if(DB.queries) return;
  const seen = new Set();
  DB.queries = QUERY_SEED.filter(q => { const k = q.query.trim(); if(seen.has(k)) return false; seen.add(k); return true; })
    .map(q => ({id:'q' + q.id, name:q.name, desc:q.description || '', query:q.query, cat:q.category || 'custom', engines:(q.engines || ['google']).filter(x => ENGINES[x]).concat(q.engines && q.engines.some(x => ENGINES[x]) ? [] : ['google']), tags:q.tags || [], starred:false, uses:0, custom:false}));
  DB.queryLog = [];
}
function engineUrl(eng, q){
  const e = ENGINES[eng] || ENGINES.google;
  const enc = e[2] ? (() => { try{ return encodeURIComponent(btoa(unescape(encodeURIComponent(q)))); }catch(x){ return ''; } })() : encodeURIComponent(q);
  return E.safeUrl(e[1] + enc);
}
const qLay = () => ['table','gallery','ide'].includes(DB.prefs.qlay) ? DB.prefs.qlay : 'table';
const qMark = s => esc(s).replace(/\{\{\s*([A-Z0-9_]+)\s*\}\}/gi, '<mark>{{$1}}</mark>');
/* the three shells every library screen shares: drawer, full page, and IDE panes */
const drawer = (body, closeAct, label, kicker) => `<div class="drw-scrim" data-act="${closeAct}"></div><aside class="drw" role="dialog" aria-modal="true" aria-label="${esc(label)}">
  <div class="drw-top"><span class="drw-k">${kicker}</span><span class="t3 drw-esc"><kbd>Esc</kbd> to close</span><button class="iconbtn" data-act="${closeAct}" aria-label="Close">${ico('x')}</button></div><div class="drw-b">${body}</div></aside>`;
const libHead = (title, sub, acts, seg) => `<header class="lhd"><div><h1>${title}</h1><p>${sub}</p></div><div class="lhd-a">${seg}${acts}</div></header>`;
const sortTh = (act, key, cur, dir, label, cls = '') => `<th class="${cls}" aria-sort="${cur === key ? (dir < 0 ? 'descending' : 'ascending') : 'none'}"><button data-act="${act}" data-v="${key}" class="${cur === key ? 'on' + (dir < 0 ? ' desc' : '') : ''}">${label}${ico('chevron-down','sm')}</button></th>`;
function viewQueries(){
  ensureQueries();
  const lay = qLay(), q = (UI.qq || '').toLowerCase(), cat = UI.qcat || 'all';
  let list = DB.queries.filter(x => (cat === 'all' || (cat === 'fav' ? x.starred : cat === 'mine' ? x.custom : x.cat === cat)) && (!q || (x.name + ' ' + x.desc + ' ' + x.query + ' ' + x.tags.join(' ')).toLowerCase().includes(q)));
  const sk = UI.qsk || 'name', sd = UI.qsd || 1;
  const cmp = {name:(a, b) => a.name.localeCompare(b.name), cat:(a, b) => qcat(a.cat)[0].localeCompare(qcat(b.cat)[0]) || a.name.localeCompare(b.name), uses:(a, b) => a.uses - b.uses, blanks:(a, b) => varsOf(a.query).length - varsOf(b.query).length}[sk] || ((a, b) => 0);
  list.sort((a, b) => lay === 'table' ? cmp(a, b) * sd : (b.starred - a.starred) || (b.uses - a.uses) || a.name.localeCompare(b.name));
  const cats = countBy(DB.queries, x => x.cat);
  let cur = DB.queries.find(x => x.id === UI.qsel) || null;
  if(lay === 'ide' && !cur && list[0]){ cur = list[0]; UI.qsel = cur.id; }
  const open = cur && (lay === 'ide' || UI.qopen);
  const head = libHead('Query library', `${DB.queries.length} saved search recipes · fill the blanks from a vault entry and search in the right engine`,
    `<button class="btn" data-act="qImport">${ico('upload','sm')}Import</button><button class="btn" data-act="qExport">${ico('download','sm')}Export</button><button class="btn primary" data-act="qNew">${ico('plus','sm')}New query</button>`,
    layoutSeg('qLay', lay, [['table','table-2','Table'],['gallery','layout-grid','Gallery'],['ide','columns-3','IDE']]));
  const catSel = `<label class="sr" for="qcatSel">Category</label><select id="qcatSel" class="gsel bord"><option value="all">All categories</option><option value="fav"${cat === 'fav' ? ' selected' : ''}>★ Favourites</option><option value="mine"${cat === 'mine' ? ' selected' : ''}>My queries</option>
    ${cats.map(([c, n]) => `<option value="${esc(c)}"${cat === c ? ' selected' : ''}>${esc(qcat(c)[0])} (${n})</option>`).join('')}</select>`;
  const search = `<div class="search-in">${ico('search')}<label class="sr" for="qq">Search queries</label><input id="qq" class="inp" placeholder="Search name, operator, tag…" value="${esc(UI.qq || '')}"></div>`;
  const engs = x => x.engines.map(e => `<span class="eng-t">${esc(ENGINES[e][0])}</span>`).join('');
  const none = empty('search','No queries match','Try another search or category, or write your own.', `<button class="btn primary" data-act="qNew">${ico('plus','sm')}New query</button>`);

  if(lay === 'gallery' && open) return `<div class="scroll"><div class="page fpage">
    <div class="fp-bar"><button class="btn ghost" data-act="qClose">${ico('arrow-left','sm')}All queries</button><span class="t3">${esc(qcat(cur.cat)[0])}</span></div>
    <section class="card fp-card">${queryPanel(cur)}</section></div></div>`;

  if(lay === 'ide'){
    const node = (v, l, n, icon, col) => `<button class="ide-n" data-act="qcat" data-v="${esc(v)}" aria-pressed="${cat === v}">${col ? `<i style="background:${col}"></i>` : ico(icon,'sm')}<span>${esc(l)}</span><b>${n}</b></button>`;
    return `<div class="ide-wrap">${head}<div class="ide">
      <nav class="ide-tree" aria-label="Query folders"><div class="ide-h">Library</div>${node('all','All queries',DB.queries.length,'layers')}${node('fav','Favourites',DB.queries.filter(x => x.starred).length,'star')}${node('mine','My queries',DB.queries.filter(x => x.custom).length,'pencil')}
        <div class="ide-h">Categories</div>${cats.map(([c, n]) => node(c, qcat(c)[0], n, '', qcat(c)[1])).join('')}</nav>
      <div class="ide-list"><div class="ide-lh">${search}<button class="iconbtn" data-act="qNew" aria-label="New query" title="New query">${ico('plus','sm')}</button></div>
        <div class="ide-items">${list.map(x => `<button class="ide-i" data-act="qSel" data-id="${x.id}" aria-selected="${!!(cur && cur.id === x.id)}"><b>${esc(x.name)}${x.starred ? ` <span class="tstar">${ico('star','sm')}</span>` : ''}</b><code>${esc(x.query)}</code></button>`).join('') || '<p class="t3" style="padding:16px">No queries match.</p>'}</div></div>
      <section class="ide-ed">${cur ? queryPanel(cur) : none}</section></div></div>`;
  }

  const body = !list.length ? none : lay === 'gallery'
    ? `<div class="gal">${list.map(x => { const [cn, col] = qcat(x.cat), vs = varsOf(x.query);
        return `<article class="gcard"><button class="gcard-hit" data-act="qSel" data-id="${x.id}" aria-label="Open ${esc(x.name)}"></button>
          <div class="gcard-h"><span class="pill" style="--c:${col}">${esc(cn)}</span>${vs.length ? `<span class="t3 gcard-m">${vs.length} blank${vs.length > 1 ? 's' : ''}</span>` : ''}<span style="flex:1"></span>
            <button class="tb-ic${x.starred ? ' on star' : ''}" data-act="qStar" data-id="${x.id}" aria-label="Favourite">${ico('star','sm')}</button></div>
          <h3>${esc(x.name)}</h3>${x.desc ? `<p>${esc(x.desc)}</p>` : ''}
          <pre class="gcode">${qMark(x.query)}</pre>
          <div class="gcard-f">${engs(x)}<span style="flex:1"></span><span class="gcard-go">Open ${ico('arrow-right','sm')}</span></div></article>`; }).join('')}</div>`
    : `<div class="card dtw"><table class="dt"><thead><tr><th class="c-star"></th>${sortTh('qSort','name',sk,sd,'Name')}${sortTh('qSort','cat',sk,sd,'Category','c-cat')}<th class="c-eng">Engines</th>${sortTh('qSort','blanks',sk,sd,'Blanks','c-num')}${sortTh('qSort','uses',sk,sd,'Runs','c-num')}<th class="c-act"></th></tr></thead><tbody>
      ${list.map(x => { const [cn, col] = qcat(x.cat), vs = varsOf(x.query);
        return `<tr data-act="qSel" data-id="${x.id}" aria-selected="${!!(open && cur.id === x.id)}" tabindex="0">
          <td class="c-star"><button class="tb-ic${x.starred ? ' on star' : ''}" data-act="qStar" data-id="${x.id}" aria-label="Favourite">${ico('star','sm')}</button></td>
          <td class="c-name"><b>${esc(x.name)}</b><code>${esc(x.query)}</code></td>
          <td class="c-cat"><span class="pill" style="--c:${col}">${esc(cn)}</span></td>
          <td class="c-eng">${engs(x)}</td><td class="c-num">${vs.length || '—'}</td><td class="c-num">${x.uses || '—'}</td>
          <td class="c-act">${ico('chevron-right','sm')}</td></tr>`; }).join('')}</tbody></table></div>`;
  return `<div class="scroll"><div class="page wide">${head}
    <div class="toolbar ltb">${search}${catSel}<span style="flex:1"></span><span class="t3 lcount">${list.length} ${list.length === 1 ? 'query' : 'queries'}</span></div>
    ${body}</div></div>${lay === 'table' && open ? drawer(queryPanel(cur), 'qClose', cur.name, ico('scan-search','sm') + 'Query') : ''}`;
}
function queryPanel(x){
  const vs = varsOf(x.query), D = derive(), [cn, col] = qcat(x.cat);
  if(!UI.runEng || !ENGINES[UI.runEng] || UI.runFor !== x.id){ UI.runEng = x.engines[0] || 'google'; UI.runFor = x.id; }
  const fillOpts = v => D.entries.filter(e => (VAR_FILL[v] || Object.keys(TYPES)).includes(e.type)).map(e => `<option value="${e.id}">${esc(TYPES[e.type].label + ' · ' + primary(e))}</option>`).join('');
  const others = Object.keys(ENGINES).filter(k => !x.engines.includes(k));
  const eng = k => `<button type="button" class="eng${k === UI.runEng ? ' on' : ''}" data-act="qEng" data-v="${k}" aria-pressed="${k === UI.runEng}">${esc(ENGINES[k][0])}</button>`;
  const runs = (DB.queryLog || []).filter(l => l.name === x.name).slice(0, 4);
  return `<div class="qp">
    <div class="qp-h"><span class="pill" style="--c:${col}">${esc(cn)}</span><span style="flex:1"></span>
      <button class="iconbtn${x.starred ? ' on' : ''}" data-act="qStar" data-id="${x.id}" aria-label="${x.starred ? 'Remove from favourites' : 'Add to favourites'}" title="Favourite">${ico('star','sm')}</button>
      <button class="iconbtn" data-act="qEdit" data-id="${x.id}" aria-label="Edit query" title="Edit">${ico('pencil','sm')}</button>
      <button class="iconbtn dangerhov" data-act="qDelAsk" data-id="${x.id}" aria-label="Delete query" title="Delete">${ico('trash-2','sm')}</button></div>
    <h2>${esc(x.name)}</h2>${x.desc ? `<p class="t2 qp-d">${esc(x.desc)}</p>` : ''}
    ${vs.length ? `<div class="qp-s"><h4><span class="stepn">1</span>Fill the blanks</h4>
      ${vs.map(v => `<div class="qvar"><label for="qv-${v}" class="mono">{{${esc(v)}}}</label><input id="qv-${v}" class="inp" data-var="${v}" autocomplete="off" placeholder="${esc(v.replace(/_/g, ' ').toLowerCase())}">
        ${fillOpts(v) ? `<label class="sr" for="qf-${v}">Fill ${esc(v)} from the vault</label><select id="qf-${v}" class="inp" data-fill="${v}"><option value="">From vault…</option>${fillOpts(v)}</select>` : ''}</div>`).join('')}</div>` : ''}
    <div class="qp-s"><h4><span class="stepn">${vs.length ? 2 : 1}</span>Query</h4><label class="sr" for="qPrev">Query</label><textarea id="qPrev" class="inp code" rows="3" spellcheck="false">${esc(x.query)}</textarea>
      <span class="hint">Edit freely before you search — the saved template stays as it is.</span></div>
    <div class="qp-s"><h4><span class="stepn">${vs.length ? 3 : 2}</span>Search with</h4><div class="engs">${x.engines.map(eng).join('')}</div>
      ${others.length ? `<details class="more"><summary>Other engines</summary><div class="engs">${others.map(eng).join('')}</div></details>` : ''}</div>
    <div class="qp-go"><a class="btn primary big" id="qRunLink" target="_blank" rel="noopener noreferrer" data-act="qGo" data-id="${x.id}">${ico('external-link','sm')}<span id="qRunLabel">Search</span></a>
      <button class="btn" data-act="qCopy">${ico('copy','sm')}Copy</button><label class="chk"><input type="checkbox" id="qLog" checked> Log to ${esc(theCase().code)}</label></div>
    <p class="hint" id="qRunHint"></p>
    ${runs.length ? `<div class="qp-s"><h4>Recent searches</h4>${runs.map(l => `<div class="qrun"><span class="mono">${esc(l.q)}</span><small>${esc(ENGINES[l.engine][0])} · ${esc((theCase(l.caseId) || {code:'deleted case'}).code)} · ${esc(E.fmtAgo(Date.now() - l.at))}</small></div>`).join('')}</div>` : ''}
  </div>`;
}
function syncRun(){
  const x = DB.queries.find(z => z.id === UI.qsel), pv = $('qPrev'), a = $('qRunLink'); if(!x || !pv || !a) return;
  const q = pv.value.trim(), blanks = varsOf(q), u = q && !blanks.length ? engineUrl(UI.runEng, q) : null;
  $('qRunLabel').textContent = 'Search ' + ENGINES[UI.runEng][0];
  if(u){ a.href = u; a.removeAttribute('aria-disabled'); $('qRunHint').textContent = 'Opens ' + hostOf(u) + ' in a new tab.'; }
  else { a.removeAttribute('href'); a.setAttribute('aria-disabled', 'true'); $('qRunHint').textContent = blanks.length ? 'Fill ' + blanks.length + ' blank' + (blanks.length > 1 ? 's' : '') + ' first: ' + blanks.join(', ') : 'Write a query first.'; }
}
function bindQueryPanel(){
  const x = DB.queries.find(z => z.id === UI.qsel); if(!x || !$('qPrev')) return;
  const upd = () => { let q = x.query; document.querySelectorAll('[data-var]').forEach(i => { if(i.value.trim()) q = q.replace(new RegExp('\\{\\{\\s*' + i.dataset.var + '\\s*\\}\\}', 'gi'), i.value.trim()); }); $('qPrev').value = q; syncRun(); };
  document.querySelectorAll('[data-var]').forEach(i => i.oninput = upd);
  document.querySelectorAll('[data-fill]').forEach(s => s.onchange = () => { const e = entryById(s.value), i = $('qv-' + s.dataset.fill); if(i && e){ i.value = fillFrom(s.dataset.fill, e); upd(); } });
  $('qPrev').oninput = syncRun; syncRun();
}
function queryDlg(id){
  const x = id ? DB.queries.find(z => z.id === id) : {name:'', desc:'', query:'', cat:'custom', engines:['google'], tags:[]};
  openDlg(dhead(id ? 'Edit query' : 'New query') + `<form data-form="query" data-id="${id || ''}"><div class="in">
    <div class="field"><label for="qN">Name</label><input id="qN" value="${esc(x.name)}" required autofocus placeholder="Exposed config files on a domain"></div>
    <div class="field"><label for="qQ">Query</label><textarea id="qQ" class="code" rows="3" required placeholder='site:{{DOMAIN_NAME}} (ext:env OR ext:ini) "password"'>${esc(x.query)}</textarea><span class="hint">Use <span class="mono">{{VARIABLE}}</span> for blanks — e.g. <span class="mono">{{DOMAIN_NAME}}</span>, <span class="mono">{{FULL_NAME}}</span>, <span class="mono">{{EMAIL}}</span>.</span></div>
    <div class="field"><label for="qD">What it finds</label><input id="qD" value="${esc(x.desc)}"></div>
    <div class="frow"><div class="field"><label for="qC">Category</label><select id="qC">${Object.entries(QCATS).map(([k, [n]]) => `<option value="${esc(k)}"${x.cat === k ? ' selected' : ''}>${esc(n)}</option>`).join('')}</select></div>
      <div class="field"><label for="qT">Tags</label><input id="qT" value="${esc(x.tags.join(', '))}"></div></div>
    <div class="field" style="margin:0"><span class="label">Engines</span><div class="wrap">${Object.entries(ENGINES).map(([k, [n]]) => `<label class="chip"><input type="checkbox" data-eng="${k}" ${x.engines.includes(k) ? 'checked' : ''}> ${esc(n)}</label>`).join('')}</div></div></div>
    <footer>${id ? `<button class="btn danger" type="button" data-act="qDelAsk" data-id="${id}" style="margin-right:auto">${ico('trash-2','sm')}Delete</button>` : ''}<button class="btn" type="button" data-act="dclose">Cancel</button><button class="btn primary" type="submit">${id ? 'Save' : 'Add query'}</button></footer></form>`, true);
}
