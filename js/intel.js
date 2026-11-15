/* ==========================================================================
   Threat Intel — news, vulnerabilities, indicators, actors & ATT&CK, briefs.
   The engine is js/cti.js. News comes through the api.rss2json.com relay (off until you
   agree); every other source is switched on one by one in Sources and names its host.
   Everything that comes back is untrusted text: HTML is stripped, links must be http(s),
   all output is escaped.
   ========================================================================== */
const RSS2JSON = 'https://api.rss2json.com/v1/api.json?rss_url=';
const DEFAULT_SOURCES = [
  ['The Hacker News','https://feeds.feedburner.com/TheHackersNews'], ['BleepingComputer','https://www.bleepingcomputer.com/feed/'],
  ['KrebsOnSecurity','https://krebsonsecurity.com/feed/'], ['SANS Internet Storm Center','https://isc.sans.edu/rssfeed.xml'],
  ['Microsoft Security Blog','https://www.microsoft.com/en-us/security/blog/feed/'], ['Google Security Blog','https://security.googleblog.com/feeds/posts/default'],
].map(([name, url], i) => ({id:'s' + i, name, url, on:true, status:'', last:0}));
const INTEL_CATS = [
  ['ransomware','Ransomware','#e5484d',/ransom|lockbit|extortion|encrypt(ed|ion) files/i],
  ['vuln','Vulnerabilities','#f59e0b',/cve-\d|vulnerab|zero[- ]day|0-day|patch|exploit|rce\b|remote code/i],
  ['apt','Nation-state & APT','#8b5cf6',/\bapt\d*|nation[- ]state|state[- ]sponsored|espionage|lazarus|kimsuky|sandworm|volt typhoon/i],
  ['malware','Malware','#ec4899',/malware|trojan|loader|stealer|botnet|backdoor|rat\b|infostealer/i],
  ['breach','Breaches & leaks','#0ea5a4',/breach|leak|exposed|stolen data|compromised accounts|dump/i],
  ['phish','Phishing & fraud','#3b82f6',/phish|scam|fraud|smish|bec\b|credential/i],
];
function classify(text){
  const t = String(text || ''); const c = INTEL_CATS.find(x => x[3].test(t));
  const sev = /actively exploited|in the wild|zero[- ]day|0-day|critical|emergency/i.test(t) ? 'critical' : /exploit|ransomware|breach|cve-\d/i.test(t) ? 'high' : 'normal';
  return {cat:c ? c[0] : 'general', sev};
}
const catMeta = id => { const c = INTEL_CATS.find(x => x[0] === id); return c ? {name:c[1], col:c[2]} : {name:'General', col:'#64748b'}; };
function plainText(html){ try{ const d = new DOMParser().parseFromString(String(html || ''), 'text/html'); d.querySelectorAll('script,style,noscript,iframe,object,template').forEach(n => n.remove()); return (d.body.textContent || '').replace(/\s+/g, ' ').trim(); }catch(e){ return String(html || '').replace(/<[^>]*>/g, ' '); } }
function ensureIntel(){
  if(!DB.feedSources) DB.feedSources = DEFAULT_SOURCES.map(s => ({...s}));
  for(const f of DB.feed){ if(!f.cat){ const k = classify(f.title + ' ' + f.body); f.cat = k.cat; f.sev = k.sev; } }
  if(typeof ctiEnsure === 'function') ctiEnsure();
}
const CAT_ICON = {ransomware:'lock', vuln:'bug', apt:'crosshair', malware:'skull', breach:'key-round', phish:'mail', general:'newspaper'};
function dayLabel(ts){ const d = new Date(ts), n = new Date(), k = x => x.toISOString().slice(0, 10), y = new Date(n - 864e5);
  return k(d) === k(n) ? 'Today' : k(d) === k(y) ? 'Yesterday' : d.toLocaleDateString(undefined, {weekday:'long', day:'numeric', month:'long'}); }
const iAgo = ts => { const d = Date.now() - ts; return d > 45 * 864e5 ? new Date(ts).toLocaleDateString(undefined, {day:'numeric', month:'short', year:'numeric'}) : E.fmtAgo(Math.max(0, d)); };

/* ---------- refreshing: news through the relay, plus every data source you switched on ---------- */
let intelBusy = false;
async function refreshFeeds(){
  ctiEnsure(); await ctiLoad();
  const onData = DB.intel.sources.filter(s => s.on && ctiSrc(s.id) && /kev|ioc|attack/.test(ctiSrc(s.id).kind));
  if(!DB.prefs.liveFeeds && !onData.length) return sourcesDlg('news');
  if(intelBusy) return; intelBusy = true; renderMain();
  let added = 0, bad = 0; const notes = [];
  if(DB.prefs.liveFeeds){
    const srcs = DB.feedSources.filter(s => s.on);
    await Promise.allSettled(srcs.map(async s => {
      try{
        const t = await ctiFetch(RSS2JSON + encodeURIComponent(s.url), {timeout:15000}), j = ctiJSON(t);
        if(j.status !== 'ok' || !Array.isArray(j.items)) throw new Error(cap(j.message, 120) || 'Relay refused the feed');
        for(const it of j.items.slice(0, 30)){
          const title = plainText(it.title).slice(0, 300), body = plainText(it.description || it.content).slice(0, 2000), link = E.safeUrl(it.link) || '';
          if(!title || DB.feed.some(f => (link && f.link === link) || f.title === title)) continue;
          const k = classify(title + ' ' + body);
          DB.feed.push({id:uid('f'), source:s.name, title, body, link, ts:Date.parse(String(it.pubDate || '').replace(' ', 'T') + (/[zZ+]/.test(it.pubDate || '') ? '' : 'Z')) || Date.now(), cat:k.cat, sev:k.sev, live:true, st:'new'}); added++;
        }
        s.status = 'ok'; s.last = Date.now(); s.err = '';
      }catch(e){ s.status = 'error'; s.err = cap(e.message || e, 160); bad++; }
    }));
    DB.feed.sort((a, b) => b.ts - a.ts); if(DB.feed.length > 1000) DB.feed.length = 1000;
  }
  for(const s of onData){
    const meta = ctiSrc(s.id);
    try{ if(meta.kind === 'kev'){ const n = await ctiRefreshKev(); ctiSrcOk('kev', n); notes.push('KEV ' + n); }
      else if(meta.kind === 'attack'){ const n = await ctiRefreshAttack(); if(n){ ctiSrcOk('attack', n); notes.push('ATT&CK ' + ATTACK.v); } }
      else { const r = await ctiRefreshIocFeed(s.id); notes.push(meta.name.replace(/^abuse\.ch /, '').split(' — ')[0] + ' +' + r.added); } }
    catch(e){ ctiSrcErr(s.id, e); bad++; }
  }
  /* EPSS for the CVEs in the news, if you turned it on */
  if(ctiSrc('epss').on){ const cves = [...new Set(DB.feed.slice(0, 300).flatMap(f => ctiX(f).cve))].filter(c => !(DB.intel.cve[c] && DB.intel.cve[c].epssAt > Date.now() - 864e5)).slice(0, 100);
    if(cves.length) try{ await ctiEpss(cves); }catch(e){ ctiSrcErr('epss', e); bad++; } }
  intelBusy = false; DB.prefs.lastFeedRefresh = Date.now(); mutate('refreshed threat intel (+' + added + ')'); renderAll();
  toast([DB.prefs.liveFeeds ? added + ' new article' + (added === 1 ? '' : 's') : '', ...notes, bad ? bad + ' source' + (bad > 1 ? 's' : '') + ' failed — see Sources' : ''].filter(Boolean).join(' · ') || 'Up to date');
}
function intelConsent(){
  openDlg(dhead('Turn on live news?') + `<div class="in">
    <p class="t2" style="margin:0 0 14px">OSINTrix is offline by default. News feeds are fetched through <b class="mono" style="color:var(--text)">api.rss2json.com</b>, a third-party relay that reads the RSS and returns it, because most news sites do not let a browser read their feeds directly.</p>
    <div class="grid" style="gap:10px">
      <div class="note"><span class="ic" style="color:var(--green);background:var(--green-soft)">${ico('check','sm')}</span><div><b>What leaves your browser:</b> only the feed URLs you switched on.</div></div>
      <div class="note"><span class="ic" style="color:var(--green);background:var(--green-soft)">${ico('lock','sm')}</span><div><b>What never leaves:</b> your cases, vault entries, notes, indicators and searches.</div></div>
      <div class="note amber"><span class="ic">${ico('triangle-alert','sm')}</span><div>The relay can see which feeds you follow and when. Articles are shown as plain text; links open only when you click them.</div></div></div>
    <label style="display:flex;gap:10px;align-items:center;margin-top:16px;font-size:calc(14px * var(--ts,1))"><input type="checkbox" id="intelOk"> I understand, allow requests to api.rss2json.com</label></div>
    <footer><button class="btn" data-act="dclose">Keep offline</button><button class="btn primary" data-act="intelOn" id="intelOnBtn" disabled>${ico('wifi','sm')}Turn on and refresh</button></footer>`, false,
    () => { $('intelOk').onchange = () => { $('intelOnBtn').disabled = !$('intelOk').checked; }; });
}

/* ---------- small pieces shared by the tabs ---------- */
const TLP_COL = {clear:'var(--text-3)', green:'var(--green)', amber:'var(--amber)', 'amber+strict':'var(--amber)', red:'var(--red)'};
const tlpTag = t => t ? `<span class="ti-tlp" style="--c:${TLP_COL[t] || 'var(--text-3)'}">TLP:${esc(t.toUpperCase())}</span>` : '';
const actName = id => { const D = ctiDict(), g = D.grp.get(id) || D.soft.get(id); return g ? g.n : id; };
const techName = id => { const t = ctiDict().tech.get(id); return t ? t[1] : ''; };
function cveChip(c){ const k = kevOf(c), s = DB.intel.cve[c] || {};
  return `<button class="ti-chip cve${k ? ' kev' : ''}" data-act="ctiCve" data-v="${esc(c)}" title="${k ? 'CISA: known exploited' + (k.ransom ? ', used by ransomware' : '') : 'Vulnerability'}">${k ? ico('flame','sm') : ''}${esc(c)}${s.epss != null ? `<small>EPSS ${Math.round(s.epss * 100)}%</small>` : ''}</button>`; }
const actChip = id => `<button class="ti-chip act" data-act="ctiActor" data-v="${esc(id)}">${ico(/^G/.test(id) ? 'users' : 'skull','sm')}${esc(actName(id))}</button>`;
const ttpChip = id => `<button class="ti-chip ttp" data-act="ctiTech" data-v="${esc(id)}" title="${esc(techName(id))}">${esc(id)}</button>`;
const venChip = v => `<span class="ti-chip ven${ctiInStack(v) ? ' mine' : ''}" title="${ctiInStack(v) ? 'In your stack' : 'Vendor'}">${ctiInStack(v) ? ico('server','sm') : ''}${esc(v)}</span>`;
const ctiStackSet = () => new Set((DB.intel.stack || []).map(s => s.vendor.toLowerCase()));
const ctiInStack = (vendor, product) => (DB.intel.stack || []).some(s => s.vendor.toLowerCase() === String(vendor).toLowerCase() && (!s.product || !product || s.product.toLowerCase() === String(product).toLowerCase()));
function storyMine(st){ const g = globalEnts(), hits = new Set(), stack = ctiStackSet();
  for(const f of st.items){ const x = ctiX(f); x.iocs.forEach(e => { const k = entKey(e); if(g.has(k)) hits.add(k); }); x.cve.forEach(c => { if(g.has('cve:' + c)) hits.add('cve:' + c); }); }
  const ven = [...new Set(st.items.flatMap(f => ctiX(f).ven))], kevStack = st.items.flatMap(f => ctiX(f).kev).some(c => { const k = kevOf(c); return k && ctiInStack(k.vendor, k.product); });
  return {hits:[...hits], stack:ven.filter(v => stack.has(v.toLowerCase())), kevStack}; }
const triage = f => f.st || (f.live ? 'new' : 'new');

/* ---------- the page ---------- */
const ITABS = [['feed','News','newspaper'], ['look','Investigate','radar'], ['vulns','Vulnerabilities','bug'], ['iocs','Indicators','fingerprint'], ['attack','Actors & ATT&CK','crosshair'], ['brief','Briefs','file-text']];
function viewIntel(){
  ensureIntel();
  if(!CTI.iocs){ ctiLoad().then(() => { if(UI.route.area === 'feeds') renderMain(); }); }
  const tab = ITABS.some(t => t[0] === UI.itab) ? UI.itab : 'feed', live = !!DB.prefs.liveFeeds, last = DB.prefs.lastFeedRefresh;
  const onN = DB.intel.sources.filter(s => s.on).length + (live ? DB.feedSources.filter(s => s.on).length : 0), hits = CTI.iocs ? ctiIocHits().length : 0;
  const unread = DB.feed.filter(f => triage(f) === 'new').length;
  const kevNew = CTI.kev ? [...CTI.kev.values()].filter(k => Date.parse(k.added) > Date.now() - 7 * 864e5).length : 0;
  const body = tab === 'look' ? ctiLookView() : tab === 'vulns' ? ctiVulnsView() : tab === 'iocs' ? ctiIocsView() : tab === 'attack' ? ctiAttackView() : tab === 'brief' ? ctiBriefView() : ctiFeedView();
  return `<div class="scroll"><div class="page wide ti">
    ${pageHead('rss','#e5484d','Threat Intel','News, vulnerabilities, indicators and adversaries — checked against every case, your stack and your indicator feeds.',
      `<span class="iv-live${onN ? ' on' : ''}"><i></i>${onN ? 'Live · ' + onN + ' source' + (onN > 1 ? 's' : '') + (last ? ' · ' + esc(iAgo(last)) : '') : 'Offline'}</span>
       <button class="btn" data-act="feedSources">${ico('settings','sm')}Sources</button>
       <button class="btn primary" data-act="feedRefresh" ${intelBusy ? 'disabled' : ''}>${ico('refresh-cw', intelBusy ? 'sm spin' : 'sm')}${intelBusy ? 'Refreshing…' : onN ? 'Refresh' : 'Go live'}</button>`,
      [[unread, 'unread stories'], [DB.feed.filter(f => f.sev === 'critical').length, 'critical'], [kevNew, 'KEV added this week', kevNew ? '<em class="r"></em>' : ''], [hits, 'feed indicators in your cases', hits ? '<em class="r"></em>' : '']])}
    <nav class="ti-tabs" role="tablist" aria-label="Threat Intel">${ITABS.map(([k, l, i]) => `<button role="tab" data-act="itab" data-v="${k}" aria-selected="${tab === k}">${ico(i,'sm')}${l}${k === 'feed' && unread ? `<span>${unread}</span>` : k === 'iocs' && hits ? `<span class="r">${hits}</span>` : ''}</button>`).join('')}</nav>
    ${body}
  </div></div>`;
}

/* ---------- News ---------- */
const TRI = [['inbox','Inbox'], ['relevant','Relevant'], ['starred','Starred'], ['all','All'], ['dismissed','Dismissed']];
function ctiFeedList(){
  const q = (UI.iq || '').toLowerCase(), cat = UI.icat || 'all', tri = UI.itri || 'inbox', ent = UI.ient || '';
  let L = DB.feed.filter(f => (cat === 'all' || f.cat === cat) && (!UI.isrc || f.source === UI.isrc) && (!q || (f.title + ' ' + f.body + ' ' + f.source).toLowerCase().includes(q)));
  if(ent){ const [k, v] = [ent.slice(0, ent.indexOf(':')), ent.slice(ent.indexOf(':') + 1)]; L = L.filter(f => { const x = ctiX(f); return k === 'cve' ? x.cve.includes(v) : k === 'ttp' ? x.ttp.includes(v) : k === 'act' ? x.act.includes(v) || x.mal.includes(v) : k === 'ven' ? x.ven.includes(v) : true; }); }
  let S = ctiStories(L).sort((a, b) => b.ts - a.ts);
  S = S.filter(st => { const t = st.items.map(triage), star = st.items.some(f => f.star);
    return tri === 'all' ? true : tri === 'starred' ? star : tri === 'dismissed' ? t.every(x => x === 'dismissed') : tri === 'relevant' ? t.some(x => x === 'relevant' || x === 'actioned') : !t.every(x => x === 'dismissed') && t.some(x => x === 'new'); });
  if(UI.imatch || UI.istack) S = S.filter(st => { const m = storyMine(st); return (!UI.imatch || m.hits.length) && (!UI.istack || m.stack.length || m.kevStack); });
  if((UI.isort || 'you') === 'you' && typeof ctiRank === 'function'){ S.forEach(st => st.rk = ctiRank(st)); S.sort((a, b) => b.rk.score - a.rk.score || b.ts - a.ts); }
  return S;
}
function ctiStoryRow(st){
  const f = st.lead, m = catMeta(f.cat), X = st.items.map(ctiX), mine = storyMine(st), read = st.items.every(i => i.read), star = st.items.some(i => i.star), t = triage(f);
  const cve = [...new Set(X.flatMap(x => x.cve))], act = [...new Set(X.flatMap(x => [...x.act, ...x.mal]))], ttp = [...new Set(X.flatMap(x => x.ttp))], ven = [...new Set(X.flatMap(x => x.ven))], iocN = new Set(X.flatMap(x => x.iocs.map(entKey))).size;
  const chips = [...cve.slice(0, 4).map(cveChip), ...act.slice(0, 4).map(actChip), ...ttp.slice(0, 4).map(ttpChip), ...ven.slice(0, 3).map(venChip)].join('');
  return `<article class="ti-st${read ? ' read' : ''}${mine.hits.length || mine.stack.length || mine.kevStack ? ' mine' : ''}" aria-current="${!!(UI.sel && UI.sel.kind === 'feed' && st.items.some(i => i.id === UI.sel.id))}">
    <span class="iv-tile" style="--c:${m.col}" aria-hidden="true">${ico(CAT_ICON[f.cat] || 'newspaper')}</span>
    <div class="ti-sb">
      <button class="ti-open" data-act="selFeed" data-id="${f.id}">
        <span class="iv-meta"><b>${esc(f.source)}</b>${st.sources.length > 1 ? `<span class="ti-more" title="${esc(st.sources.join(', '))}">+${st.sources.length - 1} source${st.sources.length > 2 ? 's' : ''}</span>` : ''}<i></i>${esc(iAgo(st.ts))}<span class="iv-cat" style="--c:${m.col}">${esc(m.name)}</span>${f.sev === 'critical' ? `<span class="iv-sev c">${ico('flame','sm')}Critical</span>` : f.sev === 'high' ? '<span class="iv-sev h">High</span>' : ''}${t === 'relevant' ? '<span class="ti-tri rel">Relevant</span>' : t === 'actioned' ? '<span class="ti-tri act">Actioned</span>' : t === 'dismissed' ? '<span class="ti-tri dis">Dismissed</span>' : ''}${f.live ? '' : '<span class="iv-sample">Sample</span>'}</span>
        <span class="iv-t">${esc(f.title)}</span><span class="iv-p">${esc(f.body.slice(0, 220))}</span></button>
      ${chips || iocN ? `<div class="ti-chips">${chips}${iocN ? `<span class="ti-chip ioc">${ico('fingerprint','sm')}${iocN} indicator${iocN > 1 ? 's' : ''}</span>` : ''}</div>` : ''}
      ${st.rk && st.rk.why.length ? `<p class="ti-why">${ico('sparkles','sm')}${esc(st.rk.why.slice(0, 3).join(' · '))}</p>` : ''}
      ${mine.hits.length ? `<div class="iv-hits"><span>${ico('crosshair','sm')}In your cases</span>${mine.hits.slice(0, 4).map(id => entPill(id)).join('')}</div>` : ''}
      ${mine.stack.length || mine.kevStack ? `<div class="ti-alert">${ico('server','sm')}${mine.kevStack ? 'An exploited vulnerability in your stack' : 'Mentions your stack'}: ${esc(mine.stack.join(', ') || 'see CVEs')}</div>` : ''}
    </div>
    <div class="ti-acts">
      <button class="iconbtn${star ? ' on' : ''}" data-act="ctiStar" data-id="${f.id}" aria-pressed="${star}" aria-label="Star" title="Star — include in the brief">${ico('star','sm')}</button>
      <button class="iconbtn${t === 'relevant' ? ' on' : ''}" data-act="ctiTri" data-id="${f.id}" data-v="relevant" aria-pressed="${t === 'relevant'}" aria-label="Relevant" title="Relevant to us">${ico('check','sm')}</button>
      <button class="iconbtn" data-act="ctiTri" data-id="${f.id}" data-v="${t === 'dismissed' ? 'new' : 'dismissed'}" aria-label="${t === 'dismissed' ? 'Back to inbox' : 'Dismiss'}" title="${t === 'dismissed' ? 'Back to inbox' : 'Not relevant — dismiss'}">${ico(t === 'dismissed' ? 'undo-2' : 'x','sm')}</button>
      <button class="iconbtn" data-act="ctiStoryMenu" data-id="${f.id}" aria-label="More" title="More">${ico('ellipsis','sm')}</button></div>
  </article>`;
}
function ctiFeedView(){
  const S = ctiFeedList(), tri = UI.itri || 'inbox', cat = UI.icat || 'all', srcs = [...new Set(DB.feed.map(f => f.source))].sort();
  const lim = UI.ilim || 60, week = DB.feed.filter(f => f.ts > Date.now() - 7 * 864e5), XW = week.map(ctiX), top = (fn, n) => countBy(XW, fn).slice(0, n);
  const hits = CTI.iocs ? ctiIocHits() : [], stackKev = CTI.kev && DB.intel.stack.length ? [...CTI.kev.values()].filter(k => ctiInStack(k.vendor, k.product) && Date.parse(k.added) > Date.now() - 30 * 864e5) : [];
  const ent = UI.ient || '', entLbl = ent ? (/^act:/.test(ent) ? actName(ent.slice(4)) : ent.slice(ent.indexOf(':') + 1)) : '';
  let lastDay = '';
  return `<div class="iv">
    <div class="iv-main">
      <div class="ti-bar"><div class="search-in">${ico('search')}<label class="sr" for="iq">Search the news</label><input id="iq" class="inp" placeholder="Search titles, summaries, sources…" value="${esc(UI.iq || '')}"></div>
        <div class="seg" role="group" aria-label="Triage">${TRI.map(([k, l]) => `<button data-act="itri" data-v="${k}" aria-pressed="${tri === k}">${l}</button>`).join('')}</div></div>
      <div class="ti-bar sub">
        <button class="chip${UI.imatch ? ' accent' : ''}" data-act="imatch" aria-pressed="${!!UI.imatch}">${ico('crosshair','sm')}Mentions my cases</button>
        <button class="chip${UI.istack ? ' accent' : ''}" data-act="istack" aria-pressed="${!!UI.istack}">${ico('server','sm')}My stack</button>
        <label class="sr" for="icatSel">Category</label><select id="icatSel" class="inp ti-sel"><option value="all">Every category</option>${INTEL_CATS.map(c => `<option value="${c[0]}"${cat === c[0] ? ' selected' : ''}>${esc(c[1])}</option>`).join('')}<option value="general"${cat === 'general' ? ' selected' : ''}>General</option></select>
        <label class="sr" for="isrc">Source</label><select id="isrc" class="inp ti-sel"><option value="">Every source</option>${srcs.map(s => `<option${UI.isrc === s ? ' selected' : ''}>${esc(s)}</option>`).join('')}</select>
        ${ent ? `<span class="ti-filt">${ico('filter','sm')}${esc(entLbl)}<button class="iconbtn" data-act="ient" data-v="" aria-label="Remove filter">${ico('x','sm')}</button></span>` : ''}
        <label class="sr" for="isort">Order</label><select id="isort" class="inp ti-sel"><option value="you"${(UI.isort || 'you') === 'you' ? ' selected' : ''}>For you</option><option value="new"${UI.isort === 'new' ? ' selected' : ''}>Newest first</option></select>
        <span class="sp"></span><span class="t3 small">${S.length} stor${S.length === 1 ? 'y' : 'ies'}</span>
        ${tri === 'inbox' && S.length ? `<button class="btn sm ghost" data-act="ctiReadAll">${ico('check-check','sm')}Mark all read</button>` : ''}</div>
      ${S.length ? `<div class="ti-list card">${S.slice(0, lim).map(st => { const d = dayLabel(st.ts), h = UI.isort === 'new' && d !== lastDay ? `<h3 class="iv-day">${esc(d)}</h3>` : ''; lastDay = d; return h + ctiStoryRow(st); }).join('')}
        ${S.length > lim ? `<button class="ti-moreb" data-act="ilim">Show ${Math.min(60, S.length - lim)} more</button>` : ''}</div>`
        : empty('search', tri === 'inbox' && DB.feed.length ? 'Inbox zero' : 'No stories here', tri === 'inbox' && DB.feed.length ? 'Every story has been read, marked or dismissed. New ones arrive when you refresh.' : DB.prefs.liveFeeds ? 'Nothing matches these filters.' : 'Go live to pull the latest from your sources, or import an RSS/Atom file.',
          `<button class="btn" data-act="itri" data-v="all">Show all</button>${DB.prefs.liveFeeds ? '' : `<button class="btn primary" data-act="feedRefresh">${ico('wifi','sm')}Go live</button>`}`)}
    </div>
    <aside class="iv-rail">
      ${hits.length || stackKev.length ? `<section class="card iv-box ti-attn"><h4>${ico('siren','sm')}Needs attention</h4>
        ${hits.length ? `<button class="ti-attn-i" data-act="itab" data-v="iocs" data-x="hits"><b>${hits.length}</b><span>indicator${hits.length > 1 ? 's' : ''} from your feeds appear in your cases</span></button>` : ''}
        ${stackKev.length ? `<button class="ti-attn-i" data-act="ctiVulnStack"><b>${stackKev.length}</b><span>exploited vulnerabilit${stackKev.length > 1 ? 'ies' : 'y'} in your stack added to KEV in 30 days</span></button>` : ''}</section>` : ''}
      <section class="card iv-box"><h4>${ico('trending-up','sm')}This week</h4>
        ${week.length ? [['CVEs', top(x => x.cve, 6), c => cveChip(c)], ['Actors & malware', top(x => [...x.act, ...x.mal], 6), id => actChip(id)], ['Techniques', top(x => x.ttp, 6), id => ttpChip(id)], ['Vendors', top(x => x.ven, 6), v => `<button class="ti-chip ven" data-act="ient" data-v="ven:${esc(v)}">${esc(v)}</button>`]]
          .filter(r => r[1].length).map(([l, L, fn]) => `<div class="ti-trend"><p>${l}</p><div>${L.map(([v, n]) => `<span class="ti-tr">${fn(v)}<em>${n}</em></span>`).join('')}</div></div>`).join('') || '<p class="t3">Nothing extracted this week yet.</p>' : '<p class="t3">No stories from the last 7 days.</p>'}</section>
      <section class="card iv-box"><h4>${ico('activity','sm')}By category</h4>
        ${(() => { const counts = Object.fromEntries(INTEL_CATS.map(c => [c[0], DB.feed.filter(f => f.cat === c[0]).length])), mx = Math.max(1, ...Object.values(counts));
          return INTEL_CATS.filter(c => counts[c[0]]).map(([id, l, col]) => `<button class="iv-bar" data-act="icat" data-v="${cat === id ? 'all' : id}" aria-pressed="${cat === id}" style="--c:${col}"><span>${esc(l)}</span><b>${counts[id]}</b><i><u style="width:${Math.round(counts[id] / mx * 100)}%"></u></i></button>`).join('') || '<p class="t3">Nothing classified yet.</p>'; })()}</section>
    </aside></div>`;
}

/* ---------- Vulnerabilities ---------- */
function ctiVulnRows(){
  const mode = UI.vmode || 'news', q = (UI.vq || '').trim().toLowerCase(), news = new Map();
  for(const f of DB.feed){ for(const c of ctiX(f).cve){ if(!news.has(c)) news.set(c, []); news.get(c).push(f); } }
  let cves;
  if(mode === 'news') cves = [...news.keys()];
  else if(mode === 'stack') cves = [...CTI.kev.values()].filter(k => ctiInStack(k.vendor, k.product)).map(k => k.cve);
  else cves = [...CTI.kev.keys()];
  const g = globalEnts();
  let R = cves.map(c => { const k = kevOf(c), s = DB.intel.cve[c] || {}; return {c, k, s, n:(news.get(c) || []).length, inCase:g.has('cve:' + c), added:k ? Date.parse(k.added) || 0 : 0}; });
  if(UI.vransom) R = R.filter(r => r.k && r.k.ransom);
  if(UI.vkev && mode === 'news') R = R.filter(r => r.k);
  if(q) R = R.filter(r => (r.c + ' ' + (r.k ? r.k.vendor + ' ' + r.k.product + ' ' + r.k.name : '') + ' ' + (r.s.desc || '')).toLowerCase().includes(q));
  const so = UI.vsort || (mode === 'news' ? 'mentions' : 'added');
  R.sort(so === 'epss' ? (a, b) => (b.s.epss || 0) - (a.s.epss || 0) : so === 'cvss' ? (a, b) => (b.s.cvss || 0) - (a.s.cvss || 0) : so === 'mentions' ? (a, b) => b.n - a.n || b.added - a.added : (a, b) => b.added - a.added || b.c.localeCompare(a.c));
  return R;
}
function ctiVulnsView(){
  const mode = UI.vmode || 'news', R = ctiVulnRows(), lim = UI.vlim || 100, kv = [...CTI.kev.values()], d30 = Date.now() - 30 * 864e5;
  const stackN = kv.filter(k => ctiInStack(k.vendor, k.product)).length, epssOn = ctiSrc('epss').on, nvdOn = ctiSrc('nvd').on;
  const sevCls = s => s >= 9 ? 'c' : s >= 7 ? 'h' : s >= 4 ? 'm' : 'l';
  return `<div class="ti-kpis">
      <div><b>${CTI.kevMeta.n.toLocaleString()}</b><span>known exploited (CISA KEV)</span><small>${CTI.kevMeta.live ? 'live' : 'snapshot'} · catalog ${esc(CTI.kevMeta.v)}</small></div>
      <div><b>${kv.filter(k => Date.parse(k.added) > d30).length}</b><span>added in the last 30 days</span></div>
      <div><b>${kv.filter(k => k.ransom).length}</b><span>used in ransomware campaigns</span></div>
      <div class="${stackN ? 'r' : ''}"><b>${stackN}</b><span>in your stack</span><small>${DB.intel.stack.length ? DB.intel.stack.length + ' product' + (DB.intel.stack.length > 1 ? 's' : '') + ' watched' : 'add what you run below'}</small></div></div>
    <section class="card ti-stack"><div class="ti-stack-h"><h4>${ico('server','sm')}My stack</h4><p class="t3">Vendors and products you run. Stories and exploited vulnerabilities that touch them are flagged everywhere.</p></div>
      <div class="ti-stack-l">${DB.intel.stack.map((s, i) => `<span class="ti-sv">${esc(s.vendor)}${s.product ? ' · ' + esc(s.product) : ''}<button data-act="ctiStackDel" data-v="${i}" aria-label="Stop watching ${esc(s.vendor)}">${ico('x','sm')}</button></span>`).join('')}
        <form data-form="ctiStack" class="ti-sadd"><label class="sr" for="ctiStackIn">Add a vendor or vendor / product</label><input id="ctiStackIn" class="inp" list="ctiVendors" placeholder="Add — e.g. Fortinet or Microsoft / Exchange Server" autocomplete="off" maxlength="160"><datalist id="ctiVendors">${ctiVendors().slice(0, 400).map(v => `<option value="${esc(v.vendor)}">`).join('')}</datalist><button class="btn sm" type="submit">${ico('plus','sm')}Watch</button></form></div></section>
    <div class="ti-bar"><div class="seg" role="group" aria-label="Show">${[['news','In the news'], ['kev','All KEV'], ['stack','My stack']].map(([k, l]) => `<button data-act="vmode" data-v="${k}" aria-pressed="${mode === k}">${l}</button>`).join('')}</div>
      <div class="search-in">${ico('search')}<label class="sr" for="vq">Search vulnerabilities</label><input id="vq" class="inp" placeholder="CVE, vendor, product…" value="${esc(UI.vq || '')}"></div>
      ${mode === 'news' ? `<button class="chip${UI.vkev ? ' accent' : ''}" data-act="vkev" aria-pressed="${!!UI.vkev}">${ico('flame','sm')}Exploited only</button>` : ''}
      <button class="chip${UI.vransom ? ' accent' : ''}" data-act="vransom" aria-pressed="${!!UI.vransom}">${ico('lock','sm')}Ransomware</button>
      <label class="sr" for="vsort">Sort</label><select id="vsort" class="inp ti-sel">${[['added','KEV date'], ['mentions','News mentions'], ['epss','EPSS'], ['cvss','CVSS']].map(([k, l]) => `<option value="${k}"${(UI.vsort || (mode === 'news' ? 'mentions' : 'added')) === k ? ' selected' : ''}>Sort: ${l}</option>`).join('')}</select>
      <span class="sp"></span>${epssOn ? `<button class="btn sm" data-act="ctiEpssShown">${ico('gauge','sm')}EPSS for these</button>` : `<button class="btn sm ghost" data-act="feedSources" data-v="data">${ico('gauge','sm')}Turn on EPSS</button>`}</div>
    ${R.length ? `<div class="card ti-tbl" role="table" aria-label="Vulnerabilities"><div class="ti-tr2 h" role="row"><span role="columnheader">CVE</span><span role="columnheader">Vendor · product</span><span role="columnheader">Exploited (CISA)</span><span class="n" role="columnheader">EPSS</span><span class="n" role="columnheader">CVSS</span><span class="n" role="columnheader">News</span><span role="columnheader"><span class="sr">Status</span></span></div>
      ${R.slice(0, lim).map(r => `<button class="ti-tr2" role="row" data-act="ctiCve" data-v="${esc(r.c)}">
        <span role="cell" class="mono b">${esc(r.c)}</span>
        <span role="cell" class="ti-vp">${r.k ? `<b>${esc(r.k.vendor)}</b> · ${esc(r.k.product)}<small>${esc(r.k.name)}</small>` : r.s.desc ? `<small>${esc(r.s.desc.slice(0, 120))}</small>` : '<small class="t3">Not in KEV — open it for the official record</small>'}</span>
        <span role="cell">${r.k ? `<span class="ti-kev">${ico('flame','sm')}${esc(r.k.added)}</span>${r.k.ransom ? '<span class="ti-ransom">Ransomware</span>' : ''}` : '<span class="t3">—</span>'}</span>
        <span role="cell" class="n">${r.s.epss != null ? `<span class="ti-epss" style="--p:${Math.round(r.s.epss * 100)}%">${(r.s.epss * 100).toFixed(r.s.epss < 0.1 ? 1 : 0)}%</span>` : '<span class="t3">—</span>'}</span>
        <span role="cell" class="n">${r.s.cvss != null ? `<span class="ti-cvss ${sevCls(r.s.cvss)}">${(+r.s.cvss).toFixed(1)}</span>` : '<span class="t3">—</span>'}</span>
        <span role="cell" class="n">${r.n || '<span class="t3">0</span>'}</span>
        <span role="cell">${r.inCase ? `<span class="ti-in">${ico('crosshair','sm')}In a case</span>` : ''}${r.k && ctiInStack(r.k.vendor, r.k.product) ? `<span class="ti-in s">${ico('server','sm')}Stack</span>` : ''}</span></button>`).join('')}
      ${R.length > lim ? `<button class="ti-moreb" data-act="vlim">Show ${Math.min(100, R.length - lim)} more of ${R.length.toLocaleString()}</button>` : ''}</div>`
      : empty('bug', mode === 'stack' ? (DB.intel.stack.length ? 'Nothing exploited in your stack' : 'Add your stack first') : 'No vulnerabilities here', mode === 'stack' ? (DB.intel.stack.length ? 'None of the products you watch is in the CISA catalog. Good news.' : 'Add the vendors and products you run above.') : mode === 'news' ? 'No CVE is mentioned in the stories you have. Refresh the news, or look at all known exploited vulnerabilities.' : 'Nothing matches.', mode === 'news' ? `<button class="btn" data-act="vmode" data-v="kev">All known exploited</button>` : '')}
    <p class="t3 small ti-fine">${nvdOn || epssOn ? 'Scores fetched on demand from ' + [epssOn ? 'api.first.org' : '', nvdOn ? 'services.nvd.nist.gov' : ''].filter(Boolean).join(' and ') + '; only CVE IDs are sent.' : 'EPSS and CVSS are off. Turn them on in Sources to fetch scores for the CVEs you look at.'} The KEV catalog is public domain from CISA.</p>`;
}
function ctiCveDlg(cve){
  ctiEnsure(); const k = kevOf(cve), s = DB.intel.cve[cve] || {}, arts = DB.feed.filter(f => ctiX(f).cve.includes(cve)).sort((a, b) => b.ts - a.ts), g = globalEnts().get('cve:' + cve);
  const epssOn = ctiSrc('epss').on, nvdOn = ctiSrc('nvd').on;
  openDlg(`${dhead(esc(cve))}<div class="in ti-dlg">
    ${k ? `<div class="ti-kevbox">${ico('flame')}<div><b>Known exploited — CISA added it ${esc(k.added)}</b><span>${esc(k.vendor)} · ${esc(k.product)} — ${esc(k.name)}</span>${k.ransom ? '<span class="ti-ransom">Used in ransomware campaigns</span>' : ''}<small>Federal agencies must fix it by ${esc(k.due)}${k.cwe ? ' · ' + esc(k.cwe) : ''}</small></div></div>`
      : '<p class="t3" style="margin:0 0 12px">Not in the CISA Known Exploited catalog' + (CTI.kevMeta.live ? '' : ' snapshot') + '. That does not mean it is safe — check EPSS and the news.</p>'}
    ${k && k.desc ? `<p>${esc(k.desc)}</p>` : ''}${s.desc ? `<p class="t2">${esc(s.desc)}</p>` : ''}
    <div class="ti-scores">
      <div><span>EPSS — chance of exploitation in 30 days</span>${s.epss != null ? `<b>${(s.epss * 100).toFixed(2)}%</b><small>higher than ${Math.round((s.pct || 0) * 100)}% of all CVEs · ${esc(iAgo(s.epssAt))}</small>` : epssOn ? `<button class="btn sm" data-act="ctiEpssOne" data-v="${esc(cve)}">${ico('gauge','sm')}Get EPSS</button>` : `<small>Off — turn on FIRST EPSS in Sources</small>`}</div>
      <div><span>CVSS${s.ver ? ' ' + esc(s.ver) : ''}</span>${s.cvss != null ? `<b>${(+s.cvss).toFixed(1)} <em>${esc(s.sev)}</em></b><small class="mono">${esc(s.vec)}</small>` : nvdOn ? `<button class="btn sm" data-act="ctiNvdOne" data-v="${esc(cve)}">${ico('download','sm')}Get the CVE record</button>` : `<small>Off — turn on CVE records in Sources</small>`}</div></div>
    ${s.exploit ? `<p class="ti-ssvc${/active/i.test(s.exploit) ? ' r' : ''}">${ico('shield-alert','sm')}CISA's assessment: exploitation <b>${esc(s.exploit)}</b>${s.cwe && s.cwe.length ? ' · ' + esc(s.cwe.join(', ')) : ''}</p>` : ''}
    ${g ? `<div class="iv-hits"><span>${ico('crosshair','sm')}In your cases</span>${entPill('cve:' + cve)}</div>` : ''}
    <h4 class="ti-h4">In the news <span class="t3">${arts.length}</span></h4>
    ${arts.length ? `<ul class="ti-arts">${arts.slice(0, 8).map(f => `<li><button class="linkbtn" data-act="ctiOpenFeed" data-id="${f.id}">${esc(f.title)}</button><small>${esc(f.source)} · ${esc(iAgo(f.ts))}</small></li>`).join('')}</ul>` : '<p class="t3">No story you have mentions it.</p>'}
    <p class="ti-links"><a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}" target="_blank" rel="noopener noreferrer">${ico('external-link','sm')}NVD</a><a href="https://www.cve.org/CVERecord?id=${encodeURIComponent(cve)}" target="_blank" rel="noopener noreferrer">${ico('external-link','sm')}CVE.org</a>${k ? `<a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${encodeURIComponent(cve)}" target="_blank" rel="noopener noreferrer">${ico('external-link','sm')}CISA KEV</a>` : ''}${(s.refs || []).map(u => E.safeUrl(String(u))).filter(Boolean).slice(0, 3).map(u => `<a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${ico('external-link','sm')}${esc(hostOf(u))}</a>`).join('')}</p>
    </div><footer><button class="btn" data-act="ient" data-v="cve:${esc(cve)}">${ico('newspaper','sm')}Show stories</button><span class="sp"></span><button class="btn primary" data-act="ctiCveToCase" data-v="${esc(cve)}">${ico('plus','sm')}Add to ${esc(theCase().code)}</button></footer>`);
}

/* ---------- Indicators ---------- */
function ctiIocList(){
  const q = (UI.oq || '').trim().toLowerCase(), k = UI.ok || '', src = UI.osrc || '', tl = UI.otlp || '', hitsOnly = UI.ohits, showExp = UI.oexp;
  const hitSet = hitsOnly ? new Set(ctiIocHits().map(h => h.ioc.id)) : null;
  return CTI.iocs.filter(x => (!k || x.k === k) && (!src || x.srcs.includes(src)) && (!tl || x.tlp === tl) && (showExp || iocLive(x)) && (!hitSet || hitSet.has(x.id))
    && (!q || (x.v + ' ' + x.tags.join(' ') + ' ' + x.threat + ' ' + x.desc).toLowerCase().includes(q))).sort((a, b) => b.last - a.last);
}
function ctiIocsView(){
  if(!CTI.iocs) return `<div class="card ti-loading">${ico('loader','sm spin')}Opening the indicator store…</div>`;
  const L = ctiIocList(), hits = ctiIocHits(), hitIds = new Set(hits.map(h => h.ioc.id)), lim = UI.olim || 200, all = CTI.iocs, exp = all.filter(x => !iocLive(x)).length;
  const kinds = countBy(all, x => x.k), srcs = countBy(all, x => x.srcs), feeds = DB.intel.sources.filter(s => { const m = ctiSrc(s.id); return m && m.kind === 'ioc'; });
  const d = t => t ? new Date(t).toISOString().slice(0, 10) : '—';
  return `<div class="ti-kpis">
      <div><b>${all.length.toLocaleString()}</b><span>indicators stored</span><small>${exp ? exp + ' expired' : 'none expired'}</small></div>
      <div class="${hits.length ? 'r' : ''}"><b>${hits.length}</b><span>also in your cases</span>${hits.length ? `<button class="linkbtn" data-act="ohits">${UI.ohits ? 'Show all' : 'Show them'}</button>` : ''}</div>
      <div><b>${srcs.length}</b><span>sources</span><small>${feeds.filter(s => s.on).length} live feed${feeds.filter(s => s.on).length === 1 ? '' : 's'} on</small></div>
      <div><b>${kinds.length}</b><span>kinds</span><small>${kinds.slice(0, 3).map(([k, n]) => esc(E.LABEL[k] || k) + ' ' + n).join(' · ')}</small></div></div>
    <div class="ti-bar"><div class="search-in">${ico('search')}<label class="sr" for="oq">Search indicators</label><input id="oq" class="inp" placeholder="Value, tag, malware…" value="${esc(UI.oq || '')}"></div>
      <label class="sr" for="okSel">Kind</label><select id="okSel" class="inp ti-sel"><option value="">Every kind</option>${kinds.map(([k, n]) => `<option value="${k}"${UI.ok === k ? ' selected' : ''}>${esc(E.LABEL[k] || k)} (${n})</option>`).join('')}</select>
      <label class="sr" for="osrcSel">Source</label><select id="osrcSel" class="inp ti-sel"><option value="">Every source</option>${srcs.map(([s, n]) => `<option${UI.osrc === s ? ' selected' : ''}>${esc(s)}</option>`).join('')}</select>
      <label class="sr" for="otlpSel">TLP</label><select id="otlpSel" class="inp ti-sel"><option value="">Any TLP</option>${TLP.map(t => `<option value="${t}"${UI.otlp === t ? ' selected' : ''}>TLP:${t.toUpperCase()}</option>`).join('')}</select>
      <button class="chip${UI.oexp ? ' accent' : ''}" data-act="oexp" aria-pressed="${!!UI.oexp}">Show expired</button>
      <span class="sp"></span><button class="btn" data-act="ctiImport">${ico('upload','sm')}Import</button><button class="btn" data-act="ctiExport">${ico('download','sm')}Export</button>
      <button class="iconbtn" data-act="ctiIocMore" aria-label="More">${ico('ellipsis','sm')}</button></div>
    ${L.length ? `<div class="card ti-tbl io" role="table" aria-label="Indicators"><div class="ti-tr3 h" role="row"><span role="columnheader">Indicator</span><span role="columnheader">Threat · tags</span><span role="columnheader">TLP</span><span class="n" role="columnheader">Conf.</span><span role="columnheader">Last seen</span><span role="columnheader">Expires</span><span role="columnheader">Source</span><span role="columnheader"><span class="sr">Actions</span></span></div>
      ${L.slice(0, lim).map(x => `<div class="ti-tr3${hitIds.has(x.id) ? ' hit' : ''}${iocLive(x) ? '' : ' exp'}" role="row">
        <span role="cell" class="ti-iv"><em>${esc(E.LABEL[x.k] || x.k)}</em><span class="mono">${esc(x.v)}</span>${hitIds.has(x.id) ? `<button class="ti-in" data-act="ctiIocCase" data-id="${x.id}">${ico('crosshair','sm')}In your cases</button>` : ''}</span>
        <span role="cell" class="ti-tg">${x.threat ? `<b>${esc(x.threat)}</b>` : ''}${x.tags.filter(t => t !== x.threat).slice(0, 4).map(t => `<i>${esc(t)}</i>`).join('')}</span>
        <span role="cell">${tlpTag(x.tlp)}</span><span role="cell" class="n">${x.conf == null ? '<span class="t3">—</span>' : x.conf}</span>
        <span role="cell" class="t2">${d(x.last)}</span><span role="cell" class="t2">${x.exp ? (iocLive(x) ? d(x.exp) : '<span class="ti-x">Expired</span>') : '<span class="t3">Never</span>'}</span>
        <span role="cell" class="t3 ti-sr" title="${esc(x.srcs.join(', '))}">${esc(x.srcs[0] || '')}${x.srcs.length > 1 ? ' +' + (x.srcs.length - 1) : ''}</span>
        <span role="cell" class="ti-ra"><button class="iconbtn" data-act="ctiIocAdd" data-id="${x.id}" aria-label="Add to case" title="Add to ${esc(theCase().code)}">${ico('plus','sm')}</button><button class="iconbtn" data-act="ctiIocDel" data-id="${x.id}" aria-label="Delete ${esc(x.v)}" title="Delete">${ico('trash-2','sm')}</button></span></div>`).join('')}
      ${L.length > lim ? `<button class="ti-moreb" data-act="olim">Show ${Math.min(200, L.length - lim)} more of ${L.length.toLocaleString()}</button>` : ''}</div>`
      : empty('fingerprint', all.length ? 'Nothing matches' : 'No indicators yet', all.length ? 'Try another filter.' : 'Import a STIX 2.1 bundle, a MISP event, a CSV or a plain list — or switch on an indicator feed in Sources. Everything is checked against your cases.',
        `<button class="btn primary" data-act="ctiImport">${ico('upload','sm')}Import indicators</button><button class="btn" data-act="feedSources" data-v="ioc">${ico('rss','sm')}Indicator feeds</button>`)}
    <p class="t3 small ti-fine">${ico('lock','sm')}Kept in this browser${SEC.key ? ', encrypted with your passphrase' : ''}. Up to ${CTI_IOC_MAX.toLocaleString()} indicators; expired ones stay hidden until you purge them.</p>`;
}
function ctiImportDlg(){
  openDlg(dhead('Import indicators') + `<div class="in">
    <p class="t2" style="margin:0 0 12px">STIX 2.1 bundles, MISP events (JSON), ThreatFox and Feodo exports, CSV with a value column, or any text — the format is worked out for you. Every value is re-checked; anything that is not a real indicator is skipped.</p>
    <div class="field"><label for="ctiPaste">Paste</label><textarea id="ctiPaste" class="mono" rows="7" placeholder="Paste a STIX bundle, MISP JSON, CSV or a list of indicators — or open a file below" spellcheck="false"></textarea></div>
    <div class="frow"><div class="field"><label for="ctiSrcName">Source name</label><input id="ctiSrcName" maxlength="80" placeholder="e.g. ISAC sharing, Partner report"></div>
      <div class="field"><label for="ctiTlpIn">TLP when the data has none</label><select id="ctiTlpIn">${TLP.map(t => `<option value="${t}"${t === 'amber' ? ' selected' : ''}>TLP:${t.toUpperCase()}</option>`).join('')}</select></div></div>
    <div class="frow"><div class="field"><label for="ctiConfIn">Confidence (0–100)</label><input id="ctiConfIn" type="number" min="0" max="100" placeholder="leave empty"></div>
      <div class="field"><label for="ctiDaysIn">Expire after (days)</label><input id="ctiDaysIn" type="number" min="0" max="3650" placeholder="never"></div></div>
    <div class="field"><label for="ctiTagsIn">Tags for all</label><input id="ctiTagsIn" maxlength="200" placeholder="comma separated"></div>
    </div><footer><button class="btn" data-act="ctiImportFile" style="margin-right:auto">${ico('file-up','sm')}Open a file…</button><button class="btn" data-act="dclose">Cancel</button><button class="btn primary" data-act="ctiImportGo">${ico('upload','sm')}Import</button></footer>`);
}
function ctiImportOpts(){ const n = id => { const v = $(id) && $(id).value.trim(); return v === '' ? null : Math.max(0, +v || 0); };
  return {tlp:$('ctiTlpIn').value, conf:n('ctiConfIn') == null ? null : Math.min(100, n('ctiConfIn')), days:n('ctiDaysIn'), tags:($('ctiTagsIn').value || '').split(',').map(t => cap(t, 64)).filter(Boolean)}; }
async function ctiDoImport(text, name, opts){
  try{ const r = await ctiImportText(text, cap(name, 80) || '', opts); closeDlg(); UI.itab = 'iocs'; renderMain();
    toast(`${r.fmt}: ${r.added} added${r.merged ? ', ' + r.merged + ' merged' : ''}${r.bad ? ', ' + r.bad + ' skipped' : ''}${r.full ? ' — store is full' : ''}`);
    const h = ctiIocHits().length; if(h) setTimeout(() => toast(h + ' indicator' + (h > 1 ? 's' : '') + ' from your feeds appear in your cases'), 1600); }
  catch(e){ toast(e.message || 'Could not read that'); }
}
function ctiExportDlg(){
  const L = ctiIocList();
  openDlg(dhead('Export indicators') + `<div class="in">
    <div class="field"><label for="ctiExWhat">What</label><select id="ctiExWhat"><option value="list">Indicators shown now (${L.length.toLocaleString()})</option><option value="all">Every live indicator (${CTI.iocs.filter(iocLive).length.toLocaleString()})</option>${DB.cases.map(c => `<option value="case:${c.id}">Case ${esc(c.code)} — ${esc(c.name)}</option>`).join('')}</select></div>
    <div class="frow"><div class="field"><label for="ctiExFmt">Format</label><select id="ctiExFmt"><option value="stix">STIX 2.1 bundle (JSON)</option><option value="misp">MISP event (JSON)</option><option value="csv">CSV</option></select></div>
      <div class="field"><label for="ctiExTlp">Marking</label><select id="ctiExTlp">${TLP.map(t => `<option value="${t}"${t === 'amber' ? ' selected' : ''}>TLP:${t.toUpperCase()}</option>`).join('')}</select></div></div>
    <p class="t3 small">Each indicator keeps its own TLP when it has one; the marking applies to the rest and to the report. Share only with people the TLP allows.</p>
    </div><footer><button class="btn" data-act="dclose">Cancel</button><button class="btn primary" data-act="ctiExportGo">${ico('download','sm')}Export</button></footer>`);
}
function ctiExportGo(){
  const what = $('ctiExWhat').value, fmt = $('ctiExFmt').value, tlp = $('ctiExTlp').value; let items, title;
  if(/^case:/.test(what)){ const c = theCase(what.slice(5)); items = ctiCaseItems(c.id); title = c.code + ' — ' + c.name; }
  else { items = what === 'all' ? CTI.iocs.filter(iocLive) : ctiIocList(); title = 'OSINTrix indicators ' + new Date().toISOString().slice(0, 10); }
  if(!items.length) return toast('Nothing to export');
  const base = slug(title) || 'indicators';
  if(fmt === 'csv') download(base + '.csv', ctiCsv(items), 'text/csv');
  else download(base + (fmt === 'stix' ? '.stix.json' : '.misp.json'), JSON.stringify(fmt === 'stix' ? ctiStix(items, title, tlp) : ctiMisp(items, title, tlp), null, 2), 'application/json');
  closeDlg(); toast(items.length + ' indicator' + (items.length > 1 ? 's' : '') + ' exported · TLP:' + tlp.toUpperCase());
}

/* ---------- Actors & ATT&CK ---------- */
function ctiMentions(days){
  const since = Date.now() - days * 864e5, m = new Map(), tech = new Map();
  for(const f of DB.feed){ if(f.ts < since) continue; const x = ctiX(f); [...x.act, ...x.mal].forEach(id => m.set(id, (m.get(id) || 0) + 1)); x.ttp.forEach(t => tech.set(t, (tech.get(t) || 0) + 1)); }
  return {m, tech};
}
function ctiMatrix(scores, title, sub){
  const A = typeof ATTACK !== 'undefined' ? ATTACK : {tactics:[], tech:[]}, D = ctiDict(), mx = Math.max(1, ...scores.values());
  const cols = A.tactics.map(([tid, short, name]) => { const L = [...scores.entries()].filter(([id]) => { const t = D.tech.get(id) || D.tech.get(id.split('.')[0]); return t && t[2].includes(short); }).sort((a, b) => b[1] - a[1]); return {tid, name, L}; });
  const used = cols.filter(c => c.L.length);
  return `<section class="card ti-mx"><div class="ti-mx-h"><h4>${ico('grid-3x3','sm')}${esc(title)}</h4><span class="t3">${esc(sub)}</span><span class="sp"></span>${scores.size ? `<button class="btn sm" data-act="ctiNav" data-v="${esc(title)}">${ico('download','sm')}ATT&CK Navigator layer</button>` : ''}</div>
    ${used.length ? `<div class="ti-mx-g" style="--n:${used.length}">${used.map(c => `<div class="ti-mx-c"><p>${esc(c.name)}<small>${c.L.length}</small></p>${c.L.slice(0, 14).map(([id, n]) => `<button class="ti-mx-t" data-act="ctiTech" data-v="${esc(id)}" style="--a:${(0.14 + 0.86 * n / mx).toFixed(2)}" title="${esc(id + ' ' + techName(id))} · ${n}"><b>${esc(id)}</b><span>${esc(techName(id))}</span></button>`).join('')}${c.L.length > 14 ? `<small class="t3">+${c.L.length - 14} more</small>` : ''}</div>`).join('')}</div>`
      : '<p class="t3" style="margin:0">No techniques yet. Stories that mention technique IDs such as T1059, or the actors you look at, fill this in.</p>'}</section>`;
}
UI.ctiNavScores = null;
function ctiAttackView(){
  const A = typeof ATTACK !== 'undefined' ? ATTACK : null; if(!A) return empty('crosshair', 'ATT&CK data is missing', 'js/data/attack.js is not loaded.');
  const D = ctiDict(), kind = UI.akind || 'g', q = (UI.aq || '').trim().toLowerCase(), M = ctiMentions(30), sel = UI.actor && (D.grp.get(UI.actor) || D.soft.get(UI.actor));
  const list = (kind === 'g' ? A.groups : A.soft).filter(x => !q || (x.n + ' ' + x.a.join(' ') + ' ' + x.id).toLowerCase().includes(q))
    .sort((a, b) => (M.m.get(b.id) || 0) - (M.m.get(a.id) || 0) || a.n.localeCompare(b.n));
  let main;
  if(sel){
    const isG = /^G/.test(sel.id), arts = DB.feed.filter(f => { const x = ctiX(f); return x.act.includes(sel.id) || x.mal.includes(sel.id); }).sort((a, b) => b.ts - a.ts);
    const techs = new Map((sel.t || []).map(t => [t, 1])); for(const f of arts) ctiX(f).ttp.forEach(t => techs.set(t, (techs.get(t) || 0) + 2));
    const users = isG ? [] : A.groups.filter(g => (g.s || []).includes(sel.id));
    UI.ctiNavScores = techs;
    main = `<section class="card ti-actor"><div class="ti-actor-h"><span class="ti-av">${ico(isG ? 'users' : 'skull')}</span><div><h2>${esc(sel.n)}</h2><p class="t3"><span class="mono">${esc(sel.id)}</span> · ${isG ? 'Threat group' : sel.k === 'm' ? 'Malware' : 'Tool'}${sel.a.length ? ' · also ' + esc(sel.a.slice(0, 8).join(', ')) : ''}</p></div><span class="sp"></span>
        <a class="btn sm" href="https://attack.mitre.org/${isG ? 'groups' : 'software'}/${encodeURIComponent(sel.id)}/" target="_blank" rel="noopener noreferrer">${ico('external-link','sm')}MITRE</a><button class="btn sm" data-act="ient" data-v="act:${esc(sel.id)}">${ico('newspaper','sm')}Stories</button><button class="iconbtn" data-act="actor" data-v="" aria-label="Close">${ico('x','sm')}</button></div>
      ${sel.d ? `<p class="t2">${esc(sel.d)}</p>` : ''}
      <div class="ti-actor-k"><div><b>${(sel.t || []).length}</b><span>techniques</span></div>${isG ? `<div><b>${(sel.s || []).length}</b><span>malware &amp; tools</span></div>` : `<div><b>${users.length}</b><span>groups use it</span></div>`}<div><b>${arts.length}</b><span>stories you have</span></div><div><b>${M.m.get(sel.id) || 0}</b><span>in 30 days</span></div></div>
      ${isG && sel.s && sel.s.length ? `<div class="ti-chips">${sel.s.slice(0, 24).map(id => actChip(id)).join('')}</div>` : ''}${users.length ? `<div class="ti-chips">${users.slice(0, 24).map(g => actChip(g.id)).join('')}</div>` : ''}
      ${arts.length ? `<ul class="ti-arts">${arts.slice(0, 5).map(f => `<li><button class="linkbtn" data-act="ctiOpenFeed" data-id="${f.id}">${esc(f.title)}</button><small>${esc(f.source)} · ${esc(iAgo(f.ts))}</small></li>`).join('')}</ul>` : ''}</section>
      ${ctiMatrix(techs, sel.n + ' — techniques', 'From MITRE ATT&CK' + (arts.length ? ', plus those named in your stories' : ''))}`;
  } else {
    UI.ctiNavScores = M.tech;
    main = ctiMatrix(M.tech, 'Techniques in the news', 'Named in stories from the last 30 days') + `<section class="card ti-actor"><h4>${ico('info','sm')}How this works</h4><p class="t2">Actor and malware names, aliases and technique IDs are read from every story, using MITRE ATT&CK ${esc(A.v)} — ${A.live ? 'fetched from MITRE ' + esc(iAgo(A.live)) : 'the copy that ships with OSINTrix; turn on MITRE ATT&CK in Sources → Reference data to keep it current'}. Pick a group or a piece of malware to see what it does.</p></section>`;
  }
  return `<div class="ti-at">
    <aside class="card ti-al"><div class="seg" role="group" aria-label="Show">${[['g','Groups', A.groups.length], ['m','Software', A.soft.length]].map(([k, l, n]) => `<button data-act="akind" data-v="${k}" aria-pressed="${kind === k}">${l}<small>${n}</small></button>`).join('')}</div>
      <div class="search-in">${ico('search')}<label class="sr" for="aq">Find</label><input id="aq" class="inp" placeholder="${kind === 'g' ? 'APT29, Lazarus, Volt Typhoon…' : 'Cobalt Strike, QakBot…'}" value="${esc(UI.aq || '')}"></div>
      <div class="ti-al-l">${list.slice(0, 200).map(x => `<button class="ti-al-i${UI.actor === x.id ? ' on' : ''}" data-act="actor" data-v="${esc(x.id)}"><span><b>${esc(x.n)}</b><small>${esc(x.a.slice(0, 3).join(', ') || x.id)}</small></span>${M.m.get(x.id) ? `<em>${M.m.get(x.id)}</em>` : ''}</button>`).join('')}${list.length > 200 ? `<p class="t3 small">${list.length - 200} more — refine the search.</p>` : ''}</div></aside>
    <div class="ti-am">${main}</div></div>`;
}
function ctiNavLayer(title){
  const S = UI.ctiNavScores || new Map(), mx = Math.max(1, ...S.values());
  return {name:cap(title, 120), versions:{attack:'16', navigator:'5.1.0', layer:'4.5'}, domain:'enterprise-attack', description:'Exported from OSINTrix ' + new Date().toISOString().slice(0, 10),
    techniques:[...S.entries()].map(([id, n]) => ({techniqueID:id, score:n, color:'', comment:'', enabled:true, showSubtechniques:false})),
    gradient:{colors:['#ffe8e6', '#e5484d'], minValue:0, maxValue:mx}, legendItems:[], showTacticRowBackground:false, selectTechniquesAcrossTactics:true};
}

/* ---------- Briefs ---------- */
function ctiBriefData(){
  const days = +(UI.bdays || 7), since = Date.now() - days * 864e5, inc = UI.binc || {star:true, rel:true, crit:true, kev:true, act:true, hits:true};
  const items = DB.feed.filter(f => f.ts >= since), S = ctiStories(items);
  const pick = S.filter(st => (inc.star && st.items.some(f => f.star)) || (inc.rel && st.items.some(f => /relevant|actioned/.test(triage(f)))) || (inc.crit && st.lead.sev === 'critical' && !st.items.every(f => triage(f) === 'dismissed')))
    .sort((a, b) => (b.items.some(f => f.star) - a.items.some(f => f.star)) || b.ts - a.ts).slice(0, 25);
  const kev = inc.kev ? [...CTI.kev.values()].filter(k => Date.parse(k.added) >= since).sort((a, b) => (ctiInStack(b.vendor, b.product) - ctiInStack(a.vendor, a.product)) || b.added.localeCompare(a.added)) : [];
  const M = ctiMentions(days), acts = inc.act ? [...M.m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8) : [], techs = inc.act ? [...M.tech.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8) : [];
  const hits = inc.hits && CTI.iocs ? ctiIocHits() : [];
  return {days, since, pick, kev, acts, techs, hits, tlp:UI.btlp || 'green'};
}
function ctiBriefMd(B){
  const d = t => new Date(t).toISOString().slice(0, 10), L = [];
  L.push(`# Threat brief — ${d(B.since)} to ${d(Date.now())}`, '', `**TLP:${B.tlp.toUpperCase()}** · prepared with OSINTrix`, '');
  L.push('## Summary', '', `- ${B.pick.length} stor${B.pick.length === 1 ? 'y' : 'ies'} selected for the team`, `- ${B.kev.length} vulnerabilit${B.kev.length === 1 ? 'y' : 'ies'} added to CISA KEV${B.kev.filter(k => ctiInStack(k.vendor, k.product)).length ? ` (${B.kev.filter(k => ctiInStack(k.vendor, k.product)).length} in our stack)` : ''}`, ...(B.hits.length ? [`- ${B.hits.length} indicator${B.hits.length > 1 ? 's' : ''} from our feeds appear in open cases`] : []), '');
  if(B.pick.length){ L.push('## Key stories', ''); for(const st of B.pick){ const f = st.lead, X = st.items.map(ctiX), cve = [...new Set(X.flatMap(x => x.cve))];
    L.push(`### ${f.title.replace(/[#*_`[\]]/g, '')}`, '', `${f.source}${st.sources.length > 1 ? ' and ' + (st.sources.length - 1) + ' more' : ''} · ${d(st.ts)}${f.sev !== 'normal' ? ' · ' + f.sev : ''}`, '', f.body.slice(0, 500).replace(/[#*_`[\]]/g, ''), '',
      ...(cve.length ? ['CVEs: ' + cve.map(c => c + (kevOf(c) ? ' (exploited)' : '')).join(', '), ''] : []), ...(f.link ? [`Source: <${f.link}>`, ''] : [])); } }
  if(B.kev.length){ L.push('## Newly known exploited (CISA KEV)', '', '| CVE | Vendor / product | Added | Ransomware | Our stack |', '|---|---|---|---|---|', ...B.kev.slice(0, 40).map(k => `| ${k.cve} | ${k.vendor} / ${k.product} | ${k.added} | ${k.ransom ? 'yes' : ''} | ${ctiInStack(k.vendor, k.product) ? '**yes**' : ''} |`.replace(/\|(?=[^|]*$)/, '|')), ''); }
  if(B.acts.length) L.push('## Most mentioned actors and malware', '', ...B.acts.map(([id, n]) => `- ${actName(id)} (${id}) — ${n} stor${n === 1 ? 'y' : 'ies'}`), '');
  if(B.techs.length) L.push('## ATT&CK techniques in the news', '', ...B.techs.map(([id, n]) => `- ${id} ${techName(id)} — ${n}`), '');
  if(B.hits.length) L.push('## Feed indicators seen in our cases', '', ...B.hits.slice(0, 30).map(h => `- \`${h.ioc.v}\` (${E.LABEL[h.ioc.k] || h.ioc.k}) — ${h.ioc.threat || h.ioc.srcs[0] || 'feed'}`), '');
  return L.join('\n');
}
function ctiBriefHtml(B){
  const d = t => new Date(t).toISOString().slice(0, 10), stackKev = B.kev.filter(k => ctiInStack(k.vendor, k.product)).length;
  return `<h2>Threat brief — ${d(B.since)} to ${d(Date.now())}</h2><p><b>TLP:${esc(B.tlp.toUpperCase())}</b> · prepared with OSINTrix</p>
    <h3>Summary</h3><ul><li>${B.pick.length} stor${B.pick.length === 1 ? 'y' : 'ies'} selected for the team</li><li>${B.kev.length} vulnerabilit${B.kev.length === 1 ? 'y' : 'ies'} added to CISA KEV${stackKev ? ` (<b>${stackKev} in our stack</b>)` : ''}</li>${B.hits.length ? `<li><b>${B.hits.length}</b> indicator${B.hits.length > 1 ? 's' : ''} from our feeds appear in open cases</li>` : ''}</ul>
    ${B.pick.length ? '<h3>Key stories</h3>' + B.pick.map(st => { const f = st.lead, cve = [...new Set(st.items.flatMap(i => ctiX(i).cve))];
      return `<h4>${esc(f.title)}</h4><p><i>${esc(f.source)}${st.sources.length > 1 ? ' and ' + (st.sources.length - 1) + ' more' : ''} · ${d(st.ts)}${f.sev !== 'normal' ? ' · ' + esc(f.sev) : ''}</i></p><p>${esc(f.body.slice(0, 500))}</p>${cve.length ? `<p>CVEs: ${cve.map(c => esc(c) + (kevOf(c) ? ' <b>(exploited)</b>' : '')).join(', ')}</p>` : ''}${E.safeUrl(f.link) ? `<p><a href="${esc(E.safeUrl(f.link))}">${esc(hostOf(f.link))}</a></p>` : ''}`; }).join('') : ''}
    ${B.kev.length ? `<h3>Newly known exploited (CISA KEV)</h3><table><thead><tr><th>CVE</th><th>Vendor / product</th><th>Added</th><th>Ransomware</th><th>Our stack</th></tr></thead><tbody>${B.kev.slice(0, 40).map(k => `<tr><td>${esc(k.cve)}</td><td>${esc(k.vendor)} / ${esc(k.product)}</td><td>${esc(k.added)}</td><td>${k.ransom ? 'yes' : ''}</td><td>${ctiInStack(k.vendor, k.product) ? '<b>yes</b>' : ''}</td></tr>`).join('')}</tbody></table>` : ''}
    ${B.acts.length ? `<h3>Most mentioned actors and malware</h3><ul>${B.acts.map(([id, n]) => `<li>${esc(actName(id))} (${esc(id)}) — ${n}</li>`).join('')}</ul>` : ''}
    ${B.techs.length ? `<h3>ATT&amp;CK techniques in the news</h3><ul>${B.techs.map(([id, n]) => `<li>${esc(id)} ${esc(techName(id))} — ${n}</li>`).join('')}</ul>` : ''}
    ${B.hits.length ? `<h3>Feed indicators seen in our cases</h3><ul>${B.hits.slice(0, 30).map(h => `<li><code>${esc(h.ioc.v)}</code> — ${esc(h.ioc.threat || h.ioc.srcs[0] || 'feed')}</li>`).join('')}</ul>` : ''}`;
}
function ctiBriefView(){
  const B = ctiBriefData(), inc = UI.binc || {star:true, rel:true, crit:true, kev:true, act:true, hits:true};
  const opt = (k, l) => `<label class="ti-ck"><input type="checkbox" data-act="binc" data-v="${k}" ${inc[k] ? 'checked' : ''}>${l}</label>`;
  return `<div class="ti-br">
    <aside class="card ti-bo"><h4>${ico('sliders-horizontal','sm')}Build the brief</h4>
      <div class="field"><label for="bdays">Period</label><select id="bdays" class="inp">${[[1,'Last 24 hours'],[7,'Last 7 days'],[14,'Last 14 days'],[30,'Last 30 days']].map(([d, l]) => `<option value="${d}"${B.days === d ? ' selected' : ''}>${l}</option>`).join('')}</select></div>
      <p class="ti-bl">Include</p>${opt('star', 'Starred stories')}${opt('rel', 'Stories marked relevant')}${opt('crit', 'Critical stories')}${opt('kev', 'New CISA KEV entries')}${opt('act', 'Top actors and techniques')}${opt('hits', 'Feed indicators in our cases')}
      <div class="field"><label for="btlp">Marking</label><select id="btlp" class="inp">${TLP.map(t => `<option value="${t}"${B.tlp === t ? ' selected' : ''}>TLP:${t.toUpperCase()}</option>`).join('')}</select></div>
      <div class="ti-bb"><button class="btn primary" data-act="ctiBriefNb">${ico('notebook-pen','sm')}Save to Notebook</button><button class="btn" data-act="ctiBriefMd">${ico('download','sm')}Markdown</button><button class="btn" data-act="ctiBriefCopy">${ico('copy','sm')}Copy</button></div>
      <p class="t3 small">Star stories in News to choose what goes in. The Notebook page can be edited and exported to Word or PDF from there.</p></aside>
    <article class="card ti-bp nb-prose">${B.pick.length || B.kev.length || B.acts.length ? ctiBriefHtml(B) : empty('file-text', 'Nothing to brief yet', 'Star or mark stories as relevant in News, or widen the period.', `<button class="btn" data-act="itab" data-v="feed">${ico('newspaper','sm')}Go to News</button>`)}</article></div>`;
}

/* ---------- Sources ---------- */
function sourcesDlg(tab){
  ensureIntel(); const t = tab || UI.srcTab || 'news'; UI.srcTab = t;
  const st = s => s.status === 'error' ? `<span class="ti-err">${esc(s.err || 'Failed')}</span>` : s.last ? `<span class="ti-ok">OK · ${esc(iAgo(s.last))}${s.n ? ' · ' + s.n : ''}</span>` : '';
  const rssRow = s => `<div class="srow"><label class="sw"><input type="checkbox" data-act="srcToggle" data-id="${s.id}" ${s.on ? 'checked' : ''}><span></span></label>
    <div class="tn"><b>${esc(s.name)}</b><span class="mono">${esc(s.url)}</span>${st(s)}</div><button class="iconbtn" data-act="srcDel" data-id="${s.id}" aria-label="Remove ${esc(s.name)}">${ico('trash-2','sm')}</button></div>`;
  const dataRow = id => { const s = ctiSrc(id); return `<div class="srow ti-srow"><label class="sw"><input type="checkbox" data-act="ctiSrcToggle" data-id="${s.id}" ${s.on ? 'checked' : ''} aria-label="Use ${esc(s.name)}"><span></span></label>
    <div class="tn"><b>${esc(s.name)}</b><span class="ti-host">${ico('globe','sm')}Contacts <span class="mono">${esc(s.host)}</span></span><span class="t3">${esc(s.about)}</span>${st(s)}
      ${s.auth ? `<span class="ti-key"><label for="key-${s.id}">${esc(s.auth)}</label><input id="key-${s.id}" type="password" class="inp" data-ctikey="${s.id}" value="${esc(s.key || '')}" placeholder="optional — kept in this browser" autocomplete="off" spellcheck="false"></span>` : ''}</div>
    ${s.custom ? `<button class="iconbtn" data-act="ctiSrcDel" data-id="${s.id}" aria-label="Remove ${esc(s.name)}">${ico('trash-2','sm')}</button>` : ''}</div>`; };
  const tabs = [['news','News feeds', DB.feedSources.filter(s => s.on).length], ['data','Reference data', ['kev','epss','nvd','attack'].filter(id => ctiSrc(id).on).length], ['ioc','Indicator feeds', DB.intel.sources.filter(s => s.on && ctiSrc(s.id) && ctiSrc(s.id).kind === 'ioc').length], ['look','Lookups', LK_PROVIDERS.filter(lkOn).length]];
  openDlg(dhead('Threat Intel sources') + `<nav class="ti-dtabs" role="tablist">${tabs.map(([k, l, n]) => `<button role="tab" data-act="srcTab" data-v="${k}" aria-selected="${t === k}">${l}<span>${n}</span></button>`).join('')}</nav><div class="in">
    ${t === 'news' ? `<div class="ti-relay ${DB.prefs.liveFeeds ? 'on' : ''}">${ico(DB.prefs.liveFeeds ? 'wifi' : 'wifi-off','sm')}<span>${DB.prefs.liveFeeds ? 'Live — news is fetched through <b class="mono">api.rss2json.com</b>.' : 'Offline — news is not fetched until you allow the relay.'}</span>${DB.prefs.liveFeeds ? `<button class="btn sm" data-act="intelOff">${ico('wifi-off','sm')}Go offline</button>` : `<button class="btn sm primary" data-act="intelAsk">${ico('wifi','sm')}Allow…</button>`}</div>
      <div class="srcs">${DB.feedSources.map(rssRow).join('')}</div>
      <form data-form="src" class="frow" style="margin-top:16px;align-items:end"><div class="field" style="margin:0"><label for="srcName">Name</label><input id="srcName" required maxlength="80" placeholder="My vendor's advisories"></div>
        <div class="field" style="margin:0"><label for="srcUrl">RSS / Atom URL</label><input id="srcUrl" type="url" required pattern="https?://.+" placeholder="https://…/feed.xml"></div>
        <button class="btn" type="submit" style="grid-column:1/-1;justify-self:start">${ico('plus','sm')}Add news source</button></form>`
    : t === 'look' ? lkSourcesTab()
    : t === 'data' ? `<p class="t2" style="margin:0 0 12px">Each source is off until you switch it on, and contacts only the host shown. Turning one on is your consent for that host.</p><div class="srcs">${['kev','epss','nvd','attack'].map(dataRow).join('')}</div>`
    : `<p class="t2" style="margin:0 0 12px">Indicator feeds are fetched when you press Refresh, merged into the indicator store with a 14-day expiry and checked against your cases. abuse.ch does not allow browser access, so these come through your relay (set it up under <b>Lookups</b>). Any other feed (STIX, MISP, CSV, plain lists) can be imported with <b>Indicators → Import</b>.</p>
      <div class="srcs">${DB.intel.sources.filter(s => { const m = ctiSrc(s.id); return m && m.kind === 'ioc'; }).map(s => dataRow(s.id)).join('')}</div>
`}
    </div><footer>${t === 'news' ? `<button class="btn ghost" data-act="srcReset" style="margin-right:auto">Restore defaults</button>` : '<span class="sp"></span>'}<button class="btn primary" data-act="dclose">Done</button></footer>`);
}

/* ---------- binding inputs, and the actions ---------- */
function bindIntel(){
  const on = (id, fn, t = 160) => { const el = $(id); if(el) el.oninput = () => { fn(el.value); clearTimeout(bindIntel.t); bindIntel.t = setTimeout(() => { renderMain(); keep(id); }, t); }; };
  on('vq', v => UI.vq = v); on('oq', v => UI.oq = v); on('aq', v => UI.aq = v);
  const sel = (id, fn) => { const el = $(id); if(el) el.onchange = () => { fn(el.value); renderMain(); }; };
  sel('icatSel', v => UI.icat = v); sel('isort', v => { UI.isort = v; UI.ilim = 0; }); sel('vsort', v => UI.vsort = v); sel('okSel', v => { UI.ok = v; UI.olim = 0; }); sel('osrcSel', v => { UI.osrc = v; UI.olim = 0; }); sel('otlpSel', v => UI.otlp = v);
  sel('bdays', v => UI.bdays = +v); sel('btlp', v => UI.btlp = v);
}
function keep(id){ const el = $(id); if(el){ el.focus(); const n = el.value.length; try{ el.setSelectionRange(n, n); }catch(e){} } }
function ctiStoryOf(id){ const f = DB.feed.find(x => x.id === id); if(!f) return [f]; const S = ctiStories(DB.feed.filter(x => Math.abs(x.ts - f.ts) < 8 * 864e5)); const st = S.find(s => s.items.includes(f)); return st ? st.items : [f]; }
/* put an indicator in the active case's vault (once), falling back to an evidence record for kinds the vault has no type for */
function ctiAddEntry(k, v, label){
  const type = typeof KIND_TO_TYPE !== 'undefined' && KIND_TO_TYPE[k], key = k + ':' + v;
  if(type && TYPES[type]){
    if(DB.entries.some(e => e.caseId === DB.active && entryKey(e) === key)) return false;
    DB.entries.push({id:uid('v'), caseId:DB.active, type, fields:{[TYPES[type].fields[0][0]]:v}, priority:'medium', starred:false, tags:['threat-intel'], notes:cap(label, 300), src:'', created:Date.now(), pos:null});
    return true;
  }
  DB.records.push({id:uid('r'), caseId:DB.active, type:'evidence', title:cap(label || v, 200), body:v + (label ? '\n\n' + label : ''), tsRaw:'', tsZone:'explicit', ts:Date.now(), source:'threat intel', host:'', tags:['intel'], ents:E.extract(v), answer:'', addedBy:'You', addedAt:Date.now(), hash:''});
  return true;
}
const CTI_ACTS = {
  itab:(id, v, t) => { UI.itab = v; if(t && t.dataset.x === 'hits') UI.ohits = true; UI.sel = null; renderMain(); const s = document.querySelector('#main .scroll'); if(s) s.scrollTop = 0; },
  itri:(id, v) => { UI.itri = v; UI.ilim = 0; renderMain(); }, istack:() => { UI.istack = !UI.istack; renderMain(); }, ient:(id, v) => { UI.ient = v; UI.itab = 'feed'; UI.itri = v ? 'all' : UI.itri; closeDlg(); renderMain(); },
  ilim:() => { UI.ilim = (UI.ilim || 60) + 60; renderMain(); }, vlim:() => { UI.vlim = (UI.vlim || 100) + 100; renderMain(); }, olim:() => { UI.olim = (UI.olim || 200) + 200; renderMain(); },
  vmode:(id, v) => { UI.vmode = v; UI.vlim = 0; UI.vsort = null; renderMain(); }, vkev:() => { UI.vkev = !UI.vkev; renderMain(); }, vransom:() => { UI.vransom = !UI.vransom; renderMain(); },
  ohits:() => { UI.ohits = !UI.ohits; renderMain(); }, oexp:() => { UI.oexp = !UI.oexp; renderMain(); },
  akind:(id, v) => { UI.akind = v; renderMain(); }, actor:(id, v) => { UI.actor = v || null; UI.itab = 'attack'; UI.akind = v && !/^G/.test(v) ? 'm' : v ? 'g' : UI.akind; closeDlg(); renderMain(); },
  ctiActor:(id, v) => CTI_ACTS.actor(null, v),
  ctiTech:(id, v) => { const t = ctiDict().tech.get(v) || ctiDict().tech.get(String(v).split('.')[0]); showMenu(innerWidth / 2 - 140, 160, [{label:(t ? v + ' — ' + t[1] : v), icon:'crosshair', fn:() => {}, disabled:true},
    {label:'Stories that name it', icon:'newspaper', fn:() => CTI_ACTS.ient(null, 'ttp:' + v)}, {label:'Open on attack.mitre.org', icon:'external-link', fn:() => window.open('https://attack.mitre.org/techniques/' + String(v).replace('.', '/') + '/', '_blank', 'noopener,noreferrer')}]); },
  ctiCve:(id, v) => ctiCveDlg(v),
  ctiStar:id => { const L = ctiStoryOf(id), on = !L.some(f => f.star); L.forEach(f => { f.star = on; f.read = true; }); mutate(on ? 'starred a story' : 'unstarred a story'); renderMain(); },
  ctiTri:(id, v) => { const L = ctiStoryOf(id); L.forEach(f => { f.st = f.st === v && v === 'relevant' ? 'new' : v; f.read = true; }); mutate('triaged a story'); renderMain(); if(v === 'dismissed') toast('Dismissed — find it under Dismissed', 'Undo', () => { L.forEach(f => f.st = 'new'); mutate('undo dismiss'); renderMain(); }); },
  ctiReadAll:() => { const S = ctiFeedList(); S.forEach(st => st.items.forEach(f => f.read = true)); mutate('marked stories read'); renderMain(); },
  ctiStoryMenu:(id, v, t) => { const r = t.getBoundingClientRect(), f = DB.feed.find(x => x.id === id), L = ctiStoryOf(id), u = E.safeUrl(f.link);
    showMenu(r.right - 240, r.bottom + 4, [...(u ? [{label:'Read the original', icon:'external-link', fn:() => window.open(u, '_blank', 'noopener,noreferrer')}] : []),
      {label:'Add to ' + theCase().code, icon:'plus', fn:() => clickAct('feedToCase', id)}, {label:'Mark actioned', icon:'check-check', fn:() => { L.forEach(x => { x.st = 'actioned'; x.read = true; }); mutate('actioned a story'); renderMain(); }},
      {label:L.every(x => x.read) ? 'Mark unread' : 'Mark read', icon:'mail', fn:() => { const r2 = !L.every(x => x.read); L.forEach(x => x.read = r2); mutate('read state'); renderMain(); }},
      ...(L.length > 1 ? [{sep:true}, ...L.map(x => ({label:x.source + ': ' + x.title, icon:'newspaper', fn:() => select('feed', x.id)}))] : [])]); },
  ctiOpenFeed:id => { closeDlg(); UI.itab = 'feed'; select('feed', id); },
  ctiCveToCase:(id, v) => { ctiAddEntry('cve', v, kevOf(v) ? 'CISA KEV: ' + kevOf(v).name : ''); mutate('added ' + v); closeDlg(); toast(v + ' added to ' + theCase().code); },
  ctiEpssOne:async (id, v) => { try{ await ctiEpss([v]); save(); ctiCveDlg(v); }catch(e){ ctiSrcErr('epss', e); toast(e.message); } },
  ctiNvdOne:async (id, v, t) => { if(t) t.disabled = true; try{ await ctiNvd(v); save(); ctiCveDlg(v); }catch(e){ ctiSrcErr('nvd', e); toast(e.message); if(t) t.disabled = false; } },
  ctiEpssShown:async (id, v, t) => { const R = ctiVulnRows().slice(0, UI.vlim || 100).filter(r => !(r.s.epssAt > Date.now() - 864e5)).map(r => r.c); if(!R.length) return toast('Scores are already fresh');
    if(t) t.disabled = true; try{ const n = await ctiEpss(R); save(); renderMain(); toast('EPSS for ' + n + ' CVE' + (n === 1 ? '' : 's')); }catch(e){ ctiSrcErr('epss', e); toast(e.message); if(t) t.disabled = false; } },
  ctiVulnStack:() => { UI.itab = 'vulns'; UI.vmode = 'stack'; renderMain(); },
  ctiStackDel:(id, v) => { const s = DB.intel.stack.splice(+v, 1)[0]; mutate('stopped watching ' + (s && s.vendor)); renderMain(); },
  ctiImport:() => ctiImportDlg(),
  ctiImportFile:() => pickFile('.json,.csv,.txt,.stix,application/json,text/csv,text/plain', (txt, name) => { const o = ctiImportOpts(); ctiDoImport(txt, ($('ctiSrcName').value || name || '').trim(), o); }),
  ctiImportGo:() => { const txt = $('ctiPaste').value; if(!txt.trim()) return toast('Paste something or open a file'); ctiDoImport(txt, $('ctiSrcName').value.trim() || 'Pasted', ctiImportOpts()); },
  ctiExport:() => ctiExportDlg(), ctiExportGo:() => ctiExportGo(),
  ctiIocMore:(id, v, t) => { const r = t.getBoundingClientRect(), L = ctiIocList(), exp = CTI.iocs.filter(x => !iocLive(x)).length;
    showMenu(r.right - 260, r.bottom + 4, [{label:'Purge ' + exp + ' expired', icon:'timer-off', disabled:!exp, fn:async () => { const n = ctiPurgeExpired(); await ctiSaveIocs(); renderMain(); toast(n + ' expired indicator' + (n === 1 ? '' : 's') + ' removed'); }},
      {label:'Delete the ' + L.length.toLocaleString() + ' shown', icon:'trash-2', disabled:!L.length, fn:() => confirmDlg('Delete ' + L.length.toLocaleString() + ' indicators?', 'They are removed from the indicator store in this browser. Your cases are not changed.', 'Delete', async () => { const ids = new Set(L.map(x => x.id)); CTI.iocs = CTI.iocs.filter(x => !ids.has(x.id)); ctiIocIndex(); await ctiSaveIocs(); renderMain(); toast('Deleted'); })},
      {label:'Add the shown to ' + theCase().code, icon:'plus', disabled:!L.length || L.length > 500, fn:() => { L.slice(0, 500).forEach(x => ctiAddEntry(x.k, x.v, [x.threat, ...x.tags].filter(Boolean).slice(0, 3).join(', '))); mutate('added indicators'); toast(Math.min(500, L.length) + ' added to ' + theCase().code); }}]); },
  ctiIocAdd:id => { const x = CTI.iocs.find(i => i.id === id); if(!x) return; ctiAddEntry(x.k, x.v, [x.threat, ...x.tags].filter(Boolean).slice(0, 3).join(', ') || x.srcs[0]); mutate('added ' + x.v); toast(x.v + ' added to ' + theCase().code); },
  ctiIocDel:async id => { const i = CTI.iocs.findIndex(x => x.id === id); if(i < 0) return; const [x] = CTI.iocs.splice(i, 1); ctiIocIndex(); await ctiSaveIocs(); renderMain();
    toast('Deleted ' + x.v, 'Undo', async () => { CTI.iocs.push(x); ctiIocIndex(); await ctiSaveIocs(); renderMain(); }); },
  ctiIocCase:id => { const x = CTI.iocs.find(i => i.id === id); if(x) select('ent', x.k + ':' + x.v); },
  ctiNav:(id, v) => download(slug(v || 'attack-layer') + '.layer.json', JSON.stringify(ctiNavLayer(v), null, 2), 'application/json'),
  binc:(id, v, t) => { UI.binc = {...(UI.binc || {star:true, rel:true, crit:true, kev:true, act:true, hits:true}), [v]:t.checked}; renderMain(); },
  ctiBriefMd:() => { const B = ctiBriefData(); download('threat-brief-' + new Date().toISOString().slice(0, 10) + '.md', ctiBriefMd(B), 'text/markdown'); },
  ctiBriefCopy:async () => { try{ await navigator.clipboard.writeText(ctiBriefMd(ctiBriefData())); toast('Brief copied as Markdown'); }catch(e){ toast('Copy failed — use Markdown instead'); } },
  ctiBriefNb:() => { if(typeof ensureNB !== 'function') return toast('The Notebook is not available'); ensureNB(); const B = ctiBriefData();
    let book = DB.nb.books.find(b => b.name === 'Threat briefs') || nbNewBook({name:'Threat briefs', kind:'Research'}), sec = DB.nb.sections.find(s => s.bookId === book.id) || nbNewSec(book.id, 'Weekly');
    const p = nbNewPage(sec.id, {title:'Threat brief ' + new Date().toISOString().slice(0, 10), html:nbClean(ctiBriefHtml(B)), tags:['threat-intel', 'tlp:' + B.tlp], src:'Threat Intel'});
    mutate('saved a threat brief'); UI.nbView = 'page'; UI.nbPage = p.id; go('#/notebook'); toast('Brief saved to Notebook → Threat briefs'); },
  feedSources:(id, v) => sourcesDlg(v || undefined), srcTab:(id, v) => sourcesDlg(v), intelAsk:() => intelConsent(),
  ctiSrcToggle:(id, v, t) => { const s = DB.intel.sources.find(x => x.id === id); if(!s) return; s.on = t.checked; if(!s.on){ s.status = ''; } mutate((s.on ? 'turned on ' : 'turned off ') + (ctiSrc(id).name)); },
  ctiSrcDel:id => { DB.intel.sources = DB.intel.sources.filter(x => x.id !== id); mutate('removed an indicator feed'); sourcesDlg('ioc'); },
};
document.addEventListener('change', ev => { const t = ev.target; if(t && t.dataset && t.dataset.ctikey){ const s = DB.intel.sources.find(x => x.id === t.dataset.ctikey); if(s){ s.key = cap(t.value, 200); mutate('saved a feed key'); } } });
