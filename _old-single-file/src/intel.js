/* ==========================================================================
   Threat Intel — live RSS through the same relay the original app used
   (api.rss2json.com). OFF by default: turning it on sends each feed's URL to
   that relay, nothing else. Everything that comes back is treated as
   untrusted text: HTML is stripped, links must be http(s), all output escaped.
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
}
let intelBusy = false;
async function refreshFeeds(){
  if(!DB.prefs.liveFeeds){ return intelConsent(); }
  if(intelBusy) return; intelBusy = true; renderMain();
  const srcs = DB.feedSources.filter(s => s.on); let added = 0;
  await Promise.allSettled(srcs.map(async s => {
    const ctl = new AbortController(), to = setTimeout(() => ctl.abort(), 12000);
    try{
      const res = await fetch(RSS2JSON + encodeURIComponent(s.url), {signal:ctl.signal, credentials:'omit', referrerPolicy:'no-referrer', cache:'no-store'});
      if(!res.ok) throw new Error('HTTP ' + res.status);
      const j = await res.json(); if(j.status !== 'ok' || !Array.isArray(j.items)) throw new Error(j.message || 'Relay refused the feed');
      for(const it of j.items.slice(0, 30)){
        const title = plainText(it.title).slice(0, 300), body = plainText(it.description || it.content).slice(0, 1500), link = E.safeUrl(it.link) || '';
        if(!title || DB.feed.some(f => (link && f.link === link) || f.title === title)) continue;
        const k = classify(title + ' ' + body);
        DB.feed.push({id:uid('f'), source:s.name, title, body, link, ts:Date.parse(String(it.pubDate || '').replace(' ', 'T') + (/[zZ+]/.test(it.pubDate || '') ? '' : 'Z')) || Date.now(), cat:k.cat, sev:k.sev, live:true}); added++;
      }
      s.status = 'ok'; s.last = Date.now(); s.err = '';
    }catch(e){ s.status = 'error'; s.err = e.name === 'AbortError' ? 'Timed out' : String(e.message || e).slice(0, 120); }
    finally{ clearTimeout(to); }
  }));
  DB.feed.sort((a, b) => b.ts - a.ts); if(DB.feed.length > 600) DB.feed.length = 600;
  intelBusy = false; DB.prefs.lastFeedRefresh = Date.now(); mutate('refreshed feeds (+' + added + ')'); renderAll();
  const bad = srcs.filter(s => s.status === 'error').length;
  toast(added + ' new article' + (added === 1 ? '' : 's') + (bad ? ' · ' + bad + ' source' + (bad > 1 ? 's' : '') + ' failed' : ''));
}
function intelConsent(){
  openDlg(dhead('Turn on live threat-intel feeds?') + `<div class="in">
    <p class="t2" style="margin:0 0 14px">OSINTrix is offline by default. Live feeds work the same way the original app did: each feed address is sent to <b class="mono" style="color:var(--text)">api.rss2json.com</b>, a third-party relay that fetches the RSS and returns it.</p>
    <div class="grid" style="gap:10px">
      <div class="note"><span class="ic" style="color:var(--green);background:var(--green-soft)">${ico('check','sm')}</span><div><b>What leaves your browser:</b> only the feed URLs in your source list.</div></div>
      <div class="note"><span class="ic" style="color:var(--green);background:var(--green-soft)">${ico('lock','sm')}</span><div><b>What never leaves:</b> your cases, vault entries, notes, detections and searches.</div></div>
      <div class="note amber"><span class="ic">${ico('triangle-alert','sm')}</span><div>The relay can see which feeds you follow and when. Articles are shown as plain text; links open only when you click them.</div></div></div>
    <label style="display:flex;gap:10px;align-items:center;margin-top:16px;font-size:14px"><input type="checkbox" id="intelOk"> I understand, allow requests to api.rss2json.com</label></div>
    <footer><button class="btn" data-act="dclose">Keep offline</button><button class="btn primary" data-act="intelOn" id="intelOnBtn" disabled>${ico('wifi','sm')}Turn on and refresh</button></footer>`, false,
    () => { $('intelOk').onchange = () => { $('intelOnBtn').disabled = !$('intelOk').checked; }; });
}
const CAT_ICON = {ransomware:'lock', vuln:'bug', apt:'crosshair', malware:'skull', breach:'key-round', phish:'mail', general:'newspaper'};
function dayLabel(ts){ const d = new Date(ts), n = new Date(), k = x => x.toISOString().slice(0, 10), y = new Date(n - 864e5);
  return k(d) === k(n) ? 'Today' : k(d) === k(y) ? 'Yesterday' : d.toLocaleDateString(undefined, {weekday:'long', day:'numeric', month:'long'}); }
function viewIntel(){
  ensureIntel();
  const g = globalEnts(), q = (UI.iq || '').toLowerCase(), cat = UI.icat || 'all', only = UI.imatch;
  const all = DB.feed.map(f => { const ex = E.extract(f.title + ' ' + f.body); return {f, hits:[...new Set(ex.map(entKey).filter(id => g.has(id)))], iocs:ex.length}; });
  let list = all.filter(x => (cat === 'all' || x.f.cat === cat) && (!only || x.hits.length) && (!UI.isrc || x.f.source === UI.isrc) && (!q || (x.f.title + ' ' + x.f.body + ' ' + x.f.source).toLowerCase().includes(q)));
  list.sort((a, b) => b.f.ts - a.f.ts);
  const live = !!DB.prefs.liveFeeds, last = DB.prefs.lastFeedRefresh, now = Date.now(), ago = ts => E.fmtAgo(Math.max(0, now - ts));
  const exposed = all.filter(x => x.hits.length), crit = all.filter(x => x.f.sev === 'critical').length;
  /* featured: the story that matters most to you right now */
  const score = x => x.hits.length * 5 + (x.f.sev === 'critical' ? 4 : x.f.sev === 'high' ? 2 : 0) - (now - x.f.ts) / 864e5;
  const filtered = cat !== 'all' || only || UI.isrc || q;
  const feat = !filtered && list.length > 3 ? list.slice().sort((a, b) => score(b) - score(a))[0] : null;
  const rows = feat ? list.filter(x => x !== feat) : list;
  const sevTag = f => f.sev === 'critical' ? `<span class="iv-sev c">${ico('flame','sm')}Critical</span>` : f.sev === 'high' ? '<span class="iv-sev h">High</span>' : '';
  const catTag = f => { const m = catMeta(f.cat); return `<span class="iv-cat" style="--c:${m.col}">${esc(m.name)}</span>`; };
  const acts = (f, big) => { const u = E.safeUrl(f.link); return `<div class="iv-act">${u ? `<a class="${big ? 'btn' : 'iconbtn'}" href="${esc(u)}" target="_blank" rel="noopener noreferrer" title="Read on ${esc(hostOf(u))}" aria-label="Read original">${ico('external-link','sm')}${big ? 'Read original' : ''}</a>` : ''}
    <button class="${big ? 'btn primary' : 'iconbtn'}" data-act="feedToCase" data-id="${f.id}" title="Add to ${esc(theCase().code)}" aria-label="Add to case">${ico('plus','sm')}${big ? 'Add to ' + esc(theCase().code) : ''}</button></div>`; };
  const hitsHTML = hits => hits.length ? `<div class="iv-hits"><span>${ico('crosshair','sm')}In your cases</span>${hits.slice(0, 4).map(id => entPill(id)).join('')}${hits.length > 4 ? `<span class="t3">+${hits.length - 4}</span>` : ''}</div>` : '';
  let lastDay = '';
  const rowHTML = ({f, hits, iocs}) => { const m = catMeta(f.cat), d = dayLabel(f.ts), head = d !== lastDay ? `<h3 class="iv-day">${esc(d)}</h3>` : ''; lastDay = d;
    return head + `<article class="iv-row${hits.length ? ' hit' : ''}" aria-selected="${!!(UI.sel && UI.sel.id === f.id)}">
      <span class="iv-tile" style="--c:${m.col}" aria-hidden="true">${ico(CAT_ICON[f.cat] || 'newspaper')}</span>
      <button class="iv-body" data-act="selFeed" data-id="${f.id}">
        <span class="iv-meta"><b>${esc(f.source)}</b><i></i>${esc(ago(f.ts))}${catTag(f)}${sevTag(f)}${f.live ? '' : '<span class="iv-sample">Sample</span>'}</span>
        <span class="iv-t">${esc(f.title)}</span>
        <span class="iv-p">${esc(f.body.slice(0, 240))}</span>
        ${iocs ? `<span class="iv-ioc">${ico('fingerprint','sm')}${iocs} indicator${iocs > 1 ? 's' : ''}</span>` : ''}</button>
      ${acts(f)}${hitsHTML(hits)}</article>`; };
  const counts = Object.fromEntries(INTEL_CATS.map(c => [c[0], DB.feed.filter(f => f.cat === c[0]).length])), mx = Math.max(1, ...Object.values(counts));
  const topEnts = countBy(exposed, x => x.hits).slice(0, 6);
  const srcCount = Object.fromEntries(countBy(DB.feed, f => f.source));
  return `<div class="scroll"><div class="page wide">
    ${pageHead('rss','#e5484d','Threat Intel','Security news and advisories from your sources — classified, and checked against every entity in your cases.',
      `<span class="iv-live${live ? ' on' : ''}"><i></i>${live ? 'Live' + (last ? ' · ' + esc(ago(last)) : '') : 'Offline'}</span>
       <button class="btn" data-act="feedSources">${ico('settings','sm')}Sources</button><button class="btn" data-act="feedImport">${ico('upload','sm')}Import</button>
       <button class="btn primary" data-act="feedRefresh" ${intelBusy ? 'disabled' : ''}>${ico('refresh-cw', intelBusy ? 'sm spin' : 'sm')}${intelBusy ? 'Refreshing…' : live ? 'Refresh' : 'Go live'}</button>`,
      [[DB.feed.length,'articles'],[exposed.length,'mention your cases', exposed.length ? '<em class="r"></em>' : ''],[crit,'critical'],[DB.feedSources.filter(s => s.on).length,'sources']])}
    <div class="iv">
      <div class="iv-main">
        <div class="iv-tabs" role="tablist">${[['all','All',DB.feed.length], ...INTEL_CATS.map(c => [c[0], c[1], counts[c[0]]])].filter(t => t[0] === 'all' || t[2]).map(([id, l, n]) => `<button role="tab" data-act="icat" data-v="${id}" aria-selected="${cat === id}">${id !== 'all' ? ico(CAT_ICON[id],'sm') : ''}${esc(l)}<span>${n}</span></button>`).join('')}</div>
        <div class="toolbar iv-tb"><div class="search-in">${ico('search')}<label class="sr" for="iq">Search articles</label><input id="iq" class="inp" placeholder="Search titles, summaries, sources…" value="${esc(UI.iq || '')}"></div>
          <button class="chip${only ? ' accent' : ''}" data-act="imatch" aria-pressed="${!!only}">${ico('crosshair','sm')}Mentions my cases</button>
          <label class="sr" for="isrc">Source</label><select id="isrc" class="gsel bord"><option value="">All sources</option>${Object.keys(srcCount).map(s => `<option${UI.isrc === s ? ' selected' : ''}>${esc(s)}</option>`).join('')}</select></div>
        ${feat ? (() => { const {f, hits, iocs} = feat, m = catMeta(f.cat); return `<article class="iv-feat" style="--c:${m.col}">
          <div class="iv-feat-art" aria-hidden="true">${ico(CAT_ICON[f.cat] || 'newspaper')}</div>
          <div class="iv-feat-b"><span class="iv-kicker">${ico(hits.length ? 'crosshair' : 'trending-up','sm')}${hits.length ? 'Top story for your cases' : 'Top story'}</span>
            <button class="iv-feat-t" data-act="selFeed" data-id="${f.id}">${esc(f.title)}</button>
            <span class="iv-meta"><b>${esc(f.source)}</b><i></i>${esc(ago(f.ts))}${catTag(f)}${sevTag(f)}${iocs ? `<i></i>${iocs} indicators` : ''}${f.live ? '' : '<span class="iv-sample">Sample</span>'}</span>
            <p>${esc(f.body.slice(0, 360))}${f.body.length > 360 ? '…' : ''}</p>${hitsHTML(hits)}${acts(f, true)}</div></article>`; })() : ''}
        ${rows.length ? `<div class="iv-list card">${rows.slice(0, 120).map(rowHTML).join('')}</div>`
          : feat ? '' : empty('search','No articles here', live ? 'Nothing matches these filters.' : 'Turn on live feeds to pull the latest from your sources, or import a saved RSS/Atom file.', live ? '' : `<button class="btn primary" data-act="feedRefresh">${ico('wifi','sm')}Go live</button>`)}
      </div>
      <aside class="iv-rail">
        <section class="card iv-box"><h4>${ico('crosshair','sm')}Your exposure</h4>
          ${exposed.length ? `<p class="t2">${exposed.length} article${exposed.length > 1 ? 's' : ''} mention${exposed.length > 1 ? '' : 's'} entities from your cases.</p><div class="iv-ents">${topEnts.map(([id, n]) => entPill(id, {n})).join('')}</div>
            <button class="btn sm" data-act="imatch" style="width:100%;justify-content:center">${only ? 'Show all articles' : 'Show only these'}</button>` : '<p class="t3">No article mentions an entity from your cases. Good news — for now.</p>'}</section>
        <section class="card iv-box"><h4>${ico('activity','sm')}By category</h4>
          ${INTEL_CATS.filter(c => counts[c[0]]).map(([id, l, col]) => `<button class="iv-bar" data-act="icat" data-v="${cat === id ? 'all' : id}" aria-pressed="${cat === id}" style="--c:${col}"><span>${esc(l)}</span><b>${counts[id]}</b><i><u style="width:${Math.round(counts[id] / mx * 100)}%"></u></i></button>`).join('') || '<p class="t3">Nothing classified yet.</p>'}</section>
        <section class="card iv-box"><h4>${ico('radio','sm')}Sources <button class="btn xs ghost" data-act="feedSources" style="margin-left:auto">Manage</button></h4>
          ${DB.feedSources.map(s => `<div class="iv-src"><i class="${!s.on ? 'off' : s.status === 'error' ? 'bad' : s.status === 'ok' ? 'ok' : ''}"></i><span>${esc(s.name)}</span><b>${srcCount[s.name] || 0}</b></div>`).join('')}
          <p class="t3 iv-fine">${live ? 'Fetched through api.rss2json.com. Only feed addresses leave the browser.' : 'Offline — nothing is fetched until you go live.'}</p></section>
      </aside>
    </div></div></div>`;
}
function sourcesDlg(){
  ensureIntel();
  const row = s => `<div class="srow"><label class="sw"><input type="checkbox" data-act="srcToggle" data-id="${s.id}" ${s.on ? 'checked' : ''}><span></span></label>
    <div class="tn"><b>${esc(s.name)}</b><span class="mono">${esc(s.url)}</span>${s.status === 'error' ? `<span style="color:var(--red)">${esc(s.err || 'Failed')}</span>` : s.last ? `<span style="color:var(--green)">OK · ${esc(E.fmtAgo(Date.now() - s.last))}</span>` : ''}</div>
    <button class="iconbtn" data-act="srcDel" data-id="${s.id}" aria-label="Remove ${esc(s.name)}">${ico('trash-2','sm')}</button></div>`;
  openDlg(dhead('Feed sources') + `<div class="in"><div class="srcs">${DB.feedSources.map(row).join('')}</div>
    <form data-form="src" class="frow" style="margin-top:16px;align-items:end"><div class="field" style="margin:0"><label for="srcName">Name</label><input id="srcName" required placeholder="CISA advisories"></div>
      <div class="field" style="margin:0"><label for="srcUrl">RSS / Atom URL</label><input id="srcUrl" type="url" required pattern="https?://.+" placeholder="https://…/feed.xml"></div>
      <button class="btn" type="submit" style="grid-column:1/-1;justify-self:start">${ico('plus','sm')}Add source</button></form></div>
    <footer><button class="btn ghost" data-act="srcReset" style="margin-right:auto">Restore defaults</button>${DB.prefs.liveFeeds ? `<button class="btn" data-act="intelOff">${ico('wifi-off','sm')}Go offline</button>` : ''}<button class="btn primary" data-act="dclose">Done</button></footer>`);
}
