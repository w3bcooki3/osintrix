/* ==========================================================================
   Context without a backend — offline enrichment, watchlist, "around this event".
   ========================================================================== */
/* ---------- offline enrichment ---------- */
let ENR = null, ENR_LOADING = null;
async function enrLoad(){
  if(ENR) return ENR; if(ENR_LOADING) return ENR_LOADING;
  ENR_LOADING = (async () => { try{
    const bin = Uint8Array.from(atob(ENRICH_B64), c => c.charCodeAt(0));
    const txt = await new Response(new Blob([bin]).stream().pipeThrough(new DecompressionStream('gzip'))).text(), d = JSON.parse(txt);
    const prov = []; for(const [name, flat] of Object.entries(d.providers)){ let p = 0; for(let i = 0; i < flat.length; i += 2){ const a = p + flat[i], b = a + flat[i + 1]; prov.push([a, b, name]); p = b; } }
    prov.sort((x, y) => x[0] - y[0]); let t = 0; const tor = new Set(d.tor.map(x => (t += x)));
    ENR = {date:d.date, prov, tor, disp:new Set(d.disposable)}; }catch(e){ ENR = {date:'', prov:[], tor:new Set(), disp:new Set(), failed:true}; } return ENR; })();
  return ENR_LOADING;
}
const ipNum = v => v.split('.').reduce((a, o) => a * 256 + +o, 0);
function provOf(v){ if(!ENR || !/^\d+\.\d+\.\d+\.\d+$/.test(v)) return null; const n = ipNum(v); let lo = 0, hi = ENR.prov.length - 1;
  while(lo <= hi){ const m = (lo + hi) >> 1, r = ENR.prov[m]; if(n < r[0]) hi = m - 1; else if(n > r[1]) lo = m + 1; else return r[2]; } return null; }
const FREE_MAIL = new Set('gmail.com googlemail.com outlook.com hotmail.com live.com msn.com yahoo.com ymail.com aol.com icloud.com me.com mac.com proton.me protonmail.com pm.me tutanota.com tuta.io gmx.com gmx.net gmx.de web.de mail.com yandex.ru yandex.com mail.ru inbox.ru bk.ru list.ru rambler.ru zoho.com qq.com 163.com 126.com sina.com naver.com daum.net hanmail.net rediffmail.com libero.it orange.fr free.fr laposte.net t-online.de seznam.cz wp.pl o2.pl interia.pl fastmail.com hushmail.com cock.li disroot.org riseup.net skiff.com'.split(' '));
const DDNS = /(^|\.)(duckdns\.org|no-ip\.(org|com|biz|info)|ddns\.net|hopto\.org|zapto\.org|sytes\.net|servebeer\.com|serveftp\.com|myftp\.(org|biz)|dynu\.(com|net)|dyndns\.(org|info)|freedns\.afraid\.org|mooo\.com|chickenkiller\.com|ngrok(-free)?\.(io|app|dev)|trycloudflare\.com|serveo\.net|loca\.lt|localtunnel\.me|portmap\.(io|host)|pagekite\.me|ddnsking\.com|3utilities\.com|bounceme\.net|ddnsfree\.com|gotdns\.ch)$/i;
const SHORT = /^(bit\.ly|tinyurl\.com|t\.co|is\.gd|v\.gd|cutt\.ly|rebrand\.ly|goo\.gl|ow\.ly|shorturl\.at|rb\.gy|tiny\.cc|buff\.ly|s\.id|t\.ly|lnkd\.in|urlz\.fr|qrco\.de|bl\.ink|shorte\.st|adf\.ly)$/i;
const FILESHARE = /(^|\.)(pastebin\.com|paste\.ee|ghostbin\.\w+|hastebin\.com|rentry\.co|controlc\.com|transfer\.sh|anonfiles\.com|file\.io|mega\.nz|gofile\.io|catbox\.moe|litter\.catbox\.moe|cdn\.discordapp\.com|media\.discordapp\.net|raw\.githubusercontent\.com|gist\.githubusercontent\.com|dropbox\.com|dl\.dropboxusercontent\.com|drive\.google\.com|docs\.google\.com|onedrive\.live\.com|1drv\.ms|sendspace\.com|mediafire\.com|wetransfer\.com|we\.tl|temp\.sh|bashupload\.com|0x0\.st|pixeldrain\.com|files\.catbox\.moe)$/i;
const FREEHOST = /(^|\.)(000webhostapp\.com|netlify\.app|vercel\.app|github\.io|pages\.dev|workers\.dev|firebaseapp\.com|web\.app|glitch\.me|repl\.co|replit\.dev|herokuapp\.com|weebly\.com|wixsite\.com|blogspot\.com|webflow\.io|azurewebsites\.net|onrender\.com|fly\.dev|surge\.sh|ipfs\.io|dweb\.link|framer\.website|square\.site|godaddysites\.com|sites\.google\.com|r2\.dev|appspot\.com)$/i;
const CC = {'1':'US / Canada','7':'Russia / Kazakhstan','20':'Egypt','27':'South Africa','30':'Greece','31':'Netherlands','32':'Belgium','33':'France','34':'Spain','36':'Hungary','39':'Italy','40':'Romania','41':'Switzerland','43':'Austria','44':'United Kingdom','45':'Denmark','46':'Sweden','47':'Norway','48':'Poland','49':'Germany','51':'Peru','52':'Mexico','53':'Cuba','54':'Argentina','55':'Brazil','56':'Chile','57':'Colombia','58':'Venezuela','60':'Malaysia','61':'Australia','62':'Indonesia','63':'Philippines','64':'New Zealand','65':'Singapore','66':'Thailand','81':'Japan','82':'South Korea','84':'Vietnam','86':'China','90':'Türkiye','91':'India','92':'Pakistan','93':'Afghanistan','94':'Sri Lanka','95':'Myanmar','98':'Iran','212':'Morocco','213':'Algeria','216':'Tunisia','218':'Libya','234':'Nigeria','233':'Ghana','254':'Kenya','255':'Tanzania','256':'Uganda','251':'Ethiopia','351':'Portugal','352':'Luxembourg','353':'Ireland','354':'Iceland','355':'Albania','358':'Finland','359':'Bulgaria','370':'Lithuania','371':'Latvia','372':'Estonia','373':'Moldova','374':'Armenia','375':'Belarus','380':'Ukraine','381':'Serbia','385':'Croatia','420':'Czechia','421':'Slovakia','852':'Hong Kong','853':'Macau','855':'Cambodia','856':'Laos','880':'Bangladesh','886':'Taiwan','960':'Maldives','961':'Lebanon','962':'Jordan','963':'Syria','964':'Iraq','965':'Kuwait','966':'Saudi Arabia','967':'Yemen','968':'Oman','970':'Palestine','971':'UAE','972':'Israel','973':'Bahrain','974':'Qatar','975':'Bhutan','976':'Mongolia','977':'Nepal','992':'Tajikistan','993':'Turkmenistan','994':'Azerbaijan','995':'Georgia','996':'Kyrgyzstan','998':'Uzbekistan'};
const phoneCountry = v => { if(!/^\+/.test(v)) return null; const d = v.slice(1); for(const n of [3, 2, 1]) if(CC[d.slice(0, n)]) return CC[d.slice(0, n)] + ' (+' + d.slice(0, n) + ')'; return null; };
/* tags: [label, tone] where tone is red | amber | blue | '' */
function ctxOf(k, v){
  const out = [], host = k === 'url' ? ((v.match(/^https?:\/\/(?:[^/@\s]*@)?([^/:?#\s]+)/i) || [])[1] || '').toLowerCase() : k === 'email' ? v.split('@')[1] : k === 'domain' ? v : '';
  if(k === 'ipv4' || k === 'ipv6'){ const c = E.ipClass(v); if(!/^Public/.test(c)){ out.push([c, '']); return out; }
    if(ENR){ const p = provOf(v); if(p) out.push([p, 'blue']); if(ENR.tor.has(ipNum(v))) out.push(['Tor exit node', 'red']); } }
  if(k === 'hostport'){ const h = v.slice(0, v.lastIndexOf(':')); if(ENR){ const p = provOf(h); if(p) out.push([p, 'blue']); if(ENR.tor.has(ipNum(h))) out.push(['Tor exit node', 'red']); } }
  if(host){ if(/\.onion$/.test(host)) out.push(['Tor onion service', 'red']); if(DDNS.test(host)) out.push(['Dynamic DNS / tunnel', 'red']); if(SHORT.test(host)) out.push(['URL shortener', 'amber']);
    if(FILESHARE.test(host)) out.push(['Paste / file sharing', 'amber']); if(FREEHOST.test(host)) out.push(['Free hosting — often abused', 'amber']); }
  if(k === 'email'){ const d = v.split('@')[1]; if(ENR && ENR.disp.has(d)) out.push(['Disposable email', 'red']); else if(FREE_MAIL.has(d)) out.push(['Free email provider', '']);
    if(/^(noreply|no-reply|admin|support|billing|security|it|helpdesk|info)@/i.test(v)) out.push(['Role address', '']); }
  if(k === 'phone'){ const c = phoneCountry(v); if(c) out.push([c, '']); }
  if(k === 'btc') out.push([/^bc1q/.test(v) ? 'SegWit (bech32)' : /^bc1p/.test(v) ? 'Taproot' : /^3/.test(v) ? 'P2SH / multisig' : 'Legacy P2PKH', '']);
  if(k === 'xmr') out.push(['Monero — untraceable by design', 'amber']);
  if(k === 'mac' && typeof macVendor === 'function'){ const r = MAC_CACHE.get(v); if(r) out.push([r, '']); else if(r === undefined){ MAC_CACHE.set(v, null); Promise.resolve(macVendor(v)).then(x => { const name = x && (x.vendor || (x.random ? 'Randomised / private MAC' : '')); if(name){ MAC_CACHE.set(v, name); renderInsp(); } }).catch(() => {}); } }
  if(k === 'coords'){ const [la, lo] = v.split(',').map(Number); out.push([(la >= 0 ? 'N' : 'S') + ' · ' + (lo >= 0 ? 'E' : 'W') + ' hemisphere', '']); }
  if(!ENR && /^(ipv4|ipv6|email|hostport)$/.test(k)) enrLoad().then(() => { if(UI.route.area === 'case' || UI.route.area === 'entities') renderMain(); renderInsp(); if($('capFound')) capPreview(); });
  return out;
}
const MAC_CACHE = new Map();
const ctxChips = (k, v) => ctxOf(k, v).map(([t, tone]) => `<span class="cxt${tone ? ' ' + tone : ''}">${esc(t)}</span>`).join('');

/* ---------- watchlist ---------- */
const isWatched = k => !!(DB.watch && DB.watch[k]);
function toggleWatch(k){ DB.watch = DB.watch || {}; if(DB.watch[k]) delete DB.watch[k]; else DB.watch[k] = {at:Date.now()}; mutate((DB.watch[k] ? 'watching ' : 'stopped watching ') + entSplit(k).v); renderAll(); toast(DB.watch[k] ? 'On your watchlist — you will be told when it shows up again' : 'Removed from watchlist'); }
function watchHits(){
  const W = DB.watch || {}, keys = Object.keys(W); if(!keys.length) return [];
  const out = [];
  for(const r of DB.records) for(const e of r.ents){ const k = entKey(e); if(W[k] && r.addedAt > W[k].at) out.push({k, r}); }
  const fe = DB.feed.flatMap(f => E.extract(f.title + ' ' + f.body).map(entKey).filter(k => W[k]).map(k => ({k, f})));
  return out.sort((a, b) => b.r.addedAt - a.r.addedAt).concat(fe);
}
function watchNotify(recs){ const W = DB.watch || {}; const hit = [...new Set(recs.flatMap(r => r.ents.map(entKey)).filter(k => W[k]))];
  if(hit.length) setTimeout(() => toast(`Watchlist: ${hit.slice(0, 2).map(k => entSplit(k).v).join(', ')}${hit.length > 2 ? ' +' + (hit.length - 2) : ''} seen again`), 900); }
function watchCard(){
  const W = DB.watch || {}, n = Object.keys(W).length, H = watchHits();
  return `<section class="card"><header><h3>${ico('eye','sm')} Watchlist</h3><span class="t3">${n} watched</span><a class="btn sm ghost" href="#/watch" style="margin-left:auto">Open ${ico('chevron-right','sm')}</a></header><div class="body flush">
    ${H.length ? H.slice(0, 6).map(h => h.r ? `<button class="li" data-act="selRec" data-id="${h.r.id}"><span class="tb sm" style="--c:var(--amber)">${ico('eye')}</span><div class="main2"><b style="font-weight:540">${esc(entSplit(h.k).v)}</b><small>${esc((theCase(h.r.caseId) || {}).code || '')} · ${esc(h.r.title.slice(0, 70))} · ${esc(E.fmtAgo(Date.now() - h.r.addedAt))} ago</small></div></button>`
      : `<button class="li" data-act="selFeed" data-id="${h.f.id}"><span class="tb sm" style="--c:var(--red)">${ico('rss')}</span><div class="main2"><b style="font-weight:540">${esc(entSplit(h.k).v)}</b><small>In the news · ${esc(h.f.title.slice(0, 70))}</small></div></button>`).join('')
      : `<p class="t3" style="padding:14px 18px;margin:0;font-size:13.5px">${n ? 'No new sightings. You will see them here, and get a notice, when a watched entity turns up in new evidence or the news.' : 'Watch an IP, domain, handle or wallet from its details panel, and new sightings show up here.'}</p>`}</div></section>`;
}
function viewWatch(){
  const W = DB.watch || {}, g = globalEnts(), H = watchHits(), keys = Object.keys(W).sort((a, b) => W[b].at - W[a].at);
  return `<div class="scroll"><div class="page">${pageHead('eye','var(--amber)','Watchlist','Entities you are tracking. Any new evidence, log import or news item that mentions one is flagged — across every case.', '')}
    ${keys.length ? `<section class="card" style="overflow:hidden"><table class="tbl cardify"><thead><tr><th>Entity</th><th>Verdict</th><th class="n">New sightings</th><th class="hide-m">Cases</th><th class="hide-m">Watching since</th><th></th></tr></thead><tbody>
      ${keys.map(k => { const {k:kind, v} = entSplit(k), ge = g.get(k), n = H.filter(h => h.k === k).length;
        return `<tr data-act="selEnt" data-id="${esc(k)}"><td><div class="ce-e">${kindBadge(kind,'sm')}<div style="min-width:0"><div class="v mono">${esc(v)}</div><div class="t3" style="font-size:12.5px">${esc(E.LABEL[kind] || kind)} ${ctxChips(kind, v)}</div></div></div></td>
          <td>${vdLabel(verdictOf(k)) || '<span class="t3">—</span>'}</td><td class="n">${n ? `<span class="chip amber sq">${n}</span>` : '0'}</td>
          <td class="hide-m">${ge ? [...ge.cases].filter(theCase).map(cid => { const o = theCase(cid); return `<a class="ce-case" href="${caseHash(cid, 'entities')}" style="--cc:${esc(o.color)}">${esc(o.code)}</a>`; }).join(' ') : '<span class="t3">—</span>'}</td>
          <td class="hide-m t3">${esc(E.fmtDate(W[k].at, tz()))}</td><td><button class="iconbtn" data-act="watch" data-id="${esc(k)}" aria-label="Stop watching" title="Stop watching">${ico('x','sm')}</button></td></tr>`; }).join('')}</tbody></table></section>
      <h2 class="hh" style="margin-top:26px">New sightings</h2>
      <section class="card"><div class="body flush">${H.length ? H.slice(0, 50).map(h => h.r ? `<button class="li" data-act="selRec" data-id="${h.r.id}"><span class="mono t3" style="width:120px;font-size:12.5px">${esc(E.fmtFull(h.r.addedAt, tz()).slice(0, 16))}</span><div class="main2"><b style="font-weight:540">${esc(entSplit(h.k).v)}</b><small>${esc((theCase(h.r.caseId) || {}).code || '')} · ${esc(h.r.title.slice(0, 90))}</small></div></button>`
        : `<button class="li" data-act="selFeed" data-id="${h.f.id}"><span class="mono t3" style="width:120px;font-size:12.5px">news</span><div class="main2"><b style="font-weight:540">${esc(entSplit(h.k).v)}</b><small>${esc(h.f.title)}</small></div></button>`).join('') : '<p class="t3" style="padding:14px 18px;margin:0">Nothing new yet.</p>'}</div></section>`
    : empty('eye', 'Nothing on your watchlist', 'Open any IP, domain, email, handle or wallet and choose <b>Watch</b>. From then on, every capture, log import and news item is checked for it.')}
  </div></div>`;
}

/* ---------- around this event ---------- */
function aroundHTML(r){
  if(!r.ts) return ''; const W = 5 * 60000, near = derive(r.caseId).recs.filter(x => x.id !== r.id && x.ts && Math.abs(x.ts - r.ts) <= W).sort((a, b) => Math.abs(a.ts - r.ts) - Math.abs(b.ts - r.ts));
  if(!near.length) return `<div class="isec"><h4>Around this time <span class="t3">±5 min</span></h4><p class="t3" style="margin:0;font-size:13.5px">Nothing else happened within five minutes.</p></div>`;
  const sgn = d => (d < 0 ? '−' : '+') + E.fmtGap(Math.abs(d));
  return `<div class="isec"><h4>Around this time <span class="t3">${near.length} within ±5 min</span></h4>
    ${near.slice(0, 8).sort((a, b) => a.ts - b.ts).map(x => `<button class="li around" data-act="selRec" data-id="${x.id}"><span class="mono ${x.ts < r.ts ? 't3' : ''}" style="width:64px;font-size:12px">${sgn(x.ts - r.ts)}</span><div class="main2"><b style="font-weight:520;font-size:13.5px">${esc(x.title)}</b><small>${esc([x.host, x.source].filter(Boolean).join(' · '))}${x.host && r.host && x.host !== r.host ? ' · <span style="color:var(--amber)">other host</span>' : ''}</small></div></button>`).join('')}
    <button class="btn sm" data-act="tlWin" data-id="${r.id}" style="margin-top:8px">${ico('clock','sm')}Show this window on the timeline</button></div>`;
}
function winPass(r){ const w = UI.facet.win; return !w || (r.ts && r.ts >= w.from && r.ts <= w.to); }
const WATCH_ACTS = {
  watch:id => toggleWatch(id),
  tlWin:id => { const r = recById(id); if(!r || !r.ts) return; UI.facet.win = {from:r.ts - 5 * 60000, to:r.ts + 5 * 60000, at:r.ts}; UI.tlMode = 'events'; go(caseHash(r.caseId, 'timeline')); renderMain(); },
  winOff:() => { delete UI.facet.win; renderMain(); }
};
