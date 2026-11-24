/* Web captures in the File inspector: a HAR (what the browser's developer tools save for a page visit), a WARC or WARC.GZ
   (web archive: Webrecorder, Browsertrix, wget --warc-file, Heritrix), a WACZ (the zipped web archive ArchiveWeb.page
   and Browsertrix make) and an MHTML (Chrome / Edge "Save page as… single file"). All four become one list of requests
   and answers, read the same way: the redirect chain the visit went through, where what was typed into the page was sent
   (masked where it is a password or a token), files the page handed out, every site it contacted (first or third party,
   analytics, captcha, IP lookups used to hide from researchers, Telegram or Discord drops), the cookies it set, the server
   software, and the page's own fingerprint (Shodan page and favicon hashes, analytics and ad IDs) with the pivots to run. */
const WC_MAXBODY = 8e6, WC_MAXTOTAL = 120e6, WC_MAXREQ = 20000;
const WC_SVC = [
  [/(^|\.)api\.telegram\.org$/, 'drop', 'Telegram bot API'], [/(^|\.)(discord(app)?\.com)$/, 'drop?', 'Discord'], [/(^|\.)script\.google(usercontent)?\.com$/, 'drop?', 'Google Apps Script'],
  [/(^|\.)(formspree\.io|getform\.io|formsubmit\.co|web3forms\.com|api\.emailjs\.com|formcarry\.com|basin\.usebasin\.com|submit-form\.com|pipedream\.net|webhook\.site|requestbin\.(com|net)|ngrok(-free)?\.(io|app|dev)|hooks\.slack\.com)$/, 'drop', 'form or webhook relay'],
  [/(^|\.)(ip-api\.com|ipinfo\.io|ipapi\.co|ipapi\.com|api\.ipify\.org|ipwho\.is|ipwhois\.app|freegeoip\.app|geoplugin\.net|extreme-ip-lookup\.com|db-ip\.com|ipdata\.co|ipgeolocation\.io|api\.db-ip\.com|ip\.sb|checkip\.amazonaws\.com|myexternalip\.com)$/, 'geo', 'IP / location lookup'],
  [/(^|\.)(google-analytics\.com|googletagmanager\.com|analytics\.google\.com|doubleclick\.net|googleadservices\.com|googlesyndication\.com|connect\.facebook\.net|facebook\.com|hotjar\.com|mc\.yandex\.(ru|com)|clarity\.ms|segment\.(io|com)|mixpanel\.com|tiktok\.com|analytics\.tiktok\.com|bat\.bing\.com|matomo\.cloud|plausible\.io|stats\.wp\.com)$/, 'track', 'analytics / ads'],
  [/(^|\.)(hcaptcha\.com|recaptcha\.net|challenges\.cloudflare\.com|google\.com)$/, 'captcha?', 'captcha'],
  [/(^|\.)(cdnjs\.cloudflare\.com|cdn\.jsdelivr\.net|unpkg\.com|code\.jquery\.com|ajax\.googleapis\.com|fonts\.googleapis\.com|fonts\.gstatic\.com|gstatic\.com|stackpath\.bootstrapcdn\.com|maxcdn\.bootstrapcdn\.com|cdn\.tailwindcss\.com|use\.fontawesome\.com|kit\.fontawesome\.com|cloudflare\.com|cdn\.cloudflare\.net|akamaihd\.net|cloudfront\.net)$/, 'cdn', 'library / CDN'],
  [/(^|\.)(firebaseio\.com|firebasestorage\.googleapis\.com|firestore\.googleapis\.com|supabase\.co|herokuapp\.com|workers\.dev|pages\.dev|vercel\.app|netlify\.app|glitch\.me|repl\.co|000webhostapp\.com|weebly\.com|wixsite\.com|github\.io|blogspot\.com|r2\.dev|web\.app|firebaseapp\.com)$/, 'host', 'free hosting / backend'],
];
const WC_SECRET = /pass|pwd|passwd|secret|otp|pin\b|^pin|cvv|cvc|card.?num|ccnum|cc_?number|^cc$|security.?code|token|ssn|2fa|mfa|code$/i;
const WC_USER = /user|login|email|mail|account|phone|^id$|^u$|^e$/i;
const wcHost = u => { try{ return new URL(u).hostname.toLowerCase(); }catch(e){ return ''; } };
const wcHdr = (H, n) => { n = n.toLowerCase(); const x = (H || []).find(h => h[0].toLowerCase() === n); return x ? x[1] : ''; };
const wcHdrs = (H, n) => { n = n.toLowerCase(); return (H || []).filter(h => h[0].toLowerCase() === n).map(h => h[1]); };
const wcSvc = h => { for(const [re, k, l] of WC_SVC) if(re.test(h)) return {k, l}; return null; };
const wcMask = v => { v = String(v); return v.length <= 2 ? '••' : v[0] + '•'.repeat(Math.min(10, v.length - 2)) + v[v.length - 1] + ` (${v.length} characters)`; };
const wcMaskTg = s => String(s).replace(/(bot)?(\d{6,12}):([A-Za-z0-9_-]{30,40})/g, (m, b, id, sec) => (b || '') + id + ':' + sec.slice(0, 3) + '•••• (token hidden)');
const wcMaskHook = s => String(s).replace(/(discord(?:app)?\.com\/api\/webhooks\/\d+\/)([\w-]{20,})/gi, (m, a, t) => a + t.slice(0, 3) + '•••• (token hidden)');
const wcDec = b => { try{ return new TextDecoder('utf-8', {fatal:false}).decode(b); }catch(e){ return ''; } };
const wcIsText = m => /html|text|json|javascript|xml|css|svg|x-www-form/i.test(m || '');
const wcB64 = s => { try{ const bin = atob(String(s).replace(/\s+/g, '')), u = new Uint8Array(bin.length); for(let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return u; }catch(e){ return null; } };

/* ---------- readers: each gives {fmt, tool, browser, entries:[{url, method, status, mime, size, t, ip, reqH, resH, post, body, enc}]} ---------- */
function wcHar(text){
  let J; try{ J = JSON.parse(text); }catch(e){ return null; } const L = J && J.log; if(!L || !Array.isArray(L.entries)) return null;
  const out = {fmt:'HAR', tool:L.creator ? [L.creator.name, L.creator.version].filter(Boolean).join(' ') : '', browser:L.browser ? [L.browser.name, L.browser.version].filter(Boolean).join(' ') : '',
    pages:(L.pages || []).map(p => ({id:p.id, title:p.title || '', t:Date.parse(p.startedDateTime)})), entries:[]};
  let total = 0;
  for(const e of L.entries.slice(0, WC_MAXREQ)){ const q = e.request || {}, r = e.response || {}, c = r.content || {}; let body = null;
    if(typeof c.text === 'string' && c.text.length && total < WC_MAXTOTAL){ body = c.encoding === 'base64' ? wcB64(c.text) : new TextEncoder().encode(c.text); if(body && body.length > WC_MAXBODY) body = body.subarray(0, WC_MAXBODY); if(body) total += body.length; }
    const pd = q.postData ? {mime:q.postData.mimeType || '', text:q.postData.text || '', params:(q.postData.params || []).map(p => [p.name, p.value == null ? (p.fileName ? '[file ' + p.fileName + ']' : '') : String(p.value)])} : null;
    out.entries.push({url:q.url || '', method:(q.method || 'GET').toUpperCase(), status:+r.status || 0, mime:(c.mimeType || wcHdr((r.headers || []).map(h => [h.name, h.value]), 'content-type') || '').split(';')[0].trim(),
      size:c.size > 0 ? c.size : (r.bodySize > 0 ? r.bodySize : (body ? body.length : 0)), t:Date.parse(e.startedDateTime), ms:+e.time || 0, ip:(e.serverIPAddress || '').replace(/^\[|\]$/g, ''),
      reqH:(q.headers || []).map(h => [String(h.name), String(h.value)]), resH:(r.headers || []).map(h => [String(h.name), String(h.value)]), post:pd, body, redirect:r.redirectURL || '', page:e.pageref || '',
      type:e._resourceType || ''}); }
  return out;
}
/* an HTTP message as WARC stores it: status or request line, headers, body (de-chunked, and gunzipped when it was sent compressed) */
async function wcHttp(b, isReq){
  let i = 0; for(; i < Math.min(b.length - 3, 65536); i++) if(b[i] === 13 && b[i + 1] === 10 && b[i + 2] === 13 && b[i + 3] === 10) break;
  if(i >= b.length - 3) return null; const head = latin1(b, 0, i).split('\r\n'), first = head.shift() || '', H = head.map(l => { const k = l.indexOf(':'); return k > 0 ? [l.slice(0, k).trim(), l.slice(k + 1).trim()] : null; }).filter(Boolean);
  let body = b.subarray(i + 4); const enc = [];
  if(/chunked/i.test(wcHdr(H, 'transfer-encoding'))){ const parts = []; let o = 0, n = 0; while(o < body.length){ let e = o; while(e < body.length - 1 && !(body[e] === 13 && body[e + 1] === 10)) e++; const len = parseInt(latin1(body, o, e), 16); if(!(len > 0)) break; parts.push(body.subarray(e + 2, e + 2 + len)); n += len; o = e + 2 + len + 2; if(n > WC_MAXBODY) break; }
    const u = new Uint8Array(n); let p = 0; for(const x of parts){ u.set(x.subarray(0, n - p), p); p += x.length; } body = u; }
  const ce = wcHdr(H, 'content-encoding').toLowerCase();
  if(/gzip|deflate/.test(ce) && body.length){ try{ body = await decompressCapped(body, /gzip/.test(ce) ? 'gzip' : 'deflate', WC_MAXBODY); }catch(e){ enc.push(ce); } } else if(ce && ce !== 'identity') enc.push(ce);
  const m = isReq ? /^([A-Z]+)\s+(\S+)/.exec(first) : /^HTTP\/[\d.]+\s+(\d{3})/.exec(first);
  return {first, H, body:body.length > WC_MAXBODY ? body.subarray(0, WC_MAXBODY) : body, method:isReq && m ? m[1] : '', status:!isReq && m ? +m[1] : 0, enc};
}
/* gzip members one after another (how .warc.gz is written): the browser's decoder stops at the first, so split them */
async function wcGunzipMembers(b){
  const starts = []; for(let i = 0; i < b.length - 3 && starts.length < 60000; i++) if(b[i] === 0x1f && b[i + 1] === 0x8b && b[i + 2] === 8 && (i === 0 || (b[i + 3] & 0xe0) === 0)) starts.push(i);
  starts.push(b.length); const out = []; let total = 0, a = 0;
  for(let j = 1; j < starts.length && total < WC_MAXTOTAL; j++){ const seg = b.subarray(starts[a], starts[j]);
    try{ const u = await decompressCapped(seg, 'gzip', WC_MAXTOTAL - total); out.push(u); total += u.length; a = j; }catch(e){ if(j === starts.length - 1) break; } }   // a failure means a false start inside the data: join with the next
  const u = new Uint8Array(total); let p = 0; for(const x of out){ u.set(x, p); p += x.length; } return u;
}
async function wcWarc(b0){
  const b = b0[0] === 0x1f && b0[1] === 0x8b ? await wcGunzipMembers(b0) : b0; if(latin1(b, 0, 5) !== 'WARC/') return null;
  const recs = []; let o = 0;
  while(o < b.length - 10 && recs.length < WC_MAXREQ * 2){
    while(o < b.length && (b[o] === 13 || b[o] === 10)) o++; if(latin1(b, o, o + 5) !== 'WARC/') break;
    let e = o; while(e < b.length - 3 && !(b[e] === 13 && b[e + 1] === 10 && b[e + 2] === 13 && b[e + 3] === 10)) e++;
    const H = latin1(b, o, e).split('\r\n').slice(1).map(l => { const k = l.indexOf(':'); return [l.slice(0, k).trim(), l.slice(k + 1).trim()]; });
    const len = +wcHdr(H, 'content-length') || 0, body = b.subarray(e + 4, e + 4 + len); recs.push({H, body}); o = e + 4 + len; }
  const out = {fmt:'WARC', tool:'', browser:'', pages:[], entries:[]}, reqs = new Map();
  for(const R of recs){ const T = wcHdr(R.H, 'warc-type').toLowerCase();
    if(T === 'warcinfo'){ const s = latin1(R.body, 0, Math.min(R.body.length, 4000)); out.tool = out.tool || ((s.match(/^software:\s*(.+)$/mi) || [])[1] || '').trim(); const ua = (s.match(/^http-header-user-agent:\s*(.+)$/mi) || [])[1]; if(ua) out.ua = ua.trim(); }
    else if(T === 'request'){ const q = await wcHttp(R.body, true); if(q) reqs.set(wcHdr(R.H, 'warc-concurrent-to') || wcHdr(R.H, 'warc-target-uri'), q), reqs.set('u:' + wcHdr(R.H, 'warc-target-uri'), q); } }
  for(const R of recs){ const T = wcHdr(R.H, 'warc-type').toLowerCase(), url = wcHdr(R.H, 'warc-target-uri').replace(/^<|>$/g, ''), t = Date.parse(wcHdr(R.H, 'warc-date')), id = wcHdr(R.H, 'warc-record-id');
    if(T === 'response'){ const r = await wcHttp(R.body, false); if(!r) continue; const q = reqs.get(id) || reqs.get('u:' + wcHdr(R.H, 'warc-target-uri')) || null;
      let post = null; if(q && q.body && q.body.length){ const mime = wcHdr(q.H, 'content-type'); post = {mime, text:wcDec(q.body.subarray(0, 200000)), params:[]}; }
      out.entries.push({url, method:q ? q.method : 'GET', status:r.status, mime:(wcHdr(r.H, 'content-type') || '').split(';')[0].trim(), size:r.body.length, t, ms:0, ip:wcHdr(R.H, 'warc-ip-address'), reqH:q ? q.H : [], resH:r.H, post, body:r.body, enc:r.enc, redirect:wcHdr(r.H, 'location') ? new URL(wcHdr(r.H, 'location'), url).href : '', type:''}); }
    else if(T === 'resource' && url){ const mime = wcHdr(R.H, 'content-type').split(';')[0].trim(); if(/^urn:/.test(url)) continue; out.entries.push({url, method:'GET', status:200, mime, size:R.body.length, t, ms:0, ip:wcHdr(R.H, 'warc-ip-address'), reqH:[], resH:[['Content-Type', mime]], post:null, body:R.body.subarray(0, WC_MAXBODY), redirect:'', type:'resource'}); } }
  return out.entries.length ? out : null;
}
async function wcWacz(b){
  const Z = typeof zipOpen === 'function' && zipOpen(b); if(!Z || !Z.files.some(f => /^archive\/.+\.warc(\.gz)?$/i.test(f.name))) return null;
  let all = null; for(const f of Z.files.filter(x => /^archive\/.+\.warc(\.gz)?$/i.test(x.name)).slice(0, 20)){ const u = await fxZipEntry(b, f.name).catch(() => null); if(!u) continue; const W = await wcWarc(u); if(!W) continue; if(!all) all = W; else { all.entries.push(...W.entries); all.tool = all.tool || W.tool; } }
  if(!all) return null; all.fmt = 'WACZ';
  const pj = await Z.read('pages/pages.jsonl', 4e6).catch(() => null); if(pj) for(const l of pj.split('\n')){ try{ const p = JSON.parse(l); if(p.url) all.pages.push({title:p.title || p.url, url:p.url, t:Date.parse(p.ts)}); }catch(e){} }
  const dp = await Z.read('datapackage.json', 1e6).catch(() => null); if(dp){ try{ const D = JSON.parse(dp); all.tool = all.tool || D.software || ''; all.made = Date.parse(D.created); }catch(e){} }
  return all;
}
/* MHTML: no requests or status codes, but every part the browser saved with its address */
function wcMhtml(text){
  if(!/^(From|Snapshot-Content-Location|Subject|Date|MIME-Version):/mi.test(text.slice(0, 2000)) || !/multipart\/related/i.test(text.slice(0, 4000))) return null;
  const bm = /boundary="?([^"\r\n;]+)"?/i.exec(text.slice(0, 4000)); if(!bm) return null;
  const head = text.slice(0, text.indexOf('--' + bm[1])), hv = n => ((head.match(new RegExp('^' + n + ':\\s*(.+(?:\\r?\\n[ \\t].+)*)', 'mi')) || [])[1] || '').replace(/\r?\n[ \t]+/g, ' ').trim();
  const out = {fmt:'MHTML', tool:/Blink|Chrome/i.test(text.slice(0, 3000)) || /=_NextPart_|----MultipartBoundary--/.test(bm[1]) ? 'Chrome / Edge “Save page as single file”' : '', browser:'', pages:[], entries:[], saved:Date.parse(hv('Date')), title:hv('Subject'), loc:hv('Snapshot-Content-Location')};
  const qp = s => { const bytes = []; s = s.replace(/=\r?\n/g, ''); for(let i = 0; i < s.length; i++){ const c = s[i]; if(c === '=' && /^[0-9A-F]{2}$/i.test(s.substr(i + 1, 2))){ bytes.push(parseInt(s.substr(i + 1, 2), 16)); i += 2; } else { const cc = s.charCodeAt(i); if(cc < 128) bytes.push(cc); else bytes.push(...new TextEncoder().encode(c)); } } return new Uint8Array(bytes); };
  for(const part of text.split('--' + bm[1]).slice(1, 4000)){ const k = part.search(/\r?\n\r?\n/); if(k < 0) continue; const ph = part.slice(0, k), raw = part.slice(k).replace(/^\r?\n\r?\n/, '').replace(/\r?\n$/, '');
    const g = n => ((ph.match(new RegExp('^' + n + ':\\s*(.+)', 'mi')) || [])[1] || '').trim(), url = g('Content-Location'); if(!url) continue;
    const te = g('Content-Transfer-Encoding').toLowerCase(), body = te === 'base64' ? wcB64(raw) : te === 'quoted-printable' ? qp(raw) : new TextEncoder().encode(raw);
    out.entries.push({url, method:'GET', status:200, mime:g('Content-Type').split(';')[0].trim(), size:body ? body.length : 0, t:out.saved, ms:0, ip:'', reqH:[], resH:[], post:null, body, redirect:'', type:''}); }
  return out.entries.length ? out : null;
}
async function wcRead(buf, name){
  const head = latin1(buf, 0, Math.min(buf.length, 400)), ext = (name.split('.').pop() || '').toLowerCase();
  if(/^\s*\{/.test(head) && (ext === 'har' || /"log"\s*:/.test(head))) return buf.length < 300e6 ? wcHar(wcDec(buf)) : null;
  if(head.startsWith('WARC/') || (buf[0] === 0x1f && buf[1] === 0x8b && /warc/i.test(name))) return wcWarc(buf);
  if(buf[0] === 0x50 && buf[1] === 0x4b && /\.wacz$/i.test(name)) return wcWacz(buf);
  if(/\.(mht|mhtml)$/i.test(name) || /^(From|Snapshot-Content-Location|MIME-Version|Subject|Date):/m.test(head) && /multipart\/related/i.test(latin1(buf, 0, Math.min(buf.length, 4000)))) return buf.length < 200e6 ? wcMhtml(latin1(buf, 0, buf.length)) : null;
  return null;
}

/* ---------- reading the capture ---------- */
function wcParams(post, url){
  const out = []; let q; try{ q = new URL(url).searchParams; }catch(e){}
  if(post){ const m = post.mime || '', t = post.text || '';
    if(post.params && post.params.length) out.push(...post.params);
    else if(/x-www-form-urlencoded/i.test(m) || (/^[\w.%\[\]-]+=[^&]*(&[\w.%\[\]-]+=[^&]*)*$/.test(t.trim()) && t.length < 100000)){ for(const [k, v] of new URLSearchParams(t)) out.push([k, v]); }
    else if(/json/i.test(m) || /^\s*[\[{]/.test(t)){ try{ const walk = (o, p) => { if(out.length > 80) return; if(o && typeof o === 'object') for(const [k, v] of Object.entries(o)) walk(v, p ? p + '.' + k : k); else out.push([p || 'value', String(o)]); }; walk(JSON.parse(t), ''); }catch(e){} }
    else if(/multipart/i.test(m)){ for(const m2 of t.matchAll(/name="([^"]+)"(?:;\s*filename="([^"]*)")?\r?\n(?:[^\r\n]+\r?\n)*\r?\n([\s\S]{0,400}?)\r?\n--/g)) out.push([m2[1], m2[2] ? '[file ' + m2[2] + ']' : m2[3]]); }
    else if(t) out.push(['(body)', t.slice(0, 300)]); }
  if(q && (!post || /telegram|webhook|script\.google/i.test(url))) for(const [k, v] of q) out.push([k, v]);
  return out.slice(0, 80).map(([k, v]) => { const secret = WC_SECRET.test(k), tg = /\d{6,12}:[A-Za-z0-9_-]{30,40}/.test(v); return {k, v:secret ? wcMask(v) : tg ? wcMaskTg(v) : String(v).slice(0, 300), secret, user:!secret && WC_USER.test(k)}; });
}
async function wcAnalyse(C){
  const E2 = C.entries.filter(e => /^https?:/i.test(e.url)).sort((a, b) => (a.t || 0) - (b.t || 0)); if(!E2.length) return null;
  const t0 = E2.find(e => isFinite(e.t)) ? E2.find(e => isFinite(e.t)).t : NaN, docs = E2.filter(e => /html/i.test(e.mime) || e.type === 'document' || (e.status >= 300 && e.status < 400));
  // the redirect chain: from the first page asked for, through 3xx answers, refresh headers, meta refresh and script redirects
  const chain = [], byUrl = u => E2.find(e => e.url === u || e.url.replace(/#.*$/, '') === u.replace(/#.*$/, ''));
  let cur = (C.loc && byUrl(C.loc)) || docs[0] || E2[0], via = 'first page asked for';
  for(let n = 0; cur && n < 25; n++){ chain.push({e:cur, via}); let next = '', how = '';
    const loc = cur.redirect || wcHdr(cur.resH, 'location'); if(cur.status >= 300 && cur.status < 400 && loc){ try{ next = new URL(loc, cur.url).href; how = cur.status + ' redirect'; }catch(e){} }
    if(!next){ const rf = wcHdr(cur.resH, 'refresh'); const m = /url\s*=\s*['"]?([^'";]+)/i.exec(rf); if(m){ try{ next = new URL(m[1], cur.url).href; how = 'Refresh header'; }catch(e){} } }
    if(!next && cur.body && /html/i.test(cur.mime)){ const s = wcDec(cur.body.subarray(0, 300000));
      const mm = /<meta[^>]+http-equiv=["']?refresh["']?[^>]+content=["'][^"']*url\s*=\s*['"]?([^"'>\s]+)/i.exec(s) || /<meta[^>]+content=["'][^"']*url\s*=\s*['"]?([^"'>\s]+)[^>]+http-equiv=["']?refresh/i.exec(s);
      const js = /(?:window\.|document\.|top\.|self\.)?location(?:\.href)?\s*=\s*["'`]([^"'`]+)["'`]|location\.(?:replace|assign)\(\s*["'`]([^"'`]+)["'`]/.exec(s);
      for(const [m2, kind] of [[mm, 'meta refresh'], [js, 'script redirect']]){ if(next || !m2) continue; try{ const u = new URL(m2[1] || m2[2], cur.url).href; if(byUrl(u)){ next = u; how = kind; } }catch(e){} } }
    if(!next) break; const nx = E2.find(e => (e.url === next || e.url.replace(/#.*$/, '') === next.replace(/#.*$/, '')) && !chain.some(c => c.e === e)); if(!nx){ chain.push({e:{url:next, status:0, ip:'', mime:'', resH:[], reqH:[]}, via:how, missing:true}); break; } cur = nx; via = how; }
  const land = [...chain].reverse().find(c => !c.missing && c.e.status >= 200 && c.e.status < 300) || chain[chain.length - 1], landHost = wcHost(land.e.url), landReg = regDomain(landHost);
  // every site contacted
  const hosts = new Map();
  for(const e of E2){ const h = wcHost(e.url); if(!h) continue; const H = hosts.get(h) || {h, n:0, bytes:0, ips:new Set(), mimes:new Set(), first:e.t, third:regDomain(h) !== landReg, svc:wcSvc(h), servers:new Set(), sent:0};
    H.n++; H.bytes += e.size || 0; if(e.ip) H.ips.add(e.ip); if(e.mime) H.mimes.add(e.mime.replace(/^(application|text|image|font)\//, '')); const sv = [wcHdr(e.resH, 'server'), wcHdr(e.resH, 'x-powered-by')].filter(Boolean).join(' · '); if(sv) H.servers.add(sv);
    if(e.method !== 'GET' && e.method !== 'HEAD' && e.method !== 'OPTIONS') H.sent++; hosts.set(h, H); }
  // what was sent: form posts and data-carrying requests, plus GETs to drops (Telegram sendMessage?text=…)
  const sends = [];
  for(const e of E2){ const h = wcHost(e.url), s = wcSvc(h), isDrop = s && s.k === 'drop' || (s && s.k === 'drop?' && /\/api\/webhooks\/|\/macros\/s\//.test(e.url));
    if(!((e.method === 'POST' || e.method === 'PUT' || e.method === 'PATCH') || (isDrop && /[?&]/.test(e.url)))) continue;
    const P = wcParams(e.post, e.url); if(!P.length && !isDrop) continue; if(s && s.k === 'track' && !P.some(p => p.secret || p.user)) continue;
    sends.push({e, host:h, P, third:regDomain(h) !== landReg, drop:isDrop ? s.l : '', creds:P.some(p => p.secret), url:wcMaskHook(wcMaskTg(e.url.split('?')[0]))}); }
  // files handed out
  const downs = E2.filter(e => /attachment/i.test(wcHdr(e.resH, 'content-disposition')) || /application\/(x-msdownload|x-msdos-program|x-dosexec|vnd\.microsoft\.portable-executable|x-iso9660-image|x-msi|java-archive|vnd\.android\.package-archive|x-rar|x-7z|zip|x-zip-compressed|hta|x-ms-shortcut)/i.test(e.mime) || /\.(exe|dll|scr|msi|iso|img|vhdx?|lnk|hta|js|jse|vbs|vbe|wsf|ps1|bat|cmd|apk|dmg|pkg|zip|rar|7z|one|docm|xlsm)(\?|$)/i.test(e.url.split('#')[0]) && !/javascript/i.test(e.mime))
    .filter(e => !/\.js(\?|$)/i.test(e.url) || /attachment/i.test(wcHdr(e.resH, 'content-disposition'))).slice(0, 40)
    .map(e => ({e, name:(/filename\*?=(?:UTF-8'')?["']?([^"';]+)/i.exec(wcHdr(e.resH, 'content-disposition')) || [])[1] || decodeURIComponent((e.url.split(/[?#]/)[0].split('/').pop() || 'download')).slice(0, 120)}));
  // cookies the sites set
  const cookies = []; for(const e of E2) for(const c of wcHdrs(e.resH, 'set-cookie').flatMap(x => x.split('\n'))){ const [nv, ...attr] = c.split(';'), k = nv.indexOf('='); if(k <= 0) continue; const name = nv.slice(0, k).trim(); if(cookies.some(x => x.name === name && x.host === wcHost(e.url))) continue;
    cookies.push({name, host:wcHost(e.url), flags:attr.map(a => a.trim().split('=')[0]).filter(a => /^(httponly|secure|samesite|domain)$/i.test(a)).join(' '), third:regDomain(wcHost(e.url)) !== landReg}); if(cookies.length >= 80) break; }
  // the landing page's fingerprint and the favicon's hash
  let page = null, fav = null; const ld = land.e.body && /html/i.test(land.e.mime) ? land.e : E2.find(e => e.body && /html/i.test(e.mime) && wcHost(e.url) === landHost);
  if(ld && typeof fxPage === 'function') page = await fxPage(wcDec(ld.body.subarray(0, 4e6))).catch(() => null);
  const fe = E2.find(e => e.body && e.body.length && e.status < 300 && (/\/favicon\.(ico|png)(\?|$)/i.test(e.url) || (page && page.favicons.some(f => { try{ return new URL(f, ld.url).href === e.url; }catch(x){ return false; } }))) && /image|octet|icon/i.test(e.mime || 'image'));
  if(fe && typeof fxFavicon === 'function') fav = Object.assign(await fxFavicon(fe.body).catch(() => ({})), {url:fe.url});
  // what stands out
  const flags = [], hv = [...hosts.values()];
  const what = s => { const K = s.P.filter(p => p.secret).map(p => p.k), w = []; if(K.some(k => /card|cc|cvv|cvc|security.?code/i.test(k))) w.push('card details'); if(K.some(k => /pass|pwd/i.test(k))) w.push('a password');
    if(K.some(k => /otp|2fa|mfa|code$|^pin|pin\b/i.test(k) && !/card|cc|cvv|cvc|security/i.test(k))) w.push('a one-time code or PIN'); if(K.some(k => /token|secret/i.test(k))) w.push('a token'); if(K.some(k => /ssn/i.test(k))) w.push('a social security number'); return w; };
  const credSend = sends.filter(s => what(s).length); for(const s of credSend){ const w = what(s); flags.push(['red', `${w.join(', ').replace(/^./, c => c.toUpperCase()).replace(/, ([^,]*)$/, ' and $1')} ${w.length > 1 || /details/.test(w[0]) ? 'were' : 'was'} sent to ${s.host}${s.third ? ' — another site than the page itself' : ''}${s.drop ? ' (' + s.drop + ')' : ''}.`]); }
  for(const s of sends.filter(s => s.drop && !s.creds)) flags.push(['red', `Data was sent to a ${s.drop} (${s.host}) — kits use these to receive what victims type.`]);
  const geo = hv.filter(H => H.svc && H.svc.k === 'geo'); if(geo.length) flags.push(['amber', `The page looked up the visitor's IP and location (${geo.map(H => H.h).join(', ')}) — kits do this to hide from researchers, clouds and other countries.`]);
  if(chain.length > 2) flags.push(['amber', `The visit went through ${chain.length - 1} redirect${chain.length > 2 ? 's' : ''} before landing on ${landHost}.`]);
  if(chain.length > 1 && regDomain(wcHost(chain[0].e.url)) !== landReg) flags.push(['', `The link opened ${wcHost(chain[0].e.url)} but the page that showed was on ${landHost}.`]);
  if(downs.length) flags.push(['amber', `${downs.length} file${downs.length > 1 ? 's were' : ' was'} handed out: ${downs.slice(0, 4).map(d => d.name).join(', ')}.`]);
  const fh = hv.filter(H => H.svc && H.svc.k === 'host' && !H.third); if(fh.length || (land && hosts.get(landHost) && hosts.get(landHost).svc && hosts.get(landHost).svc.k === 'host')) flags.push(['', `The page itself sits on a free hosting or backend service (${landHost}).`]);
  const cap = hv.filter(H => H.svc && H.svc.k === 'captcha?' && !/^www\.google\.com$/.test(H.h)); if(cap.length) flags.push(['', `A captcha (${cap.map(H => H.h).join(', ')}) sat in front of the page — often added so automated scanners see nothing.`]);
  // what the page's own forms would send, and where (an MHTML or a capture without the submit still shows the form)
  const formTo = page ? page.forms.map(a => { try{ return new URL(a, ld.url).href; }catch(e){ return ''; } }).filter(Boolean) : [], formOut = formTo.filter(u => regDomain(wcHost(u)) !== landReg);
  if(formOut.length) flags.push([page.passwords || /name=["']?(seed|mnemonic|phrase|private.?key|recovery)/i.test(wcDec(ld.body.subarray(0, 4e6))) ? 'red' : 'amber', `The page's form sends what is typed to ${[...new Set(formOut.map(wcHost))].join(', ')} — another site than the page itself.`]);
  if(ld && /<(textarea|input)[^>]+name=["']?(seed|mnemonic|phrase|secret.?phrase|private.?key|recovery.?phrase)/i.test(wcDec(ld.body.subarray(0, 4e6)))) flags.push(['red', 'The page asks for a wallet recovery phrase or private key — no real wallet or airdrop ever does.']);
  if(page && page.passwords && !credSend.length) flags.push(['', `The page has ${page.passwords} password field${page.passwords > 1 ? 's' : ''}; no login was sent in this capture.`]);
  const enc = E2.filter(e => e.enc && e.enc.length).length; if(enc) flags.push(['', `${enc} answer${enc > 1 ? 's were' : ' was'} stored compressed with ${[...new Set(E2.flatMap(e => e.enc || []))].join(', ')}, which the browser cannot open here — their content is not read.`]);
  // indicators for the case: the chain, where data went, what was handed out, server IPs, and the page's contact and wallet details
  const iv = [...chain.filter(c => !c.missing).map(c => c.e.url.split('#')[0]), ...formOut, ...sends.map(s => s.url), ...downs.map(d => d.e.url), ...[...new Set(chain.map(c => c.e.ip).concat(sends.map(s => s.e.ip)).filter(Boolean))]];
  let iocs = E.extract(iv.map(v => wcMaskHook(wcMaskTg(v))).join('\n')).filter(x => !/•/.test(x.v));
  if(page && page.ents) iocs = iocs.concat(page.ents);
  const ua = wcHdr((E2.find(e => e.reqH && e.reqH.length) || {}).reqH, 'user-agent') || C.ua || '';
  const tl = E2.filter(e => isFinite(e.t)).map(e => e.t);
  return {fmt:C.fmt, tool:C.tool, browser:C.browser, ua, pages:C.pages || [], saved:C.saved || C.made, title:C.title, n:E2.length, from:tl.length ? Math.min(...tl) : NaN, to:tl.length ? Math.max(...tl) : NaN, t0,
    chain, land:land.e.url, landHost, hosts:hv.sort((a, b) => (a.third - b.third) || ((b.svc && b.svc.k === 'drop' ? 1 : 0) - (a.svc && a.svc.k === 'drop' ? 1 : 0)) || b.n - a.n), sends, downs, cookies, page, fav, flags, iocs, all:E2};
}

/* ---------- the card ---------- */
function wcCard(W){
  if(!W) return '';
  const d = t => isFinite(t) && t ? new Date(t).toISOString().replace('T', ' ').slice(0, 19) + ' UTC' : '', off = t => isFinite(t) && isFinite(W.t0) ? '+' + ((t - W.t0) / 1000).toFixed(2) + ' s' : '';
  const keep = e => e.body && e.body.length ? dxOpenBtn((e.url.split(/[?#]/)[0].split('/').pop() || wcHost(e.url) || 'response') + (/html/i.test(e.mime) && !/\.html?$/i.test(e.url.split(/[?#]/)[0]) ? '.html' : ''), e.body, 'Inspect') : '';
  const st = s => s ? `<span class="pill" style="--c:var(${s >= 400 ? '--red' : s >= 300 ? '--amber' : '--green'})">${s}</span>` : '';
  const kindL = {HAR:'HAR — browser network recording', WARC:'WARC web archive', WACZ:'WACZ web archive', MHTML:'MHTML single-file page'}[W.fmt];
  const svcPill = H => H.svc ? `<span class="pill" style="--c:var(${H.svc.k === 'drop' ? '--red' : H.svc.k === 'geo' || H.svc.k === 'host' ? '--amber' : '--text-3'})">${esc(H.svc.l)}</span>` : '';
  const piv = (W.page || W.fav) && typeof fxPivots === 'function' ? [...(W.page ? fxPivots(W.page) : []), ...(W.fav && W.fav.mmh3 != null ? fxPivots(Object.assign({kind:'favicon'}, W.fav)) : [])].slice(0, 14) : [];
  const ids = W.page ? [['Google Analytics', [...W.page.ga, ...W.page.ga4]], ['Tag Manager', W.page.gtm], ['Google Ads', W.page.aw], ['AdSense', W.page.adsense], ['Yandex Metrica', W.page.ym], ['Meta pixel', W.page.fbp], ['Telegram', W.page.tg.map(t => '@' + t)]].filter(x => x[1].length) : [];
  return `<section class="card wc-card${W.flags.some(f => f[0] === 'red') ? ' warnc' : ''}" id="wcCard"><header><h3>${ico('globe','sm')} Web capture</h3><span class="t3">${esc(kindL)} · ${W.n} request${W.n === 1 ? '' : 's'} · ${W.hosts.length} site${W.hosts.length === 1 ? '' : 's'}</span></header><div class="body">
    ${fxKv('Landed on', W.land)}${fxKv('Page title', (W.page && W.page.title) || W.title)}${fxKv('Captured with', W.tool)}${fxKv('Browser', W.browser)}${fxKv('User agent', W.ua)}${fxKv('Recorded', isFinite(W.from) ? d(W.from) + (W.to - W.from > 1000 ? ' → ' + d(W.to) : '') : d(W.saved))}
    ${W.flags.map(([c, t]) => `<div class="fx-note ${c}">${esc(t)}</div>`).join('')}
    ${W.chain.length > 1 ? `<h4 class="wc-h">${ico('route','sm')}Redirect chain</h4><ol class="wc-chain">${W.chain.map((c, i) => `<li><span class="wc-n">${i + 1}</span><div><code>${esc(c.e.url)}</code><small>${esc(c.via)}${c.e.ip ? ' · ' + esc(c.e.ip) : ''}${c.missing ? ' · not in the capture' : ''}</small></div>${st(c.e.status)}</li>`).join('')}</ol>` : ''}
    ${W.sends.length ? `<h4 class="wc-h">${ico('send','sm')}What the page sent, and where</h4>${W.sends.slice(0, 20).map(s => `<div class="wc-send${s.creds || s.drop ? ' hot' : ''}"><div class="wc-sh"><b>${esc(s.e.method)}</b><code>${esc(s.url)}</code>${s.third ? '<span class="pill" style="--c:var(--amber)">other site</span>' : ''}${s.drop ? `<span class="pill" style="--c:var(--red)">${esc(s.drop)}</span>` : ''}${st(s.e.status)}<span class="t3 small">${esc(off(s.e.t))}</span></div>
        ${s.P.length ? `<div class="wc-ps">${s.P.slice(0, 16).map(p => `<span><i>${esc(p.k)}</i><code class="${p.secret ? 'masked' : ''}">${esc(p.v)}</code></span>`).join('')}</div>` : ''}</div>`).join('')}
      <p class="t3 small" style="margin:6px 0 0">Passwords, codes and tokens are masked here and never saved to a case.</p>` : ''}
    ${W.downs.length ? `<h4 class="wc-h">${ico('download','sm')}Files the page handed out</h4>${W.downs.map(x => `<div class="kv"><span class="mono">${esc(x.name)}</span><b>${esc(x.e.mime || '')}${x.e.size ? ' · ' + fmtBytes(x.e.size) : ''}</b>${keep(x.e)}</div>`).join('')}` : ''}
    <h4 class="wc-h">${ico('network','sm')}Sites contacted</h4>
    <div class="wc-hosts">${W.hosts.slice(0, 80).map(H => `<div class="wc-host${H.svc && H.svc.k === 'drop' ? ' hot' : ''}"><div><code>${esc(H.h)}</code>${H.third ? '' : '<span class="pill" style="--c:var(--accent)">the page</span>'}${svcPill(H)}</div><small>${H.n} request${H.n === 1 ? '' : 's'}${H.bytes ? ' · ' + fmtBytes(H.bytes) : ''}${H.ips.size ? ' · ' + esc([...H.ips].slice(0, 3).join(', ')) : ''}${H.servers.size ? ' · ' + esc([...H.servers].slice(0, 2).join(', ')) : ''}</small></div>`).join('')}${W.hosts.length > 80 ? `<p class="t3 small">and ${W.hosts.length - 80} more</p>` : ''}</div>
    ${W.page || W.fav ? `<h4 class="wc-h">${ico('fingerprint','sm')}The page's fingerprint</h4>${W.page ? fxKv('Page hash (Shodan http.html_hash)', String(W.page.mmh3)) : ''}${W.fav && W.fav.mmh3 != null ? fxKv('Favicon hash (Shodan, FOFA)', String(W.fav.mmh3)) + fxKv('Favicon MD5 (Censys)', W.fav.md5) : ''}
      ${ids.map(([l, L]) => `<div class="kv"><span>${esc(l)}</span><span class="wrap">${L.map(x => `<code class="chip sq">${esc(x)}</code>`).join('')}</span></div>`).join('')}
      ${W.page && W.page.forms.length ? fxKv('Forms post to', W.page.forms.join('  ')) : ''}
      ${piv.length ? `<details class="wc-det"><summary>${piv.length} pivots to find the same kit or owner elsewhere</summary>${piv.map(([e, l, q, u]) => `<a class="li fx-pv" href="${esc(u)}" target="_blank" rel="noopener noreferrer"><div class="main2"><b>${esc(l)} <span class="t3">· ${esc(e)}</span></b><small class="mono">${esc(q)}</small></div>${ico('arrow-up-right','sm')}</a>`).join('')}</details>` : ''}` : ''}
    ${W.cookies.length ? `<details class="wc-det"><summary>${W.cookies.length} cookie${W.cookies.length === 1 ? '' : 's'} set</summary><div class="wc-ck">${W.cookies.map(c => `<span><code>${esc(c.name)}</code><small>${esc(c.host)}${c.flags ? ' · ' + esc(c.flags) : ''}</small></span>`).join('')}</div></details>` : ''}
    <details class="wc-det"><summary>Every request (${W.all.length})</summary><div class="wc-all">${W.all.slice(0, 600).map(e => `<div><span class="t3 mono">${esc(off(e.t))}</span><b>${esc(e.method)}</b>${st(e.status)}<code>${esc(wcMaskHook(wcMaskTg(e.url)))}</code><span class="t3 hide-m">${esc(e.mime || '')}</span>${keep(e)}</div>`).join('')}${W.all.length > 600 ? `<p class="t3 small">First 600 shown.</p>` : ''}</div></details>
    <p class="t3 small" style="margin:10px 0 0">To record one: in your research browser open the developer tools (F12) → Network, tick “Preserve log”, visit the page, then export the list as HAR (the download arrow in Chrome and Edge, right-click → “Save All As HAR” in Firefox). Tick “Disable cache” too, so every file is fetched and kept. A HAR holds cookies and anything you typed, so keep it with the case.</p>
  </div></section>`;
}

/* the capture in words, for the case record (passwords, codes and tokens stay masked) */
function wcSummary(W){
  return [`Web capture (${W.fmt}): ${W.n} requests to ${W.hosts.length} sites${isFinite(W.from) ? ', ' + new Date(W.from).toISOString() : ''}`, `Landed on: ${W.land}`,
    W.chain.length > 1 ? 'Redirect chain:\n' + W.chain.map((c, i) => `  ${i + 1}. ${c.e.url}${c.e.status ? ' [' + c.e.status + ']' : ''}${c.e.ip ? ' ' + c.e.ip : ''} — ${c.via}`).join('\n') : '',
    W.flags.length ? 'Stands out:\n' + W.flags.map(f => '  - ' + f[1]).join('\n') : '',
    W.sends.length ? 'Sent:\n' + W.sends.map(x => `  ${x.e.method} ${x.url} — ${x.P.map(p => p.k + '=' + p.v).join(', ')}`).join('\n') : '',
    W.downs.length ? 'Handed out: ' + W.downs.map(d => d.name + ' (' + wcMaskTg(d.e.url) + ')').join(', ') : '',
    W.page ? `Page hash (Shodan http.html_hash): ${W.page.mmh3}` : '', W.fav && W.fav.mmh3 != null ? `Favicon hash (Shodan): ${W.fav.mmh3}` : ''].filter(Boolean).join('\n');
}
