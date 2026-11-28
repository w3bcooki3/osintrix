/* ==========================================================================
   The reasoning on top of live lookups:
     lkVerdict    — one score from many sources, weighted by how much each source is
                    trusted, how strong its evidence is and how old it is; with reasons
     lkCorrelate  — which indicators belong together (shared certificate, IP, favicon,
                    name servers, registration day…), weighted by how rare the link is
     ctiRank      — "For you": which stories matter to you, learned from your triage
     watch monitor— re-checks watched indicators while the app is open and tells you
                    what changed
   Pure reasoning — no network here; lookups.js does the asking.
   ========================================================================== */

/* ---------- verdict ---------- */
const VD_HALF = 120;                                                         // evidence loses half its weight every 120 days
const vdDecay = ts => ts ? Math.max(0.2, Math.pow(0.5, Math.max(0, (Date.now() - ts) / 864e5) / VD_HALF)) : 1;
const noisyOr = xs => 1 - xs.reduce((p, x) => p * (1 - Math.max(0, Math.min(0.999, x))), 1);
function lkVerdict(k, v, res){
  const ev = [], answered = [], failed = [];
  for(const [pid, r] of Object.entries(res || {})){
    const p = lkProv(pid); if(!p || !r) continue; if(!r.ok){ failed.push(p.name); continue; } answered.push(p.name);
    for(const s of r.sig || []) ev.push({t:s.t, x:s.w * p.rel * vdDecay(s.ts), why:s.why, src:p.name});
  }
  /* what this workspace already knows */
  const key = k + ':' + v;
  if(typeof CTI !== 'undefined' && CTI.iocIx){ const x = CTI.iocIx.get(key); if(x && iocLive(x)) ev.push({t:'mal', x:0.8 * ((+x.conf || 75) / 100), why:'In your indicator feeds' + (x.threat ? ': ' + x.threat : '') + (x.srcs && x.srcs[0] ? ' (' + x.srcs[0] + ')' : ''), src:'Your feeds'}); }
  if(k === 'cve' && typeof kevOf === 'function'){ const kv = kevOf(v); if(kv) ev.push({t:'mal', x:0.92, why:'CISA lists it as exploited in the wild' + (kv.ransom ? ', including by ransomware' : ''), src:'CISA KEV'}); }
  if(typeof ctxOf === 'function') for(const [t, tone] of ctxOf(k, v)){ if(/^In your feeds|Known exploited/.test(t)) continue; if(tone === 'red') ev.push({t:'sus', x:0.35, why:t, src:'Local checks'}); else if(tone === 'amber') ev.push({t:'sus', x:0.15, why:t, src:'Local checks'}); }
  /* independent sources agreeing is stronger than any one of them */
  const malSrc = new Set(ev.filter(e => e.t === 'mal' && e.x >= 0.15).map(e => e.src)).size;
  const M = 1 - (1 - noisyOr(ev.filter(e => e.t === 'mal').map(e => e.x))) * (malSrc >= 3 ? 0.65 : malSrc === 2 ? 0.8 : 1), S = noisyOr(ev.filter(e => e.t === 'sus').map(e => e.x)), B = noisyOr(ev.filter(e => e.t === 'ben').map(e => e.x));
  /* suspicion alone tops out around "suspicious"; benign evidence pulls the score down unless malicious evidence is strong */
  const raw = 1 - (1 - M) * (1 - 0.62 * S), score = Math.round(100 * raw * (1 - 0.75 * B * (1 - M)));
  const band = score >= 70 ? 'malicious' : score >= 40 ? 'suspicious' : B >= 0.3 && M < 0.25 ? 'benign' : ev.length || answered.length ? 'clean' : 'unknown';
  /* confidence: how many independent sources answered, and whether they agree */
  const dirs = ev.filter(e => e.x >= 0.15).map(e => e.t === 'ben' ? -1 : 1), agree = dirs.length ? Math.abs(dirs.reduce((a, b) => a + b, 0)) / dirs.length : 0, srcs = new Set(ev.map(e => e.src)).size;
  const conf = answered.length >= 4 && (agree >= 0.6 || srcs >= 3) ? 'high' : answered.length >= 2 ? 'medium' : 'low';
  return {k, v, score, band, conf, M, S, B, reasons:ev.sort((a, b) => b.x - a.x), answered, failed, attrs:lkMerge(res), related:lkRelated(res)};
}
/* one picture from every source's attributes */
const LK_ARR = ['ports', 'cves', 'tags', 'ips', 'ns', 'mx', 'certs', 'jarm', 'favicon', 'titles', 'servers', 'products', 'malware', 'actors', 'ttp', 'subs', 'abuse', 'certCN', 'cpes', 'breaches', 'ptr', 'cname'];
function lkMerge(res){
  const A = {}; for(const r of Object.values(res || {})){ if(!r || !r.ok || !r.attrs) continue;
    for(const [key, val] of Object.entries(r.attrs)){
      if(LK_ARR.includes(key)){ A[key] = A[key] || []; for(const x of (Array.isArray(val) ? val : [val])) if(x !== '' && x != null && !A[key].includes(x) && A[key].length < 400) A[key].push(x); }
      else if(A[key] == null || A[key] === '' || A[key] === 0) A[key] = val;
    } }
  return A;
}
function lkRelated(res){ const m = new Map(); for(const r of Object.values(res || {})) for(const x of (r && r.related) || []){ const key = x.k + ':' + x.v; const o = m.get(key); if(o){ if(!o.rel.includes(x.rel)) o.rel.push(x.rel); } else m.set(key, {k:x.k, v:x.v, rel:[x.rel]}); } return [...m.values()]; }
const VD_COL = {malicious:'var(--red)', suspicious:'var(--amber)', benign:'var(--green)', clean:'var(--text-3)', unknown:'var(--text-3)'};
const VD_NAME = {malicious:'Malicious', suspicious:'Suspicious', benign:'Benign', clean:'Nothing found', unknown:'Not checked'};

/* ---------- correlation ---------- */
/* name-server, hosting and CDN providers shared by millions of unrelated sites: weak evidence */
const COMMON_NS = /(^|\.)(cloudflare\.com|awsdns-\d+\.\w+|domaincontrol\.com|googledomains\.com|google\.com|azure-dns\.\w+|nsone\.net|dnsimple\.com|registrar-servers\.com|name-services\.com|dynect\.net|ultradns\.\w+|akam\.net|digitalocean\.com|linode\.com|hostgator\.com|bluehost\.com|namecheaphosting\.com|wixdns\.net|squarespacedns\.com|dns\.com|hichina\.com|dnspod\.net|ovh\.net|hetzner\.com|gandi\.net|porkbun\.com|vercel-dns\.com|netlify\.com|afternic\.com|parkingcrew\.net|sedoparking\.com|bodis\.com)$/i;
const BIG_AS = new Set(['AS13335', 'AS16509', 'AS14618', 'AS15169', 'AS396982', 'AS8075', 'AS20940', 'AS16625', 'AS54113', 'AS32934', 'AS14061', 'AS24940', 'AS16276', 'AS63949', 'AS209242', 'AS19551', 'AS8068']);
const GENERIC_TITLE = /^(index of|404|403|not found|forbidden|welcome to nginx|apache2? .*default page|iis windows server|default web site page|it works!?|test page|coming soon|under construction|login|sign in|home|untitled|document|302 found|301 moved|bad request|error|domain for sale|parked|suspended)/i;
const PIVOT_W = {cert:1, fav:0.9, ip:0.9, ns:0.8, family:0.7, jarm:0.6, regday:0.6, actor:0.6, title:0.5, prefix:0.45, mx:0.4, asn:0.25, registrar:0.2, server:0.15};
const PIVOT_NAME = {cert:'same TLS certificate', fav:'same favicon', ip:'same IP address', ns:'same name servers', family:'same malware family', jarm:'same TLS fingerprint (JARM)', regday:'registered the same day at the same registrar', actor:'same adversary', title:'same page title', prefix:'same network prefix', mx:'same mail server', asn:'same network (ASN)', registrar:'same registrar', server:'same web server banner'};
const regDomain = h => { const p = String(h).toLowerCase().replace(/\.$/, '').split('.'); return p.length > 2 && /^(co|com|net|org|gov|ac|edu)$/.test(p[p.length - 2]) ? p.slice(-3).join('.') : p.slice(-2).join('.'); };
function lkFeatures(k, v, A){
  const F = [], add = (t, x) => { if(x !== '' && x != null) F.push([t, String(x).toLowerCase()]); };
  const cdn = A.asn && BIG_AS.has(A.asn) || (A.tags || []).includes('cdn');
  (A.certs || []).forEach(x => add('cert', x)); (A.favicon || []).forEach(x => add('fav', x)); (A.jarm || []).filter(x => !/^0+$/.test(x)).forEach(x => add('jarm', x));
  if(!cdn){ if(k === 'ipv4' || k === 'ipv6') add('ip', v); (A.ips || []).forEach(x => add('ip', x)); if(A.prefix) add('prefix', A.prefix); }
  if(k !== 'ipv4' && k !== 'ipv6') [...new Set((A.ns || []).filter(n => !COMMON_NS.test(n)).map(regDomain))].filter(d => d !== regDomain(v)).forEach(d => add('ns', d));
  [...new Set((A.mx || []).filter(n => !COMMON_NS.test(n) && !/google|outlook|protection\.outlook|zoho|yandex|mailgun|sendgrid|pphosted|mimecast/.test(n)).map(regDomain))].filter(d => d !== regDomain(v)).forEach(d => add('mx', d));
  if(A.created && A.registrar) add('regday', A.registrar + '@' + new Date(A.created).toISOString().slice(0, 10));
  if(A.registrar) add('registrar', A.registrar);
  (A.titles || []).filter(t => t.length > 5 && !GENERIC_TITLE.test(t)).forEach(t => add('title', t));
  (A.malware || []).forEach(x => add('family', x)); (A.actors || []).forEach(x => add('actor', x));
  if(A.asn && !BIG_AS.has(A.asn)) add('asn', A.asn); (A.servers || []).filter(s => !/^(nginx|apache|cloudflare|microsoft-iis\/[\d.]+|openresty|litespeed|gws|awselb.*|amazons3)$/i.test(s)).forEach(s => add('server', s));
  return F;
}
/* items: [{key, k, v, attrs}] → pairs and clusters */
function lkCorrelate(items){
  const by = new Map(), feats = items.map(it => lkFeatures(it.k, it.v, it.attrs || {}));
  feats.forEach((F, i) => F.forEach(([t, x]) => { const id = t + '|' + x; if(!by.has(id)) by.set(id, new Set()); by.get(id).add(i); }));
  const pair = new Map(), n = items.length;
  for(const [id, set] of by){ if(set.size < 2) continue; const t = id.slice(0, id.indexOf('|')), x = id.slice(id.indexOf('|') + 1);
    /* a value most of the set shares is not a distinguishing link */
    const rare = n >= 5 && set.size / n > 0.4 ? 0.4 : set.size > 25 ? 0.5 : 1, w = PIVOT_W[t] * rare, L = [...set];
    for(let a = 0; a < L.length; a++) for(let b = a + 1; b < L.length; b++){ const pk = L[a] + ',' + L[b]; const o = pair.get(pk) || {a:L[a], b:L[b], ws:[], why:[]}; o.ws.push(w); o.why.push({t, x, w}); pair.set(pk, o); } }
  const pairs = [...pair.values()].map(o => ({a:items[o.a].key, b:items[o.b].key, ia:o.a, ib:o.b, score:noisyOr(o.ws), why:o.why.sort((p, q) => q.w - p.w)})).filter(p => p.score >= 0.35).sort((p, q) => q.score - p.score);
  /* clusters: connected components over strong links */
  const par = items.map((_, i) => i), f = i => par[i] === i ? i : (par[i] = f(par[i]));
  pairs.filter(p => p.score >= 0.6).forEach(p => { par[f(p.ia)] = f(p.ib); });
  const groups = new Map(); items.forEach((it, i) => { const r = f(i); if(!groups.has(r)) groups.set(r, []); groups.get(r).push(it.key); });
  return {pairs, clusters:[...groups.values()].filter(g => g.length > 1).sort((a, b) => b.length - a.length)};
}
const pivotWhy = why => [...new Set(why.map(w => PIVOT_NAME[w.t]))].slice(0, 3).join(', ');
/* draw correlated pairs as relationships on the case graph (between vault entries; an indicator not in the vault is added) */
function lkLinkPairs(pairs){
  let n = 0;
  const entryFor = key => { const {k, v} = entSplit(key); let e = DB.entries.find(x => x.caseId === DB.active && entryKey(x) === key); if(!e && KIND_TO_TYPE[k]){ ctiAddEntry(k, v, 'Found by correlation'); e = DB.entries.find(x => x.caseId === DB.active && entryKey(x) === key); } return e; };
  for(const p of pairs){ const a = entryFor(p.a), b = entryFor(p.b); if(!a || !b || a.id === b.id) continue;
    const label = cap(PIVOT_NAME[p.why[0].t], 80);
    if(DB.links.some(l => l.caseId === DB.active && ((l.a === a.id && l.b === b.id) || (l.a === b.id && l.b === a.id)) && normName(l.label) === normName(label))) continue;
    DB.links.push({id:uid('l'), caseId:DB.active, a:a.id, b:b.id, label, conf:p.score >= 0.85 ? 3 : p.score >= 0.6 ? 2 : 1, src:''}); n++; }
  return n;
}

/* ---------- "For you": ranking stories ---------- */
/* learned from what you mark relevant, act on, star or dismiss: words that predict "relevant" gain weight */
function ctiModel(){
  if(CTI.model && CTI.model.rev === rev) return CTI.model;
  const pos = new Map(), neg = new Map(); let np = 0, nn = 0;
  for(const f of DB.feed){ const good = f.st === 'relevant' || f.st === 'actioned' || f.star, bad = f.st === 'dismissed'; if(!good && !bad) continue;
    const W = ctiWords(f.title + ' ' + (f.body || '').slice(0, 300)); const X = ctiX(f); [...X.cve.map(c => 'cve'), ...X.act.map(a => 'act:' + a), ...X.mal.map(a => 'act:' + a), ...X.ven.map(v => 'ven:' + v.toLowerCase()), 'cat:' + f.cat, 'src:' + f.source].forEach(t => W.add(t));
    for(const w of W){ const m = good ? pos : neg; m.set(w, (m.get(w) || 0) + 1); } good ? np++ : nn++; }
  const wt = new Map(), all = new Set([...pos.keys(), ...neg.keys()]);
  if(np + nn >= 4) for(const w of all){ const p = ((pos.get(w) || 0) + 0.5) / (np + 1), q = ((neg.get(w) || 0) + 0.5) / (nn + 1), l = Math.log(p / q); if(Math.abs(l) > 0.4 && (pos.get(w) || 0) + (neg.get(w) || 0) >= 2) wt.set(w, Math.max(-2, Math.min(2, l))); }
  return (CTI.model = {rev, wt, np, nn});
}
function ctiRank(st){
  const R = [], add = (w, why) => { if(w) R.push([w, why]); }, mine = storyMine(st), X = st.items.map(ctiX), M = ctiModel();
  add(mine.hits.length ? 40 + 5 * Math.min(4, mine.hits.length) : 0, mine.hits.length + ' indicator' + (mine.hits.length > 1 ? 's' : '') + ' from your cases');
  add(mine.kevStack ? 35 : mine.stack.length ? 22 : 0, mine.kevStack ? 'Exploited vulnerability in your stack' : 'Mentions your stack: ' + mine.stack.slice(0, 2).join(', '));
  const kev = [...new Set(X.flatMap(x => x.kev))]; add(kev.length ? 14 : 0, 'Known exploited CVE');
  const sev = st.items.some(f => f.sev === 'critical') ? 12 : st.items.some(f => f.sev === 'high') ? 6 : 0; add(sev, sev > 6 ? 'Critical' : 'High severity');
  const feedHit = CTI.iocIx ? X.flatMap(x => x.iocs).filter(e => { const i = CTI.iocIx.get(entKey(e)); return i && iocLive(i); }).length : 0; add(feedHit ? 10 : 0, 'Indicators that are in your feeds');
  const W = DB.watch || {}, wh = X.flatMap(x => x.iocs).filter(e => W[entKey(e)]).length; add(wh ? 30 : 0, 'A watched indicator');
  add(st.sources.length > 1 ? Math.min(10, 4 * (st.sources.length - 1)) : 0, 'Reported by ' + st.sources.length + ' sources');
  if(M.wt.size){ const T = ctiWords(st.lead.title + ' ' + (st.lead.body || '').slice(0, 300)); X.forEach(x => { x.act.concat(x.mal).forEach(a => T.add('act:' + a)); x.ven.forEach(v => T.add('ven:' + v.toLowerCase())); }); T.add('cat:' + st.lead.cat); st.sources.forEach(s => T.add('src:' + s));
    const hits = [...T].map(t => [t, M.wt.get(t)]).filter(x => x[1]), s = hits.reduce((a, x) => a + x[1], 0);
    if(Math.abs(s) >= 0.5){ const top = hits.sort((a, b) => Math.abs(b[1]) - Math.abs(a[1])).slice(0, 3).map(x => x[0].replace(/^\w+:/, '')); add(Math.round(Math.max(-25, Math.min(25, s * 6))), (s > 0 ? 'Like stories you marked relevant' : 'Like stories you dismissed') + ' (' + top.join(', ') + ')'); } }
  const age = (Date.now() - st.ts) / 864e5, rec = Math.round(20 * Math.pow(0.5, age / 3));
  const score = R.reduce((a, r) => a + r[0], 0) + rec;
  return {score, why:R.filter(r => r[0] > 0).sort((a, b) => b[0] - a[0]).map(r => r[1]), down:R.filter(r => r[0] < 0).map(r => r[1])};
}

/* ---------- watch monitor ---------- */
/* what of a verdict is worth comparing between checks. A field is only compared when both checks have it, so a
   snapshot from an older version never reports everything as new. */
const WS_LIST = ['ports', 'ips', 'ns', 'mx', 'cname', 'ptr', 'cves', 'malware', 'breaches', 'subs', 'certs'];
function lkSnap(V){ const A = V.attrs || {}, j = (x, n = 400) => (Array.isArray(x) ? x : []).map(String).slice(0, n).sort().join(','), o = {sv:2, band:V.band, score:V.score};
  for(const f of WS_LIST) o[f] = j(A[f], f === 'subs' ? 200 : f === 'certs' ? 60 : 100);
  o.ports = (A.ports || []).slice().sort((a, b) => a - b).join(',');
  Object.assign(o, {asn:String(A.asn || ''), org:String(A.asname || A.org || A.netname || '').slice(0, 120), registrar:String(A.registrar || '').slice(0, 120), expires:+A.expires || 0,
    hold:(A.status || []).filter(x => /hold/i.test(x)).join(','), nx:!!A.nx, tor:String(A.tor || ''), vt:A.vtMal || 0, abuse:A.abuseScore || 0, pulses:A.pulses || 0,
    txs:+A.txs || 0, bal:+A.bal || 0, ethBal:String(A.ethBal || ''), expl:String(A.exploitation || ''), epss:+A.epss || 0});
  return o; }
const wsDay = t => t ? new Date(t).toISOString().slice(0, 10) : '?';
function lkDiff(a, b, kind){
  if(!a) return []; const out = [], list = s => s ? String(s).split(',') : [], has = f => f in a && f in b, delta = (x, y) => { const X = new Set(list(x)), Y = new Set(list(y)); return [[...Y].filter(i => !X.has(i)), [...X].filter(i => !Y.has(i))]; };
  const some = (L, n = 5) => L.slice(0, n).join(', ') + (L.length > n ? ' and ' + (L.length - n) + ' more' : '');
  if(a.band !== b.band) out.push({hot:/malicious|suspicious/.test(b.band) && !/malicious/.test(a.band), t:'Verdict ' + VD_NAME[a.band] + ' → ' + VD_NAME[b.band] + ' (' + b.score + ')'});
  /* it went dark, or came back: a takedown working, or infrastructure coming up */
  if(has('nx') && a.nx !== b.nx) out.push({hot:true, t:b.nx ? 'Stopped resolving — the domain no longer exists in DNS (taken down or let go?)' : 'Resolves again — the domain is back online'});
  if(has('hold') && b.hold && b.hold !== a.hold) out.push({hot:true, t:'Suspended by the registry or registrar: ' + b.hold});
  if(has('hold') && a.hold && !b.hold) out.push({hot:true, t:'No longer suspended (' + a.hold + ' lifted)'});
  for(const [f, name, hot] of [['ips', 'address', true], ['ports', 'port', true], ['ns', 'name server', true], ['mx', 'mail server', true], ['cname', 'CNAME', false], ['ptr', 'reverse name', false], ['cves', 'CVE on an exposed service', true], ['malware', 'malware link', true], ['breaches', 'breach', true]]){
    if(!(f in a)) continue; const [add, gone] = delta(a[f], b[f]);
    if(f === 'mx' && add.length && !list(a.mx).length && kind === 'domain'){ out.push({hot:true, t:'Mail set up: ' + some(add) + ' — the domain can now send and receive mail'}); continue; }
    if(add.length) out.push({hot, t:'New ' + name + (add.length > 1 ? 's' : '') + ': ' + some(add)}); if(gone.length) out.push({hot:false, t:'Gone' + (f === 'ips' ? ' (address)' : f === 'ports' ? ' (port)' : '') + ': ' + some(gone)}); }
  if(has('asn') && a.asn && b.asn && a.asn !== b.asn) out.push({hot:true, t:'Moved network: ' + a.asn + (a.org ? ' (' + a.org + ')' : '') + ' → ' + b.asn + (b.org ? ' (' + b.org + ')' : '')});
  if(has('registrar') && a.registrar && b.registrar && a.registrar !== b.registrar) out.push({hot:true, t:'Transferred to another registrar: ' + a.registrar + ' → ' + b.registrar});
  if(has('expires') && a.expires && b.expires && b.expires > a.expires + 864e5) out.push({hot:false, t:'Renewed until ' + wsDay(b.expires)});
  if(has('certs')){ const [add] = delta(a.certs, b.certs); if(add.length && a.certs) out.push({hot:true, t:add.length + ' new certificate' + (add.length > 1 ? 's' : '') + ' issued'}); }
  if(has('subs')){ const [add] = delta(a.subs, b.subs); if(add.length && a.subs) out.push({hot:true, t:'New subdomain' + (add.length > 1 ? 's' : '') + ': ' + some(add)}); }
  if(has('tor') && a.tor !== b.tor) out.push({hot:b.tor === 'exit', t:b.tor ? 'Now a Tor ' + b.tor : 'No longer a Tor relay'});
  if(b.vt > a.vt) out.push({hot:true, t:'VirusTotal detections ' + a.vt + ' → ' + b.vt}); if(b.abuse - a.abuse >= 15) out.push({hot:true, t:'AbuseIPDB score ' + a.abuse + '% → ' + b.abuse + '%'});
  if(b.pulses > a.pulses) out.push({hot:true, t:(b.pulses - a.pulses) + ' new OTX pulse' + (b.pulses - a.pulses > 1 ? 's' : '')});
  /* wallets: money moving is the news */
  if(has('txs') && b.txs > a.txs) out.push({hot:true, t:(b.txs - a.txs) + ' new transaction' + (b.txs - a.txs > 1 ? 's' : '')});
  if(has('bal') && b.bal !== a.bal && (a.txs || b.txs)) out.push({hot:true, t:'Balance ' + (a.bal / 1e8).toFixed(8).replace(/\.?0+$/, '') + ' → ' + (b.bal / 1e8).toFixed(8).replace(/\.?0+$/, '') + ' BTC'});
  if(has('ethBal') && a.ethBal && b.ethBal && a.ethBal !== b.ethBal) out.push({hot:true, t:'Balance ' + a.ethBal + ' → ' + b.ethBal});
  /* CVEs: exploitation is what changes the priority */
  if(has('expl') && b.expl && a.expl !== b.expl) out.push({hot:/active|poc/i.test(b.expl), t:'Exploitation: ' + (a.expl || 'none') + ' → ' + b.expl});
  if(has('epss') && b.epss - a.epss >= 0.1) out.push({hot:true, t:'EPSS ' + (a.epss * 100).toFixed(0) + '% → ' + (b.epss * 100).toFixed(0) + '% chance of exploitation in 30 days'});
  return out;
}
/* your own passive DNS: every value a watched indicator pointed to, with when it was first and last seen by your checks */
const WS_SEEN = ['ips', 'ns', 'mx', 'cname', 'ptr', 'asn', 'registrar', 'hold'];
function watchSeen(w, snap, at){
  const S = w.seen && typeof w.seen === 'object' ? w.seen : (w.seen = {});
  for(const f of WS_SEEN){ const vals = String(snap[f] || '').split(',').filter(Boolean); if(!vals.length) continue; const m = S[f] = S[f] || {};
    for(const v of vals.slice(0, 40)){ const x = m[v]; if(x) x[1] = at; else m[v] = [at, at]; }
    const keys = Object.keys(m); if(keys.length > 60) keys.sort((p, q) => m[p][1] - m[q][1]).slice(0, keys.length - 60).forEach(k => delete m[k]); }
}
const WATCH_KINDS = new Set(['ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256', 'cve', 'btc', 'eth']);
const MON = {t:null, busy:false};
function watchEvery(w){ const own = w && +w.every; const h = own > 0 ? own : +(DB.prefs && DB.prefs.watchEvery) || 0; return h > 0 ? h * 3600e3 : 0; }
const watchAny = () => (+(DB.prefs && DB.prefs.watchEvery) || 0) > 0 || Object.values(DB.watch || {}).some(w => +w.every > 0);
async function watchCheck(keys, opts = {}){
  if(MON.busy) return 0; MON.busy = true; let changed = 0; const hot = [];
  try{
    for(const key of keys){ const w = DB.watch && DB.watch[key]; if(!w) continue; const {k, v} = entSplit(key); if(!WATCH_KINDS.has(k)) continue;
      const res = await lkInvestigate(k, v, {force:true}); if(!Object.keys(res).length) continue;
      const V = lkVerdict(k, v, res), snap = lkSnap(V), now = Date.now(), diff = lkDiff(w.snap, snap, k);
      w.checked = now; w.snap = snap; watchSeen(w, snap, now);
      if(diff.length){ w.alerts = [{at:now, d:diff}, ...(w.alerts || [])].slice(0, 20); w.unseen = true; changed++;
        if(w.file) watchFile(key, 0, true);
        if(diff.some(d => d.hot) && !w.mute){ hot.push([v, diff.find(d => d.hot).t]); if(!opts.quiet) toast('Watchlist: ' + v + ' — ' + diff.find(d => d.hot).t, 'Open', () => go('#/watch')); } }
      lkHist(k, v, V);
    }
  }finally{ MON.busy = false; }
  if(hot.length) watchPing(hot);
  if(keys.length){ save(); if(UI.route && UI.route.area === 'watch') bgRender(); }
  return changed;
}
/* a desktop notice for important changes, only when asked for and only while the tab is in the background; discreet mode keeps the indicator off the lock screen */
function watchPing(hot){
  try{ if(!DB.prefs || !DB.prefs.watchNotify || typeof Notification === 'undefined' || Notification.permission !== 'granted' || !document.hidden) return;
    const body = DB.prefs.discreet ? hot.length + ' watched item' + (hot.length > 1 ? 's' : '') + ' changed' : hot.slice(0, 3).map(([v, t]) => v + ': ' + t).join('\n');
    new Notification('OSINTrix watchlist', {body, tag:'osintrix-watch'}); }catch(e){}
}
/* a change, kept as evidence in each case that holds the indicator (or the open case): dated when the check saw it, with what changed and from where */
function watchFile(key, i, auto){
  const w = DB.watch && DB.watch[key], a = w && (w.alerts || [])[i]; if(!a) return 0; const {k, v} = entSplit(key);
  const g = typeof globalEnts === 'function' ? globalEnts().get(key) : null, cases = [...(g ? g.cases : [])].filter(cid => typeof theCase === 'function' && theCase(cid));
  const to = cases.length ? cases : !auto && DB.active && theCase(DB.active) ? [DB.active] : []; if(!to.length) return 0;
  const lead = (a.d.find(d => d.hot) || a.d[0]).t, body = v + '\n\n' + a.d.map(d => '• ' + d.t).join('\n') + '\n\nNoticed by an online check from the watchlist on ' + new Date(a.at).toISOString().replace('T', ' ').slice(0, 16) + ' UTC.';
  let n = 0;
  for(const cid of to){ if(DB.records.some(r => r.caseId === cid && r.watchAt === a.at && r.watchKey === key)) continue;
    DB.records.push({id:uid('r'), caseId:cid, type:'evidence', title:'Watchlist: ' + v + ' — ' + lead.slice(0, 140), body, tsRaw:new Date(a.at).toISOString(), tsZone:'explicit', ts:a.at, source:'watchlist', host:'', tags:['watch'].concat(a.d.some(d => d.hot) ? ['change'] : []),
      ents:[{k, v}, ...E.extract(a.d.map(d => d.t).join('\n')).filter(e => !(e.k === k && e.v === v))], answer:'', addedBy:auto ? 'Watchlist' : 'You', addedAt:Date.now(), hash:'', watchAt:a.at, watchKey:key}); n++; }
  if(n){ a.filed = true; mutate((auto ? 'watchlist filed ' : 'filed ') + 'a change to ' + v); if(typeof hashRecords === 'function') hashRecords(); }
  return n;
}
/* runs while the app is open: anything not checked within its interval is re-checked, a few at a time; on opening, overdue ones are caught up first */
function watchMonitor(){
  clearInterval(MON.t); if(!watchAny()) return;
  const tick = () => { if(document.hidden && !DB.prefs.watchNotify || MON.busy || !DB.watch) return;
    const due = Object.keys(DB.watch).filter(key => { const w = DB.watch[key], e = watchEvery(w); return e && WATCH_KINDS.has(entSplit(key).k) && Date.now() - (w.checked || 0) > e; })
      .sort((p, q) => (DB.watch[p].checked || 0) - (DB.watch[q].checked || 0)).slice(0, 5);
    if(due.length) watchCheck(due); };
  MON.t = setInterval(tick, 5 * 60000); setTimeout(tick, 20000);
}
/* recent investigations, for the Investigate history */
function lkHist(k, v, V){ const I = ctiEnsure(); I.lookHist = (Array.isArray(I.lookHist) ? I.lookHist : []).filter(h => !(h.k === k && h.v === v)); I.lookHist.unshift({k, v, at:Date.now(), band:V.band, score:V.score}); I.lookHist = I.lookHist.slice(0, 200); }
