/* ==========================================================================
   Smart search — plain questions about your indicators.
     "malicious IPs last week in TN-2026-014"   "domains registered this month"
     "unchecked hashes"   "what talks to 203.0.113.47"   "IPs in Russia on port 4444"
     "flagged domains hosted on vultr"   "watched indicators seen yesterday on DC01"
   The words are turned into filters, shown back as chips ("understood as"), and run
   over every indicator in every case, using verdicts, sightings, the graph, your
   feeds and saved live-lookup answers. Nothing leaves the browser.
   ========================================================================== */
const NLQ_KIND = [[/^(ips?|ip ?addresse?s?|addresse?s|ipv4s?|ipv6s?)$/, ['ipv4', 'ipv6'], 'IP addresses'], [/^(domains?|sites?|websites?|hostnames?|fqdns?)$/, ['domain'], 'domains'], [/^(urls?|links?)$/, ['url'], 'URLs'],
  [/^(hash(es)?|samples?|md5s?|sha1s?|sha256s?|files? hash(es)?)$/, ['md5', 'sha1', 'sha256'], 'file hashes'], [/^(emails?|e-?mail addresse?s?|mailboxe?s)$/, ['email'], 'email addresses'],
  [/^(cves?|vulnerabilit(y|ies)|vulns?)$/, ['cve'], 'CVEs'], [/^(wallets?|crypto|btc|bitcoin|eth|ethereum|addresses? on chain)$/, ['btc', 'eth', 'xmr', 'ltc', 'trx', 'doge'], 'wallets'],
  [/^(handles?|usernames?|accounts?|aliases)$/, ['handle', 'social'], 'handles'], [/^(phones?|phone numbers?|numbers)$/, ['phone'], 'phone numbers'], [/^(ports?|services?|ip:ports?|hostports?)$/, ['hostport'], 'IP:port pairs']];
const NLQ_STOP = new Set('show me find list all any the a an of in on with that which who what are is were was have has been and or for to from by indicators indicator iocs ioc entities things items stuff seen observed please'.split(' '));
const NLQ_COUNTRY = {russia:'RU', china:'CN', iran:'IR', 'north korea':'KP', ukraine:'UA', germany:'DE', netherlands:'NL', france:'FR', 'united states':'US', usa:'US', us:'US', america:'US', uk:'GB', britain:'GB', 'united kingdom':'GB', india:'IN', brazil:'BR', singapore:'SG', japan:'JP', canada:'CA', romania:'RO', bulgaria:'BG', vietnam:'VN', turkey:'TR', 'hong kong':'HK', korea:'KR', 'south korea':'KR', seychelles:'SC', panama:'PA', moldova:'MD', lithuania:'LT', poland:'PL', sweden:'SE', finland:'FI', switzerland:'CH', israel:'IL', nigeria:'NG', indonesia:'ID'};
const NLQ_MONTH = ['january', 'february', 'march', 'april', 'may', 'june', 'july', 'august', 'september', 'october', 'november', 'december'];
const NLQ_UNIT = {minute:6e4, min:6e4, hour:36e5, hr:36e5, h:36e5, day:864e5, d:864e5, week:6048e5, w:6048e5, month:2592e6, year:31536e6};

/* a time phrase at the start of s → [from, to, label, length consumed] */
function nlqTime(s, now = Date.now()){
  const day0 = t => { const d = new Date(t); d.setHours(0, 0, 0, 0); return +d; }; let m;
  if((m = /^(today)\b/.exec(s))) return [day0(now), now, 'today', m[0].length];
  if((m = /^(yesterday)\b/.exec(s))) return [day0(now) - 864e5, day0(now), 'yesterday', m[0].length];
  if((m = /^(?:in )?(?:the )?(?:last|past|previous) (\d+) ?(minutes?|mins?|hours?|hrs?|h|days?|d|weeks?|w|months?|years?)\b/.exec(s))){ const u = NLQ_UNIT[m[2].replace(/s$/, '')] || NLQ_UNIT[m[2]]; return [now - +m[1] * u, now, 'last ' + m[1] + ' ' + m[2], m[0].length]; }
  if((m = /^(?:in )?(?:the )?(?:last|past|previous) (24 ?h(?:ours)?|hour|day|week|month|year)\b/.exec(s))){ const u = /24/.test(m[1]) ? 864e5 : NLQ_UNIT[m[1]]; return [now - u, now, 'last ' + m[1], m[0].length]; }
  if((m = /^this (week|month|year)\b/.exec(s))){ const d = new Date(now); if(m[1] === 'week'){ d.setDate(d.getDate() - ((d.getDay() + 6) % 7)); } else if(m[1] === 'month') d.setDate(1); else d.setMonth(0, 1); d.setHours(0, 0, 0, 0); return [+d, now, 'this ' + m[1], m[0].length]; }
  if((m = /^(?:since|after) (\d{4}-\d{2}-\d{2})\b/.exec(s))){ const t = Date.parse(m[1]); if(t) return [t, now, 'since ' + m[1], m[0].length]; }
  if((m = /^before (\d{4}-\d{2}-\d{2})\b/.exec(s))){ const t = Date.parse(m[1]); if(t) return [0, t, 'before ' + m[1], m[0].length]; }
  if((m = /^(?:on )?(\d{4}-\d{2}-\d{2})\b/.exec(s))){ const t = Date.parse(m[1]); if(t) return [t, t + 864e5, m[1], m[0].length]; }
  if((m = new RegExp('^(?:in |during )?(' + NLQ_MONTH.join('|') + ')(?: (\\d{4}))?\\b').exec(s))){ const y = m[2] ? +m[2] : new Date(now).getFullYear() - (NLQ_MONTH.indexOf(m[1]) > new Date(now).getMonth() ? 1 : 0); const a = new Date(y, NLQ_MONTH.indexOf(m[1]), 1);
    return [+a, +new Date(y, NLQ_MONTH.indexOf(m[1]) + 1, 1), m[1] + ' ' + y, m[0].length]; }
  return null;
}

function nlqParse(q){
  const raw = String(q || '').trim(); if(!raw || raw.length > 300) return null;
  const F = {kinds:null}, chips = [], rest = []; let s = raw.toLowerCase().replace(/\s+/g, ' '), orig = raw.replace(/\s+/g, ' ');
  const chip = (t, key) => chips.push({t, key}), hosts = new Set(DB.records.map(r => (r.host || '').toLowerCase()).filter(Boolean));
  while(s.length){
    s = s.replace(/^[\s,?.!]+/, ''); orig = orig.slice(orig.length - s.length); if(!s) break; let m, t;
    /* a value: "related to / talks to / linked to X" */
    if((m = /^(?:related to|connected to|linked to|talk(?:s|ing)? to|communicat(?:es|ing) with|associated with|near|around|with) (\S+)/.exec(s))){ const x = iocNorm(orig.slice(m[0].length - m[1].length, m[0].length)) || (iocNorm(m[1]));
      if(x){ F.rel = x; chip('related to ' + x.v, 'rel'); s = s.slice(m[0].length); continue; } }
    if((m = /^(?:what|which|who) (?:talks to|connects to|is related to|touches|links to|resolves to|points to) (\S+)/.exec(s))){ const x = iocNorm(orig.slice(m[0].length - m[1].length, m[0].length)); if(x){ F.rel = x; chip('related to ' + x.v, 'rel'); s = s.slice(m[0].length); continue; } }
    /* registration */
    if((m = /^(?:newly |recently )?registered\b ?/.exec(s))){ s = s.slice(m[0].length); const T = nlqTime(s) || (/^recently\b/.test(m[0]) ? [Date.now() - 30 * 864e5, Date.now(), 'last 30 days', 0] : null);
      F.reg = T ? [T[0], T[1]] : [Date.now() - 30 * 864e5, Date.now()]; chip('registered ' + (T ? T[2] : 'in the last 30 days'), 'reg'); if(T) s = s.slice(T[3]); F.kinds = F.kinds || new Set(['domain']); continue; }
    if((m = /^(?:new|young|fresh) domains?\b/.exec(s))){ F.reg = [Date.now() - 30 * 864e5, Date.now()]; F.kinds = new Set(['domain']); chip('domains', 'kinds'); chip('registered in the last 30 days', 'reg'); s = s.slice(m[0].length); continue; }
    /* time of sighting */
    if((t = nlqTime(s.replace(/^(?:seen |observed |active )/, '')))){ const off = s.length - s.replace(/^(?:seen |observed |active )/, '').length; F.when = [t[0], t[1]]; chip('seen ' + t[2], 'when'); s = s.slice(off + t[3]); continue; }
    /* verdicts and states */
    if((m = /^(malicious|bad|evil|hostile)\b/.exec(s))){ F.verdict = 'malicious'; chip('malicious', 'verdict'); s = s.slice(m[0].length); continue; }
    if((m = /^(suspicious|sus|dodgy|shady)\b/.exec(s))){ F.verdict = 'suspicious'; chip('suspicious', 'verdict'); s = s.slice(m[0].length); continue; }
    if((m = /^(benign|clean|safe|good|legit(?:imate)?)\b/.exec(s))){ F.verdict = 'benign'; chip('benign', 'verdict'); s = s.slice(m[0].length); continue; }
    if((m = /^(unjudged|without a verdict|with no verdict|no verdict|unknown|undecided|not judged)\b/.exec(s))){ F.verdict = 'none'; chip('no verdict', 'verdict'); s = s.slice(m[0].length); continue; }
    if((m = /^(flagged|risky|high[- ]risk|dangerous)\b/.exec(s))){ F.flagged = true; chip('flagged by live lookups', 'flagged'); s = s.slice(m[0].length); continue; }
    if((m = /^(unchecked|not checked|never checked|not looked up)\b/.exec(s))){ F.unchecked = true; chip('not checked online', 'unchecked'); s = s.slice(m[0].length); continue; }
    if((m = /^(checked|looked up)\b/.exec(s))){ F.checked = true; chip('checked online', 'checked'); s = s.slice(m[0].length); continue; }
    if((m = /^(watched|on (?:the|my) watchlist|in (?:the|my) watchlist|watchlist)\b/.exec(s))){ F.watched = true; chip('watched', 'watched'); s = s.slice(m[0].length); continue; }
    if((m = /^(in (?:my |the |our )?(?:threat )?feeds?|known bad|in threat intel)\b/.exec(s))){ F.feeds = true; chip('in your threat feeds', 'feeds'); s = s.slice(m[0].length); continue; }
    if((m = /^((?:actively |known )?exploited|in kev|kev)\b/.exec(s))){ F.kev = true; F.kinds = F.kinds || new Set(['cve']); chip('known exploited', 'kev'); s = s.slice(m[0].length); continue; }
    if((m = /^(in (?:more than one|several|multiple|other) cases|cross-?case|shared between cases|in \d+\+? cases)\b/.exec(s))){ F.multi = true; chip('in more than one case', 'multi'); s = s.slice(m[0].length); continue; }
    if((m = /^(tor|tor exits?|tor nodes?)\b/.exec(s))){ F.tor = true; chip('Tor relays', 'tor'); s = s.slice(m[0].length); continue; }
    /* kinds */
    const two = s.split(' ').slice(0, 2).join(' '), one = s.split(' ')[0];
    const K = NLQ_KIND.find(([re]) => re.test(two)) ? [NLQ_KIND.find(([re]) => re.test(two)), two] : NLQ_KIND.find(([re]) => re.test(one)) ? [NLQ_KIND.find(([re]) => re.test(one)), one] : null;
    if(K){ F.kinds = new Set([...(F.kinds && F.kinds.size < 6 && !chips.some(c => c.key === 'reg' || c.key === 'kev') ? F.kinds : []), ...K[0][1]]); chip(K[0][2], 'kinds'); s = s.slice(K[1].length); continue; }
    /* where */
    if((m = /^port (\d{1,5})\b/.exec(s)) || (m = /^on port (\d{1,5})\b/.exec(s))){ F.port = +m[1]; chip('port ' + m[1], 'port'); s = s.slice(m[0].length); continue; }
    if((m = /^(?:hosted (?:on|by|at)|on|at|owned by) (as\d+|[a-z0-9][\w.-]{1,40})\b/.exec(s)) && (/^as\d+$/.test(m[1]) || !hosts.has(m[1]) && /hosted|owned/.test(m[0]))){ F.net = m[1]; chip('network ' + m[1].toUpperCase().replace(/^AS/, 'AS'), 'net'); s = s.slice(m[0].length); continue; }
    if((m = /^(?:on|from|at) (?:host )?(\S+)/.exec(s)) && hosts.has(m[1])){ F.host = m[1]; chip('on ' + orig.slice(m[0].length - m[1].length, m[0].length), 'host'); s = s.slice(m[0].length); continue; }
    if((m = /^(as\d{1,10})\b/.exec(s))){ F.net = m[1]; chip('network ' + m[1].toUpperCase(), 'net'); s = s.slice(m[0].length); continue; }
    { const cn = Object.keys(NLQ_COUNTRY).sort((a, b) => b.length - a.length).find(n => s.startsWith('in ' + n) && /^(\W|$)/.test(s.slice(3 + n.length)) || s.startsWith('from ' + n) && /^(\W|$)/.test(s.slice(5 + n.length)));
      if(cn){ F.country = NLQ_COUNTRY[cn]; chip('in ' + cn.replace(/\b\w/g, c => c.toUpperCase()), 'country'); s = s.slice(s.indexOf(cn) + cn.length); continue; } }
    if((m = /^(?:in |case )?(\S+)/.exec(s))){ const w = m[1], c = DB.cases.find(c => c.code.toLowerCase() === w || (w.length >= 4 && /^(in|case) /.test(m[0]) && c.name.toLowerCase().split(/\W+/).includes(w)));
      if(c){ F.caseId = c.id; chip('in ' + c.code, 'case'); s = s.slice(m[0].length); continue; } }
    if((m = /^(riskiest|most dangerous|worst|top)\b/.exec(s))){ F.sort = 'risk'; chip('riskiest first', 'sort'); s = s.slice(m[0].length); continue; }
    if((m = /^(most seen|most common|most mentioned|busiest)\b/.exec(s))){ F.sort = 'seen'; chip('most seen first', 'sort'); s = s.slice(m[0].length); continue; }
    if((m = /^(newest|latest|most recent|recent)\b/.exec(s))){ F.sort = 'new'; chip('newest first', 'sort'); s = s.slice(m[0].length); continue; }
    const w = (/^\S+/.exec(s) || [''])[0]; if(!NLQ_STOP.has(w)) rest.push(w); s = s.slice(w.length);
  }
  return chips.length ? {F, chips, rest} : null;
}

function nlqRun(N){
  const {F} = N, G = globalEnts(), H = typeof cpHist === 'function' ? cpHist() : new Map(), keys = new Map();
  for(const [id, g] of G) keys.set(id, g);
  for(const e of DB.entries){ const k = entryKey(e); if(k && !keys.has(k)) keys.set(k, {k:entSplit(k).k, v:entSplit(k).v, recs:[], cases:new Set([e.caseId])}); }
  let rel = null; if(F.rel){ const key = F.rel.k + ':' + F.rel.v; rel = new Set();
    for(const r of DB.records) if((r.ents || []).some(e => e.k + ':' + e.v === key)) for(const e of r.ents) rel.add(e.k + ':' + e.v);
    const ids = DB.entries.filter(e => entryKey(e) === key).map(e => e.id); for(const l of DB.links) if(ids.includes(l.a) || ids.includes(l.b)){ for(const x of [l.a, l.b]){ const e = entryById(x); const k = e && entryKey(e); if(k) rel.add(k); } }
    const h = typeof lkKnown === 'function' && lkKnown(F.rel.k, F.rel.v); if(h) for(const x of lkRelated(h)) rel.add(x.k + ':' + x.v); rel.delete(key); }
  const attrs = (k, v) => typeof lkKnown === 'function' ? lkMerge(lkKnown(k, v)) : {};
  const out = [];
  for(const [id, g] of keys){
    const k = g.k, v = g.v; if(F.kinds && !F.kinds.has(k)) continue; if(typeof CE_SKIP !== 'undefined' && CE_SKIP.has(k) && !(F.kinds && F.kinds.has(k))) continue;
    if(rel && !rel.has(id)) continue;
    const vd = verdictOf(id) || (DB.entries.find(e => entryKey(e) === id) ? entryVerdict(DB.entries.find(e => entryKey(e) === id)) : '');
    if(F.verdict === 'none' ? !!vd : F.verdict && vd !== F.verdict) continue;
    const h = H.get(id);
    if(F.flagged && !(h && /malicious|suspicious/.test(h.band))) continue; if(F.unchecked && h) continue; if(F.checked && !h) continue;
    if(F.watched && !isWatched(id)) continue;
    if(F.feeds){ const i = typeof CTI !== 'undefined' && CTI.iocIx && CTI.iocIx.get(id); if(!(i && iocLive(i))) continue; }
    if(F.kev && !(k === 'cve' && kevOf(v.toUpperCase()))) continue;
    if(F.multi && g.cases.size < 2) continue;
    if(F.caseId && !g.cases.has(F.caseId)) continue;
    let recs = g.recs; if(F.caseId) recs = recs.filter(r => r.caseId === F.caseId); if(F.host) recs = recs.filter(r => (r.host || '').toLowerCase() === F.host);
    if(F.host && !recs.length) continue;
    if(F.when){ recs = recs.filter(r => r.ts && r.ts >= F.when[0] && r.ts < F.when[1]); if(!recs.length) continue; }
    let A = null; const need = F.reg || F.country || F.net || F.tor || (F.port && k !== 'hostport');
    if(need){ A = attrs(k, v); if(F.reg && !(A.created && A.created >= F.reg[0] && A.created < F.reg[1])) continue;
      if(F.country && (A.country || '').toUpperCase() !== F.country) continue;
      if(F.net){ const n = F.net.toLowerCase(); if(!((A.asn || '').toLowerCase() === n || [A.asname, A.org, A.isp, A.netname].some(x => x && x.toLowerCase().includes(n)))) continue; }
      if(F.tor && !A.tor) continue; }
    if(F.port){ if(k === 'hostport'){ if(+v.slice(v.lastIndexOf(':') + 1) !== F.port) continue; } else if(!(A.ports || []).includes(F.port)) continue; }
    const last = Math.max(0, ...recs.map(r => r.ts || 0));
    out.push({id, k, v, vd, h, n:recs.length || g.recs.length, cases:g.cases, last, A});
  }
  /* "riskiest" by default: what you or the sources judged worst, then most seen */
  const vr = {malicious:3, suspicious:2, '':1, benign:0}, rk = x => (vr[x.vd || ''] || 0) * 100 + (x.h ? x.h.score : 0);
  out.sort(F.sort === 'seen' ? (a, b) => b.n - a.n : F.sort === 'new' ? (a, b) => b.last - a.last : (a, b) => rk(b) - rk(a) || b.n - a.n);
  return out;
}

/* search-box integration: a "Smart results" group above the ordinary matches */
function nlqGroup(q){
  const N = nlqParse(q); if(!N) return null;
  /* a single word that is also ordinary text ("malicious") still searches normally below; the smart group needs something concrete */
  if(N.chips.length === 1 && N.chips[0].key === 'verdict' && !N.rest.length && q.trim().split(/\s+/).length === 1) return null;
  if(N.rest.length > 2) return null;
  const L = nlqRun(N);
  return {N, total:L.length, items:L.slice(0, 40).map(x => { const c = [...x.cases].map(theCase).filter(Boolean);
    return {kind:'ent', id:x.id, title:x.v, mono:true, icon:'crosshair', sub:(E.LABEL[x.k] || x.k) + ' · ' + (x.vd ? x.vd : 'no verdict') + (x.h ? ' · live ' + x.h.score : '') + ' · ' + x.n + ' sighting' + (x.n === 1 ? '' : 's') + (x.last ? ' · last ' + E.fmtDate(x.last, tz()) : '') + (c.length ? ' · ' + c.map(z => z.code).join(', ') : ''), text:'', w:0, caseId:c.length === 1 ? c[0].id : null}; })};
}
