/* ==========================================================================
   Threat intelligence engine — everything behind the Threat Intel screens.
   · Reads articles for CVEs, ATT&CK techniques, threat actors, malware, vendors and indicators.
   · Groups the same story from several sources into one.
   · Vulnerabilities: CISA Known Exploited (bundled snapshot, live refresh optional), FIRST EPSS, NVD CVSS.
   · An indicator store with TLP, confidence, first/last seen and expiry; imports STIX 2.1, MISP, CSV,
     ThreatFox / Feodo exports and plain lists; exports STIX 2.1, MISP and CSV.
   Every live source is off until switched on, and each names the one host it contacts.
   Everything that comes in is untrusted: values are re-validated by the indicator extractor,
   strings are capped, HTML is stripped, and output is escaped where it is drawn.
   ========================================================================== */
const CTI = {iocs:null, kev:null, kevLive:null, ready:null, x:new Map()};
const CTI_IOC_MAX = 50000, CTI_IN_MAX = 50 * 1048576;
const TLP = ['clear', 'green', 'amber', 'amber+strict', 'red'];
const TLP_STIX = {clear:'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9', green:'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da',
  amber:'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82', 'amber+strict':'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82', red:'marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed'};
const STIX_TLP = Object.fromEntries(Object.entries(TLP_STIX).filter(([k]) => k !== 'amber+strict').map(([k, v]) => [v, k]));
const cap = (s, n) => String(s == null ? '' : s).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '').trim().slice(0, n);

/* ---------- data sources: each one off until you turn it on ---------- */
const CTI_SOURCES = [
  {id:'kev', kind:'kev', name:'CISA Known Exploited Vulnerabilities', host:'raw.githubusercontent.com', url:'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json',
   about:'The official list of vulnerabilities attackers are exploiting. A snapshot ships with OSINTrix; turning this on fetches the latest catalog (about 2 MB) when you refresh.'},
  {id:'epss', kind:'epss', name:'FIRST EPSS exploit prediction', host:'api.first.org', url:'https://api.first.org/data/v1/epss',
   about:'The probability a CVE is exploited in the next 30 days. Only the CVE IDs you look at are sent.'},
  {id:'nvd', kind:'nvd', name:'CVE records (CVE.org + CISA enrichment)', host:'cveawg.mitre.org', url:'https://cveawg.mitre.org/api/cve/',
   about:'The official CVE record — description, CVSS score from the issuing CNA, CWE, affected products and CISA\'s exploitation assessment — one CVE at a time. With a relay set up, NVD fills in scores the record lacks.'},
  {id:'attack', kind:'attack', name:'MITRE ATT&CK Enterprise', host:'raw.githubusercontent.com', url:'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json',
   about:'Groups, software and techniques used to recognise adversaries in the news. A copy ships with OSINTrix; turning this on fetches the latest release (about 45 MB, checked at most once a week) and keeps it in this browser.'},
  {id:'tfx', kind:'ioc', fmt:'threatfox', name:'abuse.ch ThreatFox — recent IOCs', host:'threatfox.abuse.ch', url:'https://threatfox.abuse.ch/export/json/recent/',
   about:'Indicators for malware and C2 seen in the last 48 hours. abuse.ch does not allow browser access, so this is fetched through your relay (Sources → Lookups), which holds the Auth-Key.', relay:'threatfox-export/export/json/recent/'},
  {id:'feodo', kind:'ioc', fmt:'feodo', name:'abuse.ch Feodo Tracker — botnet C2 IPs', host:'feodotracker.abuse.ch', url:'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json',
   about:'Command-and-control servers of botnets such as Emotet, QakBot and Pikabot. Fetched through your relay.', relay:'feodo/downloads/ipblocklist_recommended.json'},
  {id:'urlhaus', kind:'ioc', fmt:'csv', name:'abuse.ch URLhaus — recent malware URLs', host:'urlhaus.abuse.ch', url:'https://urlhaus.abuse.ch/downloads/csv_recent/',
   about:'URLs that served malware recently. Fetched through your relay.', relay:'urlhaus-export/downloads/csv_recent/'},
];
/* more news sources you can switch on; the first six (in intel.js) are the classics */
const MORE_NEWS = [
  ['CISA advisories','https://www.cisa.gov/cybersecurity-advisories/all.xml'], ['NCSC UK','https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml'],
  ['Cisco Talos','https://blog.talosintelligence.com/rss/'], ['Unit 42','https://unit42.paloaltonetworks.com/feed/'], ['Securelist (Kaspersky)','https://securelist.com/feed/'],
  ['Check Point Research','https://research.checkpoint.com/feed/'], ['The DFIR Report','https://thedfirreport.com/feed/'], ['SecurityWeek','https://www.securityweek.com/feed/'],
  ['Dark Reading','https://www.darkreading.com/rss.xml'], ['Microsoft Security Response Center','https://msrc.microsoft.com/blog/feed'],
];
function ctiEnsure(){
  DB.intel = DB.intel && typeof DB.intel === 'object' ? DB.intel : {};
  const I = DB.intel; I.sources = Array.isArray(I.sources) ? I.sources : []; I.stack = Array.isArray(I.stack) ? I.stack : []; I.cve = I.cve && typeof I.cve === 'object' ? I.cve : {};
  for(const s of CTI_SOURCES) if(!I.sources.some(x => x.id === s.id)) I.sources.push({id:s.id, on:false, status:'', err:'', last:0, n:0, key:''});
  if(!CTI.kev) ctiKevIndex();
  if(!DB.feedSources) DB.feedSources = DEFAULT_SOURCES.map(s => ({...s}));
  if(!I.newsAdded){ I.newsAdded = true; for(const [name, url] of MORE_NEWS) if(!DB.feedSources.some(s => s.url === url)) DB.feedSources.push({id:uid('s'), name, url, on:false, status:'', last:0}); }
  return I;
}
/* a built-in source's address and host are fixed: stored state can only carry on/off, status and key */
const ctiSrc = id => { const meta = CTI_SOURCES.find(s => s.id === id), st = (DB.intel.sources || []).find(s => s.id === id) || {}; if(!meta) return st.custom ? {...st} : null;
  return {...meta, on:!!st.on, status:st.status || '', err:st.err || '', last:+st.last || 0, n:+st.n || 0, key:st.key || '', id:meta.id}; };
async function ctiFetch(url, opts = {}){
  const ctl = new AbortController(), to = setTimeout(() => ctl.abort(), opts.timeout || 20000);
  try{
    const res = await fetch(url, {signal:ctl.signal, credentials:'omit', referrerPolicy:'no-referrer', cache:'no-store', headers:opts.headers || {}});
    if(!res.ok) throw new Error('HTTP ' + res.status + (res.status === 401 || res.status === 403 ? ' — this source needs an API key or refused the request' : ''));
    const max = opts.max || CTI_IN_MAX, len = +res.headers.get('content-length') || 0; if(len > max) throw new Error('Response is over ' + Math.round(max / 1048576) + ' MB');
    const buf = await res.arrayBuffer(); if(buf.byteLength > max) throw new Error('Response is over ' + Math.round(max / 1048576) + ' MB');
    return new TextDecoder().decode(buf);
  }catch(e){
    if(e.name === 'AbortError') throw new Error('Timed out');
    if(e instanceof TypeError) throw new Error('Blocked — the site does not allow browser access (CORS) or you are offline. Download the file and use Import instead.');
    throw e;
  }finally{ clearTimeout(to); }
}
const ctiJSON = t => { try{ return JSON.parse(t); }catch(e){ throw new Error('Not valid JSON'); } };

/* ---------- storage: the indicator store and the live KEV catalog live in IndexedDB ---------- */
async function ctiLoad(){
  if(CTI.ready) return CTI.ready;
  CTI.ready = (async () => {
    try{ const raw = STORE.idb && await IDB.get('cti:iocs'); const arr = raw ? JSON.parse(await openStr(raw)) : []; CTI.iocs = Array.isArray(arr) ? arr : []; }catch(e){ CTI.iocs = []; }
    try{ const raw = STORE.idb && await IDB.get('cti:kev'); CTI.kevLive = raw ? JSON.parse(raw) : null; }catch(e){ CTI.kevLive = null; }
    try{ const raw = STORE.idb && await IDB.get('cti:attack'); const A = raw ? JSON.parse(raw) : null; if(A && ctiAttackOk(A)) ctiAttackUse(A); }catch(e){}
    ctiKevIndex(); ctiIocIndex(); return true;
  })();
  return CTI.ready;
}
async function ctiSaveIocs(){ if(!STORE.idb || !CTI.iocs) return false; return IDB.set('cti:iocs', await sealStr(JSON.stringify(CTI.iocs))); }

/* ---------- CISA KEV ---------- */
function ctiKevIndex(){
  const src = CTI.kevLive && Array.isArray(CTI.kevLive.rows) ? CTI.kevLive : (typeof KEV_SNAPSHOT !== 'undefined' ? KEV_SNAPSHOT : {rows:[]});
  const m = new Map(); for(const r of src.rows) m.set(r[0], {cve:r[0], vendor:r[1], product:r[2], name:r[3], added:r[4], due:r[5], ransom:!!r[6], desc:r[7], cwe:r[8] || ''});
  CTI.kev = m; CTI.kevMeta = {v:src.v || '', at:src.at || '', live:!!CTI.kevLive, n:m.size};
  CTI.vendors = null; CTI.x.clear();
}
const kevOf = cve => CTI.kev ? CTI.kev.get(String(cve).toUpperCase()) || null : null;
async function ctiRefreshKev(){
  const s = ctiSrc('kev');
  const j = ctiJSON(await ctiFetch(s.url, {timeout:45000}));
  if(!j || !Array.isArray(j.vulnerabilities)) throw new Error('That is not the KEV catalog');
  const rows = j.vulnerabilities.filter(v => /^CVE-\d{4}-\d{4,}$/.test(v.cveID)).slice(0, 20000).map(v => [v.cveID, cap(v.vendorProject, 80), cap(v.product, 120), cap(v.vulnerabilityName, 200),
    cap(v.dateAdded, 10), cap(v.dueDate, 10), v.knownRansomwareCampaignUse === 'Known' ? 1 : 0, cap(v.shortDescription, 220), (Array.isArray(v.cwes) ? v.cwes : []).map(c => cap(c, 20)).join(',')]);
  CTI.kevLive = {v:cap(j.catalogVersion, 20), at:cap(j.dateReleased, 40), rows}; await IDB.set('cti:kev', JSON.stringify(CTI.kevLive)); ctiKevIndex();
  return rows.length;
}
/* ---------- MITRE ATT&CK, live: the same compaction as tools/make_intel_data.py ---------- */
const ATTACK_SHIP = typeof ATTACK !== 'undefined' ? ATTACK.v : '';
const ctiAttackOk = A => A && typeof A.v === 'string' && Array.isArray(A.tactics) && Array.isArray(A.tech) && Array.isArray(A.groups) && Array.isArray(A.soft) && A.tech.length > 100;
function ctiAttackUse(A){ if(typeof ATTACK === 'undefined') return; Object.assign(ATTACK, {v:A.v, tactics:A.tactics, tech:A.tech, groups:A.groups, soft:A.soft}); ATTACK.live = A.at || Date.now(); CTI.dict = null; CTI.x = new Map(); }
function ctiAttackCompact(J){
  const ea = J && Array.isArray(J.objects) ? J.objects : null; if(!ea) throw new Error('That is not an ATT&CK bundle');
  const live = o => !o.revoked && !o.x_mitre_deprecated, ext = o => ((o.external_references || []).find(r => r.source_name === 'mitre-attack') || {}).external_id || null;
  const first = (d, n = 260) => { d = String(d || '').replace(/\(Citation:[^)]*\)/g, '').replace(/\[([^\]]+)\]\([^)]*\)/g, '$1').replace(/<[^>]+>/g, '').replace(/\n/g, ' ').trim(); const m = /^(.{40,}?[.!?])\s/.exec(d + ' '), x = m ? m[1] : d; return x.length > n ? x.slice(0, n - 1) + '…' : x; };
  const matrix = ea.find(o => o.type === 'x-mitre-matrix'); if(!matrix) throw new Error('No ATT&CK matrix in the bundle');
  const byid = new Map(ea.map(o => [o.id, o])), uses = new Map();
  const tactics = (matrix.tactic_refs || []).map(t => byid.get(t)).filter(Boolean).map(t => [cap(ext(t), 10), cap(t.x_mitre_shortname, 40), cap(t.name, 60)]);
  const tech = ea.filter(o => o.type === 'attack-pattern' && live(o) && ext(o)).map(o => [cap(ext(o), 12), cap(o.name, 120), (o.kill_chain_phases || []).filter(p => p.kill_chain_name === 'mitre-attack').map(p => cap(p.phase_name, 40))]).sort((a, b) => a[0] < b[0] ? -1 : 1);
  for(const r of ea) if(r.type === 'relationship' && r.relationship_type === 'uses' && live(r)){ if(!uses.has(r.source_ref)) uses.set(r.source_ref, new Set()); uses.get(r.source_ref).add(r.target_ref); }
  const refs = (id, typ) => [...new Set([...(uses.get(id) || [])].map(t => byid.get(t)).filter(t => t && typ.includes(t.type) && live(t) && ext(t)).map(ext))].sort();
  const groups = ea.filter(o => o.type === 'intrusion-set' && live(o) && ext(o)).map(o => ({id:cap(ext(o), 10), n:cap(o.name, 80), a:(o.aliases || []).filter(a => a !== o.name).map(a => cap(a, 80)).slice(0, 40), d:first(o.description), t:refs(o.id, ['attack-pattern']), s:refs(o.id, ['malware', 'tool'])}));
  const soft = ea.filter(o => (o.type === 'malware' || o.type === 'tool') && live(o) && ext(o)).map(o => ({id:cap(ext(o), 10), n:cap(o.name, 80), a:(o.x_mitre_aliases || []).filter(a => a !== o.name).map(a => cap(a, 80)).slice(0, 40), k:o.type === 'malware' ? 'm' : 't', d:first(o.description, 200)}));
  const by = (a, b) => a.n.toLowerCase() < b.n.toLowerCase() ? -1 : 1; groups.sort(by); soft.sort(by);
  return {v:'Enterprise ' + String(matrix.modified || '').slice(0, 10), tactics, tech, groups, soft, at:Date.now()};
}
async function ctiRefreshAttack(force){
  const last = ATTACK && ATTACK.live; if(!force && last && Date.now() - last < 7 * 864e5) return 0;
  const s = ctiSrc('attack'), A = ctiAttackCompact(ctiJSON(await ctiFetch(s.url, {timeout:120000, max:90 * 1048576})));
  if(!ctiAttackOk(A)) throw new Error('The ATT&CK release looks incomplete');
  if(STORE.idb) await IDB.set('cti:attack', JSON.stringify(A)); ctiAttackUse(A); return A.groups.length;
}
/* vendors and products known from KEV — the vocabulary for "my stack" */
function ctiVendors(){
  if(CTI.vendors) return CTI.vendors;
  const v = new Map(); for(const k of CTI.kev.values()){ const x = v.get(k.vendor) || {vendor:k.vendor, products:new Set(), n:0}; x.products.add(k.product); x.n++; v.set(k.vendor, x); }
  return (CTI.vendors = [...v.values()].sort((a, b) => b.n - a.n));
}

/* ---------- EPSS and NVD (on demand) ---------- */
async function ctiEpss(cves){
  const s = ctiSrc('epss'); if(!s.on) throw new Error('Turn on FIRST EPSS in Sources first');
  const L = [...new Set(cves.filter(c => /^CVE-\d{4}-\d{4,}$/.test(c)))].slice(0, 100); if(!L.length) return 0;
  const j = ctiJSON(await ctiFetch(s.url + '?cve=' + L.join(','))); let n = 0;
  for(const d of (j && Array.isArray(j.data) ? j.data : [])){ if(!/^CVE-\d{4}-\d{4,}$/.test(d.cve)) continue; const e = parseFloat(d.epss), p = parseFloat(d.percentile);
    if(!(e >= 0 && e <= 1)) continue; const c = DB.intel.cve[d.cve] = DB.intel.cve[d.cve] || {}; c.epss = e; c.pct = p >= 0 && p <= 1 ? p : null; c.epssAt = Date.now(); n++; }
  ctiSrcOk('epss', n); return n;
}
/* the CVE record from CVE.org (works from the browser); NVD through the relay fills a missing score */
async function ctiNvd(cve){
  const s = ctiSrc('nvd'); if(!s.on) throw new Error('Turn on CVE records in Sources first');
  if(!/^CVE-\d{4}-\d{4,}$/.test(cve)) throw new Error('Not a CVE ID');
  const r = await lkRun(lkProv('cveorg'), 'cve', cve, true); if(!r.ok) throw new Error(r.err); if(r.none) throw new Error('CVE.org has no record of ' + cve);
  const A = r.attrs || {}, c = DB.intel.cve[cve] = DB.intel.cve[cve] || {};
  c.cvss = A.cvss >= 0 && A.cvss <= 10 ? A.cvss : null; c.sev = cap(A.sev, 12); const vec = (r.facts.find(f => f[0] === 'Vector') || [])[1] || ''; c.vec = cap(vec, 200); c.ver = (/CVSS:(\d\.\d)/.exec(vec) || [])[1] || '';
  c.desc = cap(A.desc, 1200); c.pub = cap((r.facts.find(f => f[0] === 'Published') || [])[1], 30); c.cwe = (A.cwe || []).slice(0, 4); c.exploit = cap(A.exploitation, 20); c.refs = r.link ? [r.link] : [];
  if(c.cvss == null && lkRelay()){ const n = await lkRun(lkProv('nvd'), 'cve', cve, true); if(n.ok && n.attrs && n.attrs.nvdCvss != null){ c.cvss = n.attrs.nvdCvss; c.sev = cap((n.facts.find(f => f[0] === 'NVD CVSS') || [, ''])[1].split(' ')[1], 12); c.vec = cap((n.facts.find(f => f[0] === 'Vector') || [])[1], 200); } }
  c.nvdAt = Date.now(); ctiSrcOk('nvd', 1); return c;
}
function ctiSrcOk(id, n){ const s = DB.intel.sources.find(x => x.id === id); if(s){ s.status = 'ok'; s.err = ''; s.last = Date.now(); s.n = n; } }
function ctiSrcErr(id, e){ const s = DB.intel.sources.find(x => x.id === id); if(s){ s.status = 'error'; s.err = cap(e && e.message || e, 200); } }

/* ---------- reading an article: CVEs, techniques, actors, malware, vendors, indicators ---------- */
const CTI_STOP = new Set('at net ping cmd tor ftp dns arp ssh tasklist route systeminfo whoami reg xcopy expand certutil netsh schtasks bits page python powershell'.split(' '));
/* names that are ordinary words: only counted next to a word like ransomware, group or malware */
const CTI_GENERIC = new Set('admin@338 agenda anchor apostle at aurora biscuit bitter calendar cannon canopy carbon chaos covenant crimson cuba denis disco donut elise empire epic equation expand explosive ferocious flame havoc inception james karma kevin lv mango maze meek mercury meteor milan mirage monsoon mosquito net nickel nightclub ninja octopus page phosphorus photo ping platinum play plead plutonium pony potassium powerless prestige proton reaper reg reptile route rover royal ruler samurai scorpion shark silence silicon skid snake solar soldier spaceship spark tick tor trinity viper windshield zinc'.split(' '));
const CTI_CTX = /^(?:\s+[\p{L}\d-]+)?\s+(?:ransomware|group|gang|malware|backdoor|loader|trojan|botnet|actor|apt|rat|stealer|operators?|team|affiliates?|campaign|implant|wiper)\b|^['’]s\s+(?:ransomware|malware|operators|attacks?)/iu;
const CTI_PRE = /(?:ransomware|group|gang|actor|apt|malware|threat actor|operators? of|tracked as|known as|dubbed|called)\s+$/iu;
function ctiDict(){
  if(CTI.dict) return CTI.dict;
  const A = typeof ATTACK !== 'undefined' ? ATTACK : {groups:[], soft:[], tech:[], tactics:[]}, names = [];
  const add = (name, id, kind) => { const n = String(name || '').trim(); if(n.length < 4 || /^[a-z]+$/.test(n) && n.length < 6) return; if(kind === 't' && (CTI_STOP.has(n.toLowerCase()) || n.length < 6)) return; const l = n.toLowerCase(); names.push([l, id, kind, CTI_GENERIC.has(l)]); if(kind !== 'g'){ const base = l.replace(/\s+v?\d+\.\d+(\.\d+)*$/, ''); if(base !== l && base.length >= 5 && !CTI_GENERIC.has(base) && !names.some(x => x[0] === base)) names.push([base, id, kind, false]); } };
  for(const g of A.groups){ add(g.n, g.id, 'g'); g.a.forEach(a => add(a, g.id, 'g')); }
  for(const s of A.soft){ add(s.n, s.id, s.k); s.a.forEach(a => add(a, s.id, s.k)); }
  names.sort((a, b) => b[0].length - a[0].length);
  const tech = new Map(A.tech.map(t => [t[0], t])), grp = new Map(A.groups.map(g => [g.id, g])), soft = new Map(A.soft.map(s => [s.id, s]));
  return (CTI.dict = {names, tech, grp, soft});
}
const ctiWordAt = (t, i, len) => !/[\p{L}\p{N}_]/u.test(t[i - 1] || ' ') && !/[\p{L}\p{N}_]/u.test(t[i + len] || ' ');
function ctiFind(text){
  const D = ctiDict(), t = String(text || '').toLowerCase(), act = new Set(), mal = new Set();
  for(const [n, id, k, gen] of D.names){ let i = t.indexOf(n); while(i >= 0){
    if(ctiWordAt(t, i, n.length) && (!gen || CTI_CTX.test(t.slice(i + n.length, i + n.length + 40)) || CTI_PRE.test(t.slice(Math.max(0, i - 30), i)))){ (k === 'g' ? act : mal).add(id); break; }
    i = t.indexOf(n, i + 1); } }
  const ven = []; if(CTI.kev){ for(const v of ctiVendors().slice(0, 400)){ const n = v.vendor.toLowerCase(); if(n.length < 3) continue; const i = t.indexOf(n); if(i >= 0 && ctiWordAt(t, i, n.length)) ven.push(v.vendor); } }
  return {act:[...act], mal:[...mal], ven};
}
/* what an article is about, worked out once per article */
function ctiX(f){
  const key = f.id + ':' + (f.title || '').length + ':' + (f.body || '').length, hit = CTI.x.get(f.id); if(hit && hit.key === key) return hit;
  const text = f.title + ' ' + f.body, ex = E.extract(text), F = ctiFind(text);
  const x = {key, cve:[...new Set(ex.filter(e => e.k === 'cve').map(e => e.v.toUpperCase()))], ttp:[...new Set(ex.filter(e => e.k === 'ttp').map(e => e.v.toUpperCase()))],
    iocs:ex.filter(e => e.k !== 'cve' && e.k !== 'ttp'), act:F.act, mal:F.mal, ven:F.ven};
  x.kev = x.cve.filter(c => kevOf(c)); CTI.x.set(f.id, x); return x;
}
/* the same story from several sources: shared CVE or near-identical title within a few days */
const CTI_SW = new Set('the a an and or of to in on for with by from as at is are was were be been new how why what after over into its it this that their your you our we us vs via amid says said report reports update updates'.split(' '));
const ctiWords = s => new Set(String(s).toLowerCase().replace(/[^\p{L}\p{N}\s-]/gu, ' ').split(/\s+/).filter(w => w.length > 2 && !CTI_SW.has(w)));
function ctiStories(items){
  const n = items.length, par = items.map((_, i) => i), find = i => { while(par[i] !== i){ par[i] = par[par[i]]; i = par[i]; } return i; }, uni = (a, b) => { a = find(a); b = find(b); if(a !== b) par[b] = a; };
  const W = items.map(f => ctiWords(f.title)), X = items.map(ctiX), byCve = new Map();
  items.forEach((f, i) => X[i].cve.forEach(c => { if(!byCve.has(c)) byCve.set(c, []); byCve.get(c).push(i); }));
  for(const L of byCve.values()) if(L.length <= 12) for(let j = 1; j < L.length; j++) if(Math.abs(items[L[0]].ts - items[L[j]].ts) < 7 * 864e5) uni(L[0], L[j]);
  const order = items.map((_, i) => i).sort((a, b) => items[a].ts - items[b].ts);
  for(let a = 0; a < order.length; a++) for(let b = a + 1; b < order.length && items[order[b]].ts - items[order[a]].ts < 3 * 864e5; b++){
    const i = order[a], j = order[b]; if(items[i].source === items[j].source) continue; const A = W[i], B = W[j]; if(A.size < 3 || B.size < 3) continue;
    let s = 0; for(const w of A) if(B.has(w)) s++; if(s / Math.min(A.size, B.size) >= 0.6 && s >= 3) uni(i, j); }
  const groups = new Map(); items.forEach((f, i) => { const r = find(i); if(!groups.has(r)) groups.set(r, []); groups.get(r).push(f); });
  const sevN = f => f.sev === 'critical' ? 2 : f.sev === 'high' ? 1 : 0;
  return [...groups.values()].map(L => { L.sort((a, b) => sevN(b) - sevN(a) || b.body.length - a.body.length || a.ts - b.ts);
    return {lead:L[0], items:L, sources:[...new Set(L.map(f => f.source))], ts:Math.max(...L.map(f => f.ts))}; });
}

/* ---------- the indicator store ---------- */
const IOC_KINDS = ['ipv4', 'ipv6', 'hostport', 'domain', 'url', 'email', 'md5', 'sha1', 'sha256', 'sha512', 'cve', 'btc', 'eth', 'xmr', 'asn'];
/* a value is kept only if the extractor reads it back as exactly one indicator of a supported kind */
function iocNorm(v, hint){
  let s = cap(v, 2048); if(!s) return null;
  if(/^(ip-?src|ip-?dst|ip)$/i.test(hint || '') && /:\d+$/.test(s) && !/^\[/.test(s) && (s.match(/:/g) || []).length === 1) s = s.replace(/:\d+$/, '');
  const ex = E.extract(s).filter(e => IOC_KINDS.includes(e.k));
  if(!ex.length) return null;
  const whole = ex.find(e => e.v.toLowerCase() === s.toLowerCase().replace(/\[\.\]|\(\.\)/g, '.').replace(/^hxxp/i, 'http')) || (ex.length === 1 ? ex[0] : null);
  return whole ? {k:whole.k, v:whole.v} : null;
}
function ctiIocIndex(){ const m = new Map(); for(const x of CTI.iocs || []) m.set(x.k + ':' + x.v, x); CTI.iocIx = m; CTI.iocHitsAt = null; }
const ctiTlp = t => { const s = String(t || '').toLowerCase().replace(/^tlp[:\s-]*/, '').replace('white', 'clear').trim(); return TLP.includes(s) ? s : ''; };
/* add or merge; returns counts */
function ctiAddIocs(list, src){
  const now = Date.now(), out = {added:0, merged:0, bad:0};
  for(const it of list){
    const n = iocNorm(it.v, it.type); if(!n){ out.bad++; continue; }
    const key = n.k + ':' + n.v, ts = d => { const x = Date.parse(d); return x > 0 && x < now + 864e5 * 366 ? x : 0; };
    const first = ts(it.first) || now, last = ts(it.last) || first, exp = ts(it.exp) || 0;
    const tags = [...new Set((Array.isArray(it.tags) ? it.tags : String(it.tags || '').split(/[,;|]/)).map(t => cap(t, 64)).filter(Boolean))].slice(0, 20);
    const ex = CTI.iocIx.get(key);
    if(ex){ ex.last = Math.max(ex.last, last); ex.first = Math.min(ex.first, first); ex.tags = [...new Set([...ex.tags, ...tags])].slice(0, 30); if(!ex.srcs.includes(src)) ex.srcs.push(src);
      if(it.conf != null) ex.conf = Math.max(ex.conf || 0, Math.min(100, Math.max(0, +it.conf || 0))); if(exp) ex.exp = Math.max(ex.exp || 0, exp); const tl = ctiTlp(it.tlp); if(tl && TLP.indexOf(tl) > TLP.indexOf(ex.tlp)) ex.tlp = tl;
      if(!ex.desc && it.desc) ex.desc = cap(it.desc, 500); out.merged++; continue; }
    if(CTI.iocs.length >= CTI_IOC_MAX){ out.full = true; break; }
    const x = {id:uid('ioc'), k:n.k, v:n.v, srcs:Array.isArray(it.srcs) && it.srcs.length ? it.srcs.map(z => cap(z, 80)).filter(Boolean).slice(0, 10) : [cap(src, 80)], tlp:ctiTlp(it.tlp) || 'clear', conf:it.conf == null ? null : Math.min(100, Math.max(0, +it.conf || 0)), first, last, exp, tags,
      threat:cap(it.threat, 120), desc:cap(it.desc, 500), ref:E.safeUrl(it.ref) || '', added:now};
    CTI.iocs.push(x); CTI.iocIx.set(key, x); out.added++;
  }
  CTI.iocHitsAt = null; return out;
}
/* indicators from your feeds that also appear in your cases */
function ctiIocHits(){
  if(CTI.iocHitsAt === rev && CTI.iocHits) return CTI.iocHits;
  const g = globalEnts(), hits = []; if(CTI.iocIx) for(const [k, x] of CTI.iocIx) if(g.has(k) && !(x.exp && x.exp < Date.now())) hits.push({ioc:x, ent:g.get(k)});
  CTI.iocHitsAt = rev; return (CTI.iocHits = hits);
}
const iocLive = x => !(x.exp && x.exp < Date.now());

/* ---------- import: STIX 2.1, MISP, ThreatFox, Feodo, CSV, plain text ---------- */
const STIX_OBJ = {'ipv4-addr':'ip', 'ipv6-addr':'ip', 'domain-name':'domain', 'url':'url', 'email-addr':'email', 'autonomous-system':'asn'};
function stixPatternValues(p){
  const out = []; const re = /([a-z0-9-]+):([a-z0-9_.'-]+)\s*=\s*'((?:\\.|[^'\\]){1,2048})'/gi; let m, n = 0;
  while((m = re.exec(String(p).slice(0, 4000))) && n++ < 50){ const obj = m[1].toLowerCase(), path = m[2].toLowerCase(), val = m[3].replace(/\\(.)/g, '$1');
    if(obj === 'file' && !/hashes/.test(path)) continue; if(obj === 'autonomous-system'){ out.push({v:'AS' + val.replace(/^as/i, ''), type:'asn'}); continue; }
    out.push({v:val, type:STIX_OBJ[obj] || obj}); }
  return out;
}
function ctiParseStix(j){
  const objs = Array.isArray(j.objects) ? j.objects : Array.isArray(j) ? j : []; if(!objs.length) throw new Error('No STIX objects in that bundle');
  const byId = new Map(objs.filter(o => o && typeof o.id === 'string').map(o => [o.id, o])), marks = new Map();
  for(const o of objs) if(o && o.type === 'marking-definition'){ const t = STIX_TLP[o.id] || ctiTlp(o.name) || ctiTlp(o.definition && o.definition.tlp) || ctiTlp(o.extensions && JSON.stringify(o.extensions).match(/"tlp_2_0"\s*:\s*"([^"]+)"/)?.[1]); if(t) marks.set(o.id, t); }
  const tlpOf = o => { let best = ''; for(const r of (Array.isArray(o.object_marking_refs) ? o.object_marking_refs : [])){ const t = marks.get(r) || STIX_TLP[r] || ''; if(t && TLP.indexOf(t) > TLP.indexOf(best)) best = t; } return best; };
  /* what each indicator points at: malware, actor */
  const indicates = new Map(); for(const r of objs) if(r && r.type === 'relationship' && r.relationship_type === 'indicates'){ const t = byId.get(r.target_ref); if(t && t.name) (indicates.get(r.source_ref) || indicates.set(r.source_ref, []).get(r.source_ref)).push(cap(t.name, 64)); }
  const out = [];
  for(const o of objs){
    if(!o || typeof o !== 'object') continue;
    if(o.type === 'indicator' && (o.pattern_type || 'stix') === 'stix' && o.pattern){
      for(const pv of stixPatternValues(o.pattern)) out.push({...pv, first:o.valid_from || o.created, last:o.modified, exp:o.valid_until, conf:typeof o.confidence === 'number' ? o.confidence : null, tlp:tlpOf(o),
        tags:[...(Array.isArray(o.labels) ? o.labels : []), ...(Array.isArray(o.indicator_types) ? o.indicator_types : []), ...(indicates.get(o.id) || [])], threat:(indicates.get(o.id) || [])[0] || '', desc:o.name || o.description, ref:((o.external_references || [])[0] || {}).url});
    } else if(STIX_OBJ[o.type] && o.value) out.push({v:o.type === 'autonomous-system' ? 'AS' + o.number : o.value, type:STIX_OBJ[o.type], tlp:tlpOf(o)});
    else if(o.type === 'file' && o.hashes && typeof o.hashes === 'object') for(const h of Object.values(o.hashes)) out.push({v:h, type:'hash', tlp:tlpOf(o)});
    else if(o.type === 'vulnerability' && o.name) out.push({v:o.name, type:'cve', tlp:tlpOf(o), desc:o.description});
  }
  const name = (objs.find(o => o && o.type === 'report') || {}).name || '';
  return {items:out, name:cap(name, 120)};
}
const MISP_TYPES = /^(ip-src|ip-dst|ip-src\|port|ip-dst\|port|domain|hostname|domain\|ip|url|uri|link|email|email-src|email-dst|md5|sha1|sha256|sha512|filename\|md5|filename\|sha1|filename\|sha256|vulnerability|btc|AS)$/;
function ctiParseMisp(j){
  const evs = Array.isArray(j) ? j.map(x => x.Event || x) : j.response ? (Array.isArray(j.response) ? j.response : [j.response]).map(x => x.Event || x) : [j.Event || j];
  const out = []; let name = '';
  for(const ev of evs.slice(0, 500)){
    if(!ev || typeof ev !== 'object') continue; name = name || cap(ev.info, 120);
    const evTags = (Array.isArray(ev.Tag) ? ev.Tag : []).map(t => cap(t && t.name, 64)), evTlp = evTags.map(ctiTlp).filter(Boolean).sort((a, b) => TLP.indexOf(b) - TLP.indexOf(a))[0] || '';
    const attrs = [...(Array.isArray(ev.Attribute) ? ev.Attribute : []), ...(Array.isArray(ev.Object) ? ev.Object.flatMap(o => Array.isArray(o && o.Attribute) ? o.Attribute : []) : [])];
    for(const a of attrs.slice(0, CTI_IOC_MAX)){
      if(!a || !MISP_TYPES.test(String(a.type || ''))) continue;
      let vals = String(a.value || '').split('|'); if(/^filename\|/.test(a.type)) vals = vals.slice(1); if(/\|port$/.test(a.type)) vals = vals.slice(0, 1);
      const tags = [...evTags.filter(t => !/^tlp:/i.test(t)), ...(Array.isArray(a.Tag) ? a.Tag : []).map(t => cap(t && t.name, 64))], tl = [...tags, ...evTags].map(ctiTlp).filter(Boolean).sort((x, y) => TLP.indexOf(y) - TLP.indexOf(x))[0] || evTlp;
      for(const v of vals) out.push({v, type:a.type, first:a.first_seen || (a.timestamp ? new Date(+a.timestamp * 1000).toISOString() : ev.date), last:a.last_seen, tags:tags.filter(t => !/^tlp:/i.test(t)), tlp:tl, desc:a.comment || ev.info, conf:a.to_ids === false ? 50 : null});
    }
  }
  return {items:out, name};
}
function ctiParseThreatFox(j){
  const rows = Array.isArray(j) ? j : Array.isArray(j.data) ? j.data : Object.values(j).flat(); const out = [];
  for(const r of rows.slice(0, CTI_IOC_MAX)) if(r && r.ioc_value) out.push({v:r.ioc_value, type:r.ioc_type, first:r.first_seen_utc || r.first_seen, last:r.last_seen_utc || r.last_seen, conf:r.confidence_level, threat:r.malware_printable,
    tags:[r.malware_printable, r.threat_type, ...(Array.isArray(r.tags) ? r.tags : String(r.tags || '').split(','))], ref:r.reference});
  return {items:out, name:'ThreatFox'};
}
function ctiParseFeodo(j){
  const rows = Array.isArray(j) ? j : []; return {items:rows.slice(0, CTI_IOC_MAX).filter(r => r && r.ip_address).map(r => ({v:r.ip_address, type:'ip', first:r.first_seen, last:r.last_online, threat:r.malware, tags:[r.malware, 'botnet C2', r.status === 'online' ? 'online' : ''], conf:r.status === 'online' ? 90 : 70})), name:'Feodo Tracker'};
}
function csvRows(text){
  const rows = []; let row = [], cell = '', q = false; const t = text.slice(0, CTI_IN_MAX);
  for(let i = 0; i < t.length; i++){ const c = t[i];
    if(q){ if(c === '"'){ if(t[i + 1] === '"'){ cell += '"'; i++; } else q = false; } else cell += c; continue; }
    if(c === '"' && cell === '') q = true; else if(c === ',') { row.push(cell); cell = ''; } else if(c === '\n' || c === '\r'){ if(c === '\r' && t[i + 1] === '\n') i++; row.push(cell); rows.push(row); row = []; cell = ''; if(rows.length > CTI_IOC_MAX + 10) break; } else cell += c; }
  if(cell || row.length){ row.push(cell); rows.push(row); } return rows;
}
function ctiParseCsv(text){
  const lines = text.split(/\r?\n/), comment = lines.filter(l => /^#/.test(l)), body = lines.filter(l => !/^#/.test(l) && l.trim()).join('\n');
  let rows = csvRows(body); if(!rows.length) return {items:[], name:''};
  /* URLhaus/ThreatFox keep the header in the last comment line */
  let head = rows[0].map(h => h.trim().toLowerCase());
  const lastC = comment.length ? comment[comment.length - 1].replace(/^#\s*/, '') : ''; if(lastC && /,/.test(lastC) && !head.some(h => /ioc|value|indicator|url|ip|domain|hash/.test(h))) head = csvRows(lastC)[0].map(h => h.trim().toLowerCase()); else rows = rows.slice(1);
  const col = re => head.findIndex(h => re.test(h));
  const vi = [col(/^(ioc_value|ioc|indicator|value|observable|url|ip_address|dst_ip|ip|domain|hash|sha256_hash|sha256|md5_hash|md5)$/), col(/ioc|indicator|value|url|ip|domain|hash/)].find(i => i >= 0);
  if(vi == null || vi < 0) return {items:text.split(/\r?\n/).slice(0, CTI_IOC_MAX).flatMap(l => /^#/.test(l) ? [] : E.extract(l).filter(e => IOC_KINDS.includes(e.k)).map(e => ({v:e.v}))), name:''};
  const ti = col(/^(ioc_type|type|indicator_type|kind)$/), fi = col(/first|dateadded|date_added|created/), li = col(/last|updated|modified/), ci = col(/confidence/), gi = col(/^(tags?|labels?|malware|malware_printable|threat|signature)$/), di = col(/desc|comment|threat_type|notes?/), ri = col(/reference|urlhaus_link|link|source_url/), pi = col(/^tlp$/);
  return {items:rows.slice(0, CTI_IOC_MAX).filter(r => r[vi]).map(r => ({v:r[vi], type:ti >= 0 ? r[ti] : '', first:fi >= 0 ? r[fi] : '', last:li >= 0 ? r[li] : '', conf:ci >= 0 && r[ci] !== '' ? +r[ci] : null,
    tags:gi >= 0 ? r[gi] : '', threat:gi >= 0 ? String(r[gi] || '').split(/[,;|]/)[0] : '', desc:di >= 0 ? r[di] : '', ref:ri >= 0 ? r[ri] : '', tlp:pi >= 0 ? r[pi] : ''})), name:''};
}
/* work out the format from the content */
function ctiParse(text, hint){
  if(text.length > CTI_IN_MAX) throw new Error('That is over 50 MB');
  const t = text.replace(/^\uFEFF/, '').trim();
  if(/^[\[{]/.test(t)){
    const j = ctiJSON(t);
    if(hint === 'threatfox') return {...ctiParseThreatFox(j), fmt:'ThreatFox JSON'};
    if(hint === 'feodo') return {...ctiParseFeodo(j), fmt:'Feodo JSON'};
    if(j && (j.type === 'bundle' || (Array.isArray(j.objects) && j.objects.some(o => o && /--/.test(o.id || ''))))) return {...ctiParseStix(j), fmt:'STIX 2.1'};
    if(j && (j.Event || j.response || (Array.isArray(j) && j[0] && (j[0].Event || j[0].Attribute)))) return {...ctiParseMisp(j), fmt:'MISP'};
    if(Array.isArray(j) && j[0] && j[0].ip_address) return {...ctiParseFeodo(j), fmt:'Feodo JSON'};
    if(j && (j.query_status || Object.values(j).some(v => Array.isArray(v) && v[0] && v[0].ioc_value)) || (Array.isArray(j) && j[0] && j[0].ioc_value)) return {...ctiParseThreatFox(j), fmt:'ThreatFox JSON'};
    throw new Error('JSON, but not STIX 2.1, MISP, ThreatFox or Feodo');
  }
  if(/,/.test(t.split(/\r?\n/).find(l => l.trim() && !/^#/.test(l)) || '')) return {...ctiParseCsv(t), fmt:'CSV'};
  return {items:t.split(/\r?\n/).slice(0, CTI_IOC_MAX * 2).flatMap(l => /^\s*#/.test(l) ? [] : E.extract(l).filter(e => IOC_KINDS.includes(e.k)).map(e => ({v:e.v}))), name:'', fmt:'Text list'};
}
async function ctiImportText(text, src, defaults = {}){
  await ctiLoad();
  const P = ctiParse(text, defaults.fmt);
  const items = P.items.map(x => ({...x, tlp:x.tlp || defaults.tlp, conf:x.conf == null ? defaults.conf : x.conf, tags:[...(Array.isArray(x.tags) ? x.tags : String(x.tags || '').split(/[,;|]/)), ...(defaults.tags || [])],
    exp:x.exp || (defaults.days ? new Date(Date.now() + defaults.days * 864e5).toISOString() : '')}));
  const r = ctiAddIocs(items, src || P.name || P.fmt); await ctiSaveIocs(); return {...r, fmt:P.fmt, total:P.items.length, name:P.name};
}
async function ctiRefreshIocFeed(id){
  const s = ctiSrc(id); const st = DB.intel.sources.find(x => x.id === id);
  const R = typeof lkRelay === 'function' && lkRelay();
  if(s.relay && !R) throw new Error('Needs your relay — abuse.ch does not allow browser access. Set it up in Sources → Lookups, or download the export and use Import.');
  const text = s.relay ? await ctiFetch(R.url.replace(/\/+$/, '') + '/' + s.relay, {headers:{'X-Relay-Token':R.token || ''}, timeout:45000}) : await ctiFetch(s.url, {timeout:45000});
  const r = await ctiImportText(text, s.name, {fmt:s.fmt, days:14}); ctiSrcOk(id, r.added + r.merged); return r;
}
function ctiPurgeExpired(){ const n0 = CTI.iocs.length, now = Date.now(); CTI.iocs = CTI.iocs.filter(x => !(x.exp && x.exp < now)); ctiIocIndex(); return n0 - CTI.iocs.length; }

/* ---------- export: STIX 2.1, MISP, CSV ---------- */
const stixKind = {ipv4:"ipv4-addr:value", ipv6:"ipv6-addr:value", domain:"domain-name:value", url:"url:value", email:"email-addr:value", md5:"file:hashes.MD5", sha1:"file:hashes.'SHA-1'", sha256:"file:hashes.'SHA-256'", sha512:"file:hashes.'SHA-512'"};
const stixEsc = v => String(v).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
const uuid = () => crypto.randomUUID ? crypto.randomUUID() : '10000000-1000-4000-8000-100000000000'.replace(/[018]/g, c => (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16));
function ctiStix(items, title, tlp){
  const now = new Date().toISOString(), idn = {type:'identity', spec_version:'2.1', id:'identity--' + uuid(), created:now, modified:now, name:'OSINTrix analyst', identity_class:'individual'};
  const objs = [idn], rep = [];
  for(const x of items){
    const t = ctiTlp(x.tlp) || tlp || 'clear', mark = TLP_STIX[t];
    if(x.k === 'cve'){ const o = {type:'vulnerability', spec_version:'2.1', id:'vulnerability--' + uuid(), created:now, modified:now, created_by_ref:idn.id, name:x.v, external_references:[{source_name:'cve', external_id:x.v}], object_marking_refs:[mark]}; objs.push(o); rep.push(o.id); continue; }
    const path = x.k === 'hostport' ? null : stixKind[x.k]; if(!path) continue;
    const o = {type:'indicator', spec_version:'2.1', id:'indicator--' + uuid(), created:now, modified:now, created_by_ref:idn.id, name:x.v, pattern:`[${path} = '${stixEsc(x.v)}']`, pattern_type:'stix',
      valid_from:new Date(x.first || Date.now()).toISOString(), indicator_types:['malicious-activity'], object_marking_refs:[mark]};
    if(x.exp) o.valid_until = new Date(x.exp).toISOString(); if(typeof x.conf === 'number') o.confidence = Math.round(x.conf); if(x.tags && x.tags.length) o.labels = x.tags.slice(0, 20); if(x.desc) o.description = x.desc;
    objs.push(o); rep.push(o.id);
  }
  if(rep.length) objs.push({type:'report', spec_version:'2.1', id:'report--' + uuid(), created:now, modified:now, created_by_ref:idn.id, name:title || 'OSINTrix export', published:now, report_types:['threat-report'], object_refs:rep, object_marking_refs:[TLP_STIX[tlp || 'clear']]});
  return {type:'bundle', id:'bundle--' + uuid(), objects:objs};
}
const MISP_OUT = {ipv4:'ip-dst', ipv6:'ip-dst', domain:'domain', url:'url', email:'email-src', md5:'md5', sha1:'sha1', sha256:'sha256', sha512:'sha512', cve:'vulnerability', btc:'btc', hostport:'ip-dst|port'};
function ctiMisp(items, title, tlp){
  const now = new Date();
  return {Event:{info:title || 'OSINTrix export', date:now.toISOString().slice(0, 10), threat_level_id:'2', analysis:'1', distribution:'0', uuid:uuid(), timestamp:String(Math.floor(now / 1000)),
    Tag:[{name:'tlp:' + (tlp || 'clear')}],
    Attribute:items.filter(x => MISP_OUT[x.k]).map(x => ({type:MISP_OUT[x.k], category:/md5|sha/.test(x.k) ? 'Payload delivery' : x.k === 'cve' ? 'External analysis' : 'Network activity', value:x.k === 'hostport' ? x.v.replace(':', '|') : x.v,
      to_ids:x.k !== 'cve', uuid:uuid(), comment:cap(x.desc || '', 500), timestamp:String(Math.floor((x.last || Date.now()) / 1000)), Tag:[...(x.tags || []).slice(0, 10).map(t => ({name:t})), ...(x.tlp ? [{name:'tlp:' + x.tlp}] : [])]}))}};
}
function ctiCsv(items){
  const head = ['type', 'value', 'tlp', 'confidence', 'first_seen', 'last_seen', 'expires', 'threat', 'tags', 'sources', 'description'];
  const d = t => t ? new Date(t).toISOString() : '';
  return [head.join(','), ...items.map(x => [x.k, x.v, x.tlp || '', x.conf == null ? '' : x.conf, d(x.first), d(x.last), d(x.exp), x.threat || '', (x.tags || []).join('|'), (x.srcs || []).join('|'), x.desc || ''].map(csvCell).join(','))].join('\n');
}
/* a case's indicators in the same shape as the store */
function ctiCaseItems(caseId){
  const D = derive(caseId), out = [], seen = new Set(), push = (k, v, extra) => { const key = k + ':' + v; if(seen.has(key) || !(MISP_OUT[k] || stixKind[k])) return; seen.add(key); out.push({k, v, tags:[], ...extra}); };
  for(const e of D.entries){ const key = entryKey(e); if(!key) continue; const s = entSplit(key); const verdict = entryVerdict(e); push(s.k, s.v, {desc:e.label || '', tags:verdict ? [verdict] : [], first:e.created}); }
  for(const [key, x] of D.ents) push(x.k, x.v, {first:Math.min(...x.recs.map(r => r.ts || r.addedAt || Date.now()))});
  return out;
}
