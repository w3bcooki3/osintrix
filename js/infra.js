/* ==========================================================================
   Infrastructure pivots — from results you paste (Analysis → Infrastructure).
   Recognises WHOIS text and RDAP JSON, dig / nslookup output, passive DNS
   (VirusTotal, SecurityTrails, CIRCL/DNSDB-style JSON, CSV), crt.sh JSON,
   Shodan and Censys host JSON. Each paste is kept as evidence; the facts in
   all of a case's evidence are joined into what the domains and addresses
   SHARE — a registrant, a certificate, a site-verification token, a favicon,
   a server fingerprint, an address, a name server — each said with how much
   it means: privacy services, big DNS and hosting providers and CDN
   addresses are shared by millions of strangers and are marked as such.
   Nothing is looked up: the work stays in this browser.
   ========================================================================== */
const IF_PRIVACY = /redacted|privacy|private|withheld|proxy|protect|whoisguard|perfect ?privacy|contact ?privacy|domains by proxy|data protected|not disclosed|gdpr|anonymi[sz]ed|identity shield|super privacy|whois agent|registration private|statutory masking|on behalf of|^n\/?a$|^none$|please query the rdds/i;
const IF_BIG_NS = /(^|\.)(cloudflare\.com|domaincontrol\.com|awsdns-\d+\.(com|net|org|co\.uk)|azure-dns\.(com|net|org|info)|googledomains\.com|google\.com|registrar-servers\.com|nsone\.net|dnsimple\.com|he\.net|digitalocean\.com|linode\.com|dnsmadeeasy\.com|ultradns\.(com|net|org|biz)|akam\.net|akamaiedge\.net|name-services\.com|hostgator\.com|bluehost\.com|siteground\.net|wixdns\.net|squarespacedns\.com|dynect\.net|namebrightdns\.com|porkbun\.com|gandi\.net|ovh\.net|hetzner\.(com|de)|ionos\.(com|de)|ui-dns\.(com|de|org|biz)|dns\.jp|yandex\.net|vercel-dns\.com|netlify\.com|afternic\.com|parkingcrew\.net|sedoparking\.com|bodis\.com|above\.com|dan\.com)$/i;
const IF_CDN = [['104.16.0.0', 12], ['172.64.0.0', 13], ['188.114.96.0', 20], ['162.158.0.0', 15], ['141.101.64.0', 18], ['108.162.192.0', 18], ['190.93.240.0', 20], ['198.41.128.0', 17], ['173.245.48.0', 20], ['103.21.244.0', 22], ['103.22.200.0', 22], ['131.0.72.0', 22], ['151.101.0.0', 16], ['199.232.0.0', 16], ['13.32.0.0', 15], ['13.224.0.0', 14], ['18.64.0.0', 14], ['52.84.0.0', 15], ['99.84.0.0', 16], ['143.204.0.0', 16], ['205.251.192.0', 19], ['23.235.32.0', 20], ['185.199.108.0', 22], ['76.76.21.0', 24]];
const ifIp4 = s => /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.test(s) && s.split('.').every(x => +x < 256);
const ifIpN = s => s.split('.').reduce((a, x) => a * 256 + +x, 0);
const ifCdn = ip => ifIp4(ip) && IF_CDN.some(([b, m]) => Math.floor(ifIpN(ip) / 2 ** (32 - m)) === Math.floor(ifIpN(b) / 2 ** (32 - m)));
const ifDom = s => { s = String(s || '').trim().toLowerCase().replace(/\.$/, '').replace(/^\*\./, ''); return /^(?=.{4,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$/.test(s) ? s : ''; };
const ifDate = s => { const t = s ? Date.parse(String(s).trim().replace(/^(\d{4}-\d{2}-\d{2}) (\d)/, '$1T$2').replace(/ UTC$/, 'Z')) : NaN; return isFinite(t) && t > 0 ? t : (/^\d{10}$/.test(String(s)) ? +s * 1000 : null); };
/* the kinds of thing two domains can share, and what sharing it means */
const IF_REL = {
  'registrant email':['strong', 'The same person or organisation registered both — unless it is a reseller'], 'registrant phone':['strong', 'The same registrant phone'], 'registrant name':['medium', 'The same registrant name'], 'registrant org':['medium', 'The same registrant organisation'],
  'contact email':['strong', 'The same admin or technical contact'], 'certificate':['strong', 'The same TLS certificate — whoever holds its key runs both'], 'site verification':['strong', 'The same verification token — the same Google, Microsoft or other account set both up'],
  'favicon':['medium', 'The same site icon — often the same kit or copied site'], 'SOA contact':['medium', 'The same DNS zone contact'], 'resolves to':['medium', 'Hosted on the same address'],
  'JARM':['weak', 'The same TLS server fingerprint — the same server software and settings, common on default set-ups'], 'name server':['weak', 'The same name servers'], 'mail server':['weak', 'The same mail server'], 'registrar':['weak', 'The same registrar'], 'network':['weak', 'The same network (ASN)'], 'hosting':['weak', 'The same hosting company'],
  'registered same day':['weak', 'Registered on the same day through the same registrar'],
};
/* ---------- parsers: text → {kind, label, facts:[{s, rel, v, vk, first, last}]} ---------- */
/* dates the way registries write them: 2008-03-26, 26.03.2008, 18.7.2012, 29-apr-2005, 2001-Aug-23, 20021030, Tue Feb 10 09:42:42 2004 */
const IF_MON = {jan:0, feb:1, mar:2, apr:3, may:4, jun:5, jul:6, aug:7, sep:8, oct:9, nov:10, dec:11};
function ifWDate(s){ s = String(s || '').trim().replace(/\s*\((?:YYYY-MM-DD|[A-Z]+)\)\s*$/, '').replace(/\.$/, ''); let m;
  const ok = (y, mo, d) => y > 1984 && y < 2100 && mo >= 0 && mo < 12 && d >= 1 && d <= 31 ? Date.UTC(y, mo, d) : null;
  if((m = s.match(/^(\d{4})[-\/.](\d{1,2})[-\/.](\d{1,2})/))) return ok(+m[1], m[2] - 1, +m[3]);
  if((m = s.match(/^(\d{1,2})[.\/-](\d{1,2})[.\/-](\d{4})/))) return ok(+m[3], m[2] - 1, +m[1]);
  if((m = s.match(/^(\d{4})-([A-Za-z]{3})-(\d{1,2})/)) && IF_MON[m[2].toLowerCase()] != null) return ok(+m[1], IF_MON[m[2].toLowerCase()], +m[3]);
  if((m = s.match(/^(\d{1,2})[- ]([A-Za-z]{3})[a-z]*[- ](\d{4})/)) && IF_MON[m[2].toLowerCase()] != null) return ok(+m[3], IF_MON[m[2].toLowerCase()], +m[1]);
  if((m = s.match(/^(\d{4})(\d{2})(\d{2})\b/))) return ok(+m[1], m[2] - 1, +m[3]);
  if((m = s.match(/^[A-Za-z]{3},?\s+([A-Za-z]{3})\s+(\d{1,2})\s+[\d:]+\s+(?:[A-Z]{3,4}\s+)?(\d{4})/)) && IF_MON[m[1].toLowerCase()] != null) return ok(+m[3], IF_MON[m[1].toLowerCase()], +m[2]);
  return null; }
/* WHOIS from any registry: "key: value", "key......: value", "[Key]  value", and sections whose values follow on indented lines */
function ifWhois(t){
  if(!/(domain|regist|nserver|name ?server|dominio)/i.test(t) || t.length > 1 << 20) return null;
  const lines = t.replace(/\r/g, '').split('\n').filter(l => !/^\s*[%#;>]/.test(l)), kv = [];
  const KEY = /^\s*(?:\*\*\s*|[a-z]\.\s+)?(?:\[([^\]]{2,40})\]\s+(\S.*)|([A-Za-z][A-Za-z0-9 _\/()'-]{0,48}?)\s*(?:\.{2,}\s*:?|:)\s*(.*))$/;
  for(let i = 0; i < lines.length; i++){ const m = lines[i].match(KEY); if(!m) continue; const k = (m[1] || m[3]).toLowerCase().replace(/[^a-z ]/g, ' ').replace(/\s+/g, ' ').trim(); let v = (m[2] || m[4] || '').trim();
    const sub = []; if(!v || /^\[?\s*\]?$/.test(v)){ v = ''; for(let j = i + 1; j < lines.length && j < i + 40; j++){ const l = lines[j]; if(!l.trim()) { if(sub.length) break; else continue; } if(!/^\s/.test(l) && KEY.test(l)) break; sub.push(l.trim()); } }
    kv.push({k, v, sub}); }
  const first = (re, f) => { for(const x of kv) if(re.test(x.k)){ const v = f ? f(x) : x.v; if(v) return v; } return ''; };
  const subVal = x => x.v || (x.sub.map(l => (l.match(/^(?:name|organi[sz]ation|org)\s*:\s*(.+)$/i) || [])[1]).find(Boolean) || (x.sub[0] && !/:\s/.test(x.sub[0]) ? x.sub[0] : '') || '').trim();
  let dom = ifDom(first(/^(domain name|domain|domainname|domain name ascii|nombre de dominio|dominio)$/, x => ((x.v || x.sub[0] || '').split(/\s+/)[0] || '')));
  if(!dom){ const m = t.match(/^\s*Domain\s+([A-Za-z0-9.-]+\.[A-Za-z]{2,})\s+\(/m); if(m) dom = ifDom(m[1]); }
  if(!dom) return null;
  const F = [], add = (rel, v, vk) => { v = String(v || '').replace(/\s+AT\s+/i, '@').trim(); if(v && v.length < 200 && !F.some(f => f.rel === rel && f.v === v)) F.push({s:dom, sk:'domain', rel, v, vk:vk || 'text'}); };
  const reg = first(/^(registrar|registrar name|sponsoring registrar|registrar organi[sz]ation|registrar name of registrar|current registar|current registrar|registration service provider)$/, subVal); if(reg && !/^(not available|n\/a|-)$/i.test(reg)) add('registrar', reg.replace(/^name:\s*/i, ''));
  for(const x of kv){
    if(/^registrant( contact)? name$/.test(x.k)) add('registrant name', x.v, 'name');
    else if(/^registrant( contact)? organi[sz]ation$|^registrant org$/.test(x.k)) add('registrant org', x.v, 'org');
    else if(/^registrant( contact)? e ?mail$/.test(x.k) && /@|\sAT\s/.test(x.v)) add('registrant email', x.v.toLowerCase(), 'email');
    else if(/^registrant( contact)? phone( number)?$/.test(x.k) && /\d{6}/.test(x.v.replace(/\D/g, ''))) add('registrant phone', x.v.replace(/[^\d+]/g, ''), 'phone');
    else if(/^(admin|administrative|tech|technical)( contact)? e ?mail$|^e mail$/.test(x.k) && /@|\sAT\s/i.test(x.v)) add('contact email', x.v.toLowerCase(), 'email');
    else if(/^(registrant|holder|owner)$/.test(x.k) && x.v && !/^\d+$/.test(x.v) && !/^[A-Z0-9]{3,}-[A-Z0-9]+$/.test(x.v)) add('registrant name', x.v, 'name'); }
  /* name servers: one per line, in a section, or after a dash; addresses after them are dropped */
  const ns = new Set(); for(const x of kv){ if(!/^(name ?servers?|nserver|dns|host name|domain servers?( in listed order)?|name servers? in (the )?listed order|nameservers? information)$/.test(x.k)) continue;
    for(const raw of [x.v, ...x.sub]){ const h = ifDom(String(raw).replace(/^[-*\s]+/, '').split(/[\s(\[]/)[0]); if(h) ns.add(h); } }
  for(const m of t.matchAll(/^\s*(?:Name servers in the listed order|Domain servers in listed order|Nameservers|Domain Servers)\s*:?\s*\n((?:[ \t]*[-*]?\s*[A-Za-z0-9.-]+\.[A-Za-z]{2,}.*\n?)+)/gim)) for(const l of m[1].split('\n')){ const h = ifDom(l.replace(/^[-*\s]+/, '').split(/[\s(\[]/)[0]); if(h) ns.add(h); }
  for(const n of [...ns].slice(0, 20)) add('name server', n, 'domain');
  /* the first creation-like date in the record: later ones belong to contacts and registrars */
  let cr = ifWDate(first(/^(creation date|domain registration date|registration date|registration time|registered date|registered on|registered|record created( on)?|fecha de creaci n|created on|created date|domain create date|domain created|domain name commencement date|activated|created|creation)$/)) ?? null;
  if(!cr){ const m = t.match(/Record created on\s+(\S+)/i) || t.match(/Fecha de Creaci[oó]n:\s*(\S+)/i); if(m) cr = ifWDate(m[1]); }
  const ex = ifWDate(first(/^(registry expiry date|expiry date|expiration date|expires|expires on|record expires on|paid till|fecha de vencimiento|expire date)$/));
  for(const f of F) f.first = cr;
  return {kind:'WHOIS', label:'WHOIS — ' + dom, facts:F, attrs:{[dom]:{created:cr, expires:ex}}};
}
function ifRdap(o){
  if(!o || o.objectClassName !== 'domain' || !o.ldhName) return null; const dom = ifDom(o.ldhName); if(!dom) return null; const F = [], add = (rel, v, vk) => { if(v && !F.some(f => f.rel === rel && f.v === v)) F.push({s:dom, sk:'domain', rel, v:String(v), vk}); };
  const vc = e => { const a = Array.isArray(e.vcardArray) ? e.vcardArray[1] || [] : [], g = k => (a.find(x => x[0] === k) || [])[3]; return {fn:g('fn'), org:g('org'), email:g('email'), tel:g('tel')}; };
  const walk = (es, depth) => { for(const e of Array.isArray(es) ? es : []){ const r = (e.roles || []).join(' '), v = vc(e);
      if(/registrar/.test(r) && v.fn) add('registrar', v.fn, 'text');
      if(/registrant/.test(r)){ if(v.fn) add('registrant name', v.fn, 'name'); if(v.org) add('registrant org', Array.isArray(v.org) ? v.org[0] : v.org, 'org'); if(v.email) add('registrant email', String(v.email).toLowerCase(), 'email'); if(v.tel) add('registrant phone', String(v.tel).replace(/[^\d+]/g, ''), 'phone'); }
      if(/administrative|technical/.test(r) && v.email) add('contact email', String(v.email).toLowerCase(), 'email'); if(depth < 2) walk(e.entities, depth + 1); } };
  walk(o.entities, 0);
  for(const n of o.nameservers || []){ const d = ifDom(n.ldhName); if(d) add('name server', d, 'domain'); }
  const ev = k => ifDate(((o.events || []).find(e => e.eventAction === k) || {}).eventDate), cr = ev('registration'); for(const f of F) f.first = cr;
  return {kind:'RDAP', label:'RDAP — ' + dom, facts:F, attrs:{[dom]:{created:cr, expires:ev('expiration')}}};
}
function ifDig(t){
  const L = [...t.matchAll(/^\s*([A-Za-z0-9_.*-]+\.?)\s+(?:(\d+)\s+)?(?:IN\s+)?(A|AAAA|NS|MX|CNAME|TXT|SOA)\s+(.+)$/gm)]; if(!L.length) return null; const F = [];
  for(const m of L){ const s = ifDom(m[1]); if(!s) continue; const ty = m[3].toUpperCase(), v = m[4].trim(), add = (rel, val, vk) => { if(val && !F.some(f => f.s === s && f.rel === rel && f.v === val)) F.push({s, sk:'domain', rel, v:val, vk}); };
    if(ty === 'A' && ifIp4(v)) add('resolves to', v, 'ip'); else if(ty === 'AAAA' && /:/.test(v)) add('resolves to', v.toLowerCase(), 'ip');
    else if(ty === 'NS'){ const n = ifDom(v); if(n) add('name server', n, 'domain'); }
    else if(ty === 'MX'){ const n = ifDom(v.split(/\s+/).pop()); if(n) add('mail server', n, 'domain'); }
    else if(ty === 'CNAME'){ const n = ifDom(v); if(n) add('alias of', n, 'domain'); }
    else if(ty === 'SOA'){ const p = v.split(/\s+/); const em = p[1] ? p[1].replace(/\.$/, '').replace(/^([^.\\]+)\./, '$1@').replace(/\\\./g, '.') : ''; if(/@/.test(em)) add('SOA contact', em.toLowerCase(), 'email'); }
    else if(ty === 'TXT'){ const tx = v.replace(/"\s+"/g, '').replace(/^"|"$/g, '');
      const ver = tx.match(/^(google-site-verification|facebook-domain-verification|MS|ms-domain-verification|apple-domain-verification|atlassian-domain-verification|yandex-verification|zoom-verification|docusign|adobe-idp-site-verification|globalsign-domain-verification|stripe-verification|have-i-been-pwned-verification|openai-domain-verification|brevo-code|hubspot-developer-verification|_?amazonses)[=:]\s*(\S+)/i);
      if(ver) add('site verification', ver[1].toLowerCase() + '=' + ver[2], 'token'); } }
  return F.length ? {kind:'DNS records', label:'DNS records — ' + [...new Set(F.map(f => f.s))].slice(0, 3).join(', '), facts:F} : null;
}
function ifPdns(o, t){
  const F = [], add = (s, ip, first, last) => { s = ifDom(s); ip = String(ip || '').trim().toLowerCase(); if(!s || !(ifIp4(ip) || /^[0-9a-f:]+$/.test(ip) && ip.includes(':'))) return; const f = F.find(x => x.s === s && x.v === ip);
    if(f){ f.first = Math.min(f.first ?? first, first ?? f.first); f.last = Math.max(f.last ?? last, last ?? f.last); } else F.push({s, sk:'domain', rel:'resolves to', v:ip, vk:'ip', first, last}); };
  const rows = Array.isArray(o) ? o : o && Array.isArray(o.data) ? o.data : o && Array.isArray(o.records) ? o.records : o && Array.isArray(o.results) ? o.results : null;
  if(rows){ for(const r of rows.slice(0, 50000)){ if(!r || typeof r !== 'object') continue; const a = r.attributes || r;
      if(a.host_name && a.ip_address) add(a.host_name, a.ip_address, ifDate(a.date) , ifDate(a.date));                            // VirusTotal resolutions
      else if(a.rrname && a.rdata != null){ if(!a.rrtype || /^(A|AAAA)$/i.test(a.rrtype)) for(const ip of [].concat(a.rdata)) add(a.rrname, ip, ifDate(a.time_first ?? a.zone_time_first), ifDate(a.time_last ?? a.zone_time_last)); }   // CIRCL, DNSDB
      else if(Array.isArray(a.values) && (a.first_seen || a.last_seen)){ for(const v of a.values) add(o.hostname || o.domain || a.hostname, v.ip || v.ip_address, ifDate(a.first_seen), ifDate(a.last_seen)); }   // SecurityTrails history
      else { const h = a.hostname || a.domain || a.query || a.name, ip = a.ip || a.address || a.resolve || a.value; if(h && ip) add(h, ip, ifDate(a.first_seen || a.firstSeen || a.first), ifDate(a.last_seen || a.lastSeen || a.last)); } } }
  if(!F.length && t && /,/.test(t)){ const lines = t.split(/\r?\n/).filter(l => l.trim()), head = (lines[0] || '').toLowerCase().split(/[,\t]/).map(x => x.trim().replace(/"/g, ''));
    const ci = re => head.findIndex(h => re.test(h)), hi = ci(/^(domain|hostname|host|rrname|query|name)$/), ii = ci(/^(ip|ip_address|address|rdata|value|resolve|a)$/), fi = ci(/first/), li = ci(/last/);
    if(hi >= 0 && ii >= 0) for(const l of lines.slice(1, 50001)){ const c = l.split(/[,\t]/).map(x => x.trim().replace(/^"|"$/g, '')); add(c[hi], c[ii], fi >= 0 ? ifDate(c[fi]) : null, li >= 0 ? ifDate(c[li]) : null); } }
  return F.length ? {kind:'Passive DNS', label:'Passive DNS — ' + F.length + ' resolution' + (F.length > 1 ? 's' : ''), facts:F} : null;
}
function ifCrt(o){
  if(!Array.isArray(o) || !o.length || !o.every(x => x && (x.name_value != null || x.common_name != null) && (x.id != null || x.serial_number))) return null; const F = [];
  for(const c of o.slice(0, 20000)){ const id = c.serial_number ? 'serial ' + String(c.serial_number).toLowerCase() : 'crt.sh ' + c.id, names = new Set(String(c.name_value || '').split(/\s+/).concat(c.common_name || '').map(ifDom).filter(Boolean));
    for(const n of names) F.push({s:n, sk:'domain', rel:'certificate', v:id, vk:'cert', first:ifDate(c.not_before), last:ifDate(c.not_after), note:String(c.issuer_name || '').replace(/^.*?O=([^,]+).*$/, '$1')}); }
  return F.length ? {kind:'Certificates (crt.sh)', label:'crt.sh — ' + o.length + ' certificate' + (o.length > 1 ? 's' : ''), facts:F} : null;
}
function ifShodan(o){
  if(!o || !o.ip_str || !Array.isArray(o.data)) return null; const ip = o.ip_str, F = [], add = (rel, v, vk, s, sk) => { v = String(v ?? '').trim(); if(v && !F.some(f => f.s === (s || ip) && f.rel === rel && f.v === v)) F.push({s:s || ip, sk:sk || 'ip', rel, v, vk}); };
  if(o.asn) add('network', o.asn, 'asn'); if(o.org || o.isp) add('hosting', o.org || o.isp, 'org');
  for(const h of [].concat(o.hostnames || [], o.domains || [])){ const d = ifDom(h); if(d) add('resolves to', ip, 'ip', d, 'domain'); }
  for(const s of o.data){ const c = s.ssl && s.ssl.cert; if(c && c.fingerprint && c.fingerprint.sha256) add('certificate', 'sha256 ' + c.fingerprint.sha256.toLowerCase(), 'cert'); if(s.ssl && s.ssl.jarm && !/^0+$/.test(s.ssl.jarm)) add('JARM', s.ssl.jarm, 'jarm');
    if(s.http && s.http.favicon && s.http.favicon.hash != null) add('favicon', 'mmh3 ' + s.http.favicon.hash, 'favicon'); }
  const ports = [...new Set(o.data.map(s => s.port).filter(Boolean))].sort((a, b) => a - b);
  return {kind:'Shodan', label:'Shodan — ' + ip, facts:F, attrs:{[ip]:{ports, title:(o.data.find(s => s.http && s.http.title) || {http:{}}).http.title || ''}}};
}
function ifCensys(o){
  const h = o && o.result && o.result.ip ? o.result : o; if(!h || !h.ip || !Array.isArray(h.services)) return null; const ip = h.ip, F = [], add = (rel, v, vk, s, sk) => { v = String(v ?? '').trim(); if(v && !F.some(f => f.s === (s || ip) && f.rel === rel && f.v === v)) F.push({s:s || ip, sk:sk || 'ip', rel, v, vk}); };
  const as = h.autonomous_system || {}; if(as.asn) add('network', 'AS' + as.asn, 'asn'); if(as.name) add('hosting', as.name, 'org');
  for(const n of (h.dns && h.dns.names) || []){ const d = ifDom(n); if(d) add('resolves to', ip, 'ip', d, 'domain'); }
  for(const s of h.services){ const t = s.tls || {}, leaf = t.certificates && t.certificates.leaf_fp_sha_256 || t.certificates && t.certificates.leaf_data && t.certificates.leaf_data.fingerprint; if(leaf) add('certificate', 'sha256 ' + String(leaf).toLowerCase(), 'cert');
    if(s.jarm && s.jarm.fingerprint && !/^0+$/.test(s.jarm.fingerprint)) add('JARM', s.jarm.fingerprint, 'jarm');
    for(const f of (s.http && s.http.response && s.http.response.favicons) || []) if(f.md5_hash) add('favicon', 'md5 ' + f.md5_hash, 'favicon'); }
  return {kind:'Censys', label:'Censys — ' + ip, facts:F, attrs:{[ip]:{ports:[...new Set(h.services.map(s => s.port))].sort((a, b) => a - b)}}};
}
/* one paste or one evidence text → what it is and its facts */
function infraParse(text){
  const t = String(text || '').slice(0, 4 << 20); if(t.trim().length < 8) return null; let o = null;
  if(/^\s*[\[{]/.test(t)){ try{ o = JSON.parse(t); }catch(e){ try{ o = t.split(/\r?\n/).filter(l => l.trim()).map(l => JSON.parse(l)); }catch(e2){ o = null; } } }
  if(o) return ifRdap(o) || ifCrt(o) || ifShodan(o) || ifCensys(o) || ifPdns(o) || null;
  return ifWhois(t) || ifDig(t) || ifPdns(null, t);
}
const IF_HINT = /Domain Name:|Registrar:|nserver:|\bIN\s+(A|AAAA|NS|MX|TXT|SOA|CNAME)\s|"rrname"|"name_value"|"ip_str"|"autonomous_system"|"ldhName"|"host_name"|"first_seen"|^(domain|hostname|rrname|query),/im;
/* all the facts in a case's evidence, joined */
function infraIndex(caseId){
  const sig = caseId + ':' + rev; if(IF_C.sig === sig) return IF_C.v;
  const D = derive(caseId), facts = [], attrs = {}, srcs = [];
  for(const r of D.recs){ if(r.type === 'lead' || !r.body || r.body.length > 4 << 20 || !IF_HINT.test(r.body.slice(0, 200000))) continue; let P = null; try{ P = infraParse(r.body); }catch(e){} if(!P || !P.facts.length) continue;
    srcs.push({r, kind:P.kind, n:P.facts.length}); for(const f of P.facts) facts.push({...f, rec:r.id}); for(const [k, v] of Object.entries(P.attrs || {})) attrs[k] = {...(attrs[k] || {}), ...v}; }
  /* same-day registrations through the same registrar */
  const reg = new Map(); for(const f of facts) if(f.rel === 'registrar' && f.first){ const k = new Date(f.first).toISOString().slice(0, 10) + ' · ' + f.v; (reg.get(k) || reg.set(k, new Set()).get(k)).add(f.s); }
  for(const [k, S] of reg) if(S.size > 1) for(const s of S) facts.push({s, sk:'domain', rel:'registered same day', v:k, vk:'date'});
  /* what is shared, and what that is worth */
  const ipLoad = new Map(); for(const f of facts) if(f.rel === 'resolves to') ipLoad.set(f.v, (ipLoad.get(f.v) || new Set()).add(f.s));
  const groups = new Map();
  for(const f of facts){ let rel = f.rel; if(!IF_REL[rel] && rel !== 'name server') continue;
    /* name servers count by their domain (ns1. and ns2. of one provider are one thing) */
    const val = rel === 'name server' ? (typeof lkRegDomain === 'function' ? lkRegDomain(f.v) : f.v.split('.').slice(-2).join('.')) || f.v : f.v;
    const key = rel + '\u0000' + val; let g = groups.get(key); if(!g){ g = {rel, v:val, vk:f.vk, subs:new Map(), recs:new Set(), first:null, last:null}; groups.set(key, g); }
    g.subs.set(f.s, f.sk); g.recs.add(f.rec); if(f.first) g.first = Math.min(g.first ?? f.first, f.first); if(f.last) g.last = Math.max(g.last ?? f.last, f.last); }
  const shared = [];
  for(const g of groups.values()){ if(g.subs.size < 2) continue; let [strength, why] = IF_REL[g.rel] || ['weak', ''], caveat = '';
    if(/registrant|contact/.test(g.rel) && IF_PRIVACY.test(g.v)){ strength = 'none'; caveat = 'A privacy or redaction service — shared by countless unrelated domains'; }
    else if(g.rel === 'name server' && IF_BIG_NS.test(g.v)){ strength = 'none'; caveat = 'A big DNS provider — shared by millions of domains'; }
    else if(g.rel === 'name server'){ strength = 'medium'; why = 'The same name servers, from a provider few domains use'; }
    else if(g.rel === 'resolves to' && ifCdn(g.v)){ strength = 'none'; caveat = 'A CDN address — shared by many unrelated sites'; }
    else if(g.rel === 'resolves to' && (ipLoad.get(g.v) || new Set()).size > 25){ strength = 'weak'; caveat = 'Shared hosting: ' + ipLoad.get(g.v).size + ' names on this address'; }
    else if(g.rel === 'SOA contact' && /(awsdns-hostmaster\.amazon\.com|dns\.cloudflare\.com|hostmaster@(?:.*\.)?(google|domaincontrol|registrar-servers|azure)|dns@cloudflare|azuredns-hostmaster)/i.test(g.v)){ strength = 'none'; caveat = 'The DNS provider\'s own contact'; }
    else if(g.rel === 'registrar' || g.rel === 'hosting' || g.rel === 'network'){ /* weak by nature */ }
    shared.push({...g, subs:[...g.subs.entries()].map(([v, k]) => ({v, k})), strength, why, caveat}); }
  const rank = {strong:0, medium:1, weak:2, none:3};
  shared.sort((a, b) => rank[a.strength] - rank[b.strength] || b.subs.length - a.subs.length);
  const subjects = new Map(); for(const f of facts){ if(!subjects.has(f.s)) subjects.set(f.s, {v:f.s, k:f.sk, n:0}); subjects.get(f.s).n++; }
  const v = {facts, shared, srcs, attrs, subjects:[...subjects.values()]}; IF_C.sig = sig; IF_C.v = v; return v;
}
const IF_C = {sig:'', v:null};
/* the picture: what you investigated on the left, what they share on the right */
function infraSvg(X){
  const S = X.shared.filter(g => g.strength !== 'none').slice(0, 14); if(!S.length) return '';
  const subs = [...new Set(S.flatMap(g => g.subs.map(s => s.v)))].slice(0, 24), H = Math.max(S.length, subs.length) * 34 + 30, W = 1120, ly = i => 24 + i * ((H - 40) / Math.max(1, subs.length - 1 || 1)), ry = i => 24 + i * ((H - 40) / Math.max(1, S.length - 1 || 1));
  const col = {strong:'var(--red,#dc2626)', medium:'var(--amber,#d97706)', weak:'var(--text-3)'};
  const lines = S.flatMap((g, j) => g.subs.filter(s => subs.includes(s.v)).map(s => `<path d="M230,${ly(subs.indexOf(s.v))} C380,${ly(subs.indexOf(s.v))} 380,${ry(j)} 520,${ry(j)}" class="if-e ${g.strength}" style="stroke:${col[g.strength]}"></path>`)).join('');
  return `<div class="if-svg" role="img" aria-label="Domains and addresses on the left, joined to what they share on the right"><svg viewBox="0 0 ${W} ${H}" width="100%" preserveAspectRatio="xMinYMin meet">${lines}
    ${subs.map((s, i) => `<text x="222" y="${ly(i) + 4}" text-anchor="end" class="if-l">${esc(s.length > 30 ? s.slice(0, 28) + '…' : s)}</text><circle cx="230" cy="${ly(i)}" r="4" class="if-n"></circle>`).join('')}
    ${S.map((g, j) => `<circle cx="520" cy="${ry(j)}" r="5" class="if-n" style="fill:${col[g.strength]}"></circle><text x="530" y="${ry(j) + 4}" class="if-l"><title>${esc(g.rel + ' ' + g.v)}</title><tspan class="if-rel">${esc(g.rel)}</tspan> ${esc((m => g.v.length > m ? g.v.slice(0, m - 2) + '…' : g.v)(Math.max(16, 70 - g.rel.length)))}</text>`).join('')}</svg></div>`;
}
function infraView(c){
  const X = infraIndex(c.id), when = ms => ms ? E.fmtFull(ms, tz()).slice(0, 10) : '';
  const head = `<div class="if-top"><p class="t2" style="margin:0">Paste what you got from WHOIS, RDAP, dig, passive DNS (VirusTotal, SecurityTrails, CIRCL, DNSDB or a CSV), crt.sh, Shodan or Censys. Each paste is kept as evidence; what the domains and addresses share is worked out here. Nothing is looked up.</p><button class="btn primary sm" data-act="ifPaste">${ico('plus','sm')}Paste results</button></div>`;
  if(!X.facts.length) return head + empty('network', 'No infrastructure results in this case yet', 'Paste WHOIS, DNS, certificate or scan results and the shared registrants, certificates, addresses and name servers show up here.');
  const lbl = {strong:['Strong', 'red'], medium:['Medium', 'amber'], weak:['Weak', ''], none:['Not a link', '']};
  const sub = s => `<button class="lnk mono" data-act="ifSub" data-v="${esc(s.v)}" aria-pressed="${UI.ifSub === s.v}" title="Open ${esc(s.v)} and list every fact about it">${esc(s.v)}</button>`;
  const card = g => `<li class="if-g${g.strength === 'none' ? ' none' : ''}"><div class="if-gh"><span class="chip sq ${lbl[g.strength][1]}">${lbl[g.strength][0]}</span><span class="t3">${esc(g.rel)}</span><b class="mono">${esc(g.v)}</b><button class="iconbtn sm" data-act="ifCopy" data-v="${esc(g.v)}" aria-label="Copy ${esc(g.v)}">${ico('copy','sm')}</button></div>
    <div class="t2 small">${esc(g.caveat || g.why)}${g.first ? ` · seen ${esc(when(g.first))}${g.last && g.last !== g.first ? ' to ' + esc(when(g.last)) : ''}` : ''}</div>
    <div class="if-subs">${g.subs.length} ${g.subs.every(s => s.k === 'ip') ? 'addresses' : 'names'}: ${g.subs.slice(0, 12).map(sub).join(', ')}${g.subs.length > 12 ? ` and ${g.subs.length - 12} more` : ''}</div></li>`;
  const real = X.shared.filter(g => g.strength !== 'none'), noise = X.shared.filter(g => g.strength === 'none');
  const F = UI.ifSub ? X.facts.filter(f => f.s === UI.ifSub || f.v === UI.ifSub) : X.facts;
  return `${head}<div class="if-sum card"><div class="tlx-kpi"><div><b>${X.subjects.filter(s => s.k === 'domain').length}</b><span>domains</span></div><div><b>${X.subjects.filter(s => s.k === 'ip').length}</b><span>addresses</span></div><div><b>${real.filter(g => g.strength === 'strong').length}</b><span>strong links</span></div><div><b>${X.srcs.length}</b><span>results pasted</span></div></div>
      ${infraSvg(X)}</div>
    <section class="card if-c"><h3>What they share</h3>${real.length ? `<ul class="if-l0">${real.map(card).join('')}</ul>` : '<p class="t3">Nothing shared yet between the names and addresses here — paste results for more of them.</p>'}
      ${noise.length ? `<details class="if-noise"><summary>${noise.length} shared thing${noise.length > 1 ? 's' : ''} that mean nothing (privacy services, big DNS providers, CDN addresses)</summary><ul class="if-l0">${noise.map(card).join('')}</ul></details>` : ''}</section>
    <section class="card if-c" id="ifAll"><h3>All facts${UI.ifSub ? ` about <span class="mono">${esc(UI.ifSub)}</span> <button class="btn xs" data-act="ifSub" data-v="">Show all</button>` : ''} <span class="t3">${F.length}</span></h3>
      <div class="if-tw"><table class="if-t"><thead><tr><th scope="col">Name or address</th><th scope="col">Fact</th><th scope="col">Value</th><th scope="col">Seen</th><th scope="col">From</th></tr></thead><tbody>
      ${F.slice(0, 400).map(f => `<tr><td class="mono">${sub({v:f.s})}</td><td>${esc(f.rel)}</td><td class="mono">${esc(f.v)}${f.note ? ` <span class="t3">${esc(f.note)}</span>` : ''}</td><td class="mono t3">${esc(when(f.first))}${f.last && f.last !== f.first ? ' – ' + esc(when(f.last)) : ''}</td><td><button class="lnk small" data-act="tlxRec" data-id="${esc(f.rec)}">${esc((X.srcs.find(s => s.r.id === f.rec) || {kind:''}).kind)}</button></td></tr>`).join('')}</tbody></table></div>${F.length > 400 ? `<p class="t3 small">Showing 400 of ${F.length}.</p>` : ''}</section>`;
}
function infraPasteDlg(){
  openDlg(dhead('Paste infrastructure results') + `<form data-form="ifPaste"><div class="in">
    <div class="field"><label for="ifText">Results <span class="t3">— WHOIS, RDAP, dig, passive DNS, crt.sh, Shodan or Censys</span></label><textarea id="ifText" rows="12" class="mono" spellcheck="false" placeholder="Domain Name: example.com&#10;Registrar: …&#10;&#10;or the JSON from crt.sh, Shodan, Censys, VirusTotal…"></textarea><span class="hint" id="ifHint" aria-live="polite"></span></div></div>
    <footer><button class="btn" type="button" data-act="dclose">Cancel</button><button class="btn primary" type="submit">Add to the case</button></footer></form>`, true);
}
function infraSubmit(){
  const t = String($('ifText').value || ''); if(!t.trim()) return fieldErr('ifText', 'Paste the results first.'); if(t.length > 4 << 20) return fieldErr('ifText', 'That is over 4 MB — split it into smaller pastes.');
  const P = infraParse(t); if(!P || !P.facts.length) return fieldErr('ifText', 'Not recognised. Paste WHOIS or RDAP, dig output, passive DNS (JSON or CSV), crt.sh JSON, or a Shodan or Censys host.');
  const c = theCase(), body = t.trim(); if(DB.records.some(r => r.caseId === c.id && r.body === body)) return fieldErr('ifText', 'These exact results are already in the case.');
  const r = {id:uid('r'), caseId:c.id, type:'evidence', title:P.label.slice(0, 110), body, tsRaw:new Date().toISOString(), tsZone:'explicit', ts:Date.now(), source:'infra:' + P.kind, host:'', tags:['infrastructure'], ents:extractRich(body.slice(0, 300000)).slice(0, 2000), answer:'', addedBy:'You', addedAt:Date.now(), hash:''};
  DB.records.push(r); closeDlg(); mutate('added ' + P.kind + ' results'); if(typeof hashRecords === 'function') hashRecords(); renderMain(); toast(`${P.kind}: ${P.facts.length} fact${P.facts.length > 1 ? 's' : ''} added`);
}
document.addEventListener('input', ev => { if(ev.target && ev.target.id === 'ifText'){ const h = $('ifHint'); if(!h) return; clearTimeout(UI.ifT); UI.ifT = setTimeout(() => { let P = null; try{ P = infraParse(ev.target.value); }catch(e){} h.textContent = P && P.facts.length ? `Recognised: ${P.kind} — ${P.facts.length} fact${P.facts.length > 1 ? 's' : ''}` : ev.target.value.trim() ? 'Not recognised yet' : ''; }, 250); } });
const IF_ACTS = {
  ifPaste:() => infraPasteDlg(),
  /* a name opens in the details panel and the facts below narrow to it */
  ifSub:(id, v) => { UI.ifSub = v || null; if(!v) return renderMain(); const k = /^[\d.]+$/.test(v) ? 'ipv4' : v.includes(':') ? 'ipv6' : 'domain'; renderMain(); select('ent', k + ':' + v);
    requestAnimationFrame(() => { const a = $('ifAll'); if(a){ a.scrollIntoView({block:'start'}); a.classList.add('flash'); setTimeout(() => a.classList.remove('flash'), 1200); } }); },
  ifCopy:(id, v) => copyText(v),
};
