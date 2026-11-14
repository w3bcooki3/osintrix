/* ==========================================================================
   Live lookups — ask the services analysts use, in parallel, and bring every answer
   back in one shape the verdict and correlation engines can reason about.

   Each provider says how it is reached:
     direct — the browser may call it (checked: the service allows cross-origin reads)
     relay  — the service refuses browsers, or needs a key that should not live in a page;
              it is reached through your own relay (tools/relay, a Cloudflare Worker)
   A provider runs only when you switched it on; keys you enter are kept in this
   workspace (encrypted with it) and only ever sent to that provider's own host.
   Every answer is untrusted: values are re-validated by the extractor, strings capped,
   links must be http(s), and everything is escaped where it is drawn.
   Normalised result: {ok, at, sig:[{t:'mal'|'sus'|'ben', w, why, ts?}], facts:[[label, value]],
   attrs:{…pivots}, related:[{k, v, rel}], link, none?}
   ========================================================================== */
const LK = {cache:null, ready:null, inflight:new Map(), last:new Map()};
const LK_KINDS_IP = ['ipv4', 'ipv6'], LK_HASH = ['md5', 'sha1', 'sha256'];
const lkCap = (s, n = 300) => cap(s, n);
const lkArr = (a, n = 50) => (Array.isArray(a) ? a : []).slice(0, n);
const lkDate = s => { const t = Date.parse(s); return t > 0 && t < Date.now() + 864e5 * 400 ? t : 0; };
const lkDays = t => t ? Math.floor((Date.now() - t) / 864e5) : null;
const b64url = s => btoa(unescape(encodeURIComponent(s))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
/* related values must be real indicators */
function lkRel(k, v, rel){ const n = iocNorm(v); return n && (!k || n.k === k || (k === 'domain' && n.k === 'domain')) ? {k:n.k, v:n.v, rel} : null; }
const lkRels = (list, k, rel, n = 40) => [...new Map(lkArr(list, 400).map(v => lkRel(k, v, rel)).filter(Boolean).map(x => [x.k + ':' + x.v, x])).values()].slice(0, n);
const OTX_TYPE = {ipv4:'IPv4', ipv6:'IPv6', domain:'domain', url:'url', md5:'file', sha1:'file', sha256:'file'};
/* JARM fingerprints of default C2 server configurations (public research; a match is a lead, not proof) */
const BAD_JARM = {'07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1':'Cobalt Strike (default)', '2ad2ad16d2ad2ad22c42d42d00042d58c7162162b6a603d3d90a2b76865b53':'Cobalt Strike (common)',
  '07d0bd0fd06d06d07c07d0bd07d0bd5b8c4e1d6a5f6e9b4f5c6c2a6c5f4c5f0e':'Metasploit (common)', '00000000000000000043d43d00043de2a97eabb398317329084a8ff1c3c2a5':'Sliver (common)'};
const C2_PRODUCT = /cobalt ?strike|metasploit|sliver|havoc|mythic|covenant|brute ?ratel|posh ?c2|empire|deimos|nighthawk|merlin c2/i;

const LK_PROVIDERS = [
  /* ---------- free, straight from the browser ---------- */
  {id:'idb', name:'Shodan InternetDB', kinds:LK_KINDS_IP, via:'direct', host:'internetdb.shodan.io', ttl:24, rel:0.7, about:'Open ports, hostnames, software and known CVEs seen by Shodan. Free, no key.',
    req:(k, v) => ({url:'https://internetdb.shodan.io/' + encodeURIComponent(v)}), web:(k, v) => 'https://www.shodan.io/host/' + encodeURIComponent(v),
    parse(j){ if(j && j.detail) return {none:true, facts:[['Shodan', 'Not seen scanning or exposed']]};
      const tags = lkArr(j.tags).map(t => lkCap(t, 40)), ports = lkArr(j.ports, 200).filter(p => p > 0 && p < 65536), vulns = lkArr(j.vulns, 200).map(c => lkCap(c, 20)).filter(c => /^CVE-\d{4}-\d+$/.test(c));
      const sig = []; if(tags.some(t => /^(c2|malware|compromised)$/.test(t))) sig.push({t:'mal', w:0.85, why:'Shodan tags it ' + tags.filter(t => /c2|malware|compromised/.test(t)).join(', ')});
      if(tags.includes('scanner')) sig.push({t:'sus', w:0.35, why:'Shodan sees it scanning'}); if(tags.includes('tor')) sig.push({t:'sus', w:0.25, why:'Tor node'});
      if(tags.includes('cdn')) sig.push({t:'ben', w:0.25, why:'CDN address — many sites share it'});
      if(vulns.length >= 5) sig.push({t:'sus', w:0.2, why:vulns.length + ' known CVEs on exposed services'});
      return {sig, facts:[['Open ports', ports.join(', ') || 'none'], ['Hostnames', lkArr(j.hostnames, 8).join(', ')], ['Software', lkArr(j.cpes, 6).map(c => c.replace(/^cpe:\/\w:/, '')).join(', ')], ['Tags', tags.join(', ')], ['CVEs', vulns.slice(0, 8).join(', ') + (vulns.length > 8 ? ' +' + (vulns.length - 8) : '')]],
        attrs:{ports, cves:vulns, tags, cpes:lkArr(j.cpes, 20).map(c => lkCap(c, 80))}, related:lkRels(j.hostnames, 'domain', 'hostname')}; }},
  {id:'dns', name:'DNS (Google DoH)', kinds:['domain', 'ipv4'], via:'direct', host:'dns.google', ttl:6, rel:0.9, about:'Current A, AAAA, NS and MX records, or the reverse name of an IP.',
    async run(k, v, ctx){
      if(k === 'ipv4'){ const j = await ctx.json('https://dns.google/resolve?name=' + v.split('.').reverse().join('.') + '.in-addr.arpa&type=PTR'); const ptr = lkArr(j.Answer).filter(a => a.type === 12).map(a => lkCap(String(a.data).replace(/\.$/, ''), 253));
        return {facts:[['Reverse DNS', ptr.join(', ') || 'none']], attrs:{ptr}, related:lkRels(ptr, 'domain', 'reverse DNS')}; }
      const q = async t => ctx.json('https://dns.google/resolve?name=' + encodeURIComponent(v) + '&type=' + t);
      const [a, aaaa, ns, mx] = await Promise.all(['A', 'AAAA', 'NS', 'MX'].map(q));
      if(a.Status === 3) return {none:true, sig:[{t:'sus', w:0.1, why:'The domain does not resolve (NXDOMAIN)'}], facts:[['DNS', 'Does not exist (NXDOMAIN)']], attrs:{nx:true}};
      const pick = (j, t) => lkArr(j.Answer).filter(x => x.type === t).map(x => lkCap(String(x.data).replace(/\.$/, ''), 253));
      const ips = [...pick(a, 1), ...pick(aaaa, 28)], nss = pick(ns, 2).map(x => x.toLowerCase()), mxs = pick(mx, 15).map(x => x.replace(/^\d+\s+/, '').toLowerCase()), cn = pick(a, 5);
      return {facts:[['Resolves to', ips.join(', ') || 'nothing'], ['CNAME', cn.join(', ')], ['Name servers', nss.join(', ')], ['Mail', mxs.join(', ')]],
        attrs:{ips, ns:nss, mx:mxs, cname:cn}, related:[...lkRels(ips.filter(x => /^\d+\.\d+\.\d+\.\d+$/.test(x)), 'ipv4', 'resolves to'), ...lkRels(cn, 'domain', 'CNAME')]}; }},
  {id:'rdap', name:'RDAP registration', kinds:['domain', 'ipv4', 'ipv6'], via:'direct', host:'rdap.org', ttl:24 * 7, rel:0.5, about:'Registration date, registrar, name servers and network owner, from the registries (the modern WHOIS).',
    req:(k, v) => ({url:'https://rdap.org/' + (k === 'domain' ? 'domain/' : 'ip/') + encodeURIComponent(v)}), web:(k, v) => 'https://client.rdap.org/?type=' + (k === 'domain' ? 'domain' : 'ip') + '&object=' + encodeURIComponent(v),
    parse(j, k){
      const ev = a => lkDate((lkArr(j.events).find(e => e.eventAction === a) || {}).eventDate);
      const vc = e => { const a = Array.isArray(e && e.vcardArray) && e.vcardArray[1]; const f = Array.isArray(a) && a.find(x => x[0] === 'fn'); return f ? lkCap(f[3], 120) : ''; };
      const ents = lkArr(j.entities, 30), role = r => ents.find(e => lkArr(e.roles).includes(r));
      if(k === 'domain'){
        const created = ev('registration'), reg = vc(role('registrar')), ns = lkArr(j.nameservers).map(n => lkCap(n.ldhName, 253).toLowerCase()).filter(Boolean), age = lkDays(created), status = lkArr(j.status).map(s => lkCap(s, 40));
        const sig = []; if(age != null && age < 7) sig.push({t:'sus', w:0.6, why:'Registered ' + age + ' day' + (age === 1 ? '' : 's') + ' ago'}); else if(age != null && age < 30) sig.push({t:'sus', w:0.45, why:'Registered ' + age + ' days ago'}); else if(age != null && age > 365 * 5) sig.push({t:'ben', w:0.2, why:'Registered ' + Math.floor(age / 365) + ' years ago'});
        if(status.some(s => /hold/i.test(s))) sig.push({t:'sus', w:0.4, why:'Registry status: ' + status.filter(s => /hold/i.test(s)).join(', ')});
        return {sig, facts:[['Registered', created ? new Date(created).toISOString().slice(0, 10) + ' (' + age + ' days ago)' : 'unknown'], ['Registrar', reg], ['Expires', ev('expiration') ? new Date(ev('expiration')).toISOString().slice(0, 10) : ''], ['Name servers', ns.join(', ')], ['Status', status.join(', ')]],
          attrs:{created, registrar:reg, ns}};
      }
      const org = vc(role('registrant')) || vc(role('administrative')) || lkCap(j.name, 120), cidr = lkArr(j.cidr0_cidrs).map(c => (c.v4prefix || c.v6prefix) + '/' + c.length).join(', ');
      return {facts:[['Network', lkCap(j.name, 80) + (cidr ? ' · ' + cidr : '')], ['Owner', org], ['Country', lkCap(j.country, 4)], ['Range', lkCap(j.startAddress, 45) + ' – ' + lkCap(j.endAddress, 45)]], attrs:{netname:lkCap(j.name, 80), org, prefix:cidr.split(',')[0] || '', country:lkCap(j.country, 4)}}; }},
  {id:'ipinfo', name:'ipinfo', kinds:LK_KINDS_IP, via:'direct', host:'ipinfo.io', ttl:24, rel:0.7, key:{label:'Token', optional:true, query:'token'}, about:'Owner, ASN, location and hosting type. Works without a token at a low rate.',
    req:(k, v, key) => ({url:'https://ipinfo.io/' + encodeURIComponent(v) + '/json' + (key ? '?token=' + encodeURIComponent(key) : '')}), web:(k, v) => 'https://ipinfo.io/' + encodeURIComponent(v),
    parse(j){ if(j.bogon) return {facts:[['Address', 'Private or reserved — not on the internet']], attrs:{bogon:true}};
      const m = /^AS(\d+)\s+(.*)$/.exec(j.org || ''), sig = []; if(j.anycast) sig.push({t:'ben', w:0.15, why:'Anycast network (large provider)'});
      return {sig, facts:[['Owner', lkCap(j.org, 120)], ['Hostname', lkCap(j.hostname, 253)], ['Location', [j.city, j.region, j.country].filter(Boolean).map(x => lkCap(x, 60)).join(', ')]],
        attrs:{asn:m ? 'AS' + m[1] : '', asname:m ? lkCap(m[2], 120) : '', country:lkCap(j.country, 4), city:lkCap(j.city, 60)}, related:lkRels([j.hostname], 'domain', 'hostname')}; }},
  {id:'ripe', name:'RIPEstat', kinds:[...LK_KINDS_IP, 'asn'], via:'direct', host:'stat.ripe.net', ttl:24, rel:0.8, about:'Routed prefix, origin AS and the abuse contact to report to.',
    async run(k, v, ctx){ const res = encodeURIComponent(k === 'asn' ? v.replace(/^AS/i, '') : v);
      const [n, a] = await Promise.all([ctx.json('https://stat.ripe.net/data/network-info/data.json?resource=' + res), ctx.json('https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=' + res)]);
      const asns = lkArr(n.data && n.data.asns).map(x => 'AS' + String(x).replace(/\D/g, '')).filter(x => x !== 'AS'), prefix = lkCap(n.data && n.data.prefix, 50), abuse = lkArr(a.data && a.data.abuse_contacts, 5).map(x => lkCap(x, 120));
      return {facts:[['Prefix', prefix], ['Origin AS', asns.join(', ')], ['Abuse contact', abuse.join(', ')], ['Registry', lkCap(a.data && a.data.authoritative_rir, 10).toUpperCase()]], attrs:{prefix, asn:asns[0] || '', abuse}}; },
    web:(k, v) => 'https://stat.ripe.net/' + encodeURIComponent(v)},
  {id:'tor', name:'Tor relays (Onionoo)', kinds:LK_KINDS_IP, via:'direct', host:'onionoo.torproject.org', ttl:12, rel:0.95, about:'Whether the address is a Tor relay or exit right now.',
    req:(k, v) => ({url:'https://onionoo.torproject.org/details?search=' + encodeURIComponent(v) + '&fields=nickname,or_addresses,exit_addresses,flags,running,last_seen,as,as_name'}),
    parse(j, k, v){ const r = lkArr(j.relays, 20).find(x => lkArr(x.exit_addresses).includes(v) || lkArr(x.or_addresses).some(a => a.replace(/^\[|\]?:\d+$/g, '') === v));
      if(!r) return {none:true, facts:[['Tor', 'Not a Tor relay']]};
      const exit = lkArr(r.flags).includes('Exit') || lkArr(r.exit_addresses).includes(v);
      return {sig:[{t:'sus', w:exit ? 0.45 : 0.2, why:exit ? 'Tor exit node — traffic from it is anonymised' : 'Tor relay'}], facts:[['Tor', (exit ? 'Exit' : 'Relay') + ' · ' + lkCap(r.nickname, 40) + (r.running ? ' · running' : '')], ['Last seen', lkCap(r.last_seen, 20)]], attrs:{tor:exit ? 'exit' : 'relay'}}; }},
  {id:'cs', name:'CertSpotter (CT logs)', kinds:['domain'], via:'direct', host:'api.certspotter.com', ttl:24, rel:0.6, key:{label:'API key', optional:true, header:'Authorization', prefix:'Bearer '}, about:'Certificates issued for the domain and its subdomains, from Certificate Transparency logs.',
    req:(k, v, key) => ({url:'https://api.certspotter.com/v1/issuances?domain=' + encodeURIComponent(v) + '&include_subdomains=true&expand=dns_names&expand=issuer', headers:key ? {Authorization:'Bearer ' + key} : {}}), web:(k, v) => 'https://sslmate.com/certspotter/',
    parse(j, k, v){ const L = lkArr(j, 500), names = new Set(), certs = [], issuers = new Set(); let first = 0, recent = 0;
      for(const c of L){ lkArr(c.dns_names, 100).forEach(n => names.add(String(n).replace(/^\*\./, '').toLowerCase())); if(c.cert_sha256) certs.push(lkCap(c.cert_sha256, 64)); if(c.issuer) issuers.add(lkCap(c.issuer.friendly_name || c.issuer.name, 60));
        const nb = lkDate(c.not_before); if(nb && (!first || nb < first)) first = nb; if(nb > Date.now() - 7 * 864e5) recent++; }
      const subs = [...names].filter(n => n !== v && n.endsWith('.' + v)), sig = []; if(L.length && first && lkDays(first) < 14) sig.push({t:'sus', w:0.3, why:'First certificate issued ' + lkDays(first) + ' days ago'});
      return {sig, facts:[['Certificates', L.length + (L.length >= 500 ? '+' : '')], ['First issued', first ? new Date(first).toISOString().slice(0, 10) : ''], ['Issuers', [...issuers].slice(0, 4).join(', ')], ['Subdomains', subs.length + ''], ['Last 7 days', recent + '']],
        attrs:{certs:certs.slice(0, 50), firstCert:first, subs:subs.slice(0, 200)}, related:lkRels(subs, 'domain', 'subdomain', 60)}; }},
  {id:'ht', name:'HackerTarget host search', kinds:['domain'], via:'direct', host:'api.hackertarget.com', ttl:24, rel:0.5, about:'Subdomains and their addresses from passive DNS. Free: 50 lookups a day.',
    req:(k, v) => ({url:'https://api.hackertarget.com/hostsearch/?q=' + encodeURIComponent(v), text:true}),
    parse(t, k, v){ if(/API count exceeded|error/i.test(t.slice(0, 200))) throw new Error(lkCap(t, 120));
      const rows = t.split(/\r?\n/).slice(0, 500).map(l => l.split(',')).filter(r => r.length === 2), hosts = rows.map(r => r[0].toLowerCase()).filter(h => h !== v && h.endsWith('.' + v)), ips = rows.map(r => r[1]);
      return {facts:[['Hosts found', rows.length + ''], ['Sample', hosts.slice(0, 5).join(', ')]], attrs:{subs:hosts, ips:[...new Set(ips)].slice(0, 100)}, related:[...lkRels(hosts, 'domain', 'subdomain', 40), ...lkRels([...new Set(ips)], 'ipv4', 'hosts a subdomain', 20)]}; }},
  {id:'wb', name:'Wayback Machine', kinds:['domain', 'url'], via:'direct', host:'archive.org', ttl:24 * 7, rel:0.4, about:'When the site was first archived — a long history is a sign of an established site.',
    req:(k, v) => ({url:'https://archive.org/wayback/available?url=' + encodeURIComponent(v) + '&timestamp=19960101'}), web:(k, v) => 'https://web.archive.org/web/*/' + encodeURIComponent(v),
    parse(j){ const c = j.archived_snapshots && j.archived_snapshots.closest; if(!c || !c.available) return {none:true, facts:[['Archive', 'Never archived']], sig:[{t:'sus', w:0.1, why:'Never archived by the Wayback Machine'}]};
      const ts = String(c.timestamp || ''), d = /^\d{8}/.test(ts) ? Date.UTC(+ts.slice(0, 4), +ts.slice(4, 6) - 1, +ts.slice(6, 8)) : 0, y = d ? Math.floor(lkDays(d) / 365) : 0;
      return {sig:y >= 3 ? [{t:'ben', w:Math.min(0.35, 0.1 + y * 0.02), why:'Archived since ' + new Date(d).getUTCFullYear()}] : [], facts:[['First archived', d ? new Date(d).toISOString().slice(0, 10) : '']], attrs:{firstArchived:d}}; }},
  {id:'otx', name:'AlienVault OTX', kinds:['ipv4', 'ipv6', 'domain', 'url', ...LK_HASH], via:'direct', host:'otx.alienvault.com', ttl:12, rel:0.5, key:{label:'API key', optional:true, header:'X-OTX-API-KEY'},
    about:'Community threat reports (pulses) that include the indicator, with malware, adversaries and ATT&CK techniques. A key raises the rate limit.',
    req:(k, v, key) => ({url:'https://otx.alienvault.com/api/v1/indicators/' + OTX_TYPE[k] + '/' + (k === 'url' ? encodeURIComponent(v) : encodeURIComponent(v)) + '/general', headers:key ? {'X-OTX-API-KEY':key} : {}}),
    web:(k, v) => 'https://otx.alienvault.com/indicator/' + (k === 'url' ? 'url' : OTX_TYPE[k].toLowerCase().replace('ipv4', 'ip').replace('ipv6', 'ip')) + '/' + encodeURIComponent(v),
    parse(j){ const pi = j.pulse_info || {}, P = lkArr(pi.pulses, 100), val = lkArr(j.validation, 10).map(x => lkCap(x.name || x.message, 60)), sig = [];
      const recent = P.filter(p => lkDate(p.modified) > Date.now() - 180 * 864e5), mal = [...new Set(P.flatMap(p => lkArr(p.malware_families, 10).map(m => lkCap(m.display_name || m, 60))).filter(Boolean))].slice(0, 12);
      const adv = [...new Set(P.map(p => lkCap(p.adversary, 60)).filter(Boolean))].slice(0, 8), ttp = [...new Set(P.flatMap(p => lkArr(p.attack_ids, 20).map(a => lkCap(a.id || a, 16))).filter(x => /^T\d{4}/.test(x)))].slice(0, 20);
      if(val.length) sig.push({t:'ben', w:0.5, why:'OTX: ' + val.join(', ')});
      const n = +pi.count || P.length; if(n && !val.length) sig.push({t:recent.length ? 'mal' : 'sus', w:Math.min(0.7, (mal.length || adv.length ? 0.3 : 0.2) + recent.length * 0.08), why:n + ' OTX pulse' + (n > 1 ? 's' : '') + (recent.length ? ', ' + recent.length + ' in the last 6 months' : ', all older than 6 months') + (mal.length ? ' — ' + mal.slice(0, 3).join(', ') : ''), ts:Math.max(0, ...P.map(p => lkDate(p.modified)))});
      return {sig, facts:[['Pulses', n + ''], ['Malware', mal.join(', ')], ['Adversaries', adv.join(', ')], ['Techniques', ttp.join(', ')], ['Latest', P[0] ? lkCap(P[0].name, 100) : '']], attrs:{malware:mal, actors:adv, ttp, pulses:n}}; }},
  {id:'hibp', name:'Have I Been Pwned (breaches)', kinds:['domain'], via:'direct', host:'haveibeenpwned.com', ttl:24 * 7, rel:0.9, about:'Public data breaches of the site at this domain (not the emails in it).',
    req:(k, v) => ({url:'https://haveibeenpwned.com/api/v3/breaches?domain=' + encodeURIComponent(v)}), web:(k, v) => 'https://haveibeenpwned.com/PwnedWebsites',
    parse(j){ const L = lkArr(j, 20); if(!L.length) return {none:true, facts:[['Breaches', 'None listed']]};
      return {facts:L.slice(0, 5).map(b => ['Breach', lkCap(b.Title, 80) + ' · ' + lkCap(b.BreachDate, 10) + ' · ' + (+b.PwnCount || 0).toLocaleString() + ' accounts']), attrs:{breaches:L.map(b => lkCap(b.Name, 60))}}; }},
  {id:'cveorg', name:'CVE.org + CISA enrichment', kinds:['cve'], via:'direct', host:'cveawg.mitre.org', ttl:24 * 3, rel:0.95, about:'The official CVE record: description, CNA CVSS score, CWE, affected products, and CISA\'s exploitation assessment.',
    req:(k, v) => ({url:'https://cveawg.mitre.org/api/cve/' + encodeURIComponent(v)}), web:(k, v) => 'https://www.cve.org/CVERecord?id=' + encodeURIComponent(v),
    parse(j, k, v){ const C = j.containers || {}, cna = C.cna || {}, adp = lkArr(C.adp, 10);
      const pick = list => { for(const m of lkArr(list, 20)){ const x = m.cvssV4_0 || m.cvssV3_1 || m.cvssV3_0 || m.cvssV2_0; if(x && x.baseScore >= 0 && x.baseScore <= 10) return x; } return null; };
      const cv = pick(cna.metrics) || adp.map(a => pick(a.metrics)).find(Boolean), desc = lkCap((lkArr(cna.descriptions).find(d => /^en/.test(d.lang)) || {}).value, 1200);
      const ssvc = adp.flatMap(a => lkArr(a.metrics)).map(m => m.other).find(o => o && o.type === 'ssvc'), opt = ssvc && ssvc.content ? Object.assign({}, ...lkArr(ssvc.content.options, 10)) : {};
      const cwe = lkArr(cna.problemTypes).flatMap(p => lkArr(p.descriptions)).map(d => lkCap(d.cweId, 12)).filter(x => /^CWE-\d+$/.test(x));
      const aff = lkArr(cna.affected, 10).map(a => lkCap(a.vendor, 60) + ' ' + lkCap(a.product, 80)).filter(s => s.trim());
      const sig = []; if(/active/i.test(opt.Exploitation || '')) sig.push({t:'mal', w:0.9, why:'CISA: exploitation is active'}); else if(/poc/i.test(opt.Exploitation || '')) sig.push({t:'sus', w:0.5, why:'CISA: a public proof of concept exists'});
      if(cv && cv.baseScore >= 9) sig.push({t:'sus', w:0.4, why:'CVSS ' + cv.baseScore + ' critical'});
      return {sig, facts:[['CVSS', cv ? cv.baseScore + ' ' + lkCap(cv.baseSeverity, 10) + ' (' + lkCap(cv.version, 4) + ')' : ''], ['Vector', cv ? lkCap(cv.vectorString, 120) : ''], ['Exploitation (CISA)', lkCap(opt.Exploitation, 20)], ['Automatable', lkCap(opt.Automatable, 10)], ['Affects', aff.slice(0, 4).join('; ')], ['Weakness', cwe.join(', ')], ['Published', lkCap(j.cveMetadata && j.cveMetadata.datePublished, 10)], ['Summary', desc.slice(0, 300)]],
        attrs:{cvss:cv ? cv.baseScore : null, sev:cv ? lkCap(cv.baseSeverity, 10) : '', exploitation:lkCap(opt.Exploitation, 20), vendors:aff, cwe, desc}}; }},
  {id:'epss', name:'FIRST EPSS', kinds:['cve'], via:'direct', host:'api.first.org', ttl:24, rel:0.8, about:'Probability the CVE is exploited in the next 30 days.',
    req:(k, v) => ({url:'https://api.first.org/data/v1/epss?cve=' + encodeURIComponent(v)}), web:(k, v) => 'https://www.first.org/epss/',
    parse(j){ const d = lkArr(j.data)[0]; if(!d) return {none:true}; const e = parseFloat(d.epss), p = parseFloat(d.percentile); if(!(e >= 0 && e <= 1)) return {none:true};
      return {sig:e >= 0.5 ? [{t:'mal', w:Math.min(0.8, e), why:'EPSS ' + (e * 100).toFixed(1) + '% chance of exploitation within 30 days'}] : e >= 0.1 ? [{t:'sus', w:0.35, why:'EPSS ' + (e * 100).toFixed(1) + '%'}] : [],
        facts:[['EPSS', (e * 100).toFixed(2) + '% · higher than ' + Math.round(p * 100) + '% of CVEs']], attrs:{epss:e, pct:p}}; }},
  /* ---------- your key, straight from the browser or through the relay ---------- */
  {id:'shodan', name:'Shodan', kinds:LK_KINDS_IP, via:'both', host:'api.shodan.io', ttl:24, rel:0.75, key:{label:'API key', query:'key'}, about:'Full Shodan host record: banners, certificates, JARM, favicon hashes, products and C2 detections.',
    req:(k, v, key) => ({url:'https://api.shodan.io/shodan/host/' + encodeURIComponent(v) + (key ? '?key=' + encodeURIComponent(key) : ''), relay:'shodan/shodan/host/' + encodeURIComponent(v)}), web:(k, v) => 'https://www.shodan.io/host/' + encodeURIComponent(v),
    parse(j){ if(j.error) return /No information/i.test(j.error) ? {none:true, facts:[['Shodan', 'No information']]} : (() => { throw new Error(lkCap(j.error, 120)); })();
      const D = lkArr(j.data, 60), tags = lkArr(j.tags).map(t => lkCap(t, 40)), prods = [...new Set(D.map(d => lkCap(d.product, 60)).filter(Boolean))];
      const certs = D.map(d => d.ssl && d.ssl.cert && d.ssl.cert.fingerprint && d.ssl.cert.fingerprint.sha256).filter(Boolean).map(x => lkCap(x, 64)), jarm = [...new Set(D.map(d => d.ssl && d.ssl.jarm).filter(Boolean).map(x => lkCap(x, 62)))];
      const fav = [...new Set(D.map(d => d.http && d.http.favicon && d.http.favicon.hash).filter(x => Number.isFinite(x)).map(String))], titles = [...new Set(D.map(d => d.http && d.http.title).filter(Boolean).map(t => lkCap(t, 100)))];
      const servers = [...new Set(D.map(d => d.http && d.http.server).filter(Boolean).map(s => lkCap(s, 60)))], cn = [...new Set(D.map(d => d.ssl && d.ssl.cert && d.ssl.cert.subject && d.ssl.cert.subject.CN).filter(Boolean).map(x => lkCap(x, 120)))];
      const sig = [], c2 = prods.filter(p => C2_PRODUCT.test(p)), bj = jarm.map(x => BAD_JARM[x]).filter(Boolean);
      if(c2.length) sig.push({t:'mal', w:0.85, why:'Shodan identifies ' + c2.join(', ')}); if(bj.length) sig.push({t:'sus', w:0.5, why:'TLS fingerprint (JARM) matches ' + bj.join(', ')});
      if(tags.some(t => /^(c2|malware|compromised)$/.test(t))) sig.push({t:'mal', w:0.7, why:'Shodan tags it ' + tags.join(', ')});
      const vulns = Object.keys(j.vulns || {}).filter(c => /^CVE-/.test(c)).slice(0, 200);
      return {sig, facts:[['Organisation', lkCap(j.org, 100)], ['ISP · ASN', lkCap(j.isp, 80) + ' · ' + lkCap(j.asn, 12)], ['Ports', lkArr(j.ports, 100).join(', ')], ['Products', prods.slice(0, 8).join(', ')], ['Page titles', titles.slice(0, 3).join(' | ')], ['Certificate names', cn.slice(0, 4).join(', ')], ['Last update', lkCap(j.last_update, 10)]],
        attrs:{asn:lkCap(j.asn, 12), org:lkCap(j.org, 100), ports:lkArr(j.ports, 200), products:prods, certs, jarm, favicon:fav, titles, servers, certCN:cn, cves:vulns, country:lkCap(j.country_code, 4)},
        related:[...lkRels(j.hostnames, 'domain', 'hostname'), ...lkRels(j.domains, 'domain', 'hosted domain'), ...lkRels(cn.filter(x => !/\*/.test(x)), 'domain', 'certificate name')]}; }},
  /* ---------- through your relay (these services refuse direct browser access) ---------- */
  {id:'vt', name:'VirusTotal', kinds:['ipv4', 'ipv6', 'domain', 'url', ...LK_HASH], via:'relay', host:'www.virustotal.com', ttl:12, rel:0.9, about:'Antivirus and URL-scanner verdicts from ~70 engines, reputation, DNS, certificates, file names and threat labels.',
    req:(k, v) => ({relay:'vt/api/v3/' + (LK_KINDS_IP.includes(k) ? 'ip_addresses/' : k === 'domain' ? 'domains/' : k === 'url' ? 'urls/' : 'files/') + (k === 'url' ? b64url(v) : encodeURIComponent(v))}),
    web:(k, v) => 'https://www.virustotal.com/gui/' + (LK_KINDS_IP.includes(k) ? 'ip-address/' : k === 'domain' ? 'domain/' : k === 'url' ? 'url/' + b64url(v) : 'file/') + (k === 'url' ? '' : encodeURIComponent(v)),
    notFound:/NotFoundError/, parse(j){ const a = (j.data && j.data.attributes) || {}, st = a.last_analysis_stats || {}, m = +st.malicious || 0, s = +st.suspicious || 0, h = +st.harmless || 0, tot = m + s + h + (+st.undetected || 0), sig = [];
      if(m >= 10) sig.push({t:'mal', w:0.95, why:m + '/' + tot + ' VirusTotal engines flag it malicious'}); else if(m >= 3) sig.push({t:'mal', w:0.8, why:m + '/' + tot + ' VirusTotal engines flag it malicious'}); else if(m) sig.push({t:'sus', w:0.45, why:m + '/' + tot + ' VirusTotal engine' + (m > 1 ? 's' : '') + ' flag it'}); else if(s) sig.push({t:'sus', w:0.3, why:s + ' engines find it suspicious'});
      else if(tot > 50 && +a.reputation >= 0) sig.push({t:'ben', w:0.3, why:'0/' + tot + ' VirusTotal engines flag it'});
      if(+a.reputation <= -20) sig.push({t:'mal', w:0.4, why:'Community reputation ' + a.reputation});
      const label = a.popular_threat_classification && lkCap(a.popular_threat_classification.suggested_threat_label, 80), cert = a.last_https_certificate || {};
      const dns = lkArr(a.last_dns_records, 50), ips = dns.filter(r => r.type === 'A' || r.type === 'AAAA').map(r => lkCap(r.value, 45)), ns = dns.filter(r => r.type === 'NS').map(r => lkCap(r.value, 253).toLowerCase());
      if(label) sig.push({t:'mal', w:0.6, why:'Threat label: ' + label});
      return {sig, facts:[['Detections', m + ' malicious · ' + s + ' suspicious · ' + tot + ' engines'], ['Threat label', label], ['Reputation', a.reputation == null ? '' : String(a.reputation)], ['Owner', lkCap(a.as_owner, 80) + (a.asn ? ' · AS' + a.asn : '')], ['Categories', Object.values(a.categories || {}).slice(0, 4).map(x => lkCap(x, 40)).join(', ')], ['Names', lkArr(a.names, 5).map(x => lkCap(x, 80)).join(', ')], ['Type', lkCap(a.type_description, 60)], ['Created', a.creation_date ? new Date(a.creation_date * 1000).toISOString().slice(0, 10) : ''], ['Last analysed', a.last_analysis_date ? new Date(a.last_analysis_date * 1000).toISOString().slice(0, 10) : '']],
        attrs:{vtMal:m, vtTotal:tot, asn:a.asn ? 'AS' + a.asn : '', asname:lkCap(a.as_owner, 100), jarm:a.jarm ? [lkCap(a.jarm, 62)] : [], certs:cert.thumbprint_sha256 ? [lkCap(cert.thumbprint_sha256, 64)] : [], ips, ns, tags:lkArr(a.tags).map(t => lkCap(t, 40)), malware:label ? [label] : [], created:a.creation_date ? a.creation_date * 1000 : 0, registrar:lkCap(a.registrar, 120)},
        related:lkRels(ips.filter(x => /^\d+\.\d+\.\d+\.\d+$/.test(x)), 'ipv4', 'resolves to')}; }},
  {id:'abuse', name:'AbuseIPDB', kinds:LK_KINDS_IP, via:'relay', host:'api.abuseipdb.com', ttl:12, rel:0.8, about:'Abuse reports from the community in the last 90 days, with a confidence score and usage type.',
    req:(k, v) => ({relay:'abuseipdb/api/v2/check?maxAgeInDays=90&ipAddress=' + encodeURIComponent(v)}), web:(k, v) => 'https://www.abuseipdb.com/check/' + encodeURIComponent(v),
    parse(j){ const d = j.data || {}, sc = +d.abuseConfidenceScore || 0, n = +d.totalReports || 0, last = lkDate(d.lastReportedAt), sig = [];
      if(d.isWhitelisted) sig.push({t:'ben', w:0.6, why:'AbuseIPDB: allow-listed'});
      if(sc >= 75) sig.push({t:'mal', w:0.85, why:'AbuseIPDB confidence ' + sc + '% from ' + n + ' reports', ts:last}); else if(sc >= 25) sig.push({t:'sus', w:0.5, why:'AbuseIPDB confidence ' + sc + '% from ' + n + ' reports', ts:last}); else if(n) sig.push({t:'sus', w:0.15, why:n + ' AbuseIPDB reports, low confidence', ts:last});
      return {sig, facts:[['Confidence of abuse', sc + '%'], ['Reports (90 days)', n + ' from ' + (+d.numDistinctUsers || 0) + ' users'], ['Last reported', last ? new Date(last).toISOString().slice(0, 10) : 'never'], ['Usage', lkCap(d.usageType, 60)], ['ISP', lkCap(d.isp, 80)], ['Domain', lkCap(d.domain, 100)]],
        attrs:{abuseScore:sc, isp:lkCap(d.isp, 80), country:lkCap(d.countryCode, 4), usage:lkCap(d.usageType, 60)}, related:lkRels([d.domain], 'domain', 'ISP domain')}; }},
  {id:'gn', name:'GreyNoise Community', kinds:['ipv4'], via:'relay', host:'api.greynoise.io', ttl:12, rel:0.85, about:'Whether the address is mass-scanning the internet, and whether it belongs to a known benign service (RIOT).',
    req:(k, v) => ({relay:'greynoise/v3/community/' + encodeURIComponent(v)}), web:(k, v) => 'https://viz.greynoise.io/ip/' + encodeURIComponent(v), notFound:/IP not observed/i,
    parse(j){ const sig = [], c = String(j.classification || '');
      if(j.riot) sig.push({t:'ben', w:0.7, why:'GreyNoise: known business service' + (j.name ? ' (' + lkCap(j.name, 60) + ')' : '')});
      if(c === 'malicious') sig.push({t:'mal', w:0.7, why:'GreyNoise: malicious internet scanner', ts:lkDate(j.last_seen)}); else if(c === 'benign') sig.push({t:'ben', w:0.55, why:'GreyNoise: benign scanner' + (j.name ? ' (' + lkCap(j.name, 60) + ')' : '')}); else if(j.noise) sig.push({t:'sus', w:0.3, why:'GreyNoise: scanning the internet', ts:lkDate(j.last_seen)});
      return {sig, facts:[['Classification', c || (j.noise ? 'noise' : 'not observed')], ['Name', lkCap(j.name, 80)], ['Last seen', lkCap(j.last_seen, 10)]], attrs:{gn:c || ''}}; }},
  {id:'urlscan', name:'urlscan.io', kinds:['domain', 'ipv4', 'url'], via:'relay', host:'urlscan.io', ttl:12, rel:0.6, about:'Recent scans of pages on the domain or address: servers, IPs, titles and screenshots.',
    req:(k, v) => ({relay:'urlscan/api/v1/search/?size=50&q=' + encodeURIComponent(k === 'ipv4' ? 'ip:"' + v + '"' : k === 'url' ? 'page.url:"' + v + '"' : 'domain:' + v)}), web:(k, v) => 'https://urlscan.io/search/#' + encodeURIComponent(k === 'ipv4' ? 'ip:"' + v + '"' : 'domain:' + v),
    parse(j){ const R = lkArr(j.results, 50), ips = [...new Set(R.map(r => r.page && r.page.ip).filter(Boolean))], doms = [...new Set(R.map(r => r.page && r.page.domain).filter(Boolean))], srv = [...new Set(R.map(r => r.page && r.page.server).filter(Boolean).map(s => lkCap(s, 60)))];
      const mal = R.filter(r => r.verdicts && r.verdicts.overall && r.verdicts.overall.malicious).length, sig = mal ? [{t:'mal', w:0.75, why:mal + ' urlscan scan' + (mal > 1 ? 's' : '') + ' judged malicious'}] : [];
      return {sig, facts:[['Scans', (+j.total || R.length) + ''], ['Latest', R[0] ? lkCap(R[0].task && R[0].task.time, 10) + ' · ' + lkCap(R[0].page && R[0].page.url, 120) : ''], ['Servers', srv.slice(0, 4).join(', ')], ['IPs', ips.slice(0, 6).join(', ')]],
        attrs:{ips:ips.slice(0, 50), servers:srv, asn:R[0] && R[0].page && R[0].page.asn ? lkCap(R[0].page.asn, 12) : ''}, related:[...lkRels(ips, 'ipv4', 'served from', 20), ...lkRels(doms, 'domain', 'seen with', 20)]}; }},
  {id:'crtsh', name:'crt.sh', kinds:['domain'], via:'relay', host:'crt.sh', ttl:24, rel:0.6, about:'Certificate Transparency search: every certificate for the domain and its subdomains.',
    req:(k, v) => ({relay:'crtsh/?output=json&q=' + encodeURIComponent('%.' + v)}), web:(k, v) => 'https://crt.sh/?q=' + encodeURIComponent('%.' + v),
    parse(j, k, v){ const L = lkArr(j, 2000), names = new Set(); L.forEach(c => String(c.name_value || '').split('\n').forEach(n => names.add(n.replace(/^\*\./, '').toLowerCase())));
      const subs = [...names].filter(n => n !== v && n.endsWith('.' + v)); return {facts:[['Certificates', L.length + ''], ['Subdomains', subs.length + '']], attrs:{subs:subs.slice(0, 300)}, related:lkRels(subs, 'domain', 'subdomain', 60)}; }},
  {id:'nvd', name:'NVD', kinds:['cve'], via:'relay', host:'services.nvd.nist.gov', ttl:24 * 3, rel:0.9, about:'NVD CVSS score and CPE products.',
    req:(k, v) => ({relay:'nvd/rest/json/cves/2.0?cveId=' + encodeURIComponent(v)}), web:(k, v) => 'https://nvd.nist.gov/vuln/detail/' + encodeURIComponent(v),
    parse(j){ const c = lkArr(j.vulnerabilities)[0] && j.vulnerabilities[0].cve; if(!c) return {none:true}; const m = c.metrics || {}, b = (m.cvssMetricV40 || m.cvssMetricV31 || m.cvssMetricV30 || m.cvssMetricV2 || [])[0], d = b && b.cvssData || {};
      return {facts:[['NVD CVSS', d.baseScore != null ? d.baseScore + ' ' + lkCap(d.baseSeverity || b.baseSeverity, 10) : ''], ['Vector', lkCap(d.vectorString, 120)], ['Status', lkCap(c.vulnStatus, 30)]], attrs:{nvdCvss:+d.baseScore || null}}; }},
  {id:'tfx', name:'abuse.ch ThreatFox', kinds:['ipv4', 'domain', 'url', ...LK_HASH, 'hostport'], via:'relay', host:'threatfox-api.abuse.ch', ttl:12, rel:0.9, about:'Indicators of malware and C2 shared by the community, with malware family and confidence.',
    req:(k, v) => ({relay:'threatfox/api/v1/', method:'POST', body:JSON.stringify({query:'search_ioc', search_term:v, exact_match:true})}), web:(k, v) => 'https://threatfox.abuse.ch/browse.php?search=ioc%3A' + encodeURIComponent(v),
    parse(j){ if(j.query_status !== 'ok') return {none:true, facts:[['ThreatFox', 'No match']]}; const L = lkArr(j.data, 20), fam = [...new Set(L.map(d => lkCap(d.malware_printable, 60)))], last = Math.max(0, ...L.map(d => lkDate(d.last_seen || d.first_seen)));
      return {sig:[{t:'mal', w:0.9, why:'ThreatFox: ' + fam.join(', ') + ' (' + lkCap(L[0].threat_type_desc || L[0].threat_type, 60) + ')', ts:last}], facts:[['Malware', fam.join(', ')], ['Type', lkCap(L[0].threat_type_desc || L[0].threat_type, 80)], ['Confidence', (+L[0].confidence_level || 0) + '%'], ['First seen', lkCap(L[0].first_seen, 10)]], attrs:{malware:fam}}; }},
  {id:'urlhaus', name:'abuse.ch URLhaus', kinds:['domain', 'ipv4', 'url'], via:'relay', host:'urlhaus-api.abuse.ch', ttl:12, rel:0.9, about:'Whether the host or URL has served malware.',
    req:(k, v) => k === 'url' ? {relay:'urlhaus/v1/url/', method:'POST', body:'url=' + encodeURIComponent(v), form:true} : {relay:'urlhaus/v1/host/', method:'POST', body:'host=' + encodeURIComponent(v), form:true},
    web:(k, v) => 'https://urlhaus.abuse.ch/browse.php?search=' + encodeURIComponent(v),
    parse(j){ if(j.query_status !== 'ok') return {none:true, facts:[['URLhaus', 'No match']]}; const U = lkArr(j.urls, 100), online = U.filter(u => u.url_status === 'online').length, tags = [...new Set(U.flatMap(u => lkArr(u.tags, 10)).map(t => lkCap(t, 40)))];
      const bl = j.blacklists ? Object.entries(j.blacklists).filter(([, s]) => /listed/i.test(s) && !/not/i.test(s)).map(([n]) => lkCap(n, 30)) : [];
      return {sig:[{t:'mal', w:j.url_status === 'online' || online ? 0.9 : 0.75, why:'URLhaus: ' + (U.length || 1) + ' malware URL' + (U.length > 1 ? 's' : '') + (online ? ', ' + online + ' online' : '') + (tags.length ? ' — ' + tags.slice(0, 3).join(', ') : '')}],
        facts:[['Malware URLs', U.length + (online ? ' (' + online + ' online)' : '')], ['Tags', tags.join(', ')], ['Block lists', bl.join(', ')], ['Threat', lkCap(j.threat, 60)]], attrs:{malware:tags}}; }},
  {id:'mb', name:'abuse.ch MalwareBazaar', kinds:LK_HASH, via:'relay', host:'mb-api.abuse.ch', ttl:24, rel:0.95, about:'Malware samples by hash: family, file type, first seen and delivery method.',
    req:(k, v) => ({relay:'malwarebazaar/api/v1/', method:'POST', body:'query=get_info&hash=' + encodeURIComponent(v), form:true}), web:(k, v) => 'https://bazaar.abuse.ch/sample/' + encodeURIComponent(v) + '/',
    parse(j){ if(j.query_status !== 'ok') return {none:true, facts:[['MalwareBazaar', 'Not in the database']]}; const d = lkArr(j.data)[0] || {};
      return {sig:[{t:'mal', w:0.95, why:'MalwareBazaar: ' + (lkCap(d.signature, 60) || 'known malware sample')}], facts:[['Family', lkCap(d.signature, 60)], ['File', lkCap(d.file_name, 120) + ' · ' + lkCap(d.file_type, 20)], ['First seen', lkCap(d.first_seen, 10)], ['Tags', lkArr(d.tags, 10).map(t => lkCap(t, 40)).join(', ')], ['Delivery', lkCap(d.delivery_method, 40)]],
        attrs:{malware:[lkCap(d.signature, 60)].filter(Boolean), sha256:lkCap(d.sha256_hash, 64)}, related:lkRels([d.sha256_hash, d.md5_hash, d.sha1_hash], '', 'same sample')}; }},
];
const lkProv = id => LK_PROVIDERS.find(p => p.id === id);

/* ---------- settings: on/off, keys, relay ---------- */
function lkSettings(){ ctiEnsure(); const I = DB.intel; I.look = I.look && typeof I.look === 'object' ? I.look : {on:{}, keys:{}, relay:{url:'', token:''}}; I.look.on = I.look.on || {}; I.look.keys = I.look.keys || {}; I.look.relay = I.look.relay || {url:'', token:''}; return I.look; }
const lkRelay = () => { const r = lkSettings().relay; return r.url && /^https:\/\/[a-z0-9.-]+(:\d+)?(\/[\w./-]*)?$/i.test(r.url) ? r : null; };
/* how a provider would be reached right now: 'direct', 'relay' or null (not available) */
function lkRoute(p){
  const S = lkSettings(), key = S.keys[p.id] || '';
  if(p.via === 'direct') return 'direct';
  if(p.via === 'both') return key ? 'direct' : lkRelay() ? 'relay' : null;
  return lkRelay() ? 'relay' : null;
}
const lkOn = p => !!lkSettings().on[p.id] && !!lkRoute(p);
const lkFor = k => LK_PROVIDERS.filter(p => p.kinds.includes(k));

/* ---------- the cache (IndexedDB, encrypted with the workspace) ---------- */
async function lkLoad(){
  if(LK.ready) return LK.ready;
  LK.ready = (async () => { try{ const raw = STORE.idb && await IDB.get('cti:look'); const o = raw ? JSON.parse(await openStr(raw)) : {}; LK.cache = new Map(Object.entries(o && typeof o === 'object' ? o : {})); }catch(e){ LK.cache = new Map(); } return true; })();
  return LK.ready;
}
let lkSaveT = null;
function lkSave(){ clearTimeout(lkSaveT); lkSaveT = setTimeout(async () => { if(!STORE.idb || !LK.cache) return;
  const now = Date.now(); for(const [key, r] of LK.cache) if(now - (r.at || 0) > 30 * 864e5) LK.cache.delete(key);                    // keep a month
  if(LK.cache.size > 20000){ const L = [...LK.cache.entries()].sort((a, b) => a[1].at - b[1].at); L.slice(0, LK.cache.size - 20000).forEach(([k]) => LK.cache.delete(k)); }
  await IDB.set('cti:look', await sealStr(JSON.stringify(Object.fromEntries(LK.cache)))); }, 600); }
const lkKey = (pid, k, v) => pid + '|' + k + ':' + v;
const lkCached = (pid, k, v) => LK.cache ? LK.cache.get(lkKey(pid, k, v)) || null : null;
const lkFresh = (p, r) => r && Date.now() - r.at < (p.ttl || 24) * 3600e3;

/* ---------- running one provider ---------- */
async function lkFetch(url, opts = {}){
  const ctl = new AbortController(), to = setTimeout(() => ctl.abort(), opts.timeout || 20000);
  try{
    const res = await fetch(url, {method:opts.method || 'GET', body:opts.body, signal:ctl.signal, credentials:'omit', referrerPolicy:'no-referrer', cache:'no-store', redirect:'follow', headers:opts.headers || {}});
    if(res.status === 429) throw Object.assign(new Error('Rate limited — try again later'), {code:429});
    if(res.status === 401 || res.status === 403) throw Object.assign(new Error('Refused (' + res.status + ') — check the API key or relay token'), {code:res.status});
    const len = +res.headers.get('content-length') || 0; if(len > 20 * 1048576) throw new Error('Answer is over 20 MB');
    const buf = await res.arrayBuffer(); if(buf.byteLength > 20 * 1048576) throw new Error('Answer is over 20 MB');
    return {status:res.status, text:new TextDecoder().decode(buf)};
  }catch(e){ if(e.name === 'AbortError') throw new Error('Timed out'); if(e instanceof TypeError) throw new Error('Blocked — the service does not allow browser access, or you are offline'); throw e; }
  finally{ clearTimeout(to); }
}
/* the URL and headers for a request, direct or through the relay */
function lkWire(p, spec){
  const route = lkRoute(p), key = lkSettings().keys[p.id] || '';
  if(route === 'relay'){ const r = lkRelay(); if(!spec.relay) throw new Error('This lookup is not available through the relay');
    return {url:r.url.replace(/\/+$/, '') + '/' + spec.relay, method:spec.method || 'GET', body:spec.body, headers:{'X-Relay-Token':r.token || '', ...(spec.form ? {'Content-Type':'application/x-www-form-urlencoded'} : spec.body ? {'Content-Type':'application/json'} : {})}}; }
  const h = {...(spec.headers || {})}; if(p.key && p.key.header && key && !h[p.key.header]) h[p.key.header] = (p.key.prefix || '') + key;
  return {url:spec.url, method:spec.method || 'GET', body:spec.body, headers:h};
}
const lkGap = {cs:2000, ht:4000, nvd:6500, vt:15500, abuse:1000, gn:2000, urlscan:2000, otx:1200};          // polite spacing between calls
async function lkPace(id){ const g = lkGap[id] || 400, last = LK.last.get(id) || 0, w = last + g - Date.now(); LK.last.set(id, Math.max(Date.now(), last + g)); if(w > 0) await new Promise(r => setTimeout(r, w)); }
async function lkRun(p, k, v, force){
  await lkLoad();
  const ck = lkKey(p.id, k, v), hit = LK.cache.get(ck); if(!force && lkFresh(p, hit)) return hit;
  if(LK.inflight.has(ck)) return LK.inflight.get(ck);
  const job = (async () => {
    const key = lkSettings().keys[p.id] || '', ctx = {dead:false, json:async (url, opts) => { await lkPace(p.id); if(ctx.dead) throw new Error('cancelled'); const r = await lkFetch(url, opts); try{ return JSON.parse(r.text); }catch(e){ throw new Error('Not JSON'); } }};
    let out;
    try{
      if(p.run) out = await p.run(k, v, ctx, key);
      else {
        await lkPace(p.id);
        const spec = p.req(k, v, key), w = lkWire(p, spec), r = await lkFetch(w.url, w);
        if(r.status === 404 || (p.notFound && p.notFound.test(r.text.slice(0, 400)))) out = {none:true, facts:[[p.name, 'No record']]};
        else if(r.status >= 400) throw new Error('HTTP ' + r.status);
        else { let body = r.text; if(!spec.text){ try{ body = JSON.parse(r.text); }catch(e){ throw new Error('Not JSON'); } } out = p.parse(body, k, v) || {none:true}; }
      }
      out = {ok:true, at:Date.now(), sig:lkArr(out.sig, 20).filter(s => /^(mal|sus|ben)$/.test(s.t)).map(s => ({t:s.t, w:Math.max(0, Math.min(1, +s.w || 0)), why:lkCap(s.why, 240), ts:+s.ts || 0})),
        facts:lkArr(out.facts, 20).filter(f => f && f[1] !== '' && f[1] != null).map(f => [lkCap(f[0], 60), lkCap(f[1], 600)]), attrs:out.attrs || {}, related:lkArr(out.related, 120), none:!!out.none, link:p.web ? E.safeUrl(p.web(k, v)) || '' : ''};
    }catch(e){ ctx.dead = true; out = {ok:false, at:Date.now(), err:lkCap(e.message || e, 200), code:e.code || 0}; }
    LK.cache.set(ck, out); lkSave(); return out;
  })();
  LK.inflight.set(ck, job); try{ return await job; }finally{ LK.inflight.delete(ck); }
}
/* every switched-on provider for one indicator, in parallel; onEach lets the screen fill in as answers arrive */
async function lkInvestigate(k, v, opts = {}){
  const P = lkFor(k).filter(p => opts.all ? !!lkRoute(p) && lkSettings().on[p.id] : lkOn(p)), res = {};
  await Promise.all(P.map(async p => { res[p.id] = await lkRun(p, k, v, opts.force); if(opts.onEach) opts.onEach(p.id, res[p.id]); }));
  return res;
}
/* what is already known, without asking anyone */
function lkKnown(k, v){ const out = {}; for(const p of lkFor(k)){ const r = lkCached(p.id, k, v); if(r) out[p.id] = r; } return out; }
