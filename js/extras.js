/* ==========================================================================
   Pivots, IOC export, print, case import, and the transform workbench.
   ========================================================================== */
/* ---------- one-click lookups on external services (opened in a new tab, nothing fetched here) ---------- */
const PIV = {
  ipv4:[['VirusTotal','https://www.virustotal.com/gui/ip-address/%s'],['AbuseIPDB','https://www.abuseipdb.com/check/%s'],['Shodan','https://www.shodan.io/host/%s'],['Censys','https://search.censys.io/hosts/%s'],['GreyNoise','https://viz.greynoise.io/ip/%s'],['IPinfo','https://ipinfo.io/%s']],
  domain:[['VirusTotal','https://www.virustotal.com/gui/domain/%s'],['urlscan','https://urlscan.io/domain/%s'],['crt.sh','https://crt.sh/?q=%s'],['WHOIS','https://who.is/whois/%s'],['SecurityTrails','https://securitytrails.com/domain/%s/dns'],['Wayback','https://web.archive.org/web/*/%s*']],
  url:[['VirusTotal','https://www.virustotal.com/gui/search/%e'],['urlscan','https://urlscan.io/search/#%e'],['Wayback','https://web.archive.org/web/*/%s']],
  email:[['Have I Been Pwned','https://haveibeenpwned.com/account/%e'],['Hunter','https://hunter.io/email-verifier/%e'],['Google','https://www.google.com/search?q=%22%e%22']],
  handle:[['WhatsMyName','https://whatsmyname.app/?q=%e'],['GitHub','https://github.com/%e'],['Google','https://www.google.com/search?q=%22%e%22']],
  sha256:[['VirusTotal','https://www.virustotal.com/gui/file/%s'],['MalwareBazaar','https://bazaar.abuse.ch/sample/%s/'],['Hybrid Analysis','https://www.hybrid-analysis.com/search?query=%s']],
  md5:[['VirusTotal','https://www.virustotal.com/gui/file/%s'],['Hybrid Analysis','https://www.hybrid-analysis.com/search?query=%s']],
  sha1:[['VirusTotal','https://www.virustotal.com/gui/file/%s'],['Hybrid Analysis','https://www.hybrid-analysis.com/search?query=%s']],
  btc:[['Blockchain.com','https://www.blockchain.com/explorer/addresses/btc/%s'],['mempool.space','https://mempool.space/address/%s']],
  eth:[['Etherscan','https://etherscan.io/address/%s']],
  cve:[['NVD','https://nvd.nist.gov/vuln/detail/%s'],['CISA KEV','https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=%e'],['Exploit-DB','https://www.exploit-db.com/search?cve=%e']],
  person:[['Google','https://www.google.com/search?q=%22%e%22'],['LinkedIn','https://www.linkedin.com/search/results/all/?keywords=%e']],
  organization:[['Google','https://www.google.com/search?q=%22%e%22'],['OpenCorporates','https://opencorporates.com/companies?q=%e']],
  phone:[['Google','https://www.google.com/search?q=%22%e%22'],['WhatsApp','https://wa.me/%s'],['Telegram','https://t.me/%s'],['Sync.me','https://sync.me/search/?number=%e'],['NumLookup','https://www.numlookup.com/?number=%e']],
  ipv6:[['VirusTotal','https://www.virustotal.com/gui/ip-address/%s'],['Shodan','https://www.shodan.io/host/%s'],['IPinfo','https://ipinfo.io/%s'],['bgp.he.net','https://bgp.he.net/ip/%s']],
  social:[['Open profile','https://%s'],['Wayback','https://web.archive.org/web/*/%s*'],['Google','https://www.google.com/search?q=%22%e%22']],
  mac:[['MAC vendors','https://maclookup.app/search/result?mac=%e'],['WiGLE','https://wigle.net/search?netid=%e']],
  asn:[['bgp.he.net','https://bgp.he.net/%s'],['IPinfo','https://ipinfo.io/%s'],['PeeringDB','https://www.peeringdb.com/search?q=%e']],
  ttp:[['MITRE ATT&CK','https://attack.mitre.org/techniques/%t/']],
  coords:[['Google Maps','https://www.google.com/maps?q=%s'],['OpenStreetMap','https://www.openstreetmap.org/?mlat=%a&mlon=%o#map=17/%a/%o'],['Street View','https://www.google.com/maps/@?api=1&map_action=pano&viewpoint=%s']],
  xmr:[['Blockchair','https://blockchair.com/search?q=%s']], ltc:[['Blockchair','https://blockchair.com/litecoin/address/%s']], doge:[['Blockchair','https://blockchair.com/dogecoin/address/%s']], trx:[['Tronscan','https://tronscan.org/#/address/%s']],
  sha512:[['VirusTotal','https://www.virustotal.com/gui/search/%s']],
};
PIV.hostport = PIV.ipv4;
function pivotLinks(kind, value){
  let v = String(value || '').trim(); if(!v) return [];
  if(kind === 'hostport') v = v.split(':')[0];
  if(kind === 'phone') v = v.replace(/^\+/, '');
  if(kind === 'handle') v = v.replace(/^@/, '');
  const [la, lo] = kind === 'coords' ? v.split(',') : ['', ''], tt = kind === 'ttp' ? v.replace('.', '/') : '';
  const base = (PIV[kind] || []).map(([n, t]) => [n, E.safeUrl(t.replace(/%s/g, v).replace(/%e/g, encodeURIComponent(v)).replace(/%a/g, la).replace(/%o/g, lo).replace(/%t/g, tt))]).filter(x => x[1]);
  return base.concat(toolTplLinks(kind, v).filter(x => !base.some(b => b[0].toLowerCase() === x[0].toLowerCase())));
}
/* your own lookup tools: any toolbox entry with a URL template such as https://example.com/search?q={value} */
const TPL_KINDS = [['ipv4','IP address'],['domain','Domain'],['url','URL'],['email','Email'],['handle','Username'],['hash','File hash'],['phone','Phone'],['person','Person name'],['btc','Wallet'],['cve','CVE'],['any','Anything']];
const kindGroup = k => ({md5:'hash', sha1:'hash', sha256:'hash', sha512:'hash', file:'hash', hostport:'ipv4', ipv6:'ipv4', ip:'ipv4', eth:'btc', xmr:'btc', ltc:'btc', trx:'btc', doge:'btc', crypto:'btc', username:'handle', vulnerability:'cve'})[k] || k;
function toolUrl(t, v){ return t.tpl ? E.safeUrl(t.tpl.replace(/\{value\}/g, encodeURIComponent(v)).replace(/\{raw\}/g, v)) : null; }
function toolTplLinks(kind, v){ const g = kindGroup(kind); return DB.tools.filter(t => t.tpl && (t.kinds || []).some(k => k === g || k === 'any')).map(t => [t.name, toolUrl(t, v), t.id]).filter(x => x[1]); }
const SEED_TPL = {'Shodan':['https://www.shodan.io/host/{value}',['ipv4']], 'MalwareBazaar':['https://bazaar.abuse.ch/browse.php?search={value}',['hash']], 'Have I Been Pwned':['https://haveibeenpwned.com/account/{value}',['email']],
  'DB-IP':['https://db-ip.com/{value}',['ipv4']], 'Knowem':['https://knowem.com/checkusernames.php?u={value}',['handle']], 'Certgrep':['https://certgrep.sh/?q={value}',['domain']]};
function ensureToolTpl(){ if(DB.tplSeeded) return; for(const t of DB.tools){ const s = SEED_TPL[t.name]; if(s && !t.tpl){ t.tpl = s[0]; t.kinds = s[1]; } } DB.tplSeeded = true; }
function toolRunDlg(id){
  const t = DB.tools.find(x => x.id === id); if(!t || !t.tpl) return;
  const g = new Set(t.kinds || []), sug = [...derive().ents.values()].filter(x => g.has('any') || g.has(kindGroup(x.k))).slice(0, 12);
  openDlg(dhead('Run ' + t.name) + `<form data-form="toolRun" data-id="${t.id}"><div class="in"><div class="field"><label for="trV">Value</label><input id="trV" required autofocus placeholder="${esc((TPL_KINDS.find(k => k[0] === (t.kinds || [])[0]) || ['','value'])[1].toLowerCase())}"><span class="hint mono">${esc(t.tpl)}</span></div>
    ${sug.length ? `<div class="t3" style="font-size:13px;margin:4px 0 8px">From ${esc(theCase().code)}:</div><div class="wrap">${sug.map(x => `<button type="button" class="chip" data-act="trPick" data-v="${esc(x.v)}">${esc(x.v.length > 40 ? x.v.slice(0, 39) + '…' : x.v)}</button>`).join('')}</div>` : ''}</div>
    <footer><button class="btn" type="button" data-act="dclose">Cancel</button><button class="btn primary" type="submit">${ico('arrow-up-right','sm')}Open</button></footer></form>`);
}
/* research checklist: every lookup for an entity, ticked when you open it */
const rsKey = (kind, value) => kind + ':' + String(value || '').trim();
function rsState(key){ return ((DB.research || {})[key]) || {}; }
function rsMark(key, name, on){ DB.research = DB.research || {}; const s = DB.research[key] || (DB.research[key] = {}); if(on === false) delete s[name]; else s[name] = s[name] || {at:Date.now()}; if(!Object.keys(s).length) delete DB.research[key]; save(); }
function rsProgress(kind, value){ const l = pivotLinks(kind, value); if(!l.length) return null; const st = rsState(rsKey(kind, value)); return {done:l.filter(([n]) => st[n]).length, total:l.length}; }
function pivotSection(kind, value){
  const l = pivotLinks(kind, value); if(!l.length) return '';
  const key = rsKey(kind, value), st = rsState(key), done = l.filter(([n]) => st[n]).length, next = l.find(([n]) => !st[n]);
  return `<div class="isec rs"><h4>Research <span class="t3">${done} of ${l.length} checked</span></h4>
    <div class="rsbar"><i style="width:${Math.round(done / l.length * 100)}%"></i></div>
    <div class="rslist">${l.map(([n, u]) => { const d = st[n]; return `<div class="rsi${d ? ' done' : ''}"><button class="rsc" data-act="rsTick" data-id="${esc(key)}" data-v="${esc(n)}" aria-pressed="${!!d}" aria-label="${d ? 'Mark not checked' : 'Mark checked'}: ${esc(n)}">${d ? ico('check','sm') : ''}</button>
      <a href="${esc(u)}" target="_blank" rel="noopener noreferrer" data-act="rsOpen" data-id="${esc(key)}" data-v="${esc(n)}">${esc(n)}${ico('arrow-up-right','sm')}</a>${d ? `<span class="t3">${esc(E.fmtAgo(Date.now() - d.at))} ago</span>` : ''}</div>`; }).join('')}</div>
    <div class="wrap" style="margin-top:10px">${next ? `<a class="btn sm primary" href="${esc(next[1])}" target="_blank" rel="noopener noreferrer" data-act="rsOpen" data-id="${esc(key)}" data-v="${esc(next[0])}">${ico('arrow-up-right','sm')}Open next: ${esc(next[0])}</a>${l.length - done > 1 ? `<button class="btn sm" data-act="rsAll" data-id="${esc(key)}" data-v="${esc(kind)}">Open all ${l.length - done}</button>` : ''}` : `<span class="chip green sq">${ico('check','sm')}All lookups checked</span>`}
      <button class="btn sm ghost" data-act="copyDefang" data-v="${esc(value)}" title="Copy a defanged version, safe to paste in chat or tickets">${ico('copy','sm')}Copy defanged</button></div></div>`;
}
const RS_ACTS = {
  rsOpen:(id, v) => { rsMark(id, v, true); setTimeout(() => { renderInsp(); if(UI.route.tab === 'entities') renderMain(); }, 50); },
  rsTick:(id, v) => { const on = !rsState(id)[v]; rsMark(id, v, on); renderInsp(); if(UI.route.tab === 'entities') renderMain(); },
  rsAll:(id, v) => { const i = id.indexOf(':'), kind = id.slice(0, i), value = id.slice(i + 1), st = rsState(id), rest = pivotLinks(kind, value).filter(([n]) => !st[n]); let blocked = 0;
    for(const [n, u] of rest){ const w = window.open(u, '_blank'); if(!w){ blocked++; continue; } try{ w.opener = null; }catch(e){} rsMark(id, n, true); }
    renderInsp(); if(blocked) toast(`Your browser blocked ${blocked} tab${blocked > 1 ? 's' : ''}. Allow pop-ups for this site to open them all at once — or use “Open next”.`); }
};
const defang = s => String(s).replace(/^http/i, 'hxxp').replace(/:\/\//, '[://]').replace(/\./g, '[.]').replace(/@/g, '[@]');
const refang = s => String(s).replace(/hxxp/ig, 'http').replace(/\[:\/\/\]/g, '://').replace(/\[\.\]|\(\.\)|\{\.\}/g, '.').replace(/\[@\]|\(at\)|\[at\]/ig, '@');

/* ---------- IOCs for a case ---------- */
function caseIOCs(caseId){
  const D = derive(caseId), m = new Map();
  for(const [id, x] of D.ents) m.set(id, {k:x.k, v:x.v, recs:x.recs.length, vault:D.byKey.has(id)});
  for(const [id] of D.byKey) if(!m.has(id)){ const {k, v} = entSplit(id); m.set(id, {k, v, recs:0, vault:true}); }
  return [...m.entries()].filter(([, x]) => !/^(eventid|path|regkey|sid|account|file|custom)$/.test(x.k)).map(([id, x]) => ({...x, id, verdict:verdictOf(id)}))
    .sort((a, b) => ({malicious:0, suspicious:1, '':2, benign:3}[a.verdict] - {malicious:0, suspicious:1, '':2, benign:3}[b.verdict]) || a.k.localeCompare(b.k));
}
const STIX_PAT = {ipv4:v => `[ipv4-addr:value = '${v}']`, hostport:v => `[ipv4-addr:value = '${v.split(':')[0]}']`, domain:v => `[domain-name:value = '${v}']`, url:v => `[url:value = '${v.replace(/'/g, "\\'")}']`,
  email:v => `[email-addr:value = '${v}']`, sha256:v => `[file:hashes.'SHA-256' = '${v}']`, md5:v => `[file:hashes.MD5 = '${v}']`, sha1:v => `[file:hashes.'SHA-1' = '${v}']`};
const uuid4 = () => crypto.randomUUID ? crypto.randomUUID() : 'xxxxxxxx-xxxx-4xxx-8xxx-xxxxxxxxxxxx'.replace(/x/g, () => (Math.random() * 16 | 0).toString(16));
function exportIOCs(fmt){
  const c = theCase(), list = caseIOCs(c.id), name = slug(c.name) + '-iocs';
  if(!list.length) return toast('No indicators in this case yet');
  if(fmt === 'csv'){ const q = s => '"' + String(s).replace(/"/g, '""') + '"';
    return download(name + '.csv', ['type,value,verdict,in_vault,records,case'].concat(list.map(x => [E.LABEL[x.k] || x.k, x.v, x.verdict || 'unknown', x.vault ? 'yes' : 'no', x.recs, c.code].map(q).join(','))).join('\n'), 'text/csv'); }
  if(fmt === 'txt') return download(name + '-defanged.txt', `# ${c.code} · ${c.name}\n# ${list.length} indicators · defanged · ${new Date().toISOString()}\n\n` + list.map(x => defang(x.v) + (x.verdict ? '    # ' + x.verdict : '')).join('\n'), 'text/plain');
  const now = new Date().toISOString(), ident = {type:'identity', spec_version:'2.1', id:'identity--' + uuid4(), created:now, modified:now, name:'OSINTrix · ' + c.code, identity_class:'individual'};
  const inds = list.filter(x => STIX_PAT[x.k] && (x.verdict === 'malicious' || x.verdict === 'suspicious')).map(x => ({type:'indicator', spec_version:'2.1', id:'indicator--' + uuid4(), created:now, modified:now, created_by_ref:ident.id,
    name:(E.LABEL[x.k] || x.k) + ' ' + x.v, pattern:STIX_PAT[x.k](x.v), pattern_type:'stix', valid_from:now, indicator_types:[x.verdict === 'malicious' ? 'malicious-activity' : 'anomalous-activity'], labels:[c.code]}));
  if(!inds.length) return toast('STIX exports indicators marked malicious or suspicious — mark some first');
  download(name + '.stix.json', JSON.stringify({type:'bundle', id:'bundle--' + uuid4(), objects:[ident, ...inds]}, null, 2), 'application/json');
}
function iocMenu(anchor){
  const r = anchor.getBoundingClientRect(), n = caseIOCs(DB.active).length;
  showMenu(r.left, r.bottom + 6, [{label:'CSV — every indicator with verdicts', icon:'download', fn:() => exportIOCs('csv')}, {label:'Text — defanged, for tickets & chat', icon:'file-text', fn:() => exportIOCs('txt')},
    {label:'STIX 2.1 — malicious & suspicious', icon:'shield-alert', fn:() => exportIOCs('stix')}, {sep:true}, {label:'Whole case as JSON (with files)', icon:'download', fn:() => clickAct('exportCase', DB.active)}], n + ' indicators in ' + theCase().code);
}
/* ---------- print / save as PDF ---------- */
function printReport(){
  const doc = document.querySelector('article.doc'); if(!doc) return;
  let root = $('printRoot'); if(!root){ root = document.createElement('div'); root.id = 'printRoot'; document.body.appendChild(root); }
  root.innerHTML = doc.outerHTML + `<p class="print-foot">Generated with ${esc(BRAND.name)} · ${new Date().toISOString().slice(0, 16).replace('T', ' ')} UTC</p>`;
  const done = () => { root.innerHTML = ''; window.removeEventListener('afterprint', done); }; window.addEventListener('afterprint', done);
  setTimeout(() => window.print(), 30);
}
/* ---------- import a single case ---------- */
function importCase(){
  pickFile('.json,application/json', raw => maybeDecrypt(raw, txt => { let d; try{ d = JSON.parse(txt); }catch(e){ return toast('That file is not JSON'); }
    if(!d || d.format !== 'osintrix-case' || !d.case || !Array.isArray(d.entries)) return toast('Not an OSINTrix case — export one from a case menu');
    const map = new Map(), nid = (old, p) => { const n = uid(p); map.set(old, n); return n; };
    const c = {...d.case, id:uid('c'), updated:Date.now()}; if(DB.cases.some(x => x.code === c.code)) c.code = nextCaseCode(); if(clash(DB.cases, c.name)) c.name = nextName(String(c.name || 'Imported case').trim() + ' (imported)', DB.cases.map(x => x.name));
    const entries = d.entries.map(e => ({...e, id:nid(e.id, 'v'), caseId:c.id}));
    const records = (d.records || []).map(r => ({...r, id:nid(r.id, 'r'), caseId:c.id}));
    const links = (d.links || []).map(l => ({...l, id:uid('l'), caseId:c.id, a:map.get(l.a) || l.a, b:map.get(l.b) || l.b, src:map.get(l.src) || l.src}));
    for(const e of entries) if(e.src) e.src = map.get(e.src) || '';
    if(c.t0) c.t0 = map.get(c.t0) || null;
    DB.cases.push(c); DB.entries.push(...entries); DB.records.push(...records); DB.links.push(...links.filter(l => entries.some(e => e.id === l.a) && entries.some(e => e.id === l.b)));
    if(d.files) filesFromImport(d.files);
    mutate('imported case ' + c.code); hashRecords(); ensurePositions(); DB.active = c.id; go(caseHash(c.id));
    toast(`Imported ${c.code} — ${entries.length} entries, ${records.length} records`); }));
}

/* ---------- transform workbench (Decoder) ---------- */
const b64d = s => { const b = Uint8Array.from(atob(s.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)); return (b.length > 3 && b[1] === 0 && b[3] === 0) ? new TextDecoder('utf-16le').decode(b) : new TextDecoder().decode(b); };
const b64e = s => btoa(String.fromCharCode(...new TextEncoder().encode(s)));
const TX = {
  auto:['Auto-decode','layers','Detects and peels layers — URL, HTML, escapes, Base64, Base32, Base58, hex, binary, char codes, gzip, JWT, Morse, ROT13 — until the text is readable'],
  b64d:['Base64 decode','binary', s => b64d(s)], b64e:['Base64 encode','binary', s => b64e(s)],
  hexd:['Hex decode','hash', s => { const h = s.replace(/0x|\\x|[\s:,-]/gi, ''); if(!/^([0-9a-f]{2})+$/i.test(h)) throw new Error('Not hex'); return new TextDecoder().decode(new Uint8Array(h.match(/../g).map(x => parseInt(x, 16)))); }],
  hexe:['Hex encode','hash', s => [...new TextEncoder().encode(s)].map(b => b.toString(16).padStart(2, '0')).join(' ')],
  urld:['URL decode','link', s => decodeURIComponent(s.replace(/\+/g, ' '))], urle:['URL encode','link', s => encodeURIComponent(s)],
  html:['HTML entities','code', s => { const t = document.createElement('textarea'); t.innerHTML = s; return t.value; }],
  rot13:['ROT13','refresh-cw', s => s.replace(/[a-z]/gi, c => String.fromCharCode((c <= 'Z' ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26))],
  rev:['Reverse','undo-2', s => [...s].reverse().join('')],
  defang:['Defang','shield-check', s => s.split(/(\s+)/).map(w => /\S/.test(w) && E.extract(w).length ? defang(w) : w).join('')], refang:['Refang','shield-alert', s => refang(s)],
  jwt:['JWT decode','key-round', s => { const p = s.trim().split('.'); if(p.length < 2) throw new Error('Not a JWT'); const dj = x => JSON.stringify(JSON.parse(b64d(x)), null, 2); return '// header\n' + dj(p[0]) + '\n\n// payload\n' + dj(p[1]) + (p[2] ? '\n\n// signature not verified' : ''); }],
  iocs:['Extract IOCs','fingerprint', s => { const e = E.extract(s); return e.length ? e.map(x => (E.LABEL[x.k] || x.k).padEnd(11) + ' ' + x.v).join('\n') : '(no indicators found)'; }],
  b32d:['Base32 decode','binary', s => { const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = '', out = []; for(const c of s.toUpperCase().replace(/[=\s]/g, '')){ const i = A.indexOf(c); if(i < 0) throw new Error('Not Base32'); bits += i.toString(2).padStart(5, '0'); } for(let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2)); return new TextDecoder().decode(new Uint8Array(out)); }],
  b58d:['Base58 decode','binary', s => { const A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'; let n = 0n; for(const c of s.trim()){ const i = A.indexOf(c); if(i < 0) throw new Error('Not Base58'); n = n * 58n + BigInt(i); } let h = n.toString(16); if(h.length % 2) h = '0' + h; const lead = (s.match(/^1+/) || [''])[0].length; return new TextDecoder().decode(new Uint8Array([...Array(lead).fill(0), ...(h.match(/../g) || []).map(x => parseInt(x, 16))])); }],
  bin:['Binary → text','binary', s => { const g = s.replace(/[^01]/g, ''); if(g.length < 8) throw new Error('Not binary'); return String.fromCharCode(...(g.match(/.{8}/g) || []).map(x => parseInt(x, 2))); }],
  dec:['Char codes → text','hash', s => { const n = s.match(/\d+/g); if(!n) throw new Error('No numbers'); return String.fromCharCode(...n.map(Number).filter(x => x < 0x110000)); }],
  uni:['Unescape \\x \\u %u','code', s => s.replace(/\\u\{([0-9a-f]+)\}|\\u([0-9a-f]{4})|%u([0-9a-f]{4})|\\x([0-9a-f]{2})|&#x([0-9a-f]+);|&#(\d+);/gi, (m, a, b, c, d, e, f) => String.fromCodePoint(parseInt(a || b || c || d || e, 16) || parseInt(f, 10)))],
  caesar:['Caesar — all shifts','refresh-cw', s => Array.from({length:25}, (_, k) => `ROT${String(k + 1).padStart(2, ' ')}  ` + s.replace(/[a-z]/gi, c => { const b = c <= 'Z' ? 65 : 97; return String.fromCharCode((c.charCodeAt(0) - b + k + 1) % 26 + b); })).join('\n')],
  xor:['XOR — single-byte brute force','key-round', s => { const t = s.trim(); let b; if(/^([0-9a-f]{2}\s*)+$/i.test(t)) b = (t.replace(/\s/g, '').match(/../g)).map(x => parseInt(x, 16)); else { try{ b = [...Uint8Array.from(atob(t.replace(/\s/g, '')), c => c.charCodeAt(0))]; }catch(e){ b = [...new TextEncoder().encode(t)]; } }
    const score = x => { let p = 0; for(const c of x){ const ch = String.fromCharCode(c); p += /[etaoinshrdlu ]/.test(ch) ? 3 : /[a-z]/.test(ch) ? 2 : /[A-Z0-9]/.test(ch) ? 1 : /[{}_.,!?'-]/.test(ch) ? .5 : 0; } return p / x.length; };
    const r = []; for(let k = 1; k < 256; k++){ const x = b.map(v => v ^ k); const sc = score(x); if(x.every(v => v === 9 || v === 10 || v === 13 || (v >= 32 && v < 127))) r.push([sc, k, String.fromCharCode(...x)]); }
    r.sort((a, c) => c[0] - a[0]); return r.length ? r.slice(0, 12).map(([, k, x]) => `key 0x${k.toString(16).padStart(2, '0')}  ${x}`).join('\n') : 'No key gives printable text. Input is read as hex, then Base64, then raw text.'; }],
  morse:['Morse decode','radio', s => { const M = {'.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E','..-.':'F','--.':'G','....':'H','..':'I','.---':'J','-.-':'K','.-..':'L','--':'M','-.':'N','---':'O','.--.':'P','--.-':'Q','.-.':'R','...':'S','-':'T','..-':'U','...-':'V','.--':'W','-..-':'X','-.--':'Y','--..':'Z','-----':'0','.----':'1','..---':'2','...--':'3','....-':'4','.....':'5','-....':'6','--...':'7','---..':'8','----.':'9','.-.-.-':'.','--..--':',','..--.-':'_','-.--.':'(','-.--.-':')','---...':':'};
    return s.trim().replace(/[•·]/g, '.').replace(/[—–_]/g, '-').split(/\s*[\/|]\s*|\s{3,}/).map(w => w.split(/\s+/).map(c => M[c] || (c ? '?' : '')).join('')).join(' '); }],
  gunzip:['Gunzip / inflate (Base64 or hex in)','box', null],
  sha256:['SHA-256','fingerprint', null], sha1:['SHA-1','fingerprint', null],
};
/* ---------- auto-decode: try every decoder, keep the one that gives readable text, repeat ---------- */
function readability(s){
  if(!s) return 0; if(s.includes('�')) return 0; let ok = 0, ctl = 0;
  for(const c of s){ const k = c.codePointAt(0); if(k === 9 || k === 10 || k === 13 || (k >= 32 && k < 127)) ok++; else if(k >= 160 && k < 0x2000 || k >= 0x3000 && k < 0xFFF0) ok += .6; else ctl++; }
  const n = [...s].length; return ctl / n > .05 ? 0 : ok / n;
}
const wordy2 = s => /[A-Za-z]{3,}|\d{1,3}(\.\d{1,3}){3}|[{}()=:\/\\]/.test(s);
function bytesOf(t){ const h = t.replace(/^0x/i, '').replace(/\\x|0x|[\s:,-]/gi, '');
  if(/^([0-9a-f]{2})+$/i.test(h) && h.length >= 8) return ['hex', new Uint8Array(h.match(/../g).map(x => parseInt(x, 16)))];
  const b = t.replace(/\s+/g, ''); if(/^[A-Za-z0-9+/_-]+={0,2}$/.test(b) && b.length >= 8 && b.replace(/=+$/, '').length % 4 !== 1){ try{ return ['Base64', Uint8Array.from(atob(b.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0))]; }catch(e){} }
  return null; }
function textOf(bytes){ if(bytes.length >= 4 && bytes[1] === 0 && bytes[3] === 0) return [new TextDecoder('utf-16le').decode(bytes), ' (UTF-16LE)']; try{ return [new TextDecoder('utf-8', {fatal:true}).decode(bytes), '']; }catch(e){ return [null, '']; } }
async function inflateAny(bytes){ const kind = bytes[0] === 0x1f && bytes[1] === 0x8b ? 'gzip' : bytes[0] === 0x78 && [0x01, 0x5e, 0x9c, 0xda].includes(bytes[1]) ? 'deflate' : null; if(!kind || typeof DecompressionStream === 'undefined') return null;
  try{ return [kind, new Uint8Array(await new Response(new Blob([bytes]).stream().pipeThrough(new DecompressionStream(kind))).arrayBuffer())]; }catch(e){ return null; } }
async function decodeOnce(t){
  const cands = [], add = (name, out) => { if(typeof out === 'string' && out && out !== t && out.trim() !== t.trim()) cands.push([name, out]); };
  const tt = t.trim();
  if(/^eyJ[\w-]+\.[\w-]+(\.[\w-]*)?$/.test(tt)) try{ add('JWT', TX.jwt[2](tt)); }catch(e){}
  if(/%[0-9a-f]{2}/i.test(tt)) try{ add('URL decode', decodeURIComponent(tt.replace(/\+/g, ' '))); }catch(e){}
  if(/&(#x?[0-9a-f]+|[a-z]{2,8});/i.test(tt)) add('HTML entities', TX.html[2](tt));
  if(/\\u\{?[0-9a-f]{4}|\\x[0-9a-f]{2}|%u[0-9a-f]{4}/i.test(tt)) add('Unescape', TX.uni[2](tt));
  if(/^[01]{8}([\s,]*[01]{8})*$/.test(tt)) try{ add('Binary', TX.bin[2](tt)); }catch(e){}
  if(/^\d{2,3}([\s,;]+\d{2,3}){3,}$/.test(tt) && tt.match(/\d+/g).every(n => +n >= 9 && +n < 256)) add('Char codes', TX.dec[2](tt));
  if(/^[.\-\s\/|•·—–_]+$/.test(tt) && /[.\-]/.test(tt) && tt.length >= 5) add('Morse', TX.morse[2](tt));
  const B = bytesOf(tt);
  if(B){ let [nm, by] = B; const z = await inflateAny(by); if(z){ nm += ' → ' + z[0]; by = z[1]; } const [txt, enc] = textOf(by); if(txt != null) add(nm + enc, txt); }
  if(/^[A-Z2-7]+=*$/.test(tt.replace(/\s/g, '')) && tt.replace(/\s|=/g, '').length >= 8) try{ add('Base32', TX.b32d[2](tt)); }catch(e){}
  if(/^[1-9A-HJ-NP-Za-km-z]{8,}$/.test(tt)) try{ add('Base58', TX.b58d[2](tt)); }catch(e){}
  if(/^[A-Za-z0-9+/]{8,}={0,2}$/.test(tt.split('').reverse().join('')) && /^=/.test(tt)) { const r = bytesOf(tt.split('').reverse().join('')); if(r){ const [x] = textOf(r[1]); if(x != null) add('Reversed → Base64', x); } }
  const r13 = TX.rot13[2](tt); if(findFlags(r13).length > findFlags(tt).length) add('ROT13', r13);
  /* best candidate: readable, and looks like language or data */
  let best = null, bs = .88;
  for(const [n, o] of cands){ const sc = readability(o) + (wordy2(o) ? .05 : 0) + (findFlags(o).length ? .2 : 0); if(sc > bs){ bs = sc; best = [n, o]; } }
  return best;
}
async function autoDecode(input){
  const steps = []; let cur = String(input || '');
  /* a long line with one encoded blob in it (e.g. powershell -enc …): decode the blob */
  if(!(await decodeOnce(cur))){ const m = [...cur.matchAll(/[A-Za-z0-9+/]{20,}={0,2}|(?:[0-9a-f]{2}){12,}/gi)].sort((a, b) => b[0].length - a[0].length)[0];
    if(m){ const d = await decodeOnce(m[0]); if(d){ steps.push(['Blob in the line → ' + d[0], d[1]]); cur = d[1]; } } }
  for(let n = 0; n < 8; n++){ const d = await decodeOnce(cur); if(!d) break; steps.push(d); cur = d[1]; }
  return steps;
}
async function runTx(op, input){
  if(op === 'auto'){ const st = await autoDecode(input); return {out:st.length ? st[st.length - 1][1] : '', steps:st}; }
  if(op === 'gunzip'){ if(typeof DecompressionStream === 'undefined') throw new Error('This browser cannot decompress');
    const t = input.trim(); const bytes = /^([0-9a-f]{2}\s*)+$/i.test(t) ? new Uint8Array(t.replace(/\s/g, '').match(/../g).map(x => parseInt(x, 16))) : Uint8Array.from(atob(t.replace(/\s/g, '')), c => c.charCodeAt(0));
    const kind = bytes[0] === 0x1f && bytes[1] === 0x8b ? 'gzip' : bytes[0] === 0x78 ? 'deflate' : 'deflate-raw';
    const out = await new Response(new Blob([bytes]).stream().pipeThrough(new DecompressionStream(kind))).arrayBuffer(); return {out:new TextDecoder().decode(out)}; }
  if(op === 'sha256' || op === 'sha1'){ if(!(crypto.subtle)) throw new Error('Hashing needs a secure context (https)');
    const h = await crypto.subtle.digest(op === 'sha1' ? 'SHA-1' : 'SHA-256', new TextEncoder().encode(input)); return {out:[...new Uint8Array(h)].map(b => b.toString(16).padStart(2, '0')).join('')}; }
  return {out:TX[op][2](input)};
}
function viewDecoder(){
  const op = UI.txOp || 'auto';
  return `<div class="scroll"><div class="page wide">
    ${libHead('Decoder', 'Decode, encode, defang, hash and pull indicators out of anything — entirely in this browser.', `<button class="btn" data-act="decSample">${ico('play','sm')}Try a sample</button>`, '')}
    <div class="txops" role="toolbar" aria-label="Operation">${Object.entries(TX).map(([k, [l, i]]) => `<button data-act="txOp" data-v="${k}" aria-pressed="${op === k}">${ico(i,'sm')}${l}</button>`).join('')}</div>
    <div id="txFlags"></div>
    <div class="txgrid">
      <section class="card txpane"><header><h3>Input</h3><span class="t3" id="txInN">${(UI.decIn || '').length} chars</span><span style="flex:1"></span><button class="btn xs ghost" data-act="txClear">Clear</button></header>
        <label class="sr" for="decIn">Input</label><textarea id="decIn" spellcheck="false" placeholder="Paste an encoded string, a log line, a URL, a JWT…">${esc(UI.decIn || '')}</textarea></section>
      <section class="card txpane"><header><h3 id="txOpName">${esc(TX[op][0])}</h3><span class="t3" id="txOutN"></span><span style="flex:1"></span>
        <button class="btn xs ghost" data-act="txCopy">${ico('copy','sm')}Copy</button><button class="btn xs ghost" data-act="txChain" title="Use the output as the next input">${ico('arrow-left','sm')}Use as input</button></header>
        <pre id="txOut" class="txout" tabindex="0"></pre><div id="txSteps" class="txsteps"></div></section>
    </div>
    <section class="card txents"><header><h3>${ico('fingerprint','sm')}Indicators in the result</h3><span style="flex:1"></span><button class="btn sm primary" data-act="decSave">${ico('plus','sm')}Save to ${esc(theCase().code)} as evidence</button></header><div class="body"><div class="wrap" id="txEnts"></div></div></section>
  </div></div>`;
}
let txT = null;
async function paintTx(){
  const inp = $('decIn'); if(!inp) return; const op = UI.txOp || 'auto', s = inp.value; UI.decIn = s; $('txInN').textContent = s.length + ' chars';
  let res = {out:''}, err = '';
  if(s.trim()) try{ res = await runTx(op, s); }catch(e){ err = e.message || 'Could not transform this input'; }
  const out = $('txOut'); if(!out) return;
  out.textContent = err ? '' : (res.out || (s.trim() && op === 'auto' ? '' : '')); out.classList.toggle('err', !!err);
  if(err) out.textContent = '⚠ ' + err; else if(s.trim() && op === 'auto' && !res.steps.length) out.textContent = 'No encoding recognised — tried URL, HTML entities, escapes, Base64, Base32, Base58, hex, binary, char codes, gzip, JWT, Morse and ROT13. Pick a specific operation above to force one.';
  UI.txOut = err ? '' : res.out || '';
  $('txOutN').textContent = UI.txOut ? UI.txOut.length + ' chars' : '';
  $('txSteps').innerHTML = res.steps && res.steps.length ? res.steps.map(([o], i) => `<span>${i + 1}. ${esc(o)}</span>`).join('<i>→</i>') : '';
  const fb = $('txFlags'); if(fb) fb.innerHTML = flagBox(findFlags((UI.txOut || '') + '\n' + s));
  const ents = E.extract(UI.txOut || '');
  $('txEnts').innerHTML = ents.map(e => `<span class="ent">${kindBadge(e.k)}<span class="v">${esc(e.v)}</span></span>`).join('') || '<span class="t3">None found.</span>';
}
function bindDecoder(){ const i = $('decIn'); if(!i) return; i.oninput = () => { clearTimeout(txT); txT = setTimeout(paintTx, 120); }; paintTx(); }

/* ---------- entities: search + CSV ---------- */
function exportEntities(list){
  const q = s => '"' + String(s).replace(/"/g, '""') + '"';
  download('osintrix-entities.csv', ['type,value,verdict,records,cases'].concat(list.map(e => [E.LABEL[e.k] || e.k, e.v, verdictOf(e.id) || 'unknown', e.recs.length, [...e.cases].map(id => (theCase(id) || {}).code).join(' ')].map(q).join(','))).join('\n'), 'text/csv');
}
