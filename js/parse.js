/* ==========================================================================
   Log parser — turns a line of almost any log into named fields.

   Order: your own parsers (Lab → Log parsers) → built-in formats:
   JSON · CEF · LEEF · Windows event XML · syslog header (+ whatever follows) ·
   Apache/Nginx access · IIS/W3C and Zeek (with their #Fields header) ·
   Cisco ASA · sshd / sudo / su · key=value (FortiGate, Sysmon text, iptables,
   Linux audit, most firewalls) · "Label: value" blocks (WHOIS, headers, Windows text).
   Every vendor field name is then mapped to one common name (src.ip, dst.port,
   user, url…) so filters, entities and graph relations work across products.
   ========================================================================== */
const CANON = {
  'src.ip':'srcip src_ip src sourceip source_ip sourceaddress source.ip ipaddress client_ip clientip c-ip remote_addr remoteaddr src_addr id.orig_h saddr client.ip sourceipaddress srcaddr',
  'src.port':'srcport src_port spt sourceport source_port sport id.orig_p source.port ipport client_port',
  'dst.ip':'dstip dst_ip dst destinationip destination_ip destaddress dest_ip destination.ip server_ip s-ip dst_addr id.resp_h daddr destinationipaddress dstaddr',
  'dst.port':'dstport dst_port dpt destinationport destination_port dport id.resp_p destination.port s-port server_port',
  'nat.ip':'transip nat_src_ip natsrcip xlate_ip',
  'proto':'proto protocol transport ip_proto network.transport',
  'action':'action act disposition outcome event.outcome result status_text',
  'user':'user username usrname suser duser targetusername subjectusername accountname cs-username user_name login account uid_name user.name srcuser dstuser',
  'domain':'query queryname qname dns.query dns_query question.name destinationhostname dest_host server_name sni tls.server_name http_host cs-host',
  'host':'devname hostname computer dvchost device_name devicename host.name agent.hostname',
  'method':'method http_method requestmethod cs-method request_method http.request.method verb',
  'url':'url uri cs-uri-stem request_uri requesturl request url.full uri_path path',
  'status':'status http_status sc-status response_code statuscode http.response.status_code status_code',
  'ua':'user_agent http_user_agent cs(user-agent) requestclientapplication useragent user_agent.original agent',
  'referer':'referer referrer cs(referer) http_referer',
  'bytes.out':'sentbyte bytes_out sc-bytes bytesout sent_bytes orig_bytes',
  'bytes.in':'rcvdbyte bytes_in cs-bytes bytesin received_bytes resp_bytes rcvd_bytes',
  'process':'image process newprocessname proc exe processname comm process.executable process_path',
  'cmd':'commandline cmdline command cmd processcommandline process.command_line',
  'parent':'parentimage parentprocessname parent_process ppid_name',
  'file':'targetfilename filename fname file_name objectname file.path',
  'hash':'hashes sha256 md5 hash filehash file.hash.sha256',
  'event.id':'eventid logid event_id signature_id eventcode event.code',
  'event.type':'type subtype category cat eventtype event.category logtype',
  'severity':'level severity pri priority log.level',
  'app':'app application service appcat app_name',
  'rule':'policyid rule rule_name policy signature attack policyname rulename',
  'country':'srccountry dstcountry country geoip_country',
  'session':'sessionid session_id uid',
  'duration':'duration elapsed_time',
  'mac':'srcmac dstmac mac src_mac dst_mac',
  'logon.type':'logontype logon_type',
  'iface':'srcintf dstintf in out interface'
};
const ALIAS = (() => { const m = new Map(); for(const [c, list] of Object.entries(CANON)) for(const a of list.split(' ')) if(!m.has(a)) m.set(a, c); return m; })();
const PROTO_N = {1:'ICMP', 6:'TCP', 17:'UDP', 47:'GRE', 50:'ESP', 58:'ICMPv6'};

/* ---------- helpers ---------- */
function kvParse(s){
  const out = {}; let n = 0;
  const re = /([A-Za-z_][\w.\-()]{0,48})=(?:"((?:[^"\\]|\\.)*)"|'([^']*)'|((?:(?![A-Za-z_][\w.\-()]{0,48}=)[^\s,;])+|))/g; let m;
  while((m = re.exec(s)) !== null){ const k = m[1], v = m[2] != null ? m[2] : m[3] != null ? m[3] : m[4]; if(!k || out[k] != null) continue; out[k] = v; n++; if(n > 200) break; }
  return n >= 2 ? out : null;
}
function cefExt(s){ const out = {}; const re = /([A-Za-z0-9_]+)=((?:[^=\\]|\\.)*?)(?=\s+[A-Za-z0-9_]+=|$)/g; let m; while((m = re.exec(s)) !== null) out[m[1]] = m[2].replace(/\\([=\\|])/g, '$1').trim(); return out; }
function flat(o, p = '', out = {}){ for(const [k, v] of Object.entries(o || {})){ const key = p ? p + '.' + k : k; if(v && typeof v === 'object' && !Array.isArray(v)) flat(v, key, out); else out[key] = Array.isArray(v) ? v.join(', ') : v == null ? '' : String(v); } return out; }
const SYSLOG = /^(?:<(\d{1,3})>)?(?:1\s+)?((?:\d{4}-\d\d-\d\dT[\d:.]+(?:Z|[+-]\d\d:?\d\d)?)|(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d))\s+([\w.\-:]+)\s+([\w.\-/]+?)(?:\[(\d+)\])?:\s+([\s\S]*)$/;

/* ---------- built-in formats; each returns {format, fields} or null ---------- */
const BUILTIN = [
  ['JSON', s => { const t = s.trim(); if(!/^\{[\s\S]*\}$/.test(t)) return null; try{ return flat(JSON.parse(t)); }catch(e){ return null; } }],
  ['CEF', s => { const m = s.match(/CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)$/); if(!m) return null;
    return Object.assign({'cef.vendor':m[2], 'cef.product':m[3], 'cef.version':m[4], signature_id:m[5], name:m[6], severity:m[7]}, cefExt(m[8])); }],
  ['LEEF', s => { const m = s.match(/LEEF:([\d.]+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(?:(x[0-9a-f]{2}|.)\|)?(.*)$/i); if(!m) return null;
    const d = m[6] ? (m[6].length > 1 ? String.fromCharCode(parseInt(m[6].slice(1), 16)) : m[6]) : '\t', o = {'leef.vendor':m[2], 'leef.product':m[3], eventid:m[5]};
    for(const p of m[7].split(d)){ const i = p.indexOf('='); if(i > 0) o[p.slice(0, i).trim()] = p.slice(i + 1).trim(); } return o; }],
  ['Windows event XML', s => { if(!/<Event[\s>][\s\S]*<EventID/i.test(s)) return null; const o = {};
    for(const m of s.matchAll(/<(EventID|Level|Task|Opcode|Keywords|Channel|Computer|Provider)\b([^>]*)>([^<]*)<\/\1>|<(TimeCreated|Provider|Execution|Security)\s([^>]*)\/?>/gi)){
      if(m[1]) o[m[1]] = m[3] || ((m[2].match(/Name="([^"]*)"/) || [])[1] || ''); if(m[4]) for(const a of m[5].matchAll(/(\w+)="([^"]*)"/g)) o[m[4] + '.' + a[1]] = a[2]; }
    for(const m of s.matchAll(/<Data Name="([^"]+)">([^<]*)<\/Data>/g)) o[m[1]] = m[2]; return Object.keys(o).length ? o : null; }],
  ['Web access log', s => { const m = s.match(/^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+(HTTP\/[\d.]+)"\s+(\d{3})\s+(\d+|-)(?:\s+"([^"]*)"\s+"([^"]*)")?/); if(!m) return null;
    return {client_ip:m[1], user:m[2] === '-' ? '' : m[2], time:m[3], method:m[4], url:m[5], proto_http:m[6], status:m[7], bytes_out:m[8] === '-' ? '' : m[8], referer:m[9] || '', user_agent:m[10] || ''}; }],
  ['Cisco ASA', s => { const m = s.match(/%(?:ASA|FTD)-(\d)-(\d{6}):\s*(.*)$/); if(!m) return null; const t = m[3], o = {severity:m[1], eventid:m[2], message:t};
    const c = t.match(/(Built|Teardown|Deny|Denied)\s+(inbound|outbound)?\s*(\w+)\s+(?:connection\s+\d+\s+)?(?:for|from|src)\s+\S*?:?([\d.]+)\/(\d+)(?:\s*\([^)]*\))?\s+(?:to|dst)\s+\S*?:?([\d.]+)\/(\d+)/i);
    if(c) Object.assign(o, {action:c[1].toLowerCase(), direction:c[2] || '', proto:c[3], src_ip:c[4], src_port:c[5], dst_ip:c[6], dst_port:c[7]}); return o; }],
  ['SSH / sudo', s => { let m = s.match(/(Accepted|Failed)\s+(password|publickey|keyboard-interactive\/pam)\s+for\s+(invalid user\s+)?(\S+)\s+from\s+([\da-f.:]+)\s+port\s+(\d+)/i);
    if(m) return {action:m[1].toLowerCase() === 'accepted' ? 'login-success' : 'login-failure', auth_method:m[2], invalid_user:m[3] ? 'yes' : 'no', user:m[4], src_ip:m[5], src_port:m[6], app:'sshd'};
    m = s.match(/Invalid user\s+(\S+)\s+from\s+([\da-f.:]+)(?:\s+port\s+(\d+))?/i); if(m) return {action:'invalid-user', user:m[1], src_ip:m[2], src_port:m[3] || '', app:'sshd'};
    m = s.match(/sudo:\s+(\S+)\s*:\s*(?:.*?;\s*)?TTY=(\S+)\s*;\s*PWD=(\S+)\s*;\s*USER=(\S+)\s*;\s*COMMAND=(.*)$/); if(m) return {user:m[1], tty:m[2], pwd:m[3], target_user:m[4], cmd:m[5], app:'sudo'};
    return null; }],
  ['W3C / Zeek', (s, all) => { const h = (all || '').match(/^#fields[:\s]+(.+)$/im); if(!h) return null; const names = h[1].trim().split(/\t|\s+/), sep = /\t/.test(s) ? '\t' : ' ', vals = s.split(sep);
    if(vals.length < names.length - 1 || /^#/.test(s)) return null; const o = {}; names.forEach((n, i) => { if(vals[i] != null && vals[i] !== '-') o[n] = vals[i]; }); return o; }],
  ['key=value', s => kvParse(s)],
  ['Label: value', s => { const lines = s.split('\n'); if(lines.length < 3) return null; const o = {}; let n = 0;
    for(const l of lines){ const m = l.match(/^\s*([A-Za-z][\w .\/()-]{1,40}?)\s*:\s+(.+?)\s*$/); if(m && !/^https?$/i.test(m[1])){ const k = m[1].trim(); if(o[k] == null){ o[k] = m[2]; n++; } } }
    return n >= 3 ? o : null; }]
];

/* ---------- your own parsers (regex with named groups) ---------- */
function userParsers(){ return (DB.parsers || []).filter(p => p.on !== false && p.re); }
function runUserParser(p, s){ try{ const re = new RegExp(p.re, p.flags || 'i'); const m = s.match(re); if(!m || !m.groups) return null; const o = {}; for(const [k, v] of Object.entries(m.groups)) if(v != null && v !== '') o[k.replace(/__/g, '.')] = v; return Object.keys(o).length ? o : null; }catch(e){ return null; } }

/* ---------- normalise ---------- */
function normalise(fields){
  const norm = {}, extra = (DB.parserAliases || {});
  for(const [k, v] of Object.entries(fields)){ if(v == null || v === '' || v === '-') continue; const low = k.toLowerCase(), c = extra[low] || ALIAS.get(low) || (CANON[low] ? low : null);
    if(c && norm[c] == null){ let x = String(v); if(c === 'proto' && PROTO_N[x]) x = PROTO_N[x]; norm[c] = x; } }
  if(fields.date && fields.time && !norm.time) norm.time = fields.date + ' ' + fields.time;
  else for(const k of ['@timestamp','timestamp','time','UtcTime','TimeCreated.SystemTime','eventtime','rt','ts','datetime','event_time','_time']){ const v = fields[k]; if(v){ norm.time = String(v); break; } }
  if(norm.url && !norm.domain){ const h = (norm.url.match(/^https?:\/\/([^/:?#]+)/i) || [])[1]; if(h) norm.domain = h; }
  return norm;
}
const P_CACHE = new Map();
function parseLog(text, all){
  const s = String(text || ''); if(!s.trim()) return null; const key = s.length > 4000 ? null : s;
  if(key && P_CACHE.has(key)) return P_CACHE.get(key);
  let format = '', fields = null;
  for(const p of userParsers()){ const f = runUserParser(p, s); if(f){ format = p.name; fields = f; break; } }
  if(!fields){ let body = s, pre = {};
    const sy = s.match(SYSLOG); if(sy){ pre = {syslog_pri:sy[1] || '', syslog_time:sy[2], hostname:sy[3], program:sy[4], pid:sy[5] || ''}; body = sy[6]; }
    for(const [name, fn] of BUILTIN){ const f = fn(body, all); if(f && Object.keys(f).length){ format = (sy ? 'Syslog · ' : '') + name; fields = Object.assign({}, pre, f); break; } }
    if(!fields && sy){ format = 'Syslog'; fields = Object.assign(pre, {message:body}); } }
  if(fields && !fields.EventID){ const ev = s.match(/\bEventID[:= ]\s*(\d{1,5})\b/i); if(ev) fields.EventID = ev[1]; }
  if(fields && fields.logid && (fields.devname || fields.vd)) format = 'FortiGate (' + format + ')';
  else if(fields && fields['cef.vendor']) format = 'CEF · ' + fields['cef.vendor'] + ' ' + fields['cef.product'];
  else if(fields && fields.EventID && (fields.Image || fields.CommandLine || fields.QueryName)) format = format.includes('XML') ? 'Sysmon (XML)' : 'Sysmon (' + format + ')';
  const out = fields ? {format, fields, norm:normalise(fields)} : null;
  if(key){ if(P_CACHE.size > 3000) P_CACHE.clear(); P_CACHE.set(key, out); }
  return out;
}
const recParsed = r => parseLog(r.body);

/* entities that only the fields reveal: ports, accounts, processes */
function fieldEnts(P){
  if(!P) return []; const n = P.norm, out = [];
  const ip = v => v && (/^\d{1,3}(\.\d{1,3}){3}$/.test(v) ? 'ipv4' : E.validIPv6(v) ? 'ipv6' : null);
  if(n['dst.ip'] && n['dst.port'] && ip(n['dst.ip']) === 'ipv4') out.push({k:'hostport', v:n['dst.ip'] + ':' + n['dst.port']});
  if(n.user && !/^(-|n\/a|none|system|local service|network service|\$)$/i.test(n.user) && n.user.length < 64) out.push({k:'account', v:n.user});
  if(n.process){ const b = n.process.split(/[\\/]/).pop(); if(/\.\w{2,4}$/.test(b)) out.push({k:'file', v:b.toLowerCase()}); }
  if(n.domain && /\./.test(n.domain) && !ip(n.domain)) out.push({k:'domain', v:n.domain.toLowerCase().replace(/\.$/, '')});
  return out;
}
const XMLNS = /(^|\.)(schemas\.microsoft\.com|www\.w3\.org|schemas\.xmlsoap\.org|schemas\.openxmlformats\.org|purl\.org|ns\.adobe\.com)(\/|$)/i;
function extractRich(text){
  const base = E.extract(text).filter(e => !(/xmlns/.test(text) && (e.k === 'url' || e.k === 'domain') && XMLNS.test(e.k === 'url' ? (e.v.match(/^https?:\/\/([^/]+)/) || [])[1] + '/' : e.v))), seen = new Set(base.map(e => e.k + ':' + e.v)), lines = String(text || '').split('\n').filter(l => l.trim());
  const add = lines.length > 1 ? lines.slice(0, 500).flatMap(l => fieldEnts(parseLog(l, text))) : fieldEnts(parseLog(text));
  for(const e of add){ const k = e.k + ':' + e.v; if(!seen.has(k)){ seen.add(k); base.push(e); } }
  return base;
}
/* a readable title for a structured log line */
function parsedTitle(P){
  if(!P || /Label: value/.test(P.format)) return ''; const n = P.norm, parts = [];
  const vendor = P.format.replace(/\s*\(.*\)$/, '').replace(/^Syslog · /, '');
  if(n['src.ip'] || n['dst.ip']) parts.push([n.proto, (n['src.ip'] || '?') + (n['src.port'] ? ':' + n['src.port'] : ''), '→', (n['dst.ip'] || n.domain || '?') + (n['dst.port'] ? ':' + n['dst.port'] : '')].filter(Boolean).join(' '));
  else if(n.method || n.url) parts.push([n.method, n.url, n.status].filter(Boolean).join(' '));
  if(n.action) parts.push(n.action); if(n.user && !parts.join(' ').includes(n.user)) parts.push('user ' + n.user);
  if(n.app && parts.length < 3) parts.push(n.app); if(n.process) parts.push(n.process.split(/[\\/]/).pop()); if(n['event.id'] && parts.length < 2) parts.unshift('Event ' + n['event.id']);
  return parts.length ? (parts.join(' · ') + (/key=value|JSON/.test(vendor) ? '' : ' — ' + vendor)).slice(0, 110) : '';
}
/* the one-line summary shown in capture and the record panel */
function parsedLine(P){
  if(!P) return ''; const n = P.norm, b = x => { x = +x; return !x && x !== 0 ? '' : x < 1024 ? x + ' B' : x < 1048576 ? (x / 1024).toFixed(1) + ' KB' : (x / 1048576).toFixed(1) + ' MB'; };
  const bits = [];
  if(n['src.ip'] || n['dst.ip']) bits.push(`<span class="mono">${esc((n['src.ip'] || '?') + (n['src.port'] ? ':' + n['src.port'] : ''))} → ${esc((n['dst.ip'] || n.domain || '?') + (n['dst.port'] ? ':' + n['dst.port'] : ''))}</span>`);
  if(n.method || n.url) bits.push(`<span class="mono">${esc([n.method, n.url].filter(Boolean).join(' ').slice(0, 80))}</span>${n.status ? ` <b>${esc(n.status)}</b>` : ''}`);
  for(const k of ['proto','app','action','user','process','event.id','rule']) if(n[k] && !(k === 'app' && bits.length > 3)) bits.push(`<span class="pfx">${esc({proto:'', app:'', action:'', user:'user ', process:'', 'event.id':'event ', rule:'rule '}[k])}</span>${esc(k === 'process' ? n[k].split(/[\\/]/).pop() : n[k])}`);
  if(n['bytes.out'] || n['bytes.in']) bits.push(`${b(n['bytes.out'] || 0)} out · ${b(n['bytes.in'] || 0)} in`);
  return bits.map(x => `<span class="pb">${x}</span>`).join('<i class="psep"></i>');
}
function fieldsSection(r){
  const P = recParsed(r); if(!P || (/Label: value/.test(P.format) && Object.keys(P.norm).length < 2)) return '';
  const n = P.norm, all = Object.entries(P.fields).filter(([, v]) => v !== '' && v != null);
  const row = (k, v, canon) => `<tr><th>${esc(k)}</th><td><button class="fv" data-act="fieldFilter" data-v="${esc((canon || k) + ':' + (/\s/.test(v) ? '"' + v + '"' : v))}" title="Filter the timeline to this value">${esc(String(v).slice(0, 300))}</button></td></tr>`;
  return `<div class="isec"><h4>Parsed fields <span class="t3">${esc(P.format)} · ${all.length}</span></h4>
    ${parsedLine(P) ? `<div class="pline">${parsedLine(P)}</div>` : ''}
    ${Object.keys(n).length ? `<table class="ftab">${Object.entries(n).map(([k, v]) => row(k, v, k)).join('')}</table>` : ''}
    <details class="fall"><summary>All ${all.length} original fields</summary><table class="ftab">${all.map(([k, v]) => row(k, v)).join('')}</table></details></div>`;
}
/* timeline filter on any field: dst.port:443  action:server-rst  user:admin */
function fieldMatch(r, name, val){
  const P = recParsed(r); if(!P) return false; name = name.toLowerCase();
  const v = P.norm[name] != null ? P.norm[name] : (Object.entries(P.fields).find(([k]) => k.toLowerCase() === name) || [])[1];
  if(v == null) return false; const s = String(v).toLowerCase(); return /^[<>]=?\d/.test(val) ? (val[0] === '>' ? +s > +val.replace(/[<>=]/g, '') : +s < +val.replace(/[<>=]/g, '')) : (s === val || s.includes(val));
}

/* ---------- Lab → Log parser ---------- */
const CANON_NAMES = Object.keys(CANON).concat(['time']);
function genRegex(line){
  const rules = [
    [/\b\d{4}-\d\d-\d\d[T ][\d:.]+(?:Z|[+-]\d\d:?\d\d)?/g, 'time', '\\S+(?: [\\d:.]+)?'],
    [/\b[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d/g, 'time', '\\w{3}\\s+\\d{1,2}\\s+[\\d:]+'],
    [/https?:\/\/\S+/g, 'url', '\\S+'], [/[\w.+-]+@[\w-]+(?:\.[\w-]+)+/g, 'email', '\\S+@\\S+'],
    [/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, 'ip', '[\\d.]+'], [/\b[a-f0-9]{32,64}\b/gi, 'hash', '[a-fA-F0-9]+'],
    [/(?<=\b(?:user|for|login|account|username|by)[=:\s]\s*)(?!from\b|invalid\b)[A-Za-z][\w.\\-]*/gi, 'user', '\\S+'],
    [/"[^"]*"/g, '', '"[^"]*"'], [/\b\d+\b/g, 'num', '\\d+']];
  const toks = [];
  for(const [re, kind, pat] of rules){ re.lastIndex = 0; let m; while((m = re.exec(line)) !== null){ const a = m.index, b = a + m[0].length; if(toks.some(t => a < t.b && b > t.a)) continue; toks.push({a, b, kind, pat, text:m[0]}); } }
  toks.sort((x, y) => x.a - y.a); let ips = 0, out = '^', at = 0; const used = new Set();
  const lit = t => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\s+/g, '\\s+');
  const nm = n => { let k = n, i = 2; while(used.has(k)) k = n + i++; used.add(k); return k; };
  toks.forEach((t, i) => { out += lit(line.slice(at, t.a)); at = t.b; const prev = toks[i - 1], gap = prev ? line.slice(prev.b, t.a) : '';
    if(t.kind === 'ip'){ ips++; t.g = nm(ips === 1 ? 'src__ip' : ips === 2 ? 'dst__ip' : 'ip'); out += `(?<${t.g}>${t.pat})`; }
    else if(t.kind === 'num' && prev && prev.kind === 'ip' && /^(?:[:/]|\s+port\s+)$/i.test(gap)){ out += `(?<${nm(prev.g.replace('ip', 'port'))}>\\d+)`; }
    else if(t.kind === 'time' || t.kind === 'url' || t.kind === 'email' || t.kind === 'hash' || t.kind === 'user'){ out += `(?<${nm(t.kind === 'email' ? 'user' : t.kind)}>${t.pat})`; }
    else out += t.pat; });
  out += lit(line.slice(at)).replace(/\\s\+$/, '');
  return out;
}
function labParse(){
  const v = UI.lpIn != null ? UI.lpIn : `date=2019-05-10 time=11:50:48 logid="0001000014" type="traffic" subtype="local" level="notice" vd="vdom1" eventtime=1557514248379911176 srcip=172.16.200.254 srcport=62024 srcintf="port11" srcintfrole="undefined" dstip=172.16.200.2 dstport=443 dstintf="vdom1" dstintfrole="undefined" sessionid=107478 proto=6 action="server-rst" policyid=0 policytype="local-in-policy" service="HTTPS" dstcountry="Reserved" srccountry="Reserved" trandisp="noop" app="Web Management(HTTPS)" duration=5 sentbyte=1247 rcvdbyte=1719 sentpkt=5 rcvdpkt=6 appcat="unscanned"`;
  const P = DB.parsers || [], A = Object.entries(DB.parserAliases || {});
  return `<div class="lp">
    <section class="card"><header><h3>${ico('scan','sm')} Try a log line</h3><span class="t3">paste one or many lines</span></header><div class="body">
      <label class="sr" for="lpIn">Log lines</label><textarea id="lpIn" class="inp code" rows="6" spellcheck="false">${esc(v)}</textarea>
      <div id="lpOut">${lpOut(v)}</div></div></section>
    <div class="stack">
      <section class="card"><header><h3>${ico('file-code','sm')} My parsers</h3><button class="btn xs primary" data-act="lpNew">${ico('plus','sm')}New</button></header><div class="body flush">
        ${P.length ? P.map(p => `<div class="binrow"><label class="sw" title="On / off"><input type="checkbox" data-act="lpToggle" data-id="${p.id}"${p.on !== false ? ' checked' : ''}><span></span></label><div class="main2"><b>${esc(p.name)}</b><small class="mono">${esc(p.re.slice(0, 60))}${p.re.length > 60 ? '…' : ''}</small></div><button class="btn xs" data-act="lpEdit" data-id="${p.id}">${ico('pencil','sm')}Edit</button></div>`).join('')
          : `<p class="t3" style="padding:14px 18px;margin:0;font-size:13.5px">Most logs are understood out of the box. For a format that is not — a custom app, an odd firewall — write a regular expression with named groups, or let <b>Build from sample</b> draft one from the line on the left. Your parsers run before the built-in ones.</p>`}</div></section>
      <section class="card"><header><h3>${ico('arrow-right-left','sm')} Field names</h3><button class="btn xs" data-act="lpAliasAdd">${ico('plus','sm')}Add</button></header><div class="body">
        <p class="t3" style="margin:0 0 10px;font-size:13px">Tell the parser what a vendor's field means, e.g. <span class="mono">cip</span> → <span class="mono">src.ip</span>. About ${ALIAS.size} common names are already known.</p>
        ${A.map(([k, c]) => `<div class="lpal"><span class="mono">${esc(k)}</span>${ico('arrow-right','sm')}<span class="mono">${esc(c)}</span><button class="iconbtn" data-act="lpAliasDel" data-v="${esc(k)}" aria-label="Remove">${ico('x','sm')}</button></div>`).join('') || ''}</div></section>
      <section class="card"><header><h3>${ico('book-open','sm')} Understood out of the box</h3></header><div class="body"><p class="t3" style="margin:0;font-size:13px;line-height:1.7">${BUILTIN.map(b => b[0]).join(' · ')} · syslog headers (RFC 3164 / 5424) in front of any of them. Fields are mapped to common names — ${CANON_NAMES.slice(0, 18).map(n => `<span class="mono">${n}</span>`).join(', ')}… — so <span class="mono">dst.port:443</span> or <span class="mono">action:deny</span> work in every case timeline.</p></div></section>
    </div></div>`;
}
function lpOut(text){
  const lines = String(text || '').split(/\r?\n/).filter(l => l.trim() && !/^#/.test(l)).slice(0, 30); if(!lines.length) return '';
  const first = parseLog(lines[0], text), ents = extractRich(lines[0]), rels = recordRelations({id:'x', title:'', body:lines[0], ents});
  const nm = first ? first.norm : {};
  return `${first ? `<div class="lp-h"><span class="chip accent sq">${esc(first.format)}</span><span class="t3">${Object.keys(first.fields).length} fields · ${Object.keys(nm).length} understood</span></div>
      ${parsedLine(first) ? `<div class="pline">${parsedLine(first)}</div>` : ''}
      <div class="lp-g"><table class="ftab">${Object.entries(nm).map(([k, v]) => `<tr><th>${esc(k)}</th><td class="mono">${esc(v)}</td></tr>`).join('')}</table>
        <details class="fall" open><summary>All ${Object.keys(first.fields).length} original fields</summary><table class="ftab">${Object.entries(first.fields).map(([k, v]) => `<tr><th>${esc(k)}${ALIAS.has(k.toLowerCase()) || (DB.parserAliases || {})[k.toLowerCase()] ? ` <span class="t3">→ ${esc((DB.parserAliases || {})[k.toLowerCase()] || ALIAS.get(k.toLowerCase()))}</span>` : ''}</th><td class="mono">${esc(v)}</td></tr>`).join('')}</table></details></div>`
    : `<div class="note amber"><span class="ic">${ico('triangle-alert','sm')}</span><div><b>Not a format I recognise.</b> Indicators are still extracted. To get named fields, <button class="linkbtn" data-act="lpGen">build a parser from this line</button>.</div></div>`}
    <div class="lp-sec"><h5>Entities <span class="t3">${ents.length}</span></h5><div class="wrap">${ents.map(e => `<span class="ent">${kindBadge(e.k)}<span class="v">${esc(e.v)}</span></span>`).join('') || '<span class="t3">None</span>'}</div></div>
    ${rels.length ? `<div class="lp-sec"><h5>Relations it states <span class="t3">${rels.length}</span></h5>${rels.map(r => `<div class="lp-rel"><span class="mono">${esc(entSplit(r.a).v)}</span><b>${esc(r.label)}</b><span class="mono">${esc(entSplit(r.b).v)}</span><span class="t3">${esc(r.why)}</span></div>`).join('')}</div>` : ''}
    ${lines.length > 1 ? `<div class="lp-sec"><h5>All ${lines.length} lines</h5><table class="ftab lp-all">${lines.map(l => { const p = parseLog(l, text); return `<tr><th>${p ? esc(p.format) : '<span style="color:var(--amber)">unknown</span>'}</th><td>${p ? parsedLine(p) || esc(l.slice(0, 120)) : esc(l.slice(0, 120))}</td></tr>`; }).join('')}</table></div>` : ''}
    <div class="lp-sec"><button class="btn sm" data-act="lpGen">${ico('sparkles','sm')}Build a parser from the first line</button></div>`;
}
function parserDlg(id, pre){
  const p = id ? (DB.parsers || []).find(x => x.id === id) : {name:pre && pre.name || 'My log format', re:pre && pre.re || '', flags:'i'};
  const sample = String(UI.lpIn || '').split('\n').find(l => l.trim()) || '';
  openDlg(dhead(id ? 'Edit parser' : 'New parser') + `<form data-form="parser" data-id="${id || ''}"><div class="in">
    <div class="frow"><div class="field"><label for="lpName">Name</label><input id="lpName" value="${esc(p.name)}" required></div><div class="field"><label for="lpFlags">Flags</label><input id="lpFlags" value="${esc(p.flags || 'i')}" class="mono" maxlength="4"></div></div>
    <div class="field"><label for="lpRe">Regular expression with named groups</label><textarea id="lpRe" class="inp code" rows="4" spellcheck="false" required>${esc(p.re)}</textarea>
      <span class="hint">Name groups with the common names, writing <span class="mono">__</span> for the dot: <span class="mono">(?&lt;src__ip&gt;…)</span>, <span class="mono">(?&lt;dst__port&gt;…)</span>, <span class="mono">(?&lt;user&gt;…)</span>, <span class="mono">(?&lt;action&gt;…)</span>, <span class="mono">(?&lt;time&gt;…)</span>. Any other name is kept as-is.</span></div>
    <div class="field" style="margin:0"><label for="lpTest">Test line</label><textarea id="lpTest" class="inp code" rows="2" spellcheck="false">${esc(sample)}</textarea></div>
    <div id="lpTestOut" class="lp-test"></div></div>
    <footer>${id ? `<button class="btn danger" type="button" data-act="lpDel" data-id="${id}" style="margin-right:auto">${ico('trash-2','sm')}Delete</button>` : ''}<button class="btn" type="button" data-act="dclose">Cancel</button><button class="btn primary" type="submit">Save parser</button></footer></form>`, true, () => {
      const run = () => { const re = $('lpRe').value, t = $('lpTest').value, o = $('lpTestOut'); let r = null, err = '';
        try{ new RegExp(re, $('lpFlags').value); r = runUserParser({re, flags:$('lpFlags').value}, t); }catch(e){ err = e.message; }
        o.innerHTML = err ? `<span style="color:var(--red)">${esc(err)}</span>` : r ? `<span style="color:var(--green)">${ico('check','sm')} Matches · ${Object.keys(r).length} fields</span><table class="ftab">${Object.entries(r).map(([k, v]) => `<tr><th>${esc(k)}${ALIAS.get(k.toLowerCase()) || CANON[k] ? '' : ''}</th><td class="mono">${esc(v)}</td></tr>`).join('')}</table>` : '<span class="t3">No match on the test line.</span>'; };
      ['lpRe', 'lpTest', 'lpFlags'].forEach(i => $(i).oninput = run); run(); });
}
function parserSubmit(f){
  const re = $('lpRe').value.trim(), flags = ($('lpFlags').value || 'i').replace(/[^gimsuy]/g, ''), nm = $('lpName').value.trim().replace(/\s+/g, ' ');
  DB.parsers = DB.parsers || [];
  if(!nm) return fieldErr('lpName', 'Give the parser a name.'); if(!checkLen('lpName', nm, 80, 'Name')) return;
  if(clash(DB.parsers, nm, 'name', f.dataset.id || null)) return fieldErr('lpName', `A parser called “${nm}” already exists.`);
  if(!re) return fieldErr('lpRe', 'Write the regular expression.'); if(!checkRegex('lpRe', re, flags)) return;
  if(!/\(\?<\w+>/.test(re)) return fieldErr('lpRe', 'Add at least one named group, e.g. (?<src__ip>[\\d.]+).');
  if(/\(\?<\w+>/.test(re) && new RegExp(re, flags.replace('g', '')).test('')) return fieldErr('lpRe', 'This expression matches an empty line, so it would match everything. Make it more specific.');
  const vals = {name:nm, re, flags:flags.replace('g', '')};
  if(f.dataset.id) Object.assign(DB.parsers.find(x => x.id === f.dataset.id), vals); else DB.parsers.unshift({id:uid('p'), on:true, ...vals});
  P_CACHE.clear(); closeDlg(); mutate('saved parser ' + vals.name); renderAll(); toast('Parser saved — it runs before the built-in formats');
}
function bindParse(){ const x = $('lpIn'); if(x) x.oninput = () => { clearTimeout(x.__t); x.__t = setTimeout(() => { UI.lpIn = x.value; $('lpOut').innerHTML = lpOut(x.value); }, 150); }; }
/* keep old records in step: add the entities only their fields reveal */
function migrateFieldEnts(){ let n = 0; for(const r of DB.records){ if(r.pv === 1) continue; const add = fieldEnts(parseLog(r.body)), have = new Set(r.ents.map(e => e.k + ':' + e.v));
  for(const e of add) if(!have.has(e.k + ':' + e.v)){ r.ents.push(e); n++; } r.pv = 1; } if(n) save(); }
const PARSE_ACTS = {
  lpNew:() => parserDlg(null), lpEdit:id => parserDlg(id),
  lpGen:() => { const l = String(UI.lpIn || ($('lpIn') || {}).value || '').split('\n').find(x => x.trim()); if(!l) return toast('Paste a log line first'); parserDlg(null, {name:'Parser from sample', re:genRegex(l.trim())}); },
  lpDel:id => { const p = DB.parsers.find(x => x.id === id); DB.parsers = DB.parsers.filter(x => x !== p); P_CACHE.clear(); closeDlg(); mutate('deleted parser'); renderAll(); toast('Parser deleted', 'Undo', () => { DB.parsers.push(p); P_CACHE.clear(); mutate('restored parser'); renderAll(); }); },
  lpToggle:(id, v, t) => { const p = DB.parsers.find(x => x.id === id); p.on = t.checked; P_CACHE.clear(); mutate('parser ' + (p.on ? 'on' : 'off')); renderMain(); },
  lpAliasAdd:() => { openDlg(dhead('Map a field name') + `<form data-form="alias"><div class="in"><div class="frow"><div class="field"><label for="alK">Field in your logs</label><input id="alK" class="mono" required placeholder="cip"></div>
      <div class="field"><label for="alC">Means</label><select id="alC">${CANON_NAMES.map(c => `<option>${c}</option>`).join('')}</select></div></div></div>
      <footer><button class="btn" type="button" data-act="dclose">Cancel</button><button class="btn primary" type="submit">Add</button></footer></form>`); },
  lpAliasDel:(id, v) => { delete DB.parserAliases[v]; P_CACHE.clear(); mutate('removed field mapping'); renderMain(); },
  fieldFilter:(id, v) => { const r = UI.sel && recById(UI.sel.id); UI.q = v; UI.ast = E.parseQuery(v); UI.tlMode = 'events'; go(caseHash(r ? r.caseId : DB.active, 'timeline')); renderMain(); const q = $('tlq'); if(q) q.value = v; }
};
