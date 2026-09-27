/* ==========================================================================
   Clew engine — extraction, time, meaning, correlation.
   Pure functions, no DOM, no network. Ported from Clew and extended with
   OSINT kinds (wallets, handles) so one extractor serves DFIR and OSINT.
   ========================================================================== */
const Engine = (() => {
'use strict';

const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c =>
  ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
/* Only http(s) links are ever rendered as <a href>. Everything else is text. */
const safeUrl = u => /^https?:\/\//i.test(String(u || '').trim()) ? String(u).trim() : null;

/* ---------- extraction ---------- */
function refang(t){
  return t.replace(/\[\.\]|\(\.\)|\{\.\}/g,'.')
    .replace(/\[:\]|\(:\)/g,':')
    .replace(/\[@\]|\(@\)/g,'@')
    .replace(/\bh(?:xx|\[t\]t|__)p(s?):\/\//gi,'http$1://')
    .replace(/\[\/\]/g,'/');
}
const PATTERNS = [
  ['sha256',/\b[a-f0-9]{64}\b/gi],
  ['sha1',/\b[a-f0-9]{40}\b/gi],
  ['md5',/\b[a-f0-9]{32}\b/gi],
  ['cve',/\bCVE-\d{4}-\d{4,7}\b/gi],
  ['eventid',/\b(?:event\s*id|eventid|eid)\s*[:=]?\s*(\d{1,5})\b/gi,1],
  ['eth',/\b0x[a-fA-F0-9]{40}\b/g],
  ['btc',/\b(?:bc1[ac-hj-np-z02-9]{25,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g],
  ['sid',/\bS-1-(?:\d{1,10}-){1,14}\d{1,10}\b/g],
  ['url',/\bhttps?:\/\/[^\s"'<>()\[\]]+/gi],
  ['email',/\b[\w.+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+\b/gi],
  ['handle',/(?:^|[\s(,;:])@([A-Za-z0-9_]{3,30})\b/g,1],
  ['hostport',/\b(?:(?:\d{1,3}\.){3}\d{1,3}|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}):\d{1,5}\b/gi],
  ['regkey',/\bHK(?:EY_[A-Z_]+|LM|CU|CR|U|CC)(?:\\[^\s"'<>|,;]+)+/gi],
  ['path',/\b[a-zA-Z]:\\[^\s"'<>|,;]{2,}|(?:^|\s)\/(?:etc|var|tmp|usr|home|opt|root|dev)\/[^\s"'<>|,;]+/gi],
  ['account',/\b[A-Z][A-Z0-9-]{1,15}\\[A-Za-z][\w.$-]{1,30}\b/g],
  ['file',/\b[\w][\w.\-()]{0,60}\.(?:exe|dll|sys|ps1|bat|cmd|vbs|js|hta|scr|jar|lnk|iso|zip|rar|7z|docm|xlsm|msi|evtx|pcap)\b/gi],
  ['ipv4',/\b(?:\d{1,3}\.){3}\d{1,3}\b/g],
  ['domain',/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24})\b/gi],
];
const KINDS = ['ipv4','hostport','domain','url','email','handle','btc','eth','md5','sha1','sha256',
  'file','path','regkey','account','sid','eventid','cve','custom'];
const GROUP = {ipv4:'net',hostport:'net',domain:'net',url:'net',email:'id',handle:'id',btc:'id',eth:'id',
  md5:'hash',sha1:'hash',sha256:'hash',file:'host',path:'host',regkey:'host',account:'id',sid:'id',
  eventid:'host',cve:'vuln',custom:'hash'};
const LABEL = {ipv4:'IP',hostport:'IP:port',domain:'Domain',url:'URL',email:'Email',handle:'Handle',
  btc:'BTC wallet',eth:'ETH wallet',md5:'MD5',sha1:'SHA-1',sha256:'SHA-256',file:'File',path:'Path',
  regkey:'Reg key',account:'Account',sid:'SID',eventid:'Event ID',cve:'CVE',custom:'Custom'};
const LOWER = /^(ipv4|hostport|domain|url|email|md5|sha1|sha256|file|handle)$/;
const validIP = s => s.split('.').every(o => o.length < 4 && +o <= 255);
const trimEdge = s => String(s).replace(/[.,;:!?)\]}'"]+$/,'').replace(/^[('"[{]+/,'');
/* A dotted word is only a domain if its TLD is plausible: any 2-letter ccTLD, or a common gTLD.
   Keeps "Net.WebClient" and "System.IO" out of the entity list. */
const GTLDS = new Set(('com net org info biz edu gov mil int io co ai app dev xyz top site online store shop tech cloud live news blog club vip win bid '+
  'onion example test invalid local localhost arpa one link click space website pro name mobi asia tel travel ltd group email world today '+
  'zip mov icu buzz cam rest monster work tk ml ga cf gq pw').split(' '));
const NOT_TLD = new Set(['sh','py','ps','md','js','cs','rb','pl','so','go','db','gz','xz','ini']);
const plausibleTLD = d => { const t = d.slice(d.lastIndexOf('.') + 1).toLowerCase(); return (t.length === 2 && !NOT_TLD.has(t)) || GTLDS.has(t); };
const FILE_EXT_TLD = /\.(exe|dll|sys|ps1|bat|cmd|vbs|js|hta|scr|jar|lnk|iso|zip|rar|msi|pdf|docm|xlsm|evtx|pcap|log|txt)$/i;

function extract(text){
  if(!text) return [];
  if(text.length > 400000) text = text.slice(0, 400000);
  let work = refang(text);
  const out = [], seen = new Set();
  const push = (k, raw) => {
    let v = trimEdge(String(raw).trim()); if(!v) return;
    if(k === 'cve') v = v.toUpperCase(); else if(LOWER.test(k)) v = v.toLowerCase();
    if(k === 'handle') v = '@' + v.replace(/^@/,'');
    const id = k + ':' + v; if(seen.has(id)) return; seen.add(id); out.push({k, v});
  };
  for(const [kind, re, cap] of PATTERNS){
    re.lastIndex = 0; const hits = []; let m;
    while((m = re.exec(work)) !== null){
      if(!m[0].length){ re.lastIndex++; continue; }
      const v = trimEdge(String(cap ? m[cap] : m[0]).trim()); if(!v) continue;
      if(kind === 'ipv4' && !validIP(v)) continue;
      if(kind === 'domain' && (/^\d+\./.test(v) || FILE_EXT_TLD.test(v) || !plausibleTLD(v))) continue;
      hits.push([m.index, m[0].length, v]);
    }
    if(hits.length){ // mask in one rebuild — linear, not quadratic
      let built = '', at = 0;
      for(const [i, len] of hits){ built += work.slice(at, i) + '\u0000'.repeat(len); at = i + len; }
      work = built + work.slice(at);
    }
    for(const [,, v] of hits){
      push(kind, v);
      if(kind === 'path'){ const b = v.split(/[\\/]/).pop(); if(b && /\.[a-z0-9]{1,5}$/i.test(b)) push('file', b); }
      if(kind === 'hostport'){ const h = v.slice(0, v.lastIndexOf(':')); push(/^[\d.]+$/.test(h) ? 'ipv4' : 'domain', h); }
      if(kind === 'url'){
        const u = v.match(/^https?:\/\/(?:[^/@\s]*@)?([^/:?#\s]+)/i);
        if(u){ const h = u[1]; if(/^(?:\d{1,3}\.){3}\d{1,3}$/.test(h)){ if(validIP(h)) push('ipv4', h); } else if(plausibleTLD(h)) push('domain', h); }
      }
    }
  }
  return out.sort((a, b) => KINDS.indexOf(a.k) - KINDS.indexOf(b.k));
}

/* ---------- time ---------- */
function partsIn(ep, tz){
  try{
    const f = new Intl.DateTimeFormat('en-US',{timeZone:tz,hour12:false,year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit'});
    const p = {}; for(const x of f.formatToParts(ep)) p[x.type] = x.value;
    return {y:+p.year, mo:+p.month, d:+p.day, h:(+p.hour) % 24, mi:+p.minute, s:+p.second};
  }catch(e){ const d = new Date(ep); return {y:d.getUTCFullYear(),mo:d.getUTCMonth()+1,d:d.getUTCDate(),h:d.getUTCHours(),mi:d.getUTCMinutes(),s:d.getUTCSeconds()}; }
}
const tzOff = (ep, tz) => { const p = partsIn(ep, tz); return Date.UTC(p.y, p.mo-1, p.d, p.h, p.mi, p.s) - ep; };
function wallToEpoch(y, mo, d, h, mi, s, tz){
  const g = Date.UTC(y, mo-1, d, h, mi, s), o1 = tzOff(g, tz); let e = g - o1;
  const o2 = tzOff(e, tz); if(o2 !== o1) e = g - o2; return e;
}
function zoneAbbr(ep, tz){
  try{ return (new Intl.DateTimeFormat('en-US',{timeZone:tz,timeZoneName:'short'}).formatToParts(ep).find(x => x.type === 'timeZoneName') || {}).value || tz; }
  catch(e){ return tz; }
}
const carriesZone = s => /(?:z|[+-]\d{2}:?\d{2}|\b(?:utc|gmt)\b)\s*$/i.test(String(s).trim());
const MONTHS = ['jan','feb','mar','apr','may','jun','jul','aug','sep','oct','nov','dec'];
function parseTime(raw, tz){
  if(!raw) return null; tz = tz || 'UTC';
  const s = String(raw).trim().replace(/^\[|\]$/g,'');
  let m = s.match(/^(\d{1,2})\/([A-Za-z]{3})\/(\d{4}):(\d{1,2}):(\d{2}):(\d{2})(?:\s*([+-])(\d{2})(\d{2}))?/);
  if(m){ const mo = MONTHS.indexOf(m[2].toLowerCase()) + 1;
    if(mo){ if(m[7]){ const off = (m[7] === '-' ? -1 : 1) * ((+m[8]) * 60 + (+m[9])) * 60000; return Date.UTC(+m[3], mo-1, +m[1], +m[4], +m[5], +m[6]) - off; }
      return wallToEpoch(+m[3], mo, +m[1], +m[4], +m[5], +m[6], tz); } }
  if(/^\d{10}(\.\d{1,9})?$/.test(s)) return Math.round(parseFloat(s) * 1000);
  if(/^\d{13}$/.test(s)) return +s;
  if(carriesZone(s)){ const v = Date.parse(s.replace(/\b(UTC|GMT)\b/i,'Z').replace(/(\d)\s+Z$/,'$1Z').replace(/^(\d{4}-\d{2}-\d{2}) /,'$1T')); if(!isNaN(v)) return v; }
  m = s.match(/^(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})[T ,]+(\d{1,2}):(\d{2})(?::(\d{2}))?/);
  if(m) return wallToEpoch(+m[1], +m[2], +m[3], +m[4], +m[5], +(m[6] || 0), tz);
  m = s.match(/^(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})$/);
  if(m) return wallToEpoch(+m[1], +m[2], +m[3], 0, 0, 0, tz);
  m = s.match(/^([a-z]{3})\s+(\d{1,2})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?/i);
  if(m){ const mo = MONTHS.indexOf(m[1].toLowerCase()) + 1; if(mo) return wallToEpoch(partsIn(Date.now(), tz).y, mo, +m[2], +m[3], +m[4], +(m[5] || 0), tz); }
  const v = Date.parse(s); return isNaN(v) ? null : v;
}
const LEADING_TS = /^\s*(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?|[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{10}\.\d+)/;
const INLINE_TS = [/\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)/,
  /\[(\d{1,2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2}(?:\s*[+-]\d{4})?)\]/];
function lineTime(line){
  const m = String(line).match(LEADING_TS); if(m) return m[1];
  for(const re of INLINE_TS){ const x = String(line).match(re); if(x) return x[1]; }
  return '';
}
const pad = n => String(n).padStart(2,'0');
const fmtClock = (ts, tz) => { const p = partsIn(ts, tz); return pad(p.h)+':'+pad(p.mi)+':'+pad(p.s); };
const fmtFull  = (ts, tz) => { const p = partsIn(ts, tz); return p.y+'-'+pad(p.mo)+'-'+pad(p.d)+' '+pad(p.h)+':'+pad(p.mi)+':'+pad(p.s); };
const fmtDate  = (ts, tz) => { const p = partsIn(ts, tz); return p.y+'-'+pad(p.mo)+'-'+pad(p.d); };
function fmtDay(ts, tz){
  try{ return new Intl.DateTimeFormat('en-GB',{timeZone:tz,weekday:'short',year:'numeric',month:'short',day:'numeric'}).format(ts); }
  catch(e){ return fmtDate(ts, tz); }
}
function fmtGap(ms){
  const s = Math.round(Math.abs(ms) / 1000); if(s < 60) return s + 's';
  const m = Math.floor(s / 60); if(m < 60) return m + 'm ' + (s % 60) + 's';
  const h = Math.floor(m / 60); if(h < 24) return h + 'h ' + (m % 60) + 'm';
  return Math.floor(h / 24) + 'd ' + (h % 24) + 'h';
}
function fmtAgo(ms){
  const s = Math.max(0, Math.round(ms / 1000));
  if(s < 90) return 'just now'; const m = Math.round(s / 60); if(m < 60) return m + ' min ago';
  const h = Math.round(m / 60); if(h < 36) return h + ' h ago'; return Math.round(h / 24) + ' d ago';
}
function relClock(ts, t0){
  if(t0 == null) return null; const d = ts - t0, a = Math.abs(d);
  const h = Math.floor(a / 3600000), m = Math.floor(a % 3600000 / 60000), s = Math.floor(a % 60000 / 1000);
  return 'T' + (d < 0 ? '−' : '+') + pad(h) + ':' + pad(m) + ':' + pad(s);
}

/* ---------- meaning (offline reference, a subset of Clew's) ---------- */
const EVENTIDS = {1102:['Audit log cleared',1],4624:['Successful logon'],4625:['Failed logon'],4648:['Logon with explicit credentials',1],
  4672:['Special privileges assigned',1],4688:['Process created'],4697:['Service installed',1],4698:['Scheduled task created',1],
  4720:['User account created',1],4732:['Member added to local group',1],4769:['Kerberos service ticket',1],7045:['Service installed',1],
  4104:['PowerShell script block',1],104:['Event log cleared',1]};
const SYSMON = {1:['Sysmon: process created'],3:['Sysmon: network connection'],11:['Sysmon: file created'],13:['Sysmon: registry value set'],22:['Sysmon: DNS query']};
const EVIL_PORTS = {4444:'Metasploit default',1337:'common shell',31337:'classic backdoor',8888:'common shell'};
const PORTS = {22:'SSH',53:'DNS',80:'HTTP',443:'HTTPS',445:'SMB',3389:'RDP',5985:'WinRM'};
const LOLBINS = {'rundll32.exe':'LOLBin — runs DLL exports, T1218.011','mshta.exe':'LOLBin — runs HTA, T1218.005',
  'certutil.exe':'LOLBin — download & decode, T1140','powershell.exe':'PowerShell, T1059.001','cmd.exe':'Command shell, T1059.003',
  'schtasks.exe':'Scheduled tasks, T1053.005','wmic.exe':'LOLBin — remote exec, T1047','regsvr32.exe':'LOLBin — Squiblydoo, T1218.010'};
const SYSBINS = new Set(['svchost.exe','lsass.exe','csrss.exe','services.exe','explorer.exe','winlogon.exe','smss.exe']);
const HOTPATH = [[/\\users\\public\\/i,'User-writable — Public folder'],[/\\appdata\\local\\temp\\/i,'User-writable — Temp'],
  [/\\programdata\\/i,'World-writable — ProgramData'],[/^\/tmp\//,'World-writable — /tmp']];
const HOTKEY = [[/currentversion\\run(once)?\b/i,'Autorun persistence, T1547.001'],[/\\services\\/i,'Service definition, T1543.003']];
const BADTLD = /\.(tk|ml|ga|cf|gq|top|xyz|zip|mov|icu)$/i;
function ipClass(v){
  const o = v.split('.').map(Number);
  if(o[0] === 127) return 'Loopback';
  if(o[0] === 10 || (o[0] === 172 && o[1] >= 16 && o[1] <= 31) || (o[0] === 192 && o[1] === 168)) return 'Private — RFC 1918';
  if((o[0] === 192 && o[1] === 0 && o[2] === 2) || (o[0] === 198 && o[1] === 51 && o[2] === 100) || (o[0] === 203 && o[1] === 0 && o[2] === 113)) return 'Documentation range — RFC 5737';
  return 'Public address';
}
function meaning(k, v){
  const low = String(v).toLowerCase();
  switch(k){
    case 'eventid': { const n = +v, e = EVENTIDS[n] || (n <= 26 ? SYSMON[n] : null); return e ? {t:'Event '+n+' — '+e[0], hot:!!e[1]} : null; }
    case 'hostport': { const n = +low.slice(low.lastIndexOf(':') + 1);
      if(EVIL_PORTS[n]) return {t:'Port '+n+' — '+EVIL_PORTS[n], hot:1}; if(PORTS[n]) return {t:'Port '+n+' — '+PORTS[n], hot:0}; return null; }
    case 'ipv4': return {t:ipClass(low), hot:0};
    case 'domain': return BADTLD.test(low) ? {t:'TLD often abused', hot:1} : (/\.(example|test|invalid)$/.test(low) ? {t:'Reserved test domain — RFC 2606', hot:0} : null);
    case 'file':
      if(LOLBINS[low]) return {t:LOLBINS[low], hot:1};
      if(/\.(pdf|doc|docx|xls|jpg|png|txt)\.(exe|scr|js|vbs|bat|cmd|hta|lnk)$/i.test(low)) return {t:'Double extension — disguised executable, T1036.007', hot:1};
      if(SYSBINS.has(low)) return {t:'Windows system binary — check where it ran from', hot:0};
      if(/\.lnk$/.test(low)) return {t:'Shortcut — common delivery & persistence', hot:1};
      return null;
    case 'path': for(const [re, l] of HOTPATH) if(re.test(v)) return {t:l, hot:1}; return null;
    case 'regkey': for(const [re, l] of HOTKEY) if(re.test(v)) return {t:l, hot:1}; return null;
    case 'url': return /^http:\/\//i.test(low) ? {t:'Cleartext HTTP' + (/\.(exe|dll|ps1|hta)(\?|$)/.test(low) ? ' · payload download, T1105' : ''), hot:/\.(exe|dll|ps1|hta)(\?|$)/.test(low)} : null;
    case 'account': return /\\(administrator|admin|root)$/i.test(low) ? {t:'Privileged account name', hot:1} : (/\\svc_/i.test(low) ? {t:'Service account — check for interactive use', hot:1} : null);
    case 'btc': return {t:'Bitcoin address — trace on a block explorer', hot:0};
    case 'eth': return {t:'Ethereum address', hot:0};
    case 'handle': return {t:'Online handle — check reuse across platforms', hot:0};
    case 'md5': case 'sha1': case 'sha256': return {t:'File hash', hot:0};
    case 'cve': return {t:'Known vulnerability', hot:1};
  }
  return null;
}

/* Observations: what the indicators in one record mean together. Heuristic, never a verdict. */
function observations(rec){
  const out = [], ents = rec.ents || [], body = rec.body || '';
  const val = k => ents.filter(e => e.k === k).map(e => e.v);
  const add = (tag, t, hot = true) => out.push({tag, t, hot});
  const files = val('file'), paths = val('path');
  const sysbin = files.filter(f => SYSBINS.has(f.toLowerCase()));
  const lol = files.filter(f => LOLBINS[f.toLowerCase()]);
  const userW = paths.filter(p => HOTPATH.some(([re]) => re.test(p)));
  const eids = val('eventid').map(Number);
  if(sysbin.length && paths.length && paths.every(p => !/\\windows\\system32|\\windows\\syswow64/i.test(p)))
    add('masquerade', 'System binary name ('+sysbin.join(', ')+') running from outside System32 — T1036.005.');
  if(lol.length && (val('url').length || val('ipv4').some(v => ipClass(v) !== 'Private — RFC 1918')))
    add('download', 'A LOLBin ('+lol.join(', ')+') alongside an external address — living-off-the-land download, T1105.');
  if(/-enc(odedcommand)?\b|-e\s+[A-Za-z0-9+/=]{20,}/i.test(body)) add('encoded', 'Encoded PowerShell command — decode it, it is usually the whole answer.');
  if(eids.some(n => n === 1102 || n === 104)) add('anti-forensics', 'Event log cleared — what came before is missing on purpose, T1070.001.');
  if(val('hostport').some(v => EVIL_PORTS[+v.slice(v.lastIndexOf(':') + 1)])) add('c2', 'Traffic to a port commonly used for reverse shells.');
  if(val('regkey').some(r => HOTKEY.some(([re]) => re.test(r))) || eids.some(n => [4697,7045,4698].includes(n))) add('persistence', 'Sets something up to run again later.');
  if(val('file').some(f => /\.(pdf|doc|docx|xls|txt)\.(exe|lnk|scr|js|hta)$/i.test(f))) add('lure', 'Disguised attachment — double extension.');
  return out;
}

function beaconOf(times){
  const t = times.filter(Boolean).slice().sort((a, b) => a - b); if(t.length < 4) return null;
  const d = []; for(let i = 1; i < t.length; i++) d.push(t[i] - t[i-1]);
  const mean = d.reduce((a, b) => a + b, 0) / d.length; if(mean < 1000) return null;
  const sd = Math.sqrt(d.reduce((a, b) => a + (b - mean) ** 2, 0) / d.length);
  return {n:t.length, mean, jitter:sd / mean, regular:sd / mean < .25};
}

/* Chapters: cut the timed records where the pause is long *for this case*. */
function chapters(timed){
  if(timed.length < 2) return timed.length ? [timed] : [];
  const gaps = []; for(let i = 1; i < timed.length; i++) gaps.push(timed[i].ts - timed[i-1].ts);
  const s = gaps.slice().sort((a, b) => a - b), p80 = s[Math.floor(s.length * .8)] || 0;
  const thr = Math.min(21600000, Math.max(120000, p80 * 2));
  const out = []; let cur = [timed[0]];
  for(let i = 1; i < timed.length; i++){ if(timed[i].ts - timed[i-1].ts > thr){ out.push(cur); cur = []; } cur.push(timed[i]); }
  out.push(cur); return out;
}

/* ---------- query language ----------
   bare words = substring; field:value; -x excludes; OR / | splits alternatives */
const FIELDS = /^(host|source|from|tag|type|kind|ent|verdict|after|before|is|has)$/;
function parseGroup(q){
  const ast = {text:[], neg:[], f:[]}, re = /(-)?(?:([a-zA-Z]+):)?(?:"([^"]*)"|(\S+))/g; let m;
  while((m = re.exec(q)) !== null){
    const neg = !!m[1], field = (m[2] || '').toLowerCase(), val = (m[3] != null ? m[3] : (m[4] || '')).trim();
    if(!val) continue;
    if(field && FIELDS.test(field)) ast.f.push({field, val:val.toLowerCase(), raw:val, neg});
    else (neg ? ast.neg : ast.text).push(((field ? field + ':' : '') + val).toLowerCase());
  }
  return ast;
}
function parseQuery(q){
  const parts = String(q || '').split(/\s+(?:OR|\|\|?)\s+/i).map(x => x.trim()).filter(Boolean);
  return parts.length ? parts.map(parseGroup) : null;
}

const REF = {EVENTIDS, SYSMON, EVIL_PORTS, PORTS, LOLBINS};
return {REF, esc, safeUrl, refang, extract, KINDS, GROUP, LABEL, parseTime, carriesZone, lineTime, zoneAbbr,
  fmtClock, fmtFull, fmtDate, fmtDay, fmtGap, fmtAgo, relClock, meaning, observations, ipClass, beaconOf,
  chapters, parseQuery};
})();
