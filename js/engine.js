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
    .replace(/\[\/\]/g,'/')
    .replace(/\s*[\[({]\s*at\s*[\])}]\s*/gi,'@').replace(/\s*[\[({]\s*dot\s*[\])}]\s*/gi,'.');
}
/* ---------- normalisers shared by extraction and vault keys ---------- */
const SOCIAL_HOSTS = {'twitter.com':'x.com','x.com':'x.com','mobile.twitter.com':'x.com','instagram.com':'instagram.com','facebook.com':'facebook.com','fb.com':'facebook.com','m.facebook.com':'facebook.com',
  'tiktok.com':'tiktok.com','github.com':'github.com','gitlab.com':'gitlab.com','t.me':'t.me','telegram.me':'t.me','reddit.com':'reddit.com','old.reddit.com':'reddit.com','linkedin.com':'linkedin.com',
  'youtube.com':'youtube.com','threads.net':'threads.net','pinterest.com':'pinterest.com','medium.com':'medium.com','twitch.tv':'twitch.tv','vk.com':'vk.com','keybase.io':'keybase.io',
  'bsky.app':'bsky.app','snapchat.com':'snapchat.com','soundcloud.com':'soundcloud.com','steamcommunity.com':'steamcommunity.com','hackerone.com':'hackerone.com','patreon.com':'patreon.com','onlyfans.com':'onlyfans.com'};
const SOCIAL_STOP = /^(home|search|explore|i|intent|share|login|signup|settings|hashtag|about|help|privacy|terms|watch|results|feed|messages|notifications|orgs|topics|features|pricing|marketplace|groups|pages|events|p|reel|reels|stories|status|tv|legal|policies|jobs|company|school|sharer|dialog|plugins|embed|joinchat|s|c|channel|playlist|shorts|r|wiki|gist|sponsors|trending|new|popular)$/i;
function normSocial(url){
  const m = String(url).match(/^(?:https?:\/\/)?(?:www\.)?([a-z0-9.-]+\.[a-z]{2,})\/+(.*)$/i); if(!m) return null;
  const host = SOCIAL_HOSTS[m[1].toLowerCase()]; if(!host) return null;
  let path = m[2].split(/[?#]/)[0].split('/').filter(Boolean), user = null;
  if(host === 'linkedin.com'){ if(/^(in|company)$/i.test(path[0] || '')) user = path[0].toLowerCase() + '/' + (path[1] || ''); }
  else if(host === 'reddit.com'){ if(/^(u|user)$/i.test(path[0] || '')) user = 'user/' + (path[1] || ''); }
  else if(host === 'youtube.com'){ if(/^@/.test(path[0] || '')) user = path[0]; else if(/^(c|user)$/i.test(path[0] || '') && path[1]) user = path[0] + '/' + path[1]; }
  else if(host === 'steamcommunity.com'){ if(/^(id|profiles)$/i.test(path[0] || '') && path[1]) user = path[0] + '/' + path[1]; }
  else user = path[0] || null;
  if(!user || /\/$/.test(user)) return null;
  const bare = user.replace(/^@/, '').split('/').pop();
  if(!/^[A-Za-z0-9_.-]{2,60}$/.test(bare) || SOCIAL_STOP.test(bare) || (SOCIAL_STOP.test(user) && !user.includes('/'))) return null;
  return {v:host + '/' + user.replace(/^@/, host === 'youtube.com' || host === 'tiktok.com' || host === 'threads.net' ? '@' : ''), host, user:bare};
}
const normPhone = s => { const d = String(s).replace(/[^\d+]/g, ''); return /^\+/.test(String(s).trim()) ? '+' + d.replace(/\+/g, '') : d.replace(/\+/g, ''); };
const normMac = s => String(s).toLowerCase().replace(/[^0-9a-f]/g, '').replace(/(..)(?!$)/g, '$1:');
function validIPv6(s){
  if(!/^[0-9a-f:]+$/i.test(s) || (s.match(/::/g) || []).length > 1) return false;
  const parts = s.split(':'); if(s.includes('::')){ return parts.filter(Boolean).length <= 7 && parts.filter(Boolean).every(p => p.length <= 4) && parts.filter(Boolean).length >= 1; }
  return parts.length === 8 && parts.every(p => p.length >= 1 && p.length <= 4);
}
const ibanOK = s => { s = s.replace(/\s+/g, '').toUpperCase(); if(!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(s)) return false;
  const r = (s.slice(4) + s.slice(0, 4)).replace(/[A-Z]/g, c => c.charCodeAt(0) - 55); let m = 0; for(const ch of r) m = (m * 10 + +ch) % 97; return m === 1; };
const mixedB58 = s => /\d/.test(s) && /[a-z]/.test(s) && /[A-Z]/.test(s);
function norm(k, v){
  v = String(v).trim();
  switch(k){
    case 'phone': return normPhone(v);
    case 'mac': return normMac(v);
    case 'ipv6': return v.toLowerCase();
    case 'social': { const s = normSocial(/^https?:/i.test(v) ? v : 'https://' + v); return s ? s.v : v.toLowerCase(); }
    case 'coords': { const m = v.match(/(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)/); return m ? (+m[1]).toFixed(5) + ',' + (+m[2]).toFixed(5) : v; }
    case 'iban': return v.replace(/\s+/g, '').toUpperCase();
    case 'asn': return 'AS' + v.replace(/\D/g, '');
    case 'ttp': case 'cve': return v.toUpperCase();
    default: return v;
  }
}
function cryptoKind(v){ v = String(v).trim();
  if(/^0x[a-f0-9]{40}$/i.test(v)) return 'eth'; if(/^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$/.test(v)) return 'xmr'; if(/^(ltc1|[LM][a-km-zA-HJ-NP-Z1-9]{26,33}$)/.test(v)) return 'ltc';
  if(/^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(v)) return 'trx'; if(/^D[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32}$/.test(v)) return 'doge'; return 'btc'; }
const PATTERNS = [
  ['sha512',/\b[a-f0-9]{128}\b/gi],
  ['sha256',/\b[a-f0-9]{64}\b/gi],
  ['sha1',/\b[a-f0-9]{40}\b/gi],
  ['md5',/\b[a-f0-9]{32}\b/gi],
  ['cve',/\bCVE-\d{4}-\d{4,7}\b/gi],
  ['eventid',/\b(?:event\s*id|eventid|eid)\s*[:=]?\s*(\d{1,5})\b/gi,1],
  ['ttp',/\bT1\d{3}(?:\.\d{3})?\b/g],
  ['eth',/\b0x[a-fA-F0-9]{40}\b/g],
  ['xmr',/\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b/g],
  ['btc',/\b(?:bc1[ac-hj-np-z02-9]{25,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g],
  ['ltc',/\b(?:ltc1[ac-hj-np-z02-9]{39,59}|[LM][a-km-zA-HJ-NP-Z1-9]{26,33})\b/g],
  ['trx',/\bT[1-9A-HJ-NP-Za-km-z]{33}\b/g],
  ['doge',/\bD[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32}\b/g],
  ['iban',/\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b/g],
  ['sid',/\bS-1-(?:\d{1,10}-){1,14}\d{1,10}\b/g],
  ['social',/\b(?:https?:\/\/)?(?:www\.|m\.|mobile\.|old\.)?(?:twitter\.com|x\.com|instagram\.com|facebook\.com|fb\.com|tiktok\.com|github\.com|gitlab\.com|t\.me|telegram\.me|reddit\.com|linkedin\.com|youtube\.com|threads\.net|pinterest\.com|medium\.com|twitch\.tv|vk\.com|keybase\.io|bsky\.app|snapchat\.com|soundcloud\.com|steamcommunity\.com|hackerone\.com|patreon\.com|onlyfans\.com)\/[^\s"'<>()\[\]]+/gi],
  ['url',/\bhttps?:\/\/[^\s"'<>()\[\]]+/gi],
  ['mac',/\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b|\b(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}\b/gi],
  ['ipv6',/(?<![\w:.])(?:[0-9a-f]{1,4}:(?::?[0-9a-f]{1,4}){0,7}::?|::)(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,7})?(?![\w:.])/gi],
  ['phone',/(?:\btel:|(?:\b(?:phone|tel|mobile|cell|whats\s?app|call|fax|contact)\b[^\d+\n]{0,12}))?\+\d{1,3}[\s.-]?\(?\d{1,4}\)?(?:[\s.-]?\d{2,5}){1,4}\b|\b(?:phone|tel|mobile|cell|whats\s?app|call(?: me)?|fax)\b[^\d\n]{0,12}\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,5}\b/gi],
  ['coords',/(?<![\d.])(-?\d{1,2}\.\d{3,})\s*,\s*(-?\d{1,3}\.\d{3,})(?![\d.])/g],
  ['email',/\b[\w.+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+\b/gi],
  ['handle',/(?:^|[\s(,;:])@([A-Za-z0-9_]{3,30})\b/g,1],
  ['hostport',/\b(?:(?:\d{1,3}\.){3}\d{1,3}|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}):\d{1,5}\b/gi],
  ['regkey',/\bHK(?:EY_[A-Z_]+|LM|CU|CR|U|CC)(?:\\[^\s"'<>|,;]+)+/gi],
  ['path',/\b[a-zA-Z]:\\[^\s"'<>|,;]{2,}|(?:^|\s)\/(?:etc|var|tmp|usr|home|opt|root|dev)\/[^\s"'<>|,;]+/gi],
  ['account',/\b[A-Z][A-Z0-9-]{1,15}\\[A-Za-z][\w.$-]{1,30}\b/g],
  ['uname',/(?:\b(?:user(?:\s?name)?|login|handle|alias|nick(?:name)?|screen[_ ]?name)\s*[:=]\s*@?|\b(?:a\.k\.a\.?|aka|also known as|goes by|alias)\s+@?(?=[A-Za-z0-9_.-]*[_\d])|(?<![\w/])u\/)([A-Za-z][A-Za-z0-9_.-]{2,29})(?![\w@.-])/gi,1],
  ['asn',/\bAS\s?(\d{2,10})\b/g],
  ['file',/\b[\w][\w.\-()]{0,60}\.(?:exe|dll|sys|ps1|bat|cmd|vbs|js|hta|scr|jar|lnk|iso|zip|rar|7z|docm|xlsm|msi|evtx|pcap)\b/gi],
  ['ipv4',/\b(?:\d{1,3}\.){3}\d{1,3}\b/g],
  ['domain',/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24})\b/gi],
];
const KINDS = ['ipv4','ipv6','hostport','domain','url','email','handle','social','phone','btc','eth','xmr','ltc','trx','doge','iban','md5','sha1','sha256','sha512',
  'mac','asn','coords','file','path','regkey','account','sid','eventid','cve','ttp','custom'];
const GROUP = {ipv6:'net',mac:'net',asn:'net',social:'id',phone:'id',xmr:'id',ltc:'id',trx:'id',doge:'id',iban:'id',sha512:'hash',coords:'place',ttp:'vuln',ipv4:'net',hostport:'net',domain:'net',url:'net',email:'id',handle:'id',btc:'id',eth:'id',
  md5:'hash',sha1:'hash',sha256:'hash',file:'host',path:'host',regkey:'host',account:'id',sid:'id',
  eventid:'host',cve:'vuln',custom:'hash'};
const LABEL = {ipv6:'IPv6',mac:'MAC address',asn:'ASN',social:'Social profile',phone:'Phone',xmr:'XMR wallet',ltc:'LTC wallet',trx:'TRON wallet',doge:'DOGE wallet',iban:'IBAN',sha512:'SHA-512',coords:'Coordinates',ttp:'ATT&CK technique',ipv4:'IP',hostport:'IP:port',domain:'Domain',url:'URL',email:'Email',handle:'Handle',
  btc:'BTC wallet',eth:'ETH wallet',md5:'MD5',sha1:'SHA-1',sha256:'SHA-256',file:'File',path:'Path',
  regkey:'Reg key',account:'Account',sid:'SID',eventid:'Event ID',cve:'CVE',custom:'Custom'};
const LOWER = /^(ipv4|ipv6|hostport|domain|url|email|md5|sha1|sha256|sha512|file|handle)$/;
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
    if(k === 'cve') v = v.toUpperCase(); else if(LOWER.test(k)) v = v.toLowerCase(); else v = norm(k, v);
    if(k === 'handle') v = '@' + v.replace(/^@/,'');
    const id = k + ':' + v; if(seen.has(id)) return; seen.add(id); out.push({k, v});
  };
  for(const [kind, re, cap] of PATTERNS){
    re.lastIndex = 0; const hits = []; let m;
    while((m = re.exec(work)) !== null){
      if(!m[0].length){ re.lastIndex++; continue; }
      const v = trimEdge(String(cap ? m[cap] : m[0]).trim()); if(!v) continue;
      if(kind === 'ipv4' && !validIP(v)) continue;
      if(kind === 'ipv6' && (!validIPv6(v) || /^[0-9]+:[0-9]+(:[0-9]+)?$/.test(v) || (v.match(/:/g) || []).length < 2)) continue;
      if(kind === 'social' && !normSocial(v)) continue;
      if(kind === 'phone'){ const d = v.replace(/\D/g, ''); if(d.length < 8 || d.length > 15 || /^(19|20)\d{6}$/.test(d)) continue; }
      if(kind === 'coords' && (Math.abs(+m[1]) > 90 || Math.abs(+m[2]) > 180 || (+m[1] === 0 && +m[2] === 0))) continue;
      if(kind === 'iban' && !ibanOK(v)) continue;
      if(/^(btc|ltc|trx|doge|xmr)$/.test(kind) && !/^(bc1|ltc1)/.test(v) && !mixedB58(v)) continue;
      if(kind === 'uname' && /^(name|password|id|agent|none|null|admin|root|unknown|required|here|the|and|for|with|from)$/i.test(v)) continue;
      if(kind === 'domain' && (/^\d+\./.test(v) || FILE_EXT_TLD.test(v) || !plausibleTLD(v))) continue;
      hits.push([m.index, m[0].length, v]);
    }
    if(hits.length){ // mask in one rebuild — linear, not quadratic
      let built = '', at = 0;
      for(const [i, len] of hits){ built += work.slice(at, i) + '\u0000'.repeat(len); at = i + len; }
      work = built + work.slice(at);
    }
    for(const [,, v] of hits){
      if(kind === 'phone'){ push('phone', v.replace(/^[^\d+]*(?=[+\d(])/, '').replace(/^tel:/i, '')); continue; }
      if(kind === 'uname'){ push('handle', v); continue; }
      if(kind === 'social'){ const s = normSocial(v); push('social', s.v); if(/^(x\.com|instagram\.com|tiktok\.com|github\.com|t\.me|threads\.net|twitch\.tv|gitlab\.com|keybase\.io|bsky\.app)$/.test(s.host) && /^[A-Za-z0-9_]{3,30}$/.test(s.user)) push('handle', s.user); continue; }
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
const DTF = new Map();
const dtf = (loc, o) => { const k = loc + JSON.stringify(o); let f = DTF.get(k); if(!f){ f = new Intl.DateTimeFormat(loc, o); DTF.set(k, f); } return f; };
const PARTS = new Map();
function partsIn(ep, tz){
  const pk = tz + '|' + ep; const hit = PARTS.get(pk); if(hit) return hit;
  try{
    const f = dtf('en-US',{timeZone:tz,hour12:false,year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit'});
    const p = {}; for(const x of f.formatToParts(ep)) p[x.type] = x.value;
    const r = {y:+p.year, mo:+p.month, d:+p.day, h:(+p.hour) % 24, mi:+p.minute, s:+p.second}; if(PARTS.size > 60000) PARTS.clear(); PARTS.set(pk, r); return r;
  }catch(e){ const d = new Date(ep); return {y:d.getUTCFullYear(),mo:d.getUTCMonth()+1,d:d.getUTCDate(),h:d.getUTCHours(),mi:d.getUTCMinutes(),s:d.getUTCSeconds()}; }
}
const tzOff = (ep, tz) => { const p = partsIn(ep, tz); return Date.UTC(p.y, p.mo-1, p.d, p.h, p.mi, p.s) - ep; };
function wallToEpoch(y, mo, d, h, mi, s, tz){
  const g = Date.UTC(y, mo-1, d, h, mi, s), o1 = tzOff(g, tz); let e = g - o1;
  const o2 = tzOff(e, tz); if(o2 !== o1) e = g - o2; return e;
}
function zoneAbbr(ep, tz){
  try{ return (dtf('en-US',{timeZone:tz,timeZoneName:'short'}).formatToParts(ep).find(x => x.type === 'timeZoneName') || {}).value || tz; }
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
  try{ return dtf('en-GB',{timeZone:tz,weekday:'short',year:'numeric',month:'short',day:'numeric'}).format(ts); }
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
  if(String(v).includes(':')){ const l = String(v).toLowerCase(); return l === '::1' ? 'Loopback' : /^fe[89ab]/.test(l) ? 'Link-local' : /^f[cd]/.test(l) ? 'Private — unique local' : /^ff/.test(l) ? 'Multicast' : /^2001:0?db8:/.test(l) ? 'Documentation range — RFC 3849' : 'Public address'; }
  if(o[0] === 127) return 'Loopback';
  if(o[0] === 0) return 'This network — reserved';
  if(o[0] === 169 && o[1] === 254) return 'Link-local';
  if(o[0] === 100 && o[1] >= 64 && o[1] <= 127) return 'Carrier-grade NAT — RFC 6598';
  if(o[0] === 198 && (o[1] === 18 || o[1] === 19)) return 'Benchmarking — RFC 2544';
  if(o[0] >= 224 && o[0] <= 239) return 'Multicast';
  if(o[0] >= 240) return 'Reserved';
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
  const ast = {text:[], neg:[], f:[]}, re = /(-)?(?:([a-zA-Z][\w.\-]*):(?!\/\/))?(?:"([^"]*)"|(\S+))/g; let m;
  while((m = re.exec(q)) !== null){
    const neg = !!m[1], field = (m[2] || '').toLowerCase(), val = (m[3] != null ? m[3] : (m[4] || '')).trim();
    if(!val) continue;
    if(field && FIELDS.test(field)) ast.f.push({field, val:val.toLowerCase(), raw:val, neg});
    else if(field && !/^(https?|hxxps?|ftp|mailto|file)$/.test(field)) ast.f.push({field:'fld', name:field, val:val.toLowerCase(), raw:val, neg, text:(field + ':' + val).toLowerCase()});
    else (neg ? ast.neg : ast.text).push(((field ? field + ':' : '') + val).toLowerCase());
  }
  return ast;
}
function parseQuery(q){
  const parts = String(q || '').split(/\s+(?:OR|\|\|?)\s+/i).map(x => x.trim()).filter(Boolean);
  return parts.length ? parts.map(parseGroup) : null;
}

const REF = {EVENTIDS, SYSMON, EVIL_PORTS, PORTS, LOLBINS};
return {REF, esc, safeUrl, refang, extract, norm, normSocial, normPhone, normMac, cryptoKind, validIPv6, KINDS, GROUP, LABEL, parseTime, carriesZone, lineTime, zoneAbbr,
  fmtClock, fmtFull, fmtDate, fmtDay, fmtGap, fmtAgo, relClock, meaning, observations, ipClass, beaconOf,
  chapters, parseQuery};
})();
