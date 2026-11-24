/* ==========================================================================
   Masking: replace the identifying values in a log or text with placeholders
   of the same shape — the same value always gets the same placeholder — so a
   sample can be pasted into an online tool or shown to someone without the
   addresses, names and hosts in it. Used by the Decoder (Mask identifiers)
   and the Regex builder (Mask a copy). Runs here; nothing is sent anywhere.
   ========================================================================== */
const MASK_KEEP = new Set(['localhost', 'example.com', 'example.org', 'example.net', 'google.com', 'microsoft.com', 'windows.net', 'windowsupdate.com', 'office.com', 'office365.com', 'live.com', 'apple.com', 'icloud.com', 'amazonaws.com', 'amazon.com', 'cloudflare.com', 'akamai.net', 'akamaiedge.net', 'github.com', 'githubusercontent.com', 'gstatic.com', 'googleapis.com', 'mozilla.org', 'w3.org', 'schemas.microsoft.com']);
const MASK_USER_KEYS = /^(?:user(?:name)?|usr|account(?:[ _]name)?|login|uid|suser|duser|src_?user|dst_?user|target_?user(?:name)?|subject_?user(?:name)?|owner|principal|upn|logon_?id|samaccountname|cs[_-]?username)$/i;
const MASK_HOST_KEYS = /^(?:host(?:name)?|computer(?:[ _]name)?|workstation(?:[ _]name)?|device(?:[ _]name)?|machine|shost|dhost|src_?host|dst_?host|node|server)$/i;
const maskPriv = ip => /^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip);
/* text → {text, map:[{kind, from, to, n}]} */
function maskText(text, opts = {}){
  text = String(text || ''); if(!text) return {text:'', map:[]};
  const map = new Map(), cnt = {}, next = k => (cnt[k] = (cnt[k] || 0) + 1);
  const put = (kind, from, to) => { const key = kind + '\u0000' + from.toLowerCase(); if(!map.has(key)) map.set(key, {kind, from, to:to(), n:0}); return map.get(key); };
  const dom = d => { d = d.toLowerCase(); const reg = d.split('.').slice(-2).join('.'); if(MASK_KEEP.has(d) || MASK_KEEP.has(reg)) return null; return put('domain', d, () => `domain-${next("domain")}.example`); };
  const ip4 = v => put('ipv4', v, () => { const i = next(maskPriv(v) ? 'ip4p' : 'ip4'); if(maskPriv(v)) return `10.255.${Math.floor(i / 254)}.${i % 254 + 1}`; const pools = ['192.0.2', '198.51.100', '203.0.113'], p = Math.floor((i - 1) / 254) % 3; return `${pools[p]}.${(i - 1) % 254 + 1}`; });
  const vals = [];   /* [kind, value, placeholder getter] */
  for(const x of E.extract(text)){
    const v = x.v;
    if(x.k === 'ipv4' && v !== '0.0.0.0' && v !== '127.0.0.1') vals.push(['ipv4', v, ip4(v)]);
    else if(x.k === 'ipv6') vals.push(['ipv6', v, put('ipv6', v, () => `2001:db8::${next('ipv6').toString(16)}`)]);
    else if(x.k === 'domain'){ const m = dom(v); if(m) vals.push(['domain', v, m]); }
    else if(x.k === 'email'){ const [u, d] = v.split('@'), md = dom(d); vals.push(['email', v, put('email', v, () => `user-${next('user')}@${md ? md.to : d}`)]); }
    else if(x.k === 'handle') vals.push(['handle', v, put('handle', v, () => `@user-${next('user')}`)]);
    else if(x.k === 'mac') vals.push(['mac', v, put('mac', v, () => `00:00:5e:00:53:${(next('mac') % 256).toString(16).padStart(2, '0')}`)]);
    else if(/^(md5|sha1|sha256|sha512)$/.test(x.k)) vals.push([x.k, v, put('hash', v, () => next('hash').toString(16).padStart(v.length, '0'))]);
    else if(/^(btc|eth|ltc|trx|doge|xmr|sol|ens)$/.test(x.k)) vals.push(['wallet', v, put('wallet', v, () => `wallet-${next('wallet')}`)]);
    else if(x.k === 'phone') vals.push(['phone', v, put('phone', v, () => `+1 555 01${String(next('phone') % 100).padStart(2, '0')}`)]);
    else if(x.k === 'iban') vals.push(['iban', v, put('iban', v, () => `XX00MASK${String(next('iban')).padStart(10, '0')}`)]);
  }
  /* names that are not indicators: users and hosts by where they sit in a log */
  const named = (kind, v) => { v = v.replace(/^["']|["']$/g, ''); if(!v || v.length > 64 || /^(?:-|n\/a|none|null|system|local service|network service|anonymous logon|\$|0x0|root|admin|administrator|guest|nobody|www-data|daemon|sshd)$/i.test(v) || /^\d+$/.test(v)) return;
    vals.push([kind, v, put(kind, v, () => `${kind}-${next(kind)}`)]); };
  for(const m of text.matchAll(/(?:^|[\s,;|{])"?([A-Za-z][\w .-]{0,30}?)"?\s*[=:]\s*"?([^\s,;|"}]{1,64})"?/gm)){ if(MASK_USER_KEYS.test(m[1].trim())) named('user', m[2]); else if(MASK_HOST_KEYS.test(m[1].trim())) named('host', m[2]); }
  for(const m of text.matchAll(/\b(?:for(?: invalid user)?|invalid user|user|by user|session opened for user|logged in as)\s+([A-Za-z_][\w.$-]{0,31})(?=\s+(?:from|port|by|\(|$))/gim)) named('user', m[1]);
  for(const m of text.matchAll(/^(?:<\d+>)?[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2} ([A-Za-z0-9][\w.-]{0,62}) /gm)) if(!/^\d+\.\d+\.\d+\.\d+$/.test(m[1])) named('host', m[1]);
  for(const m of text.matchAll(/[\\/](?:Users|home|Documents and Settings)[\\/]([^\\/\s"']{1,40})/gi)) if(!/^(public|default|all users|shared)$/i.test(m[1])) named('user', m[1]);
  for(const m of text.matchAll(/\b([A-Z][A-Z0-9-]{1,14})\\([A-Za-z][\w.$-]{0,30})/g)){ named('host', m[1]); named('user', m[2]); }   /* DOMAIN\user */
  if(!vals.length) return {text, map:[]};
  /* one pass, longest value first, so a domain inside an email or URL takes the same placeholder as on its own */
  const seen = new Map(); for(const [, v, e] of vals){ const k = v.toLowerCase(); if(!seen.has(k) || seen.get(k).from.length < e.from.length) seen.set(k, e); }
  const list = [...seen.keys()].sort((a, b) => b.length - a.length).slice(0, 5000);
  const re = new RegExp('(?<![A-Za-z0-9_])(?:' + list.map(v => v.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|') + ')(?![A-Za-z0-9_])', 'gi');
  const out = text.replace(re, m => { const e = seen.get(m.toLowerCase()); if(!e) return m; e.n++; return e.to; });
  return {text:out, map:[...map.values()].filter(e => e.n).sort((a, b) => a.kind.localeCompare(b.kind) || b.n - a.n)};
}
const MASK_LABEL = {ipv4:'IP addresses', ipv6:'IPv6 addresses', domain:'Domains and hosts', email:'Email addresses', handle:'Handles', mac:'MAC addresses', hash:'Hashes', wallet:'Wallets', phone:'Phone numbers', iban:'IBANs', user:'User names', host:'Host names'};
const MASK_ONE = {ipv4:'IP address', ipv6:'IPv6 address', domain:'domain', email:'email address', handle:'handle', mac:'MAC address', hash:'hash', wallet:'wallet', phone:'phone number', iban:'IBAN', user:'user name', host:'host name'};
function maskSummary(map){ const c = {}; for(const e of map) c[e.kind] = (c[e.kind] || 0) + 1; return Object.entries(c).map(([k, n]) => { const one = MASK_ONE[k] || k; return `${n} ${n === 1 ? one : one + (/(s|sh)$/.test(one) ? 'es' : 's')}`; }).join(', '); }
/* copy a masked copy of any text, saying what was replaced */
function maskCopy(text){ const M = maskText(text); if(!M.map.length) return copyText(text, 'Copied — nothing in it needed masking');
  copyText(M.text, 'Copied masked — ' + maskSummary(M.map) + ' replaced'); }
const MASK_ACTS = {
  recCopyBody:id => { const r = recById(id); if(r) copyText(r.body || ''); },
  recCopyMasked:id => { const r = recById(id); if(r) maskCopy(r.body || ''); }};
