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
/* how many bytes a base58 string decodes to (leading 1s are zero bytes) — a Solana address is 32, a signature 64 */
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function b58Bytes(s){ let n = 0n; for(const ch of s){ const i = B58.indexOf(ch); if(i < 0) return -1; n = n * 58n + BigInt(i); }
  let len = 0; while(n > 0n){ n >>= 8n; len++; } let z = 0; while(s[z] === '1') z++; return len + z; }
/* a 64-hex value written next to "tx", "txid", "transaction" or a block-explorer path is a Bitcoin transaction, not a file hash */
const BTC_TX_CTX = /(?:\b(?:tx|txid|txn|tx[\s_-]?hash|tx[\s_-]?id|transaction(?:[\s_-]?(?:id|hash))?|spent in|paid in|funded by)\b[^\n\w]{0,4}|(?:mempool\.space|blockstream\.info|blockchair\.com|blockchain\.com|btcscan\.org|blockcypher\.com)\/[\w\/-]*?\/(?:tx|transactions?)\/(?:btc\/)?)$/i;
/* ---------- dark web: Tor onion addresses and OpenPGP keys, read offline ---------- */
/* SHA-1 (an OpenPGP v4 fingerprint) and SHA3-256 (a Tor v3 address checksum) over bytes */
function sha1(b){ const l = b.length, n = ((l + 8 >> 6) + 1) << 4, w = new Int32Array(n); for(let i = 0; i < l; i++) w[i >> 2] |= b[i] << (24 - (i & 3) * 8);
  w[l >> 2] |= 0x80 << (24 - (l & 3) * 8); w[n - 1] = l * 8; let h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0; const x = new Int32Array(80);
  for(let i = 0; i < n; i += 16){ let a = h0, bb = h1, c = h2, d = h3, e = h4;
    for(let j = 0; j < 80; j++){ x[j] = j < 16 ? w[i + j] : (t => t << 1 | t >>> 31)(x[j - 3] ^ x[j - 8] ^ x[j - 14] ^ x[j - 16]);
      const f = j < 20 ? (bb & c | ~bb & d) + 0x5A827999 : j < 40 ? (bb ^ c ^ d) + 0x6ED9EBA1 : j < 60 ? (bb & c | bb & d | c & d) + 0x8F1BBCDC : (bb ^ c ^ d) + 0xCA62C1D6;
      const t = ((a << 5 | a >>> 27) + f + e + x[j]) | 0; e = d; d = c; c = bb << 30 | bb >>> 2; bb = a; a = t; }
    h0 = h0 + a | 0; h1 = h1 + bb | 0; h2 = h2 + c | 0; h3 = h3 + d | 0; h4 = h4 + e | 0; }
  return [h0, h1, h2, h3, h4].map(h => (h >>> 0).toString(16).padStart(8, '0')).join(''); }
const KRC = [1n,0x8082n,0x800000000000808an,0x8000000080008000n,0x808bn,0x80000001n,0x8000000080008081n,0x8000000000008009n,0x8an,0x88n,0x80008009n,0x8000000an,0x8000808bn,0x800000000000008bn,0x8000000000008089n,0x8000000000008003n,0x8000000000008002n,0x8000000000000080n,0x800an,0x800000008000000an,0x8000000080008081n,0x8000000000008080n,0x80000001n,0x8000000080008008n];
const KRO = [0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14], M64 = (1n << 64n) - 1n, rot = (v, r) => r ? ((v << BigInt(r)) | (v >> BigInt(64 - r))) & M64 : v;
function sha3_256(bytes){ const rate = 136, m = [...bytes, 0x06]; while(m.length % rate) m.push(0); m[m.length - 1] |= 0x80; const S = new Array(25).fill(0n);
  for(let o = 0; o < m.length; o += rate){ for(let i = 0; i < rate / 8; i++){ let v = 0n; for(let k = 7; k >= 0; k--) v = (v << 8n) | BigInt(m[o + i * 8 + k]); S[i] ^= v; }
    for(let r = 0; r < 24; r++){ const C = [0, 1, 2, 3, 4].map(x => S[x] ^ S[x + 5] ^ S[x + 10] ^ S[x + 15] ^ S[x + 20]);
      for(let x = 0; x < 5; x++){ const D = C[(x + 4) % 5] ^ rot(C[(x + 1) % 5], 1); for(let y = 0; y < 25; y += 5) S[x + y] ^= D; }
      const B = new Array(25); for(let x = 0; x < 5; x++) for(let y = 0; y < 5; y++) B[y + ((2 * x + 3 * y) % 5) * 5] = rot(S[x + 5 * y], KRO[x + 5 * y]);
      for(let x = 0; x < 5; x++) for(let y = 0; y < 25; y += 5) S[x + y] = B[x + y] ^ ((~B[(x + 1) % 5 + y] & M64) & B[(x + 2) % 5 + y]);
      S[0] ^= KRC[r]; } }
  const out = []; for(let i = 0; i < 4; i++){ let v = S[i]; for(let k = 0; k < 8; k++){ out.push(Number(v & 255n)); v >>= 8n; } } return out; }
const B32A = 'abcdefghijklmnopqrstuvwxyz234567';
function b32dec(s){ let bits = 0, val = 0; const out = []; for(const ch of s.toLowerCase()){ const i = B32A.indexOf(ch); if(i < 0) return null; val = (val << 5) | i; bits += 5; if(bits >= 8){ out.push((val >>> (bits - 8)) & 255); bits -= 8; } } return out; }
/* a Tor onion address: v3 is 56 base32 characters = ed25519 key, 2-byte checksum, version 3 */
function onionInfo(host){ const h = String(host).toLowerCase().replace(/^.*?([a-z2-7]+)\.onion$/, '$1');
  if(h.length === 16) return {v:2, ok:null}; if(h.length !== 56) return null; const b = b32dec(h); if(!b || b.length !== 35) return {v:3, ok:false};
  const key = b.slice(0, 32), sum = b.slice(32, 34), ver = b[34], want = sha3_256([...'.onion checksum'].map(c => c.charCodeAt(0)).concat(key, [3]));
  return {v:ver, ok:ver === 3 && want[0] === sum[0] && want[1] === sum[1], key:key.map(x => x.toString(16).padStart(2, '0')).join('')}; }
/* an armoured OpenPGP public key: each primary key and subkey with its v4 fingerprint, algorithm, size, date and user IDs */
const PGP_ALGO = {1:'RSA', 2:'RSA', 3:'RSA', 16:'ElGamal', 17:'DSA', 18:'ECDH', 19:'ECDSA', 22:'EdDSA', 25:'X25519', 27:'Ed25519'};
const PGP_CURVE = {'2b060104019755010501':'Curve25519', '2b06010401da470f01':'Ed25519', '2a8648ce3d030107':'NIST P-256', '2b81040022':'NIST P-384', '2b81040023':'NIST P-521', '2b2403030208010107':'brainpoolP256r1'};
function pgpParse(text){
  const m = /-----BEGIN PGP PUBLIC KEY BLOCK-----([\s\S]*?)-----END PGP PUBLIC KEY BLOCK-----/.exec(String(text)); if(!m) return [];
  const b64 = m[1].split(/\r?\n/).filter(l => !/^[\w-]+:\s/.test(l) && !/^=/.test(l.trim())).join('').replace(/[^A-Za-z0-9+/=]/g, '');
  let bin; try{ bin = atob(b64); }catch(e){ return []; } const B = Uint8Array.from(bin, c => c.charCodeAt(0)), keys = []; let i = 0, cur = null;
  while(i < B.length && keys.length < 40){ const h = B[i++]; if(!(h & 0x80)) break; let tag, len;
    if(h & 0x40){ tag = h & 63; const o = B[i++]; if(o < 192) len = o; else if(o < 224) len = ((o - 192) << 8) + B[i++] + 192; else if(o === 255){ len = (B[i] << 24 | B[i + 1] << 16 | B[i + 2] << 8 | B[i + 3]) >>> 0; i += 4; } else break; }
    else { tag = (h >> 2) & 15; const lt = h & 3; len = lt === 0 ? B[i++] : lt === 1 ? (B[i++] << 8 | B[i++]) : lt === 2 ? ((B[i++] << 24 | B[i++] << 16 | B[i++] << 8 | B[i++]) >>> 0) : B.length - i; }
    const body = B.subarray(i, i + len); i += len; if(body.length < len) break;
    if((tag === 6 || tag === 14) && body[0] === 4){ const fp = sha1([0x99, len >> 8 & 255, len & 255, ...body]).toUpperCase(), algo = body[5];
      let bits = 0, curve = ''; if(algo <= 3 || algo === 16 || algo === 17){ bits = body[6] << 8 | body[7]; }
      else if(algo === 18 || algo === 19 || algo === 22){ const ol = body[6]; curve = PGP_CURVE[[...body.subarray(7, 7 + ol)].map(x => x.toString(16).padStart(2, '0')).join('')] || 'other curve'; }
      else if(algo === 27) curve = 'Ed25519'; else if(algo === 25) curve = 'Curve25519';
      const k = {fp, id:fp.slice(-16), sub:tag === 14, algo:PGP_ALGO[algo] || 'algorithm ' + algo, bits, curve, created:((body[1] << 24 | body[2] << 16 | body[3] << 8 | body[4]) >>> 0) * 1000, uids:[]};
      keys.push(k); if(tag === 6) cur = k; }
    else if((tag === 6 || tag === 14) && body[0] !== 4) keys.push({fp:'', sub:tag === 14, v:body[0], uids:[]});
    else if(tag === 13 && cur && cur.uids.length < 20){ try{ cur.uids.push(new TextDecoder().decode(body).slice(0, 200)); }catch(e){} } }
  return keys; }

function norm(k, v){
  v = String(v).trim();
  switch(k){
    case 'pgp': return v.replace(/\s+/g, '').replace(/^0x/i, '').toUpperCase();
    case 'tox': return v.toUpperCase();
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
  if(/^0x[a-f0-9]{40}$/i.test(v)) return 'eth'; if(/^[a-z0-9-]{3,}(?:\.[a-z0-9-]+)*\.eth$/i.test(v)) return 'ens';
  if(/^[1-9A-HJ-NP-Za-km-z]{43,44}$/.test(v) && b58Bytes(v) === 32) return 'sol'; if(/^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$/.test(v)) return 'xmr'; if(/^(ltc1|[LM][a-km-zA-HJ-NP-Z1-9]{26,33}$)/.test(v)) return 'ltc';
  if(/^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(v)) return 'trx'; if(/^D[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32}$/.test(v)) return 'doge'; return 'btc'; }
const PATTERNS = [
  ['sha512',/\b[a-f0-9]{128}\b/gi],
  /* private messengers dark-web vendors list as contacts: a Session ID is 05 + 32 bytes, a Tox ID 38 bytes, both hex */
  /* chat accounts' permanent numbers, where a text names them (an imported chat export writes them this way) */
  ['tgid',/\bTelegram (?:user )?ID:?\s*(\d{5,15})\b/gi,1],
  ['dcid',/\bDiscord (?:user |server |channel )?ID:?\s*(\d{17,20})\b/gi,1],
  ['session',/\b05[0-9a-f]{64}\b/gi],
  ['tox',/\b[0-9A-F]{76}\b/gi],
  ['pgp',/\b[0-9A-F]{4}(?: [0-9A-F]{4}){4} {1,2}[0-9A-F]{4}(?: [0-9A-F]{4}){4}\b/gi],
  ['ethtx',/\b0x[a-fA-F0-9]{64}\b/g],
  /* Solana: base58 that decodes to 32 bytes (an address) or 64 (a signature); not a piece of base64, a JWT or a longer token */
  ['soltx',/(?<![\w+=.-])[1-9A-HJ-NP-Za-km-z]{86,88}(?![\w+=-]|[.\/]\w)/g],
  ['sha256',/\b[a-f0-9]{64}\b/gi],
  ['sha1',/\b[a-f0-9]{40}\b/gi],
  ['md5',/\b[a-f0-9]{32}\b/gi],
  ['cve',/\bCVE-\d{4}-\d{4,7}\b/gi],
  ['eventid',/\b(?:event\s*id|eventid|eid)\s*[:=]?\s*(\d{1,5})\b/gi,1],
  ['ttp',/\bT1\d{3}(?:\.\d{3})?\b/g],
  ['eth',/\b0x[a-fA-F0-9]{40}\b/g],
  ['xmr',/\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b/g],
  ['ens',/\b[a-z0-9-]{3,}(?:\.[a-z0-9-]+)*\.eth\b(?![.-]\w)/gi],
  ['btc',/\b(?:bc1[ac-hj-np-z02-9]{25,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g],
  ['ltc',/\b(?:ltc1[ac-hj-np-z02-9]{39,59}|[LM][a-km-zA-HJ-NP-Z1-9]{26,33})\b/g],
  ['trx',/\bT[1-9A-HJ-NP-Za-km-z]{33}\b/g],
  ['doge',/\bD[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32}\b/g],
  ['sol',/(?<![\w+=.-])[1-9A-HJ-NP-Za-km-z]{43,44}(?![\w+=-]|[.\/]\w)/g],
  ['iban',/\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b/g],
  ['sid',/\bS-1-(?:\d{1,10}-){1,14}\d{1,10}\b/g],
  ['social',/\b(?:https?:\/\/)?(?:www\.|m\.|mobile\.|old\.)?(?:twitter\.com|x\.com|instagram\.com|facebook\.com|fb\.com|tiktok\.com|github\.com|gitlab\.com|t\.me|telegram\.me|reddit\.com|linkedin\.com|youtube\.com|threads\.net|pinterest\.com|medium\.com|twitch\.tv|vk\.com|keybase\.io|bsky\.app|snapchat\.com|soundcloud\.com|steamcommunity\.com|hackerone\.com|patreon\.com|onlyfans\.com)\/[^\s"'<>()\[\]]+/gi],
  /* a URL may hold balanced brackets (Wikipedia pages: /wiki/Foo_(bar)) and an IPv6 host in square brackets; an ellipsis ends it */
  ['url',/\bhttps?:\/\/(?:\[[0-9a-f:.]+\](?::\d{1,5})?(?:\/(?:[^\s"'<>()\[\]…]|\([^\s"'<>()\[\]…]*\))*)?|(?:[^\s"'<>()\[\]…]|\([^\s"'<>()\[\]…]*\))+)/gi],
  ['mac',/\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b|\b(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}\b/gi],
  ['ipv6',/(?<![\w:.])(?:[0-9a-f]{1,4}:(?::?[0-9a-f]{1,4}){0,7}::?|::)(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,7})?(?![\w:.])/gi],
  ['phone',/(?:\btel:|(?:\b(?:phone|tel|mobile|cell|whats\s?app|call|fax|contact)\b[^\d+\n]{0,12}))?\+\d{1,3}[\s.-]?\(?\d{1,4}\)?(?:[\s.-]?\d{2,5}){1,4}\b|\b(?:phone|tel|mobile|cell|whats\s?app|call(?: me)?|fax)\b[^\d\n]{0,12}\(?\d{2,5}\)?(?:[\s.-]?\d{2,5}){1,4}\b/gi],
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
  ['ipv4',/(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d)/g],
  /* internationalised domains written in other scripts (раураl.com): kept whole, so a look-alike is not cut down to "l.com" */
  ['domain',/(?<![\w\u00C0-\uFFFF-])(?=[\w-]*[\u00C0-\u024F\u0370-\u03FF\u0400-\u04FF])[\w\u00C0-\u024F\u0370-\u03FF\u0400-\u04FF-]{1,63}(?:\.[\w\u00C0-\u024F\u0370-\u03FF\u0400-\u04FF-]{1,63})*\.[a-z\u0400-\u04FF]{2,24}\b/gi],
  ['domain',/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24})\b/gi],
];
const KINDS = ['ipv4','ipv6','hostport','domain','url','email','handle','social','phone','btc','eth','xmr','ltc','trx','doge','sol','ens','btctx','ethtx','soltx','pgp','session','tox','tgid','dcid','iban','md5','sha1','sha256','sha512',
  'mac','asn','coords','file','path','regkey','account','sid','eventid','cve','ttp','custom'];
const GROUP = {tgid:'id',dcid:'id',session:'id',tox:'id',pgp:'id',sol:'id',ens:'id',btctx:'id',ethtx:'id',soltx:'id',ipv6:'net',mac:'net',asn:'net',social:'id',phone:'id',xmr:'id',ltc:'id',trx:'id',doge:'id',iban:'id',sha512:'hash',coords:'place',ttp:'vuln',ipv4:'net',hostport:'net',domain:'net',url:'net',email:'id',handle:'id',btc:'id',eth:'id',
  md5:'hash',sha1:'hash',sha256:'hash',file:'host',path:'host',regkey:'host',account:'id',sid:'id',
  eventid:'host',cve:'vuln',custom:'hash'};
const LABEL = {tgid:'Telegram ID',dcid:'Discord ID',session:'Session ID',tox:'Tox ID',pgp:'PGP key',sol:'SOL wallet',ens:'ENS name',btctx:'BTC transaction',ethtx:'ETH transaction',soltx:'SOL transaction',ipv6:'IPv6',mac:'MAC address',asn:'ASN',social:'Social profile',phone:'Phone',xmr:'XMR wallet',ltc:'LTC wallet',trx:'TRON wallet',doge:'DOGE wallet',iban:'IBAN',sha512:'SHA-512',coords:'Coordinates',ttp:'ATT&CK technique',ipv4:'IP',hostport:'IP:port',domain:'Domain',url:'URL',email:'Email',handle:'Handle',
  btc:'BTC wallet',eth:'ETH wallet',md5:'MD5',sha1:'SHA-1',sha256:'SHA-256',file:'File',path:'Path',
  regkey:'Reg key',account:'Account',sid:'SID',eventid:'Event ID',cve:'CVE',custom:'Custom'};
const LOWER = /^(ipv4|ipv6|hostport|domain|url|email|md5|sha1|sha256|sha512|file|handle|ens|btctx|ethtx|session)$/;
const validIP = s => s.split('.').every(o => o.length < 4 && +o <= 255);
/* punctuation around a value is not part of it — but a closing bracket that closes one opened inside it is */
const trimEdge = s => { let v = String(s).replace(/^[('"[{]+/,''), p;
  do { p = v; v = v.replace(/[.,;:!?'"]+$/, ''); const c = v.slice(-1), o = {')':'(', ']':'[', '}':'{'}[c]; if(o && v.split(o).length >= v.split(c).length) {} else if(o) v = v.slice(0, -1); } while(v !== p);
  return v; };
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
  // Very long runs without whitespace (minified blobs, base64, crafted "a.a.a…" strings) make the domain, email and
  // host:port patterns retry from every position, which is quadratic. Real indicators are far shorter than 400
  // characters, so such runs are cut into 256-character pieces before matching.
  let work = refang(text).replace(/\S{400,}/g, run => run.replace(/(.{256})/g, '$1 '));
  const out = [], seen = new Set();
  /* an armoured public key: its fingerprints and the names and emails it carries are read, then the block is set aside so its base64 yields nothing else */
  const pgpKeys = [];
  work = work.replace(/-----BEGIN PGP PUBLIC KEY BLOCK-----[\s\S]{0,200000}?-----END PGP PUBLIC KEY BLOCK-----/g, blk => { try{ pgpKeys.push(...pgpParse(blk)); }catch(e){} return blk.replace(/[^\n]/g, '\u0000'); });
  const orig = work;   // masking keeps lengths, so a URL that held a hash is read back whole from orig
  const push = (k, raw) => {
    let v = trimEdge(String(raw).trim()); if(!v) return;
    if(k === 'cve') v = v.toUpperCase(); else if(LOWER.test(k)) v = v.toLowerCase(); else v = norm(k, v);
    if(k === 'handle') v = '@' + v.replace(/^@/,'');
    const id = k + ':' + v; if(seen.has(id)) return; seen.add(id); out.push({k, v});
  };
  for(const [kind, re, cap] of PATTERNS){
    /* cheap tests first: most text holds none of these */
    if((kind === 'ens' && !/\.eth\b/i.test(work)) || (kind === 'tgid' && !/telegram/i.test(work)) || (kind === 'dcid' && !/discord/i.test(work)) || ((kind === 'session' || kind === 'tox' || kind === 'ethtx') && !/[0-9a-f]{60}/i.test(work))) continue;
    re.lastIndex = 0; const hits = []; let m;
    while((m = re.exec(work)) !== null){
      if(!m[0].length){ re.lastIndex++; continue; }
      const v = trimEdge(String(cap ? m[cap] : (kind === 'url' || kind === 'social') && m[0].includes('\u0000') ? orig.substr(m.index, m[0].length) : m[0]).trim()); if(!v) continue;
      if(kind === 'ipv4' && !validIP(v)) continue;
      if(kind === 'ipv6' && (!validIPv6(v) || /^[0-9]+:[0-9]+(:[0-9]+)?$/.test(v) || (v.match(/:/g) || []).length < 2)) continue;
      if(kind === 'social' && !normSocial(v)) continue;
      if(kind === 'phone'){ const d = v.replace(/\D/g, ''); if(d.length < 8 || d.length > 15 || /^(19|20)\d{6}$/.test(d)) continue; }
      if(kind === 'coords' && (Math.abs(+m[1]) > 90 || Math.abs(+m[2]) > 180 || (+m[1] === 0 && +m[2] === 0))) continue;
      if(kind === 'iban' && !ibanOK(v)) continue;
      if(/^(btc|ltc|trx|doge|xmr|sol|soltx)$/.test(kind) && !/^(bc1|ltc1)/.test(v) && !mixedB58(v)) continue;
      if(kind === 'sol' && b58Bytes(v) !== 32) continue;
      if(kind === 'soltx' && b58Bytes(v) !== 64) continue;
      if(kind === 'sha1' && /\b(?:pgp|gpg|openpgp|fingerprint|fpr)\b(?:\s+key)?(?:\s+(?:id|fingerprint))?[^\n\w]{0,6}$/i.test(work.slice(Math.max(0, m.index - 40), m.index))){ hits.push([m.index, m[0].length, v, 'pgp']); continue; }
      if(kind === 'sha256' && BTC_TX_CTX.test(work.slice(Math.max(0, m.index - 80), m.index))){ hits.push([m.index, m[0].length, v, 'btctx']); continue; }
      if(kind === 'uname' && /^(name|password|id|agent|none|null|admin|root|unknown|required|here|the|and|for|with|from)$/i.test(v)) continue;
      if(kind === 'domain' && (/^\d+\./.test(v) || FILE_EXT_TLD.test(v) || !plausibleTLD(v))) continue;
      if(kind === 'domain' && m.index > 0 && /[\u00C0-\uFFFF]/.test(work[m.index - 1])) continue;   // the tail of a word in another script is not a domain
      hits.push([m.index, m[0].length, v]);
    }
    if(hits.length){ // mask in one rebuild — linear, not quadratic
      let built = '', at = 0;
      for(const [i, len] of hits){ built += work.slice(at, i) + '\u0000'.repeat(len); at = i + len; }
      work = built + work.slice(at);
    }
    for(const [,, v, as] of hits){
      if(as){ push(as, v); continue; }
      if(kind === 'phone'){ push('phone', v.replace(/^[^\d+]*(?=[+\d(])/, '').replace(/^tel:/i, '')); continue; }
      if(kind === 'uname'){ push('handle', v); continue; }
      if(kind === 'social'){ const s = normSocial(v); push('social', s.v); if(/^(x\.com|instagram\.com|tiktok\.com|github\.com|t\.me|threads\.net|twitch\.tv|gitlab\.com|keybase\.io|bsky\.app)$/.test(s.host) && /^[A-Za-z0-9_]{3,30}$/.test(s.user)) push('handle', s.user); continue; }
      push(kind, v);
      if(kind === 'path'){ const b = v.split(/[\\/]/).pop(); if(b && /\.[a-z0-9]{1,5}$/i.test(b)) push('file', b); }
      if(kind === 'hostport'){ const h = v.slice(0, v.lastIndexOf(':')); push(/^[\d.]+$/.test(h) ? 'ipv4' : 'domain', h); }
      if(kind === 'url'){
        const v6 = v.match(/^https?:\/\/\[([0-9a-f:.]+)\]/i); if(v6 && validIPv6(v6[1])) push('ipv6', v6[1]);
        const u = v.match(/^https?:\/\/(?:[^/@\s]*@)?([^/:?#\s]+)/i);
        if(u){ const h = u[1]; if(/^(?:\d{1,3}\.){3}\d{1,3}$/.test(h)){ if(validIP(h)) push('ipv4', h); } else if(plausibleTLD(h)) push('domain', h); }
      }
    }
  }
  for(const k of pgpKeys){ if(!k.fp || k.sub) continue; const id = 'pgp:' + k.fp; if(!seen.has(id)){ seen.add(id); out.push({k:'pgp', v:k.fp}); }
    for(const u of k.uids){ const em = /<([^<>\s]+@[^<>\s]+\.[a-z]{2,24})>/i.exec(u) || /\b([\w.+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+)\b/i.exec(u); if(em && !seen.has('email:' + em[1].toLowerCase())){ seen.add('email:' + em[1].toLowerCase()); out.push({k:'email', v:em[1].toLowerCase()}); } } }
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
  if(/^1\d{15}$/.test(s)) return Math.round(+s / 1000);                       // microseconds since 1970 (Chrome history is not this: see below)
  if(/^1\d{18}$/.test(s)) return Math.round(+s / 1e6);                        // nanoseconds since 1970 (Go, Elastic, Zeek)
  if(/^1[2-6]\d{16}$/.test(s)) return Math.round(+s / 1e4 - 11644473600000);  // Windows FILETIME: 100 ns since 1601
  m = s.match(/^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})(?:[.,](\d{1,9}))?(Z|[+-]\d{2}:?\d{2})?$/i);   // ISO 8601 basic form
  if(m){ const ms = m[7] ? Math.round(+('0.' + m[7]) * 1000) : 0; if(m[8]){ const z = m[8].toUpperCase() === 'Z' ? 0 : (m[8][0] === '-' ? -1 : 1) * (+m[8].slice(1, 3) * 60 + +m[8].slice(-2)) * 60000; return Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]) + ms - z; }
    return wallToEpoch(+m[1], +m[2], +m[3], +m[4], +m[5], +m[6], tz) + ms; }
  if(/\d:\d{2}:\d{2},\d/.test(s)) return parseTime(s.replace(/(\d:\d{2}:\d{2}),(\d)/, '$1.$2'), tz);   // log4j / Python logging: a comma before the milliseconds
  /* day, month and year in numbers: dots are always day-first; a first number over 12 is a day; otherwise month-first, as US logs write it */
  m = s.match(/^(\d{1,2})([./-])(\d{1,2})\2(\d{4}|\d{2})(?:[T ,]+(\d{1,2}):(\d{2})(?::(\d{2}))?(?:[.,](\d{1,9}))?\s*([AP]M)?)?(\s*(?:Z|UTC|GMT|[+-]\d{2}:?\d{2}))?$/i);
  if(m){ let a = +m[1], b = +m[3], y = +m[4]; if(m[4].length === 2) y += y < 70 ? 2000 : 1900; const dayFirst = m[2] === '.' || (a > 12 && b <= 12); const d = dayFirst ? a : b, mo = dayFirst ? b : a;
    if(mo >= 1 && mo <= 12 && d >= 1 && d <= 31){ let h = +(m[5] || 0); if(m[9]){ const pm = /p/i.test(m[9]); if(h === 12) h = pm ? 12 : 0; else if(pm) h += 12; } const ms = m[8] ? Math.round(+('0.' + m[8]) * 1000) : 0;
      if(m[10]){ const zs = m[10].trim(), z = /^(Z|UTC|GMT)$/i.test(zs) ? 0 : (zs[0] === '-' ? -1 : 1) * (+zs.slice(1, 3) * 60 + +zs.slice(-2)) * 60000; return Date.UTC(y, mo - 1, d, h, +(m[6] || 0), +(m[7] || 0)) + ms - z; }
      return wallToEpoch(y, mo, d, h, +(m[6] || 0), +(m[7] || 0), tz) + ms; } }
  if(carriesZone(s)){ const v = Date.parse(s.replace(/\b(UTC|GMT)\b/i,'Z').replace(/(\d)\s+Z$/,'$1Z').replace(/^(\d{4}-\d{2}-\d{2}) /,'$1T')); if(!isNaN(v)) return v; }
  m = s.match(/^(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})[T ,]+(\d{1,2}):(\d{2})(?::(\d{2})(?:[.,](\d{1,9}))?)?/);
  if(m) return wallToEpoch(+m[1], +m[2], +m[3], +m[4], +m[5], +(m[6] || 0), tz) + (m[7] ? Math.round(+('0.' + m[7]) * 1000) : 0);
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
/* observations are read many times (copilot, report, coverage); keep them per record until its text changes */
const OBS_C = new WeakMap();
function observations(rec){ const k = (rec.body || '').length + ':' + (rec.ents || []).length + ':' + (rec.title || '').length, c = OBS_C.get(rec); if(c && c.k === k) return c.v; const v = observations0(rec); OBS_C.set(rec, {k, v}); return v; }
function observations0(rec){
  const out = [], ents = rec.ents || [], body = rec.body || '';
  const val = k => ents.filter(e => e.k === k).map(e => e.v);
  const add = (tag, t, hot = true) => out.push({tag, t, hot});
  const files = val('file'), paths = val('path');
  const sysbin = files.filter(f => SYSBINS.has(f.toLowerCase()));
  const lol = files.filter(f => LOLBINS[f.toLowerCase()]);
  const userW = paths.filter(p => HOTPATH.some(([re]) => re.test(p)));
  const eids = val('eventid').map(Number);
  /* a system binary's name on a path where Windows does not keep it — judged per binary, so explorer.exe in C:\\Windows (its real home) or as the parent of something else is not a disguise */
  const sysOk = (p, b) => /\\windows\\(system32|syswow64|winsxs|servicing)\\/i.test(p) || /^(explorer|hh|regedit|notepad|bfsvc|splwow64|winhlp32|write)\.exe$/i.test(b) && /^([a-z]:)?\\windows\\[^\\]+$/i.test(p);
  const masq = sysbin.filter(b => { const ps = paths.filter(p => p.toLowerCase().split(/[\\/]/).pop() === b.toLowerCase()); return ps.length && ps.every(p => !sysOk(p, b)); });
  if(masq.length)
    add('masquerade', 'System binary name ('+[...new Set(masq)].join(', ')+') running from outside System32 — T1036.005.');
  if(lol.length && (val('url').length || val('ipv4').some(v => !/^(Private|Loopback|Link-local|This network|Multicast|Carrier-grade)/.test(ipClass(v)))))
    add('download', 'A LOLBin ('+lol.join(', ')+') alongside an external address — living-off-the-land download, T1105.');
  if(/-enc(odedcommand)?\b|-e\s+[A-Za-z0-9+/=]{20,}/i.test(body)) add('encoded', 'Encoded PowerShell command — decode it, it is usually the whole answer.');
  if(eids.some(n => n === 1102 || n === 104)) add('anti-forensics', 'Event log cleared — what came before is missing on purpose, T1070.001.');
  if(val('hostport').some(v => EVIL_PORTS[+v.slice(v.lastIndexOf(':') + 1)])) add('c2', 'Traffic to a port commonly used for reverse shells.');
  if(val('regkey').some(r => HOTKEY.some(([re]) => re.test(r))) || eids.some(n => [4697,7045,4698].includes(n))) add('persistence', 'Sets something up to run again later.');
  if(val('file').some(f => /\.(pdf|doc|docx|xls|txt)\.(exe|lnk|scr|js|hta)$/i.test(f))) add('lure', 'Disguised attachment — double extension.');
  /* what the command line or log text itself shows — the same few dozen tricks turn up in almost every intrusion */
  const txt = (rec.title || '') + '\n' + body, have = new Set(out.map(o => o.tag));
  for(const [tag, re, t] of BEHAVIOUR) if(!have.has(tag) && re.test(txt)){ add(tag, t); have.add(tag); }
  if(val('domain').some(d => /[^\x00-\x7f]/.test(d))) add('look-alike domain', 'Domain written with non-Latin letters (IDN homograph) — check what it imitates, T1583.001.');
  return out;
}
/* [tag, pattern, what it means]. Tags already used elsewhere keep their meaning (download, anti-forensics, persistence, c2). */
const BEHAVIOUR = [
  ['download', /\bcertutil(?:\.exe)?\b[^\n]{0,80}(?:-urlcache|-verifyctl|-split\s+-f)|\bbitsadmin(?:\.exe)?\b[^\n]{0,40}\/transfer|\b(?:invoke-webrequest|iwr|downloadstring|downloadfile|start-bitstransfer|net\.webclient)\b|\b(?:curl|wget)\b[^\n|;]{1,200}\|\s*(?:ba)?sh\b/i, 'Downloads a file with a built-in tool — ingress tool transfer, T1105.'],
  ['anti-forensics', /\bwevtutil(?:\.exe)?\s+(?:cl|clear-log)\b|\bclear-eventlog\b|\baudit log was cleared\b|\bhistory\s+-c\b|\bunset\s+histfile\b|\brm\s+(?:-\w+\s+)*[^\s]*\.bash_history\b|\bfsutil\s+usn\s+deletejournal\b/i, 'Clears logs or shell history — what came before is missing on purpose, T1070.'],
  ['impact', /\bvssadmin(?:\.exe)?\s+delete\s+shadows\b|\bwmic(?:\.exe)?\s+shadowcopy\s+delete\b|\bwbadmin(?:\.exe)?\s+delete\s+(?:catalog|systemstatebackup)\b|\bbcdedit(?:\.exe)?\b[^\n]{0,40}recoveryenabled\s+no\b/i, 'Deletes backups or shadow copies — typical just before ransomware, T1490.'],
  ['persistence', /\bschtasks(?:\.exe)?\s+\/create\b|\bregister-scheduledtask\b|\bsc(?:\.exe)?\s+(?:\\\\\S+\s+)?create\b|\bnew-service\b|\\currentversion\\run(?:once)?\b|\bcrontab\b|>>?\s*\/etc\/cron|\bauthorized_keys\b|\bsystemctl\s+enable\b/i, 'Sets something up to run again later — T1053 / T1543 / T1547.'],
  ['account', /\bnet1?(?:\.exe)?\s+user\s+\S+\s+\S*\s*\/add\b|\bnet1?(?:\.exe)?\s+(?:local)?group\s+"?(?:administrators|domain admins|enterprise admins)"?\s+\S+\s+\/add\b|\buseradd\b|\badd-localgroupmember\b|\bnew-localuser\b/i, 'Creates an account or adds one to an admin group — T1136 / T1098.'],
  ['proxy execution', /\bmshta(?:\.exe)?\s+(?:https?:|javascript:|vbscript:)|\brundll32(?:\.exe)?\s+(?:javascript:|[^\n]*\\(?:users|programdata|temp|appdata)\\[^\n]*\.dll)|\bregsvr32(?:\.exe)?\b[^\n]{0,40}\/i:\s*https?:|\bmsiexec(?:\.exe)?\b[^\n]{0,30}\/[iq]\w*\s+https?:|\binstallutil(?:\.exe)?\b|\bmsbuild(?:\.exe)?\b[^\n]{0,80}\.(?:xml|csproj)\b/i, 'Runs code through a signed Windows program — system binary proxy execution, T1218.'],
  ['credentials', /\bmimikatz\b|\bsekurlsa::|\blsadump::|\bprocdump(?:64)?(?:\.exe)?\b[^\n]{0,40}\blsass\b|\bcomsvcs(?:\.dll)?[^\n]{0,30}minidump\b|\breg(?:\.exe)?\s+save\s+hklm\\(?:sam|security|system)\b|\bntdsutil\b[^\n]{0,60}\bifm\b|\/etc\/shadow\b|\bkerberoast|\bRubeus\b/i, 'Goes after passwords or hashes — OS credential dumping, T1003.'],
  ['discovery', /\bnltest(?:\.exe)?\s+\/(?:domain_trusts|dclist)\b|\bnet1?(?:\.exe)?\s+group\s+"?domain (?:admins|computers)\b|\badfind(?:\.exe)?\b|\bwhoami(?:\.exe)?\s+\/(?:all|priv|groups)\b|\bget-ad(?:user|computer|group|domain)\b|\bbloodhound|sharphound\b|\bnet1?(?:\.exe)?\s+view\s+\\\\/i, 'Maps the domain, its admins and computers — T1087 / T1482.'],
  ['lateral movement', /\bpsexec(?:64)?(?:\.exe)?\b|\bwmic(?:\.exe)?\s+\/node:|\binvoke-command\b[^\n]{0,40}-computername\b|\benter-pssession\b|\bwinrs(?:\.exe)?\b|\\\\[\w.-]+\\(?:admin|c)\$|\blogon type:?\s*(?:3|10)\b[^\n]{0,200}\b(?:administrator|admin)\b/i, 'Moves to another machine — remote services, T1021 / T1570.'],
  ['defenses off', /\bset-mppreference\b[^\n]{0,60}-disable\w*\s+\$?true|\badd-mppreference\b[^\n]{0,40}-exclusion|\bsc(?:\.exe)?\s+(?:stop|config)\s+windefend\b|\bnetsh(?:\.exe)?\s+(?:advfirewall\s+set\s+\w+\s+state\s+off|firewall\s+set\s+opmode\s+disable)\b|\bauditpol(?:\.exe)?\s+\/(?:clear|remove)\b|\bsetenforce\s+0\b|\bstoplogging\b|\bdeletetrail\b/i, 'Turns off antivirus, firewall or logging — impair defenses, T1562.'],
  ['staging', /\b7za?(?:\.exe)?\s+a\b[^\n]{0,120}\s-p\S+|\brar(?:\.exe)?\s+a\b[^\n]{0,80}\s-hp\S*/i, 'Packs files into a password-protected archive — often a step before taking them, T1560.'],
  ['exfiltration', /\brclone(?:\.exe)?\b[^\n]{0,40}\b(?:copy|sync)\b|\bmegacmd|\bmega(?:put|sync)\b|\bcurl\b[^\n]{0,60}(?:-T\s|--upload-file|-F\s+["']?file=@)|\btransfer\.sh\b|\bfile\.io\b/i, 'Sends files out to an online service — exfiltration to cloud storage, T1567.'],
  ['c2', /\bnc(?:at)?(?:\.exe)?\s+(?:-\w+\s+)*-e\s+\S*(?:sh|cmd)\b|\bbash\s+-i\s+>&\s*\/dev\/tcp\/|\bsocat\b[^\n]{0,60}exec:|\bngrok\b|\bcobalt ?strike\b|\bbeacon(?:ing)?\b[^\n]{0,40}\b(?:interval|jitter|sleep)\b/i, 'Reverse shell or command-and-control channel — T1059 / T1071.'],
];

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
  const parts = String(q || '').split(/(?<!\s)\s+(?:OR|\|\|?)\s+/i).map(x => x.trim()).filter(Boolean);
  return parts.length ? parts.map(parseGroup) : null;
}

const REF = {EVENTIDS, SYSMON, EVIL_PORTS, PORTS, LOLBINS};
return {REF, esc, safeUrl, refang, extract, pgpParse, onionInfo, sha1, sha3_256, norm, normSocial, normPhone, normMac, cryptoKind, validIPv6, KINDS, GROUP, LABEL, parseTime, carriesZone, lineTime, zoneAbbr,
  fmtClock, fmtFull, fmtDate, fmtDay, fmtGap, fmtAgo, relClock, meaning, observations, ipClass, beaconOf,
  chapters, parseQuery};
})();
