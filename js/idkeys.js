/* ==========================================================================
   SSH keys and decentralised accounts, read offline.
   · SSH keys: a public key (authorized_keys, known_hosts, a .pub file, a
     Shodan or Censys banner) is parsed for its type and size and named by its
     SHA-256 fingerprint, the form OpenSSH prints and logs. So a key pasted in
     full, "SHA256:…" in an auth log and the hex fingerprint Censys shows are
     one entity. The same key on several servers ties them to one operator.
   · Fediverse (@user@instance), Matrix (@user:server), Nostr (npub, nprofile,
     and the hex public key in signed events) and AT Protocol / Bluesky DIDs
     (did:plc, did:web). Nostr's bech32 checksum is verified and the key is
     shown both ways. A Nostr private key (nsec) is never kept: it is flagged
     as a leaked secret.
   ========================================================================== */
const IDKEYS = (() => {
  /* ---------- bytes ---------- */
  const b64d = s => { try{ return Uint8Array.from(atob(s), c => c.charCodeAt(0)); }catch(e){ return null; } };
  const b64e = u => { let s = ''; for(let i = 0; i < u.length; i += 32768) s += String.fromCharCode(...u.subarray(i, i + 32768)); return btoa(s); };
  const hexOf = u => [...u].map(x => x.toString(16).padStart(2, '0')).join('');
  const fromHex = h => Uint8Array.from(h.match(/../g).map(x => parseInt(x, 16)));
  /* SHA-256, synchronous (extraction is synchronous; WebCrypto is not) */
  const K = new Uint32Array([0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
  function sha256(m){
    const l = m.length, n = ((l + 9 + 63) >> 6) << 6, b = new Uint8Array(n); b.set(m); b[l] = 0x80; const dv = new DataView(b.buffer); dv.setUint32(n - 4, l * 8 >>> 0); dv.setUint32(n - 8, Math.floor(l / 0x20000000));
    const H = new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]), W = new Uint32Array(64), r = (x, k) => x >>> k | x << 32 - k;
    for(let o = 0; o < n; o += 64){ for(let i = 0; i < 16; i++) W[i] = dv.getUint32(o + i * 4);
      for(let i = 16; i < 64; i++){ const a = W[i - 15], c = W[i - 2]; W[i] = (W[i - 16] + (r(a, 7) ^ r(a, 18) ^ a >>> 3) + W[i - 7] + (r(c, 17) ^ r(c, 19) ^ c >>> 10)) >>> 0; }
      let [a, bb, c, d, e, f, g, h] = H;
      for(let i = 0; i < 64; i++){ const t1 = (h + (r(e, 6) ^ r(e, 11) ^ r(e, 25)) + (e & f ^ ~e & g) + K[i] + W[i]) >>> 0, t2 = ((r(a, 2) ^ r(a, 13) ^ r(a, 22)) + (a & bb ^ a & c ^ bb & c)) >>> 0; h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = bb; bb = a; a = (t1 + t2) >>> 0; }
      H[0] += a; H[1] += bb; H[2] += c; H[3] += d; H[4] += e; H[5] += f; H[6] += g; H[7] += h; }
    const out = new Uint8Array(32), ov = new DataView(out.buffer); for(let i = 0; i < 8; i++) ov.setUint32(i * 4, H[i]); return out; }

  /* ---------- SSH public keys (RFC 4253 wire format) ---------- */
  const SSH_TYPES = /^(ssh-ed25519|ssh-rsa|ssh-dss|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)$/;
  function sshParse(b64, declared){
    const blob = b64d(String(b64 || '').trim()); if(!blob || blob.length < 19 || blob.length > 4096) return null;
    let o = 0; const dv = new DataView(blob.buffer), str = () => { if(o + 4 > blob.length) throw 0; const n = dv.getUint32(o); o += 4; if(n > blob.length - o) throw 0; const s = blob.subarray(o, o + n); o += n; return s; };
    let type, bits = 0, curve = '', sk = false;
    try{ type = new TextDecoder().decode(str()); if(!SSH_TYPES.test(type) || (declared && declared !== type)) return null;
      if(type === 'ssh-rsa'){ str(); const N = str(); let i = 0; while(i < N.length && !N[i]) i++; bits = (N.length - i) * 8 - (i < N.length ? Math.clz32(N[i]) - 24 : 0); }
      else if(type === 'ssh-dss'){ const P = str(); let i = 0; while(i < P.length && !P[i]) i++; bits = (P.length - i) * 8 - (i < P.length ? Math.clz32(P[i]) - 24 : 0); }
      else if(/ed25519/.test(type)){ const k = str(); if(k.length !== 32) return null; bits = 256; sk = type.startsWith('sk-'); }
      else { curve = new TextDecoder().decode(str()); str(); bits = +curve.replace(/\D/g, '') || 0; sk = type.startsWith('sk-'); }
    }catch(e){ return null; }
    const d = sha256(blob);
    return {type, bits, curve, sk, sha256:'SHA256:' + b64e(d).replace(/=+$/, ''), hex:hexOf(d), md5:typeof md5 === 'function' ? 'MD5:' + String(md5(blob)).replace(/(..)(?!$)/g, '$1:') : ''}; }
  /* the hex SHA-256 fingerprint some scanners show (Censys) is the same digest as OpenSSH's base64 one */
  const sshHexToFp = h => /^[0-9a-f]{64}$/i.test(h) ? 'SHA256:' + b64e(fromHex(h.toLowerCase())).replace(/=+$/, '') : '';
  const sshFpToHex = fp => { const u = /^SHA256:([A-Za-z0-9+/]{43})$/.exec(fp || ''); const b = u && b64d(u[1] + '='); return b && b.length === 32 ? hexOf(b) : ''; };
  function sshInfo(k){
    const L = {'ssh-ed25519':'Ed25519', 'ssh-rsa':'RSA', 'ssh-dss':'DSA', 'sk-ssh-ed25519@openssh.com':'Ed25519 on a hardware security key', 'sk-ecdsa-sha2-nistp256@openssh.com':'ECDSA P-256 on a hardware security key'}[k.type] || 'ECDSA ' + (k.curve || '').replace('nistp', 'P-');
    const warn = k.type === 'ssh-dss' ? 'DSA keys are disabled by default since OpenSSH 7.0 (2015): the key, or the server that still accepts it, is old.' : k.type === 'ssh-rsa' && k.bits < 2048 ? 'RSA under 2048 bits can be broken with enough computing power; made long ago, or by someone careless.' : '';
    return {label:L, warn}; }

  /* ---------- bech32 (BIP-173), for Nostr ---------- */
  const CH = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l', G = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  const poly = v => { let c = 1; for(const x of v){ const b = c >>> 25; c = (c & 0x1ffffff) << 5 ^ x; for(let i = 0; i < 5; i++) if(b >> i & 1) c ^= G[i]; } return c >>> 0; };
  const hrpX = h => [...[...h].map(x => x.charCodeAt(0) >> 5), 0, ...[...h].map(x => x.charCodeAt(0) & 31)];
  const conv = (data, f, t, pad) => { let acc = 0, bits = 0; const r = [], m = (1 << t) - 1; for(const v of data){ acc = acc << f | v; bits += f; while(bits >= t){ bits -= t; r.push(acc >> bits & m); } acc &= (1 << bits) - 1; } if(pad && bits) r.push(acc << t - bits & m); else if(!pad && (bits >= f || acc << t - bits & m)) return null; return r; };
  function bechDecode(s){ s = String(s || '').toLowerCase(); const p = s.lastIndexOf('1'); if(p < 1 || s.length > 5000) return null; const hrp = s.slice(0, p), d = [...s.slice(p + 1)].map(c => CH.indexOf(c));
    if(d.length < 7 || d.some(x => x < 0) || poly([...hrpX(hrp), ...d]) !== 1) return null; const bytes = conv(d.slice(0, -6), 5, 8, false); return bytes ? {hrp, bytes:Uint8Array.from(bytes)} : null; }
  function bechEncode(hrp, bytes){ const d = conv([...bytes], 8, 5, true), cs = poly([...hrpX(hrp), ...d, 0, 0, 0, 0, 0, 0]) ^ 1; return hrp + '1' + [...d, ...[0, 1, 2, 3, 4, 5].map(i => cs >> 5 * (5 - i) & 31)].map(x => CH[x]).join(''); }
  const npubHex = n => { const D = bechDecode(n); return D && D.hrp === 'npub' && D.bytes.length === 32 ? hexOf(D.bytes) : ''; };
  const hexNpub = h => /^[0-9a-f]{64}$/i.test(h) ? bechEncode('npub', fromHex(h.toLowerCase())) : '';
  /* nprofile: TLV — 0 the public key, 1 a relay where the profile is found */
  function nprofile(s){ const D = bechDecode(s); if(!D || D.hrp !== 'nprofile') return null; const b = D.bytes, out = {pub:'', relays:[]};
    for(let o = 0; o + 2 <= b.length;){ const t = b[o], l = b[o + 1], v = b.subarray(o + 2, o + 2 + l); if(v.length !== l) break; if(t === 0 && l === 32) out.pub = hexOf(v); else if(t === 1) out.relays.push(new TextDecoder().decode(v)); o += 2 + l; }
    return out.pub ? {npub:hexNpub(out.pub), hex:out.pub, relays:out.relays.slice(0, 20)} : null; }

  /* ---------- federated accounts ---------- */
  /* large shared servers: an account there says little about who runs the server; a small or personal one points at its owner */
  const FEDI_BIG = new Set(('mastodon.social mastodon.online mstdn.social mas.to mastodon.world mstdn.jp infosec.exchange ioc.exchange hachyderm.io fosstodon.org chaos.social social.coop mastodon.art ' +
    'troet.cafe det.social mastodon.uno masto.ai universeodon.com mastodon.cloud misskey.io pixelfed.social mastodon.scot aus.social mastodon.nz toot.community techhub.social sigmoid.social ' +
    'piaille.fr framapiaf.org kolektiva.social social.vivaldi.net mastodon.green defcon.social cyberplace.social lemmy.world kbin.social threads.net').split(' '));
  const MATRIX_BIG = new Set('matrix.org mozilla.org kde.org gnome.org fedora.im envs.net tchncs.de nitro.chat converser.eu'.split(' '));
  const fediParts = v => { const m = /^@([^@]+)@(.+)$/.exec(v || ''); return m ? {user:m[1], host:m[2], url:'https://' + m[2] + '/@' + m[1], big:FEDI_BIG.has(m[2])} : null; };
  const matrixParts = v => { const m = /^@([^:]+):(.+)$/.exec(v || ''); return m ? {user:m[1], host:m[2].replace(/:\d+$/, ''), url:'https://matrix.to/#/' + v, big:MATRIX_BIG.has(m[2].replace(/:\d+$/, ''))} : null; };
  const didParts = v => { const m = /^did:(plc|web):(.+)$/.exec(v || ''); return m ? {method:m[1], id:m[2]} : null; };
  /* the user part of an account, for matching one name across networks */
  const userOf = (k, v) => k === 'fedi' ? (fediParts(v) || {}).user || '' : k === 'matrix' ? (matrixParts(v) || {}).user || '' : '';

  return {sha256, b64e, hexOf, sshParse, sshHexToFp, sshFpToHex, sshInfo, bechDecode, bechEncode, npubHex, hexNpub, nprofile, fediParts, matrixParts, didParts, userOf, FEDI_BIG};
})();
