/* ==========================================================================
   X.509 in the browser: an ASN.1 DER reader, certificates, certificate
   signing requests (PKCS#10) and PKCS#7 bundles, extensions explained in
   plain English, fingerprints, signature checks with WebCrypto, and the
   findings an investigator cares about. No network, no libraries.
   ========================================================================== */
const X5 = (() => {
  /* ---------- ASN.1 DER (definite lengths; BER indefinite lengths are read too) ---------- */
  function node(b, off, end, depth){
    if(depth > 64) throw new Error('nesting too deep');
    if(off + 2 > end) throw new Error('truncated');
    const t = b[off]; let p = off + 1;
    let tag = t & 0x1f; if(tag === 0x1f){ tag = 0; let n = 0; do{ if(p >= end || ++n > 4) throw new Error('bad tag'); tag = tag * 128 + (b[p] & 0x7f); }while(b[p++] & 0x80); }
    let len = b[p++], indef = false;
    if(len === 0x80){ indef = true; len = -1; }
    else if(len & 0x80){ const n = len & 0x7f; if(n > 4 || p + n > end) throw new Error('bad length'); len = 0; for(let i = 0; i < n; i++) len = len * 256 + b[p++]; }
    const cls = t >> 6, cons = !!(t & 0x20), cs = p;
    if(!indef && cs + len > end) throw new Error('length runs past the end');
    const N = {b, cls, cons, tag, hs:off, cs, ce:indef ? -1 : cs + len, end:indef ? -1 : cs + len, kids:null};
    if(cons){ N.kids = []; let q = cs; const lim = indef ? end : cs + len;
      while(q < lim){ if(indef && b[q] === 0 && b[q + 1] === 0){ N.ce = q; N.end = q + 2; break; } const k = node(b, q, lim, depth + 1); N.kids.push(k); q = k.end; if(N.kids.length > 20000) throw new Error('too many items'); }
      if(indef && N.end < 0) throw new Error('unterminated');
    } else if(indef) throw new Error('indefinite primitive');
    return N;
  }
  const parse = b => { const n = node(b, 0, b.length, 0); return n; };
  const bytes = n => n.b.subarray(n.cs, n.ce);
  const whole = n => n.b.subarray(n.hs, n.end);
  const U = (n, cls, tag) => n && n.cls === cls && n.tag === tag;
  const ctx = (n, tag) => n && n.cls === 2 && n.tag === tag;
  const kid = (n, i) => n && n.kids && n.kids[i];
  function oid(n){ const b = bytes(n); if(!b.length) return ''; const out = [Math.floor(b[0] / 40) > 2 ? 2 : Math.floor(b[0] / 40), b[0] >= 80 ? b[0] - 80 : b[0] % 40]; let v = 0;
    for(let i = 1; i < b.length; i++){ v = v * 128 + (b[i] & 0x7f); if(!(b[i] & 0x80)){ out.push(v); v = 0; } } return out.join('.'); }
  const hex = (u, sep = '') => [...u].map(x => x.toString(16).padStart(2, '0')).join(sep);
  function int(n){ let b = bytes(n); const neg = b[0] & 0x80; while(b.length > 1 && b[0] === 0) b = b.subarray(1); return {hex:hex(b), bits:b.length ? (b.length - 1) * 8 + Math.floor(Math.log2(b[0] || 1)) + 1 : 0, num:b.length <= 6 ? b.reduce((a, x) => a * 256 + x, 0) : null, neg:!!neg}; }
  function str(n){ const b = bytes(n);
    if(n.tag === 30){ let s = ''; for(let i = 0; i + 1 < b.length; i += 2) s += String.fromCharCode(b[i] << 8 | b[i + 1]); return s; }        // BMPString
    if(n.tag === 28){ let s = ''; for(let i = 0; i + 3 < b.length; i += 4) s += String.fromCodePoint(((b[i] << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3]) >>> 0); return s; }
    if(n.tag === 12) return new TextDecoder('utf-8', {fatal:false}).decode(b);
    return [...b].map(c => String.fromCharCode(c)).join(''); }
  function time(n){ const s = str(n); let m;
    if(n.tag === 23 && (m = s.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/))){ const y = +m[1]; return Date.UTC(y < 50 ? 2000 + y : 1900 + y, m[2] - 1, +m[3], +m[4], +m[5], +(m[6] || 0)); }
    if(n.tag === 24 && (m = s.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(\.\d+)?Z$/))) return Date.UTC(+m[1], m[2] - 1, +m[3], +m[4], +m[5], +(m[6] || 0));
    return NaN; }
  const bitstr = n => { const b = bytes(n); return {unused:b[0], data:b.subarray(1)}; };

  /* ---------- names ---------- */
  const ATTR = {'2.5.4.3':'CN', '2.5.4.6':'C', '2.5.4.7':'L', '2.5.4.8':'ST', '2.5.4.10':'O', '2.5.4.11':'OU', '2.5.4.5':'serialNumber', '2.5.4.9':'street', '2.5.4.17':'postalCode', '2.5.4.4':'SN', '2.5.4.42':'GN', '2.5.4.12':'title',
    '2.5.4.15':'businessCategory', '2.5.4.97':'organizationIdentifier', '1.2.840.113549.1.9.1':'emailAddress', '0.9.2342.19200300.100.1.25':'DC', '0.9.2342.19200300.100.1.1':'UID',
    '1.3.6.1.4.1.311.60.2.1.3':'jurisdictionC', '1.3.6.1.4.1.311.60.2.1.2':'jurisdictionST', '1.3.6.1.4.1.311.60.2.1.1':'jurisdictionL'};
  const ATTR_LONG = {CN:'Common name', C:'Country', L:'Locality', ST:'State or province', O:'Organisation', OU:'Organisational unit', serialNumber:'Registration number', emailAddress:'Email', DC:'Domain component', businessCategory:'Business category',
    jurisdictionC:'Jurisdiction country', jurisdictionST:'Jurisdiction state', jurisdictionL:'Jurisdiction locality', organizationIdentifier:'Organisation identifier', street:'Street', postalCode:'Postal code', UID:'User ID', GN:'Given name', SN:'Surname', title:'Title'};
  function name(n){ const parts = [], map = {};
    for(const set of n.kids || []) for(const atv of set.kids || []){ const o = oid(kid(atv, 0)), v = kid(atv, 1) ? str(kid(atv, 1)) : '', k = ATTR[o] || o; parts.push([k, v]); (map[k] = map[k] || []).push(v); }
    const esc = v => v.replace(/([,+"\\<>;])/g, '\\$1');
    return {parts, map, text:parts.map(([k, v]) => k + '=' + esc(v)).join(', '), raw:hex(whole(n))}; }

  /* ---------- algorithms ---------- */
  const SIG = {'1.2.840.113549.1.1.2':['MD2 with RSA', 'RSA', null], '1.2.840.113549.1.1.4':['MD5 with RSA', 'RSA', null], '1.2.840.113549.1.1.5':['SHA-1 with RSA', 'RSA', 'SHA-1'], '1.2.840.113549.1.1.11':['SHA-256 with RSA', 'RSA', 'SHA-256'],
    '1.2.840.113549.1.1.12':['SHA-384 with RSA', 'RSA', 'SHA-384'], '1.2.840.113549.1.1.13':['SHA-512 with RSA', 'RSA', 'SHA-512'], '1.2.840.113549.1.1.14':['SHA-224 with RSA', 'RSA', null], '1.2.840.113549.1.1.10':['RSASSA-PSS', 'PSS', null],
    '1.2.840.10045.4.1':['ECDSA with SHA-1', 'EC', 'SHA-1'], '1.2.840.10045.4.3.2':['ECDSA with SHA-256', 'EC', 'SHA-256'], '1.2.840.10045.4.3.3':['ECDSA with SHA-384', 'EC', 'SHA-384'], '1.2.840.10045.4.3.4':['ECDSA with SHA-512', 'EC', 'SHA-512'],
    '1.3.101.112':['Ed25519', 'Ed25519', null], '1.3.101.113':['Ed448', 'Ed448', null], '1.2.840.10040.4.3':['DSA with SHA-1', 'DSA', null], '2.16.840.1.101.3.4.3.2':['DSA with SHA-256', 'DSA', null], '1.2.643.7.1.1.3.2':['GOST R 34.10-2012 256', 'GOST', null]};
  const HASH = {'1.3.14.3.2.26':'SHA-1', '2.16.840.1.101.3.4.2.1':'SHA-256', '2.16.840.1.101.3.4.2.2':'SHA-384', '2.16.840.1.101.3.4.2.3':'SHA-512', '2.16.840.1.101.3.4.2.4':'SHA-224'};
  const CURVE = {'1.2.840.10045.3.1.7':['P-256', 256], '1.3.132.0.34':['P-384', 384], '1.3.132.0.35':['P-521', 521], '1.3.132.0.10':['secp256k1', 256], '1.2.840.10045.3.1.1':['P-192', 192], '1.3.132.0.33':['P-224', 224], '1.3.36.3.3.2.8.1.1.7':['brainpoolP256r1', 256]};
  function algId(n){ const o = oid(kid(n, 0)), p = kid(n, 1), A = {oid:o, name:(SIG[o] || [o])[0], fam:(SIG[o] || [])[1] || '', hash:(SIG[o] || [])[2] || null};
    if(o === '1.2.840.113549.1.1.10'){ let h = 'SHA-1', salt = 20;   // RSASSA-PSS parameters (defaults per RFC 4055)
      for(const k of (p && p.kids) || []){ if(ctx(k, 0)) h = HASH[oid(kid(kid(k, 0), 0))] || h; if(ctx(k, 2)) salt = int(kid(k, 0)).num; }
      A.hash = h; A.salt = salt; A.name = 'RSASSA-PSS with ' + h; }
    return A; }
  function spki(n){ const alg = kid(n, 0), o = oid(kid(alg, 0)), K = {oid:o, der:whole(n), type:o, bits:0, detail:''}, bs = bitstr(kid(n, 1));
    try{
      if(o === '1.2.840.113549.1.1.1' || o === '1.2.840.113549.1.1.10'){ const r = parse(bs.data), m = int(kid(r, 0)), e = int(kid(r, 1)); K.type = o.endsWith('.10') ? 'RSA-PSS' : 'RSA'; K.bits = m.bits; K.e = e.num != null ? e.num : e.hex; K.detail = 'e = ' + K.e; K.modulus = m.hex; }
      else if(o === '1.2.840.10045.2.1'){ const c = CURVE[oid(kid(alg, 1))] || [oid(kid(alg, 1)), 0]; K.type = 'ECDSA'; K.curve = c[0]; K.bits = c[1]; K.detail = c[0]; }
      else if(o === '1.3.101.112'){ K.type = 'Ed25519'; K.bits = 256; K.curve = 'Ed25519'; }
      else if(o === '1.3.101.113'){ K.type = 'Ed448'; K.bits = 456; }
      else if(o === '1.2.840.10040.4.1'){ K.type = 'DSA'; const r = parse(bs.data); K.bits = int(r).bits; }
      else if(o === '1.3.101.110' || o === '1.3.101.111'){ K.type = o.endsWith('110') ? 'X25519' : 'X448'; }
    }catch(e){ K.detail = 'could not read the key'; }
    K.label = K.type + (K.curve && K.curve !== K.type ? ' ' + K.curve : K.bits ? ' ' + K.bits : ''); return K; }

  /* ---------- extensions ---------- */
  const EKU = {'1.3.6.1.5.5.7.3.1':'Server authentication (TLS server)', '1.3.6.1.5.5.7.3.2':'Client authentication', '1.3.6.1.5.5.7.3.3':'Code signing', '1.3.6.1.5.5.7.3.4':'Email protection (S/MIME)',
    '1.3.6.1.5.5.7.3.8':'Time stamping', '1.3.6.1.5.5.7.3.36':'Document signing', '1.3.6.1.5.5.7.3.9':'OCSP signing', '1.3.6.1.5.5.7.3.5':'IPsec end system', '1.3.6.1.5.5.7.3.6':'IPsec tunnel', '1.3.6.1.5.5.7.3.7':'IPsec user', '1.3.6.1.5.5.7.3.17':'IPsec IKE',
    '2.5.29.37.0':'Any purpose', '1.3.6.1.4.1.311.20.2.2':'Smart card logon (Windows)', '1.3.6.1.4.1.311.10.3.12':'Document signing (Microsoft)', '1.3.6.1.4.1.311.10.3.4':'Encrypting File System (EFS)',
    '1.3.6.1.4.1.311.10.3.1':'Microsoft trust list signing', '1.3.6.1.4.1.311.20.2.1':'Certificate request agent (enrollment agent)', '1.3.6.1.5.2.3.4':'Kerberos client auth (PKINIT)', '1.3.6.1.5.2.3.5':'Kerberos KDC',
    '1.3.6.1.4.1.311.21.6':'Key recovery agent', '1.3.6.1.4.1.311.10.3.3':'Server gated crypto (legacy)', '2.16.840.1.113730.4.1':'Netscape server gated crypto (legacy)', '1.3.6.1.4.1.311.61.1.1':'Kernel mode code signing',
    '1.3.6.1.4.1.311.10.3.13':'Lifetime signing', '1.3.6.1.4.1.11129.2.4.4':'Certificate Transparency precertificate signing'};
  const KU = ['Digital signature', 'Non-repudiation', 'Key encipherment', 'Data encipherment', 'Key agreement', 'Certificate signing', 'CRL signing', 'Encipher only', 'Decipher only'];
  const POLICY = {'2.23.140.1.2.1':['Domain validated (DV)', 'DV'], '2.23.140.1.2.2':['Organisation validated (OV)', 'OV'], '2.23.140.1.2.3':['Individual validated (IV)', 'IV'], '2.23.140.1.1':['Extended validation (EV)', 'EV'],
    '2.5.29.32.0':['Any policy', ''], '2.23.140.1.3':['EV code signing', 'EV'], '2.23.140.1.4.1':['Code signing', ''], '1.3.6.1.4.1.44947.1.1.1':["ISRG domain validated (Let's Encrypt)", 'DV'], '2.23.140.1.5.1.1':['S/MIME mailbox validated', '']};
  const EXT = {'2.5.29.17':'Subject alternative names', '2.5.29.18':'Issuer alternative names', '2.5.29.19':'Basic constraints', '2.5.29.15':'Key usage', '2.5.29.37':'Extended key usage', '2.5.29.14':'Subject key identifier',
    '2.5.29.35':'Authority key identifier', '1.3.6.1.5.5.7.1.1':'Authority information access', '2.5.29.31':'CRL distribution points', '2.5.29.32':'Certificate policies', '1.3.6.1.4.1.11129.2.4.2':'Certificate Transparency timestamps (SCTs)',
    '1.3.6.1.4.1.11129.2.4.3':'Precertificate poison', '1.3.6.1.5.5.7.1.24':'TLS feature', '2.5.29.30':'Name constraints', '2.5.29.36':'Policy constraints', '2.5.29.54':'Inhibit any policy', '1.3.6.1.5.5.7.1.3':'Qualified certificate statements',
    '1.3.6.1.4.1.311.20.2':'Certificate template name (Microsoft)', '1.3.6.1.4.1.311.21.7':'Certificate template (Microsoft)', '1.3.6.1.4.1.311.21.10':'Application policies (Microsoft)', '1.3.6.1.4.1.311.21.1':'CA version (Microsoft)',
    '1.3.6.1.4.1.311.25.2':'Security identifier, SID (Microsoft)', '2.16.840.1.113730.1.13':'Netscape comment', '2.16.840.1.113730.1.1':'Netscape certificate type', '1.3.6.1.5.5.7.1.12':'Logotype', '2.5.29.9':'Subject directory attributes', '1.3.6.1.5.5.7.48.1.5':'OCSP no check'};
  function genName(g){ const t = g.tag;
    if(t === 2) return {t:'DNS', v:str(g)}; if(t === 1) return {t:'Email', v:str(g)}; if(t === 6) return {t:'URI', v:str(g)};
    if(t === 7){ const b = bytes(g); return {t:'IP', v:b.length === 4 ? [...b].join('.') : b.length === 16 ? hex(b).match(/.{4}/g).join(':').replace(/(^|:)0{1,3}/g, '$1') : hex(b)}; }
    if(t === 4) return {t:'Directory name', v:name(kid(g, 0)).text};
    if(t === 0){ const o = oid(kid(g, 0)), val = kid(kid(g, 1), 0); let v = ''; try{ v = val ? str(val) : ''; }catch(e){}
      if(o === '1.3.6.1.4.1.311.20.2.3') return {t:'UPN', v}; if(o === '1.3.6.1.5.2.2') return {t:'Kerberos principal', v:'(KRB5PrincipalName)'}; if(o === '1.3.6.1.4.1.311.25.1') return {t:'GUID', v:hex(bytes(val || g))}; return {t:'Other name ' + o, v}; }
    if(t === 8) return {t:'Registered ID', v:oid(g)};
    return {t:'Name type ' + t, v:hex(bytes(g)).slice(0, 40)}; }
  const genNames = n => (n.kids || []).map(genName);
  function sctList(b){ const r = parse(b), d = bytes(r), out = []; let p = 2;
    while(p + 2 <= d.length){ const len = d[p] << 8 | d[p + 1]; const s = d.subarray(p + 2, p + 2 + len); p += 2 + len; if(s.length < 43) break;
      let ts = 0; for(let i = 33; i < 41; i++) ts = ts * 256 + s[i];
      out.push({version:s[0] + 1, logId:btoa(String.fromCharCode(...s.subarray(1, 33))), time:ts}); }
    return out; }
  function ext(e){
    const o = oid(kid(e, 0)), crit = U(kid(e, 1), 0, 1) ? bytes(kid(e, 1))[0] !== 0 : false, val = (e.kids || []).find(k => U(k, 0, 4)), E = {oid:o, name:EXT[o] || o, critical:crit, known:!!EXT[o]};
    try{ const b = bytes(val), r = () => parse(b);
      switch(o){
        case '2.5.29.17': case '2.5.29.18': E.names = genNames(r()); E.text = E.names.map(x => x.t + ': ' + x.v).join(', '); break;
        case '2.5.29.19': { const s = r(); E.ca = !!(kid(s, 0) && U(kid(s, 0), 0, 1) && bytes(kid(s, 0))[0]); const pl = (s.kids || []).find(k => U(k, 0, 2)); E.pathLen = pl ? int(pl).num : null;
          E.text = E.ca ? 'A certificate authority' + (E.pathLen != null ? ', path length ' + E.pathLen + (E.pathLen === 0 ? ' (can issue only end certificates)' : '') : '') : 'Not a CA'; E.note = E.ca ? 'It can issue other certificates' : 'It cannot issue other certificates'; break; }
        case '2.5.29.15': { const s = bitstr(r()); E.usages = KU.filter((_, i) => (s.data[i >> 3] || 0) & (0x80 >> (i & 7))); E.text = E.usages.join(', '); break; }
        case '2.5.29.37': E.ekus = (r().kids || []).map(k => { const x = oid(k); return {oid:x, name:EKU[x] || x}; }); E.text = E.ekus.map(x => x.name).join(', '); break;
        case '2.5.29.14': E.keyId = hex(bytes(r()), ':'); E.text = E.keyId; break;
        case '2.5.29.35': { const k = (r().kids || []).find(x => ctx(x, 0)); E.keyId = k ? hex(bytes(k), ':') : ''; E.text = E.keyId ? 'Key ID ' + E.keyId : '(issuer name and serial)'; break; }
        case '1.3.6.1.5.5.7.1.1': E.access = (r().kids || []).map(ad => { const m = oid(kid(ad, 0)), g = genName(kid(ad, 1)); return {how:m === '1.3.6.1.5.5.7.48.1' ? 'OCSP' : m === '1.3.6.1.5.5.7.48.2' ? 'CA issuer certificate' : m, url:g.v}; });
          E.text = E.access.map(a => a.how + ' ' + a.url).join(' · '); break;
        case '2.5.29.31': E.urls = []; for(const dp of r().kids || []){ const dpn = (dp.kids || []).find(k => ctx(k, 0)); const full = dpn && (dpn.kids || []).find(k => ctx(k, 0)); if(full) for(const g of full.kids || []) E.urls.push(genName(g).v); } E.text = E.urls.join(' · ') || '(none listed)'; break;
        case '2.5.29.32': E.policies = (r().kids || []).map(pi => { const x = oid(kid(pi, 0)); const cps = []; for(const q of (kid(pi, 1) && kid(pi, 1).kids) || []) if(oid(kid(q, 0)) === '1.3.6.1.5.5.7.2.1' && kid(q, 1)) cps.push(str(kid(q, 1))); return {oid:x, name:(POLICY[x] || [x])[0], level:(POLICY[x] || [])[1] || '', cps}; });
          E.text = E.policies.map(p => p.oid + (POLICY[p.oid] ? ' — ' + p.name : '')).join(' · '); break;
        case '1.3.6.1.4.1.11129.2.4.2': E.scts = sctList(b); E.text = E.scts.length + ' timestamp' + (E.scts.length === 1 ? '' : 's'); break;
        case '1.3.6.1.4.1.11129.2.4.3': E.text = 'This is a precertificate made for Certificate Transparency, not the certificate a server uses'; break;
        case '1.3.6.1.5.5.7.1.24': { const f = (r().kids || []).map(k => int(k).num); E.text = f.includes(5) ? 'OCSP must-staple: the server must send a fresh revocation status' : 'TLS features ' + f.join(', '); break; }
        case '2.5.29.30': { const s = r(), sub = t => { const x = (s.kids || []).find(k => ctx(k, t)); return x ? (x.kids || []).map(st => genName(kid(st, 0))).map(g => g.t + ' ' + g.v) : []; };
          E.permitted = sub(0); E.excluded = sub(1); E.text = (E.permitted.length ? 'Only: ' + E.permitted.join(', ') : '') + (E.excluded.length ? (E.permitted.length ? ' · ' : '') + 'Never: ' + E.excluded.join(', ') : ''); break; }
        case '1.3.6.1.4.1.311.20.2': E.template = str(r()); E.text = E.template; break;
        case '1.3.6.1.4.1.311.21.7': { const s = r(); E.template = oid(kid(s, 0)); E.text = 'Template ' + E.template + (kid(s, 1) ? ' v' + int(kid(s, 1)).num + (kid(s, 2) ? '.' + int(kid(s, 2)).num : '') : ''); break; }
        case '1.3.6.1.4.1.311.25.2': { const s = r(), on = kid(s, 0), v = on && kid(kid(on, 1), 0); E.sid = v ? str(v) : ''; E.text = E.sid; break; }
        case '2.16.840.1.113730.1.13': E.text = str(r()); break;
        default: E.text = hex(b.subarray(0, 48), ' ') + (b.length > 48 ? ' …' : '');
      }
    }catch(err){ E.text = '(could not read this extension)'; E.bad = true; }
    return E;
  }

  /* ---------- certificate, request, bundle ---------- */
  function cert(der){
    const r = parse(der), tbs = kid(r, 0); if(!tbs || !tbs.kids) throw new Error('not a certificate');
    let i = 0, version = 1; if(ctx(kid(tbs, 0), 0)){ version = int(kid(kid(tbs, 0), 0)).num + 1; i = 1; }
    const serial = int(kid(tbs, i)), sigIn = algId(kid(tbs, i + 1)), issuer = name(kid(tbs, i + 2)), val = kid(tbs, i + 3), subject = name(kid(tbs, i + 4)), key = spki(kid(tbs, i + 5));
    const extn = (tbs.kids.find(k => ctx(k, 3)) || null), exts = extn ? (kid(extn, 0).kids || []).map(ext) : [];
    const C = {kind:'cert', der, version, serial:serial.hex.replace(/(..)(?=.)/g, '$1:'), serialHex:serial.hex, serialBits:serial.bits, serialNeg:serial.neg, sigAlg:algId(kid(r, 1)), sigInner:sigIn, issuer, subject, key,
      notBefore:time(kid(val, 0)), notAfter:time(kid(val, 1)), exts, tbs:whole(tbs), sig:bitstr(kid(r, 2)).data};
    return enrich(C);
  }
  function csr(der){
    const r = parse(der), info = kid(r, 0); if(!info || !info.kids) throw new Error('not a request');
    const version = int(kid(info, 0)).num + 1, subject = name(kid(info, 1)), key = spki(kid(info, 2)), attrs = [], exts = [];
    const at = info.kids.find(k => ctx(k, 0));
    for(const a of (at && at.kids) || []){ const o = oid(kid(a, 0)), set = kid(a, 1);
      if(o === '1.2.840.113549.1.9.14' || o === '1.3.6.1.4.1.311.2.1.14') for(const e of (kid(set, 0) && kid(set, 0).kids) || []) exts.push(ext(e));
      else attrs.push({oid:o, name:o === '1.2.840.113549.1.9.7' ? 'Challenge password' : o === '1.3.6.1.4.1.311.13.2.3' ? 'OS version (Microsoft)' : o === '1.3.6.1.4.1.311.21.20' ? 'Client info (Microsoft)' : o === '1.3.6.1.4.1.311.13.2.2' ? 'Enrollment CSP (Microsoft)' : o,
        value:(() => { try{ const v = kid(set, 0); return v && !v.cons ? str(v) : v ? '(structured)' : ''; }catch(e){ return ''; } })()}); }
    return enrich({kind:'csr', der, version, subject, key, exts, attrs, sigAlg:algId(kid(r, 1)), tbs:whole(info), sig:bitstr(kid(r, 2)).data});
  }
  const p7 = der => cms(der).certs;
  /* ---------- CMS / PKCS#7 signed data: certificates, signers, Authenticode content, timestamps ---------- */
  function cms(der, depth = 0){
    const r = parse(der); if(oid(kid(r, 0)) !== '1.2.840.113549.1.7.2') throw new Error('not a PKCS#7 bundle');
    const sd = kid(kid(r, 1), 0), K = (sd && sd.kids) || [], cn = K.find(k => ctx(k, 0));
    const certs = ((cn && cn.kids) || []).filter(c => U(c, 0, 16)).map(c => { try{ return cert(whole(c)); }catch(e){ return null; } }).filter(Boolean);
    const eci = K.find(k => U(k, 0, 16) && U(kid(k, 0), 0, 6)), ctype = eci ? oid(kid(eci, 0)) : '', econ = eci && ctx(kid(eci, 1), 0) ? kid(kid(eci, 1), 0) : null;
    const out = {certs, signers:[], ctype};
    try{
      if(ctype === '1.3.6.1.4.1.311.2.1.4' && econ){ const di = kid(econ, 1), a = oid(kid(kid(di, 0), 0)); out.spc = {alg:HASH[a] || a, digest:hex(bytes(kid(di, 1))), content:bytes(econ)}; }   // SpcIndirectDataContent: the program's hash
      if(ctype === '1.2.840.113549.1.9.16.1.4' && econ){ const t = parse(bytes(econ)), g = (t.kids || []).find(k => U(k, 0, 24)); out.tst = {time:g ? time(g) : NaN}; }   // RFC 3161 TSTInfo
    }catch(e){}
    const sis = K[K.length - 1]; if(U(sis, 0, 17)) for(const si of sis.kids || []) try{ out.signers.push(signer(si, certs, depth)); }catch(e){}
    return out;
  }
  const spcStr = (c, link) => { if(!c) return ''; if(c.cons) return spcStr(kid(c, 0)); const b = bytes(c);
    if(c.tag === 0 && !link || c.tag === 30){ let s = ''; for(let i = 0; i + 1 < b.length; i += 2) s += String.fromCharCode(b[i] << 8 | b[i + 1]); return s; }
    return [...b].map(x => String.fromCharCode(x)).join(''); };
  function signer(si, certs, depth){
    const k = si.kids, sid = k[1], S = {counter:[], nested:[]}; let i = 3;
    if(U(sid, 0, 16)){ S.issuer = name(kid(sid, 0)); S.serial = int(kid(sid, 1)).hex; S.cert = certs.find(c => c.issuer.raw === S.issuer.raw && c.serialHex === S.serial); }
    else if(ctx(sid, 0)){ const ki = hex(bytes(sid), ':'); S.cert = certs.find(c => c.ski === ki); }
    const ha = oid(kid(k[2], 0)); S.hash = HASH[ha] || ha;
    if(ctx(k[i], 0)){ S.signedAttrs = k[i]; i++; }
    S.sigOid = oid(kid(k[i], 0)); S.sig = bytes(k[i + 1]); const ua = ctx(k[i + 2], 1) ? k[i + 2] : null;
    for(const a of (S.signedAttrs && S.signedAttrs.kids) || []){ const o = oid(kid(a, 0)), v = kid(kid(a, 1), 0); try{
      if(o === '1.2.840.113549.1.9.5') S.time = time(v);
      else if(o === '1.2.840.113549.1.9.4') S.md = hex(bytes(v));
      else if(o === '1.3.6.1.4.1.311.2.1.12') for(const x of v.kids || []){ if(ctx(x, 0)) S.program = spcStr(kid(x, 0)); if(ctx(x, 1)) S.url = spcStr(kid(x, 0), true); }
    }catch(e){} }
    for(const a of (ua && ua.kids) || []){ const o = oid(kid(a, 0));
      for(const v of (kid(a, 1) && kid(a, 1).kids) || []) try{
        if(o === '1.2.840.113549.1.9.6'){ const c = signer(v, certs, depth + 1); S.counter.push({kind:'Countersignature', time:c.time, cert:c.cert, certs:[]}); }
        else if(o === '1.3.6.1.4.1.311.3.3.1' || o === '1.2.840.113549.1.9.16.2.14'){ const t = cms(whole(v), depth + 1); S.counter.push({kind:'RFC 3161 timestamp', time:t.tst ? t.tst.time : NaN, cert:t.signers[0] && t.signers[0].cert, certs:t.certs}); }
        else if(o === '1.3.6.1.4.1.311.2.4.1' && depth < 3) S.nested.push(cms(whole(v), depth + 1));
      }catch(e){} }
    return S;
  }
  /* does the signer's key verify its signed attributes? true / false / null */
  function verifySigner(S){
    if(!S.cert || !S.signedAttrs) return Promise.resolve(null);
    const b = new Uint8Array(whole(S.signedAttrs)); b[0] = 0x31;   // signed over as a SET, stored as [0]
    const A = SIG[S.sigOid], fam = A ? A[1] : S.sigOid === '1.2.840.113549.1.1.1' ? 'RSA' : S.sigOid === '1.2.840.10045.2.1' ? 'EC' : '';
    return verify({sigAlg:{fam, hash:(A && A[2]) || S.hash, salt:32}, sig:S.sig, tbs:b}, S.cert);
  }

  /* ---------- Windows programs (PE): the Authenticode signature ---------- */
  const MACH = {0x14c:'x86 (32-bit)', 0x8664:'x64', 0xaa64:'ARM64', 0x1c0:'ARM', 0x1c4:'ARM Thumb-2', 0x200:'Itanium'};
  function pe(u){
    if(u.length < 0x40 || u[0] !== 0x4d || u[1] !== 0x5a) return null;
    const dv = new DataView(u.buffer, u.byteOffset, u.byteLength), lf = dv.getUint32(0x3c, true);
    if(lf + 24 > u.length || dv.getUint32(lf, true) !== 0x4550) return {err:'Starts like a Windows program (MZ) but has no PE header', sigs:[], size:u.length};
    const machine = dv.getUint16(lf + 4, true), optSize = dv.getUint16(lf + 20, true), ch = dv.getUint16(lf + 22, true), opt = lf + 24, plus = dv.getUint16(opt, true) === 0x20b;
    const P = {machine:MACH[machine] || '0x' + machine.toString(16), plus, compiled:dv.getUint32(lf + 8, true) * 1000, dll:!!(ch & 0x2000), size:u.length, csOff:opt + 64, sdOff:opt + (plus ? 112 : 96) + 32, sigs:[], subsystem:opt + 70 <= u.length ? dv.getUint16(opt + 68, true) : 0};
    if(dv.getUint32(opt + (plus ? 108 : 92), true) < 5 || P.sdOff + 8 > Math.min(opt + optSize, u.length)) return P;
    const off = dv.getUint32(P.sdOff, true), size = dv.getUint32(P.sdOff + 4, true);
    if(!off || !size) return P;
    if(off + size > u.length){ P.err = 'The signature table runs past the end of the file — the file is cut short'; return P; }
    Object.assign(P, {certOff:off, certSize:size, after:u.length - off - size});
    for(let p = off; p + 8 <= off + size;){ const len = dv.getUint32(p, true), type = dv.getUint16(p + 6, true); if(len < 8 || p + len > off + size) break;
      if(type === 2) try{ const sd = cms(u.slice(p + 8, p + len)); P.sigs.push(sd); for(const s of sd.signers) for(const n of s.nested) P.sigs.push(n); }catch(e){ P.err = 'Could not read the signature (' + e.message + ')'; }
      p += (len + 7) & ~7; }
    return P;
  }
  /* the Authenticode hash: the whole file except the checksum, the pointer to the signature, and the signature itself */
  async function peCheck(P, u){
    const cut = (a, b) => u.subarray(a, Math.max(a, b)), end = P.certOff || u.length, parts = [cut(0, P.csOff), cut(P.csOff + 4, P.sdOff), cut(P.sdOff + 8, end)];
    const all = new Uint8Array(parts.reduce((s, x) => s + x.length, 0)); let o = 0; for(const x of parts){ all.set(x, o); o += x.length; }
    const H = {}; P.sha256 = await digest('SHA-256', u);
    for(const sd of P.sigs){
      if(sd.spc && /^SHA/.test(sd.spc.alg)){ H[sd.spc.alg] = H[sd.spc.alg] || await digest(sd.spc.alg, all); sd.fileHash = H[sd.spc.alg]; sd.fileOk = sd.fileHash === sd.spc.digest; }
      for(const s of sd.signers){ if(s.md && sd.spc && /^SHA/.test(s.hash)) s.mdOk = await digest(s.hash, sd.spc.content) === s.md; s.sigOk = await verifySigner(s); if(s.cert) await prints(s.cert); }
    }
    P.checked = true; return P;
  }

  /* ---------- does a certificate cover this host? ---------- */
  function covers(C, h){
    h = String(h || '').trim().toLowerCase().replace(/^[a-z]+:\/\//, '').replace(/\/.*$/, '').replace(/\.$/, '');
    if(/^\[.*\](:\d+)?$/.test(h)) h = h.replace(/^\[|\](:\d+)?$/g, ''); else if(/^[^:]+:\d+$/.test(h)) h = h.replace(/:\d+$/, '');
    if(!h) return null;
    if(/[^\x00-\x7f]/.test(h)) try{ h = new URL('http://' + h).hostname; }catch(e){}   // internationalised names → the xn-- form certificates carry
    const ip = /^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.includes(':');
    if(ip){ const hit = C.san.find(s => s.t === 'IP' && s.v.toLowerCase() === h); return hit ? {ok:true, by:hit.v, h} : {ok:false, h, why:'No IP address entry matches it'}; }
    const names = C.san.filter(s => s.t === 'DNS').map(s => s.v.toLowerCase());
    const m = n => n === h || (n.startsWith('*.') && h.endsWith(n.slice(1)) && h.length > n.length - 1 && !h.slice(0, h.length - n.length + 1).includes('.'));
    const hit = names.find(m); if(hit) return {ok:true, by:hit, h};
    if(!names.length && C.cn && m(C.cn.toLowerCase())) return {ok:'cn', by:C.cn, h};
    const deep = names.find(n => n.startsWith('*.') && h.endsWith(n.slice(1)));
    return {ok:false, h, why:deep ? '“' + deep + '” covers one level only, not ' + h : names.length ? 'Not among its ' + names.length + ' name' + (names.length === 1 ? '' : 's') : 'It lists no names'};
  }
  function enrich(C){
    const X = o => C.exts.find(e => e.oid === o);
    C.san = (X('2.5.29.17') || {}).names || [];
    C.bc = X('2.5.29.19'); C.ku = (X('2.5.29.15') || {}).usages || null; C.eku = (X('2.5.29.37') || {}).ekus || null; C.ski = (X('2.5.29.14') || {}).keyId || ''; C.aki = (X('2.5.29.35') || {}).keyId || '';
    C.aia = (X('1.3.6.1.5.5.7.1.1') || {}).access || []; C.crl = (X('2.5.29.31') || {}).urls || []; C.policies = (X('2.5.29.32') || {}).policies || []; C.scts = (X('1.3.6.1.4.1.11129.2.4.2') || {}).scts || [];
    C.template = (X('1.3.6.1.4.1.311.20.2') || X('1.3.6.1.4.1.311.21.7') || {}).template || '';
    C.cn = (C.subject.map.CN || [])[0] || '';
    C.title = C.cn || (C.san.find(s => s.t === 'DNS') || {}).v || (C.subject.map.O || [])[0] || C.subject.text || '(no name)';
    C.isCA = !!(C.bc && C.bc.ca);
    if(C.kind === 'cert'){ C.selfIssued = C.subject.raw === C.issuer.raw; C.level = (C.policies.map(p => p.level).find(Boolean)) || (C.isCA || C.selfIssued || (C.eku && !C.eku.some(e => e.oid === '1.3.6.1.5.5.7.3.1')) ? '' : C.subject.map.O ? 'OV/EV' : 'DV');   /* only TLS certificates have DV/OV/EV levels */   /* self-signed: nobody validated anything */ }
    return C;
  }

  /* ---------- reading what was pasted or dropped ---------- */
  const b64 = s => { const t = atob(s.replace(/[^A-Za-z0-9+/=]/g, '')); const u = new Uint8Array(t.length); for(let i = 0; i < t.length; i++) u[i] = t.charCodeAt(i); return u; };
  const PEM_RE = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/g;
  function read(input){
    const out = {certs:[], csrs:[], keys:[], errors:[]};
    const add = (der, hint) => {
      try{ const r = parse(der); if(r.end !== der.length && der.length - r.end > 2) out.errors.push('Extra bytes after the data were ignored');
        const first = kid(r, 0);
        if(U(first, 0, 6)){ out.certs.push(...p7(der)); return; }                                    // PKCS#7 ContentInfo
        if(first && first.kids && U(kid(first, 0), 0, 2) && !ctx(kid(first, 0), 0) && kid(first, 1) && kid(first, 1).kids && U(kid(kid(first, 1), 0), 0, 17)){ out.csrs.push(csr(der)); return; }   // version INTEGER then a Name
        if(hint === 'csr'){ out.csrs.push(csr(der)); return; }
        out.certs.push(cert(der));
      }catch(e){ out.errors.push((hint ? hint + ': ' : '') + 'could not read it (' + e.message + ')'); } };
    if(input instanceof Uint8Array && input[0] === 0x4d && input[1] === 0x5a){
      const P = pe(input); out.pe = P; const seen = new Set();
      const take = c => { const k = hex(c.der.subarray(0, 64)) + c.der.length + c.serialHex; if(c && !seen.has(k)){ seen.add(k); out.certs.push(c); } };
      for(const sd of P.sigs){ sd.certs.forEach(take); for(const s of sd.signers) for(const t of s.counter) t.certs.forEach(take); }
      return out;
    }
    if(input instanceof Uint8Array){
      const head = new TextDecoder().decode(input.subarray(0, Math.min(input.length, 2e6)));
      if(input[0] === 0x30 && !/-----BEGIN/.test(head.slice(0, 100))) { add(input); return out; }
      input = new TextDecoder().decode(input);
    }
    const text = String(input || '');
    let m, any = false; PEM_RE.lastIndex = 0;
    while((m = PEM_RE.exec(text))){ any = true; const kind = m[1], body = m[2].replace(/^[A-Za-z-]+:.*$/gm, '');
      if(/PRIVATE KEY/.test(kind)){ out.keys.push(kind); continue; }      // never decoded or kept
      try{ add(b64(body), /REQUEST/.test(kind) ? 'csr' : /PKCS7/.test(kind) ? 'p7' : ''); }catch(e){ out.errors.push(kind + ': not valid base64'); } }
    if(!any){ const t = text.trim();
      if(/^[0-9a-f\s:]+$/i.test(t) && t.replace(/[\s:]/g, '').length >= 40){ const h = t.replace(/[\s:]/g, ''); add(new Uint8Array(h.match(/../g).map(x => parseInt(x, 16)))); }
      else if(/^[A-Za-z0-9+/=\s]+$/.test(t) && t.length >= 60){ try{ add(b64(t)); }catch(e){ out.errors.push('Not valid base64'); } }
      else if(t) out.errors.push('No certificate found. Paste a PEM block (-----BEGIN CERTIFICATE-----), base64, hex, or drop a .crt .cer .der .pem .csr .p7b file.'); }
    return out;
  }
  const bin = u => { let s = ''; for(let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000)); return s; };   // no argument-count limit on big inputs
  const toPem = (der, label = 'CERTIFICATE') => `-----BEGIN ${label}-----\n` + btoa(bin(der)).replace(/.{64}/g, '$&\n').replace(/\n$/, '') + `\n-----END ${label}-----\n`;

  /* ---------- fingerprints and signatures ---------- */
  async function digest(alg, b){ return hex(new Uint8Array(await crypto.subtle.digest(alg, b))); }
  async function prints(C){ if(C.fp) return C.fp;
    const [s256, s1, k256] = await Promise.all([digest('SHA-256', C.der), digest('SHA-1', C.der), crypto.subtle.digest('SHA-256', C.key.der)]);
    C.fp = {sha256:s256, sha1:s1, pin:btoa(String.fromCharCode(...new Uint8Array(k256))), spki256:hex(new Uint8Array(k256))}; return C.fp; }
  function ecRaw(sig, size){ const r = parse(sig), a = bytes(kid(r, 0)), b = bytes(kid(r, 1)), n = Math.ceil(size / 8), out = new Uint8Array(n * 2);
    const put = (x, o) => { x = x.subarray(Math.max(0, x.length - n)); out.set(x, o + n - x.length); }; put(a, 0); put(b, n); return out; }
  /* does `issuer`'s key verify `child`'s signature? → true / false / null (cannot check here) */
  async function verify(child, issuer){
    const A = child.sigAlg, K = issuer.key;
    try{
      if(A.fam === 'RSA' && A.hash && /^RSA/.test(K.type)){ const k = await crypto.subtle.importKey('spki', K.der, {name:'RSASSA-PKCS1-v1_5', hash:A.hash}, false, ['verify']); return await crypto.subtle.verify('RSASSA-PKCS1-v1_5', k, child.sig, child.tbs); }
      if(A.fam === 'PSS' && /^RSA/.test(K.type)){ let der = K.der; if(K.type === 'RSA-PSS'){ der = rsaSpki(K); }
        const k = await crypto.subtle.importKey('spki', der, {name:'RSA-PSS', hash:A.hash}, false, ['verify']); return await crypto.subtle.verify({name:'RSA-PSS', saltLength:A.salt}, k, child.sig, child.tbs); }
      if(A.fam === 'EC' && A.hash && K.type === 'ECDSA' && /^P-(256|384|521)$/.test(K.curve)){ const k = await crypto.subtle.importKey('spki', K.der, {name:'ECDSA', namedCurve:K.curve}, false, ['verify']);
        return await crypto.subtle.verify({name:'ECDSA', hash:A.hash}, k, ecRaw(child.sig, K.bits), child.tbs); }
      if(A.fam === 'Ed25519' && K.type === 'Ed25519'){ const k = await crypto.subtle.importKey('spki', K.der, {name:'Ed25519'}, false, ['verify']); return await crypto.subtle.verify('Ed25519', k, child.sig, child.tbs); }
    }catch(e){ return null; }
    return null;
  }
  /* WebCrypto only imports RSA-PSS keys labelled rsaEncryption: rebuild the SPKI with that label */
  function rsaSpki(K){ const r = parse(K.der), bs = whole(kid(r, 1)), alg = new Uint8Array([0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]);
    const len = alg.length + bs.length, hdr = len < 128 ? [0x30, len] : len < 256 ? [0x30, 0x81, len] : [0x30, 0x82, len >> 8, len & 255], out = new Uint8Array(hdr.length + len); out.set(hdr); out.set(alg, hdr.length); out.set(bs, hdr.length + alg.length); return out; }

  /* ---------- the chain: order what was pasted and check each link ---------- */
  async function chain(certs){
    const list = certs.slice(), issuerOf = c => list.find(p => p !== c && p.subject.raw === c.issuer.raw && (!c.aki || !p.ski || c.aki === p.ski));
    const isIssuer = c => list.some(o => o !== c && issuerOf(o) === c);
    let leaf = list.find(c => !isIssuer(c) && !c.selfIssued) || list.find(c => !isIssuer(c)) || list[0];
    const order = [], links = [], seen = new Set();
    for(let c = leaf; c && !seen.has(c); c = issuerOf(c)){ seen.add(c); order.push(c); }
    for(let i = 0; i < order.length; i++){ const c = order[i], p = order[i + 1];
      if(p) links.push({ok:await verify(c, p), to:p});
      else if(c.selfIssued) links.push({ok:await verify(c, c), self:true});
      else links.push({missing:true, issuer:c.issuer}); }
    return {order, links, extra:list.filter(c => !seen.has(c))};
  }

  /* ---------- findings ---------- */
  const BRANDS = {microsoft:['microsoft.com', 'microsoftonline.com', 'office.com', 'office365.com', 'live.com', 'outlook.com', 'azure.com', 'windows.net', 'msft.net', 'sharepoint.com', 'microsoft365.com'], microsoftonline:['microsoftonline.com'], office365:['office365.com', 'office.com'],
    outlook:['outlook.com', 'live.com'], sharepoint:['sharepoint.com'], onedrive:['onedrive.com', 'live.com'], paypal:['paypal.com', 'paypal.me'], apple:['apple.com', 'icloud.com'], icloud:['icloud.com'], google:['google.com', 'googleapis.com', 'gstatic.com', 'youtube.com', 'gmail.com'],
    gmail:['gmail.com'], amazon:['amazon.com', 'amazonaws.com', 'amazon.co.uk', 'amazon.de', 'amazon.in'], okta:['okta.com', 'oktapreview.com'], docusign:['docusign.com', 'docusign.net'], dropbox:['dropbox.com'], netflix:['netflix.com'],
    facebook:['facebook.com', 'fb.com'], instagram:['instagram.com'], binance:['binance.com'], coinbase:['coinbase.com'], metamask:['metamask.io'], wellsfargo:['wellsfargo.com'], chase:['chase.com'], adobe:['adobe.com'], linkedin:['linkedin.com'], whatsapp:['whatsapp.com'], github:['github.com']};
  const MULTI = /\.(co|com|net|org|gov|ac|edu)\.[a-z]{2}$/;
  const regDom = h => { h = h.toLowerCase().replace(/^\*\./, '').replace(/\.$/, ''); if(/^[\d.]+$|:/.test(h)) return h; const p = h.split('.'); return p.slice(MULTI.test(h) ? -3 : -2).join('.'); };
  function findings(C, now = Date.now()){
    const F = [], f = (s, t, d) => F.push({s, t, d}), days = (C.notAfter - C.notBefore) / 864e5, left = (C.notAfter - now) / 864e5, age = (now - C.notBefore) / 864e5;
    const all = [C.subject.text, (C.issuer || {}).text || ''].join(' ').toLowerCase(), dns = C.san.filter(s => s.t === 'DNS').map(s => s.v.toLowerCase());
    if(C.kind === 'cert'){
      if(/major cobalt strike|cobaltstrike|advancedpentesting/.test(all)) f('bad', 'Cobalt Strike default certificate', 'This subject is the out-of-the-box Cobalt Strike team-server certificate — a strong sign of a C2 server');
      if(/internet widgits pty ltd|some-state|default company ltd|acme co\b|o=company, |ou=unit,/.test(all)) f('warn', 'Default placeholder values', 'Fields such as “Internet Widgits Pty Ltd” come from openssl or tooling defaults: made by hand, not by a CA');
      if(C.selfIssued && !C.isCA) f('warn', 'Self-signed', 'No certificate authority vouches for it. Browsers warn; common on malware infrastructure, test boxes and appliances');
      else if(C.selfIssued) f('info', 'Self-signed CA certificate', 'A root (or a home-made CA). Trust only comes from it being installed or shipped as trusted');
      if(now > C.notAfter) f('warn', 'Expired', 'Expired ' + Math.round(-left) + ' days ago (' + new Date(C.notAfter).toISOString().slice(0, 10) + ')');
      if(now < C.notBefore) f('warn', 'Not valid yet', 'Starts ' + new Date(C.notBefore).toISOString().slice(0, 10) + ' — a wrong clock or a backdated plan');
      // CA/Browser Forum limits for public TLS certificates: 398 days from Sep 2020; SC-081: 200 days from 15 Mar 2026, 100 from 15 Mar 2027, 47 from 15 Mar 2029
      const lim = C.notBefore >= Date.UTC(2029, 2, 15) ? [47, '15 March 2029'] : C.notBefore >= Date.UTC(2027, 2, 15) ? [100, '15 March 2027'] : C.notBefore >= Date.UTC(2026, 2, 15) ? [200, '15 March 2026'] : C.notBefore >= Date.UTC(2020, 8, 1) ? [398, '1 September 2020'] : null;
      if(lim && !C.isCA && !C.selfIssued && days > lim[0] + 1 && (C.eku || []).some(e => e.oid === '1.3.6.1.5.5.7.3.1')) f('warn', 'Longer than public CAs may issue', Math.round(days) + ' days; public TLS certificates issued since ' + lim[1] + ' may last at most ' + lim[0] + '. A private CA, or a CA breaking the rules');
      if(!C.isCA && days > 3650) f('warn', 'Very long validity', Math.round(days / 365) + ' years — typical of home-made certificates');
      if(!C.isCA && age >= 0 && age < 14) f('info', 'Issued ' + Math.max(0, Math.floor(age)) + ' days ago', 'New certificates on new domains are common in phishing — context, not proof');
      if(C.version < 3) f('warn', 'Version ' + C.version + ' certificate', 'No extensions at all. Public CAs issue v3; v1 usually means a quick home-made certificate');
      if(C.serialBits && C.serialBits < 64 && !C.isCA) f(C.selfIssued ? 'info' : 'warn', 'Short serial number', C.serialBits + ' bits. Public CAs must use at least 64 random bits; tiny serials point to hand-made certificates');
      if(C.serialNeg) f('warn', 'Negative serial number', 'Not allowed by the standard; some old or buggy tools do it');
      if(!C.isCA && !C.selfIssued && !C.san.length && (C.eku || [{oid:'1.3.6.1.5.5.7.3.1'}]).some(e => e.oid === '1.3.6.1.5.5.7.3.1')) f('warn', 'No subject alternative names', 'Browsers ignore the Common Name: this will not be trusted for a website');
      if(C.isCA && C.san.some(s => s.t === 'DNS')) f('warn', 'A CA certificate with website names', 'Odd mix: CA certificates normally carry no DNS names');
      if(!C.isCA && C.ku && C.ku.includes('Certificate signing')) f('warn', 'Can sign certificates but is not a CA', 'Key usage allows certificate signing without the CA flag');
      if(C.exts.some(e => e.oid === '1.3.6.1.4.1.11129.2.4.3')) f('info', 'Precertificate', 'This is the copy logged to Certificate Transparency, not what servers present');
      if(C.scts.length) f('info', 'Logged in Certificate Transparency', C.scts.length + ' log' + (C.scts.length === 1 ? '' : 's') + ' — so it can be found on crt.sh');
    }
    if(C.key.type === 'RSA' && C.key.bits && C.key.bits < 2048) f('bad', 'Weak key', 'RSA ' + C.key.bits + ' bits — below the 2048-bit minimum; factorable by well-funded attackers');
    if(C.key.type === 'RSA' && C.key.e !== 65537 && C.key.e !== undefined) f('info', 'Unusual RSA exponent', 'e = ' + C.key.e + ' (65537 is standard)');
    if(C.key.type === 'DSA') f('warn', 'DSA key', 'No longer accepted by browsers');
    if(/MD5|MD2/.test(C.sigAlg.name)) f('bad', 'Broken signature hash', C.sigAlg.name + ' — collisions are practical; a forged certificate is possible');
    else if(/SHA-1/.test(C.sigAlg.name) && !(C.kind === 'cert' && C.selfIssued && C.isCA)) f('warn', 'SHA-1 signature', 'Deprecated: browsers stopped trusting SHA-1 certificates in 2017');
    // lookalikes and odd name mixes
    const looks = []; for(const h of dns){ const rd = regDom(h); for(const [tok, own] of Object.entries(BRANDS)) if(h.includes(tok) && !own.includes(rd)) looks.push([h, tok]); }
    const lh = [...new Map(looks.map(l => [l[0], l])).values()];   // one entry per host
    if(lh.length) f('bad', 'Lookalike name', `“${lh[0][0]}” uses “${lh[0][1]}” but is not one of that company's domains` + (lh.length > 1 ? ` (+${lh.length - 1} more)` : ''));
    if(C.kind === 'cert' && C.selfIssued && !C.isCA && Object.keys(BRANDS).some(t => (C.subject.map.O || []).join(' ').toLowerCase().includes(t))) f('bad', 'Claims a big brand but is self-signed', 'The organisation field names a well-known company, yet nobody vouches for it');
    const regs = [...new Set(dns.map(regDom))], ips = C.san.filter(s => s.t === 'IP');
    if(regs.length > 1) f(regs.length > 4 ? 'info' : 'warn', regs.length + ' different domains on one certificate', regs.slice(0, 5).join(', ') + (regs.length > 5 ? '…' : '') + ' — shared hosting and CDNs do this; unrelated names on a fresh certificate are a lead');
    if(ips.length) f('info', 'IP address in the names', ips.map(i => i.v).join(', '));
    if(dns.some(h => h.startsWith('*.'))) f('info', 'Wildcard', dns.filter(h => h.startsWith('*.')).join(', '));
    // Windows / Active Directory Certificate Services
    const ek = (C.eku || []).map(e => e.oid), upn = C.san.find(s => s.t === 'UPN');
    if(upn && (ek.includes('1.3.6.1.5.5.7.3.2') || ek.includes('1.3.6.1.4.1.311.20.2.2') || ek.includes('1.3.6.1.5.2.3.4') || ek.includes('2.5.29.37.0') || !C.eku)) f(C.kind === 'csr' ? 'warn' : 'info', 'Can log on to Windows as ' + upn.v, 'Client authentication plus a UPN: Kerberos PKINIT accepts it as that user. In AD CS abuse (ESC1), attackers request certificates naming someone else');
    if(ek.includes('1.3.6.1.4.1.311.20.2.1')) f('warn', 'Enrollment agent', 'Can request certificates on behalf of other users (AD CS ESC3 if misused)');
    if(ek.includes('2.5.29.37.0') && !C.isCA) f('warn', 'Any purpose', 'Usable for anything, including client authentication and code signing');
    if(ek.includes('1.3.6.1.5.5.7.3.3')) f('info', 'Code signing certificate', 'Used to sign programs and scripts — check what was signed with it');
    if(C.template) f('info', 'Issued from template “' + C.template + '”', 'Active Directory Certificate Services. Compare the template against what this account should be able to enrol for');
    if(C.kind === 'csr'){
      if(!C.san.length) f('warn', 'No subject alternative names requested', 'Most CAs copy the CN, but browsers only trust names in the SAN extension');
      else if(C.cn && !C.san.some(s => s.v.toLowerCase() === C.cn.toLowerCase())) f('warn', 'Common name is not among the names', '“' + C.cn + '” is not in the SAN list');
      if(ek.includes('1.3.6.1.5.5.7.3.2') && ek.includes('1.3.6.1.5.5.7.3.1')) f('info', 'Asks for client authentication too', 'Public CAs are removing client auth from server certificates');
      const pw = (C.attrs || []).find(a => a.oid === '1.2.840.113549.1.9.7'); if(pw) f('warn', 'Contains a challenge password', 'Stored in the clear inside the request: “' + pw.value.slice(0, 3) + '…”');
    }
    const order = {bad:0, warn:1, info:2}; F.sort((a, b) => order[a.s] - order[b.s]); return F;
  }
  return {parse, read, cert, csr, cms, pe, peCheck, covers, toPem, prints, verify, chain, findings, regDom, hex, EKU, KU, BRANDS};
})();
