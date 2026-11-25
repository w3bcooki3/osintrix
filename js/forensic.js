/* ==========================================================================
   Forensics kit — the deeper checks behind the File inspector and Image tools.
   Pictures: how the JPEG was written (quantisation tables → quality and the
   kind of encoder, segments, colour profile), the thumbnail hidden in EXIF
   compared with the picture, what the file name says about where it came
   from, where the sun was, noise and copy-move views, levels and histogram.
   Files: Windows shortcuts (target, machine name, MAC address, volume serial),
   Windows programs (imphash, Rich header, PDB path, version info, exports,
   overlay, TLS), Linux programs (libraries, Go build ID, compiler), ZIP
   archives (the OS, user IDs and the time zone of whoever packed it), strings
   sorted by kind, and a hex viewer over the whole file.
   Everything runs on the bytes in this tab; nothing is uploaded.
   ========================================================================== */

/* ---------- JPEG: segments, quantisation, sampling, colour profile ---------- */
const FX_STD_Q = [[16,11,10,16,24,40,51,61,12,12,14,19,26,58,60,55,14,13,16,24,40,57,69,56,14,17,22,29,51,87,80,62,18,22,37,56,68,109,103,77,24,35,55,64,81,104,113,92,49,64,78,87,103,121,120,101,72,92,95,98,112,100,103,99],
  [17,18,24,47,99,99,99,99,18,21,26,66,99,99,99,99,24,26,56,99,99,99,99,99,47,66,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99]];
/* the zig-zag order DQT tables are stored in */
const FX_ZZ = [0,1,8,16,9,2,3,10,17,24,32,25,18,11,4,5,12,19,26,33,40,48,41,34,27,20,13,6,7,14,21,28,35,42,49,56,57,50,43,36,29,22,15,23,30,37,44,51,58,59,52,45,38,31,39,46,53,60,61,54,47,55,62,63];
const fxIjg = (std, q) => { const s = q < 50 ? 5000 / q : 200 - 2 * q; return std.map(v => Math.min(255, Math.max(1, Math.floor((v * s + 50) / 100)))); };
function fxJpeg(b){
  if(!(b[0] === 0xff && b[1] === 0xd8)) return null;
  const R = {segs:[], q:[], sof:null, progressive:false, icc:null, fbmd:false, adobe:false, photoshop:false, mpf:false, jfif:false, exif:false, xmp:false, comment:'', restart:false};
  let o = 2, icc = [];
  while(o + 4 <= b.length){
    if(b[o] !== 0xff){ o++; continue; } const m = b[o + 1]; if(m === 0xff){ o++; continue; } if(m === 0xd9) break;
    if(m === 0xda){ R.segs.push('SOS'); break; } if(m >= 0xd0 && m <= 0xd7 || m === 0x01){ o += 2; continue; }
    const len = u16be(b, o + 2), d = o + 4, e = o + 2 + len; if(len < 2 || e > b.length) break;
    const id = latin1(b, d, Math.min(e, d + 32));
    if(m >= 0xe0 && m <= 0xef){ const tag = 'APP' + (m - 0xe0); let what = '';
      if(m === 0xe0 && id.startsWith('JFIF')){ what = 'JFIF'; R.jfif = true; }
      else if(m === 0xe1 && id.startsWith('Exif')){ what = 'Exif'; R.exif = true; }
      else if(m === 0xe1 && id.startsWith('http://ns.adobe.com/xap')){ what = 'XMP'; R.xmp = true; }
      else if(m === 0xe2 && id.startsWith('ICC_PROFILE')){ what = 'ICC'; icc.push([b[d + 12], b.subarray(d + 14, e)]); }
      else if(m === 0xe2 && id.startsWith('MPF')){ what = 'MPF'; R.mpf = true; }
      else if(m === 0xed && id.startsWith('Photoshop 3.0')){ what = 'Photoshop'; R.photoshop = true; if(latin1(b, d, e).includes('FBMD')) R.fbmd = true; }
      else if(m === 0xee && id.startsWith('Adobe')){ what = 'Adobe'; R.adobe = true; }
      else if(m === 0xeb && id.startsWith('JP')){ what = 'JUMBF / C2PA'; R.c2pa = true; }
      else what = id.replace(/[^\x20-\x7e].*$/, '').slice(0, 12);
      R.segs.push(tag + (what ? ' ' + what : '')); }
    else if(m === 0xdb){ R.segs.push('DQT'); let p = d; while(p < e){ const pq = b[p] >> 4, tq = b[p] & 15, n = pq ? 128 : 64, t = new Array(64); for(let i = 0; i < 64; i++) t[FX_ZZ[i]] = pq ? u16be(b, p + 1 + i * 2) : b[p + 1 + i]; R.q[tq] = t; p += 1 + n; } }
    else if(m === 0xc0 || m === 0xc1 || m === 0xc2){ R.segs.push(m === 0xc2 ? 'SOF2 progressive' : 'SOF' + (m - 0xc0)); R.progressive = m === 0xc2; const nc = b[d + 5], C = [];
      for(let i = 0; i < nc; i++){ const s = b[d + 6 + i * 3 + 1]; C.push([s >> 4, s & 15]); } R.sof = {h:u16be(b, d + 1), w:u16be(b, d + 3), comps:nc, samp:C}; }
    else if(m === 0xc4) R.segs.push('DHT'); else if(m === 0xdd){ R.segs.push('DRI'); R.restart = true; }
    else if(m === 0xfe){ R.segs.push('COM'); R.comment = new TextDecoder().decode(b.subarray(d, Math.min(e, d + 300))).replace(/[\u0000-\u001f]+/g, ' ').trim(); }
    else R.segs.push('0x' + m.toString(16));
    o = e; if(R.segs.length > 80) break;
  }
  if(icc.length){ icc.sort((x, y) => x[0] - y[0]); const all = new Uint8Array(icc.reduce((s, x) => s + x[1].length, 0)); let at = 0; for(const [, p] of icc){ all.set(p, at); at += p.length; } R.icc = fxIcc(all); }
  /* the quality the tables were made with: IJG / libjpeg scales two standard tables; a perfect match means a library wrote the file */
  if(R.q[0]){ let best = [1e9, 0]; for(let q = 1; q <= 100; q++){ const L = fxIjg(FX_STD_Q[0], q), C = fxIjg(FX_STD_Q[1], q); let d = 0; for(let i = 0; i < 64; i++){ d += Math.abs(L[i] - R.q[0][i]); if(R.q[1]) d += Math.abs(C[i] - R.q[1][i]); } if(d < best[0]) best = [d, q]; }
    R.quality = best[1]; R.stdTables = best[0] === 0; R.approx = !R.stdTables; R.tableDiff = best[0]; }
  if(R.sof && R.sof.samp.length === 3){ const [y, cb] = R.sof.samp; R.subsampling = y[0] === cb[0] && y[1] === cb[1] ? '4:4:4' : y[0] === 2 * cb[0] && y[1] === 2 * cb[1] ? '4:2:0' : y[0] === 2 * cb[0] && y[1] === cb[1] ? '4:2:2' : y.join('x') + ' / ' + cb.join('x'); }
  else if(R.sof && R.sof.comps === 1) R.subsampling = 'greyscale';
  return R;
}
/* ICC profile: the description (Display P3 → Apple device, Google/Skia → Android or Chrome, sRGB → most others) and who made it */
function fxIcc(p){
  if(p.length < 132) return null; const r = {cmm:latin1(p, 4, 8).replace(/\0/g, '').trim(), device:latin1(p, 48, 52).replace(/\0/g, '').trim(), creator:latin1(p, 80, 84).replace(/\0/g, '').trim(), desc:'', cprt:''};
  const n = Math.min(u32be(p, 128), 100);
  for(let i = 0; i < n; i++){ const e = 132 + i * 12, sig = latin1(p, e, e + 4), off = u32be(p, e + 4), sz = u32be(p, e + 8); if(off + sz > p.length) continue;
    if(sig !== 'desc' && sig !== 'cprt') continue; const ty = latin1(p, off, off + 4); let v = '';
    if(ty === 'desc'){ const l = u32be(p, off + 8); v = latin1(p, off + 12, off + 12 + Math.min(l, 200)); }
    else if(ty === 'mluc'){ const cnt = u32be(p, off + 8); if(cnt){ const len = u32be(p, off + 20), so = u32be(p, off + 24); v = new TextDecoder('utf-16be').decode(p.subarray(off + so, off + so + Math.min(len, 400))); } }
    else if(ty === 'text') v = latin1(p, off + 8, off + Math.min(sz, 200));
    v = v.replace(/\0+/g, '').trim(); if(sig === 'desc') r.desc = v; else r.cprt = v; }
  return r;
}
/* the small picture EXIF keeps (IFD1). Editors that crop or retouch often leave the camera's thumbnail as it was. */
function fxExifThumb(b){
  if(!(b[0] === 0xff && b[1] === 0xd8)) return null; let o = 2;
  while(o + 4 < b.length){ if(b[o] !== 0xff) return null; const m = b[o + 1], l = u16be(b, o + 2);
    if(m === 0xe1 && latin1(b, o + 4, o + 10) === 'Exif\0\0'){ const t = o + 10, le = b[t] === 0x49, U16 = p => le ? u16le(b, p) : u16be(b, p), U32 = p => le ? u32le(b, p) : u32be(b, p);
      const i0 = t + U32(t + 4); if(i0 + 2 > b.length) return null; const n0 = U16(i0); if(n0 > 500) return null; const next = U32(i0 + 2 + n0 * 12); if(!next) return null;
      const i1 = t + next; if(i1 + 2 > b.length) return null; const n1 = U16(i1); if(n1 > 200) return null; let off = 0, len = 0;
      for(let i = 0; i < n1; i++){ const e = i1 + 2 + i * 12; const tag = U16(e); if(tag === 0x201) off = U32(e + 8); if(tag === 0x202) len = U32(e + 8); }
      if(!off || !len || t + off + len > b.length || len > 2e6) return null; const s = t + off; if(!(b[s] === 0xff && b[s + 1] === 0xd8)) return null; return b.slice(s, s + len); }
    if(m === 0xda) return null; o += 2 + l; }
  return null;
}
/* ---------- what a file name says about where a picture or video came from ---------- */
const FX_NAMES = [
  [/^IMG-(\d{4})(\d{2})(\d{2})-WA\d{4}/i, 'WhatsApp — a picture sent or received in WhatsApp (date it was saved on the phone)', 'WhatsApp'],
  [/^VID-(\d{4})(\d{2})(\d{2})-WA\d{4}/i, 'WhatsApp — a video sent or received in WhatsApp', 'WhatsApp'],
  [/^(?:photo|video|file)_(\d{4})-(\d{2})-(\d{2})_(\d{2})-(\d{2})-(\d{2})/i, 'Telegram Desktop — saved from a Telegram chat (date and time it was saved)', 'Telegram'],
  [/^signal-(\d{4})-(\d{2})-(\d{2})-(\d{2})(\d{2})(\d{2})/i, 'Signal — saved from a Signal chat', 'Signal'],
  [/^\d{6,12}_\d{9,20}_\d{9,20}_[no]\.(jpe?g|png|webp|mp4)$/i, 'Facebook or Instagram — the name their servers give a photo (numbers are photo and user IDs)', 'Meta'],
  [/^[A-Za-z0-9_-]{15}\.(jpe?g|png)$/, 'Possibly X (Twitter) — its media files have 15-character IDs', 'X'],
  [/^Snapchat-\d{6,}/i, 'Snapchat — saved from Snapchat', 'Snapchat'],
  [/^PXL_(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})/, 'Google Pixel camera (date and time in UTC)', 'Pixel'],
  [/^(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})(?:\(\d+\))?\.(jpe?g|mp4|heic)$/i, 'Samsung or another Android camera (local date and time)', 'Android'],
  [/^IMG_(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})/i, 'Android camera (local date and time)', 'Android'],
  [/^IMG_\d{4}\.(jpe?g|heic|png|mov|mp4)$/i, 'iPhone or iPad camera roll', 'Apple'],
  [/^Screenshot_(\d{4})(\d{2})(\d{2})[-_](\d{2})(\d{2})(\d{2})/i, 'Android screenshot (local date and time; the app name may follow)', 'Screenshot'],
  [/^Screen ?[Ss]hot (\d{4})-(\d{2})-(\d{2}) at (\d{1,2})\.(\d{2})\.(\d{2})/, 'macOS screenshot (local date and time)', 'Screenshot'],
  [/^Screenshot \(\d+\)\.png$|^Screenshot (\d{4})-(\d{2})-(\d{2}) (\d{2})(\d{2})(\d{2})\.png$/i, 'Windows screenshot', 'Screenshot'],
  [/^(?:image|unknown)(?:\d+)?\.png$/i, 'A pasted image — Discord and many chat apps name pasted pictures like this', 'Pasted'],
  [/^maxresdefault|^hqdefault/i, 'A YouTube video thumbnail', 'YouTube'],
  [/^DSC_?\d{4}|^DSCN\d{4}|^_?DSC\d{4}|^P\d{7}\.JPG$|^IMG_\d{4}\.CR[23]|^GOPR\d{4}|^DJI_\d{4}/i, 'Straight from a camera or drone (Nikon, Sony, Panasonic, Canon, GoPro, DJI)', 'Camera']];
function fxNameHint(name){
  const n = String(name || '').split(/[\\/]/).pop(); for(const [re, what, src] of FX_NAMES){ const m = n.match(re); if(!m) continue;
    let when = ''; if(m[1] && /^\d{4}$/.test(m[1]) && m[2] && m[3]){ when = `${m[1]}-${m[2]}-${m[3]}` + (m[4] ? ` ${String(m[4]).padStart(2, '0')}:${m[5]}:${m[6]}` : ''); }
    return {what, src, when}; }
  return null;
}
/* ---------- where the sun was (NOAA solar position) ---------- */
function fxSun(t, lat, lon){
  const jd = t / 864e5 + 2440587.5, T = (jd - 2451545) / 36525, rad = Math.PI / 180;
  const L0 = (280.46646 + T * (36000.76983 + T * .0003032)) % 360, M = 357.52911 + T * (35999.05029 - .0001537 * T), e = .016708634 - T * (.000042037 + .0000001267 * T);
  const C = Math.sin(M * rad) * (1.914602 - T * (.004817 + .000014 * T)) + Math.sin(2 * M * rad) * (.019993 - .000101 * T) + Math.sin(3 * M * rad) * .000289;
  const om = 125.04 - 1934.136 * T, lam = L0 + C - .00569 - .00478 * Math.sin(om * rad), eps0 = 23 + (26 + (21.448 - T * (46.815 + T * (.00059 - T * .001813))) / 60) / 60, eps = eps0 + .00256 * Math.cos(om * rad);
  const dec = Math.asin(Math.sin(eps * rad) * Math.sin(lam * rad)) / rad, y = Math.tan(eps / 2 * rad) ** 2;
  const eot = 4 / rad * (y * Math.sin(2 * L0 * rad) - 2 * e * Math.sin(M * rad) + 4 * e * y * Math.sin(M * rad) * Math.cos(2 * L0 * rad) - .5 * y * y * Math.sin(4 * L0 * rad) - 1.25 * e * e * Math.sin(2 * M * rad));
  const d = new Date(t), mins = d.getUTCHours() * 60 + d.getUTCMinutes() + d.getUTCSeconds() / 60, tst = ((mins + eot + 4 * lon) % 1440 + 1440) % 1440, ha = tst / 4 < 0 ? tst / 4 + 180 : tst / 4 - 180;
  const cz = Math.sin(lat * rad) * Math.sin(dec * rad) + Math.cos(lat * rad) * Math.cos(dec * rad) * Math.cos(ha * rad), zen = Math.acos(Math.max(-1, Math.min(1, cz))) / rad;
  let az = Math.acos(Math.max(-1, Math.min(1, (Math.sin(lat * rad) * Math.cos(zen * rad) - Math.sin(dec * rad)) / (Math.cos(lat * rad) * Math.sin(zen * rad))))) / rad; az = ha > 0 ? (az + 180) % 360 : (540 - az) % 360;
  const el = 90 - zen, refr = el > 85 ? 0 : el > 5 ? 58.1 / Math.tan(el * rad) - .07 / Math.tan(el * rad) ** 3 + .000086 / Math.tan(el * rad) ** 5 : el > -.575 ? 1735 + el * (-518.2 + el * (103.4 + el * (-12.79 + el * .711))) : -20.772 / Math.tan(el * rad);
  const elev = el + refr / 3600, noon = 720 - 4 * lon - eot;
  return {az:+az.toFixed(1), el:+elev.toFixed(1), dec:+dec.toFixed(2), noonUtc:((noon % 1440) + 1440) % 1440};
}
const FX_DIRS = ['north', 'north-north-east', 'north-east', 'east-north-east', 'east', 'east-south-east', 'south-east', 'south-south-east', 'south', 'south-south-west', 'south-west', 'west-south-west', 'west', 'west-north-west', 'north-west', 'north-north-west'];
const fxDir = a => FX_DIRS[Math.round(((a % 360) + 360) % 360 / 22.5) % 16];
/* the moment in UTC, if the file says it reliably: GPS date and time are UTC; an EXIF time with its offset is too */
function fxUtcMoment(meta){
  const F = meta && meta.fields || [], get = k => (F.find(f => f.k === k) || {}).v, gd = get('GPS date (UTC)'), gt = get('GPS time (UTC)');
  if(gd && gt){ const m = String(gd).match(/^(\d{4})[:-](\d{2})[:-](\d{2})/), t = String(gt).match(/^(\d{2}):(\d{2}):(\d{2})/); if(m && t) return {t:Date.UTC(+m[1], m[2] - 1, +m[3], +t[1], +t[2], +t[3]), src:'the GPS clock (UTC)'}; }
  if(meta && meta.taken != null && meta.tz === 'explicit' && /picture|video/.test(meta.fmt || '')) return {t:meta.taken, src:'the time taken with its time-zone offset'};
  return null;
}
function fxSunFacts(lat, lon, U, dir){
  if(!U) return {none:'The file gives no time in UTC (no GPS clock and no time-zone offset), so the sun position cannot be worked out without guessing the time zone.'};
  const S = fxSun(U.t, lat, lon), out = {S, src:U.src, t:U.t};
  if(S.el < -6) out.verdict = {tone:'red', t:`The sun was ${Math.abs(S.el)}° below the horizon — night. A daylight photo contradicts this time or place.`};
  else if(S.el < 0) out.verdict = {tone:'amber', t:`The sun had just set or not yet risen (${S.el}°) — twilight.`};
  else { const ratio = 1 / Math.tan(S.el * Math.PI / 180); out.shadow = {dir:(S.az + 180) % 360, ratio:+ratio.toFixed(2)}; }
  if(dir != null && S.el > 0){ const diff = Math.abs(((dir - S.az) % 360 + 540) % 360 - 180); out.facing = diff < 45 ? 'towards the sun — expect a backlit scene or lens flare' : diff > 135 ? 'away from the sun — the scene in front is lit, shadows fall away from the camera' : 'across the sun — shadows run sideways in the picture'; }
  return out;
}
/* ---------- Windows shortcut (LNK) ---------- */
const FX_FT = (b, o) => { const lo = u32le(b, o), hi = u32le(b, o + 4); if(!lo && !hi) return null; const ms = (hi * 4294967296 + lo) / 1e4 - 11644473600000; return ms > 0 && ms < 4e12 ? ms : null; };
const FX_GUID = (b, o) => { const h = x => x.toString(16).padStart(2, '0'); const d1 = u32le(b, o).toString(16).padStart(8, '0'), d2 = u16le(b, o + 4).toString(16).padStart(4, '0'), d3 = u16le(b, o + 6).toString(16).padStart(4, '0'); return `${d1}-${d2}-${d3}-${h(b[o + 8])}${h(b[o + 9])}-${[...b.subarray(o + 10, o + 16)].map(h).join('')}`; };
/* a version-1 GUID carries the time it was made and the network card (MAC) of the machine */
function fxUuid1(b, o){ const ver = b[o + 7] >> 4; if(ver !== 1) return null; const lo = u32le(b, o), mid = u16le(b, o + 4), hi = u16le(b, o + 6) & 0x0fff;
  const ticks = (hi * 2 ** 48) + (mid * 2 ** 32) + lo, ms = ticks / 1e4 - 12219292800000; const mac = [...b.subarray(o + 10, o + 16)].map(x => x.toString(16).padStart(2, '0')).join(':');
  return {time:ms > 0 && ms < 4e12 ? ms : null, mac, seq:((b[o + 8] & 0x3f) << 8) | b[o + 9], multicast:!!(b[o + 10] & 1)}; }
const FX_DRIVE = ['Unknown', 'No root directory', 'Removable (USB stick, card)', 'Fixed disk', 'Network drive', 'CD/DVD', 'RAM disk'];
function fxLnk(b){
  if(b.length < 0x4c || u32le(b, 0) !== 0x4c || hex(b.subarray(4, 20), 16) !== '0114020000000000c000000000000046') return null;
  const fl = u32le(b, 0x14), R = {flags:fl, attrs:u32le(b, 0x18), created:FX_FT(b, 0x1c), accessed:FX_FT(b, 0x24), written:FX_FT(b, 0x2c), size:u32le(b, 0x34), show:({1:'normal', 3:'maximised', 7:'minimised'})[u32le(b, 0x3c)] || u32le(b, 0x3c), extra:[]};
  let o = 0x4c; const U = !!(fl & 0x80), cstr = (p, max = 1024) => { let e = p; while(e < b.length && b[e] && e - p < max) e++; return latin1(b, p, e); }, wstr = p => { let e = p; while(e + 1 < b.length && (b[e] || b[e + 1]) && e - p < 2048) e += 2; return new TextDecoder('utf-16le').decode(b.subarray(p, e)); };
  if(fl & 1){ const n = u16le(b, o); o += 2 + n; }
  if(fl & 2 && o + 28 <= b.length){ const li = o, sz = u32le(b, li), hs = u32le(b, li + 4), lf = u32le(b, li + 8), vo = u32le(b, li + 12), lbo = u32le(b, li + 16), cno = u32le(b, li + 20), cso = u32le(b, li + 24);
    if(lf & 1 && vo){ const v = li + vo; R.drive = FX_DRIVE[u32le(b, v + 4)] || 'Unknown'; const ser = u32le(b, v + 8); R.serial = ser.toString(16).toUpperCase().padStart(8, '0').replace(/(.{4})/, '$1-'); const lo = u32le(b, v + 12); R.label = lo === 0x14 ? wstr(v + u32le(b, v + 16)) : cstr(v + lo, 64); }
    if(lf & 1 && lbo) R.base = hs >= 0x24 && u32le(b, li + 28) ? wstr(li + u32le(b, li + 28)) : cstr(li + lbo);
    if(lf & 2 && cno){ const c = li + cno; R.share = cstr(c + u32le(b, c + 8)); const dvo = u32le(b, c + 12); if(u32le(b, c + 4) & 1 && dvo) R.device = cstr(c + dvo, 16); }
    if(cso){ const suf = hs >= 0x24 && u32le(b, li + 32) ? wstr(li + u32le(b, li + 32)) : cstr(li + cso); if(suf) R.suffix = suf; }
    o = li + sz; }
  for(const [bit, k] of [[4, 'name'], [8, 'relative'], [0x10, 'workdir'], [0x20, 'args'], [0x40, 'icon']]){ if(!(fl & bit)) continue; if(o + 2 > b.length) break; const n = u16le(b, o); o += 2;
    R[k] = U ? new TextDecoder('utf-16le').decode(b.subarray(o, o + n * 2)) : latin1(b, o, o + n); o += U ? n * 2 : n; }
  for(let g = 0; g < 40 && o + 8 <= b.length; g++){ const sz = u32le(b, o); if(sz < 4) break; const sig = u32le(b, o + 4);
    if(sig === 0xa0000003 && sz >= 0x60){ R.machine = cstr(o + 16, 16); R.droidVol = FX_GUID(b, o + 32); R.droidObj = FX_GUID(b, o + 48); const u = fxUuid1(b, o + 48) || fxUuid1(b, o + 80); if(u){ R.mac = u.mac; R.macRandom = u.multicast; R.objTime = u.time; } R.birthObj = FX_GUID(b, o + 80); }
    else if(sig === 0xa0000001 && sz >= 0x314){ R.env = wstr(o + 268) || cstr(o + 8, 260); }
    else if(sig === 0xa0000005) R.extra.push('special folder'); else if(sig === 0xa000000b) R.extra.push('known folder'); else if(sig === 0xa0000009) R.extra.push('property store'); else if(sig === 0xa0000007) R.extra.push('icon environment');
    o += sz; }
  R.target = R.env || [R.base, R.suffix].filter(Boolean).join(R.base && R.suffix && !R.base.endsWith('\\') ? '\\' : '') || (R.share ? R.share + (R.suffix ? '\\' + R.suffix : '') : '') || R.relative || '';
  const cmd = (R.target + ' ' + (R.args || '')).toLowerCase();
  R.bad = /powershell|pwsh|cmd\.exe|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin|curl|msiexec|forfiles|conhost/.test(cmd) && (R.args || '').length > 0 || /https?:\/\/|\\\\[\w.-]+@ssl|-enc(odedcommand)?\s|frombase64/i.test(R.args || '');
  R.padded = (R.args || '').length > 200 && /^\s{20,}/.test(R.args || '');
  return R;
}
/* ---------- Windows programs: the parts that tie samples to an author or a build ---------- */
const FX_WS2 = {1:'accept',2:'bind',3:'closesocket',4:'connect',5:'getpeername',6:'getsockname',7:'getsockopt',8:'htonl',9:'htons',10:'ioctlsocket',11:'inet_addr',12:'inet_ntoa',13:'listen',14:'ntohl',15:'ntohs',16:'recv',17:'recvfrom',18:'select',19:'send',20:'sendto',21:'setsockopt',22:'shutdown',23:'socket',51:'gethostbyaddr',52:'gethostbyname',53:'getprotobyname',54:'getprotobynumber',55:'getservbyname',56:'getservbyport',57:'gethostname',111:'wsagetlasterror',112:'wsasetlasterror',115:'wsastartup',116:'wsacleanup',151:'__wsafdisset'};
function fxImphash(imports){
  const parts = []; for(const d of imports){ let dll = String(d.dll || '').toLowerCase(); const ext = dll.split('.').pop(); if(['ocx', 'sys', 'dll'].includes(ext)) dll = dll.slice(0, -ext.length - 1);
    for(const f of d.fns){ let fn = String(f); if(fn[0] === '#'){ const n = +fn.slice(1); fn = (dll === 'ws2_32' || dll === 'wsock32') && FX_WS2[n] ? FX_WS2[n] : 'ord' + n; } parts.push(dll + '.' + fn.toLowerCase()); } }
  return parts.length ? md5(new TextEncoder().encode(parts.join(','))) : ''; }
const FX_RICH_PROD = {0x00:'Unmarked objects', 0x01:'Imports (old)', 0x5d:'VS2005', 0x6d:'VS2008', 0x7b:'VS2010', 0x83:'VS2012', 0x93:'VS2013', 0x9d:'VS2015+', 0xff:'VS2015+ resource', 0x101:'VS2015+', 0x102:'VS2015+', 0x103:'VS2015+', 0x104:'VS2015+', 0x105:'VS2015+'};
function fxRich(b, peOff){
  const lim = Math.min(peOff, b.length); let r = -1; for(let i = 0x80; i + 8 <= lim; i += 4) if(u32le(b, i) === 0x68636952){ r = i; break; } if(r < 0) return null;
  const key = u32le(b, r + 4); let s = -1; for(let i = r - 4; i >= 0x40; i -= 4) if((u32le(b, i) ^ key) === 0x536e6144){ s = i; break; } if(s < 0) return null;
  const clear = new Uint8Array(r - s); for(let i = 0; i < r - s; i += 4){ const v = (u32le(b, s + i) ^ key) >>> 0; clear[i] = v & 255; clear[i + 1] = (v >>> 8) & 255; clear[i + 2] = (v >>> 16) & 255; clear[i + 3] = v >>> 24; }
  const ents = []; for(let i = 16; i + 8 <= clear.length; i += 8){ const id = u32le(clear, i), cnt = u32le(clear, i + 4); ents.push({prod:id >>> 16, build:id & 0xffff, count:cnt}); }
  return {key:key.toString(16).padStart(8, '0'), hash:md5(clear), ents}; }
function fxPeMore(b){
  if(!(b[0] === 0x4d && b[1] === 0x5a)) return null; const pe = u32le(b, 0x3c); if(pe + 24 > b.length || u32le(b, pe) !== 0x4550) return null;
  const nsec = u16le(b, pe + 6), ts = u32le(b, pe + 8), osz = u16le(b, pe + 20), op = pe + 24, pe64 = u16le(b, op) === 0x20b, dd = op + (pe64 ? 112 : 96), nDir = u32le(b, op + (pe64 ? 108 : 92)), secT = op + osz;
  const dir = i => i < nDir ? [u32le(b, dd + i * 8), u32le(b, dd + i * 8 + 4)] : [0, 0];
  const secs = []; for(let i = 0; i < nsec && i < 96; i++){ const s = secT + i * 40; secs.push({name:latin1(b, s, s + 8).replace(/\0+$/, ''), vs:u32le(b, s + 8), va:u32le(b, s + 12), rs:u32le(b, s + 16), rp:u32le(b, s + 20), ch:u32le(b, s + 36)}); }
  const r2o = rva => { const s = secs.find(x => rva >= x.va && rva < x.va + Math.max(x.vs, x.rs)); return s ? rva - s.va + s.rp : -1; };
  const cstr = (o, max = 300) => { if(o < 0) return ''; let e = o; while(e < b.length && b[e] && e - o < max) e++; return latin1(b, o, e); };
  const R = {ts, rich:fxRich(b, pe)};
  /* debug directory → CodeView → the PDB path the developer's machine wrote in */
  const [dbgR, dbgS] = dir(6), dbo = r2o(dbgR); R.pdb = [];
  if(dbgR && dbo > 0) for(let i = 0; i < Math.min(16, dbgS / 28); i++){ const e = dbo + i * 28; if(e + 28 > b.length) break; const type = u32le(b, e + 12), raw = u32le(b, e + 24), size = u32le(b, e + 16);
    if(type === 2 && raw + 24 < b.length && latin1(b, raw, raw + 4) === 'RSDS') R.pdb.push({guid:FX_GUID(b, raw + 4).toUpperCase(), age:u32le(b, raw + 20), path:new TextDecoder().decode(b.subarray(raw + 24, Math.min(b.length, raw + size))).replace(/\0[\s\S]*$/, '')});
    else if(type === 2 && latin1(b, raw, raw + 4) === 'NB10') R.pdb.push({guid:'', age:u32le(b, raw + 12), path:cstr(raw + 16)}); }
  /* exports: the DLL's own name for itself, and what it offers */
  const [exR] = dir(0), exo = r2o(exR); if(exR && exo > 0){ const nn = Math.min(u32le(b, exo + 24), 2000), an = r2o(u32le(b, exo + 32)); R.exportName = cstr(r2o(u32le(b, exo + 12))); R.exports = []; if(an > 0) for(let i = 0; i < nn; i++) R.exports.push(cstr(r2o(u32le(b, an + i * 4)), 200)); }
  /* version information (resources): what the file claims to be */
  const rs = secs.find(s => s.name === '.rsrc'); R.version = {};
  if(rs){ const d = b.subarray(rs.rp, Math.min(b.length, rs.rp + rs.rs)), w = new TextDecoder('utf-16le').decode(d.subarray(0, d.length & ~1));
    for(const k of ['CompanyName', 'FileDescription', 'FileVersion', 'InternalName', 'LegalCopyright', 'OriginalFilename', 'ProductName', 'ProductVersion', 'Comments']){ const m = w.match(new RegExp(k + '\\0+([^\\0]{1,200})')); if(m && !/^[\u0001-\u001f]/.test(m[1])) R.version[k] = m[1].trim(); }
    /* the language of the resources: often the language of the author's Windows */
    R.langs = [...new Set([...w.matchAll(/StringFileInfo[\s\S]{0,12}?([0-9A-Fa-f]{8})\0/g)].map(m => m[1].slice(0, 4).toLowerCase()))]; }
  const [sdO, sdS] = dir(4); R.cert = sdO && sdS ? {off:sdO, size:sdS} : null;
  const end = Math.max(0, ...secs.map(s => s.rp + s.rs)), sigEnd = R.cert ? R.cert.off : b.length; R.overlay = end < sigEnd && sigEnd - end > 16 ? {off:end, size:sigEnd - end, head:latin1(b, end, end + 16).replace(/[^\x20-\x7e]/g, '.')} : null;
  R.tls = !!dir(9)[0]; R.dotnet = !!dir(14)[0];
  R.wx = secs.filter(s => (s.ch & 0x20000000) && (s.ch & 0x80000000)).map(s => s.name);
  R.empty = secs.filter(s => s.rs === 0 && s.vs > 0x10000).map(s => s.name);
  R.tsNote = !ts ? 'zero' : ts === 0x2a425e19 ? 'Delphi default (1992) — not a real build time' : ts * 1000 > Date.now() + 864e5 ? 'in the future — faked, or a reproducible build where the field is a hash' : ts < 0x386d4380 ? 'before 2000 — faked, or a reproducible build' : '';
  return R;
}
/* language IDs commonly seen in resources */
const FX_LANG = {'0409':'English (US)', '0809':'English (UK)', '0419':'Russian', '0422':'Ukrainian', '0804':'Chinese (Simplified)', '0404':'Chinese (Traditional)', '0412':'Korean', '0411':'Japanese', '0407':'German', '040c':'French', '0410':'Italian', '0c0a':'Spanish', '0416':'Portuguese (Brazil)', '0429':'Persian', '0401':'Arabic', '041f':'Turkish', '0415':'Polish', '0000':'Neutral', '0809 ':'English (UK)', '042a':'Vietnamese', '0421':'Indonesian', '040d':'Hebrew', '0418':'Romanian'};
/* ---------- Linux programs ---------- */
function fxElfMore(b){
  if(!(b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46)) return null; const is64 = b[4] === 2, le = b[5] === 1, U16 = o => le ? u16le(b, o) : u16be(b, o), U32 = o => le ? u32le(b, o) : u32be(b, o), U64 = o => le ? U32(o) + U32(o + 4) * 4294967296 : U32(o) * 4294967296 + U32(o + 4), UA = o => is64 ? U64(o) : U32(o);
  const shoff = is64 ? UA(0x28) : U32(0x20), shentsize = U16(is64 ? 0x3a : 0x2e), shnum = U16(is64 ? 0x3c : 0x30), shstrndx = U16(is64 ? 0x3e : 0x32);
  const R = {sections:[], needed:[], comment:'', go:'', goBuild:'', stripped:true, buildId:''};
  if(!shoff || shoff + shnum * shentsize > b.length || shnum > 400) return R;
  const sh = i => { const o = shoff + i * shentsize; return {name:U32(o), type:U32(o + 4), off:is64 ? UA(o + 0x18) : U32(o + 0x10), size:is64 ? UA(o + 0x20) : U32(o + 0x14), link:U32(o + (is64 ? 0x28 : 0x18))}; };
  const S = Array.from({length:shnum}, (_, i) => sh(i)), str = S[shstrndx], nm = o => { let e = str.off + o; const s = e; while(e < b.length && b[e]) e++; return latin1(b, s, e); };
  for(const s of S) s.n = str ? nm(s.name) : '';
  R.sections = S.map(s => s.n).filter(Boolean);
  R.stripped = !S.some(s => s.type === 2);
  const cm = S.find(s => s.n === '.comment'); if(cm) R.comment = [...new Set(latin1(b, cm.off, cm.off + Math.min(cm.size, 600)).split('\0').map(x => x.trim()).filter(Boolean))].join('; ');
  const dyn = S.find(s => s.n === '.dynamic'), ds = dyn && S[dyn.link];
  if(dyn && ds){ const es = is64 ? 16 : 8; for(let o = dyn.off; o + es <= dyn.off + dyn.size && R.needed.length < 80; o += es){ const tag = is64 ? U64(o) : U32(o), val = is64 ? U64(o + 8) : U32(o + 4); if(tag === 0) break; if(tag === 1 || tag === 14){ let e = ds.off + val; const s0 = e; while(e < b.length && b[e] && e - s0 < 300) e++; if(tag === 1) R.needed.push(latin1(b, s0, e)); else R.soname = latin1(b, s0, e); } } }
  const gb = S.find(s => s.n === '.note.go.buildid'); if(gb) R.goBuild = latin1(b, gb.off + 16, gb.off + gb.size).replace(/[^\x20-\x7e]/g, '');
  const nb = S.find(s => s.n === '.note.gnu.build-id'); if(nb) R.buildId = hex(b.subarray(nb.off + 16, nb.off + nb.size), 40);
  const head = latin1(b, 0, Math.min(b.length, 8e6)), gv = head.match(/\bgo1\.\d{1,2}(?:\.\d{1,2})?\b/); if(gv) R.go = gv[0]; const gm = head.match(/\bpath\t([\w./-]{3,120})\n/); if(gm) R.goPath = gm[1];
  return R;
}
/* ---------- ZIP: the machine and time zone of whoever packed it ---------- */
const FX_ZOS = {0:'Windows / MS-DOS (FAT)', 3:'Unix or Linux', 7:'Macintosh', 10:'Windows (NTFS)', 11:'Windows (VFAT)', 19:'macOS'};
function fxZip(b){
  let eocd = -1; for(let i = b.length - 22; i >= Math.max(0, b.length - 70000); i--) if(u32le(b, i) === 0x06054b50){ eocd = i; break; } if(eocd < 0) return null;
  const n = u16le(b, eocd + 10); let o = u32le(b, eocd + 16); const E = [];
  for(let i = 0; i < n && o + 46 <= b.length && E.length < 3000; i++){ if(u32le(b, o) !== 0x02014b50) break;
    const made = u16le(b, o + 4), dt = u16le(b, o + 12), dd = u16le(b, o + 14), fl = u16le(b, o + 28), xl = u16le(b, o + 30), cl = u16le(b, o + 32), ext = u32le(b, o + 38), lho = u32le(b, o + 42);
    const name = new TextDecoder().decode(b.subarray(o + 46, o + 46 + fl)), dos = Date.UTC(((dd >> 9) & 127) + 1980, ((dd >> 5) & 15) - 1, dd & 31, dt >> 11, (dt >> 5) & 63, (dt & 31) * 2);
    const e = {name, os:made >> 8, ver:made & 255, dos, utc:null, uid:null, gid:null, ntfs:null, mode:(made >> 8) === 3 ? (ext >>> 16) & 0o7777 : null, comment:cl ? new TextDecoder().decode(b.subarray(o + 46 + fl + xl, o + 46 + fl + xl + cl)) : '', lho};
    /* extra fields: the central copy, and the local copy (Info-ZIP keeps UID/GID only in the local one) */
    const scan = (p, end) => { while(p + 4 <= end){ const id = u16le(b, p), sz = u16le(b, p + 2), d = p + 4; if(d + sz > end) break;
      if(id === 0x5455 && sz >= 5 && b[d] & 1) e.utc = u32le(b, d + 1) * 1000;
      else if(id === 0x7875 && sz >= 3){ const us = b[d + 1]; if(us === 4) e.uid = u32le(b, d + 2); else if(us === 2) e.uid = u16le(b, d + 2); const gs = b[d + 2 + us]; if(gs === 4) e.gid = u32le(b, d + 3 + us); else if(gs === 2) e.gid = u16le(b, d + 3 + us); }
      else if(id === 0x5855 && sz >= 8){ e.utc = e.utc || u32le(b, d + 4) * 1000; if(sz >= 12){ e.uid = u16le(b, d + 8); e.gid = u16le(b, d + 10); } }
      else if(id === 0x000a && sz >= 32){ const t = FX_FT(b, d + 8); if(t) e.ntfs = t; }
      p = d + sz; } };
    scan(o + 46 + fl, o + 46 + fl + xl);
    if(u32le(b, lho) === 0x04034b50){ const lfl = u16le(b, lho + 26), lxl = u16le(b, lho + 28); scan(lho + 30 + lfl, lho + 30 + lfl + lxl); }
    E.push(e); o += 46 + fl + xl + cl; }
  const R = {entries:E, os:[...new Set(E.map(e => FX_ZOS[e.os] || 'system ' + e.os))], uids:[...new Set(E.filter(e => e.uid != null).map(e => e.uid + ':' + e.gid))], mac:E.some(e => /^__MACOSX\/|\.DS_Store$/.test(e.name)), thumbs:E.some(e => /(^|\/)(Thumbs\.db|desktop\.ini)$/i.test(e.name))};
  /* DOS times are the packer's local clock; UT and NTFS times are UTC — the gap is its time zone */
  const offs = E.map(e => { const u = e.utc != null ? e.utc : e.ntfs; return u != null ? Math.round((e.dos - Math.floor(u / 2000) * 2000) / 9e5) * 15 : null; }).filter(x => x != null && Math.abs(x) <= 14 * 60);
  if(offs.length){ const c = new Map(); for(const x of offs) c.set(x, (c.get(x) || 0) + 1); const [best, k] = [...c.entries()].sort((x, y) => y[1] - x[1])[0]; R.tz = {min:best, n:k, of:offs.length, txt:'UTC' + (best < 0 ? '−' : '+') + String(Math.floor(Math.abs(best) / 60)).padStart(2, '0') + ':' + String(Math.abs(best) % 60).padStart(2, '0')}; }
  const times = E.map(e => e.utc != null ? e.utc : e.ntfs != null ? e.ntfs : null).filter(x => x != null);
  if(times.length){ R.first = Math.min(...times); R.last = Math.max(...times); }
  return R;
}
/* one file out of an archive, as bytes, so it can be inspected on its own */
async function fxZipEntry(b, name, max = 200 * 1048576){
  const Z = zipOpen(b); if(!Z) return null; const f = Z.files.find(x => x.name === name); if(!f || f.enc) return null; const lh = f.lho; if(u32le(b, lh) !== 0x04034b50) return null;
  const start = lh + 30 + u16le(b, lh + 26) + u16le(b, lh + 28), data = b.subarray(start, start + f.csize);
  if(f.method === 0) return data.slice(); if(f.method !== 8) return null; return new Uint8Array(await inflateRaw(data, max));
}
/* ---------- strings by kind ---------- */
const FX_SK = [
  ['url', 'Links', /\b(?:https?|ftp|wss?):\/\/[^\s"'<>]{4,}/i],
  ['path', 'File paths', /\b[A-Za-z]:\\[^\s"*?<>|]{3,}|\\\\[\w.$-]+\\[^\s"]{2,}|(?:^|\s)\/(?:etc|tmp|var|usr|home|root|opt|dev|proc|Users|Library|Applications|System)\/[\w./-]{2,}|%(?:APPDATA|TEMP|LOCALAPPDATA|USERPROFILE|PROGRAMDATA|SYSTEMROOT|WINDIR)%/i],
  ['reg', 'Registry', /\b(?:HKEY_[A-Z_]+|HK(?:LM|CU|CR|U)\b)[\\/]|\\(?:Software|SYSTEM)\\(?:Microsoft|CurrentControlSet|Classes|Wow6432Node)\\/i],
  ['cmd', 'Commands', /\b(?:powershell|pwsh|cmd(?:\.exe)?\s+\/[ck]|mshta|rundll32|regsvr32|schtasks|wmic|bitsadmin|certutil|vssadmin|bcdedit|net\s+(?:user|localgroup)|whoami|curl\s+-|wget\s+|chmod\s+\+x|nohup|crontab|base64\s+-d|bash\s+-[ci])\b/i],
  ['secret', 'Keys & tokens', /-----BEGIN [A-Z ]*(?:PRIVATE KEY|CERTIFICATE)-----|\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{36}\b|\bxox[baprs]-[\w-]{10,}|\bAIza[\w-]{35}\b|\b\d{8,10}:AA[\w-]{33}\b|\bsk_live_[\w]{20,}|discord(?:app)?\.com\/api\/webhooks\//],
  ['crypto', 'Crypto & wallets', /\b(?:bc1[ac-hj-np-z02-9]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40}|4[0-9AB][1-9A-HJ-NP-Za-km-z]{93})\b|\b(?:wallet\.dat|seed phrase|mnemonic|metamask|exodus|electrum)\b/i],
  ['b64', 'Base64 blobs', /^(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/],
  ['ua', 'User agents', /Mozilla\/\d\.\d \(|User-Agent:/i],
  ['dev', 'Build & developer', /\.pdb\b|\\Users\\[^\\]{2,}\\|\/home\/[^/]{2,}\/|\bgo1\.\d+|rustc|GCC: \(|MSVC|Delphi|PyInstaller|\b(?:debug|release)\\/i]];
function fxStrKinds(list){ const out = {}; for(const s of list){ const ks = []; for(const [k, , re] of FX_SK) if(re.test(s[1])) ks.push(k); s[4] = ks; for(const k of ks) out[k] = (out[k] || 0) + 1; } return out; }
function fxB64(s){ try{ const t = atob(s.replace(/\s+/g, '')); const p = [...t.slice(0, 200)].filter(c => { const k = c.charCodeAt(0); return k === 9 || k === 10 || k === 13 || (k >= 32 && k < 127); }).length / Math.max(1, Math.min(200, t.length)); return p > .85 ? t.slice(0, 600) : ''; }catch(e){ return ''; } }

/* ---------- picture views: noise, levels, copy-move, histogram ---------- */
/* noise residual: the picture minus a smoothed copy, amplified. Pasted-in areas often carry a different grain. */
function fxNoise(src, gain = 10){
  const {width:w, height:h, data:a} = src, out = new ImageData(w, h), o = out.data, g = new Float32Array(w * h);
  for(let i = 0, p = 0; p < w * h; i += 4, p++) g[p] = a[i] * .299 + a[i + 1] * .587 + a[i + 2] * .114;
  for(let y = 0; y < h; y++) for(let x = 0; x < w; x++){ let s = 0, n = 0; for(let dy = -1; dy <= 1; dy++){ const yy = y + dy; if(yy < 0 || yy >= h) continue; for(let dx = -1; dx <= 1; dx++){ const xx = x + dx; if(xx < 0 || xx >= w) continue; s += g[yy * w + xx]; n++; } }
    const v = Math.min(255, Math.abs(g[y * w + x] - s / n) * gain), i = (y * w + x) * 4; o[i] = o[i + 1] = o[i + 2] = v; o[i + 3] = 255; }
  return out;
}
/* levels: stretch each channel between its 0.5 % and 99.5 % points — brings out detail in dark or washed-out pictures */
function fxLevels(src){
  const {width:w, height:h, data:a} = src, out = new ImageData(w, h), o = out.data, n = w * h, lo = [], hi = [];
  for(let c = 0; c < 3; c++){ const H = new Uint32Array(256); for(let i = c; i < a.length; i += 4) H[a[i]]++; let s = 0, l = 0, u = 255; for(let v = 0; v < 256; v++){ s += H[v]; if(s >= n * .005){ l = v; break; } } s = 0; for(let v = 255; v >= 0; v--){ s += H[v]; if(s >= n * .005){ u = v; break; } } lo.push(l); hi.push(Math.max(l + 1, u)); }
  for(let i = 0; i < a.length; i += 4){ for(let c = 0; c < 3; c++) o[i + c] = Math.max(0, Math.min(255, (a[i + c] - lo[c]) * 255 / (hi[c] - lo[c]))); o[i + 3] = 255; }
  return {img:out, lo, hi};
}
function fxHist(src){ const H = [new Uint32Array(256), new Uint32Array(256), new Uint32Array(256)], a = src.data; for(let i = 0; i < a.length; i += 4){ H[0][a[i]]++; H[1][a[i + 1]]++; H[2][a[i + 2]]++; }
  const n = a.length / 4, clipLo = (H[0][0] + H[1][0] + H[2][0]) / 3 / n, clipHi = (H[0][255] + H[1][255] + H[2][255]) / 3 / n;
  /* gaps: a histogram with regularly empty bins was stretched by an editor (levels, curves) */
  let gaps = 0, used = 0; for(let v = 8; v < 248; v++){ const t = H[0][v] + H[1][v] + H[2][v]; if(t) used++; else if((H[0][v - 1] + H[1][v - 1] + H[2][v - 1]) && (H[0][v + 1] + H[1][v + 1] + H[2][v + 1])) gaps++; }
  return {H, clipLo, clipHi, gaps, used}; }
function fxHistSvg(Hs){ const W = 256, Ht = 70, mx = Math.max(1, ...Hs.H.flatMap(h => [...h].slice(1, 255))), col = ['#e5484d', '#30a46c', '#3e63dd'];
  return `<svg class="fx-hist" viewBox="0 0 ${W} ${Ht}" preserveAspectRatio="none" role="img" aria-label="Colour histogram">${Hs.H.map((h, c) => `<path d="M0 ${Ht}${[...h].map((v, i) => ` L${i} ${(Ht - Math.min(1, v / mx) * Ht).toFixed(1)}`).join('')} L255 ${Ht}Z" fill="${col[c]}" fill-opacity=".28" stroke="${col[c]}" stroke-width=".6"/>`).join('')}</svg>`; }
/* copy-move: the same patch of texture in two places. Blocks are compared by their shape (not brightness); a crowd of
   blocks all moved by the same offset is a copied area. Flat areas (sky, walls) are left out — they match everywhere. */
function fxCloneScan(src, o = {}){
  const sc = Math.min(1, (o.max || 640) / Math.max(src.width, src.height)), w = Math.max(16, Math.round(src.width * sc)), h = Math.max(16, Math.round(src.height * sc));
  const c = document.createElement('canvas'); c.width = w; c.height = h; const x = c.getContext('2d', {willReadFrequently:true}); x.drawImage(toCanvas(src), 0, 0, w, h);
  const d = x.getImageData(0, 0, w, h).data, g = new Float32Array(w * h); for(let i = 0, p = 0; p < w * h; i += 4, p++) g[p] = d[i] * .299 + d[i + 1] * .587 + d[i + 2] * .114;
  const B = o.B || 12, S = o.S || 2, blocks = [];
  for(let y = 0; y + B <= h; y += S) for(let xx = 0; xx + B <= w; xx += S){ let m = 0; for(let j = 0; j < B; j++) for(let i = 0; i < B; i++) m += g[(y + j) * w + xx + i]; m /= B * B;
    let v = 0; for(let j = 0; j < B; j++) for(let i = 0; i < B; i++){ const t = g[(y + j) * w + xx + i] - m; v += t * t; } v = Math.sqrt(v / (B * B)); if(v < 6) continue;
    /* 4×4 cells, each its mean relative to the block mean: the block's shape, not its brightness */
    const f = new Float32Array(16), cs = B / 4; for(let cy = 0; cy < 4; cy++) for(let cx = 0; cx < 4; cx++){ let t = 0; for(let j = 0; j < cs; j++) for(let i = 0; i < cs; i++) t += g[(y + cy * cs + j) * w + xx + cx * cs + i]; f[cy * 4 + cx] = (t / (cs * cs) - m) / v; }
    blocks.push([xx, y, m, v, f]); }
  /* neighbours in sorted order are the most alike blocks (the classic lexicographic sort for copy-move) */
  const ord = blocks.map((_, i) => i).sort((a, b2) => { const A = blocks[a][4], Bf = blocks[b2][4]; for(let k = 0; k < 16; k++){ const d = Math.round(A[k] * (o.Qs || 2)) - Math.round(Bf[k] * (o.Qs || 2)); if(d) return d; } return 0; });
  const sad = (a, b2) => { const [ax, ay, am] = blocks[a], [bx, by, bm] = blocks[b2]; let s = 0; for(let j = 0; j < B; j++) for(let i = 0; i < B; i++) s += Math.abs((g[(ay + j) * w + ax + i] - am) - (g[(by + j) * w + bx + i] - bm)); return s / (B * B); };
  const vec = new Map(), W = o.W || 16;
  for(let p = 0; p < ord.length; p++) for(let q = p + 1; q < Math.min(ord.length, p + 1 + W); q++){ const a = ord[p], c = ord[q], A = blocks[a], Bk = blocks[c]; let dx = Bk[0] - A[0], dy = Bk[1] - A[1], s0 = a, s1 = c;
    if(Math.hypot(dx, dy) < B * 2) continue; if(dx < 0 || (dx === 0 && dy < 0)){ dx = -dx; dy = -dy; s0 = c; s1 = a; }
    if(Math.abs(A[3] - Bk[3]) > Math.max(A[3], Bk[3]) * .2 || sad(a, c) > Math.max(2.5, Math.min(A[3], Bk[3]) * (o.T || .3))) continue;
    const k = (Math.round(dx / S) * S) + ',' + (Math.round(dy / S) * S); let V = vec.get(k); if(!V) vec.set(k, V = []); V.push([s0, s1]); }
  /* an offset counts when enough distinct blocks share it and they sit together (a copied area, not scattered noise) */
  const found = [];
  for(const [k, P] of [...vec.entries()].sort((a, b2) => b2[1].length - a[1].length).slice(0, 6)){
    const A = [...new Set(P.map(p => p[0]))], Bs = [...new Set(P.map(p => p[1]))]; if(A.length < (o.N || 10) || Bs.length < (o.N || 10)) continue;
    const bb = L => { const xs = L.map(i => blocks[i][0]), ys = L.map(i => blocks[i][1]), x0 = Math.min(...xs), y0 = Math.min(...ys); return [x0, y0, Math.max(...xs) + B - x0, Math.max(...ys) + B - y0]; };
    const b1 = bb(A), b2 = bb(Bs), dens = A.length * S * S / (b1[2] * b1[3]); if(dens < .2) continue; const [dx, dy] = k.split(',').map(Number);
    if(found.some(f => Math.abs(f.dx - dx) <= S && Math.abs(f.dy - dy) <= S)) continue;
    found.push({dx:Math.round(dx / sc), dy:Math.round(dy / sc), n:A.length, box:b1.map(v => v / sc), to:b2.map(v => v / sc)}); }
  return {found, scale:sc};
}
function fxCloneView(src, R){
  const out = new ImageData(new Uint8ClampedArray(src.data), src.width, src.height), o = out.data; for(let i = 0; i < o.length; i += 4){ o[i] = o[i] * .45; o[i + 1] = o[i + 1] * .45; o[i + 2] = o[i + 2] * .45; }
  const c = toCanvas(out), x = c.getContext('2d'); x.lineWidth = Math.max(2, src.width / 300);
  R.found.forEach((f, i) => { const col = ['#ff5a5f', '#ffb224', '#3ecf8e', '#5b8def'][i % 4]; x.strokeStyle = col; x.fillStyle = col + '33';
    for(const b of [f.box, f.to]){ x.fillRect(b[0], b[1], b[2], b[3]); x.strokeRect(b[0], b[1], b[2], b[3]); }
    x.beginPath(); x.moveTo(f.box[0] + f.box[2] / 2, f.box[1] + f.box[3] / 2); x.lineTo(f.to[0] + f.to[2] / 2, f.to[1] + f.to[3] / 2); x.stroke(); });
  return x.getImageData(0, 0, src.width, src.height);
}

/* ---------- the thumbnail inside the file, compared with the picture ---------- */
async function fxThumbCompare(thumbBytes, mainBlob){
  const tb = new Blob([thumbBytes], {type:'image/jpeg'}), [st, sm] = await Promise.all([picSigBlob(tb), picSigBlob(mainBlob)]); if(!st || !sm) return null;
  const [bt, bm] = await Promise.all([createImageBitmap(tb), createImageBitmap(mainBlob)]), at = bt.width / bt.height, am = bm.width / bm.height;
  const D = picDist(st, sm), shape = Math.abs(at - am) / am > .06 && Math.abs(at - 1 / am) / (1 / am) > .06;
  let tone = 'ok', t = 'The thumbnail shows the same picture.';
  if((D.how === 'contains' || D.how === 'contains mirrored') && D.d <= 14){ tone = 'amber'; t = 'The picture is a crop of what the thumbnail shows — cropped after it was taken, and the thumbnail was not updated.'; }
  else if(D.d > 10){ tone = 'red'; t = 'The thumbnail shows a different picture — the image was edited or replaced after the camera saved it, and the thumbnail was not updated.'; }
  else if(shape){ tone = 'amber'; t = 'The thumbnail has a different shape from the picture — cropped or resized after it was taken.'; }
  return {url:URL.createObjectURL(tb), d:D.d, how:D.how, at:+at.toFixed(3), am:+am.toFixed(3), tw:bt.width, th:bt.height, tone, t};
}
/* ---------- cards ---------- */
const fxKv = (k, v, mono) => v || v === 0 ? `<div class="kv"><span>${esc(k)}</span>${mono ? `<code>${esc(v)}</code>` : `<b>${esc(v)}</b>`}</div>` : '';
const fxChip = (t, tone) => `<span class="chip sq fx-c ${tone || ''}">${esc(t)}</span>`;
const fxLink = (n, u) => `<a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(n)}${ico('arrow-up-right','sm')}</a>`;
/* all the metadata the file holds, grouped, with what stands out on top */
function fxMetaCard(M){
  if(!M || !M.fields || !M.fields.length) return M && /picture/.test(M.fmt || '') ? `<section class="card"><header><h3>${ico('scan-search','sm')} Metadata</h3></header><div class="body"><p class="t3 small" style="margin:0">No metadata — stripped by an app or website, a screenshot, or saved by a program that writes none.</p></div></section>` : '';
  const F = M.fields, flags = F.filter(f => f.g === 'Stands out'), open = !!UI.fxMetaAll, groups = MT_GROUPS.filter(g => g !== 'Stands out').map(g => [g, F.filter(f => f.g === g)]).filter(x => x[1].length);
  const shown = open ? groups : groups.map(([g, L]) => [g, L.slice(0, g === 'Software' || g === 'When' ? 4 : 3)]), total = F.length - flags.length, vis = shown.reduce((s, x) => s + x[1].length, 0);
  const G = M.gps;
  return (M.gen && typeof aiGenCard === 'function' ? aiGenCard(M.gen) : '') + `<section class="card fx-meta"><header><h3>${ico('scan-search','sm')} Metadata</h3><span class="t3">${esc(M.fmt || '')} · ${total} fact${total === 1 ? '' : 's'}</span></header><div class="body">
    ${flags.length ? `<div class="wrap fx-flags">${flags.map(f => fxChip(f.v, f.tone)).join('')}</div>` : ''}
    ${G ? `<div class="gpsbox"><div>${ico('map-pin','sm')}<b>${G.lat}, ${G.lon}</b>${G.alt != null ? `<span class="t3"> · ${G.alt} m</span>` : ''}${G.dir != null ? `<span class="t3"> · facing ${G.dir}° ${fxDir(G.dir)}</span>` : ''}</div><div class="pivots">${geoLinks(G.lat, G.lon).map(([n, u]) => fxLink(n, u)).join('')}</div></div>` : ''}
    ${shown.map(([g, L]) => `<h5 class="fx-g">${esc(g)}</h5>${L.map(f => `<div class="kv fx-kv"><span>${esc(f.k)}</span><b>${esc(f.v.length > 400 && !open ? f.v.slice(0, 400) + '…' : f.v)}</b><button class="iconbtn sm" data-act="flagCopy" data-v="${esc(f.v)}" aria-label="Copy ${esc(f.k)}">${ico('copy','sm')}</button></div>`).join('')}`).join('')}
    ${vis < total || open ? `<button class="lnk small" data-act="fxMetaAll">${open ? 'Show fewer' : `Show all ${total}`}</button>` : ''}</div></section>`;
}
/* how the picture was written and what that says */
function fxPicCard(X, nameHint, sun){
  const J = X.jpg, rows = [], notes = [];
  if(J){
    rows.push(fxKv('Encoder tables', J.stdTables ? `Standard (IJG / libjpeg) at quality ${J.quality}` : `Custom — closest to quality ${J.quality}`));
    rows.push(fxKv('Chroma sampling', J.subsampling)); rows.push(fxKv('Coding', J.progressive ? 'Progressive' : 'Baseline'));
    rows.push(`<div class="kv"><span>Segments</span><code style="white-space:normal">${esc(J.segs.join(' · '))}</code></div>`);
    if(J.icc) rows.push(fxKv('Colour profile', [J.icc.desc, J.icc.creator && 'by ' + J.icc.creator].filter(Boolean).join(' ')));
    if(J.comment) rows.push(fxKv('JPEG comment', J.comment, true));
    if(J.stdTables) notes.push(['', `Standard tables at quality ${J.quality}: written by a libjpeg-family encoder — phones, apps, websites and “export” in most editors. Camera firmware and Photoshop's own save use their own tables.`]);
    else notes.push(['', `Custom quantisation tables (closest to quality ${J.quality}) — typical of a camera's firmware or Photoshop; a file re-saved by an app or website usually ends up with standard tables.`]);
    if(J.quality < 80 && J.jfif && !J.exif) notes.push(['amber', `Low quality (${J.quality}) and no EXIF: the usual signature of a picture that went through a social network or messenger — it is not the original.`]);
    if(J.fbmd) notes.push(['amber', 'Facebook marker (FBMD) in the IPTC data — this file passed through Facebook, Instagram or Messenger.']);
    if(J.photoshop && J.adobe) notes.push(['amber', 'Photoshop segments (APP13 and APP14) — saved by Adobe software.']);
    if(J.icc && /Display P3/i.test(J.icc.desc)) notes.push(['', 'Display P3 colour profile — typical of an iPhone, iPad or Mac.']);
    if(J.icc && /Google|Skia/i.test(J.icc.desc + J.icc.cprt)) notes.push(['', 'Google/Skia colour profile — written by Android or Chrome.']);
    if(J.mpf) notes.push(['', 'Multi-picture data (MPF): a phone or camera wrote this file with a second, smaller image inside.']);
  }
  if(X.png){ if(X.png.chunks.includes('iTXt') || X.png.chunks.includes('tEXt')) notes.push(['', 'PNG text chunks: ' + [...new Set(X.png.text.map(t => t.split(' → ')[0]))].slice(0, 6).join(', ')]); if(X.png.chunks.includes('eXIf')) notes.push(['', 'PNG with an EXIF chunk — usually from a phone screenshot or an app that keeps camera data.']); }
  if(nameHint) notes.push(['', `File name: ${nameHint.what}${nameHint.when ? ' — ' + nameHint.when : ''}.`]);
  const T = X.thumb;
  const thumb = T ? `<div class="fx-th"><img src="${esc(T.url)}" alt="Thumbnail stored in the file" width="${T.tw}" height="${T.th}"><div>${fxChip(T.t, T.tone === 'ok' ? '' : T.tone)}<p class="t3 small">Embedded thumbnail ${T.tw}×${T.th}, shape ${T.at} vs picture ${T.am} · ${T.d}/64 bits differ (${esc(T.how)})</p></div></div>` : X.thumbNone ? '' : '';
  const SUN = sun ? fxSunHtml(sun) : '';
  if(!rows.length && !notes.length && !thumb && !SUN) return '';
  return `<section class="card fx-pic"><header><h3>${ico('microscope','sm')} Picture forensics</h3></header><div class="body">${rows.join('')}
    ${notes.map(([tone, t]) => `<div class="fx-note ${tone}">${esc(t)}</div>`).join('')}${thumb ? `<h5 class="fx-g">Thumbnail inside the file</h5>${thumb}` : ''}${SUN}</div></section>`;
}
function fxSunHtml(F){
  if(F.none) return `<h5 class="fx-g">Sun position</h5><p class="t3 small" style="margin:0">${esc(F.none)}</p>`;
  const S = F.S, when = new Date(F.t).toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
  return `<h5 class="fx-g">Sun position</h5><div class="fx-sun"><svg viewBox="-50 -50 100 100" width="92" height="92" role="img" aria-label="Sun at azimuth ${S.az} degrees, ${S.el} degrees high"><circle r="44" fill="none" stroke="var(--line)"/><text y="-36" text-anchor="middle" font-size="9" fill="var(--t3)">N</text>
      ${S.el > 0 ? `<line x1="0" y1="0" x2="${(Math.sin(S.az * Math.PI / 180) * 40 * (1 - S.el / 90)).toFixed(1)}" y2="${(-Math.cos(S.az * Math.PI / 180) * 40 * (1 - S.el / 90)).toFixed(1)}" stroke="var(--amber)" stroke-width="2"/><circle cx="${(Math.sin(S.az * Math.PI / 180) * 40 * (1 - S.el / 90)).toFixed(1)}" cy="${(-Math.cos(S.az * Math.PI / 180) * 40 * (1 - S.el / 90)).toFixed(1)}" r="5" fill="var(--amber)"/>` : '<circle r="5" fill="var(--t3)"/>'}
      ${F.shadow ? `<line x1="0" y1="0" x2="${(Math.sin(F.shadow.dir * Math.PI / 180) * Math.min(40, 12 * F.shadow.ratio)).toFixed(1)}" y2="${(-Math.cos(F.shadow.dir * Math.PI / 180) * Math.min(40, 12 * F.shadow.ratio)).toFixed(1)}" stroke="var(--t2)" stroke-width="3" stroke-linecap="round" stroke-dasharray="2 3"/>` : ''}</svg>
    <div>${fxKv('At', when)}${fxKv('Sun direction', `${S.az}° (${fxDir(S.az)})`)}${fxKv('Sun height', `${S.el}°`)}${F.shadow ? fxKv('Shadows point', `${Math.round(F.shadow.dir)}° (${fxDir(F.shadow.dir)}), ${F.shadow.ratio}× as long as the object is tall`) : ''}${F.facing ? fxKv('Camera faced', F.facing) : ''}
      ${F.verdict ? fxChip(F.verdict.t, F.verdict.tone) : ''}<p class="t3 small" style="margin:6px 0 0">Time from ${esc(F.src)}. Compare with the shadows in the picture: a mismatch means the time, the place or the picture is wrong.</p></div></div>`;
}
function fxLnkCard(L){
  const d = t => t ? new Date(t).toISOString().replace('T', ' ').slice(0, 19) + ' UTC' : '';
  return `<section class="card${L.bad ? ' warnc' : ''}"><header><h3>${ico('link','sm')} Windows shortcut (LNK)</h3></header><div class="body">
    ${L.bad ? `<div class="note red" style="margin:0 0 10px"><span class="ic">${ico('triangle-alert','sm')}</span><div><b>Runs a command, not a document.</b> Shortcuts like this are a common way in for malware: the icon says PDF, the target is a script host.</div></div>` : ''}
    ${fxKv('Target', L.target, true)}${fxKv('Arguments', L.args ? (L.padded ? '(padded with spaces to hide it) ' : '') + L.args.trim() : '', true)}${fxKv('Start in', L.workdir, true)}${fxKv('Icon', L.icon, true)}${fxKv('Window', L.show)}
    ${fxKv('Target created', d(L.created))}${fxKv('Target modified', d(L.written))}${fxKv('Target accessed', d(L.accessed))}${fxKv('Target size', L.size ? fmtBytes(L.size) : '')}
    <h5 class="fx-g">The machine it was made on</h5>${fxKv('NetBIOS name', L.machine, true)}${fxKv('MAC address', L.mac ? L.mac + (L.macRandom ? ' (randomised)' : '') : '', true)}<div id="fxMacV"></div>${fxKv('MAC recorded', d(L.objTime))}${fxKv('Drive', L.drive)}${fxKv('Volume serial', L.serial, true)}${fxKv('Volume label', L.label)}${fxKv('Network share', L.share, true)}${fxKv('Droid volume ID', L.droidVol, true)}${fxKv('Droid object ID', L.droidObj, true)}
    <p class="t3 small" style="margin:8px 0 0">The machine name, MAC address and volume serial were copied from the computer that made the shortcut. The same values in other samples tie them to one builder.</p></div></section>`;
}
function fxPeCard(M, P, sig){
  const VT = q => 'https://www.virustotal.com/gui/search/' + encodeURIComponent(encodeURIComponent(q)), MB = q => 'https://bazaar.abuse.ch/browse.php?search=' + encodeURIComponent(q);
  const imp = M.imphash, rows = [];
  rows.push(`<div class="kv"><span>Imphash</span><code>${esc(imp || '— no imports')}</code>${imp ? `<span class="pivots inl">${fxLink('VirusTotal', VT('imphash:' + imp))}${fxLink('MalwareBazaar', MB('imphash:' + imp))}</span>` : ''}</div>`);
  if(M.rich) rows.push(`<div class="kv"><span>Rich header hash</span><code>${esc(M.rich.hash)}</code><span class="pivots inl">${fxLink('VirusTotal', VT('rich_pe_header_hash:' + M.rich.hash))}</span></div>`);
  else rows.push(fxKv('Rich header', 'none — not built with Microsoft Visual C++ (Go, Delphi, MinGW, Rust or stripped)'));
  for(const p of M.pdb){ const user = (p.path.match(/\\Users\\([^\\]+)\\/i) || p.path.match(/\/home\/([^/]+)\//) || [])[1];
    rows.push(`<div class="kv"><span>PDB path</span><code>${esc(p.path)}</code><span class="pivots inl">${fxLink('Search', 'https://www.google.com/search?q=' + encodeURIComponent('"' + p.path.split(/[\\/]/).slice(-3).join('\\') + '"'))}${fxLink('GitHub', 'https://github.com/search?type=code&q=' + encodeURIComponent('"' + p.path.split(/[\\/]/).pop() + '"'))}</span></div>`);
    if(p.guid) rows.push(fxKv('PDB GUID', p.guid + ' · age ' + p.age, true)); if(user) rows.push(`<div class="fx-note amber">The developer's user name is in the build path: <b>${esc(user)}</b></div>`); }
  const V = M.version; if(Object.keys(V).length) rows.push(`<h5 class="fx-g">What it claims to be</h5>${Object.entries(V).map(([k, v]) => fxKv(k.replace(/([a-z])([A-Z])/g, '$1 $2'), v)).join('')}`);
  if(M.langs && M.langs.length) rows.push(fxKv('Resource language', M.langs.map(l => FX_LANG[l] || l).join(', ')));
  if(M.exportName || (M.exports && M.exports.length)) rows.push(`<h5 class="fx-g">Exports</h5>${fxKv('Internal name', M.exportName, true)}${M.exports && M.exports.length ? `<div class="wrap">${M.exports.slice(0, 40).map(e => `<code class="chip sq">${esc(e)}</code>`).join('')}${M.exports.length > 40 ? `<span class="t3">+${M.exports.length - 40}</span>` : ''}</div>` : ''}`);
  if(M.rich && M.rich.ents.length) rows.push(`<details class="more"><summary>Rich header: ${M.rich.ents.length} toolchain entries</summary><table class="tbl secs"><thead><tr><th>Product</th><th>Build</th><th>Objects</th></tr></thead><tbody>${M.rich.ents.map(e => `<tr><td>0x${e.prod.toString(16)}${FX_RICH_PROD[e.prod] ? ' · ' + FX_RICH_PROD[e.prod] : ''}</td><td>${e.build}</td><td>${e.count}</td></tr>`).join('')}</tbody></table></details>`);
  const flags = [];
  if(M.tsNote) flags.push(['amber', 'Compile time ' + M.tsNote]);
  if(M.overlay) flags.push(['amber', `${fmtBytes(M.overlay.size)} of data after the last section (overlay) at 0x${M.overlay.off.toString(16)} — installers keep archives there; droppers keep payloads. Starts: ${M.overlay.head}`]);
  if(M.tls) flags.push(['amber', 'TLS callbacks — code that runs before the entry point (used by packers and anti-debugging).']);
  if(M.dotnet) flags.push(['', '.NET assembly — decompile with ILSpy or dnSpy for readable source.']);
  if(M.wx.length) flags.push(['red', 'Writable and executable section' + (M.wx.length > 1 ? 's' : '') + ': ' + M.wx.join(', ') + ' — self-modifying or unpacking code.']);
  if(M.empty.length) flags.push(['amber', 'Sections with no data on disk but space in memory: ' + M.empty.join(', ') + ' — filled at run time (packed).']);
  if(sig) flags.push([sig.ok ? '' : 'amber', sig.t]);
  return `<section class="card"><header><h3>${ico('fingerprint','sm')} Build fingerprints</h3></header><div class="body">${rows.join('')}${flags.map(([t, x]) => `<div class="fx-note ${t}">${esc(x)}</div>`).join('')}
    <p class="t3 small" style="margin:8px 0 0">Imphash and the Rich header survive recompiling small changes; samples from one builder or one project usually share them. The PDB path and version strings come from the developer's machine.</p></div></section>`;
}
function fxElfCard(E){
  if(!E) return ''; const rows = [];
  if(E.needed.length) rows.push(`<div class="kv"><span>Libraries</span><span class="wrap">${E.needed.map(n => `<code class="chip sq">${esc(n)}</code>`).join('')}</span></div>`); else rows.push(fxKv('Libraries', 'none — statically linked'));
  rows.push(fxKv('Shared object name', E.soname, true)); rows.push(fxKv('Compiler', E.comment)); rows.push(fxKv('Go version', E.go)); rows.push(fxKv('Go module', E.goPath, true)); rows.push(fxKv('Go build ID', E.goBuild, true)); rows.push(fxKv('GNU build ID', E.buildId, true));
  rows.push(fxKv('Symbols', E.stripped ? 'stripped' : 'present — function names are readable'));
  if(E.sections.length) rows.push(`<details class="more"><summary>${E.sections.length} sections</summary><code style="white-space:normal">${esc(E.sections.join(' '))}</code></details>`);
  return `<section class="card"><header><h3>${ico('fingerprint','sm')} Linux program details</h3></header><div class="body">${rows.join('')}</div></section>`;
}
function fxZipCard(Z){
  if(!Z) return ''; const d = t => new Date(t).toISOString().replace('T', ' ').slice(0, 16) + ' UTC', rows = [];
  rows.push(fxKv('Packed on', Z.os.join(', ')));
  if(Z.uids.length) rows.push(fxKv('Unix user : group', Z.uids.slice(0, 6).join(', ') + (Z.uids.includes('0:0') ? ' (root)' : '')));
  if(Z.tz) rows.push(`<div class="kv"><span>Packer's time zone</span><b>${esc(Z.tz.txt)}</b><span class="t3">from ${Z.tz.n} of ${Z.tz.of} entries — local times stored next to UTC times</span></div>`);
  if(Z.first) rows.push(fxKv('Files last changed', Z.first === Z.last ? d(Z.first) : d(Z.first) + ' to ' + d(Z.last)));
  if(Z.mac) rows.push(`<div class="fx-note">Made with macOS Finder (__MACOSX or .DS_Store inside).</div>`);
  if(Z.thumbs) rows.push(`<div class="fx-note">Windows Explorer leftovers inside (Thumbs.db or desktop.ini).</div>`);
  return `<section class="card"><header><h3>${ico('box','sm')} Who packed it</h3></header><div class="body">${rows.join('')}<p class="t3 small" style="margin:8px 0 0">ZIP keeps the packer's local clock beside a UTC clock when the tool writes both (Info-ZIP, 7-Zip, macOS) — the difference is their time zone.</p></div></section>`;
}
/* ---------- the hex viewer over the whole file ---------- */
const FX_HP = 1024;
function fxHexCard(r){
  const at = Math.max(0, Math.min(r.size - 1, UI.fxHexAt || 0)) & ~15, b = r.bytes.subarray(at, at + FX_HP), L = [];
  for(let o = 0; o < b.length; o += 16){ const row = b.subarray(o, o + 16), hit = UI.fxHexHit; L.push(`<span class="o">${(at + o).toString(16).padStart(8, '0')}</span>  ${[...row].map((x, i) => { const p = at + o + i, h = x.toString(16).padStart(2, '0'); return hit && p >= hit[0] && p < hit[0] + hit[1] ? `<mark>${h}</mark>` : h; }).join(' ').padEnd(47)}  ${esc([...row].map(x => x >= 32 && x < 127 ? String.fromCharCode(x) : '.').join(''))}`); }
  return `<section class="card fx-hex"><header><h3>${ico('binary','sm')} Hex</h3><span class="t3">0x${at.toString(16)} – 0x${Math.min(r.size, at + FX_HP).toString(16)} of 0x${r.size.toString(16)}</span></header>
    <div class="fx-hexbar"><button class="btn xs" data-act="fxHex" data-v="0" ${at === 0 ? 'disabled' : ''}>Start</button><button class="btn xs" data-act="fxHex" data-v="${Math.max(0, at - FX_HP)}" ${at === 0 ? 'disabled' : ''}>${ico('chevron-left','sm')}Back</button><button class="btn xs" data-act="fxHex" data-v="${at + FX_HP}" ${at + FX_HP >= r.size ? 'disabled' : ''}>Next${ico('chevron-right','sm')}</button>
      <label class="sr" for="fxHexGo">Go to offset</label><input id="fxHexGo" class="inp xs mono" placeholder="offset, e.g. 0x4c0" value="">
      <label class="sr" for="fxHexFind">Find</label><input id="fxHexFind" class="inp xs" placeholder="find text or hex (4d 5a)" value="${esc(UI.fxHexQ || '')}"><button class="btn xs" data-act="fxHexFind">${ico('search','sm')}Find next</button><span class="t3 small" id="fxHexMsg">${esc(UI.fxHexMsg || '')}</span></div>
    <pre class="hexd">${L.join('\n')}</pre></section>`;
}
function fxHexFind(r, q, from){
  q = String(q || '').trim(); if(!q) return null; let pat;
  if(/^(?:[0-9a-f]{2}\s*){2,}$/i.test(q)) pat = q.replace(/\s+/g, '').match(/../g).map(h => parseInt(h, 16)); else pat = [...new TextEncoder().encode(q)];
  const b = r.bytes, n = pat.length, lower = !/^(?:[0-9a-f]{2}\s*){2,}$/i.test(q), lc = x => lower && x >= 65 && x <= 90 ? x + 32 : x, P = pat.map(lc);
  for(const start of [from, 0]) for(let i = start; i + n <= b.length; i++){ if(lc(b[i]) !== P[0]) continue; let k = 1; while(k < n && lc(b[i + k]) === P[k]) k++; if(k === n) return [i, n]; if(start === 0 && i >= from) break; }
  return null;
}
const FX_ACTS = {
  fxMetaAll:() => { UI.fxMetaAll = !UI.fxMetaAll; renderMain(); },
  fxHex:(id, v) => { UI.fxHexAt = +v || 0; renderMain(); },
  fxHexFind:() => { const r = UI.labFile; if(!r || !r.bytes) return; const q = ($('fxHexFind') || {}).value || ''; UI.fxHexQ = q; const from = UI.fxHexHit ? UI.fxHexHit[0] + 1 : 0, h = fxHexFind(r, q, from);
    if(!h){ UI.fxHexHit = null; UI.fxHexMsg = 'Not found'; } else { UI.fxHexHit = h; UI.fxHexAt = h[0] & ~15; UI.fxHexMsg = 'Found at 0x' + h[0].toString(16); } renderMain(); },
  fxStrK:(id, v) => { UI.fxStrK = UI.fxStrK === v ? '' : v; renderMain(); },
  fxB64:(id, v) => { UI.decIn = v; UI.txOp = 'auto'; go('#/decoder'); },
  fxZipOpen:async (id, v) => { const r = UI.labFile; if(!r || !r.bytes) return; try{ const u = await fxZipEntry(r.bytes, v); if(!u) return toast('Could not take that file out (encrypted or an unusual compression)'); const f = new File([u], v.split('/').pop() || 'entry', {lastModified:Date.now()}); UI.fxParent = r.name; labLoad(f, false); }catch(e){ toast('Could not take that file out: ' + e.message); } },
  imgZoom:(id, v) => { UI.imgZoom = v; const c = $('imgCv'); if(c) fxApplyZoom(c); document.querySelectorAll('[data-act=imgZoom]').forEach(b => b.setAttribute('aria-pressed', b.dataset.v === v)); },
};
function fxApplyZoom(c){ const z = UI.imgZoom || 'fit'; c.style.width = z === 'fit' ? '' : (c.width * +z) + 'px'; c.style.maxWidth = z === 'fit' ? '' : 'none'; c.style.imageRendering = z === 'fit' || +z < 2 ? '' : 'pixelated'; c.closest('.imgcanvas') && c.closest('.imgcanvas').classList.toggle('zoomed', z !== 'fit'); }

/* ---------- the date inside an ID: account ages and post times from the identifier itself ---------- */
const DC_EPOCH = 1420070400000;
const dcCreated = id => /^\d{15,20}$/.test(String(id || '')) ? Number(BigInt(id) >> 22n) + DC_EPOCH : null;
/* only what is unambiguous: a Discord ID is a Discord snowflake; a URL names its platform */
function idWhen(k, v){
  if(k === 'dcid'){ const t = dcCreated(v); return t ? {t, what:'Discord account created'} : null; }
  if(k !== 'url' || typeof decodeIds !== 'function') return null;
  const R = decodeIds(v).filter(x => x[2] === 'from URL' && isFinite(x[1])); if(R.length !== 1) return null;
  return {t:R[0][1], what:/Discord account/.test(R[0][0]) ? 'Discord account or server created' : 'Posted (' + R[0][0].replace(/ \(.*\)$/, '').replace(/ \(snowflake\)/, '') + ')'};
}
const fxAgo = ms => { const d = Math.abs(ms) / 864e5; return d < 1 ? Math.round(Math.abs(ms) / 36e5) + ' hours' : d < 60 ? Math.round(d) + ' days' : d < 730 ? Math.round(d / 30.4) + ' months' : (d / 365.25).toFixed(1) + ' years'; };
function idWhenHtml(k, v){
  const W = idWhen(k, v); if(!W) return ''; const first = k === 'dcid' ? DB.records.filter(r => r.chatAuthor && r.chatAuthor.app === 'Discord' && r.chatAuthor.id === v).map(r => r.chatAuthor.first).sort((a, b) => a - b)[0] : null;
  const gap = first != null ? first - W.t : null, fresh = gap != null && gap >= 0 && gap < 30 * 864e5;
  if(k === 'dcid' && gap == null) return '';   // the creation date itself is in the profile above
  return `<div class="isec"><h4>${esc(W.what)} <span class="t3">read from the ID itself</span></h4><p style="margin:0"><b>${esc(E.fmtFull(W.t, tz()))}</b> <span class="t3">· ${fxAgo(Date.now() - W.t)} ago</span></p>
    ${gap != null ? `<p class="${fresh ? '' : 't3 '}small" style="margin:4px 0 0">${fresh ? `<b style="color:var(--amber)">Made ${fxAgo(gap)} before its first message in your exports</b> — a fresh account, typical of throwaways and scam accounts.` : `First message in your exports came ${fxAgo(gap)} after the account was made.`}</p>` : ''}</div>`;
}
/* chat authors whose Discord account was made shortly before they first posted */
function cnFresh(caseId, days = 30){
  const out = []; for(const r of DB.records){ const A = r.chatAuthor; if(r.caseId !== caseId || !A || A.app !== 'Discord' || !A.id) continue; const t = dcCreated(A.id); if(!t) continue; const gap = A.first - t; if(gap >= 0 && gap <= days * 864e5) out.push({r, A, t, gap}); }
  return out.sort((a, b) => a.gap - b.gap);
}

/* ---------- favicon and page fingerprints, for Shodan / FOFA / ZoomEye / Censys / urlscan pivots ---------- */
/* MurmurHash3 x86 32-bit, seed 0, signed — what Shodan's http.favicon.hash and http.html_hash use */
function mmh3(bytes){
  let h = 0, i = 0; const n = bytes.length, c1 = 0xcc9e2d51, c2 = 0x1b873593;
  for(; i + 4 <= n; i += 4){ let k = bytes[i] | (bytes[i + 1] << 8) | (bytes[i + 2] << 16) | (bytes[i + 3] << 24); k = Math.imul(k, c1); k = (k << 15) | (k >>> 17); k = Math.imul(k, c2); h ^= k; h = (h << 13) | (h >>> 19); h = (Math.imul(h, 5) + 0xe6546b64) | 0; }
  let k = 0; switch(n & 3){ case 3: k ^= bytes[i + 2] << 16; case 2: k ^= bytes[i + 1] << 8; case 1: k ^= bytes[i]; k = Math.imul(k, c1); k = (k << 15) | (k >>> 17); k = Math.imul(k, c2); h ^= k; }
  h ^= n; h ^= h >>> 16; h = Math.imul(h, 0x85ebca6b); h ^= h >>> 13; h = Math.imul(h, 0xc2b2ae35); h ^= h >>> 16; return h | 0;
}
/* Python's base64.encodebytes: lines of 76 characters, each ending in a newline — Shodan hashes that text, not the raw bytes */
function b64Lines(bytes){ let s = ''; for(let i = 0; i < bytes.length; i += 8192) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 8192)); const b = btoa(s); let out = ''; for(let i = 0; i < b.length; i += 76) out += b.slice(i, i + 76) + '\n'; return out; }
async function fxFavicon(bytes){
  const sha = crypto.subtle ? hex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), 64) : '';
  return {kind:'favicon', size:bytes.length, mmh3:mmh3(new TextEncoder().encode(b64Lines(bytes))), md5:md5(bytes), sha256:sha};
}
/* a saved page: its own hash, and the IDs and links that tie it to other sites of the same owner */
/* <link rel="icon"> addresses, honouring whichever quote opens each attribute (a data: URL may hold the other one) */
function fxLinkIcons(text){ const out = [];
  for(const m of text.matchAll(/<link\b(?:"[^"]*"|'[^']*'|[^'">])*>/gi)){ const t = m[0], at = n => { const x = new RegExp('\\s' + n + '\\s*=\\s*(?:"([^"]*)"|\'([^\']*)\'|([^\\s>]+))', 'i').exec(t); return x ? (x[1] ?? x[2] ?? x[3] ?? '') : ''; };
    if(/\bicon\b/i.test(at('rel'))){ const h = at('href').trim(); if(h && !out.includes(h)) out.push(h); } }
  return out; }
async function fxPage(text){
  const bytes = new TextEncoder().encode(text), sha = crypto.subtle ? hex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), 64) : '', uniq = a => [...new Set(a)];
  const all = (re, g = 1) => uniq([...text.matchAll(re)].map(m => m[g]));
  const title = ((text.match(/<title[^>]*>([\s\S]{0,300}?)<\/title>/i) || [])[1] || '').replace(/\s+/g, ' ').trim();
  const P = {kind:'page', size:bytes.length, mmh3:mmh3(bytes), md5:md5(bytes), sha256:sha, title,
    ga:all(/\b(UA-\d{4,10}-\d{1,4})\b/g), ga4:all(/\b(G-[A-Z0-9]{8,12})\b/g), gtm:all(/\b(GTM-[A-Z0-9]{5,9})\b/g), aw:all(/\b(AW-\d{8,12})\b/g), adsense:all(/\b(ca-pub-\d{10,20}|pub-\d{10,20})\b/g).map(x => x.replace(/^ca-/, '')),
    ym:all(/\bym\(\s*(\d{6,10})\s*,\s*['"]init/g), fbp:all(/fbq\(\s*['"]init['"]\s*,\s*['"](\d{12,20})['"]/g), hj:all(/\bhjid\s*:\s*(\d{5,10})/g),
    favicons:fxLinkIcons(text),
    scripts:all(/<script[^>]+src=["']([^"']+)["']/gi), forms:all(/<form[^>]+action=["']([^"']+)["']/gi), passwords:(text.match(/type=["']password["']/gi) || []).length,
    comments:uniq([...text.matchAll(/<!--([\s\S]{3,200}?)-->/g)].map(m => m[1].trim()).filter(c => !/^\[if |^\s*$|^saved from url=/i.test(c))).slice(0, 12),   // the browser's own "saved from" note can carry a local path: never a comment, never a query
    libs:uniq([...text.matchAll(/(jquery|bootstrap|vue|react|angular|lodash|font-?awesome)[.-]?(\d+\.\d+(?:\.\d+)?)/gi)].map(m => m[1].toLowerCase() + ' ' + m[2])),
    tg:all(/\bt(?:elegram)?\.me\/([A-Za-z][\w]{3,31})/g), ents:typeof E !== 'undefined' ? E.extract(text.slice(0, 400000)).filter(e => /^(btc|eth|xmr|trx|sol|ltc|email|onion|phone)$/.test(e.k)) : []};
  P.st = fxStatic(text);
  /* a favicon written into the page (data: URL) is hashed the way Shodan hashes favicons */
  const inl = P.favicons.find(f => /^data:image\//i.test(f));
  if(inl){ const m = /^data:([^;,]+)(;base64)?,(.*)$/is.exec(inl.trim()); if(m){ let b = null; try{ b = m[2] ? Uint8Array.from(atob(m[3].replace(/\s+/g, '')), c => c.charCodeAt(0)) : new TextEncoder().encode(decodeURIComponent(m[3])); }catch(e){ b = null; }
    if(b && b.length){ const F = await fxFavicon(b); P.favInline = {mime:m[1].toLowerCase(), size:b.length, mmh3:F.mmh3, md5:F.md5, src:inl.length < 200000 ? inl : ''}; } } }
  return P;
}
/* a saved page read as it stands — no network log, so this is what the HTML and its scripts would load, call and send.
   Every address is resolved against where the page was saved from, and sorted into what it is (WC_SVC from web captures). */
function fxStatic(text){
  const T = text.slice(0, 4e6), uniq = a => [...new Set(a)];
  const from = ((/<!--\s*saved from url=\(\d+\)(\S+)\s*-->/i.exec(T) || [])[1] || (/<base[^>]+href=["']([^"']+)/i.exec(T) || [])[1] || (/<link[^>]+rel=["']canonical["'][^>]*href=["']([^"']+)/i.exec(T) || [])[1] || (/<meta[^>]+property=["']og:url["'][^>]*content=["']([^"']+)/i.exec(T) || [])[1] || '').trim();
  const base = /^https?:\/\//i.test(from) ? from : '', host0 = base ? (() => { try{ return new URL(base).hostname.toLowerCase(); }catch(e){ return ''; } })() : '';
  const reg = h => typeof regDomain === 'function' ? regDomain(h) : h, svc = h => typeof wcSvc === 'function' ? wcSvc(h) : null;
  const mask = s => typeof wcMaskHook === 'function' ? wcMaskHook(wcMaskTg(s)) : String(s).replace(/(\d{6,12}):([A-Za-z0-9_-]{30,40})/g, (m, id, sec) => id + ':' + sec.slice(0, 3) + '•••• (token hidden)');
  const abs = u => { u = String(u || '').trim().replace(/&amp;/g, '&'); if(!u || /^(#|javascript:|mailto:|tel:|data:|blob:|about:)/i.test(u)) return null;
    if(/_files\//.test(u) && !/^(https?:)?\/\//i.test(u)) return {u, h:'', local:true};   // saved next to the page ("Webpage, complete")
    if(/^\/\//.test(u)) u = 'https:' + u; if(/^https?:\/\//i.test(u)) return {u, h:(() => { try{ return new URL(u).hostname.toLowerCase(); }catch(e){ return ''; } })()};
    if(base){ try{ const x = new URL(u, base); return {u:x.href, h:x.hostname.toLowerCase()}; }catch(e){} } return {u, h:'', local:true}; };
  const hosts = new Map(), add = (raw, what) => { const a = abs(raw); if(!a || a.local || !a.h) return a; const H = hosts.get(a.h) || {h:a.h, what:new Set(), n:0, svc:svc(a.h), third:host0 ? reg(a.h) !== reg(host0) : true}; H.what.add(what); H.n++; hosts.set(a.h, H); return a; };
  const local = [];
  for(const m of T.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)){ const a = add(m[1], 'scripts'); if(a && a.local) local.push(a.u); }
  for(const m of T.matchAll(/<link[^>]+>/gi)){ const href = (/href=["']([^"']+)["']/i.exec(m[0]) || [])[1], rel = ((/rel=["']([^"']+)["']/i.exec(m[0]) || [])[1] || '').toLowerCase(); if(!href) continue;
    const a = add(href, /stylesheet/.test(rel) ? 'styles' : /icon/.test(rel) ? 'icons' : /preconnect|dns-prefetch|preload|prefetch/.test(rel) ? 'preloads' : 'links'); if(a && a.local && /stylesheet/.test(rel)) local.push(a.u); }
  for(const m of T.matchAll(/<(?:img|source|video|audio)[^>]+src=["']([^"']+)["']/gi)) add(m[1], 'images & media');
  const frames = uniq([...T.matchAll(/<i?frame[^>]+src=["']([^"']+)["']/gi)].map(m => { const a = add(m[1], 'frames'); return a ? a.u : ''; }).filter(Boolean));
  for(const m of T.matchAll(/url\(\s*["']?(https?:\/\/[^"')\s]+)/gi)) add(m[1], 'styles');
  let linksOut = 0; for(const m of T.matchAll(/<a[^>]+href=["'](https?:\/\/[^"']+)["']/gi)){ const a = abs(m[1]); if(a && a.h && (!host0 || reg(a.h) !== reg(host0))){ linksOut++; add(m[1], 'links'); } }
  /* what the page's scripts call: fetch, XHR, sendBeacon, WebSocket, jQuery and axios, and bare API addresses in strings */
  const calls = [], call = (method, u, how) => { const a = add(u, 'calls'); if(!a) return; const k = method + ' ' + a.u; if(calls.some(c => c.k === k)) return; const H = a.h ? hosts.get(a.h) : null; calls.push({k, method, url:mask(a.u), host:a.h, how, svc:H ? H.svc : null, third:H ? H.third : false}); };
  for(const m of T.matchAll(/\bfetch\(\s*["'`]([^"'`]+)["'`]\s*(?:,\s*\{[^}]{0,200}?method\s*:\s*["'`](\w+))?/gi)) call((m[2] || 'GET').toUpperCase(), m[1], 'fetch');
  for(const m of T.matchAll(/\.open\(\s*["'](GET|POST|PUT|PATCH|DELETE)["']\s*,\s*["'`]([^"'`]+)["'`]/gi)) call(m[1].toUpperCase(), m[2], 'XMLHttpRequest');
  for(const m of T.matchAll(/sendBeacon\(\s*["'`]([^"'`]+)["'`]/gi)) call('POST', m[1], 'sendBeacon');
  for(const m of T.matchAll(/new\s+WebSocket\(\s*["'`]([^"'`]+)["'`]/gi)) call('WS', m[1], 'WebSocket');
  for(const m of T.matchAll(/\$\.(post|get|ajax|getJSON)\(\s*["'`]([^"'`]+)["'`]/gi)) call(/post/i.test(m[1]) ? 'POST' : 'GET', m[2], 'jQuery');
  for(const m of T.matchAll(/\$\.ajax\(\s*\{[^}]{0,300}?url\s*:\s*["'`]([^"'`]+)["'`][^}]{0,300}?(?:type|method)\s*:\s*["'`](\w+)/gi)) call(m[2].toUpperCase(), m[1], 'jQuery');
  for(const m of T.matchAll(/axios(?:\.(get|post|put))?\(\s*["'`]([^"'`]+)["'`]/gi)) call((m[1] || 'GET').toUpperCase(), m[2], 'axios');
  for(const m of T.matchAll(/["'`](https?:\/\/(?:api\.telegram\.org\/bot[^"'`\s]+|(?:discord|discordapp)\.com\/api\/webhooks\/[^"'`\s]+|script\.google\.com\/macros\/[^"'`\s]+|hooks\.slack\.com\/[^"'`\s]+))["'`]/gi)) call('POST', m[1], 'address in a script');
  /* forms: where each sends, how, and what it asks for */
  const S = typeof WC_SECRET !== 'undefined' ? WC_SECRET : /pass|pwd|secret|otp|cvv|cvc|card|ssn|pin/i, U = typeof WC_USER !== 'undefined' ? WC_USER : /user|login|email|mail|phone/i;
  const forms = [];
  for(const m of T.matchAll(/<form\b([^>]*)>([\s\S]{0,60000}?)<\/form>/gi)){
    const act = (/action=["']([^"']*)["']/i.exec(m[1]) || [])[1], meth = ((/method=["']?(\w+)/i.exec(m[1]) || [])[1] || 'GET').toUpperCase();
    const fields = [...m[2].matchAll(/<(input|textarea|select)\b([^>]*)>/gi)].map(x => { const n = (/name=["']?([^"'\s>]+)/i.exec(x[2]) || [])[1] || (/id=["']?([^"'\s>]+)/i.exec(x[2]) || [])[1] || '', ty = ((/type=["']?(\w+)/i.exec(x[2]) || [])[1] || (x[1].toLowerCase() === 'input' ? 'text' : x[1].toLowerCase())).toLowerCase();
      return {n, ty, secret:ty === 'password' || S.test(n) || /seed|mnemonic|phrase|private.?key|recovery/i.test(n), user:ty === 'email' || U.test(n)}; }).filter(f => !/^(submit|button|reset|image|hidden)$/.test(f.ty) && (f.n || f.ty === 'password'));
    const a = act ? abs(act) : null; if(a && a.h){ const H = hosts.get(a.h) || {h:a.h, what:new Set(), n:0, svc:svc(a.h), third:host0 ? reg(a.h) !== reg(host0) : true}; H.what.add('form'); H.n++; hosts.set(a.h, H); }
    forms.push({to:a ? mask(a.u) : act === undefined || act === '' ? '(this same page)' : act, host:a ? a.h : '', method:meth, fields, third:a && a.h ? hosts.get(a.h).third : false, svc:a && a.h ? hosts.get(a.h).svc : null}); if(forms.length >= 12) break; }
  /* redirects written into the page */
  const redirects = []; const mr = /<meta[^>]+http-equiv=["']?refresh["']?[^>]+content=["']([^"']*)["']/i.exec(T); if(mr){ const u = (/url\s*=\s*['"]?([^'";]+)/i.exec(mr[1]) || [])[1]; if(u) redirects.push({how:'meta refresh after ' + (parseInt(mr[1], 10) || 0) + ' s', to:mask((abs(u) || {u}).u)}); }
  for(const m of T.matchAll(/(?:window\.|document\.|top\.|self\.)?location(?:\.href)?\s*=\s*["'`]([^"'`]+)["'`]|location\.(?:replace|assign)\(\s*["'`]([^"'`]+)["'`]/g)){ const u = m[1] || m[2]; if(redirects.length < 6 && !redirects.some(r => r.to === u)) redirects.push({how:'script', to:mask((abs(u) || {u}).u)}); }
  /* what stands out */
  const flags = [], hv = [...hosts.values()];
  const credForms = forms.filter(f => f.fields.some(x => x.secret));
  for(const f of credForms){ const off = f.third && f.host; const what = uniq(f.fields.filter(x => x.secret).map(x => /card|cc|cvv|cvc/i.test(x.n) ? 'card details' : /seed|mnemonic|phrase|private.?key|recovery/i.test(x.n) ? 'a wallet recovery phrase' : /otp|2fa|mfa|code$|pin/i.test(x.n) && x.ty !== 'password' ? 'a one-time code or PIN' : 'a password'));
    flags.push([off || (f.svc && /drop/.test(f.svc.k)) ? 'red' : 'amber', `A form asks for ${what.join(' and ')}${off ? ' and sends what is typed to another site: ' + f.host : f.host ? ' and sends what is typed to ' + f.host : ''}${f.svc ? ' (' + f.svc.l + ')' : ''}.`]); }
  for(const c of calls.filter(c => c.svc && /drop/.test(c.svc.k))) flags.push(['red', `A script sends to a ${c.svc.l} (${c.host}) — kits use these to receive what victims type.`]);
  const geo = hv.filter(H => H.svc && H.svc.k === 'geo'); if(geo.length) flags.push(['amber', `The page looks up the visitor's IP and location (${geo.map(H => H.h).join(', ')}) — kits do this to hide from researchers and other countries.`]);
  const anti = []; if(/oncontextmenu\s*=\s*["']?\s*return\s+false|addEventListener\(\s*["']contextmenu["'][^)]*\)[\s\S]{0,80}?preventDefault/i.test(T)) anti.push('right-click blocked');
  if(/keyCode\s*={2,3}\s*123|key\s*={2,3}\s*["']F12["']/i.test(T)) anti.push('F12 blocked'); if(/devtools|setInterval\([^)]{0,80}debugger|\bdebugger\s*;[\s\S]{0,40}\}\s*,\s*\d+/i.test(T)) anti.push('developer tools detected');
  if(/navigator\.webdriver|headless|phantom|selenium/i.test(T)) anti.push('automated browsers detected'); if(/(bot|crawl|spider|slurp)[|\\]/i.test(T) && /userAgent/.test(T)) anti.push('bots and crawlers turned away');
  if(anti.length) flags.push(['amber', 'Anti-analysis: ' + anti.join(', ') + '.']);
  const obf = []; if(/eval\s*\(\s*(?:atob|unescape|decodeURIComponent)\s*\(/i.test(T)) obf.push('eval of decoded text'); if(/eval\(function\(p,a,c,k,e,[rd]\)/.test(T)) obf.push('packed script (p,a,c,k,e,d)');
  if(/document\.write\s*\(\s*(?:unescape|atob|decodeURIComponent)\s*\(/i.test(T)) obf.push('page written from encoded text'); if((T.match(/String\.fromCharCode\(/g) || []).length > 5) obf.push('text built from character codes');
  if(/["'`][A-Za-z0-9+/]{3000,}={0,2}["'`]/.test(T)) obf.push('a large base64 blob'); if(/_0x[0-9a-f]{4,6}\b[\s\S]{0,400}_0x[0-9a-f]{4,6}\b/.test(T)) obf.push('obfuscator.io style names');
  if(obf.length) flags.push(['amber', 'Hidden code: ' + obf.join(', ') + '.']);
  if(frames.length) flags.push(['', `${frames.length} frame${frames.length > 1 ? 's' : ''} load${frames.length > 1 ? '' : 's'} another page inside this one: ${frames.slice(0, 3).map(u => typeof wcHost === 'function' ? wcHost(u) || u : u).join(', ')}.`]);
  const order = H => (H.svc && /drop/.test(H.svc.k) ? 0 : H.what.has('form') || H.what.has('calls') ? 1 : H.svc && H.svc.k === 'geo' ? 2 : H.third ? 3 : 4);
  return {from, host:host0, hosts:hv.sort((a, b) => order(a) - order(b) || b.n - a.n), calls:calls.slice(0, 30), forms, redirects, frames, flags, linksOut, local:uniq(local).slice(0, 60)};
}
/* the page card: what stands out, where it sends data, every site it talks to, redirects, the favicon, scripts and details */
function fxSendsCard(R){
  const S = R.st || {hosts:[], calls:[], forms:[], redirects:[], frames:[], flags:[], local:[]}, kv = (k, v) => v ? `<div class="kv"><span>${k}</span><span>${v}</span></div>` : '';
  const svcTag = x => x && x.svc ? `<span class="chip sq${/drop/.test(x.svc.k) ? ' red' : x.svc.k === 'geo' ? ' amber' : ''}">${esc(x.svc.l)}</span>` : '';
  const flags = S.flags.length ? `<div class="fxs-flags">${S.flags.map(([c, t]) => `<div class="fx-note${c ? ' ' + c : ''}">${esc(t)}</div>`).join('')}</div>` : '';
  const forms = S.forms.length ? `<h4 class="fxs-h">Forms${R.passwords ? ` <span class="t3">· ${R.passwords} password field${R.passwords > 1 ? 's' : ''}</span>` : ''}</h4>${S.forms.map(f => `<div class="fxs-form"><div><b class="mono">${esc(f.method)}</b> <code>${esc(f.to)}</code> ${f.third ? '<span class="chip sq amber">another site</span>' : ''}${svcTag(f)}</div>
      ${f.fields.length ? `<div class="fxs-fields">${f.fields.slice(0, 16).map(x => `<span class="chip sq${x.secret ? ' red' : ''}" title="${esc(x.ty)}">${esc(x.n || x.ty)}</span>`).join('')}${f.fields.length > 16 ? `<span class="t3 small">+${f.fields.length - 16}</span>` : ''}</div>` : '<div class="t3 small">No fields with names.</div>'}</div>`).join('')}` : '';
  const calls = S.calls.length ? `<h4 class="fxs-h">Calls in its scripts</h4><table class="tbl fxs-t"><tbody>${S.calls.map(c => `<tr><td class="mono nw">${esc(c.method)}</td><td><code>${esc(c.url.length > 140 ? c.url.slice(0, 138) + '…' : c.url)}</code> ${svcTag(c)}</td><td class="t3 nw small">${esc(c.how)}</td></tr>`).join('')}</tbody></table>` : '';
  const hosts = S.hosts.length ? `<h4 class="fxs-h">Sites it talks to <span class="t3">${S.hosts.length}${S.host ? ' · saved from ' + esc(S.host) : ''}</span></h4><table class="tbl fxs-t"><tbody>${S.hosts.slice(0, 40).map(H => `<tr><td class="mono">${esc(H.h)}${H.third ? '' : ' <span class="t3 small">same site</span>'}</td><td class="t2 small">${esc([...H.what].join(', '))}</td><td>${svcTag(H)}</td></tr>`).join('')}</tbody></table>${S.hosts.length > 40 ? `<p class="t3 small">and ${S.hosts.length - 40} more</p>` : ''}` : '';
  const redir = S.redirects.length ? kv('Redirects', S.redirects.map(r => `<code>${esc(r.to)}</code> <span class="t3 small">${esc(r.how)}</span>`).join('<br>')) : '';
  const fi = R.favInline, favs = R.favicons.filter(f => !/^data:/i.test(f));
  const fav = fi ? kv('Favicon', `<span class="fxs-fav">${fi.src ? `<img src="${esc(fi.src)}" alt="" width="32" height="32">` : ''}<span>Inside the page (${esc(fi.mime)}, ${fi.size.toLocaleString()} bytes) · Shodan hash <code>${esc(String(fi.mmh3))}</code> · MD5 <code>${esc(fi.md5)}</code></span></span>`) : favs.length ? kv('Favicon', favs.slice(0, 4).map(f => `<code>${esc(f)}</code>`).join('<br>')) : '';
  const remote = R.scripts.filter(u => /^(https?:)?\/\//i.test(u)), loc = R.scripts.filter(u => !/^(https?:)?\/\//i.test(u));
  const scripts = R.scripts.length ? kv('Scripts', (remote.length ? remote.slice(0, 12).map(x => `<code>${esc(x)}</code>`).join('<br>') : '') + (loc.length ? `${remote.length ? '<br>' : ''}<details class="fxs-loc"><summary>${loc.length} saved with the page</summary>${loc.slice(0, 40).map(x => `<code>${esc(x.split('/').pop())}</code>`).join('<br>')}</details>` : '')) : '';
  const rest = kv('Libraries', R.libs.length ? `<b>${esc(R.libs.join(', '))}</b>` : '') + kv('Comments', R.comments.map(c => `<code>${esc(c)}</code>`).join('<br>')) + kv('Telegram', R.tg.length ? `<b>${R.tg.map(t => '@' + esc(t)).join(', ')}</b>` : '')
    + kv('Payment & contact', R.ents.length ? `<span class="wrap">${R.ents.map(e => `<span class="ent">${kindBadge(e.k)}<span class="v">${esc(e.v)}</span></span>`).join('')}</span>` : '') + kv('Links out', S.linksOut ? `${S.linksOut} link${S.linksOut > 1 ? 's' : ''} to other sites` : '');
  const body = flags + forms + calls + hosts + redir + fav + scripts + rest;
  return `<section class="card"><header><h3>${ico('code','sm')} What the page loads and sends</h3>${S.from ? `<span class="t3 mono small" title="Where the page was saved from">${esc(S.from.length > 60 ? S.from.slice(0, 58) + '…' : S.from)}</span>` : ''}</header><div class="body fxs">
    ${body || `<p class="t2" style="margin:0">Nothing to report: no forms, no calls in its scripts, and no other sites, redirects or contact details in this file. A page saved as “Webpage, HTML only” leaves out what it would load later — save it as “Webpage, complete” or capture it with a HAR to see more.</p>`}
    <p class="t3 small" style="margin:10px 0 0">Read from the saved file: what the page would load and send when opened. Nothing was opened or run.</p></div></section>`;
}
/* the queries to run with them (the engines' own syntax) */
function fxPivots(R){
  const Q = [], q = (eng, label, query) => { if(typeof engineUrl === 'function' && typeof ENGINES !== 'undefined' && ENGINES[eng]) Q.push([ENGINES[eng][0], label, query, engineUrl(eng, query)]); };
  if(R.kind === 'favicon'){ q('shodan', 'Same favicon', 'http.favicon.hash:' + R.mmh3); q('fofa', 'Same favicon', 'icon_hash="' + R.mmh3 + '"'); q('zoomeye', 'Same favicon', 'iconhash:"' + R.mmh3 + '"'); q('censys', 'Same favicon (MD5)', 'services.http.response.favicons.md5_hash: ' + R.md5); q('urlscan', 'Pages that loaded this icon', 'hash:' + R.sha256); }
  else { q('shodan', 'Same page, byte for byte', 'http.html_hash:' + R.mmh3); q('urlscan', 'Pages that loaded this exact file', 'hash:' + R.sha256); if(R.title){ q('shodan', 'Same title', 'http.title:"' + R.title.replace(/"/g, '') + '"'); q('fofa', 'Same title', 'title="' + R.title.replace(/"/g, '') + '"'); q('urlscan', 'Same title', 'page.title:"' + R.title.replace(/"/g, '') + '"'); }
    for(const id of [...R.ga, ...R.ga4, ...R.gtm, ...R.aw, ...R.adsense].slice(0, 6)){ q('publicwww', 'Sites with ' + id, '"' + id + '"'); q('fofa', 'Sites with ' + id, 'body="' + id + '"'); q('google', 'Pages naming ' + id, '"' + id + '"'); }
    for(const id of R.ym.slice(0, 2)) q('publicwww', 'Sites with Yandex Metrica ' + id, '"' + id + '"'); for(const id of R.fbp.slice(0, 2)) q('publicwww', 'Sites with Meta pixel ' + id, '"' + id + '"');
    for(const c of R.comments.filter(c => c.length >= 8).slice(0, 2)) q('fofa', 'Pages with this comment', 'body="' + c.replace(/"/g, '').slice(0, 80) + '"');
    for(const t of R.tg.slice(0, 3)) q('google', 'Where t.me/' + t + ' is advertised', '"t.me/' + t + '" -site:t.me');
    if(R.favInline){ q('shodan', 'Same favicon', 'http.favicon.hash:' + R.favInline.mmh3); q('fofa', 'Same favicon', 'icon_hash="' + R.favInline.mmh3 + '"'); } }
  return Q;
}
function labFav(){
  const R = UI.fxFav;
  const drop = `<label class="drop" id="favDrop" tabindex="0"><input type="file" id="favIn" class="sr" accept=".ico,.png,.svg,.gif,.jpg,.jpeg,.html,.htm,.mhtml,.txt,image/*,text/html">${ico('scan-search')}<b>Drop a favicon or a saved web page</b>
    <span>A favicon gives the hash Shodan, FOFA and ZoomEye index (and the MD5 Censys uses). A page (Save as → HTML) gives its own hash plus the analytics, ad and pixel IDs that tie sites to one owner — each with the query to run.</span>
    <span class="drop-feat"><i>Shodan favicon hash</i><i>MD5 · SHA-256</i><i>http.html_hash</i><i>Analytics &amp; Tag Manager</i><i>AdSense</i><i>Meta pixel</i><i>Yandex Metrica</i><i>Kit comments</i></span></label>
    <p class="t3 small">The browser cannot fetch another site's favicon for you. Open <span class="mono">https://site/favicon.ico</span> (or the icon named in the page) in your research browser, save it, and drop it here.</p>`;
  if(!R) return drop;
  const piv = fxPivots(R), row = (l, v) => v || v === 0 ? `<div class="kv"><span>${esc(l)}</span><code>${esc(String(v))}</code><button class="iconbtn" data-act="flagCopy" data-v="${esc(String(v))}" aria-label="Copy ${esc(l)}">${ico('copy','sm')}</button></div>` : '';
  const ids = R.kind === 'page' ? [['Google Analytics (UA)', R.ga], ['Google Analytics 4', R.ga4], ['Google Tag Manager', R.gtm], ['Google Ads', R.aw], ['AdSense publisher', R.adsense], ['Yandex Metrica', R.ym], ['Meta pixel', R.fbp], ['Hotjar', R.hj]].filter(x => x[1].length) : [];
  return `<div class="fi-grid"><div class="fi-side">
    <section class="card"><header><span class="fi-ic">${ico(R.kind === 'favicon' ? 'image' : 'file-code')}</span><div style="min-width:0;flex:1"><h3>${esc(R.name)}</h3><p class="t3">${R.kind === 'favicon' ? 'Favicon' : 'Web page'} · ${fmtBytes(R.size)}</p></div><button class="btn sm" data-act="favClear">${ico('x','sm')}Another</button></header><div class="body">
      ${R.kind === 'favicon' ? row('Shodan / FOFA hash (mmh3)', R.mmh3) + row('MD5 (Censys)', R.md5) + row('SHA-256 (urlscan)', R.sha256) : row('Page hash (Shodan http.html_hash)', R.mmh3) + row('SHA-256 (urlscan)', R.sha256) + row('MD5', R.md5) + row('Title', R.title)}
      <div class="wrap" style="margin-top:12px"><button class="btn primary" data-act="favSave">${ico('plus','sm')}Save to ${esc(caseNm(theCase()))}</button>${casePick()}</div></div></section>
    ${ids.length ? `<section class="card"><header><h3>${ico('fingerprint','sm')} Owner IDs in the page</h3></header><div class="body">${ids.map(([l, L]) => `<div class="kv"><span>${esc(l)}</span><span class="wrap">${L.map(x => `<code class="chip sq">${esc(x)}</code>`).join('')}</span></div>`).join('')}<p class="t3 small" style="margin:8px 0 0">One analytics or ad account usually belongs to one owner. The same ID on another site ties the two; an ID shared by thousands of sites belongs to a theme or kit seller.</p></div></section>` : ''}
    ${R.kind === 'page' ? fxSendsCard(R) : ''}
    </div><div class="fi-side"><section class="card"><header><h3>${ico('search','sm')} Find the same elsewhere</h3><span class="t3">${piv.length} queries</span></header><div class="body flush">${piv.map(([e, l, q, u]) => `<a class="li fx-pv" href="${esc(u)}" target="_blank" rel="noopener noreferrer"><div class="main2"><b>${esc(l)} <span class="t3">· ${esc(e)}</span></b><small class="mono">${esc(q)}</small></div>${ico('arrow-up-right','sm')}</a>`).join('')}</div></section>
    <p class="t3 small">Each link opens the engine with the query filled in, from this browser — use your research environment. Matching icons and IDs are leads: kits and templates are shared, so confirm with a second tie (certificate, hosting, registration).</p></div></div>`;
}
async function favLoad(f){
  if(f.size > 20 * 1048576) return toast('That file is over 20 MB');
  const b = new Uint8Array(await f.arrayBuffer()), head = latin1(b, 0, Math.min(b.length, 2000));
  const isPage = /\.(html?|mhtml|txt)$/i.test(f.name) || /<html|<!doctype html|<head|<title/i.test(head);
  UI.fxFav = Object.assign(isPage ? await fxPage(new TextDecoder().decode(b)) : await fxFavicon(b), {name:f.name}); renderMain();
}
function bindFav(){ const inp = $('favIn'), d = $('favDrop'); if(!inp) return; inp.onchange = () => inp.files[0] && favLoad(inp.files[0]);
  d.ondragover = e => { e.preventDefault(); d.classList.add('over'); }; d.ondragleave = () => d.classList.remove('over'); d.ondrop = e => { e.preventDefault(); d.classList.remove('over'); const f = e.dataTransfer.files[0]; if(f) favLoad(f); };
  d.onkeydown = e => { if(e.key === 'Enter' || e.key === ' '){ e.preventDefault(); inp.click(); } }; }
Object.assign(FX_ACTS, {
  favClear:() => { UI.fxFav = null; renderMain(); },
  favSave:() => { const R = UI.fxFav; if(!R) return; const L = R.kind === 'favicon' ? [`Favicon ${R.name}`, `Shodan favicon hash: ${R.mmh3}`, `Favicon MD5: ${R.md5}`, `Favicon SHA-256: ${R.sha256}`]
      : [`Web page ${R.name}${R.title ? ' — ' + R.title : ''}`, `Shodan html_hash: ${R.mmh3}`, `Page SHA-256: ${R.sha256}`, ...[['Google Analytics', R.ga.concat(R.ga4)], ['Tag Manager', R.gtm], ['Google Ads', R.aw], ['AdSense', R.adsense], ['Yandex Metrica', R.ym], ['Meta pixel', R.fbp]].filter(x => x[1].length).map(([l, v]) => l + ': ' + v.join(', ')), ...R.forms.map(f => 'Form sends to: ' + f), ...R.comments.map(c => 'Comment: ' + c)];
    draft.source = 'forensics kit'; openCapture(L.join('\n')); },
});

/* ---------- phishing kits: who it sends the victims' data to, who it imitates, who wrote it ---------- */
const KIT_BRANDS = ['Microsoft', 'Office 365', 'Outlook', 'OneDrive', 'SharePoint', 'Adobe', 'DocuSign', 'Dropbox', 'Google', 'Gmail', 'Apple', 'iCloud', 'PayPal', 'Netflix', 'Amazon', 'DHL', 'FedEx', 'UPS', 'USPS', 'Royal Mail', 'Facebook', 'Instagram', 'WhatsApp', 'LinkedIn', 'Coinbase', 'Binance', 'MetaMask', 'Trust Wallet', 'Ledger', 'Chase', 'Wells Fargo', 'Bank of America', 'Citi', 'HSBC', 'Barclays', 'Santander', 'ING', 'Revolut', 'Webmail', 'cPanel', 'Roundcube', 'Zimbra', 'Yahoo', 'AOL', 'Steam', 'Discord', 'Telegram', 'Okta', 'Citrix', 'Booking.com', 'Airbnb', 'Spotify', 'Venmo', 'Cash App', 'Zelle', 'Interac'];
const KIT_TEXT = /\.(php\d?|phtml|html?|js|json|txt|ini|env|htaccess|css|xml|ya?ml|py|sh|cfg|conf|inc|tpl|md|log|csv)$|(^|\/)\.htaccess$/i;
function fxKitScan(files){
  const R = {files:files.length, text:0, bots:new Map(), chats:new Set(), hooks:new Set(), emails:new Set(), smtp:[], posts:new Set(), logs:new Set(), sheets:new Set(), brands:new Map(), auth:[], block:[], obf:0, obfFiles:[], panels:new Set(), wallets:[], ents:[], titles:new Set(), pass:0, otp:0, card:0, geo:false, ua:0};
  const add = (m, k, f) => { if(!m.has(k)) m.set(k, new Set()); m.get(k).add(f); };
  for(const F of files){ if(!F.text) continue; R.text++; const t = F.text, n = F.name;
    for(const m of t.matchAll(/\b(\d{8,10}):(AA[\w-]{33})\b/g)) add(R.bots, m[1] + ':' + m[2], n);
    for(const m of t.matchAll(/chat_?id['"\]\s]*(?:=>|=|:)\s*['"]?(-?\d{6,16})/gi)) R.chats.add(m[1]);
    for(const m of t.matchAll(/https:\/\/(?:canary\.|ptb\.)?discord(?:app)?\.com\/api\/webhooks\/\d{15,20}\/[\w-]{30,}/g)) R.hooks.add(m[0]);
    for(const m of t.matchAll(/https:\/\/script\.google\.com\/macros\/s\/[\w-]{20,}\/exec|https:\/\/docs\.google\.com\/forms\/[^\s'"<>]+|https:\/\/hooks\.slack\.com\/services\/[\w/]+/g)) R.sheets.add(m[0]);
    /* where the form data goes: mail() recipients, the send-to variables, SMTP accounts */
    for(const m of t.matchAll(/\$(?:to|send|recipient|email_to|mailto|receiver|resultbox|your_email|myemail)\s*=\s*["']([^"'\s]{3,120}@[^"'\s]{3,120})["']/gi)) R.emails.add(m[1].toLowerCase());
    for(const m of t.matchAll(/\bmail\s*\(\s*["']([^"'\s]+@[^"'\s]+)["']/gi)) R.emails.add(m[1].toLowerCase());
    for(const m of t.matchAll(/(?:smtp_?host|->Host)\s*(?:=>|=)\s*["']([\w.-]+\.[a-z]{2,})["'][\s\S]{0,400}?(?:smtp_?user(?:name)?|->Username)\s*(?:=>|=)\s*["']([^"']+)["']/gi)) R.smtp.push(m[1] + ' as ' + m[2]);
    for(const m of t.matchAll(/<form[^>]+action=["']([^"']+)["']/gi)) R.posts.add(m[1]);
    for(const m of t.matchAll(/(?:fopen|file_put_contents)\s*\(\s*["']([^"']{2,80}\.(?:txt|log|html|csv|json))["']/gi)) R.logs.add(m[1]);
    for(const m of t.matchAll(/curl_init\s*\(\s*["'](https?:\/\/[^"']+)["']|CURLOPT_URL\s*,\s*["'](https?:\/\/[^"']+)["']/gi)) R.panels.add(m[1] || m[2]);
    for(const m of t.matchAll(/<title[^>]*>([^<]{2,120})<\/title>/gi)) R.titles.add(m[1].trim());
    for(const b of KIT_BRANDS){ const re = new RegExp('\\b' + b.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/ /g, '\\s?') + '\\b', 'gi'), c = (t.match(re) || []).length; if(c) R.brands.set(b, (R.brands.get(b) || 0) + c); }
    /* who wrote it: credit lines, handles, contact */
    for(const m of t.matchAll(/(?:coded|created|made|written|scam[ae]?|page|kit|script|edited|modified|updated)\s+by\s*[:\-]?\s*@?([\w.\-]{3,32})|(?:telegram|tg|icq|jabber|skype)\s*[:\-=]\s*@?([\w.\-@]{3,40})|\bcontact\s*(?:me|us)?\s*[:\-]\s*@([\w.]{3,32})/gi)){ const v = (m[1] || m[2] || m[3] || '').trim(); if(v && !/^(the|this|you|user|admin|php|google|default|jquery)$/i.test(v)) R.auth.push([v, n, m[0].slice(0, 80)]); }
    /* keeping security tools out */
    if(/googlebot|bingbot|phishtank|crawler|spider|virustotal|kaspersky|netcraft|bitdefender|urlscan|abuse|paloalto|forcepoint|trendmicro/i.test(t) && /(header\s*\(\s*["']Location|exit|die|403|deny from|RewriteRule|http_response_code)/i.test(t)) R.block.push(n);
    if(/deny from \d|(?:\d{1,3}\.){2,3}\d{1,3}\/\d{1,2}/.test(t) && /\.htaccess$|block|bot|anti/i.test(n)) R.block.push(n);
    if(/geoip|ip-api\.com|ipinfo\.io|ipapi\.co|HTTP_CF_IPCOUNTRY|geoplugin/i.test(t)) R.geo = true;
    if(/HTTP_USER_AGENT/.test(t)) R.ua++;
    const ob = (t.match(/\b(?:eval|assert)\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13|strrev)|\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}|String\.fromCharCode\((?:\d+,){20}|atob\(["'][A-Za-z0-9+/=]{200,}/gi) || []).length; if(ob){ R.obf += ob; R.obfFiles.push(n); }
    if(/type=["']password["']|name=["'](?:pass(?:word)?|pwd)["']/i.test(t)) R.pass++;
    if(/\b(?:otp|sms_?code|verification_?code|2fa|one[- ]time)\b/i.test(t)) R.otp++;
    if(/\b(?:cc_?num|card_?number|cvv|cvc|exp(?:iry)?_?date)\b/i.test(t)) R.card++;
    if(typeof E !== 'undefined'){ const es = E.extract(t.slice(0, 300000)); for(const e of es) if(/^(btc|eth|xmr|trx|sol|ltc|ltc|onion|ip|email|domain|url)$/.test(e.k)) R.ents.push([e.k, e.v, n]); }
  }
  /* the fields stolen, and the targeted brand: the brand named most, outside library code */
  R.brandTop = [...R.brands.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5);
  const seen = new Set(); R.ents = R.ents.filter(([k, v]) => { const key = k + ':' + v.toLowerCase(); if(seen.has(key) || /jquery|googleapis|gstatic|cloudflare|bootstrapcdn|jsdelivr|w3\.org|schema\.org|fontawesome|php\.net|example\.(com|org)/i.test(v)) return false; seen.add(key); return true; });
  R.auth = R.auth.filter((a, i, L) => L.findIndex(b => b[0].toLowerCase() === a[0].toLowerCase()) === i).slice(0, 20);
  R.block = [...new Set(R.block)];
  return R;
}
async function fxKitLoad(fileList){
  const files = [], out = {name:fileList.length === 1 ? fileList[0].name : fileList.length + ' files', zip:null};
  for(const f of fileList){ if(f.size > 200 * 1048576){ toast(f.name + ' is over 200 MB'); continue; } const b = new Uint8Array(await f.arrayBuffer());
    if(b[0] === 0x50 && b[1] === 0x4b){ const Z = zipOpen(b); if(!Z) continue; out.zip = fxZip(b); out.encrypted = Z.files.some(x => x.enc);
      for(const e of Z.files.slice(0, 3000)){ if(/\/$/.test(e.name)) continue; const item = {name:e.name, size:e.size, date:e.date, enc:e.enc};
        if(!e.enc && e.size <= 3 * 1048576 && (KIT_TEXT.test(e.name) || e.size < 400000)){ try{ const u = await fxZipEntry(b, e.name, 4 * 1048576); if(u){ item.bytes = u; const s = new TextDecoder('utf-8', {fatal:false}).decode(u.subarray(0, 2e6)); if(KIT_TEXT.test(e.name) || !/[\u0000-\u0008]/.test(s.slice(0, 2000))) item.text = s; } }catch(x){} }
        files.push(item); } }
    else files.push({name:f.name, size:f.size, date:f.lastModified, bytes:b, text:new TextDecoder('utf-8', {fatal:false}).decode(b.subarray(0, 2e6))}); }
  const R = Object.assign(out, fxKitScan(files), {list:files.map(f => ({name:f.name, size:f.size, date:f.date, enc:f.enc, text:!!f.text}))});
  /* every YARA rule over every file */
  const rules = (DB.rules || []).filter(x => x.type === 'yara'); R.yara = [];
  if(typeof yaraScan === 'function') for(const f of files) if(f.bytes) for(const r of rules){ try{ for(const m of yaraScan(r.code, f.bytes)) if(m.match) R.yara.push([m.rule, f.name, r.title]); }catch(e){} }
  return R;
}
function labKit(){
  const K = UI.fxKit;
  if(!K) return `<label class="drop" id="kitDrop" tabindex="0"><input type="file" id="kitIn" class="sr" multiple accept=".zip,.php,.html,.htm,.js,.txt,.htaccess">${ico('skull')}<b>Drop a phishing kit — a ZIP, or its PHP and HTML files</b>
    <span>Finds where the stolen data goes (Telegram bots and chats, Discord webhooks, mail recipients, SMTP accounts, log files, remote panels), the brand it imitates, how it keeps security scanners out, who signed it, and runs every YARA rule over every file. Nothing is executed.</span>
    <span class="drop-feat"><i>Telegram bot IDs</i><i>Drop emails</i><i>Webhooks</i><i>Brand</i><i>Anti-bot &amp; cloaking</i><i>Author credits</i><i>Obfuscation</i><i>Wallets</i><i>YARA</i><i>Who packed it</i></span></label>
    <p class="t3 small">Kits are often found as <span class="mono">site.zip</span> or <span class="mono">kit.zip</span> left on the phishing server, or in open directories. Download them only from your research environment.</p>`;
  if(K.busy) return `<div class="card" style="padding:40px;text-align:center">${ico('refresh-cw','sm spin')} Reading ${esc(K.name)}…</div>`;
  const sec = (title, ic, body, tone) => body ? `<section class="card${tone ? ' ' + tone : ''}"><header><h3>${ico(ic,'sm')} ${title}</h3></header><div class="body">${body}</div></section>` : '';
  const lst = (L, mono = true) => L.map(x => `<div class="kv"><span></span>${mono ? `<code>${esc(x)}</code>` : `<b>${esc(x)}</b>`}<button class="iconbtn" data-act="flagCopy" data-v="${esc(x)}" aria-label="Copy">${ico('copy','sm')}</button></div>`).join('');
  const bots = [...K.bots.entries()], exfil = [
    bots.length ? `<h5 class="fx-g">Telegram bots</h5>${bots.map(([tok, fs]) => `<div class="kv"><span>Bot ${esc(tok.split(':')[0])}</span><code>${esc(tok.split(':')[0])}:AA…${esc(tok.slice(-4))}</code><span class="t3 small">${esc([...fs].slice(0, 2).join(', '))}</span></div>`).join('')}<p class="t3 small" style="margin:4px 0 0">The number before the colon is the bot's permanent ID — search it across cases and reports. Do not call the Telegram API with the token; report it to Telegram (abuse@telegram.org) instead.</p>` : '',
    K.chats.size ? `<h5 class="fx-g">Telegram chat IDs the bot reports to</h5>${lst([...K.chats])}<p class="t3 small" style="margin:4px 0 0">A positive number is a person's account; -100… is a group or channel.</p>` : '',
    K.hooks.size ? `<h5 class="fx-g">Discord webhooks</h5>${lst([...K.hooks].map(h => h.replace(/\/[\w-]{30,}$/, '/…')))}` : '',
    K.emails.size ? `<h5 class="fx-g">Results emailed to</h5>${lst([...K.emails])}` : '', K.smtp.length ? `<h5 class="fx-g">SMTP accounts</h5>${lst(K.smtp)}` : '',
    K.sheets.size ? `<h5 class="fx-g">Google Apps Script, Forms or Slack</h5>${lst([...K.sheets])}` : '', K.panels.size ? `<h5 class="fx-g">Remote panels it posts to</h5>${lst([...K.panels])}` : '',
    K.logs.size ? `<h5 class="fx-g">Files it writes victims to</h5>${lst([...K.logs])}<p class="t3 small" style="margin:4px 0 0">If the kit is still live, these files may be readable on the server — that is victims' data: report it, do not download it.</p>` : '',
    K.posts.size ? `<h5 class="fx-g">Forms post to</h5>${lst([...K.posts])}` : ''].join('');
  const stolen = [K.pass && 'passwords', K.otp && 'one-time codes', K.card && 'card numbers'].filter(Boolean);
  return `<div class="fi-grid"><div class="fi-side">
    <section class="card"><header><span class="fi-ic">${ico('skull')}</span><div style="min-width:0;flex:1"><h3>${esc(K.name)}</h3><p class="t3">${K.files} files · ${K.text} read as text${K.encrypted ? ' · some password-protected' : ''}</p></div><button class="btn sm" data-act="kitClear">${ico('x','sm')}Another kit</button></header>
      <div class="body">${K.brandTop.length ? fxKv('Imitates', K.brandTop.map(([b, n]) => `${b} (${n})`).join(', ')) : ''}${K.titles.size ? fxKv('Page titles', [...K.titles].slice(0, 4).join(' · ')) : ''}${stolen.length ? fxKv('Collects', stolen.join(', ')) : ''}
        ${K.zip ? fxKv('Packed on', K.zip.os.join(', ') + (K.zip.uids.length ? ' · user:group ' + K.zip.uids.slice(0, 3).join(', ') : '') + (K.zip.tz ? ' · time zone ' + K.zip.tz.txt : '')) + (K.zip.first ? fxKv('Files last changed', new Date(K.zip.first).toISOString().slice(0, 10) + (K.zip.last > K.zip.first ? ' to ' + new Date(K.zip.last).toISOString().slice(0, 10) : '')) : '') : ''}
        <div class="wrap" style="margin-top:12px"><button class="btn primary" data-act="kitSave">${ico('plus','sm')}Save to ${esc(caseNm(theCase()))}</button>${casePick()}</div></div></section>
    ${sec('Where the stolen data goes', 'upload', exfil, exfil ? 'warnc' : '') || sec('Where the stolen data goes', 'upload', '<p class="t3" style="margin:0">No bot, webhook, mail recipient or log file found — check obfuscated files below, or a remote panel loaded by JavaScript.</p>')}
    ${sec('Who made it', 'user', K.auth.length ? K.auth.map(([v, f, ctx]) => `<div class="kv"><span>${esc(v)}</span><code>${esc(ctx)}</code><span class="t3 small">${esc(f)}</span></div>`).join('') + '<p class="t3 small" style="margin:6px 0 0">Kit authors sign their work and sell it; the buyer who runs it is often someone else. The author handle leads to the seller, the drop email or bot to the operator.</p>' : '')}
    </div><div class="fi-side">
    ${sec('Keeping security tools out', 'shield-alert', [K.block.length ? `<div class="kv"><span>Blocklist files</span><code>${esc(K.block.slice(0, 8).join(', '))}</code></div>` : '', K.geo ? '<div class="fx-note">Checks the visitor\'s country (geo-filtering) — reviewers outside the target country see a decoy or a 404.</div>' : '', K.ua ? `<div class="fx-note">Reads the browser's user agent in ${K.ua} file${K.ua > 1 ? 's' : ''} — crawlers and sandboxes get turned away.</div>` : '', K.obf ? `<div class="fx-note amber">${K.obf} obfuscated block${K.obf > 1 ? 's' : ''} (eval of base64, hex strings) in ${esc(K.obfFiles.slice(0, 5).join(', '))} — decode them in the Decoder; hidden senders often live there.</div>` : ''].join(''))}
    ${sec('YARA', 'file-code', K.yara.length ? K.yara.map(([r, f, t]) => `<div class="yhit">${ico('shield-alert','sm')}<b>${esc(t || r)}</b><span class="mono t3">${esc(f)}</span></div>`).join('') : '<p class="t3" style="margin:0">No YARA rule from Detections matched.</p>')}
    ${sec('Wallets, hosts and addresses inside', 'fingerprint', K.ents.length ? `<div class="wrap">${K.ents.slice(0, 60).map(([k, v]) => `<span class="ent">${kindBadge(k)}<span class="v">${esc(v)}</span></span>`).join('')}</div>` : '')}
    <section class="card"><header><h3>${ico('box','sm')} Files</h3><span class="t3">${K.list.length}</span></header><div class="ziplist">${K.list.slice(0, 400).map(f => `<div><span class="mono">${esc(f.name)}</span>${f.enc ? `<span class="pill" style="--c:var(--amber)">${ico('lock','sm')}encrypted</span>` : ''}<span class="t3">${fmtBytes(f.size)}</span><span class="t3 hide-m">${f.date && isFinite(f.date) ? new Date(f.date).toISOString().slice(0, 16).replace('T', ' ') : ''}</span></div>`).join('')}</div></section>
    </div></div>`;
}
function bindKit(){ const inp = $('kitIn'), d = $('kitDrop'); if(!inp) return; const go1 = fl => { if(!fl.length) return; UI.fxKit = {busy:true, name:fl[0].name}; renderMain(); fxKitLoad([...fl]).then(R => { UI.fxKit = R; renderMain(); }).catch(e => { UI.fxKit = null; toast('Could not read the kit: ' + e.message); renderMain(); }); };
  inp.onchange = () => go1(inp.files); d.ondragover = e => { e.preventDefault(); d.classList.add('over'); }; d.ondragleave = () => d.classList.remove('over'); d.ondrop = e => { e.preventDefault(); d.classList.remove('over'); go1(e.dataTransfer.files); };
  d.onkeydown = e => { if(e.key === 'Enter' || e.key === ' '){ e.preventDefault(); inp.click(); } }; }
function kitSummary(K){
  return [`Phishing kit: ${K.name} (${K.files} files)`, K.brandTop.length ? 'Imitates: ' + K.brandTop.map(x => x[0]).join(', ') : '', K.titles.size ? 'Titles: ' + [...K.titles].slice(0, 4).join(' | ') : '',
    ...[...K.bots.keys()].map(t => 'Telegram bot ID: ' + t.split(':')[0]), ...[...K.chats].map(c => 'Telegram chat ID: ' + c), ...[...K.hooks].map(h => 'Discord webhook: ' + h.replace(/\/[\w-]{30,}$/, '/…')),
    ...[...K.emails].map(e => 'Drop email: ' + e), ...K.smtp.map(s => 'SMTP: ' + s), ...[...K.panels].map(p => 'Panel: ' + p), ...[...K.logs].map(l => 'Writes victims to: ' + l), ...[...K.posts].map(p => 'Form posts to: ' + p),
    ...K.auth.map(a => 'Author credit: ' + a[2]), K.zip && K.zip.tz ? 'Packed in time zone ' + K.zip.tz.txt + ' on ' + K.zip.os.join(', ') : '', K.yara.length ? 'YARA: ' + [...new Set(K.yara.map(y => y[2] || y[0]))].join(', ') : '',
    K.ents.length ? 'Indicators: ' + K.ents.slice(0, 60).map(e => e[1]).join(' ') : ''].filter(Boolean).join('\n');
}
Object.assign(FX_ACTS, {
  kitClear:() => { UI.fxKit = null; renderMain(); },
  kitSave:() => { const K = UI.fxKit; if(!K || K.busy) return; draft.source = 'phishing kit'; openCapture(kitSummary(K)); },
});

/* ---------- info-stealer logs: the infected machine, the accounts taken, the sessions that still work ---------- */
const SL_SSO = /(^|\.)(login\.microsoftonline\.com|login\.live\.com|okta\.com|oktapreview\.com|accounts\.google\.com|auth0\.com|onelogin\.com|duosecurity\.com|pingone\.com|sso\.|adfs\.|vpn\.|citrix|webmail\.|owa\.|gitlab\.|github\.com|atlassian\.net|slack\.com|salesforce\.com|aws\.amazon\.com|signin\.aws|portal\.azure\.com)/i;
const SL_SYS = {hwid:/^(?:hwid|hardware ?id|machine ?id)$/i, build:/^(?:build ?id|build|botnet|tag|build tag)$/i, ip:/^(?:ip|ip address|ipaddress)$/i, country:/^(?:country|country code|location)$/i, city:/^(?:city|zip ?code|zip)$/i, tz:/^(?:time ?zone|timezone|utc ?offset)$/i,
  user:/^(?:user ?name|username|user|current user)$/i, machine:/^(?:machine ?name|computer ?name|pc ?name|hostname|computer)$/i, os:/^(?:os|operation ?system|windows|os version|system)$/i, date:/^(?:log ?date|date|install date|installed|log time)$/i, lang:/^(?:language|languages|keyboard layouts?|layouts?)$/i, av:/^(?:antivirus(?:es)?|av|anti ?virus)$/i, path:/^(?:file ?location|path|file path|exe path)$/i};
function slKV(text){ const out = []; for(const line of text.split(/\r?\n/)){ const m = line.match(/^\s*[-•*]?\s*([A-Za-z][A-Za-z ]{0,30}?)\s*[:=]\s*(.+?)\s*$/); if(m) out.push([m[1].trim(), m[2].trim()]); } return out; }
function slCreds(text, file){
  const out = []; let cur = {};
  const flush = () => { if((cur.url || cur.host) && (cur.user || cur.pass)) out.push({url:cur.url || cur.host, user:cur.user || '', pass:cur.pass || '', app:cur.app || '', file}); cur = {}; };
  for(const line of text.split(/\r?\n/)){ const m = line.match(/^\s*(URL|Host|Hostname|Url|Site|Domain|Origin|USER|Login|Username|User ?name|Email|PASS|Password|Pass|Application|Soft|Software|Browser|Storage|Profile)\s*:\s*(.*)$/i);
    if(!m){ if(/^\s*(={3,}|-{3,}|\*{3,})?\s*$/.test(line)) flush(); continue; } const k = m[1].toLowerCase().replace(/\s/g, ''), v = m[2].trim();
    if(/^(url|host|hostname|site|domain|origin)$/.test(k)){ if(cur.url || cur.host) flush(); cur.url = v; } else if(/^(user|login|username|email)$/.test(k)) cur.user = v; else if(/^(pass|password)$/.test(k)) cur.pass = v; else cur.app = cur.app || v; }
  flush(); return out;
}
function slCookies(text){ const D = new Map(); let n = 0; for(const line of text.split(/\r?\n/)){ const p = line.split('\t'); if(p.length < 7 || !/^(TRUE|FALSE)$/i.test(p[1])) continue; n++; const d = p[0].replace(/^\./, '').toLowerCase(); const e = +p[4], live = !e || e * 1000 > Date.now(); const x = D.get(d) || {n:0, live:0, names:new Set()}; x.n++; if(live) x.live++; x.names.add(p[5]); D.set(d, x); } return {n, D}; }
const slHost = u => { const m = String(u || '').toLowerCase().match(/^(?:[a-z][\w+.-]*:\/\/)?([^/:?#\s]+)/); return m ? m[1].replace(/^www\./, '') : ''; };
async function fxStealerLoad(fileList, mine){
  const items = [];
  for(const f of fileList){ const b = new Uint8Array(await f.arrayBuffer());
    if(b[0] === 0x50 && b[1] === 0x4b){ const Z = zipOpen(b); if(!Z) continue; if(Z.files.some(x => x.enc)) toast('Some files in ' + f.name + ' are password-protected — unpack them first (stealer logs often use “infected” or the shop’s name)');
      for(const e of Z.files.slice(0, 20000)){ if(/\/$/.test(e.name) || e.enc || e.size > 8 * 1048576 || !/\.(txt|log|json|csv|ini)$/i.test(e.name)) { items.push({path:e.name, size:e.size}); continue; } try{ const u = await fxZipEntry(b, e.name, 10 * 1048576); items.push({path:e.name, size:e.size, text:u ? new TextDecoder('utf-8', {fatal:false}).decode(u) : ''}); }catch(x){ items.push({path:e.name, size:e.size}); } } }
    else items.push({path:f.webkitRelativePath || f.name, size:f.size, text:/\.(txt|log|json|csv|ini)$/i.test(f.name) && f.size < 8 * 1048576 ? new TextDecoder('utf-8', {fatal:false}).decode(b) : ''}); }
  return Object.assign(fxStealer(items, mine), {items0:items});
}
function fxStealer(items, mine){
  /* one victim per folder that holds a system-information or passwords file */
  const isSys = p => /(^|\/)(UserInformation|System|information|SystemInfo|Info|system_info|Information)\.txt$/i.test(p), isPw = p => /(^|\/)(All ?Passwords|Passwords|passwords?_?\w*|Credentials)\.txt$/i.test(p);
  const roots = new Set(); for(const it of items) if(isSys(it.path) || isPw(it.path)) roots.add(it.path.includes('/') ? it.path.slice(0, it.path.lastIndexOf('/') + 1).replace(/(?:Browsers?|Passwords?)\/$/i, '') : '');
  const R = [...roots].sort((a, b) => b.length - a.length), ownerOf = p => R.find(r => p.startsWith(r)) ?? '';
  const V = new Map(); const vic = r => { if(!V.has(r)) V.set(r, {root:r, sys:{}, rawSys:[], creds:[], cookies:new Map(), nCookies:0, wallets:new Set(), files:0, tg:false, discord:[], autofill:0, screenshot:false}); return V.get(r); };
  const mineL = String(mine || '').toLowerCase().split(/[\s,;]+/).map(x => x.replace(/^@|^https?:\/\/|\/.*$/g, '').trim()).filter(x => /\./.test(x));
  for(const it of items){ const r = ownerOf(it.path); if(!roots.size && !it.text) continue; const v = vic(r); v.files++; const p = it.path, t = it.text || '';
    if(isSys(p)){ for(const [k, val] of slKV(t)){ for(const [key, re] of Object.entries(SL_SYS)) if(re.test(k) && !v.sys[key]) v.sys[key] = val.slice(0, 200); } v.rawSys = slKV(t).slice(0, 60); }
    else if(isPw(p) || /passwords?|logins?|credentials/i.test(p) && /\.txt$/i.test(p)) v.creds.push(...slCreds(t, p));
    else if(/cookies?/i.test(p) && t){ const C = slCookies(t); v.nCookies += C.n; for(const [d, x] of C.D){ const y = v.cookies.get(d) || {n:0, live:0, names:new Set()}; y.n += x.n; y.live += x.live; for(const nm of x.names) y.names.add(nm); v.cookies.set(d, y); } }
    { const wm = p.match(/wallets?\/([^/]+)/i); if(wm) v.wallets.add(wm[1]); }
    if(/telegram|tdata/i.test(p)) v.tg = true; if(/discord/i.test(p) && t) for(const m of t.matchAll(/[MN][A-Za-z\d]{23,25}\.[\w-]{6}\.[\w-]{27,38}/g)) v.discord.push(m[0].slice(0, 12) + '…');
    if(/autofill/i.test(p) && t) v.autofill += (t.match(/\n/g) || []).length; if(/screenshot|screen\.(jpe?g|png)/i.test(p)) v.screenshot = true; }
  const out = [...V.values()].filter(v => v.creds.length || Object.keys(v.sys).length || v.nCookies);
  for(const v of out){ const seen = new Set(); v.creds = v.creds.filter(c => { const k = c.url + '|' + c.user + '|' + c.pass; if(seen.has(k)) return false; seen.add(k); return true; });
    for(const c of v.creds){ c.host = slHost(c.url); const ud = (c.user.match(/@([\w.-]+\.[a-z]{2,})$/i) || [])[1] || ''; c.mine = mineL.some(d => c.host === d || c.host.endsWith('.' + d) || ud.toLowerCase() === d || ud.toLowerCase().endsWith('.' + d)); c.sso = SL_SSO.test(c.host); }
    v.mineCookies = [...v.cookies.entries()].filter(([d]) => mineL.some(m => d === m || d.endsWith('.' + m))).map(([d, x]) => ({d, ...x}));
    v.ssoCookies = [...v.cookies.entries()].filter(([d]) => SL_SSO.test(d)).map(([d, x]) => ({d, ...x}));
    v.score = v.creds.filter(c => c.mine).length * 5 + v.mineCookies.reduce((s, x) => s + x.live, 0) * 3 + v.creds.filter(c => c.sso).length; }
  out.sort((a, b) => b.score - a.score);
  return {victims:out, items:items.length, mine:mineL};
}
const slMask = p => !p ? '' : UI.slShow ? p : p.length <= 2 ? '••' : p.slice(0, 2) + '•'.repeat(Math.min(10, p.length - 2)) + ` (${p.length})`;
function labSteal(){
  const S = UI.fxSteal, mine = UI.slMine || '';
  const form = `<div class="sl-mine"><label for="slMine" class="ix">Your domains <span class="t3">— their logins and sessions are marked</span></label><input id="slMine" class="inp" placeholder="corp.example, corp-mail.example" title="Logins and sessions on these domains are marked as yours" value="${esc(mine)}"></div>`;
  if(!S) return `${form}<label class="drop" id="slDrop" tabindex="0"><input type="file" id="slIn" class="sr" multiple accept=".zip,.txt">${ico('key-round')}<b>Drop a stealer log — the ZIP, or the files from one victim's folder</b>
    <span>RedLine, Lumma, Vidar, Raccoon, StealC and their clones: the infected machine (user, computer name, HWID, IP, country, build tag), every saved login it gave up, and the cookies that let someone sign in without a password. Passwords stay masked until you ask.</span>
    <span class="drop-feat"><i>Machine profile</i><i>Build tag</i><i>Saved logins</i><i>Your domains</i><i>SSO &amp; VPN</i><i>Live session cookies</i><i>Wallets</i><i>Telegram &amp; Discord</i></span></label>
    <p class="t3 small">Get logs lawfully (your threat-intel provider, a law-enforcement notice, a public leak) and open them only in your research environment — a log is someone's stolen life. The Stealer-log playbook covers what to do next.</p>`;
  if(S.busy) return `<div class="card" style="padding:40px;text-align:center">${ico('refresh-cw','sm spin')} Reading the log…</div>`;
  if(!S.victims.length) return `${form}<div class="card"><div class="body">No stealer-log files recognised in ${S.items} files (looking for Passwords.txt, UserInformation.txt / System.txt and Cookies). <button class="lnk" data-act="slClear">Try another</button></div></div>`;
  const vic = S.victims.map((v, i) => { const sy = v.sys, mineN = v.creds.filter(c => c.mine).length, rows = v.creds.slice().sort((a, b) => (b.mine - a.mine) || (b.sso - a.sso)).slice(0, UI.slAll === i ? 2000 : 25);
    return `<section class="card sl-v"><header><span class="fi-ic">${ico('monitor')}</span><div style="min-width:0;flex:1"><h3>${esc(sy.machine || sy.user || v.root || 'Victim ' + (i + 1))}${sy.user && sy.machine ? ' <span class="t3">· ' + esc(sy.user) + '</span>' : ''}</h3><p class="t3">${esc(v.root || '')} · ${v.creds.length} logins · ${v.nCookies} cookies${v.wallets.size ? ' · ' + v.wallets.size + ' wallets' : ''}</p></div>
      ${mineN || v.mineCookies.length ? `<span class="chip sq red">${mineN} of your logins${v.mineCookies.length ? ', ' + v.mineCookies.reduce((s, x) => s + x.live, 0) + ' live session cookies' : ''}</span>` : ''}</header><div class="body">
      <div class="sl-sys">${[['IP', sy.ip], ['Country', [sy.country, sy.city].filter(Boolean).join(', ')], ['Time zone', sy.tz], ['Windows', sy.os], ['Language', sy.lang], ['HWID', sy.hwid], ['Build tag', sy.build], ['Infected', sy.date], ['Antivirus', sy.av], ['Ran from', sy.path]].filter(x => x[1]).map(([k, val]) => fxKv(k, val, /HWID|Build|Ran/.test(k))).join('')}</div>
      ${sy.build ? `<p class="t3 small" style="margin:4px 0 8px">The build tag names the stealer customer's campaign — the same tag in other logs means the same operator.</p>` : ''}
      ${v.mineCookies.length || v.ssoCookies.length ? `<h5 class="fx-g">Sessions someone can reuse</h5>${v.mineCookies.concat(v.ssoCookies.filter(x => !v.mineCookies.some(y => y.d === x.d))).slice(0, 20).map(x => `<div class="kv"><span>${esc(x.d)}</span><b>${x.live} live of ${x.n}</b><span class="t3 small">${esc([...x.names].slice(0, 5).join(', '))}</span></div>`).join('')}<div class="fx-note amber">A stolen session cookie signs in without the password or MFA. Revoke sessions for these accounts — resetting the password alone does not end them.</div>` : ''}
      ${v.creds.length ? `<h5 class="fx-g">Saved logins</h5><div class="tblw"><table class="tbl sl-t"><thead><tr><th>Site</th><th>User</th><th>Password</th><th>From</th></tr></thead><tbody>${rows.map(c => `<tr class="${c.mine ? 'mine' : ''}"><td>${c.mine ? `<span class="chip sq red">yours</span> ` : c.sso ? '<span class="chip sq amber">sign-in</span> ' : ''}<span class="mono">${esc(c.host || c.url)}</span></td><td class="mono">${esc(c.user)}</td><td class="mono">${esc(slMask(c.pass))}</td><td class="t3">${esc(c.app)}</td></tr>`).join('')}</tbody></table></div>${v.creds.length > rows.length ? `<button class="lnk small" data-act="slAll" data-v="${i}">All ${v.creds.length}</button>` : ''}` : ''}
      ${v.wallets.size || v.tg || v.discord.length ? `<div class="fx-note">${[v.wallets.size && 'Wallet files: ' + [...v.wallets].join(', '), v.tg && 'Telegram session (tdata) — the account can be opened elsewhere', v.discord.length && v.discord.length + ' Discord token' + (v.discord.length > 1 ? 's' : '')].filter(Boolean).map(esc).join(' · ')}</div>` : ''}</div></section>`; }).join('');
  const tot = S.victims.reduce((s, v) => s + v.creds.filter(c => c.mine).length, 0);
  return `${form}<div class="sl-hd"><div><b>${S.victims.length} infected machine${S.victims.length === 1 ? '' : 's'}</b> · ${S.victims.reduce((s, v) => s + v.creds.length, 0)} logins${S.mine.length ? ` · <b style="color:${tot ? 'var(--red)' : 'var(--green)'}">${tot} on your domains</b>` : ' · add your domains above to mark your accounts'}</div>
    <label class="chk"><input type="checkbox" data-act="slShow" ${UI.slShow ? 'checked' : ''}> Show passwords</label><button class="btn sm" data-act="slSave">${ico('plus','sm')}Save to ${esc(caseNm(theCase()))}</button>${casePick()}<button class="btn sm ghost" data-act="slClear">${ico('x','sm')}Another log</button></div>${vic}`;
}
function bindSteal(){ const inp = $('slIn'), d = $('slDrop'), m = $('slMine');
  if(m) m.oninput = () => { clearTimeout(m.__t); m.__t = setTimeout(() => { UI.slMine = m.value; if(UI.fxSteal && UI.fxSteal.items0){ UI.fxSteal = Object.assign(fxStealer(UI.fxSteal.items0, UI.slMine), {items0:UI.fxSteal.items0}); const p = m.selectionStart; renderMain(); const x = $('slMine'); if(x){ x.focus(); x.setSelectionRange(p, p); } } }, 300); };
  if(!inp) return; const go1 = fl => { if(!fl.length) return; UI.fxSteal = {busy:true}; renderMain(); slRead([...fl]).then(R => { UI.fxSteal = R; renderMain(); }).catch(e => { UI.fxSteal = null; toast('Could not read the log: ' + e.message); renderMain(); }); };
  inp.onchange = () => go1(inp.files); d.ondragover = e => { e.preventDefault(); d.classList.add('over'); }; d.ondragleave = () => d.classList.remove('over'); d.ondrop = e => { e.preventDefault(); d.classList.remove('over'); go1(e.dataTransfer.files); };
  d.onkeydown = e => { if(e.key === 'Enter' || e.key === ' '){ e.preventDefault(); inp.click(); } }; }
/* keep the parsed files, so changing "your domains" re-marks without reading again */
const slRead = fl => fxStealerLoad(fl, UI.slMine);
function slSummary(S){ const L = [`Stealer log: ${S.victims.length} infected machine(s)`];
  for(const v of S.victims){ const sy = v.sys; L.push('', `Machine: ${sy.machine || '?'} · user ${sy.user || '?'} · IP ${sy.ip || '?'} · ${sy.country || ''}`.trim(), sy.hwid ? 'HWID: ' + sy.hwid : '', sy.build ? 'Build tag: ' + sy.build : '', sy.date ? 'Infected: ' + sy.date : '', sy.path ? 'Ran from: ' + sy.path : '',
    `Logins: ${v.creds.length} (${v.creds.filter(c => c.mine).length} on our domains, ${v.creds.filter(c => c.sso).length} sign-in or VPN)`, ...v.creds.filter(c => c.mine || c.sso).slice(0, 40).map(c => `  ${c.host} — ${c.user}${c.mine ? ' [OURS]' : ''}`),
    ...v.mineCookies.map(x => `Session cookies for ${x.d}: ${x.live} live`)); }
  return L.filter(x => x !== '').join('\n'); }
Object.assign(FX_ACTS, {
  slClear:() => { UI.fxSteal = null; renderMain(); }, slShow:() => { UI.slShow = !UI.slShow; renderMain(); }, slAll:(id, v) => { UI.slAll = UI.slAll === +v ? null : +v; renderMain(); },
  slSave:() => { const S = UI.fxSteal; if(!S || S.busy) return; draft.source = 'stealer log'; openCapture(slSummary(S)); },
});
