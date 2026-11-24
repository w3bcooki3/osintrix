/* ==========================================================================
   File metadata, read from the bytes, in this browser — nothing is uploaded.
   Pictures: JPEG, HEIC/HEIF/AVIF, PNG, WebP and TIFF — EXIF (camera, times
   and time zone, GPS with the direction the camera faced), XMP (the program,
   edit history, AI-generation marks) and IPTC (place names, caption, author).
   Video and sound: MP4/MOV/3GP (recording time, GPS, phone make, model and
   software — Apple and Android), MP3 ID3 tags. Documents: PDF (including
   information kept in compressed object streams) and Word/Excel/PowerPoint.
   One shape out: grouped facts, a location, the moment it was made, the
   people and programs it names, and what stands out.
   ========================================================================== */
const MT_GROUPS = ['Stands out', 'Where', 'When', 'Device', 'People', 'Software', 'Content', 'File'];
const MT_AI = /stable diffusion|midjourney|dall[·\-\s]?e|openai|firefly|imagen|flux\b|comfyui|automatic1111|novelai|leonardo\.ai|ideogram|gemini|trainedalgorithmicmedia|compositewithtrainedalgorithmicmedia|algorithmicmedia/i;
const mtU32 = (b, o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
const mtU16 = (b, o) => (b[o] << 8) | b[o + 1];
const mtStr = (b, a, z) => { let s = ''; for(let i = a; i < z && i < b.length; i++) s += String.fromCharCode(b[i]); return s; };
const mtUtf8 = (b, a, z) => new TextDecoder('utf-8', {fatal:false}).decode(b.subarray(a, Math.min(z, b.length)));
/* ISO 6709 as phones write it: +51.4169-000.0806/  or  +32.0929+034.8620+028.516/ */
function mtIso6709(s){ const m = String(s || '').match(/([+-]\d{1,2}(?:\.\d+)?)([+-]\d{1,3}(?:\.\d+)?)([+-]\d+(?:\.\d+)?)?/); if(!m) return null;
  const lat = +m[1], lon = +m[2]; if(Math.abs(lat) > 90 || Math.abs(lon) > 180 || (lat === 0 && lon === 0)) return null; return {lat:+lat.toFixed(6), lon:+lon.toFixed(6), alt:m[3] ? Math.round(+m[3]) : null}; }
/* XMP keeps GPS as "51,45.744N" or "51,45,44.6N" */
function mtXmpDeg(s){ const m = String(s || '').match(/^\s*(-?\d+(?:\.\d+)?)(?:,(\d+(?:\.\d+)?))?(?:,(\d+(?:\.\d+)?))?\s*([NSEW])?\s*$/i); if(!m) return null;
  let v = Math.abs(+m[1]) + (+m[2] || 0) / 60 + (+m[3] || 0) / 3600; if(/[SW]/i.test(m[4] || '') || +m[1] < 0) v = -v; return v; }
/* a date written any of the usual ways → ms (UTC when the writer gave a zone; as written otherwise) */
function mtDate(s){ s = String(s || '').trim(); if(!s) return null;
  let m = s.match(/^(\d{4})[:\-](\d{2})[:\-](\d{2})(?:[ T](\d{2}):(\d{2})(?::(\d{2}))?(?:\.\d+)?)?\s*(Z|[+-]\d{2}:?\d{2})?/);
  if(m){ const t = Date.UTC(+m[1], m[2] - 1, +m[3], +(m[4] || 0), +(m[5] || 0), +(m[6] || 0)); if(!m[7] || m[7] === 'Z') return t; const z = m[7].replace(':', ''), off = (+z.slice(1, 3) * 60 + +z.slice(3, 5)) * (z[0] === '-' ? -1 : 1); return t - off * 6e4; }
  m = s.match(/^D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?(Z|[+-]\d{2}'?\d{2}'?)?/); if(m){ const t = Date.UTC(+m[1], (m[2] || 1) - 1, +(m[3] || 1), +(m[4] || 0), +(m[5] || 0), +(m[6] || 0)); if(!m[7] || m[7] === 'Z') return t; const z = m[7].replace(/'/g, ''), off = (+z.slice(1, 3) * 60 + +(z.slice(3, 5) || 0)) * (z[0] === '-' ? -1 : 1); return t - off * 6e4; }
  return null; }
/* ---------- XMP ---------- */
function mtXmp(x, add, st){
  x = String(x || '').slice(0, 400000); if(!/x:xmpmeta|rdf:RDF/.test(x)) return;
  const dec = v => v.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&#(\d+);/g, (_, n) => String.fromCharCode(+n)).replace(/&amp;/g, '&').trim();
  const get = n => { const e = n.replace(/[.:]/g, m => '\\' + m);
    let m = x.match(new RegExp('\\s' + e + '="([^"]*)"')); if(m) return dec(m[1]);
    m = x.match(new RegExp('<' + e + '(?:\\s[^>]*)?>([\\s\\S]*?)</' + e + '>')); if(!m) return '';
    const li = [...m[1].matchAll(/<rdf:li(?:\s[^>]*)?>([\s\S]*?)<\/rdf:li>/g)].map(a => dec(a[1])).filter(Boolean); return li.length ? li.join('; ') : dec(m[1].replace(/<[^>]+>/g, '')); };
  const T = [['Software', 'Made with', 'xmp:CreatorTool'], ['When', 'Created (XMP)', 'xmp:CreateDate'], ['When', 'Modified (XMP)', 'xmp:ModifyDate'], ['When', 'Taken (XMP)', 'photoshop:DateCreated'], ['When', 'Taken (XMP EXIF)', 'exif:DateTimeOriginal'],
    ['People', 'Author', 'dc:creator'], ['People', 'Copyright', 'dc:rights'], ['People', 'Credit', 'photoshop:Credit'], ['People', 'Source', 'photoshop:Source'], ['Content', 'Title', 'dc:title'], ['Content', 'Description', 'dc:description'], ['Content', 'Headline', 'photoshop:Headline'], ['Content', 'Keywords', 'dc:subject'],
    ['Where', 'City', 'photoshop:City'], ['Where', 'State / province', 'photoshop:State'], ['Where', 'Country', 'photoshop:Country'], ['Where', 'Place', 'Iptc4xmpCore:Location'], ['Where', 'Country code', 'Iptc4xmpCore:CountryCode'],
    ['Device', 'Make (XMP)', 'tiff:Make'], ['Device', 'Model (XMP)', 'tiff:Model'], ['Device', 'Serial number', 'aux:SerialNumber'], ['Device', 'Lens (XMP)', 'aux:Lens'], ['File', 'Document ID', 'xmpMM:DocumentID'], ['File', 'Original document ID', 'xmpMM:OriginalDocumentID']];
  for(const [g, k, n] of T){ const v = get(n); if(v) add(g, k, v); }
  const src = get('Iptc4xmpExt:DigitalSourceType'); if(src){ add('Content', 'Digital source', src.split('/').pop()); if(/algorithmicmedia/i.test(src)) st.ai.push('IPTC digital source: ' + src.split('/').pop()); }
  if(!st.gps){ const la = mtXmpDeg(get('exif:GPSLatitude')), lo = mtXmpDeg(get('exif:GPSLongitude')); if(la != null && lo != null && Math.abs(la) <= 90 && Math.abs(lo) <= 180 && !(la === 0 && lo === 0)) st.gps = {lat:+la.toFixed(6), lon:+lo.toFixed(6), src:'XMP'}; }
  /* the edit history: which programs saved it, when */
  const H = [...x.matchAll(/<rdf:li[^>]*stEvt:action="([^"]+)"[^>]*>|<rdf:li[^>]*rdf:parseType="Resource"[^>]*>([\s\S]*?)<\/rdf:li>/g)].map(m => { const s = m[0] + (m[2] || '');
    const a = (s.match(/stEvt:action(?:="|>)([^"<]+)/) || [])[1], w = (s.match(/stEvt:softwareAgent(?:="|>)([^"<]+)/) || [])[1], t = (s.match(/stEvt:when(?:="|>)([^"<]+)/) || [])[1]; return a ? {a, w:w ? dec(w) : '', t:t || ''} : null; }).filter(Boolean);
  if(H.length){ add('Software', 'Edit history', H.slice(0, 12).map(h => `${h.a}${h.w ? ' by ' + h.w : ''}${h.t ? ' at ' + h.t : ''}`).join('; ') + (H.length > 12 ? `; and ${H.length - 12} more` : '')); for(const h of H) if(h.w) st.soft.add(h.w); st.edits = H.length; }
  if(/c2pa|contentauth|jumbf/i.test(x)) st.c2pa = true;
}
/* ---------- IPTC (Photoshop APP13) ---------- */
const MT_IPTC = {5:['Content', 'Object name'], 25:['Content', 'Keywords'], 55:['When', 'Date created (IPTC)'], 80:['People', 'By-line'], 85:['People', 'By-line title'], 90:['Where', 'City'], 92:['Where', 'Sub-location'], 95:['Where', 'State / province'], 100:['Where', 'Country code'], 101:['Where', 'Country'], 105:['Content', 'Headline'], 110:['People', 'Credit'], 115:['People', 'Source'], 116:['People', 'Copyright'], 120:['Content', 'Caption'], 122:['People', 'Caption writer']};
function mtIptc(b, a, z, add){
  const got = {}; let o = a;
  for(let guard = 0; o + 12 < z && guard < 400; guard++){ if(mtStr(b, o, o + 4) !== '8BIM') break; const id = mtU16(b, o + 4), nl = b[o + 6], np = (nl + 2) & ~1, size = mtU32(b, o + 6 + np), d = o + 10 + np;
    if(id === 0x0404){ let p = d; while(p + 5 <= d + size && b[p] === 0x1c){ const rec = b[p + 1], ds = b[p + 2], len = mtU16(b, p + 3); if(len > 32000) break; if(rec === 2 && MT_IPTC[ds]){ const v = mtUtf8(b, p + 5, p + 5 + len).trim(); if(v){ const k = MT_IPTC[ds][1]; (got[k] = got[k] || [MT_IPTC[ds][0], []])[1].push(v); } } p += 5 + len; } }
    o = d + size + (size & 1); }
  for(const [k, [g, v]] of Object.entries(got)) add(g, k, [...new Set(v)].join('; '));
}
/* ---------- EXIF (shared TIFF reader) ---------- */
function mtExif(x, add, st){
  if(!x) return; st.exif = x;
  const g = {Make:'Device', Model:'Device', 'Lens make':'Device', Lens:'Device', 'Body serial':'Device', 'Host computer':'Device', 'Image ID':'File', Software:'Software', Taken:'When', Digitized:'When', Modified:'When', 'Taken offset':'When', 'Modified offset':'When', 'GPS date':'When',
    Artist:'People', Owner:'People', Copyright:'People', 'XP author':'People', Description:'Content', 'User comment':'Content', 'XP title':'Content', 'XP comment':'Content', 'XP keywords':'Content', 'XP subject':'Content', Width:'File', Height:'File', Orientation:'File'};
  const lbl = {Lens:'Lens model', 'Body serial':'Serial number', Owner:'Camera owner', 'Taken offset':'Time zone (taken)', 'Modified offset':'Time zone (modified)', 'GPS date':'GPS date (UTC)', 'XP author':'Author (Windows)'};
  for(const [k, v] of Object.entries(x)) if(g[k] && v !== '' && v != null && typeof v !== 'object') add(g[k], lbl[k] || k, v);
  if(x.GPS) st.gps = {...x.GPS, src:'EXIF'};
  /* no time zone with the time taken: the GPS clock (always UTC) gives it, when the picture has one */
  const gu = x['GPS date'] && x['GPS time'] ? mtDate(String(x['GPS date']).replace(/:/g, '-') + 'T' + x['GPS time'] + 'Z') : null, tl = mtDate(x.Taken);
  if(x.Taken && !x['Taken offset'] && gu != null && tl != null && Math.abs(tl - gu) <= 14 * 36e5 + 6e4){ const q = Math.round((tl - gu) / 9e5) * 15, sg = q < 0 ? '-' : '+', hh = String(Math.floor(Math.abs(q) / 60)).padStart(2, '0'), mm = String(Math.abs(q) % 60).padStart(2, '0');
    add('When', 'Time zone (taken)', `UTC${sg}${hh}:${mm} — worked out from the GPS clock`); st.taken = tl - q * 6e4; st.tz = 'explicit'; }
  else if(x.Taken && !x['Taken offset']) add('When', 'Time zone (taken)', 'not recorded — the time is the camera clock\'s local time');
  if(x['GPS time']) add('When', 'GPS time (UTC)', x['GPS time']);
  const t = mtDate(x.Taken); if(t != null){ let tt = t; if(x['Taken offset']){ const z = String(x['Taken offset']).match(/^([+-])(\d{2}):?(\d{2})$/); if(z) tt = t - (z[1] === '-' ? -1 : 1) * (+z[2] * 60 + +z[3]) * 6e4; } if(st.taken == null){ st.taken = tt; st.tz = x['Taken offset'] ? 'explicit' : 'assumed'; } }
  if(x.Software) st.soft.add(x.Software);
}
/* ---------- JPEG ---------- */
function mtJpeg(b, add, st){
  let o = 2;
  while(o + 4 < b.length){ if(b[o] !== 0xff){ o++; continue; } const m = b[o + 1]; if(m === 0xd8 || (m >= 0xd0 && m <= 0xd7) || m === 0x01 || m === 0xff){ o += m === 0xff ? 1 : 2; continue; } if(m === 0xda || m === 0xd9) break;
    const l = mtU16(b, o + 2), a = o + 4, z = o + 2 + l;
    if(m === 0xe1 && mtStr(b, a, a + 6) === 'Exif\0\0'){ try{ mtExif(parseTiff(b, a + 6), add, st); }catch(e){} }
    else if(m === 0xe1 && mtStr(b, a, a + 29) === 'http://ns.adobe.com/xap/1.0/\0') mtXmp(mtUtf8(b, a + 29, z), add, st);
    else if(m === 0xed && mtStr(b, a, a + 14) === 'Photoshop 3.0\0') mtIptc(b, a + 14, z, add);
    else if(m === 0xfe){ const c = mtUtf8(b, a, z).replace(/\0+$/, '').trim(); if(c && !/^(CREATOR: gd-jpeg|Optimized by JPEGmini|LEAD Technologies)/.test(c)) add('Content', 'Comment', c.slice(0, 300)); else if(c) st.soft.add(c.split(/[,(]/)[0].replace(/^CREATOR:\s*/, '')); }
    else if(m === 0xeb && mtStr(b, a, a + 2) === 'JP') st.c2pa = true;
    o = z; }
}
/* ---------- PNG ---------- */
async function mtPng(b, add, st){
  let o = 8; const texts = [];
  while(o + 12 <= b.length){ const len = mtU32(b, o), type = mtStr(b, o + 4, o + 8), d = o + 8; if(len > b.length) break;
    if(type === 'eXIf'){ try{ mtExif(parseTiff(b, d), add, st); }catch(e){} }
    else if(type === 'tEXt' || type === 'zTXt' || type === 'iTXt'){ const nul = b.indexOf(0, d); if(nul > d && nul < d + 80){ const key = mtStr(b, d, nul); let v = '';
        try{ if(type === 'tEXt') v = mtStr(b, nul + 1, d + len);
          else if(type === 'zTXt') v = new TextDecoder().decode(await decompressCapped(b.subarray(nul + 2, d + len), 'deflate', 4 << 20));
          else { const comp = b[nul + 1], l1 = b.indexOf(0, nul + 3), l2 = b.indexOf(0, l1 + 1), raw = b.subarray(l2 + 1, d + len); v = comp ? new TextDecoder().decode(await decompressCapped(raw, 'deflate', 4 << 20)) : new TextDecoder().decode(raw); } }catch(e){}
        texts.push([key, v]); } }
    else if(type === 'caBX') st.c2pa = true;
    if(type === 'IEND') break; o += 12 + len; }
  for(const [k, v] of texts){
    if(k === 'XML:com.adobe.xmp') mtXmp(v, add, st);
    else if(k === 'Raw profile type exif' || k === 'Raw profile type APP1'){ const hex = v.replace(/^\s*\w+\s+\d+\s*/, '').replace(/\s+/g, ''), u = Uint8Array.from((hex.match(/../g) || []).map(h => parseInt(h, 16))); const at = mtStr(u, 0, 6) === 'Exif\0\0' ? 6 : 0; try{ mtExif(parseTiff(u, at), add, st); }catch(e){} }
    else if(k === 'parameters' && /Steps:|Sampler:|CFG scale/i.test(v)){ st.ai.push('Stable Diffusion settings in the file'); add('Content', 'Generation settings', v.slice(0, 600)); }
    else if((k === 'prompt' || k === 'workflow') && /class_type|"nodes"/.test(v)){ st.ai.push('ComfyUI workflow in the file'); add('Content', 'Generator workflow', 'ComfyUI (' + v.length.toLocaleString() + ' characters)'); }
    else if(/^(Software|Author|Title|Description|Comment|Copyright|Creation Time|Source|Disclaimer|Warning)$/i.test(k) && v.trim()){ const g = /Software|Source/i.test(k) ? 'Software' : /Author|Copyright/i.test(k) ? 'People' : /Creation/i.test(k) ? 'When' : 'Content'; add(g, k, v.trim().slice(0, 400)); if(/Software/i.test(k)) st.soft.add(v.trim()); }
    else if(v && v.length < 300 && !/^Raw profile/i.test(k)) add('Content', k, v.trim()); }
}
/* ---------- WebP (RIFF) ---------- */
function mtWebp(b, add, st){
  let o = 12; while(o + 8 <= b.length){ const t = mtStr(b, o, o + 4), len = b[o + 4] | (b[o + 5] << 8) | (b[o + 6] << 16) | (b[o + 7] << 24) >>> 0, d = o + 8;
    if(t === 'EXIF'){ const at = mtStr(b, d, d + 6) === 'Exif\0\0' ? d + 6 : d; try{ mtExif(parseTiff(b, at), add, st); }catch(e){} }
    else if(t === 'XMP ') mtXmp(mtUtf8(b, d, d + len), add, st);
    o = d + len + (len & 1); if(len < 0) break; }
}
/* ---------- ISO base media: HEIC/AVIF pictures, MP4/MOV/3GP video ---------- */
function mtBoxes(b, a, z, fn, depth = 0){
  let o = a; while(o + 8 <= z){ let size = mtU32(b, o), hdr = 8; const type = mtStr(b, o + 4, o + 8);
    if(size === 1){ size = mtU32(b, o + 8) * 4294967296 + mtU32(b, o + 12); hdr = 16; } else if(size === 0) size = z - o;
    if(size < hdr || o + size > z + 8) break; if(fn(type, o + hdr, Math.min(o + size, z), depth) === false) return; o += size; }
}
const MT_QT_KEY = {'com.apple.quicktime.location.ISO6709':['Where', 'GPS (ISO 6709)'], 'com.apple.quicktime.make':['Device', 'Make'], 'com.apple.quicktime.model':['Device', 'Model'], 'com.apple.quicktime.software':['Software', 'Software'],
  'com.apple.quicktime.creationdate':['When', 'Recorded'], 'com.apple.quicktime.location.accuracy.horizontal':['Where', 'GPS accuracy (m)'], 'com.apple.quicktime.content.identifier':['File', 'Content ID'], 'com.apple.quicktime.author':['People', 'Author'],
  'com.apple.quicktime.title':['Content', 'Title'], 'com.apple.quicktime.description':['Content', 'Description'], 'com.android.version':['Software', 'Android version'], 'com.android.manufacturer':['Device', 'Make'], 'com.android.model':['Device', 'Model'], 'com.android.capture.fps':['File', 'Capture frame rate']};
const MT_UDTA = {'©xyz':['Where', 'GPS (ISO 6709)'], '©mak':['Device', 'Make'], '©mod':['Device', 'Model'], '©swr':['Software', 'Software'], '©too':['Software', 'Encoder'], '©day':['When', 'Date'], '©nam':['Content', 'Title'], '©ART':['People', 'Artist'], '©aut':['People', 'Author'], '©cmt':['Content', 'Comment'], '©des':['Content', 'Description'], '©cpy':['People', 'Copyright'], '©enc':['Software', 'Encoded by'], 'auth':['People', 'Author'], 'titl':['Content', 'Title']};
function mtIso(b, add, st){
  let heif = false, items = null, locs = null, idat = null, keys = [];
  const put = (gk, v) => { if(!gk || v == null || v === '') return; v = String(v).replace(/\0+$/, '').trim(); if(!v) return;
    if(/GPS \(ISO 6709\)/.test(gk[1])){ const g = mtIso6709(v); if(g && !st.gps) st.gps = {...g, src:'video metadata'}; add('Where', gk[1], v); return; }
    if(/Recorded|Date/.test(gk[1])){ const t = mtDate(v); if(t != null && st.taken == null){ st.taken = t; st.tz = /(Z|[+-]\d{2}:?\d{2})$/.test(v) ? 'explicit' : 'assumed'; } }
    if(gk[0] === 'Software') st.soft.add(v); add(gk[0], gk[1], v); };
  const ilstData = (a, z, cb) => mtBoxes(b, a, z, (t, d, e) => { if(t === 'data'){ const kind = mtU32(b, d) & 0xffffff; cb(kind === 1 || kind === 2 || kind === 0 ? (kind === 2 ? new TextDecoder('utf-16be').decode(b.subarray(d + 8, e)) : mtUtf8(b, d + 8, e)) : kind === 21 || kind === 22 || kind === 23 ? (e - d - 8 === 4 ? (kind === 23 ? new DataView(b.buffer, b.byteOffset + d + 8, 4).getFloat32(0) : mtU32(b, d + 8)) : e - d - 8 === 2 ? mtU16(b, d + 8) : b[d + 8]) : ''); } });
  const meta = (a, z) => { /* ISO meta is a full box (4 bytes of version), QuickTime's is not */ const qt = mtStr(b, a + 4, a + 8) === 'hdlr' && mtU32(b, a) >= 8 && mtU32(b, a) < 400; const s = qt ? a : a + 4;
    mtBoxes(b, s, z, (t, d, e) => {
      if(t === 'keys'){ const n = mtU32(b, d + 4); let p = d + 8; keys = []; for(let i = 0; i < n && p + 8 <= e && i < 500; i++){ const ks = mtU32(b, p); if(ks < 8) break; keys.push(mtStr(b, p + 8, p + ks)); p += ks; } }
      else if(t === 'ilst') mtBoxes(b, d, e, (t2, d2, e2) => { const idx = mtU32(b, d2 - 4); const key = keys.length && idx >= 1 && idx <= keys.length ? keys[idx - 1] : t2; ilstData(d2, e2, v => put(MT_QT_KEY[key] || MT_UDTA[t2] || (/^com\.(apple|android)\./.test(key) ? ['Content', key.split('.').slice(-1)[0]] : null), v)); });
      else if(t === 'iinf'){ heif = true; const v = b[d]; let p = d + 4 + (v === 0 ? 2 : 4); items = []; mtBoxes(b, p, e, (t2, d2) => { if(t2 !== 'infe') return; const iv = b[d2]; let q = d2 + 4; const id = iv >= 3 ? mtU32(b, q) : mtU16(b, q); q += iv >= 3 ? 4 : 2; q += 2; const ty = mtStr(b, q, q + 4); q += 4; const ne = b.indexOf(0, q); let ct = ''; if(ty === 'mime'){ const ce = b.indexOf(0, ne + 1); ct = mtStr(b, ne + 1, ce); } items.push({id, type:ty, ct}); }); }
      else if(t === 'iloc'){ const v = b[d], osz = b[d + 4] >> 4, lsz = b[d + 4] & 15, bsz = b[d + 5] >> 4, isz = v >= 1 ? b[d + 5] & 15 : 0; let p = d + 6; const n = v < 2 ? mtU16(b, p) : mtU32(b, p); p += v < 2 ? 2 : 4;
        const rd = sz => { let x = 0; for(let i = 0; i < sz; i++) x = x * 256 + b[p + i]; p += sz; return x; }; locs = new Map();
        for(let i = 0; i < n && p < e && i < 5000; i++){ const id = v < 2 ? rd(2) : rd(4), cm = v >= 1 ? rd(2) & 15 : 0; rd(2); const base = rd(bsz), ec = rd(2), ex = []; for(let j = 0; j < ec && j < 64; j++){ if(isz) rd(isz); ex.push([base + rd(osz), rd(lsz)]); } locs.set(id, {cm, ex}); } }
      else if(t === 'idat') idat = d;
    }); };
  const walk = (a, z, path) => mtBoxes(b, a, z, (t, d, e, depth) => {
    if(t === 'ftyp'){ const br = mtStr(b, d, d + 4) + ' ' + mtStr(b, d + 8, e); if(/heic|heix|hevc|mif1|msf1|avif|avis/.test(br)) heif = true; add('File', 'Container brand', mtStr(b, d, d + 4).trim()); }
    else if(t === 'moov' || t === 'trak' || t === 'mdia' || t === 'udta' && path !== 'udta') walk(d, e, t);
    else if(t === 'mvhd'){ const v = b[d], c = v === 1 ? mtU32(b, d + 4) * 4294967296 + mtU32(b, d + 8) : mtU32(b, d + 4); const ts = (c - 2082844800) * 1000; if(c > 2082844800 && ts < Date.now() + 864e5 * 365){ st.vidTime = ts; add('When', 'Recorded (container, UTC)', new Date(ts).toISOString().replace('.000Z', 'Z')); }
      const scale = v === 1 ? mtU32(b, d + 20) : mtU32(b, d + 12), dur = v === 1 ? mtU32(b, d + 24) * 4294967296 + mtU32(b, d + 28) : mtU32(b, d + 16); if(scale && dur) add('File', 'Length', (dur / scale).toFixed(1) + ' s'); }
    else if(t === 'meta') meta(d, e);
    else if(path === 'udta' && MT_UDTA[t]){ const n = mtU16(b, d); const v = n > 0 && n <= e - d - 4 ? mtUtf8(b, d + 4, d + 4 + n) : (mtStr(b, d, d + 4) === '\0\0\0\0' || mtU32(b, d) === e - d) ? '' : mtUtf8(b, d, e); if(v) put(MT_UDTA[t], v); else ilstData(d, e, x => put(MT_UDTA[t], x)); }
    else if(path === 'udta' && t === 'loci'){ /* 3GPP location: lon/lat as 16.16 fixed */ let p = d + 6; while(p < e && b[p]) p++; p += 2; const fx = o => (mtU32(b, o) | 0) / 65536, lon = fx(p), lat = fx(p + 4); if(!st.gps && Math.abs(lat) <= 90 && Math.abs(lon) <= 180 && (lat || lon)) st.gps = {lat:+lat.toFixed(6), lon:+lon.toFixed(6), src:'3GPP location'}; }
    else if(t === 'uuid' && [...b.subarray(d, d + 16)].map(x => x.toString(16).padStart(2, '0')).join('') === 'be7acfcb97a942e89c71999491e3afac') mtXmp(mtUtf8(b, d + 16, e), add, st);
    else if(t === 'XMP_') mtXmp(mtUtf8(b, d, e), add, st);
  });
  walk(0, b.length, '');
  if(heif && items && locs){ /* the Exif and XMP items of a HEIC/AVIF picture */
    for(const it of items){ const L = locs.get(it.id); if(!L || !L.ex.length) continue; const [off, len] = L.ex[0], at = L.cm === 1 && idat != null ? idat + off : off; if(at + len > b.length || len < 8) continue;
      if(it.type === 'Exif'){ const skip = mtU32(b, at); const tiff = at + 4 + skip; try{ mtExif(parseTiff(b, tiff), add, st); }catch(e){} }
      else if(it.type === 'mime' && /rdf\+xml|xmp/i.test(it.ct)) mtXmp(mtUtf8(b, at, at + len), add, st); } }
}
/* ---------- MP3 ID3v2 ---------- */
function mtId3(b, add, st){
  const ver = b[3], sz = ((b[6] & 127) << 21) | ((b[7] & 127) << 14) | ((b[8] & 127) << 7) | (b[9] & 127); let o = 10; const z = Math.min(b.length, 10 + sz);
  if(b[5] & 0x40) o += ver === 4 ? ((b[10] & 127) << 21 | (b[11] & 127) << 14 | (b[12] & 127) << 7 | (b[13] & 127)) : mtU32(b, 10) + 4;
  const F = {TIT2:['Content', 'Title'], TPE1:['People', 'Artist'], TPE2:['People', 'Album artist'], TALB:['Content', 'Album'], TYER:['When', 'Year'], TDRC:['When', 'Recorded'], TCOP:['People', 'Copyright'], TENC:['Software', 'Encoded by'], TSSE:['Software', 'Encoder settings'], TOWN:['People', 'Owner'], TCOM:['People', 'Composer'], COMM:['Content', 'Comment'], TXXX:['Content', 'Extra']};
  const txt = (enc, a, e) => { const u = b.subarray(a, e); const s = enc === 1 ? new TextDecoder(u[0] === 0xfe ? 'utf-16be' : 'utf-16le').decode(u.subarray(2)) : enc === 2 ? new TextDecoder('utf-16be').decode(u) : enc === 3 ? new TextDecoder().decode(u) : mtStr(b, a, e); return s.replace(/\0+/g, ' — ').replace(/^ — | — $/g, '').trim(); };
  const got = new Map();
  while(o + 10 <= z && /^[A-Z0-9]{4}$/.test(mtStr(b, o, o + 4))){ const id = mtStr(b, o, o + 4), fs = ver === 4 ? ((b[o + 4] & 127) << 21 | (b[o + 5] & 127) << 14 | (b[o + 6] & 127) << 7 | (b[o + 7] & 127)) : mtU32(b, o + 4), d = o + 10; if(!fs || d + fs > z) break;
    if(F[id]){ const enc = b[d]; let v = id === 'COMM' ? txt(enc, d + 4, d + fs) : txt(enc, d + 1, d + fs); if(v){ const k = F[id][1]; if(!got.has(k)) got.set(k, [F[id][0], new Set()]); got.get(k)[1].add(v.slice(0, 300)); if(/^T(ENC|SSE)$/.test(id)) st.soft.add(v); } }
    o = d + fs; }
  for(const [k, [g, v]] of got) add(g, k, [...v].join('; '));
}
/* ---------- PDF ---------- */
async function mtPdf(b, add, st){
  const P = pdfInfo(b); let info = {...P.info};
  /* PDF 1.5+ keeps the document information inside compressed object streams: open them when the plain text has none */
  if(!info.Author && !info.Creator && !info.Producer && P.keys['/ObjStm'] || !info['XMP creator tool'] && /\/Type\s*\/Metadata/.test(mtStr(b, 0, Math.min(b.length, 4e6)))){
    const s = mtStr(b, 0, Math.min(b.length, 30e6)), parts = []; let n = 0;
    for(const m of s.matchAll(/<<((?:(?!<<|stream)[\s\S]){0,600}?\/FlateDecode[\s\S]{0,400}?)>>\s*stream\r?\n/g)){ if(++n > 300) break; if(!/\/ObjStm|\/Metadata|\/XRef/.test(m[1])) continue; const L = (m[1].match(/\/Length\s+(\d+)(?!\s+\d+\s+R)/) || [])[1];
      const a = m.index + m[0].length, e = L ? a + +L : s.indexOf('endstream', a); if(e <= a) continue;
      try{ parts.push(new TextDecoder('latin1').decode(await decompressCapped(b.subarray(a, e), 'deflate', 8 << 20))); }catch(err){} }
    if(parts.length){ const inner = pdfInfo(Uint8Array.from(parts.join('\n'), c => c.charCodeAt(0) & 255)); for(const [k, v] of Object.entries(inner.info)) if(!info[k]) info[k] = v; }
  }
  const T = {Title:['Content', 'Title'], Subject:['Content', 'Subject'], Keywords:['Content', 'Keywords'], Author:['People', 'Author'], 'XMP author':['People', 'Author (XMP)'], Creator:['Software', 'Made with'], Producer:['Software', 'Converted to PDF by'], 'XMP creator tool':['Software', 'Made with (XMP)'],
    CreationDate:['When', 'Created'], ModDate:['When', 'Modified'], 'XMP created':['When', 'Created (XMP)'], 'Document ID':['File', 'Document ID']};
  for(const [k, v] of Object.entries(info)) if(T[k] && v) add(T[k][0], T[k][1], v);
  for(const k of ['Creator', 'Producer', 'XMP creator tool']) if(info[k]) st.soft.add(info[k]);
  const c = mtDate(info.CreationDate) ?? mtDate(info['XMP created']); if(c != null){ st.taken = c; st.tz = /(Z|[+-]\d{2}:?'?\d{2}'?)\s*$/.test(info.CreationDate || info['XMP created'] || '') ? 'explicit' : 'assumed'; } const mo = mtDate(info.ModDate); if(mo != null) st.mod = mo;
  add('File', 'PDF version', P.version); if(P.keys['/Page']) add('File', 'Pages', P.keys['/Page']); if(P.updates) { add('File', 'Saved again after creation', P.updates + ' time' + (P.updates > 1 ? 's' : '')); st.pdfUpdates = P.updates; }
  if(P.keys['/JS'] || P.keys['/JavaScript'] || P.keys['/Launch'] || P.keys['/OpenAction'] && P.keys['/JS']) st.flags.push({t:'Contains script or launch actions — open with care', tone:'red'});
}
/* ---------- Word / Excel / PowerPoint ---------- */
async function mtOffice(b, add, st){
  const Z = await zipInfo(b); if(!Z || !Z.office) return; const O = Z.office;
  const T = {Title:['Content', 'Title'], Subject:['Content', 'Subject'], Author:['People', 'Author'], 'Last modified by':['People', 'Last saved by'], Company:['People', 'Company'], Created:['When', 'Created'], Modified:['When', 'Last saved'], Printed:['When', 'Last printed'],
    Revision:['File', 'Revision'], Application:['Software', 'Made with'], Template:['Software', 'Template'], 'Edit minutes':['File', 'Total editing time (minutes)']};
  for(const [k, v] of Object.entries(O)) if(T[k] && v && String(v).trim() && !(k === 'Edit minutes' && +v === 0)) add(T[k][0], T[k][1], String(v).trim());
  if(O.Application) st.soft.add(O.Application.trim()); const c = mtDate(O.Created); if(c != null){ st.taken = c; st.tz = /Z$|[+-]\d{2}:\d{2}$/.test(O.Created) ? 'explicit' : 'assumed'; } const m = mtDate(O.Modified); if(m != null) st.mod = m;
  if(Z.macros && Z.macros.length) st.flags.push({t:'Contains macros', tone:'red'}); if(Z.external && Z.external.length) st.flags.push({t:'Links to outside content (template or object)', tone:'red'});
}
/* ---------- the one entry point ---------- */
async function metaRead(b, name, type){
  if(!(b instanceof Uint8Array)) b = new Uint8Array(b); const F = [], seen = new Set(), st = {gps:null, taken:null, mod:null, soft:new Set(), ai:[], flags:[], exif:null};
  const add = (g, k, v) => { if(v == null) return; v = String(v).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, '').trim(); if(!v || v === '0000:00:00 00:00:00') return; const key = g + '|' + k + '|' + v, same = /^(Device|Software|Content)$/.test(g) ? g + '||' + v.toLowerCase() : key; if(seen.has(key) || seen.has(same)) return; seen.add(key); seen.add(same); F.push({g, k, v:v.slice(0, 1200)}); };
  const h = mtStr(b, 0, 12); let fmt = '';
  try{
    if(b[0] === 0xff && b[1] === 0xd8){ fmt = 'JPEG picture'; mtJpeg(b, add, st); }
    else if(h.startsWith('\x89PNG')){ fmt = 'PNG picture'; await mtPng(b, add, st); }
    else if(h.startsWith('RIFF') && h.slice(8, 12) === 'WEBP'){ fmt = 'WebP picture'; mtWebp(b, add, st); }
    else if(h.startsWith('II*\0') || h.startsWith('MM\0*')){ fmt = 'TIFF picture'; try{ mtExif(parseTiff(b, 0), add, st); }catch(e){} }
    else if(h.slice(4, 8) === 'ftyp'){ mtIso(b, add, st); const br = mtStr(b, 8, 12); fmt = /hei|mif1|msf1|hevc/.test(br) ? 'HEIC picture' : /avi[fs]/.test(br) ? 'AVIF picture' : /^qt/.test(br) ? 'QuickTime video' : /^3g/.test(br) ? '3GP video' : /M4A|M4B/.test(br) ? 'MP4 audio' : 'MP4 video'; }
    else if(h.startsWith('ID3')){ fmt = 'MP3 audio'; mtId3(b, add, st); }
    else if(h.startsWith('%PDF')){ fmt = 'PDF document'; await mtPdf(b, add, st); }
    else if(typeof isCfb === 'function' && isCfb(b)){ fmt = mtCfb(b, add, st) || 'Office file'; }
    else if(h.startsWith('PK\x03\x04') && typeof mtOdf === 'function' && (mtStr(b, 30, 38) === 'mimetype' && /opendocument/.test(mtStr(b, 38, 90)) || /\.(odt|ods|odp|odg|ott|ots|otp)$/i.test(name || '') || /opendocument/.test(type || ''))){ fmt = await mtOdf(b, add, st); }
    else if(h.startsWith('PK\x03\x04') && /\.(docx|docm|xlsx|xlsm|pptx|pptm|dotx|dotm)$/i.test(name || '') || h.startsWith('PK\x03\x04') && /officedocument|ms-word|ms-excel|ms-powerpoint/.test(type || '')){ fmt = 'Office document'; await mtOffice(b, add, st); }
  }catch(e){ if(!fmt) fmt = ''; }
  /* what stands out */
  const soft = [...st.soft].filter(Boolean), ex = st.exif || {};
  if(st.gps){ const g = st.gps; add('Where', 'Location', `${g.lat}, ${g.lon}` + (g.alt != null ? ` · ${g.alt} m altitude` : '')); if(g.dir != null) add('Where', 'Camera facing', `${g.dir}° (${['north', 'north-east', 'east', 'south-east', 'south', 'south-west', 'west', 'north-west'][Math.round(g.dir / 45) % 8]}${g.dirRef ? ', ' + g.dirRef : ''})`); if(g.err != null) add('Where', 'GPS accuracy', '± ' + g.err + ' m'); if(g.speed) add('Where', 'Moving at', g.speed);
    st.flags.push({t:'Location recorded' + (g.src ? ' (' + g.src + ')' : ''), tone:'amber'}); }
  const edit = soft.find(s => typeof PIC_EDIT !== 'undefined' && PIC_EDIT.test(s)); if(edit && /picture/.test(fmt)) st.flags.push({t:'Saved by an editing program: ' + edit, tone:'amber'});
  if(st.ai.length || soft.some(s => MT_AI.test(s))) st.flags.push({t:'Marked as AI-generated: ' + (st.ai[0] || soft.find(s => MT_AI.test(s))), tone:'red'});
  if(st.c2pa) st.flags.push({t:'Carries Content Credentials (C2PA) — check them with a C2PA verifier', tone:''});
  const tk = st.taken, tw = mtDate(ex.Taken), md = mtDate(ex.Modified); if(tw != null && md != null && Math.abs(md - tw) > 6e4 * 2 && /picture/.test(fmt)) st.flags.push({t:'Changed after it was taken (' + E.fmtGap(Math.abs(md - tw)) + ' later)', tone:'amber'});
  if(st.mod != null && tk != null && st.mod - tk > 864e5 && /document/.test(fmt)) st.flags.push({t:'Last saved ' + E.fmtGap(st.mod - tk) + ' after it was created', tone:''});
  if(tk != null && tk > Date.now() + 864e5) st.flags.push({t:'Creation date in the future — the clock was wrong or the date was changed', tone:'amber'});
  const people = F.filter(f => f.g === 'People' && /^(Author|Author \(XMP\)|Author \(Windows\)|By-line|Artist|Camera owner|Last saved by|Album artist|Owner)$/.test(f.k)).map(f => f.v);
  const lastBy = F.find(f => f.k === 'Last saved by'), auth = F.find(f => f.k === 'Author'); if(lastBy && auth && lastBy.v.toLowerCase() !== auth.v.toLowerCase()) st.flags.push({t:`Written by ${auth.v}, last saved by ${lastBy.v}`, tone:''});
  if(/picture/.test(fmt) && !F.some(f => f.g === 'Device' || f.g === 'When')) st.flags.push({t:'No camera or date — stripped, a screenshot, or saved from a website or app', tone:''});
  for(const f of st.flags) F.unshift({g:'Stands out', k:'', v:f.t, tone:f.tone});
  F.sort((a, b) => MT_GROUPS.indexOf(a.g) - MT_GROUPS.indexOf(b.g));
  let gen = null; if(/picture/.test(fmt) && typeof aiGenRead === 'function'){ try{ gen = await aiGenRead(b); }catch(e){} }
  if(gen && !st.flags.some(f => /AI-generated/.test(f.t))){ const t = 'Marked as AI-generated: ' + (gen.tool || gen.c2pa || 'IPTC digital source'); st.flags.push({t, tone:'red'}); F.unshift({g:'Stands out', k:'', v:t, tone:'red'}); }
  return {gen, fmt, fields:F.slice(0, 160), gps:st.gps, taken:st.taken ?? st.vidTime ?? null, tz:st.taken != null ? st.tz || 'explicit' : 'explicit', people:[...new Set(people)].slice(0, 12), software:soft.slice(0, 12), flags:st.flags, at:Date.now()};
}
/* a file too big to hold in memory: video keeps its metadata in the 'moov' box (start or end), so read every box but the media data */
async function metaReadFile(f){
  if(f.size <= 64 * 1048576) return metaRead(new Uint8Array(await f.arrayBuffer()), f.name, f.type);
  const head = new Uint8Array(await f.slice(0, 16).arrayBuffer());
  if(mtStr(head, 4, 8) === 'ftyp'){ const parts = []; let o = 0, n = 0;
    while(o + 8 <= f.size && n++ < 200){ const h = new Uint8Array(await f.slice(o, o + 16).arrayBuffer()); let size = mtU32(h, 0), hdr = 8; const t = mtStr(h, 4, 8);
      if(size === 1){ size = mtU32(h, 8) * 4294967296 + mtU32(h, 12); hdr = 16; } else if(size === 0) size = f.size - o; if(size < hdr) break;
      if(t !== 'mdat' && t !== 'free' && t !== 'skip' && size <= 64 * 1048576) parts.push(new Uint8Array(await f.slice(o, o + size).arrayBuffer())); o += size; }
    const len = parts.reduce((a, p) => a + p.length, 0), all = new Uint8Array(len); let at = 0; for(const p of parts){ all.set(p, at); at += p.length; }
    return metaRead(all, f.name, f.type); }
  return metaRead(new Uint8Array(await f.slice(0, 16 * 1048576).arrayBuffer()), f.name, f.type);
}
/* the compact copy kept with a stored file */
const metaKeep = M => M && (M.fields.length || M.gps) ? {gen:M.gen || null, fmt:M.fmt, fields:M.fields.slice(0, 120), gps:M.gps ? {lat:M.gps.lat, lon:M.gps.lon, alt:M.gps.alt ?? null, dir:M.gps.dir ?? null, src:M.gps.src || ''} : null, taken:M.taken, tz:M.tz || 'explicit', people:M.people, software:M.software, flags:M.flags.map(f => ({t:f.t, tone:f.tone})), at:M.at} : {fmt:M ? M.fmt : '', fields:[], none:true, at:Date.now()};
/* lines for the evidence text: searchable, and what they name becomes entities */
function metaLines(M){ if(!M || !M.fields || !M.fields.length) return ''; const L = [];
  for(const f of M.fields){ if(f.g === 'Stands out') continue; if(/Edit history|Generation settings|Generator workflow|Document ID|Content ID|Image ID/.test(f.k)) continue; L.push(`${f.k}: ${f.v.replace(/\s+/g, ' ').slice(0, 200)}`); if(L.length >= 40) break; }
  return L.join('\n'); }
/* shown in the evidence panel under each file */
function metaHtml(a, rid){
  const M = a.meta; if(!M) return `<div class="mt-x"><button class="btn xs" data-act="mtRead" data-id="${esc(rid)}" data-v="${esc(a.id)}">${ico('scan-search','sm')}Read metadata</button></div>`;
  if(M.none || !M.fields.length) return `<div class="mt-x t3 small">No metadata in this file${/picture/.test(M.fmt || '') ? ' — stripped, a screenshot, or saved from a website or app' : ''}.</div>`;
  const open = UI.mtOpen && UI.mtOpen === a.id, F = M.fields, lead = F.filter(f => f.g !== 'Stands out' && /^(Make|Model|Taken|Recorded|Created|Author|Last saved by|Made with|Software|Location|Camera facing|City|Country|Place|By-line|Time zone \(taken\))$/.test(f.k)).slice(0, 8);
  const rows = L => L.map(f => `<div class="mt-r"><span class="t3">${esc(f.k)}</span><span class="mt-v">${esc(f.v)}</span><button class="iconbtn sm" data-act="mtCopy" data-v="${esc(f.v)}" aria-label="Copy ${esc(f.k)}">${ico('copy','sm')}</button></div>`).join('');
  const groups = MT_GROUPS.filter(g => g !== 'Stands out').map(g => { const L = F.filter(f => f.g === g); return L.length ? `<h5>${g}</h5>${rows(L)}` : ''; }).join('');
  return `<div class="mt"><div class="mt-h"><b>${esc(M.fmt || 'Metadata')}</b>${M.gps ? `<button class="btn xs" data-act="mtMap" data-id="${esc(rid)}" data-v="${esc(a.id)}">${ico('map-pin','sm')}On the map</button>` : ''}</div>
    ${(M.flags || []).length ? `<div class="wrap mt-f">${M.flags.map(f => `<span class="chip sq ${f.tone || ''}">${esc(f.t)}</span>`).join('')}</div>` : ''}
    ${open ? groups : rows(lead)}<button class="lnk small" data-act="mtMore" data-v="${esc(a.id)}">${open ? 'Show less' : `All ${F.filter(f => f.g !== 'Stands out').length} facts`}</button></div>`;
}
/* files stored before this reader existed get read once, in the background */
let MT_SCAN = null;
function metaScanFiles(){ clearTimeout(MT_SCAN); MT_SCAN = setTimeout(async () => {
  const todo = []; for(const r of DB.records) for(const a of r.att || []) if(!a.meta && a.size <= 50 * 1048576) todo.push([r, a]);
  if(!todo.length) return; let changed = 0;
  for(const [r, a] of todo.slice(0, 200)){ try{ const bl = await fileBlob(a.id); if(!bl){ a.meta = {none:true, fields:[], at:Date.now()}; continue; } const M = await metaRead(new Uint8Array(await bl.arrayBuffer()), a.name, a.type); a.meta = metaKeep(M); if(metaApply(r, a)) changed++; }catch(e){ a.meta = {none:true, fields:[], at:Date.now()}; } }
  rev++; cache = {}; save(); if(changed && UI.route && UI.route.area === 'case') renderMain();
}, 1200); }
/* a file's metadata into its evidence: GPS, the text lines, and the entities they name */
function metaApply(r, a){
  const M = a.meta; if(!M || M.none) return false; let ch = false;
  if(M.gps && !a.gps){ a.gps = {lat:M.gps.lat, lon:M.gps.lon, alt:M.gps.alt}; ch = true; }
  const lines = metaLines(M); if(lines && r.source === 'attachment' && !String(r.body).includes('\n— Metadata —\n')){ r.body = String(r.body) + '\n— Metadata —\n' + lines;
    if(M.gps && !/GPS: -?\d/.test(r.body)) r.body += `\n${/video/.test(M.fmt) ? 'Video' : /picture/.test(M.fmt) ? 'EXIF' : 'File'} GPS: ${M.gps.lat.toFixed(6)}, ${M.gps.lon.toFixed(6)}`;
    const have = new Set((r.ents || []).map(e => e.k + ':' + String(e.v).toLowerCase())); for(const e of extractRich(lines + (M.gps ? `\n${M.gps.lat.toFixed(6)}, ${M.gps.lon.toFixed(6)}` : ''))){ if(e.k === 'domain' && /\.(exe|app|dll)$/i.test(e.v)) continue; const k = e.k + ':' + String(e.v).toLowerCase(); if(!have.has(k)){ have.add(k); (r.ents = r.ents || []).push({k:e.k, v:e.v}); } } ch = true; }
  return ch;
}
const MT_ACTS = {
  mtRead:async (id, v) => { const r = recById(id), a = r && (r.att || []).find(x => x.id === v); if(!a) return; const bl = await fileBlob(a.id); if(!bl) return toast('The file is missing from this browser');
    a.meta = metaKeep(await metaRead(new Uint8Array(await bl.arrayBuffer()), a.name, a.type)); metaApply(r, a); mutate('read file metadata'); renderAll(); },
  mtMore:(id, v) => { UI.mtOpen = UI.mtOpen === v ? null : v; if(typeof renderInsp === 'function') renderInsp(); else renderAll(); },
  mtCopy:(id, v) => copyText(v),
  mtMap:(id, v) => { const r = recById(id), a = r && (r.att || []).find(x => x.id === v); if(!a || !a.meta || !a.meta.gps) return; const k = (+a.meta.gps.lat).toFixed(4) + ',' + (+a.meta.gps.lon).toFixed(4);
    DB.active = r.caseId; UI.map = {sel:k}; go(caseHash(r.caseId, 'map')); setTimeout(() => { if(typeof mapSelect === 'function') mapSelect(k); }, 60); },
};
