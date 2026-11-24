/* Clean before sending (OPSEC): take out what a file says about whoever made it before it goes to a subject, a forum or a
   persona's contact — camera, serial numbers, location, dates, names, company, software, edit history, comments' authors,
   file paths, thumbnails — and then read the cleaned copy back with the same metadata reader to show what is left.
   Pictures (JPEG, PNG, WebP) keep every pixel: only the metadata blocks are dropped, and a turned photo keeps its turn.
   PDFs are cleaned in place (the document's text and layout are untouched). Word, Excel and PowerPoint files are rebuilt
   with blank properties, anonymous comment and change authors and no hidden paths. Everything runs in this browser. */
const CL_CRC = (() => { const t = new Uint32Array(256); for(let n = 0; n < 256; n++){ let c = n; for(let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
const clCrc = b => { let c = 0xffffffff; for(let i = 0; i < b.length; i++) c = CL_CRC[(c ^ b[i]) & 255] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };
const clCat = parts => { let n = 0; for(const p of parts) n += p.length; const u = new Uint8Array(n); let o = 0; for(const p of parts){ u.set(p, o); o += p.length; } return u; };
const clAscii = s => Uint8Array.from(s, c => c.charCodeAt(0) & 255);

/* ---------- JPEG: keep JFIF, colour profile, Adobe colour marker and the picture; drop EXIF, XMP, IPTC, comments, C2PA, extra images ---------- */
function clJpeg(b, R){
  if(b[0] !== 0xff || b[1] !== 0xd8) throw new Error('not a JPEG'); const parts = [b.subarray(0, 2)]; let o = 2, orient = 1;
  const name = (m, seg) => { const id = latin1(seg, 4, Math.min(seg.length, 40)); if(m === 0xe1) return /^Exif/.test(id) ? 'EXIF (camera, settings, dates, location, serials)' : /ns\.adobe\.com\/(xap|xmp)/.test(id) ? 'XMP (software, edit history, IDs)' : 'APP1 block';
    if(m === 0xed) return 'Photoshop / IPTC (caption, author, place)'; if(m === 0xeb) return 'JUMBF / Content Credentials (C2PA)'; if(m === 0xfe) return 'Comment'; if(m === 0xe2 && /^MPF/.test(id)) return 'Multi-picture index (extra images)'; return 'APP' + (m - 0xe0) + ' block (' + id.replace(/[^\x20-\x7e]/g, '').slice(0, 14) + ')'; };
  while(o + 4 <= b.length){
    if(b[o] !== 0xff){ throw new Error('broken JPEG structure'); } const m = b[o + 1];
    if(m === 0xd8 || (m >= 0xd0 && m <= 0xd7) || m === 0x01){ parts.push(b.subarray(o, o + 2)); o += 2; continue; }
    const len = (b[o + 2] << 8) | b[o + 3], seg = b.subarray(o, o + 2 + len);
    if(m === 0xda){ // start of scan: the picture data runs to the end-of-image marker
      let e = o + 2 + len; for(; e < b.length - 1; e++) if(b[e] === 0xff && b[e + 1] === 0xd9) break;
      parts.push(b.subarray(o, Math.min(b.length, e + 2))); if(e + 2 < b.length - 2) R.removed.push(`Data after the end of the picture (${fmtBytes(b.length - e - 2)}) — often a second image, a depth map or something hidden`); break; }
    const keep = m === 0xe0 || (m === 0xe2 && latin1(seg, 4, 15) === 'ICC_PROFILE') || m === 0xee || (m >= 0xc0 && m <= 0xcf) || m === 0xdb || m === 0xdd;
    if(m === 0xe1 && latin1(seg, 4, 8) === 'Exif'){ try{ const t = 10, le = b[o + t] === 0x49, u16 = p => le ? b[p] | (b[p + 1] << 8) : (b[p] << 8) | b[p + 1], u32 = p => le ? (b[p] | (b[p + 1] << 8) | (b[p + 2] << 16) | (b[p + 3] << 24)) >>> 0 : ((b[p] << 24) | (b[p + 1] << 16) | (b[p + 2] << 8) | b[p + 3]) >>> 0;
      const ifd = o + t + u32(o + t + 4), n = u16(ifd); for(let i = 0; i < n; i++){ const e = ifd + 2 + i * 12; if(u16(e) === 0x0112) orient = u16(e + 8); } }catch(e){} }
    if(keep) parts.push(seg); else R.removed.push(name(m, seg) + ' — ' + fmtBytes(seg.length));
    o += 2 + len; }
  if(orient > 1 && orient <= 8){ // keep the turn: a minimal EXIF with only the orientation
    const tiff = [0x4d, 0x4d, 0, 0x2a, 0, 0, 0, 8, 0, 1, 0x01, 0x12, 0, 3, 0, 0, 0, 1, 0, orient, 0, 0, 0, 0, 0, 0, 0, 0], body = clCat([clAscii('Exif\0\0'), Uint8Array.from(tiff)]);
    parts.splice(1, 0, Uint8Array.from([0xff, 0xe1, (body.length + 2) >> 8, (body.length + 2) & 255]), body); R.kept.push('Orientation (so the photo still shows the right way up)'); }
  return clCat(parts);
}
/* ---------- PNG: keep the picture and colour chunks; drop text, EXIF, time, C2PA and anything private ---------- */
function clPng(b, R){
  const parts = [b.subarray(0, 8)], KEEP = /^(IHDR|PLTE|tRNS|IDAT|IEND|gAMA|cHRM|sRGB|iCCP|sBIT|pHYs|acTL|fcTL|fdAT)$/; let o = 8;
  while(o + 12 <= b.length){ const len = ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0, type = latin1(b, o + 4, o + 8), seg = b.subarray(o, o + 12 + len);
    if(KEEP.test(type)) parts.push(seg); else { const key = /tEXt|zTXt|iTXt/.test(type) ? latin1(b, o + 8, Math.min(o + 8 + len, b.indexOf(0, o + 8) < 0 ? o + 8 : b.indexOf(0, o + 8))) : '';
      R.removed.push({tEXt:'Text', zTXt:'Text', iTXt:'Text', eXIf:'EXIF', tIME:'Last-changed time', caBX:'Content Credentials (C2PA)'}[type] ? `${{tEXt:'Text', zTXt:'Text', iTXt:'Text', eXIf:'EXIF', tIME:'Last-changed time', caBX:'Content Credentials (C2PA)'}[type]}${key ? ' “' + key + '”' : ''} — ${fmtBytes(seg.length)}` : `${type} chunk — ${fmtBytes(seg.length)}`); }
    o += 12 + len; if(type === 'IEND') break; }
  if(o < b.length - 1) R.removed.push(`Data after the end of the picture (${fmtBytes(b.length - o)})`);
  return clCat(parts);
}
/* ---------- WebP ---------- */
function clWebp(b, R){
  const parts = [], le32 = (p) => (b[p] | (b[p + 1] << 8) | (b[p + 2] << 16) | (b[p + 3] << 24)) >>> 0; let o = 12, vp8x = null;
  while(o + 8 <= b.length){ const id = latin1(b, o, o + 4), len = le32(o + 4), seg = b.subarray(o, o + 8 + len + (len & 1));
    if(id === 'EXIF' || id === 'XMP ') R.removed.push((id === 'EXIF' ? 'EXIF' : 'XMP') + ' — ' + fmtBytes(seg.length)); else { const c = seg.slice(); if(id === 'VP8X') vp8x = c; parts.push(c); }
    o += 8 + len + (len & 1); }
  if(vp8x) vp8x[8] &= ~0x0c;   // the "has EXIF" and "has XMP" flags
  const body = clCat(parts), head = clAscii('RIFF\0\0\0\0WEBP'), n = body.length + 4; head[4] = n & 255; head[5] = n >> 8 & 255; head[6] = n >> 16 & 255; head[7] = n >>> 24;
  return clCat([head, body]);
}
const clPdfStr = v => { const s = v.replace(/\\([0-7]{1,3})|\\(.)/g, (m, o, c) => o ? String.fromCharCode(parseInt(o, 8)) : ({n:'\n', r:'', t:' ', b:'', f:''}[c] ?? c));
  if(s.charCodeAt(0) === 254 && s.charCodeAt(1) === 255){ let u = ''; for(let i = 2; i + 1 < s.length; i += 2) u += String.fromCharCode(s.charCodeAt(i) << 8 | s.charCodeAt(i + 1)); return u; }
  return s.replace(/^D:(\d{4})(\d{2})(\d{2})(\d{2})?(\d{2})?(\d{2})?(.*)$/, (m, y, mo, d, h, mi, se, z) => `${y}-${mo}-${d}${h ? ' ' + h + ':' + (mi || '00') + ':' + (se || '00') : ''}${z ? ' ' + z.replace(/'/g, '') : ''}`).replace(/[\u0080-\u009f]/g, c => ({'\u0092':'’', '\u0093':'“', '\u0094':'”', '\u0099':'™'}[c] || '')).replace(/\u00ae/g, '®'); };
const clPdfHex = v => { const h = v.replace(/[^0-9a-f]/gi, ''); let s = ''; for(let i = 0; i + 1 < h.length; i += 2) s += String.fromCharCode(parseInt(h.slice(i, i + 2), 16)); return clPdfStr(s.replace(/\\/g, '\\\\')); };
/* ---------- PDF: blank the document properties, the XMP packet and the file IDs in place, so nothing else moves ---------- */
function clPdf(b, R){
  const out = b.slice(), s = latin1(b, 0, b.length); let n = 0;
  const blank = (a, z) => { for(let i = a; i < z; i++) if(out[i] !== 10 && out[i] !== 13) out[i] = 32; };
  for(const m of s.matchAll(/\/(Author|Creator|Producer|Title|Subject|Keywords|Company|Manager|SourceModified|CreationDate|ModDate|Trapped|AAPL:Keywords)\s*(\(|<(?!<))/g)){
    const at = m.index + m[0].length; let e = at;
    if(m[2] === '('){ let depth = 1; for(; e < s.length && depth; e++){ const c = s[e]; if(c === '\\'){ e++; continue; } if(c === '(') depth++; else if(c === ')') depth--; } e--; }
    else { e = s.indexOf('>', at); if(e < 0) continue; }
    if(e > at){ const v = s.slice(at, e).replace(/^\s+|\s+$/g, ''); if(v.length && v.replace(/0/g, '').length){ blank(at, e); n++; R.removed.push(`${m[1]}: ${m[2] === '(' ? clPdfStr(v).slice(0, 80) : clPdfHex(v).slice(0, 80)}`); } } }
  for(const m of s.matchAll(/<x:xmpmeta[\s\S]*?<\/x:xmpmeta>/g)){ const rep = '<x:xmpmeta xmlns:x="adobe:ns:meta/"></x:xmpmeta>'; if(m[0].length < rep.length) continue;
    for(let i = 0; i < m[0].length; i++) out[m.index + i] = i < rep.length ? rep.charCodeAt(i) : 32; R.removed.push(`XMP packet (${fmtBytes(m[0].length)}) — software, IDs, edit history`); }
  if(/\/Metadata\s+\d+\s+\d+\s+R/.test(s) && !/<x:xmpmeta/.test(s)) R.warn.push('The XMP metadata is stored compressed and was not cleaned. Print to PDF from a viewer, or use exiftool / qpdf, to remove it.');
  for(const m of s.matchAll(/\/ID\s*\[\s*<([0-9a-fA-F]+)>\s*<([0-9a-fA-F]+)>\s*\]/g)){ const a = m.index + m[0].indexOf('<') + 1; for(let i = 0; i < m[1].length; i++) out[a + i] = 48; const b2 = m.index + m[0].lastIndexOf('<') + 1; for(let i = 0; i < m[2].length; i++) out[b2 + i] = 48; R.removed.push('File ID (ties copies of the same file together)'); }
  const saves = (s.match(/%%EOF/g) || []).length; if(saves > 1) R.warn.push(`The file was saved ${saves} times and keeps every earlier version — text taken out in a later save can still be recovered. Print it to a new PDF first, then clean that.`);
  const annots = (s.match(/\/Subtype\s*\/(Text|FreeText|Highlight|Underline|StrikeOut|Popup|Ink)\b/g) || []).length; if(annots) R.warn.push(`${annots} comment${annots > 1 ? 's' : ''} or highlight${annots > 1 ? 's' : ''} can carry the reviewer's name — delete them or flatten the PDF.`);
  if(/\/JavaScript|\/JS\b/.test(s)) R.warn.push('The PDF contains JavaScript.');
  return out;
}
/* ---------- Word, Excel, PowerPoint ---------- */
async function clOffice(b, R){
  const Z = zipOpen(b); if(!Z) throw new Error('not a readable Office file'); if(Z.files.some(f => f.enc)) throw new Error('the file is password-protected');
  const files = [], drop = new Set(), dropT = []; const text = async n => new TextDecoder().decode(await fxZipEntry(b, n, 64 << 20));
  for(const f of Z.files) if(/^docProps\/(custom\.xml|thumbnail\.\w+)$/i.test(f.name)){ drop.add(f.name); dropT.push(f.name); R.removed.push(/custom/i.test(f.name) ? 'Custom properties (often client, project, classification)' : 'Preview thumbnail (a picture of the first page as it was last saved)'); }
  const anon = x => x.replace(/\b(w:author|w15:author|w:initials|author|initials|w15:userId|w15:providerId|userId|providerId|displayName|name)="([^"]*)"/g, (m0, k, v) => {
    if(/^(name)$/.test(k)) return m0; if(/^(w:initials|initials)$/.test(k)) return `${k}="A"`; if(/providerId/i.test(k)) return `${k}="None"`; if(/userId/i.test(k)) return `${k}="Author"`; return `${k}="Author"`; });
  let authors = new Set(), paths = [];
  for(const f of Z.files){ if(drop.has(f.name) || /\/$/.test(f.name)) continue; let data = await fxZipEntry(b, f.name, 256 << 20); if(!data) throw new Error('could not read ' + f.name);
    if(/\.(xml|rels)$/i.test(f.name)){ let x = new TextDecoder().decode(data), y = x;
      for(const m of x.matchAll(/\b(?:w:author|w15:author|author|displayName)="([^"]+)"/g)) if(m[1] !== 'Author') authors.add(m[1]);
      if(f.name === 'docProps/core.xml'){ for(const t of ['dc:creator', 'cp:lastModifiedBy', 'cp:keywords', 'dc:subject', 'dc:description', 'cp:category', 'cp:contentStatus', 'dcterms:created', 'dcterms:modified', 'cp:lastPrinted', 'cp:revision', 'dc:title', 'cp:version', 'dc:identifier', 'dc:language']){
          const re = new RegExp('<' + t + '\\b[^>]*?(?:/>|>([\\s\\S]*?)</' + t + '>)', 'g'); y = y.replace(re, (m0, v) => { if(v && v.trim()) R.removed.push(t.split(':')[1].replace(/^./, c => c.toUpperCase()).replace(/([A-Z])/g, ' $1').trim() + ': ' + v.trim().slice(0, 80)); return ''; }); } }
      else if(f.name === 'docProps/app.xml'){ for(const t of ['Company', 'Manager', 'Template', 'TotalTime', 'HyperlinkBase', 'Application', 'AppVersion']){ const re = new RegExp('<' + t + '\\b[^>]*?(?:/>|>([\\s\\S]*?)</' + t + '>)', 'g'); y = y.replace(re, (m0, v) => { if(v && v.trim() && v.trim() !== '0') R.removed.push((t === 'TotalTime' ? 'Editing time (minutes)' : t === 'AppVersion' ? 'Program version' : t) + ': ' + v.trim().slice(0, 80)); return ''; }); } }
      else {
        y = y.replace(/<w:rsids>[\s\S]*?<\/w:rsids>/g, m0 => { R.removed.push('Editing-session IDs (rsids) — tie this file to other files edited in the same sessions'); return ''; });
        y = y.replace(/<w:attachedTemplate\b[^>]*\/>/, () => { R.removed.push('Link to the template it was made from'); return ''; });
        y = y.replace(/<mc:AlternateContent\b[^>]*>(?:(?!<\/mc:AlternateContent>)[\s\S])*?x15ac:absPath[\s\S]*?<\/mc:AlternateContent>/, m0 => { const p = (m0.match(/url="([^"]*)"/) || [])[1]; if(p) paths.push(p); return ''; });
        y = y.replace(/<x15ac:absPath\b[^>]*\/>/, m0 => { const p = (m0.match(/url="([^"]*)"/) || [])[1]; if(p) paths.push(p); return ''; });
        if(/word\/_rels\/settings\.xml\.rels$/.test(f.name)) y = y.replace(/<Relationship\b[^>]*attachedTemplate[^>]*\/>/g, m0 => { const p = (m0.match(/Target="([^"]*)"/) || [])[1]; if(p) paths.push(decodeURIComponent(p)); return ''; });
        y = y.replace(/<w15:presenceInfo\b[^>]*\/>/g, '');
        if(/^word\//.test(f.name)) y = y.replace(/\s+w:rsid\w*="[0-9A-Fa-f]{8}"/g, '').replace(/<w:rsid(Root)?\b[^>]*\/>/g, '');
        if(/^xl\/(.*\/)?comments?\d*\.xml$/i.test(f.name)) y = y.replace(/<author>([^<]*)<\/author>/g, (m0, a) => { if(a !== 'Author') authors.add(a); return '<author>Author</author>'; });
        y = anon(y);
        if(f.name === '[Content_Types].xml') for(const d of dropT) y = y.replace(new RegExp('<Override\\b[^>]*PartName="/' + d.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '"[^>]*/>', 'g'), '');
        if(/_rels\/\.rels$|^_rels\/\.rels$/.test(f.name)) for(const d of dropT) y = y.replace(new RegExp('<Relationship\\b[^>]*Target="/?' + d.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '"[^>]*/>', 'g'), ''); }
      if(y !== x) data = new TextEncoder().encode(y); }
    files.push({name:f.name, data}); }
  if(authors.size) R.removed.push('Names on comments and tracked changes: ' + [...authors].slice(0, 8).join(', ') + ' — now “Author”');
  if(paths.length) R.removed.push('Folder paths on the author\'s computer: ' + [...new Set(paths)].slice(0, 4).join(', '));
  // what can only be fixed in the program itself
  if(typeof dxOffice === 'function'){ try{ const X = await dxOffice(b); if(X){ if(X.del && X.del.length) R.warn.push(`${X.del.length} tracked deletion${X.del.length > 1 ? 's still hold' : ' still holds'} the deleted words — accept or reject all changes in Word before sending.`);
    if(X.comments && X.comments.length) R.warn.push(`${X.comments.length} comment${X.comments.length > 1 ? 's are' : ' is'} still in the file (${X.comments.length > 1 ? 'their authors are' : 'its author is'} now anonymous) — delete ${X.comments.length > 1 ? 'them' : 'it'} if ${X.comments.length > 1 ? 'they' : 'it'} should not be read.`);
    if(X.hidden && X.hidden.length) R.warn.push(`Hidden or white text: “${String(X.hidden[0]).slice(0, 60)}” — it travels with the file.`);
    const hs = (X.sheets || []).filter(x => x && x.state && x.state !== 'visible'); if(hs.length) R.warn.push(`Hidden sheets: ${hs.slice(0, 4).map(x => x.name).join(', ')} — unhide and check, or delete them.`);
    if(X.notes && X.notes.length) R.warn.push('Speaker notes are still in the presentation.');
    if(X.extLinks && X.extLinks.length) R.warn.push(`Links to other files (${X.extLinks.slice(0, 2).join(', ')}) — they show your folders and servers.`); } }catch(e){} }
  for(const f of files) if(/\.(jpe?g|png)$/i.test(f.name) && /\/media\//.test(f.name)){ const r2 = {removed:[], kept:[], warn:[]}; try{ const c = /png$/i.test(f.name) ? clPng(f.data, r2) : clJpeg(f.data, r2); if(r2.removed.length){ f.data = c; R.removed.push(`${f.name.split('/').pop()}: ${r2.removed.length} metadata block${r2.removed.length > 1 ? 's' : ''} in the picture inside`); } }catch(e){} }
  R.removed = [...new Set(R.removed)];
  return clZip(files);
}
/* a ZIP written fresh: entries compressed again, every date set to 1980-01-01 so the archive does not date the work */
async function clZip(files){
  const local = [], central = []; let off = 0;
  for(const f of files){ const nm = new TextEncoder().encode(f.name), crc = clCrc(f.data);
    let comp = f.data, method = 0; if(f.data.length > 64 && typeof CompressionStream !== 'undefined'){ try{ const c = new Uint8Array(await new Response(new Blob([f.data]).stream().pipeThrough(new CompressionStream('deflate-raw'))).arrayBuffer()); if(c.length < f.data.length){ comp = c; method = 8; } }catch(e){} }
    const h = new DataView(new ArrayBuffer(30)); h.setUint32(0, 0x04034b50, true); h.setUint16(4, 20, true); h.setUint16(6, 0x0800, true); h.setUint16(8, method, true); h.setUint16(10, 0, true); h.setUint16(12, 0x21, true);
    h.setUint32(14, crc, true); h.setUint32(18, comp.length, true); h.setUint32(22, f.data.length, true); h.setUint16(26, nm.length, true); h.setUint16(28, 0, true);
    const c = new DataView(new ArrayBuffer(46)); c.setUint32(0, 0x02014b50, true); c.setUint16(4, 20, true); c.setUint16(6, 20, true); c.setUint16(8, 0x0800, true); c.setUint16(10, method, true); c.setUint16(12, 0, true); c.setUint16(14, 0x21, true);
    c.setUint32(16, crc, true); c.setUint32(20, comp.length, true); c.setUint32(24, f.data.length, true); c.setUint16(28, nm.length, true); c.setUint32(42, off, true);
    local.push(new Uint8Array(h.buffer), nm, comp); central.push(new Uint8Array(c.buffer), nm); off += 30 + nm.length + comp.length; }
  const cd = clCat(central), e = new DataView(new ArrayBuffer(22)); e.setUint32(0, 0x06054b50, true); e.setUint16(8, files.length, true); e.setUint16(10, files.length, true); e.setUint32(12, cd.length, true); e.setUint32(16, off, true);
  return clCat([...local, cd, new Uint8Array(e.buffer)]);
}

/* ---------- one file ---------- */
async function clFile(f){
  const b = new Uint8Array(await f.arrayBuffer()), ext = (f.name.split('.').pop() || '').toLowerCase(), R = {name:f.name, size:f.size, removed:[], kept:[], warn:[], before:null, after:null, out:null, err:''};
  try{ R.before = typeof metaRead === 'function' ? await metaRead(b, f.name, f.type).catch(() => null) : null;
    const h = latin1(b, 0, 12);
    if(b[0] === 0xff && b[1] === 0xd8){ R.kind = 'JPEG picture'; R.out = clJpeg(b, R); }
    else if(h.startsWith('\x89PNG')){ R.kind = 'PNG picture'; R.out = clPng(b, R); }
    else if(h.startsWith('RIFF') && h.slice(8, 12) === 'WEBP'){ R.kind = 'WebP picture'; R.out = clWebp(b, R); }
    else if(h.startsWith('%PDF')){ R.kind = 'PDF document'; R.out = clPdf(b, R); }
    else if(h.startsWith('PK\x03\x04') && /^(docx|docm|xlsx|xlsm|pptx|pptm|dotx|xltx|potx)$/.test(ext)){ R.kind = 'Office document'; R.out = await clOffice(b, R); }
    else if(h.slice(4, 8) === 'ftyp') throw new Error(/hei|mif1|heic/.test(h) ? 'HEIC photos are not rewritten here — export the photo as JPEG first (Photos → Export, or “Most compatible” in the iPhone camera settings), then clean the JPEG.' : 'Videos are not rewritten in the browser. Use mat2, or ffmpeg with -map_metadata -1 -map_chapters -1, in your research environment.');
    else throw new Error('This kind of file is not cleaned here. Pictures (JPEG, PNG, WebP), PDFs and Word, Excel and PowerPoint files are. For others, use mat2 in your research environment.');
    R.after = typeof metaRead === 'function' ? await metaRead(R.out, f.name, f.type).catch(() => null) : null;
    R.sha256 = await sha256Hex(R.out.buffer.slice(R.out.byteOffset, R.out.byteOffset + R.out.byteLength));
    if(R.before && R.before.gps) R.removed.unshift(`Location: ${R.before.gps.lat}, ${R.before.gps.lon}`);
  }catch(e){ R.err = e.message || String(e); R.out = null; }
  return R;
}
/* what the cleaned copy still says (after cleaning, the metadata reader should find only harmless picture facts) */
const CL_HARMLESS = /^(Saved again|Width|Height|Size|Pixels|Colour|Color|Bit depth|Compression|Orientation|Format|Pages|PDF version|Encoding|Resolution|Dimensions|Interlace|Image size|Frames|Colour profile|Color space|Linearized|Sampling)/i;
function clLeft(R){ return R.after ? R.after.fields.filter(f => f.g !== 'Stands out' && !CL_HARMLESS.test(f.k) && f.v && !/^(No camera or date)/.test(f.v)) : []; }

function labClean(){
  const L = UI.clean, neutral = UI.clNeutral !== false;
  const drop = `<label class="drop" id="clDrop" tabindex="0"><input type="file" id="clIn" class="sr" multiple accept=".jpg,.jpeg,.png,.webp,.pdf,.docx,.docm,.xlsx,.xlsm,.pptx,.pptm,image/jpeg,image/png,image/webp,application/pdf">${ico('eraser')}<b>Drop the files you are about to send</b>
    <span>Photos, PDFs and Word, Excel and PowerPoint files. What they say about you — camera and serial numbers, location, dates, your name and company, software, edit history, who wrote the comments, folder paths — is taken out here, in this browser, and the clean copy is read back to show what is left.</span>
    <span class="drop-feat"><i>EXIF &amp; GPS</i><i>XMP &amp; IPTC</i><i>C2PA</i><i>Thumbnails</i><i>PDF properties &amp; IDs</i><i>Office authors &amp; company</i><i>Comment authors</i><i>Template &amp; paths</i><i>Pixels untouched</i></span></label>
    <label class="chk" style="margin-top:10px"><input type="checkbox" id="clNeutral"${neutral ? ' checked' : ''}> Give the clean copies plain names (photo-1.jpg) — file names such as IMG_4021 or “Contract v3 – Jane’s edits” give things away too</label>`;
  if(!L) return drop + clAdvice();
  if(L.busy) return `<div class="card" style="padding:40px;text-align:center">${ico('refresh-cw','sm spin')} Cleaning…</div>`;
  return `<div class="wrap" style="margin-bottom:12px"><button class="btn" data-act="clClear">${ico('x','sm')}Clean other files</button>${L.items.filter(r => r.out).length > 1 ? `<button class="btn primary" data-act="clAll">${ico('download','sm')}Download all clean copies</button>` : ''}</div>`
    + L.items.map((R, i) => { const left = clLeft(R), out = clOutName(R, i);
      return `<section class="card cl-r${R.err ? ' warnc' : ''}" data-i="${i}"><header><span class="fi-ic">${ico(R.err ? 'triangle-alert' : left.length ? 'circle-alert' : 'shield-check')}</span><div style="min-width:0;flex:1"><h3>${esc(R.name)}</h3><p class="t3">${esc(R.kind || '')}${R.out ? ` · ${fmtBytes(R.size)} → ${fmtBytes(R.out.length)}` : ''}</p></div>
        ${R.out ? `<button class="btn primary sm" data-act="clGet" data-v="${i}">${ico('download','sm')}Download ${esc(out)}</button>` : ''}</header><div class="body">
        ${R.err ? `<div class="fx-note amber">${esc(R.err)}</div>` : `
        <h4 class="wc-h">${ico('eraser','sm')}Taken out</h4>${R.removed.length ? `<ul class="cl-l">${R.removed.map(x => `<li>${esc(x)}</li>`).join('')}</ul>` : '<p class="t3 small">There was nothing to take out.</p>'}
        ${R.kept.length ? `<h4 class="wc-h">${ico('check','sm')}Kept on purpose</h4><ul class="cl-l">${R.kept.map(x => `<li>${esc(x)}</li>`).join('')}</ul>` : ''}
        <h4 class="wc-h">${ico('scan-search','sm')}Read back from the clean copy</h4>${left.length ? `<div class="fx-note amber">Still in the file: ${esc(left.slice(0, 8).map(f => f.k + ': ' + f.v).join(' · '))}</div>` : '<div class="fx-note">Nothing that points to a person, device, place, program or time.</div>'}
        ${R.warn.map(w => `<div class="fx-note amber">${esc(w)}</div>`).join('')}
        ${fxKv('SHA-256 of the clean copy', R.sha256, true)}`}</div></section>`; }).join('') + clAdvice();
}
const clOutName = (R, i) => UI.clNeutral !== false ? ({'JPEG picture':'photo', 'PNG picture':'image', 'WebP picture':'image', 'PDF document':'document'}[R.kind] || 'document') + '-' + (i + 1) + '.' + (R.kind === 'JPEG picture' ? 'jpg' : (R.name.split('.').pop() || 'bin').toLowerCase()) : R.name.replace(/(\.\w+)$/, '-clean$1');
function clAdvice(){ return `<details class="caphelp" style="margin-top:12px"><summary>${ico('circle-help','sm')}What cleaning cannot take out</summary><div class="caphelp-b"><ul>
  <li><b>What the picture shows</b> — a window view, a reflection, a screen, a street sign, the weather. Crop or blur before cleaning.</li>
  <li><b>The camera's own noise pattern</b> — a forensic lab can match a photo to the phone that took it from the pixels alone. Do not send a persona's photos from your own phone.</li>
  <li><b>The words</b> — spelling, phrasing and formatting habits identify writers. Writing compared (Tradecraft) shows how.</li>
  <li><b>Hidden content in documents</b> — tracked changes, comments, hidden sheets and white text are reported here but must be removed in the program itself.</li>
  <li><b>How it travels</b> — the e-mail, chat app or upload page adds its own data (your IP, account, time). Send from the persona's environment.</li></ul></div></details>`; }
function bindClean(){
  const inp = $('clIn'), d = $('clDrop'), nt = $('clNeutral'); if(nt) nt.onchange = () => { UI.clNeutral = nt.checked; };
  if(!inp) return; const go1 = async fl => { if(!fl.length) return; UI.clean = {busy:true}; renderMain(); const items = []; for(const f of [...fl].slice(0, 50)){ if(f.size > 150 * 1048576){ items.push({name:f.name, size:f.size, removed:[], kept:[], warn:[], err:'Over 150 MB — too big to rewrite in a browser tab.'}); continue; } items.push(await clFile(f)); } UI.clean = {items}; renderMain(); };
  inp.onchange = () => go1(inp.files); d.ondragover = e => { e.preventDefault(); d.classList.add('over'); }; d.ondragleave = () => d.classList.remove('over'); d.ondrop = e => { e.preventDefault(); d.classList.remove('over'); go1(e.dataTransfer.files); };
  d.onkeydown = e => { if(e.key === 'Enter' || e.key === ' '){ e.preventDefault(); inp.click(); } };
}
const CL_MIME = {'JPEG picture':'image/jpeg', 'PNG picture':'image/png', 'WebP picture':'image/webp', 'PDF document':'application/pdf'};
const CL_ACTS = {
  opClean:() => { UI.labTab = 'clean'; go('#/lab'); },
  clClear:() => { UI.clean = null; renderMain(); },
  clGet:(id, v) => { const R = UI.clean && UI.clean.items[+v]; if(R && R.out) download(clOutName(R, +v), R.out, CL_MIME[R.kind] || 'application/octet-stream'); },
  clAll:async () => { const L = UI.clean; if(!L) return; const files = L.items.map((R, i) => R.out ? {name:clOutName(R, i), data:R.out} : null).filter(Boolean); download('clean-files.zip', await clZip(files), 'application/zip'); }
};
