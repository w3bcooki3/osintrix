/* ==========================================================================
   Metadata of older office files, read in this browser:
   · Word .doc, Excel .xls, PowerPoint .ppt (and .dot, .xlt, .pot, .msg…):
     the Compound File Binary format — a small file system inside the file —
     holding SummaryInformation (title, author, who saved it last, how many
     times, total editing time, created, last saved, last printed, template,
     program) and DocumentSummaryInformation (company, manager, category)
   · OpenDocument .odt, .ods, .odp (LibreOffice, OpenOffice): meta.xml —
     who first made it, who saved it last, dates, editing cycles and time,
     the program, the template and any custom fields
   Every offset is checked against the file, every chain of sectors is
   followed with a step limit, so a damaged or crafted file reads as empty
   instead of hanging the page.
   ========================================================================== */
const CFB_SIG = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
const isCfb = b => b && b.length >= 512 && CFB_SIG.every((x, i) => b[i] === x);
function cfbOpen(b){
  if(!isCfb(b)) return null; const dv = new DataView(b.buffer, b.byteOffset, b.byteLength), u32 = o => o + 4 <= b.length ? dv.getUint32(o, true) : 0xffffffff, u16 = o => o + 2 <= b.length ? dv.getUint16(o, true) : 0;
  const shift = u16(0x1e), mshift = u16(0x20); if(shift !== 9 && shift !== 12 || mshift !== 6) return null;
  const SS = 1 << shift, MS = 1 << mshift, cutoff = u32(0x38) || 4096, END = 0xfffffffe, nSec = Math.floor((b.length - SS) / SS);
  /* the FAT: its sectors are listed in the header (109) and then in DIFAT sectors */
  const fatSecs = []; for(let i = 0; i < 109; i++){ const s = u32(0x4c + i * 4); if(s >= 0xfffffffa) break; fatSecs.push(s); }
  let di = u32(0x44), guard = 0; while(di < 0xfffffffa && di < nSec && guard++ < 1000){ const o = (di + 1) * SS; for(let i = 0; i < SS / 4 - 1; i++){ const s = u32(o + i * 4); if(s < 0xfffffffa) fatSecs.push(s); } di = u32(o + SS - 4); }
  const per = SS / 4, fat = new Uint32Array(Math.min(fatSecs.length * per, 50000000)); let fi = 0;
  for(const s of fatSecs){ if(s >= nSec) continue; const o = (s + 1) * SS; for(let i = 0; i < per && fi < fat.length; i++) fat[fi++] = u32(o + i * 4); }
  const chain = (start, table, max) => { const out = []; let s = start, n = 0; const seen = new Set(); while(s < 0xfffffffa && s < table.length && n++ < max && !seen.has(s)){ seen.add(s); out.push(s); s = table[s]; } return out; };
  const readBig = (start, size) => { const L = chain(start, fat, Math.ceil(size / SS) + 2), out = new Uint8Array(Math.min(size, L.length * SS)); let at = 0; for(const s of L){ if(s >= nSec) break; const o = (s + 1) * SS, n = Math.min(SS, out.length - at); if(n <= 0) break; out.set(b.subarray(o, o + n), at); at += n; } return out.subarray(0, at); };
  /* the directory */
  const dirSecs = chain(u32(0x30), fat, 100000), D = [];
  for(const s of dirSecs){ if(s >= nSec) break; const o = (s + 1) * SS; for(let k = 0; k < SS / 128 && D.length < 100000; k++){ const e = o + k * 128, nl = u16(e + 0x40), ty = b[e + 0x42];
    if(!ty) { D.push(null); continue; } let name = ''; for(let i = 0; i + 1 < Math.min(nl, 64) - 1; i += 2) name += String.fromCharCode(u16(e + i));
    D.push({name, type:ty, left:u32(e + 0x44), right:u32(e + 0x48), child:u32(e + 0x4c), start:u32(e + 0x74), size:u32(e + 0x78)}); } }
  const root = D[0]; if(!root || root.type !== 5) return null;
  const mini = root.size ? readBig(root.start, root.size) : new Uint8Array(0);
  const mfat = (() => { const L = chain(u32(0x3c), fat, 100000), t = new Uint32Array(L.length * per); L.forEach((s, j) => { if(s >= nSec) return; const o = (s + 1) * SS; for(let i = 0; i < per; i++) t[j * per + i] = u32(o + i * 4); }); return t; })();
  const read = e => { if(!e || e.type !== 2) return null; const size = Math.min(e.size, 64 * 1048576);
    if(size < cutoff){ const L = chain(e.start, mfat, Math.ceil(size / MS) + 2), out = new Uint8Array(size); let at = 0; for(const s of L){ const o = s * MS, n = Math.min(MS, size - at); if(n <= 0 || o + n > mini.length) break; out.set(mini.subarray(o, o + n), at); at += n; } return out.subarray(0, at); }
    return readBig(e.start, size); };
  return {entries:D.filter(Boolean), find:n => D.find(e => e && e.name === n) || null, read};
}
/* a property set stream (SummaryInformation and friends) → {id: value} of its first section */
function cfbProps(s){
  if(!s || s.length < 48) return {}; const dv = new DataView(s.buffer, s.byteOffset, s.byteLength), u32 = o => o + 4 <= s.length ? dv.getUint32(o, true) : 0, out = {};
  if(dv.getUint16(0, true) !== 0xfffe) return out; const nsets = u32(24); if(!nsets) return out;
  const sec = u32(44); if(sec + 8 > s.length) return out; const n = Math.min(u32(sec + 4), 500); let cp = 1252;
  const ent = []; for(let i = 0; i < n; i++){ const id = u32(sec + 8 + i * 8), off = u32(sec + 12 + i * 8); if(sec + off + 4 <= s.length) ent.push([id, sec + off]); }
  const cpe = ent.find(([id]) => id === 1); if(cpe && u32(cpe[1]) === 2) cp = dv.getInt16(cpe[1] + 4, true) & 0xffff;
  const dec = bytes => { const name = cp === 65001 ? 'utf-8' : cp === 1200 ? 'utf-16le' : cp === 932 ? 'shift_jis' : cp === 936 ? 'gbk' : cp === 949 ? 'euc-kr' : cp === 950 ? 'big5' : cp === 866 ? 'ibm866' : cp === 20866 ? 'koi8-r' : cp >= 1250 && cp <= 1258 ? 'windows-' + cp : cp === 10000 ? 'macintosh' : 'windows-1252';
    try{ return new TextDecoder(name).decode(bytes); }catch(e){ return new TextDecoder('windows-1252').decode(bytes); } };
  for(const [id, o] of ent){ const ty = u32(o) & 0xffff, d = o + 4;
    try{
      if(ty === 2) out[id] = dv.getInt16(d, true); else if(ty === 3) out[id] = dv.getInt32(d, true); else if(ty === 0x0b) out[id] = dv.getInt16(d, true) !== 0;
      else if(ty === 0x1e){ const len = Math.min(u32(d), 32768, s.length - d - 4); if(len > 0) out[id] = dec(s.subarray(d + 4, d + 4 + len)).replace(/\0+$/, ''); }
      else if(ty === 0x1f){ const len = Math.min(u32(d), 16384, Math.floor((s.length - d - 4) / 2)); if(len > 0) out[id] = new TextDecoder('utf-16le').decode(s.subarray(d + 4, d + 4 + len * 2)).replace(/\0+$/, ''); }
      else if(ty === 0x40){ const lo = u32(d), hi = u32(d + 4); out[id] = {ft:hi * 4294967296 + lo}; }
    }catch(e){} }
  return out;
}
const cfbTime = v => { if(!v || !v.ft) return null; const ms = v.ft / 1e4 - 11644473600000; return ms > Date.UTC(1985, 0, 1) && ms < Date.now() + 864e5 * 366 ? ms : null; };
const cfbIso = ms => new Date(ms).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
function mtCfb(b, add, st){
  const C = cfbOpen(b); if(!C) return '';
  const names = new Set(C.entries.map(e => e.name)), kind = names.has('WordDocument') ? 'Word document (.doc)' : names.has('Workbook') || names.has('Book') ? 'Excel workbook (.xls)' : names.has('PowerPoint Document') ? 'PowerPoint presentation (.ppt)' : [...names].some(n => /^__substg1\.0_/.test(n)) ? 'Outlook message (.msg)' : names.has('VisioDocument') ? 'Visio drawing (.vsd)' : 'Office file (Compound File)';
  const S = cfbProps(C.read(C.find('\u0005SummaryInformation'))), Dm = cfbProps(C.read(C.find('\u0005DocumentSummaryInformation')));
  const T = {2:['Content', 'Title'], 3:['Content', 'Subject'], 4:['People', 'Author'], 5:['Content', 'Keywords'], 6:['Content', 'Comments'], 7:['Software', 'Template'], 8:['People', 'Last saved by'], 9:['File', 'Revision'], 18:['Software', 'Made with']};
  for(const [id, [g, k]] of Object.entries(T)){ const v = S[id]; if(typeof v === 'string' && v.trim()) add(g, k, v.trim()); }
  const cr = cfbTime(S[12]), sv = cfbTime(S[13]), pr = cfbTime(S[11]);
  if(cr) add('When', 'Created', cfbIso(cr)); if(sv) add('When', 'Last saved', cfbIso(sv)); if(pr) add('When', 'Last printed', cfbIso(pr));
  if(S[10] && S[10].ft){ const min = Math.round(S[10].ft / 6e8); if(min > 0) add('File', 'Total editing time (minutes)', String(min)); }
  if(typeof S[14] === 'number' && S[14] > 0) add('File', 'Pages', String(S[14])); if(typeof S[15] === 'number' && S[15] > 0) add('File', 'Words', String(S[15]));
  for(const [id, [g, k]] of Object.entries({15:['People', 'Company'], 14:['People', 'Manager'], 2:['Content', 'Category']})){ const v = Dm[id]; if(typeof v === 'string' && v.trim()) add(g, k, v.trim()); }
  if(typeof S[18] === 'string' && S[18].trim()) st.soft.add(S[18].trim());
  /* times in these files are kept in UTC */
  if(cr){ st.taken = cr; st.tz = 'explicit'; } if(sv) st.mod = sv;
  if([...names].some(n => /^(Macros|_VBA_PROJECT_CUR|VBA|_VBA_PROJECT)$/.test(n))) st.flags.push({t:'Contains macros', tone:'red'});
  if(names.has('ObjectPool') || [...names].some(n => /^MBD[0-9A-F]{8}$/.test(n))) st.flags.push({t:'Holds embedded objects', tone:'amber'});
  if(cr && sv && sv < cr) st.flags.push({t:'Last saved before it was created — the dates were changed, or the clock was wrong', tone:'amber'});
  return kind;
}
/* OpenDocument meta.xml */
async function mtOdf(b, add, st){
  let Z; try{ Z = await nbUnzip(b); }catch(e){ return ''; }
  const mt = Z.names.includes('mimetype') ? new TextDecoder().decode(await Z.get('mimetype')).trim() : '', x = Z.names.includes('meta.xml') ? await Z.get('meta.xml') : null;
  const kind = /text$/.test(mt) ? 'OpenDocument text (.odt)' : /spreadsheet$/.test(mt) ? 'OpenDocument spreadsheet (.ods)' : /presentation$/.test(mt) ? 'OpenDocument presentation (.odp)' : /graphics$/.test(mt) ? 'OpenDocument drawing (.odg)' : 'OpenDocument file';
  if(!x || x.length > 4 * 1048576) return kind;
  const doc = new DOMParser().parseFromString(new TextDecoder().decode(x), 'application/xml'); if(doc.querySelector('parsererror')) return kind;
  const L = n => [...doc.getElementsByTagName(n)].map(e => (e.textContent || '').trim()).filter(Boolean);
  const one = n => L(n)[0] || '';
  for(const [n, g, k] of [['dc:title', 'Content', 'Title'], ['dc:subject', 'Content', 'Subject'], ['dc:description', 'Content', 'Comments'], ['meta:initial-creator', 'People', 'Author'], ['dc:creator', 'People', 'Last saved by'], ['meta:editing-cycles', 'File', 'Revision'], ['meta:generator', 'Software', 'Made with'], ['meta:printed-by', 'People', 'Last printed by']]){ const v = one(n); if(v) add(g, k, v); }
  const kw = L('meta:keyword'); if(kw.length) add('Content', 'Keywords', kw.join(', '));
  const d = s => { if(!s) return null; const z = /Z$|[+-]\d{2}:\d{2}$/.test(s), t = Date.parse(z ? s : s + 'Z'); return isFinite(t) ? {t, z} : null; };
  const cr = d(one('meta:creation-date')), sv = d(one('dc:date')), pr = d(one('meta:print-date'));
  const fmt = x => new Date(x.t).toISOString().replace('T', ' ').replace(/\.\d+Z$/, '') + (x.z ? ' UTC' : ' (local time of the computer that saved it)');
  if(cr) add('When', 'Created', fmt(cr)); if(sv) add('When', 'Last saved', fmt(sv)); if(pr) add('When', 'Last printed', fmt(pr));
  const du = one('meta:editing-duration').match(/^P(?:(\d+)D)?T?(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?$/); if(du){ const min = Math.round((+(du[1] || 0)) * 1440 + (+(du[2] || 0)) * 60 + (+(du[3] || 0)) + (+(du[4] || 0)) / 60); if(min > 0) add('File', 'Total editing time (minutes)', String(min)); }
  const ds = doc.getElementsByTagName('meta:document-statistic')[0]; if(ds){ for(const [a, k] of [['meta:page-count', 'Pages'], ['meta:word-count', 'Words'], ['meta:table-count', 'Sheets or tables'], ['meta:image-count', 'Pictures']]){ const v = +ds.getAttribute(a); if(v > 0) add('File', k, String(v)); } }
  const tpl = doc.getElementsByTagName('meta:template')[0]; if(tpl){ const h = tpl.getAttribute('xlink:href') || tpl.getAttribute('xlink:title'); if(h) add('Software', 'Template', h); }
  for(const u of [...doc.getElementsByTagName('meta:user-defined')].slice(0, 20)){ const n = u.getAttribute('meta:name'), v = (u.textContent || '').trim(); if(n && v) add('Content', 'Custom field “' + n.slice(0, 60) + '”', v); }
  const gen = one('meta:generator'); if(gen) st.soft.add(gen.split('$')[0]);
  if(cr){ st.taken = cr.t; st.tz = cr.z ? 'explicit' : 'assumed'; } if(sv) st.mod = sv.t;
  if(Z.names.some(n => /^Basic\/.+\.xml$/i.test(n) && !/script-lc\.xml|script-lb\.xml/.test(n))) st.flags.push({t:'Contains macros (Basic)', tone:'red'});
  return kind;
}
