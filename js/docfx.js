/* ==========================================================================
   Document forensics (Forensics kit → File inspector)
   PDF: every earlier version kept by incremental saves, and the text that was
   in an earlier version but not the last (removed or "redacted" by editing);
   embedded files (each opens on its own), JavaScript, fonts, form fields.
   Word / Excel / PowerPoint: tracked insertions and deletions with who and
   when, deleted and hidden text, comments and their authors, the people list
   (often with account e-mail), custom properties, hidden and very hidden
   sheets, external workbook links, speaker notes, hidden slides, embedded
   media (each opens on its own). E-mail files (.eml): the headers that
   matter and every attachment, decoded, to inspect on its own.
   Read from the bytes in this tab; nothing is uploaded or opened.
   ========================================================================== */
const DX = {blobs:new Map(), n:0};
const dxKeep = (name, bytes) => { const id = 'dx' + (++DX.n); DX.blobs.set(id, {name, bytes}); if(DX.blobs.size > 200) DX.blobs.delete(DX.blobs.keys().next().value); return id; };
const dxOpenBtn = (name, bytes, label = 'Inspect') => bytes && bytes.length ? `<button class="btn xs ghost" data-act="dxOpen" data-v="${dxKeep(name, bytes)}">${ico('file-search','sm')}${esc(label)}</button>` : '';
const dxXml = s => String(s || '').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(+n)).replace(/&#x([0-9a-f]+);/gi, (_, n) => String.fromCodePoint(parseInt(n, 16))).replace(/&amp;/g, '&');
const dxAttr = (tag, a) => { const m = tag.match(new RegExp('\\b' + a.replace(':', '\\:') + '="([^"]*)"')); return m ? dxXml(m[1]) : ''; };
const dxDate = s => { const t = Date.parse(s || ''); return isFinite(t) && t > 0 ? new Date(t).toISOString().replace('T', ' ').slice(0, 16) + ' UTC' : ''; };

/* ---------- PDF ---------- */
function dxPdfStrDecode(s){ return s.replace(/\\([nrtbf()\\]|[0-7]{1,3}|\r?\n)/g, (m, c) => c === 'n' ? '\n' : c === 'r' ? '\r' : c === 't' ? '\t' : c === 'b' ? '\b' : c === 'f' ? '\f' : /^[0-7]/.test(c) ? String.fromCharCode(parseInt(c, 8)) : /\n/.test(c) ? '' : c); }
function dxPdfHexStr(h){ h = h.replace(/\s+/g, ''); if(h.length % 2) h += '0'; let out = ''; const B = h.match(/../g) || [];
  if(B.length >= 2 && B[0] === 'fe' && B[1] === 'ff'){ for(let i = 2; i + 1 < B.length; i += 2) out += String.fromCharCode(parseInt(B[i] + B[i + 1], 16)); return out; }
  for(const x of B) out += String.fromCharCode(parseInt(x, 16)); return out; }
/* text shown by a content stream: Tj, TJ, ' and " strings, with line breaks at T*, Td, TD, Tm and ET */
function dxPdfText(cs){
  const out = []; let line = '', i = 0; const n = cs.length;
  const push = () => { if(line.trim()) out.push(line.replace(/\s+/g, ' ').trim()); line = ''; };
  while(i < n){ const c = cs[i];
    if(c === '('){ let d = 1, j = i + 1, s = ''; while(j < n && d){ const ch = cs[j]; if(ch === '\\'){ s += ch + (cs[j + 1] || ''); j += 2; continue; } if(ch === '(') d++; else if(ch === ')'){ d--; if(!d) break; } s += ch; j++; } line += dxPdfStrDecode(s); i = j + 1; continue; }
    if(c === '<' && cs[i + 1] !== '<'){ const j = cs.indexOf('>', i); if(j < 0) break; const t = dxPdfHexStr(cs.slice(i + 1, j)); if(/^[\x09\x0a\x0d\x20-\x7e -￿]*$/.test(t)) line += t; i = j + 1; continue; }
    if(c === '-' || c >= '0' && c <= '9'){ const m = /^-?\d*\.?\d+/.exec(cs.slice(i, i + 16)); if(m){ if(+m[0] < -180 && cs.lastIndexOf('[', i) > cs.lastIndexOf(']', i)) line += ' '; i += m[0].length; continue; } }
    if(/[A-Za-z'"*]/.test(c)){ const m = /^[A-Za-z'"*]+/.exec(cs.slice(i, i + 4)); const op = m[0]; if(/^(T\*|Td|TD|Tm|ET|'|")$/.test(op)) push(); i += op.length; continue; }
    i++; }
  push(); return out;
}
/* streams with their dictionaries and object numbers; Flate-compressed ones are inflated */
async function dxPdfStreams(b, s){
  const out = []; let n = 0;
  for(const m of s.matchAll(/(\d+)\s+(\d+)\s+obj\s*<<((?:(?!endobj|\sobj\b|endstream)[\s\S]){0,4000}?)>>\s*stream\r?\n/g)){ if(++n > 3000) break;
    const dict = m[3], L = (dict.match(/\/Length\s+(\d+)(?!\s+\d+\s+R)/) || [])[1], a = m.index + m[0].length; let e = L ? a + +L : s.indexOf('endstream', a); if(e < a || e > b.length) e = s.indexOf('endstream', a); if(e < a) continue;
    const st = {obj:+m[1], dict, at:m.index, a, e, raw:b.subarray(a, e)};
    if(/\/FlateDecode/.test(dict) && !/\/DecodeParms|\/DCTDecode|\/JPXDecode|\/CCITT|\/JBIG2/.test(dict)){ try{ st.data = new Uint8Array(await decompressCapped(st.raw, 'deflate', 16 << 20)); }catch(x){ st.bad = true; } }
    else if(!/\/Filter/.test(dict)) st.data = st.raw;
    out.push(st); }
  return out;
}
async function dxPdf(b){
  const s = latin1(b, 0, Math.min(b.length, 60e6)), R = {revs:[], removed:[], files:[], js:[], fonts:[], fields:[], text:0};
  const S = await dxPdfStreams(b, s);
  /* content streams (not images, fonts, XMP, object streams) */
  const isContent = st => st.data && !/\/Subtype\s*\/Image|\/Length1|\/FontFile|\/Type\s*\/(?:XObject|Metadata|ObjStm|XRef|EmbeddedFile|XRefStm)|\/Subtype\s*\/(?:Type1C|CIDFontType0C|OpenType|XML)/.test(st.dict);
  const textOf = list => list.filter(isContent).flatMap(st => dxPdfText(new TextDecoder('latin1').decode(st.data.subarray(0, 4e6))));
  const latest = new Map(); for(const st of S) latest.set(st.obj, st);   /* what a reader shows: the last copy of each object */
  const finalText = textOf([...latest.values()]); R.text = finalText.join(' ').length; R.sample = finalText.slice(0, 12);
  /* earlier versions: each %%EOF ends one; streams written before it belong to that version */
  const eofs = [...s.matchAll(/%%EOF/g)].map(m => m.index + 5);
  if(eofs.length > 1){ const finalSet = new Set(finalText.map(x => x.toLowerCase()));
    for(let i = 0; i < eofs.length; i++){ const end = eofs[i], part = s.slice(i ? eofs[i - 1] : 0, end);
      const info = k => { const m = part.match(new RegExp('/' + k + '\\s*\\(((?:\\\\.|[^\\\\)])*)\\)')); return m ? dxPdfStrDecode(m[1]).replace(/^D:(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2}).*/, '$1-$2-$3 $4:$5:$6') : ''; };
      const rev = {i, end, size:end, mod:info('ModDate'), prod:info('Producer'), creator:info('Creator'), objs:(part.match(/\d+\s+\d+\s+obj\b/g) || []).length};
      if(i < eofs.length - 1){ const live = new Map(); for(const st of S) if(st.at < end) live.set(st.obj, st);   /* the version as it stood: the latest copy of each object up to here */
        const t = textOf([...live.values()]); rev.lines = t.length; const gone = t.filter(x => x.length > 2 && !finalSet.has(x.toLowerCase())); rev.gone = [...new Set(gone)].slice(0, 80); R.removed.push(...rev.gone.map(g => [i + 1, g])); }
      R.revs.push(rev); } }
  /* embedded files: the name from the file specification, the bytes from the stream it points to */
  const byObj = new Map(S.map(st => [st.obj, st]));
  for(const m of s.matchAll(/\/(?:UF|F)\s*\(((?:\\.|[^\\)]){1,200})\)[\s\S]{0,400}?\/EF\s*<<[^>]*?\/F\s+(\d+)\s+\d+\s+R/g)){ const st = byObj.get(+m[2]); const name = dxPdfStrDecode(m[1]).replace(/^\xfe\xff/, '');
    if(st && !R.files.some(f => f.obj === st.obj)) R.files.push({name, obj:st.obj, size:(st.data || st.raw).length, bytes:st.data || (/\/Filter/.test(st.dict) ? null : st.raw)}); }
  for(const st of S) if(/\/Type\s*\/EmbeddedFile/.test(st.dict) && !R.files.some(f => f.obj === st.obj)) R.files.push({name:'embedded-' + st.obj, obj:st.obj, size:(st.data || st.raw).length, bytes:st.data || null});
  /* JavaScript: inline strings and referenced streams */
  for(const m of s.matchAll(/\/JS\s*\(((?:\\.|[^\\)]){1,20000})\)/g)) R.js.push(dxPdfStrDecode(m[1]).slice(0, 3000));
  for(const m of s.matchAll(/\/JS\s+(\d+)\s+\d+\s+R/g)){ const st = byObj.get(+m[1]); if(st && st.data) R.js.push(new TextDecoder('latin1').decode(st.data.subarray(0, 3000))); }
  R.fonts = [...new Set([...s.matchAll(/\/BaseFont\s*\/(?:[A-Z]{6}\+)?([^\s/\[\]<>()]+)/g)].map(m => m[1].replace(/#20/g, ' ')))].slice(0, 30);
  R.fields = [...new Set([...s.matchAll(/\/FT\s*\/(?:Tx|Btn|Ch|Sig)[\s\S]{0,300}?\/T\s*\(((?:\\.|[^\\)]){1,100})\)|\/T\s*\(((?:\\.|[^\\)]){1,100})\)[\s\S]{0,300}?\/FT\s*\/(?:Tx|Btn|Ch|Sig)/g)].map(m => dxPdfStrDecode(m[1] || m[2])))].slice(0, 40);
  R.sig = /\/Type\s*\/Sig\b|\/ByteRange\s*\[/.test(s);
  return R;
}
function dxPdfCard(R, name, bytes){
  if(!R) return ''; const rows = [];
  if(R.revs.length > 1){ rows.push(`<h5 class="fx-g">${R.revs.length} versions in this file</h5><p class="t3 small" style="margin:0 0 6px">Each save after the first was added to the end; the earlier versions are still inside, whole.</p>`);
    rows.push(R.revs.map((v, i) => `<div class="kv"><span>Version ${i + 1}${i === R.revs.length - 1 ? ' (what you see)' : ''}</span><b>${fmtBytes(v.end)}${v.mod ? ' · saved ' + esc(v.mod) : ''}${v.prod ? ' · ' + esc(v.prod) : ''}</b>${i < R.revs.length - 1 ? dxOpenBtn(name.replace(/\.pdf$/i, '') + '-version' + (i + 1) + '.pdf', bytes && bytes.subarray(0, v.end), 'Open this version') : ''}</div>`).join(''));
    if(R.removed.length) rows.push(`<div class="note red" style="margin:10px 0 0"><span class="ic">${ico('eye','sm')}</span><div><b>Text in an earlier version that is not in the final one</b> — removed, replaced or “redacted” by editing:${R.removed.slice(0, 30).map(([v, t]) => `<div class="mono" style="font-size:calc(12.5px * var(--ts,1));margin-top:4px"><span class="t3">v${v}</span> ${esc(t)}</div>`).join('')}</div></div>`);
    else rows.push('<p class="t3 small" style="margin:6px 0 0">No text was removed between versions (checked page content that the browser can decode).</p>'); }
  if(R.files.length) rows.push(`<h5 class="fx-g">Files inside</h5>${R.files.map(f => `<div class="kv"><span class="mono">${esc(f.name)}</span><b>${fmtBytes(f.size)}</b>${f.bytes ? dxOpenBtn(f.name, f.bytes) : '<span class="t3 small">compressed in a way the browser cannot open</span>'}</div>`).join('')}`);
  if(R.js.length) rows.push(`<h5 class="fx-g">JavaScript</h5>${R.js.slice(0, 4).map(j => `<pre class="rawbox">${esc(j.slice(0, 1200))}</pre>`).join('')}`);
  if(R.fields.length) rows.push(fxKv('Form fields', R.fields.join(', ')));
  if(R.sig) rows.push(fxKv('Digital signature', 'present — a signature covers only the bytes up to its own version; later versions are not signed'));
  if(R.fonts.length) rows.push(fxKv('Fonts', R.fonts.join(', ')));
  if(R.sample && R.sample.length && !R.revs.length) rows.push(`<details class="more"><summary>Text on the pages (first lines)</summary>${R.sample.map(t => `<div class="small">${esc(t)}</div>`).join('')}</details>`);
  return rows.length ? `<section class="card"><header><h3>${ico('file-text','sm')} PDF forensics</h3></header><div class="body">${rows.join('')}</div></section>` : '';
}

/* ---------- Word, Excel, PowerPoint ---------- */
async function dxOffice(b){
  const Z = zipOpen(b); if(!Z || !Z.files.some(f => f.name === '[Content_Types].xml')) return null;
  const has = n => Z.files.some(f => f.name === n), rd = async n => has(n) ? ((await Z.read(n, 16 << 20)) || '') : '';
  const R = {kind:has('word/document.xml') ? 'Word' : has('xl/workbook.xml') ? 'Excel' : has('ppt/presentation.xml') ? 'PowerPoint' : 'Office', ins:[], del:[], hidden:[], comments:[], people:[], custom:[], sheets:[], names:[], extLinks:[], notes:[], hiddenSlides:[], media:[], rsids:0, authors:new Set()};
  if(R.kind === 'Word'){ const parts = Z.files.map(f => f.name).filter(n => /^word\/(document|header\d*|footer\d*|footnotes|endnotes)\.xml$/.test(n));
    for(const p of parts){ const x = await rd(p);
      for(const m of x.matchAll(/<w:ins\b([^>]*)>([\s\S]*?)<\/w:ins>/g)){ const t = [...m[2].matchAll(/<w:t(?:\s[^>]*)?>([^<]*)<\/w:t>/g)].map(y => dxXml(y[1])).join(''); if(t.trim()) R.ins.push({by:dxAttr(m[1], 'w:author'), at:dxAttr(m[1], 'w:date'), t}); }
      for(const m of x.matchAll(/<w:del\b([^>]*)>([\s\S]*?)<\/w:del>/g)){ const t = [...m[2].matchAll(/<w:delText(?:\s[^>]*)?>([^<]*)<\/w:delText>/g)].map(y => dxXml(y[1])).join(''); if(t.trim()) R.del.push({by:dxAttr(m[1], 'w:author'), at:dxAttr(m[1], 'w:date'), t}); }
      for(const m of x.matchAll(/<w:r\b[^>]*>(?:(?!<\/w:r>)[\s\S])*?<w:vanish\/>(?:(?!<\/w:r>)[\s\S])*?<\/w:r>/g)){ const t = [...m[0].matchAll(/<w:t(?:\s[^>]*)?>([^<]*)<\/w:t>/g)].map(y => dxXml(y[1])).join(''); if(t.trim()) R.hidden.push(t); }
      /* white or tiny text: present but meant not to be seen */
      for(const m of x.matchAll(/<w:r\b[^>]*>(?:(?!<\/w:r>)[\s\S])*?(?:<w:color w:val="FFFFFF"\/>|<w:sz w:val="[12]"\/>)(?:(?!<\/w:r>)[\s\S])*?<\/w:r>/g)){ const t = [...m[0].matchAll(/<w:t(?:\s[^>]*)?>([^<]*)<\/w:t>/g)].map(y => dxXml(y[1])).join(''); if(t.trim()) R.hidden.push(t + ' (white or tiny text)'); } }
    const cx = await rd('word/comments.xml'); for(const m of cx.matchAll(/<w:comment\b([^>]*)>([\s\S]*?)<\/w:comment>/g)) R.comments.push({by:dxAttr(m[1], 'w:author'), ini:dxAttr(m[1], 'w:initials'), at:dxAttr(m[1], 'w:date'), t:[...m[2].matchAll(/<w:t(?:\s[^>]*)?>([^<]*)<\/w:t>/g)].map(y => dxXml(y[1])).join('')});
    const st = await rd('word/settings.xml'); R.rsids = (st.match(/<w:rsid\s/g) || []).length;
    const px = await rd('word/people.xml'); for(const m of px.matchAll(/<w15:person\b([^>]*)>([\s\S]*?)<\/w15:person>/g)){ const pi = (m[2].match(/<w15:presenceInfo\b([^>]*)\/>/) || [])[1] || ''; R.people.push({name:dxAttr(m[1], 'w15:author'), provider:dxAttr(pi, 'w15:providerId'), user:dxAttr(pi, 'w15:userId')}); } }
  if(R.kind === 'Excel'){ const wb = await rd('xl/workbook.xml');
    for(const m of wb.matchAll(/<sheet\b([^>]*)\/>/g)) R.sheets.push({name:dxAttr(m[1], 'name'), state:dxAttr(m[1], 'state') || 'visible'});
    for(const m of wb.matchAll(/<definedName\b([^>]*)>([^<]*)<\/definedName>/g)) R.names.push({name:dxAttr(m[1], 'name'), ref:dxXml(m[2]), hidden:dxAttr(m[1], 'hidden') === '1'});
    for(const f of Z.files.filter(x => /^xl\/externalLinks\/_rels\/.*\.rels$/.test(x.name))){ const x = await rd(f.name); for(const m of x.matchAll(/Target="([^"]+)"/g)) R.extLinks.push(dxXml(m[1])); }
    for(const f of Z.files.filter(x => /^xl\/comments\d*\.xml$/.test(x.name))){ const x = await rd(f.name); const A = [...x.matchAll(/<author>([^<]*)<\/author>/g)].map(m => dxXml(m[1]));
      for(const m of x.matchAll(/<comment\b([^>]*)>([\s\S]*?)<\/comment>/g)) R.comments.push({by:A[+dxAttr(m[1], 'authorId')] || '', ref:dxAttr(m[1], 'ref'), t:[...m[2].matchAll(/<t(?:\s[^>]*)?>([^<]*)<\/t>/g)].map(y => dxXml(y[1])).join('')}); }
    const pp = await rd('xl/persons/person.xml'); for(const m of pp.matchAll(/<person\b([^>]*)\/>/g)) R.people.push({name:dxAttr(m[1], 'displayName'), provider:dxAttr(m[1], 'providerId'), user:dxAttr(m[1], 'userId')}); }
  if(R.kind === 'PowerPoint'){
    for(const f of Z.files.filter(x => /^ppt\/slides\/slide\d+\.xml$/.test(x.name))){ const x = (await rd(f.name)).slice(0, 4000); if(/<p:sld\b[^>]*\bshow="0"/.test(x)) R.hiddenSlides.push(+f.name.match(/(\d+)\.xml$/)[1]); }
    for(const f of Z.files.filter(x => /^ppt\/notesSlides\/notesSlide\d+\.xml$/.test(x.name)).sort((a, b) => +a.name.match(/(\d+)\.xml/)[1] - +b.name.match(/(\d+)\.xml/)[1])){ const x = await rd(f.name); const t = [...x.matchAll(/<a:t>([^<]*)<\/a:t>/g)].map(m => dxXml(m[1])).join(' ').replace(/\s+/g, ' ').trim(); if(t && !/^\d+$/.test(t)) R.notes.push({n:+f.name.match(/(\d+)\.xml/)[1], t}); }
    const ca = await rd('ppt/commentAuthors.xml'); for(const m of ca.matchAll(/<p:cmAuthor\b([^>]*)\/?>/g)) R.people.push({name:dxAttr(m[1], 'name'), provider:'', user:dxAttr(m[1], 'initials')});
    for(const f of Z.files.filter(x => /^ppt\/comments\/(?:comment|modernComment)[^/]*\.xml$/.test(x.name))){ const x = await rd(f.name); for(const m of x.matchAll(/<p:text>([^<]*)<\/p:text>|<a:t>([^<]*)<\/a:t>/g)) R.comments.push({by:'', t:dxXml(m[1] || m[2])}); } }
  const cu = await rd('docProps/custom.xml'); for(const m of cu.matchAll(/<property\b([^>]*)>([\s\S]*?)<\/property>/g)){ const v = (m[2].match(/>([^<]*)</) || [])[1]; R.custom.push([dxAttr(m[1], 'name'), dxXml(v || '')]); }
  for(const f of Z.files.filter(x => /^(word|xl|ppt)\/(media|embeddings)\/[^/]+$/.test(x.name)).slice(0, 60)) R.media.push({name:f.name, size:f.size});
  for(const x of [...R.ins, ...R.del, ...R.comments]) if(x.by) R.authors.add(x.by);
  return R;
}
function dxOfficeCard(R){
  if(!R) return ''; const rows = [], who = x => `${x.by ? esc(x.by) : ''}${x.at ? ' <span class="t3">' + esc(dxDate(x.at)) + '</span>' : ''}`;
  if(R.del.length) rows.push(`<div class="note red" style="margin:0 0 8px"><span class="ic">${ico('eye','sm')}</span><div><b>Deleted text still in the file (tracked changes)</b>${R.del.slice(0, 25).map(d => `<div style="margin-top:4px"><span class="mono small">${esc(d.t.slice(0, 300))}</span><br><small>${who(d)}</small></div>`).join('')}</div></div>`);
  if(R.ins.length) rows.push(`<h5 class="fx-g">Tracked insertions</h5>${R.ins.slice(0, 15).map(d => `<div class="kv"><span>${who(d)}</span><b>${esc(d.t.slice(0, 200))}</b></div>`).join('')}`);
  if(R.hidden.length) rows.push(`<div class="note amber" style="margin:8px 0"><span class="ic">${ico('eye-off','sm')}</span><div><b>Hidden text</b> — in the file, not shown when printed or read normally:${R.hidden.slice(0, 12).map(t => `<div class="mono small" style="margin-top:4px">${esc(t.slice(0, 300))}</div>`).join('')}</div></div>`);
  if(R.comments.length) rows.push(`<h5 class="fx-g">Comments</h5>${R.comments.slice(0, 20).map(c => `<div class="kv"><span>${who(c) || (c.ref ? 'cell ' + esc(c.ref) : '')}</span><b>${esc((c.t || '').slice(0, 300))}</b></div>`).join('')}`);
  if(R.people.length) rows.push(`<h5 class="fx-g">People in the file</h5>${R.people.map(p => `<div class="kv"><span>${esc(p.name)}</span><code>${esc([p.user, p.provider].filter(Boolean).join(' · '))}</code></div>`).join('')}<p class="t3 small" style="margin:4px 0 0">Microsoft writes the account behind each commenter here — often a work e-mail or an account ID (provider “AD” = Entra ID, “Windows Live” = personal Microsoft account).</p>`);
  if(R.sheets.some(s => s.state !== 'visible')) rows.push(`<div class="note amber" style="margin:8px 0"><span class="ic">${ico('eye-off','sm')}</span><div><b>Hidden sheets:</b> ${R.sheets.filter(s => s.state !== 'visible').map(s => esc(s.name) + (s.state === 'veryHidden' ? ' (very hidden — only reachable from VBA)' : '')).join(', ')}</div></div>`);
  if(R.sheets.length) rows.push(fxKv('Sheets', R.sheets.map(s => s.name).join(', ')));
  if(R.names.length) rows.push(fxKv('Named ranges', R.names.slice(0, 12).map(n => n.name + ' → ' + n.ref + (n.hidden ? ' (hidden)' : '')).join('; ')));
  if(R.extLinks.length) rows.push(`<div class="kv"><span>Linked workbooks</span><code>${esc(R.extLinks.join('  '))}</code></div><p class="t3 small" style="margin:0">Paths to other workbooks often name the author's folders, file shares and servers.</p>`);
  if(R.hiddenSlides.length) rows.push(fxKv('Hidden slides', R.hiddenSlides.sort((a, b) => a - b).join(', ')));
  if(R.notes.length) rows.push(`<h5 class="fx-g">Speaker notes</h5>${R.notes.slice(0, 20).map(n => `<div class="kv"><span>Slide ${n.n}</span><b>${esc(n.t.slice(0, 400))}</b></div>`).join('')}`);
  if(R.custom.length) rows.push(`<h5 class="fx-g">Custom properties</h5>${R.custom.slice(0, 20).map(([k, v]) => fxKv(k, v)).join('')}`);
  if(R.rsids) rows.push(fxKv('Editing sessions (rsid)', R.rsids + ' — each save session gets one; documents sharing rsids share an editing history'));
  if(R.media.length) rows.push(`<h5 class="fx-g">Pictures and objects inside</h5><p class="t3 small" style="margin:0 0 4px">Pictures keep their own metadata (camera, GPS, the program that made them) — inspect each.</p>${R.media.map(m => `<div class="kv"><span class="mono">${esc(m.name)}</span><b>${fmtBytes(m.size)}</b><button class="btn xs ghost" data-act="fxZipOpen" data-v="${esc(m.name)}">${ico('file-search','sm')}Inspect</button></div>`).join('')}`);
  return rows.length ? `<section class="card"><header><h3>${ico('file-text','sm')} ${esc(R.kind)} forensics</h3></header><div class="body">${rows.join('')}</div></section>` : '';
}

/* ---------- e-mail files (.eml): headers that matter, and every attachment ---------- */
function dxQP(s){ return s.replace(/=\r?\n/g, '').replace(/=([0-9A-F]{2})/gi, (_, h) => String.fromCharCode(parseInt(h, 16))); }
function dxB64(s){ try{ const t = atob(s.replace(/[^A-Za-z0-9+/=]/g, '')); return Uint8Array.from(t, c => c.charCodeAt(0)); }catch(e){ return null; } }
function dxWord(s){ return String(s || '').replace(/=\?([\w-]+)\?([BQ])\?([^?]*)\?=/gi, (_, cs, enc, t) => { try{ const bytes = enc.toUpperCase() === 'B' ? dxB64(t) : Uint8Array.from(dxQP(t.replace(/_/g, ' ')), c => c.charCodeAt(0)); return new TextDecoder(/utf-?8/i.test(cs) ? 'utf-8' : 'latin1').decode(bytes); }catch(e){ return t; } }); }
function dxMime(raw, depth = 0, out = {atts:[], bodies:[]}){
  const sp = raw.search(/\r?\n\r?\n/); if(sp < 0) return out; const head = raw.slice(0, sp).replace(/\r?\n[ \t]+/g, ' '), body = raw.slice(sp).replace(/^\r?\n\r?\n/, '');
  const H = k => (head.match(new RegExp('^' + k + ':\\s*(.*)$', 'im')) || [])[1] || '';
  const ct = H('Content-Type') || 'text/plain', cte = H('Content-Transfer-Encoding').toLowerCase(), cd = H('Content-Disposition');
  const bnd = (ct.match(/boundary="?([^";]+)"?/i) || [])[1];
  if(/^multipart\//i.test(ct) && bnd && depth < 8){ for(const part of body.split('--' + bnd).slice(1)){ if(/^--/.test(part)) break; dxMime(part.replace(/^\r?\n/, ''), depth + 1, out); } return out; }
  const name = dxWord((cd.match(/filename\*?="?([^";]+)"?/i) || ct.match(/name="?([^";]+)"?/i) || [])[1] || '');
  const bytes = cte === 'base64' ? dxB64(body) : cte === 'quoted-printable' ? Uint8Array.from(dxQP(body), c => c.charCodeAt(0) & 255) : Uint8Array.from(body, c => c.charCodeAt(0) & 255);
  if(/attachment/i.test(cd) || name && !/^text\/(plain|html)/i.test(ct) || /^message\/rfc822/i.test(ct)) out.atts.push({name:name || (/rfc822/i.test(ct) ? 'attached-message.eml' : 'attachment'), type:ct.split(';')[0].trim(), bytes:bytes || new Uint8Array(0)});
  else if(/^text\//i.test(ct) && bytes) out.bodies.push({type:ct.split(';')[0].trim(), text:new TextDecoder(/charset="?utf-?8/i.test(ct) ? 'utf-8' : 'latin1').decode(bytes).slice(0, 200000)});
  return out;
}
function dxEml(text, loose){
  const sp = text.search(/\r?\n\r?\n/); if(sp < 0) return null; const head = text.slice(0, sp); if(/Snapshot-Content-Location:|Saved by (?:Blink|Windows Internet Explorer|Mozilla)/i.test(head)) return null;   /* a saved web page (MHTML), not a message */ if(!/^(?:received|from|return-path|delivered-to|message-id|mime-version|x-[\w-]+):/im.test(head) || !loose && (!/^from:/im.test(head) || !/^(?:to|date|subject):/im.test(head))) return null;
  const unf = head.replace(/\r?\n[ \t]+/g, ' '), H = k => dxWord((unf.match(new RegExp('^' + k + ':\\s*(.*)$', 'im')) || [])[1] || '').trim(), all = k => [...unf.matchAll(new RegExp('^' + k + ':\\s*(.*)$', 'gim'))].map(m => m[1]);
  const M = dxMime(text), links = new Set();
  for(const b of M.bodies) for(const m of b.text.matchAll(/https?:\/\/[^\s"'<>)]+/g)) if(links.size < 60) links.add(m[0].replace(/&amp;/g, '&'));
  const hrefs = []; for(const b of M.bodies.filter(x => /html/.test(x.type))) for(const m of b.text.matchAll(/<a\b[^>]*href=["']([^"']+)["'][^>]*>([\s\S]{0,200}?)<\/a>/gi)){ const shown = m[2].replace(/<[^>]+>/g, '').trim(); if(/^https?:\/\//i.test(shown) && slHost(shown) !== slHost(m[1])) hrefs.push([shown, m[1]]); }
  const recv = all('Received'), ips = [...new Set(recv.flatMap(r => [...r.matchAll(/\[(\d{1,3}(?:\.\d{1,3}){3})\]/g)].map(m => m[1])))].filter(ip => !/^(10|127|192\.168|172\.(1[6-9]|2\d|3[01]))\./.test(ip));
  return {from:H('From'), to:H('To'), cc:H('Cc'), subject:H('Subject'), date:H('Date'), msgid:H('Message-ID'), reply:H('Reply-To'), ret:H('Return-Path'), mailer:H('X-Mailer') || H('User-Agent'), origIp:H('X-Originating-IP').replace(/[\[\]]/g, ''), auth:H('Authentication-Results'), hops:recv.length, ips, head,
    atts:M.atts, bodies:M.bodies.length, links:[...links], mismatch:hrefs.slice(0, 20)};
}
function dxMailCard(M){
  if(!M) return ''; const a = s => ((s.match(/<([^>]+)>/) || [])[1] || (s.match(/[\w.+-]+@[\w.-]+/) || [''])[0]).toLowerCase(), dom = s => a(s).split('@')[1] || '';
  const flags = [];
  if(M.reply && dom(M.reply) && dom(M.reply) !== dom(M.from)) flags.push(['amber', `Replies go to ${a(M.reply)}, not the sender's domain (${dom(M.from)}).`]);
  if(M.ret && dom(M.ret) && dom(M.from) && dom(M.ret.replace(/[<>]/g, '')) !== dom(M.from)) flags.push(['', `Return-Path (bounce address) is at ${dom(M.ret.replace(/[<>]/g, ''))} — normal for mailing services, suspicious for a person.`]);
  if(/spf=(?:fail|softfail)|dkim=fail|dmarc=fail/i.test(M.auth)) flags.push(['red', 'Authentication failed: ' + (M.auth.match(/(?:spf|dkim|dmarc)=\w+/gi) || []).join(', ')]);
  if(M.mismatch.length) flags.push(['red', M.mismatch.length + ' link' + (M.mismatch.length > 1 ? 's show' : ' shows') + ' one address and go to another: ' + M.mismatch.slice(0, 3).map(([s, h]) => s + ' → ' + h).join('; ')]);
  if(M.atts.some(x => /\.(lnk|js|vbs|hta|iso|img|vhdx?|exe|scr|bat|cmd|ps1|msi|one|wsf|jar)$/i.test(x.name))) flags.push(['red', 'An attachment type commonly used to deliver malware.']);
  return `<section class="card"><header><h3>${ico('mail','sm')} ${M.outlook ? 'Outlook message' : 'E-mail message'}</h3></header><div class="body">
    ${fxKv('From', M.from)}${fxKv('To', M.to)}${fxKv('Cc', M.cc)}${fxKv('Subject', M.subject)}${fxKv('Date', M.date)}${fxKv('Reply-To', M.reply)}${fxKv('Return-Path', M.ret, true)}${fxKv('Message-ID', M.msgid, true)}${fxKv('Sent with', M.mailer)}${fxKv('Sender IP (X-Originating-IP)', M.origIp, true)}
    ${fxKv('Hops', M.hops ? M.hops + ' Received headers' + (M.ips.length ? ' · public IPs ' + M.ips.join(', ') : '') : '')}
    ${flags.map(([t, x]) => `<div class="fx-note ${t}">${esc(x)}</div>`).join('')}
    ${M.atts.length ? `<h5 class="fx-g">Attachments</h5>${M.atts.map(x => `<div class="kv"><span class="mono">${esc(x.name)}</span><b>${esc(x.type)} · ${fmtBytes(x.bytes.length)}</b>${dxOpenBtn(x.name, x.bytes)}</div>`).join('')}` : ''}
    ${M.links.length ? `<details class="more"><summary>${M.links.length} links in the message</summary>${M.links.map(l => `<div class="mono small" style="overflow-wrap:anywhere">${esc(l)}</div>`).join('')}</details>` : ''}
    ${M.head ? `<div class="wrap" style="margin-top:10px"><button class="btn sm" data-act="dxHeaders">${ico('mail','sm')}Trace the route in Email headers</button></div>` : '<p class="t3 small" style="margin:8px 0 0">No transport headers in this message (it was saved before sending, or the headers were removed).</p>'}</div></section>`;
}
/* ---------- Outlook messages (.msg): the same, read from the compound file's property streams ---------- */
function dxMsg(b){
  const C = typeof cfbOpen === 'function' ? cfbOpen(b) : null; if(!C || !C.entries.some(e => /^__substg1\.0_/.test(e.name))) return null;
  const D = C.all, kids = i => { const out = [], seen = new Set(), walk = j => { if(j == null || j >= D.length || j === 0xffffffff || seen.has(j)) return; seen.add(j); const e = D[j]; if(!e) return; walk(e.left); out.push([j, e]); walk(e.right); }; const e = D[i]; if(e) walk(e.child); return out; };
  const props = i => { const P = {}; for(const [, e] of kids(i)){ const m = /^__substg1\.0_([0-9A-F]{4})([0-9A-F]{4})$/i.exec(e.name); if(!m || e.type !== 2) continue; const raw = C.read(e); if(!raw) continue; const ty = m[2].toUpperCase();
      P[m[1].toUpperCase()] = ty === '001F' ? new TextDecoder('utf-16le').decode(raw).replace(/\0+$/, '') : ty === '001E' ? new TextDecoder('latin1').decode(raw).replace(/\0+$/, '') : raw; } return P; };
  const R0 = props(0), str = k => typeof R0[k] === 'string' ? R0[k] : '';
  const atts = [], recips = [];
  for(const [j, e] of kids(0)){ if(e.type !== 1) continue;
    if(/^__attach_version1\.0_/.test(e.name)){ const P = props(j); const data = P['3701'] instanceof Uint8Array ? P['3701'] : null; atts.push({name:(typeof P['3707'] === 'string' && P['3707']) || (typeof P['3704'] === 'string' && P['3704']) || 'attachment', type:typeof P['370E'] === 'string' ? P['370E'] : '', bytes:data || new Uint8Array(0), embedded:!data}); }
    else if(/^__recip_version1\.0_/.test(e.name)){ const P = props(j); recips.push([typeof P['3001'] === 'string' ? P['3001'] : '', typeof P['39FE'] === 'string' ? P['39FE'] : typeof P['3003'] === 'string' ? P['3003'] : '']); } }
  const head = str('007D');
  /* the headers say most; the message's own properties fill in what they lack */
  let M = head ? dxEml(head.replace(/\r?\n?$/, '') + '\r\n\r\n' + (str('1000') || ''), true) : null;
  const html = R0['1013'] instanceof Uint8Array ? new TextDecoder().decode(R0['1013']) : str('1013'), body = str('1000');
  const links = [...new Set([...(body + ' ' + html).matchAll(/https?:\/\/[^\s"'<>)]+/g)].map(m => m[0]))].slice(0, 60);
  M = Object.assign({from:'', to:'', cc:'', subject:'', date:'', msgid:'', reply:'', ret:'', mailer:'', origIp:'', auth:'', hops:0, ips:[], head:'', links:[], mismatch:[]}, M || {});
  M.subject = M.subject || str('0037'); M.from = M.from || [str('0C1A'), str('0C1F') && '<' + str('0C1F') + '>'].filter(Boolean).join(' '); M.to = M.to || recips.map(r => r[0] + (r[1] ? ' <' + r[1] + '>' : '')).join(', ') || str('0E04');
  M.atts = atts; M.links = [...new Set([...M.links, ...links])]; M.outlook = true; M.recips = recips; M.head = head;
  for(const m of html.matchAll(/<a\b[^>]*href=["']([^"']+)["'][^>]*>([\s\S]{0,200}?)<\/a>/gi)){ const shown = m[2].replace(/<[^>]+>/g, '').trim(); if(/^https?:\/\//i.test(shown) && slHost(shown) !== slHost(m[1])) M.mismatch.push([shown, m[1]]); }
  return M;
}
/* ---------- disk images and containers used to deliver malware: ISO / IMG, OneNote, RAR ---------- */
function dxIso(b){
  const SEC = 2048; if(b.length < 0x8800 || latin1(b, 0x8001, 0x8006) !== 'CD001') return null;
  let pvd = -1, jol = -1; for(let s = 16; s < 64 && (s + 1) * SEC <= b.length; s++){ const o = s * SEC, t = b[o]; if(latin1(b, o + 1, o + 6) !== 'CD001') break; if(t === 1 && pvd < 0) pvd = o; if(t === 2 && /%\/[@CE]/.test(latin1(b, o + 88, o + 91))) jol = o; if(t === 255) break; }
  if(pvd < 0) return null; const vd = jol >= 0 ? jol : pvd, u = jol >= 0;
  const txt = (o, n) => u ? new TextDecoder('utf-16be').decode(b.subarray(o, o + n)).replace(/[\0 ]+$/, '') : latin1(b, o, o + n).replace(/[\0 ]+$/, '');
  const ad = (o) => { const s = latin1(b, o, o + 16); if(!/^\d{14}/.test(s) || /^0{4}/.test(s)) return null; const tz = (b[o + 16] << 24 >> 24) * 15; return Date.UTC(+s.slice(0, 4), +s.slice(4, 6) - 1, +s.slice(6, 8), +s.slice(8, 10), +s.slice(10, 12), +s.slice(12, 14)) - tz * 6e4; };
  const R = {sys:txt(vd + 8, 32), vol:txt(vd + 40, 32), pub:txt(vd + 318, 128), prep:txt(vd + 446, 128), app:txt(vd + 574, 128), created:ad(vd + 813), modified:ad(vd + 830), joliet:u, files:[], udf:latin1(b, 0x8000 + SEC, 0x8000 + SEC + 6).includes('BEA01') || /NSR0[23]/.test(latin1(b, 0x8000, 0x8000 + 8 * SEC))};
  const tzOf = vd2 => b[vd2 + 813 + 16] << 24 >> 24; R.tz = tzOf(pvd) * 15;
  const walk = (lba, len, path, depth) => { if(depth > 8 || R.files.length > 2000) return; const end = Math.min(b.length, lba * SEC + len); let o = lba * SEC;
    while(o < end){ const rl = b[o]; if(!rl){ o = (Math.floor(o / SEC) + 1) * SEC; continue; } const ext = u32le(b, o + 2), size = u32le(b, o + 10), fl = b[o + 25], nl = b[o + 32];
      const raw = b.subarray(o + 33, o + 33 + nl); let name = u ? new TextDecoder('utf-16be').decode(raw) : latin1(raw, 0, raw.length); const y = b[o + 18];
      const when = Date.UTC(1900 + y, b[o + 19] - 1, b[o + 20], b[o + 21], b[o + 22], b[o + 23]) - (b[o + 24] << 24 >> 24) * 15 * 6e4;
      if(!(nl === 1 && (raw[0] === 0 || raw[0] === 1))){ name = name.replace(/;\d+$/, '').replace(/\.$/, ''); const p = path + name;
        if(fl & 2) walk(ext, size, p + '/', depth + 1); else R.files.push({name:p, lba:ext, size, when, hidden:!!(fl & 1)}); }
      o += rl; } };
  const root = vd + 156; walk(u32le(b, root + 2), u32le(b, root + 10), '', 0);
  return R;
}
const ONE_SIG = 'e4525c7b8cd8a74daeb15378d02996d3', ONE_FDSO = 'e716e3bd65261145a4c48d4d0b7a9eac';
function dxOne(b){
  if(hex(b, 16) !== ONE_SIG) return null; const R = {files:[]};
  for(let i = 16; i + 36 < b.length && R.files.length < 100; i++){ if(b[i] !== 0xe7 || b[i + 1] !== 0x16 || hex(b.subarray(i, i + 16), 16) !== ONE_FDSO) continue;
    const len = u32le(b, i + 16) + u32le(b, i + 20) * 4294967296; if(len <= 0 || len > b.length) continue; const data = b.subarray(i + 36, i + 36 + len), t = sniff(data), head = latin1(data, 0, Math.min(400, data.length)); if(/HTA:APPLICATION/i.test(latin1(data, 0, Math.min(4000, data.length)))) Object.assign(t, {name:'HTML application (HTA) — runs as a program', ext:'hta'}); else if(t.ext === 'txt' && /^\s*<(?:html|head|script|body)/i.test(head)) Object.assign(t, {name:'HTML document', ext:'html'}); else if(t.ext === 'txt' && /^\s*(?:@echo|cmd |powershell)/i.test(head)) Object.assign(t, {name:'Batch script', ext:'cmd'});
    R.files.push({name:'embedded-' + (R.files.length + 1) + (t.ext ? '.' + t.ext : ''), size:len, type:t.name, bytes:data}); i += 36 + len - 1; }
  return R;
}
function dxRar(b){
  const sig = latin1(b, 0, 8); const R = {files:[], encHeaders:false, v:0};
  if(sig.startsWith('Rar!\x1a\x07\x01\x00')){ R.v = 5; let o = 8; const vint = () => { let v = 0, sh = 0, c; do { c = b[o++]; v += (c & 127) * 2 ** sh; sh += 7; } while(c & 128 && sh < 64); return v; };
    for(let g = 0; g < 5000 && o + 7 < b.length; g++){ o += 4; const hs = vint(), start = o, type = vint(), fl = vint(); const ex = fl & 1 ? vint() : 0, ds = fl & 2 ? vint() : 0;
      if(type === 4){ R.encHeaders = true; break; }
      if(type === 2){ const ff = vint(), size = vint(); vint(); let mt = null; if(ff & 2){ mt = u32le(b, o) * 1000; o += 4; } if(ff & 4) o += 4; vint(); const os = vint(), nl = vint(); const name = new TextDecoder().decode(b.subarray(o, o + nl)); o += nl;
        const extra = b.subarray(start + hs - ex, start + hs); let enc = false; for(let k = 0; k < extra.length;){ let p = k; const rv = () => { let v = 0, sh = 0, c; do { c = extra[p++]; v += (c & 127) * 2 ** sh; sh += 7; } while(c & 128 && sh < 64); return v; }; const sz = rv(), st = p, ty = rv(); if(ty === 1) enc = true; k = st + sz; if(!sz) break; }
        R.files.push({name, size, when:mt, os:os === 0 ? 'Windows' : 'Unix', enc, dir:!!(ff & 1)}); }
      o = start + hs + ds; if(type === 5) break; } }
  else if(sig.startsWith('Rar!\x1a\x07\x00')){ R.v = 4; let o = 7;
    for(let g = 0; g < 5000 && o + 7 <= b.length; g++){ const type = b[o + 2], fl = u16le(b, o + 3), hs = u16le(b, o + 5); if(hs < 7) break; let add = 0;
      if(type === 0x73 && fl & 0x80) R.encHeaders = true;
      if(type === 0x74){ const pack = u32le(b, o + 7), unp = u32le(b, o + 11), os = b[o + 15], ft = u32le(b, o + 20), nl = u16le(b, o + 26), hi = fl & 0x100 ? 8 : 0;
        const name = latin1(b, o + 32 + hi, o + 32 + hi + nl).split('\0')[0]; add = pack + (hi ? u32le(b, o + 32) * 4294967296 : 0);
        R.files.push({name:name.replace(/\\/g, '/'), size:unp, when:typeof dosTime === 'function' ? dosTime(ft) : null, os:['MS-DOS', 'OS/2', 'Windows', 'Unix', 'Mac', 'BeOS'][os] || os, enc:!!(fl & 4), dir:(fl & 0xe0) === 0xe0}); }
      else if(fl & 0x8000) add = u32le(b, o + 7);
      o += hs + add; if(type === 0x7b) break; } }
  return R.v ? R : null;
}
const DX_RISKY = /\.(lnk|js|jse|vbs|vbe|hta|wsf|cmd|bat|ps1|exe|scr|dll|msi|iso|img|vhdx?|one|jar|chm|url|library-ms|search-ms|cpl|reg|xll)$/i;
function dxBoxCard(r){
  const I = r.iso, O = r.one, A = r.rar; if(!I && !O && !A) return '';
  const d = t => t ? new Date(t).toISOString().replace('T', ' ').slice(0, 16) + ' UTC' : '';
  if(I){ const risky = I.files.filter(f => DX_RISKY.test(f.name)), hid = I.files.filter(f => f.hidden);
    return `<section class="card${risky.length ? ' warnc' : ''}"><header><h3>${ico('hard-drive','sm')} Disk image (ISO / IMG)</h3><span class="t3">${I.files.length} files${I.joliet ? ' · Joliet names' : ''}${I.udf ? ' · UDF' : ''}</span></header><div class="body">
      ${fxKv('Volume name', I.vol)}${fxKv('Made with', I.app)}${fxKv('Prepared by', I.prep)}${fxKv('Publisher', I.pub)}${fxKv('System', I.sys)}${fxKv('Created', d(I.created) + (I.created ? ` (the maker's clock was at UTC${I.tz >= 0 ? '+' : '−'}${String(Math.floor(Math.abs(I.tz) / 60)).padStart(2, '0')}:${String(Math.abs(I.tz) % 60).padStart(2, '0')})` : ''))}
      ${risky.length ? `<div class="fx-note red">Inside: ${esc(risky.map(f => f.name).slice(0, 6).join(', '))} — opening an ISO in Windows mounts it and skips the “downloaded from the internet” warning, which is why droppers use them.</div>` : ''}${hid.length ? `<div class="fx-note amber">${hid.length} hidden file${hid.length > 1 ? 's' : ''}: ${esc(hid.slice(0, 6).map(f => f.name).join(', '))} — shown only to someone who turns on hidden files; the visible shortcut usually runs them.</div>` : ''}
      <div class="ziplist">${I.files.slice(0, 300).map(f => `<div><span class="mono">${esc(f.name)}</span>${f.hidden ? '<span class="pill" style="--c:var(--amber)">hidden</span>' : ''}<span class="t3">${fmtBytes(f.size)}</span><span class="t3 hide-m">${esc(d(f.when))}</span>${f.size && f.lba * 2048 + f.size <= r.size ? dxOpenBtn(f.name.split('/').pop(), r.bytes.subarray(f.lba * 2048, f.lba * 2048 + f.size)) : ''}</div>`).join('')}</div></div></section>`; }
  if(O) return `<section class="card${O.files.length ? ' warnc' : ''}"><header><h3>${ico('book-open','sm')} OneNote notebook</h3><span class="t3">${O.files.length} embedded file${O.files.length === 1 ? '' : 's'}</span></header><div class="body">
      ${O.files.length ? `<div class="fx-note red">OneNote files were used in 2023–24 to deliver scripts behind a fake “double-click to view” button. Check each embedded file.</div>${O.files.map(f => `<div class="kv"><span class="mono">${esc(f.name)}</span><b>${esc(f.type)} · ${fmtBytes(f.size)}</b>${dxOpenBtn(f.name, f.bytes)}</div>`).join('')}` : '<p class="t3" style="margin:0">No embedded files.</p>'}</div></section>`;
  const encN = A.files.filter(f => f.enc).length, risky = A.files.filter(f => DX_RISKY.test(f.name));
  return `<section class="card${risky.length || A.encHeaders ? ' warnc' : ''}"><header><h3>${ico('box','sm')} RAR archive</h3><span class="t3">RAR${A.v} · ${A.files.length} entries</span></header><div class="body">
    ${A.encHeaders ? '<div class="fx-note amber">The file names themselves are encrypted — nothing can be listed without the password.</div>' : ''}${encN ? `<div class="fx-note amber">${encN} encrypted file${encN > 1 ? 's' : ''} — password-protected archives get past mail scanners; the password is usually in the e-mail body.</div>` : ''}
    ${risky.length ? `<div class="fx-note red">Inside: ${esc(risky.map(f => f.name).slice(0, 6).join(', '))}</div>` : ''}${A.files.length ? fxKv('Packed on', [...new Set(A.files.map(f => f.os))].join(', ')) : ''}
    <div class="ziplist">${A.files.slice(0, 300).map(f => `<div><span class="mono">${esc(f.name)}</span>${f.enc ? `<span class="pill" style="--c:var(--amber)">${ico('lock','sm')}encrypted</span>` : ''}<span class="t3">${fmtBytes(f.size)}</span><span class="t3 hide-m">${esc(d(f.when))}</span></div>`).join('')}</div>
    <p class="t3 small" style="margin:8px 0 0">RAR contents are compressed with RAR's own method; the browser lists them but cannot unpack them — use 7-Zip in your research environment.</p></div></section>`;
}
const DX_ACTS = {
  dxOpen:(id, v) => { const X = DX.blobs.get(v); if(!X) return toast('That item is no longer in memory — open the file again'); UI.fxParent = UI.labFile ? UI.labFile.name : ''; labLoad(new File([X.bytes], X.name.split(/[\\/]/).pop() || 'item', {lastModified:Date.now()}), false); },
  dxHeaders:() => { const r = UI.labFile; if(!r || !r.mail) return; UI.emlIn = r.mail.head; UI.labTab = 'email'; renderMain(); },
};
