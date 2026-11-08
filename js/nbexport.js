/* ==========================================================================
   Notebook export and Word import. Everything runs in the browser.
   One export document (plain, semantic HTML) is built from the chosen pages,
   then turned into: a Word .docx (written by hand: OOXML in a stored zip),
   a single HTML file, Markdown + images in a .zip, a printout (PDF), or rich
   text on the clipboard for OneNote / Google Docs.
   ========================================================================== */
const NBX_FMT = {
  docx:{n:'Word document', tag:'DOCX', c:'#2563eb', d:'Headings, pictures, code and tables kept. One file.', to:['Word', 'Google Docs', 'OneNote']},
  html:{n:'Web page', tag:'HTML', c:'#475569', d:'One file with the pictures inside. Opens anywhere, pastes cleanly.', to:['OneNote', 'Docs', 'Confluence']},
  md:{n:'Markdown + images', tag:'MD', c:'#0f172a', d:'A .zip with one .md per page and an images folder.', to:['Obsidian', 'Notion', 'GitHub']},
  pdf:{n:'PDF', tag:'PDF', c:'#c81e1e', d:'Print-ready. Pick “Save as PDF” in the print dialog.', to:['Share', 'Archive']}};
const NBX_OPT = [['img', 'Pictures and screenshots'], ['src', 'Source links and dates'], ['cards', 'Flashcards as a Q&A table'], ['att', 'Attachments (in a .zip)'], ['toc', 'Table of contents'], ['tags', 'Tags']];
const nbSlug = s => String(s || '').normalize('NFKD').replace(/[^\w\- ]+/g, '').trim().replace(/\s+/g, '-').toLowerCase().slice(0, 60) || 'notebook';

/* ---------- what is being exported ---------- */
function nbModel(scope, id){
  const N = DB.nb, items = [];
  const pageItems = (s, lvl) => nbPagesOf(s.id).forEach(p => items.push({k:'page', p, lvl}));
  if(scope === 'page'){ const p = nbPage(id), s = p && nbSec(p.sectionId), b = s && nbBook(s.bookId); if(!p) return null; items.push({k:'page', p, lvl:1, solo:true}); return {title:p.title, sub:[b && b.name, s && s.name].filter(Boolean).join(' · '), items, pages:[p], name:p.title}; }
  if(scope === 'sec'){ const s = nbSec(id), b = s && nbBook(s.bookId); if(!s) return null; pageItems(s, 2); return {title:s.name, sub:b ? b.name : '', items, pages:nbPagesOf(s.id), name:s.name}; }
  if(scope === 'book'){ const b = nbBook(id); if(!b) return null; nbSecsOf(b.id).forEach(s => { items.push({k:'sec', s, lvl:2}); pageItems(s, 3); }); return {title:b.name, sub:b.kind || '', items, pages:nbBookPages(b.id), name:b.name}; }
  N.books.forEach(b => { items.push({k:'book', b, lvl:2}); nbSecsOf(b.id).forEach(s => { items.push({k:'sec', s, lvl:3}); pageItems(s, 4); }); });
  return {title:'Notebooks', sub:N.books.length + ' notebooks', items, pages:N.pages.slice(), name:'notebooks'};
}
/* the export document: plain HTML with real headings (h1 = title), shifted to fit the scope */
function nbExportBody(M, o){
  const fmtD = t => new Date(t).toLocaleDateString(undefined, {day:'numeric', month:'short', year:'numeric'});
  let out = `<h1>${esc(M.title)}</h1><p class="nbx-meta">${esc([M.sub, M.pages.length > 1 ? M.pages.length + ' pages' : '', 'exported ' + fmtD(Date.now())].filter(Boolean).join(' · '))}</p>`;
  if(o.toc && M.items.length > 1){ out += '<p class="nbx-toch"><b>Contents</b></p><ul class="nbx-toc">';
    let open = 0; for(const it of M.items){ if(it.k === 'page') out += `<li>${esc(it.p.title)}</li>`; else { if(open){ out += '</ul></li>'; open--; } out += `<li><b>${esc(it.k === 'sec' ? it.s.name : it.b.name)}</b><ul>`; open++; } }
    while(open--) out += '</ul></li>'; out += '</ul>'; }
  for(const it of M.items){
    if(it.k === 'book'){ out += `<h${it.lvl}>${esc(it.b.name)}</h${it.lvl}>`; continue; }
    if(it.k === 'sec'){ out += `<h${it.lvl}>${esc(it.s.name)}</h${it.lvl}>`; continue; }
    const p = it.p, shift = it.solo ? 0 : it.lvl - 1;
    if(!it.solo) out += `<h${Math.min(6, it.lvl)}>${esc(p.title)}</h${Math.min(6, it.lvl)}>`;
    const meta = [o.src && p.src ? (nbSafeUrl(p.src) ? `Source: <a href="${esc(p.src)}">${esc(p.src)}</a>` : 'Source: ' + esc(p.src)) : '', o.src ? 'Updated ' + fmtD(p.updated) : '', o.tags && p.tags.length ? 'Tags: ' + esc(p.tags.join(', ')) : ''].filter(Boolean);
    if(meta.length) out += `<p class="nbx-meta">${meta.join(' · ')}</p>`;
    const body = nbDoc(nbClean(p.html, {src:o.img ? (o.forExport ? 'data' : true) : false}));
    body.querySelectorAll('h2,h3,h4').forEach(h => { const n = Math.min(6, +h.tagName[1] + shift), x = document.createElement('h' + n); x.innerHTML = h.innerHTML; h.replaceWith(x); });
    body.querySelectorAll('div.nb-link').forEach(d => { const a = d.querySelector('a'), x = document.createElement('p'); x.className = 'nbx-link'; x.innerHTML = `<a href="${esc(a.getAttribute('href'))}">${esc(a.textContent)}</a> · ${esc(hostOf(a.getAttribute('href')))}`; d.replaceWith(x); });
    body.querySelectorAll('div.nb-call').forEach(d => d.className = 'nbx-call');
    body.querySelectorAll('ul.nb-check').forEach(u => { u.className = 'nbx-check'; u.querySelectorAll(':scope > li').forEach(li => { li.insertAdjacentText('afterbegin', li.classList.contains('done') ? '☑ ' : '☐ '); li.removeAttribute('class'); }); });
    if(!o.img) body.querySelectorAll('figure').forEach(f => { const c = f.querySelector('figcaption'), x = document.createElement('p'); x.className = 'nbx-meta'; x.textContent = '[Picture' + (c && c.textContent.trim() ? ': ' + c.textContent.trim() : '') + ']'; f.replaceWith(x); });
    else body.querySelectorAll('img[data-m]').forEach(i => { const m = nbM(i.dataset.m); if(m && m.w){ i.setAttribute('width', Math.min(m.w, 640)); i.setAttribute('height', Math.round(m.h * Math.min(m.w, 640) / m.w)); } });
    body.querySelectorAll('figcaption').forEach(c => { if(!c.textContent.trim()) c.remove(); });
    const cards = nbInfo(p).cards;
    if(o.cards && cards.length){
      const ps = [...body.querySelectorAll('p')];
      for(let i = 0; i < ps.length; i++){ const t = ps[i].textContent.trim(); if(/^Q\s*[:.]/i.test(t)){ if(/\sA\s*[:.]/.test(t)) ps[i].remove(); else if(ps[i + 1] && /^A\s*[:.]/i.test(ps[i + 1].textContent.trim())){ ps[i].remove(); ps[i + 1].remove(); i++; } } }
      const tbl = `<table class="nbx-cards"><tr><th>Question</th><th>Answer</th></tr>${cards.map(k => `<tr><td>${esc(k.q)}</td><td>${esc(k.a)}</td></tr>`).join('')}</table>`;
      const fh = [...body.querySelectorAll('h1,h2,h3,h4,h5,h6')].find(h => /^flash ?cards?$/i.test(h.textContent.trim()));
      if(fh) fh.insertAdjacentHTML('afterend', tbl); else body.insertAdjacentHTML('beforeend', `<p class="nbx-fch"><b>Flashcards</b></p>` + tbl); }
    out += body.innerHTML;
  }
  return out;
}
const NBX_CSS = `body{font:15px/1.65 -apple-system,'Segoe UI',Calibri,Arial,sans-serif;color:#1f2937;max-width:820px;margin:40px auto;padding:0 24px}
h1{font-size:30px;margin:0 0 4px;letter-spacing:-.01em}h2{font-size:22px;margin:30px 0 8px}h3{font-size:18px;margin:24px 0 6px}h4,h5,h6{font-size:15px;margin:18px 0 4px}
.nbx-meta{color:#6b7280;font-size:13px;margin:0 0 14px}pre{font:13px/1.55 Consolas,'Courier New',monospace;background:#f4f4f5;border-radius:6px;padding:10px 14px;white-space:pre-wrap;overflow-wrap:anywhere}
code{font-family:Consolas,'Courier New',monospace;font-size:.92em;background:#f4f4f5;padding:1px 4px;border-radius:4px}mark{background:#fde68a}
table{border-collapse:collapse;margin:8px 0 16px}th,td{border:1px solid #d1d5db;padding:5px 9px;text-align:left;vertical-align:top}th{background:#f3f4f6}
figure{margin:12px 0}img{max-width:100%;height:auto;border:1px solid #e5e7eb;border-radius:6px}figcaption{color:#6b7280;font-size:13px;font-style:italic;margin-top:4px}
.nbx-call{background:#eef2ff;border-radius:6px;padding:4px 14px;margin:10px 0}blockquote{color:#4b5563;font-style:italic;margin:10px 0 10px 18px}
.nbx-check{list-style:none;padding-left:4px}a{color:#2563eb}.nbx-toc{margin-bottom:24px}`;
const nbHtmlFile = (M, body) => `<!doctype html>\n<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(M.title)}</title><style>${NBX_CSS}</style></head><body>\n${body}\n<p class="nbx-meta" style="margin-top:40px">Exported from ${esc(BRAND.name)}</p></body></html>`;
/* inline styles, because OneNote and Docs drop <style> when pasting */
function nbInlineStyles(body){
  const d = nbDoc(body), S = {pre:"font-family:Consolas,'Courier New',monospace;font-size:10pt;background:#f4f4f5;padding:8px 12px;white-space:pre-wrap", code:"font-family:Consolas,'Courier New',monospace;background:#f4f4f5", mark:'background:#fde68a',
    table:'border-collapse:collapse', th:'border:1px solid #d1d5db;padding:4px 8px;background:#f3f4f6;font-weight:bold;text-align:left', td:'border:1px solid #d1d5db;padding:4px 8px;vertical-align:top', figcaption:'color:#6b7280;font-size:9pt;font-style:italic', blockquote:'color:#4b5563;font-style:italic'};
  for(const [t, s] of Object.entries(S)) d.querySelectorAll(t).forEach(e => e.setAttribute('style', s));
  d.querySelectorAll('.nbx-meta').forEach(e => e.setAttribute('style', 'color:#6b7280;font-size:9pt')); d.querySelectorAll('.nbx-call').forEach(e => e.setAttribute('style', 'background:#eef2ff;padding:6px 12px'));
  return d.innerHTML;
}

/* ---------- small zip writer (stored entries) and reader ---------- */
const NBX_CRC = (() => { const t = new Uint32Array(256); for(let n = 0; n < 256; n++){ let c = n; for(let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
const nbCrc = b => { let c = 0xFFFFFFFF; for(let i = 0; i < b.length; i++) c = NBX_CRC[(c ^ b[i]) & 255] ^ (c >>> 8); return (c ^ 0xFFFFFFFF) >>> 0; };
function nbZip(files, type){
  const enc = new TextEncoder(), parts = [], cen = [], dt = new Date(); let off = 0;
  const tm = (dt.getHours() << 11) | (dt.getMinutes() << 5) | (dt.getSeconds() >> 1), dd = ((dt.getFullYear() - 1980) << 9) | ((dt.getMonth() + 1) << 5) | dt.getDate();
  for(const f of files){ const name = enc.encode(f.name), data = typeof f.data === 'string' ? enc.encode(f.data) : f.data, crc = nbCrc(data);
    const h = new DataView(new ArrayBuffer(30)); h.setUint32(0, 0x04034b50, true); h.setUint16(4, 20, true); h.setUint16(6, 0x0800, true); h.setUint16(10, tm, true); h.setUint16(12, dd, true); h.setUint32(14, crc, true); h.setUint32(18, data.length, true); h.setUint32(22, data.length, true); h.setUint16(26, name.length, true);
    const c = new DataView(new ArrayBuffer(46)); c.setUint32(0, 0x02014b50, true); c.setUint16(4, 20, true); c.setUint16(6, 20, true); c.setUint16(8, 0x0800, true); c.setUint16(12, tm, true); c.setUint16(14, dd, true); c.setUint32(16, crc, true); c.setUint32(20, data.length, true); c.setUint32(24, data.length, true); c.setUint16(28, name.length, true); c.setUint32(42, off, true);
    parts.push(new Uint8Array(h.buffer), name, data); cen.push(new Uint8Array(c.buffer), name); off += 30 + name.length + data.length; }
  const size = cen.reduce((s, x) => s + x.length, 0), e = new DataView(new ArrayBuffer(22)); e.setUint32(0, 0x06054b50, true); e.setUint16(8, files.length, true); e.setUint16(10, files.length, true); e.setUint32(12, size, true); e.setUint32(16, off, true);
  return new Blob([...parts, ...cen, new Uint8Array(e.buffer)], {type:type || 'application/zip'});
}
async function nbUnzip(u8){
  const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength); let e = u8.length - 22; while(e >= 0 && dv.getUint32(e, true) !== 0x06054b50) e--; if(e < 0) throw new Error('not a zip file');
  const n = dv.getUint16(e + 10, true), files = {}; let p = dv.getUint32(e + 16, true), total = 0;
  for(let i = 0; i < n && p + 46 <= u8.length; i++){ if(dv.getUint32(p, true) !== 0x02014b50) break;
    const method = dv.getUint16(p + 10, true), cs = dv.getUint32(p + 20, true), nl = dv.getUint16(p + 28, true), xl = dv.getUint16(p + 30, true), cl = dv.getUint16(p + 32, true), lo = dv.getUint32(p + 42, true);
    const name = new TextDecoder().decode(u8.subarray(p + 46, p + 46 + nl)), st = lo + 30 + dv.getUint16(lo + 26, true) + dv.getUint16(lo + 28, true);
    const us = dv.getUint32(p + 24, true); total += us; if(us > 150 * 1048576 || total > 400 * 1048576 || n > 5000) throw new Error('the file unpacks to more than this browser should hold');   // zip bombs
    files[name] = {method, raw:u8.subarray(st, st + cs), us}; p += 46 + nl + xl + cl; }
  return {names:Object.keys(files), get:async name => { const f = files[name]; if(!f) return null; const out = f.method === 0 ? f.raw : f.method === 8 ? await inflateRaw(f.raw) : null; if(out && out.length > f.us + 1024) throw new Error('size mismatch in the zip'); return out; }};
}
const nbB64 = u8 => { let s = ''; for(let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000)); return btoa(s); };
const nbUnB64 = d => { const b = atob(d.slice(d.indexOf(',') + 1)), u = new Uint8Array(b.length); for(let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; };
/* a picture as PNG/JPEG/GIF bytes (Word can't show WebP), with its size */
async function nbImgBytes(src, want){
  const type = src.slice(5, src.indexOf(';')), img = await nbLoadImg(src), w = img.naturalWidth, h = img.naturalHeight;
  if((want || /^image\/(png|jpeg|gif)$/).test(type)) return {bytes:nbUnB64(src), ext:type === 'image/jpeg' ? 'jpeg' : type.split('/')[1], w, h};
  const c = document.createElement('canvas'); c.width = w; c.height = h; c.getContext('2d').drawImage(img, 0, 0); const d = c.toDataURL('image/png'); return {bytes:nbUnB64(d), ext:'png', w, h};
}

/* ---------- Word (.docx) ---------- */
const xe = s => String(s).replace(/[\x00-\x08\x0B\x0C\x0E-\x1F￾￿]/g, '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const NBX_W = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture"';
function nbDocxStyles(){
  const ps = (id, name, ppr, rpr, extra) => `<w:style w:type="paragraph" w:styleId="${id}"><w:name w:val="${name}"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/>${extra || ''}<w:qFormat/><w:pPr>${ppr}</w:pPr><w:rPr>${rpr}</w:rPr></w:style>`;
  const hd = (n, sz, before) => ps('Heading' + n, 'heading ' + n, `<w:keepNext/><w:spacing w:before="${before}" w:after="80"/><w:outlineLvl w:val="${n - 1}"/>`, `<w:b/><w:color w:val="111827"/><w:sz w:val="${sz}"/><w:szCs w:val="${sz}"/>`);
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:styles ${NBX_W}>
<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:eastAsia="Calibri" w:cs="Calibri"/><w:sz w:val="22"/><w:szCs w:val="22"/><w:lang w:val="en-GB"/></w:rPr></w:rPrDefault><w:pPrDefault><w:pPr><w:spacing w:after="120" w:line="276" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>
<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:qFormat/><w:rPr><w:color w:val="1F2937"/></w:rPr></w:style>
${ps('Title', 'Title', '<w:spacing w:after="60"/>', '<w:b/><w:color w:val="111827"/><w:sz w:val="48"/><w:szCs w:val="48"/>')}
${hd(1, 34, 360)}${hd(2, 28, 280)}${hd(3, 24, 240)}${hd(4, 22, 200)}${hd(5, 22, 160)}
${ps('Meta', 'Meta', '<w:spacing w:after="160"/>', '<w:color w:val="6B7280"/><w:sz w:val="18"/><w:szCs w:val="18"/>')}
${ps('Code', 'Code', '<w:shd w:val="clear" w:color="auto" w:fill="F4F4F5"/><w:spacing w:before="60" w:after="160" w:line="240" w:lineRule="auto"/><w:ind w:left="113" w:right="113"/>', '<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:cs="Consolas"/><w:sz w:val="18"/><w:szCs w:val="18"/>')}
${ps('Quote', 'Quote', '<w:ind w:left="567"/>', '<w:i/><w:color w:val="4B5563"/>')}
${ps('Callout', 'Callout', '<w:shd w:val="clear" w:color="auto" w:fill="EEF2FF"/><w:spacing w:before="60" w:after="60"/><w:ind w:left="113" w:right="113"/>', '')}
${ps('Caption', 'caption', '<w:spacing w:before="40" w:after="200"/>', '<w:i/><w:color w:val="6B7280"/><w:sz w:val="18"/><w:szCs w:val="18"/>')}
${ps('ListParagraph', 'List Paragraph', '<w:spacing w:after="60"/><w:ind w:left="720"/><w:contextualSpacing/>', '')}
<w:style w:type="character" w:styleId="Hyperlink"><w:name w:val="Hyperlink"/><w:rPr><w:color w:val="2563EB"/><w:u w:val="single"/></w:rPr></w:style>
<w:style w:type="table" w:styleId="TableGrid"><w:name w:val="Table Grid"/><w:tblPr><w:tblBorders>${['top', 'left', 'bottom', 'right', 'insideH', 'insideV'].map(s => `<w:${s} w:val="single" w:sz="4" w:space="0" w:color="D1D5DB"/>`).join('')}</w:tblBorders><w:tblCellMar><w:top w:w="60" w:type="dxa"/><w:left w:w="100" w:type="dxa"/><w:bottom w:w="60" w:type="dxa"/><w:right w:w="100" w:type="dxa"/></w:tblCellMar></w:tblPr></w:style>
</w:styles>`;
}
async function nbDocx(M, body){
  const doc = nbDoc(body), rels = [], media = [], nums = [], imgCache = new Map(); let rid = 10, pid = 1;
  const relId = (type, target, ext) => { const id = 'rId' + (rid++); rels.push(`<Relationship Id="${id}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/${type}" Target="${xe(target)}"${ext ? ' TargetMode="External"' : ''}/>`); return id; };
  for(const im of doc.querySelectorAll('img[src^="data:image"]')){ const src = im.getAttribute('src'); if(imgCache.has(src)) continue;
    try{ const b = await nbImgBytes(src), name = 'image' + (media.length + 1) + '.' + b.ext; media.push({name:'word/media/' + name, data:b.bytes}); imgCache.set(src, {...b, id:relId('image', 'media/' + name)}); }catch(e){} }
  const MAXW = 5760720;   // 6.3 in
  const drawing = im => { const m = imgCache.get(im.getAttribute('src')); if(!m) return ''; let cx = m.w * 9525, cy = m.h * 9525; if(cx > MAXW){ cy = Math.round(cy * MAXW / cx); cx = MAXW; } const n = pid++;
    return `<w:r><w:drawing><wp:inline distT="0" distB="0" distL="0" distR="0"><wp:extent cx="${cx}" cy="${cy}"/><wp:docPr id="${n}" name="Picture ${n}" descr="${xe(im.getAttribute('alt') || '')}"/><wp:cNvGraphicFramePr><a:graphicFrameLocks noChangeAspect="1"/></wp:cNvGraphicFramePr><a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:pic><pic:nvPicPr><pic:cNvPr id="${n}" name="image${n}"/><pic:cNvPicPr/></pic:nvPicPr><pic:blipFill><a:blip r:embed="${m.id}"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill><pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="${cx}" cy="${cy}"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr></pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r>`; };
  const run = (t, f) => { const pr = (f.b ? '<w:b/>' : '') + (f.i ? '<w:i/>' : '') + (f.s ? '<w:strike/>' : '') + (f.code ? '<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:cs="Consolas"/><w:shd w:val="clear" w:color="auto" w:fill="F4F4F5"/>' : '') + (f.mark ? '<w:highlight w:val="yellow"/>' : '') + (f.u || f.link ? '<w:u w:val="single"/>' : '') + (f.link ? '<w:color w:val="2563EB"/>' : '') + (f.sup ? '<w:vertAlign w:val="superscript"/>' : f.sub ? '<w:vertAlign w:val="subscript"/>' : '');
    return `<w:r>${pr ? '<w:rPr>' + pr + '</w:rPr>' : ''}<w:t xml:space="preserve">${xe(t)}</w:t></w:r>`; };
  const inl = (n, f) => { let o = ''; for(const c of n.childNodes){
      if(c.nodeType === 3){ const t = c.data.replace(/\s+/g, ' '); if(t) o += run(t, f); continue; } if(c.nodeType !== 1) continue; const T = c.tagName;
      if(T === 'BR'){ o += '<w:r><w:br/></w:r>'; continue; } if(T === 'IMG'){ o += drawing(c); continue; }
      if(T === 'A'){ const u = nbSafeUrl(c.getAttribute('href')); if(u){ o += `<w:hyperlink r:id="${relId('hyperlink', u, true)}" w:history="1">${inl(c, {...f, link:true})}</w:hyperlink>`; continue; } }
      const g = {...f}; if(T === 'B' || T === 'STRONG') g.b = 1; else if(T === 'I' || T === 'EM') g.i = 1; else if(T === 'U') g.u = 1; else if(T === 'S') g.s = 1; else if(T === 'MARK') g.mark = 1; else if(T === 'CODE') g.code = 1; else if(T === 'SUP') g.sup = 1; else if(T === 'SUB') g.sub = 1;
      o += inl(c, g); } return o; };
  const para = (style, content, extra) => `<w:p>${style || extra ? `<w:pPr>${style ? `<w:pStyle w:val="${style}"/>` : ''}${extra || ''}</w:pPr>` : ''}${content}</w:p>`;
  const list = (ul, lvl, ctx) => { let o = ''; const ordered = ul.tagName === 'OL', check = ul.classList.contains('nbx-check');
    let num = 1; if(ordered){ nums.push(2); num = nums.length + 2; } else if(!check) num = 1;
    for(const li of ul.children){ if(li.tagName !== 'LI') continue; const inner = document.createElement('div'), subs = [];
      for(const c of [...li.childNodes]){ if(c.nodeType === 1 && (c.tagName === 'UL' || c.tagName === 'OL')) subs.push(c); else if(c.nodeType === 1 && c.tagName === 'P'){ inner.append(...c.childNodes, document.createElement('br')); } else inner.append(c.cloneNode(true)); }
      if(inner.lastChild && inner.lastChild.tagName === 'BR') inner.lastChild.remove();
      o += check ? para('ListParagraph', inl(inner, {}), `<w:ind w:left="${720 + lvl * 360}" w:hanging="360"/>`) : para('ListParagraph', inl(inner, {}), `<w:numPr><w:ilvl w:val="${Math.min(lvl, 8)}"/><w:numId w:val="${num}"/></w:numPr>`);
      for(const s of subs) o += list(s, lvl + 1, ctx); }
    return o; };
  const cellXml = (c, w) => { const kids = [...c.children].filter(x => /^(P|UL|OL|PRE)$/.test(x.tagName)); const inner = kids.length ? blocks(c, {}) : para('', inl(c, c.tagName === 'TH' ? {b:1} : {}), '<w:spacing w:after="0"/>');
    return `<w:tc><w:tcPr><w:tcW w:w="${w}" w:type="pct"/>${c.tagName === 'TH' ? '<w:shd w:val="clear" w:color="auto" w:fill="F3F4F6"/>' : ''}</w:tcPr>${inner || '<w:p/>'}</w:tc>`; };
  const table = t => { const rows = [...t.querySelectorAll('tr')].filter(r => r.closest('table') === t); if(!rows.length) return ''; const cols = Math.max(...rows.map(r => r.children.length)), w = Math.floor(5000 / cols);
    return `<w:tbl><w:tblPr><w:tblStyle w:val="TableGrid"/><w:tblW w:w="5000" w:type="pct"/><w:tblLook w:val="04A0" w:firstRow="1" w:lastRow="0" w:firstColumn="0" w:lastColumn="0" w:noHBand="0" w:noVBand="1"/></w:tblPr><w:tblGrid>${Array.from({length:cols}, () => '<w:gridCol/>').join('')}</w:tblGrid>
      ${rows.map((r, i) => `<w:tr>${i === 0 && r.querySelector('th') ? '<w:trPr><w:tblHeader/></w:trPr>' : ''}${[...r.children].map(c => cellXml(c, w)).join('')}${Array.from({length:cols - r.children.length}, () => `<w:tc><w:tcPr><w:tcW w:w="${w}" w:type="pct"/></w:tcPr><w:p/></w:tc>`).join('')}</w:tr>`).join('')}</w:tbl>${para('', '', '<w:spacing w:after="60"/>')}`; };
  const blocks = (n, ctx) => { let o = ''; for(const c of n.childNodes){
      if(c.nodeType === 3){ if(c.data.trim()) o += para(ctx.style, run(c.data.trim(), {})); continue; } if(c.nodeType !== 1) continue; const T = c.tagName;
      if(/^H[1-6]$/.test(T)){ const lv = +T[1]; o += para(lv === 1 ? 'Title' : 'Heading' + Math.min(5, lv - 1), inl(c, {})); }
      else if(T === 'P'){ o += para(c.classList.contains('nbx-meta') ? 'Meta' : ctx.style || '', inl(c, {})); }
      else if(T === 'UL' || T === 'OL') o += list(c, 0, ctx);
      else if(T === 'PRE'){ const lines = c.textContent.split('\n'); o += para('Code', lines.map((l, i) => (i ? '<w:r><w:br/></w:r>' : '') + `<w:r><w:t xml:space="preserve">${xe(l)}</w:t></w:r>`).join('')); }
      else if(T === 'BLOCKQUOTE') o += blocks(c, {style:'Quote'});
      else if(T === 'DIV' && c.classList.contains('nbx-call')) o += blocks(c, {style:'Callout'});
      else if(T === 'TABLE') o += table(c);
      else if(T === 'FIGURE'){ const im = c.querySelector('img'), cap = c.querySelector('figcaption'); if(im) o += para('', drawing(im), '<w:keepNext/><w:spacing w:after="40"/>'); if(cap) o += para('Caption', inl(cap, {})); }
      else if(T === 'IMG') o += para('', drawing(c));
      else if(T === 'HR') o += para('', '', '<w:pBdr><w:bottom w:val="single" w:sz="6" w:space="1" w:color="D1D5DB"/></w:pBdr>');
      else o += blocks(c, ctx); }
    return o; };
  const xml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document ${NBX_W}><w:body>${blocks(doc, {})}<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1134" w:right="1134" w:bottom="1134" w:left="1134" w:header="567" w:footer="567" w:gutter="0"/></w:sectPr></w:body></w:document>`;
  const lvl = (i, fmt, txt, font) => `<w:lvl w:ilvl="${i}"><w:start w:val="1"/><w:numFmt w:val="${fmt}"/><w:lvlText w:val="${txt}"/><w:lvlJc w:val="left"/><w:pPr><w:ind w:left="${720 + i * 360}" w:hanging="360"/></w:pPr>${font ? `<w:rPr><w:rFonts w:ascii="${font}" w:hAnsi="${font}" w:hint="default"/></w:rPr>` : ''}</w:lvl>`;
  const numbering = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:numbering ${NBX_W}>
<w:abstractNum w:abstractNumId="0"><w:multiLevelType w:val="hybridMultilevel"/>${Array.from({length:9}, (_, i) => lvl(i, 'bullet', ['•', '◦', '▪'][i % 3])).join('')}</w:abstractNum>
<w:abstractNum w:abstractNumId="1"><w:multiLevelType w:val="hybridMultilevel"/>${Array.from({length:9}, (_, i) => lvl(i, ['decimal', 'lowerLetter', 'lowerRoman'][i % 3], '%' + (i + 1) + '.')).join('')}</w:abstractNum>
<w:num w:numId="1"><w:abstractNumId w:val="0"/></w:num>${nums.map((_, i) => `<w:num w:numId="${i + 3}"><w:abstractNumId w:val="1"/><w:lvlOverride w:ilvl="0"><w:startOverride w:val="1"/></w:lvlOverride></w:num>`).join('')}</w:numbering>`;
  const now = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
  return nbZip([
    {name:'[Content_Types].xml', data:`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Default Extension="png" ContentType="image/png"/><Default Extension="jpeg" ContentType="image/jpeg"/><Default Extension="gif" ContentType="image/gif"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/><Override PartName="/word/numbering.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/></Types>`},
    {name:'_rels/.rels', data:`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/></Relationships>`},
    {name:'docProps/core.xml', data:`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><dc:title>${xe(M.title)}</dc:title><dc:creator>${xe(BRAND.name)}</dc:creator><dcterms:created xsi:type="dcterms:W3CDTF">${now}</dcterms:created><dcterms:modified xsi:type="dcterms:W3CDTF">${now}</dcterms:modified></cp:coreProperties>`},
    {name:'word/document.xml', data:xml},
    {name:'word/styles.xml', data:nbDocxStyles()},
    {name:'word/numbering.xml', data:numbering},
    {name:'word/_rels/document.xml.rels', data:`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/numbering" Target="numbering.xml"/>${rels.join('')}</Relationships>`},
    ...media], 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
}

/* ---------- Markdown ---------- */
const mdEsc = s => s.replace(/\\/g, '\\\\').replace(/([*_`[\]<])/g, '\\$1');
function nbMarkdown(body, imgName){
  const doc = nbDoc(body);
  const inl = n => { let o = ''; for(const c of n.childNodes){ if(c.nodeType === 3){ o += mdEsc(c.data.replace(/\s+/g, ' ')); continue; } if(c.nodeType !== 1) continue; const T = c.tagName, x = inl(c);
      if(T === 'BR') o += '  \n'; else if(T === 'B' || T === 'STRONG') o += x.trim() ? `**${x}**` : x; else if(T === 'I' || T === 'EM') o += x.trim() ? `*${x}*` : x; else if(T === 'S') o += `~~${x}~~`;
      else if(T === 'MARK') o += `==${x}==`; else if(T === 'CODE') o += '`' + c.textContent.replace(/`/g, 'ˋ') + '`'; else if(T === 'A'){ const u = nbSafeUrl(c.getAttribute('href')); o += u ? `[${x}](${u.replace(/\)/g, '%29')})` : x; }
      else if(T === 'IMG'){ const f = imgName(c); o += f ? `![${mdEsc(c.getAttribute('alt') || '')}](${f})` : ''; } else o += x; }
    return o; };
  const lst = (ul, ind) => [...ul.children].filter(l => l.tagName === 'LI').map((li, i) => { const sub = [...li.children].filter(c => c.tagName === 'UL' || c.tagName === 'OL'), cl = li.cloneNode(true); cl.querySelectorAll(':scope > ul, :scope > ol').forEach(x => x.remove());
      let t = inl(cl).trim(); const mark = ul.tagName === 'OL' ? (i + 1) + '. ' : '- '; if(ul.classList.contains('nbx-check')) t = t.replace(/^☑\s*/, '[x] ').replace(/^☐\s*/, '[ ] ');
      return ind + mark + t + '\n' + sub.map(s => lst(s, ind + '   ')).join(''); }).join('');
  const blk = n => [...n.childNodes].map(c => { if(c.nodeType === 3) return c.data.trim() ? mdEsc(c.data.trim()) + '\n\n' : ''; if(c.nodeType !== 1) return ''; const T = c.tagName;
      if(/^H[1-6]$/.test(T)) return '#'.repeat(+T[1]) + ' ' + inl(c).trim() + '\n\n';
      if(T === 'P') return (c.classList.contains('nbx-meta') ? '*' + inl(c).trim() + '*' : inl(c).trim()) + '\n\n';
      if(T === 'UL' || T === 'OL') return lst(c, '') + '\n';
      if(T === 'PRE') return '```\n' + c.textContent.replace(/\n$/, '') + '\n```\n\n';
      if(T === 'BLOCKQUOTE' || (T === 'DIV' && c.classList.contains('nbx-call'))) return blk(c).trim().split('\n').map(l => '> ' + l).join('\n') + '\n\n';
      if(T === 'TABLE'){ const rows = [...c.querySelectorAll('tr')].map(r => [...r.children].map(x => inl(x).replace(/\|/g, '\\|').replace(/\n/g, ' ').trim())); if(!rows.length) return ''; const w = Math.max(...rows.map(r => r.length));
        const line = r => '| ' + Array.from({length:w}, (_, i) => r[i] || '').join(' | ') + ' |'; return [line(rows[0]), '|' + Array.from({length:w}, () => ' --- ').join('|') + '|', ...rows.slice(1).map(line)].join('\n') + '\n\n'; }
      if(T === 'FIGURE'){ const im = c.querySelector('img'), cap = c.querySelector('figcaption'), f = im && imgName(im); return (f ? `![${mdEsc(cap ? cap.textContent.trim() : '')}](${f})\n` : '') + (cap ? '*' + inl(cap).trim() + '*\n' : '') + '\n'; }
      if(T === 'HR') return '---\n\n';
      return blk(c); }).join('');
  return blk(doc).replace(/\n{3,}/g, '\n\n').trim() + '\n';
}

/* ---------- running an export ---------- */
function nbOpts(){ DB.nb.xopt = Object.assign({img:true, src:true, cards:true, att:false, toc:true, tags:false}, DB.nb.xopt || {}); return DB.nb.xopt; }
async function nbAttachments(M){ const out = [], seen = new Set(); for(const p of M.pages) for(const id of p.att || []){ const m = nbM(id); if(!m || seen.has(id)) continue; seen.add(id); const b = await nbBlob(id); if(b) out.push({name:'attachments/' + m.name.replace(/[\\/:*?"<>|]+/g, '_'), data:new Uint8Array(await b.arrayBuffer())}); } return out; }
async function nbRunExport(X){
  const M = nbModel(X.scope, X.id), o = nbOpts(); if(!M) return toast('Nothing to export');
  if(o.img) await nbPreload(M.pages);
  const base = nbSlug(M.name), body = nbExportBody(M, {...o, forExport:true}), att = o.att && X.fmt !== 'pdf' ? await nbAttachments(M) : [];
  const out = async (name, blob) => { if(att.length && X.fmt !== 'md'){ const data = new Uint8Array(await blob.arrayBuffer()); return download(base + '.zip', nbZip([{name, data}, ...att]), 'application/zip'); } download(name, blob, blob.type); };
  if(X.fmt === 'pdf') return nbPrint(X);
  if(X.fmt === 'html') return out(base + '.html', new Blob([nbHtmlFile(M, body)], {type:'text/html'}));
  if(X.fmt === 'docx'){ toast('Building the Word file…'); try{ return out(base + '.docx', await nbDocx(M, body)); }catch(e){ console.error(e); return toast('Could not build the Word file: ' + e.message); } }
  if(X.fmt === 'md'){ const files = [], imgs = new Map(), byPage = [];
    // one .md per page, pictures in images/; a section or notebook export also gets an index
    const items = M.items.filter(i => i.k === 'page');
    for(const it of items){ const single = nbModel('page', it.p.id), b = nbExportBody(single, {...o, toc:false, forExport:true}), folder = X.scope === 'page' ? '' : nbSlug((nbSec(it.p.sectionId) || {}).name) + '/';
      const doc = nbDoc(b); for(const im of doc.querySelectorAll('img[src^="data:image"]')){ const src = im.getAttribute('src'); if(!imgs.has(src)){ const ext = src.slice(11, src.indexOf(';')).replace('jpeg', 'jpg'), name = nbSlug(it.p.title) + '-' + (imgs.size + 1) + '.' + ext; imgs.set(src, name); files.push({name:'images/' + name, data:nbUnB64(src)}); } }
      const up = folder ? '../' : '', md = nbMarkdown(b, im => { const n = imgs.get(im.getAttribute('src')); return n ? up + 'images/' + n : ''; });
      const fn = folder + nbSlug(it.p.title) + '.md'; files.push({name:fn, data:md}); byPage.push([it.p.title, fn]); }
    if(X.scope !== 'page' && o.toc) files.unshift({name:'index.md', data:'# ' + M.title + '\n\n' + byPage.map(([t, f]) => `- [${t.replace(/[[\]]/g, '')}](${encodeURI(f)})`).join('\n') + '\n'});
    if(files.length === 1 && !att.length) return download(files[0].name.split('/').pop(), files[0].data, 'text/markdown;charset=utf-8');
    return download(base + '-markdown.zip', nbZip([...files, ...att]), 'application/zip'); }
}
async function nbPrint(X){
  const M = nbModel(X.scope, X.id); if(!M) return; const o = nbOpts(); if(o.img) await nbPreload(M.pages); const body = nbExportBody(M, {...o, forExport:true});
  let root = $('printRoot'); if(!root){ root = document.createElement('div'); root.id = 'printRoot'; document.body.appendChild(root); }
  root.innerHTML = `<article class="nbx-print">${body}</article>`;
  const done = () => { root.innerHTML = ''; window.removeEventListener('afterprint', done); }; window.addEventListener('afterprint', done);
  setTimeout(() => window.print(), 60);
}
async function nbCopyRich(X){
  const M = nbModel(X.scope, X.id); if(!M) return; const o = nbOpts(); if(o.img) await nbPreload(M.pages); const body = nbExportBody(M, {...o, forExport:true}), html = nbInlineStyles(body), text = nbLines(nbDoc(body)).join('\n');
  let ok = false; const onCopy = ev => { ev.clipboardData.setData('text/html', html); ev.clipboardData.setData('text/plain', text); ev.preventDefault(); ok = true; };
  document.addEventListener('copy', onCopy, {once:true}); try{ document.execCommand('copy'); }catch(e){} document.removeEventListener('copy', onCopy);
  if(ok) return toast('Copied with formatting — paste into OneNote, Docs or Word');
  if(navigator.clipboard && window.ClipboardItem) navigator.clipboard.write([new ClipboardItem({'text/html':new Blob([html], {type:'text/html'}), 'text/plain':new Blob([text], {type:'text/plain'})})]).then(() => toast('Copied with formatting'), () => toast('Clipboard blocked by the browser'));
  else toast('Clipboard not available here — use the Word or HTML file');
}

/* ---------- the export dialog ---------- */
function nbExportDlg(scope, id){
  ensureNB(); if(!DB.nb.pages.length) return toast('No pages to export yet');
  const p = scope === 'page' ? nbPage(id) : null, s = scope === 'sec' ? nbSec(id) : p ? nbSec(p.sectionId) : null, b = scope === 'book' ? nbBook(id) : s ? nbBook(s.bookId) : DB.nb.books[0];
  UI.nbx = {fmt:(DB.nb.xopt && DB.nb.xopt.fmt) || 'docx', ctx:{page:p && p.id, sec:s && s.id, book:b && b.id}, scope:p ? 'page' : s ? 'sec' : 'book'};
  if(scope === 'all') UI.nbx.scope = 'all';
  nbPreload(DB.nb.pages).then(() => { if($('nbx')) nbxPaint(); });   // so 'Copy as rich text' can run inside the click
  openDlg(`<div class="nbx" id="nbx">${nbExportInner()}</div>`, true); $('dlg').classList.add('nbxdlg'); $('dlg').setAttribute('aria-labelledby', 'nbxT');
}
function nbExportTarget(){ const X = UI.nbx, c = X.ctx; return {scope:X.scope, id:X.scope === 'page' ? c.page : X.scope === 'sec' ? c.sec : X.scope === 'book' ? c.book : null, fmt:X.fmt}; }
function nbExportInner(){
  const X = UI.nbx, c = X.ctx, o = nbOpts(), T = nbExportTarget(), M = nbModel(T.scope, T.id) || {title:'', pages:[]};
  const scopes = [c.page && ['page', 'This page'], c.sec && ['sec', 'Section · ' + nbPagesOf(c.sec).length], c.book && ['book', 'Notebook · ' + nbBookPages(c.book).length], DB.nb.books.length > 1 && ['all', 'Everything · ' + DB.nb.pages.length]].filter(Boolean);
  const hasAtt = M.pages.some(p => (p.att || []).length), ext = X.fmt === 'md' ? (M.pages.length > 1 || hasAtt && o.att ? '-markdown.zip' : '.md') : X.fmt === 'pdf' ? '' : (hasAtt && o.att ? '.zip' : '.' + X.fmt);
  const body = nbExportBody(M, o);
  return `<header><span class="nbx-ic">${ico('download','sm')}</span><h2 id="nbxT">Export “${esc(M.title)}”</h2><span class="sp"></span><button class="iconbtn" type="button" data-act="dclose" aria-label="Close">${ico('x')}</button></header>
    <div class="nbx-b"><div class="nbx-o">
      <div><div class="nbx-cap" id="nbxW">What</div><div class="nbx-seg" role="radiogroup" aria-labelledby="nbxW">${scopes.map(([k, l]) => `<button role="radio" aria-checked="${X.scope === k}" data-act="nbxScope" data-v="${k}">${esc(l)}</button>`).join('')}</div>
        ${X.scope === 'book' && DB.nb.books.length > 1 ? `<label class="sr" for="nbxBook">Notebook</label><select id="nbxBook" class="nbx-book">${DB.nb.books.map(bk => `<option value="${bk.id}"${bk.id === c.book ? ' selected' : ''}>${esc(bk.name)}</option>`).join('')}</select>` : ''}</div>
      <div><div class="nbx-cap" id="nbxF">Format</div><div class="nbx-fmts" role="radiogroup" aria-labelledby="nbxF">${Object.entries(NBX_FMT).map(([k, f]) => `<button class="nbx-fmt" role="radio" aria-checked="${X.fmt === k}" data-act="nbxFmt" data-v="${k}"><span class="nbx-tag" style="background:${f.c}">${f.tag}</span><span><b>${f.n}</b><small>${f.d}</small><span class="nbx-to">${f.to.map(t => `<i>${t}</i>`).join('')}</span></span></button>`).join('')}</div></div>
      <div class="nbx-chk">${NBX_OPT.map(([k, l]) => { const dis = (k === 'att' && (X.fmt === 'pdf' || !hasAtt)) || (k === 'toc' && X.scope === 'page'); return `<label class="${dis ? 'dis' : ''}"><input type="checkbox" data-nbxo="${k}"${o[k] && !dis ? ' checked' : ''}${dis ? ' disabled' : ''}>${l}</label>`; }).join('')}</div>
      <p class="nbx-tip">${ico('info','sm')}<span><b>OneNote:</b> use <i>Copy as rich text</i> and paste into a page, or <i>Insert → File printout</i> with the Word file. <b>Google Docs:</b> upload the Word file to Drive and open it with Docs. <b>Notion / Obsidian:</b> import the Markdown .zip.</span></p>
    </div>
    <div class="nbx-pv"><div class="nbx-cap">Preview</div><div class="nbx-paper" aria-hidden="true"><div class="nbx-doc">${body}</div></div></div></div>
    <footer><button class="btn ghost" data-act="nbxCopy">${ico('copy','sm')}Copy as rich text</button><span class="sp"></span><button class="btn" data-act="dclose">Cancel</button>
      <button class="btn primary" data-act="nbxGo">${ico(X.fmt === 'pdf' ? 'file-text' : 'download','sm')}${X.fmt === 'pdf' ? 'Print or save as PDF' : 'Download ' + esc(nbSlug(M.name) + ext)}</button></footer>`;
}
function nbxPaint(){ const n = $('nbx'); if(!n) return; const f = document.activeElement && document.activeElement.dataset, k = f && (f.act ? 'act:' + f.act + ':' + f.v : f.nbxo ? 'o:' + f.nbxo : '');
  n.innerHTML = nbExportInner(); if(k){ const [t, a, v] = k.split(':'); const el = t === 'act' ? n.querySelector(`[data-act="${a}"][data-v="${v}"]`) : n.querySelector(`[data-nbxo="${a}"]`); if(el) el.focus(); } }
const NBX_ACTS = {
  nbxScope:(id, v) => { UI.nbx.scope = v; nbxPaint(); },
  nbxFmt:(id, v) => { UI.nbx.fmt = v; nbOpts().fmt = v; save(); nbxPaint(); },
  nbxGo:() => { const T = nbExportTarget(); closeDlg(); nbRunExport(T); },
  nbxCopy:() => { nbCopyRich(nbExportTarget()); }
};
document.addEventListener('change', ev => {
  const t = ev.target; if(!t.closest || !t.closest('#nbx')) return;
  if(t.dataset.nbxo){ nbOpts()[t.dataset.nbxo] = t.checked; save(); nbxPaint(); }
  else if(t.id === 'nbxBook'){ UI.nbx.ctx.book = t.value; nbxPaint(); }
});

/* ---------- Word import ---------- */
async function nbFromDocx(u8){
  const z = await nbUnzip(u8), td = new TextDecoder(), X = s => new DOMParser().parseFromString(td.decode(s), 'application/xml');
  const docB = await z.get('word/document.xml'); if(!docB) throw new Error('not a Word document');
  const rels = {}, relB = await z.get('word/_rels/document.xml.rels'); if(relB) for(const r of X(relB).getElementsByTagName('Relationship')) rels[r.getAttribute('Id')] = r.getAttribute('Target');
  const fmts = {}, numB = await z.get('word/numbering.xml');
  if(numB){ const nd = X(numB), abs = {}; for(const a of nd.getElementsByTagNameNS('*', 'abstractNum')){ const lv = {}; for(const l of a.getElementsByTagNameNS('*', 'lvl')){ const f = l.getElementsByTagNameNS('*', 'numFmt')[0]; lv[l.getAttribute('w:ilvl')] = f ? f.getAttribute('w:val') : 'bullet'; } abs[a.getAttribute('w:abstractNumId')] = lv; }
    for(const n of nd.getElementsByTagNameNS('*', 'num')){ const a = n.getElementsByTagNameNS('*', 'abstractNumId')[0]; if(a) fmts[n.getAttribute('w:numId')] = abs[a.getAttribute('w:val')] || {}; } }
  const ch = (n, name) => [...n.childNodes].filter(c => c.nodeType === 1 && c.localName === name);
  const att = (n, a) => n && (n.getAttribute('w:' + a) || n.getAttribute(a));
  const on = n => !!n && !/^(0|false|none)$/.test(att(n, 'val') || '');
  const imgs = async r => { let o = ''; for(const b of r.getElementsByTagNameNS('*', 'blip')){ const id = b.getAttribute('r:embed'), tg = rels[id]; if(!tg) continue; const path = tg.startsWith('/') ? tg.slice(1) : 'word/' + tg.replace(/^\.\//, ''), bytes = await z.get(path); if(!bytes) continue;
      const ext = (path.match(/\.(\w+)$/) || [])[1] || 'png', type = 'image/' + (ext === 'jpg' ? 'jpeg' : ext.toLowerCase()); if(!/^image\/(png|jpeg|gif|webp)$/.test(type)) continue;
      const mid = uid('m'), m = {id:mid, type, name:path.split('/').pop().slice(0, 120), size:bytes.length, at:Date.now()}; if(!await nbPut(mid, new Blob([bytes], {type}))) m.data = 'data:' + type + ';base64,' + nbB64(bytes); DB.nb.media[mid] = m; o += `<img data-m="${mid}" alt="">`; } return o; };
  const runs = async n => { let o = ''; for(const c of [...n.childNodes].filter(x => x.nodeType === 1)){
      if(c.localName === 'hyperlink'){ const u = nbSafeUrl(rels[c.getAttribute('r:id')] || ''); const x = (await runs(c)).replace(/<\/?u>/g, ''); o += u ? `<a href="${esc(u)}">${x}</a>` : x; continue; }
      if(c.localName === 'ins' || c.localName === 'smartTag' || c.localName === 'sdt' || c.localName === 'sdtContent' || c.localName === 'fldSimple'){ o += await runs(c); continue; }
      if(c.localName !== 'r') continue; const pr = ch(c, 'rPr')[0]; let t = '';
      for(const k of c.childNodes){ if(k.nodeType !== 1) continue; if(k.localName === 't') t += esc(k.textContent); else if(k.localName === 'tab') t += ' '; else if(k.localName === 'br' || k.localName === 'cr') t += '<br>'; else if(k.localName === 'drawing' || k.localName === 'pict') t += await imgs(k); }
      if(pr && t && !/^<img/.test(t)){ if(on(ch(pr, 'b')[0])) t = `<b>${t}</b>`; if(on(ch(pr, 'i')[0])) t = `<i>${t}</i>`; if(on(ch(pr, 'u')[0])) t = `<u>${t}</u>`; if(on(ch(pr, 'strike')[0])) t = `<s>${t}</s>`; if(ch(pr, 'highlight').length && att(ch(pr, 'highlight')[0], 'val') !== 'none') t = `<mark>${t}</mark>`;
        const f = ch(pr, 'rFonts')[0]; if(f && /consolas|courier|mono/i.test(att(f, 'ascii') || '')) t = `<code>${t}</code>`; }
      o += t; } return o; };
  const body = X(docB).getElementsByTagNameNS('*', 'body')[0]; let html = '', title = '', listTag = null;
  const closeList = () => { if(listTag){ html += `</${listTag}>`; listTag = null; } };
  for(const n of [...body.childNodes].filter(c => c.nodeType === 1)){
    if(n.localName === 'tbl'){ closeList(); html += '<table>' + (await Promise.all(ch(n, 'tr').map(async (tr, i) => '<tr>' + (await Promise.all(ch(tr, 'tc').map(async tc => { const ps = await Promise.all(ch(tc, 'p').map(runs)); const tg = i === 0 ? 'th' : 'td'; return `<${tg}>${ps.join('<br>') || '<br>'}</${tg}>`; }))).join('') + '</tr>'))).join('') + '</table>'; continue; }
    if(n.localName !== 'p') continue;
    const pPr = ch(n, 'pPr')[0], sty = (pPr && att(ch(pPr, 'pStyle')[0], 'val')) || '', numPr = pPr && ch(pPr, 'numPr')[0], inner = await runs(n);
    if(numPr){ const id = att(ch(numPr, 'numId')[0], 'val'), lv = att(ch(numPr, 'ilvl')[0], 'val') || '0', tg = ((fmts[id] || {})[lv] || 'bullet') === 'bullet' ? 'ul' : 'ol';
      if(id !== '0'){ if(listTag !== tg){ closeList(); html += `<${tg}>`; listTag = tg; } html += `<li>${inner || '<br>'}</li>`; continue; } }
    closeList();
    if(/^title$/i.test(sty) && !title){ title = nbDoc(inner).textContent.trim(); continue; }
    const hm = sty.match(/^heading\s*(\d)/i) || sty.match(/^Heading(\d)/);
    if(hm){ const lv = +hm[1]; if(lv === 1 && !title && !html){ title = nbDoc(inner).textContent.trim(); continue; } html += `<h${Math.min(4, lv + 1)}>${inner}</h${Math.min(4, lv + 1)}>`; continue; }
    if(/^[☑☐]/.test(nbDoc(inner).textContent.trim())){ const done = /^☑/.test(nbDoc(inner).textContent.trim()), li = `<li${done ? ' class="done"' : ''}>${inner.replace(/[☑☐]\s*/, '')}</li>`;
      if(/<\/ul>$/.test(html) && html.lastIndexOf('<ul class="nb-check">') > html.lastIndexOf('</ul>', html.length - 6)) html = html.slice(0, -5) + li + '</ul>'; else html += `<ul class="nb-check">${li}</ul>`; continue; }
    if(/^callout$/i.test(sty)){ html += `<div class="nb-call"><p>${inner}</p></div>`; continue; }
    if(/^meta$/i.test(sty)) continue;
    if(/quote/i.test(sty)){ html += `<blockquote><p>${inner || '<br>'}</p></blockquote>`; continue; }
    if(/code|preformatted|source/i.test(sty)){ html += `<pre>${nbDoc(inner.replace(/<br>/g, '\n')).textContent}</pre>`; continue; }
    if(/^<img[^>]*>$/.test(inner.trim())){ html += `<figure>${inner}<figcaption></figcaption></figure>`; continue; }
    if(/caption/i.test(sty) && /<\/figure>$/.test(html)){ html = html.replace(/<figcaption><\/figcaption><\/figure>$/, `<figcaption>${inner}</figcaption></figure>`); continue; }
    html += inner.trim() ? `<p>${inner}</p>` : '';
  }
  closeList();
  return {title, html:nbClean(nbCardsFromTables(html))};
}

/* a Question | Answer table (how exports write flashcards) becomes Q:/A: lines again */
function nbCardsFromTables(html){
  const d = nbDoc(html);
  d.querySelectorAll('table').forEach(t => { const rows = [...t.querySelectorAll('tr')]; if(rows.length < 2) return; const h = [...rows[0].children].map(c => c.textContent.trim().toLowerCase());
    if(h.length !== 2 || h[0] !== 'question' || h[1] !== 'answer') return;
    const prev = t.previousElementSibling; if(prev && prev.tagName === 'P' && /^flash ?cards?$/i.test(prev.textContent.trim())) prev.remove();
    t.outerHTML = rows.slice(1).map(r => `<p>Q: ${esc(r.children[0].textContent.trim())}</p><p>A: ${esc((r.children[1] || {textContent:''}).textContent.trim())}</p>`).join(''); });
  return d.innerHTML;
}
