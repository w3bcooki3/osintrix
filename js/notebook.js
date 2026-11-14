/* ==========================================================================
   Notebook — what you learn from courses, labs and reading, kept as pages
   with screenshots, links, code, tables and flashcards. Notebooks hold
   sections, sections hold pages. Pages are stored as a small, cleaned subset
   of HTML; pictures and files live in DB.nb.media and are referenced by id.
   Export (Word, HTML, Markdown, PDF, rich text) is in nbexport.js.
   ========================================================================== */
const NB_COLORS = ['#6366f1', '#0d9488', '#ea580c', '#0284c7', '#be185d', '#65a30d', '#7c3aed', '#b45309'];
const NB_KINDS = ['Course', 'Labs', 'Study', 'Reading', 'Certification', 'Other'];
const NB_MAX_FILE = 15 * 1024 * 1024;

/* ---------- data ---------- */
function ensureNB(){
  if(DB.nb && Array.isArray(DB.nb.books)){ if(!ensureNB.j){ ensureNB.j = true; nbJournalApply(); } return DB.nb; }
  DB.nb = {books:[], sections:[], pages:[], media:{}, cards:{}};
  if(DB.sample) nbSeed();
  return DB.nb;
}
const nbBook = id => DB.nb.books.find(b => b.id === id);
const nbSec = id => DB.nb.sections.find(s => s.id === id);
const nbPage = id => DB.nb.pages.find(p => p.id === id);
const nbSecsOf = bookId => DB.nb.sections.filter(s => s.bookId === bookId);
const nbPagesOf = secId => DB.nb.pages.filter(p => p.sectionId === secId);
const nbBookPages = bookId => { const ids = new Set(nbSecsOf(bookId).map(s => s.id)); return DB.nb.pages.filter(p => ids.has(p.sectionId)); };
const nbBookOfPage = p => { const s = p && nbSec(p.sectionId); return s ? nbBook(s.bookId) : null; };
const nbHash = s => { let h = 5381; for(let i = 0; i < s.length; i++) h = (h * 33 ^ s.charCodeAt(i)) >>> 0; return h.toString(36); };
const nbAgo = t => t ? E.fmtAgo(Math.max(0, Date.now() - t)) : '';
const nbSize = n => n > 1048576 ? (n / 1048576).toFixed(1) + ' MB' : Math.max(1, Math.round(n / 1024)) + ' KB';

function nbNewPage(secId, o){ const now = Date.now(); const p = {id:uid('pg'), sectionId:secId, title:'Untitled', html:'<p><br></p>', tags:[], src:'', att:[], created:now, updated:now, ...o}; DB.nb.pages.push(p); return p; }
function nbNewBook(o){ const b = {id:uid('nb'), name:'New notebook', kind:'Course', color:NB_COLORS[DB.nb.books.length % NB_COLORS.length], created:Date.now(), open:true, ...o}; DB.nb.books.push(b); return b; }
function nbNewSec(bookId, name){ const s = {id:uid('ns'), bookId, name:name || 'New section', open:true}; DB.nb.sections.push(s); return s; }
function nbTouch(p){ p.updated = Date.now(); }

/* ---------- reading a page: text, outline, flashcards (cached per edit) ---------- */
const NB_CACHE = new Map();
function nbDoc(html){ return new DOMParser().parseFromString('<!doctype html><body>' + String(html || '').replace(/<(\/?)base\b/gi, '<$1x-base'), 'text/html').body; }
function nbLines(body){
  const out = [], walk = n => { for(const c of n.childNodes){ if(c.nodeType === 3){ out[out.length - 1] += c.data; continue; } if(c.nodeType !== 1) continue;
      if(c.tagName === 'BR'){ out.push(''); continue; } const blk = /^(P|H\d|LI|PRE|DIV|FIGCAPTION|TD|TH|TR|BLOCKQUOTE|UL|OL|TABLE|FIGURE)$/.test(c.tagName);
      if(blk) out.push(''); walk(c); if(blk) out.push(''); } };
  out.push(''); walk(body); return out.map(s => s.replace(/\s+/g, ' ').trim()).filter(Boolean);
}
function nbInfo(p){
  const c = NB_CACHE.get(p.id); if(c && c.u === p.updated && c.h === p.html) return c;
  const body = nbDoc(p.html), lines = nbLines(body), cards = [];
  for(let i = 0; i < lines.length; i++){ const q = lines[i].match(/^Q\s*[:.]\s*(.+)/i); if(!q) continue;
    const inl = q[1].match(/^(.*?)\s+A\s*[:.]\s*(.+)$/); if(inl){ cards.push({q:inl[1], a:inl[2]}); continue; }
    const a = (lines[i + 1] || '').match(/^A\s*[:.]\s*(.+)/i); if(a){ cards.push({q:q[1], a:a[1]}); i++; } }
  cards.forEach(k => k.key = p.id + ':' + nbHash(k.q.toLowerCase()));
  const heads = [...body.querySelectorAll('h2,h3')].map(h => ({lvl:+h.tagName[1], t:h.textContent.trim()})).filter(h => h.t);
  const imgs = [...body.querySelectorAll('img[data-m]')].map(i => i.getAttribute('data-m'));
  const r = {u:p.updated, h:p.html, text:lines.join('\n'), cards, heads, imgs}; NB_CACHE.set(p.id, r); return r;
}
/* ---------- spaced review (SM-2 style) ---------- */
const NB_DAY = 864e5;
function nbCardState(key){ return (DB.nb.cards || {})[key] || null; }
function nbIsDue(key, at){ const s = nbCardState(key); return !s || s.due <= (at || nbEndOfDay()); }
function nbEndOfDay(){ const d = new Date(); d.setHours(23, 59, 59, 999); return +d; }
function nbAllCards(bookId){ const pages = bookId ? nbBookPages(bookId) : DB.nb.pages, out = []; for(const p of pages) for(const k of nbInfo(p).cards) out.push({...k, pageId:p.id}); return out; }
function nbDueCards(bookId){ return nbAllCards(bookId).filter(k => nbIsDue(k.key)); }
function nbNext(key, grade){
  const s = nbCardState(key) || {reps:0, ivl:0, ease:2.5, lapses:0}, n = {...s};
  if(grade === 0){ n.reps = 0; n.ivl = 0; n.lapses = (s.lapses || 0) + 1; n.ease = Math.max(1.3, s.ease - .2); n.due = Date.now() + 60e3; }
  else { const base = s.reps === 0 ? [0, 1, 1, 4][grade] : s.ivl * [0, 1.2, s.ease, s.ease * 1.3][grade];
    n.ivl = Math.max(1, Math.round(grade === 1 ? Math.max(1, base) : base)); n.ease = Math.max(1.3, s.ease + [0, -.15, 0, .15][grade]); n.reps = s.reps + 1; n.due = Date.now() + n.ivl * NB_DAY; }
  return n;
}
const nbIvlLabel = (key, g) => { if(g === 0) return '1 min'; const d = nbNext(key, g).ivl; return d === 1 ? '1 day' : d < 31 ? d + ' days' : Math.round(d / 30) + ' mo'; };

/* ---------- cleaning HTML: the only markup a page may hold ---------- */
const NB_KEEP = {P:'p', H1:'h2', H2:'h2', H3:'h3', H4:'h4', H5:'h4', H6:'h4', B:'b', STRONG:'b', I:'i', EM:'i', U:'u', S:'s', STRIKE:'s', DEL:'s', MARK:'mark', CODE:'code', KBD:'code', SUB:'sub', SUP:'sup',
  PRE:'pre', UL:'ul', OL:'ol', LI:'li', A:'a', BR:'br', HR:'hr', BLOCKQUOTE:'blockquote', TABLE:'table', TR:'tr', TH:'th', TD:'td', FIGURE:'figure', FIGCAPTION:'figcaption', IMG:'img'};
const NB_DROP = new Set(['SCRIPT', 'STYLE', 'NOSCRIPT', 'IFRAME', 'OBJECT', 'EMBED', 'TEMPLATE', 'SVG', 'MATH', 'HEAD', 'TITLE', 'META', 'LINK', 'BUTTON', 'INPUT', 'SELECT', 'TEXTAREA', 'FORM', 'CANVAS', 'VIDEO', 'AUDIO']);
const NB_BLOCK = /^(P|H\d|UL|OL|LI|PRE|BLOCKQUOTE|TABLE|FIGURE|DIV|SECTION|ARTICLE|HEADER|FOOTER|MAIN|ASIDE|NAV|HR)$/;
const nbSafeUrl = u => /^(https?:|mailto:)/i.test(String(u || '').trim()) ? String(u).trim() : '';
/* opts.src: put the picture data on <img> (for the editor and exports); opts.media: store new data: pictures found in pasted HTML */
function nbClean(html, opts = {}){
  const body = nbDoc(String(html || '').slice(0, 8e6)), M = DB.nb.media;
  const kids = (n, d) => [...n.childNodes].map(c => node(c, d)).join('');
  const hasBlock = n => [...n.children].some(c => NB_BLOCK.test(c.tagName));
  const style = n => (n.getAttribute && n.getAttribute('style') || '').toLowerCase();
  const node = (n, d) => {
    if(d > 40) return '';
    if(n.nodeType === 3) return esc(n.data.replace(/\u00a0/g, ' ')).replace(/ {2}/g, ' &nbsp;');
    if(n.nodeType !== 1 || NB_DROP.has(n.tagName)) return '';
    const T = n.tagName, st = style(n);
    if(T === 'PRE'){ const t = (() => { const x = n.cloneNode(true); x.querySelectorAll('br').forEach(b => b.replaceWith('\n')); return x.textContent; })(); return `<pre>${esc(t.replace(/\n$/, '')) || '<br>'}</pre>`; }
    if(T === 'DIV' && n.classList.contains('nb-link')){ const a = n.querySelector('a'), u = a && nbSafeUrl(a.getAttribute('href')); if(!u) return '';
      return `<div class="nb-link" contenteditable="false"><a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(a.textContent.trim() || hostOf(u) || u)}</a><small>${esc(hostOf(u))}</small></div>`; }
    if(T === 'DIV' && n.classList.contains('nb-call')) return `<div class="nb-call">${hasBlock(n) ? kids(n, d + 1) : '<p>' + (kids(n, d + 1) || '<br>') + '</p>'}</div>`;
    if(T === 'IMG'){ const mid = n.getAttribute('data-m'); let m = nbM(mid) ? mid : null; const src = n.getAttribute('src') || '';
      if(!m && opts.media && /^data:image\/(png|jpe?g|gif|webp);base64,/i.test(src) && src.length < 2e7){ m = uid('m'); M[m] = {id:m, type:src.slice(5, src.indexOf(';')), name:'image-' + m.slice(-4) + '.png', data:src, w:+n.getAttribute('width') || 0, h:+n.getAttribute('height') || 0, size:Math.round(src.length * .75), at:Date.now()}; }
      if(!m){ const u = nbSafeUrl(src); return u ? `<a href="${esc(u)}" target="_blank" rel="noopener noreferrer">[image] ${esc(n.getAttribute('alt') || hostOf(u))}</a>` : ''; }
      const alt = esc(n.getAttribute('alt') || '').slice(0, 300), url = opts.src ? nbInline(M[m]) || NB_DATA.get(m) || (opts.src !== 'data' && NB_URLS.get(m)) : null;
      return `<img data-m="${m}" alt="${alt}"${opts.src ? (url ? ` src="${esc(url)}"` : ` data-nbm="${m}"`) : ''}>`; }
    if(T === 'A'){ const u = nbSafeUrl(n.getAttribute('href')); return u ? `<a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${kids(n, d + 1)}</a>` : kids(n, d + 1); }
    if(T === 'B' && /font-weight:\s*(normal|400)/.test(st)) return kids(n, d + 1);   // Google Docs wraps pastes in <b style="font-weight:normal">
    if(T === 'SPAN' || T === 'FONT'){ let s = kids(n, d + 1); if(!s) return '';
      if(/background(-color)?:\s*(?!transparent|initial|inherit|none|rgba\([^)]*,\s*0\)|#fff\b|#ffffff|white)[#a-z]/.test(st)) s = `<mark>${s}</mark>`;
      if(/font-weight:\s*(bold|[6-9]00)/.test(st)) s = `<b>${s}</b>`; if(/font-style:\s*italic/.test(st)) s = `<i>${s}</i>`; if(/text-decoration[^;]*underline/.test(st)) s = `<u>${s}</u>`; if(/text-decoration[^;]*line-through/.test(st)) s = `<s>${s}</s>`;
      return s; }
    if(T === 'DIV' || T === 'SECTION' || T === 'ARTICLE' || T === 'HEADER' || T === 'FOOTER' || T === 'MAIN' || T === 'ASIDE' || T === 'NAV' || T === 'CENTER'){ if(hasBlock(n)) return kids(n, d + 1); const s = kids(n, d + 1); return s.trim() ? `<p>${s}</p>` : ''; }
    if(T === 'THEAD' || T === 'TBODY' || T === 'TFOOT' || T === 'COLGROUP' || T === 'CAPTION') return T === 'CAPTION' ? '' : kids(n, d + 1);
    const t = NB_KEEP[T]; if(!t) return kids(n, d + 1);
    if(t === 'br' || t === 'hr') return `<${t}>`;
    let inner = kids(n, d + 1);
    if(t === 'table'){ const rows = [...n.querySelectorAll('tr')].filter(r => r.closest('table') === n); if(!rows.length) return '';
      return '<table>' + rows.map(r => '<tr>' + [...r.children].filter(c => /^T[DH]$/.test(c.tagName)).map(c => { const tg = c.tagName.toLowerCase(), x = kids(c, d + 2); return `<${tg}>${x || '<br>'}</${tg}>`; }).join('') + '</tr>').join('') + '</table>'; }
    if(t === 'tr' || t === 'td' || t === 'th') return inner;   // stray table parts outside a table
    if(t === 'ul' && n.classList.contains('nb-check')) return `<ul class="nb-check">${inner}</ul>`;
    if(t === 'li') return `<li${n.classList.contains('done') ? ' class="done"' : ''}>${inner || '<br>'}</li>`;
    if(t === 'figure'){ const im = n.querySelector('img'), cap = n.querySelector('figcaption'); const ih = im ? node(im, d + 1) : ''; if(!ih) return cap ? `<p>${kids(cap, d + 1)}</p>` : '';
      return `<figure>${ih}<figcaption>${cap ? kids(cap, d + 1) : ''}</figcaption></figure>`; }
    if(t === 'figcaption' && !n.closest('figure')) return inner.trim() ? `<p>${inner}</p>` : '';
    if(/^(p|h2|h3|h4|blockquote|figcaption)$/.test(t)) return t === 'blockquote' && !hasBlock(n) ? `<blockquote><p>${inner || '<br>'}</p></blockquote>` : `<${t}>${inner || (t === 'figcaption' ? '' : '<br>')}</${t}>`;
    return inner ? `<${t}>${inner}</${t}>` : '';
  };
  let out = kids(body, 0).replace(/(<p><br><\/p>){3,}/g, '<p><br></p><p><br></p>');
  // inline text sitting directly in the page gets a paragraph
  if(out && !/^\s*<(p|h\d|ul|ol|pre|blockquote|table|figure|div|hr)/.test(out)) out = '<p>' + out + '</p>';
  return out || '<p><br></p>';
}
const nbWithSrc = html => nbClean(html, {src:true});

/* ---------- media ----------
   Picture and file bytes live in IndexedDB as separate blobs ('nbm:<id>'), sealed with the workspace key when
   encryption is on, so autosaves and restore points stay small. DB.nb.media keeps only their details. A media
   item with .data still inline (just pasted, imported, or IndexedDB is blocked) is moved out by nbFlushMedia().
   Media no page uses is marked gone and only deleted 30 days later, so undo and restore points keep working. */
const NB_KEEP_DAYS = 30, NB_URLS = new Map(), NB_DATA = new Map();
const nbM = id => typeof id === 'string' && /^m-[a-z0-9-]{1,40}$/i.test(id) && Object.prototype.hasOwnProperty.call(DB.nb.media, id) ? DB.nb.media[id] : null;
const nbInline = m => m && (m.data || (m.demo && typeof NB_DEMO_SHOT !== 'undefined' ? NB_DEMO_SHOT.data : null));
const nbReadURL = f => new Promise((res, rej) => { const r = new FileReader(); r.onload = () => res(r.result); r.onerror = () => rej(r.error); r.readAsDataURL(f); });
const nbLoadImg = u => new Promise((res, rej) => { const i = new Image(); i.onload = () => res(i); i.onerror = () => rej(new Error('not a picture this browser can read')); i.src = u; });
const nbURLBlob = u => { const m = u.match(/^data:([^;,]*)(;base64)?,(.*)$/s); const b = m[2] ? Uint8Array.from(atob(m[3]), c => c.charCodeAt(0)) : new TextEncoder().encode(decodeURIComponent(m[3])); return new Blob([b], {type:m[1] || 'application/octet-stream'}); };
async function nbBlob(id){ const m = nbM(id); if(!m) return null; const d = nbInline(m); if(d) return nbURLBlob(d); try{ return await openBlob(await IDB.get('nbm:' + id)); }catch(e){ return null; } }
async function nbURL(id){ if(NB_URLS.has(id)) return NB_URLS.get(id); const b = await nbBlob(id); if(!b) return null; const u = URL.createObjectURL(b); NB_URLS.set(id, u); return u; }
async function nbDataURL(id){ const m = nbM(id); if(!m) return null; const d = nbInline(m); if(d) return d; if(NB_DATA.has(id)) return NB_DATA.get(id); const b = await nbBlob(id); if(!b) return null; const u = await nbReadURL(b); NB_DATA.set(id, u); return u; }
/* exports need the bytes inline: load every picture the pages use first */
async function nbPreload(pages){ const ids = new Set(); for(const p of pages){ nbInfo(p).imgs.forEach(i => ids.add(i)); } await Promise.all([...ids].map(nbDataURL)); }
async function nbPut(id, blob){ if(!STORE.idb) return false; try{ return await IDB.set('nbm:' + id, await sealBlob(blob)); }catch(e){ return false; } }
let nbFlushing = false;
async function nbFlushMedia(){ if(nbFlushing || !DB || !DB.nb || !STORE.idb || SEC.locked) return; nbFlushing = true; let n = 0;
  try{ for(const m of Object.values(DB.nb.media)) if(m.data && await nbPut(m.id, nbURLBlob(m.data))){ delete m.data; n++; } }finally{ nbFlushing = false; } if(n) save(); }
async function nbAddImage(file, name){
  if(file.size > NB_MAX_FILE) throw new Error('pictures up to 15 MB');
  if(!await nbRoomFor(file.size)) throw new Error('browser storage is full');
  let data = await nbReadURL(file); const img = await nbLoadImg(data); let w = img.naturalWidth, h = img.naturalHeight, type = file.type || 'image/png', blob = file;
  if(file.size > 700e3 || w > 1800 || !/^image\/(png|jpeg|gif|webp)$/.test(type)){ const s = Math.min(1, 1800 / w), c = document.createElement('canvas'); c.width = Math.round(w * s); c.height = Math.round(h * s);
    c.getContext('2d').drawImage(img, 0, 0, c.width, c.height); let d = c.toDataURL('image/webp', .9); if(!d.startsWith('data:image/webp')) d = c.toDataURL('image/jpeg', .9);
    const nb = nbURLBlob(d); if(nb.size < file.size || !/^image\/(png|jpeg|gif|webp)$/.test(type) || w > 1800){ data = d; w = c.width; h = c.height; type = d.slice(5, d.indexOf(';')); blob = nb; } }
  const id = uid('m'), m = {id, type, name:String(name || file.name || 'screenshot.png').slice(0, 120), w, h, size:blob.size, at:Date.now()};
  if(!await nbPut(id, blob)) m.data = data; DB.nb.media[id] = m; return id;
}
async function nbAddFile(file){ if(file.size > NB_MAX_FILE) throw new Error('files up to 15 MB'); if(!await nbRoomFor(file.size)) throw new Error('browser storage is full');
  const id = uid('m'), m = {id, type:file.type || 'application/octet-stream', name:String(file.name || 'file').slice(0, 120), size:file.size, at:Date.now()};
  if(!await nbPut(id, file)) m.data = await nbReadURL(file); DB.nb.media[id] = m; return id; }
/* unused media is marked, then dropped after NB_KEEP_DAYS (or at once from Settings → Storage) */
function nbUsed(){ const used = new Set(); for(const p of DB.nb.pages){ (p.att || []).forEach(m => used.add(m)); (p.html.match(/data-m="([^"]+)"/g) || []).forEach(s => used.add(s.slice(8, -1))); } return used; }
function nbGC(now){ const used = nbUsed(), cut = Date.now() - NB_KEEP_DAYS * NB_DAY; let n = 0;
  for(const [k, m] of Object.entries(DB.nb.media)){ if(used.has(k)){ if(m.gone){ delete m.gone; n++; } continue; } if(!m.gone){ m.gone = Date.now(); n++; }
    if(now || m.gone < cut){ delete DB.nb.media[k]; if(STORE.idb) IDB.del('nbm:' + k); NB_URLS.delete(k); NB_DATA.delete(k); n++; } } return n; }
async function nbMediaDl(id){ const m = nbM(id), b = await nbBlob(id); if(!m || !b) return toast('That file is missing from this browser');
  const u = URL.createObjectURL(b), a = document.createElement('a'); a.href = u; a.download = safeName(m.name, 'file'); document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(u); a.remove(); }, 200); toast('Saved ' + (m.name || 'file')); }
/* pictures in the page get their bytes after drawing */
function nbHydrate(root){ (root || document).querySelectorAll('img[data-nbm]:not([src])').forEach(async im => { const u = await nbURL(im.dataset.nbm); if(u) im.src = u; else { im.alt = 'Picture missing from this browser'; im.classList.add('nb-missing'); } }); }
new MutationObserver(() => { if(document.querySelector('img[data-nbm]:not([src])')) nbHydrate(); }).observe(document.documentElement, {childList:true, subtree:true});
/* refuse a file that would not fit, instead of failing half-way */
async function nbRoomFor(bytes){ await storageEstimate(); return !STORE.quota || (STORE.quota - (STORE.usage || 0)) > bytes * 1.5 + 5e6; }

/* ==========================================================================
   View
   ========================================================================== */
function viewNotebook(){
  ensureNB(); nbCommit();   // never redraw over keystrokes that are still waiting to be saved
  if(!nbGC.done){ nbGC.done = true; if(nbGC()) save(); nbFlushMedia(); }
  const p = UI.nbView === 'page' && nbPage(UI.nbPage);
  return p ? nbEditorView(p) : nbLibraryView();
}

/* ---------- library ---------- */
function nbBookStats(b){
  const pages = nbBookPages(b.id), cards = nbAllCards(b.id), seen = cards.filter(k => (nbCardState(k.key) || {}).reps > 0).length;
  return {pages:pages.length, cards:cards.length, due:cards.filter(k => nbIsDue(k.key)).length, shots:pages.reduce((s, p) => s + nbInfo(p).imgs.length, 0),
    pct:cards.length ? Math.round(seen / cards.length * 100) : 0, edited:pages.reduce((m, p) => Math.max(m, p.updated || 0), b.created || 0)};
}
function nbLibraryView(){
  const N = DB.nb, books = N.books.slice().sort((a, b) => nbBookStats(b).edited - nbBookStats(a).edited);
  const recent = N.pages.slice().sort((a, b) => b.updated - a.updated).slice(0, 6);
  const card = b => { const s = nbBookStats(b);
    return `<div class="nbk" style="--cc:${nbColor(b.color)}"><button class="nbk-hit" data-act="nbOpenBook" data-id="${b.id}" aria-label="Open ${esc(b.name)}"></button>
      <div class="nbk-cov"><span>${esc(b.kind || 'Notebook')}${s.cards ? ' · ' + s.pct + '% reviewed' : ''}</span><h3>${esc(b.name)}</h3>
        <button class="nbk-m" data-act="nbBookMenu" data-id="${b.id}" aria-label="Notebook options">${ico('ellipsis','sm')}</button></div>
      <div class="nbk-b"><div class="nbk-st"><span><b>${s.pages}</b> page${s.pages === 1 ? '' : 's'}</span><span><b>${s.due}</b> to review</span><span><b>${s.shots}</b> picture${s.shots === 1 ? '' : 's'}</span></div>
        <div class="nbk-bar" aria-hidden="true"><i style="width:${s.cards ? Math.max(2, s.pct) : 0}%"></i></div><div class="nbk-ed">${ico('clock','sm')}Edited ${nbAgo(s.edited)}</div></div></div>`; };
  return `<div class="scroll"><div class="page wide nbl">
    <div class="nbl-h"><div><h1>Notebook</h1><p>What you learn from courses, labs and reading — with screenshots, links and code — ready to export to Word, Google Docs, OneNote or Markdown.</p></div>
      <div class="nbl-a"><button class="btn" data-act="nbImport">${ico('upload','sm')}Import</button><button class="btn" data-act="nbExport" data-v="all"${N.pages.length ? '' : ' disabled'}>${ico('download','sm')}Export</button><button class="btn primary" data-act="nbBookNew">${ico('plus','sm')}New notebook</button></div></div>
    <div class="nbl-g"><div class="nbl-l">
      <div class="nbl-quick" id="nbQuick" tabindex="0" role="button" aria-label="Quick capture: paste a screenshot, link or text to start a page">${ico('image')}<span><b>Paste a screenshot, link or text here</b> to start a new page with it. Drop files too. Inside a page, Ctrl V works anywhere.</span></div>
      ${books.length ? `<div class="nbl-books">${books.map(card).join('')}<button class="nbk-new" data-act="nbBookNew">${ico('plus')}New notebook</button></div>`
        : `<div class="nbl-empty">${empty('book-open', 'No notebooks yet', 'Make one per course, lab platform or topic. Pages hold notes, screenshots, code and flashcards.', `<button class="btn primary" data-act="nbBookNew">${ico('plus','sm')}New notebook</button><button class="btn" data-act="nbImport">${ico('upload','sm')}Import Markdown, HTML or Word</button>`)}</div>`}
      ${recent.length ? `<section class="nbl-rec"><h2>Recent pages</h2>${recent.map(p => { const s = nbSec(p.sectionId), b = s && nbBook(s.bookId);
        return `<button class="nbl-r" data-act="nbOpen" data-id="${p.id}">${ico('file-text','sm')}<span><b>${esc(p.title || 'Untitled')}</b><small>${esc(b ? b.name : '')} · ${esc(s ? s.name : '')} · edited ${nbAgo(p.updated)}</small></span>${ico('chevron-right','sm')}</button>`; }).join('')}</section>` : ''}
    </div>
    <aside class="nbl-rv" aria-label="Review">${nbReviewHtml()}</aside></div>
  </div></div>`;
}

/* ---------- review ---------- */
function nbReviewQueue(keys){ const all = nbAllCards(), by = new Map(all.map(k => [k.key, k]));
  const list = keys ? keys.map(k => by.get(k)).filter(Boolean) : all.filter(k => nbIsDue(k.key)).sort((a, b) => ((nbCardState(a.key) || {}).due || 0) - ((nbCardState(b.key) || {}).due || 0));
  UI.nbRev = {keys:list.map(k => k.key), i:0, shown:false, done:0, only:!!keys}; }
function nbReviewHtml(){
  if(!UI.nbRev) nbReviewQueue();
  const R = UI.nbRev, all = nbAllCards(), by = new Map(all.map(k => [k.key, k]));
  while(R.i < R.keys.length && !by.get(R.keys[R.i])) R.i++;
  const total = R.keys.length, cur = by.get(R.keys[R.i]);
  const head = `<div class="nbr-h">${ico('sparkles','sm')}<span>${R.only ? 'Reviewing one page' : 'Review'}${total ? ` · ${total - R.i} left` : ''}</span>${total ? `<span class="nbr-n">${Math.min(R.i + 1, total)} / ${total}</span>` : ''}</div>`;
  if(!cur){ const next = all.map(k => (nbCardState(k.key) || {}).due).filter(Boolean).sort((a, b) => a - b)[0];
    return `<div id="nbRev">${head}<div class="nbr-card nbr-done">${ico('circle-check')}<h3>${R.done ? 'Done for now — ' + R.done + ' reviewed' : all.length ? 'Nothing to review' : 'No flashcards yet'}</h3>
      <p>${all.length ? (next ? 'Next card is due ' + new Date(next).toLocaleDateString(undefined, {day:'numeric', month:'short'}) + '.' : '') : 'Write a line starting with <b>Q:</b> and the answer on the next line starting with <b>A:</b>, or select text in a page and press <b>Flashcard</b>.'}</p>
      ${all.length ? `<button class="btn sm" data-act="nbRevAll">${ico('refresh-cw','sm')}Review all ${all.length} anyway</button>` : ''}</div>${nbTipHtml()}</div>`; }
  const p = nbPage(cur.pageId), b = nbBookOfPage(p);
  return `<div id="nbRev">${head}<div class="nbr-card"><button class="nbr-from" data-act="nbOpen" data-id="${p.id}">${ico('book-open','sm')}${esc(b ? b.name : '')} · ${esc(p.title)}</button>
    <div class="nbr-q">${esc(cur.q)}</div>
    ${R.shown ? `<div class="nbr-a">${esc(cur.a)}</div><div class="nbr-rate" role="group" aria-label="How well did you know it?">${['Again', 'Hard', 'Good', 'Easy'].map((l, g) => `<button data-act="nbRate" data-v="${g}"${g === 2 ? ' class="on"' : ''}><b>${l}</b><small>${nbIvlLabel(cur.key, g)}</small></button>`).join('')}</div>`
      : `<button class="btn primary nbr-show" data-act="nbReveal">Show answer <kbd>Space</kbd></button>`}
  </div>${nbTipHtml()}</div>`;
}
const nbTipHtml = () => `<p class="nbr-tip">${ico('lightbulb','sm')}<span>Cards come from lines that start with <b>Q:</b> followed by a line starting with <b>A:</b>. Reviews space out over days, like Anki. Keys: Space, then 1–4.</span></p>`;
function nbRevPaint(){ const r = $('nbRev'); if(r) r.outerHTML = nbReviewHtml(); }

/* ---------- editor ---------- */
function nbTreeHtml(){
  const N = DB.nb, q = (UI.nbq || '').trim().toLowerCase(), cur = UI.nbPage;
  if(q){ const words = q.split(/\s+/), hits = N.pages.map(p => { const i = nbInfo(p), hay = (p.title + ' ' + p.tags.join(' ') + ' ' + i.text).toLowerCase(); if(!words.every(w => hay.includes(w))) return null;
      const at = i.text.toLowerCase().indexOf(words[0]); return {p, snip:at < 0 ? '' : i.text.slice(Math.max(0, at - 30), at + 70).replace(/\n/g, ' ')}; }).filter(Boolean);
    return hits.length ? `<div class="nbt-res">${hits.slice(0, 60).map(({p, snip}) => { const b = nbBookOfPage(p);
      return `<button class="nbt-hit${p.id === cur ? ' on' : ''}" data-act="nbOpen" data-id="${p.id}"${p.id === cur ? ' aria-current="page"' : ''}><b>${esc(p.title || 'Untitled')}</b><small>${esc(b ? b.name : '')}</small>${snip ? `<span>…${esc(snip)}…</span>` : ''}</button>`; }).join('')}</div>`
      : `<p class="nbt-none">No page mentions “${esc(UI.nbq)}”.</p>`; }
  return N.books.map(b => { const secs = nbSecsOf(b.id), n = nbBookPages(b.id).length;
    return `<div class="nbt-b${b.open === false ? ' shut' : ''}" style="--cc:${nbColor(b.color)}"><div class="nbt-row"><button class="nbt-bk" data-act="nbBookTog" data-id="${b.id}" aria-expanded="${b.open !== false}"><span class="nbt-cv" aria-hidden="true"></span><span class="nbt-l">${esc(b.name)}</span><small>${n}</small></button><button class="nbt-m" data-act="nbBookMenu" data-id="${b.id}" aria-label="Options for ${esc(b.name)}">${ico('ellipsis','sm')}</button></div>
      ${b.open === false ? '' : secs.map(s => `<div class="nbt-s"><div class="nbt-row"><button class="nbt-sec" data-act="nbSecTog" data-id="${s.id}" aria-expanded="${s.open !== false}">${ico(s.open === false ? 'chevron-right' : 'chevron-down','sm')}<span class="nbt-l">${esc(s.name)}</span></button><button class="nbt-m" data-act="nbSecMenu" data-id="${s.id}" aria-label="Options for ${esc(s.name)}">${ico('ellipsis','sm')}</button></div>
        ${s.open === false ? '' : nbPagesOf(s.id).map(p => `<button class="nbt-pg${p.id === cur ? ' on' : ''}" data-act="nbOpen" data-id="${p.id}"${p.id === cur ? ' aria-current="page"' : ''}><span class="nbt-l">${esc(p.title || 'Untitled')}</span><small>${nbAgoShort(p.updated)}</small></button>`).join('')}</div>`).join('')}</div>`; }).join('');
}
function nbAgoShort(t){ const d = Date.now() - (t || 0); return d < 6e4 ? 'now' : d < 36e5 ? Math.round(d / 6e4) + 'm' : d < NB_DAY ? Math.round(d / 36e5) + 'h' : d < 30 * NB_DAY ? Math.round(d / NB_DAY) + 'd' : new Date(t).toLocaleDateString(undefined, {month:'short', day:'numeric'}); }

function nbEditorView(p){
  const s = nbSec(p.sectionId), b = s && nbBook(s.bookId);
  const tb = (cmd, icon, label, txt) => `<button type="button" class="nbtb" data-nbcmd="${cmd}" aria-label="${label}" title="${label}">${icon ? ico(icon,'sm') : ''}${txt || ''}</button>`;
  return `<div class="nb3${UI.nbSide === false ? ' noside' : ''}${UI.nbTreeOpen ? ' treeopen' : ''}" id="nb3">
    <aside class="nb3-tree" aria-label="Notebooks">
      <div class="nbt-h"><button class="nbt-back" data-act="nbLib" title="All notebooks">${ico('arrow-left','sm')}<span>All notebooks</span></button><span class="sp"></span><button class="iconbtn" data-act="nbNewMenu" aria-label="New…" title="New page, section or notebook">${ico('plus','sm')}</button></div>
      <div class="nbt-q">${ico('search','sm')}<label class="sr" for="nbq">Search notes</label><input id="nbq" type="search" placeholder="Search notes, code, captions…" value="${esc(UI.nbq || '')}" autocomplete="off"></div>
      <div class="nbt-body" id="nbTree">${nbTreeHtml()}</div>
      <button class="nbt-imp" data-act="nbImport">${ico('upload','sm')}Import Markdown, HTML or Word</button>
    </aside>
    <div class="nb3-scrim" data-act="nbTreeX"></div>
    <section class="nb3-doc">
      <div class="nbbar" role="toolbar" aria-label="Formatting">
        <button type="button" class="nbtb nbtb-tree" data-act="nbTreeTog" aria-label="Pages" title="Pages">${ico('panel-left','sm')}</button>
        <label class="sr" for="nbBlock">Block type</label><select id="nbBlock" class="nbsel"><option value="p">Text</option><option value="h2">Heading</option><option value="h3">Subheading</option><option value="blockquote">Quote</option></select>
        <span class="nbg">${tb('bold', '', 'Bold (Ctrl B)', '<b>B</b>')}${tb('italic', '', 'Italic (Ctrl I)', '<i style="font-family:Georgia,serif">I</i>')}${tb('underline', '', 'Underline (Ctrl U)', '<u>U</u>')}${tb('hilite', '', 'Highlight', '<span class="nbhl">A</span>')}</span>
        <span class="nbg">${tb('ul', 'list', 'Bulleted list')}${tb('check', 'list-checks', 'Checklist')}${tb('code', 'code', 'Code')}${tb('table', 'table', 'Table')}</span>
        <span class="nbg">${tb('image', 'image', 'Picture or screenshot')}${tb('link', 'link', 'Link')}${tb('callout', 'lightbulb', 'Key takeaway')}${tb('card', 'sparkles', 'Flashcard from selection', '<span class="nbtb-t">Flashcard</span>')}</span>
        <span class="sp"></span><span class="nbsaved" id="nbSaved" aria-live="polite">${ico('check','sm')}Saved</span>
        <button class="btn sm" data-act="nbExport" data-v="page">${ico('download','sm')}<span class="nbx-l">Export</span></button>
        <button type="button" class="nbtb" data-act="nbPageMenu" aria-label="Page options" title="Page options">${ico('ellipsis','sm')}</button>
        <button type="button" class="nbtb nbtb-side" data-act="nbSideTog" aria-label="Side panel" aria-pressed="${UI.nbSide !== false}" title="Outline, flashcards and links">${ico('panel-right','sm')}</button>
      </div>
      <div class="nbpage" id="nbScroll"><div class="nbpage-in">
        <div class="nbbc">${b ? `<button data-act="nbOpenBook" data-id="${b.id}">${esc(b.name)}</button>${ico('chevron-right','sm')}` : ''}<span>${esc(s ? s.name : '')}</span></div>
        <label class="sr" for="nbTitle">Page title</label><input id="nbTitle" class="nbtitle" value="${esc(p.title === 'Untitled' ? '' : p.title)}" placeholder="Untitled" autocomplete="off" maxlength="200">
        <div class="nbmeta" id="nbMeta">${nbMetaHtml(p)}</div>
        ${TABS.writer ? '' : `<p class="nb-ro">${ico('lock','sm')}This workspace is open in another tab, so this page is read-only here.</p>`}
        <div id="nbEd" class="nbed" contenteditable="${TABS.writer ? 'true' : 'false'}" spellcheck="true" role="textbox" aria-multiline="true" aria-label="Page text" data-ph="Write, or paste a screenshot, link or code…">${nbWithSrc(p.html)}</div>
        <div class="nbed-end" data-act="nbEdEnd" aria-hidden="true"></div>
      </div></div>
      <input type="file" id="nbImgIn" accept="image/*" multiple hidden><input type="file" id="nbAttIn" multiple hidden>
    </section>
    <aside class="nb3-side" id="nbSide" aria-label="About this page">${nbSideHtml(p)}</aside>
  </div>`;
}
function nbMetaHtml(p){
  const u = nbSafeUrl(p.src);
  return `${(p.tags || []).map(t => `<span class="nbtag">${esc(t)}<button data-act="nbTagX" data-v="${esc(t)}" aria-label="Remove tag ${esc(t)}">${ico('x','sm')}</button></span>`).join('')}
    <label class="sr" for="nbTagIn">Add a tag</label><input id="nbTagIn" class="nbtagin" placeholder="${p.tags && p.tags.length ? '+ tag' : '+ Add tags'}" autocomplete="off" maxlength="40">
    <span class="nbsrc">${ico('link','sm')}<label class="sr" for="nbSrc">Source</label><input id="nbSrc" value="${esc(p.src || '')}" placeholder="Source — course, lab or URL" autocomplete="off" maxlength="300">${u ? `<a href="${esc(u)}" target="_blank" rel="noopener noreferrer" aria-label="Open source">${ico('arrow-up-right','sm')}</a>` : ''}</span>
    <span class="nbwhen" id="nbWhen">${ico('clock','sm')}${new Date(p.updated).toLocaleDateString(undefined, {day:'numeric', month:'short', year:'numeric'})}</span>`;
}
function nbSideHtml(p){
  const I = nbInfo(p), links = nbLinked(p), files = [...new Set(I.imgs)].map(nbM).filter(Boolean).concat((p.att || []).map(nbM).filter(Boolean));
  const due = I.cards.filter(k => nbIsDue(k.key)).length;
  return `<section><h4>${ico('list','sm')}On this page</h4>${I.heads.length ? `<nav class="nbs-ol">${I.heads.map((h, i) => `<button class="${h.lvl === 3 ? 's' : ''}" data-act="nbGoHead" data-v="${i}">${esc(h.t)}</button>`).join('')}</nav>` : '<p class="nbs-e">Headings you add show up here.</p>'}</section>
    <section><h4>${ico('sparkles','sm')}Flashcards${I.cards.length ? `<span class="nbs-n">${I.cards.length}</span>` : ''}</h4>
      ${I.cards.length ? I.cards.slice(0, 6).map(k => `<div class="nbs-qa"><b>${esc(k.q)}</b><span>${esc(k.a)}</span></div>`).join('') + (I.cards.length > 6 ? `<p class="nbs-e">+${I.cards.length - 6} more</p>` : '') + `<button class="btn sm nbs-rv" data-act="nbRevPage">${ico('play','sm')}Review ${I.cards.length === 1 ? 'it' : 'these ' + I.cards.length}${due ? ` · ${due} due` : ''}</button>`
        : '<p class="nbs-e">Type <b>Q:</b> and a question, then <b>A:</b> and the answer on the next line — or select text and press Flashcard.</p>'}</section>
    <section><h4>${ico('link-2','sm')}Linked in ${esc(BRAND.name)}</h4>${links.length ? links.map(l => `<button class="nbs-lk" data-act="nbLinkGo" data-v="${esc(l.go)}"><span class="ic">${ico(l.icon,'sm')}</span><span><b>${esc(l.t)}</b><small>${esc(l.k)}</small></span></button>`).join('') : '<p class="nbs-e">Tags, ATT&amp;CK IDs and event IDs on this page link it to Reference, Detections and write-ups.</p>'}</section>
    <section><h4>${ico('paperclip','sm')}Pictures &amp; files<button class="nbs-add" data-act="nbAttach" aria-label="Attach a file" title="Attach a file">${ico('plus','sm')}</button></h4>
      ${files.length ? files.map(m => `<button class="nbs-f" data-act="nbMediaDl" data-id="${m.id}" title="Download ${esc(m.name)}">${ico(/^image\//.test(m.type) ? 'image' : 'file-text','sm')}<span>${esc(m.name)}</span><small>${nbSize(m.size || 0)}</small></button>`).join('') : '<p class="nbs-e">Paste screenshots into the page, or attach lab files here.</p>'}</section>`;
}
/* Tags, ATT&CK technique IDs and Windows event IDs on a page point at the rest of the app. */
function nbLinked(p){
  const I = nbInfo(p), text = p.title + '\n' + I.text + '\n' + p.tags.join(' '), out = [], seen = new Set();
  const ttp = [...new Set((text.match(/\bT1\d{3}(?:\.\d{3})?\b/g) || []))], ev = [...new Set((text.match(/\b(?:event|eid|id)\s*(?:id\s*)?[:#]?\s*(\d{3,5})\b|\b(4\d{3}|1\d{3}|7\d{3})\b/gi) || []).map(s => s.match(/\d{3,5}/)[0]))];
  const words = p.tags.map(t => t.toLowerCase()).filter(t => t.length > 3);
  const add = (k, t, icon, go) => { if(seen.has(go) || out.length >= 7) return; seen.add(go); out.push({k, t, icon, go}); };
  try{ const A = refAll(); for(const [key, S] of Object.entries(A.secs)) for(const r of S.rows){ const v = String(r[0]);
      if((key === 'win' && ev.includes(v)) || (r[4] && ttp.some(t => String(r[4]).split(/[,\s]+/).includes(t)))) add('Reference · ' + (S.name || key), v + ' · ' + r[1], 'book-open', 'ref:' + key + ':' + v); } }catch(e){}
  for(const r of DB.rules || []){ const tech = String(r.technique || ''); if(ttp.some(t => tech.split(/[,\s]+/).includes(t) || tech.startsWith(t + '.')) || words.some(w => r.title.toLowerCase().includes(w))) add('Detection rule', r.title, 'file-code', 'rule:' + r.id); }
  for(const w of ((DB.ctf || {}).writeups || [])){ const hay = (w.title + ' ' + w.tldr + ' ' + w.body).toLowerCase(); if(words.some(t => hay.includes(t)) || ttp.some(t => hay.includes(t.toLowerCase()))) add('CTF write-up', w.title, 'flag', 'wu:' + w.id); }
  return out;
}

/* ---------- binding the editor (once per render) ---------- */
let nbPend = null;   // {ed, id, t}
function nbDirty(){ const ed = $('nbEd'); if(!ed || !TABS.writer) return; const id = ed.dataset.page; clearTimeout(nbPend && nbPend.t); nbPend = {ed, id, t:setTimeout(nbCommit, 400)}; const s = $('nbSaved'); if(s) s.innerHTML = ico('pencil','sm') + 'Editing…'; }
function nbCommit(){ if(!nbPend) return; const {ed, id} = nbPend; clearTimeout(nbPend.t); nbPend = null; const p = nbPage(id); if(!p) return;
  const html = nbClean(ed.innerHTML, {media:true}); if(html !== p.html){ p.html = html; nbTouch(p); rev++; cache = {}; save(); nbFlushMedia(); }
  const s = $('nbSaved'); if(s) s.innerHTML = ico('check','sm') + 'Saved';
  if(ed.isConnected){ const side = $('nbSide'); if(side) side.innerHTML = nbSideHtml(p); renderNavSoon(); } }
const renderNavSoon = (() => { let t; return () => { clearTimeout(t); t = setTimeout(() => { if(typeof renderNav === 'function') renderNav(); }, 400); }; })();
const NB_META = new Map();   // title / source edits still waiting
BEFORE_SAVE.push(() => { if(nbPend) nbCommit(); for(const f of [...NB_META.values()]) f(); });
PENDING.push(() => !!nbPend || NB_META.size > 0);
/* Closing the tab: the save above starts an IndexedDB write that the browser may cut off. When the workspace is too big for
   the instant localStorage copy (and not encrypted), the pages changed since IndexedDB last confirmed a save are also written
   to a small localStorage journal, synchronously, and merged back on the next start. */
const NB_J = STORE_KEY + ':nbj';
function nbJournal(){ if(!DB || !DB.nb || SEC.key || SEC.locked || STORE.ls || !TABS.writer) return; const since = (STORE.idbAt || 0) - 2000, pages = DB.nb.pages.filter(p => (p.updated || 0) > since);
  if(!pages.length) return; try{ localStorage.setItem(NB_J, JSON.stringify({at:Date.now(), pages})); }catch(e){} }
window.addEventListener('pagehide', nbJournal);
document.addEventListener('visibilitychange', () => { if(document.visibilityState === 'hidden') nbJournal(); });
function nbJournalApply(){
  let j = null; try{ j = JSON.parse(localStorage.getItem(NB_J) || 'null'); localStorage.removeItem(NB_J); }catch(e){} if(!j || !Array.isArray(j.pages) || SEC.key) return 0;
  let n = 0; for(const q of j.pages){ if(!q || typeof q !== 'object' || !nbId(q.id)) continue; const upd = +q.updated || 0, p = nbPage(q.id);
    const vals = {title:nbStr(q.title, 200) || 'Untitled', html:nbClean(nbStr(q.html, 8e6)), tags:(Array.isArray(q.tags) ? q.tags : []).filter(t => typeof t === 'string').slice(0, 30).map(t => t.slice(0, 40)), src:nbStr(q.src, 300), att:(Array.isArray(q.att) ? q.att : []).filter(a => nbM(a)), updated:upd};
    if(p){ if(upd > (p.updated || 0)){ Object.assign(p, vals); n++; } } else if(nbSec(q.sectionId)){ DB.nb.pages.push({id:q.id, sectionId:q.sectionId, created:+q.created || upd, ...vals}); n++; } }
  if(n){ NB_CACHE.clear(); save(); } return n;
}

let nbRange = null;
function nbSaveRange(){ const ed = $('nbEd'), s = getSelection(); if(ed && s.rangeCount && ed.contains(s.anchorNode)) nbRange = s.getRangeAt(0).cloneRange(); }
function nbRestore(){ const ed = $('nbEd'); if(!ed) return false; const s = getSelection();
  if(document.activeElement === ed && s.rangeCount && ed.contains(s.anchorNode)) return true;   // the live caret wins over a saved one
  ed.focus({preventScroll:true});
  if(nbRange && ed.contains(nbRange.startContainer)){ s.removeAllRanges(); s.addRange(nbRange); return true; }
  if(!s.rangeCount || !ed.contains(s.anchorNode)){ const r = document.createRange(); r.selectNodeContents(ed); r.collapse(false); s.removeAllRanges(); s.addRange(r); } return true; }
function nbBlockOf(node){ const ed = $('nbEd'); while(node && node !== ed){ if(node.nodeType === 1 && /^(P|H2|H3|H4|LI|PRE|BLOCKQUOTE|FIGCAPTION|TD|TH|DIV|FIGURE)$/.test(node.tagName)) return node; node = node.parentNode; } return null; }
const nbUp = (node, tag) => { const ed = $('nbEd'); while(node && node !== ed){ if(node.nodeType === 1 && node.tagName === tag) return node; node = node.parentNode; } return null; };
function nbInsert(html){ nbRestore(); document.execCommand('insertHTML', false, html); const ed = $('nbEd'), c = ed.querySelector('[data-caret]');
  if(c){ const r = document.createRange(); r.selectNodeContents(c); if(!c.textContent.trim()) r.collapse(true); else r.collapse(false); const s = getSelection(); s.removeAllRanges(); s.addRange(r); c.removeAttribute('data-caret'); }
  ed.querySelectorAll('img[data-m]:not([src]):not([data-nbm])').forEach(i => i.dataset.nbm = i.dataset.m);
  nbDirty(); }
async function nbInsertImages(files){
  const ok = [];
  for(const f of files){ try{ ok.push(await nbAddImage(f)); }catch(e){ toast('Skipped ' + (f.name || 'a file') + ': ' + e.message); } }
  if(!ok.length) return;
  const urls = await Promise.all(ok.map(nbURL));
  nbInsert(ok.map((id, i) => `<figure><img data-m="${id}" alt=""${urls[i] ? ` src="${urls[i]}"` : ` data-nbm="${id}"`}><figcaption></figcaption></figure>`).join('') + '<p data-caret><br></p>');
}
async function nbAttachFiles(files){
  const p = nbPage(UI.nbPage); if(!p) return; let n = 0;
  for(const f of files){ try{ (p.att = p.att || []).push(await nbAddFile(f)); n++; }catch(e){ toast('Skipped ' + f.name + ': ' + e.message); } }
  if(n){ nbTouch(p); mutate('attached ' + n + ' file' + (n > 1 ? 's' : '')); const side = $('nbSide'); if(side) side.innerHTML = nbSideHtml(p); toast(n + ' file' + (n > 1 ? 's' : '') + ' attached'); }
}
function nbCardCmd(){
  nbRestore(); const s = getSelection(), txt = s.toString().replace(/\s+/g, ' ').trim();
  nbInsert(`<p>Q: <span data-caret></span></p><p>A: ${esc(txt) || '<br>'}</p>`);
}
function nbHilite(){
  nbRestore(); const s = getSelection(); if(!s.rangeCount) return; const r = s.getRangeAt(0), m = nbUp(r.commonAncestorContainer, 'MARK');
  if(m){ const f = document.createDocumentFragment(); while(m.firstChild) f.appendChild(m.firstChild); m.replaceWith(f); return nbDirty(); }
  if(r.collapsed) return toast('Select some text to highlight');
  const d = document.createElement('div'); d.appendChild(r.cloneContents()); document.execCommand('insertHTML', false, '<mark>' + d.innerHTML + '</mark>'); nbDirty();
}
function nbCodeCmd(){
  nbRestore(); const s = getSelection(), txt = s.toString(), pre = nbUp(s.anchorNode, 'PRE');
  if(pre){ const p = document.createElement('p'); p.textContent = pre.textContent; pre.replaceWith(p); return nbDirty(); }
  if(txt && !/\n/.test(txt) && txt.length < 160){ const c = nbUp(s.anchorNode, 'CODE'); if(c){ c.replaceWith(document.createTextNode(c.textContent)); return nbDirty(); } document.execCommand('insertHTML', false, '<code>' + esc(txt) + '</code>&#8203;'); return nbDirty(); }
  nbInsert(`<pre data-caret>${esc(txt) || '<br>'}</pre><p><br></p>`);
}
function nbCheckCmd(){
  nbRestore(); const s = getSelection(); let ul = nbUp(s.anchorNode, 'UL');
  if(ul && ul.classList.contains('nb-check')){ ul.classList.remove('nb-check'); document.execCommand('insertUnorderedList'); return nbDirty(); }
  if(!ul) document.execCommand('insertUnorderedList'); ul = nbUp(getSelection().anchorNode, 'UL'); if(ul) ul.classList.add('nb-check'); nbDirty();
}
function nbCmd(c){
  const ed = $('nbEd'); if(!ed) return;
  if(c === 'bold' || c === 'italic' || c === 'underline'){ nbRestore(); document.execCommand(c); return nbDirty(); }
  if(c === 'ul'){ nbRestore(); const ul = nbUp(getSelection().anchorNode, 'UL'); if(ul && ul.classList.contains('nb-check')) ul.classList.remove('nb-check'); else document.execCommand('insertUnorderedList'); return nbDirty(); }
  if(c === 'check') return nbCheckCmd();
  if(c === 'hilite') return nbHilite();
  if(c === 'code') return nbCodeCmd();
  if(c === 'table') return nbInsert('<table><tr><th data-caret><br></th><th><br></th><th><br></th></tr><tr><td><br></td><td><br></td><td><br></td></tr><tr><td><br></td><td><br></td><td><br></td></tr></table><p><br></p>');
  if(c === 'callout'){ nbRestore(); const t = getSelection().toString().trim(); return nbInsert(`<div class="nb-call"><p><b>Key takeaway:</b> <span data-caret>${esc(t)}</span></p></div><p><br></p>`); }
  if(c === 'card') return nbCardCmd();
  if(c === 'image'){ nbSaveRange(); return $('nbImgIn').click(); }
  if(c === 'link'){ nbSaveRange(); return nbLinkDlg(); }
}
function nbLinkDlg(){
  const txt = nbRange ? nbRange.toString().trim() : '';
  openDlg(dhead('Add a link') + `<form data-form="nbLink"><div class="in"><div class="field"><label for="nbLU">Address</label><input id="nbLU" type="url" required placeholder="https://…" autofocus></div>
    <div class="field" style="margin:0"><label for="nbLT">Text</label><input id="nbLT" value="${esc(txt)}" placeholder="Leave empty to add it as a card"${txt ? ' readonly' : ''}><span class="hint">${txt ? 'The selected text becomes the link.' : 'With no text, the link is added as a card that shows the site.'}</span></div></div>
    <footer><button class="btn" type="button" data-act="dclose">Cancel</button><button class="btn primary" type="submit">Add link</button></footer></form>`);
  $('dlg').classList.add('narrow');
}
const nbCardHtml = (u, t) => `<div class="nb-link" contenteditable="false"><a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(t || (hostOf(u) + new URL(u).pathname.replace(/\/$/, '')).slice(0, 90))}</a><small>${esc(hostOf(u))}</small></div><p data-caret><br></p>`;

function bindNotebook(){
  const ed = $('nbEd');
  const q = $('nbq'); if(q){ let t; q.oninput = () => { clearTimeout(t); t = setTimeout(() => { UI.nbq = q.value; const tr = $('nbTree'); if(tr) tr.innerHTML = nbTreeHtml(); }, 140); }; }
  if(!ed){ nbBindLibrary(); return; }
  const p = nbPage(UI.nbPage); ed.dataset.page = p.id;
  try{ document.execCommand('defaultParagraphSeparator', false, 'p'); }catch(e){}
  ed.addEventListener('input', nbDirty);
  ed.addEventListener('blur', () => { nbSaveRange(); });
  document.onselectionchange = () => { const s = getSelection(); if(!ed.isConnected){ document.onselectionchange = null; return; } if(!s.rangeCount || !ed.contains(s.anchorNode)) return;
    nbRange = s.getRangeAt(0).cloneRange(); const b = nbBlockOf(s.anchorNode), sel = $('nbBlock'); if(sel){ const tg = b ? (nbUp(s.anchorNode, 'BLOCKQUOTE') ? 'blockquote' : b.tagName.toLowerCase()) : 'p'; sel.value = ['h2', 'h3', 'blockquote'].includes(tg) ? tg : 'p'; }
    document.querySelectorAll('.nbtb[data-nbcmd]').forEach(x => { const c = x.dataset.nbcmd; let on = false;
      if(['bold', 'italic', 'underline'].includes(c)) try{ on = document.queryCommandState(c); }catch(e){}
      else if(c === 'hilite') on = !!nbUp(s.anchorNode, 'MARK'); else if(c === 'code') on = !!(nbUp(s.anchorNode, 'PRE') || nbUp(s.anchorNode, 'CODE'));
      else if(c === 'ul'){ const u = nbUp(s.anchorNode, 'UL'); on = !!u && !u.classList.contains('nb-check'); } else if(c === 'check'){ const u = nbUp(s.anchorNode, 'UL'); on = !!u && u.classList.contains('nb-check'); }
      x.classList.toggle('on', on); x.setAttribute('aria-pressed', on); }); };
  document.querySelectorAll('.nbtb[data-nbcmd]').forEach(b => { b.addEventListener('mousedown', ev => ev.preventDefault()); b.addEventListener('click', () => nbCmd(b.dataset.nbcmd)); });
  $('nbBlock').addEventListener('change', ev => { nbRestore(); const v = ev.target.value, inQ = nbUp(getSelection().anchorNode, 'BLOCKQUOTE');
    if(inQ && v !== 'blockquote'){ document.execCommand('outdent'); if(v !== 'p') document.execCommand('formatBlock', false, v); } else document.execCommand('formatBlock', false, v === 'blockquote' ? 'blockquote' : v); nbDirty(); });
  $('nbImgIn').addEventListener('change', ev => { const f = [...ev.target.files]; ev.target.value = ''; nbInsertImages(f); });
  $('nbAttIn').addEventListener('change', ev => { const f = [...ev.target.files]; ev.target.value = ''; nbAttachFiles(f); });
  ed.addEventListener('paste', ev => {
    const cd = ev.clipboardData; if(!cd) return;
    const imgs = [...cd.files].filter(f => /^image\//.test(f.type)), html = cd.getData('text/html'), text = cd.getData('text/plain'), s = getSelection();
    if(imgs.length && !(html && /<(p|div|table|h\d|li)\b/i.test(html))){ ev.preventDefault(); return nbInsertImages(imgs); }
    if(s.rangeCount && nbUp(s.anchorNode, 'PRE')){ ev.preventDefault(); document.execCommand('insertText', false, text); return nbDirty(); }
    const url = text && text.trim(); if(url && /^https?:\/\/\S+$/.test(url) && url.length < 2000){ ev.preventDefault(); const b = nbBlockOf(s.anchorNode);
      if(b && b.tagName === 'P' && !b.textContent.trim()) return nbInsert(nbCardHtml(url)); document.execCommand('insertHTML', false, `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(url)}</a>&nbsp;`); return nbDirty(); }
    if(html){ ev.preventDefault(); document.execCommand('insertHTML', false, nbClean(html, {src:true, media:true})); return nbDirty(); }
    if(text && /\n/.test(text) && /^( {2,}|\t|\$ |PS |C:\\|#!|[{[<])/m.test(text) && text.split('\n').length > 2){ ev.preventDefault(); return nbInsert(`<pre>${esc(text.replace(/\n$/, ''))}</pre><p data-caret><br></p>`); }
  });
  ed.addEventListener('dragover', ev => { if([...(ev.dataTransfer.items || [])].some(i => i.kind === 'file')) ev.preventDefault(); });
  ed.addEventListener('drop', ev => { const fs = [...(ev.dataTransfer.files || [])]; if(!fs.length) return; ev.preventDefault();
    const r = document.caretRangeFromPoint ? document.caretRangeFromPoint(ev.clientX, ev.clientY) : null; if(r){ const s = getSelection(); s.removeAllRanges(); s.addRange(r); nbSaveRange(); }
    const im = fs.filter(f => /^image\//.test(f.type)), other = fs.filter(f => !/^image\//.test(f.type)); if(im.length) nbInsertImages(im); if(other.length) nbAttachFiles(other); });
  ed.addEventListener('click', ev => {
    const li = ev.target.closest('.nb-check > li'); if(li && ev.offsetX < 24 && ev.target === li){ li.classList.toggle('done'); return nbDirty(); }
    const a = ev.target.closest('a[href]'); if(a && (ev.ctrlKey || ev.metaKey) && !a.closest('.nb-link')){ ev.preventDefault(); window.open(a.href, '_blank', 'noopener,noreferrer'); }
  });
  ed.addEventListener('keydown', ev => {
    const s = getSelection(); if(!s.rangeCount) return; const node = s.anchorNode;
    if((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === 's'){ ev.preventDefault(); nbCommit(); flush(); return toast('Saved'); }
    if((ev.ctrlKey || ev.metaKey) && ev.shiftKey && ev.key.toLowerCase() === 'h'){ ev.preventDefault(); return nbHilite(); }
    if((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === 'k'){ ev.preventDefault(); ev.stopPropagation(); nbSaveRange(); return nbLinkDlg(); }
    const pre = nbUp(node, 'PRE');
    if(pre && ev.key === 'Tab'){ ev.preventDefault(); return document.execCommand('insertText', false, '  '); }
    if(pre && ev.key === 'Enter' && !ev.shiftKey){ ev.preventDefault();
      const r = s.getRangeAt(0), txt = rg => { const d = document.createElement('div'); d.appendChild(rg.cloneContents()); d.querySelectorAll('br').forEach(b => b.replaceWith('\n')); return d.textContent; };
      const head = document.createRange(); head.selectNodeContents(pre); head.setEnd(r.startContainer, r.startOffset);
      const tail = document.createRange(); tail.selectNodeContents(pre); tail.setStart(r.endContainer, r.endOffset);
      const h = txt(head), t = txt(tail).replace(/\n$/, '');
      if(!t && h && h.endsWith('\n')){ pre.textContent = h.replace(/\n+$/, '');   // Enter on an empty last line leaves the code block
        const p = document.createElement('p'); p.innerHTML = '<br>'; pre.after(p); const n = document.createRange(); n.setStart(p, 0); n.collapse(true); s.removeAllRanges(); s.addRange(n); return nbDirty(); }
      document.execCommand('insertLineBreak'); return nbDirty(); }
    const cell = ev.key === 'Tab' && (nbUp(node, 'TD') || nbUp(node, 'TH'));
    if(cell){ ev.preventDefault(); const cells = [...cell.closest('table').querySelectorAll('td,th')], i = cells.indexOf(cell);
      let nx = cells[i + (ev.shiftKey ? -1 : 1)]; if(!nx && !ev.shiftKey){ const tr = cell.parentElement, row = document.createElement('tr'); row.innerHTML = [...tr.children].map(() => '<td><br></td>').join(''); tr.after(row); nx = row.firstChild; nbDirty(); }
      if(nx){ const r = document.createRange(); r.selectNodeContents(nx); r.collapse(false); s.removeAllRanges(); s.addRange(r); } return; }
    if(ev.key === ' ' && s.isCollapsed){ const b = nbBlockOf(node); if(!b || b.tagName !== 'P') return;
      const pre0 = document.createRange(); pre0.selectNodeContents(b); pre0.setEnd(s.anchorNode, s.anchorOffset); const t = pre0.toString();
      const map = {'#':['formatBlock', 'h2'], '##':['formatBlock', 'h3'], '-':['insertUnorderedList'], '*':['insertUnorderedList'], '1.':['insertOrderedList'], '>':['formatBlock', 'blockquote'], '[]':['check'], '```':['code']};
      const m = map[t]; if(!m) return; ev.preventDefault(); s.removeAllRanges(); s.addRange(pre0); document.execCommand('delete');
      if(m[0] === 'check') nbCheckCmd(); else if(m[0] === 'code') nbInsert('<pre data-caret><br></pre>'); else document.execCommand(m[0], false, m[1]); return nbDirty(); }
  });
  const ti = $('nbTitle'); let tt;
  const setTitle = () => { clearTimeout(tt); NB_META.delete('title'); const v = ti.value.trim().replace(/\s+/g, ' ').slice(0, 200) || 'Untitled'; if(v === p.title) return; p.title = v; nbTouch(p); rev++; cache = {}; save();
    const lbl = document.querySelector(`.nbt-pg[data-id="${p.id}"] .nbt-l`); if(lbl) lbl.textContent = v; document.title = v + ' — ' + BRAND.name; };
  ti.addEventListener('input', () => { clearTimeout(tt); NB_META.set('title', setTitle); tt = setTimeout(setTitle, 300); });
  ti.addEventListener('keydown', ev => { if(ev.key === 'Enter' || (ev.key === 'ArrowDown' && ti.selectionStart === ti.value.length)){ ev.preventDefault(); ed.focus(); const r = document.createRange(); r.selectNodeContents(ed); r.collapse(true); const s = getSelection(); s.removeAllRanges(); s.addRange(r); } });
  nbBindMeta(p);
  if(UI.nbFocusTitle){ UI.nbFocusTitle = false; ti.focus(); }
  document.title = (p.title || 'Untitled') + ' — ' + BRAND.name;
}
function nbBindMeta(p){
  const ti = $('nbTagIn'), si = $('nbSrc'); let st;
  ti.addEventListener('keydown', ev => {
    if((ev.key === 'Enter' || ev.key === ',') && ti.value.trim()){ ev.preventDefault(); if(p.tags.length >= 30) return toast('A page can have up to 30 tags'); const v = ti.value.trim().replace(/^#/, '').toLowerCase().slice(0, 40); if(!p.tags.includes(v)) p.tags.push(v); nbTouch(p); mutate('tagged page ' + v); nbMetaPaint(p, true); }
    else if(ev.key === 'Backspace' && !ti.value && p.tags.length){ p.tags.pop(); nbTouch(p); mutate('untagged page'); nbMetaPaint(p, true); } });
  ti.addEventListener('blur', () => { const v = ti.value.trim().replace(/^#/, '').toLowerCase().slice(0, 40); if(v && !p.tags.includes(v)){ p.tags.push(v); nbTouch(p); mutate('tagged page ' + v); nbMetaPaint(p); } });
  const setSrc = () => { clearTimeout(st); NB_META.delete('src'); const v = si.value.trim().slice(0, 300); if(v === p.src) return; p.src = v; nbTouch(p); rev++; cache = {}; save(); };
  si.addEventListener('input', () => { clearTimeout(st); NB_META.set('src', setSrc); st = setTimeout(setSrc, 400); });
  si.addEventListener('change', () => nbMetaPaint(p));
}
function nbMetaPaint(p, focusTag){ const m = $('nbMeta'); if(!m) return; m.innerHTML = nbMetaHtml(p); nbBindMeta(p); if(focusTag) $('nbTagIn').focus(); const side = $('nbSide'); if(side) side.innerHTML = nbSideHtml(p); }

/* opening a page swaps the page and side panel only — the tree stays put, so nothing flashes */
function nbOpen(id, opts = {}){
  const p = nbPage(id); if(!p) return; nbCommit();
  const s = nbSec(p.sectionId), b = s && nbBook(s.bookId); let redraw = false;
  if(s && s.open === false){ s.open = true; redraw = true; } if(b && b.open === false){ b.open = true; redraw = true; }
  UI.nbPage = id; UI.nbView = 'page'; UI.nbTreeOpen = false;
  if(UI.route.area !== 'notebook') return go('#/notebook');
  const doc = document.querySelector('.nb3-doc'), side = $('nbSide');
  if(!doc || redraw || opts.full) return renderMain();
  const tmp = document.createElement('div'); tmp.innerHTML = nbEditorView(p);
  doc.replaceWith(tmp.querySelector('.nb3-doc')); side.innerHTML = nbSideHtml(p);
  $('nb3').classList.remove('treeopen');
  document.querySelectorAll('.nbt-pg.on,.nbt-hit.on').forEach(x => { x.classList.remove('on'); x.removeAttribute('aria-current'); });
  document.querySelectorAll(`[data-act=nbOpen][data-id="${id}"]`).forEach(x => { if(x.closest('#nbTree')){ x.classList.add('on'); x.setAttribute('aria-current', 'page'); } });
  bindNotebook(); const sc = $('nbScroll'); if(sc) sc.scrollTop = 0;
}

/* ---------- library interactions ---------- */
function nbBindLibrary(){
  const qk = $('nbQuick'); if(!qk) return;
  const take = async (files, html, text) => {
    const N = DB.nb, recent = N.pages.slice().sort((a, b) => b.updated - a.updated)[0];
    let sec = recent ? nbSec(recent.sectionId) : null;
    if(!sec){ const b = N.books[0] || nbNewBook({name:'Inbox', kind:'Other'}); sec = nbSecsOf(b.id)[0] || nbNewSec(b.id, 'Notes'); }
    let body = '', title = 'Untitled';
    for(const f of files.filter(f => /^image\//.test(f.type))){ try{ const id = await nbAddImage(f); body += `<figure><img data-m="${id}" alt=""><figcaption></figcaption></figure>`; title = 'Screenshot ' + new Date().toLocaleString(undefined, {day:'numeric', month:'short', hour:'2-digit', minute:'2-digit'}); }catch(e){ toast(e.message); } }
    const u = text && text.trim();
    if(!files.length && u && /^https?:\/\/\S+$/.test(u)){ body = `<div class="nb-link"><a href="${esc(u)}">${esc(hostOf(u))}</a></div><p><br></p>`; title = hostOf(u); }
    else if(!files.length && html) body = nbClean(html, {media:true});
    else if(!files.length && text) body = text.split(/\n{2,}/).map(t => `<p>${esc(t).replace(/\n/g, '<br>')}</p>`).join('');
    if(!body) return;
    if(!files.length && title === 'Untitled'){ const first = nbLines(nbDoc(body))[0] || ''; title = first.slice(0, 80) || 'Untitled'; }
    const p = nbNewPage(sec.id, {title, html:nbClean(body), src:u && /^https?:/.test(u) ? u : ''}); mutate('captured to notebook'); toast('New page in ' + sec.name); nbOpen(p.id, {full:true});
  };
  qk.addEventListener('paste', ev => { const cd = ev.clipboardData; if(!cd) return; ev.preventDefault(); take([...cd.files], cd.getData('text/html'), cd.getData('text/plain')); });
  qk.addEventListener('dragover', ev => { ev.preventDefault(); qk.classList.add('over'); });
  qk.addEventListener('dragleave', () => qk.classList.remove('over'));
  qk.addEventListener('drop', ev => { ev.preventDefault(); qk.classList.remove('over'); const fs = [...(ev.dataTransfer.files || [])]; if(fs.length) take(fs, '', ''); else take([], ev.dataTransfer.getData('text/html'), ev.dataTransfer.getData('text/plain')); });
  qk.addEventListener('click', () => { qk.focus(); toast('Now paste (Ctrl V) — a screenshot, link or text'); });
}
document.addEventListener('keydown', ev => {
  if(UI.route.area !== 'notebook' || UI.nbView === 'page' || !$('nbRev') || !$('scrim').hidden) return;
  if(/^(INPUT|TEXTAREA|SELECT)$/.test(ev.target.tagName) || ev.target.isContentEditable || ev.ctrlKey || ev.metaKey || ev.altKey) return;
  if(ev.key === ' ' && document.querySelector('[data-act=nbReveal]')){ ev.preventDefault(); return NB_ACTS.nbReveal(); }
  if(/^[1-4]$/.test(ev.key) && document.querySelector('[data-act=nbRate]')){ ev.preventDefault(); return NB_ACTS.nbRate(null, String(+ev.key - 1)); }
});

/* ---------- dialogs ---------- */
function nbBookDlg(id){
  const b = id ? nbBook(id) : {name:'', kind:'Course', color:NB_COLORS[DB.nb.books.length % NB_COLORS.length]};
  openDlg(dhead(id ? 'Notebook settings' : 'New notebook') + `<form data-form="nbBook" data-id="${id || ''}"><div class="in">
    <div class="field"><label for="nbBN">Name</label><input id="nbBN" value="${esc(b.name)}" required maxlength="80" placeholder="e.g. OSCP course, HTB Academy, SANS FOR508" autofocus></div>
    <div class="field"><label for="nbBK">Kind</label><select id="nbBK">${NB_KINDS.map(k => `<option${k === b.kind ? ' selected' : ''}>${k}</option>`).join('')}</select></div>
    <div class="field" style="margin:0"><span class="lbl" id="nbBCl">Colour</span><div class="nbsw" role="radiogroup" aria-labelledby="nbBCl">${NB_COLORS.map(c => `<label style="--cc:${c}"><input type="radio" name="nbBC" value="${c}"${c === b.color ? ' checked' : ''}><span class="sr">${c}</span></label>`).join('')}</div></div></div>
    <footer><button class="btn" type="button" data-act="dclose">Cancel</button><button class="btn primary" type="submit">${id ? 'Save' : 'Create notebook'}</button></footer></form>`);
  $('dlg').classList.add('narrow');
}
function nbNameDlg(kind, id, title, label){
  const cur = kind === 'sec' && id && nbSec(id) ? nbSec(id).name : '';
  openDlg(dhead(title) + `<form data-form="nbName" data-k="${kind}" data-id="${id || ''}"><div class="in"><div class="field" style="margin:0"><label for="nbNm">Name</label><input id="nbNm" value="${esc(cur)}" required maxlength="80" autofocus></div></div>
    <footer><button class="btn" type="button" data-act="dclose">Cancel</button><button class="btn primary" type="submit">${label}</button></footer></form>`);
  $('dlg').classList.add('narrow');
}
function nbSubmit(f){
  const k = f.dataset.form;
  if(k === 'nbLink'){ const u = nbSafeUrl($('nbLU').value), t = $('nbLT').value.trim(); if(!u) return fieldErr('nbLU', 'Use an address that starts with https:// or http://');
    closeDlg(); nbRestore(); const s = getSelection();
    if(s.rangeCount && !s.isCollapsed){ document.execCommand('createLink', false, u); $('nbEd').querySelectorAll('a[href]').forEach(a => { a.target = '_blank'; a.rel = 'noopener noreferrer'; }); return nbDirty(); }
    return t ? nbInsert(`<a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(t)}</a>&nbsp;`) : nbInsert(nbCardHtml(u)); }
  if(k === 'nbBook'){ const name = $('nbBN').value.trim().replace(/\s+/g, ' '); if(!name) return fieldErr('nbBN', 'Name is required.');
    const vals = {name, kind:$('nbBK').value, color:nbColor((f.querySelector('input[name=nbBC]:checked') || {}).value)};
    if(f.dataset.id){ Object.assign(nbBook(f.dataset.id), vals); mutate('notebook settings'); closeDlg(); return renderMain(); }
    const b = nbNewBook(vals), s = nbNewSec(b.id, 'General'), p = nbNewPage(s.id); mutate('new notebook ' + name); closeDlg(); UI.nbFocusTitle = true; return nbOpen(p.id, {full:true}); }
  if(k === 'nbName'){ const name = $('nbNm').value.trim().replace(/\s+/g, ' '); if(!name) return fieldErr('nbNm', 'Name is required.'); closeDlg();
    if(f.dataset.k === 'sec' && nbSec(f.dataset.id)){ nbSec(f.dataset.id).name = name; mutate('renamed section'); return renderMain(); }
    if(f.dataset.k === 'newsec'){ const s = nbNewSec(f.dataset.id, name), p = nbNewPage(s.id); mutate('new section ' + name); UI.nbFocusTitle = true; return nbOpen(p.id, {full:true}); } }
}
function nbDelete(kind, id){
  const N = DB.nb, prev = JSON.stringify(N);
  const undo = what => toast(what + ' deleted', 'Undo', () => { DB.nb = JSON.parse(prev); NB_CACHE.clear(); mutate('restored ' + what.toLowerCase()); renderAll(); });
  if(kind === 'page'){ const p = nbPage(id); return confirmDlg('Delete “' + p.title + '”?', 'The page, its pictures and attachments go. You can undo right after.', 'Delete page', () => {
      const sib = nbPagesOf(p.sectionId), i = sib.indexOf(p); N.pages = N.pages.filter(x => x !== p); const nx = sib[i + 1] || sib[i - 1]; UI.nbPage = nx ? nx.id : null; if(!nx) UI.nbView = 'lib';
      mutate('deleted page'); renderMain(); renderNav(); undo('Page'); }); }
  if(kind === 'sec'){ const s = nbSec(id), n = nbPagesOf(id).length; return confirmDlg('Delete section “' + s.name + '”?', `Its ${n} page${n === 1 ? '' : 's'} go too. You can undo right after.`, 'Delete section', () => {
      N.pages = N.pages.filter(p => p.sectionId !== id); N.sections = N.sections.filter(x => x !== s); if(!nbPage(UI.nbPage)){ UI.nbView = 'lib'; UI.nbPage = null; } mutate('deleted section'); renderMain(); renderNav(); undo('Section'); }); }
  if(kind === 'book'){ const b = nbBook(id), n = nbBookPages(id).length; return confirmDlg('Delete notebook “' + b.name + '”?', `Its sections and ${n} page${n === 1 ? '' : 's'} go too. You can undo right after.`, 'Delete notebook', () => {
      const secs = new Set(nbSecsOf(id).map(s => s.id)); N.pages = N.pages.filter(p => !secs.has(p.sectionId)); N.sections = N.sections.filter(s => !secs.has(s.id)); N.books = N.books.filter(x => x !== b);
      if(!nbPage(UI.nbPage)){ UI.nbView = 'lib'; UI.nbPage = null; } mutate('deleted notebook'); renderMain(); renderNav(); undo('Notebook'); }); }
}
function nbMoveMenu(p, x, y){
  const items = []; for(const b of DB.nb.books) for(const s of nbSecsOf(b.id)) if(s.id !== p.sectionId) items.push({label:b.name + ' › ' + s.name, icon:'folder-open', fn:() => { p.sectionId = s.id; nbTouch(p); mutate('moved page'); renderMain(); toast('Moved to ' + s.name); }});
  if(!items.length) return toast('Add another section first');
  showMenu(x, y, items.slice(0, 24), 'Move “' + p.title + '” to…');
}
const nbMenuAt = t => { const r = t.getBoundingClientRect(); return [Math.max(8, Math.min(r.left, innerWidth - 260)), r.bottom + 6]; };

/* ---------- actions ---------- */
const NB_ACTS = {
  nbLib:() => { nbCommit(); UI.nbView = 'lib'; UI.nbRev = null; renderMain(); },
  nbOpen:id => nbOpen(id),
  nbOpenBook:id => { const ps = nbBookPages(id).sort((a, b) => b.updated - a.updated); if(ps[0]) return nbOpen(ps[0].id, {full:UI.nbView !== 'page'});
    const s = nbSecsOf(id)[0] || nbNewSec(id, 'General'), p = nbNewPage(s.id); mutate('new page'); UI.nbFocusTitle = true; nbOpen(p.id, {full:true}); },
  nbBookNew:() => nbBookDlg(),
  nbBookTog:id => { const b = nbBook(id); b.open = b.open === false; save(); const t = $('nbTree'); if(t) t.innerHTML = nbTreeHtml(); },
  nbSecTog:id => { const s = nbSec(id); s.open = s.open === false; save(); const t = $('nbTree'); if(t) t.innerHTML = nbTreeHtml(); },
  nbPageNew:id => { const p = nbNewPage(id); mutate('new page'); UI.nbFocusTitle = true; nbOpen(p.id, {full:true}); },
  nbSecNew:id => nbNameDlg('newsec', id, 'New section', 'Create section'),
  nbNewMenu:(id, v, t) => { const p = nbPage(UI.nbPage), [x, y] = nbMenuAt(t); showMenu(x, y, [
      ...(p ? [{label:'New page in ' + nbSec(p.sectionId).name, icon:'file-text', fn:() => NB_ACTS.nbPageNew(p.sectionId)}, {label:'New section in ' + nbBookOfPage(p).name, icon:'folder-plus', fn:() => NB_ACTS.nbSecNew(nbBookOfPage(p).id)}] : []),
      {label:'New notebook', icon:'book-open', fn:() => nbBookDlg()}, {sep:true}, {label:'Import pages…', icon:'upload', fn:() => nbImport()}]); },
  nbBookMenu:(id, v, t) => { const [x, y] = nbMenuAt(t); showMenu(x, y, [{label:'Open', icon:'book-open', fn:() => NB_ACTS.nbOpenBook(id)}, {label:'New section', icon:'folder-plus', fn:() => NB_ACTS.nbSecNew(id)},
      {label:'Rename, kind & colour', icon:'pencil', fn:() => nbBookDlg(id)}, {label:'Export notebook…', icon:'download', fn:() => nbExportDlg('book', id)}, {label:'Review its flashcards', icon:'sparkles', fn:() => { nbReviewQueue(nbAllCards(id).map(k => k.key)); UI.nbView = 'lib'; renderMain(); }},
      {sep:true}, {label:'Delete notebook…', icon:'trash-2', danger:true, fn:() => nbDelete('book', id)}], nbBook(id).name); },
  nbSecMenu:(id, v, t) => { const [x, y] = nbMenuAt(t); showMenu(x, y, [{label:'New page', icon:'file-text', fn:() => NB_ACTS.nbPageNew(id)}, {label:'Rename', icon:'pencil', fn:() => nbNameDlg('sec', id, 'Rename section', 'Save')},
      {label:'Export section…', icon:'download', fn:() => nbExportDlg('sec', id)}, {sep:true}, {label:'Delete section…', icon:'trash-2', danger:true, fn:() => nbDelete('sec', id)}], nbSec(id).name); },
  nbPageMenu:(id, v, t) => { const p = nbPage(UI.nbPage); if(!p) return; nbCommit(); const [x, y] = nbMenuAt(t); showMenu(Math.min(x, innerWidth - 260), y, [
      {label:'Move to…', icon:'arrow-right-left', fn:() => nbMoveMenu(p, x, y)}, {label:'Duplicate', icon:'copy', fn:() => { const c = nbNewPage(p.sectionId, {title:p.title + ' (copy)', html:p.html, tags:p.tags.slice(), src:p.src, att:(p.att || []).slice()}); mutate('duplicated page'); nbOpen(c.id, {full:true}); }},
      {label:'Copy as rich text', icon:'copy', fn:() => nbCopyRich({scope:'page', id:p.id})}, {label:'Print or save as PDF', icon:'file-text', fn:() => nbPrint({scope:'page', id:p.id})},
      {sep:true}, {label:'Delete page…', icon:'trash-2', danger:true, fn:() => nbDelete('page', p.id)}], p.title); },
  nbTagX:(id, v) => { const p = nbPage(UI.nbPage); p.tags = p.tags.filter(t => t !== v); nbTouch(p); mutate('untagged page'); nbMetaPaint(p); },
  nbGoHead:(id, v) => { const h = $('nbEd') && $('nbEd').querySelectorAll('h2,h3')[+v]; if(h) h.scrollIntoView({behavior:'smooth', block:'start'}); },
  nbAttach:() => $('nbAttIn') && $('nbAttIn').click(),
  nbMediaDl:id => nbMediaDl(id),
  nbEdEnd:() => { const ed = $('nbEd'); if(!ed) return; const last = ed.lastElementChild; if(!last || last.tagName !== 'P' || last.textContent.trim()){ const p = document.createElement('p'); p.innerHTML = '<br>'; ed.appendChild(p); }
    ed.focus(); const r = document.createRange(); r.selectNodeContents(ed.lastElementChild); r.collapse(true); const s = getSelection(); s.removeAllRanges(); s.addRange(r); },
  nbSideTog:() => { UI.nbSide = UI.nbSide === false; const w = $('nb3'); if(w) w.classList.toggle('noside', UI.nbSide === false); const b = document.querySelector('.nbtb-side'); if(b) b.setAttribute('aria-pressed', UI.nbSide !== false); },
  nbTreeTog:() => { UI.nbTreeOpen = !UI.nbTreeOpen; const w = $('nb3'); if(w) w.classList.toggle('treeopen', UI.nbTreeOpen); },
  nbTreeX:() => { UI.nbTreeOpen = false; const w = $('nb3'); if(w) w.classList.remove('treeopen'); },
  nbLinkGo:(id, v) => { nbCommit(); const [k, a, b] = v.split(':');
    if(k === 'ref'){ UI.refQ = ''; UI.refHot = false; UI.refGrp = 'all'; UI.refCat = a; UI.refRow = a + ':' + v.split(':').slice(2).join(':'); UI.refOpen = true; return go('#/reference'); }
    if(k === 'rule'){ UI.rule = a; UI.ropen = true; UI.dtype = 'all'; UI.dcat = ''; return go('#/detections'); }
    if(k === 'wu'){ UI.wuSel = a; UI.wuEdit = null; UI.ctfTab = 'writeups'; UI.ctfSel = null; return go('#/ctf'); } },
  nbRevPage:() => { const p = nbPage(UI.nbPage); if(!p) return; nbCommit(); nbReviewQueue(nbInfo(p).cards.map(k => k.key)); UI.nbView = 'lib'; renderMain(); },
  nbRevAll:() => { nbReviewQueue(nbAllCards().map(k => k.key)); nbRevPaint(); },
  nbReveal:() => { if(!UI.nbRev) return; UI.nbRev.shown = true; nbRevPaint(); const b = document.querySelector('.nbr-rate .on'); if(b) b.focus(); },
  nbRate:(id, v) => { const R = UI.nbRev; if(!R) return; const key = R.keys[R.i]; if(!key) return; const g = +v; DB.nb.cards[key] = nbNext(key, g);
    if(g === 0) R.keys.push(key); R.i++; R.shown = false; R.done++; rev++; save(); nbRevPaint(); renderNavSoon();
    const sb = document.querySelector('.nbr-show'); if(sb) sb.focus(); },
  nbImport:() => nbImport(),
  nbExport:(id, v) => { nbCommit(); if(v === 'all') return nbExportDlg('book', (DB.nb.books[0] || {}).id); nbExportDlg('page', UI.nbPage); }
};

/* ---------- import: Markdown, HTML, plain text, Word ---------- */
function nbImport(){
  const inp = document.createElement('input'); inp.type = 'file'; inp.multiple = true; inp.accept = '.md,.markdown,.txt,.html,.htm,.docx';
  inp.onchange = async () => {
    const files = [...inp.files]; if(!files.length) return; ensureNB();
    let sec = UI.nbView === 'page' && nbPage(UI.nbPage) ? nbSec(nbPage(UI.nbPage).sectionId) : null;
    if(!sec){ const b = DB.nb.books.find(x => x.name === 'Imported') || nbNewBook({name:'Imported', kind:'Other'}); sec = nbSecsOf(b.id)[0] || nbNewSec(b.id, 'Pages'); }
    const made = []; let skipped = 0;
    for(const f of files){ try{ if(f.size > 30 * 1024 * 1024) throw new Error('too large');
        const ext = (f.name.match(/\.(\w+)$/) || [])[1] || ''; let title = f.name.replace(/\.\w+$/, ''), html;
        if(/^docx$/i.test(ext)){ const r = await nbFromDocx(new Uint8Array(await f.arrayBuffer())); html = r.html; title = r.title || title; }
        else { const txt = await f.text();
          if(/^html?$/i.test(ext)){ const d = new DOMParser().parseFromString(txt, 'text/html'); const h1 = d.querySelector('h1'); title = (d.title || (h1 && h1.textContent) || title).trim(); if(h1 && h1.textContent.trim() === title) h1.remove(); d.querySelectorAll('.nbx-meta').forEach(x => x.remove()); d.querySelectorAll('.nbx-call').forEach(x => x.className = 'nb-call'); html = nbClean(nbCardsFromTables(d.body.innerHTML), {media:true}); }
          else if(/^(md|markdown)$/i.test(ext)){ const m = txt.match(/^\s*#\s+(.+)\n/); if(m) title = m[1].trim(); html = nbClean(mdLite(m ? txt.slice(m[0].length) : txt), {media:true}); }
          else html = txt.split(/\n{2,}/).map(t => `<p>${esc(t).replace(/\n/g, '<br>')}</p>`).join(''); }
        made.push(nbNewPage(sec.id, {title:title.slice(0, 200) || 'Imported', html:nbClean(html)})); }
      catch(e){ skipped++; console.warn('import', f.name, e); } }
    if(made.length){ mutate('imported ' + made.length + ' page' + (made.length > 1 ? 's' : '')); nbOpen(made[0].id, {full:true}); }
    toast(made.length ? `${made.length} page${made.length > 1 ? 's' : ''} imported into ${sec.name}${skipped ? ` · ${skipped} skipped` : ''}` : 'Nothing could be imported from those files');
  };
  inp.click();
}

/* ---------- sample notebooks ---------- */
function nbSeed(){
  const N = DB.nb, T0 = Date.now(), H = 36e5, mk = (b, s, title, html, o) => nbNewPage(s.id, {title, html, sample:true, ...o});
  const shot = typeof NB_DEMO_SHOT !== 'undefined' ? NB_DEMO_SHOT : null;
  if(shot) N.media['m-demo-spn'] = {id:'m-demo-spn', type:'image/png', name:'lab3-spns.png', demo:true, w:shot.w, h:shot.h, size:Math.round(shot.data.length * .75), at:T0};
  const ad = nbNewBook({name:'Active Directory course', kind:'Course', color:'#6366f1', sample:true, created:T0 - 30 * NB_DAY});
  const en = nbNewSec(ad.id, 'Enumeration'), kb = nbNewSec(ad.id, 'Kerberos attacks'), lm = nbNewSec(ad.id, 'Lateral movement'); en.open = false; lm.open = false;
  mk(ad, en, 'BloodHound basics', `<p>BloodHound maps who can reach what in Active Directory. Collect with SharpHound, load the zip, then ask for paths.</p><pre>SharpHound.exe -c All --zipfilename lab.zip
bloodhound-python -u j.okafor -p '…' -d corp.example -c All -ns 10.20.30.5</pre><ul><li>Start with <b>Shortest paths to Domain Admins</b> from owned principals.</li><li>Mark users you control as <i>Owned</i> so paths start from them.</li><li>Edges worth knowing: GenericAll, GenericWrite, WriteDACL, AddMember, ForceChangePassword.</li></ul><p>Q: Which BloodHound edge lets you reset a user's password without knowing the old one?</p><p>A: ForceChangePassword</p>`, {tags:['enumeration', 'bloodhound'], src:'Course module 4', updated:T0 - 9 * NB_DAY});
  mk(ad, kb, 'AS-REP roasting', `<p>Accounts with <b>“Do not require Kerberos preauthentication”</b> answer an AS-REQ without proof of the password. Part of the reply is encrypted with the user's key, so it can be cracked offline.</p><pre>GetNPUsers.py corp.example/ -usersfile users.txt -no-pass -dc-ip 10.20.30.5 -format hashcat
hashcat -m 18200 asrep.txt rockyou.txt</pre><h2>Detect</h2><ul><li>Event <b>4768</b> with pre-authentication type <code>0</code>.</li><li>Audit for accounts with DONT_REQ_PREAUTH set (userAccountControl <code>0x400000</code>).</li></ul><p>Q: Hashcat mode for AS-REP hashes?</p><p>A: 18200</p><p>Q: Which account setting makes AS-REP roasting possible?</p><p>A: “Do not require Kerberos preauthentication” (DONT_REQ_PREAUTH, userAccountControl 0x400000).</p>`, {tags:['kerberos', 'credential-access'], src:'Course module 7 · Lab 2', updated:T0 - 2 * NB_DAY});
  const kr = mk(ad, kb, 'Kerberoasting', `<p>Any domain user can ask a domain controller for a service ticket to an account that has an SPN. Part of that ticket is encrypted with the <mark>service account's password hash</mark>, so it can be cracked offline — no traffic to the target, no lockouts.</p>
<h2>Request the tickets</h2><pre>GetUserSPNs.py corp.example/j.okafor -dc-ip 10.20.30.5 -request -outputfile hashes.txt
# from a domain-joined Windows host
Rubeus.exe kerberoast /outfile:hashes.txt</pre>
${shot ? '<figure><img data-m="m-demo-spn" alt="GetUserSPNs output from the lab"><figcaption>Lab 3 — svc_sql is a Domain Admin with an SPN: the jackpot.</figcaption></figure>' : ''}
<h2>Crack offline</h2><table><tr><th>Ticket encryption</th><th>Hashcat mode</th><th>Speed</th></tr><tr><td>RC4 (etype 23)</td><td>13100</td><td>Fast</td></tr><tr><td>AES128 (etype 17)</td><td>19600</td><td>Slow</td></tr><tr><td>AES256 (etype 18)</td><td>19700</td><td>Slow</td></tr></table>
<div class="nb-call"><p><b>Key takeaway:</b> RC4 tickets crack far faster than AES. Defenders: alert on event 4769 with ticket encryption 0x17, and give service accounts long random passwords or gMSAs.</p></div>
<h2>Detect &amp; defend</h2><ul><li>Event <b>4769</b> (service ticket requested) with ticket encryption type <code>0x17</code>, especially many SPNs from one account in a short time.</li><li>Set <code>msDS-SupportedEncryptionTypes</code> to AES only where the service allows it.</li></ul>
<ul class="nb-check"><li class="done">Lab 3 — roast and crack svc_sql</li><li>Try targeted Kerberoasting (set an SPN on a user I can write to)</li></ul>
<h3>Flashcards</h3><p>Q: Which hashcat mode cracks Kerberos TGS-REP tickets with RC4?</p><p>A: 13100</p><p>Q: Which Windows event shows a service ticket request, and what makes it suspicious for Kerberoasting?</p><p>A: 4769 — a burst of requests from one account, especially with ticket encryption type 0x17 (RC4).</p><p>Q: Why is Kerberoasting so quiet?</p><p>A: Asking for a ticket is normal Kerberos traffic and cracking happens offline: no failed logons, no lockouts.</p>
<div class="nb-link" contenteditable="false"><a href="https://attack.mitre.org/techniques/T1558/003/">Kerberoasting — MITRE ATT&amp;CK T1558.003</a><small>attack.mitre.org</small></div>`, {tags:['kerberos', 'credential-access', 'T1558.003'], src:'Course module 7 · Lab 3', updated:T0 - 2 * 6e4});
  mk(ad, kb, 'Golden & silver tickets', `<p>A <b>golden ticket</b> is a forged TGT signed with the <code>krbtgt</code> key: it works for any user and service in the domain until krbtgt is reset twice. A <b>silver ticket</b> is a forged service ticket signed with one service account's key: narrower, and the domain controller never sees it.</p><table><tr><th></th><th>Golden</th><th>Silver</th></tr><tr><td>Key needed</td><td>krbtgt</td><td>Service account</td></tr><tr><td>Scope</td><td>Whole domain</td><td>One service</td></tr><tr><td>DC involved</td><td>Yes, when it asks for service tickets</td><td>No</td></tr></table><div class="nb-call"><p><b>Remember:</b> after a compromise, reset the krbtgt password twice, leaving time for replication in between.</p></div><p>Q: Why reset krbtgt twice?</p><p>A: Domain controllers also accept the previous krbtgt key, so tickets signed with the old key stay valid until it has been replaced a second time.</p>`, {tags:['kerberos', 'persistence'], src:'Course module 8', updated:T0 - 6 * NB_DAY});
  mk(ad, lm, 'Pass-the-hash', `<p>NTLM accepts the hash as if it were the password, so a dumped NT hash is enough to log on to other hosts where that account is an admin.</p><pre>nxc smb 10.20.30.0/24 -u administrator -H &lt;NT hash&gt; --local-auth
impacket-psexec -hashes :&lt;NT hash&gt; corp.example/administrator@10.20.30.21</pre><h2>What it looks like in logs</h2><ul><li>4624 logon type 3 with NTLM from a workstation that rarely talks to the target.</li><li>Mimikatz <code>sekurlsa::pth</code> shows on the source host as 4624 logon type 9 with logon process <code>seclogo</code>.</li></ul><p>Q: Logon type and logon process for sekurlsa::pth on the source host?</p><p>A: Logon type 9 (NewCredentials) with logon process seclogo.</p>`, {tags:['lateral-movement', 'ntlm'], src:'Course module 9', updated:T0 - 12 * NB_DAY});
  const web = nbNewBook({name:'Web app labs', kind:'Labs', color:'#0d9488', sample:true, created:T0 - 60 * NB_DAY}), ss = nbNewSec(web.id, 'Server-side');
  mk(web, ss, 'SSRF to cloud metadata', `<p>If a server fetches URLs for you, point it at the cloud metadata service. On AWS with IMDSv1 that hands out temporary credentials for the instance role.</p><pre>http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/&lt;role&gt;</pre><table><tr><th>Cloud</th><th>Endpoint</th><th>Needs</th></tr><tr><td>AWS IMDSv2</td><td>169.254.169.254</td><td>A PUT for a token first, then the X-aws-ec2-metadata-token header</td></tr><tr><td>Azure</td><td>169.254.169.254/metadata/instance?api-version=2021-02-01</td><td>Header Metadata: true</td></tr><tr><td>Google Cloud</td><td>metadata.google.internal/computeMetadata/v1/</td><td>Header Metadata-Flavor: Google</td></tr></table><div class="nb-call"><p><b>Key takeaway:</b> IMDSv2 stops most SSRF because a basic SSRF can't send a PUT with a custom header. Check whether the lab instance still allows v1.</p></div><ul><li>Filters that block 169.254.169.254 can sometimes be beaten with other spellings — <code>2852039166</code>, <code>0xa9fea9fe</code> — or a redirect from a server you control.</li></ul><p>Q: Which header does Google Cloud's metadata server require?</p><p>A: Metadata-Flavor: Google</p><p>Q: Why does IMDSv2 block most SSRF?</p><p>A: It needs a session token from a PUT request with a custom header, which a basic SSRF can't send.</p>`, {tags:['ssrf', 'cloud', 'aws'], src:'https://portswigger.net/web-security/ssrf', updated:T0 - 2 * NB_DAY - 3 * H});
  const df = nbNewBook({name:'DFIR study', kind:'Study', color:'#ea580c', sample:true, created:T0 - 20 * NB_DAY}), wa = nbNewSec(df.id, 'Windows artefacts');
  mk(df, wa, 'Prefetch and Amcache', `<p>Two places that show programs ran — or at least existed — on a Windows host.</p><table><tr><th>Artefact</th><th>Where</th><th>Tells you</th></tr><tr><td>Prefetch</td><td>C:\\Windows\\Prefetch\\*.pf</td><td>Run count, last 8 run times (Windows 8 and later), files loaded</td></tr><tr><td>Amcache</td><td>C:\\Windows\\appcompat\\Programs\\Amcache.hve</td><td>Path, SHA-1 and first-seen time of programs</td></tr></table><pre>PECmd.exe -d C:\\Windows\\Prefetch --csv out
AmcacheParser.exe -f Amcache.hve --csv out</pre><div class="nb-call"><p><b>Careful:</b> an Amcache entry alone does not prove a program ran. Back it up with Prefetch, ShimCache or event logs.</p></div><p>Q: How many last-run times does a Windows 10 prefetch file keep?</p><p>A: Eight.</p><p>Q: Which hash does Amcache record for a file?</p><p>A: SHA-1</p>`, {tags:['dfir', 'windows', 'execution'], src:'FOR500 notes', updated:T0 - 1 * NB_DAY});
  // some cards already reviewed, so progress shows
  for(const p of N.pages) nbInfo(p).cards.forEach((k, i) => { if(p.id !== kr.id && i % 2 === 0) N.cards[k.key] = {reps:2, ivl:6, ease:2.5, lapses:0, due:T0 + (3 + i) * NB_DAY}; });
}

/* ---------- backups, encryption and imported data ---------- */
/* pictures and files ride along in a backup as data: URLs, like case attachments */
async function nbBackupFiles(){ const out = {}; if(!DB.nb) return out; for(const m of Object.values(DB.nb.media)){ if(m.data || m.demo || m.gone) continue; const u = await nbDataURL(m.id); if(u) out[m.id] = u; } return out; }
async function nbRestoreFiles(files){ let n = 0; for(const [id, url] of Object.entries(files || {})){ const m = nbM(id); if(!m || typeof url !== 'string' || !/^data:[\w.+-]+\/[\w.+-]+;base64,/.test(url) || url.length > 3e7) continue;
    try{ if(await nbPut(id, nbURLBlob(url))) delete m.data; else m.data = url; n++; }catch(e){} } return n; }
async function nbReseal(fromKey){ if(!DB.nb || !STORE.idb) return; for(const id of Object.keys(DB.nb.media)){ let v = await IDB.get('nbm:' + id); if(!v) continue;
    if(v.enc){ if(!fromKey) continue; const pt = await crypto.subtle.decrypt({name:'AES-GCM', iv:b64d8(v.iv)}, fromKey, v.ct); v = new Blob([pt], {type:v.type}); } await IDB.set('nbm:' + id, await sealBlob(v)); }
  NB_URLS.clear(); NB_DATA.clear(); }
/* Notebook data from a backup is checked field by field: wrong types are dropped, text is capped, and every page is cleaned again. */
const nbColor = c => /^#[0-9a-f]{3,8}$/i.test(String(c || '')) ? c : NB_COLORS[0];
const nbStr = (v, n) => typeof v === 'string' ? v.slice(0, n) : '';
const nbId = v => typeof v === 'string' && /^[\w-]{1,60}$/.test(v) ? v : null;
function nbSanitize(){
  const N = DB.nb && typeof DB.nb === 'object' ? DB.nb : {}, arr = v => Array.isArray(v) ? v.filter(x => x && typeof x === 'object') : [];
  const media = {}; for(const [k, m] of Object.entries(N.media && typeof N.media === 'object' ? N.media : {})){ if(!/^m-[a-z0-9-]{1,40}$/i.test(k) || !m || typeof m !== 'object') continue;
    media[k] = {id:k, type:nbStr(m.type, 100), name:nbStr(m.name, 120) || 'file', size:+m.size || 0, w:+m.w || 0, h:+m.h || 0, at:+m.at || Date.now(), ...(m.demo ? {demo:true} : {}), ...(m.gone ? {gone:+m.gone} : {}),
      ...(typeof m.data === 'string' && /^data:[\w.+-]+\/[\w.+-]+;base64,/.test(m.data) ? {data:m.data} : {})}; }
  DB.nb = {media, books:[], sections:[], pages:[], cards:{}, xopt:N.xopt && typeof N.xopt === 'object' ? N.xopt : undefined};
  for(const b of arr(N.books)){ const id = nbId(b.id); if(!id) continue; DB.nb.books.push({id, name:nbStr(b.name, 120) || 'Notebook', kind:NB_KINDS.includes(b.kind) ? b.kind : 'Other', color:nbColor(b.color), created:+b.created || Date.now(), open:b.open !== false, ...(b.sample ? {sample:true} : {})}); }
  const bk = new Set(DB.nb.books.map(b => b.id));
  for(const s of arr(N.sections)){ const id = nbId(s.id); if(!id || !bk.has(s.bookId)) continue; DB.nb.sections.push({id, bookId:s.bookId, name:nbStr(s.name, 120) || 'Section', open:s.open !== false}); }
  const sc = new Set(DB.nb.sections.map(s => s.id));
  for(const p of arr(N.pages)){ const id = nbId(p.id); if(!id || !sc.has(p.sectionId)) continue;
    DB.nb.pages.push({id, sectionId:p.sectionId, title:nbStr(p.title, 200) || 'Untitled', html:nbClean(nbStr(p.html, 8e6)), tags:(Array.isArray(p.tags) ? p.tags : []).filter(t => typeof t === 'string').slice(0, 30).map(t => t.slice(0, 40)),
      src:nbStr(p.src, 300), att:(Array.isArray(p.att) ? p.att : []).filter(a => nbM(a)), created:+p.created || Date.now(), updated:+p.updated || Date.now(), ...(p.sample ? {sample:true} : {})}); }
  for(const [k, c] of Object.entries(N.cards && typeof N.cards === 'object' ? N.cards : {})) if(/^[\w-]{1,60}:[a-z0-9]{1,14}$/.test(k) && c && typeof c === 'object') DB.nb.cards[k] = {reps:+c.reps || 0, ivl:+c.ivl || 0, ease:Math.min(5, Math.max(1.3, +c.ease || 2.5)), lapses:+c.lapses || 0, due:+c.due || 0};
  NB_CACHE.clear(); return DB.nb;
}
