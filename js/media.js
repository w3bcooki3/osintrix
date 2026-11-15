/* ==========================================================================
   Media — pictures, videos, audio and saved web pages in a case.
   Every file is evidence: the original bytes are kept unchanged (with their
   SHA-256), stored once however many times they are added, encrypted with the
   workspace and covered by restore points. A small preview (about 360 px,
   WebP) is made beside each picture and video so the Media tab stays fast;
   it is kept as "file:<id>.p" and made again if it is ever missing.
   Files can be dropped anywhere on a case, pasted (Ctrl+V), or added from the
   Media tab. Files over 50 MB are recorded with their fingerprint but not stored.
   ========================================================================== */
const MEDIA_MAX = 50 * 1048576, MEDIA_HASH_MAX = 512 * 1048576, MEDIA_PREV = 360;
const MEDIA_KINDS = [['all', 'All', 'layout-grid'], ['image', 'Pictures', 'image'], ['video', 'Videos', 'video'], ['audio', 'Audio', 'music'], ['page', 'Web pages', 'globe'], ['doc', 'Documents', 'file-text'], ['other', 'Other', 'file']];
function mediaKind(a){
  const t = String(a && a.type || '').toLowerCase(), n = String(a && a.name || '').toLowerCase();
  if(/^image\//.test(t) || /\.(png|jpe?g|gif|webp|bmp|svg|heic|heif|avif|tiff?|ico)$/.test(n)) return 'image';
  if(/^video\//.test(t) || /\.(mp4|webm|mov|m4v|mkv|avi|ogv|3gp)$/.test(n)) return 'video';
  if(/^audio\//.test(t) || /\.(mp3|wav|ogg|oga|m4a|flac|aac|opus|amr)$/.test(n)) return 'audio';
  if(/html|mhtml|multipart\/related|message\/rfc822/.test(t) || /\.(html?|xhtml|mhtml?|mht)$/.test(n)) return 'page';
  if(/pdf|msword|officedocument|opendocument|^text\//.test(t) || /\.(pdf|docx?|xlsx?|pptx?|odt|ods|rtf|txt|md|csv)$/.test(n)) return 'doc';
  return 'other';
}
const MEDIA_ICON = {image:'image', video:'video', audio:'music', page:'globe', doc:'file-text', other:'file'};
const fmtDur = s => { s = Math.round(+s || 0); const h = Math.floor(s / 3600), m = Math.floor(s % 3600 / 60), x = s % 60; return (h ? h + ':' + String(m).padStart(2, '0') : m) + ':' + String(x).padStart(2, '0'); };

/* ---------- reading a file: size, length, preview ---------- */
const waitEv = (el, ev, ms) => new Promise((res, rej) => { const t = setTimeout(() => rej(new Error('timeout')), ms);
  el.addEventListener(ev, () => { clearTimeout(t); res(); }, {once:true}); el.addEventListener('error', () => { clearTimeout(t); rej(new Error('media')); }, {once:true}); });
function drawSmall(src, w, h){
  if(!w || !h) return Promise.resolve(null);
  const s = Math.min(1, MEDIA_PREV / Math.max(w, h)), c = document.createElement('canvas'); c.width = Math.max(1, Math.round(w * s)); c.height = Math.max(1, Math.round(h * s));
  c.getContext('2d').drawImage(src, 0, 0, c.width, c.height);
  return new Promise(r => c.toBlob(b => r(b), 'image/webp', 0.72));
}
/* {w, h, dur, prev:Blob} — anything it cannot read is simply left out */
async function mediaProbe(blob, kind){
  const out = {};
  try{
    if(kind === 'image'){ if(/svg/i.test(blob.type)) return out; const bm = await createImageBitmap(blob); out.w = bm.width; out.h = bm.height; out.prev = await drawSmall(bm, bm.width, bm.height); if(bm.close) bm.close(); }
    else if(kind === 'video' || kind === 'audio'){
      const u = URL.createObjectURL(blob), v = document.createElement(kind); v.muted = true; v.preload = 'metadata';
      try{ v.src = u; await waitEv(v, 'loadedmetadata', 6000);
        /* recordings from browsers and some phones leave the length out; seeking to the end makes the player work it out */
        if(!isFinite(v.duration)){ try{ v.currentTime = 1e7; await waitEv(v, 'durationchange', 4000); }catch(e){} try{ v.currentTime = 0; }catch(e){} }
        if(isFinite(v.duration) && v.duration > 0) out.dur = Math.round(v.duration * 10) / 10;
        if(kind === 'video' && v.videoWidth){ out.w = v.videoWidth; out.h = v.videoHeight;
          try{ v.currentTime = Math.min(1, (out.dur || 0) / 10); await waitEv(v, 'seeked', 6000); out.prev = await drawSmall(v, v.videoWidth, v.videoHeight); }catch(e){} } }
      finally { v.removeAttribute('src'); try{ v.load(); }catch(e){} URL.revokeObjectURL(u); }
    }
  }catch(e){}
  return out;
}
/* ---------- previews ---------- */
const PREV_URLS = new Map(); let prevBusy = 0; const prevQ = [];
function prevRun(fn){ return new Promise(res => { prevQ.push(async () => { try{ res(await fn()); }catch(e){ res(null); } }); prevPump(); }); }
function prevPump(){ while(prevBusy < 2 && prevQ.length){ const f = prevQ.shift(); prevBusy++; f().finally(() => { prevBusy--; prevPump(); }); } }
async function previewURL(fid, kind){
  if(PREV_URLS.has(fid)) return PREV_URLS.get(fid);
  const p = prevRun(async () => {
    let b = await openBlob(await IDB.get('file:' + fid + '.p'));
    if(!b && (kind === 'image' || kind === 'video')){   // older files, or a preview that was never made: make it now
      const full = await fileBlob(fid); if(!full) return null; const P = await mediaProbe(full, kind);
      if(P.prev){ b = P.prev; await IDB.set('file:' + fid + '.p', await sealBlob(P.prev)); }
      else if(kind === 'image' && full.size < 4 * 1048576) return fileURL(fid);   // small or unusual pictures are shown as they are
    }
    return b ? URL.createObjectURL(b) : null;
  });
  PREV_URLS.set(fid, p); const u = await p; if(!u) PREV_URLS.delete(fid); return u;
}
const prevIO = typeof IntersectionObserver !== 'undefined' ? new IntersectionObserver(es => { for(const en of es){ if(!en.isIntersecting) continue; const im = en.target; prevIO.unobserve(im);
  previewURL(im.dataset.pid, im.dataset.pk).then(u => { if(u) im.src = u; else im.closest('.md-th') && im.closest('.md-th').classList.add('noprev'); }); } }, {rootMargin:'400px'}) : null;
function hydratePreviews(root){ (root || document).querySelectorAll('img[data-pid]:not([src]):not([data-pw])').forEach(im => { im.dataset.pw = '1'; if(prevIO) prevIO.observe(im); else previewURL(im.dataset.pid, im.dataset.pk).then(u => { if(u) im.src = u; }); }); }
new MutationObserver(() => { if(document.querySelector('img[data-pid]:not([data-pw])')) hydratePreviews(); }).observe(document.documentElement, {childList:true, subtree:true});
function previewForget(fid){ const p = PREV_URLS.get(fid); PREV_URLS.delete(fid); if(p) Promise.resolve(p).then(u => { if(u && u.startsWith('blob:')) URL.revokeObjectURL(u); }); }

/* ---------- the same bytes are stored once ---------- */
function fileBySha(sha){
  const recs = DB.records.concat((DB.trash || []).flatMap(x => x.kind === 'record' ? [x.data.r] : x.kind === 'case' ? x.data.records || [] : []));
  for(const r of recs) for(const a of (r && r.att) || []) if(a.sha256 === sha) return a;
  return null;
}
/* how full the browser is, for the warning after adding files */
async function roomNote(){ await storageEstimate(); if(!STORE.quota) return ''; const p = (STORE.usage || 0) / STORE.quota; return p > 0.85 ? ` · browser storage ${Math.round(p * 100)}% full — free space in Settings → Storage` : ''; }

/* ---------- files too big to keep: recorded with their fingerprint ---------- */
async function bigFileRecord(f, cid){
  let sha = ''; if(f.size <= MEDIA_HASH_MAX){ try{ sha = await sha256Hex(await f.arrayBuffer()); }catch(e){} }
  const k = mediaKind(f), body = `Large file — not stored in this browser (over 50 MB).\nName: ${f.name}\nType: ${f.type || 'unknown'}\nSize: ${f.size} bytes\n${sha ? 'SHA-256: ' + sha : 'SHA-256: not calculated (over ' + fmtBytes(MEDIA_HASH_MAX) + ')'}\nKeep the original safe on your computer or evidence store; this fingerprint proves later that it is the same file.`;
  return {id:uid('r'), caseId:cid, type:'evidence', title:'Large file (not stored): ' + f.name, body, tsRaw:new Date(f.lastModified || Date.now()).toISOString(), tsZone:'explicit', ts:f.lastModified || Date.now(), source:'attachment', host:'', tags:['file', 'not-stored'], ents:E.extract(body).filter(e => e.k !== 'file'), answer:'', addedBy:'You', added:Date.now(),
    big:{name:String(f.name || 'file').slice(0, 300), type:String(f.type || '').slice(0, 120), size:f.size, sha256:sha, modified:f.lastModified || 0}};
}

/* ---------- the Media tab ---------- */
function caseMediaItems(caseId){
  const out = [];
  for(const r of DB.records){ if(r.caseId !== caseId) continue;
    for(const a of r.att || []) out.push({r, a, k:mediaKind(a)});
    if(r.big) out.push({r, a:{id:'', ...r.big, added:r.added}, k:mediaKind(r.big), big:true}); }
  return out.sort((x, y) => (y.a.added || 0) - (x.a.added || 0));
}
function caseMedia(c){
  const all = caseMediaItems(c.id), f = MEDIA_KINDS.some(x => x[0] === UI.mdK) ? UI.mdK : 'all', n = k => k === 'all' ? all.length : all.filter(x => x.k === k).length;
  const list = f === 'all' ? all : all.filter(x => x.k === f), seen = new Set(), bytes = all.reduce((s, x) => { if(x.big || seen.has(x.a.id)) return s; seen.add(x.a.id); return s + (+x.a.size || 0); }, 0);
  const q = STORE.quota, used = STORE.usage || 0, pct = q ? Math.min(100, Math.round(used / q * 100)) : 0;
  if(!STORE.quota && !UI.mdEst){ UI.mdEst = 1; storageEstimate().then(() => { if(UI.route.tab === 'media') renderMain(); }); }
  const card = x => { const a = x.a, r = x.r, img = x.k === 'image' || x.k === 'video';
    const meta = [fmtBytes(a.size), a.w ? a.w + '×' + a.h : '', a.dur ? fmtDur(a.dur) : ''].filter(Boolean).join(' · ');
    return `<article class="md-c${x.big ? ' big' : ''}"><button class="md-th${img && !x.big ? '' : ' noprev'}" data-act="${x.big ? 'selRec' : 'mdOpen'}" data-id="${r.id}" data-v="${esc(a.id)}" aria-label="Open ${esc(a.name)}">
        ${img && !x.big ? `<img data-pid="${esc(a.id)}" data-pk="${x.k}" alt="">` : ''}<span class="md-ic">${ico(MEDIA_ICON[x.k])}</span>
        ${x.k === 'video' ? `<span class="md-play">${ico('play','sm')}</span>` : ''}${a.dur ? `<span class="md-dur">${fmtDur(a.dur)}</span>` : ''}${x.big ? '<span class="md-dur">not stored</span>' : ''}</button>
      <div class="md-b"><b title="${esc(a.name)}">${esc(a.name)}</b><span class="t3">${esc(meta)}${a.gps ? ' · ' + ico('map-pin','sm') : ''}</span>
        <span class="md-a"><button class="linkbtn" data-act="selRec" data-id="${r.id}">Record</button>${x.big ? '' : `<button class="iconbtn" data-act="attDl" data-id="${r.id}" data-v="${esc(a.id)}" aria-label="Save ${esc(a.name)}" title="Save a copy">${ico('download','sm')}</button>`}</span></div></article>`; };
  const seg = `<div class="tlbar"><div class="seg" role="group" aria-label="View"><button data-act="mdView" data-v="files" aria-pressed="${UI.mdV !== 'pic'}">${ico('images','sm')}Files</button><button data-act="mdView" data-v="pic" aria-pressed="${UI.mdV === 'pic'}">${ico('scan-face','sm')}Picture insights</button></div></div>`;
  if(UI.mdV === 'pic') return `<div class="scroll md-drop">${seg}${picView(c)}</div>`;
  return `<div class="scroll md-drop">${seg}<div class="page wide">
    <section class="card md-head"><div class="body"><div class="wrap" style="align-items:center">
      <div style="flex:1;min-width:220px"><h3 style="margin:0">${all.length ? all.length + ' file' + (all.length > 1 ? 's' : '') + ' · ' + fmtBytes(bytes) : 'No media yet'}</h3>
        <p class="t3" style="margin:4px 0 0">Drop pictures, videos, audio or saved web pages anywhere on this case, or paste a screenshot with Ctrl+V. Originals are kept unchanged with their SHA-256; files over 50 MB are recorded by fingerprint only.</p></div>
      <button class="btn primary" data-act="mdAdd">${ico('image-plus','sm')}Add media</button><button class="btn" data-act="mdPage">${ico('globe','sm')}Add a saved web page</button></div>
      ${q ? `<div class="md-sto"><div class="md-bar" role="progressbar" aria-label="Browser storage used" aria-valuenow="${pct}" aria-valuemin="0" aria-valuemax="100"><i style="width:${pct}%" class="${pct > 85 ? 'hot' : ''}"></i></div><span class="t3">Browser storage: ${fmtBytes(used)} of ${fmtBytes(q)} used · <a href="#/storage">manage</a></span></div>` : ''}</div></section>
    ${all.length ? `<div class="seg md-f" role="group" aria-label="Show">${MEDIA_KINDS.filter(([k]) => k === 'all' || n(k)).map(([k, l, i]) => `<button data-act="mdKind" data-v="${k}" aria-pressed="${f === k}">${ico(i,'sm')}${l} <span class="t3">${n(k)}</span></button>`).join('')}</div>
      <div class="md-g">${list.map(card).join('')}</div>`
    : `<div class="empty md-empty">${ico('images')}<p>Pictures, videos and web pages you collect for this case appear here.</p><p class="t3">To keep a web page with its pictures, open it in Chrome or Edge, press Ctrl+S and choose “Webpage, Single File (.mhtml)”, then drop the file here.</p></div>`}
  </div></div>`;
}
/* ---------- viewing ---------- */
async function mediaOpen(rid, fid){
  const r = recById(rid), a = r && (r.att || []).find(x => x.id === fid); if(!a) return;
  const k = mediaKind(a);
  if(k === 'image' || k === 'page') return safeView(rid, fid);
  if(k !== 'video' && k !== 'audio') return attAct('attOpen', rid, fid);
  const url = await fileURL(fid); if(!url) return toast('That file is missing from this browser');
  const kv = [['Size', fmtBytes(a.size)], a.w ? ['Picture size', a.w + ' × ' + a.h] : null, a.dur ? ['Length', fmtDur(a.dur)] : null, ['Type', a.type || 'unknown'], ['SHA-256', a.sha256]].filter(Boolean);
  openDlg(dhead(esc(a.name)) + `<div class="in"><${k} class="md-player" controls preload="metadata" src="${esc(url)}"></${k}>
      <dl class="kv" style="margin-top:12px">${kv.map(([l, v]) => `<dt>${l}</dt><dd class="${l === 'SHA-256' ? 'mono' : ''}" style="overflow-wrap:anywhere">${esc(v)}</dd>`).join('')}</dl></div>
    <footer><button class="btn" data-act="selRec" data-id="${r.id}" style="margin-right:auto">${ico('file-text','sm')}Open the record</button><button class="btn" data-act="attDl" data-id="${r.id}" data-v="${fid}">${ico('download','sm')}Save a copy</button><button class="btn primary" data-act="dclose">Close</button></footer>`, true);
  $('dlg').classList.add('xwide');
}
/* ---------- a vault entry's own file (Image / video entries) ---------- */
function entryMedia(e){
  const src = recById(e.src), A = src ? (src.att || []).map(a => ({a, k:mediaKind(a)})) : [];
  const big = src && src.big ? `<p class="t3 small" style="margin:0 0 8px">${ico('file','sm')} ${esc(src.big.name)} · ${fmtBytes(src.big.size)} · not stored<br><span class="mono" style="overflow-wrap:anywhere">${esc(src.big.sha256 || 'no fingerprint (over 512 MB)')}</span></p>` : '';
  if(e.type !== 'media' && !A.some(x => x.k === 'image' || x.k === 'video')) return '';
  return `<div class="isec"><h4>File ${A.length ? '<span class="t3">' + A.length + '</span>' : ''}</h4>
    ${big}${A.map(({a, k}) => `<div class="md-ent"><button class="md-th${k === 'image' || k === 'video' ? '' : ' noprev'}" data-act="mdOpen" data-id="${src.id}" data-v="${a.id}" aria-label="Open ${esc(a.name)}">${k === 'image' || k === 'video' ? `<img data-pid="${a.id}" data-pk="${k}" alt="">` : ''}<span class="md-ic">${ico(MEDIA_ICON[k])}</span>${a.dur ? `<span class="md-dur">${fmtDur(a.dur)}</span>` : ''}</button>
      <div class="t3 small" style="margin-top:4px">${esc(a.name)} · ${fmtBytes(a.size)}</div></div>`).join('')}
    <button class="btn sm" data-act="mdEntryUp" data-id="${e.id}">${ico('upload','sm')}${A.length ? 'Add another file' : 'Upload the file'}</button></div>`;
}
async function mediaForEntry(e, files){
  const f = files[0]; if(!f) return;
  if(f.size > MEDIA_MAX){ const r = await bigFileRecord(f, e.caseId); DB.records.push(r); if(!recById(e.src)) e.src = r.id; e.fields = e.fields || {}; if(!e.fields.title) e.fields.title = f.name;
    mutate('fingerprint for ' + primary(e)); await hashRecords(); renderAll(); return toast('Over 50 MB, so the file is not stored — its name, size and SHA-256 are recorded with the entry'); }
  let m; try{ m = await storeFile(f); }catch(err){ return toast(err.message === 'full' ? 'Browser storage is full — free space in Settings → Storage' : 'That file could not be stored'); }
  let r = recById(e.src);
  if(r && r.caseId === e.caseId) r.att = (r.att || []).concat([m]);
  else { r = fileRecord(m, e.caseId); DB.records.push(r); e.src = r.id; }
  const k = mediaKind(m); e.fields = e.fields || {};
  if(!e.fields.title) e.fields.title = m.name; if(!e.fields.type && (k === 'image' || k === 'video' || k === 'audio')) e.fields.type = {image:'Image', video:'Video', audio:'Audio'}[k];
  if(!e.fields.resolution && m.w) e.fields.resolution = m.w + '×' + m.h;
  mutate('file for ' + primary(e)); await hashRecords(); renderAll(); toast('File stored with the entry' + await roomNote());
}

/* ---------- drop and paste anywhere on a case ---------- */
const mediaHere = () => UI.route.area === 'case' && $('scrim').hidden && !!theCase();
const filesDrag = ev => [...((ev.dataTransfer && ev.dataTransfer.types) || [])].includes('Files');
function mediaTake(fs){
  if(!fs.length) return; draft.caseId = DB.active;
  if(fs.length === 1 && /\.(pem|crt|cer|der|csr|req|p7b|p7c)$/i.test(fs[0].name) && typeof cxReadFile === 'function') return cxReadFile(fs[0]);
  if(fs.length === 1 && /\.(csv|tsv|json|ndjson|jsonl|log|txt|evtx)$/i.test(fs[0].name) && !/^image\//.test(fs[0].type) && UI.route.tab !== 'media') return logImportFile(fs[0]);
  attachFiles(fs);
}
const shotName = (f, i) => f.name && f.name !== 'image.png' ? f : new File([f], 'screenshot-' + new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-') + (i ? '-' + i : '') + '.' + ((f.type.split('/')[1] || 'png').replace('jpeg', 'jpg')), {type:f.type});
let mdDragT = 0;
document.addEventListener('dragover', ev => { if(ev.defaultPrevented || !mediaHere() || !filesDrag(ev)) return; ev.preventDefault(); document.body.classList.add('md-dropping'); clearTimeout(mdDragT); mdDragT = setTimeout(() => document.body.classList.remove('md-dropping'), 250); });
document.addEventListener('drop', ev => { document.body.classList.remove('md-dropping'); if(ev.defaultPrevented || !mediaHere() || !filesDrag(ev)) return; const fs = [...ev.dataTransfer.files]; if(!fs.length) return; ev.preventDefault(); mediaTake(fs); });
document.addEventListener('paste', ev => {
  if(ev.defaultPrevented || !mediaHere()) return; const cd = ev.clipboardData; if(!cd) return; const fs = [...(cd.files || [])]; if(!fs.length) return;
  const t = ev.target, typing = t && (t.isContentEditable || /^(input|textarea|select)$/i.test(t.tagName));
  if(typing && cd.getData('text/plain')) return;   // text being pasted into a field stays text
  ev.preventDefault(); mediaTake(fs.map(shotName));
});

const MD_ACTS = {
  mdKind:(id, v) => { UI.mdK = v; renderMain(); },
  mdOpen:(id, v) => mediaOpen(id, v),
  mdAdd:() => pickFiles('', fs => { draft.caseId = DB.active; attachFiles(fs); }),
  mdPage:() => pickFiles('.mhtml,.mht,.html,.htm,.xhtml', fs => { draft.caseId = DB.active; importWebPages(fs); }),
  mdEntryUp:id => { const e = entryById(id); if(e) pickFiles('image/*,video/*,audio/*', fs => mediaForEntry(e, fs), false); },
};
