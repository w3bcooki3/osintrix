/* ==========================================================================
   Safety net & evidence files — trash bin, restore points, backup reminder,
   file / screenshot attachments (IndexedDB blobs), bulk log import.
   ========================================================================== */
IDB.del = k => new Promise(res => { if(!IDB.db) return res(false); try{ const tx = IDB.db.transaction('kv', 'readwrite'); tx.objectStore('kv').delete(k); tx.oncomplete = () => res(true); tx.onerror = tx.onabort = () => res(false); }catch(e){ res(false); } });
const ago = t => E.fmtAgo(Math.max(0, Date.now() - t)) + (Date.now() - t < 6e4 ? '' : ' ago');

/* ---------- trash ---------- */
const TRASH_DAYS = 30;
const TRASH_KIND = {case:['folder-open','Case'], entry:['layers','Vault entry'], record:['file-text','Evidence record'], note:['sticky-note','Note'], link:['waypoints','Relationship']};
function trashPut(kind, label, data, caseId){ DB.trash = DB.trash || []; const x = {id:uid('x'), kind, label:String(label || '').slice(0, 140), caseId:caseId || null, at:Date.now(), data}; DB.trash.unshift(x); return x; }
function trashPurge(){
  if(!DB.trash || !DB.trash.length) return; const cut = Date.now() - TRASH_DAYS * 864e5, old = DB.trash.filter(x => x.at < cut);
  if(!old.length) return; DB.trash = DB.trash.filter(x => x.at >= cut); for(const x of old) dropFilesOf(x); save();
}
function filesOfItem(x){ const d = x.data || {}; const recs = x.kind === 'record' ? [d.r] : x.kind === 'case' ? d.records || [] : []; return recs.flatMap(r => (r && r.att) || []).map(a => a.id); }
function dropFilesOf(x){ for(const fid of filesOfItem(x)) if(!fileInUse(fid)) IDB.del('file:' + fid); }
function fileInUse(fid){ return DB.records.some(r => (r.att || []).some(a => a.id === fid)); }
function trashRestore(id){
  const x = (DB.trash || []).find(z => z.id === id); if(!x) return; const d = x.data;
  const caseOk = cid => DB.cases.some(c => c.id === cid);
  switch(x.kind){
    case 'case': if(caseOk(d.c.id)) return toast('That case already exists');
      DB.cases.push(d.c); DB.entries.push(...d.entries); DB.links.push(...d.links); DB.records.push(...d.records); DB.notes = (DB.notes || []).concat(d.notes || []); break;
    case 'entry': { const e = d.e; if(!caseOk(e.caseId)) e.caseId = DB.active; DB.entries.push(e); DB.links.push(...(d.links || []).filter(l => entryById(l.a) && entryById(l.b))); break; }
    case 'record': { const r = d.r; if(!caseOk(r.caseId)) r.caseId = DB.active; DB.records.push(r); break; }
    case 'note': DB.notes = DB.notes || []; DB.notes.push(d.n); break;
    case 'link': if(entryById(d.l.a) && entryById(d.l.b)) DB.links.push(d.l); else return toast('Both ends of that relationship are gone'); break;
  }
  DB.trash = DB.trash.filter(z => z !== x); mutate('restored ' + x.label); renderAll(); toast('Restored ' + x.label);
}
function trashDelete(id){ const x = (DB.trash || []).find(z => z.id === id); if(!x) return; DB.trash = DB.trash.filter(z => z !== x); dropFilesOf(x); mutate('deleted forever: ' + x.label); renderMain(); }
function trashEmpty(){ const n = (DB.trash || []).length; if(!n) return;
  confirmDlg('Empty the trash?', `${n} item${n > 1 ? 's are' : ' is'} deleted for good, with any attached files. This cannot be undone.`, 'Empty trash', () => { const xs = DB.trash; DB.trash = []; for(const x of xs) dropFilesOf(x); mutate('emptied trash'); renderAll(); toast('Trash emptied'); }); }

/* ---------- delete a record (to trash) ---------- */
function delRecord(ids){
  ids = [].concat(ids); const rs = DB.records.filter(r => ids.includes(r.id)); if(!rs.length) return;
  const xs = rs.map(r => { const ci = DB.cases.find(c => c.t0 === r.id); if(ci) ci.t0 = null; return trashPut('record', r.title, {r}, r.caseId); });
  const ls = DB.links.filter(l => ids.includes(l.src)); for(const l of ls) l.src = '';
  DB.records = DB.records.filter(r => !ids.includes(r.id)); if(UI.sel && ids.includes(UI.sel.id)) UI.sel = null; if(UI.evPick) for(const i of ids) UI.evPick.delete(i);
  mutate('deleted ' + rs.length + ' record(s)'); renderAll();
  toast(rs.length === 1 ? 'Record moved to trash' : rs.length + ' records moved to trash', 'Undo', () => { DB.records.push(...rs); DB.trash = DB.trash.filter(x => !xs.includes(x)); mutate('undid delete'); renderAll(); });
}

/* ---------- restore points (full snapshots in IndexedDB, outside the main state) ---------- */
let SNAPS = null; const SNAP_MAX = 8;
async function snapsLoad(){ if(SNAPS) return SNAPS; const raw = await IDB.get('osintrix-snaps'); try{ SNAPS = raw ? JSON.parse(raw) : []; }catch(e){ SNAPS = []; } return SNAPS; }
async function snapshot(why){
  if(!STORE.idb) return false; await snapsLoad(); const at = Date.now(), json = JSON.stringify(DB);
  if(!await IDB.set('osintrix-snap:' + at, json)) return false;
  SNAPS.unshift({at, why, size:json.length, cases:DB.cases.length, records:DB.records.length});
  while(SNAPS.length > SNAP_MAX){ const o = SNAPS.pop(); IDB.del('osintrix-snap:' + o.at); }
  await IDB.set('osintrix-snaps', JSON.stringify(SNAPS)); return true;
}
async function snapRestore(at){
  const s = (SNAPS || []).find(x => x.at === +at); if(!s) return;
  confirmDlg('Go back to this restore point?', `Everything in this browser returns to how it was ${E.fmtFull(s.at, tz()).slice(0, 16)} (${s.why}). A restore point of the current state is made first, so you can come back.`, 'Restore', async () => {
    const raw = await IDB.get('osintrix-snap:' + s.at); let d = null; try{ d = JSON.parse(raw); }catch(e){}
    if(!d || !Array.isArray(d.cases)) return toast('That restore point could not be read');
    await snapshot('Before restoring a restore point'); const prefs = DB.prefs; DB = d; DB.prefs = Object.assign({}, d.prefs, {lastExport:prefs.lastExport, remindAt:prefs.remindAt});
    ensureTools(); ensurePlaybooks(); ensureIntel(); ensureQueries(); ensureRules(); ensureNotes(); if(!DB.cases.some(c => c.id === DB.active)) DB.active = DB.cases[0].id;
    UI.sel = null; mutate('restored restore point'); applyPrefs(); renderAll(); toast('Restored');
  }, true);
}
async function snapDownload(at){ const raw = await IDB.get('osintrix-snap:' + at); if(raw) download('osintrix-restore-point-' + new Date(+at).toISOString().slice(0, 16).replace(/[:T]/g, '-') + '.json', raw, 'application/json'); }
async function snapNow(){ if(await snapshot('Made by hand')){ renderMain(); toast('Restore point saved'); } else toast('Restore points need IndexedDB, which this browser blocked'); }

function viewTrash(){
  if(!SNAPS){ snapsLoad().then(() => { if(UI.route.area === 'trash') renderMain(); }); }
  trashPurge(); const T = DB.trash || [];
  const row = x => { const [ic, kl] = TRASH_KIND[x.kind] || ['file','Item'], c = x.caseId && theCase(x.caseId), left = Math.max(0, TRASH_DAYS - Math.floor((Date.now() - x.at) / 864e5)), nf = filesOfItem(x).length;
    return `<div class="binrow"><span class="binic">${ico(ic)}</span><div class="main2"><b>${esc(x.label || '(untitled)')}</b><small>${kl}${c && c.id ? ' · ' + esc(c.code || c.name) : ''}${nf ? ' · ' + nf + ' file' + (nf > 1 ? 's' : '') : ''} · deleted ${esc(ago(x.at))} · ${left} day${left === 1 ? '' : 's'} left</small></div>
      <button class="btn xs" data-act="trRestore" data-id="${x.id}">${ico('undo-2','sm')}Restore</button><button class="iconbtn" data-act="trDel" data-id="${x.id}" title="Delete forever" aria-label="Delete forever">${ico('trash-2','sm')}</button></div>`; };
  const S2 = SNAPS || [];
  return `<div class="scroll"><div class="page narrow"><div class="ph"><div><h1>Trash &amp; restore points</h1><div class="sub">Deleted items wait here for ${TRASH_DAYS} days. Restore points are full copies of your workspace made before big changes.</div></div></div>
    <section class="card" style="margin-bottom:18px"><header><h3>Trash <span class="t3">${T.length}</span></h3>${T.length ? `<button class="btn xs danger" data-act="trEmpty">${ico('trash-2','sm')}Empty trash</button>` : ''}</header>
      <div class="body flush">${T.length ? T.map(row).join('') : `<p class="t3" style="padding:18px 20px;margin:0">Nothing in the trash. Deleted cases, vault entries, evidence records, relationships and notes land here.</p>`}</div></section>
    <section class="card"><header><h3>Restore points <span class="t3">${S2.length} of ${SNAP_MAX}</span></h3><button class="btn xs" data-act="snapNow">${ico('save','sm')}Make one now</button></header>
      <div class="body flush">${S2.length ? S2.map(s => `<div class="binrow"><span class="binic">${ico('history')}</span><div class="main2"><b>${esc(s.why)}</b><small>${esc(E.fmtFull(s.at, tz()).slice(0, 16))} · ${s.cases} cases · ${s.records} records · ${fmtBytes(s.size * 2)}</small></div>
        <button class="btn xs" data-act="snapRestore" data-id="${s.at}">${ico('undo-2','sm')}Restore</button><button class="iconbtn" data-act="snapDl" data-id="${s.at}" title="Download as a backup file" aria-label="Download">${ico('download','sm')}</button></div>`).join('')
        : `<p class="t3" style="padding:18px 20px;margin:0">${STORE.idb ? 'None yet. One is made automatically before importing a backup, resetting, removing sample data, starting fresh or importing a log file.' : 'This browser blocked IndexedDB, so restore points are off. Export backups by hand instead.'}</p>`}</div></section>
    <p class="t3" style="font-size:13px;margin-top:16px">Both live in this browser only. Clearing site data removes them too — keep an exported backup somewhere safe.</p></div></div>`;
}

/* ---------- backup reminder ---------- */
function backupBanner(){
  const p = DB.prefs; if(!p.firstUse){ p.firstUse = Date.now(); save(); }
  const own = DB.records.filter(r => !(theCase(r.caseId) || {}).sample).length + (DB.notes || []).filter(n => !n.sample).length;
  const since = p.lastExport || p.firstUse, days = Math.floor((Date.now() - since) / 864e5);
  if(own < 5 || days < 14 || (p.remindAt && p.remindAt > Date.now())) return '';
  return `<div class="note amber bkp"><span class="ic">${ico('hard-drive-download','sm')}</span><div><b>${p.lastExport ? `Last backup was ${days} days ago.` : 'You have not exported a backup yet.'}</b> Your ${own} records and notes live only in this browser — clearing site data or a new device loses them.</div>
    <div class="acts"><button class="btn xs primary" data-act="exportAll">${ico('download','sm')}Export now</button><button class="btn xs ghost" data-act="bkpLater">Remind me in a week</button></div></div>`;
}

/* ---------- attachments ---------- */
const FILE_URLS = new Map();
async function sha256Hex(buf){ const h = await crypto.subtle.digest('SHA-256', buf); return [...new Uint8Array(h)].map(x => x.toString(16).padStart(2, '0')).join(''); }
async function storeFile(f){
  if(!STORE.idb) throw new Error('idb');
  if(f.size > 50 * 1048576) throw new Error('big');
  const buf = await f.arrayBuffer(), sha = await sha256Hex(buf), id = uid('f');
  if(!await IDB.set('file:' + id, new Blob([buf], {type:f.type || 'application/octet-stream'}))) throw new Error('idb');
  return {id, name:f.name || 'pasted-image.png', type:f.type || '', size:f.size, sha256:sha, modified:f.lastModified || Date.now(), added:Date.now()};
}
async function fileBlob(fid){ return await IDB.get('file:' + fid); }
async function fileURL(fid){ if(FILE_URLS.has(fid)) return FILE_URLS.get(fid); const b = await fileBlob(fid); if(!b) return null; const u = URL.createObjectURL(b); FILE_URLS.set(fid, u); return u; }
function hydrateThumbs(root){ (root || document).querySelectorAll('img[data-fid]:not([src])').forEach(async im => { const u = await fileURL(im.dataset.fid); if(u) im.src = u; else im.replaceWith(Object.assign(document.createElement('span'), {className:'t3', textContent:'File missing from this browser'})); }); }
new MutationObserver(() => { if(document.querySelector('img[data-fid]:not([src])')) hydrateThumbs(); }).observe(document.documentElement, {childList:true, subtree:true});

async function attachFiles(files, recId){
  files = [...files].filter(f => f && f.size != null); if(!files.length) return;
  if(!STORE.idb) return toast('Attachments need IndexedDB, which this browser blocked');
  const made = [], metas = []; let skipped = 0;
  for(const f of files){ let m; try{ m = await storeFile(f); }catch(e){ skipped++; continue; } metas.push(m); }
  if(!metas.length) return toast(skipped ? 'Files over 50 MB are not stored' : 'Nothing attached');
  if(recId){ const r = recById(recId); r.att = (r.att || []).concat(metas); mutate('attached ' + metas.length + ' file(s)'); renderAll(); return toast(metas.length + ' file' + (metas.length > 1 ? 's' : '') + ' attached'); }
  for(const m of metas){ const img = /^image\//.test(m.type), body = `${img ? 'Screenshot' : 'File'}: ${m.name}\nType: ${m.type || 'unknown'}\nSize: ${m.size} bytes\nSHA-256: ${m.sha256}`;
    made.push({id:uid('r'), caseId:DB.active, type:'evidence', title:(img ? 'Screenshot: ' : 'File: ') + m.name, body, tsRaw:new Date(m.modified).toISOString(), tsZone:'explicit', ts:m.modified, source:'attachment', host:'', tags:[img ? 'screenshot' : 'file'], ents:E.extract(body).filter(e => e.k !== 'file'), answer:'', addedBy:'You', addedAt:Date.now(), hash:'', att:[m]}); }
  DB.records.push(...made); mutate('added ' + made.length + ' file record(s)'); await hashRecords(); closeDlg();
  UI.sel = {kind:'rec', id:made[0].id}; UI.inspOpen = true; UI.tlMode = 'events'; go(caseHash(DB.active, 'timeline'));
  toast(made.length + ' file' + (made.length > 1 ? 's' : '') + ' added as evidence' + (skipped ? ' · ' + skipped + ' skipped (over 50 MB)' : ''));
}
function attSection(r){
  const A = r.att || [];
  return `<div class="isec"><h4>Files <span class="t3">${A.length}</span></h4>
    ${A.map(a => `<div class="att">${/^image\//.test(a.type) ? `<button class="attimg" data-act="attOpen" data-id="${r.id}" data-v="${a.id}" aria-label="Open ${esc(a.name)}"><img data-fid="${a.id}" alt=""></button>` : ''}
      <div class="atth">${ico(/^image\//.test(a.type) ? 'image' : 'file','sm')}<b title="${esc(a.name)}">${esc(a.name)}</b><span class="t3">${fmtBytes(a.size)}</span></div>
      <div class="mono atts" title="SHA-256 of the stored bytes">sha256 ${esc(a.sha256.slice(0, 32))}…</div>
      <div class="wrap"><button class="btn xs" data-act="attOpen" data-id="${r.id}" data-v="${a.id}">${ico('arrow-up-right','sm')}Open</button><button class="btn xs" data-act="attDl" data-id="${r.id}" data-v="${a.id}">${ico('download','sm')}Save</button>
        <button class="btn xs" data-act="attKit" data-id="${r.id}" data-v="${a.id}">${ico('file-search','sm')}Inspect</button><button class="iconbtn" data-act="attDel" data-id="${r.id}" data-v="${a.id}" aria-label="Remove file" title="Remove file">${ico('x','sm')}</button></div></div>`).join('')}
    <button class="btn sm" data-act="attAdd" data-id="${r.id}">${ico('paperclip','sm')}Attach file or screenshot</button></div>`;
}
function pickFiles(accept, cb, multi = true){ const i = document.createElement('input'); i.type = 'file'; i.accept = accept || ''; i.multiple = multi; i.onchange = () => { if(i.files && i.files.length) cb([...i.files]); }; i.click(); }
async function attAct(a, rid, fid){
  const r = recById(rid), m = r && (r.att || []).find(x => x.id === fid);
  if(a === 'attAdd') return pickFiles('', fs => attachFiles(fs, rid));
  if(!m) return;
  if(a === 'attOpen'){ const u = await fileURL(fid); return u ? window.open(u, '_blank', 'noopener') : toast('That file is missing from this browser'); }
  if(a === 'attDl'){ const b = await fileBlob(fid); if(!b) return toast('That file is missing from this browser'); const u = URL.createObjectURL(b), l = document.createElement('a'); l.href = u; l.download = m.name; document.body.appendChild(l); l.click(); setTimeout(() => { URL.revokeObjectURL(u); l.remove(); }, 200); return; }
  if(a === 'attKit'){ const b = await fileBlob(fid); if(!b) return toast('That file is missing from this browser'); go('#/lab'); UI.labTab = 'file'; return labLoad(new File([b], m.name, {type:m.type, lastModified:m.modified})); }
  if(a === 'attDel') return confirmDlg('Remove ' + m.name + '?', 'The file is removed from this record and deleted from the browser. The record stays.', 'Remove file', () => { r.att = r.att.filter(x => x !== m); if(!fileInUse(fid) && !(DB.trash || []).some(x => filesOfItem(x).includes(fid))) IDB.del('file:' + fid); mutate('removed file ' + m.name); renderAll(); });
}
/* backups carry files as data URLs */
async function filesForExport(recs){
  const out = {}; const ids = [...new Set(recs.flatMap(r => (r.att || []).map(a => a.id)))];
  for(const fid of ids){ const b = await fileBlob(fid); if(!b) continue; out[fid] = await new Promise(res => { const fr = new FileReader(); fr.onload = () => res(fr.result); fr.onerror = () => res(null); fr.readAsDataURL(b); }); }
  return out;
}
async function filesFromImport(files){ let n = 0; for(const [fid, url] of Object.entries(files || {})){ if(typeof url !== 'string' || !url.startsWith('data:')) continue; try{ const b = await (await fetch(url)).blob(); if(await IDB.set('file:' + fid, b)) n++; }catch(e){} } return n; }
async function exportEverything(){
  const all = DB.records.concat((DB.trash || []).flatMap(x => x.kind === 'record' ? [x.data.r] : x.kind === 'case' ? x.data.records : []));
  const files = await filesForExport(all), n = Object.keys(files).length;
  DB.prefs.lastExport = Date.now(); DB.prefs.remindAt = 0; save();
  download('osintrix-' + new Date().toISOString().slice(0, 10) + '.json', JSON.stringify(n ? Object.assign({}, DB, {files}) : DB, null, 2), 'application/json');
  if(UI.route.area === 'home') renderMain();
}

/* capture dialog: drop / paste files */
function bindCaptureFiles(){
  const d = $('dlg'); if(!d) return;
  d.ondragover = e => { if([...(e.dataTransfer.types || [])].includes('Files')){ e.preventDefault(); d.classList.add('dropping'); } };
  d.ondragleave = e => { if(e.target === d) d.classList.remove('dropping'); };
  d.ondrop = e => { if(!e.dataTransfer.files.length) return; e.preventDefault(); d.classList.remove('dropping'); const fs = [...e.dataTransfer.files];
    if(fs.length === 1 && /\.(csv|tsv|json|ndjson|jsonl|log|txt)$/i.test(fs[0].name) && !/^image\//.test(fs[0].type)) return logImportFile(fs[0]); attachFiles(fs); };
  d.onpaste = e => { const fs = [...(e.clipboardData && e.clipboardData.files || [])]; if(fs.length){ e.preventDefault(); attachFiles(fs.map((f, i) => f.name && f.name !== 'image.png' ? f : new File([f], 'screenshot-' + new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-') + (i ? '-' + i : '') + '.png', {type:f.type}))); } };
}

/* ---------- bulk log import ---------- */
function csvParse(text, delim){
  const rows = []; let row = [], f = '', q = false, i = 0;
  while(i < text.length){ const ch = text[i];
    if(q){ if(ch === '"'){ if(text[i + 1] === '"'){ f += '"'; i += 2; continue; } q = false; i++; continue; } f += ch; i++; continue; }
    if(ch === '"' && f === ''){ q = true; i++; continue; }
    if(ch === delim){ row.push(f); f = ''; i++; continue; }
    if(ch === '\n' || ch === '\r'){ row.push(f); f = ''; if(row.some(x => x !== '')) rows.push(row); row = []; if(ch === '\r' && text[i + 1] === '\n') i++; i++; continue; }
    f += ch; i++; }
  row.push(f); if(row.some(x => x !== '')) rows.push(row); return rows;
}
function flatObj(o, p = '', out = {}){ for(const [k, v] of Object.entries(o || {})){ const key = p ? p + '.' + k : k; if(v && typeof v === 'object' && !Array.isArray(v) && Object.keys(out).length < 80) flatObj(v, key, out); else out[key] = Array.isArray(v) ? v.join(', ') : v == null ? '' : String(v); } return out; }
function logParse(text, name){
  text = text.replace(/^﻿/, ''); const t = text.trim();
  if(/^\[/.test(t)){ try{ const a = JSON.parse(t); if(Array.isArray(a)) return {fmt:'JSON array', rows:a.filter(x => x && typeof x === 'object').map(x => flatObj(x))}; }catch(e){} }
  if(/^\{/.test(t)){ const lines = t.split(/\r?\n/).filter(Boolean), rows = []; let bad = 0;
    for(const l of lines){ try{ rows.push(flatObj(JSON.parse(l))); }catch(e){ bad++; } }
    if(rows.length && bad < rows.length) return {fmt:'NDJSON', rows};
    try{ const o = JSON.parse(t); const arr = Object.values(o).find(Array.isArray); if(arr) return {fmt:'JSON', rows:arr.map(x => flatObj(x))}; }catch(e){} }
  const head = t.split(/\r?\n/)[0], cnt = c => head.split(c).length - 1, delim = [['\t', cnt('\t')], [',', cnt(',')], [';', cnt(';')], ['|', cnt('|')]].sort((a, b) => b[1] - a[1])[0];
  if(delim[1] >= 1){ const rs = csvParse(t, delim[0]); if(rs.length > 1){ const h = rs[0].map((x, i) => (x || 'col' + (i + 1)).trim()); return {fmt:(delim[0] === '\t' ? 'TSV' : 'CSV'), rows:rs.slice(1).map(r => Object.fromEntries(h.map((k, i) => [k, (r[i] || '').trim()])))}; } }
  return {fmt:'text lines', rows:t.split(/\r?\n/).filter(x => x.trim()).map(l => ({line:l}))};
}
const LOG_GUESS = {time:/^(@?timestamp|time|date|datetime|eventtime|_time|ts|utctime|created(_at)?|timecreated|event\.created|when)$/i, title:/^(message|msg|title|summary|description|event|action|name|_raw|line|commandline|query)$/i, host:/^(host|hostname|computer|computername|device|machine|host\.name|src_host|agent\.hostname)$/i, source:/^(source|sourcetype|provider|channel|log|logname|index|program|app)$/i};
function logGuess(cols, key){ return cols.find(c => LOG_GUESS[key].test(c)) || cols.find(c => LOG_GUESS[key].test(c.split('.').pop())) || ''; }
function logTime(raw){
  if(raw == null || raw === '') return null; const s = String(raw).trim();
  if(/^\d{10}(\.\d+)?$/.test(s)) return Math.round(parseFloat(s) * 1000); if(/^\d{13}$/.test(s)) return +s; if(/^\d{16}$/.test(s)) return Math.round(+s / 1000);
  const t = E.parseTime(s, tz()); return t == null || isNaN(t) ? (isNaN(Date.parse(s)) ? null : Date.parse(s)) : t;
}
let LOGIMP = null;
function logImportFile(f){
  if(f.size > 25 * 1048576) return toast('Log files over 25 MB are too big for one import — split it first');
  const fr = new FileReader(); fr.onload = () => { const P = logParse(String(fr.result), f.name); if(!P.rows.length) return toast('No rows found in that file');
    const cols = [...new Set(P.rows.slice(0, 200).flatMap(r => Object.keys(r)))];
    LOGIMP = {name:f.name, fmt:P.fmt, rows:P.rows, cols, map:{time:logGuess(cols, 'time'), title:logGuess(cols, 'title'), host:logGuess(cols, 'host'), source:logGuess(cols, 'source')}}; logImportDlg(); };
  fr.readAsText(f);
}
function logRec(row, M, name){
  const tsRaw = M.time ? row[M.time] : '', ts = logTime(tsRaw);
  const kv = Object.entries(row).filter(([k, v]) => v !== '' && k !== M.time).map(([k, v]) => { const key = k.replace(/\W+/g, '_'); v = String(v).replace(/\s*\n\s*/g, ' '); return key + '=' + (/[\s"]/.test(v) ? '"' + v.replace(/"/g, "'") + '"' : v); }).join(' ');
  const title = (M.title && row[M.title] ? String(row[M.title]) : kv).replace(/\s+/g, ' ').slice(0, 96) || 'Log row';
  const body = (row.line != null && Object.keys(row).length === 1) ? row.line : kv;
  return {id:uid('r'), caseId:DB.active, type:'evidence', title, body, tsRaw:tsRaw ? String(tsRaw) : '', tsZone:'explicit', ts, source:(M.source && row[M.source]) || 'import:' + name, host:(M.host && row[M.host]) || '', tags:['imported'], ents:E.extract(body), answer:'', addedBy:'You', addedAt:Date.now(), hash:''};
}
function logImportDlg(){
  const L = LOGIMP, sel = (k, lbl) => `<div class="field" style="margin:0"><label for="lm_${k}">${lbl}</label><select id="lm_${k}" data-lm="${k}"><option value="">—</option>${L.cols.map(c => `<option${L.map[k] === c ? ' selected' : ''}>${esc(c)}</option>`).join('')}</select></div>`;
  openDlg(dhead('Import log file') + `<div class="in"><p class="t2" style="margin:0 0 14px;font-size:14px"><b style="color:var(--text)">${esc(L.name)}</b> · ${esc(L.fmt)} · ${L.rows.length.toLocaleString()} rows · ${L.cols.length} columns. Each row becomes one evidence record in <b style="color:var(--text)">${esc(theCase().name)}</b>, with every column kept as <span class="mono">key=value</span> so detections can test it.</p>
    <div class="frow4">${sel('time', 'Time column')}${sel('title', 'Title column')}${sel('host', 'Host column')}${sel('source', 'Source column')}</div>
    <h4 class="caps" style="margin:18px 0 8px">Preview</h4><div id="lmPrev" class="lmprev"></div>
    ${L.rows.length > 5000 ? `<p class="note amber" style="margin-top:12px"><span class="ic">${ico('triangle-alert','sm')}</span><span>Only the first 5,000 rows are imported. Filter the file first for the rest.</span></p>` : ''}</div>
    <footer><button class="btn" data-act="dclose">Cancel</button><button class="btn primary" data-act="logGo">${ico('upload','sm')}Import ${Math.min(5000, L.rows.length).toLocaleString()} rows</button></footer>`, true, () => {
      const paint = () => { const rs = L.rows.slice(0, 5).map(r => logRec(r, L.map, L.name)); $('lmPrev').innerHTML = rs.map(r => `<div class="lmr"><span class="mono">${r.ts ? esc(E.fmtFull(r.ts, tz()).slice(0, 19)) : '<em class="t3">no time</em>'}</span><div><b>${esc(r.title)}</b><small>${esc([r.host, r.source].filter(Boolean).join(' · '))}${r.ents.length ? ' · ' + r.ents.length + ' entities' : ''}</small></div></div>`).join(''); };
      document.querySelectorAll('[data-lm]').forEach(s => s.onchange = () => { L.map[s.dataset.lm] = s.value; paint(); }); paint(); });
}
async function logGo(){
  const L = LOGIMP; if(!L) return; await snapshot('Before importing ' + L.name);
  const made = L.rows.slice(0, 5000).map(r => logRec(r, L.map, L.name)); DB.records.push(...made); LOGIMP = null; closeDlg();
  mutate('imported ' + made.length + ' log rows'); await hashRecords(); UI.tlMode = 'events'; go(caseHash(DB.active, 'timeline'));
  const ids = new Set(made.map(r => r.id)), timed = made.filter(r => r.ts).length;
  toast(`${made.length.toLocaleString()} rows imported${timed < made.length ? ' · ' + (made.length - timed) + ' without a time' : ''}`, 'Undo', () => { DB.records = DB.records.filter(r => !ids.has(r.id)); mutate('undid log import'); renderAll(); });
}

/* ---------- actions ---------- */
const SAFE_ACTS = {
  trRestore:id => trashRestore(id), trDel:id => trashDelete(id), trEmpty:() => trashEmpty(),
  snapNow:() => snapNow(), snapRestore:id => snapRestore(id), snapDl:id => snapDownload(id),
  bkpLater:() => { DB.prefs.remindAt = Date.now() + 7 * 864e5; save(); renderMain(); },
  recDel:id => delRecord(id),
  attAdd:(id, v, t) => attAct('attAdd', id, v), attOpen:(id, v) => attAct('attOpen', id, v), attDl:(id, v) => attAct('attDl', id, v), attKit:(id, v) => attAct('attKit', id, v), attDel:(id, v) => attAct('attDel', id, v),
  capFiles:() => pickFiles('', fs => attachFiles(fs)), capLog:() => pickFiles('.csv,.tsv,.json,.ndjson,.jsonl,.log,.txt', fs => logImportFile(fs[0]), false), logGo:() => logGo()
};
