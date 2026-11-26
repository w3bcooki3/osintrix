/* ==========================================================================
   Safety net & evidence files — trash bin, restore points, backup reminder,
   file / screenshot attachments (IndexedDB blobs), bulk log import.
   ========================================================================== */
IDB.del = k => new Promise(res => { if(!IDB.db) return res(false); try{ const tx = IDB.db.transaction('kv', 'readwrite'); tx.objectStore('kv').delete(k); tx.oncomplete = () => res(true); tx.onerror = tx.onabort = () => res(false); }catch(e){ res(false); } });
const ago = t => E.fmtAgo(Math.max(0, Date.now() - t));

/* ---------- trash ---------- */
const TRASH_DAYS = 30;
const TRASH_KIND = {pattern:['regex','Saved pattern'], case:['folder-open','Case'], entry:['layers','Vault entry'], record:['file-text','Evidence record'], note:['sticky-note','Note'], link:['waypoints','Relationship'], rule:['shield-check','Detection rule'], query:['search','Saved query'], hunt:['crosshair','Hunt'], playbook:['list-checks','Playbook'], tool:['wrench','Tool'], auto:['workflow','Automation']};
const trashUndo = x => { DB.trash = (DB.trash || []).filter(z => z !== x); };
function trashPut(kind, label, data, caseId){ DB.trash = DB.trash || []; const x = {id:uid('x'), kind, label:String(label || '').slice(0, 140), caseId:caseId || null, at:Date.now(), data}; DB.trash.unshift(x); return x; }
function trashPurge(){
  if(!DB.trash || !DB.trash.length) return; const cut = Date.now() - TRASH_DAYS * 864e5, old = DB.trash.filter(x => x.at < cut);
  if(!old.length) return; DB.trash = DB.trash.filter(x => x.at >= cut); for(const x of old) dropFilesOf(x); if(typeof TABS === 'undefined' || TABS.writer) save();
}
function filesOfItem(x){ const d = x.data || {}; const recs = x.kind === 'record' ? [d.r] : x.kind === 'case' ? d.records || [] : []; return recs.flatMap(r => (r && r.att) || []).map(a => a.id); }
function dropFilesOf(x){ for(const fid of filesOfItem(x)) if(!fileInUse(fid)) blobDel('file:' + fid); }
function fileInUse(fid){ return DB.records.some(r => (r.att || []).some(a => a.id === fid)); }
function trashRestore(id){
  const x = (DB.trash || []).find(z => z.id === id); if(!x) return; const d = x.data;
  /* what each kind must hold to come back; an item damaged in storage or in a backup is explained, not restored */
  const ob = v => v && typeof v === 'object' && !Array.isArray(v), hasId = v => ob(v) && typeof v.id === 'string' && v.id !== '';
  const SHAPE = {case:() => hasId(d.c), entry:() => hasId(d.e) && typeof d.e.type === 'string' && typeof TYPES !== 'undefined' && !!TYPES[d.e.type], record:() => hasId(d.r), note:() => hasId(d.n), rule:() => hasId(d.r), query:() => hasId(d.q),
    hunt:() => hasId(d.h), playbook:() => hasId(d.p), tool:() => hasId(d.t) && typeof d.t.url === 'string', auto:() => hasId(d.a), pattern:() => hasId(d.p) && typeof rxlClean === 'function' && !!rxlClean(d.p), link:() => ob(d.l) && typeof d.l.a === 'string' && typeof d.l.b === 'string'};
  if(!ob(d) || !SHAPE[x.kind]) return toast('That item cannot be restored'); if(!SHAPE[x.kind]()) return toast('That item is damaged and cannot be restored — you can delete it for good');
  if(x.kind === 'case') for(const k of ['entries', 'links', 'records', 'notes']) d[k] = Array.isArray(d[k]) ? d[k].filter(ob) : [];
  if(x.kind === 'entry' && typeof normEntry === 'function') normEntry(d.e); if(x.kind === 'record' && typeof normRecord === 'function') normRecord(d.r);
  if(x.kind === 'case' && typeof normEntry === 'function'){ d.entries.forEach(normEntry); d.records.forEach(normRecord); }
  const caseOk = cid => DB.cases.some(c => c.id === cid);
  switch(x.kind){
    case 'case': if(caseOk(d.c.id)) return toast('That case already exists');
      DB.cases.push(d.c); DB.entries.push(...d.entries); DB.links.push(...d.links); DB.records.push(...d.records); DB.notes = (DB.notes || []).concat(d.notes || []); break;
    case 'entry': { const e = d.e; if(!caseOk(e.caseId)) e.caseId = DB.active; DB.entries.push(e);
      /* a relationship whose other end is also in the trash waits with that entry, so restoring it later brings the link back */
      for(const l of d.links || []){ if(entryById(l.a) && entryById(l.b)){ if(!DB.links.some(z => z.id === l.id)) DB.links.push(l); continue; } trashKeepLink(l, x); } break; }
    case 'record': { const r = d.r; if(!caseOk(r.caseId)) r.caseId = DB.active; DB.records.push(r); break; }
    case 'note': DB.notes = DB.notes || []; DB.notes.push(d.n); break;
    case 'rule': if(DB.rules.some(z => z.id === d.r.id)) return toast('That rule is already back'); DB.rules.unshift(d.r); if(DB.deletedRules) DB.deletedRules = DB.deletedRules.filter(z => z !== d.r.id); break;
    case 'pattern': DB.rxlib = Array.isArray(DB.rxlib) ? DB.rxlib : []; if(!DB.rxlib.some(z => z.id === d.p.id)) DB.rxlib.unshift(rxlClean(d.p)); break;
    case 'query': DB.queries = DB.queries || []; if(!DB.queries.some(z => z.id === d.q.id)) DB.queries.push(d.q); break;
    case 'hunt': DB.hunts = Array.isArray(DB.hunts) ? DB.hunts : []; if(!DB.hunts.some(z => z.id === d.h.id)) DB.hunts.push(d.h); break;
    case 'playbook': if(!DB.playbooks.some(z => z.id === d.p.id)) DB.playbooks.push(d.p); if(DB.deletedPb) DB.deletedPb = DB.deletedPb.filter(z => z !== d.p.id); break;
    case 'tool': if(!DB.tools.some(z => z.id === d.t.id)) DB.tools.push(d.t); if(DB.deletedSeed) DB.deletedSeed = DB.deletedSeed.filter(u => u !== d.t.url); break;
    case 'auto': DB.autos = DB.autos || []; if(!DB.autos.some(z => z.id === d.a.id)) DB.autos.push(d.a); if(d.done){ DB.autoDone = DB.autoDone || {}; DB.autoDone[d.a.id] = d.done; } break;
    default: return toast('That item cannot be restored')
    case 'link': if(entryById(d.l.a) && entryById(d.l.b)) DB.links.push(d.l); else if(!trashKeepLink(d.l, x)) return toast('Both ends of that relationship are gone'); else { DB.trash = DB.trash.filter(z => z !== x); mutate('restored ' + x.label); renderAll(); return toast('That relationship comes back when its entry is restored from the trash'); } break;
  }
  DB.trash = DB.trash.filter(z => z !== x); mutate('restored ' + x.label); renderAll(); toast('Restored ' + x.label);
}
function trashKeepLink(l, except){ const ends = [l.a, l.b].filter(id => !entryById(id)); const t = (DB.trash || []).find(z => z !== except && z.kind === 'entry' && z.data && z.data.e && ends.includes(z.data.e.id));
  if(!t) return false; t.data.links = t.data.links || []; if(!t.data.links.some(z => z.id === l.id)) t.data.links.push(l); return true; }
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
let SNAPS = null, snapSkipWarned = false; const SNAP_MAX = 8;
let SNAPS_BAD = false;
/* the list of restore points; if it cannot be read (wrong key, damaged), it is rebuilt from the
   restore points themselves and nothing is pruned, so no restore point is lost to a bad index */
async function snapsLoad(){ if(SNAPS) return SNAPS; const raw = await IDB.get('osintrix-snaps'); let L = null;
  try{ L = raw ? JSON.parse(await openStr(raw)) : []; if(!Array.isArray(L)) throw 0; SNAPS_BAD = false; }catch(e){ L = null; }
  if(!L){ SNAPS_BAD = true; const keys = await IDB.keys(); L = keys.filter(k => typeof k === 'string' && /^osintrix-snap:\d+$/.test(k)).map(k => ({at:+k.slice(14), why:'Details could not be read', size:0})).sort((a, b) => b.at - a.at); }
  SNAPS = L; return SNAPS; }
/* everything a restore point needs that lives outside it: evidence files, notebook pictures, kept work files */
function refsOf(D){ const out = [], recs = (D.records || []).concat((D.trash || []).flatMap(x => x && x.kind === 'record' ? [x.data && x.data.r] : x && x.kind === 'case' ? (x.data && x.data.records) || [] : []));
  for(const r of recs) for(const a of (r && r.att) || []) if(a && a.id) out.push('file:' + a.id);
  for(const k of Object.keys((D.nb && D.nb.media) || {})) out.push('nbm:' + k);
  for(const x of D.recent || []) if(x && x.kind === 'file') out.push('wk:' + x.id);
  return out; }
let SNAP_REFS = null;
async function snapRefs(){ await snapsLoad(); const sig = SNAPS.map(s => s.at).join(',');
  if(SNAP_REFS && SNAP_REFS.sig === sig) return SNAP_REFS.set; const set = new Set();
  for(const s of SNAPS){ if(Array.isArray(s.refs)){ s.refs.forEach(k => set.add(k)); continue; }
    try{ const d = JSON.parse(await openStr(await IDB.get('osintrix-snap:' + s.at))); refsOf(d).forEach(k => set.add(k)); }catch(e){ SNAP_REFS = null; return null; } }   // unreadable: say so, so nothing is deleted
  SNAP_REFS = {sig, set}; return set; }
/* delete a stored file only if no restore point still needs it */
async function blobDel(k){ const base = k.replace(/\.p$/, ''), R = await snapRefs(); if(!R || R.has(base)) return false;
  if(k.startsWith('file:') && base === k){ IDB.del(k + '.p'); if(typeof previewForget === 'function') previewForget(k.slice(5)); }   // its preview goes with it
  return IDB.del(k); }
/* restore points are made one at a time, so two at once cannot overwrite each other's list */
let SNAP_Q = Promise.resolve();
function snapshot(why){ const run = SNAP_Q.then(() => snapshot0(why)); SNAP_Q = run.catch(() => false); return run; }
async function snapshot0(why){
  if(!STORE.idb) return false; await snapsLoad(); if(typeof ctiLoad === 'function') await ctiLoad();
  const at = Date.now(), json = JSON.stringify(Object.assign({}, DB, typeof CTI !== 'undefined' && CTI.iocs ? {ctiIocs:CTI.iocs} : {}));   // the indicator store goes back with it
  /* a restore point is a whole copy: it must never be what fills the browser. Make room by dropping the oldest ones; if there is still none, skip it and say so */
  if(typeof stoRoom === 'function' && !await stoRoom(json.length * 2)){
    while(SNAPS.length && !SNAPS_BAD){ const o = SNAPS.pop(); await IDB.del('osintrix-snap:' + o.at); await IDB.set('osintrix-snaps', await sealStr(JSON.stringify(SNAPS))); if(await stoRoom(json.length * 2)) break; }
    if(!await stoRoom(json.length * 2)){ if(!snapSkipWarned){ snapSkipWarned = true; toast('No restore point was made — not enough space in this browser. Save a case snapshot to your computer instead.', 'Manage storage', () => go('#/settings')); } return false; } }
  if(!await IDB.set('osintrix-snap:' + at, await sealStr(json))) return false;
  SNAPS.unshift({at, why, size:json.length, cases:DB.cases.length, records:DB.records.length, refs:refsOf(DB)});
  if(!SNAPS_BAD) while(SNAPS.length > SNAP_MAX){ const o = SNAPS.pop(); IDB.del('osintrix-snap:' + o.at); }
  await IDB.set('osintrix-snaps', await sealStr(JSON.stringify(SNAPS))); return true;
}
async function snapRestore(at){
  const s = (SNAPS || []).find(x => x.at === +at); if(!s) return;
  confirmDlg('Go back to this restore point?', `Everything in this browser returns to how it was ${E.fmtFull(s.at, tz()).slice(0, 16)} (${s.why}). A restore point of the current state is made first, so you can come back.`, 'Restore', async () => {
    const raw = await IDB.get('osintrix-snap:' + s.at); let d = null; try{ d = JSON.parse(await openStr(raw)); }catch(e){}
    if(!d || !Array.isArray(d.cases)) return toast('That restore point could not be read');
    await snapshot('Before restoring a restore point'); const iocs = Array.isArray(d.ctiIocs) ? d.ctiIocs : null; delete d.ctiIocs;
    if(iocs && typeof CTI !== 'undefined'){ await ctiLoad(); CTI.iocs = iocs; ctiIocIndex(); await ctiSaveIocs(); }
    const prefs = DB.prefs; DB = d; DB.prefs = Object.assign({}, d.prefs, {lastExport:prefs.lastExport, remindAt:prefs.remindAt});
    ensureTools(); ensurePlaybooks(); ensureIntel(); ensureQueries(); ensureRules(); ensureNotes(); if(!DB.cases.some(c => c.id === DB.active)) DB.active = DB.cases[0].id;
    UI.sel = null; mutate('restored restore point'); applyPrefs(); renderAll(); toast('Restored');
  }, true);
}
async function snapDownload(at){ const raw = await IDB.get('osintrix-snap:' + at); if(!raw) return; let d; try{ d = JSON.parse(await openStr(raw)); }catch(e){ return toast('That restore point could not be read'); }
  /* the copy kept in the browser is complete; the downloaded one has no keys, tokens or signing key */
  const obj = stripSecrets(d), name = 'osintrix-restore-point-' + new Date(+at).toISOString().slice(0, 16).replace(/[:T]/g, '-') + '.json';
  if(SEC.key) return downloadEncrypted(name, obj); download(name, JSON.stringify(obj), 'application/json'); }
async function snapNow(){ if(await snapshot('Made by hand')){ renderMain(); toast('Restore point saved'); } else toast('Restore points need IndexedDB, which this browser blocked'); }

function viewTrash(){
  if(!SNAPS){ snapsLoad().then(() => { if(UI.route.area === 'trash') renderMain(); }); }
  const T = DB.trash || [];
  const row = x => { const [ic, kl] = TRASH_KIND[x.kind] || ['file','Item'], c = x.caseId && theCase(x.caseId), left = Math.max(0, TRASH_DAYS - Math.floor((Date.now() - x.at) / 864e5)), nf = filesOfItem(x).length;
    return `<div class="binrow"><span class="binic">${ico(ic)}</span><div class="main2"><b>${esc(x.label || '(untitled)')}</b><small>${kl}${c && c.id ? ' · ' + esc(caseNm(c) || c.code) : ''}${nf ? ' · ' + nf + ' file' + (nf > 1 ? 's' : '') : ''} · deleted ${esc(ago(x.at))} · ${left} day${left === 1 ? '' : 's'} left</small></div>
      <button class="btn xs" data-act="trRestore" data-id="${x.id}">${ico('undo-2','sm')}Restore</button><button class="iconbtn" data-act="trDel" data-id="${x.id}" title="Delete forever" aria-label="Delete forever">${ico('trash-2','sm')}</button></div>`; };
  const S2 = SNAPS || [];
  return `<div class="scroll"><div class="page narrow"><div class="ph"><div><h1>Trash &amp; restore points</h1><div class="sub">Deleted items wait here for ${TRASH_DAYS} days. Restore points are full copies of your workspace made before big changes.</div></div></div>
    <section class="card" style="margin-bottom:18px"><header><h3>Trash <span class="t3">${T.length}</span></h3>${T.length ? `<button class="btn xs danger" data-act="trEmpty">${ico('trash-2','sm')}Empty trash</button>` : ''}</header>
      <div class="body flush">${T.length ? T.map(row).join('') : `<p class="t3" style="padding:18px 20px;margin:0">Nothing in the trash. Deleted cases, vault entries, evidence, relationships, notes, rules, saved queries, hunts, playbooks, tools and automations land here.</p>`}</div></section>
    <section class="card"><header><h3>Restore points <span class="t3">${S2.length} of ${SNAP_MAX}</span></h3><button class="btn xs" data-act="snapNow">${ico('save','sm')}Make one now</button></header>
      <div class="body flush">${S2.length ? S2.map(s => `<div class="binrow"><span class="binic">${ico('history')}</span><div class="main2"><b>${esc(s.why)}</b><small>${esc(E.fmtFull(s.at, tz()).slice(0, 16))} · ${s.cases} cases · ${s.records} records · ${fmtBytes(s.size * 2)}</small></div>
        <button class="btn xs" data-act="snapRestore" data-id="${s.at}">${ico('undo-2','sm')}Restore</button><button class="iconbtn" data-act="snapDl" data-id="${s.at}" title="Download as a backup file" aria-label="Download">${ico('download','sm')}</button><button class="iconbtn" data-act="snapDel" data-id="${s.at}" title="Delete this restore point" aria-label="Delete this restore point">${ico('trash-2','sm')}</button></div>`).join('')
        : `<p class="t3" style="padding:18px 20px;margin:0">${STORE.idb ? 'None yet. One is made automatically before importing a backup, resetting, removing sample data, starting fresh or importing a log file.' : 'This browser blocked IndexedDB, so restore points are off. Export backups by hand instead.'}</p>`}</div></section>
    <p class="t3" style="font-size:calc(13px * var(--ts,1));margin-top:16px">Both live in this browser only. Clearing site data removes them too — keep an exported backup somewhere safe.</p></div></div>`;
}

/* ---------- backup reminder ---------- */
/* is a backup due? Own work only (not the demo), a week since the last export or folder backup */
function backupDue(){
  const p = DB.prefs; if(!p.firstUse){ p.firstUse = Date.now(); save(); }
  const own = DB.records.filter(r => !(theCase(r.caseId) || {}).sample).length + (DB.notes || []).filter(n => !n.sample).length + DB.entries.filter(e => !(theCase(e.caseId) || {}).sample).length;
  const fbLast = typeof fbOn === 'function' && fbOn() ? fbGet().last || 0 : 0, folder = typeof fbOn === 'function' && fbOn() ? FB.state : 'off';
  const last = Math.max(p.lastExport || 0, fbLast), days = Math.floor((Date.now() - (last || p.firstUse)) / 864e5);
  const due = own >= 3 && (folder === 'paused' || folder === 'missing' || days >= 7) && !(p.remindAt && p.remindAt > Date.now());
  return {due, days, own, last, folder};
}
function backupBanner(){
  const B = backupDue(); if(!B.due) return '';
  const fbOk = typeof fbSupported === 'function' && fbSupported();
  const head = B.folder === 'paused' ? 'Folder backup is paused.' : B.folder === 'missing' ? 'The backup folder can no longer be found.' : B.last ? `Last backup was ${B.days} day${B.days === 1 ? '' : 's'} ago.` : 'You have not backed up yet.';
  return `<div class="note amber bkp"><span class="ic">${ico('hard-drive-download','sm')}</span><div><b>${head}</b> Your ${B.own} records, entries and notes live only in this browser — clearing site data or a new device loses them.</div>
    <div class="acts">${B.folder === 'paused' ? `<button class="btn xs primary" data-act="fbResume">Resume</button>` : B.folder === 'missing' || (fbOk && B.folder === 'off') ? `<button class="btn xs primary" data-act="fbChoose">${ico('folder-open','sm')}Back up to a folder automatically</button><button class="btn xs" data-act="exportAll">Export now</button>` : `<button class="btn xs primary" data-act="exportAll">${ico('download','sm')}Export now</button>`}<button class="btn xs ghost" data-act="bkpLater">Remind me in 3 days</button></div></div>`;
}
/* the sidebar footer turns into a reminder when a backup is due */
function paintBackupFoot(){
  const f = document.querySelector('.sidefoot'); if(!f) return; const B = backupDue(), sp = f.querySelector('span'), was = f.classList.contains('due');
  if(B.due === was && f.dataset.d === String(B.days)) return; f.dataset.d = B.days; f.classList.toggle('due', B.due);
  sp.innerHTML = B.due ? `<button class="linkbtn" data-act="exportAll">${B.folder === 'paused' ? 'Folder backup paused' : 'Backup due' + (B.last ? ' · ' + B.days + ' days' : '')}</button>` : 'Offline · data stays in this browser';
}

/* ---------- attachments ---------- */
const FILE_URLS = new Map();
async function sha256Hex(buf){ const h = await crypto.subtle.digest('SHA-256', buf); return [...new Uint8Array(h)].map(x => x.toString(16).padStart(2, '0')).join(''); }
async function storeFile(f){
  if(!STORE.idb) throw new Error('idb');
  if(f.size > 50 * 1048576) throw new Error('big');
  const buf = await f.arrayBuffer(), sha = await sha256Hex(buf), type = f.type || 'application/octet-stream';
  /* the same bytes already in this browser are not stored a second time */
  const same = typeof fileBySha === 'function' ? fileBySha(sha) : null;
  if(same && await IDB.get('file:' + same.id)) return {...same, name:f.name || same.name, modified:f.lastModified || same.modified, added:Date.now()};
  if(typeof nbRoomFor === 'function' && !await nbRoomFor(f.size)) throw new Error('full');
  const id = uid('f'), blob = new Blob([buf], {type});
  if(!await IDB.set('file:' + id, await sealBlob(blob))) throw new Error('idb');
  let gps = null, cam = '', ex = null; if(/jpe?g|tiff|heic/i.test(f.type || f.name || '')){ try{ ex = exif(new Uint8Array(buf)); if(ex){ if(ex.GPS) gps = ex.GPS; cam = [ex.Make, ex.Model].filter(Boolean).join(' '); } }catch(e){} }
  const dhash = /^image\//.test(f.type || '') ? await dhashBlob(blob) : null;
  const psig = /^image\//.test(f.type || '') && typeof picSigBlob === 'function' ? await picSigBlob(blob) : null;
  /* picture size, length and a small preview for pictures, videos and audio */
  const kind = typeof mediaKind === 'function' ? mediaKind({type:f.type, name:f.name}) : '', P = kind === 'image' || kind === 'video' || kind === 'audio' ? await mediaProbe(blob, kind) : {};
  if(P.prev) await IDB.set('file:' + id + '.p', await sealBlob(P.prev));
  /* everything the file says about itself: camera, place, time, author, programs (HEIC, PNG, WebP, video, PDF, Office too) */
  let meta = null; if(typeof metaRead === 'function'){ try{ meta = metaKeep(await metaRead(new Uint8Array(buf), f.name || '', type)); }catch(e){} }
  if(meta && !gps && meta.gps) gps = {lat:meta.gps.lat, lon:meta.gps.lon, alt:meta.gps.alt};
  if(meta && !cam){ const v = k => (meta.fields.find(x => x.k === k) || {}).v || ''; cam = [v('Make'), v('Model')].filter(Boolean).join(' ').replace(/^(\w+) \1 /i, '$1 '); }
  const m = {id, name:f.name || 'pasted-image.png', type:f.type || '', size:f.size, sha256:sha, modified:f.lastModified || Date.now(), added:Date.now(), gps, cam, dhash};
  if(meta) m.meta = meta; if(psig) m.psig = psig;
  if(P.w){ m.w = P.w; m.h = P.h; } if(P.dur) m.dur = P.dur; if(kind === 'image' && typeof picMeta === 'function') m.x = picMeta(ex); return m;
}
async function fileBlob(fid){ return await openBlob(await IDB.get('file:' + fid)); }
async function fileURL(fid){ if(FILE_URLS.has(fid)) return FILE_URLS.get(fid); const b = await fileBlob(fid); if(!b) return null; const u = URL.createObjectURL(b); FILE_URLS.set(fid, u); return u; }
function hydrateThumbs(root){ (root || document).querySelectorAll('img[data-fid]:not([src])').forEach(async im => { const u = await fileURL(im.dataset.fid); if(u) im.src = u; else im.replaceWith(Object.assign(document.createElement('span'), {className:'t3', textContent:'File missing from this browser'})); }); }
new MutationObserver(() => { if(document.querySelector('img[data-fid]:not([src])')) hydrateThumbs(); }).observe(document.documentElement, {childList:true, subtree:true});

function fileRecord(m, cid){
  const k = typeof mediaKind === 'function' ? mediaKind(m) : /^image\//.test(m.type) ? 'image' : 'other';
  const what = k === 'image' ? (m.cam || m.gps ? 'Photo' : /png/i.test(m.type) ? 'Screenshot' : 'Image') : k === 'video' ? 'Video' : k === 'audio' ? 'Audio' : 'File';
  const body = `${what}: ${m.name}\nType: ${m.type || 'unknown'}\nSize: ${m.size} bytes${m.w ? '\nPicture size: ' + m.w + ' × ' + m.h : ''}${m.dur ? '\nLength: ' + fmtDur(m.dur) : ''}\nSHA-256: ${m.sha256}${m.cam ? '\nCamera: ' + m.cam : ''}${m.gps ? '\n' + (k === 'video' ? 'Video' : k === 'image' ? 'EXIF' : 'File') + ' GPS: ' + m.gps.lat.toFixed(6) + ', ' + m.gps.lon.toFixed(6) : ''}${m.meta && typeof metaLines === 'function' && metaLines(m.meta) ? '\nFile modified: ' + new Date(m.modified).toISOString() + '\n— Metadata —\n' + metaLines(m.meta) : ''}`;
  const made = m.meta && m.meta.taken != null && isFinite(m.meta.taken) ? m.meta.taken : null;
  return {id:uid('r'), caseId:cid, type:'evidence', title:what + ': ' + m.name, body, tsRaw:new Date(made ?? m.modified).toISOString(), tsZone:made != null && m.meta.tz === 'assumed' ? 'UTC' : 'explicit', ts:made ?? m.modified, source:'attachment', host:'', tags:[k === 'image' ? 'screenshot' : k === 'video' || k === 'audio' ? k : 'file'], ents:E.extract(body).filter(e => e.k !== 'file'), answer:'', addedBy:'You', addedAt:Date.now(), hash:'', att:[m]}; }
async function attachFiles(files, recId){
  files = [...files].filter(f => f && f.size != null); if(!files.length) return;
  if(!recId && typeof isChatExport === 'function'){ const chats = []; for(const f of files) if(await isChatExport(f)) chats.push(f); if(chats.length){ files = files.filter(f => !chats.includes(f)); await importChats(chats); if(!files.length) return; } }
  if(!recId){ const pages = files.filter(isWebPage); if(pages.length){ files = files.filter(f => !isWebPage(f)); await importWebPages(pages); if(!files.length) return; } }
  if(!STORE.idb) return toast('Attachments need IndexedDB, which this browser blocked');
  const made = [], metas = [], bigs = []; let skipped = 0;
  const t = files.length > 1 || files.some(f => f.size > 8e6) ? setTimeout(() => toast('Storing ' + files.length + ' file' + (files.length > 1 ? 's' : '') + '…'), 300) : 0;
  let full = false; for(const f of files){ let m; try{ m = await storeFile(f); }catch(e){ if(e.message === 'big' && !recId) bigs.push(f); else { skipped++; if(e.message === 'full') full = true; } continue; } metas.push(m); }
  clearTimeout(t);
  if(!metas.length && !bigs.length) return toast(full ? 'Browser storage is full — free space in Settings → Storage' : skipped ? 'Files over 50 MB are not stored' : 'Nothing attached');
  if(recId){ const r = recById(recId); r.att = (r.att || []).concat(metas); mutate('attached ' + metas.length + ' file(s)'); renderAll(); return toast(metas.length + ' file' + (metas.length > 1 ? 's' : '') + ' attached' + (skipped ? ' · ' + skipped + ' not stored' : '') + await roomNote()); }
  const cid = capCase();
  for(const m of metas) made.push(fileRecord(m, cid));
  for(const f of bigs) made.push(await bigFileRecord(f, cid));   // too big to keep: its fingerprint is recorded instead
  DB.records.push(...made); mutate('added ' + made.length + ' file record(s)'); await hashRecords(); closeDlg();
  afterCapture(cid, made.map(r => r.id)); watchNotify(made);
  if(UI.route.area === 'case' && UI.route.tab === 'media' && DB.active === cid) renderAll();   // adding from the Media tab stays there
  else { UI.sel = {kind:'rec', id:made[0].id}; UI.inspOpen = true; UI.tlMode = 'events'; go(caseHash(cid, 'timeline')); }
  toast((metas.length ? metas.length + ' file' + (metas.length === 1 ? '' : 's') + ' added as evidence' : '') + (bigs.length ? (metas.length ? ' · ' : '') + bigs.length + ' file' + (bigs.length > 1 ? 's' : '') + ' too big to store — fingerprint recorded' : '') + (skipped ? ' · ' + skipped + ' not stored' : '') + await roomNote());
}
function attSection(r){
  const A = r.att || [];
  return `<div class="isec"><h4>Files <span class="t3">${A.length}</span></h4>
    ${A.map(a => { const k = typeof mediaKind === 'function' ? mediaKind(a) : ''; return `<div class="att">${k === 'image' || k === 'video' ? `<button class="attimg" data-act="attOpen" data-id="${r.id}" data-v="${a.id}" aria-label="Open ${esc(a.name)}"><img data-pid="${a.id}" data-pk="${k}" alt="">${k === 'video' ? `<span class="md-play">${ico('play','sm')}</span>` : ''}</button>` : ''}
      <div class="atth">${ico(typeof MEDIA_ICON !== 'undefined' ? MEDIA_ICON[k] || 'file' : 'file','sm')}<b title="${esc(a.name)}">${esc(a.name)}</b><span class="t3">${fmtBytes(a.size)}</span></div>
      <div class="mono atts" title="SHA-256 of the stored bytes">sha256 ${esc(a.sha256.slice(0, 32))}…</div>
      <div class="wrap"><button class="btn xs" data-act="attOpen" data-id="${r.id}" data-v="${a.id}">${ico('arrow-up-right','sm')}Open</button><button class="btn xs" data-act="attDl" data-id="${r.id}" data-v="${a.id}">${ico('download','sm')}Save</button>
        <button class="btn xs" data-act="attKit" data-id="${r.id}" data-v="${a.id}">${ico('file-search','sm')}Inspect</button><button class="iconbtn" data-act="attDel" data-id="${r.id}" data-v="${a.id}" aria-label="Remove file" title="Remove file">${ico('x','sm')}</button></div></div>`; }).join('')}
    <button class="btn sm" data-act="attAdd" data-id="${r.id}">${ico('paperclip','sm')}Attach file or screenshot</button></div>`;
}
function pickFiles(accept, cb, multi = true){ const i = document.createElement('input'); i.type = 'file'; i.accept = accept || ''; i.multiple = multi; i.onchange = () => { if(i.files && i.files.length) cb([...i.files]); }; i.click(); }
async function attAct(a, rid, fid){
  const r = recById(rid), m = r && (r.att || []).find(x => x.id === fid);
  if(a === 'attAdd') return pickFiles('', fs => attachFiles(fs, rid));
  if(!m) return;
  if(a === 'attOpen'){ if(typeof mediaKind === 'function' && /^(video|audio)$/.test(mediaKind(m))) return mediaOpen(rid, fid);
    if(/html|xml|svg|mhtml|multipart|message\/rfc822|^image\//i.test(m.type) || /\.(html?|xhtml|svg|xml|mhtml?|mht)$/i.test(m.name)) return safeView(rid, fid);
    // open by what the bytes are, never by the type the file claimed: markup goes to the sandbox, the rest opens with a fixed safe type
    const b = await fileBlob(fid); if(!b) return toast('That file is missing from this browser');
    const kind = await sniffKind(b);
    if(kind === 'markup' || kind === 'image') return safeView(rid, fid);
    if(kind === 'binary') return attAct('attDl', rid, fid);
    const u = URL.createObjectURL(new Blob([b], {type:kind === 'pdf' ? 'application/pdf' : 'text/plain;charset=utf-8'})); window.open(u, '_blank', 'noopener'); setTimeout(() => URL.revokeObjectURL(u), 60000); return; }
  if(a === 'attDl'){ const b = await fileBlob(fid); if(!b) return toast('That file is missing from this browser'); const u = URL.createObjectURL(b), l = document.createElement('a'); l.href = u; l.download = safeName(m.name, 'file'); document.body.appendChild(l); l.click(); setTimeout(() => { URL.revokeObjectURL(u); l.remove(); }, 200); return; }
  if(a === 'attKit'){ const b = await fileBlob(fid); if(!b) return toast('That file is missing from this browser'); go('#/lab'); UI.labTab = 'file'; return labLoad(new File([b], m.name, {type:m.type, lastModified:m.modified}), false); }
  if(a === 'attDel') return confirmDlg('Remove ' + m.name + '?', 'The file is removed from this record and deleted from the browser once no restore point needs it. The record stays.', 'Remove file', () => { const at = r.att.indexOf(m); r.att = r.att.filter(x => x !== m); mutate('removed file ' + m.name); renderAll();
    /* the file itself goes once Undo has had its chance */
    const gone = setTimeout(() => { if(!(r.att || []).includes(m) && !fileInUse(fid) && !(DB.trash || []).some(x => filesOfItem(x).includes(fid))) blobDel('file:' + fid); }, 8000);
    toast('Removed ' + m.name, 'Undo', () => { clearTimeout(gone); r.att.splice(Math.max(0, at), 0, m); mutate('put back file ' + m.name); renderAll(); }); });
}
/* backups carry files as data URLs */
async function filesForExport(recs){
  const out = {}; const ids = [...new Set(recs.flatMap(r => (r.att || []).map(a => a.id)))];
  for(const fid of ids){ const b = await fileBlob(fid); if(!b) continue; out[fid] = await new Promise(res => { const fr = new FileReader(); fr.onload = () => res(fr.result); fr.onerror = () => res(null); fr.readAsDataURL(b); }); }
  return out;
}
async function filesFromImport(files){ let n = 0; for(const [fid, url] of Object.entries(files || {})){ if(typeof url !== 'string' || !url.startsWith('data:')) continue; try{ const m = url.match(/^data:([^;,]*)(;base64)?,(.*)$/); const bytes = m[2] ? b64d8(m[3]) : new TextEncoder().encode(decodeURIComponent(m[3])); if(await IDB.set('file:' + fid, await sealBlob(new Blob([bytes], {type:m[1] || 'application/octet-stream'})))) n++; }catch(e){} } return n; }
/* everything in one object: the workspace plus attached files and notebook media as data URLs */
async function backupObject(opt = {}){
  const all = DB.records.concat((DB.trash || []).flatMap(x => x.kind === 'record' ? [x.data.r] : x.kind === 'case' ? x.data.records : []));
  const files = opt.noFiles ? {} : await filesForExport(all), nbfiles = !opt.noFiles && typeof nbBackupFiles === 'function' ? await nbBackupFiles() : {}, n = Object.keys(files).length;
  // recent tool inputs belong to this browser: they are not part of a backup
  // threat intel: the indicator store goes with the backup; feed API keys never do
  if(typeof ctiLoad === 'function') await ctiLoad();
  const intel = DB.intel ? Object.assign({}, DB.intel, {sources:(DB.intel.sources || []).map(s => Object.assign({}, s, {key:''})), look:DB.intel.look ? {on:DB.intel.look.on || {}, keys:{}, relay:{url:(DB.intel.look.relay || {}).url || '', token:''}} : undefined}) : undefined, ctiIocs = typeof CTI !== 'undefined' && CTI.iocs && CTI.iocs.length ? CTI.iocs : undefined;
  return Object.assign({}, DB, {recent:undefined, work:undefined, intel, ctiIocs}, opt.noFiles ? {filesLeftOut:true} : {}, n ? {files} : {}, Object.keys(nbfiles).length ? {nbfiles} : {}, DB.security && DB.security.sign ? {security:Object.assign({}, DB.security, {sign:{pub:DB.security.sign.pub, made:DB.security.sign.made}})} : {});   // the signing key's private half never goes into a backup
}
/* how big a backup is with and without its files (files grow by about a third as text) */
function backupSizes(){
  const all = DB.records.concat((DB.trash || []).flatMap(x => x.kind === 'record' ? [x.data.r] : x.kind === 'case' ? x.data.records || [] : [])), seen = new Set(); let files = 0, n = 0;
  for(const r of all) for(const a of (r && r.att) || []) if(!seen.has(a.id)){ seen.add(a.id); files += +a.size || 0; n++; }
  for(const m of Object.values((DB.nb && DB.nb.media) || {})) if(!m.demo && !m.gone && !m.data){ files += +m.size || 0; n++; }
  let data = 0; try{ data = JSON.stringify(DB).length; }catch(e){}
  return {data, files, n, withFiles:data + Math.ceil(files * 4 / 3)};
}
function backupDlg(enc){
  const S = backupSizes(); if(!S.n) return exportEverything(enc);
  openDlg(dhead('Back up everything') + `<div class="in"><p class="t2" style="margin:0 0 14px">Your workspace has ${S.n.toLocaleString()} stored file${S.n > 1 ? 's' : ''} (pictures, videos, attachments, notebook media) taking ${fmtBytes(S.files)}.</p>
      <div class="su-cards"><button type="button" class="su-card" data-act="bkGo" data-v="files">${ico('images')}<b>With files <span class="chip sq green">complete</span></b><span>About ${fmtBytes(S.withFiles)}. Everything comes back on restore, on any computer.</span></button>
        <button type="button" class="su-card" data-act="bkGo" data-v="nofiles">${ico('file-text')}<b>Without files</b><span>About ${fmtBytes(S.data)}. Cases, notes and evidence text only; restored records say their files are missing. Good for frequent backups.</span></button></div></div>
    <footer><button class="btn" data-act="dclose">Cancel</button></footer>`);
  UI.bkEnc = enc;
}
async function exportEverything(enc, noFiles){
  if(enc == null) enc = !!SEC.key;
  const t = !noFiles ? setTimeout(() => toast('Preparing the backup…'), 300) : 0;
  const obj = await backupObject({noFiles:!!noFiles}); clearTimeout(t);
  DB.prefs.lastExport = Date.now(); DB.prefs.remindAt = 0; save();
  const name = 'osintrix-' + new Date().toISOString().slice(0, 10) + (noFiles ? '-no-files' : '') + '.json';
  if(enc) return downloadEncrypted(name, obj);
  download(name, JSON.stringify(obj, null, 2), 'application/json');
  if(UI.route.area === 'home') renderMain();
}

/* capture dialog: drop / paste files */
function bindCaptureFiles(){
  const d = $('dlg'); if(!d) return;
  d.ondragover = e => { if([...(e.dataTransfer.types || [])].includes('Files')){ e.preventDefault(); d.classList.add('dropping'); } };
  d.ondragleave = e => { if(e.target === d) d.classList.remove('dropping'); };
  d.ondrop = e => { if(!e.dataTransfer.files.length) return; e.preventDefault(); d.classList.remove('dropping'); const fs = [...e.dataTransfer.files];
    if(fs.length === 1 && /\.(pem|crt|cer|der|csr|req|p7b|p7c)$/i.test(fs[0].name)){ closeDlg(); return cxReadFile(fs[0]); }
    if(fs.length === 1 && /\.(csv|tsv|json|ndjson|jsonl|log|txt|evtx)$/i.test(fs[0].name) && !/^image\//.test(fs[0].type)) return logImportFile(fs[0]); attachFiles(fs); };
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
  const P = logParse0(text, name);
  /* a column holding a JSON object (Microsoft 365 exports keep the whole event in "AuditData"): its fields join the row */
  if(P.rows.length && /CSV|TSV/.test(P.fmt)){ const jc = Object.keys(P.rows[0]).filter(k => P.rows.slice(0, 20).some(r => /^\s*\{[\s\S]*\}\s*$/.test(r[k] || '')));
    if(jc.length){ for(const r of P.rows) for(const k of jc){ let o = null; try{ o = JSON.parse(r[k]); }catch(e){} if(o && typeof o === 'object' && !Array.isArray(o)){ const f = flatObj(o); for(const [a, v] of Object.entries(f)) if(r[a] == null || r[a] === '') r[a] = v; if(jc.length === 1) Object.defineProperty(r, '__raw', {value:JSON.stringify(o), enumerable:false}); delete r[k]; } } P.fmt += ' with JSON in ' + jc.join(', '); } }
  return P;
}
/* a JSON event: flat columns to map, and the event itself kept whole as the record's body (hidden key __raw) */
const logJRow = x => Object.defineProperty(flatObj(x), '__raw', {value:JSON.stringify(x), enumerable:false});
function logParse0(text, name){
  text = text.replace(/^\uFEFF/, ''); const t = text.trim();
  /* Windows Event Viewer "Save as XML": many <Event> elements in one file — one row each */
  if(/<Event[\s>]/.test(t) && /<\/Event>/.test(t)){ const ev = t.match(/<Event[\s>][\s\S]*?<\/Event>/g) || []; if(ev.length) return {fmt:'Windows event XML', rows:ev.slice(0, 200000).map(x => ({line:x.replace(/\s*\n\s*/g, ' ')}))}; }
  /* Zeek / Bro TSV logs: "#fields" names the columns, "-" is empty, "#path" says which log */
  if(/^#separator\b/m.test(t) || /^#fields\t/m.test(t)){ const lines = t.split(/\r?\n/), h = lines.find(l => /^#fields\t/.test(l)), path = ((lines.find(l => /^#path\t/.test(l)) || '').split('\t')[1] || '').trim();
    if(h){ const names = h.split('\t').slice(1); return {fmt:'Zeek ' + (path || 'log'), rows:lines.filter(l => l && !l.startsWith('#')).map(l => { const v = l.split('\t'), o = {}; names.forEach((n, i) => { if(v[i] != null && v[i] !== '-' && v[i] !== '(empty)') o[n] = v[i]; }); const raw = JSON.stringify(o); if(o.ts && /^\d+(\.\d+)?$/.test(o.ts)) o.ts = new Date(parseFloat(o.ts) * 1000).toISOString(); return Object.defineProperty(o, '__raw', {value:raw, enumerable:false}); })}; } }
  if(/^\[/.test(t)){ try{ const a = JSON.parse(t); if(Array.isArray(a)) return {fmt:'JSON array', rows:a.filter(x => x && typeof x === 'object').map(logJRow)}; }catch(e){} }
  if(/^\{/.test(t)){ const lines = t.split(/\r?\n/).filter(Boolean), rows = []; let bad = 0;
    for(const l of lines){ try{ const o = JSON.parse(l); if(o && typeof o === 'object') rows.push(logJRow(o)); else bad++; }catch(e){ bad++; } }
    if(rows.length && bad < rows.length) return {fmt:'NDJSON', rows};
    try{ const o = JSON.parse(t); const arr = Object.values(o).find(Array.isArray); if(arr) return {fmt:'JSON', rows:arr.filter(x => x && typeof x === 'object').map(logJRow)}; }catch(e){} }
  const head = t.split(/\r?\n/)[0], cnt = c => head.split(c).length - 1, delim = [['\t', cnt('\t')], [',', cnt(',')], [';', cnt(';')], ['|', cnt('|')]].sort((a, b) => b[1] - a[1])[0];
  if(delim[1] >= 1){ const rs = csvParse(t, delim[0]); if(rs.length > 1){ const h = rs[0].map((x, i) => (x || 'col' + (i + 1)).trim()); return {fmt:(delim[0] === '\t' ? 'TSV' : 'CSV'), rows:rs.slice(1).map(r => Object.fromEntries(h.map((k, i) => [k, (r[i] || '').trim()])))}; } }
  return {fmt:'text lines', rows:t.split(/\r?\n/).filter(x => x.trim()).map(l => ({line:l}))};
}
const LOG_GUESS = {time:/^(@?timestamp|time|date|datetime|eventtime|_time|ts|utctime|created(_at)?|timecreated|event\.created|when|published|creationtime|creationdate|eventtime)$/i, title:/^(message|msg|title|summary|description|event|action|name|_raw|line|commandline|query)$/i, host:/^(host|hostname|computer|computername|device|machine|host\.name|src_host|agent\.hostname)$/i, source:/^(source|sourcetype|provider|channel|log|logname|index|program|app)$/i};
function logGuess(cols, key){ return cols.find(c => LOG_GUESS[key].test(c)) || cols.find(c => LOG_GUESS[key].test(c.split('.').pop())) || ''; }
function logTime(raw){
  if(raw == null || raw === '') return null; const s = String(raw).trim();
  if(/^\d{10}(\.\d+)?$/.test(s)) return Math.round(parseFloat(s) * 1000); if(/^\d{13}$/.test(s)) return +s; if(/^\d{16}$/.test(s)) return Math.round(+s / 1000); if(/^\d{19}$/.test(s)) return Math.round(+s.slice(0, 13));
  const t = E.parseTime(s, tz()); return t == null || isNaN(t) ? (isNaN(Date.parse(s)) ? null : Date.parse(s)) : t;
}
let LOGIMP = null;
function logImportFile(f){
  if(/\.evtx$/i.test(f.name)) return evtxImportFile(f);
  if(f.size > 25 * 1048576) return toast('Log files over 25 MB are too big for one import — split it first');
  fileText(f).then(txt => { const P = logParse(txt, f.name); if(!P.rows.length) return toast('No rows found in that file');
    const cols = [...new Set(P.rows.slice(0, 200).flatMap(r => Object.keys(r)))];
    LOGIMP = {caseId:capCase(), name:f.name, fmt:P.fmt, rows:P.rows, cols, map:{time:logGuess(cols, 'time'), title:logGuess(cols, 'title'), host:logGuess(cols, 'host'), source:logGuess(cols, 'source')}}; logImportDlg(); }).catch(e => toast('Could not read ' + f.name + ': ' + e.message));
}
function logRec(row, M, name){
  let tsRaw = M.time ? row[M.time] : '', ts = logTime(tsRaw);
  /* no time column (one event per line, XML exports): read the time from the event itself */
  const own = row.__raw || (row.line != null ? String(row.line) : '');
  if(ts == null && own){ const P = parseLog(own.slice(0, 20000)); const raw = (P && P.norm.time) || (P && P.fields['TimeCreated.SystemTime']) || E.lineTime(own); if(raw){ const t = logTime(raw); if(t != null){ tsRaw = String(raw); ts = t; } } }
  const kv = Object.entries(row).filter(([k, v]) => v !== '' && k !== M.time && !k.startsWith('__')).map(([k, v]) => { const key = k.replace(/\W+/g, '_'); v = String(v).replace(/\s*\n\s*/g, ' '); return key + '=' + (/[\s"]/.test(v) ? '"' + v.replace(/"/g, "'") + '"' : v); }).join(' ');
  const body = row.__raw ? row.__raw : (row.line != null && Object.keys(row).length === 1) ? row.line : kv;
  const named = M.title && M.title !== 'line' && row[M.title] ? String(row[M.title]) : '';     // a whole line is not a title: summarise it
  const title = (named || parsedTitle(parseLog(body.length <= 20000 ? body : kv)) || (M.title && row[M.title] ? String(row[M.title]) : '') || kv).replace(/\s+/g, ' ').slice(0, 110) || 'Log row';
  return {id:uid('r'), caseId:(LOGIMP && LOGIMP.caseId) || DB.active, type:'evidence', title, body, tsRaw:tsRaw ? String(tsRaw) : '', tsZone:'explicit', ts, source:(M.source && row[M.source]) || 'import:' + name, host:(M.host && row[M.host]) || '', tags:['imported'], ents:extractRich(body), answer:'', addedBy:'You', addedAt:Date.now(), hash:'', pv:1};
}
function logImportDlg(){
  const L = LOGIMP, sel = (k, lbl) => `<div class="field" style="margin:0"><label for="lm_${k}">${lbl}</label><select id="lm_${k}" data-lm="${k}"><option value="">—</option>${L.cols.map(c => `<option${L.map[k] === c ? ' selected' : ''}>${esc(c)}</option>`).join('')}</select></div>`;
  openDlg(dhead(esc(L.title || 'Import log file')) + `<div class="in"><p class="t2" style="margin:0 0 14px;font-size:calc(14px * var(--ts,1))"><b style="color:var(--text)">${esc(L.name)}</b> · ${esc(L.fmt)} · ${L.rows.length.toLocaleString()} rows · ${L.cols.length} columns. Each row becomes one evidence record in <b style="color:var(--text)">${esc(theCase(L.caseId).name)}</b>, with every column kept as <span class="mono">key=value</span> so detections can test it.</p>
    <div class="frow4">${sel('time', 'Time column')}${sel('title', 'Title column')}${sel('host', 'Host column')}${sel('source', 'Source column')}</div>
    <h4 class="caps" style="margin:18px 0 8px">Preview</h4><div id="lmPrev" class="lmprev"></div>
    ${L.rows.length > 5000 ? `<p class="note amber" style="margin-top:12px"><span class="ic">${ico('triangle-alert','sm')}</span><span>Only the first 5,000 rows are imported. Filter the file first for the rest.</span></p>` : ''}</div>
    <footer><button class="btn" data-act="dclose">Cancel</button><button class="btn primary" data-act="logGo">${ico('upload','sm')}Import ${Math.min(5000, L.rows.length).toLocaleString()} rows</button></footer>`, true, () => {
      const paint = () => { const rs = L.rows.slice(0, 5).map(r => logRec(r, L.map, L.name)); $('lmPrev').innerHTML = rs.map(r => `<div class="lmr"><span class="mono">${r.ts ? esc(E.fmtFull(r.ts, tz()).slice(0, 19)) : '<em class="t3">no time</em>'}</span><div><b>${esc(r.title)}</b><small>${esc([r.host, r.source].filter(Boolean).join(' · '))}${r.ents.length ? ' · ' + r.ents.length + ' entities' : ''}</small></div></div>`).join(''); };
      document.querySelectorAll('[data-lm]').forEach(s => s.onchange = () => { L.map[s.dataset.lm] = s.value; paint(); }); paint(); });
}
async function logGo(){
  const L = LOGIMP; if(!L) return;
  if(!await stoGuard(JSON.stringify(L.rows.slice(0, 5000)).length * 3, 'import these rows')) return;
  await snapshot('Before importing ' + L.name);
  const made = L.rows.slice(0, 5000).map(r => logRec(r, L.map, L.name)); DB.records.push(...made); LOGIMP = null; closeDlg();
  mutate('imported ' + made.length + ' log rows'); await hashRecords(); afterCapture(L.caseId, made.map(r => r.id)); watchNotify(made); UI.tlMode = 'events'; go(caseHash(L.caseId, 'timeline'));
  const ids = new Set(made.map(r => r.id)), timed = made.filter(r => r.ts).length;
  toast(`${made.length.toLocaleString()} rows imported${timed < made.length ? ' · ' + (made.length - timed) + ' without a time' : ''}`, 'Undo', () => { DB.records = DB.records.filter(r => !ids.has(r.id)); mutate('undid log import'); renderAll(); });
}

/* ---------- actions ---------- */
const SAFE_ACTS = {
  trRestore:id => trashRestore(id), trDel:id => trashDelete(id), trEmpty:() => trashEmpty(),
  snapNow:() => snapNow(), snapRestore:id => snapRestore(id), snapDl:id => snapDownload(id),
  snapDel:id => confirmDlg('Delete this restore point?', 'It is removed from this browser and cannot be restored. Your workspace is not changed.', 'Delete', async () => { await snapsLoad(); const at = +id, i = SNAPS.findIndex(s => s.at === at); if(i < 0) return;
    SNAPS.splice(i, 1); await IDB.del('osintrix-snap:' + at); await IDB.set('osintrix-snaps', await sealStr(JSON.stringify(SNAPS))); renderMain(); toast('Restore point deleted'); }),
  bkpLater:() => { DB.prefs.remindAt = Date.now() + 3 * 864e5; save(); renderAll(); },
  recDel:id => delRecord(id),
  attAdd:(id, v, t) => attAct('attAdd', id, v), attOpen:(id, v) => attAct('attOpen', id, v), attDl:(id, v) => attAct('attDl', id, v), attKit:(id, v) => attAct('attKit', id, v), attDel:(id, v) => attAct('attDel', id, v),
  bkGo:(id, v) => { closeDlg(); exportEverything(UI.bkEnc, v === 'nofiles'); },
  evtxGo:() => evtxGo(), capFiles:() => pickFiles('', fs => attachFiles(fs)), capWeb:() => pickFiles('.mhtml,.mht,.html,.htm,.xhtml', fs => importWebPages(fs)), capLog:() => pickFiles('.evtx,.csv,.tsv,.json,.ndjson,.jsonl,.log,.txt', fs => logImportFile(fs[0]), false), logGo:() => logGo()
};

/* A backup may come from someone else. Whatever it says, this browser keeps its own lookup
   sources, API keys, relay and online-check settings — otherwise a crafted file could point
   the relay (and its token) elsewhere, or switch on automatic lookups. Histories that are
   drawn on screen are reduced to plain values. */
const IMP_BANDS = new Set(['malicious', 'suspicious', 'benign', 'clean', 'unknown']);
const impNum = (x, lo, hi) => { x = +x; return Number.isFinite(x) ? Math.max(lo, Math.min(hi, x)) : 0; };
const impStr = (x, n) => typeof x === 'string' ? x.slice(0, n) : '';
function importSafeIntel(prev){
  const pi = prev.intel || {}, pl = pi.look || {};
  DB.intel = DB.intel && typeof DB.intel === 'object' ? DB.intel : {};
  const meta = id => typeof CTI_SOURCES !== 'undefined' && CTI_SOURCES.find(m => m.id === id);
  DB.intel.sources = (Array.isArray(DB.intel.sources) ? DB.intel.sources : []).filter(s => s && typeof s.id === 'string' && meta(s.id)).map(s => { const o = (pi.sources || []).find(x => x.id === s.id) || {};
    return {id:s.id, on:!!o.on, key:o.key || '', status:impStr(o.status, 40), err:impStr(o.err, 200), last:impNum(s.last, 0, 9e15), n:impNum(s.n, 0, 1e9)}; });
  for(const o of pi.sources || []) if(o && meta(o.id) && !DB.intel.sources.some(s => s.id === o.id)) DB.intel.sources.push(o);
  DB.intel.look = {on:Object.assign({}, pl.on || {}), keys:Object.assign({}, pl.keys || {}), relay:Object.assign({url:'', token:''}, pl.relay || {})};
  DB.intel.lookHist = (Array.isArray(DB.intel.lookHist) ? DB.intel.lookHist : []).slice(0, 200).map(h => { const n = h && iocNorm(String(h.k === 'asn' ? h.v : h.v || '')) || (h && h.k === 'asn' && /^AS\d{1,10}$/.test(h.v) ? {k:'asn', v:h.v} : null);
    return n ? {k:n.k, v:n.v, at:impNum(h.at, 0, 9e15), band:IMP_BANDS.has(h.band) ? h.band : 'unknown', score:Math.round(impNum(h.score, 0, 100))} : null; }).filter(Boolean);
  if(DB.intel.cve && typeof DB.intel.cve === 'object') for(const c of Object.values(DB.intel.cve)){ if(!c || typeof c !== 'object') continue; c.cvss = Number.isFinite(+c.cvss) && c.cvss !== null && c.cvss !== '' ? impNum(c.cvss, 0, 10) : null; c.refs = (Array.isArray(c.refs) ? c.refs : []).map(u => E.safeUrl(String(u))).filter(Boolean).slice(0, 10); }
  DB.prefs = DB.prefs || {}; DB.prefs.watchEvery = (prev.prefs || {}).watchEvery || 0;
  for(const c of DB.cases || []){ const p = (prev.cases || []).find(x => x.id === c.id); c.autoLook = !!(p && p.autoLook); }
  const W = {}; for(const [k, w] of Object.entries(DB.watch && typeof DB.watch === 'object' ? DB.watch : {})){ if(typeof k !== 'string' || k.length > 600 || !w || typeof w !== 'object') continue;
    const s = w.snap && typeof w.snap === 'object' ? {band:IMP_BANDS.has(w.snap.band) ? w.snap.band : 'unknown', score:Math.round(impNum(w.snap.score, 0, 100)), ports:impStr(w.snap.ports, 2000), ips:impStr(w.snap.ips, 4000), ns:impStr(w.snap.ns, 2000), vt:impNum(w.snap.vt, 0, 999), abuse:impNum(w.snap.abuse, 0, 100), pulses:impNum(w.snap.pulses, 0, 1e6), malware:impStr(w.snap.malware, 1000)} : null;
    W[k] = {at:impNum(w.at, 0, 9e15), checked:impNum(w.checked, 0, 9e15), snap:s, unseen:!!w.unseen, alerts:(Array.isArray(w.alerts) ? w.alerts : []).slice(0, 20).map(a => ({at:impNum(a && a.at, 0, 9e15), d:(Array.isArray(a && a.d) ? a.d : []).slice(0, 20).map(x => ({hot:!!(x && x.hot), t:impStr(x && x.t, 300)}))}))};
    if(!W[k].snap) delete W[k].snap; }
  DB.watch = W;
}
/* the secrets a workspace holds, removed for anything that leaves the browser */
function stripSecrets(o){
  const x = Object.assign({}, o);
  if(x.intel) x.intel = Object.assign({}, x.intel, {sources:(x.intel.sources || []).map(s => Object.assign({}, s, {key:''})), look:x.intel.look ? {on:x.intel.look.on || {}, keys:{}, relay:{url:(x.intel.look.relay || {}).url || '', token:''}} : undefined});
  if(x.security && x.security.sign) x.security = Object.assign({}, x.security, {sign:{pub:x.security.sign.pub, made:x.security.sign.made}});
  return x;
}
