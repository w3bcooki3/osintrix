/* Recent inputs: what you pasted or opened in a tool, kept in this browser so a refresh loses nothing.
   Text lives in the workspace (encrypted with it when encryption is on). Files go to IndexedDB under "wk:",
   sealed the same way as attachments. Every item can be reopened or deleted on its own. */
const RECENT_MAX = 15, RECENT_TEXT_MAX = 2 * 1048576, RECENT_FILE_MAX = 50 * 1048576;
const RECENT_TOOLS = {certs:['Certificates', 'shield-check'], cloudScan:['Cloud config scanner', 'cloud'], cloudLogs:['Cloud logs', 'cloud'], labFile:['Lab · file inspector', 'file-search'],
  pcap:['Lab · packet capture', 'network'], sqlite:['Lab · SQLite', 'database'], image:['Lab · image', 'image'], logParse:['Lab · log parser', 'scroll-text']};
const recentAll = () => (DB.recent = Array.isArray(DB.recent) ? DB.recent : []);
const recentOf = tool => recentAll().filter(x => x.tool === tool);
const recentLastMap = () => (DB.work && DB.work.last) || {};
const recentLast = tool => recentLastMap()[tool] || null;
const recentIsOpen = x => Object.values(recentLastMap()).includes(x.id);
const recentKey = (tool, mode) => tool + (mode ? ':' + mode : '');
function recentSetLast(tool, id){ DB.work = DB.work || {}; DB.work.last = DB.work.last || {}; if(id) DB.work.last[tool] = id; else delete DB.work.last[tool]; }
async function recentHash(data){ const b = typeof data === 'string' ? new TextEncoder().encode(data) : data; return sha256Hex(b.buffer ? b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) : b); }
/* Keep an input. data is text or bytes (Uint8Array / ArrayBuffer / Blob). Returns the item, or null when it could not be kept. */
async function recentAdd(tool, name, data, extra = {}){
  try{
    if(!DB || (typeof TABS !== 'undefined' && !TABS.writer)) return null;
    if(data instanceof Blob) data = new Uint8Array(await data.arrayBuffer());
    if(data instanceof ArrayBuffer) data = new Uint8Array(data);
    const isText = typeof data === 'string', size = isText ? new Blob([data]).size : data.byteLength;
    if(!size) return null;
    if(isText && size > RECENT_TEXT_MAX){ toast('Too large to keep after a refresh (over 2 MB of text)'); return null; }
    if(!isText && size > RECENT_FILE_MAX){ toast('Files over 50 MB are not kept after a refresh — open it again when you need it'); return null; }
    const sha = await recentHash(data), A = recentAll(), old = A.find(x => x.tool === tool && x.sha === sha && (x.mode || '') === (extra.mode || ''));
    if(old){ old.at = Date.now(); old.name = String(name || old.name).slice(0, 200); A.splice(A.indexOf(old), 1); A.unshift(old); recentSetLast(recentKey(tool, old.mode), old.id); save(); return old; }
    const it = {id:uid('wk'), tool, name:String(name || 'Pasted').slice(0, 200), mode:extra.mode || '', size, sha, at:Date.now(), kind:isText ? 'text' : 'file', type:String(extra.type || '').slice(0, 100)};
    if(isText) it.text = data;
    else { if(!STORE.idb) return null; if(typeof nbRoomFor === 'function' && !await nbRoomFor(size)) { toast('Browser storage is full — this file is not kept after a refresh'); return null; }
      if(!await IDB.set('wk:' + it.id, await sealBlob(new Blob([data], {type:it.type || 'application/octet-stream'})))) return null; }
    A.unshift(it); recentSetLast(recentKey(tool, it.mode), it.id);
    const mine = recentOf(tool); for(const x of mine.slice(RECENT_MAX)) recentDrop(x.id);
    save(); return it;
  }catch(e){ console.error(e); return null; }
}
/* the stored data: text, or a File for file items */
async function recentData(it){
  if(!it) return null; if(it.kind === 'text') return it.text;
  const b = await openBlob(await IDB.get('wk:' + it.id)); return b ? new File([b], it.name, {type:it.type || b.type || ''}) : null;
}
function recentDrop(id){ const A = recentAll(), i = A.findIndex(x => x.id === id); if(i < 0) return null; const [x] = A.splice(i, 1);
  if(x.kind === 'file') IDB.del('wk:' + x.id); x.wasOpen = recentIsOpen(x); for(const [k, v] of Object.entries(recentLastMap())) if(v === x.id) recentSetLast(k, null); return x; }
function recentClear(tool){ for(const x of tool ? recentOf(tool) : recentAll().slice()) recentDrop(x.id); save(); }
/* sizes, for Settings → Storage */
const recentBytes = () => recentAll().reduce((s, x) => s + (x.size || 0), 0);

/* ---------- the Recent window: open or delete each item ---------- */
const RECENT_OPEN = {};   // tool → async (item, data) => void, registered by each tool
function recentDlg(tool, extra){
  const all = tool === '*', L = all ? recentAll() : recentOf(tool), [title] = all ? ['Every tool'] : RECENT_TOOLS[tool] || [tool];
  const row = x => `<li class="rc-r"><span class="rc-ic">${ico(x.kind === 'file' ? 'file-digit' : 'file-text','sm')}</span>
      <button class="rc-o" data-act="rcOpen" data-id="${x.id}"><b>${esc(x.name)}</b><small>${all ? esc((RECENT_TOOLS[x.tool] || [x.tool])[0]) + ' · ' : ''}${x.mode ? esc(RC_MODE[x.mode] || x.mode) + ' · ' : ''}${esc(stoBytes(x.size))} · ${esc(E.fmtAgo(Math.max(0, Date.now() - x.at)))}${recentIsOpen(x) ? ' · open now' : ''}</small></button>
      <button class="iconbtn rc-d" data-act="rcDel" data-id="${x.id}" aria-label="Delete ${esc(x.name)}" title="Delete">${ico('trash-2','sm')}</button></li>`;
  openDlg(`<div class="rc"><header><h2 id="rcT">${ico('history','sm')}History</h2><span class="t3">${esc(title)}</span><span class="sp"></span><button class="iconbtn" data-act="dclose" aria-label="Close">${ico('x','sm')}</button></header>
    <section><h3>Recent in this browser<small>${L.length}</small></h3>
      ${L.length ? `<ul class="rc-l">${L.map(row).join('')}</ul>` : '<p class="rc-none">Nothing yet. What you paste or open here is kept, so a refresh does not lose it.</p>'}
      <p class="rc-note">${ico('lock','sm')}Kept only in this browser${typeof SEC !== 'undefined' && SEC.key ? ', encrypted with your passphrase' : ''}. Private keys are never kept.</p></section>
    ${extra || ''}
    <footer>${L.length ? `<button class="btn ghost dangerhov" data-act="rcClear" data-v="${tool}">${ico('trash-2','sm')}Delete all recent</button>` : ''}<span class="sp"></span><button class="btn" data-act="dclose">Done</button></footer></div>`);
  $('dlg').setAttribute('aria-labelledby', 'rcT'); UI.rcTool = tool; UI.rcExtra = extra;
}
const RC_MODE = {cmp:'Compare', ct:'Transparency log', csr:'Signing request'};
function recentRefresh(){ if(UI.rcTool && $('dlg') && $('dlg').querySelector('.rc')){ const t = UI.rcTool, ex = typeof UI.rcExtraFn === 'function' ? UI.rcExtraFn() : UI.rcExtra; recentDlg(t, ex); } }
async function recentOpen(id){
  const it = recentAll().find(x => x.id === id); if(!it) return;
  const data = await recentData(it); if(data == null) return toast('That item could not be read — it may have been removed from this browser');
  const fn = RECENT_OPEN[it.tool]; if(!fn) return;
  it.at = Date.now(); recentSetLast(recentKey(it.tool, it.mode), it.id); save(); closeDlg(); await fn(it, data);
}
/* reopen the last input of a tool after a refresh (once per page load) */
const RECENT_DONE = new Set();
async function recentRestore(tool){
  if(RECENT_DONE.has(tool)) return false; RECENT_DONE.add(tool); let n = 0;
  for(const [k, id] of Object.entries(recentLastMap())){ if(k !== tool && !k.startsWith(tool + ':')) continue;
    const it = recentAll().find(x => x.id === id); if(!it || !RECENT_OPEN[it.tool]) continue;
    const data = await recentData(it); if(data == null) continue;
    try{ await RECENT_OPEN[it.tool](it, data, true); n++; }catch(e){ console.error(e); } }
  return n > 0;
}
const RC_ACTS = {
  rcOpen:id => recentOpen(id),
  rcDel:id => { const x = recentDrop(id); if(!x) return; save(); recentRefresh(); if(typeof RECENT_AFTER_DEL[x.tool] === 'function') RECENT_AFTER_DEL[x.tool](x); if(typeof storageRefresh === 'function' && UI.route.area === 'settings') storageRefresh();
    toast('Deleted ' + x.name); },
  rcClear:(id, v) => confirmDlg(v === '*' ? 'Delete every recent tool input?' : 'Delete all recent ' + ((RECENT_TOOLS[v] || [v])[0]) + ' inputs?', 'They are removed from this browser. Anything you saved to a case stays.', 'Delete all', () => {
    const tools = v === '*' ? Object.keys(RECENT_TOOLS) : [v]; recentClear(v === '*' ? null : v); for(const t of tools){ const f = RECENT_AFTER_DEL[t]; if(typeof f === 'function') f(null); } if(typeof storageRefresh === 'function' && UI.route.area === 'settings') storageRefresh(); toast('Recent inputs deleted'); })
};
const RECENT_AFTER_DEL = {};   // tool → (item|null) => void: let a tool forget what was deleted

/* ---------- what you typed into a tool's input box survives a refresh ----------
   Decoder, Lab tools and the log parser keep their input in UI; it is mirrored into the workspace here. */
const WORK_KEYS = ['decIn', 'txOp', 'ctfFlag', 'ctfFlagFor', 'tsIn', 'hashIn', 'geoIn', 'emlIn', 'cidrIn', 'uaIn', 'macIn', 'genName', 'genNums', 'genDom', 'lpIn', 'sqlText', 'labTab', 'cloudTab'];
const WORK_TEXT_MAX = 1048576;
function workHydrate(){
  if(workHydrate.done || !DB) return; workHydrate.done = true;
  const I = (DB.work && DB.work.inputs) || {}; for(const k of WORK_KEYS) if(typeof I[k] === 'string') UI[k] = I[k];   // runs once, before the first page is drawn
}
function workSync(){
  if(!DB || !workHydrate.done || (typeof TABS !== 'undefined' && !TABS.writer)) return;
  DB.work = DB.work || {}; const I = DB.work.inputs = DB.work.inputs || {}; let ch = false;
  for(const k of WORK_KEYS){ const v = UI[k] == null ? '' : String(UI[k]); if(v.length > WORK_TEXT_MAX) continue; if((I[k] || '') !== v){ if(v) I[k] = v; else delete I[k]; ch = true; } }
  if(ch){ clearTimeout(workSync.t); workSync.t = setTimeout(save, 400); }
}
/* inputs whose tool debounces its own handler: take the value at once, so leaving the page right after typing loses nothing */
const WORK_IDS = {decIn:'decIn', lpIn:'lpIn', tsIn:'tsIn', hashIn:'hashIn', geoIn:'geoIn', emlIn:'emlIn', cidrIn:'cidrIn', uaIn:'uaIn', macIn:'macIn', genName:'genName', genNums:'genNums', genDom:'genDom', sqSql:'sqlText'};
document.addEventListener('input', ev => { const k = ev.target && WORK_IDS[ev.target.id]; if(k) UI[k] = ev.target.value; clearTimeout(workSync.i); workSync.i = setTimeout(workSync, 350); });
document.addEventListener('change', () => { clearTimeout(workSync.i); workSync.i = setTimeout(workSync, 350); });

/* ---------- Lab files ---------- */
const recentN = tool => typeof DB !== 'undefined' && DB ? recentOf(tool).length : 0;
function recentKeepFile(tool, f){ recentAdd(tool, f.name, f, {type:f.type}).then(it => { if(it) document.querySelectorAll(`[data-act=rcShow][data-v=${tool}] .crt-cnt`).forEach(b => b.textContent = recentN(tool)); }); }
const LAB_RECENT = {labFile:['file', f => labLoad(f, false), () => UI.labFile], pcap:['pcap', f => pcLoad(f, false), () => UI.pcap], sqlite:['sqlite', f => sqlLoad(f, false), () => UI.sql], image:['image', f => imgLoad(f, false), () => UI.img]};
for(const [tool, [tab, open, cur]] of Object.entries(LAB_RECENT)){
  RECENT_OPEN[tool] = async (it, file, restoring) => { if(!(file instanceof File)) return; if(!restoring){ UI.labTab = tab; if(UI.route.area !== 'lab') go('#/lab'); } await open(file); };
  RECENT_AFTER_DEL[tool] = x => { const clear = {labFile:'labClear', pcap:'pcClear', sqlite:'sqClear', image:'imgClear'}[tool];
    if((!x || x.wasOpen) && cur()) clickAct(clear); else if(UI.route.area === 'lab') document.querySelectorAll(`[data-act=rcShow][data-v=${tool}] .crt-cnt`).forEach(b => b.textContent = recentN(tool)); };
}
/* after a refresh, reopen the file the Lab tab had open */
function labRestore(){ const tab = UI.labTab || 'file'; for(const [tool, [t, , cur]] of Object.entries(LAB_RECENT)) if(t === tab && !cur()) recentRestore(tool); }
RC_ACTS.rcShow = (id, v) => recentDlg(v);
