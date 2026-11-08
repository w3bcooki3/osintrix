/* ==========================================================================
   Automatic backup to a folder (Chrome and Edge: File System Access API).
   You pick a folder once — Documents, or a OneDrive / Google Drive folder —
   and the app writes osintrix-latest.json there a few minutes after changes,
   plus one dated copy per day (the last 7 are kept). Encrypted workspaces
   write encrypted backups, opened with the workspace passphrase.
   The folder handle and these settings belong to this browser, so they live
   in IndexedDB / localStorage, not in the workspace or its backups.
   ========================================================================== */
const FB_KEY = 'osintrix:fbak', FB_DIR = 'osintrix-fbak-dir', FB_DAY_RE = /^osintrix-\d{4}-\d{2}-\d{2}\.json$/;
const FB = {dir:null, state:'off', busy:false, t:null};
const fbSupported = () => typeof window.showDirectoryPicker === 'function';
const fbGet = () => { let p = {}; try{ p = JSON.parse(localStorage.getItem(FB_KEY) || '{}') || {}; }catch(e){} return Object.assign({on:false, every:10, keep:7, last:0, at:0, size:0, name:'', err:''}, p); };
const fbSet = p => { try{ localStorage.setItem(FB_KEY, JSON.stringify(p)); }catch(e){} };
const fbOn = () => fbGet().on;
const fbToday = () => { const d = new Date(); return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0'); };

async function fbPerm(ask){
  if(!FB.dir || !FB.dir.queryPermission) return false;
  try{ const o = {mode:'readwrite'}; if(await FB.dir.queryPermission(o) === 'granted') return true; return ask ? (await FB.dir.requestPermission(o)) === 'granted' : false; }catch(e){ return false; }
}
/* at start: find the folder again and check the browser still lets us write there */
async function fbInit(){
  if(!fbOn() || !fbSupported()) return;
  if(!FB.dir) FB.dir = await IDB.get(FB_DIR);
  if(!FB.dir){ FB.state = 'missing'; return; }
  FB.state = await fbPerm(false) ? 'on' : 'paused';
  if(FB.state === 'paused') toast('Folder backup is paused — the browser needs your OK to write to “' + fbGet().name + '” again', 'Resume', fbResume);
  else fbSchedule(true);
}
async function fbChoose(){
  if(!fbSupported()) return toast('This browser cannot write to folders — use Chrome or Edge, or Export everything');
  let dir; try{ dir = await window.showDirectoryPicker({id:'osintrix-backup', mode:'readwrite', startIn:'documents'}); }
  catch(e){ if(e && e.name !== 'AbortError') toast('Could not use that folder: ' + (e.message || e.name)); return; }
  FB.dir = dir; try{ await IDB.set(FB_DIR, dir); }catch(e){}
  const p = fbGet(); Object.assign(p, {on:true, name:dir.name || 'folder', err:''}); fbSet(p); FB.state = 'on';
  await fbRun(true); toast('Backing up to “' + p.name + '”');
}
async function fbResume(){
  if(!FB.dir) FB.dir = await IDB.get(FB_DIR);
  if(!FB.dir) return fbChoose();
  if(await fbPerm(true)){ FB.state = 'on'; await fbRun(true); toast('Folder backup resumed'); } else toast('The browser did not allow it — choose the folder again');
  storagePaint();
}
function fbOff(){ const p = fbGet(); p.on = false; fbSet(p); FB.state = 'off'; clearTimeout(FB.t); FB.dir = null; IDB.del(FB_DIR); storagePaint(); toast('Folder backup turned off — the files already there stay'); }

/* changed since the last backup? (DB.savedAt moves on every confirmed save) */
const fbStale = () => { const p = fbGet(); return (DB.savedAt || 0) > (p.at || 0) || !p.last; };
function fbSchedule(soon){
  clearTimeout(FB.t); if(!fbOn() || FB.state !== 'on' || !fbStale()) return;
  const p = fbGet(), wait = soon ? 3000 : Math.max(5000, (p.last || 0) + p.every * 60000 - Date.now());
  FB.t = setTimeout(() => fbRun(false), wait);
}
async function fbWrite(name, text){ const fh = await FB.dir.getFileHandle(name, {create:true}), w = await fh.createWritable(); await w.write(text); await w.close(); }   // written to a temporary file and swapped in on close
async function fbPrune(keep){
  const days = []; for await (const [name, h] of FB.dir.entries()) if(h.kind === 'file' && FB_DAY_RE.test(name)) days.push(name);
  days.sort().reverse(); for(const n of days.slice(keep)) try{ await FB.dir.removeEntry(n); }catch(e){}
}
async function fbRun(force){
  if(FB.busy || !FB.dir || !DB || SEC.locked) return;
  if(!force && !fbStale()) return;
  if(!await fbPerm(false)){ FB.state = 'paused'; storagePaint(); return; }
  FB.busy = true; storagePaint(); const p = fbGet();
  try{
    flush(); const at = DB.savedAt;
    let text = JSON.stringify(await backupObject());
    if(SEC.key) text = await sealWith(SEC.key, SEC.salt, SEC.iter, text, {format:'osintrix-encrypted', what:'backup'});   // opens with the workspace passphrase
    await fbWrite('osintrix-latest.json', text);
    await fbWrite('osintrix-' + fbToday() + '.json', text);   // today's copy is the last state of the day
    await fbPrune(p.keep);
    Object.assign(p, {last:Date.now(), at, size:text.length, err:''}); FB.state = 'on';
  }catch(e){
    if(e && e.name === 'NotAllowedError'){ FB.state = 'paused'; p.err = ''; }
    else p.err = e && (e.name === 'QuotaExceededError' ? 'The disk is full' : e.name === 'NotFoundError' ? 'The folder was moved or deleted — choose it again' : (e.message || e.name)) || 'Unknown error';
    if(e && e.name === 'NotFoundError') FB.state = 'missing';
  }finally{ fbSet(p); FB.busy = false; storagePaint(); if(typeof paintSaved === 'function') paintSaved(); }
}
/* every confirmed save schedules a backup; switching away from the tab writes one if it is due */
const _fbMarkSafe = markSafe;
markSafe = function(g){ _fbMarkSafe(g); if(fbOn() && FB.state === 'on' && !FB.busy) fbSchedule(false); };
document.addEventListener('visibilitychange', () => { if(document.visibilityState === 'hidden' && fbOn() && FB.state === 'on' && fbStale() && Date.now() - fbGet().last > 60000) fbRun(false); });

function fbHtml(){
  const p = fbGet(), ago2 = t => t ? ago(t) : 'never';
  if(!fbSupported()) return `<div class="fb"><h4>${ico('hard-drive-download','sm')}Automatic backup to a folder</h4><p class="t3">This browser cannot write to folders on your computer — Chrome and Edge can. Here, use <b>Export everything</b> regularly.</p></div>`;
  if(!p.on) return `<div class="fb"><h4>${ico('hard-drive-download','sm')}Automatic backup to a folder</h4>
    <p class="t3">Pick a folder once — Documents, or a OneDrive or Google Drive folder to also keep a copy in the cloud. A backup is written there a few minutes after you change something, with one dated copy per day (the last 7 are kept). If browser data is ever cleared, import <span class="mono">osintrix-latest.json</span>.</p>
    <button class="btn sm primary" data-act="fbChoose">${ico('folder-open','sm')}Choose a folder…</button></div>`;
  const st = FB.busy ? ['Backing up…', 'var(--text-3)'] : FB.state === 'paused' ? ['Paused', 'var(--amber)'] : FB.state === 'missing' ? ['Folder not found', 'var(--red)'] : p.err ? ['Last backup failed', 'var(--red)'] : ['On', 'var(--green)'];
  return `<div class="fb"><h4>${ico('hard-drive-download','sm')}Automatic backup to a folder<span class="fb-st"><i style="background:${st[1]}"></i>${st[0]}</span></h4>
    <p class="fb-d">Writing to <b>${esc(p.name)}</b> · last backup ${esc(ago2(p.last))}${p.size ? ' · ' + stoBytes(p.size) : ''}${SEC.key ? ' · encrypted with your workspace passphrase' : ''}</p>
    ${FB.state === 'paused' ? `<p class="sto-warn">The browser needs your OK again before writing to this folder (it asks after a restart unless you choose “Allow on every visit”).</p>` : ''}
    ${FB.state === 'missing' ? `<p class="sto-warn">The folder was moved, renamed or deleted. Choose it again.</p>` : ''}
    ${p.err && FB.state === 'on' ? `<p class="sto-warn">${esc(p.err)}</p>` : ''}
    <div class="wrap fb-a">${FB.state === 'paused' ? `<button class="btn sm primary" data-act="fbResume">${ico('play','sm')}Resume</button>` : FB.state === 'missing' ? `<button class="btn sm primary" data-act="fbChoose">${ico('folder-open','sm')}Choose the folder again</button>` : `<button class="btn sm" data-act="fbNow"${FB.busy ? ' disabled' : ''}>${ico('save','sm')}Back up now</button>`}
      <label class="fb-ev">After changes, at most every <select id="fbEvery" aria-label="How often">${[5, 10, 30, 60].map(m => `<option value="${m}"${+p.every === m ? ' selected' : ''}>${m} min</option>`).join('')}</select></label>
      <button class="btn sm ghost" data-act="fbChoose">${ico('folder-open','sm')}Change folder</button><button class="btn sm ghost" data-act="fbOff">Turn off</button></div></div>`;
}
const FB_ACTS = {fbChoose:() => fbChoose(), fbResume:() => fbResume(), fbOff:() => fbOff(), fbNow:() => fbRun(true)};
document.addEventListener('change', ev => { if(ev.target.id === 'fbEvery'){ const p = fbGet(); p.every = +ev.target.value || 10; fbSet(p); fbSchedule(false); } });
