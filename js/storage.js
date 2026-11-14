/* ==========================================================================
   Storage: how much this browser lets the app keep, what is using it, early
   warnings before it runs out, and one-click ways to free space.
   Everything lives in this browser's IndexedDB (plus a localStorage mirror of
   small workspaces). Browsers cap it per site: Chrome and Edge allow up to
   about 60% of free disk, Firefox about 10% (more once marked persistent),
   Safari about 60% of disk on recent versions. The real figure comes from
   navigator.storage.estimate().
   ========================================================================== */
const STO_LOW = .85, STO_LOW_FREE = 200 * 1048576, STO_FULL_FREE = 40 * 1048576;
let stoWarned = false, stoFailWarned = false, stoInfo = null;

IDB.keys = () => new Promise(res => { if(!IDB.db) return res([]); try{ const q = IDB.db.transaction('kv').objectStore('kv').getAllKeys(); q.onsuccess = () => res(q.result || []); q.onerror = () => res([]); }catch(e){ res([]); } });

/* refresh the numbers and the warning state; warn once per session when it turns low */
async function storageCheck(){
  await storageEstimate();
  const q = STO_QUOTA(), u = STORE.usage || 0, free = q ? q - u : Infinity;
  const was = STORE.low; STORE.low = !!q && (u / q > STO_LOW || free < STO_LOW_FREE); STORE.full = !!q && free < STO_FULL_FREE;
  if(STORE.low && !was && !stoWarned){ stoWarned = true; toast(STORE.full ? 'Browser storage is full — new files may not save' : 'Browser storage is nearly full', 'Manage storage', () => go('#/settings')); }
  paintSaved(); return STORE;
}
const STO_QUOTA = () => STORE.quota || 0;
const stoBytes = n => n >= 1073741824 ? (n / 1073741824).toFixed(1) + ' GB' : n >= 1048576 ? (n / 1048576).toFixed(1) + ' MB' : n >= 1024 ? Math.round(n / 1024) + ' KB' : (n || 0) + ' B';
/* re-measure after saves, at most every 20 seconds */
const _flush = flush; let stoT = 0;
flush = function(){ const r = _flush.apply(this, arguments); if(Date.now() - stoT > 20000 && DB && !SEC.locked){ stoT = Date.now(); setTimeout(storageCheck, 1500); } return r; };
setInterval(() => { if(DB && !SEC.locked) storageCheck(); }, 120000);

/* the top-bar status also shows low space and failed saves */
const _paintSaved = paintSaved;
paintSaved = function(){
  _paintSaved(); const s = $('saved'); if(!s || !TABS.writer) return;
  if(!storageOK){ s.innerHTML = '<i style="background:var(--red)"></i><span>Not saved — storage full or blocked</span>'; s.title = 'Open Settings → Storage';
    if(!stoFailWarned){ stoFailWarned = true; toast('Your last change could not be saved. Free some space or export a backup now.', 'Manage storage', () => go('#/settings')); } }
  else if(STORE.low){ const pct = STO_QUOTA() ? Math.round((STORE.usage || 0) / STO_QUOTA() * 100) : 0; s.innerHTML = `<i style="background:var(--amber)"></i><span>Storage ${pct}% full</span>`; s.title = 'Saved, but space is running out — open Settings → Storage'; }
  s.style.cursor = !storageOK || STORE.low ? 'pointer' : ''; s.onclick = !storageOK || STORE.low ? () => go('#/settings') : null;
};

/* what is using the space */
async function storageBreakdown(){
  await storageCheck(); await snapsLoad();
  const recs = DB.records.concat((DB.trash || []).flatMap(x => x.kind === 'record' ? [x.data.r] : x.kind === 'case' ? x.data.records || [] : []));
  const att = recs.reduce((s, r) => s + (r && r.att || []).reduce((t, a) => t + (+a.size || 0), 0), 0);
  const media = DB.nb ? Object.values(DB.nb.media) : [], nbLive = media.filter(m => !m.gone && !m.demo).reduce((s, m) => s + (+m.size || 0), 0), nbGone = media.filter(m => m.gone).reduce((s, m) => s + (+m.size || 0), 0);
  const snaps = (SNAPS || []).reduce((s, x) => s + (x.size || 0) * 2, 0);
  // files in IndexedDB that nothing points at any more (left behind by crashes or older versions)
  const keys = await IDB.keys(), fids = new Set(recs.flatMap(r => (r && r.att || []).map(a => 'file:' + a.id))), nbk = new Set(media.map(m => 'nbm:' + m.id));
  const wk = new Set((DB.recent || []).filter(x => x.kind === 'file').map(x => 'wk:' + x.id));
  const orphans = keys.filter(k => typeof k === 'string' && ((k.startsWith('file:') && !fids.has(k)) || (k.startsWith('nbm:') && !nbk.has(k)) || (k.startsWith('wk:') && !wk.has(k))));
  stoInfo = {quota:STO_QUOTA(), usage:STORE.usage || 0, json:STORE.bytes || 0, att, nbLive, nbGone, nbGoneN:media.filter(m => m.gone).length, snaps, snapN:(SNAPS || []).length, trashN:(DB.trash || []).length, orphans};
  return stoInfo;
}
function storageCard(){
  const I = stoInfo, q = STO_QUOTA(), u = STORE.usage || 0, pct = q ? Math.min(100, u / q * 100) : 0;
  const tone = STORE.full ? 'var(--red)' : STORE.low ? 'var(--amber)' : 'var(--accent-bg)';
  const row = (l, v, act, btn) => `<div class="sto-r"><span>${l}</span><b>${v}</b>${act ? `<button class="btn xs" data-act="${act}">${btn}</button>` : '<span></span>'}</div>`;
  return `<section class="card sto" id="storage"><header><h3>Storage</h3>${!storageOK ? '<span class="pill red">Not saving</span>' : STORE.low ? '<span class="pill amber">Running low</span>' : ''}</header><div class="body">
    <div class="sto-m"><div class="sto-bar" role="meter" aria-label="Browser storage used" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${Math.round(pct)}"><i style="width:${Math.max(1, pct)}%;background:${tone}"></i></div>
      <p><b>${stoBytes(u)}</b> used of ${q ? stoBytes(q) + ' this browser allows here' : 'an unknown amount'}${q ? ` · ${stoBytes(Math.max(0, q - u))} free` : ''}</p></div>
    ${STORE.low ? `<p class="sto-warn">${STORE.full ? 'Storage is full: new pictures, files and big imports will be refused, and saves can fail.' : 'Storage is getting full.'} Export a backup, then free space below — or free disk space on this computer, since the browser's allowance grows with it.</p>` : ''}
    ${I ? `<div class="sto-t">
      ${row('Workspace data (cases, notes, pages)', stoBytes(I.json))}
      ${row('Case attachments', stoBytes(I.att))}
      ${row('Notebook pictures and files', stoBytes(I.nbLive))}
      ${I.nbGoneN ? row(`Deleted notebook pictures, kept ${NB_KEEP_DAYS} days for undo`, stoBytes(I.nbGone), 'stoNbFree', 'Free now') : ''}
      ${row(`Restore points (${I.snapN} of ${SNAP_MAX})`, stoBytes(I.snaps), I.snapN > 2 ? 'stoSnapTrim' : '', 'Keep newest 2')}
      ${typeof recentAll === 'function' ? row(`Recent tool inputs (${recentAll().length}) — certificates, Lab files, cloud`, stoBytes(recentBytes()), recentAll().length ? 'rcShow' : '', 'Manage').replace('data-act="rcShow"', 'data-act="rcShow" data-v="*"') : ''}
      ${row(`Trash (${I.trashN} item${I.trashN === 1 ? '' : 's'})`, I.trashN ? 'auto-empties after 30 days' : '—', I.trashN ? 'trEmpty' : '', 'Empty')}
      ${I.orphans.length ? row(`Leftover files nothing uses (${I.orphans.length})`, '', 'stoOrphans', 'Remove') : ''}</div>` : '<p class="t3">Measuring…</p>'}
    <p class="t3 sto-n">${STORE.persisted ? 'Marked persistent: the browser will not clear this data to free disk space.' : 'Not marked persistent: under heavy disk pressure the browser may clear it.'}
      There are no accounts — this is one private workspace per browser profile. Another browser, profile or computer starts empty; move work with Export everything / Import.</p>
    ${typeof fbHtml === 'function' ? fbHtml() : ''}
    <div class="wrap">${STORE.persisted ? '' : `<button class="btn sm" data-act="stoPersist">${ico('shield-check','sm')}Ask the browser to keep it</button>`}<button class="btn sm" data-act="exportAll">${ico('download','sm')}Export everything</button><button class="btn sm ghost" data-act="stoRefresh">${ico('refresh-cw','sm')}Measure again</button></div>
  </div></section>`;
}
function storagePaint(){ const c = $('storage'); if(c) c.outerHTML = storageCard(); }
async function storageRefresh(){ await storageBreakdown(); storagePaint(); }
const STO_ACTS = {
  stoRefresh:() => storageRefresh(),
  stoPersist:async () => { let ok = false; try{ ok = await navigator.storage.persist(); }catch(e){} STORE.persisted = ok; storagePaint(); toast(ok ? 'The browser will keep this data' : 'The browser said no — it usually agrees once the site is bookmarked or used often. Keep backups.'); },
  stoNbFree:() => confirmDlg('Free deleted notebook pictures now?', 'Pictures and files from deleted pages are removed for good. Undo and older restore points can no longer bring them back.', 'Free space', async () => { const n = nbGC(true); mutate('freed notebook space'); await storageRefresh(); toast('Freed ' + n + ' item' + (n === 1 ? '' : 's')); }),
  stoSnapTrim:() => confirmDlg('Delete older restore points?', 'The two newest restore points stay. Older ones are deleted and cannot be restored.', 'Delete older', async () => { await snapsLoad(); const drop = SNAPS.splice(2); for(const s of drop) await IDB.del('osintrix-snap:' + s.at); await IDB.set('osintrix-snaps', await sealStr(JSON.stringify(SNAPS))); await storageRefresh(); toast(drop.length + ' restore point' + (drop.length === 1 ? '' : 's') + ' deleted'); }),
  stoOrphans:() => confirmDlg('Remove leftover files?', 'These files are not attached to any record, trash item or notebook page. They are deleted for good.', 'Remove', async () => { const I = await storageBreakdown(); for(const k of I.orphans) await IDB.del(k); await storageRefresh(); toast(I.orphans.length + ' leftover file' + (I.orphans.length === 1 ? '' : 's') + ' removed'); })
};
