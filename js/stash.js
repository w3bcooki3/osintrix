/* ==========================================================================
   Cases kept in a file
   A finished case moves out of the browser into one file on your computer, and only a card stays:
   name, dates, counts, and the case's indicators — so "also seen in another case" still finds it.
     1. Save the file (encrypted when the workspace is)
     2. Pick the saved file back: it is read and compared byte for byte with what was saved
     3. Only then are its entries, records, notes, links and attached files removed here
   Bringing it back reads the same file and puts everything back under the same ids.
   ========================================================================== */
const STASH_KEYS = 20000;
const stashed = c => !!(c && c.stash && typeof c.stash === 'object');
function stashParts(c){ const id = c.id; return {entries:DB.entries.filter(e => e.caseId === id), links:DB.links.filter(l => l.caseId === id), records:DB.records.filter(r => r.caseId === id), notes:(DB.notes || []).filter(n => n.caseId === id)}; }
function stashSize(c){ const P = stashParts(c), att = P.records.reduce((s, r) => s + (r.att || []).reduce((t, a) => t + (+a.size || 0), 0), 0);
  let json = 0; try{ json = JSON.stringify(P).length * 2; }catch(e){} return {P, att, json, total:att + json}; }
async function stashObj(c){
  const P = stashParts(c), files = await filesForExport(P.records), D = derive(c.id);
  const keys = new Set([...D.ents.keys(), ...P.entries.map(e => typeof entryKey === 'function' ? entryKey(e) : '').filter(Boolean)]);
  const verdicts = Object.fromEntries(Object.entries(DB.verdicts || {}).filter(([k]) => keys.has(k)));
  return {o:{format:'osintrix-case', v:3, stored:true, case:c, entries:P.entries, links:P.links, records:P.records, notes:P.notes, verdicts, files}, keys:[...keys]};
}
const stashName = c => slug(caseNm(c, 60)) + '-' + new Date().toISOString().slice(0, 10) + '.osintrix-case.json';

/* ---------- 1. what will happen ---------- */
async function stashDlg(id){
  const c = theCase(id); if(!c || stashed(c)) return; const S = stashSize(c);
  openDlg(dhead('Move ' + esc(caseNm(c)) + ' to a file') + `<div class="in">
    <p style="margin:0 0 12px">Everything in this case goes into one file on your computer: <b>${S.P.entries.length}</b> entries, <b>${S.P.records.length}</b> records${S.P.notes.length ? `, <b>${S.P.notes.length}</b> notes` : ''}${S.att ? ` and <b>${stoBytes(S.att)}</b> of attached files` : ''}. That frees about <b>${stoBytes(S.total)}</b> here.</p>
    <ol class="st-steps"><li><b>Save the file</b>${SEC.key ? ' — encrypted with a passphrase, like this workspace' : ''}.</li><li><b>Pick it back</b> so it can be checked: it must match what was saved, byte for byte.</li><li>Only then is the case removed from this browser. A card stays in Cases, and its indicators still show up as “also in a stored case”.</li></ol>
    <p class="t3 small" style="margin:12px 0 0">Bring it back any time from its card by picking the same file. Restore points made earlier still hold a copy until they are replaced.</p></div>
    <footer><button class="btn" data-act="dclose">Cancel</button><button class="btn primary" data-act="stashSave" data-id="${esc(c.id)}">${ico('download','sm')}Save the file</button></footer>`);
}
/* ---------- 2. save, then ask for the file back ---------- */
async function stashSave(id){
  const c = theCase(id); if(!c) return; const {o, keys} = await stashObj(c), text = JSON.stringify(o), name = stashName(c);
  const sha = await sha256Hex(new TextEncoder().encode(text)); UI.stash = {id:c.id, sha, name, bytes:text.length, keys, n:{entries:o.entries.length, records:o.records.length, notes:o.notes.length, links:o.links.length, files:Object.keys(o.files).length}};
  const next = () => openDlg(dhead('Now pick the file you saved') + `<div class="in"><p style="margin:0 0 10px">Your browser saved <b class="mono">${esc(name)}</b>${SEC.key ? '' : ` (${stoBytes(text.length)})`}, usually in Downloads. Pick it so it can be checked before anything is removed.</p>
    <p class="t3 small" style="margin:0">Nothing has been removed yet. If the download did not happen, cancel — the case stays as it is.</p></div>
    <footer><button class="btn" data-act="dclose">Cancel</button><button class="btn" data-act="stashSave" data-id="${esc(c.id)}">Save again</button><button class="btn primary" data-act="stashCheck">${ico('folder-open','sm')}Pick the file…</button></footer>`);
  if(!SEC.key){ download(name, text, 'application/json'); return next(); }
  passDlg('Encrypt the case file', 'Anyone who gets the file needs this passphrase to open it. It is not stored anywhere — you need it to bring the case back.', 'Encrypt and save', async pass => {
    const salt = crypto.getRandomValues(new Uint8Array(16)), key = await deriveKey(pass, salt, SEC.iter), env = await sealWith(key, salt, SEC.iter, text, {format:'osintrix-encrypted', what:'osintrix-case'});
    closeDlg(); download(name.replace(/\.json$/, '.encrypted.json'), env, 'application/json'); next(); }, true);
}
/* ---------- 3. checked: remove it here ---------- */
function stashCheck(){
  const S = UI.stash; if(!S) return;
  pickFile('.json,application/json', raw => maybeDecrypt(raw, async txt => {
    const sha = await sha256Hex(new TextEncoder().encode(txt));
    if(sha !== S.sha) return openDlg(dhead('That is not the same file') + `<div class="in"><p style="margin:0">It does not match what was just saved${txt.length !== S.bytes ? ` (${stoBytes(txt.length)} instead of ${stoBytes(S.bytes)})` : ''} — another file, an older copy, or a download that did not finish. <b>Nothing was removed.</b></p></div>
      <footer><button class="btn" data-act="dclose">Close</button><button class="btn primary" data-act="stashCheck">Pick another file…</button></footer>`);
    await stashCommit(S); }));
}
async function stashCommit(S){
  const c = theCase(S.id); if(!c) return; const P = stashParts(c), fids = new Set(P.records.flatMap(r => (r.att || []).map(a => a.id))), freed = stashSize(c).total;
  DB.entries = DB.entries.filter(e => e.caseId !== c.id); DB.links = DB.links.filter(l => l.caseId !== c.id); DB.records = DB.records.filter(r => r.caseId !== c.id); if(DB.notes) DB.notes = DB.notes.filter(n => n.caseId !== c.id);
  c.stash = {at:Date.now(), file:S.name, sha:S.sha, bytes:S.bytes, n:S.n, keys:S.keys.slice(0, STASH_KEYS), status:c.status};
  if(c.pinned) c.pinned = false; c.updated = Date.now(); UI.stash = null; if(UI.sel && UI.sel.kind !== 'ent') UI.sel = null;
  mutate('moved ' + caseNm(c) + ' to a file'); hashRecords();
  /* its files go too — except any that another record, the trash or a restore point still needs */
  const still = new Set(DB.records.concat((DB.trash || []).flatMap(x => x.kind === 'record' ? [x.data.r] : x.kind === 'case' ? x.data.records || [] : [])).flatMap(r => (r && r.att || []).map(a => a.id))), R = await snapRefs();
  if(R) for(const f of fids) if(!still.has(f)) await blobDel('file:' + f);
  closeDlg(); renderAll(); toast(`${caseNm(c)} is now in ${S.name} — about ${stoBytes(freed)} freed${R ? '' : ' (its files stay until restore points are cleared)'}`);
  if(typeof storageCheck === 'function') storageCheck();
}

/* ---------- bringing it back ---------- */
function stashBack(id){
  const c = theCase(id); if(!stashed(c)) return;
  pickFile('.json,application/json', raw => maybeDecrypt(raw, async txt => {
    let d; try{ d = JSON.parse(txt); }catch(e){ return toast('That file is not JSON'); }
    if(!d || d.format !== 'osintrix-case' || !d.case || !Array.isArray(d.entries)) return toast('Not an OSINTrix case file');
    if(d.case.id !== c.id) return toast('That file holds another case — ' + caseNm(d.case));
    { const errs = checkImport(d, 'case'); if(errs.length) return importRefused('The case', errs); }
    const sha = await sha256Hex(new TextEncoder().encode(txt)), same = sha === c.stash.sha;
    const go2 = async () => {
      if(!await stoGuard(txt.length * 2, 'bring this case back')) return;
      const ent = d.entries.map(e => normEntry({...e, caseId:c.id})), recs = (d.records || []).map(r => normRecord({...r, caseId:c.id})), links = (d.links || []).map(l => normLink({...l, caseId:c.id}));
      const ids = new Set(DB.entries.map(e => e.id).concat(DB.records.map(r => r.id)));
      if(ent.concat(recs).some(x => ids.has(x.id))) return toast('Some of it is already here — nothing was changed');
      const NC = typeof NOTE_COLORS !== 'undefined' ? NOTE_COLORS.map(x => x[0]) : [];
      const notes = (Array.isArray(d.notes) ? d.notes : []).filter(n => n && typeof n === 'object' && typeof n.text === 'string').slice(0, 2000).map(n => ({...n, caseId:c.id, color:NC.includes(n.color) ? n.color : 'yellow', text:String(n.text).slice(0, 20000)}));
      const vin = normVerdicts(d.verdicts); DB.verdicts = DB.verdicts || {}; for(const [k, x] of Object.entries(vin)) if(!DB.verdicts[k]) DB.verdicts[k] = x;
      if(d.files) await filesFromImport(d.files);
      const keep = {pinned:c.pinned}; Object.assign(c, normCase({...d.case, id:c.id}), keep); delete c.stash; c.updated = Date.now();
      DB.entries.push(...ent); DB.records.push(...recs); DB.links.push(...links.filter(l => ent.some(e => e.id === l.a) && ent.some(e => e.id === l.b))); if(notes.length){ ensureNotes(); DB.notes.push(...notes); }
      mutate('brought back ' + caseNm(c)); hashRecords(); ensurePositions(); closeDlg(); renderAll();
      toast(`${caseNm(c)} is back — ${ent.length} entries, ${recs.length} records${d.files ? ', ' + Object.keys(d.files).length + ' files' : ''}`); };
    if(same) return go2();
    UI.stashGo = go2;
    openDlg(dhead('This copy has changed') + `<div class="in"><p style="margin:0">It is ${esc(caseNm(c))}, but not byte for byte the file stored on ${esc(E.fmtDate(c.stash.at, tz()))} — it was edited, or is another export of the case. Bring it back anyway?</p></div>
      <footer><button class="btn" data-act="dclose">Cancel</button><button class="btn primary" data-act="stashBackGo">Bring it back</button></footer>`);
  }));
}

/* ---------- where a stored case shows ---------- */
function stashView(c){
  const S = c.stash, n = S.n || {};
  return `<div class="page stash-page"><div class="stash-card">
    <span class="stash-ic" aria-hidden="true">${ico('archive','lg')}</span>
    <h2>${esc(c.name)}</h2><p class="t2">${esc(c.scope || '')}</p>
    <p class="stash-at">Kept in a file since ${esc(E.fmtDate(S.at, tz()))}</p>
    <dl class="kv stash-kv"><dt>File</dt><dd class="mono">${esc(S.file)}</dd><dt>Size</dt><dd>${stoBytes(S.bytes)}</dd><dt>Holds</dt><dd>${n.entries || 0} entries · ${n.records || 0} records${n.notes ? ' · ' + n.notes + (n.notes === 1 ? ' note' : ' notes') : ''}${n.files ? ' · ' + n.files + ' files' : ''}</dd><dt>Indicators</dt><dd>${(S.keys || []).length.toLocaleString()} — still matched against your other cases</dd><dt>SHA-256</dt><dd class="mono small" style="overflow-wrap:anywhere">${esc(S.sha)}</dd></dl>
    <div class="wrap" style="justify-content:center;margin-top:18px"><button class="btn primary" data-act="stashBack" data-id="${esc(c.id)}">${ico('archive-restore','sm')}Bring it back — pick the file</button><button class="btn" data-act="caseMenu" data-id="${esc(c.id)}">${ico('ellipsis','sm')}More</button></div></div></div>`;
}
{ const vc = viewCase; viewCase = function(tab){ const c = theCase(); return stashed(c) ? stashView(c) : vc.apply(this, arguments); }; }
/* cases kept in files that hold an indicator */
function stashHits(key){ return DB.cases.filter(c => stashed(c) && (c.stash.keys || []).includes(key)); }
/* closed cases worth moving out, biggest first */
function stashCandidates(){ return DB.cases.filter(c => !stashed(c) && c.status === 'closed').map(c => ({c, s:stashSize(c).total})).filter(x => x.s > 0).sort((a, b) => b.s - a.s); }
function stashPickDlg(){
  const L = stashCandidates();
  openDlg(dhead('Move archived cases to files') + `<div class="in">${L.length ? `<p class="t2" style="margin:0 0 10px">Archived cases, biggest first. Each becomes one file on your computer; its card stays here.</p>
    ${L.map(x => `<div class="sto-r"><span>${esc(caseNm(x.c))}</span><b>${stoBytes(x.s)}</b><button class="btn xs" data-act="stashOne" data-id="${esc(x.c.id)}">Move to a file…</button></div>`).join('')}` : '<p style="margin:0">No archived cases. Archive a finished case from its menu first.</p>'}</div>
    <footer><button class="btn" data-act="dclose">Close</button></footer>`);
}
const STASH_ACTS = {
  stashOne:id => stashDlg(id),
  stashSave:id => stashSave(id),
  stashCheck:() => stashCheck(),
  stashBack:id => stashBack(id),
  stashBackGo:() => { const f = UI.stashGo; UI.stashGo = null; if(f) f(); },
  stashPick:() => stashPickDlg(),
};
function stashCard(c){ const S = c.stash, n = S.n || {};
  return `<article class="case-card cs2-card archived stashed" style="--cc:${esc(c.color)}">
    <a class="case-hit" href="${caseHash(c.id)}" aria-label="Open ${esc(c.name)}"></a>
    <div class="cs2-map stash-map"><span class="stash-f">${ico('archive','sm')}In a file since ${esc(E.fmtDate(S.at, tz()))}</span><span class="mono t3 small">${esc(S.file)}</span></div>
    <div class="cs2-b"><div class="cs2-code">${caseSq(c)}<span class="cs2-sp"></span>${caseActs(c)}</div>
      <h3>${esc(c.name)}</h3><p class="${c.scope ? '' : 'none'}">${esc(c.scope || 'No scope written yet.')}</p>
      <div class="cs2-f"><span class="q">${n.entries || 0} entries · ${n.records || 0} records · ${stoBytes(S.bytes)}</span><button class="btn xs" data-act="stashBack" data-id="${esc(c.id)}">${ico('archive-restore','sm')}Bring back</button></div>
    </div></article>`; }
