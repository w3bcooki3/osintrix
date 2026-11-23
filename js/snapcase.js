/* ==========================================================================
   Case snapshots — a copy of one case at a moment, saved as a file on your
   computer (never in browser storage, so they cost no space here). Later,
   open a snapshot file to see what changed since — entries, links, records
   and notes added, removed or edited — and either bring back only what was
   removed, or roll the whole case back to it. Before a roll-back a snapshot
   of the case as it is now is downloaded first, and Undo works right after.
   The file is the same shape as a case export, so it also imports as a case.
   ========================================================================== */
const SNC = {MAX_LIST:60};
/* the case as an object — the same shape as Export case (attachments optional) */
async function sncBuild(cid, withFiles){
  const c = theCase(cid), recs = DB.records.filter(r => r.caseId === c.id), D = derive(c.id);
  const keys = new Set([...D.ents.keys(), ...DB.entries.filter(e => e.caseId === c.id).map(entryKey).filter(Boolean)]);
  const files = withFiles && typeof filesForExport === 'function' ? await filesForExport(recs) : undefined;
  return {format:'osintrix-case', v:3, snapshot:{name:UI.snc && UI.snc.name || '', at:Date.now(), app:BRAND.version}, case:c, entries:DB.entries.filter(e => e.caseId === c.id), links:DB.links.filter(l => l.caseId === c.id), records:recs,
    notes:(DB.notes || []).filter(n => n.caseId === c.id), verdicts:Object.fromEntries(Object.entries(DB.verdicts || {}).filter(([k]) => keys.has(k))), ...(files ? {files} : {})};
}
const sncStamp = t => new Date(t).toISOString().slice(0, 16).replace('T', '-').replace(':', '');
async function sncSave(cid, name, withFiles){
  UI.snc = {name}; const o = await sncBuild(cid, withFiles), c = theCase(cid);
  download(`${slug(caseNm(c))}-snapshot-${sncStamp(o.snapshot.at)}${name ? '-' + slug(name).slice(0, 40) : ''}.json`, JSON.stringify(o), 'application/json');
  return o;
}
function sncSaveDlg(){
  const c = theCase(), n = derive(c.id), hasFiles = DB.records.some(r => r.caseId === c.id && (r.files || []).length);
  openDlg(dhead('Save a snapshot of ' + esc(caseNm(c))) + `<form data-form="sncSave"><div class="in">
    <p class="t2" style="margin:0 0 12px">The case as it is now — ${n.entries.length.toLocaleString()} entries, ${n.links.length.toLocaleString()} links, ${n.recs.length.toLocaleString()} records — saved as a file on your computer. It takes no space in this browser. Open it later to see what changed, bring back what was removed, or roll back.</p>
    <div class="field"><label for="sncName">Name <span class="t3">(optional)</span></label><input id="sncName" maxlength="80" placeholder="Before the Maltego import" autocomplete="off"></div>
    ${hasFiles ? `<label class="chk"><input type="checkbox" id="sncFiles"> Include attached files (pictures, documents) — a bigger file</label>` : ''}</div>
    <footer><button class="btn" type="button" data-act="dclose">Cancel</button><button class="btn primary" type="submit">${ico('download','sm')}Save snapshot</button></footer></form>`);
  $('dlg').classList.add('narrow'); setTimeout(() => { const i = $('sncName'); if(i) i.focus(); });
}
async function sncSaveSubmit(){ const name = ($('sncName').value || '').trim().replace(/\s+/g, ' ').slice(0, 80), files = !!($('sncFiles') && $('sncFiles').checked);
  closeDlg(); await sncSave(DB.active, name, files); toast('Snapshot saved to your downloads' + (name ? ' — ' + name : '')); }

/* ---------- comparing ---------- */
const sncEntrySig = e => JSON.stringify([e.type, e.fields, [...(e.tags || [])].sort(), e.priority, !!e.starred, e.notes || '']);
const sncLinkKey = l => l.a + '|' + l.b + '|' + String(l.label || '').toLowerCase();
function sncDiff(S, cid){
  const now = {entries:DB.entries.filter(e => e.caseId === cid), links:DB.links.filter(l => l.caseId === cid), records:DB.records.filter(r => r.caseId === cid), notes:(DB.notes || []).filter(n => n.caseId === cid)};
  const by = L => new Map(L.map(x => [x.id, x]));
  const E0 = by(S.entries), E1 = by(now.entries), R0 = by(S.records), R1 = by(now.records), N0 = by(S.notes), N1 = by(now.notes);
  const L0 = new Map(S.links.map(l => [sncLinkKey(l), l])), L1 = new Map(now.links.map(l => [sncLinkKey(l), l]));
  const vd = id => { const e = E0.get(id) || E1.get(id); return e ? e : null; };
  return {
    eAdd:now.entries.filter(e => !E0.has(e.id)), eDel:S.entries.filter(e => !E1.has(e.id)), eMod:now.entries.filter(e => E0.has(e.id) && sncEntrySig(E0.get(e.id)) !== sncEntrySig(e)),
    lAdd:now.links.filter(l => !L0.has(sncLinkKey(l))), lDel:S.links.filter(l => !L1.has(sncLinkKey(l))),
    rAdd:now.records.filter(r => !R0.has(r.id)), rDel:S.records.filter(r => !R1.has(r.id)),
    nAdd:now.notes.filter(n => !N0.has(n.id)), nDel:S.notes.filter(n => !N1.has(n.id)), nMod:now.notes.filter(n => N0.has(n.id) && N0.get(n.id).text !== n.text),
    name:vd };
}
/* what changed in an edited entry, in words */
function sncWhat(a, b){ const out = [];
  for(const k of new Set([...Object.keys(a.fields || {}), ...Object.keys(b.fields || {})])) if(String(a.fields[k] || '') !== String(b.fields[k] || '')) out.push(((TYPES[b.type] && TYPES[b.type].fields.find(f => f[0] === k)) || [k, k])[1] + `: ${a.fields[k] || '—'} → ${b.fields[k] || '—'}`);
  if(a.priority !== b.priority) out.push(`priority ${a.priority} → ${b.priority}`); if(!!a.starred !== !!b.starred) out.push(b.starred ? 'starred' : 'unstarred');
  const ta = new Set(a.tags || []), tb = new Set(b.tags || []), ad = [...tb].filter(t => !ta.has(t)), rm = [...ta].filter(t => !tb.has(t));
  if(ad.length) out.push('tagged #' + ad.join(' #')); if(rm.length) out.push('untagged #' + rm.join(' #')); if((a.notes || '') !== (b.notes || '')) out.push('notes edited');
  return out.join(' · '); }
function sncLoad(){
  const i = document.createElement('input'); i.type = 'file'; i.accept = '.json,application/json';
  i.onchange = async () => { const f = i.files && i.files[0]; if(!f) return; if(f.size > 400 * 1048576) return toast('That file is too big to be a case snapshot');
    let d; try{ d = JSON.parse(await f.text()); }catch(e){ return toast('That file is not a snapshot (not JSON)'); }
    if(!d || d.format !== 'osintrix-case' || !d.case || !Array.isArray(d.entries)) return toast('Not an OSINTrix case snapshot — save one from the case menu');
    { const errs = checkImport(d, 'case'); if(errs.length) return importRefused('The snapshot', errs); }
    const c = theCase();
    if(d.case.id !== c.id) return toast(`That snapshot is of ${theCase(d.case.id) ? caseNm(theCase(d.case.id)) : String(d.case.name || d.case.code || 'another case').split(' — ')[0].slice(0, 48)}, not ${caseNm(c)} — open it from that case, or import it as a new case from Cases`);
    d.entries = d.entries.map(e => normEntry({...e})); d.records = (d.records || []).map(r => normRecord({...r})); d.links = (d.links || []).map(l => normLink({...l})); d.notes = Array.isArray(d.notes) ? d.notes.filter(n => n && typeof n.text === 'string') : [];
    UI.sncF = {name:f.name, d}; sncDlg(); };
  i.click();
}
function sncDlg(){
  const F = UI.sncF; if(!F) return; const d = F.d, c = theCase(), X = sncDiff(d, c.id), at = d.snapshot && d.snapshot.at;
  const nm = e => esc(primary(e)), sec = (title, list, fn) => list.length ? `<details class="snc-s"${list.length <= 8 ? ' open' : ''}><summary><b>${list.length.toLocaleString()}</b> ${list.length === 1 ? {entries:'entry', links:'link', records:'record', notes:'note'}[title] : title}</summary><ul>${list.slice(0, SNC.MAX_LIST).map(fn).join('')}${list.length > SNC.MAX_LIST ? `<li class="t3">and ${(list.length - SNC.MAX_LIST).toLocaleString()} more</li>` : ''}</ul></details>` : '';
  const E0 = new Map(d.entries.map(e => [e.id, e])), Ex = id => E0.get(id) || entryById(id), ln = l => `<li>${esc(Ex(l.a) ? primary(Ex(l.a)) : '?')} <span class="t3">${esc(l.label)}</span> ${esc(Ex(l.b) ? primary(Ex(l.b)) : '?')}</li>`;
  const same = !Object.entries(X).some(([k, v]) => Array.isArray(v) && v.length), back = X.eDel.length + X.lDel.length + X.rDel.length + X.nDel.length;
  openDlg(dhead('Since the snapshot') + `<div class="in snc">
    <p class="snc-src">${ico('history','sm')}<b>${esc(d.snapshot && d.snapshot.name || F.name)}</b><span class="t3">${at ? esc(E.fmtFull(at, tz()).slice(0, 16)) + ' · ' + esc(E.fmtAgo(Math.max(0, Date.now() - at))) : esc(F.name)}</span></p>
    ${same ? `<p class="dp-done">${ico('check','sm')}<b>Nothing has changed in ${esc(caseNm(c))} since this snapshot.</b></p>` : `
    <div class="snc-cols"><div><h4>Added since</h4>${sec('entries', X.eAdd, e => `<li>${tbadge(e.type)}${nm(e)}</li>`)}${sec('links', X.lAdd, ln)}${sec('records', X.rAdd, r => `<li>${esc(r.title)}</li>`)}${sec('notes', X.nAdd, n => `<li>${esc(noteLabel(n))}</li>`)}${X.eAdd.length + X.lAdd.length + X.rAdd.length + X.nAdd.length ? '' : '<p class="t3">Nothing</p>'}</div>
      <div><h4>Removed since</h4>${sec('entries', X.eDel, e => `<li>${tbadge(e.type)}${nm(e)}</li>`)}${sec('links', X.lDel, ln)}${sec('records', X.rDel, r => `<li>${esc(r.title)}</li>`)}${sec('notes', X.nDel, n => `<li>${esc(noteLabel(n))}</li>`)}${back ? '' : '<p class="t3">Nothing</p>'}</div>
      <div><h4>Edited since</h4>${sec('entries', X.eMod, e => `<li>${tbadge(e.type)}${nm(e)}<small class="t3">${esc(sncWhat(E0.get(e.id), e))}</small></li>`)}${sec('notes', X.nMod, n => `<li>${esc(noteLabel(n))}</li>`)}${X.eMod.length + X.nMod.length ? '' : '<p class="t3">Nothing</p>'}</div></div>`}</div>
    <footer><button class="btn" data-act="dclose">Close</button>${back ? `<button class="btn" data-act="sncBack" title="Add back what was removed; keep everything added or edited since">${ico('undo-2','sm')}Bring back ${back.toLocaleString()} removed</button>` : ''}${same ? '' : `<button class="btn dangerbtn" data-act="sncRoll">${ico('history','sm')}Roll back to the snapshot</button>`}</footer>`, true);
}
/* the bytes a change would add, for the storage guard */
const sncBytes = (...lists) => lists.reduce((n, L) => n + JSON.stringify(L).length * 2, 0);
async function sncBringBack(){
  const F = UI.sncF; if(!F) return; const d = F.d, c = theCase(), X = sncDiff(d, c.id);
  if(!await stoGuard(sncBytes(X.eDel, X.lDel, X.rDel, X.nDel), 'bring these back')) return;
  const before = {entries:DB.entries.slice(), links:DB.links.slice(), records:DB.records.slice(), notes:(DB.notes || []).slice()};
  const have = new Set(DB.entries.map(e => e.id));
  DB.entries.push(...X.eDel.map(e => ({...e, caseId:c.id}))); for(const e of X.eDel) have.add(e.id);
  DB.links.push(...X.lDel.filter(l => have.has(l.a) && have.has(l.b)).map(l => ({...l, id:DB.links.some(z => z.id === l.id) ? uid('l') : l.id, caseId:c.id})));
  DB.records.push(...X.rDel.map(r => ({...r, caseId:c.id}))); if(X.nDel.length){ ensureNotes(); DB.notes.push(...X.nDel.map(n => ({...n, caseId:c.id}))); }
  if(d.files && X.rDel.length && typeof rekeyFiles === 'function') await rekeyFiles(d.files, X.rDel);
  const n = X.eDel.length + X.lDel.length + X.rDel.length + X.nDel.length;
  closeDlg(); mutate(`brought back ${n} removed items from a snapshot`); renderAll();
  toast(`Brought back ${n.toLocaleString()} removed item${n === 1 ? '' : 's'}`, 'Undo', () => { Object.assign(DB, before); mutate('undid bringing back'); renderAll(); });
}
function sncRoll(){
  const F = UI.sncF; if(!F) return; const c = theCase();
  confirmDlg(`Roll ${caseNm(c)} back to the snapshot?`, `Its entries, links, records and notes become what they were in the snapshot. A snapshot of the case as it is now is saved to your downloads first, and you can undo right after.`, 'Roll back', async () => {
    const d = F.d, X = sncDiff(d, c.id);
    if(!await stoGuard(sncBytes(X.eDel, X.lDel, X.rDel, X.nDel), 'roll back')) return;
    await sncSave(c.id, 'before rolling back', false);
    const before = {entries:DB.entries.slice(), links:DB.links.slice(), records:DB.records.slice(), notes:(DB.notes || []).slice(), verdicts:{...DB.verdicts}};
    DB.entries = DB.entries.filter(e => e.caseId !== c.id).concat(d.entries.map(e => ({...e, caseId:c.id})));
    DB.links = DB.links.filter(l => l.caseId !== c.id).concat(d.links.map(l => ({...l, caseId:c.id})));
    DB.records = DB.records.filter(r => r.caseId !== c.id).concat(d.records.map(r => ({...r, caseId:c.id})));
    ensureNotes(); DB.notes = DB.notes.filter(n => n.caseId !== c.id).concat(d.notes.map(n => ({...n, caseId:c.id})));
    const vin = normVerdicts(d.verdicts); DB.verdicts = DB.verdicts || {}; for(const [k, v] of Object.entries(vin)) DB.verdicts[k] = v;
    if(d.files && X.rDel.length && typeof rekeyFiles === 'function') await rekeyFiles(d.files, X.rDel);
    if(UI.sel && !entryById(UI.sel.id) && !recById(UI.sel.id)) UI.sel = null;
    UI.sncF = null; mutate('rolled ' + caseNm(c) + ' back to a snapshot'); renderAll();
    toast(`${caseNm(c)} rolled back — the state before is in your downloads`, 'Undo', () => { Object.assign(DB, before); mutate('undid the roll-back'); renderAll(); }); });
}
const SNC_ACTS = {
  sncSaveDlg:() => sncSaveDlg(),
  sncLoad:() => sncLoad(),
  sncBack:() => sncBringBack(),
  sncRoll:() => sncRoll(),
};
