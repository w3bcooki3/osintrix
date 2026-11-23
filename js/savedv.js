/* ==========================================================================
   Saved views — give a name to a way of looking at things and come back to
   it in one click:
     · a vault view: its search, category, filters, sort and layout
     · a graph view: its focus, steps, filters
     · a search: what was typed in Ctrl K, with its scope
   Vault and graph views belong to their case; searches are for everywhere.
   They are listed in the vault's side panel, on the graph bar, and in Ctrl K
   (type the name, or "view"). A view is a few hundred bytes.
   ========================================================================== */
const SV = {MAX:200, NAME:80};
const SV_KIND = {vault:['Vault view', 'layers'], graph:['Graph view', 'waypoints'], search:['Saved search', 'search']};
const svList = (kind, cid) => (Array.isArray(DB.views) ? DB.views : []).filter(v => (!kind || v.kind === kind) && (cid === undefined || v.caseId === cid));
/* what each kind keeps */
function svCapture(kind){
  if(kind === 'vault'){ const F = vbF(DB.active); return {vd:F.vd, type:F.type, tag:F.tag, only:F.only, sort:F.sort, q:UI.vq || '', cat:UI.vcat || 'all', lay:DB.prefs.vLay === 'list' ? 'list' : 'cards'}; }
  if(kind === 'graph'){ const G = gvS(); return {focus:G.focus, hops:G.hops, vd:G.vd, tag:G.tag, leaves:G.leaves, exp:G.exp.slice(0, 50)}; }
  return {q:(typeof S !== 'undefined' && S.q || '').trim(), scope:typeof S !== 'undefined' ? S.scope : 'all'};
}
function svDescribe(v){ const s = v.s || {}, p = [];
  if(v.kind === 'search') return (s.scope && s.scope !== 'all' ? 'in ' + s.scope + ' · ' : '') + (s.q || '');
  if(v.kind === 'graph'){ const e = s.focus && entryById(s.focus); if(e) p.push(s.hops + ' step' + (s.hops > 1 ? 's' : '') + ' around ' + primary(e)); }
  if(s.q) p.push('“' + s.q + '”'); if(s.cat && s.cat !== 'all') p.push(s.cat); if(s.vd) p.push(s.vd === 'none' ? 'no verdict' : s.vd); if(s.type) p.push(s.type); if(s.tag) p.push('#' + s.tag);
  if(s.only) p.push((VB_ONLY.find(o => o[0] === s.only) || [, s.only])[1].toLowerCase()); if(s.leaves) p.push('no single links'); if(s.sort && s.sort !== 'prio') p.push('by ' + (VB_SORT.find(o => o[0] === s.sort) || [, s.sort])[1].toLowerCase());
  return p.join(' · ') || 'everything'; }
function svSaveDlg(kind){
  const s = svCapture(kind); if(kind === 'search' && !s.q) return toast('Type a search first');
  if(svList().length >= SV.MAX) return toast(`Up to ${SV.MAX} saved views — delete some first`);
  UI.svNew = {kind, s, caseId:kind === 'search' ? null : DB.active};
  if(kind === 'search' && typeof S !== 'undefined' && S.open) srchClose();   /* the naming dialog must not sit under the search */
  openDlg(dhead('Save this ' + SV_KIND[kind][0].toLowerCase()) + `<form data-form="svSave"><div class="in"><p class="t2" style="margin:0 0 12px">${esc(svDescribe({kind, s}))}</p>
    <div class="field"><label for="svName">Name</label><input id="svName" maxlength="${SV.NAME}" autocomplete="off" placeholder="${kind === 'search' ? 'Malicious IPs everywhere' : kind === 'graph' ? 'Around the phishing domain' : 'Unlinked suspicious domains'}"></div></div>
    <footer><button class="btn" type="button" data-act="dclose">Cancel</button><button class="btn primary" type="submit">${ico('bookmark','sm')}Save</button></footer></form>`);
  $('dlg').classList.add('narrow'); setTimeout(() => { const i = $('svName'); if(i) i.focus(); });
}
function svSaveSubmit(){
  const N = UI.svNew; if(!N) return; const name = ($('svName').value || '').trim().replace(/\s+/g, ' ').slice(0, SV.NAME);
  if(!name) return fieldErr('svName', 'Give it a name.');
  if(svList(N.kind, N.caseId).some(v => v.name.toLowerCase() === name.toLowerCase())) return fieldErr('svName', `There is already a ${SV_KIND[N.kind][0].toLowerCase()} called “${name}” here.`);
  DB.views = Array.isArray(DB.views) ? DB.views : []; DB.views.push({id:uid('sv'), kind:N.kind, caseId:N.caseId, name, s:N.s, at:Date.now()}); UI.svNew = null;
  closeDlg(); mutate('saved view ' + name); renderMain(); toast(N.kind === 'search' ? `Saved “${name}” — find it in Ctrl K by its name` : `Saved “${name}”`);
}
/* open a view: go where it belongs and put everything back as it was */
function svOpen(id){
  const v = svList().find(x => x.id === id); if(!v) return; const s = v.s || {};
  if(v.kind === 'search'){ if(typeof S !== 'undefined' && S.open) srchClose(); srchOpen(s.q ? s.q + ' ' : ''); S.scope = SCOPES.some(x => x[0] === s.scope) ? s.scope : 'all'; srchPaint(); return; }
  if(!DB.cases.some(c => c.id === v.caseId)) return toast('The case of this view is gone');
  DB.active = v.caseId;
  if(v.kind === 'vault'){ const F = vbF(v.caseId); Object.assign(F, {vd:s.vd || '', type:s.type || '', tag:s.tag || '', only:s.only || '', sort:s.sort || 'prio'}); UI.vq = s.q || ''; UI.vcat = s.cat || 'all'; DB.prefs.vLay = s.lay === 'list' ? 'list' : 'cards'; UI.vLim = null; UI.vPick = new Set();
    UI.svOn = v.id; go(caseHash(v.caseId, 'vault')); renderMain(); }
  else { const G = gvS(v.caseId); Object.assign(G, {focus:s.focus && entryById(s.focus) ? s.focus : null, hops:Math.max(1, Math.min(3, +s.hops || 1)), vd:s.vd || '', tag:s.tag || '', leaves:!!s.leaves, exp:(s.exp || []).filter(x => entryById(x))});
    if(s.focus && !G.focus) toast('The entry this view focused on is gone — showing the rest of the view'); UI.graph.views && delete UI.graph.views[v.caseId]; UI.svOn = v.id; go(caseHash(v.caseId, 'graph')); renderMain(); }
}
function svDel(id){ const v = svList().find(x => x.id === id); if(!v) return; DB.views = DB.views.filter(x => x.id !== id); mutate('deleted view ' + v.name); if(typeof S !== 'undefined' && S.open) srchPaint(); else renderMain();
  toast(`Deleted “${v.name}”`, 'Undo', () => { DB.views.push(v); mutate('restored view ' + v.name); renderMain(); }); }
/* the vault side panel's list, and the graph bar's */
function svVaultList(cid){ const L = svList('vault', cid); return L.length ? `<div class="caps sv-caps">Saved views</div>${L.map(v => `<div class="sv-row"><button class="cat sv-b${UI.svOn === v.id ? ' on' : ''}" data-act="svOpen" data-id="${v.id}" title="${esc(svDescribe(v))}">${ico('bookmark','sm')}<span>${esc(v.name)}</span></button><button class="iconbtn xs sv-x" data-act="svDel" data-id="${v.id}" aria-label="Delete the view ${esc(v.name)}" title="Delete">${ico('x','sm')}</button></div>`).join('')}` : ''; }
function svGraphSel(cid){ const L = svList('graph', cid); return L.length ? `<label class="sr" for="svG">Saved graph views</label><select id="svG" class="gsel bord gv-s" data-svg="1"><option value="">Saved views…</option>${L.map(v => `<option value="${v.id}">${esc(v.name)}</option>`).join('')}</select>` : ''; }
function bindSavedViews(){ const g = $('svG'); if(g) g.onchange = () => { if(g.value) svOpen(g.value); }; }
/* cleaning what was stored (a backup, an older version) */
function svClean(list){
  if(!Array.isArray(list)) return [];
  const str = (v, n) => typeof v === 'string' ? v.slice(0, n) : '', out = [];
  for(const v of list.slice(0, SV.MAX)){ if(!v || typeof v !== 'object' || !SV_KIND[v.kind] || typeof v.name !== 'string' || !v.name.trim()) continue; const s = v.s && typeof v.s === 'object' ? v.s : {};
    const c = v.kind === 'search' ? {q:str(s.q, 500), scope:str(s.scope, 20) || 'all'}
      : v.kind === 'vault' ? {vd:str(s.vd, 20), type:str(s.type, 40), tag:str(s.tag, 60), only:str(s.only, 20), sort:str(s.sort, 20) || 'prio', q:str(s.q, 200), cat:str(s.cat, 30) || 'all', lay:s.lay === 'list' ? 'list' : 'cards'}
      : {focus:typeof s.focus === 'string' ? s.focus.slice(0, 80) : null, hops:Math.max(1, Math.min(3, +s.hops || 1)), vd:str(s.vd, 20), tag:str(s.tag, 60), leaves:!!s.leaves, exp:Array.isArray(s.exp) ? s.exp.filter(x => typeof x === 'string').slice(0, 50) : []};
    out.push({id:typeof v.id === 'string' && v.id ? v.id.slice(0, 40) : uid('sv'), kind:v.kind, caseId:v.kind === 'search' ? null : typeof v.caseId === 'string' ? v.caseId : null, name:v.name.trim().slice(0, SV.NAME), s:c, at:+v.at || 0}); }
  return out.filter(v => v.kind === 'search' || v.caseId);
}
const SV_ACTS = {
  svSave:(id, v) => svSaveDlg(v),
  svOpen:id => svOpen(id),
  svDel:id => svDel(id),
};
