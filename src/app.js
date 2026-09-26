/* ==========================================================================
   Render loop, events, keyboard, boot
   ========================================================================== */
function applyPrefs(){ const h = document.documentElement, p = DB.prefs; h.dataset.theme = p.theme; h.dataset.size = p.size; h.dataset.density = p.density;
  const t = $('themeBtn'); if(t) t.innerHTML = ico(p.theme === 'dark' ? 'sun' : 'moon'); }
const isNarrow = () => window.innerWidth < 1440;
function renderMain(){
  const r = UI.route, el = $('main');
  const V = {help:viewHelp, home:viewHome, cases:viewCases, toolbox:viewToolbox, entities:viewEntities, feeds:viewIntel, decoder:viewDecoder, reference:viewReference, settings:viewSettings,
    detections:viewDetections, queries:viewQueries, notes:viewNotes, playbooks:viewPlaybooks, library:viewLibrary};
  if(cy && !(r.area === 'case' && r.tab === 'graph')){ cy.destroy(); cy = null; }
  const key = r.area + '/' + (r.tab || ''), sc = el.querySelector('.scroll'), keepY = renderMain.key === key && sc ? sc.scrollTop : 0; renderMain.key = key;
  try{ el.innerHTML = r.area === 'case' ? viewCase(r.tab) : (V[r.area] || viewHome)(); }
  catch(err){ console.error(err); el.innerHTML = `<div class="page"><div class="note red"><span class="ic">${ico('triangle-alert','sm')}</span><div><b>This screen failed to draw.</b> Your data is safe. <code class="mono">${esc(err.message)}</code></div></div></div>`; }
  if(keepY){ const s2 = el.querySelector('.scroll'); if(s2) s2.scrollTop = keepY; }
  if(r.area === 'case' && r.tab === 'graph') requestAnimationFrame(mountGraph);
  if(r.area === 'toolbox') paintBulk();
  if(r.area === 'queries') bindQueryPanel();
  if(r.area === 'detections') bindRuleEditor();
}
function renderAll(){ renderNav(); renderMain(); renderInsp(); $('inspBtn').classList.toggle('on', UI.inspOpen); }
const TITLES = {help:'Help', home:'Dashboard', cases:'Cases', toolbox:'Toolbox', entities:'Entities', feeds:'Threat Intel', decoder:'Decoder', reference:'Reference', settings:'Settings', detections:'Detections', queries:'Query library', notes:'Notes', playbooks:'Playbooks', library:'Library'};
function onRoute(){
  UI.route = parseHash(); $('side').classList.remove('open');
  document.title = (UI.route.area === 'case' ? theCase().name.split(' — ')[0] + ' · ' + CASE_TABS.find(t => t[0] === UI.route.tab)[1] : TITLES[UI.route.area] || 'OSINTrix') + ' — OSINTrix';
  const m = $('main'); m.classList.add('enter'); clearTimeout(onRoute.t); onRoute.t = setTimeout(() => m.classList.remove('enter'), 320);
  if(UI.route.area !== 'case' || UI.route.tab !== 'graph'){ UI.graph.mode = null; UI.graph.first = null; }
  if(UI.sel && UI.sel.kind === 'entry'){ const e = entryById(UI.sel.id); if(!e || e.caseId !== DB.active) UI.sel = null; }
  renderAll(); const s = $('main').querySelector('.scroll'); if(s) s.scrollTop = 0;
}
function animInsp(){ const i = $('insp'); i.classList.add('enter'); setTimeout(() => i.classList.remove('enter'), 260); }
function selectEntry(id, fromGraph){
  if(!UI.inspOpen) animInsp(); UI.sel = {kind:'entry', id}; UI.inspOpen = true; renderInsp(); $('inspBtn').classList.add('on');
  document.querySelectorAll('.ecard[aria-selected=true]').forEach(x => x.setAttribute('aria-selected', 'false'));
  const c = document.querySelector(`.ecard[data-id="${CSS.escape(id)}"]`); if(c) c.setAttribute('aria-selected', 'true');
  if(fromGraph) refreshGraphTools();
}
function select(kind, id){
  if(!UI.inspOpen) animInsp(); UI.sel = {kind, id}; UI.inspOpen = true; renderInsp(); $('inspBtn').classList.add('on');
  document.querySelectorAll('.ev[aria-selected=true]').forEach(x => x.setAttribute('aria-selected', 'false'));
  const ev = document.querySelector(`.ev[data-id="${CSS.escape(id)}"]`); if(ev) ev.setAttribute('aria-selected', 'true');
}
function promote(entId){
  const {k, v} = entSplit(entId), type = KIND_TO_TYPE[k]; if(!type) return;
  const t = TYPES[type], g = globalEnts().get(entId), src = g && g.recs.find(r => r.caseId === DB.active);
  entryDlg(null, {type, fields:{[t.fields[0][0]]:k === 'handle' ? v : v}, src:src ? src.id : ''});
}
function slug(s){ return (s || 'case').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40); }
function reportMd(){
  const c = theCase(), D = derive(), L = ['# ' + c.name, '', '_' + c.code + ' · ' + tz() + '_', '', '## Summary', '', c.scope, '', '## Vault', '', '| Type | Value | Priority | Verdict |', '|---|---|---|---|'];
  for(const e of D.entries) L.push('| ' + TYPES[e.type].label + ' | `' + primary(e) + '` | ' + e.priority + ' | ' + (entryVerdict(e) || '') + ' |');
  L.push('', '## Relationships', ''); for(const l of D.links) L.push('- ' + primary(entryById(l.a)) + ' — ' + l.label + ' → ' + primary(entryById(l.b)) + ' (confidence ' + l.conf + ')');
  L.push('', '## Chronology', ''); for(const r of D.recs.filter(r => r.ts)) L.push('- `' + E.fmtFull(r.ts, tz()) + '` ' + r.title);
  return L.join('\n');
}

document.addEventListener('click', ev => {
  if($('side').classList.contains('open') && !ev.target.closest('#side') && !ev.target.closest('[data-act=navToggle]')){ $('side').classList.remove('open'); return; }
  const t = ev.target.closest('[data-act]'); if(!t) return;
  const a = t.dataset.act, id = t.dataset.id, v = t.dataset.v;
  const needs = ['caseMenu','qDelAsk','rMenu','nMenu','nEdit','nColor','nColorPick','qStar','qEng','rStar','deleteCaseDlg','gLegend','gHide','star','toolPin','toolStar','toolEdit','pickType','pickColor','pickIcon','linkFrom','gZoom','gFit','gConnect','gEdit','gDelete','gCo','gPng'];
  if(needs.includes(a)) ev.preventDefault();
  switch(a){
    case 'navToggle': return $('side').classList.toggle('open');
    case 'welcomeDemo': closeWelcome(); return go(caseHash('c-lantern', 'overview'));
    case 'welcomeClose': closeWelcome(); return go('#/home');
    case 'showWelcome': return showWelcome();
    case 'palette': return palette();
    case 'theme': DB.prefs.theme = DB.prefs.theme === 'dark' ? 'light' : 'dark'; applyPrefs(); save(); return renderAll();
    case 'inspToggle': UI.inspOpen = !UI.inspOpen; return renderAll();
    case 'closeInsp': UI.inspOpen = false; UI.sel = null; renderInsp(); $('inspBtn').classList.remove('on'); return refreshGraphTools();
    case 'capture': return openCapture();
    case 'capSave': return capSave(false);
    case 'capSplit': return capSave(true);
    case 'sampleLine': $('capBody').value = '2026-09-14T09:03:15Z EventID 3 Image=C:\\Users\\Public\\svchost.exe DestinationIp=203.0.113.47 -> 203.0.113.47:4444'; $('capSrc').value = 'sysmon'; $('capHost').value = 'WS-FIN-07'; return capPreview();
    case 'dclose': return closeDlg();
    case 'newCase': return caseDlg();
    case 'editCase': return caseDlg(true);
    case 'archiveCase': { const c = theCase(); c.status = c.status === 'closed' ? 'active' : 'closed'; mutate((c.status === 'closed' ? 'archived ' : 'reopened ') + c.code); closeDlg(); renderAll(); return toast(c.status === 'closed' ? 'Case archived — find it under Cases' : 'Case reopened'); }
    case 'cf': UI.cf = v; return renderMain();
    case 'caseMenu': { const c = theCase(id), r0 = t.getBoundingClientRect(); if(!c) return; return showMenu(Math.max(8, r0.right - 220), r0.bottom + 6, [
      {label:'Open case', icon:'folder-open', fn:() => go(caseHash(c.id))},
      {label:'Edit details…', icon:'pencil', fn:() => { DB.active = c.id; caseDlg(true); }},
      {label:c.status === 'closed' ? 'Reopen' : 'Archive', icon:c.status === 'closed' ? 'archive-restore' : 'archive', fn:() => { c.status = c.status === 'closed' ? 'active' : 'closed'; c.updated = Date.now(); mutate((c.status === 'closed' ? 'archived ' : 'reopened ') + c.code); renderAll(); toast(c.status === 'closed' ? c.code + ' archived' : c.code + ' reopened'); }},
      {label:'Export as JSON', icon:'download', fn:() => clickAct('exportCase', c.id)},
      {sep:true}, {label:'Delete case…', icon:'trash-2', danger:true, fn:() => deleteCaseDlg(c.id)}], c.code); }
    case 'confirmOk': { const fn = UI.confirmFn; UI.confirmFn = null; closeDlg(); if(fn) fn(); return; }
    case 'deleteCaseDlg': return deleteCaseDlg(id || DB.active);
    case 'deleteCase': { const c = theCase(id); if(!c || $('delConfirm').value.trim() !== c.code) return;
      const snap = {c, entries:DB.entries.filter(e => e.caseId === c.id), links:DB.links.filter(l => l.caseId === c.id), records:DB.records.filter(r => r.caseId === c.id), notes:(DB.notes || []).filter(n => n.caseId === c.id), idx:DB.cases.indexOf(c)};
      DB.cases = DB.cases.filter(x => x !== c); DB.entries = DB.entries.filter(e => e.caseId !== c.id); DB.links = DB.links.filter(l => l.caseId !== c.id); DB.records = DB.records.filter(r => r.caseId !== c.id);
      if(DB.notes) DB.notes = DB.notes.filter(n => n.caseId !== c.id);
      if(!DB.cases.length) DB.cases.push({id:uid('c'), name:'Untitled case', code:'TN-2026-100', status:'active', owner:'You', created:Date.now(), updated:Date.now(), scope:'', color:CASE_COLORS[7], icon:'briefcase'});
      if(DB.active === c.id) DB.active = DB.cases[0].id; UI.sel = null; mutate('deleted case ' + c.code); closeDlg(); go('#/cases');
      return toast('Deleted ' + c.name, 'Undo', () => { DB.cases.splice(snap.idx, 0, snap.c); DB.entries.push(...snap.entries); DB.links.push(...snap.links); DB.records.push(...snap.records); if(DB.notes) DB.notes.push(...snap.notes); mutate('restored case ' + c.code); renderAll(); }); }
    case 'pickColor': window.__caseDraft.color = v; document.querySelectorAll('#sw button').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.v === v))); return;
    case 'pickIcon': window.__caseDraft.icon = v; document.querySelectorAll('#ip button').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.v === v))); return;
    case 'addEntry': return entryDlg();
    case 'pickType': entryDraft.type = v || null; entryDraft.fields = {}; return paintEntryDlg();
    case 'editEntry': return entryDlg(id);
    case 'selEntry': return selectEntry(id);
    case 'star': { ev.stopPropagation(); const e = entryById(id); e.starred = !e.starred; mutate((e.starred ? 'starred ' : 'unstarred ') + primary(e)); renderMain(); return renderInsp(); }
    case 'entryVerdict': { const e = entryById(id); setEntryVerdict(e, v); mutate('verdict ' + (v || 'cleared') + ' on ' + primary(e)); renderMain(); return renderInsp(); }
    case 'entryPrio': { const e = entryById(id); e.priority = v; mutate('priority ' + v + ' on ' + primary(e)); renderMain(); return renderInsp(); }
    case 'delEntry': { const e = entryById(id), gone = DB.links.filter(l => l.a === id || l.b === id);
      DB.entries = DB.entries.filter(x => x.id !== id); DB.links = DB.links.filter(l => !gone.includes(l)); UI.sel = null; mutate('deleted ' + primary(e)); renderAll();
      return toast('Deleted ' + primary(e), 'Undo', () => { DB.entries.push(e); DB.links.push(...gone); mutate('restored ' + primary(e)); renderAll(); }); }
    case 'linkFrom': return linkDlg({a:id});
    case 'selLink': return select('link', id);
    case 'editLink': return linkDlg({id});
    case 'delLink': { const l = DB.links.find(x => x.id === id); DB.links = DB.links.filter(x => x.id !== id); UI.sel = null; mutate('deleted relationship'); renderAll();
      return toast('Relationship deleted', 'Undo', () => { DB.links.push(l); mutate('restored relationship'); renderAll(); }); }
    case 'showInGraph': UI.sel = {kind:'entry', id}; return;
    case 'promote': return promote(id);
    case 'vcat': UI.vcat = v; if(UI.route.tab !== 'vault') return go(caseHash(DB.active, 'vault')); return renderMain();
    case 'selRec': { const r = recById(id); if(!r) return; if(r.caseId !== DB.active){ DB.active = r.caseId; UI.sel = {kind:'rec', id}; UI.inspOpen = true; return go(caseHash(r.caseId, 'timeline')); } return select('rec', id); }
    case 'selEnt': return select('ent', id);
    case 'selFeed': return select('feed', id);
    case 'entVerdict': if(v) DB.verdicts[id] = v; else delete DB.verdicts[id]; mutate('verdict on ' + entSplit(id).v); renderMain(); return renderInsp();
    case 'setT0': { const c = theCase(); c.t0 = c.t0 === id ? null : id; mutate('T0 changed'); return renderAll(); }
    case 'pivot': UI.pivot = id; UI.tlMode = 'events'; return go(caseHash(DB.active, 'timeline'));
    case 'pivotOff': UI.pivot = null; return renderMain();
    case 'facet': UI.facet[t.dataset.f] = UI.facet[t.dataset.f] === v ? null : v; return renderMain();
    case 'clearFilters': UI.facet = {}; UI.pivot = null; UI.q = ''; UI.ast = null; $('gq').value = ''; return renderMain();
    case 'tlMode': UI.tlMode = v; return renderMain();
    case 'goMal': UI.entKind = 'malicious'; return go('#/entities');
    case 'goCross': UI.entKind = 'cross'; return go('#/entities');
    case 'entKind': UI.entKind = v || null; return renderMain();
    case 'feedToCase': { const f = DB.feed.find(x => x.id === id); DB.records.push({id:uid('r'), caseId:DB.active, type:'evidence', title:f.title, body:f.body + (f.link ? '\n\nSource: ' + f.link : ''), tsRaw:'', tsZone:'explicit', ts:f.ts, source:'feed:' + f.source, host:'', tags:['intel'], ents:E.extract(f.title + ' ' + f.body), answer:'', addedBy:'You', addedAt:Date.now(), hash:''});
      mutate('added feed item'); hashRecords(); renderAll(); return toast('Added to ' + theCase().code); }
    case 'feedImport': return importFeedFile();
    case 'feedRefresh': return refreshFeeds();
    case 'intelOn': DB.prefs.liveFeeds = true; save(); closeDlg(); return refreshFeeds();
    case 'intelOff': DB.prefs.liveFeeds = false; mutate('feeds offline'); closeDlg(); renderAll(); return toast('Live feeds off — nothing will be fetched');
    case 'feedSources': return sourcesDlg();
    case 'srcToggle': { const s = DB.feedSources.find(x => x.id === id); s.on = t.checked; mutate('source ' + s.name); return; }
    case 'srcDel': DB.feedSources = DB.feedSources.filter(x => x.id !== id); mutate('removed source'); return sourcesDlg();
    case 'srcReset': DB.feedSources = DEFAULT_SOURCES.map(s => ({...s})); mutate('reset sources'); return sourcesDlg();
    case 'icat': UI.icat = v; return renderMain();
    case 'imatch': UI.imatch = !UI.imatch; return renderMain();
    /* toolbox */
    case 'tcat': UI.tcat = v; UI.tsub = null; return renderMain();
    case 'tview': UI.tview = v; DB.prefs.tview = v; save(); return renderMain();
    case 'tsub': UI.tsub = UI.tsub === v ? null : v; return renderMain();
    case 'toolPin': { const x = DB.tools.find(z => z.id === id); x.pinned = !x.pinned; mutate((x.pinned ? 'pinned ' : 'unpinned ') + x.name); return renderMain(); }
    case 'toolStar': { const x = DB.tools.find(z => z.id === id); x.starred = !x.starred; mutate((x.starred ? 'starred ' : 'unstarred ') + x.name); return renderMain(); }
    case 'toolEdit': return toolDlg(id);
    case 'toolAdd': return toolDlg();
    case 'toolDel': { const x = DB.tools.find(z => z.id === id); if(!x) return; DB.tools = DB.tools.filter(z => z.id !== id); if(x.seed) (DB.deletedSeed || (DB.deletedSeed = [])).push(x.url); if(UI.tpick) UI.tpick.delete(id); closeDlg(); mutate('deleted tool ' + x.name); renderAll();
      return toast('Deleted ' + x.name, 'Undo', () => { DB.tools.push(x); if(DB.deletedSeed) DB.deletedSeed = DB.deletedSeed.filter(u => u !== x.url); mutate('restored tool'); renderAll(); }); }
    case 'toolDelAsk': { const x = DB.tools.find(z => z.id === id); return confirmDlg('Delete ' + x.name + '?', x.seed ? 'It is a pre-added tool. It stays deleted, even when the app updates its tool list. You can undo right after.' : 'It will be removed from your toolbox. You can undo right after.', 'Delete tool', () => clickAct('toolDel', id)); }
    case 'toolPick': { const s = UI.tpick || (UI.tpick = new Set()); t.checked ? s.add(id) : s.delete(id); const c = t.closest('.tcard2'); if(c) c.classList.toggle('picked', t.checked); return paintBulk(); }
    case 'tqClear': UI.tq = ''; return renderMain();
    case 'toolTag': UI.tq = v; UI.tcat = 'all'; UI.tsub = null; return renderMain();
    case 'bulkAll': { const s = UI.tpick || (UI.tpick = new Set()); document.querySelectorAll('[data-act=toolPick]').forEach(i => { i.checked = true; s.add(i.dataset.id); const c = i.closest('.tcard2'); if(c) c.classList.add('picked'); }); return paintBulk(); }
    case 'bulkClear': UI.tpick = new Set(); return renderMain();
    case 'bulkStar': case 'bulkPin': { const k = a === 'bulkStar' ? 'starred' : 'pinned', xs = DB.tools.filter(z => UI.tpick.has(z.id)), on = !xs.every(z => z[k]); xs.forEach(z => z[k] = on); mutate((on ? '' : 'un') + k + ' ' + xs.length + ' tools'); renderAll(); return toast(xs.length + ' tool' + (xs.length > 1 ? 's ' : ' ') + (on ? (k === 'starred' ? 'starred' : 'added to quick launch') : (k === 'starred' ? 'unstarred' : 'removed from quick launch'))); }
    case 'bulkExport': { const xs = DB.tools.filter(z => UI.tpick.has(z.id)); return download('osintrix-tools.json', JSON.stringify(xs.map(z => ({name:z.name, url:z.url, parentCategory:z.cat, childCategory:z.sub, description:z.desc, tags:z.tags})), null, 2), 'application/json'); }
    case 'bulkDel': { const xs = DB.tools.filter(z => UI.tpick.has(z.id)); return confirmDlg('Delete ' + xs.length + ' tool' + (xs.length > 1 ? 's' : '') + '?', 'They will be removed from your toolbox. You can undo right after.', 'Delete ' + xs.length, () => {
      const prev = DB.tools.slice(), prevGone = (DB.deletedSeed || []).slice(); DB.tools = DB.tools.filter(z => !UI.tpick.has(z.id)); DB.deletedSeed = prevGone.concat(xs.filter(z => z.seed).map(z => z.url)); UI.tpick = new Set(); mutate('deleted ' + xs.length + ' tools'); renderAll();
      toast(xs.length + ' tools deleted', 'Undo', () => { DB.tools = prev; DB.deletedSeed = prevGone; mutate('restored tools'); renderAll(); }); }); }
    case 'importAll': return pickFile('.json,application/json', txt => { let d; try{ d = JSON.parse(txt); }catch(e){ return toast('That file is not JSON'); }
      if(!d || d.v !== 2 || !Array.isArray(d.cases) || !Array.isArray(d.entries) || !Array.isArray(d.records)) return toast('Not an OSINTrix backup — use a file from “Export everything”');
      confirmDlg('Replace everything with this backup?', 'Your current cases, notes, tools and rules in this browser are replaced by the ' + d.cases.length + ' case' + (d.cases.length === 1 ? '' : 's') + ' in the file. You can undo right after.', 'Import backup', async () => {
        const prev = DB; DB = d; DB.prefs = Object.assign({}, prev.prefs, d.prefs || {}); ensureTools(); ensureIntel(); ensureQueries(); ensureRules(); ensureNotes(); if(!DB.cases.some(c => c.id === DB.active)) DB.active = DB.cases[0] && DB.cases[0].id;
        await hashRecords(); ensurePositions(); mutate('imported backup'); UI.sel = null; applyPrefs(); renderAll(); toast('Backup imported', 'Undo', () => { DB = prev; mutate('undo import'); applyPrefs(); renderAll(); }); }); });
    case 'freshStart': return confirmDlg('Start fresh?', 'Deletes every case, vault entry, evidence record and note in this browser. Tools, queries, rules and settings stay. Export first if you might need them. You can undo right after.', 'Delete my cases', () => {
      const prev = JSON.parse(JSON.stringify(DB)); const c = {id:uid('c'), name:'My first case', code:'TN-2026-001', status:'active', owner:'You', created:Date.now(), updated:Date.now(), scope:'', color:CASE_COLORS[0], icon:'briefcase'};
      Object.assign(DB, {cases:[c], entries:[], links:[], records:[], notes:[], verdicts:{}, active:c.id}); UI.sel = null; mutate('started fresh'); go('#/home'); renderAll();
      toast('All cases deleted', 'Undo', () => { DB = prev; mutate('undo fresh start'); renderAll(); }); });
    case 'toolOpen': { const x = DB.tools.find(z => z.id === id); if(x){ x.uses++; save(); } return; }
    case 'toolImport': return pickFile('.json,application/json', txt => { let d; try{ d = JSON.parse(txt); }catch(e){ return toast('Not a JSON file'); }
      if(!Array.isArray(d)) return toast('Expected a list of tools, like tools.json'); let n = 0;
      for(const t of d){ if(!t || !t.name || !E.safeUrl(t.url) || DB.tools.some(x => x.url === t.url)) continue;
        DB.tools.push({id:uid('t'), name:String(t.name).slice(0, 80), url:t.url, cat:TOOL_CATS[t.parentCategory] ? t.parentCategory : 'osint', sub:t.childCategory || '', desc:String(t.description || '').slice(0, 400), tags:Array.isArray(t.tags) ? t.tags.slice(0, 8).map(String) : [], pinned:false, starred:false, added:Date.now(), uses:0}); n++; }
      mutate('imported ' + n + ' tools'); renderAll(); toast(n + ' tools imported'); });

    /* query library */
    case 'qcat': UI.qcat = v; return renderMain();
    case 'qStar': { const x = DB.queries.find(z => z.id === id); x.starred = !x.starred; mutate('star query'); return renderMain(); }
    case 'qLay': DB.prefs.qlay = v; save(); return renderMain();
    case 'rLay': if(ruleDirty()) return confirmDlg('Discard unsaved changes?', 'You have edits to this rule that are not saved yet.', 'Discard changes', () => clickAct('rLay2', v), true); DB.prefs.rlay = v; save(); return renderMain();
    case 'rLay2': DB.prefs.rlay = id; save(); return renderMain();
    case 'qSort': UI.qsd = UI.qsk === v ? -(UI.qsd || 1) : 1; UI.qsk = v; return renderMain();
    case 'rSort': UI.rsd = UI.rsk === v ? -(UI.rsd || -1) : (v === 'title' || v === 'technique' || v === 'type' ? 1 : -1); UI.rsk = v; return renderMain();
    case 'qClose': UI.qopen = false; return renderMain();
    case 'rClose': if(ruleDirty()) return confirmDlg('Discard unsaved changes?', 'You have edits to this rule that are not saved yet.', 'Discard changes', () => clickAct('rClose'), true); UI.ropen = false; return renderMain();
    case 'dtree': { const [tv, cv] = v.split('|'); UI.dtype = tv; UI.dcat = cv; return renderMain(); }
    case 'qRun': case 'qSel': UI.qsel = id; UI.qopen = true; renderMain(); { const m = document.querySelector('.wb-main'); if(m && window.innerWidth <= 1180) m.scrollIntoView({block:'start', behavior:'smooth'}); } return;
    case 'qDelAsk': return confirmDlg('Delete this query?', 'It will be removed from your library. You can undo right after.', 'Delete query', () => clickAct('qDel', id));
    case 'qNew': return queryDlg();
    case 'qEdit': return queryDlg(id);
    case 'qDel': { const x = DB.queries.find(z => z.id === id); DB.queries = DB.queries.filter(z => z.id !== id); closeDlg(); mutate('deleted query'); renderAll(); return toast('Deleted “' + x.name + '”', 'Undo', () => { DB.queries.push(x); mutate('restored query'); renderAll(); }); }
    case 'qEng': UI.runEng = v; document.querySelectorAll('.eng').forEach(b => { b.classList.toggle('on', b.dataset.v === v); b.setAttribute('aria-pressed', String(b.dataset.v === v)); }); return syncRun();
    case 'qCopy': return copyText($('qPrev').value);
    case 'qGo': { if(t.getAttribute('aria-disabled') === 'true' || !t.href){ ev.preventDefault(); return toast($('qRunHint').textContent || 'Fill the blanks first'); }
      const x = DB.queries.find(z => z.id === id), q = $('qPrev').value.trim(); x.uses++;
      (DB.queryLog || (DB.queryLog = [])).unshift({at:Date.now(), name:x.name, q, engine:UI.runEng, caseId:DB.active}); DB.queryLog.length = Math.min(DB.queryLog.length, 100);
      if($('qLog').checked) DB.records.push({id:uid('r'), caseId:DB.active, type:'note', title:'Searched ' + ENGINES[UI.runEng][0] + ': ' + x.name, body:q, tsRaw:new Date().toISOString(), tsZone:'explicit', ts:Date.now(), source:'query:' + UI.runEng, host:'', tags:['research'], ents:E.extract(q), answer:'', addedBy:'You', addedAt:Date.now(), hash:''});
      mutate('ran query ' + x.name); hashRecords(); setTimeout(() => { renderNav(); renderMain(); }, 50); return toast('Opened in ' + ENGINES[UI.runEng][0] + ($('qLog').checked ? ' · logged to ' + theCase().code : '')); }
    case 'qExport': return download('osintrix-queries.json', JSON.stringify(DB.queries.map(({id, uses, ...r}) => r), null, 2), 'application/json');
    case 'qImport': return pickFile('.json,application/json', txt => { let d; try{ d = JSON.parse(txt); }catch(e){ return toast('Not a JSON file'); } if(!Array.isArray(d)) return toast('Expected a list of queries'); let n = 0;
      for(const r of d){ const query = String(r.query || '').slice(0, 2000); if(!query || DB.queries.some(z => z.query === query)) continue;
        DB.queries.push({id:uid('q'), name:String(r.name || 'Imported query').slice(0, 120), desc:String(r.description || r.desc || '').slice(0, 400), query, cat:QCATS[r.category || r.cat] ? (r.category || r.cat) : 'custom', engines:(Array.isArray(r.engines) ? r.engines : ['google']).filter(e => ENGINES[e]).slice(0, 9).concat([]).filter((e, i, a) => a.indexOf(e) === i).length ? (r.engines || []).filter(e => ENGINES[e]) : ['google'], tags:Array.isArray(r.tags) ? r.tags.map(String).slice(0, 10) : [], starred:false, uses:0, custom:true}); n++; }
      mutate('imported ' + n + ' queries'); renderAll(); toast(n + ' queries imported'); });
    /* detections */
    case 'dtype': UI.dtype = v; UI.dcat = ''; return renderMain();
    case 'rSel': if(id === UI.rule && (UI.ropen || rLay() === 'ide')) return; if(ruleDirty()) return confirmDlg('Discard unsaved changes?', 'You have edits to this rule that are not saved yet.', 'Discard changes', () => clickAct('rSel', id), true); UI.rule = id; UI.ropen = true; renderMain(); { const r = document.querySelector('.wb-main'); if(r && window.innerWidth <= 1180) r.scrollIntoView({block:'start'}); } return;
    case 'rNew': { const r0 = t.getBoundingClientRect(); return showMenu(r0.left, r0.bottom + 6, [
      {label:'Sigma rule (log detection)', icon:'file-code', fn:() => newRule('sigma')}, {label:'YARA rule (file / memory)', icon:'binary', fn:() => newRule('yara')}], 'New rule'); }
    case 'rRevert': renderMain(); return toast('Changes discarded');
    case 'rMenu': { const r = DB.rules.find(z => z.id === id), r0 = t.getBoundingClientRect(); if(!r) return; return showMenu(Math.max(8, r0.right - 220), r0.bottom + 6, [
      {label:'Duplicate', icon:'copy', fn:() => clickAct('rDup', id)},
      {label:'Copy rule text', icon:'file-code', fn:() => clickAct('rCopy', id)},
      {label:'Download .' + (r.type === 'sigma' ? 'yml' : 'yar'), icon:'download', fn:() => clickAct('rExport', id)},
      {sep:true}, {label:'Delete rule', icon:'trash-2', danger:true, fn:() => confirmDlg('Delete “' + r.title + '”?', 'The rule is removed from your library. You can undo right after.', 'Delete rule', () => clickAct('rDel', id))}], 'Rule'); }
    case 'rStar': { const r = DB.rules.find(z => z.id === id); r.starred = !r.starred; mutate('star rule'); return renderMain(); }
    case 'rDel': { const r = DB.rules.find(z => z.id === id); if(!r) return; DB.rules = DB.rules.filter(z => z.id !== id); UI.rule = null; mutate('deleted rule'); renderAll();
      return toast('Deleted “' + r.title + '”', 'Undo', () => { DB.rules.unshift(r); UI.rule = r.id; mutate('restored rule'); renderAll(); }); }
    case 'rDup': { const r = DB.rules.find(z => z.id === id); const c2 = {...r, id:uid('r'), title:r.title + ' (copy)', created:Date.now(), modified:Date.now(), starred:false}; DB.rules.unshift(c2); UI.rule = c2.id; mutate('duplicated rule'); return renderMain(); }
    case 'rCopy': { const r = DB.rules.find(z => z.id === id); return copyText(ruleText(r, $('rCode') ? $('rCode').value : r.code)); }
    case 'rExport': { const r = DB.rules.find(z => z.id === id); return download(slug(r.title) + (r.type === 'sigma' ? '.yml' : '.yar'), ruleText(r, $('rCode') ? $('rCode').value : r.code), 'text/plain'); }
    case 'rExportAll': return download('osintrix-detections.json', JSON.stringify(DB.rules.map(r => ({type:r.type, title:r.title, description:r.desc, code:ruleText(r), severity:r.severity, category:r.category, technique:r.technique, author:r.author, platform:r.platform, tags:r.tags})), null, 2), 'application/json');
    case 'rImport': return importRules();
    case 'rFromCase': return ruleFromCase();
    /* notes */
    case 'nf': UI.nf = v; if(UI.route.area !== 'notes') return; return renderMain();
    case 'nTick': { const n = DB.notes.find(z => z.id === id); const L = n.text.split('\n'); L[+v] = L[+v].replace(/\[( |x|X)\]/, m => m === '[ ]' ? '[x]' : '[ ]'); n.text = L.join('\n'); n.updated = Date.now(); mutate('ticked a to-do'); renderNav(); const card = t.closest('.ntask'); if(card) card.classList.toggle('done', t.checked);
      const art = t.closest('.note-card'); if(art){ const tk = noteTasks(n), dn = tk.filter(x => x.done).length, pr = art.querySelector('.nprog i'), lab = art.querySelector('.nprog + span'); if(pr) pr.style.width = Math.round(dn / tk.length * 100) + '%'; if(lab) lab.textContent = dn + '/' + tk.length; } return; }
    case 'nEdit': return noteDlg(id);
    case 'nMenu': { const n = DB.notes.find(z => z.id === id), r0 = t.getBoundingClientRect(); return showMenu(r0.left - 180, r0.bottom + 4, [
      {label:n.pinned ? 'Unpin' : 'Pin', icon:'pin', fn:() => { n.pinned = !n.pinned; mutate('pin note'); renderAll(); }},
      {label:'Edit…', icon:'pencil', fn:() => noteDlg(id)},
      {label:'Colour', seg:NOTE_COLORS.map(([k]) => ({label:k[0].toUpperCase() + k.slice(1), on:n.color === k, fn:() => { n.color = k; mutate('note colour'); renderAll(); }}))},
      {label:'Duplicate', icon:'copy', fn:() => { DB.notes.unshift({...n, id:uid('n'), pinned:false, created:Date.now(), updated:Date.now()}); mutate('duplicated note'); renderAll(); }},
      {sep:true}, {label:'Delete', icon:'trash-2', danger:true, fn:() => clickAct('nDel', id)}]); }
    case 'nDel': { const n = DB.notes.find(z => z.id === id); DB.notes = DB.notes.filter(z => z.id !== id); closeDlg(); mutate('deleted note'); renderAll(); return toast('Note deleted', 'Undo', () => { DB.notes.push(n); mutate('restored note'); renderAll(); }); }
    case 'nColor': document.querySelectorAll('.ncolors.big button').forEach(b => b.setAttribute('aria-pressed', String(b === t))); UI.noteColorEdit = v; return;
    case 'nColorPick': UI.ncolor = v; t.parentElement.querySelectorAll('button').forEach(b => b.setAttribute('aria-pressed', String(b === t))); return;
    /* graph */
    case 'gConnect': UI.graph.mode = UI.graph.mode === 'connect' ? null : 'connect'; UI.graph.first = null; return renderMain();
    case 'gEdit': if(UI.sel && UI.sel.kind === 'entry') return entryDlg(UI.sel.id); if(UI.sel && UI.sel.kind === 'link') return linkDlg({id:UI.sel.id}); return;
    case 'gDelete': if(!UI.sel) return; { const b = document.createElement('button'); b.dataset.act = UI.sel.kind === 'entry' ? 'delEntry' : 'delLink'; b.dataset.id = UI.sel.id; document.body.appendChild(b); b.click(); b.remove(); } return;
    case 'gFit': return cy && cy.animate({fit:{padding:50}, duration:250});
    case 'gZoom': return cy && cy.animate({zoom:{level:cy.zoom() * +v, renderedPosition:{x:cy.width() / 2, y:cy.height() / 2}}, duration:150});
    case 'gLegend': UI.graph.legendMin = !UI.graph.legendMin; { const l = document.querySelector('.glegend'); if(l){ l.classList.toggle('min', UI.graph.legendMin); t.setAttribute('aria-expanded', String(!UI.graph.legendMin)); t.innerHTML = ico(UI.graph.legendMin ? 'chevron-right' : 'chevron-down','sm') + 'Legend &amp; filters'; } } return;
    case 'gCo': UI.graph.co = !UI.graph.co; return renderMain();
    case 'gHide': { const h = UI.graph.hide || (UI.graph.hide = new Set()); h.has(v) ? h.delete(v) : h.add(v); return renderMain(); }
    case 'gPng': if(!cy) return; { const b64 = cy.png({full:true, scale:2, bg:getComputedStyle(document.documentElement).getPropertyValue('--bg').trim()}); const a2 = document.createElement('a'); a2.href = b64; a2.download = slug(theCase().name) + '-graph.png'; a2.click(); return toast('Graph saved as PNG'); }
    /* misc */
    case 'decSample': UI.decIn = 'powershell.exe -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA'; return renderMain();
    case 'decSave': { const s = decodeChain(UI.decIn); draft.source = 'decoder'; return openCapture(s.length ? s[s.length - 1][1] : UI.decIn); }
    case 'pref': DB.prefs[t.dataset.k] = v; applyPrefs(); save(); return renderMain();
    case 'exportMd': return download(slug(theCase().name) + '-report.md', reportMd(), 'text/markdown');
    case 'exportCase': { const c = theCase(id); return download(slug(c.name) + '.json', JSON.stringify({format:'osintrix-case', v:2, case:c, entries:DB.entries.filter(e => e.caseId === c.id), links:DB.links.filter(l => l.caseId === c.id), records:DB.records.filter(r => r.caseId === c.id)}, null, 2), 'application/json'); }
    case 'exportAll': return download('osintrix-' + new Date().toISOString().slice(0, 10) + '.json', JSON.stringify(DB, null, 2), 'application/json');
    case 'resetDemo': { const prev = DB; DB = seedDB(); DB.prefs = prev.prefs; mutate('reset demo'); hashRecords(); UI.sel = null; renderAll(); return toast('Demo data reset', 'Undo', () => { DB = prev; mutate('undo reset'); renderAll(); }); }
  }
});
document.addEventListener('keydown', ev => { if((ev.key === 'Enter' || ev.key === ' ') && ev.target.matches('span[role=button][data-act], tr[data-act]')){ ev.preventDefault(); ev.target.click(); } });

document.addEventListener('submit', ev => {
  const f = ev.target.closest('form[data-form]'); if(!f) return; ev.preventDefault();
  const k = f.dataset.form;
  if(k === 'entry'){
    const d = entryDraft, t = TYPES[d.type], fields = {};
    f.querySelectorAll('[data-f]').forEach(i => { const v = i.value.trim(); if(v) fields[i.dataset.f] = v; });
    if(!fields[t.fields[0][0]]) return toast(t.fields[0][1] + ' is required');
    const tags = $('ef-tags').value.split(',').map(s => s.trim()).filter(Boolean), priority = $('ef-prio').value, notes = $('ef-notes').value.trim();
    if(d.id){ const e = entryById(d.id); Object.assign(e, {fields, tags, priority, notes}); mutate('edited ' + primary(e)); closeDlg(); renderAll(); return toast('Saved'); }
    const e = {id:uid('v'), caseId:DB.active, type:d.type, fields, priority, starred:false, tags, notes, src:d.src || '', created:Date.now(), pos:UI.graph.newPos || null};
    if(!e.pos && cy){ const ext = cy.extent(); e.pos = {x:(ext.x1 + ext.x2) / 2, y:(ext.y1 + ext.y2) / 2}; }
    UI.graph.newPos = null;
    if(!e.pos && DB.entries.some(x => x.caseId === DB.active && x.pos)){ const ps = DB.entries.filter(x => x.caseId === DB.active && x.pos).map(x => x.pos); e.pos = {x:Math.max(...ps.map(p => p.x)) + 90, y:ps.reduce((s, p) => s + p.y, 0) / ps.length}; }
    const lf = UI.graph.linkFrom; DB.entries.push(e); mutate('added ' + primary(e)); closeDlg(); UI.sel = {kind:'entry', id:e.id}; UI.inspOpen = true; renderAll();
    if(lf && entryById(lf)){ setTimeout(() => linkDlg({a:lf, b:e.id}), 60); }
    return toast(t.label + ' added to the vault' + (UI.route.tab === 'graph' ? ' and the graph' : ''));
  }
  if(k === 'case'){
    const st = window.__caseDraft, name = $('cName').value.trim(); if(!name) return;
    if(f.dataset.edit){ const c = theCase(); Object.assign(c, {name, scope:$('cScope').value.trim(), status:$('cStatus').value, color:st.color, icon:st.icon, updated:Date.now()}); mutate('edited case'); closeDlg(); return renderAll(); }
    const c = {id:uid('c'), name, code:'TN-2026-' + String(13 + DB.cases.length).padStart(3, '0'), status:'active', owner:'You', created:Date.now(), updated:Date.now(), scope:$('cScope').value.trim(), color:st.color, icon:st.icon};
    DB.cases.push(c); DB.active = c.id; mutate('created case ' + c.code); closeDlg(); return go(caseHash(c.id));
  }
  if(k === 'tool'){
    const url = $('tUrl').value.trim(); if(!E.safeUrl(url)) return toast('The address must start with http:// or https://');
    const vals = {name:$('tName').value.trim(), url, cat:$('tCat').value, sub:$('tSub').value, desc:$('tDesc').value.trim(), tags:$('tTags').value.split(',').map(s => s.trim()).filter(Boolean)};
    if(f.dataset.id){ Object.assign(DB.tools.find(x => x.id === f.dataset.id), vals); mutate('edited tool ' + vals.name); }
    else { DB.tools.push({id:uid('t'), ...vals, pinned:false, starred:false, added:Date.now(), uses:0}); mutate('added tool ' + vals.name); }
    closeDlg(); renderAll(); return toast(f.dataset.id ? 'Tool saved' : vals.name + ' added to the toolbox');
  }
  if(k === 'link'){
    const a = $('lA').value, b = $('lB').value, label = $('lL').value.trim(); if(!label) return; if(a === b) return toast('Pick two different entries');
    if(f.dataset.id) Object.assign(DB.links.find(l => l.id === f.dataset.id), {a, b, label, conf:+$('lC').value, src:$('lS').value});
    else DB.links.push({id:uid('l'), caseId:DB.active, a, b, label, conf:+$('lC').value, src:$('lS').value});
    mutate('relationship ' + label); closeDlg(); renderAll(); return toast('Relationship saved');
  }
  if(k === 'query'){ const engs = [...document.querySelectorAll('[data-eng]')].filter(i => i.checked).map(i => i.dataset.eng);
    const vals = {name:$('qN').value.trim().slice(0, 120), query:$('qQ').value.trim().slice(0, 2000), desc:$('qD').value.trim().slice(0, 400), cat:$('qC').value, tags:$('qT').value.split(',').map(s => s.trim()).filter(Boolean), engines:engs.length ? engs : ['google']};
    if(!vals.name || !vals.query) return;
    if(f.dataset.id) Object.assign(DB.queries.find(z => z.id === f.dataset.id), vals); else DB.queries.unshift({id:uid('q'), ...vals, starred:false, uses:0, custom:true});
    mutate('saved query ' + vals.name); closeDlg(); renderAll(); return toast('Query saved'); }
  if(k === 'rule'){ const r = DB.rules.find(z => z.id === f.dataset.id); if(!r) return;
    Object.assign(r, {title:$('rTitle').value.trim() || r.title, severity:$('rSev').value, technique:$('rTech').value.trim().toUpperCase(), caseId:$('rCase').value || null, desc:$('rDesc').value.trim(), code:$('rCode').value,
      platform:$('rPlat').value.trim(), author:$('rAuthor').value.trim(), tags:$('rTags').value.split(',').map(x => x.trim()).filter(Boolean).slice(0, 20), modified:Date.now()});
    mutate('saved rule ' + r.title); renderAll(); const iss = validateRule(r.type, r.code, r.title); return toast(iss.length ? 'Saved — with ' + iss.length + ' structure warning' + (iss.length > 1 ? 's' : '') : 'Rule saved'); }
  if(k === 'nQuick'){ const ta = f.querySelector('textarea'), text = ta.value.trim(); if(!text) return;
    DB.notes.unshift({id:uid('n'), caseId:f.dataset.case || null, color:UI.ncolor || 'yellow', pinned:false, text:text.slice(0, 4000), due:'', created:Date.now(), updated:Date.now()});
    mutate('added note'); renderAll(); const x = document.querySelector('.nquick textarea'); if(x) x.focus(); return; }
  if(k === 'note'){ const n = DB.notes.find(z => z.id === f.dataset.id); Object.assign(n, {text:$('nText').value.slice(0, 4000), caseId:$('nCase').value || null, due:$('nDue').value, pinned:$('nPin').checked, color:UI.noteColorEdit || n.color, updated:Date.now()});
    UI.noteColorEdit = null; mutate('edited note'); closeDlg(); return renderAll(); }
  if(k === 'src'){ const url = $('srcUrl').value.trim(); if(!E.safeUrl(url)) return toast('Use an http(s) feed address'); DB.feedSources.push({id:uid('s'), name:$('srcName').value.trim().slice(0, 60), url, on:true, status:'', last:0}); mutate('added source'); return sourcesDlg(); }
  if(k === 'answer'){ const r = recById(f.dataset.id); r.answer = $('ansIn').value.trim(); mutate('answered a question'); renderAll(); return toast('Answer saved'); }
  if(k === 'addQ'){ const q = $('newQ').value.trim(); if(!q) return;
    DB.records.push({id:uid('q'), caseId:DB.active, type:'lead', title:q, body:'', tsRaw:'', ts:null, source:'checklist', host:'', tags:[], ents:E.extract(q), answer:'', addedBy:'You', addedAt:Date.now(), hash:''});
    mutate('added question'); renderAll(); $('newQ').focus(); }
});
let tq = null;
document.addEventListener('input', ev => {
  const t = ev.target, keep = id => { const x = $(id); if(x){ x.focus(); x.setSelectionRange(x.value.length, x.value.length); } };
  if(t.id === 'capBody'){ clearTimeout(tq); tq = setTimeout(capPreview, 150); return; }
  if(t.id === 'vq'){ UI.vq = t.value; clearTimeout(tq); tq = setTimeout(() => { renderMain(); keep('vq'); }, 160); return; }
  if(t.id === 'tq'){ UI.tq = t.value; clearTimeout(tq); tq = setTimeout(() => { renderMain(); keep('tq'); }, 160); return; }
  if(t.id === 'qq'){ UI.qq = t.value; clearTimeout(tq); tq = setTimeout(() => { renderMain(); keep('qq'); }, 160); return; }
  if(t.id === 'dq'){ UI.dq = t.value; clearTimeout(tq); tq = setTimeout(() => { renderMain(); keep('dq'); }, 160); return; }
  if(t.id === 'nqs'){ UI.nq = t.value; clearTimeout(tq); tq = setTimeout(() => { renderMain(); keep('nqs'); }, 160); return; }
  if(t.matches && t.matches('.nquick textarea')){ t.style.height = 'auto'; t.style.height = Math.min(220, t.scrollHeight) + 'px'; return; }
  if(t.id === 'iq'){ UI.iq = t.value; clearTimeout(tq); tq = setTimeout(() => { renderMain(); keep('iq'); }, 160); return; }
  if(t.id === 'refQ'){ UI.refQ = t.value; clearTimeout(tq); tq = setTimeout(() => { renderMain(); keep('refQ'); }, 160); return; }
  if(t.id === 'decIn'){ UI.decIn = t.value; clearTimeout(tq); tq = setTimeout(() => { renderMain(); keep('decIn'); }, 300); return; }
  if(t.id === 'gq'){ clearTimeout(tq); tq = setTimeout(() => { UI.q = t.value.trim(); UI.ast = E.parseQuery(UI.q); if(UI.q && !(UI.route.area === 'case' && UI.route.tab === 'timeline')){ UI.tlMode = 'events'; go(caseHash(DB.active, 'timeline')); } else renderMain(); }, 200); }
});
document.addEventListener('change', ev => { if(ev.target.id === 'qcatSel'){ UI.qcat = ev.target.value; UI.qsel = null; return renderMain(); } if(ev.target.id === 'dsev'){ UI.dsev = ev.target.value; return renderMain(); } if(ev.target.id === 'isrc'){ UI.isrc = ev.target.value; return renderMain(); } if(ev.target.id === 'tSort'){ UI.tsort = ev.target.value; return renderMain(); } if(ev.target.dataset.pref){ DB.prefs[ev.target.dataset.pref] = ev.target.value; mutate('time zone'); renderAll(); } });
$('scrim').addEventListener('mousedown', ev => { if(ev.target.id === 'scrim') closeDlg(); });

document.addEventListener('keydown', ev => {
  const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(ev.target.tagName), dlg = !$('scrim').hidden;
  if(ev.key === 'Escape'){ if(!$('welcome').hidden) return closeWelcome(); if(dlg) return closeDlg(); if($('side').classList.contains('open')) return $('side').classList.remove('open'); if(typing) return ev.target.blur();
    if(UI.route.area === 'queries' && UI.qopen && qLay() !== 'ide') return clickAct('qClose');
    if(UI.route.area === 'detections' && UI.ropen && rLay() !== 'ide') return clickAct('rClose');
    if(UI.graph.mode){ UI.graph.mode = null; UI.graph.first = null; return renderMain(); } if(UI.sel){ UI.sel = null; if(isNarrow()) UI.inspOpen = false; return renderAll(); } return; }
  if((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === 'k'){ ev.preventDefault(); return palette(); }
  if((ev.ctrlKey || ev.metaKey) && ev.key === 'Enter' && ev.target.matches('.nquick textarea')){ ev.preventDefault(); return ev.target.form.requestSubmit(); }
  if((ev.ctrlKey || ev.metaKey) && ev.key === 'Enter' && $('capBody')){ ev.preventDefault(); return capSave(false); }
  if(dlg){ if(ev.key === 'Tab'){ const f = [...$('dlg').querySelectorAll('button,input,select,textarea,a[href]')].filter(x => !x.disabled); if(f.length){ const i = f.indexOf(document.activeElement);
      if(ev.shiftKey && i <= 0){ ev.preventDefault(); f[f.length - 1].focus(); } else if(!ev.shiftKey && i === f.length - 1){ ev.preventDefault(); f[0].focus(); } } } return; }
  if(typing || ev.ctrlKey || ev.metaKey || ev.altKey) return;
  if(ev.key === 'n' || ev.key === 'N'){ ev.preventDefault(); return openCapture(); }
  if(ev.key === 'e'){ ev.preventDefault(); return entryDlg(); }
  if(ev.key === '/'){ ev.preventDefault(); return $('gq').focus(); }
  if((ev.key === 'Delete' || ev.key === 'Backspace') && UI.route.tab === 'graph' && UI.sel){ ev.preventDefault(); document.querySelector('[data-act=gDelete]').click(); }
  if(/^[1-6]$/.test(ev.key) && UI.route.area === 'case') return go(caseHash(DB.active, CASE_TABS[+ev.key - 1][0]));
});
window.addEventListener('hashchange', onRoute);
let rz = null; window.addEventListener('resize', () => { clearTimeout(rz); rz = setTimeout(() => { if(cy) cy.resize(); }, 120); });

function showWelcome(){
  const w = $('welcome'); w.hidden = false;
  w.innerHTML = `<div class="wcard">${logoMark(76)}
    <h1 id="wTitle">Follow every <span>thread.</span></h1>
    <p>OSINTrix is an investigation workspace for OSINT analysts and security researchers. Cases, evidence, entities and relationships — in one place, entirely in your browser.</p>
    <div class="wfeat">
      <div><span class="ic" style="color:var(--accent);background:var(--accent-soft)">${ico('layers')}</span><b>Cases are vaults</b><span>People, handles, wallets, domains and IPs, each with their own fields, priority and evidence.</span></div>
      <div><span class="ic" style="color:var(--amber);background:var(--amber-soft)">${ico('clock')}</span><b>Evidence becomes a timeline</b><span>Paste any log or post. Indicators, timestamps and observations come out on their own.</span></div>
      <div><span class="ic" style="color:var(--t-identity);background:color-mix(in srgb,var(--t-identity) 15%,transparent)">${ico('waypoints')}</span><b>Draw the connections</b><span>A graph you can drag, edit and export — every link carries its confidence and its proof.</span></div>
    </div>
    <div class="wacts"><button class="btn primary" data-act="welcomeDemo">${ico('crosshair','sm')}Explore the demo case</button><button class="btn" data-act="welcomeClose">Go to Dashboard</button></div>
    <div class="wnote"><i></i>Runs fully offline. Nothing you enter ever leaves this browser.</div></div>`;
  const b = w.querySelector('[data-act=welcomeDemo]'); if(b) b.focus();
}
function closeWelcome(){ $('welcome').hidden = true; try{ localStorage.setItem('osintrix:welcomed', '1'); }catch(e){} }
(async function boot(){
  $('splash').innerHTML = logoMark(64); $('brand').innerHTML = logoMark(32) + `<div class="txt">${wordmark()}<small>${esc(BRAND.tagline)}</small></div>`; $('fav').href = FAVICON;
  DB = load() || seedDB();
  UI.inspOpen = false; UI.graph.legendMin = window.innerWidth < 1100;
  if(window.innerWidth <= 760) $('gq').placeholder = 'Search this case';
  ensureTools(); ensureIntel(); ensureQueries(); ensureRules(); ensureNotes(); applyPrefs(); await hashRecords(); ensurePositions(); flush(); onRoute();
  let seen = false; try{ seen = !!localStorage.getItem('osintrix:welcomed'); }catch(e){}
  setTimeout(() => { $('splash').classList.add('out'); setTimeout(() => $('splash').remove(), 320); if(!seen) showWelcome(); }, 350);
})();

function newRule(type){ ensureRules(); const now = Date.now(); const r = {id:uid('r'), type, title:type === 'sigma' ? 'New Sigma rule' : 'New YARA rule', desc:'', code:RULE_TPL[type].replace('00000000-0000-4000-8000-000000000000', crypto.randomUUID ? crypto.randomUUID() : uid('sig')), severity:'medium', category:'', technique:'', author:'You', platform:'', tags:[], refs:[], created:now, modified:now, starred:false, caseId:null};
  DB.rules.unshift(r); UI.rule = r.id; UI.ropen = true; UI.dtype = 'all'; UI.dcat = ''; mutate('new rule'); if(UI.route.area !== 'detections') go('#/detections'); else renderMain(); setTimeout(() => { const x = $('rTitle'); if(x){ x.focus(); x.select(); } }, 50); }
function copyText(s){ if(navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(s).then(() => toast('Copied'), () => toast('Clipboard blocked by the browser')); else toast('Clipboard not available'); }

function confirmDlg(title, body, label, fn, neutral){
  UI.confirmFn = () => { if(neutral){ const f = document.querySelector('form.rx'); if(f) f.classList.remove('dirty'); } fn(); };
  openDlg(`<div class="cdlg"><span class="cdlg-ic${neutral ? ' n' : ''}">${ico(neutral ? 'triangle-alert' : 'trash-2')}</span><h2 id="cdT">${esc(title)}</h2><p>${esc(body)}</p>
    <footer><button class="btn" data-act="dclose">Cancel</button><button class="btn ${neutral ? 'primary' : 'dangerbtn'}" data-act="confirmOk" autofocus>${esc(label)}</button></footer></div>`);
  $('dlg').classList.add('narrow'); $('dlg').setAttribute('aria-labelledby', 'cdT');
}
