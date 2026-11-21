/* ==========================================================================
   Integrity: what comes in from files is checked before it touches the
   workspace, and what the app writes never destroys what it cannot read.
   - checkImport()   shape and ID checks for backups, case files and tool lists
   - rekeyFiles()    imported attachments always get fresh IDs, so an import
                     can never overwrite another case's evidence bytes
   - cleanTitle()    menu titles keep our icon and text, nothing else
   - sniffKind()     what a stored file really is, from its first bytes
   ========================================================================== */
/* An ID may be anything a real export contains, but never a character that can
   end an HTML attribute or start markup. */
const SAFE_ID = /^[^"'<>&`\s\\]{1,512}$/;
const BAD_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const isObj = x => x && typeof x === 'object' && !Array.isArray(x);

function checkTree(root, errs, max = 3e6){
  let n = 0;
  (function walk(o, path, depth){
    if(errs.length > 4 || !o || typeof o !== 'object') return;
    if(depth > 24){ errs.push('nested too deeply at ' + path); return; }
    for(const k of Object.keys(o)){
      if(++n > max){ errs.push('too many items'); return; }
      const v = o[k], p = path + (Array.isArray(o) ? '[' + k + ']' : '.' + k);
      if(BAD_KEYS.has(k)){ errs.push('forbidden key ' + p); continue; }
      if((k === 'id' || /Id$/.test(k) || (/\.links\[\d+\]$/.test(path) && (k === 'a' || k === 'b' || k === 'src'))) && v != null && v !== ''){
        if(!(typeof v === 'string' || typeof v === 'number') || !SAFE_ID.test(String(v))) errs.push('invalid ID at ' + p);
      }
      if(v && typeof v === 'object') walk(v, p, depth + 1);
    }
  })(root, '', 0);
}
const need = (errs, ok, msg) => { if(!ok) errs.push(msg); };
function checkItems(errs, list, name, req){
  if(list == null) return;
  if(!Array.isArray(list)){ errs.push(name + ' is not a list'); return; }
  list.forEach((x, i) => { if(errs.length > 4) return;
    if(!isObj(x)){ errs.push(name + '[' + i + '] is not an object'); return; }
    for(const [k, t] of Object.entries(req)){ const v = x[k];
      if(t === 'id'){ if(typeof v !== 'string' && typeof v !== 'number') errs.push(name + '[' + i + '].' + k + ' is missing'); }
      else if(t === 'str?'){ if(v != null && typeof v !== 'string') errs.push(name + '[' + i + '].' + k + ' must be text'); }
      else if(t === 'str'){ if(typeof v !== 'string') errs.push(name + '[' + i + '].' + k + ' must be text'); }
      else if(t === 'obj?'){ if(v != null && !isObj(v)) errs.push(name + '[' + i + '].' + k + ' must be an object'); }
      else if(t === 'arr?'){ if(v != null && !Array.isArray(v)) errs.push(name + '[' + i + '].' + k + ' must be a list'); }
      else if(t === 'num?'){ if(v != null && typeof v !== 'number') errs.push(name + '[' + i + '].' + k + ' must be a number'); }
    } });
}
const CASE_REQ = {id:'id', name:'str', code:'str?', status:'str?', scope:'str?', color:'str?', icon:'str?'};
const ENTRY_REQ = {id:'id', caseId:'id', type:'str', fields:'obj?', tags:'arr?', notes:'str?'};
const REC_REQ = {id:'id', caseId:'id', title:'str?', body:'str?', host:'str?', source:'str?', ts:'num?', tags:'arr?', ents:'arr?', att:'arr?'};
const LINK_REQ = {id:'id', a:'id', b:'id', label:'str?'};
function checkAtt(errs, recs){
  for(const r of recs || []) for(const a of (r && r.att) || []){
    if(!isObj(a) || typeof a.name !== 'string'){ errs.push('an attachment on ' + (r.id || 'a record') + ' is malformed'); return; }
  }
}
function checkEntryTypes(errs, entries){
  for(const e of entries || []){ if(isObj(e) && typeof e.type === 'string' && typeof TYPES !== 'undefined' && !TYPES[e.type]){ errs.push('unknown entry type "' + e.type.slice(0, 30) + '"'); return; } }
}
/* kind: 'backup' | 'case' | 'tools' */
function checkImport(d, kind){
  const errs = [];
  if(kind === 'tools'){
    if(!Array.isArray(d)) return ['expected a list of tools'];
    checkTree(d, errs);
    return errs;
  }
  if(!isObj(d)) return ['the file does not hold an object'];
  checkTree(d, errs);
  if(kind === 'backup'){
    need(errs, d.v === 2, d.v > 2 ? 'made by a newer version of OSINTrix' : 'unknown backup version');
    checkItems(errs, d.cases, 'cases', CASE_REQ); checkItems(errs, d.entries, 'entries', ENTRY_REQ);
    checkItems(errs, d.records, 'records', REC_REQ); checkItems(errs, d.links, 'links', LINK_REQ);
    checkItems(errs, d.tools, 'tools', {id:'id', name:'str', url:'str'});
    checkItems(errs, d.notes, 'notes', {id:'id'}); checkItems(errs, d.rules, 'rules', {id:'id'});
    checkItems(errs, d.trash, 'trash', {id:'id', kind:'str'});
    need(errs, d.verdicts == null || isObj(d.verdicts), 'verdicts must be an object');
    need(errs, d.prefs == null || isObj(d.prefs), 'settings must be an object');
    checkEntryTypes(errs, d.entries); checkAtt(errs, d.records);
    for(const t of d.tools || []) if(isObj(t) && typeof t.url === 'string' && t.url && !E.safeUrl(t.url)){ errs.push('a tool link is not http(s): ' + String(t.name).slice(0, 40)); break; }
  } else if(kind === 'case'){
    need(errs, isObj(d.case), 'no case in the file');
    if(isObj(d.case)) checkItems(errs, [d.case], 'case', CASE_REQ);
    checkItems(errs, d.entries, 'entries', {id:'id', type:'str', fields:'obj?', tags:'arr?'});
    checkItems(errs, d.records, 'records', {id:'id', title:'str?', body:'str?', ts:'num?', tags:'arr?', ents:'arr?', att:'arr?'});
    checkItems(errs, d.links, 'links', {a:'id', b:'id', label:'str?'});
    checkEntryTypes(errs, d.entries); checkAtt(errs, d.records);
  }
  if(d.files != null && !isObj(d.files)) errs.push('files must be an object');
  return errs;
}
/* Fill in what older or hand-made files leave out, so every screen can rely on it. */
function normRecord(r){
  r.title = String(r.title || 'Untitled record'); r.body = String(r.body || ''); r.type = ['evidence','finding','lead','note'].includes(r.type) ? r.type : 'evidence';
  r.tags = Array.isArray(r.tags) ? r.tags.map(String) : []; r.att = Array.isArray(r.att) ? r.att : [];
  r.ents = Array.isArray(r.ents) ? r.ents.filter(e => e && typeof e.k === 'string' && typeof e.v === 'string') : E.extract(r.body);
  r.host = String(r.host || ''); r.source = String(r.source || ''); if(typeof r.ts !== 'number') r.ts = null; r.answer = String(r.answer || ''); if(r.tsShift != null && (typeof r.tsShift !== 'number' || !isFinite(r.tsShift) || Math.abs(r.tsShift) > 864e5 * 2 || r.ts == null)) delete r.tsShift;   // a clock correction: a number of ms within ±2 days, on a timed event
  return r;
}
function normEntry(e){ e.fields = isObj(e.fields) ? Object.fromEntries(Object.entries(e.fields).map(([k, v]) => [k, String(v == null ? '' : v)])) : {}; e.tags = Array.isArray(e.tags) ? e.tags.map(String) : []; e.notes = String(e.notes || ''); e.priority = ['low', 'medium', 'high', 'critical'].includes(e.priority) ? e.priority : 'medium'; e.starred = !!e.starred; return e; }
/* values that are drawn as labels or classes must be one of the known ones */
function normCase(c){ c.status = ['active', 'review', 'closed'].includes(c.status) ? c.status : 'active'; c.name = String(c.name || 'Untitled case'); c.code = String(c.code || 'CASE').slice(0, 40); c.scope = String(c.scope || ''); c.color = /^#[0-9a-f]{3,8}$/i.test(c.color) ? c.color : '#5468ff'; c.icon = /^[a-z0-9-]{1,40}$/.test(c.icon) ? c.icon : 'briefcase'; c.autoLook = false; if(c.ach != null) c.ach = normAch(c.ach); if(c.ach === null) delete c.ach; return c; }
/* competing-hypotheses data: ids are plain, marks are known codes, text is capped */
function normAch(A){ if(!A || typeof A !== 'object') return null; const sid = v => typeof v === 'string' && /^[\w-]{1,60}$/.test(v) ? v : null, arr = v => Array.isArray(v) ? v.filter(x => x && typeof x === 'object') : [];
  const hyps = arr(A.hyps).slice(0, 50).map(h => ({id:sid(h.id) || uid('h'), t:String(h.t || '').slice(0, 400), status:['open', 'rejected', 'likely'].includes(h.status) ? h.status : 'open', note:String(h.note || '').slice(0, 4000)}));
  const ev = arr(A.ev).slice(0, 500).map(x => ({id:sid(x.id) || uid('e'), t:String(x.t || '').slice(0, 400), rec:sid(x.rec), cred:[1, 2, 3].includes(+x.cred) ? +x.cred : 2, rel:[1, 2, 3].includes(+x.rel) ? +x.rel : 2}));
  const H = new Set(hyps.map(h => h.id)), m = {}, codes = ['CC', 'C', 'N', 'I', 'II', 'NA'];
  for(const e of ev){ const row = A.m && typeof A.m === 'object' && A.m[e.id]; if(!row || typeof row !== 'object') continue; m[e.id] = {}; for(const [h, v] of Object.entries(row)) if(H.has(h) && codes.includes(v)) m[e.id][h] = v; }
  return {hyps, ev, m}; }
function normLink(l){ l.conf = [1, 2, 3].includes(+l.conf) ? +l.conf : 1; l.label = String(l.label || 'related to').slice(0, 120); return l; }
function normVerdicts(v){ const o = {}; if(v && typeof v === 'object') for(const [k, x] of Object.entries(v)) if(typeof k === 'string' && k.length < 2100 && ['malicious', 'suspicious', 'benign'].includes(x)) o[k] = x; return o; }
function importRefused(what, errs){
  console.warn('Import refused:', errs);
  toast(what + ' was not imported: ' + errs[0] + (errs.length > 1 ? ' (+' + (errs.length - 1) + ' more)' : ''));
}

/* Imported files always get fresh IDs; every att[] reference in the imported
   data is rewritten to match. Returns the number of files stored. */
async function rekeyFiles(files, ...holders){
  const map = new Map();
  for(const fid of Object.keys(files || {})) map.set(fid, uid('f'));
  (function walk(o, depth){
    if(!o || typeof o !== 'object' || depth > 24) return;
    if(Array.isArray(o.att)) for(const a of o.att) if(isObj(a)) a.id = map.get(a.id) || uid('f');
    for(const v of Object.values(o)) if(v && typeof v === 'object') walk(v, depth + 1);
  })(holders, 0);
  const renamed = {}; for(const [old, url] of Object.entries(files || {})) renamed[map.get(old)] = url;
  return await filesFromImport(renamed);
}

/* Menu titles: keep the leading icon our code drew and the plain text; drop anything else. */
function cleanTitle(html){
  if(!html) return '';
  const tpl = document.createElement('template'); tpl.innerHTML = String(html);
  const svg = tpl.content.querySelector('svg'), text = tpl.content.textContent || '';
  let icon = '';
  if(svg){ const s = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    for(const a of ['class', 'viewBox', 'fill', 'stroke', 'stroke-linecap', 'stroke-linejoin', 'stroke-width']) if(svg.hasAttribute(a)) s.setAttribute(a, svg.getAttribute(a));
    for(const el of svg.querySelectorAll('path,circle,rect,line,polyline,polygon,ellipse')){ const c = document.createElementNS('http://www.w3.org/2000/svg', el.tagName.toLowerCase());
      for(const a of ['d', 'cx', 'cy', 'r', 'rx', 'ry', 'x', 'y', 'x1', 'y1', 'x2', 'y2', 'width', 'height', 'points']) if(el.hasAttribute(a)) c.setAttribute(a, el.getAttribute(a));
      s.appendChild(c); }
    s.setAttribute('aria-hidden', 'true'); icon = s.outerHTML; }
  return icon + esc(text);
}

/* What a stored file really is: by its bytes, not by the name or type it came with. */
async function sniffKind(blob){
  const head = new Uint8Array(await blob.slice(0, 512).arrayBuffer()), s = new TextDecoder('latin1').decode(head);
  if(s.startsWith('%PDF-')) return 'pdf';
  if(/^\s*(<!doctype|<html|<head|<body|<script|<svg|<\?xml|<iframe|<!--)/i.test(s) || /<script|<html|<svg|<iframe|<meta/i.test(s)) return 'markup';
  if(head[0] === 0xFF && head[1] === 0xD8 || s.startsWith('\x89PNG') || s.startsWith('GIF8') || s.slice(8, 12) === 'WEBP') return 'image';
  if(/^MIME-Version:|^From:|^Content-Type:/im.test(s)) return 'markup';
  let bin = 0; for(const b of head) if(b < 9 || b > 13 && b < 32) bin++;
  return bin > head.length * .1 ? 'binary' : 'text';
}

/* Shown instead of the app when the stored workspace cannot be used. Nothing is
   written until the person picks an option. */
function recoveryScreen(copies){
  const c = copies[0] || {}, w = $('welcome'); w.hidden = false; w.classList.add('lockscr');
  w.innerHTML = `<div class="wcard lockcard recover">${logoMark(56)}<h1 id="wTitle" style="font-size:calc(26px * var(--ts,1))">Your workspace needs attention</h1>
    <p>OSINTrix found saved data in this browser but did not open it, because ${esc(c.why || 'it could not be read')}. Nothing has been changed or deleted.</p>
    ${c.newer ? '<p>Open it with the newer version of OSINTrix you used last, or download it to keep a copy.</p>' : '<p>Download it first to keep a copy. If you have an exported backup, you can restore it after starting fresh.</p>'}
    <div class="recover-a"><button class="btn primary" id="recDl" type="button">${ico('download','sm')}Download the stored data</button>
      <button class="btn" id="recFresh" type="button">${ico('folder-open','sm')}Start fresh and keep the old data aside</button></div>
    <p class="t3 lockfoot">The old data stays in this browser under a separate name either way, until you clear the site's data.</p></div>`;
  $('recDl').onclick = () => download('osintrix-stored-data-' + new Date().toISOString().slice(0, 10) + '.json', c.raw || '', 'application/json');
  $('recFresh').onclick = async () => {
    for(const x of copies) await IDB.set(STORE_KEY + ':kept:' + Date.now() + ':' + Math.random().toString(36).slice(2, 6), x.raw);
    w.hidden = true; w.classList.remove('lockscr'); DB = seedDB(); bootRest(false); toast('Started fresh. The old data is kept aside in this browser.');
  };
}

/* One tab writes. Every other tab is read-only and follows the writer's saves,
   until the person moves the workspace to it. Without Web Locks, every tab writes. */
const TABS = {writer:!(window.navigator && navigator.locks), ch:null};
try{ TABS.ch = new BroadcastChannel('osintrix-workspace'); }catch(e){}
function claimWriter(steal){
  if(!navigator.locks) return Promise.resolve(TABS.writer = true);
  return new Promise(res => {
    navigator.locks.request('osintrix-workspace', steal ? {steal:true} : {ifAvailable:true}, lock => {
      if(!lock){ TABS.writer = false; res(false);
        /* Taken: either another tab has the workspace, or this is a refresh and the page before it is
           still letting go. Wait in line and take over the moment it is free — a refresh never leaves
           the new page read-only. The notice shows only if the wait is a real other tab. */
        setTimeout(() => { if(!TABS.writer) paintReadOnly(); }, 1500);
        navigator.locks.request('osintrix-workspace', async () => {
          if(!TABS.writer){
            if(performance.now() > 5000){ try{ const d = await loadAll(); if(d && !d.__locked && !d.__bad && usable(d)){ DB = normStored(d); cache = {}; } }catch(e){} }   // another tab closed: start from what it saved
            TABS.writer = true; paintReadOnly(); if(typeof save === 'function' && DB) save(); if(typeof renderAll === 'function' && DB) renderAll(); }
          return new Promise(() => {}); }).catch(() => {});
        return; }
      TABS.writer = true; res(true); paintReadOnly();
      return new Promise(() => {});                         // held for the life of the tab
    }).catch(() => { TABS.writer = false; paintReadOnly(); if(typeof paintSaved === 'function') paintSaved(); });   // another tab took it over
  });
}
function paintReadOnly(){
  let b = $('rotab');
  if(TABS.writer){ if(b) b.remove(); return; }
  if(!b){ b = document.createElement('div'); b.id = 'rotab'; b.className = 'rotab'; b.setAttribute('role', 'status'); document.body.appendChild(b); }
  b.innerHTML = `${ico('lock','sm')}<span><b>Read-only.</b> This workspace is open in another tab, so changes here are not saved.</span><button class="btn sm" id="rotabGo" type="button">Use it in this tab</button>`;
  $('rotabGo').onclick = async () => { const go = $('rotabGo'); if(go) go.disabled = true;
    await claimWriter(true);                                   // the other tab turns read-only
    try{ const d = await loadAll(); if(d && !d.__locked && !d.__bad && usable(d)){ DB = normStored(d); cache = {}; renderAll(); } else location.reload(); }catch(e){ location.reload(); }
    if(typeof paintSaved === 'function') paintSaved(); toast('This tab now saves the workspace'); };
}
function tabSaved(){ try{ TABS.ch && TABS.ch.postMessage({t:'saved', at:Date.now()}); }catch(e){} }
if(TABS.ch) TABS.ch.onmessage = async ev => {
  if(TABS.writer || !ev.data || ev.data.t !== 'saved' || !DB || SEC.key || SEC.locked) return;
  clearTimeout(TABS.rt); TABS.rt = setTimeout(async () => { const d = await loadAll(); if(d && !d.__locked && !d.__bad && usable(d)){ const prefs = DB.prefs; DB = normStored(d); DB.prefs = prefs; cache = {}; renderAll(); } }, 300);
};

/* automations from a backup arrive switched off and checked field by field: a file must never start acting on its own */
function normAutos(L){
  if(!Array.isArray(L)) return []; const kinds = AUTO_KINDS.map(x => x[0]), acts = Object.keys(AUTO_DO);
  return L.filter(R => R && typeof R === 'object').slice(0, 100).map(R => { const w = R.when && typeof R.when === 'object' ? R.when : {};
    return {id:typeof R.id === 'string' && /^[\w-]{1,60}$/.test(R.id) ? R.id : uid('au'), tpl:typeof R.tpl === 'string' ? R.tpl.slice(0, 40) : undefined, name:String(R.name || 'Automation').slice(0, 120), on:false, runs:0,
      when:{ev:['ind', 'tag', 'verdict'].includes(w.ev) ? w.ev : 'ind', kinds:(Array.isArray(w.kinds) ? w.kinds : []).filter(k => kinds.includes(k)), text:String(w.text || '').slice(0, 80), verdict:['malicious', 'suspicious'].includes(w.verdict) ? w.verdict : 'malicious'},
      scope:typeof R.scope === 'string' && /^[\w-]{1,60}$/.test(R.scope) ? R.scope : 'all',
      then:(Array.isArray(R.then) ? R.then : []).filter(t => t && acts.includes(t.a)).slice(0, 8).map(t => ({a:t.a, prio:['low', 'medium', 'high', 'critical'].includes(t.prio) ? t.prio : undefined, text:t.text ? String(t.text).slice(0, 200) : undefined, v:['malicious', 'suspicious', 'benign'].includes(t.v) ? t.v : undefined, id:typeof t.id === 'string' ? t.id.slice(0, 60) : undefined}))}; }); }

/* sample events kept with a rule: plain text, capped */
function normRuleTests(t){ return Array.isArray(t) ? t.filter(x => x && typeof x.text === 'string').slice(0, 50).map(x => ({id:typeof x.id === 'string' && /^[\w-]{1,60}$/.test(x.id) ? x.id : uid('t'), kind:x.kind === 'hit' ? 'hit' : 'miss', text:x.text.slice(0, 4000)})) : []; }

/* Stored data in the wrong shape — from an old version, a hand-edited backup or a damaged copy —
   is put right on every load and every import, so no page has to guard against it. Only shapes
   are fixed: a value of the right kind is never changed. */
function normStored(d){
  if(!isObj(d)) return d; const objs = v => Array.isArray(v) ? v.filter(isObj) : [], str = v => typeof v === 'string' ? v : v == null ? '' : typeof v === 'number' ? String(v) : '';
  for(const k of ['cases', 'records', 'entries', 'links', 'notes', 'tools', 'queries', 'rules', 'playbooks', 'trash']) if(d[k] != null && !Array.isArray(d[k])) d[k] = []; else if(d[k]) d[k] = objs(d[k]);
  if(d.hunts != null && !Array.isArray(d.hunts)) d.hunts = [];
  for(const r of d.records || []){
    if(typeof r.title !== 'string') r.title = str(r.title) || 'Untitled record'; if(typeof r.body !== 'string') r.body = str(r.body);
    if(typeof r.host !== 'string') r.host = str(r.host); if(typeof r.source !== 'string') r.source = str(r.source);
    r.tags = Array.isArray(r.tags) ? r.tags.filter(t => typeof t === 'string' || typeof t === 'number').map(String) : [];
    if(!Array.isArray(r.ents)) r.ents = []; else r.ents = r.ents.filter(e => isObj(e) && typeof e.k === 'string' && typeof e.v === 'string');
    if(r.ts != null && (typeof r.ts !== 'number' || !isFinite(r.ts))) r.ts = null;
    if(r.tsShift != null && (typeof r.tsShift !== 'number' || !isFinite(r.tsShift))) delete r.tsShift;
    r.att = objs(r.att).filter(a => typeof a.id === 'string');
    for(const a of r.att){ a.name = str(a.name) || 'file'; a.type = str(a.type); if(typeof a.size !== 'number' || !isFinite(a.size)) a.size = 0; if(a.meta != null && !isObj(a.meta)) delete a.meta; if(a.psig != null && typeof a.psig !== 'string') delete a.psig; if(a.dhash != null && typeof a.dhash !== 'string') delete a.dhash; }
    if(r.title.length > 2000) r.title = r.title.slice(0, 2000); if(r.tags.length > 200 || r.tags.some(t => t.length > 200)) r.tags = r.tags.slice(0, 200).map(t => t.slice(0, 200));   // limits: far past anything typed
    if(r.geo != null && !isObj(r.geo)) delete r.geo;
    if(r.hours != null && !(isObj(r.hours) && Array.isArray(r.hours.t) && Array.isArray(r.hours.who))) delete r.hours; if(r.cred != null && !/^[1-6]$/.test(String(r.cred))) delete r.cred; }
  for(const k of ['cases', 'records', 'entries', 'notes', 'tools', 'queries', 'rules', 'playbooks']) if(d[k]) d[k] = d[k].filter(x => typeof x.id === 'string' && x.id);
  /* a built search keeps its rows: a short list of {k, v} strings, or nothing */
  if(d.queries) for(const q of d.queries) if(q.b !== undefined){ if(!Array.isArray(q.b)) delete q.b; else { q.b = q.b.filter(r => r && typeof r === 'object' && typeof r.k === 'string' && typeof r.v === 'string' && (typeof QB_KINDS === 'undefined' || QB_KINDS[r.k])).slice(0, 30).map(r => ({k:r.k, v:r.v.slice(0, 500)})); if(!q.b.length) delete q.b; } }
  if(d.links) d.links = d.links.filter(l => typeof l.a === 'string' && typeof l.b === 'string');
  /* an entry of a kind this version does not know is kept as a document, its kind written on it as a tag */
  for(const e of d.entries || []) if(typeof TYPES !== 'undefined' && !TYPES[e.type]){ const was = typeof e.type === 'string' ? e.type.slice(0, 30) : ''; e.type = 'document'; e.tags = (Array.isArray(e.tags) ? e.tags : []).concat(was ? ['was ' + was] : []); }
  for(const e of d.entries || []){ if(!isObj(e.fields)) e.fields = {}; for(const [k, v] of Object.entries(e.fields)) if(typeof v !== 'string') e.fields[k] = str(v);
    if(!Array.isArray(e.tags)) e.tags = []; else e.tags = e.tags.filter(t => typeof t === 'string' || typeof t === 'number').map(String); if(e.notes != null && typeof e.notes !== 'string') e.notes = str(e.notes); }
  for(const e of d.entries || []){ for(const [k, v] of Object.entries(e.fields)) if(v.length > 100000) e.fields[k] = v.slice(0, 100000); if(e.tags.length > 200) e.tags = e.tags.slice(0, 200); }
  for(const c of d.cases || []){ if(typeof c.name !== 'string') c.name = str(c.name) || 'Untitled case'; if(typeof c.code !== 'string') c.code = str(c.code) || 'CASE'; if(c.name.length > 500) c.name = c.name.slice(0, 500); if(c.code.length > 40) c.code = c.code.slice(0, 40); }
  d.trash = (d.trash || []).filter(x => typeof x.id === 'string' && typeof x.kind === 'string' && isObj(x.data)).map(x => { x.label = str(x.label); if(typeof x.at !== 'number' || !isFinite(x.at)) x.at = Date.now(); return x; });
  if(d.srcRel != null){ const o = {}; if(isObj(d.srcRel)) for(const [k, v] of Object.entries(d.srcRel)) if(isObj(v) && /^[A-F]$/.test(v.rel)) o[k] = v; d.srcRel = o; }
  if(d.phoneCC != null && !(typeof d.phoneCC === 'string' && /^[A-Z]{2}$|^$/.test(d.phoneCC))) d.phoneCC = '';
  if(d.research != null){ if(!isObj(d.research)) d.research = {}; else for(const [k, v] of Object.entries(d.research)){ if(!isObj(v)) delete d.research[k]; else for(const [n, x] of Object.entries(v)) if(!isObj(x)) delete v[n]; else { if(x.r != null && !['found', 'none', 'private'].includes(x.r)) delete x.r; if(x.note != null) x.note = String(x.note).slice(0, 500); } } }
  if(d.autoDone != null && !isObj(d.autoDone)) d.autoDone = {}; if(d.autoLog != null && !Array.isArray(d.autoLog)) d.autoLog = [];
  if(d.rxlib != null) d.rxlib = Array.isArray(d.rxlib) && typeof rxlClean === 'function' ? d.rxlib.map(rxlClean).filter(Boolean).slice(0, 300) : [];
  if(d.verdicts != null && !isObj(d.verdicts)) d.verdicts = {}; if(d.prefs != null && !isObj(d.prefs)) d.prefs = {};
  return d;
}
