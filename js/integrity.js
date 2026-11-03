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
      if((k === 'id' || /Id$/.test(k)) && v != null && v !== ''){
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
  r.host = String(r.host || ''); r.source = String(r.source || ''); if(typeof r.ts !== 'number') r.ts = null; r.answer = String(r.answer || '');
  return r;
}
function normEntry(e){ e.fields = isObj(e.fields) ? Object.fromEntries(Object.entries(e.fields).map(([k, v]) => [k, String(v == null ? '' : v)])) : {}; e.tags = Array.isArray(e.tags) ? e.tags.map(String) : []; e.notes = String(e.notes || ''); e.priority = e.priority || 'medium'; return e; }
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
  w.innerHTML = `<div class="wcard lockcard recover">${logoMark(56)}<h1 id="wTitle" style="font-size:26px">Your workspace needs attention</h1>
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
      if(!lock){ TABS.writer = false; res(false); paintReadOnly(); return; }
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
  $('rotabGo').onclick = async () => { await claimWriter(true); location.reload(); };
}
function tabSaved(){ try{ TABS.ch && TABS.ch.postMessage({t:'saved', at:Date.now()}); }catch(e){} }
if(TABS.ch) TABS.ch.onmessage = async ev => {
  if(TABS.writer || !ev.data || ev.data.t !== 'saved' || !DB || SEC.key || SEC.locked) return;
  clearTimeout(TABS.rt); TABS.rt = setTimeout(async () => { const d = await loadAll(); if(d && !d.__locked && !d.__bad && usable(d)){ const prefs = DB.prefs; DB = d; DB.prefs = prefs; cache = {}; renderAll(); } }, 300);
};
