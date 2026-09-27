/* ==========================================================================
   State, derivation, routing, persistence, shared render helpers.
   ========================================================================== */
const E = Engine, esc = E.esc;
const $ = id => document.getElementById(id);
const STORE_KEY = 'osintrix-poc:v4';
const uid = p => (p || 'x') + '-' + Math.random().toString(36).slice(2, 8) + Date.now().toString(36).slice(-3);
const ico = (n, cls = '') => `<svg class="i ${cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${LUCIDE[n] || ''}</svg>`;

let DB = null;
const UI = {route:{area:'home'}, q:'', ast:null, sel:null, inspOpen:false, navOpen:false, vcat:'all', vq:'', vview:'grid',
  tcat:'all', tsub:null, tq:'', tlMode:'events', facet:{}, pivot:null, graph:{mode:null, first:null}, entKind:null};

/* ---------- seed ---------- */
function seedDB(){
  const T = Date.parse('2026-09-15T12:00:00Z');
  const recs = DEMO.R.map(([id, caseId, type, t, host, source, title, body, tags]) => ({
    id, caseId, type, tsRaw:t || '', tsZone:t ? 'explicit' : '', ts:t ? E.parseTime(t) : null, host, source, title, body, tags:tags || [],
    ents:E.extract(body), answer:DEMO.answers[id] || '', addedBy:'You', addedAt:t ? E.parseTime(t) + 240000 : Date.parse('2026-09-14T09:40:00Z'), hash:''}));
  const cases = DEMO.cases.map(c => ({...c, created:Date.parse(c.created), updated:Date.parse(c.updated), color:DEMO_CASE_STYLE[c.id][0], icon:DEMO_CASE_STYLE[c.id][1]}));
  const entries = DEMO_ENTRIES.map(([id, caseId, type, fields, x], i) => ({id, caseId, type, fields:{...fields}, priority:x.priority || 'medium', starred:!!x.starred,
    tags:x.tags || [], notes:x.notes || '', src:x.src || '', created:T - i * 3600e3, pos:DEMO_POS[id] ? {x:DEMO_POS[id][0] * .84, y:DEMO_POS[id][1] * .84} : null}));
  const verdicts = {...DEMO.verdicts};
  for(const [id,,,, x] of DEMO_ENTRIES) if(x.verdict){ const e = entries.find(z => z.id === id), k = entryKey(e); if(k) verdicts[k] = x.verdict; else e.verdict = x.verdict; }
  const tools = TOOLS_SEED.map(t => ({id:'t' + t.id, name:t.name, url:t.url, cat:t.parentCategory, sub:t.childCategory, desc:t.description, tags:t.tags || [],
    pinned:!!t.isPinned, starred:!!t.isStarred, added:Date.parse(t.dateAdded) || Date.now(), uses:0, seed:true}));
  return {v:2, cases, records:recs, entries, links:DEMO_LINKS.map(([a, b, label, conf, src], i) => ({id:'l' + i, caseId:entries.find(e => e.id === a).caseId, a, b, label, conf, src})),
    verdicts, tools, feed:DEMO.feed.map(f => ({...f, ts:Date.parse(f.date)})), active:'c-lantern',
    prefs:{theme:'light', size:'m', density:'comfortable', tz:'UTC'}, log:[], sample:true};
}
function load(){ try{ const d = JSON.parse(localStorage.getItem(STORE_KEY) || 'null'); if(d && d.v === 2 && Array.isArray(d.entries)) return d; }catch(e){} return null; }
/* IndexedDB is the primary store: far more room than localStorage (~5 MB). localStorage keeps a mirror while it fits. */
const IDB = {db:null,
  open(){ return new Promise(res => { try{ const r = indexedDB.open('osintrix', 1); r.onupgradeneeded = () => r.result.createObjectStore('kv'); r.onsuccess = () => { IDB.db = r.result; res(true); }; r.onerror = () => res(false); r.onblocked = () => res(false); }catch(e){ res(false); } }); },
  get(k){ return new Promise(res => { if(!IDB.db) return res(null); try{ const q = IDB.db.transaction('kv').objectStore('kv').get(k); q.onsuccess = () => res(q.result || null); q.onerror = () => res(null); }catch(e){ res(null); } }); },
  set(k, v){ return new Promise(res => { if(!IDB.db) return res(false); try{ const tx = IDB.db.transaction('kv', 'readwrite'); tx.objectStore('kv').put(v, k); tx.oncomplete = () => res(true); tx.onerror = tx.onabort = () => res(false); }catch(e){ res(false); } }); }};
const STORE = {idb:false, ls:false, persisted:false, bytes:0, quota:0, lastSaved:0};
async function loadAll(){
  STORE.idb = await IDB.open();
  let a = null, envs = []; if(STORE.idb){ const raw = await IDB.get(STORE_KEY); if(isEnv(raw)) envs.push(raw); else { try{ a = raw ? JSON.parse(raw) : null; }catch(e){ a = null; } if(!(a && a.v === 2 && Array.isArray(a.entries))) a = null; } }
  try{ const ls = localStorage.getItem(STORE_KEY); if(isEnv(ls)) envs.push(ls); }catch(e){}
  if(envs.length){ try{ if(navigator.storage && navigator.storage.persisted) STORE.persisted = await navigator.storage.persisted(); }catch(e){} const env = envs.sort((x, y) => (JSON.parse(y).at || 0) - (JSON.parse(x).at || 0))[0]; SEC.locked = true; return {__locked:true, env}; }
  const b = load();
  const pick = a && b ? ((a.savedAt || 0) >= (b.savedAt || 0) ? a : b) : (a || b);
  try{ if(navigator.storage && navigator.storage.persist) STORE.persisted = await navigator.storage.persisted() || await navigator.storage.persist(); }catch(e){}
  return pick;
}
async function storageEstimate(){ try{ if(navigator.storage && navigator.storage.estimate){ const e = await navigator.storage.estimate(); STORE.quota = e.quota || 0; STORE.usage = e.usage || 0; } }catch(e){} return STORE; }
let saveT = null, storageOK = true;
function save(){ clearTimeout(saveT); saveT = setTimeout(flush, 250); }
function flush(){ clearTimeout(saveT); if(!DB || SEC.locked) return; DB.savedAt = Date.now(); const json = JSON.stringify(DB);
  if(SEC.key) return flushSealed(json);
  STORE.bytes = json.length * 2;
  let ok = false; try{ if(json.length < 2400000){ localStorage.setItem(STORE_KEY, json); STORE.ls = true; ok = true; } else { localStorage.removeItem(STORE_KEY); STORE.ls = false; } }catch(e){ STORE.ls = false; }
  if(STORE.idb){ ok = true; IDB.set(STORE_KEY, json).then(r => { if(!r && !STORE.ls){ storageOK = false; paintSaved(); } }); }
  storageOK = ok; STORE.lastSaved = Date.now(); paintSaved(); }
function paintSaved(){ const s = $('saved'); if(s) s.innerHTML = storageOK ? '<i></i>Saved in this browser' : '<i style="background:var(--red)"></i>Not saved'; }
window.addEventListener('pagehide', flush); document.addEventListener('visibilitychange', () => { if(document.visibilityState === 'hidden') flush(); });
let rev = 0, cache = {};
function mutate(what){ rev++; cache = {}; auditAdd(what); DB.log.unshift({at:Date.now(), what}); DB.log.length = Math.min(DB.log.length, 200); save(); }

/* ---------- lookups ---------- */
const tz = () => DB.prefs.tz || 'UTC';
const theCase = id => DB.cases.find(c => c.id === (id || DB.active)) || null;
const recById = id => DB.records.find(r => r.id === id) || null;
const entryById = id => DB.entries.find(e => e.id === id) || null;
const entKey = e => e.k + ':' + e.v;
const entSplit = id => { const i = id.indexOf(':'); return {k:id.slice(0, i), v:id.slice(i + 1)}; };
const verdictOf = id => DB.verdicts[id] || '';
const primary = e => { const t = TYPES[e.type]; if(e.type === 'social' && e.fields.url){ const s = E.normSocial(e.fields.url); if(s) return s.v; } return (e.fields[t.fields[0][0]] || '').trim(); };
function entryKey(e){
  const t = TYPES[e.type]; if(!t) return null;
  if(e.type === 'location'){ const co = (e.fields.coordinates || '').trim(); return /-?\d+(\.\d+)?\s*,\s*-?\d+(\.\d+)?/.test(co) ? 'coords:' + E.norm('coords', co) : null; }
  if(e.type === 'social'){ const u = (e.fields.url || '').trim(), s = u && E.normSocial(u); if(s) return 'social:' + s.v; return null; }
  if(!t.kind) return null;
  let v = primary(e); if(!v) return null;
  let k = t.kind;
  if(e.type === 'crypto') k = E.cryptoKind(v);
  if(e.type === 'ip' && v.includes(':') && E.validIPv6(v.trim())) k = 'ipv6';
  if(/^(phone|mac)$/.test(k)) v = E.norm(k, v);
  if(e.type === 'username') v = '@' + v.replace(/^@/, '');
  if(/^(ipv4|ipv6|domain|url|email|sha256|handle)$/.test(k)) v = v.toLowerCase();
  v = v.trim();
  if(k === 'cve') v = v.toUpperCase();
  return k + ':' + v;
}
const entryVerdict = e => { const k = entryKey(e); return k ? verdictOf(k) : (e.verdict || ''); };
function setEntryVerdict(e, v){ const k = entryKey(e); if(k){ if(v) DB.verdicts[k] = v; else delete DB.verdicts[k]; } else e.verdict = v; }
const sortRecs = l => l.slice().sort((a, b) => (a.ts && b.ts) ? a.ts - b.ts : a.ts ? -1 : b.ts ? 1 : a.addedAt - b.addedAt);

function derive(caseId){
  caseId = caseId || DB.active;
  if(cache[caseId]) return cache[caseId];
  const recs = sortRecs(DB.records.filter(r => r.caseId === caseId));
  const ents = new Map();
  for(const r of recs) for(const e of r.ents){ const id = entKey(e); if(!ents.has(id)) ents.set(id, {id, k:e.k, v:e.v, recs:[]}); ents.get(id).recs.push(r); }
  const entries = DB.entries.filter(e => e.caseId === caseId);
  const byKey = new Map(); for(const e of entries){ const k = entryKey(e); if(k) byKey.set(k, e); }
  const links = DB.links.filter(l => l.caseId === caseId);
  const c = theCase(caseId), t0r = c && c.t0 ? recById(c.t0) : null;
  return (cache[caseId] = {recs, ents, entries, byKey, links, t0:t0r && t0r.ts ? t0r.ts : null});
}
function globalEnts(){
  if(cache.__g) return cache.__g;
  const m = new Map();
  for(const r of DB.records) for(const e of r.ents){ const id = entKey(e); if(!m.has(id)) m.set(id, {id, k:e.k, v:e.v, recs:[], cases:new Set()}); const x = m.get(id); x.recs.push(r); x.cases.add(r.caseId); }
  for(const en of DB.entries){ const k = entryKey(en); if(!k) continue; if(!m.has(k)){ const s = entSplit(k); m.set(k, {id:k, k:s.k, v:s.v, recs:[], cases:new Set()}); } m.get(k).cases.add(en.caseId); }
  return (cache.__g = m);
}
/* how many records mention a vault entry */
function entryMentions(e){ const k = entryKey(e); if(!k) return []; const x = derive(e.caseId).ents.get(k); return x ? x.recs : []; }
function countBy(list, f){ const m = new Map(); for(const x of list){ const vs = f(x); for(const v of (Array.isArray(vs) ? vs : [vs])) if(v) m.set(v, (m.get(v) || 0) + 1); } return [...m.entries()].sort((a, b) => b[1] - a[1]); }

/* ---------- query ---------- */
function matchField(r, f){
  const v = f.val;
  switch(f.field){
    case 'host': return (r.host || '').toLowerCase().includes(v);
    case 'source': case 'from': return (r.source || '').toLowerCase().includes(v);
    case 'tag': return r.tags.some(t => t.toLowerCase().includes(v));
    case 'type': return r.type.startsWith(v);
    case 'kind': return r.ents.some(e => e.k === v);
    case 'ent': return r.ents.some(e => e.v.toLowerCase().includes(v));
    case 'verdict': return r.ents.some(e => verdictOf(entKey(e)) === v);
    case 'is': return v === 'open' ? (r.type === 'lead' && !r.answer) : r.type.startsWith(v);
    case 'fld': { const P = parseLog(r.body); if(P && (P.norm[f.name] != null || Object.keys(P.fields).some(k => k.toLowerCase() === f.name))) return fieldMatch(r, f.name, v);
      return (r.title + ' ' + r.body).toLowerCase().includes(f.text); }
  }
  return true;
}
function passes(r){
  if(UI.facet.host && r.host !== UI.facet.host) return false;
  if(UI.facet.type && r.type !== UI.facet.type) return false;
  if(UI.pivot && !r.ents.some(e => entKey(e) === UI.pivot)) return false;
  if(UI.facet.slot && !slotPass(r)) return false;
  if(UI.facet.win && !winPass(r)) return false;
  if(UI.ast){ const h = (r.title + ' ' + r.body + ' ' + r.host + ' ' + r.source + ' ' + r.tags.join(' ')).toLowerCase();
    if(!UI.ast.some(g => g.text.every(t => h.includes(t)) && g.neg.every(t => !h.includes(t)) && g.f.every(f => matchField(r, f) !== f.neg))) return false; }
  return true;
}

/* ---------- routing ---------- */
const AREAS = ['security','watch','trash','help','ctf','lab','home','cases','case','toolbox','entities','feeds','decoder','reference','settings','detections','playbooks','queries','notes'];
const CASE_TABS = [['overview','Overview','layout-dashboard'],['vault','Vault','layers'],['entities','Entities','fingerprint'],['timeline','Timeline','clock'],['graph','Graph','waypoints'],['map','Map','map'],['questions','Analysis','scale'],['report','Report','file-chart-column']];
function parseHash(){
  const p = (location.hash || '#/home').replace(/^#\/?/, '').split('/').map(decodeURIComponent);
  if(p[0] === 'case' && DB.cases.some(c => c.id === p[1])){ DB.active = p[1]; return {area:'case', tab:CASE_TABS.some(t => t[0] === p[2]) ? p[2] : 'overview'}; }
  if(p[0] === 'dorks') p[0] = 'queries';
  return {area:AREAS.includes(p[0]) && p[0] !== 'case' ? p[0] : 'home'};
}
const caseHash = (id, tab) => '#/case/' + encodeURIComponent(id || DB.active) + '/' + (tab || 'overview');
function go(h){ if(location.hash === h) onRoute(); else location.hash = h; }

async function hashRecords(){
  if(!(window.crypto && crypto.subtle)) return; const enc = new TextEncoder();
  for(const r of DB.records) if(!r.hash){ try{ const b = await crypto.subtle.digest('SHA-256', enc.encode(r.body || '')); r.hash = [...new Uint8Array(b)].map(x => x.toString(16).padStart(2,'0')).join(''); }catch(e){} }
}

/* ---------- toast ---------- */
let toastT = null;
function toast(msg, label, fn){
  const t = $('toast'); $('toastMsg').textContent = msg; const b = $('toastBtn'); b.hidden = !label;
  if(label){ b.textContent = label; b.onclick = () => { t.hidden = true; fn(); }; }
  t.hidden = false; clearTimeout(toastT); toastT = setTimeout(() => t.hidden = true, label ? 7000 : 2800);
}

/* ---------- shared render helpers ---------- */
const typeOfKind = k => TYPES[KIND_TO_TYPE[k]] || null;
function tbadge(typeId, cls = ''){ const t = TYPES[typeId] || {icon:'hash', color:'--t-file'}; return `<span class="tb ${cls}" style="--c:var(${t.color})">${ico(t.icon)}</span>`; }
function kindBadge(k, cls = ''){ const t = typeOfKind(k); return t ? tbadge(t.id, cls) : `<span class="tb ${cls}" style="--c:var(--t-file)">${ico(k === 'eventid' ? 'activity' : k === 'path' || k === 'file' ? 'file-code' : k === 'account' ? 'user' : 'hash')}</span>`; }
function entPill(id, opts = {}){
  const {k, v} = entSplit(id);
  return `<button class="ent${UI.sel && UI.sel.id === id ? ' on' : ''}" data-v="${verdictOf(id)}" data-act="selEnt" data-id="${esc(id)}" title="${esc(E.LABEL[k] || k)}">${kindBadge(k)}<span class="v">${esc(v)}</span>${opts.n ? `<span class="n">×${opts.n}</span>` : ''}</button>`;
}
function entryPill(e){
  return `<button class="ent" data-v="${entryVerdict(e)}" data-act="selEntry" data-id="${e.id}">${tbadge(e.type)}<span class="v"${MONO_TYPES.has(e.type) ? '' : ' style="font-family:var(--font);font-size:13px"'}>${esc(primary(e))}</span></button>`;
}
const vdLabel = v => v ? `<span class="vd" data-v="${v}">${v[0].toUpperCase() + v.slice(1)}</span>` : '';
const prioLabel = p => `<span class="prio" data-p="${p}">${p[0].toUpperCase() + p.slice(1)}</span>`;
const statusTag = s => `<span class="status" data-s="${s}">${{active:'Active', review:'In review', closed:'Closed'}[s] || s}</span>`;
const conf = n => `<span class="conf" data-c="${n}" title="Confidence: ${['','low','medium','high'][n]}"><i></i><i></i><i></i></span>`;
const impl = i => `<span class="impl" data-i="${i}">${{real:'Working', mock:'Sample data', planned:'Planned'}[i]}</span>`;
const typeLabel = t => ({evidence:'Evidence', note:'Note', finding:'Finding', lead:'Question'}[t] || t);
const ILL_FOR = {waypoints:'graph', layers:'vault', 'folder-open':'vault', clock:'time', 'book-open':'time', filter:'search', search:'search', wrench:'tools', 'list-checks':'time'};
function empty(icon, title, body, acts){ const il = ILLUS[ILL_FOR[icon]]; return `<div class="empty" role="status">${il ? `<div class="illus">${il}</div>` : `<div class="art">${ico(icon)}</div>`}<h3>${title}</h3><div>${body}</div>${acts ? `<div class="acts">${acts}</div>` : ''}</div>`; }
function download(name, text, mime){
  try{ const u = URL.createObjectURL(new Blob([text], {type:mime || 'text/plain;charset=utf-8'})); const a = document.createElement('a'); a.href = u; a.download = name;
    document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(u); a.remove(); }, 150); toast('Saved ' + name); }catch(e){ toast('The browser blocked the download'); }
}
const hostOf = u => { try{ return new URL(u).hostname.replace(/^www\./, ''); }catch(e){ return ''; } };
const AVC = ['#5470f5','#8b5cf6','#0ea5a4','#e8590c','#d6336c','#2f9e44','#b07b00','#3b82f6','#9333ea','#0891b2'];
const avColor = s => AVC[[...String(s)].reduce((a, c) => (a * 31 + c.charCodeAt(0)) >>> 0, 7) % AVC.length];
/* Standard page header: icon tile, title, subtitle, actions, and an optional KPI strip */
function pageHead(icon, color, title, sub, acts, kpis){
  return `<header class="phd"><div class="phd-t"><span class="phd-ic" style="--c:${color}">${ico(icon)}</span><div class="phd-tt"><h1>${title}</h1>${sub ? `<p>${sub}</p>` : ''}</div>${acts ? `<div class="phd-a">${acts}</div>` : ''}</div>
    ${kpis && kpis.length ? `<div class="kpis">${kpis.map(([n, l, extra]) => `<div class="kpi"><b>${n}</b><span>${l}</span>${extra || ''}</div>`).join('')}</div>` : ''}</header>`;
}

/* pre-added tools: flag them, and add new ones from tools.json after an update — never re-add one the user deleted */
function ensureTools(){
  const gone = new Set(DB.deletedSeed || []), have = new Set(DB.tools.map(t => t.url)), seedUrls = new Set(TOOLS_SEED.map(t => t.url)); let n = 0;
  for(const t of DB.tools) if(t.seed === undefined) t.seed = seedUrls.has(t.url);
  for(const t of TOOLS_SEED) if(!have.has(t.url) && !gone.has(t.url)){ DB.tools.push({id:'t' + t.id + '-' + uid('u').slice(-4), name:t.name, url:t.url, cat:t.parentCategory, sub:t.childCategory, desc:t.description, tags:t.tags || [], pinned:false, starred:false, added:Date.now(), uses:0, seed:true}); n++; }
  return n;
}
