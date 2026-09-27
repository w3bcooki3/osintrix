/* ==========================================================================
   SQLite viewer — browser history, cookies, chats and any other SQLite file.
   Uses sql.js (SQLite compiled to WebAssembly, MIT), loaded only when this tab
   is first used. The database is opened as an in-memory copy, so the original
   file is never changed. Known artefacts get ready-made views; numeric time
   columns are recognised (Unix, WebKit/Chrome, Mozilla PRTime, Apple, FILETIME)
   and shown as dates. Pages on the free list are scanned for leftover text,
   which is often what remains of deleted rows.
   ========================================================================== */
let SQLJS = null;
function lazyScript(src){
  const L = document.getElementById('lazy:' + src);
  return new Promise((res, rej) => { const s = document.createElement('script'); if(L){ s.textContent = L.textContent; document.head.appendChild(s); return res(); }
    s.src = src; s.onload = res; s.onerror = () => rej(new Error('Could not load ' + src)); document.head.appendChild(s); });
}
async function sqlEngine(){
  if(SQLJS) return SQLJS;
  if(typeof initSqlJs === 'undefined') await lazyScript('js/vendor/sql-wasm.js');
  if(!self.SQL_WASM_GZ) await lazyScript('js/vendor/sql-wasm-b64.js');
  const gz = Uint8Array.from(atob(self.SQL_WASM_GZ), c => c.charCodeAt(0));
  const wasm = await new Response(new Blob([gz]).stream().pipeThrough(new DecompressionStream('gzip'))).arrayBuffer();
  SQLJS = await initSqlJs({wasmBinary:wasm, locateFile:f => f});
  return SQLJS;
}

/* ---------- time columns ---------- */
const TS_KINDS = {
  unix:{label:'Unix seconds', ms:v => v * 1000, lo:9.4e8, hi:2.3e9},
  unixms:{label:'Unix milliseconds', ms:v => v, lo:9.4e11, hi:2.3e12},
  unixus:{label:'Unix microseconds (PRTime)', ms:v => v / 1000, lo:9.4e14, hi:2.3e15},
  unixns:{label:'Unix nanoseconds', ms:v => v / 1e6, lo:9.4e17, hi:2.3e18},
  webkit:{label:'WebKit / Chrome (µs since 1601)', ms:v => v / 1000 - 11644473600000, lo:1.259e16, hi:1.39e16},
  filetime:{label:'Windows FILETIME', ms:v => v / 1e4 - 11644473600000, lo:1.259e17, hi:1.39e17},
  mac:{label:'Apple absolute seconds (since 2001)', ms:v => (v + 978307200) * 1000, lo:1e8, hi:1.3e9},
  macns:{label:'Apple absolute nanoseconds', ms:v => v / 1e6 + 978307200000, lo:2.5e17, hi:9.3e17}
};
const TS_HINT = /(time|date|_at$|^at$|created|modified|updated|accessed|last|expir|visit|utc|stamp|^ts$|_ts$|when|start|end|seen|sent|received|read)/i;
function tsGuess(name, vals, apple){
  const nums = vals.filter(v => typeof v === 'number' && v !== 0); if(nums.length < 1 || nums.length < vals.filter(v => v != null && v !== '').length * .9) return null;
  const hint = TS_HINT.test(name), order = apple || /^Z/.test(name) ? ['macns', 'mac', 'unixms', 'unixus', 'unixns', 'webkit', 'filetime', 'unix'] : ['webkit', 'filetime', 'unixus', 'unixms', 'unixns', 'macns', 'unix', 'mac'];
  for(const k of order){ const K = TS_KINDS[k], ok = nums.filter(v => v >= K.lo && v <= K.hi).length; if(ok >= nums.length * .9){
    if((k === 'unix' || k === 'unixms' || k === 'mac') && !hint) continue; if(k === 'mac' && !(apple || /^Z/.test(name))) continue; return k; } }
  return null;
}
const tsFmt = (v, k) => { if(v == null || v === 0 || !k) return null; const ms = TS_KINDS[k].ms(v); if(!isFinite(ms)) return null; return E.fmtFull(Math.floor(ms), tz()); };
const tsISO = (v, k) => { const ms = v && k ? TS_KINDS[k].ms(v) : NaN; return isFinite(ms) ? new Date(ms).toISOString() : ''; };

/* ---------- known artefacts ---------- */
const SQL_ARTS = [
  {id:'chrome-hist', app:'Chrome / Edge / Brave history', need:['urls', 'visits'], label:'Visited pages', sql:`SELECT v.visit_time AS visited, u.url, u.title, u.visit_count, u.typed_count, (v.transition & 255) AS how FROM visits v JOIN urls u ON u.id = v.url ORDER BY v.visit_time DESC`, ts:{visited:'webkit'}, title:r => r.title || r.url, how:{0:'link',1:'typed',2:'bookmark',3:'embedded',4:'address bar',5:'generated',6:'start page',7:'form',8:'reload',9:'keyword',10:'keyword'}},
  {id:'chrome-dl', app:'Chrome / Edge / Brave history', need:['downloads'], label:'Downloads', sql:`SELECT start_time, end_time, target_path, tab_url, referrer, total_bytes, mime_type, danger_type, opened FROM downloads ORDER BY start_time DESC`, ts:{start_time:'webkit', end_time:'webkit'}, title:r => 'Downloaded ' + String(r.target_path || '').split(/[\\/]/).pop()},
  {id:'chrome-search', app:'Chrome / Edge / Brave history', need:['keyword_search_terms', 'urls'], label:'Searches', sql:`SELECT u.last_visit_time AS searched, k.term, u.url FROM keyword_search_terms k JOIN urls u ON u.id = k.url_id ORDER BY u.last_visit_time DESC`, ts:{searched:'webkit'}, title:r => 'Searched: ' + r.term},
  {id:'chrome-cookies', app:'Chrome / Edge cookies', need:['cookies'], cols:['host_key'], label:'Cookies', sql:`SELECT host_key, name, value, path, creation_utc, last_access_utc, expires_utc, is_secure, is_httponly, length(encrypted_value) AS encrypted_bytes FROM cookies ORDER BY last_access_utc DESC`, ts:{creation_utc:'webkit', last_access_utc:'webkit', expires_utc:'webkit'}, title:r => 'Cookie ' + r.name + ' for ' + r.host_key, note:'Cookie values are usually encrypted with a key held by the operating system; they are not decrypted here. Host, name and times are enough to show which sites were used and when.'},
  {id:'chrome-logins', app:'Chrome / Edge saved logins', need:['logins'], cols:['origin_url'], label:'Saved logins', sql:`SELECT origin_url, action_url, username_value, date_created, date_last_used, times_used, length(password_value) AS encrypted_password_bytes FROM logins ORDER BY date_created DESC`, ts:{date_created:'webkit', date_last_used:'webkit'}, title:r => 'Saved login ' + r.username_value + ' at ' + r.origin_url, note:'Passwords stay encrypted — this viewer never tries to decrypt them. Usernames and the sites they belong to are shown.'},
  {id:'chrome-autofill', app:'Chrome / Edge form data', need:['autofill'], label:'Autofill entries', sql:`SELECT name, value, count, date_created, date_last_used FROM autofill ORDER BY date_last_used DESC`, ts:{date_created:'unix', date_last_used:'unix'}, title:r => 'Autofill ' + r.name + ' = ' + r.value},
  {id:'ff-hist', app:'Firefox history', need:['moz_places', 'moz_historyvisits'], label:'Visited pages', sql:`SELECT h.visit_date AS visited, p.url, p.title, p.visit_count, h.visit_type AS how FROM moz_historyvisits h JOIN moz_places p ON p.id = h.place_id ORDER BY h.visit_date DESC`, ts:{visited:'unixus'}, title:r => r.title || r.url, how:{1:'link',2:'typed',3:'bookmark',4:'embedded',5:'redirect (permanent)',6:'redirect (temporary)',7:'download',8:'framed link',9:'reload'}},
  {id:'ff-bm', app:'Firefox history', need:['moz_bookmarks', 'moz_places'], label:'Bookmarks', sql:`SELECT b.dateAdded AS added, b.title, p.url FROM moz_bookmarks b JOIN moz_places p ON p.id = b.fk WHERE b.type = 1 ORDER BY b.dateAdded DESC`, ts:{added:'unixus'}, title:r => 'Bookmarked ' + (r.title || r.url)},
  {id:'ff-cookies', app:'Firefox cookies', need:['moz_cookies'], label:'Cookies', sql:`SELECT host, name, value, path, creationTime, lastAccessed, expiry FROM moz_cookies ORDER BY lastAccessed DESC`, ts:{creationTime:'unixus', lastAccessed:'unixus', expiry:'unix'}, title:r => 'Cookie ' + r.name + ' for ' + r.host},
  {id:'ff-forms', app:'Firefox form history', need:['moz_formhistory'], label:'Form entries', sql:`SELECT fieldname, value, timesUsed, firstUsed, lastUsed FROM moz_formhistory ORDER BY lastUsed DESC`, ts:{firstUsed:'unixus', lastUsed:'unixus'}, title:r => 'Typed in ' + r.fieldname + ': ' + r.value},
  {id:'safari-hist', app:'Safari history', need:['history_items', 'history_visits'], label:'Visited pages', sql:`SELECT v.visit_time AS visited, i.url, v.title, i.visit_count FROM history_visits v JOIN history_items i ON i.id = v.history_item ORDER BY v.visit_time DESC`, ts:{visited:'mac'}, title:r => r.title || r.url},
  {id:'android-sms', app:'Android messages', need:['sms'], cols:['address', 'body'], label:'SMS', sql:`SELECT date, address, CASE type WHEN 1 THEN 'received' WHEN 2 THEN 'sent' WHEN 3 THEN 'draft' ELSE type END AS direction, body, read FROM sms ORDER BY date DESC`, ts:{date:'unixms'}, title:r => (r.direction === 'sent' ? 'SMS to ' : 'SMS from ') + r.address + ': ' + String(r.body || '').slice(0, 60)},
  {id:'android-calls', app:'Android call log', need:['calls'], cols:['number', 'duration'], label:'Calls', sql:`SELECT date, number, CASE type WHEN 1 THEN 'incoming' WHEN 2 THEN 'outgoing' WHEN 3 THEN 'missed' WHEN 5 THEN 'rejected' ELSE type END AS direction, duration AS seconds, name FROM calls ORDER BY date DESC`, ts:{date:'unixms'}, title:r => 'Call ' + r.direction + ' ' + r.number},
  {id:'ios-sms', app:'iPhone messages', need:['message', 'handle'], cols:['text', 'is_from_me'], label:'Messages', sql:`SELECT m.date, h.id AS contact, CASE m.is_from_me WHEN 1 THEN 'sent' ELSE 'received' END AS direction, m.text, m.service FROM message m LEFT JOIN handle h ON h.ROWID = m.handle_id ORDER BY m.date DESC`, ts:{date:'auto'}, title:r => (r.direction === 'sent' ? 'Message to ' : 'Message from ') + (r.contact || '?') + ': ' + String(r.text || '').slice(0, 60)},
  {id:'wa-old', app:'WhatsApp (Android)', need:['messages'], cols:['key_remote_jid', 'data'], label:'Messages', sql:`SELECT timestamp, key_remote_jid AS chat, CASE key_from_me WHEN 1 THEN 'sent' ELSE 'received' END AS direction, remote_resource AS sender, data AS text, media_mime_type FROM messages WHERE key_remote_jid != '-1' ORDER BY timestamp DESC`, ts:{timestamp:'unixms'}, title:r => 'WhatsApp ' + r.direction + ' ' + r.chat + ': ' + String(r.text || '').slice(0, 60)},
  {id:'wa-new', app:'WhatsApp (Android)', need:['message', 'chat', 'jid'], cols:['text_data', 'from_me'], label:'Messages', sql:`SELECT m.timestamp, j.raw_string AS chat, CASE m.from_me WHEN 1 THEN 'sent' ELSE 'received' END AS direction, m.text_data AS text FROM message m LEFT JOIN chat c ON c._id = m.chat_row_id LEFT JOIN jid j ON j._id = c.jid_row_id ORDER BY m.timestamp DESC`, ts:{timestamp:'unixms'}, title:r => 'WhatsApp ' + r.direction + ' ' + (r.chat || '') + ': ' + String(r.text || '').slice(0, 60)}
];
function sqlExec(db, sql, params){ const r = db.exec(sql, params); return r[0] ? {cols:r[0].columns, rows:r[0].values} : {cols:[], rows:[]}; }
function sqlArts(db, tables){
  const out = [];
  for(const A of SQL_ARTS){ if(!A.need.every(t => tables.some(x => x.name.toLowerCase() === t.toLowerCase()))) continue;
    if(A.cols){ const t = tables.find(x => x.name.toLowerCase() === A.need[0].toLowerCase()); if(!A.cols.every(c => t.cols.some(x => x.name.toLowerCase() === c.toLowerCase()))) continue; }
    try{ const n = sqlExec(db, `SELECT count(*) FROM (${A.sql})`).rows[0][0]; out.push({...A, n}); }catch(e){} }
  return out;
}
/* free pages often hold what is left of deleted rows */
function sqlFree(b){
  const u16 = o => (b[o] << 8) | b[o + 1], u32 = o => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
  let ps = u16(16); if(ps === 1) ps = 65536; const total = u32(36); let trunk = u32(32); const pages = [];
  for(let g = 0; trunk && g < 10000 && pages.length < 20000; g++){ const o = (trunk - 1) * ps; if(o + 8 > b.length) break; pages.push(trunk); const n = u32(o + 4); for(let i = 0; i < n && i < ps / 4; i++) pages.push(u32(o + 8 + i * 4)); trunk = u32(o); }
  const found = []; const seen = new Set();
  for(const p of pages){ const o = (p - 1) * ps; if(o < 0 || o + ps > b.length) continue; const s = latin1(b, o, o + ps);
    for(const m of s.matchAll(/[\x20-\x7e]{8,}/g)){ const t = m[0].trim(); if(t.length < 8 || seen.has(t) || !/[a-z]{3}/i.test(t)) continue; seen.add(t); found.push({page:p, text:t}); if(found.length >= 3000) break; } }
  return {ps, total, scanned:pages.length, found};
}

/* ---------- open ---------- */
async function sqlLoad(f){
  if(f.size > 300 * 1048576) return toast('That database is over 300 MB — too big for a browser tab');
  UI.sql = {busy:true, name:f.name}; UI.sqlView = null; renderMain();
  try{
    const buf = new Uint8Array(await f.arrayBuffer());
    if(latin1(buf, 0, 15) !== 'SQLite format 3') throw new Error('This is not a SQLite database (the file does not start with “SQLite format 3”).');
    const wal = buf[18] === 2 || buf[19] === 2, copy = buf.slice(); if(wal){ copy[18] = 1; copy[19] = 1; }
    const SQL = await sqlEngine(), db = new SQL.Database(copy);
    const tables = sqlExec(db, `SELECT name, type FROM sqlite_master WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%' ORDER BY type, name`).rows.map(([name, type]) => {
      const cols = sqlExec(db, `PRAGMA table_info("${name.replace(/"/g, '""')}")`).rows.map(r => ({name:r[1], type:r[2]})); let n = null; try{ n = sqlExec(db, `SELECT count(*) FROM "${name.replace(/"/g, '""')}"`).rows[0][0]; }catch(e){}
      return {name, type, cols, n}; });
    const apple = tables.some(t => /^Z[A-Z]/.test(t.name) || /^(history_items|message|ZSFARTIFACT)$/.test(t.name));
    const arts = sqlArts(db, tables);
    UI.sql = {name:f.name, size:f.size, file:f, db, tables, arts, apple, wal, sha256:await sha256Hex(buf.buffer), free:sqlFree(buf), user:{version:(buf[60] << 24 | buf[61] << 16 | buf[62] << 8 | buf[63]) >>> 0, enc:['', 'UTF-8', 'UTF-16le', 'UTF-16be'][(buf[56] << 24 | buf[57] << 16 | buf[58] << 8 | buf[59]) >>> 0] || ''}};
    UI.sqlView = arts.length ? {kind:'art', id:arts[0].id} : tables.length ? {kind:'table', name:tables[0].name} : {kind:'sql'};
    UI.sqlPage = 0; UI.sqlQ = ''; UI.sqlSort = null;
  }catch(e){ UI.sql = null; toast(e.message || 'Could not open that database'); }
  renderMain();
}

/* ---------- query the current view ---------- */
const qid = s => '"' + String(s).replace(/"/g, '""') + '"';
function sqlCurrent(limit = 100, offset = 0){
  const S = UI.sql, V = UI.sqlView || {}; let base, ts = {}, meta = null;
  if(V.kind === 'art'){ meta = S.arts.find(a => a.id === V.id); if(!meta) return null; base = meta.sql; ts = {...meta.ts}; }
  else if(V.kind === 'table'){ const t = S.tables.find(x => x.name === V.name); if(!t) return null; meta = t; base = `SELECT * FROM ${qid(t.name)}`; }
  else if(V.kind === 'sql'){ if(!UI.sqlRes) return null; return UI.sqlRes; }
  const q = (UI.sqlQ || '').trim(); let cols = sqlExec(S.db, `SELECT * FROM (${base}) LIMIT 0`).cols;
  if(!cols.length){ try{ const st = S.db.prepare(`SELECT * FROM (${base})`); cols = st.getColumnNames(); st.free(); }catch(e){} }
  const where = q ? ' WHERE ' + cols.map(c => `CAST(${qid(c)} AS TEXT) LIKE $q`).join(' OR ') : '', params = q ? {$q:'%' + q + '%'} : undefined;
  const ord = UI.sqlSort && cols.includes(UI.sqlSort.col) ? ` ORDER BY ${qid(UI.sqlSort.col)} ${UI.sqlSort.desc ? 'DESC' : 'ASC'}` : '';
  const total = sqlExec(S.db, `SELECT count(*) FROM (${base})${where}`, params).rows[0][0];
  const R = sqlExec(S.db, `SELECT * FROM (${base})${where}${ord} LIMIT ${limit} OFFSET ${offset}`, params);
  /* detect time columns on this page; artefact views may say 'auto' */
  const res = {cols:R.cols.length ? R.cols : cols, rows:R.rows, total, ts:{}, meta};
  res.cols.forEach((c, i) => { const want = ts[c]; const vals = R.rows.map(r => r[i]);
    if(want && want !== 'auto') res.ts[c] = want; else { const g = tsGuess(c, vals, S.apple || want === 'auto'); if(g) res.ts[c] = g; } });
  return res;
}
function sqlCell(v, k){
  if(v == null) return '<span class="t3">NULL</span>';
  if(v instanceof Uint8Array){ const h = hex(v, 4), kind = h.startsWith('62706c6973') ? 'plist' : h.startsWith('89504e47') ? 'PNG' : h.startsWith('ffd8ff') ? 'JPEG' : h.startsWith('1f8b') ? 'gzip' : ''; return `<span class="cxt">${kind ? kind + ' · ' : ''}blob ${fmtBytes(v.length)}</span>`; }
  if(k){ const f = tsFmt(v, k); if(f) return `<span class="mono sq-time" title="${esc(String(v))} · ${esc(TS_KINDS[k].label)}">${esc(f)}</span>`; }
  const s = String(v); return s.length > 220 ? esc(s.slice(0, 220)) + '<span class="t3">…</span>' : esc(s);
}

/* ---------- view ---------- */
function labSql(){
  const S = UI.sql;
  if(!S) return `<label class="drop" id="sqDrop" tabindex="0"><input type="file" id="sqIn" class="sr">${ico('database')}<b>Drop a SQLite database, or click to choose</b>
    <span>Browser history, cookies, phone messages, app databases — up to 300 MB. Opened as a copy in your browser; the original is never changed.</span>
    <span class="drop-feat"><i>Chrome · Edge · Brave</i><i>Firefox</i><i>Safari</i><i>Android SMS &amp; calls</i><i>iPhone messages</i><i>WhatsApp</i><i>Any table</i><i>Timestamps decoded</i><i>Deleted-data scan</i><i>SQL console</i></span></label>
    <details class="caphelp" style="margin-top:12px"><summary>${ico('circle-help','sm')}Where do I find these files?</summary><div class="caphelp-b"><ul>
      <li><b>Chrome</b> (Windows): <span class="mono">%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\History</span> — also <span class="mono">Cookies</span>, <span class="mono">Login Data</span>, <span class="mono">Web Data</span>. Edge and Brave use the same names in their own folders.</li>
      <li><b>Firefox</b>: <span class="mono">places.sqlite</span>, <span class="mono">cookies.sqlite</span>, <span class="mono">formhistory.sqlite</span> in the profile folder (about:profiles shows it).</li>
      <li><b>Safari</b> (macOS): <span class="mono">~/Library/Safari/History.db</span>.</li>
      <li><b>Android / iPhone</b>: <span class="mono">mmssms.db</span>, <span class="mono">calllog.db</span>, <span class="mono">sms.db</span>, <span class="mono">msgstore.db</span> from a forensic extraction or backup.</li></ul>
      <p>Close the browser first or copy the file — a running browser locks it. If a <span class="mono">-wal</span> file sits next to the database, the newest changes are in there and are not read here.</p></div></details>`;
  if(S.busy) return `<div class="card" style="padding:40px;text-align:center">${ico('refresh-cw','sm spin')} Opening ${esc(S.name)}${SQLJS ? '' : ' — loading the SQLite engine the first time'}…</div>`;
  const V = UI.sqlView || {}, apps = [...new Set(S.arts.map(a => a.app))];
  const side = `<nav class="sq-side">
    ${S.arts.length ? `<div class="caps">Artefacts</div>${S.arts.map(a => `<button data-act="sqView" data-v="art" data-id="${a.id}" aria-selected="${V.kind === 'art' && V.id === a.id}">${ico('sparkles','sm')}<span>${esc(a.label)}</span><small>${a.n.toLocaleString()}</small></button>`).join('')}` : ''}
    <div class="caps">Tables</div>${S.tables.filter(t => t.type === 'table').map(t => `<button data-act="sqView" data-v="table" data-id="${esc(t.name)}" aria-selected="${V.kind === 'table' && V.name === t.name}">${ico('table-2','sm')}<span class="mono">${esc(t.name)}</span><small>${t.n == null ? '' : t.n.toLocaleString()}</small></button>`).join('') || '<p class="t3 small">No tables.</p>'}
    ${S.tables.some(t => t.type === 'view') ? `<div class="caps">Views</div>${S.tables.filter(t => t.type === 'view').map(t => `<button data-act="sqView" data-v="table" data-id="${esc(t.name)}" aria-selected="${V.kind === 'table' && V.name === t.name}">${ico('eye','sm')}<span class="mono">${esc(t.name)}</span></button>`).join('')}` : ''}
    <div class="caps">Tools</div><button data-act="sqView" data-v="sql" aria-selected="${V.kind === 'sql'}">${ico('terminal','sm')}<span>SQL console</span></button>
    <button data-act="sqView" data-v="free" aria-selected="${V.kind === 'free'}">${ico('trash-2','sm')}<span>Deleted data</span><small>${S.free.found.length ? S.free.found.length.toLocaleString() : ''}</small></button>
    <button data-act="sqView" data-v="info" aria-selected="${V.kind === 'info'}">${ico('info','sm')}<span>File details</span></button></nav>`;
  return `<section class="card pc-head"><header><span class="fi-ic">${ico('database')}</span><div style="min-width:0;flex:1"><h3>${esc(S.name)}</h3>
      <p class="t3">${apps.length ? esc(apps.join(' · ')) : 'SQLite database'} · ${S.tables.filter(t => t.type === 'table').length} tables · ${fmtBytes(S.size)}${S.wal ? ' · WAL mode' : ''}</p></div>
      <div class="wrap"><button class="btn sm" data-act="sqSave">${ico('plus','sm')}Save to ${esc(theCase().code)}</button><button class="btn sm" data-act="sqClear">${ico('x','sm')}Another file</button></div></header></section>
    <div class="sq-grid">${side}<div class="sq-main" id="sqMain">${sqlMain()}</div></div>`;
}
function sqlMain(){
  const S = UI.sql, V = UI.sqlView || {};
  if(V.kind === 'info') return `<section class="card"><div class="body">
    <div class="kv"><span>SHA-256</span><code style="font-size:11.5px;word-break:break-all">${S.sha256}</code></div><div class="kv"><span>Size</span><b>${fmtBytes(S.size)}</b></div>
    <div class="kv"><span>Page size</span><b>${S.free.ps.toLocaleString()} bytes</b></div><div class="kv"><span>Free pages</span><b>${S.free.total.toLocaleString()}</b></div><div class="kv"><span>Text encoding</span><b>${esc(S.user.enc)}</b></div><div class="kv"><span>Journal</span><b>${S.wal ? 'WAL — recent changes may be in the separate -wal file' : 'rollback journal'}</b></div>
    <h4 class="caps" style="margin:16px 0 8px">Schema</h4><pre class="sq-schema">${esc(sqlExec(S.db, `SELECT sql FROM sqlite_master WHERE sql IS NOT NULL`).rows.map(r => r[0]).join(';\n\n'))}</pre></div></section>`;
  if(V.kind === 'free'){ const F = S.free, q = (UI.sqlQ || '').toLowerCase(), f = q ? F.found.filter(x => x.text.toLowerCase().includes(q)) : F.found;
    return `<p class="note" style="margin:0 0 12px"><span class="ic">${ico('info','sm')}</span><span>SQLite does not wipe deleted rows; their pages go on a free list until reused. ${F.scanned.toLocaleString()} free page${F.scanned === 1 ? '' : 's'} scanned — the text below was found there and is likely left over from deleted records. Treat it as a lead and confirm it another way.</span></p>
      ${sqFilter()}${f.length ? `<div class="tblwrap"><table class="tbl pc-t"><thead><tr><th class="num">Page</th><th>Text</th></tr></thead><tbody>${f.slice(0, 1000).map(x => `<tr><td class="num">${x.page}</td><td class="mono pc-wrap">${esc(x.text.slice(0, 400))}</td></tr>`).join('')}</tbody></table></div>` : pcEmpty(F.scanned ? 'No readable text on the free pages.' : 'This database has no free pages, so there is nothing left over to recover here.')}`; }
  if(V.kind === 'sql') return `<section class="card"><div class="body"><label class="sr" for="sqSql">SQL</label><textarea id="sqSql" class="inp mono sq-sql" spellcheck="false" placeholder="SELECT * FROM sqlite_master">${esc(UI.sqlText || '')}</textarea>
    <div class="wrap" style="margin-top:8px"><button class="btn primary sm" data-act="sqRun">${ico('play','sm')}Run</button><span class="t3 small">Read-only: SELECT, WITH, PRAGMA and EXPLAIN. Ctrl+Enter runs. At most 5,000 rows.</span></div></div></section>
    <div id="sqRes">${UI.sqlRes ? sqlGrid(UI.sqlRes, true) : ''}</div>`;
  let R; try{ R = sqlCurrent(100, (UI.sqlPage || 0) * 100); }catch(e){ return pcEmpty('Could not read this table: ' + e.message); }
  if(!R) return pcEmpty('Pick a table on the left.');
  return `${R.meta && R.meta.note ? `<p class="note" style="margin:0 0 12px"><span class="ic">${ico('lock','sm')}</span><span>${esc(R.meta.note)}</span></p>` : ''}${sqFilter()}${sqlGrid(R)}`;
}
const sqFilter = () => `<div class="pc-filter search-in">${ico('search')}<label class="sr" for="sqq">Filter</label><input id="sqq" class="inp" placeholder="Search every column…" value="${esc(UI.sqlQ || '')}"></div>`;
function sqlGrid(R, console){
  const tsCols = Object.entries(R.ts || {}), page = UI.sqlPage || 0, pages = Math.ceil(R.total / 100), how = R.meta && R.meta.how;
  return `${tsCols.length ? `<p class="t3 small sq-tsnote">${ico('clock-3','sm')} Times shown in ${esc(tz())}: ${tsCols.map(([c, k]) => `<b>${esc(c)}</b> read as ${esc(TS_KINDS[k].label)}`).join(' · ')}. Hover a time for the raw value.</p>` : ''}
    <div class="tblwrap sq-wrap"><table class="tbl pc-t sq-t"><thead><tr>${R.cols.map(c => `<th>${console ? esc(c) : `<button class="sq-th" data-act="sqSort" data-v="${esc(c)}">${esc(c)}${UI.sqlSort && UI.sqlSort.col === c ? (UI.sqlSort.desc ? ' ↓' : ' ↑') : ''}</button>`}</th>`).join('')}</tr></thead>
    <tbody>${R.rows.map(r => `<tr>${r.map((v, i) => `<td>${how && R.cols[i] === 'how' && how[v] ? esc(how[v]) : sqlCell(v, R.ts && R.ts[R.cols[i]])}</td>`).join('')}</tr>`).join('') || `<tr><td colspan="${R.cols.length || 1}" class="t3" style="text-align:center;padding:20px">No rows.</td></tr>`}</tbody></table></div>
    <div class="sq-foot"><span class="t3 small">${R.total.toLocaleString()} row${R.total === 1 ? '' : 's'}${console ? '' : pages > 1 ? ` · page ${page + 1} of ${pages.toLocaleString()}` : ''}</span>
      ${!console && pages > 1 ? `<button class="btn xs" data-act="sqPage" data-v="${page - 1}" ${page ? '' : 'disabled'}>${ico('chevron-left','sm')}Previous</button><button class="btn xs" data-act="sqPage" data-v="${page + 1}" ${page + 1 < pages ? '' : 'disabled'}>Next${ico('chevron-right','sm')}</button>` : ''}
      <span style="flex:1"></span><button class="btn xs" data-act="sqCsv" ${R.total ? '' : 'disabled'}>${ico('download','sm')}CSV</button><button class="btn xs" data-act="sqSend" ${R.total ? '' : 'disabled'}>${ico('list-plus','sm')}Send to timeline</button></div>`;
}
function sqlAll(){ /* every row of the current view, times converted */
  const V = UI.sqlView || {}; if(V.kind === 'sql') return UI.sqlRes;
  const R0 = sqlCurrent(1, 0); if(!R0) return null; const R = sqlCurrent(20000, 0); R.ts = {...R0.ts, ...R.ts}; return R;
}
function sqlCsv(){ const R = sqlAll(); if(!R) return; const V = UI.sqlView || {};
  const L = [R.cols.map(csvCell).join(',')].concat(R.rows.map(r => r.map((v, i) => { const k = R.ts && R.ts[R.cols[i]]; return csvCell(v instanceof Uint8Array ? '[blob ' + v.length + ' bytes]' : k && v ? tsISO(v, k) || v : v == null ? '' : v); }).join(',')));
  download((UI.sql.name + '-' + (V.id || V.name || 'query')).replace(/[^\w.-]+/g, '_') + '.csv', L.join('\n'), 'text/csv'); }
function sqlSend(){
  const R = sqlAll(); if(!R || !R.rows.length) return; const meta = R.meta, tcol = Object.keys(R.ts || {})[0] || '';
  const rows = R.rows.slice(0, 5000).map(r => { const o = {}; R.cols.forEach((c, i) => { const v = r[i], k = R.ts && R.ts[c]; o[c] = v instanceof Uint8Array ? '[blob ' + v.length + ' bytes]' : k && v ? tsISO(v, k) : v == null ? '' : String(meta && meta.how && c === 'how' && meta.how[v] ? meta.how[v] : v); });
    if(meta && meta.title){ try{ o.summary = String(meta.title(o)).slice(0, 140); }catch(e){} } o.artifact = meta && meta.label ? (meta.app + ' — ' + meta.label) : UI.sql.name; return o; });
  const cols = [...new Set(rows.flatMap(r => Object.keys(r)))];
  LOGIMP = {title:'Send rows to the timeline', caseId:DB.active, name:UI.sql.name, fmt:'SQLite' + (meta && meta.label ? ' · ' + meta.label : ''), rows, cols, map:{time:tcol, title:rows[0].summary != null ? 'summary' : logGuess(cols, 'title'), host:'', source:'artifact'}}; logImportDlg();
}
function sqlRun(){
  const S = UI.sql, t = ($('sqSql') || {}).value || ''; UI.sqlText = t; const sql = t.trim().replace(/;\s*$/, '');
  if(!sql) return; if(!/^(select|with|pragma|explain)\b/i.test(sql) || /;\s*\S/.test(sql)) return toast('Only one read-only statement: SELECT, WITH, PRAGMA or EXPLAIN');
  if(/^pragma\s+\w+\s*=/i.test(sql)) return toast('Changing settings is not allowed here');
  try{ const r = sqlExec(S.db, /^(select|with)\b/i.test(sql) ? `SELECT * FROM (${sql}) LIMIT 5000` : sql), R = {cols:r.cols, rows:r.rows, total:r.rows.length, ts:{}};
    R.cols.forEach((c, i) => { const g = tsGuess(c, R.rows.slice(0, 100).map(x => x[i]), S.apple); if(g) R.ts[c] = g; }); UI.sqlRes = R; }
  catch(e){ UI.sqlRes = null; const el = $('sqRes'); if(el) el.innerHTML = `<p class="note red" style="margin-top:12px"><span class="ic">${ico('triangle-alert','sm')}</span><span>${esc(e.message)}</span></p>`; return; }
  const el = $('sqRes'); if(el) el.innerHTML = sqlGrid(UI.sqlRes, true);
}
async function sqlSave(){
  const S = UI.sql; if(!S || S.busy) return; const cid = DB.active; let att = null;
  const L = [`SQLite database: ${S.name}`, `SHA-256: ${S.sha256}`, `Size: ${fmtBytes(S.size)}${S.wal ? ' (WAL mode — the -wal file was not included)' : ''}`, ''];
  if(S.arts.length){ L.push('Recognised artefacts:'); for(const a of S.arts) L.push(`- ${a.app}: ${a.label} (${a.n} rows)`); L.push(''); }
  L.push('Tables:'); for(const t of S.tables) L.push(`- ${t.name}${t.n != null ? ' (' + t.n + ' rows)' : ''}: ${t.cols.map(c => c.name).join(', ')}`);
  if(S.free.found.length) L.push('', `Free-list pages: ${S.free.scanned}, ${S.free.found.length} text fragments recovered (possible deleted data).`);
  const body = L.join('\n'); if(S.size <= 50 * 1048576){ try{ att = await storeFile(S.file); }catch(e){} }
  const r = {id:uid('r'), caseId:cid, type:'evidence', title:'SQLite database: ' + S.name, body, tsRaw:new Date(S.file.lastModified).toISOString(), tsZone:'explicit', ts:S.file.lastModified, source:'sqlite', host:'', tags:['sqlite'], ents:[], answer:'', addedBy:'You', addedAt:Date.now(), hash:'', pv:1, att:att ? [att] : []};
  DB.records.push(r); mutate('saved database ' + S.name); await hashRecords(); renderAll();
  toast('Saved to ' + theCase(cid).code + ' — use “Send to timeline” to add the rows themselves', 'Open', () => { UI.sel = {kind:'rec', id:r.id}; UI.inspOpen = true; go(caseHash(cid, 'timeline')); });
}
function bindSql(){
  const inp = $('sqIn'), d = $('sqDrop');
  if(inp){ inp.onchange = () => { if(inp.files[0]) sqlLoad(inp.files[0]); }; d.ondragover = e => { e.preventDefault(); d.classList.add('over'); }; d.ondragleave = () => d.classList.remove('over');
    d.ondrop = e => { e.preventDefault(); d.classList.remove('over'); const f = e.dataTransfer.files[0]; if(f) sqlLoad(f); }; d.onkeydown = e => { if(e.key === 'Enter' || e.key === ' '){ e.preventDefault(); inp.click(); } }; }
  const q = $('sqq'); if(q) q.oninput = () => { clearTimeout(q.__t); q.__t = setTimeout(() => { UI.sqlQ = q.value; UI.sqlPage = 0; const m = $('sqMain'); if(m){ m.innerHTML = sqlMain(); bindSql(); const x = $('sqq'); if(x){ x.focus(); x.setSelectionRange(x.value.length, x.value.length); } } }, 220); };
  const ta = $('sqSql'); if(ta) ta.onkeydown = e => { if(e.key === 'Enter' && (e.ctrlKey || e.metaKey)){ e.preventDefault(); sqlRun(); } };
}
const sqMainPaint = () => { const m = $('sqMain'); if(m){ m.innerHTML = sqlMain(); bindSql(); } else renderMain(); };
const SQL_ACTS = {
  sqView:(id, v) => { UI.sqlView = v === 'art' ? {kind:'art', id} : v === 'table' ? {kind:'table', name:id} : {kind:v}; UI.sqlPage = 0; UI.sqlQ = ''; UI.sqlSort = null; renderMain(); },
  sqPage:(id, v) => { UI.sqlPage = Math.max(0, +v); sqMainPaint(); },
  sqSort:(id, v) => { UI.sqlSort = UI.sqlSort && UI.sqlSort.col === v ? {col:v, desc:!UI.sqlSort.desc} : {col:v, desc:false}; UI.sqlPage = 0; sqMainPaint(); },
  sqRun:() => sqlRun(), sqCsv:() => sqlCsv(), sqSend:() => sqlSend(), sqSave:() => sqlSave(),
  sqClear:() => { if(UI.sql && UI.sql.db) try{ UI.sql.db.close(); }catch(e){} UI.sql = null; UI.sqlRes = null; renderMain(); }
};
