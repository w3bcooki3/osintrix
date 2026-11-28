/* Browser profile: drop a Chrome, Edge, Brave, Firefox or Safari profile folder (or a ZIP of it, or just some of its files)
   and get one picture of what the person did: who was signed in, every page visited, what they searched for and typed
   into the address bar, what they downloaded and from where, the sites they saved logins for (user names only: passwords
   are never read), what they typed into forms, their bookmarks and extensions, and which sites left cookies. Everything
   lands on one timeline with the hours of the day the browser was used. A -wal file next to a database is replayed first,
   so the newest entries a running browser had not written back yet are read too. */
const BR_W = v => { v = +v; return v > 0 ? v / 1000 - 11644473600000 : NaN; };          // Chrome / WebKit: µs since 1601
const BR_P = v => { v = +v; return v > 0 ? v / 1000 : NaN; };                           // Firefox PRTime: µs since 1970
const BR_S = v => { v = +v; return v ? (v + 978307200) * 1000 : NaN; };                 // Safari: seconds since 2001
const BR_TRANS = ['link', 'typed', 'bookmark', 'frame', 'frame (clicked)', 'from the address bar', 'start page', 'form sent', 'reload', 'search keyword', 'search keyword'];
const BR_FFV = {1:'link', 2:'typed', 3:'bookmark', 4:'embed', 5:'redirect', 6:'redirect', 7:'download', 8:'frame (clicked)', 9:'reload'};
const BR_DANGER = ['', 'dangerous file type', 'dangerous site', 'dangerous content', 'possibly unwanted', 'uncommon', 'allowed by the user', 'dangerous host', 'potentially unwanted', 'allowlisted', 'blocked by policy'];
const BR_SHARE = /(^|\.)(mega\.(nz|io)|wetransfer\.com|we\.tl|dropbox\.com|drive\.google\.com|onedrive\.live\.com|1drv\.ms|box\.com|mediafire\.com|gofile\.io|file\.io|anonfiles\.com|transfer\.sh|sendspace\.com|pastebin\.com|ghostbin\.\w+|privatebin\.\w+|filemail\.com|swisstransfer\.com|pcloud\.com|icedrive\.net|tresorit\.com|catbox\.moe|krakenfiles\.com)$/i;
const BR_PRIV = /(^|\.)(proton\.me|protonmail\.(com|ch)|tuta(nota)?\.(com|io|de)|guerrillamail\.com|temp-mail\.org|10minutemail\.com|mailfence\.com|cock\.li|disroot\.org|riseup\.net|startmail\.com|posteo\.(de|net))$/i;
const BR_HIDE = /\b(delete|clear|wipe|erase|remove|hide|shred|destroy|cover)\b.{0,40}\b(history|usb|logs?|evidence|files?|tracks|traces|browsing|metadata|recycle|free space|hard drive|disk)\b|\b(ccleaner|bleachbit|eraser|sdelete|veracrypt|truecrypt|tails os|tor browser|anti.?forensic|incognito|private browsing|untraceable|wipe free space)\b/i;
const BR_EXE = /\.(exe|msi|dll|scr|bat|cmd|ps1|vbs|js|hta|lnk|iso|img|jar|apk|dmg|pkg|zip|rar|7z)$/i;
const BR_SECRET = /pass|pwd|otp|cvv|cvc|card.?num|ccnum|ssn|pin\b|token|secret|code$|recovery|2fa|mfa/i;

/* ---------- SQLite with its -wal replayed ---------- */
function brWal(db, wal){
  const be = (b, o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
  if(!wal || wal.length < 32) return null; const magic = be(wal, 0); if(magic !== 0x377f0682 && magic !== 0x377f0683) return null;
  const ps = be(wal, 8), s1 = be(wal, 16), s2 = be(wal, 20); if(!(ps >= 512 && ps <= 65536)) return null;
  let o = 32, pend = new Map(), done = new Map(), size = 0, nPend = 0, frames = 0;
  while(o + 24 + ps <= wal.length){ const pg = be(wal, o), commit = be(wal, o + 4); if(be(wal, o + 8) !== s1 || be(wal, o + 12) !== s2 || !pg) break;
    pend.set(pg, wal.subarray(o + 24, o + 24 + ps)); nPend++; if(commit){ for(const [k, v] of pend) done.set(k, v); pend.clear(); size = commit; frames += nPend; nPend = 0; } o += 24 + ps; }
  if(!done.size) return {bytes:db, frames:0, pages:0};
  const out = new Uint8Array(size * ps); out.set(db.subarray(0, Math.min(db.length, out.length)));
  for(const [k, v] of done) if(k <= size) out.set(v, (k - 1) * ps);
  out[18] = 1; out[19] = 1; out[28] = size >>> 24 & 255; out[29] = size >>> 16 & 255; out[30] = size >>> 8 & 255; out[31] = size & 255;
  out.set(out.subarray(24, 28), 92);                                     // "version valid for" = change counter, so the size above is trusted
  return {bytes:out, frames, pages:done.size};
}
async function brDb(bytes, wal){
  let b = bytes, W = null; if(wal){ W = brWal(bytes, wal); if(W) b = W.bytes; }
  const copy = b === bytes ? bytes.slice() : b; if(copy[18] === 2 || copy[19] === 2){ copy[18] = 1; copy[19] = 1; }
  const SQL = await sqlEngine(), db = new SQL.Database(copy);
  const tables = new Map(sqlExec(db, `SELECT name FROM sqlite_master WHERE type='table'`).rows.map(r => [r[0].toLowerCase(), new Set(sqlExec(db, `PRAGMA table_info("${String(r[0]).replace(/"/g, '""')}")`).rows.map(c => String(c[1]).toLowerCase()))]));
  return {db, tables, wal:W, q:(sql, p) => { try{ const r = sqlExec(db, sql, p); return r.rows.map(row => Object.fromEntries(r.cols.map((c, i) => [c, row[i]]))); }catch(e){ return []; } }, has:(t, ...cols) => tables.has(t) && cols.every(c => tables.get(t).has(c))};
}

/* ---------- reading the profile ---------- */
async function brItems(fileList){
  const items = [];
  for(const f of fileList){ const b = new Uint8Array(await f.arrayBuffer()), path = (f.webkitRelativePath || f.name).replace(/\\/g, '/');
    if(b[0] === 0x50 && b[1] === 0x4b && /\.zip$/i.test(f.name)){ const Z = zipOpen(b); if(!Z) continue;
      for(const e of Z.files.slice(0, 50000)){ if(/\/$/.test(e.name) || e.enc || e.size > 300 * 1048576) continue; const base = e.name.split('/').pop();
        if(!brWanted(base)) continue; const u = await fxZipEntry(b, e.name, 300 * 1048576).catch(() => null); if(u) items.push({path:e.name, name:base, bytes:u}); } }
    else if(brWanted(path.split('/').pop())) items.push({path, name:path.split('/').pop(), bytes:b}); }
  return items;
}
const brWanted = n => /^(History|History-wal|Web Data|Web Data-wal|Login Data|Login Data-wal|Login Data For Account|Login Data For Account-wal|Cookies|Cookies-wal|Top Sites|Top Sites-wal|Shortcuts|Shortcuts-wal|Bookmarks|Preferences|Secure Preferences|Local State|places\.sqlite|places\.sqlite-wal|formhistory\.sqlite|formhistory\.sqlite-wal|cookies\.sqlite|cookies\.sqlite-wal|logins\.json|extensions\.json|prefs\.js|History\.db|History\.db-wal|[^/]+\.(sqlite|db))$/i.test(n || '');
async function brRead(fileList){
  const items = await brItems(fileList), R = {files:[], ev:[], searches:[], typed:[], downloads:[], logins:[], autofill:[], addresses:[], cards:[], bookmarks:[], extensions:[], cookies:new Map(), visits:0, sites:new Map(),
    profile:{accounts:[], name:'', sync:'', dlDir:'', created:NaN}, browser:'', hints:new Set(), skipped:[]};
  const ev = (t, k, title, url, sub) => { if(isFinite(t)) R.ev.push({t, k, title:String(title || url || '').slice(0, 400), url:url || '', sub:sub || ''}); };
  const site = (url, t) => { let h = ''; try{ h = new URL(url).hostname.replace(/^www\./, ''); }catch(e){ return; } if(!h) return; const S = R.sites.get(h) || {h, n:0, first:t, last:t}; S.n++; if(t < S.first || !isFinite(S.first)) S.first = t; if(t > S.last || !isFinite(S.last)) S.last = t; R.sites.set(h, S); };
  for(const p of items.map(i => i.path)){ if(/microsoft\/edge/i.test(p)) R.hints.add('Microsoft Edge'); else if(/bravesoftware/i.test(p)) R.hints.add('Brave'); else if(/google\/chrome/i.test(p)) R.hints.add('Google Chrome'); else if(/opera/i.test(p)) R.hints.add('Opera'); else if(/mozilla\/firefox|\.default(-release)?\//i.test(p)) R.hints.add('Firefox'); }
  for(const it of items){ if(/-wal$/i.test(it.name)) continue; const head = latin1(it.bytes, 0, Math.min(16, it.bytes.length)), file = {path:it.path, what:'', n:0, wal:null};
    try{
      if(head === 'SQLite format 3\u0000'){ const walIt = items.find(x => x.path === it.path + '-wal'), D = await brDb(it.bytes, walIt && walIt.bytes); file.wal = walIt ? (D.wal ? D.wal.frames : 0) : null;
        if(file.wal){ const B = await brDb(it.bytes, null).catch(() => null), lbl = {visits:'visit', moz_historyvisits:'visit', downloads:'download', keyword_search_terms:'search', logins:'saved login', autofill:'form entry', moz_formhistory:'form entry', cookies:'cookie', moz_cookies:'cookie', omni_box_shortcuts:'typed entry'}, diff = [];
          if(B){ for(const [t, l] of Object.entries(lbl)) if(D.tables.has(t)){ const n1 = (D.q(`SELECT count(*) AS n FROM ${t}`)[0] || {}).n || 0, n0 = B.tables.has(t) ? ((B.q(`SELECT count(*) AS n FROM ${t}`)[0] || {}).n || 0) : 0; if(n1 > n0) diff.push((n1 - n0) + ' ' + l + (n1 - n0 > 1 ? 's' : '')); } try{ B.db.close(); }catch(e){} }
          file.walOnly = diff; }
        try{ brSqlite(D, R, ev, site, file); } finally { try{ D.db.close(); }catch(e){} } }
      else if(/^\s*[{\[]/.test(head)){ brJson(JSON.parse(new TextDecoder().decode(it.bytes)), it, R, ev, file); }
      else if(/prefs\.js$/i.test(it.name)){ const s = new TextDecoder().decode(it.bytes), pref = k => (s.match(new RegExp('user_pref\\("' + k.replace(/\./g, '\\.') + '",\\s*"([^"]*)"')) || [])[1] || '';
        R.profile.sync = R.profile.sync || pref('services.sync.username'); R.profile.dlDir = R.profile.dlDir || pref('browser.download.dir') || pref('browser.download.lastDir'); R.hints.add('Firefox'); file.what = 'Firefox settings'; }
    }catch(e){ file.what = 'could not be read (' + (e.message || 'error') + ')'; }
    if(file.what) R.files.push(file); else R.skipped.push(it.path); }
  R.ev.sort((a, b) => a.t - b.t); R.searches.sort((a, b) => b.t - a.t); R.downloads.sort((a, b) => b.t - a.t);
  R.browser = [...R.hints][0] || (R.files.some(f => /Chrome|Chromium/.test(f.what)) ? 'Chromium-based (Chrome, Edge, Brave…)' : '');
  return brFinish(R);
}
function brSqlite(D, R, ev, site, file){
  const q = D.q;
  if(D.has('urls', 'url') && D.has('visits', 'visit_time')){ file.what = 'Chrome / Edge history';
    for(const v of q(`SELECT v.visit_time AS t, u.url, u.title, v.transition AS tr, v.visit_duration AS dur FROM visits v JOIN urls u ON u.id = v.url ORDER BY v.visit_time`)){
      const core = (+v.tr || 0) & 0xff; if(core === 3) continue; const t = BR_W(v.t); R.visits++; file.n++; site(v.url, t); ev(t, 'visit', v.title || v.url, v.url, BR_TRANS[core] || ''); }
    if(D.has('keyword_search_terms', 'term')) for(const s of q(`SELECT k.term, u.url, u.last_visit_time AS t FROM keyword_search_terms k JOIN urls u ON u.id = k.url_id`)){ const t = BR_W(s.t); R.searches.push({term:s.term, url:s.url, t}); ev(t, 'search', s.term, s.url, 'searched'); }
    if(D.has('downloads', 'target_path')){ const chain = D.has('downloads_url_chains', 'url') ? q(`SELECT id, chain_index AS i, url FROM downloads_url_chains ORDER BY id, chain_index`) : [];
      for(const d of q(`SELECT * FROM downloads ORDER BY start_time`)){ const urls = chain.filter(c => c.id === d.id).map(c => c.url), t = BR_W(d.start_time), path = d.target_path || d.current_path || '';
        const D2 = {t, end:BR_W(d.end_time), path, name:path.split(/[\\/]/).pop() || '(not saved)', url:urls[urls.length - 1] || d.tab_url || '', chain:urls, tab:d.tab_url || '', ref:d.referrer || d.tab_referrer_url || '', bytes:+d.received_bytes || +d.total_bytes || 0,
          mime:d.mime_type || '', state:['in progress', 'complete', 'cancelled', 'interrupted'][+d.state] || '', danger:BR_DANGER[+d.danger_type] || '', opened:!!+d.opened};
        R.downloads.push(D2); ev(t, 'download', D2.name, D2.url, [D2.state, D2.opened ? 'opened' : '', D2.danger].filter(Boolean).join(' · ')); } } }
  if(D.has('logins', 'origin_url') && D.has('logins', 'username_value')){ file.what = 'Chrome / Edge saved logins';
    for(const l of q(`SELECT origin_url, action_url, username_value, date_created, date_last_used, times_used FROM logins`)){ file.n++;      // password_value is never read
      const L = {site:l.origin_url, user:l.username_value || '', created:BR_W(l.date_created), used:BR_W(l.date_last_used), n:+l.times_used || 0}; R.logins.push(L);
      ev(L.created, 'login', 'Saved a login for ' + brHost(L.site), L.site, L.user); if(isFinite(L.used) && L.used !== L.created) ev(L.used, 'login', 'Signed in with a saved login on ' + brHost(L.site), L.site, L.user); } }
  if(D.has('autofill', 'name', 'value')){ file.what = 'Chrome / Edge form data';
    for(const a of q(`SELECT name, value, count, date_created, date_last_used FROM autofill`)){ file.n++; const A = brAuto(a.name, a.value, +a.count, BR_P(+a.date_created * 1e6), BR_P(+a.date_last_used * 1e6)); R.autofill.push(A); ev(A.first, 'form', A.field + ': ' + A.value, '', 'typed into a form' + (A.n > 1 ? ' · used ' + A.n + ' times' : '')); }
    if(D.has('autofill_profiles', 'guid')){ const g = (t, c) => D.has(t, 'guid', c) ? q(`SELECT guid, ${c} AS v FROM ${t}`) : [];
      const names = g('autofill_profile_names', 'full_name'), mails = g('autofill_profile_emails', 'email'), phones = g('autofill_profile_phones', 'number');
      for(const p of q(`SELECT * FROM autofill_profiles`)){ const pick = L => L.filter(x => x.guid === p.guid).map(x => x.v).filter(Boolean);
        R.addresses.push({name:pick(names).join(', '), email:pick(mails).join(', '), phone:pick(phones).join(', '), addr:[p.street_address, p.city, p.zipcode, p.country_code].filter(Boolean).join(', '), company:p.company_name || '', t:BR_P(+p.date_modified * 1e6), n:+p.use_count || 0}); } }
    if(D.has('credit_cards', 'name_on_card')) for(const c of q(`SELECT name_on_card, expiration_month, expiration_year, date_modified, use_count, ${D.has('credit_cards', 'nickname') ? 'nickname' : "'' AS nickname"} FROM credit_cards`))   // the number is encrypted and never read
      R.cards.push({name:c.name_on_card || '', exp:c.expiration_month ? String(c.expiration_month).padStart(2, '0') + '/' + c.expiration_year : '', nick:c.nickname || '', t:BR_P(+c.date_modified * 1e6), n:+c.use_count || 0}); }
  if(D.has('cookies', 'host_key')){ file.what = 'Chrome / Edge cookies'; for(const c of q(`SELECT host_key AS h, name, creation_utc AS c, last_access_utc AS a FROM cookies`)){ file.n++; brCookie(R, c.h, BR_W(c.c), BR_W(c.a)); } }
  if(D.has('top_sites', 'url')){ file.what = 'Chrome top sites'; file.n = q(`SELECT count(*) AS n FROM top_sites`)[0].n; R.top = q(`SELECT url, title, url_rank AS r FROM top_sites ORDER BY url_rank`).slice(0, 20); }
  if(D.has('omni_box_shortcuts', 'text')){ file.what = 'Chrome address-bar shortcuts'; for(const s of q(`SELECT text, url, contents, last_access_time AS t, number_of_hits AS n FROM omni_box_shortcuts`)){ file.n++; const T = {text:s.text, url:s.url, title:s.contents || '', t:BR_W(s.t), n:+s.n || 0}; R.typed.push(T); ev(T.t, 'typed', 'Typed “' + T.text + '” in the address bar', T.url, T.n > 1 ? T.n + ' times' : ''); } }
  if(D.has('moz_places', 'url') && D.has('moz_historyvisits', 'visit_date')){ file.what = 'Firefox history'; R.hints.add('Firefox');
    for(const v of q(`SELECT h.visit_date AS t, p.url, p.title, h.visit_type AS vt FROM moz_historyvisits h JOIN moz_places p ON p.id = h.place_id ORDER BY h.visit_date`)){ if(+v.vt === 4 || +v.vt === 8) continue; const t = BR_P(v.t); R.visits++; file.n++; site(v.url, t); ev(t, 'visit', v.title || v.url, v.url, BR_FFV[+v.vt] || '');
      if(+v.vt === 2) R.typed.push({text:v.url, url:v.url, title:v.title || '', t, n:1}); }
    // searches: the query is in the address of the results page
    for(const p of q(`SELECT url, last_visit_date AS t FROM moz_places WHERE url LIKE '%q=%' OR url LIKE '%query=%' OR url LIKE '%search_query=%' OR url LIKE '%p=%'`)){ const term = brTerm(p.url); if(term){ R.searches.push({term, url:p.url, t:BR_P(p.t)}); ev(BR_P(p.t), 'search', term, p.url, 'searched'); } }
    if(D.has('moz_bookmarks', 'fk')) for(const b of q(`SELECT b.title, p.url, b.dateAdded AS t FROM moz_bookmarks b JOIN moz_places p ON p.id = b.fk WHERE b.type = 1`)){ if(/^place:/.test(b.url)) continue; R.bookmarks.push({title:b.title || b.url, url:b.url, t:BR_P(b.t)}); ev(BR_P(b.t), 'bookmark', b.title || b.url, b.url, 'bookmarked'); }
    if(D.has('moz_annos', 'content') && D.has('moz_anno_attributes', 'name')) for(const d of q(`SELECT p.url, a.content, a.dateAdded AS t FROM moz_annos a JOIN moz_anno_attributes n ON n.id = a.anno_attribute_id JOIN moz_places p ON p.id = a.place_id WHERE n.name = 'downloads/destinationFileURI'`)){
      let path = decodeURIComponent(String(d.content).replace(/^file:\/\/\/?/, '')); const t = BR_P(d.t), D2 = {t, path, name:path.split(/[\\/]/).pop(), url:d.url, chain:[d.url], tab:'', ref:'', bytes:0, mime:'', state:'', danger:'', opened:false}; R.downloads.push(D2); ev(t, 'download', D2.name, d.url, ''); } }
  if(D.has('moz_formhistory', 'fieldname')){ file.what = 'Firefox form history'; R.hints.add('Firefox');
    for(const a of q(`SELECT fieldname, value, timesUsed AS n, firstUsed AS f, lastUsed AS l FROM moz_formhistory`)){ file.n++; const A = brAuto(a.fieldname, a.value, +a.n, BR_P(a.f), BR_P(a.l)); R.autofill.push(A);
      if(/^searchbar-history$/i.test(a.fieldname)){ R.searches.push({term:a.value, url:'', t:A.last}); ev(A.last, 'search', a.value, '', 'search bar'); } else ev(A.first, 'form', A.field + ': ' + A.value, '', 'typed into a form' + (A.n > 1 ? ' · used ' + A.n + ' times' : '')); } }
  if(D.has('moz_cookies', 'host')){ file.what = 'Firefox cookies'; R.hints.add('Firefox'); for(const c of q(`SELECT host AS h, creationTime AS c, lastAccessed AS a FROM moz_cookies`)){ file.n++; brCookie(R, c.h, BR_P(c.c), BR_P(c.a)); } }
  if(D.has('history_items', 'url') && D.has('history_visits', 'visit_time')){ file.what = 'Safari history'; R.hints.add('Safari');
    for(const v of q(`SELECT v.visit_time AS t, i.url, v.title FROM history_visits v JOIN history_items i ON i.id = v.history_item ORDER BY v.visit_time`)){ const t = BR_S(v.t); R.visits++; file.n++; site(v.url, t); ev(t, 'visit', v.title || v.url, v.url, ''); } }
}
function brJson(J, it, R, ev, file){
  if(J && J.roots){ file.what = 'Chrome / Edge bookmarks'; const walk = (n, folder) => { if(!n) return; if(n.type === 'url'){ file.n++; const t = BR_W(n.date_added); R.bookmarks.push({title:n.name || n.url, url:n.url, t, folder}); ev(t, 'bookmark', n.name || n.url, n.url, 'bookmarked' + (folder ? ' in ' + folder : '')); }
      (n.children || []).forEach(c => walk(c, n.type === 'folder' && n.name ? n.name : folder)); }; Object.values(J.roots).forEach(r => walk(r, '')); return; }
  if(J && J.profile && J.profile.info_cache){ file.what = 'Chrome / Edge profiles list (Local State)'; for(const [dir, p] of Object.entries(J.profile.info_cache)){ file.n++; if(p.user_name && !R.profile.accounts.some(x => x.email === p.user_name)) R.profile.accounts.push({email:p.user_name, name:p.gaia_name || '', id:p.gaia_id || '', dir}); if(!R.profile.name && p.name) R.profile.name = p.name; } return; }
  if(J && (J.account_info || J.profile || J.extensions || J.download)){ file.what = 'Chrome / Edge settings (' + it.name + ')';
    for(const a of J.account_info || []){ if(!a.email) continue; const A = {email:a.email, name:a.full_name || a.given_name || '', id:a.gaia || '', hosted:a.hd && a.hd !== 'NO_HOSTED_DOMAIN' ? a.hd : ''}, X = R.profile.accounts.find(x => x.email === a.email);
      if(X) for(const k of Object.keys(A)){ if(!X[k] && A[k]) X[k] = A[k]; } else R.profile.accounts.push(A); }
    if(J.google && J.google.services && J.google.services.last_username && !R.profile.sync) R.profile.sync = J.google.services.last_username;
    if(J.profile){ R.profile.name = R.profile.name || J.profile.name || ''; const c = BR_W(J.profile.creation_time); if(isFinite(c)) R.profile.created = c; }
    if(J.download && J.download.default_directory) R.profile.dlDir = J.download.default_directory; else if(J.savefile && J.savefile.default_directory && !R.profile.dlDir) R.profile.dlDir = J.savefile.default_directory;
    if(J.edge || J.edge_shopping_assistant || /msedge|microsoft/i.test(JSON.stringify(J.browser || {}))) R.hints.add('Microsoft Edge'); if(J.brave) R.hints.add('Brave');
    for(const [id, x] of Object.entries((J.extensions && J.extensions.settings) || {})){ const m = x.manifest || {}; if(!m.name || x.location === 5 || x.location === 10) continue; if(R.extensions.some(e => e.id === id)) continue;
      file.n++; const E2 = {id, name:m.name, version:m.version || '', t:BR_W(x.install_time || x.first_install_time), store:!!x.from_webstore, unpacked:x.location === 4, on:x.state !== 0 && !(x.disable_reasons && (Array.isArray(x.disable_reasons) ? x.disable_reasons.length : x.disable_reasons)), perms:[...(m.permissions || []), ...(m.host_permissions || [])].map(String).slice(0, 12)};
      R.extensions.push(E2); ev(E2.t, 'extension', 'Installed the extension ' + E2.name, '', E2.store ? 'from the store' : E2.unpacked ? 'loaded unpacked' : 'not from the store'); }
    return; }
  if(J && Array.isArray(J.logins)){ file.what = 'Firefox saved logins'; R.hints.add('Firefox');
    for(const l of J.logins){ file.n++; const L = {site:l.hostname || l.origin || '', user:'(encrypted)', created:+l.timeCreated || NaN, used:+l.timeLastUsed || NaN, n:+l.timesUsed || 0}; R.logins.push(L); ev(L.created, 'login', 'Saved a login for ' + brHost(L.site), L.site, '');
      if(isFinite(L.used) && L.used !== L.created) ev(L.used, 'login', 'Signed in with a saved login on ' + brHost(L.site), L.site, ''); } return; }
  if(J && Array.isArray(J.addons)){ file.what = 'Firefox extensions'; R.hints.add('Firefox');
    for(const a of J.addons){ if(a.type !== 'extension' || a.location === 'app-builtin' || a.location === 'app-system-defaults' || /@mozilla\.(org|com)$/.test(a.id)) continue; file.n++;
      const E2 = {id:a.id, name:(a.defaultLocale && a.defaultLocale.name) || a.id, version:a.version || '', t:+a.installDate || NaN, store:/addons\.mozilla\.org|addons\.cdn\.mozilla/.test(a.sourceURI || ''), unpacked:a.location === 'app-temporary', on:!!a.active, perms:((a.userPermissions && a.userPermissions.permissions) || []).slice(0, 12)};
      R.extensions.push(E2); ev(E2.t, 'extension', 'Installed the extension ' + E2.name, '', E2.store ? 'from addons.mozilla.org' : 'not from addons.mozilla.org'); } return; }
}
const brHost = u => { try{ return new URL(u).hostname.replace(/^www\./, ''); }catch(e){ return String(u || '').replace(/^\w+:\/\//, '').split('/')[0]; } };
function brTerm(url){ try{ const U = new URL(url), h = U.hostname; if(!/google\.|bing\.com|duckduckgo|yahoo\.|yandex\.|baidu\.|ecosia|startpage|search\.brave|youtube\.com|qwant/.test(h)) return ''; const v = U.searchParams.get('q') || U.searchParams.get('query') || U.searchParams.get('search_query') || U.searchParams.get('text') || U.searchParams.get('wd') || (/yahoo/.test(h) ? U.searchParams.get('p') : ''); return (v || '').trim(); }catch(e){ return ''; } }
function brAuto(field, value, n, first, last){ const secret = BR_SECRET.test(field || ''); return {field:field || '', value:secret ? wcMaskV(value) : String(value || '').slice(0, 300), raw:secret ? '' : String(value || ''), secret, n, first, last}; }
const wcMaskV = v => typeof wcMask === 'function' ? wcMask(v) : '••••';
function brCookie(R, h, c, a){ h = String(h || '').replace(/^\./, ''); const C = R.cookies.get(h) || {h, n:0, first:c, last:a}; C.n++; if(c < C.first || !isFinite(C.first)) C.first = c; if(a > C.last || !isFinite(C.last)) C.last = a; R.cookies.set(h, C); }
function brFinish(R){
  const flags = [], vis = R.ev.filter(e => e.k === 'visit');
  for(const f of R.files) if(f.wal) flags.push(['', f.walOnly && f.walOnly.length ? `${f.walOnly.join(', ').replace(/, ([^,]*)$/, ' and $1')} ${f.walOnly.length > 1 || !/^1 /.test(f.walOnly[0]) ? 'were' : 'was'} only in ${f.path.split('/').pop()}-wal — the newest activity, not yet written into the main file. Read here; a tool that opens only the main file misses it.` : `${f.path.split('/').pop()}-wal held changes not yet written into the main file; they are read too.`]);
  const hide = [...R.searches.filter(s => BR_HIDE.test(s.term)).map(s => '“' + s.term + '”'), ...R.typed.filter(t => BR_HIDE.test(t.text)).map(t => '“' + t.text + '”')];
  if(hide.length) flags.push(['amber', `Searches about hiding or wiping traces: ${[...new Set(hide)].slice(0, 5).join(', ')}.`]);
  const share = [...R.sites.values()].filter(S => BR_SHARE.test(S.h)); if(share.length) flags.push(['amber', `File-sharing and paste sites visited: ${share.slice(0, 6).map(S => S.h + ' (' + S.n + ')').join(', ')}.`]);
  const mails = [...R.profile.accounts.map(a => a.email), R.profile.sync, ...R.logins.map(l => l.user), ...R.autofill.filter(a => !a.secret).map(a => a.raw)].filter(x => /^[^@\s]+@[^@\s]+\.\w+$/.test(x || '')).map(x => x.split('@')[1].toLowerCase());
  const priv = [...new Set([...R.logins.map(l => brHost(l.site)), ...R.sites.keys(), ...mails].filter(h => BR_PRIV.test(h)).map(regDomain))]; if(priv.length) flags.push(['', `Private or throwaway mail: ${priv.join(', ')}${R.logins.some(l => BR_PRIV.test(brHost(l.site))) ? ' — with a saved login' : ''}.`]);
  const risky = R.downloads.filter(d => BR_EXE.test(d.name) || d.danger); if(risky.length) flags.push([risky.some(d => d.danger && !/allowed|allowlisted/.test(d.danger)) ? 'red' : 'amber', `Programs or archives downloaded: ${risky.slice(0, 5).map(d => d.name + (d.danger ? ' (' + d.danger + ')' : '') + (d.opened ? ' — opened' : '')).join(', ')}.`]);
  const wide = R.extensions.filter(e => e.store && e.perms.some(p => /^(<all_urls>|proxy|cookies|webRequest|debugger|nativeMessaging)$|^\*:\/\/\*\//.test(p))); if(wide.length) flags.push(['', `Extensions that can read or reroute every site: ${wide.map(e => e.name + ' (' + e.perms.filter(p => /all_urls|proxy|cookies|webRequest|debugger|nativeMessaging|^\*:/.test(p)).join(', ') + ')').join('; ')}.`]);
  const odd = R.extensions.filter(e => !e.store); if(odd.length) flags.push(['amber', `Extensions not from the store: ${odd.map(e => e.name + (e.unpacked ? ' (loaded unpacked)' : '')).join(', ')} — check what they can read.`]);
  if(isFinite(R.profile.created) && vis.length && vis[0].t - R.profile.created > 30 * 864e5) flags.push(['amber', `The profile was made on ${new Date(R.profile.created).toISOString().slice(0, 10)} but its history starts on ${new Date(vis[0].t).toISOString().slice(0, 10)} — older history may have been cleared.`]);
  const hours = new Array(24).fill(0), Z = tz(); for(const e of R.ev.length > 60000 ? R.ev.filter((x, i) => i % Math.ceil(R.ev.length / 60000) === 0) : R.ev){ const h = +E.fmtFull(Math.floor(e.t), Z).slice(11, 13); if(h >= 0 && h < 24) hours[h]++; }
  // indicators: signed-in accounts, login and form e-mails and phones, the places downloads came from
  const iv = [...R.profile.accounts.map(a => a.email), R.profile.sync, ...R.logins.map(l => l.user).filter(u => /@/.test(u)), ...R.autofill.filter(a => !a.secret && /mail|phone|tel/i.test(a.field)).map(a => a.raw), ...R.addresses.flatMap(a => [a.email, a.phone]),
    ...R.downloads.map(d => d.url).filter(u => /^https?:/.test(u))].filter(Boolean);
  const iocs = E.extract(iv.join('\n')).filter((e, i, A) => A.findIndex(x => x.k === e.k && x.v === e.v) === i);
  return Object.assign(R, {flags, hours, iocs, sites:[...R.sites.values()].sort((a, b) => b.n - a.n), cookies:[...R.cookies.values()].sort((a, b) => b.n - a.n), from:R.ev.length ? R.ev[0].t : NaN, to:R.ev.length ? R.ev[R.ev.length - 1].t : NaN});
}

/* ---------- the view ---------- */
const BR_KIND = {visit:['Visits', 'globe'], search:['Searches', 'search'], typed:['Typed', 'keyboard'], download:['Downloads', 'download'], login:['Logins', 'key-round'], form:['Form entries', 'text-cursor-input'], bookmark:['Bookmarks', 'bookmark'], extension:['Extensions', 'puzzle']};
function labBrowser(){
  const R = UI.brP;
  if(!R) return `<label class="drop" id="brDrop" tabindex="0"><input type="file" id="brIn" class="sr" multiple>${ico('app-window')}<b>Drop a browser profile — its folder, a ZIP of it, or some of its files</b>
    <span>Chrome, Edge, Brave, Opera, Firefox and Safari. One timeline of visits, searches, what was typed in the address bar, downloads and where they came from, saved logins (user names only — passwords are never read), form entries, bookmarks and extensions, with the account that was signed in. A <span class="mono">-wal</span> file next to a database is read too.</span>
    <span class="drop-feat"><i>Signed-in accounts</i><i>Visits</i><i>Searches</i><i>Typed in the address bar</i><i>Downloads &amp; their source</i><i>Saved logins</i><i>Form entries</i><i>Extensions</i><i>Hours of use</i></span></label>
    <div class="wrap" style="margin-top:10px"><button class="btn" data-act="brFolder">${ico('folder-open','sm')}Choose a profile folder</button><button class="btn ghost" data-act="brExample">${ico('sparkles','sm')}Try an example profile</button><input type="file" id="brDir" class="sr" webkitdirectory multiple></div>
    <details class="caphelp" style="margin-top:12px"><summary>${ico('circle-help','sm')}Where is the profile?</summary><div class="caphelp-b"><ul>
      <li><b>Chrome</b> — Windows <span class="mono">%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default</span> (other profiles are <span class="mono">Profile 1</span>, <span class="mono">Profile 2</span>…; <span class="mono">Local State</span> sits one folder up). macOS <span class="mono">~/Library/Application Support/Google/Chrome/Default</span>.</li>
      <li><b>Edge</b> — <span class="mono">%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default</span>. <b>Brave</b> — <span class="mono">%LOCALAPPDATA%\\BraveSoftware\\Brave-Browser\\User Data\\Default</span>.</li>
      <li><b>Firefox</b> — <span class="mono">%APPDATA%\\Mozilla\\Firefox\\Profiles\\xxxx.default-release</span> (about:profiles shows it).</li>
      <li><b>Safari</b> — <span class="mono">~/Library/Safari</span> (History.db).</li></ul>
      <p>Work on a copy from your image or collection, not the live profile. Copy each database with its <span class="mono">-wal</span> file — the newest history is often only there. Passwords, cookie values and card numbers are encrypted by the browser and are never read here.</p></div></details>`;
  if(R.busy) return `<div class="card" style="padding:40px;text-align:center">${ico('refresh-cw','sm spin')} Reading the profile${SQLJS ? '' : ' — loading the SQLite engine the first time'}…</div>`;
  if(!R.files.length) return `<div class="card"><div class="body">No browser files recognised${R.skipped.length ? ' in ' + R.skipped.length + ' files' : ''}. Looking for History, Login Data, Web Data, Cookies, Bookmarks, Preferences (Chrome / Edge / Brave), places.sqlite, formhistory.sqlite, logins.json (Firefox) or History.db (Safari). <button class="lnk" data-act="brClear">Try another</button></div></div>`;
  const d = t => isFinite(t) ? E.fmtFull(Math.floor(t), tz()) : '', day = t => isFinite(t) ? E.fmtFull(Math.floor(t), tz()).slice(0, 10) : '';
  const P = R.profile, tab = UI.brTab || 'time', cnt = {time:R.ev.length, search:R.searches.length + R.typed.length, dl:R.downloads.length, login:R.logins.length + R.autofill.length + R.addresses.length + R.cards.length, site:R.sites.length, ext:R.bookmarks.length + R.extensions.length};
  const max = Math.max(1, ...R.hours);
  const head = `<section class="card"><header><span class="fi-ic">${ico('app-window')}</span><div style="min-width:0;flex:1"><h3>${esc(R.browser || 'Browser profile')}${P.name ? ` <span class="t3">· profile “${esc(P.name)}”</span>` : ''}</h3><p class="t3">${R.files.length} file${R.files.length === 1 ? '' : 's'} read${isFinite(R.from) ? ' · ' + esc(day(R.from)) + ' → ' + esc(day(R.to)) : ''}</p></div>
      <button class="btn sm primary" data-act="brSave">${ico('plus','sm')}Save to ${esc(caseNm(theCase()))}</button>${casePick()}<button class="btn sm" data-act="brSend">${ico('list-plus','sm')}Send to timeline</button>${DB.active ? casePick() : ''}<button class="btn sm" data-act="brCsv">${ico('download','sm')}CSV</button><button class="btn sm" data-act="brClear">${ico('x','sm')}Another</button></header><div class="body">
      ${P.accounts.map(a => fxKv('Signed in', a.email + (a.name ? ' (' + a.name + ')' : '') + (a.hosted ? ' · work account of ' + a.hosted : ''))).join('')}${fxKv('Sync account', P.sync && !P.accounts.some(a => a.email === P.sync) ? P.sync : '')}${fxKv('Downloads go to', P.dlDir)}${fxKv('Profile made', d(P.created))}
      ${R.flags.map(([c, t]) => `<div class="fx-note ${c}">${esc(t)}</div>`).join('')}
      <div class="br-hours" role="img" aria-label="Activity by hour of the day">${R.hours.map((n, h) => `<span title="${h}:00 — ${n} event${n === 1 ? '' : 's'}"><i style="height:${Math.round(n / max * 100)}%"></i><small>${h % 6 === 0 ? h : ''}</small></span>`).join('')}</div>
      <p class="t3 small" style="margin:4px 0 0">When the browser was used, by hour (${esc(tz())}). A quiet block is usually sleep — it hints at the person's time zone.</p>
      <details class="wc-det"><summary>Files read</summary>${R.files.map(f => `<div class="kv"><span class="mono">${esc(f.path)}</span><b>${esc(f.what)}${f.n ? ' · ' + f.n : ''}${f.wal != null ? ' · with its -wal' + (f.walOnly && f.walOnly.length ? ' (' + f.walOnly.join(', ') + ' only there)' : '') : ''}</b></div>`).join('')}${R.skipped.length ? `<p class="t3 small">Not a browser file: ${esc(R.skipped.slice(0, 8).join(', '))}</p>` : ''}</details></div></section>`;
  const tabs = `<div class="seg br-tabs" role="group" aria-label="Views">${[['time', 'Timeline'], ['search', 'Searches & typed'], ['dl', 'Downloads'], ['login', 'Logins & forms'], ['site', 'Sites'], ['ext', 'Bookmarks & extensions']].map(([k, l]) => `<button aria-pressed="${tab === k}" data-act="brTab" data-v="${k}">${l}<span class="t3"> ${cnt[k]}</span></button>`).join('')}</div>`;
  return head + tabs + `<section class="card"><div class="body" id="brBody">${brBody(R, tab, d)}</div></section>`;
}
function brBody(R, tab, d){
  const link = u => u ? `<code class="br-u">${esc(u.length > 140 ? u.slice(0, 139) + '…' : u)}</code>` : '';
  if(tab === 'time'){ const F = UI.brF || {}, q = (UI.brQ || '').toLowerCase(), on = k => !F.off || !F.off.includes(k);
    const L = R.ev.filter(e => on(e.k) && (!q || (e.title + ' ' + e.url + ' ' + e.sub).toLowerCase().includes(q))), pg = UI.brPg || 0, per = 200, show = L.slice().reverse().slice(pg * per, pg * per + per);
    let last = ''; const rows = show.map(e => { const dd = d(e.t).slice(0, 10), h = dd !== last ? `<div class="br-day">${esc(dd)}</div>` : ''; last = dd; const K = BR_KIND[e.k] || ['', 'circle'];
      return h + `<div class="br-ev k-${e.k}"><span class="mono t3">${esc(d(e.t).slice(11, 19))}</span><span class="br-k" title="${esc(K[0])}">${ico(K[1], 'sm')}</span><div><b>${esc(e.title)}</b>${e.url && e.url !== e.title ? link(e.url) : ''}${e.sub ? `<small>${esc(e.sub)}</small>` : ''}</div></div>`; }).join('');
    return `<div class="br-fil"><input class="inp" id="brQ" placeholder="Filter the timeline" value="${esc(UI.brQ || '')}" aria-label="Filter the timeline"><span class="wrap">${Object.entries(BR_KIND).filter(([k]) => R.ev.some(e => e.k === k)).map(([k, [l, i]]) => `<button class="chip${on(k) ? ' on' : ''}" data-act="brKind" data-v="${k}" aria-pressed="${on(k)}">${ico(i, 'sm')}${l}</button>`).join('')}</span></div>
      <p class="t3 small">${L.length} event${L.length === 1 ? '' : 's'}, newest first.</p>${rows || '<p class="t3">Nothing matches.</p>'}
      ${L.length > per ? `<div class="wrap" style="margin-top:10px">${pg ? `<button class="btn sm" data-act="brPg" data-v="${pg - 1}">Newer</button>` : ''}<span class="t3 small">${pg * per + 1}–${Math.min(L.length, pg * per + per)} of ${L.length}</span>${(pg + 1) * per < L.length ? `<button class="btn sm" data-act="brPg" data-v="${pg + 1}">Older</button>` : ''}</div>` : ''}`; }
  if(tab === 'search') return `<h4 class="wc-h">${ico('search','sm')}Searches</h4>${R.searches.length ? R.searches.slice(0, 500).map(s => `<div class="br-row${BR_HIDE.test(s.term) ? ' hot' : ''}"><span class="mono t3">${esc(d(s.t))}</span><b>${esc(s.term)}</b><span class="t3">${esc(brHost(s.url))}</span></div>`).join('') : '<p class="t3">No searches.</p>'}
    <h4 class="wc-h">${ico('keyboard','sm')}Typed in the address bar</h4>${R.typed.length ? R.typed.slice().sort((a, b) => b.t - a.t).slice(0, 300).map(t => `<div class="br-row"><span class="mono t3">${esc(d(t.t))}</span><b>${esc(t.text)}</b>${link(t.url)}${t.n > 1 ? `<span class="t3">${t.n}×</span>` : ''}</div>`).join('') : '<p class="t3">Nothing recorded (Chrome keeps it in Shortcuts; Firefox marks typed visits in places.sqlite).</p>'}`;
  if(tab === 'dl') return R.downloads.length ? R.downloads.map(x => `<div class="br-dl${BR_EXE.test(x.name) || x.danger ? ' hot' : ''}"><div class="br-dlh"><b>${esc(x.name)}</b>${x.state ? `<span class="pill">${esc(x.state)}</span>` : ''}${x.opened ? '<span class="pill" style="--c:var(--amber)">opened</span>' : ''}${x.danger ? `<span class="pill" style="--c:var(--red)">${esc(x.danger)}</span>` : ''}<span class="t3">${x.bytes ? fmtBytes(x.bytes) : ''}</span></div>
      ${fxKv('When', d(x.t))}${fxKv('Saved as', x.path, true)}${x.chain.length > 1 ? `<div class="kv"><span>Came from</span><span>${x.chain.map(u => link(u)).join('<br>')}</span></div>` : fxKv('Came from', x.url, true)}${fxKv('Page it was on', x.tab !== x.url ? x.tab : '', true)}${fxKv('Referrer', x.ref, true)}${fxKv('Type', x.mime)}</div>`).join('') : '<p class="t3">No downloads recorded.</p>';
  if(tab === 'login') return `<h4 class="wc-h">${ico('key-round','sm')}Saved logins <span class="t3">— passwords are never read</span></h4>${R.logins.length ? R.logins.slice().sort((a, b) => (b.used || b.created) - (a.used || a.created)).map(l => `<div class="br-row"><b>${esc(brHost(l.site))}</b><code>${esc(l.user || '(no user name)')}</code><span class="t3">saved ${esc(d(l.created).slice(0, 10))}${isFinite(l.used) ? ' · last used ' + esc(d(l.used).slice(0, 10)) : ''}${l.n ? ' · ' + l.n + '×' : ''}</span></div>`).join('') : '<p class="t3">None.</p>'}
    ${R.addresses.length ? `<h4 class="wc-h">${ico('contact','sm')}Saved names and addresses</h4>${R.addresses.map(a => `<div class="br-row"><b>${esc(a.name || '(no name)')}</b><span>${esc([a.email, a.phone, a.company, a.addr].filter(Boolean).join(' · '))}</span></div>`).join('')}` : ''}
    ${R.cards.length ? `<h4 class="wc-h">${ico('credit-card','sm')}Saved cards <span class="t3">— the number is encrypted and not read</span></h4>${R.cards.map(c => `<div class="br-row"><b>${esc(c.name || '(no name)')}</b><span>${esc([c.nick, c.exp ? 'expires ' + c.exp : '', c.n ? 'used ' + c.n + '×' : ''].filter(Boolean).join(' · '))}</span></div>`).join('')}` : ''}
    <h4 class="wc-h">${ico('text-cursor-input','sm')}Typed into forms</h4>${R.autofill.length ? R.autofill.slice().sort((a, b) => b.last - a.last).slice(0, 500).map(a => `<div class="br-row"><span class="t3">${esc(a.field)}</span><code class="${a.secret ? 'masked' : ''}">${esc(a.value)}</code><span class="t3">${a.n}× · ${esc(d(a.first).slice(0, 10))}${a.last !== a.first ? ' → ' + esc(d(a.last).slice(0, 10)) : ''}</span></div>`).join('') : '<p class="t3">None.</p>'}`;
  if(tab === 'site') return `<h4 class="wc-h">${ico('globe','sm')}Sites by visits</h4><div class="wc-hosts">${R.sites.slice(0, 200).map(S => `<div class="wc-host${BR_SHARE.test(S.h) || BR_PRIV.test(S.h) ? ' hot' : ''}"><div><code>${esc(S.h)}</code></div><small>${S.n} visit${S.n === 1 ? '' : 's'} · ${esc(d(S.first).slice(0, 10))} → ${esc(d(S.last).slice(0, 10))}</small></div>`).join('') || '<p class="t3">No history.</p>'}</div>
    ${R.cookies.length ? `<h4 class="wc-h">${ico('database','sm')}Sites with cookies <span class="t3">— values are encrypted and not read</span></h4><div class="wc-hosts">${R.cookies.slice(0, 200).map(C => `<div class="wc-host"><div><code>${esc(C.h)}</code></div><small>${C.n} cookie${C.n === 1 ? '' : 's'} · first ${esc(d(C.first).slice(0, 10))} · last used ${esc(d(C.last).slice(0, 10))}</small></div>`).join('')}</div>` : ''}
    ${R.top && R.top.length ? `<h4 class="wc-h">${ico('star','sm')}Top sites on the new-tab page</h4>${R.top.map(t => `<div class="br-row"><b>${esc(t.title || brHost(t.url))}</b>${link(t.url)}</div>`).join('')}` : ''}`;
  return `<h4 class="wc-h">${ico('puzzle','sm')}Extensions</h4>${R.extensions.length ? R.extensions.map(e => `<div class="br-row${e.store ? '' : ' hot'}"><b>${esc(e.name)}</b><span class="t3">${esc(e.version)} · ${e.store ? 'store' : e.unpacked ? 'loaded unpacked' : 'not from the store'}${e.on ? '' : ' · turned off'}${isFinite(e.t) ? ' · ' + esc(d(e.t).slice(0, 10)) : ''}</span><code class="t3">${esc(e.id)}</code>${e.perms.length ? `<small class="t3">${esc(e.perms.join(', '))}</small>` : ''}</div>`).join('') : '<p class="t3">None found (Chrome lists them in Preferences or Secure Preferences; Firefox in extensions.json).</p>'}
    <h4 class="wc-h">${ico('bookmark','sm')}Bookmarks</h4>${R.bookmarks.length ? R.bookmarks.slice().sort((a, b) => b.t - a.t).map(b => `<div class="br-row"><span class="mono t3">${esc(d(b.t).slice(0, 10))}</span><b>${esc(b.title)}</b>${link(b.url)}</div>`).join('') : '<p class="t3">None.</p>'}`;
}
function brLoad(fl){ if(!fl.length) return; UI.brP = {busy:true}; UI.brTab = 'time'; UI.brQ = ''; UI.brF = {}; UI.brPg = 0; renderMain();
  brRead([...fl]).then(R => { UI.brP = R; renderMain(); }).catch(e => { UI.brP = null; toast('Could not read the profile: ' + (e.message || e)); renderMain(); }); }
function bindBrowser(){
  const inp = $('brIn'), dir = $('brDir'), d = $('brDrop'), q = $('brQ');
  if(q) q.oninput = () => { clearTimeout(q.__t); q.__t = setTimeout(() => { UI.brQ = q.value; UI.brPg = 0; const b = $('brBody'); if(b && (UI.brTab || 'time') === 'time' && q.isConnected){ b.innerHTML = brBody(UI.brP, 'time', t => isFinite(t) ? E.fmtFull(Math.floor(t), tz()) : ''); bindBrowser(); const x = $('brQ'); if(x){ x.focus(); x.setSelectionRange(x.value.length, x.value.length); } } }, 220); };
  if(dir) dir.onchange = () => brLoad(dir.files);
  if(!inp) return; inp.onchange = () => brLoad(inp.files);
  d.ondragover = e => { e.preventDefault(); d.classList.add('over'); }; d.ondragleave = () => d.classList.remove('over');
  d.ondrop = async e => { e.preventDefault(); d.classList.remove('over'); const its = [...(e.dataTransfer.items || [])].map(i => i.webkitGetAsEntry && i.webkitGetAsEntry()).filter(Boolean);
    if(its.some(x => x.isDirectory)){ const out = []; const walk = (en, p) => new Promise(res => { if(en.isFile) return en.file(f => { try{ Object.defineProperty(f, 'webkitRelativePath', {value:p + f.name}); }catch(x){} out.push(f); res(); }, () => res());
        const r = en.createReader(), all = []; const more = () => r.readEntries(b => { if(!b.length) return Promise.all(all.map(c => walk(c, p + en.name + '/'))).then(res); all.push(...b); more(); }, () => res()); more(); });
      await Promise.all(its.map(x => walk(x, ''))); return brLoad(out); }
    brLoad(e.dataTransfer.files); };
  d.onkeydown = e => { if(e.key === 'Enter' || e.key === ' '){ e.preventDefault(); inp.click(); } };
}
/* the profile as one evidence record — what the Save button and the sample case add */
function brRecord(R, cid){ const P = R.profile, d = t => isFinite(t) ? new Date(t).toISOString().replace('T', ' ').slice(0, 19) + ' UTC' : '';
    const body = [`Browser profile: ${R.browser || 'unknown browser'}${P.name ? ' — profile “' + P.name + '”' : ''}`, P.accounts.length ? 'Signed in: ' + P.accounts.map(a => a.email + (a.name ? ' (' + a.name + ')' : '')).join(', ') : '', P.sync ? 'Sync account: ' + P.sync : '', P.dlDir ? 'Downloads folder: ' + P.dlDir : '',
      isFinite(R.from) ? `Activity: ${d(R.from)} → ${d(R.to)} — ${R.visits} visits, ${R.searches.length} searches, ${R.downloads.length} downloads, ${R.logins.length} saved logins (passwords not read), ${R.extensions.length} extensions` : '',
      R.flags.length ? 'Stands out:\n' + R.flags.map(f => '  - ' + f[1]).join('\n') : '', R.searches.length ? 'Searches:\n' + R.searches.slice(0, 40).map(x => `  ${d(x.t)}  ${x.term}`).join('\n') : '',
      R.downloads.length ? 'Downloads:\n' + R.downloads.slice(0, 40).map(x => `  ${d(x.t)}  ${x.name} ← ${x.url}${x.opened ? ' (opened)' : ''}`).join('\n') : '', R.logins.length ? 'Saved logins:\n' + R.logins.map(l => `  ${brHost(l.site)} — ${l.user}`).join('\n') : '',
      'Files read: ' + R.files.map(f => f.path).join(', ')].filter(Boolean).join('\n');
    const r = {id:uid('r'), caseId:cid, type:'evidence', title:'Browser profile: ' + (P.accounts[0] ? P.accounts[0].email : P.name || R.browser || 'profile'), body, tsRaw:isFinite(R.to) ? new Date(R.to).toISOString() : new Date().toISOString(), tsZone:'explicit', ts:isFinite(R.to) ? R.to : Date.now(), source:'browser-profile', host:'', tags:['browser'].concat(R.flags.some(f => f[0]) ? ['flag'] : []), ents:R.iocs, answer:'', addedBy:'You', addedAt:Date.now(), hash:''};
  return r; }
/* every event of the profile as timeline rows, the shape the log importer takes */
const brRows = R => R.ev.slice(-5000).map(e => ({time:new Date(e.t).toISOString(), summary:(BR_KIND[e.k] ? BR_KIND[e.k][0].replace(/s$/, '') + ': ' : '') + e.title, url:e.url, detail:e.sub, artifact:(R.browser || 'Browser') + ' — ' + e.k}));
const BR_MAP = {time:'time', title:'summary', host:'', source:'artifact'};
const BR_ACTS = {
  brFolder:() => { const x = $('brDir'); if(x) x.click(); },
  // the sample case's victim profile: made up, with reserved domains (tools/make_sample_forensics.py)
  brExample:async () => { const ok = typeof lazyNeed === 'function' && await lazyNeed('sample'), B = ok && typeof SAMPLE_OSINT !== 'undefined' && SAMPLE_OSINT.extra && SAMPLE_OSINT.extra.forensics && SAMPLE_OSINT.extra.forensics.browser;
    if(!B) return toast('The example profile could not be loaded');
    brLoad([new File([Uint8Array.from(atob(B.b64), c => c.charCodeAt(0))], B.name, {type:'application/zip', lastModified:B.mod})]); },
  brClear:() => { UI.brP = null; renderMain(); },
  brSave:() => { const R = UI.brP; if(!R || !R.files) return; const r = brRecord(R, DB.active);
    DB.records.push(r); mutate('saved browser profile'); hashRecords(); renderNav(); toast('Saved to ' + caseNm(theCase()) + ' with ' + R.iocs.length + ' indicators — “Send to timeline” adds every event', 'Open', () => { UI.sel = {kind:'rec', id:r.id}; UI.inspOpen = true; go(caseHash(DB.active, 'timeline')); }); },
  brTab:(id, v) => { UI.brTab = v; UI.brPg = 0; renderMain(); },
  brKind:(id, v) => { const F = UI.brF || (UI.brF = {}); F.off = F.off || []; F.off = F.off.includes(v) ? F.off.filter(x => x !== v) : F.off.concat(v); UI.brPg = 0; renderMain(); },
  brPg:(id, v) => { UI.brPg = +v; renderMain(); },
  brCsv:() => { const R = UI.brP; if(!R || !R.ev) return; download('browser-timeline.csv', ['time_utc,kind,title,url,detail'].concat(R.ev.map(e => [new Date(e.t).toISOString(), e.k, e.title, e.url, e.sub].map(csvCell).join(','))).join('\n'), 'text/csv'); },
  brSend:() => { const R = UI.brP; if(!R || !R.ev || !R.ev.length) return;
    LOGIMP = {title:'Send the browser timeline', caseId:DB.active, name:(R.browser || 'Browser') + ' profile', fmt:'Browser profile', rows:brRows(R), cols:['time', 'summary', 'url', 'detail', 'artifact'], map:Object.assign({}, BR_MAP)}; logImportDlg(); }
};
