/* ==========================================================================
   Security — encrypted workspace, encrypted backups, tamper-evident audit log
   and signed chain-of-custody reports. WebCrypto only; nothing leaves the page.

   Encryption: AES-256-GCM, key from your passphrase with PBKDF2-SHA-256
   (310 000 rounds). The workspace, restore points, attached files and the
   restore-point index are all sealed. The passphrase is never stored: lose it
   and the data cannot be recovered.

   Audit: every change is appended to a hash chain — each entry's hash covers
   the previous one — so editing or deleting a past entry breaks the chain.
   Custody reports list each record's SHA-256 with the chain and are signed
   with an ECDSA P-256 key that belongs to this workspace.
   ========================================================================== */
const SEC = {key:null, salt:null, iter:310000, locked:false, env:null};
const ENV_TAG = 'osintrix-aes-gcm';
const b64e8 = u => { let s = ''; const b = new Uint8Array(u); for(let i = 0; i < b.length; i += 32768) s += String.fromCharCode(...b.subarray(i, i + 32768)); return btoa(s); };
const b64d8 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
async function deriveKey(pass, salt, iter){
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pass.normalize('NFC')), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2', hash:'SHA-256', salt, iterations:iter}, base, {name:'AES-GCM', length:256}, false, ['encrypt', 'decrypt']);
}
async function sealWith(key, salt, iter, str, extra){
  const iv = crypto.getRandomValues(new Uint8Array(12)), ct = await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, new TextEncoder().encode(str));
  return JSON.stringify(Object.assign({enc:ENV_TAG, v:1, kdf:{name:'PBKDF2', hash:'SHA-256', iter, salt:b64e8(salt)}, iv:b64e8(iv), ct:b64e8(ct), at:Date.now()}, extra || {}));
}
async function openWith(key, env){ const e = typeof env === 'string' ? JSON.parse(env) : env; const pt = await crypto.subtle.decrypt({name:'AES-GCM', iv:b64d8(e.iv)}, key, b64d8(e.ct)); return new TextDecoder().decode(pt); }
const isEnv = s => typeof s === 'string' ? s.startsWith('{"enc":"' + ENV_TAG) : !!(s && s.enc === ENV_TAG);
/* workspace-level helpers used by storage, restore points and files */
async function sealStr(str){ return SEC.key ? sealWith(SEC.key, SEC.salt, SEC.iter, str) : str; }
async function openStr(str){ if(!isEnv(str)) return str; if(!SEC.key) throw new Error('locked'); return openWith(SEC.key, str); }
async function sealBlob(blob){ if(!SEC.key) return blob; const iv = crypto.getRandomValues(new Uint8Array(12)), ct = await crypto.subtle.encrypt({name:'AES-GCM', iv}, SEC.key, await blob.arrayBuffer()); return {enc:ENV_TAG, iv:b64e8(iv), ct, type:blob.type}; }
async function openBlob(v){ if(!v || !v.enc) return v; if(!SEC.key) return null; const pt = await crypto.subtle.decrypt({name:'AES-GCM', iv:b64d8(v.iv)}, SEC.key, v.ct); return new Blob([pt], {type:v.type || 'application/octet-stream'}); }

/* ---------- saving an encrypted workspace ---------- */
let sealing = null;
function flushSealed(json){
  const run = async () => { try{ const env = await sealWith(SEC.key, SEC.salt, SEC.iter, json); STORE.bytes = env.length * 2;
      let ok = false; try{ if(env.length < 2400000){ localStorage.setItem(STORE_KEY, env); STORE.ls = true; ok = true; } else { localStorage.removeItem(STORE_KEY); STORE.ls = false; } }catch(e){ STORE.ls = false; }
      if(STORE.idb){ ok = (await IDB.set(STORE_KEY, env)) || ok; } storageOK = ok; }catch(e){ storageOK = false; } STORE.lastSaved = Date.now(); paintSaved(); };
  sealing = (sealing || Promise.resolve()).then(run); return sealing;
}
/* re-seal everything stored beside the workspace (restore points, their index, attached files) with the current key state */
async function resealAll(fromKey){
  const conv = async s => { let plain = s; if(isEnv(s)){ if(!fromKey) return s; plain = await openWith(fromKey, s); } return SEC.key ? sealWith(SEC.key, SEC.salt, SEC.iter, plain) : plain; };
  const idx = await IDB.get('osintrix-snaps'); if(idx) await IDB.set('osintrix-snaps', await conv(idx));
  let list = []; try{ list = JSON.parse(isEnv(idx) && fromKey ? await openWith(fromKey, idx) : idx || '[]'); }catch(e){}
  for(const s of list){ const v = await IDB.get('osintrix-snap:' + s.at); if(v) await IDB.set('osintrix-snap:' + s.at, await conv(v)); }
  const fids = new Set(DB.records.concat((DB.trash || []).flatMap(x => x.kind === 'record' ? [x.data.r] : x.kind === 'case' ? x.data.records : [])).flatMap(r => (r.att || []).map(a => a.id)));
  for(const fid of fids){ let v = await IDB.get('file:' + fid); if(!v) continue; if(v.enc){ if(!fromKey) continue; const pt = await crypto.subtle.decrypt({name:'AES-GCM', iv:b64d8(v.iv)}, fromKey, v.ct); v = new Blob([pt], {type:v.type}); } await IDB.set('file:' + fid, await sealBlob(v)); }
  FILE_URLS.clear(); SNAPS = null;
}
async function encEnable(pass){
  const salt = crypto.getRandomValues(new Uint8Array(16)), key = await deriveKey(pass, salt, SEC.iter);
  Object.assign(SEC, {key, salt}); DB.security = Object.assign(DB.security || {}, {encrypted:true, since:Date.now()});
  await resealAll(null); await flushSealed(JSON.stringify(DB)); mutate('turned on encryption');
}
async function encChange(oldPass, newPass){
  const env = JSON.parse(localStorage.getItem(STORE_KEY) || (await IDB.get(STORE_KEY)) || 'null'); if(!isEnv(env)) throw new Error('not encrypted');
  const oldKey = await deriveKey(oldPass, b64d8(env.kdf.salt), env.kdf.iter); await openWith(oldKey, env);
  const salt = crypto.getRandomValues(new Uint8Array(16)), key = await deriveKey(newPass, salt, SEC.iter);
  Object.assign(SEC, {key, salt}); await resealAll(oldKey); await flushSealed(JSON.stringify(DB)); mutate('changed passphrase');
}
async function encDisable(pass){
  const env = JSON.parse(localStorage.getItem(STORE_KEY) || (await IDB.get(STORE_KEY)) || 'null'); if(!isEnv(env)) return;
  const k = await deriveKey(pass, b64d8(env.kdf.salt), env.kdf.iter); await openWith(k, env);
  SEC.key = null; SEC.salt = null; DB.security = Object.assign(DB.security || {}, {encrypted:false}); await resealAll(k); mutate('turned off encryption'); flush();
}

/* ---------- lock screen ---------- */
function lockScreen(env, done){
  const w = $('welcome'); w.hidden = false; w.classList.add('lockscr');
  w.innerHTML = `<div class="wcard lockcard">${logoMark(64)}<h1 id="wTitle" style="font-size:30px">This workspace is locked</h1><p>Your cases are encrypted in this browser. Enter your passphrase to open them.</p>
    <form id="unlockF" class="unlock"><label class="sr" for="unlockP">Passphrase</label><input id="unlockP" type="password" class="inp" autocomplete="current-password" placeholder="Passphrase" autofocus><button class="btn primary" type="submit">${ico('lock-open','sm')}Unlock</button></form>
    <p class="lockerr" id="unlockE" role="alert"></p>
    <p class="t3 lockfoot">Forgot it? There is no reset — that is what keeps the data private. <button class="linkbtn" type="button" id="eraseB">Erase this workspace and start over…</button></p></div>`;
  const f = $('unlockF');
  f.onsubmit = async ev => { ev.preventDefault(); const pass = $('unlockP').value; if(!pass) return; const e = JSON.parse(env); $('unlockE').textContent = 'Checking…';
    try{ const salt = b64d8(e.kdf.salt), key = await deriveKey(pass, salt, e.kdf.iter), txt = await openWith(key, e); Object.assign(SEC, {key, salt, iter:e.kdf.iter, locked:false});
      w.hidden = true; w.classList.remove('lockscr'); done(JSON.parse(txt)); }catch(err){ $('unlockE').textContent = 'That passphrase does not open this workspace.'; $('unlockP').select(); } };
  $('eraseB').onclick = () => { $('unlockE').innerHTML = `Type <b>ERASE</b> to delete every case, file and restore point in this browser: <input id="eraseI" class="inp" style="max-width:140px;display:inline-block;height:32px;margin-left:6px"> <button class="btn sm dangerfill" id="eraseGo" type="button">Erase</button>`;
    $('eraseGo').onclick = async () => { if($('eraseI').value !== 'ERASE') return; try{ localStorage.removeItem(STORE_KEY); }catch(e){} try{ IDB.db && IDB.db.close(); indexedDB.deleteDatabase('osintrix'); }catch(e){} setTimeout(() => location.reload(), 300); }; };
  setTimeout(() => { const p = $('unlockP'); if(p) p.focus({preventScroll:true}); }, 50);
}
async function lockNow(){ if(!SEC.key) return; await flush(); await sealing; location.reload(); }
let idleT = null;
function armAutolock(){ const m = +((DB.security || {}).autolock || 0); clearTimeout(idleT); if(!SEC.key || !m) return; idleT = setTimeout(lockNow, m * 60000); }
['pointerdown', 'keydown', 'wheel', 'touchstart'].forEach(t => document.addEventListener(t, () => { if(SEC.key) armAutolock(); }, {passive:true, capture:true}));

/* ---------- encrypted backup files ---------- */
async function passDlg(title, body, label, cb, confirm2){
  openDlg(dhead(title) + `<form data-form="pass"><div class="in"><p class="t2" style="margin:0 0 14px;font-size:14px">${body}</p>
    <div class="field"><label for="pw1">Passphrase</label><input id="pw1" type="password" class="inp" autocomplete="new-password" required minlength="${confirm2 ? 8 : 1}" autofocus>${confirm2 ? '<div class="pwmeter" id="pwM"><i></i></div><span class="hint" id="pwH">At least 8 characters. A few random words is strong and easy to remember.</span>' : ''}</div>
    ${confirm2 ? `<div class="field" style="margin:0"><label for="pw2">Repeat it</label><input id="pw2" type="password" class="inp" autocomplete="new-password" required></div>` : ''}<p class="lockerr" id="pwE" role="alert"></p></div>
    <footer><button class="btn" type="button" data-act="dclose">Cancel</button><button class="btn primary" type="submit">${label}</button></footer></form>`, false, () => {
      if(confirm2){ const p = $('pw1'); p.oninput = () => { const s = pwStrength(p.value); $('pwM').firstElementChild.style.width = s.pct + '%'; $('pwM').dataset.s = s.lvl; $('pwH').textContent = s.msg; }; } });
  PASS_CB = async () => { const a = $('pw1').value, b = confirm2 ? $('pw2').value : a; if(confirm2 && a.length < 8) return $('pwE').textContent = 'Use at least 8 characters.'; if(a !== b) return $('pwE').textContent = 'The two passphrases do not match.';
    $('pwE').textContent = 'Working…'; try{ await cb(a); }catch(e){ $('pwE').textContent = e && e.message === 'bad' ? 'That passphrase is not right.' : 'Something went wrong: ' + (e && e.message || e); } };
}
let PASS_CB = null;
function pwStrength(p){ let s = 0; if(p.length >= 8) s++; if(p.length >= 12) s++; if(p.length >= 16) s++; if(/[a-z]/.test(p) && /[A-Z]/.test(p)) s++; if(/\d/.test(p)) s++; if(/[^\w]/.test(p) || /\s/.test(p)) s++;
  const lvl = s <= 2 ? 'weak' : s <= 4 ? 'ok' : 'strong'; return {lvl, pct:Math.min(100, s / 6 * 100), msg:lvl === 'weak' ? 'Weak — make it longer.' : lvl === 'ok' ? 'Reasonable. Longer is better.' : 'Strong.'}; }
async function downloadEncrypted(name, obj){
  passDlg('Encrypt this file', 'Anyone who gets the file needs this passphrase to open it. It is not stored anywhere — keep it safe.', 'Encrypt and save', async pass => {
    const salt = crypto.getRandomValues(new Uint8Array(16)), key = await deriveKey(pass, salt, SEC.iter), env = await sealWith(key, salt, SEC.iter, JSON.stringify(obj), {format:'osintrix-encrypted', what:obj.format || 'backup'});
    closeDlg(); download(name.replace(/\.json$/, '') + '.encrypted.json', env, 'application/json'); }, true);
}
/* import side: any JSON picker calls this first */
function maybeDecrypt(txt, then){
  let d; try{ d = JSON.parse(txt); }catch(e){ return then(txt); }
  if(!(d && d.enc === ENV_TAG)) return then(txt);
  passDlg('Encrypted file', 'This file was encrypted with a passphrase. Enter it to open the file.', 'Decrypt', async pass => {
    let out; try{ const key = await deriveKey(pass, b64d8(d.kdf.salt), d.kdf.iter); out = await openWith(key, d); }catch(e){ throw new Error('bad'); } closeDlg(); then(out); }, false);
}

/* ---------- tamper-evident audit log ----------
   Each entry has a content hash d = SHA-256(index|time|case|action) that anyone can recompute, and a chain
   link h. Entries written from v1.17 on (marked m:1) link with HMAC-SHA-256 under a key that is created in
   this browser as a non-extractable CryptoKey and kept in IndexedDB, never in the workspace JSON or a backup.
   So editing the stored data or a backup cannot rewrite the chain: that needs code running in this browser
   with this key. Older entries keep their plain SHA-256 links and are checked as before. */
const sha256hex = async s => [...new Uint8Array(await crypto.subtle.digest('SHA-256', typeof s === 'string' ? new TextEncoder().encode(s) : s))].map(x => x.toString(16).padStart(2, '0')).join('');
const KEYS = {audit:null, sign:null};
async function deviceKey(name, make){
  if(KEYS[name]) return KEYS[name];
  if(!IDB.db) await IDB.open();
  let k = await IDB.get('key:' + name);
  if(!k && make){ k = await make(); if(!await IDB.set('key:' + name, k)) return null; }
  return KEYS[name] = k || null;
}
const auditKey = make => deviceKey('audit', make ? () => crypto.subtle.generateKey({name:'HMAC', hash:'SHA-256'}, false, ['sign', 'verify']) : null);
async function hmacHex(key, s){ return [...new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(s)))].map(x => x.toString(16).padStart(2, '0')).join(''); }
let auditQ = Promise.resolve();
function auditAdd(what){
  if(!DB) return; const A = DB.audit || (DB.audit = {entries:[], head:'genesis', n:0});
  const e = {i:A.n++, at:Date.now(), what:String(what).slice(0, 200), c:DB.active || '', d:'', h:''}; A.entries.push(e);
  auditQ = auditQ.then(async () => { const prev = A.entries[A.entries.indexOf(e) - 1]; e.d = await sha256hex(`${e.i}|${e.at}|${e.c}|${e.what}`);
    const key = await auditKey(true), link = (prev ? prev.h : A.base || 'genesis') + '|' + e.d;
    if(key){ e.h = await hmacHex(key, link); e.m = 1; if(KEYS.from == null){ const f = await IDB.get('key:audit-from'); KEYS.from = f ? +f : null; if(KEYS.from == null){ KEYS.from = e.i; IDB.set('key:audit-from', String(e.i)); } } } else e.h = await sha256hex(link);
    A.head = e.h;
    if(A.entries.length > 20000){ const cut = A.entries.splice(0, 5000); A.base = cut[cut.length - 1].h; A.baseI = cut[cut.length - 1].i; } });
}
/* mode 'local': keyed links are checked with this browser's key (or reported as written elsewhere).
   mode 'report': for a signed custody report, where keyed links are covered by the signature instead. */
async function auditVerify(entries, base, mode = 'local'){
  let prev = base || 'genesis', key = null, foreign = 0, keyed = 0;
  let from = null;   // in this browser, every entry from this index on must be keyed: stripping the marks is a rewrite
  if(mode === 'local'){ key = await auditKey(false); if(key){ const f = await IDB.get('key:audit-from'); from = f ? +f : null; } }
  for(let k = 0; k < entries.length; k++){ const e = entries[k]; const d = e.what != null ? await sha256hex(`${e.i}|${e.at}|${e.c}|${e.what}`) : e.d;
    if(d !== e.d) return {ok:false, at:k, why:'Entry ' + e.i + ' was edited after it was written'};
    if(k && e.i !== entries[k - 1].i + 1) return {ok:false, at:k, why:'Entry ' + (entries[k - 1].i + 1) + ' is missing'};
    if(!e.m && from != null && e.i >= from) return {ok:false, at:k, why:'Entry ' + e.i + ' lost its key mark — the log was rewritten outside this browser'};
    if(e.m){ keyed++;
      if(mode === 'local'){ if(!key){ foreign++; } else if(await hmacHex(key, prev + '|' + d) !== e.h) return {ok:false, at:k, why:'The chain breaks at entry ' + e.i + ' — an entry was changed, removed or reordered, or the log was rewritten outside this browser'}; }
    } else { const h = await sha256hex(prev + '|' + d); if(h !== e.h) return {ok:false, at:k, why:'The chain breaks at entry ' + e.i + ' — an entry before it was changed, removed or reordered'}; }
    prev = e.h; }
  return {ok:true, head:prev, n:entries.length, keyed, foreign};
}
/* Workspace signing key (ECDSA P-256). The private half is a non-extractable CryptoKey in this browser's
   IndexedDB; the workspace keeps only the public half. Older workspaces that carried the private key in their
   JSON are moved over on first use and the copy in the JSON is removed. */
async function signingKey(){
  DB.security = DB.security || {};
  const old = DB.security.sign && DB.security.sign.priv;
  const pair = await deviceKey('sign', async () => {
    if(old){ const priv = await crypto.subtle.importKey('jwk', old, {name:'ECDSA', namedCurve:'P-256'}, false, ['sign']); return {priv, pub:DB.security.sign.pub}; }
    const kp = await crypto.subtle.generateKey({name:'ECDSA', namedCurve:'P-256'}, false, ['sign', 'verify']);
    return {priv:kp.privateKey, pub:await crypto.subtle.exportKey('jwk', kp.publicKey)}; });
  if(!pair) throw new Error('This browser blocked key storage');
  if(!DB.security.sign || old || JSON.stringify(DB.security.sign.pub) !== JSON.stringify(pair.pub)){ DB.security.sign = {pub:pair.pub, made:(DB.security.sign && DB.security.sign.made) || Date.now()}; save(); }
  const fp = await keyFp(pair.pub); trustKey(fp, 'This workspace', true);
  return {pub:pair.pub, priv:pair.priv, fp};
}
const keyFp = async j => (await sha256hex(JSON.stringify({crv:j.crv, x:j.x, y:j.y}))).slice(0, 32);
/* Keys you have confirmed out of band. A valid signature from any other key is reported, never passed. */
function trustKey(fp, label, quiet){
  DB.security = DB.security || {}; const T = DB.security.trusted || (DB.security.trusted = []);
  if(T.some(t => t.fp === fp)) return; T.push({fp, label:String(label || 'Trusted key').slice(0, 80), added:Date.now()}); if(!quiet) mutate('trusted signing key ' + fp.slice(0, 8)); else save();
}
const trustedKey = fp => ((DB.security || {}).trusted || []).find(t => t.fp === fp) || null;
const canon = o => JSON.stringify(o, Object.keys(flatKeys(o)).sort());
function flatKeys(o, out = {}){ if(o && typeof o === 'object'){ for(const k of Object.keys(o)){ out[k] = 1; flatKeys(o[k], out); } } return out; }
async function custodyManifest(caseId){
  await auditQ; await hashRecords(); const K = await signingKey(), c = theCase(caseId), A = DB.audit || {entries:[]};
  const recs = DB.records.filter(r => r.caseId === caseId).map(r => ({id:r.id, title:r.title, captured:new Date(r.addedAt).toISOString(), event_time:r.ts ? new Date(r.ts).toISOString() : null, source:r.source || '', sha256:r.hash, files:(r.att || []).map(a => ({name:a.name, size:a.size, sha256:a.sha256}))}));
  const chain = A.entries.map(e => Object.assign(e.c === caseId || !e.c ? {i:e.i, at:e.at, c:e.c, what:e.what, d:e.d, h:e.h} : {i:e.i, at:e.at, d:e.d, h:e.h}, e.m ? {m:1} : {}));
  const body = {format:'osintrix-custody', v:2, generated:new Date().toISOString(), tool:BRAND.name + ' ' + BRAND.version, case:{id:c.id, code:c.code, name:c.name},
    records:recs, audit:{base:A.base || 'genesis', head:A.head, entries:chain}, key:{alg:'ECDSA-P256-SHA256', fingerprint:K.fp, jwk:{kty:K.pub.kty, crv:K.pub.crv, x:K.pub.x, y:K.pub.y}}};
  const sig = await crypto.subtle.sign({name:'ECDSA', hash:'SHA-256'}, K.priv, new TextEncoder().encode(canon(body)));
  return Object.assign(body, {signature:b64e8(sig)});
}
/* Each result: [state, text] where state is true (pass), false (fail) or 'warn' (needs your judgement). */
async function custodyVerify(m){
  const out = []; const push = (ok, t) => out.push([ok, t]);
  if(!m || m.format !== 'osintrix-custody' || !m.key || !m.key.jwk || !m.audit || !Array.isArray(m.records)) return [[false, 'Not an OSINTrix custody report']];
  const {signature, ...body} = m; let sigOk = false;
  try{ const pub = await crypto.subtle.importKey('jwk', {kty:'EC', crv:m.key.jwk.crv, x:m.key.jwk.x, y:m.key.jwk.y, ext:true}, {name:'ECDSA', namedCurve:'P-256'}, false, ['verify']);
    sigOk = await crypto.subtle.verify({name:'ECDSA', hash:'SHA-256'}, pub, b64d8(signature), new TextEncoder().encode(canon(body))); }catch(e){ push(false, 'Could not check the signature: ' + e.message); }
  const fp = await keyFp(m.key.jwk), t = trustedKey(fp), fpTxt = fp.replace(/(.{4})/g, '$1 ').trim();
  if(!sigOk) push(false, 'Signature does NOT match — the report was edited after signing, or signed with a different key.');
  else if(t) push(true, `Signed by a key you trust (${t.label}) and not changed since. Fingerprint ${fpTxt}.`);
  else push('warn', `The signature is valid, but the key is not one you have confirmed, so anyone could have made this report. Ask the sender for their key fingerprint and compare: ${fpTxt}.`);
  if(fp !== m.key.fingerprint) push(false, 'The fingerprint written in the report does not belong to its key.');
  const v = await auditVerify(m.audit.entries || [], m.audit.base, 'report'); push(v.ok, v.ok ? `Audit chain complete — ${v.n} entries in order, none edited${v.keyed ? ' (their links are covered by the signature)' : ''}.` : v.why);
  if(v.ok && m.audit.head && v.head !== m.audit.head) push(false, 'The chain head does not match the one recorded in the report.');
  const here = DB.records.filter(r => m.records.some(x => x.id === r.id));
  if(here.length){ const bad = here.filter(r => r.hash !== m.records.find(x => x.id === r.id).sha256); push(!bad.length, bad.length ? `${bad.length} record${bad.length > 1 ? 's' : ''} in this browser differ from the report: ${bad.slice(0, 3).map(r => r.title).join(', ')}` : `${here.length} records in this browser match the report.`); }
  else push(true, `${m.records.length} records listed with their SHA-256 (none of them are in this browser to compare).`);
  return {res:out, fp, sigOk, trusted:!!t};
}

/* ---------- Security page ---------- */
function viewSecurity(){
  const S = DB.security || {}, A = DB.audit || {entries:[]}, enc = !!SEC.key;
  if(!A.entries.length && !UI.auditV) UI.auditV = {ok:true, empty:true};
  const V = UI.auditV;
  if(!V && A.entries.length) auditQ.then(() => auditVerify(A.entries, A.base)).then(r => { UI.auditV = r; if(UI.route.area === 'security') renderMain(); });
  const recent = A.entries.slice(-40).reverse(), lastB = DB.prefs && DB.prefs.lastExport, fresh = lastB && Date.now() - lastB < 14 * 864e5;
  const chainOk = V ? V.ok : null, n = A.entries.length;
  const done = [enc, chainOk === true, !!S.sign, !!fresh], score = done.filter(Boolean).length;
  const todo = [!enc && 'turn on encryption', chainOk === false && 'fix the audit chain', !S.sign && 'create a signing key', !fresh && (lastB ? 'make a fresh backup' : 'make a backup')].filter(Boolean);
  const words = ['None','One','Two','Three','All four'];
  const C = 2 * Math.PI * 26, ring = `<svg class="sx2-ring" viewBox="0 0 64 64" aria-hidden="true"><circle cx="32" cy="32" r="26" class="bg"/><circle cx="32" cy="32" r="26" class="fg${score === 4 ? ' full' : ''}" stroke-dasharray="${(C * score / 4).toFixed(1)} ${C.toFixed(1)}" transform="rotate(-90 32 32)"/></svg>`;
  const st = (tone, icon) => `<span class="sx2-st ${tone}">${ico(icon,'sm')}</span>`;
  const item = (id, tone, icon, title, desc, state, acts, more = '') => `<section class="sx2-i" id="${id}">${st(tone, icon)}<div class="sx2-m"><h3>${title}</h3><p>${desc}</p>${more}</div><div class="sx2-s"><span class="sx2-v ${tone}">${state}</span><div class="sx2-b">${acts}</div></div></section>`;
  return `<div class="sx2">
    <div class="sx2-main"><div class="scroll"><div class="sx2-in">
      <header class="sx2-h"><span class="ix">Knowledge</span><h1>Security &amp; audit</h1><p>Protect what this browser stores, and prove later that your evidence was not changed.</p></header>
      <div class="sx2-score">${ring}<b class="sx2-n">${score}<small>/4</small></b><div><h2>${score === 4 ? 'All four protections in place' : words[score] + ' of four protections in place'}</h2><p>${score === 4 ? 'Encrypted, chained, signed and backed up. Keep backing up every couple of weeks.' : 'To finish: ' + todo.join(', ') + '.'}</p></div></div>
      <div class="sx2-list">
      ${item('enc', enc ? 'ok' : 'warn', enc ? 'lock' : 'lock-open', 'Workspace encryption', 'AES-256-GCM, key from your passphrase (PBKDF2 · 310,000 rounds). The passphrase is never stored — there is no recovery.',
        enc ? 'On' + (S.autolock ? ' · locks after ' + S.autolock + ' min' : '') : 'Off',
        enc ? `<button class="btn sm" data-act="secLock">${ico('lock','sm')}Lock now</button>` : `<button class="btn primary sm" data-act="secOn">${ico('lock','sm')}Turn on…</button>`,
        enc ? `<div class="sx2-x"><label for="secAuto">Lock automatically</label><select id="secAuto" class="gsel bord">${[[0,'Never'],[5,'After 5 minutes idle'],[15,'After 15 minutes idle'],[30,'After 30 minutes idle'],[60,'After 1 hour idle']].map(([v, l]) => `<option value="${v}"${+(S.autolock || 0) === v ? ' selected' : ''}>${l}</option>`).join('')}</select><button class="btn sm ghost" data-act="secChange">${ico('key-round','sm')}Change passphrase</button><button class="btn sm ghost sx-off" data-act="secOff">Turn off</button></div>` : '<p class="sx2-w">Anyone who can open this browser profile can read your cases.</p>')}
      ${item('audit', chainOk === false ? 'bad' : chainOk ? 'ok' : 'idle', chainOk === false ? 'triangle-alert' : 'link-2', 'Audit chain', 'Every change is chained with a key kept only in this browser. Editing, removing or rewriting any past entry — in the stored data or a backup — breaks it and shows where.',
        V ? (V.empty ? 'Empty' : V.ok ? (V.foreign ? 'Intact · ' + V.foreign + ' written elsewhere' : 'Intact · ' + n + ' entr' + (n === 1 ? 'y' : 'ies')) : 'Broken') : 'Checking…',
        `<button class="btn sm" data-act="auditCheck">${ico('shield-check','sm')}Verify</button>`, V && !V.ok ? `<p class="sx2-w bad">${esc(V.why)}</p>` : '')}
      ${item('key', S.sign ? 'ok' : 'idle', 'key-round', 'Signing key', 'ECDSA P-256 key that signs chain-of-custody reports. The private half never leaves this browser and is not in backups; share the fingerprint so others can confirm reports came from you.',
        S.sign ? 'Ready' : 'Not created', S.sign ? '' : `<button class="btn sm" data-act="secGo" data-v="custody">Create</button>`, S.sign ? `<p class="sx2-fp">Fingerprint <span class="mono" id="keyFp">…</span></p>` : '')}
      ${item('bkp', fresh ? 'ok' : 'warn', 'download', 'Backup', 'One file with every case, note, tool and setting. Seal it with its own passphrase and keep it off this computer.',
        lastB ? esc(ago(lastB)) + ' ago' : 'Never', `<button class="btn sm${fresh ? '' : ' primary'}" data-act="exportAll">${ico('download','sm')}Export</button><button class="btn sm" data-act="secBackup" title="Export everything, encrypted with its own passphrase">${ico('file-lock','sm')}Encrypted</button>`)}
      </div>
      <section class="sx2-cus" id="custody">${st('idle', 'stamp')}<div class="sx2-m"><h3>Chain-of-custody report</h3><p>A signed JSON file listing every record in a case with its SHA-256, capture time and attached files, plus the audit chain. Anyone can verify it here; any change after signing is detected.</p>
        <div class="sx2-cr"><label class="sr" for="cusCase">Case</label><select id="cusCase" class="gsel bord">${DB.cases.map(c => `<option value="${c.id}"${c.id === DB.active ? ' selected' : ''}>${esc(c.code + ' · ' + c.name)}</option>`).join('')}</select><button class="btn primary" data-act="cusMake">${ico('stamp','sm')}Create signed report</button><button class="btn" data-act="cusVerify">${ico('badge-check','sm')}Verify a report…</button></div></div></section>
    </div></div></div>
    <aside class="sx2-log" aria-label="Audit log"><header><div><span class="ix">Audit chain</span><h2>${n} entr${n === 1 ? 'y' : 'ies'}${V && !V.empty ? ' · ' + (V.ok ? 'intact' : 'broken') : ''}</h2></div><button class="btn sm" data-act="auditCsv" ${n ? '' : 'disabled'}>${ico('download','sm')}CSV</button></header>
      <div class="sx2-ll">${recent.length ? recent.map(e => `<div class="sx2-e"><i></i><div><b>${esc(e.what)}</b><span class="mono">${esc(E.fmtFull(e.at, tz()).slice(0, 19))} · <span title="${esc(e.h)}">${esc((e.h || '…').slice(0, 10))}</span></span></div></div>`).join('') : '<p class="sx2-none">No entries yet. Changes you make from now on are recorded here.</p>'}</div>
      ${A.head && A.head !== 'genesis' ? `<footer class="mono">head ${esc(A.head.slice(0, 24))}…</footer>` : ''}</aside>
  </div>`;
}
const SEC_ACTS = {
  secGo:(id, v) => { const el = $(v); if(el){ el.scrollIntoView({behavior:'smooth', block:'center'}); el.classList.add('flash'); setTimeout(() => el.classList.remove('flash'), 1200); } },
  secOn:() => passDlg('Encrypt this workspace', 'Choose a passphrase. You will need it every time you open ' + esc(BRAND.name) + ' in this browser. It cannot be recovered.', 'Encrypt', async p => { await encEnable(p); closeDlg(); renderAll(); toast('Encryption is on'); }, true),
  secChange:() => passDlg('Current passphrase', 'First, your current passphrase.', 'Next', async old => { const env = JSON.parse(localStorage.getItem(STORE_KEY) || (await IDB.get(STORE_KEY))); try{ const k = await deriveKey(old, b64d8(env.kdf.salt), env.kdf.iter); await openWith(k, env); }catch(e){ throw new Error('bad'); }
    closeDlg(); setTimeout(() => passDlg('New passphrase', 'Choose the new passphrase.', 'Change', async nw => { await encChange(old, nw); closeDlg(); renderAll(); toast('Passphrase changed'); }, true), 50); }, false),
  secOff:() => passDlg('Turn off encryption', 'Your data will be stored unencrypted in this browser. Enter the passphrase to confirm.', 'Turn off', async p => { try{ await encDisable(p); }catch(e){ throw new Error('bad'); } closeDlg(); renderAll(); toast('Encryption is off'); }, false),
  secLock:() => lockNow(),
  secBackup:() => { const files = null; exportEverything(true); },
  auditCheck:() => { UI.auditV = null; renderMain(); },
  auditCsv:() => { const A = DB.audit || {entries:[]}; download('osintrix-audit-' + new Date().toISOString().slice(0, 10) + '.csv', ['index,time,case,action,entry_hash,chain_hash'].concat(A.entries.map(e => [e.i, new Date(e.at).toISOString(), (theCase(e.c) || {}).code || '', e.what, e.d, e.h].map(csvCell).join(','))).join('\n'), 'text/csv'); },
  cusMake:async () => { const id = $('cusCase').value, m = await custodyManifest(id), c = theCase(id); download(slug(c.name) + '-custody.json', JSON.stringify(m, null, 2), 'application/json'); renderMain(); },
  cusVerify:() => pickFile('.json,application/json', txt => maybeDecrypt(txt, async t => { let m; try{ m = JSON.parse(t); }catch(e){ return toast('Not a JSON file'); } const V = await custodyVerify(m), res = Array.isArray(V) ? V : V.res;
    UI.cusTrust = !Array.isArray(V) && V.sigOk && !V.trusted ? V.fp : null;
    const row = ([ok, t]) => `<div class="vres ${ok === true ? 'ok' : ok === 'warn' ? 'warn' : 'bad'}">${ico(ok === true ? 'circle-check' : 'triangle-alert','sm')}<span>${esc(t)}</span></div>`;
    openDlg(dhead('Custody report check') + `<div class="in"><p class="t2" style="margin:0 0 12px">${esc(m && m.case ? m.case.code + ' · ' + m.case.name : '')}${m && m.generated ? ' · signed ' + esc(m.generated) : ''}</p>${res.map(row).join('')}
      ${UI.cusTrust ? `<form class="cus-trust" data-form="cusTrust"><label for="cusTL">Confirmed the fingerprint with the sender? Name this key to trust it from now on.</label><div><input id="cusTL" class="inp" placeholder="e.g. Priya — IR team laptop" autocomplete="off" required><button class="btn" type="submit">${ico('key-round','sm')}Trust this key</button></div></form>` : ''}</div>
      <footer><button class="btn primary" data-act="dclose">Close</button></footer>`); })),
};
function paintLock(){ let b = $('lockBtn'); if(SEC.key && !b){ b = document.createElement('button'); b.id = 'lockBtn'; b.className = 'iconbtn'; b.dataset.act = 'secLock'; b.title = 'Lock now'; b.setAttribute('aria-label', 'Lock the workspace'); b.innerHTML = ico('lock'); $('themeBtn').before(b); } if(!SEC.key && b) b.remove(); }
async function paintFp(){ const el = $('keyFp'); if(!el || !DB.security || !DB.security.sign) return; const s = DB.security.sign.pub; el.textContent = (await sha256hex(JSON.stringify({crv:s.crv, x:s.x, y:s.y}))).slice(0, 32).replace(/(.{4})/g, '$1 ').trim(); }
