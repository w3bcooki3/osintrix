/* ==========================================================================
   Story — for reporting.
   · Claims: each claim the story makes, its status, the evidence for and
     against it, and who it is about. A check before publishing lists what
     is not ready: too few independent sources, unverified pictures, people
     not yet given the right of reply, cited pages with no archived copy.
   · Protected sources: a person who gave you information is kept under a
     pseudonym. Their real details are encrypted with a passphrase of their
     own (AES-256-GCM, key from PBKDF2), held in memory only while unlocked,
     shown only when asked, and locked again after ten idle minutes or when
     the tab is hidden. The pseudonym is all that evidence, claims and
     exports carry. Burning a source wipes it from the workspace and from
     every restore point in this browser.
   · Right of reply: who was asked to comment, when, by when, and what they
     said.
   · Archived copies: the pages the case cites, saved to the Wayback Machine
     and checked, so a deleted page can still be shown.
   ========================================================================== */
const ST = {key:null, open:new Map(), shown:new Set(), idle:null};
const ST_IDLE = 10 * 60000;
const ST_REL = [['A', 'Completely reliable'], ['B', 'Usually reliable'], ['C', 'Fairly reliable'], ['D', 'Not usually reliable'], ['E', 'Unreliable'], ['F', 'Cannot be judged']];
const ST_STATUS = [['unverified', 'Unverified', 'circle-help'], ['confirmed', 'Confirmed', 'circle-check'], ['disputed', 'Disputed', 'scale'], ['false', 'False', 'circle-x']];
const ST_VERIFY = ['Reverse image search', 'Metadata (EXIF)', 'Content Credentials (C2PA)', 'Geolocated', 'Chronolocated (time of day, weather)', 'Confirmed with the author or source', 'Other'];
const ST_VIA = ['Email', 'Phone', 'Letter', 'In person', 'Through a lawyer or press office', 'Messaging app', 'Other'];
const stView = () => ['claims', 'sources', 'reply', 'archive'].includes(UI.stView) ? UI.stView : 'claims';
const stDay = ts => ts ? E.fmtDate(ts, tz()) : '';
const stDate = v => { const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(v || '').trim()); return m ? Date.UTC(+m[1], +m[2] - 1, +m[3], 12) : null; };
const stISO = ts => ts ? new Date(ts).toISOString().slice(0, 10) : '';
function stOf(c){ c.claims = Array.isArray(c.claims) ? c.claims : []; c.replies = Array.isArray(c.replies) ? c.replies : []; return c; }
const stSources = caseId => (DB.sources || []).filter(s => s.caseId === caseId);
const stSource = id => (DB.sources || []).find(s => s.id === id) || null;

/* ---------- protected sources: the passphrase, the key in memory ---------- */
const stVault = () => DB.srcVault && typeof DB.srcVault === 'object' && DB.srcVault.salt ? DB.srcVault : null;
function stArm(){ clearTimeout(ST.idle); if(ST.key) ST.idle = setTimeout(() => { stLock(); if(UI.route && UI.route.tab === 'story') renderMain(); }, ST_IDLE); }
function stLock(){ ST.key = null; ST.open.clear(); ST.shown.clear(); clearTimeout(ST.idle); }
document.addEventListener('visibilitychange', () => { if(document.hidden && ST.key){ stLock(); if(UI.route && UI.route.tab === 'story') renderMain(); } });
async function stSeal(obj){ const V = stVault(); return sealWith(ST.key, b64d8(V.salt), V.iter, JSON.stringify(obj)); }
async function stSetPass(pass){
  const salt = crypto.getRandomValues(new Uint8Array(16)), iter = SEC.iter, key = await deriveKey(pass, salt, iter);
  DB.srcVault = {salt:b64e8(salt), iter, check:await sealWith(key, salt, iter, 'osintrix-sources')}; ST.key = key; stArm(); }
async function stUnlock(pass){
  const V = stVault(); if(!V) return false; let key;
  try{ key = await deriveKey(pass, b64d8(V.salt), V.iter); if(await openWith(key, V.check) !== 'osintrix-sources') return false; }catch(e){ return false; }
  ST.key = key; ST.open.clear();
  for(const s of DB.sources || []){ try{ ST.open.set(s.id, JSON.parse(await openWith(key, s.sealed))); }catch(e){ ST.open.set(s.id, null); } }
  stArm(); return true; }
/* burning: out of the workspace, out of every restore point this browser keeps; evidence keeps only the word "burned" */
function stForget(d, id){
  d.sources = (d.sources || []).filter(s => s.id !== id);
  for(const r of d.records || []) if(r.srcId === id){ delete r.srcId; r.source = 'Protected source (burned)'; }
  for(const c of d.cases || []) for(const cl of c.claims || []){ cl.for = (cl.for || []).filter(x => x !== 's:' + id); cl.against = (cl.against || []).filter(x => x !== 's:' + id); }
}
async function stPurgeSnaps(id){
  let done = 0, bad = 0; if(typeof IDB === 'undefined' || !STORE.idb) return {done, bad};
  for(const k of (await IDB.keys()).filter(k => typeof k === 'string' && /^osintrix-snap:\d+$/.test(k))){
    try{ const d = JSON.parse(await openStr(await IDB.get(k)));
      if(!(d.sources || []).some(s => s.id === id) && !(d.records || []).some(r => r.srcId === id)) continue;
      stForget(d, id); await IDB.set(k, await sealStr(JSON.stringify(d))); done++; }catch(e){ bad++; } }
  return {done, bad}; }
async function stBurn(id){
  stForget(DB, id); ST.open.delete(id); ST.shown.delete(id);
  mutate('burned a protected source'); renderAll();
  const P = await stPurgeSnaps(id);
  toast(P.bad ? `Source burned. ${P.bad} restore point${P.bad > 1 ? 's' : ''} could not be opened to remove it — delete ${P.bad > 1 ? 'them' : 'it'} in Settings → Storage.` : 'Source burned' + (P.done ? ` and removed from ${P.done} restore point${P.done > 1 ? 's' : ''}` : ''));
}

/* ---------- the source of a record, for counting independent sources ---------- */
function stSrcKeyOf(item){
  if(item.startsWith('s:')) return 'protected source: ' + item.slice(2);
  const r = recById(item.slice(2)); if(!r) return '';
  if(r.srcId) return 'protected source: ' + r.srcId;
  return typeof srcKey === 'function' ? srcKey(r) : String(r.source || '').trim().toLowerCase();
}
const stImages = r => (r.att || []).filter(a => /^image\//.test(a.type || '') || /\.(jpe?g|png|webp|gif|heic|tiff?)$/i.test(a.name || ''));

/* ---------- right of reply: where each request stands ---------- */
function stReplyState(x){
  if(x.st === 'answered') return {k:'answered', l:'Answered', tone:'green', done:true};
  if(x.st === 'declined') return {k:'declined', l:'Declined to comment', tone:'', done:true};
  if(x.due && x.due < Date.now() - 12 * 3600e3) return {k:'overdue', l:'No reply by the deadline', tone:'amber', done:true};
  return {k:'waiting', l:x.due ? 'Waiting until ' + stDay(x.due) : 'Waiting', tone:'', done:false};
}
const stWho = x => { const e = x.who && entryById(x.who); return e ? primary(e) : x.name || 'Someone'; };

/* ---------- archived copies ---------- */
const stArch = () => DB.archive && typeof DB.archive === 'object' ? DB.archive : (DB.archive = {});
function stCaseUrls(c, D){
  const m = new Map(), add = (u, rid) => { u = String(u || '').trim(); if(!/^https?:\/\//i.test(u)) return; if(!m.has(u)) m.set(u, new Set()); if(rid) m.get(u).add(rid); };
  for(const r of D.recs) for(const e of r.ents || []) if(e.k === 'url') add(e.v, r.id);
  for(const e of D.entries) if(e.type === 'url' || e.type === 'link') add(e.fields.url);
  return [...m.entries()].map(([url, recs]) => ({url, recs:[...recs]}));
}

/* ---------- the check before publishing ---------- */
function stClaimCheck(c, cl, D){
  const out = [], push = (lvl, t) => out.push({lvl, t});
  if(cl.st === 'false') return [{lvl:'info', t:'Marked false: keep it out of the story, or say it is false'}];
  if(cl.st !== 'confirmed') push('bad', cl.st === 'disputed' ? 'Disputed: not confirmed' : 'Not confirmed yet');
  const keys = new Set(), unsourced = [];
  for(const it of cl.for || []){ const k = stSrcKeyOf(it); if(k) keys.add(k); else if(it.startsWith('r:')) unsourced.push(it); }
  if(keys.size < 2) push('bad', keys.size ? 'Only one independent source' : 'No source for it yet');
  if(unsourced.length) push('warn', unsourced.length + ' piece' + (unsourced.length > 1 ? 's' : '') + ' of evidence with no source written down');
  if((cl.against || []).length && !String(cl.note || '').trim()) push('warn', 'Evidence against it, with no note on why the claim stands');
  for(const it of cl.for || []){ if(!it.startsWith('r:')) continue; const r = recById(it.slice(2)); if(!r) continue;
    for(const a of stImages(r)) if(!a.verified) push('bad', 'Picture not verified: ' + (a.name || 'image') + ' in “' + cap(r.title, 50) + '”'); }
  for(const who of cl.about || []){ const e = entryById(who); if(!e) continue; const R = stOf(c).replies.filter(x => x.who === who && (!x.claims || !x.claims.length || x.claims.includes(cl.id)));
    if(!R.length) push('bad', 'No right of reply for ' + primary(e));
    else if(!R.some(x => stReplyState(x).done)) push('warn', 'Waiting for ' + primary(e) + (R[0].due ? ' until ' + stDay(R[0].due) : '')); }
  const A = stArch(), cited = new Set();
  for(const it of cl.for || []){ if(!it.startsWith('r:')) continue; const r = recById(it.slice(2)); for(const e of (r && r.ents) || []) if(e.k === 'url') cited.add(e.v); }
  const noCopy = [...cited].filter(u => !(A[u] && A[u].snap)); if(noCopy.length) push('warn', noCopy.length + ' cited page' + (noCopy.length > 1 ? 's' : '') + ' with no archived copy');
  return out;
}
function stCheck(c, D){
  const rows = stOf(c).claims.map(cl => ({cl, issues:stClaimCheck(c, cl, D)}));
  const live = rows.filter(x => x.cl.st !== 'false');
  return {rows, ready:live.filter(x => !x.issues.some(i => i.lvl === 'bad')).length, total:live.length, bad:live.reduce((n, x) => n + x.issues.filter(i => i.lvl === 'bad').length, 0)};
}

/* ---------- the tab ---------- */
function caseStory(c, D){
  stOf(c); const v = stView(), S = stSources(c.id), K = stCheck(c, D), late = c.replies.filter(x => stReplyState(x).k === 'overdue' || stReplyState(x).k === 'waiting').length;
  const seg = `<div class="seg st-seg" role="group" aria-label="Show"><button data-act="stView" data-v="claims" aria-pressed="${v === 'claims'}">${ico('list-checks','sm')}Claims <span class="segn">${c.claims.length}</span></button><button data-act="stView" data-v="sources" aria-pressed="${v === 'sources'}">${ico('lock','sm')}Protected sources <span class="segn">${S.length}</span></button><button data-act="stView" data-v="reply" aria-pressed="${v === 'reply'}">${ico('message-square','sm')}Right of reply <span class="segn">${late || c.replies.length}</span></button><button data-act="stView" data-v="archive" aria-pressed="${v === 'archive'}">${ico('archive','sm')}Archived pages</button></div>`;
  const body = v === 'sources' ? stSourcesHTML(c, S) : v === 'reply' ? stReplyHTML(c) : v === 'archive' ? stArchiveHTML(c, D) : stClaimsHTML(c, D, K);
  return `<div class="scroll"><div class="page wide st">${seg}${body}</div></div>`;
}

/* claims */
function stItemChip(c, it, side, cl){
  const rm = `<button class="iconbtn sm" data-act="stEvDel" data-id="${esc(cl.id)}" data-v="${esc(side + '|' + it)}" aria-label="Remove">${ico('x','sm')}</button>`;
  if(it.startsWith('s:')){ const s = stSource(it.slice(2)); return `<span class="st-ev">${ico('lock','sm')}<span>${esc(s ? s.alias : 'Burned source')}</span><span class="t3">protected source</span>${rm}</span>`; }
  const r = recById(it.slice(2)); if(!r) return '';
  const k = stSrcKeyOf(it), imgs = stImages(r);
  return `<span class="st-ev"><button class="lnk" data-act="selRec" data-id="${r.id}">${esc(cap(r.title, 70))}</button><span class="t3">${esc(k ? k.replace(/^protected source: .*/, 'protected source') : 'no source written down')}</span>${imgs.length ? `<span class="t3">${ico('image','sm')}${imgs.filter(a => a.verified).length}/${imgs.length} verified</span>` : ''}${rm}</span>`;
}
function stClaimsHTML(c, D, K){
  const st = k => ST_STATUS.find(x => x[0] === k) || ST_STATUS[0];
  const issues = K.rows.flatMap(x => x.issues.filter(i => i.lvl !== 'info').map(i => ({...i, cl:x.cl})));
  const check = c.claims.length ? `<section class="card st-check"><header><h3>${ico('badge-check','sm')}Before you publish</h3><span class="t2">${K.ready} of ${K.total} claim${K.total === 1 ? '' : 's'} ready</span></header>
    ${issues.length ? `<ul class="st-issues">${issues.slice(0, 60).map(i => `<li class="${i.lvl}"><button class="lnk" data-act="stClaimGo" data-id="${esc(i.cl.id)}">${esc(cap(i.cl.t, 60))}</button><span>${esc(i.t)}</span></li>`).join('')}</ul>`
      : `<p class="st-ok">${ico('check','sm')}Every claim is confirmed by at least two independent sources, its pictures are verified, and everyone it is about has had the right of reply.</p>`}</section>` : '';
  const pics = cl => { const L = []; for(const it of cl.for || []){ if(!it.startsWith('r:')) continue; const r = recById(it.slice(2)); if(r) for(const a of stImages(r)) L.push({r, a}); }
    return L.length ? `<div class="st-row"><span class="caps">Pictures</span><div class="st-evs">${L.map(({r, a}) => `<span class="st-ev">${ico('image','sm')}<span>${esc(a.name || 'image')}</span>${a.verified ? `<span class="chip sq green">${ico('check','sm')}${esc(a.verified.how)}</span>` : `<button class="btn sm" data-act="stVerify" data-id="${esc(r.id)}" data-v="${esc(a.id)}">Mark verified…</button>`}</span>`).join('')}</div></div>` : ''; };
  const about = cl => `<div class="st-row"><span class="caps">About</span><div class="st-evs">${(cl.about || []).map(id => { const e = entryById(id); return e ? `<span class="st-ev">${tbadge(e.type, 'sm')}<span>${esc(primary(e))}</span><button class="iconbtn sm" data-act="stAboutDel" data-id="${esc(cl.id)}" data-v="${esc(id)}" aria-label="Remove">${ico('x','sm')}</button></span>` : ''; }).join('')}<button class="btn sm ghost" data-act="stAbout" data-id="${esc(cl.id)}">${ico('plus','sm')}Person or organisation</button></div></div>`;
  const card = (cl, issues) => { const s = st(cl.st); return `<section class="card st-claim" id="stc-${esc(cl.id)}"><header><p class="st-t">${esc(cl.t)}</p><button class="iconbtn sm" data-act="stClaimEdit" data-id="${esc(cl.id)}" aria-label="Edit claim">${ico('pencil','sm')}</button></header>
    <div class="seg sm" role="group" aria-label="Status of this claim">${ST_STATUS.map(([k, l, i]) => `<button data-act="stStatus" data-id="${esc(cl.id)}" data-v="${k}" aria-pressed="${cl.st === k}">${ico(i,'sm')}${l}</button>`).join('')}</div>
    <div class="st-row"><span class="caps">For</span><div class="st-evs">${(cl.for || []).map(it => stItemChip(c, it, 'for', cl)).join('')}<button class="btn sm ghost" data-act="stEvAdd" data-id="${esc(cl.id)}" data-v="for">${ico('plus','sm')}Evidence</button></div></div>
    <div class="st-row"><span class="caps">Against</span><div class="st-evs">${(cl.against || []).map(it => stItemChip(c, it, 'against', cl)).join('')}<button class="btn sm ghost" data-act="stEvAdd" data-id="${esc(cl.id)}" data-v="against">${ico('plus','sm')}Evidence</button></div></div>
    ${pics(cl)}${about(cl)}${cl.note ? `<p class="t2 st-note">${esc(cl.note)}</p>` : ''}
    ${issues.length ? `<ul class="st-issues small">${issues.map(i => `<li class="${i.lvl}"><span>${esc(i.t)}</span></li>`).join('')}</ul>` : cl.st !== 'false' ? `<p class="st-ok small">${ico('check','sm')}Ready</p>` : ''}</section>`; };
  return `<p class="t2 st-p">Each claim the story makes, with the evidence for and against it. A claim is ready when it is confirmed by at least two independent sources, its pictures are verified and everyone it is about has had the chance to reply.</p>
    ${check}<form class="card qadd" data-form="stClaim"><label class="sr" for="stNew">New claim</label><input id="stNew" class="inp" placeholder="A claim the story makes, e.g. “The company paid the official €40,000 in 2024”" autocomplete="off"><button class="btn primary" type="submit">${ico('plus','sm')}Add</button></form>
    ${c.claims.length ? K.rows.map(x => card(x.cl, x.issues)).join('') : empty('list-checks', 'No claims yet', 'Write down each thing the story will say as fact. Then attach the evidence and sources for it, and see what is missing before you publish.')}`;
}

/* protected sources */
function stSourcesHTML(c, S){
  const V = stVault();
  if(!V) return `<section class="card st-intro"><h3>${ico('lock','sm')}Protect the people who talk to you</h3>
    <p>A protected source is kept under a pseudonym, such as “Harbour insider”. Their real name, how to reach them and how they know what they know are encrypted with a passphrase you choose. That passphrase is never stored: lose it and the details cannot be recovered, by you or anyone.</p>
    <p class="t2">Evidence and claims carry only the pseudonym. Exports and case files never contain the details. They are shown only when you unlock and ask, and they lock again after ten idle minutes or when you leave the tab.</p>
    <form data-form="stPass" class="st-form"><div class="frow"><div class="field"><label for="stP1">Sources passphrase</label><input id="stP1" type="password" autocomplete="new-password"></div><div class="field"><label for="stP2">Again</label><input id="stP2" type="password" autocomplete="new-password"></div></div>
      <p class="t3 small">At least 10 characters. Use a different one from any other passphrase.</p><button class="btn primary" type="submit">${ico('lock','sm')}Set the passphrase</button></form></section>`;
  const open = !!ST.key;
  const head = open ? `<div class="st-bar"><span class="chip sq green">${ico('lock-open','sm')}Unlocked</span><span class="t3">Locks after ten idle minutes or when you leave the tab</span><span style="flex:1"></span><button class="btn sm" data-act="stLock">${ico('lock','sm')}Lock now</button><button class="btn sm primary" data-act="stSrcNew">${ico('plus','sm')}Add a source</button></div>`
    : `<form class="card st-bar" data-form="stUnlock"><span class="chip sq">${ico('lock','sm')}Locked</span><label class="sr" for="stUp">Sources passphrase</label><input id="stUp" class="inp" type="password" autocomplete="current-password" placeholder="Sources passphrase"><button class="btn primary" type="submit">Unlock</button></form>`;
  const card = s => { const d = ST.open.get(s.id), shown = open && ST.shown.has(s.id) && d, n = DB.records.filter(r => r.srcId === s.id).length, cls = stOf(theCase(s.caseId)).claims.filter(cl => (cl.for || []).includes('s:' + s.id)).length;
    return `<section class="card st-src"><header><span class="st-av">${ico('user','sm')}</span><div><b>${esc(s.alias)}</b><div class="t3 small">${n} piece${n === 1 ? '' : 's'} of evidence · backs ${cls} claim${cls === 1 ? '' : 's'}${s.rel ? ' · reliability ' + esc(s.rel) : ''}</div></div><span style="flex:1"></span>
      ${open ? `<button class="btn sm" data-act="stShow" data-id="${esc(s.id)}">${ico(shown ? 'eye-off' : 'eye','sm')}${shown ? 'Hide details' : 'Show details'}</button><button class="iconbtn sm" data-act="stSrcEdit" data-id="${esc(s.id)}" aria-label="Edit ${esc(s.alias)}">${ico('pencil','sm')}</button>` : ''}
      <button class="btn sm danger" data-act="stBurnAsk" data-id="${esc(s.id)}">${ico('flame','sm')}Burn</button></header>
      ${shown ? `<dl class="kv st-real">${[['Real name', d.name], ['How to reach them', d.contact], ['How they know', d.access], ['Risks and agreements', d.risk]].filter(x => x[1]).map(([k, x]) => `<dt>${k}</dt><dd>${esc(x)}</dd>`).join('') || '<dt>Details</dt><dd class="t3">None written down</dd>'}</dl>` : open && !d ? '<p class="t3 small">These details could not be opened with this passphrase.</p>' : ''}</section>`; };
  return `<p class="t2 st-p">People who gave you information, under a pseudonym. Attribute evidence to them from its details panel; claims count each protected source as one independent source.</p>${head}
    ${S.length ? S.map(card).join('') : empty('lock', 'No protected sources in this case', open ? 'Add one with the button above.' : 'Unlock to add one.')}`;
}
function stSrcDlg(id){
  if(!ST.key) return toast('Unlock the protected sources first');
  const s = id ? stSource(id) : null, d = (s && ST.open.get(s.id)) || {};
  const f = (k, l, v, ta, hint) => `<div class="field"><label for="ss-${k}">${l}</label>${ta ? `<textarea id="ss-${k}" rows="3">${esc(v || '')}</textarea>` : `<input id="ss-${k}" value="${esc(v || '')}" autocomplete="off">`}${hint ? `<span class="hint">${hint}</span>` : ''}</div>`;
  openDlg(dhead(s ? 'Edit protected source' : 'New protected source') + `<form data-form="stSrc" data-id="${esc(id || '')}"><div class="in">
    ${f('alias', 'Pseudonym <span class="t3">shown everywhere</span>', s && s.alias, false, 'Nothing that points to them: not their job title, town or initials.')}
    <div class="field"><label for="ss-rel">Reliability</label><select id="ss-rel"><option value="">Not rated</option>${ST_REL.map(([k, l]) => `<option value="${k}"${s && s.rel === k ? ' selected' : ''}>${k} — ${l}</option>`).join('')}</select></div>
    <p class="caps" style="margin:14px 0 6px">${ico('lock','sm')} Encrypted, shown only when unlocked</p>
    ${f('name', 'Real name', d.name)}${f('contact', 'How to reach them', d.contact, false, 'The safe channel you agreed, e.g. Signal on a second phone.')}${f('access', 'How they know', d.access, true)}${f('risk', 'Risks and agreements', d.risk, true, 'What they risk, and what you promised: anonymity, what may be quoted, embargoes.')}
  </div><footer><button class="btn" type="button" data-act="dclose">Cancel</button><button class="btn primary" type="submit">${s ? 'Save' : 'Add source'}</button></footer></form>`);
}

/* right of reply */
function stReplyHTML(c){
  const R = c.replies.slice().sort((a, b) => { const o = {overdue:0, waiting:1, answered:2, declined:2}; return o[stReplyState(a).k] - o[stReplyState(b).k] || (a.due || 9e15) - (b.due || 9e15); });
  const row = x => { const s = stReplyState(x), cl = (x.claims || []).map(id => c.claims.find(y => y.id === id)).filter(Boolean);
    return `<section class="card st-reply"><header><div><b>${esc(stWho(x))}</b><div class="t3 small">Asked ${esc(stDay(x.at))}${x.via ? ' · ' + esc(x.via) : ''}${x.due ? ' · deadline ' + esc(stDay(x.due)) : ''}</div></div><span style="flex:1"></span><span class="chip sq ${s.tone}">${esc(s.l)}</span><button class="iconbtn sm" data-act="stReplyEdit" data-id="${esc(x.id)}" aria-label="Edit">${ico('pencil','sm')}</button></header>
      ${cl.length ? `<ul class="st-cl">${cl.map(y => `<li>${esc(y.t)}</li>`).join('')}</ul>` : ''}${x.resp ? `<blockquote class="st-resp">${esc(x.resp)}${x.respAt ? `<footer class="t3 small">${esc(stDay(x.respAt))}</footer>` : ''}</blockquote>` : ''}</section>`; };
  return `<p class="t2 st-p">Everyone a story makes claims about should be told what it will say and given a fair time to answer. Log each request here; a claim about someone counts as ready once they have answered, declined, or let the deadline pass.</p>
    <div class="st-bar"><span style="flex:1"></span><button class="btn primary sm" data-act="stReplyNew">${ico('plus','sm')}Log a request for comment</button></div>
    ${R.length ? R.map(row).join('') : empty('message-square', 'No requests for comment yet', 'When you put the story’s claims to the people or organisations they are about, log who, when, how and by when.')}`;
}
function stReplyDlg(id){
  const c = stOf(theCase()), x = id ? c.replies.find(y => y.id === id) : null, D = derive(), people = D.entries.filter(e => e.type === 'person' || e.type === 'organization' || e.type === 'alias');
  const now = stISO(Date.now()), due = stISO(Date.now() + 3 * 864e5);
  openDlg(dhead(x ? 'Request for comment' : 'Log a request for comment') + `<form data-form="stReply" data-id="${esc(id || '')}"><div class="in">
    <div class="frow"><div class="field"><label for="sr-who">Who</label><select id="sr-who"><option value="">Someone not in the vault</option>${people.map(e => `<option value="${e.id}"${x && x.who === e.id ? ' selected' : ''}>${esc(primary(e))} (${esc(TYPES[e.type].label)})</option>`).join('')}</select></div>
      <div class="field"><label for="sr-name">Name, if not in the vault</label><input id="sr-name" value="${esc(x && !x.who ? x.name || '' : '')}" autocomplete="off"></div></div>
    <div class="frow"><div class="field"><label for="sr-via">How</label><select id="sr-via">${ST_VIA.map(v => `<option${x && x.via === v ? ' selected' : ''}>${v}</option>`).join('')}</select></div>
      <div class="field"><label for="sr-at">Asked on</label><input id="sr-at" type="date" value="${x ? stISO(x.at) : now}"></div><div class="field"><label for="sr-due">Deadline</label><input id="sr-due" type="date" value="${x ? stISO(x.due) : due}"></div></div>
    ${c.claims.length ? `<fieldset class="field"><legend>Claims put to them</legend>${c.claims.map(cl => `<label class="chk"><input type="checkbox" data-cl="${esc(cl.id)}"${!x || (x.claims || []).includes(cl.id) ? ' checked' : ''}>${esc(cap(cl.t, 90))}</label>`).join('')}</fieldset>` : ''}
    <div class="frow"><div class="field"><label for="sr-st">Status</label><select id="sr-st">${[['waiting', 'Waiting'], ['answered', 'Answered'], ['declined', 'Declined to comment']].map(([k, l]) => `<option value="${k}"${(x ? x.st || 'waiting' : 'waiting') === k ? ' selected' : ''}>${l}</option>`).join('')}</select></div>
      <div class="field"><label for="sr-respAt">Answered on</label><input id="sr-respAt" type="date" value="${x ? stISO(x.respAt) : ''}"></div></div>
    <div class="field"><label for="sr-resp">What they said</label><textarea id="sr-resp" rows="4">${esc(x ? x.resp || '' : '')}</textarea></div>
  </div><footer>${x ? `<button class="btn danger" type="button" data-act="stReplyDel" data-id="${esc(x.id)}" style="margin-right:auto">Delete</button>` : ''}<button class="btn" type="button" data-act="dclose">Cancel</button><button class="btn primary" type="submit">Save</button></footer></form>`);
}

/* archived pages */
function stArchiveHTML(c, D){
  const U = stCaseUrls(c, D), A = stArch();
  const row = ({url, recs}) => { const a = A[url] || {}, wait = a.req && !a.snap && Date.now() - a.req < 864e5;
    return `<li class="st-arch"><div class="st-au"><span class="mono">${esc(cap(url, 110))}</span><span class="t3 small">${recs.length ? 'cited in ' + recs.length + ' piece' + (recs.length > 1 ? 's' : '') + ' of evidence' : 'in the vault'}</span></div>
      <div class="st-as">${a.snap ? `<a class="chip sq green" href="${esc(a.snap)}" target="_blank" rel="noopener noreferrer">${ico('archive','sm')}Archived ${esc(stDay(a.at))}</a>` : wait && a.checked > a.req ? `<span class="chip sq amber" title="Saving can take a few minutes; check again">Not found yet</span>` : wait ? `<span class="chip sq amber">Saving requested</span>` : a.checked ? '<span class="chip sq">No copy found</span>' : ''}
        <button class="btn sm" data-act="stArchSave" data-v="${esc(url)}">${ico('archive','sm')}${a.snap ? 'Archive again' : 'Archive now'}</button><button class="btn sm ghost" data-act="stArchCheck" data-v="${esc(url)}">Find the copy</button></div></li>`; };
  const pending = U.filter(u => !(A[u.url] && A[u.url].snap));
  return `<p class="t2 st-p">The pages this case cites. A page can be changed or deleted after you publish; an archived copy on the Wayback Machine shows what it said, and when.</p>
    <div class="card st-warn">${ico('info','sm')}<span>Archiving sends the address to the Internet Archive and makes a public copy anyone can find. Someone watching the page may learn that it was archived. Archive a page about a sensitive subject only when you are ready for that.</span></div>
    ${U.length ? `<div class="st-bar"><span class="t3">${U.length - pending.length} of ${U.length} archived</span><span style="flex:1"></span>${pending.length ? `<button class="btn sm" data-act="stArchCheckAll">Find copies for all ${pending.length}</button>` : ''}</div><ul class="st-al card">${U.map(row).join('')}</ul>`
      : empty('archive', 'No web pages cited in this case', 'Web addresses in the evidence and URL entries in the vault show up here.')}`;
}
/* Save Page Now runs in its own tab (the archive does not let a page save another page); the copy is then found and kept */
async function stArchFind(url){
  const A = stArch(), x = A[url] || (A[url] = {});
  try{ const r = await lkFetch('https://archive.org/wayback/available?url=' + encodeURIComponent(url), {timeout:15000}); const j = JSON.parse(r.text), s = j.archived_snapshots && j.archived_snapshots.closest;
    x.checked = Date.now();
    if(s && s.available && /^https?:\/\/web\.archive\.org\//.test(s.url || '')){ const t = String(s.timestamp || ''); x.snap = s.url.replace(/^http:/, 'https:'); x.at = /^\d{14}$/.test(t) ? Date.UTC(+t.slice(0, 4), +t.slice(4, 6) - 1, +t.slice(6, 8), +t.slice(8, 10), +t.slice(10, 12), +t.slice(12, 14)) : Date.now(); return true; }
    return false; }
  catch(e){ x.checked = Date.now(); throw e; }
}
async function stArchFindMany(urls){ let found = 0, err = null; for(const u of urls){ try{ if(await stArchFind(u)) found++; }catch(e){ err = e; } } mutate('checked archived copies'); bgRender(); return {found, err}; }
/* back from the archive's tab: look for copies just requested */
window.addEventListener('focus', () => { const A = DB && DB.archive; if(!A || !(UI.route && UI.route.tab === 'story')) return;
  const L = Object.entries(A).filter(([, x]) => x.req && !x.snap && Date.now() - x.req < 15 * 60000).map(([u]) => u); if(L.length) setTimeout(() => stArchFindMany(L).catch(() => {}), 1500); });

/* ---------- pickers ---------- */
function stEvDlg(clId, side){
  const c = stOf(theCase()), cl = c.claims.find(x => x.id === clId); if(!cl) return; const D = derive(), have = new Set([...(cl.for || []), ...(cl.against || [])]);
  const recs = D.recs.filter(r => r.type !== 'lead' && !have.has('r:' + r.id)), S = stSources(c.id).filter(s => !have.has('s:' + s.id));
  UI.stPick = {cl:clId, side, q:''};
  openDlg(dhead(side === 'for' ? 'Evidence for the claim' : 'Evidence against the claim') + `<div class="in"><p class="t2" style="margin:0 0 10px">${esc(cap(cl.t, 140))}</p>
    <div class="search-in" style="margin-bottom:10px">${ico('search')}<label class="sr" for="stPq">Search</label><input id="stPq" class="inp" placeholder="Search the evidence…" autocomplete="off"></div>
    ${S.length ? `<div class="caps" style="margin:6px 0">Protected sources</div><div class="st-pick">${S.map(s => `<label class="chk"><input type="checkbox" data-pk="s:${esc(s.id)}">${ico('lock','sm')}${esc(s.alias)}</label>`).join('')}</div>` : ''}
    <div class="caps" style="margin:10px 0 6px">Evidence in this case</div><div class="st-pick" id="stPl">${recs.slice(0, 400).map(r => `<label class="chk" data-q="${esc((r.title + ' ' + (r.source || '')).toLowerCase())}"><input type="checkbox" data-pk="r:${esc(r.id)}"><span>${esc(cap(r.title, 90))}</span><span class="t3 small">${esc(r.source || 'no source written down')}</span></label>`).join('') || '<p class="t3">No other evidence in this case.</p>'}</div></div>
    <footer><button class="btn" data-act="dclose">Cancel</button><button class="btn primary" data-act="stEvGo">Add</button></footer>`, true, () => {
    $('stPq').oninput = e => { const q = e.target.value.toLowerCase(); document.querySelectorAll('#stPl label[data-q]').forEach(l => { l.hidden = !!q && !l.dataset.q.includes(q); }); }; });
}
function stAboutDlg(clId){
  const c = stOf(theCase()), cl = c.claims.find(x => x.id === clId); if(!cl) return; const D = derive(), P = D.entries.filter(e => (e.type === 'person' || e.type === 'organization' || e.type === 'alias') && !(cl.about || []).includes(e.id));
  openDlg(dhead('Who the claim is about') + `<div class="in"><p class="t2" style="margin:0 0 10px">People and organisations from this case’s vault. Each one should get the right of reply before you publish.</p>
    <div class="st-pick">${P.map(e => `<label class="chk"><input type="checkbox" data-ab="${esc(e.id)}">${tbadge(e.type, 'sm')}${esc(primary(e))}</label>`).join('') || '<p class="t3">Add the people and organisations to the vault first.</p>'}</div></div>
    <footer><button class="btn" data-act="dclose">Cancel</button><button class="btn primary" data-act="stAboutGo" data-id="${esc(clId)}">Add</button></footer>`);
}
function stVerifyDlg(rid, aid){
  const r = recById(rid), a = r && (r.att || []).find(x => x.id === aid); if(!a) return;
  openDlg(dhead('Picture verified') + `<form data-form="stVerify" data-id="${esc(rid)}" data-v="${esc(aid)}"><div class="in"><p class="t2" style="margin:0 0 12px">${esc(a.name || 'image')} in “${esc(cap(r.title, 80))}”</p>
    <div class="field"><label for="sv-how">How you verified it</label><select id="sv-how">${ST_VERIFY.map(v => `<option>${v}</option>`).join('')}</select></div>
    <div class="field"><label for="sv-note">What you found</label><textarea id="sv-note" rows="3" placeholder="e.g. Earliest copy posted 3 March by the photographer; shadows match 10:40 local time"></textarea></div></div>
    <footer><button class="btn" type="button" data-act="dclose">Cancel</button><button class="btn primary" type="submit">Mark verified</button></footer></form>`);
}
function stClaimDlg(id){
  const c = stOf(theCase()), cl = c.claims.find(x => x.id === id); if(!cl) return;
  openDlg(dhead('Claim') + `<form data-form="stClaimEd" data-id="${esc(id)}"><div class="in"><div class="field"><label for="sc-t">Claim</label><textarea id="sc-t" rows="3">${esc(cl.t)}</textarea></div>
    <div class="field"><label for="sc-n">Note <span class="t3">why it stands, what is left to check</span></label><textarea id="sc-n" rows="3">${esc(cl.note || '')}</textarea></div></div>
    <footer><button class="btn danger" type="button" data-act="stClaimDel" data-id="${esc(id)}" style="margin-right:auto">Delete</button><button class="btn" type="button" data-act="dclose">Cancel</button><button class="btn primary" type="submit">Save</button></footer></form>`);
}

/* ---------- in a record's panel: who gave it ---------- */
function stRecSection(r){
  if(!r || r.type === 'lead') return ''; const S = stSources(r.caseId); if(!S.length && !r.srcId) return '';
  return `<div class="isec"><h4>${ico('lock','sm')} Protected source</h4><label class="sr" for="stRecSrc">Protected source</label><select id="stRecSrc" data-st="recsrc" data-id="${esc(r.id)}"><option value="">None</option>${S.map(s => `<option value="${esc(s.id)}"${r.srcId === s.id ? ' selected' : ''}>${esc(s.alias)}</option>`).join('')}</select>
    <p class="t3 small" style="margin-top:6px">Only the pseudonym is kept with this evidence.</p></div>`;
}
document.addEventListener('change', ev => { const el = ev.target; if(!el || !el.dataset || el.dataset.st !== 'recsrc') return; const r = recById(el.dataset.id); if(!r) return;
  const s = el.value ? stSource(el.value) : null; if(s){ r.srcId = s.id; r.source = 'Protected source · ' + s.alias; } else if(r.srcId){ delete r.srcId; r.source = ''; }
  mutate(s ? 'attributed evidence to a protected source' : 'removed a protected source from evidence'); renderAll(); });

/* ---------- forms ---------- */
async function stSubmit(f){
  const k = f.dataset.form, c = stOf(theCase());
  if(k === 'stClaim'){ const t = $('stNew').value.trim().replace(/\s+/g, ' '); if(!t) return fieldErr('stNew', 'Write the claim.'); if(!checkLen('stNew', t, 1000, 'Claim')) return;
    c.claims.push({id:uid('cl'), t, st:'unverified', for:[], against:[], about:[], note:'', at:Date.now()}); mutate('added a claim'); return renderMain(); }
  if(k === 'stClaimEd'){ const cl = c.claims.find(x => x.id === f.dataset.id); if(!cl) return closeDlg(); const t = $('sc-t').value.trim().replace(/\s+/g, ' '); if(!t) return fieldErr('sc-t', 'Write the claim.');
    if(!checkLen('sc-t', t, 1000, 'Claim') || !checkLen('sc-n', $('sc-n').value.trim(), LIMITS.desc, 'Note')) return; cl.t = t; cl.note = $('sc-n').value.trim(); closeDlg(); mutate('edited a claim'); return renderMain(); }
  if(k === 'stPass'){ const a = $('stP1').value, b = $('stP2').value; if(a.length < 10) return fieldErr('stP1', 'At least 10 characters.'); if(a !== b) return fieldErr('stP2', 'The two do not match.');
    await stSetPass(a); mutate('set a passphrase for protected sources'); renderMain(); return toast('Protected sources are ready. Write the passphrase down somewhere safe: it cannot be recovered.'); }
  if(k === 'stUnlock'){ const p = $('stUp').value; if(!p) return fieldErr('stUp', 'Type the passphrase.'); const ok = await stUnlock(p); if(!ok) return fieldErr('stUp', 'That is not the passphrase.'); return renderMain(); }
  if(k === 'stSrc'){ if(!ST.key){ closeDlg(); return toast('Locked — unlock again'); } const alias = $('ss-alias').value.trim().replace(/\s+/g, ' '); if(!alias) return fieldErr('ss-alias', 'Give the source a pseudonym.');
    if(!checkLen('ss-alias', alias, 80, 'Pseudonym')) return; const id = f.dataset.id;
    if(stSources(c.id).some(s => s.id !== id && s.alias.toLowerCase() === alias.toLowerCase())) return fieldErr('ss-alias', 'Another source in this case has that pseudonym.');
    const d = {name:$('ss-name').value.trim(), contact:$('ss-contact').value.trim(), access:$('ss-access').value.trim(), risk:$('ss-risk').value.trim()};
    for(const [i, v] of Object.entries(d)) if(!checkLen('ss-' + i, v, LIMITS.desc, 'This')) return;
    DB.sources = Array.isArray(DB.sources) ? DB.sources : []; let s = id ? stSource(id) : null;
    if(!s){ s = {id:uid('src'), caseId:c.id, alias, rel:'', created:Date.now()}; DB.sources.push(s); }
    const old = s.alias; s.alias = alias; s.rel = $('ss-rel').value; s.sealed = await stSeal(d); ST.open.set(s.id, d);
    if(old !== alias) for(const r of DB.records) if(r.srcId === s.id) r.source = 'Protected source · ' + alias;
    closeDlg(); stArm(); mutate(id ? 'edited a protected source' : 'added a protected source'); return renderAll(); }
  if(k === 'stReply'){ const who = $('sr-who').value, name = $('sr-name').value.trim(); if(!who && !name) return fieldErr('sr-name', 'Pick someone from the vault or write a name.');
    const at = stDate($('sr-at').value), due = stDate($('sr-due').value); if(!at) return fieldErr('sr-at', 'When did you ask?'); if(due && due < at) return fieldErr('sr-due', 'The deadline is before the request.');
    const resp = $('sr-resp').value.trim(); if(!checkLen('sr-resp', resp, LIMITS.body, 'The reply')) return;
    const id = f.dataset.id; let x = id ? c.replies.find(y => y.id === id) : null; if(!x){ x = {id:uid('rr')}; c.replies.push(x); }
    Object.assign(x, {who, name:who ? '' : name, via:$('sr-via').value, at, due, claims:[...f.querySelectorAll('input[data-cl]:checked')].map(i => i.dataset.cl), st:$('sr-st').value, resp, respAt:stDate($('sr-respAt').value) || (resp && !x.respAt ? Date.now() : x.respAt || null)});
    if(x.resp && x.st === 'waiting') x.st = 'answered';
    closeDlg(); mutate('logged a request for comment'); return renderMain(); }
  /* burning asks for the pseudonym typed out, so a slip of the mouse cannot do it */
  if(k === 'stBurn'){ const s = stSource(f.dataset.id); if(!s) return closeDlg(); if($('sb-a').value.trim().toLowerCase() !== s.alias.toLowerCase()) return fieldErr('sb-a', 'Type the pseudonym exactly.'); closeDlg(); return stBurn(s.id); }
  if(k === 'stVerify'){ const r = recById(f.dataset.id), a = r && (r.att || []).find(x => x.id === f.dataset.v); if(!a) return closeDlg();
    a.verified = {how:$('sv-how').value, note:$('sv-note').value.trim().slice(0, 2000), at:Date.now(), by:'You'}; closeDlg(); mutate('verified a picture'); return renderAll(); }
}

/* ---------- actions ---------- */
const STORY_ACTS = {
  stView:(id, v) => { UI.stView = v; renderMain(); },
  stClaimGo:id => { UI.stView = 'claims'; renderMain(); const el = document.getElementById('stc-' + id); if(el){ el.scrollIntoView({block:'center'}); el.classList.add('flash'); setTimeout(() => el.classList.remove('flash'), 1200); } },
  stStatus:(id, v) => { const cl = stOf(theCase()).claims.find(x => x.id === id); if(!cl || !ST_STATUS.some(s => s[0] === v)) return; cl.st = v; mutate('claim marked ' + v); renderMain(); },
  stClaimEdit:id => stClaimDlg(id),
  stClaimDel:id => { const c = stOf(theCase()), cl = c.claims.find(x => x.id === id); if(!cl) return; confirmDlg('Delete this claim?', cap(cl.t, 200), 'Delete', () => { const i = c.claims.indexOf(cl), was = c.replies.map(r => [r, (r.claims || []).slice()]);
    c.claims = c.claims.filter(x => x.id !== id); for(const r of c.replies) r.claims = (r.claims || []).filter(x => x !== id); mutate('deleted a claim'); renderMain();
    toast('Claim deleted', 'Undo', () => { c.claims.splice(i, 0, cl); for(const [r, k] of was) r.claims = k; mutate('put back a claim'); renderMain(); }); }); },
  stEvAdd:(id, v) => stEvDlg(id, v),
  stEvGo:() => { const P = UI.stPick, cl = P && stOf(theCase()).claims.find(x => x.id === P.cl); if(!cl) return closeDlg(); const add = [...document.querySelectorAll('#dlg input[data-pk]:checked')].map(i => i.dataset.pk);
    cl[P.side] = [...new Set([...(cl[P.side] || []), ...add])]; closeDlg(); if(add.length) mutate('added evidence to a claim'); renderMain(); },
  stEvDel:(id, v) => { const cl = stOf(theCase()).claims.find(x => x.id === id); if(!cl) return; const i = v.indexOf('|'), side = v.slice(0, i), it = v.slice(i + 1); cl[side] = (cl[side] || []).filter(x => x !== it); mutate('removed evidence from a claim'); renderMain(); },
  stAbout:id => stAboutDlg(id),
  stAboutGo:id => { const cl = stOf(theCase()).claims.find(x => x.id === id); if(!cl) return closeDlg(); const add = [...document.querySelectorAll('#dlg input[data-ab]:checked')].map(i => i.dataset.ab); cl.about = [...new Set([...(cl.about || []), ...add])]; closeDlg(); if(add.length) mutate('claim is about ' + add.length + ' more'); renderMain(); },
  stAboutDel:(id, v) => { const cl = stOf(theCase()).claims.find(x => x.id === id); if(!cl) return; cl.about = (cl.about || []).filter(x => x !== v); mutate('claim edited'); renderMain(); },
  stVerify:(id, v) => stVerifyDlg(id, v),
  stLock:() => { stLock(); renderMain(); },
  stSrcNew:() => stSrcDlg(null),
  stSrcEdit:id => stSrcDlg(id),
  stShow:id => { if(!ST.key) return; if(ST.shown.has(id)) ST.shown.delete(id); else ST.shown.add(id); stArm(); renderMain(); },
  stBurnAsk:id => { const s = stSource(id); if(!s) return;
    openDlg(dhead('Burn ' + esc(s.alias) + '?') + `<form data-form="stBurn" data-id="${esc(id)}"><div class="in"><p>Burning wipes this source: the encrypted details, and the source in every restore point in this browser. Evidence keeps only the words “Protected source (burned)”. It cannot be undone.</p>
      <p class="t2">Copies outside this browser are not reached: backups and case files you saved, and other devices.</p>
      <div class="field"><label for="sb-a">Type the pseudonym to confirm</label><input id="sb-a" autocomplete="off"></div></div>
      <footer><button class="btn" type="button" data-act="dclose">Cancel</button><button class="btn danger" type="submit">${ico('flame','sm')}Burn</button></footer></form>`); },
  stReplyNew:() => stReplyDlg(null),
  stReplyEdit:id => stReplyDlg(id),
  stReplyDel:id => { const c = stOf(theCase()), i = c.replies.findIndex(x => x.id === id), x = c.replies[i]; if(!x) return; c.replies.splice(i, 1); closeDlg(); mutate('deleted a request for comment'); renderMain();
    toast('Request for comment deleted', 'Undo', () => { c.replies.splice(i, 0, x); mutate('put back a request for comment'); renderMain(); }); },   /* the record that someone had the chance to reply: easy to get back */
  stArchSave:(id, url) => { const go = () => { const A = stArch(); (A[url] || (A[url] = {})).req = Date.now(); window.open('https://web.archive.org/save/' + url, '_blank', 'noopener,noreferrer'); mutate('asked the Wayback Machine to save a page'); renderMain(); toast('Saving in a new tab. Come back here when it is done; the copy is found and kept.'); };
    if(DB.prefs.archOk) return go();
    confirmDlg('Make a public copy of this page?', 'The address ' + cap(url, 120) + ' is sent to the Internet Archive, which saves the page where anyone can see it. Whoever runs the page may notice it was archived. You will not be asked again.', 'Archive it', () => { DB.prefs.archOk = 1; go(); }, true); },
  stArchCheck:async (id, url) => { try{ const ok = await stArchFind(url); mutate('checked an archived copy'); renderMain(); toast(ok ? 'Archived copy found' : 'No archived copy yet'); }catch(e){ renderMain(); toast('Could not reach the Wayback Machine: ' + e.message); } },
  stArchCheckAll:async () => { const D = derive(), A = stArch(), L = stCaseUrls(theCase(), D).map(u => u.url).filter(u => !(A[u] && A[u].snap)); const r = await stArchFindMany(L); toast(r.err && !r.found ? 'Could not reach the Wayback Machine: ' + r.err.message : `${r.found} of ${L.length} found`); },
};

/* ---------- loading saved data: the shapes this file reads ---------- */
function stClean(d){
  if(d.sources != null) d.sources = (Array.isArray(d.sources) ? d.sources : []).filter(s => s && typeof s === 'object' && typeof s.id === 'string' && typeof s.caseId === 'string' && typeof s.alias === 'string' && typeof s.sealed === 'string' && s.alias.trim())
    .map(s => ({id:s.id, caseId:s.caseId, alias:s.alias.slice(0, 80), rel:/^[A-F]$/.test(s.rel || '') ? s.rel : '', sealed:s.sealed, created:+s.created || Date.now()}));
  if(d.srcVault != null && !(d.srcVault && typeof d.srcVault === 'object' && typeof d.srcVault.salt === 'string' && typeof d.srcVault.check === 'string' && Number.isInteger(d.srcVault.iter))) delete d.srcVault;
  if(d.archive != null){ const o = {}; if(d.archive && typeof d.archive === 'object' && !Array.isArray(d.archive)) for(const [u, x] of Object.entries(d.archive)){ if(!/^https?:\/\//i.test(u) || !x || typeof x !== 'object') continue;
    o[u] = {req:+x.req || 0, checked:+x.checked || 0, at:+x.at || 0, snap:typeof x.snap === 'string' && /^https:\/\/web\.archive\.org\//.test(x.snap) ? x.snap : ''}; if(!o[u].snap) delete o[u].snap; } d.archive = o; }
  const ids = arr => (Array.isArray(arr) ? arr : []).filter(x => typeof x === 'string').slice(0, 500);
  for(const c of d.cases || []){
    if(c.claims != null) c.claims = (Array.isArray(c.claims) ? c.claims : []).filter(x => x && typeof x.id === 'string' && typeof x.t === 'string').map(x => ({id:x.id, t:x.t.slice(0, 1000), st:ST_STATUS.some(s => s[0] === x.st) ? x.st : 'unverified', for:ids(x.for), against:ids(x.against), about:ids(x.about), note:typeof x.note === 'string' ? x.note.slice(0, 2000) : '', at:+x.at || 0}));
    if(c.replies != null) c.replies = (Array.isArray(c.replies) ? c.replies : []).filter(x => x && typeof x.id === 'string').map(x => ({id:x.id, who:typeof x.who === 'string' ? x.who : '', name:typeof x.name === 'string' ? x.name.slice(0, 200) : '', via:typeof x.via === 'string' ? x.via.slice(0, 80) : '',
      at:+x.at || null, due:+x.due || null, claims:ids(x.claims), st:['waiting', 'answered', 'declined'].includes(x.st) ? x.st : 'waiting', resp:typeof x.resp === 'string' ? x.resp.slice(0, 20000) : '', respAt:+x.respAt || null})); }
  for(const r of d.records || []){ if(r.srcId != null && typeof r.srcId !== 'string') delete r.srcId;
    for(const a of r.att || []) if(a.verified != null && !(a.verified && typeof a.verified === 'object' && typeof a.verified.how === 'string')) delete a.verified; }
  return d;
}
