/* ==========================================================================
   The Blackbook — a hidden part of the Kit (contents: js/data/blackbook-sealed.js, encrypted).
   Opened by typing "blackbook" in search (Ctrl K) or at #/blackbook; once
   opened it stays in the side menu. Four parts:
   · Hunt — plays across the attack chain, with your coverage (to do / hunted / detecting, kept in this browser).
   · Sweeps — ordered sets of plays for one situation (new environment, ransomware warning, vendor breach).
   · Doctrine — the hunt workflow, telemetry, habits, the attacker's first checks mirrored for defenders, and
     plays across the attack chain: how an operator sees it, what it leaves,
     the logs you need, hunts in KQL / SPL / Sigma / EQL / osquery, tuning
     and what closes it. A Sigma hunt joins your Detections in one click and
     can run as a saved hunt over your evidence.
   · APT casebook — public campaigns, their tells, and the plays that catch them.
   · Underground — working cybercrime forums, markets and Telegram as an
     authorised investigator, and how cybercriminals were actually caught.
   · OSINT — infrastructure pivots, archives, verification, exact syntax.
   ========================================================================== */
const BB_TABS = [['hunt', 'Hunt', 'crosshair'], ['sweeps', 'Sweeps', 'route'], ['doctrine', 'Doctrine', 'lightbulb'], ['apt', 'APT casebook', 'shield-alert'], ['under', 'Underground', 'skull'], ['osint', 'OSINT', 'scan-search']];
const BB_SEV = {low:'Low', medium:'Medium', high:'High', critical:'Critical'};
const BB_GO = {lab:['Forensics kit', 'file-search'], tradecraft:['Tradecraft', 'eye-off'], entities:['Entities', 'fingerprint'], 'case:timeline':['Timeline', 'clock'], 'case:infra':['Infrastructure', 'network'], 'case:questions':['Analysis', 'scale']};
const bbOpen = () => UI.bbOpen || (UI.bbOpen = new Set());
const bbStack = () => { const L = DB.prefs.bbLangs; return Array.isArray(L) && L.length ? L : ['kql', 'spl', 'sigma', 'eql', 'osq', 'cli']; };
function bbUnlock(){ if(!DB.prefs.bb){ DB.prefs.bb = Date.now(); save(); if(typeof renderNav === 'function') renderNav(); return true; } return false; }
function bbGoBtn(where){ const g = BB_GO[where]; return g ? `<button class="tc-go" data-act="bbGo" data-v="${esc(where)}">${ico(g[1], 'sm')}${esc(g[0])}${ico('arrow-right', 'sm')}</button>` : ''; }
function bbTech(id){ const t = typeof ATTACK !== 'undefined' ? ATTACK.tech.find(x => x[0] === id) : null; return `<a class="bb-att" href="https://attack.mitre.org/techniques/${esc(id.replace('.', '/'))}/" target="_blank" rel="noopener noreferrer"${t ? ` title="${esc(t[1])}"` : ''}>${esc(id)}</a>`; }
function bbRuleOf(p){ return (DB.rules || []).find(r => r.bb === p.id); }

/* The contents ship encrypted (js/data/blackbook-sealed.js, made by tools/seal_blackbook.mjs from a pack that is never
   committed): the page asks for the passphrase and decrypts here, in the browser. "Remember on this device" keeps the derived
   key — not the passphrase — in this browser's storage as a key that cannot be read back out, only used. */
const bbB64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
async function bbDerive(pass, S){
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2', salt:bbB64(S.salt), iterations:S.iter, hash:'SHA-256'}, base, {name:'AES-GCM', length:256}, false, ['decrypt']);
}
async function bbOpenWith(key){
  const S = BLACKBOOK_SEALED, pt = await crypto.subtle.decrypt({name:'AES-GCM', iv:bbB64(S.iv)}, key, bbB64(S.ct));
  const txt = S.z === 'gzip' ? await new Response(new Blob([pt]).stream().pipeThrough(new DecompressionStream('gzip'))).text() : new TextDecoder().decode(pt);
  window.BLACKBOOK = JSON.parse(txt);
}
async function bbTry(){
  const i = $('bbPass'), err = $('bbErr'), btn = document.querySelector('[data-form=bbUnlock] button[type=submit]'); if(!i || !i.value) return;
  if(btn){ btn.disabled = true; btn.textContent = 'Opening…'; } if(err) err.textContent = '';
  try{ const key = await bbDerive(i.value, BLACKBOOK_SEALED); await bbOpenWith(key); i.value = '';
    if($('bbRemember') && $('bbRemember').checked) await IDB.set('bb:key', key);
    renderMain(); if(typeof renderNav === 'function') renderNav(); }
  catch(e){ if(btn){ btn.disabled = false; btn.textContent = 'Open'; } if(err) err.textContent = 'That passphrase does not open it.'; if(i){ i.select(); i.focus(); } }
}
function bbLockView(){
  if(!UI.bbAuto){ UI.bbAuto = 'trying'; IDB.get('bb:key').then(async k => { if(k){ try{ await bbOpenWith(k); UI.bbAuto = 'done'; return UI.route.area === 'blackbook' && renderMain(); }catch(e){ IDB.setMany([], ['bb:key']); } } UI.bbAuto = 'done'; if(UI.route.area === 'blackbook') renderMain(); }); }
  if(UI.bbAuto === 'trying') return `<div class="scroll"><div class="page"><p class="t3">Opening…</p></div></div>`;
  return `<div class="scroll"><div class="page bb-lock"><div class="bb-lockbox">${ico('gem')}<h1>Blackbook</h1><p class="t2">Locked. The contents are encrypted; enter the passphrase to open them in this browser.</p>
    <form data-form="bbUnlock" autocomplete="off"><label class="lbl" for="bbPass">Passphrase</label><input id="bbPass" class="inp" type="password" autocomplete="off" spellcheck="false" required>
      <label class="bb-rem"><input type="checkbox" id="bbRemember"> Remember on this device</label><button class="btn" type="submit">Open</button><p class="bb-err" id="bbErr" role="alert" aria-live="assertive"></p></form></div></div></div>`;
}
document.addEventListener('submit', ev => { if(ev.target && ev.target.dataset && ev.target.dataset.form === 'bbUnlock'){ ev.preventDefault(); ev.stopImmediatePropagation(); bbTry(); } }, true);

/* ---- Drawing (1.91): a compact header, one bar for the tabs and search, then each part.
   Hunt is a list grouped by stage of the attack with your coverage beside it; a play opens as a dossier in the order the work
   happens (understand, detect, hunt, triage, respond, harden, prove); Sweeps are ordered sets of plays for one situation. */
const BB_ST = {todo:'To do', hunted:'Hunted', live:'Detecting'};
const bbSt = id => { const S = DB.prefs.bbSt; return S && BB_ST[S[id]] ? S[id] : 'todo'; };
const bbShort = (B, k) => (B.langs[k] || k).split(' — ')[0];
const bbSevTag = s => `<span class="bbx-sev s-${s}">${BB_SEV[s]}</span>`;

function viewBlackbook(){
  if(typeof BLACKBOOK === 'undefined'){
    if(typeof BLACKBOOK_SEALED === 'undefined'){
      if(UI.bbMissing) return `<div class="scroll"><div class="page bb-lock"><div class="bb-lockbox">${ico('gem')}<h1>Blackbook</h1><p class="t2">Not sealed on this copy yet. In the project folder run <code>node tools/seal_blackbook.mjs</code>, then <code>python tools/stamp.py</code>.</p></div></div></div>`;
      if(typeof lazyNeed === 'function') lazyNeed('bb').then(ok => { if(!ok) UI.bbMissing = true; if(UI.route.area === 'blackbook') renderMain(); }); return `<div class="scroll"><div class="page"><p class="t3">Opening…</p></div></div>`; }
    bbUnlock(); return bbLockView();
  }
  bbUnlock(); bbNorm(BLACKBOOK);
  const B = BLACKBOOK, tab = BB_TABS.some(t => t[0] === UI.bbTab) ? UI.bbTab : 'hunt', q = (UI.bbQ || '').trim().toLowerCase(), words = q.split(/\s+/).filter(Boolean);
  const hit = (...s) => !words.length || words.every(w => s.join(' ').toLowerCase().includes(w));
  const mark = s => { let h = esc(s); for(const w of words) h = h.replace(new RegExp('(' + w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ')', 'gi'), '<mark>$1</mark>'); return h; };
  let body = '', shown = 0;
  if(tab === 'hunt'){
    const play = UI.bbPlay && B.plays.find(p => p.id === UI.bbPlay);
    if(play) body = bbDossier(play, mark);
    else { const r = bbMatrix(B, hit, mark); body = r.html; shown = r.n; }
  } else if(tab === 'sweeps'){ const r = bbSweeps(B, hit, mark); body = r.html; shown = r.n; }
  else if(tab === 'doctrine'){ const r = bbDoctrine(B, hit, mark); body = r.html; shown = r.n; }
  else if(tab === 'apt'){ const r = bbCases(B, hit, mark); body = r.html; shown = r.n; }
  else if(tab === 'under'){ const r = bbUnder(B, hit, mark); body = r.html; shown = r.n; }
  else { const r = bbRef(B.osint, 'bb-o-', hit, mark); shown = r.n;
    body = r.html ? r.html + `<p class="t3 small bbx-foot">The basics — research environment, personas, pivoting, attribution — are in <button class="lnk" data-act="bbGo" data-v="tradecraft">Tradecraft</button>.</p>` : ''; }
  const dossier = tab === 'hunt' && UI.bbPlay;
  const counts = {plays:B.plays.length, hunts:B.plays.reduce((n, p) => n + Object.keys(p.q).length, 0), sigma:B.plays.filter(p => p.q.sigma).length, apt:B.apt.length};
  const nothing = !dossier && !body ? empty('search', 'Nothing in the Blackbook matches', 'Try another word, or clear the search.') : '';
  return `<div class="scroll"><div class="page tc bb bbx">
    <header class="bbx-hd"><div class="bbx-id"><span class="tc-ix">${ico('gem', 'sm')}Private · works offline</span><h1>Blackbook</h1>
        <p>Detection plays, hunts and investigation tradecraft — defensive only, no exploit code.</p></div>
      <dl class="bbx-stats"><div><dt>Plays</dt><dd>${counts.plays}</dd></div><div><dt>Hunts</dt><dd>${counts.hunts}</dd></div><div><dt>Proven Sigma</dt><dd>${counts.sigma}</dd></div><div><dt>Campaigns</dt><dd>${counts.apt}</dd></div></dl>
      ${typeof BLACKBOOK_SEALED !== 'undefined' ? `<button class="btn sm ghost bb-lockbtn" data-act="bbLock" title="Lock it again on this device">${ico('lock', 'sm')}Lock</button>` : ''}</header>
    <div class="bbx-bar"><nav class="tabs bb-tabs" role="tablist" aria-label="Parts of the Blackbook">${BB_TABS.map(([k, l, i]) => `<button role="tab" aria-selected="${k === tab}" class="${k === tab ? 'on' : ''}" data-act="bbTab" data-v="${k}">${ico(i, 'sm')}${l}</button>`).join('')}</nav>
      <div class="search-in bbx-q">${ico('search')}<label class="sr" for="bbQ">Search the Blackbook</label><input id="bbQ" class="inp" type="search" placeholder="Kerberoast, AD CS, rclone, Okta…" value="${esc(UI.bbQ || '')}"></div></div>
    ${body}${nothing}${words.length && shown && !dossier ? `<p class="t3 small bbx-foot">${shown} match${shown === 1 ? '' : 'es'} for “${esc(UI.bbQ)}”.</p>` : ''}</div></div>`;
}

const BB_FID = {high:'High signal', medium:'Needs triage', low:'Hunt in bulk'};
/* older or partial packs still draw: anything missing gets a safe default */
function bbNorm(B){ if(B.__norm) return; for(const k of ['sections', 'plays', 'doctrine', 'mirror', 'apt', 'underground', 'caught', 'caughtPatterns', 'osint', 'workflow', 'telemetry', 'sweeps']) if(!Array.isArray(B[k])) B[k] = []; B.langs = B.langs || {}; B.plats = B.plats || {};
  for(const p of B.plays){ p.plat = Array.isArray(p.plat) ? p.plat : []; p.fid = BB_FID[p.fid] ? p.fid : 'medium'; p.sev = BB_SEV[p.sev] ? p.sev : 'medium'; for(const k of ['sig', 'fix', 'att', 'events', 'triage', 'respond', 'seen']) if(!Array.isArray(p[k])) p[k] = []; p.q = p.q || {}; p.lens = p.lens || ''; p.logs = p.logs || ''; p.fp = p.fp || ''; }
  for(const a of B.apt){ a.plays = Array.isArray(a.plays) ? a.plays.filter(id => B.plays.some(p => p.id === id)) : []; a.tells = Array.isArray(a.tells) ? a.tells : []; }
  for(const s of B.sweeps){ s.steps = Array.isArray(s.steps) ? s.steps.filter(x => Array.isArray(x) && B.plays.some(p => p.id === x[0])) : []; }
  try{ Object.defineProperty(B, '__norm', {value:true}); }catch(e){} }
const bbFilters = () => UI.bbF || (UI.bbF = {plat:new Set(), sev:new Set(), sigma:false, st:'', ids:null, idsLabel:''});
function bbVisible(B, hit){
  const F = bbFilters();
  return B.plays.filter(p => (!F.plat.size || p.plat.some(x => F.plat.has(x))) && (!F.sev.size || F.sev.has(p.sev)) && (!F.sigma || p.q.sigma) && (!F.st || bbSt(p.id) === F.st) && (!F.ids || F.ids.includes(p.id))
    && hit(p.t, p.lens, p.sig.join(' '), p.att.join(' '), p.logs, p.fp, p.fix.join(' '), Object.values(p.q).join(' '), (p.seen || []).flat().join(' '), (p.events || []).flat().join(' '), (p.triage || []).join(' '), p.plat.map(x => B.plats[x]).join(' ')));
}
/* your progress: a bar split into detecting / hunted / to do */
function bbProgress(ids, label){
  const n = ids.length, live = ids.filter(id => bbSt(id) === 'live').length, hunted = ids.filter(id => bbSt(id) === 'hunted').length, pc = x => n ? (x / n * 100).toFixed(2) + '%' : '0';
  return `<div class="bbx-prog" role="img" aria-label="${esc(label)}: ${live} detecting, ${hunted} hunted, ${n - live - hunted} to do"><i class="p-live" style="width:${pc(live)}"></i><i class="p-hunted" style="width:${pc(hunted)}"></i></div>`;
}
/* your coverage as an ATT&CK Navigator layer (format 4.5): every technique a play covers, scored by the best status you gave
   any play for it — 2 detecting, 1 hunted, 0 to do — with the plays and their status in the comment. Open it in the Navigator
   (Open Existing Layer → Upload from local); nothing is sent anywhere from here. */
function bbNavLayer(B){
  const rank = {live:2, hunted:1, todo:0}, T = new Map();
  for(const p of B.plays) for(const id of p.att || []){ const st = bbSt(p.id), t = T.get(id) || {score:0, plays:[]}; t.score = Math.max(t.score, rank[st] || 0); t.plays.push(p.t + ' — ' + BB_ST[st]); T.set(id, t); }
  const col = ['#e8e8e8', '#f6c35b', '#4caf7d'];
  return {name:'Blackbook coverage', versions:{layer:'4.5', navigator:'5.1.0'}, domain:'enterprise-attack',
    description:`Blackbook plays marked in OSINTrix on ${new Date().toISOString().slice(0, 10)}: ${B.plays.filter(p => bbSt(p.id) === 'live').length} detecting, ${B.plays.filter(p => bbSt(p.id) === 'hunted').length} hunted, ${B.plays.filter(p => bbSt(p.id) === 'todo').length} to do.`.replace(/\s+/g, ' '),
    techniques:[...T].sort((a, b) => a[0].localeCompare(b[0])).map(([id, t]) => ({techniqueID:id, score:t.score, color:col[t.score], comment:t.plays.join('\n'), enabled:true, showSubtechniques:id.includes('.')})),
    gradient:{colors:col, minValue:0, maxValue:2}, legendItems:[{label:'Detecting', color:col[2]}, {label:'Hunted', color:col[1]}, {label:'To do', color:col[0]}],
    sorting:3, layout:{layout:'side', showName:true, showID:false}, hideDisabled:false, selectTechniquesAcrossTactics:true, selectSubtechniquesWithParent:false};
}
function bbMatrix(B, hit, mark){
  const F = bbFilters(), vis = bbVisible(B, hit), ids = new Set(vis.map(p => p.id)), used = new Set(B.plays.flatMap(p => p.plat)), all = B.plays.map(p => p.id);
  const live = all.filter(id => bbSt(id) === 'live').length, hunted = all.filter(id => bbSt(id) === 'hunted').length;
  const chip = (act, v, label, on) => `<button class="chip${on ? ' on' : ''}" aria-pressed="${on}" data-act="${act}" data-v="${v}">${label}</button>`;
  const plat = F.plat.size === 1 ? [...F.plat][0] : '';
  const stack = bbStack();
  const anyF = F.plat.size || F.sev.size || F.sigma || F.st || F.ids;
  const bar = `<div class="bbx-tools" role="group" aria-label="Filter plays">
      <label class="bbx-sel"><span class="sr">Platform</span><select id="bbPlat" class="inp sm" aria-label="Platform"><option value="">All platforms</option>${Object.entries(B.plats).filter(([k]) => used.has(k)).map(([k, l]) => `<option value="${esc(k)}"${k === plat ? ' selected' : ''}>${esc(l)} (${B.plays.filter(p => p.plat.includes(k)).length})</option>`).join('')}</select></label>
      <span class="bbx-seg" role="group" aria-label="Severity">${['critical', 'high', 'medium', 'low'].map(k => chip('bbFSev', k, BB_SEV[k], F.sev.has(k))).join('')}</span>
      ${chip('bbFSigma', '1', `${ico('check', 'sm')}Proven Sigma`, F.sigma)}
      <label class="bbx-sel"><span class="sr">Your status</span><select id="bbSt" class="inp sm" aria-label="Your status"><option value="">Any status</option>${Object.entries(BB_ST).map(([k, l]) => `<option value="${k}"${F.st === k ? ' selected' : ''}>${l}</option>`).join('')}</select></label>
      ${F.ids ? `<span class="chip on bbx-set">${esc(F.idsLabel || 'A set of plays')}<button class="bbx-x" data-act="bbFIds" aria-label="Show every play">${ico('x', 'sm')}</button></span>` : ''}
      ${anyF ? `<button class="lnk" data-act="bbFClear">Clear filters</button>` : ''}<span class="sp"></span>
      <details class="bbx-stack"><summary>${ico('file-code', 'sm')}Languages: ${stack.map(k => esc(bbShort(B, k))).join(', ')}</summary>
        <div><p class="t3">Hunts in these languages are shown on each play.</p>${Object.entries(B.langs).map(([k, l]) => chip('bbStack', k, esc(l), stack.includes(k))).join('')}</div></details></div>`;
  const cover = `<section class="bbx-cover" aria-label="Your coverage"><div><h2>Your coverage</h2><p class="t3">Mark each play as you hunt it and as a detection goes live. Kept in this browser.</p></div>
      <div class="bbx-cn"><span><b>${live}</b>detecting</span><span><b>${hunted}</b>hunted</span><span><b>${all.length - live - hunted}</b>to do</span></div>${bbProgress(all, 'All plays')}
      <div class="bbx-cx"><button class="btn sm" data-act="bbNav" title="A layer file for the MITRE ATT&amp;CK Navigator: each technique coloured by your best status for it">${ico('download', 'sm')}ATT&amp;CK Navigator layer</button></div></section>`;
  const secs = B.sections.map(s => ({s, ps:B.plays.filter(p => p.sec === s.id)}));
  const nav = `<nav class="bbx-secs" aria-label="Stages of an attack">${secs.map(({s, ps}) => { const n = ps.filter(p => ids.has(p.id)).length;
      return `<button data-act="bbToc" data-v="bb-s-${s.id}"${n ? '' : ' disabled'}>${ico(s.icon, 'sm')}<span>${esc(s.title)}</span><small>${n}</small>${bbProgress(ps.map(p => p.id), s.title)}</button>`; }).join('')}</nav>`;
  const rows = secs.map(({s, ps}) => { ps = ps.filter(p => ids.has(p.id)); if(!ps.length) return '';
    return `<section class="bb-row" id="bb-s-${s.id}" aria-labelledby="bb-sh-${s.id}"><header><h2 id="bb-sh-${s.id}">${ico(s.icon, 'sm')}${esc(s.title)}</h2><p>${esc(s.lead)}</p></header>
      <ul class="bbx-plays">${ps.map(p => { const st = bbSt(p.id);
        return `<li><button class="bb-tile" data-act="bbOpenPlay" data-v="${p.id}">${bbSevTag(p.sev)}<span class="bbx-t"><span class="bb-tt">${mark(p.t)}</span><small>${p.plat.map(x => esc(B.plats[x])).join(' · ')}</small></span>
          <span class="bbx-h">${Object.keys(p.q).filter(k => stack.includes(k)).map(k => `<span${k === 'sigma' ? ' class="sg" title="Proven Sigma rule"' : ''}>${esc(bbShort(B, k))}</span>`).join('')}</span>
          <span class="bbx-st st-${st}">${BB_ST[st]}</span></button></li>`; }).join('')}</ul></section>`; }).join('');
  return {n:vis.length, html:`<div class="bbx-idx">${nav}<div class="bbx-main">${cover}${bar}<p class="t3 small bbx-count" aria-live="polite">${vis.length} of ${B.plays.length} plays</p>${rows || empty('search', 'No play matches', 'Clear a filter or try another word.')}</div></div>`};
}

function bbDossier(p, mark){
  const B = BLACKBOOK, sec = B.sections.find(s => s.id === p.sec) || {}, list = bbVisible(B, () => true), i = list.findIndex(x => x.id === p.id), prev = list[i - 1], next = list[i + 1];
  const stack = bbStack(), langs = Object.keys(p.q).filter(k => stack.includes(k)), cur = langs.includes((UI.bbLang || {})[p.id]) ? UI.bbLang[p.id] : langs[0], rule = bbRuleOf(p), code = cur ? p.q[cur] : '';
  const st = bbSt(p.id), cases = B.apt.filter(a => a.plays.includes(p.id)), sweeps = B.sweeps.filter(s => s.steps.some(x => x[0] === p.id));
  const tbl = (head, rows) => `<div class="tc-mx bb-tbl" tabindex="0" role="region" aria-label="${esc(head.join(', '))}"><table><thead><tr>${head.map(h => `<th scope="col">${h}</th>`).join('')}</tr></thead><tbody>${rows.map(r => `<tr>${r.map((c, j) => `<td${j === 0 ? ' class="nw"' : ''}>${mark(c)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
  const stage = (id, n, title, inner) => `<section class="bbx-s" id="bbd-${id}" aria-labelledby="bbd-${id}-h"><h3 id="bbd-${id}-h"><span class="bbx-n">${n}</span>${title}</h3>${inner}</section>`;
  const parts = [['understand', 'Understand'], ['detect', 'Detect'], ['hunt', 'Hunt'], ['triage', 'Triage'], ['respond', 'Respond'], ['harden', 'Harden'], ['prove', 'Prove']];
  const hunt = langs.length ? `<div class="bb-q"><div class="bb-qt"><div class="bb-qtabs" role="tablist" aria-label="Hunts for ${esc(p.t)}">${langs.map(k => `<button role="tab" aria-selected="${k === cur}" class="${k === cur ? 'on' : ''}" data-act="bbLang" data-id="${p.id}" data-v="${k}">${esc(bbShort(B, k))}</button>`).join('')}</div>
        <span class="sp"></span><button class="btn sm ghost" data-act="bbCopy" data-id="${p.id}" data-v="${cur}">${ico('copy', 'sm')}Copy</button>
        ${cur === 'sigma' ? (rule ? `<button class="btn sm ghost" data-act="bbOpenRule" data-v="${p.id}">${ico('file-code', 'sm')}In your Detections</button>` : `<button class="btn sm ghost" data-act="bbRule" data-v="${p.id}">${ico('plus', 'sm')}Add to Detections</button>`) + `<button class="btn sm ghost" data-act="bbHunt" data-v="${p.id}">${ico('crosshair', 'sm')}Hunt my evidence</button>` : ''}</div>
      <pre class="bb-code" tabindex="0" aria-label="${esc(B.langs[cur] || cur)}"><code>${esc(code)}</code></pre>
      ${cur === 'sigma' && p.ev ? `<p class="bb-proof">${ico('check', 'sm')}<span>Proven: matches <code>${esc(p.ev[0])}</code>, and leaves <code>${esc(p.ev[1])}</code> alone.</span></p>` : ''}</div>`
    : `<p class="t3">None of your languages has a hunt for this play. Change “Languages” on the play list.</p>`;
  return `<div class="bbx-dwrap"><article class="bb-dos" id="bb-dossier" data-play="${p.id}" aria-labelledby="bb-dt">
    <nav class="bb-dnav" aria-label="Plays"><button class="btn sm ghost" data-act="bbBack">${ico('arrow-left', 'sm')}All plays</button><span class="t3 bbx-crumb">${ico(sec.icon || 'crosshair', 'sm')}${esc(sec.title || '')}</span><span class="sp"></span>
      ${prev ? `<button class="btn sm ghost" data-act="bbOpenPlay" data-v="${prev.id}" title="${esc(prev.t)}" aria-label="Previous: ${esc(prev.t)}">${ico('arrow-left', 'sm')}<span class="bbx-lbl">Previous</span></button>` : ''}${next ? `<button class="btn sm ghost" data-act="bbOpenPlay" data-v="${next.id}" title="${esc(next.t)}" aria-label="Next: ${esc(next.t)}"><span class="bbx-lbl">Next</span>${ico('arrow-right', 'sm')}</button>` : ''}</nav>
    <header class="bb-dh"><h2 id="bb-dt" tabindex="-1">${mark(p.t)}</h2>
      <ul class="bbx-facts"><li>${bbSevTag(p.sev)}</li><li><span class="bb-fid f-${p.fid}">${BB_FID[p.fid]}</span></li><li>${p.plat.map(x => esc(B.plats[x])).join(', ')}</li><li class="bb-tech">${p.att.map(bbTech).join(' ')}</li></ul>
      <div class="bbx-mine" role="radiogroup" aria-label="Your status for this play">${Object.entries(BB_ST).map(([k, l]) => `<button role="radio" aria-checked="${k === st}" class="${k === st ? 'on' : ''}" data-act="bbSetSt" data-id="${p.id}" data-v="${k}">${k === 'live' ? ico('circle-check', 'sm') : k === 'hunted' ? ico('crosshair', 'sm') : ico('circle-dot', 'sm')}${l}</button>`).join('')}</div></header>
    <div class="bbx-dgrid"><div class="bbx-dmain">
    ${stage('understand', 1, 'Understand', `<h4>How an operator sees it</h4><p>${mark(p.lens)}</p>${(p.seen || []).length ? `<h4>Seen in the wild</h4>${tbl(['Who', 'When', 'What'], p.seen)}` : ''}
      ${cases.length ? `<p class="bbx-also">${ico('shield-alert', 'sm')}<span>In the APT casebook: ${cases.map(a => `<button class="lnk" data-act="bbCase" data-v="${esc(a.id)}">${esc(a.name)}</button>`).join(', ')}</span></p>` : ''}`)}
    ${stage('detect', 2, 'Detect', `<div class="bb-cols"><div><h4>What it leaves</h4><ul>${p.sig.map(s => `<li>${mark(s)}</li>`).join('')}</ul></div><div><h4>Logs you need</h4><p class="t2">${mark(p.logs)}</p></div></div>
      ${(p.events || []).length ? `<h4>Telemetry to read</h4>${tbl(['Source', 'Event', 'Fields', 'Look for'], p.events)}` : '<h4>Telemetry to read</h4><p class="t3">The logs above; no single event marks it.</p>'}`)}
    ${stage('hunt', 3, 'Hunt', hunt + (p.fp ? `<h4>What else looks like this</h4><p class="t2">${mark(p.fp)}</p>` : ''))}
    ${stage('triage', 4, 'Triage', `<h4>When it fires</h4><ol>${(p.triage || []).map(s => `<li>${mark(s)}</li>`).join('')}</ol>`)}
    ${stage('respond', 5, 'Respond', `<ol>${(p.respond || []).map(s => `<li>${mark(s)}</li>`).join('')}</ol>`)}
    ${stage('harden', 6, 'Harden', `<h4>What closes it</h4><ul>${p.fix.map(s => `<li>${mark(s)}</li>`).join('')}</ul>`)}
    ${stage('prove', 7, 'Prove', `<h4>Prove it works</h4><p class="t2">${mark(p.validate || 'Replay the behaviour in a test environment and check the hunt finds it.')}</p>
      ${sweeps.length ? `<p class="bbx-also">${ico('route', 'sm')}<span>Part of the sweeps: ${sweeps.map(s => `<button class="lnk" data-act="bbSweepGo" data-v="${esc(s.id)}">${esc(s.t)}</button>`).join(', ')}</span></p>` : ''}`)}
    </div><nav class="bbx-otp" aria-label="On this play"><b>On this play</b>${parts.map(([id, l], n) => `<button data-act="bbToc" data-v="bbd-${id}"><span>${n + 1}</span>${l}</button>`).join('')}</nav></div>
  </article></div>`;
}

/* Sweeps: plays in the order to run them for one situation, with why each one is next */
function bbSweeps(B, hit, mark){
  const L = B.sweeps.filter(s => hit(s.t, s.when, s.why, s.steps.map(x => x[1]).join(' '), s.steps.map(x => (B.plays.find(p => p.id === x[0]) || {}).t).join(' ')));
  if(!B.sweeps.length) return {n:0, html:`<p class="t3">This copy of the Blackbook has no sweeps yet.</p>`};
  return {n:L.length, html:`<p class="bbx-intro">A sweep is a set of plays run in order for one situation — a new environment, a ransomware warning, a vendor breach. Each step says why it comes next. Your status on each play counts here too.</p>
    <div class="bbx-sweeps">${L.map(s => { const ids = s.steps.map(x => x[0]), done = ids.filter(id => bbSt(id) !== 'todo').length;
      return `<article class="bbx-sweep" id="bb-sw-${esc(s.id)}" aria-labelledby="bb-sw-${esc(s.id)}-h"><header><div><h2 id="bb-sw-${esc(s.id)}-h">${mark(s.t)}</h2><p class="t2">${mark(s.when)}</p></div>
          <div class="bbx-swp"><span class="t3">${done} of ${ids.length} worked</span>${bbProgress(ids, s.t)}</div></header>
        ${s.why ? `<p class="bbx-why">${mark(s.why)}</p>` : ''}
        <ol class="bbx-steps">${s.steps.map(([id, why]) => { const p = B.plays.find(x => x.id === id), st = bbSt(id);
          return `<li class="st-${st}"><span class="bbx-dot" aria-hidden="true"></span><div><button class="lnk bbx-stp" data-act="bbJump" data-v="${esc(id)}">${esc(p.t)}</button> ${bbSevTag(p.sev)}<span class="bbx-st st-${st}">${BB_ST[st]}</span><p>${mark(why)}</p></div></li>`; }).join('')}</ol>
        <div class="bbx-acts"><button class="btn sm" data-act="bbJump" data-v="${esc((s.steps.find(x => bbSt(x[0]) === 'todo') || s.steps[0])[0])}">${ico('crosshair', 'sm')}${done && done < ids.length ? 'Next step' : 'Start'}</button>
          <button class="btn sm ghost" data-act="bbShowSet" data-v="sweep:${esc(s.id)}">${ico('list', 'sm')}These plays in the list</button></div></article>`; }).join('')}</div>`};
}

function bbDoctrine(B, hit, mark){
  const wf = (B.workflow || []).filter(x => hit(...x)), tel = (B.telemetry || []).filter(x => hit(...x)), doc = B.doctrine.filter(d => hit(...d)), mir = B.mirror.filter(m => hit(...m.slice(0, 3)));
  const n = wf.length + tel.length + doc.length + mir.length;
  const ch = (id, i, k, title, lead, inner) => `<section class="tc-ch" id="${id}"><header><span class="tc-n">${k}</span><div><h2>${ico(i, 'sm')}${title}</h2><p>${lead}</p></div></header>${inner}</section>`;
  const html = (wf.length ? ch('bb-wf', 'list-checks', '01', 'A hunt, start to finish', 'Six steps, each with what it should produce. Every play plugs into steps 2–4.',
        `<ol class="bb-wf">${wf.map(([t, d, out]) => `<li><div><b>${mark(t)}</b><p>${mark(d)}</p></div><span class="bb-out"><small>Produces</small>${mark(out)}</span></li>`).join('')}</ol>`) : '')
    + (tel.length ? ch('bb-tel', 'database', '02', 'Telemetry you need first', 'What each source reveals, how to switch it on, and how long to keep it. A hunt can only find what was recorded.',
        `<div class="tc-mx bb-tbl" tabindex="0" role="region" aria-label="Telemetry sources"><table><thead><tr><th scope="col">Source</th><th scope="col">What it reveals</th><th scope="col">How to switch it on</th><th scope="col">Keep</th></tr></thead><tbody>${tel.map(([a, b, c, d]) => `<tr><td><b>${mark(a)}</b></td><td>${mark(b)}</td><td>${mark(c)}</td><td class="nw">${mark(d)}</td></tr>`).join('')}</tbody></table></div>`) : '')
    + (doc.length ? ch('bb-doctrine', 'lightbulb', '03', 'How a hunter thinks', 'The habits that separate a hunt from a search.', `<div class="bbx-ref"><dl>${doc.map(([t, b]) => `<div><dt>${mark(t)}</dt><dd>${mark(b)}</dd></div>`).join('')}</dl></div>`) : '')
    + (mir.length ? ch('bb-mirror', 'git-compare', '04', 'Their first checks, your first checks', 'What a penetration tester or bug-bounty hunter looks at first — and the defender’s mirror of each.',
        `<div class="tc-mx bb-tbl" tabindex="0" role="region" aria-label="Their checks and yours"><table><thead><tr><th scope="col">They look for</th><th scope="col">Why it pays</th><th scope="col">Your check</th></tr></thead><tbody>${mir.map(([a, b, c, id]) => `<tr><td><b>${mark(a)}</b></td><td>${mark(b)}</td><td>${mark(c)}<br><button class="lnk" data-act="bbJump" data-v="${esc(id)}">The play ${ico('arrow-right', 'sm')}</button></td></tr>`).join('')}</tbody></table></div>`) : '');
  const toc = [['bb-wf', 'list-checks', 'A hunt, start to finish'], ['bb-tel', 'database', 'Telemetry you need first'], ['bb-doctrine', 'lightbulb', 'How a hunter thinks'], ['bb-mirror', 'git-compare', 'Their checks, yours']];
  return {n, html:html ? bbWithToc(toc, html) : ''};
}

function bbCases(B, hit, mark){
  const L = B.apt.filter(a => hit(a.name, a.who, a.when, a.what, a.tells.join(' '), a.lesson));
  const html = L.map(a => `<article class="bb-case bbx-case" id="bb-apt-${a.id}" aria-labelledby="bb-apt-${a.id}-h"><header><h2 id="bb-apt-${a.id}-h">${mark(a.name)}</h2><p class="t3">${mark(a.who)} · ${mark(a.when)}</p></header>
      <p class="bbx-what">${mark(a.what)}</p>
      <div class="bb-cols"><div><h3>The tells</h3><ul>${a.tells.map(t => `<li>${mark(t)}</li>`).join('')}</ul></div>
        <div><h3>Plays that catch it</h3><ul class="bbx-cplays">${a.plays.map(id => { const p = B.plays.find(x => x.id === id), st = bbSt(id); return `<li>${bbSevTag(p.sev)}<button class="lnk" data-act="bbJump" data-v="${esc(id)}">${esc(p.t)}</button><span class="bbx-st st-${st}">${BB_ST[st]}</span></li>`; }).join('')}</ul>
          <button class="btn sm ghost" data-act="bbShowSet" data-v="apt:${esc(a.id)}">${ico('list', 'sm')}These plays in the list</button></div></div>
      <p class="bb-lesson"><b>The lesson.</b> ${mark(a.lesson)}</p></article>`).join('');
  return {n:L.length, html:html ? bbWithToc(B.apt.map(a => [`bb-apt-${a.id}`, 'shield-alert', a.name]), html) : ''};
}

function bbUnder(B, hit, mark){
  const r = bbRef(B.underground, 'bb-u-', hit, mark, true), cases = B.caught.filter(c => hit(c.name, c.year, c.how, c.lesson, c.src));
  const caught = cases.length ? `<section class="tc-ch" id="bb-caught"><header><span class="tc-n">${ico('lock', 'sm')}</span><div><h2>How they were caught</h2><p>From court filings and official statements: the mistake that identified each one, and what an investigator can learn from it.</p></div></header>
      <div class="bb-pat">${B.caughtPatterns.map(([t, d]) => `<div><b>${esc(t)}</b><span>${esc(d)}</span></div>`).join('')}</div>
      ${cases.map(c => `<article class="bb-case bbx-case"><header><h2>${mark(c.name)}</h2><p class="t3">${esc(c.year)} · ${mark(c.src)}</p></header><p>${mark(c.how)}</p><p class="bb-lesson"><b>For the investigator.</b> ${mark(c.lesson)}</p></article>`).join('')}</section>` : '';
  const html = r.html || caught ? `<div class="bb-note">${ico('scale', 'sm')}<p>For authorised investigators: CTI teams, journalists and law enforcement. Observe and record; do not buy, take part or provoke. Anything that names a victim or a crime in progress goes to the victim and the police.</p></div>${r.html}${caught}` : '';
  return {n:r.n + cases.length, html:html ? bbWithToc(B.underground.map((g, gi) => [`bb-u-${gi}`, 'skull', g.h]).concat([['bb-caught', 'lock', 'How they were caught']]), html) : ''};
}

/* a reference part (Underground, OSINT): one heading per group, each point a term and its explanation side by side */
function bbRef(groups, pre, hit, mark, inner){
  let n = 0;
  const html = groups.map((g, gi) => { const pts = g.pts.filter(x => hit(x[0], x[1], g.h)); n += pts.length; return pts.length ? `<section class="bbx-grp" id="${pre}${gi}" aria-labelledby="${pre}${gi}-h"><h2 id="${pre}${gi}-h">${esc(g.h)}<small>${pts.length}</small></h2>
      <div class="bbx-ref"><dl>${pts.map(x => `<div><dt>${mark(x[0])}</dt><dd>${mark(x[1])}${x[2] ? bbGoBtn(x[2]) : ''}</dd></div>`).join('')}</dl></div></section>` : ''; }).join('');
  return {n, html:inner || !html ? html : bbWithToc(groups.map((g, gi) => [`${pre}${gi}`, 'scan-search', g.h]), html)};
}
function bbWithToc(items, html){
  return `<div class="tc-grid"><nav class="tc-toc" aria-label="Contents">${items.map(([id, i, l]) => `<button data-act="bbToc" data-v="${esc(id)}">${ico(i, 'sm')}<span>${esc(l)}</span></button>`).join('')}</nav><div class="tc-main">${html}</div></div>`;
}

function bbAddRule(id, quiet){
  const p = BLACKBOOK.plays.find(x => x.id === id); if(!p || !p.q.sigma) return null;
  ensureRules(); let r = bbRuleOf(p); if(r) return r;
  const now = Date.now(), title = (p.q.sigma.match(/^title: (.*)$/m) || [, p.t])[1].trim();
  r = {id:uid('r'), type:'sigma', title:nextName(title, DB.rules.map(x => x.title)), desc:p.lens.split('. ').slice(0, 2).join('. ').replace(/\.?$/, '.'), code:p.q.sigma, severity:p.sev, category:p.sec, technique:p.att[0], author:'OSINTrix Blackbook',
    platform:/product: linux/.test(p.q.sigma) ? 'Linux' : /product: aws/.test(p.q.sigma) ? 'AWS' : /product: m365/.test(p.q.sigma) ? 'Microsoft 365' : /category: webserver/.test(p.q.sigma) ? 'Web' : 'Windows', tags:['blackbook', p.sec], refs:['https://attack.mitre.org/techniques/' + p.att[0].replace('.', '/') + '/'], created:now, modified:now, starred:false, caseId:null, bb:p.id};
  DB.rules.push(r); mutate('added Blackbook rule ' + r.title);
  if(!quiet) toast(`“${r.title}” is in your Detections`, 'Open', () => { UI.rule = r.id; UI.ropen = true; go('#/detections'); });
  return r;
}
document.addEventListener('change', ev => { const t = ev.target; if(!t || (t.id !== 'bbPlat' && t.id !== 'bbSt')) return; const F = bbFilters();
  if(t.id === 'bbPlat') F.plat = t.value ? new Set([t.value]) : new Set(); else F.st = BB_ST[t.value] ? t.value : '';
  renderMain(); const el = $(t.id); if(el) el.focus(); });
document.addEventListener('input', ev => { if(ev.target && ev.target.id === 'bbQ'){ clearTimeout(UI.bbT); UI.bbT = setTimeout(() => { UI.bbQ = ev.target.value; UI.bbPlay = null; const p = ev.target.selectionStart; renderMain(); const i = $('bbQ'); if(i){ i.focus(); i.setSelectionRange(p, p); } }, 180); } });
const BB_ACTS = {
  bbNav:() => { if(typeof BLACKBOOK === 'undefined') return; const B = BLACKBOOK; download('blackbook-coverage-layer.json', JSON.stringify(bbNavLayer(B), null, 1), 'application/json'); toast('Layer saved — open it in the ATT&CK Navigator with “Open Existing Layer”'); },
  bbTab:(id, v) => { if(v === 'hunt' && UI.bbTab === 'hunt') UI.bbPlay = null; UI.bbTab = v; renderMain(); const m = $('main'); const s = m && m.querySelector('.scroll'); if(s) s.scrollTop = 0; },
  bbToc:(id, v) => { const el = $(v); if(el) el.scrollIntoView({behavior:'smooth', block:'start'}); },
  bbOpenPlay:(id, v) => { UI.bbPlay = v; renderMain(); const sc = document.querySelector('#main .scroll'); if(sc) sc.scrollTop = 0; const h = $('bb-dt'); if(h) h.focus({preventScroll:true}); },
  bbBack:() => { const was = UI.bbPlay; UI.bbPlay = null; renderMain(); const t = was && document.querySelector(`.bb-tile[data-v="${was}"]`); if(t){ t.scrollIntoView({block:'center'}); t.focus({preventScroll:true}); } },
  bbFPlat:(id, v) => { const F = bbFilters(); F.plat.has(v) ? F.plat.delete(v) : F.plat.add(v); renderMain(); },
  bbFSev:(id, v) => { const F = bbFilters(); F.sev.has(v) ? F.sev.delete(v) : F.sev.add(v); renderMain(); },
  bbFSigma:() => { const F = bbFilters(); F.sigma = !F.sigma; renderMain(); },
  bbFClear:() => { UI.bbF = null; renderMain(); },
  bbFIds:() => { const F = bbFilters(); F.ids = null; F.idsLabel = ''; renderMain(); },
  bbSetSt:(id, v, el) => { const pid = el && el.dataset.id; if(!pid || !BB_ST[v]) return; const S = Object.assign({}, DB.prefs.bbSt || {}); if(v === 'todo') delete S[pid]; else S[pid] = v; DB.prefs.bbSt = S; save(); renderMain();
    const b = document.querySelector(`[data-act=bbSetSt][data-id="${pid}"][data-v="${v}"]`); if(b) b.focus(); },
  bbCase:(id, v) => { UI.bbTab = 'apt'; UI.bbQ = ''; UI.bbPlay = null; renderMain(); const el = $('bb-apt-' + v); if(el){ el.scrollIntoView({block:'start'}); const h = el.querySelector('h2'); if(h){ h.tabIndex = -1; h.focus({preventScroll:true}); } } },
  bbSweepGo:(id, v) => { UI.bbTab = 'sweeps'; UI.bbQ = ''; UI.bbPlay = null; renderMain(); const el = $('bb-sw-' + v); if(el){ el.scrollIntoView({block:'start'}); const h = el.querySelector('h2'); if(h){ h.tabIndex = -1; h.focus({preventScroll:true}); } } },
  bbShowSet:(id, v) => { const B = BLACKBOOK, [kind, key] = v.split(':'), src = kind === 'apt' ? B.apt.find(a => a.id === key) : B.sweeps.find(s => s.id === key); if(!src) return;
    UI.bbF = null; const F = bbFilters(); F.ids = kind === 'apt' ? src.plays.slice() : src.steps.map(x => x[0]); F.idsLabel = kind === 'apt' ? src.name : src.t;
    UI.bbTab = 'hunt'; UI.bbQ = ''; UI.bbPlay = null; renderMain(); const sc = document.querySelector('#main .scroll'); if(sc) sc.scrollTop = 0; },
  bbPlay:(id, v) => { const o = bbOpen(); if(o.has(v)) o.delete(v); else o.add(v); renderMain(); const b = document.querySelector(`[data-act=bbPlay][data-v="${v}"]`); if(b) b.focus(); },
  bbJump:(id, v) => { UI.bbTab = 'hunt'; UI.bbQ = ''; UI.bbF = null; BB_ACTS.bbOpenPlay(null, v); },
  bbLang:(id, v, el) => { const pid = el && el.dataset.id; if(!pid) return; UI.bbLang = UI.bbLang || {}; UI.bbLang[pid] = v; renderMain(); const b = document.querySelector(`[data-act=bbLang][data-id="${pid}"][data-v="${v}"]`); if(b) b.focus(); },
  bbStack:(id, v) => { let L = bbStack().slice(); L = L.includes(v) ? L.filter(x => x !== v) : L.concat(v); if(!L.length) return toast('Keep at least one language'); DB.prefs.bbLangs = L; save(); renderMain(); },
  bbCopy:(id, v, el) => { const p = BLACKBOOK.plays.find(x => x.id === (el && el.dataset.id)); if(p && p.q[v]) copyText(p.q[v], 'Copied the ' + BLACKBOOK.langs[v].split(' — ')[0] + ' hunt'); },
  bbRule:(id, v) => { bbAddRule(v); renderMain(); },
  bbOpenRule:(id, v) => { const r = bbRuleOf({id:v}); if(r){ UI.rule = r.id; UI.ropen = true; go('#/detections'); } },
  bbHunt:(id, v) => { const r = bbAddRule(v, true); if(!r) return; let h = huntList().find(x => x.kind === 'rule' && x.ruleId === r.id);
    if(!h){ h = {id:uid('h'), name:nextName('Blackbook — ' + r.title, huntList().map(x => x.name)).slice(0, 120), kind:'rule', ruleId:r.id, created:Date.now(), lastAt:Date.now(), seen:[]}; DB.hunts = [...huntList(), h]; mutate('saved hunt ' + h.name); }
    const res = huntRun(h), n = res.matches.length; renderMain();
    toast(n ? `${n} event${n === 1 ? '' : 's'} in your evidence match — the hunt keeps watching` : 'Nothing in your evidence matches yet — the hunt keeps watching new evidence', 'Open', () => { UI.dview = 'hunts'; go('#/detections'); }); },
  bbLock:() => { try{ delete window.BLACKBOOK; }catch(e){ window.BLACKBOOK = undefined; } UI.bbAuto = 'done'; UI.bbOpen = new Set(); IDB.setMany([], ['bb:key']); renderMain(); toast('Locked — the passphrase is needed again on this device'); },
  bbGo:(id, v) => { if(v.startsWith('case:')){ if(!theCase()) return toast('Open a case first'); return go(caseHash(DB.active, v.slice(5))); } go('#/' + v); },
};
