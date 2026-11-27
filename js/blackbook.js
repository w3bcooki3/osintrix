/* ==========================================================================
   The Blackbook — a hidden part of the Kit (contents: js/data/blackbook-sealed.js, encrypted).
   Opened by typing "blackbook" in search (Ctrl K) or at #/blackbook; once
   opened it stays in the side menu. Four parts:
   · Hunt — doctrine, the attacker's first checks mirrored for defenders, and
     plays across the attack chain: how an operator sees it, what it leaves,
     the logs you need, hunts in KQL / SPL / Sigma / EQL / osquery, tuning
     and what closes it. A Sigma hunt joins your Detections in one click and
     can run as a saved hunt over your evidence.
   · APT casebook — public campaigns, their tells, and the plays that catch them.
   · Underground — working cybercrime forums, markets and Telegram as an
     authorised investigator, and how cybercriminals were actually caught.
   · OSINT — infrastructure pivots, archives, verification, exact syntax.
   ========================================================================== */
const BB_TABS = [['hunt', 'Hunt', 'crosshair'], ['doctrine', 'Doctrine', 'lightbulb'], ['apt', 'APT casebook', 'shield-alert'], ['under', 'Underground', 'skull'], ['osint', 'OSINT', 'scan-search']];
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
  let body = '', toc = '', shown = 0, wide = false;
  if(tab === 'hunt'){
    const play = UI.bbPlay && B.plays.find(p => p.id === UI.bbPlay);
    if(play){ body = bbDossier(play, mark); wide = true; }
    else { const r = bbMatrix(B, hit, mark); body = r.html; shown = r.n; wide = true; }
  } else if(tab === 'doctrine'){
    const wf = (B.workflow || []).filter(x => hit(...x)), tel = (B.telemetry || []).filter(x => hit(...x)), doc = B.doctrine.filter(d => hit(...d)), mir = B.mirror.filter(m => hit(...m.slice(0, 3)));
    shown = wf.length + tel.length + doc.length + mir.length;
    body = (wf.length ? `<section class="tc-ch" id="bb-wf"><header><span class="tc-n">01</span><div><h2>${ico('list-checks', 'sm')}A hunt, start to finish</h2><p>Six steps, each with what it should produce. Every play in the Hunt tab plugs into steps 2–4.</p></div></header>
        <ol class="bb-wf">${wf.map(([t, d, out]) => `<li><div><b>${mark(t)}</b><p>${mark(d)}</p></div><span class="bb-out"><small>Produces</small>${mark(out)}</span></li>`).join('')}</ol></section>` : '')
      + (tel.length ? `<section class="tc-ch" id="bb-tel"><header><span class="tc-n">02</span><div><h2>${ico('database', 'sm')}Telemetry you need first</h2><p>What each source reveals, how to switch it on, and how long to keep it. A hunt can only find what was recorded.</p></div></header>
        <div class="tc-mx bb-tbl" tabindex="0" role="region" aria-label="Telemetry sources"><table><thead><tr><th>Source</th><th>What it reveals</th><th>How to switch it on</th><th>Keep</th></tr></thead><tbody>${tel.map(([a, b, c, d]) => `<tr><td><b>${mark(a)}</b></td><td>${mark(b)}</td><td>${mark(c)}</td><td class="nw">${mark(d)}</td></tr>`).join('')}</tbody></table></div></section>` : '')
      + (doc.length ? `<section class="tc-ch" id="bb-doctrine"><header><span class="tc-n">03</span><div><h2>${ico('lightbulb', 'sm')}How a hunter thinks</h2><p>The habits that separate a hunt from a search.</p></div></header><div class="tc-part bb-doc"><ol>${doc.map(([t, b]) => `<li><b>${mark(t)}</b><p>${mark(b)}</p></li>`).join('')}</ol></div></section>` : '')
      + (mir.length ? `<section class="tc-ch" id="bb-mirror"><header><span class="tc-n">04</span><div><h2>${ico('git-compare', 'sm')}Their first checks, your first checks</h2><p>What a penetration tester or bug-bounty hunter looks at first on an organisation — and the defender’s mirror of each.</p></div></header>
        <div class="tc-mx bb-tbl" tabindex="0" role="region" aria-label="Their checks and yours"><table><thead><tr><th>They look for</th><th>Why it pays</th><th>Your check</th></tr></thead><tbody>${mir.map(([a, b, c, id]) => `<tr><td><b>${mark(a)}</b></td><td>${mark(b)}</td><td>${mark(c)}<br><button class="lnk" data-act="bbJump" data-v="${esc(id)}">The play ${ico('arrow-right', 'sm')}</button></td></tr>`).join('')}</tbody></table></div></section>` : '');
    toc = [['bb-wf', 'list-checks', 'A hunt, start to finish'], ['bb-tel', 'database', 'Telemetry you need first'], ['bb-doctrine', 'lightbulb', 'How a hunter thinks'], ['bb-mirror', 'git-compare', 'Their checks, yours']].map(([id, i, l]) => `<button data-act="bbToc" data-v="${id}">${ico(i, 'sm')}<span>${l}</span></button>`).join('');
  } else if(tab === 'apt'){
    const L = B.apt.filter(a => hit(a.name, a.who, a.when, a.what, a.tells.join(' '), a.lesson)); shown += L.length;
    body = L.map(a => `<article class="bb-case" id="bb-apt-${a.id}"><header><h2>${mark(a.name)}</h2><p class="t3">${mark(a.who)} · ${mark(a.when)}</p></header>
      <p>${mark(a.what)}</p><div class="bb-cols"><div><h3>The tells</h3><ul>${a.tells.map(t => `<li>${mark(t)}</li>`).join('')}</ul></div>
      <div><h3>Plays that catch it</h3><ul class="bb-plist">${a.plays.map(id => { const p = B.plays.find(x => x.id === id); return p ? `<li><button class="lnk" data-act="bbJump" data-v="${esc(id)}">${esc(p.t)}</button> <span class="bb-sev s-${p.sev}">${BB_SEV[p.sev]}</span></li>` : ''; }).join('')}</ul></div></div>
      <p class="bb-lesson"><b>The lesson.</b> ${mark(a.lesson)}</p></article>`).join('');
    toc = B.apt.map(a => `<button data-act="bbToc" data-v="bb-apt-${a.id}">${ico('shield-alert', 'sm')}<span>${esc(a.name)}</span></button>`).join('');
  } else if(tab === 'under'){
    const groups = B.underground.map((g, gi) => { const pts = g.pts.filter(x => hit(x[0], x[1], g.h)); shown += pts.length; return pts.length ? `<section class="tc-part" id="bb-u-${gi}"><h3>${esc(g.h)}</h3><ul>${pts.map(x => `<li><b>${mark(x[0])}</b><p>${mark(x[1])}</p>${x[2] ? bbGoBtn(x[2]) : ''}</li>`).join('')}</ul></section>` : ''; }).join('');
    const cases = B.caught.filter(c => hit(c.name, c.year, c.how, c.lesson, c.src)); shown += cases.length;
    body = `<div class="bb-note">${ico('scale', 'sm')}<p>For authorised investigators: CTI teams, journalists and law enforcement. Observe and record; do not buy, take part or provoke. Anything that names a victim or a crime in progress goes to the victim and the police.</p></div>${groups}
      ${cases.length ? `<section class="tc-ch" id="bb-caught"><header><span class="tc-n">${ico('lock', 'sm')}</span><div><h2>How they were caught</h2><p>From court filings and official statements: the mistake that identified each one, and what an investigator can learn from it.</p></div></header>
        <div class="bb-pat">${B.caughtPatterns.map(([t, d]) => `<div><b>${esc(t)}</b><span>${esc(d)}</span></div>`).join('')}</div>
        ${cases.map(c => `<article class="bb-case"><header><h2>${mark(c.name)}</h2><p class="t3">${esc(c.year)} · ${mark(c.src)}</p></header><p>${mark(c.how)}</p><p class="bb-lesson"><b>For the investigator.</b> ${mark(c.lesson)}</p></article>`).join('')}</section>` : ''}`;
    toc = B.underground.map((g, gi) => `<button data-act="bbToc" data-v="bb-u-${gi}">${ico('skull', 'sm')}<span>${esc(g.h)}</span></button>`).join('') + `<button data-act="bbToc" data-v="bb-caught">${ico('lock', 'sm')}<span>How they were caught</span></button>`;
  } else {
    const groups = B.osint.map((g, gi) => { const pts = g.pts.filter(x => hit(x[0], x[1], g.h)); shown += pts.length; return pts.length ? `<section class="tc-part" id="bb-o-${gi}"><h3>${esc(g.h)}</h3><ul>${pts.map(x => `<li><b>${mark(x[0])}</b><p>${mark(x[1])}</p>${x[2] ? bbGoBtn(x[2]) : ''}</li>`).join('')}</ul></section>` : ''; }).join('');
    body = groups + `<p class="t3 small">The basics — research environment, personas, pivoting, attribution — are in <button class="lnk" data-act="bbGo" data-v="tradecraft">Tradecraft</button>.</p>`;
    toc = B.osint.map((g, gi) => `<button data-act="bbToc" data-v="bb-o-${gi}">${ico('scan-search', 'sm')}<span>${esc(g.h)}</span></button>`).join('');
  }
  const counts = {plays:B.plays.length, hunts:B.plays.reduce((n, p) => n + Object.keys(p.q).length, 0), sigma:B.plays.filter(p => p.q.sigma).length};
  return `<div class="scroll"><div class="page tc bb">
    <header class="tc-hd bb-hd"><div><span class="tc-ix">${ico('gem', 'sm')}Private · works offline</span><h1>Blackbook</h1><p>Think like the intruder, hunt like the defender: ${counts.plays} plays across today’s attack surface with ${counts.hunts} hunts (${counts.sigma} Sigma rules, each proven), the APT casebook, the cybercrime underground, and the OSINT that moves an investigation. Detection and investigation only — no exploit code.</p></div>
      ${typeof BLACKBOOK_SEALED !== 'undefined' ? `<button class="btn sm ghost bb-lockbtn" data-act="bbLock" title="Lock it again on this device">${ico('lock', 'sm')}Lock</button>` : ''}<div class="search-in tc-q">${ico('search')}<label class="sr" for="bbQ">Search the Blackbook</label><input id="bbQ" class="inp" placeholder="Kerberoast, AD CS, rclone, Okta, favicon…" value="${esc(UI.bbQ || '')}"></div></header>
    <nav class="tabs bb-tabs" role="tablist" aria-label="Parts of the Blackbook">${BB_TABS.map(([k, l, i]) => `<button role="tab" aria-selected="${k === tab}" class="${k === tab ? 'on' : ''}" data-act="bbTab" data-v="${k}">${ico(i, 'sm')}${l}</button>`).join('')}</nav>
    ${wide ? `<div class="bb-wide">${body}</div>` : `<div class="tc-grid"><nav class="tc-toc" aria-label="Contents">${toc}</nav>
      <div class="tc-main">${body || empty('search', 'Nothing in the Blackbook matches', 'Try another word.')}${words.length && shown ? `<p class="t3 small">${shown} match${shown === 1 ? '' : 'es'} for “${esc(UI.bbQ)}”.</p>` : ''}</div></div>`}</div></div>`;
}

const BB_FID = {high:'High signal', medium:'Needs triage', low:'Hunt in bulk'};
/* older or partial packs still draw: anything missing gets a safe default */
function bbNorm(B){ if(B.__norm) return; for(const k of ['sections', 'plays', 'doctrine', 'mirror', 'apt', 'underground', 'caught', 'caughtPatterns', 'osint', 'workflow', 'telemetry']) if(!Array.isArray(B[k])) B[k] = []; B.langs = B.langs || {}; B.plats = B.plats || {};
  for(const p of B.plays){ p.plat = Array.isArray(p.plat) ? p.plat : []; p.fid = BB_FID[p.fid] ? p.fid : 'medium'; p.sev = BB_SEV[p.sev] ? p.sev : 'medium'; for(const k of ['sig', 'fix', 'att', 'events', 'triage', 'respond', 'seen']) if(!Array.isArray(p[k])) p[k] = []; p.q = p.q || {}; p.lens = p.lens || ''; p.logs = p.logs || ''; p.fp = p.fp || ''; }
  try{ Object.defineProperty(B, '__norm', {value:true}); }catch(e){} }
const bbFilters = () => UI.bbF || (UI.bbF = {plat:new Set(), sev:new Set(), sigma:false});
function bbVisible(B, hit){
  const F = bbFilters();
  return B.plays.filter(p => (!F.plat.size || p.plat.some(x => F.plat.has(x))) && (!F.sev.size || F.sev.has(p.sev)) && (!F.sigma || p.q.sigma)
    && hit(p.t, p.lens, p.sig.join(' '), p.att.join(' '), p.logs, p.fp, p.fix.join(' '), Object.values(p.q).join(' '), (p.seen || []).flat().join(' '), (p.events || []).flat().join(' '), (p.triage || []).join(' '), p.plat.map(x => B.plats[x]).join(' ')));
}
function bbMatrix(B, hit, mark){
  const F = bbFilters(), vis = bbVisible(B, hit), ids = new Set(vis.map(p => p.id)), used = new Set(B.plays.flatMap(p => p.plat));
  const chip = (act, v, label, on, n) => `<button class="chip${on ? ' on' : ''}" aria-pressed="${on}" data-act="${act}" data-v="${v}">${esc(label)}${n != null ? `<small>${n}</small>` : ''}</button>`;
  const bar = `<div class="bb-filters" role="group" aria-label="Filter plays">
      <div><span class="t3">Platform</span>${Object.entries(B.plats).filter(([k]) => used.has(k)).map(([k, l]) => chip('bbFPlat', k, l, F.plat.has(k), B.plays.filter(p => p.plat.includes(k)).length)).join('')}</div>
      <div><span class="t3">Severity</span>${['critical', 'high', 'medium', 'low'].map(k => chip('bbFSev', k, BB_SEV[k], F.sev.has(k))).join('')}${chip('bbFSigma', '1', 'Has a proven Sigma rule', F.sigma)}
        ${F.plat.size || F.sev.size || F.sigma ? `<button class="lnk" data-act="bbFClear">Clear filters</button>` : ''}<span class="sp"></span><span class="t3">${vis.length} of ${B.plays.length} plays</span></div>
      <div><span class="t3">Your stack</span>${Object.entries(B.langs).map(([k, l]) => chip('bbStack', k, l.split(' — ')[0], bbStack().includes(k))).join('')}</div></div>`;
  const rows = B.sections.map(s => { const ps = B.plays.filter(p => p.sec === s.id && ids.has(p.id)); if(!ps.length) return '';
    return `<section class="bb-row" id="bb-s-${s.id}" aria-labelledby="bb-sh-${s.id}"><header><h2 id="bb-sh-${s.id}">${ico(s.icon, 'sm')}${esc(s.title)}<small>${ps.length}</small></h2><p>${esc(s.lead)}</p></header>
      <div class="bb-tiles">${ps.map(p => `<button class="bb-tile" data-act="bbOpenPlay" data-v="${p.id}"><span class="bb-tt">${mark(p.t)}</span>
        <span class="bb-tm"><span class="bb-sev s-${p.sev}">${BB_SEV[p.sev]}</span><span class="bb-fid f-${p.fid}">${BB_FID[p.fid]}</span>${p.q.sigma ? `<span class="bb-sg" title="Proven Sigma rule">${ico('check', 'sm')}Sigma</span>` : ''}</span>
        <span class="bb-tp">${p.plat.map(x => esc(B.plats[x])).join(' · ')}</span><span class="bb-ids">${p.att.map(esc).join(' ')}</span></button>`).join('')}</div></section>`; }).join('');
  return {n:vis.length, html:bar + (rows || empty('search', 'No play matches', 'Clear a filter or try another word.'))};
}

function bbDossier(p, mark){
  const B = BLACKBOOK, sec = B.sections.find(s => s.id === p.sec) || {}, list = bbVisible(B, () => true), i = list.findIndex(x => x.id === p.id), prev = list[i - 1], next = list[i + 1];
  const stack = bbStack(), langs = Object.keys(p.q).filter(k => stack.includes(k)), cur = langs.includes((UI.bbLang || {})[p.id]) ? UI.bbLang[p.id] : langs[0], rule = bbRuleOf(p), code = cur ? p.q[cur] : '';
  const tbl = (head, rows) => `<div class="tc-mx bb-tbl" tabindex="0" role="region" aria-label="${esc(head.join(', '))}"><table><thead><tr>${head.map(h => `<th>${h}</th>`).join('')}</tr></thead><tbody>${rows.map(r => `<tr>${r.map((c, j) => `<td${j === 0 ? ' class="nw"' : ''}>${mark(c)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
  return `<article class="bb-dos" id="bb-dossier" data-play="${p.id}" aria-labelledby="bb-dt">
    <nav class="bb-dnav" aria-label="Plays"><button class="btn sm ghost" data-act="bbBack">${ico('arrow-left', 'sm')}All plays</button><span class="t3">${ico(sec.icon || 'crosshair', 'sm')}${esc(sec.title || '')}</span><span class="sp"></span>
      ${prev ? `<button class="btn sm ghost" data-act="bbOpenPlay" data-v="${prev.id}" title="${esc(prev.t)}">${ico('arrow-left', 'sm')}Previous</button>` : ''}${next ? `<button class="btn sm ghost" data-act="bbOpenPlay" data-v="${next.id}" title="${esc(next.t)}">Next${ico('arrow-right', 'sm')}</button>` : ''}</nav>
    <header class="bb-dh"><h2 id="bb-dt" tabindex="-1">${mark(p.t)}</h2><p class="bb-tech">${p.att.map(bbTech).join(' ')}</p>
      <dl class="bb-meta"><div><dt>Severity</dt><dd><span class="bb-sev s-${p.sev}">${BB_SEV[p.sev]}</span></dd></div><div><dt>Signal</dt><dd><span class="bb-fid f-${p.fid}">${BB_FID[p.fid]}</span></dd></div>
        <div><dt>Platforms</dt><dd>${p.plat.map(x => esc(B.plats[x])).join(', ')}</dd></div><div><dt>Hunts</dt><dd>${Object.keys(p.q).map(k => esc(B.langs[k].split(' — ')[0])).join(', ')}</dd></div></dl></header>
    <div class="bb-cols"><section><h3>How an operator sees it</h3><p>${mark(p.lens)}</p>
        ${(p.seen || []).length ? `<h3>Seen in the wild</h3>${tbl(['Who', 'When', 'What'], p.seen)}` : ''}</section>
      <section><h3>What it leaves</h3><ul>${p.sig.map(s => `<li>${mark(s)}</li>`).join('')}</ul><h3>Logs you need</h3><p class="t2">${mark(p.logs)}</p></section></div>
    <section><h3>Telemetry to read</h3>${tbl(['Source', 'Event', 'Fields', 'Look for'], p.events || [])}</section>
    ${langs.length ? `<section class="bb-q"><div class="bb-qt"><div class="bb-qtabs" role="tablist" aria-label="Hunts for ${esc(p.t)}">${langs.map(k => `<button role="tab" aria-selected="${k === cur}" class="${k === cur ? 'on' : ''}" data-act="bbLang" data-id="${p.id}" data-v="${k}">${esc(B.langs[k].split(' — ')[0])}</button>`).join('')}</div>
        <span class="sp"></span><button class="btn sm ghost" data-act="bbCopy" data-id="${p.id}" data-v="${cur}">${ico('copy', 'sm')}Copy</button>
        ${cur === 'sigma' ? (rule ? `<button class="btn sm ghost" data-act="bbOpenRule" data-v="${p.id}">${ico('file-code', 'sm')}In your Detections</button>` : `<button class="btn sm ghost" data-act="bbRule" data-v="${p.id}">${ico('plus', 'sm')}Add to Detections</button>`) + `<button class="btn sm ghost" data-act="bbHunt" data-v="${p.id}">${ico('crosshair', 'sm')}Hunt my evidence</button>` : ''}</div>
      <pre class="bb-code" tabindex="0" aria-label="${esc(B.langs[cur])}"><code>${esc(code)}</code></pre>
      ${cur === 'sigma' && p.ev ? `<p class="bb-proof t3">${ico('check', 'sm')}Proven on: <code>${esc(p.ev[0])}</code></p>` : ''}</section>` : `<p class="t3">None of your stack’s languages has a hunt for this play — change “Your stack” on the play list.</p>`}
    <div class="bb-cols3"><section><h3>When it fires</h3><ol>${(p.triage || []).map(s => `<li>${mark(s)}</li>`).join('')}</ol></section>
      <section><h3>Respond</h3><ol>${(p.respond || []).map(s => `<li>${mark(s)}</li>`).join('')}</ol></section>
      <section><h3>What closes it</h3><ul>${p.fix.map(s => `<li>${mark(s)}</li>`).join('')}</ul></section></div>
    <div class="bb-cols"><section><h3>What else looks like this</h3><p class="t2">${mark(p.fp)}</p></section>${p.validate ? `<section><h3>Prove it works</h3><p class="t2">${mark(p.validate)}</p></section>` : ''}</div>
  </article>`;
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
document.addEventListener('input', ev => { if(ev.target && ev.target.id === 'bbQ'){ clearTimeout(UI.bbT); UI.bbT = setTimeout(() => { UI.bbQ = ev.target.value; UI.bbPlay = null; const p = ev.target.selectionStart; renderMain(); const i = $('bbQ'); if(i){ i.focus(); i.setSelectionRange(p, p); } }, 180); } });
const BB_ACTS = {
  bbTab:(id, v) => { if(v === 'hunt' && UI.bbTab === 'hunt') UI.bbPlay = null; UI.bbTab = v; renderMain(); const m = $('main'); const s = m && m.querySelector('.scroll'); if(s) s.scrollTop = 0; },
  bbToc:(id, v) => { const el = $(v); if(el) el.scrollIntoView({behavior:'smooth', block:'start'}); },
  bbOpenPlay:(id, v) => { UI.bbPlay = v; renderMain(); const sc = document.querySelector('#main .scroll'); if(sc) sc.scrollTop = 0; const h = $('bb-dt'); if(h) h.focus({preventScroll:true}); },
  bbBack:() => { const was = UI.bbPlay; UI.bbPlay = null; renderMain(); const t = was && document.querySelector(`.bb-tile[data-v="${was}"]`); if(t){ t.scrollIntoView({block:'center'}); t.focus({preventScroll:true}); } },
  bbFPlat:(id, v) => { const F = bbFilters(); F.plat.has(v) ? F.plat.delete(v) : F.plat.add(v); renderMain(); },
  bbFSev:(id, v) => { const F = bbFilters(); F.sev.has(v) ? F.sev.delete(v) : F.sev.add(v); renderMain(); },
  bbFSigma:() => { const F = bbFilters(); F.sigma = !F.sigma; renderMain(); },
  bbFClear:() => { UI.bbF = null; renderMain(); },
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
