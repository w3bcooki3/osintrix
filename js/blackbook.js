/* ==========================================================================
   The Blackbook — a hidden part of the Kit (data: js/data/blackbook-pack.js).
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
const BB_TABS = [['hunt', 'Hunt', 'crosshair'], ['apt', 'APT casebook', 'shield-alert'], ['under', 'Underground', 'skull'], ['osint', 'OSINT', 'scan-search']];
const BB_SEV = {low:'Low', medium:'Medium', high:'High', critical:'Critical'};
const BB_GO = {lab:['Forensics kit', 'file-search'], tradecraft:['Tradecraft', 'eye-off'], entities:['Entities', 'fingerprint'], 'case:timeline':['Timeline', 'clock'], 'case:infra':['Infrastructure', 'network'], 'case:questions':['Analysis', 'scale']};
const bbOpen = () => UI.bbOpen || (UI.bbOpen = new Set());
const bbStack = () => { const L = DB.prefs.bbLangs; return Array.isArray(L) && L.length ? L : ['kql', 'spl', 'sigma', 'eql', 'osq', 'cli']; };
function bbUnlock(){ if(!DB.prefs.bb){ DB.prefs.bb = Date.now(); save(); if(typeof renderNav === 'function') renderNav(); return true; } return false; }
function bbGoBtn(where){ const g = BB_GO[where]; return g ? `<button class="tc-go" data-act="bbGo" data-v="${esc(where)}">${ico(g[1], 'sm')}${esc(g[0])}${ico('arrow-right', 'sm')}</button>` : ''; }
function bbTech(id){ const t = typeof ATTACK !== 'undefined' ? ATTACK.tech.find(x => x[0] === id) : null; return `<a class="bb-att" href="https://attack.mitre.org/techniques/${esc(id.replace('.', '/'))}/" target="_blank" rel="noopener noreferrer"${t ? ` title="${esc(t[1])}"` : ''}>${esc(id)}</a>`; }
function bbRuleOf(p){ return (DB.rules || []).find(r => r.bb === p.id); }

function viewBlackbook(){
  if(typeof BLACKBOOK === 'undefined'){ if(typeof lazyNeed === 'function') lazyNeed('bb').then(ok => ok && UI.route.area === 'blackbook' && renderMain()); return `<div class="scroll"><div class="page"><p class="t3">Opening the Blackbook…</p></div></div>`; }
  bbUnlock();
  const B = BLACKBOOK, tab = BB_TABS.some(t => t[0] === UI.bbTab) ? UI.bbTab : 'hunt', q = (UI.bbQ || '').trim().toLowerCase(), words = q.split(/\s+/).filter(Boolean);
  const hit = (...s) => !words.length || words.every(w => s.join(' ').toLowerCase().includes(w));
  const mark = s => { let h = esc(s); for(const w of words) h = h.replace(new RegExp('(' + w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ')', 'gi'), '<mark>$1</mark>'); return h; };
  let body = '', toc = '', shown = 0;
  if(tab === 'hunt'){
    const doc = B.doctrine.filter(d => hit(...d)), mir = B.mirror.filter(m => hit(...m.slice(0, 3)));
    shown += doc.length + mir.length;
    const docH = doc.length ? `<section class="tc-ch" id="bb-doctrine"><header><span class="tc-n">00</span><div><h2>${ico('lightbulb', 'sm')}How a hunter thinks</h2><p>The habits that separate a hunt from a search. Read once; come back when a hunt goes nowhere.</p></div></header>
      <div class="tc-part bb-doc"><ol>${doc.map(([t, b]) => `<li><b>${mark(t)}</b><p>${mark(b)}</p></li>`).join('')}</ol></div></section>` : '';
    const mirH = mir.length ? `<section class="tc-ch" id="bb-mirror"><header><span class="tc-n">01</span><div><h2>${ico('git-compare', 'sm')}Their first checks, your first checks</h2><p>What a penetration tester or bug-bounty hunter looks at first on an organisation — and the defender's mirror of each.</p></div></header>
      <div class="tc-mx"><table><thead><tr><th>They look for</th><th>Why it pays</th><th>Your check</th></tr></thead><tbody>${mir.map(([a, b, c, id]) => `<tr><td><b>${mark(a)}</b></td><td>${mark(b)}</td><td>${mark(c)}<br><button class="lnk" data-act="bbJump" data-v="${esc(id)}">The play ${ico('arrow-right', 'sm')}</button></td></tr>`).join('')}</tbody></table></div></section>` : '';
    const secs = B.sections.map((s, i) => { const ps = B.plays.filter(p => p.sec === s.id && hit(p.t, p.lens, p.sig.join(' '), p.att.join(' '), p.logs, p.fp, p.fix.join(' '), Object.values(p.q).join(' '), s.title)); shown += ps.length;
      return ps.length ? `<section class="tc-ch" id="bb-s-${s.id}"><header><span class="tc-n">${String(i + 2).padStart(2, '0')}</span><div><h2>${ico(s.icon, 'sm')}${esc(s.title)}</h2><p>${esc(s.lead)}</p></div></header><div class="bb-plays">${ps.map(p => bbPlay(p, mark, words.length > 0)).join('')}</div></section>` : ''; }).join('');
    body = docH + mirH + secs;
    toc = `<button data-act="bbToc" data-v="bb-doctrine">${ico('lightbulb', 'sm')}<span>How a hunter thinks</span></button><button data-act="bbToc" data-v="bb-mirror">${ico('git-compare', 'sm')}<span>Their checks, yours</span></button>` + B.sections.map(s => `<button data-act="bbToc" data-v="bb-s-${s.id}">${ico(s.icon, 'sm')}<span>${esc(s.title)}</span><small>${B.plays.filter(p => p.sec === s.id).length}</small></button>`).join('');
  } else if(tab === 'apt'){
    const L = B.apt.filter(a => hit(a.name, a.who, a.when, a.what, a.tells.join(' '), a.lesson)); shown += L.length;
    body = L.map(a => `<article class="bb-case" id="bb-apt-${a.id}"><header><h2>${mark(a.name)}</h2><p class="t3">${mark(a.who)} · ${mark(a.when)}</p></header>
      <p>${mark(a.what)}</p><h3>The tells</h3><ul>${a.tells.map(t => `<li>${mark(t)}</li>`).join('')}</ul>
      <h3>Plays that catch it</h3><div class="wrap">${a.plays.map(id => { const p = B.plays.find(x => x.id === id); return p ? `<button class="chip" data-act="bbJump" data-v="${esc(id)}">${esc(p.t)}</button>` : ''; }).join('')}</div>
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
  const stack = bbStack(), counts = {plays:B.plays.length, hunts:B.plays.reduce((n, p) => n + Object.keys(p.q).length, 0)};
  return `<div class="scroll"><div class="page tc bb">
    <header class="tc-hd bb-hd"><div><span class="tc-ix">${ico('gem', 'sm')}Hidden · works offline</span><h1>Blackbook</h1><p>Think like the intruder, hunt like the defender: ${counts.plays} plays across the attack chain with ${counts.hunts} hunts, the APT casebook, the cybercrime underground, and the OSINT that moves an investigation. Detection and investigation only — no exploit code.</p></div>
      <div class="search-in tc-q">${ico('search')}<label class="sr" for="bbQ">Search the Blackbook</label><input id="bbQ" class="inp" placeholder="Kerberoast, rclone, Telegram, favicon…" value="${esc(UI.bbQ || '')}"></div></header>
    <nav class="tabs bb-tabs" role="tablist" aria-label="Parts of the Blackbook">${BB_TABS.map(([k, l, i]) => `<button role="tab" aria-selected="${k === tab}" class="${k === tab ? 'on' : ''}" data-act="bbTab" data-v="${k}">${ico(i, 'sm')}${l}</button>`).join('')}</nav>
    ${tab === 'hunt' ? `<div class="bb-stack" role="group" aria-label="Query languages to show"><span class="t3">Your stack</span>${Object.entries(B.langs).map(([k, l]) => `<button class="chip${stack.includes(k) ? ' on' : ''}" aria-pressed="${stack.includes(k)}" data-act="bbStack" data-v="${k}" title="${esc(l)}">${esc(l.split(' — ')[0])}</button>`).join('')}</div>` : ''}
    <div class="tc-grid"><nav class="tc-toc" aria-label="Contents">${toc}</nav>
      <div class="tc-main">${body || empty('search', 'Nothing in the Blackbook matches', 'Try another word.')}${words.length && shown ? `<p class="t3 small">${shown} match${shown === 1 ? '' : 'es'} for “${esc(UI.bbQ)}”.</p>` : ''}</div></div></div></div>`;
}

function bbPlay(p, mark, searching){
  const open = bbOpen().has(p.id) || (searching && UI.bbQ && UI.bbQ.trim().length > 2), stack = bbStack();
  const langs = Object.keys(p.q).filter(k => stack.includes(k)), cur = langs.includes((UI.bbLang || {})[p.id]) ? UI.bbLang[p.id] : langs[0], rule = bbRuleOf(p);
  const head = `<button class="bb-ph" data-act="bbPlay" data-v="${p.id}" aria-expanded="${open}" aria-controls="bbp-${p.id}"><span class="bb-sev s-${p.sev}">${BB_SEV[p.sev]}</span><b>${mark(p.t)}</b><span class="bb-ids">${p.att.map(esc).join(' · ')}</span>${ico('chevron-down', 'sm')}</button>`;
  if(!open) return `<article class="bb-play" id="bb-${p.id}">${head}</article>`;
  const code = cur ? p.q[cur] : '';
  return `<article class="bb-play open" id="bb-${p.id}">${head}<div class="bb-pb" id="bbp-${p.id}">
    <div class="bb-cols"><div><h4>How an operator sees it</h4><p>${mark(p.lens)}</p></div>
      <div><h4>What it leaves</h4><ul>${p.sig.map(s => `<li>${mark(s)}</li>`).join('')}</ul><h4>Logs you need</h4><p class="t2">${mark(p.logs)}</p><p class="bb-tech">${p.att.map(bbTech).join(' ')}</p></div></div>
    ${langs.length ? `<div class="bb-q"><div class="bb-qt"><div class="bb-qtabs" role="tablist" aria-label="Hunts for ${esc(p.t)}">${langs.map(k => `<button role="tab" aria-selected="${k === cur}" class="${k === cur ? 'on' : ''}" data-act="bbLang" data-id="${p.id}" data-v="${k}">${esc(BLACKBOOK.langs[k].split(' — ')[0])}</button>`).join('')}</div>
        <span class="sp"></span><button class="btn sm ghost" data-act="bbCopy" data-id="${p.id}" data-v="${cur}">${ico('copy', 'sm')}Copy</button>
        ${cur === 'sigma' ? (rule ? `<button class="btn sm ghost" data-act="bbOpenRule" data-v="${p.id}">${ico('file-code', 'sm')}In your Detections</button>` : `<button class="btn sm ghost" data-act="bbRule" data-v="${p.id}">${ico('plus', 'sm')}Add to Detections</button>`) + `<button class="btn sm ghost" data-act="bbHunt" data-v="${p.id}">${ico('crosshair', 'sm')}Hunt my evidence</button>` : ''}</div>
      <pre class="bb-code" tabindex="0" aria-label="${esc(BLACKBOOK.langs[cur])}"><code>${esc(code)}</code></pre>
      ${cur === 'sigma' && p.ev ? `<p class="bb-proof t3">${ico('check', 'sm')}Proven on: <code>${esc(p.ev[0])}</code></p>` : ''}</div>` : `<p class="t3">None of your stack's languages has a hunt for this play — add one under “Your stack”.</p>`}
    <div class="bb-cols"><div><h4>What else looks like this</h4><p class="t2">${mark(p.fp)}</p></div><div><h4>What closes it</h4><ul>${p.fix.map(s => `<li>${mark(s)}</li>`).join('')}</ul></div></div>
  </div></article>`;
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
document.addEventListener('input', ev => { if(ev.target && ev.target.id === 'bbQ'){ clearTimeout(UI.bbT); UI.bbT = setTimeout(() => { UI.bbQ = ev.target.value; const p = ev.target.selectionStart; renderMain(); const i = $('bbQ'); if(i){ i.focus(); i.setSelectionRange(p, p); } }, 180); } });
const BB_ACTS = {
  bbTab:(id, v) => { UI.bbTab = v; renderMain(); const m = $('main'); const s = m && m.querySelector('.scroll'); if(s) s.scrollTop = 0; },
  bbToc:(id, v) => { const el = $(v); if(el) el.scrollIntoView({behavior:'smooth', block:'start'}); },
  bbPlay:(id, v) => { const o = bbOpen(); if(o.has(v)) o.delete(v); else o.add(v); renderMain(); const b = document.querySelector(`[data-act=bbPlay][data-v="${v}"]`); if(b) b.focus(); },
  bbJump:(id, v) => { UI.bbTab = 'hunt'; UI.bbQ = ''; bbOpen().add(v); renderMain(); requestAnimationFrame(() => { const el = $('bb-' + v); if(el){ el.scrollIntoView({block:'start'}); const b = el.querySelector('.bb-ph'); if(b) b.focus(); } }); },
  bbLang:(id, v, el) => { const pid = el && el.dataset.id; if(!pid) return; UI.bbLang = UI.bbLang || {}; UI.bbLang[pid] = v; renderMain(); const b = document.querySelector(`[data-act=bbLang][data-id="${pid}"][data-v="${v}"]`); if(b) b.focus(); },
  bbStack:(id, v) => { let L = bbStack().slice(); L = L.includes(v) ? L.filter(x => x !== v) : L.concat(v); if(!L.length) return toast('Keep at least one language'); DB.prefs.bbLangs = L; save(); renderMain(); },
  bbCopy:(id, v, el) => { const p = BLACKBOOK.plays.find(x => x.id === (el && el.dataset.id)); if(p && p.q[v]) copyText(p.q[v], 'Copied the ' + BLACKBOOK.langs[v].split(' — ')[0] + ' hunt'); },
  bbRule:(id, v) => { bbAddRule(v); renderMain(); },
  bbOpenRule:(id, v) => { const r = bbRuleOf({id:v}); if(r){ UI.rule = r.id; UI.ropen = true; go('#/detections'); } },
  bbHunt:(id, v) => { const r = bbAddRule(v, true); if(!r) return; let h = huntList().find(x => x.kind === 'rule' && x.ruleId === r.id);
    if(!h){ h = {id:uid('h'), name:nextName('Blackbook — ' + r.title, huntList().map(x => x.name)).slice(0, 120), kind:'rule', ruleId:r.id, created:Date.now(), lastAt:Date.now(), seen:[]}; DB.hunts = [...huntList(), h]; mutate('saved hunt ' + h.name); }
    const res = huntRun(h), n = res.matches.length; renderMain();
    toast(n ? `${n} event${n === 1 ? '' : 's'} in your evidence match — the hunt keeps watching` : 'Nothing in your evidence matches yet — the hunt keeps watching new evidence', 'Open', () => { UI.dview = 'hunts'; go('#/detections'); }); },
  bbGo:(id, v) => { if(v.startsWith('case:')){ if(!theCase()) return toast('Open a case first'); return go(caseHash(DB.active, v.slice(5))); } go('#/' + v); },
};
