/* ==========================================================================
   Tradecraft — the investigator's field guide (data: js/data/tradecraft-pack.js)
   A readiness check for the research environment (kept with your workspace),
   then the chapters: threat model, environment, personas, starting an actor
   investigation, pivoting, finding the human, attribution. Points that are done
   in the app open where they are done.
   ========================================================================== */
const TC_GO = {
  'case:infra':['Infrastructure', 'network'], 'case:timeline':['Timeline', 'clock'], 'case:graph':['Graph', 'waypoints'], 'case:questions':['Analysis', 'scale'],
  lab:['Forensics kit', 'file-search'], decoder:['Decoder', 'binary'], certs:['Certificates', 'shield-check'], feeds:['Threat Intel', 'rss'], entities:['Entities', 'fingerprint'], detections:['Detections', 'file-code'], queries:['Queries', 'search'], cloud:['Cloud field guide', 'cloud']};
const tcReady = () => { DB.prefs.tcReady = DB.prefs.tcReady && typeof DB.prefs.tcReady === 'object' ? DB.prefs.tcReady : {}; return DB.prefs.tcReady; };
function tcGoBtn(where){ const g = TC_GO[where]; return g ? `<button class="tc-go" data-act="tcGo" data-v="${esc(where)}">${ico(g[1], 'sm')}${esc(g[0])}${ico('arrow-right', 'sm')}</button>` : ''; }
function viewTradecraft(){
  if(typeof TRADECRAFT === 'undefined'){ if(typeof lazyNeed === 'function') lazyNeed('tc').then(ok => ok && UI.route.area === 'tradecraft' && renderMain()); return `<div class="scroll"><div class="page"><p class="t3">Loading the field guide…</p></div></div>`; }
  const T = TRADECRAFT, R = tcReady(), done = T.ready.filter(x => R[x[0]]).length, q = (UI.tcQ || '').trim().toLowerCase(), words = q.split(/\s+/).filter(Boolean);
  const hit = (...s) => !words.length || words.every(w => s.join(' ').toLowerCase().includes(w));
  const mark = s => { let h = esc(s); for(const w of words) h = h.replace(new RegExp('(' + w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ')', 'gi'), '<mark>$1</mark>'); return h; };
  let shown = 0;
  const chapters = T.chapters.map((c, ci) => {
    const parts = c.parts.map(p => { const pts = p.pts.filter(x => hit(x[0], x[1], p.h, c.title)); shown += pts.length; return pts.length ? `<div class="tc-part"><h3>${esc(p.h)}</h3><ul>${pts.map(x => `<li><b>${mark(x[0])}</b><p>${mark(x[1])}</p>${x[2] ? tcGoBtn(x[2]) : ''}</li>`).join('')}</ul></div>` : ''; }).join('');
    const mx = c.matrix ? c.matrix.filter(r => hit(...r.slice(0, 4))) : []; shown += mx.length;
    const table = mx.length ? `<div class="tc-mx"><table><thead><tr><th>From</th><th>Pivot on</th><th>Where</th><th>How much it says</th></tr></thead><tbody>${mx.map(r => `<tr><td><b>${esc(r[0])}</b></td><td>${mark(r[1])}</td><td>${mark(r[2])}${r[4] ? tcGoBtn(r[4]) : ''}</td><td>${mark(r[3])}</td></tr>`).join('')}</tbody></table></div>` : '';
    if(!parts && !table) return '';
    return `<section class="tc-ch" id="tc-${c.id}"><header><span class="tc-n">${String(ci + 1).padStart(2, '0')}</span><div><h2>${ico(c.icon, 'sm')}${esc(c.title)}</h2><p>${esc(c.lead)}</p></div></header>${table}${parts}</section>`; }).join('');
  return `<div class="scroll"><div class="page tc">
    <header class="tc-hd"><div><span class="tc-ix">Field guide · works offline</span><h1>Tradecraft</h1><p>How to investigate without being seen: the research environment, personas, and how an actor investigation runs — from one indicator to an attribution you can defend.</p></div>
      <div class="search-in tc-q">${ico('search')}<label class="sr" for="tcQ">Search the guide</label><input id="tcQ" class="inp" placeholder="WebRTC, LinkedIn, JARM, PDB, PGP…" value="${esc(UI.tcQ || '')}"></div></header>
    <div class="tc-grid">
      <nav class="tc-toc" aria-label="Chapters"><button data-act="tcJumpId" data-v="opX">${ico('eye', 'sm')}<span>This browser</span></button><button data-act="tcJumpId" data-v="opP">${ico('user', 'sm')}<span>Your personas</span></button>${T.chapters.map((c, i) => `<button data-act="tcJump" data-v="${c.id}">${ico(c.icon, 'sm')}<span>${esc(c.title)}</span></button>`).join('')}</nav>
      <div class="tc-main">
        <section class="tc-ready${done === T.ready.length ? ' all' : ''}"><header><h2>${ico('shield-check', 'sm')}Before you start</h2><span class="tc-rc">${done} of ${T.ready.length}</span><span class="tc-rb" role="img" aria-label="${done} of ${T.ready.length} checked"><i style="width:${Math.round(done / T.ready.length * 100)}%"></i></span></header>
          <p class="t3">Your own check of the environment you are about to work from — kept in this workspace, cleared with one click when you start a new session.</p>
          <ul>${T.ready.map(([id, t, h]) => `<li><label><input type="checkbox" data-tc="${id}"${R[id] ? ' checked' : ''}><span><b>${esc(t)}</b><small>${esc(h)}</small>${typeof opReadyHint === 'function' ? opReadyHint(id) : ''}</span></label></li>`).join('')}</ul>
          ${done ? `<button class="btn sm ghost" data-act="tcReset">${ico('refresh-cw', 'sm')}New session — clear the checks</button>` : ''}</section>
        ${!words.length && typeof opExposureHtml === 'function' ? opExposureHtml() + opPersonasHtml() : ''}
        ${chapters || empty('search', 'Nothing in the guide matches', 'Try another word.')}
        ${words.length && shown ? `<p class="t3 small">${shown} point${shown === 1 ? '' : 's'} match “${esc(UI.tcQ)}”.</p>` : ''}
        <p class="t3 small tc-foot">Playbooks turns the same ground into checklists you can run on a case: <button class="lnk" data-act="tcPb" data-v="pb-opsec-env">Investigation environment</button>, <button class="lnk" data-act="tcPb" data-v="pb-persona">Research persona</button>, <button class="lnk" data-act="tcPb" data-v="pb-apt-seed">Actor investigation from one indicator</button>, <button class="lnk" data-act="tcPb" data-v="pb-operator">Finding the operator</button>, <button class="lnk" data-act="tcPb" data-v="pb-chat-scam">Scammer on Telegram, Discord or WhatsApp</button>, <button class="lnk" data-act="tcPb" data-v="pb-discord">Discord server and user</button>, <button class="lnk" data-act="tcPb" data-v="pb-chat-actor">Threat actor on chat platforms</button>, <button class="lnk" data-act="tcPb" data-v="pb-bot-c2">Bot or webhook found in malware</button>.</p>
        <a class="tc-door" href="#/blackbook">${ico('gem', 'sm')}<span><b>Blackbook</b> Locked</span>${ico('lock', 'sm')}</a>
      </div></div></div></div>`;
}
document.addEventListener('change', ev => { const t = ev.target; if(!t || !t.dataset || !t.dataset.tc) return; const R = tcReady(); if(t.checked) R[t.dataset.tc] = Date.now(); else delete R[t.dataset.tc]; save(); renderMain(); });
document.addEventListener('input', ev => { if(ev.target && ev.target.id === 'tcQ'){ clearTimeout(UI.tcT); UI.tcT = setTimeout(() => { UI.tcQ = ev.target.value; const p = ev.target.selectionStart; renderMain(); const i = $('tcQ'); if(i){ i.focus(); i.setSelectionRange(p, p); } }, 160); } });
const TC_ACTS = {
  tcGo:(id, v) => { if(v.startsWith('case:')){ if(!theCase()) return toast('Open a case first'); return go(caseHash(DB.active, v.slice(5))); } go('#/' + v); },
  tcJumpId:(id, v) => { const el = $(v); if(el) el.scrollIntoView({behavior:'smooth', block:'start'}); },
  tcJump:(id, v) => { const el = $('tc-' + v); if(el) el.scrollIntoView({behavior:'smooth', block:'start'}); },
  tcReset:() => { DB.prefs.tcReady = {}; save(); renderMain(); toast('Checks cleared for a new session'); },
  tcPb:(id, v) => (typeof lazyNeed === 'function' ? lazyNeed('pb') : Promise.resolve()).then(() => { ensurePlaybooks(); UI.pb = v; if(UI.route.area === 'playbooks') renderMain(); else go('#/playbooks'); }),
};
