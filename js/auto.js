/* ==========================================================================
   Automations — "when this happens in a case, do that", run in the browser.
   Rules fire while OSINTrix is open (nothing runs when the tab is closed)
   a moment after something changes. Each rule acts once per indicator,
   record or case, so it never loops or repeats itself. Online lookups use
   only the sources you switched on; every other action stays in the browser.
   Everything an automation adds is marked "Automation", and every run is
   written to the automation log.
     when  · a new indicator of chosen kinds appears in a case
           · evidence arrives tagged with, or containing, some text
           · an indicator is judged malicious / suspicious
     then  · check it against the indicator store (and mark it suspicious if found)
           · look it up online · watch it · add it to the vault
           · ask a question · set a verdict · run a playbook (once per case)
   ========================================================================== */
const AUTO = {busy:false, t:0};
const AUTO_KINDS = [['ip', 'IP addresses', ['ipv4', 'ipv6']], ['domain', 'Domains', ['domain']], ['url', 'URLs', ['url']], ['hash', 'File hashes', ['md5', 'sha1', 'sha256', 'sha512']], ['email', 'Email addresses', ['email']], ['cve', 'CVEs', ['cve']], ['handle', 'Usernames and profiles', ['handle', 'social']], ['wallet', 'Crypto wallets', ['btc', 'eth', 'xmr', 'ltc', 'trx', 'doge']], ['phone', 'Phone numbers', ['phone']]];
const AUTO_DO = {store:'Check it against the indicator store', lookup:'Look it up with my switched-on sources', watch:'Watch it', vault:'Add it to the vault', question:'Ask a question', verdict:'Set a verdict', playbook:'Run a playbook on the case'};
const AUTO_TPL = [
  {id:'t-store', name:'Check new indicators against the indicator store', when:{ev:'ind', kinds:['ip', 'domain', 'url', 'hash']}, then:[{a:'store'}], why:'Offline. Anything your feeds or imports already know about is marked suspicious and tagged with the threat.'},
  {id:'t-look', name:'Look up every new IP, domain and hash', when:{ev:'ind', kinds:['ip', 'domain', 'hash']}, then:[{a:'store'}, {a:'lookup'}], why:'Sends each new public indicator to the lookup sources you switched on.'},
  {id:'t-watch', name:'Watch everything judged malicious', when:{ev:'verdict', verdict:'malicious'}, then:[{a:'watch'}, {a:'vault', prio:'high'}], why:'You hear when it shows up again — in new evidence, news or another case.'},
  {id:'t-email', name:'Ask who is behind new email addresses', when:{ev:'ind', kinds:['email']}, then:[{a:'vault', prio:'medium'}, {a:'question', text:'Who is behind {value}? Check breaches, registrations and reuse.'}], why:'Adds each address to the vault with a question to answer.'},
  {id:'t-phish', name:'Start the phishing checklist when evidence mentions phishing', when:{ev:'tag', text:'phish'}, then:[{a:'playbook', id:'pb-phish'}], why:'Adds the phishing playbook\'s steps as questions, once per case.'},
];
const autoKinds = keys => new Set(AUTO_KINDS.filter(x => (keys || []).includes(x[0])).flatMap(x => x[2]));
function autoEnsure(){ if(!Array.isArray(DB.autos)) DB.autos = []; if(!DB.autoDone || typeof DB.autoDone !== 'object') DB.autoDone = {}; if(!Array.isArray(DB.autoLog)) DB.autoLog = []; }
function autoSay(R){
  const ONE = {ip:'IP address', domain:'domain', url:'URL', hash:'file hash', email:'email address', cve:'CVE', handle:'username', wallet:'crypto wallet', phone:'phone number'};
  const w = R.when || {}, k = (w.kinds || []).map(x => ONE[x]).filter(Boolean), list = k.length > 1 ? k.slice(0, -1).join(', ') + ' or ' + k[k.length - 1] : k[0] || 'indicator';
  const when = w.ev === 'ind' ? 'a new ' + list + ' appears' : w.ev === 'tag' ? 'evidence mentions “' + (w.text || '') + '”' : 'an indicator is judged ' + (w.verdict || 'malicious');
  const where = R.scope && R.scope !== 'all' ? ' in ' + ((theCase(R.scope) || {}).code || 'a deleted case') : ' in any of my cases';
  return 'When ' + when + where + ' → ' + (R.then || []).map(t => t.a === 'question' ? 'ask “' + t.text + '”' : t.a === 'verdict' ? 'mark it ' + t.v : t.a === 'playbook' ? 'run “' + ((DB.playbooks || []).find(p => p.id === t.id) || {name:'a playbook'}).name + '”' : t.a === 'vault' ? 'add it to the vault' : AUTO_DO[t.a].replace(/^\w/, ch => ch.toLowerCase())).join(', ');
}
/* the cases a rule looks at: one case, or all of the user's own (never the demo cases) */
const autoCases = R => R.scope && R.scope !== 'all' ? [theCase(R.scope)].filter(Boolean) : DB.cases.filter(c => !c.sample && c.status !== 'closed');
/* what would fire now: [{R, c, key, k, v, rec}] — each not done before */
function autoPending(R, all){
  const done = DB.autoDone[R.id] || {}, out = [], w = R.when || {};
  for(const c of autoCases(R)){ const D = derive(c.id);
    if(w.ev === 'ind'){ const K = autoKinds(w.kinds); for(const [key, x] of D.ents){ if(!K.has(x.k) || done[c.id + '|' + key]) continue; if((x.k === 'ipv4' || x.k === 'ipv6') && !/^Public/.test(E.ipClass(x.v))) continue; out.push({c, key, k:x.k, v:x.v}); } }
    else if(w.ev === 'tag'){ const t = String(w.text || '').toLowerCase(); if(!t) continue; for(const r of D.recs){ if(r.type === 'lead' || done[c.id + '|r:' + r.id]) continue; if((r.tags || []).some(x => x.toLowerCase().includes(t)) || (r.title + ' ' + r.body).toLowerCase().includes(t)) out.push({c, key:'r:' + r.id, rec:r}); } }
    else if(w.ev === 'verdict'){ for(const [key, x] of D.ents){ if(done[c.id + '|' + key] || verdictOf(key) !== (w.verdict || 'malicious')) continue; out.push({c, key, k:x.k, v:x.v}); } }
    if(!all && out.length > 400) break; }
  return out;
}
function autoLog(R, c, what){ DB.autoLog.unshift({at:Date.now(), rule:R.id, name:R.name, c:c.id, what:String(what).slice(0, 200)}); DB.autoLog.length = Math.min(DB.autoLog.length, 300); }
/* one pass over every rule that is on */
function autoTick(){
  autoEnsure(); if(AUTO.busy || !DB.autos.some(R => R.on)) return 0; AUTO.busy = true; let acts = 0, look = false;
  try{
    for(const R of DB.autos.filter(R => R.on)){
      const P = autoPending(R).slice(0, 200), done = DB.autoDone[R.id] = DB.autoDone[R.id] || {};
      for(const x of P){ done[x.c.id + '|' + x.key] = Date.now(); let did = false;
        for(const t of R.then || []){ const r = autoDo(R, t, x); if(r){ acts++; did = true; autoLog(R, x.c, r); if(t.a === 'lookup') look = true; } }
        if(did){ R.runs = (R.runs || 0) + 1; R.last = Date.now(); } }
      /* keep the memory of what was done from growing without end */
      const ks = Object.keys(done); if(ks.length > 20000) for(const k of ks.slice(0, ks.length - 20000)) delete done[k];
    }
  } finally { AUTO.busy = false; }
  if(acts){ mutate('automations: ' + acts + ' action' + (acts > 1 ? 's' : '')); hashRecords(); if(look && typeof cpDrain === 'function') cpDrain(); if(UI.route.area !== 'playbooks') renderAll(); else renderMain(); }
  return acts;
}
function autoDo(R, t, x){
  const c = x.c, fill = s => String(s || '').replace(/\{value\}/g, x.v || '').replace(/\{kind\}/g, x.k ? (E.LABEL[x.k] || x.k) : '').replace(/\{case\}/g, c.code).replace(/\{title\}/g, x.rec ? x.rec.title : '');
  switch(t.a){
    case 'store': { if(!x.k || typeof CTI === 'undefined' || !CTI.iocIx) return ''; const i = CTI.iocIx.get(x.key); if(!i || !iocLive(i)) return '';
      if(!DB.verdicts[x.key]) DB.verdicts[x.key] = 'suspicious'; return x.v + ' is in the indicator store' + (i.threat ? ' (' + i.threat + ')' : '') + ' — marked suspicious'; }
    case 'lookup': { if(!x.k || typeof lkFor !== 'function' || !lkFor(x.k).some(lkOn)) return ''; if(CP.q.some(q => q.key === x.key)) return '';
      CP.q.push({key:x.key, k:x.k, v:x.v, caseId:c.id}); CP.q = CP.q.slice(0, 300); return 'looking up ' + x.v; }
    case 'watch': { if(!x.k || (DB.watch && DB.watch[x.key])) return ''; DB.watch = DB.watch || {}; DB.watch[x.key] = {at:Date.now()}; return 'watching ' + x.v; }
    case 'vault': { const type = x.k && KIND_TO_TYPE[x.k]; if(!type || DB.entries.some(e => e.caseId === c.id && entryKey(e) === x.key)) return '';
      const T = TYPES[type], src = DB.records.find(r => r.caseId === c.id && r.ents.some(e => entKey(e) === x.key));
      DB.entries.push({id:uid('v'), caseId:c.id, type, fields:{[T.fields[0][0]]:x.v}, priority:['low', 'medium', 'high', 'critical'].includes(t.prio) ? t.prio : 'medium', starred:false, tags:['automation'], notes:'Added by the automation “' + R.name + '”.', src:src ? src.id : '', created:Date.now(), pos:null});
      return 'added ' + x.v + ' to the vault'; }
    case 'question': { const q = fill(t.text || 'What is {value}?').slice(0, 300); if(DB.records.some(r => r.caseId === c.id && r.type === 'lead' && r.title.toLowerCase() === q.toLowerCase())) return '';
      DB.records.push({id:uid('q'), caseId:c.id, type:'lead', title:q, body:'', tsRaw:'', ts:null, source:'automation', host:'', tags:['automation'], ents:E.extract(q), answer:'', addedBy:'Automation', addedAt:Date.now(), hash:''}); return 'asked “' + q + '”'; }
    case 'verdict': { if(!x.k || DB.verdicts[x.key] || !['malicious', 'suspicious', 'benign'].includes(t.v)) return ''; DB.verdicts[x.key] = t.v; return 'marked ' + x.v + ' ' + t.v; }
    case 'playbook': { const done = DB.autoDone[R.id], k = c.id + '|pb:' + t.id; if(done[k]) return ''; done[k] = Date.now(); const p = (DB.playbooks || []).find(z => z.id === t.id); if(!p) return '';
      const have = new Set(DB.records.filter(r => r.caseId === c.id && r.type === 'lead').map(r => r.title.toLowerCase())); let n = 0;
      for(const s of p.steps){ if(have.has(s.t.toLowerCase())) continue; DB.records.push({id:uid('q'), caseId:c.id, type:'lead', title:s.t, body:s.h || '', tsRaw:'', ts:null, source:'playbook', host:'', tags:[pbTag(p.id), 'automation'], ents:E.extract(s.t), answer:'', addedBy:'Automation', addedAt:Date.now(), hash:''}); n++; }
      return n ? 'ran the playbook “' + p.name + '” (' + n + ' steps)' : ''; }
  }
  return '';
}
function autoSchedule(){ clearTimeout(AUTO.t); AUTO.t = setTimeout(() => { try{ autoTick(); }catch(e){ console.warn('automation', e); } }, 900); }

/* ---------- the Automations view (Playbooks → Automations) ---------- */
function autoView(){
  autoEnsure(); const used = new Set(DB.autos.map(R => R.tpl).filter(Boolean)), log = DB.autoLog.slice(0, 40), lookOn = typeof LK_PROVIDERS !== 'undefined' && LK_PROVIDERS.some(lkOn);
  const rule = R => `<div class="au-r${R.on ? '' : ' off'}"><label class="sw" title="${R.on ? 'On' : 'Off'}"><input type="checkbox" data-act="auOn" data-id="${R.id}" ${R.on ? 'checked' : ''} aria-label="${esc(R.name)} on"><span></span></label>
      <div class="au-t"><b>${esc(R.name)}</b><small>${esc(autoSay(R))}</small><small class="t3">${R.runs ? 'Acted ' + R.runs + ' time' + (R.runs > 1 ? 's' : '') + (R.last ? ' · last ' + esc(E.fmtAgo(Date.now() - R.last)) : '') : 'Has not acted yet'}${(R.then || []).some(t => t.a === 'lookup') && !lookOn ? ' · <span class="ti-x">no lookup sources are switched on</span>' : ''}</small></div>
      <button class="btn xs" data-act="auEdit" data-id="${R.id}">Edit</button><button class="iconbtn" data-act="auDel" data-id="${R.id}" aria-label="Delete ${esc(R.name)}">${ico('trash-2','sm')}</button></div>`;
  return `<div class="page wide au">
    <section class="card au-intro"><div><h2>${ico('workflow','sm')} Automations</h2><p class="t2">Rules that do the routine work for you. They run in this browser while OSINTrix is open — nothing runs when the tab is closed, and only lookups go online, to the sources you switched on. Each rule acts once per indicator, record or case.</p></div><button class="btn primary" data-act="auNew">${ico('plus','sm')}New automation</button></section>
    ${DB.autos.length ? `<section class="card au-list">${DB.autos.map(rule).join('')}</section>` : ''}
    ${AUTO_TPL.some(T => !used.has(T.id)) ? `<h3 class="au-h">Ready-made</h3><div class="au-tpl">${AUTO_TPL.filter(T => !used.has(T.id)).map(T => `<article class="card"><b>${esc(T.name)}</b><p class="t2">${esc(T.why)}</p><small class="t3">${esc(autoSay(T))}</small><button class="btn sm" data-act="auTpl" data-id="${T.id}">${ico('plus','sm')}Add</button></article>`).join('')}</div>` : ''}
    <h3 class="au-h">What they did</h3>${log.length ? `<section class="card au-log"><ul>${log.map(l => `<li><span class="t3 mono">${esc(E.fmtFull(l.at, tz()).slice(5, 16))}</span><b>${esc((theCase(l.c) || {}).code || '—')}</b><span>${esc(l.what)}</span><small class="t3">${esc(l.name)}</small></li>`).join('')}</ul></section>` : '<p class="t3">Nothing yet. Rules act a moment after evidence arrives.</p>'}
  </div>`;
}
function autoDlg(R){
  autoEnsure(); const r = R ? JSON.parse(JSON.stringify(R)) : {id:'', name:'', on:true, when:{ev:'ind', kinds:['ip', 'domain']}, scope:'all', then:[{a:'store'}]}, w = r.when, has = a => (r.then || []).find(t => t.a === a);
  const cases = DB.cases.filter(c => !c.sample), pbs = DB.playbooks || [];
  openDlg(dhead(R ? 'Edit automation' : 'New automation') + `<form data-form="auto" data-id="${esc(r.id)}"><div class="in au-f">
    <div class="field"><label for="auName">Name</label><input id="auName" value="${esc(r.name)}" placeholder="e.g. Check new domains" required maxlength="120"></div>
    <fieldset><legend>When</legend>
      <label class="au-o"><input type="radio" name="auEv" value="ind" ${w.ev === 'ind' ? 'checked' : ''}> A new indicator appears</label>
      <div class="au-kinds">${AUTO_KINDS.map(([k, l]) => `<label><input type="checkbox" name="auK" value="${k}" ${(w.kinds || []).includes(k) ? 'checked' : ''}> ${l}</label>`).join('')}</div>
      <label class="au-o"><input type="radio" name="auEv" value="tag" ${w.ev === 'tag' ? 'checked' : ''}> Evidence is tagged with, or mentions <input id="auText" class="inp" value="${esc(w.text || '')}" placeholder="phishing" maxlength="80" aria-label="Text to look for"></label>
      <label class="au-o"><input type="radio" name="auEv" value="verdict" ${w.ev === 'verdict' ? 'checked' : ''}> An indicator is judged <select id="auVer" aria-label="Verdict">${['malicious', 'suspicious'].map(v => `<option${w.verdict === v ? ' selected' : ''}>${v}</option>`).join('')}</select></label>
    </fieldset>
    <div class="field"><label for="auScope">In</label><select id="auScope"><option value="all">Any of my cases (not the demo cases, not closed ones)</option>${cases.map(c => `<option value="${c.id}"${r.scope === c.id ? ' selected' : ''}>${esc(c.code + ' · ' + c.name)}</option>`).join('')}</select></div>
    <fieldset><legend>Then</legend>
      ${['store', 'lookup', 'watch'].map(a => `<label class="au-o"><input type="checkbox" name="auDo" value="${a}" ${has(a) ? 'checked' : ''}> ${AUTO_DO[a]}</label>`).join('')}
      <label class="au-o"><input type="checkbox" name="auDo" value="vault" ${has('vault') ? 'checked' : ''}> Add it to the vault with priority <select id="auPrio" aria-label="Priority">${['low', 'medium', 'high', 'critical'].map(p => `<option${((has('vault') || {}).prio || 'medium') === p ? ' selected' : ''}>${p}</option>`).join('')}</select></label>
      <label class="au-o"><input type="checkbox" name="auDo" value="question" ${has('question') ? 'checked' : ''}> Ask <input id="auQ" class="inp" value="${esc((has('question') || {}).text || 'Who is behind {value}?')}" maxlength="200" aria-label="Question"></label>
      <label class="au-o"><input type="checkbox" name="auDo" value="verdict" ${has('verdict') ? 'checked' : ''}> Mark it <select id="auV" aria-label="Verdict to set">${['suspicious', 'malicious', 'benign'].map(v => `<option${(has('verdict') || {}).v === v ? ' selected' : ''}>${v}</option>`).join('')}</select> <span class="t3">if it has no verdict</span></label>
      <label class="au-o"><input type="checkbox" name="auDo" value="playbook" ${has('playbook') ? 'checked' : ''}> Run the playbook <select id="auPb" aria-label="Playbook">${pbs.map(p => `<option value="${p.id}"${(has('playbook') || {}).id === p.id ? ' selected' : ''}>${esc(p.name)}</option>`).join('')}</select></label>
      <p class="t3 small">In questions, {value} is the indicator, {kind} its kind, {title} the evidence title and {case} the case code.</p>
    </fieldset>
    ${R ? '' : `<label class="au-o"><input type="checkbox" id="auPast"> Also act on what is already in the cases <span class="t3">(otherwise only on what arrives from now on)</span></label>`}
    </div><footer><button class="btn" type="button" data-act="dclose">Cancel</button><button class="btn primary" type="submit">${R ? 'Save' : 'Create'}</button></footer></form>`);
}
function autoSave(f){
  autoEnsure(); const name = $('auName').value.trim().slice(0, 120); if(!name) return fieldErr('auName', 'Give the automation a name.');
  const ev = (f.querySelector('[name=auEv]:checked') || {}).value || 'ind', kinds = [...f.querySelectorAll('[name=auK]:checked')].map(x => x.value), text = $('auText').value.trim().slice(0, 80);
  if(ev === 'ind' && !kinds.length) return toast('Pick at least one kind of indicator');
  if(ev === 'tag' && !text) return fieldErr('auText', 'Say what the evidence should mention.');
  const dos = [...f.querySelectorAll('[name=auDo]:checked')].map(x => x.value); if(!dos.length) return toast('Pick at least one thing to do');
  const then = dos.map(a => a === 'vault' ? {a, prio:$('auPrio').value} : a === 'question' ? {a, text:$('auQ').value.trim().slice(0, 200) || 'What is {value}?'} : a === 'verdict' ? {a, v:$('auV').value} : a === 'playbook' ? {a, id:$('auPb').value} : {a});
  if(ev === 'tag' && then.some(t => ['store', 'lookup', 'watch', 'vault', 'verdict'].includes(t.a))) return toast('For evidence, the actions are: ask a question or run a playbook');
  const old = DB.autos.find(R => R.id === f.dataset.id), R = old || {id:uid('au'), on:true, runs:0, made:Date.now()};
  Object.assign(R, {name, when:{ev, kinds, text, verdict:$('auVer').value}, scope:$('auScope').value, then});
  if(!old){ DB.autos.push(R); if(!($('auPast') && $('auPast').checked)) autoBaseline(R); }
  mutate((old ? 'edited' : 'created') + ' automation ' + name); closeDlg(); renderMain(); toast(old ? 'Saved' : 'Automation on — it acts on what arrives from now on'); autoSchedule();
}
/* "only from now on": remember everything that is already there as done */
function autoBaseline(R){ const done = DB.autoDone[R.id] = DB.autoDone[R.id] || {}; for(const x of autoPending(R, true)) done[x.c.id + '|' + x.key] = Date.now(); if((R.then || []).some(t => t.a === 'playbook')) for(const c of autoCases(R)) for(const t of R.then) if(t.a === 'playbook') done[c.id + '|pb:' + t.id] = 0; }
const AU_ACTS = {
  pbTab:(id, v) => { UI.pbTab = v; renderMain(); },
  auNew:() => autoDlg(null), auEdit:id => autoDlg(DB.autos.find(R => R.id === id)),
  auOn:(id, v, t) => { const R = DB.autos.find(x => x.id === id); if(!R) return; R.on = t.checked; mutate((R.on ? 'switched on ' : 'paused ') + 'automation ' + R.name); renderMain(); if(R.on) autoSchedule(); },
  auDel:id => { const R = DB.autos.find(x => x.id === id); if(!R) return; DB.autos = DB.autos.filter(x => x !== R); const done = (DB.autoDone || {})[R.id]; if(DB.autoDone) delete DB.autoDone[R.id]; const tx = trashPut('auto', R.name, {a:R, done}); mutate('deleted automation ' + R.name); renderMain();
    toast('Automation deleted — it is in the trash', 'Undo', () => { trashUndo(tx); DB.autos.push(R); if(done) DB.autoDone[R.id] = done; mutate('restored automation ' + R.name); renderMain(); }); },
  auTpl:id => { const T = AUTO_TPL.find(x => x.id === id); if(!T) return; autoEnsure(); const R = {id:uid('au'), tpl:T.id, name:T.name, on:true, when:JSON.parse(JSON.stringify(T.when)), scope:'all', then:JSON.parse(JSON.stringify(T.then)), runs:0, made:Date.now()};
    if(R.then.some(t => t.a === 'playbook') && !(DB.playbooks || []).some(p => p.id === R.then.find(t => t.a === 'playbook').id)){ const p = (DB.playbooks || []).find(p => /phish/i.test(p.name)); if(p) R.then.find(t => t.a === 'playbook').id = p.id; }
    DB.autos.push(R); autoBaseline(R); mutate('added automation ' + R.name); renderMain(); toast('“' + R.name + '” is on — it acts on what arrives from now on'); },
};
