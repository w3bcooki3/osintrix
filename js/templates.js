/* ==========================================================================
   Case templates — start a case set up for the kind of job it is.
   A template brings the playbooks that job needs (their steps become the
   case's open questions; any can be left out), a few questions of its own, a
   note on what the scope should say, a colour and icon, and the tab the case
   opens on. Your own templates are made from a case you have shaped: its
   questions (never their answers), the playbooks run on it, its icon, colour
   and the scope's wording. No evidence, entries or notes go into a template.
   ========================================================================== */
const CT_BUILTIN = [
  {id:'blank', name:'Blank case', icon:'briefcase', color:'#5470f5', tab:'overview', desc:'Nothing set up: start from scratch.', playbooks:[], questions:[], scope:''},
  {id:'story', name:'Story', icon:'newspaper', color:'#d6336c', tab:'story', desc:'Journalism: claims and what backs each one, protected sources, right of reply, archived pages.',
    playbooks:['pb-opsec-env', 'pb-image-provenance'], scope:'What the story is about, who commissioned it, and what you will and will not publish.',
    questions:['What is the central claim of the story, in one sentence?', 'What would prove it wrong, and have you looked for that?', 'Who is it about, and when will they be asked for comment?', 'Which sources need protecting, and how do you reach them safely?']},
  {id:'person', name:'Person profile', icon:'user-search', color:'#8b5cf6', tab:'questions', desc:'A documented, proportionate profile of a named person.',
    playbooks:['pb-subject-profile', 'pb-email-investigation', 'pb-phone-number', 'pb-opsec-env'], scope:'Who asked for the profile, the lawful basis, and what is out of bounds (family, health, …).',
    questions:['Why is this profile needed, and is it proportionate?']},
  {id:'company', name:'Company due diligence', icon:'building-2', color:'#0ea5a4', tab:'questions', desc:'Who owns and runs a company, and whether it is what it says it is.',
    playbooks:['pb-company-dd', 'pb-site-attribution'], scope:'The company, the decision this supports, and the date the answer is needed.',
    questions:['Who are the ultimate beneficial owners?', 'Are there sanctions, enforcement actions or insolvency records?']},
  {id:'phishing', name:'Phishing incident', icon:'mail', color:'#e8590c', tab:'timeline', desc:'From a reported email to scope, clicks and blocked indicators.',
    playbooks:['pb-phish', 'pb-aitm'], scope:'The reported message, who reported it and when, and the systems in scope.', questions:['Who received it, and did anyone click or enter credentials?']},
  {id:'incident', name:'Incident response', icon:'shield-alert', color:'#e5484d', tab:'timeline', desc:'The first hour, then scope, containment and lessons learned.',
    playbooks:['pb-ir1h', 'pb-containment', 'pb-post-incident'], scope:'Affected systems, who declared the incident, and who must be told.', questions:['What is the first known malicious event, and on which host?', 'Is the attacker still active?']},
  {id:'fraud', name:'Fraud or scam', icon:'bitcoin', color:'#e0a800', tab:'questions', desc:'Trace the money, the accounts and the infrastructure behind a scam.',
    playbooks:['pb-chat-scam', 'pb-crypto', 'pb-scam-takedown'], scope:'The victim or reporter, the loss, and whether the police or a bank are involved.', questions:['How much was lost, when, and through which payment method?', 'Is any money still recoverable or frozen?']},
  {id:'actor', name:'Threat actor', icon:'skull', color:'#64748b', tab:'graph', desc:'From one indicator to the infrastructure and the operator behind it.',
    playbooks:['pb-apt-seed', 'pb-actor-profile', 'pb-operator'], scope:'The starting indicator, who asked, and how far attribution should go.', questions:['What is the starting indicator, and how confident is it?']},
  {id:'missing', name:'Missing person', icon:'map-pin', color:'#2f9e44', tab:'map', desc:'Open-source support for a search led by the police or a search team.',
    playbooks:['pb-missing-person', 'pb-geo'], scope:'Who leads the search, how findings are passed to them, and what must not be published.',
    questions:['When and where was the person last seen?', 'Who is the contact at the search team, and how are leads handed over?']},
];
const ctList = () => [...CT_BUILTIN, ...(DB.caseTemplates || []).map(t => ({...t, own:true}))];
const ctGet = id => ctList().find(t => t.id === id) || CT_BUILTIN[0];
const ctPb = id => (DB.playbooks || []).find(p => p.id === id) || (typeof PB_PACK !== 'undefined' ? PB_PACK.find(p => p.id === id) : null);

/* ---------- picking one ---------- */
function ctPickDlg(){
  if(typeof ensurePlaybooks === 'function') ensurePlaybooks();
  const card = t => `<button type="button" class="ct-card" data-act="ctPick" data-v="${esc(t.id)}"><span class="ct-ic" style="--c:${esc(t.color)}">${ico(t.icon)}</span><span class="ct-tx"><b>${esc(t.name)}</b><small>${esc(t.desc || (t.own ? 'Your template' : ''))}</small></span>${t.playbooks.length + t.questions.length ? `<span class="t3 small ct-n">${t.playbooks.length ? t.playbooks.length + ' playbook' + (t.playbooks.length > 1 ? 's' : '') : ''}${t.playbooks.length && t.questions.length ? ' · ' : ''}${t.questions.length ? t.questions.length + ' question' + (t.questions.length > 1 ? 's' : '') : ''}</span>` : ''}</button>`;
  const own = ctList().filter(t => t.own);
  openDlg(dhead('New case') + `<div class="in"><p class="t2" style="margin:0 0 12px">Start from a template to get the right questions and playbooks, or from a blank case.</p>
    <div class="ct-grid">${CT_BUILTIN.map(card).join('')}</div>
    ${own.length ? `<div class="caps" style="margin:18px 0 8px">Your templates</div><div class="ct-grid">${own.map(t => `<div class="ct-own">${card(t)}<button type="button" class="iconbtn sm" data-act="ctDel" data-v="${esc(t.id)}" aria-label="Delete the template ${esc(t.name)}">${ico('trash-2','sm')}</button></div>`).join('')}</div>` : ''}
  </div><footer><span class="t3 small" style="margin-right:auto">Save any case as a template from its ⋯ menu.</span><button class="btn" data-act="dclose">Cancel</button></footer>`, true);
}
/* the details form for the case, with what the template brings, each playbook optional */
function ctFormHTML(t){
  if(!t || t.id === 'blank') return '';
  const pbs = t.playbooks.map(id => ({id, p:ctPb(id)})).filter(x => x.p);
  return `<div class="ct-what"><div class="ct-head"><span class="ct-ic" style="--c:${esc(t.color)}">${ico(t.icon)}</span><div><b>${esc(t.name)}</b><small class="t3">${esc(t.desc || 'Your template')}</small></div><button class="btn sm ghost" type="button" data-act="ctChange">Change</button></div>
    ${pbs.length ? `<fieldset class="field"><legend>Playbooks to run <span class="t3">their steps become open questions</span></legend>${pbs.map(({id, p}) => `<label class="chk"><input type="checkbox" data-ctpb="${esc(id)}" checked><span>${esc(p.name)} <span class="t3">· ${p.steps ? p.steps.length : 0} steps</span></span></label>`).join('')}</fieldset>` : ''}
    ${t.questions.length ? `<fieldset class="field"><legend>Questions to start with</legend>${t.questions.map((q, i) => `<label class="chk"><input type="checkbox" data-ctq="${i}" checked><span>${esc(q)}</span></label>`).join('')}</fieldset>` : ''}</div>`;
}
/* after the case is made: the questions, then each playbook ticked; returns how many questions were added */
function ctApply(c, t, form){
  if(!t || t.id === 'blank') return 0; let n = 0;
  const qs = t.questions.filter((q, i) => !form || (form.querySelector(`input[data-ctq="${i}"]`) || {checked:true}).checked);
  for(const q of qs){ DB.records.push({id:uid('q'), caseId:c.id, type:'lead', title:q, body:'', tsRaw:'', ts:null, source:'template', host:'', tags:['template:' + t.id], ents:E.extract(q), answer:'', addedBy:'You', addedAt:Date.now(), hash:''}); n++; }
  for(const id of t.playbooks){ if(form && !(form.querySelector(`input[data-ctpb="${CSS.escape(id)}"]`) || {checked:true}).checked) continue;
    const p = ctPb(id); if(!p) continue; const have = new Set(DB.records.filter(r => r.caseId === c.id && r.type === 'lead').map(r => r.title.toLowerCase()));
    for(const s of (p.steps || pbSteps(p))){ const st = s.t || s[0], h = s.h || s[1] || ''; if(have.has(String(st).toLowerCase())) continue;
      DB.records.push({id:uid('q'), caseId:c.id, type:'lead', title:st, body:h, tsRaw:'', ts:null, source:'playbook', host:'', tags:[pbTag(p.id)], ents:E.extract(st), answer:'', addedBy:'You', addedAt:Date.now(), hash:''}); n++; } }
  c.tpl = t.id; if(typeof hashRecords === 'function') hashRecords();
  return n;
}

/* ---------- your own templates ---------- */
function ctSaveDlg(caseId){
  const c = theCase(caseId); if(!c) return; const leads = DB.records.filter(r => r.caseId === c.id && r.type === 'lead');
  const pbs = [...new Set(leads.flatMap(r => (r.tags || []).filter(x => x.startsWith('playbook:')).map(x => x.slice(9))))].filter(ctPb);
  const own = leads.filter(r => !(r.tags || []).some(x => x.startsWith('playbook:')));
  UI.ctSave = {caseId:c.id, pbs, qs:own.map(r => r.title).slice(0, 60)};
  openDlg(dhead('Save as a template') + `<form data-form="ctSave"><div class="in">
    <p class="t2" style="margin:0 0 12px">A new case made from it starts with the same questions and playbooks. Only the structure is saved: no evidence, vault entries, answers or notes.</p>
    <div class="field"><label for="ctName">Template name</label><input id="ctName" value="${esc(c.name.slice(0, 60))}" autocomplete="off"></div>
    <div class="field"><label for="ctDesc">What it is for</label><input id="ctDesc" placeholder="e.g. Our standard check on a new supplier" autocomplete="off"></div>
    <dl class="kv" style="margin-top:12px"><dt>Playbooks</dt><dd>${pbs.length ? pbs.map(id => esc(ctPb(id).name)).join(', ') : '<span class="t3">none</span>'}</dd>
      <dt>Own questions</dt><dd>${own.length ? own.length + (own.length > 60 ? ' (the first 60)' : '') : '<span class="t3">none</span>'}</dd><dt>Opens on</dt><dd>${esc((CASE_TABS.find(x => x[0] === (UI.route && UI.route.area === 'case' ? UI.route.tab : 'overview')) || CASE_TABS[0])[1])}</dd>
      <dt>Scope</dt><dd>${c.scope ? 'its wording, as a hint for the next case' : '<span class="t3">none</span>'}</dd></dl></div>
    <footer><button class="btn" type="button" data-act="dclose">Cancel</button><button class="btn primary" type="submit">${ico('layout-template','sm')}Save template</button></footer></form>`);
}
function ctSave(f){
  const S = UI.ctSave, c = S && theCase(S.caseId); if(!c) return closeDlg();
  const name = $('ctName').value.trim().replace(/\s+/g, ' '); if(!name) return fieldErr('ctName', 'Give the template a name.'); if(!checkLen('ctName', name, 60, 'Name')) return;
  if(ctList().some(t => t.name.toLowerCase() === name.toLowerCase())) return fieldErr('ctName', 'There is already a template with that name.');
  const tab = UI.route && UI.route.area === 'case' && CASE_TABS.some(x => x[0] === UI.route.tab) ? UI.route.tab : 'overview';
  (DB.caseTemplates || (DB.caseTemplates = [])).push({id:uid('ct'), name, desc:$('ctDesc').value.trim().slice(0, 200), icon:c.icon, color:c.color, tab, playbooks:S.pbs, questions:S.qs, scope:(c.scope || '').slice(0, 2000), at:Date.now()});
  closeDlg(); mutate('saved a case template'); toast('Template “' + name + '” saved. It is offered when you make a new case.');
}
function ctClean(d){
  if(d.caseTemplates == null) return d; const str = (v, n) => typeof v === 'string' ? v.slice(0, n) : '';
  d.caseTemplates = (Array.isArray(d.caseTemplates) ? d.caseTemplates : []).filter(t => t && typeof t === 'object' && typeof t.id === 'string' && typeof t.name === 'string' && t.name.trim()).slice(0, 100)
    .map(t => ({id:t.id, name:str(t.name, 60), desc:str(t.desc, 200), icon:/^[a-z0-9-]{1,40}$/.test(t.icon || '') ? t.icon : 'briefcase', color:/^#[0-9a-f]{6}$/i.test(t.color || '') ? t.color : '#5470f5',
      tab:CASE_TABS.some(x => x[0] === t.tab) ? t.tab : 'overview', playbooks:(Array.isArray(t.playbooks) ? t.playbooks : []).filter(x => typeof x === 'string').slice(0, 20),
      questions:(Array.isArray(t.questions) ? t.questions : []).filter(x => typeof x === 'string' && x.trim()).map(x => x.slice(0, 500)).slice(0, 60), scope:str(t.scope, 2000), at:+t.at || 0}));
  return d;
}

const CT_ACTS = {
  ctPick:(id, v) => { closeDlg(); caseDlg(false, v); },
  ctChange:() => { closeDlg(); ctPickDlg(); },
  ctSaveAs:id => ctSaveDlg(id),
  ctDel:(id, v) => { const t = (DB.caseTemplates || []).find(x => x.id === v); if(!t) return; confirmDlg('Delete the template “' + t.name + '”?', 'Cases made from it keep everything; only the template goes.', 'Delete', () => { const i = DB.caseTemplates.indexOf(t); DB.caseTemplates = DB.caseTemplates.filter(x => x.id !== v); mutate('deleted a case template'); ctPickDlg();
    toast('Template “' + t.name + '” deleted', 'Undo', () => { DB.caseTemplates.splice(i, 0, t); mutate('put back a case template'); if($('dlg') && $('dlg').querySelector('.ct-card')) ctPickDlg(); }); }); },
};
