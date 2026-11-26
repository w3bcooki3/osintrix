/* ==========================================================================
   Guided tour — Op Lantern for the cybercrime and OSINT side, Kestrel Dawn for the journalism side.
   Each step opens the right screen, rings the part it talks about and says
   what it is for in two sentences. Next / Back / Esc; it can be left and
   restarted any time (Help, or the setup's "Where to start").
   ========================================================================== */
const TOUR = {i:-1, steps:[]};
/* Op Lantern shows the cybercrime and OSINT side, Kestrel Dawn the journalism side; a step whose case is not in the
   workspace is left out */
const TOUR_STEPS = [
  {need:'c-lantern', go:() => caseHash('c-lantern', 'overview'), sel:'.cp', t:'Your copilot', d:'Every case has one. It reads the evidence and suggests the next steps, writes the story so far, and points out what is missing. Nothing here is sent anywhere.'},
  {need:'c-lantern', go:() => caseHash('c-lantern', 'timeline'), pre:() => { UI.tlMode = 'events'; }, sel:'#tlV .ev', t:'The timeline', d:'Every piece of evidence in time order, in your time zone. Click an event for its details; press J and K to move through them.'},
  {need:'c-lantern', go:() => caseHash('c-lantern', 'timeline'), pre:() => { UI.tlMode = 'patterns'; }, sel:'.tlx-c.red', t:'Patterns', d:'OSINTrix finds the likely first sign of compromise, bursts of activity, quiet periods, cleared logs and time zone mix-ups — with the reasons, so you can check them.'},
  {need:'c-lantern', go:() => caseHash('c-lantern', 'timeline'), pre:() => { UI.tlMode = 'rules'; UI.crf = 'blind'; }, sel:'.cr-sum, #crProg', t:'Your rules, against this case', d:'Every rule runs over the case: what fired, what looks suspicious but nothing caught — grouped, one click from a draft rule — and which rules are too noisy here.'},
  {need:'c-lantern', go:() => caseHash('c-lantern', 'entities'), sel:'.ce-t', t:'Indicators come out on their own', d:'IPs, domains, hashes, emails, wallets, ships and aircraft, SSH keys and fediverse or Nostr accounts are pulled from everything you add. Give each a verdict once and it applies in every case.'},
  {need:'c-lantern', go:() => caseHash('c-lantern', 'graph'), sel:'#cy', t:'The link graph', d:'People, accounts, infrastructure and files, and how they connect. Ask it for the shortest path between two things, or what is most central. Tab into it and the arrow keys walk from entry to entry.'},
  {need:'c-lantern', go:() => caseHash('c-lantern', 'vault'), sel:'[data-act=dupOpen], .ecard', t:'Related entries', d:'The same account under two spellings, look-alike domains, one name on several platforms: the vault lists them to review, with why it thinks so, and merges or links them in one step.'},
  {need:'c-lantern', go:() => caseHash('c-lantern', 'infra'), pre:() => { UI.ivView = 'dom'; }, sel:'.seg.qseg', t:'The crew behind it', d:'Infrastructure, money flows from blockchain explorers, when each account was made and what changed on its pages, and when the people behind it are awake. Here a refund scam on the same server ties the crew to the intrusion — shown as a lead with its evidence, not as proof.'},
  {need:'c-story', go:() => caseHash('c-story', 'story'), pre:() => { UI.stView = 'claims'; }, sel:'.st-check, .st', t:'Claims, for journalists', d:'Kestrel Dawn is a story in progress. Each claim it makes has the evidence for and against it; a claim is ready when two independent sources confirm it, its pictures are verified and everyone it names has had the chance to reply.'},
  {need:'c-story', go:() => caseHash('c-story', 'story'), pre:() => { UI.stView = 'reply'; }, sel:'.st', t:'Right of reply', d:'Who was asked, about which claims, by when — and what they said, or that they declined. Requests past their deadline show up on Today.'},
  {need:'c-story', go:() => caseHash('c-story', 'story'), pre:() => { UI.stView = 'sources'; }, sel:'.st', t:'Protected sources', d:'Who told you what is sealed with its own passphrase, locks itself when you step away, and never goes into a shared case file. Burning a source removes it from restore points too.'},
  {go:() => '#/playbooks', pre:() => { UI.pbTab = 'auto'; UI.pb = null; }, sel:'.au-intro', t:'Let the routine work run itself', d:'Automations act on new evidence while the app is open: check indicators, look them up, ask the questions you always ask.'},
  {go:null, sel:'.top [data-act=capture], [data-act=capture]', t:'Now your own case', d:'Press N, or Capture, and paste anything — a log line, an email, a post. A new case starts from a template — a story, phishing, fraud, a missing person and more — with the right questions and playbooks set up.', last:true},
];
function tourStart(){ TOUR.steps = TOUR_STEPS.filter(s => !s.need || DB.cases.some(c => c.id === s.need)); if(TOUR.steps.length < 3) return toast('The sample cases are not in this workspace — restore sample data in Settings to take the tour'); TOUR.i = 0; closeDlg(); tourShow(); }
function tourEnd(){ TOUR.i = -1; const c = $('tourCard'), r = $('tourRing'); if(c) c.remove(); if(r) r.remove(); DB.prefs.tourDone = Date.now(); save(); }
function tourShow(){
  const S = TOUR.steps[TOUR.i]; if(!S) return tourEnd();
  if(S.pre) S.pre();
  const h = S.go && S.go(); if(h && location.hash !== h) go(h); else renderAll();
  setTimeout(() => tourPlace(0), 260);
}
function tourPlace(n){
  const S = TOUR.steps[TOUR.i]; if(!S) return;
  const el = [...document.querySelectorAll(S.sel)].find(x => x.getBoundingClientRect().width > 0);
  if(!el && n < 8) return setTimeout(() => tourPlace(n + 1), 150);
  let ring = $('tourRing'); if(!ring){ ring = document.createElement('div'); ring.id = 'tourRing'; ring.setAttribute('aria-hidden', 'true'); document.body.appendChild(ring); }
  let card = $('tourCard'); if(!card){ card = document.createElement('div'); card.id = 'tourCard'; card.setAttribute('role', 'dialog'); card.setAttribute('aria-modal', 'false'); card.setAttribute('aria-labelledby', 'tourT'); document.body.appendChild(card); }
  card.innerHTML = `<div class="tour-n">${TOUR.i + 1} of ${TOUR.steps.length}</div><h3 id="tourT">${esc(S.t)}</h3><p>${esc(S.d)}</p>
    <div class="tour-f">${TOUR.i ? `<button class="btn sm ghost" data-act="tourBack">${ico('arrow-left','sm')}Back</button>` : `<button class="btn sm ghost" data-act="tourEnd">Skip</button>`}<span style="flex:1"></span>
      ${S.last ? `<button class="btn sm" data-act="tourEnd">Close</button><button class="btn sm primary" data-act="tourNew">${ico('folder-plus','sm')}Make my case</button>` : `<button class="btn sm primary" data-act="tourNext">Next${ico('arrow-right','sm')}</button>`}</div>`;
  if(el){ el.scrollIntoView({block:el.offsetHeight > innerHeight * 0.6 ? 'nearest' : 'center', behavior:'instant'}); const r = el.getBoundingClientRect(), pad = 6;
    Object.assign(ring.style, {display:'block', left:(r.left - pad) + 'px', top:(r.top - pad) + 'px', width:Math.min(r.width + pad * 2, innerWidth - 8) + 'px', height:Math.min(r.height + pad * 2, innerHeight - 8) + 'px'});
    const cw = Math.min(360, innerWidth - 24), below = r.bottom + 14 + 200 < innerHeight, above = r.top - 14 - 200 > 0;
    const top = below ? r.bottom + 14 : above ? Math.max(12, r.top - 14 - card.offsetHeight) : Math.max(12, innerHeight - card.offsetHeight - 16);
    Object.assign(card.style, {left:Math.max(12, Math.min(innerWidth - cw - 12, r.left)) + 'px', top:Math.min(top, innerHeight - card.offsetHeight - 12) + 'px', width:cw + 'px'}); }
  else { ring.style.display = 'none'; Object.assign(card.style, {left:'50%', top:'30%', width:Math.min(360, innerWidth - 24) + 'px', transform:'translateX(-50%)'}); }
  if(el) card.style.transform = '';
  const b = card.querySelector('.btn.primary'); if(b) b.focus({preventScroll:true});
}
addEventListener('resize', () => { if(TOUR.i >= 0) tourPlace(8); });
document.addEventListener('keydown', ev => { if(TOUR.i < 0) return; if(ev.key === 'Escape'){ ev.stopPropagation(); tourEnd(); } }, true);
const TOUR_ACTS = {
  tourStart:() => tourStart(), tourEnd:() => tourEnd(),
  tourNext:() => { TOUR.i++; tourShow(); }, tourBack:() => { TOUR.i = Math.max(0, TOUR.i - 1); tourShow(); },
  tourNew:() => { tourEnd(); go('#/cases'); setTimeout(() => typeof caseDlg === 'function' && caseDlg(), 80); },
};
