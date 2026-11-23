/* ==========================================================================
   Case copilot — reads the whole case and says what to do next.
     • Next steps: ranked actions with the reason and a button (check indicators online,
       mark what the sources flagged, review suggested links, run the right playbook…)
     • Gaps: what is missing or contradicts itself (no timestamps, unclear time zones,
       a verdict the evidence disagrees with)
     • The story so far: a plain-language summary built only from the case's own data
     • Auto-check: per case, off by default — new public indicators are looked up
       with the sources you switched on, as evidence arrives
   No AI service: every sentence comes from data in the case, and says where from.
   ========================================================================== */
const CP = {memo:new Map(), q:[], busy:false, seen:new Map(), t:0};
const CP_PUBLIC = new Set(['ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256', 'cve']);
const cpHist = () => { const m = new Map(); for(const h of (DB.intel && DB.intel.lookHist) || []) if(!m.has(h.k + ':' + h.v)) m.set(h.k + ':' + h.v, h); return m; };
const plural = (n, w, ws) => n + ' ' + (n === 1 ? w : ws || w + 's');
const listOf = (a, n = 3) => a.length <= n ? a.join(', ').replace(/, ([^,]*)$/, ' and $1') : a.slice(0, n).join(', ') + ' and ' + (a.length - n) + ' more';
/* public indicators of a case that the lookup sources could check */
function cpIndicators(caseId){
  const D = derive(caseId), keys = new Set([...D.ents.keys(), ...D.byKey.keys()]), out = [];
  for(const key of keys){ const {k, v} = entSplit(key); if(!CP_PUBLIC.has(k)) continue; if((k === 'ipv4' || k === 'ipv6') && !/^Public/.test(E.ipClass(v))) continue; out.push({key, k, v}); }
  return out;
}
/* what kind of case this is, for the playbook to suggest */
function cpKind(D, kinds, tags){
  const has = k => (kinds.get(k) || 0) > 0, eids = new Set(D.recs.flatMap(r => (r.ents || []).filter(e => e.k === 'eventid').map(e => +e.v)));
  if(tags.has('ransom') || D.recs.some(r => /ransom|encrypted your files|\.onion.*decrypt/i.test(r.body || ''))) return 'pb-ransom';
  if(has('email') && (has('url') || has('domain')) && D.recs.some(r => /^(received|from|subject|return-path):/im.test(r.body || ''))) return 'pb-phish';
  if(eids.has(4625) || eids.has(4771) || D.recs.some(r => /failed (login|sign-?in|password)|brute.?force|credential stuffing/i.test(r.body || ''))) return 'pb-login';
  if(has('md5') || has('sha256') || has('sha1')) return 'pb-malware';
  if(['btc', 'eth', 'xmr', 'ltc', 'trx', 'doge'].some(has)) return 'pb-crypto';
  if(D.recs.some(r => /cloudtrail|azuread|signinlogs|consolelogin|okta/i.test((r.source || '') + ' ' + (r.body || '').slice(0, 2000)))) return 'pb-cloudir';
  if(has('handle') || has('social')) return 'pb-user';
  if(has('coords')) return 'pb-geo';
  if(has('domain')) return 'pb-domain';
  if(has('ipv4')) return 'pb-ip';
  return null;
}

function copilot(caseId){
  caseId = caseId || DB.active; const mk = caseId + ':' + rev + ':' + ((DB.intel && DB.intel.lookHist || [])[0] || {}).at; const hit = CP.memo.get(caseId); if(hit && hit.mk === mk) return hit.v;
  const c = theCase(caseId), D = derive(caseId), H = cpHist(), I = cpIndicators(caseId), steps = [], gaps = [], tags = new Set();
  const step = (pri, icon, title, why, act, extra = {}) => steps.push({pri, icon, title, why, act, ...extra});
  const gap = (icon, title, why, act, extra = {}) => gaps.push({icon, title, why, act, ...extra});
  const kinds = new Map(); for(const [key] of D.ents){ const k = key.slice(0, key.indexOf(':')); kinds.set(k, (kinds.get(k) || 0) + 1); }
  for(const e of D.entries){ const k = entryKey(e); if(k) { const kk = k.slice(0, k.indexOf(':')); kinds.set(kk, (kinds.get(kk) || 0) + 1); } }
  const obs = []; for(const r of D.recs) for(const o of E.observations(r)) if(o.hot){ obs.push({r, o}); tags.add(o.tag); }
  const lookOn = typeof LK_PROVIDERS !== 'undefined' && LK_PROVIDERS.some(lkOn);

  /* --- what live lookups and feeds say --- */
  const checked = I.filter(x => H.has(x.key)), unchecked = I.filter(x => !H.has(x.key) && (typeof lkFor !== 'function' || lkFor(x.k).some(lkOn)));
  const flagged = checked.filter(x => /malicious|suspicious/.test(H.get(x.key).band) && !verdictOf(x.key)).sort((a, b) => H.get(b.key).score - H.get(a.key).score);
  const conflicts = checked.filter(x => { const h = H.get(x.key), v = verdictOf(x.key); return (h.band === 'malicious' && /benign/.test(v)) || (h.band === 'benign' && h.score < 15 && v === 'malicious'); });
  const feed = typeof CTI !== 'undefined' && CTI.iocIx ? I.filter(x => { const i = CTI.iocIx.get(x.key); return i && iocLive(i) && !verdictOf(x.key); }) : [];
  const kev = I.filter(x => x.k === 'cve' && typeof kevOf === 'function' && kevOf(x.v.toUpperCase()));
  if(feed.length) step(95, 'radio', plural(feed.length, 'indicator') + ' in your threat feeds', 'Your indicator feeds list ' + listOf(feed.map(x => x.v), 2) + (CTI.iocIx.get(feed[0].key).threat ? ' (' + CTI.iocIx.get(feed[0].key).threat + ')' : '') + '. Mark them malicious so every case and detection rule knows.', 'cpMarkFeed', {label:'Mark malicious'});
  if(flagged.length) step(92, 'shield-alert', plural(flagged.length, 'indicator') + ' flagged by live lookups', listOf(flagged.map(x => x.v + ' (' + H.get(x.key).score + ')'), 3) + ' — no verdict of yours yet. Review, then mark them.', 'cpReviewFlagged', {label:'Review'});
  if(kev.length) step(88, 'bug', plural(kev.length, 'CVE') + ' in the case ' + (kev.length > 1 ? 'are' : 'is') + ' exploited in the wild', listOf(kev.map(x => x.v.toUpperCase()), 3) + ' ' + (kev.length > 1 ? 'are' : 'is') + ' in CISA\'s Known Exploited catalog — check whether the affected systems are patched.', 'cpCve', {label:'Open', v:kev[0].v.toUpperCase()});
  if(unchecked.length && lookOn) step(80 + Math.min(8, unchecked.length), 'radar', 'Check ' + plural(unchecked.length, 'indicator') + ' online', 'Never looked up: ' + listOf(unchecked.map(x => x.v), 3) + '. Your switched-on sources will weigh in and the copilot will update.', 'lookCase', {label:'Investigate all'});
  else if(I.length && !lookOn) step(60, 'radar', 'Switch on lookup sources', plural(I.length, 'public indicator') + ' in this case could be checked against Shodan, OTX, RDAP, DNS and more. Nothing is sent until you choose the sources.', 'feedSources', {label:'Choose sources', v:'look'});

  /* --- graph and relationships --- */
  const sugg = typeof suggestLinks === 'function' ? suggestLinks(caseId).filter(s => s.score >= 2) : [];
  if(sugg.length) step(70 + Math.min(10, sugg.length), 'waypoints', plural(sugg.length, 'relationship') + ' to review', 'For example ' + primary(sugg[0].a) + ' ↔ ' + primary(sugg[0].b) + ': ' + sugg[0].why[0].toLowerCase() + '. Accepting them makes the graph and the report complete.', 'cpGraph', {label:'Review on graph'});
  const risk = typeof gRisk === 'function' ? [...gRisk(caseId)].filter(([id, x]) => !x.own && x.r >= 0.45 && !entryVerdict(entryById(id))).sort((a, b) => b[1].r - a[1].r) : [];
  if(risk.length) step(74, 'flame', plural(risk.length, 'entry', 'entries') + ' close to malicious infrastructure', primary(entryById(risk[0][0])) + ' scores ' + Math.round(risk[0][1].r * 100) + '% — ' + riskWhy(risk[0][1]) + '. Decide on a verdict.', 'cpRisk', {label:'Show on graph'});
  const mal = [...new Set([...D.entries.filter(e => entryVerdict(e) === 'malicious').map(entryKey), ...I.filter(x => verdictOf(x.key) === 'malicious').map(x => x.key)].filter(Boolean))];
  const unwatched = mal.filter(k => !isWatched(k));
  if(unwatched.length) step(62, 'eye', 'Watch ' + plural(unwatched.length, 'malicious indicator'), 'You will hear when ' + listOf(unwatched.map(k => entSplit(k).v), 2) + ' shows up in new evidence, news or another case' + (lookOn ? ', and when its online picture changes.' : '.'), 'cpWatch', {label:'Watch'});
  if(mal.length && !(DB.rules || []).some(r => r.caseId === caseId)) step(58, 'file-code', 'Turn the malicious indicators into detections', 'A Sigma rule for the network indicators and a YARA rule for the hashes and strings, ready to review.', 'cpRules', {label:'Generate rules'});

  if(typeof coverage === 'function'){ const caseT = new Set(); for(const x of obs) for(const m of x.o.t.match(/T\d{4}(?:\.\d{3})?/g) || []) caseT.add(m); for(const [key] of D.ents) if(key.startsWith('ttp:')) caseT.add(key.slice(4).toUpperCase());
    if(caseT.size){ const G = coverage().gaps.filter(g => caseT.has(g.id) || [...caseT].some(t => t.split('.')[0] === g.id)); if(G.length) step(56, 'grid-3x3', plural(G.length, 'technique') + ' in this case with no detection rule', listOf(G.map(g => g.id + ' ' + g.name), 2) + '. Draft a rule so it is caught next time.', 'cpCov', {label:'See coverage'}); } }
  /* --- playbook and questions --- */
  const pk = cpKind(D, kinds, tags), pb = pk && (DB.playbooks || []).find(p => p.id === pk);
  if(pb && !pbProgress(pb, caseId).total) step(66, 'list-checks', 'Run the "' + pb.name + '" playbook', 'The evidence looks like this kind of case. Its ' + pb.steps.length + ' steps become questions here, so nothing standard is forgotten.', 'pbRun', {label:'Run playbook', id:pb.id});
  const open = D.recs.filter(r => r.type === 'lead' && !r.answer);
  if(open.length) step(50 + Math.min(10, open.length), 'circle-help', plural(open.length, 'open question'), 'Next: ' + open[0].title, 'selRec', {label:'Answer', id:open[0].id});

  /* --- gaps --- */
  const ev = D.recs.filter(r => r.type !== 'lead'), noTs = ev.filter(r => !r.ts), unsure = ev.filter(r => r.ts && r.tsZone && r.tsZone !== 'explicit');
  if(ev.length >= 3 && noTs.length / ev.length > 0.3) gap('clock', plural(noTs.length, 'record') + ' without a time', 'They are missing from the timeline and from "around this time". Add when it happened, even roughly.', 'selRec', {id:noTs[0].id, label:'Open first'});
  if(unsure.length) gap('globe', plural(unsure.length, 'time') + ' with an assumed time zone', 'Read as ' + tz() + ' because the source did not say. Confirm, or the order of events may be wrong.', 'selRec', {id:unsure[0].id, label:'Check'});
  for(const x of conflicts.slice(0, 3)){ const h = H.get(x.key); gap('git-compare', x.v + ': your verdict and the sources disagree', 'You marked it ' + verdictOf(x.key) + '; live lookups scored it ' + h.score + ' (' + h.band + ').', 'lookEnt', {id:x.key, label:'See why'}); }
  const loose = D.entries.filter(e => !entryMentions(e).length && !D.links.some(l => l.a === e.id || l.b === e.id));
  if(loose.length >= 2) gap('unlink', plural(loose.length, 'vault entry', 'vault entries') + ' with no evidence or link', listOf(loose.map(primary), 3) + ' — nothing in the case supports or connects them yet.', 'selEntry', {id:loose[0].id, label:'Open first'});
  if(!c.scope && D.recs.length >= 3) gap('target', 'No scope written', 'One sentence on what this case must answer keeps the work focused and opens the report.', 'editCase', {label:'Write scope'});

  steps.sort((a, b) => b.pri - a.pri);
  const v = {steps, gaps, story:cpStory(c, D, I, H, obs, mal, kev, feed), kind:pb ? pb.name : '', checked:checked.length, total:I.length};
  CP.memo.set(caseId, {mk, v}); return v;
}

/* actor and malware names in the evidence: only re-read when the evidence changes */
const CP_FIND = new Map();
function cpFind(caseId, ev, text){ const k = ev.length + ':' + (ev[ev.length - 1] || {}).id + ':' + text.length, o = CP_FIND.get(caseId); if(o && o.k === k) return o.v; const v = ctiFind(text); CP_FIND.set(caseId, {k, v}); return v; }
/* ---------- the story so far ---------- */
function cpStory(c, D, I, H, obs, mal, kev, feed){
  const P = [], ts = D.recs.map(r => r.ts).filter(Boolean).sort((a, b) => a - b), ev = D.recs.filter(r => r.type !== 'lead');
  if(!ev.length && !D.entries.length) return P;
  const hosts = countBy(ev.filter(r => r.host), r => r.host);
  if(ts.length) P.push(`Evidence runs from <b>${esc(E.fmtFull(ts[0], tz()))}</b> to <b>${esc(E.fmtFull(ts[ts.length - 1], tz()))}</b> (${esc(E.fmtGap(ts[ts.length - 1] - ts[0]) || 'one moment')}) across ${plural(ev.length, 'record')}${hosts.length ? ` from ${plural(hosts.length, 'host')}${hosts.length <= 4 ? ' — ' + hosts.map(([h, n]) => `<span class="mono">${esc(h)}</span> (${n})`).join(', ') : ', most from <span class="mono">' + esc(hosts[0][0]) + '</span>'}` : ''}.`);
  else P.push(`${plural(ev.length, 'evidence record')} and ${plural(D.entries.length, 'vault entry', 'vault entries')}, none with a time yet.`);
  const KN = {ipv4:['IP address', 'IP addresses'], ipv6:['IP address', 'IP addresses'], domain:['domain'], url:['URL'], md5:['file hash', 'file hashes'], sha1:['file hash', 'file hashes'], sha256:['file hash', 'file hashes'], cve:['CVE']};
  const by = countBy(I, x => KN[x.k][0]).map(([k, n]) => plural(n, k, (Object.values(KN).find(a => a[0] === k) || [])[1]));
  if(I.length){ const flagged = I.filter(x => H.has(x.key) && /malicious|suspicious/.test(H.get(x.key).band) && !mal.includes(x.key));
    P.push(`It names ${listOf(by, 4)}. ${mal.length ? `<b>${plural(mal.length, 'indicator')} judged malicious</b>: ${listOf(mal.map(k => '<span class="mono">' + esc(entSplit(k).v) + '</span>'), 3)}.` : 'Nothing is judged malicious yet.'}${flagged.length ? ` Live lookups flag ${listOf(flagged.map(x => '<span class="mono">' + esc(x.v) + '</span> (' + H.get(x.key).score + ')'), 2)} as well.` : ''}`); }
  const tg = countBy(obs, x => x.o.tag);
  if(tg.length) P.push(`What the evidence shows: ${listOf(tg.map(([t, n]) => `<b>${esc(t)}</b>${n > 1 ? ' ×' + n : ''}`), 5)}${(() => { const b = [...D.ents.values()].map(e => ({e, b:E.beaconOf(e.recs.map(r => r.ts))})).find(x => x.b && x.b.regular); return b ? `, and a <b>regular beacon</b> to <span class="mono">${esc(b.e.v)}</span> every ${esc(E.fmtGap(b.b.mean))}` : ''; })()}.`);
  const T = new Set(); for(const x of obs) for(const m of x.o.t.match(/T\d{4}(?:\.\d{3})?/g) || []) T.add(m); for(const [key] of D.ents) if(key.startsWith('ttp:')) T.add(key.slice(4).toUpperCase());
  if(T.size && typeof ATTACK !== 'undefined'){ const nm = id => (ATTACK.tech.find(t => t[0] === id) || [, ''])[1]; P.push(`ATT&CK: ${listOf([...T].sort().map(id => `<b>${esc(id)}</b>${nm(id) ? ' ' + esc(nm(id)) : ''}`), 5)}.`); }
  const text = ev.slice(0, 400).map(r => (r.title || '') + ' ' + (r.body || '').slice(0, 1500)).join('\n').slice(0, 150000), F = typeof ctiFind === 'function' ? cpFind(c.id, ev, text) : {act:[], mal:[]};
  const actors = F.act.map(id => (ATTACK.groups.find(g => g.id === id) || {}).n).filter(Boolean), soft = F.mal.map(id => ATTACK.soft.find(g => g.id === id)).filter(s => s && s.k === 'm').map(s => s.n);
  if(actors.length || soft.length || feed.length || kev.length) P.push([actors.length ? `The evidence mentions ${listOf(actors.map(a => '<b>' + esc(a) + '</b>'), 3)}` : '', soft.length ? `${actors.length ? 'and' : 'The evidence mentions'} ${listOf(soft.map(a => '<b>' + esc(a) + '</b>'), 3)}` : '', feed.length ? `${actors.length || soft.length ? '; ' : ''}${plural(feed.length, 'indicator')} ${feed.length > 1 ? 'are' : 'is'} in your threat feeds` : '', kev.length ? `${actors.length || soft.length || feed.length ? '; ' : ''}${listOf(kev.map(x => esc(x.v.toUpperCase())), 2)} ${kev.length > 1 ? 'are' : 'is'} exploited in the wild` : ''].join(' ').trim() + '.');
  const leads = D.recs.filter(r => r.type === 'lead'), done = leads.filter(r => r.answer).length;
  if(leads.length) P.push(`${done} of ${plural(leads.length, 'question')} answered${leads.length > done ? '; still open: ' + listOf(leads.filter(r => !r.answer).map(r => '“' + esc(r.title) + '”'), 2) : ''}.`);
  return P;
}
const cpStoryText = caseId => copilot(caseId).story.map(p => p.replace(/<[^>]+>/g, '').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'")).join('\n\n');

/* ---------- drawing ---------- */
function cpCard(c){
  /* on a very large case, draw the page first and read the case a moment later */
  const fresh = (() => { const h = CP.memo.get(c.id); return h && h.mk === c.id + ':' + rev + ':' + ((DB.intel && DB.intel.lookHist || [])[0] || {}).at; })();
  if(!fresh && derive(c.id).recs.length > 3000){ clearTimeout(CP.late); CP.late = setTimeout(() => { if(DB.active !== c.id) return; copilot(c.id); const el = $('cpCard'); if(el) el.outerHTML = cpCard(c); }, 40);
    return `<section class="card cp" id="cpCard" aria-busy="true"><header><h3>${ico('sparkles','sm')}Copilot</h3><span class="t3">Reading ${derive(c.id).recs.length.toLocaleString()} records…</span></header></section>`; }
  const C = copilot(c.id), N = UI.cpAll ? 20 : 4, S = C.steps.slice(0, N), lookOn = typeof LK_PROVIDERS !== 'undefined' && LK_PROVIDERS.some(lkOn);
  const row = (x, g) => `<li class="cp-s${g ? ' gap' : ''}"><span class="cp-i">${ico(x.icon,'sm')}</span><div><b>${esc(x.title)}</b><small>${esc(x.why)}</small></div>
    ${x.act ? `<button class="btn sm${!g && x === C.steps[0] ? ' primary' : ''}" data-act="${x.act}"${x.id ? ` data-id="${esc(x.id)}"` : ''}${x.v ? ` data-v="${esc(x.v)}"` : ''}>${esc(x.label || 'Open')}</button>` : ''}</li>`;
  return `<section class="card cp" id="cpCard" aria-labelledby="cpH"><header><h3 id="cpH">${ico('sparkles','sm')}Copilot</h3>${C.kind ? `<span class="t3">Looks like: ${esc(C.kind)}</span>` : ''}
      <label class="cp-auto" title="${lookOn ? 'New public indicators in this case are looked up with your switched-on sources as evidence arrives' : 'Switch on lookup sources in Threat Intel first'}"><span class="sw sm"><input type="checkbox" data-act="cpAuto" ${c.autoLook ? 'checked' : ''} ${lookOn ? '' : 'disabled'}><span></span></span>Check new indicators online</label></header>
    <div class="cp-grid"><div><h4>Next steps</h4>${S.length ? `<ol class="cp-l">${S.map(x => row(x)).join('')}</ol>` : '<p class="t3">Nothing pressing — the case is in good shape.</p>'}
        ${C.steps.length > 4 ? `<button class="btn sm ghost" data-act="cpAll">${UI.cpAll ? 'Show fewer' : 'Show all ' + C.steps.length}</button>` : ''}
        ${C.gaps.length ? `<h4>Gaps</h4><ol class="cp-l">${C.gaps.slice(0, UI.cpAll ? 20 : 3).map(x => row(x, true)).join('')}</ol>` : ''}</div>
      <div class="cp-story"><h4>The story so far <button class="iconbtn" data-act="cpCopy" aria-label="Copy the story" title="Copy">${ico('copy','sm')}</button><button class="iconbtn" data-act="cpNote" aria-label="Save the story as a note" title="Save as a note">${ico('sticky-note','sm')}</button></h4>
        ${C.story.length ? C.story.map(p => `<p>${p}</p>`).join('') : '<p class="t3">Add evidence and the story writes itself.</p>'}
        <p class="heur">Built only from this case's records, verdicts and lookups — check before you rely on it.</p></div></div></section>`;
}

/* ---------- auto-check new indicators ---------- */
function onMutate(){ if(typeof cxScanRecords === 'function') cxScanRecords(); if(typeof epScanRecords === 'function') epScanRecords(); clearTimeout(CP.t); CP.t = setTimeout(cpAutoScan, 1500); if(typeof autoSchedule === 'function') autoSchedule(); }
function cpAutoScan(){
  if(typeof LK_PROVIDERS === 'undefined' || !LK_PROVIDERS.some(lkOn)) return;
  const H = cpHist(), queued = new Set(CP.q.map(x => x.key));
  for(const c of DB.cases.filter(c => c.autoLook)) for(const x of cpIndicators(c.id)){ if(H.has(x.key) || queued.has(x.key) || CP.seen.has(x.key) || !lkFor(x.k).some(lkOn)) continue; CP.q.push({...x, caseId:c.id}); queued.add(x.key); }
  CP.q = CP.q.slice(0, 200); cpDrain();
}
async function cpDrain(){
  if(CP.busy) return; CP.busy = true; const bad = [];
  try{ while(CP.q.length){ const batch = CP.q.splice(0, 2);
    await Promise.all(batch.map(async x => { CP.seen.set(x.key, Date.now()); const res = await lkInvestigate(x.k, x.v); if(!Object.keys(res).length) return; const V = lkVerdict(x.k, x.v, res); lkHist(x.k, x.v, V); if(V.band === 'malicious') bad.push(x.v + ' (' + V.score + ')'); })); } }
  finally{ CP.busy = false; }
  save(); CP.memo.clear(); if(UI.route.area === 'case') renderMain();
  if(bad.length) toast('Auto-check: ' + listOf(bad, 2) + ' look' + (bad.length === 1 ? 's' : '') + ' malicious', 'Open', () => go(caseHash(DB.active, 'overview')));
}

const CP_ACTS = {
  cpAll:() => { UI.cpAll = !UI.cpAll; renderMain(); },
  cpAuto:(id, v, t) => { const c = theCase(); c.autoLook = !!t.checked; mutate((c.autoLook ? 'turned on' : 'turned off') + ' auto-check for ' + caseNm(c));
    if(c.autoLook){ const n = cpIndicators(c.id).filter(x => !cpHist().has(x.key)).length; toast(n ? 'Checking ' + plural(n, 'indicator') + ' in ' + caseNm(c) + '…' : 'New indicators in ' + caseNm(c) + ' will be checked as they arrive'); cpAutoScan(); } },
  cpMarkFeed:() => { const I = cpIndicators(DB.active).filter(x => { const i = CTI.iocIx && CTI.iocIx.get(x.key); return i && iocLive(i) && !verdictOf(x.key); }); I.forEach(x => DB.verdicts[x.key] = 'malicious'); mutate('marked ' + I.length + ' feed indicators malicious'); renderMain();
    toast(plural(I.length, 'indicator') + ' marked malicious', 'Undo', () => { I.forEach(x => delete DB.verdicts[x.key]); mutate('undo'); renderMain(); }); },
  cpReviewFlagged:() => { const H = cpHist(), L = cpIndicators(DB.active).filter(x => H.has(x.key) && /malicious|suspicious/.test(H.get(x.key).band) && !verdictOf(x.key));
    UI.itab = 'look'; LKV.bulk = {caseId:DB.active, items:L.map(x => ({...x, V:Object.assign(lkVerdict(x.k, x.v, lkKnown(x.k, x.v)), {}), res:lkKnown(x.k, x.v)})), done:L.length, fin:true};
    LKV.bulk.corr = lkCorrelate(LKV.bulk.items.map(x => ({key:x.key, k:x.k, v:x.v, attrs:x.V.attrs}))); go('#/feeds'); },
  cpCve:(id, v) => { go('#/feeds'); setTimeout(() => ctiCveDlg(v), 60); },
  cpRisk:() => { if(UI.graph){ UI.graph.panel = 'ins'; UI.graph.risk = true; UI.graph.clusters = false; } go(caseHash(DB.active, 'graph')); },
  cpCov:() => { UI.dview = 'coverage'; go('#/detections'); },
  cpGraph:() => { if(UI.graph) UI.graph.panel = 'sugg'; go(caseHash(DB.active, 'graph')); },
  cpWatch:() => { const D = derive(), I = cpIndicators(DB.active), L = [...new Set([...D.entries.filter(e => entryVerdict(e) === 'malicious').map(entryKey), ...I.filter(x => verdictOf(x.key) === 'malicious').map(x => x.key)].filter(k => k && !isWatched(k)))];
    DB.watch = DB.watch || {}; L.forEach(k => { DB.watch[k] = {at:Date.now()}; }); mutate('watching ' + L.length + ' indicators'); renderMain(); toast('Watching ' + plural(L.length, 'indicator'), 'Watchlist', () => go('#/watch')); },
  cpRules:() => ruleFromCase(),
  cpCopy:async () => { try{ await navigator.clipboard.writeText(theCase().name + '\n\n' + cpStoryText()); toast('Story copied'); }catch(e){ toast('Copy failed'); } },
  cpNote:() => { const c = theCase(), now = Date.now(); DB.notes = DB.notes || []; DB.notes.unshift({id:uid('n'), caseId:c.id, color:'blue', pinned:false, text:('# Story so far — ' + E.fmtDate(now, tz()) + '\n\n' + cpStoryText()).slice(0, 4000), due:'', created:now, updated:now}); mutate('saved the case story as a note'); renderMain(); toast('Saved as a note in ' + caseNm(c)); },
};
