/* ==========================================================================
   Report writer — the parts of a report an analyst writes last, drafted from the case:
     • Bottom line: what happened, how, what is confirmed, what is open — with a stated
       confidence (words of estimative probability, as in intelligence writing)
     • Attack path: the ATT&CK tactics in the order the evidence shows them, each cited
     • Recommendations: now / next / later, each with its reason and the indicators
     • Confidence and limitations: why the confidence is what it is, and the gaps
   Every sentence comes from the case's records, verdicts and saved lookups. The bottom
   line can be rewritten by hand; recommendations can be dropped one by one.
   ========================================================================== */
const RW_KIND = {'pb-phish':'a phishing intrusion', 'pb-ransom':'a ransomware incident', 'pb-login':'a credential attack', 'pb-malware':'a malware infection', 'pb-crypto':'a cryptocurrency trail', 'pb-cloudir':'a cloud account compromise',
  'pb-user':'an online persona', 'pb-geo':'a geolocation question', 'pb-domain':'malicious infrastructure', 'pb-ip':'suspicious network activity'};
const RW_TAG = {lure:['a disguised attachment', 'initial-access'], masquerade:['a program posing as a system binary', 'defense-evasion'], download:['a living-off-the-land download', 'command-and-control'], encoded:['encoded PowerShell', 'execution'],
  persistence:['persistence that survives a reboot', 'persistence'], c2:['command-and-control traffic', 'command-and-control'], 'anti-forensics':['cleared event logs', 'defense-evasion']};
/* tags that mean the host itself ran something bad (not a sensor that saw it pass) */
const RW_ENDPOINT = /^(masquerade|encoded|persistence|download|anti-forensics)$/;
const RW_CONF = {high:'high confidence', moderate:'moderate confidence', low:'low confidence'};
const rwList = (a, n = 3) => a.length <= n ? a.join(', ').replace(/, ([^,]*)$/, ' and $1') : a.slice(0, n).join(', ') + ' and ' + (a.length - n) + ' more';
const rwDay = t => E.fmtFull(t, tz()).slice(0, 16);

function rwFacts(c, D){
  const ev = D.recs.filter(r => r.type !== 'lead'), timed = ev.filter(r => r.ts).sort((a, b) => a.ts - b.ts), H = typeof cpHist === 'function' ? cpHist() : new Map();
  const obs = []; for(const r of timed.concat(ev.filter(r => !r.ts))) for(const o of E.observations(r)) if(o.hot) obs.push({r, o});
  const hosts = countBy(ev.filter(r => r.host), r => r.host).map(x => x[0]);
  const I = typeof cpIndicators === 'function' ? cpIndicators(c.id) : [];
  const malKeys = [...new Set([...D.entries.filter(e => entryVerdict(e) === 'malicious').map(entryKey), ...[...D.ents.keys()].filter(k => verdictOf(k) === 'malicious')].filter(Boolean))];
  const leads = D.recs.filter(r => r.type === 'lead'), open = leads.filter(r => !r.answer), findings = D.recs.filter(r => r.type === 'finding');
  const kinds = new Map(); for(const [key] of D.ents){ const k = key.slice(0, key.indexOf(':')); kinds.set(k, (kinds.get(k) || 0) + 1); }
  const tags = new Set(obs.map(x => x.o.tag)), kind = typeof cpKind === 'function' ? cpKind(D, kinds, tags) : null;
  const beacon = [...D.ents.values()].map(e => ({e, b:E.beaconOf(e.recs.map(r => r.ts))})).find(x => x.b && x.b.regular);
  /* independent confirmation: your verdict plus live lookups that agree */
  const confirmed = malKeys.filter(k => { const h = H.get(k); return h && /malicious|suspicious/.test(h.band); });
  const kev = I.filter(x => x.k === 'cve' && typeof kevOf === 'function' && kevOf(x.v.toUpperCase())).map(x => kevOf(x.v.toUpperCase()));
  return {ev, timed, obs, hosts, I, H, malKeys, confirmed, leads, open, findings, tags, kind, beacon, kev};
}

/* ---------- confidence ---------- */
function rwConfidence(c, D, F){
  let s = 0; const why = [], lim = [];
  if(F.findings.length) { s += Math.min(3, F.findings.length); why.push(F.findings.length + ' recorded finding' + (F.findings.length > 1 ? 's' : '')); }
  const ans = F.leads.length - F.open.length; if(ans) { s += Math.min(2, ans); why.push(ans + ' answered question' + (ans > 1 ? 's' : '')); }
  if(F.malKeys.length){ s += 1; why.push(F.malKeys.length + ' indicator' + (F.malKeys.length > 1 ? 's' : '') + ' judged malicious'); }
  if(F.confirmed.length){ s += Math.min(2, F.confirmed.length); why.push(F.confirmed.length + ' confirmed by live lookups'); }
  if(F.timed.length >= 5){ s += 1; why.push('a timeline of ' + F.timed.length + ' timed records'); }
  const srcs = new Set(F.ev.map(r => (r.source || '').toLowerCase()).filter(Boolean)); if(srcs.size >= 3){ s += 1; why.push(srcs.size + ' separate evidence sources'); }
  /* limitations lower it */
  const noTs = F.ev.filter(r => !r.ts).length, unsure = F.ev.filter(r => r.ts && r.tsZone && r.tsZone !== 'explicit').length, unchecked = F.I.filter(x => !F.H.has(x.key)).length;
  if(F.open.length){ lim.push(F.open.length + ' question' + (F.open.length > 1 ? 's are' : ' is') + ' still open: ' + rwList(F.open.map(r => '“' + r.title + '”'), 2) + '.'); s -= F.open.length > 3 ? 2 : 1; }
  if(noTs && noTs / Math.max(1, F.ev.length) > 0.3){ lim.push(noTs + ' records have no time, so the order of events is partly inferred.'); s -= 1; }
  if(unsure) lim.push(unsure + ' times were read in an assumed time zone (' + tz() + ').');
  if(unchecked) lim.push(unchecked + ' public indicator' + (unchecked > 1 ? 's were' : ' was') + ' not checked against external sources.');
  if(srcs.size <= 1 && F.ev.length) { lim.push('The evidence comes from a single source.'); s -= 1; }
  const conflicts = F.I.filter(x => { const h = F.H.get(x.key), v = verdictOf(x.key); return h && ((h.band === 'malicious' && v === 'benign') || (h.band === 'benign' && h.score < 15 && v === 'malicious')); });
  if(conflicts.length){ lim.push('Live lookups disagree with the verdict on ' + rwList(conflicts.map(x => x.v), 2) + '.'); s -= 1; }
  if(c.ach && c.ach.hyps && c.ach.hyps.length > 1){ const A = achScore(c.ach); if(A.rank.length > 1 && Math.abs(A.rank[0].inc - A.rank[1].inc) < 1) lim.push('Competing hypotheses are close: “' + A.rank[0].h.t + '” and “' + A.rank[1].h.t + '”.'); }
  const level = s >= 7 ? 'high' : s >= 3 ? 'moderate' : 'low';
  return {level, why, lim, score:s};
}

/* ---------- bottom line ---------- */
function rwBottomLine(c, D, F, C, red){
  if(!F.ev.length && !D.entries.length) return 'Nothing to assess yet.';
  const S = [];
  const span = F.timed.length ? ` between ${rwDay(F.timed[0].ts)} and ${rwDay(F.timed[F.timed.length - 1].ts)} ${tz()}` : '';
  const what = F.kind && RW_KIND[F.kind] ? RW_KIND[F.kind] : F.malKeys.length ? 'malicious activity' : 'activity that is not yet explained';
  const hit = [...new Set(F.obs.filter(x => x.r.host && RW_ENDPOINT.test(x.o.tag)).map(x => x.r.host))], where = hit.length ? hit : F.hosts;
  S.push(where.length ? `${what.replace(/^./, ch => ch.toUpperCase())} affected ${rwList(where.map(red), 3)}${span}.` : `The evidence points to ${what}${span}.`);
  const seen = []; for(const x of F.obs) if(RW_TAG[x.o.tag] && !seen.includes(RW_TAG[x.o.tag][0])) seen.push(RW_TAG[x.o.tag][0]);
  if(seen.length || F.beacon) S.push(`It involved ${rwList(seen, 4) || 'network traffic'}${F.beacon ? `${seen.length ? ', with' : ' with'} an implant calling ${red(F.beacon.e.v)} every ${E.fmtGap(F.beacon.b.mean)}` : ''}.`);
  if(F.malKeys.length) S.push(`${F.malKeys.length} indicator${F.malKeys.length > 1 ? 's are' : ' is'} judged malicious — ${rwList(F.malKeys.map(k => red(entSplit(k).v)), 3)}${F.confirmed.length ? `; ${F.confirmed.length} of them confirmed by external sources` : ''}.`);
  if(F.kev.length) S.push(`${rwList(F.kev.map(k => k.cve), 2)} ${F.kev.length > 1 ? 'are' : 'is'} exploited in the wild (CISA KEV).`);
  if(F.findings.length) S.push(`Key finding: ${red(F.findings[0].title)}.`);
  S.push(F.open.length ? `${F.open.length} question${F.open.length > 1 ? 's remain' : ' remains'} open, notably “${red(F.open[0].title)}”.` : F.leads.length ? 'All recorded questions are answered.' : '');
  return S.filter(Boolean).join(' ');
}

/* ---------- attack path ---------- */
function rwAttackPath(D, F){
  if(typeof ATTACK === 'undefined') return [];
  const order = new Map(ATTACK.tactics.map((t, i) => [t[1], i])), name = new Map(ATTACK.tactics.map(t => [t[1], t[2]])), tech = new Map(ATTACK.tech.map(t => [t[0], t]));
  const first = new Map();
  const put = (tac, r, what) => { if(!order.has(tac)) return; const o = first.get(tac); if(!o || (r.ts && (!o.r.ts || r.ts < o.r.ts))) first.set(tac, {r, what}); };
  for(const x of F.obs){ const ids = x.o.t.match(/T\d{4}(?:\.\d{3})?/g) || [];
    for(const id of ids){ const t = tech.get(id) || tech.get(id.split('.')[0]); if(t) for(const tac of t[2]) put(tac, x.r, id + ' ' + t[1]); }
    if(!ids.length && RW_TAG[x.o.tag]) put(RW_TAG[x.o.tag][1], x.r, RW_TAG[x.o.tag][0]); }
  for(const r of F.ev) for(const e of r.ents || []) if(e.k === 'ttp'){ const t = tech.get(e.v.toUpperCase()); if(t) for(const tac of t[2]) put(tac, r, t[0] + ' ' + t[1]); }
  return [...first.entries()].sort((a, b) => order.get(a[0]) - order.get(b[0])).map(([tac, x]) => ({tac:name.get(tac), r:x.r, what:x.what}));
}

/* ---------- recommendations ---------- */
function rwRecs(c, D, F){
  const R = [], add = (when, key, t, why, items) => R.push({when, key, t, why, items:items || []});
  const kv = k => entSplit(k).v, mal = F.malKeys, net = mal.filter(k => /^(ipv4|ipv6|domain|url|hostport)$/.test(entSplit(k).k)), hashes = mal.filter(k => /^(md5|sha1|sha256)$/.test(entSplit(k).k));
  const emails = mal.filter(k => entSplit(k).k === 'email'), infected = [...new Set(F.obs.filter(x => RW_ENDPOINT.test(x.o.tag) && x.r.host).map(x => x.r.host))];
  if(infected.length) add('now', 'isolate', `Isolate and image ${rwList(infected, 3)}`, 'Evidence of ' + rwList([...new Set(F.obs.filter(x => infected.includes(x.r.host)).map(x => (RW_TAG[x.o.tag] || [x.o.tag])[0]))], 3) + ' on ' + (infected.length > 1 ? 'these hosts' : 'this host') + '. Capture memory before rebooting.');
  if(net.length) add('now', 'block', `Block ${net.length} network indicator${net.length > 1 ? 's' : ''} at the proxy, firewall and DNS`, 'Judged malicious in this case' + (F.beacon ? '; an implant is calling out' : '') + '.', net.map(kv));
  if(F.kind === 'pb-phish' || emails.length) add('now', 'purge', 'Remove the phishing message from every mailbox and block the sender', (emails.length ? 'Sender ' + rwList(emails.map(kv), 2) + ' is malicious. ' : '') + 'Find everyone who received or clicked it.', emails.map(kv));
  if(F.kind === 'pb-login' || F.kind === 'pb-cloudir' || F.kind === 'pb-phish') add('now', 'creds', 'Reset credentials and revoke sessions for the affected accounts', F.kind === 'pb-phish' ? 'Phishing is usually after passwords; assume anything typed after the click is known.' : 'Sign-in abuse shows the credentials are known to the attacker. Enforce MFA.');
  if(hashes.length) add('next', 'hunt', `Hunt for ${hashes.length} file hash${hashes.length > 1 ? 'es' : ''} across all endpoints`, 'The same files elsewhere mean the intrusion is wider than ' + (infected[0] || 'the hosts seen so far') + '.', hashes.map(kv));
  if(F.tags.has('persistence')) add('next', 'persist', 'Remove persistence before returning hosts to service', 'Scheduled tasks, services or run keys were set up to start again after a reboot.');
  for(const k of F.kev.slice(0, 5)) add('now', 'kev:' + k.cve, `Patch ${k.cve}${k.vendor ? ' (' + k.vendor + ' ' + k.product + ')' : ''}`, 'Exploited in the wild' + (k.ransom ? ', including by ransomware' : '') + (k.due ? '. CISA set a remediation deadline of ' + k.due + ' for US federal agencies.' : '.'));
  if(F.tags.has('anti-forensics')) add('next', 'logs', 'Preserve what logs remain and forward them off the hosts', 'Event logs were cleared; what is left is the only record.');
  const regDoms = D.entries.filter(e => e.type === 'domain' && entryVerdict(e) === 'malicious');
  if(regDoms.length){ const ab = regDoms.map(e => { const res = typeof lkKnown === 'function' ? lkKnown('domain', primary(e)) : {}, A = typeof lkMerge === 'function' ? lkMerge(res) : {}; return (e.fields.registrar && e.fields.registrar !== '—' ? e.fields.registrar : A.registrar) || ''; }).filter(Boolean);
    add('next', 'takedown', `Report ${regDoms.length > 1 ? regDoms.length + ' domains' : primary(regDoms[0])} for takedown`, ab.length ? 'Send the evidence to the registrar\'s abuse desk (' + rwList([...new Set(ab)], 2) + ').' : 'Find the registrar with an RDAP lookup and send the evidence to its abuse desk.', regDoms.map(primary)); }
  const rules = (DB.rules || []).filter(r => r.caseId === c.id);
  if(mal.length) add('next', 'detect', rules.length ? `Deploy the ${rules.length} detection rule${rules.length > 1 ? 's' : ''} written for this case` : 'Write detections for the malicious indicators', rules.length ? rwList(rules.map(r => r.title), 2) + '.' : 'Detections → From case drafts a Sigma rule for the network indicators and a YARA rule for the files.');
  const unw = mal.filter(k => !isWatched(k)); if(mal.length) add('later', 'watch', 'Keep watching the malicious indicators', unw.length ? unw.length + ' are not on the watchlist yet; new sightings and changes will be flagged.' : 'They are on the watchlist; new sightings and changes will be flagged.');
  if(F.open.length) add('later', 'questions', `Answer the ${F.open.length} open question${F.open.length > 1 ? 's' : ''}`, rwList(F.open.map(r => '“' + r.title + '”'), 3) + '.');
  if(F.malKeys.length) add('later', 'lessons', 'Review how it got in and what would have caught it sooner', 'Turn the attack path into a control or a detection for each stage.');
  return R;
}

/* ---------- into the report model ---------- */
const RW_WHEN = {now:'Now', next:'Next', later:'Later'};
function rwSections(c, D, red, tpl){
  const F = rwFacts(c, D), C = rwConfidence(c, D, F), bl = c.rep && c.rep.bl ? c.rep.bl : rwBottomLine(c, D, F, C, red);
  const off = new Set((c.rep && c.rep.off) || []), recs = rwRecs(c, D, F).filter(r => !off.has(r.key));
  const path = rwAttackPath(D, F);
  return {F, C, bl, edited:!!(c.rep && c.rep.bl), recs, path, hidden:off.size};
}

/* ---------- Word (.docx) export of the report ---------- */
function reportDocHtml(c, D, M, tplName){
  const ci = x => x && x.n ? ` [${x.n}]` : '';
  const L = [`<h1>${esc(M.red(c.name))}</h1><p class="nbx-meta">${esc(tplName)} report · ${esc(tz())}${UI.redact ? ' · redacted' : ''} · ${esc(E.fmtDate(Date.now(), tz()))}</p>`];
  for(const s of M.S){ L.push(`<h2>${esc(s.h)}</h2>`); const rows = s.items.filter(it => it.k === 'row'), recs = s.items.filter(it => it.k === 'rec');
    for(const it of s.items){ if(it.k === 'p') L.push(`<p>${it.b ? '<b>' + esc(it.b) + '</b>' : ''}${esc(it.t)}${ci(it.c)}</p>`);
      else if(it.k === 'bl') L.push(`<div class="nbx-call"><p><b>Bottom line (${esc(RW_CONF[it.level])}).</b> ${esc(it.t)}</p></div>`);
      else if(it.k === 'step') L.push(`<p><b>${it.n}. ${esc(it.t)}</b>${ci(it.c)}</p>${it.body && it.body !== it.t ? '<pre>' + esc(it.body) + '</pre>' : ''}`);
      else if(it.k === 'map'){ const svg = reportMap(c, D, M.red); if(svg) L.push(`<figure><img alt="Relationship map" src="data:image/svg+xml;base64,${btoa(unescape(encodeURIComponent(svg)))}"><figcaption>Relationship map — red rings mark malicious entries.</figcaption></figure>`); }
      else if(it.k === 'src') L.push(`<p>[${it.n}] ${esc(it.t)} · ${esc(it.s)} · sha256 ${esc(it.h)}…</p>`); }
    if(rows.length) L.push(`<table><tr><th>${esc(s.cols ? s.cols[0] : '')}</th><th>${esc(s.cols ? s.cols[1] : '')}</th></tr>${rows.map(r => `<tr><td>${esc(r.l)}</td><td>${esc(r.t)}${ci(r.c)}</td></tr>`).join('')}</table>`);
    if(recs.length) L.push(`<table><tr><th>When</th><th>Action</th><th>Why</th></tr>${recs.map(r => `<tr><td>${esc(RW_WHEN[r.when])}</td><td><b>${esc(r.t)}</b>${r.items.length ? '<br>' + esc(rwList(r.items, 6)) : ''}</td><td>${esc(r.why)}</td></tr>`).join('')}</table>`);
  }
  return L.join('');
}
async function reportDocx(){
  const c = theCase(), D = derive(), tpl = DB.prefs.repT || (c.id === 'c-lab' ? 'ctf' : 'full'), M = reportModel(c, D, tpl, !!UI.redact), name = REP_T.find(x => x[0] === tpl)[1];
  toast('Building the Word file…');
  try{ const blob = await nbDocx({title:M.red(c.name)}, reportDocHtml(c, D, M, name)); const a = document.createElement('a'), u = URL.createObjectURL(blob); a.href = u; a.download = safeName(slug(c.name) + '-report.docx'); document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(u), 4000); toast('Word file ready'); }
  catch(e){ console.error(e); toast('Could not build the Word file: ' + e.message); }
}

/* ---------- editing ---------- */
function repEditDlg(){
  const c = theCase(), D = derive(), M = rwSections(c, D, redactor(D, false), 'full'), draft = rwBottomLine(c, D, M.F, M.C, s => String(s));
  openDlg(dhead('Edit the bottom line') + `<form data-form="repBL"><div class="in"><p class="t2" style="margin:0 0 10px">The draft is written from the case. Rewrite it in your own words; the report uses yours until you reset it.</p>
    <div class="field"><label for="repBLt">Bottom line</label><textarea id="repBLt" class="inp" rows="8" maxlength="3000">${esc(c.rep && c.rep.bl || draft)}</textarea></div>
    <details><summary class="t3">The draft</summary><p class="t2" style="font-size:calc(13.5px * var(--ts,1))">${esc(draft)}</p></details></div>
    <footer>${c.rep && c.rep.bl ? `<button class="btn ghost" type="button" data-act="repBLReset" style="margin-right:auto">${ico('refresh-cw','sm')}Use the draft</button>` : ''}<button class="btn" type="button" data-act="dclose">Cancel</button><button class="btn primary" type="submit">Save</button></footer></form>`);
}
const RW_ACTS = {
  repEdit:() => repEditDlg(),
  repBLReset:() => { const c = theCase(); if(c.rep) delete c.rep.bl; closeDlg(); mutate('report bottom line reset to the draft'); renderMain(); },
  repRecOff:(id) => { const c = theCase(); c.rep = c.rep || {}; c.rep.off = [...new Set([...(c.rep.off || []), id])]; mutate('dropped a recommendation'); renderMain(); toast('Recommendation dropped', 'Undo', () => { c.rep.off = c.rep.off.filter(x => x !== id); mutate('undo'); renderMain(); }); },
  repRecAll:() => { const c = theCase(); if(c.rep) c.rep.off = []; mutate('restored recommendations'); renderMain(); },
  exportDocx:() => reportDocx(),
};
