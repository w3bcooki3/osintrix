/* ==========================================================================
   Threat Intel — Overview, and the story panel
     • What stands out: four findings worked out from your stories, your cases, your stack
       and your rules (known-exploited flaws in what you run, news indicators already in your
       evidence, how much of a named group your rules cover, the thinnest-covered technique)
     • Actors & malware, known-exploited vulnerabilities, techniques against your rules
     • The stories, when they were published, which cases they touch and where they came from
     • The story panel: why it matters to you first, then the source's own summary, a link to
       the original, and previous / next through the list you opened it from
   Everything is computed in the page from what is already stored; nothing is fetched here.
   ========================================================================== */
const TIO = {key:'', d:null, shown:'', dir:0};
const TIO_SEV = {critical:3, high:2, medium:1};
const tioPct = (a, b) => b ? Math.round(a / b * 100) : 0;
const tioPl = (n, one, many) => n + ' ' + (n === 1 ? one : many || one + 's');
const tioRel = ts => { const d = Math.max(0, Date.now() - ts) / 864e5; return d < 1 ? 'today' : d < 2 ? 'yesterday' : d < 45 ? Math.floor(d) + ' days ago' : d < 548 ? Math.round(d / 30.4) + ' months ago' : Math.round(d / 365) + ' years ago'; };
const tioShort = ts => new Date(ts).toLocaleDateString(undefined, Date.now() - ts < 300 * 864e5 ? {day:'numeric', month:'short'} : {day:'numeric', month:'short', year:'numeric'});

/* how many of your rules are tagged with a technique — a rule for the parent technique covers its sub-techniques */
function tioRuleIdx(){
  const m = new Map(); if(typeof ruleTechs !== 'function') return m;
  for(const r of DB.rules || []) for(const id of ruleTechs(r)){ if(!m.has(id)) m.set(id, new Set()); m.get(id).add(r.id); }
  return m;
}
const tioRulesFor = (R, id) => { const s = new Set(R.get(id) || []); if(id.includes('.')) (R.get(id.split('.')[0]) || []).forEach(x => s.add(x)); return s.size; };

function tioData(){
  const key = [rev, DB.feed.length, CTI.kevMeta && CTI.kevMeta.v, JSON.stringify(DB.intel.stack), (DB.rules || []).length, typeof ATTACK !== 'undefined' ? ATTACK.v : ''].join('|');
  if(TIO.key === key && TIO.d) return TIO.d;
  const D = ctiDict(), g = globalEnts(), R = tioRuleIdx();
  const S = ctiStories(DB.feed.filter(f => triage(f) !== 'dismissed')).sort((a, b) => b.ts - a.ts);
  const ind = new Map(), perCase = new Map(), kev = new Map(), act = new Map(), tech = new Map(), notKev = new Set();
  for(const st of S){
    const X = st.items.map(ctiX), mine = storyMine(st);
    st.mine = mine; st.cve = [...new Set(X.flatMap(x => x.cve))]; st.kevs = st.cve.filter(c => kevOf(c));
    st.acts = [...new Set(X.flatMap(x => [...x.act, ...x.mal]))]; st.ttps = [...new Set(X.flatMap(x => x.ttp))];
    st.sev = st.items.reduce((m, f) => (TIO_SEV[f.sev] || 0) > (TIO_SEV[m] || 0) ? f.sev : m, 'normal');
    st.unread = st.items.some(f => !f.read); st.caseIds = new Set();
    for(const k of mine.hits){ const e = g.get(k); if(!e) continue; ind.set(k, e.cases);
      for(const c of e.cases){ st.caseIds.add(c); if(!perCase.has(c)) perCase.set(c, {ind:new Set(), st:new Set()}); perCase.get(c).ind.add(k); perCase.get(c).st.add(st.lead.id); } }
    for(const c of st.cve){ const k = kevOf(c); if(!k){ notKev.add(c); continue; } const r = kev.get(c) || {c, k, n:0, stack:ctiInStack(k.vendor, k.product)}; r.n++; kev.set(c, r); }
    st.stackKev = st.kevs.some(c => kev.get(c).stack);
    for(const id of st.acts){ const a = act.get(id) || {id, n:0, last:0}; a.n++; a.last = Math.max(a.last, st.ts); act.set(id, a); }
    for(const id of st.ttps){ const t = tech.get(id) || {id, n:0}; t.n++; tech.set(id, t); }
  }
  /* groups: the techniques ATT&CK lists for them, against the techniques your rules are tagged with */
  const cov = id => { const x = D.grp.get(id); if(!x || !(x.t || []).length) return null; return {n:x.t.length, cov:x.t.filter(t => tioRulesFor(R, t)).length}; };
  const actors = [...act.values()].map(a => { const x = D.grp.get(a.id) || D.soft.get(a.id); return x ? {...a, x, g:/^G/.test(a.id), cov:cov(a.id)} : null; }).filter(Boolean).sort((a, b) => b.n - a.n || b.last - a.last);
  const groups = actors.filter(a => a.cov).sort((a, b) => a.cov.cov / a.cov.n - b.cov.cov / b.cov.n);
  const tacOrder = typeof ATTACK !== 'undefined' ? ATTACK.tactics.map(t => t[1]) : [];
  const techs = [...tech.values()].map(t => { const T = D.tech.get(t.id) || D.tech.get(t.id.split('.')[0]); return {...t, name:T ? T[1] : '', tac:T ? T[2][0] : '', rules:tioRulesFor(R, t.id)}; })
    .sort((a, b) => (tacOrder.indexOf(a.tac) - tacOrder.indexOf(b.tac)) || b.n - a.n);
  const kevRows = [...kev.values()].sort((a, b) => b.stack - a.stack || a.k.due.localeCompare(b.k.due));
  const byMonth = new Map(); for(const st of S){ const m = new Date(st.ts).toISOString().slice(0, 7); if(!byMonth.has(m)) byMonth.set(m, new Map()); const b = byMonth.get(m); b.set(st.lead.cat, (b.get(st.lead.cat) || 0) + 1); }
  const bySrc = countBy(S, st => st.sources);
  return TIO.key = key, TIO.d = {S, ind, perCase, kevRows, notKev:[...notKev], actors, groups, techs, byMonth, bySrc, ruleN:(DB.rules || []).length};
}

const TIO_F = [['all','All'], ['unread','Unread'], ['cases','In my cases'], ['stack','My stack'], ['kev','Known exploited'], ['critical','Critical']];
const tioFilt = (st, k) => k === 'unread' ? st.unread : k === 'cases' ? st.caseIds.size > 0 : k === 'stack' ? st.stackKev || st.mine.stack.length > 0 : k === 'kev' ? st.kevs.length > 0 : k === 'critical' ? st.sev === 'critical' : true;

function ctiOverView(){
  const T = tioData(), S = T.S;
  if(!S.length) return empty('newspaper', 'No stories yet', DB.prefs.liveFeeds ? 'Refresh to pull the latest from your sources.' : 'Go live to pull the latest from your sources, or import an RSS/Atom file in Sources.',
    `<button class="btn primary" data-act="feedRefresh">${ico('wifi','sm')}Go live</button>`);
  const f = UI.tiof || 'all', L = S.filter(st => tioFilt(st, f)), lim = 12;
  UI.tioNav = L.map(st => st.lead.id);
  /* the four findings */
  const stack = DB.intel.stack || [], sk = T.kevRows.filter(r => r.stack), prods = [...new Set(sk.map(r => r.k.product.split(/\s+/)[0]))];
  const tile = (icon, k, v, unit, p, go, extra = '') => `<article class="tio-tk"><span class="k">${ico(icon,'sm')}${k}</span><div class="v">${v}<small>${unit}</small></div><p>${p}</p>${extra}${go || ''}</article>`;
  const goBtn = (act, v, l) => `<button class="tio-go" data-act="${act}"${v ? ` data-v="${esc(v)}"` : ''}>${l}${ico('arrow-right','sm')}</button>`;
  const t1 = !stack.length ? tile('server', 'Your stack', '—', 'no products listed', 'List the vendors and products you run; known-exploited flaws in them are flagged here and in every story.', goBtn('ctiVulnStack', '', 'Add your products'))
    : tile('server', 'Your stack', prods.length, prods.length === 1 ? 'product you run is exploited' : 'products you run are exploited',
      sk.length ? `In the news: ${esc(prods.slice(0, 4).join(', '))} — ${sk.every(r => Date.parse(r.k.due) < Date.now()) ? 'every CISA deadline has passed' : sk.filter(r => Date.parse(r.k.due) < Date.now()).length + ' of ' + sk.length + ' CISA deadlines passed'}${sk.every(r => r.k.ransom) ? ', and all are used by ransomware' : sk.some(r => r.k.ransom) ? '; ' + sk.filter(r => r.k.ransom).length + ' used by ransomware' : ''}.`
        : `None of the ${tioPl(T.kevRows.length, 'known-exploited CVE')} in your stories affect the ${tioPl(stack.length, 'product')} you listed.`, sk.length ? goBtn('tioGo', 'tioKev', 'See the flaws') : goBtn('ctiVulnStack', '', 'Your stack'));
  const multi = [...T.ind.values()].filter(cs => cs.size > 1).length, hitSt = S.filter(st => st.caseIds.size).length;
  const t2 = tile('crosshair', 'Your evidence', T.ind.size, T.ind.size === 1 ? 'news indicator in your cases' : 'news indicators in your cases',
    T.ind.size ? `${[...T.perCase.entries()].slice(0, 3).map(([c, v]) => `${esc(caseNm(theCase(c), 28))} (${v.ind.size})`).join(', ')}${multi ? ` — ${multi} in more than one case` : ''}; from ${tioPl(hitSt, 'story', 'stories')}.` : 'No IP, domain, hash or URL from your stories appears in any case yet. Every new story is checked as it arrives.',
    T.ind.size ? goBtn('tioCases', '', 'Show those stories') : goBtn('itab', 'iocs', 'Indicators'));
  const g0 = T.groups[0];
  const t3 = g0 ? tile('users', 'Actor coverage', tioPct(g0.cov.cov, g0.cov.n) + '%', `of ${esc(g0.x.n)}’s techniques`,
      `Your rules cover ${g0.cov.cov} of the ${g0.cov.n} techniques ATT&amp;CK lists for ${esc(g0.x.n)}${T.groups.length > 1 ? ` — the least covered group in your stories (${T.groups.slice(1, 3).map(g => esc(g.x.n) + ' ' + tioPct(g.cov.cov, g.cov.n) + '%').join(', ')})` : ''}.`,
      goBtn('actor', g0.id, 'Open ' + esc(g0.x.n)), `<span class="tio-m" aria-hidden="true"><i style="width:${tioPct(g0.cov.cov, g0.cov.n)}%"></i></span>`)
    : tile('users', 'Actor coverage', '—', 'no groups named', 'When a story names an ATT&amp;CK group, its techniques are checked against your rules here.', goBtn('itab', 'attack', 'Actors &amp; ATT&amp;CK'));
  const tw = T.techs.slice().sort((a, b) => a.rules - b.rules || b.n - a.n)[0], rest = tw ? T.techs.filter(t => t !== tw) : [];
  const t4 = tw ? tile('grid-3x3', 'Thinnest rule', tw.rules, `rule${tw.rules === 1 ? '' : 's'} for ${esc(tw.id)}`,
      `${esc(tw.name || tw.id)} — named in ${tioPl(tw.n, 'story', 'stories')}${rest.length ? `; ${rest.every(t => t.rules > tw.rules) ? 'every other technique in the news has ' + Math.min(...rest.map(t => t.rules)) + ' or more' : rest.filter(t => t.rules === tw.rules).length + ' more at the same count'}` : ''}.`,
      goBtn('tioRule', tw.id, 'Start a rule for it'))
    : tile('grid-3x3', 'Thinnest rule', '—', 'no techniques named', 'Stories that name ATT&amp;CK technique IDs such as T1190 are checked against your rules here.', '');
  /* the three boxes */
  const mxR = Math.max(1, ...T.techs.map(t => t.rules)), tacName = Object.fromEntries((typeof ATTACK !== 'undefined' ? ATTACK.tactics : []).map(t => [t[1], t[2]]));
  let lastTac = null;
  const months = [...T.byMonth.keys()].sort().slice(-8), mxM = Math.max(1, ...months.map(m => [...T.byMonth.get(m).values()].reduce((a, b) => a + b, 0))), usedCats = [...new Set(months.flatMap(m => [...T.byMonth.get(m).keys()]))];
  const match = st => [st.caseIds.size ? `<span class="acc">${[...st.caseIds].map(c => esc(caseNm(theCase(c), 24))).join(', ')}</span>` : '', st.stackKev || st.mine.stack.length ? `<span class="acc">your ${esc((st.mine.stack.length ? st.mine.stack : st.kevs.filter(c => T.kevRows.find(r => r.c === c && r.stack)).map(c => kevOf(c).product)).join(', '))}</span>` : ''].filter(Boolean).join(' · ') || '<span class="t3">—</span>';
  const sel = UI.sel && UI.sel.kind === 'feed' ? UI.sel.id : '';
  return `<div class="tio">
    <div class="tio-sec"><h2>What stands out</h2><span>worked out from your ${tioPl(S.length, 'story', 'stories')}, your cases, your stack and your rules</span></div>
    <div class="tio-take">${t1}${t2}${t3}${t4}</div>
    <div class="tio-three">
      <section class="tio-box"><h3>Actors &amp; malware<small>named in your stories · ATT&amp;CK</small></h3>
        ${T.actors.length ? T.actors.slice(0, 7).map(a => `<button class="tio-lr" data-act="actor" data-v="${esc(a.id)}"><span>${esc(a.x.n)} <small>· ${a.g ? 'Group' : a.x.k === 't' ? 'Tool' : 'Malware'} ${esc(a.id)}</small></span><span class="n" title="Stories">${a.n}</span>${a.cov ? `<span class="cv"><span class="tio-m"><i style="width:${tioPct(a.cov.cov, a.cov.n)}%"></i></span><span>rules cover ${a.cov.cov} of ${a.cov.n}</span></span>` : `<small class="sub">${a.x.a.length ? 'also ' + esc(a.x.a.slice(0, 2).join(', ')) + ' · ' : ''}last ${esc(tioShort(a.last))}</small>`}</button>`).join('')
          : '<p class="tio-none">No ATT&amp;CK group or malware is named in your stories.</p>'}
        <div class="ft">Coverage: the group’s techniques in ATT&amp;CK against the techniques your rules are tagged with.</div></section>
      <section class="tio-box tio-kt" id="tioKev"><h3>Known-exploited vulnerabilities<small>CISA KEV ${esc(CTI.kevMeta ? CTI.kevMeta.v : '')}</small></h3>
        ${T.kevRows.length ? `<table><thead><tr><th>CVE</th><th>Product</th><th>CISA due</th><th>Your stack</th></tr></thead><tbody>${T.kevRows.slice(0, 7).map(r => { const past = Date.parse(r.k.due) < Date.now(); return `<tr data-act="ctiCve" data-v="${esc(r.c)}" tabindex="0"><td class="mono nw">${esc(r.c)}<small>${tioPl(r.n, 'story', 'stories')}</small></td><td>${esc(r.k.vendor)}<small>${esc(r.k.product)}${r.k.ransom ? ' · used by ransomware' : ''}</small></td><td class="nw${past ? ' past' : ''}">${esc(r.k.due)}<small>${past ? 'passed' : 'open'}</small></td><td class="nw">${r.stack ? '<b class="acc">Yes</b>' : '<span class="t3">No</span>'}</td></tr>`; }).join('')}</tbody></table>`
          : '<p class="tio-none">No CVE in your stories is in the KEV catalogue.</p>'}
        <div class="ft">${T.kevRows.length > 7 ? `${T.kevRows.length - 7} more in Vulnerabilities. ` : ''}${T.notKev.length ? `Not in KEV: <span class="mono">${esc(T.notKev.slice(0, 4).join(', '))}${T.notKev.length > 4 ? '…' : ''}</span>. ` : ''}EPSS and CVSS appear in Vulnerabilities once those lookups are on in Sources.</div></section>
      <section class="tio-box"><h3>Techniques vs your rules<small>${tioPl(T.ruleN, 'rule')}</small></h3><div class="tio-tq">
        ${T.techs.length ? T.techs.slice(0, 12).map(t => { const h = t.tac !== lastTac ? `<div class="tac">${esc(tacName[t.tac] || 'Other')}</div>` : ''; lastTac = t.tac;
          return h + `<button class="tio-trw${t.rules < 2 ? ' low' : ''}" data-act="ctiTech" data-v="${esc(t.id)}"><span class="mono">${esc(t.id)}</span><span class="nm" title="${esc(t.name)}">${esc(t.name)}</span><span class="b"><s><u style="width:${t.rules / mxR * 100}%"></u></s>${t.rules}</span></button>`; }).join('')
          : '<p class="tio-none" style="padding:0">No technique IDs in your stories.</p>'}</div>
        <div class="ft">Techniques named in the stories, and how many of your rules are tagged with each.</div></section>
    </div>
    <div class="tio-bot">
      <section class="tio-tbl" id="tioStories"><div class="th"><h3>Stories</h3><div class="tio-f" role="group" aria-label="Show">${TIO_F.map(([k, l]) => { const n = S.filter(st => tioFilt(st, k)).length; return `<button data-act="tiof" data-v="${k}" aria-pressed="${f === k}">${l}<small>${n}</small></button>`; }).join('')}</div></div>
        ${L.length ? `<table><thead><tr><th><span class="sr">Unread</span></th><th>Date</th><th>Story</th><th>Severity</th><th>Matches</th></tr></thead><tbody>${L.slice(0, lim).map(st => `<tr class="${st.items.some(i => i.id === sel) ? 'on' : ''}" data-act="selFeed" data-id="${st.lead.id}" tabindex="0"><td class="u"><span class="tio-dot${st.unread ? '' : ' r'}"></span></td><td class="w">${esc(tioShort(st.ts))}</td><td><b>${esc(st.lead.title)}</b><small>${esc(st.sources[0])}${st.sources.length > 1 ? ' and ' + (st.sources.length - 1) + ' more' : ''}</small></td><td class="w"><span class="tio-sev ${esc(st.sev)}">${st.sev === 'normal' ? '—' : esc(st.sev[0].toUpperCase() + st.sev.slice(1))}</span></td><td class="m">${match(st)}</td></tr>`).join('')}</tbody></table>
          ${L.length > lim ? `<button class="tio-more" data-act="itab" data-v="feed">All ${L.length} in News ${ico('arrow-right','sm')}</button>` : ''}` : '<p class="tio-none">No stories match.</p>'}</section>
      <aside class="tio-side">
        <section class="tio-box"><h3>When they were published<small>stories per month</small></h3><div class="tio-chart">
          <div class="bars">${months.map(m => `<div title="${esc(m)}">${[...T.byMonth.get(m).entries()].map(([c, n]) => `<i style="height:${Math.max(3, n / mxM * 88)}px;background:${catMeta(c).col}" title="${esc(catMeta(c).name)}: ${n}"></i>`).join('')}</div>`).join('')}</div>
          <div class="bx">${months.map(m => `<span>${esc(new Date(m + '-15').toLocaleDateString(undefined, {month:'short'}))} ${m.slice(2, 4)}</span>`).join('')}</div>
          <div class="lg">${usedCats.map(c => `<span><i style="background:${catMeta(c).col}"></i>${esc(catMeta(c).name)}</span>`).join('')}</div></div></section>
        <section class="tio-box"><h3>Your cases in the news</h3>${T.perCase.size ? [...T.perCase.entries()].map(([c, v]) => `<a class="tio-cs" href="${caseHash(c, 'overview')}"><b>${esc(caseNm(theCase(c)))}</b><small>${tioPl(v.ind.size, 'indicator')} in ${tioPl(v.st.size, 'story', 'stories')}</small></a>`).join('') : '<p class="tio-none">No case shares an indicator with your stories.</p>'}</section>
        <section class="tio-box"><h3>Sources<small>stories</small></h3><div class="tio-kv">${T.bySrc.slice(0, 8).map(([s, n]) => `<button data-act="tioSrc" data-v="${esc(s)}"><span>${esc(s)}</span><b>${n}</b></button>`).join('')}</div></section>
      </aside>
    </div></div>`;
}

/* ---------- the story panel ---------- */
function inspFeed(f){
  if(!f) return '';
  if(!f.read){ f.read = true; save(); }
  const g = globalEnts(), x = ctiX(f), others = ctiStoryOf(f.id).filter(o => o && o !== f), all = [f, ...others], t = f.st || 'new', m = catMeta(f.cat);
  const X = all.map(ctiX), cve = [...new Set(X.flatMap(y => y.cve))], acts = [...new Set(X.flatMap(y => [...y.act, ...y.mal]))], ttps = [...new Set(X.flatMap(y => y.ttp))], D = ctiDict(), R = tioRuleIdx();
  const iocs = [...new Map(X.flatMap(y => y.iocs).map(e => [entKey(e), e])).values()], mine = iocs.filter(e => g.has(entKey(e)));
  /* previous / next through the list it was opened from */
  const nav = (UI.route.area === 'feeds' && (UI.itab || 'over') === 'over' ? UI.tioNav : null) || (typeof ctiFeedList === 'function' ? ctiFeedList().map(st => st.lead.id) : []);
  const at = nav.findIndex(id => all.some(i => i.id === id));
  /* why it matters to you */
  const why = [];
  if(mine.length){ const cs = new Set(mine.flatMap(e => [...g.get(entKey(e)).cases]));
    why.push(`<div class="st-w hot"><span class="i">${ico('crosshair','sm')}</span><div><b>${tioPl(mine.length, 'indicator')} already in ${[...cs].map(c => esc(caseNm(theCase(c), 28))).join(', ')}</b><div class="wrap">${mine.slice(0, 6).map(e => entPill(entKey(e))).join('')}</div></div></div>`); }
  for(const c of cve.filter(c => kevOf(c)).slice(0, 3)){ const k = kevOf(c), past = Date.parse(k.due) < Date.now(), st = ctiInStack(k.vendor, k.product);
    why.push(`<button class="st-w${st ? ' hot' : ''}" data-act="ctiCve" data-v="${esc(c)}"><span class="i">${ico('shield-alert','sm')}</span><div><b><span class="mono">${esc(c)}</span> is known exploited</b><small>${esc(k.vendor + ' ' + k.product)} · CISA due ${esc(k.due)}${past ? ' (passed)' : ''}${k.ransom ? ' · used by ransomware' : ''}${st ? ' · <em>in your stack</em>' : ''}</small></div>${ico('chevron-right','sm')}</button>`); }
  for(const id of acts.slice(0, 3)){ const a = D.grp.get(id) || D.soft.get(id); if(!a) continue; const isG = /^G/.test(id), n = (a.t || []).length, cv = isG && n ? a.t.filter(tt => tioRulesFor(R, tt)).length : 0;
    why.push(`<button class="st-w" data-act="actor" data-v="${esc(id)}"><span class="i">${ico(isG ? 'users' : 'skull','sm')}</span><div><b>${esc(a.n)}</b><small>${isG ? 'Group' : a.k === 't' ? 'Tool' : 'Malware'} ${esc(id)}${isG && n ? ` · your rules cover ${cv} of its ${n} techniques` : a.a.length ? ' · also ' + esc(a.a.slice(0, 2).join(', ')) : ''}</small>${isG && n ? `<span class="tio-m"><i style="width:${tioPct(cv, n)}%"></i></span>` : ''}</div>${ico('chevron-right','sm')}</button>`); }
  if(ttps.length) why.push(`<div class="st-w"><span class="i">${ico('grid-3x3','sm')}</span><div><b>${tioPl(ttps.length, 'technique')} named</b><div class="st-tt">${ttps.slice(0, 6).map(id => { const n = tioRulesFor(R, id), T = D.tech.get(id) || D.tech.get(id.split('.')[0]); return `<button data-act="ctiTech" data-v="${esc(id)}" class="${n < 2 ? 'low' : ''}"><span class="mono">${esc(id)}</span><span class="nm">${esc(T ? T[1] : '')}</span><em>${tioPl(n, 'rule')}</em></button>`; }).join('')}</div></div></div>`);
  /* the source's own summary, as paragraphs; a long one opens on request */
  const paras = String(f.body || '').replace(/\r/g, '').split(/\n\s*\n|\n(?=[A-Z•\-–])/).map(y => y.replace(/\s+/g, ' ').trim()).filter(Boolean), P = paras.length > 1 ? paras : String(f.body || '').replace(/\s+/g, ' ').trim().split(/(?<=[.!?])\s+(?=[A-Z])/).reduce((a, y) => { const l = a[a.length - 1]; if(l && l.length < 320) a[a.length - 1] = l + ' ' + y; else a.push(y); return a; }, []);
  let n = 0, cut = P.findIndex(y => (n += y.length) > 900); if(cut < 1 || P.length - cut < 1) cut = P.length;
  const para = y => `<p>${esc(y)}</p>`, sev = f.sev && f.sev !== 'normal' ? String(f.sev) : '', u = E.safeUrl(f.link);
  const rest = iocs.filter(e => !g.has(entKey(e))), other = cve.filter(c => !kevOf(c)), vens = [...new Set(X.flatMap(y => y.ven))];
  const fresh = TIO.shown !== f.id; TIO.shown = f.id;
  const dir = TIO.dir; TIO.dir = 0;
  return `<div class="ihead st-h"><span class="st-cat" style="--c:${m.col}" aria-hidden="true">${ico(CAT_ICON[f.cat] || 'newspaper','sm')}</span><span class="caps">Story</span>${at >= 0 && nav.length > 1 ? `<span class="st-pos">${at + 1} of ${nav.length}</span>` : ''}<span class="sp"></span>
      ${at >= 0 && nav.length > 1 ? `<button class="iconbtn" data-act="stNav" data-v="-1" aria-label="Previous story" title="Previous (K)" ${at === 0 ? 'disabled' : ''}>${ico('chevron-left')}</button><button class="iconbtn" data-act="stNav" data-v="1" aria-label="Next story" title="Next (J)" ${at === nav.length - 1 ? 'disabled' : ''}>${ico('chevron-right')}</button>` : ''}
      <button class="iconbtn" data-act="closeInsp" aria-label="Close">${ico('x')}</button></div>
    <div class="ibody st-b${fresh ? ' fresh' : ''}" style="--dx:${dir * 18}px">
      <div class="st-tags"><span class="st-chip" style="--c:${m.col}">${esc(m.name)}</span>${sev ? `<span class="story-sev ${esc(sev.toLowerCase())}">${esc(sev[0].toUpperCase() + sev.slice(1))}</span>` : ''}${f.live ? '' : '<span class="iv-sample">Sample</span>'}</div>
      <h2>${esc(f.title)}</h2>
      <div class="story-m"><span class="src">${esc(f.source)}</span>${others.length ? `<span>+${tioPl(others.length, 'more source')}</span>` : ''}<span title="${esc(E.fmtDate(f.ts, tz()))}">${esc(new Date(f.ts).toLocaleDateString(undefined, {day:'numeric', month:'short', year:'numeric'}))}, ${esc(tioRel(f.ts))}</span></div>
      <div class="story-tri"><button class="btn sm${f.star ? ' on' : ''}" data-act="ctiStar" data-id="${f.id}" aria-pressed="${!!f.star}">${ico('star','sm')}${f.star ? 'Starred' : 'Star'}</button><button class="btn sm${t === 'relevant' ? ' on' : ''}" data-act="ctiTri" data-id="${f.id}" data-v="relevant" aria-pressed="${t === 'relevant'}">${ico('check','sm')}Relevant</button><button class="btn sm${t === 'actioned' ? ' on' : ''}" data-act="ctiTri" data-id="${f.id}" data-v="${t === 'actioned' ? 'new' : 'actioned'}" aria-pressed="${t === 'actioned'}">${ico('check-check','sm')}Actioned</button><button class="btn sm" data-act="ctiTri" data-id="${f.id}" data-v="${t === 'dismissed' ? 'new' : 'dismissed'}">${ico(t === 'dismissed' ? 'undo-2' : 'x','sm')}${t === 'dismissed' ? 'Restore' : 'Dismiss'}</button></div>
      <section class="st-why"><h4>${ico('sparkles','sm')}Why it matters to you</h4>${why.length ? why.join('') : '<p class="t3">Nothing here touches your cases, your stack or your rules.</p>'}</section>
      <div class="story-b"><h4>From ${esc(f.source)}</h4>${P.slice(0, cut).map(para).join('')}${cut < P.length ? `<details class="story-more"><summary>Read the rest of the summary</summary>${P.slice(cut).map(para).join('')}</details>` : ''}</div>
      ${rest.length ? `<div class="isec"><h4>Other indicators</h4><div class="wrap">${rest.slice(0, 20).map(e => entPill(entKey(e))).join('')}</div></div>` : ''}
      ${other.length ? `<div class="isec"><h4>Other CVEs</h4><div class="wrap">${other.map(cveChip).join('')}</div></div>` : ''}
      ${vens.length ? `<div class="isec"><h4>Vendors</h4><div class="wrap">${vens.map(venChip).join('')}</div></div>` : ''}
      ${others.length ? `<div class="isec"><h4>Also reported by</h4>${others.map(o => `<button class="li" data-act="selFeed" data-id="${o.id}"><div class="main2"><b>${esc(o.source)}</b><span class="t3">${esc(o.title)}</span></div></button>`).join('')}</div>` : ''}
    </div>
    <div class="st-foot"><button class="btn primary" data-act="feedToCase" data-id="${f.id}">${ico('plus','sm')}Add to ${esc(caseNm(theCase()))}</button>${casePick()}<span class="sp"></span>${u ? `<a class="btn" href="${esc(u)}" target="_blank" rel="noopener noreferrer">Read original ${ico('external-link','sm')}</a>` : '<span class="t3 small" title="Sample stories carry no link">No link to the original</span>'}</div>`;
}
/* the panel is wider for a story, and knows it is one */
{ const ri = renderInsp; renderInsp = function(){ const r = ri.apply(this, arguments), el = $('insp'), on = !!(UI.inspOpen && UI.sel && UI.sel.kind === 'feed'); el.classList.toggle('story', on);
  /* an open story gets the page behind it blurred and dimmed, so it reads on its own; a click there closes it */
  let sc = $('stScrim'); if(on && !sc){ sc = document.createElement('div'); sc.id = 'stScrim'; sc.className = 'st-scrim'; sc.dataset.act = 'closeInsp'; sc.setAttribute('aria-hidden', 'true'); el.parentNode.insertBefore(sc, el); } else if(!on && sc) sc.remove();
  return r; }; }

function tioNavGo(d){
  const s = UI.sel; if(!s || s.kind !== 'feed') return;
  const nav = UI.route.area === 'feeds' && (UI.itab || 'over') === 'over' ? UI.tioNav || [] : ctiFeedList().map(st => st.lead.id), all = ctiStoryOf(s.id).map(f => f && f.id);
  const i = nav.findIndex(id => all.includes(id)), j = i + d; if(i < 0 || j < 0 || j >= nav.length) return;
  TIO.dir = d; select('feed', nav[j]);
  document.querySelectorAll('[data-act=selFeed][aria-current],[data-act=selFeed].on').forEach(r => { r.classList.remove('on'); });
  const row = document.querySelector(`.tio-tbl tr[data-id="${CSS.escape(nav[j])}"], .ti-open[data-id="${CSS.escape(nav[j])}"]`);
  if(row){ if(row.tagName === 'TR') row.classList.add('on'); row.scrollIntoView({block:'nearest', behavior:'smooth'}); }
}
document.addEventListener('keydown', ev => {
  if((ev.key === 'Enter' || ev.key === ' ') && ev.target && ev.target.matches && ev.target.matches('.tio tr[data-act]')){ ev.preventDefault(); ev.target.click(); return; }
  if(ev.ctrlKey || ev.metaKey || ev.altKey || (ev.key !== 'j' && ev.key !== 'k')) return;
  const t = ev.target; if(t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName))) return;
  if(UI.route.area !== 'feeds' || !UI.inspOpen || !UI.sel || UI.sel.kind !== 'feed' || !$('scrim').hidden) return;
  ev.preventDefault(); tioNavGo(ev.key === 'j' ? 1 : -1);
});

const TIO_ACTS = {
  tiof:(id, v) => { UI.tiof = v; renderMain(); },
  tioGo:(id, v) => { const el = $(v); if(el) el.scrollIntoView({behavior:'smooth', block:'start'}); },
  tioCases:() => { UI.tiof = 'cases'; renderMain(); const el = $('tioStories'); if(el) el.scrollIntoView({behavior:'smooth', block:'start'}); },
  tioSrc:(id, v) => { UI.isrc = v; UI.itri = 'all'; UI.itab = 'feed'; renderMain(); },
  stNav:(id, v) => tioNavGo(+v),
  /* a Sigma rule started from a technique: title, description and the ATT&CK tag filled in — the detection logic is yours to write */
  tioRule:(id, v) => { if(typeof newRule !== 'function') return; const T = ctiDict().tech.get(v) || ctiDict().tech.get(String(v).split('.')[0]), name = T ? T[1] : v;
    newRule('sigma'); const r = DB.rules[0]; r.title = cap('Detect ' + v + ' — ' + name, 200); r.technique = v; r.tags = ['attack.' + String(v).toLowerCase()];
    r.desc = 'Started from Threat Intel: ' + name + ' (' + v + ') is named in your stories.';
    r.code = r.code.replace('title: New detection', 'title: ' + r.title.replace(/[\r\n]/g, ' ')).replace('description: What this detects and why it matters', 'description: ' + r.desc).replace(/\nlevel: medium$/, '\ntags:\n    - attack.' + String(v).toLowerCase() + '\nlevel: medium');
    mutate('started a rule for ' + v); renderMain(); toast('New Sigma rule for ' + v + ' — write the detection, then save'); },
};
