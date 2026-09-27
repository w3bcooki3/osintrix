/* ==========================================================================
   Screens
   ========================================================================== */
function renderNav(){
  const r = UI.route, cur = a => r.area === a ? ' aria-current="page"' : '';
  const openQ = DB.records.filter(x => x.type === 'lead' && !x.answer).length;
  const nv = (a, icon, label, cnt) => `<a class="nv" href="#/${a}"${cur(a)} title="${label}">${ico(icon)}<span class="lbl">${label}</span>${cnt != null ? `<span class="cnt">${cnt}</span>` : ''}</a>`;
  $('sidenav').innerHTML = `
    <div class="navg">${nv('home','layout-dashboard','Dashboard', openQ || null)}${nv('cases','folder-open','Cases', DB.cases.length)}</div>
    <div class="navg"><div class="caps">Open cases <button data-act="newCase" title="New case" aria-label="New case">${ico('plus','sm')}</button></div>
      ${DB.cases.filter(c => c.status !== 'closed').map(c => `<a class="nv case" href="${caseHash(c.id)}"${r.area === 'case' && DB.active === c.id ? ' aria-current="page"' : ''} title="${esc(c.name)}">
        <span class="dot" style="background:${esc(c.color)}"></span><span class="lbl">${esc(c.name.split(' — ')[0])}</span><span class="cnt">${derive(c.id).entries.length}</span></a>`).join('')}</div>
    <div class="navg"><div class="caps">Workspace</div>${nv('notes','sticky-note','Notes', (DB.notes || []).reduce((s, n) => s + noteTasks(n).filter(t => !t.done).length, 0) || null)}</div>
    <div class="navg"><div class="caps">Research</div>${nv('toolbox','wrench','Toolbox', DB.tools.length)}${nv('queries','scan-search','Query library', (DB.queries || []).length || null)}</div>
    <div class="navg"><div class="caps">Lab</div>${nv('ctf','flag','CTF', DB.ctf ? DB.ctf.chals.filter(c => c.status !== 'solved').length || null : null)}${nv('lab','file-search','Forensics kit')}${nv('decoder','binary','Decoder')}</div>
    <div class="navg"><div class="caps">Intelligence</div>${nv('feeds','rss','Threat Intel', DB.feed.length || null)}${nv('detections','file-code','Detections', (DB.rules || []).length || null)}${nv('entities','fingerprint','Entities')}</div>
    <div class="navg"><div class="caps">Knowledge</div>${nv('reference','book-open','Reference')}${nv('playbooks','list-checks','Playbooks', (DB.playbooks || []).length || null)}</div>
    <div class="navg">${(DB.trash || []).length ? nv('trash','trash-2','Trash', DB.trash.length) : ''}${nv('help','circle-help','Help')}${nv('settings','settings','Settings')}</div>`;
  const b = $('bbar');
  b.innerHTML = `<a href="#/home"${cur('home')}>${ico('layout-dashboard')}Home</a><a href="#/cases"${r.area === 'cases' || r.area === 'case' ? ' aria-current="page"' : ''}>${ico('folder-open')}Cases</a>
    <button class="cap" data-act="capture" aria-label="Capture"><span class="b">${ico('plus')}</span></button>
    <a href="${caseHash(DB.active, 'graph')}"${r.tab === 'graph' ? ' aria-current="page"' : ''}>${ico('waypoints')}Graph</a><a href="#/toolbox"${cur('toolbox')}>${ico('wrench')}Tools</a>`;
}

/* ---------- Dashboard ---------- */
function feedMatches(){ const g = globalEnts(); return DB.feed.map(f => ({f, hits:E.extract(f.title + ' ' + f.body).map(entKey).filter(id => g.has(id))})).filter(x => x.hits.length); }
function stat(icon, color, n, label, sub, act, spark){
  const inner = `<span class="ic" style="color:${color};background:color-mix(in srgb,${color} 14%,transparent)">${ico(icon)}</span><div class="sx"><b>${n}</b><span>${label}</span>${sub ? `<small>${sub}</small>` : ''}</div>${spark ? `<div class="sp">${sparkline(spark, color)}</div>` : ''}`;
  return act.startsWith('#') ? `<a class="stat" href="${act}">${inner}</a>` : `<button class="stat" data-act="${act}">${inner}</button>`;
}
function perDay(list, f, days = 8){ const since = Date.parse('2026-09-08T00:00:00Z'), b = new Array(days).fill(0); for(const x of list){ const t = f(x); if(t >= since){ const i = Math.floor((t - since) / 864e5); if(i < days) b[i]++; } } return b; }
function greeting(){ const h = new Date().getHours(); return h < 5 ? 'Working late' : h < 12 ? 'Good morning' : h < 18 ? 'Good afternoon' : 'Good evening'; }
function viewHome(){
  const active = DB.cases.filter(c => c.status !== 'closed'), g = globalEnts();
  const mal = [...g.values()].filter(e => verdictOf(e.id) === 'malicious').length;
  const openQ = DB.records.filter(r => r.type === 'lead' && !r.answer);
  const cross = [...g.values()].filter(e => e.cases.size > 1 && verdictOf(e.id) !== 'benign');
  const fm = feedMatches(), top = active.slice().sort((a, b) => derive(b.id).entries.length - derive(a.id).entries.length)[0];
  const buckets = perDay(DB.records, r => r.ts), mx = Math.max(1, ...buckets);
  const recSpark = perDay(DB.records, r => r.ts), entSpark = perDay(DB.entries, e => e.created);
  return `<div class="scroll"><div class="page">
    ${sampleBanner()}${backupBanner()}
    <section class="hero">
      <div class="hero-l"><div class="hero-date">${esc(new Date().toLocaleDateString(undefined, {weekday:'long', day:'numeric', month:'long'}))}</div>
        <h1>${top ? `<span>${esc(top.name.split(' — ')[0])}</span> has ${openQ.filter(r => r.caseId === top.id).length} open questions and ${derive(top.id).entries.filter(e => entryVerdict(e) === 'malicious').length} confirmed-malicious entries.` : 'Start your first investigation.'}</h1>
        <p>${cross.length ? `<b>${esc(cross[0].v)}</b> appears in ${cross[0].cases.size} cases. ` : ''}${fm.length ? `${fm.length} feed items mention your entities.` : ''}</p>
        <div class="hero-acts"><button class="btn primary" data-act="capture">${ico('plus','sm')}Capture evidence <kbd>N</kbd></button>
          ${top ? `<a class="btn" href="${caseHash(top.id, 'graph')}">${ico('waypoints','sm')}Open the graph</a>` : ''}<button class="btn" data-act="newCase">${ico('folder-open','sm')}New case</button></div></div>
      ${top ? `<a class="hero-map" href="${caseHash(top.id, 'graph')}" aria-label="Open the ${esc(top.name)} graph">${caseMap(top.id, 420, 240)}<span class="cap">${esc(top.code)} · ${derive(top.id).entries.length} entries · ${derive(top.id).links.length} links</span></a>` : ''}
    </section>
    <div class="stats">
      ${stat('folder-open','var(--accent)', active.length, 'Open cases', DB.cases.filter(c => c.status === 'review').length + ' in review', '#/cases')}
      ${stat('layers','var(--t-identity)', DB.entries.length, 'Vault entries', 'across all cases', '#/cases', entSpark)}
      ${stat('shield-alert','var(--red)', mal, 'Malicious', 'entities judged', 'goMal')}
      ${stat('clock','var(--amber)', DB.records.length, 'Evidence records', 'captured this week', caseHash(DB.active, 'timeline'), recSpark)}
    </div>
    <div class="grid cols-main" style="margin-top:18px">
      <div class="stack">
        <section class="card"><header><h3>Open investigations</h3><a class="btn sm ghost" href="#/cases">All cases ${ico('chevron-right','sm')}</a></header><div class="body flush">
          ${active.map(c => { const D = derive(c.id), q = D.recs.filter(r => r.type === 'lead' && !r.answer).length, done = D.recs.filter(r => r.type === 'lead').length;
            const pct = done ? Math.round((done - q) / done * 100) : 0;
            return `<a class="li" href="${caseHash(c.id)}"><span class="cicon" style="background:${esc(c.color)};width:42px;height:42px;border-radius:12px">${ico(c.icon)}</span>
              <div class="main2"><b>${esc(c.name)}</b><small>${esc(c.scope || 'No scope written yet')}</small>
                ${done ? `<span class="prog" title="${pct}% of questions answered"><i style="width:${pct}%;background:${esc(c.color)}"></i></span>` : ''}</div>
              <div class="end hide-m">${statusTag(c.status)}<span class="chip sq">${D.entries.length} entries</span>${q ? `<span class="chip amber sq">${q} open</span>` : ''}</div></a>`; }).join('')}
        </div></section>
        <section class="card"><header><h3>Activity</h3><span class="t3">evidence captured per day</span></header><div class="body">
          <div class="bars">${buckets.map((v, i) => `<div style="--h:${Math.round(v / mx * 100)}%" title="${v} records"><span>${v || ''}</span></div>`).join('')}</div>
          <div class="axis">${buckets.map((v, i) => `<span>${['Tue 8','Wed 9','Thu 10','Fri 11','Sat 12','Sun 13','Mon 14','Tue 15'][i]}</span>`).join('')}</div></div></section>
      </div>
      <div class="stack">
        <section class="card"><header><h3>Feed items about your entities</h3>${impl('mock')}</header><div class="body flush">
          ${fm.map(({f, hits}) => `<button class="li" data-act="selFeed" data-id="${f.id}" style="align-items:flex-start"><span class="tb sm" style="--c:var(--red)">${ico('rss')}</span>
            <div class="main2"><b style="white-space:normal">${esc(f.title)}</b><small>${esc(f.source)} · ${hits.length} match${hits.length > 1 ? 'es' : ''}</small></div></button>`).join('') || empty('rss', 'No matches', 'No feed item mentions an entity from your cases.')}</div></section>
        <section class="card"><header><h3>Seen in more than one case</h3></header><div class="body">
          ${cross.map(e => `<div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">${entPill(e.id)}<span class="t3" style="font-size:13px">${[...e.cases].map(id => esc(theCase(id).code)).join(' · ')}</span></div>`).join('') || '<span class="t3">Nothing shared yet.</span>'}
          <p class="heur">An exact match on the normalised value. A lead, not an attribution.</p></div></section>
        ${(DB.notes || []).some(n => n.pinned) ? `<section class="card"><header><h3>Pinned notes</h3><a class="btn sm ghost" href="#/notes">All notes ${ico('chevron-right','sm')}</a></header><div class="body"><div class="board mini">${DB.notes.filter(n => n.pinned).slice(0, 3).map(n => noteCard(n)).join('')}</div></div></section>` : ''}
        <section class="card"><header><h3>Open questions</h3><span class="t3">${openQ.length}</span></header><div class="body flush">
          ${openQ.slice(0, 5).map(r => `<button class="li" data-act="selRec" data-id="${r.id}"><span class="t3">${ico('circle-dot','sm')}</span><div class="main2"><b style="font-weight:520">${esc(r.title)}</b></div><span class="end mono">${esc(theCase(r.caseId).code)}</span></button>`).join('')}</div></section>
      </div></div>
  </div></div>`;
}

/* ---------- Cases (the multi-vault) ---------- */
function viewCases(){
  const f = UI.cf || 'all', counts = {all:DB.cases.length, active:0, review:0, closed:0};
  for(const c of DB.cases) counts[c.status] = (counts[c.status] || 0) + 1;
  const list = DB.cases.filter(c => f === 'all' || c.status === f).slice().sort((a, b) => b.updated - a.updated);
  return `<div class="scroll"><div class="page">
    ${pageHead('folder-open','var(--accent)','Cases','Every investigation is its own vault — entries, evidence, timeline, graph and report.',
      `<button class="btn" data-act="importCase">${ico('upload','sm')}Import case</button><button class="btn primary" data-act="newCase">${ico('plus','sm')}New case</button>`)}
    <div class="toolbar"><div class="seg">${[['all','All'],['active','Active'],['review','In review'],['closed','Archived']].map(([k, l]) => `<button data-act="cf" data-v="${k}" aria-pressed="${f === k}">${l} <span class="segn">${counts[k] || 0}</span></button>`).join('')}</div></div>
    <div class="cgrid">${list.map(caseCard).join('')}
      <button class="case-card case-new" data-act="newCase"><span class="nw">${ico('plus','lg')}</span><b>New case</b><span>Name it, pick a colour and icon, write the scope</span></button></div>
  </div></div>`;
}
function caseCard(c){
  const D = derive(c.id), leads = D.recs.filter(r => r.type === 'lead'), done = leads.filter(r => r.answer).length;
  const mal = D.entries.filter(e => entryVerdict(e) === 'malicious').length, pct = leads.length ? Math.round(done / leads.length * 100) : 0;
  return `<article class="case-card${c.status === 'closed' ? ' archived' : ''}" style="--cc:${esc(c.color)}">
    <a class="case-hit" href="${caseHash(c.id)}" aria-label="Open ${esc(c.name)}"></a>
    <div class="case-map">${D.entries.length > 1 ? caseMap(c.id, 360, 120) : `<div class="case-empty">${ico(c.icon,'lg')}<span>No entries yet</span></div>`}</div>
    <div class="case-b">
      <div class="case-meta"><span class="cicon sm" style="background:${esc(c.color)}">${ico(c.icon,'sm')}</span><span class="mono t3">${esc(c.code)}</span>${statusTag(c.status)}<span class="case-upd">${esc(E.fmtAgo(Math.max(0, Date.now() - c.updated)))}</span>
        <button class="iconbtn case-more" data-act="caseMenu" data-id="${c.id}" aria-label="More actions for ${esc(c.name)}">${ico('ellipsis','sm')}</button></div>
      <h3>${esc(c.name)}</h3>
      <p>${esc(c.scope || 'No scope written yet.')}</p>
      ${leads.length ? `<div class="case-prog"><div><span>Questions answered</span><b>${done}/${leads.length}</b></div><span class="bar"><i style="width:${pct}%"></i></span></div>` : ''}
      <div class="case-stats"><span>${ico('layers','sm')}<b>${D.entries.length}</b> entries</span><span>${ico('clock','sm')}<b>${D.recs.length}</b> records</span>${mal ? `<span class="m">${ico('shield-alert','sm')}<b>${mal}</b> malicious</span>` : ''}</div>
    </div></article>`;
}
function viewCase(tab){
  const c = theCase(), D = derive();
  const counts = {vault:D.entries.length, timeline:D.recs.filter(r => r.ts).length, questions:D.recs.filter(r => r.type === 'lead' && !r.answer).length || null};
  const body = {overview:caseOverview, vault:caseVault, timeline:caseTimeline, graph:caseGraph, questions:caseQuestions, report:caseReport}[tab] || caseOverview;
  return `<div class="chead${tab === 'graph' ? ' g' : ''}" style="--cc:${esc(c.color)}"><div class="crumb"><a href="#/cases">Cases</a>${ico('chevron-right','sm')}<span>${esc(c.code)}</span></div>
    <div class="row1"><span class="cicon" style="background:${esc(c.color)}">${ico(c.icon)}</span>
      <div style="flex:1;min-width:0"><h1>${esc(c.name)}</h1><div class="meta">${statusTag(c.status)}<span>${ico('calendar','sm')}Opened ${esc(E.fmtDate(c.created, tz()))}</span><span>${ico('user','sm')}${esc(c.owner)}</span></div></div>
      <div class="acts"><button class="btn" data-act="editCase" aria-label="Edit case">${ico('pencil','sm')}<span class="bl">Edit</span></button><button class="btn" data-act="addEntry">${ico('plus','sm')}<span class="bl">Add entry</span><span class="bm">Entry</span></button><button class="btn primary" data-act="capture">${ico('plus','sm')}Capture</button></div></div>
    <nav class="tabs" role="tablist">${CASE_TABS.map(([k, l, i]) => `<a class="tab" role="tab" href="${caseHash(c.id, k)}" aria-selected="${tab === k}">${ico(i,'sm')}${l}${counts[k] ? `<span class="cnt">${counts[k]}</span>` : ''}</a>`).join('')}</nav></div>
  ${body(c, D)}`;
}

function caseOverview(c, D){
  if(!D.recs.length && !D.entries.length) return `<div class="scroll">${empty('folder-open','This case is empty','Add a vault entry for anything you know — a person, a handle, a wallet — or press <kbd>N</kbd> and paste raw evidence. Entities come out on their own.',
    `<button class="btn primary" data-act="addEntry">${ico('plus','sm')}Add entry</button><button class="btn" data-act="capture">Capture evidence</button>`)}</div>`;
  const obs = []; for(const r of D.recs) for(const o of E.observations(r)) if(o.hot) obs.push({r, o});
  const byTag = new Map(); for(const x of obs){ if(!byTag.has(x.o.tag)) byTag.set(x.o.tag, []); byTag.get(x.o.tag).push(x); }
  const leads = D.recs.filter(r => r.type === 'lead'), done = leads.filter(r => r.answer).length;
  const byGroup = countBy(D.entries, e => TYPES[e.type].group);
  const key = D.entries.filter(e => e.starred || e.priority === 'critical').slice(0, 6);
  const beacon = [...D.ents.values()].map(e => ({e, b:E.beaconOf(e.recs.map(r => r.ts))})).find(x => x.b && x.b.regular && x.e.k === 'hostport');
  return `<div class="scroll"><div class="page">
    ${c.scope ? `<p style="margin:0 0 20px;max-width:880px;color:var(--text-2);font-size:15.5px;line-height:1.65">${esc(c.scope)}</p>` : ''}
    <div class="stats">
      ${stat('layers','var(--accent)', D.entries.length, 'Vault entries', byGroup.slice(0, 2).map(([g, n]) => n + ' ' + GROUPS.find(x => x[0] === g)[1].toLowerCase()).join(' · '), caseHash(c.id,'vault'))}
      ${stat('clock','var(--amber)', D.recs.length, 'Evidence records', D.recs.filter(r => r.ts).length + ' on the timeline', caseHash(c.id,'timeline'))}
      ${stat('shield-alert','var(--red)', D.entries.filter(e => entryVerdict(e) === 'malicious').length, 'Malicious', 'judged in this case', caseHash(c.id,'vault'))}
      ${stat('list-checks','var(--green)', done + '/' + leads.length, 'Questions answered', leads.length - done + ' still open', caseHash(c.id,'questions'))}
    </div>
    <div class="grid cols-main" style="margin-top:18px">
      <div class="stack">
        <a class="card mapcard" href="${caseHash(c.id,'graph')}"><header><h3>Case map</h3><span class="t3">${D.entries.length} entries · ${D.links.length} relationships</span><span class="btn sm ghost" style="margin-left:auto">Open graph ${ico('chevron-right','sm')}</span></header><div class="body">${caseMap(c.id, 720, 260)}</div></a>
        <section class="card"><header><h3>Key entries</h3><a class="btn sm ghost" href="${caseHash(c.id,'vault')}">Open vault ${ico('chevron-right','sm')}</a></header><div class="body"><div class="egrid" style="grid-template-columns:repeat(auto-fill,minmax(240px,1fr))">${key.map(entryCard).join('')}</div></div></section>
        <section class="card"><header><h3>What the evidence adds up to</h3><span class="t3">heuristic</span></header><div class="body">
          ${[...byTag.entries()].map(([tag, l]) => `<div class="note amber obs"><span class="ic">${ico('triangle-alert','sm')}</span><div><b>${esc(tag[0].toUpperCase() + tag.slice(1))}</b> — ${esc(l[0].o.t)} <button class="btn xs" data-act="selRec" data-id="${l[0].r.id}" style="margin-left:6px">Open</button>${l.length > 1 ? ` <span class="t3" style="font-size:12.5px">+${l.length - 1} more</span>` : ''}</div></div>`).join('') || '<span class="t3">Nothing combined yet.</span>'}
          <p class="heur">These point at combinations worth a look. They never set a verdict.</p></div></section>
      </div>
      <div class="stack">
        ${beacon ? `<div class="note accent"><span class="ic">${ico('radar','sm')}</span><div><b>Regular beacon</b> — <span class="mono">${esc(beacon.e.v)}</span> every ${esc(E.fmtGap(beacon.b.mean))}, jitter ${Math.round(beacon.b.jitter * 100)}% across ${beacon.b.n} sightings.</div></div>` : ''}
        <section class="card"><header><h3>Questions</h3><span class="t3">${done} of ${leads.length}</span></header><div class="body flush">
          ${leads.map(l => `<button class="li" data-act="selRec" data-id="${l.id}"><span style="color:${l.answer ? 'var(--green)' : 'var(--text-3)'}">${ico(l.answer ? 'check' : 'circle-dot','sm')}</span><div class="main2"><b style="font-weight:520${l.answer ? ';color:var(--text-2)' : ''}">${esc(l.title)}</b></div></button>`).join('')}</div></section>
        <section class="card"><header><h3>Notes</h3><a class="btn sm ghost" href="#/notes" data-act="nf" data-v="${c.id}">All ${ico('chevron-right','sm')}</a></header><div class="body">
          ${quickNote(c.id)}<div class="board mini">${(DB.notes || []).filter(n => n.caseId === c.id).sort((a, b) => (b.pinned - a.pinned) || b.updated - a.updated).slice(0, 4).map(n => noteCard(n, true)).join('')}</div></div></section>
        <section class="card"><header><h3>Vault composition</h3></header><div class="body"><div class="compo">${donut(GROUPS.map(([g, l,, col]) => ({label:l, n:D.entries.filter(e => TYPES[e.type].group === g).length, color:'var(' + col + ')'})).filter(p => p.n))}
          <div class="legend">${GROUPS.map(([g, l,, col]) => { const n = D.entries.filter(e => TYPES[e.type].group === g).length; return n ? `<button data-act="vcat" data-v="${g}"><i style="background:var(${col})"></i>${l}<b>${n}</b></button>` : ''; }).join('')}</div></div></div></section>
      </div></div></div></div>`;
}

/* ---------- vault ---------- */
function entryCard(e){
  const t = TYPES[e.type], v = entryVerdict(e), m = entryMentions(e).length;
  const extra = t.fields.slice(1).filter(([n]) => e.fields[n]).slice(0, 2);
  return `<button class="ecard" data-act="selEntry" data-id="${e.id}" aria-selected="${!!(UI.sel && UI.sel.id === e.id)}">
    <div class="h">${tbadge(e.type)}<div class="tt"><div class="kind">${esc(t.label)}</div><div class="val${MONO_TYPES.has(e.type) ? ' mono' : ''}" title="${esc(primary(e))}">${esc(primary(e))}</div></div>
      <span class="star${e.starred ? ' on' : ''}" data-act="star" data-id="${e.id}" role="button" tabindex="0" aria-label="${e.starred ? 'Unstar' : 'Star'}">${ico('star','sm')}</span></div>
    ${extra.length ? `<dl>${extra.map(([n, l]) => `<dt>${esc(l)}</dt><dd>${esc(e.fields[n])}</dd>`).join('')}</dl>` : ''}
    <div class="f">${prioLabel(e.priority)}${v ? vdLabel(v) : ''}<span class="sp"></span>${m ? `<span title="Records that mention it">${ico('file-text','sm')} ${m}</span>` : ''}${e.tags.slice(0, 1).map(tg => `<span class="chip sq" style="height:22px;font-size:12px">#${esc(tg)}</span>`).join('')}</div></button>`;
}
function caseVault(c, D){
  const q = UI.vq.toLowerCase(), cat = UI.vcat;
  let list = D.entries.filter(e => (cat === 'all' || (cat === 'starred' ? e.starred : cat === 'priority' ? /high|critical/.test(e.priority) : TYPES[e.type].group === cat)) &&
    (!q || (Object.values(e.fields).join(' ') + ' ' + e.tags.join(' ') + ' ' + e.notes + ' ' + TYPES[e.type].label).toLowerCase().includes(q)));
  const prio = {critical:0, high:1, medium:2, low:3};
  list.sort((a, b) => (b.starred - a.starred) || prio[a.priority] - prio[b.priority]);
  const auto = [...D.ents.values()].filter(x => KIND_TO_TYPE[x.k] && x.k !== 'hostport' && !D.byKey.has(x.id) && verdictOf(x.id) !== 'benign' && (cat === 'all' || TYPES[KIND_TO_TYPE[x.k]].group === cat) && (!q || x.v.toLowerCase().includes(q)));
  const catBtn = (id, label, n, col) => `<button class="vcat" data-act="vcat" data-v="${id}" aria-pressed="${cat === id}">${col ? `<span class="sw" style="--c:var(${col})"></span>` : ''}${label}<span class="cnt">${n}</span></button>`;
  const groups = cat === 'all' ? GROUPS.filter(([g]) => list.some(e => TYPES[e.type].group === g)) : null;
  return `<div class="scroll"><div class="vault">
    <aside class="vcats"><div class="caps" style="padding:0 10px 8px">Views</div>
      ${catBtn('all','All entries', D.entries.length)}${catBtn('starred','Starred', D.entries.filter(e => e.starred).length)}${catBtn('priority','High priority', D.entries.filter(e => /high|critical/.test(e.priority)).length)}
      <div class="caps" style="padding:18px 10px 8px">Categories</div>
      ${GROUPS.map(([g, l,, col]) => catBtn(g, l, D.entries.filter(e => TYPES[e.type].group === g).length, col)).join('')}</aside>
    <div class="vmain">
      <div class="toolbar"><div class="search-in">${ico('search')}<label class="sr" for="vq">Search this vault</label><input id="vq" class="inp" placeholder="Search entries, fields, tags…" value="${esc(UI.vq)}"></div>
        <span class="t3" style="font-size:13.5px">${list.length} entries</span><span style="flex:1"></span>
        <button class="btn primary" data-act="addEntry">${ico('plus','sm')}Add entry</button></div>
      ${list.length ? (groups ? groups.map(([g, l, i, col]) => { const gl = list.filter(e => TYPES[e.type].group === g);
          return `<div class="vgroup"><span class="tb sm" style="--c:var(${col})">${ico(i)}</span><h3>${l}</h3><span class="t3">${gl.length}</span></div><div class="egrid">${gl.map(entryCard).join('')}</div>`; }).join('')
        : `<div class="egrid">${list.map(entryCard).join('')}</div>`)
        : empty('layers','Nothing here yet','Add an entry by hand, or capture evidence and promote what it finds.', `<button class="btn primary" data-act="addEntry">${ico('plus','sm')}Add entry</button>`)}
      ${auto.length ? `<div class="vgroup" style="margin-top:34px"><span class="tb sm" style="--c:var(--accent)">${ico('scan')}</span><h3>Found in evidence, not in the vault yet</h3><span class="t3">${auto.length}</span></div>
        <p class="t2" style="margin:-4px 0 14px;font-size:14px">Extracted automatically from captured records. Promote one to give it fields, a priority and a place on the graph.</p>
        <div class="egrid">${auto.slice(0, 12).map(x => { const t = TYPES[KIND_TO_TYPE[x.k]];
          return `<div class="ecard auto"><div class="h">${tbadge(t.id)}<div class="tt"><div class="kind">${esc(t.label)} · in ${x.recs.length} record${x.recs.length > 1 ? 's' : ''}</div><div class="val mono">${esc(x.v)}</div></div></div>
            <div class="f"><button class="btn xs" data-act="selEnt" data-id="${esc(x.id)}">Details</button><span class="sp"></span><button class="btn xs primary" data-act="promote" data-id="${esc(x.id)}">${ico('plus','sm')}Add to vault</button></div></div>`; }).join('')}</div>` : ''}
    </div></div></div>`;
}

/* ---------- timeline ---------- */
function caseTimeline(c, D){
  const list = D.recs.filter(passes);
  const hosts = countBy(D.recs, r => r.host);
  const bar = `<div class="tlbar"><div class="seg" role="group" aria-label="View"><button data-act="tlMode" data-v="events" aria-pressed="${UI.tlMode === 'events'}">${ico('clock','sm')}Events</button><button data-act="tlMode" data-v="story" aria-pressed="${UI.tlMode === 'story'}">${ico('book-open','sm')}Story</button></div>
    ${UI.tlMode === 'events' ? `<div class="search-in tlq">${ico('filter')}<label class="sr" for="tlq">Filter the timeline</label><input id="tlq" class="inp" placeholder="Filter — host:DC01 verdict:malicious 4624" value="${esc(UI.q || '')}" autocomplete="off" spellcheck="false"></div><span class="t3" style="font-size:13.5px">${list.length} of ${D.recs.length}</span>
    ${hosts.slice(0, 5).map(([h, n]) => `<button class="chip" data-act="facet" data-f="host" data-v="${esc(h)}" aria-pressed="${UI.facet.host === h}">${esc(h)}<span class="n">${n}</span></button>`).join('')}
    ${UI.pivot ? `<span class="chip accent">Pivot: ${esc(entSplit(UI.pivot).v)} <button data-act="pivotOff" aria-label="Exit pivot">${ico('x','sm')}</button></span>` : ''}
    ${UI.facet.slot ? `<span class="chip accent">${esc(UI.facet.slot.day != null ? UI.facet.slot.day.replace(/^\w+,?\s*/, '') : WD[UI.facet.slot.wd])} ${String(UI.facet.slot.h).padStart(2, '0')}:00 <button data-act="slotOff" aria-label="Clear time filter">${ico('x','sm')}</button></span>` : ''}
    ${UI.facet.host || UI.pivot || UI.q || UI.facet.slot ? `<button class="btn xs ghost" data-act="clearFilters">Clear</button>` : ''}
    <span class="sp"></span><button class="btn xs${UI.tlSel ? ' on' : ''}" data-act="tlSel" aria-pressed="${!!UI.tlSel}">${ico('square-check','sm')}Select</button><button class="btn xs${UI.tlHeat ? ' on' : ''}" data-act="tlHeat" aria-pressed="${!!UI.tlHeat}">${ico('grid-3x3','sm')}Heatmap</button>` : ''}</div>`;
  if(UI.tlMode === 'story') return `<div class="scroll">${bar}${storyHTML(D)}</div>`;
  let h = '', lastDay = null, prev = null;
  for(const r of list){
    if(r.ts){ const d = E.fmtDay(r.ts, tz());
      if(d !== lastDay){ const n = list.filter(x => x.ts && E.fmtDay(x.ts, tz()) === d).length; h += `<div class="day"><b>${esc(d)}</b><span>${n} event${n > 1 ? 's' : ''} · ${esc(tz())}</span></div>`; lastDay = d; prev = null; }
      if(prev !== null){ const g = r.ts - prev; if(g > 1000){ const px = Math.max(10, Math.min(56, Math.round(5 * Math.log2(g / 1000)))); h += `<div class="gap${g > 36e5 ? ' wide' : ''}" style="--h:${px}px" aria-hidden="true"><em>${g > 36e5 ? ico('clock','sm') : ''}${esc(E.fmtGap(g))}${g > 36e5 ? ' gap' : ''}</em></div>`; } }
      prev = r.ts;
    } else if(lastDay !== '-'){ h += `<div class="day">No timestamp</div>`; lastDay = '-'; prev = null; }
    h += evWrap(r, evHTML(r, D, c));
  }
  if(UI.evPick){ const have = new Set(D.recs.map(r => r.id)); for(const i of [...UI.evPick]) if(!have.has(i)) UI.evPick.delete(i); }
  return `<div class="scroll">${bar}${UI.tlHeat ? heatHTML(D) : ''}<div class="tl${UI.tlSel || (UI.evPick && UI.evPick.size) ? ' picking' : ''}">${evBulkHTML(list)}${list.length ? h : empty('filter','Nothing matches','Clear the filters or change the search.', `<button class="btn" data-act="clearFilters">Clear filters</button>`)}</div></div>`;
}
const EVTYPE = {evidence:['file-text','var(--t-infra)','Evidence'], finding:['target','var(--amber)','Finding'], lead:['circle-help','var(--t-identity)','Question'], note:['notebook-pen','var(--text-3)','Note']};
function evHTML(r, D, c){
  const [ic, col, tl] = EVTYPE[r.type] || EVTYPE.note;
  const mal = r.ents.filter(e => verdictOf(entKey(e)) === 'malicious'), ob = E.observations(r).filter(o => o.hot), rel = r.ts ? E.relClock(r.ts, D.t0) : null;
  const ents = [...new Set(r.ents.map(entKey))].filter(id => { const k = entSplit(id).k; return !['eventid','file','path','regkey','hostport'].includes(k) && verdictOf(id) !== 'benign'; }).slice(0, 4);
  const meta = [r.host ? `<span>${ico('cpu','sm')}${esc(r.host)}</span>` : '', r.source ? `<span>${ico('scroll-text','sm')}${esc(r.source)}</span>` : '', r.ents.length ? `<span>${ico('fingerprint','sm')}${r.ents.length} entities</span>` : ''].filter(Boolean).join('');
  const badges = [mal.length ? `<span class="chip red sq">${ico('shield-alert','sm')}${mal.length} malicious</span>` : '', ob.length ? `<span class="chip amber sq" title="${esc(ob.map(o => o.t).join(' · '))}">${esc(ob[0].tag[0].toUpperCase() + ob[0].tag.slice(1))}${ob.length > 1 ? ' +' + (ob.length - 1) : ''}</span>` : '', r.type !== 'evidence' ? `<span class="chip sq">${tl}</span>` : '', r.tags.includes('key-evidence') ? `<span class="chip accent sq">${ico('star','sm')}Key</span>` : '', (r.att || []).length ? `<span class="chip sq">${ico('paperclip','sm')}${r.att.length}</span>` : ''].join('');
  return `<button class="ev${c.t0 === r.id ? ' t0' : ''}${mal.length ? ' mal' : ''}" data-act="selRec" data-id="${r.id}" aria-selected="${!!(UI.sel && UI.sel.id === r.id)}">
    <span class="when"><span class="clk">${r.ts ? esc(E.fmtClock(r.ts, tz())) : '—'}</span>${rel ? `<span class="rl">${rel}</span>` : ''}</span>
    <span class="mk" style="--c:${col}">${c.t0 === r.id ? ico('crosshair','sm') : ico(ic,'sm')}</span>
    <span class="bd"><span class="ttl">${esc(r.title)}</span>${meta ? `<span class="meta">${meta}</span>` : ''}
      ${r.body && r.body !== r.title ? `<span class="raw">${esc(r.body.split('\n')[0])}</span>` : ''}
      ${ents.length ? `<span class="ents">${ents.map(id => { const {k, v} = entSplit(id); return `<span class="ent xs" data-v="${verdictOf(id)}">${kindBadge(k)}<span class="v">${esc(v)}</span></span>`; }).join('')}</span>` : ''}</span>
    <span class="bdg">${badges}</span></button>`;
}
function storyHTML(D){
  const timed = D.recs.filter(r => r.ts && r.type !== 'lead');
  if(timed.length < 2) return empty('book-open','No story yet','Chapters appear once at least two records have a time.');
  const chs = E.chapters(timed), seen = new Set();
  return `<div class="tl" style="max-width:860px;padding-top:24px"><p class="t2" style="margin:0 0 26px;font-size:15px;line-height:1.7">${timed.length} records, cut into <b style="color:var(--text)">${chs.length} chapters</b> wherever the pause is unusually long for this case. Everything is read back from the evidence; nothing is invented.</p>
    ${chs.map((items, i) => { const hosts = [...new Set(items.map(x => x.host).filter(Boolean))], fresh = [];
      for(const r of items) for(const e of r.ents){ const id = entKey(e); if(!seen.has(id)){ seen.add(id); if(verdictOf(id) === 'malicious') fresh.push(id); } }
      const title = (items.find(x => x.type === 'finding') || {}).title || (items.every(x => /^osint/.test(x.source)) ? 'Open-source research' : hosts.length === 1 ? 'Activity on ' + hosts[0] : 'Activity across ' + hosts.length + ' hosts');
      const a = items[0].ts, b = items[items.length - 1].ts;
      return `<div class="chap"><span class="num">${i + 1}</span><h3>${esc(title)}</h3><time>${esc(E.fmtFull(a, tz()).slice(5, 16))} – ${esc(E.fmtClock(b, tz()).slice(0, 5))} · ${esc(E.fmtGap(b - a))}</time>
        <p><b>${items.length}</b> records${hosts.length ? ' on <b>' + esc(hosts.join(', ')) + '</b>' : ''}. ${fresh.length ? '<b>' + fresh.length + '</b> malicious entities appear for the first time.' : ''}</p>
        ${fresh.length ? `<div class="wrap" style="margin-bottom:10px">${fresh.slice(0, 6).map(id => entPill(id)).join('')}</div>` : ''}
        <div class="card"><div class="body flush">${items.slice(0, 8).map(r => `<button class="li" data-act="selRec" data-id="${r.id}" style="padding:8px 16px"><span class="mono t3" style="font-size:12.5px;width:62px">${esc(E.fmtClock(r.ts, tz()))}</span><div class="main2"><b style="font-weight:520;font-size:14px">${esc(r.title)}</b></div></button>`).join('')}${items.length > 8 ? `<div class="t3" style="padding:8px 16px;font-size:13px">+${items.length - 8} more</div>` : ''}</div></div></div>`; }).join('')}</div>`;
}

/* ---------- questions ---------- */
function caseQuestions(c, D){
  ensurePlaybooks();
  const leads = D.recs.filter(r => r.type === 'lead'), pbOf = r => ((r.tags || []).find(t => t.startsWith('playbook:')) || '').slice(9);
  const done = leads.filter(l => l.answer).length, pct = leads.length ? Math.round(done / leads.length * 100) : 0;
  const row = l => `<button class="li qrow" data-act="selRec" data-id="${l.id}"><span class="qchk${l.answer ? ' on' : ''}">${ico(l.answer ? 'check' : 'circle-dot','sm')}</span>
    <div class="main2"><b>${esc(l.title)}</b>${l.answer ? `<small class="ans">${esc(l.answer)}</small>` : l.body ? `<small>${esc(l.body)}</small>` : `<small>Open — select to answer</small>`}</div></button>`;
  const groups = [{id:'', name:'Case questions', icon:'circle-help', items:leads.filter(l => !pbOf(l))}];
  for(const l of leads){ const k = pbOf(l); if(!k) continue; let g = groups.find(x => x.id === k); if(!g){ const p = DB.playbooks.find(x => x.id === k); g = {id:k, name:p ? p.name : 'Playbook', icon:p ? p.icon : 'list-checks', items:[], pb:true}; groups.push(g); } g.items.push(l); }
  const sec = g => { const d = g.items.filter(l => l.answer).length; return `<section class="card qsec"><header><span class="qsec-ic">${ico(g.icon,'sm')}</span><h3>${esc(g.name)}${g.pb ? ' <span class="pill" style="--c:#8b5cf6">Playbook</span>' : ''}</h3><span style="flex:1"></span><span class="pb-prog"><i style="width:${g.items.length ? Math.round(d / g.items.length * 100) : 0}%"></i></span><span class="t3 mono">${d}/${g.items.length}</span></header>
    <div class="body flush">${g.items.map(row).join('')}</div></section>`; };
  return `<div class="scroll"><div class="page narrow">
    <div class="qtop card"><div class="qring" style="--p:${pct}"><b>${pct}%</b></div><div style="flex:1;min-width:0"><h3>${done} of ${leads.length} questions answered</h3><p class="t3">Every open question is something the case does not know yet.</p></div>
      <button class="btn" data-act="pbMenu">${ico('list-checks','sm')}Run a playbook</button></div>
    <form class="card qadd" data-form="addQ"><label class="sr" for="newQ">New question</label><input id="newQ" class="inp" placeholder="What do you still need to find out?" autocomplete="off"><button class="btn primary" type="submit">${ico('plus','sm')}Add</button></form>
    ${leads.length ? groups.filter(g => g.items.length).map(sec).join('') : empty('list-checks','No questions yet','Add what you still need to find out — or run a playbook to start from a proven checklist.', `<button class="btn primary" data-act="pbMenu">${ico('list-checks','sm')}Run a playbook</button>`)}
  </div></div>`;
}
