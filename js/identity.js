/* ==========================================================================
   Identity profiles — one card per person, across every case.
   Starts from a Person (or Alias or Organisation) in the vault and gathers:
   · the handles, profiles, emails, phones, wallets, messaging accounts and
     other identifiers linked to them, each with how sure the link is (the
     confidence of the relationships on the way, one step weaker for every
     step past the first)
   · the same identifier in other cases, and the person it belongs to there —
     so one person known by different names in two cases comes together, how
     sure depending on what they share (an email address, a phone number or a
     wallet is strong; a username can be reused by someone else)
   · what is said about them: names, date of birth, nationality — and where
     two cases disagree, the disagreement, side by side
   · photos and files linked to them, the evidence that names them, when each
     account was made and the time zone it posts from (from the Infrastructure
     tab), first and last sighting
   ========================================================================== */
const IDP_ROOT = new Set(['person', 'alias', 'organization']);
const IDP_ID = new Set(['pgpkey', 'username', 'social', 'email', 'phone', 'crypto', 'messaging', 'forum', 'link', 'alias', 'device', 'transaction', 'breach', 'domain', 'location', 'media', 'document', 'file', 'ip']);
const IDP_STRONG = new Set(['pgpkey', 'email', 'phone', 'crypto', 'device', 'transaction']);   /* shared, these say "the same person" much more than a username does */
const IDP_CONF = ['', 'Possible', 'Likely', 'Confirmed'];
const idpKey = e => { try{ return entryKey(e); }catch(x){ return null; } };
/* the identifiers around one root, with the weakest link on the way */
function idpReach(root){
  const got = new Map([[root.id, {e:root, conf:3, depth:0, via:null}]]), q = [root.id];
  while(q.length){ const id = q.shift(), cur = got.get(id); if(cur.depth >= 2) continue;
    for(const l of DB.links){ if(l.a !== id && l.b !== id) continue; const o = entryById(l.a === id ? l.b : l.a); if(!o || got.has(o.id)) continue;
      if(IDP_ROOT.has(o.type) && o.type !== 'alias') continue;   /* another person or organisation is someone else */
      if(!IDP_ID.has(o.type)) continue;
      const c = Math.max(1, Math.min(cur.conf, +l.conf || 1) - (cur.depth >= 1 ? 1 : 0));
      got.set(o.id, {e:o, conf:c, depth:cur.depth + 1, via:l, from:id}); if(o.type !== 'location' && o.type !== 'media' && o.type !== 'document') q.push(o.id); } }
  got.delete(root.id); return [...got.values()];
}
/* one person's profile, joined with the same person in other cases */
function idpBuild(rootId){
  const root = entryById(rootId); if(!root) return null;
  const people = [{e:root, why:null, conf:3}], ids = new Map(), seenRoot = new Set([root.id]);
  const addIds = (P, viaPerson) => { for(const x of idpReach(P.e)){ const k = idpKey(x.e) || ('entry:' + x.e.id), cur = ids.get(k), conf = Math.min(x.conf, P.conf);
    if(!cur){ ids.set(k, {k, e:x.e, conf, cases:new Set([x.e.caseId]), entries:[x.e], persons:new Set([P.e.id]), link:x.via}); }
    else { cur.cases.add(x.e.caseId); if(!cur.entries.includes(x.e)) cur.entries.push(x.e); cur.persons.add(P.e.id); if(conf > cur.conf) cur.conf = conf; } } };
  addIds(people[0]);
  /* the same identifier in another case, and who it belongs to there */
  for(let round = 0; round < 2; round++){
    for(const id of [...ids.values()]){ if(id.k.startsWith('entry:')) continue;
      for(const o of DB.entries){ if(o.id === id.e.id || idpKey(o) !== id.k || id.entries.includes(o)) continue; id.entries.push(o); id.cases.add(o.caseId);
        for(const l of DB.links){ if(l.a !== o.id && l.b !== o.id) continue; const p = entryById(l.a === o.id ? l.b : l.a); if(!p || !IDP_ROOT.has(p.type) || p.type === 'alias' || seenRoot.has(p.id)) continue;
          const strong = IDP_STRONG.has(o.type), conf = Math.max(1, Math.min(id.conf, +l.conf || 1, strong ? 3 : 2));
          seenRoot.add(p.id); const P = {e:p, conf, why:{shared:o, strong, inCase:p.caseId}}; people.push(P); addIds(P); } } } }
  /* what is said about them */
  const facts = {name:[], dob:[], nationality:[], role:[], alias:[]}, F = (k, v, e) => { v = String(v || '').trim(); if(!v) return; const L = facts[k]; const x = L.find(y => y.v.toLowerCase() === v.toLowerCase()); if(x){ if(!x.cases.includes(e.caseId)) x.cases.push(e.caseId); } else L.push({v, cases:[e.caseId], e}); };
  for(const P of people){ if(P.e.type === 'organization') F('name', P.e.fields.name, P.e); else { F('name', P.e.fields.name, P.e); F('dob', P.e.fields.dob, P.e); F('nationality', P.e.fields.nationality, P.e); F('role', P.e.fields.role, P.e); } }
  for(const id of ids.values()) if(id.e.type === 'alias') F('alias', id.e.fields.alias, id.e);
  const norm = v => v.toLowerCase().replace(/[^a-z0-9]/g, ''), conflicts = [];
  if(new Set(facts.dob.map(x => norm(x.v))).size > 1) conflicts.push({what:'Date of birth', vals:facts.dob});
  if(new Set(facts.nationality.map(x => norm(x.v))).size > 1) conflicts.push({what:'Nationality', vals:facts.nationality});
  /* evidence, accounts, hours */
  const L = [...ids.values()], recs = new Set(), g = globalEnts();
  for(const x of L){ const ge = g.get(x.k); if(ge) for(const r of ge.recs) recs.add(r); }
  { const ge = g.get(idpKey(root) || ''); if(ge) for(const r of ge.recs) recs.add(r); }
  const R = [...recs].filter(r => r.type !== 'lead'), ts = R.map(r => r.ts).filter(Boolean).sort((a, b) => a - b);
  const acc = [], hrs = [];
  for(const x of L){ if(!/^(username|social|email)$/.test(x.e.type)) continue; const h = primary(x.e).replace(/^@/, '').replace(/^https?:\/\/[^/]+\/(@|u\/|user\/)?/, '').replace(/\/.*$/, '').toLowerCase();
    for(const cid of x.cases){ try{ const F2 = typeof footIndex === 'function' ? footIndex(cid) : null, a = F2 && F2.accounts.find(z => z.handle.toLowerCase() === h); if(a && a.created && !acc.some(z => z.h === a.handle)) acc.push({h:a.handle, platform:a.platform, created:a.created, names:a.names});
      const H = typeof hrIndex === 'function' ? hrIndex(cid) : null, p = H && H.people.find(z => z.who.replace(/^@|^u\//, '').toLowerCase() === h); if(p && !hrs.some(z => z.who === p.who)) hrs.push({who:p.who, offs:p.prof.offs, conf:p.prof.conf, flat:p.prof.flat, n:p.ts.length}); }catch(e){} } }
  const media = L.filter(x => x.e.type === 'media' || x.e.type === 'document');
  return {root, people, ids:L.filter(x => x.e.type !== 'media' && x.e.type !== 'document' && x.e.type !== 'alias').sort((a, b) => b.conf - a.conf || (IDP_STRONG.has(b.e.type) - IDP_STRONG.has(a.e.type))), media, facts, conflicts, recs:R, first:ts[0] || null, last:ts[ts.length - 1] || null, acc, hrs, cases:[...new Set([...people.map(p => p.e.caseId), ...L.flatMap(x => [...x.cases])])]};
}
/* how sure a link is: a three-step meter and a word */
const idpConf = c => `<span class="idp-cf c${c}" title="How sure this link is: ${IDP_CONF[c]}"><i></i><i></i><i></i><span>${IDP_CONF[c]}</span></span>`;
const idpCase = cid => { const c = theCase(cid); return c ? `<a href="${caseHash(cid)}" class="idp-case" title="${esc(c.name)}">${esc(caseNm(c))}</a>` : ''; };
const IDP_GROUPS = [['Contact', ['email', 'phone', 'messaging']], ['Accounts', ['username', 'social', 'forum', 'link', 'domain']], ['Money', ['crypto', 'transaction']], ['Devices and places', ['device', 'ip', 'location', 'breach', 'file']]];
/* per identifier: how much evidence names it, and when it was last seen */
function idpSeen(x){ const ge = globalEnts().get(x.k); if(!ge) return {n:0, last:null, first:null}; const R = ge.recs.filter(r => r.type !== 'lead'), ts = R.map(r => r.ts).filter(Boolean).sort((a, b) => a - b); return {n:R.length, first:ts[0] || null, last:ts[ts.length - 1] || null}; }
/* what is still open about this person */
function idpGaps(P){
  const G = [], has = t => P.ids.some(x => x.e.type === t);
  for(const c of P.conflicts) G.push(['warn', `${c.what} differs between cases (${c.vals.map(v => v.v).join(' / ')}). Find a document that settles it, or treat them as two people.`]);
  if(!P.facts.dob.length) G.push(['', 'No date of birth recorded.']);
  if(!has('email') && !has('phone')) G.push(['', 'No email address or phone number — the identifiers that tie accounts to one person most firmly.']);
  for(const o of P.people.slice(1)) if(!o.why.strong) G.push(['warn', `${primary(o.e) || 'The person'} in ${caseNm(o.e.caseId)} is joined only by a username. Confirm with a second identifier before treating them as the same person.`]);
  for(const x of P.ids) if(x.conf === 1) G.push(['', `${primary(x.e)} is only a possible link (${x.link && x.link.label ? x.link.label + ', ' : ''}two steps away). Confirm it directly.`]);
  if(!P.media.length) G.push(['', 'No photo linked.']);
  for(const h of P.hrs) if(h.flat) G.push(['warn', `${h.who} posts at all hours — it may be automated or shared.`]);
  return G.slice(0, 8);
}
/* a one-paragraph reading of the profile */
function idpSummary(P){
  const n = P.people.length, strong = P.people.slice(1).filter(o => o.why.strong), weak = P.people.slice(1).filter(o => !o.why.strong);
  const L = [];
  L.push(n > 1 ? `Appears in ${P.cases.length} case${P.cases.length === 1 ? '' : 's'} under ${n} name${n === 1 ? '' : 's'}.` : `Known in ${P.cases.length} case${P.cases.length === 1 ? '' : 's'}.`);
  if(strong.length) L.push(`Tied to ${strong.map(o => primary(o.e)).join(' and ')} by a shared ${[...new Set(strong.map(o => TYPES[o.why.shared.type].label.toLowerCase()))].join(' and ')} — a strong link.`);
  if(weak.length) L.push(`Possibly also ${weak.map(o => primary(o.e)).join(' and ')}, through a username only.`);
  const c3 = P.ids.filter(x => x.conf === 3).length; L.push(`${P.ids.length} identifier${P.ids.length === 1 ? '' : 's'}, ${c3} confirmed.`);
  if(P.acc.length){ const a = P.acc.slice().sort((x, y) => x.created.ms - y.created.ms)[0]; L.push(`Oldest known account: ${a.h}, made ${ftWhen(a.created)}.`); }
  const tz = P.hrs.find(h => !h.flat); if(tz) L.push(`Posts from around UTC${tz.offs.map(hrOff).join(' or ')}.`);
  if(P.conflicts.length) L.push(`The cases disagree on ${P.conflicts.map(c => c.what.toLowerCase()).join(' and ')}.`);
  return L.join(' ');
}
/* the person in the middle, their identifiers around them, other cases' people outside — line style by how sure */
function idpMap(P){
  const ids = P.ids.slice(0, 14), others = P.people.slice(1, 7); if(!ids.length) return '';
  /* identifiers on an ellipse around the person, starting off the vertical so labels spread sideways; people from other cases further out on the same ray */
  const rx = 210, ry = 92, n = ids.length, pos = ids.map((x, i) => { const a = -Math.PI / 2 + (i + .5) / n * Math.PI * 2; return [Math.cos(a) * rx, Math.sin(a) * ry, a]; });
  const dash = c => c >= 3 ? '' : c === 2 ? ' stroke-dasharray="6 4"' : ' stroke-dasharray="2 4"', short = v => v.length > 24 ? v.slice(0, 22) + '…' : v;
  const outer = []; others.forEach(o => { const i = ids.findIndex(x => x.entries.some(e => e.id === o.why.shared.id) || primary(x.e).toLowerCase().replace(/^@/, '') === primary(o.why.shared).toLowerCase().replace(/^@/, '')); if(i < 0) return; const [x, y, a] = pos[i]; outer.push({o, i, x:x + Math.cos(a) * 120, y:y + Math.sin(a) * 62}); });
  const xs = [0, ...pos.map(p => p[0]), ...outer.map(p => p.x)], ys = [0, ...pos.map(p => p[1]), ...outer.map(p => p.y)];
  const x0 = Math.min(...xs) - 120, x1 = Math.max(...xs) + 120, y0 = Math.min(...ys) - 34, y1 = Math.max(...ys) + 26;
  let svg = pos.map(([x, y], i) => `<line x1="0" y1="0" x2="${x}" y2="${y}" class="idp-ml"${dash(ids[i].conf)}></line>`).join('');
  svg += outer.map(({o, i, x, y}) => `<line x1="${pos[i][0]}" y1="${pos[i][1]}" x2="${x}" y2="${y}" class="idp-ml"${dash(o.conf)}></line>`).join('');
  svg += pos.map(([x, y], i) => `<g class="idp-mn"><circle cx="${x}" cy="${y}" r="5"></circle><text x="${x}" y="${y > 0 ? y + 18 : y - 10}" text-anchor="middle">${esc(short(primary(ids[i].e)))}</text></g>`).join('');
  svg += outer.map(({o, x, y}) => { const t = (primary(o.e) || 'Person') + ' · ' + caseNm(o.e.caseId), w = Math.min(220, 16 + t.length * 7); return `<g class="idp-mo"><rect x="${x - w / 2}" y="${y - 13}" width="${w}" height="26" rx="13"></rect><text x="${x}" y="${y + 4}" text-anchor="middle">${esc(short(t))}</text></g>`; }).join('');
  svg += `<g class="idp-mc"><circle cx="0" cy="0" r="22"></circle><text x="0" y="4.5" text-anchor="middle">${esc((primary(P.root) || '?').split(/\s+/).map(w => w[0]).join('').slice(0, 2).toUpperCase())}</text></g>`;
  return `<figure class="idp-map"><svg viewBox="${x0} ${y0} ${x1 - x0} ${y1 - y0}" role="img" aria-label="How the identifiers connect to ${esc(primary(P.root))}">${svg}</svg>
    <figcaption class="t3 small"><span class="idp-lg"><i class="s"></i>confirmed</span><span class="idp-lg"><i class="d"></i>likely</span><span class="idp-lg"><i class="o"></i>possible</span><span>· people in other cases on the outside</span></figcaption></figure>`;
}
function idpCard(P){
  const r = P.root, name = primary(r) || TYPES[r.type].label, aka = [...P.facts.name.slice(1), ...P.facts.alias].map(x => x.v), bad = new Set(P.conflicts.map(c => c.what));
  const ini = name.split(/\s+/).map(w => w[0]).join('').slice(0, 2).toUpperCase(), d10 = t => t ? E.fmtFull(t, tz()).slice(0, 10) : '—';
  const role = P.facts.role[0] ? P.facts.role[0].v : '', strongN = P.ids.filter(x => x.conf === 3).length;
  const extra = x => { const h = primary(x.e).replace(/^@/, '').replace(/^https?:\/\/[^/]+\/(@|u\/|user\/)?/, '').replace(/\/.*$/, '').toLowerCase(), a = P.acc.find(z => z.h.toLowerCase() === h), hr = P.hrs.find(z => z.who.replace(/^@|^u\//, '').toLowerCase() === h);
    return [a ? 'made ' + ftWhen(a.created) : '', hr ? (hr.flat ? 'posts at all hours' : 'posts from UTC' + hr.offs.map(hrOff).join('/')) : ''].filter(Boolean).join(' · '); };
  const fact = (what, L) => `<div class="idp-kf${bad.has(what) ? ' warn' : ''}"><dt>${esc(what)}</dt><dd>${L.length ? L.map(x => `<span>${esc(x.v)}${P.cases.length > 1 ? ` <span class="t3">${esc(x.cases.map(c => caseNm(c)).join(', '))}</span>` : ''}</span>`).join('') : '<span class="t3">Not known</span>'}${bad.has(what) ? `<em>${ico('triangle-alert','sm')}Cases disagree</em>` : ''}</dd></div>`;
  const gaps = idpGaps(P);
  return `<article class="idp" aria-label="Identity profile of ${esc(name)}">
    <header class="idp-hd"><div class="idp-av" aria-hidden="true">${esc(ini || '?')}</div>
      <div class="idp-who"><div class="idp-kind">${esc(TYPES[r.type].label)}${role ? ' · ' + esc(role) : ''}</div><h3>${esc(name)}</h3>${aka.length ? `<div class="idp-aka">Also known as ${aka.map(v => `<b>${esc(v)}</b>`).join(', ')}</div>` : ''}</div>
      <div class="idp-cases">${P.cases.map(idpCase).join('')}</div></header>
    <div class="idp-stats">${[[P.ids.length, 'identifiers', strongN + ' confirmed'], [P.cases.length, 'cases', P.people.length > 1 ? P.people.length + ' names' : 'one name'], [P.recs.length, 'pieces of evidence', ''], [d10(P.first), 'first seen', ''], [d10(P.last), 'last seen', '']].map(([v, l, s]) => `<div><b>${esc(String(v))}</b><span>${esc(l)}</span>${s ? `<small>${esc(s)}</small>` : ''}</div>`).join('')}</div>
    <p class="idp-sum">${esc(idpSummary(P))}</p>
    <div class="idp-grid">
      <div class="idp-main">
        <section><h4>Identifiers</h4>${P.ids.length ? `<div class="idp-tw"><table class="idp-tb"><thead><tr><th scope="col">Identifier</th><th scope="col">Link</th><th scope="col">How sure</th><th scope="col" class="n">Evidence</th><th scope="col">Last seen</th><th scope="col">Cases</th></tr></thead><tbody>
          ${P.ids.map(x => { const S = idpSeen(x), ex = extra(x); return `<tr><td><div class="idp-idc">${tbadge(x.e.type, 'sm')}<div><button class="lnk mono" data-act="idpEnt" data-id="${esc(x.e.id)}">${esc(primary(x.e))}</button><div class="t3 small">${esc(TYPES[x.e.type].label)}${ex ? ' · ' + esc(ex) : ''}</div></div></div></td>
            <td class="t2 small">${esc(x.link && x.link.label ? x.link.label : '—')}</td><td>${idpConf(x.conf)}</td><td class="n">${S.n || '—'}</td><td class="t2 small mono">${esc(S.last ? d10(S.last) : '—')}</td><td><span class="idp-cs">${[...x.cases].map(idpCase).join('')}</span></td></tr>`; }).join('')}</tbody></table></div>`
          : '<p class="t3 small">No identifiers linked yet. Link handles, emails, phones or wallets to this entry in the graph or from their details panel.</p>'}</section>
        ${P.ids.length ? `<section><h4>How they connect</h4>${idpMap(P)}</section>` : ''}
      </div>
      <aside class="idp-side">
        <section><h4>Key facts</h4><dl class="idp-kfs">${fact('Date of birth', P.facts.dob)}${fact('Nationality', P.facts.nationality)}</dl></section>
        ${P.people.length > 1 ? `<section><h4>Same person in other cases</h4>${P.people.slice(1).map(o => `<div class="idp-o idp-same"><div class="idp-oh"><b>${esc(primary(o.e) || 'Unnamed')}</b>${idpCase(o.e.caseId)}</div><div class="t2 small">Shares ${esc(TYPES[o.why.shared.type].label.toLowerCase())} <span class="mono">${esc(primary(o.why.shared))}</span></div><div class="idp-oh">${idpConf(o.conf)}<button class="lnk small" data-act="idpOpen" data-id="${esc(o.e.id)}">Open</button></div></div>`).join('')}</section>` : ''}
        ${gaps.length ? `<section><h4>Gaps to close</h4><ul class="idp-gaps">${gaps.map(([t, g]) => `<li class="${t}">${ico(t ? 'triangle-alert' : 'circle-dot','sm')}<span>${esc(g)}</span></li>`).join('')}</ul></section>` : ''}
        ${P.media.length ? `<section><h4>Photos and files</h4>${P.media.map(x => `<div class="idp-o"><button class="lnk" data-act="idpEnt" data-id="${esc(x.e.id)}">${esc(primary(x.e) || TYPES[x.e.type].label)}</button>${idpConf(x.conf)}</div>`).join('')}</section>` : ''}
      </aside></div>
    <p class="t3 small idp-foot">How sure: from the confidence on each relationship in the vault, one step weaker for every step past the first; across cases, from what is shared — an email, phone or wallet confirms, a username alone does not.</p></article>`;
}
function idpDlg(id){
  const P = idpBuild(id); if(!P) return;
  openDlg(dhead('Identity profile') + `<div class="in">${idpCard(P)}</div><footer><button class="btn" data-act="dclose">Close</button></footer>`); $('dlg').classList.add('xwide');
}
/* every person and organisation in every case, one card each, joined across cases */
function idpAll(){ const done = new Set(), out = [];
  for(const e of DB.entries.filter(x => x.type === 'person' || x.type === 'organization').sort((a, b) => (a.caseId === DB.active ? -1 : 0) - (b.caseId === DB.active ? -1 : 0))){ if(done.has(e.id)) continue; const P = idpBuild(e.id); if(!P) continue; P.people.forEach(p => done.add(p.e.id)); out.push(P); }
  return out; }
function idpListDlg(){
  const L = idpAll();
  openDlg(dhead('Identity profiles') + `<div class="in"><p class="t2 small" style="margin:0 0 12px">Every person and organisation in your vault, one card each — joined across cases when they share an identifier.</p>
    ${L.length ? `<ul class="idp-list">${L.map(P => `<li><button class="li" data-act="idpOpen" data-id="${esc(P.root.id)}">${tbadge(P.root.type, 'sm')}<div class="main2"><b>${esc(primary(P.root) || 'Unnamed')}</b><small>${P.cases.map(c => esc(caseNm(c))).join(', ')} · ${P.ids.length} identifier${P.ids.length === 1 ? '' : 's'}${P.people.length > 1 ? ' · the same person in ' + (P.people.length - 1) + ' other case' + (P.people.length > 2 ? 's' : '') : ''}${P.conflicts.length ? ' · cases disagree' : ''}</small></div></button></li>`).join('')}</ul>` : empty('users', 'No people in the vault yet', 'Add a Person entry and link their handles, emails, phones and wallets to it.')}</div>
    <footer><button class="btn" data-act="dclose">Close</button></footer>`); $('dlg').classList.add('xwide');
}
const IDP_ACTS = {
  idpOpen:id => idpDlg(id),
  idpList:() => idpListDlg(),
  idpEnt:id => { const e = entryById(id); if(!e) return; closeDlg(); if(e.caseId !== DB.active){ DB.active = e.caseId; save(); } go(caseHash(e.caseId, 'vault')); setTimeout(() => selectEntry(id), 50); },
};
