/* ==========================================================================
   Chats & forwards — the network behind Telegram and Discord chats you imported
   (case → Infrastructure → Chats)
     · sources: every channel your chats forward from — how often, into how many
       chats, first and last time, and whether it turns up in your other cases
     · coordinated pushes: the same post appearing in several chats within
       minutes — forwarded from one source, or copy-pasted — and which chat had
       it first
     · copy-paste accounts: the same text sent by different accounts, a sign
       of coordinated or automated posting
     · clusters: chats that draw on the same sources, grouped, with what they share
     · a map: sources on the left, your chats on the right, width = forwards
   And for every account number (Telegram or Discord): the names it went by, when.
   Built from what the exports recorded; nothing is looked up.
   ========================================================================== */
const CN = {key:'', v:null}, CN_PUSH_MIN = 15;
const cnRecs = caseId => DB.records.filter(r => r.chatnet && (!caseId || r.caseId === caseId) && theCase(r.caseId) && !theCase(r.caseId).stash);
const cnSrcKey = s => s[0] ? 'id:' + s[0] : 'name:' + String(s[1]).toLowerCase();
function cnIndex(caseId){
  const key = caseId + ':' + rev; if(CN.key === key) return CN.v;
  const R = cnRecs(caseId), chats = R.map(r => ({r, name:r.chatnet.chat, app:r.chatnet.app, n:r.chatnet.msgs.length}));
  /* sources */
  const S = new Map();
  R.forEach((r, ci) => { const N = r.chatnet; for(const m of N.msgs){ if(m[2] < 0) continue; const s = N.srcs[m[2]], k = cnSrcKey(s); let x = S.get(k);
    if(!x){ x = {k, id:s[0], name:s[1], n:0, chats:new Map(), first:m[0], last:m[0]}; S.set(k, x); } x.n++; x.chats.set(ci, (x.chats.get(ci) || 0) + 1); x.first = Math.min(x.first, m[0]); x.last = Math.max(x.last, m[0]); } });
  /* the same sources in other cases */
  const elsewhere = new Map(); for(const r of cnRecs('')) if(r.caseId !== caseId) for(const s of r.chatnet.srcs){ const k = cnSrcKey(s); if(!elsewhere.has(k)) elsewhere.set(k, new Set()); elsewhere.get(k).add(r.caseId); }
  const sources = [...S.values()].map(x => ({...x, other:[...(elsewhere.get(x.k) || [])]})).sort((a, b) => b.chats.size - a.chats.size || b.n - a.n);
  /* coordinated pushes: one text in two or more chats, first appearances close together */
  const byFp = new Map();
  R.forEach((r, ci) => { const N = r.chatnet; for(const m of N.msgs){ if(!m[3]) continue; let x = byFp.get(m[3]); if(!x){ x = []; byFp.set(m[3], x); } x.push({ci, t:m[0], a:N.authors[m[1]], src:m[2] >= 0 ? N.srcs[m[2]][1] : ''}); } });
  const pushes = [], copy = [];
  for(const [fp, L] of byFp){
    const firstIn = new Map(); for(const x of L) if(!firstIn.has(x.ci) || x.t < firstIn.get(x.ci).t) firstIn.set(x.ci, x);
    if(firstIn.size >= 2){ const F = [...firstIn.values()].sort((a, b) => a.t - b.t), spread = F[F.length - 1].t - F[0].t, src = F.find(x => x.src);
      pushes.push({fp, chats:F, spread, fast:spread <= CN_PUSH_MIN * 60000, src:src ? src.src : '', forwarded:F.filter(x => x.src).length, copied:F.filter(x => !x.src).length, rec:R[F[0].ci]}); }
    const by = new Map(); for(const x of L) if(!x.src){ const ak = x.a[0] || 'name:' + x.a[1]; if(!by.has(ak)) by.set(ak, x); }
    if(by.size >= 2) copy.push({fp, accounts:[...by.values()].sort((a, b) => a.t - b.t), chats:new Set([...by.values()].map(x => x.ci)).size, spread:Math.max(...[...by.values()].map(x => x.t)) - Math.min(...[...by.values()].map(x => x.t))});
  }
  pushes.sort((a, b) => b.fast - a.fast || b.chats.length - a.chats.length || a.spread - b.spread);
  copy.sort((a, b) => b.accounts.length - a.accounts.length || a.spread - b.spread);
  /* who posts first: for each chat, how often it had a shared post before the others */
  const leads = new Map(); for(const p of pushes) leads.set(p.chats[0].ci, (leads.get(p.chats[0].ci) || 0) + 1);
  /* clusters: chats that share at least a third of their sources */
  const setOf = ci => new Set(sources.filter(s => s.chats.has(ci)).map(s => s.k)), sets = chats.map((c, i) => setOf(i)), par = chats.map((c, i) => i), find = i => par[i] === i ? i : (par[i] = find(par[i]));
  const pairs = []; for(let i = 0; i < chats.length; i++) for(let j = i + 1; j < chats.length; j++){ const A = sets[i], B = sets[j]; if(!A.size || !B.size) continue; let inter = 0; for(const k of A) if(B.has(k)) inter++; const jac = inter / (A.size + B.size - inter); if(jac >= 1 / 3){ par[find(i)] = find(j); pairs.push([i, j, jac, inter]); } }
  const groups = new Map(); chats.forEach((c, i) => { const g = find(i); if(!groups.has(g)) groups.set(g, []); groups.get(g).push(i); });
  const clusters = [...groups.values()].filter(g => g.length >= 2).map(g => ({chats:g, shared:sources.filter(s => g.filter(i => s.chats.has(i)).length >= 2).slice(0, 8)}));
  return CN.key = key, CN.v = {chats, sources, pushes, copy, leads, clusters, pairs};
}
/* ---------- names over time, for one account number ---------- */
function cnNames(k){
  const {k:kind, v} = entSplit(k); if(!/^(tgid|dcid)$/.test(kind)) return [];
  const app = kind === 'tgid' ? 'Telegram' : 'Discord', out = [];
  for(const r of DB.records){ const A = r.chatAuthor; if(!A || A.app !== app || A.id !== v) continue;
    for(const n of A.names || []) out.push({name:n.name, uname:n.uname, first:n.first, last:n.last, chat:A.chat, caseId:r.caseId, rec:r.id}); }
  /* one row per name: its whole span, and where it was seen */
  const by = new Map(); for(const x of out){ const key = x.name + '\u0000' + (x.uname || ''); const y = by.get(key); if(!y) by.set(key, {...x, chats:new Set([x.chat]), cases:new Set([x.caseId])}); else { y.first = Math.min(y.first, x.first); y.last = Math.max(y.last, x.last); y.chats.add(x.chat); y.cases.add(x.caseId); } }
  return [...by.values()].sort((a, b) => a.first - b.first);
}
function cnNamesHtml(k){
  const L = cnNames(k); if(!L.length) return '';
  const d = t => esc(E.fmtDate(t, tz()));
  return `<div class="isec"><h4>Names over time <span class="t3">${L.length > 1 ? L.length + ' names — the account number stayed the same' : 'one name seen'}</span></h4><ol class="cn-nh">${L.map((x, i) => `<li${i === L.length - 1 ? ' class="now"' : ''}><b>${esc(x.name)}</b>${x.uname && x.uname !== x.name ? ` <span class="t3">(${esc(x.uname)})</span>` : ''}<small>${d(x.first)}${x.last > x.first ? ' – ' + d(x.last) : ''} · ${esc([...x.chats].slice(0, 2).join(', '))}${x.chats.size > 2 ? ' +' + (x.chats.size - 2) : ''}${x.cases.size > 1 ? ' · ' + x.cases.size + ' cases' : ''}</small></li>`).join('')}</ol>
    ${L.length > 1 ? '<p class="t3 small" style="margin:6px 0 0">Names come from the exports you imported, as each recorded them; a rename between two exports shows here.</p>' : ''}</div>`;
}
/* every account number in a case that went by more than one name */
function cnRenamed(caseId){ const ids = new Map(); for(const r of DB.records){ if(r.caseId !== caseId || !r.chatAuthor || !r.chatAuthor.id) continue; const k = (r.chatAuthor.app === 'Telegram' ? 'tgid:' : 'dcid:') + r.chatAuthor.id; ids.set(k, 1); }
  return [...ids.keys()].map(k => ({k, L:cnNames(k)})).filter(x => x.L.length > 1).sort((a, b) => b.L.length - a.L.length); }

/* ---------- the view ---------- */
function cnMap(X){
  const S = X.sources.slice(0, 18), C = X.chats; if(!S.length || !C.length) return '';
  const H = Math.max(S.length, C.length) * 30 + 30, W = 760, lx = 220, rx = 540, ys = i => 26 + i * (H - 40) / Math.max(1, S.length - 1 || 1), yc = i => 26 + i * (H - 40) / Math.max(1, C.length - 1 || 1);
  const yS = i => S.length === 1 ? H / 2 : ys(i), yC = i => C.length === 1 ? H / 2 : yc(i), mx = Math.max(1, ...S.flatMap(s => [...s.chats.values()]));
  const paths = S.flatMap((s, i) => [...s.chats.entries()].map(([ci, n]) => `<path d="M${lx},${yS(i)} C${(lx + rx) / 2},${yS(i)} ${(lx + rx) / 2},${yC(ci)} ${rx},${yC(ci)}" stroke-width="${(1 + 9 * n / mx).toFixed(1)}" class="${s.other.length ? 'x' : ''}"><title>${esc(s.name)} → ${esc(C[ci].name)}: ${n}</title></path>`)).join('');
  return `<svg class="cn-map" viewBox="0 0 ${W} ${H}" role="img" aria-label="Forward network: ${S.length} sources into ${C.length} chats">${paths}
    ${S.map((s, i) => `<g><circle cx="${lx}" cy="${yS(i)}" r="5" class="${s.other.length ? 'x' : ''}"/><text x="${lx - 10}" y="${yS(i) + 4}" text-anchor="end">${esc(s.name.length > 26 ? s.name.slice(0, 25) + '…' : s.name)}</text></g>`).join('')}
    ${C.map((c, i) => `<g><rect x="${rx}" y="${yC(i) - 7}" width="14" height="14" rx="3"/><text x="${rx + 22}" y="${yC(i) + 4}">${esc(c.name.length > 28 ? c.name.slice(0, 27) + '…' : c.name)}</text></g>`).join('')}</svg>`;
}
function cnView(c){
  const X = cnIndex(c.id), ago = ms => ms < 60000 ? Math.round(ms / 1000) + ' s' : ms < 3600000 ? Math.round(ms / 60000) + ' min' : ms < 864e5 ? (ms / 3600000).toFixed(1) + ' h' : Math.round(ms / 864e5) + ' days', d = t => esc(E.fmtFull(t, tz()).slice(0, 16));
  if(!X.chats.length) return empty('message-square', 'No chat exports in this case', 'Drop a Telegram Desktop export (result.json) or a DiscordChatExporter JSON into Capture. Each author becomes a record, and the chat’s forwards, shared posts and copy-paste are mapped here.');
  const fast = X.pushes.filter(p => p.fast), ren = cnRenamed(c.id), nm = i => esc(X.chats[i].name);
  return `<div class="cn">
    <div class="cn-sum">${[[X.chats.length, 'chats'], [X.chats.reduce((s, x) => s + x.n, 0).toLocaleString(), 'messages'], [X.sources.length, 'sources forwarded from'], [fast.length, 'pushed into several chats within ' + CN_PUSH_MIN + ' min'], [X.copy.length, 'texts sent by several accounts'], [ren.length, 'accounts that changed name']].map(([n, l]) => `<div><b>${n}</b><span>${l}</span></div>`).join('')}</div>
    ${X.sources.length ? `<section class="card"><header><h3>Forward map</h3><span class="t3 small">sources → your chats · width = forwards${X.sources.some(s => s.other.length) ? ' · <span class="cn-x">orange</span>: also in another case' : ''}</span></header><div class="body cn-mapw">${cnMap(X)}</div></section>` : ''}
    <div class="cn-two">
      <section class="card"><header><h3>Sources</h3><span class="t3 small">channels your chats forward from</span></header><div class="body flush">${X.sources.length ? `<table class="tbl cn-t"><thead><tr><th>Source</th><th class="n">Forwards</th><th class="n">Chats</th><th>Seen</th></tr></thead><tbody>${X.sources.slice(0, 40).map(s => `<tr><td><b>${esc(s.name)}</b>${s.id ? `<small class="mono t3">${esc(s.id)}</small>` : ''}${s.other.length ? `<small class="cn-o">also in ${s.other.map(id => esc(caseNm(theCase(id), 22))).join(', ')}</small>` : ''}</td><td class="n">${s.n}</td><td class="n">${s.chats.size}</td><td class="w">${d(s.first)}${s.last > s.first ? '<br>' + d(s.last) : ''}</td></tr>`).join('')}</tbody></table>` : '<p class="t3" style="padding:12px 16px">No forwards in these exports.</p>'}</div></section>
      <section class="card"><header><h3>Coordinated pushes</h3><span class="t3 small">the same post in several chats</span></header><div class="body flush">${X.pushes.length ? X.pushes.slice(0, 20).map(p => `<button class="li cn-p${p.fast ? ' fast' : ''}" data-act="selRec" data-id="${p.rec.id}"><div class="main2"><b>${p.fast ? 'Within ' + ago(p.spread) : 'Over ' + ago(p.spread)} — ${p.chats.length} chats${p.src ? ', from ' + esc(p.src) : ''}${p.copied && p.forwarded ? ' (' + p.copied + ' copy-pasted)' : !p.forwarded ? ' (copy-pasted, not forwarded)' : ''}</b>
          <small>${p.chats.map((x, i) => `${nm(x.ci)} ${i ? '+' + ago(x.t - p.chats[0].t) : '<em>first</em>'}`).join(' · ')}</small></div></button>`).join('') : '<p class="t3" style="padding:12px 16px">No post appears in more than one chat.</p>'}</div></section>
    </div>
    <div class="cn-two">
      <section class="card"><header><h3>Same text, different accounts</h3><span class="t3 small">not forwarded — typed or pasted</span></header><div class="body flush">${X.copy.length ? X.copy.slice(0, 15).map(x => `<div class="li cn-c"><div class="main2"><b>${x.accounts.length} accounts${x.chats > 1 ? ' in ' + x.chats + ' chats' : ''}, within ${ago(x.spread || 1000)}</b><small>${x.accounts.slice(0, 6).map(a => esc(a.a[1]) + (a.a[0] ? ' <span class="mono t3">' + esc(a.a[0]) + '</span>' : '')).join(' · ')}</small></div></div>`).join('') : '<p class="t3" style="padding:12px 16px">No message was sent word for word by more than one account.</p>'}</div></section>
      <section class="card"><header><h3>Clusters and first posters</h3><span class="t3 small">chats that share sources</span></header><div class="body">${X.clusters.length ? X.clusters.map(g => `<div class="cn-cl"><b>${g.chats.map(nm).join(' · ')}</b><small>share ${g.shared.map(s => esc(s.name)).join(', ') || 'sources'}</small></div>`).join('') : '<p class="t3" style="margin:0">No two chats share a third of their sources.</p>'}
        ${X.leads.size ? `<h4 class="cn-h">Posts first</h4>${[...X.leads.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([ci, n]) => `<div class="cn-cl"><b>${nm(ci)}</b><small>first with ${n} shared post${n === 1 ? '' : 's'}</small></div>`).join('')}` : ''}</div></section>
    </div>
    ${ren.length ? `<section class="card"><header><h3>Accounts that changed their name</h3><span class="t3 small">same account number, different names</span></header><div class="body flush">${ren.slice(0, 30).map(x => `<button class="li" data-act="selEnt" data-id="${esc(x.k)}"><div class="main2"><b>${x.L.map(n => esc(n.name)).join(' → ')}</b><small><span class="mono">${esc(entSplit(x.k).v)}</span> · ${esc(E.fmtDate(x.L[0].first, tz()))} – ${esc(E.fmtDate(x.L[x.L.length - 1].last, tz()))}</small></div></button>`).join('')}</div></section>` : ''}
    <p class="t3 small">A push within minutes into several chats, and the same words from different accounts, are signs of coordination — not proof: news channels forward the same breaking post, and people paste the same announcement. Read the messages.</p></div>`;
}
