/* ==========================================================================
   Investigate — the screen for live lookups, verdicts and correlation.
   One indicator: every switched-on source in parallel, a scored verdict with its
   reasons, each source's answer, and what it led to. A whole case: every indicator
   checked in a queue, ranked, and grouped where the evidence says they belong together.
   ========================================================================== */
const LKV = {key:'', res:{}, pending:new Set(), bulk:null, paintT:0};
const LK_TRY = ['ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256', 'cve', 'asn', 'hostport'];
function lkPaint(){ if(LKV.paintT) return; LKV.paintT = setTimeout(() => { LKV.paintT = 0; if(UI.route.area === 'feeds' && UI.itab === 'look') renderMain(); renderInsp(); }, 120); }
function lkParse(q){
  const s = cap(q, 2048); if(!s) return null; const n = iocNorm(s);
  if(n && n.k === 'url'){ const m = /^https?:\/\/([^/:?#@\s]+)\/?$/i.exec(n.v), h = m && iocNorm(m[1]); if(h) return h; }                   // a bare http://host is the host
  if(n && LK_TRY.includes(n.k)) return n;
  if(/^AS\d{1,10}$/i.test(s)) return {k:'asn', v:s.toUpperCase()};
  return null;
}
async function lookGo(k, v, force){
  const key = k + ':' + v; UI.look = {k, v}; LKV.key = key; LKV.bulk = null;
  LKV.res = force ? {} : lkKnown(k, v); const on = lkFor(k).filter(lkOn); LKV.pending = new Set(on.filter(p => force || !lkFresh(p, LKV.res[p.id])).map(p => p.id));
  UI.itab = 'look'; if(UI.route.area !== 'feeds') go('#/feeds'); else renderMain();
  if(!on.length) return;
  await lkInvestigate(k, v, {force, onEach:(id, r) => { if(LKV.key !== key) return; LKV.res[id] = r; LKV.pending.delete(id); lkPaint(); }});
  if(LKV.key === key){ lkHist(k, v, lkVerdict(k, v, LKV.res)); save(); lkPaint(); }
}

/* ---------- drawing ---------- */
function vdRing(V, size = 64){
  const r = size / 2 - 5, c = 2 * Math.PI * r, col = VD_COL[V.band];
  return `<svg class="lk-ring" width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" role="img" aria-label="Score ${V.score} of 100"><circle cx="${size / 2}" cy="${size / 2}" r="${r}" fill="none" stroke="var(--line)" stroke-width="6"/>
    <circle cx="${size / 2}" cy="${size / 2}" r="${r}" fill="none" stroke="${col}" stroke-width="6" stroke-linecap="round" stroke-dasharray="${(c * V.score / 100).toFixed(1)} ${c.toFixed(1)}" transform="rotate(-90 ${size / 2} ${size / 2})"/>
    <text x="50%" y="54%" text-anchor="middle" dominant-baseline="middle" fill="var(--text)" font-size="${size / 3.4}" font-weight="650">${V.score}</text></svg>`;
}
const vdChip = V => `<span class="lk-band" style="--c:${VD_COL[V.band]}">${esc(VD_NAME[V.band])}</span>`;
function lkStatus(p, r, pending){
  if(pending) return `<span class="lk-st run">${ico('refresh-cw','sm spin')}Asking…</span>`;
  if(!lkSettings().on[p.id]) return '<span class="lk-st off">Off</span>';
  if(!lkRoute(p)) return '<span class="lk-st off">Needs your relay</span>';
  if(!r) return '<span class="lk-st off">Not asked</span>';
  if(!r.ok) return `<span class="lk-st err" title="${esc(r.err)}">${ico('triangle-alert','sm')}${esc(r.err.slice(0, 60))}</span>`;
  const s = (r.sig || []).reduce((a, x) => x.t === 'mal' ? 'mal' : a === 'mal' ? a : x.t === 'sus' ? 'sus' : a || x.t, '');
  return `<span class="lk-st ${s || (r.none ? 'none' : 'ok')}">${s === 'mal' ? 'Bad' : s === 'sus' ? 'Suspicious' : s === 'ben' ? 'Good' : r.none ? 'No record' : 'Answered'} · ${esc(iAgo(r.at))}</span>`;
}
function lkCard(p, r, pending){
  const facts = r && r.ok ? r.facts : [];
  return `<section class="lk-card${r && r.ok && (r.sig || []).some(s => s.t === 'mal') ? ' mal' : ''}"><header><b>${esc(p.name)}</b>${lkStatus(p, r, pending)}${r && r.link ? `<a class="iconbtn" href="${esc(r.link)}" target="_blank" rel="noopener noreferrer" aria-label="Open on ${esc(p.name)}" title="Open on ${esc(hostOf(r.link))}">${ico('external-link','sm')}</a>` : ''}</header>
    ${facts.length ? `<dl>${facts.map(([l, v]) => `<dt>${esc(l)}</dt><dd>${esc(v)}</dd>`).join('')}</dl>` : r && r.ok && r.none ? '' : !r && lkSettings().on[p.id] && lkRoute(p) ? '' : `<p class="t3">${esc(p.about)}</p>`}</section>`;
}
function ctiLookView(){
  const S = lkSettings(), onN = LK_PROVIDERS.filter(lkOn).length, relay = lkRelay();
  const form = `<form class="lk-q" data-form="ctiLook"><div class="search-in">${ico('scan-search')}<label class="sr" for="lkQ">Indicator to investigate</label><input id="lkQ" class="inp mono" placeholder="IP, domain, URL, file hash, CVE or ASN" value="${esc(UI.look ? UI.look.v : '')}" autocomplete="off" spellcheck="false"></div>
    <button class="btn primary" type="submit">${ico('radar','sm')}Investigate</button><button class="btn" type="button" data-act="lookCase">${ico('list-checks','sm')}Investigate ${esc(theCase().code)}</button>
    <button class="iconbtn" type="button" data-act="feedSources" data-v="look" aria-label="Lookup sources" title="Lookup sources">${ico('settings','sm')}</button></form>
    ${onN ? `<p class="lk-note">${ico('globe','sm')}${onN} source${onN > 1 ? 's' : ''} on${relay ? ' · relay ' + esc(hostOf(relay.url)) : ' · no relay — VirusTotal, AbuseIPDB, GreyNoise, urlscan and abuse.ch need one'}. Only the indicator you investigate is sent, and only to those sources.</p>`
      : `<div class="ti-relay">${ico('wifi-off','sm')}<span>No lookup source is switched on. Each one is off until you choose it — the indicator is sent to that service when you investigate.</span><button class="btn sm primary" data-act="lkFreeOn">${ico('wifi','sm')}Turn on the free sources</button><button class="btn sm" data-act="feedSources" data-v="look">Choose…</button></div>`}`;
  if(LKV.bulk) return form + lkBulkView();
  if(!UI.look) return form + lkHistView();
  const {k, v} = UI.look, P = lkFor(k), V = lkVerdict(k, v, LKV.res), key = k + ':' + v, busy = LKV.pending.size, mine = verdictOf(key);
  const order = p => (LKV.res[p.id] && LKV.res[p.id].ok && !LKV.res[p.id].none ? 0 : lkOn(p) ? 1 : 2);
  const A = V.attrs, rel = V.related.filter(x => x.k + ':' + x.v !== key);
  const pivots = [['Network', [A.asn, A.asname || A.org].filter(Boolean).join(' · ')], ['Prefix', A.prefix], ['Country', A.country], ['Registrar', A.registrar], ['Registered', A.created ? new Date(A.created).toISOString().slice(0, 10) : ''], ['Name servers', (A.ns || []).slice(0, 4).join(', ')], ['Open ports', (A.ports || []).slice(0, 20).join(', ')], ['Malware', (A.malware || []).slice(0, 5).join(', ')], ['Adversaries', (A.actors || []).join(', ')], ['Techniques', (A.ttp || []).slice(0, 8).join(', ')], ['Certificates', (A.certs || []).length ? (A.certs || []).length + '' : ''], ['Subdomains', (A.subs || []).length ? (A.subs || []).length + '' : '']].filter(x => x[1]);
  return form + `<div class="lk">
    <section class="card lk-head"><div class="lk-hl">${kindBadge(k, 'lg')}<div class="lk-id"><span class="t3">${esc(E.LABEL[k] || k)}</span><h2 class="mono">${esc(v)}</h2><div class="cxts">${ctxChips(k, v)}</div></div>
        <div class="lk-v">${V.answered.length || V.reasons.length ? vdRing(V) : ''}<div>${vdChip(V)}<small>${V.answered.length} of ${P.filter(lkOn).length} sources answered${busy ? ' · ' + busy + ' pending' : ''} · ${esc(V.conf)} confidence</small></div></div></div>
      <div class="lk-acts">
        <button class="btn sm" data-act="lookAgain">${ico('refresh-cw', busy ? 'sm spin' : 'sm')}Check again</button>
        ${/malicious|suspicious|benign/.test(V.band) && mine !== V.band ? `<button class="btn sm primary" data-act="lookVerdict" data-v="${V.band}">${ico('check','sm')}Mark ${esc(V.band)}</button>` : mine ? `<span class="t3 small">Your verdict: ${vdLabel(mine)}</span>` : ''}
        ${KIND_TO_TYPE[k] || k === 'cve' ? `<button class="btn sm" data-act="lookAdd">${ico('plus','sm')}Add to ${esc(theCase().code)}</button>` : ''}
        <button class="btn sm${isWatched(key) ? ' on' : ''}" data-act="watch" data-id="${esc(key)}">${ico(isWatched(key) ? 'eye-off' : 'eye','sm')}${isWatched(key) ? 'Unwatch' : 'Watch'}</button>
        <button class="btn sm ghost" data-act="lookNote">${ico('copy','sm')}Copy summary</button></div></section>
    <div class="lk-grid">
      <div class="lk-col">
        <section class="card lk-why"><h3>Why</h3>${V.reasons.length ? `<ul>${V.reasons.slice(0, 12).map(e => `<li class="${e.t}"><i aria-hidden="true"></i><span>${esc(e.why)}</span><small>${esc(e.src)}</small></li>`).join('')}</ul>`
          : `<p class="t3">${busy ? 'Waiting for answers…' : V.answered.length ? 'No source has anything against it, or for it.' : 'Nothing asked yet.'}</p>`}
          ${V.failed.length ? `<p class="t3 small">${esc(V.failed.join(', '))} did not answer.</p>` : ''}</section>
        ${pivots.length ? `<section class="card lk-piv"><h3>What it is</h3><dl>${pivots.map(([l, x]) => `<dt>${esc(l)}</dt><dd>${esc(x)}</dd>`).join('')}</dl></section>` : ''}
        ${rel.length ? `<section class="card lk-rel"><h3>Leads to <span class="t3">${rel.length}</span>${rel.length > 1 ? `<button class="btn sm ghost" data-act="lookRelAll">${ico('plus','sm')}Add all to ${esc(theCase().code)}</button>` : ''}</h3>
          <ul>${rel.slice(0, 40).map((x, i) => `<li>${kindBadge(x.k, 'sm')}<span class="mono">${esc(x.v)}</span><small>${esc(x.rel.join(', '))}</small><button class="iconbtn" data-act="lookRel" data-v="${i}" aria-label="Investigate ${esc(x.v)}" title="Investigate">${ico('radar','sm')}</button><button class="iconbtn" data-act="lookRelAdd" data-v="${i}" aria-label="Add ${esc(x.v)} to the case" title="Add to ${esc(theCase().code)}">${ico('plus','sm')}</button></li>`).join('')}</ul>
          ${rel.length > 40 ? `<p class="t3 small">${rel.length - 40} more not shown.</p>` : ''}</section>` : ''}
      </div>
      <div class="lk-cards">${P.slice().sort((a, b) => order(a) - order(b)).map(p => lkCard(p, LKV.res[p.id], LKV.pending.has(p.id))).join('')}</div>
    </div></div>`;
}
function lkHistView(){
  const H = (DB.intel.lookHist || []).slice(0, 60);
  return H.length ? `<section class="card lk-hist"><header><h3>Recent investigations</h3><button class="btn sm ghost" data-act="lookHistClear" style="margin-left:auto">${ico('trash-2','sm')}Clear</button></header>
    <ul>${H.map((h, i) => `<li><button class="li" data-act="lookHist" data-v="${i}">${kindBadge(h.k, 'sm')}<span class="mono">${esc(h.v)}</span>${vdChip(h)}<span class="t3">${h.score}</span><small>${esc(iAgo(h.at))}</small></button><button class="iconbtn" data-act="lookHistDel" data-v="${i}" aria-label="Remove ${esc(h.v)} from history">${ico('x','sm')}</button></li>`).join('')}</ul></section>`
    : empty('scan-search', 'Investigate an indicator', 'Paste an IP, domain, URL, file hash or CVE above. Every source you switched on is asked at once, and the answers are weighed into one verdict with the reasons shown — or investigate every indicator in the case and see which belong together.');
}

/* ---------- a whole case ---------- */
function lkCaseItems(){
  const D = derive(), keys = new Set([...D.ents.keys(), ...D.byKey.keys()]), out = [];
  for(const key of keys){ const {k, v} = entSplit(key); if(!['ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256', 'cve'].includes(k)) continue;
    if((k === 'ipv4' || k === 'ipv6') && !/^Public/.test(E.ipClass(v))) continue; if(!lkFor(k).some(lkOn)) continue; out.push({key, k, v}); }
  return out.slice(0, 300);
}
async function lookCase(){
  const items = lkCaseItems(); if(!items.length) return toast(LK_PROVIDERS.some(lkOn) ? 'No public IPs, domains, URLs, hashes or CVEs in ' + theCase().code : 'Turn on lookup sources first');
  const B = LKV.bulk = {caseId:DB.active, items:items.map(x => ({...x, V:null, res:null})), done:0, stop:false}; UI.look = null; renderMain();
  let i = 0; const worker = async () => { while(i < B.items.length && !B.stop && LKV.bulk === B){ const it = B.items[i++];
    it.res = await lkInvestigate(it.k, it.v); it.V = lkVerdict(it.k, it.v, it.res); lkHist(it.k, it.v, it.V); B.done++; lkPaint(); } };
  await Promise.all([worker(), worker(), worker()]);
  if(LKV.bulk === B){ B.corr = lkCorrelate(B.items.filter(x => x.V).map(x => ({key:x.key, k:x.k, v:x.v, attrs:x.V.attrs}))); B.fin = true; save(); lkPaint(); }
}
function lkBulkView(){
  const B = LKV.bulk, L = B.items.filter(x => x.V).sort((a, b) => b.V.score - a.V.score), pct = Math.round(B.done / B.items.length * 100), cnt = b => L.filter(x => x.V.band === b).length;
  const C = B.corr, byKey = new Map(B.items.map(x => [x.key, x]));
  return `<div class="lk">
    <section class="card lk-bh"><div><h3>${esc(theCase(B.caseId).code)} — ${B.items.length} indicators</h3><p class="t3">${B.fin ? 'Done.' : B.stop ? 'Stopped.' : 'Checking ' + B.done + ' of ' + B.items.length + '…'} ${['malicious', 'suspicious', 'benign'].map(b => cnt(b) ? `<span class="lk-band" style="--c:${VD_COL[b]}">${cnt(b)} ${b}</span>` : '').join(' ')}</p></div>
      <div class="lk-prog" role="progressbar" aria-valuenow="${pct}" aria-valuemin="0" aria-valuemax="100"><i style="width:${pct}%"></i></div>
      <div class="lk-acts">${B.fin || B.stop ? '' : `<button class="btn sm" data-act="lookStop">${ico('square','sm')}Stop</button>`}
        ${L.some(x => /malicious|suspicious/.test(x.V.band) && !verdictOf(x.key)) ? `<button class="btn sm primary" data-act="lookBulkVerdict">${ico('check','sm')}Mark the ${L.filter(x => /malicious|suspicious/.test(x.V.band) && !verdictOf(x.key)).length} flagged</button>` : ''}
        <button class="btn sm ghost" data-act="lookBulkClose">${ico('x','sm')}Close</button></div></section>
    ${C && C.clusters.length ? `<section class="card lk-cl"><h3>${ico('waypoints','sm')}Belong together <span class="t3">${C.clusters.length} group${C.clusters.length > 1 ? 's' : ''}</span><button class="btn sm primary" data-act="lookLink">${ico('share-2','sm')}Link on the graph</button></h3>
      ${C.clusters.slice(0, 12).map((g, gi) => { const P = C.pairs.filter(p => p.score >= 0.6 && g.includes(p.a)); return `<div class="lk-grp"><b>Group ${gi + 1}</b><span class="t3">${esc(pivotWhy(P.flatMap(p => p.why)))}</span>
        <div class="lk-gi">${g.map(key => { const it = byKey.get(key); return `<button class="lk-gc" data-act="lookOpen" data-id="${esc(key)}">${kindBadge(it.k, 'sm')}<span class="mono">${esc(it.v)}</span>${it.V ? vdChip(it.V) : ''}</button>`; }).join('')}</div></div>`; }).join('')}</section>` : B.fin ? '<p class="t3 lk-note">No two indicators share a certificate, address, favicon, name servers or other distinguishing trait.</p>' : ''}
    <section class="card"><table class="tbl lk-tbl"><thead><tr><th>Indicator</th><th>Verdict</th><th class="n">Score</th><th class="hide-m">Strongest reason</th><th class="hide-m">Sources</th></tr></thead><tbody>
      ${L.map(x => `<tr data-act="lookOpen" data-id="${esc(x.key)}"><td><div class="ce-e">${kindBadge(x.k, 'sm')}<span class="mono">${esc(x.v)}</span></div></td><td>${vdChip(x.V)}</td><td class="n">${x.V.score}</td><td class="hide-m t2">${esc((x.V.reasons[0] || {}).why || '—')}</td><td class="hide-m t3">${x.V.answered.length}</td></tr>`).join('')}
      ${B.items.filter(x => !x.V).slice(0, 5).map(x => `<tr class="t3"><td><div class="ce-e">${kindBadge(x.k, 'sm')}<span class="mono">${esc(x.v)}</span></div></td><td colspan="4">${B.stop ? 'Not checked' : 'Waiting…'}</td></tr>`).join('')}</tbody></table></section></div>`;
}
function lkSummary(){
  const {k, v} = UI.look, V = lkVerdict(k, v, LKV.res);
  return [`${v} (${E.LABEL[k] || k}) — ${VD_NAME[V.band]}, score ${V.score}/100, ${V.conf} confidence, ${V.answered.length} sources, ${new Date().toISOString().slice(0, 16).replace('T', ' ')} UTC`, ...V.reasons.slice(0, 8).map(e => `- ${e.why} [${e.src}]`)].join('\n');
}

/* ---------- inspector: the last verdict, and a button ---------- */
function lkInspSection(k, v){
  if(!lkFor(k).length) return '';
  const h = (DB.intel && DB.intel.lookHist || []).find(x => x.k === k && x.v === v);
  return `<div class="isec"><h4>Live lookups ${h ? `<span class="t3">${esc(iAgo(h.at))}</span>` : ''}</h4>${h ? `<p class="lk-ih">${vdChip(h)}<b>${h.score}</b><span class="t3">/ 100</span></p>` : ''}
    <button class="btn sm" data-act="lookEnt" data-id="${esc(k + ':' + v)}">${ico('radar','sm')}${h ? 'Open the investigation' : 'Investigate'}</button></div>`;
}

/* ---------- Sources → Lookups ---------- */
function lkSourcesTab(){
  const S = lkSettings(), r = S.relay, grp = [['direct', 'Free — straight from your browser', p => p.via === 'direct'], ['both', 'Your API key — direct, or through your relay', p => p.via === 'both'], ['relay', 'Through your relay — these services do not allow browser access', p => p.via === 'relay']];
  const row = p => { const route = lkRoute(p), on = !!S.on[p.id];
    return `<div class="srow ti-srow"><label class="sw"><input type="checkbox" data-act="lkToggle" data-id="${p.id}" ${on ? 'checked' : ''} aria-label="Use ${esc(p.name)}"><span></span></label>
    <div class="tn"><b>${esc(p.name)}</b><span class="ti-host">${ico('globe','sm')}${route === 'relay' ? 'Through your relay to' : 'Contacts'} <span class="mono">${esc(p.host)}</span>${!route ? ' · <span class="ti-err">needs your relay' + (p.key ? ' or a key' : '') + '</span>' : ''}</span><span class="t3">${esc(p.about)}</span><span class="t3 small">Checks: ${esc(p.kinds.map(x => E.LABEL[x] || x).join(', '))}</span>
      ${p.key ? `<span class="ti-key"><label for="lkkey-${p.id}">${esc(p.key.label)}${p.key.optional ? ' (optional)' : ''}</label><input id="lkkey-${p.id}" type="password" class="inp" data-lkkey="${p.id}" value="${esc(S.keys[p.id] || '')}" placeholder="${p.via === 'both' ? 'or leave empty and use the relay' : 'optional'}" autocomplete="off" spellcheck="false"></span>` : ''}</div></div>`; };
  return `<div class="lk-relay"><h4>${ico('server','sm')}Your relay <span class="t3">${lkRelay() ? 'set' : 'not set'}</span></h4>
      <p class="t3">Your own Cloudflare Worker (in the OSINTrix repository under <span class="mono">tools/relay</span>) that holds your API keys and calls the services that refuse browsers. The free plan is enough. Only the indicator you look up passes through it. A <span class="mono">workers.dev</span> address works as is; a custom domain must also be added to <span class="mono">connect-src</span> in index.html.</p>
      <div class="frow"><div class="field" style="margin:0"><label for="lkRelayUrl">Relay address</label><input id="lkRelayUrl" class="inp mono" type="url" data-lkrelay="url" value="${esc(r.url || '')}" placeholder="https://osintrix-relay.you.workers.dev" autocomplete="off" spellcheck="false"></div>
        <div class="field" style="margin:0"><label for="lkRelayTok">Relay token</label><input id="lkRelayTok" class="inp" type="password" data-lkrelay="token" value="${esc(r.token || '')}" placeholder="the RELAY_TOKEN you set" autocomplete="off" spellcheck="false"></div></div>
      <div class="wrap" style="margin-top:8px"><button class="btn sm" data-act="lkRelayTest">${ico('activity','sm')}Test relay</button><span id="lkRelayRes" class="t3 small" role="status"></span></div></div>
    <p class="t2" style="margin:14px 0 6px">Each source is off until you switch it on. Turning one on is your consent to send the indicators you investigate to that service. Keys are kept in this workspace (encrypted when you lock it) and left out of backups — keeping them in the relay is safer.</p>
    <div class="wrap" style="margin-bottom:8px"><button class="btn sm" data-act="lkFreeOn">${ico('wifi','sm')}Turn on all free sources</button><button class="btn sm ghost" data-act="lkAllOff">Turn all off</button><button class="btn sm ghost" data-act="lkCacheClear">${ico('trash-2','sm')}Clear saved answers</button></div>
    ${grp.map(([id, l, f]) => `<h4 class="lk-gh">${esc(l)}</h4><div class="srcs">${LK_PROVIDERS.filter(f).map(row).join('')}</div>`).join('')}`;
}
async function lkRelayTest(){
  const out = $('lkRelayRes'), R = lkRelay(); if(!R){ if(out) out.textContent = 'Enter an https:// address first.'; return; }
  if(out) out.textContent = 'Testing…';
  try{ const r = await lkFetch(R.url.replace(/\/+$/, '') + '/health', {headers:{'X-Relay-Token':R.token || ''}, timeout:10000}); const j = JSON.parse(r.text);
    if(!j || !j.ok) throw new Error('The relay answered, but not as expected');
    const P = (Array.isArray(j.providers) ? j.providers : []).map(x => cap(x, 30)); if(out) out.textContent = 'Working · ' + (P.length ? 'keys for ' + P.join(', ') : 'no provider keys set yet');
  }catch(e){ if(out) out.textContent = 'Failed: ' + (e.message || e); }
}

const LK_ACTS = {
  lookCase:() => lookCase(),
  lookStop:() => { if(LKV.bulk) LKV.bulk.stop = true; renderMain(); },
  lookBulkClose:() => { if(LKV.bulk) LKV.bulk.stop = true; LKV.bulk = null; renderMain(); },
  lookOpen:id => { const {k, v} = entSplit(id); const B = LKV.bulk, it = B && B.items.find(x => x.key === id); LKV.bulk = null; if(it && it.res){ UI.look = {k, v}; LKV.key = id; LKV.res = {...it.res}; LKV.pending = new Set(); renderMain(); } else lookGo(k, v); },
  lookAgain:() => UI.look && lookGo(UI.look.k, UI.look.v, true),
  lookEnt:id => { const {k, v} = entSplit(id); lookGo(k, v); },
  lookHist:(id, v) => { const h = (DB.intel.lookHist || [])[+v]; if(h) lookGo(h.k, h.v); },
  lookHistDel:(id, v) => { DB.intel.lookHist.splice(+v, 1); mutate('removed an investigation from history'); renderMain(); },
  lookHistClear:() => confirmDlg('Clear the investigation history?', 'The list of recent investigations is emptied. Saved answers from the sources stay until they expire (Sources → Lookups → Clear saved answers).', 'Clear', () => { DB.intel.lookHist = []; mutate('cleared investigation history'); renderMain(); }),
  lookVerdict:(id, v) => { const key = UI.look.k + ':' + UI.look.v, old = DB.verdicts[key]; DB.verdicts[key] = v; mutate('marked ' + UI.look.v + ' ' + v); renderMain(); toast('Marked ' + v + ' — applies in every case', 'Undo', () => { if(old) DB.verdicts[key] = old; else delete DB.verdicts[key]; mutate('undo verdict'); renderMain(); }); },
  lookAdd:() => { const {k, v} = UI.look, V = lkVerdict(k, v, LKV.res); if(ctiAddEntry(k, v, VD_NAME[V.band] + ' (' + V.score + ') — ' + V.reasons.slice(0, 2).map(e => e.why).join('; '))){ mutate('added ' + v); toast(v + ' added to ' + theCase().code); } else toast('Already in ' + theCase().code); },
  lookRel:(id, v) => { const V = lkVerdict(UI.look.k, UI.look.v, LKV.res), x = V.related.filter(r => r.k + ':' + r.v !== UI.look.k + ':' + UI.look.v)[+v]; if(x) lookGo(x.k, x.v); },
  lookRelAdd:(id, v) => { const V = lkVerdict(UI.look.k, UI.look.v, LKV.res), x = V.related.filter(r => r.k + ':' + r.v !== UI.look.k + ':' + UI.look.v)[+v]; if(!x) return; ctiAddEntry(x.k, x.v, x.rel.join(', ') + ' of ' + UI.look.v); mutate('added ' + x.v); toast(x.v + ' added to ' + theCase().code); },
  lookRelAll:() => { const V = lkVerdict(UI.look.k, UI.look.v, LKV.res), L = V.related.filter(r => r.k + ':' + r.v !== UI.look.k + ':' + UI.look.v).slice(0, 100); let n = 0; L.forEach(x => { if(ctiAddEntry(x.k, x.v, x.rel.join(', ') + ' of ' + UI.look.v)) n++; }); mutate('added related indicators'); toast(n + ' added to ' + theCase().code); },
  lookNote:async () => { try{ await navigator.clipboard.writeText(lkSummary()); toast('Summary copied'); }catch(e){ toast('Copy failed'); } },
  lookBulkVerdict:() => { const L = LKV.bulk.items.filter(x => x.V && /malicious|suspicious/.test(x.V.band) && !verdictOf(x.key)); L.forEach(x => DB.verdicts[x.key] = x.V.band); mutate('marked ' + L.length + ' indicators'); renderMain();
    toast(L.length + ' marked', 'Undo', () => { L.forEach(x => delete DB.verdicts[x.key]); mutate('undo verdicts'); renderMain(); }); },
  lookLink:() => { const C = LKV.bulk && LKV.bulk.corr; if(!C) return; const n = lkLinkPairs(C.pairs.filter(p => p.score >= 0.6)); mutate('linked correlated indicators'); toast(n ? n + ' relationship' + (n > 1 ? 's' : '') + ' added to the graph' : 'They are already linked', n ? 'Open graph' : '', n ? () => go(caseHash(DB.active, 'graph')) : null); },
  lkToggle:(id, v, t) => { const S = lkSettings(); if(t.checked) S.on[id] = true; else delete S.on[id]; mutate((t.checked ? 'turned on ' : 'turned off ') + lkProv(id).name); },
  lkFreeOn:() => { const S = lkSettings(); LK_PROVIDERS.filter(p => p.via === 'direct').forEach(p => S.on[p.id] = true); if(lkRelay()) LK_PROVIDERS.filter(p => p.via !== 'direct').forEach(p => S.on[p.id] = true); mutate('turned on lookup sources'); if($('dlg') && $('dlg').open) sourcesDlg('look'); renderMain(); toast('Free lookup sources on'); },
  lkAllOff:() => { lkSettings().on = {}; mutate('turned off lookup sources'); sourcesDlg('look'); renderMain(); },
  lkCacheClear:() => confirmDlg('Clear saved answers?', 'Answers the sources gave are kept for a while so the same indicator is not asked twice. Clearing them means the next investigation asks again.', 'Clear', async () => { await lkLoad(); LK.cache.clear(); if(STORE.idb) await IDB.del('cti:look'); toast('Saved answers cleared'); }),
  lkRelayTest:() => lkRelayTest(),
  watchNow:async (id, v, t) => { const keys = Object.keys(DB.watch || {}).filter(k => WATCH_KINDS.has(entSplit(k).k)); if(!keys.length) return toast('Nothing on the watchlist can be checked online'); if(!LK_PROVIDERS.some(lkOn)) return toast('Turn on lookup sources in Threat Intel → Sources first');
    if(t) t.disabled = true; toast('Checking ' + keys.length + ' watched indicator' + (keys.length > 1 ? 's' : '') + '…'); const n = await watchCheck(keys, {quiet:true}); toast(n ? n + ' changed — see Changes' : 'No changes'); renderMain(); },
  watchSeen:() => { Object.values(DB.watch || {}).forEach(w => w.unseen = false); mutate('watch changes seen'); renderMain(); },
};
document.addEventListener('change', ev => { const t = ev.target; if(!t || !t.dataset) return;
  if(t.id === 'watchEvery'){ DB.prefs.watchEvery = +t.value || 0; mutate('online watch checks: ' + t.options[t.selectedIndex].text); watchMonitor(); return; }
  if(t.dataset.lkkey){ const S = lkSettings(), v = cap(t.value, 300).replace(/\s+/g, ''); if(v) S.keys[t.dataset.lkkey] = v; else delete S.keys[t.dataset.lkkey]; mutate('saved a lookup key'); }
  if(t.dataset.lkrelay){ const S = lkSettings(), v = cap(t.value, 300).trim(); if(t.dataset.lkrelay === 'url'){ if(v && !/^https:\/\/[a-z0-9.-]+(:\d+)?(\/[\w./-]*)?$/i.test(v)){ t.setCustomValidity('Use an https:// address'); t.reportValidity(); return; } t.setCustomValidity(''); S.relay.url = v.replace(/\/+$/, ''); } else S.relay.token = v; mutate('saved relay settings'); }
});
