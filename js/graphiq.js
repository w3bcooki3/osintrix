/* ==========================================================================
   Graph intelligence
     • Risk: suspicion spreads from what is judged malicious along the links you drew,
       weakening with every hop and with weaker links; benign entries stop it. Each
       score says which malicious entry it comes from and through what.
     • Key nodes: PageRank, betweenness and connections combined, with the reason.
     • Hidden links: live-lookup answers already saved (no new requests) are compared —
       a shared certificate, IP, favicon, name servers… becomes a suggestion.
     • Expand online: one node's live lookups bring back what it resolves to, its
       hostnames, subdomains and samples, as new entries linked with the relation.
   ========================================================================== */
const RISK_HOP = 0.6, RISK_CONF = {3:1, 2:0.8, 1:0.55};
/* how much suspicion an entry takes from a malicious neighbour: infrastructure fully, people, organisations and places far less — they are often the victim or a bystander */
const RISK_GROUP = {tech:1, files:1, intel:1, comms:0.9, finance:0.9, identity:0.6, places:0.3}, RISK_TYPE = {person:0.35, org:0.35, company:0.35, registrar:0.3, address:0.3};
const riskTake = e => e ? (RISK_TYPE[e.type] != null ? RISK_TYPE[e.type] : RISK_GROUP[(TYPES[e.type] || {}).group] != null ? RISK_GROUP[TYPES[e.type].group] : 0.6) : 0.6;
function gRisk(caseId){
  caseId = caseId || DB.active; const D = derive(caseId), ids = new Set(D.entries.map(e => e.id)), H = typeof cpHist === 'function' ? cpHist() : new Map();
  const adj = new Map(); for(const l of D.links){ if(!ids.has(l.a) || !ids.has(l.b)) continue; const w = RISK_CONF[l.conf] || 0.55;
    for(const [x, y] of [[l.a, l.b], [l.b, l.a]]){ if(!adj.has(x)) adj.set(x, []); adj.get(x).push({to:y, w, label:l.label}); } }
  const R = new Map(), stop = new Set();
  for(const e of D.entries){ const v = entryVerdict(e), k = entryKey(e), h = k && H.get(k);
    if(v === 'benign') stop.add(e.id);
    const s = v === 'malicious' ? 1 : v === 'suspicious' ? 0.5 : h && h.band === 'malicious' ? 0.8 * h.score / 100 : h && h.band === 'suspicious' ? 0.45 * h.score / 100 : 0;
    if(s) R.set(e.id, {r:s, seed:e.id, via:[], own:true}); }
  /* max-product spreading (a widest-path search): the strongest single chain wins, so every score can be explained */
  const q = [...R.keys()];
  while(q.length){ q.sort((a, b) => R.get(a).r - R.get(b).r); const id = q.pop(), cur = R.get(id); if(stop.has(id) && !cur.own) continue;
    for(const n of adj.get(id) || []){ const take = riskTake(entryById(n.to)), r = cur.r * RISK_HOP * n.w * take; if(r < 0.05) continue; const o = R.get(n.to);
      if(!o || (!o.own && r > o.r + 1e-9)){ R.set(n.to, {r:stop.has(n.to) ? Math.min(r, 0.1) : r, seed:cur.seed, via:[...cur.via, {id, label:n.label}], own:false}); if(!stop.has(n.to)) q.push(n.to); } } }
  return R;
}
function riskWhy(x){ const s = entryById(x.seed); if(!s) return ''; const hops = x.via.length;
  return hops <= 1 ? 'linked to ' + primary(s) + (x.via[0] ? ' (' + x.via[0].label + ')' : '') : hops + ' links from ' + primary(s) + ' via ' + x.via.slice(1).map(v => { const e = entryById(v.id); return e ? primary(e) : ''; }).filter(Boolean).slice(0, 2).join(', '); }

/* key nodes, from the drawn graph */
function gKeyNodes(){
  if(!cy || cy.nodes().length < 3) return [];
  const pr = cy.elements().pageRank({dampingFactor:0.85}), bc = cy.elements().betweennessCentrality({directed:false}), N = cy.nodes();
  const mx = f => Math.max(1e-9, ...N.map(f)), mp = mx(n => pr.rank(n)), mb = mx(n => bc.betweenness(n)), md = mx(n => n.degree(false));
  return N.map(n => { const p = pr.rank(n) / mp, b = bc.betweenness(n) / mb, d = n.degree(false) / md, why = [];
      if(b > 0.5) why.push('connects separate groups'); if(d >= 0.6) why.push(n.degree(false) + ' links'); if(p > 0.7 && !why.length) why.push('central to the case');
      const e = entryById(n.id()); if(e && entryVerdict(e) === 'malicious') why.push('malicious');
      return {id:n.id(), s:0.45 * p + 0.35 * b + 0.2 * d, why}; })
    .filter(x => x.s > 0.2).sort((a, b) => b.s - a.s).slice(0, 6);
}

/* hidden links from saved lookup answers (no network) */
function gInfraSuggest(D){
  if(typeof lkKnown !== 'function' || !LK.cache) return [];
  const items = [];
  for(const e of D.entries){ const k = entryKey(e); if(!k) continue; const {k:kind, v} = entSplit(k); const res = lkKnown(kind, v); if(!Object.keys(res).length) continue;
    items.push({key:e.id, k:kind, v, attrs:lkMerge(res)}); }
  if(items.length < 2) return [];
  return lkCorrelate(items).pairs.filter(p => p.score >= 0.55);
}

/* ---------- expand a node with live lookups ---------- */
const EXP_REL_ORDER = ['resolves to', 'reverse DNS', 'hostname', 'certificate name', 'CNAME', 'same sample', 'hosted domain', 'served from', 'subdomain', 'hosts a subdomain', 'seen with', 'ISP domain'];
async function expandOnline(id){
  const e = entryById(id), key = e && entryKey(e); if(!key) return toast('This entry has no value to look up');
  const {k, v} = entSplit(key); if(typeof lkFor !== 'function' || !lkFor(k).some(lkOn)) return toast(lkFor && lkFor(k).length ? 'Switch on lookup sources in Threat Intel → Sources first' : 'Nothing online can look up a ' + (E.LABEL[k] || k));
  toast('Looking up ' + v + '…');
  const res = await lkInvestigate(k, v), V = lkVerdict(k, v, res); lkHist(k, v, V);
  const D = derive(), have = new Map(D.entries.map(x => [entryKey(x), x])), rank = r => { const i = EXP_REL_ORDER.indexOf(r.rel[0]); return i < 0 ? 99 : i; };
  const rel = V.related.filter(x => x.k + ':' + x.v !== key && KIND_TO_TYPE[x.k]).sort((a, b) => rank(a) - rank(b));
  const subs = rel.filter(x => /subdomain/.test(x.rel[0])), pick = [...rel.filter(x => !/subdomain/.test(x.rel[0])).slice(0, 12), ...subs.slice(0, Math.max(3, 15 - rel.filter(x => !/subdomain/.test(x.rel[0])).length))].slice(0, 15);
  const made = [], links = [], base = e.pos || {x:0, y:0};
  pick.forEach((x, i) => { const kk = x.k + ':' + x.v; let t = have.get(kk);
    if(!t){ const type = KIND_TO_TYPE[x.k]; t = {id:uid('v'), caseId:DB.active, type, fields:{[TYPES[type].fields[0][0]]:x.v}, priority:'medium', starred:false, tags:['online'], notes:'', src:'', created:Date.now(),
      pos:{x:base.x + 220 * Math.cos(i / pick.length * 2 * Math.PI), y:base.y + 220 * Math.sin(i / pick.length * 2 * Math.PI)}}; DB.entries.push(t); made.push(t); have.set(kk, t); }
    const label = cap(x.rel[0], 60);
    if(!DB.links.some(l => l.caseId === DB.active && ((l.a === id && l.b === t.id) || (l.a === t.id && l.b === id)))){ const l = {id:uid('l'), caseId:DB.active, a:id, b:t.id, label, conf:2, src:'', auto:true, why:'Live lookup: ' + x.rel.join(', ')}; DB.links.push(l); links.push(l); } });
  if(!made.length && !links.length) return toast(V.answered.length ? 'The sources found nothing new to add — ' + VD_NAME[V.band].toLowerCase() + ' (' + V.score + ')' : 'No source answered');
  mutate('expanded ' + v + ' online'); renderAll();
  toast(`${made.length} entities and ${links.length} links from live lookups${rel.length > pick.length ? ' (' + (rel.length - pick.length) + ' more in Investigate)' : ''} · ${VD_NAME[V.band]} ${V.score}`, 'Undo', () => {
    const s = new Set(made.map(x => x.id)), sl = new Set(links.map(l => l.id)); DB.entries = DB.entries.filter(x => !s.has(x.id)); DB.links = DB.links.filter(l => !sl.has(l.id)); mutate('undid online expand'); renderAll(); });
}

/* ---------- colour by risk ---------- */
function applyRisk(){
  if(!cy) return; cy.batch(() => cy.nodes().removeClass('rk1 rk2 rk3')); if(!UI.graph.risk) return;
  const R = gRisk(); cy.batch(() => R.forEach((x, id) => { const n = cy.getElementById(id); if(n.length) n.addClass(x.r >= 0.6 ? 'rk3' : x.r >= 0.3 ? 'rk2' : 'rk1'); }));
}
