/* ==========================================================================
   Timeline → Patterns, two more findings:
   · Clocks that disagree: the same indicator (IP, domain, URL, hash, email)
     seen by two sources at times that differ by the same amount again and
     again — one source's clock is off, or its time zone was read wrongly.
     It can be corrected (and undone) for that source in this case.
   · Sessions: each host's events split where it goes quiet, and the stages
     each burst passes through, in order — "logon → discovery → staging in
     12 minutes". The ones with the most suspicious content come first.
   ========================================================================== */
const TX2_KEYS = new Set(['ipv4', 'ipv6', 'domain', 'url', 'sha256', 'sha1', 'md5', 'email']);
const tx2Med = a => { const s = a.slice().sort((x, y) => x - y), m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };
const tx2Src = r => String(r.source || '').trim() || 'unknown source';
/* Sources whose clocks are consistently apart. For two sources, every sighting of a shared indicator is compared with
   every sighting of it in the other source (within 14 hours); the offset most of them agree on wins. A repeated indicator
   then cannot pair the wrong events. A source that is off against several others is reported once, as the odd one out. */
function tx2Pair(A, B){
  const ds = []; for(const [k, ta] of A){ const tb = B.get(k); if(!tb) continue; for(const t of ta) for(const u of tb){ const d = u - t; if(Math.abs(d) <= 14 * 36e5) ds.push([d, k]); } if(ds.length > 20000) break; }
  if(ds.length < 3) return null;
  const bins = new Map(); for(const [d] of ds){ const b = Math.round(d / 6e4); for(const x of [b - 1, b, b + 1]) bins.set(x, (bins.get(x) || 0) + 1); }
  const best = [...bins.entries()].sort((x, y) => y[1] - x[1])[0][0] * 6e4, tol = Math.max(6e4, Math.abs(best) * 0.03);
  const mem = ds.filter(([d]) => Math.abs(d - best) <= tol), keys = new Set(mem.map(x => x[1])); if(mem.length < 3 || keys.size < 2) return null;
  const med = tx2Med(mem.map(x => x[0])), shared = [...A.keys()].filter(k => B.has(k)), sightings = Math.min(shared.reduce((n, k) => n + A.get(k).length, 0), shared.reduce((n, k) => n + B.get(k).length, 0));
  if(mem.length < 0.6 * sightings) return null;
  return {med, close:mem.length, n:sightings, keys:[...keys].slice(0, 4).map(k => k.split(':').slice(1).join(':'))};
}
function tx2Skew(T){
  const bySrc = new Map(); for(const r of T){ const s = tx2Src(r); if(!bySrc.has(s)) bySrc.set(s, []); bySrc.get(s).push(r); }
  const S = [...bySrc.entries()].filter(([, L]) => L.length >= 3).slice(0, 12); if(S.length < 2) return [];
  const idx = new Map(S.map(([s, L]) => { const M = new Map(); for(const r of L) for(const e of r.ents || []){ if(!TX2_KEYS.has(e.k)) continue; const k = e.k + ':' + String(e.v).toLowerCase(); if(!M.has(k)) M.set(k, []); M.get(k).push(r.ts); } return [s, M]; }));
  const pairs = [], agree = new Set();
  for(let i = 0; i < S.length; i++) for(let j = i + 1; j < S.length; j++){ const a = S[i][0], b = S[j][0], P = tx2Pair(idx.get(a), idx.get(b)); if(!P) continue;
    if(Math.abs(P.med) < 12e4){ agree.add(a + '\u0000' + b); agree.add(b + '\u0000' + a); continue; }
    pairs.push({a, b, ...P}); }
  /* the odd one out: the source in the most disagreeing pairs; its offset is given as "it records things later/earlier than the others" */
  const out = [], used = new Set();
  while(true){ const cnt = new Map(); for(const p of pairs){ if(used.has(p)) continue; for(const s of [p.a, p.b]) cnt.set(s, (cnt.get(s) || 0) + 1); }
    if(!cnt.size) break; const odd = [...cnt.entries()].sort((x, y) => y[1] - x[1])[0][0], mine = pairs.filter(p => !used.has(p) && (p.a === odd || p.b === odd));
    mine.forEach(p => used.add(p));
    const rel = mine.map(p => ({other:p.a === odd ? p.b : p.a, d:p.a === odd ? -p.med : p.med, p})), med = tx2Med(rel.map(x => x.d)), h = med / 36e5;
    out.push({b:odd, a:rel.map(x => x.other).join(' and '), others:rel.map(x => x.other), med:Math.round(med), close:rel.reduce((n, x) => n + x.p.close, 0), n:rel.reduce((n, x) => n + x.p.n, 0),
      keys:[...new Set(rel.flatMap(x => x.p.keys))].slice(0, 4), zone:Math.abs(h - Math.round(h)) * 60 <= 2 && Math.round(h) !== 0 ? Math.round(h) : null}); }
  return out.sort((x, y) => y.close - x.close).slice(0, 4);
}
/* stage names (ATT&CK tactics) an event shows, in the chain's terms */
function tx2Stages(r){
  const tac = new Map(ATTACK.tactics.map(t => [t[1], t[2]])), tech = new Map(ATTACK.tech.map(t => [t[0], t])), st = [];
  const add = s => { const k = tac.has(s) ? s : s === 'defense-evasion' ? (tac.has('stealth') ? 'stealth' : s) : s; if(tac.has(k)) st.push(tac.get(k)); };
  try{ for(const o of E.observations(r)){ const ids = String(o.t || '').match(/T\d{4}(?:\.\d{3})?/g) || []; ids.forEach(id => { const t = tech.get(id) || tech.get(id.split('.')[0]); if(t) t[2].slice(0, 1).forEach(add); }); if(!ids.length && typeof RW_TAG !== 'undefined' && RW_TAG[o.tag]) add(RW_TAG[o.tag][1]); } }catch(e){}
  for(const e of r.ents || []) if(e.k === 'ttp'){ const t = tech.get(e.v.toUpperCase()) || tech.get(e.v.toUpperCase().split('.')[0]); if(t) t[2].slice(0, 1).forEach(add); }
  if(typeof CH_TAGS !== 'undefined') for(const tg of r.tags || []){ const m = CH_TAGS.find(([re]) => re.test(String(tg).toLowerCase())); if(m) add(m[1]); }
  if(/\b(4624|4625|4648|4776)\b/.test(r.body || '') && /logon|log on|signed in|authenticat/i.test(r.title + ' ' + r.body) && !st.length) st.push('Logon');
  return [...new Set(st)];
}
function tx2Sessions(T){
  const byHost = new Map(); for(const r of T){ if(!r.host) continue; if(!byHost.has(r.host)) byHost.set(r.host, []); byHost.get(r.host).push(r); }
  const out = [];
  for(const [h, L] of byHost){ if(L.length < 3) continue; L.sort((a, b) => a.ts - b.ts);
    const gaps = L.slice(1).map((r, i) => r.ts - L[i].ts), cut = Math.max(15 * 6e4, Math.min(2 * 36e5, 6 * (tx2Med(gaps) || 0)));
    let cur = [L[0]]; const flush = () => { if(cur.length >= 3) out.push(cur); };
    for(let i = 1; i < L.length; i++){ if(L[i].ts - L[i - 1].ts > cut){ flush(); cur = []; } cur.push(L[i]); } flush(); }
  return out.map(L => { const steps = []; let score = 0;
    for(const r of L){ for(const s of tx2Stages(r)) if(steps[steps.length - 1] !== s && !steps.includes(s)) steps.push(s); score += (typeof tlxScore === 'function' ? tlxScore(r).s : 0); }
    return {host:L[0].host, from:L[0].ts, to:L[L.length - 1].ts, n:L.length, steps, score:score + steps.length * 2, recs:L}; })
    .filter(s => s.steps.length).sort((a, b) => b.score - a.score || b.n - a.n).slice(0, 6);
}
function tlxMore(D, card, f, g){
  const T = D.recs.filter(r => r.type !== 'lead' && r.ts).sort((a, b) => a.ts - b.ts), parts = {skew:'', sess:''};
  const SK = tx2Skew(T), SS = tx2Sessions(T);
  if(SK.length) parts.skew = card('clock-alert', 'amber', 'Clocks that disagree', `<ul class="tlx-l">${SK.map(x => `<li><div><b>${esc(x.b)}</b> records the same things <b>${g(Math.abs(x.med))} ${x.med > 0 ? 'later' : 'earlier'}</b> than <b>${esc(x.a)}</b></div>
      <div class="t2">${x.close} of ${x.n} sightings agree, on ${x.keys.map(k => '<span class="mono">' + esc(k) + '</span>').join(', ')}${x.zone ? ` · exactly ${Math.abs(x.zone)} hour${Math.abs(x.zone) > 1 ? 's' : ''} — most likely a time zone read wrongly` : ' · one of the clocks is off'}</div>
      <div class="wrap"><button class="btn xs" data-act="tx2Shift" data-v="${esc(JSON.stringify({s:x.b, d:-x.med}))}">${ico('clock','sm')}Move ${esc(x.b)} ${x.med > 0 ? 'earlier' : 'later'} by ${g(Math.abs(x.med))}</button>${x.others.length === 1 ? `<button class="btn xs ghost" data-act="tx2Shift" data-v="${esc(JSON.stringify({s:x.a, d:x.med}))}">or move ${esc(x.a)} instead</button>` : ''}</div></li>`).join('')}</ul>
    <p class="t3 small">The same indicator seen by two sources should be seen at about the same time. A steady gap means one clock is wrong; until it is corrected, the order of events between these sources is not reliable. Correcting changes only this case's times, and can be undone.</p>`);
  if(SS.length) parts.sess = card('route', SS.some(s => s.score >= 4) ? 'red' : '', 'Sessions', `<ul class="tlx-l">${SS.map(s => `<li><div><b class="mono">${esc(s.host)}</b> · ${f(s.from)} → ${esc(E.fmtClock(s.to, tz()))} <span class="t3">(${g(Math.max(s.to - s.from, 1000))}, ${s.n} events)</span></div>
      <div class="tx2-steps">${s.steps.map(x => `<span class="chip sq">${esc(x)}</span>`).join('<span class="t3" aria-hidden="true">→</span>')}</div>
      <div class="wrap"><button class="btn xs" data-act="tx2Sess" data-v="${s.from}|${s.to}|${esc(s.host)}">${ico('list-filter','sm')}Show this session</button></div></li>`).join('')}</ul>
    <p class="t3 small">Each host's events, split where it goes quiet for longer than usual. The stages come from technique IDs, what OSINTrix recognises, and tags; sessions with the most suspicious content first.</p>`);
  return parts;
}
const TX2_ACTS = {
  tx2Shift:(id, v) => { let o; try{ o = JSON.parse(v); }catch(e){ return; } const c = theCase(); if(!c || !isFinite(o.d)) return;
    const L = DB.records.filter(r => r.caseId === c.id && tx2Src(r) === o.s && r.ts), before = L.map(r => [r, r.ts, r.tsShift]);
    L.forEach(r => { r.ts += o.d; r.tsShift = (r.tsShift || 0) + o.d; }); mutate('corrected the clock of ' + o.s); renderMain();
    toast(`${L.length} event${L.length === 1 ? '' : 's'} from ${o.s} moved ${o.d > 0 ? 'later' : 'earlier'} by ${E.fmtGap(Math.abs(o.d))}`, 'Undo', () => { before.forEach(([r, t, s]) => { r.ts = t; if(s == null) delete r.tsShift; else r.tsShift = s; }); mutate('undid a clock correction'); renderMain(); }); },
  tx2Sess:(id, v) => { const [a, b, h] = String(v).split('|'); UI.facet.win = {from:+a, to:+b, at:+a, label:'session on ' + h}; UI.facet.host = h; UI.tlMode = 'events'; renderMain(); },
};
