/* ==========================================================================
   Timeline analysis — the "Patterns" view of a case's timeline.
   Reads only the case's own records and verdicts; nothing leaves the browser.
     · first sign of compromise: the earliest event that carries a malicious or
       suspicious indicator, an initial-access technique or a delivery tag,
       scored and explained; the host it happened on; the dwell time after it
     · bursts: time slices far busier than the case's usual rate
     · quiet periods: gaps much longer than the usual spacing between events
     · hosts that went silent long before the rest (shut down, wiped, or logs cleared)
     · log clearing (Windows 1102 / 104, wevtutil cl, Clear-EventLog, history -c …)
     · time problems: future or impossible dates, unsure time zones, and events
       whose own text carries a time far from where they sit (often a zone mix-up)
     · working hours: when the suspicious activity happens, and which UTC offset
       would make it an office day — a hint, never proof
   Each finding can open the matching events in the timeline.
   ========================================================================== */
const TLX_INIT = /^T(1566|1190|1133|1078|1189|1195|1199|1091|1200|1659)\b/;   // ATT&CK initial access
const TLX_TAG = /\b(phish\w*|initial[- ]?access|lnk|macro|maldoc|dropper|exploit\w*|loader|payload|malware|c2|beacon\w*|implant|webshell|ransom\w*)\b/i;
const TLX_CLEAR = /\b(event ?id[: ]*1102|eventid[":= ]*1102|event ?id[: ]*104\b|audit log was cleared|log file was cleared|wevtutil(\.exe)?\s+(cl|clear-log)\b|clear-eventlog|remove-eventlog|history\s+-c\b|unset\s+histfile|rm\s+(-\w+\s+)*\S*\.bash_history|shred\s+.*\/var\/log)/i;
const TLX_C = {sig:'', v:null};
function tlxScore(r){
  const why = []; let s = 0;
  for(const e of r.ents || []){ const v = verdictOf(entKey(e));
    if(v === 'malicious'){ s += 3; why.push(E.LABEL[e.k] + ' ' + e.v + ' judged malicious'); }
    else if(v === 'suspicious'){ s += 1.5; why.push(E.LABEL[e.k] + ' ' + e.v + ' judged suspicious'); }
    if(e.k === 'ttp' && TLX_INIT.test(e.v)){ s += 3; why.push('initial-access technique ' + e.v); } }
  const tg = (r.tags || []).join(' '); const m = tg.match(TLX_TAG) || String(r.title || '').match(TLX_TAG);
  if(m){ s += 2; why.push('tagged “' + m[1].toLowerCase() + '”'); }
  if(r.answer && /malicious|compromis|attack/i.test(r.answer)){ s += 1; why.push('your answer says so'); }
  return {s, why:[...new Set(why)].slice(0, 4)};
}
function tlxAnalyse(D){
  const sig = D.recs.length + ':' + rev + ':' + Object.keys(DB.verdicts || {}).length; if(TLX_C.sig === sig) return TLX_C.v;
  const ev = D.recs.filter(r => r.type !== 'lead'), T = ev.filter(r => r.ts).sort((a, b) => a.ts - b.ts), now = Date.now(), out = {n:ev.length, timed:T.length};
  /* time problems first: they make everything else less reliable */
  const future = T.filter(r => r.ts > now + 864e5), ancient = T.filter(r => r.ts < Date.UTC(1995, 0, 1)), unsure = T.filter(r => r.tsZone && r.tsZone !== 'explicit');
  const mism = []; for(const r of T){ const raw = E.lineTime(r.body || ''); if(!raw) continue; const t = E.parseTime(raw); if(!t || !isFinite(t)) continue; const d = t - r.ts;
    if(Math.abs(d) > 9e5){ const h = d / 36e5; mism.push({r, d, zone:Math.abs(h - Math.round(h)) < 0.02 && Math.abs(h) <= 14 && Math.abs(h) >= 1 ? Math.round(h) : null}); } }
  out.time = {future, ancient, unsure, mism, noTs:ev.length - T.length};
  const good = T.filter(r => !future.includes(r) && !ancient.includes(r));
  if(good.length < 2){ out.empty = true; TLX_C.sig = sig; TLX_C.v = out; return out; }
  const t0 = good[0].ts, t1 = good[good.length - 1].ts, span = t1 - t0; Object.assign(out, {t0, t1, span, hosts:[...new Set(good.map(r => r.host).filter(Boolean))]});
  /* first sign of compromise */
  const sc = good.map(r => ({r, ...tlxScore(r)})), bad = sc.filter(x => x.s >= 2);
  if(bad.length){ const f = bad[0], lastBad = bad[bad.length - 1], before = good.filter(r => r.ts < f.r.ts && r.ts >= f.r.ts - 36e5 && (!f.r.host || r.host === f.r.host));
    out.first = {r:f.r, why:f.why, before, dwell:lastBad.r.ts - f.r.ts, nBad:bad.length, host:f.r.host || '', later:bad.slice(1, 4).map(x => x.r)}; }
  /* bursts: busy slices against the usual rate */
  const bin = Math.max(6e4, Math.min(36e5, Math.round(span / 160) || 6e4)), nb = Math.min(4000, Math.floor(span / bin) + 1), cnt = new Array(nb).fill(0);
  for(const r of good) cnt[Math.min(nb - 1, Math.floor((r.ts - t0) / bin))]++;
  const nz = cnt.filter(Boolean).sort((a, b) => a - b), base = nz.length ? nz[Math.floor(nz.length / 2)] : 0, mean = good.length / nb, sd = Math.sqrt(cnt.reduce((s, c) => s + (c - mean) ** 2, 0) / nb);
  const hot = cnt.map(c => c >= Math.max(5, base * 4, mean + 3 * sd));
  const bursts = []; for(let i = 0; i < nb; i++){ if(!hot[i]) continue; let j = i; while(j + 1 < nb && hot[j + 1]) j++;
    const from = t0 + i * bin, to = t0 + (j + 1) * bin, R = good.filter(r => r.ts >= from && r.ts < to), hs = countBy(R, r => r.host).filter(([h]) => h), tags = countBy(R, r => r.tags);
    bursts.push({from, to, n:R.length, x:base ? Math.round(R.length / (j - i + 1) / base) : null, host:hs[0] ? hs[0][0] : '', hostShare:hs[0] ? hs[0][1] / R.length : 0, tags:tags.slice(0, 3).map(t => t[0]), bad:R.filter(r => tlxScore(r).s >= 2).length}); i = j; }
  out.bursts = bursts.sort((a, b) => b.n - a.n).slice(0, 5); out.bin = bin; out.hist = cnt; out.hot = hot;
  /* quiet periods */
  const gaps = []; for(let i = 1; i < good.length; i++){ const g = good[i].ts - good[i - 1].ts; if(g > 0) gaps.push({g, a:good[i - 1], b:good[i]}); }
  const gs = gaps.map(x => x.g).sort((a, b) => a - b), med = gs.length ? gs[Math.floor(gs.length / 2)] : 0;
  out.gaps = gaps.filter(x => x.g >= Math.max(36e5, med * 20)).sort((a, b) => b.g - a.g).slice(0, 4).map(x => ({...x, cross:x.a.host !== x.b.host}));
  /* hosts that stop long before the rest */
  out.silent = out.hosts.map(h => { const R = good.filter(r => r.host === h); return {h, first:R[0].ts, last:R[R.length - 1].ts, n:R.length}; })
    .filter(x => x.n >= 4 && x.last - x.first >= 36e5 && t1 - x.last > Math.max(6 * 36e5, span * 0.25))   // was active for a while, then stopped.sort((a, b) => a.last - b.last).slice(0, 4);
  /* log clearing */
  out.cleared = ev.filter(r => TLX_CLEAR.test(r.title + '\n' + (r.body || '').slice(0, 4000)));
  /* working hours, from the suspicious events if there are enough, otherwise from all */
  const base2 = (bad.length >= 20 ? bad.map(x => x.r) : good), hrs = new Array(24).fill(0), wk = [0, 0];
  for(const r of base2){ const d = new Date(r.ts); hrs[d.getUTCHours()]++; wk[d.getUTCDay() % 6 === 0 ? 1 : 0]++; }
  if(base2.length >= 20){ let best = 0, at = 0; for(let s = 0; s < 24; s++){ let n = 0; for(let k = 0; k < 9; k++) n += hrs[(s + k) % 24]; if(n > best){ best = n; at = s; } }
    const share = best / base2.length; let off = 9 - at; if(off > 14) off -= 24; if(off < -12) off += 24;
    out.hours = {hrs, at, share, off, from:bad.length >= 20 ? 'suspicious' : 'all', n:base2.length, weekend:wk[1] / base2.length}; }
  TLX_C.sig = sig; TLX_C.v = out; return out;
}
/* a small bar chart of activity over the case, bursts in red and the first sign marked */
function tlxSpark(A){
  const H = A.hist, n = H.length, w = 720, h = 64, mx = Math.max(...H, 1), bw = w / n;
  const bars = H.map((c, i) => c ? `<rect x="${(i * bw).toFixed(1)}" y="${(h - 2 - (c / mx) * (h - 8)).toFixed(1)}" width="${Math.max(1, bw - (bw > 3 ? 1 : 0)).toFixed(1)}" height="${((c / mx) * (h - 8)).toFixed(1)}" class="${A.hot[i] ? 'hot' : ''}"/>` : '').join('');
  const fx = A.first ? ((A.first.r.ts - A.t0) / (A.span || 1)) * w : null;
  return `<svg class="tlx-spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" role="img" aria-label="Events over time: ${A.timed} events from ${esc(E.fmtFull(A.t0, tz()))} to ${esc(E.fmtFull(A.t1, tz()))}${A.bursts.length ? ', ' + A.bursts.length + ' bursts' : ''}">${bars}${fx != null ? `<line x1="${fx.toFixed(1)}" x2="${fx.toFixed(1)}" y1="0" y2="${h}" class="first"/>` : ''}</svg>
    <div class="tlx-ax t3"><span>${esc(E.fmtFull(A.t0, tz()))}</span><span>${esc(E.fmtFull(A.t1, tz()))}</span></div>`;
}
function tlxView(D){
  const A = tlxAnalyse(D), f = ts => esc(E.fmtFull(ts, tz())), g = ms => esc(E.fmtGap(ms));
  const show = (from, to, label) => `<button class="btn xs" data-act="tlxWin" data-v="${from}|${to}|${esc(label)}">${ico('list-filter','sm')}Show these events</button>`;
  const recBtn = r => `<button class="linkbtn" data-act="tlxRec" data-id="${r.id}">${esc(r.title.slice(0, 90))}</button>`;
  const card = (icon, tone, title, body) => `<section class="card tlx-c ${tone}"><div class="tlx-h"><span class="tb sm">${ico(icon,'sm')}</span><h3>${title}</h3></div><div class="tlx-b">${body}</div></section>`;
  if(A.empty) return `<div class="page wide">${empty('activity', 'Not enough timed events yet', 'Patterns need at least two events with a time. Capture or import evidence with timestamps and they appear here.')}${tlxTime(A, card, recBtn)}</div>`;
  const parts = [];
  parts.push(`<section class="card tlx-sum"><div class="tlx-kpi"><div><b>${A.timed.toLocaleString()}</b><span>timed events</span></div><div><b>${g(A.span)}</b><span>from first to last</span></div><div><b>${A.hosts.length}</b><span>host${A.hosts.length === 1 ? '' : 's'}</span></div>${A.first ? `<div class="r"><b>${g(A.first.dwell)}</b><span>between the first and last suspicious event</span></div>` : ''}</div>${tlxSpark(A)}</section>`);
  if(A.first){ const F = A.first;
    parts.push(card('flag', 'red', 'Likely first sign of compromise', `<p><b>${f(F.r.ts)}</b>${F.host ? ' on <b class="mono">' + esc(F.host) + '</b>' : ''} — ${recBtn(F.r)}</p>
      <ul class="tlx-why">${F.why.map(w => `<li>${esc(w)}</li>`).join('')}</ul>
      <p class="t2">${F.nBad} suspicious event${F.nBad === 1 ? '' : 's'} in all. ${F.before.length ? `${F.before.length} event${F.before.length === 1 ? '' : 's'} happened${F.host ? ' on the same host' : ''} in the hour before it — that is where the way in usually shows.` : 'Nothing was recorded in the hour before it' + (F.host ? ' on that host' : '') + ' — the way in may be in logs you do not have yet.'}</p>
      <div class="wrap">${F.before.length ? show(F.r.ts - 36e5, F.r.ts, 'hour before the first sign') : ''}${show(F.r.ts, F.r.ts + 36e5, 'hour after the first sign')}</div>
      <p class="t3 small">Chosen as the earliest event carrying a malicious indicator, an initial-access technique or a delivery tag. Change a verdict and this updates.</p>`)); }
  if(A.cleared.length) parts.push(card('eraser', 'red', 'Logs were cleared', `<ul class="tlx-l">${A.cleared.slice(0, 6).map(r => `<li><div><span class="mono">${r.ts ? f(r.ts) : 'no time'}</span>${r.host ? ' · <b class="mono">' + esc(r.host) + '</b>' : ''} — ${recBtn(r)}</div></li>`).join('')}</ul>
    <p class="t2">Clearing logs hides what came before. Treat the time just before each as missing evidence and look for other sources (EDR, network, backups).</p>`));
  if(A.bursts.length) parts.push(card('zap', 'amber', 'Bursts of activity', `<ul class="tlx-l">${A.bursts.map(b => `<li><div><b>${b.n} events</b> in ${g(b.to - b.from)}${b.x && b.x > 1 ? ` <span class="chip sq amber">${b.x}× the usual rate</span>` : ''}${b.bad ? ` <span class="chip sq red">${b.bad} suspicious</span>` : ''}</div>
      <div class="t2">${f(b.from)}${b.host ? ' · mostly <span class="mono">' + esc(b.host) + '</span>' + (b.hostShare < 1 ? ' (' + Math.round(b.hostShare * 100) + '%)' : '') : ''}${b.tags.length ? ' · ' + b.tags.map(esc).join(', ') : ''}</div>${show(b.from, b.to, 'burst at ' + E.fmtClock(b.from, tz()))}</li>`).join('')}</ul>
    <p class="t3 small">Busy slices of ${g(A.bin)} compared with this case's usual rate. Bursts often mean scanning, brute force, mass execution or exfiltration.</p>`));
  if(A.gaps.length) parts.push(card('pause', '', 'Quiet periods', `<ul class="tlx-l">${A.gaps.map(x => `<li><div><b>${g(x.g)}</b> with no events</div><div class="t2">${f(x.a.ts)} → ${f(x.b.ts)}${x.cross ? ' · ends on a different host (<span class="mono">' + esc(x.b.host || '—') + '</span>)' : ''}</div>${show(x.a.ts - 6e5, x.b.ts + 6e5, 'around the quiet period')}</li>`).join('')}</ul>
    <p class="t3 small">Gaps much longer than the usual spacing. Ask whether nothing happened, or whether the logs for that time are missing.</p>`));
  if(A.silent.length) parts.push(card('moon', 'amber', 'Hosts that went silent early', `<ul class="tlx-l">${A.silent.map(x => `<li><div><b class="mono">${esc(x.h)}</b> — last event ${f(x.last)}, ${g(A.t1 - x.last)} before the case's last event</div><button class="btn xs" data-act="facet" data-f="host" data-v="${esc(x.h)}">${ico('list-filter','sm')}Its events</button></li>`).join('')}</ul>
    <p class="t3 small">A host that stops reporting may have been shut down, isolated, wiped — or had its logs cleared.</p>`));
  if(A.hours){ const H = A.hours, mx = Math.max(...H.hrs, 1), o = H.off;
    parts.push(card('clock', '', 'When it happens', `<div class="tlx-hrs" role="img" aria-label="Events by hour of day, UTC">${H.hrs.map((c, i) => `<i style="--v:${(c / mx).toFixed(2)}" class="${(i - H.at + 24) % 24 < 9 ? 'on' : ''}" title="${String(i).padStart(2, '0')}:00 UTC · ${c}"></i>`).join('')}</div><div class="tlx-ax t3"><span>00 UTC</span><span>12</span><span>23</span></div>
      <p>${Math.round(H.share * 100)}% of the ${H.from === 'suspicious' ? 'suspicious ' : ''}events fall between ${String(H.at).padStart(2, '0')}:00 and ${String((H.at + 9) % 24).padStart(2, '0')}:00 UTC${H.share >= 0.6 ? ` — an office day in <b>UTC${o >= 0 ? '+' : '−'}${Math.abs(o)}</b>` : ''}. ${Math.round(H.weekend * 100)}% at weekends.</p>
      <p class="t3 small">${H.share >= 0.6 ? 'A hint about the operator\'s working hours, not proof: automation, shifts and deliberate timing all break it.' : 'Spread across the day — automated, or several people.'}</p>`)); }
  parts.push(tlxTime(A, card, recBtn));
  return `<div class="page wide tlx">${parts.join('')}</div>`;
}
function tlxTime(A, card, recBtn){
  const T = A.time, f = ts => esc(E.fmtFull(ts, tz())), items = [];
  if(T.future.length) items.push(`<li><b>${T.future.length} event${T.future.length > 1 ? 's' : ''} in the future</b> — e.g. ${recBtn(T.future[0])} at ${f(T.future[0].ts)}. A wrong clock or a mis-read date format.</li>`);
  if(T.ancient.length) items.push(`<li><b>${T.ancient.length} event${T.ancient.length > 1 ? 's' : ''} before 1995</b> — e.g. ${recBtn(T.ancient[0])}. Usually an empty time field read as 1970 or 1601.</li>`);
  const zm = T.mism.filter(x => x.zone != null), om = T.mism.filter(x => x.zone == null);
  if(zm.length){ const z = countBy(zm, x => String(x.zone))[0]; items.push(`<li><b>${zm.length} event${zm.length > 1 ? 's' : ''} sit ${Math.abs(z[0])} hour${Math.abs(z[0]) > 1 ? 's' : ''} from the time in their own text</b> — e.g. ${recBtn(zm[0].r)}. Almost always a time zone read wrongly; check the source's zone.</li>`); }
  if(om.length) items.push(`<li><b>${om.length} event${om.length > 1 ? 's' : ''} carry a different time in their text</b> — e.g. ${recBtn(om[0].r)} (${esc(E.fmtGap(om[0].d))} apart). The record may be placed by when it was collected, not when it happened.</li>`);
  if(T.unsure.length) items.push(`<li><b>${T.unsure.length} event${T.unsure.length > 1 ? 's have' : ' has'} no time zone</b> in the source, so ${A.time.unsure.length > 1 ? 'they were' : 'it was'} read as ${esc(tz())}. Mixed with zoned events, order can be wrong by hours.</li>`);
  if(T.noTs) items.push(`<li><b>${T.noTs} event${T.noTs > 1 ? 's have' : ' has'} no time</b> and ${T.noTs > 1 ? 'are' : 'is'} left out of the patterns.</li>`);
  return items.length ? card('clock-alert', 'amber', 'Time problems', `<ul class="tlx-l">${items.join('')}</ul>`) : '';
}
const TLX_ACTS = {
  tlxWin:(id, v) => { const [a, b, l] = String(v).split('|'); UI.facet.win = {from:+a, to:+b, at:+a, label:l}; UI.tlMode = 'events'; renderMain(); },
  tlxRec:id => { UI.sel = {kind:'rec', id}; UI.inspOpen = true; UI.tlMode = 'events'; renderAll(); if(typeof vlScrollTo === 'function') vlScrollTo('tlV', id); },
};
