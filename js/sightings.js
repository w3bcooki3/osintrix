/* ==========================================================================
   Seen over time — for an indicator (or a vault entry that is one): when it
   was first and last seen in your evidence, in which case each time, how the
   sightings spread over time, and every sighting across every case in date
   order. Built only from records you captured; nothing is looked up.
   ========================================================================== */
const SIGHT = {BARS:36, LIST:500};
function sightData(id){
  const g = globalEnts().get(id); if(!g) return null;
  const recs = g.recs.filter(Boolean), timed = recs.filter(r => r.ts).sort((a, b) => a.ts - b.ts);
  const byCase = new Map(); for(const r of recs){ let c = byCase.get(r.caseId); if(!c) byCase.set(r.caseId, c = {caseId:r.caseId, n:0, first:0, last:0}); c.n++; if(r.ts){ if(!c.first || r.ts < c.first) c.first = r.ts; if(r.ts > c.last) c.last = r.ts; } }
  return {recs, timed, first:timed[0] || null, last:timed[timed.length - 1] || null, untimed:recs.length - timed.length, cases:[...byCase.values()].sort((a, b) => (a.first || Infinity) - (b.first || Infinity))};
}
/* sightings in time buckets: days, weeks or months, whichever fits */
function sightBuckets(timed){
  if(timed.length < 2) return null;
  const t0 = timed[0].ts, t1 = timed[timed.length - 1].ts, span = Math.max(1, t1 - t0), day = 864e5;
  const unit = span <= 45 * day ? ['day', day] : span <= 300 * day ? ['week', 7 * day] : ['month', 30.44 * day];
  const n = Math.min(SIGHT.BARS, Math.floor(span / unit[1]) + 1), size = span / n || 1, b = new Array(n).fill(0);
  for(const r of timed) b[Math.min(n - 1, Math.floor((r.ts - t0) / size))]++;
  return {b, unit:unit[0], t0, t1};
}
function sightSection(id){
  const D = sightData(id); if(!D || !D.recs.length) return '';
  const B = sightBuckets(D.timed), max = B ? Math.max(...B.b) : 0, fmt = t => esc(E.fmtDate(t, tz()));
  const code = cid => { const c = theCase(cid); return c ? esc(caseNm(c)) : '—'; };
  const span = D.first && D.last && D.last.ts > D.first.ts ? E.fmtAgo(D.last.ts - D.first.ts).replace(/ ago$/, '') : '';
  return `<div class="isec sight"><h4>Seen over time <span class="t3">${D.recs.length} record${D.recs.length === 1 ? '' : 's'} · ${D.cases.length} case${D.cases.length === 1 ? '' : 's'}</span></h4>
    ${D.first ? `<dl class="kv sight-kv"><dt>First seen</dt><dd>${fmt(D.first.ts)} <span class="t3">in ${code(D.first.caseId)}</span></dd>${D.last !== D.first ? `<dt>Last seen</dt><dd>${fmt(D.last.ts)} <span class="t3">in ${code(D.last.caseId)}</span></dd>` : ''}${span ? `<dt>Over</dt><dd>${esc(span)}</dd>` : ''}</dl>` : '<p class="t3 sight-none">None of the records it is in has a time.</p>'}
    ${B ? `<div class="sight-bars" role="img" aria-label="${D.timed.length} sightings from ${fmt(B.t0)} to ${fmt(B.t1)}, by ${B.unit}">${B.b.map(n => `<i style="height:${n ? Math.max(8, n / max * 100) : 0}%" title="${n}"></i>`).join('')}</div><div class="sight-ax"><span>${fmt(B.t0)}</span><span>by ${B.unit}</span><span>${fmt(B.t1)}</span></div>` : ''}
    ${D.cases.length > 1 ? `<ul class="sight-cases">${D.cases.map(c => `<li><a href="${caseHash(c.caseId)}">${code(c.caseId)}</a><span>${c.n} record${c.n === 1 ? '' : 's'}</span><span class="t3">${c.first ? fmt(c.first) + (c.last > c.first ? ' – ' + fmt(c.last) : '') : 'no time'}</span></li>`).join('')}</ul>` : ''}
    ${D.untimed && D.first ? `<p class="t3 sight-none">${D.untimed} more without a time.</p>` : ''}
    ${D.recs.length > 1 ? `<button class="btn sm" data-act="sightAll" data-id="${esc(id)}">${ico('list','sm')}Every sighting, oldest first</button>` : ''}</div>`;
}
function sightDlg(id){
  const D = sightData(id); if(!D) return; const {v} = entSplit(id);
  const L = D.timed.concat(D.recs.filter(r => !r.ts)).slice(0, SIGHT.LIST);
  openDlg(dhead('Every sighting of <span class="mono">' + esc(v.length > 50 ? v.slice(0, 48) + '…' : v) + '</span>') + `<div class="in"><p class="t2" style="margin:0 0 12px">${D.recs.length.toLocaleString()} record${D.recs.length === 1 ? '' : 's'} across ${D.cases.length} case${D.cases.length === 1 ? '' : 's'}, oldest first${D.untimed ? '; those without a time last' : ''}.</p>
    <ol class="sight-list">${L.map(r => { const c = theCase(r.caseId); return `<li><button class="li" data-act="sightOpen" data-id="${r.id}"><span class="sight-t mono">${r.ts ? esc(E.fmtFull(r.ts, tz()).slice(0, 16)) : 'no time'}</span><span class="sight-c">${c ? esc(caseNm(c)) : ''}</span><b>${esc(r.title)}</b>${r.host ? `<small class="t3">${esc(r.host)}</small>` : ''}</button></li>`; }).join('')}</ol>
    ${D.recs.length > L.length ? `<p class="t3">The first ${L.length} are shown.</p>` : ''}</div><footer><button class="btn" data-act="dclose">Close</button></footer>`, true);
}
const SIGHT_ACTS = {
  sightAll:id => sightDlg(id),
  sightOpen:id => { const r = recById(id); if(!r) return; closeDlg(); DB.active = r.caseId; UI.sel = {kind:'rec', id:r.id}; UI.inspOpen = true; go(caseHash(r.caseId, 'timeline')); },   /* selected just before going, so the move keeps it */
};
