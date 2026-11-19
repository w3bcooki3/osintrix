/* ==========================================================================
   Active hours (Infrastructure → Active hours) — when the people behind the
   accounts in a case are awake, from the times they post:
   · posts from Telegram and Discord chat exports, Reddit, Mastodon and X/Twitter
     data, any JSON list with a time in it, CSV, or one time per line
   · per person: a week of hours, the likely time zone from when they sleep
     (sleep is the steadiest human signal: few people post at 4 in the morning),
     whether their weekend is Saturday–Sunday or Friday–Saturday, whether their
     clock moves for daylight saving, and how sure that reading is
   · accounts that keep the same hours, side by side — one person behind two
     names, or a team working one shift
   Times are kept in UTC. Times written without a zone are read as UTC, and
   the page says so.
   ========================================================================== */
const HR_MAX = 200000;
/* the time in a post, whichever way the source writes it → ms or null */
function hrTime(v, unix){
  if(v == null || v === '') return null;
  if(typeof v === 'number' && isFinite(v)) return v > 1e14 ? Math.round(v / 1000) : v > 1e11 ? v : v * 1000;
  const s = String(v).trim(); if(/^\d{9,10}(\.\d+)?$/.test(s)) return Math.round(+s * 1000); if(/^\d{12,13}$/.test(s)) return +s;
  const t = E.parseTime(s, 'UTC'); return t != null && isFinite(t) ? t : null; }
const hrZoned = s => typeof s === 'number' || /^\d{9,13}(\.\d+)?$/.test(String(s).trim()) || E.carriesZone(String(s)) || /[+-]\d{2}:?\d{2}\)?\s*$|GMT[+-]\d/.test(String(s));
/* the shapes posts come in → {fmt, posts:[{t, who}], unzoned} */
function hrParse(text){
  const s = String(text || '').trim(); if(!s) return null; let o = null;
  if(/^[\[{]/.test(s)){ try{ o = JSON.parse(s); }catch(e){ o = null; } }
  const out = [], names = new Map(); let fmt = '', unzoned = 0;
  const add = (t, who, raw) => { if(t == null || !isFinite(t) || t < Date.UTC(2000, 0, 1) || t > Date.now() + 864e5 || out.length >= HR_MAX) return; if(raw != null && !hrZoned(raw)) unzoned++; out.push({t, who:String(who || '').trim().slice(0, 80)}); };
  if(o && typeof o === 'object'){
    if(Array.isArray(o.messages) && o.messages.some(m => m && (m.date_unixtime || m.date) && ('from' in m || 'from_id' in m || 'actor' in m))){ fmt = 'Telegram export';
      for(const m of o.messages){ if(!m || m.type === 'service') continue; add(m.date_unixtime ? +m.date_unixtime * 1000 : hrTime(m.date), m.from || m.from_id || '', m.date_unixtime ? null : m.date); } }
    else if(Array.isArray(o.messages) && o.messages.some(m => m && m.timestamp && m.author)){ fmt = 'Discord export';
      for(const m of o.messages){ if(!m || !m.author) continue; add(hrTime(m.timestamp), m.author.nickname || m.author.name || m.author.id, m.timestamp); } }
    else if(o.kind === 'Listing' && o.data && Array.isArray(o.data.children)){ fmt = 'Reddit';
      for(const c of o.data.children){ const d = c && c.data; if(d && d.created_utc) add(+d.created_utc * 1000, d.author ? 'u/' + d.author : ''); } }
    else if(Array.isArray(o.data) && o.data.some(x => x && x.created_at && (x.author_id || x.text))){ fmt = 'X / Twitter';
      const U = new Map(((o.includes || {}).users || []).map(u => [u.id, '@' + u.username]));
      for(const x of o.data) if(x) add(hrTime(x.created_at), U.get(x.author_id) || (x.author_id ? 'id ' + x.author_id : ''), x.created_at); }
    else {
      const L = Array.isArray(o) ? o : Array.isArray(o.data) ? o.data : Array.isArray(o.items) ? o.items : Array.isArray(o.posts) ? o.posts : Array.isArray(o.statuses) ? o.statuses : Array.isArray(o.results) ? o.results : null;
      if(L && L.length){
        const first = L.find(x => x && typeof x === 'object') || {};
        if(first.account && first.account.acct && first.created_at) fmt = 'Mastodon';
        else if(first.user && first.user.screen_name && first.created_at) fmt = 'X / Twitter';
        else fmt = 'JSON list';
        const TK = ['created_at', 'createdAt', 'timestamp', 'date_unixtime', 'created_utc', 'date', 'time', 'datetime', 'published', 'publishedAt', 'posted_at', 'postedAt', 'ts', 'taken_at'];
        const WK = x => x.account && (x.account.acct || x.account.username) ? '@' + (x.account.acct || x.account.username) : x.user && (x.user.screen_name || x.user.username) ? '@' + (x.user.screen_name || x.user.username) : x.author && typeof x.author === 'object' ? (x.author.name || x.author.username || x.author.id) : x.author || x.username || x.user || x.from || x.sender || x.owner || '';
        for(const x of L){ if(x == null) continue; if(typeof x !== 'object'){ add(hrTime(x), '', x); continue; }
          const k = TK.find(k => x[k] != null && x[k] !== ''); if(!k) continue; const v = x[k]; add(k === 'created_utc' || k === 'date_unixtime' ? +v * 1000 : hrTime(v), typeof WK(x) === 'object' ? '' : WK(x), k === 'created_utc' || k === 'date_unixtime' ? null : v); } } } }
  if(!out.length && !o){
    /* CSV with a time column (and maybe an author column), or one time per line */
    const lines = s.split(/\r?\n/).filter(l => l.trim()).slice(0, HR_MAX + 1), head = lines[0] || '';
    const dl = [',', '\t', ';'].find(d => head.split(d).length > 1 && /time|date|created|posted|timestamp/i.test(head));
    if(dl){ const R = csvParse(lines.join('\n'), dl), h = R[0].map(x => String(x || '').toLowerCase().trim());
      const ti = h.findIndex(x => /^(created_?at|timestamp|date_?time|datetime|time|date|posted_?at|published)$/.test(x)), wi = h.findIndex(x => /^(author|user(name)?|from|sender|account|handle|screen_name|name)$/.test(x));
      if(ti >= 0){ fmt = 'CSV'; for(const r of R.slice(1)) add(hrTime(r[ti]), wi >= 0 ? r[wi] : '', r[ti]); } }
    if(!out.length){ fmt = 'One time per line';
      for(const l of lines){ const raw = E.lineTime(l) || (l.match(/(\d{4}-\d{2}-\d{2}[T ]\d{1,2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:\s*(?:Z|UTC|GMT|[+-]\d{2}:?\d{2}))?|\d{1,2}[./]\d{1,2}[./]\d{2,4},?\s+\d{1,2}:\d{2}(?::\d{2})?(?:\s*[AP]M)?|\b1\d{9}\b)/i) || [])[1]; if(!raw) continue;
        const t = hrTime(raw); if(t == null) continue; const who = l.replace(raw, '').replace(/^[\s,;:\-\t|\[\]]+|[\s,;:\-\t|\[\]]+$/g, '').match(/^@?[\w.-]{2,40}$/) ? l.replace(raw, '').replace(/^[\s,;:\-\t|\[\]]+|[\s,;:\-\t|\[\]]+$/g, '') : '';
        add(t, who, raw); } } }
  if(!out.length) return null;
  return {fmt, posts:out, unzoned, total:out.length};
}
/* a person's week, read in their own clock → what it says */
const HR_TZ = {'-10':'Hawaii', '-9':'Alaska', '-8':'Los Angeles, Vancouver', '-7':'Denver, Phoenix', '-6':'Mexico City, Chicago in winter', '-5':'New York in winter, Bogotá, Lima', '-4':'New York in summer, Caracas, Santiago', '-3':'São Paulo, Buenos Aires', '-2':'South Georgia, Greenland', '-1':'Azores, Cape Verde', '0':'London in winter, Lisbon, Accra, Dakar', '1':'London in summer, Paris and Berlin in winter, Lagos, Algiers', '2':'Paris and Berlin in summer, Kyiv in winter, Cairo, Johannesburg', '3':'Moscow, Istanbul, Riyadh, Nairobi, Kyiv in summer', '4':'Dubai, Baku, Tbilisi, Samara', '5':'Karachi, Tashkent, Yekaterinburg', '6':'Dhaka, Almaty, Omsk', '7':'Bangkok, Jakarta, Hanoi, Novosibirsk', '8':'Beijing, Hong Kong, Singapore, Manila, Perth', '9':'Tokyo, Seoul, Pyongyang', '10':'Sydney in winter, Vladivostok, Guam', '11':'Sydney in summer, Magadan', '12':'Auckland in winter, Kamchatka', '13':'Auckland in summer, Samoa', '14':'Kiribati (Line Islands)'};
const hrWrap = h => ((h % 24) + 24) % 24;
const hrOff = o => (o >= 0 ? '+' : '−') + Math.abs(o);
function hrHours(ts){ const h = new Array(24).fill(0); for(const t of ts) h[new Date(t).getUTCHours()]++; return h; }
/* the six quietest hours in a row, and how quiet */
function hrSleep(h){ const n = h.reduce((a, b) => a + b, 0) || 1; let best = 0, bs = Infinity; for(let s = 0; s < 24; s++){ let sum = 0; for(let k = 0; k < 6; k++) sum += h[(s + k) % 24]; if(sum < bs){ bs = sum; best = s; } } return {start:best, share:bs / n}; }
/* the middle of the night, to a fraction of an hour: the run of near-silent hours around the quietest six, or those six when no hour is near-silent */
function hrMid(h){ const n = h.reduce((a, b) => a + b, 0) || 1, sl = hrSleep(h), thr = Math.max(.5, .2 * n / 24);
  let a = sl.start, b = sl.start + 5; const q = i => h[hrWrap(i)] < thr;
  if(![0, 1, 2, 3, 4, 5].some(k => q(sl.start + k))) return sl.start + 3;
  while(!q(a) && a < b) a++; while(!q(b) && b > a) b--;
  for(let k = 0; k < 12 && q(a - 1); k++) a--; for(let k = 0; k < 12 && q(b + 1); k++) b++;
  return (a + b + 1) / 2; }
/* local mid-sleep is about 03:30 for most people (01:00–07:00 or 23:30–07:30); offset = 03:30 − the UTC middle of the night */
const HR_MIDSLEEP = 3.5;
function hrOffOf(h){ let e = HR_MIDSLEEP - hrMid(h); e = ((e % 24) + 24) % 24; if(e > 12.5) e -= 24; return e; }
/* how alike two days are when one is moved by k hours */
function hrShift(a, b){ const na = Math.hypot(...a) || 1, nb = Math.hypot(...b) || 1; let best = 0, bv = -1; for(let k = -3; k <= 3; k++){ let d = 0; for(let i = 0; i < 24; i++) d += a[i] * b[hrWrap(i + k)]; d /= na * nb; if(d > bv){ bv = d; best = k; } } return {k:best, sim:bv}; }
function hrProfile(ts){
  ts = ts.filter(t => isFinite(t)).sort((a, b) => a - b); const n = ts.length; if(!n) return null;
  const h = hrHours(ts), sl = hrSleep(h);
  /* daylight saving first: if the day moves an hour between winter and summer, winter gives the standard offset */
  let dst = null; const sum = ts.filter(t => { const m = new Date(t).getUTCMonth(); return m >= 4 && m <= 8; }), win = ts.filter(t => { const m = new Date(t).getUTCMonth(); return m === 11 || m <= 1; });
  if(sum.length >= 30 && win.length >= 30){ const x = hrShift(hrHours(win), hrHours(sum)); dst = {k:x.k, sim:x.sim, sum:sum.length, win:win.length}; }
  const flat = sl.share > .16;   /* no night: shown in UTC, no time zone */
  const useWin = !flat && dst && dst.k === -1 && dst.sim > .75, est = flat ? 0 : hrOffOf(useWin ? hrHours(win) : h), off = Math.round(est), fr = est - Math.floor(est), offs = fr > .3 && fr < .7 ? [Math.floor(est), Math.ceil(est)] : [off];
  const conf = n < 20 || flat ? 'low' : n < 60 || sl.share > .08 ? 'medium' : 'high';
  /* the week in their clock */
  const grid = Array.from({length:7}, () => new Array(24).fill(0)), days = new Map();
  const offAt = t => { const m = new Date(t).getUTCMonth(); return off + (useWin && m >= 3 && m <= 9 ? 1 : 0); };   /* summer time, roughly April to October */
  for(const t of ts){ const l = new Date(t + offAt(t) * 36e5); grid[(l.getUTCDay() + 6) % 7][l.getUTCHours()]++; const dk = Math.floor((t + offAt(t) * 36e5) / 864e5); days.set(dk, (days.get(dk) || 0) + 1); }
  const dayCount = new Array(7).fill(0); for(const dk of days.keys()) dayCount[(new Date(dk * 864e5).getUTCDay() + 6) % 7]++;
  const span = n > 1 ? ts[n - 1] - ts[0] : 0, weeks = Math.max(1, span / (7 * 864e5));
  const perDay = grid.map(r => r.reduce((a, b) => a + b, 0) / weeks), wk = [0, 1, 2, 3].map(i => perDay[i]).reduce((a, b) => a + b, 0) / 4;   /* Mon–Thu: a working day everywhere */
  let weekend = null;
  if(n >= 40 && span >= 21 * 864e5 && wk > 0){ const satsun = (perDay[5] + perDay[6]) / 2, frisat = (perDay[4] + perDay[5]) / 2, sun = perDay[6], fri = perDay[4];
    if(satsun < wk * .6 && satsun <= frisat) weekend = {days:'Saturday and Sunday', how:'quieter', r:satsun / wk};
    else if(frisat < wk * .6 && frisat < satsun && sun > wk * .7) weekend = {days:'Friday and Saturday', how:'quieter', r:frisat / wk, note:'the weekend in much of the Middle East'};
    else if(satsun > wk * 1.5) weekend = {days:'Saturday and Sunday', how:'busier', r:satsun / wk}; }
  const peakH = [...h.keys()].sort((a, b) => h[b] - h[a]).slice(0, 3).map(u => hrWrap(u + off)).sort((a, b) => a - b);
  const sleepLocal = hrWrap(Math.round(hrMid(useWin ? hrHours(win) : h) - 3) + off);
  const work = [0, 1, 2, 3, 4].reduce((a, d) => a + grid[d].slice(9, 18).reduce((x, y) => x + y, 0), 0) / n;
  return {n, first:ts[0], last:ts[n - 1], span, h, grid, sleep:sl, sleepLocal, off, offs, est, winter:useWin, conf, flat, weekend, dst, peakH, work, dayCount};
}
/* how alike two people's weeks are: every hour of every weekday in UTC, smoothed by an hour either side — the same hours AND the same weekend */
function hrWeekU(ts){ const w = new Array(168).fill(0); for(const t of ts){ const d = new Date(t); w[((d.getUTCDay() + 6) % 7) * 24 + d.getUTCHours()]++; } return w; }
const hrCos = (x, y) => { let d = 0; for(let i = 0; i < x.length; i++) d += x[i] * y[i]; return d / ((Math.hypot(...x) || 1) * (Math.hypot(...y) || 1)); };
/* the shape of the day (hours, smoothed) times the shape of the week (how much on each weekday): both have to match */
function hrAlike(a, b){ const day = w => { const h = new Array(24).fill(0); w.forEach((v, i) => h[i % 24] += v); return h.map((v, i) => v * .5 + (h[hrWrap(i - 1)] + h[hrWrap(i + 1)]) * .25); }, wk = w => Array.from({length:7}, (_, d) => w.slice(d * 24, d * 24 + 24).reduce((x, y) => x + y, 0));
  /* the week by correlation, so which days are quiet matters (Sat–Sun against Fri–Sat), unless one of the two keeps an even week */
  const A = wk(a), B = wk(b), cv = v => { const m = v.reduce((x, y) => x + y, 0) / 7 || 1; return Math.sqrt(v.reduce((x, y) => x + (y - m) ** 2, 0) / 7) / m; };
  const r = v => { const m = v.reduce((x, y) => x + y, 0) / 7; return v.map(x => x - m); }, week = cv(A) < .15 || cv(B) < .15 ? hrCos(A, B) : (1 + hrCos(r(A), r(B))) / 2;
  return hrCos(day(a), day(b)) * week; }
/* every person with posts in the case: from pasted post data, and from evidence naming one account at a time */
function hrIndex(caseId){
  const sig = caseId + ':' + rev; if(HR_C.sig === sig) return HR_C.v;
  const P = new Map(), recsOf = new Map();
  const put = (who, t, rid, src) => { const k = who || '(no name)'; let p = P.get(k); if(!p){ p = {who:k, ts:[], srcs:new Set(), recs:new Set()}; P.set(k, p); } p.ts.push(t); p.srcs.add(src); p.recs.add(rid); };
  for(const r of DB.records){ if(r.caseId !== caseId || !r.hours || !Array.isArray(r.hours.t)) continue; const W = Array.isArray(r.hours.who) ? r.hours.who : [];
    for(const x of r.hours.t){ if(!Array.isArray(x) || !isFinite(x[1])) continue; put(String(W[x[0]] || ''), +x[1], r.id, r.hours.fmt || 'posts'); } }
  const people = [...P.values()].filter(p => p.ts.length >= 5).map(p => ({...p, prof:hrProfile(p.ts), wk:hrWeekU(p.ts), srcs:[...p.srcs], recs:[...p.recs]})).sort((a, b) => b.ts.length - a.ts.length).slice(0, 40);
  const pairs = []; const big = people.filter(p => p.ts.length >= 20 && !p.prof.flat);   /* a bot's all-hours spread looks like everyone */
  for(let i = 0; i < big.length; i++) for(let j = i + 1; j < big.length; j++){ const s = hrAlike(big[i].wk, big[j].wk); if(s >= .75) pairs.push({a:big[i], b:big[j], s}); }
  pairs.sort((x, y) => y.s - x.s);
  const v = {people, pairs:pairs.slice(0, 20)}; HR_C.sig = sig; HR_C.v = v; return v;
}
const HR_C = {sig:'', v:null};
const hrHH = h => String(hrWrap(h)).padStart(2, '0') + ':00';
const HR_DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
function hrGrid(p){
  const max = Math.max(1, ...p.grid.flat());
  return `<div class="hr-grid" role="img" aria-label="Posts by day and hour, ${p.flat ? 'in UTC' : `in their likely local time (UTC${hrOff(p.off)}${p.winter ? ' in winter' : ''})`}">
    <span></span>${Array.from({length:24}, (_, i) => `<span class="hr-x">${i % 3 ? '' : String(i).padStart(2, '0')}</span>`).join('')}
    ${p.grid.map((r, d) => `<span class="hr-y">${HR_DAYS[d]}</span>${r.map((v, i) => `<span class="hr-c" style="--a:${v ? (.12 + .88 * v / max).toFixed(2) : 0}" title="${HR_DAYS[d]} ${String(i).padStart(2, '0')}:00 — ${v} post${v === 1 ? '' : 's'}"></span>`).join('')}`).join('')}</div>`;
}
function hrBars(p){ const max = Math.max(1, ...p.h); const L = Array.from({length:24}, (_, i) => p.h[hrWrap(i - p.off)]);
  return `<div class="hr-bars" aria-hidden="true">${L.map((v, i) => { const sl = hrWrap(i - p.sleepLocal) < 6; return `<span class="${sl ? 'sl' : ''}" style="height:${Math.max(2, Math.round(v / max * 44))}px" title="${String(i).padStart(2, '0')}:00 — ${v}"></span>`; }).join('')}</div>`; }
function hrCard(x){
  const p = x.prof, fl = [], zs = p.offs.map(o => HR_TZ[String(o)] ? `UTC${hrOff(o)}: ${HR_TZ[String(o)]}` : '').filter(Boolean), tzTxt = 'UTC' + p.offs.map(hrOff).join(' or ') + (p.winter ? ' in winter' : '');
  if(p.flat) fl.push(['amber', 'Posts at all hours, with no night — automated, several people sharing the account, or shift work. No time zone can be read from it.']);
  if(p.weekend) fl.push(['', `${p.weekend.how === 'quieter' ? 'Quieter' : 'Busier'} on ${p.weekend.days} (${Math.round(p.weekend.r * 100)} % of a weekday)${p.weekend.note ? ' — ' + p.weekend.note : ''}`]);
  if(p.dst && p.dst.sim > .75){ if(p.dst.k === -1) fl.push(['', 'Their day moves an hour earlier in UTC in summer — they live where clocks change for summer (most of Europe and North America)']); else if(p.dst.k === 0) fl.push(['', 'Their day stays at the same UTC hours in summer and winter — no daylight saving where they are (most of Asia, Africa, South America, Russia)']); }
  if(p.work > .55 && !p.flat) fl.push(['', `${Math.round(p.work * 100)} % of posts in working hours on weekdays — posting looks like part of a job`]);
  const sure = {high:'fairly sure', medium:'a reasonable guess', low:'a weak guess'}[p.conf];
  return `<section class="card hr-p"><header class="hr-h"><div><b class="mono">${esc(x.who)}</b><div class="t3 small">${p.n.toLocaleString()} post${p.n === 1 ? '' : 's'} · ${esc(E.fmtFull(p.first, tz()).slice(0, 10))} – ${esc(E.fmtFull(p.last, tz()).slice(0, 10))} · ${esc(x.srcs.join(', '))}</div></div>
      <div class="hr-tz">${p.flat ? `<b>No night</b><span class="t3 small">posts at every hour</span>` : `<b>${esc(tzTxt)}</b><span class="t3 small">likely time zone · ${sure}</span>`}</div></header>
    ${p.flat ? `<p class="t2 small" style="margin:0 0 10px">Busiest around ${p.peakH.map(u => hrHH(u - p.off)).join(', ')} UTC.</p>` : `<p class="t2 small" style="margin:0 0 10px">${zs.length ? `Places on ${esc(zs.join('; '))}. ` : ''}${p.winter ? 'An hour later in summer. ' : ''}Asleep about ${hrHH(p.sleepLocal)}–${hrHH(p.sleepLocal + 6)} there (${Math.round(p.sleep.share * 100)} % of posts in those six hours); busiest around ${p.peakH.map(hrHH).join(', ')}.</p>`}
    ${hrBars(p)}${hrGrid(p)}
    ${fl.length ? `<ul class="hr-f">${fl.map(([c, t]) => `<li>${c ? `<span class="chip sq ${c}">Bot or shared</span> ` : ''}${esc(t)}</li>`).join('')}</ul>` : ''}</section>`;
}
function hrView(c){
  const X = hrIndex(c.id);
  const head = `<div class="if-top"><p class="t2" style="margin:0">When the people behind the accounts are awake, from the times they post — and from that, their likely time zone, weekend and whether their clock changes for summer. Paste or import posts: a Telegram or Discord chat export, Reddit, Mastodon or X data, any JSON list or CSV with times, or one time per line.</p>
    <div class="wrap" style="flex:none"><button class="btn sm" data-act="hrFile">${ico('upload','sm')}Import a file</button><button class="btn primary sm" data-act="hrPaste">${ico('plus','sm')}Paste posts</button></div></div>`;
  if(!X.people.length) return head + empty('clock-3', 'No post times in this case yet', 'Each person needs five posts or more; twenty or more for a time zone worth relying on, and a few weeks for the weekend.');
  const unz = DB.records.filter(r => r.caseId === c.id && r.hours && r.hours.unzoned).length;
  return `${head}${unz ? `<div class="note amber" style="margin-bottom:12px"><span class="ic">${ico('info','sm')}</span><div>Some times were written without a time zone and are read as UTC. If they were exported in the exporter's local time, every reading below is off by that offset.</div></div>` : ''}
    ${X.pairs.length ? `<section class="card if-c"><h3>Keep the same hours</h3><ul class="if-l0">${X.pairs.map(q => `<li class="if-g"><div class="if-gh"><span class="chip sq ${q.s >= .82 ? 'amber' : ''}">${Math.round(q.s * 100)} % alike</span> <b class="mono">${esc(q.a.who)}</b> and <b class="mono">${esc(q.b.who)}</b></div><div class="t3 small">${q.s >= .82 ? 'Weeks this alike — the same hours and the same weekend — are what one person behind two names, or a team on one shift, looks like.' : 'Similar weeks — the same region, or a similar routine.'} Likely UTC${q.a.prof.offs.map(hrOff).join(' or ')} and UTC${q.b.prof.offs.map(hrOff).join(' or ')}.</div></li>`).join('')}</ul></section>` : ''}
    ${X.people.map(hrCard).join('')}
    <p class="t3 small">The time zone comes from the six quietest hours in a row, taken as about 01:00–07:00 local. Night owls, shift workers and shared accounts move it; use it with the rest of the case.</p>`;
}
/* posts → a record that keeps only who and when (a chat export can be tens of megabytes; this keeps the times) */
function hrSave(P, name){
  const c = theCase(), who = [], at = new Map(), t = [];
  for(const p of P.posts){ let i = at.get(p.who); if(i == null){ i = who.length; who.push(p.who); at.set(p.who, i); } t.push([i, p.t]); }
  const counts = who.map((w, i) => [w || '(no name)', t.filter(x => x[0] === i).length]).sort((a, b) => b[1] - a[1]);
  const span = [Math.min(...t.map(x => x[1])), Math.max(...t.map(x => x[1]))];
  const body = `${P.fmt}${name ? ' — ' + name : ''}: ${P.posts.length.toLocaleString()} post times, ${E.fmtFull(span[0], 'UTC').slice(0, 10)} to ${E.fmtFull(span[1], 'UTC').slice(0, 10)} (UTC).\n` + counts.slice(0, 50).map(([w, n]) => `${w}: ${n}`).join('\n');
  const r = {id:uid('r'), caseId:c.id, type:'evidence', title:`Post times — ${P.fmt}${name ? ' (' + name.slice(0, 60) + ')' : ''}`, body, tsRaw:new Date().toISOString(), tsZone:'explicit', ts:Date.now(), source:'posts:' + P.fmt, host:'', tags:['post-times'], ents:extractRich(body), answer:'', addedBy:'You', addedAt:Date.now(), hash:'', hours:{fmt:P.fmt, who, t, unzoned:P.unzoned || 0}};
  DB.records.push(r); mutate('added post times'); if(typeof hashRecords === 'function') hashRecords(); renderMain();
  toast(`${P.posts.length.toLocaleString()} post times from ${P.fmt} added${counts.length > 1 ? ' — ' + counts.length + ' people' : ''}`);
}
function hrPasteDlg(){
  openDlg(dhead('Paste posts') + `<form data-form="hrPaste"><div class="in">
    <div class="field"><label for="hrText">Posts <span class="t3">— a Telegram or Discord chat export, Reddit, Mastodon or X JSON, a JSON list or CSV with times, or one time per line (a name before the time is kept)</span></label><textarea id="hrText" rows="12" class="mono" spellcheck="false"></textarea><span class="hint" id="hrHint" aria-live="polite"></span></div></div>
    <footer><button class="btn" type="button" data-act="dclose">Cancel</button><button class="btn primary" type="submit">Add to the case</button></footer></form>`, true);
}
function hrSubmit(){
  const t = String($('hrText').value || ''); if(!t.trim()) return fieldErr('hrText', 'Paste the posts first.');
  const P = hrParse(t); if(!P) return fieldErr('hrText', 'No post times found. A chat export, a JSON list or CSV with a time column, or one date and time per line.');
  closeDlg(); hrSave(P, '');
}
document.addEventListener('input', ev => { if(ev.target && ev.target.id === 'hrText'){ const h = $('hrHint'); if(!h) return; clearTimeout(UI.hrT); UI.hrT = setTimeout(() => { const P = hrParse(ev.target.value); h.textContent = P ? `Recognised: ${P.fmt}, ${P.posts.length.toLocaleString()} post times from ${new Set(P.posts.map(p => p.who)).size} ${new Set(P.posts.map(p => p.who)).size === 1 ? 'person' : 'people'}${P.unzoned ? ' — ' + P.unzoned + ' without a time zone, read as UTC' : ''}` : ev.target.value.trim() ? 'No post times found yet' : ''; }, 300); } });
const HR_ACTS = {
  hrPaste:() => hrPasteDlg(),
  hrFile:() => { const i = document.createElement('input'); i.type = 'file'; i.accept = '.json,.csv,.txt,.tsv,application/json,text/csv,text/plain';
    i.onchange = async () => { const f = i.files && i.files[0]; if(!f) return; if(f.size > 300 * 1048576) return toast('That file is over 300 MB');
      toast('Reading ' + f.name + '…'); let txt; try{ txt = await fileText(f); }catch(e){ return toast('Could not read ' + f.name); }
      const P = hrParse(txt); if(!P) return toast('No post times found in ' + f.name); hrSave(P, f.name); };
    i.click(); },
};
