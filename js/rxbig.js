/* ==========================================================================
   Regex builder — run the finished pattern over a whole log file, however
   big: read in 4 MB pieces (nothing is uploaded, nothing kept but counts),
   with progress, a way to stop, and at the end how many lines match, each
   field's coverage and commonest values, the matches as CSV, and the lines
   it missed — which can go back into the sample to teach the pattern.
   ========================================================================== */
const RXB = {CHUNK:4 << 20, MAX_DISTINCT:50000, MAX_ROWS:200000, MAX_MISS:10000, MAX_LINE:65536};
function rxBigPick(){ const C = rxCurrent(); if(!C.ok) return toast('Build a pattern first');
  const Sf = rxSafety(C.src, [], true); if(Sf.level === 'risky' || Sf.level === 'bad') return toast('This pattern could hang on a big file — make it safer first');
  const i = document.createElement('input'); i.type = 'file'; i.accept = '.log,.txt,.csv,.json,.jsonl,.evtx.txt,text/*,*/*';
  i.onchange = () => { const f = i.files && i.files[0]; if(!f) return; if(f.size > 4 * 1024 ** 3) return toast('Up to 4 GB'); rxBigRun(f, C); }; i.click(); }
async function rxBigRun(file, C){
  const S = RX(), re = new RegExp(C.src), names = C.groups.map(g => g.name), rec = S.ml && !S.mlOff ? new RegExp(S.ml.re) : null;
  const st = {file:file.name, size:file.size, read:0, lines:0, hit:0, t0:performance.now(), stop:false, done:false, f:Object.fromEntries(names.map(n => [n, {n:0, vals:new Map(), over:false}])), rows:[], rowsCut:false, miss:[], src:C.src, names};
  UI.rxBig = st; rxBigDlg();
  /* the encoding from the first bytes: UTF-16 with a byte-order mark, else UTF-8 */
  const head = new Uint8Array(await file.slice(0, 2).arrayBuffer()), dec = new TextDecoder(head[0] === 0xFF && head[1] === 0xFE ? 'utf-16le' : head[0] === 0xFE && head[1] === 0xFF ? 'utf-16be' : 'utf-8');
  let carry = '', cur = null, lastPaint = 0;
  const one = l => { if(l.length > RXB.MAX_LINE) l = l.slice(0, RXB.MAX_LINE); st.lines++; const m = re.exec(l);
    if(!m){ if(st.miss.length < RXB.MAX_MISS) st.miss.push(l); return; }
    st.hit++; const g = m.groups || {};
    for(const n of names){ const v = g[n]; if(v == null) continue; const F = st.f[n]; F.n++; if(F.vals.has(v)) F.vals.set(v, F.vals.get(v) + 1); else if(F.vals.size < RXB.MAX_DISTINCT) F.vals.set(v, 1); else F.over = true; }
    if(st.rows.length < RXB.MAX_ROWS) st.rows.push([st.lines, ...names.map(n => g[n] ?? '')]); else st.rowsCut = true; };
  const feed = l => { if(l.endsWith('\r')) l = l.slice(0, -1); if(!l.trim()) return;
    if(!rec) return one(l);
    if(rec.test(l) || cur == null){ if(cur != null) one(cur); cur = l; } else if(cur.length < RXB.MAX_LINE) cur += '\n' + l; };
  for(let at = 0; at < file.size && !st.stop; at += RXB.CHUNK){
    const buf = await file.slice(at, at + RXB.CHUNK).arrayBuffer(), text = carry + dec.decode(buf, {stream:at + RXB.CHUNK < file.size}), parts = text.split('\n');
    carry = parts.pop(); for(const l of parts) feed(l);
    st.read = Math.min(file.size, at + RXB.CHUNK);
    if(performance.now() - lastPaint > 120){ lastPaint = performance.now(); rxBigPaint(); await new Promise(r => setTimeout(r)); } }
  if(!st.stop){ if(carry) feed(carry); if(cur != null) one(cur); st.read = file.size; }
  st.done = true; st.ms = performance.now() - st.t0; rxBigPaint();
}
function rxBigDlg(){ openDlg(dhead('Run on a whole file') + `<div class="in" id="rxBigIn"></div><footer id="rxBigFt"></footer>`, true); rxBigPaint(); }
function rxBigPaint(){ const st = UI.rxBig, el = $('rxBigIn'), ft = $('rxBigFt'); if(!st) return; if(!el){ if(!st.done) st.stop = true; return; }   /* closing the window stops the run */
  const pct = st.size ? st.read / st.size : 1, rate = st.lines / Math.max(.001, ((st.done ? st.ms : performance.now() - st.t0) / 1000)), mb = n => (n / 1048576).toFixed(n > 10485760 ? 0 : 1) + ' MB';
  const unit = RX().ml && !RX().mlOff ? 'records' : 'lines';
  el.innerHTML = `<div class="rxb-top"><b class="mono">${esc(st.file)}</b><span class="t3">${mb(st.read)} of ${mb(st.size)}${st.done ? ` · ${(st.ms / 1000).toFixed(1)} s` : ''}</span></div>
    <div class="rxb-bar" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${Math.round(pct * 100)}" aria-label="Read"><i style="width:${pct * 100}%"></i></div>
    <div class="rxb-n"><div><b>${st.lines.toLocaleString()}</b><span>${unit}</span></div><div><b>${st.hit.toLocaleString()}</b><span>match${st.lines ? ' · ' + (st.hit / st.lines * 100).toFixed(st.hit === st.lines ? 0 : 1) + '%' : ''}</span></div><div><b>${(st.lines - st.hit).toLocaleString()}</b><span>missed</span></div><div><b>${rxRate(rate)}</b><span>${unit} a second</span></div></div>
    ${st.stop ? '<p class="rx-cn warn">Stopped — the counts are for the part read so far.</p>' : ''}
    ${st.done || st.lines ? `<table class="tbl rxb-t"><thead><tr><th>Field</th><th>Present</th><th>Distinct</th><th>Commonest values</th></tr></thead><tbody>${st.names.map(n => { const F = st.f[n], top = [...F.vals.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8);
        return `<tr><td class="mono"><b>${esc(n)}</b></td><td>${st.hit ? Math.round(F.n / st.hit * 100) + '%' : '—'}</td><td>${F.vals.size.toLocaleString()}${F.over ? '+' : ''}</td><td class="rxb-top-v">${top.map(([v, c]) => `<span class="mono" title="${esc(v)}">${esc(v.length > 34 ? v.slice(0, 32) + '…' : v)} <i>${c.toLocaleString()}</i></span>`).join('')}</td></tr>`; }).join('')}</tbody></table>` : ''}
    ${st.done && st.miss.length ? `<details class="rx-box"><summary>First missed ${unit} (${Math.min(st.miss.length, 50)} of ${(st.lines - st.hit).toLocaleString()})</summary><pre class="rx-out mono" style="max-height:220px">${esc(st.miss.slice(0, 50).join('\n'))}</pre></details>` : ''}`;
  if(ft) ft.innerHTML = st.done ? `<button class="btn" data-act="dclose">Close</button>${st.miss.length ? `<button class="btn" data-act="rxBigTeach" title="Add some of the missed ${unit} to the sample, to teach the pattern">${ico('plus','sm')}Add 50 missed to the sample</button>` : ''}${st.rows.length ? `<button class="btn primary" data-act="rxBigCsv">${ico('download','sm')}Matches as CSV${st.rowsCut ? ' (first 200,000)' : ''}</button>` : ''}`
    : `<button class="btn" data-act="rxBigStop">Stop</button>`; }
const rxbCell = v => { v = String(v ?? ''); if(/^[=+\-@\t\r]/.test(v)) v = "'" + v; return /[",\n\r]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; };
const RXB_ACTS = {
  rxBig:() => rxBigPick(),
  rxBigStop:() => { if(UI.rxBig) UI.rxBig.stop = true; },
  rxBigCsv:() => { const st = UI.rxBig; if(!st) return; download(st.file.replace(/\.[^.]+$/, '') + '-matches.csv', [['line', ...st.names].map(rxbCell).join(',')].concat(st.rows.map(r => r.map(rxbCell).join(','))).join('\r\n'), 'text/csv'); },
  rxBigTeach:() => { const st = UI.rxBig, S = RX(); if(!st) return; const add = st.miss.slice(0, 50).filter(l => !S.lines.includes(l)); if(!add.length) return toast('Those are already in the sample');
    const keep = S.fmt >= 0 && S.fmts[S.fmt] ? S.fields.find(f => S.fmts[S.fmt].lines.includes(f.line)) : null;
    const rawAdd = add.flatMap(l => l.split('\n')); S.raw = S.raw.concat(rawAdd).slice(0, RX_MAX_LINES); S.text += '\n' + rawAdd.join('\n');
    S.lines = S.ml && !S.mlOff ? rxJoin(S.raw, S.ml.re) : S.raw.slice(); S.fmts = S.lines.length > 1 ? rxFormats(S.lines) : S.fmts;
    if(keep){ const k = S.fmts.findIndex(F => F.lines.includes(keep.line)); S.fmt = k; } S.manual = null; S.opt = null; S.show = 'miss'; S.left = 'lines';
    closeDlg(); rxRender(); toast(`Added ${add.length} missed ${add.length === 1 ? 'line' : 'lines'} — select their fields to teach the pattern`); }};
