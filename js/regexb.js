/* ==========================================================================
   Regex builder (sidebar → Kit → Regex builder). Paste log lines, select the
   parts you want in one line or a few, name them, and get the regular
   expression that pulls them out — checked against every line you pasted.
   Nothing leaves this browser and nothing is kept unless you save the result
   as a parser.

   How the pattern is made
   · each field: a pattern for what it is when that is clear-cut (an IP
     address, a timestamp, an email, a hash, a number…), otherwise "up to the
     next delimiter" — never a bare .* that could run past the field
   · the text between fields: kept as written where it is the same in every
     example, numbers made into \d+, words that differ between examples
     become a short list of alternatives, anything else a short lazy gap
   · before the first field: the words just before it as an anchor, or the
     whole line from its start when you ask for that
   · the result is tried on every line; the lines it misses are listed, and
     selecting the fields on one of them teaches it that variation
   · a safety check for patterns that can freeze a log tool on bad input
   · the same pattern written for JavaScript, PCRE, Python, Grok (Logstash,
     Elastic), Splunk rex and KQL (Sentinel, Defender)
   ========================================================================== */
const RX_MAX_LINES = 20000, RX_SHOW = 400;
/* what a value can be: [key, label, regex, grok, example name, strong] — strong types are used on one example; the rest only when every example agrees and a delimiter would not do */
const RX_TYPES = [
  ['iso', 'ISO 8601 time', '\\d{4}-\\d{2}-\\d{2}[T ]\\d{2}:\\d{2}:\\d{2}(?:[.,]\\d+)?(?:Z|[+-]\\d{2}:?\\d{2})?', 'TIMESTAMP_ISO8601', 'time', true],
  ['syslogts', 'Syslog time (Nov  2 08:15:30)', '[A-Z][a-z]{2} +\\d{1,2} \\d{2}:\\d{2}:\\d{2}', 'SYSLOGTIMESTAMP', 'time', true],
  ['httpdate', 'Web server time (02/Nov/2026:08:15:30 +0100)', '\\d{2}\\/[A-Z][a-z]{2}\\/\\d{4}:\\d{2}:\\d{2}:\\d{2} [+-]\\d{4}', 'HTTPDATE', 'time', true],
  ['datetime', 'Date and time in numbers', '\\d{1,4}[\\/.-]\\d{1,2}[\\/.-]\\d{1,4}[ T,]+\\d{1,2}:\\d{2}(?::\\d{2})?(?:[.,]\\d+)?(?: ?[AP]M)?', '', 'time', true],
  ['epoch', 'Unix time', '1\\d{9}(?:\\.\\d{1,6}|\\d{3})?', '', 'time', true],
  ['date', 'Date (2026-11-02)', '\\d{4}-\\d{2}-\\d{2}', '', 'date', true],
  ['clock', 'Time of day (08:15:30)', '\\d{1,2}:\\d{2}:\\d{2}(?:[.,]\\d+)?', 'TIME', 'time', true],
  ['ipv4', 'IPv4 address', '(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}', 'IPV4', 'ip', true],
  ['mac', 'MAC address', '(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}', 'MAC', 'mac', true],
  ['ipv6', 'IPv6 address', '[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:%\\w+)?', 'IPV6', 'ip', true],
  ['ip', 'IP address (v4 or v6)', '(?:(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}|[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:%\\w+)?)', 'IP', 'ip', true],
  ['email', 'Email address', '[\\w.+-]+@[\\w-]+(?:\\.[\\w-]+)+', 'EMAILADDRESS', 'email', true],
  ['url', 'URL', 'https?:\\/\\/[^\\s"\'<>]+', 'URI', 'url', true],
  ['uuid', 'GUID / UUID', '\\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\\}?', 'UUID', 'guid', true],
  ['hash', 'Hash (MD5, SHA-1, SHA-256)', '[0-9A-Fa-f]{32,128}', '', 'hash', true],
  ['sid', 'Windows SID', 'S-1-\\d+(?:-\\d+){1,14}', '', 'sid', true],
  ['hex', 'Hex number (0x…)', '0x[0-9A-Fa-f]+', 'BASE16NUM', 'code', true],
  ['float', 'Decimal number', '-?\\d+\\.\\d+', 'NUMBER', 'value', true],
  ['int', 'Whole number', '-?\\d+', 'INT', 'number', true],
  ['word', 'Word (letters, digits, _)', '\\w+', 'WORD', 'name', false],
  ['notspace', 'Anything up to a space', '\\S+', 'NOTSPACE', 'value', false],
  ['rest', 'The rest of the line', '.+', 'GREEDYDATA', 'message', false]];
/* patterns worth having for incident response, ready to copy */
const RX_LIB = [
  ['Windows event ID in text', '\\bEvent(?:ID| ID|Code)\\D{0,3}(?<event_id>\\d{1,5})\\b'],
  ['Encoded PowerShell command', '-[eE][nNcC]{0,1}[a-zA-Z]{0,13}\\s+(?<b64>[A-Za-z0-9+\\/=]{20,})'],
  ['Base64 blob (40+ characters)', '(?<b64>[A-Za-z0-9+\\/]{40,}={0,2})'],
  ['AWS access key ID', '\\b(?<aws_key>(?:AKIA|ASIA)[0-9A-Z]{16})\\b'],
  ['JSON Web Token', '\\b(?<jwt>eyJ[\\w-]+\\.eyJ[\\w-]+\\.[\\w-]+)\\b'],
  ['CVE number', '\\b(?<cve>CVE-\\d{4}-\\d{4,7})\\b'],
  ['MITRE ATT&CK technique', '\\b(?<technique>T\\d{4}(?:\\.\\d{3})?)\\b'],
  ['Windows path', '(?<path>[A-Za-z]:\\\\(?:[^\\\\\\/:*?"<>|\\r\\n]+\\\\)*[^\\\\\\/:*?"<>|\\r\\n]*)'],
  ['Domain\\user', '\\b(?<domain>[\\w.-]+)\\\\(?<user>[\\w.$-]+)'],
  ['key=value pair', '(?<key>[\\w.-]+)=(?<value>"[^"]*"|\\S+)'],
  ['Quoted string', '"(?<text>(?:[^"\\\\]|\\\\.)*)"'],
  ['HTTP request line', '"(?<method>[A-Z]{3,7}) (?<path>\\S+) HTTP\\/(?<http>[\\d.]+)"'],
  ['User agent (in quotes)', '"(?<ua>Mozilla\\/[^"]+|curl\\/[^"]+|python-requests\\/[^"]+|[^"]*(?:bot|crawl|spider)[^"]*)"'],
  ['IPv4 with port', '(?<ip>\\d{1,3}(?:\\.\\d{1,3}){3}):(?<port>\\d{1,5})\\b'],
  ['Credit card-like number (to redact)', '\\b(?:\\d[ -]?){13,19}\\b']];
const rxEsc = s => String(s).replace(/[.*+?^${}()|[\]\\\/]/g, '\\$&');
const rxType = k => RX_TYPES.find(t => t[0] === k);
const rxFull = (src, v) => { try{ return new RegExp('^(?:' + src + ')$').test(v); }catch(e){ return false; } };
/* the clear-cut kind of a set of values, or '' */
function rxGuess(vals){ for(const t of RX_TYPES){ if(!t[5]) continue; if(vals.every(v => rxFull(t[2], v))) return t[0]; } return ''; }
const rxNameFor = vals => { const k = rxGuess(vals); if(k) return rxType(k)[4]; const v = vals[0] || ''; if(/^[A-Z]{3,7}$/.test(v)) return 'method'; if(/^\d{3}$/.test(v)) return 'status'; return 'field'; };
/* text between fields → tokens: names that mix letters and digits (web01, host-7, a1b2), words, numbers, spaces, single punctuation */
const rxTok = s => s.match(/[A-Za-z_][A-Za-z0-9_-]*\d[A-Za-z0-9_-]*|[A-Za-z_]+|\d+|\s+|[^A-Za-z_\d\s]/g) || [];
const rxTokKind = t => /^[A-Za-z_].*\d/.test(t) ? 'n' : /^[A-Za-z_]/.test(t) ? 'w' : /^\d/.test(t) ? 'd' : /^\s/.test(t) ? 's' : 'p';
/* one token as a pattern: words as written, numbers \d+, names with digits in them [\w.-]+, spaces " +" */
const rxTokRe = x => { const k = rxTokKind(x); return k === 'd' ? '\\d+' : k === 'n' ? '[\\w.-]+' : k === 's' ? (x === '\n' ? '\\n' : x === '\r\n' ? '\\r?\\n' : /[\t\r\n]/.test(x) ? '\\s+' : ' +') : rxEsc(x); };
/* a lone - between spaces, or "-" in quotes, is how logs write an empty field (no user, no referrer): it stands for whatever may be there */
function rxGapOne(t){ const T = rxTok(t), out = [];
  for(let i = 0; i < T.length; i++){ const x = T[i];
    if(x === '"' && T[i + 1] === '-' && T[i + 2] === '"'){ out.push('"[^"]*"'); i += 2; continue; }
    if(x === '-' && (i === 0 || rxTokKind(T[i - 1]) === 's') && (i === T.length - 1 || rxTokKind(T[i + 1]) === 's')){ out.push('\\S+'); continue; }
    out.push(rxTokRe(x)); }
  return out.join(''); }
/* the gap's pattern, one piece per token (an empty field as one piece) */
function rxGapToks(t){ const T = rxTok(t), out = [];
  for(let i = 0; i < T.length; i++){ const x = T[i];
    if(x === '"' && T[i + 1] === '-' && T[i + 2] === '"'){ out.push('"[^"]*"', '', ''); i += 2; continue; }
    if(x === '-' && (i === 0 || rxTokKind(T[i - 1]) === 's') && (i === T.length - 1 || rxTokKind(T[i + 1]) === 's')){ out.push('\\S+'); continue; }
    out.push(rxTokRe(x)); }
  return out; }
/* one gap seen in several examples → its pattern */
function rxGap(G){
  const T = G.map(rxGapToks);
  if(T.every(t => t.join('') === T[0].join(''))) return T[0].join('');
  const raw = G.map(rxTok);
  /* the same shape: where words differ, the words they can be */
  if(T.every(t => t.length === T[0].length) && raw.every(r => r.every((x, i) => rxTokKind(x) === rxTokKind(raw[0][i]) || (/[wn]/.test(rxTokKind(x)) && /[wn]/.test(rxTokKind(raw[0][i])))))){
    return T[0].map((x, i) => { const col = T.map(t => t[i]), uniq = [...new Set(col)]; if(uniq.length === 1) return x;
      const words = raw.map(r => r[i]); if(words.every(w => /^[A-Za-z_]+$/.test(w)) && uniq.length <= 6) return '(?:' + [...new Set(words)].map(rxEsc).join('|') + ')';
      if(words.every(w => /^[\w.-]+$/.test(w))) return '[\\w.-]+'; return '[^\\s]+'; }).join(''); }
  /* different shapes: what they share at both ends, and the middles — optional, a few alternatives, or a short lazy gap */
  let a = 0; while(T.every(t => a < t.length && t[a] === T[0][a])) a++;
  let b = 0; while(T.every(t => b < t.length - a && t[t.length - 1 - b] === T[0][T[0].length - 1 - b])) b++;
  const mids = [...new Set(T.map(t => t.slice(a, t.length - b).join('')))], non = mids.filter(Boolean);
  non.sort((x, y) => y.length - x.length);   /* the longest first: tried in order, it saves backtracking */
  const one = x => /^(?:\\.|[^\\()[\]|*+?{}])$/.test(x);
  const mid = non.length && non.length <= 4 ? (non.length === 1 ? (one(non[0]) && mids.includes('') ? non[0] : '(?:' + non[0] + ')') : '(?:' + non.join('|') + ')') + (mids.includes('') ? '?' : '') : '.*?';
  return T[0].slice(0, a).join('') + mid + T[0].slice(T[0].length - b).join('');
}
/* the anchor before the first field: a run of up to three words that every example has close before it,
   then what lies between that run and the field — nothing, a part some examples have ((?:invalid user )?), or a short lazy gap */
function rxLead(P){
  const T0 = rxTok(P[0]), cands = [];
  for(let end = T0.length; end > 0 && T0.length - end < 12; end--) for(let st = end - 1; st >= 0 && end - st <= 6; st--){
    const run = T0.slice(st, end), words = run.filter(t => rxTokKind(t) === 'w').length; if(!words || words > 3 || rxTokKind(run[0]) === 's') continue;
    const str = run.join(''); if(P.every(p => p.includes(str))) cands.push({str, dist:T0.length - end, len:str.length}); }
  if(!cands.length) return null;
  cands.sort((a, b) => a.dist - b.dist || b.len - a.len); const A = cands[0].str;
  const tails = P.map(p => p.slice(p.lastIndexOf(A) + A.length)), uniq = [...new Set(tails)];
  let tail = ''; if(uniq.length === 1) tail = rxGapOne(uniq[0]);
  else { const non = uniq.filter(Boolean); tail = non.length && non.length <= 4 ? '(?:' + non.map(rxGapOne).join('|') + ')' + (uniq.includes('') ? '?' : '') : '.*?'; }
  return rxGapOne(A) + tail;
}
/* the examples: lines with fields → {ok, why, src, groups:[{name, type, src, vals, opt}]}
   A field missing from some examples is optional: it is written with the words just before it, (?: port (?<port>\d+))?,
   in the place the examples have it. Fields must keep one order. */
function rxBuild(S){
  const lines = S.lines, byLine = new Map();
  for(const f of S.fields){ if(!byLine.has(f.line)) byLine.set(f.line, []); byLine.get(f.line).push(f); }
  if(!byLine.size) return {ok:false, why:'Select a part of a line to start.'};
  const ex = [...byLine.entries()].map(([i, F]) => ({i, line:lines[i] || '', F:F.slice().sort((a, b) => a.s - b.s)}));
  for(const e of ex) for(let k = 1; k < e.F.length; k++) if(e.F[k].s < e.F[k - 1].e) return {ok:false, why:`On line ${e.i + 1}, ${e.F[k - 1].name} and ${e.F[k].name} overlap.`};
  /* one order for every field: the example with most fields first, the others' extra fields placed after the field they follow */
  const order = [];
  for(const e of ex.slice().sort((a, b) => b.F.length - a.F.length)){ const o = e.F.map(f => f.name), at = o.map(n => order.indexOf(n)).filter(x => x >= 0);
    if(at.some((x, k) => k && x < at[k - 1])){ const a = o.find((n, k) => k && order.indexOf(n) >= 0 && order.indexOf(n) < Math.max(...o.slice(0, k).map(x => order.indexOf(x)))), first = ex.find(x => x !== e && x.F.some(f => f.name === a));
      return {ok:false, why:`Line ${e.i + 1} has its fields in a different order than line ${(first || ex[0]).i + 1}${a ? ' (' + a + ')' : ''}. Select the fields in the same order in every example.`}; }
    let p = -1; for(const n of o){ const q = order.indexOf(n); if(q >= 0) p = q; else { order.splice(p + 1, 0, n); p++; } } }
  const has = (e, n) => e.F.find(f => f.name === n), req = order.filter(n => ex.every(e => has(e, n)));
  if(!req.length) return {ok:false, why:'No field is on every example line. Select at least one field on each example.'};
  const opt = order.filter(n => !req.includes(n));
  /* an optional field's lead: the text every example has just before it, from a word boundary (" port ", " user=") */
  const lead = {};
  for(const n of opt){ const G = ex.filter(e => has(e, n)).map(e => { const k = e.F.findIndex(f => f.name === n); return e.line.slice(k ? e.F[k - 1].e : 0, e.F[k].s); });
    let L = G[0]; for(const g of G) while(L && !g.endsWith(L)) L = L.slice(1);
    while(L && /\w/.test(L[0]) && G.some(g => /\w/.test(g[g.length - L.length - 1] || ''))) L = L.slice(1);
    lead[n] = L; }
  /* each example with its optional fields taken out: the required fields' places, and where each optional one sat */
  const red = ex.map(e => { let t = '', from = 0; const R = {}, O = {};
    for(const f of e.F){ if(opt.includes(f.name)){ const s0 = f.s - lead[f.name].length; t += e.line.slice(from, s0); O[f.name] = t.length; from = f.e; }
      else { t += e.line.slice(from, f.s); R[f.name] = [t.length, t.length + f.e - f.s]; t += e.line.slice(f.s, f.e); from = f.e; } }
    t += e.line.slice(from); return {e, t, R, O}; });
  const nR = req.length, gapR = (r, k) => k === 0 ? r.t.slice(0, r.R[req[0]][0]) : k === nR ? r.t.slice(r.R[req[nR - 1]][1]) : r.t.slice(r.R[req[k - 1]][1], r.R[req[k]][0]), gapAt = (r, k) => k === 0 ? 0 : r.R[req[k - 1]][1];
  /* which gap each optional field is in (between the same two required fields in every example) */
  const optIn = {};
  for(const n of opt){ const ks = new Set(red.filter(r => r.O[n] != null).map(r => { const p = r.O[n]; let k = 0; while(k < nR && r.R[req[k]][0] < p) k++; return k; }));
    if(ks.size > 1) return {ok:false, why:`${n} is in a different place on different example lines. Select it in the same place.`}; optIn[n] = [...ks][0]; }
  /* the value patterns */
  const groups = [], vals = n => ex.filter(e => has(e, n)).map(e => { const f = has(e, n); return e.line.slice(f.s, f.e); });
  for(const n of order){ const V = vals(n), want = (S.types || {})[n] || 'auto', E = ex.filter(e => has(e, n)), nexts = E.map(e => e.line.slice(has(e, n).e)), nx = [...new Set(nexts.map(x => x[0] || ''))], nextCh = nx.length === 1 ? nx[0] : '', prevCh = (() => { const e = E[0], f = has(e, n); return e.line[f.s - 1] || ''; })();
    let type = want, src;
    if(want === 'custom' && S.custom && S.custom[n]) src = S.custom[n];
    else if(want !== 'auto' && want !== 'delim' && rxType(want)) src = rxType(want)[2];
    else { const g = want === 'auto' ? rxGuess(V) : ''; if(g){ type = g; src = rxType(g)[2]; }
      else { type = 'delim'; const last = n === order[order.length - 1];
        if(V.some(v => v.includes('\n'))) src = last && nexts.every(g => !g.trim()) ? '[\\s\\S]+' : '[\\s\\S]+?';
        else if(nexts.every(x => x[0] === '\n') || last && nexts.every(x => !x.trim()) && V.every(v => /\S/.test(v))) src = V.every(v => !/\s/.test(v)) ? '\\S+' : '.+';
        else if(prevCh === '"' && nextCh === '"') src = V.some(v => /\\"/.test(v)) ? '(?:[^"\\\\]|\\\\.)*' : '[^"]*';
        else if(nextCh && !/\s/.test(nextCh) && V.every(v => !v.includes(nextCh))) src = '[^' + rxEsc(nextCh).replace(/^\\\//, '/') + '\\r\\n]+';
        else if(V.every(v => !/\s/.test(v))) src = '\\S+';
        else if(last && nexts.every(g => !g.trim())) src = '.+';
        else src = '.+?'; } }
    groups.push({name:n, type, src, vals:V, opt:opt.includes(n)}); }
  const G = n => groups.find(g => g.name === n);
  /* a gap with optional fields in it: cut at each one (where an example lacks one, at the place that matches the others), a pattern per piece */
  const gapPat = (k, first) => { const O = opt.filter(n => optIn[n] === k), texts = red.map(r => gapR(r, k));
    if(!O.length) return {pieces:[texts], O};
    const cuts = red.map((r, ri) => { let prev = 0; return O.map(n => { let c;
      if(r.O[n] != null) c = r.O[n] - gapAt(r, k);
      else { const known = red.filter(x => x.O[n] != null), P = new Set(known.map(x => gapR(x, k).slice(0, x.O[n] - gapAt(x, k)))), Sf = new Set(known.map(x => gapR(x, k).slice(x.O[n] - gapAt(x, k)))), t = texts[ri];
        c = -1; for(let j = t.length; j >= 0; j--) if(P.has(t.slice(0, j))){ c = j; break; }
        if(c < 0) for(let j = 0; j <= t.length; j++) if(Sf.has(t.slice(j))){ c = j; break; }
        if(c < 0) c = P.has('') ? 0 : t.length; }
      c = Math.max(prev, Math.min(c, texts[ri].length)); prev = c; return c; }); });
    const pieces = []; for(let q = 0; q <= O.length; q++) pieces.push(texts.map((t, ri) => t.slice(q ? cuts[ri][q - 1] : 0, q < O.length ? cuts[ri][q] : t.length)));
    return {pieces, O}; };
  const optPat = n => '(?:' + rxGapOne(lead[n]) + '(?<' + n + '>' + G(n).src + '))?';
  /* a lazy field with only optional fields after it stops where one of them starts, or at the end */
  const lastReq = req[nR - 1], tailOpt = opt.filter(n => optIn[n] === nR);
  for(const n of [lastReq, ...tailOpt]){ const g = G(n); if(g.src !== '.+?') continue; const after = tailOpt.filter(m => order.indexOf(m) > order.indexOf(n));
    if(after.length && after.every(m => /^\n/.test(lead[m]))) g.src = '.+';
    else if(after.length && after.every(m => lead[m])) g.src = '.+?(?=' + after.map(m => rxGapOne(lead[m])).join('|') + '|$)'; }
  /* assemble */
  let out = '';
  { const {pieces, O} = gapPat(0); const p0 = pieces[0];
    if(S.fromStart) out = '^' + rxGap(p0);
    else { const ld = rxLead(p0); out = ld != null ? ld : (!O.length && rxType(G(req[0]).type) && rxType(G(req[0]).type)[5] ? '' : p0.every(x => !x) && O.length ? '' : '^' + rxGap(p0));
      if(ld == null && !out && !O.length && /^\w/.test(ex[0].line.slice(has(ex[0], req[0]).s))) out = '\\b'; }
    O.forEach((n, q) => { out += optPat(n) + rxGap(pieces[q + 1]); }); }
  for(let k = 0; k < nR; k++){ out += '(?<' + req[k] + '>' + G(req[k]).src + ')';
    if(k < nR - 1){ const {pieces, O} = gapPat(k + 1); out += rxGap(pieces[0]); O.forEach((n, q) => { out += optPat(n) + rxGap(pieces[q + 1]); }); } }
  { const {pieces, O} = gapPat(nR); if(O.length){ out += rxGap(pieces[0]); O.forEach((n, q) => { out += optPat(n) + (q < O.length - 1 ? rxGap(pieces[q + 1]) : ''); }); } }
  /* a lazy last field needs something after it to stop at: the first word that follows in every example */
  const g = G(order[order.length - 1]); if(!g.opt && g.src === '.+?'){ const tail = ex.map(e => e.line.slice(has(e, g.name).e)), t = rxTok(tail[0]), stop = []; for(const x of t){ stop.push(x); if(rxTokKind(x) === 'w') break; }
    const st = stop.join(''); if(st && tail.every(s => s.startsWith(st))) out += rxGapOne(st); else { g.src = '.+'; out = out.replace(/\.\+\?\)$/, '.+)'); } }
  /* shared starts of alternatives taken out (Failed password for(?: invalid user)?), when every line gives the same values */
  if(typeof RX_OPT !== 'undefined'){ const fx = RX_OPT.find(o => o.k === 'factor').f(out); if(fx && rxSame(out, fx, lines.slice(0, 2000))) out = fx; }
  return {ok:true, src:out, groups, examples:ex.map(e => e.i), optional:opt};
}
/* how risky a pattern is on hostile input: what to watch, from its shape and from timed runs */
function rxSafety(src, lines, quick){
  const notes = []; let level = 'safe';
  const body = src.replace(/\\./g, 'x').replace(/\[[^\]]*\]/g, 'c');
  if(/\([^()]*[+*][^()]*\)[+*{]/.test(body)){ level = 'risky'; notes.push('A repeated group holds a repeat of its own — on a line that almost matches this can take seconds or hang (catastrophic backtracking). Make the inner part exclusive, e.g. [^,]+ instead of .+'); }
  if(/(\.[*+])[^()]{0,4}\1/.test(body) || (body.match(/\.\*|\.\+/g) || []).length >= 3){ if(level === 'safe') level = 'watch'; notes.push('Several wildcards (.* or .+) in a row make the engine try many ways to split a line that does not match. A delimiter class ([^ ]+, [^"]*) is faster and stricter.'); }
  if(!/^\^|^\\b|^[A-Za-z]/.test(src) && /^\(\?<\w+>\.\+/.test(src)){ if(level === 'safe') level = 'watch'; notes.push('The pattern starts with a wildcard and no anchor, so it is tried from every position of every line.'); }
  let re; try{ re = new RegExp(src); }catch(e){ return {level:'bad', notes:['Not a valid expression: ' + e.message], ms:0}; }
  /* a pattern already known to be risky is not run on hostile input here: it would freeze this page the same way */
  if(level === 'risky' || quick) return {level, notes, ms:0};
  /* timed: the sample, each line with its end broken, and long runs of the characters the pattern uses */
  const tries = lines.slice(0, 300).flatMap(l => [l, l.slice(0, -1) + '\u0001', l + ' ' + l.slice(0, 200)]), long = ['a'.repeat(3000), ' '.repeat(3000), '1.'.repeat(1500), ('a ' + '"').repeat(1000), (lines[0] || 'x').repeat(Math.ceil(3000 / Math.max(1, (lines[0] || 'x').length))).slice(0, 3000)];
  let worst = 0; const t0 = performance.now();
  for(const s of tries.concat(long)){ const a = performance.now(); re.test(s); const d = performance.now() - a; if(d > worst) worst = d; if(performance.now() - t0 > 1500) break; }
  if(worst > 50){ level = 'risky'; notes.push(`One test line took ${Math.round(worst)} ms — on real logs this pattern can stall.`); }
  else if(worst > 8 && level === 'safe'){ level = 'watch'; notes.push(`The slowest test line took ${worst.toFixed(1)} ms.`); }
  return {level, notes, ms:worst};
}
/* the same pattern for each tool */
function rxExport(src, groups, kind){
  const names = [...src.matchAll(/\(\?<(\w+)>/g)].map(m => m[1]);
  if(kind === 'js') return '/' + src.replace(/(^|[^\\])\//g, '$1\\/') + '/';
  if(kind === 'pcre') return src;
  if(kind === 'python'){ const p = src.replace(/\(\?<(\w+)>/g, '(?P<$1>'); return `import re\n\npattern = re.compile(r${p.includes("'") ? '"' + p + '"' : "'" + p + "'"})\nm = pattern.search(line)\nif m:\n    fields = m.groupdict()  # ${names.join(', ')}`; }
  if(kind === 'grok'){ let g = src; for(const G of groups || []){ const t = rxType(G.type); if(t && t[3] && G.src === t[2]) g = g.replace('(?<' + G.name + '>' + G.src + ')', '%{' + t[3] + ':' + G.name + '}'); } return g; }
  if(kind === 'splunk') return `| rex field=_raw "${src.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"\n| table ${names.join(' ')}`;
  if(kind === 'kql'){ const plain = src.replace(/\(\?<\w+>/g, '('), v = '@"' + plain.replace(/"/g, '""') + '"';
    return `// RawData: the column holding the raw line (Syslog: SyslogMessage, CommonSecurityLog: AdditionalExtensions, custom tables: RawData)\n| extend ${names.map((n, i) => `${n} = extract(${v}, ${i + 1}, RawData)`).join(',\n         ')}\n| where isnotempty(${names[0] || 'RawData'})`; }
  return src;
}
const RX_EXPORTS = [['js', 'JavaScript'], ['pcre', 'PCRE'], ['python', 'Python'], ['grok', 'Grok'], ['splunk', 'Splunk'], ['kql', 'KQL']];
/* ---------- the page ---------- */
const RX = () => UI.rx || (UI.rx = {text:'', raw:[], lines:[], fields:[], types:{}, custom:{}, fromStart:false, manual:null, exp:'js', expAll:false, show:'all', pend:null, ml:null, mlOff:false, fmts:[], fmt:-1, opt:null});
function rxSetText(t){ const S = RX(); S.text = String(t || ''); S.raw = S.text.replace(/\r\n?/g, '\n').split('\n').filter(l => l.trim()).slice(0, RX_MAX_LINES);
  S.ml = typeof rxRecordStart === 'function' ? rxRecordStart(S.raw.slice(0, 5000)) : null; S.mlOff = false; rxApplyMl(); }
/* records joined or not: the lines, the formats, and a fresh start for the fields */
function rxApplyMl(){ const S = RX(); S.lines = S.ml && !S.mlOff ? rxJoin(S.raw, S.ml.re) : S.raw.slice();
  S.fields = []; S.types = {}; S.custom = {}; S.manual = null; S.pend = null; S.opt = null; S.fmt = -1; S.show = 'all';
  S.fmts = typeof rxFormats === 'function' && S.lines.length > 1 ? rxFormats(S.lines) : [{tpl:[], lines:S.lines.map((_, i) => i), name:'format', kind:'', label:''}]; }
/* the lines in view: one format, or all of them */
function rxView(){ const S = RX(), F = S.fmt >= 0 && S.fmts[S.fmt]; if(!F) return {idx:S.lines.map((_, i) => i), fields:S.fields, all:true};
  const set = new Set(F.lines); return {idx:F.lines, fields:S.fields.filter(f => set.has(f.line)), F}; }
function rxBuiltFor(fields){ const S = RX(); return rxBuild({lines:S.lines, fields, types:S.types, custom:S.custom, fromStart:S.fromStart}); }
function rxCurrent(){ const S = RX(), V = rxView();
  if(S.manual != null) return {ok:!!S.manual, manual:true, src:S.manual, groups:[...S.manual.matchAll(/\(\?<(\w+)>/g)].map(m => ({name:m[1], type:'custom', src:''}))};
  const C = rxBuiltFor(V.fields); if(C.ok && S.opt && S.opt.on && S.opt.from === C.src) return {...C, built:C.src, src:S.opt.src, optimised:true};
  return C; }
/* run on the lines in view: matches by line number */
function rxRun(src, lines, idx){ let re; try{ re = new RegExp(src, 'd'); }catch(e){ return {err:e.message}; } const M = []; let n = 0;
  for(const i of idx || lines.map((_, k) => k)){ const m = re.exec(lines[i]); if(m){ M[i] = {g:m.groups || {}, ix:m.indices && m.indices.groups || {}}; n++; } }
  return {M, n}; }
const rxRate = r => r >= 1e6 ? (r / 1e6).toFixed(r >= 1e7 ? 0 : 1) + ' M' : r >= 1e3 ? Math.round(r / 1e3) + ' k' : String(Math.round(r));
/* what one rewrite changed, with a little of what is around it */
function rxDiff(a, b){ let p = 0; while(p < a.length && p < b.length && a[p] === b[p]) p++; let s = 0; while(s < a.length - p && s < b.length - p && a[a.length - 1 - s] === b[b.length - 1 - s]) s++;
  const c = 18, pre = a.slice(Math.max(0, p - c), p), post = a.slice(a.length - s, a.length - s + c);
  return `${p > c ? '…' : ''}${esc(pre)}<del>${esc(a.slice(p, a.length - s))}</del><ins>${esc(b.slice(p, b.length - s))}</ins>${esc(post)}${s > c ? '…' : ''}`; }
/* every format that has a pattern: [{name, src, groups, n, of}] */
function rxAllPatterns(){ const S = RX(); return S.fmts.map((F, fi) => { const set = new Set(F.lines), C = rxBuiltFor(S.fields.filter(f => set.has(f.line))); if(!C.ok) return null;
  const src = S.fmt === fi && S.opt && S.opt.on && S.opt.from === C.src ? S.opt.src : C.src; return {name:F.name, src, groups:C.groups, fi}; }).filter(Boolean)
  /* the first that matches wins, so the most specific go first: those with the most fixed words (a catch-all "message" pattern last) */
  .sort((a, b) => rxFixed(b.src) - rxFixed(a.src)); }
const rxFixed = src => src.replace(/\(\?<\w+>/g, '(').replace(/\[(?:\\.|[^\]])*\]/g, '').replace(/\\./g, '').replace(/[^A-Za-z]/g, '').length;
const RX_TABS = [['match', 'Match'], ['explain', 'Explain'], ['fields', 'Fields'], ['tests', 'Tests'], ['speed', 'Speed'], ['export', 'Export']];
/* ---------- reading a pattern ---------- */
/* the top-level pieces of a pattern: a group with all that is in it, or one atom */
function rxPieces(src){ const A = rxAtoms(src), out = []; let d = 0, cur = '';
  for(const a of A){ if(a.open){ d++; cur += a.t; continue; } cur += a.t; if(a.t[0] === ')' && !/^\\/.test(a.t)) d = Math.max(0, d - 1); if(!d){ out.push(cur); cur = ''; } }
  if(cur) out.push(cur); return out; }
/* coloured pattern: named groups carry their field's colour and a label (drawn by CSS, so the text stays the pattern itself) */
function rxHl(src, col){ let out = '', i = 0; const st = [];
  while(i < src.length){ const r = src.slice(i); let m;
    if((m = /^\(\?<(\w+)>/.exec(r))){ st.push(1); out += `<span class="rx-gb c${col(m[1])}" data-f="${esc(m[1])}"><span class="rx-gl" data-n="${esc(m[1])}">${esc(m[0])}</span>`; i += m[0].length;
      /* a long standard pattern (an IP address, a timestamp) shows as its name; the text is still there to copy, and Expand shows it */
      const T = !RX().fullPat && RX_TYPES.find(t => t[2].length >= 14 && src.startsWith(t[2] + ')', i)); if(T){ out += `<span class="rx-ty" data-t="${esc(T[1].replace(/ \(.*\)$/, ''))}" title="${esc(T[2])}">${esc(T[2])}</span>`; i += T[2].length; }
      continue; }
    if((m = /^\(\?[:=!]|^\(\?<[=!]|^\(/.exec(r))){ st.push(0); out += `<span class="rx-sp">${esc(m[0])}</span>`; i += m[0].length; continue; }
    if(r[0] === ')'){ const g = st.pop(); out += g ? '<span class="rx-sp rx-gc">)</span></span>' : '<span class="rx-sp">)</span>'; i++; continue; }
    if((m = /^\[(?:\\.|[^\]])*\]/.exec(r))){ out += `<span class="rx-sc">${esc(m[0])}</span>`; i += m[0].length; continue; }
    if((m = /^\\[dDsSwWbBnrt]/.exec(r))){ out += `<span class="rx-sc">${m[0]}</span>`; i += 2; continue; }
    if((m = /^(?:[+*?]|\{\d+(?:,\d*)?\})[?+]?/.exec(r))){ out += `<span class="rx-sq">${esc(m[0])}</span>`; i += m[0].length; continue; }
    if(r[0] === '|'){ out += '<span class="rx-sp">|</span>'; i++; continue; }
    if(r.startsWith(' +')){ out += '<span class="rx-ws" title="one or more spaces"> +</span>'; i += 2; continue; }
    if(r[0] === '.'){ out += '<span class="rx-sc">.</span>'; i++; continue; }
    if(r[0] === '^' || r[0] === '$'){ out += `<span class="rx-sa">${r[0]}</span>`; i++; continue; }
    if((m = /^\\./.exec(r))){ out += esc(m[0]); i += 2; continue; }
    out += esc(r[0]); i++; }
  while(st.length) out += st.pop() ? '</span>' : '';
  return out; }
/* plain words for a piece of pattern */
const rxLit = p => { const A = rxAtoms(p); if(!A.length || A.some(a => a.open || a.t[0] === ')' || a.t[0] === '|')) return null; let s = '';
  for(const a of A){ if(/^ [+*]?$/.test(a.t)) s += ' '; else if(/^\\[^\w\s]$/.test(a.t)) s += a.t[1]; else if(/^[^\\\[.()|*+?{}^$]$/.test(a.t)) s += a.t; else return null; } return s; };
function rxSay(p){ const t = p.replace(/[*+?]\??$|\{\d+(?:,\d*)?\}\??$/, ''), q = p.slice(t.length), many = /^[+*]|^\{/.test(q), opt = /^[?*]/.test(q);
  const base = t === '\\b' ? 'a word boundary' : t === '^' ? 'start of the line' : t === '$' ? 'end of the line' : t === '\\S' ? (many ? 'text up to a space' : 'one non-space character') : t === '\\d' ? (many ? 'a number' : 'one digit') : t === ' ' ? (many ? 'one or more spaces' : 'a space') : t === '\\s' ? (many ? 'whitespace' : 'one whitespace character') : t === '\\w' ? (many ? 'a word' : 'one word character') : t === '.' ? (q === '+' || q === '*' ? 'the rest of the line' : many ? 'as little text as needed' : 'any character') : t === '\\n' ? 'a line break'
    : /^\[\^(.+?)(?:\\r\\n)?\]$/.test(t) ? `text up to “${t.slice(2, -1).replace(/\\r\\n|\\n|\\r/g, '').replace(/\\(.)/g, '$1')}”` : /^\[/.test(t) ? `one of ${t}` : null;
  return base ? base + (opt && !/rest|little/.test(base) ? ' (optional)' : '') : null; }
function rxExplainRows(src, groups){ const P = rxPieces(src), rows = []; let lit = '';
  const flush = () => { if(lit){ rows.push({k:'lit', html:lit.trim() ? `the text <code class="mono rx-xl">${esc(lit)}</code>` : 'spaces'}); lit = ''; } };
  for(const p of P){ const L = rxLit(p); if(L != null){ lit += L; continue; } flush();
    const g = /^\(\?<(\w+)>/.exec(p), G = g && (groups || []).find(x => x.name === g[1]);
    if(g){ const ty = G ? (G.type === 'delim' ? rxSay(G.src) || 'up to the next delimiter' : (rxType(G.type) || [, rxSay(G.src) || 'custom'])[1]) : rxSay(p.slice(g[0].length, -1)) || 'custom'; rows.push({k:'field', f:g[1], src:p, html:`field <b class="mono">${esc(g[1])}</b> — ${esc(ty)}`}); continue; }
    const og = /^\(\?:([\s\S]*)\)\?$/.exec(p);
    if(og){ const inner = og[1], f = /\(\?<(\w+)>/.exec(inner), il = rxLit(inner);
      rows.push({k:'opt', f:f && f[1], src:p, html:f ? `optional: ${(x => x ? `<code class="mono rx-xl">${esc(x)}</code> then ` : '')(rxLit(inner.slice(0, inner.indexOf('(?<'))))}field <b class="mono">${esc(f[1])}</b>` : il != null ? `optional text <code class="mono rx-xl">${esc(il)}</code>` : `optional: <code class="mono">${esc(inner)}</code>`}); continue; }
    if(/^\(\?:[\s\S]*\)$/.test(p)){ const alts = rxSplitTop(p.slice(3, -1)); if(alts.length > 1){ rows.push({k:'alt', src:p, html:'one of ' + alts.map(x => `<code class="mono rx-xl">${esc(rxLoose(x))}</code>`).join(' ')}); continue; } }
    const s = rxSay(p); rows.push({k:'tok', src:p, html:s ? esc(s) : `<code class="mono">${esc(p)}</code>`}); }
  flush(); return rows; }
/* alternatives at the top level of a group body */
function rxSplitTop(b){ const out = []; let d = 0, cur = '', cls = false; for(let i = 0; i < b.length; i++){ const c = b[i]; if(c === '\\'){ cur += c + (b[i + 1] || ''); i++; continue; }
    if(cls){ if(c === ']') cls = false; cur += c; continue; } if(c === '['){ cls = true; cur += c; continue; } if(c === '(') d++; else if(c === ')') d--; if(c === '|' && !d){ out.push(cur); cur = ''; continue; } cur += c; }
  out.push(cur); return out; }
/* a piece of fixed text with optional words, as plain text: Failed password for [invalid user] */
const rxLoose = x => x.replace(/\(\?:([^()]*)\)\?/g, (m, a) => { const L = rxLit(a) ?? a; return (/^\s/.test(L) ? ' ' : '') + '[' + L.trim() + ']'; }).replace(/ \+/g, ' ').replace(/\\([^\w\s])/g, '$1');
/* where a missed line stops matching: the longest start of the pattern that still matches, and the piece after it */
function rxWhy(src, line){ const P = rxPieces(src); let best = null;
  for(let k = P.length - 1; k >= 1; k--){ let re; try{ re = new RegExp(P.slice(0, k).join('')); }catch(e){ continue; } const m = re.exec(line); if(m){ let nx = P[k], j = k + 1; if(rxLit(nx) != null) while(j < P.length && rxLit(P[j]) != null && j - k < 12) nx += P[j++]; best = {at:m.index + m[0].length, from:m.index, next:nx, k}; break; } }
  return best || {at:0, from:0, next:P[0] || '', k:0}; }
/* ---------- tests pinned to a pattern ---------- */
/* each: {text, want:'match'|'none', expect:{field:value}|null, fmt} — run on every change, so a fix cannot quietly break an older line */
function rxTestRun(src, T){ let re; try{ re = new RegExp(src); }catch(e){ return T.map(() => ({ok:false, why:'the pattern is not valid'})); }
  return T.map(t => { const m = re.exec(t.text);
    if(t.want === 'none') return m ? {ok:false, why:'it matches, and must not'} : {ok:true};
    if(!m) return {ok:false, why:'it does not match any more'};
    if(t.expect){ const g = m.groups || {}, bad = Object.keys(t.expect).filter(k => (g[k] ?? null) !== t.expect[k]); if(bad.length) return {ok:false, why:bad.slice(0, 2).map(k => `${k} is ${g[k] == null ? 'empty' : '“' + g[k] + '”'}, was “${t.expect[k] ?? ''}”`).join('; ')}; }
    return {ok:true}; }); }
/* ---------- what each tool can run ---------- */
/* KQL runs RE2 (no lookaround, no back-references); Python needs (?P<name>) and fixed-width lookbehind; the rest take this pattern as it is */
const RX_FLAVOR = {js:'JavaScript', pcre:'PCRE', python:'Python re', grok:'Oniguruma (Logstash, Elastic)', splunk:'PCRE (Splunk)', kql:'RE2 (KQL, Sentinel, Defender)'};
function rxCompat(src, kind, lines){
  const look = /\(\?[=!]|\(\?<[=!]/.test(src), back = /\\[1-9]|\\k</.test(src), atomic = /\(\?>|[*+?}]\+/.test(src);
  if(kind === 'kql' && (look || back)){
    /* a fixed word checked first, or a lookahead that only says where a lazy field stops: taken out, and kept only if every line still gives the same values */
    let fix = src.replace(/^\^\(\?=\[\^\\n\]\*\?(?:\\.|[^()\\])*\)/, '^').replace(/\(\?=(?:[^()]|\((?!\?<)[^()]*\))*\)/g, '');
    if(/\(\?[=!]|\(\?<[=!]|\\[1-9]|\\k</.test(fix)) return {level:'bad', note:`${RX_FLAVOR.kql} has no ${back ? 'back-references' : 'lookahead or lookbehind'}, and this pattern cannot do without it.`};
    const same = rxSame(src, fix, lines);
    return same ? {level:'fixed', src:fix, note:`${RX_FLAVOR.kql} has no lookahead: written without it — the same values on all your lines.`}
      : {level:'warn', src:fix, note:`${RX_FLAVOR.kql} has no lookahead: written without it, but some of your lines then give different values — check the results in your tool.`}; }
  if(kind === 'python' && /\(\?<[=!][^)]*[*+{]/.test(src)) return {level:'bad', note:'Python lookbehind must have a fixed width.'};
  if(kind === 'js' && atomic) return {level:'bad', note:'JavaScript has no atomic groups or possessive quantifiers.'};
  return {level:'ok', note:`Runs as it is in ${RX_FLAVOR[kind] || kind}.`}; }
/* ---------- undo and redo of field changes ---------- */
function rxSnap(){ const S = RX(); (S.hist = S.hist || []).push(JSON.stringify({f:S.fields, t:S.types, c:S.custom})); if(S.hist.length > 80) S.hist.shift(); S.fut = []; }
function rxUndo(redo){ const S = RX(), from = redo ? S.fut : S.hist, to = redo ? S.hist : S.fut; if(!from || !from.length) return toast(redo ? 'Nothing to redo' : 'Nothing to undo');
  (to || (redo ? S.hist = [] : S.fut = [])).push(JSON.stringify({f:S.fields, t:S.types, c:S.custom})); const x = JSON.parse(from.pop()); S.fields = x.f; S.types = x.t; S.custom = x.c; S.manual = null; S.opt = null; S.pend = null; rxRender(); }
/* ---------- the page ---------- */
function labRegex(){
  const S = RX();
  if(!S.lines.length) return `<div class="rx-in card-ish"><div class="field"><label for="rxText">Log lines</label><textarea id="rxText" rows="12" class="mono" spellcheck="false" placeholder="Paste log lines — one format or several, single lines or records over several lines (stack traces, Event Viewer exports)"></textarea></div>
    <div class="rx-inb"><button class="btn primary" data-act="rxGo">${ico('wand-sparkles','sm')}Start</button><button class="btn" data-act="rxFile">${ico('upload','sm')}Open a log file</button>
      <span class="rx-samples t3 small">Or try a sample: <button class="lnk" data-act="rxDemo">SSH</button> · <button class="lnk" data-act="rxDemo" data-v="mixed">mixed server log</button> · <button class="lnk" data-act="rxDemo" data-v="java">Java with stack traces</button></span></div>
    <ol class="rx-how t3 small"><li><b>Auto-parse</b> names the fields of known layouts — or select any part of a line and name it.</li><li>The pattern is built, checked on every line and on hostile input, explained in plain words, and can be made faster.</li><li>Copy it for Splunk, KQL, Grok, Python, JavaScript or PCRE. Nothing leaves this browser.</li></ol></div>
    ${rxlHtml()}
    <details class="rx-lib"><summary>Ready-made patterns for incident response</summary>${rxLibHtml()}</details>`;
  const V = rxView(), C = rxCurrent();
  const Sf = C.ok ? rxSafety(C.src, V.idx.slice(0, 300).map(i => S.lines[i])) : null, held = Sf && Sf.level === 'risky' && C.manual, R = C.ok && !held ? rxRun(C.src, S.lines, V.idx) : null, ok = R && !R.err, n = ok ? R.n : 0, groups = C.ok ? C.groups : [];
  const names = [...new Set((C.ok && !C.manual ? groups.map(g => g.name) : C.ok ? groups.map(g => g.name) : []).concat(V.fields.map(f => f.name)))], allNames = [...new Set(S.fields.map(f => f.name).concat(names))], col = nm => Math.max(0, allNames.indexOf(nm)) % 8;
  const total = V.idx.length, rec = S.ml && !S.mlOff, unit = rec ? ['record', 'records'] : ['line', 'lines'], U = k => k === 1 ? unit[0] : unit[1];
  const inView = new Set(V.idx), every = S.show === 'every';
  const FL = S.filter && ok ? S.filter : null;
  const pool = every ? S.lines.map((_, i) => i) : V.idx, shown = pool.filter(i => (!FL || (R.M[i] && R.M[i].g[FL.f] === FL.v)) && (!ok || every || S.show === 'all' || (S.show === 'hit' ? R.M[i] : !R.M[i]))).slice(0, RX_SHOW);
  UI.rxShown = shown;
  if(S.cur == null || !S.lines[S.cur] || (!every && !inView.has(S.cur))) S.cur = (ok && V.idx.find(i => R.M[i])) ?? V.idx[0];
  const misses = ok ? total - n : 0;
  const lineHtml = i => { const l = S.lines[i], ex = S.fields.filter(f => f.line === i).sort((a, b) => a.s - b.s), m = ok && R.M[i], other = !inView.has(i);
    const spans = (m ? Object.entries(m.ix).filter(([, v]) => v).map(([k, v]) => [v[0], v[1], k, false]) : []).concat(ex.map(f => [f.s, f.e, f.name, true])).sort((a, b) => a[0] - b[0] || b[3] - a[3]);
    let h = '', at = 0; for(const [s, e, nm, sel] of spans){ if(s < at) continue; h += esc(l.slice(at, s)) + `<mark class="rx-m c${col(nm)}${sel ? ' sel' : ''}" data-f="${esc(nm)}" data-tip="${esc(nm)}${sel ? ' · your example' : ''}">${esc(l.slice(s, e))}</mark>`; at = e; } h += esc(l.slice(at));
    /* a missed line shows where the pattern stops */
    let why = '';
    if(ok && !m && !other && i === S.cur){ const w = rxWhy(C.src, l); why = `<div class="rx-why">${ico('corner-down-right','sm')}<span>Matches up to column ${w.at + 1}${w.at < l.length ? ` (“${esc(l.slice(Math.max(w.from, w.at - 14), w.at))}”)` : ''}, then expects <code class="rx-src-in mono">${rxHl(w.next, col)}</code>${w.at < l.length ? ` but finds <code class="mono">${esc(l.slice(w.at, w.at + 18))}</code>` : ' but the line ends'}.</span></div>`;
      const at2 = Math.min(w.at, l.length); h = ''; at = 0; for(const [s, e, nm, sel] of spans){ if(s < at) continue; h += esc(l.slice(at, s)) + `<mark class="rx-m c${col(nm)}${sel ? ' sel' : ''}" data-f="${esc(nm)}">${esc(l.slice(s, e))}</mark>`; at = e; }
      if(!spans.length){ h = `<span class="rx-ok-part">${esc(l.slice(0, at2))}</span><span class="rx-stop" aria-label="the pattern stops here"></span>${esc(l.slice(at2))}`; } else h += esc(l.slice(at)); }
    return `<div role="listitem" class="rx-ln${ok && !other ? (m ? ' hit' : ' miss') : ''}${other ? ' other' : ''}${ex.length ? ' ex' : ''}${i === S.cur ? ' cur' : ''}" data-i="${i}"><span class="rx-no" title="${ex.length ? 'Example you selected' : other ? 'Another format' : ok ? (m ? 'Matches' : 'Missed') : ''}">${i + 1}</span><span class="rx-t">${h || ' '}</span>${ex.length ? `<button class="iconbtn xs" data-act="rxUnex" data-v="${i}" aria-label="Stop using ${unit[0]} ${i + 1} as an example" title="Stop using this as an example">${ico('x','sm')}</button>` : ''}${why}</div>`; };
  /* field statistics over the matches: how often present, how many values, the commonest */
  const FS = {}; if(ok && n) for(const nm of names){ let c = 0; const cnt = new Map(); for(const i of V.idx){ const m = R.M[i]; if(m && m.g[nm] != null){ c++; cnt.set(m.g[nm], (cnt.get(m.g[nm]) || 0) + 1); } }
    FS[nm] = {cov:c / n, distinct:cnt.size, top:[...cnt.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3)}; }
  const opt = new Set(C.optional || []);
  const fstat = F => { const set = new Set(F.lines), fl = S.fields.filter(f => set.has(f.line));
    if(F.kind === 'header') return ['muted', 'not parsed', 'Header lines are left out'];
    if(!fl.length) return ['muted', 'no fields', 'No fields yet'];
    const B = rxBuiltFor(fl); if(!B.ok) return ['warn', 'fix fields', B.why];
    let k = 0; try{ const re = new RegExp(B.src); for(const i of F.lines) if(re.test(S.lines[i])) k++; }catch(e){}
    return [k === F.lines.length ? 'good' : 'warn', `${k} of ${F.lines.length}`, `The pattern matches ${k} of its ${F.lines.length} ${U(F.lines.length)}`]; };
  const fmts = S.fmts.length > 1 ? `<div class="rx-fm" role="tablist" aria-label="Formats"><button class="rx-fmi rx-fmall" role="tab" data-act="rxFmt" data-v="-1" aria-selected="${S.fmt < 0}" title="One pattern for every ${unit[0]}"><b>All</b><span class="rx-fmc">${S.lines.length.toLocaleString()}</span></button>${S.fmts.map((F, fi) => { const [c, t, tip] = fstat(F), ex = S.lines[F.lines[0]].split('\n')[0];
      return `<button class="rx-fmi" role="tab" data-act="rxFmt" data-v="${fi}" aria-selected="${S.fmt === fi}" title="${esc((F.label ? F.label + ' · ' : '') + tip + '\n' + ex.slice(0, 160))}"><span class="rx-fdot ${c}"></span><b class="mono">${esc(F.name)}</b><span class="rx-fmc">${F.lines.length.toLocaleString()}</span><span class="rx-fms ${c}">${esc(t)}</span></button>`; }).join('')}</div>` : '';
  const P = S.fmts.length > 1 ? rxAllPatterns() : [], src0 = C.ok ? (C.built || C.src) : '', O = S.opt && C.ok && S.opt.from === src0 ? S.opt : null;
  const tab = RX_TABS.some(t => t[0] === S.tab) ? S.tab : 'match', cm = ok && R.M[S.cur];
  const TT = (S.tests || []).filter(t => t.fmt === S.fmt), TR = C.ok && !held ? rxTestRun(C.src, TT) : TT.map(() => ({ok:false, why:'no pattern'})), tFail = TR.filter(x => !x.ok).length;
  const speed = ok && n && !held ? (O ? O.end && C.optimised ? O.end : O.start : null) : null;
  /* the sidebar */
  const body = {
    match:() => { const i = S.cur, l = S.lines[i]; if(l == null) return `<p class="rx-empty t3">Click a ${unit[0]} to see what it gives.</p>`;
      const head = `<div class="rx-mh"><b>${unit[0][0].toUpperCase() + unit[0].slice(1)} ${i + 1}</b>${!inView.has(i) ? '<span class="t3">· another format</span>' : cm ? `<span class="rx-good">${ico('check','sm')}matches</span>` : ok ? `<span class="rx-warn">${ico('triangle-alert','sm')}missed</span>` : ''}<span style="flex:1"></span>${cm ? `<button class="btn xs ghost" data-act="rxCopyRow">${ico('copy','sm')}Copy as JSON</button>` : ''}</div>`;
      const pinned = TT.find(t => t.text === l), pin = !C.ok ? '' : `<div class="rx-pin">${pinned ? `<span class="t3 small">${ico('pin','sm')}Pinned as a test: must ${pinned.want === 'none' ? 'not ' : ''}match</span>` : cm ? `<button class="btn xs" data-act="rxPin" data-v="match">${ico('pin','sm')}Pin as test: must match, with these values</button>` : `<button class="btn xs" data-act="rxPin" data-v="none">${ico('pin','sm')}Pin as test: must not match</button>`}</div>`;
      if(cm) return head + pin + `<dl class="rx-kv">${groups.map(g => { const v = cm.g[g.name]; return `<dt class="c${col(g.name)}" data-f="${esc(g.name)}"><span class="rx-dot"></span>${esc(g.name)}</dt><dd class="mono${v == null ? ' rx-none' : ''}">${v == null ? 'not on this line' : esc(v)}</dd>`; }).join('')}</dl>`;
      if(ok && inView.has(i)){ const w = rxWhy(C.src, l); return head + pin + `<p class="small" style="margin:0 0 8px">The pattern matches the start of this ${unit[0]} up to column <b>${w.at + 1}</b>, then needs <code class="rx-src-in mono">${rxHl(w.next, col)}</code>${w.at < l.length ? `, but the ${unit[0]} has <code class="mono">${esc(l.slice(w.at, w.at + 24))}</code>` : `, but the ${unit[0]} ends there`}.</p><p class="t3 small" style="margin:0">To teach it this variation, select the same fields on this ${unit[0]}. A field it does not have becomes optional.</p>`; }
      return head + pin + `<p class="t3 small" style="margin:0">${C.ok ? 'This line belongs to another format.' : 'Select a part of a line to start.'}</p>`; },
    explain:() => !C.ok ? `<p class="rx-empty t3">The pattern is explained here, piece by piece.</p>` : `<ol class="rx-xp">${rxExplainRows(C.src, groups).map(r => `<li class="rx-x-${r.k}${r.f ? ' c' + col(r.f) : ''}"${r.f ? ` data-f="${esc(r.f)}"` : ''}><span class="rx-xh">${r.html}</span>${r.src ? `<code class="mono rx-xs">${rxHl(r.src, col)}</code>` : ''}</li>`).join('')}</ol>`,
    fields:() => !names.length ? `<p class="rx-empty t3">Select a part of a ${unit[0]} — an IP address, a user name, a time — and name it, or use <b>Auto-parse</b>.</p>`
      : `<div class="rx-fs" role="list">${names.map(nm => { const g = groups.find(x => x.name === nm), t = (S.types || {})[nm] || 'auto', st = FS[nm], auto = g && (g.type === 'delim' ? 'text' : (rxType(g.type) || [, g.type])[1].replace(/ \(.*\)$/, ''));
          return `<div class="rx-fld c${col(nm)}" role="listitem" data-f="${esc(nm)}">
            <div class="rx-fr1"><span class="rx-dot"></span><b class="mono rx-fnm" title="${esc(nm)}">${esc(nm)}</b>${opt.has(nm) ? '<span class="rx-tagopt">optional</span>' : ''}
              ${C.manual ? '<span style="flex:1"></span>' : `<label class="sr" for="rxT-${esc(nm)}">What ${esc(nm)} is</label><select class="rx-sel" id="rxT-${esc(nm)}" data-rx="type" data-name="${esc(nm)}" title="What ${esc(nm)} is"><option value="auto"${t === 'auto' ? ' selected' : ''}>${auto ? 'Auto · ' + esc(auto) : 'Auto'}</option><option value="delim"${t === 'delim' ? ' selected' : ''}>Up to the next delimiter</option>${RX_TYPES.map(x => `<option value="${x[0]}"${t === x[0] ? ' selected' : ''}>${esc(x[1])}</option>`).join('')}</select>`}
              <span class="rx-cov${st && st.cov < 1 ? ' part' : ''}" title="Share of matching ${unit[1]} that have ${esc(nm)}">${st ? `${opt.has(nm) ? 'optional · ' : ''}${st.cov === 1 ? 'every match' : Math.round(st.cov * 100) + '% of matches'}` : opt.has(nm) ? 'optional' : ''}</span>
              ${st ? `<button class="iconbtn xs" data-act="rxToCase" data-v="${esc(nm)}" aria-label="Add the values of ${esc(nm)} to the case" title="Add its ${st.distinct.toLocaleString()} value${st.distinct === 1 ? '' : 's'} to the case">${ico('folder-plus','sm')}</button>` : ''}
              ${C.manual ? '' : `<button class="iconbtn xs" data-act="rxDel" data-v="${esc(nm)}" aria-label="Remove ${esc(nm)}" title="Remove the field">${ico('x','sm')}</button>`}</div>
            ${st ? `<div class="rx-fr3"><span class="rx-bar1" aria-hidden="true"><i style="width:${Math.round(st.cov * 100)}%"></i></span><span class="t3">${st.distinct.toLocaleString()} distinct</span><span class="rx-top mono">${st.top.map(([v, c]) => `<button class="rx-val${FL && FL.f === nm && FL.v === v ? ' on' : ''}" data-act="rxFilt" data-v="${esc(JSON.stringify([nm, v]))}" title="Show only ${unit[1]} where ${esc(nm)} is “${esc(v)}”">${esc(v.length > 22 ? v.slice(0, 20) + '…' : v)}${c > 1 ? ` <i>×${c}</i>` : ''}</button>`).join('')}</span></div>` : ''}</div>`; }).join('')}</div>`,
    tests:() => { const add = `<form class="rx-tadd" data-form="rxTestAdd"><label class="sr" for="rxTestText">A line to test</label><textarea id="rxTestText" class="mono" rows="2" spellcheck="false" placeholder="Paste a line that must or must not match"></textarea>
          <div class="wrap"><button class="btn xs" type="submit" data-want="match">Must match</button><button class="btn xs" type="button" data-act="rxTestNone">Must not match</button></div></form>`;
        if(!TT.length) return `<p class="t3 small" style="margin:0">Tests keep a pattern honest: pin lines that must match (with their values) and lines that must not, and every change is checked against them — a fix cannot quietly break an older line. Pin a line from the Match tab, or paste one here.</p>${add}`;
        return `<p class="rx-tsum ${tFail ? 'rx-warn' : 'rx-good'}">${ico(tFail ? 'triangle-alert' : 'circle-check','sm')}${tFail ? `${tFail} of ${TT.length} tests fail` : `All ${TT.length} tests pass`}</p>
          <ul class="rx-tl">${TT.map((t, k) => `<li class="${TR[k].ok ? 'pass' : 'fail'}"><span class="rx-ti">${ico(TR[k].ok ? 'check' : 'x','sm')}</span><div><span class="rx-tw2">must ${t.want === 'none' ? 'not ' : ''}match${t.expect ? ' · ' + Object.keys(t.expect).length + ' values' : ''}</span><code class="mono">${esc(t.text.length > 140 ? t.text.slice(0, 138) + '…' : t.text)}</code>${TR[k].ok ? '' : `<span class="rx-tf">${esc(TR[k].why)}</span>`}</div><button class="iconbtn xs" data-act="rxTestDel" data-v="${S.tests.indexOf(t)}" aria-label="Remove this test">${ico('x','sm')}</button></li>`).join('')}</ul>${add}`; },
    speed:() => !(ok && n) ? `<p class="rx-empty t3">Build a pattern that matches first.</p>` : C.manual ? `<p class="rx-empty t3">The optimiser works on the built pattern.</p>`
      : `<div class="rx-sh"><button class="btn sm${O ? '' : ' primary'}" data-act="rxOpt">${ico('gauge','sm')}${O ? 'Run again' : 'Optimise'}</button>${O && O.src !== O.from && !C.optimised ? `<button class="btn sm primary" data-act="rxOptUse">${ico('check','sm')}Use the optimised pattern</button>` : ''}</div>
        ${O ? `<p class="rx-speed"><b>${rxRate(O.start)}</b> → <b>${rxRate(O.end)}</b> ${unit[1]} a second${O.end > O.start * 1.02 ? ` <span class="rx-good">${Math.round((O.end / O.start - 1) * 100)}% faster</span>` : ' <span class="t3">· already about as fast as it gets</span>'}</p>
          <ol class="rx-steps">${O.steps.map(st => `<li class="${st.state}"><div class="rx-sth"><b>${esc(st.title)}</b><span class="rx-sts">${{kept:'Kept', none:'Nothing to change', slower:'Not faster — left out', differs:'Would change the results — left out'}[st.state]}${st.detail ? ' · ' + esc(st.detail) : ''}</span>${st.from ? `<span class="t3 small">${rxRate(st.from)} → ${rxRate(st.to)} a second</span>` : ''}</div>
            ${st.state !== 'none' ? `<p class="t3 small">${esc(st.why)}</p>` : ''}${st.before && st.state !== 'none' ? `<code class="mono rx-diff">${rxDiff(st.before, st.after)}</code>` : ''}</li>`).join('')}</ol>
          <p class="t3 small">Measured in this browser on ${Math.min(2000, S.lines.length).toLocaleString()} ${U(2)}, matching and not. A rewrite is kept only if every ${unit[0]} gives exactly the same values.</p>`
        : `<p class="t3 small rx-empty">Tries six rewrites one at a time — tying the pattern to the line start, taking out shared words, exact character classes instead of wildcards, a fixed word checked first — times each, and keeps only those that give exactly the same values on every ${unit[0]}.</p>`}
        ${Sf && Sf.notes.length ? `<div class="rx-safebox"><b class="rx-safe ${Sf.level}">${ico(Sf.level === 'safe' ? 'shield-check' : 'triangle-alert','sm')}${{safe:'Safe on hostile input', watch:'Watch', risky:'Risky', bad:'Invalid'}[Sf.level]}</b><ul class="rx-notes">${Sf.notes.map(x => `<li>${esc(x)}</li>`).join('')}</ul></div>` : ''}`,
    export:() => !(ok && n) ? `<p class="rx-empty t3">Build a pattern that matches first.</p>`
      : `<div class="rx-sh"><div class="seg" role="group" aria-label="Tool">${RX_EXPORTS.map(([k, l]) => `<button data-act="rxExp" data-v="${k}" aria-pressed="${S.exp === k}">${l}</button>`).join('')}</div>
          ${P.length > 1 ? `<div class="seg" role="group" aria-label="Which patterns"><button data-act="rxExpAll" data-v="0" aria-pressed="${!S.expAll}">This format</button><button data-act="rxExpAll" data-v="1" aria-pressed="${!!S.expAll}">All formats (${P.length})</button></div>` : ''}</div>
        ${(() => { const all = P.length > 1 && S.expAll, K = all ? null : rxCompat(C.src, S.exp, V.idx.slice(0, 2000).map(i => S.lines[i]));
          const out = all ? rxExportAll(P.map(p => { const k = rxCompat(p.src, S.exp, S.lines.slice(0, 2000)); return k.src ? {...p, src:k.src} : p; }), S.exp) : rxExport(K.src || C.src, groups, S.exp);
          const chips = RX_EXPORTS.map(([k, l]) => { const c = rxCompat(C.src, k, []); return `<span class="rx-cc ${c.level === 'ok' ? 'ok' : c.level === 'bad' ? 'bad' : 'fix'}" title="${esc(c.note)}">${ico(c.level === 'ok' ? 'check' : c.level === 'bad' ? 'x' : 'wand-sparkles','sm')}${l}</span>`; }).join('');
          return `<div class="rx-compat"><span class="t3 small">Runs in</span>${chips}</div>${K && K.level !== 'ok' ? `<p class="rx-cn ${K.level}">${ico(K.level === 'bad' ? 'triangle-alert' : K.level === 'warn' ? 'triangle-alert' : 'info','sm')}${esc(K.note)}</p>` : ''}<pre class="rx-out mono" id="rxOut">${esc(out)}</pre>`; })()}
        <div class="wrap"><button class="btn sm primary" data-act="rxCopy">${ico('copy','sm')}Copy</button><button class="btn sm" data-act="rxBig" title="Read a log file of any size here and count what this pattern finds in it">${ico('file-search','sm')}Run on a whole file</button><button class="btn sm" data-act="rxSave">${ico('save','sm')}Save as a parser for log imports</button></div>
        ${rec ? `<details class="rx-box"><summary>Records over several lines: the same setting for Logstash, Filebeat, Splunk and Fluent Bit</summary><pre class="rx-out mono" id="rxMlOut">${esc(rxMlExport(S.ml.re))}</pre><button class="btn xs" data-act="rxMlCopy">${ico('copy','sm')}Copy</button></details>` : ''}`};
  const cnt = {match:'', explain:'', fields:names.length || '', tests:TT.length ? (tFail ? '✗' + tFail : TT.length) : '', speed:'', export:''};
  const tbl = () => ok && n ? (() => { const G = groups.map(g => g.name), rows = V.idx.filter(i => R.M[i] && (!FL || R.M[i].g[FL.f] === FL.v)).slice(0, 500);
      return `<div class="rx-tw"><table class="rx-tb"><thead><tr><th scope="col">#</th>${G.map(g => `<th scope="col" class="c${col(g)}" data-f="${esc(g)}"><span class="rx-dot"></span>${esc(g)}</th>`).join('')}</tr></thead><tbody>${rows.map(i => `<tr data-i="${i}"${i === S.cur ? ' class="cur"' : ''}><td class="t3">${i + 1}</td>${G.map(g => { const v = R.M[i].g[g], nl = v ? (v.match(/\n/g) || []).length : 0; return `<td class="mono${v == null ? ' rx-none' : ''}${nl ? ' rx-ml' : ''}"${v != null && (v.length > 40 || nl) ? ` title="${esc(v.length > 600 ? v.slice(0, 600) + '…' : v)}"` : ''}${nl ? ` data-more="+${nl} line${nl === 1 ? '' : 's'}"` : ''}>${v == null ? '—' : esc(v)}</td>`; }).join('')}</tr>`).join('')}</tbody></table></div>${n > 500 ? `<p class="t3 small" style="margin:8px 12px">First 500 of ${n.toLocaleString()} matches.</p>` : ''}`; })() : `<p class="rx-empty t3">Nothing matched yet.</p>`;
  return `<div class="rxb">
    <div class="rx-bar">
      ${S.lib && rxlList().find(x => x.id === S.lib) ? `<span class="rx-libn" title="Opened from My patterns">${ico('save','sm')}${esc(rxlList().find(x => x.id === S.lib).name)}</span>` : ''}
      <span class="rx-cnt"><b>${S.lines.length.toLocaleString()}</b> ${U(S.lines.length)}${rec ? ` <span class="t3">from ${S.raw.length.toLocaleString()} lines</span>` : ''}${S.fmts.length > 1 ? ` · ${S.fmts.length} formats` : ''}</span>
      ${S.ml ? `<span class="rx-mlc${rec ? ' on' : ''}" title="${rec ? `Each record starts with ${esc(S.ml.label)}` : `These lines look like records over several lines, each starting with ${esc(S.ml.label)}`}">${ico('rows-3','sm')}${rec ? `${S.raw.length.toLocaleString()} lines read as ${S.lines.length.toLocaleString()} records · each starts with ${esc(S.ml.label)}` : 'Records over several lines found'}<button class="lnk" data-act="rxMl">${rec ? 'Read lines separately' : 'Join into records'}</button></span>` : ''}
      <span style="flex:1"></span>
      <span class="rx-ur"><button class="iconbtn sm" data-act="rxUndo" aria-label="Undo" title="Undo (Ctrl+Z)"${(S.hist || []).length ? '' : ' disabled'}>${ico('undo-2','sm')}</button><button class="iconbtn sm" data-act="rxRedo" aria-label="Redo" title="Redo (Ctrl+Shift+Z)"${(S.fut || []).length ? '' : ' disabled'}>${ico('redo-2','sm')}</button></span>
      <label class="rx-opt" title="Tie the pattern to the start of the line"><input type="checkbox" data-rx="fromStart"${S.fromStart ? ' checked' : ''}> From line start</label>
      <button class="btn sm ghost" data-act="rxMask" title="A copy of these lines with addresses, users and hosts replaced — safe to paste elsewhere">${ico('eye-off','sm')}Mask a copy</button>
      <button class="btn sm ghost" data-act="rxlLib" title="Patterns you saved">${ico('folder-open','sm')}My patterns${rxlList().length ? ` <span class="t3">${rxlList().length}</span>` : ''}</button>
      <button class="btn sm ghost" data-act="rxReset" title="Clear everything and paste other log lines">${ico('eraser','sm')}Start over</button>
      <button class="btn sm primary" data-act="rxAutoParse">${ico('wand-sparkles','sm')}Auto-parse</button></div>
    <section class="rx-pc" aria-label="Pattern">
      <div class="rx-pch">${fmts || '<span class="rx-plbl">Pattern</span>'}<span style="flex:1"></span>
        ${ok ? `<span class="rx-stat"><b>${n.toLocaleString()}</b> of ${total.toLocaleString()} ${U(total)}${V.F ? ' in this format' : ''} match</span>` : ''}
        ${Sf && !held ? `<span class="rx-safe ${Sf.level}" title="${esc(Sf.notes.join(' ') || 'Tried on very long and almost-matching lines; it never took more than a few milliseconds')}">${ico(Sf.level === 'safe' ? 'shield-check' : 'triangle-alert','sm')}${{safe:'Safe on hostile input', watch:'Watch', risky:'Risky', bad:'Invalid'}[Sf.level]}</span>` : ''}
        ${TT.length ? `<button class="rx-chip rx-tchip ${tFail ? 'bad' : 'good'}" data-act="rxTab" data-v="tests" title="Pinned tests">${ico(tFail ? 'triangle-alert' : 'flask-conical','sm')}${tFail ? `${tFail} of ${TT.length} tests fail` : `${TT.length} test${TT.length === 1 ? '' : 's'} pass`}</button>` : ''}
        ${speed ? `<span class="rx-chip" title="Measured by the optimiser">${ico('gauge','sm')}${rxRate(speed)} ${unit[1]}/s</span>` : ''}</div>
      <div class="rx-pbox${C.manual ? ' editing' : ''}"><span class="rx-delim">/</span>
        ${C.manual ? `<label class="sr" for="rxSrc">Pattern</label><textarea id="rxSrc" class="mono rx-src" rows="3" spellcheck="false">${esc(S.manual)}</textarea>` : C.ok ? `<pre class="rx-src mono" id="rxSrcView" data-act="rxEditP" title="Click to edit by hand">${rxHl(C.src, col)}</pre>` : `<div class="rx-src rx-ph">${V.fields.length ? esc(C.why) + (V.all && S.fmts.length > 1 ? ' With several formats, pick one above: each gets its own pattern.' : '') : `Select any part of a ${unit[0]} below to make it a field — or press Auto-parse.`}</div>`}
        <span class="rx-delim">/</span>
        <div class="rx-pact">${C.manual ? '<span class="chip sq amber">edited by hand</span><button class="btn xs ghost" data-act="rxAuto">Back to built</button>' : C.optimised ? '<span class="chip sq">optimised</span><button class="btn xs ghost" data-act="rxOptOff">Back to built</button>' : ''}${C.ok && !C.manual ? `<button class="btn xs ghost" data-act="rxFull" aria-pressed="${!!S.fullPat}" title="${S.fullPat ? 'Show standard patterns by name' : 'Show standard patterns in full'}">${ico(S.fullPat ? 'minimize-2' : 'maximize-2','sm')}</button><button class="btn xs ghost" data-act="rxEdit" title="Edit by hand">${ico('pencil','sm')}</button><button class="btn xs ghost" data-act="rxCopySrc" title="Copy the pattern">${ico('copy','sm')}</button>` : ''}${C.ok ? `<button class="btn xs" data-act="rxlSave" title="Save to My patterns, with the sample lines, fields and tests">${ico('save','sm')}Save</button>` : ''}</div></div>
      ${held ? `<div class="rx-stat"><span class="rx-safe risky">${ico('triangle-alert','sm')}Risky — not run</span></div><ul class="rx-notes">${Sf.notes.map(x => `<li>${esc(x)}</li>`).join('')}</ul>` : R && R.err ? `<p class="rx-err">${esc(R.err)}</p>` : ''}
    </section>
    <div class="rxw${S.side === 'closed' ? ' side-closed' : ''}">
      <section class="rxw-l" aria-label="Log ${unit[1]}">
        <div class="rxw-h"><div class="seg sm" role="group" aria-label="View"><button data-act="rxLeft" data-v="lines" aria-pressed="${S.left !== 'table'}">${ico('scan-text','sm')}${unit[1][0].toUpperCase() + unit[1].slice(1)}</button><button data-act="rxLeft" data-v="table" aria-pressed="${S.left === 'table'}">${ico('table','sm')}Table</button></div>
          ${FL ? `<span class="rx-flt c${col(FL.f)}">${ico('filter','sm')}<b class="mono">${esc(FL.f)}</b> = <span class="mono">${esc(FL.v.length > 30 ? FL.v.slice(0, 28) + '…' : FL.v)}</span><button class="iconbtn xs" data-act="rxFilt" data-v="" aria-label="Clear the filter">${ico('x','sm')}</button></span>` : S.left !== 'table' ? `<span class="t3 small rx-hint" title="Keys: ↑ ↓ move · M next missed · / edit the pattern · Ctrl+Z undo">Select text to add a field <kbd>↑</kbd><kbd>↓</kbd><kbd>M</kbd></span>` : ''}<span style="flex:1"></span>
          ${ok && S.left !== 'table' ? `<div class="seg sm" role="group" aria-label="Show ${unit[1]}">${[['all', V.F ? 'This format' : 'All', total], ['hit', 'Matched', n], ['miss', 'Missed', misses]].concat(V.F ? [['every', 'Every ' + unit[0], S.lines.length]] : []).map(([k, l, c]) => `<button data-act="rxShow" data-v="${k}" aria-pressed="${S.show === k}">${l} <span class="${k === 'miss' && c ? 'rx-nm' : 'rx-nc'}">${c.toLocaleString()}</span></button>`).join('')}</div>` : ''}</div>
        ${S.left === 'table' ? tbl() : `<div class="rx-lines" id="rxLines" role="list">${shown.map(lineHtml).join('') || `<p class="rx-empty t3">No ${unit[1]} here.</p>`}</div>`}
        ${S.pend ? `<form class="rx-pend" data-form="rxName" style="left:${S.pend.x || 12}px;top:${S.pend.y || 12}px"><span class="rx-pv mono" title="${esc(S.pend.v)}">${esc(S.pend.v.length > 40 ? S.pend.v.slice(0, 38) + '…' : S.pend.v)}</span><div class="rx-prow"><label class="sr" for="rxName">Field name</label><input id="rxName" class="inp sm mono" value="${esc(S.pend.name)}" maxlength="32" autocomplete="off" pattern="[A-Za-z_][A-Za-z0-9_]{0,31}">
          <button class="btn sm primary" type="submit">Add field</button><button class="iconbtn xs" type="button" data-act="rxCancel" aria-label="Cancel">${ico('x','sm')}</button></div>
          ${allNames.length ? `<div class="rx-pk"><span class="t3 small">Same as</span>${allNames.slice(0, 14).map(nm => `<button type="button" class="chip c${col(nm)}" data-act="rxPick" data-v="${esc(nm)}">${esc(nm)}</button>`).join('')}</div>` : ''}<span class="hint" id="rxNameHint"></span></form>` : ''}
      </section>
      ${S.side === 'closed' ? `<aside class="rxw-r rx-rail" aria-label="Details (hidden)"><button class="iconbtn sm" data-act="rxSide" aria-label="Show the details panel" title="Show the details panel">${ico('panel-right','sm')}</button>${RX_TABS.map(([k, l]) => `<button class="rx-rt" data-act="rxTab" data-v="${k}" title="${l}">${l}${cnt[k] ? `<span class="rx-tc${k === 'tests' && tFail ? ' bad' : ''}">${cnt[k]}</span>` : ''}</button>`).join('')}</aside>`
      : `<aside class="rxw-r" aria-label="Details">
        <div class="rx-tabs"><div class="rx-tabl" role="tablist" aria-label="Details">${RX_TABS.map(([k, l]) => `<button role="tab" data-act="rxTab" data-v="${k}" aria-selected="${tab === k}" id="rxtab-${k}">${l}${cnt[k] ? `<span class="rx-tc${k === 'tests' && tFail ? ' bad' : ''}">${cnt[k]}</span>` : ''}</button>`).join('')}</div><span style="flex:1"></span><button class="iconbtn xs rx-hide" data-act="rxSide" aria-label="Hide the details panel" title="Hide the panel — more room for the ${S.left === 'table' ? 'table' : unit[1]}">${ico('panel-right','sm')}</button></div>
        <div class="rx-tb-b" role="tabpanel" tabindex="0" aria-labelledby="rxtab-${tab}">${body[tab]()}</div>
      </aside>`}
    </div>
    <details class="rx-lib"><summary>Ready-made patterns for incident response</summary>${rxLibHtml()}</details></div>`;
}
/* redraw without losing your place in the lines */
function rxRender(){ const a = $('rxLines'), y = a ? a.scrollTop : 0; renderMain(); const b = $('rxLines'); if(b) b.scrollTop = y; }
/* its own page in the sidebar (Kit → Regex builder) */
/* Regex: build a pattern from your own lines, and the parsers that read evidence into fields — one place for both */
function viewRegex(){ const t = UI.patTab === 'logs' ? 'logs' : 'build', np = (DB.parsers || []).length;
  return `<div class="scroll"><div class="page wide">
    <header class="lhd rx-lhd"><div><h1>Regex</h1><p>${t === 'logs' ? 'How evidence is read into fields: try a log line, keep your own parsers, and tell the parser what a vendor’s field names mean.' : 'Tested, explained, fast patterns for Splunk, KQL, Grok, Python, JavaScript and PCRE — your lines never leave this browser.'}</p></div></header>
    <div class="seg pat-tabs" role="tablist" aria-label="Regex"><button role="tab" data-act="patTab" data-v="build" aria-selected="${t === 'build'}">${ico('regex','sm')}Build a pattern</button><button role="tab" data-act="patTab" data-v="logs" aria-selected="${t === 'logs'}">${ico('scan-text','sm')}Log parsers${np ? ` <span class="t3">${np}</span>` : ''}</button></div>
    ${t === 'logs' ? labParse() : labRegex()}</div></div>`; }
function rxLibHtml(){ return `<div class="rx-libl">${RX_LIB.map(([n, p], i) => `<div class="rx-libi"><span>${esc(n)}</span><code class="mono">${esc(p)}</code><button class="iconbtn xs" data-act="rxLib" data-v="${i}" aria-label="Copy the pattern for ${esc(n)}">${ico('copy','sm')}</button></div>`).join('')}</div>`; }
/* selecting text in a line → a field to name */
function rxFromSel(quiet){
  { const sel = getSelection(); if(!sel || sel.isCollapsed || !sel.rangeCount) return; const r = sel.getRangeAt(0), t0 = r.startContainer.parentElement && r.startContainer.parentElement.closest('.rx-t'), t1 = r.endContainer.parentElement && r.endContainer.parentElement.closest('.rx-t');
    if(!t0 || t0 !== t1){ if(!quiet && (t0 || t1)) toast('Select within one line'); return; } if(RX().pend) return;
    const pre = document.createRange(); pre.selectNodeContents(t0); pre.setEnd(r.startContainer, r.startOffset); let s = pre.toString().length, e = s + r.toString().length;
    const i = +t0.parentElement.dataset.i, S = RX(), line = S.lines[i] || '';
    while(s < e && /\s/.test(line[s])) s++; while(e > s && /\s/.test(line[e - 1])) e--; if(e <= s) return;
    if(S.fields.some(f => f.line === i && s < f.e && e > f.s)) return toast('That overlaps a field you already chose');
    const v = line.slice(s, e), taken = new Set(S.fields.map(f => f.name));
    /* the next field in order on an example line is likely the same field here */
    let name = rxNameFor([v]); if(taken.has(name)){ let k = 2; while(taken.has(name + k)) k++; name = name + k; }
    const VF = rxView().fields, ex0 = VF.length ? VF.filter(f => f.line === VF[0].line).sort((a, b) => a.s - b.s) : [], mine = S.fields.filter(f => f.line === i);
    if(VF.length && i !== VF[0].line && ex0[mine.length]) name = ex0[mine.length].name;
    const box = t0.closest('.rxw-l'), rb = r.getBoundingClientRect(), bb = box.getBoundingClientRect();
    const x = Math.max(8, Math.min(rb.left - bb.left, bb.width - 320)), y = rb.bottom - bb.top + 6;
    S.pend = {line:i, s, e, v, name, x:Math.round(x), y:Math.round(y)}; sel.removeAllRanges(); rxRender(); const inp = $('rxName'); if(inp){ inp.focus(); inp.select(); } }
}
/* keys on the Regex builder: ↑ ↓ move between lines, M the next missed line, / edit the pattern, Ctrl+Z / Ctrl+Shift+Z undo and redo, Esc cancels */
document.addEventListener('keydown', ev => { if(!UI.route || UI.route.area !== 'regex' || !UI.rx || !UI.rx.lines.length) return; const t = ev.target, typing = t && (/^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName) || t.isContentEditable); const S = RX();
  if(ev.key === 'Escape'){ if(S.pend){ S.pend = null; rxRender(); ev.preventDefault(); } else if(S.manual != null && typing && t.id === 'rxSrc'){ t.blur(); } return; }
  if(typing || ev.altKey || document.querySelector('#dlg[open], .dlg.open')) return;
  if((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === 'z'){ ev.preventDefault(); return rxUndo(ev.shiftKey); }
  if((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === 'y'){ ev.preventDefault(); return rxUndo(true); }
  if(ev.ctrlKey || ev.metaKey) return;
  const L = UI.rxShown || [], k = L.indexOf(S.cur);
  if(ev.key === 'ArrowDown' || ev.key === 'ArrowUp' || ev.key === 'j' || ev.key === 'k'){ if(!L.length) return; ev.preventDefault(); const d = ev.key === 'ArrowDown' || ev.key === 'j' ? 1 : -1; S.cur = L[Math.max(0, Math.min(L.length - 1, (k < 0 ? 0 : k + d)))]; if(S.tab !== 'match' && S.tab !== 'tests') S.tab = 'match'; rxRender(); const el = document.querySelector(`#rxLines .rx-ln[data-i="${S.cur}"]`); if(el) el.scrollIntoView({block:'nearest'}); return; }
  if(ev.key === 'm' || ev.key === 'M'){ const miss = [...document.querySelectorAll('#rxLines .rx-ln.miss')].map(x => +x.dataset.i); if(!miss.length) return toast('No missed lines'); ev.preventDefault(); const nx = miss.find(i => L.indexOf(i) > k) ?? miss[0]; S.cur = nx; S.tab = 'match'; rxRender(); const el = document.querySelector(`#rxLines .rx-ln[data-i="${nx}"]`); if(el) el.scrollIntoView({block:'center'}); return; }
  if(ev.key === '/'){ ev.preventDefault(); RX_ACTS.rxEdit(); } });
/* click a line (or a table row) to inspect it; hover a field to see it everywhere */
document.addEventListener('click', ev => { const t = ev.target; if(!t.closest || t.closest('button, a, input, select, textarea, form')) return; const ln = t.closest('#rxLines .rx-ln, .rx-tb tbody tr[data-i]'); if(!ln) return;
  const sel = getSelection(); if(sel && !sel.isCollapsed) return; const S = RX(); if(S.pend) return; const i = +ln.dataset.i; if(S.cur === i && S.tab === 'match' && S.side !== 'closed') return; S.cur = i; S.tab = 'match'; S.side = 'open'; rxRender(); });
document.addEventListener('mouseover', ev => { const t = ev.target; if(!t.closest) return; const box = t.closest('.rxb'); if(!box) return; const f = t.closest('[data-f]'), nm = f ? f.dataset.f : null; if(nm === UI.rxHot) return; UI.rxHot = nm;
  box.querySelectorAll('.hot[data-f]').forEach(x => x.classList.remove('hot')); if(nm) box.querySelectorAll(`[data-f="${CSS.escape(nm)}"]`).forEach(x => x.classList.add('hot')); });
document.addEventListener('mouseup', ev => { if(ev.target && ev.target.closest && ev.target.closest('#rxLines')) setTimeout(() => rxFromSel(false), 0); });
/* phones and tablets: a selection made by touch ends without a mouse-up; take it once it has stopped changing */
document.addEventListener('selectionchange', () => { clearTimeout(UI.rxSelT); UI.rxSelT = setTimeout(() => { const sel = getSelection(), n = sel && sel.anchorNode; if(n && n.parentElement && n.parentElement.closest('#rxLines') && matchMedia('(pointer: coarse)').matches) rxFromSel(true); }, 700); });
function rxTestAdd(want){ const S = RX(), el = $('rxTestText'), t = el && el.value.replace(/\r\n?/g, '\n').replace(/\n+$/, ''); if(!t || !t.trim()) return fieldErr('rxTestText', 'Paste a line first.');
  if(t.length > 20000) return fieldErr('rxTestText', 'Up to 20,000 characters.'); let expect = null;
  if(want === 'match'){ const C = rxCurrent(); try{ const m = C.ok && new RegExp(C.src).exec(t); if(m) expect = Object.fromEntries(Object.entries(m.groups || {}).filter(([, x]) => x != null)); }catch(e){} }
  (S.tests = S.tests || []).push({text:t, want, expect, fmt:S.fmt}); rxRender(); }
function rxNameSubmit(){ const S = RX(), nm = String($('rxName').value || '').trim(); if(!/^[A-Za-z_][A-Za-z0-9_]{0,31}$/.test(nm)) return fieldErr('rxName', 'Letters, digits and _ only, starting with a letter or _.'); rxAdd(nm); }
function rxAdd(nm){ const S = RX(), p = S.pend; if(!p) return; if(S.fields.some(f => f.line === p.line && f.name === nm)) return toast(`This line already has ${nm}`); rxSnap();
  S.fields.push({line:p.line, s:p.s, e:p.e, name:nm}); S.pend = null; S.manual = null; S.opt = null; rxRender(); }
document.addEventListener('change', ev => { const el = ev.target; if(!el || !el.dataset || !el.dataset.rx) return; const S = RX();
  if(el.dataset.rx === 'fromStart'){ S.fromStart = el.checked; rxRender(); }
  if(el.dataset.rx === 'type'){ rxSnap(); S.types[el.dataset.name] = el.value; S.manual = null; S.opt = null; rxRender(); } });
document.addEventListener('input', ev => { if(ev.target && ev.target.id === 'rxSrc'){ RX().manual = ev.target.value; clearTimeout(UI.rxT); UI.rxT = setTimeout(() => { const el = $('rxSrc'), pos = el && el.selectionStart; rxRender(); const n = $('rxSrc'); if(n){ n.focus(); try{ n.setSelectionRange(pos, pos); }catch(e){} } }, 500); } });
const RX_DEMO = `Nov  2 08:15:30 web01 sshd[1234]: Failed password for root from 203.0.113.7 port 51544 ssh2
Nov  2 08:15:33 web01 sshd[1234]: Failed password for invalid user admin from 203.0.113.7 port 51560 ssh2
Nov  2 08:16:02 web01 sshd[1240]: Accepted password for deploy from 198.51.100.23 port 40022 ssh2
Nov 12 22:01:47 web02 sshd[88213]: Failed password for root from 2001:db8::7 port 6022 ssh2
Nov 12 22:01:50 web02 sshd[88213]: Accepted publickey for j.doe from 192.0.2.44 port 52111 ssh2: RSA SHA256:Zx9...
Nov 12 22:02:10 web02 sshd[88219]: Connection closed by 192.0.2.44 port 52111 [preauth]`;
const RX_DEMO_MIXED = `Nov  2 08:15:30 web01 sshd[1234]: Failed password for root from 203.0.113.7 port 51544 ssh2
Nov  2 08:15:33 web01 sshd[1234]: Failed password for invalid user admin from 203.0.113.7 port 51560 ssh2
Nov  2 08:16:02 web01 sshd[1240]: Accepted password for deploy from 198.51.100.23 port 40022 ssh2
Nov  2 08:17:01 web01 CRON[2201]: (root) CMD (cd / && run-parts --report /etc/cron.hourly)
Nov  2 08:18:11 web01 sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx
Nov  2 08:19:01 web01 CRON[2210]: (root) CMD (cd / && run-parts --report /etc/cron.hourly)
Nov  2 08:20:44 web01 sudo:   alice : TTY=pts/1 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/cat /etc/shadow
Nov  2 08:21:09 web01 kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:16:3e:aa:bb:cc SRC=185.220.101.4 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=44321 DPT=22 WINDOW=64240
Nov  2 08:21:12 web01 kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:16:3e:aa:bb:cc SRC=45.155.205.3 DST=10.0.0.5 LEN=40 PROTO=UDP SPT=5353 DPT=161
Nov 12 22:01:47 web02 sshd[88213]: Failed password for root from 2001:db8::7 port 6022 ssh2
Nov 12 22:01:50 web02 sshd[88213]: Accepted publickey for j.doe from 192.0.2.44 port 52111 ssh2: RSA SHA256:Zx9...
Nov 12 22:02:10 web02 sshd[88219]: Connection closed by 192.0.2.44 port 52111 [preauth]
Nov 12 22:02:14 web02 sshd[88221]: Connection closed by 203.0.113.9 port 40110 [preauth]`;
const RX_DEMO_JAVA = `2026-11-02 08:15:30,123 INFO  [main] c.e.App - Started in 2.3s
2026-11-02 08:15:31,456 ERROR [http-nio-8080-exec-1] c.e.Api - Request failed for user alice
java.lang.NullPointerException: user is null
	at com.example.Api.handle(Api.java:42)
	at org.apache.catalina.core.StandardWrapperValve.invoke(StandardWrapperValve.java:197)
Caused by: java.io.IOException: closed
	... 12 more
2026-11-02 08:15:32,001 WARN  [main] c.e.Db - Slow query 1200 ms
2026-11-02 08:15:40,777 ERROR [http-nio-8080-exec-4] c.e.Auth - Login refused for 203.0.113.7
java.lang.SecurityException: too many attempts
	at com.example.Auth.check(Auth.java:88)`;
const RX_ACTS = {
  rxGo:() => { const t = $('rxText') && $('rxText').value; if(!t || !t.trim()) return fieldErr('rxText', 'Paste some log lines first.'); rxSetText(t); rxRender(); },
  rxDemo:(id, v) => { rxSetText(v === 'mixed' ? RX_DEMO_MIXED : v === 'java' ? RX_DEMO_JAVA : RX_DEMO); rxRender(); },
  rxAutoParse:() => { const S = RX(), done = []; rxSnap();
    S.fmts.forEach((F, fi) => { if(F.kind === 'header') return; const set = new Set(F.lines); if(S.fields.some(f => set.has(f.line))) return;   /* a format you already started is left as it is */
      const A = rxAutoFields(S, F.lines); if(A && A.fields.length){ S.fields.push(...A.fields); F.label = F.label || A.label; done.push(A.label); } });
    S.manual = null; S.opt = null;
    if(!done.length) toast(S.fields.length ? 'Every format already has fields' : 'Not a layout it knows — select the fields yourself');
    else { const c = {}; done.forEach(l => c[l] = (c[l] || 0) + 1); toast('Recognised: ' + Object.entries(c).map(([l, k]) => k > 1 ? l + ' ×' + k : l).join(', '));
      if(S.fmts.length > 1 && S.fmt < 0) S.fmt = Math.max(0, S.fmts.findIndex(F => F.kind !== 'header')); S.tab = 'match'; }
    rxRender(); },
  rxMl:() => { const S = RX(), had = S.fields.length; S.mlOff = !S.mlOff; rxApplyMl(); rxRender(); if(had) toast('Fields cleared: the lines are read differently now'); },
  rxMlCopy:() => { const el = $('rxMlOut'); if(el) copyText(el.textContent); },
  rxFmt:(id, v) => { const S = RX(); S.fmt = +v; S.manual = null; S.opt = null; S.show = 'all'; S.pend = null; rxRender(); },
  rxOpt:() => { const S = RX(), V = rxView(), C = rxBuiltFor(V.fields); if(!C.ok) return;
    const alt = rxBuild({lines:S.lines, fields:V.fields, types:S.types, custom:S.custom, fromStart:true}), lines = (V.all ? S.lines : V.idx.map(i => S.lines[i]).concat(S.lines.filter((_, i) => !V.F.lines.includes(i)).slice(0, 1000))).slice(0, 3000);
    const r = rxOptimise(C.src, lines, alt.ok ? [{k:'anchor', src:alt.src}] : []); S.opt = {...r, from:C.src, on:false}; S.tab = 'speed'; rxRender(); },
  rxOptUse:() => { const S = RX(); if(S.opt) S.opt.on = true; rxRender(); },
  rxOptOff:() => { const S = RX(); if(S.opt) S.opt.on = false; rxRender(); },
  rxExpAll:(id, v) => { RX().expAll = v === '1'; rxRender(); },
  rxTab:(id, v) => { const S = RX(); S.tab = v; S.side = 'open'; rxRender(); },
  rxEditP:() => { if(getSelection && !getSelection().isCollapsed) return; RX_ACTS.rxEdit(); },
  rxMask:() => { const S = RX(), src = S.raw.join('\n'), r = maskText(src); UI.rxMasked = r.text;
    openDlg(dhead('Masked copy') + `<div class="in"><p class="small" style="margin:0 0 10px">${r.map.length ? `Replaced ${esc(maskSummary(r.map))} — the same value always with the same placeholder, in the same shape, so patterns still work on it.` : 'Nothing identifying was found in these lines.'} Nothing leaves this browser.</p>
      <pre class="rx-out mono" id="rxMaskOut" style="max-height:46vh">${esc(r.text)}</pre>
      ${r.map.length ? `<details class="rx-box" style="margin-top:10px"><summary>What was replaced (${r.map.length}) — this list stays here, it is not in the copy</summary><table class="tbl rx-mt"><thead><tr><th>Kind</th><th>Was</th><th>Now</th><th>Times</th></tr></thead><tbody>${r.map.slice(0, 500).map(e => `<tr><td class="t3">${esc(MASK_LABEL[e.kind] || e.kind)}</td><td class="mono">${esc(e.from)}</td><td class="mono">${esc(e.to)}</td><td>${e.n}</td></tr>`).join('')}</tbody></table></details>` : ''}</div>
      <footer><button class="btn" data-act="dclose">Close</button><button class="btn" data-act="rxMaskUse" title="Work on the masked lines in the builder">Use masked lines here</button><button class="btn primary" data-act="rxMaskCopy">${ico('copy','sm')}Copy masked lines</button></footer>`, true); },
  rxMaskCopy:() => copyText(UI.rxMasked || ''),
  rxMaskUse:() => { closeDlg(); rxSetText(UI.rxMasked || ''); RX().lib = null; rxRender(); toast('Now working on the masked lines'); },
  rxUndo:() => rxUndo(false), rxRedo:() => rxUndo(true),
  rxFilt:(id, v) => { const S = RX(); if(!v){ S.filter = null; } else { const [f, val] = JSON.parse(v); S.filter = S.filter && S.filter.f === f && S.filter.v === val ? null : {f, v:val}; S.left = S.left || 'lines'; } rxRender(); },
  rxPin:(id, v) => { const S = RX(), C = rxCurrent(), l = S.lines[S.cur]; if(l == null) return; let expect = null;
    if(v === 'match'){ try{ const m = new RegExp(C.src).exec(l); if(m) expect = Object.fromEntries(Object.entries(m.groups || {}).filter(([, x]) => x != null)); }catch(e){} }
    (S.tests = S.tests || []).push({text:l, want:v === 'none' ? 'none' : 'match', expect, fmt:S.fmt}); toast('Pinned — every change is now checked against this line'); rxRender(); },
  rxTestDel:(id, v) => { const S = RX(); (S.tests || []).splice(+v, 1); rxRender(); },
  rxTestNone:() => rxTestAdd('none'),
  rxToCase:(id, v) => { const S = RX(), C = rxCurrent(), V = rxView(); if(!C.ok) return; if(!DB.active || !theCase()) return toast('Open a case first');
    let re; try{ re = new RegExp(C.src); }catch(e){ return; } const vals = new Map(); for(const i of V.idx){ const m = re.exec(S.lines[i]); const x = m && m.groups && m.groups[v]; if(x != null) vals.set(x, (vals.get(x) || 0) + 1); }
    if(!vals.size) return; const list = [...vals.entries()].sort((a, b) => b[1] - a[1]).slice(0, 2000), body = `Patterns: values of ${v} in ${V.idx.length.toLocaleString()} log ${V.idx.length === 1 ? 'line' : 'lines'}${V.F ? ' (format ' + V.F.name + ')' : ''}\nPattern: ${C.src}\n\n` + list.map(([x, c]) => `${x}\t${c}`).join('\n');
    DB.records.push({id:uid('r'), caseId:DB.active, type:'evidence', title:`Log values: ${v} (${vals.size.toLocaleString()})`, body, tsRaw:'', tsZone:'explicit', ts:Date.now(), source:'regex-builder', host:'', tags:['log', 'regex'], ents:E.extract(body), answer:'', addedBy:'You', addedAt:Date.now(), hash:''});
    mutate('saved log values'); hashRecords(); { const r0 = DB.records[DB.records.length - 1]; afterCapture(DB.active, [r0.id]); watchNotify([r0]); } renderNav(); toast(`${vals.size.toLocaleString()} values of ${v} saved to ${caseNm(theCase())}`, 'Open', () => go(caseHash(DB.active, 'timeline'))); },
  rxFull:() => { const S = RX(); S.fullPat = !S.fullPat; rxRender(); },
  rxLeft:(id, v) => { const S = RX(); if(S.left !== v) S.side = v === 'table' ? 'closed' : 'open'; S.left = v; rxRender(); },
  rxSide:() => { const S = RX(); S.side = S.side === 'closed' ? 'open' : 'closed'; rxRender(); },
  rxCopySrc:() => { const C = rxCurrent(); if(C.ok) copyText(C.src); },
  rxCopyRow:() => { const S = RX(), C = rxCurrent(); let re; try{ re = new RegExp(C.src); }catch(e){ return; } const m = re.exec(S.lines[S.cur] || ''); if(m) copyText(JSON.stringify(m.groups || {}, null, 2)); },
  rxFile:() => { const i = document.createElement('input'); i.type = 'file'; i.accept = '.log,.txt,.csv,.json,.jsonl,text/*'; i.onchange = async () => { const f = i.files && i.files[0]; if(!f) return; if(f.size > 50 * 1048576) return toast('That file is over 50 MB — paste a sample of it instead');
      const t = await fileText(f.size > 5 * 1048576 ? f.slice(0, 5 * 1048576) : f); rxSetText(t); rxRender(); if(f.size > 5 * 1048576) toast('Read the first 5 MB'); }; i.click(); },
  rxReset:() => { UI.rx = null; rxRender(); },
  rxCancel:() => { RX().pend = null; rxRender(); },
  rxPick:(id, v) => rxAdd(v),
  rxDel:(id, v) => { rxSnap(); const S = RX(), V = rxView(), set = new Set(V.idx); S.fields = S.fields.filter(f => f.name !== v || !set.has(f.line)); if(!S.fields.some(f => f.name === v)) delete S.types[v]; S.manual = null; S.opt = null; rxRender(); },
  rxUnex:(id, v) => { rxSnap(); const S = RX(); S.fields = S.fields.filter(f => f.line !== +v); S.manual = null; S.opt = null; rxRender(); },
  rxShow:(id, v) => { RX().show = v; rxRender(); },
  rxExp:(id, v) => { RX().exp = v; rxRender(); },
  rxEdit:() => { const S = RX(), C = rxCurrent(); S.manual = C.ok ? C.src : ''; rxRender(); const el = $('rxSrc'); if(el) el.focus(); },
  rxAuto:() => { RX().manual = null; rxRender(); },
  rxCopy:() => { const el = $('rxOut'); if(el) copyText(el.textContent); },
  rxLib:(id, v) => { const x = RX_LIB[+v]; if(x) copyText(x[1]); },
  patTab:(id, v) => { UI.patTab = v === 'logs' ? 'logs' : 'build'; renderMain(); },
  rxSave:() => { const C = rxCurrent(); if(!C.ok) return; if(typeof parserDlg === 'function') parserDlg(null, {name:'Built: ' + C.groups.map(g => g.name).slice(0, 4).join(', '), re:C.src}); },
};
