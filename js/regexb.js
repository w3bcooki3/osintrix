/* ==========================================================================
   Regex builder (Forensics kit → Regex builder). Paste log lines, select the
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
  ['ipv4', 'IPv4 address', '(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}', 'IPV4', 'ip', true],
  ['ipv6', 'IPv6 address', '[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:%\\w+)?', 'IPV6', 'ip', true],
  ['ip', 'IP address (v4 or v6)', '(?:(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}|[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:%\\w+)?)', 'IP', 'ip', true],
  ['mac', 'MAC address', '(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}', 'MAC', 'mac', true],
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
const rxTok = s => s.match(/[A-Za-z_][A-Za-z0-9_-]*\d[A-Za-z0-9_-]*|[A-Za-z_]+|\d+|[ \t]+|[^A-Za-z_\d \t]/g) || [];
const rxTokKind = t => /^[A-Za-z_].*\d/.test(t) ? 'n' : /^[A-Za-z_]/.test(t) ? 'w' : /^\d/.test(t) ? 'd' : /^[ \t]/.test(t) ? 's' : 'p';
/* one token as a pattern: words as written, numbers \d+, names with digits in them [\w.-]+, spaces " +" */
const rxTokRe = x => { const k = rxTokKind(x); return k === 'd' ? '\\d+' : k === 'n' ? '[\\w.-]+' : k === 's' ? (/\t/.test(x) ? '\\s+' : ' +') : rxEsc(x); };
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
  const mid = non.length && non.length <= 4 ? (non.length === 1 ? '(?:' + non[0] + ')' : '(?:' + non.join('|') + ')') + (mids.includes('') ? '?' : '') : '.*?';
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
/* the examples: lines with fields, all in the same order → {ok, why, src, groups:[{name, type, src}]} */
function rxBuild(S){
  const lines = S.lines, byLine = new Map();
  for(const f of S.fields){ if(!byLine.has(f.line)) byLine.set(f.line, []); byLine.get(f.line).push(f); }
  if(!byLine.size) return {ok:false, why:'Select a part of a line to start.'};
  const ex = [...byLine.entries()].map(([i, F]) => ({i, line:lines[i] || '', F:F.slice().sort((a, b) => a.s - b.s)}));
  const order = ex[0].F.map(f => f.name);
  for(const e of ex){ const o = e.F.map(f => f.name); if(o.join('\u0001') !== order.join('\u0001')){ const miss = order.filter(n => !o.includes(n)), extra = o.filter(n => !order.includes(n));
      return {ok:false, why:`Line ${e.i + 1} ${miss.length ? 'is missing ' + miss.join(', ') : extra.length ? 'has ' + extra.join(', ') + ', which the first example does not' : 'has the same fields in a different order'}. Select the same fields, in the same order, in every example.`}; }
    for(let k = 1; k < e.F.length; k++) if(e.F[k].s < e.F[k - 1].e) return {ok:false, why:`On line ${e.i + 1}, ${e.F[k - 1].name} and ${e.F[k].name} overlap.`}; }
  const n = order.length, val = (e, k) => e.line.slice(e.F[k].s, e.F[k].e), gap = (e, k) => k === 0 ? e.line.slice(0, e.F[0].s) : k === n ? e.line.slice(e.F[n - 1].e) : e.line.slice(e.F[k - 1].e, e.F[k].s);
  const groups = [];
  for(let k = 0; k < n; k++){
    const vals = ex.map(e => val(e, k)), want = (S.types || {})[order[k]] || 'auto', next = ex.map(e => gap(e, k + 1)), nextCh = next[0][0] || '', prevCh = gap(ex[0], k).slice(-1);
    let type = want, src;
    if(want === 'custom' && S.custom && S.custom[order[k]]) src = S.custom[order[k]];
    else if(want !== 'auto' && want !== 'delim' && rxType(want)) src = rxType(want)[2];
    else {
      const g = want === 'auto' ? rxGuess(vals) : ''; if(g){ type = g; src = rxType(g)[2]; }
      else { type = 'delim';
        const quoted = prevCh === '"' && nextCh === '"', last = k === n - 1;
        if(quoted) src = vals.some(v => /\\"/.test(v)) ? '(?:[^"\\\\]|\\\\.)*' : '[^"]*';
        else if(nextCh && !/\s/.test(nextCh) && vals.every(v => !v.includes(nextCh))) src = '[^' + rxEsc(nextCh).replace(/^\\\//, '/') + '\\r\\n]+';
        else if(vals.every(v => !/\s/.test(v))) src = '\\S+';
        else if(last && next.every(g => !g.trim())) src = '.+';
        else src = '.+?'; } }
    groups.push({name:order[k], type, src, vals}); }
  /* assemble */
  const firstGap = ex.map(e => gap(e, 0)); let out = '';
  if(S.fromStart) out = '^' + rxGap(firstGap);
  else { const lead = rxLead(firstGap); out = lead != null ? lead : (rxType(groups[0].type) && rxType(groups[0].type)[5] ? '' : '^' + rxGap(firstGap)); if(lead == null && !out && /^\w/.test(ex[0].line.slice(ex[0].F[0].s))) out = '\\b'; }
  for(let k = 0; k < n; k++){ out += '(?<' + groups[k].name + '>' + groups[k].src + ')'; if(k < n - 1) out += rxGap(ex.map(e => gap(e, k + 1))); }
  /* a lazy last field needs something after it to stop at: the first word that follows in every example */
  const g = groups[n - 1]; if(/\.\+\?$|\.\*\?$/.test(g.src)){ const tail = ex.map(e => gap(e, n)), t = rxTok(tail[0]), stop = []; for(const x of t){ stop.push(x); if(rxTokKind(x) === 'w') break; }
    const st = stop.join(''); if(st && tail.every(s => s.startsWith(st))) out += rxGapOne(st); else { g.src = '.+'; out = out.replace(/\.\+\?\)$/, '.+)'); } }
  return {ok:true, src:out, groups, examples:ex.map(e => e.i)};
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
const RX = () => UI.rx || (UI.rx = {text:'', lines:[], fields:[], types:{}, custom:{}, fromStart:false, manual:null, exp:'js', show:'all', pend:null});
function rxSetText(t){ const S = RX(); S.text = String(t || ''); S.lines = S.text.replace(/\r\n?/g, '\n').split('\n').filter(l => l.trim()).slice(0, RX_MAX_LINES); S.fields = []; S.types = {}; S.custom = {}; S.manual = null; S.pend = null; }
function rxCurrent(){ const S = RX(); if(S.manual != null) return {ok:!!S.manual, manual:true, src:S.manual, groups:[...S.manual.matchAll(/\(\?<(\w+)>/g)].map(m => ({name:m[1], type:'custom', src:''}))}; return rxBuild(S); }
function rxRun(src, lines){ let re; try{ re = new RegExp(src, 'd'); }catch(e){ return {err:e.message}; } const M = lines.map(l => { const m = re.exec(l); return m ? {g:m.groups || {}, ix:m.indices && m.indices.groups || {}} : null; }); return {M, n:M.filter(Boolean).length}; }
function labRegex(){
  const S = RX();
  if(!S.lines.length) return `<div class="rx-in"><p class="t2" style="margin:0 0 10px">Paste log lines, select the parts you want and name them; the builder writes the regular expression, tries it on every line, and gives it to you for JavaScript, PCRE, Python, Grok, Splunk and KQL. Nothing leaves this browser and nothing is saved unless you save it as a parser.</p>
    <div class="field"><label for="rxText">Log lines</label><textarea id="rxText" rows="10" class="mono" spellcheck="false" placeholder="Nov  2 08:15:30 web01 sshd[1234]: Failed password for root from 203.0.113.7 port 51544 ssh2"></textarea></div>
    <div class="wrap"><button class="btn primary" data-act="rxGo">${ico('wand-sparkles','sm')}Start</button><button class="btn" data-act="rxFile">${ico('upload','sm')}Open a log file</button><button class="btn ghost" data-act="rxDemo">Try with sample SSH lines</button></div></div>
    <details class="rx-lib"><summary>Ready-made patterns for incident response</summary>${rxLibHtml()}</details>`;
  /* a pattern written by hand is checked before it is run: one that backtracks badly would freeze this page on the sample itself */
  const C = rxCurrent(), Sf = C.ok ? rxSafety(C.src, S.lines) : null, held = Sf && Sf.level === 'risky' && C.manual, R = C.ok && !held ? rxRun(C.src, S.lines) : null, ok = R && !R.err, n = ok ? R.n : 0, groups = C.ok ? C.groups : [];
  const names = [...new Set(S.fields.map(f => f.name))], col = nm => Math.max(0, names.indexOf(nm)) % 6;
  const shown = S.lines.map((l, i) => [l, i]).filter(([, i]) => !ok || S.show === 'all' || (S.show === 'hit' ? R.M[i] : !R.M[i])).slice(0, RX_SHOW);
  const lineHtml = (l, i) => { const ex = S.fields.filter(f => f.line === i).sort((a, b) => a.s - b.s), m = ok && R.M[i];
    /* the examples show what you selected; other lines show what the pattern pulls out */
    const spans = ex.length ? ex.map(f => [f.s, f.e, f.name, true]) : m ? Object.entries(m.ix).filter(([, v]) => v).map(([k, v]) => [v[0], v[1], k, false]).sort((a, b) => a[0] - b[0]) : [];
    let h = '', at = 0; for(const [s, e, nm, sel] of spans){ if(s < at) continue; h += esc(l.slice(at, s)) + `<mark class="rx-m c${col(nm)}${sel ? ' sel' : ''}" title="${esc(nm)}">${esc(l.slice(s, e))}</mark>`; at = e; } h += esc(l.slice(at));
    return `<div class="rx-ln${ok ? (m ? ' hit' : ' miss') : ''}${ex.length ? ' ex' : ''}" data-i="${i}"><span class="rx-no">${i + 1}</span><span class="rx-t">${h || ' '}</span>${ex.length ? `<button class="iconbtn xs" data-act="rxUnex" data-v="${i}" aria-label="Stop using line ${i + 1} as an example" title="Stop using this line as an example">${ico('x','sm')}</button>` : ''}</div>`; };
  const tbl = ok && n ? (() => { const G = groups.map(g => g.name), rows = R.M.map((m, i) => [m, i]).filter(([m]) => m).slice(0, 200);
    return `<div class="rx-tw"><table class="rx-tb"><thead><tr><th scope="col">Line</th>${G.map(g => `<th scope="col"><span class="rx-dot c${col(g)}"></span>${esc(g)}</th>`).join('')}</tr></thead><tbody>${rows.map(([m, i]) => `<tr><td class="t3">${i + 1}</td>${G.map(g => `<td class="mono">${esc(m.g[g] == null ? '' : m.g[g])}</td>`).join('')}</tr>`).join('')}</tbody></table></div>${n > 200 ? `<p class="t3 small">First 200 of ${n.toLocaleString()} matching lines.</p>` : ''}`; })() : '';
  return `<div class="rx">
    <div class="rx-bar"><span class="t2 small"><b>${S.lines.length.toLocaleString()}</b> line${S.lines.length === 1 ? '' : 's'}${S.lines.length >= RX_MAX_LINES ? ' (the first ' + RX_MAX_LINES.toLocaleString() + ')' : ''}</span><span style="flex:1"></span>
      <label class="rx-opt"><input type="checkbox" data-rx="fromStart"${S.fromStart ? ' checked' : ''}> Match from the start of the line</label>
      <button class="btn sm ghost" data-act="rxReset">${ico('refresh-cw','sm')}Other lines</button></div>
    <p class="t3 small rx-help">${S.fields.length ? 'Select more parts to add fields. To teach a variation, select the same fields on a line it misses.' : 'Select a part of a line — an IP address, a user name, a time — and name it.'}</p>
    <div class="rx-lines" id="rxLines" role="list" aria-label="Log lines">${shown.map(([l, i]) => lineHtml(l, i)).join('')}</div>
    ${S.pend ? `<form class="rx-pend" data-form="rxName"><span class="t2 small">Name <b class="mono">${esc(S.pend.v.length > 60 ? S.pend.v.slice(0, 58) + '…' : S.pend.v)}</b></span>
      <label class="sr" for="rxName">Field name</label><input id="rxName" class="inp sm mono" value="${esc(S.pend.name)}" maxlength="32" autocomplete="off" pattern="[A-Za-z_][A-Za-z0-9_]{0,31}">
      ${names.length ? `<span class="t3 small">or</span>${names.map(nm => `<button type="button" class="chip" data-act="rxPick" data-v="${esc(nm)}">${esc(nm)}</button>`).join('')}` : ''}
      <button class="btn sm primary" type="submit">Add field</button><button class="btn sm ghost" type="button" data-act="rxCancel">Cancel</button><span class="hint" id="rxNameHint"></span></form>` : ''}
    ${names.length ? `<section class="rx-sec"><h4>Fields</h4><div class="rx-fs">${names.map(nm => { const g = groups.find(x => x.name === nm), t = (S.types || {})[nm] || 'auto';
        return `<div class="rx-f"><span class="rx-dot c${col(nm)}"></span><b class="mono">${esc(nm)}</b><label class="sr" for="rxT-${esc(nm)}">What ${esc(nm)} is</label><select class="inp sm" id="rxT-${esc(nm)}" data-rx="type" data-name="${esc(nm)}"><option value="auto"${t === 'auto' ? ' selected' : ''}>Work it out${g && t === 'auto' ? ' — ' + esc(g.type === 'delim' ? 'up to the next delimiter' : (rxType(g.type) || [, g.type])[1]) : ''}</option><option value="delim"${t === 'delim' ? ' selected' : ''}>Up to the next delimiter</option>${RX_TYPES.map(x => `<option value="${x[0]}"${t === x[0] ? ' selected' : ''}>${esc(x[1])}</option>`).join('')}</select>
          <button class="iconbtn xs" data-act="rxDel" data-v="${esc(nm)}" aria-label="Remove ${esc(nm)}">${ico('x','sm')}</button></div>`; }).join('')}</div></section>` : ''}
    ${C.ok || C.manual ? `<section class="rx-sec"><div class="rx-sh"><h4>Pattern</h4>${C.manual ? '<span class="chip sq amber">edited by hand</span><button class="btn xs ghost" data-act="rxAuto">Back to the built pattern</button>' : '<button class="btn xs ghost" data-act="rxEdit">Edit by hand</button>'}</div>
      ${C.manual ? `<label class="sr" for="rxSrc">Pattern</label><textarea id="rxSrc" class="mono rx-src" rows="3" spellcheck="false">${esc(S.manual)}</textarea>` : `<pre class="rx-src mono" id="rxSrcView">${esc(C.src)}</pre>`}
      ${held ? `<div class="rx-stat"><span class="rx-safe risky">${ico('triangle-alert','sm')}Risky — not run</span></div><ul class="rx-notes">${Sf.notes.map(x => `<li>${esc(x)}</li>`).join('')}</ul>` : R && R.err ? `<p class="rx-err">${esc(R.err)}</p>` : ok ? `<div class="rx-stat"><b>${n.toLocaleString()}</b> of ${S.lines.length.toLocaleString()} lines match <div class="rx-meter" role="img" aria-label="${Math.round(n / S.lines.length * 100)} percent of lines match"><i style="width:${n / S.lines.length * 100}%"></i></div>
        <div class="seg" role="group" aria-label="Show lines">${[['all', 'All'], ['hit', 'Matched'], ['miss', 'Missed']].map(([k, l]) => `<button data-act="rxShow" data-v="${k}" aria-pressed="${S.show === k}">${l}</button>`).join('')}</div>
        <span class="rx-safe ${Sf.level}">${ico(Sf.level === 'safe' ? 'shield-check' : 'triangle-alert','sm')}${{safe:'Safe on hostile input', watch:'Watch', risky:'Risky', bad:'Invalid'}[Sf.level]}</span></div>
        ${Sf.notes.length ? `<ul class="rx-notes">${Sf.notes.map(x => `<li>${esc(x)}</li>`).join('')}</ul>` : ''}` : ''}
    </section>` : S.fields.length && !C.ok ? `<div class="note amber"><span class="ic">${ico('info','sm')}</span><div>${esc(C.why)}</div></div>` : ''}
    ${ok && n ? `<section class="rx-sec"><h4>What it pulls out</h4>${tbl}</section>
      <section class="rx-sec"><div class="rx-sh"><h4>Use it in</h4><div class="seg" role="tablist" aria-label="Format">${RX_EXPORTS.map(([k, l]) => `<button role="tab" data-act="rxExp" data-v="${k}" aria-selected="${S.exp === k}" aria-pressed="${S.exp === k}">${l}</button>`).join('')}</div></div>
        <pre class="rx-src mono" id="rxOut">${esc(rxExport(C.src, groups, S.exp))}</pre>
        <div class="wrap"><button class="btn sm" data-act="rxCopy">${ico('copy','sm')}Copy</button><button class="btn sm" data-act="rxSave">${ico('save','sm')}Save as a parser for log imports</button></div></section>` : ''}
    <details class="rx-lib"><summary>Ready-made patterns for incident response</summary>${rxLibHtml()}</details></div>`;
}
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
    const ex0 = S.fields.filter(f => f.line === S.fields[0].line).sort((a, b) => a.s - b.s), mine = S.fields.filter(f => f.line === i);
    if(S.fields.length && i !== S.fields[0].line && ex0[mine.length]) name = ex0[mine.length].name;
    S.pend = {line:i, s, e, v, name}; sel.removeAllRanges(); renderMain(); const inp = $('rxName'); if(inp){ inp.focus(); inp.select(); } }
}
document.addEventListener('mouseup', ev => { if(ev.target && ev.target.closest && ev.target.closest('#rxLines')) setTimeout(() => rxFromSel(false), 0); });
/* phones and tablets: a selection made by touch ends without a mouse-up; take it once it has stopped changing */
document.addEventListener('selectionchange', () => { clearTimeout(UI.rxSelT); UI.rxSelT = setTimeout(() => { const sel = getSelection(), n = sel && sel.anchorNode; if(n && n.parentElement && n.parentElement.closest('#rxLines') && matchMedia('(pointer: coarse)').matches) rxFromSel(true); }, 700); });
function rxNameSubmit(){ const S = RX(), nm = String($('rxName').value || '').trim(); if(!/^[A-Za-z_][A-Za-z0-9_]{0,31}$/.test(nm)) return fieldErr('rxName', 'Letters, digits and _ only, starting with a letter or _.'); rxAdd(nm); }
function rxAdd(nm){ const S = RX(), p = S.pend; if(!p) return; if(S.fields.some(f => f.line === p.line && f.name === nm)) return toast(`This line already has ${nm}`);
  S.fields.push({line:p.line, s:p.s, e:p.e, name:nm}); S.pend = null; S.manual = null; renderMain(); }
document.addEventListener('change', ev => { const el = ev.target; if(!el || !el.dataset || !el.dataset.rx) return; const S = RX();
  if(el.dataset.rx === 'fromStart'){ S.fromStart = el.checked; renderMain(); }
  if(el.dataset.rx === 'type'){ S.types[el.dataset.name] = el.value; S.manual = null; renderMain(); } });
document.addEventListener('input', ev => { if(ev.target && ev.target.id === 'rxSrc'){ RX().manual = ev.target.value; clearTimeout(UI.rxT); UI.rxT = setTimeout(() => { const el = $('rxSrc'), pos = el && el.selectionStart; renderMain(); const n = $('rxSrc'); if(n){ n.focus(); try{ n.setSelectionRange(pos, pos); }catch(e){} } }, 500); } });
const RX_DEMO = `Nov  2 08:15:30 web01 sshd[1234]: Failed password for root from 203.0.113.7 port 51544 ssh2
Nov  2 08:15:33 web01 sshd[1234]: Failed password for invalid user admin from 203.0.113.7 port 51560 ssh2
Nov  2 08:16:02 web01 sshd[1240]: Accepted password for deploy from 198.51.100.23 port 40022 ssh2
Nov 12 22:01:47 web02 sshd[88213]: Failed password for root from 2001:db8::7 port 6022 ssh2
Nov 12 22:01:50 web02 sshd[88213]: Accepted publickey for j.doe from 192.0.2.44 port 52111 ssh2: RSA SHA256:Zx9...
Nov 12 22:02:10 web02 sshd[88219]: Connection closed by 192.0.2.44 port 52111 [preauth]`;
const RX_ACTS = {
  rxGo:() => { const t = $('rxText') && $('rxText').value; if(!t || !t.trim()) return fieldErr('rxText', 'Paste some log lines first.'); rxSetText(t); renderMain(); },
  rxDemo:() => { rxSetText(RX_DEMO); renderMain(); },
  rxFile:() => { const i = document.createElement('input'); i.type = 'file'; i.accept = '.log,.txt,.csv,.json,.jsonl,text/*'; i.onchange = async () => { const f = i.files && i.files[0]; if(!f) return; if(f.size > 50 * 1048576) return toast('That file is over 50 MB — paste a sample of it instead');
      const t = await fileText(f.size > 5 * 1048576 ? f.slice(0, 5 * 1048576) : f); rxSetText(t); renderMain(); if(f.size > 5 * 1048576) toast('Read the first 5 MB'); }; i.click(); },
  rxReset:() => { UI.rx = null; renderMain(); },
  rxCancel:() => { RX().pend = null; renderMain(); },
  rxPick:(id, v) => rxAdd(v),
  rxDel:(id, v) => { const S = RX(); S.fields = S.fields.filter(f => f.name !== v); delete S.types[v]; S.manual = null; renderMain(); },
  rxUnex:(id, v) => { const S = RX(); S.fields = S.fields.filter(f => f.line !== +v); S.manual = null; renderMain(); },
  rxShow:(id, v) => { RX().show = v; renderMain(); },
  rxExp:(id, v) => { RX().exp = v; renderMain(); },
  rxEdit:() => { const S = RX(), C = rxBuild(S); S.manual = C.ok ? C.src : ''; renderMain(); const el = $('rxSrc'); if(el) el.focus(); },
  rxAuto:() => { RX().manual = null; renderMain(); },
  rxCopy:() => { const el = $('rxOut'); if(el) copyText(el.textContent); },
  rxLib:(id, v) => { const x = RX_LIB[+v]; if(x) copyText(x[1]); },
  rxSave:() => { const C = rxCurrent(); if(!C.ok) return; if(typeof parserDlg === 'function') parserDlg(null, {name:'Built: ' + C.groups.map(g => g.name).slice(0, 4).join(', '), re:C.src}); },
};
