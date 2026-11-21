/* ==========================================================================
   Regex builder engine — the parts that work on many lines at once:
   · records that span several lines (stack traces, Windows text exports,
     pretty-printed JSON): where a record starts, and the same setting for
     Logstash, Filebeat, Splunk and Fluent Bit
   · formats: mixed logs sorted into groups of lines written the same way
     (template mining, as Drain does), so each gets its own pattern
   · auto-parse: key=value, JSON, CSV/TSV, CEF, LEEF, syslog (RFC 3164 and
     5424), Apache/nginx, IIS W3C and "Key: value" exports, with the fields
     selected and named for you
   · the optimiser: rewrites tried one at a time, each kept only when it
     pulls out exactly the same values from every line, with its speed
     measured before and after
   Pure functions; the page is in regexb.js.
   ========================================================================== */

/* ---------- records over several lines ---------- */
/* [key, what a record starts with, pattern]. A timestamp form is used only when the lines in between do not start with a time of their own. */
const RX_STARTS = [
  ['iso', 'an ISO 8601 time', '^\\[?\\d{4}-\\d{2}-\\d{2}[T ]\\d{2}:\\d{2}'],
  ['syslog', 'a syslog time', '^(?:<\\d{1,3}>)?[A-Z][a-z]{2} +\\d{1,2} \\d{2}:\\d{2}:\\d{2}'],
  ['dmy', 'a date in numbers', '^\\[?\\d{1,4}[\\/.-]\\d{1,2}[\\/.-]\\d{1,4}[ T,]+\\d{1,2}:\\d{2}'],
  ['http', 'a client and a web-server time', '^\\S+ \\S+ \\S+ \\[\\d{2}\\/[A-Z][a-z]{2}\\/\\d{4}:'],
  ['epoch', 'a Unix time', '^\\[?1\\d{9}\\b'],
  ['level', 'a log level (INFO, ERROR…)', '^\\[?(?:TRACE|DEBUG|INFO|NOTICE|WARN(?:ING)?|ERROR|SEVERE|FATAL|CRITICAL)\\b'],
  ['json', 'an opening brace at the margin', '^\\{'],
  ['text', 'text at the margin (the rest is indented)', '^\\S']];
const RX_TIMEY = RX_STARTS.filter(x => !['json', 'text', 'level'].includes(x[0])).map(x => new RegExp(x[2]));
const RX_CONT = /^(?:\s|at |Caused by|Suppressed:|\.\.\. \d+ (?:more|common)|[}\])])/;
/* raw lines → {re, label, records, lines} when the lines are records spread over several lines, else null */
function rxRecordStart(L){
  if(!L || L.length < 3) return null;
  const cands = RX_STARTS.map(([k, label, re]) => ({k, label, re}));
  /* a Windows text export or any "Key: value" block: its first key starts each record */
  const m = /^([A-Za-z][\w .()-]{0,40}?):(?:[ \t]|$)/.exec(L[0]); if(m) cands.splice(cands.length - 2, 0, {k:'key', label:`“${m[1]}:”`, re:'^' + rxEsc(m[1]) + ':'});
  for(const c of cands){
    let R; try{ R = new RegExp(c.re); }catch(e){ continue; }
    const hit = L.map(l => R.test(l)), n = hit.filter(Boolean).length, cont = L.length - n;
    if(!hit[0] || n < 2 || !cont) continue;
    const others = L.filter((l, i) => !hit[i]);
    if(c.k === 'text' || c.k === 'json'){ if(!others.every(l => RX_CONT.test(l))) continue; }
    else if(c.k === 'key'){ if(cont < n) continue; }   /* a key block is several lines; one key per line is just a log */
    else if(others.some(l => RX_TIMEY.some(t => t.test(l)))) continue;   /* a line in between with its own time is a record of another kind */
    return {k:c.k, re:c.re, label:c.label, records:n, lines:L.length};
  }
  return null;
}
function rxJoin(L, re){ const R = new RegExp(re), out = []; let k = 0;
  for(const l of L){ if(!out.length || R.test(l) || k >= 500){ out.push(l); k = 1; } else { out[out.length - 1] += '\n' + l; k++; } }
  return out; }
/* the record start for the tools that read logs line by line */
function rxMlExport(re){
  const q = re.includes("'") ? '"' + re.replace(/"/g, '\\"') + '"' : "'" + re + "'", look = re.replace(/^\^/, '');
  return `# Logstash — input codec
codec => multiline {
  pattern => ${q}
  negate => true
  what => "previous"
}

# Filebeat — filestream input
parsers:
  - multiline:
      type: pattern
      pattern: '${re.replace(/'/g, "''")}'
      negate: true
      match: after

# Splunk — props.conf
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\\r\\n]+)(?=${look})

# Fluent Bit — parsers file
[MULTILINE_PARSER]
    name  osintrix_records
    type  regex
    rule  "start_state"  "/${re}/"  "cont"
    rule  "cont"         "/^(?!${look})/"  "cont"`;
}

/* ---------- formats ---------- */
/* a line as its template: quoted text and bracketed text with spaces as one token, numbers and long hex as #; split on spaces and on , ; | */
const rxMask = l => l.split('\n')[0].replace(/"(?:[^"\\]|\\.)*"/g, '"…"').replace(/\[[^\]\n]*\s[^\]\n]*\]/g, '[…]').split(/[\s,;|]+/).filter(Boolean).slice(0, 48)
  .map(t => t.length > 48 ? '<*>' : t.replace(/^([A-Za-z_][\w.-]*=).+$/, '$1…').replace(/[0-9A-Fa-f]{12,}/g, '#').replace(/\d+/g, '#'));
/* how alike two templates are: the share of their words (tokens with letters) they have in the same order — numbers and wildcards do not count, so a shared
   timestamp and host do not make two different messages one format */
const rxWordy = t => t !== '<*>' && /[A-Za-z]/.test(t);
function rxLcs(a, b){ const n = a.length, m = b.length; if(!n || !m) return 0; let prev = new Uint16Array(m + 1), cur = new Uint16Array(m + 1);
  for(let i = 1; i <= n; i++){ for(let j = 1; j <= m; j++) cur[j] = a[i - 1] === b[j - 1] && rxWordy(a[i - 1]) ? prev[j - 1] + 1 : Math.max(prev[j], cur[j - 1]); [prev, cur] = [cur, prev]; }
  return prev[m]; }
function rxSim(a, b){ const wa = a.filter(rxWordy).length, wb = b.filter(rxWordy).length, w = Math.max(wa, wb);
  if(!w) return a.join(' ') === b.join(' ') ? 1 : a.length === b.length ? .7 : 0;
  if(Math.abs(a.length - b.length) > 4) return 0;
  return rxLcs(a, b) / w; }
/* the template both share: tokens they agree on, <*> elsewhere (the longer one's shape) */
function rxMerge(a, b){
  if(a.length === b.length) return a.map((x, i) => x === b[i] ? x : '<*>');
  const [L, S] = a.length >= b.length ? [a, b] : [b, a], out = []; let j = 0;
  for(const x of L){ const k = S.indexOf(x, j); if(k >= 0 && k - j <= 4 && x !== '<*>'){ out.push(x); j = k + 1; } else out.push('<*>'); }
  return out; }
/* lines → [{tpl, lines:[index], name}], largest first */
function rxFormats(lines){
  const C = [], memo = new Map();
  lines.forEach((l, i) => {
    const t = rxMask(l), key = t.join(' ');
    let c = memo.get(key);
    if(!c){ let bs = 0; for(const x of C){ if(Math.abs(x.tpl.length - t.length) > 4) continue; const s = rxSim(x.tpl, t); if(s > bs){ bs = s; c = x; } }
      if(c && bs >= .6) c.tpl = rxMerge(c.tpl, t); else if(C.length < 150) C.push(c = {tpl:t, lines:[]}); else c = C[C.length - 1];
      if(memo.size < 20000) memo.set(key, c); }
    c.lines.push(i); });
  /* a second pass joins formats that turn out to be the same with a few words more or less */
  for(let i = 0; i < C.length; i++) for(let j = i + 1; j < C.length; j++){ const a = C[i], b = C[j];
    if(a.tpl[0] === b.tpl[0] && rxSim(a.tpl, b.tpl) >= .75){ a.tpl = rxMerge(a.tpl, b.tpl); a.lines = a.lines.concat(b.lines).sort((x, y) => x - y); C.splice(j, 1); j = i; } }
  /* formats whose fields have names (JSON, CSV, CEF, key=value, web logs, app logs…) are one format however their messages differ */
  for(const c of C){ const D = rxDetect(c.lines.map(i => lines[i]), lines); c.kind = D ? D.kind : ''; c.label = D ? D.label : ''; }
  for(let i = 0; i < C.length; i++) for(let j = i + 1; j < C.length; j++) if(C[i].kind && C[i].kind === C[j].kind && RX_ONE_FORMAT.has(C[i].kind)){ C[i].lines = C[i].lines.concat(C[j].lines).sort((x, y) => x - y); C[i].tpl = rxMerge(C[i].tpl, C[j].tpl); C.splice(j, 1); j--; }
  C.sort((a, b) => (a.kind === 'header') - (b.kind === 'header') || b.lines.length - a.lines.length || a.lines[0] - b.lines[0]);
  const used = new Set();
  for(const c of C){ const first = lines[c.lines[0]] || '';
    let nm = (/^\s*(?:<\d+>)?(?:\S+\s+){0,5}?([A-Za-z][\w.\/-]{1,24})(?:\[\d+\])?:\s/.exec(first) || [])[1];
    if(c.kind && c.kind !== 'syslog') nm = RX_KIND_NAME[c.kind] || c.kind;
    if(!nm || /^(?:[A-Z][a-z]{2}|T\d)$/.test(nm)) nm = 'format';
    nm = nm.toLowerCase().replace(/[^a-z0-9_]/g, '_').slice(0, 20); let k = nm, n = 2; while(used.has(k)) k = nm + '_' + n++; used.add(k); c.name = k; }
  return C;
}

/* ---------- auto-parse ---------- */
const RX_APPLOG = '^\\[?(?<time>\\d{4}-\\d{2}-\\d{2}[T ]\\d{2}:\\d{2}:\\d{2}(?:[.,]\\d+)?(?:Z|[+-]\\d{2}:?\\d{2})?|\\d{1,4}[\\/.-]\\d{1,2}[\\/.-]\\d{1,4}[ T]\\d{1,2}:\\d{2}:\\d{2}(?:[.,]\\d+)?)\\]?[ ,|]+\\[?(?<level>TRACE|DEBUG|INFO|NOTICE|WARN(?:ING)?|ERROR|SEVERE|FATAL|CRITICAL)\\]?[ :|]+(?:\\[(?<thread>[^\\]\\n]+)\\] +)?(?:(?<logger>[A-Za-z_$][\\w.$]*) +[-:] +)?(?<msg>\\S)';
const RX_ONE_FORMAT = new Set(['json', 'cef', 'leef', 'w3c', 'csv', 'combined', 'rfc5424', 'kv', 'colon', 'applog', 'header']);
const RX_KIND_NAME = {json:'json', cef:'cef', leef:'leef', w3c:'iis', csv:'csv', combined:'access_log', rfc5424:'syslog5424', kv:'kv', colon:'record', applog:'app_log', header:'header'};
const rxFieldName = s => { let n = String(s).replace(/[^A-Za-z0-9_]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 32) || 'field'; if(/^\d/.test(n)) n = 'f_' + n.slice(0, 29); return n; };
/* one line, one kind → [{s, e, name}] */
function rxSpansFor(line, kind, ctx){
  const out = [], add = (s, e, name) => { while(s < e && /\s/.test(line[s])) s++; while(e > s && /\s/.test(line[e - 1])) e--; if(e > s) out.push({s, e, name:rxFieldName(name)}); };
  const byRe = (re, names) => { const m = new RegExp(re, 'd').exec(line); if(!m) return false; names.forEach((n, i) => { const ix = m.indices[i + 1]; if(n && ix) add(ix[0], ix[1], n); }); return m; };
  const kv = (from, to, re, pre) => { const R = new RegExp(re, 'g'), seg = line.slice(from, to), K = [...seg.matchAll(R)];
    /* the words before the first pair (sudo's user, a firewall's [UFW BLOCK]) */
    if(pre && K.length){ let s = from, e = from + K[0].index; while(e > s && /[\s:;,|-]/.test(line[e - 1])) e--; while(s < e && /[\s:;,|-]/.test(line[s])) s++; if(e > s) add(s, e, pre); }
    K.forEach((m, j) => { const vs = from + m.index + m[0].length, ve = j + 1 < K.length ? from + K[j + 1].index : to; let s = vs, e = ve;
      while(e > s && /[\s,;]/.test(line[e - 1])) e--; if(line[s] === '"' && line[e - 1] === '"' && e - s >= 2){ s++; e--; } else if(line[s] === "'" && line[e - 1] === "'" && e - s >= 2){ s++; e--; }
      add(s, e, m[1]); }); return K.length; };
  if(kind === 'json'){ /* every value in objects, nested ones named by their path (actor_alternateId); lists are skipped */
    const st = []; let i = 0, wantKey = false, key = null;
    const inObj = () => st.length && st[st.length - 1].t === '{' && !st.some(x => x.t === '[');
    const path = k => st.map(x => x.k).filter(Boolean).concat(k).join('_');
    while(i < line.length){ const c = line[i];
      if(c === '"'){ let j = i + 1; while(j < line.length && line[j] !== '"'){ if(line[j] === '\\') j++; j++; }
        if(inObj()){ if(wantKey){ key = line.slice(i + 1, j); wantKey = false; } else if(key != null){ add(i + 1, j, path(key)); key = null; } }
        i = j + 1; continue; }
      if(c === '{' || c === '['){ st.push({t:c, k:c === '{' && st.length ? key : null}); key = null; wantKey = c === '{'; }
      else if(c === '}' || c === ']'){ st.pop(); key = null; }
      else if(c === ',' && inObj()){ wantKey = true; key = null; }
      else if(inObj() && key != null && /[-\d tfn]/.test(c)){ const m = /^(?:-?\d[\d.eE+-]*|true|false|null)/.exec(line.slice(i)); if(m){ add(i, i + m[0].length, path(key)); key = null; i += m[0].length; continue; } }
      i++; }
    return out; }
  if(kind === 'cef' || kind === 'leef'){ const at = line.search(kind === 'cef' ? /CEF:\d+\|/ : /LEEF:[\d.]+\|/); let p = at, parts = [];
    const head = kind === 'cef' ? ['cef_version', 'vendor', 'product', 'product_version', 'signature_id', 'name', 'severity'] : ['leef_version', 'vendor', 'product', 'product_version', 'event_id'];
    if(at > 0){ const pre = line.slice(0, at); const t = new RegExp('^(?:<\\d{1,3}>)?(?<time>' + rxType('syslogts')[2] + '|' + rxType('iso')[2] + ') (?<host>\\S+)', 'd').exec(pre); if(t){ add(t.indices.groups.time[0], t.indices.groups.time[1], 'time'); add(t.indices.groups.host[0], t.indices.groups.host[1], 'host'); } }
    p = line.indexOf(':', at) + 1;
    for(let k = 0; k < head.length; k++){ let q = p; while(q < line.length && line[q] !== '|'){ if(line[q] === '\\') q++; q++; } parts.push([p, q]); p = q + 1; }
    parts.forEach(([s, e], k) => add(s, e, head[k]));
    let sep = '\t', from = p;
    if(kind === 'leef' && /^LEEF:2/.test(line.slice(at))){ let q = from; while(q < line.length && line[q] !== '|') q++; const d = line.slice(from, q); if(q < line.length && d.length <= 4){ sep = /^x[0-9a-f]+$/i.test(d) ? String.fromCharCode(parseInt(d.slice(1), 16)) : d; from = q + 1; } }
    if(kind === 'cef') kv(from, line.length, '(?:^|\\s)([A-Za-z0-9_.\\[\\]-]{1,40})=');
    else if(line.slice(from).includes(sep)) kv(from, line.length, '(?:^|' + rxEsc(sep) + ')([A-Za-z0-9_.-]{1,40})=');
    else kv(from, line.length, '(?:^|\\s)([A-Za-z0-9_.-]{1,40})=');
    return out; }
  if(kind === 'w3c' || kind === 'csv'){ const names = ctx.names, d = ctx.delim; let i = 0, k = 0;
    while(i <= line.length && k < names.length){ let s = i, e;
      if(line[i] === '"'){ let j = i + 1; while(j < line.length){ if(line[j] === '"'){ if(line[j + 1] === '"'){ j += 2; continue; } break; } j++; } add(i + 1, j, names[k]); e = j + 1; }
      else { e = line.indexOf(d, i); if(e < 0) e = line.length; add(s, e, names[k]); }
      const nx = line.indexOf(d, e); i = nx < 0 ? line.length + 1 : nx + 1; k++; }
    return out; }
  if(kind === 'combined'){ byRe('^(\\S+) (\\S+) (\\S+) \\[([^\\]]+)\\] "(\\S+) (\\S+?)(?: (\\S+))?" (\\d{3}) (\\S+)(?: "([^"]*)" "([^"]*)")?', ['client_ip', '', 'user', 'time', 'method', 'path', 'protocol', 'status', 'bytes', 'referrer', 'user_agent']); return out; }
  if(kind === 'rfc5424'){ const m = byRe('^(?:<(\\d{1,3})>)?1 (\\S+) (\\S+) (\\S+) (\\S+) (\\S+) (?:-|\\[(.*?)\\])(?: (.*))?$', ['pri', 'time', 'host', 'app', 'procid', 'msgid', 'sd', '']);
    if(m && m[8] != null){ const ms = m.indices[8][0]; if(!kv(ms, line.length, '(?:^|\\s)([A-Za-z_][\\w.-]{0,40})=')) add(ms, line.length, 'message'); } return out; }
  /* inside a free-text message: the values in it — addresses, numbers after a word like port, the user after "user" or "for" — named from the word before them */
  const msgVars = (from, to) => { const T = [...line.slice(from, to).matchAll(/\S+/g)].map(m => ({s:from + m.index, e:from + m.index + m[0].length, t:m[0]})), got = [];
    const named = {from:'src_ip', by:'src_ip', src:'src_ip', to:'dst_ip', dst:'dst_ip', port:'port', pid:'pid', uid:'uid', user:'user', for:'user', account:'user', session:'session', id:'id', size:'size', code:'code'};
    for(let k = 0; k < T.length; k++){ const x = T[k], prev = (T[k - 1] && T[k - 1].t.toLowerCase().replace(/[^a-z]/g, '')) || '', v = x.t.replace(/[,;:.)\]]+$/, ''), e = x.s + v.length;
      const g = rxGuess([v]), nm = named[prev];
      if(['ipv4', 'ipv6', 'ip', 'email', 'url', 'uuid', 'hash', 'sid', 'mac'].includes(g)) got.push([x.s, e, nm && /ip$/.test(nm) ? nm : g === 'ipv4' || g === 'ipv6' ? 'ip' : rxType(g)[4]]);
      else if(/^\d+$/.test(v) && nm && !/ip$/.test(nm) && nm !== 'user') got.push([x.s, e, nm]);
      else if(nm === 'user' && /^[\w.$@\\-]+$/.test(v) && !(T[k + 1] && /^user$/i.test(T[k + 1].t)) && !/^(?:invalid|illegal|unknown|the|a)$/i.test(v)) got.push([x.s, e, 'user']); }
    const seen = new Set(); return got.filter(([, , n]) => { if(seen.has(n)) return false; seen.add(n); return true; }); };
  if(kind === 'syslog'){ const m = byRe('^(?:<(\\d{1,3})>)?(' + rxType('syslogts')[2] + '|' + rxType('iso')[2] + ') (\\S+) ([^:\\[\\s]+)(?:\\[(\\d+)\\])?: ?(.*)$', ['pri', 'time', 'host', 'program', 'pid', '']);
    if(m){ const ms = m.indices[6][0]; /* a firewall or audit message is key=value pairs: those are the fields */ if(!(/(?:^|\s)[A-Za-z_][\w.-]*=/.test(m[6]) && (m[6].match(/(?:^|\s)[A-Za-z_][\w.-]*=/g) || []).length >= 2 && kv(ms, line.length, '(?:^|\\s)([A-Za-z_][\\w.-]{0,40})=', 'text'))){ const V = msgVars(ms, line.length); if(V.length) V.forEach(([a, b, n]) => add(a, b, n)); else add(ms, line.length, 'message'); } }
    return out; }
  if(kind === 'applog'){ const m = new RegExp(RX_APPLOG, 'd').exec(line); if(!m) return out; const G = m.indices.groups;
    for(const n of ['time', 'level', 'thread', 'logger']) if(G[n]) add(G[n][0], G[n][1], n);
    const nl = line.indexOf('\n', G.msg[0]); add(G.msg[0], nl < 0 ? line.length : nl, 'message'); if(nl >= 0) add(nl + 1, line.length, 'detail');
    return out; }
  if(kind === 'kv'){ const t = new RegExp('^\\[?(' + rxType('iso')[2] + '|' + rxType('syslogts')[2] + '|' + rxType('datetime')[2] + ')', 'd').exec(line); let from = 0;
    if(t){ add(t.indices[1][0], t.indices[1][1], 'time'); from = t.indices[1][1]; }
    kv(from, line.length, '(?:^|[\\s,;|])([A-Za-z_][\\w.-]{0,40})=', 'text');
    return out; }
  if(kind === 'colon'){ const R = /^([ \t]*)([A-Za-z][\w .()\/-]{0,40}?):[ \t]+(\S[^\n]*?)[ \t]*$/gmd; let m;
    while((m = R.exec(line))) add(m.indices[3][0], m.indices[3][1], m[2]);
    return out; }
  return out;
}
/* what a group of lines is → {kind, label, ctx} or null */
function rxDetect(lines, all){
  const L = lines.slice(0, 40), share = f => L.filter(f).length / L.length;
  if(share(l => { const t = l.trim(); if(!/^\{[\s\S]*\}$/.test(t)) return false; try{ JSON.parse(t); return true; }catch(e){ return false; } }) >= .8) return {kind:'json', label:'JSON'};
  if(share(l => /CEF:\d+\|/.test(l)) >= .8) return {kind:'cef', label:'CEF'};
  if(share(l => /LEEF:[\d.]+\|/.test(l)) >= .8) return {kind:'leef', label:'LEEF'};
  if(L.every(l => /^#/.test(l))) return {kind:'header', label:'Header lines'};
  const fl = (all || []).find(l => /^#Fields:\s/.test(l));
  if(fl && share(l => !/^#/.test(l)) === 1){ const names = fl.replace(/^#Fields:\s*/, '').trim().split(/\s+/); if(share(l => l.split(' ').length === names.length) >= .8) return {kind:'w3c', label:'IIS / W3C extended', ctx:{names, delim:' '}}; }
  if(share(l => /^\S+ \S+ \S+ \[[^\]]+\] "[^"]*" \d{3} \S+/.test(l)) >= .8) return {kind:'combined', label:'Apache / nginx access log'};
  if(share(l => /^(?:<\d{1,3}>)?1 \d{4}-\d{2}-\d{2}T\S+ \S+ \S+ \S+ \S+ (?:-|\[)/.test(l)) >= .8) return {kind:'rfc5424', label:'Syslog (RFC 5424)'};
  if(share(l => new RegExp('^(?:<\\d{1,3}>)?(?:' + rxType('syslogts')[2] + '|' + rxType('iso')[2] + ') \\S+ [^:\\[\\s]+(?:\\[\\d+\\])?: ').test(l)) >= .8) return {kind:'syslog', label:'Syslog'};
  /* CSV / TSV: a header line in the file and the same number of separators on every line */
  for(const d of ['\t', ',', ';', '|']){ const head = (all || lines)[0] || '', n = head.split(d).length - 1;
    if(L.every(l => l === head)) { if(n >= 2 && !/\d{2}/.test(head)) return {kind:'header', label:'Header line'}; continue; }
    if(n >= 2 && /^[\w "().\/-]+$/.test(head.split(d).join('')) && !/\d{2}/.test(head) && share(l => l.split(d).length - 1 >= n) >= .9) return {kind:'csv', label:d === '\t' ? 'TSV' : 'CSV (' + (d === ',' ? 'comma' : d === ';' ? 'semicolon' : 'pipe') + ')', ctx:{names:head.split(d).map(x => x.replace(/^"|"$/g, '').trim() || 'column'), delim:d, head}}; }
  if(share(l => new RegExp(RX_APPLOG).test(l)) >= .8) return {kind:'applog', label:'Application log (time, level, message)'};
  if(share(l => (l.match(/(?:^|[\s,;|])[A-Za-z_][\w.-]{0,40}=/g) || []).length >= 2) >= .8) return {kind:'kv', label:'key=value'};
  if(share(l => (l.match(/^[ \t]*[A-Za-z][\w .()\/-]{0,40}?:[ \t]+\S/gm) || []).length >= 3) >= .8) return {kind:'colon', label:'“Key: value” lines'};
  return null;
}
/* the example lines for a format: the first line; then, while the pattern built from them misses a line of the format, that line too —
   so a quoted value, an extra key or an empty field is learnt the way you would teach it by hand (up to six examples) */
function rxAutoFields(S, idx){
  const lines = idx.map(i => S.lines[i]), D = rxDetect(lines, S.lines); if(!D || D.kind === 'header') return D && {kind:D.kind, label:D.label, fields:[]};
  const dedupe = sp => { const c = {}; return sp.map(f => { c[f.name] = (c[f.name] || 0) + 1; return c[f.name] > 1 ? {...f, name:(f.name + '_' + c[f.name]).slice(0, 32)} : f; }); };
  const spans = i => (D.ctx && D.ctx.head === S.lines[i]) || (D.kind === 'w3c' && /^#/.test(S.lines[i])) ? [] : dedupe(rxSpansFor(S.lines[i], D.kind, D.ctx || {})).slice(0, 40);
  const cand = idx.filter(i => !(D.ctx && D.ctx.head === S.lines[i]) && !/^#/.test(D.kind === 'w3c' ? S.lines[i] : '')), fields = [];
  const first = cand.find(i => spans(i).length); if(first == null) return null;
  spans(first).forEach(f => fields.push({line:first, ...f}));
  const seen = new Set(fields.map(f => f.name));
  for(let round = 0; round < 5; round++){
    const C = rxBuild({lines:S.lines, fields, types:{}}); let re = null; try{ if(C.ok) re = new RegExp(C.src); }catch(e){}
    /* a line the pattern misses, or one with a field the examples do not have yet */
    const used = new Set(fields.map(f => f.line));
    const next = cand.slice(0, 3000).find(i => !used.has(i) && (re ? !re.test(S.lines[i]) : true) && spans(i).length) ?? cand.slice(0, 600).find(i => !used.has(i) && spans(i).some(f => !seen.has(f.name)));
    if(next == null) break;
    const sp = spans(next), trial = fields.concat(sp.map(f => ({line:next, ...f}))), T = rxBuild({lines:S.lines, fields:trial, types:{}});
    if(!T.ok) break;   /* fields in another order: this line stays a miss for you to look at */
    sp.forEach(f => { fields.push({line:next, ...f}); seen.add(f.name); }); }
  return {kind:D.kind, label:D.label, fields};
}

/* ---------- optimiser ---------- */
/* lines tested per second: the sample repeated until a run takes long enough to time, best of three */
function rxBench(re, lines){
  const L = lines.length ? lines : [''], run = r => { const t = performance.now(); for(let k = 0; k < r; k++) for(const l of L) re.test(l); return performance.now() - t; };
  let reps = 1, ms = run(1); while(ms < 20 && reps < 1 << 14){ reps *= 4; ms = run(reps); }
  const best = Math.min(ms, run(reps), run(reps)); return L.length * reps / Math.max(best, .001) * 1000; }
/* two patterns are the same for these lines when they match the same lines and pull out the same values */
function rxSame(a, b, lines){ let A, B; try{ A = new RegExp(a); B = new RegExp(b); }catch(e){ return false; }
  for(const l of lines){ const x = A.exec(l), y = B.exec(l); if(!x !== !y) return false; if(x && JSON.stringify(x.groups || {}) !== JSON.stringify(y.groups || {})) return false; }
  return true; }
/* a pattern as atoms: escapes, classes, groups opened and closed, single characters — each with its quantifier */
function rxAtoms(src){ const A = []; let i = 0;
  while(i < src.length){ let j = i;
    if(src[j] === '\\'){ j += 2; }
    else if(src[j] === '['){ j++; if(src[j] === '^') j++; if(src[j] === ']') j++; while(j < src.length && src[j] !== ']'){ if(src[j] === '\\') j++; j++; } j++; }
    else if(src[j] === '('){ j++; if(src[j] === '?'){ j++; if(src[j] === '<' && /[\w]/.test(src[j + 1])){ while(j < src.length && src[j] !== '>') j++; j++; } else j++; } A.push({t:src.slice(i, j), open:true}); i = j; continue; }
    else j++;
    const q = /^(?:[*+?]|\{\d+(?:,\d*)?\})[?+]?/.exec(src.slice(j)); if(q) j += q[0].length;
    A.push({t:src.slice(i, j)}); i = j; }
  return A; }
const rxIsWs = t => /^(?: [+*]?|\\s[+*]?|\[ \\t\][+*]?)$/.test(t);
/* the steps, each a rewrite of the whole pattern or null */
const RX_OPT = [
  {k:'anchor', title:'Tied to the start of the line', why:'A pattern that can start anywhere is tried at every position of every line that does not match. Tied to the line start with ^, a line that does not match is given up after a few characters.', alt:true},
  {k:'factor', title:'Shared start of alternatives taken out', why:'(?:Accepted password|Accepted publickey) makes the engine read “Accepted ” once per alternative; Accepted (?:password|publickey) reads it once.',
   f:src => { let changed = false;
     const out = src.replace(/\(\?:((?:[^()|\\]|\\.)+(?:\|(?:[^()|\\]|\\.)+)+)\)(\??)(?![*+{?])/g, (all, body, q) => {
       if(/\[[^\]]*\|/.test(body)) return all; const alts = body.split(/(?<!\\)\|/).map(rxAtoms); if(alts.some(a => a.some(x => x.open))) return all;
       let p = 0; while(alts.every(a => p < a.length - 1 && a[p].t === alts[0][p].t)) p++; while(p > 0 && !rxIsWs(alts[0][p - 1].t)) p--;
       let s = 0; while(alts.every(a => s < a.length - 1 - p && a[a.length - 1 - s].t === alts[0][alts[0].length - 1 - s].t)) s++; while(s > 0 && !rxIsWs(alts[0][alts[0].length - s].t)) s--;
       if(!p && !s){ /* no start shared by all: alternatives that share a start are put together, Failed password for(?: invalid user)? */
         const G = new Map(); for(const x of alts){ const k = x[0].t; if(!G.has(k)) G.set(k, []); G.get(k).push(x); }
         if(G.size === alts.length) return all;
         const part = [...G.values()].map(g => { if(g.length < 2) return g[0].map(x => x.t).join('');
           let q = 0; while(g.every(x => q < x.length && x[q].t === g[0][q].t)) q++;
           while(q > 0 && !g.every(x => q === x.length || rxIsWs(x[q].t))) q--;
           if(!q) return g.map(x => x.map(y => y.t).join('')).join('|');
           const rest = [...new Set(g.map(x => x.slice(q).map(y => y.t).join('')))], non = rest.filter(Boolean).sort((u, v) => v.length - u.length);
           return g[0].slice(0, q).map(y => y.t).join('') + (non.length ? '(?:' + non.join('|') + ')' + (rest.includes('') ? '?' : '') : ''); });
         if(part.length === alts.length && part.every((x, i) => x === alts[i].map(y => y.t).join(''))) return all;
         changed = true; return '(?:' + part.join('|') + ')' + q; }
       changed = true;
       const mid = alts.map(a => a.slice(p, a.length - s).map(x => x.t).join(''));
       return (q ? '(?:' : '') + alts[0].slice(0, p).map(x => x.t).join('') + '(?:' + mid.join('|') + ')' + alts[0].slice(alts[0].length - s).map(x => x.t).join('') + (q ? ')?' : ''); });
     return changed ? out : null; }},
  {k:'class', title:'Single-character alternatives made a character class', why:'(?:a|b|c) is tried one alternative at a time; [abc] is one lookup.',
   f:src => { let changed = false; const out = src.replace(/\(\?:((?:\\[^bB]|[^()|\\\[\].])(?:\|(?:\\[^bB]|[^()|\\\[\].]))+)\)/g, (all, body) => { changed = true; return '[' + body.split('|').map(c => c === ']' || c === '^' || c === '-' ? '\\' + c : c).join('') + ']'; }); return changed ? out : null; }},
  {k:'unroll', title:'Quoted text read in one pass', why:'(?:[^"\\\\]|\\\\.)* tries an alternative for every character; [^"\\\\]*(?:\\\\.[^"\\\\]*)* (an “unrolled loop”) reads plain characters in one run and stops only at a backslash.',
   f:src => { const a = '(?:[^"\\\\]|\\\\.)*'; return src.includes(a) ? src.split(a).join('[^"\\\\]*(?:\\\\.[^"\\\\]*)*') : null; }},
  {k:'lazy', title:'Wildcards replaced by exact character classes', why:'A lazy .*? or .+? goes forward one character at a time and checks the rest of the pattern after each; [^X]* runs straight to the next X. Each one is changed only where the values stay the same.', multi:true},
  {k:'prefilter', title:'A fixed word checked first', why:'A word every match contains, looked for before anything else, lets lines without it be skipped in one fast scan.',
   f:src => { if(src[0] !== '^' || /^\^\(\?=/.test(src)) return null; const A = rxAtoms(src.replace(/^\^/, '')); if(A.length && !/^[\\\[(.]/.test(A[0].t)) return null;   /* already starts with a fixed character */
     let best = '', cur = '', d = 0; for(const x of A){ if(x.open){ d++; cur = ''; continue; } if(x.t[0] === ')' ){ d = Math.max(0, d - 1); cur = ''; continue; }
       if(!d && /^(?:[A-Za-z0-9_ =:@-]|\\[.\/\[\]()-])$/.test(x.t)){ cur += x.t.length === 2 ? x.t[1] : x.t; if(cur.replace(/\W/g, '').length > best.replace(/\W/g, '').length) best = cur; } else cur = ''; }
     best = best.trim(); if(best.replace(/\W/g, '').length < 4) return null;
     return (src[0] === '^' ? '^' : '') + '(?=[^\\n]*?' + rxEsc(best) + ')' + src.replace(/^\^/, ''); }}];
/* the lazy wildcards in a pattern that have a fixed character after them: [{at, len, next}] */
function rxLazySpots(src){ const A = rxAtoms(src), out = []; let at = 0;
  for(let i = 0; i < A.length; i++){ const t = A[i].t; let k = i + 1; while(A[k] && A[k].t === ')') k++; const n = A[k] && A[k].t;
    if((t === '.*?' || t === '.+?') && n){ let c = null; const m = /^(\\[^\w\s]|[^\\()\[\]{}.*+?^$|])$/.exec(n);
      if(m) c = n.length === 2 ? n[1] : n; else if(/^ [+*]?$/.test(n)) c = ' ';
      if(c != null) out.push({at, len:t.length, c, plus:t === '.+?'}); }
    at += t.length; }
  return out; }
function rxOptimise(src, lines, alts){
  const sample = lines.slice(0, 2000), bench = s => { try{ return rxBench(new RegExp(s), sample); }catch(e){ return 0; } };
  let cur = src, speed = bench(cur); const start = speed, steps = [];
  for(const O of RX_OPT){
    let cand = null, detail = '';
    if(O.multi){ /* each wildcard on its own: kept where it changes nothing */
      let s = cur, n = 0; for(const sp of rxLazySpots(cur).reverse()){ const cls = sp.c === ' ' ? '[^ \\r\\n]' : '[^' + (sp.c === ']' || sp.c === '\\' || sp.c === '^' || sp.c === '-' ? '\\' + sp.c : sp.c) + '\\r\\n]';
        const t = s.slice(0, sp.at) + cls + (sp.plus ? '+' : '*') + s.slice(sp.at + sp.len); if(rxSame(s, t, lines)){ s = t; n++; } }
      if(n){ cand = s; detail = n + ' wildcard' + (n === 1 ? '' : 's'); } }
    else if(O.alt){ const a = (alts || []).find(x => x.k === O.k); if(a && a.src && a.src !== cur && !/^\^/.test(cur)) cand = a.src; }
    else cand = O.f(cur);
    if(!cand || cand === cur){ steps.push({k:O.k, title:O.title, why:O.why, state:'none'}); continue; }
    if(!rxSame(cur, cand, lines)){ steps.push({k:O.k, title:O.title, why:O.why, state:'differs', before:cur, after:cand}); continue; }
    const sp = bench(cand), gain = speed ? sp / speed - 1 : 0;
    /* a rewrite that only tightens the pattern is kept unless it is slower; one made only for speed must be clearly faster */
    const keep = O.k === 'lazy' || O.k === 'factor' || O.k === 'class' || O.k === 'unroll' ? gain > -.25 : gain > .1;
    steps.push({k:O.k, title:O.title, why:O.why, state:keep ? 'kept' : 'slower', before:cur, after:cand, from:speed, to:sp, detail});
    if(keep){ cur = cand; speed = sp; } }
  return {src:cur, from:src, start, end:speed, steps};
}

/* ---------- every format at once ---------- */
function rxExportAll(P, kind){
  const js = s => '/' + s.replace(/(^|[^\\])\//g, '$1\\/') + '/';
  if(kind === 'js') return `const patterns = {\n${P.map(p => `  ${p.name}: ${js(p.src)},`).join('\n')}\n};\n// the first that matches wins\nfor (const [format, re] of Object.entries(patterns)) {\n  const m = re.exec(line);\n  if (m) { fields = { format, ...m.groups }; break; }\n}`;
  if(kind === 'pcre') return P.map(p => `# ${p.name}\n${p.src}`).join('\n\n');
  if(kind === 'python') return `import re\n\nPATTERNS = {\n${P.map(p => `    ${JSON.stringify(p.name)}: re.compile(r${(x => x.includes("'") ? '"' + x + '"' : "'" + x + "'")(p.src.replace(/\(\?<(\w+)>/g, '(?P<$1>'))}),`).join('\n')}\n}\n\ndef parse(line):\n    for fmt, rx in PATTERNS.items():\n        m = rx.search(line)\n        if m:\n            return {"format": fmt, **m.groupdict()}\n    return None`;
  if(kind === 'grok'){ const G = P.map(p => rxExport(p.src, p.groups, 'grok')); return `filter {\n  grok {\n    match => { "message" => [\n${G.map(g => '      ' + (g.includes("'") ? '"' + g.replace(/"/g, '\\"') + '"' : "'" + g + "'")).join(',\n')}\n    ] }\n    break_on_match => true\n  }\n}`; }
  if(kind === 'splunk') return P.map(p => `| rex field=_raw "${p.src.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`).join('\n') + `\n| table ${[...new Set(P.flatMap(p => [...p.src.matchAll(/\(\?<(\w+)>/g)].map(m => m[1])))].join(' ')}`;
  if(kind === 'kql'){ const v = s => '@"' + s.replace(/\(\?<\w+>/g, '(').replace(/"/g, '""') + '"', names = [...new Set(P.flatMap(p => [...p.src.matchAll(/\(\?<(\w+)>/g)].map(m => m[1])))];
    const fmt = `| extend format = case(\n${P.map(p => `    RawData matches regex ${v(p.src)}, "${p.name}",`).join('\n')}\n    "other")`;
    const fld = names.map(n => { const has = P.map(p => [p, [...p.src.matchAll(/\(\?<(\w+)>/g)].map(m => m[1]).indexOf(n)]).filter(([, i]) => i >= 0);
      return `    ${n} = case(${has.map(([p, i]) => `format == "${p.name}", extract(${v(p.src)}, ${i + 1}, RawData)`).join(', ')}, "")`; });
    return `// RawData: the column holding the raw line (Syslog: SyslogMessage, custom tables: RawData)\n${fmt}\n| extend\n${fld.join(',\n')}\n| where format != "other"`; }
  return P.map(p => p.src).join('\n');
}
