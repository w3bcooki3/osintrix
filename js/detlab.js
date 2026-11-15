/* ==========================================================================
   Detection lab — build, test and harden rules. Works on your rules and
   evidence only, so it never needs a daily update.
     · Queries: any Sigma rule as Splunk SPL, Microsoft Defender XDR / Sentinel
       KQL, Elastic ES|QL and QRadar AQL, with field names you can remap
     · Tests: sample events a rule must fire on and must not fire on, kept with
       the rule and re-run on every save (a failing test warns you)
     · Evasion check: a matching event changed the way attackers change it —
       renamed binary, letter case, ^ and quotes, other flag dashes, extra spaces,
       environment variables, short paths — and which changes slip past the rule,
       with the fix for each
     · Events → rule: select events in a timeline and get a draft Sigma rule
       from what they share, checked against all your other evidence for noise
   ========================================================================== */

/* ---------- reading a Sigma rule ---------- */
function sigmaLogsource(code){
  const L = {}, m = String(code).match(/^logsource\s*:\s*\n((?:[ \t]+.*\n?)+)/m);
  if(m) for(const l of m[1].split('\n')){ const x = l.match(/^\s+(category|product|service)\s*:\s*['"]?([\w-]+)/); if(x) L[x[1]] = x[2].toLowerCase(); }
  return L;
}
/* the condition as a tree: {op:'and'|'or', a, b} | {op:'not', a} | {sel:name} | {of:'all'|'1', pat} */
function sigmaCondTree(cond){
  const toks = String(cond).match(/\(|\)|\band\b|\bor\b|\bnot\b|\b(?:1|all|any)\s+of\s+[\w*]+|[\w*]+/gi) || []; let i = 0;
  const atom = () => { const t = toks[i++]; if(t === '('){ const v = or(); i++; return v; } if(/^not$/i.test(t)) return {op:'not', a:atom()};
    const m = t && t.match(/^(1|all|any)\s+of\s+([\w*]+)$/i); if(m) return {of:m[1].toLowerCase() === 'all' ? 'all' : '1', pat:m[2]}; return {sel:t}; };
  const and = () => { let v = atom(); while(/^and$/i.test(toks[i] || '')){ i++; v = {op:'and', a:v, b:atom()}; } return v; };
  const or = () => { let v = and(); while(/^or$/i.test(toks[i] || '')){ i++; v = {op:'or', a:v, b:and()}; } return v; };
  return toks.length ? or() : null;
}

/* ---------- query backends ---------- */
const DL_BACK = {
  splunk:{name:'Splunk SPL', lang:'spl'}, kql:{name:'Microsoft Defender XDR (KQL)', lang:'kql'}, sentinel:{name:'Microsoft Sentinel — Sysmon / SecurityEvent (KQL)', lang:'kql'},
  esql:{name:'Elastic ES|QL (ECS)', lang:'esql'}, aql:{name:'IBM QRadar AQL', lang:'aql'},
};
/* Sigma field → field in each product. Unknown fields pass through as written. */
const DL_FMAP = {
  kql:{Image:'FolderPath', CommandLine:'ProcessCommandLine', ParentImage:'InitiatingProcessFolderPath', ParentCommandLine:'InitiatingProcessCommandLine', OriginalFileName:'ProcessVersionInfoOriginalFileName',
    User:'AccountName', Hashes:'SHA256', sha256:'SHA256', md5:'MD5', sha1:'SHA1', TargetFilename:'FolderPath', DestinationIp:'RemoteIP', DestinationPort:'RemotePort', DestinationHostname:'RemoteUrl', SourceIp:'LocalIP',
    TargetObject:'RegistryKey', Details:'RegistryValueData', QueryName:'RemoteUrl', ImageLoaded:'FolderPath', Computer:'DeviceName', Company:'ProcessVersionInfoCompanyName', Product:'ProcessVersionInfoProductName', Description:'ProcessVersionInfoFileDescription', IntegrityLevel:'ProcessIntegrityLevel', CurrentDirectory:'ProcessCurrentWorkingDirectory'},
  esql:{Image:'process.executable', CommandLine:'process.command_line', ParentImage:'process.parent.executable', ParentCommandLine:'process.parent.command_line', OriginalFileName:'process.pe.original_file_name',
    User:'user.name', Hashes:'process.hash.sha256', TargetFilename:'file.path', DestinationIp:'destination.ip', DestinationPort:'destination.port', DestinationHostname:'destination.domain', SourceIp:'source.ip', SourcePort:'source.port',
    TargetObject:'registry.path', Details:'registry.data.strings', QueryName:'dns.question.name', ImageLoaded:'dll.path', Computer:'host.name', EventID:'event.code', Company:'process.pe.company', Product:'process.pe.product', Description:'process.pe.description', IntegrityLevel:'winlog.event_data.IntegrityLevel', CurrentDirectory:'process.working_directory'},
  aql:{Image:'Process Path', CommandLine:'Process CommandLine', ParentImage:'Parent Process Path', ParentCommandLine:'Parent Process CommandLine', OriginalFileName:'Original File Name', User:'username', Hashes:'SHA256 Hash',
    TargetFilename:'Filename', DestinationIp:'destinationip', DestinationPort:'destinationport', SourceIp:'sourceip', SourcePort:'sourceport', DestinationHostname:'Destination Host Name', QueryName:'DNS Query', TargetObject:'Registry Key', Details:'Registry Value Data', Computer:'Machine Identifier', EventID:'EventID'},
  sentinel:{Computer:'Computer', EventID:'EventID'},
  splunk:{},
};
const DL_TABLE = {
  kql:{process_creation:'DeviceProcessEvents', network_connection:'DeviceNetworkEvents', file_event:'DeviceFileEvents', file_change:'DeviceFileEvents', file_delete:'DeviceFileEvents', registry_set:'DeviceRegistryEvents', registry_event:'DeviceRegistryEvents', registry_add:'DeviceRegistryEvents', registry_delete:'DeviceRegistryEvents', image_load:'DeviceImageLoadEvents', dns_query:'DeviceEvents\n| where ActionType == "DnsQueryResponse"'},
  sysmon:{process_creation:1, network_connection:3, process_termination:5, driver_load:6, image_load:7, create_remote_thread:8, raw_access_thread:9, process_access:10, file_event:11, registry_add:12, registry_delete:12, registry_set:13, registry_rename:14, registry_event:'(12,13,14)', create_stream_hash:15, pipe_created:17, wmi_event:'(19,20,21)', dns_query:22, file_delete:23, clipboard_change:24, process_tampering:25},
  ecs:{process_creation:'process', network_connection:'network', file_event:'file', file_change:'file', file_delete:'file', registry_set:'registry', registry_event:'registry', registry_add:'registry', registry_delete:'registry', image_load:'library', dns_query:'network'},
};
const dlFmap = b => Object.assign({}, DL_FMAP[b] || {}, ((DB.prefs.fmap || {})[b]) || {});
function dlField(b, name){ const M = dlFmap(b); return M[name] || M[Object.keys(M).find(k => k.toLowerCase() === name.toLowerCase())] || name; }
/* one value of one field, in one backend */
function dlValue(b, field, mods, x){
  const F = dlField(b, field), raw = String(x), wild = !mods.includes('re') && /[*?]/.test(raw);
  const pos = mods.includes('contains') ? 'c' : mods.includes('startswith') ? 's' : mods.includes('endswith') ? 'e' : 'x';
  if(raw === 'null'){ return {splunk:`NOT ${F}=*`, kql:`isempty(${F})`, sentinel:`isempty(${F})`, esql:`${F} IS NULL`, aql:`"${F}" IS NULL`}[b]; }
  if(mods.includes('cidr')) return {splunk:`cidrmatch("${raw}", ${F})`, kql:`ipv4_is_in_range(${F}, "${raw}")`, sentinel:`ipv4_is_in_range(${F}, "${raw}")`, esql:`CIDR_MATCH(${F}, "${raw}")`, aql:`INCIDR('${raw}', "${F}")`}[b];
  if(b === 'splunk'){ const v = raw.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\?/g, '*');
    if(mods.includes('re')) return `match(${F}, "(?i)${raw.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}")`;
    return `${F}="${pos === 'c' ? '*' + v + '*' : pos === 's' ? v + '*' : pos === 'e' ? '*' + v : v}"`; }
  if(b === 'kql' || b === 'sentinel'){ const q = s => '"' + s.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
    if(mods.includes('re')) return `${F} matches regex ${q('(?i)' + raw)}`;
    if(wild){ const rx = '(?i)' + (pos === 'c' || pos === 'e' ? '' : '^') + raw.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + (pos === 'c' || pos === 's' ? '' : '$'); return `${F} matches regex ${q(rx)}`; }
    return `${F} ${pos === 'c' ? 'contains' : pos === 's' ? 'startswith' : pos === 'e' ? 'endswith' : '=~'} ${q(raw)}`; }
  if(b === 'esql'){ const q = s => '"' + s.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
    if(mods.includes('re')) return `${F} RLIKE ${q(raw)}`;
    const v0 = raw.toLowerCase(); if(pos === 'x' && !wild) return `TO_LOWER(${F}) == ${q(v0)}`;
    const v = v0.replace(/\\/g, '\\\\');   // LIKE treats \ as its escape character, so a literal backslash is written twice
    return `TO_LOWER(${F}) LIKE ${q(pos === 'c' ? '*' + v + '*' : pos === 's' ? v + '*' : pos === 'e' ? '*' + v : v)}`; }
  if(b === 'aql'){ const q = s => "'" + s.replace(/'/g, "''") + "'";
    if(mods.includes('re')) return `"${F}" IMATCHES ${q(raw)}`;
    const v = raw.replace(/\\/g, '\\\\').replace(/%/g, '\\%').replace(/_/g, '\\_').replace(/\*/g, '%').replace(/\?/g, '_');
    return `"${F}" ILIKE ${q(pos === 'c' ? '%' + v + '%' : pos === 's' ? v + '%' : pos === 'e' ? '%' + v : v)}`; }
}
function dlSel(b, sel){
  const AND = b === 'splunk' ? ' ' : b === 'aql' ? ' AND ' : b === 'esql' ? ' AND ' : ' and ', OR = b === 'kql' || b === 'sentinel' ? ' or ' : ' OR ';
  const parts = [];
  for(const {f:key, vals} of sel.fields){ const [name, ...mods] = key.split('|'), V = sigmaVals(vals, mods.filter(m => m !== 'base64' && m !== 'base64offset')).concat(mods.some(m => /^base64/.test(m)) ? sigmaVals(vals, mods) : []);
    const xs = (mods.some(m => /^base64/.test(m)) ? sigmaVals(vals, mods) : V).map(x => dlValue(b, name, mods.some(m => /^base64/.test(m)) ? [...mods, 'contains'] : mods, x));
    parts.push(xs.length === 1 ? xs[0] : '(' + xs.join(mods.includes('all') ? AND : OR) + ')'); }
  for(const k of sel.keywords){ const v = String(k); parts.push(b === 'splunk' ? '"' + v.replace(/"/g, '\\"') + '"' : b === 'kql' || b === 'sentinel' ? '* contains "' + v.replace(/"/g, '\\"') + '"' : b === 'esql' ? 'TO_LOWER(message) LIKE "*' + v.toLowerCase().replace(/"/g, '\\"') + '*"' : `UTF8(payload) ILIKE '%${v.replace(/'/g, "''")}%'`); }
  if(sel.keywords.length && !sel.fields.length && parts.length > 1) return '(' + parts.join(OR) + ')';
  return parts.length > 1 ? '(' + parts.join(AND) + ')' : parts[0] || 'true';
}
function dlCond(b, P, T){
  const AND = b === 'splunk' ? ' ' : b === 'kql' || b === 'sentinel' ? ' and ' : ' AND ', OR = b === 'kql' || b === 'sentinel' ? ' or ' : ' OR ', NOT = b === 'kql' || b === 'sentinel' ? 'not' : 'NOT';
  const go = n => { if(!n) return 'true';
    if(n.sel){ const s = P.det[n.sel]; if(!s) throw new Error('Unknown selection ' + n.sel); return dlSel(b, s); }
    if(n.of){ const ks = Object.keys(P.det).filter(k => n.pat === 'them' ? true : n.pat.endsWith('*') ? k.startsWith(n.pat.slice(0, -1)) : k === n.pat); return '(' + ks.map(k => dlSel(b, P.det[k])).join(n.of === 'all' ? AND : OR) + ')'; }
    if(n.op === 'not') return b === 'kql' || b === 'sentinel' ? `not(${go(n.a)})` : `${NOT} (${go(n.a)})`;
    return '(' + go(n.a) + (n.op === 'and' ? AND : OR) + go(n.b) + ')'; };
  return go(T).replace(/^\((.*)\)$/s, '$1');
}
function sigmaToQuery(code, b){
  const P = sigmaParse(code), T = sigmaCondTree(P.cond), L = sigmaLogsource(code), notes = [];
  if(!T || !Object.keys(P.det).length) return {error:'Could not read the detection block.'};
  if(/\|\s*(count|near)\b|timeframe\s*:/m.test(code)) notes.push('Aggregations and timeframes are not translated — add them in the product.');
  let where = dlCond(b, P, T); const cat = L.category || '', win = L.product === 'windows';
  if(b === 'splunk'){
    const base = win ? (cat && DL_TABLE.sysmon[cat] != null ? `index=* source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=${String(DL_TABLE.sysmon[cat]).replace(/[()]/g, '').split(',').join(' OR EventCode=')}` : L.service ? `index=* source="XmlWinEventLog:${({security:'Security', system:'System', powershell:'Microsoft-Windows-PowerShell/Operational', sysmon:'Microsoft-Windows-Sysmon/Operational'})[L.service] || L.service}"` : 'index=*') : L.product ? `index=* sourcetype=*${L.service || L.product}*` : 'index=*';
    const usesFn = /\b(match|cidrmatch)\(/.test(where);
    return {q:usesFn ? `${base}\n| where ${where.replace(/(\w+)="([^"]*)"/g, (m, f, v) => /\*/.test(v) ? `like(${f}, "${v.replace(/%/g, '\\%').replace(/\*/g, '%')}")` : `${f}="${v}"`).replace(/ (?=(like|match|cidrmatch|\(|NOT|\w+=))/g, ' AND ').replace(/AND OR AND/g, 'OR').replace(/ AND (OR|AND) /g, ' $1 ')}` : `${base}\n${where}`, notes};
  }
  if(b === 'kql'){ const t = DL_TABLE.kql[cat]; if(!t) notes.push('No Defender table for the log source “' + (cat || L.service || L.product || 'unknown') + '” — replace the table name.'); return {q:`${t || 'DeviceEvents'}\n| where ${where.replace(/\n/g, ' ')}`, notes}; }
  if(b === 'sentinel'){ const id = DL_TABLE.sysmon[cat];
    const base = win && id != null ? `Event\n| where Source == "Microsoft-Windows-Sysmon" and EventID ${String(id).startsWith('(') ? 'in ' + id : '== ' + id}\n| extend d = parse_xml(EventData) | mv-apply x = d.DataItem.EventData.Data on (summarize bag = make_bag(pack(tostring(x['@Name']), tostring(x['#text'])))) | evaluate bag_unpack(bag)` : win && L.service === 'security' ? 'SecurityEvent' : 'Syslog';
    notes.push('Sysmon fields are unpacked from EventData under their own names; adjust if your workspace parses them differently.');
    return {q:`${base}\n| where ${where.replace(/\n/g, ' ')}`, notes}; }
  if(b === 'esql'){ const c = DL_TABLE.ecs[cat]; return {q:`FROM logs-*\n| WHERE ${c ? `event.category == "${c}" AND ` : ''}${where}`, notes}; }
  if(b === 'aql'){ notes.push('QRadar property names depend on your DSMs and custom properties — map them below.'); return {q:`SELECT * FROM events\nWHERE ${where}\nLAST 24 HOURS`, notes}; }
}
function dlQueriesPane(r, code){
  if(r.type !== 'sigma') return '<p class="t3">Queries are made from Sigma rules. YARA rules run on files, not in a SIEM.</p>';
  const b = DL_BACK[UI.dlB] ? UI.dlB : 'splunk', out = sigmaToQuery(code, b), M = (DB.prefs.fmap || {})[b] || {};
  return `<div class="seg dl-seg" role="group" aria-label="Product">${Object.entries(DL_BACK).map(([k, x]) => `<button type="button" data-act="dlB" data-v="${k}" aria-pressed="${b === k}">${esc(x.name.split(' (')[0].replace('Microsoft ', ''))}</button>`).join('')}</div>
    ${out.error ? `<p class="ti-x">${esc(out.error)}</p>` : `<div class="dl-q"><pre class="mono" id="dlQ">${esc(out.q)}</pre><button type="button" class="btn xs" data-act="dlCopy">${ico('copy','sm')}Copy</button></div>
      ${out.notes.map(n => `<p class="t3 small">${ico('info','sm')} ${esc(n)}</p>`).join('')}`}
    <details class="dl-map"><summary>Field names for ${esc(DL_BACK[b].name)}</summary><p class="t3 small">One per line: <span class="mono">SigmaField = YourField</span>. Your changes are kept in this browser and used for every rule.</p>
      <textarea id="dlMap" class="inp mono" rows="5" spellcheck="false" placeholder="CommandLine = process.args">${esc(Object.entries(M).map(([k, v]) => k + ' = ' + v).join('\n'))}</textarea><button type="button" class="btn xs" data-act="dlMapSave">Save field names</button></details>`;
}

/* ---------- tests kept with the rule ---------- */
const dlRec = text => ({id:'t', title:'', body:String(text || ''), host:'', source:'', tags:[], ents:[]});
function dlFires(r, code, text){
  if(r.type === 'sigma'){ const p = sigmaParse(code); if(!p.cond) throw new Error('No condition'); return sigmaEval(p, recFields(dlRec(text))); }
  return yaraScan(code, new TextEncoder().encode(String(text))).some(z => z.match);
}
function dlRunTests(r, code){ return (r.tests || []).map(t => { let got = null, err = ''; try{ got = dlFires(r, code == null ? r.code : code, t.text); }catch(e){ err = e.message; } return {t, got, err, ok:!err && got === (t.kind === 'hit')}; }); }
function dlTestsPane(r, code){
  const R = dlRunTests(r, code), fail = R.filter(x => !x.ok).length;
  return `<p class="t2 small">Events this rule <b>must</b> fire on, and events it must <b>not</b> fire on. They run against the rule as it is in the editor, and again every time you save.</p>
    ${R.length ? `<div class="dl-sum ${fail ? 'bad' : 'ok'}">${ico(fail ? 'triangle-alert' : 'circle-check','sm')}${fail ? fail + ' of ' + R.length + ' tests fail' : 'All ' + R.length + ' tests pass'}</div>
      <ul class="dl-tests">${R.map(x => `<li class="${x.ok ? 'ok' : 'bad'}"><span class="chip sq ${x.t.kind === 'hit' ? 'red' : 'green'}">${x.t.kind === 'hit' ? 'Must fire' : 'Must not fire'}</span>
        <code class="mono">${esc(x.t.text.slice(0, 400))}</code><span class="dl-r">${x.err ? esc(x.err) : x.ok ? ico('check','sm') + 'Pass' : ico('x','sm') + (x.got ? 'Fired' : 'Did not fire')}</span><button type="button" class="iconbtn" data-act="dlTestDel" data-id="${esc(x.t.id)}" aria-label="Remove test">${ico('trash-2','sm')}</button></li>`).join('')}</ul>` : ''}
    <div class="field"><label for="dlTestIn">New test event <span class="t3">— a log line, key=value pairs or JSON</span></label><textarea id="dlTestIn" class="inp mono" rows="3" spellcheck="false" placeholder='Image="C:\\Windows\\System32\\cmd.exe" CommandLine="cmd /c whoami"'></textarea></div>
    <div class="wrap"><button type="button" class="btn sm" data-act="dlTestAdd" data-v="hit">${ico('plus','sm')}Must fire</button><button type="button" class="btn sm" data-act="dlTestAdd" data-v="miss">${ico('plus','sm')}Must not fire</button>
      ${theCase() ? `<button type="button" class="btn sm ghost" data-act="dlTestFromCase">${ico('folder-open','sm')}Add what it fires on in ${esc(theCase().code)}</button>` : ''}</div>`;
}

/* ---------- evasion check ---------- */
const DL_MUT = [
  {id:'rename', t:'Renamed the program', fields:['image', 'newprocessname', 'targetfilename'], f:v => v.replace(/[^\\/]+(\.exe|\.dll|\.ps1|\.bat)$/i, (m, e) => 'svch0st' + e), fix:'Match OriginalFileName (Sysmon / Defender) or the hash as well as the file name — a rename does not change them.'},
  {id:'caret', t:'Put ^ inside the command (cmd.exe ignores it)', fields:['commandline'], f:v => v.replace(/\b([a-z])([a-z]{2,})/gi, (m, a, b) => a + '^' + b), fix:'Match short fragments with |contains, or detect the ^ itself: CommandLine|contains: \'^\' together with the program.'},
  {id:'quote', t:'Put quotes inside words', fields:['commandline'], f:v => v.replace(/\b([a-z]{2})([a-z]{2,})/gi, '$1""$2'), fix:'cmd.exe and PowerShell drop empty quotes; match smaller fragments, or flag "" in command lines of interest.'},
  {id:'dash', t:'Used / or an en dash for flags', fields:['commandline'], f:v => v.replace(/(^|\s)-(\w)/g, '$1/$2'), fix:'Add the |windash modifier: it matches -, /, – and — for you.'},
  {id:'dash2', t:'Used an en dash for flags', fields:['commandline'], f:v => v.replace(/(^|\s)-(\w)/g, '$1\u2013$2'), fix:'Add the |windash modifier.'},
  {id:'abbr', t:'Shortened PowerShell flags', fields:['commandline'], f:v => v.replace(/-encodedcommand\b/gi, '-e').replace(/-noprofile\b/gi, '-nop').replace(/-windowstyle\b/gi, '-w').replace(/-executionpolicy\b/gi, '-ep').replace(/-noninteractive\b/gi, '-noni'), fix:'PowerShell accepts any unique prefix of a parameter: match \' -e\' / \' -en\' … or use a regex like \\s-e(nc?|ncodedcommand)?\\s.'},
  {id:'space', t:'Added extra spaces and tabs', fields:['commandline'], f:v => v.replace(/ /g, '  \t'), fix:'Avoid long phrases with single spaces; match each token separately with |contains|all.'},
  {id:'env', t:'Used an environment variable for the path', fields:['commandline', 'image'], f:v => v.replace(/c:\\windows/gi, '%SystemRoot%'), fix:'Match the program name with |endswith rather than the full path, or include %SystemRoot% and %WinDir% forms.'},
  {id:'short', t:'Used a short (8.3) path', fields:['commandline', 'image', 'targetfilename'], f:v => v.replace(/program files/gi, 'PROGRA~1').replace(/\\windows\\system32\\/gi, '\\WINDOWS\\SYSTEM~1\\'), fix:'Short names still end with the program name: match |endswith on it, not the folder.'},
  {id:'ipdec', t:'Wrote the IP address as a number', fields:['commandline', 'url', 'destinationhostname'], f:v => v.replace(/\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g, (m, a, b, c, d) => String(((+a * 256 + +b) * 256 + +c) * 256 + +d)), fix:'Match the destination IP field rather than text in URLs or command lines.'},
];
/* a sample to work on: a must-fire test, an evidence hit, or one built from the rule's own values */
function dlSample(r, code){
  const t = (r.tests || []).find(x => x.kind === 'hit' && (() => { try{ return dlFires(r, code, x.text); }catch(e){ return false; } })()); if(t) return {text:t.text, from:'your must-fire test'};
  if(theCase()){ const h = testRule({...r, code}, DB.active); if(h.hits && h.hits.length) return {text:h.hits[0].body, from:'an event in ' + theCase().code}; }
  const P = sigmaParse(code), T = sigmaCondTree(P.cond); if(!T) return null;
  const pick = n => n.sel ? [n.sel] : n.of ? Object.keys(P.det).filter(k => n.pat === 'them' || (n.pat.endsWith('*') ? k.startsWith(n.pat.slice(0, -1)) : k === n.pat)).slice(0, n.of === 'all' ? 99 : 1) : n.op === 'and' ? pick(n.a).concat(pick(n.b)) : n.op === 'or' ? pick(n.a) : [];
  const kv = {};
  for(const s of pick(T)){ const S = P.det[s]; if(!S) continue; for(const {f:key, vals} of S.fields){ const [name, ...mods] = key.split('|'); if(mods.includes('re') || mods.includes('cidr')) continue; const vs = mods.includes('all') ? vals : vals.slice(0, 1);
    const v = vs.map(x => String(x).replace(/\*/g, '').replace(/\?/g, 'x')).join(' '); kv[name] = (mods.includes('endswith') ? 'C:\\Windows\\System32\\' : mods.includes('contains') ? 'x ' : '') + (mods.includes('endswith') ? v.replace(/^[\\/]+/, '') : v) + (mods.includes('startswith') || mods.includes('contains') ? ' 1' : ''); } }
  if(!Object.keys(kv).length) return null;
  const text = Object.entries(kv).map(([k, v]) => `${k}="${v.replace(/"/g, "'")}"`).join(' ');
  try{ return dlFires(r, code, text) ? {text, from:'the rule\'s own values'} : null; }catch(e){ return null; }
}
function dlEvasion(r, code){
  if(r.type !== 'sigma') return {error:'The evasion check runs on Sigma rules.'};
  const S = dlSample(r, code); if(!S) return {error:'No event that this rule fires on — add a must-fire test first.'};
  const base = recFields(dlRec(S.text)), P = sigmaParse(code), out = [];
  for(const M of DL_MUT){ const f = {...base}; let changed = false;
    for(const k of Object.keys(f)){ if(k.startsWith('_') || (M.fields[0] !== '*' && !M.fields.includes(k))) continue; const nv = M.f(f[k]).toLowerCase(); if(nv !== f[k]){ f[k] = nv; changed = true; } }
    if(!changed) continue; f._raw = Object.entries(f).filter(([k]) => !k.startsWith('_')).map(([k, v]) => k + '=' + v).join(' '); let fires = false; try{ fires = sigmaEval(P, f); }catch(e){}
    out.push({M, fires}); }
  /* checks on the rule itself */
  if(/\|re\b/.test(code) && !/\(\?i\)/.test(code)) out.push({M:{t:'Changed letter case (regular expressions)', fix:'Most SIEMs match |re patterns with case — start the pattern with (?i).'}, fires:false});
  if(/\|cased\b/.test(code)) out.push({M:{t:'Changed letter case', fix:'|cased makes the match case-sensitive; Windows does not care about case, so attackers can change it freely.'}, fires:false});
  if(/^\s*(Hashes|sha256|md5|sha1|Imphash)\b/mi.test(code) && !/Image|CommandLine|OriginalFileName/i.test(code)) out.push({M:{t:'Changed one byte of the file', fix:'Hash-only rules break on any rebuild — add behaviour (command line, parent, path) alongside the hash.'}, fires:false});
  return {S, rows:out, evaded:out.filter(x => !x.fires)};
}
function dlEvasionPane(r, code){
  const E2 = dlEvasion(r, code); if(E2.error) return `<p class="t3">${esc(E2.error)}</p>`;
  const n = E2.rows.length, ev = E2.evaded.length;
  return `<p class="t2 small">Starting from ${esc(E2.S.from)}, each change below is one attackers use. A rule that stops firing after a change is easy to slip past.</p>
    <div class="dl-sum ${ev ? 'bad' : 'ok'}">${ico(ev ? 'shield-alert' : 'shield-check','sm')}${ev ? `Slips past this rule: ${ev} of ${n} changes` : `Still fires after all ${n} changes`}</div>
    <ul class="dl-ev">${E2.rows.map(x => `<li class="${x.fires ? 'ok' : 'bad'}"><span class="dl-r">${x.fires ? ico('check','sm') + 'Still fires' : ico('x','sm') + 'Missed'}</span><div><b>${esc(x.M.t)}</b>${x.fires ? '' : `<small>${esc(x.M.id === 'rename' ? dlRenameFix(code) : x.M.fix)}</small>${/^dash/.test(x.M.id || '') ? `<button type="button" class="btn xs" data-act="dlFixDash">${ico('wand-sparkles','sm')}Add |windash for me</button>` : ''}`}</div></li>`).join('')}</ul>
    <details class="dl-map"><summary>The starting event</summary><pre class="mono">${esc(E2.S.text.slice(0, 2000))}</pre></details>`;
}

/* the original file name Windows keeps inside common programs, so a rename can be caught */
const DL_ORIG = {'powershell.exe':'PowerShell.EXE', 'pwsh.exe':'pwsh.dll', 'cmd.exe':'Cmd.Exe', 'rundll32.exe':'RUNDLL32.EXE', 'regsvr32.exe':'REGSVR32.EXE', 'mshta.exe':'MSHTA.EXE', 'certutil.exe':'CertUtil.exe', 'wmic.exe':'wmic.exe', 'bitsadmin.exe':'bitsadmin.exe', 'schtasks.exe':'schtasks.exe', 'reg.exe':'reg.exe', 'net.exe':'net.exe', 'net1.exe':'net1.exe', 'wscript.exe':'wscript.exe', 'cscript.exe':'cscript.exe', 'msiexec.exe':'msiexec.exe', 'msbuild.exe':'MSBuild.exe', 'installutil.exe':'InstallUtil.exe', 'regasm.exe':'RegAsm.exe', 'regsvcs.exe':'RegSvcs.exe', 'cmstp.exe':'CMSTP.EXE', 'procdump.exe':'procdump', 'psexec.exe':'psexec.c', 'vssadmin.exe':'VSSADMIN.EXE', 'wevtutil.exe':'wevtutil.exe', 'nltest.exe':'nltestrk.exe', 'whoami.exe':'whoami.exe', 'sc.exe':'sc.exe', 'curl.exe':'curl.exe', 'ntdsutil.exe':'ntdsutil.exe', 'forfiles.exe':'forfiles.exe', 'hh.exe':'HH.exe', 'odbcconf.exe':'odbcconf.exe', 'mavinject.exe':'mavinject.exe'};
function dlRenameFix(code){ const m = String(code).match(/Image\|endswith:\s*['"]?\\?([\w.-]+\.exe)/i), o = m && DL_ORIG[m[1].toLowerCase()];
  return o ? `Also match the name Windows keeps inside the program: add a selection "OriginalFileName: '${o}'" and use "condition: (selection_img or selection_orig) and …".` : 'Match OriginalFileName (Sysmon / Defender) or the hash as well as the file name — a rename does not change them.'; }

/* ---------- events → rule ---------- */
const DL_NOISY = new Set(['cmd.exe', 'powershell.exe', 'c:\\windows\\system32', '.exe', 'http', 'https', 'the', 'and']);
function dlFromEvents(recs){
  const F = recs.map(recFields), keys = Object.keys(F[0]).filter(k => !k.startsWith('_') && F.every(f => f[k] != null && f[k] !== ''));
  const SKIP = /^(computer|source|utctime|time|timestamp|processid|processguid|parentprocessid|parentprocessguid|logonid|logonguid|record|recordid|eventrecordid|keywords|opcode|task|version|level|threadid|hashes|sha256|md5|sha1|imphash|sourceport|ts|date)$/;
  const sel = [], eid = F[0].eventid && F.every(f => f.eventid === F[0].eventid) ? F[0].eventid : '';
  for(const k of keys){ if(SKIP.test(k) || k === 'eventid') continue; const vals = F.map(f => f[k]);
    if(vals.every(v => v === vals[0])){
      if(/image|filename|path|targetfilename|imageloaded/.test(k) && /[\\/]/.test(vals[0])) sel.push([k, 'endswith', ['\\' + vals[0].split(/[\\/]/).pop()]]);
      else if(vals[0].length <= 200) sel.push([k, '', [vals[0]]]); continue; }
    if(/commandline|cmd|url|query|details/.test(k)){ const toks = vals.map(v => new Set(v.split(/[\s"']+/).filter(t => t.length >= 3 && !DL_NOISY.has(t))));
      const common = [...toks[0]].filter(t => toks.every(s => s.has(t))).sort((a, b) => b.length - a.length).slice(0, 4); if(common.length) sel.push([k, 'contains|all', common]); }
    else if(/image|parentimage|originalfilename/.test(k)){ const ends = new Set(vals.map(v => v.split(/[\\/]/).pop())); if(ends.size <= 3) sel.push([k, 'endswith', [...ends].map(e => '\\' + e)]); } }
  const cat = {'1':'process_creation', '4688':'process_creation', '3':'network_connection', '11':'file_event', '13':'registry_set', '12':'registry_event', '22':'dns_query', '7':'image_load'}[eid] || '';
  const fieldName = k => ({image:'Image', commandline:'CommandLine', parentimage:'ParentImage', parentcommandline:'ParentCommandLine', originalfilename:'OriginalFileName', user:'User', targetfilename:'TargetFilename', destinationip:'DestinationIp', destinationport:'DestinationPort', destinationhostname:'DestinationHostname', queryname:'QueryName', targetobject:'TargetObject', details:'Details', imageloaded:'ImageLoaded', integritylevel:'IntegrityLevel'})[k] || k;
  const y = v => /[:#'"{}\[\],&*?|<>=!%@`\\]|^\s|\s$/.test(v) ? "'" + v.replace(/'/g, "''") + "'" : v;
  const lines = sel.filter(([k]) => !(cat && k === 'eventid')).slice(0, 6).map(([k, m, vs]) => vs.length === 1 && !m.includes('all') ? `        ${fieldName(k)}${m ? '|' + m : ''}: ${y(vs[0])}` : `        ${fieldName(k)}${m ? '|' + m : ''}:\n${vs.map(v => '            - ' + y(v)).join('\n')}`);
  if(!lines.length) return null;
  const code = `title: Draft from ${recs.length} event${recs.length > 1 ? 's' : ''}${theCase() ? ' in ' + theCase().code : ''}\nid: ${crypto.randomUUID ? crypto.randomUUID() : uid('s')}\nstatus: experimental\ndescription: Drafted by OSINTrix from what the selected events share. Review the values and test it before use.\nauthor: You\ndate: ${new Date().toISOString().slice(0, 10).replace(/-/g, '/')}\nlogsource:\n${cat ? '    category: ' + cat + '\n    product: windows' : '    product: windows'}\ndetection:\n    selection:\n${eid && !cat ? '        EventID: ' + eid + '\n' : ''}${lines.join('\n')}\n    condition: selection\nfalsepositives:\n    - Unknown — check against normal activity\nlevel: medium`;
  return code;
}
function dlDraftFromPick(){
  const ids = [...(UI.evPick || [])], recs = ids.map(recById).filter(r => r && r.type !== 'lead'); if(!recs.length) return toast('Select some events first');
  const code = dlFromEvents(recs); if(!code) return toast('These events share nothing a rule could match on — pick events of the same kind');
  /* how noisy would it be on everything else you have? */
  const r0 = {type:'sigma', code}, P = sigmaParse(code), others = DB.records.filter(x => x.type !== 'lead' && !ids.includes(x.id)), extra = others.filter(x => { try{ return sigmaEval(P, recFields(x)); }catch(e){ return false; } });
  const now = Date.now(), R = {id:uid('r'), type:'sigma', title:code.match(/^title: (.*)$/m)[1], desc:`Drafted from ${recs.length} selected event${recs.length > 1 ? 's' : ''}. Also matches ${extra.length} other event${extra.length === 1 ? '' : 's'} in your evidence.`, code, severity:'medium', category:'process', technique:'', author:'You', platform:'Windows', tags:['draft'], refs:[], created:now, modified:now, starred:false, caseId:DB.active || null,
    tests:recs.slice(0, 5).map(x => ({id:uid('t'), kind:'hit', text:x.body.slice(0, 2000)})).concat(others.filter(x => !extra.includes(x)).slice(0, 3).map(x => ({id:uid('t'), kind:'miss', text:x.body.slice(0, 2000)})))};
  DB.rules.unshift(R); UI.evPick = new Set(); UI.tlSel = false; UI.rule = R.id; UI.ropen = true; UI.rtab = 'tests'; mutate('drafted a rule from events'); go('#/detections');
  toast(extra.length ? `Draft rule made — it also matches ${extra.length} other event${extra.length === 1 ? '' : 's'}; tighten it before use` : 'Draft rule made, with the selected events as tests — it matches nothing else in your evidence');
}

/* re-run a rule's tests when it is saved */
function dlAfterSave(r){ const R = dlRunTests(r), bad = R.filter(x => !x.ok); if(bad.length) toast(`Saved — but ${bad.length} of ${R.length} tests now fail`, 'Show', () => { UI.rtab = 'tests'; renderMain(); }); return bad.length; }
function dlPaneFill(){
  const r = DB.rules.find(z => z.id === UI.rule), el = $('dlPane'), ta = $('rCode'); if(!r || !el) return; const code = ta ? ta.value : r.code;
  el.innerHTML = UI.rtab === 'queries' ? dlQueriesPane(r, code) : UI.rtab === 'tests' ? dlTestsPane(r, code) : UI.rtab === 'evasion' ? dlEvasionPane(r, code) : '';
}
const DL_ACTS = {
  dlB:(id, v) => { UI.dlB = v; dlPaneFill(); },
  dlCopy:() => { const q = $('dlQ'); if(q) copyText(q.textContent); },
  dlMapSave:() => { const b = DL_BACK[UI.dlB] ? UI.dlB : 'splunk', M = {};
    for(const l of $('dlMap').value.split('\n')){ const m = l.match(/^\s*([\w.|-]{1,80})\s*=\s*([^=]{1,120}?)\s*$/); if(m) M[m[1]] = m[2]; }
    DB.prefs.fmap = DB.prefs.fmap || {}; DB.prefs.fmap[b] = M; save(); dlPaneFill(); toast(Object.keys(M).length + ' field name' + (Object.keys(M).length === 1 ? '' : 's') + ' saved for ' + DL_BACK[b].name); },
  dlTestAdd:(id, v) => { const r = DB.rules.find(z => z.id === UI.rule), t = $('dlTestIn').value.trim(); if(!r) return; if(!t) return fieldErr('dlTestIn', 'Paste the event first.');
    r.tests = (r.tests || []).concat([{id:uid('t'), kind:v === 'hit' ? 'hit' : 'miss', text:t.slice(0, 4000)}]).slice(-50); mutate('test added to ' + r.title); dlPaneFill(); },
  dlTestDel:id => { const r = DB.rules.find(z => z.id === UI.rule); if(!r) return; r.tests = (r.tests || []).filter(t => t.id !== id); mutate('test removed from ' + r.title); dlPaneFill(); },
  dlTestFromCase:() => { const r = DB.rules.find(z => z.id === UI.rule), ta = $('rCode'); if(!r || !theCase()) return; const h = testRule({...r, code:ta ? ta.value : r.code}, DB.active); if(h.error) return toast(h.error); if(!h.hits.length) return toast('It fires on nothing in ' + theCase().code);
    const have = new Set((r.tests || []).map(t => t.text)); const add = h.hits.filter(x => !have.has(x.body)).slice(0, 5).map(x => ({id:uid('t'), kind:'hit', text:x.body.slice(0, 4000)}));
    r.tests = (r.tests || []).concat(add).slice(-50); mutate('tests from ' + theCase().code); dlPaneFill(); toast(add.length + ' event' + (add.length === 1 ? '' : 's') + ' added as must-fire tests'); },
  evRule:() => dlDraftFromPick(),
  dlFixDash:() => { const ta = $('rCode'); if(!ta) return; const before = ta.value;
    ta.value = ta.value.replace(/^(\s*-?\s*(?:ParentCommandLine|CommandLine)(?:\|[\w]+)*)(?=\s*:)/gm, m => /\|windash\b/.test(m) ? m : m + '|windash');
    if(ta.value === before) return toast('No command-line fields to change'); ta.dispatchEvent(new Event('input', {bubbles:true})); dlPaneFill(); toast('|windash added — save the rule to keep it'); },
};
