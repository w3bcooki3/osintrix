/* ==========================================================================
   Endpoint evidence, read the way an analyst would:
   · Process trees (Timeline → Processes): Sysmon 1 and Windows 4688 events
     joined parent → child — by process GUID, then process ID, then the parent's
     path — with suspicious processes and the branches leading to them marked.
   · Command lines decoded where they sit: -EncodedCommand, FromBase64String,
     [char] arrays, string concatenation, backtick obfuscation, base64 blobs;
     what the decoded text names becomes indicators.
   · Rare things (Timeline → Patterns): processes, domains, services and tasks
     seen on one host once or twice across all your evidence — the long tail.
   · Lateral movement (Timeline → Movement): host → host from network and RDP
     logons, explicit-credential logons, PsExec-style services, WinRM, RDP
     connection records and SMB/RDP/WinRM connections.
   ========================================================================== */
/* fields of an event, by any of several names, original case kept */
function epF(r){
  const k = r.id + ':' + (r.body || '').length; if(EP_F.has(k)) return EP_F.get(k);
  let P = null; try{ P = parseLog(String(r.body || '').slice(0, 20000)); }catch(e){}
  const f = P ? P.fields : {}, low = new Map(Object.entries(f).map(([a, v]) => [a.toLowerCase().replace(/^.*\./, (m) => m), v]));
  for(const [a, v] of Object.entries(f)){ const s = a.toLowerCase().split('.').pop(); if(!low.has(s)) low.set(s, v); }
  const get = (...names) => { for(const n of names){ const v = low.get(n.toLowerCase()); if(v != null && String(v).trim() !== '' && v !== '-') return String(v); } return ''; };
  const eid = get('EventID', 'event.code', 'event_id') || ((String(r.body || '').match(/\bEventID[=: ]+(\d{1,5})\b/i) || [])[1] || '');
  const o = {get, eid, norm:P ? P.norm : {}}; if(EP_F.size > 150000) EP_F.clear(); EP_F.set(k, o); return o;
}
const EP_F = new Map();
/* one name per machine whatever the log calls it: WS-HR-03, ws-hr-03.corp.local and WS-HR-03$ are the same host */
const epHostName = h => String(h || '').trim().replace(/\$$/, '').split('.')[0].toUpperCase();
const epHost = (r, F) => epHostName(r.host || (F || epF(r)).get('Computer', 'hostname', 'host.name') || (F || epF(r)).norm.host);
const epBase = p => String(p || '').split(/[\\/]/).pop();
const epNormPath = p => String(p || '').toLowerCase().replace(/\\users\\[^\\]+\\/, '\\users\\*\\').replace(/\\\\\?\\/, '');
/* ---------- process trees ---------- */
function epProc(r){
  if(r.type === 'lead' || !/image|processname|executable|process_path/i.test(r.body || '')) return null; const F = epF(r);
  if(!/^(1|4688)$/.test(F.eid) && !(F.get('Image', 'NewProcessName') && F.get('ParentImage', 'ParentProcessName'))) return null;
  const is4688 = F.eid === '4688', image = F.get('Image', 'NewProcessName', 'executable', 'process_path'); if(!image) return null;
  const hexd = v => v && /^0x[0-9a-f]+$/i.test(v) ? String(parseInt(v, 16)) : v;
  return {r, image, parent:F.get('ParentImage', 'ParentProcessName'), cmd:F.get('CommandLine', 'ProcessCommandLine', 'command_line'), user:F.get('User', 'SubjectUserName', 'TargetUserName'),
    guid:F.get('ProcessGuid'), pguid:F.get('ParentProcessGuid'), pid:hexd(is4688 ? F.get('NewProcessId') : F.get('ProcessId')), ppid:hexd(is4688 ? F.get('ProcessId', 'CreatorProcessId') : F.get('ParentProcessId')),
    host:epHost(r, F) || 'unknown host', ts:r.ts || 0, kids:[]};
}
const EP_LOL = /^(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|msiexec|wmic|schtasks|curl|wget|installutil|msbuild|forfiles|hh|cmstp|odbcconf|ieexec|regasm|regsvcs)\.exe$/i;
const EP_OFFICE = /^(winword|excel|powerpnt|outlook|onenote|msaccess|mspub|visio|acrord32|acrobat|foxitreader)\.exe$/i;
const EP_SYS = {'svchost.exe':1, 'lsass.exe':1, 'csrss.exe':1, 'services.exe':1, 'smss.exe':1, 'wininit.exe':1, 'winlogon.exe':1, 'explorer.exe':1, 'taskhostw.exe':1, 'spoolsv.exe':1, 'conhost.exe':1, 'dllhost.exe':1, 'rundll32.exe':1, 'lsm.exe':1};
function epWhy(n){
  const why = [], b = epBase(n.image).toLowerCase(), pb = epBase(n.parent).toLowerCase(), p = n.image.toLowerCase();
  try{ for(const o of E.observations(n.r)) if(o && o.t && o.tag !== 'masquerade') why.push(o.t.replace(/\s+—.*$/, '')); }catch(e){}
  if(EP_SYS[b] && !/\\windows\\(system32|syswow64|explorer\.exe|winsxs)/i.test(n.image) && !/^[a-z]:\\windows\\explorer\.exe$/i.test(n.image) && /\\/.test(n.image)) why.push(`${epBase(n.image)} outside Windows — a disguise`);
  if(/\\(users\\public|programdata|temp|appdata\\local\\temp|windows\\temp|perflogs|\$recycle\.bin)\\/i.test(p)) why.push('runs from a folder anyone can write to');
  if(EP_OFFICE.test(pb) && EP_LOL.test(b)) why.push(`${epBase(n.parent)} started ${epBase(n.image)}`);
  if(/^(services|wmiprvse|w3wp|sqlservr|httpd|nginx|tomcat\d*|java)\.exe$/i.test(pb) && /^(cmd|powershell|pwsh)\.exe$/i.test(b)) why.push(`a shell under ${epBase(n.parent)}`);
  if(typeof cmdDecode === 'function' && n.cmd && !why.some(w => /encod|obfusc/i.test(w)) && cmdDecode(n.cmd).length) why.push('obfuscated command line');
  return [...new Set(why)].slice(0, 4);
}
function epTrees(D){
  const sig = (D.recs[0] && D.recs[0].caseId) + ':' + rev; if(EP_T.sig === sig) return EP_T.v;
  const P = D.recs.map(epProc).filter(Boolean).sort((a, b) => a.ts - b.ts), byHost = new Map();
  for(const n of P){ if(!byHost.has(n.host)) byHost.set(n.host, []); byHost.get(n.host).push(n); }
  const hosts = [];
  for(const [host, L] of byHost){
    const byGuid = new Map(L.filter(n => n.guid).map(n => [n.guid.toLowerCase(), n])), synth = new Map(), roots = [];
    const byPid = new Map(), byImg = new Map();     // the latest process so far with that ID / that path: IDs and paths are reused, so the most recent earlier one is the parent
    for(let i = 0; i < L.length; i++){ const n = L[i]; let par = null;
      if(n.pguid) par = byGuid.get(n.pguid.toLowerCase()) || null;
      if(!par && n.ppid){ const q = byPid.get(n.ppid); if(q && (!n.parent || !q.image || epBase(q.image).toLowerCase() === epBase(n.parent).toLowerCase())) par = q; }
      if(!par && n.parent){ const q = byImg.get(n.parent.toLowerCase()); if(q && n.ts - q.ts <= 864e5) par = q; }
      if(n.pid) byPid.set(n.pid, n); byImg.set(n.image.toLowerCase(), n);
      if(!par && n.parent){ const k = n.parent.toLowerCase(); par = synth.get(k); if(!par){ par = {synthetic:true, image:n.parent, kids:[], host, ts:n.ts, why:[]}; synth.set(k, par); roots.push(par); } }
      n.why = epWhy(n); if(par){ par.kids.push(n); n.up = par; } else roots.push(n); }
    /* a parent missing from the evidence was often started by an earlier process's own command line (cmd /c powershell …): hang it there, marked as inferred */
    for(const s of synth.values()){ const b = epBase(s.image).toLowerCase().replace(/\.exe$/, ''); if(!b) continue; const re = new RegExp('(^|[\\s"\'/\\\\])' + b.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '(\\.exe)?(["\'\\s]|$)', 'i');
      let by = null; for(const n of L) if(n !== s && n.ts <= s.ts && n.ts >= s.ts - 36e5 && n.cmd && re.test(n.cmd.replace(/^"?[^"\s]*"?/, ' ')) && !(x => { for(; x; x = x.up) if(x === s) return true; return false; })(n)) by = n;
      if(by){ s.inferred = true; s.ts = by.ts; by.kids.push(s); s.up = by; roots.splice(roots.indexOf(s), 1); } }
    /* a branch is "hot" when it leads to something suspicious */
    const hot = n => { let h = !!(n.why && n.why.length); for(const k of n.kids) if(hot(k)) h = true; n.hot = h; return h; }; roots.forEach(hot);
    hosts.push({host, n:L.length, roots, flagged:L.filter(n => n.why.length).length});
  }
  hosts.sort((a, b) => b.flagged - a.flagged || b.n - a.n);
  EP_T.sig = sig; EP_T.v = hosts; return hosts;
}
const EP_T = {sig:'', v:null};
function procView(c, D){
  const H = epTrees(D), only = UI.epOnly !== false;
  if(!H.length) return `<div class="page wide">${empty('git-branch', 'No process events in this case yet', 'Process trees are built from Sysmon event 1 and Windows event 4688 (process creation). Import those logs — EVTX, XML, JSON or text — and the trees appear here.')}</div>`;
  let shown = 0; const cap = 600;
  const node = n => { if(only && !n.hot) return ''; if(++shown > cap) return '';
    const kids = n.kids.map(node).join(''), hidden = only ? n.kids.filter(k => !k.hot).length : 0;
    const dec = n.cmd && typeof cmdDecode === 'function' ? cmdDecode(n.cmd) : [];
    return `<li class="${n.why && n.why.length ? 'flag' : n.hot ? 'path' : ''}"><div class="ep-n">${n.synthetic ? `<span class="ep-i">${ico('circle-help','sm')}</span><b title="${esc(n.image)}">${esc(epBase(n.image) || n.image)}</b><span class="t3">${n.inferred ? 'not in the evidence — started by the command line above' : 'not in the evidence — known as the parent'}</span>`
      : `<button class="ep-b" data-act="tlxRec" data-id="${n.r.id}"><span class="mono t3">${n.ts ? esc(E.fmtClock(n.ts, tz())) : '—'}</span><b title="${esc(n.image)}">${esc(epBase(n.image))}</b>${n.pid ? `<span class="t3 mono">pid ${esc(n.pid)}</span>` : ''}${n.user ? `<span class="t3">${esc(n.user)}</span>` : ''}</button>`}
      ${n.why && n.why.length ? n.why.map(w => `<span class="chip sq red">${esc(w)}</span>`).join('') : ''}</div>
      ${n.cmd && n.cmd.trim() !== n.image.trim() ? `<code class="ep-c">${esc(n.cmd.length > 400 ? n.cmd.slice(0, 400) + '…' : n.cmd)}</code>` : ''}
      ${dec.length ? `<div class="ep-dec">${ico('lock-open','sm')}<span><b>Decoded</b> <span class="t3">· ${esc(dec[dec.length - 1].how)}</span></span><code>${esc(dec[dec.length - 1].out.slice(0, 500))}</code></div>` : ''}
      ${kids || hidden ? `<ul>${kids}${hidden ? `<li class="ep-more t3">${hidden} quiet branch${hidden > 1 ? 'es' : ''} hidden</li>` : ''}</ul>` : ''}</li>`; };
  const total = H.reduce((a, h) => a + h.n, 0), flagged = H.reduce((a, h) => a + h.flagged, 0);
  return `<div class="page wide ep"><section class="card ep-sum"><div class="tlx-kpi"><div><b>${total}</b><span>processes</span></div><div><b>${H.length}</b><span>host${H.length > 1 ? 's' : ''}</span></div><div class="${flagged ? 'r' : ''}"><b>${flagged}</b><span>look suspicious</span></div></div>
      <div class="seg" role="group" aria-label="Show"><button data-act="epOnly" data-v="1" aria-pressed="${only}">Suspicious branches</button><button data-act="epOnly" data-v="0" aria-pressed="${!only}">Everything</button></div>
      <p class="t3 small" style="margin:8px 0 0">From Sysmon 1 and Windows 4688. Joined by process GUID, then process ID, then the parent's path; a parent that is not in the evidence is marked with a question mark.</p></section>
    ${H.map(h => { shown = 0; const body = h.roots.map(node).join(''); return `<section class="card ep-h"><header><h3>${ico('monitor','sm')} <span class="mono">${esc(h.host)}</span></h3><span class="t3">${h.n} process${h.n > 1 ? 'es' : ''}</span>${h.flagged ? `<span class="chip sq red">${h.flagged} suspicious</span>` : ''}</header>
      ${body ? `<ul class="ep-t">${body}</ul>` : `<p class="t3" style="margin:4px 0 0">Nothing suspicious here — switch to Everything to see the ${h.n} processes.</p>`}${shown > cap ? `<p class="t3 small">Showing the first ${cap}.</p>` : ''}</section>`; }).join('')}</div>`;
}
/* ---------- command-line decoding ---------- */
const b64ok = s => /^[A-Za-z0-9+/]+={0,2}$/.test(s) && s.length % 4 !== 1;
function b64txt(s){ let bin; try{ bin = atob(s.replace(/\s+/g, '') + '==='.slice((s.length + 3) % 4 || 3)); }catch(e){ try{ bin = atob(s); }catch(e2){ return null; } }
  const u = Uint8Array.from(bin, c => c.charCodeAt(0)), zeros = u.filter((x, i) => i % 2 === 1 && x === 0).length;
  let t = zeros > u.length / 4 ? new TextDecoder('utf-16le').decode(u) : new TextDecoder('utf-8', {fatal:false}).decode(u);
  t = t.replace(/\u0000+$/, ''); const printable = (t.match(/[\x20-\x7e\t\r\n]/g) || []).length; return t.length >= 4 && printable / t.length > 0.9 ? t : null; }
function cmdDecode(s){
  s = String(s || ''); if(s.length < 12 || s.length > 200000) return [];
  const out = []; let cur = s;
  for(let depth = 0; depth < 4; depth++){ let step = null;
    const enc = cur.match(/\s-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedcommand)\s+["']?([A-Za-z0-9+/=]{16,})/i);
    if(enc && b64ok(enc[1])){ const t = b64txt(enc[1]); if(t) step = {how:'-EncodedCommand (Base64, UTF-16)', out:t}; }
    if(!step){ const m = cur.match(/FromBase64String\(\s*["']([A-Za-z0-9+/=\s]{12,})["']\s*\)/i); if(m){ const t = b64txt(m[1]); if(t) step = {how:'FromBase64String', out:t}; } }
    if(!step){ const m = cur.match(/((?:\[char\]\s*\d{2,3}\s*\+?\s*){3,})/i) || cur.match(/\[char\[\]\]\s*\(([\d\s,]{8,})\)/i);
      if(m){ const nums = m[1].match(/\d{2,3}/g).map(Number).filter(n => n >= 9 && n < 127); if(nums.length >= 3){ const t = String.fromCharCode(...nums); step = {how:'[char] codes', out:cur.replace(m[0], JSON.stringify(t))}; if(/^\[char\[\]\]/i.test(m[0]) || m[0].length > cur.length * 0.6) step.out = t; } } }
    if(!step && /(['"])[^'"]{0,40}\1\s*\+\s*(['"])[^'"]{0,40}\2/.test(cur)){ const joined = cur.replace(/(?:(['"])([^'"]{0,200})\1\s*\+\s*)+(['"])([^'"]{0,200})\3/g, m => JSON.stringify(m.match(/(['"])([^'"]*)\1/g).map(x => x.slice(1, -1)).join(''))); if(joined !== cur) step = {how:'joined strings', out:joined}; }
    if(!step && /\w`[^0abfnrtv\W]/i.test(cur)){ const t = cur.replace(/`(?=[a-zA-Z0-9-])(?![0abfnrtv])/g, '');   /* `t `n `0 … are real escapes in PowerShell: kept */ if(t !== cur) step = {how:'backticks removed', out:t}; }
    if(!step){ const m = cur.match(/(?:^|[\s"'=(:])([A-Za-z0-9+/]{40,}={0,2})(?=$|[\s"')])/); if(m && b64ok(m[1])){ const t = b64txt(m[1]); if(t && t !== cur) step = {how:'Base64', out:t}; } }
    if(!step || step.out === cur) break; out.push(step); cur = step.out; }
  return out;
}
/* what decoded command lines name becomes indicators of the record, once, in the background */
let EP_SCAN = null;
function epScanRecords(){ clearTimeout(EP_SCAN); EP_SCAN = setTimeout(() => {
  const L = DB.records.filter(r => !r.decX && r.body && /-e(nc|ncodedcommand)?\s|frombase64|\[char|`|[A-Za-z0-9+/]{40,}/i.test(r.body)).slice(0, 2000); if(!L.length) return; let n = 0;
  for(const r of L){ r.decX = 1; const D = cmdDecode(r.body); if(!D.length) continue; const have = new Set((r.ents || []).map(e => e.k + ':' + String(e.v).toLowerCase()));
    for(const e of extractRich(D.map(d => d.out).join('\n'))){ const k = e.k + ':' + String(e.v).toLowerCase(); if(!have.has(k)){ have.add(k); (r.ents = r.ents || []).push({k:e.k, v:e.v}); n++; } } }
  if(n){ rev++; cache = {}; save(); if(UI.route && /case|entities/.test(UI.route.area)) renderMain(); } else save();
}, 500); }
function decodedHtml(r){ const D = r && r.body ? cmdDecode(r.body) : []; if(!D.length) return '';
  return `<div class="ep-dec">${ico('lock-open','sm')}<span><b>Decoded</b> <span class="t3">· ${esc(D.map(d => d.how).join(' → '))}</span></span><code>${esc(D[D.length - 1].out.slice(0, 1500))}</code></div>`; }
/* ---------- rare things ---------- */
function epRareIndex(){
  const sig = rev + ':' + DB.records.length; if(EP_R.sig === sig) return EP_R.v;
  const own = DB.cases.filter(c => !c.sample), cs = new Set((own.length ? own : DB.cases).map(c => c.id)), M = {process:new Map(), domain:new Map(), service:new Map(), task:new Map()};
  const put = (kind, key, label, r) => { if(!key) return; const m = M[kind]; let x = m.get(key); if(!x){ x = {kind, key, label, hosts:new Set(), recs:[]}; m.set(key, x); } if(x.recs.includes(r)) return; x.hosts.add(epHost(r) || r.caseId); x.n = (x.n || 0) + 1; if(x.recs.length < 20) x.recs.push(r); };
  for(const r of DB.records){ if(!cs.has(r.caseId) || r.type === 'lead') continue;
    const p = epProc(r); if(p) put('process', epNormPath(p.image), p.image, r);
    for(const e of r.ents || []) if(e.k === 'domain') put('domain', String(e.v).toLowerCase(), e.v, r);
    if(!/\b(7045|4697|4698|106)\b|schtasks/i.test(r.body || '')) continue; const F = epF(r);
    if(F.eid === '7045' || F.eid === '4697'){ const sn = F.get('ServiceName'), ip = F.get('ImagePath', 'ServiceFileName'); if(sn || ip) put('service', (sn + '|' + epNormPath(ip)).toLowerCase(), sn + (ip ? ' — ' + ip : ''), r); }
    if(F.eid === '4698' || F.eid === '106'){ const tn = F.get('TaskName'); if(tn) put('task', tn.toLowerCase(), tn, r); }
    const tm = String(r.body || '').match(/schtasks(?:\.exe)?\b[^\n]*?\/create\b[^\n]*?\/tn\s+("[^"]+"|\S+)/i); if(tm) put('task', tm[1].replace(/"/g, '').toLowerCase(), tm[1].replace(/"/g, ''), r); }
  EP_R.sig = sig; EP_R.v = M; return M;
}
const EP_R = {sig:'', v:null};
function epRare(D){
  const M = epRareIndex(), caseId = D.recs[0] && D.recs[0].caseId, out = [];
  for(const [kind, m] of Object.entries(M)){ if(m.size < 8) continue;           // too few to say what is normal
    for(const x of m.values()){ const n = x.n; if(x.hosts.size !== 1 || n > 2 || !x.recs.some(r => r.caseId === caseId)) continue; out.push({...x, n}); } }
  const order = {process:0, service:1, task:2, domain:3};
  return out.sort((a, b) => order[a.kind] - order[b.kind] || (a.recs[0].ts || 0) - (b.recs[0].ts || 0)).slice(0, 40);
}
function rareCard(D, card){
  const R = epRare(D); if(!R.length) return '';
  const lbl = {process:'Program', service:'Service', task:'Scheduled task', domain:'Domain'};
  return card('sparkles', 'amber', 'Rare things', `<ul class="tlx-l">${R.slice(0, 15).map(x => `<li><div><span class="t3">${lbl[x.kind]}</span> <b class="mono">${esc(String(x.label).slice(0, 160))}</b></div>
    <div class="t2">Only on <b class="mono">${esc([...x.hosts][0])}</b>, ${x.n === 1 ? 'once' : 'twice'} in all your evidence${x.recs[0].ts ? ' — ' + esc(E.fmtFull(x.recs[0].ts, tz())) : ''}</div>
    <div class="wrap"><button class="btn xs" data-act="tlxRec" data-id="${x.recs[0].id}">${ico('eye','sm')}See it</button></div></li>`).join('')}</ul>
    <p class="t3 small">The long tail: of all the programs, services, tasks and domains in your cases, these appear on one host, once or twice. Attackers' tools usually do; most of the rest is just unusual software.${R.length > 15 ? ' ' + (R.length - 15) + ' more.' : ''}</p>`);
}
/* ---------- lateral movement ---------- */
const epIpOk = ip => ip && !/^(127\.|0\.|::1$|-$|fe80:)/i.test(ip) && ip !== '::';
function epMoves(D){
  const sig = (D.recs[0] && D.recs[0].caseId) + ':' + rev; if(EP_M.sig === sig) return EP_M.v;
  const ipHost = new Map(), edges = new Map(), recs = D.recs.filter(r => r.type !== 'lead' && r.ts && /\b(4624|4648|1149|7045|4697|445|3389|5985|5986|135)\b|wsmprovhost/i.test(r.body || ''));
  const host = epHostName;
  /* who has which address: logons name the workstation and its IP; a host's own connections give its source IP */
  for(const r of recs){ const F = epF(r), ws = F.get('WorkstationName', 'Workstation'), ip = F.get('IpAddress', 'SourceNetworkAddress', 'ClientIP');
    if(ws && epIpOk(ip) && ws !== '-') ipHost.set(ip, host(ws));
    const sip = F.get('SourceIp', 'src_ip', 'SourceAddress'); if(F.eid === '3' && epHost(r, F) && epIpOk(sip)) ipHost.set(sip, epHost(r, F)); }
  const who = (v, ws) => ws && ws !== '-' ? host(ws) : epIpOk(v) ? (ipHost.get(v) || v) : '';
  const add = (a, b, how, r, user) => { if(!a || !b || a === b) return; const k = a + '\u0000' + b + '\u0000' + how; let e = edges.get(k); if(!e){ e = {a, b, how, first:r.ts, last:r.ts, n:0, users:new Set(), recs:[]}; edges.set(k, e); }
    e.n++; e.first = Math.min(e.first, r.ts); e.last = Math.max(e.last, r.ts); if(user && user !== '-') e.users.add(user); if(e.recs.length < 200) e.recs.push(r.id); };
  for(const r of recs){ const F = epF(r), dst = epHost(r, F), user = F.get('TargetUserName', 'User', 'SubjectUserName');
    if(F.eid === '4624'){ const lt = F.get('LogonType'); if(lt === '3' || lt === '10') add(who(F.get('IpAddress'), F.get('WorkstationName')), dst, lt === '10' ? 'RDP logon' : 'network logon', r, user); }
    else if(F.eid === '4648'){ const ts2 = F.get('TargetServerName'); if(ts2 && !/^(localhost|-)$/i.test(ts2)) add(dst, host(ts2), 'explicit credentials', r, F.get('TargetUserName')); }
    else if(F.eid === '1149') add(who(F.get('Param3', 'SourceNetworkAddress', 'IpAddress')), dst, 'RDP connection', r, F.get('Param1'));
    else if((F.eid === '7045' || F.eid === '4697') && /psexe|\\admin\$|\\\\127|%systemroot%\\[a-z0-9]{6,}\.exe|remcom|paexec|csexec/i.test(F.get('ImagePath', 'ServiceFileName') + ' ' + F.get('ServiceName'))){
      const near = recs.find(x => x !== r && Math.abs(x.ts - r.ts) <= 120000 && epHost(x) === dst && epF(x).eid === '4624' && epF(x).get('LogonType') === '3');
      add(near ? who(epF(near).get('IpAddress'), epF(near).get('WorkstationName')) || '?' : '?', dst, 'remote service (PsExec-style)', r, near ? epF(near).get('TargetUserName') : ''); }
    else if(F.eid === '1' && /wsmprovhost\.exe$/i.test(F.get('Image'))) add('?', dst, 'WinRM / PowerShell remoting', r, F.get('User'));
    else if(F.eid === '3' || r.source === 'fw' || /->|→/.test(r.body || '')){ const f = recFields(r), port = f.destinationport || F.get('DestinationPort', 'dst_port', 'dpt'), dip = f.destinationip || F.get('DestinationIp');
      const via = {445:'SMB', 3389:'RDP', 5985:'WinRM', 5986:'WinRM', 135:'RPC'}[port]; if(via && epIpOk(dip) && ipHost.has(dip)){ const src = F.eid === '3' && epHost(r, F) ? epHost(r, F) : ipHost.get(f.sourceip || F.get('SourceIp')); if(src) add(src, ipHost.get(dip), via + ' connection', r); } } }
  const E2 = [...edges.values()].sort((a, b) => a.first - b.first), nodes = new Map();
  for(const e of E2){ for(const h of [e.a, e.b]) if(!nodes.has(h)) nodes.set(h, {h, first:e.first}); }
  EP_M.sig = sig; EP_M.v = {edges:E2, nodes:[...nodes.values()].sort((a, b) => a.first - b.first)}; return EP_M.v;
}
const EP_M = {sig:'', v:null};
function moveView(c, D){
  const M = epMoves(D);
  if(!M.edges.length) return `<div class="page wide">${empty('waypoints', 'No movement between hosts found yet', 'This map is built from network and RDP logons (4624 types 3 and 10), explicit-credential logons (4648), PsExec-style services (7045), WinRM, RDP connection records (1149) and SMB/RDP/WinRM connections between your hosts.')}</div>`;
  const N = M.nodes.slice(0, 18), W = Math.max(640, N.length * 150), Hh = 260, pos = new Map(N.map((n, i) => [n.h, {x:70 + i * ((W - 140) / Math.max(1, N.length - 1)), y:i % 2 ? 170 : 80}]));
  const svgE = M.edges.filter(e => pos.has(e.a) && pos.has(e.b)).map((e, i) => { const A = pos.get(e.a), B = pos.get(e.b), mx = (A.x + B.x) / 2, my = (A.y + B.y) / 2 - 40 - (i % 3) * 14;
    return `<path d="M${A.x},${A.y} Q${mx},${my} ${B.x},${B.y}" class="mv-e${/PsExec|explicit|RDP/.test(e.how) ? ' hot' : ''}" marker-end="url(#mvA)"><title>${esc(e.a + ' → ' + e.b + ': ' + e.how + ', ' + E.fmtFull(e.first, tz()))}</title></path><text x="${mx}" y="${my + 6}" class="mv-l">${esc(e.how.split(' ')[0])} · ${esc(E.fmtClock(e.first, tz()))}</text>`; }).join('');
  const svgN = N.map(n => { const p = pos.get(n.h); return `<g class="mv-n${n.h === '?' ? ' unk' : /^\d/.test(n.h) ? ' ip' : ''}"><circle cx="${p.x}" cy="${p.y}" r="16"></circle><text x="${p.x}" y="${p.y + 34}" text-anchor="middle">${esc(n.h === '?' ? 'unknown source' : n.h)}</text></g>`; }).join('');
  return `<div class="page wide mv"><section class="card mv-sum"><div class="tlx-kpi"><div><b>${M.nodes.filter(n => n.h !== '?').length}</b><span>hosts</span></div><div><b>${M.edges.length}</b><span>movement${M.edges.length > 1 ? 's' : ''}</span></div><div><b>${esc(E.fmtClock(M.edges[0].first, tz()))}</b><span>first</span></div></div>
      <div class="mv-svg" role="img" aria-label="Hosts in the order they were reached, with arrows for each movement"><svg viewBox="0 0 ${W} ${Hh}" width="${W}" height="${Hh}"><defs><marker id="mvA" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0L10,5L0,10z"></path></marker></defs>${svgE}${svgN}</svg></div>
      <p class="t3 small">Hosts left to right in the order they were first reached. Addresses are named from logons and the hosts' own connections; an address still shown as a number is not one of your hosts.</p></section>
    <section class="card mv-c"><table class="mv-t"><thead><tr><th scope="col">When</th><th scope="col">From</th><th scope="col">To</th><th scope="col">How</th><th scope="col">Account</th><th scope="col"></th></tr></thead><tbody>
      ${M.edges.map(e => `<tr><td class="mono">${esc(E.fmtFull(e.first, tz()))}${e.n > 1 ? `<br><span class="t3">${e.n}× until ${esc(E.fmtClock(e.last, tz()))}</span>` : ''}</td><td class="mono">${esc(e.a === '?' ? 'unknown' : e.a)}</td><td class="mono">${esc(e.b)}</td><td>${esc(e.how)}</td><td class="mono">${esc([...e.users].slice(0, 3).join(', ') || '—')}</td>
        <td><button class="btn xs" data-act="mvShow" data-v="${esc(e.recs.join(','))}">Events</button></td></tr>`).join('')}</tbody></table></section></div>`;
}
const EP_ACTS = {
  epOnly:(id, v) => { UI.epOnly = v === '1'; renderMain(); },
  mvShow:(id, v) => { UI.facet.ids = String(v).split(',').filter(Boolean); UI.tlMode = 'events'; renderMain(); },
};
