/* ==========================================================================
   File triage — one answer to "how worried should I be about this file?"
   A score out of 100 with every reason, built from what the inspector already reads:
   disguised names and wrong extensions, executables and scripts, macros and active
   PDF content, packers and high-entropy code, suspicious imports and strings, files
   hidden inside files, indicators the file contains — and what your cases, feeds and
   lookups already know about its hash or those indicators. An entropy map shows where
   the packed or encrypted parts are. Nothing leaves the browser.
   ========================================================================== */
const TRI_STR = [
  [/-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{24,}/i, 18, 'Encoded PowerShell command'], [/\b(iex|invoke-expression)\b.{0,80}(downloadstring|webclient|invoke-webrequest|iwr)\b|\b(downloadstring|downloadfile)\s*\(/i, 16, 'Downloads and runs code (PowerShell cradle)'],
  [/\b(virtualalloc(ex)?|writeprocessmemory|createremotethread|ntunmapviewofsection|queueuserapc)\b/i, 12, 'Process-injection API names'], [/\b(isdebuggerpresent|checkremotedebuggerpresent|ntqueryinformationprocess)\b/i, 6, 'Anti-debugging checks'],
  [/software\\microsoft\\windows\\currentversion\\run(once)?\b/i, 10, 'Writes a Run key (starts at logon)'], [/\bschtasks(\.exe)?\s+\/create\b/i, 10, 'Creates a scheduled task'],
  [/\bvssadmin(\.exe)?\s+delete\s+shadows\b|\bwbadmin\s+delete\b|\bbcdedit\b.{0,40}recoveryenabled\s+no/i, 22, 'Deletes backups or shadow copies (ransomware behaviour)'],
  [/your files (have been|are) encrypted|decrypt(ion)? (key|tool)|bitcoin wallet|\.onion\b.{0,60}(decrypt|key|payment)/i, 22, 'Ransom note text'], [/\b(mimikatz|sekurlsa|lsadump|kerberos::)\b/i, 22, 'Credential-theft tool strings (Mimikatz)'],
  [/\bcertutil(\.exe)?\s+-(urlcache|decode)\b|\bbitsadmin\b.{0,30}\/transfer\b|\bmshta(\.exe)?\s+(https?:|vbscript|javascript)/i, 12, 'Living-off-the-land download (certutil, bitsadmin, mshta)'],
  [/\bwscript\.shell\b|\bshell\.application\b|\bcreateobject\s*\(\s*["']wscript/i, 8, 'Script runs shell commands'], [/\bauto(open|_open|exec)\b|\bdocument_open\b|\bworkbook_open\b/i, 10, 'Macro that runs when the document opens'],
  [/\b(cmd(\.exe)?\s+\/c|powershell(\.exe)?\s+-(w|windowstyle)\s+hidden|-nop\b.{0,20}-w\s+hidden)/i, 8, 'Hidden command execution'], [/\b(keylog|getasynckeystate|setwindowshookex)\b/i, 10, 'Keylogging API names'],
  [/\b(cobaltstrike|beacon\.dll|meterpreter|metasploit|sliver|havoc)\b/i, 18, 'Offensive framework strings']];
const TRI_EXEC = /^(exe|elf|macho|class|lnk|sh)$/, TRI_RISKY_EXT = /^(exe|scr|com|pif|bat|cmd|ps1|vbs|vbe|js|jse|wsf|wsh|hta|lnk|msi|jar|dll|cpl|iso|img|vhd|vhdx|one|xll|docm|xlsm|pptm)$/i;
function entropyMap(b, n = 96){
  const len = Math.min(b.length, 64e6), size = Math.max(256, Math.ceil(len / n)), out = [];
  for(let o = 0; o < len; o += size){ const f = new Uint32Array(256), end = Math.min(len, o + size); for(let i = o; i < end; i++) f[b[i]]++; let e = 0; const m = end - o; for(const c of f) if(c){ const p = c / m; e -= p * Math.log2(p); } out.push({o, e}); }
  return out;
}
function fileTriage(r){
  if(r.triage && r.triage.yaraN === (r.yara ? r.yara.length : -1)) return r.triage;
  const R = [], add = (w, t, sev) => R.push({w, t, sev:sev || (w >= 15 ? 'hi' : w >= 7 ? 'md' : w < 0 ? 'ok' : 'lo')});
  const name = r.name || '', low = name.toLowerCase(), ext = r.ext || '', T = r.type || {};
  /* names and types */
  if(/\.(pdf|docx?|xlsx?|txt|jpe?g|png|mp4|zip)\.(exe|scr|lnk|js|jse|vbs|hta|bat|cmd|ps1|com|pif)$/i.test(name)) add(25, 'Double extension “' + name.split('.').slice(-2).join('.') + '” — made to look like a document');
  if(/[‮‏]/.test(name)) add(25, 'Right-to-left override character in the name — the extension is disguised');
  if(r.mismatch) add(15, 'The extension .' + ext + ' does not match the content (' + T.name + ')');
  if(TRI_EXEC.test(T.ext || '')) add(T.ext === 'lnk' ? 14 : 10, (T.ext === 'lnk' ? 'Windows shortcut — a common way to launch commands from an email or ZIP' : 'Runs as a program (' + T.name + ')'));
  else if(TRI_RISKY_EXT.test(ext)) add(8, '.' + ext + ' files can run code when opened');
  /* documents */
  if(r.zip && r.zip.macros && r.zip.macros.length) add(20, 'Office document with macros (' + r.zip.macros.slice(0, 2).join(', ') + ')');
  if(r.zip && r.zip.external && r.zip.external.length) add(12, 'Loads ' + r.zip.external.length + ' remote resource' + (r.zip.external.length > 1 ? 's' : '') + ' when opened (remote template or tracking)');
  if(r.zip && r.zip.encrypted) add(8, 'Password-protected archive — a common way to slip past mail scanners');
  if(r.zip && r.zip.files && r.zip.files.some(f => TRI_RISKY_EXT.test(f.name.split('.').pop() || ''))) add(12, 'The archive holds files that run code: ' + r.zip.files.filter(f => TRI_RISKY_EXT.test(f.name.split('.').pop() || '')).slice(0, 3).map(f => f.name).join(', '));
  if(r.pdf){ const k = ['/JS', '/JavaScript', '/OpenAction', '/AA', '/Launch', '/EmbeddedFile', '/XFA'].filter(x => r.pdf.keys[x]); if(k.length) add(k.some(x => /JS|JavaScript|Launch/.test(x)) ? 18 : 10, 'PDF with active content: ' + k.join(', ')); }
  /* executables */
  if(r.pe){ const p = r.pe;
    if(p.packers.length) add(12, 'Packed (' + p.packers.join(', ') + ') — the real code is hidden until it runs');
    const hot = p.secs.filter(s => s.ent > 7.2 && s.rs > 4096); if(hot.length) add(10, hot.length + ' section' + (hot.length > 1 ? 's' : '') + ' with near-random entropy (' + hot.map(s => s.name).join(', ') + ') — packed or encrypted code');
    if(p.suspicious.length >= 3) add(Math.min(14, 4 + p.suspicious.length * 2), 'Imports often used by malware: ' + p.suspicious.slice(0, 5).join(', '));
    const fn = p.imports.reduce((a, d) => a + d.fns.length, 0); if(p.imports.length && fn <= 6) add(8, 'Only ' + fn + ' imported functions — it resolves the rest at run time to hide them');
    if(/^(19[0-9]{2}|20[0-9]{2})/.test(p.compiled || '') && (+p.compiled.slice(0, 4) < 2000 || Date.parse(p.compiled) > Date.now() + 864e5)) add(6, 'Compile time ' + p.compiled + ' is impossible — it was tampered with'); }
  /* data hiding */
  if(r.trailing && !/^(zip|pdf)$/.test(T.ext || '')) add(12, fmtBytes(r.size - r.trailing) + ' of data hidden after the end of the ' + (T.name || 'file'));
  const inner = (r.carve || []).filter(([o, n]) => o > 512 && !(T.ext === 'zip' && n === 'ZIP') && !(T.ext === 'pdf'));
  const mz = r.bytes ? (() => { let n = 0; const b = r.bytes, L = Math.min(b.length, 20e6); for(let i = 512; i < L - 64 && n < 3; i++) if(b[i] === 0x4d && b[i + 1] === 0x5a){ const pe = b[i + 0x3c] | (b[i + 0x3d] << 8); if(pe > 0 && pe < 1024 && b[i + pe] === 0x50 && b[i + pe + 1] === 0x45) n++; } return n; })() : 0;
  if(mz) add(18, mz + ' Windows program' + (mz > 1 ? 's' : '') + ' embedded inside the file');
  else if(inner.length) add(6, 'Other files embedded inside: ' + [...new Set(inner.map(x => x[1]))].slice(0, 4).join(', '));
  if(!/^(png|jpg|gif|zip|gz|7z|rar|mp3|mp4|mkv|pdf|ogg|flac|riff|xz|bz2)$/.test(T.ext || '') && r.entropy > 7.5 && r.size > 4096) add(10, 'Almost random content (entropy ' + r.entropy.toFixed(2) + '), unusual for ' + (T.name ? T.name.toLowerCase() : 'this kind of') + ' content — encrypted or packed');
  /* strings */
  const text = (r.strings || []).map(s => s[1]).join('\n').slice(0, 2e6) + '\n' + (r.trailPreview || ''), hitStr = new Set();
  for(const [re, w, t] of TRI_STR) if(re.test(text) && !hitStr.has(t)){ hitStr.add(t); add(w, t); }
  /* indicators */
  const net = (r.iocs || []).filter(e => /^(url|domain|ipv4|ipv6|hostport)$/.test(e.k) && !(e.k === 'ipv4' && !/^Public/.test(E.ipClass(e.v))));
  if(net.length && !/^(html|xml|pdf)$/.test(T.ext || '')) add(Math.min(10, 3 + net.length), net.length + ' network address' + (net.length > 1 ? 'es' : '') + ' inside: ' + net.slice(0, 3).map(e => e.v).join(', '));
  const known = (r.iocs || []).filter(e => verdictOf(e.k + ':' + e.v) === 'malicious' || (typeof CTI !== 'undefined' && CTI.iocIx && CTI.iocIx.get(e.k + ':' + e.v) && iocLive(CTI.iocIx.get(e.k + ':' + e.v))));
  if(known.length) add(30, 'Contains indicators already known as malicious: ' + known.slice(0, 3).map(e => e.v).join(', '));
  /* the hash itself */
  const H = typeof cpHist === 'function' ? cpHist() : new Map();
  for(const [k, h] of [['sha256', r.sha256], ['sha1', r.sha1], ['md5', r.md5]]){ if(!h) continue; const key = k + ':' + h, v = verdictOf(key), lh = H.get(key), feed = typeof CTI !== 'undefined' && CTI.iocIx && CTI.iocIx.get(key);
    if(v === 'malicious') { add(45, 'You marked this file malicious before'); break; }
    if(v === 'benign') { add(-40, 'You marked this file benign before'); break; }
    if(feed && iocLive(feed)){ add(45, 'In your threat feeds' + (feed.threat ? ': ' + feed.threat : '')); break; }
    if(lh && /malicious|suspicious/.test(lh.band)){ add(lh.band === 'malicious' ? 45 : 20, 'Live lookups scored it ' + lh.score + ' (' + lh.band + ')'); break; }
    if(lh && lh.band === 'benign'){ add(-25, 'Live lookups found it benign'); break; } }
  const others = DB.records.filter(x => x.source === 'forensics-kit' && (x.body || '').includes(r.sha256)).map(x => (theCase(x.caseId) || {}).code).filter(Boolean);
  if(others.length) add(0, 'Seen before in ' + [...new Set(others)].join(', '), 'lo');
  /* YARA, when it has been run */
  const yh = r.yara ? r.yara.filter(x => x.match) : []; if(yh.length) add(Math.min(40, 20 + yh.length * 5), 'YARA: ' + yh.slice(0, 3).map(x => x.rule).join(', '));
  /* plain media with nothing else is reassuring */
  if(!R.some(x => x.w > 0) && /^(png|jpg|gif|mp3|mp4|txt)$/.test(T.ext || '')) add(-10, 'Ordinary ' + T.name + ' with nothing unusual found');
  const pos = R.filter(x => x.w > 0).map(x => x.w).sort((a, b) => b - a), neg = R.filter(x => x.w < 0).reduce((a, x) => a + x.w, 0);
  /* diminishing returns: the strongest reason counts fully, each next one a little less */
  let s = pos.reduce((a, w, i) => a + w * Math.pow(0.85, i), 0) + neg; s = Math.max(0, Math.min(100, Math.round(s)));
  const band = s >= 60 ? 'malicious' : s >= 30 ? 'suspicious' : s >= 10 ? 'unusual' : 'clean';
  return (r.triage = {score:s, band, reasons:R.sort((a, b) => b.w - a.w), yaraN:r.yara ? r.yara.length : -1, map:r.bytes ? entropyMap(r.bytes) : []});
}
const TRI_COL = {malicious:'var(--red)', suspicious:'var(--amber)', unusual:'var(--accent)', clean:'var(--green)'};
const TRI_NAME = {malicious:'Likely malicious', suspicious:'Suspicious', unusual:'Some unusual traits', clean:'Nothing alarming'};
function entropySvg(map, size){
  if(!map.length) return ''; const W = 600, H = 56, bw = W / map.length;
  return `<svg class="tri-ent" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="Entropy across the file, from start to end">
    ${map.map((x, i) => { const h = Math.max(1, x.e / 8 * (H - 4)), c = x.e > 7.2 ? 'var(--red)' : x.e > 6 ? 'var(--amber)' : 'var(--accent)'; return `<rect x="${(i * bw).toFixed(1)}" y="${(H - h).toFixed(1)}" width="${Math.max(1, bw - 1).toFixed(1)}" height="${h.toFixed(1)}" fill="${c}" opacity=".85"><title>0x${x.o.toString(16)} · entropy ${x.e.toFixed(2)}</title></rect>`; }).join('')}
    <line x1="0" x2="${W}" y1="${(H - 7.2 / 8 * (H - 4)).toFixed(1)}" y2="${(H - 7.2 / 8 * (H - 4)).toFixed(1)}" stroke="var(--red)" stroke-dasharray="3 3" stroke-width="1" opacity=".5"/></svg>
    <div class="tri-axis"><span>0x0</span><span>Entropy across the file — red above 7.2 is packed or encrypted</span><span>${fmtBytes(size)}</span></div>`;
}
function triageCard(r){
  const T = fileTriage(r), top = T.reasons.filter(x => x.w !== 0).slice(0, 8), info = T.reasons.filter(x => x.w === 0);
  const lookOn = typeof lkFor === 'function' && lkFor('sha256').some(lkOn);
  return `<section class="card tri" style="--c:${TRI_COL[T.band]}"><div class="tri-h">${typeof vdRing === 'function' ? vdRing({score:T.score, band:T.band === 'clean' ? 'benign' : T.band === 'unusual' ? 'clean' : T.band}, 64) : ''}
      <div class="tri-v"><b>${esc(TRI_NAME[T.band])}</b><span class="t3">File triage · ${T.reasons.filter(x => x.w > 0).length} warning sign${T.reasons.filter(x => x.w > 0).length === 1 ? '' : 's'}${r.yara ? '' : ' · YARA not run yet'}</span></div>
      <div class="tri-a">${!r.yara ? `<button class="btn sm" data-act="labYara">${ico('play','sm')}Run YARA</button>` : ''}${lookOn ? `<button class="btn sm" data-act="lookEnt" data-id="${esc('sha256:' + r.sha256)}">${ico('radar','sm')}Check the hash online</button>` : ''}
        ${T.band !== 'clean' ? `<button class="btn sm${T.band === 'malicious' ? ' primary' : ''}" data-act="triMark" data-v="${T.band === 'malicious' ? 'malicious' : 'suspicious'}">${ico('check','sm')}Mark ${T.band === 'malicious' ? 'malicious' : 'suspicious'}</button>` : ''}</div></div>
    ${top.length ? `<ul class="tri-r">${top.map(x => `<li class="${x.sev}"><i aria-hidden="true"></i><span>${esc(x.t)}</span><small>${x.w > 0 ? '+' + x.w : x.w}</small></li>`).join('')}</ul>` : ''}
    ${info.length ? `<p class="t3 tri-i">${info.map(x => esc(x.t)).join(' · ')}</p>` : ''}
    ${entropySvg(T.map, r.size)}
    <p class="heur">Weighs traits malware often has. A high score is a reason to look closer in a sandbox, not proof.</p></section>`;
}
const TRI_ACTS = {
  triMark:(id, v) => { const r = UI.labFile; if(!r) return; const keys = ['sha256:' + r.sha256, 'md5:' + r.md5].filter(k => !k.endsWith(':')); const old = keys.map(k => DB.verdicts[k]);
    keys.forEach(k => DB.verdicts[k] = v); r.triage = null; mutate('marked ' + r.name + ' ' + v); renderMain(); toast(r.name + ' marked ' + v, 'Undo', () => { keys.forEach((k, i) => { if(old[i]) DB.verdicts[k] = old[i]; else delete DB.verdicts[k]; }); r.triage = null; mutate('undo'); renderMain(); }); },
};
