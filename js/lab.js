/* ==========================================================================
   Lab: CTF tracker, forensics kit (file inspector, timestamps, hash ID,
   coordinates), flag finder — plus sample-data management.
   Every file is read locally with the File API. Nothing is uploaded.
   ========================================================================== */

/* ---------- sample data ---------- */
const SAMPLE_CASES = ['c-lantern', 'c-portal', 'c-lab', 'c-empty'];
function ensureSample(){
  if(DB.sample === undefined) DB.sample = DB.cases.some(c => SAMPLE_CASES.includes(c.id));
  for(const c of DB.cases) if(SAMPLE_CASES.includes(c.id)) c.sample = true;
  for(const n of DB.notes || []) if(/^n[1-5]$/.test(n.id)) n.sample = true;
  for(const f of DB.feed) if(!f.live) f.sample = true;
  /* older saves had an empty “Untitled case” — swap in the lab case once */
  if(DB.sample && !DB.labAdded){
    DB.labAdded = true;
    const e = DB.cases.find(c => c.id === 'c-empty'); if(e && !DB.entries.some(x => x.caseId === 'c-empty') && !DB.records.some(x => x.caseId === 'c-empty')) DB.cases = DB.cases.filter(c => c !== e);
    if(!DB.cases.some(c => c.id === 'c-lab')){ const s = seedDB();
      DB.cases.push(...s.cases.filter(c => c.id === 'c-lab').map(c => ({...c, sample:true})));
      DB.entries.push(...s.entries.filter(x => x.caseId === 'c-lab')); DB.records.push(...s.records.filter(x => x.caseId === 'c-lab')); DB.links.push(...s.links.filter(x => x.caseId === 'c-lab').map(l => ({...l, id:uid('l')})));
      if(!DB.cases.some(c => c.id === DB.active)) DB.active = DB.cases[0].id; }
  }
}
function removeSample(){
  const ids = new Set(DB.cases.filter(c => c.sample).map(c => c.id));
  const n = {cases:ids.size, notes:(DB.notes || []).filter(x => x.sample || ids.has(x.caseId)).length, feed:DB.feed.filter(f => f.sample).length, ctf:((DB.ctf || {}).chals || []).filter(c => c.sample).length};
  confirmDlg('Remove all sample data?', `Deletes the ${n.cases} sample cases (with their entries, evidence and graph), ${n.notes} sample notes, ${n.feed} sample news items and ${n.ctf} sample CTF challenges. Your own work, tools, queries, rules and playbooks stay. You can undo right after.`, 'Remove sample data', () => {
    snapshot('Before removing sample data'); const prev = JSON.parse(JSON.stringify(DB)), seedV = seedDB().verdicts;
    DB.cases = DB.cases.filter(c => !ids.has(c.id)); DB.entries = DB.entries.filter(e => !ids.has(e.caseId)); DB.links = DB.links.filter(l => !ids.has(l.caseId)); DB.records = DB.records.filter(r => !ids.has(r.caseId));
    DB.notes = (DB.notes || []).filter(x => !x.sample && !ids.has(x.caseId)); DB.feed = DB.feed.filter(f => !f.sample);
    if(DB.ctf){ DB.ctf.chals = DB.ctf.chals.filter(c => !c.sample); DB.ctf.events = DB.ctf.events.filter(e => !e.sample || DB.ctf.chals.some(c => c.eventId === e.id)); }
    for(const [k, v] of Object.entries(seedV)) if(DB.verdicts[k] === v) delete DB.verdicts[k];
    DB.queryLog = (DB.queryLog || []).filter(l => !ids.has(l.caseId));
    if(!DB.cases.length) DB.cases.push({id:uid('c'), name:'My first case', code:'TN-' + new Date().getFullYear() + '-001', status:'active', owner:'You', created:Date.now(), updated:Date.now(), scope:'', color:CASE_COLORS[0], icon:'briefcase'});
    DB.active = DB.cases[0].id; DB.sample = false; UI.sel = null; UI.ctfSel = null; mutate('removed sample data'); go('#/home'); renderAll();
    toast('Sample data removed', 'Undo', () => { DB = prev; mutate('restored sample data'); renderAll(); }); });
}
const sampleBanner = () => (!storageOK ? `<div class="sbanner bad">${ico('triangle-alert','sm')}<div><b>This browser is not saving your work.</b> Storage is blocked here — a private window, blocked site data, or an embedded preview. Export everything before closing the tab.</div><button class="btn sm" data-act="exportAll">${ico('download','sm')}Export</button></div>` : '') + (DB.sample && DB.cases.some(c => c.sample) ? `<div class="sbanner">${ico('box','sm')}<div><b>You’re looking at sample data.</b> Three example investigations, notes, news and CTF challenges show how OSINTrix works.</div>
  <button class="btn sm" data-act="removeSample">${ico('trash-2','sm')}Remove sample data</button></div>` : '');

/* ---------- flags ---------- */
const FLAG_RE = /\b(?:flag|ctf|picoCTF|HTB|THM|DUCTF|UIUCTF|CSAW|[A-Za-z0-9_]{2,12}CTF|FLAG|CTF)\{[^}\s]{1,160}\}/g;
function findFlags(text){
  const set = new Set((String(text || '').match(FLAG_RE) || []));
  for(const ev of ((DB.ctf || {}).events || [])) if(ev.flagRe){ try{ for(const m of String(text).match(new RegExp(ev.flagRe, 'g')) || []) set.add(m); }catch(e){} }
  return [...set].slice(0, 20);
}
const flagBox = flags => flags.length ? `<div class="flagbox">${ico('flag','sm')}<b>${flags.length === 1 ? 'Flag-shaped string found' : flags.length + ' flag-shaped strings found'}</b>
  ${flags.map(f => `<span class="flag"><code>${esc(f)}</code><button class="btn xs" data-act="flagCopy" data-v="${esc(f)}">${ico('copy','sm')}Copy</button><button class="btn xs" data-act="flagToChal" data-v="${esc(f)}">${ico('trophy','sm')}Save to challenge</button></span>`).join('')}</div>` : '';

/* ---------- CTF tracker ---------- */
const CTF_CATS = {osint:['OSINT','#8b5cf6','search'], forensics:['Forensics','#0ea5a4','hard-drive'], crypto:['Crypto','#eab308','key-round'], web:['Web','#3b82f6','globe'],
  stego:['Stego','#ec4899','image'], rev:['Reversing','#f97316','binary'], pwn:['Pwn','#e5484d','bug'], misc:['Misc','#64748b','box'], network:['Network','#06b6d4','network']};
const ctfCat = k => CTF_CATS[k] || CTF_CATS.misc;
const CTF_STATUS = [['todo','To do','circle-dot'], ['working','Working','clock'], ['solved','Solved','check']];
function ensureCTF(){
  if(DB.ctf) return;
  const ev = {id:'ev-sample', name:'Sample CTF 2026', flagRe:'FLAG\\{[^}]+\\}', url:'', sample:true, created:Date.now()};
  const mk = (name, cat, points, status, extra) => ({id:uid('ch'), eventId:ev.id, name, cat, points, status, flag:'', notes:'', caseId:null, created:Date.now(), solvedAt:status === 'solved' ? Date.now() - 3600e3 : 0, sample:true, ...extra});
  DB.ctf = {events:[ev], chals:[
    mk('Harbour lights', 'osint', 300, 'working', {caseId:'c-lab', notes:'Photo → EXIF GPS → Oslo harbour. Uploader @k3lpie_sails.\nTrailing base64 after the JPEG end marker — decode it for the flag.'}),
    mk('Who registered it?', 'osint', 150, 'solved', {flag:'FLAG{wh01s_n3v3r_f0rg3ts}', notes:'Historic WHOIS on the phishing domain showed the registrant email before privacy was turned on.'}),
    mk('Memory lane', 'forensics', 400, 'todo', {notes:'Volatility: check pslist, netscan and cmdline for the odd process.'}),
    mk('Packet whisper', 'network', 250, 'todo', {notes:'DNS queries with long base32 subdomains — exfil over DNS?'}),
    mk('Rot in peace', 'crypto', 100, 'solved', {flag:'FLAG{c4es4r_w4s_h3r3}', notes:'ROT13 then Base64. Decoder → ROT13, then Base64 decode.'}),
    mk('Hidden layers', 'stego', 200, 'todo', {notes:'PNG with a tEXt chunk and data after IEND. File inspector shows both.'}),
  ]};
}
function viewCTF(){
  ensureCTF();
  const C = DB.ctf, evId = UI.ctfEv && C.events.some(e => e.id === UI.ctfEv) ? UI.ctfEv : 'all', q = (UI.ctfq || '').toLowerCase(), cf = UI.ctfCat || '';
  const list = C.chals.filter(c => (evId === 'all' || c.eventId === evId) && (!cf || c.cat === cf) && (!q || (c.name + ' ' + c.notes + ' ' + c.flag).toLowerCase().includes(q)));
  const solved = list.filter(c => c.status === 'solved'), pts = solved.reduce((s, c) => s + (+c.points || 0), 0), total = list.reduce((s, c) => s + (+c.points || 0), 0);
  const cur = C.chals.find(c => c.id === UI.ctfSel);
  const byCat = countBy(list, c => c.cat);
  const card = c => { const [cn, col, ic] = ctfCat(c.cat), ev = C.events.find(e => e.id === c.eventId), cs = c.caseId ? theCase(c.caseId) : null;
    return `<article class="chal${c.status === 'solved' ? ' done' : ''}" style="--c:${col}"><button class="gcard-hit" data-act="ctfSel" data-id="${c.id}" aria-label="Open ${esc(c.name)}"></button>
      <div class="chal-h"><span class="chal-ic">${ico(ic,'sm')}</span><span class="chal-cat">${esc(cn)}</span><span class="chal-pts">${esc(c.points || 0)} pts</span></div>
      <h3>${esc(c.name)}</h3>
      ${c.status === 'solved' && c.flag ? `<code class="chal-flag">${esc(c.flag)}</code>` : c.notes ? `<p>${esc(c.notes.split('\n')[0])}</p>` : ''}
      <div class="chal-f">${evId === 'all' && ev ? `<span class="t3">${esc(ev.name)}</span>` : ''}${cs ? `<span class="chal-case" style="--cc:${esc(cs.color)}">${esc(cs.code)}</span>` : ''}</div></article>`; };
  return `<div class="scroll"><div class="page wide">
    ${libHead('CTF', 'Track challenges, flags and write-ups. Link a challenge to a case to keep the evidence next to it.',
      `<button class="btn" data-act="ctfEvNew">${ico('flag','sm')}New event</button><button class="btn" data-act="ctfExport">${ico('download','sm')}Export write-ups</button><button class="btn primary" data-act="ctfNew">${ico('plus','sm')}New challenge</button>`, '')}
    <div class="ctf-sum">
      <div class="ctf-score"><div><b>${pts}</b><span>of ${total} points</span></div><div><b>${solved.length}/${list.length}</b><span>solved</span></div></div>
      <div class="ctf-cats">${Object.entries(CTF_CATS).filter(([k]) => byCat.some(([c]) => c === k)).map(([k, [n, col]]) => { const all = list.filter(c => c.cat === k), d = all.filter(c => c.status === 'solved').length;
        return `<button class="ctf-cat" data-act="ctfCat" data-v="${cf === k ? '' : k}" aria-pressed="${cf === k}" style="--c:${col}"><span>${esc(n)}</span><b>${d}/${all.length}</b><i><u style="width:${all.length ? Math.round(d / all.length * 100) : 0}%"></u></i></button>`; }).join('')}</div>
    </div>
    <div class="toolbar ltb"><div class="search-in">${ico('search')}<label class="sr" for="ctfq">Search challenges</label><input id="ctfq" class="inp" placeholder="Search challenges, notes, flags…" value="${esc(UI.ctfq || '')}"></div>
      <label class="sr" for="ctfEvSel">Event</label><select id="ctfEvSel" class="gsel bord"><option value="all">All events</option>${C.events.map(e => `<option value="${e.id}"${evId === e.id ? ' selected' : ''}>${esc(e.name)}</option>`).join('')}</select>
      ${evId !== 'all' ? `<button class="btn sm ghost" data-act="ctfEvEdit" data-id="${evId}">${ico('pencil','sm')}Event settings</button>` : ''}</div>
    ${list.length ? `<div class="kanban">${CTF_STATUS.map(([s, l, ic]) => { const col = list.filter(c => c.status === s).sort((a, b) => (b.points || 0) - (a.points || 0));
      return `<section class="kcol"><header>${ico(ic,'sm')}<h3>${l}</h3><span>${col.length}</span></header><div class="kcards">${col.map(card).join('') || '<p class="kempty">Nothing here.</p>'}</div></section>`; }).join('')}</div>`
      : empty('flag','No challenges yet','Add the challenges from your CTF or lab and track flags and notes as you solve them.', `<button class="btn primary" data-act="ctfNew">${ico('plus','sm')}New challenge</button>`)}
  </div></div>${cur ? drawer(ctfEditor(cur), 'ctfClose', cur.name, ico(ctfCat(cur.cat)[2],'sm') + 'Challenge') : ''}`;
}
function ctfEditor(c){
  const C = DB.ctf, ev = C.events.find(e => e.id === c.eventId), fmt = ev && ev.flagRe;
  let ok = null; if(c.flag){ try{ ok = fmt ? new RegExp('^(?:' + fmt + ')$').test(c.flag) : FLAG_RE.test(c.flag); }catch(e){ ok = null; } FLAG_RE.lastIndex = 0; }
  return `<form data-form="chal" data-id="${c.id}" class="chalf">
    <label class="sr" for="chN">Name</label><input id="chN" class="rx-title" value="${esc(c.name)}" required placeholder="Challenge name">
    <div class="seg full chal-st">${CTF_STATUS.map(([s, l, ic]) => `<button type="button" data-act="chStatus" data-v="${s}" aria-pressed="${c.status === s}">${ico(ic,'sm')}${l}</button>`).join('')}</div>
    <div class="frow"><div class="field"><label for="chC">Category</label><select id="chC">${Object.entries(CTF_CATS).map(([k, [n]]) => `<option value="${k}"${c.cat === k ? ' selected' : ''}>${n}</option>`).join('')}</select></div>
      <div class="field"><label for="chP">Points</label><input id="chP" type="number" min="0" step="10" value="${esc(c.points || 0)}"></div></div>
    <div class="frow"><div class="field"><label for="chE">Event</label><select id="chE">${C.events.map(e => `<option value="${e.id}"${c.eventId === e.id ? ' selected' : ''}>${esc(e.name)}</option>`).join('')}</select></div>
      <div class="field"><label for="chK">Linked case</label><select id="chK"><option value="">None</option>${DB.cases.map(x => `<option value="${x.id}"${c.caseId === x.id ? ' selected' : ''}>${esc(x.code + ' · ' + x.name.split(' — ')[0])}</option>`).join('')}</select></div></div>
    <div class="field"><label for="chF">Flag</label><div class="chal-flagin"><input id="chF" class="mono" value="${esc(c.flag)}" placeholder="${esc(fmt ? 'Format: ' + fmt : 'FLAG{…}')}" autocomplete="off" spellcheck="false">
      <button type="button" class="btn" data-act="flagCopy" data-v="${esc(c.flag)}" aria-label="Copy flag">${ico('copy','sm')}</button></div>
      ${c.flag ? `<span class="hint" style="color:${ok ? 'var(--green)' : ok === false ? 'var(--amber)' : 'var(--text-3)'}">${ok ? 'Matches the event’s flag format.' : ok === false ? 'Does not match the event’s flag format — check for typos.' : ''}</span>` : ''}</div>
    <div class="field"><label for="chW">Notes & write-up</label><textarea id="chW" rows="12" placeholder="What you tried, what worked, commands, links. Exported as Markdown.">${esc(c.notes)}</textarea></div>
    <div class="chal-acts">${c.caseId ? `<a class="btn" href="${caseHash(c.caseId)}">${ico('folder-open','sm')}Open linked case</a>` : `<button type="button" class="btn" data-act="chCase" data-id="${c.id}">${ico('folder-open','sm')}Create a case for it</button>`}
      <button type="button" class="btn ghost dangerhov" data-act="chDelAsk" data-id="${c.id}">${ico('trash-2','sm')}Delete</button></div>
    <div class="rx-f"><span class="t3 rx-kb">${c.solvedAt ? 'Solved ' + esc(E.fmtAgo(Date.now() - c.solvedAt)) : 'Not solved yet'}</span><span style="flex:1"></span><button class="btn" type="button" data-act="ctfClose">Close</button><button class="btn primary" type="submit">${ico('check','sm')}Save</button></div></form>`;
}
function ctfSubmit(f){
  const c = DB.ctf.chals.find(x => x.id === f.dataset.id); if(!c) return;
  const status = f.dataset.status || c.status;
  const nm = $('chN').value.trim().replace(/\s+/g, ' '); if(!nm) return fieldErr('chN', 'Name is required.'); if(!checkLen('chN', nm, 140, 'Name')) return;
  if(clash(DB.ctf.chals.filter(x => x.eventId === $('chE').value), nm, 'name', c.id)) return fieldErr('chN', `This event already has a challenge called “${nm}”.`);
  if(!/^\d{0,6}$/.test($('chP').value.trim())) return fieldErr('chP', 'Points must be a whole number from 0 to 999999.');
  if(!checkLen('chF', $('chF').value.trim(), 400, 'Flag') || !checkLen('chW', $('chW').value, 20000, 'Notes')) return;
  Object.assign(c, {name:nm, cat:$('chC').value, points:Math.max(0, parseInt($('chP').value, 10) || 0), eventId:$('chE').value, caseId:$('chK').value || null,
    flag:$('chF').value.trim().slice(0, 400), notes:$('chW').value.slice(0, 20000), status});
  if(c.flag && c.status !== 'solved' && !f.dataset.status) c.status = 'solved';
  if(c.status === 'solved' && !c.solvedAt) c.solvedAt = Date.now(); if(c.status !== 'solved') c.solvedAt = 0;
  mutate('saved challenge ' + c.name); renderMain(); toast(c.status === 'solved' ? 'Solved — nice work' : 'Challenge saved');
}
function ctfEventDlg(id){
  const e = id ? DB.ctf.events.find(x => x.id === id) : {name:'', flagRe:'', url:''};
  openDlg(dhead(id ? 'Event settings' : 'New CTF event') + `<form data-form="ctfEv" data-id="${id || ''}"><div class="in">
    <div class="field"><label for="evN">Name</label><input id="evN" value="${esc(e.name)}" required autofocus placeholder="DownUnderCTF 2026"></div>
    <div class="field"><label for="evR">Flag format (regular expression)</label><input id="evR" class="mono" value="${esc(e.flagRe || '')}" placeholder="DUCTF\\{[^}]+\\}"><span class="hint">Used to check flags and to spot them in the Decoder and File inspector.</span></div>
    <div class="field" style="margin:0"><label for="evU">Event URL</label><input id="evU" type="url" value="${esc(e.url || '')}" placeholder="https://…"></div></div>
    <footer>${id ? `<button class="btn danger" type="button" data-act="ctfEvDel" data-id="${id}" style="margin-right:auto">${ico('trash-2','sm')}Delete event</button>` : ''}<button class="btn" type="button" data-act="dclose">Cancel</button><button class="btn primary" type="submit">Save</button></footer></form>`);
}
function ctfWriteups(){
  const C = DB.ctf, evs = UI.ctfEv && UI.ctfEv !== 'all' ? C.events.filter(e => e.id === UI.ctfEv) : C.events;
  const L = [];
  for(const ev of evs){ const ch = C.chals.filter(c => c.eventId === ev.id); if(!ch.length) continue;
    const pts = ch.filter(c => c.status === 'solved').reduce((s, c) => s + (+c.points || 0), 0);
    L.push('# ' + ev.name, '', `Solved ${ch.filter(c => c.status === 'solved').length} of ${ch.length} · ${pts} points`, '');
    for(const [k, [n]] of Object.entries(CTF_CATS)){ const cc = ch.filter(c => c.cat === k); if(!cc.length) continue; L.push('## ' + n, '');
      for(const c of cc){ L.push(`### ${c.name} (${c.points || 0} pts) — ${c.status === 'solved' ? 'solved' : c.status}`, ''); if(c.flag) L.push('Flag: `' + c.flag + '`', ''); if(c.notes) L.push(c.notes, ''); } } }
  download('ctf-writeups.md', L.join('\n') || '# No challenges', 'text/markdown');
}

/* ---------- forensics kit ---------- */
const LAB_TABS = [['file','File inspector','file-search'], ['logs','Log parser','scan-text'], ['pcap','PCAP','network'], ['sqlite','SQLite','database'], ['image','Image','image'], ['email','Email headers','mail'], ['time','Time & IDs','clock-3'], ['hash','Hashes','fingerprint'], ['geo','Coordinates','compass'], ['net','Network','network'], ['gen','Generators','users']];
function viewLab(){
  const t = LAB_TABS.some(x => x[0] === UI.labTab) ? UI.labTab : 'file';
  const body = {file:labFile, logs:labParse, pcap:labPcap, sqlite:labSql, image:labImage, email:labEmail, time:labTime, hash:labHash, geo:labGeo, net:labNet, gen:labGen}[t]();
  return `<div class="scroll"><div class="page wide">
    ${libHead('Forensics kit', 'Inspect files and images, read email headers, decode timestamps and IDs, identify hashes — entirely in your browser. Nothing is uploaded.', '', '')}
    <nav class="labtabs" role="tablist">${LAB_TABS.map(([k, l, i]) => `<button role="tab" data-act="labTab" data-v="${k}" aria-selected="${t === k}">${ico(i,'sm')}${l}</button>`).join('')}</nav>
    ${body}</div></div>`;
}
/* file inspector */
const MAGIC = [
  ['89504e470d0a1a0a','PNG image','png'], ['ffd8ff','JPEG image','jpg'], ['474946383','GIF image','gif'], ['25504446','PDF document','pdf'], ['504b0304','ZIP archive (also DOCX/XLSX/APK/JAR)','zip'],
  ['504b0506','ZIP archive (empty)','zip'], ['1f8b08','GZIP','gz'], ['377abcaf271c','7-Zip archive','7z'], ['526172211a07','RAR archive','rar'], ['4d5a','Windows executable (PE/MZ)','exe'],
  ['7f454c46','ELF executable','elf'], ['cafebabe','Java class / Mach-O fat','class'], ['cffaedfe','Mach-O 64-bit','macho'], ['53514c69746520666f726d6174203300','SQLite database','sqlite'],
  ['d4c3b2a1','PCAP capture','pcap'], ['a1b2c3d4','PCAP capture','pcap'], ['0a0d0d0a','PCAPNG capture','pcapng'], ['494433','MP3 audio (ID3)','mp3'], ['52494646','RIFF (WAV/AVI/WEBP)','riff'],
  ['0000001866747970','MP4 video','mp4'], ['0000002066747970','MP4 video','mp4'], ['1a45dfa3','Matroska / WebM','mkv'], ['d0cf11e0a1b11ae1','OLE2 (old Office DOC/XLS, MSI)','doc'],
  ['425a68','BZIP2','bz2'], ['fd377a585a00','XZ','xz'], ['4c0000000114020000000000c000000000000046','Windows shortcut (LNK)','lnk'], ['7b5c727466','RTF document','rtf'],
  ['424d','BMP image','bmp'], ['49492a00','TIFF image','tif'], ['4d4d002a','TIFF image','tif'], ['00000100','ICO icon','ico'], ['2321','Script (shebang)','sh'], ['3c3f786d6c','XML document','xml'], ['3c21444f43','HTML document','html'],
  ['4f676753','OGG','ogg'], ['664c6143','FLAC audio','flac'], ['2d2d2d2d2d424547494e','PEM key / certificate','pem'], ['4b444d','VMDK disk image','vmdk'], ['454d5202','Windows Event Log (EVT)','evt'], ['456c6646696c65','Windows Event Log (EVTX)','evtx'], ['72656766','Windows registry hive','reg']];
const hex = (b, n) => [...b.slice(0, n)].map(x => x.toString(16).padStart(2, '0')).join('');
function sniff(b){ const h = hex(b, 24); for(const [m, n, ext] of MAGIC) if(h.startsWith(m)) return {name:n, ext}; const s = new TextDecoder().decode(b.slice(0, 512));
  if(/^[\x09\x0a\x0d\x20-\x7e -￿]*$/.test(s)) return {name:'Text', ext:'txt'}; return {name:'Unknown binary', ext:''}; }
function entropy(b){ const f = new Array(256).fill(0); const n = Math.min(b.length, 8e6); for(let i = 0; i < n; i++) f[b[i]]++; let e = 0; for(const c of f) if(c){ const p = c / n; e -= p * Math.log2(p); } return e; }
function md5(bytes){ /* compact MD5 (RFC 1321) for local file hashing */
  const K = [], S = [7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21];
  for(let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32) >>> 0;
  const len = bytes.length, nb = ((len + 8) >> 6) + 1, W = new Uint32Array(nb * 16);
  for(let i = 0; i < len; i++) W[i >> 2] |= bytes[i] << ((i % 4) * 8);
  W[len >> 2] |= 0x80 << ((len % 4) * 8); W[nb * 16 - 2] = (len * 8) >>> 0; W[nb * 16 - 1] = Math.floor(len / 0x20000000);
  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  for(let o = 0; o < W.length; o += 16){ let A = a0, B = b0, C = c0, D = d0;
    for(let i = 0; i < 64; i++){ let F, g;
      if(i < 16){ F = (B & C) | (~B & D); g = i; } else if(i < 32){ F = (D & B) | (~D & C); g = (5 * i + 1) % 16; } else if(i < 48){ F = B ^ C ^ D; g = (3 * i + 5) % 16; } else { F = C ^ (B | ~D); g = (7 * i) % 16; }
      F = (F + A + K[i] + W[o + g]) >>> 0; A = D; D = C; C = B; B = (B + ((F << S[i]) | (F >>> (32 - S[i])))) >>> 0; }
    a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0; }
  return [a0, b0, c0, d0].map(x => [0, 8, 16, 24].map(s => ((x >>> s) & 255).toString(16).padStart(2, '0')).join('')).join('');
}
function strings(b, min = 6){ const out = []; const n = Math.min(b.length, 6e6); let cur = '', start = 0;
  for(let i = 0; i < n; i++){ const c = b[i]; if(c >= 32 && c < 127){ if(!cur) start = i; cur += String.fromCharCode(c); } else { if(cur.length >= min) out.push([start, cur]); cur = ''; } if(out.length > 4000) break; }
  if(cur.length >= min) out.push([start, cur]);
  /* UTF-16LE */ cur = ''; for(let i = 0; i + 1 < n && out.length < 6000; i += 2){ const c = b[i]; if(c >= 32 && c < 127 && b[i + 1] === 0){ if(!cur) start = i; cur += String.fromCharCode(c); } else { if(cur.length >= min) out.push([start, cur, 'u16']); cur = ''; } }
  return out.sort((x, y) => x[0] - y[0]);
}
function exif(b){
  if(!(b[0] === 0xff && b[1] === 0xd8)) return null;
  let o = 2; while(o < b.length - 4){ if(b[o] !== 0xff) break; const m = b[o + 1], l = (b[o + 2] << 8) | b[o + 3];
    if(m === 0xe1 && String.fromCharCode(...b.slice(o + 4, o + 10)) === 'Exif\0\0') return parseTiff(b, o + 10); if(m === 0xda) break; o += 2 + l; }
  return null;
}
function parseTiff(b, t){
  const le = b[t] === 0x49, u16 = p => le ? b[p] | (b[p + 1] << 8) : (b[p] << 8) | b[p + 1], u32 = p => (le ? (b[p] | (b[p + 1] << 8) | (b[p + 2] << 16) | (b[p + 3] << 24)) : ((b[p] << 24) | (b[p + 1] << 16) | (b[p + 2] << 8) | b[p + 3])) >>> 0;
  const NAMES = {0x10e:'Description',0x10f:'Make',0x110:'Model',0x112:'Orientation',0x131:'Software',0x132:'Modified',0x13b:'Artist',0x8298:'Copyright',0x9003:'Taken',0x9004:'Digitized',0xa434:'Lens',0xa430:'Owner',0xa431:'Body serial',0x9286:'User comment',0xa002:'Width',0xa003:'Height'};
  const GPSN = {1:'LatRef',2:'Lat',3:'LonRef',4:'Lon',5:'AltRef',6:'Alt',7:'GPSTime',0x1d:'GPSDate'};
  const out = {}, gps = {};
  const val = (type, cnt, p) => { const sz = {1:1,2:1,3:2,4:4,5:8,7:1,9:4,10:8}[type] || 1, total = sz * cnt, at = total > 4 ? t + u32(p) : p;
    if(type === 2) return String.fromCharCode(...b.slice(at, at + cnt)).replace(/\0+$/, '').trim();
    if(type === 3) return cnt === 1 ? u16(at) : Array.from({length:cnt}, (_, i) => u16(at + i * 2));
    if(type === 4 || type === 9) return u32(at);
    if(type === 5 || type === 10){ const r = Array.from({length:cnt}, (_, i) => { const n = u32(at + i * 8), d = u32(at + i * 8 + 4); return d ? n / d : 0; }); return cnt === 1 ? r[0] : r; }
    if(type === 7) return String.fromCharCode(...b.slice(at, at + Math.min(cnt, 200))).replace(/[^\x20-\x7e]/g, '').trim();
    return b[at]; };
  const ifd = (p, names, into, depth) => { if(p <= t || p >= b.length - 2 || depth > 3) return; const n = u16(p); if(n > 400) return;
    for(let i = 0; i < n; i++){ const e = p + 2 + i * 12; if(e + 12 > b.length) break; const tag = u16(e), type = u16(e + 2), cnt = u32(e + 4);
      try{ if(tag === 0x8769) ifd(t + u32(e + 8), names, into, depth + 1); else if(tag === 0x8825) ifd(t + u32(e + 8), GPSN, gps, depth + 1); else if(names[tag]) into[names[tag]] = val(type, cnt, e + 8); }catch(x){} } };
  ifd(t + u32(t + 4), NAMES, out, 0);
  if(Array.isArray(gps.Lat) && Array.isArray(gps.Lon)){ const d = a => a[0] + a[1] / 60 + a[2] / 3600; let la = d(gps.Lat), lo = d(gps.Lon); if(gps.LatRef === 'S') la = -la; if(gps.LonRef === 'W') lo = -lo; out.GPS = {lat:+la.toFixed(6), lon:+lo.toFixed(6), alt:typeof gps.Alt === 'number' ? Math.round(gps.Alt) : null}; }
  if(gps.GPSDate) out['GPS date'] = gps.GPSDate;
  return Object.keys(out).length ? out : null;
}
function pngInfo(b){
  if(hex(b, 8) !== '89504e470d0a1a0a') return null; const r = {chunks:[], text:[]}; let o = 8;
  while(o + 8 <= b.length){ const len = ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0, type = String.fromCharCode(...b.slice(o + 4, o + 8));
    r.chunks.push(type); if(type === 'IHDR'){ const d = b.slice(o + 8, o + 16); r.w = (d[0] << 24 | d[1] << 16 | d[2] << 8 | d[3]) >>> 0; r.h = (d[4] << 24 | d[5] << 16 | d[6] << 8 | d[7]) >>> 0; }
    if(type === 'tEXt' || type === 'iTXt'){ const s = new TextDecoder().decode(b.slice(o + 8, o + 8 + Math.min(len, 4000))).replace(/\0+/g, ' → '); r.text.push(s); }
    if(type === 'IEND'){ r.end = o + 12; break; } o += 12 + len; if(r.chunks.length > 2000) break; }
  return r;
}
function trailing(b, kind){
  if(kind === 'jpg'){ for(let i = b.length - 2; i > 2; i--) if(b[i] === 0xff && b[i + 1] === 0xd9) return i + 2 < b.length ? i + 2 : null; }
  if(kind === 'png'){ const p = pngInfo(b); return p && p.end && p.end < b.length ? p.end : null; }
  if(kind === 'zip'){ for(let i = b.length - 22; i >= Math.max(0, b.length - 70000); i--) if(b[i] === 0x50 && b[i + 1] === 0x4b && b[i + 2] === 5 && b[i + 3] === 6){ const end = i + 22 + (b[i + 20] | (b[i + 21] << 8)); return end < b.length ? end : null; } }
  if(kind === 'pdf'){ const s = new TextDecoder('latin1').decode(b.slice(Math.max(0, b.length - 2048))); const k = s.lastIndexOf('%%EOF'); if(k >= 0){ const end = b.length - 2048 + k + 5; const rest = b.slice(Math.max(end, 0)); return rest.length > 4 && [...rest].some(x => x > 32) ? Math.max(end, 0) : null; } }
  return null;
}
function carve(b){ const sig = [['504b0304','ZIP'],['25504446','PDF'],['89504e47','PNG'],['ffd8ffe','JPEG'],['47494638','GIF'],['377abcaf','7-Zip'],['52617221','RAR'],['1f8b08','GZIP'],['7f454c46','ELF']];
  const out = [], n = Math.min(b.length, 20e6), H = []; for(let i = 1; i < n - 8; i++){ const x = b[i]; if(x !== 0x50 && x !== 0x25 && x !== 0x89 && x !== 0xff && x !== 0x47 && x !== 0x37 && x !== 0x52 && x !== 0x1f && x !== 0x7f) continue;
    const h = hex(b.slice(i, i + 4), 4); for(const [m, name] of sig) if(h.startsWith(m.slice(0, Math.min(8, m.length)))){ if(name === 'JPEG' && !(b[i + 1] === 0xd8)) continue; out.push([i, name]); break; } if(out.length >= 30) break; }
  return out; }
async function analyseFile(file){
  const buf = new Uint8Array(await file.arrayBuffer()), t = sniff(buf), ext = (file.name.split('.').pop() || '').toLowerCase();
  const [s256, s1] = await Promise.all(['SHA-256', 'SHA-1'].map(a => crypto.subtle ? crypto.subtle.digest(a, buf).then(h => hex(new Uint8Array(h), 64)) : Promise.resolve('')));
  const noise = noiseRanges(buf, t.ext), inNoise = o => noise.some(([a, b]) => o >= a && o < b), textFile = t.ext === 'txt' || t.ext === 'xml' || t.ext === 'html' || t.ext === 'sh' || t.ext === 'pem';
  const st = strings(buf).map(([o, s, u]) => [o, s, u, textFile || (!inNoise(o) && (wordy(s) || (s.length >= 16 && /[a-z]{3}/i.test(s))))]);
  const good = st.filter(x => x[3]), txt = good.map(x => x[1]).join('\n');
  const tr = trailing(buf, t.ext), trTxt = tr ? new TextDecoder('latin1').decode(buf.slice(tr, tr + 8000)) : '';
  const zip0 = t.ext === 'zip' ? await zipInfo(buf).catch(() => null) : null, zip = zip0;
  if(zip && zip.office){ t.name = 'Microsoft Office document (Open XML' + (zip.macros.length ? ', with macros' : '') + ')'; }
  const _z = 0, pdf = t.ext === 'pdf' ? pdfInfo(buf) : null, pe = t.ext === 'exe' ? peInfo(buf) : null, elf = t.ext === 'elf' ? elfInfo(buf) : null;
  let iocs = E.extract((txt + '\n' + trTxt).slice(0, 600000)); if(!textFile) iocs = iocs.filter(fileIocOK);
  if(zip && zip.external) iocs = iocs.concat(E.extract(zip.external.map(x => x[1]).join('\n')));
  if(pdf) iocs = iocs.concat(E.extract(pdf.uris.join('\n')));
  const seen = new Set(); iocs = iocs.filter(e => { const k = e.k + ':' + e.v; if(seen.has(k)) return false; seen.add(k); return true; });
  return {name:file.name, size:file.size, lastModified:file.lastModified, type:t, ext, file, bytes:buf,
    mismatch:t.ext && ext && !(t.ext === ext || (t.ext === 'jpg' && /jpe?g/.test(ext)) || (t.ext === 'zip' && /docx|xlsx|pptx|docm|xlsm|pptm|apk|jar|odt|ods|epub|vsix|nupkg|ipa/.test(ext)) || (t.ext === 'tif' && /tiff?/.test(ext)) || (t.ext === 'riff' && /wav|avi|webp/.test(ext)) || (t.ext === 'doc' && /xls|ppt|msi|msg|dot/.test(ext)) || (t.ext === 'exe' && /dll|sys|scr|ocx|cpl|efi/.test(ext)) || (t.ext === 'elf' && /so|ko|o|bin|out/.test(ext)) || t.ext === 'txt' || (t.ext === 'mp4' && /m4a|mov|m4v/.test(ext))),
    md5:buf.length <= 200e6 ? md5(buf) : '', sha1:s1, sha256:s256, entropy:entropy(buf), exif:exif(buf), png:pngInfo(buf), trailing:tr, trailPreview:trTxt.slice(0, 400),
    c2pa:/c2pa\./.test(txt) ? ((txt.match(/claim_generator[^\n]{0,80}/) || [''])[0].replace(/[^\x20-\x7e]/g, ' ') || 'present') : '',     carve:carve(buf).filter(([o]) => o > 0), strings:st, good:good.length, iocs, flags:findFlags(txt + '\n' + trTxt), head:buf.slice(0, 256), zip, pdf, pe, elf, noise:noise.length > 0};
}
const fmtBytes = n => n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : (n / 1048576).toFixed(2) + ' MB';
function hexdump(b){ const L = []; for(let o = 0; o < b.length; o += 16){ const row = b.slice(o, o + 16); L.push(o.toString(16).padStart(8, '0') + '  ' + [...row].map(x => x.toString(16).padStart(2, '0')).join(' ').padEnd(48) + '  ' + [...row].map(x => x >= 32 && x < 127 ? String.fromCharCode(x) : '.').join('')); } return L.join('\n'); }
const kvr = (k, v, mono) => v || v === 0 ? `<div class="kv"><span>${esc(k)}</span>${mono ? `<code>${esc(v)}</code>` : `<b>${esc(v)}</b>`}</div>` : '';
function fileStructure(r){
  let h = '';
  if(r.zip){ const z = r.zip;
    if(z.office){ h += `<section class="card"><header><h3>${ico('file-text','sm')} Office document metadata</h3></header><div class="body">${Object.entries(z.office).map(([k, v]) => kvr(k, v)).join('') || '<p class="t3">No metadata.</p>'}
      ${z.macros.length ? `<div class="note red" style="margin:10px 0 0"><span class="ic">${ico('triangle-alert','sm')}</span><div><b>Contains macros:</b> ${esc(z.macros.join(', '))}. Extract with <span class="mono">olevba</span> before opening.</div></div>` : ''}
      ${z.external.length ? `<div class="note amber" style="margin:10px 0 0"><span class="ic">${ico('link','sm')}</span><div><b>External links (possible remote template / tracking):</b>${z.external.slice(0, 10).map(([f, u]) => `<div class="mono" style="font-size:12px;overflow-wrap:anywhere">${esc(u)}</div>`).join('')}</div></div>` : ''}
      ${z.ole.length ? `<p class="t3" style="font-size:12.5px;margin:10px 0 0">Embedded objects: ${esc(z.ole.slice(0, 8).join(', '))}</p>` : ''}</div></section>`; }
    h += `<section class="card"><header><h3>${ico('box','sm')} Archive contents</h3><span class="t3">${z.files.length} files${z.encrypted ? ' · password-protected' : ''}</span></header>
      ${z.comment ? `<div class="body" style="padding-bottom:0">${kvr('Comment', z.comment, true)}</div>` : ''}
      <div class="ziplist">${z.files.slice(0, 300).map(f => `<div><span class="mono">${esc(f.name)}</span>${f.enc ? `<span class="pill" style="--c:var(--amber)">${ico('lock','sm')}encrypted</span>` : ''}<span class="t3">${fmtBytes(f.size)}</span><span class="t3 hide-m">${isFinite(f.date) ? new Date(f.date).toISOString().slice(0, 16).replace('T', ' ') : ''}</span></div>`).join('')}</div></section>`; }
  if(r.pdf){ const p = r.pdf, risky = ['/JS','/JavaScript','/OpenAction','/AA','/Launch','/EmbeddedFile','/XFA'].filter(k => p.keys[k]);
    h += `<section class="card"><header><h3>${ico('file-text','sm')} PDF structure</h3><span class="t3">PDF ${esc(p.version)}${p.updates ? ' · ' + p.updates + ' incremental update' + (p.updates > 1 ? 's' : '') : ''}</span></header><div class="body">
      ${Object.entries(p.info).map(([k, v]) => kvr(k, v)).join('')}
      <div class="pdfkeys">${Object.entries(p.keys).map(([k, n]) => `<span class="${n && ['/JS','/JavaScript','/OpenAction','/AA','/Launch','/EmbeddedFile','/XFA'].includes(k) ? 'hot' : ''}"><code>${esc(k)}</code><b>${n}</b></span>`).join('')}</div>
      ${risky.length ? `<div class="note red" style="margin:10px 0 0"><span class="ic">${ico('triangle-alert','sm')}</span><div><b>Active content:</b> ${esc(risky.join(', '))}. Inspect with <span class="mono">pdf-parser</span> in a sandbox.</div></div>` : '<p class="t3" style="font-size:12.5px;margin:10px 0 0">No JavaScript, auto-actions or embedded files.</p>'}
      ${p.uris.length ? `<div class="isec"><h4>Links in the document</h4>${p.uris.slice(0, 12).map(u => `<div class="mono" style="font-size:12px;overflow-wrap:anywhere">${esc(u)}</div>`).join('')}</div>` : ''}</div></section>`; }
  if(r.pe){ const p = r.pe;
    h += `<section class="card"><header><h3>${ico('cpu','sm')} Windows executable</h3></header><div class="body">${kvr('Type', p.kind)}${kvr('Machine', p.machine)}${kvr('Compiled', p.compiled)}${kvr('Subsystem', p.subsystem)}${kvr('Entry point', p.entry, true)}
      ${p.packers.length ? `<div class="note amber" style="margin:8px 0"><span class="ic">${ico('box','sm')}</span><div><b>Packer section names:</b> ${esc(p.packers.join(', '))}</div></div>` : ''}
      <table class="tbl secs"><thead><tr><th>Section</th><th>Raw size</th><th>Entropy</th></tr></thead><tbody>${p.secs.map(s => `<tr><td class="mono">${esc(s.name)}</td><td>${fmtBytes(s.rs)}</td><td style="color:${s.ent > 7.2 ? 'var(--red)' : s.ent > 6.5 ? 'var(--amber)' : 'inherit'}">${s.ent.toFixed(2)}</td></tr>`).join('')}</tbody></table>
      ${p.suspicious.length ? `<div class="isec"><h4>Imports worth a look</h4><div class="wrap">${p.suspicious.map(f => `<code class="chip sq">${esc(f)}</code>`).join('')}</div></div>` : ''}
      <details class="more"><summary>${p.imports.length} imported DLLs</summary>${p.imports.map(d => `<div class="imp"><b class="mono">${esc(d.dll)}</b><span class="mono">${esc(d.fns.slice(0, 40).join(', '))}${d.fns.length > 40 ? ' …' : ''}</span></div>`).join('')}</details></div></section>`; }
  if(r.elf){ const p = r.elf; h += `<section class="card"><header><h3>${ico('cpu','sm')} ELF binary</h3></header><div class="body">${kvr('Class', p.cls)}${kvr('Byte order', p.endian)}${kvr('Type', p.type)}${kvr('Machine', p.machine)}${kvr('Interpreter', p.interp, true)}</div></section>`; }
  return h;
}
function yaraPanel(r){
  const rules = (DB.rules || []).filter(x => x.type === 'yara'), res = r.yara;
  return `<section class="card"><header><h3>${ico('file-code','sm')} YARA scan</h3><span class="t3">${rules.length} rules in Detections</span><span style="flex:1"></span><button class="btn sm${res ? '' : ' primary'}" data-act="labYara">${ico('play','sm')}${res ? 'Scan again' : 'Scan this file'}</button></header>
    <div class="body">${!res ? '<p class="t3" style="margin:0;font-size:13.5px">Runs every YARA rule from Detections against this file, in the browser. Supports text, hex (with wildcards and jumps) and regex strings, and conditions like <span class="mono">any of them</span>, <span class="mono">2 of ($a*)</span>, <span class="mono">uint16(0) == 0x5A4D</span>, <span class="mono">filesize</span>. Module functions (<span class="mono">pe.</span>, <span class="mono">math.</span>) are reported as unsupported.</p>'
      : (() => { const hit = res.filter(x => x.match), bad = res.filter(x => x.error);
        return `<p style="margin:0 0 10px;font-size:14px"><b>${hit.length ? hit.length + ' rule' + (hit.length > 1 ? 's' : '') + ' matched' : 'No rule matched'}</b><span class="t3"> · ${res.length - bad.length} checked${bad.length ? ' · ' + bad.length + ' use features the browser engine does not support' : ''}</span></p>
          ${hit.map(x => `<div class="yhit">${ico('shield-alert','sm')}<b>${esc(x.rule)}</b><span class="mono t3">${Object.entries(x.strings).filter(([, v]) => v.hits.length).slice(0, 6).map(([n, v]) => esc(n) + '@0x' + v.hits[0].toString(16)).join('  ')}</span></div>`).join('')}
          ${bad.length ? `<details class="more"><summary>Unsupported rules</summary>${bad.map(x => `<div class="t3" style="font-size:12.5px"><b>${esc(x.rule)}</b> — ${esc(x.error)}</div>`).join('')}</details>` : ''}`; })()}</div></section>`;
}
function labFile(){
  const r = UI.labFile;
  if(!r) return `<label class="drop" id="labDrop" tabindex="0"><input type="file" id="labIn" class="sr">${ico('file-search')}<b>Drop a file here, or click to choose</b>
    <span>Images, Office documents, PDFs, archives, executables — up to 200 MB. Read locally; nothing is uploaded.</span>
    <span class="drop-feat"><i>Magic bytes</i><i>MD5 · SHA-1 · SHA-256</i><i>EXIF & GPS</i><i>Office & PDF metadata</i><i>Macros & active content</i><i>ZIP listing</i><i>PE / ELF headers</i><i>YARA scan</i><i>Appended data</i><i>Flag finder</i></span></label>`;
  if(r.busy) return `<div class="card" style="padding:40px;text-align:center">${ico('refresh-cw','sm spin')} Reading ${esc(r.name)}…</div>`;
  const eh = r.entropy, ehl = eh > 7.5 ? ['Very high — compressed or encrypted','var(--red)'] : eh > 6 ? ['High — packed or compressed data likely','var(--amber)'] : ['Normal','var(--green)'];
  const q = (UI.strq || '').toLowerCase(), showAll = !!UI.strAll, st = r.strings.filter(s => (showAll || s[3]) && (!q || s[1].toLowerCase().includes(q))).slice(0, 500);
  const hashRow = (l, v) => v ? `<div class="kv"><span>${l}</span><code>${esc(v)}</code><button class="iconbtn" data-act="flagCopy" data-v="${esc(v)}" aria-label="Copy ${l}">${ico('copy','sm')}</button></div>` : '';
  const G = r.exif && r.exif.GPS, isImg = /^(png|jpg|gif|bmp|riff)$/.test(r.type.ext);
  return `${flagBox(r.flags)}
  <div class="fi-grid">
    <div class="fi-side">
    <section class="card fi-sum"><header><span class="fi-ic">${ico('file-digit')}</span><div style="min-width:0;flex:1"><h3>${esc(r.name)}</h3><p class="t3">${fmtBytes(r.size)} · modified ${esc(new Date(r.lastModified).toISOString().slice(0, 16).replace('T', ' '))} UTC</p></div>
      <button class="btn sm" data-act="labClear">${ico('x','sm')}Another file</button></header>
      <div class="body">
        <div class="kv"><span>Detected type</span><b>${esc(r.type.name)}</b></div>
        ${r.mismatch ? `<div class="note amber" style="margin:6px 0 10px"><span class="ic">${ico('triangle-alert','sm')}</span><div>Extension <b>.${esc(r.ext)}</b> does not match the content (${esc(r.type.name)}). Classic trick — rename it and look again.</div></div>` : ''}
        ${hashRow('MD5', r.md5)}${hashRow('SHA-1', r.sha1)}${hashRow('SHA-256', r.sha256)}
        <div class="kv"><span>Entropy</span><b style="color:${ehl[1]}">${eh.toFixed(2)} / 8</b><span class="t3">${ehl[0]}</span></div>
        <div class="entbar"><i style="width:${eh / 8 * 100}%;background:${ehl[1]}"></i></div>
        ${/^(png|jpg|gif|zip|gz|7z|rar|mp3|mp4|mkv|pdf)$/.test(r.type.ext) && eh > 7.5 ? '<p class="t3" style="font-size:12.5px;margin:0 0 8px">High entropy is normal for this format — its content is compressed.</p>' : ''}
        ${pivotSection('sha256', r.sha256)}
        <div class="wrap" style="margin-top:14px"><button class="btn primary" data-act="labSave">${ico('plus','sm')}Save to ${esc(theCase().code)}</button><button class="btn" data-act="labReport">${ico('download','sm')}Download report</button>${isImg ? `<button class="btn" data-act="labToImage">${ico('image','sm')}Open in Image tools</button>` : ''}${/^pcap/.test(r.type.ext) ? `<button class="btn" data-act="labToPcap">${ico('network','sm')}Open in PCAP reader</button>` : ''}${r.type.ext === 'sqlite' ? `<button class="btn" data-act="labToSql">${ico('database','sm')}Open in SQLite viewer</button>` : ''}</div></div></section>
    ${yaraPanel(r)}
    </div>
    <div class="fi-side">
      ${fileStructure(r)}
      ${r.exif ? `<section class="card"><header><h3>${ico('image','sm')} EXIF metadata</h3></header><div class="body">${Object.entries(r.exif).filter(([k]) => k !== 'GPS').map(([k, v]) => `<div class="kv"><span>${esc(k)}</span><b>${esc(Array.isArray(v) ? v.join(', ') : v)}</b></div>`).join('')}
        ${G ? `<div class="gpsbox"><div>${ico('map-pin','sm')}<b>${G.lat}, ${G.lon}</b>${G.alt != null ? `<span class="t3"> · ${G.alt} m</span>` : ''}</div><div class="pivots">${geoLinks(G.lat, G.lon).map(([n, u]) => `<a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(n)}${ico('arrow-up-right','sm')}</a>`).join('')}</div></div>` : '<p class="t3" style="margin:8px 0 0;font-size:13px">No GPS tags.</p>'}</div></section>` : ''}
      ${r.c2pa ? `<section class="card"><header><h3>${ico('shield-check','sm')} Content Credentials (C2PA)</h3></header><div class="body"><p style="margin:0 0 8px;font-size:13.5px">This file carries a signed provenance manifest — who or what created or edited it. Readable parts appear in the strings below (look for <span class="mono">claim_generator</span>, <span class="mono">softwareAgent</span>).</p><div class="pivots"><a href="https://contentcredentials.org/verify" target="_blank" rel="noopener noreferrer">Verify on contentcredentials.org${ico('arrow-up-right','sm')}</a></div></div></section>` : ''}
      ${r.png ? `<section class="card"><header><h3>${ico('image','sm')} PNG structure</h3></header><div class="body"><div class="kv"><span>Size</span><b>${r.png.w} × ${r.png.h}</b></div><div class="kv"><span>Chunks</span><code style="white-space:normal">${esc([...new Set(r.png.chunks)].join(' '))}</code></div>
        ${r.png.text.map(t => `<div class="kv"><span>Text chunk</span><code style="white-space:normal">${esc(t.slice(0, 300))}</code></div>`).join('') || '<p class="t3" style="font-size:12.5px;margin:8px 0 0">No text chunks.</p>'}</div></section>` : ''}
      ${r.trailing ? `<section class="card warnc"><header><h3>${ico('triangle-alert','sm')} Data after the end of the file</h3><span class="t3">offset 0x${r.trailing.toString(16)} · ${fmtBytes(r.size - r.trailing)}</span></header><div class="body"><pre class="rawbox">${esc(r.trailPreview.replace(/[^\x09\x0a\x0d\x20-\x7e]/g, '.'))}</pre><button class="btn sm" data-act="labTrailDecode">${ico('binary','sm')}Open in Decoder</button></div></section>` : ''}
      ${r.carve.length ? `<section class="card"><header><h3>${ico('box','sm')} Embedded file signatures</h3><span class="t3">${r.carve.length}</span></header><div class="body">${r.carve.map(([o, n]) => `<div class="kv"><span class="mono">0x${o.toString(16).padStart(6, '0')}</span><b>${esc(n)}</b></div>`).join('')}<p class="t3" style="font-size:12.5px;margin:8px 0 0">Signatures can occur by chance inside compressed data. Carve with <span class="mono">binwalk -e</span> or <span class="mono">dd skip=${r.carve[0][0]}</span> to confirm.</p></div></section>` : ''}
      <section class="card"><header><h3>${ico('fingerprint','sm')} Indicators in the file</h3><span class="t3">${r.iocs.length}</span></header><div class="body"><div class="wrap">${r.iocs.slice(0, 60).map(e => `<span class="ent">${kindBadge(e.k)}<span class="v">${esc(e.v)}</span></span>`).join('') || '<span class="t3">None found.</span>'}</div>
        ${r.noise ? '<p class="t3" style="font-size:12.5px;margin:10px 0 0">Compressed image data is skipped — random bytes there only look like text by chance.</p>' : ''}</div></section>
    </div>
  </div>
  <div class="fi-grid2">
    <section class="card"><header><h3>Strings</h3><span class="t3">${r.good} readable${r.strings.length !== r.good ? ' · ' + r.strings.length + ' total' : ''}</span><span style="flex:1"></span>
      <label class="chk"><input type="checkbox" data-act="strAll" ${showAll ? 'checked' : ''}> Include noise</label><div class="search-in" style="max-width:220px">${ico('search')}<label class="sr" for="strq">Filter strings</label><input id="strq" class="inp" placeholder="Filter…" value="${esc(UI.strq || '')}"></div></header>
      <pre class="strs">${st.map(([o, s, u, g]) => `<span class="o">${o.toString(16).padStart(8, '0')}</span>${u ? '<span class="u">U</span>' : ' '} ${g ? '' : '<span class="nz">'}${esc(s.length > 300 ? s.slice(0, 300) + '…' : s)}${g ? '' : '</span>'}`).join('\n') || (showAll ? 'No strings match.' : 'No readable strings. Tick “Include noise” to see every printable run.')}</pre></section>
    <section class="card"><header><h3>First 256 bytes</h3></header><pre class="hexd">${esc(hexdump(r.head))}</pre></section>
  </div>`;
}
function bindLab(){
  const inp = $('labIn'), d = $('labDrop');
  if(inp){ inp.onchange = () => { if(inp.files[0]) labLoad(inp.files[0]); };
    d.ondragover = e => { e.preventDefault(); d.classList.add('over'); }; d.ondragleave = () => d.classList.remove('over');
    d.ondrop = e => { e.preventDefault(); d.classList.remove('over'); const f = e.dataTransfer.files[0]; if(f) labLoad(f); };
    d.onkeydown = e => { if(e.key === 'Enter' || e.key === ' '){ e.preventDefault(); inp.click(); } }; }
  const deb = (id, fn, ms = 120) => { const x = $(id); if(x) x.oninput = () => { clearTimeout(x.__t); x.__t = setTimeout(() => fn(x.value), ms); }; };
  deb('tsIn', v => { UI.tsIn = v; $('tsOut').innerHTML = tsTable(v); $('idOut').innerHTML = idTable(v); });
  deb('hashIn', v => { UI.hashIn = v; $('hashOut').innerHTML = hashTable(v); }, 60);
  deb('geoIn', v => { UI.geoIn = v; $('geoOut').innerHTML = geoOut(v); }, 60);
  deb('emlIn', v => { UI.emlIn = v; $('emlOut').innerHTML = emailOut(v); }, 200);
  deb('cidrIn', v => { UI.cidrIn = v; $('cidrOut').innerHTML = cidrOut(v); }, 60);
  deb('uaIn', v => { UI.uaIn = v; $('uaOut').innerHTML = uaOut(v); }, 60);
  deb('macIn', v => { UI.macIn = v; macOut(v); }, 150);
  deb('genName', v => { UI.genName = v; $('genOut').innerHTML = genOut(); }, 100); deb('genNums', v => { UI.genNums = v; $('genOut').innerHTML = genOut(); }, 100); deb('genDom', v => { UI.genDom = v; $('genOut').innerHTML = genOut(); }, 100);
  if(UI.macIn) macOut(UI.macIn);
  const sq = $('strq'); if(sq) sq.oninput = () => { UI.strq = sq.value; clearTimeout(bindLab.s); bindLab.s = setTimeout(() => { renderMain(); const x = $('strq'); if(x){ x.focus(); x.setSelectionRange(x.value.length, x.value.length); } }, 200); };
  bindImage(); bindParse(); bindPcap(); bindSql();
  const tb = document.querySelector('.labtabs [aria-selected=true]'), nav = tb && tb.parentElement; if(nav && nav.scrollWidth > nav.clientWidth) nav.scrollLeft = Math.max(0, tb.offsetLeft - nav.clientWidth / 2 + tb.offsetWidth / 2);
}
async function labLoad(f){
  if(f.size > 200 * 1048576) return toast('That file is over 200 MB — too big to inspect in a browser tab');
  UI.labFile = {busy:true, name:f.name}; UI.strq = ''; renderMain();
  try{ UI.labFile = await analyseFile(f); }catch(e){ UI.labFile = null; toast('Could not read that file'); }
  renderMain();
}
function labSummary(r){
  return [`File: ${r.name} (${fmtBytes(r.size)})`, `Type: ${r.type.name}${r.mismatch ? ' — extension .' + r.ext + ' does not match' : ''}`, `MD5: ${r.md5}`, `SHA1: ${r.sha1}`, `SHA256: ${r.sha256}`, `Entropy: ${r.entropy.toFixed(2)}`,
    r.exif ? 'EXIF: ' + Object.entries(r.exif).filter(([k]) => k !== 'GPS').map(([k, v]) => k + '=' + v).join('; ') : '', r.exif && r.exif.GPS ? `GPS: ${r.exif.GPS.lat}, ${r.exif.GPS.lon}` : '',
    r.trailing ? `Appended data at offset 0x${r.trailing.toString(16)}: ${r.trailPreview.slice(0, 200).replace(/[^\x20-\x7e]/g, '.')}` : '', r.carve.length ? 'Embedded: ' + r.carve.map(([o, n]) => n + '@0x' + o.toString(16)).join(', ') : '',
    r.zip && r.zip.office ? 'Office: ' + Object.entries(r.zip.office).filter(([, v]) => v).map(([k, v]) => k + '=' + v).join('; ') : '', r.zip && r.zip.macros.length ? 'MACROS: ' + r.zip.macros.join(', ') : '', r.zip && r.zip.external.length ? 'External links: ' + r.zip.external.map(x => x[1]).join(' ') : '',
    r.zip ? 'Archive: ' + r.zip.files.length + ' files' + (r.zip.encrypted ? ' (encrypted)' : '') : '', r.pdf ? 'PDF: ' + Object.entries(r.pdf.info).map(([k, v]) => k + '=' + v).join('; ') + ' · ' + Object.entries(r.pdf.keys).filter(([, n]) => n).map(([k, n]) => k + ' ' + n).join(', ') : '',
    r.pe ? `PE: ${r.pe.kind}, ${r.pe.machine}, compiled ${r.pe.compiled}${r.pe.packers.length ? ', packed (' + r.pe.packers.join(', ') + ')' : ''}${r.pe.suspicious.length ? ', imports ' + r.pe.suspicious.join(' ') : ''}` : '',
    r.yara && r.yara.some(x => x.match) ? 'YARA matches: ' + r.yara.filter(x => x.match).map(x => x.rule).join(', ') : '',
    r.flags.length ? 'Flags: ' + r.flags.join(' ') : '', r.iocs.length ? 'Indicators: ' + r.iocs.slice(0, 40).map(e => e.v).join(' ') : ''].filter(Boolean).join('\n');
}
/* timestamps */
const EPOCHS = [['Unix seconds', v => v * 1e3, v => v >= 1e8 && v < 1e11], ['Unix milliseconds', v => v, v => v >= 1e11 && v < 1e14], ['Unix microseconds', v => v / 1e3, v => v >= 1e14 && v < 1e17], ['Unix nanoseconds', v => v / 1e6, v => v >= 1e17 && v < 1e20],
  ['Windows FILETIME / LDAP (100 ns since 1601)', v => v / 1e4 - 11644473600000, v => v >= 1e17 && v < 3e18], ['Chrome / WebKit (µs since 1601)', v => v / 1e3 - 11644473600000, v => v >= 1e16 && v < 2e17],
  ['Mac / Cocoa absolute (s since 2001)', v => (v + 978307200) * 1e3, v => v >= 1e7 && v < 2e9], ['HFS+ (s since 1904)', v => (v - 2082844800) * 1e3, v => v >= 2e9 && v < 5e9], ['GPS time (s since 1980-01-06)', v => (v + 315964800) * 1e3, v => v >= 1e8 && v < 3e9]];
function dosTime(n){ const d = n >>> 16, t = n & 0xffff; const Y = ((d >> 9) & 127) + 1980, M = (d >> 5) & 15, D = d & 31, h = t >> 11, m = (t >> 5) & 63, s = (t & 31) * 2; return M >= 1 && M <= 12 && D >= 1 ? Date.UTC(Y, M - 1, D, h, m, s) : NaN; }
function tsRows(input){
  const s = String(input || '').trim(); if(!s) return [];
  const rows = [], add = (l, ms, note) => { if(isFinite(ms) && ms > -62e12 && ms < 4e12) rows.push([l, ms, note]); };
  const iso = Date.parse(s); if(!/^-?\d+(\.\d+)?$/.test(s) && !/^0x/i.test(s) && isFinite(iso)) add('Parsed date', iso, 'as written');
  let n = null; if(/^0x[0-9a-f]+$/i.test(s) || /^[0-9a-f]{8,16}$/i.test(s) && /[a-f]/i.test(s)){ n = Number(BigInt(s.startsWith('0x') ? s : '0x' + s)); const h = s.replace(/^0x/i, ''); if(h.length <= 8) add('DOS date/time (FAT, ZIP)', dosTime(parseInt(h, 16)), 'hex'); }
  else if(/^-?\d+(\.\d+)?$/.test(s)) n = +s;
  if(n != null) for(const [l, f, plausible] of EPOCHS){ const ms = f(n); const y = new Date(ms).getUTCFullYear(); if(plausible(Math.abs(n)) || (y >= 1990 && y <= 2040)) add(l, ms, plausible(Math.abs(n)) ? 'likely' : ''); }
  return rows;
}
function tsTable(input){
  const rows = tsRows(input); if(!String(input || '').trim()) return '<p class="t3">Paste a number (Unix, FILETIME, WebKit, Cocoa…), a hex value (DOS / FILETIME) or a date string.</p>';
  if(!rows.length) return '<p class="t3">No plausible interpretation.</p>';
  const now = Date.now();
  return `<table class="tbl tstbl"><thead><tr><th>Interpretation</th><th>UTC</th><th class="hide-m">Local</th><th class="hide-m">Relative</th></tr></thead><tbody>${rows.map(([l, ms, note]) => { const d = new Date(ms), y = d.getUTCFullYear(), ok = y >= 1995 && y <= 2035;
    return `<tr class="${ok ? 'ok' : 'dim'}"><td>${esc(l)}${note === 'likely' && ok ? ' <span class="pill" style="--c:var(--green)">likely</span>' : ''}</td><td class="mono">${esc(d.toISOString().replace('T', ' ').replace('.000Z', 'Z'))}</td><td class="mono hide-m">${esc(d.toLocaleString())}</td><td class="hide-m t3">${ms > now ? 'in ' + esc(E.fmtAgo(ms - now).replace(/ ago$/, '')) : esc(E.fmtAgo(now - ms))}</td></tr>`; }).join('')}</tbody></table>`;
}
function idTable(input){
  const rows = decodeIds(input); if(!rows.length) return '';
  return `<div class="idrows"><h4>${ico('fingerprint','sm')} Decoded from the ID</h4>${rows.map(([l, ms, note]) => `<div class="idrow"><span>${esc(l)}${note === 'from URL' ? ' <span class="pill" style="--c:var(--green)">from the link</span>' : ''}</span>${isFinite(ms) ? `<code>${esc(new Date(ms).toISOString().replace('T', ' ').replace('.000Z', 'Z'))}</code>` : `<span class="t3">${esc(note)}</span>`}</div>`).join('')}
    <p class="t3" style="font-size:12px;margin:8px 0 0">Social-media IDs embed their creation time. Only the platform you know the ID came from is meaningful.</p></div>`;
}
function labTime(){
  const now = Date.now(), ft = (BigInt(now) * 10000n + 116444736000000000n).toString();
  return `<div class="labgrid"><section class="card"><header><h3>Convert a timestamp</h3></header><div class="body">
    <label class="sr" for="tsIn">Timestamp or ID</label><input id="tsIn" class="inp mono big" placeholder="1726303053 · 133708740530000000 · a post link · a Discord ID · a UUID…" value="${esc(UI.tsIn || '')}" autocomplete="off" spellcheck="false">
    <div id="idOut">${idTable(UI.tsIn || '')}</div>
    <div id="tsOut" class="tsout">${tsTable(UI.tsIn || '')}</div>
    <div class="wrap" style="margin-top:12px"><span class="t3" style="font-size:12.5px">Try:</span>${[['1834567890123456789','X post ID'],['1234567890123456789','Discord ID'],['https://www.instagram.com/p/C8x9yZ2Nabc/','Instagram link'],['66f5a3c2e1b2c3d4e5f60718','MongoDB ObjectId'],['133708740530000000','FILETIME']].map(([v, l]) => `<button class="chip" data-act="tsTry" data-v="${esc(v)}">${esc(l)}</button>`).join('')}</div></div></section>
    <section class="card"><header><h3>Right now</h3></header><div class="body">
      ${[['Unix seconds', Math.floor(now / 1000)], ['Unix milliseconds', now], ['Windows FILETIME', ft], ['Chrome / WebKit', (BigInt(now) * 1000n + 11644473600000000n).toString()], ['Cocoa absolute', Math.floor(now / 1000 - 978307200)], ['ISO 8601', new Date(now).toISOString()]]
        .map(([l, v]) => `<div class="kv"><span>${l}</span><code>${esc(v)}</code><button class="iconbtn" data-act="flagCopy" data-v="${esc(v)}" aria-label="Copy">${ico('copy','sm')}</button></div>`).join('')}
      <p class="t3" style="font-size:12.5px;margin:12px 0 0">Tip: forensic artefacts mix epochs — browser history (WebKit), NTFS & registry (FILETIME), iOS/macOS (Cocoa), ZIP (DOS).</p></div></section></div>`;
}
/* hash identifier */
const HASHES = [
  [/^[a-f0-9]{32}$/i, ['MD5', 'NTLM', 'MD4', 'LM'], '0 · 1000 · 900'], [/^[a-f0-9]{40}$/i, ['SHA-1', 'RIPEMD-160', 'MySQL 4.1+ (without *)'], '100 · 6000'], [/^\*[a-f0-9]{40}$/i, ['MySQL 4.1+'], '300'],
  [/^[a-f0-9]{56}$/i, ['SHA-224', 'SHA3-224'], '1300'], [/^[a-f0-9]{64}$/i, ['SHA-256', 'SHA3-256', 'BLAKE2s-256'], '1400 · 17400'], [/^[a-f0-9]{96}$/i, ['SHA-384', 'SHA3-384'], '10800'],
  [/^[a-f0-9]{128}$/i, ['SHA-512', 'SHA3-512', 'Whirlpool', 'BLAKE2b-512'], '1700 · 6100'], [/^[a-f0-9]{8}$/i, ['CRC32', 'Adler-32'], '11500'], [/^[a-f0-9]{16}$/i, ['MySQL 3.x', 'Half MD5', 'SipHash'], '200'],
  [/^\$2[abxy]?\$\d{2}\$[.\/A-Za-z0-9]{53}$/, ['bcrypt'], '3200'], [/^\$1\$[^$]{0,8}\$[.\/A-Za-z0-9]{22}$/, ['MD5-crypt (Unix $1$)'], '500'], [/^\$5\$/, ['SHA-256-crypt (Unix $5$)'], '7400'], [/^\$6\$/, ['SHA-512-crypt (Unix $6$)'], '1800'],
  [/^\$y\$/, ['yescrypt (modern Linux shadow)'], '—'], [/^\$argon2(id|i|d)\$/, ['Argon2'], '—'], [/^\$apr1\$/, ['Apache APR1-MD5'], '1600'], [/^pbkdf2_sha256\$/, ['Django PBKDF2-SHA256'], '10000'],
  [/^\$P\$|^\$H\$/, ['phpass (WordPress, phpBB)'], '400'], [/^[^:]+::[^:]*:[a-f0-9]{16}:[a-f0-9]{32}:[a-f0-9]+$/i, ['NetNTLMv2'], '5600'], [/^[^:]+::[^:]*:[a-f0-9]{48}:[a-f0-9]{48}:[a-f0-9]{16}$/i, ['NetNTLMv1'], '5500'],
  [/^\$krb5tgs\$23\$/, ['Kerberos 5 TGS-REP (Kerberoast)'], '13100'], [/^\$krb5asrep\$23\$/, ['Kerberos 5 AS-REP (AS-REP roast)'], '18200'], [/^eyJ[\w-]+\.eyJ[\w-]+\.[\w-]*$/, ['JWT (JSON Web Token) — decode in Decoder'], '16500'],
  [/^[A-Za-z0-9+/]{27}=$/, ['Base64 SHA-1 (e.g. LDAP {SHA})'], '101'], [/^[A-Za-z0-9+/]{43}=$/, ['Base64 SHA-256'], '1411'], [/^\{SSHA\}/i, ['LDAP SSHA'], '111']];
function hashTable(input){
  const lines = String(input || '').split('\n').map(s => s.trim()).filter(Boolean).slice(0, 50);
  if(!lines.length) return '<p class="t3">Paste one hash per line — hex digests, Unix crypt strings, NetNTLM, Kerberos tickets, JWTs…</p>';
  return lines.map(h => { const m = HASHES.filter(([re]) => re.test(h)); const kind = h.length === 64 ? 'sha256' : h.length === 40 ? 'sha1' : h.length === 32 ? 'md5' : '';
    return `<div class="hrow"><code>${esc(h.length > 90 ? h.slice(0, 90) + '…' : h)}</code><div>${m.length ? m.map(([, n, mode]) => `<span class="hcand"><b>${esc(n[0])}</b>${n.slice(1).length ? `<span class="t3"> · or ${esc(n.slice(1).join(', '))}</span>` : ''}<span class="mono hmode">hashcat -m ${esc(mode)}</span></span>`).join('') : '<span class="t3">Unknown format</span>'}
      ${/^[a-f0-9]+$/i.test(h) && kind ? `<div class="pivots" style="margin-top:6px">${pivotLinks(kind, h).map(([n, u]) => `<a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(n)}${ico('arrow-up-right','sm')}</a>`).join('')}</div>` : ''}</div></div>`; }).join('');
}
function labHash(){
  return `<div class="labgrid one"><section class="card"><header><h3>Identify hashes</h3></header><div class="body">
    <label class="sr" for="hashIn">Hashes</label><textarea id="hashIn" class="inp mono" rows="5" spellcheck="false" placeholder="5f4dcc3b5aa765d61d8327deb882cf99&#10;$2b$12$…&#10;admin::CORP:1122334455667788:…">${esc(UI.hashIn || '')}</textarea>
    <div id="hashOut" class="hashout">${hashTable(UI.hashIn || '')}</div>
    <p class="t3" style="font-size:12.5px;margin:12px 0 0">Identification is by shape only — a 32-character hex string could be MD5, NTLM or something custom. Mode numbers are for hashcat.</p></div></section></div>`;
}
/* coordinates */
function parseCoords(s){
  s = String(s || '').trim(); if(!s) return null;
  const at = s.match(/@(-?\d+\.\d+),(-?\d+\.\d+)/) || s.match(/[?&](?:q|ll|query)=(-?\d+\.\d+)(?:,|%2C)\s*(-?\d+\.\d+)/i); if(at) return [+at[1], +at[2]];
  const dms = [...s.matchAll(/(-?\d+(?:\.\d+)?)\s*(?:°|deg|d|\s)\s*(?:(\d+(?:\.\d+)?)\s*(?:'|′|m|min|\s)\s*)?(?:(\d+(?:\.\d+)?)\s*(?:"|″|''|s|sec)?\s*)?([NSEW])?/gi)].filter(m => m[0].trim());
  if(dms.length >= 2 && /[°'′"NSEWd]/i.test(s)){ const v = m => { let x = Math.abs(+m[1]) + (+m[2] || 0) / 60 + (+m[3] || 0) / 3600; if(+m[1] < 0 || /[SW]/i.test(m[4] || '')) x = -x; return x; }; return [v(dms[0]), v(dms[1])]; }
  const dec = s.match(/(-?\d+(?:\.\d+)?)\s*[, ]\s*(-?\d+(?:\.\d+)?)/); if(dec) return [+dec[1], +dec[2]];
  return null;
}
const toDMS = (v, pos, neg) => { const a = Math.abs(v), d = Math.floor(a), mf = (a - d) * 60, m = Math.floor(mf), s = ((mf - m) * 60).toFixed(2); return `${d}°${String(m).padStart(2, '0')}′${String(s).padStart(5, '0')}″${v < 0 ? neg : pos}`; };
const geoLinks = (la, lo) => [['Google Maps', `https://www.google.com/maps?q=${la},${lo}`], ['Street View', `https://www.google.com/maps/@?api=1&map_action=pano&viewpoint=${la},${lo}`], ['OpenStreetMap', `https://www.openstreetmap.org/?mlat=${la}&mlon=${lo}#map=17/${la}/${lo}`],
  ['Google Earth', `https://earth.google.com/web/@${la},${lo},200a,800d,35y,0h,0t,0r`], ['Bing Maps', `https://www.bing.com/maps?cp=${la}~${lo}&lvl=17`], ['Mapillary', `https://www.mapillary.com/app/?lat=${la}&lng=${lo}&z=17`], ['Wikimapia', `https://wikimapia.org/#lat=${la}&lon=${lo}&z=17`]]
  .map(([n, u]) => [n, E.safeUrl(u)]).filter(x => x[1]);
function geoOut(s){
  const p = parseCoords(s); if(!String(s || '').trim()) return '<p class="t3">Paste decimal degrees, DMS (59°54′38″N 10°44′25″E), exiftool output, or a Google Maps link.</p>';
  if(!p || Math.abs(p[0]) > 90 || Math.abs(p[1]) > 180) return '<p class="t3">Could not read coordinates from that.</p>';
  const [la, lo] = p.map(x => +x.toFixed(6)), ddm = (v, a, b) => `${Math.floor(Math.abs(v))}° ${((Math.abs(v) % 1) * 60).toFixed(4)}′ ${v < 0 ? b : a}`;
  return `<div class="kv"><span>Decimal</span><code>${la}, ${lo}</code><button class="iconbtn" data-act="flagCopy" data-v="${la}, ${lo}" aria-label="Copy">${ico('copy','sm')}</button></div>
    <div class="kv"><span>DMS</span><code>${esc(toDMS(la, 'N', 'S') + ' ' + toDMS(lo, 'E', 'W'))}</code><button class="iconbtn" data-act="flagCopy" data-v="${esc(toDMS(la, 'N', 'S') + ' ' + toDMS(lo, 'E', 'W'))}" aria-label="Copy">${ico('copy','sm')}</button></div>
    <div class="kv"><span>Degrees, decimal minutes</span><code>${esc(ddm(la, 'N', 'S') + ', ' + ddm(lo, 'E', 'W'))}</code></div>
    <div class="isec"><h4>Open in</h4><div class="pivots">${geoLinks(la, lo).map(([n, u]) => `<a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(n)}${ico('arrow-up-right','sm')}</a>`).join('')}</div></div>
    <button class="btn primary" data-act="geoSave" data-v="${la}, ${lo}" style="margin-top:14px">${ico('map-pin','sm')}Add as a location to ${esc(theCase().code)}</button>`;
}
function labGeo(){
  return `<div class="labgrid one"><section class="card"><header><h3>Read coordinates</h3></header><div class="body">
    <label class="sr" for="geoIn">Coordinates</label><input id="geoIn" class="inp mono big" placeholder='59 deg 54&apos; 38.00" N, 10 deg 44&apos; 25.00" E' value="${esc(UI.geoIn || '')}" autocomplete="off" spellcheck="false">
    <div id="geoOut" class="geoout">${geoOut(UI.geoIn || '')}</div></div></section></div>`;
}

/* ---------- image tools ---------- */
function labImage(){
  const I = UI.img;
  if(!I) return `<label class="drop" id="imgDrop" tabindex="0"><input type="file" id="imgIn" accept="image/*" class="sr">${ico('image')}<b>Drop an image, or click to choose</b>
    <span>Colour channels, bit planes, least-significant-bit extraction, QR codes and reverse image search — the usual steganography and geolocation checks.</span>
    <span class="drop-feat"><i>R · G · B · Alpha</i><i>Bit planes 0–7</i><i>LSB text</i><i>QR / barcode</i><i>Invert</i><i>Error level (ELA)</i><i>Look-alikes</i><i>Reverse search</i></span></label>`;
  if(I.busy) return `<div class="card" style="padding:40px;text-align:center">${ico('refresh-cw','sm spin')} Loading image…</div>`;
  const ch = UI.imgCh || 'rgb', bit = UI.imgBit === undefined ? 'all' : UI.imgBit, L = I.lsb || {};
  return `<div class="imgwrap">
    <section class="card imgview"><header><h3>${esc(I.name)}</h3><span class="t3">${I.w} × ${I.h}${I.scaled ? ' · previewed at 4096 px' : ''}</span><span style="flex:1"></span><button class="btn sm" data-act="imgClear">${ico('x','sm')}Another image</button></header>
      <div class="imgtools"><div class="seg">${[['rgb','Colour'],['r','Red'],['g','Green'],['b','Blue'],['a','Alpha'],['gray','Grey'],['inv','Invert'],['ela','Error level']].map(([k, l]) => `<button data-act="imgCh" data-v="${k}" aria-pressed="${ch === k}">${l}</button>`).join('')}</div>
        ${ch !== 'rgb' && ch !== 'inv' && ch !== 'ela' ? `<div class="seg bits"><button data-act="imgBit" data-v="all" aria-pressed="${bit === 'all'}">All bits</button>${[7,6,5,4,3,2,1,0].map(b => `<button data-act="imgBit" data-v="${b}" aria-pressed="${bit === b}" title="Bit plane ${b}">${b}</button>`).join('')}</div>` : ''}</div>
      <div class="imgcanvas"><canvas id="imgCv"></canvas></div>
      <p class="t3" id="elaNote" style="font-size:12.5px;margin:0;padding:10px 16px">${ch === 'ela' ? 'Computing error levels…' : 'Hidden data often shows up as noise or text in bit plane 0 of one channel — compare it with plane 7.'}</p></section>
    <div class="fi-side">
      ${imgxCard()}
      <section class="card"><header><h3>${ico('scan','sm')} QR / barcode</h3></header><div class="body">${I.qr ? `<pre class="rawbox">${esc(I.qr)}</pre><div class="wrap" style="margin-top:8px"><button class="btn sm" data-act="flagCopy" data-v="${esc(I.qr)}">${ico('copy','sm')}Copy</button><button class="btn sm" data-act="imgToDecoder" data-v="${esc(I.qr)}">${ico('binary','sm')}Open in Decoder</button></div>${flagBox(findFlags(I.qr))}` : '<p class="t3" style="margin:0;font-size:13.5px">No QR code found in this image. Try a bit plane or crop tighter.</p>'}</div></section>
      <section class="card"><header><h3>${ico('binary','sm')} LSB extraction</h3></header><div class="body">
        <div class="wrap" style="margin-bottom:10px">${['rgb','r','g','b','bgr','rgba'].map(c => `<button class="chip" data-act="imgLsb" data-v="${c}" aria-pressed="${L.ch === c}">${c.toUpperCase()}</button>`).join('')}<button class="chip" data-act="imgLsbOrder" aria-pressed="${UI.imgCol ? 'true' : 'false'}">Column order</button></div>
        ${L.text !== undefined ? `<p class="t3" style="font-size:12.5px;margin:0 0 6px">${L.lead >= 8 ? `<b style="color:var(--green)">${L.lead} bytes of readable text at the start — likely hidden data</b>` : Math.round(L.printable * 100) + '% of the first 64 bytes are text — probably nothing here'}</p><pre class="rawbox">${esc(L.text.slice(0, 1200).replace(/[^\x09\x0a\x0d\x20-\x7e]/g, '.'))}</pre>${flagBox(findFlags(L.text))}` : '<p class="t3" style="margin:0;font-size:13.5px">Reads the lowest bit of each pixel’s channels and turns it into bytes (like <span class="mono">zsteg</span>). Pick the channel order.</p>'}</div></section>
      <section class="card"><header><h3>${ico('search','sm')} Reverse image search</h3></header><div class="body"><p class="t3" style="margin:0 0 10px;font-size:13.5px">These sites need the image itself — open one and drop the file in. Nothing is sent from here.</p>
        <div class="pivots">${[['Google Lens','https://lens.google.com/'],['Bing Visual Search','https://www.bing.com/visualsearch'],['Yandex Images','https://yandex.com/images/'],['TinEye','https://tineye.com/'],['PimEyes (faces)','https://pimeyes.com/en']].map(([n, u]) => `<a href="${u}" target="_blank" rel="noopener noreferrer">${n}${ico('arrow-up-right','sm')}</a>`).join('')}</div></div></section>
    </div></div>`;
}
function bindImage(){
  const inp = $('imgIn'), d = $('imgDrop');
  if(inp){ inp.onchange = () => { if(inp.files[0]) imgLoad(inp.files[0]); }; d.ondragover = e => { e.preventDefault(); d.classList.add('over'); }; d.ondragleave = () => d.classList.remove('over');
    d.ondrop = e => { e.preventDefault(); d.classList.remove('over'); const f = e.dataTransfer.files[0]; if(f) imgLoad(f); }; d.onkeydown = e => { if(e.key === 'Enter' || e.key === ' '){ e.preventDefault(); inp.click(); } }; }
  const cv = $('imgCv'); if(cv && UI.img && UI.img.data){ if(UI.imgCh === 'ela') showEla(cv); else renderPlane(UI.img.data, UI.imgCh || 'rgb', UI.imgBit === undefined ? 'all' : UI.imgBit, cv); }
}
async function imgLoad(f){
  UI.img = {busy:true}; renderMain();
  try{ const r = await loadImageData(f); UI.img = {name:f.name, w:r.w, h:r.h, scaled:r.scaled, data:r.data, qr:qrDecode(r.data)}; UI.imgCh = 'rgb'; UI.imgBit = 'all'; }
  catch(e){ UI.img = null; toast(e.message || 'Could not open that image'); }
  renderMain();
}

/* ---------- email headers ---------- */
const SAMPLE_EML = `Return-Path: <bounce@mailer.lantern-invoice.example>
Received: from mx01.corp.example (mx01.corp.example [10.20.1.5])
	by mailstore.corp.example with LMTP; Mon, 14 Sep 2026 08:52:14 +0000
Received: from lantern-invoice.example (unknown [198.51.100.23])
	by mx01.corp.example with ESMTP id 4F1A2B3C; Mon, 14 Sep 2026 08:52:10 +0000
Received: from [192.168.8.14] (unknown [192.168.8.14])
	by lantern-invoice.example with ESMTPSA; Mon, 14 Sep 2026 08:51:58 +0000
Authentication-Results: mx01.corp.example; spf=softfail smtp.mailfrom=lantern-invoice.example; dkim=none; dmarc=fail header.from=corp-billing.example
From: "Accounts Payable <ap@corp.example>" <billing@corp-billing.example>
Reply-To: payments@lantern-invoice.example
To: j.okafor@corp.example
Subject: Invoice 4471 overdue
Date: Mon, 14 Sep 2026 08:51:55 +0000
Message-ID: <20260914085155.1a2b@lantern-invoice.example>
X-Mailer: PHPMailer 6.8.0`;
function emailOut(raw){
  if(!String(raw || '').trim()) return '<p class="t3">Paste the full headers (in Outlook: File → Properties → Internet headers; in Gmail: ⋮ → Show original).</p>';
  const A = analyseEmail(raw); if(!A) return '<p class="t3">No headers found — paste the header block, starting with lines like “Received:” or “From:”.</p>';
  const badge = v => v ? `<span class="authb ${/pass/.test(v) ? 'ok' : /fail|softfail|permerror/.test(v) ? 'bad' : 'meh'}">${esc(v)}</span>` : '<span class="authb meh">none</span>';
  const fmtD = s => s == null ? '' : Math.abs(s) < 60 ? Math.round(s) + ' s' : Math.abs(s) < 3600 ? Math.round(s / 60) + ' min' : (s / 3600).toFixed(1) + ' h';
  return `${A.flags.length ? `<div class="emflags">${A.flags.map(([c, t]) => `<div class="note ${c === 'red' ? 'red' : 'amber'}"><span class="ic">${ico('triangle-alert','sm')}</span><div>${esc(t)}</div></div>`).join('')}</div>` : `<div class="note" style="margin-bottom:12px"><span class="ic" style="color:var(--green);background:var(--green-soft)">${ico('check','sm')}</span><div>No obvious spoofing signs in these headers.</div></div>`}
    <div class="emgrid"><section class="card"><header><h3>Message</h3></header><div class="body">${kvr('From', A.from, true)}${kvr('Reply-To', A.reply, true)}${kvr('Return-Path', A.ret, true)}${kvr('To', A.to)}${kvr('Subject', A.subject)}${kvr('Date', A.date)}${kvr('Message-ID', A.msgid, true)}${kvr('Mailer', A.mailer)}</div></section>
      <section class="card"><header><h3>Authentication</h3></header><div class="body"><div class="authrow"><span>SPF</span>${badge(A.spf)}</div><div class="authrow"><span>DKIM</span>${badge(A.dkim)}${A.dkimD ? `<span class="t3 mono">d=${esc(A.dkimD)} s=${esc(A.dkimS)}</span>` : ''}</div><div class="authrow"><span>DMARC</span>${badge(A.dmarc)}</div>
        ${A.originIP ? `<div class="isec"><h4>Sender IP (first external hop)</h4><code class="mono" style="font-size:14px">${esc(A.originIP)}</code> <span class="t3">${esc(E.ipClass(A.originIP))}</span>${pivotSection('ipv4', A.originIP)}</div>` : ''}</div></section></div>
    <section class="card" style="margin-top:14px"><header><h3>Delivery path</h3><span class="t3">${A.hops.length} hops, oldest first</span></header><div class="hops">${A.hops.map((h, i) => `<div class="hop"><span class="hn">${i + 1}</span><div><b class="mono">${esc(h.from || '?')}</b> → <b class="mono">${esc(h.by || '?')}</b><small>${esc(h.with)} ${h.ips.length ? '· ' + esc(h.ips.join(', ')) : ''}</small></div><span class="t3 mono">${h.ts ? esc(new Date(h.ts).toISOString().slice(11, 19)) + 'Z' : ''}</span><span class="hd ${h.delay != null && (h.delay > 600 || h.delay < -60) ? 'warn' : ''}">${h.delay != null ? '+' + fmtD(h.delay) : ''}</span></div>`).join('') || '<p class="t3" style="padding:14px 18px;margin:0">No Received headers.</p>'}</div></section>
    <section class="card" style="margin-top:14px"><header><h3>${ico('fingerprint','sm')} Indicators</h3><span style="flex:1"></span><button class="btn sm primary" data-act="emlSave">${ico('plus','sm')}Save to ${esc(theCase().code)}</button></header><div class="body"><div class="wrap">${A.iocs.map(e => `<span class="ent">${kindBadge(e.k)}<span class="v">${esc(e.v)}</span></span>`).join('') || '<span class="t3">None.</span>'}</div></div></section>`;
}
function labEmail(){
  return `<div class="labgrid one wide"><section class="card"><header><h3>Analyse email headers</h3><span style="flex:1"></span><button class="btn sm" data-act="emlSample">${ico('play','sm')}Sample phishing headers</button></header><div class="body">
    <label class="sr" for="emlIn">Headers</label><textarea id="emlIn" class="inp mono" rows="8" spellcheck="false" placeholder="Received: from …&#10;From: …&#10;Authentication-Results: …">${esc(UI.emlIn || '')}</textarea></div></section>
    <div id="emlOut">${emailOut(UI.emlIn || '')}</div></div>`;
}

/* ---------- network ---------- */
function cidrOut(v){ if(!String(v || '').trim()) return '<p class="t3">Try 10.20.4.17/22 or 192.168.1.0 255.255.255.0</p>'; const r = subnet(v); if(!r) return '<p class="t3">Enter an IPv4 address with a /prefix or a netmask.</p>';
  return kvr('Network', r.network + '/' + r.bits, true) + kvr('Netmask', r.mask, true) + kvr('Wildcard', r.wildcard, true) + kvr('Broadcast', r.broadcast, true) + kvr('Usable hosts', r.first + ' – ' + r.last, true) + kvr('Host count', r.hosts.toLocaleString()) + kvr('Address type', r.cls) + kvr('Binary', r.bin, true); }
function uaOut(v){ const r = parseUA(v); if(!r) return '<p class="t3">Paste a User-Agent string from a web log.</p>';
  return (r.bot ? `<div class="note amber" style="margin-bottom:10px"><span class="ic">${ico('bot','sm')}</span><div><b>Automated client:</b> ${esc(r.bot)}</div></div>` : '') + kvr('Browser', r.browser || '—') + kvr('Operating system', r.os || '—') + kvr('Device', r.device) + kvr('Engine', r.engine || '—'); }
async function macOut(v){ const el = $('macOut'); if(!el) return; if(!String(v || '').trim()){ el.innerHTML = '<p class="t3">Paste a MAC address — 00:1A:2B:3C:4D:5E, 001A.2B3C.4D5E or 00-1A-2B…</p>'; return; }
  el.innerHTML = '<p class="t3">Looking up…</p>'; try{ const r = await macVendor(v); if(!r){ el.innerHTML = '<p class="t3">That is not a MAC address.</p>'; return; }
    el.innerHTML = kvr('OUI', r.oui, true) + kvr('Vendor', r.vendor || (r.local ? 'None — locally administered address' : 'Not in the IEEE register')) + kvr('Scope', (r.multicast ? 'Multicast' : 'Unicast') + ' · ' + (r.local ? 'locally administered' : 'globally unique')) + (r.random ? '<p class="t3" style="font-size:12.5px;margin:8px 0 0">Locally administered addresses are usually randomised by phones and laptops for privacy, so no vendor can be named.</p>' : ''); }
  catch(e){ el.innerHTML = `<p class="t3">${esc(e.message)}</p>`; } }
function labNet(){
  return `<div class="netgrid">
    <section class="card"><header><h3>${ico('network','sm')} Subnet calculator</h3></header><div class="body"><input id="cidrIn" class="inp mono" placeholder="10.20.4.17/22" value="${esc(UI.cidrIn || '')}" autocomplete="off" spellcheck="false"><div id="cidrOut" style="margin-top:12px">${cidrOut(UI.cidrIn || '')}</div></div></section>
    <section class="card"><header><h3>${ico('cpu','sm')} MAC address vendor</h3><span class="t3">IEEE register, offline</span></header><div class="body"><input id="macIn" class="inp mono" placeholder="3C:22:FB:12:34:56" value="${esc(UI.macIn || '')}" autocomplete="off" spellcheck="false"><div id="macOut" style="margin-top:12px"></div></div></section>
    <section class="card"><header><h3>${ico('globe','sm')} User-agent decoder</h3></header><div class="body"><textarea id="uaIn" class="inp mono" rows="3" placeholder="Mozilla/5.0 (Windows NT 10.0; Win64; x64) … or python-requests/2.31">${esc(UI.uaIn || '')}</textarea><div id="uaOut" style="margin-top:12px">${uaOut(UI.uaIn || '')}</div></div></section>
  </div>`;
}

/* ---------- generators ---------- */
function genOut(){
  const n = UI.genName || '', u = usernameVariants(n, UI.genNums || ''), e = emailVariants(n, UI.genDom || '');
  if(!n.trim()) return '<p class="t3">Type a full name to generate likely usernames and email addresses.</p>';
  const list = (items, kind) => `<div class="genlist">${items.map(x => `<span><code>${esc(x)}</code>${kind === 'u' ? `<a href="https://whatsmyname.app/?q=${encodeURIComponent(x)}" target="_blank" rel="noopener noreferrer" title="Check on WhatsMyName">${ico('arrow-up-right','sm')}</a>` : ''}</span>`).join('')}</div>`;
  return `<div class="genres"><section><div class="genh"><h4>Usernames <span class="t3">${u.length}</span></h4><button class="btn xs" data-act="flagCopy" data-v="${esc(u.join('\n'))}">${ico('copy','sm')}Copy all</button></div>${list(u, 'u')}</section>
    ${e.length ? `<section><div class="genh"><h4>Email formats <span class="t3">${e.length}</span></h4><button class="btn xs" data-act="flagCopy" data-v="${esc(e.join('\n'))}">${ico('copy','sm')}Copy all</button></div>${list(e, 'e')}
      <p class="t3" style="font-size:12.5px;margin:10px 0 0">The first four formats cover most companies. Confirm one real address before trusting the pattern.</p></section>` : ''}</div>`;
}
function labGen(){
  return `<div class="labgrid one wide"><section class="card"><header><h3>${ico('users','sm')} Username & email permutations</h3></header><div class="body">
    <div class="frow3"><div class="field"><label for="genName">Full name</label><input id="genName" value="${esc(UI.genName || '')}" placeholder="Jordan Okafor" autocomplete="off"></div>
      <div class="field"><label for="genNums">Numbers (years, favourites)</label><input id="genNums" value="${esc(UI.genNums || '')}" placeholder="1992, 7" autocomplete="off"></div>
      <div class="field"><label for="genDom">Company domain</label><input id="genDom" value="${esc(UI.genDom || '')}" placeholder="corp.example" autocomplete="off"></div></div>
    <div id="genOut">${genOut()}</div></div></section></div>`;
}
