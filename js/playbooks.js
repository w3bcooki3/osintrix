/* ==========================================================================
   Playbooks — reusable investigation checklists. Running one on a case turns
   each step into an open question on that case, so progress lives where the
   work happens. Ships with a starter set; analysts can write, edit, import
   and export their own.
   ========================================================================== */
const PB_CATS = {osint:['OSINT','#8b5cf6'], ir:['Incident response','#f97316'], threat:['Threat analysis','#e5484d'], fraud:['Fraud & finance','#eab308'], custom:['My playbooks','#5468ff']};
const PB_SEED = [
  {id:'pb-phish', name:'Phishing email triage', cat:'ir', icon:'mail', desc:'From a reported email to a verdict, scope and block list.', steps:[
    ['Get the original message with full headers (.eml / .msg)', 'Screenshots lose the headers you need.'],
    ['Trace the delivery path: Received chain, sending IP, SPF / DKIM / DMARC results', 'Note the first external hop — that is the real sender infrastructure.'],
    ['Extract every indicator: sender, reply-to, links, attachment hashes', 'Paste the headers and body into Capture — indicators are pulled out for you.'],
    ['Check sender domain age, registrar and look-alikes', 'Newly registered or typosquatted domains are the classic tell.'],
    ['Detonate or reputation-check links and attachments', 'Use a sandbox or urlscan; never open them on your workstation.'],
    ['Who else received it? Search mail logs for sender, subject and hashes', 'Scope before you clean up.'],
    ['Did anyone click, reply or open the attachment?', 'Proxy, EDR and mail-gateway click logs.'],
    ['Block indicators and purge the message from mailboxes', 'Record what was blocked and where.']]},
  {id:'pb-user', name:'Username & online persona', cat:'osint', icon:'at-sign', desc:'Map everything a handle reveals — accounts, links, timeline and the person behind it.', steps:[
    ['Enumerate the handle across platforms', 'WhatsMyName, Sherlock-style checks — confirm each hit by hand.'],
    ['Capture profile details: bio, avatar, links, join dates, location claims', 'Archive pages before they change.'],
    ['Reverse-search the avatar and banner images', 'Reused photos link accounts together.'],
    ['Collect linked emails, phone numbers and websites', 'Check breach data for the emails.'],
    ['Look for handle variations and older names', 'Archive.org snapshots and forum signatures.'],
    ['Build an activity timeline — posting hours, time zone, language', 'Patterns point to geography.'],
    ['Link accounts in the graph with confidence and evidence', 'Every link should cite why you believe it.'],
    ['Assess attribution confidence and what would change it', 'Write the alternative explanations down.']]},
  {id:'pb-domain', name:'Domain & infrastructure', cat:'threat', icon:'globe', desc:'Who registered it, where it lives, and what else runs next to it.', steps:[
    ['WHOIS / RDAP: registrar, dates, registrant, name servers', 'Privacy-protected is still a data point.'],
    ['Resolve current and historical DNS (A, MX, NS, TXT)', 'Passive DNS shows where it used to point.'],
    ['Certificate transparency: find sibling subdomains and certs', 'crt.sh — shared certs reveal related hosts.'],
    ['Scan the hosting IPs: open ports, banners, JARM / favicon hashes', 'Shodan and Censys.'],
    ['Find co-hosted and look-alike domains', 'Same IP, same registrant email, same name server pattern.'],
    ['Check reputation and prior reporting', 'VirusTotal, urlscan, threat-intel feeds.'],
    ['Snapshot the site content and technology stack', 'Archive it — infrastructure moves fast.'],
    ['Decide: block, monitor or take-down request', 'Record the reasoning.']]},
  {id:'pb-ip', name:'Suspicious IP address', cat:'threat', icon:'server', desc:'Is this IP an attacker, a proxy, a scanner — or your own VPN?', steps:[
    ['Classify the range: private, cloud, hosting, residential, Tor / VPN', 'Context changes the verdict.'],
    ['Geo and ASN — who owns the network?', 'IPinfo, RIR records.'],
    ['Reputation: abuse reports, scanner noise, blocklists', 'AbuseIPDB and GreyNoise separate noise from targeting.'],
    ['What services does it expose?', 'Shodan / Censys history, not just today.'],
    ['Internal hits: which hosts talked to it, when, how much data?', 'Firewall, proxy and EDR logs.'],
    ['Pivot on shared certificates, hostnames and passive DNS', 'Find the rest of the infrastructure.'],
    ['Verdict and response: block, watch, or benign', 'Mark it in OSINTrix — the verdict follows it into every case.']]},
  {id:'pb-malware', name:'Malware sample triage', cat:'threat', icon:'bug', desc:'Safe first look at a suspicious file: identify, extract, contain.', steps:[
    ['Hash the sample (SHA-256, MD5) and store it safely', 'Password-protected archive, never on a shared drive.'],
    ['Reputation lookup by hash', 'VirusTotal, MalwareBazaar — do not upload sensitive files blindly.'],
    ['Static triage: file type, signer, strings, imports, packer', 'Look for URLs, IPs, mutexes, suspicious APIs.'],
    ['Detonate in a sandbox and record behaviour', 'Processes, network, persistence, dropped files.'],
    ['Extract network and host indicators', 'Paste the sandbox report into Capture.'],
    ['Map behaviour to ATT&CK techniques', 'Helps detection and reporting.'],
    ['Write or update detections (YARA / Sigma)', 'Use Detections → Generate from case as a start.'],
    ['Hunt for the indicators across the estate', 'Scope, then contain.']]},
  {id:'pb-login', name:'Suspicious sign-in / credential stuffing', cat:'ir', icon:'key-round', desc:'Separate a password spray from an account takeover — fast.', steps:[
    ['Pull the sign-in logs: users, source IPs, user agents, results', 'Look at failures and successes together.'],
    ['Identify the pattern: many users one IP, one user many IPs, or low-and-slow', 'The pattern tells you the attack type.'],
    ['Check source IPs for proxy, VPN, Tor and hosting ranges', 'Residential proxies are common now.'],
    ['Find any successful logins from the same sources', 'That is the account-takeover list.'],
    ['Check affected accounts against known breaches', 'Reused passwords explain success.'],
    ['Reset credentials, revoke sessions, enforce MFA', 'Record every account touched.'],
    ['Add blocks and a detection for the pattern', 'Rate limits, conditional access, a Sigma rule.']]},
  {id:'pb-crypto', name:'Crypto wallet tracing', cat:'fraud', icon:'bitcoin', desc:'Follow the money from a wallet to exchanges and linked identities.', steps:[
    ['Validate the address and identify the chain', 'BTC, ETH, TRON… formats differ.'],
    ['Review balance, first / last activity and transaction volume', 'Blockchain explorers.'],
    ['Trace inbound and outbound flows two or three hops', 'Note mixers, bridges and peel chains.'],
    ['Look for exchange deposit addresses', 'Exchanges can respond to legal requests.'],
    ['Search the address on the open web, forums and scam reports', 'Addresses are often posted in ransom notes or scam pages.'],
    ['Cluster related addresses (common input, change patterns)', 'Record your confidence for each link.'],
    ['Summarise the flow for law enforcement or the client', 'Dates, amounts, hops and evidence.']]},
  {id:'pb-ir1h', name:'Incident response — first hour', cat:'ir', icon:'siren', desc:'Stabilise, scope and communicate before you dig deep.', steps:[
    ['Confirm the alert is real and note the detection time', 'T0 for the timeline.'],
    ['Assign severity and an incident lead', 'One owner, one channel.'],
    ['Identify affected hosts, users and data', 'Start the vault now — add them as entries.'],
    ['Preserve evidence before changing anything', 'Memory, logs, disk images.'],
    ['Contain: isolate hosts, disable accounts, block indicators', 'Record every action with a timestamp.'],
    ['Notify stakeholders per the escalation plan', 'Legal and privacy early if data may be involved.'],
    ['List the open questions for the investigation', 'They are already here — keep answering them.'],
    ['Schedule the next update', 'Cadence beats silence.']]},

  {id:'pb-geo', name:'Geolocate a photo or video', cat:'osint', icon:'map-pin', desc:'Work out where — and roughly when — an image was taken.', steps:[
    ['Get the original file, not a screenshot or re-upload', 'Messaging apps and social sites strip metadata.'],
    ['Read the metadata: EXIF GPS, camera, timestamps', 'Forensics kit → File inspector; attach it in Capture and GPS lands on the case map.'],
    ['Reverse-search the image and its key details', 'Earlier copies give context, dates and sometimes the location.'],
    ['List visible clues: signs, language, plates, architecture, terrain, vegetation', 'Write each one down with what it narrows down.'],
    ['Narrow the area, then match with satellite and street-level imagery', 'Line up skylines, roads and fixed landmarks.'],
    ['Estimate the time from shadows, weather and events', 'Sun angle and weather archives can confirm a date.'],
    ['Record the location with coordinates and confidence', 'Add a Location entry — it appears on the case map.']]},
  {id:'pb-pcap', name:'Packet capture review', cat:'ir', icon:'network', desc:'From a .pcap to hosts, conversations, credentials and C2 leads.', steps:[
    ['Open the capture and note its time span, hosts and SHA-256', 'Forensics kit → PCAP. Save it to the case to keep the file and hash.'],
    ['Read the findings first: cleartext logins, beacons, scans, odd ports', 'They are leads, not verdicts.'],
    ['List external hosts and the names they were reached by (DNS, SNI, Host)', 'Names often matter more than IPs.'],
    ['Check HTTP requests and downloaded files', 'Export files only to a safe place.'],
    ['Review TLS: server names, versions, JA3 fingerprints', 'No SNI or a rare JA3 is worth a search.'],
    ['Follow the streams that matter', 'Read cleartext protocols end to end.'],
    ['Send the events to the case timeline and mark verdicts', 'Lookups, requests and connections become evidence.']]},
  {id:'pb-browser', name:'Browser and phone artefacts', cat:'ir', icon:'database', desc:'What a person visited, searched, downloaded and wrote — from SQLite files.', steps:[
    ['Collect the database files (and their -wal files) from a copy, not the live profile', 'History, Cookies, Login Data, places.sqlite, sms.db, msgstore.db.'],
    ['Open each in the SQLite viewer and record its SHA-256', 'Forensics kit → SQLite. The original is never changed.'],
    ['Review visited pages and searches around the time of interest', 'Dates are converted for you; check the time zone.'],
    ['Review downloads: file names, source URLs, referrers', 'Match them to files on disk.'],
    ['List saved-login sites and usernames (passwords stay encrypted)', 'They show accounts the person holds.'],
    ['Check the deleted-data view for leftovers', 'Treat recovered text as a lead and confirm it elsewhere.'],
    ['Send the relevant rows to the case timeline', 'Each row becomes a timed record with its source.']]},
  {id:'pb-ransom', name:'Ransomware first look', cat:'ir', icon:'lock', desc:'Identify the strain, the entry point and what else is at risk.', steps:[
    ['Isolate affected hosts — do not power them off', 'Memory can hold keys and evidence.'],
    ['Collect the ransom note, an encrypted sample and the file extension', 'Paste the note into Capture — wallets, emails and onion links are pulled out.'],
    ['Identify the strain from the note, extension and sample hash', 'ID Ransomware and vendor reports.'],
    ['Find the entry point: RDP, VPN, phishing, exposed service', 'Check 4624 type 10, VPN logs and recent phishing.'],
    ['Check for data theft before encryption', 'Large outbound transfers, rclone, cloud storage domains.'],
    ['Look for deleted backups and shadow copies', 'vssadmin and wbadmin commands (see Reference → LOLBins).'],
    ['Hunt the indicators across the estate and block them', 'Detections → Generate from case gives a starting rule.'],
    ['Record decisions and timeline for legal and insurers', 'The report and a signed custody file help here.']]},
];
const pbSteps = p => p.steps.map(s => Array.isArray(s) ? {t:s[0], h:s[1] || ''} : s);
function ensurePlaybooks(){
  if(!DB.playbooks) DB.playbooks = PB_SEED.map(p => ({...p, steps:pbSteps(p), custom:false, created:Date.now()}));
  const have = new Set(DB.playbooks.map(p => p.id)), gone = new Set(DB.deletedPb || []);
  for(const p of PB_SEED) if(!have.has(p.id) && !gone.has(p.id)) DB.playbooks.push({...p, steps:pbSteps(p), custom:false, created:Date.now()});
}
const pbTag = id => 'playbook:' + id;
/* the part of OSINTrix that helps with a step — picked from its wording */
const PB_TOOLS = [
  [/into capture|paste (the|it|them).*capture|extract every indicator/i, 'Capture', 'plus', 'capture'],
  [/pcap|packet capture|capture file/i, 'PCAP reader', 'network', 'lab:pcap'], [/sqlite|browser history|database file|history,|places\.sqlite|msgstore/i, 'SQLite viewer', 'database', 'lab:sqlite'],
  [/header|received chain|spf|dkim/i, 'Email headers', 'mail', 'lab:email'], [/exif|metadata|photo|image|avatar/i, 'Image tools', 'image', 'lab:image'],
  [/hash the sample|file type|signer|strings|imports|packer|static triage/i, 'File inspector', 'file-search', 'lab:file'],
  [/yara|sigma|detection/i, 'Detections', 'file-code', '#/detections'], [/decode|base64|encoded|-enc/i, 'Decoder', 'binary', '#/decoder'],
  [/timeline|timestamp|activity/i, 'Timeline', 'clock', 'case:timeline'], [/graph|link accounts|cluster/i, 'Graph', 'waypoints', 'case:graph'],
  [/location|coordinates|geolocat|map/i, 'Case map', 'map', 'case:map'], [/paste|capture|extract every|ransom note/i, 'Capture', 'plus', 'capture'],
  [/handle|username|platforms/i, 'Username tools', 'at-sign', 'tools:username'], [/whois|rdap|registrar/i, 'WHOIS tools', 'globe', 'tools:whois'],
  [/dns|passive dns/i, 'DNS tools', 'globe', 'tools:dns'], [/certificate transparency|crt\.sh/i, 'Cert tools', 'shield-check', 'tools:certificate'],
  [/shodan|censys|ports|banners|services/i, 'Scanning tools', 'radar', 'tools:shodan'], [/reputation|virustotal|abuseipdb|greynoise|blocklists/i, 'Reputation tools', 'shield-alert', 'tools:reputation'],
  [/breach/i, 'Breach tools', 'key-round', 'tools:breach'], [/reverse-search|reverse image/i, 'Reverse image', 'image', 'lab:image'],
  [/sandbox|detonate|urlscan/i, 'Sandbox tools', 'bug', 'tools:sandbox'], [/blockchain|explorer|address|wallet|chain/i, 'Blockchain tools', 'bitcoin', 'tools:blockchain'],
  [/event|4624|logs?\b|sign-in/i, 'Reference', 'book-open', '#/reference']];
const PB_HOME = {'pb-pcap':['PCAP reader','network','lab:pcap'], 'pb-browser':['SQLite viewer','database','lab:sqlite'], 'pb-geo':['Image tools','image','lab:image'], 'pb-malware':['File inspector','file-search','lab:file']};
const pbTool = (s, p) => { const t = s.t + ' ' + (s.h || ''), home = p && PB_HOME[p.id];
  if(home && !/timeline|capture\b|case map|location entry|detections|graph|reverse-search|reputation|sandbox|hunt/i.test(t)) return {l:home[0], i:home[1], go:home[2]};
  const m = PB_TOOLS.find(([re]) => re.test(t)); return m ? {l:m[1], i:m[2], go:m[3]} : null; };
function pbGo(where){
  if(where === 'capture') return openCapture();
  if(where.startsWith('lab:')){ UI.labTab = where.slice(4); return go('#/lab'); }
  if(where.startsWith('case:')) return go(caseHash(DB.active, where.slice(5)));
  if(where.startsWith('tools:')){ UI.tq = where.slice(6); UI.tcat = 'all'; return go('#/toolbox'); }
  return go(where);
}
function pbProgress(p, caseId){
  const recs = DB.records.filter(r => r.caseId === caseId && r.type === 'lead' && (r.tags || []).includes(pbTag(p.id)));
  return {total:recs.length, done:recs.filter(r => r.answer).length};
}
function pbCases(p){ return DB.cases.filter(c => pbProgress(p, c.id).total); }
function runPlaybook(id, caseId){
  const p = DB.playbooks.find(x => x.id === id), c = theCase(caseId); if(!p || !c) return;
  const have = new Set(DB.records.filter(r => r.caseId === c.id && r.type === 'lead').map(r => r.title.toLowerCase())); let n = 0;
  for(const s of p.steps){ if(have.has(s.t.toLowerCase())) continue;
    DB.records.push({id:uid('q'), caseId:c.id, type:'lead', title:s.t, body:s.h || '', tsRaw:'', ts:null, source:'playbook', host:'', tags:[pbTag(p.id)], ents:E.extract(s.t), answer:'', addedBy:'You', addedAt:Date.now(), hash:''}); n++; }
  mutate('ran playbook ' + p.name + ' on ' + c.code); hashRecords(); renderAll();
  toast(n ? n + ' steps added to ' + c.code + ' as questions' : 'Those steps are already on ' + c.code, 'Open', () => { DB.active = c.id; go(caseHash(c.id, 'questions')); });
}
function viewPlaybooks(){
  ensurePlaybooks();
  const cur = DB.playbooks.find(p => p.id === UI.pb);
  if(cur) return pbDetail(cur);
  const q = (UI.pbq || '').toLowerCase(), f = UI.pbf || 'all';
  const list = DB.playbooks.filter(p => (f === 'all' || p.cat === f) && (!q || (p.name + ' ' + p.desc + ' ' + p.steps.map(s => s.t).join(' ')).toLowerCase().includes(q)));
  const cats = countBy(DB.playbooks, p => p.cat);
  return `<div class="scroll"><div class="page wide">
    ${libHead('Playbooks', `${DB.playbooks.length} investigation checklists · run one on a case and every step becomes an open question`,
      `<button class="btn" data-act="pbImport">${ico('upload','sm')}Import</button><button class="btn" data-act="pbExport">${ico('download','sm')}Export</button><button class="btn primary" data-act="pbNew">${ico('plus','sm')}New playbook</button>`, '')}
    <div class="toolbar ltb"><div class="search-in">${ico('search')}<label class="sr" for="pbq">Search playbooks</label><input id="pbq" class="inp" placeholder="Search playbooks and steps…" value="${esc(UI.pbq || '')}"></div>
      <div class="seg"><button data-act="pbf" data-v="all" aria-pressed="${f === 'all'}">All</button>${cats.map(([c]) => `<button data-act="pbf" data-v="${c}" aria-pressed="${f === c}">${esc((PB_CATS[c] || PB_CATS.custom)[0])}</button>`).join('')}</div></div>
    ${list.length ? `<div class="pbl">${list.map(p => { const [cn, col] = PB_CATS[p.cat] || PB_CATS.custom, used = pbCases(p), a = pbProgress(p, DB.active);
      return `<article class="pbl-c" style="--c:${col}"><button class="gcard-hit" data-act="pbOpen" data-id="${p.id}" aria-label="Open ${esc(p.name)}"></button>
        <div class="pbl-h"><span class="pbl-ic">${ico(p.icon || 'list-checks')}</span><span class="pbl-cat"><i></i>${esc(cn)}${p.custom ? ' · Custom' : ''}</span></div>
        <h3>${esc(p.name)}</h3><p>${esc(p.desc)}</p>
        <footer>${a.total ? `<span class="pbl-prog"><span class="pb-prog"><i style="width:${Math.round(a.done / a.total * 100)}%"></i></span>${a.done}/${a.total} on ${esc(theCase().code)}</span>` : `<span class="t3">${p.steps.length} steps${used.length ? ' · in ' + used.length + ' case' + (used.length > 1 ? 's' : '') : ''}</span>`}
          <button class="btn sm pb-run" data-act="pbRun" data-id="${p.id}">${ico('play','sm')}Run on ${esc(theCase().code)}</button></footer></article>`; }).join('')}</div>`
      : empty('list-checks','No playbooks match','Try another search, or write your own checklist.', `<button class="btn primary" data-act="pbNew">${ico('plus','sm')}New playbook</button>`)}
  </div></div>`;
}
function pbDetail(p){
  const [cn, col] = PB_CATS[p.cat] || PB_CATS.custom, used = DB.cases.map(c => ({c, ...pbProgress(p, c.id)})).filter(x => x.total);
  const recs = DB.records.filter(r => r.caseId === DB.active && r.type === 'lead' && (r.tags || []).includes(pbTag(p.id))), doneOf = s => { const r = recs.find(x => x.title.toLowerCase() === s.t.toLowerCase()); return r ? (r.answer ? 'done' : 'open') : ''; };
  return `<div class="scroll"><div class="page">
    <div class="fp-bar"><button class="btn ghost" data-act="pbBack">${ico('arrow-left','sm')}All playbooks</button></div>
    <div class="pbx" style="--c:${col}">
      <div class="pbx-main">
        <header class="pbx-h"><span class="pbl-cat"><i></i>${esc(cn)}${p.custom ? ' · Custom' : ''}</span><h1>${esc(p.name)}</h1><p>${esc(p.desc)}</p></header>
        <ol class="pbx-steps">${p.steps.map((s, i) => { const t = pbTool(s, p), st = doneOf(s);
          return `<li class="${st}"><span class="n">${st === 'done' ? ico('check','sm') : i + 1}</span><div class="pbx-s"><b>${esc(s.t)}</b>${s.h ? `<p>${esc(s.h)}</p>` : ''}
            ${t ? `<button class="pbx-go" data-act="pbGo" data-v="${esc(t.go)}">${ico(t.i,'sm')}${esc(t.l)}${ico('arrow-right','sm')}</button>` : ''}</div>${st ? `<span class="pbx-st ${st}">${st === 'done' ? 'Answered' : 'Open'} in ${esc(theCase().code)}</span>` : ''}</li>`; }).join('')}</ol>
      </div>
      <aside class="pbx-side">
        <section class="card"><div class="body">
          <h4>Run on a case</h4><p class="t3 small">Each step becomes an open question on the case. Answer them as you go — progress shows here and on the case.</p>
          <label class="sr" for="pbCase">Case</label><select id="pbCase" class="gsel bord">${DB.cases.filter(c => c.status !== 'closed').map(c => `<option value="${c.id}"${c.id === DB.active ? ' selected' : ''}>${esc(c.code + ' · ' + c.name.split(' — ')[0])}</option>`).join('')}</select>
          <button class="btn primary" data-act="pbRunSel" data-id="${p.id}">${ico('play','sm')}Run playbook</button></div></section>
        ${used.length ? `<section class="card"><div class="body"><h4>In progress</h4>${used.map(x => `<a href="${caseHash(x.c.id, 'questions')}" class="pbd-u"><i style="background:${esc(x.c.color)}"></i><span>${esc(x.c.code)}</span><span class="pb-prog"><i style="width:${Math.round(x.done / x.total * 100)}%"></i></span><b>${x.done}/${x.total}</b></a>`).join('')}</div></section>` : ''}
        <section class="card"><div class="body pbx-meta"><div><span>Steps</span><b>${p.steps.length}</b></div><div><span>Shortcuts</span><b>${p.steps.filter(x => pbTool(x, p)).length}</b></div><div><span>Source</span><b>${p.custom ? 'Yours' : 'Built in'}</b></div>
          <div class="pbx-acts"><button class="btn sm" data-act="pbEdit" data-id="${p.id}">${ico('pencil','sm')}Edit</button><button class="btn sm" data-act="pbDup" data-id="${p.id}">${ico('copy','sm')}Duplicate</button><button class="btn sm ghost pbx-del" data-act="pbDelAsk" data-id="${p.id}">${ico('trash-2','sm')}Delete</button></div></div></section>
      </aside></div></div></div>`;
}
function pbDlg(id){
  const p = id ? DB.playbooks.find(x => x.id === id) : {name:'', desc:'', cat:'custom', icon:'list-checks', steps:[]};
  const icons = ['list-checks','mail','at-sign','globe','server','bug','key-round','bitcoin','siren','user','shield-alert','crosshair','fingerprint','file-text'];
  window.__pbIcon = p.icon || 'list-checks';
  openDlg(dhead(id ? 'Edit playbook' : 'New playbook') + `<form data-form="pb" data-id="${id || ''}"><div class="in">
    <div class="field"><label for="pbN">Name</label><input id="pbN" value="${esc(p.name)}" required autofocus placeholder="Ransomware note triage"></div>
    <div class="field"><label for="pbD">What it is for</label><input id="pbD" value="${esc(p.desc)}"></div>
    <div class="frow"><div class="field"><label for="pbC">Category</label><select id="pbC">${Object.entries(PB_CATS).map(([k, [n]]) => `<option value="${k}"${p.cat === k ? ' selected' : ''}>${esc(n)}</option>`).join('')}</select></div>
      <div class="field"><span class="label">Icon</span><div class="icopick" id="pbI">${icons.map(i => `<button type="button" data-act="pbIcon" data-v="${i}" aria-pressed="${window.__pbIcon === i}" aria-label="${i}">${ico(i,'sm')}</button>`).join('')}</div></div></div>
    <div class="field" style="margin:0"><label for="pbS">Steps</label><textarea id="pbS" rows="9" required placeholder="One step per line. Add a hint after ' -- '&#10;Collect the headers -- screenshots lose them">${esc(p.steps.map(s => s.t + (s.h ? ' -- ' + s.h : '')).join('\n'))}</textarea><span class="hint">One step per line. Anything after <span class="mono">--</span> becomes the hint.</span></div></div>
    <footer><button class="btn" type="button" data-act="dclose">Cancel</button><button class="btn primary" type="submit">${id ? 'Save' : 'Create playbook'}</button></footer></form>`, true);
}
function pbSubmit(f){
  const steps = $('pbS').value.split('\n').map(l => l.trim()).filter(Boolean).slice(0, 60).map(l => { const [t, ...h] = l.split(/\s+--\s+/); return {t:t.slice(0, 300), h:h.join(' -- ').slice(0, 400)}; });
  const vals = {name:$('pbN').value.trim().slice(0, 120), desc:$('pbD').value.trim().slice(0, 300), cat:$('pbC').value, icon:window.__pbIcon || 'list-checks', steps};
  vals.name = vals.name.replace(/\s+/g, ' ');
  if(!vals.name) return fieldErr('pbN', 'Give the playbook a name.'); if(!steps.length) return fieldErr('pbS', 'Add at least one step — one per line.');
  if(clash(DB.playbooks, vals.name, 'name', f.dataset.id || null)) return fieldErr('pbN', `A playbook called “${vals.name}” already exists.`);
  if($('pbS').value.split('\n').filter(l => l.trim()).length > 60) return fieldErr('pbS', 'A playbook can have up to 60 steps.');
  if(f.dataset.id) Object.assign(DB.playbooks.find(p => p.id === f.dataset.id), vals);
  else { const p = {id:uid('pb'), ...vals, custom:true, created:Date.now()}; DB.playbooks.unshift(p); UI.pb = p.id; }
  mutate('saved playbook ' + vals.name); closeDlg(); renderAll(); toast('Playbook saved');
}
function pbImport(){
  pickFile('.json,application/json', txt => { let d; try{ d = JSON.parse(txt); }catch(e){ return toast('Not a JSON file'); }
    const arr = Array.isArray(d) ? d : [d]; let n = 0;
    for(const p of arr){ if(!p || !p.name || !Array.isArray(p.steps)) continue;
      const steps = p.steps.map(s => typeof s === 'string' ? {t:s, h:''} : {t:String(s.t || s.title || ''), h:String(s.h || s.hint || '')}).filter(s => s.t).slice(0, 60);
      if(!steps.length) continue;
      DB.playbooks.push({id:uid('pb'), name:clash(DB.playbooks, String(p.name).slice(0, 120)) ? copyName(String(p.name).slice(0, 110), DB.playbooks.map(x => x.name)) : String(p.name).slice(0, 120), desc:String(p.desc || p.description || '').slice(0, 300), cat:PB_CATS[p.cat] ? p.cat : 'custom', icon:LUCIDE[p.icon] ? p.icon : 'list-checks', steps, custom:true, created:Date.now()}); n++; }
    mutate('imported ' + n + ' playbooks'); renderAll(); toast(n ? n + ' playbook' + (n > 1 ? 's' : '') + ' imported' : 'No playbooks found in that file'); });
}
