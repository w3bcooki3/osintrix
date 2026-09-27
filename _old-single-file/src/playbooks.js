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
];
const pbSteps = p => p.steps.map(s => Array.isArray(s) ? {t:s[0], h:s[1] || ''} : s);
function ensurePlaybooks(){
  if(!DB.playbooks) DB.playbooks = PB_SEED.map(p => ({...p, steps:pbSteps(p), custom:false, created:Date.now()}));
  const have = new Set(DB.playbooks.map(p => p.id)), gone = new Set(DB.deletedPb || []);
  for(const p of PB_SEED) if(!have.has(p.id) && !gone.has(p.id)) DB.playbooks.push({...p, steps:pbSteps(p), custom:false, created:Date.now()});
}
const pbTag = id => 'playbook:' + id;
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
    ${list.length ? `<div class="pbgrid">${list.map(p => { const [cn, col] = PB_CATS[p.cat] || PB_CATS.custom, used = pbCases(p), a = pbProgress(p, DB.active);
      return `<article class="pbcard" style="--c:${col}"><button class="gcard-hit" data-act="pbOpen" data-id="${p.id}" aria-label="Open ${esc(p.name)}"></button>
        <div class="pbcard-h"><span class="pb-ic">${ico(p.icon || 'list-checks')}</span><span class="pill" style="--c:${col}">${esc(cn)}</span>${p.custom ? '<span class="tc-badge mine">Custom</span>' : ''}</div>
        <h3>${esc(p.name)}</h3><p>${esc(p.desc)}</p>
        <ol class="pb-peek">${p.steps.slice(0, 3).map(s => `<li>${esc(s.t)}</li>`).join('')}${p.steps.length > 3 ? `<li class="more">+ ${p.steps.length - 3} more steps</li>` : ''}</ol>
        <div class="pbcard-f">${a.total ? `<span class="pb-prog"><i style="width:${Math.round(a.done / a.total * 100)}%"></i></span><span class="t3">${a.done}/${a.total} on ${esc(theCase().code)}</span>` : `<span class="t3">${p.steps.length} steps${used.length ? ' · used in ' + used.length + ' case' + (used.length > 1 ? 's' : '') : ''}</span>`}
          <button class="btn sm primary pb-run" data-act="pbRun" data-id="${p.id}">${ico('play','sm')}Run on ${esc(theCase().code)}</button></div></article>`; }).join('')}</div>`
      : empty('list-checks','No playbooks match','Try another search, or write your own checklist.', `<button class="btn primary" data-act="pbNew">${ico('plus','sm')}New playbook</button>`)}
  </div></div>`;
}
function pbDetail(p){
  const [cn, col] = PB_CATS[p.cat] || PB_CATS.custom, used = DB.cases.map(c => ({c, ...pbProgress(p, c.id)})).filter(x => x.total);
  return `<div class="scroll"><div class="page fpage">
    <div class="fp-bar"><button class="btn ghost" data-act="pbBack">${ico('arrow-left','sm')}All playbooks</button></div>
    <section class="card pbd" style="--c:${col}">
      <header class="pbd-h"><span class="pb-ic lg">${ico(p.icon || 'list-checks')}</span><div style="flex:1;min-width:0"><span class="pill" style="--c:${col}">${esc(cn)}</span><h1>${esc(p.name)}</h1><p>${esc(p.desc)}</p></div>
        <div class="pbd-a"><button class="iconbtn" data-act="pbEdit" data-id="${p.id}" title="Edit" aria-label="Edit">${ico('pencil','sm')}</button><button class="iconbtn" data-act="pbDup" data-id="${p.id}" title="Duplicate" aria-label="Duplicate">${ico('copy','sm')}</button><button class="iconbtn dangerhov" data-act="pbDelAsk" data-id="${p.id}" title="Delete" aria-label="Delete">${ico('trash-2','sm')}</button></div></header>
      <div class="pbd-run"><label class="sr" for="pbCase">Case</label><select id="pbCase" class="gsel bord">${DB.cases.filter(c => c.status !== 'closed').map(c => `<option value="${c.id}"${c.id === DB.active ? ' selected' : ''}>${esc(c.code + ' · ' + c.name.split(' — ')[0])}</option>`).join('')}</select>
        <button class="btn primary" data-act="pbRunSel" data-id="${p.id}">${ico('play','sm')}Run on this case</button><span class="t3">Each step becomes an open question you answer as you go.</span></div>
      <ol class="pb-steps">${p.steps.map((s, i) => `<li><span class="n">${i + 1}</span><div><b>${esc(s.t)}</b>${s.h ? `<p>${esc(s.h)}</p>` : ''}</div></li>`).join('')}</ol>
      ${used.length ? `<div class="pbd-used"><h4>In progress</h4>${used.map(x => `<a href="${caseHash(x.c.id, 'questions')}" class="pbd-u"><i style="background:${esc(x.c.color)}"></i><span>${esc(x.c.code)} · ${esc(x.c.name.split(' — ')[0])}</span><span class="pb-prog"><i style="width:${Math.round(x.done / x.total * 100)}%"></i></span><b>${x.done}/${x.total}</b></a>`).join('')}</div>` : ''}
    </section></div></div>`;
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
  if(!vals.name || !steps.length) return toast('Give it a name and at least one step');
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
      DB.playbooks.push({id:uid('pb'), name:String(p.name).slice(0, 120), desc:String(p.desc || p.description || '').slice(0, 300), cat:PB_CATS[p.cat] ? p.cat : 'custom', icon:LUCIDE[p.icon] ? p.icon : 'list-checks', steps, custom:true, created:Date.now()}); n++; }
    mutate('imported ' + n + ' playbooks'); renderAll(); toast(n ? n + ' playbook' + (n > 1 ? 's' : '') + ' imported' : 'No playbooks found in that file'); });
}
