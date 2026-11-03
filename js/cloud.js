/* ==========================================================================
   Cloud section — three tabs:
     Scanner       : drop IaC / policy / K8s files, see misconfigurations
     Log hunting   : drop CloudTrail / Azure / GCP logs, flag notable events
     Field guide   : cloud attack/enum, defence & forensics, CTF cheat sheets
   Engines live in cloudscan.js / cloudlogs.js / data/cloudguide.js.
   ========================================================================== */
const CLOUD_TABS = [['guide', 'book-open', 'Field guide'], ['scanner', 'shield-alert', 'Misconfig scanner'], ['logs', 'file-search', 'Log hunting']];
const SEV_META = {critical:['Critical', 'var(--red)'], high:['High', '#f97316'], medium:['Medium', 'var(--amber)'], low:['Low', 'var(--signal)'], info:['Info', 'var(--text-3)']};

const CLOUD_SAMPLES = {
  'IAM policy (public admin)': JSON.stringify({Version:'2012-10-17', Statement:[{Sid:'Admin', Effect:'Allow', Action:'*', Resource:'*'}, {Sid:'PublicRead', Effect:'Allow', Principal:'*', Action:['s3:GetObject'], Resource:'arn:aws:s3:::data/*'}]}, null, 2),
  'Terraform (open SG + public RDS)': 'resource "aws_security_group" "web" {\n  name = "web"\n  ingress {\n    from_port   = 22\n    to_port     = 22\n    protocol    = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\nresource "aws_db_instance" "db" {\n  publicly_accessible = true\n  storage_encrypted   = false\n}\nresource "aws_instance" "app" {\n  metadata_options {\n    http_tokens = "optional"\n  }\n}',
  'Kubernetes (privileged pod)': 'apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  template:\n    spec:\n      hostNetwork: true\n      volumes:\n        - name: host\n          hostPath:\n            path: /\n      containers:\n        - name: app\n          image: nginx:latest\n          securityContext:\n            privileged: true',
  'CloudTrail (suspicious burst)': JSON.stringify({Records:[
    {eventTime:'2026-10-24T09:00:00Z', eventName:'ConsoleLogin', eventSource:'signin.amazonaws.com', userIdentity:{arn:'arn:aws:iam::111:user/dev', type:'IAMUser'}, sourceIPAddress:'203.0.113.9', awsRegion:'us-east-1'},
    {eventTime:'2026-10-24T09:03:00Z', eventName:'CreateAccessKey', eventSource:'iam.amazonaws.com', userIdentity:{arn:'arn:aws:iam::111:user/dev'}, sourceIPAddress:'203.0.113.9'},
    {eventTime:'2026-10-24T09:04:00Z', eventName:'AttachUserPolicy', eventSource:'iam.amazonaws.com', userIdentity:{arn:'arn:aws:iam::111:user/dev'}, sourceIPAddress:'203.0.113.9', requestParameters:{policyArn:'arn:aws:iam::aws:policy/AdministratorAccess'}},
    {eventTime:'2026-10-24T09:06:00Z', eventName:'StopLogging', eventSource:'cloudtrail.amazonaws.com', userIdentity:{arn:'arn:aws:iam::111:user/dev'}, sourceIPAddress:'203.0.113.9'},
    {eventTime:'2026-10-24T09:08:00Z', eventName:'GetSecretValue', eventSource:'secretsmanager.amazonaws.com', userIdentity:{arn:'arn:aws:iam::111:user/dev'}, sourceIPAddress:'203.0.113.9', requestParameters:{secretId:'prod/db'}}
  ]}, null, 2)
};

function viewCloud(){
  const tab = ['scanner', 'logs', 'guide'].includes(UI.cloudTab) ? UI.cloudTab : 'guide';
  const tabs = CLOUD_TABS.map(([k, i, l]) => `<button data-act="cloudTab" data-v="${k}" aria-pressed="${tab === k}">${ico(i, 'sm')}${l}</button>`).join('');
  const body = tab === 'scanner' ? cloudScannerView() : tab === 'logs' ? cloudLogsView() : cloudGuideView();
  return `<div class="scroll"><div class="cld">
    <header class="cld-h"><div><span class="ix">Lab</span><h1>Cloud</h1><p>A field guide for cloud, bug bounty and CTF work, a misconfiguration scanner and cloud log hunting — all offline, in this browser.</p></div></header>
    <nav class="cld-tabs" aria-label="Cloud tools">${tabs}</nav>
    ${body}</div></div>`;
}

/* ---------------- Scanner ---------------- */
function cloudDrop(id, label, hint){
  return `<label class="cld-drop" id="${id}" tabindex="0" role="button" aria-label="${label}">
    ${ico('file-up')}<b>${label}</b><span>${hint}</span>
    <input type="file" class="sr" accept=".json,.yaml,.yml,.tf,.template,.txt,application/json,text/yaml"></label>`;
}
function cloudScannerView(){
  const R = UI.cloudScan;
  const samples = Object.keys(CLOUD_SAMPLES).map(k => `<button class="cld-samp" data-act="cloudSample" data-v="${esc(k)}">${esc(k)}</button>`).join('');
  const intro = `<div class="cld-kinds"><span class="ix">Reads</span> AWS IAM &amp; resource policies · Terraform (<code>.tf</code> and plan JSON) · CloudFormation · Azure ARM · Azure roles · GCP IAM · Kubernetes manifests</div>`;
  if(!R) return `<section class="cld-pane">${cloudDrop('csDrop', 'Drop a config or policy file', 'or click to choose · or paste below')}
    ${intro}
    <div class="cld-paste"><label class="ix" for="csText">Paste config</label><textarea id="csText" class="inp mono" placeholder="Paste IAM JSON, Terraform, a Kubernetes manifest…" spellcheck="false"></textarea><div class="cld-paste-a"><button class="btn primary" data-act="cloudScanText">${ico('shield-alert','sm')}Scan</button><span class="t3">Samples:</span>${samples}</div></div></section>`;
  const c = R.counts, total = R.findings.length;
  const chips = Object.keys(SEV_META).filter(s => c[s]).map(s => `<span class="cld-sev ${s}">${c[s]} ${SEV_META[s][0].toLowerCase()}</span>`).join('');
  const rows = R.findings.map((f, i) => `<article class="cld-f ${f.sev}">
      <div class="cld-f-s" title="${SEV_META[f.sev][0]}">${SEV_META[f.sev][0][0]}</div>
      <div class="cld-f-m"><h3>${esc(f.title)}</h3><p>${esc(f.detail)}</p>
        <div class="cld-f-fix">${ico('circle-check','sm')}<span><b>Fix</b> ${esc(f.fix)}</span></div></div>
      <div class="cld-f-w">${f.where ? `<code>${esc(f.where)}</code>` : ''}${f.line ? `<span class="t3">line ${f.line}</span>` : ''}</div></article>`).join('');
  return `<section class="cld-pane">
    <div class="cld-res-h"><div><h2>${esc(R.name || 'Pasted config')}</h2><p class="t3">${esc(R.kindLabel)}${R.resources ? ' · ' + R.resources + ' resource' + (R.resources === 1 ? '' : 's') : ''} · ${total} finding${total === 1 ? '' : 's'}</p></div>
      <div class="cld-res-a"><button class="btn" data-act="cloudRescan">${ico('arrow-left','sm')}New scan</button>${total ? `<button class="btn" data-act="cloudExport">${ico('download','sm')}Export</button>${DB.cases.length ? `<button class="btn" data-act="cloudToCase">${ico('list-plus','sm')}Add to ${esc((theCase() || DB.cases[0]).code)}</button>` : ''}` : ''}</div></div>
    ${R.kind === 'unknown' ? `<div class="note red"><span class="ic">${ico('triangle-alert','sm')}</span><div><b>Not recognised.</b> This doesn't look like a policy, IaC or Kubernetes file. Check it is valid JSON/YAML/HCL.</div></div>`
      : total ? `<div class="cld-sevbar">${chips}</div><div class="cld-flist">${rows}</div>`
      : `<div class="cld-clean">${ico('shield-check')}<b>No misconfigurations found</b><p>The ${R.resources} resource${R.resources === 1 ? '' : 's'} in this ${esc(R.kindLabel)} passed every check. This is a focused linter, not a full audit — keep using your cloud provider's own tools too.</p><button class="btn" data-act="cloudRescan">Scan another</button></div>`}
  </section>`;
}

/* ---------------- Log hunting ---------------- */
function cloudLogsView(){
  const R = UI.cloudLogs;
  if(!R) return `<section class="cld-pane">${cloudDrop('clDrop', 'Drop a cloud audit log', 'or click to choose · or paste below')}
    <div class="cld-kinds"><span class="ix">Reads</span> AWS CloudTrail (<code>Records</code> or JSON lines) · Azure Activity log · GCP Audit log</div>
    <div class="cld-paste"><label class="ix" for="clText">Paste log</label><textarea id="clText" class="inp mono" placeholder="Paste CloudTrail / Azure / GCP audit JSON…" spellcheck="false"></textarea><div class="cld-paste-a"><button class="btn primary" data-act="cloudLogText">${ico('file-search','sm')}Hunt</button><span class="t3">Sample:</span><button class="cld-samp" data-act="cloudSample" data-v="CloudTrail (suspicious burst)">CloudTrail (suspicious burst)</button></div></div></section>`;
  if(R.fmt === 'unknown') return `<section class="cld-pane"><div class="cld-res-h"><div><h2>${esc(R.name || 'Pasted log')}</h2></div><div class="cld-res-a"><button class="btn" data-act="cloudLogReset">${ico('arrow-left','sm')}New</button></div></div><div class="note red"><span class="ic">${ico('triangle-alert','sm')}</span><div><b>Not recognised.</b> Expected CloudTrail, Azure Activity or GCP Audit JSON.</div></div></section>`;
  const c = R.counts;
  const chips = Object.keys(SEV_META).filter(s => c[s]).map(s => `<span class="cld-sev ${s}">${c[s]} ${SEV_META[s][0].toLowerCase()}</span>`).join('');
  const flag = R.flagged.map(e => `<article class="cld-ev ${e.sev}"><div class="cld-f-s">${SEV_META[e.sev][0][0]}</div>
    <div class="cld-ev-m"><div class="cld-ev-t"><b>${esc(e.name)}</b>${e.service ? `<span class="tag">${esc(e.service)}</span>` : ''}<span class="t3">${esc((e.time || '').replace('T', ' ').replace(/\.\d+Z?$/, '').replace('Z', ''))}</span></div>
      <p>${esc(e.why)}</p><div class="cld-ev-meta">${e.actor ? `${ico('user','sm')}${esc(e.actor)}` : ''}${e.src_ip ? `${ico('globe','sm')}${esc(e.src_ip)}` : ''}${e.error ? `<span class="chip red sq">${esc(e.error)}</span>` : ''}</div></div></article>`).join('');
  const actors = R.topActors.map(a => `<div><span>${esc(a.v)}</span><b>${a.n}</b></div>`).join('');
  const ips = R.topIps.map(a => `<div><span class="mono">${esc(a.v)}</span><b>${a.n}</b></div>`).join('');
  return `<section class="cld-pane"><div class="cld-res-h"><div><h2>${esc(R.name || 'Pasted log')}</h2><p class="t3">${esc(R.fmtLabel)} · ${R.total} event${R.total === 1 ? '' : 's'} · ${R.flagged.length} flagged · ${R.errors} error${R.errors === 1 ? '' : 's'}</p></div>
    <div class="cld-res-a"><button class="btn" data-act="cloudLogReset">${ico('arrow-left','sm')}New</button>${R.total ? `<button class="btn" data-act="cloudLogCase">${ico('list-plus','sm')}Send to timeline</button>` : ''}</div></div>
    ${R.flagged.length ? `<div class="cld-sevbar">${chips}</div>` : ''}
    <div class="cld-loggrid">
      <div class="cld-logmain">${R.flagged.length ? flag : `<div class="cld-clean">${ico('shield-check')}<b>No notable events</b><p>None of the ${R.total} events matched a high-signal rule. You can still send them all to a case timeline.</p></div>`}</div>
      <aside class="cld-logside">${actors ? `<section class="card"><header><h3>Top actors</h3></header><div class="cld-tally">${actors}</div></section>` : ''}${ips ? `<section class="card"><header><h3>Top source IPs</h3></header><div class="cld-tally">${ips}</div></section>` : ''}</aside></div></section>`;
}

/* ---------------- Field guide (left rail of sections + right content) ---------------- */
const CG_PROV = {aws:['AWS', '#ff9900'], azure:['Azure', '#2f9bff'], gcp:['GCP', '#34a853'], k8s:['Kubernetes', '#4f7cff'], web:['Web', '#22c55e'], linux:['Linux', '#e5a50a'], windows:['Windows', '#0ea5e9']};
const CG_LVL = {basic:['Basic', 1], intermediate:['Intermediate', 2], advanced:['Advanced', 3]};
let CG_ALL = null;
/* The guide = cloudguide.js plus the optional pack (new groups, extra cards, and look/detect/fix notes for existing cards). */
function cgAll(){
  if(CG_ALL) return CG_ALL;
  const P = typeof CLOUDGUIDE_PACK !== 'undefined' ? CLOUDGUIDE_PACK : {}, en = P.enrich || {}, add = P.add || {};
  const groups = CLOUDGUIDE.map(g => ({...g, cards:g.cards.concat(add[g.name] || []).map(c => ({...c, ...(en[c.t] || {})}))})).concat((P.groups || []).map(g => ({...g, cards:g.cards.slice()})));
  const seen = new Set(); for(const g of groups) for(const c of g.cards){ let k = c.t; while(seen.has(k)) k += ' '; seen.add(k); c.k = k; c.g = g.name;
    c.hay = [c.t, c.body, c.look, c.detect, c.fix, c.provider, c.att, g.name, ...(c.cmds || []).map(x => x.join(' '))].join(' ').toLowerCase(); }
  return CG_ALL = groups;
}
const cgProvTag = c => c.provider && CG_PROV[c.provider] ? `<span class="cg-p" style="--pc:${CG_PROV[c.provider][1]}"><i></i>${CG_PROV[c.provider][0]}</span>` : '';
const cgLvlTag = c => c.level && CG_LVL[c.level] ? `<span class="cg-lv l${CG_LVL[c.level][1]}" title="${CG_LVL[c.level][0]}"><i></i><i></i><i></i>${CG_LVL[c.level][0]}</span>` : '';
function cgDetailHtml(sel){
  const cmdRow = ([l, cmd], i) => `<li class="cg-cmd"><div class="cg-cmd-l"><span>${i + 1}</span>${esc(l)}</div><div class="cg-term"><code>${esc(cmd)}</code><button class="cg-copy" data-act="cloudCopy" data-v="${esc(cmd)}" aria-label="Copy: ${esc(l)}" title="Copy">${ico('copy','sm')}</button></div></li>`;
  const note = (icon, h, t, cls) => t ? `<section class="cg-n ${cls}"><h4>${ico(icon,'sm')}${h}</h4><p>${esc(t)}</p></section>` : '';
  return sel ? `<article class="cg-d${UI.cgOpen ? ' open' : ''}" id="cgDetail">
      <button class="btn ghost cg-back" data-act="cgBack">${ico('arrow-left','sm')}All techniques</button>
      <header><div class="cg-d-m">${cgProvTag(sel)}${cgLvlTag(sel)}<span class="cg-d-g">${esc(sel.g)}</span>${sel.att ? `<a class="cg-att" href="https://attack.mitre.org/techniques/${esc(sel.att.replace('.', '/'))}/" target="_blank" rel="noopener noreferrer">ATT&amp;CK ${esc(sel.att)} ${ico('arrow-up-right','sm')}</a>` : ''}</div>
        <h2>${esc(sel.t)}</h2><p>${esc(sel.body)}</p></header>
      ${sel.cmds && sel.cmds.length ? `<section class="cg-ds"><h3>Commands</h3><ol class="cg-cmds">${sel.cmds.map(cmdRow).join('')}</ol></section>` : ''}
      <div class="cg-ns">${note('eye', 'What to look for', sel.look, 'look')}${note('radar', 'How defenders see it', sel.detect, 'det')}${note('shield-check', 'How to fix it', sel.fix, 'fix')}</div>
      ${sel.refs && sel.refs.length ? `<section class="cg-ds"><h3>Read more</h3><div class="cg-refs">${sel.refs.map(([l, u]) => /^https:\/\//.test(u) ? `<a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(l)}${ico('arrow-up-right','sm')}</a>` : '').join('')}</div></section>` : ''}
    </article>` : '<div class="cg-d cg-none">Pick a technique.</div>';
}
function cloudGuideView(){
  const G = cgAll(), q = (UI.cgQ || '').trim().toLowerCase(), words = q.split(/\s+/).filter(Boolean), pv = UI.cgProv || '', lv = UI.cgLvl || '';
  const match = c => (!words.length || words.every(w => c.hay.includes(w))) && (!pv || c.provider === pv) && (!lv || (c.level || 'basic') === lv);
  const hits = G.map(g => [g, g.cards.filter(match)]), total = G.reduce((n, g) => n + g.cards.length, 0), nHit = hits.reduce((n, x) => n + x[1].length, 0);
  const cur = (q || pv || lv) && !UI.cgCatPinned ? 'all' : (G.some(g => g.name === UI.cgCat) ? UI.cgCat : 'all');
  const list = hits.filter(([g]) => cur === 'all' || g.name === cur);
  const flat = list.flatMap(([, cs]) => cs);
  let sel = flat.find(c => c.k === UI.cgSel) || flat[0] || null; if(sel) UI.cgSel = sel.k;
  const provs = [...new Set(G.flatMap(g => g.cards.map(c => c.provider)).filter(p => CG_PROV[p]))];
  const railItem = (k, label, icon, n, on) => `<button class="cg-nav${on ? ' on' : ''}" data-act="cgCat" data-v="${esc(k)}" aria-pressed="${on}"${n === 0 ? ' disabled' : ''}>${icon ? ico(icon, 'sm') : ''}<span class="cg-nav-l">${esc(label)}</span><span class="cg-nav-n">${n}</span></button>`;
  const rail = `<aside class="cg-rail" aria-label="Field-guide sections">
      ${railItem('all', 'All sections', 'layers', nHit, cur === 'all')}
      ${hits.map(([g, cs]) => railItem(g.name, g.name, g.icon, cs.length, cur === g.name)).join('')}</aside>`;
  const item = c => `<button class="cg-it${sel && sel.k === c.k ? ' on' : ''}" data-act="cgSel" data-v="${esc(c.k)}" aria-pressed="${!!(sel && sel.k === c.k)}">
      <span class="cg-it-h">${cgProvTag(c)}${cgLvlTag(c)}</span><b>${esc(c.t)}</b><small>${esc(c.body)}</small></button>`;
  const listHtml = list.filter(([, cs]) => cs.length).map(([g, cs]) => `${cur === 'all' ? `<div class="cg-lh">${ico(g.icon, 'sm')}${esc(g.name)}<span>${cs.length}</span></div>` : `<div class="cg-lnote">${esc(g.note || '')}</div>`}${cs.map(item).join('')}`).join('')
    || `<div class="cg-none">Nothing matches. Try fewer words or clear the filters.</div>`;
  const detail = cgDetailHtml(sel);
  return `<section class="cld-pane cg">
    <div class="cg-top"><div class="search-in cg-q">${ico('search')}<label class="sr" for="cgQ">Search the guide</label><input id="cgQ" class="inp" placeholder="Search ${total} techniques — ssrf, s3, passrole, kubectl, consent…" value="${esc(UI.cgQ || '')}" autocomplete="off">${UI.cgQ ? `<button class="iconbtn" data-act="cgClear" aria-label="Clear">${ico('x','sm')}</button>` : '<kbd>/</kbd>'}</div>
      <div class="cg-filt"><div class="seg" role="group" aria-label="Provider"><button data-act="cgProv" data-v="" aria-pressed="${!pv}">All</button>${provs.map(p => `<button data-act="cgProv" data-v="${p}" aria-pressed="${pv === p}">${CG_PROV[p][0]}</button>`).join('')}</div>
        <label class="sr" for="cgLvl">Level</label><select id="cgLvl" class="gsel bord"><option value="">Any level</option>${Object.entries(CG_LVL).map(([k, [l]]) => `<option value="${k}"${lv === k ? ' selected' : ''}>${l}</option>`).join('')}</select></div></div>
    <p class="cg-scope">${ico('shield-check','sm')}For CTFs, bug bounty and systems you are authorised to test. Nothing runs from here; commands are copied as text.</p>
    <div class="cg-layout">${rail}<div class="cg-list" id="cgMain">${listHtml}</div>${detail}</div></section>`;
}

/* ---------------- actions ---------------- */
function cloudRunScan(text, name){
  if(!text || !text.trim()) return toast('Nothing to scan');
  try{ const R = cloudScan(text, name || ''); R.name = name || 'Pasted config'; UI.cloudScan = R; UI.cloudTab = 'scanner'; renderMain(); }
  catch(e){ toast('Could not scan that file'); }
}
function cloudRunLogs(text, name){
  if(!text || !text.trim()) return toast('Nothing to hunt');
  try{ const R = CL.parse(text); R.name = name || 'Pasted log'; UI.cloudLogs = R; UI.cloudTab = 'logs'; renderMain(); }
  catch(e){ toast('Could not read that log'); }
}
function cloudReadFile(file, cb){
  if(!file) return; if(file.size > 52428800) return toast('That file is over 50 MB');
  const r = new FileReader(); r.onload = () => cb(String(r.result), file.name); r.readAsText(file);
}
function cloudFindingsToCase(){
  const R = UI.cloudScan; if(!R || !R.findings.length) return; const cid = DB.active && theCase() ? DB.active : (DB.cases[0] && DB.cases[0].id); if(!cid) return toast('Create a case first');
  const body = `Cloud misconfiguration scan — ${R.kindLabel}${R.name ? ' (' + R.name + ')' : ''}\n` +
    R.findings.map(f => `[${f.sev.toUpperCase()}] ${f.title}${f.where ? '  @' + f.where : ''}\n  ${f.detail}\n  Fix: ${f.fix}`).join('\n\n');
  const r = {id:uid('r'), caseId:cid, type:'finding', title:'Cloud scan: ' + R.findings.length + ' finding' + (R.findings.length === 1 ? '' : 's') + ' in ' + (R.name || R.kindLabel), body,
    tsRaw:'', tsZone:'', ts:null, source:'cloud-scan', host:'', tags:['cloud', 'misconfig', R.kind], ents:[], answer:'', addedBy:'You', addedAt:Date.now(), hash:'', pv:1, att:[]};
  DB.records.push(r); mutate('added cloud scan to ' + theCase(cid).code); hashRecords().then(renderAll);
  toast('Added to ' + theCase(cid).code, 'Open', () => { UI.sel = {kind:'rec', id:r.id}; UI.inspOpen = true; go(caseHash(cid, 'timeline')); });
}
function cloudLogsToTimeline(){
  const R = UI.cloudLogs; if(!R || !R.rows.length) return; if(!DB.cases.length) return toast('Create a case first');
  const rows = R.rows.map(e => ({time:e.time, event:e.name + (e.why ? ' — ' + e.why : ''), actor:e.actor, src:e.src_ip, service:e.service, severity:e.sev || '', error:e.error || '', resource:e.resource || ''}));
  const cols = [...new Set(rows.flatMap(r => Object.keys(r)))];
  LOGIMP = {title:'Send cloud log events to the timeline', caseId:DB.active, name:R.name || 'cloud log', fmt:R.fmtLabel, rows, cols, map:{time:'time', title:'event', host:'src', source:'service'}};
  logImportDlg();
}

function bindCloud(){
  const wire = (id, run) => { const el = $(id); if(!el) return; const inp = el.querySelector('input'); el.onkeydown = e => { if(e.key === 'Enter' || e.key === ' '){ e.preventDefault(); inp.click(); } };
    if(inp) inp.onchange = () => cloudReadFile(inp.files[0], run);
    el.ondragover = e => { e.preventDefault(); el.classList.add('over'); }; el.ondragleave = () => el.classList.remove('over');
    el.ondrop = e => { e.preventDefault(); el.classList.remove('over'); cloudReadFile(e.dataTransfer.files[0], run); }; };
  wire('csDrop', cloudRunScan); wire('clDrop', cloudRunLogs);
  const lvs = $('cgLvl'); if(lvs) lvs.onchange = () => { UI.cgLvl = lvs.value; UI.cgSel = null; renderMain(); };
  const cg = $('cgQ'); if(cg) cg.oninput = () => { UI.cgQ = cg.value; clearTimeout(bindCloud.t); bindCloud.t = setTimeout(() => { renderMain(); const x = $('cgQ'); if(x){ x.focus(); x.setSelectionRange(x.value.length, x.value.length); } }, 150); };
}

const CLOUD_ACTS = {
  cloudTab:(id, v) => { UI.cloudTab = v; renderMain(); },
  cgCat:(id, v) => { UI.cgCat = v; UI.cgCatPinned = v !== 'all'; UI.cgSel = null; renderMain(); const m = $('cgMain'); if(m) m.scrollTop = 0; },
  cgSel:(id, v) => { UI.cgSel = v; UI.cgOpen = true; document.querySelectorAll('.cg-it').forEach(b => { const on = b.dataset.v === v; b.classList.toggle('on', on); b.setAttribute('aria-pressed', on); });
    const card = cgAll().flatMap(g => g.cards).find(c => c.k === v), d = $('cgDetail'); if(!card || !d) return renderMain();
    d.outerHTML = cgDetailHtml(card); const n = $('cgDetail'); if(n) n.scrollTop = 0; },
  cgBack:() => { UI.cgOpen = false; const d = $('cgDetail'); if(d) d.classList.remove('open'); },
  cgProv:(id, v) => { UI.cgProv = v; UI.cgSel = null; renderMain(); },
  cgClear:() => { UI.cgQ = ''; renderMain(); },
  cloudScanText:() => { const t = $('csText'); cloudRunScan(t ? t.value : '', 'Pasted config'); },
  cloudLogText:() => { const t = $('clText'); cloudRunLogs(t ? t.value : '', 'Pasted log'); },
  cloudSample:(id, v) => { const txt = CLOUD_SAMPLES[v]; if(!txt) return; if(/CloudTrail/.test(v)) cloudRunLogs(txt, v); else cloudRunScan(txt, v); },
  cloudRescan:() => { UI.cloudScan = null; renderMain(); },
  cloudLogReset:() => { UI.cloudLogs = null; renderMain(); },
  cloudToCase:() => cloudFindingsToCase(),
  cloudLogCase:() => cloudLogsToTimeline(),
  cloudExport:() => { const R = UI.cloudScan; if(!R) return; download('cloud-scan-' + new Date().toISOString().slice(0, 10) + '.json', JSON.stringify({scanned:R.name, kind:R.kindLabel, resources:R.resources, counts:R.counts, findings:R.findings}, null, 2), 'application/json'); },
  cloudCopy:(id, v) => copyText(v)
};
