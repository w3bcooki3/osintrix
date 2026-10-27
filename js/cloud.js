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
const CG_PROV = {aws:['AWS', '#ff9900'], azure:['Azure', '#2f9bff'], gcp:['GCP', '#4f8cff'], k8s:['K8s', '#4f7cff'], web:['Web', '#22c55e']};
function cloudGuideView(){
  const q = (UI.cgQ || '').trim().toLowerCase();
  const matchCard = c => !q || (c.t + ' ' + c.body + ' ' + c.cmds.map(x => x.join(' ')).join(' ') + ' ' + (c.provider || '')).toLowerCase().includes(q);
  const groupHits = CLOUDGUIDE.map(g => [g, g.cards.filter(matchCard)]);
  const total = CLOUDGUIDE.reduce((n, g) => n + g.cards.length, 0);
  const cur = !q && CLOUDGUIDE.some(g => g.name === UI.cgCat) ? UI.cgCat : (q ? 'all' : (UI.cgCat || 'all'));
  const railItem = (k, label, icon, n, on) => `<button class="cg-nav${on ? ' on' : ''}" data-act="cgCat" data-v="${esc(k)}" aria-pressed="${on}"${n === 0 ? ' disabled' : ''}>${icon ? ico(icon, 'sm') : `<span class="cg-nav-dot"></span>`}<span class="cg-nav-l">${esc(label)}</span><span class="cg-nav-n">${n}</span></button>`;
  const rail = `<aside class="cg-rail" aria-label="Field-guide sections">
      <div class="cg-rail-h"><span class="ix">Field guide</span><span class="cg-rail-c">${q ? groupHits.reduce((n, x) => n + x[1].length, 0) + ' of ' + total : total}</span></div>
      ${railItem('all', 'All sections', 'layers', q ? groupHits.reduce((n, x) => n + x[1].length, 0) : total, cur === 'all')}
      ${groupHits.map(([g, cards]) => railItem(g.name, g.name, g.icon, q ? cards.length : g.cards.length, cur === g.name)).join('')}
    </aside>`;
  const cmdRow = ([l, cmd]) => `<div class="cg-cmd"><div class="cg-cmd-l">${esc(l)}</div><div class="cg-term"><span class="cg-pr" aria-hidden="true">$</span><code>${esc(cmd)}</code><button class="cg-copy" data-act="cloudCopy" data-v="${esc(cmd)}" aria-label="Copy: ${esc(l)}" title="Copy">${ico('copy','sm')}</button></div></div>`;
  const card = c => `<article class="cg-c">
    <header>${c.provider && CG_PROV[c.provider] ? `<span class="cg-p"><i style="background:${CG_PROV[c.provider][1]}"></i>${CG_PROV[c.provider][0]}</span>` : ''}<h3>${esc(c.t)}</h3>${c.att ? `<a class="cg-att" href="https://attack.mitre.org/techniques/${esc(c.att.replace('.', '/'))}/" target="_blank" rel="noopener noreferrer">${esc(c.att)} ${ico('arrow-up-right','sm')}</a>` : ''}</header>
    <p>${esc(c.body)}</p>
    <div class="cg-cmds">${c.cmds.map(cmdRow).join('')}</div></article>`;
  const visible = groupHits.filter(([g, cards]) => (cur === 'all' || g.name === cur) && cards.length);
  const main = visible.length ? visible.map(([g, cards]) => `<section class="cg-sec" id="cg-${esc(g.name.replace(/\W+/g, '-'))}"><header class="cg-sh"><div class="cg-sh-t">${ico(g.icon, 'sm')}<h2>${esc(g.name)}</h2><span class="cg-sh-n">${cards.length}</span></div><p>${esc(g.note)}</p></header><div class="cg-grid">${cards.map(card).join('')}</div></section>`).join('')
    : `<div class="hx2-empty">Nothing matches “${esc(UI.cgQ || '')}”.</div>`;
  return `<section class="cld-pane cg">
    <div class="cg-top"><div class="search-in cg-q">${ico('search')}<label class="sr" for="cgQ">Search the guide</label><input id="cgQ" class="inp" placeholder="Search ${total} techniques — ssrf, s3, idor, kubectl, nuclei…" value="${esc(UI.cgQ || '')}" autocomplete="off">${UI.cgQ ? `<button class="iconbtn" data-act="cgClear" aria-label="Clear">${ico('x','sm')}</button>` : '<kbd>/</kbd>'}</div>
      <div class="note accent cg-note"><span class="ic">${ico('shield-check','sm')}</span><div>For CTFs, bug bounty and systems you are authorised to test. Commands are enumeration and triage starting points — nothing runs from here.</div></div></div>
    <div class="cg-layout">${rail}<div class="cg-main" id="cgMain">${main}</div></div></section>`;
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
  const cg = $('cgQ'); if(cg) cg.oninput = () => { UI.cgQ = cg.value; clearTimeout(bindCloud.t); bindCloud.t = setTimeout(() => { renderMain(); const x = $('cgQ'); if(x){ x.focus(); x.setSelectionRange(x.value.length, x.value.length); } }, 150); };
}

const CLOUD_ACTS = {
  cloudTab:(id, v) => { UI.cloudTab = v; renderMain(); },
  cgCat:(id, v) => { UI.cgCat = v; renderMain(); const m = $('cgMain'); if(m) m.scrollTop = 0; },
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
