/* ==========================================================================
   Inspector + dialogs
   ========================================================================== */
const TOOL_FOR = {ip:['ip-analysis'], domain:['domain-investigation','dns-analysis'], email:['email-investigation','breach-data'], username:['username-investigation','social-media'],
  social:['social-media','username-investigation'], phone:['phone-investigation'], person:['people-search','public-records'], file:['hash-lookup','file-analysis','sandboxes'],
  media:['image-investigation'], location:['geolocation'], url:['url-analysis'], threat:['threat-hunting','ioc-analysis'], document:['metadata-analysis']};
const ihead = (label, extra = '') => `<div class="ihead"><span class="caps">${label}</span>${extra}<button class="iconbtn" data-act="closeInsp" aria-label="Close">${ico('x')}</button></div>`;

function renderInsp(){
  const el = $('insp'); el.classList.toggle('closed', !UI.inspOpen);
  if(!UI.inspOpen){ el.innerHTML = ''; return; }
  const s = UI.sel;
  try{
    if(s && s.kind === 'entry' && entryById(s.id)) return el.innerHTML = inspEntry(entryById(s.id));
    if(s && s.kind === 'link' && DB.links.find(l => l.id === s.id)) return el.innerHTML = inspLink(DB.links.find(l => l.id === s.id));
    if(s && s.kind === 'rec' && recById(s.id)) return el.innerHTML = inspRecord(recById(s.id));
    if(s && s.kind === 'ent') return el.innerHTML = inspEnt(s.id);
    if(s && s.kind === 'feed') return el.innerHTML = inspFeed(DB.feed.find(f => f.id === s.id));
  }catch(err){ console.error(err); }
  el.innerHTML = ihead('Details') + `<div class="ibody">${empty('eye','Nothing selected','Pick a vault entry, a piece of evidence or a node on the graph to see everything about it here.')}</div>`;
}

function inspEntry(e){
  const t = TYPES[e.type], v = entryVerdict(e), mentions = entryMentions(e), src = recById(e.src);
  const links = DB.links.filter(l => l.a === e.id || l.b === e.id);
  const k = entryKey(e), g = k ? globalEnts().get(k) : null, other = g ? [...g.cases].filter(x => x !== e.caseId) : [];
  const tools = DB.tools.filter(x => (TOOL_FOR[e.type] || []).includes(x.sub)).slice(0, 6);
  const m = k ? E.meaning(entSplit(k).k, entSplit(k).v) : null;
  return ihead('Vault entry', `<button class="iconbtn${e.starred ? ' on' : ''}" data-act="star" data-id="${e.id}" aria-label="Star">${ico('star')}</button>`) + `<div class="ibody">
    <div style="display:flex;gap:14px;align-items:flex-start">${tbadge(e.type,'lg')}<div style="min-width:0"><div class="t3" style="font-size:13px;font-weight:560">${esc(t.label)}</div>
      <h2 class="${MONO_TYPES.has(e.type) ? 'mono' : ''}" style="overflow-wrap:anywhere;${MONO_TYPES.has(e.type) ? 'font-size:16px;font-weight:600' : ''}">${esc(primary(e))}</h2>
      ${m ? `<div style="font-size:13px;margin-top:3px;color:${m.hot ? 'var(--amber)' : 'var(--text-3)'}">${esc(m.t)}</div>` : ''}${k ? `<div class="cxts">${ctxChips(entSplit(k).k, entSplit(k).v)}</div>` : ''}</div></div>
    <div class="wrap" style="margin-top:14px"><button class="btn sm" data-act="editEntry" data-id="${e.id}">${ico('pencil','sm')}Edit</button>${k ? `<button class="btn sm${isWatched(k) ? ' on' : ''}" data-act="watch" data-id="${esc(k)}">${ico(isWatched(k) ? 'eye-off' : 'eye','sm')}${isWatched(k) ? 'Unwatch' : 'Watch'}</button>` : ''}<button class="btn sm" data-act="linkFrom" data-id="${e.id}">${ico('git-branch','sm')}Connect</button>
      <a class="btn sm" href="${caseHash(e.caseId,'graph')}" data-act="showInGraph" data-id="${e.id}">${ico('waypoints','sm')}Graph</a><button class="btn sm danger" data-act="delEntry" data-id="${e.id}" aria-label="Delete">${ico('trash-2','sm')}</button></div>
    ${pivotSection(k ? entSplit(k).k : e.type, k ? entSplit(k).v : primary(e))}
    <div class="isec"><h4>Verdict ${k ? '<span class="t3">applies in every case</span>' : ''}</h4><div class="seg v">${[['malicious','Malicious'],['suspicious','Suspicious'],['benign','Benign'],['','Unknown']].map(([x, l]) => `<button data-act="entryVerdict" data-id="${e.id}" data-v="${x}" aria-pressed="${v === x}">${l}</button>`).join('')}</div></div>
    <div class="isec"><h4>Priority</h4><div class="seg">${['low','medium','high','critical'].map(p => `<button data-act="entryPrio" data-id="${e.id}" data-v="${p}" aria-pressed="${e.priority === p}">${p[0].toUpperCase() + p.slice(1)}</button>`).join('')}</div></div>
    <div class="isec"><h4>Details</h4><dl class="kv">${t.fields.filter(([n]) => e.fields[n]).map(([n, l]) => `<dt>${esc(l)}</dt><dd class="${MONO_TYPES.has(e.type) && n === t.fields[0][0] ? 'mono' : ''}">${esc(e.fields[n])}</dd>`).join('')}
      <dt>Added</dt><dd>${esc(E.fmtFull(e.created, tz()).slice(0, 16))}</dd>${src ? `<dt>Source</dt><dd><button class="linkbtn" data-act="selRec" data-id="${src.id}">${esc(src.title)}</button></dd>` : ''}</dl>
      ${e.tags.length ? `<div class="wrap" style="margin-top:12px">${e.tags.map(x => `<span class="chip sq">#${esc(x)}</span>`).join('')}</div>` : ''}
      ${e.notes ? `<p style="margin:12px 0 0;color:var(--text-2);font-size:14px;line-height:1.6">${esc(e.notes)}</p>` : ''}</div>
    ${other.length ? `<div class="isec"><div class="note amber"><span class="ic">${ico('link-2','sm')}</span><div><b>Also in ${other.length} other case${other.length > 1 ? 's' : ''}:</b> ${other.map(x => `<a href="${caseHash(x)}">${esc(theCase(x).name)}</a>`).join(', ')}</div></div></div>` : ''}
    <div class="isec"><h4>Relationships <span class="t3">${links.length}</span></h4>
      ${links.map(l => { const out = l.a === e.id, o = entryById(out ? l.b : l.a); return o ? `<div class="rel"><div class="rt"><span class="dir" title="${out ? 'Outgoing' : 'Incoming'}">${ico(out ? 'arrow-up-right' : 'undo-2','sm')}</span><button class="lab" data-act="selLink" data-id="${l.id}">${out ? '' : '← '}${esc(l.label)}</button>${conf(l.conf)}</div>${entryPill(o)}</div>` : ''; }).join('') || '<span class="t3" style="font-size:13.5px">None yet — use Connect.</span>'}</div>
    <div class="isec"><h4>Evidence that mentions it <span class="t3">${mentions.length}</span></h4>
      ${mentions.slice(0, 8).map(r => `<button class="li" data-act="selRec" data-id="${r.id}" style="padding:8px 0"><div class="main2"><b style="font-weight:520;font-size:14px">${esc(r.title)}</b><small>${r.ts ? esc(E.fmtFull(r.ts, tz()).slice(5, 16)) : 'no time'}${r.host ? ' · ' + esc(r.host) : ''}</small></div></button>`).join('') || '<span class="t3" style="font-size:13.5px">No captured record mentions this yet.</span>'}</div>
    ${tools.length ? `<div class="isec"><h4>From your toolbox</h4><div class="wrap">${tools.map(x => { const u = E.safeUrl(x.url); return u ? `<a class="btn sm" href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(x.name)} ${ico('external-link','sm')}</a>` : ''; }).join('')}</div>
      <p class="heur">Opens the tool's site. The value is not sent anywhere.</p></div>` : ''}
  </div>`;
}
function inspLink(l){
  const a = entryById(l.a), b = entryById(l.b), r = recById(l.src);
  return ihead('Relationship') + `<div class="ibody">
    <div style="display:flex;flex-direction:column;gap:10px;align-items:flex-start">${entryPill(a)}<span style="color:var(--accent);font-weight:620;display:flex;gap:6px;align-items:center">${ico('arrow-up-right','sm')}${esc(l.label)}</span>${entryPill(b)}</div>
    <div class="isec"><dl class="kv"><dt>Confidence</dt><dd>${conf(l.conf)} ${['','Low','Medium','High'][l.conf]}</dd><dt>Evidence</dt><dd>${r ? `<button class="linkbtn" data-act="selRec" data-id="${r.id}">${esc(r.title)}</button>` : '—'}</dd><dt>Kind</dt><dd>${l.auto ? 'Found in evidence' : 'Analyst claim'}</dd>${l.why ? `<dt>Why</dt><dd>${esc(l.why)}</dd>` : ''}</dl></div>
    <div class="wrap" style="margin-top:18px"><button class="btn sm" data-act="editLink" data-id="${l.id}">${ico('pencil','sm')}Edit</button><button class="btn sm danger" data-act="delLink" data-id="${l.id}">${ico('trash-2','sm')}Delete</button></div></div>`;
}
function inspRecord(r){
  const c = theCase(r.caseId), D = derive(r.caseId), obs = E.observations(r), rel = r.ts ? E.relClock(r.ts, D.t0) : null;
  return ihead(typeLabel(r.type)) + `<div class="ibody"><h2>${esc(r.title)}</h2>
    ${r.type === 'lead' ? `<div class="isec"><h4>Answer</h4><form data-form="answer" data-id="${r.id}" style="display:flex;gap:8px"><label class="sr" for="ansIn">Answer</label><input id="ansIn" class="inp" value="${esc(r.answer)}" placeholder="What you concluded"><button class="btn primary" type="submit">Save</button></form></div>` : ''}
    <div class="isec"><h4>Where it came from</h4><dl class="kv">
      <dt>When</dt><dd>${r.ts ? esc(E.fmtFull(r.ts, tz())) + ' ' + esc(tz()) : 'No timestamp'}</dd>${rel ? `<dt>Since T0</dt><dd style="color:var(--amber)" class="mono">${rel}</dd>` : ''}
      <dt>Source</dt><dd>${esc(r.source || '—')}</dd><dt>Host</dt><dd>${esc(r.host || '—')}</dd><dt>Case</dt><dd>${esc(c.name)}</dd>
      <dt>Added</dt><dd>${esc(r.addedBy)} · ${esc(E.fmtFull(r.addedAt, tz()).slice(0, 16))}</dd><dt>SHA-256</dt><dd class="mono" title="Fingerprint of the captured text">${esc((r.hash || '…').slice(0, 24))}…</dd></dl>
      ${r.ts ? `<button class="btn sm" data-act="setT0" data-id="${r.id}" style="margin-top:12px">${ico('crosshair','sm')}${c.t0 === r.id ? 'Clear T0' : 'Make this T0'}</button>` : ''}</div>
    ${r.body ? `<div class="isec"><h4>Captured text</h4><pre class="rawbox">${esc(r.body)}</pre></div>` : ''}
    ${r.body ? fieldsSection(r) : ''}
    ${obs.length ? `<div class="isec"><h4>Observations <span class="t3">heuristic</span></h4>${obs.map(o => `<div class="note amber obs"><span class="ic">${ico('triangle-alert','sm')}</span><div><b>${esc(o.tag[0].toUpperCase() + o.tag.slice(1))}</b> — ${esc(o.t)}</div></div>`).join('')}</div>` : ''}
    <div class="isec"><h4>Entities found <span class="t3">${r.ents.length}</span></h4><div class="wrap">${r.ents.map(e => { const id = entKey(e), en = D.byKey.get(id); return en ? entryPill(en) : entPill(id); }).join('') || '<span class="t3">None.</span>'}</div></div>
    ${aroundHTML(r)}
    ${attSection(r)}
    <div class="isec"><div class="wrap"><button class="btn sm danger" data-act="recDel" data-id="${r.id}">${ico('trash-2','sm')}Delete record</button></div></div></div>`;
}
function inspEnt(id){
  const {k, v} = entSplit(id), g = globalEnts().get(id), recs = g ? g.recs : [], m = E.meaning(k, v), vd = verdictOf(id), canVault = !!KIND_TO_TYPE[k];
  return ihead('Indicator') + `<div class="ibody"><div style="display:flex;gap:14px;align-items:flex-start">${kindBadge(k,'lg')}<div style="min-width:0"><div class="t3" style="font-size:13px">${esc(E.LABEL[k] || k)} · extracted</div><h2 class="mono" style="font-size:16px;font-weight:600;overflow-wrap:anywhere">${esc(v)}</h2>
    ${m ? `<div style="font-size:13px;margin-top:3px;color:${m.hot ? 'var(--amber)' : 'var(--text-3)'}">${esc(m.t)}</div>` : ''}<div class="cxts">${ctxChips(k, v)}</div></div></div>
    <div class="wrap" style="margin-top:14px"><button class="btn sm${isWatched(id) ? ' on' : ''}" data-act="watch" data-id="${esc(id)}">${ico(isWatched(id) ? 'eye-off' : 'eye','sm')}${isWatched(id) ? 'Unwatch' : 'Watch'}</button></div>
    ${canVault && !derive().byKey.has(id) ? `<button class="btn primary sm" data-act="promote" data-id="${esc(id)}" style="margin-top:14px">${ico('plus','sm')}Add to ${esc(theCase().code)} vault</button>` : ''}
    ${pivotSection(k, v)}
    <div class="isec"><h4>Verdict <span class="t3">applies in every case</span></h4><div class="seg v">${[['malicious','Malicious'],['suspicious','Suspicious'],['benign','Benign'],['','Unknown']].map(([x, l]) => `<button data-act="entVerdict" data-id="${esc(id)}" data-v="${x}" aria-pressed="${vd === x}">${l}</button>`).join('')}</div></div>
    <div class="isec"><h4>Appears in <span class="t3">${recs.length} records · ${g ? g.cases.size : 0} cases</span></h4>${recs.slice(0, 10).map(r => `<button class="li" data-act="selRec" data-id="${r.id}" style="padding:8px 0"><div class="main2"><b style="font-weight:520;font-size:14px">${esc(r.title)}</b><small>${esc(theCase(r.caseId).code)}${r.ts ? ' · ' + esc(E.fmtFull(r.ts, tz()).slice(5, 16)) : ''}</small></div></button>`).join('')}</div>
    <div class="wrap" style="margin-top:16px"><button class="btn sm" data-act="pivot" data-id="${esc(id)}">${ico('filter','sm')}Filter timeline to this</button></div></div>`;
}
function inspFeed(f){
  if(!f) return '';
  const g = globalEnts(), hits = E.extract(f.title + ' ' + f.body);
  return ihead('Feed item') + `<div class="ibody"><h2>${esc(f.title)}</h2><p class="t3" style="font-size:13px;margin:6px 0 14px">${esc(f.source)} · ${esc(E.fmtDate(f.ts, tz()))}</p><pre class="rawbox" style="font-family:var(--font);font-size:14px">${esc(f.body)}</pre>
    <div class="isec"><h4>Entities</h4><div class="wrap">${hits.map(e => entPill(entKey(e))).join('')}</div>${hits.some(e => g.has(entKey(e))) ? '<p class="heur">Highlighted entities already exist in your cases.</p>' : ''}</div>
    <div class="wrap" style="margin-top:18px"><button class="btn primary" data-act="feedToCase" data-id="${f.id}">${ico('plus','sm')}Add to ${esc(theCase().code)}</button>${E.safeUrl(f.link) ? `<a class="btn" href="${esc(E.safeUrl(f.link))}" target="_blank" rel="noopener noreferrer">Read original ${ico('arrow-up-right','sm')}</a>` : ''}</div></div>`;
}

/* ---------- dialogs ---------- */
let lastFocus = null;
function openDlg(html, wide, after){ lastFocus = document.activeElement; $('scrim').hidden = false; const d = $('dlg'); d.className = 'dlg' + (wide ? ' wide' : ''); d.removeAttribute('aria-labelledby'); d.innerHTML = html; if(after) after();
  const f = d.querySelector('[autofocus]') || d.querySelector('input,select,textarea,button'); if(f) f.focus(); }
function closeDlg(){ UI.graph.linkFrom = null; $('scrim').hidden = true; $('dlg').innerHTML = ''; if(lastFocus && lastFocus.focus) lastFocus.focus(); }
const dhead = t => `<header><h3>${t}</h3><button class="iconbtn" type="button" data-act="dclose" aria-label="Close">${ico('x')}</button></header>`;

/* vault entry — pick a type, then its own fields (the Multi-vault form, one list) */
let entryDraft = null;
function entryDlg(edit, pre){
  const e = edit ? entryById(edit) : null;
  entryDraft = e ? {id:e.id, type:e.type, fields:{...e.fields}, priority:e.priority, tags:e.tags.join(', '), notes:e.notes}
    : {type:(pre && pre.type) || null, fields:(pre && pre.fields) || {}, priority:'medium', tags:'', notes:'', src:pre && pre.src};
  paintEntryDlg();
}
function paintEntryDlg(){
  const d = entryDraft, t = d.type ? TYPES[d.type] : null;
  if(!t){
    openDlg(dhead('Add to vault') + `<div class="in"><p class="t2" style="margin:0 0 16px">What are you adding?</p>
      ${GROUPS.map(([g, l,, col]) => `<div class="caps" style="margin:14px 0 8px">${l}</div><div class="typegrid">${TYPE_LIST.filter(x => x[3] === g).map(([id, lab]) => `<button type="button" data-act="pickType" data-v="${id}">${tbadge(id,'sm')}${esc(lab)}</button>`).join('')}</div>`).join('')}</div>`, true);
    return;
  }
  const f = ([n, l, inp, opts], i) => `<div class="field"><label for="ef-${n}">${esc(l)}${i === 0 ? ' <span class="t3">required</span>' : ''}</label>${inp === 'select'
    ? `<select id="ef-${n}" data-f="${n}"><option value=""></option>${opts.map(o => `<option${d.fields[n] === o ? ' selected' : ''}>${esc(o)}</option>`).join('')}</select>`
    : `<input id="ef-${n}" data-f="${n}" type="${inp === 'number' ? 'text' : inp}" value="${esc(d.fields[n] || '')}" ${i === 0 ? 'required autofocus' : ''} ${inp === 'number' ? 'inputmode="numeric"' : ''} autocomplete="off">`}</div>`;
  openDlg(dhead((d.id ? 'Edit ' : 'New ') + t.label.toLowerCase()) + `<form data-form="entry"><div class="in">
    <div style="display:flex;gap:12px;align-items:center;margin-bottom:18px">${tbadge(d.type)}<div><b>${esc(t.label)}</b><div class="t3" style="font-size:13px">${esc(GROUPS.find(g => g[0] === t.group)[1])}</div></div>${d.id ? '' : `<button type="button" class="btn sm ghost" data-act="pickType" data-v="" style="margin-left:auto">Change type</button>`}</div>
    <div class="frow">${t.fields.map(f).join('')}</div>
    <div class="frow"><div class="field"><label for="ef-prio">Priority</label><select id="ef-prio">${['low','medium','high','critical'].map(p => `<option value="${p}"${d.priority === p ? ' selected' : ''}>${p[0].toUpperCase() + p.slice(1)}</option>`).join('')}</select></div>
      <div class="field"><label for="ef-tags">Tags</label><input id="ef-tags" value="${esc(d.tags)}" placeholder="actor, c2"></div></div>
    <div class="field" style="margin:0"><label for="ef-notes">Notes</label><textarea id="ef-notes" rows="3" placeholder="What you know and how you know it">${esc(d.notes)}</textarea></div></div>
    <footer><span class="t3">${d.id ? '' : 'Lands in ' + esc(theCase().name.split(' — ')[0])}</span><button class="btn" type="button" data-act="dclose">Cancel</button><button class="btn primary" type="submit">${d.id ? 'Save changes' : 'Add to vault'}</button></footer></form>`, true);
}

function caseDlg(edit){
  const c = edit ? theCase() : null, st = {color:c ? c.color : CASE_COLORS[0], icon:c ? c.icon : CASE_ICONS[0]};
  window.__caseDraft = st;
  openDlg(dhead(c ? 'Edit case' : 'New case') + `<form data-form="case" data-edit="${c ? 1 : ''}"><div class="in">
    <div class="field"><label for="cName">Name</label><input id="cName" value="${esc(c ? c.name : '')}" required autofocus placeholder="What are you investigating?"></div>
    <div class="field"><label for="cScope">Scope</label><textarea id="cScope" rows="3" placeholder="What is in and out of scope, and what authorises the work">${esc(c ? c.scope : '')}</textarea></div>
    <div class="field"><span class="label">Colour</span><div class="swatches" id="sw">${CASE_COLORS.map(x => `<button type="button" data-act="pickColor" data-v="${x}" style="--c:${x}" aria-pressed="${st.color === x}" aria-label="Colour ${x}"></button>`).join('')}</div></div>
    <div class="field"><span class="label">Icon</span><div class="icopick" id="ip">${CASE_ICONS.map(x => `<button type="button" data-act="pickIcon" data-v="${x}" aria-pressed="${st.icon === x}" aria-label="${x}">${ico(x)}</button>`).join('')}</div></div>
    ${c ? `<div class="field" style="margin:0"><label for="cStatus">Status</label><select id="cStatus">${['active','review','closed'].map(s => `<option value="${s}"${c.status === s ? ' selected' : ''}>${{active:'Active', review:'In review', closed:'Closed'}[s]}</option>`).join('')}</select></div>` : ''}
    ${c ? `<div class="dzone"><div><b>Danger zone</b><span>Archiving hides the case from the sidebar but keeps everything. Deleting removes it for good.</span></div>
      <div class="wrap"><button class="btn sm" type="button" data-act="archiveCase">${ico('lock','sm')}${c.status === 'closed' ? 'Reopen' : 'Archive'}</button><button class="btn sm dangerbtn" type="button" data-act="deleteCaseDlg">${ico('trash-2','sm')}Delete case…</button></div></div>` : ''}
  </div><footer><button class="btn" type="button" data-act="dclose">Cancel</button><button class="btn primary" type="submit">${c ? 'Save' : 'Create case'}</button></footer></form>`);
}
function deleteCaseDlg(id){
  const c = theCase(id), D = derive(c.id), notes = (DB.notes || []).filter(n => n.caseId === c.id).length;
  openDlg(`<header><span class="tb" style="--c:var(--red)">${ico('triangle-alert')}</span><h3>Delete “${esc(c.name)}”?</h3><button class="iconbtn" data-act="dclose" aria-label="Close">${ico('x')}</button></header>
    <div class="in"><p class="t2" style="margin:0 0 14px">This permanently removes the case and everything inside it from this browser. There is no server copy.</p>
      <div class="delcounts"><div><b>${D.entries.length}</b>vault entries</div><div><b>${D.recs.length}</b>evidence records</div><div><b>${D.links.length}</b>relationships</div><div><b>${notes}</b>notes</div></div>
      <div class="note accent" style="margin:16px 0"><span class="ic">${ico('download','sm')}</span><div><b>Keep a copy first?</b> Export the case to a JSON file you can import later. <button class="btn xs" data-act="exportCase" data-id="${c.id}" style="margin-left:6px">Export case</button></div></div>
      <div class="field" style="margin:0"><label for="delConfirm">Type <b class="mono" style="color:var(--text)">${esc(c.code)}</b> to confirm</label><input id="delConfirm" autocomplete="off" spellcheck="false" placeholder="${esc(c.code)}"></div></div>
    <footer><button class="btn" data-act="dclose">Cancel</button><button class="btn dangerfill" data-act="deleteCase" data-id="${c.id}" id="delGo" disabled>${ico('trash-2','sm')}Delete permanently</button></footer>`, false,
    () => { $('delConfirm').oninput = () => { $('delGo').disabled = $('delConfirm').value.trim() !== c.code; }; });
}

function toolDlg(id){
  const t = id ? DB.tools.find(x => x.id === id) : {name:'', url:'https://', cat:UI.tcat in TOOL_CATS ? UI.tcat : 'osint', sub:UI.tsub || '', desc:'', tags:[]};
  const subs = () => Object.entries((TOOL_CATS[$('tCat') ? $('tCat').value : t.cat] || {children:{}}).children).map(([k, l]) => `<option value="${k}"${t.sub === k ? ' selected' : ''}>${esc(l)}</option>`).join('');
  openDlg(dhead(id ? 'Edit tool' : 'Add a tool') + `<form data-form="tool" data-id="${id || ''}"><div class="in">
    <div class="frow"><div class="field"><label for="tName">Name</label><input id="tName" value="${esc(t.name)}" required autofocus></div>
      <div class="field"><label for="tUrl">Address</label><input id="tUrl" type="url" value="${esc(t.url)}" required pattern="https?://.+"><span class="hint">Must start with http:// or https://</span></div></div>
    <div class="frow"><div class="field"><label for="tCat">Category</label><select id="tCat">${Object.entries(TOOL_CATS).filter(([k]) => k !== 'general').map(([k, c]) => `<option value="${k}"${t.cat === k ? ' selected' : ''}>${esc(c.name)}</option>`).join('')}</select></div>
      <div class="field"><label for="tSub">Sub-category</label><select id="tSub">${subs()}</select></div></div>
    <div class="field"><label for="tDesc">What it is for</label><textarea id="tDesc" rows="3">${esc(t.desc)}</textarea></div>
    <div class="field"><label for="tTags">Tags</label><input id="tTags" value="${esc(t.tags.join(', '))}" placeholder="free, osint, email"></div>
    <div class="field" style="margin:0"><label for="tTpl">Lookup address <span class="t3">optional</span></label><input id="tTpl" value="${esc(t.tpl || '')}" placeholder="https://example.com/search?q={value}" spellcheck="false">
      <span class="hint">Put <span class="mono">{value}</span> where the IP, domain, email or hash goes. The tool then shows up under “Look up” for those entities.</span>
      <div class="wrap" style="margin-top:8px">${TPL_KINDS.map(([k, l]) => `<label class="chk kchk"><input type="checkbox" name="tKind" value="${k}"${(t.kinds || []).includes(k) ? ' checked' : ''}>${l}</label>`).join('')}</div></div></div>
    <footer>${id ? `<button class="btn danger" type="button" data-act="toolDel" data-id="${id}" style="margin-right:auto">${ico('trash-2','sm')}Delete</button>` : ''}<button class="btn" type="button" data-act="dclose">Cancel</button><button class="btn primary" type="submit">${id ? 'Save' : 'Add tool'}</button></footer></form>`,
    false, () => { $('tCat').onchange = () => { t.cat = $('tCat').value; t.sub = ''; $('tSub').innerHTML = subs(); }; });
}

function linkDlg(o = {}){
  const L = o.id ? DB.links.find(l => l.id === o.id) : null, D = derive();
  const a = L ? L.a : o.a, b = L ? L.b : o.b;
  const opts = sel => D.entries.map(e => `<option value="${e.id}"${e.id === sel ? ' selected' : ''}>${esc(TYPES[e.type].label + ' · ' + primary(e))}</option>`).join('');
  openDlg(dhead(L ? 'Edit relationship' : 'New relationship') + `<form data-form="link" data-id="${L ? L.id : ''}"><div class="in">
    <p class="t2" style="margin:0 0 16px;font-size:14px">A relationship is your claim. It carries a confidence and points at the evidence behind it.</p>
    <div class="field"><label for="lA">From</label><select id="lA">${opts(a)}</select></div>
    <div class="field"><label for="lL">Relationship</label><input id="lL" list="lSug" value="${esc(L ? L.label : '')}" required autofocus placeholder="e.g. uses email, resolves to, operates">
      <datalist id="lSug">${['uses email','resolves to','hosted on','registered via','registrant','operates','alias of','advertises wallet','paid','beacons to','drops','sent','posts on','sells','same person as','located at'].map(x => `<option value="${x}">`).join('')}</datalist></div>
    <div class="field"><label for="lB">To</label><select id="lB">${opts(b || (D.entries[1] || {}).id)}</select></div>
    <div class="frow"><div class="field" style="margin:0"><label for="lC">Confidence</label><select id="lC">${[[1,'Low'],[2,'Medium'],[3,'High']].map(([v, l]) => `<option value="${v}"${(L ? L.conf : 2) === v ? ' selected' : ''}>${l}</option>`).join('')}</select></div>
      <div class="field" style="margin:0"><label for="lS">Evidence</label><select id="lS"><option value="">None yet</option>${D.recs.filter(r => r.type !== 'lead').map(r => `<option value="${r.id}"${L && L.src === r.id ? ' selected' : ''}>${esc(r.title.slice(0, 60))}</option>`).join('')}</select></div></div></div>
    <footer><button class="btn" type="button" data-act="dclose">Cancel</button><button class="btn primary" type="submit">${L ? 'Save' : 'Add relationship'}</button></footer></form>`);
}

/* capture */
const draft = {body:'', type:'evidence', source:'', host:'', caseId:null};
const capCase = () => { const s = $('capCase'); const id = (s && s.value) || draft.caseId || DB.active; return DB.cases.some(c => c.id === id) ? id : DB.active; };
function openCapture(prefill){
  if(prefill != null) draft.body = prefill;
  if(!draft.caseId || !DB.cases.some(c => c.id === draft.caseId)) draft.caseId = DB.active;
  const cur = theCase(draft.caseId), open = DB.cases.filter(c => c.status !== 'closed' || c.id === cur.id);
  openDlg(dhead('Capture evidence') + `<div class="in"><div class="capto"><label for="capCase">Save to</label><span class="capdot" style="background:${esc(cur.color)}"></span><select id="capCase" class="gsel bord">${open.map(c => `<option value="${c.id}"${c.id === cur.id ? ' selected' : ''}>${esc(c.code + ' · ' + c.name)}</option>`).join('')}<option value="__new">+ New case…</option></select>
      <label class="chk capg" title="Add what this evidence mentions to the case graph, and link relations it states"><span class="sw"><input type="checkbox" id="capGraph"${cur.autoGraph ? ' checked' : ''}><span></span></span>Add to graph</label></div>
    <p class="t2" style="margin:0 0 12px;font-size:14px">Paste a log line, a WHOIS record, a forum post, a whole report — anything. Indicators are picked out and checked against every case, your watchlist and the offline context lists.</p>
    <label class="sr" for="capBody">Evidence text</label><textarea id="capBody" class="inp code" rows="6" placeholder="2026-09-14T09:03:15Z EventID 3 … -> 203.0.113.47:4444">${esc(draft.body)}</textarea>
    <div class="found" id="capFound"></div>
    <div class="frow" style="margin-top:14px"><div class="field"><label for="capSrc">Source</label><input id="capSrc" value="${esc(draft.source)}" placeholder="sysmon, whois, forum…"></div><div class="field"><label for="capHost">Host</label><input id="capHost" value="${esc(draft.host)}" placeholder="WS-FIN-07"></div></div>
    <div class="capfiles">${ico('paperclip','sm')}<span>Drop files, screenshots or saved pages here, or paste an image</span><button class="btn xs" data-act="capFiles">Attach files…</button><button class="btn xs" data-act="capWeb" title="A page you saved from your browser (.mhtml or .html)">${ico('globe','sm')}Saved web page…</button><button class="btn xs" data-act="capLog" title="CSV, TSV, JSON or NDJSON — one record per row">${ico('table-2','sm')}Import log file…</button></div>
    <details class="caphelp"><summary>${ico('circle-help','sm')}How do I archive a web page?</summary><div class="caphelp-b"><ol>
      <li>Open the page in your browser and press <kbd>Ctrl</kbd>+<kbd>S</kbd> (<kbd>⌘</kbd>+<kbd>S</kbd> on a Mac).</li>
      <li>Chrome / Edge: choose <b>Webpage, Single File</b> (.mhtml). Firefox: <b>Web Page, HTML only</b> (.html). Safari: <b>Page Source</b>.</li>
      <li>Click <b>Saved web page…</b> above, or drop the file here.</li></ol>
      <p>OSINTrix keeps the original file with its SHA-256, reads the title, URL, author, dates, text and outbound links into a new evidence entry, and extracts the entities. Open it later from the entry's attachments — it is shown in a sandbox with scripts and outside requests blocked.</p></div></details></div>
    <footer><button class="btn ghost" type="button" data-act="sampleLine" style="margin-right:auto">Use a sample line</button><button class="btn" data-act="capSplit">One per line</button><button class="btn" data-act="capPara" title="Split at blank lines — good for reports and chat logs">One per paragraph</button><button class="btn primary" data-act="capSave">Capture <kbd>Ctrl ↵</kbd></button></footer>`, true, () => { capPreview(); bindCaptureFiles(); bindCapCase(); });
}
function bindCapCase(){
  const s = $('capCase'), g = $('capGraph'); if(!s) return;
  s.onchange = () => { if(s.value === '__new'){ draft.body = $('capBody').value; draft.reopen = Date.now(); closeDlg(); return caseDlg(false); }
    draft.caseId = s.value; const c = theCase(s.value); document.querySelector('.capdot').style.background = c.color; g.checked = !!c.autoGraph; capPreview(); };
  g.onchange = () => { const c = theCase(capCase()); c.autoGraph = g.checked; save(); };
}
function capPreview(){
  const el = $('capFound'); if(!el) return; const txt = $('capBody').value, lines = txt.split('\n').filter(l => l.trim()), P = lines.length ? parseLog(lines[0], txt) : null, ents = extractRich(txt).filter(e => e.k !== 'eventid'), cid = capCase(), D = derive(cid), G = globalEnts();
  const ph = P ? `<div class="cap-parse"><span class="chip accent sq">${esc(P.format)}</span><span class="t3">${Object.keys(P.fields).length} fields${lines.length > 1 ? ' · first of ' + lines.length + ' lines' : ''}</span>${parsedLine(P) ? `<div class="pline">${parsedLine(P)}</div>` : ''}</div>` : '';
  if(!ents.length){ el.innerHTML = ph; return; }
  let inCase = 0, other = 0, bad = 0, watched = 0;
  const chips = ents.slice(0, 40).map(e => { const id = entKey(e), here = D.byKey.get(id) || D.ents.get(id), ge = G.get(id), oc = ge ? [...ge.cases].filter(x => x !== cid && theCase(x)) : [], vd = verdictOf(id), w = isWatched(id), cx = ctxOf(e.k, e.v);
    if(here) inCase++; if(oc.length) other++; if(vd === 'malicious' || vd === 'suspicious') bad++; if(w) watched++;
    const note = w ? `<span class="n w">${ico('eye','sm')}watched</span>` : oc.length ? `<span class="n o" title="${esc(oc.map(x => theCase(x).name).join(', '))}">in ${esc(theCase(oc[0]).code)}${oc.length > 1 ? ' +' + (oc.length - 1) : ''}</span>` : `<span class="n">${here ? 'in case' : 'new'}</span>`;
    const ctx = cx.find(x => x[1] === 'red') || cx.find(x => x[1] === 'amber') || cx.find(x => x[1] === 'blue');
    return `<span class="ent" data-v="${vd}" title="${esc((E.LABEL[e.k] || e.k) + (cx.length ? ' · ' + cx.map(x => x[0]).join(' · ') : ''))}">${kindBadge(e.k)}<span class="v">${esc(e.v)}</span>${ctx ? `<span class="n ctxn ${ctx[1]}">${esc(ctx[0])}</span>` : ''}${note}</span>`; }).join('');
  const sum = [`<b>${ents.length}</b> indicator${ents.length > 1 ? 's' : ''}`, inCase ? `${inCase} already in this case` : '', other ? `<span style="color:var(--accent)">${other} seen in other cases</span>` : '', bad ? `<span style="color:var(--red)">${bad} marked malicious or suspicious</span>` : '', watched ? `<span style="color:var(--amber)">${watched} on your watchlist</span>` : ''].filter(Boolean).join(' · ');
  el.innerHTML = `${ph}<div class="capsum">${sum}</div>${chips}${ents.length > 40 ? `<span class="t3" style="font-size:12.5px">+${ents.length - 40} more</span>` : ''}`;
}
async function capSave(split){
  const body = ($('capBody').value || '').trim(); draft.source = $('capSrc').value.trim(); draft.host = $('capHost').value.trim();
  if(!body) return fieldErr('capBody', 'Paste or type what you found — or attach a file below.');
  if(body.length > 2000000) return fieldErr('capBody', 'That is more than 2 million characters. Use “Import log file…” for large logs.');
  if(draft.source.length > 200) return fieldErr('capSrc', 'Source is too long (max 200 characters).'); if(draft.host.length > 200) return fieldErr('capHost', 'Host is too long (max 200 characters).');
  const cid = capCase(); draft.caseId = cid;
  const parts = split === 'para' ? body.split(/\n\s*\n/).map(s => s.trim()).filter(Boolean) : split ? body.split('\n').map(s => s.trim()).filter(Boolean) : [body];
  const have = new Set(DB.records.filter(r => r.caseId === cid).map(r => r.body.trim()));
  const made = parts.filter(p => !have.has(p)).map(p => { let tsRaw = E.lineTime(p); if(!tsRaw){ const P = parseLog(p.split('\n')[0]); if(P && P.norm.time){ const t = logTime(P.norm.time); if(t) tsRaw = new Date(t).toISOString(); } }
    const Pp = parseLog(p.split('\n')[0]), pt = parsedTitle(Pp);
    return {id:uid('r'), caseId:cid, type:'evidence', title:pt || (p.split('\n')[0].replace(tsRaw, '').replace(/^[\s\-|,\]]+/, '') || 'Untitled').slice(0, 96), body:p, tsRaw, tsZone:tsRaw && E.carriesZone(tsRaw) ? 'explicit' : tz(),
      ts:tsRaw ? E.parseTime(tsRaw, tz()) : null, source:draft.source || (Pp && !/Label/.test(Pp.format) ? Pp.format : ''), host:draft.host || (Pp && Pp.norm.host) || '', tags:[], ents:extractRich(p), pv:1, answer:'', addedBy:'You', addedAt:Date.now(), hash:''}; });
  if(!made.length) return fieldErr('capBody', parts.length > 1 ? 'Every one of these is already captured in this case — nothing new to add.' : 'This exact text is already captured in this case.');
  DB.records.push(...made); draft.body = ''; mutate('captured ' + made.length + ' record(s)'); await hashRecords(); closeDlg();
  const g = afterCapture(cid, made.map(r => r.id)); watchNotify(made);
  UI.sel = {kind:'rec', id:made[0].id}; UI.inspOpen = true; UI.tlMode = 'events'; go(caseHash(cid, 'timeline'));
  toast(made.length + ' record' + (made.length > 1 ? 's' : '') + ' captured in ' + theCase(cid).code + (g ? ` · ${g.made.length} added to the graph${g.links.length ? ', ' + g.links.length + ' linked' : ''}` : ''), 'Undo', () => { const ids = new Set(made.map(r => r.id)); DB.records = DB.records.filter(r => !ids.has(r.id));
    if(g){ const s = new Set(g.made.map(e => e.id)), sl = new Set(g.links.map(l => l.id)); DB.entries = DB.entries.filter(e => !s.has(e.id)); DB.links = DB.links.filter(l => !sl.has(l.id)); } UI.sel = null; mutate('undid capture'); renderAll(); });
}

/* command palette */
let palList = [], palAt = 0;
function palette(){
  const all = [];
  const add = (group, label, hint, icon, fn) => all.push({group, label, hint, icon, fn});
  add('Actions','Capture evidence','N','plus', () => openCapture()); add('Actions','Add a vault entry','','layers', () => entryDlg());
  add('Actions','New case','','folder-open', () => caseDlg());
  add('Actions','Export a backup of everything','','download', () => clickAct('exportAll')); add('Actions','Import a backup…','','upload', () => clickAct('importAll')); add('Actions','Help — how OSINTrix works','','circle-help', () => go('#/help'));
  add('Actions','Delete the current case…','','trash-2', () => deleteCaseDlg(DB.active)); add('Actions','Add a tool','','wrench', () => toolDlg());
  add('Actions','Switch theme','','moon', () => { DB.prefs.theme = DB.prefs.theme === 'dark' ? 'light' : 'dark'; applyPrefs(); save(); if(cy) mountGraph(); });
  for(const c of DB.cases) add('Cases', c.name, c.code, 'folder-open', () => go(caseHash(c.id)));
  for(const e of DB.entries) add('Vault', primary(e), TYPES[e.type].label + ' · ' + theCase(e.caseId).code, TYPES[e.type].icon, () => { DB.active = e.caseId; UI.sel = {kind:'entry', id:e.id}; UI.inspOpen = true; go(caseHash(e.caseId, 'vault')); });
  for(const t of DB.tools) add('Tools', t.name, hostOf(t.url), 'wrench', () => { const u = E.safeUrl(t.url); if(u) window.open(u, '_blank', 'noopener,noreferrer'); });
  for(const r of DB.records) add('Evidence', r.title, theCase(r.caseId).code, 'file-text', () => { DB.active = r.caseId; UI.sel = {kind:'rec', id:r.id}; UI.inspOpen = true; go(caseHash(r.caseId, 'timeline')); });
  openDlg(`<div class="pal"><div class="srch">${ico('search')}<label class="sr" for="palQ">Search everything</label><input id="palQ" placeholder="Search cases, vault entries, tools, evidence, actions…" autocomplete="off" autofocus></div><div class="list" id="palL" role="listbox"></div></div>`, true, () => {
    const paint = () => { const q = $('palQ').value.toLowerCase().trim();
      let l = q ? all.filter(x => (x.label + ' ' + x.hint).toLowerCase().includes(q)) : all.filter(x => x.group === 'Actions' || x.group === 'Cases');
      palList = l.slice(0, 40); palAt = Math.min(palAt, Math.max(0, palList.length - 1)); let h = '', g = null;
      palList.forEach((x, i) => { if(x.group !== g){ h += `<div class="grp">${esc(x.group)}</div>`; g = x.group; } h += `<button class="it" data-pal="${i}" aria-selected="${i === palAt}">${ico(x.icon,'sm')}<span>${esc(x.label)}</span><small>${esc(x.hint)}</small></button>`; });
      $('palL').innerHTML = h || empty('search','No matches','Try a shorter search.'); const s = $('palL').querySelector('[aria-selected=true]'); if(s) s.scrollIntoView({block:'nearest'}); };
    paint(); $('palQ').oninput = () => { palAt = 0; paint(); };
    $('palQ').onkeydown = ev => { if(ev.key === 'ArrowDown'){ ev.preventDefault(); palAt = Math.min(palList.length - 1, palAt + 1); paint(); } else if(ev.key === 'ArrowUp'){ ev.preventDefault(); palAt = Math.max(0, palAt - 1); paint(); } else if(ev.key === 'Enter'){ ev.preventDefault(); const x = palList[palAt]; if(x){ closeDlg(); x.fn(); } } };
    $('palL').onclick = ev => { const b = ev.target.closest('[data-pal]'); if(b){ const x = palList[+b.dataset.pal]; closeDlg(); x.fn(); } };
  });
}
