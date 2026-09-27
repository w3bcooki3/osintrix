/* ==========================================================================
   Notes — sticky notes for to-dos and scratch thoughts. General or pinned
   to a case. Lines starting with "[ ]" or "- [ ]" become tickable tasks.
   ========================================================================== */
const NOTE_COLORS = [['yellow','#f5c451'],['pink','#f472b6'],['blue','#60a5fa'],['green','#4ade80'],['purple','#a78bfa'],['gray','#94a3b8']];
function ensureNotes(){
  if(DB.notes) return;
  const T = Date.parse('2026-09-15T12:00:00Z');
  DB.notes = [
    {id:'n1', caseId:'c-lantern', color:'yellow', pinned:true, text:'Before handoff\n[x] Isolate WS-FIN-07\n[ ] Image DC01 memory\n[ ] Pull proxy logs 14:00–15:00\n[ ] Ask finance who else got Invoice 4471', due:'2026-09-17', created:T - 7200e3, updated:T - 3600e3},
    {id:'n2', caseId:'c-lantern', color:'blue', pinned:false, text:'@n1ghtlamp joined forum.example 2025-11. Check archive.org snapshots of the profile — was the email ever different?', due:'', created:T - 5400e3, updated:T - 5400e3},
    {id:'n3', caseId:'c-lantern', color:'pink', pinned:false, text:'Beacon interval ~60 s ± 8%. The 6 KB beacon at 09:02 is the odd one — tasking or exfil?', due:'', created:T - 9000e3, updated:T - 9000e3},
    {id:'n4', caseId:null, color:'green', pinned:true, text:'This week\n[ ] Write up Op Lantern for the client\n[ ] Update Sigma rule for Lamp loader C2\n[x] Import new dork templates', due:'2026-09-19', created:T - 86400e3, updated:T - 3600e3},
    {id:'n5', caseId:'c-portal', color:'purple', pinned:false, text:'203.0.113.47 is also the Lantern C2. Same actor, or shared hosting? Compare timing.', due:'', created:T - 180000e3, updated:T - 180000e3},
  ];
}
const noteTasks = n => n.text.split('\n').map((l, i) => { const m = l.match(/^\s*(?:[-*]\s*)?\[( |x|X)\]\s*(.*)$/); return m ? {i, done:m[1] !== ' ', t:m[2]} : null; }).filter(Boolean);
const noteCol = c => (NOTE_COLORS.find(x => x[0] === c) || NOTE_COLORS[0])[1];
function noteCard(n, compact){
  const lines = n.text.split('\n'), tasks = noteTasks(n), done = tasks.filter(t => t.done).length, c = n.caseId ? theCase(n.caseId) : null;
  const overdue = n.due && Date.parse(n.due + 'T23:59:59Z') < Date.parse('2026-09-26T12:00:00Z') && tasks.some(t => !t.done);
  const body = lines.map((l, i) => { const t = tasks.find(x => x.i === i);
    return t ? `<label class="ntask${t.done ? ' done' : ''}"><input type="checkbox" data-act="nTick" data-id="${n.id}" data-v="${i}" ${t.done ? 'checked' : ''}><span>${esc(t.t)}</span></label>` : (l.trim() ? `<p>${esc(l)}</p>` : ''); }).join('');
  return `<article class="note-card${n.pinned ? ' npinned' : ''}" style="--nc:${noteCol(n.color)}">
    <div class="nhead">${n.pinned ? `<span class="npin">${ico('pin','sm')}</span>` : ''}${c && !compact ? `<a class="ncase" href="${caseHash(c.id)}" style="--cc:${esc(c.color)}">${esc(c.code)}</a>` : !c && !compact ? '<span class="ncase gen">General</span>' : ''}
      <span style="flex:1"></span><button class="nbtn" data-act="nEdit" data-id="${n.id}" aria-label="Edit note">${ico('pencil','sm')}</button><button class="nbtn" data-act="nMenu" data-id="${n.id}" aria-label="More">${ico('ellipsis','sm')}</button></div>
    <div class="nbody">${body}</div>
    ${tasks.length || n.due ? `<div class="nfoot">${tasks.length ? `<span class="nprog"><i style="width:${Math.round(done / tasks.length * 100)}%"></i></span><span>${done}/${tasks.length}</span>` : ''}${n.due ? `<span class="ndue${overdue ? ' late' : ''}">${ico('calendar-clock','sm')}${esc(n.due.slice(5))}</span>` : ''}</div>` : ''}</article>`;
}
function quickNote(caseId){
  return `<form data-form="nQuick" data-case="${caseId || ''}" class="nquick"><label class="sr" for="nq-${caseId || 'g'}">New note</label>
    <textarea id="nq-${caseId || 'g'}" rows="1" placeholder="Jot something down… start a line with [ ] for a to-do. Ctrl+Enter to add"></textarea>
    <div class="nqbar"><div class="ncolors">${NOTE_COLORS.map(([k, col], i) => `<button type="button" data-act="nColorPick" data-v="${k}" style="--nc:${col}" aria-pressed="${(UI.ncolor || 'yellow') === k}" aria-label="${k}"></button>`).join('')}</div>
      <button class="btn sm primary" type="submit">${ico('plus','sm')}Add note</button></div></form>`;
}
function viewNotes(){
  ensureNotes();
  const f = UI.nf || 'all', q = (UI.nq || '').toLowerCase();
  let list = DB.notes.filter(n => (f === 'all' || (f === 'general' ? !n.caseId : f === 'tasks' ? noteTasks(n).some(t => !t.done) : f === 'pinned' ? n.pinned : n.caseId === f)) && (!q || n.text.toLowerCase().includes(q)));
  list.sort((a, b) => (b.pinned - a.pinned) || b.updated - a.updated);
  const open = DB.notes.reduce((s, n) => s + noteTasks(n).filter(t => !t.done).length, 0);
  return `<div class="scroll"><div class="page">
    <div class="ph"><div><h1>Notes</h1><div class="sub">Sticky notes and to-dos — general, or pinned to a case. ${open} open to-do${open === 1 ? '' : 's'}.</div></div></div>
    ${quickNote(f !== 'all' && f !== 'general' && f !== 'tasks' && f !== 'pinned' ? f : '')}
    <div class="toolbar" style="margin-top:18px"><div class="catbar" style="margin:0"><button class="chip" data-act="nf" data-v="all" aria-pressed="${f === 'all'}">All <span class="n">${DB.notes.length}</span></button>
      <button class="chip" data-act="nf" data-v="pinned" aria-pressed="${f === 'pinned'}">${ico('pin','sm')}Pinned</button><button class="chip" data-act="nf" data-v="tasks" aria-pressed="${f === 'tasks'}">${ico('square-check','sm')}Open to-dos</button>
      <button class="chip" data-act="nf" data-v="general" aria-pressed="${f === 'general'}">General</button>
      ${DB.cases.map(c => `<button class="chip" data-act="nf" data-v="${c.id}" aria-pressed="${f === c.id}"><i class="cdot" style="background:${esc(c.color)}"></i>${esc(c.name.split(' — ')[0])}</button>`).join('')}</div>
      <span style="flex:1"></span><div class="search-in" style="max-width:260px">${ico('search')}<label class="sr" for="nqs">Search notes</label><input id="nqs" class="inp" placeholder="Search notes…" value="${esc(UI.nq || '')}"></div></div>
    ${list.length ? `<div class="board">${list.map(n => noteCard(n)).join('')}</div>` : empty('notebook-pen','No notes here','Write one above. Start a line with [ ] and it becomes a to-do you can tick off.')}
  </div></div>`;
}
function noteDlg(id){
  const n = DB.notes.find(x => x.id === id); if(!n) return;
  openDlg(dhead('Edit note') + `<form data-form="note" data-id="${n.id}"><div class="in">
    <div class="field"><label for="nText">Note</label><textarea id="nText" rows="8" autofocus>${esc(n.text)}</textarea><span class="hint">Lines starting with <span class="mono">[ ]</span> or <span class="mono">[x]</span> are to-dos.</span></div>
    <div class="frow"><div class="field"><label for="nCase">Case</label><select id="nCase"><option value="">General (no case)</option>${DB.cases.map(c => `<option value="${c.id}"${n.caseId === c.id ? ' selected' : ''}>${esc(c.code + ' · ' + c.name.split(' — ')[0])}</option>`).join('')}</select></div>
      <div class="field"><label for="nDue">Due</label><input id="nDue" type="date" value="${esc(n.due || '')}"></div></div>
    <div class="field" style="margin:0"><span class="label">Colour</span><div class="ncolors big">${NOTE_COLORS.map(([k, col]) => `<button type="button" data-act="nColor" data-id="${n.id}" data-v="${k}" style="--nc:${col}" aria-pressed="${n.color === k}" aria-label="${k}"></button>`).join('')}</div></div>
    <label style="display:flex;gap:10px;align-items:center;margin-top:14px;font-size:14px"><input type="checkbox" id="nPin" ${n.pinned ? 'checked' : ''}> Pin to the top and to the Dashboard</label></div>
    <footer><button class="btn danger" type="button" data-act="nDel" data-id="${n.id}" style="margin-right:auto">${ico('trash-2','sm')}Delete</button><button class="btn" type="button" data-act="dclose">Cancel</button><button class="btn primary" type="submit">Save</button></footer></form>`);
}
