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
/* A note's title: optional, shown at the top of the card. Cleaned the same way everywhere it is set —
   hidden and direction-changing characters out, spaces collapsed, at most 120 characters — and always
   escaped when shown. Another note with the same title in the same place is a warning, not a block. */
const NT_MAX = 120;
const ntClean = s => String(s == null ? '' : s).normalize('NFKC').replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]/g, '').replace(/\s+/g, ' ').trim();
const noteTitle = n => n && typeof n.title === 'string' ? ntClean(n.title).slice(0, NT_MAX) : '';
/* what a note is called in lists, search, Today and the trash: its title, or its first line */
const noteLabel = n => noteTitle(n) || (String((n && n.text) || '').split('\n').find(l => l.trim()) || '').replace(/^\s*(#{1,3}|[-*•]|\[[ xX]\]|\d{1,3}[.)])\s+/, '').trim().slice(0, 120) || 'Note';
const noteTitleTwin = (title, caseId, selfId) => { const k = normName(title); return k ? (DB.notes || []).find(x => x.id !== selfId && (x.caseId || null) === (caseId || null) && normName(noteTitle(x)) === k) : null; };
const noteTasks = n => n.text.split('\n').map((l, i) => { const m = l.match(/^\s*(?:[-*]\s*)?\[( |x|X)\]\s*(.*)$/); return m ? {i, done:m[1] !== ' ', t:m[2]} : null; }).filter(Boolean);
/* when a note is due, in this computer's local time: the time if one is set, otherwise the end of the day */
const noteDueAt = n => { if(!n || !/^\d{4}-\d{2}-\d{2}$/.test(n.due || '')) return null; const t = /^\d{2}:\d{2}$/.test(n.dueTime || '') ? n.dueTime : '23:59'; const ms = new Date(n.due + 'T' + t + ':00').getTime(); return isFinite(ms) ? ms : null; };
const noteDueText = n => { const at = noteDueAt(n); if(at == null) return ''; const d = new Date(at), today = new Date(); const same = d.toDateString() === today.toDateString(), tmr = new Date(today.getTime() + 864e5).toDateString() === d.toDateString();
  return (same ? 'Today' : tmr ? 'Tomorrow' : d.toLocaleDateString(undefined, {day:'numeric', month:'short'}) + (d.getFullYear() !== today.getFullYear() ? ' ' + d.getFullYear() : '')) + (n.dueTime ? ' ' + n.dueTime : ''); };
const noteCol = c => (NOTE_COLORS.find(x => x[0] === c) || NOTE_COLORS[0])[1];
function noteCard(n, compact){
  const lines = n.text.split('\n'), tasks = noteTasks(n), done = tasks.filter(t => t.done).length, c = n.caseId ? theCase(n.caseId) : null, tt = noteTitle(n);
  const at = noteDueAt(n), overdue = at != null && at < Date.now() && (tasks.some(t => !t.done) || (n.remind && !tasks.length));
  const body = lines.map((l, i) => { const t = tasks.find(x => x.i === i);
    if(t) return `<label class="ntask${t.done ? ' done' : ''}"><input type="checkbox" data-act="nTick" data-id="${n.id}" data-v="${i}" ${t.done ? 'checked' : ''}><span>${noteInline(t.t)}</span></label>`;
    if(!l.trim()) return ''; if(/^\s*---+\s*$/.test(l)) return '<hr>';
    const h = l.match(/^\s*#{1,3}\s+(.*)$/); if(h) return `<h4>${noteInline(h[1])}</h4>`;
    const b = l.match(/^\s*[-*•]\s+(.*)$/); if(b) return `<p class="nli">${noteInline(b[1])}</p>`;
    const o = l.match(/^\s*(\d{1,3})[.)]\s+(.*)$/); if(o) return `<p class="nli num" data-n="${o[1]}.">${noteInline(o[2])}</p>`;
    return `<p>${noteInline(l)}</p>`; }).join(''), cites = typeof noteRefs === 'function' ? noteRefs(n).length : 0;
  const bodyM = typeof menHtml === 'function' ? menHtml(body, n.caseId) : body;
  return `<article class="note-card${n.pinned ? ' npinned' : ''}" style="--nc:${noteCol(n.color)}">
    <div class="nhead">${n.pinned ? `<span class="npin">${ico('pin','sm')}</span>` : ''}${c && !compact ? `<a class="ncase" href="${caseHash(c.id)}" style="--cc:${esc(c.color)}">${esc(caseNm(c))}</a>` : ''}${!c && !compact ? '<span class="ncase gen">General</span>' : ''}
      <span style="flex:1"></span><button class="nbtn" data-act="nEdit" data-id="${n.id}" aria-label="Edit note">${ico('pencil','sm')}</button><button class="nbtn" data-act="nMenu" data-id="${n.id}" aria-label="More">${ico('ellipsis','sm')}</button></div>
    ${tt ? `<h3 class="ntitle">${esc(tt)}</h3>` : ''}<div class="nbody">${typeof noteCiteHtml === 'function' ? noteCiteHtml(n, bodyM) : bodyM}</div>${cites && !compact ? `<button class="ncites" data-act="nCiteAll" data-id="${n.id}">${ico('list-filter','sm')}Show the ${cites} cited event${cites > 1 ? 's' : ''}</button>` : ''}
    ${tasks.length || n.due ? `<div class="nfoot">${tasks.length ? `<span class="nprog"><i style="width:${Math.round(done / tasks.length * 100)}%"></i></span><span>${done}/${tasks.length}</span>` : ''}${n.due ? `<span class="ndue${overdue ? ' late' : ''}" title="${n.remind ? 'Reminder set' : 'Due'}">${ico(n.remind ? 'bell' : 'calendar-clock','sm')}${esc(noteDueText(n))}</span>` : ''}</div>` : ''}</article>`;
}
/* **bold**, *italic*, `code` — escaped first, so nothing in a note can become markup */
const noteInline = t => esc(t).replace(/`([^`]+)`/g, '<code>$1</code>').replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>').replace(/(^|[\s(])\*([^*\s][^*]*)\*(?=[\s).,!?]|$)/g, '$1<i>$2</i>');
/* the formatting bar above a note's text */
const NOTE_FMT = [['todo','square-check','To-do item','[ ] '],['bullet','list','Bullet','- '],['num','list-ordered','Numbered item','1. '],['h','heading','Heading','# '],['b','bold','Bold  (Ctrl+B)','**'],['code','code','Code','`'],['date','calendar','Insert today\'s date',''],['hr','minus','Divider','---']];
function noteTools(taId){ return `<div class="nfmt" role="toolbar" aria-label="Formatting">${NOTE_FMT.map(([k, i, l]) => `<button type="button" class="nbtn" data-act="nFmt" data-id="${taId}" data-v="${k}" title="${l}" aria-label="${l}">${ico(i,'sm')}</button>`).join('')}</div>`; }
function noteFmt(ta, k){
  if(!ta) return; const v = ta.value, s = ta.selectionStart, e = ta.selectionEnd, ls = v.lastIndexOf('\n', s - 1) + 1, le = (i => i < 0 ? v.length : i)(v.indexOf('\n', e));
  const F = NOTE_FMT.find(x => x[0] === k); if(!F) return;
  if(k === 'b' || k === 'code'){ const m = F[3], sel = v.slice(s, e) || (k === 'b' ? 'bold text' : 'code'); ta.setRangeText(m + sel + m, s, e, 'select'); if(s === e){ ta.selectionStart = s + m.length; ta.selectionEnd = s + m.length + sel.length; } }
  else if(k === 'date'){ ta.setRangeText(new Date().toISOString().slice(0, 10), s, e, 'end'); }
  else if(k === 'hr'){ ta.setRangeText((s > 0 && v[s - 1] !== '\n' ? '\n' : '') + '---\n', s, e, 'end'); }
  else { /* line prefixes: applied to every selected line, or taken off if all already have it */
    const pre = /^\s*(\[[ xX]\]|[-*•]|\d{1,3}[.)]|#{1,3})\s+/, lines = v.slice(ls, le).split('\n'), mine = {todo:/^\s*\[[ xX]\]\s+/, bullet:/^\s*[-*•]\s+/, num:/^\s*\d{1,3}[.)]\s+/, h:/^\s*#{1,3}\s+/}[k];
    const off = lines.some(l => l.trim()) && lines.every(l => mine.test(l) || !l.trim());
    const out = lines.map((l, i) => !l.trim() && lines.length > 1 ? l : off ? l.replace(mine, '') : (k === 'num' ? (i + 1) + '. ' : F[3]) + l.replace(pre, ''));
    ta.setRangeText(out.join('\n'), ls, le, 'end'); }
  ta.focus(); ta.dispatchEvent(new Event('input', {bubbles:true}));
}
/* Enter carries a list on; Enter on an empty item ends it. Ctrl+B for bold. */
document.addEventListener('keydown', ev => {
  const ta = ev.target; if(!ta || ta.tagName !== 'TEXTAREA' || !ta.classList.contains('ned')) return;
  if((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === 'b'){ ev.preventDefault(); return noteFmt(ta, 'b'); }
  if(ev.key !== 'Enter' || ev.shiftKey || ev.ctrlKey || ev.metaKey || ev.altKey || ta.selectionStart !== ta.selectionEnd) return;
  const v = ta.value, s = ta.selectionStart, ls = v.lastIndexOf('\n', s - 1) + 1, line = v.slice(ls, s), m = line.match(/^(\s*)(\[[ xX]\]|[-*•]|(\d{1,3})([.)]))\s+/); if(!m) return;
  ev.preventDefault();
  if(!line.slice(m[0].length).trim()){ ta.setRangeText('', ls, s, 'end'); }   // an empty item ends the list
  else { const next = m[3] ? (+m[3] + 1) + m[4] : /^\[/.test(m[2]) ? '[ ]' : m[2]; ta.setRangeText('\n' + m[1] + next + ' ', s, s, 'end'); }
  ta.dispatchEvent(new Event('input', {bubbles:true}));
});
function quickNote(caseId){
  return `<form data-form="nQuick" data-case="${esc(caseId || '')}" class="nquick"><label class="sr" for="nqt-${caseId || 'g'}">Title</label><input id="nqt-${caseId || 'g'}" class="nqtitle" data-nq="title" maxlength="${NT_MAX + 40}" autocomplete="off" placeholder="Title (optional)"><label class="sr" for="nq-${caseId || 'g'}">New note</label>
    <textarea id="nq-${caseId || 'g'}" class="ned" rows="1" placeholder="Jot something down… Ctrl+Enter to add"></textarea>
    <div class="nqbar">${noteTools('nq-' + (caseId || 'g'))}<span class="nqsep" aria-hidden="true"></span><div class="ncolors">${NOTE_COLORS.map(([k, col], i) => `<button type="button" data-act="nColorPick" data-v="${k}" style="--nc:${col}" aria-pressed="${(UI.ncolor || 'yellow') === k}" aria-label="${k}"></button>`).join('')}</div>
      <span class="nqwhen"><label class="sr" for="nqd-${caseId || 'g'}">Due date</label><input id="nqd-${caseId || 'g'}" type="date" class="inp xs" data-nq="due" title="Due date">
        <label class="sr" for="nqh-${caseId || 'g'}">Time</label><input id="nqh-${caseId || 'g'}" type="time" class="inp xs" data-nq="time" title="Time">
        <label class="nqrem" title="Remind me when it is due"><input type="checkbox" data-nq="remind" checked>${ico('bell','sm')}<span>Remind</span></label></span>
      <button class="btn sm primary" type="submit">${ico('plus','sm')}Add note</button></div></form>`;
}
function viewNotes(){
  ensureNotes();
  const f = UI.nf || 'all', q = (UI.nq || '').toLowerCase();
  if(String(f).startsWith('h:')){ UI.nf = 'all'; return viewNotes(); }
  let list = DB.notes.filter(n => (f === 'all' || (f === 'general' ? !n.caseId : f === 'tasks' ? noteTasks(n).some(t => !t.done) : f === 'pinned' ? n.pinned : n.caseId === f)) && (!q || n.text.toLowerCase().includes(q) || noteTitle(n).toLowerCase().includes(q)));
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
    <div class="field"><label for="nTitle">Title <span class="t3">(optional)</span></label><input id="nTitle" value="${esc(noteTitle(n))}" maxlength="${NT_MAX + 40}" autocomplete="off" placeholder="What this note is about"></div>
    <div class="field"><label for="nText">Note</label>${noteTools('nText')}<textarea id="nText" class="ned" rows="8"${noteTitle(n) ? ' autofocus' : ''}>${esc(n.text)}</textarea><span class="hint">Use the buttons above, or type <span class="mono">[ ]</span> for a to-do, <span class="mono">-</span> for a bullet, <span class="mono">#</span> for a heading. Enter continues a list.</span></div>
    <div class="frow"><div class="field"><label for="nCase">Case</label><select id="nCase"><option value="">General (no case)</option>${DB.cases.map(c => `<option value="${c.id}"${n.caseId === c.id ? ' selected' : ''}>${esc(c.name.split(' — ')[0])}</option>`).join('')}</select></div>
      <div class="field"><label for="nDue">Due</label><div class="nwhen"><input id="nDue" type="date" value="${esc(n.due || '')}"><label class="sr" for="nTime">Time</label><input id="nTime" type="time" value="${esc(n.dueTime || '')}"></div></div></div>
    <label style="display:flex;gap:10px;align-items:center;margin:0 0 12px;font-size:calc(14px * var(--ts,1))"><input type="checkbox" id="nRemind" ${n.remind ? 'checked' : ''}> ${ico('bell','sm')}Remind me when it is due${n.reminded ? ` <span class="t3 small">(reminded ${esc(new Date(n.reminded).toLocaleString(undefined, {dateStyle:'medium', timeStyle:'short'}))})</span>` : ''}</label>
    <div class="field" style="margin:0"><span class="label">Colour</span><div class="ncolors big">${NOTE_COLORS.map(([k, col]) => `<button type="button" data-act="nColor" data-id="${n.id}" data-v="${k}" style="--nc:${col}" aria-pressed="${n.color === k}" aria-label="${k}"></button>`).join('')}</div></div>
    <label style="display:flex;gap:10px;align-items:center;margin-top:14px;font-size:calc(14px * var(--ts,1))"><input type="checkbox" id="nPin" ${n.pinned ? 'checked' : ''}> Pin to the top and to the Dashboard</label></div>
    <footer><button class="btn danger" type="button" data-act="nDel" data-id="${n.id}" style="margin-right:auto">${ico('trash-2','sm')}Delete</button><button class="btn" type="button" data-act="dclose">Cancel</button><button class="btn primary" type="submit">Save</button></footer></form>`);
}

/* ---------- reminders: a note with a date (and time) tells you when it is due — in the app, and as a system notification if allowed ---------- */
function noteRemindCheck(){
  if(!DB || !Array.isArray(DB.notes)) return; const now = Date.now(); let fired = 0;
  for(const n of DB.notes){ if(!n.remind || n.reminded) continue; const at = noteDueAt(n); if(at == null || at > now) continue;
    n.reminded = now; fired++; const late = now - at > 10 * 6e4, label = noteLabel(n).slice(0, 90);
    toast(`${late ? 'Missed reminder' : 'Reminder'}: ${label}${late ? ' — was due ' + noteDueText(n) : ''}`, 'Open', () => { go('#/notes'); setTimeout(() => noteDlg(n.id), 60); });
    try{ if(typeof Notification !== 'undefined' && Notification.permission === 'granted') new Notification('OSINTrix reminder', {body:label, tag:'note-' + n.id}); }catch(e){} }
  if(fired){ save(); if(UI.route && (UI.route.area === 'notes' || UI.route.area === 'today' || UI.route.area === 'home')) bgRender(); }
}
/* the next one is due soon: check every 20 seconds, and when the tab comes back */
setInterval(noteRemindCheck, 20000);
document.addEventListener('visibilitychange', () => { if(!document.hidden) noteRemindCheck(); });
setTimeout(noteRemindCheck, 1500);
/* asking for system notifications only when someone sets a reminder, never on load */
function noteAskNotify(){ try{ if(typeof Notification !== 'undefined' && Notification.permission === 'default') Notification.requestPermission().catch(() => {}); }catch(e){} }
