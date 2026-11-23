/* ==========================================================================
   @ in notes: type @ in a note and pick a vault entry — it is written as
   @[value], which still reads as plain text. In the note it becomes a link to
   the entry, and the entry lists the notes that mention it ("Mentioned in
   notes"), so the reasoning sits next to the evidence. A mention matches by
   value, so it survives export, import and snapshots; one whose entry has
   gone shows faded, and clicking it offers to add the entry back.
   ========================================================================== */
const MEN_RE = /@\[([^\]\n]{1,120})\]/g;
const menNorm = v => String(v || '').trim().toLowerCase();
/* the entry a mention means: in the note's case first, then anywhere */
function menFind(v, caseId){ const k = menNorm(v); if(!k) return null; const all = DB.entries.filter(e => menNorm(primary(e)) === k); return all.find(e => e.caseId === caseId) || all[0] || null; }
/* note text (already escaped) → mentions as links */
function menHtml(html, caseId){
  return html.replace(/@\[([^\]<>\n]{1,120})\]/g, (m, v) => { const raw = v.replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'"), e = menFind(raw, caseId);
    return `<button class="nment${e ? '' : ' gone'}" data-act="menOpen" data-v="${v}"${caseId ? ` data-id="${esc(caseId)}"` : ''} title="${e ? 'Open ' + v : 'No entry called ' + v + ' — click to add it'}">@${v}</button>`; });
}
/* the notes that mention an entry */
function menNotesFor(e){ const k = menNorm(primary(e)); if(!k) return [];
  return (DB.notes || []).filter(n => (n.caseId == null || n.caseId === e.caseId) && [...String(n.text || '').matchAll(MEN_RE)].some(m => menNorm(m[1]) === k)); }
function menSection(e){ const N = menNotesFor(e); if(!N.length) return '';
  return `<div class="isec"><h4>Mentioned in notes <span class="t3">${N.length}</span></h4>${N.slice(0, 12).map(n => `<button class="li men-n" data-act="nEdit" data-id="${n.id}"><span class="men-c" style="--nc:${noteCol(n.color)}"></span><div class="main2"><b>${esc(noteLabel(n))}</b><small class="t3">${esc(menSnippet(n, e))}</small></div></button>`).join('')}</div>`; }
const menSnippet = (n, e) => { const k = '@[' + primary(e) + ']', t = String(n.text || ''), i = t.toLowerCase().indexOf(k.toLowerCase()); if(i < 0) return ''; const a = Math.max(0, i - 50), b = Math.min(t.length, i + k.length + 60); return (a ? '…' : '') + t.slice(a, b).replace(/\s+/g, ' ') + (b < t.length ? '…' : ''); };

/* ---------- typing: @ suggests entries ---------- */
let MEN = null;   /* {ta, start, items, at} while the list is open */
const menCaseOf = ta => { if(ta.id === 'nText'){ const sel = $('nCase'); return sel ? sel.value || null : DB.active; }
  const m = ta.id.match(/^nq-(.+)$/); return m && m[1] !== 'g' ? m[1] : null; };
function menQuery(ta){ const pos = ta.selectionStart, before = ta.value.slice(0, pos), m = before.match(/(^|[\s(])@\[?([^\s\]@\[]{0,40})$/); return m ? {start:pos - m[2].length - (before.endsWith('@[' + m[2]) ? 2 : 1), q:m[2]} : null; }
function menSuggest(ta){
  const Q = menQuery(ta); if(!Q){ return menClose(); }
  const cid = menCaseOf(ta), q = Q.q.toLowerCase();
  const pool = DB.entries.filter(e => !cid || e.caseId === cid), items = pool.filter(e => !q || primary(e).toLowerCase().includes(q))
    .sort((a, b) => (q ? (primary(a).toLowerCase().startsWith(q) ? 0 : 1) - (primary(b).toLowerCase().startsWith(q) ? 0 : 1) : 0) || (b.starred - a.starred) || primary(a).localeCompare(primary(b))).slice(0, 8);
  if(!items.length) return menClose();
  MEN = {ta, start:Q.start, items, at:MEN && MEN.ta === ta ? Math.min(MEN.at, items.length - 1) : 0}; menPaint();
}
function menPaint(){
  let box = $('menBox'); if(!MEN) return; if(!box){ box = document.createElement('div'); box.id = 'menBox'; box.className = 'men-box'; box.setAttribute('role', 'listbox'); box.setAttribute('aria-label', 'Vault entries'); document.body.appendChild(box); }
  const r = MEN.ta.getBoundingClientRect();
  box.style.left = Math.max(8, Math.min(r.left + 8, innerWidth - 328)) + 'px'; box.style.top = Math.min(r.bottom + 4, innerHeight - 290) + 'px';
  box.innerHTML = MEN.items.map((e, i) => `<button type="button" role="option" id="menO${i}" aria-selected="${i === MEN.at}" data-mi="${i}">${tbadge(e.type)}<span class="${MONO_TYPES.has(e.type) ? 'mono' : ''}">${esc(primary(e))}</span><small>${esc(TYPES[e.type].label)}</small></button>`).join('') + '<p class="men-h">↑ ↓ to pick · Enter or Tab to insert · Esc</p>';
  box.querySelectorAll('[data-mi]').forEach(b => b.onmousedown = ev => { ev.preventDefault(); MEN.at = +b.dataset.mi; menPick(); });
  /* a note box is a plain text box, so the highlighted entry is read out through a live region */
  let live = $('menLive'); if(!live){ live = document.createElement('div'); live.id = 'menLive'; live.className = 'sr'; live.setAttribute('aria-live', 'polite'); document.body.appendChild(live); }
  const e = MEN.items[MEN.at]; live.textContent = `${TYPES[e.type].label} ${primary(e)}, ${MEN.at + 1} of ${MEN.items.length}. Enter to insert.`;
}
function menClose(){ const b = $('menBox'); if(b) b.remove(); const l = $('menLive'); if(l) l.textContent = ''; MEN = null; }
function menPick(){
  if(!MEN) return; const {ta, start, items, at} = MEN, e = items[at], end = ta.selectionStart, ins = '@[' + primary(e).replace(/[\]\n]/g, ' ') + '] ';
  ta.value = ta.value.slice(0, start) + ins + ta.value.slice(end); const p = start + ins.length; ta.setSelectionRange(p, p); menClose(); ta.dispatchEvent(new Event('input', {bubbles:true})); ta.focus();
}
document.addEventListener('input', ev => { const t = ev.target; if(t && t.matches && t.matches('textarea.ned')) menSuggest(t); else if(MEN) menClose(); });
document.addEventListener('keydown', ev => { if(!MEN || ev.target !== MEN.ta) return;
  if(ev.key === 'ArrowDown' || ev.key === 'ArrowUp'){ ev.preventDefault(); MEN.at = (MEN.at + (ev.key === 'ArrowDown' ? 1 : -1) + MEN.items.length) % MEN.items.length; menPaint(); }
  else if((ev.key === 'Enter' && !ev.ctrlKey && !ev.metaKey) || ev.key === 'Tab'){ ev.preventDefault(); ev.stopPropagation(); menPick(); }
  else if(ev.key === 'Escape'){ ev.preventDefault(); ev.stopPropagation(); menClose(); } }, true);
document.addEventListener('focusout', ev => { if(MEN && ev.target === MEN.ta) setTimeout(() => { if(MEN && document.activeElement !== MEN.ta) menClose(); }, 120); });
const MEN_ACTS = {
  menOpen:(id, v) => { const e = menFind(v, id || DB.active);
    if(e){ closeDlg(); DB.active = e.caseId; UI.sel = {kind:'entry', id:e.id}; UI.inspOpen = true; return renderAll(); }
    toast(`No entry called “${v}” in the vault`, 'Add it', () => { closeDlg(); const t = typeof vimAuto === 'function' ? vimAuto(v) : null; entryDlg(null, t ? {type:t, fields:{[TYPES[t].fields[0][0]]:v}} : null); }); },
};
