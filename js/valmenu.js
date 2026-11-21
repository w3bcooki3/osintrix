/* ==========================================================================
   Right-click any indicator — an IP, domain, URL, email, hash, handle,
   wallet, CVE — anywhere in the app (or select one and right-click) for:
   copy, copy defanged, its details, every case it is in, watch, and the
   lookups for its kind (opened in a new tab; nothing is fetched here).
   Anything else keeps the browser's own menu.
   ========================================================================== */
/* the indicator under the pointer, or in the selection: {k, v} or null */
function valAt(target){
  const sel = getSelection && getSelection(), st = sel && !sel.isCollapsed ? sel.toString().trim() : '';
  const pick = (text, strict) => { if(!text || text.length > 400) return null; const E2 = E.extract(text).filter(x => x.k && x.v);
    if(!E2.length) return null; const best = E2.slice().sort((a, b) => b.v.length - a.v.length)[0];
    /* the indicator must be most of what was pointed at, so right-clicking a paragraph keeps the normal menu */
    return !strict || best.v.length >= text.replace(/^[\s"'(<\[]+|[\s"')>\].,;:]+$/g, '').length * .6 ? best : null; };
  if(st) return pick(st, true);
  for(let e = target, k = 0; e && e.nodeType === 1 && k < 3; e = e.parentElement, k++){
    if(e.matches('input, textarea, select, [contenteditable], .cm-editor, .cm-editor *')) return null;
    if(e.matches('#main, #insp, body')) break;
    const t = (e.textContent || '').trim(); if(t.length > 400) break;
    const x = pick(t, true); if(x) return x; }
  return null; }
function valMenu(x, y, it){
  const id = it.k + ':' + it.v, label = (E.LABEL && E.LABEL[it.k]) || it.k, watched = typeof isWatched === 'function' && isWatched(id), L = pivotLinks(it.k, it.v);
  const items = [
    {label:'Copy', icon:'copy', fn:() => copyText(it.v)},
    {label:'Copy defanged', icon:'shield-check', fn:() => copyText(defang(it.v))},
    {sep:true},
    {label:'Details', icon:'panel-right', fn:() => { select('ent', id); }},
    {label:'Find in every case', icon:'search', fn:() => { UI.entq = it.v; go('#/entities'); }},
    {label:watched ? 'Stop watching' : 'Watch', icon:watched ? 'eye-off' : 'eye', fn:() => toggleWatch(id)}];
  if(L.length){ items.push({sep:true}); for(const [n, u] of L.slice(0, 7)) items.push({label:'Open in ' + n, icon:'external-link', fn:() => window.open(u, '_blank', 'noopener,noreferrer')}); }
  showMenu(x, y, items, `${esc(label)} · <span class="mono">${esc(it.v.length > 48 ? it.v.slice(0, 46) + '…' : it.v)}</span>`);
}
document.addEventListener('contextmenu', ev => {
  if(ev.shiftKey || !ev.target.closest || !ev.target.closest('#main, #insp')) return;   /* Shift + right-click: the browser's own menu */
  if(ev.target.closest('input, textarea, select, [contenteditable], canvas, .cy, #cy')) return;
  const it = valAt(ev.target);
  if(!it){ const sel = getSelection(), t = sel && !sel.isCollapsed ? sel.toString() : '';   /* a stretch of selected text with indicators in it */
    if(!t.trim() || t.length > 200000 || !E.extract(t.slice(0, 20000)).length) return;
    ev.preventDefault(); return showMenu(ev.clientX, ev.clientY, [{label:'Copy', icon:'copy', fn:() => copyText(t)}, {label:'Copy masked', icon:'eye-off', fn:() => maskCopy(t)}, {label:'Copy defanged', icon:'shield-check', fn:() => copyText(defangText(t))}], 'Selected text'); }
  ev.preventDefault(); valMenu(ev.clientX, ev.clientY, it); });
