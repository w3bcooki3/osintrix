/* ==========================================================================
   Virtual lists — only the rows near the screen exist in the page.
   A list is declared while a view builds its HTML (vlist / vlistBody) and brought to
   life after it is drawn (vlMount, called by renderMain). Rows can have any height:
   each one is measured once drawn and the estimate is used until then. Sticky group
   headers (day headings) stay visible because the header for the first row on screen
   is always drawn. Rows keep their focus across redraws; vlScrollTo brings any row
   into view, for the keyboard and for "open this record".
   ========================================================================== */
const VL = {pend:new Map(), live:new Map(), OVER:900};
/* items: [{k:key, h:estimated height, r:() => html, sticky?:true}] */
function vlist(id, items, o = {}){
  VL.pend.set(id, {items, o});
  const est = items.reduce((a, x) => a + (x.h || o.est || 60), 0);
  return o.tbody ? `<tbody class="vl" id="${id}"><tr class="vl-sp" aria-hidden="true"><td colspan="${o.cols || 1}" style="height:${est}px"></td></tr></tbody>`
    : `<div class="vl" id="${id}"${o.role ? ` role="${o.role}"` : ''}${o.label ? ` aria-label="${esc(o.label)}"` : ''}><div class="vl-sp" aria-hidden="true" style="height:${est}px"></div></div>`;
}
function vlMount(){
  for(const [id, L] of VL.pend){ const el = document.getElementById(id); if(!el) continue;
    const sc = el.closest('[data-vlsc], .scroll') || document.scrollingElement, old = VL.live.get(id);
    const S = {id, el, sc, items:L.items, o:L.o, hs:L.items.map(x => x.h || L.o.est || 60), seen:new Map(old ? old.seen : []), start:-1, end:-1, raf:0};
    /* heights measured last time are kept for rows that are still in the list */
    S.items.forEach((x, i) => { const h = S.seen.get(x.k); if(h) S.hs[i] = h; });
    S.onScroll = () => { if(!S.raf) S.raf = requestAnimationFrame(() => { S.raf = 0; vlPaint(S); }); };
    sc.addEventListener('scroll', S.onScroll, {passive:true});
    VL.live.set(id, S); vlPaint(S, true);
    if(L.o.focus != null) vlScrollTo(id, L.o.focus, true);
  }
  VL.pend.clear();
  for(const [id, S] of VL.live) if(!S.el.isConnected){ S.sc.removeEventListener('scroll', S.onScroll); VL.live.delete(id); }
}
function vlPaint(S, force){
  if(!S.el.isConnected) return;
  const n = S.items.length, scR = S.sc === document.scrollingElement ? {top:0} : S.sc.getBoundingClientRect(), top = S.el.getBoundingClientRect().top - scR.top + S.sc.scrollTop;
  const v0 = S.sc.scrollTop - top - VL.OVER, v1 = S.sc.scrollTop - top + (S.sc.clientHeight || innerHeight) + VL.OVER;
  let y = 0, start = 0, end = n;
  for(let i = 0; i < n; i++){ if(y + S.hs[i] < v0) start = i + 1; if(y > v1){ end = i; break; } y += S.hs[i]; }
  start = Math.min(start, Math.max(0, n - 1)); if(end <= start) end = Math.min(n, start + 1);
  if(!force && start === S.start && end === S.end) return;
  S.start = start; S.end = end;
  /* the group header for the first row drawn, so a sticky heading stays on screen */
  let hdr = -1; for(let i = start - 1; i >= 0; i--) if(S.items[i].sticky){ hdr = i; break; } if(start < n && S.items[start].sticky) hdr = -1;
  let above = 0; for(let i = 0; i < start; i++) above += S.hs[i]; let below = 0; for(let i = end; i < n; i++) below += S.hs[i];
  if(hdr >= 0) above = Math.max(0, above - S.hs[hdr]);
  const focus = document.activeElement && S.el.contains(document.activeElement) ? document.activeElement.getAttribute('data-id') : null;
  const sp = h => S.o.tbody ? `<tr class="vl-sp" aria-hidden="true"><td colspan="${S.o.cols || 1}" style="height:${h}px"></td></tr>` : `<div class="vl-sp" aria-hidden="true" style="height:${h}px"></div>`;
  let html = sp(above);
  if(hdr >= 0) html += vlRow(S, hdr);
  for(let i = start; i < end; i++) html += vlRow(S, i);
  html += sp(below);
  S.el.innerHTML = html;
  /* measure what was drawn; the space below takes up any difference */
  let changed = false;
  /* a row's height is the distance to the next row's top, so margins count */
  const nodes = [...S.el.querySelectorAll(':scope > [data-vi]')], tops = nodes.map(x => x.getBoundingClientRect().top), tail = S.el.lastElementChild ? S.el.lastElementChild.getBoundingClientRect().top : 0;
  nodes.forEach((node, k) => { const i = +node.dataset.vi, h = (k + 1 < nodes.length ? tops[k + 1] : tail) - tops[k]; if(h > 0){ if(Math.abs(h - S.hs[i]) > 0.5){ S.hs[i] = h; changed = true; } S.seen.set(S.items[i].k, h); } });
  if(changed){ let b = 0; for(let i = end; i < n; i++) b += S.hs[i]; const last = S.el.lastElementChild; if(last){ const t = S.o.tbody ? last.firstElementChild : last; if(t) t.style.height = b + 'px'; } }
  if(focus){ const f = S.el.querySelector(`[data-id="${CSS.escape(focus)}"]`); if(f) f.focus({preventScroll:true}); }
  if(S.o.onPaint) S.o.onPaint(S);
}
/* each item's markup carries its index, so it can be measured */
function vlRow(S, i){ const h = S.items[i].r(); return h.replace(/^(\s*<[a-z]+)/i, `$1 data-vi="${i}"`); }
function vlScrollTo(id, key, instant){
  const S = VL.live.get(id); if(!S) return false; const i = S.items.findIndex(x => x.k === key); if(i < 0) return false;
  let y = 0; for(let j = 0; j < i; j++) y += S.hs[j];
  const scR = S.sc === document.scrollingElement ? {top:0} : S.sc.getBoundingClientRect(), top = S.el.getBoundingClientRect().top - scR.top + S.sc.scrollTop;
  const want = top + y, view = S.sc.clientHeight || innerHeight;
  if(want < S.sc.scrollTop + 60 || want + S.hs[i] > S.sc.scrollTop + view - 40) S.sc.scrollTop = Math.max(0, want - view / 3);
  vlPaint(S, true); return true;
}
/* the keys of a live list, in order (for keyboard navigation) */
const vlKeys = id => { const S = VL.live.get(id); return S ? S.items.map(x => x.k) : []; };
addEventListener('resize', () => { for(const S of VL.live.values()) vlPaint(S, true); }, {passive:true});
