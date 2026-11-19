/* ==========================================================================
   How much can go into a field. Every text box gets a length cap so nothing
   — a stuck key, a runaway paste, a crafted file — can grow a field without
   end, slow the page or fill the browser's storage:
   · one-line fields (names, searches, links, codes): 4,096 characters
   · text areas: 5 million characters (a large pasted log or JSON export);
     short notes and descriptions keep the smaller caps set on them
   · the notebook page: 2 million characters of text
   A field that already sets its own maxlength keeps it. A paste that would go
   over the cap is cut, and says so.
   ========================================================================== */
const LIM = {line:4096, area:5000000, page:2000000};
const LIM_SKIP = /^(file|number|range|checkbox|radio|color|date|datetime-local|time|month|week|hidden|submit|button|reset|image)$/i;
function limCap(el){
  if(el.tagName === 'TEXTAREA'){ if(!el.hasAttribute('maxlength')) el.maxLength = +el.dataset.max || LIM.area; }
  else if(el.tagName === 'INPUT' && !LIM_SKIP.test(el.type || 'text')){ if(!el.hasAttribute('maxlength')) el.maxLength = +el.dataset.max || LIM.line; }
}
function limScan(root){ if(!root || !root.querySelectorAll) return; if(root.matches && root.matches('input, textarea')) limCap(root); root.querySelectorAll('input, textarea').forEach(limCap); }
new MutationObserver(ms => { for(const m of ms) for(const n of m.addedNodes) if(n.nodeType === 1) limScan(n); }).observe(document.documentElement, {childList:true, subtree:true});
limScan(document.body);
/* a field set by code (a restored draft, a tool filling it in) is held to the same cap */
document.addEventListener('focusin', ev => { const el = ev.target; if(el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA')){ limCap(el); if(el.maxLength > 0 && el.value.length > el.maxLength) el.value = el.value.slice(0, el.maxLength); } }, true);
/* say so when a paste is cut */
document.addEventListener('paste', ev => {
  const el = ev.target; if(!el || !ev.clipboardData) return; const t = ev.clipboardData.getData('text/plain') || '';
  if(el.tagName === 'INPUT' || el.tagName === 'TEXTAREA'){ limCap(el); const max = el.maxLength; if(!(max > 0)) return;
    const room = max - (el.value.length - ((el.selectionEnd || 0) - (el.selectionStart || 0)));
    if(t.length > room && typeof toast === 'function') toast(`That paste is ${t.length.toLocaleString()} characters; this field takes ${max.toLocaleString()}, so it was cut` + (el.tagName === 'TEXTAREA' ? ' — import a file instead' : '')); return; }
  const ed = el.closest && el.closest('[contenteditable="true"]'); if(!ed) return;
  if((ed.textContent || '').length + t.length > LIM.page){ ev.preventDefault(); ev.stopImmediatePropagation(); if(typeof toast === 'function') toast('This page is full (' + LIM.page.toLocaleString() + ' characters) — start a new page or attach the text as a file'); }
}, true);
/* typing or dropping into a full notebook page */
document.addEventListener('beforeinput', ev => {
  const el = ev.target, ed = el && el.closest && el.closest('[contenteditable="true"]'); if(!ed || /^delete/.test(ev.inputType)) return;
  if((ed.textContent || '').length >= LIM.page){ ev.preventDefault(); if(typeof toast === 'function' && !limCap.told){ limCap.told = true; setTimeout(() => limCap.told = false, 4000); toast('This page is full (' + LIM.page.toLocaleString() + ' characters) — start a new page'); } }
}, true);
