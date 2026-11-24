/* Notebook links, the Obsidian way: type [[ in a page to link another page (or a case, evidence, an indicator, a vault entry,
   a note, a detection or a playbook). Links are stored by id, so renaming a page never breaks them, and a link to a page that
   does not exist yet creates it when clicked. The side panel shows the pages that link here (backlinks), pages that mention
   this page's title without linking it (one click links them), where this page links to, and the indicators on the page that
   are already in your cases. The graph shows every page and its links. Markdown export writes [[Title]], and imported
   Markdown with [[Title]] or [[Title|alias]] links up by itself. */
const NBW_KINDS = {page:['Page', 'file-text'], new:['Page not created yet', 'file-plus'], case:['Case', 'folder-open'], entry:['Vault entry', 'layers'], record:['Evidence', 'file-search'],
  ent:['Indicator', 'crosshair'], note:['Note', 'sticky-note'], rule:['Detection', 'file-code'], playbook:['Playbook', 'list-checks']};
const NBW_RE = /^(page|new|case|entry|record|ent|note|rule|playbook):([^\n]{1,200})$/;
const NBW_LIT = /\[\[([^\[\]\n|]{1,120})(?:\|([^\[\]\n]{1,120}))?\]\]/g;
const nbwParse = v => { const m = NBW_RE.exec(String(v || '')); return m && m[2].trim() ? {k:m[1], id:m[2].trim()} : null; };
let nbwEM = {r:-1, m:null};
const nbwEnts = () => { if(nbwEM.r !== rev || !nbwEM.m){ let m = new Map(); try{ m = globalEnts(); }catch(e){} nbwEM = {r:rev, m}; } return nbwEM.m; };
const nbwByTitle = t => { const k = String(t || '').trim().toLowerCase(); return k ? DB.nb.pages.find(p => (p.title || '').trim().toLowerCase() === k) || null : null; };

/* what a link points at, and whether it is still there */
function nbwTarget(v){
  const w = nbwParse(v); if(!w) return {ok:false, k:'', id:'', title:'', sub:'', icon:'link', kind:''};
  const [kind, icon] = NBW_KINDS[w.k], r = {k:w.k, id:w.id, kind, icon, ok:false, title:w.id, sub:kind};
  if(w.k === 'page' || w.k === 'new'){ const p = w.k === 'page' ? nbPage(w.id) : nbwByTitle(w.id);
    if(p){ const b = nbBookOfPage(p); return Object.assign(r, {ok:true, k:'page', id:p.id, kind:'Page', icon:'file-text', title:p.title || 'Untitled', sub:'Page' + (b ? ' · ' + b.name : '')}); }
    if(w.k === 'page') r.title = 'Deleted page'; else r.sub = 'Not created yet — click to create'; return r; }
  try{
    if(w.k === 'case'){ const c = DB.cases.find(x => x.id === w.id); if(c) Object.assign(r, {ok:true, title:caseNm(c), sub:'Case · ' + (c.code || '')}); }
    else if(w.k === 'entry'){ const e = DB.entries.find(x => x.id === w.id); if(e) Object.assign(r, {ok:true, title:primary(e), caseId:e.caseId, sub:((TYPES[e.type] || {}).label || 'Vault entry') + ' · ' + caseNm(e.caseId)}); }
    else if(w.k === 'record'){ const x = DB.records.find(y => y.id === w.id); if(x) Object.assign(r, {ok:true, title:x.title, caseId:x.caseId, sub:'Evidence · ' + caseNm(x.caseId)}); }
    else if(w.k === 'ent'){ const g = nbwEnts().get(w.id); r.title = w.id.replace(/^[^:]+:/, '');
      if(g) Object.assign(r, {ok:true, title:g.v, sub:(E.LABEL[g.k] || g.k) + ' · in ' + g.cases.size + ' case' + (g.cases.size === 1 ? '' : 's')});
      else { const k = w.id.split(':')[0]; Object.assign(r, {ok:true, look:true, sub:(E.LABEL[k] || 'Indicator') + ' · not in a case — opens a lookup'}); } }
    else if(w.k === 'note'){ const n = (DB.notes || []).find(x => x.id === w.id); if(n) Object.assign(r, {ok:true, title:noteLabel(n)}); }
    else if(w.k === 'rule'){ const x = (DB.rules || []).find(y => y.id === w.id); if(x) Object.assign(r, {ok:true, title:x.title}); }
    else if(w.k === 'playbook'){ const x = (DB.playbooks || []).find(y => y.id === w.id); if(x) Object.assign(r, {ok:true, title:x.name}); }
  }catch(e){}
  return r;
}

/* the stored form: <a class="nb-wl" data-wl="kind:id">. In the editor (live) a page link shows the page's current title unless
   it was written with an alias, and a link whose target is gone is shown dashed. */
function nbwAnchor(w, label, alias, live){
  const v = w.k + ':' + w.id; let t = String(label || '').replace(/\s+/g, ' ').trim().slice(0, 200), cls = 'nb-wl', tip = '';
  if(live){ const T = nbwTarget(v); if(!T.ok) cls += ' miss'; else if(T.k === 'page' && !alias) t = T.title; if(!t) t = T.title; tip = ` title="${esc(T.kind + (T.ok ? '' : ' — missing'))}"`; if(w.k !== 'page' && w.k !== 'new') cls += ' x'; }
  return `<a class="${cls}" data-wl="${esc(v)}"${alias ? ' data-a="1"' : ''} contenteditable="false"${tip}>${esc(t || w.id)}</a>`;
}
/* [[Title]] and [[Title|alias]] typed as plain text (imported Markdown, pasted text) become links when the page is shown */
function nbwLit(s){
  const fx = x => esc(x.replace(/ /g, ' ')).replace(/ {2}/g, ' &nbsp;'); let out = '', last = 0;
  for(const m of s.matchAll(NBW_LIT)){ out += fx(s.slice(last, m.index)); const p = nbwByTitle(m[1]);
    out += nbwAnchor(p ? {k:'page', id:p.id} : {k:'new', id:m[1].trim()}, m[2] || m[1], !!m[2], true); last = m.index + m[0].length; }
  return out + fx(s.slice(last));
}
/* links on a page, resolved: [{v:'page:id' | 'new:Title' | 'case:id' …, t:label, ctx:the line it sits in}] */
function nbwOut(p){
  const I = nbInfo(p); return (I.wl || []).map(l => { const w = nbwParse(l.v); if(!w) return null;
    if(w.k === 'new' || w.k === 'lit'){ const q = nbwByTitle(w.id); return {...l, v:q ? 'page:' + q.id : 'new:' + w.id}; } return l; }).filter(Boolean);
}
function nbwBacklinks(p){
  const out = []; for(const q of DB.nb.pages){ if(q.id === p.id) continue; const hits = nbwOut(q).filter(l => l.v === 'page:' + p.id); if(hits.length) out.push({q, ctx:hits[0].ctx, n:hits.length}); }
  return out.sort((a, b) => b.q.updated - a.q.updated);
}
const nbwTitleRe = t => { const s = String(t || '').trim(); if(s.length < 3 || /^untitled$/i.test(s)) return null; const e = s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\s+/g, '\\s+');
  try{ return new RegExp('(^|[^\\p{L}\\p{N}_])(' + e + ')(?![\\p{L}\\p{N}_])', 'iu'); }catch(x){ return null; } };
function nbwMentions(p){
  const re = nbwTitleRe(p.title); if(!re) return []; const linked = new Set(nbwBacklinks(p).map(x => x.q.id)), out = [];
  for(const q of DB.nb.pages){ if(q.id === p.id || linked.has(q.id)) continue; const I = nbInfo(q);
    const line = I.text.split('\n').find(l => re.test(l.replace(/\[\[[^\]]*\]\]/g, ''))); if(line) out.push({q, ctx:line.slice(0, 220)}); if(out.length >= 12) break; }
  return out;
}
/* turns the first plain mention of p's title in page q into a link (not inside a link, code or a code block) */
function nbwLinkMention(qid, pid){
  const q = nbPage(qid), p = nbPage(pid), re = p && nbwTitleRe(p.title); if(!q || !re) return false;
  const body = nbDoc(q.html), tw = document.createTreeWalker(body, NodeFilter.SHOW_TEXT); let n, done = false;
  while(!done && (n = tw.nextNode())){ if(n.parentNode.closest('a,pre,code')) continue; const m = re.exec(n.data); if(!m) continue;
    const at = m.index + m[1].length, mid = n.splitText(at); mid.splitText(m[2].length);
    const a = body.ownerDocument.createElement('a'); a.setAttribute('data-wl', 'page:' + p.id); if(m[2] !== p.title) a.setAttribute('data-a', '1'); a.textContent = m[2]; mid.replaceWith(a); done = true; }
  if(!done) return false; q.html = nbClean(body.innerHTML); nbTouch(q); return true;
}
/* indicators written on this page that are already in a case */
function nbwIocs(p){
  const out = [], seen = new Set(); let ents; try{ ents = nbwEnts(); }catch(e){ return out; }
  for(const e of E.extract(nbInfo(p).text).slice(0, 400)){ const id = e.k + ':' + e.v; if(seen.has(id)) continue; seen.add(id); const g = ents.get(id); if(g) out.push({id, g}); if(out.length >= 8) break; }
  return out;
}

/* ---------- side panel ---------- */
function nbwSideHtml(p){
  const back = nbwBacklinks(p), men = nbwMentions(p), outs = [], seen = new Set();
  for(const l of nbwOut(p)){ if(seen.has(l.v)) continue; seen.add(l.v); outs.push(nbwTarget(l.v)); }
  const iocs = nbwIocs(p).filter(x => !seen.has('ent:' + x.id));
  const row = (v, T, small, extra) => `<div class="nbs-bl"><button class="nbs-lk${T.ok ? '' : ' miss'}" data-act="nbwGo" data-v="${esc(v)}"><span class="ic">${ico(T.icon,'sm')}</span><span><b>${esc(T.title)}</b><small>${esc(small)}</small></span></button>${extra || ''}</div>`;
  const pg = q => { const b = nbBookOfPage(q); return {ok:true, icon:'file-text', title:q.title || 'Untitled', b:b ? b.name : ''}; };
  return `<section class="nbs-w" id="nbwBack"><h4>${ico('corner-down-right','sm')}Linked from${back.length ? `<span class="nbs-n">${back.length}</span>` : ''}</h4>
      ${back.length ? back.map(x => row('page:' + x.q.id, pg(x.q), x.ctx || pg(x.q).b)).join('') : '<p class="nbs-e">No page links here yet. In any page, type <b>[[</b> and pick this one.</p>'}</section>
    ${men.length ? `<section class="nbs-w" id="nbwMen"><h4>${ico('unlink','sm')}Mentioned in<span class="nbs-n">${men.length}</span></h4>
      ${men.map(x => row('page:' + x.q.id, pg(x.q), x.ctx, `<button class="btn sm nbs-mk" data-act="nbwLinkIt" data-id="${x.q.id}" title="Make this mention a link">Link</button>`)).join('')}</section>` : ''}
    <section class="nbs-w" id="nbwOut"><h4>${ico('link','sm')}Links on this page${outs.length ? `<span class="nbs-n">${outs.length}</span>` : ''}<button class="nbs-add" data-act="nbwGraph" aria-label="Graph of pages" title="Graph of pages">${ico('waypoints','sm')}</button></h4>
      ${outs.length ? outs.map(T => row(T.k + ':' + T.id, T, T.sub)).join('') : '<p class="nbs-e">Type <b>[[</b> to link a page, a case, evidence, an indicator, a note, a detection or a playbook. <b>[[case:</b> or <b>[[ip:</b> narrows the list.</p>'}</section>
    ${iocs.length ? `<section class="nbs-w" id="nbwIoc"><h4>${ico('crosshair','sm')}Indicators in your cases<span class="nbs-n">${iocs.length}</span></h4>
      ${iocs.map(x => row('ent:' + x.id, {ok:true, icon:'crosshair', title:x.g.v}, (E.LABEL[x.g.k] || x.g.k) + ' · in ' + x.g.cases.size + ' case' + (x.g.cases.size === 1 ? '' : 's'))).join('')}</section>` : ''}`;
}

/* ---------- opening a link ---------- */
function nbwGo(v){
  const w = nbwParse(v); if(!w) return; nbCommit(); nbwClose();
  if(w.k === 'page' || w.k === 'new'){ const p = w.k === 'page' ? nbPage(w.id) : nbwByTitle(w.id); if(p) return nbOpen(p.id); if(w.k === 'page') return toast('That page was deleted'); return nbwCreate(w.id); }
  const T = nbwTarget(v); if(!T.ok) return toast('That ' + T.kind.toLowerCase() + ' is no longer in ' + BRAND.name);
  if(T.look){ const i = w.id.indexOf(':'); return lookGo(w.id.slice(0, i), w.id.slice(i + 1)); }
  srchGo({kind:w.k, id:w.id, caseId:T.caseId});
}
function nbwCreate(title){
  const cur = nbPage(UI.nbPage); let sec = cur ? cur.sectionId : (DB.nb.sections[0] || {}).id;
  if(!sec){ const b = nbNewBook({name:'Notes'}); sec = nbNewSec(b.id, 'General').id; }
  const t = String(title).trim().slice(0, 200), p = nbNewPage(sec, {title:t}), key = t.toLowerCase();
  for(const q of DB.nb.pages) if(q !== p && q.html.includes('data-wl="new:')){ const h = q.html.replace(/data-wl="new:([^"]*)"/g, (m, x) => { const d = new DOMParser().parseFromString('<b>' + x + '</b>', 'text/html').body.textContent; return d.trim().toLowerCase() === key ? `data-wl="page:${p.id}"` : m; }); if(h !== q.html){ q.html = h; nbTouch(q); } }
  mutate('new page ' + t); toast('Created the page “' + t + '”'); nbOpen(p.id, {full:true});
}

/* ---------- [[ autocomplete in the editor ---------- */
let NBW = null;   // {node, start, q, items, at, idx}
function nbwClose(){ const el = $('nbwPop'); if(el) el.remove(); NBW = null; const ed = $('nbEd'); if(ed) ed.removeAttribute('aria-activedescendant'); }
function nbwIdx(){ if(NBW && NBW.idx) return NBW.idx; let I = []; try{ I = srchIndex().filter(x => ['case', 'entry', 'record', 'ent', 'note', 'rule', 'playbook'].includes(x.kind)); }catch(e){} if(NBW) NBW.idx = I; return I; }
const NBW_PFX = {page:'page', p:'page', case:'case', c:'case', entry:'entry', vault:'entry', ev:'record', evidence:'record', record:'record', ind:'ent', ioc:'ent', note:'note', rule:'rule', detection:'rule', playbook:'playbook', pb:'playbook'};
function nbwItems(q){
  const raw = q.trim(), m = /^([a-z]+):\s*(.*)$/i.exec(raw), only = m && NBW_PFX[m[1].toLowerCase()], text = only ? m[2] : raw, low = text.toLowerCase(), words = low.split(/\s+/).filter(Boolean);
  const score = t => { const s = String(t || '').toLowerCase(); if(!words.length) return 1; if(!words.every(w => s.includes(w))) return 0; return s === low ? 5 : s.startsWith(low) ? 3 : 1; };
  const out = [], cur = UI.nbPage;
  if(!only || only === 'page') DB.nb.pages.filter(p => p.id !== cur).map(p => ({p, s:score(p.title) * 2 + (p.updated > Date.now() - 7 * NB_DAY ? .5 : 0)})).filter(x => x.s > 0).sort((a, b) => b.s - a.s || b.p.updated - a.p.updated).slice(0, only ? 12 : 6)
    .forEach(({p}) => { const b = nbBookOfPage(p); out.push({v:'page:' + p.id, t:p.title || 'Untitled', sub:'Page' + (b ? ' · ' + b.name : ''), icon:'file-text'}); });
  if(only !== 'page' && (words.length || only)){ nbwIdx().filter(x => (!only || x.kind === only)).map(x => ({x, s:score(x.title + ' ' + (only ? '' : x.sub || ''))})).filter(y => y.s > 0).sort((a, b) => b.s - a.s).slice(0, only ? 12 : 6)
    .forEach(({x}) => out.push({v:x.kind + ':' + x.id, t:x.title, sub:(x.kind === 'case' || x.kind === 'rule' || x.kind === 'record' ? NBW_KINDS[x.kind][0] + ' · ' : '') + (x.sub || ''), icon:NBW_KINDS[x.kind][1]})); }
  // an indicator typed straight in links even when no case has it yet
  if(text && (!only || only === 'ent')){ let n = null; try{ n = iocNorm(text); }catch(e){} if(n && !out.some(o => o.v === 'ent:' + n.k + ':' + n.v)) out.push({v:'ent:' + n.k + ':' + n.v, t:n.v, sub:(E.LABEL[n.k] || n.k) + ' · indicator', icon:'crosshair'}); }
  if(text && (!only || only === 'page') && !nbwByTitle(text)) out.push({v:'new:' + text.trim().slice(0, 120), t:'Create page “' + text.trim().slice(0, 80) + '”', sub:'New page in this section', icon:'file-plus', make:true, label:text.trim()});
  return out.slice(0, 14);
}
function nbwPaint(){
  if(!NBW) return; let el = $('nbwPop'); const ed = $('nbEd');
  if(!el){ el = document.createElement('div'); el.id = 'nbwPop'; el.className = 'nbw-pop'; el.setAttribute('role', 'listbox'); el.setAttribute('aria-label', 'Link to');
    el.addEventListener('mousedown', ev => ev.preventDefault()); el.addEventListener('click', ev => { const b = ev.target.closest('[data-i]'); if(b){ NBW.at = +b.dataset.i; nbwPick(); } });
    document.body.appendChild(el); }
  const it = NBW.items;
  el.innerHTML = `<div class="nbw-h">${ico('link','sm')}Link to <span>· [[case: [[ioc: [[note: …</span></div>` + (it.length ? it.map((x, i) => `<button type="button" role="option" id="nbwo${i}" data-i="${i}" aria-selected="${i === NBW.at}" class="${x.make ? 'mk' : ''}">${ico(x.icon,'sm')}<span><b>${esc(x.t)}</b><small>${esc(x.sub)}</small></span></button>`).join('')
    : '<p class="nbw-none">Nothing matches. Keep typing a page title, or close with ]] to make a new page.</p>');
  if(ed) ed.setAttribute('aria-activedescendant', 'nbwo' + NBW.at);
  const s = getSelection(); let r = null; if(s.rangeCount){ const rr = s.getRangeAt(0).cloneRange(); rr.collapse(true); r = rr.getClientRects()[0] || rr.getBoundingClientRect(); }
  if(!r || (!r.left && !r.top)){ const e = ed.getBoundingClientRect(); r = {left:e.left + 20, bottom:e.top + 40, top:e.top + 20}; }
  const w = Math.min(340, innerWidth - 16), h = el.offsetHeight || 260, below = r.bottom + 6 + h < innerHeight;
  el.style.width = w + 'px'; el.style.left = Math.max(8, Math.min(r.left - 12, innerWidth - w - 8)) + 'px'; el.style.top = (below ? r.bottom + 6 : Math.max(8, r.top - h - 6)) + 'px';
  const on = el.querySelector('[aria-selected=true]'); if(on) on.scrollIntoView({block:'nearest'});
}
/* the [[query just before the caret, if any */
function nbwProbe(){
  const s = getSelection(); if(!s.rangeCount || !s.isCollapsed) return null; const n = s.anchorNode; if(!n || n.nodeType !== 3) return null;
  if(n.parentNode.closest && n.parentNode.closest('pre,code,a')) return null;
  const t = n.data.slice(0, s.anchorOffset), m = /\[\[([^\[\]\n]{0,80})$/.exec(t); if(!m) return null;
  return {node:n, start:m.index, end:s.anchorOffset, q:m[1]};
}
function nbwReplace(node, start, end, html){
  // built by hand: the browser's insertHTML moves a non-editable link out of its paragraph
  const s = getSelection(), r = document.createRange(); r.setStart(node, start); r.setEnd(node, Math.min(end, node.data.length)); r.deleteContents();
  const tp = document.createElement('template'); tp.innerHTML = html; const a = tp.content.firstChild, sp = document.createTextNode('\u00a0');
  r.insertNode(sp); r.insertNode(a); const c = document.createRange(); c.setStart(sp, 1); c.collapse(true); s.removeAllRanges(); s.addRange(c); nbDirty();
}
function nbwPick(){
  if(!NBW) return; const x = NBW.items[NBW.at], P = nbwProbe(); if(!x || !P){ nbwClose(); return; }
  const w = nbwParse(x.v); nbwClose(); nbwReplace(P.node, P.start, P.end, nbwAnchor(w, x.make ? x.label : x.t, false, true));
}
function nbwInput(){
  const s = getSelection();
  // [[Title]] typed out in full links straight away
  if(s.rangeCount && s.isCollapsed && s.anchorNode && s.anchorNode.nodeType === 3 && !(s.anchorNode.parentNode.closest && s.anchorNode.parentNode.closest('pre,code,a'))){
    const n = s.anchorNode, t = n.data.slice(0, s.anchorOffset), m = /\[\[([^\[\]\n|]{1,120})(?:\|([^\[\]\n]{1,120}))?\]\]$/.exec(t);
    if(m){ nbwClose(); const q = m[1].trim(), best = nbwItems(q).find(x => !x.make && x.t.toLowerCase() === q.replace(/^[a-z]+:\s*/i, '').toLowerCase()) || null;
      const w = best ? nbwParse(best.v) : (nbwByTitle(q) ? {k:'page', id:nbwByTitle(q).id} : {k:'new', id:q});
      return nbwReplace(n, m.index, s.anchorOffset, nbwAnchor(w, m[2] || (best ? best.t : q), !!m[2], true)); }
  }
  const P = nbwProbe(); if(!P){ if(NBW) nbwClose(); return; }
  const keep = NBW && NBW.idx; NBW = {q:P.q, at:0, idx:keep, items:[]}; NBW.items = nbwItems(P.q); nbwPaint();
}
function nbwBind(ed){
  nbwClose();
  ed.addEventListener('input', nbwInput);
  ed.addEventListener('keydown', ev => {
    if(!NBW) return; const n = NBW.items.length;
    if(ev.key === 'ArrowDown' || ev.key === 'ArrowUp'){ ev.preventDefault(); ev.stopImmediatePropagation(); if(n){ NBW.at = (NBW.at + (ev.key === 'ArrowDown' ? 1 : n - 1)) % n; nbwPaint(); } return; }
    if(ev.key === 'Enter' || ev.key === 'Tab'){ if(!n) return nbwClose(); ev.preventDefault(); ev.stopImmediatePropagation(); return nbwPick(); }
    if(ev.key === 'Escape'){ ev.preventDefault(); ev.stopImmediatePropagation(); return nbwClose(); }
  });
  ed.addEventListener('blur', () => setTimeout(() => { if(document.activeElement !== ed) nbwClose(); }, 120));
  ed.addEventListener('click', ev => { const a = ev.target.closest('a.nb-wl'); if(!a) return; ev.preventDefault(); nbwGo(a.getAttribute('data-wl')); });
  const sc = $('nbScroll'); if(sc) sc.addEventListener('scroll', () => { if(NBW) nbwPaint(); }, {passive:true});
}

/* ---------- graph of pages ---------- */
function nbwGraphData(){
  const G = UI.nbg || (UI.nbg = {book:'all', ext:false, orph:true});
  const pages = DB.nb.pages.filter(p => G.book === 'all' || (nbBookOfPage(p) || {}).id === G.book);
  const ids = new Set(pages.map(p => p.id)), nodes = new Map(), edges = new Map();
  for(const p of pages){ const b = nbBookOfPage(p); nodes.set('page:' + p.id, {id:'page:' + p.id, t:p.title || 'Untitled', page:true, color:nbColor(b && b.color), book:b ? b.name : '', deg:0}); }
  for(const p of pages) for(const l of nbwOut(p)){ const w = nbwParse(l.v); if(!w) continue;
    if(w.k === 'page' && !ids.has(w.id)) continue;
    if(w.k !== 'page'){ if(!G.ext && w.k !== 'new') continue; if(!nodes.has(l.v)){ const T = nbwTarget(l.v); nodes.set(l.v, {id:l.v, t:T.title, page:false, miss:!T.ok || w.k === 'new', icon:T.kind, deg:0}); } }
    const a = 'page:' + p.id, key = a < l.v ? a + '|' + l.v : l.v + '|' + a; if(a === l.v || edges.has(key)) continue; edges.set(key, {a, b:l.v}); nodes.get(a).deg++; nodes.get(l.v).deg++; }
  if(!G.orph) for(const [k, n] of nodes) if(!n.deg) nodes.delete(k);
  return {nodes:[...nodes.values()], edges:[...edges.values()].filter(e => nodes.has(e.a) && nodes.has(e.b))};
}
function nbwLayout(D){
  const N = D.nodes, n = N.length, at = new Map(N.map((x, i) => [x.id, i])), seed = s => { let h = 2166136261; for(let i = 0; i < s.length; i++) h = Math.imul(h ^ s.charCodeAt(i), 16777619); return (h >>> 0) / 4294967296; };
  N.forEach((x, i) => { const a = seed(x.id) * Math.PI * 2, r = 60 + 220 * Math.sqrt((i + 1) / (n + 1)); x.x = Math.cos(a) * r; x.y = Math.sin(a) * r; });
  const E2 = D.edges.map(e => [at.get(e.a), at.get(e.b)]), iters = n > 400 ? 80 : n > 150 ? 160 : 300, K = 70;
  for(let it = 0; it < iters; it++){ const t = 1 - it / iters, fx = new Float64Array(n), fy = new Float64Array(n);
    for(let i = 0; i < n; i++) for(let j = i + 1; j < n; j++){ let dx = N[i].x - N[j].x, dy = N[i].y - N[j].y, d2 = dx * dx + dy * dy || .01; if(d2 > 250000) continue; const f = K * K / d2; fx[i] += dx * f; fy[i] += dy * f; fx[j] -= dx * f; fy[j] -= dy * f; }
    for(const [i, j] of E2){ const dx = N[i].x - N[j].x, dy = N[i].y - N[j].y, d = Math.sqrt(dx * dx + dy * dy) || .01, f = (d - K) / d * .5; fx[i] -= dx * f; fy[i] -= dy * f; fx[j] += dx * f; fy[j] += dy * f; }
    for(let i = 0; i < n; i++){ fx[i] -= N[i].x * .06; fy[i] -= N[i].y * .06; const m = Math.sqrt(fx[i] * fx[i] + fy[i] * fy[i]) || 1, s = Math.min(m, 40 * t + 2) / m; N[i].x += fx[i] * s; N[i].y += fy[i] * s; } }
}
function nbwGraphView(){
  const G = UI.nbg || (UI.nbg = {book:'all', ext:false, orph:true}), D = nbwGraphData(); nbwLayout(D); UI.nbgD = D;
  const focus = UI.nbgFocus, nb = new Set(); if(focus) for(const e of D.edges){ if(e.a === focus) nb.add(e.b); if(e.b === focus) nb.add(e.a); }
  const pos = new Map(D.nodes.map(x => [x.id, x])), xs = D.nodes.map(x => x.x), ys = D.nodes.map(x => x.y);
  const px = 150, py = 70, x0 = Math.min(0, ...xs) - px, y0 = Math.min(0, ...ys) - py, w = Math.max(...xs, 0) - x0 + px, h = Math.max(...ys, 0) - y0 + py;   // room for the labels
  const npages = D.nodes.filter(x => x.page).length;
  const svg = D.nodes.length ? `<svg id="nbgSvg" class="nbg-svg" viewBox="${x0} ${y0} ${w} ${h}" role="img" aria-label="Graph of ${npages} pages and ${D.edges.length} links"><g id="nbgG">
      ${D.edges.map(e => { const a = pos.get(e.a), b = pos.get(e.b); return `<line data-a="${esc(e.a)}" data-b="${esc(e.b)}" x1="${a.x.toFixed(1)}" y1="${a.y.toFixed(1)}" x2="${b.x.toFixed(1)}" y2="${b.y.toFixed(1)}"${focus && (e.a === focus || e.b === focus) ? ' class="on"' : ''}/>`; }).join('')}
      ${D.nodes.map(x => { const r = (x.page ? 5 : 4) + Math.min(10, Math.sqrt(x.deg) * 2.2);
        return `<g class="nbg-n${x.page ? '' : ' ext'}${x.miss ? ' miss' : ''}${x.id === focus ? ' cur' : nb.has(x.id) ? ' nb' : ''}" data-id="${esc(x.id)}" transform="translate(${x.x.toFixed(1)} ${x.y.toFixed(1)})" tabindex="0" role="button" aria-label="${esc((x.page ? 'Page ' : (x.icon || '') + ' ') + x.t)}">
          <g class="nbg-d">${x.page ? `<circle r="${r.toFixed(1)}" style="fill:${x.color}"/>` : `<rect x="${-r}" y="${-r}" width="${2 * r}" height="${2 * r}" rx="3"/>`}<text y="${r.toFixed(1)}" dy="1.25em">${esc(x.t.length > 34 ? x.t.slice(0, 33) + '…' : x.t)}</text></g></g>`; }).join('')}
    </g></svg>` : '';
  return `<div class="nbg3" id="nbGraph">
    <div class="nbg-h"><button class="btn sm" data-act="nbwBack">${ico('arrow-left','sm')}Back</button><h1>Graph</h1><span class="nbg-st">${npages} page${npages === 1 ? '' : 's'} · ${D.edges.length} link${D.edges.length === 1 ? '' : 's'}</span><span class="sp"></span>
      <label class="sr" for="nbgBook">Notebook</label><select id="nbgBook" class="nbsel"><option value="all">All notebooks</option>${DB.nb.books.map(b => `<option value="${b.id}"${G.book === b.id ? ' selected' : ''}>${esc(b.name)}</option>`).join('')}</select>
      <label class="nbg-ck"><input type="checkbox" id="nbgExt"${G.ext ? ' checked' : ''}>Cases, evidence &amp; indicators</label><label class="nbg-ck"><input type="checkbox" id="nbgOrph"${G.orph ? ' checked' : ''}>Pages with no links</label></div>
    <div class="nbg-cv" id="nbgCv">${svg || `<div class="nbg-empty">${empty('waypoints', 'Nothing to show', DB.nb.pages.length ? 'No page here has a link yet. In a page, type [[ and pick another page, a case or an indicator.' : 'Make a notebook and a few pages, then link them with [[.', '')}</div>`}
      ${svg ? `<div class="nbg-zm" role="group" aria-label="Zoom"><button class="iconbtn" data-act="nbwZoom" data-v="1.25" aria-label="Zoom in">${ico('plus','sm')}</button><button class="iconbtn" data-act="nbwZoom" data-v="0.8" aria-label="Zoom out">${ico('minus','sm')}</button><button class="iconbtn" data-act="nbwZoom" data-v="0" aria-label="Fit">${ico('maximize-2','sm')}</button></div>
      <p class="nbg-tip">Click a page to open it · drag to move around · scroll to zoom · round dots are pages, squares are cases, evidence and indicators, dashed ones are not created yet.</p>` : ''}</div>
  </div>`;
}
function nbwGraphBind(){
  const G = UI.nbg, sel = $('nbgBook'), ex = $('nbgExt'), or = $('nbgOrph');
  if(sel) sel.onchange = () => { G.book = sel.value; renderMain(); }; if(ex) ex.onchange = () => { G.ext = ex.checked; renderMain(); }; if(or) or.onchange = () => { G.orph = or.checked; renderMain(); };
  const svg = $('nbgSvg'); if(!svg) return; const vb0 = svg.getAttribute('viewBox').split(' ').map(Number); let vb = vb0.slice(); // labels keep the same size on screen at any zoom
  const fit = () => { const r = svg.getBoundingClientRect(); if(!r.width) return; const k = Math.max(vb[2] / r.width, vb[3] / r.height), nk = Math.max(1, k * .7);   // dots never shrink below a readable size either
    svg.style.setProperty('--nk', nk.toFixed(3)); svg.style.setProperty('--nfs', (12 * k / nk).toFixed(2) + 'px'); svg.style.setProperty('--nsw', (3 * k / nk).toFixed(2) + 'px'); };
  UI.nbgVB = {vb0, set:v => { vb = v; svg.setAttribute('viewBox', v.join(' ')); svg.classList.toggle('far', v[2] > vb0[2] * 1.6); fit(); }, get:() => vb}; fit();
  if(window.ResizeObserver){ const ro = new ResizeObserver(() => { if(!svg.isConnected) return ro.disconnect(); fit(); }); ro.observe(svg); }
  const D = UI.nbgD, adj = new Map(); for(const e of D.edges){ (adj.get(e.a) || adj.set(e.a, new Set()).get(e.a)).add(e.b); (adj.get(e.b) || adj.set(e.b, new Set()).get(e.b)).add(e.a); }
  const hi = id => { svg.classList.toggle('hov', !!id); svg.querySelectorAll('.nbg-n').forEach(g => g.classList.toggle('lit', !!id && (g.dataset.id === id || (adj.get(id) || new Set()).has(g.dataset.id))));
    svg.querySelectorAll('line').forEach(l => l.classList.toggle('lit', !!id && (l.dataset.a === id || l.dataset.b === id))); };
  svg.addEventListener('pointerover', ev => { const g = ev.target.closest('.nbg-n'); hi(g ? g.dataset.id : null); });
  svg.addEventListener('pointerleave', () => hi(null));
  svg.addEventListener('focusin', ev => { const g = ev.target.closest('.nbg-n'); hi(g ? g.dataset.id : null); });
  let drag = null;
  svg.addEventListener('pointerdown', ev => { if(ev.button) return; drag = {x:ev.clientX, y:ev.clientY, vb:vb.slice(), moved:false, node:ev.target.closest('.nbg-n')}; });
  svg.addEventListener('pointermove', ev => { if(!drag) return; const dx = ev.clientX - drag.x, dy = ev.clientY - drag.y; if(!drag.moved && Math.hypot(dx, dy) < 4) return;
    if(!drag.moved){ drag.moved = true; try{ svg.setPointerCapture(ev.pointerId); }catch(e){} } const r = svg.getBoundingClientRect(), k = Math.max(vb[2] / r.width, vb[3] / r.height);
    UI.nbgVB.set([drag.vb[0] - dx * k, drag.vb[1] - dy * k, vb[2], vb[3]]); });
  svg.addEventListener('pointerup', () => { const d = drag; drag = null; if(!d || d.moved || !d.node) return; nbwGraphOpen(d.node.dataset.id); });
  svg.addEventListener('keydown', ev => { const g = ev.target.closest('.nbg-n'); if(g && (ev.key === 'Enter' || ev.key === ' ')){ ev.preventDefault(); nbwGraphOpen(g.dataset.id); } });
  svg.addEventListener('wheel', ev => { ev.preventDefault(); const r = svg.getBoundingClientRect(), f = ev.deltaY > 0 ? 1.12 : 1 / 1.12; nbwZoomAt(f, (ev.clientX - r.left) / r.width, (ev.clientY - r.top) / r.height); }, {passive:false});
}
function nbwZoomAt(f, fx = .5, fy = .5){ const Z = UI.nbgVB; if(!Z) return; const v = Z.get(); if(!f){ return Z.set(Z.vb0.slice()); }
  const w = Math.max(Z.vb0[2] / 8, Math.min(Z.vb0[2] * 4, v[2] * f)), h = v[3] * (w / v[2]); Z.set([v[0] + (v[2] - w) * fx, v[1] + (v[3] - h) * fy, w, h]); }
function nbwGraphOpen(id){ const w = nbwParse(id); if(!w) return; if(w.k === 'page'){ UI.nbgFocus = id; return nbOpen(w.id, {full:true}); } nbwGo(id); }

const NBW_ACTS = {
  nbwGo:(id, v) => nbwGo(v),
  nbwLinkIt:id => { const p = nbPage(UI.nbPage); if(!p) return; nbCommit(); if(nbwLinkMention(id, p.id)){ mutate('linked a mention'); const side = $('nbSide'); if(side) side.innerHTML = nbSideHtml(p); toast('Linked from “' + (nbPage(id).title || 'Untitled') + '”'); } else toast('Could not find the mention to link'); },
  nbwGraph:() => { nbCommit(); nbwClose(); UI.nbgFrom = UI.nbView === 'page' ? UI.nbPage : null; UI.nbgFocus = UI.nbgFrom ? 'page:' + UI.nbgFrom : null; UI.nbView = 'graph'; if(UI.route.area !== 'notebook') return go('#/notebook'); renderMain(); },
  nbwBack:() => { const p = UI.nbgFrom && nbPage(UI.nbgFrom); if(p) return nbOpen(p.id, {full:true}); UI.nbView = 'lib'; renderMain(); },
  nbwZoom:(id, v) => nbwZoomAt(+v)
};
