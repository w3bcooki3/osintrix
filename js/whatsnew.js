/* "What's new" — the release history.
   Reads CHANGELOG_DATA (js/data/changelog.js), the same source CHANGELOG.md is built from.
   Filtering and searching repaint only the timeline, so the page never flashes. */
const WN_TYPES = {
  added:   {label: 'Added',   icon: 'plus',          cls: 'add', one: 'new feature',  many: 'new features'},
  changed: {label: 'Changed', icon: 'arrow-down-up', cls: 'chg', one: 'improvement',  many: 'improvements'},
  fixed:   {label: 'Fixed',   icon: 'wrench',        cls: 'fix', one: 'fix',          many: 'fixes'},
  removed: {label: 'Removed', icon: 'trash-2',       cls: 'rem', one: 'removal',      many: 'removals'}
};
const WN_ORDER = ['added', 'changed', 'fixed', 'removed'];
function wnDate(d){
  if(!d) return '';
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(d); if(!m) return esc(d);
  const MON = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  return MON[+m[2] - 1] + ' ' + (+m[3]) + ', ' + m[1];
}
const wnData = () => typeof CHANGELOG_DATA !== 'undefined' ? CHANGELOG_DATA : [];
/* the text, escaped, with every match of the search marked */
function wnMark(text, q){
  const s = esc(text); if(!q) return s;
  const re = new RegExp('(' + esc(q).replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ')', 'gi');
  return s.replace(re, '<mark>$1</mark>');
}
function wnMatches(){
  const q = (UI.wnQ || '').trim().toLowerCase(), f = UI.wnType && WN_TYPES[UI.wnType] ? UI.wnType : null;
  return wnData().map(v => ({v, ch:v.changes.filter(c => (!f || c.type === f) && (!q || (c.text + ' ' + v.name + ' v' + v.version).toLowerCase().includes(q)))})).filter(x => x.ch.length);
}
function viewWhatsNew(){
  const data = wnData(), latest = data[0], tally = {}, total = data.reduce((n, v) => n + v.changes.length, 0);
  data.forEach(v => v.changes.forEach(c => tally[c.type] = (tally[c.type] || 0) + 1));
  const first = data.slice().reverse().find(v => /^\d{4}-/.test(v.date || '')), cur = UI.wnType || '';
  const tile = (t, label, n, icon, cls) => `<button class="wn2-f ${cls}" data-act="wnType" data-v="${t}" aria-pressed="${cur === t}"><span class="wn2-fi">${ico(icon,'sm')}</span><span class="wn2-fl"><b>${n}</b>${label}</span></button>`;
  return `<div class="scroll" id="wnScroll"><div class="wn2">
    <header class="wn2-hero"><div class="wn2-hin">
      <div class="wn2-ht"><div><p class="wn2-k">${esc(BRAND.name)} · release history</p><h1>What’s new</h1>
        <p class="wn2-sub">Every change, newest first. Everything runs offline in your browser.</p></div>
        ${latest ? `<a class="wn2-now" href="#/whatsnew" data-act="wnJump" data-v="${esc(latest.version)}"><span class="wn2-pulse"></span><span><small>You’re on</small><b>v${esc(latest.version)} · ${esc(latest.name)}</b><small>${wnDate(latest.date)}</small></span></a>` : ''}</div>
      <div class="wn2-stats"><div><b>${data.length}</b><span>releases</span></div><div><b>${total}</b><span>changes</span></div>${first ? `<div><b>${esc(wnDate(first.date))}</b><span>first dated release</span></div>` : ''}
        <div class="wn2-dist" role="img" aria-label="${WN_ORDER.filter(t => tally[t]).map(t => tally[t] + ' ' + WN_TYPES[t].label.toLowerCase()).join(', ')}">${WN_ORDER.filter(t => tally[t]).map(t => `<i class="${WN_TYPES[t].cls}" style="flex:${tally[t]}"></i>`).join('')}</div></div>
      <div class="wn2-bar"><div class="wn2-fs" role="group" aria-label="Show changes of type">${tile('', 'All', total, 'layers', 'all')}${WN_ORDER.filter(t => tally[t]).map(t => tile(t, WN_TYPES[t].label, tally[t], WN_TYPES[t].icon, WN_TYPES[t].cls)).join('')}</div>
        <div class="wn2-q">${ico('search')}<label class="sr" for="wnQ">Search the history</label><input id="wnQ" type="search" placeholder="Search the history — graph, encryption, certificates…" value="${esc(UI.wnQ || '')}" autocomplete="off" spellcheck="false"></div></div>
    </div></header>
    <div class="wn2-main"><nav class="wn2-nav" aria-label="Releases" id="wnNav">${wnNav()}</nav><div class="wn2-tl" id="wnTl" aria-live="polite">${wnTimeline()}</div></div>
  </div></div>`;
}
function wnNav(){
  const M = new Set(wnMatches().map(x => x.v.version));
  return `<p class="wn2-nh">Releases</p>${wnData().map((v, i) => `<button class="wn2-ni${M.has(v.version) ? '' : ' dim'}" data-act="wnJump" data-v="${esc(v.version)}"><span class="mono">v${esc(v.version)}</span><span>${esc(v.name)}</span>${i === 0 ? '<em>Latest</em>' : ''}</button>`).join('')}`;
}
function wnTimeline(){
  const q = (UI.wnQ || '').trim(), M = wnMatches(), searching = !!(q || UI.wnType), n = M.reduce((s, x) => s + x.ch.length, 0), latest = (wnData()[0] || {}).version;
  if(!M.length) return `<div class="wn2-empty">${ico('search')}<b>Nothing matches${q ? ' “' + esc(q) + '”' : ''}</b><span>Try another word, or show every type of change.</span><button class="btn sm" data-act="wnClear">Clear the search</button></div>`;
  const head = searching ? `<p class="wn2-res"><b>${n}</b> change${n === 1 ? '' : 's'} in <b>${M.length}</b> release${M.length === 1 ? '' : 's'}${q ? ' for “' + esc(q) + '”' : ''}${UI.wnType ? ' · ' + WN_TYPES[UI.wnType].label.toLowerCase() + ' only' : ''}<button class="btn xs ghost" data-act="wnClear">${ico('x','sm')}Clear</button></p>` : '';
  const open = UI.wnOpen || (UI.wnOpen = new Set());
  return head + M.map(({v, ch}, i) => {
    const full = searching || i < 3 || open.has(v.version), cnt = {}; v.changes.forEach(c => cnt[c.type] = (cnt[c.type] || 0) + 1);
    const groups = WN_ORDER.map(t => { const L = ch.filter(c => c.type === t); return L.length ? `<section class="wn2-g"><h3 class="${WN_TYPES[t].cls}">${ico(WN_TYPES[t].icon,'sm')}${WN_TYPES[t].label}<span>${L.length}</span></h3><ul>${L.map(c => `<li>${wnMark(c.text, q)}</li>`).join('')}</ul></section>` : ''; }).join('');
    return `<article class="wn2-v${v.version === latest ? ' now' : ''}" id="v${esc(v.version)}"><div class="wn2-rail"><i></i></div><div class="card wn2-card">
      <header><span class="wn2-tag">v${esc(v.version)}</span><h2>${wnMark(v.name, q)}</h2>${v.version === latest ? '<span class="wn2-latest">Latest</span>' : ''}<span class="wn2-sp"></span>${v.date ? `<time datetime="${esc(v.date)}">${wnDate(v.date)}</time>` : ''}</header>
      ${v.summary && !searching ? `<p class="wn2-sum">${esc(v.summary)}</p>` : ''}
      <div class="wn2-cnt">${WN_ORDER.filter(t => cnt[t]).map(t => `<span class="${WN_TYPES[t].cls}">${ico(WN_TYPES[t].icon,'sm')}${cnt[t]} ${cnt[t] === 1 ? WN_TYPES[t].one : WN_TYPES[t].many}</span>`).join('')}</div>
      ${full ? `<div class="wn2-gs">${groups}</div>` : `<button class="wn2-more" data-act="wnOpen" data-v="${esc(v.version)}" aria-expanded="false">${ico('chevron-down','sm')}Show all ${v.changes.length} changes</button>`}
    </div></article>`; }).join('');
}
function wnRepaint(){ const t = $('wnTl'), n = $('wnNav'); if(t) t.innerHTML = wnTimeline(); if(n) n.innerHTML = wnNav();
  document.querySelectorAll('.wn2-f').forEach(b => b.setAttribute('aria-pressed', (UI.wnType || '') === b.dataset.v)); }
function bindWhatsNew(){
  const i = $('wnQ'); if(i) i.oninput = () => { UI.wnQ = i.value; clearTimeout(bindWhatsNew.t); bindWhatsNew.t = setTimeout(wnRepaint, 120); };
}
const WN_ACTS = {
  wnType:(id, v) => { UI.wnType = v || null; wnRepaint(); },
  wnClear:() => { UI.wnQ = ''; UI.wnType = null; const q = $('wnQ'); if(q) q.value = ''; wnRepaint(); },
  wnOpen:(id, v) => { (UI.wnOpen || (UI.wnOpen = new Set())).add(v); wnRepaint(); },
  wnJump:(id, v, t, ev) => { if(ev) ev.preventDefault(); if(!$('v' + v)){ UI.wnQ = ''; UI.wnType = null; const q = $('wnQ'); if(q) q.value = ''; wnRepaint(); }
    (UI.wnOpen || (UI.wnOpen = new Set())).add(v); wnRepaint(); const el = $('v' + v), sc = $('wnScroll');
    if(el && sc) sc.scrollTo({top:sc.scrollTop + el.getBoundingClientRect().top - sc.getBoundingClientRect().top - 16, behavior:'smooth'}); }
};
