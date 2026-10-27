/* "What's new" — the release history as a designed timeline.
   Reads CHANGELOG_DATA (js/data/changelog.js), the same source CHANGELOG.md is built from. */
const WN_TYPES = {
  added:   {label: 'Added',   icon: 'plus',          cls: 'add'},
  changed: {label: 'Changed', icon: 'arrow-down-up', cls: 'chg'},
  fixed:   {label: 'Fixed',   icon: 'wrench',        cls: 'fix'},
  removed: {label: 'Removed', icon: 'trash-2',       cls: 'rem'}
};
function wnDate(d){
  if(!d) return '';
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(d); if(!m) return esc(d);
  const MON = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  return MON[+m[2] - 1] + ' ' + (+m[3]) + ', ' + m[1];
}
function viewWhatsNew(){
  const data = typeof CHANGELOG_DATA !== 'undefined' ? CHANGELOG_DATA : [];
  const q = (UI.wnQ || '').trim().toLowerCase();
  const tally = {}; data.forEach(v => v.changes.forEach(c => tally[c.type] = (tally[c.type] || 0) + 1));
  const filt = UI.wnType && WN_TYPES[UI.wnType] ? UI.wnType : null;
  const changesOf = v => v.changes.filter(c => (!filt || c.type === filt) && (!q || (c.text + ' ' + v.name + ' ' + v.version + ' ' + v.summary).toLowerCase().includes(q)));
  const chips = [['', 'All', data.reduce((n, v) => n + v.changes.length, 0)]]
    .concat(Object.keys(WN_TYPES).filter(t => tally[t]).map(t => [t, WN_TYPES[t].label, tally[t]]));
  const latest = data[0], searching = !!(filt || q);
  const entry = (v, i) => {
    const changes = changesOf(v);
    if(searching && !changes.length) return '';
    const rows = changes.map(c => { const T = WN_TYPES[c.type] || WN_TYPES.changed;
      return `<li class="wn-c"><span class="wn-t ${T.cls}">${ico(T.icon, 'sm')}${T.label}</span><span class="wn-x">${esc(c.text)}</span></li>`; }).join('');
    return `<article class="wn-v" id="v${esc(v.version)}">
      <div class="wn-rail"><span class="wn-dot${i === 0 ? ' now' : ''}"></span></div>
      <div class="wn-body">
        <header class="wn-h"><span class="wn-tag">v${esc(v.version)}</span><h2>${esc(v.name)}</h2>${i === 0 ? '<span class="wn-latest">Latest</span>' : ''}<span class="wn-sp"></span>${v.date ? `<time class="wn-date">${wnDate(v.date)}</time>` : ''}</header>
        ${v.summary && !searching ? `<p class="wn-sum">${esc(v.summary)}</p>` : ''}
        <ul class="wn-list">${rows}</ul>
      </div></article>`;
  };
  const body = data.map(entry).join('');
  return `<div class="scroll"><div class="wn">
    <header class="wn-head"><div class="wn-head-in">
      <span class="ix">${esc(BRAND.name)} · release history</span>
      <h1>What's new</h1>
      <p>Every change, newest first. ${latest ? "You're on <b>v" + esc(latest.version) + ' — ' + esc(latest.name) + '</b>.' : ''} Everything runs offline in your browser.</p>
      <div class="wn-bar"><div class="wn-chips" role="group" aria-label="Filter by type">${chips.map(([t, l, n]) => `<button data-act="wnType" data-v="${t}" aria-pressed="${(UI.wnType || '') === t}">${l}<small>${n}</small></button>`).join('')}</div>
        <div class="search-in wn-q">${ico('search')}<label class="sr" for="wnQ">Search changes</label><input id="wnQ" class="inp" placeholder="Search the history — cloud, graph, encryption…" value="${esc(UI.wnQ || '')}" autocomplete="off"></div></div>
    </div></header>
    <div class="wn-tl">${body || `<div class="hx2-empty">Nothing matches “${esc(UI.wnQ || '')}”.</div>`}</div>
  </div></div>`;
}
function bindWhatsNew(){
  const i = $('wnQ'); if(i) i.oninput = () => { UI.wnQ = i.value; clearTimeout(bindWhatsNew.t); bindWhatsNew.t = setTimeout(() => { renderMain(); const x = $('wnQ'); if(x){ x.focus(); x.setSelectionRange(x.value.length, x.value.length); } }, 150); };
}
const WN_ACTS = {
  wnType:(id, v) => { UI.wnType = v || null; renderMain(); }
};
