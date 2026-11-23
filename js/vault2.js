/* ==========================================================================
   A big vault, workable: filter by verdict, type, tag and a few useful
   states (not linked, in other cases, watched, open questions, no records),
   sort the cards as well as the list, draw only the first few hundred with
   "show more", and select many entries — click, Shift+click for a range,
   or everything shown — to set priority or verdict, tag, star, watch or
   delete them at once. Every bulk change can be undone.
   ========================================================================== */
const VB_LIM = {cards:150, list:400};
const VB_ONLY = [['', 'Show everything'], ['nolinks', 'Not linked to anything'], ['other', 'Also in other cases'], ['watched', 'Watched'], ['open', 'With open questions'], ['norecs', 'Not seen in any record'], ['notes', 'With notes'], ['flagged', 'Look-alikes and other warnings']];
const VB_SORT = [['prio', 'Priority'], ['new', 'Newest first'], ['old', 'Oldest first'], ['recs', 'Most records'], ['last', 'Last seen'], ['value', 'Value A–Z'], ['type', 'Type']];
const VB_VD = [['', 'Any verdict'], ['malicious', 'Malicious'], ['suspicious', 'Suspicious'], ['none', 'No verdict'], ['benign', 'Benign']];
/* the filters belong to one case; switching case starts clean */
function vbF(cid){ if(!UI.vf || UI.vf.cid !== cid){ UI.vf = {cid, vd:'', type:'', tag:'', only:'', sort:'prio'}; UI.vPick = new Set(); UI.vLim = null; } return UI.vf; }
const vbActive = F => !!(F.vd || F.type || F.tag || F.only);
function vbFilter(list, F){
  return list.filter(e => { if(F.type && e.type !== F.type) return false; if(F.tag && !e.tags.includes(F.tag)) return false;
    if(F.vd){ const v = entryVerdict(e); if(F.vd === 'none' ? v && v !== 'unknown' : v !== F.vd) return false; }
    if(F.only){ const X = entryCtx(e);
      if(F.only === 'nolinks' && X.links.length) return false; if(F.only === 'other' && !X.other.length) return false; if(F.only === 'watched' && !X.watched) return false;
      if(F.only === 'open' && !X.open) return false; if(F.only === 'norecs' && X.recs.length) return false; if(F.only === 'notes' && !(e.notes || '').trim()) return false; if(F.only === 'flagged' && !(typeof ipfEntryFlag === 'function' && ipfEntryFlag(e, true))) return false; }
    return true; });
}
function vbSort(list, how){
  const prio = {critical:0, high:1, medium:2, low:3}, S = list.slice();
  const by = {prio:(a, b) => (b.starred - a.starred) || prio[a.priority] - prio[b.priority] || (b.created || 0) - (a.created || 0),
    new:(a, b) => (b.created || 0) - (a.created || 0), old:(a, b) => (a.created || 0) - (b.created || 0),
    recs:(a, b) => entryCtx(b).recs.length - entryCtx(a).recs.length, last:(a, b) => (entryCtx(b).last || 0) - (entryCtx(a).last || 0),
    value:(a, b) => primary(a).localeCompare(primary(b), undefined, {numeric:true, sensitivity:'base'}), type:(a, b) => TYPES[a.type].label.localeCompare(TYPES[b.type].label) || primary(a).localeCompare(primary(b))}[how] || null;
  return by ? S.sort(by) : S;
}
/* the filter row under the toolbar */
function vbBar(all, F){
  const vdN = k => all.filter(e => { const v = entryVerdict(e); return k === 'none' ? !v || v === 'unknown' : v === k; }).length;
  const types = countBy(all, e => e.type), tags = countBy(all.flatMap(e => e.tags), t => t);
  const sel = (id, label, cur, opts) => `<label class="sr" for="${id}">${label}</label><select id="${id}" class="gsel bord vb-s${cur && id !== 'vb-Sort' ? ' on' : ''}" data-vbf="${id.slice(3).toLowerCase()}">${opts.map(([v, l]) => `<option value="${esc(v)}"${cur === v ? ' selected' : ''}>${esc(l)}</option>`).join('')}</select>`;
  return `<div class="vb-bar" role="group" aria-label="Filter the vault">
    ${sel('vb-Vd', 'Verdict', F.vd, VB_VD.map(([v, l]) => [v, v ? `${l} (${vdN(v)})` : l]))}
    ${sel('vb-Type', 'Type', F.type, [['', 'Every type']].concat(types.map(([t, n]) => [t, `${TYPES[t] ? TYPES[t].label : t} (${n})`])))}
    ${tags.length ? sel('vb-Tag', 'Tag', F.tag, [['', 'Any tag']].concat(tags.slice(0, 200).map(([t, n]) => [t, `#${t} (${n})`]))) : ''}
    ${sel('vb-Only', 'Show', F.only, VB_ONLY)}
    ${vbActive(F) ? `<button class="btn xs ghost" data-act="vbClear" title="Clear every filter">${ico('x','sm')}Clear</button>` : ''}
    <span class="sp"></span>${vbActive(F) || UI.vq || F.sort !== 'prio' || (UI.vcat && UI.vcat !== 'all') ? `<button class="btn xs ghost" data-act="svSave" data-v="vault" title="Name this view to come back to it">${ico('bookmark','sm')}Save view</button>` : ''}${sel('vb-Sort', 'Sort by', F.sort, VB_SORT.map(([v, l]) => [v, 'Sort: ' + l]))}</div>`;
}
/* the bulk bar while entries are picked */
function vbBulk(shown){
  const P = UI.vPick, n = P ? P.size : 0; if(!n) return '';
  const all = shown.length && shown.every(e => P.has(e.id));
  return `<div class="tbulk vb-bulk" role="toolbar" aria-label="${n} selected"><b>${n.toLocaleString()} selected</b>${all ? '' : `<button class="btn xs ghost" data-act="vbAll">Select all ${shown.length.toLocaleString()} shown</button>`}<span class="sp"></span>
    <button class="btn xs" data-act="vbPrio">${ico('flag','sm')}Priority</button><button class="btn xs" data-act="vbVerdict">${ico('shield','sm')}Verdict</button><button class="btn xs" data-act="vbTag">${ico('tag','sm')}Tag…</button>
    <button class="btn xs" data-act="vbStar">${ico('star','sm')}Star</button><button class="btn xs" data-act="vbWatch">${ico('eye','sm')}Watch</button><button class="btn xs" data-act="vbCsv">${ico('download','sm')}CSV</button>
    <button class="btn xs dangerbtn" data-act="vbDel">${ico('trash-2','sm')}Delete</button><button class="iconbtn" data-act="vbNone" aria-label="Clear the selection" title="Clear the selection (Esc)">${ico('x','sm')}</button></div>`;
}
const vbPickBtn = e => { const on = UI.vPick && UI.vPick.has(e.id); return `<button class="vb-pk${on ? ' on' : ''}" role="checkbox" aria-checked="${!!on}" data-act="vbPick" data-id="${e.id}" aria-label="Select ${esc(primary(e))}">${on ? ico('check','sm') : ''}</button>`; };
/* change many entries, with one undo */
function vbChange(label, fn){
  const ids = [...(UI.vPick || [])], es = ids.map(entryById).filter(Boolean); if(!es.length) return;
  const before = es.map(e => [e, JSON.stringify(e)]), vd = JSON.stringify(DB.verdicts), wl = JSON.stringify(DB.watch || null);
  const n = fn(es); if(n === false) return;
  mutate(label + ' on ' + es.length + ' entries'); renderAll();
  toast(`${label[0].toUpperCase() + label.slice(1)} — ${es.length.toLocaleString()} ${es.length === 1 ? 'entry' : 'entries'}`, 'Undo', () => {
    for(const [e, j] of before) Object.assign(e, JSON.parse(j)); DB.verdicts = JSON.parse(vd); const w = JSON.parse(wl); if(w) DB.watch = w; else delete DB.watch;
    mutate('undid ' + label); renderAll(); });
}
/* the list shown right now, in its order (for ranges and "select all") */
const VB_ACTS = {
  vbClear:() => { UI.svOn = null; const F = vbF(DB.active); F.vd = F.type = F.tag = F.only = ''; UI.vq = ''; UI.vLim = null; renderMain(); },
  vbJumpAuto:() => { const a = $('vAuto'); if(a){ a.scrollIntoView({behavior:'smooth', block:'start'}); const b = a.parentElement.querySelector('#vAuto ~ .egrid button, #vAuto ~ * button'); if(b) b.focus({preventScroll:true}); } },
  vbMore:(id, v) => { UI.vLim = (UI.vLim || 0) + (v === 'all' ? 1e9 : 1) ; renderMain(); },
  vbPick:(id, v, t, ev) => { const P = UI.vPick || (UI.vPick = new Set()), list = UI.vShown || [];
    if(ev && ev.shiftKey && UI.vLast && list.includes(UI.vLast) && list.includes(id)){ const a = list.indexOf(UI.vLast), b = list.indexOf(id), on = !P.has(id); for(const x of list.slice(Math.min(a, b), Math.max(a, b) + 1)) on ? P.add(x) : P.delete(x); }
    else if(P.has(id)) P.delete(id); else P.add(id);
    UI.vLast = id; renderMain(); const b = document.querySelector(`.vb-pk[data-id="${CSS.escape(id)}"]`); if(b) b.focus({preventScroll:true}); },
  vbAll:() => { UI.vPick = new Set(UI.vShown || []); renderMain(); },
  vbNone:() => { UI.vPick = new Set(); renderMain(); },
  vbPrio:(id, v, t) => { const r = t.getBoundingClientRect();
    showMenu(r.left, r.bottom + 6, ['critical', 'high', 'medium', 'low'].map(p => ({label:p[0].toUpperCase() + p.slice(1), icon:'flag', fn:() => vbChange('priority ' + p, es => { for(const e of es) e.priority = p; })})), 'Set priority'); },
  vbVerdict:(id, v, t) => { const r = t.getBoundingClientRect();
    showMenu(r.left, r.bottom + 6, [['malicious', 'shield-alert'], ['suspicious', 'shield'], ['benign', 'shield-check'], ['', 'x']].map(([k, i]) => ({label:k ? k[0].toUpperCase() + k.slice(1) : 'Clear the verdict', icon:i, fn:() => vbChange(k ? 'marked ' + k : 'cleared the verdict', es => { for(const e of es) setEntryVerdict(e, k); })})), 'Set verdict'); },
  vbTag:() => { const n = UI.vPick ? UI.vPick.size : 0; if(!n) return;
    openDlg(dhead(`Tag ${n.toLocaleString()} ${n === 1 ? 'entry' : 'entries'}`) + `<form data-form="vbTag"><div class="in"><div class="field"><label for="vbTagIn">Tags</label><input id="vbTagIn" autofocus placeholder="phishing, wave-2" autocomplete="off"><span class="hint">Separate with commas. Start one with − to take it off instead: <span class="mono">-todo</span></span></div></div>
      <footer><button class="btn" type="button" data-act="dclose">Cancel</button><button class="btn primary" type="submit">Apply</button></footer></form>`); $('dlg').classList.add('narrow'); },
  vbStar:() => { const es = [...UI.vPick].map(entryById).filter(Boolean), on = !es.every(e => e.starred); vbChange(on ? 'starred' : 'unstarred', es => { for(const e of es) e.starred = on; }); },
  vbWatch:() => { const es = [...UI.vPick].map(entryById).filter(Boolean), keys = es.map(entryKey).filter(Boolean);
    if(!keys.length) return toast('None of these can be watched — watching works on IPs, domains, emails, handles, hashes and wallets');
    const on = !keys.every(k => isWatched(k)); vbChange(on ? 'watched' : 'stopped watching', () => { DB.watch = DB.watch || {}; for(const k of keys){ if(on && !DB.watch[k]) DB.watch[k] = {at:Date.now()}; if(!on) delete DB.watch[k]; } });
    if(keys.length < es.length) toast(`${keys.length} watched — the other ${es.length - keys.length} are names or notes, which cannot be watched`); },
  vbCsv:() => { const es = [...UI.vPick].map(entryById).filter(Boolean), cell = csvCell;
    download(slug(caseNm(theCase())) + '-entries.csv', [['type', 'value', 'verdict', 'priority', 'starred', 'tags', 'records', 'links', 'notes', 'fields'].join(',')].concat(es.map(e => { const X = entryCtx(e);
      return [TYPES[e.type].label, primary(e), entryVerdict(e), e.priority, e.starred ? 'yes' : '', e.tags.join(' '), X.recs.length, X.links.length, e.notes, Object.entries(e.fields).map(([k, v]) => k + '=' + v).join('; ')].map(cell).join(','); })).join('\r\n'), 'text/csv'); },
  vbDel:() => { const es = [...UI.vPick].map(entryById).filter(Boolean); if(!es.length) return;
    confirmDlg(`Delete ${es.length.toLocaleString()} ${es.length === 1 ? 'entry' : 'entries'}?`, `They go to the trash with their ${(() => { const s = new Set(es.map(e => e.id)); return DB.links.filter(l => s.has(l.a) || s.has(l.b)).length; })()} relationships, and can be restored from there for 30 days — or undone right after.`, 'Delete', () => {
      const ids = new Set(es.map(e => e.id)), gone = DB.links.filter(l => ids.has(l.a) || ids.has(l.b)), txs = [];
      for(const e of es){ const ls = gone.filter(l => l.a === e.id || l.b === e.id); txs.push(trashPut('entry', primary(e), {e, links:ls}, e.caseId)); }
      DB.entries = DB.entries.filter(e => !ids.has(e.id)); DB.links = DB.links.filter(l => !gone.includes(l)); if(UI.sel && ids.has(UI.sel.id)) UI.sel = null; UI.vPick = new Set();
      mutate('deleted ' + es.length + ' entries'); renderAll();
      toast(`Deleted ${es.length.toLocaleString()} ${es.length === 1 ? 'entry' : 'entries'} — they are in the trash`, 'Undo', () => { DB.trash = DB.trash.filter(t => !txs.includes(t)); DB.entries.push(...es); DB.links.push(...gone); mutate('restored ' + es.length + ' entries'); renderAll(); }); }); },
};
function vbTagSubmit(){
  const raw = ($('vbTagIn').value || '').split(',').map(s => s.trim().replace(/^#/, '')).filter(Boolean), add = raw.filter(t => !/^[-−]/.test(t)).map(t => t.slice(0, 40)), rm = raw.filter(t => /^[-−]/.test(t)).map(t => t.slice(1).trim().replace(/^#/, ''));
  if(!add.length && !rm.length) return fieldErr('vbTagIn', 'Write a tag.');
  closeDlg(); vbChange(add.length ? 'tagged ' + add.map(t => '#' + t).join(' ') : 'took off ' + rm.map(t => '#' + t).join(' '), es => { for(const e of es){ e.tags = [...new Set(e.tags.filter(t => !rm.includes(t)).concat(add))].slice(0, 30); } });
}
/* the filter selects, and Esc to drop the selection */
function bindVaultBar(){
  document.querySelectorAll('[data-vbf]').forEach(s => s.onchange = () => { UI.svOn = null; const F = vbF(DB.active); F[s.dataset.vbf] = s.value; UI.vLim = null; renderMain(); const n = $(s.id); if(n) n.focus(); });
}
document.addEventListener('keydown', ev => { if(ev.key === 'Escape' && UI.vPick && UI.vPick.size && /\/vault$/.test(location.hash) && $('scrim').hidden && !document.querySelector('#ctx') && !ev.target.closest('input, textarea, select')){ UI.vPick = new Set(); renderMain(); } });
