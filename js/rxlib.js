/* ==========================================================================
   Regex builder — My patterns: save a pattern with its sample lines, fields,
   types and pinned tests, tag it, keep its earlier versions, load it again,
   and move the whole library as one JSON file. Stored in this browser with
   the rest of the workspace (encrypted when the workspace is).
   ========================================================================== */
const RXL_MAX = {items:300, name:80, tags:10, tag:24, text:100000, tests:200, versions:20};
const rxlAgo = at => E.fmtAgo(Math.max(0, Date.now() - at));
const rxlList = () => (DB.rxlib = Array.isArray(DB.rxlib) ? DB.rxlib : []);
/* what is kept of the builder: enough to open it again exactly as it was */
function rxlSnap(){ const S = RX(), C = rxCurrent();
  return {text:S.text.slice(0, RXL_MAX.text), mlOff:!!S.mlOff, fields:S.fields.slice(0, 2000), types:{...S.types}, custom:{...S.custom}, fromStart:!!S.fromStart, manual:S.manual, fmt:S.fmt, tests:(S.tests || []).slice(0, RXL_MAX.tests), src:C.ok ? C.src : (S.manual || '')}; }
function rxlOpen(id, ver){ const it = rxlList().find(x => x.id === id); if(!it) return;
  rxSetText(it.text || ''); const S = RX(); if(it.mlOff && S.ml){ S.mlOff = true; rxApplyMl(); }
  Object.assign(S, {fields:(it.fields || []).filter(f => S.lines[f.line] != null), types:{...(it.types || {})}, custom:{...(it.custom || {})}, fromStart:!!it.fromStart, manual:it.manual ?? null, fmt:Math.min(it.fmt ?? -1, S.fmts.length - 1), tests:(it.tests || []).map(t => ({...t})), opt:null, hist:[], fut:[], lib:id});
  if(ver != null){ const v = (it.versions || [])[ver]; if(v) S.manual = v.src; }
  if(UI.route.area !== 'regex') go('#/regex'); else rxRender();
  toast(ver != null ? `Opened ${it.name} as it was ${rxlAgo(it.versions[ver].at)}` : `Opened ${it.name}`); }
function rxlSaveDlg(){ const S = RX(), C = rxCurrent(); if(!C.ok) return toast('Build a pattern first');
  const cur = S.lib && rxlList().find(x => x.id === S.lib);
  openDlg(dhead(cur ? 'Save pattern' : 'Save to My patterns') + `<form data-form="rxlSave"><div class="in">
    ${cur ? `<div class="seg" role="group" aria-label="Save as"><button type="button" data-act="rxlMode" data-v="update" aria-pressed="true">Update “${esc(cur.name)}”</button><button type="button" data-act="rxlMode" data-v="new" aria-pressed="false">Save as a new pattern</button></div><input type="hidden" id="rxlMode" value="update">` : '<input type="hidden" id="rxlMode" value="new">'}
    <div class="field"><label for="rxlName">Name</label><input id="rxlName" value="${esc(cur ? cur.name : (rxView().F ? rxView().F.name + ' — ' : '') + 'my pattern')}" maxlength="${RXL_MAX.name}" required autocomplete="off"></div>
    <div class="field"><label for="rxlTags">Tags <span class="t3">separated by commas</span></label><input id="rxlTags" value="${esc(cur ? (cur.tags || []).join(', ') : '')}" maxlength="240" placeholder="ssh, linux, auth" autocomplete="off"></div>
    <p class="t3 small" style="margin:0">Kept with it: the ${S.lines.length.toLocaleString()} sample ${S.lines.length === 1 ? 'line' : 'lines'}${S.text.length > RXL_MAX.text ? ' (the first 100,000 characters)' : ''}, the fields and their types, and ${(S.tests || []).length} pinned ${(S.tests || []).length === 1 ? 'test' : 'tests'}. Stored in this browser only.</p></div>
    <footer><button class="btn" type="button" data-act="dclose">Cancel</button><button class="btn primary" type="submit">${ico('save','sm')}Save</button></footer></form>`); }
function rxlSaveSubmit(){ const S = RX(), name = ($('rxlName').value || '').trim().slice(0, RXL_MAX.name), mode = $('rxlMode').value;
  if(!name) return fieldErr('rxlName', 'Give it a name.');
  const tags = [...new Set(($('rxlTags').value || '').split(',').map(t => t.trim().toLowerCase().slice(0, RXL_MAX.tag)).filter(Boolean))].slice(0, RXL_MAX.tags), snap = rxlSnap(), L = rxlList();
  let it = mode === 'update' && S.lib && L.find(x => x.id === S.lib);
  if(it){ if(it.src !== snap.src) it.versions = [{src:it.src, at:it.updated}].concat(it.versions || []).slice(0, RXL_MAX.versions); Object.assign(it, snap, {name, tags, updated:Date.now()}); }
  else { if(L.length >= RXL_MAX.items) return toast(`My patterns holds up to ${RXL_MAX.items}. Delete some first.`); it = {id:uid('rx'), name, tags, created:Date.now(), updated:Date.now(), versions:[], ...snap}; L.unshift(it); }
  S.lib = it.id; mutate('saved pattern ' + name); closeDlg(); rxRender(); toast(`Saved to My patterns${it.versions.length ? ' · version ' + (it.versions.length + 1) : ''}`); }
/* the library list: on the start screen, and in a dialog from the builder */
function rxlHtml(inDlg){ const L = rxlList(), q = (UI.rxlq || '').toLowerCase().trim(), words = q.split(/\s+/).filter(Boolean);
  const shown = L.filter(x => !words.length || words.every(w => (x.name + ' ' + (x.tags || []).join(' ') + ' ' + x.src).toLowerCase().includes(w)));
  return `<section class="rxl"><div class="rxl-h"><h3>${ico('save','sm')}My patterns <span class="t3">${L.length}</span></h3><span style="flex:1"></span>
      ${L.length > 4 ? `<div class="search-in sm">${ico('search','sm')}<label class="sr" for="rxlq">Search my patterns</label><input id="rxlq" class="inp sm" placeholder="Search name, tag, pattern…" value="${esc(UI.rxlq || '')}" maxlength="120"></div>` : ''}
      <button class="btn sm ghost" data-act="rxlImport">${ico('upload','sm')}Import</button>${L.length ? `<button class="btn sm ghost" data-act="rxlExport">${ico('download','sm')}Export all</button>` : ''}</div>
    ${!L.length ? `<p class="t3 small rxl-empty">Patterns you save from the builder — with their sample lines, fields and tests — appear here. Use <b>Save</b> next to a pattern.</p>`
      : `<ul class="rxl-l">${shown.map(x => { const tf = x.tests && x.tests.length ? rxTestRun(x.src, x.tests.filter(t => t.fmt === x.fmt)).filter(r => !r.ok).length : 0;
          return `<li><button class="rxl-o" data-act="rxlOpen" data-v="${x.id}"><b>${esc(x.name)}</b><code class="mono">${esc(x.src.length > 120 ? x.src.slice(0, 118) + '…' : x.src)}</code>
            <span class="rxl-m">${(x.tags || []).map(t => `<span class="chip sq">${esc(t)}</span>`).join('')}<span class="t3">${x.tests && x.tests.length ? `${ico(tf ? 'triangle-alert' : 'flask-conical','sm')}${x.tests.length} test${x.tests.length === 1 ? '' : 's'}${tf ? ' · ' + tf + ' failing' : ''} · ` : ''}${x.versions && x.versions.length ? 'version ' + (x.versions.length + 1) + ' · ' : ''}saved ${esc(rxlAgo(x.updated))}</span></span></button>
            <button class="iconbtn sm" data-act="rxlMore" data-v="${x.id}" aria-label="More for ${esc(x.name)}">${ico('ellipsis','sm')}</button></li>`; }).join('') || '<li class="t3 small rxl-empty">Nothing matches.</li>'}</ul>`}</section>`; }
function rxlVersionsDlg(id){ const it = rxlList().find(x => x.id === id); if(!it) return;
  const all = [{src:it.src, at:it.updated, now:true}].concat(it.versions || []);
  openDlg(dhead('Versions of ' + esc(it.name)), true, null);
  $('dlg').insertAdjacentHTML('beforeend', `<div class="in"><ol class="rxl-v">${all.map((v, i) => `<li><div class="rxl-vh"><b>${v.now ? 'Current' : 'Version ' + (all.length - i)}</b><span class="t3 small">${esc(rxlAgo(v.at))}</span><span style="flex:1"></span>${v.now ? '' : `<button class="btn xs" data-act="rxlVerOpen" data-id="${id}" data-v="${i - 1}">Open this version</button>`}</div>
      ${i < all.length - 1 ? `<code class="mono rx-diff">${rxDiff(all[i + 1].src, v.src)}</code>` : `<code class="mono rx-diff">${esc(v.src)}</code>`}</li>`).join('')}</ol></div><footer><button class="btn" data-act="dclose">Close</button></footer>`); }
function rxlImportText(t){ let d; try{ d = JSON.parse(t); }catch(e){ return toast('That is not a My patterns file'); }
  const arr = Array.isArray(d) ? d : d && Array.isArray(d.patterns) ? d.patterns : null; if(!arr) return toast('That is not a My patterns file');
  const L = rxlList(), ids = new Set(L.map(x => x.id)); let n = 0;
  for(const raw of arr.slice(0, RXL_MAX.items)){ const x = rxlClean(raw); if(!x) continue; if(ids.has(x.id)) x.id = uid('rx'); if(L.length >= RXL_MAX.items) break; L.push(x); ids.add(x.id); n++; }
  if(!n) return toast('No patterns found in that file'); mutate('imported ' + n + ' patterns'); renderMain(); toast(`Imported ${n} pattern${n === 1 ? '' : 's'}`); }
/* one saved pattern, checked and cut to size (used on import and when the workspace loads) */
function rxlClean(x){ if(!x || typeof x !== 'object' || typeof x.name !== 'string' || typeof x.src !== 'string') return null; const s = (v, n) => String(v ?? '').slice(0, n);
  try{ new RegExp(x.src); }catch(e){ return null; }
  const num = v => typeof v === 'number' && isFinite(v) ? v : Date.now();
  return {id:typeof x.id === 'string' && /^[\w-]{1,40}$/.test(x.id) ? x.id : uid('rx'), name:s(x.name, RXL_MAX.name).trim() || 'pattern', tags:(Array.isArray(x.tags) ? x.tags : []).map(t => s(t, RXL_MAX.tag)).filter(Boolean).slice(0, RXL_MAX.tags),
    src:s(x.src, 20000), text:s(x.text, RXL_MAX.text), mlOff:!!x.mlOff, fromStart:!!x.fromStart, manual:typeof x.manual === 'string' ? s(x.manual, 20000) : null, fmt:Number.isInteger(x.fmt) ? x.fmt : -1,
    fields:(Array.isArray(x.fields) ? x.fields : []).filter(f => f && Number.isInteger(f.line) && Number.isInteger(f.s) && Number.isInteger(f.e) && f.e > f.s && /^[A-Za-z_]\w{0,31}$/.test(f.name)).slice(0, 2000).map(f => ({line:f.line, s:f.s, e:f.e, name:f.name})),
    types:x.types && typeof x.types === 'object' ? Object.fromEntries(Object.entries(x.types).filter(([k, v]) => /^\w{1,32}$/.test(k) && typeof v === 'string').slice(0, 100).map(([k, v]) => [k, s(v, 20)])) : {},
    custom:x.custom && typeof x.custom === 'object' ? Object.fromEntries(Object.entries(x.custom).filter(([k, v]) => /^\w{1,32}$/.test(k) && typeof v === 'string').slice(0, 100).map(([k, v]) => [k, s(v, 2000)])) : {},
    tests:(Array.isArray(x.tests) ? x.tests : []).filter(t => t && typeof t.text === 'string').slice(0, RXL_MAX.tests).map(t => ({text:s(t.text, 20000), want:t.want === 'none' ? 'none' : 'match', expect:t.expect && typeof t.expect === 'object' ? Object.fromEntries(Object.entries(t.expect).slice(0, 60).map(([k, v]) => [s(k, 32), s(v, 2000)])) : null, fmt:Number.isInteger(t.fmt) ? t.fmt : -1})),
    versions:(Array.isArray(x.versions) ? x.versions : []).filter(v => v && typeof v.src === 'string').slice(0, RXL_MAX.versions).map(v => ({src:s(v.src, 20000), at:num(v.at)})),
    created:num(x.created), updated:num(x.updated)}; }
const RXL_ACTS = {
  rxlSave:() => rxlSaveDlg(),
  rxlMode:(id, v, t) => { $('rxlMode').value = v; t.parentElement.querySelectorAll('button').forEach(b => b.setAttribute('aria-pressed', b === t)); if(v === 'new'){ const n = $('rxlName'); n.value = n.value + ' (copy)'; } },
  rxlOpen:(id, v) => { closeDlg(); rxlOpen(v); },
  rxlLib:() => { openDlg(dhead('My patterns') + `<div class="in">${rxlHtml(true)}</div><footer><button class="btn" data-act="dclose">Close</button></footer>`, true); },
  rxlMore:(id, v, t) => { const it = rxlList().find(x => x.id === v); if(!it) return; const r = t.getBoundingClientRect();
    showMenu(r.left, r.bottom + 6, [{label:'Open', icon:'folder-open', fn:() => { closeDlg(); rxlOpen(v); }}, {label:'Versions' + (it.versions && it.versions.length ? ' (' + (it.versions.length + 1) + ')' : ''), icon:'history', fn:() => rxlVersionsDlg(v), disabled:!(it.versions && it.versions.length)},
      {label:'Copy the pattern', icon:'copy', fn:() => copyText(it.src)}, {label:'Export this one', icon:'download', fn:() => download(it.name.replace(/[^\w.-]+/g, '_') + '.osintrix-patterns.json', JSON.stringify({kind:'osintrix-patterns', version:1, patterns:[it]}, null, 2), 'application/json')},
      {sep:true}, {label:'Delete', icon:'trash-2', danger:true, fn:() => { const L = rxlList(), i = L.indexOf(it); if(i < 0) return; L.splice(i, 1); if(typeof trashPut === 'function') trashPut('pattern', it.name, {p:it}); mutate('deleted pattern ' + it.name); if(RX().lib === v) RX().lib = null; renderMain(); toast('Deleted ' + it.name); }}], it.name); },
  rxlVerOpen:(id, v, t) => { closeDlg(); rxlOpen(t.dataset.id, +v); },
  rxlExport:() => download('osintrix-patterns.json', JSON.stringify({kind:'osintrix-patterns', version:1, exported:new Date().toISOString(), patterns:rxlList()}, null, 2), 'application/json'),
  rxlImport:() => pickFile('.json,application/json', t => rxlImportText(t))};
