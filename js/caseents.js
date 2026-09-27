/* ==========================================================================
   Entities inside one case — every indicator extracted from this case's
   evidence plus everything in its vault, with bulk verdicts and export.
   ========================================================================== */
const CE_SKIP = new Set(['eventid']);
function caseEntList(caseId){
  const D = derive(caseId), g = globalEnts(), m = new Map();
  for(const [id, x] of D.ents){ if(CE_SKIP.has(x.k)) continue; const ts = x.recs.map(r => r.ts).filter(Boolean);
    m.set(id, {id, k:x.k, v:x.v, recs:x.recs, first:ts.length ? Math.min(...ts) : null, last:ts.length ? Math.max(...ts) : null, entry:D.byKey.get(id) || null}); }
  for(const [id, e] of D.byKey) if(!m.has(id)){ const {k, v} = entSplit(id); m.set(id, {id, k, v, recs:[], first:null, last:null, entry:e}); }
  for(const x of m.values()){ const ge = g.get(x.id); x.others = ge ? [...ge.cases].filter(cid => cid !== caseId && theCase(cid)) : []; x.verdict = verdictOf(x.id); }
  return [...m.values()];
}
const CE_V = [['','All'],['malicious','Malicious'],['suspicious','Suspicious'],['unknown','No verdict'],['benign','Benign']];
function caseEntities(c, D){
  const all = caseEntList(c.id), F = UI.ce || (UI.ce = {q:'', kind:'', v:'', cross:false, novault:false, pick:new Set()});
  const q = F.q.toLowerCase();
  const list = all.filter(x => (!F.kind || x.k === F.kind) && (!F.v || (F.v === 'unknown' ? !x.verdict : x.verdict === F.v)) && (!F.cross || x.others.length) && (!F.novault || !x.entry) && (!q || (x.v + ' ' + (E.LABEL[x.k] || x.k)).toLowerCase().includes(q)))
    .sort((a, b) => ({malicious:0, suspicious:1, '':2, benign:3}[a.verdict] - {malicious:0, suspicious:1, '':2, benign:3}[b.verdict]) || b.others.length - a.others.length || b.recs.length - a.recs.length || a.v.localeCompare(b.v));
  UI.ceList = list.map(x => x.id); for(const id of [...F.pick]) if(!all.some(x => x.id === id)) F.pick.delete(id);
  const kinds = countBy(all, x => x.k), n = F.pick.size;
  const mal = all.filter(x => x.verdict === 'malicious').length, cross = all.filter(x => x.others.length).length, nov = all.filter(x => !x.entry && KIND_TO_TYPE[x.k]).length;
  const when = t => t ? `<span class="mono">${esc(E.fmtFull(t, tz()).slice(5, 16))}</span>` : '<span class="t3">—</span>';
  return `<div class="scroll"><div class="page">
    <div class="ce-stats"><div><b>${all.length}</b><span>entities in this case</span></div><div><b style="color:var(--red)">${mal}</b><span>malicious</span></div>
      <div><b style="color:var(--accent)">${cross}</b><span>also in other cases</span></div><div><b>${nov}</b><span>not in the vault yet</span></div></div>
    <div class="toolbar ce-tb"><div class="search-in">${ico('search')}<label class="sr" for="ceq">Search this case's entities</label><input id="ceq" class="inp" placeholder="Search values…" value="${esc(F.q)}" autocomplete="off"></div>
      <label class="sr" for="ceKind">Kind</label><select id="ceKind" class="gsel bord"><option value="">All kinds</option>${kinds.map(([k, cnt]) => `<option value="${esc(k)}"${F.kind === k ? ' selected' : ''}>${esc(E.LABEL[k] || k)} (${cnt})</option>`).join('')}</select>
      <div class="seg" role="group" aria-label="Verdict">${CE_V.map(([v, l]) => `<button data-act="ceV" data-v="${v}" aria-pressed="${F.v === v}">${l}</button>`).join('')}</div>
      <button class="chip" data-act="ceCross" aria-pressed="${F.cross}">${ico('link-2','sm')}In other cases</button><button class="chip" data-act="ceNoVault" aria-pressed="${F.novault}">Not in vault</button>
      <span class="sp"></span><button class="btn sm" data-act="ceCsv">${ico('download','sm')}CSV</button></div>
    ${n ? `<div class="tbulk"><b>${n} selected</b><button class="btn xs ghost" data-act="ceAll">Select all ${list.length} shown</button><span style="flex:1"></span>
      <span class="t3" style="font-size:13px">Verdict:</span>${[['malicious','Malicious'],['suspicious','Suspicious'],['benign','Benign'],['','Clear']].map(([v, l]) => `<button class="btn xs" data-act="ceSetV" data-v="${v}">${l}</button>`).join('')}
      <button class="btn xs" data-act="ceVault">${ico('plus','sm')}Add to vault &amp; graph</button><button class="btn xs" data-act="ceWatch">${ico('eye','sm')}Watch</button><button class="btn xs" data-act="ceCopy">${ico('copy','sm')}Copy defanged</button><button class="iconbtn" data-act="ceNone" aria-label="Clear selection">${ico('x','sm')}</button></div>` : ''}
    ${list.length ? `<section class="card" style="overflow:hidden"><table class="tbl cardify ce-t"><thead><tr><th class="c-chk"><span class="sr">Select</span></th><th>Entity</th><th>Verdict</th><th class="n">Records</th><th class="hide-m">First seen</th><th class="hide-m">Last seen</th><th class="hide-m">Checked</th><th>Also in</th><th class="hide-m">Vault &amp; graph</th></tr></thead><tbody>
      ${list.slice(0, 400).map(x => `<tr data-act="selEnt" data-id="${esc(x.id)}"${F.pick.has(x.id) ? ' class="on"' : ''}>
        <td class="c-chk"><label class="tc-chk"><span class="sr">Select ${esc(x.v)}</span><input type="checkbox" data-act="cePick" data-id="${esc(x.id)}"${F.pick.has(x.id) ? ' checked' : ''}></label></td>
        <td><div class="ce-e">${kindBadge(x.k,'sm')}<div style="min-width:0"><div class="v mono">${esc(x.v)}</div><div class="t3" style="font-size:12.5px">${esc(E.LABEL[x.k] || x.k)}${isWatched(x.id) ? ` <span class="cxt amber">${ico('eye','sm')}watched</span>` : ''} ${ctxChips(x.k, x.v)}</div></div></div></td>
        <td>${vdLabel(x.verdict) || '<span class="t3">—</span>'}</td><td class="n">${x.recs.length}</td><td class="hide-m">${when(x.first)}</td><td class="hide-m">${when(x.last)}</td>
        <td class="hide-m">${(p => p ? `<span class="rsmini${p.done === p.total ? ' full' : ''}" title="${p.done} of ${p.total} lookups checked"><i style="width:${Math.round(p.done / p.total * 100)}%"></i></span><span class="t3" style="font-size:12px">${p.done}/${p.total}</span>` : '<span class="t3">—</span>')(rsProgress(x.k, x.v))}</td>
        <td>${x.others.length ? `<div class="wrap" style="gap:4px">${x.others.slice(0, 3).map(cid => { const o = theCase(cid); return `<a class="ce-case" href="${caseHash(cid, 'entities')}" style="--cc:${esc(o.color)}" title="${esc(o.name)}">${esc(o.code)}</a>`; }).join('')}${x.others.length > 3 ? `<span class="t3">+${x.others.length - 3}</span>` : ''}</div>` : '<span class="t3">—</span>'}</td>
        <td class="hide-m">${x.entry ? `<span class="chip sq green">${ico('check','sm')}In vault</span>` : KIND_TO_TYPE[x.k] ? `<button class="btn xs" data-act="promote" data-id="${esc(x.id)}" title="Add to the vault and the graph">${ico('plus','sm')}Add</button>` : '<span class="t3">—</span>'}</td></tr>`).join('')}
      </tbody></table>${list.length > 400 ? `<p class="t3" style="padding:12px 16px;margin:0;font-size:13px">Showing 400 of ${list.length}. Narrow with search or filters.</p>` : ''}</section>`
      : empty('fingerprint', all.length ? 'Nothing matches' : 'No entities yet', all.length ? 'Clear a filter or change the search.' : 'Capture evidence or add vault entries — indicators are picked out automatically.', all.length ? `<button class="btn" data-act="ceReset">Clear filters</button>` : `<button class="btn primary" data-act="capture">${ico('plus','sm')}Capture evidence</button>`)}
  </div></div>`;
}
function bindCaseEnts(){
  const q = $('ceq'); let t; if(q) q.oninput = () => { clearTimeout(t); t = setTimeout(() => { UI.ce.q = q.value; renderMain(); const n = $('ceq'); if(n){ n.focus(); n.setSelectionRange(n.value.length, n.value.length); } }, 180); };
  const k = $('ceKind'); if(k) k.onchange = () => { UI.ce.kind = k.value; renderMain(); };
}
const CE_ACTS = {
  ceV:(id, v) => { UI.ce.v = v; renderMain(); },
  ceCross:() => { UI.ce.cross = !UI.ce.cross; renderMain(); },
  ceNoVault:() => { UI.ce.novault = !UI.ce.novault; renderMain(); },
  ceReset:() => { Object.assign(UI.ce, {q:'', kind:'', v:'', cross:false, novault:false}); renderMain(); },
  cePick:(id, v, t) => { t.checked ? UI.ce.pick.add(id) : UI.ce.pick.delete(id); renderMain(); },
  ceAll:() => { UI.ce.pick = new Set(UI.ceList); renderMain(); },
  ceNone:() => { UI.ce.pick = new Set(); renderMain(); },
  ceSetV:(id, v) => { const ids = [...UI.ce.pick], prev = ids.map(i => [i, DB.verdicts[i]]);
    for(const i of ids){ if(v) DB.verdicts[i] = v; else delete DB.verdicts[i]; } mutate((v || 'cleared') + ' verdict on ' + ids.length + ' entities'); renderAll();
    toast(ids.length + ' entit' + (ids.length > 1 ? 'ies' : 'y') + (v ? ' marked ' + v : ' cleared'), 'Undo', () => { for(const [i, o] of prev){ if(o) DB.verdicts[i] = o; else delete DB.verdicts[i]; } mutate('undid verdicts'); renderAll(); }); },
  ceVault:() => { const D = derive(), made = [];
    for(const id of UI.ce.pick){ if(D.byKey.has(id)) continue; const {k, v} = entSplit(id), type = KIND_TO_TYPE[k]; if(!type) continue; const t = TYPES[type], g = D.ents.get(id);
      made.push({id:uid('v'), caseId:DB.active, type, fields:{[t.fields[0][0]]:v}, priority:verdictOf(id) === 'malicious' ? 'high' : 'medium', starred:false, tags:[], notes:'', src:g && g.recs[0] ? g.recs[0].id : '', created:Date.now(), pos:null}); }
    if(!made.length) return toast('Those are already in the vault, or cannot be vault entries');
    DB.entries.push(...made); ensurePositions(); UI.ce.pick = new Set(); mutate('added ' + made.length + ' entries to the vault'); renderAll();
    toast(made.length + ' added to the vault', 'Undo', () => { const s = new Set(made.map(e => e.id)); DB.entries = DB.entries.filter(e => !s.has(e.id)); mutate('undid vault add'); renderAll(); }); },
  ceWatch:() => { DB.watch = DB.watch || {}; let n = 0; for(const id of UI.ce.pick) if(!DB.watch[id]){ DB.watch[id] = {at:Date.now()}; n++; } mutate('watching ' + n + ' entities'); renderAll(); toast(n + ' added to your watchlist'); },
  ceCopy:() => { copyText([...UI.ce.pick].map(id => defang(entSplit(id).v)).join('\n')); },
  ceCsv:() => { const rows = caseEntList(DB.active).filter(x => UI.ceList.includes(x.id)), c = theCase();
    download(slug(c.name) + '-entities.csv', ['kind,value,verdict,records,first_seen,last_seen,in_vault,other_cases'].concat(rows.map(x => [x.k, x.v, x.verdict, x.recs.length, x.first ? new Date(x.first).toISOString() : '', x.last ? new Date(x.last).toISOString() : '', x.entry ? 'yes' : 'no', x.others.map(i => theCase(i).code).join(' ')].map(csvCell).join(','))).join('\n'), 'text/csv'); }
};
