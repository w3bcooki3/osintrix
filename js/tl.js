/* ==========================================================================
   Timeline extras — activity heatmap (day × hour) and multi-select bulk actions
   ========================================================================== */
const hourOf = ts => +E.fmtClock(ts, tz()).slice(0, 2);
const WD = ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'];
function wdOf(ts){ const d = new Date(new Date(ts).toLocaleString('en-US', {timeZone:tz()})); return (d.getDay() + 6) % 7; }
function slotPass(r){ const s = UI.facet.slot; if(!s) return true; if(!r.ts) return false;
  if(hourOf(r.ts) !== s.h) return false; return s.day != null ? E.fmtDay(r.ts, tz()) === s.day : wdOf(r.ts) === s.wd; }
function heatHTML(D){
  const timed = D.recs.filter(r => r.ts); if(timed.length < 2) return `<div class="heat"><p class="t3" style="margin:0">The heatmap needs at least two timed records.</p></div>`;
  const days = [...new Set(timed.map(r => E.fmtDay(r.ts, tz())))], byWeek = days.length > 14;
  const rows = byWeek ? WD.map((l, i) => ({l, key:i})) : days.map(d => ({l:d, key:d}));
  const M = new Map(); let mx = 1, mal = new Set();
  for(const r of timed){ const k = (byWeek ? wdOf(r.ts) : E.fmtDay(r.ts, tz())) + '|' + hourOf(r.ts); M.set(k, (M.get(k) || 0) + 1); mx = Math.max(mx, M.get(k));
    if(r.ents.some(e => verdictOf(entKey(e)) === 'malicious')) mal.add(k); }
  const s = UI.facet.slot, on = (key, h) => s && s.h === h && (byWeek ? s.wd === key : s.day === key);
  const hrs = [...Array(24).keys()];
  return `<div class="heat" role="group" aria-label="Activity by ${byWeek ? 'weekday' : 'day'} and hour">
    <div class="hhead"><b>Activity</b><span class="t3">${timed.length} timed records · ${byWeek ? 'by weekday' : days.length + ' day' + (days.length > 1 ? 's' : '')} × hour · ${esc(tz())}</span><span class="sp"></span>
      <span class="hleg"><i style="--a:.15"></i><i style="--a:.45"></i><i style="--a:.8"></i><span>more</span><i class="m"></i><span>malicious</span></span></div>
    <div class="hmgrid" style="--rows:${rows.length}"><span></span>${hrs.map(h => `<span class="hmh">${h % 3 ? '' : String(h).padStart(2, '0')}</span>`).join('')}
    ${rows.map(r => `<span class="hml" title="${esc(r.l)}">${esc(byWeek ? r.l : r.l.replace(/^\w+,?\s*/, '').split(' ').slice(0, 2).join(' '))}</span>${hrs.map(h => { const k = r.key + '|' + h, n = M.get(k) || 0;
      return n ? `<button class="hc${mal.has(k) ? ' m' : ''}" style="--a:${(.15 + .85 * n / mx).toFixed(2)}" data-act="heatCell" data-v="${esc(JSON.stringify(byWeek ? {wd:r.key, h} : {day:r.key, h}))}" aria-pressed="${on(r.key, h)}" title="${esc(r.l)} ${String(h).padStart(2, '0')}:00 — ${n} record${n > 1 ? 's' : ''}"><span class="sr">${n}</span></button>` : `<span class="hc e"></span>`; }).join('')}`).join('')}</div></div>`;
}
/* multi-select */
function evWrap(r, html){ const on = UI.evPick && UI.evPick.has(r.id);
  return `<div class="evw${on ? ' on' : ''}"><label class="evchk" title="Select"><input type="checkbox" data-act="evPick" data-id="${r.id}"${on ? ' checked' : ''} aria-label="Select ${esc(r.title.slice(0, 60))}"><span></span></label>${html}</div>`; }
function evBulkHTML(list){
  const n = UI.evPick ? UI.evPick.size : 0; if(!n) return '';
  return `<div class="tbulk evbulk"><b>${n} selected</b><button class="btn xs ghost" data-act="evAll">Select all ${list.length} shown</button><span style="flex:1"></span>
    <button class="btn xs" data-act="evTag">${ico('tag','sm')}Tag…</button><button class="btn xs" data-act="evKey">${ico('star','sm')}Key evidence</button><button class="btn xs" data-act="evCsv">${ico('download','sm')}CSV</button>
    <button class="btn xs dangerbtn" data-act="evDel">${ico('trash-2','sm')}Delete</button><button class="iconbtn" data-act="evNone" aria-label="Clear selection">${ico('x','sm')}</button></div>`;
}
const csvCell = v => { v = String(v == null ? '' : v); return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; };
function recsCsv(rs){ return ['time,title,type,host,source,tags,entities,body'].concat(rs.map(r => [r.ts ? new Date(r.ts).toISOString() : '', r.title, r.type, r.host, r.source, (r.tags || []).join(' '), r.ents.map(e => e.k + ':' + e.v).join(' '), r.body].map(csvCell).join(','))).join('\n'); }
const TL_ACTS = {
  tlMore:(id, v) => { const cur = UI.tlLim && UI.tlLim.k === v ? UI.tlLim.n : 300; UI.tlLim = {k:v, n:id === 'all' ? 1e9 : cur + 500}; renderMain(); },
  tlHeat:() => { UI.tlHeat = !UI.tlHeat; if(!UI.tlHeat) delete UI.facet.slot; renderMain(); },
  heatCell:(id, v) => { const s = JSON.parse(v), cur = UI.facet.slot; UI.facet.slot = cur && cur.h === s.h && cur.day === s.day && cur.wd === s.wd ? null : s; renderMain(); },
  slotOff:() => { delete UI.facet.slot; renderMain(); },
  evPick:(id, v, t) => { UI.evPick = UI.evPick || new Set(); t.checked ? UI.evPick.add(id) : UI.evPick.delete(id); renderMain(); },
  evAll:() => { UI.evPick = new Set(derive().recs.filter(passes).map(r => r.id)); renderMain(); },
  evNone:() => { UI.evPick = new Set(); UI.tlSel = false; renderMain(); },
  tlSel:() => { UI.tlSel = !UI.tlSel; if(!UI.tlSel) UI.evPick = new Set(); renderMain(); },
  evKey:() => { const rs = DB.records.filter(r => UI.evPick.has(r.id)), all = rs.every(r => r.tags.includes('key-evidence'));
    for(const r of rs){ r.tags = r.tags.filter(x => x !== 'key-evidence'); if(!all) r.tags.push('key-evidence'); } mutate((all ? 'unmarked ' : 'marked ') + rs.length + ' key evidence'); renderAll(); toast(all ? 'Unmarked' : rs.length + ' marked as key evidence'); },
  evTag:() => { openDlg(dhead('Tag ' + UI.evPick.size + ' records') + `<form data-form="evTag"><div class="in"><div class="field" style="margin:0"><label for="evTagIn">Tags, separated by commas</label><input id="evTagIn" required autofocus placeholder="lateral-movement, phase-2"></div>
      <p class="t3" style="font-size:13px;margin:10px 0 0">Prefix a tag with “-” to remove it.</p></div><footer><button class="btn" type="button" data-act="dclose">Cancel</button><button class="btn primary" type="submit">Apply</button></footer></form>`); },
  evCsv:() => { const rs = sortRecs(DB.records.filter(r => UI.evPick.has(r.id))); download(slug(theCase().name) + '-records.csv', recsCsv(rs), 'text/csv'); },
  evDel:() => { const ids = [...UI.evPick]; confirmDlg('Delete ' + ids.length + ' record' + (ids.length > 1 ? 's' : '') + '?', 'They move to the trash for 30 days. You can undo right after.', 'Move to trash', () => delRecord(ids)); }
};
function evTagSubmit(){
  const tags = $('evTagIn').value.split(',').map(s => s.trim().toLowerCase().replace(/\s+/g, '-')).filter(Boolean), rs = DB.records.filter(r => UI.evPick.has(r.id));
  for(const r of rs) for(const t of tags){ if(t[0] === '-') r.tags = r.tags.filter(x => x !== t.slice(1)); else if(!r.tags.includes(t)) r.tags.push(t); }
  closeDlg(); mutate('tagged ' + rs.length + ' records'); renderAll(); toast('Tagged ' + rs.length + ' records');
}
