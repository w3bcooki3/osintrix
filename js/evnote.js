/* ==========================================================================
   A note from selected events (Timeline → Select → Write a note).
   Writes a short summary in plain words — how many events, which hosts, the
   time span, what stands out (what the evidence reader recognises, the attack
   stages they pass through, indicators you marked malicious) — then the
   chronology, each line ending in a citation [n] that opens that event. It is
   an ordinary note: edit it like any other; the citations stay clickable.
   ========================================================================== */
function evNoteDraft(recs){
  const L = recs.filter(r => r && r.type !== 'lead').sort((a, b) => (a.ts || 9e15) - (b.ts || 9e15)).slice(0, 60), c = theCase(L[0] && L[0].caseId) || theCase();
  const timed = L.filter(r => r.ts), hosts = [...new Set(L.map(r => r.host).filter(Boolean))], t1 = timed[0], t2 = timed[timed.length - 1];
  const stages = []; if(typeof tx2Stages === 'function') for(const r of L) for(const s of tx2Stages(r)) if(!stages.includes(s)) stages.push(s);
  const seen = new Map(); for(const r of L){ try{ for(const o of E.observations(r)) if(o && o.t && o.hot !== false) seen.set(o.t, (seen.get(o.t) || 0) + 1); }catch(e){} }
  const bad = new Map(); for(const r of L) for(const e of r.ents || []){ const k = entKey(e), v = verdictOf(k); if(v === 'malicious') bad.set(e.v, v); }
  const P = [];
  P.push(`${L.length} event${L.length > 1 ? 's' : ''}${hosts.length ? ' on ' + (hosts.length <= 3 ? hosts.join(', ') : hosts.length + ' hosts') : ''}${t1 ? `, ${E.fmtFull(t1.ts, tz())}${t2 && t2 !== t1 ? ' to ' + E.fmtFull(t2.ts, tz()) + ' (' + E.fmtGap(t2.ts - t1.ts) + ')' : ''}` : ''}.`);
  if(stages.length) P.push(`They pass through ${stages.join(' → ')}.`);
  const short = v => v.length > 40 ? v.slice(0, 16) + '…' + v.slice(-8) : v;
  if(bad.size) P.push(`Indicators you marked malicious: ${[...bad.keys()].slice(0, 4).map(short).join(', ')}${bad.size > 4 ? ' and ' + (bad.size - 4) + ' more' : ''}.`);
  const obs = [...seen.entries()].sort((a, b) => b[1] - a[1]).slice(0, 4).map(([t, n]) => t.replace(/\.$/, '') + (n > 1 ? ` (${n}×)` : ''));
  const lines = [P.join(' ')];
  if(obs.length) lines.push('', '## What stands out', ...obs.map(o => '- ' + o));
  lines.push('', '## Chronology', ...L.map((r, i) => `- ${r.ts ? E.fmtClock(r.ts, tz()) : 'no time'}${r.host ? ' ' + r.host : ''} — ${String(r.title || 'event').replace(/\s+/g, ' ').slice(0, 120)} [${i + 1}]`));
  if(recs.length > L.length) lines.push('', `(${recs.length - L.length} more selected events are not listed.)`);
  return {caseId:c ? c.id : null, title:`${L.length} event${L.length > 1 ? 's' : ''}${stages.length ? ': ' + stages.slice(0, 3).join(' → ') : hosts.length === 1 ? ' on ' + hosts[0] : ''}`.slice(0, 120), text:lines.join('\n').slice(0, 4000), refs:L.map(r => r.id)};
}
const noteRefs = n => Array.isArray(n && n.refs) ? n.refs.filter(x => typeof x === 'string').slice(0, 500) : [];
/* [n] in a note's text becomes a link to the n-th cited event */
function noteCiteHtml(n, html){ const R = noteRefs(n); if(!R.length) return html;
  return html.replace(/\[(\d{1,3})\]/g, (m, d) => R[d - 1] && recById(R[d - 1]) ? `<button class="ncite" data-act="nCite" data-id="${esc(n.id)}" data-v="${d}" title="Open the cited event">[${d}]</button>` : m); }
const EVN_ACTS = {
  evNote:() => { const ids = [...(UI.evPick || [])], recs = ids.map(recById).filter(r => r && r.type !== 'lead'); if(!recs.length) return toast('Select some events first');
    const d = evNoteDraft(recs), n = {id:uid('n'), caseId:d.caseId, title:d.title, text:d.text, refs:d.refs, color:'blue', pinned:false, due:'', created:Date.now(), updated:Date.now()};
    DB.notes.unshift(n); UI.evPick = new Set(); UI.tlSel = false; mutate('wrote a note from ' + recs.length + ' events'); renderMain();
    toast(`Note written from ${recs.length} event${recs.length > 1 ? 's' : ''}`, 'Open', () => noteDlg(n.id)); },
  nCite:(id, v) => { const n = (DB.notes || []).find(x => x.id === id), rid = noteRefs(n)[+v - 1], r = rid && recById(rid); if(!r) return toast('That event is no longer in the case');
    DB.active = r.caseId; closeDlg(); UI.sel = {kind:'rec', id:r.id}; UI.tlMode = 'events'; UI.q = ''; UI.ast = null; delete UI.facet.ids; go(caseHash(r.caseId, 'timeline')); },
  nCiteAll:id => { const n = (DB.notes || []).find(x => x.id === id), R = noteRefs(n).filter(recById); if(!R.length) return; const r0 = recById(R[0]);
    DB.active = r0.caseId; closeDlg(); UI.tlMode = 'events'; UI.q = ''; UI.ast = null; UI.facet.ids = R; delete UI.facet.idsLabel; go(caseHash(r0.caseId, 'timeline')); },
  idsOff:() => { delete UI.facet.ids; delete UI.facet.idsLabel; renderMain(); },
};
