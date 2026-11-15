/* ==========================================================================
   Duplicates and merging — the same thing entered twice in a vault.
   Entries of the same type are compared on their main value after tidying
   it the way it would be written anyway: letter case, defanged forms
   (hxxp, [.]), a leading @, www. and trailing slashes, spaces and dashes in
   phone numbers, accents and word order in names. Names and handles one
   letter apart are offered too, marked "probably". Merging keeps one entry,
   fills its empty fields from the others, keeps every tag, note and link,
   and can be undone.
   ========================================================================== */
const dupStrip = s => String(s || '').normalize('NFKD').replace(/[̀-ͯ]/g, '');
function dupNorm(e){
  let v = String(primary(e) || '').trim(); if(!v) return '';
  try{ v = E.refang(v); }catch(x){}
  v = v.replace(/\s+/g, ' ');
  switch(e.type){
    case 'crypto': return v.replace(/\s/g, '');                                   // some wallet formats care about case
    case 'phone': { const d = v.replace(/\D/g, ''); return d.slice(-10); }
    case 'domain': return v.toLowerCase().replace(/^[a-z]+:\/\//, '').replace(/^www\./, '').replace(/[/.]+$/, '');
    case 'url': return v.toLowerCase().replace(/^[a-z]+:\/\//, '').replace(/^www\./, '').replace(/\/+$/, '');
    case 'username': case 'social': return v.toLowerCase().replace(/^@/, '').replace(/\/+$/, '');
    case 'person': case 'organization': case 'alias': return dupStrip(v).toLowerCase().replace(/[^\w\s@]/g, ' ').split(/\s+/).filter(Boolean).sort().join(' ');
    default: return v.toLowerCase().replace(/[.\s]+$/, '');
  }
}
function lev1(a, b){ if(Math.abs(a.length - b.length) > 1) return false; let i = 0, j = 0, d = 0; while(i < a.length && j < b.length){ if(a[i] === b[j]){ i++; j++; continue; } if(++d > 1) return false; if(a.length > b.length) i++; else if(b.length > a.length) j++; else { i++; j++; } } return d + (a.length - i) + (b.length - j) <= 1; }
function dupGroups(caseId){
  const L = DB.entries.filter(e => e.caseId === caseId), by = new Map(), out = [], skip = new Set((DB.prefs.notDup || []));
  for(const e of L){ const n = dupNorm(e); if(!n) continue; const k = e.type + '|' + n; if(!by.has(k)) by.set(k, []); by.get(k).push(e); }
  for(const G of by.values()) if(G.length > 1) out.push({sure:true, G});
  /* one letter apart: names and handles only, and not too short to mean anything */
  const loose = [...by.entries()].filter(([k, G]) => G.length === 1 && /^(person|organization|alias|username|social)\|/.test(k) && k.split('|')[1].length >= 6);
  for(let i = 0; i < loose.length; i++) for(let j = i + 1; j < loose.length; j++){ const [ka, A] = loose[i], [kb, B] = loose[j]; if(ka.split('|')[0] !== kb.split('|')[0]) continue; if(lev1(ka.split('|')[1], kb.split('|')[1])) out.push({sure:false, G:[A[0], B[0]]}); }
  return out.map(g => ({...g, sig:g.G.map(e => e.id).sort().join('+')})).filter(g => !skip.has(g.sig));
}
const dupFilled = e => Object.values(e.fields || {}).filter(v => v && String(v).trim()).length + (e.notes ? 1 : 0) + e.tags.length + (e.src ? 1 : 0);
function dupMerge(keepId, ids){
  const keep = entryById(keepId), others = ids.filter(id => id !== keepId).map(entryById).filter(Boolean); if(!keep || !others.length) return;
  const before = {entries:JSON.parse(JSON.stringify(DB.entries)), links:JSON.parse(JSON.stringify(DB.links))};
  const P = {low:0, medium:1, high:2, critical:3}, extra = [];
  for(const o of others){
    for(const [k, v] of Object.entries(o.fields || {})){ if(!v || !String(v).trim()) continue; if(!keep.fields[k] || !String(keep.fields[k]).trim()) keep.fields[k] = v; else if(String(keep.fields[k]).trim().toLowerCase() !== String(v).trim().toLowerCase()) extra.push(`${(TYPES[o.type].fields.find(f => f[0] === k) || [k, k])[1]}: ${v}`); }
    keep.tags = [...new Set([...keep.tags, ...o.tags])]; if(o.notes && !keep.notes.includes(o.notes)) keep.notes = [keep.notes, o.notes].filter(Boolean).join('\n');
    keep.starred = keep.starred || o.starred; if(P[o.priority] > P[keep.priority]) keep.priority = o.priority; if(!keep.src && o.src) keep.src = o.src; if(!keep.pos && o.pos) keep.pos = o.pos;
    for(const l of DB.links){ if(l.a === o.id) l.a = keep.id; if(l.b === o.id) l.b = keep.id; }
  }
  if(extra.length) keep.notes = [keep.notes, 'Also recorded as — ' + [...new Set(extra)].join(' · ')].filter(Boolean).join('\n');
  const gone = new Set(others.map(o => o.id)), seen = new Set();
  DB.entries = DB.entries.filter(e => !gone.has(e.id));
  DB.links = DB.links.filter(l => { if(l.a === l.b) return false; const k = [l.a, l.b].sort().join('|') + '|' + (l.label || ''); if(seen.has(k)) return false; seen.add(k); return true; });
  if(UI.sel && gone.has(UI.sel.id)) UI.sel = {kind:'entry', id:keep.id};
  mutate('merged ' + (others.length + 1) + ' entries into ' + primary(keep)); renderAll();
  toast(`Merged into ${primary(keep)}`, 'Undo', () => { DB.entries = before.entries; DB.links = before.links; mutate('undid a merge'); renderAll(); });
}
function dupDlg(){
  const G = dupGroups(DB.active); if(!G.length){ closeDlg(); return toast('No duplicates in this vault'); }
  const row = (g, e) => { const X = typeof entryCtx === 'function' ? entryCtx(e) : {recs:[], links:[]}, best = g.G.slice().sort((a, b) => dupFilled(b) - dupFilled(a) || (a.created || 0) - (b.created || 0))[0];
    return `<label class="dp-e"><input type="radio" name="dpk-${g.sig}" value="${e.id}" ${e === best ? 'checked' : ''}><div><b class="${MONO_TYPES.has(e.type) ? 'mono' : ''}">${esc(primary(e))}</b>
      <small>${esc(TYPES[e.type].fields.slice(1).filter(([n]) => e.fields[n] && String(e.fields[n]).trim() && e.fields[n] !== '—').slice(0, 3).map(([n, l]) => l + ': ' + e.fields[n]).join(' · ') || 'no other fields')}</small>
      <small class="t3">${X.recs.length} record${X.recs.length === 1 ? '' : 's'} · ${X.links.length} link${X.links.length === 1 ? '' : 's'}${e.tags.length ? ' · #' + e.tags.slice(0, 3).map(esc).join(' #') : ''}</small></div></label>`; };
  openDlg(dhead('Possible duplicates') + `<div class="in"><p class="t2" style="margin:0 0 12px">Pick the entry to keep in each group. The others are merged into it: empty fields are filled, tags, notes and links are kept, and different values are noted. You can undo it.</p>
    ${G.map(g => `<section class="dp-g" data-sig="${esc(g.sig)}"><header>${tbadge(g.G[0].type)}<b>${esc(TYPES[g.G[0].type].label)}</b><span class="chip sq ${g.sure ? 'red' : 'amber'}">${g.sure ? 'Same value' : 'Probably the same — one letter apart'}</span></header>
      ${g.G.map(e => row(g, e)).join('')}<div class="wrap"><button class="btn sm primary" data-act="dupMerge" data-v="${esc(g.sig)}">${ico('merge','sm')}Merge</button><button class="btn sm ghost" data-act="dupNot" data-v="${esc(g.sig)}">Not the same</button></div></section>`).join('')}</div>
    <footer><button class="btn" data-act="dclose">Done</button></footer>`);
}
const DUP_ACTS = {
  dupOpen:() => dupDlg(),
  dupMerge:(id, v) => { const sec = document.querySelector(`.dp-g[data-sig="${CSS.escape(v)}"]`), k = sec && sec.querySelector('input[type=radio]:checked'); if(!k) return; dupMerge(k.value, v.split('+')); dupDlg(); },
  dupNot:(id, v) => { DB.prefs.notDup = [...new Set([...(DB.prefs.notDup || []), v])].slice(-500); save(); dupDlg(); renderMain(); },
};
