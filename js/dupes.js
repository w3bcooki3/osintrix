/* ==========================================================================
   Duplicates and merging — the same thing entered twice in a vault.
   Entries of the same type are compared on their main value after tidying
   it the way it would be written anyway: letter case, defanged forms
   (hxxp, [.]), a leading @, www. and trailing slashes, spaces and dashes in
   phone numbers, accents and word order in names. Names and handles one
   letter apart are offered too, marked "probably". Merging keeps one entry,
   fills its empty fields from the others, keeps every tag, note and link,
   and can be undone — one group at a time, or every same-value group at
   once, each into its fullest entry.
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
/* one letter apart — but not one digit swapped for another: "case 2033" and "case 2433", or "user7" and "user8", are different things */
const digitSwap = (a, b) => { if(a.length !== b.length) return false; let d = -1; for(let i = 0; i < a.length; i++) if(a[i] !== b[i]){ if(d >= 0) return false; d = i; } return d >= 0 && /\d/.test(a[d]) && /\d/.test(b[d]); };
function lev1(a, b){ if(Math.abs(a.length - b.length) > 1) return false; let i = 0, j = 0, d = 0; while(i < a.length && j < b.length){ if(a[i] === b[j]){ i++; j++; continue; } if(++d > 1) return false; if(a.length > b.length) i++; else if(b.length > a.length) j++; else { i++; j++; } } return d + (a.length - i) + (b.length - j) <= 1; }
function dupGroups(caseId){
  const L = DB.entries.filter(e => e.caseId === caseId), by = new Map(), out = [], skip = new Set((DB.prefs.notDup || []));
  for(const e of L){ const n = dupNorm(e); if(!n) continue; const k = e.type + '|' + n; if(!by.has(k)) by.set(k, []); by.get(k).push(e); }
  for(const G of by.values()) if(G.length > 1) out.push({sure:true, G});
  /* one letter apart: names and handles only, and not too short to mean anything */
  const loose = [...by.entries()].filter(([k, G]) => G.length === 1 && /^(person|organization|alias|username|social)\|/.test(k) && k.split('|')[1].length >= 6);
  /* two values one letter apart share a form with one letter taken out, so only those are compared — not every pair (thousands of names stay quick) */
  const bucket = new Map(), pairs = new Set();
  loose.forEach(([k], i) => { const [t, v] = k.split('|'), forms = new Set([v]); for(let p = 0; p < v.length; p++) forms.add(v.slice(0, p) + v.slice(p + 1));
    for(const f of forms){ const b = t + '|' + f; let L = bucket.get(b); if(!L) bucket.set(b, L = []); for(const j of L) pairs.add(j < i ? j + ',' + i : i + ',' + j); if(L.length < 50) L.push(i); } });
  let nm = 0; for(const pr of pairs){ if(nm >= 2000) break;   /* more near matches than anyone could review would be noise, not help */ const [i, j] = pr.split(',').map(Number), [ka, A] = loose[i], [kb, B] = loose[j]; const va = ka.split('|')[1], vb = kb.split('|')[1]; if(lev1(va, vb) && !digitSwap(va, vb)){ out.push({sure:false, G:[A[0], B[0]]}); nm++; } }
  return out.map(g => ({...g, sig:g.G.map(e => e.id).sort().join('+')})).filter(g => !skip.has(g.sig));
}
const dupFilled = e => Object.values(e.fields || {}).filter(v => v && String(v).trim()).length + (e.notes ? 1 : 0) + e.tags.length + (e.src ? 1 : 0);
/* merge many groups at once: [{keep, others:[entries]}] — fields, tags, notes, stars, priority; links re-pointed in one pass */
function dupMergeMany(groups){
  const P = {low:0, medium:1, high:2, critical:3}, to = new Map();
  for(const {keep, others} of groups){ const extra = [];
    for(const o of others){
      for(const [k, v] of Object.entries(o.fields || {})){ if(!v || !String(v).trim()) continue; if(!keep.fields[k] || !String(keep.fields[k]).trim()) keep.fields[k] = v; else if(String(keep.fields[k]).trim().toLowerCase() !== String(v).trim().toLowerCase()) extra.push(`${(TYPES[o.type].fields.find(f => f[0] === k) || [k, k])[1]}: ${v}`); }
      keep.tags = [...new Set([...keep.tags, ...o.tags])]; if(o.notes && !keep.notes.includes(o.notes)) keep.notes = [keep.notes, o.notes].filter(Boolean).join('\n');
      keep.starred = keep.starred || o.starred; if(P[o.priority] > P[keep.priority]) keep.priority = o.priority; if(!keep.src && o.src) keep.src = o.src; if(!keep.pos && o.pos) keep.pos = o.pos;
      to.set(o.id, keep.id); }
    if(extra.length) keep.notes = [keep.notes, 'Also recorded as — ' + [...new Set(extra)].join(' · ')].filter(Boolean).join('\n'); }
  for(const l of DB.links){ if(to.has(l.a)) l.a = to.get(l.a); if(to.has(l.b)) l.b = to.get(l.b); }
  const seen = new Set();
  DB.entries = DB.entries.filter(e => !to.has(e.id));
  DB.links = DB.links.filter(l => { if(l.a === l.b) return false; const k = [l.a, l.b].sort().join('|') + '|' + (l.label || ''); if(seen.has(k)) return false; seen.add(k); return true; });
  if(UI.sel && to.has(UI.sel.id)) UI.sel = {kind:'entry', id:to.get(UI.sel.id)};
  return to.size;
}
const dupSnap = () => ({entries:JSON.parse(JSON.stringify(DB.entries)), links:JSON.parse(JSON.stringify(DB.links))});
const dupBest = G => G.slice().sort((a, b) => dupFilled(b) - dupFilled(a) || (a.created || 0) - (b.created || 0))[0];
function dupMerge(keepId, ids){
  const keep = entryById(keepId), others = ids.filter(id => id !== keepId).map(entryById).filter(Boolean); if(!keep || !others.length) return;
  const before = dupSnap(); dupMergeMany([{keep, others}]);
  mutate('merged ' + (others.length + 1) + ' entries into ' + primary(keep)); renderAll();
  toast(`Merged into ${primary(keep)}`, 'Undo', () => { DB.entries = before.entries; DB.links = before.links; mutate('undid a merge'); renderAll(); if($('dupIn')) dupPaint(); });
}
/* every "same value" group, each into its fullest entry (or the one picked on screen) */
function dupMergeAll(){
  const G = dupGroups(DB.active).filter(g => g.sure); if(!G.length) return;
  const pick = sig => { const sec = document.querySelector(`.dp-g[data-sig="${CSS.escape(sig)}"]`), k = sec && sec.querySelector('input[type=radio]:checked'); return k ? entryById(k.value) : null; };
  const before = dupSnap(), groups = G.map(g => { const keep = pick(g.sig) || dupBest(g.G); return {keep, others:g.G.filter(e => e !== keep)}; });
  const n = dupMergeMany(groups);
  mutate(`merged ${G.length} groups of duplicates`); renderAll(); dupPaint();
  toast(`Merged ${G.length.toLocaleString()} group${G.length === 1 ? '' : 's'} — ${n.toLocaleString()} duplicate entr${n === 1 ? 'y' : 'ies'} folded in`, 'Undo', () => { DB.entries = before.entries; DB.links = before.links; mutate('undid merging duplicates'); renderAll(); if($('dupIn')) dupPaint(); });
}
const DUP_PAGE = 40;
function dupDlg(){
  if(!dupGroups(DB.active).length){ closeDlg(); return toast('No duplicates in this vault'); }
  UI.dup = {tab:null, lim:DUP_PAGE};
  openDlg(dhead('Possible duplicates') + `<div class="in" id="dupIn"></div><footer><button class="btn" data-act="dclose">Done</button></footer>`, true); dupPaint();
}
function dupPaint(){
  const el = $('dupIn'); if(!el) return; const all = dupGroups(DB.active), S = UI.dup || (UI.dup = {tab:null, lim:DUP_PAGE});
  const sure = all.filter(g => g.sure), maybe = all.filter(g => !g.sure); if(!S.tab || (S.tab === 'sure' && !sure.length) || (S.tab === 'maybe' && !maybe.length)) S.tab = sure.length ? 'sure' : 'maybe';   /* an emptied tab hands over to the other */
  if(!all.length){ el.innerHTML = `<div class="dp-done">${ico('check','sm')}<b>No duplicates left in this vault.</b></div>`; return; }
  const list = S.tab === 'sure' ? sure : maybe, shown = list.slice(0, S.lim);
  const row = (g, e) => { const X = typeof entryCtx === 'function' ? entryCtx(e) : {recs:[], links:[]}, best = dupBest(g.G);
    return `<label class="dp-e"><input type="radio" name="dpk-${g.sig}" value="${e.id}" ${e === best ? 'checked' : ''}><div><b class="${MONO_TYPES.has(e.type) ? 'mono' : ''}">${esc(primary(e))}</b>
      <small>${esc(TYPES[e.type].fields.slice(1).filter(([n]) => e.fields[n] && String(e.fields[n]).trim() && e.fields[n] !== '—').slice(0, 3).map(([n, l]) => l + ': ' + e.fields[n]).join(' · ') || 'no other fields')}</small>
      <small class="t3">${X.recs.length} record${X.recs.length === 1 ? '' : 's'} · ${X.links.length} link${X.links.length === 1 ? '' : 's'}${e.tags.length ? ' · #' + e.tags.slice(0, 3).map(esc).join(' #') : ''}</small></div></label>`; };
  el.innerHTML = `<div class="dp-top"><div class="seg" role="group" aria-label="Which duplicates"><button data-act="dupTab" data-v="sure" aria-pressed="${S.tab === 'sure'}"${sure.length ? '' : ' disabled'}>Same value <span class="cnt">${sure.length}</span></button><button data-act="dupTab" data-v="maybe" aria-pressed="${S.tab === 'maybe'}"${maybe.length ? '' : ' disabled'}>Probably the same <span class="cnt">${maybe.length}</span></button></div>
      ${S.tab === 'sure' && sure.length > 1 ? `<button class="btn primary sm" data-act="dupAll">${ico('merge','sm')}Merge all ${sure.length.toLocaleString()} groups</button>` : ''}</div>
    <p class="t2 dp-p">${S.tab === 'sure' ? 'The same value written differently — letter case, defanged, a leading @, www., spacing. ' : 'Names and handles one letter apart: check each one. '}Pick the entry to keep in each group; the others are merged into it — empty fields are filled, tags, notes and links are kept, and different values are noted. ${S.tab === 'sure' ? 'Merge all keeps the fullest entry in each group, or the one you picked.' : ''} Every merge can be undone.</p>
    ${shown.map(g => `<section class="dp-g" data-sig="${esc(g.sig)}"><header>${tbadge(g.G[0].type)}<b>${esc(TYPES[g.G[0].type].label)}</b><span class="chip sq ${g.sure ? 'red' : 'amber'}">${g.sure ? 'Same value' : 'One letter apart'}</span></header>
      ${g.G.map(e => row(g, e)).join('')}<div class="wrap"><button class="btn sm primary" data-act="dupMerge" data-v="${esc(g.sig)}">${ico('merge','sm')}Merge</button><button class="btn sm ghost" data-act="dupNot" data-v="${esc(g.sig)}">Not the same</button></div></section>`).join('')}
    ${list.length > shown.length ? `<div class="vb-more"><span class="t3">Showing ${shown.length} of ${list.length.toLocaleString()}</span><button class="btn sm" data-act="dupMore">Show ${Math.min(DUP_PAGE, list.length - shown.length)} more</button></div>` : ''}`;
}
const DUP_ACTS = {
  dupOpen:() => dupDlg(),
  dupMerge:(id, v) => { const sec = document.querySelector(`.dp-g[data-sig="${CSS.escape(v)}"]`), k = sec && sec.querySelector('input[type=radio]:checked'); if(!k) return; dupMerge(k.value, v.split('+')); dupPaint(); },
  dupNot:(id, v) => { DB.prefs.notDup = [...new Set([...(DB.prefs.notDup || []), v])].slice(-5000); save(); dupPaint(); renderMain(); },
  dupAll:() => dupMergeAll(),
  dupTab:(id, v) => { UI.dup.tab = v; UI.dup.lim = DUP_PAGE; dupPaint(); const b = document.querySelector(`[data-act=dupTab][data-v="${v}"]`); if(b) b.focus(); },
  dupMore:() => { UI.dup.lim += DUP_PAGE; dupPaint(); },
};
