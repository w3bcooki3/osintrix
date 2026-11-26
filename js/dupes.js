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
/* a ship or an aircraft carries several numbers; two entries sharing any of them are one craft. A US registration and
   its ICAO address are worked out from each other, so N628TS and a835af are seen as the same aircraft. */
function dupCraftIds(e){ const f = e.fields || {}, out = [];
  if(e.type === 'vessel'){ const i = String(f.imo || '').replace(/\D/g, ''), m = String(f.mmsi || '').replace(/\D/g, ''); if(i) out.push('IMO number|' + i); if(m) out.push('MMSI|' + m); }
  else if(e.type === 'aircraft' && typeof TRANSPORT !== 'undefined'){ const r = String(f.registration || '').replace(/\s+/g, '').toUpperCase(), h = String(f.icao24 || '').trim().toLowerCase();
    if(r){ out.push('registration|' + r); const x = TRANSPORT.nToIcao(r); if(x) out.push('ICAO address|' + x); }
    if(/^[0-9a-f]{6}$/.test(h)){ out.push('ICAO address|' + h); const n = TRANSPORT.icaoToN(h); if(n) out.push('registration|' + n); } }
  return out; }
function dupCraft(L){
  const C = L.filter(e => e.type === 'vessel' || e.type === 'aircraft'), par = new Map(C.map(e => [e.id, e.id])), f = id => par.get(id) === id ? id : (par.set(id, f(par.get(id))), par.get(id));
  const owner = new Map(), why = new Map();
  for(const e of C) for(const id of dupCraftIds(e)){ const o = owner.get(e.type + '|' + id); if(o){ const a = f(o), b = f(e.id); if(a !== b){ par.set(a, b); why.set(b, [...(why.get(a) || []), ...(why.get(b) || []), id.split('|')[0]]); } } else owner.set(e.type + '|' + id, e.id); }
  const G = new Map(); for(const e of C){ const r = f(e.id); if(!G.has(r)) G.set(r, []); G.get(r).push(e); }
  return [...G.entries()].filter(([, g]) => g.length > 1).map(([r, g]) => ({sure:true, G:g, why:'Same ' + [...new Set(why.get(r) || [])].join(' and ')}));
}
function dupGroups(caseId){
  const L = DB.entries.filter(e => e.caseId === caseId), by = new Map(), out = [], skip = new Set((DB.prefs.notDup || []));
  for(const e of L){ if(e.type === 'vessel' || e.type === 'aircraft') continue; const n = dupNorm(e); if(!n) continue; const k = e.type + '|' + n; if(!by.has(k)) by.set(k, []); by.get(k).push(e); }
  for(const G of by.values()) if(G.length > 1) out.push({sure:true, G});
  out.push(...dupCraft(L));
  /* one letter apart: names and handles only, and not too short to mean anything */
  const loose = [...by.entries()].filter(([k, G]) => G.length === 1 && /^(person|organization|alias|username|social)\|/.test(k) && k.split('|')[1].length >= 6);
  /* two values one letter apart share a form with one letter taken out, so only those are compared — not every pair (thousands of names stay quick) */
  const bucket = new Map(), pairs = new Set();
  loose.forEach(([k], i) => { const [t, v] = k.split('|'), forms = new Set([v]); for(let p = 0; p < v.length; p++) forms.add(v.slice(0, p) + v.slice(p + 1));
    for(const f of forms){ const b = t + '|' + f; let L = bucket.get(b); if(!L) bucket.set(b, L = []); for(const j of L) pairs.add(j < i ? j + ',' + i : i + ',' + j); if(L.length < 50) L.push(i); } });
  let nm = 0; for(const pr of pairs){ if(nm >= 2000) break;   /* more near matches than anyone could review would be noise, not help */ const [i, j] = pr.split(',').map(Number), [ka, A] = loose[i], [kb, B] = loose[j]; const va = ka.split('|')[1], vb = kb.split('|')[1]; if(lev1(va, vb) && !digitSwap(va, vb)){ out.push({sure:false, G:[A[0], B[0]]}); nm++; } }
  return out.map(g => ({...g, sig:g.G.map(e => e.id).sort().join('+')})).filter(g => !skip.has(g.sig));
}
/* ---------- related, not the same: linked, never merged ----------
   · one name on several accounts: @jdoe, x.com/jdoe and jdoe@proton.me are probably one person, but three entries
   · look-alike domains: paypa1.com, paypal-secure.net and раураl.com beside paypal.com are separate sites made to be
     mistaken for it. Each group is offered as links ("same name as", "look-alike of"), which say why. */
const DUP_GENERIC = new Set('info admin administrator contact contacts support sales hello office mail email noreply no-reply donotreply webmaster abuse security privacy billing accounts account test user users team help service services news marketing jobs careers press media root postmaster hostmaster enquiries inquiries feedback'.split(' '));
function dupNameOf(e){ let v = '';
  if(e.type === 'username') v = String(e.fields.username || '');
  else if(e.type === 'social'){ const s = e.fields.url && E.normSocial(e.fields.url); v = s ? s.user : String(e.fields.username || ''); }
  else if(e.type === 'daccount'){ const a = typeof idAccount === 'function' ? idAccount(e.fields.id) : null; v = a && typeof IDKEYS !== 'undefined' ? IDKEYS.userOf(a.k, a.v) : ''; }
  else if(e.type === 'email'){ const m = /^([^@\s]+)@([^@\s]+)$/.exec(String(e.fields.email || '').trim().toLowerCase()); if(!m) return ''; v = m[1].replace(/\+.*$/, ''); if(/^(gmail|googlemail)\.com$/.test(m[2])) v = v.replace(/\./g, ''); }
  else return '';
  v = v.toLowerCase().replace(/^@/, '').trim(); if(DUP_GENERIC.has(v)) return '';
  v = v.replace(/[._-]/g, ''); return v.length >= 5 && !/^\d+$/.test(v) ? v : ''; }
/* a domain's name part, with letters that look alike made the same (0 and o, 1 and l, Cyrillic а and Latin a, rn and m) */
const dupSkel = n => ipfSkel(n.normalize('NFKD').replace(/[̀-ͯ]/g, '').toLowerCase()).replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/-/g, '');
function dupLooks(L){
  const D = L.filter(e => e.type === 'domain').map(e => { const h = ipfUnicode(String(e.fields.domain || '').trim().toLowerCase().replace(/^www\./, '')); if(!h.includes('.')) return null; const r = ipfReg(h); return r.platform ? null : {e, r, sk:dupSkel(r.name), toks:r.name.split('-')}; }).filter(x => x && x.r.name.length >= 4);
  const pairs = new Map(), add = (x, y, why) => { if(x.r.reg === y.r.reg) return; const k = [x.e.id, y.e.id].sort().join('+'); if(!pairs.has(k)) pairs.set(k, {a:x, b:y, why}); };
  /* same letters once look-alikes are evened out: a different ending, or characters swapped for ones that look the same */
  const bySk = new Map(); for(const x of D){ if(!bySk.has(x.sk)) bySk.set(x.sk, []); bySk.get(x.sk).push(x); }
  for(const G of bySk.values()) for(let i = 0; i < G.length; i++) for(let j = i + 1; j < G.length && j < 60; j++) add(G[i], G[j], G[i].r.name === G[j].r.name ? 'Same name, other ending' : 'Look-alike characters');
  /* one letter apart (the same trick as for names: only values sharing a form with one letter taken out are compared) */
  const bucket = new Map(); for(const x of D){ if(x.sk.length < 5) continue; const forms = new Set([x.sk]); for(let p = 0; p < x.sk.length; p++) forms.add(x.sk.slice(0, p) + x.sk.slice(p + 1));
    for(const f of forms){ let B = bucket.get(f); if(!B) bucket.set(f, B = []); for(const y of B) if(y.sk !== x.sk && lev1(x.sk, y.sk) && !digitSwap(x.r.name, y.r.name)) add(x, y, 'One letter apart'); if(B.length < 50) B.push(x); } }
  /* a name with words added: paypal-secure, secure-paypal, paypal-login-help */
  const byName = new Map(); for(const x of D) if(x.sk.length >= 5){ if(!byName.has(x.sk)) byName.set(x.sk, []); byName.get(x.sk).push(x); }
  for(const x of D){ if(x.toks.length < 2) continue; for(const t of x.toks){ const ts = dupSkel(t); for(const y of byName.get(ts) || []) if(y !== x) add(x, y, 'Its name with words added'); } }
  return [...pairs.values()];
}
function dupRelated(caseId){
  const L = DB.entries.filter(e => e.caseId === caseId), skip = new Set(DB.prefs.notDup || []), out = [];
  const linked = new Set(DB.links.filter(l => l.caseId === caseId).map(l => [l.a, l.b].sort().join('+')));
  /* names: one group per name, more than one distinct account */
  const byName = new Map(); for(const e of L){ const n = dupNameOf(e); if(!n) continue; if(!byName.has(n)) byName.set(n, []); byName.get(n).push(e); }
  for(const [n, G] of byName){ const distinct = new Set(G.map(e => e.type + '|' + dupNorm(e))); if(distinct.size < 2 || G.length > 12) continue;
    const anchor = G.slice().sort((a, b) => (a.type === 'username' ? -1 : 0) - (b.type === 'username' ? -1 : 0) || dupFilled(b) - dupFilled(a))[0];
    const P = G.filter(e => e !== anchor).map(e => [e, anchor]).filter(([x, y]) => !linked.has([x.id, y.id].sort().join('+')));
    if(P.length) out.push({rel:'name', label:'same name as', G, P, why:'The name “' + n + '” on ' + distinct.size + ' accounts'}); }
  /* look-alikes: one group per family, every imitation linked to the plainest name in it (Latin letters, no digits, shortest) */
  const LP = dupLooks(L), par = new Map(), f = id => { while(par.get(id) !== id){ par.set(id, par.get(par.get(id))); id = par.get(id); } return id; }, X = new Map();
  for(const {a, b} of LP){ for(const x of [a, b]){ if(!par.has(x.e.id)) par.set(x.e.id, x.e.id); X.set(x.e.id, x); } par.set(f(a.e.id), f(b.e.id)); }
  const fam = new Map(); for(const id of par.keys()){ const r = f(id); if(!fam.has(r)) fam.set(r, []); fam.get(r).push(X.get(id)); }
  const plain = x => (/[^\x00-\x7f]/.test(x.r.name) ? 4 : 0) + (/\d/.test(x.r.name) ? 2 : 0) + (x.r.name.includes('-') ? 1 : 0) + x.r.name.length / 100 + (/^(com|org|net)$/.test(x.r.suffix) ? 0 : 0.5);
  const whyOf = new Map(LP.map(p => [[p.a.e.id, p.b.e.id].sort().join('+'), p.why]));
  for(const F of fam.values()){ if(F.length > 40) continue; F.sort((p, q) => plain(p) - plain(q)); const real = F[0], M = F.filter(x => x === real || x.r.reg !== real.r.reg);   /* the real site under another host name is the same site */ if(M.length < 2) continue;
    const P = M.slice(1).filter(x => !linked.has([x.e.id, real.e.id].sort().join('+'))).map(x => [x.e, real.e]); if(!P.length) continue;
    const why = [...new Set(M.slice(1).map(x => whyOf.get([x.e.id, real.e.id].sort().join('+'))).filter(Boolean))];
    out.push({rel:'look', label:'look-alike of', G:M.map(x => x.e), P, why:(M.length - 1) + ' look-alike' + (M.length > 2 ? 's' : '') + ' of ' + real.r.reg + (why.length ? ': ' + why.join(', ').toLowerCase() : ''), whys:Object.fromEntries(M.slice(1).map(x => [x.e.id, whyOf.get([x.e.id, real.e.id].sort().join('+')) || 'Looks like ' + real.r.reg]))}); }
  return out.map(g => ({...g, sig:'rel:' + g.G.map(e => e.id).sort().join('+')})).filter(g => !skip.has(g.sig));
}
function dupLinkGroup(g){
  let n = 0; for(const [x, y] of g.P){ if(DB.links.some(l => l.caseId === x.caseId && ((l.a === x.id && l.b === y.id) || (l.a === y.id && l.b === x.id)))) continue;
    const why = g.whys ? g.whys[x.id] : g.why; DB.links.push({id:uid('l'), caseId:x.caseId, a:x.id, b:y.id, label:g.label, conf:why === 'Look-alike characters' ? 3 : 2, src:'', why}); n++; }
  return n; }
const dupReviewCount = caseId => dupGroups(caseId).length + dupRelated(caseId).length;
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
  if(!dupReviewCount(DB.active)){ closeDlg(); return toast('No duplicates or related entries in this vault'); }
  UI.dup = {tab:null, lim:DUP_PAGE};
  openDlg(dhead('Duplicates and related entries') + `<div class="in" id="dupIn"></div><footer><button class="btn" data-act="dclose">Done</button></footer>`, true); dupPaint();
}
function dupPaint(){
  const el = $('dupIn'); if(!el) return; const all = dupGroups(DB.active), S = UI.dup || (UI.dup = {tab:null, lim:DUP_PAGE});
  const sure = all.filter(g => g.sure), maybe = all.filter(g => !g.sure), rel = dupRelated(DB.active), has = {sure:sure.length, maybe:maybe.length, rel:rel.length}; if(!S.tab || !has[S.tab]) S.tab = sure.length ? 'sure' : maybe.length ? 'maybe' : 'rel';   /* an emptied tab hands over to the other */
  if(!all.length && !rel.length){ el.innerHTML = `<div class="dp-done">${ico('check','sm')}<b>Nothing left to review in this vault.</b></div>`; return; }
  if(S.tab === 'rel'){ el.innerHTML = dupTabs(S, has) + dupRelHtml(rel.slice(0, S.lim), rel.length); return; }
  const list = S.tab === 'sure' ? sure : maybe, shown = list.slice(0, S.lim);
  const row = (g, e) => { const X = typeof entryCtx === 'function' ? entryCtx(e) : {recs:[], links:[]}, best = dupBest(g.G);
    return `<label class="dp-e"><input type="radio" name="dpk-${g.sig}" value="${e.id}" ${e === best ? 'checked' : ''}><div><b class="${MONO_TYPES.has(e.type) ? 'mono' : ''}">${esc(primary(e))}</b>
      <small>${esc(TYPES[e.type].fields.slice(1).filter(([n]) => e.fields[n] && String(e.fields[n]).trim() && e.fields[n] !== '—').slice(0, 3).map(([n, l]) => l + ': ' + e.fields[n]).join(' · ') || 'no other fields')}</small>
      <small class="t3">${X.recs.length} record${X.recs.length === 1 ? '' : 's'} · ${X.links.length} link${X.links.length === 1 ? '' : 's'}${e.tags.length ? ' · #' + e.tags.slice(0, 3).map(esc).join(' #') : ''}</small></div></label>`; };
  el.innerHTML = `${dupTabs(S, has, true)}
      ${S.tab === 'sure' && sure.length > 1 ? `<button class="btn primary sm" data-act="dupAll">${ico('merge','sm')}Merge all ${sure.length.toLocaleString()} groups</button>` : ''}</div>
    <p class="t2 dp-p">${S.tab === 'sure' ? 'The same value written differently — letter case, defanged, a leading @, www., spacing. ' : 'Names and handles one letter apart: check each one. '}Pick the entry to keep in each group; the others are merged into it — empty fields are filled, tags, notes and links are kept, and different values are noted. ${S.tab === 'sure' ? 'Merge all keeps the fullest entry in each group, or the one you picked.' : ''} Every merge can be undone.</p>
    ${shown.map(g => `<section class="dp-g" data-sig="${esc(g.sig)}"><header>${tbadge(g.G[0].type)}<b>${esc(TYPES[g.G[0].type].label)}</b><span class="chip sq ${g.sure ? 'red' : 'amber'}">${g.sure ? esc(g.why || 'Same value') : 'One letter apart'}</span></header>
      ${g.G.map(e => row(g, e)).join('')}<div class="wrap"><button class="btn sm primary" data-act="dupMerge" data-v="${esc(g.sig)}">${ico('merge','sm')}Merge</button><button class="btn sm ghost" data-act="dupNot" data-v="${esc(g.sig)}">Not the same</button></div></section>`).join('')}
    ${list.length > shown.length ? `<div class="vb-more"><span class="t3">Showing ${shown.length} of ${list.length.toLocaleString()}</span><button class="btn sm" data-act="dupMore">Show ${Math.min(DUP_PAGE, list.length - shown.length)} more</button></div>` : ''}`;
}
/* the tabs; the duplicate tabs keep their "merge all" button inside the same row, so the row is closed by the caller */
function dupTabs(S, has, open){
  const b = (v, l) => `<button data-act="dupTab" data-v="${v}" aria-pressed="${S.tab === v}"${has[v] ? '' : ' disabled'}>${l} <span class="cnt">${has[v]}</span></button>`;
  return `<div class="dp-top"><div class="seg" role="group" aria-label="What to review">${b('sure', 'Same value')}${b('maybe', 'Probably the same')}${b('rel', 'Related')}</div>${open ? '' : '</div>'}`; }
function dupRelHtml(shown, total){
  const row = (g, e) => `<div class="dp-e"><div><b class="${MONO_TYPES.has(e.type) ? 'mono' : ''}">${esc(primary(e))}</b><small>${esc(g.whys ? g.whys[e.id] || 'The name the others imitate' : TYPES[e.type].label)}</small></div></div>`;
  return `<p class="t2 dp-p">Different entries that belong together: one name on several accounts, and domains made to look like another. Linking keeps them apart and puts the reason on the link, so it shows on the graph.</p>
    ${shown.map(g => `<section class="dp-g" data-sig="${esc(g.sig)}"><header>${tbadge(g.G[0].type)}<b>${g.rel === 'look' ? 'Look-alike domain' : 'One name, several accounts'}</b><span class="chip sq amber">${esc(g.why)}</span></header>
      ${g.G.map(e => row(g, e)).join('')}<div class="wrap"><button class="btn sm primary" data-act="dupLink" data-v="${esc(g.sig)}">${ico('link','sm')}Link as “${esc(g.label)}”</button><button class="btn sm ghost" data-act="dupNot" data-v="${esc(g.sig)}">Not related</button></div></section>`).join('')}
    ${total > shown.length ? `<div class="vb-more"><span class="t3">Showing ${shown.length} of ${total.toLocaleString()}</span><button class="btn sm" data-act="dupMore">Show ${Math.min(DUP_PAGE, total - shown.length)} more</button></div>` : ''}`; }
const DUP_ACTS = {
  dupLink:(id, v) => { const g = dupRelated(DB.active).find(x => x.sig === v); if(!g) return; const n = dupLinkGroup(g); if(n){ mutate('linked ' + (n + 1) + ' entries as ' + g.label); renderAll(); toast(n + ' link' + (n === 1 ? '' : 's') + ' added: “' + g.label + '”'); } dupPaint(); },
  dupOpen:() => dupDlg(),
  dupMerge:(id, v) => { const sec = document.querySelector(`.dp-g[data-sig="${CSS.escape(v)}"]`), k = sec && sec.querySelector('input[type=radio]:checked'); if(!k) return; dupMerge(k.value, v.split('+')); dupPaint(); },
  dupNot:(id, v) => { DB.prefs.notDup = [...new Set([...(DB.prefs.notDup || []), v])].slice(-5000); save(); dupPaint(); renderMain(); },
  dupAll:() => dupMergeAll(),
  dupTab:(id, v) => { UI.dup.tab = v; UI.dup.lim = DUP_PAGE; dupPaint(); const b = document.querySelector(`[data-act=dupTab][data-v="${v}"]`); if(b) b.focus(); },
  dupMore:() => { UI.dup.lim += DUP_PAGE; dupPaint(); },
};
