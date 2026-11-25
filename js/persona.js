/* ==========================================================================
   Personas across your evidence
   One operator, many names: a vendor rebrands, a forum account is abandoned, a
   new market opens — but the PGP key, the wallet, the Session ID or the email
   stays. This finds the names that share such an identifier in your evidence,
   across every case, and says what ties them and where each tie was seen.
     · strong ties — a PGP key, a wallet, an email, a phone, a Session or Tox
       ID — tie the names written next to them on the same page or post
     · a username alone never ties two names (anyone can register one), and a
       page that names many people (a thread, a list) ties no names at all
     · a persona is shown when its ties were seen in two or more records
   Nothing is looked up; it reads what you have already captured.
   ========================================================================== */
const PS_STRONG = new Set(['tgid', 'dcid', 'pgp', 'email', 'phone', 'session', 'tox', 'btc', 'eth', 'xmr', 'sol', 'ltc', 'trx', 'doge', 'ens']);
const PS_NAME = new Set(['handle', 'social']);
const PS_TIE = {tgid:'Telegram account', dcid:'Discord account', pgp:'PGP key', email:'email', phone:'phone number', session:'Session ID', tox:'Tox ID', btc:'Bitcoin wallet', eth:'Ethereum wallet', xmr:'Monero wallet', sol:'Solana wallet', ltc:'Litecoin wallet', trx:'TRON wallet', doge:'Dogecoin wallet', ens:'ENS name'};
const PS = {key:'', v:null};
function personas(){
  const key = rev + ':' + DB.records.length; if(PS.key === key) return PS.v;
  const par = new Map(), find = a => { let p = par.get(a) || a; if(p !== a){ p = find(p); par.set(a, p); } return p; }, join = (a, b) => { const x = find(a), y = find(b); if(x !== y) par.set(x, y); };
  const seen = new Map();   // key -> [record]
  for(const r of DB.records){ if(r.type === 'lead' || !theCase(r.caseId) || theCase(r.caseId).stash) continue;
    const ents = (r.ents || []).filter(e => PS_STRONG.has(e.k) || PS_NAME.has(e.k)); if(!ents.length) continue;
    const ks = [...new Set(ents.map(e => e.k + ':' + e.v))], strong = ks.filter(k => PS_STRONG.has(k.slice(0, k.indexOf(':')))), names = ks.filter(k => PS_NAME.has(k.slice(0, k.indexOf(':'))));
    if(!strong.length || strong.length > 12) continue;                         // a dump of many wallets or emails ties nothing
    if((r.tags || []).includes('chat')) names.length = 0;   // a chat author's record: the handles they mention are other people
    const subj = /^Page subject: @?([^\s—]+)/m.exec(r.body || ''); if(subj){ const k = 'handle:@' + subj[1].replace(/^@/, ''); if(names.includes(k)){ names.length = 0; names.push(k); } }   // a page about one profile, that also names its buyers
    for(const k of strong.concat(names.length <= 3 ? names : [])){ if(!seen.has(k)) seen.set(k, []); seen.get(k).push(r); }
    for(let i = 1; i < strong.length; i++) join(strong[0], strong[i]);
    if(names.length <= 3) for(const n of names) join(strong[0], n); }
  const groups = new Map(); for(const k of seen.keys()){ const g = find(k); if(!groups.has(g)) groups.set(g, []); groups.get(g).push(k); }
  const out = [];
  for(const ks of groups.values()){
    const recs = new Map(); for(const k of ks) for(const r of seen.get(k)) recs.set(r.id, r);
    const ties = ks.filter(k => PS_STRONG.has(k.slice(0, k.indexOf(':'))) && new Set(seen.get(k).map(r => r.id)).size >= 2);
    const names = ks.filter(k => PS_NAME.has(k.slice(0, k.indexOf(':'))) || /^(email|tgid|dcid):/.test(k)).sort((a, b) => a.startsWith('email:') - b.startsWith('email:'));
    if(!ties.length || recs.size < 2 || names.length < 1) continue;
    const cases = new Set([...recs.values()].map(r => r.caseId));
    out.push({id:'ps:' + ties[0], keys:ks.sort(), ties, names, recs:[...recs.values()].sort((a, b) => (a.ts || 0) - (b.ts || 0)), cases:[...cases],
      first:Math.min(...[...recs.values()].map(r => r.ts || Infinity)), last:Math.max(...[...recs.values()].map(r => r.ts || 0))});
  }
  out.sort((a, b) => b.cases.length - a.cases.length || b.ties.length - a.ties.length || b.recs.length - a.recs.length);
  return PS.key = key, PS.v = out;
}
const psOf = key => personas().find(p => p.keys.includes(key));
const psName = (P, n = 3) => P.names.slice(0, n).map(k => entSplit(k).v).join(' / ') + (P.names.length > n ? ' +' + (P.names.length - n) : '');
/* what ties it, in words: "same PGP key in 3 records (Op Lantern, Customer portal)" */
function psTieText(P, k){ const rs = P.recs.filter(r => (r.ents || []).some(e => e.k + ':' + e.v === k)), cs = [...new Set(rs.map(r => caseNm(theCase(r.caseId), 24)))];
  return `same ${PS_TIE[entSplit(k).k] || entSplit(k).k} in ${rs.length} records${cs.length > 1 ? ' across ' + cs.join(', ') : ' (' + cs[0] + ')'}`; }
function psCard(P){
  return `<article class="ps-card"><header><span class="ps-ic">${ico('users','sm')}</span><div><h3>${esc(psName(P))}</h3><small>${P.cases.length > 1 ? `<b>${P.cases.length} cases</b> · ` : ''}${P.recs.length} records${P.first < Infinity ? ' · ' + esc(E.fmtDate(P.first, tz())) + (P.last > P.first ? ' – ' + esc(E.fmtDate(P.last, tz())) : '') : ''}</small></div></header>
    <ul class="ps-ties">${P.ties.slice(0, 4).map(k => `<li>${kindBadge(entSplit(k).k, 'sm')}<button class="lnk mono" data-act="selEnt" data-id="${esc(k)}" title="${esc(entSplit(k).v)}">${esc(chShortAny(entSplit(k).v))}</button><span>${esc(psTieText(P, k))}</span></li>`).join('')}</ul>
    <div class="ps-names">${P.names.slice(0, 8).map(k => entPill(k)).join('')}</div>
    <footer><button class="btn sm" data-act="psOpen" data-id="${esc(P.id)}">${ico('list','sm')}The evidence</button>${(h => h.length >= 2 && typeof stDlg === 'function' ? `<button class="btn sm" data-act="stGo" data-id="${esc(h[0])}" data-v="${esc(h[1])}">${ico('pencil','sm')}Compare writing</button>` : '')(P.names.filter(k => k.startsWith('handle:')))}${DB.active && theCase() && !theCase().stash ? `<span class="ps-mk"><button class="btn sm" data-act="psProfile" data-id="${esc(P.id)}" title="Make a profile of this persona in ${esc(caseNm(theCase()))}">${ico('user','sm')}<span class="ps-mk-t">Profile in ${esc(caseNm(theCase(), 40))}</span></button>${casePick()}</span>` : ''}</footer></article>`;
}
const chShortAny = v => v.length > 26 ? v.slice(0, 14) + '…' + v.slice(-8) : v;
function psSection(){
  const L = personas(); if(!L.length) return '';
  return `<section class="ps-sec"><div class="ps-h"><h2>Personas across your evidence</h2><span>Names that share a PGP key, wallet, email, phone or messenger ID — the identifiers an operator keeps through rebrands.</span></div>
    <div class="ps-grid">${L.slice(0, 12).map(psCard).join('')}</div>${L.length > 12 ? `<p class="t3 small">${L.length - 12} more.</p>` : ''}</section>`;
}
function psDlg(id){
  const P = personas().find(p => p.id === id); if(!P) return;
  const by = new Map(); for(const r of P.recs){ if(!by.has(r.caseId)) by.set(r.caseId, []); by.get(r.caseId).push(r); }
  openDlg(dhead(esc(psName(P, 4))) + `<div class="in"><p class="t2" style="margin:0 0 12px">Tied by ${P.ties.map(k => esc(psTieText(P, k))).join('; ')}. A shared identifier is strong evidence of one operator, not proof: keys and wallets can be shared, sold or copied into a scam page — read each record.</p>
    ${[...by.entries()].map(([c, rs]) => `<h4 class="ps-ch">${esc(caseNm(theCase(c)))}</h4>${rs.map(r => { const here = (r.ents || []).map(e => e.k + ':' + e.v).filter(k => P.keys.includes(k));
      return `<button class="li ps-r" data-act="psRec" data-id="${r.id}"><div class="main2"><b>${esc(r.title)}</b><small>${r.ts ? esc(E.fmtDate(r.ts, tz())) + ' · ' : ''}${here.slice(0, 5).map(k => esc((E.LABEL[entSplit(k).k] || '') + ' ' + chShortAny(entSplit(k).v))).join(' · ')}</small></div></button>`; }).join('')}`).join('')}</div>
    <footer><button class="btn" data-act="dclose">Close</button>${DB.active && theCase() && !theCase().stash ? `<button class="btn primary" data-act="psProfile" data-id="${esc(P.id)}">${ico('user','sm')}Make a profile in ${esc(caseNm(theCase(), 22))}</button>${casePick()}` : ''}</footer>`);
  $('dlg').classList.add('wide');
}
/* a Person in the active case with each identifier as a vault entry linked to it — then the identity profile opens */
function psProfile(id){
  const P = personas().find(p => p.id === id), c = theCase(); if(!P || !c || c.stash) return;
  const made = [], have = new Map(DB.entries.filter(e => e.caseId === c.id).map(e => [entryKey(e), e]));
  const person = {id:uid('v'), caseId:c.id, type:'person', fields:{name:'Operator behind ' + psName(P, 2), role:'Subject'}, priority:'high', starred:false, tags:['persona'], notes:'Tied by ' + P.ties.map(k => psTieText(P, k)).join('; ') + '.', src:P.recs[0].caseId === c.id ? P.recs[0].id : '', created:Date.now(), pos:null};
  DB.entries.push(person); made.push(person);
  for(const k of P.keys){ let e = have.get(k); if(!e){ const t = entryFor(k); if(!t) continue; const src = P.recs.find(r => r.caseId === c.id && (r.ents || []).some(x => x.k + ':' + x.v === k));
      if(t.type === 'pgpkey' && typeof ipfPgpKey === 'function'){ const K = ipfPgpKey(entSplit(k).v); if(K){ t.fields.uids = K.uids.join('; ').slice(0, 400); if(K.created) t.fields.created = new Date(K.created).toISOString().slice(0, 10); } }
      e = {id:uid('v'), caseId:c.id, type:t.type, fields:t.fields, priority:'medium', starred:false, tags:['persona'], notes:'', src:src ? src.id : '', created:Date.now(), pos:null}; DB.entries.push(e); made.push(e); }
    DB.links.push({id:uid('l'), caseId:c.id, a:person.id, b:e.id, label:'uses', conf:P.ties.includes(k) ? 3 : 2, src:''}); }
  if(typeof ensurePositions === 'function') ensurePositions(); mutate('made a profile from a persona'); closeDlg(); renderAll();
  toast(`Profile made in ${caseNm(c)} — ${made.length - 1} identifiers linked`, 'Open it', () => typeof idpDlg === 'function' && idpDlg(person.id));
}
const PS_ACTS = {
  psOpen:id => psDlg(id),
  psProfile:id => psProfile(id),
  psRec:id => { closeDlg(); const r = recById(id); if(!r) return; DB.active = r.caseId; UI.sel = {kind:'rec', id}; UI.inspOpen = true; UI.tlMode = 'events'; go(caseHash(r.caseId, 'timeline')); },
};
