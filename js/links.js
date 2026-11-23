/* ==========================================================================
   Connected cases — what one case shares with the others, and why it matters.
   · the same indicator in both (IP, domain, URL, hash, email, wallet, handle…),
     weighted by your verdict: malicious counts most, benign is left out
   · the same vault entry in both (a phone, wallet, handle or name, compared the
     way duplicate detection does: case, defanging, @, accents, word order)
   · nearby infrastructure: public IPs in the same /24, hosts under the same
     registered domain — weaker, said so
   Private and reserved addresses, and anything present in most cases (a mail
   provider, a CDN) are not evidence of a link and are ignored.
   ========================================================================== */
const CLK_C = {sig:'', v:null};
const lkPrivate = ip => /^(10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|22[4-9]\.|2[3-5]\d\.)/.test(ip) || /^(::1|fe80:|fc|fd)/i.test(ip);
const CLK_TLD2 = /^(co|com|org|net|ac|gov|edu|ltd|plc|me|ne|or|go)$/;
function lkRegDomain(d){ const p = String(d).toLowerCase().replace(/\.$/, '').split('.'); if(p.length < 2) return ''; return (p.length >= 3 && CLK_TLD2.test(p[p.length - 2]) && p[p.length - 1].length === 2 ? p.slice(-3) : p.slice(-2)).join('.'); }
const CLK_W = {malicious:6, suspicious:3, '':1};
function lkIndex(){
  const sig = rev + ':' + DB.cases.length + ':' + Object.keys(DB.verdicts || {}).length + ':' + (typeof libphonenumber !== 'undefined') + ':' + (DB.phoneCC || ''); if(CLK_C.sig === sig) return CLK_C.v;
  const cases = DB.cases.filter(c => !c.sample || DB.cases.every(x => x.sample)), per = new Map(), seen = new Map();
  for(const c of cases){ const D = derive(c.id), keys = new Map();
    for(const e of D.ents.values()){ if(e.k === 'ttp') continue; if((e.k === 'ipv4' || e.k === 'ipv6') && lkPrivate(e.v)) continue; if(verdictOf(e.id) === 'benign') continue;
      /* a phone number counts by its standard form, so 07700 900123 here and +44 7700 900123 there are one number */
      const pi = e.k === 'phone' && typeof phoneInfo === 'function' ? phoneInfo(e.v) : null; keys.set('e|' + (pi && pi.ok && pi.valid ? 'phone:' + pi.e164 : e.id), {kind:'ind', k:e.k, v:pi && pi.ok && pi.valid ? pi.e164 : e.v, id:e.id, n:e.recs.length}); }
    for(const en of D.entries){ const n = typeof dupNorm === 'function' ? dupNorm(en) : ''; if(!n || n.length < 4) continue; keys.set('v|' + en.type + '|' + n, {kind:'vault', type:en.type, v:primary(en), id:en.id}); }
    per.set(c.id, {c, keys}); for(const k of keys.keys()) seen.set(k, (seen.get(k) || 0) + 1); }
  /* things in most cases are background (a webmail domain, a public resolver), not a link */
  const common = new Set(cases.length >= 4 ? [...seen.entries()].filter(([, n]) => n / cases.length > 0.5).map(([k]) => k) : []);
  CLK_C.sig = sig; CLK_C.v = {per, common, cases}; return CLK_C.v;
}
function caseLinks(caseId){
  const X = lkIndex(), me = X.per.get(caseId); if(!me) return [];
  const myNet = new Map(), myDom = new Map();
  for(const [k, x] of me.keys){ if(x.kind !== 'ind') continue; if(x.k === 'ipv4') myNet.set(x.v.split('.').slice(0, 3).join('.'), x.v); if(x.k === 'domain' || x.k === 'url'){ const h = x.k === 'url' ? (x.v.match(/^[a-z]+:\/\/([^/:?#]+)/i) || [])[1] : x.v; const r = h && lkRegDomain(h); if(r) myDom.set(r, h); } }
  const out = [];
  for(const [id, o] of X.per){ if(id === caseId) continue; const shared = [], near = []; let score = 0;
    for(const [k, x] of me.keys){ if(X.common.has(k) || !o.keys.has(k)) continue; const vd = x.kind === 'ind' ? (verdictOf(x.id) || '') : '';
      const age = vd && typeof verdictWeight === 'function' ? verdictWeight(x.id) : 1, w = x.kind === 'vault' ? 4 : 1 + ((CLK_W[vd] ?? 1) - 1) * age; score += w; shared.push({...x, vd, w, old:age < 0.5}); }
    for(const [k, x] of o.keys){ if(x.kind !== 'ind' || X.common.has(k) || me.keys.has(k)) continue;
      if(x.k === 'ipv4'){ const net = x.v.split('.').slice(0, 3).join('.'); if(myNet.has(net) && myNet.get(net) !== x.v){ near.push({why:'same /24 network', a:myNet.get(net), b:x.v}); score += 0.5; } }
      else if(x.k === 'domain'){ const r = lkRegDomain(x.v); if(r && myDom.has(r) && myDom.get(r) !== x.v){ near.push({why:'same registered domain ' + r, a:myDom.get(r), b:x.v}); score += 0.5; } } }
    if(!shared.length && !near.length) continue;
    shared.sort((a, b) => b.w - a.w || (a.kind === 'vault' ? -1 : 1));
    const strength = shared.some(s => s.vd === 'malicious' && !s.old) || shared.filter(s => s.kind === 'vault').length >= 1 && shared.length >= 2 || score >= 8 ? 'strong' : shared.length ? 'some' : 'weak';
    out.push({c:o.c, score, shared, near:near.slice(0, 4), strength}); }
  return out.sort((a, b) => ({strong:2, some:1, weak:0}[b.strength] - {strong:2, some:1, weak:0}[a.strength]) || b.score - a.score).slice(0, 8);
}
function linksCard(c){
  const L = caseLinks(c.id); if(!L.length) return '';
  const lbl = {strong:['Strong link', 'red'], some:['Shares indicators', 'amber'], weak:['Related infrastructure', '']};
  const item = s => s.kind === 'vault' ? `<span class="lk-i"><span class="t3">${esc(TYPES[s.type] ? TYPES[s.type].label : s.type)}</span> <b>${esc(s.v)}</b> <span class="t3">in both vaults</span></span>`
    : `<button class="lk-i" data-act="lkEnt" data-id="${esc(s.id)}"><span class="t3">${esc(E.LABEL[s.k] || s.k)}</span> <b class="mono">${esc(s.v)}</b>${s.vd ? ` <span class="chip sq ${s.old ? '' : s.vd === 'malicious' ? 'red' : 'amber'}"${s.old ? ' title="Marked a long time ago — counts for less"' : ''}>${esc(s.vd)}${s.old ? ' · old' : ''}</span>` : ''}</button>`;
  return `<section class="card lk"><header><h3>${ico('link-2','sm')} Connected cases</h3><span class="t3">${L.length}</span></header><div class="body">
    ${L.map(x => `<div class="lk-c"><div class="lk-h"><a href="${caseHash(x.c.id, 'overview')}"><b>${esc(x.c.name.split(' — ')[0])}</a><span class="chip sq ${lbl[x.strength][1]}">${lbl[x.strength][0]}</span></div>
      ${x.shared.length ? `<p class="t2">${x.shared.length} thing${x.shared.length > 1 ? 's' : ''} in both${x.shared.some(s => s.vd === 'malicious' && !s.old) ? ', including what you marked malicious' : x.shared.some(s => s.vd === 'malicious') ? ', including indicators you marked malicious a long time ago' : ''}:</p><div class="lk-l">${x.shared.slice(0, 6).map(item).join('')}${x.shared.length > 6 ? `<span class="t3">and ${x.shared.length - 6} more</span>` : ''}</div>` : ''}
      ${x.near.length ? `<p class="t3 small">Nearby: ${x.near.map(n => `<span class="mono">${esc(n.a)}</span> here and <span class="mono">${esc(n.b)}</span> there — ${esc(n.why)}`).join('; ')}. Weaker: shared hosting is common.</p>` : ''}</div>`).join('')}
    <p class="t3 small">Private addresses, things you marked benign, and anything in most of your cases are left out; verdicts count for less as they age.</p></div></section>`;
}
const CLK_ACTS = { lkEnt:id => { if(typeof clickAct === 'function') clickAct('selEnt', id); } };
