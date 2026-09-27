/* ==========================================================================
   Relate — turn evidence into a graph, and find the links you have not drawn.

   1. Relations STATED in evidence become relationships automatically:
      • structure  — a URL is hosted on its domain, an email belongs to its domain,
                     a social profile belongs to its handle            (confidence high)
      • fields     — DNS answers, Sysmon DestinationHostname/Ip, email headers,
                     WHOIS registrant and name servers, zone-file lines (medium)
      • phrases    — "X resolves to Y", "X beacons to Y", "X aka Y" … between two
                     indicators in the same sentence                  (medium)
   2. Everything else is only SUGGESTED, with the reason, for you to accept:
      seen together, near in time on one host, look-alike identities,
      shared IP or registrant. Nothing is guessed silently.
   ========================================================================== */
const GRAPH_KINDS = ['ipv4','ipv6','domain','url','email','handle','social','phone','btc','eth','xmr','ltc','trx','doge','md5','sha1','sha256','cve','mac','coords'];
const KIND_GROUP_LABEL = [['net','Network','ipv4 ipv6 domain url mac'], ['id','Identity','email handle social phone'], ['fin','Wallets','btc eth xmr ltc trx doge'], ['hash','File hashes','md5 sha1 sha256'], ['other','Other','cve coords']];
const isPrivIP = v => /private|loopback|link-local|reserved|carrier|multicast|benchmark|this network/i.test(E.ipClass(v) || '');
/* graph key of an extracted entity: host:port collapses to its host */
function gkey(e){ if(e.k === 'hostport'){ const h = e.v.slice(0, e.v.lastIndexOf(':')); return (/^[\d.]+$/.test(h) ? 'ipv4:' : 'domain:') + h; } return GRAPH_KINDS.includes(e.k) ? e.k + ':' + e.v : null; }

/* ---------- 1. relations stated in one record ---------- */
const REL_VERBS = [
  [/\bresolv(?:es|ed|ing)?\s+(?:to|as)\b|\bA\s+record\b|\bpoints?\s+to\b|\bIN\s+(?:A|AAAA)\b/i, 'resolves to'],
  [/\bredirect(?:s|ed|ing)?\s+to\b/i, 'redirects to'],
  [/\bbeacon(?:s|ed|ing)?\b|\bcall(?:s|ed)?\s*back\b|\bcallback\b|\bc2\b|\bconnect(?:s|ed|ion|ing)?\s+(?:to|out)\b|\bcontacts?\b(?=\s)|->|→|=>/i, 'connects to'],
  [/\bhosted\s+(?:on|at|by)\b|\bserved\s+from\b|\bbehind\b|\blives\s+on\b/i, 'hosted on'],
  [/\bregist(?:ered|rant)(?:\s+(?:by|to|with|email|as))?\b|\bwhois\b/i, 'registered by'],
  [/\bdownload(?:s|ed|ing)?(?:\s+from)?\b|\bfetch(?:es|ed)?\b|\bpull(?:s|ed)\s+from\b|\bdrop(?:s|ped)?\b/i, 'downloaded from'],
  [/\bpaid\b|\bpay(?:s|ment)?\s+to\b|\btransfer(?:s|red)?\s+to\b|\bdeposit(?:s|ed)?\s+(?:to|into)\b|\bsent\s+[\d.,]+\s*(?:btc|eth|xmr|usdt|ltc|trx)\b/i, 'paid'],
  [/\bsent\s+(?:to|from)\b|\bemail(?:s|ed)\b|\bmail(?:s|ed)?\s+to\b|\breplied\s+to\b/i, 'sent'],
  [/\ba\.?k\.?a\.?\b|\balso\s+known\s+as\b|\balias(?:\s+of)?\b|\bsame\s+(?:person|actor|operator|user)\s+as\b|\bgoes\s+by\b|\bformerly\b/i, 'alias of'],
  [/\boperated\s+by\b|\bowned\s+by\b|\brun\s+by\b|\bcontrolled\s+by\b|\bbelongs?\s+to\b|\badmin(?:istered)?\s+by\b/i, 'operated by'],
  [/\buses?\b|\busing\b|\bused\b|\blogs?\s+in\s+(?:with|as)\b/i, 'uses'],
  [/\blinked\s+(?:to|with)\b|\bassociated\s+with\b|\brelated\s+to\b|\btied\s+to\b|\bconnected\s+with\b|\bshares?\b/i, 'associated with'],
];
const REL_STOP = new Set('is was are were be been being the a an to at on by of and or then which that it its also has have had now later currently still same this these those new old main his her their our my your domain domains ip ips address addresses server servers host hosts email emails mail wallet wallets account accounts handle user username url urls link site website via through from with into as for -> → => - — – : |'.split(' '));
const NET = new Set(['ipv4','ipv6','domain','url']), IDK = new Set(['email','handle','social','phone']), WAL = new Set(['btc','eth','xmr','ltc','trx','doge']), IPK = new Set(['ipv4','ipv6']);
function relOK(label, ka, kb){
  switch(label){
    case 'resolves to': return (ka === 'domain' || ka === 'url') && IPK.has(kb) ? 1 : IPK.has(ka) && kb === 'domain' ? -1 : 0;
    case 'redirects to': return (NET.has(ka) && NET.has(kb)) ? 1 : 0;
    case 'connects to': return (NET.has(ka) || /^(md5|sha1|sha256|mac)$/.test(ka)) && NET.has(kb) ? 1 : 0;
    case 'hosted on': return (ka === 'url' || ka === 'domain') && (IPK.has(kb) || kb === 'domain') ? 1 : 0;
    case 'registered by': return ka === 'domain' && (IDK.has(kb)) ? 1 : IDK.has(ka) && kb === 'domain' ? -1 : 0;
    case 'downloaded from': return (/^(md5|sha1|sha256|url|domain|ipv4|ipv6)$/.test(ka)) && NET.has(kb) ? 1 : 0;
    case 'paid': return WAL.has(ka) && WAL.has(kb) ? 1 : 0;
    case 'sent': return ka === 'email' && kb === 'email' ? 1 : 0;
    case 'alias of': return IDK.has(ka) && IDK.has(kb) ? 1 : 0;
    case 'operated by': return IDK.has(kb) ? 1 : IDK.has(ka) ? -1 : 0;
    default: return 1;
  }
}
function recordRelations(r){
  const text = E.refang((r.title || '') + '\n' + (r.body || '')), ents = r.ents.map(e => ({...e, g:gkey(e)})).filter(e => e.g);
  const out = [], seen = new Set();
  const add = (a, b, label, conf, why) => { if(!a || !b || a === b) return; const k = a + '|' + b + '|' + label; if(seen.has(k)) return; seen.add(k); out.push({a, b, label, conf, why, rec:r.id}); };
  const has = k => ents.some(e => e.g === k);
  /* structure */
  for(const e of ents){
    if(e.k === 'url'){ const h = (e.v.match(/^https?:\/\/(?:[^/@\s]*@)?([^/:?#\s]+)/i) || [])[1]; if(h){ const hk = (/^[\d.]+$/.test(h) ? 'ipv4:' : 'domain:') + h.toLowerCase(); if(has(hk)) add(e.g, hk, 'hosted on', 3, 'The URL is on this ' + (hk.startsWith('ipv4') ? 'IP' : 'domain')); } }
    if(e.k === 'email'){ const d = 'domain:' + e.v.split('@')[1]; if(has(d)) add(e.g, d, 'email at', 3, 'The address is at this domain'); }
    if(e.k === 'social'){ const u = e.v.split('/').pop().replace(/^@/, '').toLowerCase(), hk = 'handle:@' + u; if(has(hk)) add(e.g, hk, 'profile of', 3, 'Same username on ' + e.v.split('/')[0]); }
  }
  /* fields */
  const fv = (re) => { const m = text.match(re); return m ? m[1] : null; };
  const inField = (val, kinds) => ents.filter(e => kinds.includes(e.k) && val && val.toLowerCase().includes(e.v.toLowerCase()));
  const pairsBy = (re1, k1, re2, k2, label, why) => { const a = fv(re1), b = fv(re2); if(!a || !b) return; for(const x of inField(a, k1)) for(const y of inField(b, k2)) add(x.g, y.g, label, 2, why); };
  pairsBy(/QueryName[=:]\s*"?([^\s"]+)/i, ['domain'], /QueryResults?[=:]\s*"?([^"\n]+)/i, ['ipv4','ipv6'], 'resolves to', 'DNS query and its answer in the same event');
  pairsBy(/DestinationHostname[=:]\s*"?([^\s"]+)/i, ['domain'], /DestinationIp[=:]\s*"?([^\s"]+)/i, ['ipv4','ipv6'], 'resolves to', 'Destination host name and IP in the same connection');
  pairsBy(/SourceIp[=:]\s*"?([^\s"]+)/i, ['ipv4','ipv6'], /DestinationIp[=:]\s*"?([^\s"]+)/i, ['ipv4','ipv6'], 'connects to', 'Source and destination of one connection');
  pairsBy(/(?:^|\n|\s)(?:src|src_ip|client_ip|c-ip)[=:]\s*"?([^\s"]+)/i, ['ipv4','ipv6'], /(?:dst|dst_ip|dest_ip|server_ip|s-ip)[=:]\s*"?([^\s"]+)/i, ['ipv4','ipv6'], 'connects to', 'Source and destination of one connection');
  pairsBy(/(?:^|\s)From:\s*([^\n]*?)(?=\s+To:|\n|$)/i, ['email'], /(?:^|\s)To:\s*([^\n]*?)(?=\s+(?:Subject|Cc|Date|Attachment):|\n|$)/i, ['email'], 'sent', 'From and To of one message');
  pairsBy(/(?:^|\s)From:\s*([^\n]*?)(?=\s+To:|\n|$)/i, ['email'], /(?:^|\s)Reply-To:\s*([^\n]+)/i, ['email'], 'reply-to', 'Replies go to a different address');
  pairsBy(/Domain Name:\s*(\S+)/i, ['domain'], /Registrant(?:\s+\w+)*?\s+Email:\s*(\S+)/i, ['email'], 'registered by', 'WHOIS registrant');
  pairsBy(/Domain Name:\s*(\S+)/i, ['domain'], /Registrant(?:\s+\w+)*?\s+Phone:\s*(\S+)/i, ['phone'], 'registered by', 'WHOIS registrant phone');
  { const d = fv(/Domain Name:\s*(\S+)/i); if(d) for(const m of text.matchAll(/Name Server:\s*(\S+)/gi)) for(const x of inField(d, ['domain'])) for(const y of inField(m[1], ['domain'])) add(x.g, y.g, 'name server', 2, 'WHOIS name server'); }
  for(const m of text.matchAll(/^\s*([a-z0-9.-]+\.[a-z]{2,})\.?\s+(?:\d+\s+)?IN\s+(A|AAAA|CNAME|MX|NS)\s+(\S+)/gim)){
    const lab = {A:'resolves to', AAAA:'resolves to', CNAME:'alias of', MX:'mail server', NS:'name server'}[m[2].toUpperCase()];
    for(const x of inField(m[1], ['domain'])) for(const y of inField(m[3].replace(/\.$/, ''), ['ipv4','ipv6','domain'])) if(x.g !== y.g) add(x.g, y.g, lab, 2, 'DNS ' + m[2].toUpperCase() + ' record'); }
  /* parsed log fields (any format the parser understands) */
  for(const line of (r.body || '').split('\n').slice(0, 50)){ const P = parseLog(line, r.body); if(!P) continue; const n = P.norm;
    const find = v => v && ents.find(e => (e.k === 'ipv4' || e.k === 'ipv6' || e.k === 'domain') && e.v.toLowerCase() === String(v).toLowerCase());
    const s = find(n['src.ip']), d = find(n['dst.ip']), dn = find(n.domain);
    if(s && d) add(s.g, d.g, 'connects to', 2, `${n['src.ip']}${n['src.port'] ? ':' + n['src.port'] : ''} → ${n['dst.ip']}${n['dst.port'] ? ':' + n['dst.port'] : ''}${n.proto ? ' ' + n.proto : ''}${n.action ? ' · ' + n.action : ''} — ${P.format}`);
    if(dn && d && dn.g !== d.g) add(dn.g, d.g, 'resolves to', 2, 'Host name and IP in the same event — ' + P.format); }
  /* phrases: two indicators in one sentence joined by a relation verb */
  for(const sent of text.split(/\n|(?<=[a-z0-9)\]])\.\s+(?=[A-Z])|;\s/)){
    const low = sent.toLowerCase(), pos = [];
    for(const e of ents){ const needle = (e.k === 'handle' && !low.includes(e.v.toLowerCase()) ? e.v.slice(1) : e.v).toLowerCase(); let i = low.indexOf(needle);
      while(i >= 0){ pos.push({e, i, j:i + needle.length}); i = low.indexOf(needle, i + needle.length); } }
    pos.sort((a, b) => a.i - b.i || b.j - a.j);
    const clean = pos.filter((p, n) => !pos.some((q, m) => m !== n && q.i <= p.i && q.j >= p.j && (q.j - q.i) > (p.j - p.i)));
    for(let n = 0; n + 1 < clean.length; n++){
      const A = clean[n], B = clean[n + 1], gap = sent.slice(A.j, B.i); if(gap.length > 70 || A.e.g === B.e.g) continue;
      for(const [re, label] of REL_VERBS){ if(!re.test(gap)) continue;
        const rest = gap.replace(re, ' ').replace(/https?:\/*|www\./gi, ' ').split(/[\s,;:()"'\[\]]+/).filter(w => w && !REL_STOP.has(w.toLowerCase()));
        if(rest.length > 2 || rest.some(w => /[_\d@.\/]/.test(w))) break; const d = relOK(label, A.e.k, B.e.k); if(d === 1) add(A.e.g, B.e.g, label, 2, '“' + (gap.trim().slice(0, 40) || '→') + '” in the evidence'); else if(d === -1) add(B.e.g, A.e.g, label, 2, '“' + gap.trim().slice(0, 40) + '” in the evidence'); if(d) break; }
    }
  }
  return out;
}

/* ---------- entries & links from keys ---------- */
function entryFor(key){ const i = key.indexOf(':'), k = key.slice(0, i), v = key.slice(i + 1), type = KIND_TO_TYPE[k]; if(!type) return null;
  const f = {};
  switch(type){
    case 'social': { const s = E.normSocial('https://' + v); f.username = s ? s.user : v; f.platform = {'x.com':'X / Twitter','instagram.com':'Instagram','facebook.com':'Facebook','linkedin.com':'LinkedIn','tiktok.com':'TikTok','youtube.com':'YouTube','t.me':'Telegram'}[s && s.host] || 'Other'; f.url = 'https://' + v; break; }
    case 'location': f.address = 'Coordinates from evidence'; f.coordinates = v; break;
    case 'crypto': f.address = v; f.currency = {btc:'Bitcoin', eth:'Ethereum', xmr:'Monero', ltc:'Litecoin'}[k] || 'Other'; break;
    case 'username': f.username = v.replace(/^@/, ''); break;
    default: f[TYPES[type].fields[0][0]] = v;
  }
  return {type, fields:f};
}
function graphPlan(caseId, opts, recIds){
  const D = derive(caseId), recs = recIds ? D.recs.filter(r => recIds.includes(r.id)) : D.recs, mentions = new Map(), rels = [];
  for(const r of recs){ for(const e of r.ents){ const g = gkey(e); if(!g) continue; const m = mentions.get(g) || {n:0, rec:r.id}; m.n++; mentions.set(g, m); } rels.push(...recordRelations(r)); }
  const inGraph = k => D.byKey.has(k), relKeys = new Set(rels.flatMap(x => [x.a, x.b]));
  const keep = k => { const i = k.indexOf(':'), kind = k.slice(0, i), v = k.slice(i + 1), vd = verdictOf(k);
    if(!opts.kinds.includes(kind)) return false; if(opts.skipPrivate && IPK.has(kind) && isPrivIP(v)) return false; if(opts.skipBenign && vd === 'benign') return false;
    if(opts.focus && !(vd === 'malicious' || vd === 'suspicious' || relKeys.has(k) || isWatched(k))) return false; return (mentions.get(k) || {n:0}).n >= (opts.min || 1); };
  const newKeys = [...mentions.keys()].filter(k => !inGraph(k) && keep(k));
  const will = new Set([...D.byKey.keys(), ...newKeys]);
  const linked = new Set(D.links.map(l => [l.a, l.b].sort().join('|')));
  const keyEntry = k => D.byKey.get(k);
  const newRels = []; const pairSeen = new Set();
  for(const x of rels){ if(!will.has(x.a) || !will.has(x.b)) continue; const pk = [x.a, x.b].sort().join('|'); if(pairSeen.has(pk)) continue;
    const ea = keyEntry(x.a), eb = keyEntry(x.b); if(ea && eb && linked.has([ea.id, eb.id].sort().join('|'))) continue; pairSeen.add(pk); newRels.push(x); }
  const byKind = countBy([...mentions.keys()].filter(k => !inGraph(k)), k => k.slice(0, k.indexOf(':')));
  return {D, newKeys, newRels, mentions, byKind, scanned:recs.length, relsFound:rels.length};
}
function applyPlan(caseId, P, tag){
  const made = [], links = [], idOf = new Map(P.D.entries.map(e => [entryKey(e), e.id]).filter(x => x[0]));
  for(const k of P.newKeys){ const t = entryFor(k); if(!t) continue; const m = P.mentions.get(k), vd = verdictOf(k);
    const e = {id:uid('v'), caseId, type:t.type, fields:t.fields, priority:vd === 'malicious' ? 'high' : 'medium', starred:false, tags:['auto'], notes:'Added from evidence' + (tag ? ' (' + tag + ')' : '') + '.', src:m ? m.rec : '', created:Date.now(), pos:null};
    made.push(e); idOf.set(k, e.id); }
  for(const x of P.newRels){ const a = idOf.get(x.a), b = idOf.get(x.b); if(!a || !b || a === b) continue; links.push({id:uid('l'), caseId, a, b, label:x.label, conf:x.conf, src:x.rec, auto:true, why:x.why}); }
  DB.entries.push(...made); DB.links.push(...links); placeNew(caseId, made.map(e => e.id));
  return {made, links};
}
/* place new nodes next to what they connect to, instead of re-shuffling the whole graph */
function placeNew(caseId, ids){
  if(!ids.length) return; const set = new Set(ids), all = DB.entries.filter(e => e.caseId === caseId), placed = all.filter(e => e.pos && !set.has(e.id));
  const L = DB.links.filter(l => l.caseId === caseId);
  if(!placed.length){ ensurePositions(); return; }
  const xs = placed.map(e => e.pos.x), ys = placed.map(e => e.pos.y), cx = (Math.min(...xs) + Math.max(...xs)) / 2, maxX = Math.max(...xs), cyy = (Math.min(...ys) + Math.max(...ys)) / 2;
  let orphan = 0; const ring = new Map();
  for(let pass = 0; pass < 3; pass++) for(const e of all){ if(!set.has(e.id) || e.pos) continue;
    const nb = L.filter(l => l.a === e.id || l.b === e.id).map(l => entryById(l.a === e.id ? l.b : l.a)).find(n => n && n.pos);
    if(nb){ const n = (ring.get(nb.id) || 0) + 1; ring.set(nb.id, n); const ang = n * 2.4, rad = 130 + 22 * Math.floor(n / 6); e.pos = {x:nb.pos.x + Math.cos(ang) * rad, y:nb.pos.y + Math.sin(ang) * rad}; }
    else if(pass === 2){ const col = orphan % 4, row = Math.floor(orphan / 4); orphan++; e.pos = {x:maxX + 200 + col * 150, y:cyy - 150 + row * 120}; } }
}

/* ---------- auto-add after capture ---------- */
const GRAPH_DEFAULTS = () => ({kinds:GRAPH_KINDS.slice(), skipPrivate:true, skipBenign:true, focus:false, min:1});
function graphOpts(c){ return Object.assign(GRAPH_DEFAULTS(), c.graphOpts || {}); }
function afterCapture(caseId, recIds){
  const c = theCase(caseId); if(!c || !c.autoGraph || !recIds.length) return null;
  const P = graphPlan(caseId, graphOpts(c), recIds);
  if(P.newKeys.length > 40){ toast(P.newKeys.length + ' new entities — too many to add blindly. Review them in Graph → Build from evidence.'); return null; }
  if(!P.newKeys.length && !P.newRels.length) return null;
  const res = applyPlan(caseId, P, 'auto'); mutate('auto-added ' + res.made.length + ' entities to the graph'); return res;
}

/* ---------- build dialog ---------- */
let BUILD = null;
function buildDlg(){
  const c = theCase(); BUILD = {opts:graphOpts(c), auto:!!c.autoGraph};
  openDlg(dhead('Build the graph from evidence') + `<div class="in" id="bgIn"></div>
    <footer><label class="chk" style="margin-right:auto"><span class="sw"><input type="checkbox" id="bgAuto"${BUILD.auto ? ' checked' : ''}><span></span></span>Keep adding new captures automatically</label><button class="btn" data-act="dclose">Cancel</button><button class="btn primary" data-act="bgGo" id="bgGo">Add</button></footer>`, true, () => { paintBuild(); $('bgAuto').onchange = e => { BUILD.auto = e.target.checked; }; });
}
function paintBuild(){
  const o = BUILD.opts, P = graphPlan(DB.active, o); BUILD.plan = P;
  const kchk = k => { const n = P.byKind.find(x => x[0] === k); return `<label class="chk kchk"><input type="checkbox" data-bk="${k}"${o.kinds.includes(k) ? ' checked' : ''}>${esc(E.LABEL[k] || k)}${n ? ` <b>${n[1]}</b>` : ''}</label>`; };
  const labels = countBy(P.newRels, x => x.label);
  $('bgIn').innerHTML = `<p class="t2" style="margin:0 0 14px;font-size:14px">Scanned <b style="color:var(--text)">${P.scanned}</b> records. Relations written in the evidence — DNS answers, email headers, WHOIS, “resolves to”, “aka”, URLs and their domains — become relationships. Everything else is added unlinked and appears under <b style="color:var(--text)">Suggested links</b> for you to decide.</p>
    ${P.byKind.length ? '' : `<p class="note" style="margin:0 0 12px"><span class="ic">${ico('check','sm')}</span><span>Every entity in this case's evidence is already on the graph.</span></p>`}
    ${KIND_GROUP_LABEL.map(([g, l, ks]) => { const list = ks.split(' ').filter(k => P.byKind.some(x => x[0] === k)); return list.length ? `<div class="bgrow"><span class="caps">${l}</span><div class="wrap">${list.map(kchk).join('')}</div></div>` : ''; }).join('')}
    <div class="bgopts"><label class="chk"><input type="checkbox" id="bgPriv"${o.skipPrivate ? ' checked' : ''}>Skip private and reserved IPs</label><label class="chk"><input type="checkbox" id="bgBen"${o.skipBenign ? ' checked' : ''}>Skip entities marked benign</label>
      <label class="chk"><input type="checkbox" id="bgFocus"${o.focus ? ' checked' : ''}>Only malicious, suspicious, watched, or with a stated relation</label>
      <label class="chk">Mentioned at least <select id="bgMin" class="gsel bord">${[1,2,3,5].map(n => `<option${o.min === n ? ' selected' : ''}>${n}</option>`).join('')}</select> time(s)</label></div>
    <div class="bgsum"><div><b>${P.newKeys.length}</b><span>new entities</span></div><div><b>${P.newRels.length}</b><span>relationships stated in evidence</span></div><div><b>${P.D.entries.length}</b><span>already in the graph</span></div></div>
    ${P.newRels.length ? `<div class="bgrels">${Object.entries(Object.fromEntries(labels)).map(([l, n]) => `<span class="chip sq">${esc(l)} <b>${n}</b></span>`).join('')}</div>` : ''}
    ${P.newKeys.length > 80 ? `<p class="note amber" style="margin-top:12px"><span class="ic">${ico('triangle-alert','sm')}</span><span>That is a lot of nodes. Consider “Only malicious… or with a stated relation”, or a higher mention count.</span></p>` : ''}`;
  $('bgGo').textContent = P.newKeys.length || P.newRels.length ? `Add ${P.newKeys.length} ${P.newKeys.length === 1 ? 'entity' : 'entities'}${P.newRels.length ? ' and ' + P.newRels.length + ' relationships' : ''}` : 'Save setting';
  $('bgIn').querySelectorAll('[data-bk]').forEach(x => x.onchange = () => { o.kinds = x.checked ? [...new Set(o.kinds.concat(x.dataset.bk))] : o.kinds.filter(k => k !== x.dataset.bk); paintBuild(); });
  $('bgPriv').onchange = e => { o.skipPrivate = e.target.checked; paintBuild(); }; $('bgBen').onchange = e => { o.skipBenign = e.target.checked; paintBuild(); };
  $('bgFocus').onchange = e => { o.focus = e.target.checked; paintBuild(); }; $('bgMin').onchange = e => { o.min = +e.target.value; paintBuild(); };
}
async function buildGo(){
  const c = theCase(), P = BUILD.plan; c.graphOpts = BUILD.opts; c.autoGraph = BUILD.auto;
  if(!P.newKeys.length && !P.newRels.length){ closeDlg(); mutate('graph settings'); return toast(c.autoGraph ? 'New captures will be added to the graph' : 'Saved'); }
  await snapshot('Before building the graph of ' + c.code);
  const res = applyPlan(c.id, P, 'build'); closeDlg(); mutate('built graph: ' + res.made.length + ' entities, ' + res.links.length + ' relationships'); UI.graph.views = {}; renderAll();
  toast(`${res.made.length} entities and ${res.links.length} relationships added`, 'Undo', () => { const s = new Set(res.made.map(e => e.id)), sl = new Set(res.links.map(l => l.id)); DB.entries = DB.entries.filter(e => !s.has(e.id)); DB.links = DB.links.filter(l => !sl.has(l.id)); mutate('undid graph build'); renderAll(); });
}

/* ---------- 2. suggested links ---------- */
const lev = (a, b) => { if(a === b) return 0; const m = a.length, n = b.length; if(!m || !n) return m || n; let p = Array.from({length:n + 1}, (_, j) => j);
  for(let i = 1; i <= m; i++){ const q = [i]; for(let j = 1; j <= n; j++) q[j] = Math.min(p[j] + 1, q[j - 1] + 1, p[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)); p = q; } return p[n]; };
function identName(e){ const t = e.type, f = e.fields;
  if(t === 'username') return (f.username || '').replace(/^@/, ''); if(t === 'social') return (f.username || ''); if(t === 'email') return (f.email || '').split('@')[0];
  if(t === 'alias') return f.alias || ''; return ''; }
const nameCore = s => String(s).toLowerCase().replace(/[^a-z0-9]/g, '').replace(/\d{2,}$/, '');
function suggestLinks(caseId){
  const c = theCase(caseId), D = derive(caseId), dis = c.dismissed || {}, S = new Map();
  const byKey = D.byKey, linked = new Set(D.links.map(l => [l.a, l.b].sort().join('|')));
  const put = (a, b, label, score, why, rec, kind) => { if(!a || !b || a.id === b.id) return; const pk = [a.id, b.id].sort().join('|'); if(linked.has(pk) || dis[pk]) return;
    const s = S.get(pk); if(s){ s.score += score * .5; if(!s.why.includes(why)) s.why.push(why); if(score > s.top){ s.top = score; s.label = label; s.a = a; s.b = b; s.kind = kind; } if(rec && !s.rec) s.rec = rec; return; }
    S.set(pk, {pk, a, b, label, score, top:score, why:[why], rec, kind}); };
  /* together in the same evidence */
  const co = new Map();
  for(const r of D.recs){ const es = [...new Set(r.ents.map(gkey).filter(Boolean))].map(k => byKey.get(k)).filter(Boolean);
    if(es.length > 12) continue; for(let i = 0; i < es.length; i++) for(let j = i + 1; j < es.length; j++){ const pk = [es[i].id, es[j].id].sort().join('|'), x = co.get(pk) || {a:es[i], b:es[j], n:0, rec:r.id}; x.n++; co.set(pk, x); } }
  for(const x of co.values()) put(x.a, x.b, 'seen with', 1 + Math.min(3, x.n), `Together in ${x.n} record${x.n > 1 ? 's' : ''}`, x.rec, 'co');
  /* near in time on the same host */
  const timed = D.recs.filter(r => r.ts && r.host).sort((a, b) => a.ts - b.ts);
  for(let i = 0; i < timed.length; i++) for(let j = i + 1; j < timed.length && timed[j].ts - timed[i].ts <= 120000; j++){
    if(timed[i].host !== timed[j].host) continue; const ea = timed[i].ents.map(gkey).map(k => byKey.get(k)).filter(Boolean), eb = timed[j].ents.map(gkey).map(k => byKey.get(k)).filter(Boolean);
    for(const a of ea.slice(0, 4)) for(const b of eb.slice(0, 4)) if(entryVerdict(a) === 'malicious' || entryVerdict(b) === 'malicious') put(a, b, 'seen with', 1, `Within ${E.fmtGap(timed[j].ts - timed[i].ts)} on ${timed[i].host}`, timed[j].id, 'time'); }
  /* look-alike identities */
  const ids = D.entries.map(e => ({e, n:identName(e)})).filter(x => x.n && x.n.length >= 4);
  for(let i = 0; i < ids.length; i++) for(let j = i + 1; j < ids.length; j++){ const A = ids[i], B = ids[j]; if(A.e.type === B.e.type && A.e.type !== 'social') continue;
    const a = nameCore(A.n), b = nameCore(B.n); if(a.length < 4 || b.length < 4) continue;
    if(a === b) put(A.e, B.e, 'same person as', 4, `Same name “${A.n}” / “${B.n}”`, null, 'ident');
    else if(Math.max(a.length, b.length) >= 6 && 1 - lev(a, b) / Math.max(a.length, b.length) >= .8) put(A.e, B.e, 'same person as', 2, `Look-alike names “${A.n}” / “${B.n}”`, null, 'ident'); }
  /* structure the evidence did not state */
  for(const e of D.entries){ const k = entryKey(e); if(!k) continue;
    if(e.type === 'email'){ const d = byKey.get('domain:' + (e.fields.email || '').split('@')[1]); if(d) put(e, d, 'email at', 4, 'The address is at this domain', e.src, 'struct'); }
    if(e.type === 'url'){ const h = ((e.fields.url || '').match(/^https?:\/\/(?:[^/@\s]*@)?([^/:?#\s]+)/i) || [])[1]; const d = h && (byKey.get('domain:' + h.toLowerCase()) || byKey.get('ipv4:' + h)); if(d) put(e, d, 'hosted on', 4, 'The URL is on this host', e.src, 'struct'); } }
  /* shared infrastructure through links you already drew */
  const out = new Map(); for(const l of D.links){ (out.get(l.b) || out.set(l.b, []).get(l.b)).push(l); }
  for(const [tgt, ls] of out){ const t = entryById(tgt); if(!t) continue; const lab = t.type === 'ip' ? 'shares IP with' : t.type === 'email' ? 'same registrant as' : null; if(!lab) continue;
    const srcs = ls.filter(l => /resolves|hosted|registered/.test(l.label)).map(l => entryById(l.a)).filter(Boolean);
    for(let i = 0; i < srcs.length; i++) for(let j = i + 1; j < srcs.length; j++) put(srcs[i], srcs[j], lab, 3, `Both point to ${primary(t)}`, null, 'infra'); }
  return [...S.values()].sort((x, y) => y.score - x.score).slice(0, 80);
}
function acceptSugg(s, conf){ const c = theCase(); const l = {id:uid('l'), caseId:c.id, a:s.a.id, b:s.b.id, label:s.label, conf:conf || (s.top >= 4 ? 2 : 1), src:s.rec || '', auto:true, why:s.why.join(' · ')}; DB.links.push(l); return l; }

/* ---------- expand a node from evidence ---------- */
function expandNode(id){
  const e = entryById(id), k = entryKey(e); if(!k) return toast('This entry has no value to look for in the evidence');
  const D = derive(), recs = D.recs.filter(r => r.ents.some(x => gkey(x) === k)); if(!recs.length) return toast('Not mentioned in any record of this case');
  const P = graphPlan(DB.active, {kinds:GRAPH_KINDS, skipPrivate:false, skipBenign:false, focus:false, min:1}, recs.map(r => r.id));
  const keys = P.newKeys.slice(0, 25), res = applyPlan(DB.active, {...P, newKeys:keys, newRels:P.newRels.filter(x => keys.includes(x.a) || keys.includes(x.b) || D.byKey.has(x.a) && D.byKey.has(x.b))}, 'expanded');
  const idOf = new Map(DB.entries.filter(x => x.caseId === DB.active).map(x => [entryKey(x), x.id])), got = new Set(res.links.flatMap(l => [l.a, l.b]));
  for(const x of res.made){ if(got.has(x.id)) continue; const r = recs.find(r => r.ents.some(y => gkey(y) === entryKey(x)));
    res.links.push(...[{id:uid('l'), caseId:DB.active, a:id, b:x.id, label:'seen with', conf:1, src:r ? r.id : '', auto:true, why:'Mentioned in the same evidence'}]); DB.links.push(res.links[res.links.length - 1]); }
  if(!res.made.length && !res.links.length) return toast('Everything in its evidence is already on the graph');
  mutate('expanded ' + primary(e)); renderAll();
  toast(`${res.made.length} entities and ${res.links.length} links from ${recs.length} record${recs.length > 1 ? 's' : ''}${P.newKeys.length > 25 ? ' (first 25)' : ''}`, 'Undo', () => { const s = new Set(res.made.map(x => x.id)), sl = new Set(res.links.map(l => l.id)); DB.entries = DB.entries.filter(x => !s.has(x.id)); DB.links = DB.links.filter(l => !sl.has(l.id)); mutate('undid expand'); renderAll(); });
}

/* ---------- graph insights ---------- */
function graphInsights(){
  if(!cy) return null; const nodes = cy.nodes(); if(nodes.length < 2) return null;
  const bc = cy.elements().betweennessCentrality({directed:false});
  const hubs = nodes.sort((a, b) => b.degree(false) - a.degree(false)).slice(0, 5).filter(n => n.degree(false) > 0).map(n => ({id:n.id(), v:n.degree(false)}));
  const bridges = nodes.map(n => ({id:n.id(), v:bc.betweenness(n)})).filter(x => x.v > 0).sort((a, b) => b.v - a.v).slice(0, 5);
  /* label propagation communities */
  const lab = new Map(nodes.map(n => [n.id(), n.id()]));
  for(let it = 0; it < 12; it++){ let ch = 0; nodes.forEach(n => { const cnt = new Map(); n.neighborhood('node').forEach(m => { const l = lab.get(m.id()); cnt.set(l, (cnt.get(l) || 0) + 1); });
    if(!cnt.size) return; const best = [...cnt.entries()].sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1))[0][0]; if(best !== lab.get(n.id())){ lab.set(n.id(), best); ch++; } }); if(!ch) break; }
  const groups = new Map(); for(const [id, l] of lab){ (groups.get(l) || groups.set(l, []).get(l)).push(id); }
  const clusters = [...groups.values()].filter(g => g.length > 1).sort((a, b) => b.length - a.length);
  const next = nodes.filter(n => !entryVerdict(entryById(n.id()))).map(n => ({id:n.id(), v:n.neighborhood('node').filter(m => entryVerdict(entryById(m.id())) === 'malicious').length})).filter(x => x.v > 0).sort((a, b) => b.v - a.v).slice(0, 6);
  const lonely = nodes.filter(n => n.degree(false) === 0).map(n => n.id());
  return {hubs, bridges, clusters, next, lonely, lab};
}
const CLUSTER_COLS = ['#5470f5','#e8590c','#0ea5a4','#d6336c','#2f9e44','#8b5cf6','#e0a800','#64748b'];
function applyClusters(){ if(!cy) return; cy.nodes().removeStyle('underlay-color underlay-opacity underlay-padding underlay-shape'); if(!UI.graph.clusters) return;
  const I = graphInsights(); if(!I) return; I.clusters.forEach((g, i) => g.forEach(id => cy.getElementById(id).style({'underlay-color':CLUSTER_COLS[i % CLUSTER_COLS.length], 'underlay-opacity':.28, 'underlay-padding':12, 'underlay-shape':'ellipse'}))); }

/* side panel inside the graph: Suggestions | Insights */
function gPanelHTML(){
  const P = UI.graph.panel; if(!P) return '';
  if(P === 'sugg'){ const L = suggestLinks(DB.active); UI.graph.sugg = L;
    return `<aside class="gpanel" aria-label="Suggested links"><header><b>${ico('sparkles','sm')}Suggested links</b><span class="t3">${L.length}</span><span style="flex:1"></span><button class="iconbtn" data-act="gPanel" data-v="" aria-label="Close">${ico('x','sm')}</button></header>
      <p class="gp-note">Found by comparing your entries and evidence. Nothing is added until you accept it.</p>
      ${L.length ? `${L.some(s => s.top >= 4) ? `<div class="gp-bar"><button class="btn xs" data-act="sgAllStrong">${ico('check','sm')}Accept all strong (${L.filter(s => s.top >= 4).length})</button></div>` : ''}
      <div class="gp-list">${L.map((s, i) => `<div class="sg" data-i="${i}"><div class="sg-h"><span class="sg-n" title="${esc(primary(s.a))}">${esc(primary(s.a))}</span><span class="sg-l">${esc(s.label)}</span><span class="sg-n" title="${esc(primary(s.b))}">${esc(primary(s.b))}</span></div>
        <div class="sg-w">${s.top >= 4 ? '<span class="chip sq green">Strong</span>' : s.top >= 2 ? '<span class="chip sq">Likely</span>' : '<span class="chip sq">Weak</span>'} ${esc(s.why.join(' · '))}</div>
        <div class="sg-a">${s.rec && recById(s.rec) ? `<button class="btn xs ghost" data-act="selRec" data-id="${s.rec}">${ico('file-text','sm')}Evidence</button>` : ''}<span style="flex:1"></span><button class="btn xs ghost" data-act="sgNo" data-v="${i}">Dismiss</button><button class="btn xs primary" data-act="sgYes" data-v="${i}">${ico('check','sm')}Link</button></div></div>`).join('')}</div>`
      : `<div class="gp-empty">${ico('check','sm')} No suggestions right now. Capture more evidence or use <b>Build from evidence</b>.</div>`}</aside>`; }
  const I = graphInsights(); UI.graph.ins = I;
  const nm = id => { const e = entryById(id); return e ? esc(primary(e)) : '?'; };
  const row = (x, unit) => `<button class="gp-row" data-act="gFocus" data-id="${x.id}"><span>${nm(x.id)}</span><b>${unit === 'b' ? x.v.toFixed(1) : x.v}</b></button>`;
  return `<aside class="gpanel" aria-label="Graph insights"><header><b>${ico('radar','sm')}Insights</b><span style="flex:1"></span><button class="iconbtn" data-act="gPanel" data-v="" aria-label="Close">${ico('x','sm')}</button></header>
    ${!I ? `<div class="gp-empty">Add at least two connected entries.</div>` : `
    ${I.next.length ? `<section><h5>Look at next <span class="t3">no verdict, touches malicious</span></h5>${I.next.map(x => row(x)).join('')}</section>` : ''}
    <section><h5>Hubs <span class="t3">most connections</span></h5>${I.hubs.map(x => row(x)).join('') || '<p class="t3">—</p>'}</section>
    <section><h5>Bridges <span class="t3">connect separate groups</span></h5>${I.bridges.map(x => row(x, 'b')).join('') || '<p class="t3">None — every node has another route.</p>'}</section>
    <section><h5>Clusters <span class="t3">${I.clusters.length}</span></h5><label class="chk" style="margin:0 0 8px"><span class="sw"><input type="checkbox" data-act="gClusters"${UI.graph.clusters ? ' checked' : ''}><span></span></span>Colour by cluster</label>
      ${I.clusters.slice(0, 6).map((g, i) => `<div class="gp-cl"><i style="background:${CLUSTER_COLS[i % CLUSTER_COLS.length]}"></i><span>${g.slice(0, 3).map(nm).join(', ')}${g.length > 3 ? ` +${g.length - 3}` : ''}</span></div>`).join('')}</section>
    ${I.lonely.length ? `<section><h5>Unconnected <span class="t3">${I.lonely.length}</span></h5><p class="t3" style="margin:0 0 8px;font-size:12.5px">${I.lonely.slice(0, 6).map(nm).join(', ')}${I.lonely.length > 6 ? '…' : ''}</p><button class="btn xs" data-act="gPanel" data-v="sugg">${ico('sparkles','sm')}See suggested links</button></section>` : ''}`}</aside>`;
}
function bindGPanel(gp){
  gp.querySelectorAll('.sg').forEach(el => { const s = UI.graph.sugg[+el.dataset.i]; if(!s) return;
    el.onmouseenter = () => { if(!cy) return; const ns = cy.getElementById(s.a.id).union(cy.getElementById(s.b.id)); cy.elements().addClass('faded'); ns.removeClass('faded').addClass('hit'); };
    el.onmouseleave = () => { if(cy) cy.elements().removeClass('faded hit'); }; });
}
/* ---------- pick entities to put on the graph ---------- */
let PICK = null;
function pickDlg(){
  const P = graphPlan(DB.active, {kinds:GRAPH_KINDS, skipPrivate:false, skipBenign:false, focus:false, min:1});
  PICK = {P, sel:new Set(), q:'', kind:''};
  openDlg(dhead('Add entities to the graph') + `<div class="in"><p class="t2" style="margin:0 0 12px;font-size:14px">Everything below is mentioned in this case's evidence but is not on the graph yet. Adding an entity puts it in the vault and on the graph. Relations stated in the evidence between the ones you pick are linked too.</p>
    <div class="toolbar" style="margin:0 0 10px"><div class="search-in">${ico('search')}<label class="sr" for="pkQ">Search</label><input id="pkQ" class="inp" placeholder="Search…" autocomplete="off"></div><label class="sr" for="pkK">Kind</label><select id="pkK" class="gsel bord"><option value="">All kinds</option>${P.byKind.map(([k, n]) => `<option value="${k}">${esc(E.LABEL[k] || k)} (${n})</option>`).join('')}</select><button class="btn sm" data-act="pkAll">Select shown</button></div>
    <div id="pkList" class="pklist"></div></div>
    <footer><span class="t3" id="pkN" style="margin-right:auto;font-size:13.5px"></span><button class="btn" data-act="dclose">Cancel</button><button class="btn primary" data-act="pkGo" id="pkGo" disabled>Add to graph</button></footer>`, true, () => {
      $('pkQ').oninput = e => { PICK.q = e.target.value.toLowerCase(); paintPick(); }; $('pkK').onchange = e => { PICK.kind = e.target.value; paintPick(); }; paintPick(); });
}
function pickShown(){ const {P, q, kind} = PICK; return [...P.mentions.keys()].filter(k => !P.D.byKey.has(k) && entryFor(k) && (!kind || k.startsWith(kind + ':')) && (!q || k.toLowerCase().includes(q)))
  .sort((a, b) => ({malicious:0, suspicious:1, '':2, benign:3}[verdictOf(a)] - {malicious:0, suspicious:1, '':2, benign:3}[verdictOf(b)]) || P.mentions.get(b).n - P.mentions.get(a).n); }
function paintPick(){
  const L = pickShown(); PICK.shown = L;
  $('pkList').innerHTML = L.length ? L.slice(0, 300).map(k => { const {k:kind, v} = entSplit(k), n = PICK.P.mentions.get(k).n;
    return `<label class="pk${PICK.sel.has(k) ? ' on' : ''}"><input type="checkbox" data-pk="${esc(k)}"${PICK.sel.has(k) ? ' checked' : ''}>${kindBadge(kind,'sm')}<span class="pkv"><span class="mono">${esc(v)}</span><small>${esc(E.LABEL[kind] || kind)} · ${n} mention${n > 1 ? 's' : ''} ${vdLabel(verdictOf(k))} ${ctxChips(kind, v)}</small></span></label>`; }).join('')
    : `<p class="t3" style="margin:12px 0">${PICK.P.mentions.size ? 'Everything is already on the graph.' : 'No entities in this case\'s evidence yet.'}</p>`;
  $('pkList').querySelectorAll('[data-pk]').forEach(x => x.onchange = () => { x.checked ? PICK.sel.add(x.dataset.pk) : PICK.sel.delete(x.dataset.pk); x.closest('.pk').classList.toggle('on', x.checked); pickCount(); });
  pickCount();
}
function pickCount(){ const n = PICK.sel.size; $('pkN').textContent = n ? n + ' selected' : ''; $('pkGo').disabled = !n; $('pkGo').textContent = n ? `Add ${n} to graph` : 'Add to graph'; }
function pickGo(){
  const keys = [...PICK.sel], P = PICK.P, keep = new Set([...keys, ...P.D.byKey.keys()]);
  const all = graphPlan(DB.active, {kinds:GRAPH_KINDS, skipPrivate:false, skipBenign:false, focus:false, min:1});
  const res = applyPlan(DB.active, {...all, newKeys:keys, newRels:all.newRels.filter(x => keep.has(x.a) && keep.has(x.b))}, 'picked');
  closeDlg(); mutate('added ' + res.made.length + ' entities to the graph'); renderAll();
  toast(`${res.made.length} added${res.links.length ? ', ' + res.links.length + ' linked from the evidence' : ''}`, 'Undo', () => { const s = new Set(res.made.map(e => e.id)), sl = new Set(res.links.map(l => l.id)); DB.entries = DB.entries.filter(e => !s.has(e.id)); DB.links = DB.links.filter(l => !sl.has(l.id)); mutate('undid add'); renderAll(); });
}
function missingCount(caseId){ const D = derive(caseId), s = new Set(); for(const r of D.recs) for(const e of r.ents){ const g = gkey(e); if(g && !D.byKey.has(g) && entryFor(g)) s.add(g); } return s.size; }
const REL_ACTS = {
  gPick:() => pickDlg(), pkGo:() => pickGo(), pkAll:() => { for(const k of PICK.shown.slice(0, 300)) PICK.sel.add(k); paintPick(); },
  gNoteOff:() => { (UI.graph.noteOff || (UI.graph.noteOff = new Set())).add(DB.active); renderMain(); },
  gBuild:() => buildDlg(), bgGo:() => buildGo(),
  gPanel:(id, v) => { UI.graph.panel = v || null; renderMain(); },
  gExpand:id => expandNode(id),
  gFocus:id => { if(!cy) return; const n = cy.getElementById(id); if(!n.length) return; cy.animate({center:{eles:n}, zoom:Math.max(cy.zoom(), 1)}, {duration:250}); cy.nodes().unselect(); n.select(); selectEntry(id, true); },
  gClusters:(id, v, t) => { UI.graph.clusters = t.checked; applyClusters(); },
  sgYes:(id, v) => { const s = UI.graph.sugg[+v]; if(!s) return; const l = acceptSugg(s); mutate('linked ' + primary(s.a) + ' — ' + s.label); renderAll();
    toast('Linked: ' + s.label, 'Undo', () => { DB.links = DB.links.filter(x => x !== l); mutate('undid link'); renderAll(); }); },
  sgNo:(id, v) => { const s = UI.graph.sugg[+v]; if(!s) return; const c = theCase(); (c.dismissed || (c.dismissed = {}))[s.pk] = Date.now(); mutate('dismissed suggestion'); renderMain(); },
  sgAllStrong:() => { const L = UI.graph.sugg.filter(s => s.top >= 4), made = L.map(s => acceptSugg(s)); mutate('accepted ' + made.length + ' suggestions'); renderAll();
    toast(made.length + ' links added', 'Undo', () => { const s = new Set(made.map(l => l.id)); DB.links = DB.links.filter(l => !s.has(l.id)); mutate('undid links'); renderAll(); }); }
};
