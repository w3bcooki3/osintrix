/* ==========================================================================
   Money trail — a Bitcoin or Ethereum wallet's transactions, and what they
   say: who paid it, whom it paid, how much and when, which wallets were
   probably the same owner, and whether any of them is sanctioned, labelled
   or already in your cases.
   Two ways in, one result:
     · fetched from mempool.space (Bitcoin) or Blockscout (Ethereum) — only
       the wallet address is sent, and only after you switch that source on
     · imported from a file you exported (Etherscan CSV, or any CSV with
       from / to / amount columns) — nothing leaves the browser
   The sanctions list (OFAC, as published in 0xB10C's nightly list) is
   downloaded once and checked locally from then on.
   Everything is kept in DB.chain; amounts are whole units (satoshi, wei) in
   strings, because they do not fit in a JavaScript number.
   ========================================================================== */
const CH = {STEP:200, MAX:5000, ROWS:400, TL:300};
const CH_NATIVE = {btc:{sym:'BTC', dec:8, name:'Bitcoin', prov:'mempool', tx:'https://mempool.space/tx/', addr:'https://mempool.space/address/'},
  eth:{sym:'ETH', dec:18, name:'Ethereum', prov:'bscout', tx:'https://eth.blockscout.com/tx/', addr:'https://eth.blockscout.com/address/'}};
const CH_SANC_URL = 'https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_';
const CH_SANC_LISTS = [['XBT', 'btc'], ['ETH', 'eth'], ['USDT', ''], ['USDC', ''], ['TRX', 'trx']];
const CH_KINDS = [['exchange', 'Exchange'], ['mixer', 'Mixer'], ['service', 'Service or merchant'], ['scam', 'Scam or fraud'], ['victim', 'Victim'], ['suspect', 'Suspect'], ['other', 'Other']];

function chDB(){ const C = DB.chain = DB.chain && typeof DB.chain === 'object' ? DB.chain : {};
  for(const k of ['tx', 'addr', 'meta', 'labels']) if(!C[k] || typeof C[k] !== 'object' || Array.isArray(C[k])) C[k] = {}; return C; }
const chOf = k => k === 'btc' || k === 'eth' ? k : null;
const chNorm = (c, a) => { a = String(a || '').trim(); return c === 'eth' || /^(bc1|tb1)/i.test(a) ? a.toLowerCase() : a; };
const chGuess = a => /^0x[0-9a-f]{40}$/i.test(a) ? 'eth' : /^(bc1|tb1|[13mn2])[a-zA-HJ-NP-Z0-9]{20,90}$/.test(a) ? 'btc' : null;
const chShort = a => a && a.length > 18 ? a.slice(0, 10) + '…' + a.slice(-6) : a || '';
let CH_REV = 0; const chTouch = () => { CH_REV++; CH_IDX = null; };

/* ---------- amounts ---------- */
const chBig = v => { try{ return BigInt(String(v || '0')); }catch(e){ return 0n; } };
function chFmt(v, dec, sym){
  let b = typeof v === 'bigint' ? v : chBig(v); const neg = b < 0n; if(neg) b = -b;
  const s = b.toString().padStart(dec + 1, '0'); let i = s.slice(0, s.length - dec), f = dec ? s.slice(s.length - dec).replace(/0+$/, '') : '';
  if(f.length > 8){ f = f.slice(0, 8).replace(/0+$/, ''); if(!f && i === '0') f = '00000001'.slice(0, 0) || ''; }
  const out = i.replace(/\B(?=(\d{3})+(?!\d))/g, ',') + (f ? '.' + f : '');
  return (neg ? '−' : '') + (out === '0' && b > 0n ? '<0.00000001' : out) + (sym ? ' ' + sym : '');
}
function chUnits(str, dec){
  const m = /^\s*(-?)(\d*)(?:\.(\d*))?\s*$/.exec(String(str == null ? '' : str).replace(/[,\s]/g, '')); if(!m || (!m[2] && !m[3])) return null;
  const r = BigInt((m[2] || '0') + (m[3] || '').slice(0, dec).padEnd(dec, '0')); return (m[1] ? -r : r).toString();
}
const chAsset = (c, t) => t && t.tok ? {sym:t.tok.s || 'token', dec:t.tok.d, tok:t.tok.a || t.tok.s} : {sym:CH_NATIVE[c].sym, dec:CH_NATIVE[c].dec, tok:''};

/* ---------- what is known about any address: sanctions, your labels, public tags, your cases ---------- */
function chSanc(c, a){ const S = chDB().sanc; if(!S) return false; const n = chNorm(c, a); if(!S._set){ S._set = new Set([...(S.btc || []), ...(S.eth || []), ...(S.trx || [])].map(x => /^0x/i.test(x) || /^(bc1|tb1)/i.test(x) ? x.toLowerCase() : x)); } return S._set.has(n); }
let CH_CASES = {at:-1, m:null};
function chInCases(c, a){
  if(CH_CASES.at !== rev){ const m = new Map(); for(const e of DB.entries) if(e.type === 'crypto'){ const v = primary(e), g = chGuess(v); if(g) { const k = g + ':' + chNorm(g, v); if(!m.has(k)) m.set(k, []); m.get(k).push(e); } } CH_CASES = {at:rev, m}; }
  return CH_CASES.m.get(c + ':' + chNorm(c, a)) || [];
}
function chLabels(c, a){
  const C = chDB(), n = chNorm(c, a), out = [], L = C.labels[c + ':' + n], M = C.meta[c + ':' + n];
  if(chSanc(c, a)) out.push({t:'Sanctioned (OFAC)', lvl:'bad'});
  if(L) out.push({t:L.t, lvl:L.kind === 'mixer' || L.kind === 'scam' ? 'warn' : 'info', kind:L.kind, mine:1});
  if(M){ if(M.scam) out.push({t:'Flagged as scam by Blockscout', lvl:'warn'}); if(M.ens) out.push({t:M.ens, lvl:'info', ens:1}); for(const t of (M.tags || []).slice(0, 3)) out.push({t, lvl:/tornado|mixer|blender|sinbad|wasabi|samourai|coinjoin|exploit|hack|phish|scam|drainer|lazarus/i.test(t) ? 'warn' : 'info'}); if(M.contract) out.push({t:'Contract', lvl:'info'}); }
  const E2 = chInCases(c, a); if(E2.length) out.push({t:'In ' + [...new Set(E2.map(e => caseNm(e.caseId)).filter(Boolean))].join(', '), lvl:'case', ids:E2.map(e => e.id)});
  return out;
}
const chChips = L => L.map(l => `<span class="chx ${l.lvl}">${l.lvl === 'bad' ? ico('shield-alert','sm') : l.lvl === 'case' ? ico('folder-open','sm') : ''}${esc(l.t)}</span>`).join('');

/* ---------- reading what the sources send ---------- */
function chBtcTx(x){
  const ins = (x.vin || []).slice(0, 400).map(v => [v.is_coinbase ? 'coinbase' : String(v.prevout && v.prevout.scriptpubkey_address || 'unknown').slice(0, 100), String(v.prevout ? +v.prevout.value || 0 : 0)]);
  const outs = (x.vout || []).slice(0, 400).map(v => [String(v.scriptpubkey_address || (v.scriptpubkey_type === 'op_return' ? 'OP_RETURN' : 'unknown')).slice(0, 100), String(+v.value || 0)]);
  const t = x.status && x.status.block_time ? x.status.block_time * 1000 : 0;
  return {id:'btc:' + x.txid, c:'btc', h:String(x.txid).slice(0, 80), t, b:x.status && x.status.block_height || 0, f:String(+x.fee || 0), i:ins, o:outs, ok:true, pend:!t};
}
function chMetaFrom(o){ if(!o || !o.hash) return; const C = chDB(), k = 'eth:' + chNorm('eth', o.hash), tags = ((o.metadata && o.metadata.tags) || []).map(t => String(t.name || '').slice(0, 60)).filter(Boolean).concat((o.public_tags || []).map(t => String(t.display_name || t.label || '').slice(0, 60)).filter(Boolean)).concat(o.name ? [String(o.name).slice(0, 60)] : []);
  if(!tags.length && !o.ens_domain_name && !o.is_scam && !o.is_contract) return; C.meta[k] = {ens:o.ens_domain_name ? String(o.ens_domain_name).slice(0, 120) : '', tags:[...new Set(tags)].slice(0, 6), scam:!!o.is_scam, contract:!!o.is_contract}; }
function chEthTx(x){ chMetaFrom(x.from); chMetaFrom(x.to); const to = x.to ? x.to.hash : x.created_contract ? x.created_contract.hash : 'contract creation';
  return {id:'eth:' + x.hash, c:'eth', h:String(x.hash).slice(0, 80), t:Date.parse(x.timestamp) || 0, b:+x.block_number || 0, f:String(x.fee && x.fee.value || '0'), i:[[String(x.from && x.from.hash || 'unknown'), String(x.value || '0')]], o:[[String(to), String(x.value || '0')]], ok:x.status !== 'error' && x.result !== 'error' && !/revert|fail/i.test(x.result || ''), m:x.method ? String(x.method).slice(0, 40) : ''}; }
function chEthTok(x){ if(x.token_type && x.token_type !== 'ERC-20') return null; chMetaFrom(x.from); chMetaFrom(x.to); const T = x.token || {}, v = x.total && x.total.value; if(v == null) return null;
  return {id:'eth:' + x.transaction_hash + ':' + (x.log_index != null ? x.log_index : 0), c:'eth', h:String(x.transaction_hash).slice(0, 80), t:Date.parse(x.timestamp) || 0, b:+x.block_number || 0, f:'0', i:[[String(x.from && x.from.hash || 'unknown'), String(v)]], o:[[String(x.to && x.to.hash || 'unknown'), String(v)]], ok:true,
    tok:{s:String(T.symbol || '?').slice(0, 20), d:Math.min(36, +(x.total.decimals || T.decimals) || 0), a:String(T.address_hash || T.address || '').slice(0, 60), n:String(T.name || '').slice(0, 60)}}; }

/* ---------- fetching ---------- */
async function chGet(p, url){ await lkPace(p.id); const r = await lkFetch(url, {timeout:25000}); if(r.status === 400 || r.status === 404) throw new Error('The source does not know this address'); if(r.status >= 400) throw new Error('HTTP ' + r.status); try{ return JSON.parse(r.text); }catch(e){ throw new Error('Not JSON'); } }
async function chFetch(c, a, more){
  const C = chDB(), n = chNorm(c, a), key = c + ':' + n, p = lkProv(CH_NATIVE[c].prov), R = C.addr[key] = C.addr[key] || {a, c, ids:[]};
  if(!more){ R.ids = []; R.cur = R.curT = ''; R.done = R.doneT = false; }
  const got = [], raw = [], limit = Math.min(CH.STEP, CH.MAX - R.ids.length); if(limit <= 0) return {n:0};
  if(c === 'btc'){ const base = 'https://mempool.space/api/address/' + encodeURIComponent(a);
    const S = await chGet(p, base), cs = S.chain_stats || {}, ms = S.mempool_stats || {};
    R.n = (+cs.tx_count || 0) + (+ms.tx_count || 0); R.bal = String((+cs.funded_txo_sum || 0) - (+cs.spent_txo_sum || 0) + (+ms.funded_txo_sum || 0) - (+ms.spent_txo_sum || 0));
    while(!R.done && got.length < limit){
      const L = await chGet(p, R.cur ? base + '/txs/chain/' + encodeURIComponent(R.cur) : base + '/txs'); if(!Array.isArray(L)) break;
      for(const x of L){ got.push(chBtcTx(x)); raw.push(x); } const conf = L.filter(x => x.status && x.status.confirmed);
      if(conf.length) R.cur = conf[conf.length - 1].txid; if(conf.length < 25) R.done = true; }
  } else {
    const base = 'https://eth.blockscout.com/api/v2/addresses/' + encodeURIComponent(a), S = await chGet(p, base);
    chMetaFrom(S); R.bal = String(S.coin_balance || '0'); R.n = null;
    const page = async (path, cur, map) => { const j = await chGet(p, base + path + (cur ? '?' + new URLSearchParams(JSON.parse(cur)).toString() : '')); for(const x of (j.items || [])){ const t = map(x); if(t){ got.push(t); raw.push(x); } } return j.next_page_params ? JSON.stringify(j.next_page_params) : ''; };
    while(!R.done && got.length < limit / 2){ R.cur = await page('/transactions', R.cur, chEthTx); if(!R.cur) R.done = true; }
    while(!R.doneT && got.length < limit){ R.curT = await page('/token-transfers', R.curT, chEthTok); if(!R.curT) R.doneT = true; }
    if(R.done && R.doneT) R.n = new Set(R.ids.concat(got.map(t => t.id))).size;
  }
  const text = raw.length ? JSON.stringify(c === 'btc' ? raw : {items:raw}) : '';
  if(!await stoGuard(JSON.stringify(got).length * 2 + text.length * 2, 'keep these transactions')) return {n:0};
  const seen = new Set(R.ids); for(const t of got){ C.tx[t.id] = t; if(!seen.has(t.id)){ seen.add(t.id); R.ids.push(t.id); } }
  R.at = Date.now(); R.src = p.host; chTouch();
  /* what the source sent is kept as evidence in the open case — the case's Money view reads it too */
  let rec = null; if(text && DB.active && typeof walletParse === 'function'){ const P = walletParse(text); if(P){ P.label = `${CH_NATIVE[c].name} transactions of ${chShort(a)} — ${got.length} from ${p.host}`; rec = walletKeep(text, P, DB.active, p.host); } }
  mutate('fetched transactions of ' + chShort(a)); return {n:got.length, rec};
}
const chMoreLeft = R => R && !(R.done && (R.c === 'btc' || R.doneT)) && R.ids.length < CH.MAX;

/* ---------- the trail of one wallet ---------- */
let CH_IDX = null;
function chTxIndex(){ if(CH_IDX) return CH_IDX; const m = new Map(); for(const t of Object.values(chDB().tx)){ const seen = new Set(); for(const [x] of t.i.concat(t.o)){ const k = t.c + ':' + chNorm(t.c, x); if(seen.has(k)) continue; seen.add(k); let L = m.get(k); if(!L) m.set(k, L = []); L.push(t); } } return CH_IDX = m; }
const chCoinJoin = t => { if(t.c !== 'btc' || t.i.length < 3) return false; const f = {}; for(const [, v] of t.o) f[v] = (f[v] || 0) + 1; return Math.max(0, ...Object.values(f)) >= 3; };
function chTrail(c, a){
  const n = chNorm(c, a), txs = (chTxIndex().get(c + ':' + n) || []).slice().sort((x, y) => (y.t || 9e15) - (x.t || 9e15));
  const me = x => chNorm(c, x) === n, cps = new Map(), co = new Map(), rows = [], tot = {}; let first = 0, last = 0, cj = 0;
  const cp = x => { const k = chNorm(c, x); let r = cps.get(k); if(!r) cps.set(k, r = {a:x, n:0, amt:{}, first:0, last:0}); return r; };
  const add = (r, sym, dir, v) => { const s = r.amt[sym] = r.amt[sym] || {in:0n, out:0n}; s[dir] += v; };
  for(const t of txs){
    const A = chAsset(c, t), mi = t.i.filter(([x]) => me(x)).reduce((s, [, v]) => s + chBig(v), 0n), mo = t.o.filter(([x]) => me(x)).reduce((s, [, v]) => s + chBig(v), 0n);
    const T = tot[A.sym] = tot[A.sym] || {dec:A.dec, in:0n, out:0n, fee:0n, n:0}; T.n++; if(t.t){ if(!first || t.t < first) first = t.t; if(t.t > last) last = t.t; }
    const isCj = chCoinJoin(t); if(isCj) cj++;
    let dir, amt, who = [];
    if(mi > 0n){
      const coIn = new Set(t.i.map(([x]) => chNorm(c, x)).filter(x => x !== n && x !== 'coinbase' && x !== 'unknown'));
      if(!isCj) for(const x of coIn){ const r = co.get(x) || {a:t.i.find(([y]) => chNorm(c, y) === x)[0], n:0}; r.n++; co.set(x, r); }
      const outs = t.o.filter(([x]) => !me(x) && !coIn.has(chNorm(c, x)));
      if(c === 'eth' && !t.tok && t.ok !== false) T.fee += chBig(t.f);   /* a Bitcoin fee is already inside what left the wallet */
      if(t.ok === false){ dir = 'fail'; amt = 0n; }
      else { amt = mi - mo; dir = amt > 0n ? 'out' : 'self'; T.out += amt > 0n ? amt : 0n;
        /* what the transaction paid each recipient; in a CoinJoin the outputs are strangers' */
        if(!isCj) for(const [x, v] of outs){ const r = cp(x); add(r, A.sym, 'out', chBig(v)); who.push(x); } }
    } else if(mo > 0n){
      dir = t.ok === false ? 'fail' : 'in'; amt = t.ok === false ? 0n : mo; if(t.ok !== false) T.in += mo;
      const ins = t.i.filter(([x]) => !me(x)), tin = ins.reduce((s, [, v]) => s + chBig(v), 0n) || 1n;
      if(t.ok !== false) for(const [x, v] of ins){ const r = cp(x); add(r, A.sym, 'in', ins.length === 1 ? mo : mo * chBig(v) / tin); who.push(x); }
    } else continue;
    for(const x of new Set(who.map(y => chNorm(c, y)))){ const r = cps.get(x); if(!r) continue; r.n++; if(t.t){ if(!r.first || t.t < r.first) r.first = t.t; if(t.t > r.last) r.last = t.t; } }
    rows.push({t, dir, amt, A, who:[...new Set(who)], cj:isCj});
  }
  const nat = CH_NATIVE[c].sym, val = r => { const s = r.amt[nat]; return s ? s.in + s.out : 0n; };
  const list = [...cps.values()].map(r => Object.assign(r, {L:chLabels(c, r.a)})).sort((x, y) => (val(y) > val(x) ? 1 : val(y) < val(x) ? -1 : 0) || y.n - x.n);
  return {c, a, n:txs.length, rows, cps:list, co:[...co.values()].sort((x, y) => y.n - x.n), tot, first, last, cj, R:chDB().addr[c + ':' + n] || null, L:chLabels(c, a),
    sancCp:list.filter(r => r.L.some(l => l.lvl === 'bad'))};
}
const chAmt = (r, sym, dir) => r.amt[sym] ? r.amt[sym][dir] : 0n;
function chCpAmt(r, c){ const nat = CH_NATIVE[c], p = []; const s = r.amt[nat.sym];
  if(s){ if(s.in) p.push('<span class="ch-in">+' + esc(chFmt(s.in, nat.dec, nat.sym)) + '</span>'); if(s.out) p.push('<span class="ch-out">−' + esc(chFmt(s.out, nat.dec, nat.sym)) + '</span>'); }
  const toks = Object.keys(r.amt).filter(k => k !== nat.sym); if(toks.length) p.push('<span class="t3">' + esc(toks.slice(0, 2).join(', ')) + (toks.length > 2 ? ' +' + (toks.length - 2) : '') + '</span>');
  return p.join(' '); }

/* ---------- in the inspector ---------- */
function chSection(k, v){
  const c = chOf(k); if(!c) return ''; const N = CH_NATIVE[c], T = chTrail(c, v), p = lkProv(N.prov), on = p && lkSettings().on[p.id], S = chDB().sanc;
  const head = `<h4>Money trail <span class="t3">${T.n ? T.n.toLocaleString() + ' transaction' + (T.n === 1 ? '' : 's') + (T.R && T.R.src ? ' · ' + esc(T.R.src) + ' ' + esc(E.fmtAgo(Date.now() - T.R.at)) : ' · from your files') : 'who paid it, whom it paid'}</span></h4>`;
  const flags = []; if(T.L.some(l => l.lvl === 'bad')) flags.push(['bad', 'This wallet is on the OFAC sanctions list', 'Dealing with it can be illegal for US persons. List as of ' + E.fmtDate(S.at, tz()) + '.']);
  if(T.sancCp.length) flags.push(['bad', T.sancCp.length + ' counterpart' + (T.sancCp.length > 1 ? 'ies are' : 'y is') + ' sanctioned', T.sancCp.slice(0, 3).map(r => chShort(r.a)).join(', ') + ' — direct exposure, one step away.']);
  if(T.cj) flags.push(['warn', T.cj + ' transaction' + (T.cj > 1 ? 's look' : ' looks') + ' like CoinJoin', 'Mixing breaks the trail; ownership estimates skip them.']);
  const fl = flags.map(([l, t, w]) => `<div class="ipf-f ${l}"><span class="ipf-i">${ico(l === 'bad' ? 'shield-alert' : 'triangle-alert','sm')}</span><div><b>${esc(t)}</b><small>${esc(w)}</small></div></div>`).join('');
  const sancNote = S ? '' : `<p class="t3 small ch-sn">Sanctions: <button class="lnk" data-act="chSancGet">download the OFAC list once</button> to check every wallet here, offline from then on.</p>`;
  if(!T.n) return `<div class="isec ch">${head}${fl}${T.L.length ? `<div class="wrap ch-l">${chChips(T.L)}</div>` : ''}<p class="t2 small" style="margin:0 0 10px">Bring in its transactions to see the money: amounts, dates, counterparties, wallets that are probably the same owner.</p>
    <div class="wrap"><button class="btn sm primary" data-act="chGet" data-id="${esc(k + ':' + v)}">${ico('download','sm')}Fetch from ${esc(p.host)}</button><button class="btn sm" data-act="chImport" data-id="${esc(k + ':' + v)}">${ico('upload','sm')}Import a file…</button></div>
    <p class="t3 small ch-sn">${on ? 'Sends only this address to ' + esc(p.host) + '.' : 'Asks first: only this address would be sent, to ' + esc(p.host) + '.'} A file you exported works offline: explorer JSON (Blockstream, mempool.space, blockchain.com, BlockCypher, Etherscan, Blockscout), an Etherscan CSV, or any CSV with from, to and amount.</p>${sancNote}</div>`;
  const nat = T.tot[N.sym] || {in:0n, out:0n, fee:0n, dec:N.dec}, toks = Object.keys(T.tot).filter(x => x !== N.sym);
  return `<div class="isec ch">${head}${fl}${T.L.length ? `<div class="wrap ch-l">${chChips(T.L)}</div>` : ''}
    <dl class="kv ch-kv">${T.R && T.R.bal != null ? `<dt>Balance</dt><dd>${esc(chFmt(T.R.bal, N.dec, N.sym))} <span class="t3">when fetched</span></dd>` : ''}<dt>Received</dt><dd><span class="ch-in">${esc(chFmt(nat.in, N.dec, N.sym))}</span></dd><dt>Sent</dt><dd><span class="ch-out">${esc(chFmt(nat.out, N.dec, N.sym))}</span>${nat.fee ? ` <span class="t3">+ ${esc(chFmt(nat.fee, N.dec))} in fees</span>` : ''}</dd>
      ${toks.length ? `<dt>Tokens</dt><dd>${esc(toks.slice(0, 5).join(', '))}${toks.length > 5 ? ' +' + (toks.length - 5) : ''}</dd>` : ''}${T.first ? `<dt>Active</dt><dd>${esc(E.fmtDate(T.first, tz()))}${T.last > T.first ? ' – ' + esc(E.fmtDate(T.last, tz())) : ''}</dd>` : ''}
      <dt>Transactions</dt><dd>${T.n.toLocaleString()}${T.R && T.R.n ? ' of ' + T.R.n.toLocaleString() : ''}${chMoreLeft(T.R) ? ` · <button class="lnk" data-act="chMore" data-id="${esc(k + ':' + v)}">fetch more</button>` : ''}</dd></dl>
    ${T.cps.length ? `<div class="caps ch-caps">Top counterparties</div>${T.cps.slice(0, 5).map(r => `<div class="ch-cp"><span class="mono" title="${esc(r.a)}">${esc(chShort(r.a))}</span><span class="ch-am">${chCpAmt(r, c)}</span>${r.L.length ? `<span class="ch-cl">${chChips(r.L.slice(0, 2))}</span>` : ''}</div>`).join('')}` : ''}
    ${T.co.length ? `<p class="small ch-co"><b>Probably the same owner:</b> ${T.co.slice(0, 3).map(r => `<span class="mono">${esc(chShort(r.a))}</span>`).join(', ')}${T.co.length > 3 ? ' and ' + (T.co.length - 3) + ' more' : ''} <span class="t3">— spent together with it (an estimate)</span></p>` : ''}
    <div class="wrap" style="margin-top:10px"><button class="btn sm primary" data-act="chOpen" data-id="${esc(k + ':' + v)}">${ico('arrow-right-left','sm')}Open the trail</button>${T.R && T.R.src ? `<button class="btn sm" data-act="chGet" data-id="${esc(k + ':' + v)}">${ico('refresh-cw','sm')}Refresh</button>` : ''}<button class="btn sm ghost" data-act="chImport" data-id="${esc(k + ':' + v)}">${ico('upload','sm')}Import…</button><button class="btn sm ghost" data-act="chMoney">${ico('waypoints','sm')}Case money flows</button></div>${sancNote}</div>`;
}

/* ---------- the trail, in full ---------- */
function chDlg(c, a, tab){
  const T = chTrail(c, a), N = CH_NATIVE[c]; UI.ch = {c, a, tab:tab || (UI.ch && UI.ch.a === a && UI.ch.tab) || 'cp', pick:UI.ch && UI.ch.a === a ? UI.ch.pick : new Set()};
  const tabB = (id, l, n) => `<button role="tab" aria-selected="${UI.ch.tab === id}" data-act="chTab" data-v="${id}">${l} <span class="t3">${n}</span></button>`;
  let body = '';
  if(UI.ch.tab === 'cp') body = T.cps.length ? `<div class="ch-tw"><table class="tbl ch-t"><thead><tr><th class="c-pk"><span class="sr">Select</span></th><th>Counterparty</th><th>Amounts</th><th class="n">Txs</th><th class="hide-m">When</th><th><span class="sr">Actions</span></th></tr></thead><tbody>
    ${T.cps.slice(0, CH.ROWS).map(r => { const k = chNorm(c, r.a); return `<tr><td class="c-pk"><input type="checkbox" data-chpick="${esc(k)}" aria-label="Select ${esc(r.a)}" ${UI.ch.pick.has(k) ? 'checked' : ''}></td><td><span class="mono ch-a" title="${esc(r.a)}">${esc(chShort(r.a))}</span>${r.L.length ? `<div class="ch-cl">${chChips(r.L)}</div>` : ''}</td><td class="ch-am">${chCpAmt(r, c)}</td><td class="n">${r.n}</td>
      <td class="hide-m t3 small">${r.first ? esc(E.fmtDate(r.first, tz())) + (r.last > r.first ? ' – ' + esc(E.fmtDate(r.last, tz())) : '') : ''}</td><td class="ch-ra"><button class="iconbtn" data-act="chLabel" data-id="${esc(c + ':' + r.a)}" aria-label="Label ${esc(r.a)}" title="Label">${ico('tag','sm')}</button><a class="iconbtn" href="${esc(N.addr + r.a)}" target="_blank" rel="noopener noreferrer" aria-label="Open ${esc(r.a)} on the explorer" title="Explorer">${ico('external-link','sm')}</a></td></tr>`; }).join('')}</tbody></table></div>${T.cps.length > CH.ROWS ? `<p class="t3">The ${CH.ROWS} largest are shown.</p>` : ''}` : '<p class="t3">No counterparties yet.</p>';
  else if(UI.ch.tab === 'tx') body = `<div class="ch-tw"><table class="tbl ch-t"><thead><tr><th>When</th><th></th><th>Amount</th><th>Counterparties</th><th><span class="sr">Transaction</span></th></tr></thead><tbody>${T.rows.slice(0, CH.ROWS).map(x => `<tr class="${x.dir}"><td class="mono small">${x.t.t ? esc(E.fmtFull(x.t.t, tz()).slice(0, 16)) : 'pending'}</td><td>${{in:'Received', out:'Sent', self:'To itself', fail:'Failed'}[x.dir]}${x.cj ? ' <span class="chx warn">CoinJoin</span>' : ''}</td>
    <td class="${x.dir === 'in' ? 'ch-in' : x.dir === 'out' ? 'ch-out' : 't3'}">${x.dir === 'in' ? '+' : x.dir === 'out' ? '−' : ''}${esc(chFmt(x.amt, x.A.dec, x.A.sym))}</td><td class="mono small">${x.who.slice(0, 2).map(chShort).map(esc).join(', ')}${x.who.length > 2 ? ' +' + (x.who.length - 2) : ''}</td><td><a class="iconbtn" href="${esc(N.tx + x.t.h)}" target="_blank" rel="noopener noreferrer" aria-label="Open transaction ${esc(x.t.h.slice(0, 12))}" title="${esc(x.t.h)}">${ico('external-link','sm')}</a></td></tr>`).join('')}</tbody></table></div>${T.rows.length > CH.ROWS ? `<p class="t3">The newest ${CH.ROWS} are shown; all are in the export.</p>` : ''}`;
  else body = T.co.length ? `<p class="t2 small" style="margin:0 0 10px">Wallets spent in the same transaction as this one. Spending together needs every key, so they are usually one owner — not when a service batches payments or in CoinJoin (those are left out).</p><div class="ch-tw"><table class="tbl ch-t"><thead><tr><th class="c-pk"><span class="sr">Select</span></th><th>Wallet</th><th class="n">Times together</th></tr></thead><tbody>${T.co.map(r => { const k = chNorm(c, r.a); return `<tr><td class="c-pk"><input type="checkbox" data-chpick="${esc(k)}" aria-label="Select ${esc(r.a)}" ${UI.ch.pick.has(k) ? 'checked' : ''}></td><td><span class="mono">${esc(r.a)}</span><div class="ch-cl">${chChips(chLabels(c, r.a))}</div></td><td class="n">${r.n}</td></tr>`; }).join('')}</tbody></table></div>` : `<p class="t3">${c === 'eth' ? 'Ethereum accounts spend alone, so this estimate is for Bitcoin.' : 'It never spent together with another wallet.'}</p>`;
  const np = UI.ch.pick.size;
  openDlg(dhead('Money trail of <span class="mono">' + esc(chShort(a)) + '</span>') + `<div class="in ch-d"><div class="wrap ch-l">${chChips(T.L)}</div>
    <div class="seg ch-tabs" role="tablist" aria-label="Money trail">${tabB('cp', 'Counterparties', T.cps.length)}${tabB('tx', 'Transactions', T.rows.length)}${tabB('co', 'Same owner?', T.co.length)}</div>${body}</div>
    <footer><button class="btn ghost" data-act="chCsv">${ico('download','sm')}Export CSV</button><button class="btn" data-act="chTl" title="One timeline event per transaction">${ico('clock','sm')}Add to the timeline</button><span class="sp"></span><button class="btn primary" data-act="chVault" ${np ? '' : 'disabled'}>${ico('git-branch','sm')}${np ? 'Add ' + np + ' to the vault, linked' : 'Select wallets to add'}</button><button class="btn" data-act="dclose">Close</button></footer>`, true);
  $('dlg').querySelectorAll('[data-chpick]').forEach(b => b.onchange = () => { b.checked ? UI.ch.pick.add(b.dataset.chpick) : UI.ch.pick.delete(b.dataset.chpick); const f = $('dlg').querySelector('[data-act=chVault]'); const n2 = UI.ch.pick.size; f.disabled = !n2; f.innerHTML = ico('git-branch','sm') + (n2 ? 'Add ' + n2 + ' to the vault, linked' : 'Select wallets to add'); });
}

/* ---------- into the case: vault entries with links, timeline events ---------- */
function chEntry(c, a, cid, made){
  const e0 = chInCases(c, a).find(e => e.caseId === cid); if(e0) return e0;
  const e = {id:uid('v'), caseId:cid, type:'crypto', fields:{address:a, currency:CH_NATIVE[c].name}, priority:'medium', starred:false, tags:['money-trail'], notes:'', src:'', created:Date.now(), pos:null};
  DB.entries.push(e); made.push(e); CH_CASES.at = -1; return e;
}
function chVault(){
  const S = UI.ch; if(!S || !S.pick.size) return; const T = chTrail(S.c, S.a), N = CH_NATIVE[S.c], cid = DB.active, made = [], links = [];
  const src = chEntry(S.c, S.a, cid, made);
  for(const k of S.pick){
    const r = T.cps.find(x => chNorm(S.c, x.a) === k), o = !r && T.co.find(x => chNorm(S.c, x.a) === k); if(!r && !o) continue;
    const e = chEntry(S.c, (r || o).a, cid, made), has = (a, b, l) => DB.links.some(x => x.a === a && x.b === b && x.label === l);
    if(o){ if(!has(src.id, e.id, 'same owner?')) links.push({id:uid('l'), caseId:cid, a:src.id, b:e.id, label:'same owner?', conf:2, auto:true, why:`Spent together in ${o.n} transaction${o.n > 1 ? 's' : ''} — common-input estimate`}); continue; }
    const sIn = chAmt(r, N.sym, 'in'), sOut = chAmt(r, N.sym, 'out'), when = r.first ? ', ' + E.fmtDate(r.first, tz()) + (r.last > r.first ? ' – ' + E.fmtDate(r.last, tz()) : '') : '';
    if((sOut || !sIn) && !has(src.id, e.id, 'paid')) links.push({id:uid('l'), caseId:cid, a:src.id, b:e.id, label:'paid', conf:3, auto:true, why:(sOut ? chFmt(sOut, N.dec, N.sym) : 'tokens') + ' in ' + r.n + ' transaction' + (r.n > 1 ? 's' : '') + when});
    if(sIn && !has(e.id, src.id, 'paid')) links.push({id:uid('l'), caseId:cid, a:e.id, b:src.id, label:'paid', conf:3, auto:true, why:chFmt(sIn, N.dec, N.sym) + ' in ' + r.n + ' transaction' + (r.n > 1 ? 's' : '') + when});
  }
  DB.links.push(...links); S.pick = new Set(); mutate('money trail to vault'); closeDlg(); renderAll();
  toast(`${made.length} wallet${made.length === 1 ? '' : 's'} added, ${links.length} link${links.length === 1 ? '' : 's'}`, 'Show in the graph', () => go(caseHash(cid, 'graph')));
}
async function chTimeline(){
  const S = UI.ch; if(!S) return; const T = chTrail(S.c, S.a), cid = DB.active, have = new Set(DB.records.filter(r => r.caseId === cid && r.chainTx).map(r => r.chainTx)), N = CH_NATIVE[S.c];
  const rows = T.rows.filter(x => x.t.t && x.dir !== 'fail' && !have.has(x.t.id)).slice(0, CH.TL); if(!rows.length) return toast('Every payment is already on this case’s timeline');
  if(!await stoGuard(rows.length * 900, 'add these payments')) return;
  const kind = x => E.cryptoKind(x), now = Date.now();
  for(const x of rows){ const verb = x.dir === 'in' ? 'Received' : x.dir === 'out' ? 'Sent' : 'Moved', amt = chFmt(x.amt, x.A.dec, x.A.sym);
    const body = [`Transaction ${x.t.h}`, `Wallet: ${S.a}`, `${x.dir === 'in' ? 'From' : 'To'}: ${x.who.join(', ') || '—'}`, `Amount: ${amt}`, x.t.tok ? `Token: ${x.t.tok.n || x.t.tok.s} ${x.t.tok.a}` : '', x.t.f && x.t.f !== '0' && !x.t.tok ? `Fee: ${chFmt(x.t.f, N.dec, N.sym)}` : '', x.t.b ? `Block: ${x.t.b}` : ''].filter(Boolean).join('\n');
    DB.records.push({id:uid('r'), caseId:cid, type:'evidence', title:`${verb} ${amt} ${x.dir === 'in' ? 'from' : 'to'} ${x.who.length ? chShort(x.who[0]) + (x.who.length > 1 ? ' +' + (x.who.length - 1) : '') : x.cj ? 'a CoinJoin' : 'itself'}`, body, tsRaw:new Date(x.t.t).toISOString(), tsZone:'explicit', ts:x.t.t,
      source:'chain:' + (T.R && T.R.src || 'import'), host:'', tags:['crypto', 'payment'], ents:[S.a].concat(x.who.slice(0, 20)).filter(w => chGuess(w)).map(w => ({k:kind(w), v:w})), answer:'', addedBy:'You', addedAt:now, hash:'', chainTx:x.t.id}); }
  mutate('payments to the timeline'); closeDlg(); renderAll(); toast(`${rows.length} payment${rows.length === 1 ? '' : 's'} added to the timeline`, 'Open it', () => go(caseHash(cid, 'timeline')));
}
function chCsv(){
  const S = UI.ch; if(!S) return; const T = chTrail(S.c, S.a), rows = [];
  for(const x of T.rows){ const ins = x.t.i.map(([a]) => a), outs = x.t.o.map(([a]) => a);
    rows.push([x.t.h, x.t.t ? new Date(x.t.t).toISOString() : '', S.c === 'btc' ? 'bitcoin' : 'ethereum', x.dir === 'in' ? (x.who[0] || ins[0] || '') : S.a, x.dir === 'in' ? S.a : (x.who[0] || outs[0] || ''), chFmt(x.amt, x.A.dec).replace(/,/g, ''), x.A.sym, x.dir, x.who.join(' ')].map(csvCell).join(',')); }
  download(safeName('trail-' + S.a.slice(0, 16) + '.csv'), 'hash,time,chain,from,to,amount,asset,direction,counterparties\n' + rows.join('\n') + '\n', 'text/csv');
}

/* ---------- labels you give ---------- */
function chLabelDlg(id){ const i = id.indexOf(':'), c = id.slice(0, i), a = id.slice(i + 1), L = chDB().labels[c + ':' + chNorm(c, a)] || {};
  UI.chLab = {c, a, back:UI.ch ? {c:UI.ch.c, a:UI.ch.a} : null};
  openDlg(dhead('Label this wallet') + `<form data-form="chLabel"><div class="in"><p class="mono small" style="margin:0 0 12px;overflow-wrap:anywhere">${esc(a)}</p>
    <div class="field"><label for="chLt">Label</label><input id="chLt" maxlength="80" value="${esc(L.t || '')}" placeholder="Binance deposit, the suspect’s cold wallet…" autocomplete="off"></div>
    <div class="field"><label for="chLk">Kind</label><select id="chLk">${CH_KINDS.map(([k, l]) => `<option value="${k}"${L.kind === k ? ' selected' : ''}>${l}</option>`).join('')}</select></div><p class="t3 small">Labels apply in every case and show wherever the wallet appears.</p></div>
    <footer>${L.t ? '<button class="btn danger" type="button" data-act="chUnlabel">Remove</button>' : ''}<span class="sp"></span><button class="btn" type="button" data-act="dclose">Cancel</button><button class="btn primary" type="submit">Save</button></footer></form>`);
  $('dlg').classList.add('narrow'); setTimeout(() => { const x = $('chLt'); if(x) x.focus(); }); }
function chLabelSave(rm){ const L = UI.chLab; if(!L) return; const C = chDB(), k = L.c + ':' + chNorm(L.c, L.a), t = rm ? '' : ($('chLt').value || '').trim().slice(0, 80);
  if(!rm && !t) return fieldErr('chLt', 'Give it a label.');
  if(t) C.labels[k] = {t, kind:CH_KINDS.some(x => x[0] === $('chLk').value) ? $('chLk').value : 'other', at:Date.now()}; else delete C.labels[k];
  mutate('labelled ' + chShort(L.a)); closeDlg(); if(L.back) chDlg(L.back.c, L.back.a); else renderAll(); }

/* ---------- sanctions ---------- */
async function chSancGet(ok){
  if(!ok) return openDlg(dhead('Download the sanctions list') + `<div class="in"><p>Downloads the crypto addresses on the US Treasury’s OFAC sanctions list, as published every night at <span class="mono">github.com/0xB10C/ofac-sanctioned-digital-currency-addresses</span> — Bitcoin, Ethereum, USDT, USDC and TRON.</p><p class="t2">Nothing about your cases is sent. From then on every wallet is checked here, offline. Download again to update it.</p></div>
    <footer><button class="btn" data-act="dclose">Cancel</button><button class="btn primary" data-act="chSancGo">${ico('download','sm')}Download</button></footer>`);
  closeDlg(); toast('Downloading the sanctions list…');
  try{ const out = {btc:[], eth:[], trx:[]};
    for(const [f] of CH_SANC_LISTS){ const r = await lkFetch(CH_SANC_URL + f + '.json', {timeout:30000}); if(r.status >= 400) throw new Error('HTTP ' + r.status); const L = JSON.parse(r.text); if(!Array.isArray(L)) throw new Error('Not a list');
      for(const x of L.slice(0, 50000)){ const s = String(x).trim(); if(/^0x[0-9a-f]{40}$/i.test(s)) out.eth.push(s.toLowerCase()); else if(/^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(s)) out.trx.push(s); else if(/^(bc1[02-9ac-hj-np-z]{8,87}|[13][1-9A-HJ-NP-Za-km-z]{25,34})$/i.test(s)) out.btc.push(/^bc1/i.test(s) ? s.toLowerCase() : s); } }
    const n = out.btc.length + out.eth.length + out.trx.length; if(!n) throw new Error('The list was empty');
    if(!await stoGuard(n * 50, 'keep the sanctions list')) return;
    const C = chDB(); C.sanc = {at:Date.now(), src:'OFAC SDN via 0xB10C', btc:[...new Set(out.btc)], eth:[...new Set(out.eth)], trx:[...new Set(out.trx)]}; chTouch(); mutate('sanctions list updated'); renderAll();
    const hits = Object.values(C.addr).filter(R => chSanc(R.c, R.a)).length + DB.entries.filter(e => e.type === 'crypto' && chGuess(primary(e)) && chSanc(chGuess(primary(e)), primary(e))).length;
    toast(`Sanctions list: ${n.toLocaleString()} addresses${hits ? ' — ' + hits + ' of yours ' + (hits > 1 ? 'are' : 'is') + ' on it' : ''}`);
  }catch(e){ toast('Could not download the list — ' + (e.message || e)); }
}

/* ---------- importing an exported file ---------- */
function chParse(text, name){
  const t0 = String(text).replace(/^\uFEFF/, '').slice(0, 30e6), first = t0.slice(0, t0.indexOf('\n') + 1 || 2000), rows = csvParse(t0, (first.match(/\t/g) || []).length > (first.match(/,/g) || []).length ? '\t' : first.includes(';') && !first.includes(',') ? ';' : ',').filter(r => r.some(x => String(x).trim())); if(rows.length < 2) return {err:'No rows found'};
  const H = rows[0].map(h => String(h).trim().toLowerCase()), col = (...re) => { for(const r of re){ const i = H.findIndex(h => r.test(h)); if(i >= 0) return i; } return -1; };
  const iH = col(/^transaction hash$/, /^(tx_?)?hash$/, /^txid$/, /^tx( id)?$/, /^transaction( id)?$/), iT = col(/^unixtimestamp$/, /^timestamp$/, /^date ?time/, /^time/, /^date/, /^block_?time/), iF = col(/^from$/, /^from_?address$/, /^sender$/, /^source$/), iTo = col(/^to$/, /^to_?address$/, /^recipient$/, /^receiver$/, /^destination$/);
  const iIn = col(/^value_in\(/), iOut = col(/^value_out\(/), iV = col(/^tokenvalue$/, /^amount$/, /^value$/, /^quantity$/, /^value \(/), iSym = col(/^tokensymbol$/, /^asset$/, /^symbol$/, /^currency$/, /^token$/), iTok = col(/^contractaddress$/, /^token_?address$/), iTn = col(/^tokenname$/), iSt = col(/^status$/), iFee = col(/^txnfee\(/, /^fee$/), iBlk = col(/^blockno$/, /^block( number)?$/), iCh = col(/^chain$/, /^network$/);
  if(iF < 0 || iTo < 0 || (iV < 0 && iIn < 0)) return {err:'The file needs from, to and amount (or value) columns'};
  const fmt = iIn >= 0 ? 'Etherscan transactions' : iSym >= 0 && H[iSym] === 'tokensymbol' ? 'Etherscan token transfers' : 'CSV';
  const out = [], bad = [];
  rows.slice(1, 200001).forEach((r, n) => {
    const f = String(r[iF] || '').trim(), to = String(r[iTo] || '').trim(), c = (iCh >= 0 && /eth/i.test(r[iCh])) ? 'eth' : (iCh >= 0 && /btc|bitcoin/i.test(r[iCh])) ? 'btc' : chGuess(f) || chGuess(to);
    if(!c || !(chGuess(f) || chGuess(to))){ bad.push(n + 2); return; }
    const sym = iSym >= 0 ? String(r[iSym] || '').trim().slice(0, 20) : '', isTok = !!sym && sym.toUpperCase() !== CH_NATIVE[c].sym, dec = isTok ? 18 : CH_NATIVE[c].dec;
    let raw = iIn >= 0 ? (+String(r[iIn]).replace(/,/g, '') ? r[iIn] : r[iOut]) : r[iV]; const v = chUnits(raw, dec); if(v == null){ bad.push(n + 2); return; }
    const tsr = iT >= 0 ? String(r[iT]).trim() : '', t = /^\d{9,11}$/.test(tsr) ? +tsr * 1000 : /^\d{12,14}$/.test(tsr) ? +tsr : Date.parse(/[zZ]|[+-]\d\d:?\d\d$/.test(tsr) || !tsr ? tsr : tsr.replace(' ', 'T') + 'Z') || 0;
    const h = (iH >= 0 ? String(r[iH]).trim() : '').slice(0, 80) || ('row' + (n + 2) + '-' + name);
    const fee = iFee >= 0 && !isTok ? chUnits(r[iFee], CH_NATIVE[c].dec) || '0' : '0';
    out.push({id:c + ':' + h + (isTok ? ':' + (String(r[iTok] || sym)).slice(0, 60).toLowerCase() + ':' + n : out.some(x => x.id === c + ':' + h) ? ':' + n : ''), c, h, t, b:iBlk >= 0 ? +r[iBlk] || 0 : 0, f:fee, i:[[f || 'unknown', v]], o:[[to || 'unknown', v]], ok:iSt < 0 || !/error|fail|revert/i.test(r[iSt] || ''), src:'import',
      tok:isTok ? {s:sym, d:dec, a:iTok >= 0 ? String(r[iTok] || '').trim().slice(0, 60) : '', n:iTn >= 0 ? String(r[iTn] || '').slice(0, 60) : ''} : undefined});
  });
  return {txs:out, bad, fmt, addrs:new Set(out.flatMap(t => [t.c + ':' + chNorm(t.c, t.i[0][0]), t.c + ':' + chNorm(t.c, t.o[0][0])])).size};
}
/* explorer JSON the Money view already reads (Esplora, blockchain.com, BlockCypher, Etherscan, Blockscout) → trail transactions */
function chFromWallet(W){
  const u = (v, d) => chUnits(Number(v || 0).toLocaleString('en-US', {useGrouping:false, maximumFractionDigits:Math.min(d, 18)}), d) || '0', out = [];
  for(const x of W.txs){ const c = x.chain === 'BTC' ? 'btc' : x.chain === 'ETH' ? 'eth' : null; if(!c) continue; const nat = x.asset === CH_NATIVE[c].sym, d = nat ? CH_NATIVE[c].dec : 18;
    out.push({id:c + ':' + x.id, c, h:String(x.tx || x.id).slice(0, 80), t:x.ts || 0, b:0, f:u(x.fee, CH_NATIVE[c].dec), i:x.ins.map(({a, v}) => [String(a), u(v, d)]), o:x.outs.map(({a, v}) => [String(a), u(v, d)]), ok:!x.failed, src:'import', ...(nat ? {} : {tok:{s:String(x.asset).slice(0, 20), d, a:'', n:''}})}); }
  const skipped = W.txs.length - out.length; return {txs:out, bad:[], skipped, fmt:W.kind, addrs:new Set(out.flatMap(t => t.i.concat(t.o).map(([a]) => t.c + ':' + chNorm(t.c, a)))).size};
}
async function chImportText(text, name, focus){
  const W = /^\s*[\[{]/.test(text) && typeof walletParse === 'function' ? walletParse(text) : null;
  const P = W ? chFromWallet(W) : chParse(text, name || 'file'); if(P.err) return toast(P.err + ' — ' + (name || 'file'));
  if(!P.txs.length) return toast('No transactions could be read from ' + (name || 'the file'));
  if(!await stoGuard(JSON.stringify(P.txs).length * 2, 'import these transactions')) return;
  const C = chDB(); let n = 0; for(const t of P.txs){ if(!C.tx[t.id]) n++; C.tx[t.id] = t; } chTouch();
  /* the file itself is kept as evidence in the open case */
  if(DB.active && typeof walletKeep === 'function') walletKeep(String(text).slice(0, 8 << 20), W ? Object.assign(W, {label:`${W.label} — ${name || 'imported'}`}) : {txs:P.txs.map(t => ({ts:t.t})), label:`Transactions (${P.fmt}) — ${name || 'imported'}`}, DB.active, 'import');
  mutate('imported transactions from ' + (name || 'a file'));
  toast(`${n.toLocaleString()} transaction${n === 1 ? '' : 's'} imported (${P.fmt}) between ${P.addrs.toLocaleString()} wallets${P.bad.length ? ' · ' + P.bad.length + ' row' + (P.bad.length > 1 ? 's' : '') + ' skipped' : ''}${P.skipped ? ' · ' + P.skipped + ' on other chains (in the Money view)' : ''}`);
  if(focus){ const {k, v} = entSplit(focus); if(chTrail(k, v).n) return chDlg(k, v); } renderAll();
}
function chImport(id){ const i = document.createElement('input'); i.type = 'file'; i.accept = '.csv,.tsv,.txt'; i.onchange = async () => { const f = i.files && i.files[0]; if(!f) return; if(f.size > 30e6) return toast('That file is over 30 MB'); chImportText(await f.text(), f.name, id); }; i.click(); }

/* ---------- asking before the first fetch ---------- */
async function chGetGo(id, more){
  const {k, v} = entSplit(id), c = chOf(k); if(!c) return; const p = lkProv(CH_NATIVE[c].prov);
  if(!lkSettings().on[p.id]) return openDlg(dhead('Fetch from ' + esc(p.host) + '?') + `<div class="in"><p>Only this address is sent to <b>${esc(p.host)}</b>:</p><p class="mono small" style="overflow-wrap:anywhere">${esc(v)}</p><p class="t2">The service sees which address you asked about, not who you are or anything else in your case. This switches ${esc(p.name)} on in Settings → Lookups, where you can switch it off.</p></div>
    <footer><button class="btn" data-act="dclose">Cancel</button><button class="btn primary" data-act="chGetOk" data-id="${esc(id)}">Switch on and fetch</button></footer>`);
  const btn = document.querySelector(`#insp [data-act=chGet][data-id="${CSS.escape(id)}"], #insp [data-act=chMore]`); if(btn){ btn.disabled = true; btn.textContent = 'Fetching…'; }
  try{ const {n, rec} = await chFetch(c, v, more); renderInsp(); toast(n ? `${n.toLocaleString()} transaction${n === 1 ? '' : 's'} from ${p.host}${rec ? ' — kept as evidence in ' + theCase(rec.caseId).name : ''}` : 'No transactions'); }
  catch(e){ renderInsp(); toast('Could not fetch — ' + (e.message || e)); }
}
const CHAIN_ACTS = {
  chGet:id => chGetGo(id, false),
  chGetOk:id => { const {k} = entSplit(id), p = lkProv(CH_NATIVE[chOf(k)].prov); lkSettings().on[p.id] = true; save(); closeDlg(); chGetGo(id, false); },
  chMore:id => chGetGo(id, true),
  chOpen:id => { const {k, v} = entSplit(id); UI.ch = null; chDlg(chOf(k), v); },
  chTab:(id, v) => { UI.ch.tab = v; chDlg(UI.ch.c, UI.ch.a); },
  chVault:() => chVault(), chTl:() => chTimeline(), chCsv:() => chCsv(),
  chImport:id => chImport(id), chLabel:id => chLabelDlg(id), chUnlabel:() => chLabelSave(true),
  chMoney:() => { closeDlg(); UI.ivView = 'money'; go(caseHash(DB.active, 'infra')); },
  chSancGet:() => chSancGet(false), chSancGo:() => chSancGet(true),
};
/* cleaning what was stored (a backup, an older version, a hand-edited file) */
function chClean(C){
  if(!C || typeof C !== 'object' || Array.isArray(C)) return undefined;
  const str = (v, n) => typeof v === 'string' ? v.slice(0, n) : '', num = v => Number.isFinite(+v) ? +v : 0, amt = v => /^-?\d{1,80}$/.test(String(v)) ? String(v) : '0', obj = o => o && typeof o === 'object' && !Array.isArray(o) ? o : {};
  const pair = p => Array.isArray(p) ? [str(p[0], 100) || 'unknown', amt(p[1])] : null, out = {tx:{}, addr:{}, meta:{}, labels:{}};
  for(const [k, t] of Object.entries(obj(C.tx)).slice(0, 200000)){ if(!t || !/^(btc|eth)$/.test(t.c) || !Array.isArray(t.i) || !Array.isArray(t.o)) continue;
    out.tx[str(k, 200)] = {id:str(k, 200), c:t.c, h:str(t.h, 80), t:num(t.t), b:num(t.b), f:amt(t.f), i:t.i.slice(0, 400).map(pair).filter(Boolean), o:t.o.slice(0, 400).map(pair).filter(Boolean), ok:t.ok !== false, ...(t.pend ? {pend:true} : {}), ...(t.src ? {src:str(t.src, 20)} : {}), ...(t.m ? {m:str(t.m, 40)} : {}),
      ...(t.tok && typeof t.tok === 'object' ? {tok:{s:str(t.tok.s, 20), d:Math.max(0, Math.min(36, num(t.tok.d))), a:str(t.tok.a, 60), n:str(t.tok.n, 60)}} : {})}; }
  for(const [k, R] of Object.entries(obj(C.addr)).slice(0, 20000)){ if(!R || !/^(btc|eth)$/.test(R.c)) continue;
    out.addr[str(k, 200)] = {a:str(R.a, 100), c:R.c, ids:Array.isArray(R.ids) ? R.ids.filter(x => typeof x === 'string').slice(0, CH.MAX) : [], at:num(R.at), src:str(R.src, 60), n:R.n == null ? null : num(R.n), bal:amt(R.bal), cur:str(R.cur, 2000), curT:str(R.curT, 2000), done:!!R.done, doneT:!!R.doneT}; }
  for(const [k, M] of Object.entries(obj(C.meta)).slice(0, 50000)) if(M && typeof M === 'object') out.meta[str(k, 200)] = {ens:str(M.ens, 120), tags:Array.isArray(M.tags) ? M.tags.map(x => str(x, 60)).filter(Boolean).slice(0, 6) : [], scam:!!M.scam, contract:!!M.contract};
  for(const [k, L] of Object.entries(obj(C.labels)).slice(0, 50000)) if(L && typeof L.t === 'string' && L.t.trim()) out.labels[str(k, 200)] = {t:str(L.t, 80), kind:CH_KINDS.some(x => x[0] === L.kind) ? L.kind : 'other', at:num(L.at)};
  if(C.sanc && typeof C.sanc === 'object'){ const L = v => Array.isArray(v) ? v.filter(x => typeof x === 'string' && x.length < 100).slice(0, 50000) : []; out.sanc = {at:num(C.sanc.at), src:str(C.sanc.src, 80), btc:L(C.sanc.btc), eth:L(C.sanc.eth), trx:L(C.sanc.trx)}; }
  return out;
}
