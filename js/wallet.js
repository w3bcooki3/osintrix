/* ==========================================================================
   Where the money went (Analysis → Money) — from transactions you paste.
   Reads what blockchain explorers give you: Blockstream / mempool.space
   (Esplora) and blockchain.com and BlockCypher JSON for Bitcoin, Etherscan JSON
   and CSV exports for Ethereum (coins and tokens), Tronscan and TronGrid for
   TRON (USDT). Each paste is kept as evidence. Then, across the case:
   · who paid whom, how much and when — as a flow picture and a table
   · addresses spent together in one Bitcoin transaction are very likely one
     owner (the common-input rule) and are grouped — except in transactions
     that look like CoinJoin, where strangers spend together on purpose
   · change sent back to the sender is not counted as a payment
   · patterns worth a look: money passing straight through a wallet, many
     payers into one wallet, one wallet paying many, peel chains
   · the wallets of this case that appear in other cases
   Nothing is looked up; amounts are as the explorer gave them.
   ========================================================================== */
const WL_DEC = (v, d) => { const s = String(v ?? '').trim(); if(!/^-?\d+$/.test(s)) return +s || 0; if(!d) return +s; const neg = s[0] === '-', t = (neg ? s.slice(1) : s).padStart(d + 1, '0'), n = +(t.slice(0, -d) + '.' + t.slice(-d)); return neg ? -n : n; };
const wlNorm = (a, chain) => { a = String(a || '').trim(); return /^0x[0-9a-f]{40}$/i.test(a) ? a.toLowerCase() : a; };
const wlChainOf = a => /^0x[0-9a-f]{40}$/i.test(a) ? 'ETH' : /^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(a) ? 'TRON' : /^(bc1|[13])/.test(a) ? 'BTC' : /^(ltc1|[LM])/.test(a) ? 'LTC' : '';
const wlTs = v => { if(v == null || v === '') return null; if(/^\d{10}$/.test(String(v))) return +v * 1000; if(/^\d{13}$/.test(String(v))) return +v; const t = Date.parse(String(v).replace(' ', 'T').replace(/(\d)$/, '$1Z').replace(/ZZ$/, 'Z')); return isFinite(t) ? t : null; };
/* ---------- parsers: → {kind, label, txs:[{id, chain, asset, ts, ins:[{a, v}], outs:[{a, v}], fee, failed}], focus} ---------- */
function wlEsplora(o){
  const L = Array.isArray(o) ? o : o && o.txid ? [o] : null; if(!L || !L.length || !L.every(t => t && t.txid && Array.isArray(t.vin) && Array.isArray(t.vout))) return null;
  const txs = L.map(t => ({id:t.txid, chain:'BTC', asset:'BTC', ts:t.status && t.status.block_time ? t.status.block_time * 1000 : null, fee:(t.fee || 0) / 1e8,
    ins:t.vin.filter(v => !v.is_coinbase && v.prevout && v.prevout.scriptpubkey_address).map(v => ({a:v.prevout.scriptpubkey_address, v:v.prevout.value / 1e8})),
    outs:t.vout.filter(v => v.scriptpubkey_address).map(v => ({a:v.scriptpubkey_address, v:v.value / 1e8}))}));
  return {kind:'Bitcoin (Esplora)', txs};
}
function wlBlockchainCom(o){
  if(!o || !Array.isArray(o.txs) || !o.txs.every(t => t && t.hash && Array.isArray(t.inputs) && Array.isArray(t.out))) return null;
  const txs = o.txs.map(t => ({id:t.hash, chain:'BTC', asset:'BTC', ts:t.time ? t.time * 1000 : null, fee:(t.fee || 0) / 1e8, ins:t.inputs.filter(i => i.prev_out && i.prev_out.addr).map(i => ({a:i.prev_out.addr, v:i.prev_out.value / 1e8})), outs:t.out.filter(x => x.addr).map(x => ({a:x.addr, v:x.value / 1e8}))}));
  return {kind:'Bitcoin (blockchain.com)', txs, focus:[o.address, ...(Array.isArray(o.addresses) ? o.addresses.map(x => x.address) : [])].filter(Boolean)};
}
function wlBlockcypher(o){
  if(!o || !Array.isArray(o.txs) || !o.txs.every(t => t && t.hash && Array.isArray(t.inputs) && Array.isArray(t.outputs))) return null;
  const txs = o.txs.map(t => ({id:t.hash, chain:'BTC', asset:'BTC', ts:wlTs(t.confirmed || t.received), fee:(t.fees || 0) / 1e8, ins:t.inputs.filter(i => i.addresses && i.addresses.length).map(i => ({a:i.addresses[0], v:(i.output_value || 0) / 1e8})), outs:t.outputs.filter(x => x.addresses && x.addresses.length).map(x => ({a:x.addresses[0], v:(x.value || 0) / 1e8}))}));
  return {kind:'Bitcoin (BlockCypher)', txs, focus:o.address ? [o.address] : []};
}
function wlEtherscan(o){
  const L = o && Array.isArray(o.result) ? o.result : null; if(!L || !L.length || !L.every(t => t && t.hash && t.from != null && t.value != null && t.timeStamp)) return null;
  const tok = L.some(t => t.tokenSymbol);
  const txs = L.map(t => { const asset = t.tokenSymbol || 'ETH', d = t.tokenSymbol ? +t.tokenDecimal || 0 : 18, v = WL_DEC(t.value, d), from = wlNorm(t.from), to = wlNorm(t.to || t.contractAddress);
    return {id:t.hash + (t.tokenSymbol ? ':' + asset + ':' + (t.logIndex || t.transactionIndex || '') : ''), tx:t.hash, chain:'ETH', asset, ts:+t.timeStamp * 1000, fee:t.gasUsed && t.gasPrice && !tok ? WL_DEC((BigInt(t.gasUsed) * BigInt(t.gasPrice)).toString(), 18) : 0, failed:t.isError === '1', ins:[{a:from, v}], outs:to ? [{a:to, v}] : []}; });
  return {kind:tok ? 'Ethereum tokens (Etherscan)' : 'Ethereum (Etherscan)', txs};
}
function wlCsv(t){
  const rows = []; let row = [], f = '', q = false;
  for(let i = 0; i < t.length && rows.length < 50001; i++){ const c = t[i];
    if(q){ if(c === '"' && t[i + 1] === '"'){ f += '"'; i++; } else if(c === '"') q = false; else f += c; }
    else if(c === '"') q = true; else if(c === ','){ row.push(f); f = ''; } else if(c === '\n' || c === '\r'){ if(c === '\r' && t[i + 1] === '\n') i++; row.push(f); rows.push(row); row = []; f = ''; } else f += c; }
  if(f || row.length){ row.push(f); rows.push(row); }
  const H = (rows[0] || []).map(h => h.trim()), ix = re => H.findIndex(h => re.test(h));
  const hi = ix(/^(Txhash|Transaction Hash)$/i), fi = ix(/^From$/i), ti = ix(/^To$/i), tsi = ix(/^UnixTimestamp$/i), dti = ix(/^DateTime/i), vin = ix(/^Value_IN/i), vout = ix(/^Value_OUT/i), tv = ix(/^(TokenValue|Value)$/i), sym = ix(/^(TokenSymbol|Token Symbol)$/i), st = ix(/^Status$/i);
  if(hi < 0 || fi < 0 || ti < 0 || (vin < 0 && tv < 0)) return null;
  const txs = rows.slice(1).filter(r => r.length > Math.max(hi, fi, ti)).map(r => { const asset = sym >= 0 && r[sym] ? r[sym].trim() : (H[vin] || 'ETH').replace(/^Value_IN\(|\)$/g, '') || 'ETH', v = vin >= 0 ? (+String(r[vin]).replace(/,/g, '') || 0) + (+String(r[vout]).replace(/,/g, '') || 0) : +String(r[tv]).replace(/,/g, '') || 0;
    return {id:r[hi].trim() + (sym >= 0 ? ':' + asset : ''), tx:r[hi].trim(), chain:'ETH', asset, ts:wlTs(tsi >= 0 ? r[tsi] : r[dti]), failed:st >= 0 && /error|fail/i.test(r[st]), ins:[{a:wlNorm(r[fi]), v}], outs:[{a:wlNorm(r[ti]), v}]}; }).filter(x => x.tx && x.ins[0].a);
  return txs.length ? {kind:sym >= 0 ? 'Ethereum tokens (Etherscan CSV)' : 'Ethereum (Etherscan CSV)', txs} : null;
}
function wlTron(o){
  const L = o && Array.isArray(o.token_transfers) ? o.token_transfers : o && Array.isArray(o.data) && o.data.length && o.data[0] && (o.data[0].token_info || o.data[0].transaction_id) ? o.data : null; if(!L || !L.length) return null;
  const txs = L.filter(t => t && (t.transaction_id || t.transactionHash)).map(t => { const ti = t.tokenInfo || t.token_info || {}, sym = ti.tokenAbbr || ti.symbol || 'TRX', d = +(ti.tokenDecimal ?? ti.decimals ?? 6), v = WL_DEC(t.quant ?? t.value ?? t.amount, d);
    return {id:(t.transaction_id || t.transactionHash) + ':' + sym, tx:t.transaction_id || t.transactionHash, chain:'TRON', asset:sym, ts:wlTs(t.block_ts ?? t.block_timestamp ?? t.timestamp), ins:[{a:t.from_address || t.from || t.ownerAddress, v}], outs:[{a:t.to_address || t.to || t.toAddress, v}], failed:t.finalResult && t.finalResult !== 'SUCCESS'}; });
  return txs.length ? {kind:'TRON (Tronscan / TronGrid)', txs} : null;
}
/* Blockscout API v2: an address's transactions and token transfers ({items:[…]}), as the money trail keeps them */
function wlBlockscout(o){
  const L = o && Array.isArray(o.items) ? o.items : null; if(!L || !L.length || !L.every(t => t && (t.hash || t.transaction_hash) && t.from && typeof t.from === 'object')) return null;
  const txs = L.filter(t => !t.token_type || t.token_type === 'ERC-20').map(t => { const tok = !!t.transaction_hash, T = t.token || {}, d = tok ? +(t.total && t.total.decimals || T.decimals) || 0 : 18, asset = tok ? String(T.symbol || '?').slice(0, 20) : 'ETH', v = WL_DEC(tok ? t.total && t.total.value : t.value, d);
    const to = t.to ? t.to.hash : t.created_contract ? t.created_contract.hash : '';
    return {id:tok ? t.transaction_hash + ':' + asset + ':' + (t.log_index ?? '') : t.hash, tx:t.transaction_hash || t.hash, chain:'ETH', asset, ts:wlTs(t.timestamp), fee:!tok && t.fee ? WL_DEC(t.fee.value, 18) : 0, failed:!tok && (t.status === 'error' || /revert|fail|error/i.test(t.result || '')), ins:[{a:wlNorm(t.from.hash), v}], outs:to ? [{a:wlNorm(to), v}] : []}; });
  return txs.length ? {kind:'Ethereum (Blockscout)', txs} : null;
}
/* keep transactions as evidence in a case — what the Money view reads */
function walletKeep(text, P, caseId, src){
  if(DB.records.some(r => r.caseId === caseId && r.body === text)) return null;
  const ts = P.txs.map(x => x.ts).filter(Boolean), r = {id:uid('r'), caseId, type:'evidence', title:P.label.slice(0, 110), body:text, tsRaw:ts.length ? new Date(Math.min(...ts)).toISOString() : new Date().toISOString(), tsZone:'explicit', ts:ts.length ? Math.min(...ts) : Date.now(), source:'chain:' + (src || P.kind), host:'', tags:['transactions'], ents:extractRich(text.slice(0, 400000)).slice(0, 3000), answer:'', addedBy:'You', addedAt:Date.now(), hash:''};
  DB.records.push(r); if(typeof hashRecords === 'function') hashRecords(); return r;
}
function walletParse(text){
  const t = String(text || '').slice(0, 8 << 20).trim(); if(t.length < 20) return null; let o = null, P = null;
  if(/^[\[{]/.test(t)){ try{ o = JSON.parse(t); }catch(e){ return null; } P = wlEsplora(o) || wlBlockchainCom(o) || wlBlockcypher(o) || wlEtherscan(o) || wlTron(o) || wlBlockscout(o); }
  else P = wlCsv(t);
  if(!P || !P.txs.length) return null; P.txs = P.txs.filter(x => (x.ins.length || x.outs.length)); const assets = [...new Set(P.txs.map(x => x.asset))];
  P.label = `${P.kind} — ${P.txs.length} transaction${P.txs.length > 1 ? 's' : ''}${assets.length <= 3 ? ' · ' + assets.join(', ') : ''}`; return P;
}
const WL_HINT = /"txid"\s*:|"vin"\s*:|"prev_out"\s*:|"output_value"\s*:|"timeStamp"\s*:|"token_transfers"\s*:|"transaction_id"\s*:|^"?(Txhash|Transaction Hash)"?,/m;
/* ---------- the case's money, joined ---------- */
function walletIndex(caseId){
  const sig = caseId + ':' + rev; if(WL_C.sig === sig) return WL_C.v;
  const D = derive(caseId), seen = new Set(), txs = [], srcs = [];
  for(const r of D.recs){ if(r.type === 'lead' || !r.body || r.body.length > 8 << 20 || !WL_HINT.test(r.body.slice(0, 100000))) continue; let P = null; try{ P = walletParse(r.body); }catch(e){} if(!P) continue;
    srcs.push({r, kind:P.kind, n:P.txs.length}); for(const x of P.txs){ const k = x.chain + ':' + x.id; if(seen.has(k)) continue; seen.add(k); txs.push({...x, rec:r.id}); } }
  txs.sort((a, b) => (a.ts || 0) - (b.ts || 0));
  /* owners: addresses spent together (not in a CoinJoin-looking transaction) */
  const par = new Map(), find = a => { let p = par.get(a) || a; if(p !== a){ p = find(p); par.set(a, p); } return p; }, join = (a, b) => { const x = find(a), y = find(b); if(x !== y) par.set(x, y); };
  const cj = new Set();
  for(const t of txs){ if(t.chain !== 'BTC' || t.failed) continue; const ins = [...new Set(t.ins.map(i => i.a))];
    const eq = new Map(); for(const o of t.outs) eq.set(o.v, (eq.get(o.v) || 0) + 1); if(ins.length >= 3 && [...eq.values()].some(n => n >= 3)){ cj.add(t.id); continue; }
    for(let i = 1; i < ins.length; i++) join(ins[0], ins[i]); }
  const W = new Map(), wal = (a, chain) => { if(!W.has(a)) W.set(a, {a, chain:chain || wlChainOf(a), inn:{}, out:{}, n:0, first:null, last:null, from:new Set(), to:new Set()}); return W.get(a); };
  const flows = new Map(), addFlow = (f, to, asset, v, t) => { const k = f + '\u0000' + to + '\u0000' + asset; let e = flows.get(k); if(!e){ e = {f, to, asset, v:0, n:0, first:t.ts, last:t.ts, recs:new Set(), txs:[]}; flows.set(k, e); }
    e.v += v; e.n++; if(t.ts){ e.first = Math.min(e.first ?? t.ts, t.ts); e.last = Math.max(e.last ?? t.ts, t.ts); } e.recs.add(t.rec); if(e.txs.length < 50) e.txs.push(t.tx || t.id); };
  for(const t of txs){ if(t.failed || cj.has(t.id)) continue; const insA = new Set(t.ins.map(i => i.a)), owner = t.ins.length ? find(t.ins[0].a) : null, tot = t.ins.reduce((s, i) => s + i.v, 0) || 1;
    for(const i of t.ins){ const w = wal(i.a, t.chain); w.n++; w.out[t.asset] = (w.out[t.asset] || 0) + (t.chain === 'BTC' ? 0 : i.v); upd(w, t); }
    for(const o of t.outs){ const w = wal(o.a, t.chain); w.n++; upd(w, t);
      if(insA.has(o.a) || (t.chain === 'BTC' && owner && find(o.a) === owner)){ t.change = (t.change || 0) + o.v; continue; }                 // change back to the sender is not a payment
      w.inn[t.asset] = (w.inn[t.asset] || 0) + o.v; for(const i of t.ins){ wal(i.a).to.add(o.a); w.from.add(i.a); }
      if(t.chain === 'BTC') for(const i of t.ins){ wal(i.a).out.BTC = (wal(i.a).out.BTC || 0) + o.v * i.v / tot; }
      if(owner) addFlow(owner, find(o.a), t.asset, o.v, t); } }
  function upd(w, t){ if(t.ts){ w.first = Math.min(w.first ?? t.ts, t.ts); w.last = Math.max(w.last ?? t.ts, t.ts); } }
  /* owners (groups of addresses) */
  const own = new Map(); for(const w of W.values()){ const k = find(w.a); if(!own.has(k)) own.set(k, {id:k, addrs:[], chain:w.chain}); own.get(k).addrs.push(w.a); }
  /* the case's own wallets: named in its other evidence or its vault, marked, or the address an explorer page was about — not every address inside the pasted transactions */
  const paste = new Set(srcs.map(x => x.r.id)), ents = new Map();
  for(const e of D.ents.values()){ if(!/^(btc|eth|ltc|trx|doge|xmr)$/.test(e.k)) continue; const vd = verdictOf(e.id); if(e.recs.some(r => !paste.has(r.id)) || (D.byKey && D.byKey.has(e.id)) || vd === 'malicious' || vd === 'suspicious') ents.set(wlNorm(e.v), e); }
  for(const en of D.entries || []){ const v = typeof primary === 'function' ? wlNorm(primary(en)) : ''; if(v && W.has(v) && !ents.has(v)) ents.set(v, {v}); }
  for(const x of srcs){ let P = null; try{ P = walletParse(x.r.body); }catch(e){} for(const a of (P && P.focus) || []){ const n = wlNorm(a); if(W.has(n) && !ents.has(n)) ents.set(n, {v:n}); } }
  const focus = new Set([...W.keys()].filter(a => ents.has(a)).map(find));
  /* in other cases */
  const g = typeof globalEnts === 'function' ? globalEnts() : new Map(), other = new Map();
  for(const [id, x] of g){ if(!/^(btc|eth|ltc|trx|doge)[:|]/.test(id)) continue; const a = wlNorm(id.replace(/^\w+[:|]/, '')); if(!W.has(a)) continue; const cs = [...x.cases].filter(c => c !== caseId); if(cs.length) other.set(a, cs); }
  /* what stands out */
  const F = [...flows.values()], notes = [], byOwnerIn = new Map(), byOwnerOut = new Map();
  for(const e of F){ if(!byOwnerIn.has(e.to)) byOwnerIn.set(e.to, []); byOwnerIn.get(e.to).push(e); if(!byOwnerOut.has(e.f)) byOwnerOut.set(e.f, []); byOwnerOut.get(e.f).push(e); }
  for(const [o, L] of byOwnerIn){ const payers = new Set(L.map(e => e.f)); if(payers.size >= 4) notes.push({kind:'fan-in', o, n:payers.size, t:`${payers.size} different payers into one ${own.get(o) && own.get(o).addrs.length > 1 ? 'owner' : 'wallet'} — collection point (victims paying in, or deposits)`}); }
  for(const [o, L] of byOwnerOut){ const payees = new Set(L.map(e => e.to)); if(payees.size >= 4) notes.push({kind:'fan-out', o, n:payees.size, t:`Pays out to ${payees.size} different wallets — distribution or payroll`}); }
  for(const [o, L] of byOwnerOut){ const ins = byOwnerIn.get(o) || []; for(const e of L){ const before = ins.filter(x => x.asset === e.asset && x.last != null && e.first != null && x.last <= e.first && e.first - x.last <= 6 * 36e5).reduce((s, x) => s + x.v, 0); if(before && e.v >= before * 0.8 && e.v <= before * 1.05){ notes.push({kind:'pass-through', o, t:`Money passes straight through: ${wlAmt(before, e.asset)} in, ${wlAmt(e.v, e.asset)} out within ${E.fmtGap(e.first - Math.max(...ins.filter(x => x.asset === e.asset).map(x => x.last)))}`}); break; } } }
  /* peel chain: a single owner pays a small amount and sends the rest on to a new address, again and again */
  const peel = []; for(const t of txs){ if(t.chain !== 'BTC' || t.ins.length !== 1 || t.outs.length !== 2) continue; const [a, b] = [...t.outs].sort((x, y) => y.v - x.v); if(a.v >= b.v * 4) peel.push({t, next:a.a, from:t.ins[0].a, pay:b}); }
  const byFrom = new Map(peel.map(p => [p.from, p])); for(const p of peel){ if([...byFrom.values()].some(q => q.next === p.from)) continue; let n = 0, cur = p, chain = []; while(cur && n < 50){ chain.push(cur); n++; cur = byFrom.get(cur.next); }
    if(chain.length >= 3) notes.push({kind:'peel', o:find(chain[0].from), t:`Peel chain: ${chain.length} hops, each paying out a small amount (${chain.map(c => wlAmt(c.pay.v, 'BTC')).slice(0, 4).join(', ')}${chain.length > 4 ? '…' : ''}) and moving the rest to a new address`, addrs:chain.map(c => c.from)}); }
  if(cj.size) notes.push({kind:'coinjoin', t:`${cj.size} transaction${cj.size > 1 ? 's look' : ' looks'} like CoinJoin (many inputs, equal outputs) — their inputs are not grouped as one owner`});
  const v = {txs, wallets:[...W.values()], owners:own, find, flows:F.sort((a, b) => (a.first || 0) - (b.first || 0)), focus, ents, other, notes, srcs, cj};
  WL_C.sig = sig; WL_C.v = v; return v;
}
const WL_C = {sig:'', v:null};
const wlShort = a => a.length > 16 ? a.slice(0, 8) + '…' + a.slice(-6) : a;
const wlAmt = (v, asset) => (Math.abs(v) >= 1000 ? Math.round(v).toLocaleString('en') : Math.abs(v) >= 1 ? (+v.toFixed(4)).toLocaleString('en', {maximumFractionDigits:4}) : +v.toPrecision(4)) + ' ' + asset;
const wlOwnerName = (X, o) => { const g = X.owners.get(o); if(!g) return wlShort(o); return g.addrs.length > 1 ? `${wlShort(g.addrs.find(a => X.ents.has(a)) || g.addrs[0])} +${g.addrs.length - 1}` : wlShort(g.addrs[0]); };
/* the picture: the case's own wallets in the middle, who paid them on the left, who they paid on the right */
function walletSvg(X){
  const tot = new Map(); for(const e of X.flows){ tot.set(e.f, (tot.get(e.f) || 0) + 1); tot.set(e.to, (tot.get(e.to) || 0) + 1); }
  if(!X.flows.length) return '';
  const start = X.focus.size ? [...X.focus] : [...tot.entries()].sort((a, b) => b[1] - a[1]).slice(0, 1).map(x => x[0]);
  const col = new Map(start.map(s => [s, 0])), q = [...start];
  while(q.length){ const n = q.shift(), c = col.get(n); for(const e of X.flows){ if(e.f === n && !col.has(e.to) && c >= 0 && c < 3){ col.set(e.to, c + 1); q.push(e.to); } if(e.to === n && !col.has(e.f) && c <= 0 && c > -3){ col.set(e.f, c - 1); q.push(e.f); } } }
  const nodes = [...col.entries()].sort((a, b) => a[1] - b[1]).slice(0, 40), cols = [...new Set(nodes.map(n => n[1]))].sort((a, b) => a - b), per = new Map();
  for(const [n, c] of nodes){ if(!per.has(c)) per.set(c, []); per.get(c).push(n); }
  const W = Math.max(720, cols.length * 210), H = Math.max(...[...per.values()].map(l => l.length)) * 58 + 40, pos = new Map();
  cols.forEach((c, i) => per.get(c).forEach((n, j) => pos.set(n, {x:90 + i * ((W - 180) / Math.max(1, cols.length - 1)), y:30 + (j + .5) * ((H - 40) / per.get(c).length)})));
  const mxA = {}; for(const e of X.flows) mxA[e.asset] = Math.max(mxA[e.asset] || 0, e.v);          // widths compare amounts of the same coin only
  const edges = X.flows.filter(e => pos.has(e.f) && pos.has(e.to) && e.f !== e.to).map(e => { const A = pos.get(e.f), B = pos.get(e.to), w = 1 + 4 * Math.sqrt(e.v / (mxA[e.asset] || 1));
    return `<path d="M${A.x + 8},${A.y} C${(A.x + B.x) / 2},${A.y} ${(A.x + B.x) / 2},${B.y} ${B.x - 8},${B.y}" class="wl-e" style="stroke-width:${w.toFixed(1)}"><title>${esc(wlOwnerName(X, e.f) + ' → ' + wlOwnerName(X, e.to) + ': ' + wlAmt(e.v, e.asset) + ' in ' + e.n + ' payment' + (e.n > 1 ? 's' : ''))}</title></path><text x="${(A.x + B.x) / 2}" y="${(A.y + B.y) / 2 - 4}" class="wl-a">${esc(wlAmt(e.v, e.asset))}</text>`; }).join('');
  const nd = [...pos.entries()].map(([n, p]) => { const g = X.owners.get(n), mine = X.focus.has(n), oth = g && g.addrs.some(a => X.other.has(a));
    return `<g class="wl-n${mine ? ' mine' : ''}${oth ? ' other' : ''}"><circle cx="${p.x}" cy="${p.y}" r="${mine ? 9 : 7}"></circle><text x="${p.x}" y="${p.y + 22}" text-anchor="middle">${esc(wlOwnerName(X, n))}</text></g>`; }).join('');
  return `<div class="wl-svg" role="img" aria-label="Who paid whom: payers on the left, the case's wallets in the middle, who they paid on the right"><svg viewBox="0 0 ${W} ${H}" width="${W}" height="${H}">${edges}${nd}</svg></div>`;
}
function walletView(c){
  const X = walletIndex(c.id), when = ms => ms ? E.fmtFull(ms, tz()).slice(0, 16) : '—';
  const head = `<div class="if-top"><p class="t2" style="margin:0">Paste transactions from a block explorer: Blockstream or mempool.space, blockchain.com or BlockCypher (Bitcoin), Etherscan JSON or CSV export (Ethereum and tokens), Tronscan or TronGrid (TRON, USDT). Each paste is kept as evidence. Nothing is looked up.</p><button class="btn primary sm" data-act="wlPaste">${ico('plus','sm')}Paste transactions</button></div>`;
  if(!X.txs.length) return head + empty('bitcoin', 'No transactions in this case yet', 'Paste an address\'s transactions from a block explorer and who paid whom shows up here, with owners grouped and patterns pointed out.');
  const assets = {}; for(const e of X.flows) assets[e.asset] = (assets[e.asset] || 0) + e.v;
  const owner = o => `<button class="lnk mono" data-act="wlOwner" data-v="${esc(o)}">${esc(wlOwnerName(X, o))}</button>${X.focus.has(o) ? ' <span class="chip sq">this case</span>' : ''}`;
  const groups = [...X.owners.values()].filter(g => g.addrs.length > 1);
  const sel = UI.wlOwner && X.owners.has(UI.wlOwner) ? UI.wlOwner : null, F = sel ? X.flows.filter(e => e.f === sel || e.to === sel) : X.flows;
  return `${head}<div class="if-sum card"><div class="tlx-kpi"><div><b>${X.wallets.length}</b><span>addresses</span></div><div><b>${X.owners.size}</b><span>owners after grouping</span></div><div><b>${X.txs.length}</b><span>transactions</span></div>${Object.entries(assets).slice(0, 3).map(([a, v]) => `<div><b>${esc(wlAmt(v, a).split(' ')[0])}</b><span>${esc(a)} moved</span></div>`).join('')}</div>${walletSvg(X)}
      <p class="t3 small">The case's own wallets (those in its evidence and vault) are in the middle, payers to the left, payees to the right. Line width follows the amount.</p></div>
    ${X.notes.length ? `<section class="card if-c"><h3>What stands out</h3><ul class="if-l0">${X.notes.map(n => `<li class="if-g"><div class="if-gh"><span class="chip sq ${n.kind === 'coinjoin' ? '' : 'amber'}">${esc({'fan-in':'Collection point', 'fan-out':'Distribution', 'pass-through':'Pass-through', peel:'Peel chain', coinjoin:'CoinJoin'}[n.kind])}</span>${n.o ? owner(n.o) : ''}</div><div class="t2 small">${esc(n.t)}</div></li>`).join('')}</ul></section>` : ''}
    ${X.other.size ? `<section class="card if-c"><h3>In other cases</h3><ul class="if-l0">${[...X.other.entries()].map(([a, cs]) => `<li class="if-g"><span class="mono">${esc(a)}</span> — ${cs.map(id => { const k = theCase(id); return k ? `<a href="${caseHash(id, 'overview')}"><b>${esc(k.name.split(' — ')[0])}</b></a>` : ''; }).join(', ')}</li>`).join('')}</ul></section>` : ''}
    ${groups.length ? `<section class="card if-c"><h3>One owner, several addresses</h3><p class="t3 small">Addresses spent together in one Bitcoin transaction almost always belong to one wallet (the common-input rule). It can be fooled on purpose — CoinJoin and PayJoin — so treat it as strong, not certain.</p><ul class="if-l0">${groups.map(g => `<li class="if-g"><div class="if-gh">${owner(g.id)}<span class="t3">${g.addrs.length} addresses</span></div><div class="mono small wl-as">${g.addrs.map(a => esc(a)).join('<br>')}</div></li>`).join('')}</ul></section>` : ''}
    <section class="card if-c"><h3>Payments${sel ? ` to and from <span class="mono">${esc(wlOwnerName(X, sel))}</span> <button class="btn xs" data-act="wlOwner" data-v="">Show all</button>` : ''} <span class="t3">${F.length}</span></h3><div class="if-tw"><table class="if-t"><thead><tr><th scope="col">When</th><th scope="col">From</th><th scope="col">To</th><th scope="col">Amount</th><th scope="col">Transactions</th><th scope="col"></th></tr></thead><tbody>
      ${F.slice(0, 500).map(e => `<tr><td class="mono">${esc(when(e.first))}${e.n > 1 && e.last !== e.first ? `<div class="t3">to ${esc(when(e.last))}</div>` : ''}</td><td>${owner(e.f)}</td><td>${owner(e.to)}</td><td class="mono">${esc(wlAmt(e.v, e.asset))}</td><td>${e.n}</td><td><button class="btn xs" data-act="wlRecs" data-v="${esc([...e.recs].join(','))}">Evidence</button> <button class="iconbtn sm" data-act="wlCopy" data-v="${esc(e.txs.join('\n'))}" aria-label="Copy the transaction IDs">${ico('copy','sm')}</button></td></tr>`).join('')}</tbody></table></div>${F.length > 500 ? `<p class="t3 small">Showing 500 of ${F.length}.</p>` : ''}</section>
    <section class="card if-c"><h3>Addresses <span class="t3">${X.wallets.length}</span></h3><div class="if-tw"><table class="if-t"><thead><tr><th scope="col">Address</th><th scope="col">Chain</th><th scope="col">Received</th><th scope="col">Sent</th><th scope="col">Active</th></tr></thead><tbody>
      ${X.wallets.sort((a, b) => (X.focus.has(X.find(b.a)) - X.focus.has(X.find(a.a))) || b.n - a.n).slice(0, 300).map(w => `<tr><td class="mono"><button class="lnk mono" data-act="wlOwner" data-v="${esc(X.find(w.a))}">${esc(w.a)}</button>${X.other.has(w.a) ? ' <span class="chip sq red">other cases</span>' : ''}</td><td>${esc(w.chain)}</td><td class="mono">${Object.entries(w.inn).map(([a, v]) => esc(wlAmt(v, a))).join('<br>') || '—'}</td><td class="mono">${Object.entries(w.out).filter(([, v]) => v).map(([a, v]) => esc(wlAmt(v, a))).join('<br>') || '—'}</td><td class="mono t3">${esc(when(w.first))}${w.last !== w.first ? '<br>' + esc(when(w.last)) : ''}</td></tr>`).join('')}</tbody></table></div></section>`;
}
function walletPasteDlg(){
  openDlg(dhead('Paste transactions') + `<form data-form="wlPaste"><div class="in">
    <div class="field"><label for="wlText">Transactions <span class="t3">— JSON from Blockstream, mempool.space, blockchain.com, BlockCypher, Etherscan, Tronscan or TronGrid, or an Etherscan CSV export</span></label><textarea id="wlText" rows="12" class="mono" spellcheck="false"></textarea><span class="hint" id="wlHint" aria-live="polite"></span></div></div>
    <footer><button class="btn" type="button" data-act="dclose">Cancel</button><button class="btn primary" type="submit">Add to the case</button></footer></form>`, true);
}
function walletSubmit(){
  const t = String($('wlText').value || '').trim(); if(!t) return fieldErr('wlText', 'Paste the transactions first.'); if(t.length > 8 << 20) return fieldErr('wlText', 'That is over 8 MB — split it into smaller pastes.');
  const P = walletParse(t); if(!P) return fieldErr('wlText', 'Not recognised. Paste the JSON an explorer gives for an address or transaction, or an Etherscan CSV export.');
  const c = theCase(); if(!walletKeep(t, P, c.id)) return fieldErr('wlText', 'These exact transactions are already in the case.');
  closeDlg(); mutate('added ' + P.kind + ' transactions'); renderMain(); toast(`${P.kind}: ${P.txs.length} transaction${P.txs.length > 1 ? 's' : ''} added`);
}
document.addEventListener('input', ev => { if(ev.target && ev.target.id === 'wlText'){ const h = $('wlHint'); if(!h) return; clearTimeout(UI.wlT); UI.wlT = setTimeout(() => { let P = null; try{ P = walletParse(ev.target.value); }catch(e){} h.textContent = P ? 'Recognised: ' + P.label : ev.target.value.trim() ? 'Not recognised yet' : ''; }, 250); } });
const WL_ACTS = {
  ivView:(id, v) => { UI.ivView = v; renderMain(); },
  cnMsgs:() => { const R = DB.records.filter(r => r.caseId === DB.active && r.chatAuthor).map(r => r.id); if(!R.length) return; UI.facet.ids = R; UI.facet.idsLabel = 'chat records, one per author'; UI.tlMode = 'events'; UI.q = ''; go(caseHash(DB.active, 'timeline')); },
  wlPaste:() => walletPasteDlg(),
  wlOwner:(id, v) => { UI.wlOwner = v || null; renderMain(); },
  wlRecs:(id, v) => { UI.facet.ids = String(v).split(',').filter(Boolean); UI.facet.idsLabel = 'records behind this payment'; UI.tlMode = 'events'; go(caseHash(DB.active, 'timeline')); },
  wlCopy:(id, v) => copyText(v),
};
