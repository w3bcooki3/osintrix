// Money trail: a wallet's transactions — fetched (mocked sources here) or imported from a file — read into counterparties,
// amounts, same-owner estimates and sanctions exposure, and brought into the case as vault entries, links and timeline events.
const { test, expect } = require('@playwright/test');
const { open, capture, noErrors, fixture } = require('./helpers');
const fs = require('fs');

const cors = { 'access-control-allow-origin': '*', 'content-type': 'application/json' };
const B32 = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const addr = seed => { let x = seed * 2654435761 % 4294967296; return 'bc1q' + Array.from({ length: 38 }, () => B32[(x = (x * 1103515245 + 12345) % 2147483648) >> 16 & 31]).join(''); };
const W = 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh';   // the demo case's wallet
const W2 = addr(2), SANC = addr(3), CASH = addr(4), CJA = addr(5), CJB = addr(6), V1 = addr(7);
const T0 = 1757836800;   // 2025-09-14
const tx = (id, t, vin, vout, fee = 1000) => ({ txid: id.padEnd(64, '0'), status: { confirmed: true, block_height: 900000 + t, block_time: T0 + t * 3600 }, fee,
  vin: vin.map(([a, v]) => ({ prevout: { scriptpubkey_address: a, value: v } })), vout: vout.map(([a, v]) => ({ scriptpubkey_address: a, value: v })) });
// 30 small payments in, then the big ones: a victim pays, W spends together with W2 to a sanctioned wallet and a cash-out, and a CoinJoin
const PAY = Array.from({ length: 30 }, (_, i) => tx('aa' + String(i).padStart(2, '0'), i, [[addr(100 + i), 120000]], [[W, 100000], [addr(100 + i), 19000]]));
const BIG = [
  tx('b1', 40, [[V1, 31000000]], [[W, 30000000], [V1, 990000]], 10000),
  tx('b2', 41, [[W, 20000000], [W2, 15000000]], [[SANC, 25000000], [CASH, 9990000]], 10000),
  tx('b3', 42, [[W, 6000000], [CJA, 6000000], [CJB, 6000000]], [[addr(50), 5000000], [addr(51), 5000000], [addr(52), 5000000], [W, 990000], [CJA, 990000], [CJB, 990000]], 30000),
];
const ALL = PAY.concat(BIG).sort((a, b) => b.status.block_time - a.status.block_time);   // newest first, as the API answers
async function mockMempool(page, hits) {
  await page.route('https://mempool.space/api/**', r => {
    const u = new URL(r.request().url()); hits.push(u.pathname);
    if (u.pathname === '/api/address/' + W) return r.fulfill({ headers: cors, body: JSON.stringify({ address: W, chain_stats: { tx_count: ALL.length, funded_txo_sum: 33990000, spent_txo_sum: 26000000 }, mempool_stats: { tx_count: 0, funded_txo_sum: 0, spent_txo_sum: 0 } }) });
    if (u.pathname === '/api/address/' + W + '/txs') return r.fulfill({ headers: cors, body: JSON.stringify(ALL.slice(0, 25)) });
    const m = /\/txs\/chain\/(\w+)$/.exec(u.pathname); if (m) { const i = ALL.findIndex(t => t.txid === m[1]); return r.fulfill({ headers: cors, body: JSON.stringify(ALL.slice(i + 1, i + 26)) }); }
    r.fulfill({ status: 404, headers: cors, body: 'not found' });
  });
}
async function mockSanctions(page) {
  await page.route('https://raw.githubusercontent.com/0xB10C/**', r => { const f = /sanctioned_addresses_(\w+)\.json$/.exec(r.request().url())[1];
    r.fulfill({ headers: cors, body: JSON.stringify({ XBT: [SANC, '12QtD5BFwRsdNsAZY76UVE1xyCGNTojH9h'], ETH: ['0xD90E2F925DA726B50C4ED8D0FB90AD053324F31B'], USDT: ['TT1qhPf8CMG5ZLJEGXTfBQrGbx5DnFsrbX'], USDC: [], TRX: ['TT1qhPf8CMG5ZLJEGXTfBQrGbx5DnFsrbX'] }[f] || []) }); });
}

test('money trail (Bitcoin): asks before sending the address, fetches every page, and reads amounts, counterparties, same owner and CoinJoin', async ({ page }) => {
  const errors = await open(page, '#/case/c-lantern/vault');
  const hits = [], other = []; await mockMempool(page, hits);
  page.on('request', r => { const u = r.url(); if (/^https?:/.test(u) && !/^https:\/\/mempool\.space\//.test(u)) other.push(u); });
  await page.evaluate(w => select('ent', 'btc:' + w), W);
  const sec = page.locator('#insp .ch');
  await expect(sec.locator('h4')).toContainText('Money trail');
  await sec.locator('[data-act=chGet]').click();
  // nothing is sent until you agree, and the dialog says exactly what would be
  await expect(page.locator('#dlg')).toContainText('Only this address is sent to mempool.space');
  expect(hits).toEqual([]);
  await page.locator('#dlg [data-act=chGetOk]').click();
  await expect(sec.locator('.ch-kv')).toContainText('Transactions33 of 33');
  expect(hits).toEqual(['/api/address/' + W, '/api/address/' + W + '/txs', '/api/address/' + W + '/txs/chain/' + ALL[24].txid]);
  expect(other).toEqual([]);   // no other site was contacted
  // what came back is kept as evidence in the case, and the case's Money view reads it
  const ev = await page.evaluate(([w, s]) => { const r = DB.records.filter(x => x.caseId === 'c-lantern' && x.source === 'chain:mempool.space'); const X = walletIndex('c-lantern');
    return [r.length, r[0] && r[0].title, X.flows.some(f => f.to === X.find(s))]; }, [W, SANC]);
  expect(ev).toEqual([1, `Bitcoin transactions of ${W.slice(0, 10)}…${W.slice(-6)} — 33 from mempool.space`, true]);
  await expect(page.locator('.toast').last()).toContainText('kept as evidence in');
  // received: 30 × 0.001 + 0.3; sent: what left W itself — 0.2 with W2, and 0.06 into the CoinJoin less its 0.0099 back
  await expect(sec.locator('.ch-kv')).toContainText('Received0.33 BTC');
  await expect(sec.locator('.ch-kv')).toContainText('Sent0.2501 BTC');
  await expect(sec.locator('.ch-kv')).toContainText('Balance0.0799 BTC');
  await expect(sec.locator('.ch-cp').first()).toContainText('+0.3 BTC');   // the victim, the largest
  await expect(sec.locator('.ch-co')).toContainText(W2.slice(0, 10));      // spent together → probably the same owner
  await expect(sec.locator('.ch-co')).not.toContainText(CJA.slice(0, 10)); // but not the CoinJoin partners
  await expect(sec).toContainText('1 transaction looks like CoinJoin');
  // a counterparty is credited with what the transaction paid it; a CoinJoin's outputs are nobody's counterparties
  const sanc = await page.evaluate(([w, s]) => { const T = chTrail('btc', w), r = T.cps.find(x => x.a === s); return chFmt(r.amt.BTC.out, 8); }, [W, SANC]);
  expect(sanc).toBe('0.25');
  expect(await page.evaluate(w => chTrail('btc', w).cps.some(r => /^bc1q/.test(r.a) && r.amt.BTC && r.amt.BTC.out === 5000000n), W)).toBe(false);
  noErrors(errors);
});

test('money trail (Bitcoin): sanctions exposure, labels, and into the case — vault links, the graph and the timeline', async ({ page }) => {
  const errors = await open(page, '#/case/c-lantern/vault');
  const hits = []; await mockMempool(page, hits); await mockSanctions(page);
  await page.evaluate(w => { lkSettings().on.mempool = true; select('ent', 'btc:' + w); }, W);
  await page.locator('#insp .ch [data-act=chGet]').click();
  await expect(page.locator('#insp .ch .ch-kv')).toContainText('33 of 33');
  // the sanctions list: downloaded once on request, then checked here
  await page.locator('#insp .ch [data-act=chSancGet]').click();
  await expect(page.locator('#dlg')).toContainText('Nothing about your cases is sent');
  await page.locator('#dlg [data-act=chSancGo]').click();
  await expect(page.locator('#insp .ch .ipf-f.bad')).toContainText('1 counterparty is sanctioned');
  // the full trail
  await page.locator('#insp .ch [data-act=chOpen]').click();
  const row = page.locator('#dlg .ch-t tr', { hasText: SANC.slice(0, 10) });
  await expect(row.locator('.chx.bad')).toHaveText('Sanctioned (OFAC)');
  await expect(row).toContainText('−0.25 BTC');
  // a label you give shows wherever the wallet appears
  await page.locator('#dlg .ch-t tr', { hasText: V1.slice(0, 10) }).locator('[data-act=chLabel]').click();
  await page.fill('#chLt', 'Victim — Harbourline finance'); await page.selectOption('#chLk', 'victim'); await page.locator('#dlg [type=submit]').click();
  await expect(page.locator('#dlg .ch-t tr', { hasText: V1.slice(0, 10) }).locator('.chx')).toContainText('Victim — Harbourline finance');
  // pick the sanctioned wallet, the victim and (on the same-owner tab) W2, and add them, linked
  await page.locator(`#dlg [data-chpick="${SANC}"]`).check(); await page.locator(`#dlg [data-chpick="${V1}"]`).check();
  await page.locator('#dlg [data-act=chTab][data-v=co]').click();
  await page.locator(`#dlg [data-chpick="${W2}"]`).check();
  await expect(page.locator('#dlg [data-act=chVault]')).toHaveText('Add 3 to the vault, linked');
  await page.locator('#dlg [data-act=chVault]').click();
  const L = await page.evaluate(w => { const id = a => (DB.entries.find(e => e.caseId === 'c-lantern' && primary(e) === a) || {}).id, src = id(w);
    return DB.links.filter(l => l.a === src || l.b === src).filter(l => l.auto && /paid|same owner/.test(l.label)).map(l => [primary(entryById(l.a)) === w ? 'W' : primary(entryById(l.a)).slice(0, 10), l.label, primary(entryById(l.b)) === w ? 'W' : primary(entryById(l.b)).slice(0, 10), l.why]); }, W);
  expect(L).toEqual(expect.arrayContaining([
    ['W', 'paid', SANC.slice(0, 10), expect.stringMatching(/^0\.25 BTC in 1 transaction, /)],
    [V1.slice(0, 10), 'paid', 'W', expect.stringMatching(/^0\.3 BTC in 1 transaction, /)],
    ['W', 'same owner?', W2.slice(0, 10), 'Spent together in 1 transaction — common-input estimate']]));
  expect(L.length).toBe(3);
  // the graph draws them
  await page.evaluate(() => go(caseHash('c-lantern', 'graph')));
  await expect(page.locator('#main .gcanvas')).toBeVisible();
  expect(await page.evaluate(s => { const D = derive('c-lantern'), e = D.entries.find(x => primary(x) === s); return !!e && D.links.some(l => l.b === e.id && l.label === 'paid'); }, SANC)).toBe(true);
  // payments onto the timeline, once each
  await page.evaluate(w => { DB.active = 'c-lantern'; UI.ch = null; chDlg('btc', w); }, W);
  await page.locator('#dlg [data-act=chTl]').click();
  await expect(page.locator('.toast').last()).toContainText('added to the timeline');            // the payments are written after a storage check
  const recs = await page.evaluate(() => DB.records.filter(r => r.chainTx).map(r => [r.title, r.ents.length]));
  expect(recs.length).toBe(33);
  expect(recs).toContainEqual([`Sent 0.2 BTC to ${SANC.slice(0, 10)}…${SANC.slice(-6)} +1`, 3]);
  expect(recs).toContainEqual(['Sent 0.0501 BTC to a CoinJoin', 1]);
  await page.evaluate(w => chDlg('btc', w), W); await page.locator('#dlg [data-act=chTl]').click();
  await expect(page.locator('.toast').last()).toContainText('already on this case’s timeline');
  // export, and the export reads back
  await page.evaluate(w => chDlg('btc', w), W);
  const [dl] = await Promise.all([page.waitForEvent('download'), page.locator('#dlg [data-act=chCsv]').click()]);
  const csv = fs.readFileSync(await dl.path(), 'utf8');
  expect(csv.split('\n')[0]).toBe('hash,time,chain,from,to,amount,asset,direction,counterparties');
  expect(await page.evaluate(t => chParse(t, 'x').txs.length, csv)).toBe(33);
  noErrors(errors);
});

test('money trail (Ethereum): imported from Etherscan exports with no network at all — failed transactions left out, tokens kept apart', async ({ page }) => {
  const errors = await open(page, '#/case/c-lantern/timeline');
  const net = []; page.on('request', r => { if (/^https?:/.test(r.url())) net.push(r.url()); });
  const W = '0x7a3f9c2e5b1d4a6f8e0c2b4d6f8a1c3e5b7d9f2a';
  await capture(page, 'Suspect wallet from the chat: ' + W);
  await page.evaluate(w => select('ent', 'eth:' + w), W);
  for (const f of ['etherscan-txs.csv', 'etherscan-tokens.csv']) await page.evaluate(([t, n, w]) => chImportText(t, n, 'eth:' + w), [fs.readFileSync(fixture('trail/' + f), 'utf8'), f, W]);
  await page.keyboard.press('Escape');
  await page.evaluate(w => select('ent', 'eth:' + w), W);
  const sec = page.locator('#insp .ch');
  await expect(sec.locator('h4')).toContainText('7 transactions · from your files');
  await expect(sec.locator('.ch-kv')).toContainText('Received2.25 ETH');
  await expect(sec.locator('.ch-kv')).toContainText('Sent2.1 ETH + 0.002543 in fees');   // the reverted deposit moved nothing
  await expect(sec.locator('.ch-kv')).toContainText('TokensUSDT');
  const T = await page.evaluate(w => { const T = chTrail('eth', w); return { cps: T.cps.map(r => [r.a.slice(0, 6), chFmt(chAmt(r, 'ETH', 'in'), 18), chFmt(chAmt(r, 'ETH', 'out'), 18), r.amt.USDT ? chFmt(r.amt.USDT.in, 18) + '/' + chFmt(r.amt.USDT.out, 18) : '']), usdt: [chFmt(T.tot.USDT.in, 18), chFmt(T.tot.USDT.out, 18)], fail: T.rows.filter(x => x.dir === 'fail').length }; }, W);
  expect(T.cps).toEqual([['0x4b1e', '1.5', '0', '2,500/0'], ['0x28c6', '0', '1.2', '0/2,000.5'], ['0xd90e', '0', '0.9', ''], ['0x9d8c', '0.75', '0', '']]);
  expect(T.usdt).toEqual(['2,500', '2,000.5']); expect(T.fail).toBe(1);
  // a plain CSV works too; rows it cannot read are counted, not guessed
  await page.evaluate(t => chImportText(t, 'plain-btc.csv'), fs.readFileSync(fixture('trail/plain-btc.csv'), 'utf8'));
  await expect(page.locator('.toast').last()).toContainText('2 transactions imported (CSV) between 3 wallets · 1 row skipped');
  // explorer JSON the Money view reads works here too (Esplora, from the money-flows fixtures)
  const A = JSON.parse(fs.readFileSync(fixture('chain/addresses.json'), 'utf8'));
  await page.evaluate(t => chImportText(t, 'esplora-scam1.json'), fs.readFileSync(fixture('chain/esplora-scam1.json'), 'utf8'));
  await expect(page.locator('.toast').last()).toContainText('imported (Bitcoin (Esplora))');
  expect(await page.evaluate(s => chTrail('btc', s).n, A.S1)).toBeGreaterThan(0);
  // every imported file is kept as evidence
  expect(await page.evaluate(() => DB.records.filter(r => r.source === 'chain:import').length)).toBe(4);
  expect(net).toEqual([]);   // nothing left the browser
  noErrors(errors);
});

test('money trail (Ethereum): Blockscout pages, public name tags and scam flags are read; stored data is cleaned on load', async ({ page }) => {
  const errors = await open(page, '#/case/c-lantern/timeline');
  const W = '0x7a3f9c2e5b1d4a6f8e0c2b4d6f8a1c3e5b7d9f2a', EX = '0x28c6c06298d514db089934071355e5743bf21d60', SC = '0x00000000000000000000000000000000000bad01';
  const party = (h, x = {}) => ({ hash: h, ens_domain_name: null, is_contract: false, is_scam: false, metadata: null, name: null, public_tags: [], ...x });
  const etx = (h, from, to, v, ts, st = 'ok') => ({ hash: h, from: party(from), to: to === EX ? party(EX, { metadata: { tags: [{ name: 'Binance 14', tagType: 'name' }] } }) : to === SC ? party(SC, { is_scam: true }) : party(to), value: v, timestamp: ts, block_number: 1, fee: { value: '21000000000000' }, status: st, result: st === 'ok' ? 'success' : 'Reverted', method: null });
  const hits = [];
  await page.route('https://eth.blockscout.com/api/v2/**', r => { const u = new URL(r.request().url()); hits.push(u.pathname + u.search);
    if (u.pathname.endsWith('/transactions')) return r.fulfill({ headers: cors, body: JSON.stringify(u.searchParams.get('index') ? { items: [etx('0x' + 'c3'.repeat(32), W, SC, '100000000000000000', '2026-09-03T00:00:00Z')], next_page_params: null }
      : { items: [etx('0x' + 'c1'.repeat(32), '0x' + '11'.repeat(20), W, '2000000000000000000', '2026-09-01T00:00:00Z'), etx('0x' + 'c2'.repeat(32), W, EX, '1500000000000000000', '2026-09-02T00:00:00Z')], next_page_params: { block_number: 5, index: 7 } }) });
    if (u.pathname.endsWith('/token-transfers')) return r.fulfill({ headers: cors, body: JSON.stringify({ items: [{ transaction_hash: '0x' + 'd1'.repeat(32), log_index: 3, from: party(W), to: party(EX, { metadata: { tags: [{ name: 'Binance 14' }] } }), token: { symbol: 'USDC', decimals: '6', address_hash: '0xa0b8' + '0'.repeat(36), name: 'USD Coin' }, total: { value: '1250000000', decimals: '6' }, token_type: 'ERC-20', timestamp: '2026-09-04T00:00:00Z', block_number: 2 },
      { transaction_hash: '0x' + 'd2'.repeat(32), log_index: 1, from: party(EX), to: party(W), token: { symbol: 'NFT' }, total: { token_id: '7' }, token_type: 'ERC-721', timestamp: '2026-09-05T00:00:00Z' }], next_page_params: null }) });
    return r.fulfill({ headers: cors, body: JSON.stringify({ hash: W, coin_balance: '400000000000000000', ens_domain_name: 'lamp-ops.eth', is_contract: false, is_scam: false, metadata: null, public_tags: [] }) });
  });
  await capture(page, 'Wallet ' + W);
  await page.evaluate(w => { lkSettings().on.bscout = true; select('ent', 'eth:' + w); }, W);
  await page.locator('#insp .ch [data-act=chGet]').click();
  const sec = page.locator('#insp .ch');
  await expect(sec.locator('.ch-kv')).toContainText('Transactions4 of 4');
  await expect(sec.locator('.ch-kv')).toContainText('Balance0.4 ETH');
  await expect(sec.locator('.ch-l')).toContainText('lamp-ops.eth');
  await expect(sec.locator('.ch-cp', { hasText: '0x28c6c062' })).toContainText('Binance 14');
  await expect(sec.locator('.ch-cp', { hasText: '0x28c6c062' })).toContainText('USDC');
  await expect(sec.locator('.ch-cp', { hasText: '0x00000000' }).locator('.chx.warn')).toHaveText('Flagged as scam by Blockscout');
  // the kept Blockscout answer is read by the Money view, failed and NFT transfers left out
  expect(await page.evaluate(() => { const r = DB.records.find(x => x.source === 'chain:eth.blockscout.com'), P = walletParse(r.body); return [P.kind, P.txs.length, P.txs.filter(x => x.asset === 'USDC').length]; })).toEqual(['Ethereum (Blockscout)', 4, 1]);
  expect(hits.filter(h => /transactions/.test(h))).toEqual([`/api/v2/addresses/${W}/transactions`, `/api/v2/addresses/${W}/transactions?block_number=5&index=7`]);
  // what is stored survives a round trip through the cleaner, and junk does not
  const c = await page.evaluate(() => { const C = chClean(JSON.parse(JSON.stringify(DB.chain))); const bad = chClean({ tx: { x: { c: 'doge', i: [], o: [] }, y: { c: 'eth', i: [['<b>', 'NaN']], o: [] } }, labels: { a: { t: '' } }, sanc: { btc: [1, 'ok'] } });
    return [Object.keys(C.tx).length === Object.keys(DB.chain.tx).length, Object.keys(bad.tx), bad.tx.y.i[0][1], Object.keys(bad.labels).length, bad.sanc.btc]; });
  expect(c).toEqual([true, ['y'], '0', 0, ['ok']]);
  noErrors(errors);
});

test('legacy Bitcoin addresses: the Base58Check checksum is verified', async ({ page }) => {
  const errors = await open(page);
  const r = await page.evaluate(() => ['1BoatSLRHtKNngkdXEeobR76b53LETtpyT', '1BoatSLRHtKNngkdXEeobR76b53LETtpyU', '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy'].map(a => { const P = ipfProfile('btc', a); return [Object.fromEntries(P.facts).Checksum || '', P.flags.map(f => f.t).join()]; }));
  expect(r).toEqual([['Valid (Base58Check)', ''], ['', 'Checksum fails'], ['Valid (Base58Check)', '']]);
  noErrors(errors);
});

test('money trail: accessible in both themes', async ({ page }) => {
  const AxeBuilder = require('@axe-core/playwright').default;
  const errors = await open(page, '#/case/c-lantern/vault');
  const hits = []; await mockMempool(page, hits); await mockSanctions(page);
  await page.evaluate(w => { lkSettings().on.mempool = true; select('ent', 'btc:' + w); }, W);
  await page.locator('#insp .ch [data-act=chGet]').click(); await expect(page.locator('#insp .ch .ch-kv')).toContainText('33 of 33');
  await page.evaluate(() => chSancGet(true)); await expect(page.locator('#insp .ch .ipf-f.bad')).toBeVisible();
  const serious = r => r.violations.filter(v => ['serious', 'critical'].includes(v.impact)).map(v => v.id + ': ' + v.nodes.map(n => n.target).join(' '));
  for (const theme of ['light', 'dark']) {
    await page.evaluate(([t, w]) => { DB.prefs.theme = t; applyPrefs(); closeDlg(); select('ent', 'btc:' + w); }, [theme, W]);
    await expect(page.locator('#insp .ch .ch-kv')).toBeVisible();
    expect(serious(await new AxeBuilder({ page }).include('#insp').analyze())).toEqual([]);
    for (const tab of ['cp', 'tx', 'co']) {
      await page.evaluate(([w, t]) => { UI.ch = null; chDlg('btc', w, t); }, [W, tab]);
      await expect(page.locator('#dlg .ch-t')).toBeVisible();
      expect(serious(await new AxeBuilder({ page }).include('#dlg').analyze())).toEqual([]);
    }
  }
  noErrors(errors.filter(e => !/Connecting to 'file:.*violates the following Content Security Policy directive: "connect-src/.test(e)));
});

test('crypto identifiers: ENS names, Solana addresses and signatures, and Bitcoin / Ethereum transactions are told apart from file hashes, and each leads somewhere', async ({ page }) => {
  const errors = await open(page, '#/case/c-lantern/vault');
  const BTX = 'f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16';           // the first person-to-person Bitcoin payment
  const ETX = '0x5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060';
  const SHA = '2d4d7e1f2a0e8f0b0c2b4f9a5a0c3a1e2d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c';
  const SOL = '7EcDhSYGxXyscszYEp35KHN8vvw3svAuLKTzXwCFLtV';
  const SIG = '5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW';
  const JWT = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
  // a ransom note and a chat log, as an analyst pastes them
  await capture(page, `Pay to lamp-ops.eth or the Solana wallet ${SOL}.\nThe victim paid, txid: ${BTX}\nsee also https://mempool.space/tx/${BTX}\nrefund went out in ${ETX}\nSolana signature ${SIG}\nDropper SHA-256 ${SHA}\nsession token ${JWT}\nethz.ch is a university.`, 'c-lantern');
  const K = await page.evaluate(() => { const r = DB.records[DB.records.length - 1]; return E.extract(r.body).map(x => x.k + ' ' + x.v); });
  expect(K).toEqual(expect.arrayContaining(['ens lamp-ops.eth', 'sol ' + SOL, 'btctx ' + BTX, 'ethtx ' + ETX, 'soltx ' + SIG, 'sha256 ' + SHA, 'url https://mempool.space/tx/' + BTX]));
  expect(K.filter(k => /^sha256 /.test(k))).toEqual(['sha256 ' + SHA]);                       // the transaction ID is not also a file hash
  expect(K.filter(k => /^(sol|soltx) /.test(k)).length).toBe(2);                              // nothing in the JWT is taken for a Solana value
  expect(K.some(k => /ethz/.test(k) && !/^domain/.test(k))).toBe(false);

  // a Bitcoin transaction: fetched on its own, its wallets go into the case in one step, the answer is kept as evidence
  const hits = [];
  await page.route('https://mempool.space/api/**', r => { hits.push(new URL(r.request().url()).pathname);
    r.fulfill({ headers: cors, body: JSON.stringify({ txid: BTX, fee: 0, status: { confirmed: true, block_height: 170, block_time: 1231731025 },
      vin: [{ prevout: { scriptpubkey_address: '12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S', value: 5000000000 } }],
      vout: [{ scriptpubkey_address: '1Q2TWHE3GMdB6BZKafqwxXtWAWgFt5Jvm3', value: 1000000000 }, { scriptpubkey_address: '12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S', value: 4000000000 }] }) }); });
  await page.evaluate(id => select('ent', id), 'btctx:' + BTX);
  const P = page.locator('#insp');
  await expect(P).toContainText('BTC transaction');
  await expect(P.locator('.ipf, .isec').first()).toBeVisible();
  await P.locator('[data-act=chTxGet]').click();
  await page.click('[data-act=chTxOk]');                                                        // asks first: only the ID is sent
  const sec = P.locator('.isec.ch');
  await expect(sec.locator('.ch-kv')).toContainText('Confirmed'); await expect(sec.locator('.ch-kv')).toContainText('170');
  await expect(sec).toContainText('To · 2 outputs · 50 BTC'); await expect(sec.locator('.ch-cp', { hasText: '1Q2TWHE3' })).toContainText('10 BTC');
  expect(hits).toEqual(['/api/tx/' + BTX]);
  expect(await page.evaluate(() => DB.records.filter(r => r.source === 'chain:mempool.space' && /transaction f4184fc5/.test(r.title)).length)).toBe(1);
  await P.locator('[data-act=chTxWal]').click();
  expect(await page.evaluate(() => DB.entries.filter(e => e.caseId === 'c-lantern' && e.type === 'crypto' && /^1(Q2TWHE3|2cbQLTF)/.test(e.fields.address)).length)).toBe(2);
  // the wallet opens with its own trail section, which knows this transaction already
  await sec.locator('.ent', { hasText: '1Q2TWHE3' }).first().click(); await expect(P).toContainText('Money trail');

  // an Ethereum transaction, with a token transfer
  await page.route('https://eth.blockscout.com/api/v2/**', r => { const u = new URL(r.request().url()); hits.push(u.pathname + u.search);
    if (u.pathname.startsWith('/api/v2/search')) return r.fulfill({ headers: cors, body: JSON.stringify({ items: [{ type: 'token', name: 'Lamp', address_hash: '0x' + '99'.repeat(20) }, { type: 'ens_domain', address_hash: '0xA1E4380A3B1f749673E270229993eE55F35663b4', ens_info: { name: 'lamp-ops.eth', expiry_date: '2025-01-01T00:00:00.000Z' } }] }) });
    r.fulfill({ headers: cors, body: JSON.stringify({ hash: ETX, from: { hash: '0xA1E4380A3B1f749673E270229993eE55F35663b4', ens_domain_name: 'lamp-ops.eth' }, to: { hash: '0x5DF9B87991262F6BA471F09758CDE1c0FC1De734' }, value: '31337', timestamp: '2015-08-07T03:30:33.000000Z', status: 'ok', result: 'success', block_number: 46147, fee: { type: 'actual', value: '1050000000000000000' },
      token_transfers: [{ log_index: 0, from: { hash: '0xA1E4380A3B1f749673E270229993eE55F35663b4' }, to: { hash: '0x' + '22'.repeat(20) }, token: { symbol: 'USDT', decimals: '6', address_hash: '0x' + '33'.repeat(20) }, total: { value: '250000000', decimals: '6' }, token_type: 'ERC-20' }] }) }); });
  await page.evaluate(id => { lkSettings().on.bscout = true; select('ent', id); }, 'ethtx:' + ETX);
  await P.locator('[data-act=chTxGet]').click();
  await expect(sec.locator('.ch-kv')).toContainText('1.05 ETH');                                 // the fee
  await expect(sec).toContainText('Tokens moved'); await expect(sec).toContainText('250 USDT');
  await expect(sec.locator('.ch-cp', { hasText: '0xa1e4380a' }).first()).toContainText('lamp-ops.eth'); // the sender's ENS, from Blockscout

  // an ENS name resolves to its wallet; an expired registration is called out
  await page.evaluate(() => select('ent', 'ens:lamp-ops.eth'));
  await P.locator('[data-act=chEnsGet]').click();
  await expect(P.locator('.isec.ch .ent')).toContainText('0xa1e4380a3b1f749673e270229993ee55f35663b4');
  await expect(P.locator('.isec.ch')).toContainText('expired — anyone can register it');
  await P.locator('[data-act=chEnsAdd]').click();
  expect(await page.evaluate(() => { const e = DB.entries.find(x => x.caseId === 'c-lantern' && x.fields.address === '0xa1e4380a3b1f749673e270229993ee55f35663b4'); return e && e.notes; })).toBe('ENS: lamp-ops.eth');
  expect(await page.evaluate(() => DB.records.some(r => r.title === 'ENS lamp-ops.eth → 0xa1e4380a3b1f749673e270229993ee55f35663b4'))).toBe(true);

  // Solana: checked offline, opened in an explorer — nothing is fetched
  const before = hits.length;
  await page.evaluate(id => select('ent', id), 'sol:' + SOL);
  await expect(P).toContainText('Solana address'); await expect(P.locator(`a[href="https://solscan.io/account/${SOL}"]`).first()).toBeVisible();
  await page.evaluate(id => select('ent', id), 'soltx:' + SIG);
  await expect(P.locator(`a[href="https://solscan.io/tx/${SIG}"]`).first()).toBeVisible();
  expect(hits.length).toBe(before);
  // a 64-hex hash found next to payment words offers to be read as a transaction
  await page.evaluate(id => select('ent', id), 'sha256:' + SHA);
  await expect(P.locator('[data-act=selEnt][data-id="btctx:' + SHA + '"]')).toHaveCount(1);
  // stored lookups survive the cleaner
  expect(await page.evaluate(() => { const C = chClean(JSON.parse(JSON.stringify(DB.chain))); return [Object.keys(C.txq).length, C.ens['lamp-ops.eth'].a]; })).toEqual([2, '0xa1e4380a3b1f749673e270229993ee55f35663b4']);
  noErrors(errors);
});

test('Solana: transfers exported from an explorer become a trail — raw units read with their decimals, SOL and tokens apart — and nothing is fetched', async ({ page }) => {
  const net = []; page.on('request', r => { if (!/^(file|data|blob):/.test(r.url())) net.push(r.url()); });
  const errors = await open(page, '#/case/c-lantern/vault');
  const W = 'GfsJWjmGXMfct8JMR9Lm9ySUnniZbnGUTQDbT8ipWf9U', V = '2smn4jxZEcnQuRmjJhNbcgeouXDCD6ALD8TKHMfCBSCY', X = 'CX7qmkwesTtKaXrzaN5MWf5qtbXjaP8nwArq2WMhewQU';
  await capture(page, 'Victim was told to send SOL to ' + W, 'c-lantern');
  await page.waitForTimeout(400);                                                                  // the capture opens the timeline; select once it has
  const P = page.locator('#insp .isec.ch');
  await expect.poll(async () => { await page.evaluate(w => select('ent', 'sol:' + w), W); return P.count(); }).toBe(1);
  await expect(P).toContainText('Import its transfers'); await expect(P.locator('[data-act=chGet]')).toHaveCount(0);   // no fetch offered — none would work
  const [fc] = await Promise.all([page.waitForEvent('filechooser'), P.locator('[data-act=chImport]').click()]);
  await fc.setFiles(require('path').join(__dirname, 'fixtures', 'trail', 'solscan-transfers.csv'));
  await expect(page.locator('.toast').last()).toContainText('4 transactions imported (Solana transfers)'); await expect(page.locator('.toast').last()).toContainText('1 row skipped');
  const T = await page.evaluate(w => { const T = chTrail('sol', w); return { n: T.n, tot: Object.fromEntries(Object.entries(T.tot).map(([k, x]) => [k, [chFmt(x.in, x.dec), chFmt(x.out, x.dec)]])), cps: T.cps.map(r => r.a) }; }, W);
  expect(T.n).toBe(4);
  expect(T.tot.SOL).toEqual(['4', '3.9']);                                                       // 2.5 + 1.5 in, 3.9 out — from lamports and 9 decimals
  expect(Object.entries(T.tot).find(([k]) => k !== 'SOL')[1]).toEqual(['0', '1,250']);             // the USDC transfer, with its own 6 decimals
  expect(T.cps).toEqual(expect.arrayContaining([V, X]));
  // the wallets go into the case with Solana as their currency
  await page.evaluate(w => { UI.ch = null; chDlg('sol', w); }, W);
  await page.locator(`#dlg [data-chpick="${X}"]`).check(); await page.locator('#dlg [data-act=chVault]').click();
  expect(await page.evaluate(x => { const e = DB.entries.find(e => e.caseId === 'c-lantern' && e.fields.address === x); return e && e.fields.currency; }, X)).toBe('Solana');
  expect(net).toEqual([]);
  noErrors(errors);
});
