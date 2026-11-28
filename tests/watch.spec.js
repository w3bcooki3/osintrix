// The watchlist, 1.93: more kinds of change noticed, wallets watched, your own passive-DNS history,
// changes kept as evidence, per-indicator settings and opt-in desktop notices. The lookup sources are mocked:
// nothing here reaches the internet.
const { test, expect } = require('@playwright/test');
const { open, noErrors } = require('./helpers');

/* a little world the sources describe; the test changes it between checks */
function world() {
  return {
    a: ['203.0.113.5'], mx: [], ns: ['ns1.cheap-dns.example'], nx: false,
    registrar: 'Example Registrar', status: ['active'], certs: ['aa11'], subs: ['www.portal-refunds.example'],
    btc: { txs: 3, funded: 150000000, spent: 50000000 },
  };
}
async function mock(page, W) {
  const json = (route, body, status = 200) => route.fulfill({ status, contentType: 'application/json', headers: { 'access-control-allow-origin': '*' }, body: JSON.stringify(body) });
  await page.route(/^https:\/\/dns\.google\/resolve/, route => {
    const u = new URL(route.request().url()), t = u.searchParams.get('type');
    if (W.nx) return json(route, { Status: 3 });
    const ans = t === 'A' ? W.a.map(d => ({ type: 1, data: d })) : t === 'NS' ? W.ns.map(d => ({ type: 2, data: d + '.' })) : t === 'MX' ? W.mx.map(d => ({ type: 15, data: '10 ' + d + '.' })) : [];
    return json(route, { Status: 0, Answer: ans });
  });
  await page.route(/^https:\/\/rdap\.org\/domain\//, route => json(route, {
    ldhName: 'portal-refunds.example', status: W.status, nameservers: W.ns.map(n => ({ ldhName: n })),
    events: [{ eventAction: 'registration', eventDate: '2026-02-20T00:00:00Z' }, { eventAction: 'expiration', eventDate: '2027-02-20T00:00:00Z' }],
    entities: [{ roles: ['registrar'], vcardArray: ['vcard', [['fn', {}, 'text', W.registrar]]] }],
  }));
  await page.route(/^https:\/\/api\.certspotter\.com\//, route => json(route, W.certs.map((c, i) => ({ cert_sha256: c, not_before: '2026-03-0' + (i + 1) + 'T00:00:00Z', dns_names: ['portal-refunds.example', ...W.subs], issuer: { friendly_name: 'Let\'s Encrypt' } }))));
  await page.route(/^https:\/\/mempool\.space\/api\/address\//, route => json(route, { chain_stats: { tx_count: W.btc.txs, funded_txo_sum: W.btc.funded, spent_txo_sum: W.btc.spent }, mempool_stats: { tx_count: 0, funded_txo_sum: 0, spent_txo_sum: 0 } }));
  await page.evaluate(() => { const S = lkSettings(); S.on = { dns: true, rdap: true, cs: true, mempool: true }; LK.last = new Map(); lkGap.cs = 0; });
}
const D = 'domain:portal-refunds.example', B = 'btc:bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq';
const texts = (page, key) => page.evaluate(k => (DB.watch[k].alerts || []).flatMap(a => a.d.map(d => (d.hot ? '▲ ' : '') + d.t)), key);

test('the watchlist notices what moved: address, mail, certificates, subdomains, registrar, suspension, going dark — and a wallet moving money', async ({ page }) => {
  const errors = await open(page, '#/watch');
  const W = world(); await mock(page, W);
  await page.evaluate(async ([d, b]) => { DB.watch = {}; DB.watch[d] = { at: Date.now() }; DB.watch[b] = { at: Date.now() }; await watchCheck([d, b], { quiet: true }); }, [D, B]);
  expect(await texts(page, D)).toEqual([]);                                   // the first check sets the baseline
  // the crew moves the portal, sets up mail, gets a certificate for a new subdomain and transfers the domain
  Object.assign(W, { a: ['203.0.113.80'], mx: ['mx.mail-host.example'], certs: ['aa11', 'bb22'], subs: ['www.portal-refunds.example', 'pay.portal-refunds.example'], registrar: 'Cheap Names Ltd' });
  W.btc = { txs: 5, funded: 400000000, spent: 50000000 };
  await page.evaluate(async ([d, b]) => { await watchCheck([d, b], { quiet: true }); }, [D, B]);
  const t = (await texts(page, D)).join(' | ');
  expect(t).toContain('▲ New address: 203.0.113.80'); expect(t).toContain('Gone (address): 203.0.113.5');
  expect(t).toContain('▲ Mail set up: mx.mail-host.example'); expect(t).toContain('▲ 1 new certificate issued');
  expect(t).toContain('▲ New subdomain: pay.portal-refunds.example'); expect(t).toContain('▲ Transferred to another registrar: Example Registrar → Cheap Names Ltd');
  const w = (await texts(page, B)).join(' | ');
  expect(w).toContain('▲ 2 new transactions'); expect(w).toContain('▲ Balance 1 → 3.5 BTC');
  // the registrar suspends it, then it stops resolving
  W.status = ['client hold']; await page.evaluate(async d => { await watchCheck([d], { quiet: true }); }, D);
  expect((await texts(page, D))[0]).toBe('▲ Suspended by the registry or registrar: client hold');
  W.nx = true; await page.evaluate(async d => { await watchCheck([d], { quiet: true }); }, D);
  expect((await texts(page, D))[0]).toMatch(/^▲ Stopped resolving/);
  // your own history: both addresses, with first and last seen, the current one marked
  const seen = await page.evaluate(d => DB.watch[d].seen, D);
  expect(Object.keys(seen.ips).sort()).toEqual(['203.0.113.5', '203.0.113.80']);
  expect(seen.registrar['Cheap Names Ltd'][0]).toBeGreaterThanOrEqual(seen.registrar['Example Registrar'][0]);
  noErrors(errors);
});

test('a snapshot from before 1.93 is not reported as all new; it gains the new fields quietly', async ({ page }) => {
  const errors = await open(page, '#/watch');
  const W = world(); await mock(page, W);
  await page.evaluate(async d => { DB.watch = { [d]: { at: Date.now(), checked: 1, snap: { band: 'clean', score: 5, ports: '', ips: '203.0.113.5', ns: 'ns1.cheap-dns.example', vt: 0, abuse: 0, pulses: 0, malware: '' } } }; await watchCheck([d], { quiet: true }); }, D);
  expect(await texts(page, D)).toEqual([]);
  expect(await page.evaluate(d => DB.watch[d].snap.sv, D)).toBe(2);
  noErrors(errors);
});

test('a change becomes dated evidence in the cases that hold the indicator — once — and can be filed by itself', async ({ page }) => {
  const errors = await open(page, '#/watch');
  const W = world(); await mock(page, W);
  const cid = await page.evaluate(d => {
    const c = { id: uid('c'), name: 'Refund portal', code: 'RP-1', status: 'active', owner: 'You', created: Date.now(), updated: Date.now(), scope: '', color: CASE_COLORS[0], icon: 'briefcase' }; DB.cases.push(c);
    DB.records.push({ id: uid('r'), caseId: c.id, type: 'evidence', title: 'portal', body: 'the portal is portal-refunds.example', tsRaw: '', tsZone: 'explicit', ts: Date.now() - 864e5, source: 'test', host: '', tags: [], ents: E.extract('portal-refunds.example'), answer: '', addedBy: 'You', addedAt: Date.now(), hash: '' });
    DB.watch = { [d]: { at: Date.now() } }; mutate('t'); return c.id;
  }, D);
  await page.evaluate(async d => { await watchCheck([d], { quiet: true }); }, D);
  W.a = ['203.0.113.80']; await page.evaluate(async d => { await watchCheck([d], { quiet: true }); }, D);
  await page.evaluate(() => renderMain());
  await page.locator('.wl-row', { hasText: '203.0.113.80' }).getByRole('button', { name: 'Add to case' }).click();
  await expect(page.locator('.wl-row', { hasText: '203.0.113.80' })).toContainText('In the case');
  const rec = await page.evaluate(([c, d]) => DB.records.filter(r => r.caseId === c && r.source === 'watchlist').map(r => ({ title: r.title, ts: r.ts === DB.watch[d].alerts[0].at, ents: r.ents.map(e => e.k + ':' + e.v), tags: r.tags })), [cid, D]);
  expect(rec).toEqual([{ title: 'Watchlist: portal-refunds.example — New address: 203.0.113.80', ts: true, ents: expect.arrayContaining(['domain:portal-refunds.example', 'ipv4:203.0.113.80']), tags: ['watch', 'change'] }]);
  expect(await page.evaluate(d => watchFile(d, 0, false), D)).toBe(0);           // not twice
  // "add every change": the next one files itself
  await page.evaluate(d => { DB.watch[d].file = true; }, D);
  W.mx = ['mx.mail-host.example']; await page.evaluate(async d => { await watchCheck([d], { quiet: true }); }, D);
  expect(await page.evaluate(c => DB.records.filter(r => r.caseId === c && r.source === 'watchlist').map(r => r.addedBy), cid)).toEqual(['You', 'Watchlist']);
  noErrors(errors);
});

test('each watched item has a note, its own interval, mute and filing, and shows what your checks have seen', async ({ page }) => {
  const errors = await open(page, '#/watch');
  const W = world(); await mock(page, W);
  await page.evaluate(async d => { DB.prefs.watchEvery = 0; DB.watch = { [d]: { at: Date.now() } }; await watchCheck([d], { quiet: true }); renderMain(); }, D);
  W.a = ['203.0.113.80']; await page.evaluate(async d => { await watchCheck([d], { quiet: true }); renderMain(); }, D);
  await page.getByRole('button', { name: 'History and settings for portal-refunds.example' }).click();
  const card = page.locator('#wlDetail');
  await card.getByLabel('Why you watch it').fill('the portal server; tell me if it moves'); await card.getByLabel('Why you watch it').press('Tab');
  await card.getByLabel('Check online').selectOption('6');
  await card.getByLabel(/Mute/).check();
  const w = await page.evaluate(d => ({ note: DB.watch[d].note, every: DB.watch[d].every, mute: DB.watch[d].mute, any: watchAny(), ms: watchEvery(DB.watch[d]) }), D);
  expect(w).toEqual({ note: 'the portal server; tell me if it moves', every: 6, mute: true, any: true, ms: 6 * 3600e3 });   // its own interval runs even with the list's off
  await expect(card.locator('.wl-h', { hasText: 'Addresses' })).toContainText('203.0.113.80');
  await expect(card.locator('.wl-h tr', { hasText: '203.0.113.80' })).toContainText('now');
  await expect(card.locator('.wl-h tr', { hasText: '203.0.113.5' })).toContainText('before');
  await expect(page.locator('.wl-note')).toHaveText('the portal server; tell me if it moves');
  // a muted item still records the change, without a notice
  await page.evaluate(() => { window.__toasts = []; const t = window.toast; window.toast = (m, ...a) => { window.__toasts.push(m); return t(m, ...a); }; });
  W.a = ['198.51.100.23']; await page.evaluate(async d => { await watchCheck([d]); }, D);
  expect(await page.evaluate(() => window.__toasts.filter(m => /^Watchlist:/.test(m)))).toEqual([]);
  expect((await texts(page, D))[0]).toContain('New address: 198.51.100.23');
  noErrors(errors);
});

test('desktop notices only when asked for, only in the background, and discreet mode keeps the indicator off them', async ({ page }) => {
  const errors = await open(page, '#/watch');
  const W = world(); await mock(page, W);
  await page.evaluate(() => { window.__notes = []; window.Notification = class { constructor(t, o) { window.__notes.push([t, o.body]); } static get permission() { return 'granted'; } static requestPermission() { return Promise.resolve('granted'); } };
    Object.defineProperty(document, 'hidden', { configurable: true, get: () => true }); });
  await page.evaluate(async d => { DB.watch = { [d]: { at: Date.now() } }; await watchCheck([d], { quiet: true }); }, D);
  W.a = ['203.0.113.80']; await page.evaluate(async d => { await watchCheck([d], { quiet: true }); }, D);
  expect(await page.evaluate(() => window.__notes)).toEqual([]);              // not asked for
  await page.evaluate(() => { DB.prefs.watchNotify = true; });
  W.a = ['203.0.113.81']; await page.evaluate(async d => { await watchCheck([d], { quiet: true }); }, D);
  expect(await page.evaluate(() => window.__notes)).toEqual([['OSINTrix watchlist', 'portal-refunds.example: New address: 203.0.113.81']]);
  await page.evaluate(() => { DB.prefs.discreet = true; window.__notes = []; });
  W.a = ['203.0.113.82']; await page.evaluate(async d => { await watchCheck([d], { quiet: true }); }, D);
  expect(await page.evaluate(() => window.__notes)).toEqual([['OSINTrix watchlist', '1 watched item changed']]);
  noErrors(errors);
});

test('an imported workspace keeps the history and notes, but cannot make this browser check online more often', async ({ page }) => {
  const errors = await open(page, '#/watch');
  const r = await page.evaluate(d => {
    const prev = DB, file = JSON.parse(JSON.stringify(DB));
    file.watch = { [d]: { at: 1, checked: 2, every: 1, note: 'x'.repeat(900), mute: true, file: true, seen: { ips: { '203.0.113.5': [1, 2], '<b>': 'bad' }, evil: { a: [1, 1] } },
      snap: { sv: 2, band: 'clean', score: 300, ips: '203.0.113.5', registrar: 'R', bal: -5, nx: 'yes', junk: 'drop me' }, alerts: [{ at: 3, d: [{ hot: 1, t: 'New address' }], filed: true }] } };
    DB = file; importSafeIntel(prev); const w = DB.watch[d]; DB = prev; return w;
  }, D);
  expect(r.every).toBeUndefined(); expect(r.note.length).toBe(500); expect(r.mute).toBe(true); expect(r.file).toBe(true);
  expect(r.seen).toEqual({ ips: { '203.0.113.5': [1, 2] } });
  expect(r.snap).toEqual({ band: 'clean', score: 100, ips: '203.0.113.5', registrar: 'R', bal: 0, nx: true, sv: 2 });
  expect(r.alerts[0]).toEqual({ at: 3, d: [{ hot: true, t: 'New address' }], filed: true });
  noErrors(errors);
});

test('@phone the watchlist with a change and the history card open fits a phone', async ({ page }) => {
  const errors = await open(page, '#/watch');
  const W = world(); await mock(page, W);
  await page.evaluate(async d => { DB.watch = { [d]: { at: Date.now(), note: 'the portal server; tell me if it moves' } }; await watchCheck([d], { quiet: true }); }, D);
  W.a = ['203.0.113.80']; W.certs = ['aa11', 'bb22'];
  await page.evaluate(async d => { await watchCheck([d], { quiet: true }); UI.wOpen = d; renderMain(); }, D);
  await expect(page.locator('#wlDetail')).toBeVisible();
  await page.locator('.wl-row').first().scrollIntoViewIfNeeded(); await page.screenshot({ path: 'test-results/watch-phone.png' });
  await page.locator('#wlDetail').scrollIntoViewIfNeeded(); await page.screenshot({ path: 'test-results/watch-phone2.png' });
  expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBeLessThanOrEqual(0);
  noErrors(errors);
});
