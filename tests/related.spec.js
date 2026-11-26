// Duplicates and related entries. One ship or aircraft entered twice under different numbers is merged; one name on
// several accounts and look-alike domains are linked, never merged, with the reason on the link. Ordinary
// neighbours (two companies' domains, generic mailboxes, short names) are left alone.
const { test, expect } = require('@playwright/test');
const { open, noErrors } = require('./helpers');

const seed = () => {
  DB.cases.push(Object.assign({}, DB.cases[0], { id: 'rx', name: 'Related' })); DB.active = 'rx';
  const mk = (type, fields, tags = []) => { const e = { id: uid('v'), caseId: 'rx', type, fields, priority: 'medium', starred: false, tags, notes: '', src: '', created: Date.now(), pos: null }; DB.entries.push(e); return e; };
  const ids = {
    ship1: mk('vessel', { imo: '9074729', name: 'Nordic Star' }).id, ship2: mk('vessel', { imo: '9074729', mmsi: '636019825' }).id, ship3: mk('vessel', { mmsi: '636019825', flag: 'Liberia' }).id,
    otherShip: mk('vessel', { mmsi: '257123450' }).id,
    jet1: mk('aircraft', { registration: 'N628TS' }).id, jet2: mk('aircraft', { icao24: 'A835AF', operator: 'Falcon Landing LLC' }).id, plane: mk('aircraft', { registration: 'G-EUPT' }).id,
    h: mk('username', { username: 'nightowl_ops' }).id, x: mk('social', { url: 'https://x.com/NightOwl_Ops' }).id, mail: mk('email', { email: 'night.owl.ops+shop@gmail.com' }).id, mail2: mk('email', { email: 'nightowlops@proton.me' }).id,
    info1: mk('email', { email: 'info@alpha-trading.example' }).id, info2: mk('email', { email: 'info@beta-logistics.example' }).id, short1: mk('username', { username: 'bob' }).id, short2: mk('email', { email: 'bob@mail.example' }).id,
    real: mk('domain', { domain: 'paypal.com' }).id, digit: mk('domain', { domain: 'paypa1.com' }).id, cyr: mk('domain', { domain: 'раураl.com' }).id, words: mk('domain', { domain: 'paypal-secure-login.net' }).id,
    tld: mk('domain', { domain: 'paypal.net' }).id, sub: mk('domain', { domain: 'www.paypal.com' }).id,
    a: mk('domain', { domain: 'northwind-traders.example' }).id, b: mk('domain', { domain: 'contoso.example' }).id, c: mk('domain', { domain: 'example.org' }).id
  };
  mutate('seed'); return ids;
};

test('a ship or aircraft entered under different numbers is one duplicate group, US registration and address included', async ({ page }) => {
  const errors = await open(page, '#/home');
  const ids = await page.evaluate(seed);
  const G = await page.evaluate(() => dupGroups('rx').filter(g => /vessel|aircraft/.test(g.G[0].type)).map(g => ({ ids: g.G.map(e => e.id).sort(), why: g.why })));
  expect(G).toEqual(expect.arrayContaining([
    { ids: [ids.ship1, ids.ship2, ids.ship3].sort(), why: expect.stringMatching(/IMO number.*MMSI|MMSI.*IMO number/) },
    { ids: [ids.jet1, ids.jet2].sort(), why: expect.stringMatching(/ICAO address|registration/) }]));
  expect(G.length).toBe(2);   // the other ship and G-EUPT stay on their own
  // merging the jets keeps one aircraft with both numbers and the operator
  await page.evaluate(() => go(caseHash('rx', 'vault')));
  await page.click('[data-act=dupOpen]');
  const sec = page.locator('.dp-g', { hasText: 'Aircraft' });
  await expect(sec).toContainText(/Same (ICAO address|registration)/);
  await sec.locator('[data-act=dupMerge]').click();
  const left = await page.evaluate(() => DB.entries.filter(e => e.caseId === 'rx' && e.type === 'aircraft').map(e => ({ reg: e.fields.registration || '', hex: e.fields.icao24 || '', op: e.fields.operator || '' })));
  expect(left).toEqual(expect.arrayContaining([{ reg: 'N628TS', hex: 'A835AF', op: 'Falcon Landing LLC' }, { reg: 'G-EUPT', hex: '', op: '' }]));
  expect(left.length).toBe(2);
  noErrors(errors);
});

test('one name on several accounts and look-alike domains are offered as links with the reason; ordinary neighbours are not', async ({ page }) => {
  const errors = await open(page, '#/home');
  const ids = await page.evaluate(seed);
  const R = await page.evaluate(() => dupRelated('rx').map(g => ({ rel: g.rel, label: g.label, why: g.why, ids: g.G.map(e => e.id).sort(), pairs: g.P.map(([x, y]) => [x.id, y.id]) })));
  const names = R.filter(g => g.rel === 'name'), looks = R.filter(g => g.rel === 'look');
  expect(names.length).toBe(1);
  expect(names[0].ids).toEqual([ids.h, ids.x, ids.mail, ids.mail2].sort());
  expect(names[0].why).toBe('The name “nightowlops” on 4 accounts');
  expect(names[0].pairs.every(([, to]) => to === ids.h)).toBe(true);   // linked to the handle
  // one family: every imitation linked to the real name, each with its own reason
  const R2 = await page.evaluate(() => dupRelated('rx').filter(g => g.rel === 'look').map(g => ({ ids: g.G.map(e => e.id).sort(), pairs: g.P.map(([x, y]) => [x.id, y.id]).sort(), whys: g.whys, why: g.why })));
  expect(R2.length).toBe(1);
  expect(R2[0].ids).toEqual([ids.real, ids.digit, ids.cyr, ids.words, ids.tld].sort());
  expect(R2[0].pairs).toEqual([ids.digit, ids.cyr, ids.words, ids.tld].map(i => [i, ids.real]).sort());
  expect(R2[0].whys).toEqual({ [ids.digit]: 'Look-alike characters', [ids.cyr]: 'Look-alike characters', [ids.words]: 'Its name with words added', [ids.tld]: 'Same name, other ending' });
  expect(R2[0].why).toMatch(/^4 look-alikes of paypal\.com: /);
  expect(R.some(g => g.ids.includes(ids.sub) && g.ids.includes(ids.real))).toBe(false);          // www. is the same site (a duplicate, not a look-alike)
  expect(R.some(g => [ids.a, ids.b, ids.c, ids.info1, ids.info2, ids.short1, ids.short2].some(i => g.ids.includes(i)))).toBe(false);

  // from the vault: the button counts them, linking adds labelled links that the graph shows, and they are not offered again
  await page.evaluate(() => go(caseHash('rx', 'vault')));
  await expect(page.locator('[data-act=dupOpen]')).toContainText('to review');
  await page.click('[data-act=dupOpen]');
  await page.click('[data-act=dupTab][data-v=rel]');
  await page.locator('.dp-g', { hasText: 'One name, several accounts' }).locator('[data-act=dupLink]').click();
  await expect(page.locator('.toast')).toContainText('3 links added: “same name as”');
  // "not related" on a family is remembered
  await page.locator('.dp-g', { hasText: 'Look-alike domain' }).locator('[data-act=dupNot]').click();
  expect(await page.evaluate(() => dupRelated('rx').length)).toBe(0);
  await page.evaluate(() => { DB.prefs.notDup = []; dupPaint(); }); await page.click('[data-act=dupTab][data-v=rel]');
  await page.locator('.dp-g', { hasText: 'Look-alike domain' }).locator('[data-act=dupLink]').click();
  await expect(page.locator('.toast')).toContainText('4 links added: “look-alike of”');
  const L = await page.evaluate(id => DB.links.filter(l => l.caseId === 'rx').map(l => ({ a: l.a, b: l.b, label: l.label, why: l.why })), ids.cyr);
  expect(L).toEqual(expect.arrayContaining([{ a: ids.cyr, b: ids.real, label: 'look-alike of', why: 'Look-alike characters' }, { a: ids.mail2, b: ids.h, label: 'same name as', why: 'The name “nightowlops” on 4 accounts' }]));
  expect(await page.evaluate(() => dupRelated('rx').some(g => g.rel === 'name'))).toBe(false);
  expect(await page.evaluate(() => dupRelated('rx').length)).toBe(0);
  noErrors(errors);
});

test('a big vault is reviewed quickly', async ({ page }) => {
  const errors = await open(page, '#/home');
  const ms = await page.evaluate(() => {
    DB.cases.push(Object.assign({}, DB.cases[0], { id: 'big', name: 'Big' }));
    for (let i = 0; i < 3000; i++) DB.entries.push({ id: 'd' + i, caseId: 'big', type: i % 3 ? 'domain' : 'email', fields: i % 3 ? { domain: 'site' + (i * 7919 % 100000) + 'x' + (i % 97) + '.example' } : { email: 'user' + i + '@mail' + (i % 50) + '.example' }, priority: 'medium', starred: false, tags: [], notes: '', src: '', created: 1, pos: null });
    mutate('big'); const t = performance.now(); dupRelated('big'); dupGroups('big'); return performance.now() - t;
  });
  expect(ms).toBeLessThan(1500);
  noErrors(errors);
});
