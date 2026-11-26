// The one-file copy (dist/osintrix-offline.html): its big data files and libraries are packed and run only when
// something needs them. It must open without errors under its strict script policy, and every packed file must
// unpack and work: the graph library, the MAC vendor list, the world map, phone numbers, the rule and KEV packs,
// and the SQLite engine.
const { test, expect } = require('@playwright/test');
const path = require('path');
const fs = require('fs');
const ONE = 'file://' + path.resolve(__dirname, '..', 'dist', 'osintrix-offline.html');

test('the one-file copy opens, and each packed file unpacks and works when needed', async ({ page }) => {
  const errors = [];
  page.on('pageerror', e => errors.push('pageerror: ' + e.message));
  page.on('console', m => { if (m.type() === 'error' && !/localStorage.*sandboxed/.test(m.text())) errors.push('console: ' + m.text()); });
  await page.addInitScript(() => { try { localStorage.setItem('osintrix:welcomed', '1'); } catch (e) {} });
  await page.goto(ONE + '#/home');
  await expect.poll(() => page.evaluate(() => typeof DB !== 'undefined' && !!DB && !!document.querySelector('#sidenav .nv')), { timeout: 20000 }).toBe(true);

  // nothing packed has run before the app asked for it; the background ones arrive after the first screen
  const html = fs.readFileSync(path.resolve(__dirname, '..', 'dist', 'osintrix-offline.html'), 'utf8');
  expect((html.match(/data-gz>/g) || []).length).toBeGreaterThanOrEqual(15);
  await expect.poll(() => page.evaluate(() => lazyPending()), { timeout: 20000 }).toBe(0);
  const r = await page.evaluate(async () => {
    const out = {};
    out.cy = typeof cytoscape === 'function';
    out.rules = typeof RULE_PACK !== 'undefined'; out.kev = typeof KEV_SNAPSHOT !== 'undefined' && KEV_SNAPSHOT.rows.length > 1000;
    out.oui = (await macVendor('00:1A:11:00:00:00')).vendor;                     // Google's block
    out.world = !!(await worldLoad());
    await lazyNeed('phone'); out.phone = typeof libphonenumber !== 'undefined' && libphonenumber.parsePhoneNumberFromString('+4791234567').country;
    out.qr = await lazyNeed('qr') && typeof jsQR === 'function';
    const SQL = await sqlEngine(); const db = new SQL.Database(); out.sql = db.exec('select 6*7')[0].values[0][0];
    return out;
  });
  expect(r).toEqual({ cy: true, rules: true, kev: true, oui: expect.stringMatching(/Google/i), world: true, phone: 'NO', qr: true, sql: 42 });

  // the graph draws
  await page.evaluate(() => go(caseHash(DB.cases[0].id, 'graph')));
  await expect.poll(() => page.evaluate(() => typeof cy !== 'undefined' && cy && cy.nodes().length)).toBeGreaterThan(0);
  expect(errors).toEqual([]);
});
