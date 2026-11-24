// Tradecraft: the field guide loads offline, the readiness check is kept, search narrows it, every "open it here" link
// goes to a real place, and the guide's playbooks exist and can be run.
const { test, expect } = require('@playwright/test');
const { open, noErrors } = require('./helpers');

test('tradecraft: readiness check kept across a reload, search, links into the app, and its playbooks', async ({ page }) => {
  const errors = await open(page, '#/tradecraft');
  await expect(page.locator('.tc-hd h1')).toHaveText('Tradecraft');
  await expect(page.locator('.tc-ch')).toHaveCount(10);
  await expect(page.locator('.tc-mx tbody tr')).toHaveCount(14);
  // the check: two ticked, kept after a reload, cleared for a new session
  await page.locator('input[data-tc=vm]').check(); await page.locator('input[data-tc=webrtc]').check();
  await expect(page.locator('.tc-rc')).toHaveText('2 of 8');
  await expect.poll(() => page.evaluate(() => { flush(); return isDirty(); }), { timeout: 15000 }).toBe(false); await page.reload(); await expect(page.locator('.tc-rc')).toHaveText('2 of 8'); await expect(page.locator('input[data-tc=vm]')).toBeChecked();
  await page.locator('[data-act=tcReset]').click(); await expect(page.locator('.tc-rc')).toHaveText('0 of 8');
  // search narrows to the matching points and marks the words
  await page.fill('#tcQ', 'LinkedIn'); await expect(page.locator('.tc-part li')).toHaveCount(1); await expect(page.locator('.tc mark').first()).toHaveText('LinkedIn');
  await page.fill('#tcQ', 'JARM'); await expect(page.locator('.tc-mx tbody tr')).toHaveCount(1);
  await page.fill('#tcQ', ''); await expect(page.locator('.tc-mx tbody tr')).toHaveCount(14);
  // every link into the app names a place that exists
  const gos = await page.evaluate(() => [...new Set([...document.querySelectorAll('[data-act=tcGo]')].map(b => b.dataset.v))]);
  expect(gos.length).toBeGreaterThan(6);
  const known = await page.evaluate(() => Object.keys(TC_GO));
  for (const v of gos) { expect(known).toContain(v);
    if (v.startsWith('case:')) expect(await page.evaluate(t => CASE_TABS.some(x => x[0] === t), v.slice(5))).toBe(true); else expect(await page.evaluate(a => AREAS.includes(a), v)).toBe(true); }
  await page.locator('[data-act=tcGo][data-v="case:infra"]').first().click(); await expect(page).toHaveURL(/#\/case\/[\w-]+\/infra/);
  // the guide's playbooks open and can be run on a case
  await page.evaluate(() => go('#/tradecraft')); await page.locator('[data-act=tcPb][data-v=pb-apt-seed]').click();
  await expect(page.locator('.pbx-h h1')).toHaveText('Actor investigation from one indicator');
  for (const id of ['pb-opsec-env', 'pb-persona', 'pb-operator']) expect(await page.evaluate(i => DB.playbooks.some(p => p.id === i), id)).toBe(true);
  noErrors(errors);
});

test('what this browser tells every site: read locally, a language and time zone that do not fit are called out, and nothing is sent', async ({ browser }) => {
  const ctx = await browser.newContext({ timezoneId: 'Europe/London', locale: 'ru-RU' }), page = await ctx.newPage();
  const net = []; page.on('request', r => { if (!/^(file|data|blob):/.test(r.url())) net.push(r.url()); });
  const errors = await open(page, '#/tradecraft');
  const X = page.locator('#opX');
  await expect(X).toContainText('Europe/London'); await expect(X).toContainText('ru-RU');
  await expect(X).toContainText('Language ru-RU with time zone Europe/London');                 // the guide's own example of a fingerprint
  await expect(page.locator('.tc-ready')).toContainText('This browser: Europe/London, ru-RU');
  await expect(X.locator('.op-f')).toContainText(/WebRTC (is on|gives away)/);
  noErrors(errors); expect(net).toEqual([]); await ctx.close();
});

test('research personas: added, used across cases with a warning, burned with a record, kept after a reload; stored junk is cleaned', async ({ page }) => {
  const errors = await open(page, '#/tradecraft');
  await page.locator('#opP [data-act=opNew]').click(); await page.fill('#opN', 'marta.k'); await page.fill('#opPl', 'Instagram, Telegram'); await page.fill('#opEg', 'NL residential');
  await page.locator('[data-act=opNewSave]').click();
  await expect(page.locator('.op-pc')).toContainText('Instagram, Telegram · exits NL residential');
  for (const c of ['c-lantern', 'c-portal', 'c-lab']) { await page.locator('#opP header [data-act=opLog]').click(); await page.selectOption('#opLc', c); await page.fill('#opLpl', 'Instagram'); await page.fill('#opLw', 'Viewed the subject profile'); await page.locator('[data-act=opLogSave]').click(); }
  await expect(page.locator('.op-pc')).toContainText('3 uses · 3 cases'); await expect(page.locator('.op-pc')).toContainText('Used on 3 cases');
  await expect(page.locator('.op-log li')).toHaveCount(3);
  await expect.poll(() => page.evaluate(() => { flush(); return isDirty(); }), { timeout: 15000 }).toBe(false); await page.reload(); await expect(page.locator('.op-pc')).toContainText('3 uses · 3 cases');
  await page.locator('.op-pc [data-act=opBurn]').click(); await page.fill('#opBw', 'Subject blocked it'); await page.locator('[data-act=opBurnOk]').click();
  await expect(page.locator('.toast').last()).toContainText('touched 3 cases'); await expect(page.locator('.op-pc')).toContainText('Burned'); await expect(page.locator('.op-pc')).toContainText('Subject blocked it');
  await expect(page.locator('#opP header [data-act=opLog]')).toHaveCount(0);                        // nothing left to log with
  const c = await page.evaluate(() => pnClean({ list: [{ id: 'ok', name: 'x' }, { id: '<bad>', name: 'y' }, 7], log: [{ id: 'l1', p: 'ok', what: 'w'.repeat(900), at: 'x' }, { id: 'l2' }] }));
  expect([c.list.map(x => x.id), c.log.length, c.log[0].what.length, c.log[0].at]).toEqual([['ok'], 1, 600, 0]);
  noErrors(errors);
});
