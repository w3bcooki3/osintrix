// Notes: a date, a time and a reminder can be set when a note is written (not only by editing it later); the card shows
// them; the reminder fires once at the time (in-app, and a system notification when allowed), and a missed one fires
// when the app is opened again; editing the time re-arms it.
const { test, expect } = require('@playwright/test');
const { open, noErrors } = require('./helpers');

test('a note with a date, time and reminder from the start; the reminder fires once, and again after re-timing', async ({ page }) => {
  await page.clock.install({ time: new Date('2026-11-24T09:00:00') });
  const errors = await open(page, '#/notes');
  await page.fill('.nquick [data-nq=title]', 'Call the registrar');
  await page.fill('.nquick textarea', 'Ask for the WHOIS history of update-lamp.test');
  await page.fill('.nquick [data-nq=due]', '2026-11-24'); await page.fill('.nquick [data-nq=time]', '09:30');
  await expect(page.locator('.nquick [data-nq=remind]')).toBeChecked();
  await page.click('.nquick button[type=submit]');
  const n = await page.evaluate(() => { const x = DB.notes.find(z => z.title === 'Call the registrar'); return { due: x.due, t: x.dueTime, r: x.remind }; });
  expect(n).toEqual({ due: '2026-11-24', t: '09:30', r: true });
  const card = page.locator('.note-card', { hasText: 'Call the registrar' });
  await expect(card.locator('.ndue')).toHaveText('Today 09:30');
  await page.clock.fastForward('31:00');
  await expect(page.locator('.toast').last()).toContainText('Reminder: Call the registrar');
  expect(await page.evaluate(() => !!DB.notes.find(z => z.title === 'Call the registrar').reminded)).toBe(true);
  await expect(card.locator('.ndue')).toHaveClass(/late/);
  // re-time it in the editor: armed again, fires again
  await card.locator('[data-act=nEdit]').click();
  await expect(page.locator('#nTime')).toHaveValue('09:30'); await expect(page.locator('#nRemind')).toBeChecked();
  await page.fill('#nTime', '10:15'); await page.click('#dlg button[type=submit]');
  expect(await page.evaluate(() => DB.notes.find(z => z.title === 'Call the registrar').reminded)).toBe(0);
  await page.clock.fastForward('45:00');
  await expect(page.locator('.toast').last()).toContainText('Reminder: Call the registrar');
  // a time without a date is refused
  await page.fill('.nquick textarea', 'no date'); await page.fill('.nquick [data-nq=time]', '11:00'); await page.click('.nquick button[type=submit]');
  await expect(page.locator('.field-err, [aria-invalid=true]').first()).toBeVisible();
  noErrors(errors);
});

test('a reminder that came due while the app was closed fires when it opens, once', async ({ page }) => {
  await page.clock.install({ time: new Date('2026-11-24T12:00:00') });
  await page.addInitScript(() => { window.__seedNote = true; });
  const errors = await open(page, '#/notes');
  await page.evaluate(() => { DB.notes.unshift({ id: 'nr1', caseId: null, title: 'Check the drop site', color: 'yellow', pinned: false, text: 'is it still up?', due: '2026-11-24', dueTime: '08:00', remind: true, reminded: 0, created: Date.now(), updated: Date.now() }); save(); });
  await page.clock.fastForward('00:25');
  await expect(page.locator('.toast').last()).toContainText('Missed reminder: Check the drop site — was due Today 08:00');
  const r1 = await page.evaluate(() => DB.notes.find(n => n.id === 'nr1').reminded);
  await page.clock.fastForward('01:00');
  expect(await page.evaluate(() => DB.notes.find(n => n.id === 'nr1').reminded)).toBe(r1);
  noErrors(errors);
});
