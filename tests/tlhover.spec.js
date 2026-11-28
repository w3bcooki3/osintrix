// Long timeline records open when chosen or reached with the keyboard, never under a passing pointer (1.92)
const { test, expect } = require('@playwright/test');
const { open, noErrors } = require('./helpers');

test('a long timeline record does not grow under the pointer; choosing it or tabbing to it opens it', async ({ page }) => {
  const errors = await open(page, '#/case/c-lantern/timeline');
  const id = await page.evaluate(() => { const body = Array.from({ length: 14 }, (_, i) => 'line ' + i + ' of a long log record, src=203.0.113.' + i).join('\n');
    DB.records.push({ id: 'r-long', caseId: 'c-lantern', type: 'evidence', title: 'A long record', body, tsRaw: '2026-09-14T09:00:00Z', tsZone: 'explicit', ts: Date.parse('2026-09-14T09:00:00Z'), source: 'test', host: '', tags: [], ents: [], answer: '', addedBy: 'You', addedAt: Date.now(), hash: '' });
    mutate('long'); UI.q = 'long log record'; UI.ast = E.parseQuery(UI.q); renderMain(); return 'r-long'; });
  expect(id).toBeTruthy();
  const ev = page.locator(`.ev[data-id="${id}"]`); await ev.scrollIntoViewIfNeeded();
  const raw = ev.locator('.raw'), h0 = (await raw.boundingBox()).height;
  await ev.hover(); await page.waitForTimeout(200);
  expect((await raw.boundingBox()).height).toBe(h0);
  await ev.focus(); await page.keyboard.press('Shift+Tab'); await page.keyboard.press('Tab');
  await expect.poll(async () => (await raw.boundingBox()).height).toBeGreaterThan(h0);
  noErrors(errors);
});
