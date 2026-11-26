// Panels that open over a page: as tall as what is in them (no empty panel running to the bottom of the window), the
// page behind blurred so they read on their own, and strips that scroll sideways show no scrollbar.
const { test, expect } = require('@playwright/test');
const { open, noErrors } = require('./helpers');

test('Threat Intel: a story panel is as tall as the story, the page behind it blurs, and a click there closes it', async ({ page }) => {
  await page.setViewportSize({ width: 1450, height: 1100 });
  const errors = await open(page, '#/feeds');
  await page.locator('.tio-tbl tbody tr').first().click();
  await expect(page.locator('#insp.story')).toBeVisible();
  const r = await page.evaluate(() => { const i = $('insp').getBoundingClientRect(), f = document.querySelector('#insp .st-foot').getBoundingClientRect(), s = $('stScrim');
    return { endsEarly: i.bottom < innerHeight - 60, footAtEnd: Math.abs(i.bottom - f.bottom) < 4, blur: s && getComputedStyle(s).backdropFilter }; });
  expect(r.endsEarly).toBe(true); expect(r.footAtEnd).toBe(true); expect(r.blur).toMatch(/blur/);
  await page.mouse.click(200, 600);
  await expect(page.locator('#stScrim')).toHaveCount(0); expect(await page.evaluate(() => UI.inspOpen)).toBe(false);
  // a short window: the panel stops at its edge, the story scrolls inside, the buttons stay in view
  await page.setViewportSize({ width: 1450, height: 560 }); await page.locator('.tio-tbl tbody tr').first().click();
  const s = await page.evaluate(() => { const b = document.querySelector('#insp .st-b'), f = document.querySelector('#insp .st-foot').getBoundingClientRect(); return { scrolls: b.scrollHeight > b.clientHeight, footIn: f.bottom <= innerHeight }; });
  expect(s).toEqual({ scrolls: true, footIn: true });
  noErrors(errors);
});

test('Query library: the query panel is as tall as its content and the page behind it blurs', async ({ page }) => {
  await page.setViewportSize({ width: 1450, height: 1100 });
  const errors = await open(page, '#/queries');
  await page.locator('#main tr[data-id]').first().click();
  await expect(page.locator('.drw')).toBeVisible();
  const r = await page.evaluate(() => { const d = document.querySelector('.drw').getBoundingClientRect(), b = document.querySelector('.drw-b'); return { endsEarly: d.bottom < innerHeight - 60, noInnerScroll: b.scrollHeight <= b.clientHeight + 1, blur: getComputedStyle(document.querySelector('.drw-scrim')).backdropFilter }; });
  expect(r.endsEarly).toBe(true); expect(r.noInnerScroll).toBe(true); expect(r.blur).toMatch(/blur/);
  noErrors(errors);
});

test('the case tabs show no scrollbar at Windows display scaling', async ({ browser }) => {
  const ctx = await browser.newContext({ viewport: { width: 1463, height: 760 }, deviceScaleFactor: 1.25 }); const page = await ctx.newPage();
  const errors = await open(page, '#/case/c-lantern/timeline');
  const t = await page.evaluate(() => { const n = document.querySelector('#main nav.tabs'), cs = getComputedStyle(n); return { bar: cs.scrollbarWidth, y: cs.overflowY }; });
  expect(t).toEqual({ bar: 'none', y: 'hidden' });
  await ctx.close(); noErrors(errors);
});
