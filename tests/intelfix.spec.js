// Threat Intel fixes: the story panel closes when you change tab (no stale panel, the next click opens the new story at
// once); the Sources dialog keeps its tabs and Done in view with one scroll; Investigate on the indicator already shown
// asks again, Clear empties it; sources that are off are listed compactly, and name lists keep whole names.
const { test, expect } = require('@playwright/test');
const { open, noErrors } = require('./helpers');
const JSONH = { 'access-control-allow-origin': '*', 'content-type': 'application/json' };

test('story panel follows the tab: closed on switch, one click opens a story on Overview', async ({ page }) => {
  await page.setViewportSize({ width: 1600, height: 1000 });
  const errors = await open(page, '#/feeds');
  await page.click('[data-act=itab][data-v=feed]');
  await page.locator('.ti-open').first().click(); await expect(page.locator('#insp.story')).toBeVisible();
  // an open story blurs the page behind it: Esc closes it, and so does a click outside it
  await page.keyboard.press('Escape'); await expect(page.locator('#insp')).toHaveClass(/closed/); await expect(page.locator('#stScrim')).toHaveCount(0);
  await page.locator('.ti-open').first().click(); await expect(page.locator('#insp.story')).toBeVisible();
  await page.mouse.click(300, 700); await expect(page.locator('#insp')).toHaveClass(/closed/);
  await page.click('[data-act=itab][data-v=over]'); await expect(page.locator('#insp')).toHaveClass(/closed/);
  const rows = page.locator('.tio-tbl tbody tr');
  await rows.nth(0).click(); await expect(page.locator('#insp.story')).toBeVisible();
  const t1 = await page.locator('#insp h2').first().textContent();
  await page.click('#insp [data-act=stNav][data-v="1"]'); await expect(page.locator('#insp h2').first()).not.toHaveText(t1);   // the next story, from the panel
  noErrors(errors);
});

test('sources dialog: one scroll, the tabs and Done always in view', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 800 });
  const errors = await open(page, '#/feeds');
  await page.click('[data-act=feedSources]');
  await page.click('[data-act=srcTab][data-v=look]');
  const box = await page.locator('#dlg').boundingBox();
  expect(box.y + box.height).toBeLessThanOrEqual(800);
  await expect(page.locator('#dlg footer [data-act=dclose]')).toBeInViewport();
  expect(await page.evaluate(() => { const s = document.querySelector('#dlg .srcs'); return s ? getComputedStyle(s).overflowY : 'none'; })).not.toBe('auto');
  const inner = page.locator('#dlg > .in');
  expect(await inner.evaluate(el => el.scrollHeight > el.clientHeight)).toBe(true);
  await inner.evaluate(el => el.scrollTop = el.scrollHeight);
  await expect(page.locator('#dlg .ti-dtabs')).toBeInViewport(); await expect(page.locator('#dlg footer [data-act=dclose]')).toBeInViewport();
  noErrors(errors);
});

test('Investigate again re-asks, Clear empties, off sources are a compact list and names stay whole', async ({ page }) => {
  await page.route(/^https:\/\/(?!dns\.google)[^/]+\//, r => r.abort());
  let asked = 0;
  await page.route('https://dns.google/**', r => { asked++; const t = new URL(r.request().url()).searchParams.get('type');
    const A = t === 'A' ? [{ type: 1, data: '198.187.29.150' }] : t === 'NS' ? [{ type: 2, data: 'dns2.namecheaphosting.com.' }, { type: 2, data: 'dns1.namecheaphosting.com.' }] : [];
    r.fulfill({ headers: JSONH, body: JSON.stringify({ Status: 0, Answer: A }) }); });
  await page.setViewportSize({ width: 1708, height: 1100 });
  const errors = await open(page, '#/feeds');
  await page.evaluate(() => { lkSettings().on = { dns: true }; UI.itab = 'look'; renderMain(); });
  await page.fill('#lkQ', 'goo9le.com'); await page.click('form[data-form=ctiLook] button[type=submit]');
  await expect(page.locator('.lk-card:has-text("DNS (Google DoH)")')).toContainText('198.187.29.150');
  const n1 = asked; expect(n1).toBeGreaterThan(0);
  await page.click('form[data-form=ctiLook] button[type=submit]');                     // the same indicator: asked again, not just shown from memory
  await expect.poll(() => asked).toBeGreaterThan(n1);
  const ns = page.locator('.lk-card:has-text("DNS (Google DoH)") .lk-li');
  await expect(ns).toHaveCount(2); await expect(ns.first()).toHaveText('dns2.namecheaphosting.com');
  await expect(page.locator('.lk-off')).toContainText('Not switched on'); await expect(page.locator('.lk-off li').first()).toBeVisible();
  expect(await page.locator('.lk-card').count()).toBe(1);                                  // only the source that is on gets a card
  await page.click('[data-act=lookClear]');
  await expect(page.locator('.lk-head')).toHaveCount(0); await expect(page.locator('#lkQ')).toHaveValue('');
  noErrors(errors);
});
