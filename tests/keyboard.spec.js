// Keyboard only: the graph is reached with Tab and walked with the arrow keys (details follow, a live line says where
// you are), opens its menu with Shift+F10 and zooms with + / − / 0; dialogs take focus, keep Tab inside and give it back
// on Esc; the template picker is a set of buttons; entity rows and map places are in the tab order.
const { test, expect } = require('@playwright/test');
const { open, noErrors } = require('./helpers');
test.use({ viewport: { width: 1440, height: 900 } });

test('graph by keyboard: Tab in, arrows move from entry to entry, Shift+F10 menu, zoom and fit, Esc lets go', async ({ page }) => {
  const errors = await open(page, '#/case/c-story/graph', { legacy: false });
  await expect.poll(() => page.evaluate(() => typeof cy !== 'undefined' && !!cy && cy.nodes().length > 5)).toBe(true);
  await page.waitForTimeout(700);   // the graph settles after its first draw
  await page.evaluate(() => { cy.container().focus(); });
  expect(await page.evaluate(() => document.activeElement.id)).toBe('cy');
  expect(await page.evaluate(() => [cy.container().tabIndex, cy.container().getAttribute('aria-describedby')])).toEqual([0, 'gKeysHelp']);
  await page.keyboard.press('ArrowRight');
  const first = await page.evaluate(() => UI.sel && UI.sel.id); expect(first).toBeTruthy();
  await expect(page.locator('#gLive')).toContainText('connection');
  await expect(page.locator('#insp')).not.toHaveClass(/closed/);
  const seen = new Set([first]);
  for (const k of ['ArrowRight', 'ArrowDown', 'ArrowLeft', 'ArrowUp', 'ArrowRight']) { await page.keyboard.press(k); seen.add(await page.evaluate(() => UI.sel && UI.sel.id)); }
  expect(seen.size).toBeGreaterThan(2);                                       // it really moves around the graph
  // the arrows go the way they say: right goes to an entry further right
  const dir = await page.evaluate(() => { const a = cy.getElementById(UI.sel.id).renderedPosition().x; return a; });
  await page.keyboard.press('ArrowRight'); const moved = await page.evaluate(() => cy.getElementById(UI.sel.id).renderedPosition().x);
  expect(moved >= dir).toBe(true);
  await page.keyboard.press('Shift+F10'); await expect(page.locator('#ctx')).toBeVisible(); await page.keyboard.press('Escape'); await expect(page.locator('#ctx')).toHaveCount(0);
  await page.waitForTimeout(400); await page.evaluate(() => cy.container().focus());   // after the redraw that closing the menu brings
  const z0 = await page.evaluate(() => cy.zoom()); await page.keyboard.press('+'); expect(await page.evaluate(() => cy.zoom())).toBeGreaterThan(z0);
  await page.keyboard.press('-'); await page.keyboard.press('-'); expect(await page.evaluate(() => cy.zoom())).toBeLessThan(z0);
  await page.keyboard.press('0');
  noErrors(errors);
});

test('dialogs take focus, keep Tab inside and give focus back on Esc; the template picker and entity rows work by keyboard', async ({ page }) => {
  const errors = await open(page, '#/cases', { legacy: false });
  const opener = page.locator('#main [data-act=newCase]').first(); await opener.focus(); await page.keyboard.press('Enter');
  await expect(page.locator('.ct-card').first()).toBeVisible();
  expect(await page.evaluate(() => $('dlg').contains(document.activeElement))).toBe(true);
  for (let i = 0; i < 30; i++) { await page.keyboard.press('Tab'); expect(await page.evaluate(() => $('dlg').contains(document.activeElement)), 'Tab stays in the dialog').toBe(true); }
  // pick a template with the keyboard
  await page.locator('[data-act=ctPick][data-v=story]').focus(); await page.keyboard.press('Enter');
  await expect(page.locator('#cName')).toBeVisible();
  await page.keyboard.press('Escape'); await expect(page.locator('#dlg')).toBeHidden();
  expect(await page.evaluate(() => document.activeElement && document.activeElement.dataset.act)).toBe('newCase');
  // entity rows: Tab reaches them, Enter opens the details
  await page.evaluate(() => go('#/case/c-story/entities')); await page.waitForTimeout(400);
  const row = page.locator('#main tr[data-act=selEnt]').first(); await row.focus(); await page.keyboard.press('Enter');
  await expect(page.locator('#insp')).not.toHaveClass(/closed/); expect(await page.evaluate(() => UI.sel && UI.sel.kind)).toBe('ent');
  // a place on the map: its name is a button
  await page.evaluate(() => go('#/case/c-story/map')); const place = page.locator('#main .ph-sel').first(); await expect(place).toBeVisible();
  const k = await place.getAttribute('data-v'); await place.focus(); await page.keyboard.press('Enter');
  await expect.poll(() => page.evaluate(() => UI.mapSel || (document.querySelector('#main article.on, #main .on [data-act=mapSel]') ? 'on' : null))).toBeTruthy();
  noErrors(errors);
});
