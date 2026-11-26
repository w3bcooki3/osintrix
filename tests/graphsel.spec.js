// Many nodes at once on the graph (1.89), with the real mouse and keyboard: Shift/Ctrl+click adds nodes, Shift+drag (or Select
// mode and a plain drag) draws a box, dragging one picked node moves them all, the bar and the right-click menu act on all of
// them with one undo, Space/Ctrl+A/Esc do it from the keyboard, and a plain click goes back to one.
const { test, expect } = require('@playwright/test');
const { open, noErrors } = require('./helpers');

const at = (page, id) => page.evaluate(id => { const n = cy.getElementById(id), r = $('cy').getBoundingClientRect(), p = n.renderedPosition(); return { x: r.left + p.x, y: r.top + p.y }; }, id);
async function ready(page) {
  await page.setViewportSize({ width: 1500, height: 950 });
  const errors = await open(page, '#/case/c-lantern/graph', { legacy: false });
  await expect.poll(() => page.evaluate(() => typeof cy !== 'undefined' && !!cy && cy.nodes().length > 5)).toBe(true);
  await page.evaluate(() => { cy.zoom(1); cy.center(cy.getElementById('v-ip1')); }); await page.waitForTimeout(250);
  return errors;
}

test('Shift+click picks several, the bar marks them malicious in one go, and one undo puts it back', async ({ page }) => {
  const errors = await ready(page);
  for (const id of ['v-ip1', 'v-ip2', 'v-dom2']) { const p = await at(page, id); await page.keyboard.down('Shift'); await page.mouse.click(p.x, p.y); await page.keyboard.up('Shift'); }
  await expect(page.locator('.gbulk')).toContainText('3 selected');
  expect(await page.evaluate(() => cy.nodes(':selected').map(n => n.id()).sort())).toEqual(['v-dom2', 'v-ip1', 'v-ip2']);
  const before = await page.evaluate(() => ['v-ip1', 'v-ip2', 'v-dom2'].map(id => entryVerdict(entryById(id))));
  await page.click('.gbulk [data-act=vbVerdict]'); await page.click('#ctx button:has-text("Benign")');
  expect(await page.evaluate(() => ['v-ip1', 'v-ip2', 'v-dom2'].map(id => entryVerdict(entryById(id))))).toEqual(['benign', 'benign', 'benign']);
  await page.locator('.toast').last().getByRole('button', { name: 'Undo' }).click();
  expect(await page.evaluate(() => ['v-ip1', 'v-ip2', 'v-dom2'].map(id => entryVerdict(entryById(id))))).toEqual(before);
  // Ctrl+click takes one off again; a plain click on another node goes back to a single selection
  const p = await at(page, 'v-ip2'); await page.keyboard.down('Control'); await page.mouse.click(p.x, p.y); await page.keyboard.up('Control');
  await expect(page.locator('.gbulk')).toContainText('2 selected');
  const q = await at(page, 'v-url'); await page.mouse.click(q.x, q.y);
  await expect(page.locator('.gbulk')).toHaveCount(0); expect(await page.evaluate(() => UI.sel && UI.sel.id)).toBe('v-url');
  noErrors(errors);
});

test('Shift+drag draws a box; dragging one picked node moves them all; delete takes them with their links and undo brings all back', async ({ page }) => {
  const errors = await ready(page);
  const ids = ['v-ip1', 'v-ip2', 'v-dom2'], P = await Promise.all(ids.map(id => at(page, id)));
  const x1 = Math.min(...P.map(p => p.x)) - 40, y1 = Math.min(...P.map(p => p.y)) - 40, x2 = Math.max(...P.map(p => p.x)) + 40, y2 = Math.max(...P.map(p => p.y)) + 40;
  const inBox = await page.evaluate(([x1, y1, x2, y2]) => { const r = $('cy').getBoundingClientRect(); return cy.nodes().filter(n => { const p = n.renderedPosition(); return p.x + r.left > x1 && p.x + r.left < x2 && p.y + r.top > y1 && p.y + r.top < y2; }).map(n => n.id()).sort(); }, [x1, y1, x2, y2]);
  await page.keyboard.down('Shift'); await page.mouse.move(x1, y1); await page.mouse.down(); await page.mouse.move((x1 + x2) / 2, (y1 + y2) / 2, { steps: 5 }); await page.mouse.move(x2, y2, { steps: 5 }); await page.mouse.up(); await page.keyboard.up('Shift');
  await expect.poll(() => page.evaluate(() => UI.vPick.size)).toBe(inBox.length); await expect(page.locator('.gbulk')).toContainText(inBox.length + ' selected');
  expect(await page.evaluate(() => [...UI.vPick].sort())).toEqual(inBox);
  // drag one: all move by the same amount, and the new places are kept
  const pos0 = await page.evaluate(ids => ids.map(id => ({ ...cy.getElementById(id).position() })), inBox);
  const g = await at(page, 'v-ip1'); await page.mouse.move(g.x, g.y); await page.mouse.down(); await page.mouse.move(g.x + 60, g.y + 40, { steps: 8 }); await page.mouse.up();
  const moved = await page.evaluate(([ids, pos0]) => ids.map((id, i) => { const p = cy.getElementById(id).position(), e = entryById(id); return [Math.round(p.x - pos0[i].x), Math.round(p.y - pos0[i].y), Math.round(e.pos.x - p.x)]; }), [inBox, pos0]);
  for (const [dx, dy, saved] of moved) { expect(dx).toBeGreaterThan(30); expect(dy).toBeGreaterThan(15); expect(saved).toBe(0); }
  expect(new Set(moved.map(m => m[0] + ',' + m[1])).size).toBe(1);
  // delete them all, then undo
  const links = await page.evaluate(ids => DB.links.filter(l => ids.includes(l.a) || ids.includes(l.b)).length, inBox);
  await page.click('.gbulk [data-act=vbDel]'); await page.locator('#dlg .btn.danger, #dlg button:has-text("Delete")').last().click();
  await expect.poll(() => page.evaluate(ids => [ids.filter(id => entryById(id)).length, cy.nodes().filter(n => ids.includes(n.id())).length], inBox)).toEqual([0, 0]);
  await page.locator('.toast').last().getByRole('button', { name: 'Undo' }).click();
  expect(await page.evaluate(([ids, n]) => [ids.every(id => entryById(id)), DB.links.filter(l => ids.includes(l.a) || ids.includes(l.b)).length === n], [inBox, links])).toEqual([true, true]);
  noErrors(errors);
});

test('Select mode: a plain drag draws the box instead of panning; right-click on a picked node acts on all of them', async ({ page }) => {
  const errors = await ready(page);
  await page.click('[data-act=gSelMode]'); await expect(page.locator('.gbulk-hint')).toBeVisible();
  const pan0 = await page.evaluate(() => ({ ...cy.pan() }));
  const a = await at(page, 'v-ip1'), b = await at(page, 'v-ip2');
  const x1 = Math.min(a.x, b.x) - 30, y1 = Math.min(a.y, b.y) - 30, x2 = Math.max(a.x, b.x) + 30, y2 = Math.max(a.y, b.y) + 30;
  await page.mouse.move(x1, y1); await page.mouse.down(); await page.mouse.move(x2, y2, { steps: 8 }); await page.mouse.up();
  expect(await page.evaluate(() => cy.pan())).toEqual(pan0);                                    // no pan
  await expect.poll(() => page.evaluate(() => UI.vPick.size)).toBeGreaterThanOrEqual(2); const n = await page.evaluate(() => UI.vPick.size);
  const c = await at(page, 'v-ip1'); await page.mouse.click(c.x, c.y, { button: 'right' });
  await expect(page.locator('#ctx .ctx-title')).toHaveText(n + ' selected');
  await page.click('#ctx .ctx-seg button:has-text("Malicious")');
  expect(await page.evaluate(() => [...UI.vPick].every(id => entryVerdict(entryById(id)) === 'malicious'))).toBe(true);
  noErrors(errors);
});

test('the keyboard: arrows and Space pick several, Ctrl+A picks all, Esc lets go', async ({ page }) => {
  const errors = await ready(page);
  await page.focus('#cy'); await page.waitForTimeout(700);
  await page.keyboard.press('ArrowRight'); const first = await page.evaluate(() => UI.sel && UI.sel.id); expect(first).toBeTruthy();
  await page.keyboard.press('Space'); await expect(page.locator('.gbulk')).toContainText('1 selected'); await expect.poll(() => page.evaluate(() => document.activeElement && document.activeElement.id)).toBe('cy');
  for (const k of ['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown']) { await page.keyboard.press(k); if (await page.evaluate(f => UI.gKeyAt && UI.gKeyAt !== f, first)) break; }   // whichever way has a neighbour
  expect(await page.evaluate(f => UI.gKeyAt !== f, first)).toBe(true);
  await page.keyboard.press('Space');
  await expect(page.locator('.gbulk')).toContainText('2 selected');
  await expect(page.locator('#gLive')).toContainText('2 selected'); await expect.poll(() => page.evaluate(() => document.activeElement && document.activeElement.id)).toBe('cy');
  await page.keyboard.press('Control+a'); const all = await page.evaluate(() => cy.nodes(':visible').length);
  await expect(page.locator('.gbulk')).toContainText(all + ' selected');
  await page.locator('#cy').focus(); await page.keyboard.press('Escape');
  await expect(page.locator('.gbulk')).toHaveCount(0); expect(await page.evaluate(() => UI.vPick.size)).toBe(0);
  noErrors(errors);
});
