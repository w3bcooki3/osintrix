// The graph must keep taking the mouse when it moves on the page without changing size (a note or bar appearing
// above it after entities are added). Cytoscape caches where its canvas is, and a stale cache made every click,
// drag and wheel look like it was outside the graph, until something else made it measure again.
const { test, expect } = require('@playwright/test');
const { open, noErrors } = require('./helpers');

test('the graph keeps taking drag, wheel and clicks after it moves on the page', async ({ page }) => {
  const errors = await open(page, '#/home');
  await page.evaluate(() => {
    DB.cases.push(Object.assign({}, DB.cases[0], { id: 'gx', name: 'Graph input' })); DB.active = 'gx';
    const body = 'contact 198.51.100.7 and evil-host.example, mail ops@evil-host.example';
    DB.records.push({ id: uid('r'), caseId: 'gx', type: 'evidence', title: 'note', body, tsRaw: '', tsZone: 'explicit', ts: Date.now(), source: '', host: '', tags: [], ents: E.extract(body), answer: '', addedBy: 'You', addedAt: Date.now(), hash: '' });
    DB.entries.push({ id: uid('v'), caseId: 'gx', type: 'domain', fields: { domain: 'other.example' }, priority: 'medium', starred: false, tags: [], notes: '', src: '', created: Date.now(), pos: null });
    mutate('t'); go(caseHash('gx', 'graph'));
  });
  await page.click('[data-act=gPick]');
  await page.locator('#pkList input[type=checkbox]').first().check();
  await page.click('[data-act=pkGo]');
  await expect.poll(() => page.evaluate(() => cy && cy.nodes().length)).toBe(2);
  await page.waitForTimeout(300);
  // let the graph measure itself where it is now, then move it 120px up the page without resizing it, as when a bar above it goes away
  const b0 = await page.locator('#cy').boundingBox();
  await page.mouse.move(b0.x + 20, b0.y + 20);
  await page.evaluate(() => { const g = document.querySelector('.gcanvas'); g.style.position = 'relative'; g.style.top = '-120px'; g.style.zIndex = '50'; });
  const box = await page.locator('#cy').boundingBox();
  expect(Math.round(b0.y - box.y)).toBe(120);
  // drag on an empty spot near its new top edge: it lies above where the graph used to be
  const p0 = await page.evaluate(() => ({ ...cy.pan() }));
  const y = box.y + 40;
  expect(await page.evaluate(([x, y]) => document.elementFromPoint(x, y).tagName, [box.x + 40, y])).toBe('CANVAS');
  await page.mouse.move(box.x + 40, y); await page.mouse.down(); await page.mouse.move(box.x + 140, y - 50, { steps: 6 }); await page.mouse.up();
  const p1 = await page.evaluate(() => ({ ...cy.pan() }));
  expect(p1.x - p0.x).toBeGreaterThan(50);
  // the wheel zooms
  const z0 = await page.evaluate(() => cy.zoom());
  await page.mouse.move(box.x + 60, y); await page.mouse.wheel(0, 400); await page.waitForTimeout(200);
  expect(await page.evaluate(() => cy.zoom())).not.toBe(z0);
  // a click on a node selects it
  const n = await page.evaluate(() => { const r = document.getElementById('cy').getBoundingClientRect(), node = cy.nodes()[0], p = node.renderedPosition(); return { id: node.id(), x: r.left + p.x, y: r.top + p.y }; });
  await page.mouse.click(n.x, n.y);
  await expect.poll(() => page.evaluate(() => UI.sel && UI.sel.id)).toBe(n.id);
  noErrors(errors);
});
