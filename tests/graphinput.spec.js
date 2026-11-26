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

// Cytoscape switches off its mouse handling when its graph box is taken out of the element it was first put in. A
// re-render that keeps the drawn graph (opening the details panel, a note, a verdict) moves that box, so after clicking
// one node the graph stopped taking clicks, drags and the wheel until something rebuilt it.
test('the graph keeps taking the mouse after re-renders that keep it, such as the details panel opening', async ({ page }) => {
  const errors = await open(page, '#/case/c-lantern/graph');
  await expect.poll(() => page.evaluate(() => typeof cy !== 'undefined' && !!cy && cy.nodes().length > 3)).toBe(true);
  const nodeAt = id => page.evaluate(id => { const r = cy.container().getBoundingClientRect(), p = cy.getElementById(id).renderedPosition(); return [r.left + p.x, r.top + p.y]; }, id);
  const free = () => page.evaluate(() => { const r = cy.container().getBoundingClientRect(); return cy.nodes().map(n => { const p = n.renderedPosition(); return [n.id(), r.left + p.x, r.top + p.y]; })
    .filter(([id, x, y]) => { const el = document.elementFromPoint(x, y); return el && cy.container().contains(el) && id !== (UI.sel && UI.sel.id); }).map(a => a[0]); });
  for (let round = 0; round < 3; round++) {
    // a re-render that keeps the drawn graph, as happens when the details panel opens
    await page.evaluate(async () => { const frame = () => new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r))); renderMain(); await frame(); window.__cy0 = cy; renderMain(); await frame(); renderMain(); renderMain(); await frame(); cy.fit(undefined, 60); });
    expect(await page.evaluate(() => [cy === __cy0, !cy.renderer().destroyed, cy.container().isConnected].join()), 'round ' + round + ': the same graph is kept and still live').toBe('true,true,true');
    // a click on a node selects it
    const [id] = await free(); const [x, y] = await nodeAt(id);
    await page.mouse.click(x, y, { delay: 120 });
    await expect.poll(() => page.evaluate(() => UI.sel && UI.sel.id), { message: 'round ' + round }).toBe(id);
    // dragging another node moves it
    const [id2] = await free(); const [x2, y2] = await nodeAt(id2); const p0 = await page.evaluate(id => ({ ...cy.getElementById(id).position() }), id2);
    await page.mouse.move(x2, y2); await page.mouse.down(); await page.mouse.move(x2 + 50, y2 + 30, { steps: 6 }); await page.mouse.up();
    const p1 = await page.evaluate(id => cy.getElementById(id).position(), id2);
    expect(Math.hypot(p1.x - p0.x, p1.y - p0.y) * await page.evaluate(() => cy.zoom()), 'node ' + id2 + ' moved on screen').toBeGreaterThan(40);
    // the wheel zooms
    const z0 = await page.evaluate(() => cy.zoom()), [wx, wy] = await page.evaluate(() => { const r = cy.container().getBoundingClientRect(); for (let y = r.top + r.height / 2; y < r.bottom; y += 20) for (let x = r.left + 200; x < r.right; x += 20) { const el = document.elementFromPoint(x, y); if (el && el.tagName === 'CANVAS' && cy.container().contains(el)) return [x, y]; } }); await page.mouse.move(wx, wy); await page.mouse.wheel(0, z0 > 1 ? 300 : -300); await page.waitForTimeout(150);
    expect(await page.evaluate(() => cy.zoom())).not.toBe(z0);
  }
  noErrors(errors);
});
