// Real-mouse timing: things a person does that a script's instant clicks never do. A press held before a drag, a press
// whose release never arrives, a menu left open while the page moves on, a redraw nobody asked for landing while they
// type or halfway through a click, a double-click on Create.
const { test, expect } = require('@playwright/test');
const { open, noErrors } = require('./helpers');
test.use({ viewport: { width: 1440, height: 860 } });

const onScreen = page => page.evaluate(() => { const r = cy.container().getBoundingClientRect(); return cy.nodes().map(n => { const p = n.renderedPosition(); return [n.id(), r.left + p.x, r.top + p.y]; })
  .filter(([, x, y]) => { const el = document.elementFromPoint(x, y); return el && cy.container().contains(el); }); });
const menuOpen = page => page.evaluate(() => !!document.getElementById('ctx'));

test('graph: holding a node before dragging it opens no menu; the right button and a touch long-press still do', async ({ page, browser }) => {
  const errors = await open(page, '#/case/c-lantern/graph');
  await expect.poll(() => page.evaluate(() => typeof cy !== 'undefined' && !!cy && cy.nodes().length > 3)).toBe(true);
  const [[id, x, y]] = await onScreen(page); const p0 = await page.evaluate(id => ({ ...cy.getElementById(id).position() }), id);
  await page.mouse.move(x, y); await page.mouse.down(); await page.waitForTimeout(1000);   // longer than a hold
  expect(await menuOpen(page)).toBe(false);
  await page.mouse.move(x + 70, y + 40, { steps: 8 }); await page.mouse.up();
  expect(await menuOpen(page)).toBe(false);
  const p1 = await page.evaluate(id => cy.getElementById(id).position(), id); expect(Math.hypot(p1.x - p0.x, p1.y - p0.y)).toBeGreaterThan(10);
  // the right button opens it; a drag or a zoom closes it
  const [[, x2, y2]] = await onScreen(page); await page.mouse.click(x2, y2, { button: 'right', delay: 80 }); expect(await menuOpen(page)).toBe(true);
  const [gx, gy] = await page.evaluate(() => { const r = cy.container().getBoundingClientRect(); for (let y = r.top + 60; y < r.bottom - 60; y += 23) for (let x = r.left + 60; x < r.right - 60; x += 23) { const e = document.elementFromPoint(x, y); if (e && e.tagName === 'CANVAS' && cy.container().contains(e)) return [x, y]; } });
  await page.mouse.move(gx, gy); await page.mouse.wheel(0, -200); await page.waitForTimeout(150); expect(await menuOpen(page)).toBe(false);
  // a touch long-press still opens it
  const ctx = await browser.newContext({ hasTouch: true, viewport: { width: 1100, height: 800 } }); const p2 = await ctx.newPage(); const e2 = await open(p2, '#/case/c-lantern/graph');
  await expect.poll(() => p2.evaluate(() => typeof cy !== 'undefined' && !!cy && cy.nodes().length > 3)).toBe(true); await p2.waitForTimeout(400);
  const [[, tx, ty]] = await onScreen(p2); const cdp = await ctx.newCDPSession(p2);
  await cdp.send('Input.dispatchTouchEvent', { type: 'touchStart', touchPoints: [{ x: tx, y: ty }] }); await p2.waitForTimeout(1000); await cdp.send('Input.dispatchTouchEvent', { type: 'touchEnd', touchPoints: [] });
  await expect.poll(() => menuOpen(p2)).toBe(true);
  await ctx.close(); noErrors([...errors, ...e2]);
});

test('menus belong to their page: going elsewhere or rebuilding the graph closes them, as Back closes search', async ({ page }) => {
  const errors = await open(page, '#/case/c-lantern/graph');
  await expect.poll(() => page.evaluate(() => typeof cy !== 'undefined' && !!cy && cy.nodes().length > 3)).toBe(true);
  const rclick = async () => { const [[, x, y]] = await onScreen(page); await page.mouse.click(x, y, { button: 'right', delay: 80 }); expect(await menuOpen(page)).toBe(true); };
  await rclick(); await page.evaluate(() => go('#/case/c-lantern/timeline')); await page.waitForTimeout(200); expect(await menuOpen(page)).toBe(false);
  await page.evaluate(() => go('#/case/c-lantern/graph')); await expect.poll(() => page.evaluate(() => !!cy && cy.container().isConnected)).toBe(true); await page.waitForTimeout(300);
  // a redraw that keeps the same graph keeps the menu (it is still right); a change that rebuilds the graph closes it
  await rclick(); await page.evaluate(() => { window.__c = cy; renderMain(); }); await page.waitForTimeout(150);
  expect(await page.evaluate(() => cy === __c)).toBe(true); expect(await menuOpen(page)).toBe(true);
  await page.evaluate(() => { DB.entries.push({ id: 'mx1', caseId: 'c-lantern', type: 'domain', fields: { domain: 'menu-rebuild.example' }, priority: 'medium', starred: false, tags: [], notes: '', src: '', created: Date.now(), pos: null }); mutate('x'); renderMain(); });
  await expect.poll(() => page.evaluate(() => cy !== __c)).toBe(true); expect(await menuOpen(page)).toBe(false);
  // search, then the browser's Back button
  await page.evaluate(() => srchOpen('lantern')); await page.goBack(); await page.waitForTimeout(300);
  expect(await page.evaluate(() => !!(document.getElementById('srch') && !document.getElementById('srch').hidden))).toBe(false);
  noErrors(errors);
});

test('notebook page graph: a press whose release never arrives does not leave the view panning on plain hover', async ({ page }) => {
  const errors = await open(page, '#/home');
  await page.evaluate(() => { UI.nbView = 'graph'; UI.nbgFrom = null; go('#/notebook'); });
  await expect(page.locator('#nbgSvg')).toBeVisible();
  const vb = () => page.evaluate(() => $('nbgSvg').getAttribute('viewBox'));
  const c = await page.evaluate(() => { const r = $('nbgSvg').getBoundingClientRect(); return [r.left + r.width / 2, r.top + r.height / 2]; });
  for (const end of ['pointercancel', 'nothing']) {
    await page.evaluate(() => nbwZoomAt(0)); const v0 = await vb(); await page.mouse.move(c[0], c[1]);
    await page.evaluate(([x, y, end]) => { const s = $('nbgSvg'); s.dispatchEvent(new PointerEvent('pointerdown', { clientX: x, clientY: y, bubbles: true, button: 0, buttons: 1, pointerId: 7, isPrimary: true }));
      if (end === 'pointercancel') s.dispatchEvent(new PointerEvent('pointercancel', { bubbles: true, pointerId: 7 })); }, [c[0], c[1], end]);
    await page.mouse.move(c[0] + 150, c[1] + 70, { steps: 6 });   // no button held
    expect(await vb(), end).toBe(v0);
  }
  // a real drag still pans
  await page.evaluate(() => nbwZoomAt(0)); const v0 = await vb();
  await page.mouse.move(c[0] - 200, c[1] + 150); await page.mouse.down(); await page.mouse.move(c[0] - 60, c[1] + 190, { steps: 8 }); await page.mouse.up();
  expect(await vb()).not.toBe(v0);
  noErrors(errors);
});

test('a background redraw waits while you type and while a button is half-clicked', async ({ page }) => {
  const errors = await open(page, '#/notes');
  const box = page.locator('.nquick textarea').first();
  await box.click(); await page.keyboard.type('Half-typed thought about the', { delay: 10 });
  // a reminder falls due: it used to redraw the page at once and take the typing with it
  await page.evaluate(() => { const d = new Date(Date.now() - 120000), p = x => String(x).padStart(2, '0');
    DB.notes.push({ id: 'rm1', caseId: '', text: 'Call back the registrar', remind: true, due: d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()), dueTime: p(d.getHours()) + ':' + p(d.getMinutes()), at: Date.now(), pinned: false });
    window.__drawn = 0; const o = renderMain; window.renderMain = function () { __drawn++; return o.apply(this, arguments); }; noteRemindCheck(); });
  expect(await page.evaluate(() => DB.notes.find(n => n.id === 'rm1').reminded)).toBeTruthy();
  await page.waitForTimeout(300);
  expect(await page.evaluate(() => ({ v: document.querySelector('.nquick textarea').value, f: document.activeElement === document.querySelector('.nquick textarea'), n: __drawn })))
    .toEqual({ v: 'Half-typed thought about the', f: true, n: 0 });
  await page.keyboard.type(' renewal'); await page.keyboard.press('Tab');
  await expect.poll(() => page.evaluate(() => __drawn)).toBe(1);   // done once the box is left

  // a redraw waiting while a button is pressed: the click still lands
  await page.evaluate(() => go('#/case/c-lantern/overview')); await page.waitForTimeout(300);
  const b = await page.locator('#main button[data-act]:visible').first().boundingBox();
  await page.evaluate(() => { window.__clicked = 0; document.addEventListener('click', e => { if (e.target.closest('[data-act]')) __clicked++; }, true); });
  await page.mouse.move(b.x + b.width / 2, b.y + b.height / 2); await page.mouse.down();
  await page.evaluate(() => bgRender()); await page.waitForTimeout(120); await page.mouse.up();
  await expect.poll(() => page.evaluate(() => __clicked)).toBe(1);
  noErrors(errors);
});

test('a text selection that ends on the backdrop keeps the dialog; a double-click on Create makes one thing', async ({ page }) => {
  const errors = await open(page, '#/case/c-lantern/vault');
  await page.evaluate(() => entryDlg(null, { type: 'person' }));
  const f = await page.evaluate(() => { const i = document.querySelector('#dlg input:not([type=hidden]):not([type=checkbox])'); i.value = 'A long name to select with the mouse'; const r = i.getBoundingClientRect(); return [r.left + 10, r.top + r.height / 2]; });
  await page.mouse.move(f[0], f[1]); await page.mouse.down(); await page.mouse.move(6, 6, { steps: 10 }); await page.mouse.up();
  await expect(page.locator('#dlg input').first()).toBeVisible();
  await page.evaluate(() => closeDlg());
  const n0 = await page.evaluate(() => DB.cases.length);
  await page.evaluate(() => caseDlg(false)); await page.fill('#cName', 'Double-click case');
  const s = await page.locator('#dlg button[type=submit]').boundingBox(); await page.mouse.dblclick(s.x + s.width / 2, s.y + s.height / 2, { delay: 60 });
  await page.waitForTimeout(400); expect(await page.evaluate(() => DB.cases.length)).toBe(n0 + 1);
  noErrors(errors);
});

test('graph: from a node straight onto the zoom buttons leaves nothing faded; with the side panel open they and the time slider are not under it', async ({ page }) => {
  const errors = await open(page, '#/case/c-lantern/graph');
  await expect.poll(() => page.evaluate(() => typeof cy !== 'undefined' && !!cy && cy.nodes().length > 3)).toBe(true);
  const [[, x, y]] = await onScreen(page); await page.mouse.move(x, y, { steps: 3 });
  expect(await page.evaluate(() => cy.elements('.faded').length)).toBeGreaterThan(0);   // hovering fades the rest
  const z = await page.locator('[data-act=gZoom]').first().boundingBox(); await page.mouse.move(z.x + z.width / 2, z.y + z.height / 2, { steps: 1 });
  expect(await page.evaluate(() => cy.elements('.faded').length)).toBe(0);
  await page.evaluate(() => { UI.graph.panel = 'sugg'; renderMain(); }); await expect(page.locator('.gpanel')).toBeVisible();
  const r = await page.evaluate(() => { const p = document.querySelector('.gpanel').getBoundingClientRect(), hit = el => { const r = el.getBoundingClientRect(), e = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2); return el === e || el.contains(e); };
    return { buttons: [...document.querySelectorAll('[data-act=gZoom],[data-act=gFit]')].map(hit), slider: document.querySelector('.gtime') ? document.querySelector('.gtime').getBoundingClientRect().right <= p.left : true }; });
  expect(r).toEqual({ buttons: [true, true, true], slider: true });
  noErrors(errors);
});
