// A 10,000-record case: built, then every case tab and the main pages open within a time limit, a re-render of the
// graph keeps the drawing instead of rebuilding it, and saving and moving the case to a file stay quick.
const { test, expect } = require('@playwright/test');
const { open, noErrors, budget } = require('./helpers');

test('a 10,000-record case stays quick: every tab, the graph kept on re-render, save and move-to-file', async ({ page }) => {
  test.setTimeout(180000);
  const errors = await open(page, '#/home');
  await page.evaluate(() => { const c = { id: 'c-big', code: 'BIG', name: 'Big case — load test', color: '#5468ff', status: 'active', created: Date.now() - 864e5 * 90, updated: Date.now(), owner: 'You', scope: '', icon: 'folder' }; DB.cases.push(c);
    const T0 = Date.now() - 864e5 * 60;
    for (let i = 0; i < 10000; i++) { const body = `${['Logon', 'Process', 'DNS query', 'Connection', 'File write'][i % 5]} on WS-${i % 40} by user${i % 300}\nsrc=203.0.${(i * 7) % 256}.${(i * 13) % 256} dst=198.51.100.${i % 200} dport=443\nquery=node${i % 900}.evil-${i % 37}.example\nuser: @user${i % 300} email user${i % 300}@corp.example`;
      const r = { id: 'rb' + i, caseId: 'c-big', type: 'evidence', title: `Event ${i}`, body, tsRaw: '', tsZone: 'explicit', ts: T0 + i * 517000, source: 'log', host: 'WS-' + (i % 40), tags: [], answer: '', addedBy: 'You', addedAt: Date.now(), hash: '' }; r.ents = extractRich(body); DB.records.push(r); }
    for (let i = 0; i < 2000; i++) DB.entries.push({ id: 'vb' + i, caseId: 'c-big', type: i % 3 ? 'ip' : 'domain', fields: i % 3 ? { ip: `203.0.${i % 256}.${(i * 3) % 256}` } : { domain: `node${i % 900}.evil-${i % 37}.example` }, priority: 'medium', starred: false, tags: [], notes: '', src: 'rb' + i, created: Date.now(), pos: null });
    for (let i = 0; i < 3000; i++) DB.links.push({ id: 'lb' + i, caseId: 'c-big', a: 'vb' + (i % 2000), b: 'vb' + ((i * 7 + 1) % 2000), label: 'related to', conf: 1, src: '' });
    mutate('big'); DB.active = 'c-big'; });
  const lim = await budget(page, 900), slow = [];
  const openTime = h => page.evaluate(h => new Promise(res => { const t = performance.now(); go(h); requestAnimationFrame(() => requestAnimationFrame(() => res(performance.now() - t))); }), h);
  /* each screen opened twice, the better time kept: one garbage-collection pause on a busy machine is not a slow screen */
  const twice = async h => { const a = await openTime(h); await openTime('#/settings'); return Math.min(a, await openTime(h)); };
  for (const tab of ['overview', 'vault', 'entities', 'timeline', 'map', 'media', 'infra', 'questions', 'report']) { const t = await twice('#/case/c-big/' + tab); if (t > lim) slow.push(tab + ' ' + Math.round(t)); }
  for (const a of ['home', 'today', 'cases', 'entities', 'feeds', 'tradecraft']) { const t = await twice('#/' + a); if (t > lim) slow.push(a + ' ' + Math.round(t)); }
  expect(slow).toEqual([]);
  // the graph: built once, then a re-render keeps the same drawing
  await page.evaluate(() => go('#/case/c-big/graph')); await expect(page.locator('#cy canvas').first()).toBeVisible({ timeout: 30000 });
  await expect.poll(() => page.evaluate(() => !!cy && cy.nodes().length)).toBe(2000);
  const g = await page.evaluate(() => new Promise(res => { const before = cy, t = performance.now(); renderMain(); requestAnimationFrame(() => requestAnimationFrame(() => res({ same: cy === before, nodes: cy.nodes().length, ms: performance.now() - t, inDom: document.getElementById('cy') === cy.container() }))); }));
  expect(g).toMatchObject({ same: true, nodes: 2000, inDom: true }); expect(g.ms).toBeLessThan(lim);
  // a change to the graph's data still rebuilds it
  await page.evaluate(() => { DB.entries.find(e => e.id === 'vb1').fields.ip = '192.0.2.77'; mutate('x'); renderMain(); });
  await expect.poll(() => page.evaluate(() => cy.nodes().some(n => /192\.0\.2\.77/.test(n.data('label') || '')))).toBe(true);
  // saving, and the file a move-to-file would write
  const s = await page.evaluate(async () => { let t = performance.now(); flush(); const save = performance.now() - t; t = performance.now(); const { o } = await stashObj(theCase('c-big')); const len = JSON.stringify(o).length; return { save, stash: performance.now() - t, len }; });
  expect(s.save).toBeLessThan(lim); expect(s.stash).toBeLessThan(lim * 2); expect(s.len).toBeGreaterThan(1e6);
  noErrors(errors);
});
