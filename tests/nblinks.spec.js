// Notebook links, Obsidian style: [[ autocomplete between pages, a link to a page that does not exist yet creates it,
// backlinks with the line they sit in, unlinked mentions turned into links with one click, links to cases and indicators
// that open them, rename-safe links, [[Title]] in imported Markdown, Markdown export writing [[Title]], and the graph.
const { test, expect } = require('@playwright/test');
const { open, noErrors } = require('./helpers');

async function setup(page) {
  return page.evaluate(() => {
    ensureNB(); const b = nbNewBook({ name: 'AD course' }), s = nbNewSec(b.id, 'Attacks');
    const k = nbNewPage(s.id, { title: 'SPN roasting', html: '<p>Request TGS tickets for SPN accounts and crack them offline.</p>' });
    const a = nbNewPage(s.id, { title: 'AD attack paths', html: '<p>Overview.</p>' });
    const m = nbNewPage(s.id, { title: 'Persistence notes', html: '<p>After spn roasting the service account we kept access.</p>' });
    mutate('test pages'); return { k: k.id, a: a.id, m: m.id };
  });
}
const commit = page => page.evaluate(() => nbCommit());
const html = (page, id) => page.evaluate(id => nbPage(id).html, id);

test('[[ suggests pages, picks one, the target shows the backlink, clicking opens it; a new title creates the page', async ({ page }) => {
  const errors = await open(page, '#/notebook');
  const P = await setup(page);
  await page.evaluate(id => nbOpen(id, { full: true }), P.a);
  await page.click('#nbEd p');
  await page.keyboard.press('End');
  await page.keyboard.type(' See [[spn r');
  const pop = page.locator('#nbwPop');
  await expect(pop).toBeVisible();
  await expect(pop.locator('[role=option]').first()).toContainText('SPN roasting');
  await page.keyboard.press('Enter');
  await expect(pop).toHaveCount(0);
  await page.keyboard.type('for the details.');
  await commit(page);
  expect(await html(page, P.a)).toContain(`data-wl="page:${P.k}"`);
  expect(await html(page, P.a)).not.toContain('[[');
  // the link opens the page, whose side panel lists where it is linked from, with the line it sits in
  await page.click(`#nbEd a.nb-wl[data-wl="page:${P.k}"]`);
  await expect(page.locator('#nbTitle')).toHaveValue('SPN roasting');
  const back = page.locator('#nbwBack');
  await expect(back).toContainText('AD attack paths');
  await expect(back).toContainText('See SPN roasting for the details.');
  await back.locator('[data-act=nbwGo]').click();
  await expect(page.locator('#nbTitle')).toHaveValue('AD attack paths');
  // [[Title]] typed in full links straight away; a page that does not exist yet is created on click
  await page.click('#nbEd p');
  await page.keyboard.press('End');
  await page.keyboard.type(' Next: [[Golden ticket]]');
  await commit(page);
  const miss = page.locator('#nbEd a.nb-wl.miss');
  await expect(miss).toHaveText('Golden ticket');
  await miss.click();
  await expect(page.locator('#nbTitle')).toHaveValue('Golden ticket');
  const g = await page.evaluate(() => nbwByTitle('Golden ticket').id);
  expect(await html(page, P.a)).toContain(`data-wl="page:${g}"`);              // the link now points at the new page by id
  await expect(page.locator('#nbwBack')).toContainText('AD attack paths');
  // renaming a page keeps the links and shows the new title
  await page.evaluate(id => { nbPage(id).title = 'SPN roasting (T1558.003)'; nbTouch(nbPage(id)); mutate('rename'); }, P.k);
  await page.evaluate(id => nbOpen(id, { full: true }), P.a);
  await expect(page.locator(`#nbEd a.nb-wl[data-wl="page:${P.k}"]`)).toHaveText('SPN roasting (T1558.003)');
  noErrors(errors);
});

test('unlinked mentions become links with one click; Markdown export writes [[Title]] and imported [[links]] resolve', async ({ page }) => {
  const errors = await open(page, '#/notebook');
  const P = await setup(page);
  await page.evaluate(id => nbOpen(id, { full: true }), P.k);
  const men = page.locator('#nbwMen');
  await expect(men).toContainText('Persistence notes');
  await expect(men).toContainText('After spn roasting the service account');
  await men.locator('.nbs-bl:has-text("Persistence notes") [data-act=nbwLinkIt]').click();
  await expect(page.locator('#nbwMen .nbs-bl:has-text("Persistence notes")')).toHaveCount(0);
  await expect(page.locator('#nbwBack')).toContainText('Persistence notes');
  const h = await html(page, P.m);
  expect(h).toContain(`<a class="nb-wl" data-wl="page:${P.k}" data-a="1" contenteditable="false">spn roasting</a>`);   // keeps the words as written
  expect(await page.evaluate(id => nbMarkdown(nbPage(id).html), P.m)).toContain('[[SPN roasting|spn roasting]]');
  // a page written elsewhere with [[...]] links (Obsidian, plain Markdown) links up when shown
  await page.evaluate(() => { const s = DB.nb.sections.find(x => x.name === 'Attacks'); nbNewPage(s.id, { title: 'Imported', html: nbClean(mdLite('Read [[SPN roasting]] and [[AD attack paths|the overview]], then [[Silver ticket]].')) }); mutate('import'); });
  const imp = await page.evaluate(() => nbwByTitle('Imported').id);
  await page.evaluate(id => nbOpen(id, { full: true }), imp);
  await expect(page.locator(`#nbEd a.nb-wl[data-wl="page:${P.k}"]`)).toHaveText('SPN roasting');
  await expect(page.locator(`#nbEd a.nb-wl[data-wl="page:${P.a}"]`)).toHaveText('the overview');
  await expect(page.locator('#nbEd a.nb-wl.miss')).toHaveText('Silver ticket');
  await page.evaluate(id => nbOpen(id, { full: true }), P.a);
  await expect(page.locator('#nbwBack')).toContainText('Imported');           // backlinks count the plain-text [[links]] too
  noErrors(errors);
});

test('links to a case and an indicator from a page open them; indicators already in cases are listed; the graph opens pages', async ({ page }) => {
  const errors = await open(page, '#/notebook');
  const P = await setup(page);
  const c = await page.evaluate(() => { const c = DB.cases.find(x => DB.entries.some(e => e.caseId === x.id)) || DB.cases[0]; return { id: c.id, name: caseNm(c) }; });
  const ioc = await page.evaluate(() => { for (const [id, g] of globalEnts()) if (g.k === 'ip' || g.k === 'domain') return { id, v: g.v }; return null; });
  expect(ioc).not.toBeNull();
  await page.evaluate(({ id, v }) => { const p = nbPage(id); p.html = '<p>Seen beaconing to ' + esc(v) + ' during the lab.</p>'; nbTouch(p); mutate('x'); nbOpen(id, { full: true }); }, { id: P.m, v: ioc.v });
  await expect(page.locator('#nbwIoc')).toContainText(ioc.v);
  await page.click('#nbEd p');
  await page.keyboard.press('End');
  await page.keyboard.type(' Case: [[case:' + c.name.split(' ')[0]);
  const opt = page.locator('#nbwPop [role=option]').first();
  await expect(opt).toContainText(c.name.split(' ')[0]);
  await expect(opt).toContainText('Case');
  await page.keyboard.press('Enter');
  await commit(page);
  expect(await html(page, P.m)).toContain(`data-wl="case:${c.id}"`);
  await expect(page.locator('#nbwOut')).toContainText(c.name);
  await page.click(`#nbEd a.nb-wl[data-wl="case:${c.id}"]`);
  await expect.poll(() => page.evaluate(() => UI.route.area)).toBe('case');
  expect(await page.evaluate(() => DB.active)).toBe(c.id);
  // the side panel's indicator opens it in Entities
  await page.evaluate(id => nbOpen(id, { full: true }), P.m);
  await page.locator('#nbwIoc [data-act=nbwGo]').first().click();
  await expect.poll(() => page.evaluate(() => UI.route.area)).toBe('entities');
  // graph: the pages and links, filtered to one notebook; clicking a page opens it
  await page.evaluate(({ a, k }) => { const p = nbPage(a); p.html = '<p>See <a data-wl="page:' + k + '">it</a>.</p>'; nbTouch(p); mutate('x'); nbOpen(a, { full: true }); }, P);
  await page.click('.nb3-tree [data-act=nbwGraph]');
  await expect(page.locator('#nbgSvg')).toBeVisible();
  await page.selectOption('#nbgBook', { label: 'AD course' });
  await expect(page.locator('.nbg-st')).toContainText('3 pages');
  await expect(page.locator('.nbg-st')).toContainText('1 link');
  await expect(page.locator('.nbg-n.cur')).toHaveAttribute('data-id', 'page:' + P.a);
  await page.check('#nbgExt');
  await expect(page.locator('.nbg-n.ext')).toHaveCount(1);                    // the case linked from Persistence notes
  await expect(page.locator('.nbg-st')).toContainText('2 links');
  await page.locator(`.nbg-n[data-id="page:${P.k}"] circle`).click({ force: true });
  await expect(page.locator('#nbTitle')).toHaveValue('SPN roasting');
  noErrors(errors);
});
