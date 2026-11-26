// Story: protected sources (encrypted, shown only when asked, locked when idle or hidden, burned from every restore
// point), claims with a check before publishing, right of reply, and archived copies of cited pages.
const { test, expect } = require('@playwright/test');
const { open, noErrors } = require('./helpers');
const fs = require('fs');

const PASS = 'correct horse battery staple';
const REAL = 'Kari Nordmann-Vik';

async function seed(page){
  await page.evaluate(() => {
    DB.cases.push(Object.assign({}, DB.cases[0], { id: 'sx', name: 'Harbour refunds', claims: undefined, replies: undefined, ach: undefined })); DB.active = 'sx';
    const rec = (id, title, source, body, att) => DB.records.push({ id, caseId: 'sx', type: 'evidence', title, body, tsRaw: '', tsZone: 'explicit', ts: Date.now(), source, host: '', tags: [], ents: E.extract(body), answer: '', addedBy: 'You', addedAt: Date.now(), hash: '', att: att || [] });
    rec('r1', 'Company register extract', 'brreg.no', 'Harbourline Logistics AS, board member Jon Berg. https://register.example/harbourline');
    rec('r2', 'Second register copy', 'brreg.no', 'Same extract, downloaded again.');
    rec('r3', 'Court filing 2024', 'court records', 'Filing names Jon Berg as director. https://court.example/case/2024-117');
    rec('r4', 'Photo of the office sign', 'sent by email', 'Picture of the sign.', [{ id: 'a1', name: 'office-sign.jpg', type: 'image/jpeg', size: 1000 }]);
    rec('r5', 'Notes from a call', '', 'Insider says invoices were faked.');
    DB.entries.push({ id: 'p1', caseId: 'sx', type: 'person', fields: { name: 'Jon Berg' }, priority: 'high', starred: false, tags: [], notes: '', src: '', created: Date.now(), pos: null });
    mutate('seed');
  });
}

test('protected source: encrypted at rest, never in exports or the saved workspace, shown only when asked, locks when hidden', async ({ page }) => {
  const errors = await open(page, '#/home'); await seed(page);
  await page.evaluate(() => go(caseHash('sx', 'story'))); await page.click('[data-act=stView][data-v=sources]');
  // the passphrase: long enough, typed twice
  await page.fill('#stP1', 'short'); await page.fill('#stP2', 'short'); await page.click('form[data-form=stPass] button');
  await expect(page.locator('.ferr').first()).toContainText('At least 10 characters');
  await page.fill('#stP1', PASS); await page.fill('#stP2', PASS + 'x'); await page.click('form[data-form=stPass] button');
  await expect(page.locator('.ferr').first()).toContainText('do not match');
  await page.fill('#stP2', PASS); await page.click('form[data-form=stPass] button');
  await page.click('[data-act=stSrcNew]');
  await page.fill('#ss-alias', 'Harbour insider'); await page.fill('#ss-name', REAL); await page.fill('#ss-contact', 'Signal, second phone'); await page.selectOption('#ss-rel', 'B');
  await page.click('#dlg button[type=submit]');
  await expect(page.locator('.st-src')).toContainText('Harbour insider');
  await expect(page.locator('#main')).not.toContainText(REAL);                       // not shown until asked
  await page.click('[data-act=stShow]'); await expect(page.locator('.st-real')).toContainText(REAL);

  // nowhere in plain text: the workspace, what is saved, a case export
  expect(await page.evaluate(r => JSON.stringify(DB).includes(r), REAL)).toBe(false);
  await page.evaluate(() => save()); await page.waitForTimeout(400);
  expect(await page.evaluate(r => (localStorage.getItem(STORE_KEY) || '').includes(r) || (localStorage.getItem(STORE_KEY) || '').includes('Signal, second phone'), REAL)).toBe(false);
  const [dl] = await Promise.all([page.waitForEvent('download'), page.evaluate(() => clickAct('exportCase', 'sx'))]);
  const exp = fs.readFileSync(await dl.path(), 'utf8');
  expect(exp).not.toContain(REAL); expect(exp).not.toContain('sealed');

  // attribute evidence to the source: only the pseudonym goes with it
  await page.evaluate(() => select('rec', 'r5'));
  await page.selectOption('#stRecSrc', { label: 'Harbour insider' });
  expect(await page.evaluate(() => { const r = recById('r5'); return [r.source, !!r.srcId]; })).toEqual(['Protected source · Harbour insider', true]);

  // leaving the tab locks it and forgets the details
  await page.evaluate(() => { Object.defineProperty(document, 'hidden', { configurable: true, get: () => true }); document.dispatchEvent(new Event('visibilitychange')); });
  expect(await page.evaluate(() => [!!ST.key, ST.open.size])).toEqual([false, 0]);
  await page.evaluate(() => { Object.defineProperty(document, 'hidden', { configurable: true, get: () => false }); go(caseHash('sx', 'story')); });
  await expect(page.locator('#main')).not.toContainText(REAL);
  await page.fill('#stUp', 'wrong passphrase'); await page.click('form[data-form=stUnlock] button');
  await expect(page.locator('.ferr').first()).toContainText('not the passphrase');
  await page.fill('#stUp', PASS); await page.click('form[data-form=stUnlock] button');
  await page.click('[data-act=stShow]'); await expect(page.locator('.st-real')).toContainText('Signal, second phone');
  noErrors(errors);
});

test('burning a source wipes it from the workspace and from restore points; it asks for the pseudonym typed out', async ({ page }) => {
  const errors = await open(page, '#/home'); await seed(page);
  await page.evaluate(async p => { await stSetPass(p); const c = theCase('sx'); stOf(c);
    DB.sources = [{ id: 'src-1', caseId: 'sx', alias: 'Dock worker', rel: 'C', sealed: await stSeal({ name: 'Ola Hansen' }), created: 1 }];
    const r = recById('r5'); r.srcId = 'src-1'; r.source = 'Protected source · Dock worker';
    c.claims.push({ id: 'cl1', t: 'Invoices were faked', st: 'unverified', for: ['s:src-1', 'r:r1'], against: [], about: [], note: '', at: 1 }); mutate('x'); }, PASS);
  await page.evaluate(() => snapshot('before burning'));
  await expect.poll(() => page.evaluate(async () => (await IDB.keys()).filter(k => /^osintrix-snap:/.test(k)).length)).toBeGreaterThan(0);
  const before = await page.evaluate(async () => { let n = 0; for (const k of (await IDB.keys()).filter(k => /^osintrix-snap:\d+$/.test(k))) { const d = JSON.parse(await openStr(await IDB.get(k))); if ((d.sources || []).some(s => s.id === 'src-1')) n++; } return n; });
  expect(before).toBeGreaterThan(0);

  await page.evaluate(() => { go(caseHash('sx', 'story')); UI.stView = 'sources'; renderMain(); });
  await page.click('[data-act=stBurnAsk]');
  await page.fill('#sb-a', 'dock'); await page.click('#dlg button[type=submit]');
  await expect(page.locator('.ferr').first()).toContainText('exactly');
  await page.fill('#sb-a', 'Dock worker'); await page.click('#dlg button[type=submit]');
  await expect(page.locator('.toast')).toContainText('Source burned');
  const after = await page.evaluate(async () => { let n = 0; for (const k of (await IDB.keys()).filter(k => /^osintrix-snap:\d+$/.test(k))) { const d = JSON.parse(await openStr(await IDB.get(k))); if ((d.sources || []).some(s => s.id === 'src-1') || (d.records || []).some(r => r.srcId === 'src-1')) n++; } return n; });
  expect(after).toBe(0);
  expect(await page.evaluate(() => [DB.sources.length, recById('r5').source, recById('r5').srcId, theCase('sx').claims[0].for])).toEqual([0, 'Protected source (burned)', undefined, ['r:r1']]);
  noErrors(errors);
});

test('claims: two records from one source are one source; a protected source counts once; pictures and right of reply hold a claim back', async ({ page }) => {
  const errors = await open(page, '#/home'); await seed(page);
  await page.evaluate(() => go(caseHash('sx', 'story')));
  await page.fill('#stNew', 'Jon Berg was a director of Harbourline Logistics in 2024'); await page.click('form[data-form=stClaim] button');
  const issues = () => page.evaluate(() => stClaimCheck(theCase('sx'), theCase('sx').claims[0], derive('sx')).map(i => i.lvl + ': ' + i.t));
  expect(await issues()).toEqual(['bad: Not confirmed yet', 'bad: No source for it yet']);

  // evidence for it, picked from the case: the two register copies are one source
  await page.click('[data-act=stEvAdd][data-v=for]');
  await page.check('#dlg input[data-pk="r:r1"]'); await page.check('#dlg input[data-pk="r:r2"]'); await page.click('[data-act=stEvGo]');
  await page.click('[data-act=stStatus][data-v=confirmed]');
  expect(await issues()).toEqual(['bad: Only one independent source', 'warn: 1 cited page with no archived copy']);
  // a second, independent source, with a picture
  await page.click('[data-act=stEvAdd][data-v=for]'); await page.fill('#stPq', 'court'); await expect(page.locator('#dlg label[data-q*="register"]').first()).toBeHidden();
  await page.check('#dlg input[data-pk="r:r3"]'); await page.fill('#stPq', ''); await page.check('#dlg input[data-pk="r:r4"]'); await page.click('[data-act=stEvGo]');
  expect(await issues()).toEqual(['bad: Picture not verified: office-sign.jpg in “Photo of the office sign”', 'warn: 2 cited pages with no archived copy']);
  await page.click('[data-act=stVerify]'); await page.selectOption('#sv-how', 'Geolocated'); await page.fill('#sv-note', 'Sign matches street view, Strandkaien 4'); await page.click('#dlg button[type=submit]');
  await expect(page.locator('.st-claim')).toContainText('Geolocated');

  // it is about Jon Berg: no right of reply yet
  await page.click('[data-act=stAbout]'); await page.check('#dlg input[data-ab=p1]'); await page.click('[data-act=stAboutGo]');
  expect(await issues()).toEqual(['bad: No right of reply for Jon Berg', 'warn: 2 cited pages with no archived copy']);
  await expect(page.locator('.st-check')).toContainText('0 of 1 claim ready');

  // log the request: waiting until the deadline, then counted once he answers
  await page.click('[data-act=stView][data-v=reply]'); await page.click('[data-act=stReplyNew]');
  await page.selectOption('#sr-who', 'p1'); await page.selectOption('#sr-via', 'Email'); await page.click('#dlg button[type=submit]');
  await expect(page.locator('.st-reply')).toContainText(/Waiting until/);
  expect((await issues())[0]).toMatch(/^warn: Waiting for Jon Berg until /);
  await page.click('[data-act=stReplyEdit]'); await page.fill('#sr-resp', 'Mr Berg says he resigned in March 2024.'); await page.click('#dlg button[type=submit]');
  await expect(page.locator('.st-reply')).toContainText('Answered');
  expect(await issues()).toEqual(['warn: 2 cited pages with no archived copy']);
  await page.click('[data-act=stView][data-v=claims]');
  await expect(page.locator('.st-check')).toContainText('1 of 1 claim ready');

  // evidence against it, without a note on why the claim stands
  await page.click('[data-act=stEvAdd][data-v=against]'); await page.check('#dlg input[data-pk="r:r5"]'); await page.click('[data-act=stEvGo]');
  expect(await issues()).toContain('warn: Evidence against it, with no note on why the claim stands');
  noErrors(errors);
});

test('a protected source and the evidence it gave are one source, not two', async ({ page }) => {
  const errors = await open(page, '#/home'); await seed(page);
  const r = await page.evaluate(() => { const c = stOf(theCase('sx')); DB.sources = [{ id: 'src-9', caseId: 'sx', alias: 'Clerk', rel: '', sealed: '{}', created: 1 }];
    const rec = recById('r5'); rec.srcId = 'src-9'; rec.source = 'Protected source · Clerk';
    const cl = { id: 'q', t: 'x', st: 'confirmed', for: ['s:src-9', 'r:r5'], against: [], about: [], note: '' }; c.claims.push(cl);
    const one = stClaimCheck(c, cl, derive('sx')).map(i => i.t); cl.for.push('r:r3'); const two = stClaimCheck(c, cl, derive('sx')).map(i => i.t); return { one, two }; });
  expect(r.one).toContain('Only one independent source');
  expect(r.two).not.toContain('Only one independent source');
  noErrors(errors);
});

test('the Today page reminds of right-of-reply deadlines in the next two days', async ({ page }) => {
  const errors = await open(page, '#/home'); await seed(page);
  await page.evaluate(() => { const c = stOf(theCase('sx')); c.replies.push({ id: 'rr1', who: 'p1', name: '', via: 'Email', at: Date.now(), due: Date.now() + 864e5, claims: [], st: 'waiting', resp: '', respAt: null }); mutate('r'); go('#/today'); });
  await expect(page.locator('#main')).toContainText('right of reply deadline');
  await expect(page.locator('#main')).toContainText('Jon Berg');
  noErrors(errors);
});

test('right of reply: a deadline that has passed counts as the chance given; declined is final', async ({ page }) => {
  const errors = await open(page, '#/home'); await seed(page);
  const r = await page.evaluate(() => { const D = 864e5, n = Date.now();
    return [{ at: n - 5 * D, due: n - 2 * D }, { at: n, due: n + 2 * D }, { at: n, due: n + D, st: 'declined' }, { at: n - D, due: n - 3600e3, st: 'answered', resp: 'x' }].map(x => stReplyState(x).k); });
  expect(r).toEqual(['overdue', 'waiting', 'declined', 'answered']);
  noErrors(errors);
});

test('archived pages: asks once, opens the save in a new tab, finds and keeps the copy', async ({ page, context }) => {
  const errors = await open(page, '#/home'); await seed(page);
  let asked = [];
  await context.route('https://archive.org/wayback/available**', route => { const u = new URL(route.request().url()).searchParams.get('url'); asked.push(u);
    route.fulfill({ contentType: 'application/json', headers: { 'access-control-allow-origin': '*' }, body: JSON.stringify(u.includes('register.example') ? { archived_snapshots: { closest: { available: true, status: '200', timestamp: '20261125093012', url: 'http://web.archive.org/web/20261125093012/https://register.example/harbourline' } } } : { archived_snapshots: {} }) }); });
  await context.route('https://web.archive.org/**', route => route.fulfill({ contentType: 'text/html', body: '<p>saved</p>' }));
  await page.evaluate(() => { go(caseHash('sx', 'story')); UI.stView = 'archive'; renderMain(); });
  await expect(page.locator('.st-arch')).toHaveCount(2);
  const row = page.locator('.st-arch', { hasText: 'register.example' });
  await row.locator('[data-act=stArchSave]').click();
  await expect(page.locator('#dlg')).toContainText('Make a public copy of this page?');
  const [tab] = await Promise.all([context.waitForEvent('page'), page.click('[data-act=confirmOk]')]);
  expect(tab.url()).toBe('https://web.archive.org/save/https://register.example/harbourline');
  await tab.close();
  await expect(row).toContainText('Saving requested');
  await row.locator('[data-act=stArchCheck]').click();
  await expect(row.locator('a.chip')).toHaveAttribute('href', 'https://web.archive.org/web/20261125093012/https://register.example/harbourline');
  await expect(row).toContainText('Archived 2026-11-25');
  // not asked again
  const [t2] = await Promise.all([context.waitForEvent('page'), page.locator('.st-arch', { hasText: 'court.example' }).locator('[data-act=stArchSave]').click()]); await t2.close();
  await page.locator('.st-arch', { hasText: 'court.example' }).locator('[data-act=stArchCheck]').click();
  await expect(page.locator('.st-arch', { hasText: 'court.example' })).toContainText('Not found yet');
  expect(asked.length).toBe(2);
  noErrors(errors);
});

test('saved data with a broken story is cleaned when it is read', async ({ page }) => {
  const errors = await open(page, '#/home');
  const d = await page.evaluate(() => stClean({ cases: [{ id: 'c', claims: [{ id: 'a', t: 'ok', st: 'weird', for: ['r:x', 5] }, { t: 'no id' }, 7], replies: [{ id: 'r', st: 'nope', at: 'x' }] }],
    sources: [{ id: 's', caseId: 'c', alias: 'A', sealed: '{}', rel: 'Z' }, { id: 't', caseId: 'c', alias: '', sealed: 'x' }, { id: 'u' }], srcVault: { salt: 1 },
    archive: { 'https://a.example': { snap: 'javascript:alert(1)', at: 5 }, 'ftp://b': {} } }));
  expect(d.cases[0].claims).toEqual([{ id: 'a', t: 'ok', st: 'unverified', for: ['r:x'], against: [], about: [], note: '', at: 0 }]);
  expect(d.cases[0].replies[0]).toMatchObject({ id: 'r', st: 'waiting', at: null });
  expect(d.sources.map(s => [s.id, s.rel])).toEqual([['s', '']]);
  expect(d.srcVault).toBeUndefined();
  expect(d.archive).toEqual({ 'https://a.example': { req: 0, checked: 0, at: 5 } });
  noErrors(errors);
});
