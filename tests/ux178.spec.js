// v1.78 — URLs keep the case of their path, Patterns joins the regex builder and the log parsers, recent searches on
// the Decoder, Certificates and Cloud guide, and a notice with copyable details when something on a page fails.
const { test, expect } = require('@playwright/test');
const { open, noErrors } = require('./helpers');

test('a URL keeps the case of its path and query; scheme and host are lowercased; one entity for both spellings of the host', async ({ page }) => {
  const errors = await open(page, '#/home');
  const r = await page.evaluate(() => {
    const ex = E.extract('payload at HTTPS://Files.Example.COM/s/AbC123XyZ?Token=Q9wE and https://files.example.com/s/AbC123XyZ?Token=Q9wE');
    const urls = ex.filter(e => e.k === 'url').map(e => e.v), doms = ex.filter(e => e.k === 'domain').map(e => e.v);
    const ent = { id: 'x', caseId: DB.active, type: 'url', fields: { url: 'HTTPS://Files.Example.COM/s/AbC123XyZ?Token=Q9wE' } };
    return { urls, doms, key: entryKey(ent), other: E.extract('https://files.example.com/s/abc123xyz').filter(e => e.k === 'url').map(e => e.v) };
  });
  expect(r.urls).toEqual(['https://files.example.com/s/AbC123XyZ?Token=Q9wE']);
  expect(r.doms).toEqual(['files.example.com']);
  expect(r.key).toBe('url:https://files.example.com/s/AbC123XyZ?Token=Q9wE');
  expect(r.other).toEqual(['https://files.example.com/s/abc123xyz']);   // a different path is a different URL
  noErrors(errors);
});

test('URLs saved lowercase by 1.77 get their case back from the record, and their verdicts and watches follow; feeds still match', async ({ page }) => {
  const errors = await open(page, '#/home');
  const r = await page.evaluate(async () => {
    const real = 'https://drive.example.net/file/d/1AbCdEfGh/view?usp=Sharing', low = real.toLowerCase();
    const mk = (body, ents) => ({ id: uid('r'), caseId: DB.active, type: 'evidence', title: 'Share link', body, tsRaw: '', tsZone: 'explicit', ts: Date.now(), source: '', host: '', tags: [], ents, answer: '', addedBy: 'You', addedAt: Date.now(), hash: '' });
    const a = mk('sent ' + real + ' to finance', [{ k: 'url', v: low }, { k: 'domain', v: 'drive.example.net' }]);
    const b = mk('defanged hxxps://evil[.]example/Pay', [{ k: 'url', v: 'https://evil.example/pay' }]);   // not in its text verbatim: left alone
    DB.records.push(a, b);
    DB.verdicts['url:' + low] = 'malicious'; DB.watch = DB.watch || {}; DB.watch['url:' + low] = { at: 1 }; DB.verdicts['url:https://evil.example/pay'] = 'suspicious';
    const n = migrateUrlCase(), again = migrateUrlCase(); mutate('test');
    // a feed saved before 1.78 holds the URL lowercased: it still matches the record's URL
    await ctiLoad(); CTI.iocs.push({ id: uid('ioc'), k: 'url', v: low, srcs: ['old feed'], tlp: 'clear', conf: null, tags: [], first: 1, last: 1, exp: 0, threat: '', desc: '', ref: '', added: 1 }); ctiIocIndex();
    const hit = ctiIocHits().find(h => h.ioc.v === low);
    return { v: a.ents[0].v, bv: b.ents[0].v, n, again, verdict: DB.verdicts['url:' + real], gone: !(('url:' + low) in DB.verdicts), watch: !!DB.watch['url:' + real],
      keepB: DB.verdicts['url:https://evil.example/pay'], hit: hit ? hit.ent.id : null, look: !!CTI.iocIx.get('url:' + real) };
  });
  expect(r.v).toBe('https://drive.example.net/file/d/1AbCdEfGh/view?usp=Sharing');
  expect(r.bv).toBe('https://evil.example/pay');
  expect(r.n).toBe(3); expect(r.again).toBe(0);
  expect(r.verdict).toBe('malicious'); expect(r.gone).toBe(true); expect(r.watch).toBe(true); expect(r.keepB).toBe('suspicious');
  expect(r.hit).toBe('url:https://drive.example.net/file/d/1AbCdEfGh/view?usp=Sharing');
  expect(r.look).toBe(true);
  noErrors(errors);
});

test('Regex: one page with the pattern builder and the log parsers; not in the Forensics kit; the old Log parsers tab opens it', async ({ page }) => {
  const errors = await open(page, '#/regex');
  await expect(page.locator('.pat-tabs [role=tab]')).toHaveText([/Build a pattern/, /Log parsers/]);
  await expect(page.locator('.pat-tabs [data-v=build]')).toHaveAttribute('aria-selected', 'true');
  await page.click('.pat-tabs [data-v=logs]');
  await expect(page.locator('.pat-tabs [data-v=logs]')).toHaveAttribute('aria-selected', 'true');
  await expect(page.locator('[data-act=lpNew]').first()).toBeVisible();
  await page.click('.pat-tabs [data-v=build]');
  await expect(page.locator('[data-act=rxDemo]').first()).toBeVisible();
  // from the kit's old tab
  await page.evaluate(() => { go('#/lab'); });
  // the Forensics kit no longer lists a log parser; the Regex page is in the sidebar
  await expect(page.locator('.labtabs')).toBeVisible(); expect(await page.evaluate(() => LAB_TABS.some(t => t[0] === 'logs') || /log parser/i.test(document.querySelector('.labtabs').textContent))).toBe(false);
  await expect(page.locator('#side a[href="#/regex"]')).toContainText('Regex');
  // an old link or bookmark to the kit's Log parsers tab
  await page.evaluate(() => { const b = document.createElement('button'); b.dataset.act = 'labTab'; b.dataset.v = 'logs'; document.querySelector('main, #main, body').appendChild(b); b.click(); });
  await expect(page).toHaveURL(/#\/regex/); await expect(page.locator('.pat-tabs [data-v=logs]')).toHaveAttribute('aria-selected', 'true');
  await expect(page.locator('h1')).toContainText('Regex');
  noErrors(errors);
});

test('Decoder, Certificates and Cloud guide remember recent input only when tool history is on', async ({ page }) => {
  const errors = await open(page, '#/decoder');
  await expect(page.locator('.lab-strip')).toHaveCount(0);                      // off by default: nothing kept, nothing shown
  await page.fill('#decIn', 'aGVsbG8gd29ybGQ='); await page.dispatchEvent('#decIn', 'change');
  expect(await page.evaluate(() => !!(DB.work && DB.work.hist && DB.work.hist.decoder))).toBe(false);
  await page.evaluate(() => { DB.prefs.toolHist = 'on'; renderMain(); });
  await page.fill('#decIn', 'aGVsbG8gd29ybGQ='); await page.dispatchEvent('#decIn', 'change');
  await page.evaluate(() => { UI.decIn = ''; renderMain(); });
  const chip = page.locator('.lab-strip [data-act=labHist]');
  await expect(chip).toHaveCount(1); await expect(page.locator('.lab-strip [data-act=labToolClear]')).toHaveCount(0);   // the page has its own Clear
  await chip.click(); await expect(page.locator('#decIn')).toHaveValue('aGVsbG8gd29ybGQ=');

  await page.evaluate(() => go('#/cloud')); await page.evaluate(() => { UI.cloudTab = 'guide'; renderMain(); });
  await page.fill('#cgQ', 'metadata'); await page.dispatchEvent('#cgQ', 'change');
  await page.evaluate(() => { UI.cgQ = ''; renderMain(); });
  await page.locator('.lab-strip [data-act=labHist]').click(); await expect(page.locator('#cgQ')).toHaveValue('metadata');

  await page.evaluate(() => go('#/certs')); await page.evaluate(() => { const S = cxS(); S.tab = 'ct'; renderMain(); });
  await page.fill('#cxCtDom', 'example.org'); await page.dispatchEvent('#cxCtDom', 'change');
  await page.evaluate(() => { cxS().ctDom = ''; renderMain(); });
  await page.locator('.lab-strip [data-act=labHist]').click(); await expect(page.locator('#cxCtDom')).toHaveValue('example.org');
  // turning it off forgets everything
  await page.evaluate(() => actFor('toolHist')(null, 'off'));
  expect(await page.evaluate(() => DB.work.hist)).toBeUndefined();
  noErrors(errors);
});

test('an error on a page shows a notice whose “Copy details” copies what failed, where, and on which page', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  const errors = await open(page, '#/home');
  await page.evaluate(() => setTimeout(() => { throw new Error('probe failure 178'); }, 0));
  const t = page.locator('.toast', { hasText: 'Something went wrong on this page' });
  await expect(t).toBeVisible();
  await t.locator('button', { hasText: 'Copy details' }).click();
  const clip = await page.evaluate(() => navigator.clipboard.readText());
  expect(clip).toContain('probe failure 178'); expect(clip).toContain('"page": "home"');
  expect(errors.filter(e => !/probe failure 178/.test(e))).toEqual([]);
});
