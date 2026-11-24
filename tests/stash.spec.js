// Cases kept in a file: an archived case moves out of the browser into one file, checked byte for byte before anything is
// removed; its card and its indicators stay; it comes back from the same file with the same ids, files included.
const { test, expect } = require('@playwright/test');
const { open, noErrors } = require('./helpers');
const fs = require('fs'), path = require('path'), os = require('os');

test('moving an archived case to a file: saved, checked against the wrong file and the right one, removed, still matched, brought back whole', async ({ page }) => {
  const errors = await open(page, '#/cases');
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'stash-'));
  // the Customer portal case, archived, with a file attached to one of its records
  const before = await page.evaluate(async () => {
    const c = theCase('c-portal'); c.status = 'closed';
    const r = DB.records.find(x => x.caseId === 'c-portal'); r.att = (r.att || []).concat({ id: 'fstash1', name: 'note.txt', size: 11, type: 'text/plain' });
    await IDB.set('file:fstash1', await sealBlob(new Blob(['hello stash'], { type: 'text/plain' }))); mutate('x');
    const shared = [...globalEnts().entries()].filter(([k, g]) => g.cases.has('c-portal') && g.cases.has('c-lantern')).map(([k]) => k);
    return { e: DB.entries.filter(x => x.caseId === 'c-portal').map(x => x.id).sort(), r: DB.records.filter(x => x.caseId === 'c-portal').map(x => x.id).sort(),
      l: DB.links.filter(x => x.caseId === 'c-portal').length, n: (DB.notes || []).filter(x => x.caseId === 'c-portal').length, shared, other: DB.entries.length - DB.entries.filter(x => x.caseId === 'c-portal').length };
  });
  expect(before.e.length).toBeGreaterThan(0); expect(before.shared.length).toBeGreaterThan(0);
  // Settings → Storage suggests it
  await page.evaluate(() => go('#/settings'));
  await expect(page.locator('#storage')).toContainText('Archived cases you could move to files (1)');
  await page.locator('#storage [data-act=stashPick]').click();
  await page.locator('#dlg [data-act=stashOne][data-id=c-portal]').click();
  await expect(page.locator('#dlg')).toContainText(`${before.e.length} entries`);
  const [dl] = await Promise.all([page.waitForEvent('download'), page.locator('#dlg [data-act=stashSave]').click()]);
  const file = path.join(tmp, dl.suggestedFilename()); await dl.saveAs(file);
  expect(dl.suggestedFilename()).toMatch(/^customer-portal.*\.osintrix-case\.json$/);
  // a different file is refused, and nothing is removed
  const wrong = path.join(tmp, 'other.json'); fs.writeFileSync(wrong, fs.readFileSync(file, 'utf8').replace('"stored":true', '"stored":true '));
  let [fc] = await Promise.all([page.waitForEvent('filechooser'), page.locator('#dlg [data-act=stashCheck]').click()]); await fc.setFiles(wrong);
  await expect(page.locator('#dlg')).toContainText('That is not the same file'); await expect(page.locator('#dlg')).toContainText('Nothing was removed');
  expect(await page.evaluate(() => DB.entries.filter(x => x.caseId === 'c-portal').length)).toBe(before.e.length);
  [fc] = await Promise.all([page.waitForEvent('filechooser'), page.locator('#dlg [data-act=stashCheck]').click()]); await fc.setFiles(file);
  await expect(page.locator('.toast').last()).toContainText('freed');
  const after = await page.evaluate(async () => ({ e: DB.entries.filter(x => x.caseId === 'c-portal').length, r: DB.records.filter(x => x.caseId === 'c-portal').length, s: theCase('c-portal').stash, f: !!(await IDB.get('file:fstash1')), other: DB.entries.length }));
  expect([after.e, after.r, after.f, after.other]).toEqual([0, 0, false, before.other]);   // only this case went, its file too
  expect(after.s.n).toMatchObject({ entries: before.e.length, records: before.r.length }); expect(after.s.keys).toEqual(expect.arrayContaining(before.shared));
  // the file on disk is the case, whole
  const d = JSON.parse(fs.readFileSync(file, 'utf8')); expect(d.entries.map(x => x.id).sort()).toEqual(before.e); expect(Object.keys(d.files)).toContain('fstash1');
  // it stays stored after a reload; its card says so; its page offers to bring it back, from any tab
  await expect.poll(() => page.evaluate(() => { flush(); return isDirty(); }), { timeout: 15000 }).toBe(false);
  await page.reload(); await expect.poll(() => page.evaluate(() => typeof DB !== 'undefined' && !!DB && !!theCase('c-portal') && !!theCase('c-portal').stash)).toBe(true);
  await page.evaluate(() => go('#/cases'));
  await expect(page.locator('.cs2-card.stashed')).toContainText('In a file since');
  await page.evaluate(() => go(caseHash('c-portal', 'graph')));
  await expect(page.locator('.stash-card')).toContainText('Kept in a file since'); await expect(page.locator('.stash-card')).toContainText(`${before.e.length} entries`);
  // an indicator the two cases shared still says where else it is
  await page.evaluate(() => { DB.active = 'c-lantern'; go(caseHash('c-lantern', 'vault')); }); await expect(page).toHaveURL(/c-lantern\/vault/);
  await page.evaluate(k => select('ent', k), before.shared[0]);
  await expect(page.locator('#insp')).toContainText('Also in a case kept in a file'); await expect(page.locator('#insp')).toContainText('Customer portal');
  // bring it back from the same file: same ids, links, notes and the attached file
  await page.evaluate(() => go(caseHash('c-portal')));
  [fc] = await Promise.all([page.waitForEvent('filechooser'), page.locator('.stash-card [data-act=stashBack]').click()]); await fc.setFiles(file);
  await expect(page.locator('.toast').last()).toContainText('is back');
  const back = await page.evaluate(async () => ({ e: DB.entries.filter(x => x.caseId === 'c-portal').map(x => x.id).sort(), r: DB.records.filter(x => x.caseId === 'c-portal').map(x => x.id).sort(),
    l: DB.links.filter(x => x.caseId === 'c-portal').length, n: (DB.notes || []).filter(x => x.caseId === 'c-portal').length, s: !!theCase('c-portal').stash, f: await (await fileBlob('fstash1')).text() }));
  expect(back).toEqual({ e: before.e, r: before.r, l: before.l, n: before.n, s: false, f: 'hello stash' });
  noErrors(errors);
});
