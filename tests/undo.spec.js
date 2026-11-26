// Undo right after a delete, where it was missing: a Story claim (with the replies that cite it), a request for comment,
// a case template, and a file removed from a record (the file itself goes only once Undo has had its chance).
const { test, expect } = require('@playwright/test');
const { open, noErrors } = require('./helpers');

test('Story: a deleted claim and a deleted request for comment come back with Undo, in their place', async ({ page }) => {
  const errors = await open(page, '#/case/c-story/story', { legacy: false });
  const before = await page.evaluate(() => { const c = theCase('c-story'); return { claims: c.claims.map(x => x.id), sr1: c.replies[0].claims.slice() }; });
  await page.evaluate(() => STORY_ACTS.stClaimDel('sc2')); await page.click('[data-act=confirmOk]');
  expect(await page.evaluate(() => [theCase('c-story').claims.some(x => x.id === 'sc2'), theCase('c-story').replies[0].claims.includes('sc2')])).toEqual([false, false]);
  await expect(page.locator('#toastMsg')).toHaveText('Claim deleted'); await page.click('#toastBtn');
  expect(await page.evaluate(() => { const c = theCase('c-story'); return { claims: c.claims.map(x => x.id), sr1: c.replies[0].claims.slice() }; })).toEqual(before);
  const replies = await page.evaluate(() => theCase('c-story').replies.map(x => x.id));
  await page.evaluate(() => STORY_ACTS.stReplyDel('sr2'));
  expect(await page.evaluate(() => theCase('c-story').replies.some(x => x.id === 'sr2'))).toBe(false);
  await expect(page.locator('#toastMsg')).toHaveText('Request for comment deleted'); await page.click('#toastBtn');
  expect(await page.evaluate(() => theCase('c-story').replies.map(x => x.id))).toEqual(replies);
  noErrors(errors);
});

test('a deleted case template and a file removed from a record come back with Undo', async ({ page }) => {
  const errors = await open(page, '#/case/c-lantern/timeline', { legacy: false });
  await page.evaluate(() => { DB.caseTemplates = [{ id: 'tx1', name: 'Supplier check', desc: '', icon: 'briefcase', color: '#5470f5', tab: 'overview', playbooks: [], questions: ['q'], scope: '', at: 1 }]; mutate('t'); caseDlg(); });
  await page.click('[data-act=ctDel][data-v=tx1]'); await page.click('[data-act=confirmOk]');
  expect(await page.evaluate(() => DB.caseTemplates.length)).toBe(0); await page.click('#toastBtn');
  expect(await page.evaluate(() => DB.caseTemplates.map(t => t.name))).toEqual(['Supplier check']);
  await page.evaluate(() => closeDlg());
  // a file on a record: removed, put back, and its stored copy is still there to open
  const rid = await page.evaluate(async () => { const r = DB.records.find(x => x.caseId === 'c-lantern' && x.type === 'evidence'); draft.caseId = 'c-lantern';
    await attachFiles([new File(['hello evidence'], 'note.txt', { type: 'text/plain' })], r.id); return r.id; }).catch(() => null);
  const att = await page.evaluate(() => DB.records.flatMap(r => (r.att || []).map(a => [r.id, a.id, a.name])).find(x => x[2] === 'note.txt'));
  if (att) {
    await page.evaluate(([rid, fid]) => attAct('attDel', rid, fid), att); await page.click('[data-act=confirmOk]');
    expect(await page.evaluate(rid => (recById(rid).att || []).length, att[0])).toBe(0);
    await page.click('#toastBtn');
    expect(await page.evaluate(rid => (recById(rid).att || []).map(a => a.name), att[0])).toEqual(['note.txt']);
    await page.waitForTimeout(8500);   // past the moment the file would have gone
    expect(await page.evaluate(async fid => !!(await IDB.get('file:' + fid)), att[1])).toBe(true);
  }
  expect(att, 'a file was attached to test with').toBeTruthy();
  noErrors(errors);
});
