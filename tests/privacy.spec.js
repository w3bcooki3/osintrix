// Privacy: what leaves the workspace and where. Discreet mode keeps case names out of the tab, the taskbar, browser
// history and system alerts; no form hands what is typed to the browser's autofill; a shared case file carries no
// protected sources or keys; a stealer log saved to a case never carries a password.
const { test, expect } = require('@playwright/test');
const { open, noErrors, fixture } = require('./helpers');

test('discreet titles and alerts: no case name in the tab or history, a reminder alert says only that one is due', async ({ page }) => {
  const errors = await open(page, '#/case/c-story/story', { legacy: false });
  await expect(page).toHaveTitle(/^Kestrel Dawn · Story/);
  await page.evaluate(() => go('#/security')); await page.click('[data-act=secDisc]');
  await page.evaluate(() => go('#/case/c-story/timeline')); await expect(page).toHaveTitle('Case · Timeline — OSINTrix');
  await page.reload(); await expect.poll(() => page.evaluate(() => typeof DB !== 'undefined' && !!DB && !!document.querySelector('#sidenav .nv'))).toBe(true);
  await expect(page).toHaveTitle('Case · Timeline — OSINTrix');   // remembered
  // a reminder falls due: the system alert carries nothing from the note
  const alert = await page.evaluate(() => { const seen = []; window.Notification = function (t, o) { seen.push([t, o.body, o.tag]); }; window.Notification.permission = 'granted';
    const d = new Date(Date.now() - 60000), p = x => String(x).padStart(2, '0'); DB.notes.push({ id: 'rmx', caseId: 'c-story', text: 'Call Henrik Lund about the shares', title: 'Call Henrik Lund', remind: true, due: d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()), dueTime: p(d.getHours()) + ':' + p(d.getMinutes()), created: 1, updated: 1 });
    noteRemindCheck(); return seen; });
  expect(alert).toEqual([['OSINTrix reminder', 'A reminder is due', 'osintrix-reminder']]);
  // and off again
  await page.evaluate(() => go('#/security')); await page.click('[data-act=secDisc]'); await page.evaluate(() => go('#/case/c-story/timeline'));
  await expect(page).toHaveTitle(/^Kestrel Dawn · Timeline/);
  noErrors(errors);
});

test('no form hands what is typed to the browser’s autofill: dialogs, pages and panels', async ({ page }) => {
  const errors = await open(page, '#/home', { legacy: false });
  const missing = await page.evaluate(async () => { const out = [], wait = () => new Promise(r => setTimeout(r, 80));
    const check = tag => { for (const f of document.querySelectorAll('form')) if (f.getAttribute('autocomplete') !== 'off') out.push(tag + ': ' + (f.dataset.form || f.className || f.id)); };
    for (const [tag, fn] of [['entry', () => entryDlg(null, { type: 'email' })], ['case', () => caseDlg(false)], ['capture', () => openCapture()], ['source', () => stSrcDlg()], ['reply', () => stReplyDlg()], ['note', () => noteDlg && noteDlg()]]) {
      try { fn(); } catch (e) {} await wait(); check(tag); closeDlg(); await wait(); }
    for (const h of ['#/notes', '#/case/c-story/story', '#/case/c-story/questions', '#/security', '#/feeds', '#/queries']) { go(h); await wait(); await wait(); check(h); }
    return { out, forms: document.querySelectorAll('form').length }; });
  expect(missing.out).toEqual([]);
  noErrors(errors);
});

test('a shared case file carries no protected sources, no sources passphrase data and no keys; a stealer log saved to a case carries no password', async ({ page }) => {
  const errors = await open(page, '#/case/c-story/story', { legacy: false });
  await page.evaluate(async () => { await stSetPass('correct horse battery'); DB.sources = [{ id: 'z1', caseId: 'c-story', alias: 'Harbour insider', rel: 'B', sealed: await stSeal({ name: 'Ingrid', contact: 'Signal +47 400 00 000' }), created: 1 }]; mutate('s'); });
  const dl = page.waitForEvent('download'); await page.evaluate(() => clickAct('exportCase', 'c-story'));
  const txt = require('fs').readFileSync(await (await dl).path(), 'utf8');
  expect(txt).not.toMatch(/Harbour insider|Ingrid|Signal \+47|sealed|srcVault/);
  expect(JSON.parse(txt).case.id).toBe('c-story');
  // stealer log: shown masked; even with passwords shown, saving to a case takes hosts and users, never passwords
  await page.evaluate(() => { UI.labTab = 'steal'; go('#/lab'); });
  await page.setInputFiles('#slIn', fixture('forensic/stealer-logs.zip'));
  await expect.poll(() => page.evaluate(() => !!(UI.fxSteal && !UI.fxSteal.busy))).toBe(true);
  await page.click('[data-act=slShow]'); await page.click('[data-act=slSave]');
  const body = await page.locator('#capBody').inputValue();
  expect(body).toMatch(/Stealer log/); for (const pw of ['Winter2025!', 'netflix88', 'gh-Pass-2024', 'Sommer!2023', 'K!aus-2025']) expect(body).not.toContain(pw);
  noErrors(errors);
});
