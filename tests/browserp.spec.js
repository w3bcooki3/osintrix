// Browser profile reader. The fixtures are built with Python's sqlite3 on Chrome's and Firefox's own table layouts.
// The Chrome History is copied the way it sits on disk while the browser runs: the main file plus a History-wal that
// holds the last three visits, a search and a download (Python reading main + wal sees 11 visits, the main file alone 8).
const { test, expect } = require('@playwright/test');
const { open, fixture, noErrors } = require('./helpers');
const path = require('path');

async function load(page, sel, files) {
  await page.evaluate(() => { UI.labTab = 'brow'; UI.brP = null; renderMain(); });
  await page.setInputFiles(sel, files);
  await expect.poll(() => page.evaluate(() => !!(UI.brP && !UI.brP.busy)), { timeout: 30000 }).toBe(true);
}
const tab = async (page, t) => page.click(`[data-act=brTab][data-v=${t}]`);

test('a Chrome profile ZIP: the account, what only the -wal held, hiding searches, downloads and where they came from, logins without passwords', async ({ page }) => {
  const errors = await open(page, '#/lab');
  await load(page, '#brIn', fixture('browser/chrome-jdoe.zip'));
  const head = page.locator('#main section.card').first();
  await expect(head).toContainText('profile “Work”');
  await expect(head).toContainText('jdoe@acme.example (John Doe) · work account of acme.example');
  await expect(head).toContainText('C:\\Users\\jdoe\\Downloads');
  await expect(head).toContainText('3 visits, 1 download and 1 search were only in History-wal');
  await expect(head).toContainText('“wipe free space windows”');
  await expect(head).toContainText('mega.nz (2)');
  await expect(head).toContainText('Private or throwaway mail: proton.me — with a saved login');
  await expect(head).toContainText('VeraCrypt Setup 1.26.7.exe — opened');
  await expect(head).toContainText('Tab Saver (loaded unpacked)');
  await expect(head).toContainText('Hola VPN - The Website Unblocker (proxy, webRequest, <all_urls>)');
  await expect(head).toContainText('older history may have been cleared');
  // the timeline: newest first, the subframe left out, filters work
  const body = page.locator('#brBody');
  await expect(body).toContainText('28 events');
  await expect(body.locator('.br-ev').first()).toContainText('payroll_2025.xlsx');
  await expect(body).not.toContainText('ads.example');
  await page.click('[data-act=brKind][data-v=visit]');
  await page.click('[data-act=brKind][data-v=form]');
  await page.fill('#brQ', 'mega');
  await expect(body).toContainText('1 event,');                                  // visits and form entries off: only “meg” typed in the address bar
  await expect(body.locator('.br-ev')).toContainText('Typed “meg” in the address bar');
  await page.fill('#brQ', '');
  // searches and typed text
  await tab(page, 'search');
  await expect(body.locator('.br-row.hot')).toHaveCount(2);
  await expect(body).toContainText('protonmail sign up');
  await expect(body).toContainText('meg');
  // downloads with the full chain of addresses and the page they were on
  await tab(page, 'dl');
  const vc = body.locator('.br-dl:has-text("VeraCrypt")');
  await expect(vc).toContainText('https://launchpadlibrarian.net/680123/VeraCrypt%20Setup%201.26.7.exe');
  await expect(vc).toContainText('https://www.veracrypt.fr/en/Downloads.html');
  await expect(vc).toContainText('opened');
  // logins: user names, never the password; the card without its number; a recovery code masked
  await tab(page, 'login');
  await expect(body).toContainText('jd.exit2025@proton.me');
  await expect(body).toContainText('212×');
  await expect(body).toContainText('Revolut · expires 09/2027');
  await expect(body).toContainText('7••••4 (6 characters)');
  await expect(body).not.toContainText('739204');
  const all = await page.evaluate(() => JSON.stringify(UI.brP, (k, v) => v instanceof Map ? [...v] : v));
  expect(all).not.toContain('SECRETPASSWORD');
  expect(all).not.toContain('739204');
  await tab(page, 'ext');
  await expect(body.locator('.br-row.hot')).toContainText('Tab Saver');
  await expect(body).not.toContainText('Google Docs Offline');                    // built-in component
  // into the case: one record with the indicators, and the events through the timeline import
  const before = await page.evaluate(() => DB.records.length);
  await page.click('[data-act=brSave]');
  await expect.poll(() => page.evaluate(() => DB.records.length)).toBe(before + 1);
  const rec = await page.evaluate(() => DB.records[DB.records.length - 1]);
  expect(rec.ents.map(e => e.v)).toEqual(expect.arrayContaining(['jd.exit2025@proton.me', 'jdoe@acme.example', 'https://intranet.acme.example/hr/payroll_2025.xlsx']));
  expect(rec.body).toContain('wipe free space windows');
  expect(rec.body).not.toContain('739204');
  await page.click('[data-act=brSend]');
  await expect(page.locator('.modal, dialog, [role=dialog]').filter({ hasText: 'Send the browser timeline' }).first()).toBeVisible();
  noErrors(errors);
});

test('a Firefox profile ZIP and loose Chrome files picked by hand', async ({ page }) => {
  const errors = await open(page, '#/lab');
  await load(page, '#brIn', fixture('browser/firefox-mk.zip'));
  const head = page.locator('#main section.card').first();
  await expect(head).toContainText('Firefox');
  await expect(head).toContainText('Private or throwaway mail: tuta.io');
  await expect(head).toContainText('tor-browser-windows-x86_64-portable-14.0.7.exe');
  await tab(page, 'search');
  await expect(page.locator('#brBody')).toContainText('buy usdt without kyc');
  await expect(page.locator('#brBody')).toContainText('monero to usdt swap');
  await tab(page, 'login');
  await expect(page.locator('#brBody')).toContainText('web.telegram.org');
  await expect(page.locator('#brBody')).toContainText('TQ5Wn3kF8bJXhW1xY9mZ4pRt7vS2aD6cLe');
  expect(await page.evaluate(() => UI.brP.iocs.map(e => e.v))).toContain('mk.trader@tuta.io');
  // just History without its -wal: the newest activity is not there, and nothing claims it is
  const dir = fixture('browser/User Data/Default');
  await load(page, '#brIn', [path.join(dir, 'History')]);
  expect(await page.evaluate(() => UI.brP.visits)).toBe(7);
  await load(page, '#brIn', [path.join(dir, 'History'), path.join(dir, 'History-wal'), path.join(dir, 'Login Data')]);
  expect(await page.evaluate(() => UI.brP.visits)).toBe(10);
  expect(await page.evaluate(() => UI.brP.logins.length)).toBe(2);
  // the whole "User Data" folder through the folder picker
  await load(page, '#brDir', fixture('browser/User Data'));
  expect(await page.evaluate(() => [UI.brP.files.length, UI.brP.profile.accounts[0].email, UI.brP.visits])).toEqual([8, 'jdoe@acme.example', 10]);
  noErrors(errors);
});
