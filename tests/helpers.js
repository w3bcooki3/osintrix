// Shared helpers: open the app from disk, fail on any page error or console error.
const path = require('path');
const { expect } = require('@playwright/test');
const APP = 'file://' + path.resolve(__dirname, '..', 'index.html');
const fixture = name => path.resolve(__dirname, 'fixtures', name);

async function open(page, hash = '#/home') {
  const errors = [];
  page.on('pageerror', e => errors.push('pageerror: ' + e.message));
  page.on('console', m => { if (m.type() === 'error' && !/localStorage.*sandboxed|Blocked script execution in 'about:(srcdoc|blank)'|Refused to load the image 'https:/.test(m.text())) errors.push('console: ' + m.text()); });
  await page.addInitScript(() => { try { localStorage.setItem('osintrix:welcomed', '1'); } catch (e) {} });
  await page.goto(APP + hash);
  // the app's Content Security Policy blocks eval, so poll with plain evaluate calls instead of waitForFunction
  await expect.poll(() => page.evaluate(() => typeof DB !== 'undefined' && !!DB && !!document.querySelector('#sidenav .nv')), { timeout: 15000 }).toBe(true);
  return errors;
}
async function capture(page, text, caseId) {
  await page.evaluate(() => openCapture());
  if (caseId) await page.selectOption('#capCase', caseId);
  await page.fill('#capBody', text);
  await page.click('[data-act=capSave]');
  await page.waitForTimeout(400);
}
const noErrors = errors => expect(errors, errors.join('\n')).toEqual([]);
module.exports = { APP, fixture, open, capture, noErrors };
