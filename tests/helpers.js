// Shared helpers: open the app from disk, fail on any page error or console error.
const path = require('path');
const { expect } = require('@playwright/test');
const APP = 'file://' + path.resolve(__dirname, '..', 'index.html');
const fixture = name => path.resolve(__dirname, 'fixtures', name);

async function open(page, hash = '#/home', opt = {}) {
  const errors = [];
  page.on('pageerror', e => errors.push('pageerror: ' + e.message));
  page.on('console', m => { if (m.type() === 'error' && !/localStorage.*sandboxed|Blocked script execution in 'about:(srcdoc|blank)'|Refused to load the image 'https:|Loading the image 'https:[^']*' violates|^Executing inline event handler violates the following Content Security Policy directive 'script-src /.test(m.text())) errors.push('console: ' + m.text()); });
  await page.addInitScript(() => { try { localStorage.setItem('osintrix:welcomed', '1'); } catch (e) {} });
  // newer Chromium also reports an inline handler (onerror=…) when hostile HTML is only parsed with DOMParser, where nothing
  // loads or runs; the hostile-input tests check separately that nothing runs and that the handler never reaches the page
  // most tests are written against the original demo cases; the OSINT sample case is added only where a test asks for it
  if (!opt.osintSample) await page.context().addInitScript(() => { window.__noOsintSample = true; });
  await page.goto(APP + hash);
  // the app's Content Security Policy blocks eval, so poll with plain evaluate calls instead of waitForFunction
  await expect.poll(() => page.evaluate(() => typeof DB !== 'undefined' && !!DB && !!document.querySelector('#sidenav .nv')), { timeout: 15000 }).toBe(true);
  // the big data files load in the background; tests about their features start once they are in
  await expect.poll(() => page.evaluate(() => typeof lazyPending !== 'function' || lazyPending() === 0), { timeout: 15000 }).toBe(true);
  return errors;
}
async function capture(page, text, caseId) {
  await page.evaluate(() => openCapture());
  if (caseId) await page.selectOption('#capCase', caseId);
  await page.fill('#capBody', text);
  await page.click('[data-act=capSave]');
  await expect(page.locator('#capBody')).toHaveCount(0);   // saved: the capture window has closed
}
/* A time limit that holds on a busy machine: a fixed workload is timed first (about 25 ms when idle), and the
   limit grows with how much slower it ran — at most 6×, so a real slowdown in the app still fails. */
const CAL_MS = 25;
async function budget(page, ms) {
  const runs = [];
  for (let i = 0; i < 3; i++) runs.push(await page.evaluate(() => { const t = performance.now(); let x = 0; const a = [];
    for (let i = 0; i < 200000; i++) { x += Math.sqrt(i) * Math.sin(i); if (i % 50 === 0) a.push({ i, s: 'v' + i }); }
    JSON.parse(JSON.stringify(a)); const m = new Map(); for (let i = 0; i < 60000; i++) m.set('k' + (i % 5000), i); return performance.now() - t + (x > Infinity ? 1 : 0); }));
  runs.sort((a, b) => a - b);
  return ms * Math.min(6, Math.max(1, runs[1] / CAL_MS));
}
const noErrors = errors => expect(errors, errors.join('\n')).toEqual([]);
module.exports = { APP, fixture, open, capture, noErrors, budget };
