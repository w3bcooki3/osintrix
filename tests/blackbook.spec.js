// The Blackbook is locked (1.90): its contents ship encrypted, the page asks for the passphrase and decrypts in the browser.
// These tests use a throwaway sample sealed with a throwaway passphrase, so they reveal nothing; the real contents are checked
// by a local-only test next to the readable pack, which is never published.
const { test, expect } = require('@playwright/test');
const fs = require('fs'), path = require('path');
const { open, noErrors } = require('./helpers');
const ROOT = path.resolve(__dirname, '..');

const SAMPLE = { v: 1, sections: [{ id: 'cred', title: 'Sample section', icon: 'key-round', lead: 'A sample.' }], langs: { kql: 'KQL — sample', cli: 'Commands — sample' },
  doctrine: [['Sample principle', 'Body of the sample principle.']], mirror: [], apt: [], underground: [], caught: [], caughtPatterns: [], osint: [],
  plays: [{ id: 'zz-sample', sec: 'cred', t: 'Sample play nobody should see', att: ['T1003.001'], sev: 'high', lens: 'x'.repeat(130), sig: ['a'], logs: 'b', q: { kql: 'SampleTable | take 1' }, fp: 'c', fix: ['d'] }] };
let SEALED;
test.beforeAll(async () => { const { seal } = await import(path.join(ROOT, 'tools', 'seal_blackbook.mjs')); SEALED = seal(JSON.stringify(SAMPLE), 'correct horse battery staple', 2000); });
const lockedApp = async (page, hash = '#/blackbook') => { await page.addInitScript(s => { window.BLACKBOOK_SEALED = s; }, SEALED); return open(page, hash, { legacy: false }); };

test('locked until the passphrase: nothing of the contents before, a wrong passphrase is refused, the right one opens it', async ({ page }) => {
  const errors = await lockedApp(page);
  await expect(page.locator('#bbPass')).toBeVisible();
  await expect(page.locator('#main')).not.toContainText('Sample play');
  expect(await page.evaluate(() => typeof BLACKBOOK)).toBe('undefined');
  await page.fill('#bbPass', 'wrong horse'); await page.press('#bbPass', 'Enter');
  await expect(page.locator('#bbErr')).toHaveText('That passphrase does not open it.');
  await page.fill('#bbPass', 'correct horse battery staple'); await page.click('[data-form=bbUnlock] button[type=submit]');
  await expect(page.locator('.bb h1')).toHaveText('Blackbook');
  await expect(page.locator('#main')).toContainText('Sample play nobody should see');
  await page.reload(); await expect(page.locator('#bbPass')).toBeVisible();                    // not remembered: asks again
  noErrors(errors);
});

test('remember on this device keeps a key that opens it after a reload; Lock forgets it', async ({ page }) => {
  const errors = await lockedApp(page);
  await page.fill('#bbPass', 'correct horse battery staple'); await page.check('#bbRemember'); await page.press('#bbPass', 'Enter');
  await expect(page.locator('#main')).toContainText('Sample play');
  const stored = await page.evaluate(async () => { const k = await IDB.get('bb:key'); return k && { type: k.type, extractable: k.extractable, alg: k.algorithm.name }; });
  expect(stored).toEqual({ type: 'secret', extractable: false, alg: 'AES-GCM' });               // usable, never readable — and no passphrase stored
  expect(await page.evaluate(() => JSON.stringify(localStorage).includes('horse'))).toBe(false);
  await page.reload(); await expect(page.locator('#main')).toContainText('Sample play', { timeout: 15000 });
  await page.click('[data-act=bbLock]'); await expect(page.locator('#bbPass')).toBeVisible();
  await page.reload(); await expect(page.locator('#bbPass')).toBeVisible();
  expect(await page.evaluate(() => IDB.get('bb:key'))).toBeNull();
  noErrors(errors);
});

test('a way back for whoever forgot it: a door at the foot of Tradecraft and a line in the shortcuts list', async ({ page }) => {
  const errors = await lockedApp(page, '#/tradecraft');
  // the page can still be drawing (the Tradecraft data loads on demand): wait for the door, then click it (a click re-finds it if it was redrawn)
  await expect(page.locator('a.tc-door')).toHaveText(/Blackbook\s*Locked/);
  await page.click('a.tc-door'); await expect(page.locator('#bbPass')).toBeVisible();
  await page.evaluate(() => go('#/home')); await page.keyboard.press('?');
  await expect(page.locator('#dlg')).toContainText('then type blackbook');
  noErrors(errors);
});

test('what is published carries no readable Blackbook: the page loads the sealed file, and the offline bundle has no plain contents', async () => {
  const html = fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8');
  expect(html).toContain('js/data/blackbook-sealed.js'); expect(html).not.toContain('blackbook-pack.js');
  const lazy = fs.readFileSync(path.join(ROOT, 'js', 'lazy.js'), 'utf8'); expect(lazy).not.toContain('blackbook-pack.js');
  const ign = fs.readFileSync(path.join(ROOT, '.gitignore'), 'utf8');
  for (const p of ['js/data/blackbook-pack.js', 'tools/blackbook/', 'tools/make_blackbook.py', 'tests/blackbook.local.spec.js']) expect(ign).toContain(p);
  const sealed = fs.readFileSync(path.join(ROOT, 'js', 'data', 'blackbook-sealed.js'), 'utf8');
  expect(sealed).toMatch(/^\/\*[^]*\*\/\nconst BLACKBOOK_SEALED = \{"v":1,"kdf":"PBKDF2-SHA256","iter":600000,/);
  const dist = path.join(ROOT, 'dist', 'osintrix-offline.html');
  if (fs.existsSync(dist)) { const d = fs.readFileSync(dist, 'utf8'); expect(d).not.toContain('const BLACKBOOK = '); expect(d).not.toContain('"doctrine":['); }
});
