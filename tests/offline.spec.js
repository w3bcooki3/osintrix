// The offline helper (service worker) only runs over http(s), so this test serves the app itself.
const { test, expect } = require('@playwright/test');
const http = require('http'), fs = require('fs'), path = require('path');
const ROOT = path.resolve(__dirname, '..'), TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.woff2': 'font/woff2', '.json': 'application/json', '.png': 'image/png', '.svg': 'image/svg+xml' };
let server, base, hits = [];
test.beforeAll(async () => { server = http.createServer((req, res) => { const u = decodeURIComponent(req.url.split('?')[0]), f = path.join(ROOT, u === '/' ? 'index.html' : u); hits.push(req.url);
  if (!f.startsWith(ROOT) || !fs.existsSync(f) || fs.statSync(f).isDirectory()) { res.writeHead(404); return res.end(); }
  res.writeHead(200, { 'Content-Type': TYPES[path.extname(f)] || 'application/octet-stream' }); fs.createReadStream(f).pipe(res); });
  await new Promise(r => server.listen(0, '127.0.0.1', r)); base = 'http://127.0.0.1:' + server.address().port + '/'; });
test.afterAll(() => server.close());

test('offline helper: caches the app (not your data), repeat visits skip the network, works with no connection', async ({ page, context }) => {
  const errors = []; page.on('pageerror', e => errors.push(e.message));
  await page.goto(base + 'index.html#/home');
  await expect.poll(() => page.evaluate(() => !!document.querySelector('#sidenav .nv'))).toBe(true);
  await expect.poll(() => page.evaluate(async () => !!(await navigator.serviceWorker.getRegistration()) && !!(await navigator.serviceWorker.ready).active), { timeout: 20000 }).toBe(true);
  const cached = await page.evaluate(async () => { const K = await caches.keys(), c = await caches.open(K[0]), reqs = await c.keys(); return { keys: K, n: reqs.length, foreign: reqs.filter(r => new URL(r.url).origin !== location.origin).length, fonts: reqs.filter(r => /woff2/.test(r.url)).length }; });
  expect(cached.keys).toHaveLength(1); expect(cached.keys[0]).toMatch(/^osintrix-\d+\.\d+-[0-9a-f]{12}$/);
  expect(cached.n).toBeGreaterThan(100); expect(cached.foreign).toBe(0); expect(cached.fonts).toBe(3);
  // a repeat visit: scripts and styles come from the copy, only the page itself is asked for
  await page.reload(); await expect.poll(() => page.evaluate(() => !!navigator.serviceWorker.controller)).toBe(true);
  hits = []; await page.reload();
  await expect.poll(() => page.evaluate(() => !!document.querySelector('#sidenav .nv') && typeof lazyPending === 'function' && lazyPending() === 0), { timeout: 15000 }).toBe(true);
  expect(hits.filter(u => /\.(js|css)\?v=/.test(u))).toEqual([]);
  // no connection at all: the app still opens, with the built-in rules, and new work is kept
  await context.setOffline(true);
  await page.goto(base + 'index.html#/detections');
  await expect.poll(() => page.evaluate(() => !!document.querySelector('#sidenav .nv') && lazyPending() === 0), { timeout: 15000 }).toBe(true);
  expect(await page.evaluate(() => DB.rules.length)).toBeGreaterThan(300);
  await page.evaluate(() => { DB.notes.unshift({ id: uid('n'), caseId: null, title: 'Written offline', text: 'x', color: 'yellow', pinned: false, due: '', created: Date.now(), updated: Date.now() }); flush(); });
  await page.waitForTimeout(400); await page.reload();
  await expect.poll(() => page.evaluate(() => !!(typeof DB !== 'undefined' && DB && DB.notes.some(n => n.title === 'Written offline'))), { timeout: 15000 }).toBe(true);
  await context.setOffline(false);
  expect(errors).toEqual([]);
});

test('offline helper: a new build replaces the old copy', async ({ page }) => {
  await page.goto(base + 'index.html#/home');
  await expect.poll(() => page.evaluate(async () => !!(await navigator.serviceWorker.ready).active), { timeout: 20000 }).toBe(true);
  const sw = fs.readFileSync(path.join(ROOT, 'sw.js'), 'utf8');
  try {
    fs.writeFileSync(path.join(ROOT, 'sw.js'), sw.replace(/const BUILD = '([^']+)'/, "const BUILD = '$1x'"));
    await page.evaluate(async () => { const r = await navigator.serviceWorker.getRegistration(); await r.update(); });
    await expect.poll(() => page.evaluate(async () => (await caches.keys()).join(',')), { timeout: 20000 }).toMatch(/^osintrix-[^,]+x$/);
  } finally { fs.writeFileSync(path.join(ROOT, 'sw.js'), sw); }
});

test('offline helper: Settings can turn it off, which removes the copy', async ({ page }) => {
  await page.addInitScript(() => { try { localStorage.setItem('osintrix:welcomed', '1'); } catch (e) {} });
  await page.goto(base + 'index.html#/settings');
  await expect.poll(() => page.evaluate(async () => !!(await navigator.serviceWorker.ready).active), { timeout: 20000 }).toBe(true);
  await page.click('[data-act=offlineSet][data-v=off]');
  await expect.poll(() => page.evaluate(async () => (await navigator.serviceWorker.getRegistrations()).length + (await caches.keys()).length)).toBe(0);
  await page.reload(); await page.waitForTimeout(2500);
  expect(await page.evaluate(async () => (await navigator.serviceWorker.getRegistrations()).length)).toBe(0);     // stays off
  await page.click('[data-act=offlineSet][data-v=on]');
  await expect.poll(() => page.evaluate(async () => (await navigator.serviceWorker.getRegistrations()).length), { timeout: 15000 }).toBe(1);
});
