// Shared helpers: open the app from disk, fail on any page error or console error.
const path = require('path');
const { expect } = require('@playwright/test');
const APP = 'file://' + path.resolve(__dirname, '..', 'index.html');
const fixture = name => path.resolve(__dirname, 'fixtures', name);
const LEGACY = require('./fixtures/legacy-cases.json');

async function open(page, hash = '#/home', opt = {}) {
  const errors = [];
  page.on('pageerror', e => errors.push('pageerror: ' + e.message));
  page.on('console', m => { if (m.type() === 'error' && !/localStorage.*sandboxed|Blocked script execution in 'about:(srcdoc|blank)'|Refused to load the image 'https:|Loading the image 'https:[^']*' violates|^Executing inline event handler violates the following Content Security Policy directive 'script-src /.test(m.text())) errors.push('console: ' + m.text()); });
  await page.addInitScript(() => { try { localStorage.setItem('osintrix:welcomed', '1'); } catch (e) {} });
  // newer Chromium also reports an inline handler (onerror=…) when hostile HTML is only parsed with DOMParser, where nothing
  // loads or runs; the hostile-input tests check separately that nothing runs and that the handler never reaches the page
  // most tests are written against the original demo cases; the OSINT sample case is added only where a test asks for it
  if (!opt.osintSample) await page.context().addInitScript(() => { window.__noOsintSample = true; });
  // since 1.87 the app ships two sample cases (Op Lantern, Kestrel Dawn). Many tests need a second case with shared
  // indicators and a case with a geotagged photo: the two sample cases from before 1.87 come back as test fixtures
  // (tests/fixtures/legacy-cases.json) unless a test says { legacy: false }.
  const legacy = opt.legacy !== false, toLegacy = legacy && /c-(portal|lab)\b/.test(hash);
  await page.goto(APP + (toLegacy ? '#/home' : hash));
  // the app's Content Security Policy blocks eval, so poll with plain evaluate calls instead of waitForFunction
  await expect.poll(() => page.evaluate(() => typeof DB !== 'undefined' && !!DB && !!document.querySelector('#sidenav .nv')), { timeout: 15000 }).toBe(true);
  // the big data files load in the background; tests about their features start once they are in
  await expect.poll(() => page.evaluate(() => typeof lazyPending !== 'function' || lazyPending() === 0), { timeout: 15000 }).toBe(true);
  if (legacy) {
    await page.evaluate(L => {
      if (DB.cases.some(c => c.id === 'c-portal')) return;
      const T = Date.parse('2026-09-15T12:00:00Z');
      for (const c of L.cases) DB.cases.push({ ...c, created: Date.parse(c.created), updated: Date.parse(c.updated), sample: true });
      for (const [id, caseId, type, t, host, source, title, body, tags] of L.records) DB.records.push({ id, caseId, type, tsRaw: t || '', tsZone: t ? 'explicit' : '', ts: t ? E.parseTime(t) : null, host, source, title, body, tags: tags || [],
        ents: E.extract(body), answer: L.answers[id] || '', addedBy: 'You', addedAt: t ? E.parseTime(t) + 240000 : Date.parse('2026-09-14T09:40:00Z'), hash: '' });
      L.entries.forEach(([id, caseId, type, fields, x], i) => { const e = { id, caseId, type, fields: { ...fields }, priority: x.priority || 'medium', starred: !!x.starred, tags: x.tags || [], notes: x.notes || '', src: x.src || '',
        created: T - (20 + i) * 3600e3, pos: L.pos[id] ? { x: L.pos[id][0] * .84, y: L.pos[id][1] * .84 } : null }; DB.entries.push(e);
        if (x.verdict) { const k = entryKey(e); if (k) DB.verdicts[k] = x.verdict; else e.verdict = x.verdict; } });
      L.links.forEach(([a, b, label, conf, src], i) => DB.links.push({ id: 'll' + i, caseId: DB.entries.find(e => e.id === a).caseId, a, b, label, conf, src }));
      for (const n of L.notes) if (Array.isArray(DB.notes) && !DB.notes.some(x => x.id === n.id)) DB.notes.push({ ...n, created: T - 180000e3, updated: T - 180000e3, sample: true });
      if (DB.ctf) for (const ch of DB.ctf.chals || []) if (ch.name === 'Harbour lights') ch.caseId = 'c-lab';
      if (typeof sampleOsintElsewhere === 'function') sampleOsintElsewhere();   // the OSINT sample's tie to the portal case, when it is in
      if (typeof hashRecords === 'function') hashRecords(); if (typeof ensurePositions === 'function') ensurePositions(); mutate('test fixtures'); renderAll();
    }, LEGACY);
    if (toLegacy) { await page.evaluate(h => go(h), hash); await page.waitForTimeout(150); }
  }
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
/* Every change written to storage? Wait for that before a reload: a write still on its way when the page goes away
   can land too late for the next page (on a busy machine, a large workspace is written to IndexedDB in the background). */
async function settled(page) {
  await expect.poll(() => page.evaluate(() => typeof isDirty === 'function' && !isDirty()), { timeout: 15000 }).toBe(true);
}

module.exports = { APP, fixture, open, capture, noErrors, budget, settled };
