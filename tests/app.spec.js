// End-to-end checks for OSINTrix. Every test opens the real app from disk, like a user would.
const { test, expect } = require('@playwright/test');
const { open, capture, fixture, noErrors } = require('./helpers');

const ROUTES = ['#/home', '#/cases', '#/case/c-lantern/overview', '#/case/c-lantern/vault', '#/case/c-lantern/entities', '#/case/c-lantern/timeline',
  '#/case/c-lantern/graph', '#/case/c-lab/map', '#/case/c-lantern/questions', '#/case/c-lantern/report', '#/toolbox', '#/queries', '#/detections',
  '#/notes', '#/playbooks', '#/ctf', '#/lab', '#/decoder', '#/feeds', '#/watch', '#/entities', '#/reference', '#/trash', '#/security', '#/help', '#/settings'];

test('every screen draws without errors @phone', async ({ page }) => {
  const errors = await open(page);
  for (const r of ROUTES) {
    await page.evaluate(h => { location.hash = h; }, r);
    await page.waitForTimeout(150);
    await expect(page.locator('#main')).not.toContainText('This screen failed to draw');
  }
  noErrors(errors);
});

test('extracts indicators, including obfuscated and structured ones', async ({ page }) => {
  const errors = await open(page);
  const ents = await page.evaluate(() => extractRich('mail john [at] proton [dot] me, phone: +44 20 7946 0958, 2001:db8::1, https://x.com/n1ghtlamp, T1059.001, IBAN GB82 WEST 1234 5698 7654 32').map(e => e.k + '=' + e.v));
  for (const want of ['email=john@proton.me', 'phone=+442079460958', 'ipv6=2001:db8::1', 'social=x.com/n1ghtlamp', 'handle=@n1ghtlamp', 'ttp=T1059.001', 'iban=GB82WEST12345698765432'])
    expect(ents).toContain(want);
  noErrors(errors);
});

test('parses a FortiGate line into fields and filters by them', async ({ page }) => {
  const errors = await open(page, '#/case/c-portal/timeline');
  await capture(page, 'date=2019-05-10 time=11:50:48 logid="0001000014" type="traffic" vd="vdom1" srcip=172.16.200.254 srcport=62024 dstip=172.16.200.2 dstport=443 proto=6 action="server-rst" service="HTTPS" sentbyte=1247 rcvdbyte=1719');
  const rec = await page.evaluate(() => { const r = DB.records[DB.records.length - 1]; return { title: r.title, ts: new Date(r.ts).toISOString() }; });
  expect(rec.title).toContain('172.16.200.254:62024 → 172.16.200.2:443');
  expect(rec.ts).toBe('2019-05-10T11:50:48.000Z');
  await page.fill('#tlq', 'dst.port:443'); await page.waitForTimeout(400);
  await expect(page.locator('.ev')).toHaveCount(1);
  noErrors(errors);
});

test('imports a CSV log with column mapping', async ({ page }) => {
  const errors = await open(page, '#/case/c-portal/timeline');
  await page.evaluate(() => openCapture());
  const [fc] = await Promise.all([page.waitForEvent('filechooser'), page.click('[data-act=capLog]')]);
  await fc.setFiles(fixture('fortigate-40.csv'));
  await expect(page.locator('#lmPrev .lmr')).toHaveCount(5);
  await page.click('[data-act=logGo]'); await page.waitForTimeout(600);
  expect(await page.evaluate(() => DB.records.filter(r => r.tags.includes('imported')).length)).toBe(40);
  noErrors(errors);
});

test('builds graph relations stated in evidence, and only suggests the rest', async ({ page }) => {
  const errors = await open(page, '#/case/c-portal/timeline');
  await page.evaluate(() => { theCase('c-portal').autoGraph = true; });
  await capture(page, 'Domain Name: lamp-support.example\nRegistrant Email: n1ghtlamp@proton.me\nlamp-support.example resolves to 198.51.100.77');
  const links = await page.evaluate(() => DB.links.filter(l => l.caseId === 'c-portal' && l.auto).map(l => l.label));
  expect(links).toContain('registered by');
  expect(links).toContain('resolves to');
  noErrors(errors);
});

test('encrypts the workspace, locks on reload and unlocks with the passphrase', async ({ page }) => {
  const errors = await open(page, '#/security');
  await page.click('[data-act=secOn]');
  await page.fill('#pw1', 'correct horse battery'); await page.fill('#pw2', 'correct horse battery');
  await page.click('form[data-form=pass] button[type=submit]');
  await expect.poll(() => page.evaluate(() => (localStorage.getItem(STORE_KEY) || '').slice(0, 30))).toContain('osintrix-aes-gcm');
  const before = await page.evaluate(() => DB.records.length);
  await page.reload();
  await expect(page.locator('#unlockP')).toBeVisible();
  await page.fill('#unlockP', 'wrong one'); await page.keyboard.press('Enter');
  await expect(page.locator('#unlockE')).toContainText('does not open');
  await page.fill('#unlockP', 'correct horse battery'); await page.keyboard.press('Enter');
  await expect.poll(() => page.evaluate(() => typeof DB !== 'undefined' && DB && DB.records.length)).toBe(before);
  noErrors(errors);
});

test('audit chain detects edits and custody reports detect tampering', async ({ page }) => {
  const errors = await open(page, '#/home');
  await capture(page, 'evidence for the chain 203.0.113.9');
  const res = await page.evaluate(async () => {
    const m = await custodyManifest(DB.active); const ok = await custodyVerify(m);
    const bad = JSON.parse(JSON.stringify(m)); bad.records[0].sha256 = '0'.repeat(64); const tampered = await custodyVerify(bad);
    await auditQ; DB.audit.entries[0].what = 'rewritten history'; const chain = await auditVerify(DB.audit.entries, DB.audit.base);
    return { ok: ok.every(x => x[0]), tampered: tampered[0][0], chain: chain.ok };
  });
  expect(res).toEqual({ ok: true, tampered: false, chain: false });
  noErrors(errors);
});

test('archives a saved web page without running its scripts', async ({ page }) => {
  const errors = await open(page, '#/case/c-lantern/timeline');
  let dialogs = 0; page.on('dialog', d => { dialogs++; d.dismiss(); });
  await page.evaluate(() => openCapture());
  const [fc] = await Promise.all([page.waitForEvent('filechooser'), page.click('[data-act=capFiles]')]);
  await fc.setFiles(fixture('forum-post.mhtml'));
  await expect.poll(() => page.evaluate(() => DB.records[DB.records.length - 1].title)).toContain('Web page: Lamp loader v2');
  await page.evaluate(() => { const r = DB.records[DB.records.length - 1]; return attAct('attOpen', r.id, r.att[0].id); });
  await expect(page.locator('.safeframe')).toBeVisible();
  expect(dialogs).toBe(0);
  noErrors(errors);
});

test('photo GPS lands on the case map', async ({ page }) => {
  const errors = await open(page, '#/case/c-lab/timeline');
  await page.evaluate(() => openCapture());
  const [fc] = await Promise.all([page.waitForEvent('filechooser'), page.click('[data-act=capFiles]')]);
  await fc.setFiles(fixture('photo-gps.jpg'));
  await page.waitForTimeout(800);
  await page.evaluate(() => { location.hash = '#/case/c-lab/map'; });
  await expect.poll(() => page.evaluate(() => UI.mapData && UI.mapData.pts.some(p => Math.abs(p.la - 48.8584) < 0.01))).toBe(true);
  noErrors(errors);
});

test('hypothesis board ranks by evidence against', async ({ page }) => {
  const errors = await open(page, '#/case/c-lantern/questions');
  const top = await page.evaluate(() => achScore(theCase('c-lantern').ach).rank[0].h.t);
  expect(top).toContain('Lamp loader');
  noErrors(errors);
});

test('reads a packet capture: DNS, HTTP, TLS SNI/JA3, cleartext logins, beacons', async ({ page }) => {
  const errors = await open(page, '#/lab');
  await page.click('[data-act=labTab][data-v=pcap]');
  for (const f of ['sample.pcap', 'sample.pcapng']) {
    await page.setInputFiles('#pcIn', fixture(f));
    await expect.poll(() => page.evaluate(() => !!(UI.pcap && UI.pcap.flows))).toBe(true);
    const A = await page.evaluate(() => ({ n: UI.pcap.n, dns: UI.pcap.dns.map(d => d.name), http: UI.pcap.http.map(h => h.url), sni: UI.pcap.tls.map(t => t.sni), ja3: UI.pcap.tls[0].ja3,
      creds: UI.pcap.creds.map(c => c.proto + ':' + c.user), find: UI.pcap.findings.map(f => f.title), flags: UI.pcap.flags }));
    expect(A.n).toBe(77);
    expect(A.dns).toContain('updates.lamp-loader.xyz');
    expect(A.http).toContain('http://updates.lamp-loader.xyz/files/update.exe');
    expect(A.sni).toContain('login.microsoftonline.com');
    expect(A.ja3).toBe('a1055821978a49a49eb2ce46cd0ba418');
    expect(A.creds).toEqual(expect.arrayContaining(['HTTP:jdoe', 'HTTP form:jdoe', 'FTP:backup']));
    expect(A.find.join('|')).toMatch(/beacon/);
    expect(A.find.join('|')).toMatch(/several MAC/);
    expect(A.flags).toContain('flag{pcap_follow_the_stream}');
    await page.click('[data-act=pcClear]');
  }
  noErrors(errors);
});

test('opens a Chrome history database with decoded times and deleted-row recovery', async ({ page }) => {
  const errors = await open(page, '#/lab');
  await page.click('[data-act=labTab][data-v=sqlite]');
  await page.setInputFiles('#sqIn', fixture('History'));
  await expect.poll(() => page.evaluate(() => !!(UI.sql && UI.sql.db)), { timeout: 15000 }).toBe(true);
  const S = await page.evaluate(() => ({ arts: UI.sql.arts.map(a => a.id), free: UI.sql.free.found.some(x => /harbour warehouse/.test(x.text)) }));
  expect(S.arts).toEqual(expect.arrayContaining(['chrome-hist', 'chrome-dl', 'chrome-search']));
  expect(S.free).toBe(true);
  await expect(page.locator('.sq-time').first()).toHaveText(/^2026-09-21 14:28:20/);
  await page.click('[data-act=sqView][data-v=sql]');
  await page.fill('#sqSql', 'DELETE FROM urls');
  await page.click('[data-act=sqRun]');
  expect(await page.evaluate(() => UI.sql.db.exec('SELECT count(*) FROM urls')[0].values[0][0])).toBe(4);
  noErrors(errors);
});

test('validates input inline and refuses duplicate names', async ({ page }) => {
  const errors = await open(page, '#/cases');
  await page.evaluate(() => clickAct('newCase'));
  await page.click('#dlg button[type=submit]');
  await expect(page.locator('#dlg .ferr')).toHaveText(/required/);
  const name = await page.evaluate(() => DB.cases[0].name);
  await page.fill('#cName', '  ' + name.toUpperCase() + ' ');
  await page.click('#dlg button[type=submit]');
  await expect(page.locator('#dlg .ferr')).toHaveText(/already exists/);
  await page.evaluate(() => closeDlg());
  await page.evaluate(() => clickAct('toolAdd'));
  await page.fill('#tName', await page.evaluate(() => DB.tools[0].name));
  await page.fill('#tUrl', 'https://example.org/');
  await page.click('#dlg button[type=submit]');
  await expect(page.locator('#dlg .ferr')).toHaveText(/already in the toolbox/);
  await page.evaluate(() => closeDlg());
  const names = await page.evaluate(() => { const p = DB.playbooks[0]; clickAct('pbDup', p.id); clickAct('pbDup', p.id); return DB.playbooks.filter(x => x.name.startsWith(p.name)).map(x => x.name); });
  expect(names).toEqual(expect.arrayContaining([expect.stringMatching(/\(copy\)$/), expect.stringMatching(/\(copy 2\)$/)]));
  const codes = await page.evaluate(() => DB.cases.map(c => c.code));
  expect(new Set(codes).size).toBe(codes.length);
  noErrors(errors);
});

test('clicks every control on the main screens without an error', async ({ page }) => {
  test.setTimeout(240_000);
  const errors = await open(page);
  const SKIP = new Set(['exportAll', 'resetDemo', 'freshStart', 'removeSample', 'importAll', 'importCase', 'secOn', 'secLock', 'secOff', 'secChange', 'capFiles', 'capLog', 'capWeb', 'attAdd', 'attOpen', 'attDl', 'rsAll', 'printReport']);
  for (const r of ['#/home', '#/case/c-lantern/overview', '#/case/c-lantern/entities', '#/case/c-lantern/timeline', '#/case/c-lantern/graph', '#/case/c-lab/map', '#/case/c-lantern/questions', '#/toolbox', '#/lab', '#/security']) {
    await page.evaluate(h => { location.hash = h; renderMain(); }, r); await page.waitForTimeout(200);
    const acts = await page.evaluate(() => [...document.querySelectorAll('#main [data-act]')].map((e, i) => [i, e.dataset.act]));
    for (const [i, a] of acts.slice(0, 60)) {
      if (SKIP.has(a)) continue;
      await page.evaluate(([h, i, a]) => { if (location.hash !== h) location.hash = h; renderMain(); const e = document.querySelectorAll('#main [data-act]')[i]; if (e && e.dataset.act === a) e.click(); }, [r, i, a]);
      await page.waitForTimeout(40); await page.keyboard.press('Escape');
    }
  }
  noErrors(errors);
});
