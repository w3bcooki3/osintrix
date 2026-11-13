// End-to-end checks for OSINTrix. Every test opens the real app from disk, like a user would.
const { test, expect } = require('@playwright/test');
const { open, capture, fixture, noErrors, APP } = require('./helpers');

const ROUTES = ['#/home', '#/cases', '#/cloud', '#/pad', '#/whatsnew', '#/case/c-lantern/overview', '#/case/c-lantern/vault', '#/case/c-lantern/entities', '#/case/c-lantern/timeline',
  '#/case/c-lantern/graph', '#/case/c-lab/map', '#/case/c-lantern/questions', '#/case/c-lantern/report', '#/toolbox', '#/queries', '#/detections',
  '#/notes', '#/notebook', '#/certs', '#/playbooks', '#/ctf', '#/lab', '#/decoder', '#/feeds', '#/watch', '#/entities', '#/reference', '#/trash', '#/security', '#/help', '#/settings'];

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
    const m = await custodyManifest(DB.active); const ok = (await custodyVerify(m)).res;
    const bad = JSON.parse(JSON.stringify(m)); bad.records[0].sha256 = '0'.repeat(64); const tampered = (await custodyVerify(bad)).res;
    await auditQ; DB.audit.entries[0].what = 'rewritten history'; const chain = await auditVerify(DB.audit.entries, DB.audit.base);
    return { ok: ok.every(x => x[0] === true), tampered: tampered[0][0], chain: chain.ok };
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

test('auto-decode finds layered and uncommon encodings', async ({ page }) => {
  const errors = await open(page, '#/decoder');
  const run = v => page.evaluate(async x => { const s = await autoDecode(x); return s.length ? s[s.length - 1][1] : ''; }, v);
  expect(await run('aGVsbG8gYW5hbHlzdCwgZmxhZ3thdXRvfQ==')).toBe('hello analyst, flag{auto}');
  expect(await run('YUdWc2JHOGdZVzVoYkhsemRDd2dabXhoWjN0aGRYUnZmUT09')).toBe('hello analyst, flag{auto}');
  expect(await run('68656c6c6f20776f726c64')).toBe('hello world');
  expect(await run('NBSWY3DPEB3W64TMMQ======')).toBe('hello world');
  expect(await run('StV1DL6CwTryKyV')).toBe('hello world');
  expect(await run('01101000 01101001 00100001')).toBe('hi!');
  expect(await run('104 105 33 32 104 105')).toBe('hi! hi');
  expect(await run('synt{ebg_guvegrra}')).toBe('flag{rot_thirteen}');
  expect(await run('.... . .-.. .-.. --- / .-- --- .-. .-.. -..')).toBe('HELLO WORLD');
  expect(await run('powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA')).toContain('IEX (New-Object');
  expect(await run('just a normal sentence')).toBe('');
  noErrors(errors);
});

test('clicks every control on the main screens without an error', async ({ page }) => {
  test.setTimeout(240_000);
  const errors = await open(page);
  const SKIP = new Set(['exportAll', 'resetDemo', 'freshStart', 'removeSample', 'importAll', 'importCase', 'secOn', 'secLock', 'secOff', 'secChange', 'capFiles', 'capLog', 'capWeb', 'attAdd', 'attOpen', 'attDl', 'rsAll', 'printReport', 'helpWelcome', 'refFind', 'pbGo', 'wuImport', 'placesKml', 'placesCsv', 'wuExportAll', 'wuExport', 'nbImport', 'nbAttach', 'nbMediaDl', 'nbLinkGo']);
  for (let r of ['#/home', '#/case/c-lantern/overview', '#/case/c-lantern/entities', '#/case/c-lantern/timeline', '#/case/c-lantern/graph', '#/case/c-lab/map', '#/case/c-lantern/questions', '#/toolbox', '#/lab', '#/security', '#/reference', '#/playbooks', '#/help', '#/cloud', '#/whatsnew', '#/pad', '#/ctf', '#/detections', '#/notebook', 'nb-page']) {
    const nbp = r === 'nb-page'; if (nbp) r = '#/notebook';
    await page.evaluate(([h, nbp]) => { if (h === '#/notebook'){ UI.nbView = nbp ? 'page' : 'lib'; UI.nbPage = DB.nb.pages[2].id; } location.hash = h; renderMain(); }, [r, nbp]); await page.waitForTimeout(200);
    const acts = await page.evaluate(() => [...document.querySelectorAll('#main [data-act]')].map((e, i) => [i, e.dataset.act]));
    for (const [i, a] of acts.slice(0, 60)) {
      if (SKIP.has(a)) continue;
      await page.evaluate(([h, i, a, nbp]) => { closeDlg(); if (h === '#/notebook'){ UI.nbView = nbp ? 'page' : 'lib'; if (!nbPage(UI.nbPage)) UI.nbPage = DB.nb.pages[0].id; } if (location.hash !== h) location.hash = h; renderMain(); const e = document.querySelectorAll('#main [data-act]')[i]; if (e && e.dataset.act === a) e.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true })); }, [r, i, a, nbp]);
      await page.waitForTimeout(40); await page.keyboard.press('Escape');
    }
  }
  noErrors(errors);
});

test('cloud scanner flags IaC and logs, and sends to a case', async ({ page }) => {
  await open(page, "#/cloud");
  // run the Terraform sample
  await page.evaluate(() => CLOUD_ACTS.cloudSample(0, 'Terraform (open SG + public RDS)'));
  await expect(page.locator('.cld-f')).not.toHaveCount(0);
  const n = await page.locator('.cld-f').count();
  expect(n).toBeGreaterThanOrEqual(3);
  // critical SG finding present
  await expect(page.locator('.cld-f.critical').first()).toContainText(/0\.0\.0\.0\/0/);
  // log hunting on CloudTrail sample flags StopLogging
  await page.evaluate(() => CLOUD_ACTS.cloudSample(0, 'CloudTrail (suspicious burst)'));
  await expect(page.locator('.cld-ev')).not.toHaveCount(0);
  await expect(page.locator('.cld-ev', { hasText: 'StopLogging' })).toHaveCount(1);
  // guide copy action is wired (no throw)
  await page.evaluate(() => { UI.cloudTab = 'guide'; renderMain(); });
  await expect(page.locator('.cg-it')).not.toHaveCount(0);
  const list = await page.evaluateHandle(() => document.querySelector('.cg-list'));
  await page.locator('.cg-it').nth(2).click();
  await expect(page.locator('#cgDetail .cg-cmd')).not.toHaveCount(0);
  expect(await page.evaluate(l => l.isConnected, list)).toBe(true);
});

test('scratchpad detects indicators and groups them into lanes', async ({ page }) => {
  await open(page, "#/pad");
  await page.fill('#padText', 'src=203.0.113.9 dport=4444 proto=TCP\nc2 update-lamp.test CVE-2024-3400 sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  await page.waitForTimeout(400);
  await expect(page.locator('.pad-lane')).not.toHaveCount(0);
  await expect(page.locator('.pad-chip', { hasText: '4444' })).toHaveCount(1);
  await expect(page.locator('.pad-chip', { hasText: 'TCP' })).toHaveCount(1);
  await expect(page.locator('.pad-chip', { hasText: 'CVE-2024-3400' })).toHaveCount(1);
  await page.locator('.pad-chip').first().click();
  await expect(page.locator('#padBulk')).toBeVisible();
});

/* ---------- release blockers: data safety and imports ---------- */
const seedStore = async (page, raw) => page.evaluate(async raw => {
  if (typeof TABS !== 'undefined') TABS.writer = false;   // stop this page saving over the seeded data as it unloads
  localStorage.setItem('osintrix-poc:v4', raw);
  await new Promise(res => { const r = indexedDB.open('osintrix', 1); r.onupgradeneeded = () => r.result.createObjectStore('kv');
    r.onsuccess = () => { const tx = r.result.transaction('kv', 'readwrite'); tx.objectStore('kv').put(raw, 'osintrix-poc:v4'); tx.oncomplete = () => { r.result.close(); res(); }; }; });
  await new Promise(res => setTimeout(res, 250));          // Chromium commits localStorage asynchronously; let it land before the reload
}, raw);
const readStore = page => page.evaluate(() => new Promise(res => { const r = indexedDB.open('osintrix', 1);
  r.onsuccess = () => { const q = r.result.transaction('kv').objectStore('kv').get('osintrix-poc:v4'); q.onsuccess = () => res([q.result, localStorage.getItem('osintrix-poc:v4')]); }; }));

test('never overwrites a workspace it cannot read', async ({ page }) => {
  await open(page);
  const newer = JSON.stringify({ v: 3, marker: 'keep-me', cases: [] });
  await seedStore(page, newer);
  await page.reload();
  await expect(page.locator('.recover')).toBeVisible();
  await expect(page.locator('.recover')).toContainText('newer version');
  await page.waitForTimeout(800);
  const [idb, ls] = await readStore(page);
  // the stored copies are never replaced. (Chromium sometimes hasn't committed a localStorage write made just
  // before a reload, so the second copy can be missing; it must never hold anything else.)
  expect(idb).toBe(newer); expect([newer, null]).toContain(ls);
  // damaged data: same, and starting fresh keeps the old copy aside
  await seedStore(page, '{"v":2,"cases":[');
  await page.reload();
  await expect(page.locator('.recover')).toContainText('damaged');
  await page.click('#recFresh');
  await expect.poll(() => page.evaluate(() => typeof DB !== 'undefined' && !!DB && DB.cases.length > 0)).toBe(true);
  const kept = await page.evaluate(() => new Promise(res => { const r = indexedDB.open('osintrix', 1);
    r.onsuccess = () => { const q = r.result.transaction('kv').objectStore('kv').getAllKeys(); q.onsuccess = () => res(q.result.filter(k => String(k).includes(':kept:')).length); }; }));
  expect(kept).toBeGreaterThan(0);
});

test('a second tab is read-only until it takes over', async ({ page, context }) => {
  const errors = await open(page);
  const two = await context.newPage();
  await two.goto(page.url());
  await expect(two.locator('#rotab')).toBeVisible();
  await two.evaluate(() => { DB.cases[0].name = 'Edited in tab two'; mutate('rename'); flush(); });
  await page.waitForTimeout(500);
  expect((await readStore(page))[1]).not.toContain('Edited in tab two');
  // tab one saves; tab two follows
  await page.evaluate(() => { DB.cases[0].name = 'Edited in tab one'; mutate('rename'); flush(); });
  await expect.poll(() => two.evaluate(() => DB.cases[0].name)).toBe('Edited in tab one');
  // take over: tab two becomes the writer, tab one turns read-only
  await two.click('#rotabGo');
  await expect.poll(() => two.evaluate(() => TABS.writer && !document.getElementById('rotab'))).toBe(true);
  await expect.poll(() => page.evaluate(() => !TABS.writer && !!document.getElementById('rotab'))).toBe(true);
  expect(await two.evaluate(() => DB.cases[0].name)).toBe('Edited in tab one');
  // the new writer's saves reach storage, the old one's do not
  await two.evaluate(() => { DB.cases[0].name = 'Saved by tab two'; mutate('rename'); flush(); });
  await page.evaluate(() => { DB.cases[0].name = 'Ignored from tab one'; mutate('rename'); flush(); });
  await expect.poll(async () => (await readStore(two))[1]).toContain('Saved by tab two');
  expect((await readStore(two))[1]).not.toContain('Ignored from tab one');
  noErrors(errors);
});

test('imports are checked: bad IDs are refused, markup in names stays text, files never overwrite', async ({ page }) => {
  const errors = await open(page, '#/case/c-lantern/timeline');
  const feed = (page, obj) => page.evaluate(t => { window.pickFile = (a, cb) => cb(t); }, JSON.stringify(obj));
  // a backup whose IDs try to break out of an attribute
  const bad = await page.evaluate(() => { const d = JSON.parse(JSON.stringify(DB)); d.tools[0].id = '"><a href=https://evil.example style=position:fixed;inset:0>'; return d; });
  await feed(page, bad); await page.evaluate(() => clickAct('importAll'));
  await expect(page.locator('#toast')).toContainText('was not imported');
  expect(await page.evaluate(() => DB.tools.some(t => t.id.includes('"')))).toBe(false);
  // a case file with markup in its code and name, and an attachment ID that already exists here
  const fid = await page.evaluate(async () => { const m = await storeFile(new File(['original bytes'], 'keep.txt', { type: 'text/plain' })); DB.records[0].att = [m]; return m.id; });
  await feed(page, { format: 'osintrix-case', case: { id: 'c1', name: 'Imported <img src=x onerror=alert(1)>', code: '<b>X</b>' }, entries: [{ id: 'v1', type: 'ip', fields: { ip: '192.0.2.9' } }],
    records: [{ id: 'r1', title: 'With file', body: '', att: [{ id: fid, name: 'evil.pdf', type: 'application/pdf', size: 4, sha256: '' }] }], files: { [fid]: 'data:text/html,<script>alert(1)</script>' } });
  await page.evaluate(() => importCase()); await page.waitForTimeout(600);
  expect(await page.evaluate(async fid => (await fileBlob(fid)).text(), fid)).toBe('original bytes');
  const att = await page.evaluate(() => DB.records.find(r => r.title === 'With file').att[0].id);
  expect(att).not.toBe(fid);
  // the context menu shows the code as text
  await page.evaluate(() => { const c = DB.cases[DB.cases.length - 1]; showMenu(10, 10, [{ label: 'x', fn: () => {} }], ico('folder', 'sm') + esc(c.code) + c.name); });
  expect(await page.locator('#ctx .ctx-title img, #ctx .ctx-title b').count()).toBe(0);
  await expect(page.locator('#ctx .ctx-title')).toContainText('<b>X</b>');
  // the "PDF" that is really HTML is not opened as a page
  expect(await page.evaluate(async att => sniffKind(await fileBlob(att)), att)).toBe('markup');
  noErrors(errors);
});

test('extractor stays fast on hostile input', async ({ page }) => {
  await open(page);
  const ms = await page.evaluate(() => { const t = performance.now(); Engine.extract('a.'.repeat(50000)); Engine.extract('1.'.repeat(50000)); Engine.extract('a-'.repeat(50000) + '@'); return performance.now() - t; });
  expect(ms).toBeLessThan(1500);
});

test('the audit chain and custody reports cannot be forged by editing data', async ({ page }) => {
  const errors = await open(page, '#/home');
  await capture(page, 'first record 198.51.100.1'); await capture(page, 'second record 198.51.100.2');
  const r = await page.evaluate(async () => {
    await auditQ; const A = DB.audit;
    // forge: drop an entry, then recompute every link with plain SHA-256, as an editor of the stored JSON would
    const forged = JSON.parse(JSON.stringify(A.entries)); forged.splice(1, 1); let prev = A.base || 'genesis';
    for (const [k, e] of forged.entries()) { e.i = k; e.d = await sha256hex(`${e.i}|${e.at}|${e.c}|${e.what}`); e.h = await sha256hex(prev + '|' + e.d); delete e.m; prev = e.h; }
    const forgedLooksPlain = (await auditVerify(forged, A.base)).ok;
    // keyed entries rewritten without the key
    const keyed = JSON.parse(JSON.stringify(A.entries)); keyed.splice(1, 1); prev = A.base || 'genesis';
    for (const [k, e] of keyed.entries()) { e.i = k; e.d = await sha256hex(`${e.i}|${e.at}|${e.c}|${e.what}`); e.h = await sha256hex(prev + '|' + e.d); prev = e.h; }
    const keyedForged = (await auditVerify(keyed, A.base)).ok;
    const real = await auditVerify(A.entries, A.base);
    // a report re-signed with a fresh key: valid signature, but not trusted
    const m = await custodyManifest(DB.active); m.records[0].title = 'edited';
    const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']); const jwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
    m.key = { alg: 'ECDSA-P256-SHA256', jwk: { kty: 'EC', crv: jwk.crv, x: jwk.x, y: jwk.y }, fingerprint: await keyFp(jwk) };
    const { signature, ...body } = m; m.signature = b64e8(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, kp.privateKey, new TextEncoder().encode(canon(body))));
    const resigned = await custodyVerify(m);
    // the private key is not in the workspace or a backup
    let saved = null; window.download = (n, text) => { saved = text; }; await exportEverything(false);
    return { real: real.ok, keyedEntries: real.keyed > 0, keyedForged, forgedPlainHasNoKeyedEntries: forgedLooksPlain,
      resignedFirst: resigned.res[0][0], privInDB: JSON.stringify(DB).includes('"d":"') && !!(DB.security.sign || {}).priv, privInBackup: /"priv"/.test(saved || '') };
  });
  expect(r.forgedPlainHasNoKeyedEntries).toBe(false); expect(r.real).toBe(true); expect(r.keyedEntries).toBe(true); expect(r.keyedForged).toBe(false);
  expect(r.resignedFirst).toBe('warn'); expect(r.privInDB).toBe(false); expect(r.privInBackup).toBe(false);
  noErrors(errors);
});

test('large cases save in pieces and open on the board without freezing', async ({ page }) => {
  test.setTimeout(90000);
  const errors = await open(page, '#/home');
  const r = await page.evaluate(async () => {
    const c = DB.active || DB.cases[0].id, t = Date.now(), ip = i => `10.${(i >> 16) & 255}.${(i >> 8) & 255}.${i & 255}`;
    for (let i = 0; i < 2400; i++) DB.records.push({ id: 'big' + i, caseId: c, type: 'note', at: t - i * 1000, created: t, title: 'host ' + ip(i), text: `seen ${ip(i)} with ${ip(i + 1)}`, ents: [{ k: 'ipv4', v: ip(i) }, { k: 'ipv4', v: ip(i + 1) }], tags: [] });
    flush(); await new Promise(res => setTimeout(res, 400));
    let core = await IDB.get(STORE_KEY); if (typeof core === 'string') core = JSON.parse(core); const chunks = core && core.__rc ? core.__rc.n : 0;
    DB.records.find(x => x.id === 'big5').title = 'changed'; const t0 = performance.now(); flush(); const ms = performance.now() - t0;
    await new Promise(res => setTimeout(res, 400));
    const back = await loadAll(), n = back.records.length, changed = back.records.find(x => x.id === 'big5').title;
    const types = ['ip', 'domain', 'email', 'username', 'person'];
    for (let i = 0; i < 2000; i++) { const ty = types[i % 5]; DB.entries.push({ id: 'g' + i, caseId: c, type: ty, fields: { [TYPES[ty].fields[0][0]]: 'n' + i + '.example' }, priority: 'medium', tags: [], notes: '', created: t }); }
    for (let i = 1; i < 2000; i++) DB.links.push({ id: 'gl' + i, caseId: c, a: 'g' + i, b: 'g' + Math.floor(i / 3), label: 'rel', conf: 2 });
    cache = {}; DB.active = c; location.hash = '#/home'; await new Promise(res => setTimeout(res, 200));
    const g0 = performance.now(); location.hash = '#/case/' + c + '/graph'; for (let i = 0; i < 750 && !(cy && cy.nodes().length > 1000); i++) await new Promise(res => setTimeout(res, 20));
    return { chunks, ms, n, changed, graphMs: performance.now() - g0, nodes: cy ? cy.nodes().length : 0 };
  });
  expect(r.chunks).toBeGreaterThan(1); expect(r.ms).toBeLessThan(250); expect(r.n).toBeGreaterThan(2400); expect(r.changed).toBe('changed');
  expect(r.nodes).toBeGreaterThan(1000); expect(r.graphMs).toBeLessThan(15000);
  noErrors(errors);
});

test('CTF: work log, flag check, write-up and cheatsheets', async ({ page }) => {
  const errors = await open(page, '#/ctf');
  await page.evaluate(() => { const c = DB.ctf.chals.find(x => x.name === 'Hidden layers'); UI.ctfSel = c.id; renderMain(); });
  await page.click('[data-act=ctfKind][data-v=ok]'); await page.fill('#ctfLogIn', 'Data after IEND\n$ binwalk -e layers.png'); await page.click('[data-act=ctfLogAdd]');
  await expect(page.locator('.att')).toHaveCount(1); await expect(page.locator('.att .code')).toContainText('binwalk -e layers.png');
  await page.fill('#ctfFlagIn', 'nope'); await expect(page.locator('.flagin')).toHaveClass(/bad/);
  await page.fill('#ctfFlagIn', 'FLAG{ok}'); await expect(page.locator('.flagin')).toHaveClass(/ok/);
  await page.click('[data-act=ctfSolve]');
  expect(await page.evaluate(() => DB.ctf.chals.find(x => x.name === 'Hidden layers').status)).toBe('solved');
  await page.click('[data-act=wuFromChal]'); await page.click('form[data-form=wu] button[type=submit]');
  await expect(page.locator('.reader .md-code')).toContainText('binwalk');
  await page.evaluate(() => { UI.ctfTab = 'cheats'; UI.csCat = 'web'; renderMain(); });
  await page.fill('[data-csvar=target]', '10.10.11.42');
  await expect(page.locator('.csr code').first()).toContainText('10.10.11.42');
  await page.fill('#csq', 'steghide'); await expect(page.locator('.cs-blk')).not.toHaveCount(0);
  await page.click('[data-act=ctfCheat][data-v=stego]'); await page.click('[data-act=csFm][data-v="0"]');
  expect(await page.evaluate(() => DB.ctf.fm.stego)).toEqual([0]);
  noErrors(errors);
});

test('places, reference and packs load', async ({ page }) => {
  const errors = await open(page, '#/case/c-lab/map');
  await expect(page.locator('.pcard')).toHaveCount(1);
  await expect(page.locator('.pcard .plink', { hasText: 'Google Maps' })).toHaveAttribute('href', /google\.com\/maps\/search\/\?api=1&query=59\.9/);
  const n = await page.evaluate(() => ({ ref: Object.values(refAll().secs).reduce((a, S) => a + S.rows.length, 0), pb: (ensurePlaybooks(), DB.playbooks.length), cg: cgAll().reduce((a, g) => a + g.cards.length, 0), rules: (ensureRules(), DB.rules.length) }));
  expect(n.ref).toBeGreaterThan(1000); expect(n.pb).toBeGreaterThan(50); expect(n.cg).toBeGreaterThan(90);
  await page.evaluate(() => { location.hash = '#/reference'; UI.refQ = 'AADSTS50126'; renderMain(); });
  await expect(page.locator('.rf2-r').first()).toContainText('50126');
  noErrors(errors);
});

test('no serious accessibility problems on the main screens, light and dark', async ({ page }) => {
  test.setTimeout(300_000);
  const AxeBuilder = require('@axe-core/playwright').default;
  const errors = await open(page, '#/home');
  const routes = ['#/home', '#/case/c-lantern/graph', '#/case/c-lantern/timeline', '#/case/c-lantern/entities', '#/case/c-lab/map', '#/case/c-lantern/questions', '#/case/c-lantern/overview', '#/case/c-lantern/vault',
    '#/toolbox', '#/queries', '#/lab', '#/cloud', '#/ctf', '#/reference', '#/playbooks', '#/feeds', '#/detections', '#/notes', '#/security', '#/whatsnew', '#/help', '#/settings', 'ctf-ws', 'ctf-cheats', 'ctf-wu', 'nb-page', 'nb-export', '#/notebook', 'cx-dec', 'cx-chain', 'cx-csr', 'cx-guide', 'welcome'];
  const found = [];
  for (const theme of ['light', 'dark']) {
    await page.evaluate(t => { DB.prefs.theme = t; applyPrefs(); renderAll(); }, theme);
    for (const r of routes) {
      await page.evaluate(r => { closeWelcome();
        if (r === 'welcome') return showWelcome();
        if (r === 'nb-page' || r === 'nb-export'){ closeDlg(); UI.nbPage = DB.nb.pages.find(p => p.title === 'Kerberoasting').id; UI.nbView = 'page'; location.hash = '#/notebook'; setTimeout(() => { renderMain(); if (r === 'nb-export') nbExportDlg('page', UI.nbPage); }, 30); return; }
        if (r === '#/notebook'){ closeDlg(); UI.nbView = 'lib'; }
        if (r.startsWith('cx-')){ closeDlg(); location.hash = '#/certs'; setTimeout(() => { renderMain(); const t = r.slice(3); if (t === 'guide') CX_ACTS.cxCh(null, 'inside'); else CX_ACTS.cxSample(null, t === 'dec' ? 'phish' : t); }, 30); return; }
        if (r.startsWith('ctf-')) { location.hash = '#/ctf'; UI.ctfTab = r === 'ctf-ws' ? 'board' : r === 'ctf-cheats' ? 'cheats' : 'writeups'; UI.ctfSel = r === 'ctf-ws' ? DB.ctf.chals[0].id : null; setTimeout(renderMain, 30); return; }
        location.hash = r; }, r);
      await page.waitForTimeout(450);
      const res = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).analyze();
      for (const v of res.violations) if (['serious', 'critical'].includes(v.impact)) for (const n of v.nodes.slice(0, 3)) found.push(`${theme} ${r} ${v.id}: ${n.target.join(' ')}`);
    }
  }
  expect(found, found.join('\n')).toEqual([]);
  noErrors(errors.filter(e => !/Connecting to 'file:.*violates the following Content Security Policy directive: "connect-src/.test(e)));   // axe reads the stylesheets; the app's CSP rightly blocks that
});

test('Windows event logs (.evtx) are read, checked against Sigma rules and imported', async ({ page }) => {
  test.setTimeout(120_000);
  const errors = await open(page, '#/case/c-lantern/timeline');
  // the reader on its own: a synthetic Security log spread over several chunks (tests/fixtures/make_evtx.py)
  const sec = await page.evaluate(async b64 => { const u = Uint8Array.from(atob(b64), c => c.charCodeAt(0)); const r = EVTX.parse(u.buffer);
    return { n: r.events.length, chunks: r.chunks, bad: r.badRecords, add: r.events.find(x => x.EventID === '4732'), clr: r.events.find(x => x.EventID === '1102'), fail: r.events.filter(x => x.EventID === '4625').length }; },
    require('fs').readFileSync(fixture('security-sample.evtx')).toString('base64'));
  expect(sec).toMatchObject({ n: 321, bad: 0, fail: 12 }); expect(sec.chunks).toBeGreaterThan(1);
  expect(sec.add).toMatchObject({ Channel: 'Security', Computer: 'WS-FIN-07.corp.example', TargetUserName: 'Administrators', MemberSid: 'S-1-5-21-1234567890-2345678901-3456789012-1001', TimeCreated: '2026-09-14T08:47:52.000Z' });
  expect(sec.clr).toMatchObject({ UserDataType: 'LogFileCleared', SubjectUserName: 'svc_backup' });
  // the whole flow with a synthetic Sysmon log
  await page.evaluate(() => openCapture());
  const [chooser] = await Promise.all([page.waitForEvent('filechooser'), page.click('[data-act=capLog]')]);
  await chooser.setFiles(fixture('sysmon-sample.evtx'));
  await expect(page.locator('[data-act=evtxGo]:not([disabled])')).toBeVisible({ timeout: 60_000 });
  await expect(page.locator('#evtxDlg')).toContainText('22');
  const sig = await page.evaluate(() => Object.fromEntries(EVTXIMP.sig.per.map(([r, n]) => [r.title, n])));
  expect(sig['Certutil Used to Download a File']).toBe(1);
  expect(sig['Registry Run Key Persistence']).toBe(1);
  expect(sig['LSASS Credential Dump Attempt']).toBe(1);                     // the dumper, not Windows or the antivirus reading LSASS
  expect(sig['Remote Thread Created in LSASS']).toBeUndefined();            // log sources are respected: process access is not a remote thread
  await page.click('[data-act=evtxGo]');
  await expect.poll(() => page.evaluate(() => DB.records.filter(r => (r.tags || []).includes('evtx')).length)).toBe(22);
  const rec = await page.evaluate(() => { const r = DB.records.find(x => (x.tags || []).includes('evtx') && /certutil/.test(x.body) && /EventID=1 /.test(x.body)); return { title: r.title, host: r.host, ts: r.ts, det: (r.det || []).map(d => d.title) }; });
  expect(rec.title).toMatch(/^1 · Process created/); expect(rec.host).toBe('WS-FIN-07.corp.example'); expect(rec.ts).toBe(Date.parse('2026-09-14T08:57:40Z'));
  expect(rec.det).toContain('Certutil Used to Download a File');
  await expect(page.locator('.ev .evdet').first()).toBeVisible();
  noErrors(errors);
});

test('an improved built-in rule replaces an unedited old copy, but never one you edited', async ({ page }) => {
  const errors = await open(page, '#/detections');
  const r = await page.evaluate(() => {
    const seed = RULE_SEED.find(x => x.id === 'sig-2026-cred-010'), old = seed.replaces[0];
    DB.rules = DB.rules.filter(x => x.id !== 'sig-2026-cred-010' && x.id !== 'pk-sig-001');
    DB.rules.push({ ...ruleFromSeed(seed), code: old });                                                  // an old, unedited copy
    const mine = { ...ruleFromSeed(RULE_PACK[0]), code: 'my own edit' }; DB.rules.push(mine);             // an edited copy (no replaces entry matches)
    RULES_MERGED = false; ensureRules();
    return { upgraded: DB.rules.find(x => x.id === 'sig-2026-cred-010').code.includes('filter_system'), kept: DB.rules.find(x => x.id === 'pk-sig-001').code };
  });
  expect(r.upgraded).toBe(true); expect(r.kept).toBe('my own edit');
  noErrors(errors);
});

test('notebook: write, paste a picture, flashcards, review, export to Word and Markdown, import back', async ({ page }) => {
  const fs = require('fs');
  const errors = await open(page, '#/notebook');
  await expect(page.locator('.nbk')).toHaveCount(3);
  await page.evaluate(() => NB_ACTS.nbPageNew(DB.nb.sections.find(s => s.name === 'Kerberos attacks').id));
  await page.keyboard.type('Delegation abuse'); await page.keyboard.press('Enter');
  await page.keyboard.type('## Unconstrained'); await page.keyboard.press('Enter');
  await page.keyboard.type('- first'); await page.keyboard.press('Enter'); await page.keyboard.type('second'); await page.keyboard.press('Enter'); await page.keyboard.press('Enter');
  await page.keyboard.type('``` '); await page.keyboard.type('Get-ADComputer -Filter *'); await page.keyboard.press('Enter'); await page.keyboard.type('next line'); await page.keyboard.press('Enter'); await page.keyboard.press('Enter');
  await page.keyboard.type('Q: What does unconstrained delegation store?'); await page.keyboard.press('Enter'); await page.keyboard.type('A: The TGTs of users who connect.');
  await page.evaluate(() => { const bin = Uint8Array.from(atob(NB_DEMO_SHOT.data.split(',')[1]), c => c.charCodeAt(0)), dt = new DataTransfer(); dt.items.add(new File([bin], 'shot.png', { type: 'image/png' }));
    $('nbEd').dispatchEvent(new ClipboardEvent('paste', { clipboardData: dt, bubbles: true, cancelable: true })); });
  await page.waitForTimeout(300);
  await page.evaluate(() => { const dt = new DataTransfer(); dt.setData('text/html', '<p><span style="font-weight:700">Bold</span> <a href="javascript:alert(1)">bad</a><img src=x onerror=alert(1)><script>alert(1)</script></p>'); dt.setData('text/plain', 'x');
    $('nbEd').dispatchEvent(new ClipboardEvent('paste', { clipboardData: dt, bubbles: true, cancelable: true })); });
  await page.waitForTimeout(900);
  const pg = await page.evaluate(() => { const p = nbPage(UI.nbPage); return { title: p.title, html: p.html, cards: nbInfo(p).cards.length, imgs: nbInfo(p).imgs.length }; });
  expect(pg.title).toBe('Delegation abuse');
  expect(pg.html).toContain('<h3>Unconstrained</h3>'); expect(pg.html).toContain('<li>first</li><li>second</li>'); expect(pg.html).toContain('<pre>Get-ADComputer -Filter *\nnext line</pre>');
  expect(pg.html).toContain('<b>Bold</b>'); expect(pg.html).not.toMatch(/javascript:|onerror|<script/);
  expect(pg.cards).toBe(1); expect(pg.imgs).toBe(1);
  await expect(page.locator('#nbSide')).toContainText('What does unconstrained delegation store?');
  // review from the library: reveal, rate Good
  await page.click('[data-act=nbLib]');
  await page.keyboard.press('Space'); await page.keyboard.press('3');
  expect(await page.evaluate(() => Object.values(DB.nb.cards).filter(c => c.reps > 0).length)).toBeGreaterThan(0);
  // Word export: a real .docx with the picture inside
  await page.evaluate(() => nbOpen(DB.nb.pages.find(p => p.title === 'Kerberoasting').id));
  await page.click('.nbbar [data-act=nbExport]');
  const [dl] = await Promise.all([page.waitForEvent('download'), page.click('[data-act=nbxGo]')]);
  expect(dl.suggestedFilename()).toBe('kerberoasting.docx');
  const file = await dl.path(), bytes = fs.readFileSync(file), txt = bytes.toString('latin1');
  expect(bytes.slice(0, 2).toString()).toBe('PK');
  for (const part of ['[Content_Types].xml', 'word/document.xml', 'word/styles.xml', 'word/numbering.xml', 'word/media/image1.png']) expect(txt).toContain(part);
  expect(txt).toContain('Request the tickets'); expect(txt).toContain('w:pStyle w:val="Heading1"');
  // Markdown export of the section: a zip with one .md per page and the picture
  await page.click('.nbbar [data-act=nbExport]'); await page.click('[data-act=nbxScope][data-v=sec]'); await page.click('[data-act=nbxFmt][data-v=md]');
  const [md] = await Promise.all([page.waitForEvent('download'), page.click('[data-act=nbxGo]')]);
  const mtxt = fs.readFileSync(await md.path()).toString('utf8');
  expect(md.suggestedFilename()).toBe('kerberos-attacks-markdown.zip'); expect(mtxt).toContain('kerberos-attacks/kerberoasting.md'); expect(mtxt).toContain('## Request the tickets'); expect(mtxt).toContain('| 13100 |');
  // the Word file imports back as a page with its picture and flashcards
  const back = await page.evaluate(async b64 => { const r = await nbFromDocx(Uint8Array.from(atob(b64), c => c.charCodeAt(0))); return { title: r.title, img: /<img data-m=/.test(r.html), q: (r.html.match(/<p>Q: /g) || []).length }; }, bytes.toString('base64'));
  expect(back).toEqual({ title: 'Kerberoasting', img: true, q: 3 });
  // reload keeps everything
  await page.reload(); await expect.poll(() => page.evaluate(() => !!DB && !!DB.nb && DB.nb.pages.some(p => p.title === 'Delegation abuse'))).toBe(true);
  noErrors(errors);
});

test('notebook cleaning: hostile HTML never survives, and nothing runs', async ({ page }) => {
  const errors = await open(page, '#/notebook');
  const V = ['<img src=x onerror=window.__x=1>', '<svg onload=window.__x=1>', '<script>window.__x=1</script>', '<a href=" JaVaScRiPt:window.__x=1">a</a>', '<a href="java&#x09;script:x">a</a>',
    '<a href="data:text/html,<script>1</script>">a</a>', '<iframe src="javascript:x"></iframe>', '<math><mtext><table><mglyph><style><img src=x onerror=window.__x=1>', '<noscript><p title="</noscript><img src=x onerror=window.__x=1>">',
    '<p style="background:url(http://evil)">x</p>', '<form action="http://evil"><input></form>', '<div class="nb-link"><a href="javascript:alert(1)">x</a></div>', '<img data-m="__proto__">',
    '<img data-m="constructor" src="data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+">', '<ul class="nb-check evil"><li class="done x" onclick=x>t</li></ul>', '<base href="http://evil/">', '<details open ontoggle=window.__x=1>', '<p>' + '<b>'.repeat(3000) + 'deep</p>'];
  const bad = await page.evaluate(V => { const out = [];
    for (const v of V) { const d = document.createElement('div'); d.innerHTML = nbClean(v, { src: true, media: true });
      for (const el of d.querySelectorAll('*')) { if (!/^(P|H2|H3|H4|B|I|U|S|MARK|CODE|SUB|SUP|PRE|UL|OL|LI|A|BR|HR|BLOCKQUOTE|TABLE|TR|TH|TD|FIGURE|FIGCAPTION|IMG|DIV|SMALL|TBODY)$/.test(el.tagName)) out.push(v + ' tag ' + el.tagName);
        for (const a of el.attributes) { if (/^on|^style$/i.test(a.name)) out.push(v + ' ' + a.name); if (a.name === 'href' && !/^(https?:|mailto:)/i.test(a.value)) out.push(v + ' href'); if (a.name === 'src' && !/^(data:image\/(png|jpeg|gif|webp);base64,|blob:)/.test(a.value)) out.push(v + ' src');
          if (a.name === 'class' && !['nb-link', 'nb-call', 'nb-check', 'done'].includes(a.value)) out.push(v + ' class'); } } }
    const pg = nbNewPage(DB.nb.sections[0].id, { html: nbClean(V.join('')) }); nbOpen(pg.id, { full: true }); return out; }, V);
  await page.waitForTimeout(500);
  expect(bad).toEqual([]); expect(await page.evaluate(() => window.__x)).toBeUndefined();
  // a backup with hostile notebook data is cleaned on import
  const clean = await page.evaluate(() => { const prev = DB.nb; DB.nb = { books: [{ id: 'nb-x', name: '<b>x</b>'.repeat(50), color: 'red;background:url(http://evil)', kind: 'Hack' }], sections: [{ id: 'ns-x', bookId: 'nb-x', name: 'S' }, { id: 'ns-y', bookId: 'nope' }],
      pages: [{ id: 'pg-x', sectionId: 'ns-x', title: 7, html: '<img src=x onerror=alert(1)><p>ok</p>', tags: ['a', 5, {}], att: ['m-none'] }], media: { '__proto__': {}, 'm-ok': { type: 'image/png', name: 'a', data: 'javascript:1' } }, cards: { 'bad key': {} } };
    nbSanitize(); const r = JSON.parse(JSON.stringify(DB.nb)); DB.nb = prev; return r; });
  expect(clean.books[0].color).toMatch(/^#/); expect(clean.books[0].name.length).toBeLessThanOrEqual(120); expect(clean.books[0].kind).toBe('Other');
  expect(clean.sections.length).toBe(1); expect(clean.pages[0].html).toBe('<p>ok</p>'); expect(clean.pages[0].title).toBe('Untitled'); expect(clean.pages[0].tags).toEqual(['a']); expect(clean.pages[0].att).toEqual([]);
  expect(Object.keys(clean.media)).toEqual(['m-ok']); expect(clean.media['m-ok'].data).toBeUndefined(); expect(clean.cards).toEqual({});
  noErrors(errors);
});

test('notebook pictures live outside the save, survive closing the tab, and travel in backups', async ({ page: first, context }) => {
  const fs = require('fs');
  const errors = await open(first, '#/notebook'); let page = first;
  await page.evaluate(() => NB_ACTS.nbPageNew(DB.nb.sections[0].id)); await page.keyboard.press('Enter');
  await page.evaluate(() => { const bin = Uint8Array.from(atob(NB_DEMO_SHOT.data.split(',')[1]), c => c.charCodeAt(0)), dt = new DataTransfer(); dt.items.add(new File([bin], 'lab.png', { type: 'image/png' }));
    $('nbEd').dispatchEvent(new ClipboardEvent('paste', { clipboardData: dt, bubbles: true, cancelable: true })); });
  await expect(page.locator('#nbEd img[src^="blob:"]')).toHaveCount(1);
  // close the tab straight after typing, then open the app again (the test helper's start-up script would race a plain reload)
  await page.keyboard.type('typed just before closing'); await page.close({ runBeforeUnload: true });
  page = await context.newPage(); page.on('pageerror', e => errors.push('pageerror: ' + e.message)); await page.goto(APP + '#/notebook');
  await expect.poll(() => page.evaluate(() => typeof DB !== 'undefined' && !!DB && !!DB.nb && DB.nb.pages.some(p => p.html.includes('typed just before closing')))).toBe(true);
  await page.evaluate(() => { if (typeof closeWelcome === 'function') closeWelcome(); });
  const st = await page.evaluate(async () => { const m = Object.values(DB.nb.media).find(x => x.name === 'lab.png'); return { inline: !!m.data, stored: !!(await IDB.get('nbm:' + m.id)), inSave: JSON.stringify(DB).includes('iVBOR') }; });
  expect(st).toEqual({ inline: false, stored: true, inSave: false });
  const [dl] = await Promise.all([page.waitForEvent('download'), page.evaluate(() => exportEverything(false))]);
  const bk = JSON.parse(fs.readFileSync(await dl.path(), 'utf8')); expect(Object.keys(bk.nbfiles).length).toBe(1);
  await page.evaluate(async () => { for (const k of Object.keys(DB.nb.media)) await IDB.del('nbm:' + k); });
  const [fc] = await Promise.all([page.waitForEvent('filechooser'), page.evaluate(() => clickAct('importAll'))]); await fc.setFiles(await dl.path());
  await page.click('[data-act=confirmOk]');
  await expect.poll(() => page.evaluate(async () => { const m = Object.values(DB.nb.media).find(x => x.name === 'lab.png'); return !!(m && await IDB.get('nbm:' + m.id)); })).toBe(true);
  noErrors(errors);
});

test('storage: real usage, early warnings, refusing files that do not fit, and clean-up', async ({ page }) => {
  const errors = await open(page, '#/settings');
  await expect(page.locator('#storage .sto-t')).toBeVisible();
  await page.evaluate(async () => { await IDB.set('file:f-orphan', new Blob(['x'])); await IDB.set('nbm:m-orphan', new Blob(['y'])); await storageRefresh(); });
  await expect(page.locator('#storage')).toContainText('Leftover files nothing uses (2)');
  await page.click('[data-act=stoOrphans]'); await page.click('[data-act=confirmOk]');
  await expect.poll(() => page.evaluate(async () => (await IDB.keys()).filter(k => /orphan/.test(k)).length)).toBe(0);
  await page.evaluate(async () => { storageEstimate = async () => { STORE.quota = 500e6; STORE.usage = 450e6; return STORE; }; await storageCheck(); });
  await expect(page.locator('#saved')).toContainText('Storage 90% full');
  expect(await page.evaluate(() => nbRoomFor(80e6))).toBe(false);
  await page.evaluate(() => { storageOK = false; paintSaved(); }); await expect(page.locator('#saved')).toContainText('Not saved');
  noErrors(errors);
});

test('a large workspace keeps the last typing when the tab closes (journal)', async ({ page: first, context }) => {
  const errors = await open(first, '#/notebook'); let page = first;
  await page.evaluate(() => { const h = DB.nb.pages[2].html; for (let i = 0; i < 900; i++) nbNewPage(DB.nb.sections[0].id, { title: 'P' + i, html: h }); flush(); });
  await expect.poll(() => page.evaluate(() => STORE.ls)).toBe(false);          // too big for the instant localStorage copy
  await page.evaluate(() => NB_ACTS.nbPageNew(DB.nb.sections[0].id)); await page.keyboard.press('Enter');
  await page.keyboard.type('last words before closing'); await page.close({ runBeforeUnload: true });
  page = await context.newPage(); page.on('pageerror', e => errors.push('pageerror: ' + e.message)); await page.goto(APP + '#/notebook');
  await expect.poll(() => page.evaluate(() => typeof DB !== 'undefined' && !!DB && !!DB.nb && DB.nb.pages.some(p => p.html.includes('last words before closing'))), { timeout: 15000 }).toBe(true);
  noErrors(errors);
});

test('leaving with a change not yet on disk asks first; a saved workspace never asks', async ({ page: first, context }) => {
  const errors = await open(first, '#/notebook'); let page = first;
  await page.evaluate(() => encEnable('correct horse battery staple 9')); await page.waitForTimeout(1200);   // encrypted saves finish in the background
  await page.evaluate(() => NB_ACTS.nbPageNew(DB.nb.sections[0].id)); await page.keyboard.press('Enter'); await page.keyboard.type('encrypted words');
  let asked = false; page.on('dialog', async d => { asked = d.type() === 'beforeunload'; await d.dismiss(); });
  await page.close({ runBeforeUnload: true });
  await expect.poll(() => asked).toBe(true);
  await expect.poll(() => page.evaluate(() => isDirty())).toBe(false);                       // the save finished while the browser asked
  await expect(page.locator('#saved')).toContainText('Saved');
  expect(await page.evaluate(() => DB.nb.pages.some(p => p.html.includes('encrypted words')))).toBe(true);
  // nothing pending: closing does not ask
  page.removeAllListeners('dialog'); let again = false; page.on('dialog', d => { again = true; d.accept(); });
  await page.close({ runBeforeUnload: true }); await new Promise(r => setTimeout(r, 400)); expect(again).toBe(false);
  noErrors(errors);
});

test('automatic backup to a folder: writes, keeps 7 days, pauses without permission, encrypts, restores', async ({ page }) => {
  const errors = await open(page, '#/settings');
  // a stand-in folder (headless browsers cannot show the real picker)
  await page.evaluate(() => {
    const files = new Map(); let perm = 'granted';
    const dir = { kind: 'directory', name: 'OSINTrix backups', files, setPerm: p => perm = p,
      queryPermission: async () => perm, requestPermission: async () => perm,
      getFileHandle: async (n, o) => { if (!files.has(n) && !(o && o.create)) throw new DOMException('no', 'NotFoundError'); if (perm !== 'granted') throw new DOMException('no', 'NotAllowedError');
        return { kind: 'file', createWritable: async () => { let buf = ''; return { write: async t => { buf += t; }, close: async () => { files.set(n, buf); } }; } }; },
      entries: async function* () { for (const k of files.keys()) yield [k, { kind: 'file' }]; },
      removeEntry: async n => { files.delete(n); } };
    window.__dir = dir; window.showDirectoryPicker = async () => dir;
    for (let i = 1; i <= 9; i++) files.set('osintrix-2020-01-0' + i + '.json', '{}');   // old daily copies
    files.set('my-notes.txt', 'not ours');
  });
  await expect(page.locator('#storage')).toContainText('Automatic backup to a folder');
  await page.click('[data-act=fbChoose]');
  await expect(page.locator('#storage .fb-st')).toContainText('On');
  const names = await page.evaluate(() => [...__dir.files.keys()].sort());
  expect(names).toContain('osintrix-latest.json'); expect(names).toContain('my-notes.txt');
  expect(names.filter(n => /^osintrix-\d{4}-\d{2}-\d{2}\.json$/.test(n)).length).toBe(7);           // today + the 6 newest old ones
  const latest = await page.evaluate(() => JSON.parse(__dir.files.get('osintrix-latest.json')));
  expect(latest.cases.length).toBeGreaterThan(0); expect(latest.nb.pages.length).toBeGreaterThan(0);
  // a change is backed up automatically
  await page.evaluate(() => { const p = fbGet(); p.every = 0; fbSet(p); DB.notes.push({ id: uid('n'), text: 'after the first backup', created: Date.now() }); mutate('note'); });
  await expect.poll(() => page.evaluate(() => (__dir.files.get('osintrix-latest.json') || '').includes('after the first backup')), { timeout: 20000 }).toBe(true);
  // permission withdrawn: paused, and Resume brings it back
  await page.evaluate(async () => { __dir.setPerm('prompt'); DB.notes.push({ id: uid('n'), text: 'while paused', created: Date.now() }); mutate('note'); await fbRun(true); });
  await expect(page.locator('#storage .fb-st')).toContainText('Paused');
  await page.evaluate(() => __dir.setPerm('granted')); await page.click('[data-act=fbResume]');
  await expect.poll(() => page.evaluate(() => (__dir.files.get('osintrix-latest.json') || '').includes('while paused'))).toBe(true);
  // encrypted workspace: the backup is encrypted and opens with the passphrase
  await page.evaluate(async () => { await encEnable('correct horse battery staple 9'); await fbRun(true); });
  const env = await page.evaluate(() => JSON.parse(__dir.files.get('osintrix-latest.json')));
  expect(env.enc).toBeTruthy(); expect(JSON.stringify(env)).not.toContain('while paused');
  const back = await page.evaluate(async () => { const d = JSON.parse(__dir.files.get('osintrix-latest.json')); const key = await deriveKey('correct horse battery staple 9', b64d8(d.kdf.salt), d.kdf.iter); return JSON.parse(await openWith(key, d)).notes.some(n => n.text === 'while paused'); });
  expect(back).toBe(true);
  await page.click('[data-act=fbOff]'); await expect(page.locator('#storage [data-act=fbChoose]')).toBeVisible();
  noErrors(errors);
});

test('certificates: decode, findings, chain, CSR, private keys refused, save to case, notebook cards', async ({ page }) => {
  const fs = require('fs'), path = require('path'), D = path.join(__dirname, 'fixtures', 'certs');
  const errors = await open(page, '#/certs');
  // a phishing-style leaf with its issuer, pasted as PEM
  await page.fill('#cxIn', fs.readFileSync(path.join(D, 'chain-phish.pem'), 'utf8')); await page.click('[data-act=cxDecode]');
  await expect(page.locator('.crt-hero h1')).toHaveText('secure-acme-login.com');
  await expect(page.locator('.crt-r')).toContainText('Lookalike name');
  await expect(page.locator('.crt-chips .chip.hl')).toHaveText(/acme-sso\.microsoftonline-auth\.com/);
  await expect(page.locator('.crt-fp code').first()).toContainText(':');
  const fp = await page.evaluate(() => cxS().R.certs.find(c => c.title === 'secure-acme-login.com').fp.sha256);
  const want = require('crypto').createHash('sha256').update(fs.readFileSync(path.join(D, 'leaf-phish.der'))).digest('hex');
  expect(fp).toBe(want);
  // the chain is ordered and each signature checked; the missing root is named
  await page.click('[data-act=cxTab][data-v=chain]');
  await expect(page.locator('.crt-lnk.ok')).toHaveCount(1); await expect(page.locator('.crt-lnk.warn')).toContainText('Example Root CA X1');
  // a .p7b bundle opened as a file: full chain, all signatures good
  const [fc] = await Promise.all([page.waitForEvent('filechooser'), page.click('[data-act=cxFile]')]); await fc.setFiles(path.join(D, 'bundle.p7b'));
  await expect(page.locator('.crt-lnk.ok')).toHaveCount(3);
  // tampering is caught
  await page.evaluate(() => { const leaf = cxS().R.chain.order[0], b = new Uint8Array(leaf.der); b[b.length - 300] ^= 1; cxLoad(b); });
  await page.evaluate(() => { const R = cxS().R; R.certs.push(...X5.read(CERT_SAMPLES.ov.pem).certs.slice(1)); return cxEnrich(R); });
  await page.click('[data-act=cxTab][data-v=chain]'); await expect(page.locator('.crt-lnk.bad')).toHaveCount(1);
  // CSR: signature, challenge password, matching a certificate key
  await page.evaluate(() => CX_ACTS.cxSample(null, 'csr'));
  await expect(page.locator('.crt-csr')).toContainText('Signature is valid'); await expect(page.locator('.crt-csr')).toContainText('Contains a challenge password');
  // private keys are refused and removed from the box
  await page.fill('#cxIn', fs.readFileSync(path.join(D, 'private-key.pem'), 'utf8')); await page.click('[data-act=cxDecode]');
  await expect(page.locator('.crt-key')).toContainText('private key'); expect(await page.inputValue('#cxIn')).not.toContain('PRIVATE KEY');
  // Cobalt Strike default, AD CS logon certificate
  await page.evaluate(() => CX_ACTS.cxSample(null, 'cs')); await expect(page.locator('.crt-r')).toContainText('Cobalt Strike default certificate');
  await page.evaluate(() => CX_ACTS.cxSample(null, 'adcs')); await expect(page.locator('.crt-r')).toContainText('Can log on to Windows as j.okafor@corp.example');
  // save to the case: an evidence record whose names and fingerprints are entities, reopened from the list
  await page.evaluate(() => CX_ACTS.cxSample(null, 'phish')); await expect(page.locator('.crt-fp code').first()).toContainText(':');
  await page.click('.crt-hero [data-act=cxSave]');
  const rec = await page.evaluate(() => { const r = DB.records.find(x => x.source === 'certificate'); return r && { title: r.title, ents: JSON.stringify(r.ents), ts: r.ts }; });
  expect(rec.title).toBe('Certificate: secure-acme-login.com'); expect(rec.ents).toContain('files-acme.net'); expect(rec.ents).toContain(fp); expect(rec.ts).toBeGreaterThan(0);
  await page.evaluate(() => { cxS().R = null; cxPaint(); }); await page.click('.crt-it'); await expect(page.locator('.crt-hero h1')).toHaveText('secure-acme-login.com');
  // guide flashcards into the Notebook
  await page.evaluate(() => CX_ACTS.cxCh(null, 'chain')); await page.click('[data-act=cxToNb]');
  expect(await page.evaluate(() => { const b = DB.nb.books.find(x => x.name === 'Certificates'), p = DB.nb.pages.find(x => x.title === 'Chain of trust'); return !!b && nbInfo(p).cards.length; })).toBe(4);
  noErrors(errors);
});

test('certificates from a TLS 1.2 capture open in the decoder', async ({ page }) => {
  const fs = require('fs'), path = require('path');
  const errors = await open(page, '#/lab');
  const b64 = fs.readFileSync(path.join(__dirname, 'fixtures', 'tls12-cert.pcap')).toString('base64');
  const tls = await page.evaluate(async b64 => { const A = await pcapAnalyse(new File([Uint8Array.from(atob(b64), c => c.charCodeAt(0))], 'tls12-cert.pcap')); UI.pcap = A; UI.labTab = 'pcap'; UI.pcTab = 'tls'; renderMain(); return A.tls.map(t => [t.sni, t.ver, t.certs.length]); }, b64);
  expect(tls).toEqual([['shop.acme.example', 'TLS 1.2', 1]]);
  await page.click('[data-act=pcCerts]');
  await expect(page.locator('.crt-hero h1')).toHaveText('shop.acme.example');
  await expect(page.locator('.crt-chips')).toContainText('pay.acme.example');
  noErrors(errors);
});
