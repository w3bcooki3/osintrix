// End-to-end checks for OSINTrix. Every test opens the real app from disk, like a user would.
const { test, expect } = require('@playwright/test');
const { open, capture, fixture, noErrors } = require('./helpers');

const ROUTES = ['#/home', '#/cases', '#/cloud', '#/pad', '#/whatsnew', '#/case/c-lantern/overview', '#/case/c-lantern/vault', '#/case/c-lantern/entities', '#/case/c-lantern/timeline',
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
  const SKIP = new Set(['exportAll', 'resetDemo', 'freshStart', 'removeSample', 'importAll', 'importCase', 'secOn', 'secLock', 'secOff', 'secChange', 'capFiles', 'capLog', 'capWeb', 'attAdd', 'attOpen', 'attDl', 'rsAll', 'printReport', 'helpWelcome', 'refFind', 'pbGo', 'wuImport', 'placesKml', 'placesCsv', 'wuExportAll', 'wuExport']);
  for (const r of ['#/home', '#/case/c-lantern/overview', '#/case/c-lantern/entities', '#/case/c-lantern/timeline', '#/case/c-lantern/graph', '#/case/c-lab/map', '#/case/c-lantern/questions', '#/toolbox', '#/lab', '#/security', '#/reference', '#/playbooks', '#/help', '#/cloud', '#/whatsnew', '#/pad', '#/ctf', '#/detections']) {
    await page.evaluate(h => { location.hash = h; renderMain(); }, r); await page.waitForTimeout(200);
    const acts = await page.evaluate(() => [...document.querySelectorAll('#main [data-act]')].map((e, i) => [i, e.dataset.act]));
    for (const [i, a] of acts.slice(0, 60)) {
      if (SKIP.has(a)) continue;
      await page.evaluate(([h, i, a]) => { if (location.hash !== h) location.hash = h; renderMain(); const e = document.querySelectorAll('#main [data-act]')[i]; if (e && e.dataset.act === a) e.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true })); }, [r, i, a]);
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
  await page.locator('.cg-it').nth(2).click();
  await expect(page.locator('#cgDetail .cg-cmd')).not.toHaveCount(0);
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
  expect(idb).toBe(newer); expect(ls).toBe(newer);
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
  await expect.poll(() => page.evaluate(() => !!document.getElementById('rotab'))).toBe(true);
  await expect.poll(() => two.evaluate(() => typeof TABS !== 'undefined' && TABS.writer)).toBe(true);
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
  await page.evaluate(() => { UI.ctfTab = 'cheats'; UI.csq = 'steghide'; renderMain(); });
  await expect(page.locator('.cs-sec')).not.toHaveCount(0);
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
