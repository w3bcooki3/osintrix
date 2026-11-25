// WinForensicX hand-off, both ways.
// In: osint_WS-APT.stix.json is the file the WinForensicX case report writes with "Export for OSINT" (Indicators tab,
//     11 ticked: public addresses, domains, URLs and SHA-1s of the sample APT case), saved unchanged.
// Out: "Hunt list for WinForensicX" is read by Invoke-WfxHunt -IocFile: one value per line, '#' starts a comment at the
//     start of a line or after a space, so the check below applies the same rule.
const { test, expect } = require('@playwright/test');
const { open, fixture, noErrors } = require('./helpers');
const fs = require('fs');

const wfxFile = fixture('wfx/osint_WS-APT.stix.json');
const huntValues = text => text.split(/\r?\n/).map(l => l.replace(/(?:^|\s)#.*$/, '').trim()).filter(Boolean);

test('WinForensicX export: imports as one batch with its findings, TLP and host; the list shows just that batch; ticked "add to case" files them', async ({ page }) => {
  const errors = await open(page, '#/feeds', { osintSample: true });
  await page.evaluate(async () => { await ctiLoad(); UI.itab = 'iocs'; renderMain(); });
  const caseName = await page.evaluate(() => caseNm(theCase()));
  const before = await page.evaluate(() => DB.entries.filter(e => e.caseId === DB.active).length);

  // first without "add to case": the library gets the 11, the case is untouched
  await page.click('[data-act=ctiImport]');
  await expect(page.locator('#ctiToCase')).toBeVisible();
  await expect(page.locator('label:has(#ctiToCase)')).toContainText('Also add them to ' + caseName);
  await expect(page.locator('#ctiToCase')).not.toBeChecked();
  await page.fill('#ctiPaste', fs.readFileSync(wfxFile, 'utf8'));
  await page.fill('#ctiSrcName', 'WinForensicX WS-APT');
  await page.click('[data-act=ctiImportGo]');
  await expect(page.locator('.toast')).toContainText('STIX 2.1: 11 added');
  expect(await page.evaluate(() => DB.entries.filter(e => e.caseId === DB.active).length)).toBe(before);

  // the list now shows only this import
  await expect(page.locator('#osrcSel')).toHaveValue('WinForensicX WS-APT');
  const shown = await page.evaluate(() => ctiIocList().map(x => ({ k: x.k, v: x.v, tlp: x.tlp, desc: x.desc, tags: x.tags })));
  expect(shown.length).toBe(11);
  expect(shown.every(x => x.tlp === 'amber' && x.tags.includes('winforensicx') && x.tags.includes('host:WS-APT'))).toBe(true);
  const dl = shown.find(x => x.v === '203.0.113.50');
  expect(dl.desc).toBe('WS-APT: Risky download: Invoice_2026.iso');
  expect(shown.filter(x => x.k === 'sha1').length).toBe(2);
  expect(shown.find(x => x.k === 'domain' && x.v === 'kq3x9zmnvbwp7h.top').tags).toContain('severity:medium');

  // again with "add to case": nothing new in the library (merged), all 11 filed in the case with the finding as the note
  await page.click('[data-act=ctiImport]');
  await page.check('#ctiToCase');
  await page.fill('#ctiPaste', fs.readFileSync(wfxFile, 'utf8'));
  await page.fill('#ctiSrcName', 'WinForensicX WS-APT');
  await page.click('[data-act=ctiImportGo]');
  await expect(page.locator('.toast')).toContainText('11 merged');
  await expect(page.locator('.toast')).toContainText('11 added to ' + caseName);
  const filed = await page.evaluate(() => DB.entries.filter(e => e.caseId === DB.active).map(e => ({ key: entryKey(e), notes: e.notes })));
  expect(filed.length).toBe(before + 11);
  expect(filed.find(e => e.key === 'ipv4:203.0.113.50').notes).toBe('WS-APT: Risky download: Invoice_2026.iso');
  expect(filed.some(e => e.key === 'sha1:1122334455667788990011223344556677889900')).toBe(true);
  // a third import adds nothing twice
  await page.click('[data-act=ctiImport]'); await page.check('#ctiToCase');
  await page.fill('#ctiPaste', fs.readFileSync(wfxFile, 'utf8')); await page.fill('#ctiSrcName', 'WinForensicX WS-APT');
  await page.click('[data-act=ctiImportGo]');
  await expect(page.locator('.toast')).not.toContainText('added to');
  expect(await page.evaluate(() => DB.entries.filter(e => e.caseId === DB.active).length)).toBe(before + 11);
  noErrors(errors);
});

test('hunt list for WinForensicX: one value per line with commented header, only what a host can show, from a case or the library', async ({ page }) => {
  const errors = await open(page, '#/feeds', { osintSample: true });
  await page.evaluate(async () => { await ctiLoad(); });
  // a library with every kind, including ones a Windows host cannot show
  await page.evaluate(async () => {
    await ctiImportText('type,value\nipv4,203.0.113.7\ndomain,evil-cdn.example\nurl,https://evil-cdn.example/dl/page#token=abc\nsha256,e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n' +
      'md5,44d88612fea8a8f36de82e1278abb02f\nemail,ops@evil-cdn.example\ncve,CVE-2024-3400\nbtc,bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq\n', 'Hunt test');
    UI.itab = 'iocs'; UI.osrc = 'Hunt test'; renderMain();
  });
  await page.click('[data-act=ctiExport]');
  await page.selectOption('#ctiExFmt', 'hunt');
  const [dl] = await Promise.all([page.waitForEvent('download'), page.click('[data-act=ctiExportGo]')]);
  expect(dl.suggestedFilename()).toMatch(/\.hunt\.txt$/);
  const text = fs.readFileSync(await dl.path(), 'utf8');
  expect(text).toMatch(/^# OSINTrix hunt list: /);
  expect(text).toContain('\r\n');
  expect(text).toMatch(/TLP:AMBER · 6 indicators/);
  const vals = huntValues(text);
  expect(vals.sort()).toEqual(['203.0.113.7', '44d88612fea8a8f36de82e1278abb02f', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'evil-cdn.example',
    'https://evil-cdn.example/dl/page#token=abc', 'ops@evil-cdn.example'].sort());   // the URL keeps its '#'; no CVE, no wallet
  await expect(page.locator('.toast')).toContainText('6 indicators in the hunt list');

  // from a case: the sample case's indicators, same rules
  await page.click('[data-act=ctiExport]');
  const caseId = await page.evaluate(() => DB.active);
  await page.selectOption('#ctiExWhat', 'case:' + caseId);
  await page.selectOption('#ctiExFmt', 'hunt');
  const [dl2] = await Promise.all([page.waitForEvent('download'), page.click('[data-act=ctiExportGo]')]);
  const v2 = huntValues(fs.readFileSync(await dl2.path(), 'utf8'));
  const want = await page.evaluate(id => ctiHuntList(ctiCaseItems(id)), caseId);
  expect(v2).toEqual(want);
  expect(v2.length).toBeGreaterThan(3);
  expect(v2.every(v => !/^CVE-/i.test(v))).toBe(true);

  // only CVEs: nothing to hunt, says so, writes nothing
  await page.evaluate(async () => { await ctiImportText('type,value\ncve,CVE-2023-4966\n', 'CVE only'); UI.osrc = 'CVE only'; renderMain(); });
  await page.click('[data-act=ctiExport]'); await page.selectOption('#ctiExFmt', 'hunt');
  let downloaded = false; page.once('download', () => { downloaded = true; });
  await page.click('[data-act=ctiExportGo]');
  await expect(page.locator('.toast')).toContainText('None of these can be hunted on a host');
  await page.waitForTimeout(300); expect(downloaded).toBe(false);
  noErrors(errors);
});

test('a file entry with an MD5 or SHA-1 is keyed as that hash, joins the same hash in records, and old sha256: keys are moved', async ({ page }) => {
  const errors = await open(page, '#/home');
  const r = await page.evaluate(() => {
    const sha1 = '9A8B7C6D5E4F30211203F4E5D6C7B8A990817263', md5 = '44d88612fea8a8f36de82e1278abb02f', sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    const mk = h => ({ id: uid('v'), caseId: DB.active, type: 'file', fields: { hash: h }, priority: 'medium', starred: false, tags: [], notes: '', src: '', created: Date.now(), pos: null });
    const keys = [sha1, md5, sha256].map(h => entryKey(mk(h)));
    // a record that mentions the same SHA-1 (as Amcache would) and the entry: one entity, not two
    DB.entries.push(mk(sha1));
    DB.records.push({ id: uid('r'), caseId: DB.active, type: 'evidence', title: 'Amcache', body: 'onedriveupdater.exe SHA1 ' + sha1.toLowerCase(), tsRaw: '', tsZone: 'explicit', ts: Date.now(), source: 'amcache', host: '', tags: [], ents: E.extract('SHA1 ' + sha1.toLowerCase()), answer: '', addedBy: 'You', addedAt: Date.now(), hash: '' });
    mutate('test');
    const items = ctiCaseItems(DB.active).filter(x => x.v === sha1.toLowerCase());
    // verdicts and watches saved by 1.75 under sha256:<40 or 32 chars> move to the right kind; real SHA-256 keys stay
    DB.verdicts['sha256:' + sha1.toLowerCase()] = 'malicious'; DB.watch = DB.watch || {}; DB.watch['sha256:' + md5] = { at: 1 };
    DB.verdicts['sha256:' + sha256] = 'benign'; DB.verdicts['sha1:' + 'b'.repeat(40)] = 'benign'; DB.verdicts['sha256:' + 'b'.repeat(40)] = 'malicious';
    const moved = migrateHashKeys(), again = migrateHashKeys();
    return { keys, items: items.map(x => x.k), moved, again, v1: DB.verdicts['sha1:' + sha1.toLowerCase()], gone: !('sha256:' + sha1.toLowerCase() in DB.verdicts), w: !!DB.watch['md5:' + md5],
      keep256: DB.verdicts['sha256:' + sha256], noOverwrite: DB.verdicts['sha1:' + 'b'.repeat(40)], entVerdict: entryVerdict(DB.entries[DB.entries.length - 1]) };
  });
  expect(r.keys).toEqual(['sha1:9a8b7c6d5e4f30211203f4e5d6c7b8a990817263', 'md5:44d88612fea8a8f36de82e1278abb02f', 'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']);
  expect(r.items).toEqual(['sha1']);
  expect(r.moved).toBe(3); expect(r.again).toBe(0);
  expect(r.v1).toBe('malicious'); expect(r.gone).toBe(true); expect(r.w).toBe(true);
  expect(r.keep256).toBe('benign'); expect(r.noOverwrite).toBe('benign');
  expect(r.entVerdict).toBe('malicious');
  noErrors(errors);
});
