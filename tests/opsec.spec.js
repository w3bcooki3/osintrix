// Clean before sending, AI generator settings, VINs.
// Clean: the dirty files were written with exiftool, piexif, pypdf, python-docx, openpyxl and python-pptx. The clean copies
// are checked here byte by byte, and — where installed — with exiftool (nothing personal left), qpdf --check (the PDF is
// still valid) and Python (python-docx, openpyxl and python-pptx still open the Office files).
// AI: the PNGs carry what AUTOMATIC1111 / Forge, ComfyUI, Midjourney and NovelAI really write (exiftool lists the same tags).
const { test, expect } = require('@playwright/test');
const { open, fixture, noErrors } = require('./helpers');
const { execFileSync } = require('child_process');
const fs = require('fs'), os = require('os'), path = require('path');
const has = cmd => { try { execFileSync(cmd, ['-ver'], { stdio: 'ignore' }); return true; } catch (e) { try { execFileSync(cmd, ['--version'], { stdio: 'ignore' }); return true; } catch (e2) { return false; } } };

async function cleanAll(page, files) {
  await page.evaluate(() => { UI.labTab = 'clean'; UI.clean = null; UI.clNeutral = true; renderMain(); });
  await page.setInputFiles('#clIn', files.map(f => fixture('clean/' + f)));
  await expect.poll(() => page.evaluate(() => !!(UI.clean && UI.clean.items)), { timeout: 30000 }).toBe(true);
}
async function save(page, i, dir) {
  const [dl] = await Promise.all([page.waitForEvent('download'), page.click(`[data-act=clGet][data-v="${i}"]`)]);
  const p = path.join(dir, dl.suggestedFilename()); await dl.saveAs(p); return p;
}

test('clean before sending: photos keep every pixel and their turn, lose camera, place, names and hidden data; checked with exiftool', async ({ page }) => {
  const errors = await open(page, '#/lab');
  await cleanAll(page, ['persona-photo.jpg', 'screenshot.png', 'sticker.webp']);
  const cards = page.locator('.cl-r');
  await expect(cards).toHaveCount(3);
  const jpg = cards.nth(0);
  await expect(jpg).toContainText('Location: 52.520094, 13.410308');
  await expect(jpg).toContainText('EXIF (camera, settings, dates, location, serials)');
  await expect(jpg).toContainText('XMP (software, edit history, IDs)');
  await expect(jpg).toContainText('Photoshop / IPTC');
  await expect(jpg).toContainText('Data after the end of the picture');
  await expect(jpg).toContainText('Orientation (so the photo still shows the right way up)');
  await expect(jpg).toContainText('Nothing that points to a person, device, place, program or time.');
  await expect(cards.nth(1)).toContainText('Text “Author”');
  await expect(cards.nth(2)).toContainText('XMP');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'clean-'));
  const outs = [await save(page, 0, dir), await save(page, 1, dir), await save(page, 2, dir)];
  expect(outs.map(p => path.basename(p))).toEqual(['photo-1.jpg', 'image-2.png', 'image-3.webp']);       // plain names by default
  const orig = fs.readFileSync(fixture('clean/persona-photo.jpg')), out = fs.readFileSync(outs[0]);
  const scan = b => { const i = b.lastIndexOf(Buffer.from([0xff, 0xda])); return b.subarray(i, b.indexOf(Buffer.from([0xff, 0xd9]), i) + 2); };      // the main picture's scan (the EXIF thumbnail has its own, earlier)
  expect(Buffer.compare(scan(orig), scan(out))).toBe(0);                                             // the picture data is byte-for-byte the same
  for (const p of outs) { const b = fs.readFileSync(p).toString('latin1'); for (const s of ['Kroll', 'iPhone', 'Pixel 8', 'SM-S918B', 'HIDDEN', 'Photoshop', 'F2LXK9QWN1']) expect(b, path.basename(p) + ' ' + s).not.toContain(s); }
  if (has('exiftool')) {
    const J = JSON.parse(execFileSync('exiftool', ['-j', '-a', '-G1', ...outs]).toString());
    for (const t of J) { const keys = Object.keys(t).filter(k => k !== 'SourceFile' && !/^(ExifTool|System|File|Composite|JFIF|PNG|RIFF):/.test(k));
      expect(keys.filter(k => k !== 'IFD0:Orientation'), t.SourceFile).toEqual([]); }
    expect(J[0]['IFD0:Orientation']).toBe('Rotate 90 CW');
  }
  noErrors(errors);
});

test('clean before sending: a PDF stays valid and loses its properties, XMP and IDs; Office files still open, with no names, company or session IDs', async ({ page }) => {
  const errors = await open(page, '#/lab');
  await cleanAll(page, ['statement.pdf', 'notes.docx', 'payments.xlsx', 'briefing.pptx']);
  const cards = page.locator('.cl-r');
  const pdf = cards.nth(0);
  await expect(pdf).toContainText('Author: Daniel Kroll');
  await expect(pdf).toContainText('Company: Kroll Investigations GmbH');
  await expect(pdf).toContainText('CreationDate: 2025-03-14 08:12:44 +0100');
  await expect(pdf).toContainText('Producer: Microsoft® Word for Microsoft 365');
  await expect(pdf).toContainText('saved 2 times and keeps every earlier version');
  const doc = cards.nth(1);
  for (const t of ['Company: Kroll Investigations GmbH', 'Manager: M. Weber', 'Keywords: case 4471, confidential', 'Editing time (minutes): 94', 'Editing-session IDs (rsids)', 'Names on comments and tracked changes: Daniel Kroll — now “Author”', 'Preview thumbnail']) await expect(doc).toContainText(t);
  await expect(doc).toContainText('1 tracked deletion still holds the deleted words');
  await expect(doc).toContainText('1 comment is still in the file (its author is now anonymous)');
  await expect(cards.nth(2)).toContainText('Hidden sheets: Sources');
  await expect(cards.nth(3)).toContainText('Speaker notes are still in the presentation.');
  for (let i = 0; i < 4; i++) await expect(cards.nth(i)).toContainText('Nothing that points to a person, device, place, program or time.');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'clean-'));
  const outs = []; for (let i = 0; i < 4; i++) outs.push(await save(page, i, dir));
  const o = fs.readFileSync(fixture('clean/statement.pdf')), c = fs.readFileSync(outs[0]);
  expect(c.length).toBe(o.length);                                                                    // cleaned in place: nothing moved
  expect(c.toString('latin1')).not.toMatch(/Kroll|prosecutor|2f1c3a4e/);
  // every part of the Office files, read back in the page
  const leaks = await page.evaluate(async bufs => { const out = []; for (const arr of bufs) { const b = new Uint8Array(arr), Z = zipOpen(b); for (const f of Z.files) { const u = await fxZipEntry(b, f.name); const s = new TextDecoder().decode(u); if (/Kroll|M\. Weber|00A1B2C3|w:rsid/.test(s)) out.push(f.name); } } return out; },
    outs.slice(1).map(p => [...fs.readFileSync(p)]));
  expect(leaks).toEqual([]);
  if (has('qpdf')) execFileSync('qpdf', ['--check', outs[0]]);
  if (has('exiftool')) { const J = JSON.parse(execFileSync('exiftool', ['-j', ...outs]).toString()); for (const t of J) for (const k of ['Author', 'Creator', 'LastModifiedBy', 'Company', 'Manager', 'Title', 'Keywords']) expect(t[k] || '', t.SourceFile + ' ' + k).not.toMatch(/\w/); }
  let py = false; try { execFileSync('python3', ['-c', 'import docx, openpyxl, pptx']); py = true; } catch (e) {}
  if (py) { const r = execFileSync('python3', ['-c', `import docx, openpyxl, pptx, sys
d = docx.Document(sys.argv[1]); w = openpyxl.load_workbook(sys.argv[2]); p = pptx.Presentation(sys.argv[3])
print(d.paragraphs[0].text, '|', w.sheetnames, '|', w['Payments']['A2'].comment.author, '|', p.slides[0].shapes.title.text)`, outs[1], outs[2], outs[3]]).toString();
    expect(r).toContain('The account was opened with a Revolut card. Payment confirmed.'); expect(r).toContain("['Payments', 'Sources']"); expect(r).toContain('| Author |'); expect(r).toContain('Varga network'); }
  noErrors(errors);
});

test('clean before sending: what it does not rewrite says so', async ({ page }) => {
  const errors = await open(page, '#/lab');
  await page.evaluate(() => { UI.labTab = 'clean'; UI.clean = null; renderMain(); });
  await page.setInputFiles('#clIn', [{ name: 'clip.mp4', mimeType: 'video/mp4', buffer: Buffer.concat([Buffer.from([0, 0, 0, 24]), Buffer.from('ftypisom'), Buffer.alloc(40)]) }, { name: 'notes.odt', mimeType: 'application/octet-stream', buffer: Buffer.from('PK\x03\x04mimetypeapplication/vnd.oasis') }]);
  await expect(page.locator('.cl-r').first()).toContainText('Videos are not rewritten in the browser');
  await expect(page.locator('.cl-r').nth(1)).toContainText('mat2');
  await expect(page.locator('[data-act=clGet]')).toHaveCount(0);
  noErrors(errors);
});

test('AI generator settings: AUTOMATIC1111 / Forge (PNG and JPEG), ComfyUI, Midjourney and NovelAI; a camera photo shows none', async ({ page }) => {
  const errors = await open(page, '#/lab');
  const read = f => page.evaluate(async a => { const G = await aiGenRead(new Uint8Array(a)); return G; }, [...fs.readFileSync(fixture('aigen/' + f))]);
  const A = await read('a1111-forge.png');
  expect(A.tool).toBe('Stable Diffusion WebUI Forge');
  expect(A.prompt).toContain('giving a speech at a podium');
  expect(A.negative).toBe('cartoon, painting, blurry, extra fingers');
  expect([A.seed, A.steps, A.sampler, A.scheduler, A.cfg, A.size, A.model, A.modelHash]).toEqual(['2871934455', '28', 'DPM++ 2M', 'Karras', '6.5', '1024×1024', 'juggernautXL_v9', '31e35c80fc']);
  expect(A.loras).toEqual([{ name: 'sen_marcus_hale_v2', w: '', hash: '9f2c4a1b7e3d' }]);
  const J = await read('a1111.jpg');                      // the same settings in the JPEG's EXIF comment
  expect([J.seed, J.model, J.prompt]).toEqual([A.seed, A.model, A.prompt]);
  const C = await read('comfyui.png');
  expect(C.tool).toBe('ComfyUI');
  expect(C.prompt).toContain('bank statement screenshot');
  expect(C.negative).toBe('blurry, watermark');
  expect([C.model, C.seed, C.steps, C.cfg, C.sampler, C.size]).toEqual(['realvisxlV50_v50Bakedvae.safetensors', '918273645', '30', '4.5', 'euler', '832×1216']);
  expect(C.loras[0]).toEqual({ name: 'phone_screenshot_ui_xl.safetensors', w: '0.7' });
  const M = await read('midjourney.png');
  expect([M.tool, M.jobId, M.version, M.author]).toEqual(['Midjourney', '0d6f2b7e-8c41-4a2f-9e55-31b7c2a9f004', 'v6.1', 'storm_chaser_77']);
  expect(M.prompt).toBe('flooded street in Valencia with cars piled up, news photo, overcast --ar 3:2 --v 6.1');
  const N = await read('novelai.png');
  expect(N.tool).toBe('NovelAI (NovelAI Diffusion V4 Full 7ABFFA2A)');
  expect([N.seed, N.negative, N.size]).toEqual(['3371920054', 'lowres, text, watermark', '1216×832']);
  expect(await read('camera.jpg')).toBeNull();
  // on screen, in the File inspector: the card, the flag and the Civitai leads
  await page.evaluate(() => { UI.labTab = 'file'; UI.labFile = null; renderMain(); });
  await page.setInputFiles('#labIn', fixture('aigen/a1111-forge.png'));
  const card = page.locator('#aigCard');
  await expect(card).toContainText('Made with Stable Diffusion WebUI Forge');
  await expect(card).toContainText('sen_marcus_hale_v2');
  await expect(card).toContainText('trained on a style, an object — or one real person');
  await expect(card.locator('a[href="https://civitai.com/api/v1/model-versions/by-hash/31e35c80fc"]')).toHaveCount(1);
  await expect(page.locator('.fx-meta')).toContainText('Marked as AI-generated');
  // and in Image tools
  await page.evaluate(() => { UI.labTab = 'image'; renderMain(); });
  await page.setInputFiles('#imgIn', fixture('aigen/midjourney.png'));
  await expect(page.locator('#aigCard')).toContainText('0d6f2b7e-8c41-4a2f-9e55-31b7c2a9f004');
  await expect(page.locator('#aigCard a[href="https://www.midjourney.com/jobs/0d6f2b7e-8c41-4a2f-9e55-31b7c2a9f004"]')).toHaveCount(1);
  noErrors(errors);
});

test('VIN: maker, country, check digit and model year; a wrong check digit in a North American VIN is called out', async ({ page }) => {
  const errors = await open(page, '#/lab');
  const V = await page.evaluate(() => [vinDecode('1HGCM82633A004352'), vinDecode('1HGCM82643A004352'), vinDecode('WVWZZZ1KZ6W612345'), vinDecode('5YJ3E1EA7KF317000'), vinDecode('not a vin')]);
  expect([V[0].maker, V[0].region, V[0].check.ok, V[0].years]).toEqual(['Honda (USA)', 'United States', true, [2003]]);
  expect([V[1].check.ok, V[1].check.want]).toEqual([false, '3']);
  expect([V[2].maker, V[2].region, V[2].na]).toEqual(['Volkswagen (Germany)', 'Germany', false]);
  expect([V[3].maker, V[3].years]).toEqual(['Tesla (USA)', [2019]]);
  expect(V[4]).toBeNull();
  await page.evaluate(() => { UI.labTab = 'time'; renderMain(); });
  await page.fill('#tsIn', '1HGCM82643A004352');
  const c = page.locator('#vinOut');
  await expect(c).toContainText('Honda (USA)');
  await expect(c).toContainText('Wrong — position 9 should be 3, not 4');
  await page.fill('#tsIn', 'WVWZZZ1KZ6W612345');
  await expect(c).toContainText('most makers outside North America do not use a check digit');
  noErrors(errors);
});

test('the new playbooks open with their steps, and the OPSEC panel leads to Clean before sending', async ({ page }) => {
  const errors = await open(page, '#/playbooks');
  const P = await page.evaluate(() => { ensurePlaybooks(); return ['pb-sextortion', 'pb-pig-butchering', 'pb-deepfake', 'pb-sim-swap', 'pb-missing-person', 'pb-doxxing-defence'].map(id => { const p = DB.playbooks.find(x => x.id === id); return p ? [p.name, p.steps.length] : null; }); });
  expect(P.every(Boolean)).toBe(true);
  expect(P.map(p => p[1])).toEqual([9, 7, 8, 6, 7, 6]);
  await page.evaluate(() => { UI.pb = 'pb-sextortion'; renderMain(); });
  await expect(page.locator('#main')).toContainText('Take It Down');
  await expect(page.locator('#main')).toContainText('Never put the intimate images themselves in the case');
  await page.evaluate(() => { UI.pb = 'pb-deepfake'; renderMain(); });
  await expect(page.locator('#main')).toContainText('the AI generation card shows prompts, models, LoRAs and seeds');
  await page.evaluate(() => clickAct('opClean'));
  await expect.poll(() => page.evaluate(() => UI.route.area + ' ' + UI.labTab)).toBe('lab clean');
  await expect(page.locator('#clDrop')).toBeVisible();
  noErrors(errors);
});
