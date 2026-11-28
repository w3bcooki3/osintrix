// Document forensics in the File inspector: a PDF whose second save "redacted" an IBAN (the earlier version and the
// removed line come back; the embedded file and the JavaScript are shown; pdftotext and pypdf read the fixture as
// valid), Word tracked deletions / hidden and white text / comments / the people list with account IDs, Excel hidden
// and very hidden sheets and a linked workbook on a file share, PowerPoint notes and a hidden slide, and an .eml with a
// mismatched link, failed authentication and a shortcut attachment that opens on its own.
const { test, expect } = require('@playwright/test');
const { open, fixture, noErrors } = require('./helpers');

async function inspect(page, f) {
  await page.evaluate(() => { UI.labTab = 'file'; UI.labFile = null; renderMain(); });
  await page.setInputFiles('#labIn', fixture(f));
  await expect.poll(() => page.evaluate(() => !!(UI.labFile && !UI.labFile.busy && UI.labFile.sha256)), { timeout: 30000 }).toBe(true);
}
const card = (page, h) => page.locator(`section.card:has(h3:has-text("${h}"))`);

test('a PDF saved twice gives back the version before the redaction, its embedded file and its script', async ({ page }) => {
  const errors = await open(page, '#/lab');
  await inspect(page, 'docs/redacted-invoice.pdf');
  const c = card(page, 'PDF forensics');
  await expect(c).toContainText('2 versions in this file');
  await expect(c).toContainText('Adobe Acrobat Pro 24.1');
  await expect(c).toContainText('IBAN DE89 3704 0044 0532 0130 00');                 // in version 1, gone from version 2
  await expect(c).not.toContainText('Wire transfer approved by Jane Roe');            // unchanged lines are not listed as removed
  await expect(c).toContainText('passwords.txt'); await expect(c).toContainText("app.alert('Please enable editing')");
  await expect(c).toContainText('ABCDEF+Calibri-Bold'.replace('ABCDEF+', ''));
  const iocs = await page.evaluate(() => UI.labFile.iocs.map(e => e.k + ' ' + e.v));
  expect(iocs.some(x => /^iban /i.test(x) || /DE89/.test(x))).toBe(true);
  // the earlier version opens on its own and has no second save
  await c.locator('[data-act=dxOpen]:has-text("Open this version")').click();
  await expect.poll(() => page.evaluate(() => UI.labFile && UI.labFile.name)).toBe('redacted-invoice-version1.pdf');
  await expect(page.locator('.fi-sum')).toContainText('taken out of redacted-invoice.pdf');
  await expect(page.locator('pre.strs')).toContainText('IBAN DE89');
  // and the embedded file
  await inspect(page, 'docs/redacted-invoice.pdf');
  await card(page, 'PDF forensics').locator('.kv:has-text("passwords.txt") [data-act=dxOpen]').click();
  await expect.poll(() => page.evaluate(() => UI.labFile && UI.labFile.name)).toBe('passwords.txt');
  await expect(page.locator('pre.strs')).toContainText('vpn.corp.example admin / Hunter2-2025');
  noErrors(errors);
});

test('Word, Excel and PowerPoint: deleted, hidden and white text, comments, people, hidden sheets, notes', async ({ page }) => {
  const errors = await open(page, '#/lab');
  await inspect(page, 'docs/board-memo.docx');
  const w = card(page, 'Word forensics');
  await expect(w).toContainText('Halvorsen Logistics, paid through our Cyprus account');
  await expect(w).toContainText('Mark Vance'); await expect(w).toContainText('2025-03-05 16:20 UTC');
  await expect(w).toContainText('Do not share outside the board: margin 41%');
  await expect(w).toContainText('contact m.vance@protonmail.com (white or tiny text)');
  await expect(w).toContainText('Remove the Cyprus detail before this goes out');
  await expect(w).toContainText('S::jane.roe@corp.example::0f9e8d7c-1111-2222-3333-444455556666');
  await expect(w).toContainText('Windows Live');
  await expect(w).toContainText('ORCA-7'); await expect(w).toContainText('Internal - Finance');
  await expect(w).toContainText('3 —');                                                 // rsids
  const ents = await page.evaluate(() => UI.labFile.iocs.map(e => e.v));
  expect(ents).toContain('m.vance@protonmail.com');
  await w.locator('[data-act=fxZipOpen][data-v="word/media/image1.jpg"]').click();      // the picture inside keeps its own metadata
  await expect.poll(() => page.evaluate(() => UI.labFile && UI.labFile.name)).toBe('image1.jpg');
  await expect(page.locator('.fx-meta')).toContainText('Adobe Photoshop 25.0');
  await inspect(page, 'docs/payouts.xlsx');
  const x = card(page, 'Excel forensics');
  await expect(x).toContainText('Payouts'); await expect(x).toContainText('Keys (very hidden');
  await expect(x).toContainText('Wallets → Keys!$A$1:$A$20 (hidden)');
  await expect(x).toContainText('fs01.corp.local');
  await expect(x).toContainText('split across the two mules');
  await expect(x).toContainText('mvance@corp.example');
  await inspect(page, 'docs/pitch.pptx');
  const p = card(page, 'PowerPoint forensics');
  await expect(p).toContainText('Hidden slides'); await expect(p).toContainText('Do not mention the Brightline talks'); await expect(p).toContainText('Priya Shah');
  const sum = await page.evaluate(() => labSummary(UI.labFile));
  expect(sum).toContain('Speaker notes: 1 slides');
  noErrors(errors);
});

test('an .eml: who sent it, where replies go, failed authentication, a lying link, and the attachment opened on its own', async ({ page }) => {
  const errors = await open(page, '#/lab');
  await inspect(page, 'docs/parcel-notice.eml');
  const m = card(page, 'E-mail message');
  await expect(m).toContainText('Your parcel is on hold — action needed');           // the encoded subject, decoded
  await expect(m).toContainText('PHPMailer 6.8.0');
  await expect(m).toContainText('Replies go to support@dhl-redelivery.example');
  await expect(m).toContainText('Authentication failed: spf=fail');
  await expect(m).toContainText('https://www.dhl.com/track → https://dhl-redelivery.example/track?id=99');
  await expect(m).toContainText('203.0.113.77'); await expect(m).toContainText('198.51.100.40');
  await expect(m).toContainText('commonly used to deliver malware');
  await m.locator('.kv:has-text("Invoice.pdf.lnk") [data-act=dxOpen]').click();
  await expect.poll(() => page.evaluate(() => UI.labFile && UI.labFile.name)).toBe('Invoice.pdf.lnk');
  await expect(card(page, 'Windows shortcut (LNK)')).toContainText('desktop-7f3k2a');
  await inspect(page, 'docs/parcel-notice.eml');
  await page.click('[data-act=dxHeaders]');
  await expect(page.locator('#emlIn')).toHaveValue(/Authentication-Results/);
  noErrors(errors);
});

test('an Outlook .msg (extract-msg reads the fixture too): sender, reply-to, recipients, the HTML attachment opened and its phishing form read', async ({ page }) => {
  const errors = await open(page, '#/lab');
  await inspect(page, 'docs/remittance.msg');
  const m = card(page, 'Outlook message');
  await expect(m).toContainText('Payment remittance advice — 12 March');
  await expect(m).toContainText('no-reply@microsoft.com');
  await expect(m).toContainText('Replies go to billing@invoice-portal.example');
  await expect(m).toContainText('dmarc=fail');
  await expect(m).toContainText('Mike Jones'); await expect(m).toContainText('198.51.100.91');
  await m.locator('.kv:has-text("Remittance-Advice.html") [data-act=dxOpen]').click();
  await expect.poll(() => page.evaluate(() => UI.labFile && UI.labFile.name)).toBe('Remittance-Advice.html');
  const iocs = await page.evaluate(() => UI.labFile.iocs.map(e => e.v));
  expect(iocs.some(v => /login-m365\.invoice-portal\.example/.test(v))).toBe(true);
  noErrors(errors);
});

test('delivery containers: an ISO with a hidden DLL behind a shortcut, a OneNote with an HTA inside, a RAR with a disguised script', async ({ page }) => {
  const errors = await open(page, '#/lab');
  await inspect(page, 'docs/invoice.iso');      // built with pycdlib (ISO 9660 + Joliet), one file marked hidden
  const i = card(page, 'Disk image (ISO / IMG)');
  await expect(i).toContainText('INVOICE_0311'); await expect(i).toContainText('IMGBURN V2.5.8.0');
  await expect(i).toContainText('Invoice.lnk'); await expect(i).toContainText('data/loader.dll');
  await expect(i).toContainText('1 hidden file: data/loader.dll');
  await expect(i).toContainText('skips the “downloaded from the internet” warning');
  await expect(page.locator('.fi-sum')).toContainText('Disk image (ISO 9660)');
  await i.locator('.ziplist div:has-text("Invoice.lnk") [data-act=dxOpen]').click();
  await expect.poll(() => page.evaluate(() => UI.labFile && UI.labFile.name)).toBe('Invoice.lnk');
  await expect(card(page, 'Windows shortcut (LNK)')).toContainText('powershell.exe');
  await inspect(page, 'docs/click-to-view.one');
  const o = card(page, 'OneNote notebook');
  await expect(o).toContainText('1 embedded file'); await expect(o).toContainText('HTML application (HTA)');
  await o.locator('[data-act=dxOpen]').click();
  await expect.poll(() => page.evaluate(() => UI.labFile && UI.labFile.name)).toBe('embedded-1.hta');
  expect(await page.evaluate(() => UI.labFile.iocs.map(e => e.v))).toContain('http://198.51.100.12/p.ps1');
  await inspect(page, 'docs/scan.rar');         // rarfile lists the same entry
  const r = card(page, 'RAR archive');
  await expect(r).toContainText('RAR4'); await expect(r).toContainText('Scan_0311.pdf.cmd'); await expect(r).toContainText('2025-03-11 09:20');
  await expect(r).toContainText('Inside: Scan_0311.pdf.cmd');
  noErrors(errors);
});
