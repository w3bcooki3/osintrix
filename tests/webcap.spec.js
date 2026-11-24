// Web captures in the File inspector. The fixtures are what the tools really write: a Chrome-style HAR (haralyzer reads
// it), a WARC.GZ written with warcio (a chunked, gzip-encoded answer and a JSON checkout with card data), the same archive
// as a WACZ, and a Chrome "single file" MHTML (Python's email parser reads its parts). The Shodan favicon and page hashes
// were checked against Python's mmh3.
const { test, expect } = require('@playwright/test');
const { open, fixture, noErrors } = require('./helpers');

async function inspect(page, f) {
  await page.evaluate(() => { UI.labTab = 'file'; UI.labFile = null; renderMain(); });
  await page.setInputFiles('#labIn', fixture(f));
  await expect.poll(() => page.evaluate(() => !!(UI.labFile && !UI.labFile.busy && UI.labFile.sha256)), { timeout: 30000 }).toBe(true);
}

test('a HAR of a phishing visit: the redirect chain, the login and the Telegram drop (masked), the IP check, the file handed out, the fingerprint', async ({ page }) => {
  const errors = await open(page, '#/lab');
  await inspect(page, 'web/phish-visit.har');
  const c = page.locator('#wcCard');
  await expect(page.locator('.fi-sum')).toContainText('Web capture (HAR)');
  await expect(c).toContainText('Sign in to your account');
  await expect(c).toContainText('WebInspector 537.36');
  // bit.ly → 302 tracker → a page that refreshes itself onward → the kit
  const chain = c.locator('.wc-chain li');
  await expect(chain).toHaveCount(4);
  await expect(chain.nth(0)).toContainText('https://bit.ly/3xQpKz7');
  await expect(chain.nth(3)).toContainText('secure-m365.login-portal.example/owa/');
  await expect(chain.nth(3)).toContainText('meta refresh');
  await expect(chain.nth(3)).toContainText('198.51.100.23');
  await expect(c).toContainText('A password was sent to secure-m365.login-portal.example');
  await expect(c).toContainText('Data was sent to a Telegram bot API (api.telegram.org)');
  await expect(c).toContainText("looked up the visitor's IP and location (ipapi.co)");
  await expect(c).toContainText('challenges.cloudflare.com');
  // what was typed: the e-mail shows, the password and the bot token never do
  const send = c.locator('.wc-send').first();
  await expect(send).toContainText('jane.doe@corp.example');
  await expect(send).toContainText('W•••••••••! (11 characters)');
  const html = await c.innerHTML();
  expect(html).not.toContain('Winter2025');
  expect(html).not.toContain('AAHk3jL9vX2mQp8sTn4RwYz6BcDeFgHiJkL');
  await expect(c).toContainText('bot7012345678:AAH•••• (token hidden)');
  await expect(c).toContainText('-1001987654321');
  const iocs = await page.evaluate(() => UI.labFile.iocs.map(e => e.k + ' ' + e.v));
  expect(iocs).toContain('ipv4 198.51.100.23');
  expect(iocs).toContain('domain cdn-verify.example');
  expect(iocs.some(x => /Winter2025|AAHk3jL9/.test(x))).toBe(false);
  expect(iocs.some(x => /code\.jquery\.com|googletagmanager/.test(x))).toBe(false);          // libraries and analytics are not indicators
  // sites, server software, the fingerprint (Shodan hashes match Python's mmh3)
  await expect(c.locator('.wc-host:has-text("secure-m365.login-portal.example")')).toContainText('nginx/1.18.0 (Ubuntu) · PHP/7.4.3');
  await expect(c.locator('.wc-host.hot')).toContainText('api.telegram.org');
  await expect(c).toContainText('122570858');
  await expect(c).toContainText('606405659');
  await expect(c).toContainText('G-7QK2M9XW3P');
  await c.locator('summary:has-text("pivots")').click();
  await expect(c.locator('a.fx-pv[href*="606405659"]').first()).toBeVisible();
  // the file the page handed out opens on its own, and the script inside is read
  await c.locator('.kv:has-text("Invoice_0311.zip") [data-act=dxOpen]').click();
  await expect.poll(() => page.evaluate(() => UI.labFile && UI.labFile.name)).toBe('Invoice_0311.zip');
  await expect(page.locator('.ziplist')).toContainText('Invoice_0311.pdf.js');
  noErrors(errors);
});

test('a WARC.GZ and the same archive as WACZ: gzip members, a chunked and compressed answer, card data masked, the wallet on the page', async ({ page }) => {
  const errors = await open(page, '#/lab');
  for (const [f, kind] of [['web/shop-capture.warc.gz', 'Web archive (WARC)'], ['web/shop-capture.wacz', 'Web archive (WACZ)']]) {
    await inspect(page, f);
    const c = page.locator('#wcCard');
    await expect(page.locator('.fi-sum')).toContainText(kind);
    await expect(c).toContainText('Webrecorder ArchiveWeb.page 0.12.8');
    await expect(c).toContainText('Mega Sale -90%');                                     // read through chunked + gzip
    await expect(c.locator('.wc-chain li')).toHaveCount(2);
    await expect(c).toContainText('Card details were sent to shop-deals.example');
    await expect(c.locator('.wc-send')).toContainText('card.card_number');
    await expect(c.locator('.wc-send')).toContainText('4••••••••••1 (16 characters)');
    expect(await c.innerHTML()).not.toContain('4111111111111111');
    await expect(c).toContainText('98123456');                                           // Yandex Metrica counter
    const iocs = await page.evaluate(() => UI.labFile.iocs.map(e => e.k + ' ' + e.v));
    expect(iocs).toContain('trx TQ5Wn3kF8bJXhW1xY9mZ4pRt7vS2aD6cLe');
    expect(iocs).toContain('email support@shop-deals.example');
    expect(iocs).toContain('ipv4 192.0.2.77');
  }
  noErrors(errors);
});

test('an MHTML saved from Chrome: the page, its favicon hash, and a form that sends a wallet phrase to another site', async ({ page }) => {
  const errors = await open(page, '#/lab');
  await inspect(page, 'web/claim-airdrop.mhtml');
  const c = page.locator('#wcCard');
  await expect(page.locator('.fi-sum')).toContainText('Saved web page (MHTML)');
  await expect(c).toContainText('Wallet Connect — Claim airdrop');                         // quoted-printable decoded
  await expect(c).toContainText('2025-03-13 21:02:11 UTC');
  await expect(c).toContainText("The page's form sends what is typed to collect.drop-site.example");
  await expect(c).toContainText('asks for a wallet recovery phrase');
  await expect(c).toContainText('606405659');
  await expect(c).toContainText('@airdrop_helpdesk_bot');
  const iocs = await page.evaluate(() => UI.labFile.iocs.map(e => e.k + ' ' + e.v));
  expect(iocs).toContain('domain collect.drop-site.example');
  expect(await page.evaluate(() => UI.labFile.mail)).toBeNull();                          // not mistaken for an e-mail
  noErrors(errors);
});
