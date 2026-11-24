// Forensics kit, OSINT tools: dates inside IDs (Bluesky, Slack, Discord) and fresh accounts in chat exports; favicon and
// page fingerprints with the Shodan hashes checked against Python's mmh3; a phishing kit unpacked to its bot, drop email,
// SMTP account, author, anti-bot files and YARA hit; a stealer log read into machines and accounts with "your domains"
// marked; a company footprint from (mocked) Google DNS and CertSpotter; and the look-alike watch marking new ones.
const { test, expect } = require('@playwright/test');
const { open, fixture, noErrors } = require('./helpers');
const fs = require('fs');

const tool = async (page, t) => { await page.evaluate(t => { UI.labTab = t; renderMain(); }, t); };
const JSONH = { 'access-control-allow-origin': '*', 'content-type': 'application/json' };

test('dates inside IDs: Bluesky, Slack and Discord links; a Discord account made days before it posted', async ({ page }) => {
  const errors = await open(page, '#/lab');
  const r = await page.evaluate(() => {
    /* a Bluesky record key for 2024-05-01 12:00 UTC, built the way the PDS builds one */
    const t = BigInt(Date.UTC(2024, 4, 1, 12, 0, 0)) * 1000n, A = '234567abcdefghijklmnopqrstuvwxyz'; let n = (t << 10n) | 7n, k = ''; for(let i = 0; i < 13; i++){ k = A[Number(n & 31n)] + k; n >>= 5n; }
    const pick = (s, re) => (decodeIds(s).find(x => re.test(x[0])) || [])[1];
    return { bs: pick('https://bsky.app/profile/alice.bsky.social/post/' + k, /Bluesky/), slack: pick('https://acme.slack.com/archives/C024BE91L/p1700000000123456', /Slack/),
      dcu: pick('https://discord.com/users/175928847299117063', /Discord account/), tg: decodeIds('https://t.me/somechannel/123').map(x => x[2]).join(' '),
      w: idWhen('url', 'https://acme.slack.com/archives/C024BE91L/p1700000000123456') };
  });
  expect(r.bs).toBe(Date.UTC(2024, 4, 1, 12, 0, 0));
  expect(r.slack).toBe(1700000000123);
  expect(r.dcu).toBe(1462015105796);                  // Discord's own documented example: 2016-04-30 11:18:25.796 UTC
  expect(r.tg).toContain('carry no date');
  expect(r.w.what).toBe('Posted (Slack message)');
  // a Discord export whose author's account was made two days before the first message
  const first = Date.UTC(2025, 2, 10, 9, 0, 0), id = String(BigInt(first - 2 * 864e5 - 1420070400000) << 22n);
  const exp = { guild: { id: '1', name: 'Airdrop Hub' }, channel: { id: '2', type: 'GuildTextChat', name: 'claims' }, messages: [
    { id: '10', timestamp: new Date(first).toISOString(), author: { id, name: 'claims_helper', nickname: 'Claims Helper' }, content: 'DM me to claim your airdrop, connect wallet at the link' },
    { id: '11', timestamp: new Date(first + 6e4).toISOString(), author: { id: '80351110224678912', name: 'oldtimer', nickname: 'Old' }, content: 'is this legit?' }] };
  await page.evaluate(async e => { DB.active = 'c-lantern'; await importChats([new File([JSON.stringify(e)], 'claims.json', { type: 'application/json' })]); }, exp);
  const body = await page.evaluate(() => DB.records.find(r => r.chatAuthor && r.chatAuthor.names[0].uname === 'claims_helper').body);
  expect(body).toContain('Discord account created: 2025-03-08 09:00 UTC (2 days before the first message here)');
  await page.evaluate(() => { UI.ivView = 'chats'; go(caseHash('c-lantern', 'infra')); });
  await expect(page.locator('section.card:has(h3:has-text("Accounts made just before they posted"))')).toContainText('Claims Helper');
  await expect(page.locator('section.card:has(h3:has-text("Accounts made just before they posted"))')).not.toContainText('Old');
  await page.evaluate(id => select('ent', 'dcid:' + id), id);
  await expect(page.locator('#insp')).toContainText('Made 2 days before its first message');
  noErrors(errors);
});

test('favicon and page fingerprints match Python mmh3, with the pivots to run', async ({ page }) => {
  const errors = await open(page, '#/lab');
  await tool(page, 'fav');
  await page.setInputFiles('#favIn', fixture('forensic/favicon.ico'));
  // python3: mmh3.hash(codecs.encode(open('favicon.ico','rb').read(), 'base64')) → 111367185
  await expect(page.locator('#main')).toContainText('111367185');
  await expect(page.locator('#main')).toContainText('e2e3a4047050fe3f8fb7f755fadcc83b');
  const links = await page.locator('a.fx-pv').evaluateAll(a => a.map(x => x.href));
  expect(links).toContain('https://www.shodan.io/search?query=' + encodeURIComponent('http.favicon.hash:111367185'));
  expect(links.some(u => u.startsWith('https://urlscan.io/search/#hash%3A3f69d9e1'))).toBe(true);
  await page.click('[data-act=favClear]');
  await page.setInputFiles('#favIn', fixture('forensic/kit-page.html'));
  // python3: mmh3.hash(open('kit-page.html','rb').read()) → -1578560311 (Shodan http.html_hash)
  await expect(page.locator('#main')).toContainText('-1578560311');
  for (const id of ['G-7QX2B9KD4M', 'UA-118273645-2', 'pub-1234567890123456', '91234567', '1234567890123456']) await expect(page.locator('#main')).toContainText(id);
  await expect(page.locator('#main')).toContainText('kit by @lampdev v4.2');
  await expect(page.locator('#main')).toContainText('https://lantern-verify.example.net/submit.php');
  await expect(page.locator('#main')).toContainText('1 password field');
  const q = await page.locator('a.fx-pv small').allTextContents();
  expect(q).toContain('"UA-118273645-2"'); expect(q).toContain('http.html_hash:-1578560311'); expect(q).toContain('"t.me/lantern_support_bot" -site:t.me');
  await page.click('[data-act=favSave]');
  await expect(page.locator('#capBody')).toHaveValue(/Google Analytics: UA-118273645-2, G-7QX2B9KD4M/);
  noErrors(errors);
});

test('a phishing kit: where the data goes, who made it, how it hides, YARA and the packer time zone', async ({ page }) => {
  const errors = await open(page, '#/lab');
  await tool(page, 'kit');
  await page.setInputFiles('#kitIn', fixture('forensic/office365-kit.zip'));
  await expect.poll(() => page.evaluate(() => !!(UI.fxKit && !UI.fxKit.busy))).toBe(true);
  const m = page.locator('#main');
  await expect(m).toContainText('Imitates'); await expect(m).toContainText('Microsoft');
  await expect(m).toContainText('Bot 6091234567'); await expect(m).not.toContainText('AAHk9x_Zq2LmN4pQr7sTuVwXyZ01234abcd');   // the token is shortened, never shown whole
  await expect(m).toContainText('-1001987654321');
  await expect(m).toContainText('rezults.drop2024@gmail.com');
  await expect(m).toContainText('smtp.mail-relay.example.org as noreply@office-docs-share.example.org');
  await expect(m).toContainText('rezult.txt');
  await expect(m).toContainText('ScamaKing');
  await expect(m).toContainText('antibots.php'); await expect(m).toContainText('geo-filtering'); await expect(m).toContainText('obfuscated block');
  await expect(m).toContainText('passwords');
  await expect(m).toContainText('Phishing Kit Sending Victim Data to Telegram');
  await expect(m).toContainText('UTC+03:00');
  await page.click('[data-act=kitSave]');
  await expect(page.locator('#capBody')).toHaveValue(/Telegram bot ID: 6091234567[\s\S]*Drop email: rezults\.drop2024@gmail\.com/);
  noErrors(errors);
});

test('a stealer log: machines, the build tag, your accounts and live sessions marked, passwords masked', async ({ page }) => {
  const errors = await open(page, '#/lab');
  await tool(page, 'steal');
  await page.fill('#slMine', 'corp.example');
  await page.waitForTimeout(400);
  await page.setInputFiles('#slIn', fixture('forensic/stealer-logs.zip'));
  await expect.poll(() => page.evaluate(() => !!(UI.fxSteal && !UI.fxSteal.busy))).toBe(true);
  const v = page.locator('.sl-v');
  await expect(v).toHaveCount(2);
  await expect(v.first()).toContainText('DESKTOP-MJ01'); await expect(v.first()).toContainText('mjones');
  await expect(v.first()).toContainText('Mar_traffic_7'); await expect(v.first()).toContainText('8F3C2A91D44E5B07A6C1E9F2B3D45A61');
  await expect(v.first()).toContainText('C:\\Users\\mjones\\AppData\\Local\\Temp\\Setup_Win_x64.exe');
  await expect(v.first()).toContainText('2 of your logins, 1 live session cookies');
  await expect(v.first().locator('tr.mine')).toHaveCount(2);
  await expect(v.first()).toContainText('login.microsoftonline.com');
  await expect(v.first()).toContainText('Wi••••••••• (11)'); await expect(v.first()).not.toContainText('Winter2025!');
  await expect(v.first()).toContainText('Exodus');
  await expect(v.nth(1)).toContainText('LAPTOP-KLAUS'); await expect(v.nth(1)).toContainText('lumma_eu_04');
  await expect(v.nth(1).locator('tr.mine')).toHaveCount(1);
  await page.click('[data-act=slShow]');
  await expect(v.first()).toContainText('Winter2025!');
  await page.click('[data-act=slSave]');
  await expect(page.locator('#capBody')).toHaveValue(/Build tag: Mar_traffic_7[\s\S]*login\.microsoftonline\.com — m\.jones@corp\.example \[OURS\]/);
  await expect(page.locator('#capBody')).not.toHaveValue(/Winter2025/);   // passwords never go into the case
  noErrors(errors);
});

test('company footprint from DNS and certificates (mocked), and the look-alike watch marks what is new', async ({ page }) => {
  await page.route(/^https:\/\/(?!dns\.google|api\.certspotter\.com)[^/]+\//, r => r.abort());
  let live = new Set(['acme-corp.com']);
  await page.route('https://dns.google/**', r => { const u = new URL(r.request().url()), n = u.searchParams.get('name'), t = u.searchParams.get('type');
    const A = []; let st = 3;
    if (n === 'acme-corp.com') { st = 0;
      if (t === 'MX') A.push({ type: 15, data: '0 acmecorp-com.mail.protection.outlook.com.' });
      if (t === 'TXT') A.push({ type: 16, data: '"v=spf1 include:spf.protection.outlook.com include:sendgrid.net -all"' }, { type: 16, data: '"MS=ms12345678"' }, { type: 16, data: '"google-site-verification=abc"' }, { type: 16, data: '"atlassian-domain-verification=xyz"' }, { type: 16, data: '"docusign=1234-5678"' }, { type: 16, data: '"knowbe4-site-verification=q"' });
      if (t === 'A') A.push({ type: 1, data: '203.0.113.10' });
      if (t === 'NS') A.push({ type: 2, data: 'ns1.dnsprovider.example.' }); }
    else if (n === '_dmarc.acme-corp.com' && t === 'TXT') { st = 0; A.push({ type: 16, data: '"v=DMARC1; p=none; rua=mailto:d@rua.agari.com"' }); }
    else if (n === 'selector1._domainkey.acme-corp.com') { st = 0; A.push({ type: 5, data: 'selector1-acmecorp-com._domainkey.acmecorp.onmicrosoft.com.' }); }
    else if (n === 'autodiscover.acme-corp.com') { st = 0; A.push({ type: 5, data: 'autodiscover.outlook.com.' }, { type: 1, data: '52.97.1.1' }); }
    else if (n === 'vpn.acme-corp.com') { st = 0; A.push({ type: 1, data: '203.0.113.20' }); }
    else if (live.has(n)) { st = 0; if (t === 'A') A.push({ type: 1, data: '198.51.100.66' }); if (t === 'MX' && n === 'acme-c0rp.com') A.push({ type: 15, data: '10 mail.acme-c0rp.com.' }); }
    r.fulfill({ headers: JSONH, body: JSON.stringify({ Status: st, Answer: A.length ? A : undefined }) }); });
  await page.route('https://api.certspotter.com/**', r => { const d = new URL(r.request().url()).searchParams.get('domain');
    const C = d === 'acme-corp.com' ? [{ not_before: '2023-01-05T00:00:00Z', dns_names: ['acme-corp.com', 'www.acme-corp.com'], issuer: { friendly_name: "Let's Encrypt" } }, { not_before: '2025-02-01T00:00:00Z', dns_names: ['dev-api.acme-corp.com', 'jenkins.acme-corp.com'], issuer: { friendly_name: "Let's Encrypt" } }]
      : d === 'acme-c0rp.com' ? [{ not_before: new Date(Date.now() - 3 * 864e5).toISOString(), dns_names: ['acme-c0rp.com'], issuer: { friendly_name: "Let's Encrypt" } }] : [];
    r.fulfill({ headers: JSONH, body: JSON.stringify(C) }); });
  const errors = await open(page, '#/lab');
  await tool(page, 'corp');
  await page.click('[data-act=fpOn]');
  await page.fill('#fpD', 'acme-corp.com'); await page.click('form[data-form=fpGo] button[type=submit]');
  const m = page.locator('#main');
  await expect(m).toContainText('Microsoft 365 (Exchange Online)');
  await expect(m).toContainText('SendGrid (Twilio)');
  for (const s of ['Microsoft 365', 'Google (Search Console / Workspace)', 'Atlassian (Jira, Confluence)', 'DocuSign', 'KnowBe4 (phishing training)']) await expect(m.locator('.chip', { hasText: s }).first()).toBeVisible();
  await expect(m).toContainText('DMARC is at p=none');
  await expect(m).toContainText('reports to rua.agari.com');
  await expect(m).toContainText('selector1 (Microsoft 365)');
  await expect(m).toContainText('autodiscover.acme-corp.com → autodiscover.outlook.com');
  await expect(m).toContainText('vpn.acme-corp.com');
  await expect(m).toContainText('jenkins.acme-corp.com');
  await expect(m).toContainText('names worth a look');
  await page.click('[data-act=fpSave]');
  await expect(page.locator('#capBody')).toHaveValue(/Verified SaaS: Microsoft 365, Google \(Search Console \/ Workspace\), Atlassian/);
  await page.click('[data-act=dclose]').catch(() => {}); await page.keyboard.press('Escape');
  // look-alikes: first check finds one, the second finds a new one
  live.add('acmecorp.com');
  await page.evaluate(() => { const S = lkSettings(); S.on.dns = true; S.on.cs = true; UI.tw = { d: 'acme-corp.com', list: twGen('acme-corp.com') }; UI.labTab = 'twist'; renderMain(); });
  await page.click('[data-act=twCheck]');
  await expect(page.locator('.tw-tbl tbody tr')).toHaveCount(1, { timeout: 60000 });
  await expect.poll(() => page.evaluate(() => UI.tw.running)).toBe(false);
  await expect(page.locator('.tw-tbl .chip', { hasText: 'new' })).toHaveCount(0);
  live.add('acme-c0rp.com');
  await page.click('[data-act=twCheck]');
  await expect.poll(() => page.evaluate(() => !UI.tw.running && UI.tw.list.filter(x => x.exists).length), { timeout: 60000 }).toBe(2);
  const row = page.locator('.tw-tbl tbody tr', { hasText: 'acme-c0rp.com' });
  await expect(row.locator('.chip', { hasText: 'new' })).toBeVisible();
  await expect(row).toContainText('certificate issued 3 days ago');
  await expect(page.locator('.tw-watch')).toContainText('1 new');
  await expect(page.locator('.tw-watch [data-act=twWatch][data-v="acme-corp.com"]')).toBeVisible();
  noErrors(errors);
});
