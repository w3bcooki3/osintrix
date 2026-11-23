// Indicator profile: what a value is and what should worry you about it, read from the value alone.
const { test, expect } = require('@playwright/test');
const { open, capture, noErrors, budget } = require('./helpers');

const prof = (page, k, v) => page.evaluate(([k, v]) => { const P = ipfProfile(k, v); return { flags: P.flags.map(f => f.lvl + ' ' + f.t), facts: Object.fromEntries(P.facts) }; }, [k, v]);
const has = (P, re) => P.flags.some(f => re.test(f));

test('profile: look-alikes of brands are caught the ways attackers make them, and real names are left alone', async ({ page }) => {
  const errors = await open(page);
  const cases = [
    ['xn--80ak6aa92e.com', /^bad Looks like apple\.com$/],                 // punycode of Cyrillic “аррӏе”
    ['аррӏе.com', /^bad Looks like apple\.com$/],
    ['paypa1.com', /^bad Looks like paypal\.com$/],                         // digit for a letter
    ['rnicrosoft.com', /^bad Looks like microsoft\.com$/],                  // rn drawn as m
    ['micros0ft-online.net', /^bad Looks like microsoft\.com with other words$/],
    ['amazom.com', /^bad One letter off amazon\.com$/],
    ['paypal.com.account-verify.top', /^bad paypal\.com used as a subdomain of account-verify\.top$/],
    ['dhl-parcel-tracking.com', /^warn Uses the name dhl with other words$/],
    ['paypal.xyz', /^warn Same name as paypal\.com on another ending \(\.xyz\)$/],
    ['раураl.com', /^bad Mixes Latin and Cyrillic letters in one name$/],
  ];
  for (const [d, re] of cases) { const P = await prof(page, 'domain', d); expect(has(P, re), d + ' → ' + P.flags.join(' | ')).toBe(true); }
  // the punycode is shown decoded, and which letter is foreign is named
  const A = await page.evaluate(() => ipfProfile('domain', 'xn--80ak6aa92e.com'));
  expect(Object.fromEntries(A.facts)['Shown as']).toBe('аррӏе.com');
  expect(A.flags[0].why).toMatch(/Cyrillic “а” \(U\+0430\)/);
  // real names, brands' own other domains, and words that merely contain a brand: no warnings
  const fine = ['google.com', 'paypal.com', 'login.microsoftonline.com', 'mail.google.com', 'pineapple.com', 'applebees.com', 'snapple.com', 'teslamotors.com', 'chaseprivateclient.com', 'stackoverflow.com', 'wikipedia.org',
    'thing.com', 'opening.com', 'pups.com', 'githubusercontent.com', 'paypalobjects.com', 'tmobile.com', 'docusign.net', 'att.net', 'ups.edu', 'github.io', 'example.com', 'shop.example.com'];
  const noisy = await page.evaluate(L => L.map(d => [d, ipfProfile('domain', d).flags.filter(f => f.lvl !== 'info').map(f => f.t)]).filter(x => x[1].length), fine);
  expect(noisy).toEqual([]);
  noErrors(errors);
});

test('profile: hosting, URL tricks, addresses, hashes and wallets are read correctly', async ({ page }) => {
  const errors = await open(page);
  expect(has(await prof(page, 'domain', 'kq3vxz8hjwptl.com'), /^warn Name looks machine-generated/)).toBe(true);
  expect(has(await prof(page, 'domain', 'abc.duckdns.org'), /^warn Dynamic DNS name on duckdns\.org/)).toBe(true);
  expect(has(await prof(page, 'domain', 'quiet-moon.trycloudflare.com'), /^warn Tunnel on trycloudflare\.com/)).toBe(true);
  const pg = await prof(page, 'domain', 'login-paypal.pages.dev');
  expect(pg.facts['Registered name']).toBe('login-paypal.pages.dev — a name on pages.dev');   // the user's name, not the platform, is what to judge
  expect(has(pg, /^info Free hosting on pages\.dev/)).toBe(true);
  // URLs
  expect(has(await prof(page, 'url', 'https://paypal.com@evil.top/login'), /^bad Text before @ hides the real host/)).toBe(true);
  const num = await prof(page, 'url', 'http://3232235777/'); expect(has(num, /^bad Host written as a number/)).toBe(true); expect(num.facts.Host).toBe('192.168.1.1');
  const red = await prof(page, 'url', 'https://evil.top/r?url=https%3A%2F%2Fsteal.example%2Fx'); expect(red.facts['Goes on to']).toBe('steal.example');
  const em = await page.evaluate(() => ipfProfile('url', 'https://evil.top/p?e=dmljdGltQGNvcnAuZXhhbXBsZQ==').flags.find(f => f.em));
  expect(em.why).toContain('victim@corp.example');   // the base64 in the link is read
  expect(has(await prof(page, 'url', 'http://203.0.113.9/a.exe'), /^warn Downloads a\.exe/)).toBe(true);
  // addresses
  expect(has(await prof(page, 'ipv4', '8.8.8.8'), /^info Google Public DNS/)).toBe(true);
  expect(has(await prof(page, 'ipv4', '169.254.169.254'), /^info Cloud metadata service/)).toBe(true);
  expect((await prof(page, 'ipv6', '2002:c000:0204::1')).facts['Holds IPv4']).toBe('192.0.2.4');
  expect((await prof(page, 'ipv6', '2001:0:4136:e378:8000:63bf:3fff:fdd2')).facts['Holds IPv4']).toBe('192.0.2.45');
  expect((await prof(page, 'ipv6', 'fe80::21a:2bff:fe3c:4d5e')).facts['Built from MAC']).toBe('00:1a:2b:3c:4d:5e');
  // hashes
  expect(has(await prof(page, 'sha256', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'), /^info Hash of an empty file/)).toBe(true);
  expect(has(await prof(page, 'md5', '44d88612fea8a8f36de82e1278abb02f'), /^info EICAR antivirus test file/)).toBe(true);
  // wallets: the bech32 checksum catches one wrong character
  expect((await prof(page, 'btc', 'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq')).facts.Checksum).toBe('Valid (bech32)');
  expect(has(await prof(page, 'btc', 'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdr'), /^bad Checksum fails/)).toBe(true);
  expect((await prof(page, 'btc', 'bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297')).facts).toMatchObject({ Type: 'Taproot (P2TR)', Checksum: 'Valid (bech32m)' });
  // email: the mailbox and its domain
  const e = await prof(page, 'email', 'billing@paypa1.com'); expect(has(e, /^bad Looks like paypal\.com/)).toBe(true); expect(has(e, /^info Role mailbox/)).toBe(true);
  expect((await prof(page, 'email', 'j.doe+shop@gmail.com')).facts['Same inbox as']).toBe('jdoe@gmail.com');
  // a thousand domains profile quickly
  const ms = await page.evaluate(() => { IPF.cache.clear(); const t = performance.now(); for (let i = 0; i < 1000; i++) ipfProfile('domain', 'host' + i + '-portal' + (i % 7) + '.example' + (i % 3 ? '.com' : '.top')); return performance.now() - t; });
  expect(ms).toBeLessThan(await budget(page, 400));
  noErrors(errors);
});

test('profile: secrets in captured text are found and only ever shown masked', async ({ page }) => {
  const errors = await open(page);
  const tg = '5212345678:AA' + 'Hq3xZ9kLmN0pQrStUvWxYz1234567890a', gh = 'ghp_' + 'Zx9Qw8Er7Ty6Ui5Op4As3Df2Gh1Jk0Lz9Xc8', aws = 'AKIAZ7QXJ3K2L4M5N6P7';
  const S = await page.evaluate(t => ipfSecrets(t).map(s => [s.label, s.mask, s.lvl]), `token=${tg}\nkey ${aws} and example AKIAIOSFODNN7EXAMPLE\n${gh}\n` +
    'jwt eyJhbGciOiJub25lIn0.eyJpc3MiOiJodHRwczovL2xvZ2luLmV4YW1wbGUiLCJzdWIiOiJhbGljZSIsImV4cCI6NDEwMjQ0NDgwMH0.\nftp://admin:hunter2@files.example.com/x\n-----BEGIN OPENSSH PRIVATE KEY-----');
  expect(S).toEqual([
    ['AWS access key', 'AKIAZ7…N6P7', 'bad'], ['AWS access key', 'AKIAIO…MPLE', 'info'], ['GitHub token', 'ghp_Zx…9Xc8', 'bad'],
    ['Telegram bot token', '5212345678:AA…890a', 'bad'], ['Private key', '-----BEGIN OPENSSH PRIVATE KEY-----', 'bad'],
    ['JSON Web Token', 'eyJhbG…MH0.', 'bad'], ['Password in a link', 'ftp://admin:••••@files.example.com', 'bad']]);
  const jwt = await page.evaluate(t => ipfSecrets(t)[0].why, 'eyJhbGciOiJub25lIn0.eyJpc3MiOiJodHRwczovL2xvZ2luLmV4YW1wbGUiLCJzdWIiOiJhbGljZSIsImV4cCI6NDEwMjQ0NDgwMH0.');
  expect(jwt).toMatch(/^Issued by https:\/\/login\.example, for alice, expires 2100-01-01\. Unsigned \(alg “none”\)/);
  noErrors(errors);
});

test('profile: a captured phishing kit is read in the record and the indicator, a look-alike of your own client is caught, and the vault flags it', async ({ page }) => {
  const errors = await open(page, '#/case/c-lantern/timeline');
  const tg = '5212345678:AA' + 'Hq3xZ9kLmN0pQrStUvWxYz1234567890a';
  // the client's real domain, marked benign
  await page.evaluate(() => { DB.verdicts['domain:harbourline.example'] = 'benign'; save(); });
  await capture(page, `Phishing kit config\nLanding https://secure-login.paypa1.com/verify/account?e=dmljdGltQGNvcnAuZXhhbXBsZQ==\nMirror https://portal.harbourIine.example/sso\n$bot = '${tg}';`);
  const rid = await page.evaluate(() => DB.records[DB.records.length - 1].id);
  await page.evaluate(id => select('rec', id), rid);
  const sec = page.locator('#insp .ipf');
  await expect(sec.locator('h4')).toContainText('Worth a second look');
  await expect(sec).toContainText('secure-login.paypa1.com/verify/account');
  await expect(sec).toContainText('looks like paypal.com');
  await expect(sec).toContainText('victim@corp.example');   // the link was made for one person
  await expect(sec).toContainText('harbourline.example is marked benign in your cases');
  await expect(sec).toContainText('Telegram bot token 5212345678:AA…890a');
  expect(await sec.innerHTML()).not.toContain(tg.split(':')[1]);   // the finding never shows the whole token
  // the indicator's own profile, opened from there
  await sec.locator('button.ipf-f', { hasText: 'harbouriine' }).click();
  const ip = page.locator('#insp .ipf');
  await expect(ip.locator('h4')).toContainText('Profile');
  await expect(ip.locator('.ipf-f.bad b').first()).toHaveText('Looks like harbourline.example');
  await expect(ip.locator('dl')).toContainText('Registered nameharbouriine.example');
  // in the vault: the card and the row say so, and a filter finds every such entry
  await page.evaluate(() => { const e = { id: uid('e'), caseId: 'c-lantern', type: 'domain', fields: { domain: 'paypa1.com' }, tags: [], notes: '', priority: 'medium', starred: false, created: Date.now(), conf: 2 };
    DB.entries.push(e); mutate('test entry'); DB.prefs.vLay = 'cards'; UI.vq = 'paypa1'; go(caseHash('c-lantern', 'vault')); renderMain(); });
  await expect(page.locator('.ecard', { hasText: 'paypa1.com' }).locator('.ec-sig li.pf')).toHaveText('Looks like paypal.com');
  await expect(page.locator('#main tr', { hasText: 'paypa1.com' })).toHaveCount(0);
  await page.evaluate(() => { UI.vq = ''; DB.prefs.vLay = 'list'; renderMain(); });
  await expect(page.locator('#main tr', { hasText: 'paypa1.com' }).locator('.vflag')).toHaveText('Looks like paypal.com');
  await page.evaluate(() => { DB.prefs.vLay = 'cards'; renderMain(); });
  await page.selectOption('#vb-Only', 'flagged');
  await expect(page.locator('#main .ecard .val', { hasText: /^paypa1\.com$/ })).toHaveCount(1);
  const shown = (await page.locator('#main .ecard[data-id]').evaluateAll(L => L.filter(c => entryById(c.dataset.id)).map(c => c.querySelector('.val').textContent))).sort();   // vault cards, not the found-in-evidence ones below
  const want = await page.evaluate(() => DB.entries.filter(e => e.caseId === 'c-lantern' && ipfEntryFlag(e, true)).map(primary).sort());
  expect(shown).toEqual(want);
  expect(want).not.toContain('n1ghtlamp@mail.example');   // mail.example is not “one letter off gmail.com”
  noErrors(errors);
});

test('profile: accessible in both themes', async ({ page }) => {
  const AxeBuilder = require('@axe-core/playwright').default;
  const errors = await open(page, '#/case/c-lantern/timeline');
  await capture(page, 'Kit: https://paypal.com@secure-login.paypa1.com/verify?e=dmljdGltQGNvcnAuZXhhbXBsZQ== token 5212345678:AAHq3xZ9kLmN0pQrStUvWxYz1234567890a');
  for (const theme of ['light', 'dark']) {
    await page.evaluate(t => { DB.prefs.theme = t; applyPrefs(); renderAll(); const r = DB.records[DB.records.length - 1]; select('rec', r.id); }, theme);
    await expect(page.locator('#insp .ipf')).toBeVisible();
    const a = await new AxeBuilder({ page }).include('#insp').analyze();
    expect(a.violations.filter(v => ['serious', 'critical'].includes(v.impact)).map(v => v.id + ': ' + v.nodes.map(n => n.target).join(' '))).toEqual([]);
    await page.evaluate(() => select('ent', 'domain:secure-login.paypa1.com'));
    await expect(page.locator('#insp .ipf .ipf-f').first()).toBeVisible();
    const b = await new AxeBuilder({ page }).include('#insp').analyze();
    expect(b.violations.filter(v => ['serious', 'critical'].includes(v.impact)).map(v => v.id + ': ' + v.nodes.map(n => n.target).join(' '))).toEqual([]);
  }
  noErrors(errors.filter(e => !/Connecting to 'file:.*violates the following Content Security Policy directive: "connect-src/.test(e)));   // axe reads the stylesheets; the CSP blocks that
});
