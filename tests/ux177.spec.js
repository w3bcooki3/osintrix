// v1.77 — the fixes from a walk through the Forensics kit, Toolbox, Query library, Detections, Entities and Settings.
// Page hash: tests/fixtures/page/phish-saved.html is a saved sign-in page as a kit ships it (form to another site, a Telegram
// bot drop, an IP lookup, right-click and F12 blocked, favicon written into the page). Its favicon hash, 1520981741, was
// worked out independently with Python's mmh3 the way Shodan documents it: mmh3.hash(codecs.encode(bytes, 'base64')).
const { test, expect } = require('@playwright/test');
const { open, fixture, noErrors } = require('./helpers');

test('save to another case or a new one: the ▾ lists every case and “New case…”, which makes the case without leaving the tool', async ({ page }) => {
  const errors = await open(page, '#/lab', { osintSample: true });
  await page.evaluate(() => { UI.labTab = 'ident'; renderMain(); });
  await page.fill('#idQ', 'n1ghtlamp'); await page.press('#idQ', 'Enter');
  const add = page.locator('[data-act=idAdd]');
  await expect(add).toContainText('Add @n1ghtlamp to');
  await add.locator('xpath=following-sibling::button[contains(@class,"ctpick")]').click();
  await expect(page.locator('#ctx .ctx-it', { hasText: 'New case…' })).toBeVisible();
  await page.locator('#ctx .ctx-it', { hasText: 'New case…' }).click();
  await page.fill('#csName', 'Night lamp persona'); await page.click('form[data-form=csNew] button.primary');
  await expect(add).toContainText('Add @n1ghtlamp to Night lamp persona');
  expect(await page.inputValue('#idQ')).toBe('n1ghtlamp');                       // still on the tool, nothing lost
  await add.click();
  const r = await page.evaluate(() => { const c = DB.cases.find(x => x.name === 'Night lamp persona'); return { active: DB.active === c.id, n: DB.entries.filter(e => e.caseId === c.id && entryKey(e) === 'handle:@n1ghtlamp').length, code: !!c.code }; });
  expect(r).toEqual({ active: true, n: 1, code: true });
  // a name already used is refused
  await add.locator('xpath=following-sibling::button[contains(@class,"ctpick")]').click();
  await page.locator('#ctx .ctx-it', { hasText: 'New case…' }).click();
  await page.fill('#csName', 'Night lamp persona'); await page.click('form[data-form=csNew] button.primary');
  await expect(page.locator('#csName')).toHaveAttribute('aria-invalid', 'true');
  // the screens that only offered the open case now have the ▾ too
  for (const [tab, act] of [['geo', 'geoSave'], ['fav', null]]) { await page.evaluate(t => { UI.labTab = t; renderMain(); }, tab); if (act) { await page.fill('#geoIn', '40.774411, -73.918212'); await expect(page.locator(`[data-act=${act}] + .ctpick`)).toBeVisible(); } }
  noErrors(errors);
});

test('query library: “Record the search in” picks any case, nowhere, or a new case', async ({ page, context }) => {
  const errors = await open(page, '#/queries');
  await page.evaluate(() => { UI.qsel = DB.queries[0].id; UI.qopen = true; renderMain(); });
  await expect(page.locator('#qLog')).toBeVisible();
  await expect(page.locator('label.qp-log')).toContainText('Record the search in');
  const opts = await page.locator('#qLog option').allTextContents();
  expect(opts).toContain('Nowhere — don\'t record it'); expect(opts).toContain('New case…');
  // fill any blanks so the link can run
  await page.evaluate(() => document.querySelectorAll('[id^="qv-"]').forEach(i => { i.value = 'acme.example'; i.dispatchEvent(new Event('input', { bubbles: true })); }));
  // the search opens in a new tab; the note about where it was recorded shows at once, so read it before closing the tab
  const run = async want => { const tab = context.waitForEvent('page', { timeout: 5000 }).catch(() => null); await page.click('#qRunLink'); await expect(page.locator('.toast')).toContainText(want); const p = await tab; if (p) await p.close(); };
  await page.selectOption('#qLog', 'c-portal');
  const n0 = await page.evaluate(() => DB.records.filter(r => r.caseId === 'c-portal').length);
  await run('recorded in Customer portal');
  expect(await page.evaluate(() => DB.records.filter(r => r.caseId === 'c-portal').length)).toBe(n0 + 1);
  await page.selectOption('#qLog', '');
  const all0 = await page.evaluate(() => DB.records.length);
  await run('not recorded');
  expect(await page.evaluate(() => DB.records.length)).toBe(all0);
  noErrors(errors);
});

test('look-alikes: Generate lists every candidate at once, a row opens Investigate, Clear empties it, watched domains can be dropped', async ({ page }) => {
  const errors = await open(page, '#/lab');
  await page.evaluate(() => { UI.labTab = 'twist'; DB.prefs.twSeen = { 'acme-corp.com': { at: Date.parse('2026-11-01'), list: ['acme-c0rp.com', 'acmecorp.co'] } }; renderMain(); });
  await page.fill('#twD', 'harbour-line-portal.test'); await page.press('#twD', 'Enter');
  const rows = page.locator('.tw-tbl tbody tr');
  await expect(rows.first()).toBeVisible();
  expect(await rows.count()).toBe(150);                                          // first page of the candidates
  await expect(rows.first()).toContainText('not checked');
  await page.click('[data-act=twMore]'); expect(await rows.count()).toBeGreaterThan(150);
  // watched: a list with when and how many, and a way to stop watching
  await expect(page.locator('.tw-wl li')).toHaveCount(1);
  await expect(page.locator('.tw-wl li')).toContainText('checked 2026-11-01 · 2 existed');
  // Enter on a row, like a click, opens Investigate on it
  const d = await rows.first().getAttribute('data-v');
  await rows.first().focus(); await page.keyboard.press('Enter');
  await expect.poll(() => page.evaluate(() => UI.look && UI.look.v)).toBe(d);
  await page.evaluate(() => { UI.labTab = 'twist'; go('#/lab'); });
  await page.click('[data-act=twUnwatch][data-v="acme-corp.com"]');
  await expect(page.locator('.tw-wl')).toHaveCount(0);
  expect(await page.evaluate(() => Object.keys(DB.prefs.twSeen))).toEqual([]);
  await page.click('[data-act=labToolClear][data-v=twist]');
  await expect(page.locator('.tw-tbl')).toHaveCount(0); expect(await page.inputValue('#twD')).toBe('');
  noErrors(errors);
});

test('tool history: off unless switched on; then the last 10 per tool, reusable, and forgotten when switched off', async ({ page }) => {
  const errors = await open(page, '#/lab');
  await page.evaluate(() => { UI.labTab = 'hash'; renderMain(); });
  await page.fill('#hashIn', '5f4dcc3b5aa765d61d8327deb882cf99'); await page.locator('#hashIn').blur();
  await expect(page.locator('.lab-strip .chip')).toHaveCount(0);                // off by default: nothing kept
  expect(await page.evaluate(() => (DB.work && DB.work.hist) || null)).toBe(null);
  await page.evaluate(() => go('#/settings')); await page.click('[data-act=toolHist][data-v=on]');
  await page.evaluate(() => { UI.labTab = 'hash'; go('#/lab'); });
  for (let i = 0; i < 12; i++) { await page.fill('#hashIn', 'a'.repeat(31) + i.toString(16)); await page.locator('#hashIn').blur(); }
  await page.evaluate(() => renderMain());
  await expect(page.locator('.lab-strip .chip')).toHaveCount(10);
  await page.click('[data-act=labToolClear][data-v=hash]');
  expect(await page.inputValue('#hashIn')).toBe('');
  await page.locator('.lab-strip .chip').first().click();
  expect(await page.inputValue('#hashIn')).toBe('a'.repeat(31) + 'b');           // the most recent first
  // each tool keeps its own
  await page.evaluate(() => { UI.labTab = 'geo'; renderMain(); }); await expect(page.locator('.lab-strip .chip')).toHaveCount(0);
  await page.evaluate(() => go('#/settings')); await page.click('[data-act=toolHist][data-v=off]');
  expect(await page.evaluate(() => (DB.work && DB.work.hist) || null)).toBe(null);
  noErrors(errors);
});

test('page hash: what a saved kit page loads and sends — form fields, the Telegram drop with its token hidden, the IP check, anti-analysis, its favicon', async ({ page }) => {
  const errors = await open(page, '#/lab');
  await page.evaluate(() => { UI.labTab = 'fav'; renderMain(); });
  await page.setInputFiles('#favIn', fixture('page/phish-saved.html'));
  const card = page.locator('section.card', { hasText: 'What the page loads and sends' });
  await expect(card).toContainText('A form asks for a password and card details and sends what is typed to another site: collect.harbourline-verify.test.');
  await expect(card.locator('.fx-note.red')).toHaveCount(2);
  await expect(card).toContainText('Telegram bot API (api.telegram.org)');
  await expect(card).toContainText('ipapi.co'); await expect(card).toContainText('Anti-analysis: right-click blocked, F12 blocked.');
  await expect(card).not.toContainText('AAH4kq9Zx2Lm8Pq7Rt6Yu5Io4Pa3Sd2Fg1H');     // the bot token never shows
  await expect(card).toContainText('(token hidden)');
  await expect(card.locator('.fxs-fields .chip.red')).toHaveText(['pass', 'card_number', 'cvv']);
  await expect(card).toContainText('Shodan hash 1520981741');
  expect(await card.locator('.fxs-fav img').evaluate(i => i.complete && i.naturalWidth > 0)).toBe(true);
  await expect(card).toContainText('saved from secure-login.harbour-line-bank.test');
  await expect(card).toContainText('1 saved with the page');
  // the browser's own "saved from" note is never a comment or a query (it can carry a local path)
  const piv = await page.locator('.fx-pv').allTextContents();
  expect(piv.join(' ')).not.toMatch(/saved from url/);
  expect(piv.join(' ')).toContain('http.favicon.hash:1520981741');
  // a page with nothing in it says so instead of an empty card
  await page.click('[data-act=favClear]');
  await page.setInputFiles('#favIn', { name: 'plain.html', mimeType: 'text/html', buffer: Buffer.from('<!doctype html><html><head><title>Hello</title></head><body><p>Hi</p></body></html>') });
  await expect(page.locator('section.card', { hasText: 'What the page loads and sends' })).toContainText('Nothing to report');
  noErrors(errors);
});

test('hashes: crypt and capture strings are taken apart, base64 and LDAP digests become hex, JWTs and text are decoded', async ({ page }) => {
  const errors = await open(page, '#/lab');
  await page.evaluate(() => { UI.labTab = 'hash'; renderMain(); });
  const rows = { '{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=': ['LDAP SHA-1', '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8'],   // SHA-1("password")
    'X03MO1qnZdYdgyfeuILPmQ==': ['Base64 MD5', '5f4dcc3b5aa765d61d8327deb882cf99'],                                // MD5("password")
    '$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/db01.corp.local~1433*$ab$cd': ['Kerberoast', 'MSSQLSvc/db01.corp.local:1433'],
    'admin::CORP:1122334455667788:0123456789abcdef0123456789abcdef:0101000000000000': ['NetNTLMv2', 'CORP'],
    '$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW': ['bcrypt', '4,096 rounds'],
    'eyJhbGciOiJub25lIn0.eyJzdWIiOiJhbGljZSIsImV4cCI6MTcwMDAwMDAwMH0.': ['JWT (JSON Web Token)', 'not signed and can be forged'],
    '68656c6c6f20776f726c64': ['decoded below', 'hello world'],
    'WPA*02*4d4fe58c8d4a3c4b1a5e6f7a8b9c0d1e*a0b1c2d3e4f5*112233445566*486f6d65*aa*bb*00': ['hashcat -m 22000', 'Home'],
    '$office$*2013*100000*256*16*aa*bb*cc': ['Microsoft Office document password', 'hashcat -m 9400'] };
  await page.fill('#hashIn', Object.keys(rows).join('\n'));
  const out = page.locator('#hashOut .hrow');
  await expect(out).toHaveCount(Object.keys(rows).length);
  let i = 0; for (const [, want] of Object.entries(rows)) { for (const w of want) await expect(out.nth(i)).toContainText(w); i++; }
  // the decoded base64 digest gets the same hash lookups as hex
  await expect(out.nth(1).locator('.pivots a').first()).toBeVisible();
  noErrors(errors);
});

test('toolbox: a tool can name its own lookup type; one OSINTrix recognises makes it show under Look up', async ({ page }) => {
  const errors = await open(page, '#/toolbox');
  for (const [name, kind, want] of [['IBAN checker', 'IBAN', 'iban'], ['Plate lookup', 'licence plate', null]]) {
    await page.evaluate(() => toolDlg());
    await page.fill('#tName', name); await page.fill('#tUrl', 'https://' + name.split(' ')[0].toLowerCase() + '.example.org/'); await page.fill('#tTpl', 'https://' + name.split(' ')[0].toLowerCase() + '.example.org/q={value}'); await page.fill('#tKindOther', kind);
    await page.click('form[data-form=tool] button[type=submit]'); await expect(page.locator('form[data-form=tool]')).toHaveCount(0);
    const t = await page.evaluate(n => { const x = DB.tools.find(t => t.name === n); return { kinds: x.kinds, other: x.kindOther }; }, name);
    expect(t.other).toBe(kind); if (want) expect(t.kinds).toContain(want); else expect(t.kinds).toEqual(['any']);   // not something OSINTrix picks out, so it is offered for any value
  }
  expect(await page.evaluate(() => toolTplLinks('iban', 'GB29NWBK60161331926819').map(x => x[0]))).toContain('IBAN checker');
  noErrors(errors);
});

test('layout: Settings has no gap above Storage, persona cards keep their buttons inside, the Query library control is labelled', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  const errors = await open(page, '#/settings', { osintSample: true });
  const g = await page.evaluate(() => { const ap = [...document.querySelectorAll('section.card')].find(s => /Appearance/.test(s.querySelector('h3') ? s.querySelector('h3').textContent : '')), st = document.getElementById('storage');
    return st.getBoundingClientRect().top - ap.getBoundingClientRect().bottom; });
  expect(g).toBeGreaterThan(10); expect(g).toBeLessThan(26);
  await page.evaluate(() => go('#/entities'));
  await expect(page.locator('.ps-card').first()).toBeVisible();
  const spill = await page.evaluate(() => [...document.querySelectorAll('.ps-card')].map(c => { const r = c.getBoundingClientRect(); return [...c.querySelectorAll('footer .btn')].some(b => b.getBoundingClientRect().right > r.right + 0.5); }));
  expect(spill.every(x => !x)).toBe(true);
  await expect(page.locator('.ps-card [data-act=psProfile] + .ctpick').first()).toBeVisible();
  noErrors(errors);
});

test('no action name is claimed both by a feature map and by the main switch (one would silently shadow the other)', async ({ page }) => {
  const errors = await open(page, '#/home');
  const src = require('fs').readFileSync(require('path').resolve(__dirname, '..', 'js', 'app.js'), 'utf8');
  const sw = [...src.matchAll(/^\s*case '([A-Za-z0-9_]+)':/gm)].map(m => m[1]);
  const mapped = await page.evaluate(() => [...actIndex().keys()]);
  expect(sw.filter(k => mapped.includes(k))).toEqual([]);
  noErrors(errors);
});
