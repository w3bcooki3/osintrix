// Dark web, OSINT side only: onion addresses checked offline (version, checksum, vanity look-alikes, mirror lists) and the
// identities that last across markets — OpenPGP keys read from their armoured blocks (fingerprint, date, names and emails).
// The keys in fixtures/darkweb were made with GnuPG; the fingerprints below are the ones GnuPG printed for them.
const { test, expect } = require('@playwright/test');
const { open, capture, noErrors, fixture } = require('./helpers');
const fs = require('fs'), path = require('path');
const FX = f => fs.readFileSync(path.join(__dirname, 'fixtures', 'darkweb', f), 'utf8');

const REAL = 'lampmarketvizzs3la5cjrdngrveqnvyb4nv72hlqzk3csmyxcoi7dqd.onion';   // valid v3, made for the test
const FAKE = 'lampmarketwxkuyopgmzy4s4y3t5dr4wc5qjrm2t2usy7qzeyifz52yd.onion';   // valid v3, same first 10 characters
const MIRROR = 'lampmarkxxnhn5bo5m3wifm5zwyj7vmnjy25dr3xx72u4mjamudzkayd.onion';
const TYPO = 'lampmarketvizzs3la5cjrdngrveqnvyb4nv72hlqzk3csmyxcoi7dqe.onion';   // last character changed
const LAMP = '488452521EEFD616BD2C409F52BFD7383C520E37', LAMPSUB = '0A6CAD219B7A004BB12164FA92214447D04632AC', OLD = '28A15CB71AC749D877557461D8192EF39C6C139E';

test('onion addresses: version, checksum, a look-alike made by key grinding, a mirror list — and nothing is looked up online', async ({ page }) => {
  const net = []; page.on('request', r => { if (!/^(file|data|blob):/.test(r.url())) net.push(r.url()); });
  const errors = await open(page, '#/case/c-lantern/vault');
  // the dark-web technique reference: SHA3-256 and the Tor checksum, against known values
  const v = await page.evaluate(() => { const h = a => a.map(x => x.toString(16).padStart(2, '0')).join(''), b = s => [...s].map(c => c.charCodeAt(0));
    return [h(E.sha3_256(b('abc'))), E.sha1(b('abc')), E.onionInfo('duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion').ok]; });
  expect(v).toEqual(['3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532', 'a9993e364706816aba3e25717850c26c9cd0d89d', true]);
  await capture(page, `Lamp Market mirrors (official):\nhttp://${REAL}/\nhttp://${MIRROR}/\nold: 3g2upl4pq6kufc4m.onion`, 'c-lantern');
  await capture(page, `Posted on a forum: the new Lamp Market link is http://${FAKE}/login — and a broken copy ${TYPO}`, 'c-lantern');
  const P = page.locator('#insp');
  const prof = async d => { await page.evaluate(id => select('ent', id), 'domain:' + d); return P.locator('.ipf'); };
  let f = await prof(REAL);
  await expect(f).toContainText('Tor version3 — ed25519 key'); await expect(f).toContainText('ChecksumValid');
  await expect(f).toContainText('Listed with1 other onion in the same text');
  await expect(f).toContainText('Starts like 1 other onion in your cases'); await expect(f).toContainText('Same first 10 characters');
  await expect(f).not.toContainText('machine-generated');                                       // every onion looks random; that is not a finding
  await expect(P.locator('a[href^="https://ahmia.fi/search/?q="]').first()).toBeVisible();
  await expect(P.locator('a[href*="virustotal.com"]')).toHaveCount(0);
  f = await prof(TYPO); await expect(f).toContainText('Checksum fails');
  f = await prof('3g2upl4pq6kufc4m.onion'); await expect(f).toContainText('Version 2 onion — dead since October 2021');
  expect(net).toEqual([]);
  noErrors(errors);
});

test('PGP keys: an armoured key gives its fingerprint, date, algorithm and every name and email on it; the same key in two cases ties them', async ({ page }) => {
  const errors = await open(page, '#/case/c-lantern/vault');
  const lamp = FX('lamp.asc'), old = FX('old.asc');
  // parsed in the page, compared with what GnuPG printed
  const K = await page.evaluate(([a, b]) => [E.pgpParse(a).map(k => [k.fp, k.sub, k.algo, k.curve, k.uids.length]), E.pgpParse(b).map(k => [k.fp, k.algo, k.bits])], [lamp, old]);
  expect(K).toEqual([[[LAMP, false, 'EdDSA', 'Ed25519', 2], [LAMPSUB, true, 'ECDH', 'Curve25519', 0]], [[OLD, 'RSA', 3072]]]);
  // a vendor profile pasted from a market: the key block yields the fingerprint and the two emails inside it; its base64 yields nothing else
  await capture(page, `Vendor: lamp_ops — ships worldwide\nContact only with PGP:\n${lamp}\nPayment XMR only.`, 'c-lantern');
  const E1 = await page.evaluate(() => E.extract(DB.records[DB.records.length - 1].body).map(x => x.k + ' ' + x.v));
  expect(E1.sort()).toEqual(['email lamp@onionmail.example', 'email lampvendor@proton.example', 'pgp ' + LAMP].sort());
  // the same key on a forum, written as a spaced fingerprint, in another case
  await capture(page, `dread user lamp_ops signs with ${LAMP.replace(/(.{4})/g, '$1 ').trim().replace(/^((?:\S{4} ){5})/, '$1 ')}`, 'c-portal');
  await capture(page, `Their old key fingerprint: ${OLD}\nchecksum of the image: ${'ab'.repeat(20)}`, 'c-portal');
  const E2 = await page.evaluate(() => DB.records.filter(r => r.caseId === 'c-portal').slice(-2).flatMap(r => E.extract(r.body).map(x => x.k + ' ' + x.v)));
  expect(E2).toEqual(expect.arrayContaining(['pgp ' + LAMP, 'pgp ' + OLD, 'sha1 ' + 'ab'.repeat(20)]));   // a fingerprint by its words; any other 40-hex stays a hash
  await page.evaluate(id => select('ent', id), 'pgp:' + LAMP);
  const P = page.locator('#insp'), f = P.locator('.ipf');
  await expect(f).toContainText('AlgorithmEdDSA · Ed25519'); await expect(f).toContainText('User IDLamp Vendor <lampvendor@proton.example>');
  await expect(f).toContainText('User IDlamp_ops (dread) <lamp@onionmail.example>'); await expect(f).toContainText('SubkeysECDH Curve25519');
  await expect(f).toContainText('2 names on one key'); await expect(f).toContainText('Made in the last 30 days');
  await expect(P).toContainText('Customer portal');                                              // seen in both cases
  await expect(P.locator('a[href="https://keys.openpgp.org/search?q=' + LAMP + '"]').first()).toBeVisible();
  // only a fingerprint known: it says what would tell more
  await page.evaluate(id => select('ent', id), 'pgp:' + OLD);
  await expect(P.locator('.ipf')).toContainText('paste the public key block');
  noErrors(errors);
});

test('a vendor page saved from Tor Browser: the site from its links, the profile it is about, mirrors, contacts and the key — then the same Session ID in another case makes a persona', async ({ page }) => {
  const errors = await open(page, '#/case/c-lantern/vault');
  const html = FX('vendor-page.html');
  await page.evaluate(async h => { DB.active = 'c-lantern'; await importWebPages([new File([h], 'lamp_ops - Vendor profile.html', { type: 'text/html' })]); }, html);
  const r = await page.evaluate(() => { const r = DB.records.filter(x => x.caseId === 'c-lantern').pop(); return { t: r.title, tags: r.tags, b: r.body, k: r.ents.map(e => e.k + ' ' + e.v) }; });
  expect(r.t).toBe('Onion page: lamp_ops — Vendor profile — Lamp Market'); expect(r.tags).toContain('darkweb');
  expect(r.b).toContain('URL: http://' + REAL + '/ (site only — Tor Browser records no page address)');
  expect(r.b).toContain(`Onion site: ${REAL} (from where its links point — the saved file records no address) · version 3, checksum valid`);
  expect(r.b).toContain('Page subject: @lamp_ops');
  expect(r.b).toContain('Profiles linked on the page (3): @lamp_ops, @nightowl_77, @br4dl3y');   // the forum profile on another onion is not this site's
  expect(r.b).toContain('Listed as mirrors or new links (1):\n' + MIRROR);
  expect(r.b).toContain('Holds a PGP-signed message'); expect(r.b).toContain('Prices mentioned: $450, 0.71 XMR, 120 USD');
  const tox = '8670CD4BC81724FD3677BA631CD815397A01DBE4333A6E742FBC14920D268DDD123456782116', ses = '053f3af1ecebbd1410ab417ec0d27bbfcb5d340e177ae159b59fc8626c2dfd9175';
  expect(r.k).toEqual(expect.arrayContaining(['pgp ' + LAMP, 'email lampvendor@proton.example', 'session ' + ses, 'tox ' + tox, 'domain ' + MIRROR, 'handle @lamp_ops']));
  const fileHash = /SHA-256 of saved file: (\w+)/.exec(r.b)[1];
  expect(r.k.filter(k => /^(sha256|sha512|md5|sol|soltx) /.test(k))).toEqual(['sha256 ' + fileHash]);   // only the saved file's own hash: messenger IDs are not hashes, the key block yields no junk
  await page.evaluate(t => select('ent', 'tox:' + t), tox); await expect(page.locator('#insp .ipf')).toContainText('ChecksumValid');
  // the same operator on a forum, in another case, under another name — tied by the Session ID
  await capture(page, `Thread: anyone tried lampvendor2? Posted by @lampvendor2 — for bulk deals message me on Session ${ses}`, 'c-portal');
  const P = await page.evaluate(() => personas().map(p => ({ names: p.names, ties: p.ties, cases: p.cases.sort() })));
  const mine = P.find(p => p.ties.includes('session:' + ses));
  expect(mine).toBeTruthy(); expect(mine.cases).toEqual(['c-lantern', 'c-portal']);
  expect(mine.names).toEqual(expect.arrayContaining(['handle:@lamp_ops', 'handle:@lampvendor2'])); expect(mine.names).not.toContain('handle:@nightowl_77');   // buyers in the feedback are not the vendor
  await page.evaluate(() => go('#/entities'));
  const card = page.locator('.ps-card', { hasText: 'lampvendor2' });
  await expect(card).toContainText('2 cases'); await expect(card).toContainText('same Session ID in 2 records across');
  // made into a profile in the active case: a Person linked to each identifier, the PGP key with its names
  await page.evaluate(() => { DB.active = 'c-portal'; renderMain(); });
  await card.locator('[data-act=psProfile]').click();
  const prof = await page.evaluate(() => { const p = DB.entries.filter(e => e.caseId === 'c-portal' && e.type === 'person').pop(), L = DB.links.filter(l => l.a === p.id).map(l => entryById(l.b)); return { name: p.fields.name, types: L.map(e => e.type).sort(), key: (L.find(e => e.type === 'pgpkey') || {}).fields }; });
  expect(prof.name).toMatch(/^Operator behind /); expect(prof.types).toEqual(expect.arrayContaining(['email', 'pgpkey', 'username', 'crypto']));
  expect(prof.key.fingerprint).toBe(LAMP); expect(prof.key.uids).toContain('lamp_ops (dread) <lamp@onionmail.example>');
  // an identifier in it says so in its panel
  await page.evaluate(k => select('ent', k), 'session:' + ses); await expect(page.locator('#insp')).toContainText('Part of a persona');
  noErrors(errors);
});
