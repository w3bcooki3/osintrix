// SSH keys and decentralised accounts. The keys in fixtures/sshkeys.json are real (made with Python's cryptography
// library) and their fingerprints were computed there with hashlib, the way OpenSSH does: SHA-256 and MD5 of the key.
// The Nostr values are the NIP-19 examples and a key encoded with the reference bech32 code.
const { test, expect } = require('@playwright/test');
const { open, noErrors } = require('./helpers');
const fs = require('fs'), path = require('path');
const K = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', 'sshkeys.json'), 'utf8'));
const NIP19 = { npub: 'npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg', hex: '7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e', nsec: 'nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5' };
const OTHER = { npub: 'npub17gden739kdmkvhgkmamu6zz956t0csypmdtqfnhknvpnzssmy59sp6gzua', hex: 'f21b99fa25b377665d16df77cd0845a696fc4081db5604cef69b0331421b250b' };
const ents = (page, t) => page.evaluate(t => E.extract(t).map(e => e.k + ':' + e.v), t);

test('SSH keys: every form is the same key — a public key, an auth log line, ssh -v, a Shodan banner and Censys JSON', async ({ page }) => {
  const errors = await open(page, '#/home');
  const ed = K.ed25519, rsa = K.rsa3072, only = (L, k) => L.filter(x => x.startsWith(k + ':')).sort();
  // authorized_keys with four key types; the comment (user@host) is not read as an e-mail address
  const ak = await ents(page, [K.ed25519.pub, K.rsa3072.pub, K.dsa.pub, K.p384.pub].join('\n'));
  expect(only(ak, 'sshkey')).toEqual([K.ed25519, K.rsa3072, K.dsa, K.p384].map(k => 'sshkey:' + k.sha256).sort());
  expect(only(ak, 'email')).toEqual([]);
  expect(await ents(page, 'vps-7.example.net,203.0.113.9 ' + rsa.pub.split(' ').slice(0, 2).join(' '))).toEqual(expect.arrayContaining(['sshkey:' + rsa.sha256, 'ipv4:203.0.113.9', 'domain:vps-7.example.net']));
  expect(only(await ents(page, 'sshd[812]: Accepted publickey for root from 198.51.100.4 port 51122 ssh2: ED25519 ' + ed.sha256), 'sshkey')).toEqual(['sshkey:' + ed.sha256]);
  expect(only(await ents(page, 'The RSA key fingerprint is ' + rsa.md5.slice(4) + '.'), 'sshkey')).toEqual(['sshkey:' + rsa.md5]);
  expect(only(await ents(page, 'SSH-2.0-OpenSSH_8.9p1\nKey type: ssh-rsa\nKey: ' + rsa.pub.split(' ')[1] + '\nFingerprint: ' + rsa.md5.slice(4)), 'sshkey')).toEqual(['sshkey:' + rsa.md5, 'sshkey:' + rsa.sha256].sort());
  expect(only(await ents(page, '{"server_host_key":{"fingerprint_sha256":"' + ed.hex + '"}}'), 'sshkey')).toEqual(['sshkey:' + ed.sha256]);
  // look-alikes stay what they are
  const noise = await ents(page, 'nginx@sha256:' + 'c'.repeat(64) + ' git@github.com:org/repo.git MAC 3c:22:fb:11:22:33 SHA256:short ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAA broken');
  expect(only(noise, 'sshkey')).toEqual([]);
  expect(noise).toContain('sha256:' + 'c'.repeat(64));
  noErrors(errors);
});

test('SSH key details: type, size, weak keys, other fingerprint forms, an MD5 sighting joined to its key, and one key on several machines', async ({ page }) => {
  const errors = await open(page, '#/home');
  const rsa = K.rsa3072;
  await page.evaluate(([K, rsa]) => {
    const rec = (id, body) => DB.records.push({ id, caseId: DB.active, type: 'evidence', title: id, body, tsRaw: '', tsZone: 'explicit', ts: Date.now(), source: id, host: '', tags: [], ents: E.extract(body), answer: '', addedBy: 'You', addedAt: Date.now(), hash: '' });
    rec('known_hosts', 'vps-7.example.net,203.0.113.9 ' + rsa.pub);
    rec('censys', 'host 198.51.100.20 {"fingerprint_sha256":"' + rsa.hex + '"}');
    rec('shodan', '192.0.2.44:22 SSH-2.0-OpenSSH\nFingerprint: ' + rsa.md5.slice(4));
    rec('old keys', K.dsa.pub + '\n' + K.rsa1024.pub);
    mutate('t'); }, [K, rsa]);
  const facts = async key => { await page.evaluate(k => select('ent', k), key); return page.locator('#insp').innerText(); };
  let t = await facts('sshkey:' + rsa.sha256);
  expect(t).toContain('RSA · 3072 bits'); expect(t).toContain(rsa.hex); expect(t).toContain(rsa.md5.slice(4)); expect(t).toContain('deploy@build-rsa3072.example.com');
  expect(t).toContain('One key, 2 machines'); expect(t).toMatch(/203\.0\.113\.9|vps-7\.example\.net/); expect(t).toContain('198.51.100.20');
  // links use the forms each service searches by
  const L = await page.evaluate(v => pivotLinks('sshkey', v), rsa.sha256);
  expect(L.find(x => x[0] === 'Censys hosts')[1]).toContain(rsa.hex);
  expect(L.some(x => x[0] === 'Shodan')).toBe(false);                                  // Shodan searches MD5 fingerprints
  expect(decodeURIComponent((await page.evaluate(v => pivotLinks('sshkey', v), rsa.md5)).find(x => x[0] === 'Shodan')[1])).toContain(rsa.md5.slice(4));
  t = await facts('sshkey:' + rsa.md5);
  expect(t).toContain('Same key as ' + rsa.sha256); expect(t).toContain('RSA · 3072 bits');
  t = await facts('sshkey:' + K.dsa.sha256); expect(t).toContain('Weak or outdated key'); expect(t).toContain('DSA');
  t = await facts('sshkey:' + K.rsa1024.sha256); expect(t).toContain('Weak or outdated key'); expect(t).toContain('1024 bits');
  // a vault entry with the public key pasted is the same key as the one in the evidence
  expect(await page.evaluate(p => entryKey({ type: 'sshkey', fields: { key: p } }), rsa.pub)).toBe('sshkey:' + rsa.sha256);
  expect(await page.evaluate(h => entryKey({ type: 'sshkey', fields: { fingerprint: h } }), rsa.hex)).toBe('sshkey:' + rsa.sha256);
  noErrors(errors);
});

test('decentralised accounts: fediverse, Matrix, Nostr (npub, nprofile, signed events) and Bluesky DIDs; private keys are flagged, never kept', async ({ page }) => {
  const errors = await open(page, '#/home');
  const r = await ents(page, 'Follow @NightOwl@infosec.exchange or https://mastodon.social/@night_owl and @nightowl:matrix.org. Nostr ' + NIP19.npub +
    ', Bluesky did:plc:z72i7hdynmk6r22z27h6tvur and did:web:nightowl.example. Mail me at owl@proton.me, git@github.com:x/y, @plainhandle.');
  expect(r).toEqual(expect.arrayContaining(['fedi:@nightowl@infosec.exchange', 'fedi:@night_owl@mastodon.social', 'matrix:@nightowl:matrix.org', 'npub:' + NIP19.npub,
    'did:did:plc:z72i7hdynmk6r22z27h6tvur', 'did:did:web:nightowl.example', 'email:owl@proton.me', 'handle:@plainhandle']));
  expect(r.filter(x => /^(fedi|matrix):/.test(x)).length).toBe(3);                      // git@github.com:x is not an account
  // a signed event: the hex key is the account; the event ID and signature are not file hashes
  const ev = await ents(page, JSON.stringify({ id: 'a'.repeat(64), pubkey: OTHER.hex, created_at: 1, kind: 1, tags: [], content: 'gm', sig: 'b'.repeat(128) }));
  expect(ev).toEqual(['npub:' + OTHER.npub]);
  // nprofile carries the key and relays
  const np = await page.evaluate(h => IDKEYS.bechEncode('nprofile', Uint8Array.from([0, 32, ...h.match(/../g).map(x => parseInt(x, 16)), 1, 22, ...new TextEncoder().encode('wss://relay.damus.io/x')])), NIP19.hex);
  expect(await ents(page, 'profile ' + np)).toEqual(['npub:' + NIP19.npub]);
  expect(await ents(page, 'bad npub17gden739kdmkvhgkmamu6zz956t0csypmdtqfnhknvpnzssmy59sp6gzub')).toEqual([]);   // checksum fails
  // a private key: no entity, a masked secret warning
  expect(await ents(page, 'my key ' + NIP19.nsec)).toEqual([]);
  const sec = await page.evaluate(s => ipfSecrets('backup ' + s).map(x => [x.label, x.mask]), NIP19.nsec);
  expect(sec).toEqual([['Nostr private key', 'nsec1v…lfe5']]);

  // details and links
  await page.evaluate(() => { const t = 'contact @nightowl@owl.example, @x:homeserver.example, ' + 'did:web:nightowl.example'; DB.records.push({ id: 'acc', caseId: DB.active, type: 'evidence', title: 'acc', body: t, tsRaw: '', tsZone: 'explicit', ts: Date.now(), source: 's', host: '', tags: [], ents: E.extract(t), answer: '', addedBy: 'You', addedAt: Date.now(), hash: '' }); mutate('t'); });
  const facts = async key => { await page.evaluate(k => select('ent', k), key); return page.locator('#insp').innerText(); };
  expect(await facts('fedi:@nightowl@owl.example')).toContain('A small or personal server');
  expect(await facts('matrix:@x:homeserver.example')).toContain('A self-hosted homeserver');
  expect(await facts('did:did:web:nightowl.example')).toContain('Tied to a domain');
  const P = await page.evaluate(([n]) => ({ fedi: pivotLinks('fedi', '@nightowl@infosec.exchange'), npub: pivotLinks('npub', n), plc: pivotLinks('did', 'did:plc:z72i7hdynmk6r22z27h6tvur'), mx: pivotLinks('matrix', '@nightowl:matrix.org') }), [NIP19.npub]);
  expect(P.fedi[0]).toEqual(['Profile', 'https://infosec.exchange/@nightowl']);
  expect(P.npub[0][1]).toBe('https://njump.me/' + NIP19.npub);
  expect(P.plc.find(x => /PLC/.test(x[0]))[1]).toBe('https://plc.directory/did:plc:z72i7hdynmk6r22z27h6tvur/log/audit');
  expect(P.mx[0][1]).toBe('https://matrix.to/#/@nightowl:matrix.org');
  noErrors(errors);
});

test('accounts in the vault: typed in any form, keyed like the evidence; one name across networks is offered as related', async ({ page }) => {
  const errors = await open(page, '#/home');
  const k = await page.evaluate(([n, h]) => ['NightOwl@Infosec.Exchange', '@nightowl@infosec.exchange', '@NightOwl:Matrix.org', n.toUpperCase(), h, 'did:plc:z72i7hdynmk6r22z27h6tvur', 'nonsense'].map(v => entryKey({ type: 'daccount', fields: { id: v } })), [NIP19.npub, NIP19.hex]);
  expect(k).toEqual(['fedi:@nightowl@infosec.exchange', 'fedi:@nightowl@infosec.exchange', 'matrix:@nightowl:matrix.org', 'npub:' + NIP19.npub, 'npub:' + NIP19.npub, 'did:did:plc:z72i7hdynmk6r22z27h6tvur', null]);
  const rel = await page.evaluate(() => {
    DB.cases.push(Object.assign({}, DB.cases[0], { id: 'dx', name: 'D' }));
    const mk = (type, fields) => DB.entries.push({ id: uid('v'), caseId: 'dx', type, fields, priority: 'medium', starred: false, tags: [], notes: '', src: '', created: Date.now(), pos: null });
    mk('daccount', { id: '@nightowl_ops@infosec.exchange' }); mk('daccount', { id: '@nightowl_ops:matrix.org' }); mk('social', { url: 'https://x.com/NightOwl_Ops' }); mutate('d');
    return dupRelated('dx').filter(g => g.rel === 'name').map(g => g.G.length); });
  expect(rel).toEqual([3]);
  noErrors(errors);
});
