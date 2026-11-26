// Web search links from a node or the details panel: each engine is asked for every common way the value is written,
// as exact phrases joined by OR (Yandex: |), not only the one spelling that was saved.
const { test, expect } = require('@playwright/test');
const { open, noErrors } = require('./helpers');

const q = (links, name) => { const l = links.find(x => x[0] === name); return l ? decodeURIComponent(l[1].split(/[?&](?:q|text)=/)[1]) : null; };

test('each kind is searched in all its usual forms, on Google, Bing, DuckDuckGo and Yandex', async ({ page }) => {
  const errors = await open(page, '#/home');
  await page.evaluate(() => lazyNeed('phone'));
  const L = await page.evaluate(() => Object.fromEntries([
    ['phone', '+447700900123'], ['phoneUS', '+12125550123'], ['email', 'night.owl@proton.me'], ['handle', '@nightowl_ops'], ['social', 'x.com/NightOwl_Ops'],
    ['person', 'Jordan Okafor'], ['person3', 'Mary Ann Smith'], ['organization', 'Harbourline Logistics Ltd'], ['domain', 'harbourline-refunds.example'],
    ['sha256', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'], ['imo', '9074729'], ['tail', 'G-EUPT'], ['coords', '60.39,5.32']
  ].map(([k, v]) => [k, pivotLinks(k.replace(/US$|3$/, ''), v)])));

  expect(q(L.phone, 'Google')).toBe('"+447700900123" OR "+44 7700 900123" OR "07700 900123" OR "07700-900123" OR "07700900123" OR "7700900123"');
  expect(q(L.phoneUS, 'Google')).toBe('"+12125550123" OR "+1 212 555 0123" OR "(212) 555-0123" OR "212-555-0123" OR "2125550123"');
  expect(q(L.email, 'Google')).toBe('"night.owl@proton.me" OR "night.owl at proton.me" OR "night.owl at proton dot me"');
  expect(q(L.handle, 'Google')).toBe('"nightowl_ops"');
  expect(q(L.social, 'Google')).toBe('"x.com/NightOwl_Ops" OR "NightOwl_Ops"');
  expect(q(L.person, 'Google')).toBe('"Jordan Okafor" OR "Okafor, Jordan" OR "Okafor Jordan"');
  expect(q(L.person3, 'Google')).toBe('"Mary Ann Smith" OR "Mary Smith" OR "Smith, Mary" OR "Smith Mary"');
  expect(q(L.organization, 'Google')).toBe('"Harbourline Logistics Ltd" OR "Harbourline Logistics"');
  expect(q(L.domain, 'Google')).toBe('"harbourline-refunds.example" -site:harbourline-refunds.example');
  expect(q(L.sha256, 'Google')).toBe('"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"');
  expect(q(L.imo, 'Google')).toBe('"IMO 9074729" OR "9074729"');
  expect(q(L.tail, 'Google')).toBe('"G-EUPT" OR "GEUPT"');
  // every engine gets the same forms; Yandex joins them with |
  expect(q(L.person, 'Bing')).toBe(q(L.person, 'Google')); expect(q(L.person, 'DuckDuckGo')).toBe(q(L.person, 'Google'));
  expect(q(L.person, 'Yandex')).toBe('"Jordan Okafor" | "Okafor, Jordan" | "Okafor Jordan"');
  // services stay first, each engine once, and a place is not web-searched
  for (const k of Object.keys(L)) expect(L[k].filter(x => x[0] === 'Google').length).toBe(k === 'coords' ? 0 : 1);
  expect(L.phone[0][0]).toBe('WhatsApp');
  expect(L.sha256.slice(0, 2).map(x => x[0])).toEqual(['VirusTotal', 'MalwareBazaar']);
  expect(Object.values(L).flat().every(([, u]) => /^https:\/\//.test(u))).toBe(true);
  noErrors(errors);
});

test('the details panel lists the searches, and they open the built query', async ({ page }) => {
  const errors = await open(page, '#/home');
  await page.evaluate(() => lazyNeed('phone'));
  await page.evaluate(() => { const t = 'Call +44 7700 900123 about the refund.'; DB.records.push({ id: uid('r'), caseId: DB.active, type: 'evidence', title: 'Note', body: t, tsRaw: '', tsZone: 'explicit', ts: Date.now(), source: '', host: '', tags: [], ents: E.extract(t), answer: '', addedBy: 'You', addedAt: Date.now(), hash: '' }); mutate('t'); select('ent', 'phone:+447700900123'); });
  const g = page.locator('#insp a', { hasText: /^Google/ });
  await expect(g).toHaveCount(1);
  expect(decodeURIComponent(await g.getAttribute('href'))).toContain('"07700 900123"');
  await expect(page.locator('#insp a', { hasText: /^Yandex/ })).toHaveCount(1);
  noErrors(errors);
});
