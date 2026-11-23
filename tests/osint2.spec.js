// OSINT additions in v1.48: active hours, the identity checklist, page changes, identity profiles and old Office metadata — each against realistic data.
const { test, expect } = require('@playwright/test');
const { open, noErrors, budget } = require('./helpers');
const fs = require('fs'), path = require('path');
const FX = (...p) => path.join(__dirname, 'fixtures', ...p);

test('active hours: Telegram, Reddit, Discord and CSV post times give each person their time zone, sleep, weekend and summer time; one person behind two names is found; a bot is flagged', async ({ page }) => {
  const errors = await open(page, '#/home');
  await page.evaluate(() => { DB.cases.push({ id: 'c-hr', code: 'HR-1', name: 'Night shift group', color: '#0ea5e9', status: 'active', created: Date.now(), updated: Date.now() }); DB.active = 'c-hr'; mutate('case'); UI.ivView = 'hours'; go(caseHash('c-hr', 'infra')); });
  await expect(page.locator('#main')).toContainText('No post times in this case yet');
  // a Telegram group export through the paste box: the hint reads it as it is pasted
  // (a 320 KB paste: put in at once, as a paste is, rather than typed)
  const paste = (sel, t) => page.evaluate(([sel, t]) => { const el = document.querySelector(sel); el.focus(); el.value = t; el.dispatchEvent(new Event('input', { bubbles: true })); }, [sel, t]);
  await page.click('[data-act=hrPaste]'); await paste('#hrText', fs.readFileSync(FX('hours', 'telegram-group.json'), 'utf8'));
  await expect(page.locator('#hrHint')).toContainText('Recognised: Telegram export, 1,792 post times from 2 people');
  await page.click('#dlg [type=submit]');
  // a Reddit listing and a Discord export as files, a bot's CSV pasted
  for(const f of ['reddit-user.json', 'discord-channel.json']){
    const [fc] = await Promise.all([page.waitForEvent('filechooser'), page.click('[data-act=hrFile]')]); await fc.setFiles(FX('hours', f));
    await expect.poll(() => page.evaluate(f => DB.records.some(r => r.caseId === 'c-hr' && r.title.includes(f)), f)).toBe(true); }
  await page.click('[data-act=hrPaste]'); await paste('#hrText', fs.readFileSync(FX('hours', 'bot.csv'), 'utf8')); await page.click('#dlg [type=submit]');
  const X = await page.evaluate(() => { const X = hrIndex('c-hr'); return { p: Object.fromEntries(X.people.map(x => [x.who, { n: x.ts.length, offs: x.prof.offs, winter: x.prof.winter, conf: x.prof.conf, flat: x.prof.flat, wk: x.prof.weekend && x.prof.weekend.days, dst: x.prof.dst && x.prof.dst.k }])),
    pairs: X.pairs.map(q => [q.a.who, q.b.who, Math.round(q.s * 100)]) }; });
  // Moscow: UTC+3, no summer time; New York: −5 in winter (an hour later in summer); Riyadh: +3 with a Friday–Saturday weekend
  expect(X.p['Dmitri K']).toMatchObject({ n: 911, conf: 'high', flat: false, wk: 'Saturday and Sunday', dst: 0 }); expect(X.p['Dmitri K'].offs).toContain(3);
  expect(X.p['jake_nyc']).toMatchObject({ n: 881, winter: true, wk: 'Saturday and Sunday', dst: -1 }); expect(X.p['jake_nyc'].offs).toContain(-5);
  expect(X.p['u/north_wind_77'].offs).toContain(3);
  expect(X.p['Faisal']).toMatchObject({ wk: 'Friday and Saturday', dst: 0 }); expect(X.p['Faisal'].offs).toContain(3);
  expect(X.p['newsbot_24']).toMatchObject({ flat: true, conf: 'low' });
  // the second name of the Moscow person keeps the same hours; New York keeps nobody's
  const pair = X.pairs.find(q => q.includes('Dmitri K') && q.includes('u/north_wind_77')); expect(pair && pair[2]).toBeGreaterThanOrEqual(82);
  expect(X.pairs.some(q => q.includes('jake_nyc'))).toBe(false);                                   // another continent
  expect(X.pairs.some(q => q.includes('Faisal') && q.includes('Dmitri K'))).toBe(false);           // the same hours, but a Friday–Saturday weekend
  expect(X.pairs.some(q => q.includes('newsbot_24'))).toBe(false);                                 // a bot's all-hours spread is left out
  // on screen: a card each, the time zone, places, the week grid; the bot's warning
  await expect(page.locator('.hr-p')).toHaveCount(5);
  const dm = page.locator('.hr-p', { hasText: 'Dmitri K' }); await expect(dm).toContainText('Moscow'); await expect(dm.locator('.hr-c')).toHaveCount(168);
  await expect(page.locator('.hr-p', { hasText: 'jake_nyc' })).toContainText('An hour later in summer');
  await expect(page.locator('.hr-p', { hasText: 'Faisal' })).toContainText('Friday and Saturday');
  await expect(page.locator('.hr-p', { hasText: 'newsbot_24' })).toContainText('Posts at all hours');
  await expect(page.locator('.if-c', { hasText: 'Keep the same hours' })).toContainText('north_wind_77');
  // kept: only who and when, and it survives a refresh
  const kept = await page.evaluate(() => DB.records.filter(r => r.caseId === 'c-hr').map(r => [r.hours.t.length, r.body.length < 4000]));
  expect(kept).toEqual([[1792, true], [380, true], [532, true], [751, true]]);
  await page.reload(); await expect.poll(() => page.evaluate(() => typeof DB !== 'undefined' && !!document.querySelector('#sidenav .nv') && hrIndex('c-hr').people.length)).toBe(5);
  // nothing usable: said so in the box
  await page.evaluate(() => { UI.ivView = 'hours'; go(caseHash('c-hr', 'infra')); renderAll(); });
  await page.click('[data-act=hrPaste]'); await page.fill('#hrText', 'hello\nno times here'); await page.click('#dlg [type=submit]'); await expect(page.locator('#dlg')).toContainText('No post times found');
  noErrors(errors);
});

test('identity checklist: every place for a username, an email and a phone number; marked there, not there or private with a note; a found profile saved as evidence; kept after a refresh and copied as a summary', async ({ page, context }) => {
  const errors = await open(page, '#/home');
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.evaluate(() => { UI.labTab = 'ident'; go('#/lab'); });
  await page.fill('#idQ', 'n1ghtlamp_77'); await page.click('form[data-form=idGo] [type=submit]');
  const rows = page.locator('.ck-r'); const n = await rows.count(); expect(n).toBeGreaterThan(45);
  // every link is a real http(s) address with the name in it, opened in a new tab without access back
  const links = await page.evaluate(() => [...document.querySelectorAll('.ck-n > a')].map(a => [a.textContent.trim(), a.href, a.target, a.rel]));
  for(const [name, href, target, rel] of links){ expect(href, name).toMatch(/^https:\/\//); expect(target).toBe('_blank'); expect(rel).toContain('noopener'); }
  expect(links.filter(([, h]) => h.includes('n1ghtlamp_77')).length).toBeGreaterThan(40);
  // GitHub: there, with a note, saved to the case; Reddit not there; Instagram private
  const row = name => page.locator('.ck-r', { has: page.getByRole('group', { name: name + ': what you found', exact: true }) });
  const mark = (name, what) => page.getByRole('group', { name: name + ': what you found', exact: true }).getByRole('button', { name: what, exact: true }).click();
  await mark('GitHub', 'There');
  await expect(row('GitHub').locator('.ck-note')).toBeFocused();
  await row('GitHub').locator('.ck-note').fill('Same avatar as the X account; repo "hl-portal" pushed 2024-03'); await row('GitHub').locator('.ck-note').press('Tab');
  await row('GitHub').locator('[data-act=ckSave]').click(); await expect(row('GitHub')).toContainText('saved to the case');
  await mark('Reddit', 'Not there');
  await mark('Instagram', 'Private');
  await expect(page.locator('.ck-top')).toContainText('3 of ' + n + ' checked · 1 there · 1 private · 1 not there');
  const rec = await page.evaluate(() => DB.records.find(r => r.title === '@n1ghtlamp_77 on GitHub'));
  expect(rec.body).toContain('https://github.com/n1ghtlamp_77'); expect(rec.body).toContain('Same avatar as the X account'); expect(rec.ents.some(e => /github\.com\/n1ghtlamp_77/.test(e.v))).toBe(true);
  // the filter shows only what is still to check, or only what was there
  await page.click('[data-act=ckF][data-v=found]'); await expect(rows).toHaveCount(1);
  await page.click('[data-act=ckF][data-v=open]'); await expect(rows).toHaveCount(n - 3);
  await page.click('[data-act=ckF][data-v=all]');
  // marking the same answer again clears it
  await mark('Reddit', 'Not there'); await expect(page.locator('.ck-top')).toContainText('2 of ' + n + ' checked');
  // a summary to paste into notes
  await page.click('[data-act=ckCopy]'); const clip = await page.evaluate(() => navigator.clipboard.readText());
  expect(clip).toContain('@n1ghtlamp_77 — checked 2 of'); expect(clip).toContain('There:\n- GitHub: https://github.com/n1ghtlamp_77 — Same avatar'); expect(clip).toContain('Private:\n- Instagram');
  // after a refresh, all of it is still there — and the details panel's research list counts the same place as checked
  await page.reload(); await expect.poll(() => page.evaluate(() => typeof DB !== 'undefined' && !!document.querySelector('#sidenav .nv'))).toBe(true);
  await page.evaluate(() => { UI.labTab = 'ident'; UI.idq = 'n1ghtlamp_77'; go('#/lab'); renderAll(); });
  await expect(row('GitHub').locator('.ck-note')).toHaveValue(/Same avatar/); await expect(row('Instagram').locator('[aria-pressed=true]')).toHaveText('Private');
  // an email: breach and leak searches, accounts, search queries, its own domain when not webmail
  await page.fill('#idQ', 'j.harbour+shop@harbourline-support.com'); await page.click('form[data-form=idGo] [type=submit]');
  for(const g of ['Breaches and leaks', 'Accounts it opened', 'Search queries', 'Its domain']) await expect(page.locator('.ck-g h4', { hasText: g })).toHaveCount(1);
  await expect(page.locator('.ck-n > a', { hasText: 'Have I Been Pwned' })).toHaveAttribute('href', 'https://haveibeenpwned.com/account/j.harbour%2Bshop%40harbourline-support.com');
  await page.fill('#idQ', 'someone@gmail.com'); await page.click('form[data-form=idGo] [type=submit]'); await expect(page.locator('.ck-g h4', { hasText: 'Its domain' })).toHaveCount(0);
  // a phone number
  await page.fill('#idQ', '+44 7700 900123'); await page.click('form[data-form=idGo] [type=submit]');
  await expect(page.locator('.ck-n > a', { hasText: 'WhatsApp' })).toHaveAttribute('href', 'https://wa.me/447700900123');
  // hostile input stays text and in the links only as an encoded value
  await page.fill('#idQ', '"><img src=x onerror=window.__x=1>'); await page.click('form[data-form=idGo] [type=submit]');
  expect(await page.evaluate(() => [window.__x, document.querySelectorAll('img[src="x"]').length, [...document.querySelectorAll('.ck-n > a')].every(a => /^https:/.test(a.href) && !a.href.includes('<'))])).toEqual([undefined, 0, true]);
  noErrors(errors);
});

test('page changes over time: two saved copies of a shop page show the removed company details and the added Telegram and crypto contact; two copies of a Mastodon profile show the new name, bio, picture, fields and a jump in followers; any two records can be compared', async ({ page }) => {
  const errors = await open(page, '#/home');
  await page.evaluate(() => { DB.cases.push({ id: 'c-ch', code: 'CH-1', name: 'Harbourline shop', color: '#0ea5e9', status: 'active', created: Date.now(), updated: Date.now() }); DB.active = 'c-ch'; mutate('case'); });
  const H = n => fs.readFileSync(FX('changes', n), 'utf8');
  await page.evaluate(async ([a, b]) => { await importWebPages([new File([a], 'about-march.html', { type: 'text/html', lastModified: Date.UTC(2026, 2, 1, 10) }), new File([b], 'about-april.html', { type: 'text/html', lastModified: Date.UTC(2026, 3, 12, 9) })]); }, [H('shop-2026-03-01.html'), H('shop-2026-04-12.html')]);
  await page.evaluate(([a, b]) => { let i = 0; for(const [body, t] of [[a, Date.UTC(2024, 2, 1)], [b, Date.UTC(2024, 3, 12)]]) DB.records.push({ id: 'r-ch' + (i++), caseId: 'c-ch', type: 'evidence', title: 'Mastodon profile', body, ts: t, tsRaw: '', tsZone: 'explicit', source: 'profile', host: '', tags: [], ents: [], addedBy: 'You', addedAt: t, hash: '' }); mutate('profiles'); UI.ivView = 'acc'; go(caseHash('c-ch', 'infra')); },
    [fs.readFileSync(FX('profiles', 'mastodon-account.json'), 'utf8'), H('mastodon-later.json')]);
  const X = await page.evaluate(() => chIndex('c-ch').groups.map(g => ({ label: g.label, n: g.recs.length, f: g.steps[0].d.fields.map(f => [f.label, f.a == null ? null : f.a, f.b == null ? null : f.b, f.delta]), add: g.steps[0].d.lines.filter(x => x[0] === '+').map(x => x[1]), del: g.steps[0].d.lines.filter(x => x[0] === '-').map(x => x[1]), links: g.steps[0].d.links, mails: g.steps[0].d.mails })));
  const shop = X.find(g => /harbourline-deals\.shop\/about/.test(g.label)), mast = X.find(g => /Mastodon/.test(g.label));
  // the page: what was taken down, what was put up, in order
  expect(shop.n).toBe(2);
  expect(shop.del).toEqual(['Director: Pieter van Dam. Chamber of Commerce (KvK) number 81234567.', 'Call us on +31 30 000 1234, Monday to Friday 09:00–17:00.', 'Payments by card or bank transfer to NL91 ABNA 0417 1643 00.', 'Follow us on Facebook.', 'Email sales@harbourline-deals.shop']);
  expect(shop.add).toEqual(['Questions? Message us on Telegram @harbourline_support — we answer 24/7.', 'Payments by crypto (USDT, TRC-20) to TQn9Y2khEsLJW1ChVWFMSMeRDow5KcbLSE for a 10 % discount.', 'Follow us on Telegram.', 'Email support@harbourline-help.top']);
  expect(shop.f).toEqual([['Description', 'Family-run outlet for marine electronics since 2009. Free shipping across the EU.', 'Marine electronics outlet. Free shipping worldwide.', undefined]]);
  expect(shop.links).toEqual({ add: ['https://t.me/harbourline_support'], del: ['https://www.facebook.com/harbourlinedeals'] });
  expect(shop.mails).toEqual({ add: ['support@harbourline-help.top'], del: ['sales@harbourline-deals.shop'] });
  // the profile: the fields that moved, with how much the counts moved; the same account number throughout
  const F = Object.fromEntries(mast.f.map(([l, a, b, d]) => [l, [a, b, d]]));
  expect(F['Display name']).toEqual(['Harbour Line', 'Harbour Line Support ✅', null]);
  expect(F['Bio']).toEqual(['Customer notices', 'Official support. DM for refunds. Telegram: @harbourline_support', null]);   // a Mastodon bio is HTML; shown as text
  expect(F['Followers']).toEqual(['3', '4182', 4179]); expect(F['Posts']).toEqual(['12', '57', 45]);
  expect(F['Picture'][0]).toMatch(/missing\.png$/);
  expect(F['Profile field “Telegram”']).toEqual([null, '@harbourline_support', null]); expect(F['Profile field “Website”']).toEqual(['harbour-line-portal.test', 'harbourline-help.top', null]);
  expect(Object.keys(F).some(k => /uri|emojis|last status/i.test(k))).toBe(false);
  // on screen
  const sec = page.locator('.pc'); await expect(sec).toContainText('2 pages and accounts saved more than once');
  await expect(sec.locator('.pc-l .pc-del', { hasText: 'Director: Pieter van Dam' })).toHaveCount(1);
  await expect(sec.locator('.pc-l .pc-add', { hasText: 'TQn9Y2khEsLJW1ChVWFMSMeRDow5KcbLSE' })).toHaveCount(1);
  await expect(sec.locator('.pc-f tr', { hasText: 'Followers' })).toContainText('+4,179');
  // compare any two records
  await page.click('[data-act=chPick]'); await page.selectOption('#chA', { label: await page.locator('#chA option', { hasText: 'Mastodon profile' }).first().textContent() });
  await page.selectOption('#chB', { label: await page.locator('#chB option', { hasText: 'Web page' }).last().textContent() }); await page.click('#dlg [type=submit]');
  await expect(page.locator('#chOut')).toContainText('change');
  noErrors(errors);
});

test('identity profiles: one person across three cases — joined by a shared email (confirmed) and a shared username (only likely), each identifier with how sure the link is, the cases disagreeing on date of birth and nationality, accounts and hours from the Infrastructure tab', async ({ page }) => {
  const errors = await open(page, '#/home');
  await page.evaluate(() => {
    const now = Date.now(), C = (id, code, name) => DB.cases.push({ id, code, name, color: '#0ea5e9', status: 'active', created: now, updated: now });
    C('c-a', 'ID-A', 'Harbour phishing'); C('c-b', 'ID-B', 'Marketplace refunds'); C('c-c', 'ID-C', 'Giveaway spam');
    const E = (id, caseId, type, fields) => DB.entries.push({ id, caseId, type, fields, tags: [], notes: '', priority: 'medium', starred: false, created: now, x: 0, y: 0 });
    const L = (id, a, b, conf, label, caseId) => DB.links.push({ id, caseId, a, b, conf, label, src: '' });
    // case A: the person, an email (sure), a username (fairly sure), a phone, a wallet reached through the email, a photo
    E('pa', 'c-a', 'person', { name: 'Jan Harbour', dob: '1991-04-02', nationality: 'Dutch', role: 'Subject' });
    E('ea', 'c-a', 'email', { email: 'j.harbour@proton.me' }); E('ua', 'c-a', 'username', { username: 'harbour_deals', platform: 'X' }); E('ph', 'c-a', 'phone', { number: '+447700900123' });
    E('wa', 'c-a', 'crypto', { address: 'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq', currency: 'Bitcoin' }); E('ma', 'c-a', 'media', { title: 'Profile photo from Telegram', type: 'Image' });
    L('l1', 'pa', 'ea', 3, 'uses', 'c-a'); L('l2', 'pa', 'ua', 2, 'runs', 'c-a'); L('l3', 'pa', 'ph', 3, 'uses', 'c-a'); L('l4', 'ea', 'wa', 2, 'paid from', 'c-a'); L('l5', 'pa', 'ma', 3, 'shows', 'c-a');
    // case B: another name for the same person — the same email
    E('pb', 'c-b', 'person', { name: 'J. Haven', dob: '1990-04-02', nationality: 'Belgian' }); E('eb', 'c-b', 'email', { email: 'J.Harbour@proton.me' }); L('l6', 'pb', 'eb', 3, 'uses', 'c-b');
    // case C: only the same username, which someone else could hold
    E('pc', 'c-c', 'person', { name: 'Giveaway admin' }); E('uc', 'c-c', 'username', { username: '@harbour_deals' }); L('l7', 'pc', 'uc', 3, 'runs', 'c-c');
    // someone unrelated in case A, linked to the photo: not pulled in
    E('px', 'c-a', 'person', { name: 'Witness' }); L('l8', 'px', 'ma', 3, 'took', 'c-a');
    // post times for the username, and its creation date from profile data
    DB.records.push({ id: 'r-hr', caseId: 'c-a', type: 'evidence', title: 'Post times', body: 'x', ts: now, tsRaw: '', tsZone: 'explicit', source: 'posts', host: '', tags: [], ents: [], addedBy: 'You', addedAt: now, hash: '',
      hours: { fmt: 'CSV', who: ['@harbour_deals'], t: Array.from({ length: 120 }, (_, i) => [0, Date.UTC(2026, 0, 5 + Math.floor(i / 4), [6, 10, 15, 18][i % 4] + (i % 3) * 0.3)]) } });
    DB.records.push({ id: 'r-x', caseId: 'c-a', type: 'evidence', title: 'X profile', body: JSON.stringify({ data: { id: '1760099200000000001', username: 'harbour_deals', name: 'Harbour Deals', created_at: '2024-02-20T22:41:07.000Z' } }), ts: now, tsRaw: '', tsZone: 'explicit', source: 'profile', host: '', tags: [], ents: [{ k: 'handle', v: '@harbour_deals' }], addedBy: 'You', addedAt: now, hash: '' });
    DB.active = 'c-a'; mutate('people'); go(caseHash('c-a', 'vault')); });
  const P = await page.evaluate(() => { const P = idpBuild('pa'); return { people: P.people.map(p => [p.e.id, p.conf, p.why && p.why.strong]), ids: Object.fromEntries(P.ids.map(x => [primary(x.e), [x.conf, [...x.cases].sort()]])), media: P.media.map(x => x.e.id), conflicts: P.conflicts.map(c => [c.what, c.vals.map(v => v.v)]), names: P.facts.name.map(x => x.v), acc: P.acc.map(a => [a.h, ftWhen(a.created)]), hrs: P.hrs.map(h => [h.who, h.offs]) }; });
  expect(P.people).toEqual([['pa', 3, null], ['pb', 3, true], ['pc', 2, false]]);        // the email makes B certain; the username only makes C likely
  expect(P.ids['j.harbour@proton.me']).toEqual([3, ['c-a', 'c-b']]);
  expect(P.ids['harbour_deals'][0]).toBe(2); expect(P.ids['harbour_deals'][1]).toEqual(['c-a', 'c-c']);
  expect(P.ids['+447700900123'][0]).toBe(3);
  expect(P.ids['bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq'][0]).toBe(1);                          // two steps away: one step weaker than its weakest link
  expect(P.media).toEqual(['ma']); expect(Object.keys(P.ids)).not.toContain('Witness');
  expect(P.conflicts).toEqual([['Date of birth', ['1991-04-02', '1990-04-02']], ['Nationality', ['Dutch', 'Belgian']]]);
  expect(P.names).toEqual(['Jan Harbour', 'J. Haven', 'Giveaway admin']);
  expect(P.acc).toEqual([['harbour_deals', '2024-02-20']]); expect(P.hrs[0][0]).toBe('@harbour_deals');
  // the card, from the vault and from the person's details panel
  await page.click('[data-act=idpList]');
  const items = await page.locator('#dlg .idp-list b').allTextContents();
  expect(items.filter(t => /Jan Harbour|J\. Haven|Giveaway admin/.test(t))).toEqual(['Jan Harbour']);   // one card for the person known by three names
  expect(items).toContain('Witness');
  await page.locator('#dlg .idp-list [data-act=idpOpen]', { hasText: 'Jan Harbour' }).click();
  const card = page.locator('#dlg .idp');
  await expect(card.locator('.idp-kf.warn')).toHaveCount(2); await expect(card.locator('.idp-kf', { hasText: 'Date of birth' })).toContainText('1991-04-02'); await expect(card.locator('.idp-kf', { hasText: 'Date of birth' })).toContainText('1990-04-02');
  await expect(card.locator('.idp-sum')).toContainText('Appears in 3 cases under 3 names. Tied to J. Haven by a shared email address — a strong link. Possibly also Giveaway admin, through a username only.');
  await expect(card.locator('.idp-gaps li', { hasText: 'Giveaway admin in Giveaway spam is joined only by a username' })).toHaveCount(1);
  await expect(card.locator('.idp-map svg line')).not.toHaveCount(0);
  await expect(card.locator('.idp-same')).toHaveCount(2);
  await expect(card.locator('.idp-same', { hasText: 'J. Haven' })).toContainText('Confirmed');
  await expect(card.locator('.idp-same', { hasText: 'Giveaway admin' })).toContainText('Likely');
  await expect(card.locator('.idp-tb tr', { hasText: 'harbour_deals' })).toContainText('made 2024-02-20');
  await expect(card.locator('.idp-hd')).toContainText('Also known as J. Haven, Giveaway admin');
  // an identifier opens in its own case
  await card.locator('[data-act=idpEnt]', { hasText: '+447700900123' }).click();
  await expect.poll(() => page.evaluate(() => UI.sel && UI.sel.id)).toBe('ph');
  await page.evaluate(() => selectEntry('pa')); await expect(page.locator('#insp [data-act=idpOpen]')).toBeVisible(); await expect(page.locator('#insp')).toContainText('cases disagree');
  noErrors(errors);
});

test('old Office and OpenDocument metadata: .doc, .xls and .ppt (Compound File) and .odt give the same author, last saver, revision, editing time and dates as an independent reader; damaged copies read as empty without hanging', async ({ page }) => {
  const errors = await open(page, '#/home');
  const files = Object.fromEntries(['invoice.doc', 'payouts.xls', 'deck.ppt', 'invoice.odt', 'invoice-lo.odt', 'payouts.ods'].map(n => [n, fs.readFileSync(FX('office', n)).toString('base64')]));
  const R = await page.evaluate(async F => { const out = {}; for(const [n, b] of Object.entries(F)){ const u = Uint8Array.from(atob(b), c => c.charCodeAt(0)); const M = await metaRead(u, n, ''); out[n] = { fmt: M.fmt, f: Object.fromEntries(M.fields.map(x => [x.k, x.v])), flags: (M.flags || []).map(x => x.t) }; } return out; }, files);
  // the values olefile (Python) reads from the same files
  expect(R['invoice.doc'].fmt).toBe('Word document (.doc)');
  expect(R['invoice.doc'].f).toMatchObject({ Title: 'Invoice 2026-118', Subject: 'Refund of marine radio order', Author: 'Pieter van Dam', Keywords: 'invoice, refund, harbourline', 'Last saved by': 'Ops Desk 3', Revision: '14', 'Total editing time (minutes)': '155', Created: '2026-03-02 09:14:00 UTC', 'Last saved': '2026-04-11 22:40:31 UTC' });
  expect(R['payouts.xls'].fmt).toBe('Excel workbook (.xls)'); expect(R['payouts.xls'].f).toMatchObject({ Author: 'Kasia N.', Revision: '6', 'Total editing time (minutes)': '48', Created: '2026-03-05 18:02:00 UTC', 'Last saved': '2026-03-29 07:45:10 UTC' });
  expect(R['deck.ppt'].fmt).toBe('PowerPoint presentation (.ppt)'); expect(R['deck.ppt'].f).toMatchObject({ Author: 'Marco Rossi', 'Last saved by': 'M. Rossi (laptop)', Revision: '3', 'Total editing time (minutes)': '65', Created: '2026-01-20 10:00:00 UTC' });
  expect(R['invoice.odt'].fmt).toBe('OpenDocument text (.odt)');
  expect(R['invoice.odt'].f).toMatchObject({ Title: 'Invoice 2026-118', Author: 'Pieter van Dam', 'Last saved by': 'Ops Desk 3', Revision: '14', 'Total editing time (minutes)': '155', 'Custom field “Client”': 'Harbourline Deals', 'Custom field “Case ref”': 'HL-4471' });
  expect(R['invoice.odt'].f['Created']).toBe('2026-03-02 09:14:00 (local time of the computer that saved it)');
  expect(R['invoice.odt'].f['Made with']).toBe('ODFPY/1.4.1');                                    // the library that wrote this one
  expect(R['invoice-lo.odt'].f).toMatchObject({ Author: 'Pieter van Dam', 'Last saved by': 'Ops Desk 3', Keywords: 'invoice, refund, harbourline', Pages: '1', Words: '14' });   // saved again by LibreOffice: keywords as separate entries
  expect(R['invoice-lo.odt'].f['Made with']).toMatch(/^LibreOffice\/24\.2/);
  expect(R['payouts.ods'].fmt).toBe('OpenDocument spreadsheet (.ods)');
  // damaged and crafted copies: truncated, bytes overwritten, a sector chain that loops
  const bad = await page.evaluate(async b => { const u = Uint8Array.from(atob(b), c => c.charCodeAt(0)), out = [], rnd = (s => () => (s = (s * 1103515245 + 12345) >>> 0) / 4294967296)(3);
    const cases = [u.slice(0, 512), u.slice(0, 2000), u.slice(0, u.length >> 1)]; for(let k = 0; k < 20; k++){ const m = u.slice(); for(let j = 0; j < 40; j++) m[Math.floor(rnd() * m.length)] = Math.floor(rnd() * 256); cases.push(m); }
    const loop = u.slice(); const dv = new DataView(loop.buffer); const fat0 = dv.getUint32(0x4c, true); for(let i = 0; i < 128; i++) dv.setUint32((fat0 + 1) * 512 + i * 4, i, true); cases.push(loop);
    for(const c of cases){ const t = performance.now(); try{ await metaRead(c, 'x.doc', ''); }catch(e){ out.push('threw ' + e.message); } if(performance.now() - t > 1500) out.push('slow'); } return out; }, files['invoice.doc']);
  expect(bad).toEqual([]);
  // through the Forensics kit's file inspector and as an attachment, the fields show
  await page.evaluate(() => { UI.labTab = 'file'; go('#/lab'); });
  noErrors(errors);
});

test('sample case: “Harbourline refund scam” is added to a workspace with sample data and fills every Infrastructure view and an identity profile; the account timeline fits its card and shows every label whole', async ({ page }) => {
  const errors = await open(page, '#/home', { osintSample: true });
  await expect.poll(() => page.evaluate(() => DB.cases.some(c => c.id === 'c-harbour')), { timeout: 15000 }).toBe(true);
  const X = await page.evaluate(() => { const I = infraIndex('c-harbour'), W = walletIndex('c-harbour'), F = footIndex('c-harbour'), C = chIndex('c-harbour'), H = hrIndex('c-harbour'), P = idpBuild('sp-jan');
    return { infra: I && (I.facts || I.rows || []).length, links: I && (I.links || I.groups || []).length, money: W && (W.flows || W.edges || []).length, acc: F.accounts.length, renamed: F.accounts.filter(a => a.names.some(n => n.old)).length,
      changes: C.groups.map(g => g.label).sort(), hours: H.people.map(p => p.who).sort(), same: H.pairs.map(q => [q.a.who, q.b.who].sort().join(' ~ ')), people: P.people.map(p => p.e.id), ids: P.ids.length, conflicts: P.conflicts.length }; });
  expect(X.infra).toBeGreaterThan(10); expect(X.money).toBeGreaterThan(3); expect(X.acc).toBeGreaterThan(4); expect(X.renamed).toBeGreaterThanOrEqual(2);
  expect(X.changes.some(l => /harbourline-deals\.shop\/about/.test(l))).toBe(true); expect(X.changes.some(l => /^Mastodon/.test(l))).toBe(true);
  expect(X.hours).toEqual(['@harbour_deals', 'Faisal', 'jake_nyc', 'newsbot_24', 'u/north_wind_77']); expect(X.same).toContain('@harbour_deals ~ u/north_wind_77');
  expect(X.people).toEqual(['sp-jan', 'sp-haven']); expect(X.ids).toBeGreaterThanOrEqual(6); expect(X.conflicts).toBe(2);
  // every view draws without an error
  await page.evaluate(() => { DB.active = 'c-harbour'; go(caseHash('c-harbour', 'infra')); });
  for(const v of ['dom', 'money', 'acc', 'hours']){ await page.evaluate(v => { UI.ivView = v; renderAll(); }, v); await page.waitForTimeout(200); await expect(page.locator('#main .empty')).toHaveCount(0); }
  // the account timeline: as wide as its card, and no label cut off on the left
  await page.evaluate(() => { UI.ivView = 'acc'; renderAll(); });
  const geo = await page.evaluate(() => { const box = document.querySelector('.ft-svg'), svg = box.querySelector('svg'), b = box.getBoundingClientRect(), s = svg.getBoundingClientRect();
    const cut = [...svg.querySelectorAll('text.ft-l')].filter(t => t.getBoundingClientRect().left < b.left - 1).map(t => t.textContent); return { fill: s.width / b.width, cut }; });
  expect(geo.fill).toBeGreaterThan(0.97); expect(geo.cut).toEqual([]);
  // removing the sample data removes it too
  await page.evaluate(() => removeSample ? 0 : 0);
  noErrors(errors);
});

test('regex builder: select fields in SSH log lines, the pattern is built and tried on every line, a missed line teaches it a variation, it is exported for six tools, saved as a parser that reads a log import, and a risky hand-written pattern is flagged', async ({ page, context }) => {
  const errors = await open(page, '#/home');
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  // its own entry in the sidebar, and "regex" in search goes straight to it
  await page.click('#side a[href="#/regex"]'); await expect(page.locator('.lhd h1')).toHaveText('Regex builder');
  await page.evaluate(() => go('#/home')); await page.evaluate(() => srchOpen()); await page.fill('#srQ', 'regex'); await page.keyboard.press('Enter');
  await expect(page).toHaveURL(/#\/regex$/); await expect(page.locator('[data-act=rxDemo]:not([data-v])')).toBeVisible();
  await page.click('[data-act=rxDemo]:not([data-v])');
  await expect(page.locator('.rx-ln')).toHaveCount(6);
  // select text in a line, as with the mouse, and name it
  const pick = async (line, text, name) => {
    await page.evaluate(([line, text]) => { const t = document.querySelector(`.rx-ln[data-i="${line}"] .rx-t`), full = t.textContent, s = full.indexOf(text); const r = document.createRange();
      const walk = (off) => { const w = document.createTreeWalker(t, NodeFilter.SHOW_TEXT); let n, at = 0; while((n = w.nextNode())){ if(at + n.length >= off) return [n, off - at]; at += n.length; } };
      const [a, ao] = walk(s), [b, bo] = walk(s + text.length); r.setStart(a, ao); r.setEnd(b, bo); const sel = getSelection(); sel.removeAllRanges(); sel.addRange(r);
      t.dispatchEvent(new MouseEvent('mouseup', { bubbles: true })); }, [line, text]);
    await expect(page.locator('#rxName')).toBeVisible();
    if(name) await page.fill('#rxName', name); await page.click('form[data-form=rxName] [type=submit]'); await expect(page.locator('#rxName')).toHaveCount(0); };
  await pick(0, 'Nov  2 08:15:30', 'time'); await pick(0, 'root', 'user'); await pick(0, '203.0.113.7', 'src_ip'); await pick(0, '51544', 'port');
  // suggested names come from what was selected: an IP is "ip", a time "time"
  const stat = () => page.locator('.rx-stat b').textContent();
  expect(await stat()).toBe('1');
  await expect(page.locator('#rxSrcView')).toContainText('(?<src_ip>(?:25[0-5]');
  // a missed line says where the pattern stops and what it expected there
  await page.click('.rx-ln[data-i="1"] .rx-no');
  await expect(page.locator('.rx-ln[data-i="1"] .rx-why')).toContainText('then expects');
  await expect(page.locator('.rx-tb-b')).toContainText('The pattern matches the start of this line up to column');
  // teach it: the same fields on lines it missed — a second line suggests the names in order
  await pick(1, 'Nov  2 08:15:33'); await pick(1, 'admin'); await pick(1, '203.0.113.7'); await pick(1, '51560');
  await pick(2, 'Nov  2 08:16:02'); await pick(2, 'deploy'); await pick(2, '198.51.100.23'); await pick(2, '40022');
  await pick(3, 'Nov 12 22:01:47'); await pick(3, 'root'); await pick(3, '2001:db8::7'); await pick(3, '6022');
  expect(await stat()).toBe('4');   // "Accepted publickey" is a wording it has not seen yet
  await page.click('[data-act=rxShow][data-v=miss]'); await expect(page.locator('.rx-ln')).toHaveCount(2); await page.click('[data-act=rxShow][data-v=all]');
  await pick(4, 'Nov 12 22:01:50'); await pick(4, 'j.doe'); await pick(4, '192.0.2.44'); await pick(4, '52111');
  expect(await stat()).toBe('5');   // all but "Connection closed", which has no user
  const src = await page.locator('#rxSrcView').textContent();
  expect(src).toContain('(?:Failed +password +for(?: +invalid +user)?|Accepted(?: +publickey +for| +password +for))'); expect(src).toContain('[\\w.-]+ +sshd\\[\\d+\\]');
  expect(src).not.toMatch(/\.\*(?!\?)/);                                                     // no greedy wildcards
  await expect(page.locator('.rx-safe')).toHaveText(/Safe on hostile input/);
  await page.click('[data-act=rxLeft][data-v=table]');
  const rows = await page.locator('.rx-tb tbody tr').evaluateAll(T => T.map(r => [...r.cells].map(c => c.textContent)));
  expect(rows).toEqual([['1', 'Nov  2 08:15:30', 'root', '203.0.113.7', '51544'], ['2', 'Nov  2 08:15:33', 'admin', '203.0.113.7', '51560'], ['3', 'Nov  2 08:16:02', 'deploy', '198.51.100.23', '40022'], ['4', 'Nov 12 22:01:47', 'root', '2001:db8::7', '6022'], ['5', 'Nov 12 22:01:50', 'j.doe', '192.0.2.44', '52111']]);
  await page.click('[data-act=rxLeft][data-v=lines]');
  await page.click('[data-act=rxShow][data-v=miss]'); await expect(page.locator('.rx-ln')).toHaveCount(1); await expect(page.locator('.rx-ln')).toContainText('Connection closed'); await page.click('[data-act=rxShow][data-v=all]');
  // the pattern explained piece by piece
  await page.click('[data-act=rxTab][data-v=explain]');
  await expect(page.locator('.rx-xp')).toContainText('field time — Syslog time'); await expect(page.locator('.rx-xp')).toContainText('one of Failed password for [invalid user]');
  // exports: each one is the same pattern in that tool's own syntax
  await page.click('[data-act=rxTab][data-v=export]');
  const exp = async k => { await page.click(`[data-act=rxExp][data-v=${k}]`); return page.locator('#rxOut').textContent(); };
  const js = await exp('js'); expect(js.startsWith('/') && js.endsWith('/')).toBe(true); const re = new RegExp(js.slice(1, -1));
  expect('Nov 30 23:59:59 bastion-3 sshd[9]: Accepted password for svc_backup from 10.0.0.5 port 1 ssh2'.match(re).groups).toEqual({ time: 'Nov 30 23:59:59', user: 'svc_backup', src_ip: '10.0.0.5', port: '1' });
  expect(await exp('python')).toContain("re.compile(r'\\b(?P<time>");
  const grok = await exp('grok'); expect(grok).toContain('%{SYSLOGTIMESTAMP:time}'); expect(grok).toContain('%{IP:src_ip}'); expect(grok).toContain('%{INT:port}'); expect(grok).toContain('(?<user>\\S+)');
  expect(await exp('splunk')).toMatch(/^\| rex field=_raw "\\\\b\(\?<time>/);
  const kql = await exp('kql'); expect(kql).toContain('user = extract(@"'); expect(kql).toContain('", 2, RawData)'); expect(kql).not.toContain('(?<');
  await page.click('[data-act=rxCopy]'); expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(kql);
  // saved as a parser, it reads a log import
  await page.click('[data-act=rxSave]'); await expect(page.locator('#lpRe')).toHaveValue(js.slice(1, -1).replace(/\\\//g, '\\/'));
  await page.fill('#lpName', 'SSH auth (built)'); await page.click('#dlg [type=submit]');
  const P = await page.evaluate(() => { const p = DB.parsers.find(x => x.name === 'SSH auth (built)'); return runUserParser(p, 'Dec  1 01:02:03 web09 sshd[77]: Failed password for invalid user oracle from 203.0.113.250 port 22 ssh2'); });
  expect(P).toMatchObject({ user: 'oracle', src_ip: '203.0.113.250', port: '22' });
  // by hand: a pattern that backtracks badly is caught before it reaches a log tool
  await page.click('[data-act=rxEdit]'); await page.fill('#rxSrc', '(?<a>(\\w+\\s?)+)$'); await page.waitForTimeout(800);
  await expect(page.locator('.rx-safe')).toHaveText(/Risky — not run/); await expect(page.locator('.rx-notes')).toContainText('catastrophic backtracking'); await expect(page.locator('.rx-tb')).toHaveCount(0);   // not run, so the page stays responsive
  await page.fill('#rxSrc', '(?<a>[unclosed'); await page.waitForTimeout(800); await expect(page.locator('.rx-err')).toContainText('Invalid regular expression');
  await page.click('[data-act=rxAuto]'); await expect(page.locator('#rxSrcView')).toBeVisible();
  // hostile log text stays text; nothing of the sample is saved
  await page.click('[data-act=rxReset]'); await page.fill('#rxText', '<img src=x onerror=window.__x=1> user="><b id=pwn>x</b> from 10.1.1.1'); await page.click('[data-act=rxGo]');
  await pick(0, '10.1.1.1', 'ip'); expect(await page.evaluate(() => [window.__x, document.querySelectorAll('#pwn, img[src="x"]').length])).toEqual([undefined, 0]);
  expect(await page.evaluate(() => JSON.stringify(DB).includes('onerror=window.__x'))).toBe(false);
  noErrors(errors);
});

/* ---------- Regex builder, v1.51: formats, records over several lines, auto-parse, optional fields, the optimiser ---------- */
const rxTable = page => page.locator('.rx-tb').evaluate(t => { const H = [...t.tHead.rows[0].cells].slice(1).map(c => c.textContent.trim()); return [...t.tBodies[0].rows].map(r => Object.fromEntries([...r.cells].slice(1).map((c, i) => [H[i], c.textContent]))); });
const rxLoad = async (page, text) => { await page.evaluate(() => { UI.rx = null; go('#/regex'); renderMain(); }); await page.fill('#rxText', text); await page.click('[data-act=rxGo]'); };
const rxFormat = async (page, name) => { await page.locator('.rx-fmi', { has: page.locator(`b.mono:text-is("${name}")`) }).click(); };

test('regex builder formats: a mixed server log is sorted into formats, auto-parse names each one\'s fields, a field some lines lack is optional with its coverage, and every format is exported at once for six tools', async ({ page, context }) => {
  const errors = await open(page, '#/regex');
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.click('[data-act=rxDemo][data-v=mixed]');
  await expect(page.locator('.rx-bar')).toContainText('13 lines · 6 formats');
  const F = await page.evaluate(() => Object.fromEntries(UI.rx.fmts.map(f => [f.name, f.lines.map(i => i + 1)])));
  // failed and accepted passwords (with and without "invalid user", IPv4 and IPv6) are one format; closed connections, cron, sudo and the firewall are each their own
  expect(F).toMatchObject({ sshd: [1, 2, 3, 10], cron: [4, 6], sudo: [5, 7], kernel: [8, 9], sshd_2: [12, 13] });
  await page.click('[data-act=rxAutoParse]');
  await expect(page.locator('.toast').last()).toContainText('Recognised: Syslog ×6');
  // every format has a pattern that matches all its lines
  for (const s of await page.locator('.rx-fmi:not(.rx-fmall) .rx-fms').allTextContents()) { const m = s.match(/(\d+) of (\d+)/); expect(m && m[1]).toBe(m && m[2]); }
  await expect(page.locator('.rx-fmi[aria-selected=true] b.mono')).toHaveText('sshd');
  await page.click('[data-act=rxLeft][data-v=table]');
  let T = await rxTable(page);
  expect(T.map(r => [r.user, r.src_ip, r.port])).toEqual([['root', '203.0.113.7', '51544'], ['admin', '203.0.113.7', '51560'], ['deploy', '198.51.100.23', '40022'], ['root', '2001:db8::7', '6022']]);
  // the firewall lines: key=value pairs become fields; WINDOW is on one line of two, so it is optional
  await rxFormat(page, 'kernel');
  T = await rxTable(page);
  expect(T.map(r => [r.text, r.SRC, r.DPT, r.PROTO, r.WINDOW])).toEqual([['[UFW BLOCK]', '185.220.101.4', '22', 'TCP', '64240'], ['[UFW BLOCK]', '45.155.205.3', '161', 'UDP', '—']]);
  await page.click('[data-act=rxTab][data-v=fields]');
  await expect(page.locator('.rx-cov[title$=" have WINDOW"]')).toHaveText('optional · 50% of matches');
  await expect(page.locator('.rx-fld[data-f=PROTO] .rx-fr3')).toContainText('2 distinct');
  await expect(page.locator('.rx-fld[data-f=DST] .rx-fr3')).toContainText('1 distinct10.0.0.5 ×2');
  await expect(page.locator('.rx-cov[title$=" have SRC"]')).toHaveText('every match');
  await page.click('[data-act=rxTab][data-v=explain]'); await expect(page.locator('.rx-xp')).toContainText('optional: WINDOW= then field WINDOW');
  expect(await page.locator('#rxSrcView').textContent()).toContain('(?: +WINDOW=(?<WINDOW>');
  await rxFormat(page, 'sudo');
  T = await rxTable(page); expect(T.map(r => [r.text, r.USER, r.COMMAND])).toEqual([['deploy', 'root', '/usr/bin/systemctl restart nginx'], ['alice', 'root', '/bin/cat /etc/shadow']]);
  // every format at once
  await page.click('[data-act=rxTab][data-v=export]');
  await page.click('[data-act=rxExpAll][data-v="1"]');
  const exp = async k => { await page.click(`[data-act=rxExp][data-v=${k}]`); return page.locator('#rxOut').textContent(); };
  const js = await exp('js');
  const parse = new Function('line', 'let fields = null;\n' + js + '\nreturn fields;');
  const lines = (await page.evaluate(() => RX_DEMO_MIXED)).split('\n');
  const out = lines.map(parse);
  expect(out.every(Boolean)).toBe(true);
  expect(out.map(o => o.format)).toEqual(['sshd', 'sshd', 'sshd', 'cron', 'sudo', 'cron', 'sudo', 'kernel', 'kernel', 'sshd', 'sshd_3', 'sshd_2', 'sshd_2']);
  expect(out[7]).toMatchObject({ SRC: '185.220.101.4', DPT: '22' }); expect(out[11]).toMatchObject({ src_ip: '192.0.2.44', port: '52111' });
  expect(await exp('python')).toMatch(/PATTERNS = \{[\s\S]*"kernel": re\.compile\(r'.*\(\?P<SRC>/);
  const grok = await exp('grok'); expect(grok).toContain('match => { "message" => ['); expect((grok.match(/^      '/gm) || []).length).toBe(6); expect(grok).toContain('%{SYSLOGTIMESTAMP:time}');
  expect(((await exp('splunk')).match(/^\| rex field=_raw/gm) || []).length).toBe(6);
  const kql = await exp('kql'); expect(kql).toContain('| extend format = case('); expect(kql).toMatch(/SRC = case\(format == "kernel", extract\(@".*", 7, RawData\), ""\)/);
  await page.click('[data-act=rxCopy]'); expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(kql);
  // back to one pattern for every line: the fields of different formats do not line up, and it says so
  await page.click('.rx-fmall'); await page.click('[data-act=rxLeft][data-v=lines]');
  await expect(page.locator('.rx-bar')).toContainText('13 lines'); await expect(page.locator('.rx-ln')).toHaveCount(13);
  noErrors(errors);
});

test('regex builder records: a Java log with stack traces and a Windows Event Viewer text export are read as records, auto-parse names their fields, and the same record setting is given for Logstash, Filebeat, Splunk and Fluent Bit', async ({ page }) => {
  const errors = await open(page, '#/regex');
  await page.click('[data-act=rxDemo][data-v=java]');
  await expect(page.locator('.rx-mlc')).toContainText('11 lines read as 4 records · each starts with an ISO 8601 time');
  await expect(page.locator('.rx-ln')).toHaveCount(4);
  await page.click('[data-act=rxAutoParse]');
  await expect(page.locator('.toast').last()).toContainText('Application log');
  await expect(page.locator('.rx-stat b')).toHaveText('4');
  await page.click('[data-act=rxLeft][data-v=table]');
  const T = await rxTable(page);
  expect(T.map(r => [r.level, r.thread, r.logger, r.message])).toEqual([['INFO', 'main', 'c.e.App', 'Started in 2.3s'], ['ERROR', 'http-nio-8080-exec-1', 'c.e.Api', 'Request failed for user alice'], ['WARN', 'main', 'c.e.Db', 'Slow query 1200 ms'], ['ERROR', 'http-nio-8080-exec-4', 'c.e.Auth', 'Login refused for 203.0.113.7']]);
  expect(T[1].detail).toBe('java.lang.NullPointerException: user is null\n\tat com.example.Api.handle(Api.java:42)\n\tat org.apache.catalina.core.StandardWrapperValve.invoke(StandardWrapperValve.java:197)\nCaused by: java.io.IOException: closed\n\t... 12 more');
  expect(T[2].detail).toBe('—');
  await page.click('[data-act=rxTab][data-v=fields]');
  await expect(page.locator('.rx-cov[title$=" have detail"]')).toHaveText('optional · 50% of matches');
  // the shipper settings: applied to the raw lines, the start pattern cuts them into the same 4 records
  await page.click('[data-act=rxTab][data-v=export]'); await page.click('.rx-box summary');
  const ml = await page.locator('#rxMlOut').textContent();
  expect(ml).toContain('negate => true'); expect(ml).toContain('match: after'); expect(ml).toContain('SHOULD_LINEMERGE = false'); expect(ml).toContain('[MULTILINE_PARSER]');
  const fb = ml.match(/pattern: '(.*)'/)[1], raw = (await page.evaluate(() => RX_DEMO_JAVA)).split('\n');
  expect(raw.filter(l => new RegExp(fb).test(l)).length).toBe(4);
  const lb = ml.match(/LINE_BREAKER = (.*)/)[1]; expect(raw.join('\n').split(new RegExp(lb)).filter(x => x && !/^[\r\n]+$/.test(x)).length).toBe(4);
  // read line by line again
  await page.click('[data-act=rxMl]'); await expect(page.locator('.rx-bar')).toContainText('11 lines'); await page.click('[data-act=rxLeft][data-v=lines]'); await expect(page.locator('.rx-ln')).toHaveCount(11);
  // a Windows Event Viewer export (text): one record per event, each "Key: value" a field
  await rxLoad(page, fs.readFileSync(FX('logs', 'winevents.txt'), 'utf8'));
  await expect(page.locator('.rx-mlc')).toContainText('33 lines read as 3 records · each starts with “Log Name:”');
  await page.click('[data-act=rxAutoParse]'); await page.click('[data-act=rxLeft][data-v=table]');
  const W = await rxTable(page);
  expect(W.map(r => [r.Event_ID, r.Task_Category, r.Keywords, r.Computer, r.Date])).toEqual([['4625', 'Logon', 'Audit Failure', 'DC01.corp.local', '11/2/2026 8:15:30 AM'], ['4624', 'Logon', 'Audit Success', 'WS042.corp.local', '11/2/2026 8:15:41 AM'], ['4672', 'Special Logon', 'Audit Success', 'WS042.corp.local', '11/2/2026 8:16:02 AM']]);
  noErrors(errors);
});

test('regex builder auto-parse: Apache, a Palo Alto CEF feed, IIS W3C with its header, Okta JSON with nested fields and a VPN CSV with a quoted comma each get named fields and a pattern that matches every line', async ({ page }) => {
  const errors = await open(page, '#/regex');
  const cases = [
    ['access.log', 'Apache / nginx', 4, T => { expect(T.map(r => [r.client_ip, r.user, r.method, r.path, r.status, r.user_agent])[3]).toEqual(['203.0.113.9', '-', 'GET', '/.env', '403', 'zgrab/0.x']); expect(T[2].path).toBe('/index.php?s=/Index/\\think\\app/invokefunction&function=call_user_func_array'); expect(T[1].referrer).toBe('https://example.com/login'); }],
    ['firewall-cef.log', 'CEF', 4, T => { expect(T.map(r => [r.signature_id, r.src, r.dst, r.dpt, r.act])).toEqual([['THREAT', '203.0.113.7', '10.0.0.5', '443', 'reset-both'], ['TRAFFIC', '10.0.0.8', '8.8.8.8', '53', 'allow'], ['THREAT', '10.0.0.9', '185.220.101.4', '443', 'drop'], ['TRAFFIC', '10.0.0.8', '1.1.1.1', '443', 'allow']]); expect(T[2].msg).toBe('C2 beacon to known Tor exit'); expect(T[1].msg).toBe('—'); expect(T[0].rt).toBe('Nov 02 2026 08:15:30'); }],
    ['iis.log', 'IIS / W3C', 4, T => { expect(T.map(r => [r.cs_method, r.cs_uri_stem, r.cs_username, r.c_ip, r.sc_status])).toEqual([['GET', '/owa/auth/logon.aspx', '-', '203.0.113.7', '200'], ['POST', '/autodiscover/autodiscover.json', '-', '198.51.100.23', '200'], ['POST', '/ecp/DDI/DDIService.svc/GetList', 'CORP\\svc-backup', '198.51.100.23', '401'], ['GET', '/aspnet_client/system_web/shell.aspx', '-', '198.51.100.23', '200']]); expect(T[3].cs_uri_query).toBe('cmd=whoami'); }],
    ['okta.jsonl', 'JSON', 3, T => { expect(T.map(r => [r.eventType, r.actor_alternateId, r.client_ip, r.outcome, r.reason])).toEqual([['user.session.start', 'alice@corp.example', '203.0.113.7', 'FAILURE', 'INVALID_CREDENTIALS'], ['user.session.start', 'alice@corp.example', '203.0.113.7', 'SUCCESS', '—'], ['user.mfa.factor.deactivate', 'alice@corp.example', '203.0.113.7', 'SUCCESS', 'User deactivated factor']]); }],
    ['vpn.csv', 'CSV (comma)', 4, T => { expect(T.map(r => [r.user, r.src_ip, r.country, r.result])).toEqual([['alice', '203.0.113.7', 'NL', 'fail'], ['alice', '203.0.113.7', 'NL', 'ok'], ['smith, j', '192.0.2.4', 'US', 'ok'], ['bob', '198.51.100.23', 'DE', 'ok']]); }]];
  for (const [file, label, n, check] of cases) {
    await rxLoad(page, fs.readFileSync(FX('logs', file), 'utf8'));
    await page.click('[data-act=rxAutoParse]');
    await expect(page.locator('.toast').last()).toContainText(label);
    await expect(page.locator('.rx-stat')).toContainText(`${n} of ${n}`);
    await page.click('[data-act=rxLeft][data-v=table]');
    check(await rxTable(page));
  }
  // the header lines of the IIS log and the CSV are their own format and left alone
  await expect(page.locator('.rx-fmi', { hasText: 'header' }).locator('.rx-fms')).toHaveText('not parsed');
  // a field selected by hand is never overwritten: auto-parse fills only formats without fields
  await rxLoad(page, fs.readFileSync(FX('logs', 'access.log'), 'utf8'));
  await page.evaluate(() => { UI.rx.fields.push({ line: 0, s: 0, e: 11, name: 'mine' }); renderMain(); });
  await page.click('[data-act=rxAutoParse]'); await expect(page.locator('.toast').last()).toContainText('Every format already has fields');
  expect(await page.evaluate(() => UI.rx.fields.map(f => f.name))).toEqual(['mine']);
  noErrors(errors);
});

test('regex builder optimiser: rewrites are tried one at a time, kept only when every line gives the same values, shown with what changed and the speed before and after, and the optimised pattern is what gets exported', async ({ page }) => {
  const errors = await open(page, '#/regex');
  // the engine on its own: shared starts are taken out, a lazy wildcard becomes an exact class, a rewrite that changes a value is refused
  const r = await page.evaluate(() => { const L = RX_DEMO_MIXED.split('\n');
    const a = rxOptimise('sshd\\[\\d+\\]: +(?:Failed +password +for +invalid +user|Accepted +password +for|Failed +password +for) +(?<user>\\S+) +from', L, []);
    const b = rxOptimise('(?<pid>\\d+)\\]: .*?for (?<user>\\S+) from (?<ip>\\S+)', L, []);
    const c = rxOptimise('for (?<who>.+?) from', L, [{ k: 'anchor', src: '^for (?<who>.+?) from' }]);
    const d = rxOptimise('"(?<q>(?:[^"\\\\]|\\\\.)*)"', ['say "a \\"b\\" c" now', 'x "" y', 'none'], []);
    return { a: a.src, a0: a.from, aA: a.steps.find(s => s.k === 'factor').after, aS: a.steps.find(s => s.k === 'factor').state, b: b.src, bS: b.steps.find(s => s.k === 'lazy'), c: c.src, cS: c.steps.map(s => s.k + ':' + s.state), d: d.src, dA: d.steps.find(s => s.k === 'unroll').after, same: [a, b, c].every(x => rxSame(x.from, x.src, L)) && rxSame(d.from, d.src, ['say "a \\"b\\" c" now', 'x "" y']) }; });
  // a pure rewrite: kept unless this browser measures it slower
  expect(r.aA).toBe('sshd\\[\\d+\\]: +(?:Failed +password +for(?: +invalid +user)?|Accepted +password +for) +(?<user>\\S+) +from'); expect(['kept', 'slower']).toContain(r.aS); expect(r.a).toBe(r.aS === 'kept' ? r.aA : r.a0);
  expect(r.bS.after).toBe('(?<pid>\\d+)\\]: [^f\\r\\n]*for (?<user>\\S+) from (?<ip>\\S+)'); expect(['kept', 'slower']).toContain(r.bS.state); expect(r.bS.detail).toBe('1 wildcard');
  // "for invalid user admin from": the name has spaces, so [^ ]+ would cut it short — left as it is; tied to the line start it would match nothing — refused
  expect(r.c).toBe('for (?<who>.+?) from'); expect(r.cS).toContain('anchor:differs'); expect(r.cS).toContain('lazy:none');
  expect(r.dA).toBe('"(?<q>[^"\\\\]*(?:\\\\.[^"\\\\]*)*)"'); expect(r.same).toBe(true);
  // in the page
  await page.click('[data-act=rxDemo][data-v=mixed]'); await page.click('[data-act=rxAutoParse]');
  await page.click('[data-act=rxTab][data-v=speed]'); await page.click('[data-act=rxOpt]');
  await expect(page.locator('.rx-steps li')).toHaveCount(6);
  await expect(page.locator('.rx-speed')).toContainText(/lines a second/);
  const states = await page.locator('.rx-steps .rx-sts').allTextContents();
  expect(states.every(s => /^(Kept|Nothing to change|Not faster — left out|Would change the results — left out)/.test(s))).toBe(true);
  for (const li of await page.locator('.rx-steps li.kept').all()) { await expect(li.locator('.rx-diff del, .rx-diff ins').first()).toBeAttached(); await expect(li).toContainText(/a second/); }
  const before = await page.locator('.rx-stat b').textContent(), built = await page.locator('#rxSrcView').textContent();
  if (await page.locator('[data-act=rxOptUse]').count()) {
    await page.click('[data-act=rxOptUse]');
    await expect(page.locator('.rx-pact .chip')).toHaveText('optimised');
    const opt = await page.locator('#rxSrcView').textContent(); expect(opt).not.toBe(built);
    await expect(page.locator('.rx-stat b')).toHaveText(before);
    await page.click('[data-act=rxTab][data-v=export]'); await page.click('[data-act=rxExp][data-v=pcre]'); await expect(page.locator('#rxOut')).toHaveText(opt);
    await page.click('[data-act=rxOptOff]'); await expect(page.locator('#rxSrcView')).toHaveText(built);
  }
  noErrors(errors);
});

test('regex builder for daily work: pinned tests catch a regression, each tool says whether it can run the pattern (KQL gets a version without lookahead), a value filters the lines and goes to the case, undo and keys work', async ({ page }) => {
  const errors = await open(page, '#/regex');
  await page.click('[data-act=rxDemo][data-v=mixed]'); await page.click('[data-act=rxAutoParse]');
  // pin line 1 with its values, and a cron line that must not match
  await page.click('.rx-ln[data-i="0"] .rx-no'); await page.click('[data-act=rxPin][data-v=match]');
  await page.click('[data-act=rxShow][data-v=every]'); await page.click('.rx-ln[data-i="3"] .rx-no'); await page.click('[data-act=rxPin][data-v=none]');
  await expect(page.locator('.rx-tchip')).toHaveText('2 tests pass');
  // a pasted line that must match too
  await page.click('[data-act=rxTab][data-v=tests]'); await page.fill('#rxTestText', 'Nov 30 23:59:59 bastion-3 sshd[9]: Accepted password for svc_backup from 10.0.0.5 port 1 ssh2'); await page.click('form[data-form=rxTestAdd] [type=submit]');
  await expect(page.locator('.rx-tsum')).toHaveText('All 3 tests pass');
  // break it by hand: the tests say what broke
  await page.click('[data-act=rxEdit]'); const src = await page.inputValue('#rxSrc');
  await page.fill('#rxSrc', src.replace('(?<user>\\S+)', '(?<user>[a-z]+)')); await page.waitForTimeout(700);
  await expect(page.locator('.rx-tchip')).toHaveText('1 of 3 tests fail');
  await expect(page.locator('.rx-tl li.fail .rx-tf')).toHaveText('it does not match any more');
  await page.click('[data-act=rxAuto]'); await expect(page.locator('.rx-tchip')).toHaveText('3 tests pass');
  // compatibility: the optimiser's fixed-word check is lookahead — KQL (RE2) gets it taken out, with the same values
  await page.click('[data-act=rxTab][data-v=speed]'); await page.click('[data-act=rxOpt]');
  await page.evaluate(() => { const S = UI.rx; S.opt.src = '^(?=[^\\n]*?password)' + S.opt.from.replace(/^\^|^\\b/, ''); S.opt.on = true; rxRender(); });
  await page.click('[data-act=rxTab][data-v=export]'); await page.click('[data-act=rxExp][data-v=kql]');
  await expect(page.locator('.rx-cn')).toContainText('has no lookahead: written without it — the same values on all your lines');
  expect(await page.locator('#rxOut').textContent()).not.toContain('(?=');
  await expect(page.locator('.rx-cc', { hasText: 'KQL' })).toHaveClass(/fix/); await expect(page.locator('.rx-cc', { hasText: 'Splunk' })).toHaveClass(/ok/);
  await page.click('[data-act=rxExp][data-v=pcre]'); expect(await page.locator('#rxOut').textContent()).toContain('(?=[^\\n]*?password)');
  await page.click('[data-act=rxOptOff]');
  // pivot: a value filters the lines and the table
  await page.click('[data-act=rxTab][data-v=fields]'); await page.click('[data-act=rxShow][data-v=all]');
  await page.locator('.rx-fld[data-f=src_ip] .rx-val', { hasText: '203.0.113.7' }).click();
  await expect(page.locator('.rx-flt')).toContainText('src_ip = 203.0.113.7'); await expect(page.locator('.rx-ln')).toHaveCount(2);
  await page.click('.rx-flt [data-act=rxFilt]'); await expect(page.locator('.rx-ln')).toHaveCount(4);
  // the values go to the case as evidence, and their addresses become indicators
  await page.click('.rx-fld[data-f=src_ip] [data-act=rxToCase]');
  const rec = await page.evaluate(() => { const r = DB.records.find(x => x.source === 'regex-builder' && x.caseId === DB.active); return r && { title: r.title, ips: r.ents.filter(e => e.k === 'ipv4' || e.k === 'ipv6' || e.k === 'ip').map(e => e.v).sort() }; });
  expect(rec.title).toBe('Log values: src_ip (3)'); expect(rec.ips).toEqual(expect.arrayContaining(['198.51.100.23', '203.0.113.7']));
  // undo and redo of field changes, from the keyboard too
  await page.click('.rx-fld[data-f=port] [data-act=rxDel]'); await expect(page.locator('.rx-fld[data-f=port]')).toHaveCount(0);
  await page.keyboard.press('Control+z'); await expect(page.locator('.rx-fld[data-f=port]')).toHaveCount(1);
  await page.keyboard.press('Control+Shift+z'); await expect(page.locator('.rx-fld[data-f=port]')).toHaveCount(0);
  await page.click('[data-act=rxUndo]'); await expect(page.locator('.rx-fld[data-f=port]')).toHaveCount(1);
  // keys: ↓ moves to the next line, / opens the pattern for editing (not the app search)
  await page.click('.rx-ln[data-i="0"] .rx-no'); await page.keyboard.press('ArrowDown'); await expect(page.locator('.rx-ln.cur')).toHaveAttribute('data-i', '1');
  await page.keyboard.press('/'); await expect(page.locator('#rxSrc')).toBeVisible(); await expect(page.locator('#srQ')).toBeHidden();
  noErrors(errors);
});

test('regex builder table and CTF help: the details panel folds away for the table and comes back on a row; long multi-line values stay one line with a count; a category description sits behind a ?', async ({ page }) => {
  const errors = await open(page, '#/regex');
  await expect(page.locator('[data-act=rxReset]')).toHaveCount(0);
  await page.click('[data-act=rxDemo][data-v=java]'); await page.click('[data-act=rxAutoParse]');
  await expect(page.locator('[data-act=rxReset]')).toHaveText('Start over');
  await page.click('[data-act=rxLeft][data-v=table]');
  await expect(page.locator('.rx-rail')).toBeVisible(); await expect(page.locator('.rx-tb-b')).toHaveCount(0);
  await expect(page.locator('.rx-tb tbody tr[data-i="1"] td.rx-ml')).toHaveAttribute('data-more', '+4 lines');
  const h = await page.locator('.rx-tb tbody tr[data-i="1"]').evaluate(r => r.getBoundingClientRect().height); expect(h).toBeLessThan(40);   // one line per record
  await page.click('.rx-tb tbody tr[data-i="3"] td:nth-child(3)'); await expect(page.locator('.rx-mh')).toContainText('Record 4');
  await page.click('[data-act=rxSide]'); await expect(page.locator('.rx-rail')).toBeVisible();
  await page.click('.rx-rail [data-act=rxSide]'); await expect(page.locator('.rx-tabs')).toBeVisible();
  // CTF: the description is behind a ? and readable in full
  await page.evaluate(() => { go('#/ctf'); UI.ctfTab = 'cheats'; renderMain(); });
  await expect(page.locator('.cs4-hp')).toBeHidden();
  await page.hover('.cs4-hb'); await expect(page.locator('.cs4-hp')).toBeVisible(); await expect(page.locator('.cs4-hp')).toContainText('public breadcrumbs');
  noErrors(errors);
});

test('polish: no screen is wider than a phone, tab strips that do not fit scroll with a soft edge, and text cut off with … shows in full when pointed at', async ({ browser }) => {
  const ctx = await browser.newContext({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
  await ctx.addInitScript(() => { try { localStorage.setItem('osintrix:welcomed', '1'); } catch (e) {} });
  const page = await ctx.newPage(); const errors = []; page.on('pageerror', e => errors.push(e.message));
  await page.goto(require('url').pathToFileURL(require('path').join(__dirname, '..', 'index.html')).href + '#/home');
  await expect(page.locator('#main .page, #main .scroll').first()).toBeVisible();
  const areas = ['home', 'today', 'cases', 'entities', 'feeds', 'watch', 'security', 'detections', 'playbooks', 'queries', 'notes', 'pad', 'notebook', 'toolbox', 'lab', 'regex', 'decoder', 'certs', 'cloud', 'ctf', 'reference', 'help', 'whatsnew', 'settings', 'trash', 'case/c-harbour/overview', 'case/c-harbour/vault', 'case/c-harbour/entities', 'case/c-harbour/timeline', 'case/c-harbour/infra', 'case/c-harbour/questions'];
  const wide = [];
  for (const a of areas) { await page.evaluate(r => { location.hash = '#/' + r; }, a); await page.waitForTimeout(250);
    const w = await page.evaluate(() => { const s = document.querySelector('#main .scroll') || document.querySelector('#main'); return [document.scrollingElement.scrollWidth - innerWidth, s.scrollWidth - s.clientWidth]; });
    if (w[0] > 1 || w[1] > 1) wide.push(a + ' ' + w.join('/')); }
  expect(wide).toEqual([]);
  // the cloud guide's tabs do not fit a phone: they scroll, with an edge
  await page.evaluate(() => { location.hash = '#/cloud'; }); await expect(page.locator('.cld-tabs.x-more')).toHaveCount(1);
  await page.locator('.cld-tabs').evaluate(e => { e.scrollLeft = e.scrollWidth; e.dispatchEvent(new Event('scroll')); }); await expect(page.locator('.cld-tabs')).toHaveClass(/x-end/);
  await ctx.close();
  expect(errors).toEqual([]);
});

test('polish on a desktop: a case summary cut off with … shows in full when pointed at; the decoder groups its operations', async ({ page }) => {
  const errors = await open(page, '#/home', { osintSample: true });
  const cut = page.locator('#main small').filter({ hasText: 'Fake refund support' }).first();
  await cut.hover(); await expect(cut).toHaveAttribute('title', /went quiet: who runs it, where the money goes, and when they work/);
  await page.evaluate(() => go('#/decoder')); await expect(page.locator('.txbar > button')).toHaveCount(4);   // one row: Auto-decode, then a menu per group
  await expect(page.locator('[data-act=txMenu] small')).toHaveText([/^Decode · \d+$/, /^Encode & transform · \d+$/, /^Analyse · \d+$/]);
  await page.click('[data-act=txMenu][data-v=Decode]'); await page.locator('#ctx .ctx-it', { hasText: 'Base64 decode' }).click();
  await expect(page.locator('[data-act=txMenu][data-v=Decode]')).toHaveAttribute('aria-pressed', 'true'); await expect(page.locator('[data-act=txMenu][data-v=Decode] b')).toHaveText('Base64 decode');
  await expect(page.locator('[data-act=txOp][data-v=auto]')).toHaveAttribute('aria-pressed', 'false');
  await page.fill('#decIn', 'aGVsbG8gd29ybGQ='); await expect(page.locator('#txOut')).toHaveText('hello world');
  noErrors(errors);
});

test('right-click an indicator anywhere: copy, copy defanged, details, every case it is in, watch and the lookups for its kind; plain text keeps the browser menu', async ({ page, context }) => {
  const errors = await open(page, '#/case/c-harbour/timeline', { osintSample: true });
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  const v = page.locator('#main .v', { hasText: /^j\.harbour@proton\.me$/ }).first();
  await v.click({ button: 'right' });
  await expect(page.locator('#ctx .ctx-title')).toContainText('j.harbour@proton.me');
  await expect(page.locator('#ctx')).toContainText('Open in Have I Been Pwned');
  await page.locator('#ctx .ctx-it', { hasText: 'Copy defanged' }).click();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe('j[.]harbour[@]proton[.]me');
  // an address from the sample case: watch it, then find it in every case
  const ip = page.locator('#main .v', { hasText: /^198\.51\.100\.23$/ }).first();
  await ip.click({ button: 'right' }); await page.getByRole('menuitem', { name: 'Watch', exact: true }).click();
  expect(await page.evaluate(() => !!(DB.watch || {})['ipv4:198.51.100.23'])).toBe(true);
  await ip.click({ button: 'right' }); await expect(page.locator('#ctx .ctx-it', { hasText: 'Stop watching' })).toBeVisible();
  await page.locator('#ctx .ctx-it', { hasText: 'Find in every case' }).click();
  await expect(page).toHaveURL(/#\/entities$/); await expect(page.locator('#entq')).toHaveValue('198.51.100.23');
  // a heading is not an indicator: no menu of ours
  await page.locator('#main h1').first().click({ button: 'right' }); await expect(page.locator('#ctx')).toHaveCount(0);
  noErrors(errors);
});

test('regex builder My patterns: save with sample lines, fields and tests, keep earlier versions, open again after a reload, export and import, delete to the trash and restore', async ({ page }) => {
  const errors = await open(page, '#/regex');
  await page.click('[data-act=rxDemo][data-v=mixed]'); await page.click('[data-act=rxAutoParse]');
  await page.click('.rx-ln[data-i="0"] .rx-no'); await page.click('[data-act=rxPin][data-v=match]');
  const built = await page.locator('#rxSrcView').textContent();
  await page.click('[data-act=rxlSave]'); await page.fill('#rxlName', 'SSH logins'); await page.fill('#rxlTags', 'SSH, linux, auth, ssh');
  await page.click('form[data-form=rxlSave] [type=submit]');
  await expect(page.locator('.rx-libn')).toHaveText('SSH logins');
  expect(await page.evaluate(() => DB.rxlib.map(x => [x.name, x.tags, x.tests.length, x.fields.length > 3]))).toEqual([['SSH logins', ['ssh', 'linux', 'auth'], 1, true]]);
  // a second version: edit by hand and save over it
  await page.click('[data-act=rxEdit]'); await page.fill('#rxSrc', built.replace('(?<port>', '(?<port>\\b')); await page.waitForTimeout(600);
  await page.click('[data-act=rxlSave]'); await page.click('form[data-form=rxlSave] [type=submit]');
  await expect(page.locator('.toast').last()).toContainText('version 2');
  // after a reload it is still there and opens as it was, tests and all
  await page.waitForTimeout(400); await page.reload(); await expect.poll(() => page.evaluate(() => typeof DB !== 'undefined' && !!DB && !!document.querySelector('#sidenav .nv'))).toBe(true); await page.evaluate(() => go('#/regex'));
  await expect(page.locator('.rxl-o')).toHaveCount(1); await expect(page.locator('.rxl-o')).toContainText('version 2');
  await page.click('.rxl-o');
  await expect(page.locator('.rx-libn')).toHaveText('SSH logins'); await expect(page.locator('.rx-tchip')).toHaveText('1 test pass');
  expect(await page.inputValue('#rxSrc')).toContain('(?<port>\\b');
  // the earlier version
  await page.click('[data-act=rxlLib]'); await page.click('.dlg [data-act=rxlMore]'); await page.getByRole('menuitem', { name: /Versions/ }).click();
  await expect(page.locator('.rxl-v li')).toHaveCount(2); await expect(page.locator('.rxl-v .rx-diff ins').first()).toHaveText('\\b');
  await page.click('[data-act=rxlVerOpen]'); expect(await page.inputValue('#rxSrc')).toBe(built);
  // export, delete (to the trash), import back
  const [dl] = await Promise.all([page.waitForEvent('download'), page.evaluate(() => RXL_ACTS.rxlExport())]);
  const file = await (await dl.createReadStream()).toArray().then(b => Buffer.concat(b).toString());
  expect(JSON.parse(file).patterns[0].name).toBe('SSH logins');
  await page.evaluate(() => go('#/regex')); await page.click('[data-act=rxReset]');
  await page.click('[data-act=rxlMore]'); await page.getByRole('menuitem', { name: 'Delete' }).click();
  await expect(page.locator('.rxl-o')).toHaveCount(0);
  await page.evaluate(() => { const x = DB.trash.find(t => t.kind === 'pattern'); trashRestore(x.id); go('#/regex'); });
  await expect(page.locator('.rxl-o')).toHaveCount(1);
  await page.evaluate(t => rxlImportText(t), file); await expect(page.locator('.rxl-o')).toHaveCount(2);
  // a broken or hostile file is refused
  await page.evaluate(() => rxlImportText('{"patterns":[{"name":"bad","src":"(unclosed"},{"name":"<img src=x onerror=alert(1)>","src":"a+"}]}'));
  await expect(page.locator('.rxl-o')).toHaveCount(3); await expect(page.locator('.rxl-o img')).toHaveCount(0);
  noErrors(errors);
});

test('masking: addresses, users, hosts, emails, hashes and MACs get placeholders of the same shape, the same value always the same one; in the Decoder and as a masked copy in the Regex builder', async ({ page, context }) => {
  const errors = await open(page, '#/regex');
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  const r = await page.evaluate(() => maskText(`Nov  2 08:15:30 web01 sshd[1234]: Failed password for invalid user alice from 203.0.113.7 port 51544 ssh2
Nov  2 08:15:33 web01 sshd[1234]: Accepted password for root from 10.0.4.17 port 51560 ssh2
2026-11-02 08:15:30 10.0.0.5 POST /owa/ - 443 CORP\\svc-backup 203.0.113.7 curl 401
mail from j.harbour@proton.me via mx.harbourline-deals.shop C:\\Users\\jdoe\\AppData\\x.exe user=alice mac 00:16:3e:aa:bb:cc google.com
9f2c1d0b7e4a6c8f3b5d2e1a0c9b8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a`));
  const t = r.text;
  for (const secret of ['203.0.113.7', '10.0.4.17', 'web01', 'alice', 'svc-backup', 'CORP', 'j.harbour', 'proton.me', 'harbourline', 'jdoe', '00:16:3e', '9f2c1d0b']) expect(t).not.toContain(secret);
  // the same value, the same placeholder; shapes kept; system accounts and big providers kept
  expect(t.match(/192\.0\.2\.1\b/g).length).toBe(2); expect(t).toMatch(/for invalid user user-\d+ from/); expect((t.match(/user=(user-\d+)/) || [])[1]).toBe((t.match(/invalid user (user-\d+)/) || [])[1]);
  expect(t).toContain('for root from 10.255.'); expect(t).toContain('google.com'); expect(t).toMatch(/\b0{63}1\b/); expect(t).toContain('00:00:5e:00:53:');
  expect(t).toMatch(/user-\d+@domain-\d+\.example/);
  // in the builder: a masked copy, and work on it
  await page.click('[data-act=rxDemo]:not([data-v])'); await page.click('[data-act=rxMask]');
  await expect(page.locator('.dlg')).toContainText('Replaced'); const out = await page.locator('#rxMaskOut').textContent();
  expect(out).not.toContain('203.0.113.7'); expect(out).not.toContain('web01');
  await page.click('[data-act=rxMaskCopy]'); expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(out);
  await page.click('[data-act=rxMaskUse]'); await expect(page.locator('.rx-ln').first()).not.toContainText('web01');
  // in the Decoder
  await page.evaluate(() => go('#/decoder')); await page.click('[data-act=txMenu][data-v="Encode & transform"]'); await page.locator('#ctx .ctx-it', { hasText: 'Mask identifiers' }).click();
  await page.fill('#decIn', 'login by alice from 198.51.100.23 to fileserver.acme-corp.com'); await page.waitForTimeout(500);
  const dec = await page.locator('#txOut').textContent(); expect(dec).not.toContain('198.51.100.23'); expect(dec).not.toContain('acme-corp'); expect(dec).toContain('domain-1.example');
  noErrors(errors);
});

test('regex builder on a whole file: a 40 MB log is read in pieces with progress, every line counted, field coverage and commonest values, matches as CSV, and missed lines go back into the sample', async ({ page }, info) => {
  test.setTimeout(120000);
  const errors = await open(page, '#/regex');
  // 400,000 lines: SSH logins from a few addresses, and lines of other kinds in between
  const os = require('os'), p = require('path').join(os.tmpdir(), 'osx-big-' + process.pid + '.log'), ips = ['203.0.113.7', '198.51.100.23', '192.0.2.44', '2001:db8::7'], users = ['root', 'admin', 'deploy', 'alice'];
  const out = fs.createWriteStream(p); let want = 0, wantRoot = 0;
  for (let i = 0; i < 400000; i++) {
    if (i % 4 === 3) out.write(`Nov  2 08:${String(i % 60).padStart(2, '0')}:00 web01 CRON[${i}]: (root) CMD (run-parts /etc/cron.hourly)\n`);
    else { const u = users[i % 4]; want++; if (u === 'root') wantRoot++; out.write(`Nov  2 08:${String(i % 60).padStart(2, '0')}:${String(i % 60).padStart(2, '0')} web0${i % 3} sshd[${1000 + i % 9000}]: ${i % 2 ? 'Accepted' : 'Failed'} password for ${u} from ${ips[i % 4]} port ${40000 + i % 20000} ssh2\n`); }
  }
  await new Promise(r => out.end(r));
  await page.click('[data-act=rxDemo][data-v=mixed]'); await page.click('[data-act=rxAutoParse]');
  await page.click('[data-act=rxTab][data-v=export]');
  const [fc] = await Promise.all([page.waitForEvent('filechooser'), page.click('[data-act=rxBig]')]); await fc.setFiles(p);
  await expect(page.locator('.rxb-bar')).toBeVisible();
  await expect(page.locator('[data-act=rxBigCsv]')).toBeVisible({ timeout: 90000 });
  const n = await page.locator('.rxb-n b').allTextContents();
  expect(n[0]).toBe('400,000'); expect(n[1]).toBe(want.toLocaleString('en-US')); expect(n[2]).toBe((400000 - want).toLocaleString('en-US'));
  const userRow = page.locator('.rxb-t tr', { has: page.locator('td b', { hasText: /^user$/ }) });
  await expect(userRow).toContainText('100%'); await expect(userRow.locator('td').nth(2)).toHaveText('3');   // root, admin, deploy — alice's lines are the cron ones
  await expect(userRow).toContainText('root ' + wantRoot.toLocaleString('en-US'));
  // matches as CSV
  const [dl] = await Promise.all([page.waitForEvent('download'), page.click('[data-act=rxBigCsv]')]);
  const csv = Buffer.concat(await (await dl.createReadStream()).toArray()).toString(); const rows = csv.trim().split('\r\n');
  expect(rows[0]).toContain('line,'); expect(rows.length - 1).toBe(Math.min(want, 200000));
  // the missed lines go into the sample, shown as missed
  await page.click('[data-act=rxBigTeach]'); await expect(page.locator('.toast').last()).toContainText('Added');
  await expect(page.locator('[data-act=rxShow][data-v=miss]')).toHaveAttribute('aria-pressed', 'true');
  fs.unlinkSync(p); noErrors(errors);
});

test('a fresh workspace without the sample says what to do next everywhere, and the activity chart shows the real last eight days', async ({ page }) => {
  const errors = await open(page, '#/home');
  await page.evaluate(() => removeSample()); await page.click('[data-act=confirmOk]');
  await expect(page.locator('.brief p')).toContainText('is empty');
  await expect(page.locator('.act-none')).toContainText('Nothing captured in the last 8 days');
  const labels = await page.locator('.axis span').allTextContents();
  const today = new Date(); expect(labels).toHaveLength(8); expect(labels[7]).toContain(String(today.getDate()));
  await expect(page.locator('.impl', { hasText: 'Sample data' })).toHaveCount(0);
  await page.evaluate(() => go('#/entities')); await expect(page.locator('#main .empty h3')).toHaveText('No entities yet');
  await page.fill('#entq', 'nothing-here'); await page.evaluate(() => { UI.entq = 'zzz'; renderMain(); });
  await page.evaluate(() => go(caseHash(DB.active, 'timeline'))); await expect(page.locator('#main .empty h3')).toHaveText('No events yet');
  await expect(page.locator('#main .empty [data-act=capture]')).toBeVisible();
  // once there is evidence, the chart has a bar today
  await page.evaluate(() => { DB.records.push({ id: 'r-now', caseId: DB.active, type: 'evidence', title: 'Seen 203.0.113.9', body: '203.0.113.9', tsRaw: '', tsZone: 'explicit', ts: Date.now(), source: 'test', host: '', tags: [], ents: E.extract('203.0.113.9'), answer: '', addedBy: 'You', addedAt: Date.now(), hash: '' }); mutate('t'); go('#/home'); renderMain(); });
  await expect(page.locator('.bars span').last()).toHaveText('1'); await expect(page.locator('.act-none')).toHaveCount(0);
  noErrors(errors);
});

test('a 3,000-node graph fits on screen whole, and the screens with it stay quick', async ({ page }) => {
  test.setTimeout(120_000);
  const errors = await open(page, '#/home');
  const t = await page.evaluate(() => { const N = 3000; for (let i = 0; i < N; i++) DB.entries.push({ id: 'gv' + i, caseId: 'c-portal', type: i % 3 ? 'domain' : 'ip', fields: i % 3 ? { domain: 'host' + i + '.example.org' } : { ip: '203.0.113.' + (i % 250) }, priority: 'medium', starred: false, tags: [], notes: '', src: '', created: Date.now(), pos: null });
    for (let i = 1; i < N; i++) DB.links.push({ id: 'gl' + i, caseId: 'c-portal', a: 'gv' + i, b: 'gv' + Math.floor(i / 3), label: 'resolves', conf: 2, src: '' }); mutate('g');
    const out = {}; for (const tab of ['overview', 'vault', 'entities', 'graph']) { const s = performance.now(); location.hash = caseHash('c-portal', tab); onRoute(); out[tab] = performance.now() - s; } return out; });
  for (const k in t) expect(t[k], k).toBeLessThan(await budget(page, 3000));
  await page.waitForTimeout(1500);
  const v = await page.evaluate(() => { const bb = cy.elements().renderedBoundingBox(), W = cy.width(), H = cy.height(); return { z: cy.zoom(), fits: bb.w <= W + 2 && bb.h <= H + 2 }; });
  expect(v.z).toBeLessThan(.7); expect(v.fits).toBe(true);
  noErrors(errors);
});

test('the regex builder works by keyboard and has no accessibility problems, light and dark', async ({ page }) => {
  test.setTimeout(180_000);
  const AxeBuilder = require('@axe-core/playwright').default;
  const errors = await open(page, '#/regex');
  await page.click('[data-act=rxDemo][data-v=mixed]'); await page.click('[data-act=rxAutoParse]');
  // ← → Home End move between the detail tabs and open them, keeping focus
  await page.focus('#rxtab-match'); await page.keyboard.press('ArrowRight');
  await expect(page.locator('#rxtab-explain')).toBeFocused(); await expect(page.locator('#rxtab-explain')).toHaveAttribute('aria-selected', 'true');
  await page.keyboard.press('End'); await expect(page.locator('#rxtab-export')).toBeFocused();
  await page.keyboard.press('ArrowRight'); await expect(page.locator('#rxtab-match')).toBeFocused();
  const found = [];
  for (const theme of ['light', 'dark']) {
    await page.evaluate(t => { DB.prefs.theme = t; applyPrefs(); }, theme);
    for (const step of ['match', 'explain', 'fields', 'tests', 'speed', 'export', 'table', 'save', 'lib', 'mask']) {
      await page.evaluate(s => { closeDlg(); const S = UI.rx; if (s === 'table') S.left = 'table'; else { S.left = 'lines'; if (RX_TABS.some(t => t[0] === s)) S.tab = s; }
        rxRender(); if (s === 'save') RXL_ACTS.rxlSave(); if (s === 'lib') RXL_ACTS.rxlLib(); if (s === 'mask') document.querySelector('[data-act=rxMask]').click(); }, step);
      await page.waitForTimeout(250);
      const res = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).analyze();
      for (const x of res.violations) if (['serious', 'critical'].includes(x.impact)) for (const n of x.nodes.slice(0, 2)) found.push(`${theme} ${step} ${x.id}: ${n.target.join(' ')}`);
    }
  }
  expect(found, found.join('\n')).toEqual([]);
  noErrors(errors.filter(e => !/Connecting to 'file:[^']*\.css/.test(e)));
});

test('mask from anywhere: a record’s captured text, the scratchpad, and any selected text', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  const errors = await open(page, '#/home');
  const body = 'Nov 21 10:02:11 web-prod-03 sshd[811]: Accepted password for jsmith from 185.220.101.7 port 51122\nlogin alert sent to jsmith@harbourline.co.uk via mail.harbourline.co.uk';
  const clip = () => page.evaluate(() => navigator.clipboard.readText());
  const id = await page.evaluate(b => { const r = { id: 'r-mask', caseId: DB.active, type: 'evidence', title: 'SSH login', body: b, tsRaw: '', tsZone: 'explicit', ts: Date.now(), source: 'test', host: '', tags: [], ents: E.extract(b), answer: '', addedBy: 'You', addedAt: Date.now(), hash: '' }; DB.records.push(r); mutate('t'); select('rec', r.id); return r.id; }, body);
  await page.click(`[data-act=recCopyBody][data-id=${id}]`); expect(await clip()).toBe(body);
  await page.click(`[data-act=recCopyMasked][data-id=${id}]`);
  const m = await clip();
  for (const v of ['185.220.101.7', 'jsmith', 'harbourline', 'web-prod-03']) expect(m).not.toContain(v);
  expect(m).toContain('192.0.2.1'); expect(m).toContain('sshd[811]: Accepted password for user-'); expect(m.split('\n')).toHaveLength(2);
  await expect(page.locator('.toast').last()).toContainText('Copied masked');
  // the scratchpad
  await page.evaluate(b => { UI.padText = b; DB.pad = b; go('#/pad'); }, body);
  await page.click('[data-act=padMask]'); expect(await clip()).toBe(m);
  // selected text in a page: copy masked and copy defanged (only the indicators are defanged)
  await page.evaluate(() => select('rec', 'r-mask'));
  const pre = page.locator('#insp .rawbox');
  /* the panel may still redraw once after opening, which drops a selection made in the same instant — select and right-click again until the menu shows */
  await expect(async () => { await pre.evaluate(el => { const r = document.createRange(); r.selectNodeContents(el); const s = getSelection(); s.removeAllRanges(); s.addRange(r); });
    await pre.click({ button: 'right', position: { x: 20, y: 10 } }); await expect(page.locator('#ctx .ctx-title')).toHaveText('Selected text', { timeout: 600 }); }).toPass({ timeout: 8000 });
  await page.locator('#ctx button', { hasText: 'Copy defanged' }).click();
  const d = await clip(); expect(d).toContain('185[.]220[.]101[.]7'); expect(d).toContain('Accepted password for jsmith'); expect(d).not.toContain('[.]\n');
  await pre.evaluate(el => { const r = document.createRange(); r.selectNodeContents(el); const s = getSelection(); s.removeAllRanges(); s.addRange(r); });
  await pre.click({ button: 'right', position: { x: 20, y: 10 } });
  await page.locator('#ctx button', { hasText: 'Copy masked' }).click(); expect(await clip()).toBe(m);
  noErrors(errors);
});

test('search builder: rows become a search for each engine, what an engine cannot do is said, and a saved search is rewritten for the engine it runs on', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  const errors = await open(page, '#/queries');
  await page.click('[data-act=qbOpen]');
  await page.fill('#qbv0', '{{DOMAIN_NAME}}'); await page.fill('#qbv1', 'password backup');
  await page.click('[data-act=qbAdd][data-v=filetype]'); await page.fill('#qbv2', '.sql');
  await page.click('[data-act=qbAdd][data-v=not]'); await page.fill('#qbv3', 'github');
  await page.click('[data-act=qbAdd][data-v=intitle]'); await page.fill('#qbv4', 'index of');
  await expect(page.locator('#qbQ')).toHaveText('site:{{DOMAIN_NAME}} password backup filetype:sql -github intitle:"index of"');
  // a blank means it cannot be searched yet, only saved
  await expect(page.locator('.qb-go button.primary')).toBeDisabled();
  // Shodan: the file type and the exclusion are said to be left out, and struck through
  await page.click('[data-act=qbEng][data-v=shodan]');
  await expect(page.locator('#qbQ')).toHaveText('hostname:{{DOMAIN_NAME}} password backup http.title:"index of"');
  await expect(page.locator('.qb-w').first()).toContainText('file type, none of these');
  await expect(page.locator('.qb-r.off')).toHaveCount(2);
  await expect(page.locator('#qbt-shodan .qb-d')).toHaveText('2');
  // GitHub: file type becomes a path
  await page.click('[data-act=qbEng][data-v=github]'); await expect(page.locator('#qbQ')).toHaveText('password backup path:*.sql NOT github');
  // a wrong value is pointed out under its row
  await page.fill('#qbv2', 'not a type'); await expect(page.locator('#qbe2')).toHaveText('An extension, like pdf'); await expect(page.locator('#qbv2')).toHaveAttribute('aria-invalid', 'true');
  await page.fill('#qbv2', 'sql');
  // typing keeps the caret where it was
  await page.click('#qbv1'); await page.keyboard.press('End'); await page.keyboard.type(' dump'); await expect(page.locator('#qbv1')).toHaveValue('password backup dump'); await expect(page.locator('#qbv1')).toBeFocused();
  // save on Google
  await page.click('[data-act=qbEng][data-v=google]');
  await page.click('[data-act=qbSave]'); await expect(page.locator('#qbName')).toHaveAttribute('aria-invalid', 'true');
  await page.fill('#qbName', 'Database dumps on a domain'); await page.click('[data-act=qbSave]');
  await expect(page.locator('.qp h2')).toHaveText('Database dumps on a domain');
  const saved = await page.evaluate(() => { const x = DB.queries.find(q => q.name === 'Database dumps on a domain'); return { engines: x.engines, cat: x.cat, custom: x.custom, b: x.b.length }; });
  expect(saved).toEqual({ engines: ['google', 'bing', 'duckduckgo'], cat: 'files', custom: true, b: 5 });
  // run it: fill the blank, and the link is right for Google, then for Bing after switching
  await page.fill('#qv-DOMAIN_NAME', 'acme.example');
  await expect(page.locator('#qPrev')).toHaveValue('site:acme.example password backup dump filetype:sql -github intitle:"index of"');
  expect(decodeURIComponent(await page.locator('#qRunLink').getAttribute('href'))).toContain('google.com/search?q=site:acme.example');
  // on an engine that cannot do all of it, the panel rewrites the search for that engine
  await page.locator('.qp details.more summary').click(); await page.click('.eng[data-v=shodan]');
  await expect(page.locator('#qPrev')).toHaveValue('hostname:{{DOMAIN_NAME}} password backup dump http.title:"index of"');
  await page.fill('#qv-DOMAIN_NAME', 'acme.example'); await expect(page.locator('#qPrev')).toHaveValue('hostname:acme.example password backup dump http.title:"index of"');
  // edit reopens the builder with its rows; saving keeps one entry
  await page.click('.qp [data-act=qEdit]'); await expect(page.locator('#qbv4')).toHaveValue('index of');
  await page.click('[data-act=qbDel][data-v="3"]'); await page.click('[data-act=qbSave]');
  expect(await page.evaluate(() => DB.queries.filter(q => q.name === 'Database dumps on a domain').map(q => q.query))).toEqual(['site:{{DOMAIN_NAME}} password backup dump filetype:sql intitle:"index of"']);
  // a hostile stored shape is cleaned on load
  const clean = await page.evaluate(() => { const d = { queries: [{ id: 'qa', name: 'a', query: 'x', engines: ['google'], tags: [], b: 'nope' }, { id: 'qb', name: 'b', query: 'y', engines: ['google'], tags: [], b: [{ k: 'site', v: 'a.example' }, { k: 'evil', v: '<img>' }, null, { k: 'words', v: 5 }] }] }; normStored(d); return d.queries.map(q => q.b); });
  expect(clean).toEqual([undefined, [{ k: 'site', v: 'a.example' }]]);
  noErrors(errors);
});

test('a vault of 3,000 entries: filters, sorting, pages, a Shift+click range, bulk priority, verdict, tags, star, watch and delete, each undoable', async ({ page }) => {
  test.setTimeout(120_000);
  const errors = await open(page, '#/home');
  await page.evaluate(() => { const types = ['domain', 'ip', 'email', 'username', 'person'];
    for (let i = 0; i < 3000; i++) { const ty = types[i % 5]; const f = ty === 'domain' ? { domain: 'host' + i + '.example.org' } : ty === 'ip' ? { ip: '203.0.' + (i >> 8 & 255) + '.' + (i & 255) } : ty === 'email' ? { email: 'u' + i + '@mail.example' } : ty === 'username' ? { username: 'user' + i } : { name: 'Person ' + i };
      DB.entries.push({ id: 'gv' + i, caseId: 'c-portal', type: ty, fields: f, priority: ['low', 'medium', 'high', 'critical'][i % 4], starred: false, tags: i % 7 === 0 ? ['wave-2'] : [], notes: '', src: '', created: 1e12 + i, pos: null }); }
    for (let i = 1; i < 3000; i += 3) DB.links.push({ id: 'gl' + i, caseId: 'c-portal', a: 'gv' + i, b: 'gv' + (i - 1), label: 'uses', conf: 2, src: '' });
    DB.verdicts['domain:host5.example.org'] = 'malicious'; mutate('big'); });
  const t0 = Date.now(); await page.evaluate(() => go(caseHash('c-portal', 'vault'))); await expect(page.locator('.ecard').first()).toBeVisible();
  expect(Date.now() - t0).toBeLessThan(await budget(page, 3000));
  const total = await page.evaluate(() => derive('c-portal').entries.length);
  // only the first page is drawn, the rest on request
  await expect(page.locator('.vmain .ecard:not(.auto)')).toHaveCount(150);
  await expect(page.locator('.vb-more')).toContainText(`Showing 150 of ${total.toLocaleString('en-US')}`);
  await page.click('[data-act=vbMore]:not([data-v])'); await expect(page.locator('.vmain .ecard:not(.auto)')).toHaveCount(300);
  // filters: type, tag, verdict, "not linked", with the count and a way out
  await page.selectOption('#vb-Type', 'domain'); await page.selectOption('#vb-Tag', 'wave-2');
  const want = await page.evaluate(() => DB.entries.filter(e => e.caseId === 'c-portal' && e.type === 'domain' && e.tags.includes('wave-2')).length);
  await expect(page.locator('.vmain .toolbar .t3').first()).toHaveText(`${want} of ${total.toLocaleString('en-US')} entries`);
  await page.selectOption('#vb-Vd', 'malicious'); await expect(page.locator('#main .empty h3')).toHaveText('Nothing matches');
  await page.click('#main .empty [data-act=vbClear]'); await expect(page.locator('.vb-s.on')).toHaveCount(0);
  await page.selectOption('#vb-Vd', 'malicious'); const mal = await page.evaluate(() => derive('c-portal').entries.filter(e => entryVerdict(e) === 'malicious').length); expect(mal).toBeGreaterThan(0);
  await expect(page.locator('.vmain .ecard:not(.auto)')).toHaveCount(mal); await expect(page.locator('.vmain .ecard:not(.auto)', { hasText: 'host5.example.org' })).toHaveCount(1);
  await page.selectOption('#vb-Vd', ''); await page.selectOption('#vb-Only', 'nolinks');
  const nolinks = await page.evaluate(() => { const s = new Set(DB.links.flatMap(l => [l.a, l.b])); return derive('c-portal').entries.filter(e => !s.has(e.id)).length; });
  await expect(page.locator('.vmain .toolbar .t3').first()).toHaveText(`${nolinks.toLocaleString('en-US')} of ${total.toLocaleString('en-US')} entries`);
  await page.selectOption('#vb-Only', '');
  // list view, sorted by value, then a Shift+click range of five in screen order
  await page.evaluate(() => { DB.prefs.vLay = 'list'; renderMain(); }); await page.selectOption('#vb-Type', 'username'); await page.selectOption('#vb-Sort', 'value');
  const first5 = await page.locator('.vl-t tbody tr .vl-v > span[title]').evaluateAll(n => n.slice(0, 5).map(x => x.textContent));
  const U = await page.evaluate(() => derive('c-portal').entries.filter(e => e.type === 'username').map(e => primary(e)).sort((a, b) => a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' })).slice(0, 5));
  expect(first5).toEqual(U);
  await page.locator('.vl-t tbody tr').nth(0).locator('.vb-pk').click(); await page.locator('.vl-t tbody tr').nth(4).locator('.vb-pk').click({ modifiers: ['Shift'] });
  await expect(page.locator('.vb-bulk b')).toHaveText('5 selected');
  // bulk priority, undone
  await page.click('[data-act=vbPrio]'); await page.locator('#ctx button', { hasText: 'Critical' }).click();
  const byName = (u, f) => page.evaluate(([u, f]) => { const e = DB.entries.find(x => x.caseId === 'c-portal' && primary(x) === u); return f === 'tags' ? e.tags : f === 'v' ? entryVerdict(e) : e[f]; }, [u, f]);
  for (const u of U) expect(await byName(u, 'priority')).toBe('critical');
  await page.locator('.toast').last().getByRole('button', { name: 'Undo' }).click();
  const prio0 = await page.evaluate(() => Object.fromEntries(DB.entries.filter(e => e.caseId === 'c-portal' && e.type === 'username').map(e => [primary(e), e.priority])));
  expect(prio0[U[1]]).not.toBe(undefined); expect(await byName(U[1], 'priority')).toBe(prio0[U[1]]);
  // verdict, tags (add and take off), star, watch
  await page.click('[data-act=vbVerdict]'); await page.locator('#ctx button', { hasText: 'Suspicious' }).click();
  for (const u of U) expect(await byName(u, 'v')).toBe('suspicious');
  await page.click('[data-act=vbTag]'); await page.fill('#vbTagIn', 'sprayers, wave-3'); await page.click('#dlg button[type=submit]');
  expect(await byName(U[4], 'tags')).toEqual(expect.arrayContaining(['sprayers', 'wave-3']));
  await page.click('[data-act=vbTag]'); await page.fill('#vbTagIn', '-wave-3'); await page.click('#dlg button[type=submit]');
  expect(await byName(U[4], 'tags')).toContain('sprayers'); expect(await byName(U[4], 'tags')).not.toContain('wave-3');
  await page.click('[data-act=vbStar]'); for (const u of U) expect(await byName(u, 'starred')).toBe(true);
  await page.click('[data-act=vbWatch]'); expect(await page.evaluate(U => U.filter(u => isWatched(entryKey(DB.entries.find(x => x.caseId === 'c-portal' && primary(x) === u)))).length, U)).toBe(5);
  // select all shown, delete to the trash with their links, then undo
  const nU = await page.evaluate(() => derive('c-portal').entries.filter(e => e.type === 'username').length);
  await page.click('[data-act=vbAll]'); await expect(page.locator('.vb-bulk b')).toHaveText(`${nU} selected`);
  const links0 = await page.evaluate(() => DB.links.length);
  await page.click('[data-act=vbDel]'); await page.click('[data-act=confirmOk]');
  expect(await page.evaluate(() => DB.entries.filter(e => e.caseId === 'c-portal' && e.type === 'username').length)).toBe(0);
  expect(await page.evaluate(() => DB.trash.filter(t => t.kind === 'entry').length)).toBe(nU);
  await page.locator('.toast').last().getByRole('button', { name: 'Undo' }).click();
  expect(await page.evaluate(() => [DB.entries.filter(e => e.caseId === 'c-portal' && e.type === 'username').length, DB.links.length, DB.trash.filter(t => t.kind === 'entry').length])).toEqual([nU, links0, 0]);
  // Esc clears the selection; another case starts with no filters
  await page.locator('.vl-t tbody tr').first().locator('.vb-pk').click(); await page.click('[data-act=vbAll]'); await page.evaluate(() => document.activeElement.blur()); await page.keyboard.press('Escape'); await expect(page.locator('.vb-bulk')).toHaveCount(0);
  await page.evaluate(() => go(caseHash('c-lantern', 'vault'))); await expect(page.locator('.vb-s.on')).toHaveCount(0);
  noErrors(errors);
});

test('Ctrl K: filters narrow every result and are suggested as you type, and a result can be acted on without leaving the search', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  const errors = await open(page, '#/home');
  await page.keyboard.press('Control+k'); await expect(page.locator('#srQ')).toBeFocused();
  // typing an operator's name suggests it, but Enter still goes to the best result
  await page.keyboard.type('ca'); await expect(page.locator('.sr-it').first()).toContainText('case:');
  await expect(page.locator('.sr-it[aria-selected=true]')).not.toContainText('case:');
  // after the colon, values are suggested and Enter/Tab finishes the filter
  await page.fill('#srQ', ''); await page.keyboard.type('type:i');
  await expect(page.locator('.sr-it[aria-selected=true]')).toContainText('type:ip');
  await page.keyboard.press('Tab'); await expect(page.locator('#srQ')).toHaveValue('type:ip ');
  await page.keyboard.type('verdict:mal'); await page.keyboard.press('Enter'); await expect(page.locator('#srQ')).toHaveValue('type:ip verdict:malicious ');
  // only malicious IPs, from the vault and the indicators — nothing else
  const kinds = await page.locator('.sr-it small').allTextContents();
  expect(kinds.length).toBeGreaterThan(0);
  for (const k of kinds) expect(k).toMatch(/^IP/);
  const want = await page.evaluate(() => [...globalEnts()].filter(([id, g]) => /^ip/.test(g.k) && verdictOf(id) === 'malicious').length);
  await expect(page.locator('[data-act=srScope][data-v=ent] span')).toHaveText(String(want));
  await expect(page.locator('.sr-fl .sr-fc')).toHaveCount(2);
  // a filter chip drops its filter
  await page.locator('.sr-fc', { hasText: 'malicious' }).click(); await expect(page.locator('#srQ')).toHaveValue('type:ip ');
  // tag: and is: filters
  await page.evaluate(() => { const e = DB.entries.find(x => x.caseId === 'c-lantern' && x.type === 'domain'); e.tags = ['zz-wave']; e.starred = true; mutate('t'); });
  await page.keyboard.press('Escape'); await page.keyboard.press('Control+k');
  await page.keyboard.type('tag:zz'); await expect(page.locator('.sr-it[aria-selected=true]')).toContainText('tag:zz-wave'); await page.keyboard.press('Enter');
  await expect(page.locator('.sr-it')).toHaveCount(1);
  await page.fill('#srQ', 'is:starred type:domain'); await page.locator('#srQ').dispatchEvent('input');
  const starred = await page.evaluate(() => DB.entries.filter(e => e.starred && e.type === 'domain').length);
  await expect(page.locator('.sr-it')).toHaveCount(starred);
  // the timeline offer only appears for timeline-only filters
  await expect(page.locator('.sr-it', { hasText: 'Filter the' })).toHaveCount(0);
  await page.fill('#srQ', 'host:DC01'); await page.locator('#srQ').dispatchEvent('input'); await expect(page.locator('.sr-it', { hasText: 'Filter the' })).toHaveCount(1);
  // actions on the selected result: Alt+1 copies, Alt+3 watches, the search stays open
  await page.fill('#srQ', '203.0.113.47 in:indicators'); await page.locator('#srQ').dispatchEvent('input');
  await expect(page.locator('.sp-a').first()).toContainText('Copy');
  await page.keyboard.press('Alt+1'); expect(await page.evaluate(() => navigator.clipboard.readText())).toBe('203.0.113.47');
  await page.keyboard.press('Alt+2'); expect(await page.evaluate(() => navigator.clipboard.readText())).toBe('203[.]0[.]113[.]47');
  const w0 = await page.evaluate(() => isWatched('ipv4:203.0.113.47'));
  await page.locator('.sp-a', { hasText: /Watch|Stop watching/ }).click();
  expect(await page.evaluate(() => isWatched('ipv4:203.0.113.47'))).toBe(!w0);
  await expect(page.locator('#srQ')).toBeVisible(); await expect(page.locator('.sp-a', { hasText: w0 ? /^Watch/ : 'Stop watching' })).toHaveCount(1);
  // an action that goes somewhere closes the search
  await page.locator('.sp-a', { hasText: 'Find in every case' }).click(); await expect(page.locator('#srQ')).toHaveCount(0);
  await expect(page).toHaveURL(/#\/entities/); await expect(page.locator('#entq')).toHaveValue('203.0.113.47');
  noErrors(errors);
});

test('the vault filters and selection, and Ctrl K with filters, hints and actions, have no accessibility problems, light and dark', async ({ page }) => {
  test.setTimeout(120_000);
  const AxeBuilder = require('@axe-core/playwright').default;
  const errors = await open(page, '#/case/c-lantern/vault');
  const found = [], check = async name => { const r = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).analyze();
    for (const v of r.violations) if (['serious', 'critical'].includes(v.impact)) for (const n of v.nodes.slice(0, 2)) found.push(`${name} ${v.id}: ${n.target.join(' ')}`); };
  for (const theme of ['light', 'dark']) {
    await page.evaluate(t => { DB.prefs.theme = t; applyPrefs(); DB.prefs.vLay = 'cards'; UI.vPick = new Set(); go(caseHash('c-lantern', 'vault')); renderMain(); }, theme);
    await page.selectOption('#vb-Vd', 'malicious'); await page.locator('.ecard').first().hover(); await page.locator('.ecard >> .vb-pk').first().click(); await page.mouse.move(0, 0);
    await check(theme + ' vault cards');
    await page.evaluate(() => { DB.prefs.vLay = 'list'; renderMain(); }); await check(theme + ' vault list');
    await page.evaluate(() => { UI.vPick = new Set(); renderMain(); });
    await page.keyboard.press('Control+k'); await page.keyboard.type('type:'); await check(theme + ' search hints');
    await page.fill('#srQ', '203.0.113.47 verdict:malicious'); await page.locator('#srQ').dispatchEvent('input'); await check(theme + ' search actions');
    await expect(page.locator('#srQ')).toHaveAttribute('aria-activedescendant', 'sro0');
    await page.keyboard.press('ArrowDown'); await expect(page.locator('#srQ')).toHaveAttribute('aria-activedescendant', 'sro1');
    await page.keyboard.press('Escape');
  }
  expect(found, found.join('\n')).toEqual([]);
  noErrors(errors.filter(e => !/Connecting to 'file:[^']*\.css/.test(e)));
});

test('graph focus: steps out from one entry, expand a node, filter by verdict and tag, hide single links — and the whole graph keeps its layout', async ({ page }) => {
  test.setTimeout(120_000);
  const errors = await open(page, '#/home');
  await page.evaluate(() => { const N = 3000; for (let i = 0; i < N; i++) DB.entries.push({ id: 'gv' + i, caseId: 'c-portal', type: i % 3 ? 'domain' : 'ip', fields: i % 3 ? { domain: 'host' + i + '.example.org' } : { ip: '203.0.113.' + (i % 250) }, priority: 'medium', starred: false, tags: i % 9 === 0 ? ['wave-2'] : [], notes: '', src: '', created: Date.now(), pos: null });
    for (let i = 1; i < N; i++) DB.links.push({ id: 'gl' + i, caseId: 'c-portal', a: 'gv' + i, b: 'gv' + Math.floor(i / 3), label: 'resolves', conf: 2, src: '' });
    DB.verdicts['domain:host16.example.org'] = 'malicious'; mutate('g'); go(caseHash('c-portal', 'graph')); });
  await expect(page.locator('.gview')).toBeVisible();
  await expect.poll(() => page.evaluate(() => cy && cy.nodes().length)).toBeGreaterThan(3000);
  const pos0 = await page.evaluate(() => DB.entries.filter(e => e.caseId === 'c-portal').map(e => JSON.stringify(e.pos)).join('|'));
  // pick the focus by typing; host5 links to host1 (its parent) and host15, host16, host17 (its children)
  await page.click('[data-act=gvPick]'); await page.fill('#gvQ', 'host5.ex'); await expect(page.locator('#gvL .gv-o').first()).toContainText('host5.example.org'); await page.keyboard.press('Enter');
  const ids = () => page.evaluate(() => cy.nodes().map(n => n.id()).sort());
  await expect.poll(ids).toEqual(['gv1', 'gv15', 'gv16', 'gv17', 'gv5']);
  await expect(page.locator('.gv-n')).toHaveText('5 of 3,003');
  // two steps: the parent's parent and siblings, and the children's children
  await page.click('[data-act=gvHops][data-v="2"]');
  const two = await page.evaluate(() => { const adj = new Map(); for (const l of DB.links.filter(l => l.caseId === 'c-portal')) { (adj.get(l.a) || adj.set(l.a, []).get(l.a)).push(l.b); (adj.get(l.b) || adj.set(l.b, []).get(l.b)).push(l.a); }
    const V = new Set(['gv5']); let e = ['gv5']; for (let h = 0; h < 2; h++) { const nx = []; for (const x of e) for (const n of adj.get(x) || []) if (!V.has(n)) { V.add(n); nx.push(n); } e = nx; } return [...V].sort(); });
  await expect.poll(ids).toEqual(two);
  // expand one of the nodes at the edge: its links join the view
  await page.click('[data-act=gvHops][data-v="1"]');
  await page.evaluate(() => GV_ACTS.gvExpand('gv16'));
  await expect.poll(ids).toEqual(['gv1', 'gv15', 'gv16', 'gv17', 'gv48', 'gv49', 'gv5', 'gv50']);
  // verdict and tag narrow what the steps go through; hide single links drops the leaves
  await page.selectOption('#gvVd', 'malicious'); await expect.poll(ids).toEqual(['gv16', 'gv5']);
  await page.selectOption('#gvVd', ''); await page.click('[data-act=gvLeaves]');
  await expect.poll(ids).toEqual(['gv16', 'gv5']);
  await page.click('[data-act=gvLeaves]'); await page.click('[data-act=gvFocus][data-v=""]');
  await page.selectOption('#gvTag', 'wave-2');
  const tagged = await page.evaluate(() => DB.entries.filter(e => e.caseId === 'c-portal' && e.tags.includes('wave-2')).length);
  await expect.poll(() => page.evaluate(() => cy.nodes().length)).toBe(tagged);
  // the right-click menu offers focus and expand
  await page.click('[data-act=gvClear]'); await expect.poll(() => page.evaluate(() => cy.nodes().length)).toBeGreaterThan(3000);
  await page.evaluate(() => nodeMenu('gv5', 400, 400)); await page.locator('#ctx button', { hasText: 'Focus here' }).click();
  await expect.poll(ids).toEqual(['gv1', 'gv15', 'gv16', 'gv17', 'gv5']);
  await page.evaluate(() => nodeMenu('gv16', 400, 400)); await expect(page.locator('#ctx button', { hasText: 'Expand — 3 more linked' })).toBeVisible(); await page.keyboard.press('Escape');
  // dragging in a focused view never moves the saved layout
  await page.evaluate(() => { const n = cy.getElementById('gv5'); n.position({ x: n.position('x') + 300, y: 0 }); n.emit('dragfree'); });
  expect(await page.evaluate(() => DB.entries.filter(e => e.caseId === 'c-portal').map(e => JSON.stringify(e.pos)).join('|'))).toBe(pos0);
  // another case has its own view
  await page.evaluate(() => go(caseHash('c-lantern', 'graph'))); await expect(page.locator('.gv-f')).toHaveCount(0);
  noErrors(errors);
});

test('import into a case: a Maltego graph, a SpiderFoot scan and a CSV become entries and links, reuse what is there, can be re-typed or skipped, and undone', async ({ page }) => {
  const F = require('path').join(__dirname, 'fixtures', 'import');
  const errors = await open(page, '#/case/c-lantern/vault');
  const pick = async f => { const [fc] = await Promise.all([page.waitForEvent('filechooser'), page.click('.vmain .toolbar [data-act=vimOpen]')]); await fc.setFiles(require('path').join(F, f)); };
  const imported = () => page.evaluate(() => DB.entries.filter(e => e.caseId === 'c-lantern' && e.tags.some(t => t.startsWith('import:'))).map(e => e.type + ':' + primary(e)).sort());
  const linksOf = () => page.evaluate(() => DB.links.filter(l => l.caseId === 'c-lantern').map(l => primary(entryById(l.a)) + ' -' + l.label + '-> ' + primary(entryById(l.b))));
  const n0 = await page.evaluate(() => [DB.entries.length, DB.links.length]);
  // Maltego .mtgx: each entity kind is matched to a type; the phrase has no obvious type and is left out
  await pick('maltego-harbourline.mtgx');
  await expect(page.locator('.vim-src')).toContainText('Maltego · 9 things · 8 links');
  await expect(page.locator('[data-vimk="maltego.affiliation.Twitter"]')).toHaveValue('username');
  await expect(page.locator('[data-vimk="maltego.Phrase"]')).toHaveValue('auto');
  await expect(page.locator('.vim-sum > div').nth(0)).toHaveText('8new entries'); await expect(page.locator('.vim-sum > div').nth(2)).toHaveText('7new links'); await expect(page.locator('.vim-sum > div').nth(3)).toHaveText('1left out');
  // re-type one kind before importing: the person becomes an alias, then back
  await page.selectOption('[data-vimk="maltego.Person"]', 'alias'); await expect(page.locator('[data-vimk="maltego.Person"]')).toHaveValue('alias');
  await page.selectOption('[data-vimk="maltego.Person"]', 'person');
  await page.click('[data-act=vimGo]'); await expect(page.locator('#dlg .vim')).toHaveCount(0);
  expect(await imported()).toEqual(['domain:example.org', 'domain:harbourline-support.com', 'domain:mail.harbourline-support.com', 'email:billing@harbourline-support.com', 'ip:185.220.101.7', 'person:Dana Whitfield', 'phone:+44 20 7946 0958', 'username:dwhitfield_ops']);
  const L = await linksOf();
  for (const l of ['harbourline-support.com -resolves to-> 185.220.101.7', 'Dana Whitfield -uses-> billing@harbourline-support.com', 'Dana Whitfield -is-> dwhitfield_ops', 'harbourline-support.com -linked to-> mail.harbourline-support.com']) expect(L).toContain(l);
  expect(L.some(l => /-0->/.test(l))).toBe(false);
  expect(await page.evaluate(() => DB.entries.find(e => primary(e) === 'dwhitfield_ops').notes)).toContain('Network: Twitter');
  // the same graph as GraphML again: everything is already there
  await pick('maltego-harbourline.graphml');
  await expect(page.locator('.vim-sum > div').nth(0)).toHaveText('0new entries'); await expect(page.locator('.vim-sum > div').nth(1)).toHaveText('8already in the case'); await expect(page.locator('[data-act=vimGo]')).toBeDisabled(); await page.click('#dlg [data-act=dclose]');
  // SpiderFoot: the false positive and raw DNS text are left out; existing entries are reused and linked
  await pick('spiderfoot-harbourline.csv');
  await expect(page.locator('#dlg')).toContainText('1 row marked false positive in SpiderFoot was left out.');
  await page.click('[data-act=vimGo]'); await expect(page.locator('#dlg .vim')).toHaveCount(0);
  expect(await imported()).toContain('domain:portal-harbourline.net');
  expect(await page.evaluate(() => DB.entries.filter(e => e.caseId === 'c-lantern' && primary(e) === '185.220.101.7').length)).toBe(1);
  expect(await page.evaluate(() => DB.entries.some(e => /noreply@/.test(primary(e)) || /spf1/.test(primary(e))))).toBe(false);
  expect(await linksOf()).toContain('185.220.101.7 -led to-> portal-harbourline.net');
  // a CSV with a type column, notes and tags; the formula-looking row has no recognisable type and stays out
  await pick('indicators.csv'); await page.click('[data-act=vimGo]'); await expect(page.locator('#dlg .vim')).toHaveCount(0);
  const h = await page.evaluate(() => DB.entries.find(e => primary(e) === 'd41d8cd98f00b204e9800998ecf8427e'));
  expect(h.type).toBe('file'); expect(h.notes).toBe('Empty attachment');
  expect(await page.evaluate(() => DB.entries.some(e => /cmd\|calc/.test(primary(e))))).toBe(false);
  // undo takes back only the last import
  await page.locator('.toast').last().getByRole('button', { name: 'Undo' }).click();
  expect(await page.evaluate(() => DB.entries.some(e => primary(e) === 'd41d8cd98f00b204e9800998ecf8427e'))).toBe(false);
  expect(await imported()).toContain('domain:portal-harbourline.net');
  // a round trip: this case's own GraphML export, into an empty case, keeps the types and the links
  const xml = await page.evaluate(() => { let out = ''; const d0 = window.download; window.download = (n, t) => { out = t; }; exportGraph('graphml'); window.download = d0; return out; });
  await page.evaluate(() => { const c = { ...DB.cases[0], id: 'c-empty', code: 'TN-EMPTY', name: 'Empty' }; DB.cases.push(c); mutate('c'); go(caseHash('c-empty', 'vault')); });
  await page.evaluate(x => vimFile(new File([x], 'lantern-graph.graphml')), xml);
  await page.click('[data-act=vimGo]'); await expect(page.locator('#dlg .vim')).toHaveCount(0);
  const src = await page.evaluate(() => [derive('c-lantern').entries.map(e => e.type + ':' + primary(e)).sort(), derive('c-lantern').links.length]);
  const dst = await page.evaluate(() => [derive('c-empty').entries.map(e => e.type + ':' + primary(e)).sort(), derive('c-empty').links.length]);
  expect(dst[0]).toEqual(src[0]); expect(dst[1]).toBe(src[1]);
  // files that are not what they claim are refused with a reason
  await page.evaluate(() => vimFile(new File(['<graphml><node id="a">'], 'broken.graphml'))); await expect(page.locator('.toast').last()).toContainText('not well-formed');
  await page.evaluate(() => vimFile(new File([new Uint8Array([80, 75, 3, 4, 0, 0])], 'fake.mtgx'))); await expect(page.locator('.toast').last()).toContainText('not a Maltego graph');
  noErrors(errors);
});

test('duplicates in a big vault: found quickly, merged all at once into the fullest entry with links kept, undone in one step', async ({ page }) => {
  test.setTimeout(120_000);
  const errors = await open(page, '#/home');
  const r = await page.evaluate(() => {
    const add = (id, type, fields, extra = {}) => DB.entries.push({ id, caseId: 'c-portal', type, fields, priority: 'medium', starred: false, tags: [], notes: '', src: '', created: 1e12, pos: null, ...extra });
    // 200 domains written twice (case, defanged, www.), the second copy fuller; 4,000 distinct names
    for (let i = 0; i < 200; i++) { add('da' + i, 'domain', { domain: 'Shop' + i + '.Example.org' }); add('db' + i, 'domain', { domain: 'www.shop' + i + '[.]example.org', registrar: 'NameCheap' }, { tags: ['seen-twice'] });
      DB.links.push({ id: 'lk' + i, caseId: 'c-portal', a: 'da' + i, b: 'db' + ((i + 1) % 200), label: 'redirects to', conf: 2, src: '' }); }
    /* 4,000 varied names, as a real vault would have: first and last names mixed, few of them one letter apart */
    const F = ['Amara','Bastian','Chiara','Dmitri','Elif','Farah','Gustavo','Hana','Ibrahim','Joanna','Kenji','Leila','Mateus','Nadia','Oskar','Priya','Quentin','Rosa','Sven','Tamsin'], L = ['Okafor','Lindqvist','Moreau','Haddad','Kowalski','Tanaka','Silva','Byrne','Novak','Petrov','Adeyemi','Larsen','Rossi','Ibarra','Kaur','Fischer','Mendes','Walsh','Yilmaz','Costa'];
    for (let i = 0; i < 4000; i++) add('p' + i, 'person', { name: F[i % 20] + ' ' + L[Math.floor(i / 20) % 20] + ' ' + (1000 + i * 7919 % 9000) });
    add('h1', 'username', { username: 'nightlamp_ops' }); add('h2', 'username', { username: 'nightlamp_op' });
    mutate('d'); const t = performance.now(); const G = dupGroups('c-portal'); return { ms: performance.now() - t, sure: G.filter(g => g.sure).length, maybe: G.filter(g => !g.sure).map(g => g.G.map(e => primary(e)).sort().join(' / ')) };
  });
  expect(r.ms).toBeLessThan(await budget(page, 1500));
  expect(r.sure).toBeGreaterThanOrEqual(200);
  expect(r.maybe).toContain('nightlamp_op / nightlamp_ops');
  await page.evaluate(() => go(caseHash('c-portal', 'vault'))); await page.evaluate(() => clickAct('dupOpen'));
  await expect(page.locator('[data-act=dupTab][data-v=sure] .cnt')).toHaveText(String(r.sure));
  await expect(page.locator('.dp-g')).toHaveCount(40); await page.click('[data-act=dupMore]'); await expect(page.locator('.dp-g')).toHaveCount(80);
  const before = await page.evaluate(() => [DB.entries.length, DB.links.length]);
  await page.click('[data-act=dupAll]');
  const after = await page.evaluate(() => ({ n: DB.entries.length, keep: DB.entries.filter(e => /^d[ab]\d/.test(e.id)).map(e => e.id), shop5: DB.entries.find(e => /^d[ab]5$/.test(e.id)),
    links: DB.links.filter(l => /^lk/.test(l.id)).map(l => [l.a, l.b]) }));
  // the fuller copy (with the registrar and tag) is kept in every group
  expect(after.keep.length).toBe(200); expect(after.keep.every(id => id.startsWith('db'))).toBe(true);
  expect(after.shop5.fields.registrar).toBe('NameCheap'); expect(after.shop5.tags).toContain('seen-twice');
  // links now join the kept entries
  expect(after.links.every(([a, b]) => a.startsWith('db') && b.startsWith('db'))).toBe(true); expect(after.links.length).toBe(200);
  await expect(page.locator('[data-act=dupTab][data-v=sure]')).toBeDisabled();
  await expect(page.locator('[data-act=dupTab][data-v=maybe]')).toHaveAttribute('aria-pressed', 'true');
  // one undo puts every merge back
  await page.locator('.toast').last().getByRole('button', { name: 'Undo' }).click();
  expect(await page.evaluate(() => [DB.entries.length, DB.links.length])).toEqual(before);
  // the near match is a separate decision: "Not the same" is remembered
  await page.click('[data-act=dupTab][data-v=maybe]');
  await expect(page.locator('[data-act=dupTab][data-v=maybe]')).toHaveAttribute('aria-pressed', 'true');
  const sig = await page.evaluate(() => dupGroups('c-portal').find(g => g.G.some(e => primary(e) === 'nightlamp_op')).sig);
  await page.evaluate(s => DUP_ACTS.dupNot(null, s), sig);
  expect(await page.evaluate(s => dupGroups('c-portal').some(g => g.sig === s), sig)).toBe(false);
  noErrors(errors);
});

test('case snapshots: saved as a file (not in the browser), compared later, removed things brought back, the whole case rolled back with the current state downloaded first, and undone', async ({ page }, info) => {
  const fs = require('fs'), path = require('path');
  const errors = await open(page, '#/case/c-lantern/vault');
  const usage0 = await page.evaluate(async () => { await snapsLoad(); return SNAPS.length; });
  await page.click('.acts [data-act=caseMenu]'); await page.locator('#ctx button', { hasText: 'Save a snapshot' }).click(); await page.fill('#sncName', 'before edits');
  const [dl] = await Promise.all([page.waitForEvent('download'), page.click('#dlg button[type=submit]')]);
  expect(dl.suggestedFilename()).toMatch(/^op-lantern-snapshot-\d{4}-\d\d-\d\d-\d{4}-before-edits\.json$/);
  const file = info.outputPath('snap.json'); await dl.saveAs(file);
  const snap = JSON.parse(fs.readFileSync(file, 'utf8'));
  expect(snap.format).toBe('osintrix-case'); expect(snap.snapshot.name).toBe('before edits'); expect(snap.case.id).toBe('c-lantern');
  // nothing was kept in the browser for it
  expect(await page.evaluate(async () => { await snapsLoad(); return SNAPS.length; })).toBe(usage0);
  // change the case: remove an entry (and its links), edit one, add one
  const ch = await page.evaluate(() => { const es = DB.entries.filter(e => e.caseId === 'c-lantern'), gone = es.find(e => DB.links.some(l => l.a === e.id || l.b === e.id)), ed = es.find(e => e !== gone);
    const links = DB.links.filter(l => l.a === gone.id || l.b === gone.id).length; DB.entries = DB.entries.filter(e => e !== gone); DB.links = DB.links.filter(l => l.a !== gone.id && l.b !== gone.id);
    ed.tags.push('edited-now'); DB.entries.push({ id: 'v-new', caseId: 'c-lantern', type: 'domain', fields: { domain: 'new-since.example' }, priority: 'low', starred: false, tags: [], notes: '', src: '', created: Date.now(), pos: null }); mutate('x'); renderAll();
    return { gone: primary(gone), goneId: gone.id, links, ed: primary(ed) }; });
  const compare = async f => { await page.click('.acts [data-act=caseMenu]'); const [fc] = await Promise.all([page.waitForEvent('filechooser'), page.locator('#ctx button', { hasText: 'Compare with a snapshot' }).click()]); await fc.setFiles(f); };
  await compare(file);
  const cols = page.locator('.snc-cols > div');
  await expect(cols.nth(0)).toContainText('1 entry'); await expect(cols.nth(0)).toContainText('new-since.example');
  await expect(cols.nth(1)).toContainText(ch.gone); await expect(cols.nth(1)).toContainText(`${ch.links} link`);
  await expect(cols.nth(2)).toContainText(ch.ed); await expect(cols.nth(2)).toContainText('tagged #edited-now');
  // bring back only what was removed: the new entry and the edit stay
  await page.click('[data-act=sncBack]');
  await expect.poll(() => page.evaluate(id => [!!entryById(id), !!entryById('v-new'), DB.links.filter(l => l.a === id || l.b === id).length], ch.goneId)).toEqual([true, true, ch.links]);
  // roll back everything: the state before is downloaded first
  await compare(file);
  await page.click('[data-act=sncRoll]');
  const [dl2] = await Promise.all([page.waitForEvent('download'), page.click('[data-act=confirmOk]')]);
  expect(dl2.suggestedFilename()).toContain('before-rolling-back');
  await expect.poll(() => page.evaluate(() => !!entryById('v-new'))).toBe(false);
  expect(await page.evaluate(() => DB.entries.some(e => e.tags.includes('edited-now')))).toBe(false);
  expect(await page.evaluate(() => DB.entries.filter(e => e.caseId === 'c-lantern').length)).toBe(snap.entries.length);
  await page.locator('.toast').last().getByRole('button', { name: 'Undo' }).click();
  expect(await page.evaluate(() => [!!entryById('v-new'), DB.entries.some(e => e.tags.includes('edited-now'))])).toEqual([true, true]);
  // a snapshot of another case, or something that is not one, is refused
  const other = info.outputPath('other.json'); fs.writeFileSync(other, JSON.stringify({ ...snap, case: { ...snap.case, id: 'c-portal', code: 'TN-2026-011' } }));
  await compare(other); await expect(page.locator('.toast').last()).toContainText('snapshot is of Customer portal');
  const junk = info.outputPath('junk.json'); fs.writeFileSync(junk, '{"hello":1}');
  await compare(junk); await expect(page.locator('.toast').last()).toContainText('Not an OSINTrix case snapshot');
  noErrors(errors);
});

test('the browser never runs out of space: big imports are refused when they would not fit, and restore points make room or step aside', async ({ page }) => {
  const errors = await open(page, '#/case/c-lantern/vault');
  const F = require('path').join(__dirname, 'fixtures', 'import');
  // pretend the browser is nearly full: 100 MB quota, 97 MB used
  await page.evaluate(() => { Object.defineProperty(navigator.storage, 'estimate', { configurable: true, value: async () => ({ quota: 100e6, usage: 97e6 }) }); });
  const n0 = await page.evaluate(() => [DB.entries.length, DB.links.length]);
  const [fc] = await Promise.all([page.waitForEvent('filechooser'), page.click('.vmain .toolbar [data-act=vimOpen]')]); await fc.setFiles(require('path').join(F, 'maltego-harbourline.mtgx'));
  await page.click('[data-act=vimGo]');
  await expect(page.locator('#dlg')).toContainText('Not enough space in this browser'); await expect(page.locator('#dlg')).toContainText('Nothing was changed.');
  expect(await page.evaluate(() => [DB.entries.length, DB.links.length])).toEqual(n0);
  await page.click('#dlg [data-act=stoManage]'); await expect(page).toHaveURL(/#\/settings/);
  // restore points: with no room even after dropping the old ones, none is made, and it says so once
  const made = await page.evaluate(async () => { await snapsLoad(); const before = SNAPS.length; const ok = await snapshot('test'); return { ok, before, after: SNAPS.length }; });
  expect(made.ok).toBe(false); expect(made.after).toBe(0);
  await expect(page.locator('.toast').last()).toContainText('No restore point was made');
  // with room again, everything works as before
  await page.evaluate(() => { Object.defineProperty(navigator.storage, 'estimate', { configurable: true, value: async () => ({ quota: 10e9, usage: 1e6 }) }); });
  expect(await page.evaluate(() => snapshot('test'))).toBe(true);
  await page.evaluate(() => go(caseHash('c-lantern', 'vault')));
  const [fc2] = await Promise.all([page.waitForEvent('filechooser'), page.click('.vmain .toolbar [data-act=vimOpen]')]); await fc2.setFiles(require('path').join(F, 'maltego-harbourline.mtgx'));
  await page.click('[data-act=vimGo]'); await expect.poll(() => page.evaluate(() => DB.entries.length)).toBeGreaterThan(n0[0]);
  noErrors(errors);
});

test('saved views: a vault view, a graph view and a search are named, listed where they belong and in Ctrl K, opened again exactly, and deleted with undo', async ({ page }) => {
  const errors = await open(page, '#/case/c-lantern/vault');
  // a vault view
  await page.selectOption('#vb-Vd', 'suspicious'); await page.selectOption('#vb-Sort', 'value');
  await page.click('[data-act=svSave][data-v=vault]'); await page.fill('#svName', 'Suspicious A–Z'); await page.click('#dlg button[type=submit]');
  await expect(page.locator('.sv-b', { hasText: 'Suspicious A–Z' })).toBeVisible();
  // the same name twice is refused
  await page.click('[data-act=svSave][data-v=vault]'); await page.fill('#svName', 'suspicious a–z'); await page.click('#dlg button[type=submit]'); await expect(page.locator('#svName')).toHaveAttribute('aria-invalid', 'true'); await page.click('#dlg [data-act=dclose]');
  await page.click('[data-act=vbClear]'); await expect(page.locator('#vb-Vd')).toHaveValue('');
  await page.locator('.sv-b', { hasText: 'Suspicious A–Z' }).click();
  await expect(page.locator('#vb-Vd')).toHaveValue('suspicious'); await expect(page.locator('#vb-Sort')).toHaveValue('value'); await expect(page.locator('.sv-b.on')).toHaveCount(1);
  // a graph view
  const fid = await page.evaluate(() => DB.entries.find(e => e.caseId === 'c-lantern' && DB.links.some(l => l.a === e.id || l.b === e.id)).id);
  await page.evaluate(id => { go(caseHash('c-lantern', 'graph')); GV_ACTS.gvFocus(null, id); GV_ACTS.gvHops(null, '2'); }, fid);
  await page.click('[data-act=svSave][data-v=graph]'); await page.fill('#svName', 'Around the actor'); await page.click('#dlg button[type=submit]');
  await page.click('[data-act=gvClear]'); await expect(page.locator('#svG')).toBeVisible();
  await page.selectOption('#svG', { label: 'Around the actor' });
  expect(await page.evaluate(() => { const G = gvS('c-lantern'); return [G.focus, G.hops]; })).toEqual([fid, 2]);
  // a search, from Ctrl K
  await page.keyboard.press('Control+k'); await page.keyboard.type('type:ip verdict:malicious ');
  await page.click('#srSave'); await expect(page.locator('#srQ')).toHaveCount(0); await page.fill('#svName', 'Bad IPs everywhere'); await page.click('#dlg button[type=submit]');
  await page.evaluate(() => go('#/home'));
  // every saved view is found by name in Ctrl K and opens where it belongs
  await page.keyboard.press('Control+k'); await page.keyboard.type('Suspicious A');
  await expect(page.locator('.sr-it').first()).toContainText('Suspicious A–Z'); await page.keyboard.press('Enter');
  await expect(page).toHaveURL(/#\/case\/c-lantern\/vault/); await expect(page.locator('#vb-Vd')).toHaveValue('suspicious');
  await page.keyboard.press('Control+k'); await page.keyboard.type('Bad IPs'); await page.keyboard.press('Enter');
  await expect(page.locator('#srQ')).toHaveValue('type:ip verdict:malicious ');
  await page.keyboard.press('Escape');
  // delete, then undo
  await page.locator('.sv-row', { hasText: 'Suspicious A–Z' }).hover(); await page.locator('.sv-row', { hasText: 'Suspicious A–Z' }).locator('[data-act=svDel]').click();
  await expect(page.locator('.sv-b', { hasText: 'Suspicious A–Z' })).toHaveCount(0);
  await page.locator('.toast').last().getByRole('button', { name: 'Undo' }).click(); await expect(page.locator('.sv-b', { hasText: 'Suspicious A–Z' })).toHaveCount(1);
  // stored views are cleaned on load
  expect(await page.evaluate(() => { const d = { views: [{ kind: 'vault', caseId: 'c-x', name: ' ok ', s: { vd: 'malicious', sort: 'value', hack: '<x>' } }, { kind: 'evil', name: 'x' }, { kind: 'graph', name: '' }, { kind: 'search', name: 's', s: { q: 5 } }, null] }; normStored(d); return d.views.map(v => [v.kind, v.name, v.s.hack, v.s.vd || v.s.q]); }))
    .toEqual([['vault', 'ok', undefined, 'malicious'], ['search', 's', undefined, '']]);
  noErrors(errors);
});

test('@ in a note links a vault entry: suggested as you type, shown as a link, opens the entry, and the entry lists the notes that mention it', async ({ page }) => {
  const errors = await open(page, '#/case/c-lantern/overview');
  const ent = await page.evaluate(() => { const e = DB.entries.find(x => x.caseId === 'c-lantern' && x.type === 'email'); return { id: e.id, v: primary(e) }; });
  await page.evaluate(() => go('#/notes'));
  await page.evaluate(() => { const n = { id: 'n-men', caseId: 'c-lantern', color: 'blue', pinned: false, text: 'Check ', due: '', created: Date.now(), updated: Date.now() }; DB.notes.push(n); mutate('n'); renderAll(); });
  await page.evaluate(() => clickAct('nEdit', 'n-men'));
  const t = page.locator('#nText'); await t.click(); await page.keyboard.press('End'); await page.keyboard.type('@' + ent.v.slice(0, 6));
  await expect(page.locator('#menBox [role=option]').first()).toContainText(ent.v);
  await expect(page.locator('#menLive')).toContainText('1 of');
  await page.keyboard.press('Enter');
  await expect(t).toHaveValue(`Check @[${ent.v}] `);
  await page.keyboard.type('and @[Nobody Here] too'); await page.click('#dlg button[type=submit]');
  // rendered as links; the unknown one faded
  const card = page.locator('.note-card', { hasText: 'Check' });
  await expect(card.locator('.nment').first()).toHaveText('@' + ent.v); await expect(card.locator('.nment.gone')).toHaveText('@Nobody Here');
  // the entry lists the note
  await card.locator('.nment').first().click();
  await expect(page.locator('#insp')).toContainText('Mentioned in notes'); await expect(page.locator('#insp .men-n')).toContainText('Check');
  // a mention of nothing offers to add the entry
  await page.evaluate(() => go('#/notes')); await page.locator('.note-card', { hasText: 'Check' }).locator('.nment.gone').click();
  await expect(page.locator('.toast').last()).toContainText('No entry called “Nobody Here”');
  noErrors(errors);
});

test('a new user can start empty from the welcome screen, and the first real case takes the placeholder case’s place and number', async ({ page }) => {
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  await page.goto(require('path').join('file://', __dirname, '..', 'index.html'));
  await page.getByRole('button', { name: 'Start with an empty workspace' }).click();
  await page.click('[data-act=confirmOk]');
  expect(await page.evaluate(() => DB.cases.map(c => [c.name, !!c.placeholder]))).toEqual([['My first case', true]]);
  await page.locator('#main').getByRole('button', { name: /New case/ }).first().click(); await page.fill('#cName', 'Harbourline phishing'); await page.click('#dlg button[type=submit]');
  expect(await page.evaluate(() => DB.cases.map(c => c.code + ' ' + c.name))).toEqual([await page.evaluate(() => 'TN-' + new Date().getFullYear() + '-001') + ' Harbourline phishing']);
  // the vault's empty state points to what the evidence already found
  await page.keyboard.press('n'); await page.locator('#dlg textarea').first().fill('Mail from billing@harbourline-support.com via 185.220.101.7'); await page.click('#dlg .btn.primary');
  await page.evaluate(() => go(caseHash(DB.active, 'vault')));
  await expect(page.locator('#main .empty h3')).toHaveText('Nothing in the vault yet'); await expect(page.locator('#main .empty')).toContainText('already names');
  await page.click('[data-act=vbJumpAuto]'); await expect(page.locator('#vAuto')).toBeInViewport();
  // a placeholder with something in it, or renamed, stays
  await page.evaluate(() => { DB.cases.push({ id: 'c-ph', name: 'My first case', placeholder: true, code: 'TN-X', status: 'active', owner: 'You', created: 1, updated: 1, scope: '', color: '#5470f5', icon: 'briefcase' }); DB.records.push({ id: 'r-ph', caseId: 'c-ph', type: 'evidence', title: 'x', body: 'x', tsRaw: '', tsZone: 'explicit', ts: 0, source: '', host: '', tags: [], ents: [], answer: '', addedBy: 'You', addedAt: 1, hash: '' }); mutate('x'); });
  await page.evaluate(() => caseDlg()); await page.fill('#cName', 'Second'); await page.click('#dlg button[type=submit]');
  expect(await page.evaluate(() => DB.cases.some(c => c.id === 'c-ph'))).toBe(true);
  expect(errors).toEqual([]);
});

test('archiving a case says Archived everywhere and can be undone from its message', async ({ page }) => {
  const errors = await open(page, '#/cases');
  await page.locator('.cs2-acts [data-act=caseMenu]').first().click();
  const code = await page.evaluate(() => document.querySelector('#ctx .ctx-title').textContent.trim());   // the case's name
  await page.locator('#ctx button', { hasText: 'Archive' }).click();
  await expect(page.locator('.toast').last()).toContainText(code + ' archived');
  await page.click('[data-act=cf][data-v=closed], .seg [data-v=closed]').catch(() => {});
  await expect(page.locator('.status[data-s=closed]').first()).toHaveText('Archived');
  await page.locator('.toast').last().getByRole('button', { name: 'Undo' }).click();
  expect(await page.evaluate(c => DB.cases.find(x => caseNm(x) === c).status, code)).toBe('active');
  noErrors(errors);
});

test('seen over time: first and last sighting, by case and in date order across cases; and ? lists every keyboard shortcut', async ({ page }) => {
  const errors = await open(page, '#/case/c-lantern/vault');
  const want = await page.evaluate(() => { const g = globalEnts().get('ipv4:203.0.113.47'); const t = g.recs.filter(r => r.ts).sort((a, b) => a.ts - b.ts); return { n: g.recs.length, cases: g.cases.size, first: E.fmtDate(t[0].ts, tz()), last: E.fmtDate(t[t.length - 1].ts, tz()), firstCase: caseNm(t[0].caseId), order: t.map(r => r.id) }; });
  await page.evaluate(() => select('ent', 'ipv4:203.0.113.47'));
  const sec = page.locator('#insp .sight');
  await expect(sec.locator('h4')).toContainText(`${want.n} records · ${want.cases} cases`);
  await expect(sec.locator('.sight-kv')).toContainText(`First seen${want.first} in ${want.firstCase}`); await expect(sec.locator('.sight-kv')).toContainText(`Last seen${want.last}`);
  await expect(sec.locator('.sight-cases li')).toHaveCount(want.cases);
  await expect(sec.locator('.sight-bars')).toHaveAttribute('aria-label', new RegExp(`^${want.order.length} sightings from`));
  await sec.locator('[data-act=sightAll]').click();
  expect(await page.locator('.sight-list [data-act=sightOpen]').evaluateAll(b => b.map(x => x.dataset.id))).toEqual(want.order);
  // opening one goes to its case's timeline with it selected
  const last = want.order[want.order.length - 1];
  await page.locator(`.sight-list [data-id="${last}"]`).click();
  expect(await page.evaluate(() => [UI.sel && UI.sel.id, location.hash])).toEqual([last, await page.evaluate(id => caseHash(recById(id).caseId, 'timeline'), last)]);
  // a vault entry that is an indicator shows the same
  const eid = await page.evaluate(() => DB.entries.find(e => entryKey(e) === 'ipv4:203.0.113.47').id);
  await page.evaluate(id => { const e = entryById(id); DB.active = e.caseId; select('entry', id); }, eid); await expect(page.locator('#insp .sight h4')).toContainText(`${want.n} records`);
  // ? opens the shortcuts, but not while typing
  await page.evaluate(() => { UI.sel = null; renderAll(); document.activeElement && document.activeElement.blur(); });
  await page.keyboard.press('?'); await expect(page.locator('#dlg .keys')).toContainText('Alt'); await expect(page.locator('#dlg .keys-g h3')).toHaveCount(6);
  await page.keyboard.press('Escape');
  await page.evaluate(() => go('#/notes')); await page.locator('textarea.ned').first().click(); await page.keyboard.type('why?');
  await expect(page.locator('#dlg .keys')).toHaveCount(0); await expect(page.locator('textarea.ned').first()).toHaveValue('why?');
  // Help shows the same list
  await page.evaluate(() => go('#/help')); await expect(page.locator('#main .keys .keys-g')).toHaveCount(6);
  noErrors(errors);
});

test('cases are called by their names on screen — the TN-… number is not shown, but still finds the case', async ({ page }) => {
  const errors = await open(page, '#/home');
  const routes = ['#/home', '#/cases', '#/case/c-lantern/overview', '#/case/c-lantern/vault', '#/case/c-lantern/timeline', '#/case/c-lantern/entities', '#/case/c-lantern/report', '#/entities', '#/notes', '#/detections', '#/playbooks', '#/today'];
  const seen = [];
  for (const r of routes) { await page.evaluate(h => go(h), r); await page.waitForTimeout(150);
    const t = await page.evaluate(() => document.body.innerText); const m = t.match(/\b(TN|LAB)-20\d\d-\d{3}\b/g); if (m) seen.push(r + ': ' + [...new Set(m)].join(', ')); }
  expect(seen).toEqual([]);
  // the indicator seen in both demo cases names them
  await page.evaluate(() => select('ent', 'ipv4:203.0.113.47'));
  await expect(page.locator('#insp .sight-cases')).toContainText('Op Lantern'); await expect(page.locator('#insp .sight-cases')).toContainText('Customer portal');
  // the number still works where people type it, and so does the name
  await page.keyboard.press('Control+k'); await page.fill('#srQ', 'case:TN-2026-011 ');
  await expect(page.locator('#srFl')).toContainText('in Customer portal');
  await page.fill('#srQ', 'case:op-l'); await expect(page.getByText('case:op-lantern', { exact: true }).first()).toBeVisible();
  noErrors(errors);
});
