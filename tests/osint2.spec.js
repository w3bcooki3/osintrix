// OSINT additions in v1.48: active hours, the identity checklist, page changes, identity profiles and old Office metadata — each against realistic data.
const { test, expect } = require('@playwright/test');
const { open, noErrors } = require('./helpers');
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
  await expect(card.locator('.idp-gaps li', { hasText: 'Giveaway admin in ID-C is joined only by a username' })).toHaveCount(1);
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
