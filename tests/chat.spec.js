// Chat exports: a Telegram Desktop result.json and a DiscordChatExporter JSON become one record per author, with the
// account's permanent number; post times go to Active hours; a Discord ID gives its creation date; the same Telegram
// account in another case makes a persona. Plus the playbooks and the Tradecraft chapter for chat platforms.
const { test, expect } = require('@playwright/test');
const { open, capture, noErrors } = require('./helpers');
const fs = require('fs'), path = require('path');
const FX = f => fs.readFileSync(path.join(__dirname, 'fixtures', 'chat', f), 'utf8');

test('chat exports: one record per author with the permanent account number, post times, IDs dated, and a persona across cases', async ({ page }) => {
  const errors = await open(page, '#/case/c-lantern/vault');
  const tg = FX('telegram-result.json'), dc = FX('discord-export.json');
  await page.evaluate(async ([a, b]) => { DB.active = 'c-lantern'; await attachFiles([new File([a], 'result.json', { type: 'application/json' }), new File([b], 'general.json', { type: 'application/json' })]); }, [tg, dc]);
  await expect(page.locator('.toast').last()).toContainText('messages read');
  const R = await page.evaluate(() => DB.records.filter(r => r.caseId === 'c-lantern' && ((r.tags || []).includes('chat') || (r.tags || []).includes('post-times'))).map(r => ({ t: r.title, b: r.body, k: (r.ents || []).map(e => e.k + ' ' + e.v), h: r.hours ? r.hours.who : null })));
  const sup = R.find(r => r.t === 'Telegram posts by Lamp Support — Lamp Market Support');
  expect(sup).toBeTruthy(); expect(sup.b).toContain('Telegram user ID: 5550001'); expect(sup.b).toContain('Messages: 3');
  expect(sup.k).toEqual(expect.arrayContaining(['tgid 5550001', 'handle @lamp_ops'])); expect(sup.k.some(k => /^xmr /.test(k))).toBe(true);
  expect(R.find(r => r.t.startsWith('Telegram posts by Buyer Bob')).b).toContain('Telegram user ID: 5550002');
  expect(R.find(r => r.t.startsWith('Telegram posts by Lamp Market News')).b).toContain('Posted as the channel');   // a channel post has no person behind it in the export
  expect(R.some(r => /service|create_group/.test(r.b))).toBe(false);                                                // service messages are not posts
  const dcr = R.find(r => r.t === 'Discord posts by Support — Drainer Hub #general');
  expect(dcr.b).toContain('Discord user ID: 1023456789012345678'); expect(dcr.k).toContain('dcid 1023456789012345678');
  const hrs = R.filter(r => r.h); expect(hrs.length).toBe(2); expect(hrs[0].h).toEqual(expect.arrayContaining(['Lamp Support', 'Buyer Bob']));
  // a Discord ID is dated from itself
  await page.evaluate(() => select('ent', 'dcid:1023456789012345678'));
  await expect(page.locator('#insp .ipf')).toContainText('Created2022-09-25 04:51:53 UTC');
  // the same Telegram account named in another case ties the two
  await capture(page, 'Seller on the forum gave his Telegram ID: 5550001 and asked for payment to bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh', 'c-portal');
  const P = await page.evaluate(() => personas().find(p => p.ties.includes('tgid:5550001')));
  expect(P).toBeTruthy(); expect(P.cases.sort()).toEqual(['c-lantern', 'c-portal']);
  expect(P.names).not.toContain('handle:@lamp_ops');                                                               // a handle the author mentioned is someone else
  noErrors(errors);
});

test('playbooks for scammers, Discord, chat-platform actors and bot C2, and the Tradecraft chapter on chats', async ({ page }) => {
  const errors = await open(page, '#/tradecraft');
  await expect(page.locator('.tc-ch')).toHaveCount(10);
  await expect(page.locator('#tc-chat')).toContainText('The user ID is the identity'); await expect(page.locator('#tc-chat')).toContainText('Do not use credentials you find');
  await page.evaluate(async () => { await lazyNeed('pb'); ensurePlaybooks(); });
  const P = await page.evaluate(() => ['pb-chat-scam', 'pb-discord', 'pb-chat-actor', 'pb-bot-c2'].map(id => { const p = DB.playbooks.find(x => x.id === id); return p ? [p.name, p.steps.length] : null; }));
  expect(P.every(Boolean)).toBe(true); expect(P.every(([, n]) => n >= 7)).toBe(true);
  // the Discord date rule the playbook states is the one the app uses
  expect(await page.evaluate(() => Number(BigInt('1023456789012345678') / 4194304n) + 1420070400000)).toBe(1664081513408);
  noErrors(errors);
});

// three chats in one case and one in another, built like Telegram Desktop exports
const T0 = 1757844000;
const tgExport = (name, id, msgs) => JSON.stringify({ name, type: 'public_supergroup', id, messages: msgs.map((m, i) => ({ id: i + 1, type: 'message', date_unixtime: String(T0 + m.at), from: m.from, from_id: m.fid, text: m.text, ...(m.fw ? { forwarded_from: m.fw[1], forwarded_from_id: 'channel' + m.fw[0] } : {}) })) });
const PUSH = 'URGENT: the old Lamp Market link is dead, the only working mirror is in our pinned post — do not trust any other link';
const PASTE = 'I bought from this vendor three times, always fast and stealth, best on the market, highly recommend to everyone here';
const A = tgExport('Lamp Buyers EU', 101, [
  { at: 0, from: 'Lamp Support', fid: 'user5550001', text: 'Welcome to the EU buyers chat, read the rules before asking anything please' },
  { at: 600, from: 'Lamp Market News', fid: 'channel777', text: PUSH, fw: [777, 'Lamp Market News'] },
  { at: 900, from: 'acc_one', fid: 'user6000001', text: PASTE }, { at: 960, from: 'acc_two', fid: 'user6000002', text: PASTE },
  { at: 1200, from: 'Drop Alerts', fid: 'channel888', text: 'New drop locations for this week are up, check the bot for your region now', fw: [888, 'Drop Alerts'] }]);
const B = tgExport('Lamp Buyers US', 102, [
  { at: 780, from: 'Lamp Market News', fid: 'channel777', text: PUSH, fw: [777, 'Lamp Market News'] },
  { at: 1000, from: 'acc_three', fid: 'user6000003', text: PASTE },
  { at: 1300, from: 'Drop Alerts', fid: 'channel888', text: 'Drop locations for US are delayed by a day because of the courier problem', fw: [888, 'Drop Alerts'] },
  { at: 86400 * 40, from: 'LampHelp', fid: 'user5550001', text: 'Support moved to the new bot, the old one is gone, use the link in the pinned post' }]);
const C = tgExport('Lamp Reviews', 103, [
  { at: 1020, from: 'Lamp Market News', fid: 'channel777', text: PUSH, fw: [777, 'Lamp Market News'] },
  { at: 2000, from: 'Someone', fid: 'user7000001', text: 'Has anyone tested the new batch yet, I want to know before I order a lot' }]);
const D = tgExport('Other market chat', 201, [{ at: 5000, from: 'Lamp Market News', fid: 'channel777', text: 'Lamp Market News reposted in another market chat today for everyone', fw: [777, 'Lamp Market News'] }]);

test('chats & forwards: sources across chats and cases, a push within minutes and who had it first, copy-paste accounts, clusters, and names over time', async ({ page }) => {
  const errors = await open(page, '#/case/c-lantern/vault');
  await page.evaluate(async ([a, b, c, d]) => { DB.active = 'c-portal'; await attachFiles([new File([d], 'other.json', { type: 'application/json' })]);
    DB.active = 'c-lantern'; await attachFiles([new File([a], 'eu.json', { type: 'application/json' }), new File([b], 'us.json', { type: 'application/json' }), new File([c], 'reviews.json', { type: 'application/json' })]); }, [A, B, C, D]);
  await page.evaluate(() => { UI.ivView = 'chats'; go(caseHash('c-lantern', 'infra')); });
  const V = page.locator('.cn');
  await expect(V.locator('.cn-sum')).toContainText('3chats'); await expect(V.locator('.cn-sum')).toContainText('2sources forwarded from');
  // sources: News reached all three chats and is also in the other case
  const news = V.locator('.cn-t tr', { hasText: 'Lamp Market News' });
  await expect(news.locator('td.n').nth(1)).toHaveText('3'); await expect(news).toContainText('also in Customer portal');
  await expect(V.locator('.cn-t tr', { hasText: 'Drop Alerts' }).locator('td.n').nth(1)).toHaveText('2');
  // the push: three chats within 7 minutes, EU first
  const p = V.locator('.cn-p.fast').first();
  await expect(p).toContainText('Within 7 min — 3 chats, from Lamp Market News'); await expect(p).toContainText('Lamp Buyers EU first · Lamp Buyers US +3 min · Lamp Reviews +7 min');
  // copy-paste: three accounts, two chats
  await expect(V.locator('.cn-c').first()).toContainText('3 accounts in 2 chats'); await expect(V.locator('.cn-c').first()).toContainText('acc_one');
  // the two buyers chats share both sources: one cluster; the reviews chat shares only one of two
  await expect(V.locator('.cn-cl').first()).toContainText('Lamp Buyers EU · Lamp Buyers US');
  await expect(V.locator('.cn-map path')).toHaveCount(5);
  // the support account renamed: same number, two names, in order
  await expect(V).toContainText('Lamp Support → LampHelp');
  await page.evaluate(() => select('ent', 'tgid:5550001'));
  const nh = page.locator('#insp .cn-nh li');
  await expect(nh).toHaveCount(2); await expect(nh.nth(0)).toContainText('Lamp Support'); await expect(nh.nth(1)).toContainText('LampHelp');
  noErrors(errors);
});
