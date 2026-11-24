// Writing compared: two names written by one person rank closer than every other writer in the evidence, the habits
// that tie them are named, too little text says nothing, and with too few other writers no ranking is given.
const { test, expect } = require('@playwright/test');
const { open, capture, noErrors } = require('./helpers');

// neutral content; each writer gets different sentences, then their own habits are applied
const POOL = ['I shipped the order on monday and it should arrive by friday if the post is not slow', 'The quality of the last batch was better than the one before it',
  'You need to send the payment before I can confirm the address', 'I think the market will be down for a few days because of the update',
  'We had a problem with the courier last week but it is fixed now', 'If you want a discount you have to order more than ten units',
  'I do not answer messages on the weekend so please be patient', 'The new listing is up and the price is the same as before',
  'Someone asked about refunds and the answer is still no', 'My stock is low right now so I will restock next week',
  'I have been doing this for a long time and I know what works', 'The reviews were good and I want to keep it that way',
  'Do not use the old address because it is not mine anymore', 'I can not promise the delivery time for other countries',
  'The package was tracked and it shows that it arrived', 'I will be away for a few days but orders are still open',
  'There is a new rule on the forum about posting links', 'The admin said the server will move to a new host soon',
  'Please check the instructions before you ask the same question', 'I lost some money last month because of a bad buyer'];
const rnd = s => () => (s = (s * 1103515245 + 12345) % 2147483648) / 2147483648;
const styles = {
  // the same person, two names: lowercase i, dropped apostrophes, "alot", ellipses, British spelling, "mate"
  ops: s => s.replace(/\bI\b/g, 'i').replace(/\bdo not\b/g, 'dont').replace(/\bcan not\b/g, 'cant').replace(/\bis not\b/g, 'isnt').replace(/ a long time/, ' alot of time')
    .replace(/^./, c => c.toLowerCase()) + (s.length % 3 ? '...' : ' mate...') + (s.length % 4 ? '' : ' realise the colour of the bag changed.'),
  formal: s => s.replace(/\bdo not\b/g, "don't") + '. Thank you for your understanding.',
  shout: s => s.toUpperCase().replace(/\bTHE\b/g, 'THE') + '!!!',
  american: s => s + '. I realize the color and center label changed, honestly.',
  short: s => s.replace(/\byou\b/g, 'u').replace(/\bplease\b/g, 'pls') + ' thx',
};
const textOf = (style, seed, n) => { const r = rnd(seed); return Array.from({ length: n }, () => styles[style](POOL[Math.floor(r() * POOL.length)])).join(' '); };

test('writing compared: one writer behind two names ranks closest, the shared habits are named, short texts and thin baselines say so', async ({ page }) => {
  const errors = await open(page, '#/case/c-lantern/vault');
  const posts = [['lamp_ops', 'ops', 11, 30], ['lampvendor2', 'ops', 97, 30], ['quiet_buyer', 'formal', 5, 30], ['LOUD_SELLER', 'shout', 7, 30], ['yank_trader', 'american', 9, 30], ['shorty', 'short', 13, 30], ['newbie', 'formal', 21, 3]];
  await page.evaluate(P => { for (const [h, body] of P) { const r = { id: uid('r'), caseId: 'c-lantern', type: 'evidence', title: 'Posts by @' + h, body: 'Posted by @' + h + '\n' + body, ts: Date.now(), tsRaw: '', tsZone: 'explicit', source: 'forum', host: '', tags: [], answer: '', addedBy: 'You', addedAt: Date.now(), hash: '' }; r.ents = extractRich(r.body); DB.records.push(r); } mutate('posts'); },
    posts.map(([h, st, seed, n]) => [h, textOf(st, seed, n)]));
  // from the handle's panel
  await page.evaluate(() => select('ent', 'handle:@lamp_ops'));
  await page.locator('#insp [data-act=stPick]').click();
  await expect(page.locator('#dlg .li')).toHaveCount(5);                                          // every name with enough text — not the newcomer
  await page.locator('#dlg .li', { hasText: 'lampvendor2' }).click();
  const D = page.locator('#dlg');
  await expect(D).toContainText('@lampvendor2 writes more like @lamp_ops than 4 of 4 other writers'); await expect(D).toContainText('closer than every one of them');
  await expect(D.locator('.st-t tr', { hasText: 'Lowercase “i”' })).toContainText('alike');
  await expect(D.locator('.st-t tr', { hasText: 'Apostrophes dropped' })).toContainText('alike');
  await expect(D).toContainText('Never link two names on writing alone');
  // a different writer is not ranked closest
  const other = await page.evaluate(() => { const R = stCompare('handle:@lamp_ops', 'handle:@yank_trader'); return [R.below, R.others]; });
  expect(other[0]).toBeLessThan(other[1]);
  // too little text
  await page.evaluate(() => stDlg('handle:@lamp_ops', 'handle:@newbie')); await expect(page.locator('#dlg')).toContainText('Too little text');
  // with too few other writers there is no ranking
  const thin = await page.evaluate(() => { const keep = ['handle:@lamp_ops', 'handle:@lampvendor2']; const all = stWriters; stWriters = () => all().filter(w => keep.includes(w.k)); const R = stCompare(...keep); stWriters = all; return R.others; });
  expect(thin).toBe(0);
  noErrors(errors);
});
