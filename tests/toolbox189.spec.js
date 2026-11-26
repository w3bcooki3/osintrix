// The curated toolbox (1.89): every built-in tool is maintained and says what it is for, its licence comes first, and the
// one-click lookups build real addresses. An older workspace loses the retired entries it never used, keeps the ones it did,
// follows tools to their new address with stars and notes intact, and never loses a tool of its own.
const { test, expect } = require('@playwright/test');
const { open, noErrors } = require('./helpers');

test('a new workspace: no retired or duplicate tools, licence first, and every lookup opens a proper address', async ({ page }) => {
  const errors = await open(page, '#/toolbox', { legacy: false });
  const r = await page.evaluate(() => {
    const urls = DB.tools.map(t => t.url), lic = new Set(['open-source', 'free', 'freemium', 'commercial']);
    const sample = { ipv4: '8.8.8.8', domain: 'example.com', url: 'https://example.com/a', email: 'a@example.com', handle: 'someone', hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', btc: 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh', person: 'Example Ltd', any: 'lantern' };
    const bad = DB.tools.filter(t => t.tpl).filter(t => !(t.kinds || []).length || (t.kinds || []).some(k => { const u = toolUrl(t, sample[k]); return !u || !/^https:\/\//.test(u); })).map(t => t.name);
    return { n: DB.tools.length, dup: urls.length - new Set(urls).size, retired: urls.filter(u => TOOLS_RETIRED.includes(u) || TOOLS_MOVED[u]), noLic: DB.tools.filter(t => !lic.has(t.tags[0])).map(t => t.name),
      short: DB.tools.filter(t => t.desc.length < 50).map(t => t.name), lookups: DB.tools.filter(t => t.tpl).length, bad, insecure: urls.filter(u => !u.startsWith('https://')),
      cats: DB.tools.filter(t => !TOOL_CATS[t.cat] || !TOOL_CATS[t.cat].children[t.sub]).map(t => t.name) };
  });
  expect(r.n).toBeGreaterThan(150); expect(r.dup).toBe(0); expect(r.retired).toEqual([]); expect(r.noLic).toEqual([]); expect(r.short).toEqual([]);
  expect(r.lookups).toBeGreaterThan(25); expect(r.bad).toEqual([]); expect(r.insecure).toEqual([]); expect(r.cats).toEqual([]);
  await expect(page.locator('#main')).toContainText('CyberChef');
  noErrors(errors);
});

test('an older workspace: unused retired tools go, used ones stay, moved tools keep your stars, your own tools are untouched, once', async ({ page }) => {
  const errors = await open(page, '#/home', { legacy: false });
  const r = await page.evaluate(() => {
    const t = (id, name, url, x) => ({ id, name, url, cat: 'osint', sub: 'people-search', desc: 'old text', tags: ['old'], pinned: false, starred: false, added: 1, uses: 0, seed: true, ...x });
    DB.tools = [t('a', 'Spokeo', 'http://www.spokeo.com'), t('b', 'Whitepages', 'http://www.whitepages.com', { starred: true }), t('c', 'HashKiller', 'https://hashkiller.co.uk/', { uses: 3, last: 5 }),
      t('d', 'TinEye', 'http://www.tineye.com', { starred: true, notes: 'my note' }), t('e', 'Shodan', 'https://www.shodan.io', { desc: 'my own words', edited: true }),
      t('f', 'Mine', 'https://intranet.example/tool', { seed: false }), t('g', 'VirusTotal', 'https://www.virustotal.com')];
    DB.deletedSeed = ['http://monitter.com/', 'https://www.brimdata.io/']; delete DB.toolsV;
    ensureTools(); const first = JSON.stringify(DB.tools.map(x => x.url).sort()); ensureTools();
    const by = u => DB.tools.find(x => x.url === u);
    return { once: first === JSON.stringify(DB.tools.map(x => x.url).sort()), spokeo: !!by('http://www.spokeo.com'), whitepages: !!by('http://www.whitepages.com'), hashkiller: !!by('https://hashkiller.co.uk/'),
      tineye: by('https://tineye.com') && { id: by('https://tineye.com').id, starred: by('https://tineye.com').starred, notes: by('https://tineye.com').notes, old: !!by('http://www.tineye.com') },
      shodan: by('https://www.shodan.io').desc, vt: { desc: by('https://www.virustotal.com').desc.slice(0, 20), tpl: !!by('https://www.virustotal.com').tpl, lic: by('https://www.virustotal.com').tags[0] },
      mine: by('https://intranet.example/tool').desc, brim: DB.deletedSeed.includes('https://github.com/brimdata/zui') && !by('https://github.com/brimdata/zui'), chef: !!by('https://gchq.github.io/CyberChef/') };
  });
  expect(r.once).toBe(true);
  expect(r.spokeo).toBe(false); expect(r.whitepages).toBe(true); expect(r.hashkiller).toBe(true);   // retired: gone unless starred or used
  expect(r.tineye).toEqual({ id: 'd', starred: true, notes: 'my note', old: false });                    // moved to its new address, stars and notes kept
  expect(r.shodan).toBe('my own words');                                                                 // your edit wins
  expect(r.vt).toEqual({ desc: 'Hash, file, URL and ', tpl: true, lic: 'freemium' });                     // built-in text refreshed, lookup added
  expect(r.mine).toBe('old text'); expect(r.brim).toBe(true); expect(r.chef).toBe(true);                // a deleted tool stays deleted at its new address
  noErrors(errors);
});
