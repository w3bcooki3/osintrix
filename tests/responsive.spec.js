// Phone and tablet: every page and every case tab fits the screen — nothing pushes the page sideways — and none throws.
const { test, expect, devices } = require('@playwright/test');
const { open, noErrors } = require('./helpers');

for (const [name, dev] of [['phone', 'iPhone 13'], ['tablet', 'iPad Mini']]) {
  test(`${name}: every page and case tab fits the width`, async ({ browser }) => {
    const { defaultBrowserType, ...d } = devices[dev];
    const ctx = await browser.newContext(d), page = await ctx.newPage();
    const errors = await open(page, '#/home');
    const routes = await page.evaluate(() => [...new Set([...document.querySelectorAll('a[href^="#/"]')].map(a => a.getAttribute('href')).filter(h => /^#\/[a-z]+$/.test(h)))]
      .concat(CASE_TABS.map(t => caseHash('c-lantern', t[0]))).concat(['#/feeds', '#/settings', '#/cases']));
    expect(routes.length).toBeGreaterThan(20);
    const bad = [];
    for (const r of routes) {
      await page.evaluate(h => { location.hash = h; }, r); await page.waitForTimeout(300);
      const o = await page.evaluate(() => { const W = document.documentElement.clientWidth, out = [];
        if (document.documentElement.scrollWidth > W + 1) out.push('page is ' + document.documentElement.scrollWidth + 'px wide');
        for (const el of document.querySelectorAll('#main *')) { const rc = el.getBoundingClientRect(); if (!rc.width || rc.right <= W + 2 || getComputedStyle(el).position === 'fixed') continue;
          let p = el.parentElement, clip = false; while (p && p.id !== 'main') { if (/(auto|scroll|hidden|clip)/.test(getComputedStyle(p).overflowX)) { clip = true; break; } p = p.parentElement; }
          if (!clip) { out.push(el.tagName.toLowerCase() + '.' + String(el.className).split(' ')[0] + ' ends at ' + Math.round(rc.right)); break; } }
        return out; });
      if (o.length) bad.push(r + ': ' + o.join(', '));
    }
    expect(bad).toEqual([]);
    noErrors(errors); await ctx.close();
  });
}
