// The Blackbook (1.89): hidden until you type its name in search, then in the Kit menu for good. Every Sigma hunt is proven
// on an event it must match and one it must not, through the app's own Sigma engine; a hunt joins Detections in one click and
// runs as a saved hunt over the evidence; the stack choice hides languages you do not use; every part draws and is accessible.
const { test, expect } = require('@playwright/test');
const AxeBuilder = require('@axe-core/playwright').default;
const { open, noErrors } = require('./helpers');

test('hidden until found: not in the menu, typing "blackbook" in search opens it, then it stays in the menu', async ({ page }) => {
  const errors = await open(page, '#/home', { legacy: false });
  await expect(page.locator('#sidenav [data-v="blackbook"], #sidenav a[href="#/blackbook"]')).toHaveCount(0);
  await page.keyboard.press('Control+k'); await page.keyboard.type('blackbook');
  await expect(page.locator('#srList')).toContainText('Open the Blackbook');
  await page.keyboard.press('Enter');
  await expect(page.locator('.bb h1')).toHaveText('Blackbook');
  await expect(page.locator('#sidenav')).toContainText('Blackbook');
  await page.reload(); await expect.poll(() => page.evaluate(() => typeof DB !== 'undefined' && !!DB && !!document.querySelector('#sidenav .nv'))).toBe(true);
  await expect(page.locator('#sidenav')).toContainText('Blackbook');                        // remembered
  // once found, its plays are searchable
  await page.keyboard.press('Control+k'); await page.keyboard.type('kerberoasting');
  await expect(page.locator('#srList')).toContainText('Kerberoasting');
  noErrors(errors);
});

test('every Sigma hunt reads, matches its proof event and leaves the look-alike alone; every play is complete', async ({ page }) => {
  const errors = await open(page, '#/blackbook', { legacy: false });
  await expect(page.locator('.bb h1')).toBeVisible();
  const r = await page.evaluate(() => {
    const bad = [], rec = body => ({ id: 'x', caseId: 'c', type: 'evidence', title: '', body, host: '', source: '', tags: [], ents: [] });
    for (const p of BLACKBOOK.plays) {
      if (!p.lens || p.lens.length < 120 || !p.sig.length || !p.fix.length || !p.att.every(a => /^T\d{4}(\.\d{3})?$/.test(a))) bad.push(p.id + ': incomplete');
      if (!p.q.sigma) continue;
      const P = sigmaParse(p.q.sigma);
      if (!P.cond || !Object.keys(P.det).length) { bad.push(p.id + ': unreadable'); continue; }
      if (!/^id: [0-9a-f-]{36}$/m.test(p.q.sigma)) bad.push(p.id + ': no id');
      try { if (!sigmaEval(P, recFields(rec(p.ev[0])))) bad.push(p.id + ': misses its proof'); if (sigmaEval(P, recFields(rec(p.ev[1])))) bad.push(p.id + ': fires on the look-alike'); }
      catch (e) { bad.push(p.id + ': ' + e.message); }
    }
    const tech = new Set(ATTACK.tech.map(t => t[0])), tac = new Map(ATTACK.tech.map(t => [t[0].toLowerCase(), t[2] || []]));
    for (const p of BLACKBOOK.plays) if (p.q.sigma) {   // a rule's tactic tag is one of its technique's tactics in the shipped ATT&CK
      const tags = [...p.q.sigma.matchAll(/^  - attack\.([a-z0-9.-]+)$/gm)].map(m => m[1]), techs = tags.filter(t => /^t\d{4}/.test(t)), tactics = tags.filter(t => !/^t\d{4}/.test(t));
      if (!techs.length || !tactics.length) bad.push(p.id + ': untagged');
      for (const t of techs) if (!tac.has(t)) bad.push(p.id + ': unknown ' + t); else if (!tactics.some(x => tac.get(t).includes(x))) bad.push(p.id + ': ' + tactics + ' is not a tactic of ' + t);
    }
    return { bad, plays: BLACKBOOK.plays.length, sigma: BLACKBOOK.plays.filter(p => p.q.sigma).length, unknownTech: [...new Set(BLACKBOOK.plays.flatMap(p => p.att))].filter(t => !tech.has(t)),
      langs: Object.keys(BLACKBOOK.plays.reduce((a, p) => Object.assign(a, p.q), {})).sort(), apt: BLACKBOOK.apt.length, caught: BLACKBOOK.caught.length };
  });
  expect(r.bad).toEqual([]); expect(r.plays).toBeGreaterThanOrEqual(45); expect(r.sigma).toBeGreaterThanOrEqual(35);
  expect(r.unknownTech).toEqual([]);                                                             // every ATT&CK id exists in the shipped ATT&CK data
  expect(r.langs).toEqual(['cli', 'eql', 'kql', 'osq', 'sigma', 'spl']); expect(r.apt).toBeGreaterThanOrEqual(8); expect(r.caught).toBeGreaterThanOrEqual(10);
  noErrors(errors);
});

test('a hunt joins Detections once, runs over the evidence as a saved hunt and finds the event it was written for', async ({ page }) => {
  const errors = await open(page, '#/blackbook', { legacy: false });
  // evidence an analyst pasted from a host: the comsvcs LSASS dump
  await page.evaluate(() => { const c = DB.cases.find(x => !x.sample) || DB.cases[0]; c.sample = false;
    DB.records.push({ id: 'bb-ev', caseId: c.id, type: 'evidence', title: 'Sysmon 1 from WS-FIN-07', body: 'EventID=1 Image="C:\\Windows\\System32\\rundll32.exe" CommandLine="rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\out.dmp full"', host: 'WS-FIN-07', source: 'sysmon', tags: [], ents: [], ts: Date.now(), addedBy: 'You', addedAt: Date.now(), hash: '' }); mutate('t'); });
  await page.evaluate(() => BB_ACTS.bbJump(null, 'ca-lsass'));
  const play = page.locator('#bb-ca-lsass'); await expect(play).toHaveClass(/open/);
  await play.locator('[data-act=bbLang][data-v=sigma]').click();
  await expect(play.locator('.bb-code')).toContainText('comsvcs');
  await play.locator('[data-act=bbRule]').click();
  await expect(play.locator('[data-act=bbOpenRule]')).toBeVisible();
  await play.locator('[data-act=bbHunt]').click();
  await expect(page.locator('.toast').last()).toContainText('1 event in your evidence match');
  const s = await page.evaluate(() => { const rs = DB.rules.filter(r => r.bb === 'ca-lsass'), h = huntList().filter(x => x.ruleId === (rs[0] || {}).id); return { rules: rs.length, sev: rs[0].severity, tech: rs[0].technique, hunts: h.length, hits: huntRun(h[0]).matches.map(r => r.id) }; });
  expect(s).toEqual({ rules: 1, sev: 'critical', tech: 'T1003.001', hunts: 1, hits: ['bb-ev'] });
  await play.locator('[data-act=bbHunt]').click();                                                // again: no second rule or hunt
  expect(await page.evaluate(() => [DB.rules.filter(r => r.bb === 'ca-lsass').length, huntList().filter(h => /Blackbook/.test(h.name)).length])).toEqual([1, 1]);
  noErrors(errors);
});

test('your stack hides the languages you do not use, search finds inside the hunts, every part draws without accessibility problems', async ({ page }) => {
  await page.setViewportSize({ width: 1400, height: 1000 });
  const errors = await open(page, '#/blackbook', { legacy: false });
  await page.click('[data-act=bbStack][data-v=spl]'); await page.click('[data-act=bbStack][data-v=eql]');
  await page.evaluate(() => BB_ACTS.bbJump(null, 'c2-beacon'));
  const tabs = await page.locator('#bb-c2-beacon [data-act=bbLang]').allTextContents();
  expect(tabs).toEqual(['KQL', 'Commands']);                                                     // SPL hidden by choice
  expect(await page.evaluate(() => DB.prefs.bbLangs)).not.toContain('spl');
  await page.fill('#bbQ', 'GetCallerIdentity'); await page.waitForTimeout(400);
  await expect(page.locator('.bb-play')).toHaveCount(1); await expect(page.locator('.bb-play')).toContainText('Leaked keys');
  await page.fill('#bbQ', ''); await page.waitForTimeout(300);
  for (const t of ['hunt', 'apt', 'under', 'osint']) {
    await page.click(`[data-act=bbTab][data-v=${t}]`);
    if (t === 'hunt') await page.evaluate(() => BB_ACTS.bbJump(null, 'ia-aitm'));
    const a = await new AxeBuilder({ page }).include('#main').withTags(['wcag2a', 'wcag2aa']).analyze();
    expect(a.violations.filter(v => ['serious', 'critical'].includes(v.impact)).map(v => t + ': ' + v.id + ' ' + v.nodes[0].target), t).toEqual([]);
    if (t === 'under') await expect(page.locator('#main')).toContainText('IntelBroker');
  }
  noErrors(errors.filter(e => !/Connecting to 'file:.*violates the following Content Security Policy directive: "connect-src/.test(e)));   // the checker reading the stylesheets
});

test('at phone size the Blackbook fits the screen', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 800 });
  const errors = await open(page, '#/blackbook', { legacy: false });
  await page.evaluate(() => BB_ACTS.bbJump(null, 'ca-kerberoast'));
  const w = await page.evaluate(() => document.documentElement.scrollWidth - innerWidth);
  expect(w).toBeLessThanOrEqual(1);
  noErrors(errors);
});
