// Accessibility of the screens added in 1.78–1.81: Story (claims, protected sources, right of reply, archived pages)
// and its dialogs, duplicates and related entries, vehicle/ship/aircraft details and form, and Patterns. Light and
// dark, WCAG 2.1 A and AA, serious and critical findings.
const { test, expect } = require('@playwright/test');
const { open, noErrors } = require('./helpers');

const SEED = async page => page.evaluate(async () => {
  DB.cases.push(Object.assign({}, DB.cases[0], { id: 'ax', name: 'Accessibility', claims: undefined, replies: undefined, ach: undefined })); DB.active = 'ax';
  const rec = (id, title, source, body, att) => DB.records.push({ id, caseId: 'ax', type: 'evidence', title, body, tsRaw: '', tsZone: 'explicit', ts: Date.now(), source, host: '', tags: [], ents: E.extract(body), answer: '', addedBy: 'You', addedAt: Date.now(), hash: '', att: att || [] });
  rec('a1', 'Register extract', 'brreg.no', 'Contact @nightowl@owl.example. Board member Jon Berg. https://register.example/x. Ship IMO 9074729, MMSI: 636019825. VIN: WVWZZZ1JZ3W386752. Jet registration N628TS.');
  rec('a2', 'Court filing', 'court records', 'Jon Berg director. https://court.example/2024');
  rec('a3', 'Photo of the sign', 'email', 'Sign.', [{ id: 'i1', name: 'sign.jpg', type: 'image/jpeg', size: 10 }]);
  const mk = (id, type, fields) => DB.entries.push({ id, caseId: 'ax', type, fields, priority: 'medium', starred: false, tags: [], notes: '', src: '', created: Date.now(), pos: null });
  mk('p1', 'person', { name: 'Jon Berg' }); mk('d1', 'domain', { domain: 'paypal.com' }); mk('d2', 'domain', { domain: 'paypa1.com' }); mk('h1', 'username', { username: 'nightowl_ops' }); mk('h2', 'email', { email: 'nightowlops@proton.me' });
  mk('s1', 'vessel', { imo: '9074729' }); mk('s2', 'vessel', { imo: '9074729', mmsi: '636019825' });
  const c = stOf(theCase('ax'));
  c.claims.push({ id: 'c1', t: 'Jon Berg was a director in 2024', st: 'confirmed', for: ['r:a1', 'r:a3'], against: ['r:a2'], about: ['p1'], note: '', at: 1 },
    { id: 'c2', t: 'The office sign was photographed in March', st: 'unverified', for: [], against: [], about: [], note: '', at: 2 });
  c.replies.push({ id: 'q1', who: 'p1', name: '', via: 'Email', at: Date.now() - 864e5, due: Date.now() + 864e5, claims: ['c1'], st: 'waiting', resp: '', respAt: null },
    { id: 'q2', who: '', name: 'Harbourline press office', via: 'Phone', at: Date.now() - 3 * 864e5, due: Date.now() - 864e5, claims: [], st: 'answered', resp: 'No comment beyond our statement.', respAt: Date.now() - 864e5 });
  DB.archive = { 'https://register.example/x': { at: Date.now(), snap: 'https://web.archive.org/web/2026/https://register.example/x', req: 0, checked: Date.now() } };
  mutate('seed');
});

const SETUPS = {
  storyClaims: () => { UI.stView = 'claims'; location.hash = '#/case/ax/story'; },
  storySourcesNew: () => { UI.stView = 'sources'; location.hash = '#/case/ax/story'; },
  storySourcesLocked: async () => { await stSetPass('correct horse battery'); DB.sources = [{ id: 'z1', caseId: 'ax', alias: 'Harbour insider', rel: 'B', sealed: await stSeal({ name: 'Kari', contact: 'Signal' }), created: 1 }]; stLock(); UI.stView = 'sources'; location.hash = '#/case/ax/story'; },
  storySourcesOpen: async () => { await stUnlock('correct horse battery'); ST.shown.add('z1'); UI.stView = 'sources'; location.hash = '#/case/ax/story'; },
  storyReply: () => { UI.stView = 'reply'; location.hash = '#/case/ax/story'; },
  storyArchive: () => { UI.stView = 'archive'; location.hash = '#/case/ax/story'; },
  dlgEvidence: () => { location.hash = '#/case/ax/story'; setTimeout(() => stEvDlg('c2', 'for'), 60); },
  dlgAbout: () => { location.hash = '#/case/ax/story'; setTimeout(() => stAboutDlg('c2'), 60); },
  dlgVerify: () => { location.hash = '#/case/ax/story'; setTimeout(() => stVerifyDlg('a3', 'i1'), 60); },
  dlgClaim: () => { location.hash = '#/case/ax/story'; setTimeout(() => stClaimDlg('c1'), 60); },
  dlgReply: () => { location.hash = '#/case/ax/story'; setTimeout(() => stReplyDlg('q1'), 60); },
  dlgSource: () => { location.hash = '#/case/ax/story'; setTimeout(() => stSrcDlg('z1'), 60); },
  dlgBurn: () => { location.hash = '#/case/ax/story'; setTimeout(() => STORY_ACTS.stBurnAsk('z1'), 60); },
  recordPanel: () => { location.hash = '#/case/ax/timeline'; setTimeout(() => select('rec', 'a1'), 60); },
  dupSure: () => { location.hash = '#/case/ax/vault'; setTimeout(() => { dupDlg(); UI.dup.tab = 'sure'; dupPaint(); }, 60); },
  dupRelated: () => { location.hash = '#/case/ax/vault'; setTimeout(() => { dupDlg(); UI.dup.tab = 'rel'; dupPaint(); }, 60); },
  inspVin: () => { location.hash = '#/case/ax/entities'; setTimeout(() => select('ent', 'vin:WVWZZZ1JZ3W386752'), 60); },
  inspMmsi: () => { location.hash = '#/case/ax/entities'; setTimeout(() => select('ent', 'mmsi:636019825'), 60); },
  inspTail: () => { location.hash = '#/case/ax/entities'; setTimeout(() => select('ent', 'tail:N628TS'), 60); },
  formAircraft: () => { location.hash = '#/case/ax/vault'; setTimeout(() => entryDlg(null, { type: 'aircraft' }), 60); },
  formVessel: () => { location.hash = '#/case/ax/vault'; setTimeout(() => entryDlg(null, { type: 'vessel' }), 60); },
  inspSsh: () => { const t = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBMSWT8rq9/ytVBKhLu1/r8gXPjBRMTaM8E5rnmTLeTp ops@vps'; DB.records.push({ id: 'k1', caseId: 'ax', type: 'evidence', title: 'key', body: t, tsRaw: '', tsZone: 'explicit', ts: Date.now(), source: 's', host: '', tags: [], ents: E.extract(t), answer: '', addedBy: 'You', addedAt: Date.now(), hash: '' }); mutate('k'); location.hash = '#/case/ax/entities'; setTimeout(() => { const e = DB.records.find(r => r.id === 'k1').ents.find(x => x.k === 'sshkey'); select('ent', 'sshkey:' + e.v); }, 60); },
  inspFedi: () => { location.hash = '#/case/ax/entities'; setTimeout(() => select('ent', 'fedi:@nightowl@owl.example'), 60); },
  formSsh: () => { location.hash = '#/case/ax/vault'; setTimeout(() => entryDlg(null, { type: 'sshkey' }), 60); },
  formAccount: () => { location.hash = '#/case/ax/vault'; setTimeout(() => entryDlg(null, { type: 'daccount' }), 60); },
  dlgTemplatePick: () => { location.hash = '#/cases'; setTimeout(() => caseDlg(), 60); },
  dlgTemplateForm: () => { location.hash = '#/cases'; setTimeout(() => caseDlg(undefined, 'story'), 60); },
  dlgTemplateSave: () => { location.hash = '#/case/ax/overview'; setTimeout(() => ctSaveDlg('ax'), 60); },
  patternsBuild: () => { UI.patTab = 'build'; location.hash = '#/regex'; },
  patternsLogs: () => { UI.patTab = 'logs'; location.hash = '#/regex'; },
};

for (const theme of ['light', 'dark']) test(`no serious accessibility problems on the 1.78–1.81 screens and dialogs, ${theme}`, async ({ page }) => {
  test.setTimeout(300_000);
  const AxeBuilder = require('@axe-core/playwright').default;
  const errors = await open(page, '#/home'); await SEED(page);
  await page.evaluate(t => { DB.prefs.theme = t; applyPrefs(); renderAll(); }, theme);
  const found = [];
  for (const name of Object.keys(SETUPS)) {
    await page.evaluate(async src => { closeDlg(); await (0, eval)('(' + src + ')')(); setTimeout(renderMain, 20); }, SETUPS[name].toString());
    await page.waitForTimeout(450);
    /* the screen really is there: a dialog for dialogs, the panel for details, the Story tab for its views */
    const there = await page.evaluate(n => { const dlg = !!document.querySelector('#dlg') && $('dlg').innerHTML.trim().length > 50 && !$('scrim').hidden;
      return /^(dlg|dup|form)/.test(n) ? dlg : /^insp|^record/.test(n) ? $('insp').innerText.length > 80 : /^story/.test(n) ? !!document.querySelector('#main .st') : /^patterns/.test(n) ? !!document.querySelector('.pat-tabs') : true; }, name);
    expect(there, name + ' is on screen').toBe(true);
    const res = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).analyze();
    for (const v of res.violations) if (['serious', 'critical'].includes(v.impact)) for (const n of v.nodes.slice(0, 3)) found.push(`${theme} ${name} ${v.id}: ${n.target.join(' ')} ${n.failureSummary ? n.failureSummary.split('\n')[1] : ''}`);
  }
  console.log(found.join('\n'));
  expect(found, found.join('\n')).toEqual([]);
  noErrors(errors.filter(e => !/Connecting to 'file:.*violates the following Content Security Policy directive: "connect-src/.test(e)));   // the checker reading the stylesheets
});
