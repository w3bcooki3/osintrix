// Case templates: a new case starts from a template (or blank) with its playbooks' steps and its own questions as open
// questions, opens on the right tab, and any playbook or question can be left out. A case can be saved as a template
// (structure only: never evidence, entries or answers), and saved templates are cleaned when read.
const { test, expect } = require('@playwright/test');
const { open, noErrors } = require('./helpers');

test('every built-in template names playbooks that exist, and makes a case that opens on its tab with its questions', async ({ page }) => {
  const errors = await open(page, '#/cases');
  await page.evaluate(() => lazyNeed('pb')); await page.evaluate(() => ensurePlaybooks());
  const missing = await page.evaluate(() => CT_BUILTIN.flatMap(t => t.playbooks.filter(id => !ctPb(id)).map(id => t.id + ': ' + id)));
  expect(missing).toEqual([]);
  for (const id of await page.evaluate(() => CT_BUILTIN.map(t => t.id))) {
    await page.evaluate(() => clickAct('newCase'));
    await page.click(`[data-act=ctPick][data-v=${id}]`);
    await page.fill('#cName', 'From ' + id);
    await page.click('#dlg button[type=submit]');
    const r = await page.evaluate(id => { const c = DB.cases.find(x => x.name === 'From ' + id), T = ctGet(id), qs = DB.records.filter(x => x.caseId === c.id && x.type === 'lead');
      const want = new Set([...T.questions, ...T.playbooks.flatMap(p => (ctPb(p).steps || []).map(s => s.t || s[0]))].map(x => x.toLowerCase()));
      return { route: location.hash, tab: T.tab, color: c.color, icon: c.icon, n: qs.length, want: want.size, tpl: c.tpl || '', tagged: qs.every(q => q.tags.some(t => /^(template|playbook):/.test(t))) }; }, id);
    expect(r.route, id).toBe('#/case/' + encodeURIComponent(await page.evaluate(id => DB.cases.find(x => x.name === 'From ' + id).id, id)) + '/' + r.tab);
    expect(r.n, id + ': one question per distinct step').toBe(r.want);
    expect(r.tagged, id).toBe(true);
    if (id !== 'blank') expect(r.tpl).toBe(id);
  }
  noErrors(errors);
});

test('the Story template opens the Story tab; leaving out a playbook and a question leaves them out', async ({ page }) => {
  const errors = await open(page, '#/cases');
  await page.evaluate(() => lazyNeed('pb')); await page.evaluate(() => ensurePlaybooks());
  await page.evaluate(() => clickAct('newCase'));
  await expect(page.locator('.ct-card')).toHaveCount(await page.evaluate(() => CT_BUILTIN.length));
  await page.click('[data-act=ctPick][data-v=story]');
  await expect(page.locator('.ct-what')).toContainText('Story');
  await expect(page.locator('#cScope')).toHaveAttribute('placeholder', /What the story is about/);
  await page.uncheck('input[data-ctpb="pb-image-provenance"]');
  await page.uncheck('input[data-ctq="0"]');
  await page.fill('#cName', 'Port authority story');
  await page.click('#dlg button[type=submit]');
  await expect(page.locator('.st')).toBeVisible();                                       // the Story tab
  const r = await page.evaluate(() => { const c = DB.cases.find(x => x.name === 'Port authority story'), Q = DB.records.filter(x => x.caseId === c.id && x.type === 'lead');
    return { img: Q.some(q => q.tags.includes('playbook:pb-image-provenance')), opsec: Q.filter(q => q.tags.includes('playbook:pb-opsec-env')).length, own: Q.filter(q => q.tags.includes('template:story')).map(q => q.title) }; });
  expect(r.img).toBe(false); expect(r.opsec).toBeGreaterThan(0);
  expect(r.own).toEqual(['What would prove it wrong, and have you looked for that?', 'Who is it about, and when will they be asked for comment?', 'Which sources need protecting, and how do you reach them safely?']);
  // "Change" goes back to the list; the quick new case from Capture still goes straight to the form
  await page.evaluate(() => clickAct('newCase')); await page.click('[data-act=ctPick][data-v=fraud]'); await page.click('[data-act=ctChange]');
  await expect(page.locator('.ct-card').first()).toBeVisible();
  await page.evaluate(() => { closeDlg(); caseDlg(false); }); await expect(page.locator('#cName')).toBeVisible(); await expect(page.locator('.ct-what')).toHaveCount(0);
  noErrors(errors);
});

test('save a case as a template: its questions and playbooks, not its evidence or answers; reuse it; delete it', async ({ page }) => {
  const errors = await open(page, '#/home');
  await page.evaluate(() => lazyNeed('pb')); await page.evaluate(() => ensurePlaybooks());
  // shape a case: a playbook, two own questions (one answered), evidence and an entry
  await page.evaluate(() => {
    DB.cases.push({ id: 'tx', code: 'TX-1', name: 'Supplier check — Acme', status: 'active', owner: 'You', created: Date.now(), updated: Date.now(), scope: 'Supplier onboarding check for procurement.', color: '#0ea5a4', icon: 'building-2' }); DB.active = 'tx';
    runPlaybook('pb-company-dd', 'tx');
    const q = (title, answer) => DB.records.push({ id: uid('q'), caseId: 'tx', type: 'lead', title, body: '', tsRaw: '', ts: null, source: '', host: '', tags: [], ents: [], answer: answer || '', addedBy: 'You', addedAt: Date.now(), hash: '' });
    q('Is the VAT number valid?', 'Yes, checked in VIES'); q('Do they hold ISO 27001?');
    DB.records.push({ id: 'ev1', caseId: 'tx', type: 'evidence', title: 'Register extract', body: 'Acme Ltd, director Jane Roe', tsRaw: '', ts: Date.now(), source: 'register', host: '', tags: [], ents: [], answer: '', addedBy: 'You', addedAt: Date.now(), hash: '' });
    DB.entries.push({ id: 'en1', caseId: 'tx', type: 'person', fields: { name: 'Jane Roe' }, priority: 'medium', starred: false, tags: [], notes: '', src: '', created: Date.now(), pos: null });
    mutate('t'); go(caseHash('tx', 'questions')); });
  await page.click('[data-act=caseMenu]');
  await page.click('text=Save as a template…');
  await page.fill('#ctName', 'Supplier check'); await page.fill('#ctDesc', 'Our standard check on a new supplier');
  await page.click('#dlg button[type=submit]');
  await expect(page.locator('.toast')).toContainText('Template “Supplier check” saved');
  const T = await page.evaluate(() => DB.caseTemplates[0]);
  expect(T).toMatchObject({ name: 'Supplier check', icon: 'building-2', color: '#0ea5a4', tab: 'questions', playbooks: ['pb-company-dd'], questions: ['Is the VAT number valid?', 'Do they hold ISO 27001?'], scope: 'Supplier onboarding check for procurement.' });
  expect(JSON.stringify(T)).not.toMatch(/VIES|Jane Roe|Register extract/);
  // the same name twice is refused
  await page.click('[data-act=caseMenu]'); await page.click('text=Save as a template…'); await page.fill('#ctName', 'supplier check'); await page.click('#dlg button[type=submit]');
  await expect(page.locator('.ferr')).toContainText('already a template'); await page.evaluate(() => closeDlg());

  // reuse it after a reload
  await page.reload(); await expect.poll(() => page.evaluate(() => typeof DB !== 'undefined' && !!document.querySelector('#sidenav .nv'))).toBe(true);
  await page.evaluate(() => go('#/cases')); await page.evaluate(() => clickAct('newCase'));
  await expect(page.locator('.ct-own')).toContainText('Supplier check');
  await page.click(`[data-act=ctPick][data-v="${T.id}"]`);
  await page.fill('#cName', 'Supplier check — Globex'); await page.click('#dlg button[type=submit]');
  const r = await page.evaluate(() => { const c = DB.cases.find(x => x.name === 'Supplier check — Globex'); return { hash: location.hash.endsWith('/questions'), qs: DB.records.filter(x => x.caseId === c.id && x.type === 'lead').map(q => q.title), answered: DB.records.filter(x => x.caseId === c.id && x.answer).length, ev: DB.records.filter(x => x.caseId === c.id && x.type !== 'lead').length, en: DB.entries.filter(e => e.caseId === c.id).length }; });
  expect(r.hash).toBe(true); expect(r.qs).toEqual(expect.arrayContaining(['Is the VAT number valid?', 'Do they hold ISO 27001?']));
  expect(r.qs.length).toBe(2 + await page.evaluate(() => ctPb('pb-company-dd').steps.length));
  expect([r.answered, r.ev, r.en]).toEqual([0, 0, 0]);
  // delete it
  await page.evaluate(() => clickAct('newCase')); await page.click(`[data-act=ctDel][data-v="${T.id}"]`); await page.click('[data-act=confirmOk]');
  await expect(page.locator('.ct-own')).toHaveCount(0); expect(await page.evaluate(() => DB.caseTemplates.length)).toBe(0);
  noErrors(errors);
});

test('saved templates are cleaned when read', async ({ page }) => {
  const errors = await open(page, '#/home');
  const d = await page.evaluate(() => ctClean({ caseTemplates: [{ id: 'a', name: 'Good', icon: '<img>', color: 'red', tab: 'nowhere', playbooks: ['pb-x', 5], questions: ['q', '', 7] }, { id: 'b', name: '' }, { name: 'no id' }, 5] }));
  expect(d.caseTemplates).toEqual([{ id: 'a', name: 'Good', desc: '', icon: 'briefcase', color: '#5470f5', tab: 'overview', playbooks: ['pb-x'], questions: ['q'], scope: '', at: 0 }]);
  noErrors(errors);
});
