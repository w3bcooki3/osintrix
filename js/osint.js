/* ==========================================================================
   OSINT research
     • Look-alike domains: every way a domain can be imitated (typos, keyboard slips,
       homoglyphs, bit flips, other endings, added words), then which ones exist —
       resolving, receiving mail, newly registered — ranked by how dangerous they look
     • Identity pivots: a username across platforms, an email address taken apart
       (provider, disposable, role account, canonical form, Gravatar, mail servers),
       a phone number read into country and international format
     • Pivot plan: for any indicator, the next steps worth taking given what is known
   Checks go only through the lookup sources you switched on (Google DNS, RDAP).
   ========================================================================== */
const TW_KEYS = ['1234567890-', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm'];
const TW_ADJ = (() => { const m = {}; TW_KEYS.forEach((row, r) => [...row].forEach((ch, i) => { const s = new Set(); for(const [dr, di] of [[0, -1], [0, 1], [-1, 0], [-1, 1], [1, 0], [1, -1]]){ const rr = TW_KEYS[r + dr]; if(rr && rr[i + di]) s.add(rr[i + di]); } m[ch] = [...s].filter(c => /[a-z0-9]/.test(c)); })); return m; })();
const TW_GLYPH = {a:['4', 'а', 'à', 'á'], b:['d', 'lb', '6'], c:['e', 'с'], d:['b', 'cl'], e:['3', 'е', 'é'], g:['q', '9'], h:['lh'], i:['1', 'l', 'í', 'і'], k:['lk'], l:['1', 'i', 'ӏ'], m:['rn', 'nn'], n:['m', 'r'], o:['0', 'о', 'ó'], p:['р'], q:['g'], s:['5', 'ѕ'], t:['7'], u:['v', 'ü'], v:['u'], w:['vv', 'ш'], x:['х'], y:['у'], z:['2']};
const TW_TLDS = ['com', 'net', 'org', 'co', 'io', 'info', 'biz', 'online', 'site', 'top', 'xyz', 'app', 'shop', 'store', 'live', 'support', 'cloud', 'me', 'us', 'uk', 'co.uk', 'de', 'ru', 'cn', 'cc', 'tk', 'ml', 'ga', 'click', 'link', 'icu', 'vip', 'work', 'services', 'email'];
const TW_WORDS = ['login', 'secure', 'account', 'support', 'verify', 'mail', 'pay', 'billing', 'update', 'online', 'portal', 'help', 'auth', 'signin', 'my', 'app', 'service', 'invoice', 'web', 'id'];
const TW_NAME = {addition:'Letter added', bitsquat:'Bit flip', homoglyph:'Look-alike character', hyphen:'Hyphen added', insertion:'Key slip (extra)', omission:'Letter missing', repetition:'Letter doubled', replacement:'Key slip (wrong)', subdomain:'Dot inserted', transposition:'Letters swapped', vowel:'Vowel swapped', tld:'Other ending', word:'Word added', idn:'Unicode look-alike'};

function twSplit(d){ d = String(d || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/[/:?#].*$/, '').replace(/^www\./, '').replace(/\.$/, '');
  const p = d.split('.'); if(p.length < 2) return null; const two = p.length > 2 && /^(co|com|net|org|gov|ac|edu)$/.test(p[p.length - 2]) && p[p.length - 1].length === 2;
  const tld = p.slice(two ? -2 : -1).join('.'), rest = p.slice(0, two ? -2 : -1); return {sub:rest.slice(0, -1).join('.'), name:rest[rest.length - 1], tld, full:d}; }
const twPuny = d => { try{ return new URL('http://' + d).hostname; }catch(e){ return null; } };
function twGen(domain){
  const S = twSplit(String(domain || '').slice(0, 253)); if(!S || !S.name) return [];
  const {name, tld} = S, out = new Map(), add = (n, t, kind) => { if(!n || n === name && t === tld) return; if(!/^[a-z0-9¡-￿](?:[a-z0-9¡-￿-]{0,61}[a-z0-9¡-￿])?(\.[a-z0-9-]+)*$/.test(n) || n.length > 63) return;
    const uni = n + '.' + t, puny = /[^\x00-\x7f]/.test(uni) ? twPuny(uni) : uni; if(!puny || out.has(puny)) return; out.set(puny, {d:puny, show:uni, kind:/[^\x00-\x7f]/.test(uni) ? 'idn' : kind}); };
  for(let i = 0; i < name.length; i++){
    add(name.slice(0, i) + name.slice(i + 1), tld, 'omission');
    add(name.slice(0, i) + name[i] + name[i] + name.slice(i + 1), tld, 'repetition');
    if(i < name.length - 1) add(name.slice(0, i) + name[i + 1] + name[i] + name.slice(i + 2), tld, 'transposition');
    for(const c of TW_ADJ[name[i]] || []){ add(name.slice(0, i) + c + name.slice(i + 1), tld, 'replacement'); add(name.slice(0, i) + c + name.slice(i), tld, 'insertion'); add(name.slice(0, i + 1) + c + name.slice(i + 1), tld, 'insertion'); }
    for(const g of TW_GLYPH[name[i]] || []) add(name.slice(0, i) + g + name.slice(i + 1), tld, 'homoglyph');
    if('aeiou'.includes(name[i])) for(const v of 'aeiou') if(v !== name[i]) add(name.slice(0, i) + v + name.slice(i + 1), tld, 'vowel');
    for(let b = 0; b < 8; b++){ const c = String.fromCharCode(name.charCodeAt(i) ^ (1 << b)); if(/[a-z0-9]/.test(c)) add(name.slice(0, i) + c + name.slice(i + 1), tld, 'bitsquat'); }
    if(i > 0){ add(name.slice(0, i) + '-' + name.slice(i), tld, 'hyphen'); add(name.slice(0, i) + '.' + name.slice(i), tld, 'subdomain'); }
  }
  for(const [a, b] of [['rn', 'm'], ['m', 'rn'], ['vv', 'w'], ['w', 'vv'], ['cl', 'd'], ['nn', 'm']]) if(name.includes(a)) add(name.replace(a, b), tld, 'homoglyph');
  for(const c of 'abcdefghijklmnopqrstuvwxyz0123456789') add(name + c, tld, 'addition');
  for(const t of TW_TLDS) add(name, t, 'tld');
  for(const w of TW_WORDS){ add(name + '-' + w, tld, 'word'); add(w + '-' + name, tld, 'word'); add(name + w, tld, 'word'); }
  return [...out.values()];
}

/* check which exist: A, MX and NS through Google DNS (only these names are sent), then RDAP age for the ones that do */
const TW = {run:null};
async function twCheck(list, onEach, signal){
  let i = 0; const doh = async (d, t) => { const r = await lkFetch('https://dns.google/resolve?name=' + encodeURIComponent(d) + '&type=' + t, {timeout:12000}); return JSON.parse(r.text); };
  const worker = async () => { while(i < list.length && !signal.stop){ const x = list[i++];
    try{ const [a, mx, ns] = await Promise.all([doh(x.d, 'A'), doh(x.d, 'MX'), doh(x.d, 'NS')]);
      const pick = (j, t) => (Array.isArray(j.Answer) ? j.Answer : []).filter(y => y.type === t).map(y => cap(String(y.data).replace(/\.$/, '').replace(/^\d+\s+/, ''), 253).toLowerCase());
      x.ips = pick(a, 1); x.mx = pick(mx, 15); x.ns = pick(ns, 2); x.exists = a.Status !== 3 && (x.ips.length || x.mx.length || x.ns.length || a.Status === 0 && (ns.Status === 0)); x.err = '';
      x.parked = x.ns.some(n => /parkingcrew|sedoparking|bodis|above\.com|parklogic|dan\.com|afternic|namebrightdns|uniregistrymarket|hugedomains/.test(n));
    }catch(e){ x.err = cap(e.message, 80); }
    x.done = true; onEach(x); } };
  await Promise.all(Array.from({length:6}, worker));
  /* age of the registered ones, if RDAP is on */
  const rd = lkProv('rdap'); if(rd && lkOn(rd)) for(const x of list.filter(y => y.exists && !y.parked).slice(0, 40)){ if(signal.stop) break; const r = await lkRun(rd, 'domain', x.d); if(r.ok && r.attrs){ x.created = r.attrs.created || 0; x.registrar = r.attrs.registrar || ''; } onEach(x); }
}
function twRisk(x, orig){
  let s = 0; const why = [];
  if(!x.exists) return {s:0, why};
  s += 30; why.push('registered');
  if(x.mx.length){ s += 25; why.push('can receive mail'); }
  if(x.ips.length){ s += 10; why.push('resolves'); }
  if(x.created && Date.now() - x.created < 90 * 864e5){ s += 30; why.push('registered ' + Math.floor((Date.now() - x.created) / 864e5) + ' days ago'); }
  if(x.parked){ s -= 20; why.push('parked'); }
  if(/homoglyph|idn|bitsquat/.test(x.kind)){ s += 10; why.push('hard to spot'); }
  if(orig && orig.ips && x.ips.some(ip => orig.ips.includes(ip))){ s -= 25; why.push('same servers as the original — likely owned by the same company'); }
  return {s:Math.max(0, Math.min(100, s)), why};
}
function labTwist(){
  const T = UI.tw || {}, L = T.list || [], done = L.filter(x => x.done).length, reg = L.filter(x => x.exists).map(x => Object.assign(x, {r:twRisk(x, T.orig)})).sort((a, b) => b.r.s - a.r.s);
  const dnsOn = typeof lkProv === 'function' && lkOn(lkProv('dns')), rdOn = typeof lkProv === 'function' && lkOn(lkProv('rdap'));
  const kinds = countBy(L, x => x.kind);
  return `<div class="labgrid one wide"><section class="card"><header><h3>${ico('copy','sm')} Look-alike domains</h3><span class="t3">typosquats, homoglyphs and other imitations of a domain</span></header><div class="body">
    <form class="lk-q" data-form="twGen"><div class="search-in">${ico('globe')}<label class="sr" for="twD">Domain to imitate</label><input id="twD" class="inp mono" value="${esc(T.d || '')}" placeholder="your-company.com" autocomplete="off" spellcheck="false"></div>
      <button class="btn primary" type="submit">${ico('sparkles','sm')}Generate</button>
      ${L.length ? `<button class="btn" type="button" data-act="twCheck" ${dnsOn ? '' : 'disabled'}>${ico('radar','sm')}${T.running ? 'Checking ' + done + ' of ' + L.length + '…' : done ? 'Check again' : 'Check which exist'}</button>${T.running ? `<button class="btn ghost" type="button" data-act="twStop">Stop</button>` : ''}` : ''}</form>
    ${L.length && !dnsOn ? `<div class="ti-relay">${ico('wifi-off','sm')}<span>Checking sends each candidate name to Google DNS (<span class="mono">dns.google</span>). Switch on the DNS source to allow it${rdOn ? '' : ' — and RDAP to see how new each one is'}.</span><button class="btn sm" data-act="twDnsOn">Allow Google DNS${rdOn ? '' : ' and RDAP'}</button></div>` : ''}
    ${L.length ? `<p class="t3" style="margin:4px 0 12px">${L.length} candidates — ${kinds.slice(0, 8).map(([k, n]) => esc(TW_NAME[k] || k) + ' ' + n).join(' · ')}</p>` : '<p class="t3">Enter a domain you want to protect — or one from a case — to see how it could be imitated.</p>'}
    ${T.running || done ? `<div class="lk-prog" role="progressbar" aria-label="Checking look-alikes" aria-valuenow="${Math.round(done / Math.max(1, L.length) * 100)}" aria-valuemin="0" aria-valuemax="100"><i style="width:${Math.round(done / Math.max(1, L.length) * 100)}%"></i></div>` : ''}
    ${reg.length ? `<div class="wrap" style="margin:12px 0 8px"><b>${reg.length} exist</b><span class="t3">${reg.filter(x => x.mx.length).length} can receive mail · ${reg.filter(x => x.created && Date.now() - x.created < 90 * 864e5).length} registered in the last 90 days</span><span class="sp"></span>
        <button class="btn sm" data-act="twAdd">${ico('plus','sm')}Add the risky ones to ${esc(caseNm(theCase()))}</button><button class="btn sm ghost" data-act="twCsv">${ico('download','sm')}CSV</button></div>
      <table class="tbl tw-tbl"><thead><tr><th>Domain</th><th>How</th><th class="n">Risk</th><th class="hide-m">Why</th><th class="hide-m">Address · mail</th><th></th></tr></thead><tbody>
        ${reg.slice(0, 150).map(x => `<tr><td><span class="mono">${esc(x.show)}</span>${x.show !== x.d ? `<br><small class="mono t3">${esc(x.d)}</small>` : ''}</td><td class="t2">${esc(TW_NAME[x.kind] || x.kind)}</td><td class="n"><b style="color:${x.r.s >= 70 ? 'var(--red)' : x.r.s >= 45 ? 'var(--amber)' : 'var(--text-2)'}">${x.r.s}</b></td>
          <td class="hide-m t2">${esc(x.r.why.join(', '))}</td><td class="hide-m mono t3">${esc((x.ips[0] || '—') + (x.mx.length ? ' · MX ' + x.mx[0] : ''))}</td><td><button class="iconbtn" data-act="twLook" data-v="${esc(x.d)}" aria-label="Investigate ${esc(x.d)}" title="Investigate">${ico('radar','sm')}</button></td></tr>`).join('')}</tbody></table>`
      : done && !T.running ? `<p class="t2">${ico('check','sm')} None of the ${done} candidates exist${L.some(x => x.err) ? ' (' + L.filter(x => x.err).length + ' could not be checked)' : ''}.</p>` : ''}
    </div></section></div>`;
}
async function twRun(){
  const T = UI.tw; if(!T || !T.list) return; T.list.forEach(x => { x.done = false; }); T.running = true; T.sig = {stop:false}; renderMain();
  const S = twSplit(T.d); try{ const j = JSON.parse((await lkFetch('https://dns.google/resolve?name=' + encodeURIComponent(S.full) + '&type=A', {timeout:10000})).text); T.orig = {ips:(j.Answer || []).filter(y => y.type === 1).map(y => y.data)}; }catch(e){ T.orig = {ips:[]}; }
  let t = 0; await twCheck(T.list, () => { if(Date.now() - t > 400){ t = Date.now(); if(UI.labTab === 'twist') renderMain(); } }, T.sig);
  T.running = false; if(UI.labTab === 'twist') renderMain();
  const n = T.list.filter(x => x.exists).length; toast(n ? n + ' look-alike' + (n > 1 ? 's' : '') + ' of ' + T.d + ' exist' : 'No look-alikes of ' + T.d + ' exist');
}

/* ---------- identity pivots ---------- */
const ID_SITES = [['Social', [['X', 'https://x.com/%s'], ['Instagram', 'https://www.instagram.com/%s/'], ['TikTok', 'https://www.tiktok.com/@%s'], ['Facebook', 'https://www.facebook.com/%s'], ['Threads', 'https://www.threads.net/@%s'], ['Bluesky', 'https://bsky.app/profile/%s.bsky.social'], ['Mastodon (social)', 'https://mastodon.social/@%s'], ['Reddit', 'https://www.reddit.com/user/%s'], ['Pinterest', 'https://www.pinterest.com/%s/'], ['Tumblr', 'https://%s.tumblr.com'], ['Snapchat', 'https://www.snapchat.com/add/%s'], ['VK', 'https://vk.com/%s']]],
  ['Messaging', [['Telegram', 'https://t.me/%s'], ['Keybase', 'https://keybase.io/%s'], ['Linktree', 'https://linktr.ee/%s']]],
  ['Work & code', [['GitHub', 'https://github.com/%s'], ['GitLab', 'https://gitlab.com/%s'], ['LinkedIn (search)', 'https://www.linkedin.com/search/results/all/?keywords=%s'], ['Medium', 'https://medium.com/@%s'], ['Dev.to', 'https://dev.to/%s'], ['Stack Overflow (search)', 'https://stackoverflow.com/users?tab=Reputation&filter=all&search=%s'], ['Docker Hub', 'https://hub.docker.com/u/%s'], ['npm', 'https://www.npmjs.com/~%s'], ['PyPI', 'https://pypi.org/user/%s/'], ['HackerOne', 'https://hackerone.com/%s'], ['Behance', 'https://www.behance.net/%s'], ['Dribbble', 'https://dribbble.com/%s']]],
  ['Video & music', [['YouTube', 'https://www.youtube.com/@%s'], ['Twitch', 'https://www.twitch.tv/%s'], ['SoundCloud', 'https://soundcloud.com/%s'], ['Spotify (search)', 'https://open.spotify.com/search/%s'], ['Vimeo', 'https://vimeo.com/%s']]],
  ['Gaming', [['Steam', 'https://steamcommunity.com/id/%s'], ['Xbox', 'https://www.xboxgamertag.com/search/%s'], ['Roblox (search)', 'https://www.roblox.com/search/users?keyword=%s'], ['Chess.com', 'https://www.chess.com/member/%s']]],
  ['Money & market', [['Cash App', 'https://cash.app/$%s'], ['Venmo', 'https://venmo.com/u/%s'], ['PayPal.me', 'https://paypal.me/%s'], ['Patreon', 'https://www.patreon.com/%s'], ['Ko-fi', 'https://ko-fi.com/%s'], ['Etsy', 'https://www.etsy.com/shop/%s'], ['eBay', 'https://www.ebay.com/usr/%s']]],
  ['Search everywhere', [['WhatsMyName', 'https://whatsmyname.app/?q=%s'], ['Google (exact)', 'https://www.google.com/search?q=%22%s%22'], ['Bing (exact)', 'https://www.bing.com/search?q=%22%s%22'], ['DuckDuckGo', 'https://duckduckgo.com/?q=%22%s%22']]]];
const ID_DISPOSABLE = /^(mailinator|guerrillamail|guerrillamailblock|sharklasers|10minutemail|temp-mail|tempmail|tempmailo|throwawaymail|yopmail|getnada|nada|dispostable|trashmail|maildrop|mintemail|mohmal|emailondeck|fakeinbox|spamgourmet|mailnesia|tempr|tempail|burnermail|33mail|anonaddy|simplelogin|duck|mail\.tm|moakt|inboxkitten|tmail|tmpmail|1secmail|emailfake|mytemp|byom|grr|cock|spam4)\./i;
const ID_PROVIDER = [[/(^|\.)google\.com$|googlemail|aspmx\.l\.google/, 'Google Workspace / Gmail'], [/outlook\.com$|protection\.outlook|hotmail/, 'Microsoft 365 / Outlook'], [/protonmail|proton\.me/, 'Proton Mail (encrypted)'], [/zoho/, 'Zoho Mail'], [/yandex/, 'Yandex Mail'], [/mail\.ru/, 'Mail.ru'], [/icloud|me\.com/, 'Apple iCloud'], [/yahoodns|yahoo/, 'Yahoo Mail'], [/tutanota|tuta\.io/, 'Tuta (encrypted)'], [/mimecast/, 'Mimecast (filtering)'], [/pphosted|proofpoint/, 'Proofpoint (filtering)'], [/messagelabs|symantec/, 'Broadcom (filtering)'], [/mailgun|sendgrid|amazonses|mandrillapp|sparkpost/, 'Bulk-sending service']];
const ID_ROLE = /^(admin|administrator|info|contact|support|help|sales|billing|accounts?|noreply|no-reply|postmaster|abuse|security|webmaster|hostmaster|office|hr|jobs|careers|marketing|press|team|hello|mail|service)$/;
const ID_CC = [['1', 'United States / Canada'], ['7', 'Russia / Kazakhstan'], ['20', 'Egypt'], ['27', 'South Africa'], ['30', 'Greece'], ['31', 'Netherlands'], ['32', 'Belgium'], ['33', 'France'], ['34', 'Spain'], ['36', 'Hungary'], ['39', 'Italy'], ['40', 'Romania'], ['41', 'Switzerland'], ['43', 'Austria'], ['44', 'United Kingdom'], ['45', 'Denmark'], ['46', 'Sweden'], ['47', 'Norway'], ['48', 'Poland'], ['49', 'Germany'], ['51', 'Peru'], ['52', 'Mexico'], ['54', 'Argentina'], ['55', 'Brazil'], ['56', 'Chile'], ['57', 'Colombia'], ['58', 'Venezuela'], ['60', 'Malaysia'], ['61', 'Australia'], ['62', 'Indonesia'], ['63', 'Philippines'], ['64', 'New Zealand'], ['65', 'Singapore'], ['66', 'Thailand'], ['81', 'Japan'], ['82', 'South Korea'], ['84', 'Vietnam'], ['86', 'China'], ['90', 'Turkey'], ['91', 'India'], ['92', 'Pakistan'], ['93', 'Afghanistan'], ['94', 'Sri Lanka'], ['95', 'Myanmar'], ['98', 'Iran'], ['212', 'Morocco'], ['213', 'Algeria'], ['216', 'Tunisia'], ['218', 'Libya'], ['234', 'Nigeria'], ['254', 'Kenya'], ['255', 'Tanzania'], ['256', 'Uganda'], ['351', 'Portugal'], ['352', 'Luxembourg'], ['353', 'Ireland'], ['354', 'Iceland'], ['358', 'Finland'], ['359', 'Bulgaria'], ['370', 'Lithuania'], ['371', 'Latvia'], ['372', 'Estonia'], ['373', 'Moldova'], ['375', 'Belarus'], ['380', 'Ukraine'], ['381', 'Serbia'], ['385', 'Croatia'], ['420', 'Czechia'], ['421', 'Slovakia'], ['852', 'Hong Kong'], ['853', 'Macau'], ['855', 'Cambodia'], ['880', 'Bangladesh'], ['886', 'Taiwan'], ['960', 'Maldives'], ['961', 'Lebanon'], ['962', 'Jordan'], ['963', 'Syria'], ['964', 'Iraq'], ['965', 'Kuwait'], ['966', 'Saudi Arabia'], ['967', 'Yemen'], ['968', 'Oman'], ['970', 'Palestine'], ['971', 'United Arab Emirates'], ['972', 'Israel'], ['973', 'Bahrain'], ['974', 'Qatar'], ['977', 'Nepal'], ['992', 'Tajikistan'], ['993', 'Turkmenistan'], ['994', 'Azerbaijan'], ['995', 'Georgia'], ['996', 'Kyrgyzstan'], ['998', 'Uzbekistan']];
function idEmail(e){
  const m = /^([^@\s]{1,64})@([a-z0-9.-]+\.[a-z]{2,})$/i.exec(String(e || '').trim()); if(!m) return null;
  const local = m[1].toLowerCase(), dom = m[2].toLowerCase(), gm = /^(gmail|googlemail)\.com$/.test(dom);
  const canon = (gm ? local.replace(/\+.*$/, '').replace(/\./g, '') : local.replace(/\+.*$/, '')) + '@' + (gm ? 'gmail.com' : dom);
  const parts = local.replace(/\+.*$/, '').split(/[._-]/).filter(Boolean), names = parts.map(p => p.replace(/\d+/g, '')).filter(p => /^[a-z]{2,}$/.test(p)), nums = local.match(/\d{2,4}/g) || [];
  const year = nums.find(n => n.length === 4 && +n >= 1940 && +n <= new Date().getFullYear()) || nums.find(n => n.length === 2 && +n >= 50) ;
  return {e:local + '@' + dom, local, dom, canon, tag:(/\+(.+)$/.exec(local) || [])[1] || '', disposable:ID_DISPOSABLE.test(dom + '.'), role:ID_ROLE.test(local.replace(/\+.*$/, '')), free:/^(gmail|googlemail|outlook|hotmail|live|yahoo|ymail|aol|icloud|me|mail|gmx|proton|protonmail|pm|yandex|zoho|tutanota|tuta)\./.test(dom + '.'),
    guess:names.length >= 2 ? names.map(n => n[0].toUpperCase() + n.slice(1)).join(' ') : '', user:local.replace(/\+.*$/, ''), year:year || '', gravatar:'https://gravatar.com/' + md5(new TextEncoder().encode(local + '@' + dom))};
}
function idPhone(p){
  let d = String(p || '').replace(/[^\d+]/g, ''); if(!d) return null; if(d.startsWith('00')) d = '+' + d.slice(2); if(!d.startsWith('+')) return {raw:d, e164:'', country:'', note:'Add the country code (+…) to read it.'};
  const n = d.slice(1); if(n.length < 7 || n.length > 15) return {raw:d, e164:'', country:'', note:'Not a valid international number (7–15 digits).'};
  const cc = ID_CC.filter(([c]) => n.startsWith(c)).sort((a, b) => b[0].length - a[0].length)[0];
  return {raw:d, e164:'+' + n, cc:cc ? cc[0] : '', country:cc ? cc[1] : 'Unknown country code', national:cc ? n.slice(cc[0].length) : n};
}
function labIdent(){
  const q = UI.idq || '', kind = /^[^@\s]+@[^@\s]+\.[a-z]{2,}$/i.test(q.trim()) ? 'email' : /^[+\d][\d\s().-]{6,}$/.test(q.trim()) ? 'phone' : q.trim() ? 'user' : '';
  let body = '';
  if(kind === 'user'){ const u = q.trim().replace(/^@/, '').replace(/\s+/g, ''), key = 'handle:@' + u, st = rsState(key);
    const vars = [...new Set([u, u.replace(/[._-]/g, ''), u.replace(/\d+$/, ''), u.replace(/_/g, '.'), u.replace(/\./g, '_')].filter(x => x && x !== u))].slice(0, 4);
    body = `<p class="t2">Open each place and mark what you found — there, not there, or private — with a note. Kept with <span class="mono">@${esc(u)}</span> in every case.${vars.length ? ' Also try: ' + vars.map(v => `<button class="chip" data-act="idTry" data-v="${esc(v)}">${esc(v)}</button>`).join(' ') : ''}</p>
      ${ckList('user', u)}
      <div class="wrap" style="margin-top:12px"><button class="btn sm" data-act="idAdd" data-v="${esc('@' + u)}">${ico('plus','sm')}Add @${esc(u)} to ${esc(caseNm(theCase()))}</button></div>`; }
  else if(kind === 'email'){ const E2 = idEmail(q);
    if(!E2) body = '<p class="t3">That does not look like an email address.</p>';
    else { const mx = UI.idmx && UI.idmx.dom === E2.dom ? UI.idmx : null, prov = mx && mx.mx.length ? (ID_PROVIDER.find(([re]) => mx.mx.some(h => re.test(h))) || [, 'Own mail servers'])[1] : '';
      const flags = [E2.disposable ? ['red', 'Disposable inbox — made to be thrown away'] : null, E2.role ? ['amber', 'Role account — likely shared, not one person'] : null, E2.free ? ['', 'Free webmail'] : ['', 'Organisation domain'], E2.tag ? ['', 'Sub-address “+' + E2.tag + '” — shows where it was used'] : null, E2.canon !== E2.e ? ['', 'Delivers to ' + E2.canon] : null].filter(Boolean);
      body = `<div class="wrap" style="margin:0 0 12px">${flags.map(([c, t]) => `<span class="chip${c ? ' ' + c : ''}">${esc(t)}</span>`).join('')}</div>
        <dl class="id-dl"><dt>Username part</dt><dd class="mono">${esc(E2.user)} <button class="btn xs ghost" data-act="idTry" data-v="${esc(E2.user)}">Check this username</button></dd>
          ${E2.guess ? `<dt>Looks like a name</dt><dd>${esc(E2.guess)}</dd>` : ''}${E2.year ? `<dt>Number in it</dt><dd>${esc(E2.year)} — often a birth year or graduation year</dd>` : ''}
          <dt>Domain</dt><dd class="mono">${esc(E2.dom)} ${E2.free ? '' : `<button class="btn xs ghost" data-act="idDomLook" data-v="${esc(E2.dom)}">Investigate the domain</button>`}</dd>
          <dt>Mail servers</dt><dd>${mx ? mx.err ? esc(mx.err) : mx.mx.length ? `<span class="mono">${esc(mx.mx.slice(0, 3).join(', '))}</span> — ${esc(prov)}` : '<b style="color:var(--red)">None — this domain cannot receive mail</b>' : `<button class="btn xs" data-act="idMx" data-v="${esc(E2.dom)}">Look up (Google DNS)</button>`}</dd>
          <dt>Gravatar</dt><dd><a href="${esc(E2.gravatar)}" target="_blank" rel="noopener noreferrer">Profile picture and links, if any ${ico('arrow-up-right','sm')}</a></dd></dl>
        <h4 class="ck-h">Places to check</h4>${ckList('email', E2.e)}
        <div class="wrap" style="margin-top:10px"><button class="btn sm primary" data-act="idAdd" data-v="${esc(E2.e)}">${ico('plus','sm')}Add to ${esc(caseNm(theCase()))}</button></div>`; } }
  else if(kind === 'phone'){ const P = idPhone(q);
    body = P && P.e164 ? `<dl class="id-dl"><dt>International</dt><dd class="mono">${esc(P.e164)}</dd><dt>Country</dt><dd>${esc(P.country)} (+${esc(P.cc)})</dd><dt>National number</dt><dd class="mono">${esc(P.national)}</dd></dl>
      <h4 class="ck-h">Places to check</h4>${ckList('phone', P.e164)}
      <div class="wrap" style="margin-top:10px"><button class="btn sm primary" data-act="idAdd" data-v="${esc(P.e164)}">${ico('plus','sm')}Add to ${esc(caseNm(theCase()))}</button></div>` : `<p class="t3">${esc(P ? P.note : 'Not a phone number.')}</p>`; }
  return `<div class="labgrid one wide"><section class="card"><header><h3>${ico('fingerprint','sm')} Identity pivots</h3><span class="t3">a username, an email address or a phone number</span></header><div class="body">
    <form class="lk-q" data-form="idGo"><div class="search-in">${ico('at-sign')}<label class="sr" for="idQ">Username, email or phone</label><input id="idQ" class="inp mono" value="${esc(q)}" placeholder="n1ghtlamp · someone@example.com · +44 20 7946 0000" autocomplete="off" spellcheck="false"></div><button class="btn primary" type="submit">${ico('search','sm')}Pivot</button></form>
    ${body || '<p class="t3">Nothing is sent anywhere until you open a link or look up mail servers.</p>'}</div></section></div>`;
}

/* ---------- pivot plan: what to do next for one indicator ---------- */
function pivotPlan(k, v){
  const P = [], add = (t, why, act, val) => P.push({t, why, act, v:val || v});
  const res = typeof lkKnown === 'function' ? lkKnown(k, v) : {}, A = typeof lkMerge === 'function' ? lkMerge(res) : {}, H = typeof cpHist === 'function' ? cpHist().get(k + ':' + v) : null, on = p => typeof lkProv === 'function' && lkProv(p) && lkOn(lkProv(p));
  if(typeof lkFor === 'function' && lkFor(k).some(lkOn) && !H) add('Check it online', 'Nobody has asked the lookup sources about it yet.', 'lookEnt', k + ':' + v);
  if(k === 'domain'){
    if(!A.created && on('rdap')) add('Find when it was registered', 'A domain registered days before an attack is a strong sign.', 'lookEnt', k + ':' + v);
    add('Find look-alikes of it', 'Phishing kits register several near-copies at once.', 'osTwist');
    if((A.subs || []).length) add('Review its ' + A.subs.length + ' subdomains', 'Certificate logs list hosts the attacker set up.', 'lookEnt', k + ':' + v);
  }
  if(k === 'email'){ const e = idEmail(v); add('Take the address apart', 'Provider, disposable inbox, username to pivot on, mail servers.', 'osIdent');
    if(e && !e.free) add('Investigate ' + e.dom, 'The domain behind a custom address often leads to the operator.', 'lookEnt', 'domain:' + e.dom); }
  if(k === 'handle' || k === 'social') add('Look for the username elsewhere', 'People reuse handles; each profile adds details.', 'osIdent', v.replace(/^@/, '').replace(/^https?:\/\/[^/]+\//, ''));
  if(k === 'phone') add('Read the number', 'Country, international format and messaging apps.', 'osIdent');
  if((k === 'ipv4' || k === 'ipv6') && A.asn && !A.abuse) add('Find who to report abuse to', 'RIPEstat names the network\'s abuse contact.', 'lookEnt', k + ':' + v);
  return P.slice(0, 3);
}
const OS_ACTS = {
  twCheck:() => twRun(), twStop:() => { if(UI.tw && UI.tw.sig) UI.tw.sig.stop = true; },
  twDnsOn:() => { const S = lkSettings(); S.on.dns = true; S.on.rdap = true; mutate('turned on Google DNS and RDAP lookups'); renderMain(); },
  twLook:(id, v) => lookGo('domain', v),
  twAdd:() => { const L = (UI.tw.list || []).filter(x => x.exists && twRisk(x, UI.tw.orig).s >= 45); let n = 0; L.forEach(x => { if(ctiAddEntry('domain', x.d, 'Look-alike of ' + UI.tw.d + ' (' + (TW_NAME[x.kind] || x.kind) + '): ' + twRisk(x, UI.tw.orig).why.join(', '))) n++; }); mutate('added look-alike domains'); toast(n ? n + ' added to ' + caseNm(theCase()) : 'They are already in ' + caseNm(theCase())); },
  twCsv:() => download(safeName(UI.tw.d + '-lookalikes.csv'), ['domain,unicode,how,risk,why,ips,mx,ns,created'].concat((UI.tw.list || []).filter(x => x.exists).map(x => { const r = twRisk(x, UI.tw.orig); return [x.d, x.show, TW_NAME[x.kind] || x.kind, r.s, r.why.join('; '), x.ips.join(' '), x.mx.join(' '), x.ns.join(' '), x.created ? new Date(x.created).toISOString().slice(0, 10) : ''].map(csvCell).join(','); })).join('\n'), 'text/csv'),
  idTry:(id, v) => { UI.idq = v; renderMain(); },
  idAdd:(id, v) => { const n = iocNorm(v) || (/^@/.test(v) ? {k:'handle', v} : /^\+\d/.test(v) ? {k:'phone', v} : null); if(!n) return toast('Cannot add that');
    if(ctiAddEntry(n.k, n.v, 'Identity pivot')){ mutate('added ' + n.v); toast(n.v + ' added to ' + caseNm(theCase())); } else toast('Already in ' + caseNm(theCase()) + ', or not a kind the vault keeps'); },
  idMx:async (id, v) => { if(!lkOn(lkProv('dns'))) return toast('Switch on Google DNS in Threat Intel → Sources → Lookups first');
    try{ const j = JSON.parse((await lkFetch('https://dns.google/resolve?name=' + encodeURIComponent(v) + '&type=MX', {timeout:10000})).text); UI.idmx = {dom:v, mx:(j.Answer || []).filter(y => y.type === 15).map(y => cap(String(y.data).replace(/^\d+\s+/, '').replace(/\.$/, ''), 253).toLowerCase())}; }
    catch(e){ UI.idmx = {dom:v, mx:[], err:e.message}; } renderMain(); },
  idDomLook:(id, v) => lookGo('domain', v),
  osTwist:(id, v) => { UI.labTab = 'twist'; UI.tw = {d:v, list:twGen(v)}; go('#/lab'); },
  osIdent:(id, v) => { UI.labTab = 'ident'; UI.idq = v; go('#/lab'); },
};
