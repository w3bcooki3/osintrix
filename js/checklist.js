/* ==========================================================================
   Handle, email and phone checklist (Forensics kit → Identity pivots).
   Every place worth checking for one username, email address or phone
   number — profiles, breach and leak searches, search-engine queries,
   messaging apps — and for each, what you found: there, not there, or
   private. A note per place, archived copies one click away, and a found
   profile saved to the case as evidence. Nothing is looked up by the app:
   you open each place yourself; the list keeps the hunt complete.
   Kept per value, across cases, in the same store as the details panel's
   research ticks (an older plain tick shows as "opened").
   ========================================================================== */
const CK_RES = [['found', 'There', 'check'], ['none', 'Not there', 'x'], ['private', 'Private', 'lock']];
const CK_U = u => encodeURIComponent(u);
/* the places for each kind of value: [group, [[name, url, kind?]]] — kind 'profile' means a hit is an account page worth saving */
function ckPlaces(kind, v){
  if(kind === 'user'){ const u = v, q = CK_U(u);
    return ID_SITES.map(([g, L]) => [g, L.map(([n, t]) => [n, t.replace('%s', q), /search|WhatsMyName|Google|Bing|DuckDuckGo/i.test(n) ? 'search' : 'profile'])]).concat([
      ['Search queries', [['Google: pastes and leaks', 'https://www.google.com/search?q=' + CK_U(`"${u}" (site:pastebin.com OR site:ghostbin.com OR site:rentry.co OR site:justpaste.it)`), 'search'],
        ['Google: in links', 'https://www.google.com/search?q=' + CK_U(`inurl:${u}`), 'search'], ['Google: with password or leak', 'https://www.google.com/search?q=' + CK_U(`"${u}" (password OR leak OR dump OR combolist)`), 'search'],
        ['Yandex (exact)', 'https://yandex.com/search/?text=' + CK_U(`"${u}"`), 'search'], ['Telegram channels (TGStat)', 'https://tgstat.com/search?q=' + q, 'search'], ['GitHub code', 'https://github.com/search?type=code&q=' + CK_U(`"${u}"`), 'search']]]]); }
  if(kind === 'email'){ const e = v, q = CK_U(e), dom = e.split('@')[1] || '', free = /^(gmail|googlemail|outlook|hotmail|live|yahoo|ymail|aol|icloud|me|mail|gmx|proton|protonmail|pm|yandex|zoho|tutanota|tuta)\./.test(dom + '.');
    return [['Breaches and leaks', [['Have I Been Pwned', 'https://haveibeenpwned.com/account/' + q, 'search'], ['DeHashed', 'https://dehashed.com/search?query=' + q, 'search'], ['Intelligence X', 'https://intelx.io/?s=' + q, 'search'], ['LeakCheck', 'https://leakcheck.io/', 'search'], ['BreachDirectory', 'https://breachdirectory.org/', 'search']]],
      ['Accounts it opened', [['Epieos (Google, Skype, others)', 'https://epieos.com/?q=' + q, 'search'], ['Gravatar', 'https://gravatar.com/' + md5(new TextEncoder().encode(e.toLowerCase())), 'profile'], ['GitHub commits', 'https://github.com/search?type=commits&q=' + CK_U('author-email:' + e), 'search'], ['PGP keys (keys.openpgp.org)', 'https://keys.openpgp.org/search?q=' + q, 'search'], ['PGP keys (Ubuntu)', 'https://keyserver.ubuntu.com/pks/lookup?search=' + q + '&op=index', 'search']]],
      ['Search queries', [['Google (exact)', 'https://www.google.com/search?q=' + CK_U(`"${e}"`), 'search'], ['Bing (exact)', 'https://www.bing.com/search?q=' + CK_U(`"${e}"`), 'search'], ['DuckDuckGo (exact)', 'https://duckduckgo.com/?q=' + CK_U(`"${e}"`), 'search'], ['Google: pastes', 'https://www.google.com/search?q=' + CK_U(`"${e}" (site:pastebin.com OR site:ghostbin.com OR site:rentry.co)`), 'search'], ['Google: documents', 'https://www.google.com/search?q=' + CK_U(`"${e}" (filetype:pdf OR filetype:xlsx OR filetype:docx OR filetype:csv)`), 'search']]]]
      .concat(free ? [] : [['Its domain', [['Hunter (people at ' + dom + ')', 'https://hunter.io/search/' + CK_U(dom), 'search'], ['Who registered ' + dom, 'https://lookup.icann.org/en/lookup?name=' + CK_U(dom), 'search'], ['Certificates for ' + dom, 'https://crt.sh/?q=' + CK_U(dom), 'search']]]]); }
  if(kind === 'phone'){ const d = v.replace(/[^\d+]/g, ''), n = d.replace(/^\+/, '');
    return [['Messaging', [['WhatsApp', 'https://wa.me/' + n, 'profile'], ['Telegram', 'https://t.me/' + d, 'profile'], ['Viber (open in the app)', 'viber://chat?number=' + CK_U(d), 'profile']]],
      ['Who it belongs to', [['Sync.me', 'https://sync.me/search/?number=' + CK_U(d), 'search'], ['NumLookup', 'https://www.numlookup.com/?phone=' + CK_U(d), 'search'], ['Truecaller (search)', 'https://www.truecaller.com/search/' + CK_U(d), 'search'], ['CallerID Test', 'https://calleridtest.com/', 'search']]],
      ['Search queries', [['Google (written several ways)', 'https://www.google.com/search?q=' + CK_U(`"${d}" OR "${n}"`), 'search'], ['Google: classifieds and ads', 'https://www.google.com/search?q=' + CK_U(`"${n}" (ad OR listing OR sale OR rent)`), 'search'], ['Yandex', 'https://yandex.com/search/?text=' + CK_U(`"${n}"`), 'search']]]]; }
  return [];
}
const ckKey = (kind, v) => (kind === 'user' ? 'handle:@' + v.replace(/^@/, '') : kind + ':' + v);
/* the state of one place: '' not looked at, 'opened', 'found', 'none', 'private' */
const ckRes = x => !x ? '' : x.r || 'opened';
function ckSet(key, name, patch){ DB.research = DB.research && typeof DB.research === 'object' ? DB.research : {}; const s = DB.research[key] || (DB.research[key] = {}); const cur = s[name] || {at:Date.now()};
  Object.assign(cur, patch, {at:Date.now()}); if(patch.r === '') delete cur.r; if(patch.note === '') delete cur.note; if(!cur.r && !cur.note && patch.clear){ delete s[name]; } else s[name] = cur; if(!Object.keys(s).length) delete DB.research[key]; save(); }
function ckList(kind, v){
  const G = ckPlaces(kind, v), key = ckKey(kind, v), st = (DB.research || {})[key] || {}, all = G.flatMap(([, L]) => L);
  const c = {found:0, none:0, private:0, opened:0}; for(const [n] of all){ const r = ckRes(st[n]); if(r) c[r]++; } const done = c.found + c.none + c.private, f = UI.ckF || 'all';
  const show = ([n]) => f === 'all' || (f === 'open' ? !['found', 'none', 'private'].includes(ckRes(st[n])) : ckRes(st[n]) === 'found');
  const row = ([n, url, k]) => { const x = st[n], r = ckRes(x), arch = /^https?:/.test(url) && k === 'profile';
    return `<div class="ck-r${r ? ' ck-' + r : ''}"><div class="ck-n"><a href="${esc(url)}" target="_blank" rel="noopener noreferrer" data-act="ckOpen" data-id="${esc(key)}" data-v="${esc(n)}">${esc(n)}${ico('arrow-up-right','sm')}</a>
      ${arch ? `<span class="ck-ar"><a href="${esc('https://web.archive.org/web/*/' + url)}" target="_blank" rel="noopener noreferrer" title="Archived copies (Wayback Machine)">Wayback</a> · <a href="${esc('https://archive.ph/' + url)}" target="_blank" rel="noopener noreferrer" title="Archived copies (archive.today)">archive.today</a></span>` : ''}${r === 'opened' ? '<span class="t3 small">opened</span>' : ''}</div>
      <div class="ck-b" role="group" aria-label="${esc(n)}: what you found">${CK_RES.map(([v2, l, i]) => `<button class="ck-s" data-act="ckRes" data-id="${esc(key)}" data-v="${esc(n + '\u0001' + v2)}" aria-pressed="${r === v2}">${ico(i,'sm')}${l}</button>`).join('')}</div>
      ${r === 'found' || r === 'private' || (x && x.note) ? `<div class="ck-x"><label class="sr" for="ckN-${esc(btoa(unescape(encodeURIComponent(n))).replace(/=/g, ''))}">Note on ${esc(n)}</label><input class="inp sm ck-note" id="ckN-${esc(btoa(unescape(encodeURIComponent(n))).replace(/=/g, ''))}" data-ck="${esc(key)}" data-name="${esc(n)}" value="${esc(x && x.note || '')}" maxlength="500" placeholder="What is there — name, photo, bio, last post…" autocomplete="off">
        ${r === 'found' && k === 'profile' && /^https?:/.test(url) ? (x && x.rec && typeof recById === 'function' && recById(x.rec) ? `<span class="t3 small">${ico('check','sm')} saved to the case</span>` : `<button class="btn xs" data-act="ckSave" data-id="${esc(key)}" data-v="${esc(n)}">${ico('plus','sm')}Save to ${esc(caseNm(theCase()))}</button>`) : ''}</div>` : ''}</div>`; };
  return `<div class="ck">
    <div class="ck-top"><div class="ck-bar" role="img" aria-label="${done} of ${all.length} places checked: ${c.found} there, ${c.none} not there, ${c.private} private"><i class="f" style="width:${c.found / all.length * 100}%"></i><i class="p" style="width:${c.private / all.length * 100}%"></i><i class="n" style="width:${c.none / all.length * 100}%"></i></div>
      <span class="t2 small"><b>${done}</b> of ${all.length} checked · <b>${c.found}</b> there · ${c.private} private · ${c.none} not there</span><span style="flex:1"></span>
      <div class="seg" role="group" aria-label="Show">${[['all', 'All'], ['open', 'To check'], ['found', 'There']].map(([k, l]) => `<button data-act="ckF" data-v="${k}" aria-pressed="${f === k}">${l}</button>`).join('')}</div>
      <button class="btn sm ghost" data-act="ckCopy" data-id="${esc(key)}" data-v="${esc(kind + '\u0001' + v)}">${ico('copy','sm')}Copy what was found</button></div>
    <div class="ck-g">${G.map(([g, L]) => { const R = L.filter(show); return R.length ? `<section><h4>${esc(g)}</h4>${R.map(row).join('')}</section>` : ''; }).join('') || '<p class="t3">Nothing here with this filter.</p>'}</div></div>`;
}
document.addEventListener('change', ev => { const el = ev.target; if(!el || !el.classList || !el.classList.contains('ck-note')) return; ckSet(el.dataset.ck, el.dataset.name, {note:String(el.value || '').slice(0, 500)}); });
const CK_ACTS = {
  ckOpen:(id, v) => { const s = ((DB.research || {})[id] || {})[v]; if(!s || !s.r) ckSet(id, v, {}); setTimeout(() => renderMain(), 60); },
  ckRes:(id, v) => { const [n, r] = String(v).split('\u0001'), cur = ckRes(((DB.research || {})[id] || {})[n]); ckSet(id, n, cur === r ? {r:'', clear:true} : {r}); renderMain();
    if(cur !== r && r === 'found'){ const el = document.querySelector(`.ck-note[data-name="${CSS.escape(n)}"]`); if(el) el.focus(); } },
  ckF:(id, v) => { UI.ckF = v; renderMain(); },
  ckSave:(id, n) => { const i = id.indexOf(':'), kind0 = id.slice(0, i), val = id.slice(i + 1), kind = kind0 === 'handle' ? 'user' : kind0, v = kind === 'user' ? val.replace(/^@/, '') : val;
    const pl = ckPlaces(kind, v).flatMap(([, L]) => L).find(x => x[0] === n); if(!pl) return; const st = ((DB.research || {})[id] || {})[n] || {}, c = theCase();
    const body = `${pl[1]}\n\nFound while checking ${kind === 'user' ? '@' + v : v} on ${n}${st.note ? ':\n' + st.note : '.'}\nChecked ${new Date().toISOString().slice(0, 16).replace('T', ' ')} UTC.`;
    const r = {id:uid('r'), caseId:c.id, type:'evidence', title:`${kind === 'user' ? '@' + v : v} on ${n}`, body, tsRaw:new Date().toISOString(), tsZone:'explicit', ts:Date.now(), source:'checklist:' + n, host:'', tags:['profile', 'checklist'], ents:extractRich(body), answer:'', addedBy:'You', addedAt:Date.now(), hash:''};
    DB.records.push(r); ckSet(id, n, {rec:r.id}); mutate('saved ' + r.title); if(typeof hashRecords === 'function') hashRecords(); renderMain(); toast(r.title + ' saved to ' + caseNm(c)); },
  ckCopy:(id, v) => { const [kind, val] = String(v).split('\u0001'), st = (DB.research || {})[id] || {}, L = ckPlaces(kind, val).flatMap(([, x]) => x);
    const lines = [`${kind === 'user' ? '@' + val : val} — checked ${Object.values(st).filter(x => x && x.r).length} of ${L.length} places`];
    for(const [r, h] of [['found', 'There'], ['private', 'Private'], ['none', 'Not there']]){ const xs = L.filter(([n]) => ckRes(st[n]) === r); if(xs.length) lines.push('', h + ':', ...xs.map(([n, u]) => `- ${n}: ${u}${st[n].note ? ' — ' + st[n].note : ''}`)); }
    copyText(lines.join('\n')); },
};
