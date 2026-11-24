/* ==========================================================================
   Writing compared — supporting evidence, never proof
   The posts two names wrote, from your evidence, compared on what writers do
   without thinking: the letter patterns of their words, the small words they
   lean on, and habits — punctuation, capitals, British or American spelling,
   dropped apostrophes, recurring misspellings, shorthand.
   A raw similarity means nothing alone, so it is ranked against every other
   writer in your evidence with enough text: "closer to A than 9 of 11 others".
   With fewer than three other writers, no ranking is given — only the habits.
   Indicators (addresses, wallets, links, handles) are taken out first, so a
   shared wallet does not make two texts look alike.
   ========================================================================== */
const ST_MIN = 250;   // words each, below which nothing is said
const ST_FW = 'the of and to a in is that it i you for on with as was be at this have not but are they he she we my me so if or just what all can there from do your about would like one no will an get dont know think people because when out up more some them their then than also only even really much'.split(' ');
const ST_HABITS = [
  ['excl', 'Exclamation marks', t => (t.match(/!/g) || []).length],
  ['multi', 'Repeated !!! or ???', t => (t.match(/[!?]{2,}/g) || []).length],
  ['ellip', 'Ellipses …', t => (t.match(/\.{3}|…/g) || []).length],
  ['semi', 'Semicolons', t => (t.match(/;/g) || []).length],
  ['dash', 'Double hyphens --', t => (t.match(/ -- |--/g) || []).length],
  ['emoji', 'Emoji', t => (t.match(/\p{Extended_Pictographic}/gu) || []).length],
  ['emot', 'Text smileys :) :D', t => (t.match(/(?:^|\s)[:;=]-?[)(DPp](?=\s|$)/g) || []).length],
  ['lowi', 'Lowercase “i” as a word', t => (t.match(/(?:^|[\s.,!?])i(?=[\s',.!?])/g) || []).length],
  ['lowstart', 'Sentences starting lowercase', t => (t.match(/(?:^|[.!?]\s+)[a-z]/gm) || []).length],
  ['caps', 'WORDS IN CAPITALS', t => (t.match(/\b[A-Z]{3,}\b/g) || []).filter(w => !/^(USD|EUR|BTC|XMR|ETH|PGP|VPN|DM|PM|OK|LOL|USA|UK|EU|API|URL|IP|CEO|FBI|NSA|CIA)$/.test(w)).length],
  ['nopos', 'Apostrophes dropped (dont, cant, im)', t => (t.match(/\b(dont|cant|wont|didnt|doesnt|isnt|wasnt|im|ive|youre|theyre|thats|whats|couldnt|shouldnt|wouldnt)\b/gi) || []).length],
  ['brit', 'British spelling (colour, realise, centre)', t => (t.match(/\b(colou?rs?|favou?rite|favou?rs?|honou?rs?|behaviou?rs?|neighbou?rs?|centres?|theatres?|metres?|realis(e|ed|ing)|organis(e|ed|ing|ation)|recognis(e|ed|ing)|apologis(e|ed|ing)|analys(e|ed|ing)|travelled|cancelled|defence|offence|programme|grey|whilst|amongst|mum)\b/gi) || []).filter(w => /our|tre|is(e|ed|ing|ation)$|ys(e|ed|ing)$|ll|ence$|mme$|grey|whilst|amongst|mum/i.test(w)).length],
  ['amer', 'American spelling (color, realize, center)', t => (t.match(/\b(colors?|favorite|favors?|honors?|behaviors?|neighbors?|centers?|theaters?|meters?|realiz(e|ed|ing)|organiz(e|ed|ing|ation)|recogniz(e|ed|ing)|apologiz(e|ed|ing)|analyz(e|ed|ing)|traveled|canceled|defense|offense|gray|mom)\b/gi) || []).length],
  ['miss', 'Common misspellings (alot, definately, recieve…)', t => (t.match(/\b(alot|definately|definatly|recieve|recieved|seperate|untill|wierd|occured|accross|beleive|goverment|tommorow|thier|truely|wich|becuase|alright)\b/gi) || []).length],
  ['short', 'Shorthand (u, ur, pls, thx, bro)', t => (t.match(/\b(u|ur|pls|plz|thx|tnx|ty|bro|bruh|idk|imo|tbh|ngl|smh|rn|w\/)\b/gi) || []).length],
  ['dsp', 'Two spaces after a full stop', t => (t.match(/\. {2}\S/g) || []).length],
];
/* the text a name wrote: records where it is the only name, with indicators taken out */
function stText(key){
  const g = globalEnts().get(key); if(!g) return {text:'', recs:0, words:0};
  const parts = []; let recs = 0;
  for(const r of g.recs){ if(r.type === 'lead') continue; /* a chat export's record is one author's messages — the names they mention do not make it someone else's text */
    if((r.tags || []).includes('chat')){ const m = /^(?:Telegram|Discord) user ID: (\d+)/m.exec(r.body || ''); if(!m || !/^(tgid|dcid):/.test(key) || key.split(':')[1] !== m[1]) continue; }
    else { const names = new Set((r.ents || []).filter(e => e.k === 'handle' || e.k === 'social' || e.k === 'tgid' || e.k === 'dcid').map(e => e.k + ':' + e.v)); if(names.size > 1) continue; }
    const t = String(r.body || '').replace(/^(URL|Title|Saved|Site|Author|Published|SHA-256 of saved file|Description|Posted by|Chat|Telegram user ID|Discord user ID|Messages|No account number|Posted as the channel)[^\n]*\n?/gim, '').replace(/^\[\d{4}-\d\d-\d\d \d\d:\d\d UTC\]( \(forwarded from [^)]*\))?/gm, '')
      .replace(/https?:\/\/\S+|\b[\w.+-]+@[\w-]+(\.[\w-]+)+\b|@\w+|\b(0x)?[0-9a-f]{24,}\b|\b[1-9A-HJ-NP-Za-km-z]{25,}\b|\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[a-z2-7]{16,56}\.onion\b/gi, ' ');
    if(t.trim()){ parts.push(t); recs++; } }
  const text = parts.join('\n'); return {text, recs, words:(text.match(/[A-Za-zÀ-ɏ']+/g) || []).length};
}
function stProfile(text){
  const low = text.toLowerCase().replace(/\s+/g, ' '), tri = new Map(); for(let i = 0; i + 3 <= low.length; i++){ const g = low.slice(i, i + 3); tri.set(g, (tri.get(g) || 0) + 1); }
  const words = low.match(/[a-zÀ-ɏ']+/g) || [], W = words.length || 1, fw = ST_FW.map(f => words.filter(w => w === f).length / W);
  const hab = Object.fromEntries(ST_HABITS.map(([k, , fn]) => [k, fn(text) / W * 1000]));
  const big = new Map(); for(let i = 0; i + 1 < words.length; i++){ if(ST_FW.includes(words[i]) && ST_FW.includes(words[i + 1])) continue; const b = words[i] + ' ' + words[i + 1]; big.set(b, (big.get(b) || 0) + 1); }
  return {tri, fw, hab, big, words:W};
}
const stCos = (a, b) => { let d = 0, x = 0, y = 0; for(let i = 0; i < a.length; i++){ d += a[i] * b[i]; x += a[i] * a[i]; y += b[i] * b[i]; } return x && y ? d / Math.sqrt(x * y) : 0; };
function stTriCos(A, B){ const keys = new Set([...[...A.tri.entries()].sort((p, q) => q[1] - p[1]).slice(0, 400).map(x => x[0]), ...[...B.tri.entries()].sort((p, q) => q[1] - p[1]).slice(0, 400).map(x => x[0])]);
  return stCos([...keys].map(k => A.tri.get(k) || 0), [...keys].map(k => B.tri.get(k) || 0)); }
function stHabSim(A, B){ const ks = ST_HABITS.map(h => h[0]).filter(k => A.hab[k] > .5 || B.hab[k] > .5); if(!ks.length) return .5;
  return ks.reduce((s, k) => s + Math.min(A.hab[k], B.hab[k]) / Math.max(A.hab[k], B.hab[k]), 0) / ks.length; }
function stScore(A, B){ const c = stTriCos(A, B), f = stCos(A.fw, B.fw), h = stHabSim(A, B); return {c, f, h, all:.5 * c + .3 * f + .2 * h}; }
/* every writer in your evidence with enough text, as a baseline */
function stWriters(){ const out = []; for(const [k, g] of globalEnts()){ if(!/^(handle|tgid|dcid)$/.test(g.k)) continue; const T = stText(k); if(T.words >= ST_MIN) out.push({k, T}); } return out; }
function stCompare(ka, kb){
  const A = stText(ka), B = stText(kb); if(A.words < ST_MIN || B.words < ST_MIN) return {short:true, A, B};
  const pa = stProfile(A.text), pb = stProfile(B.text), s = stScore(pa, pb);
  const others = stWriters().filter(w => w.k !== ka && w.k !== kb).map(w => ({k:w.k, s:stScore(pa, stProfile(w.T.text)).all}));
  const below = others.filter(o => o.s < s.all).length;
  const habits = ST_HABITS.map(([k, l]) => ({l, a:pa.hab[k], b:pb.hab[k]})).filter(x => x.a > .5 || x.b > .5).map(x => ({...x, same:Math.min(x.a, x.b) / Math.max(x.a, x.b) >= .5}));
  const shared = [...pa.big.entries()].filter(([b, n]) => n >= 2 && (pb.big.get(b) || 0) >= 2).map(([b, n]) => [b, n, pb.big.get(b)]).sort((x, y) => (y[1] + y[2]) - (x[1] + x[2])).slice(0, 10);
  return {A, B, s, others:others.length, below, habits, shared};
}
const stBar = (l, v, t) => `<div class="st-b2"><span>${l}</span><span class="st-m"><i style="width:${Math.round(Math.max(0, Math.min(1, v)) * 100)}%"></i></span><small>${t}</small></div>`;
function stDlg(ka, kb){
  const R = stCompare(ka, kb), na = entSplit(ka).v, nb = entSplit(kb).v;
  const head = dhead('Writing compared: ' + esc(na) + ' and ' + esc(nb));
  const amount = `<p class="t3 small" style="margin:0 0 12px">${esc(na)}: ${R.A.words.toLocaleString()} words from ${R.A.recs} record${R.A.recs === 1 ? '' : 's'} · ${esc(nb)}: ${R.B.words.toLocaleString()} words from ${R.B.recs} record${R.B.recs === 1 ? '' : 's'}. Only records where the name is the only one are read; addresses, wallets, links and handles are taken out.</p>`;
  if(R.short) return openDlg(head + `<div class="in">${amount}<p style="margin:0">Too little text to say anything — at least ${ST_MIN} words each. Capture more of their posts first.</p></div><footer><button class="btn" data-act="dclose">Close</button></footer>`);
  const verdict = R.others >= 3 ? `<p class="st-v"><b>${esc(nb)} writes more like ${esc(na)} than ${R.below} of ${R.others} other writers</b> in your evidence${R.below === R.others ? ' — closer than every one of them' : R.below / R.others < .5 ? ' — no closer than most' : ''}.</p>`
    : `<p class="st-v"><b>No ranking</b> — ${R.others ? 'only ' + R.others : 'no'} other writer${R.others === 1 ? '' : 's'} in your evidence ${R.others === 1 ? 'has' : 'have'} ${ST_MIN}+ words to compare against, and a similarity alone means nothing. The habits below still stand.</p>`;
  openDlg(head + `<div class="in">${amount}${verdict}
    <div class="st-bars">${stBar('Letter patterns', R.s.c, 'how words are spelled and joined')}${stBar('Small words', R.s.f, 'the, of, just, really…')}${stBar('Habits', R.s.h, 'punctuation, capitals, spelling')}</div>
    ${R.habits.length ? `<h4 class="st-h">Habits, per 1,000 words</h4><table class="st-t"><thead><tr><th></th><th>${esc(na)}</th><th>${esc(nb)}</th><th></th></tr></thead><tbody>${R.habits.map(h => `<tr><td>${esc(h.l)}</td><td class="n">${h.a.toFixed(1)}</td><td class="n">${h.b.toFixed(1)}</td><td>${h.same ? '<span class="st-same">alike</span>' : ''}</td></tr>`).join('')}</tbody></table>` : ''}
    ${R.shared.length ? `<h4 class="st-h">Phrases both use more than once</h4><div class="wrap">${R.shared.map(([b, x, y]) => `<span class="chip sq">“${esc(b)}” <small class="t3">${x} · ${y}</small></span>`).join('')}</div>` : ''}
    <p class="st-warn">${ico('triangle-alert','sm')}Supporting evidence only. Short texts, translation tools, shared templates, quoted or copied text and several people behind one account all distort it. Never link two names on writing alone.</p></div>
    <footer><button class="btn" data-act="dclose">Close</button></footer>`);
  $('dlg').classList.add('wide');
}
function stPickDlg(ka){
  const L = stWriters().filter(w => w.k !== ka).sort((a, b) => b.T.words - a.T.words);
  openDlg(dhead('Compare ' + esc(entSplit(ka).v) + '’s writing with…') + `<div class="in">${L.length ? L.slice(0, 40).map(w => `<button class="li" data-act="stGo" data-id="${esc(ka)}" data-v="${esc(w.k)}"><div class="main2"><b>${esc(entSplit(w.k).v)}</b><small>${w.T.words.toLocaleString()} words · ${w.T.recs} records</small></div></button>`).join('')
    : `<p style="margin:0">No other name has ${ST_MIN}+ words of its own in your evidence yet.</p>`}</div><footer><button class="btn" data-act="dclose">Close</button></footer>`);
}
const ST_ACTS = {
  stPick:id => stPickDlg(id),
  stGo:(id, v) => stDlg(id, v),
};
