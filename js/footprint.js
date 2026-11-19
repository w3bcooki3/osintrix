/* ==========================================================================
   Online footprint (Analysis → Accounts) — when each account in a case was
   made, when it shows up in your evidence, and what it was called before.
   · Creation dates from profile data you paste (GitHub, Reddit, Mastodon,
     X/Twitter, YouTube, Bluesky JSON) and from what captured pages say
     ("Joined March 2019", "Member since 2015-02-01", "Account created …").
   · First and last time each account appears in the case's evidence.
   · Earlier names: the same account number under another name in two pastes,
     or a page that says "formerly @…" / "changed username from … to …".
   · What stands out: accounts made shortly before they first show up, and
     accounts made within days of each other — the usual signs of accounts
     set up for the job.
   ========================================================================== */
const FT_MON = {jan:0, january:0, feb:1, february:1, mar:2, march:2, apr:3, april:3, may:4, jun:5, june:5, jul:6, july:6, aug:7, august:7, sep:8, sept:8, september:8, oct:9, october:9, nov:10, november:10, dec:11, december:11};
/* a date as profile pages write it → {ms, exact} (exact false when only the month or year is known) */
function ftDate(s){ s = String(s || '').trim().replace(/,/g, ' ').replace(/\s+/g, ' '); let m;
  if((m = s.match(/^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2}))?)?/))) return {ms:Date.UTC(+m[1], m[2] - 1, +m[3], +(m[4] || 0), +(m[5] || 0), +(m[6] || 0)), exact:true};
  if((m = s.match(/^(\d{1,2}) ([A-Za-z]{3,9})\.? (\d{4})/)) && FT_MON[m[2].toLowerCase()] != null) return {ms:Date.UTC(+m[3], FT_MON[m[2].toLowerCase()], +m[1]), exact:true};
  if((m = s.match(/^([A-Za-z]{3,9})\.? (\d{1,2}) (\d{4})/)) && FT_MON[m[1].toLowerCase()] != null) return {ms:Date.UTC(+m[3], FT_MON[m[1].toLowerCase()], +m[2]), exact:true};
  if((m = s.match(/^([A-Za-z]{3,9})\.? (\d{4})/)) && FT_MON[m[1].toLowerCase()] != null) return {ms:Date.UTC(+m[2], FT_MON[m[1].toLowerCase()], 1), exact:false, month:true};
  if((m = s.match(/^(\d{1,2})[./](\d{1,2})[./](\d{4})/))) return {ms:Date.UTC(+m[3], m[2] - 1, +m[1]), exact:true};
  if((m = s.match(/^(\d{4})$/))) return {ms:Date.UTC(+m[1], 0, 1), exact:false, year:true};
  if((m = s.match(/^[A-Za-z]{3} ([A-Za-z]{3}) (\d{1,2}) (\d{2}):(\d{2}):(\d{2}) [+-]\d{4} (\d{4})$/)) && FT_MON[m[1].toLowerCase()] != null) return {ms:Date.UTC(+m[6], FT_MON[m[1].toLowerCase()], +m[2], +m[3], +m[4], +m[5]), exact:true};   // Twitter v1.1
  return null; }
/* is date d earlier than date c? A month or a year counts as earlier only if it ends before c — "Joined February 2024" does not replace 20 February 2024 */
const ftEnd = d => d.year ? Date.UTC(new Date(d.ms).getUTCFullYear() + 1, 0, 1) : d.month ? Date.UTC(new Date(d.ms).getUTCFullYear(), new Date(d.ms).getUTCMonth() + 1, 1) : d.ms;
const ftEarlier = (d, c) => !c || (d.exact && c.exact ? d.ms < c.ms : ftEnd(d) <= c.ms || (!c.exact && d.exact && d.ms < ftEnd(c)) );
const ftIso = s => { const t = Date.parse(s); return isFinite(t) ? {ms:t, exact:true} : null; };
/* ---------- profile data → {platform, id, handle, name, created, active, url} ---------- */
function ftProfile(o){
  if(!o || typeof o !== 'object') return null; let p = null;
  if(o.login && o.created_at && /github\.com/.test(o.html_url || o.url || '')) p = {platform:'GitHub', id:String(o.id || ''), handle:o.login, name:o.name || '', created:ftIso(o.created_at), active:o.updated_at ? ftIso(o.updated_at) : null, activeWhat:'profile last changed', url:o.html_url, extra:[o.location, o.blog, o.email, o.company].filter(Boolean)};
  else if(o.kind === 't2' && o.data && o.data.name) p = {platform:'Reddit', id:'t2_' + (o.data.id || ''), handle:o.data.name, name:o.data.subreddit && o.data.subreddit.title || '', created:o.data.created_utc ? {ms:o.data.created_utc * 1000, exact:true} : null, url:'https://www.reddit.com/user/' + o.data.name};
  else if(o.acct && o.username && o.created_at && o.url) p = {platform:'Mastodon', id:String(o.id || '') + '@' + String(o.url).replace(/^https?:\/\/([^/]+).*$/, '$1'), handle:o.acct.includes('@') ? o.acct : o.username + '@' + String(o.url).replace(/^https?:\/\/([^/]+).*$/, '$1'), name:o.display_name || '', created:ftIso(o.created_at), active:o.last_status_at ? ftIso(o.last_status_at) : null, activeWhat:'last post', url:o.url};
  else if(o.data && o.data.username && o.data.created_at) p = {platform:'X / Twitter', id:String(o.data.id || ''), handle:o.data.username, name:o.data.name || '', created:ftIso(o.data.created_at), url:'https://x.com/' + o.data.username};
  else if(o.screen_name && o.created_at && o.id_str) p = {platform:'X / Twitter', id:o.id_str, handle:o.screen_name, name:o.name || '', created:ftDate(o.created_at), url:'https://x.com/' + o.screen_name};
  else if(o.kind === 'youtube#channelListResponse' && Array.isArray(o.items) && o.items[0] && o.items[0].snippet){ const it = o.items[0]; p = {platform:'YouTube', id:it.id, handle:it.snippet.customUrl || it.id, name:it.snippet.title || '', created:ftIso(it.snippet.publishedAt), url:'https://www.youtube.com/' + (it.snippet.customUrl || 'channel/' + it.id)}; }
  else if(o.did && o.handle && o.createdAt) p = {platform:'Bluesky', id:o.did, handle:o.handle, name:o.displayName || '', created:ftIso(o.createdAt), url:'https://bsky.app/profile/' + o.handle};
  if(p) p.handle = String(p.handle).replace(/^@/, ''); return p;
}
function ftParseJson(t){ if(!/^\s*[\[{]/.test(t)) return []; let o = null; try{ o = JSON.parse(t); }catch(e){ return []; } return (Array.isArray(o) ? o : [o]).map(ftProfile).filter(Boolean); }
/* what captured pages say about when an account began, and what it was called */
const FT_JOIN = /\b(?:joined(?: on)?|member since|account created(?: on)?|registered(?: on)?|date joined|created(?: on)?|on (?:twitter|x|instagram|tiktok|telegram|reddit|github) since|cake day)\s*[:\-–]?\s*((?:\d{1,2} )?[A-Z][a-z]{2,8}\.?(?: \d{1,2})?,? \d{4}|\d{4}-\d{2}-\d{2}|\d{1,2}[./]\d{1,2}[./]\d{4}|\d{4})\b/gi;
const FT_RENAME = [/\b(?:formerly|previously|aka|a\.k\.a\.|formerly known as|previously known as|old (?:user)?name)\s*:?\s*@?([A-Za-z0-9_.]{3,40})/gi, /\bchanged (?:(?:his|her|their|the) )?(?:user ?name|handle|name) from @?([A-Za-z0-9_.]{3,40}) to @?([A-Za-z0-9_.]{3,40})/gi];
/* a profile link, with or without https:// → the account name; site pages and API addresses (github.com/users, x.com/i/…) are not accounts */
const FT_NOT_ACC = /^(users|orgs|repos|search|settings|login|signup|home|explore|i|intent|share|hashtag|about|help|privacy|terms|search|r|user|u|watch|channel|c|p|reel|stories|groups|pages|events|marketplace|notifications|messages|status|api|v1|v2)$/i;
const ftKey = (k, v) => { v = String(v || '').trim(); if(k === 'social'){ const m = v.match(/^(?:https?:\/\/)?(?:www\.|m\.|mobile\.)?([^/\s]+)\/(?:@|user\/|u\/|in\/)?([^/?#]+)/i); if(!m || /^api\./i.test(m[1]) || FT_NOT_ACC.test(m[2])) return ''; return m[2].replace(/^@/, '').toLowerCase(); } return v.replace(/^@/, '').toLowerCase(); };
const ftPlat = v => { const h = (String(v).match(/^(?:https?:\/\/)?(?:www\.|m\.|mobile\.)?([^/\s]+)/i) || [])[1] || ''; return ({'github.com':'GitHub', 'reddit.com':'Reddit', 'x.com':'X / Twitter', 'twitter.com':'X / Twitter', 'instagram.com':'Instagram', 'tiktok.com':'TikTok', 't.me':'Telegram', 'youtube.com':'YouTube', 'facebook.com':'Facebook', 'linkedin.com':'LinkedIn', 'bsky.app':'Bluesky', 'mastodon.social':'Mastodon'})[h.toLowerCase()] || h; };
function footIndex(caseId){
  const sig = caseId + ':' + rev; if(FT_C.sig === sig) return FT_C.v;
  const D = derive(caseId), A = new Map();
  const acc = (key, base) => { let a = A.get(key); if(!a){ a = {key, handle:base.handle, platform:base.platform || '', kind:base.kind || 'handle', ids:new Set(), names:[], created:null, createdSrc:null, active:null, activeWhat:'', seen:[], ents:new Set(), extra:[]}; A.set(key, a); } if(base.platform && !a.platform) a.platform = base.platform; return a; };
  /* the accounts the evidence names */
  for(const e of D.ents.values()){ if(!/^(handle|social|email)$/.test(e.k)) continue; const k = ftKey(e.k, e.v); if(!k || k.length < 3 || (e.k !== 'email' && FT_NOT_ACC.test(k))) continue;
    const a = acc(k, {handle:e.k === 'social' ? k : e.v.replace(/^@/, ''), platform:e.k === 'social' ? ftPlat(e.v) : e.k === 'email' ? 'Email' : '', kind:e.k}); a.ents.add(e.id); for(const r of e.recs) if(r.ts && r.type !== 'lead') a.seen.push({ts:r.ts, rec:r.id}); }
  /* profiles pasted as JSON; dates and old names written in pages */
  const byId = new Map(), alias = new Map();   /* an old name points to the account it became */
  for(const r of D.recs){ if(r.type === 'lead' || !r.body) continue; const body = String(r.body).slice(0, 400000);
    for(const p of ftParseJson(body)){ const a = acc(p.handle.toLowerCase(), {handle:p.handle, platform:p.platform}); a.platform = p.platform; if(p.id) a.ids.add(p.platform + ':' + p.id);
      if(p.created && ftEarlier(p.created, a.created)){ a.created = p.created; a.createdSrc = {rec:r.id, how:p.platform + ' profile data'}; }
      if(p.active && (!a.active || p.active.ms > a.active.ms)){ a.active = p.active; a.activeWhat = p.activeWhat; } if(p.name && !a.names.some(n => n.v === p.name && n.display)) a.names.push({v:p.name, display:true, rec:r.id});
      for(const x of p.extra || []) if(!a.extra.includes(x)) a.extra.push(x); if(r.ts) a.seen.push({ts:r.ts, rec:r.id});
      if(p.id){ const k = p.platform + ':' + p.id; if(!byId.has(k)) byId.set(k, []); byId.get(k).push({handle:p.handle, rec:r, a}); } }
    if(/joined|member since|account created|registered|date joined|created|since|cake day|formerly|previously|aka|known as|changed/i.test(body)){
      /* which account a phrase is about: the nearest one named before it */
      const names = [...A.values()].map(a => a.handle.toLowerCase()).filter(h => h.length >= 3), low = body.toLowerCase();
      const near = i => { let best = null, at = -1; for(const h of names){ const j = low.lastIndexOf(h, i); if(j > at){ at = j; best = h; } } if(!best || i - at >= 600) return null; const a = A.get(best) || [...A.values()].find(x => x.handle.toLowerCase() === best); return alias.get(best) || a; };
      for(const re of FT_RENAME) for(const m of body.matchAll(re)){ const a = m[2] ? (A.get(m[2].toLowerCase()) || near(m.index)) : near(m.index); if(!a) continue; const old = m[1]; if(old.toLowerCase() === a.handle.toLowerCase()) continue; if(!a.names.some(n => n.v.toLowerCase() === old.toLowerCase())) a.names.push({v:old, old:true, rec:r.id, how:m[0].trim().slice(0, 80)}); alias.set(old.toLowerCase(), a); }
      for(const m of body.matchAll(FT_JOIN)){ const d = ftDate(m[1]), a = near(m.index); if(!d || !a || d.ms > Date.now() + 864e5 || d.ms < Date.UTC(1995, 0, 1)) continue; if(ftEarlier(d, a.created)){ a.created = d; a.createdSrc = {rec:r.id, how:'“' + m[0].trim() + '”'}; } } } }
  /* the same account number under different names */
  for(const [k, L] of byId){ const hs = [...new Set(L.map(x => x.handle))]; if(hs.length < 2) continue; const sorted = [...L].sort((x, y) => (x.rec.ts || 0) - (y.rec.ts || 0)), cur = sorted[sorted.length - 1].a;
    for(const x of sorted.slice(0, -1)) if(x.handle !== cur.handle && !cur.names.some(n => n.v === x.handle)) cur.names.push({v:x.handle, old:true, rec:x.rec.id, how:`same ${k.split(':')[0]} account number ${k.split(':').slice(1).join(':')}`, when:x.rec.ts});
    for(const x of sorted.slice(0, -1)) if(x.a !== cur && A.get(x.a.key) === x.a){ for(const s of x.a.seen) cur.seen.push(s); if(x.a.created && (!cur.created || x.a.created.ms < cur.created.ms)){ cur.created = x.a.created; cur.createdSrc = x.a.createdSrc; } A.delete(x.a.key); } }
  for(const [old, cur] of alias){ const o = A.get(old); if(o && o !== cur){ for(const x of o.seen) cur.seen.push(x); if(o.created && ftEarlier(o.created, cur.created) && !o.createdSrc){ cur.created = o.created; } A.delete(old); } }
  const L = [...A.values()].filter(a => a.created || a.seen.length || a.names.length).map(a => { const s = a.seen.map(x => x.ts).filter(Boolean).sort((x, y) => x - y); return {...a, first:s[0] || null, last:s[s.length - 1] || null, n:new Set(a.seen.map(x => x.rec)).size}; });
  /* what stands out — in the order the accounts were made */
  L.sort((x, y) => ((x.created && x.created.ms) || x.first || 9e15) - ((y.created && y.created.ms) || y.first || 9e15));
  const notes = [];
  for(const a of L){ if(a.created && a.first && a.first >= a.created.ms){ const d = (a.first - a.created.ms) / 864e5; if(d <= 30 && a.created.exact) notes.push({a, kind:'new', t:`${a.handle} was made ${d < 1 ? 'the same day' : Math.round(d) + ' day' + (Math.round(d) === 1 ? '' : 's')} before it first appears in your evidence`}); }
    if(a.names.some(n => n.old)) notes.push({a, kind:'renamed', t:`${a.handle} was called ${a.names.filter(n => n.old).map(n => n.v).join(', ')} before`}); }
  const made = L.filter(a => a.created && a.created.exact).sort((x, y) => x.created.ms - y.created.ms);
  for(let i = 0; i < made.length; i++){ const g = [made[i]]; for(let j = i + 1; j < made.length && made[j].created.ms - made[i].created.ms <= 7 * 864e5; j++) g.push(made[j]); if(g.length >= 2 && !notes.some(n => n.kind === 'together' && g.every(x => n.g.includes(x)))){ notes.push({kind:'together', g, t:`${g.map(x => x.handle).join(', ')} were made within ${Math.max(1, Math.round((g[g.length - 1].created.ms - g[0].created.ms) / 864e5))} day${Math.round((g[g.length - 1].created.ms - g[0].created.ms) / 864e5) > 1 ? 's' : ''} of each other`}); i += g.length - 1; } }
  const v = {accounts:L.sort((x, y) => ((x.created && x.created.ms) || x.first || 9e15) - ((y.created && y.created.ms) || y.first || 9e15)), notes}; FT_C.sig = sig; FT_C.v = v; return v;
}
const FT_C = {sig:'', v:null};
const ftWhen = d => !d ? '—' : d.year ? String(new Date(d.ms).getUTCFullYear()) : d.month ? new Date(d.ms).toLocaleString('en', {month:'long', year:'numeric', timeZone:'UTC'}) : E.fmtFull(d.ms, tz()).slice(0, 10);
function footSvg(X){
  const L = X.accounts.filter(a => a.created || a.first).slice(0, 40); if(!L.length) return '';
  /* labels: platform and handle, long ones shortened in the middle so both ends stay readable; the label column is as wide as the longest one needs */
  const lab = a => { const s = (a.platform ? a.platform + ' · ' : '') + a.handle; return s.length > 40 ? s.slice(0, 22) + '…' + s.slice(-15) : s; };
  const ts = L.flatMap(a => [a.created && a.created.ms, a.first, a.last, ...a.seen.map(s => s.ts)]).filter(Boolean), pad = 864e5 * 10, t0 = Math.min(...ts) - pad, t1 = Math.max(...ts, t0 + 864e5) + pad;
  const W = 1200, lw = Math.min(330, Math.max(120, Math.max(...L.map(a => lab(a).length)) * 7.4 + 16)), H = L.length * 30 + 44, x = t => lw + 14 + (t - t0) / (t1 - t0) * (W - lw - 34);
  const yr0 = new Date(t0).getUTCFullYear(), yr1 = new Date(t1).getUTCFullYear(), step = Math.max(1, Math.ceil((yr1 - yr0 + 1) / 10)), ticks = [];
  /* years when the span crosses one, else months; with only a year or two, months in between too */
  if(yr1 - yr0 >= 3) for(let y = yr0 + 1; y <= yr1; y += step) ticks.push([Date.UTC(y, 0, 1), String(y)]);
  else { const span = (t1 - t0) / (30 * 864e5), every = span > 18 ? 3 : span > 8 ? 2 : 1; for(let y = yr0; y <= yr1; y++) for(let mo = 0; mo < 12; mo += every){ const t = Date.UTC(y, mo, 1); if(t > t0 && t < t1) ticks.push([t, mo === 0 || !ticks.length ? new Date(t).toLocaleString('en', {month:'short', year:'numeric', timeZone:'UTC'}) : new Date(t).toLocaleString('en', {month:'short', timeZone:'UTC'})]); } }
  const rows = L.map((a, i) => { const y = 34 + i * 30, c = a.created ? a.created.ms : null, f = a.first, l = a.last || f;
    return `<text x="${lw}" y="${y + 4}" text-anchor="end" class="ft-l"><title>${esc((a.platform ? a.platform + ' · ' : '') + a.handle)}</title>${esc(lab(a))}</text>
      ${c != null && f != null && f > c ? `<line x1="${x(c)}" y1="${y}" x2="${x(f)}" y2="${y}" class="ft-pre"></line>` : ''}${f != null ? `<line x1="${x(f)}" y1="${y}" x2="${x(Math.max(l, f))}" y2="${y}" class="ft-on"></line>` : ''}
      ${a.seen.slice(0, 200).map(s => `<circle cx="${x(s.ts)}" cy="${y}" r="3" class="ft-d"></circle>`).join('')}
      ${c != null ? `<path d="M${x(c)},${y - 7} l7,7 l-7,7 l-7,-7z" class="ft-c${a.created.exact ? '' : ' approx'}"><title>${esc('Made ' + ftWhen(a.created))}</title></path>` : ''}`; }).join('');
  return `<div class="ft-svg" role="img" aria-label="One line per account: a diamond where it was made, dots where it appears in the evidence"><svg viewBox="0 0 ${W} ${H}" width="100%" preserveAspectRatio="xMinYMin meet">
    ${ticks.map(([t, l]) => `<line x1="${x(t)}" y1="16" x2="${x(t)}" y2="${H - 8}" class="ft-g"></line><text x="${x(t) + 3}" y="12" class="ft-t">${esc(l)}</text>`).join('')}${rows}</svg></div>`;
}
function footView(c){
  const X = footIndex(c.id);
  const head = `<div class="if-top"><p class="t2" style="margin:0">When each account in the case was made, when it shows up in your evidence, and what it was called before. Paste profile data (GitHub, Reddit, Mastodon, X/Twitter, YouTube or Bluesky JSON) or the text of a profile page; dates in captured pages (“Joined March 2019”) are read too.</p><button class="btn primary sm" data-act="ftPaste">${ico('plus','sm')}Paste a profile</button></div>`;
  const CH = typeof chView === 'function' ? chView(c) : '';
  if(!X.accounts.length) return head + empty('history', 'No accounts in this case yet', 'Handles, profile links and email addresses in your evidence, and profiles you paste, are laid out here on one timeline.') + CH;
  const src = s => s && s.rec ? `<button class="lnk small" data-act="tlxRec" data-id="${esc(s.rec)}">${esc(s.how || 'source')}</button>` : '';
  return `${head}<div class="if-sum card"><div class="tlx-kpi"><div><b>${X.accounts.length}</b><span>accounts</span></div><div><b>${X.accounts.filter(a => a.created).length}</b><span>with a creation date</span></div><div><b>${X.accounts.filter(a => a.names.some(n => n.old)).length}</b><span>renamed</span></div></div>${footSvg(X)}
      <p class="t3 small">◆ where the account was made (hollow: only the month or year is known), a thin line until it first appears in your evidence, then a thick line and a dot for each sighting.</p></div>
    ${X.notes.length ? `<section class="card if-c"><h3>What stands out</h3><ul class="if-l0">${X.notes.map(n => `<li class="if-g"><div class="if-gh"><span class="chip sq ${n.kind === 'renamed' ? '' : 'amber'}">${esc({new:'New account', renamed:'Renamed', together:'Made together'}[n.kind])}</span></div><div class="t2 small">${esc(n.t)}</div></li>`).join('')}</ul></section>` : ''}
    ${CH}<section class="card if-c"><h3>Accounts</h3><div class="if-tw"><table class="if-t"><thead><tr><th scope="col">Account</th><th scope="col">Made</th><th scope="col">In your evidence</th><th scope="col">Names</th></tr></thead><tbody>
      ${X.accounts.map(a => `<tr><td><b class="mono">${esc(a.handle)}</b><div class="t3 small">${esc(a.platform || ({handle:'Handle', social:'Profile', email:'Email'}[a.kind] || ''))}${a.ids.size ? ' · ' + esc([...a.ids].map(i => i.split(':').slice(1).join(':')).join(', ')) : ''}</div>${a.extra.length ? `<div class="t3 small">${a.extra.slice(0, 3).map(esc).join(' · ')}</div>` : ''}</td>
        <td class="mono">${esc(ftWhen(a.created))}${a.createdSrc ? `<div>${src(a.createdSrc)}</div>` : ''}${a.active ? `<div class="t3 small">${esc(a.activeWhat)}: ${esc(ftWhen(a.active))}</div>` : ''}</td>
        <td class="mono">${a.first ? esc(E.fmtFull(a.first, tz()).slice(0, 10)) + (a.last && a.last !== a.first ? ' – ' + esc(E.fmtFull(a.last, tz()).slice(0, 10)) : '') : '—'}<div class="t3 small">${a.n} piece${a.n === 1 ? '' : 's'} of evidence</div></td>
        <td>${a.names.length ? a.names.map(n => `<div><span class="${n.old ? 'mono' : ''}">${esc(n.v)}</span> <span class="t3 small">${n.old ? 'earlier name' : 'display name'}${n.how ? ' · ' + esc(n.how) : ''}</span></div>`).join('') : '<span class="t3">—</span>'}</td></tr>`).join('')}</tbody></table></div></section>`;
}
function footPasteDlg(){
  openDlg(dhead('Paste a profile') + `<form data-form="ftPaste"><div class="in">
    <div class="field"><label for="ftText">Profile <span class="t3">— JSON from GitHub, Reddit, Mastodon, X/Twitter, YouTube or Bluesky, or the text of a profile page</span></label><textarea id="ftText" rows="12" class="mono" spellcheck="false"></textarea><span class="hint" id="ftHint" aria-live="polite"></span></div></div>
    <footer><button class="btn" type="button" data-act="dclose">Cancel</button><button class="btn primary" type="submit">Add to the case</button></footer></form>`, true);
}
function footSubmit(){
  const t = String($('ftText').value || '').trim(); if(!t) return fieldErr('ftText', 'Paste the profile first.'); if(t.length > 2 << 20) return fieldErr('ftText', 'That is over 2 MB.');
  const P = ftParseJson(t), c = theCase(); if(/^\s*[\[{]/.test(t) && !P.length) return fieldErr('ftText', 'That JSON is not a profile from GitHub, Reddit, Mastodon, X/Twitter, YouTube or Bluesky.');
  if(DB.records.some(r => r.caseId === c.id && r.body === t)) return fieldErr('ftText', 'This exact profile is already in the case.');
  const title = P.length ? `${P[0].platform} profile — ${P[0].handle}${P.length > 1 ? ' and ' + (P.length - 1) + ' more' : ''}` : 'Profile page — ' + (t.split('\n')[0] || '').slice(0, 80);
  const r = {id:uid('r'), caseId:c.id, type:'evidence', title, body:t, tsRaw:new Date().toISOString(), tsZone:'explicit', ts:Date.now(), source:P.length ? 'profile:' + P[0].platform : 'profile page', host:'', tags:['profile'], ents:extractRich(t.slice(0, 200000)).slice(0, 2000), answer:'', addedBy:'You', addedAt:Date.now(), hash:''};
  if(P.length){ for(const p of P){ const h = '@' + p.handle; if(!r.ents.some(e => e.k === 'handle' && e.v.toLowerCase() === h.toLowerCase())) r.ents.push({k:'handle', v:h}); } }
  DB.records.push(r); closeDlg(); mutate('added a profile'); if(typeof hashRecords === 'function') hashRecords(); renderMain(); toast(P.length ? `${P[0].platform} profile added — made ${ftWhen(P[0].created)}` : 'Profile page added');
}
document.addEventListener('input', ev => { if(ev.target && ev.target.id === 'ftText'){ const h = $('ftHint'); if(!h) return; clearTimeout(UI.ftT); UI.ftT = setTimeout(() => { const P = ftParseJson(ev.target.value); h.textContent = P.length ? `Recognised: ${P[0].platform} profile of ${P[0].handle}, made ${ftWhen(P[0].created)}` : ev.target.value.trim() ? (/^\s*[\[{]/.test(ev.target.value) ? 'Not a profile format I know yet' : 'Page text — dates like “Joined March 2019” are read from it') : ''; }, 250); } });
const FT_ACTS = { ftPaste:() => footPasteDlg() };
