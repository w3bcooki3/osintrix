/* ==========================================================================
   Page changes over time (Infrastructure → Accounts → Changes over time).
   The same page or account saved more than once, each version set against
   the one before:
   · saved web pages (same address): title, description, text line by line,
     links and email addresses added and removed
   · profile data (same platform and account number, so a rename is still the
     same account): every field — name, handle, bio, location, links, picture,
     and counts such as followers with how much they moved
   · any two records, picked by hand
   Deleted text is often the point: what someone took down after being
   noticed. It is shown, struck through, with the version it was last in.
   ========================================================================== */
/* a saved page as the record keeps it → its parts */
function chPage(r){
  const b = String(r.body || ''), L = b.split('\n'), hd = {}; let i = 0;
  for(; i < L.length && L[i].trim(); i++){ const m = L[i].match(/^(URL|Title|Site|Author|Published|Saved|Description|SHA-256 of saved file):\s*(.*)$/); if(m) hd[m[1]] = m[2]; else break; }
  const rest = L.slice(i).join('\n'), cut = rest.search(/\n\nLinks to other sites \(\d+\):\n|\n\nEmail links:\n/), text = (cut >= 0 ? rest.slice(0, cut) : rest).trim();
  const lm = rest.match(/\n\nLinks to other sites \(\d+\):\n([\s\S]*?)(?:\n\nEmail links:\n|$)/), em = rest.match(/\n\nEmail links:\n([\s\S]*)$/);
  const links = lm ? lm[1].split('\n').map(x => (x.match(/(https?:\/\/\S+)\s*$/) || [])[1]).filter(Boolean) : [];
  return {url:hd.URL || (r.page && r.page.url) || '', title:hd.Title || '', desc:hd.Description || '', text, links, mails:em ? em[1].split('\n').map(s => s.trim()).filter(Boolean) : []};
}
const chUrlKey = u => { try{ const x = new URL(u); return (x.hostname.replace(/^www\.|^m\.|^mobile\./, '') + x.pathname.replace(/\/+$/, '') + (x.search || '')).toLowerCase(); }catch(e){ return ''; } };
/* profile data → flat fields worth comparing; API addresses and internal ids are left out, pictures kept */
const CH_SKIP = /(^|\.)(node_id|gravatar_id|etag|kind|id_str|_links|entities|status$|pinned_tweet_id|withheld|profile_link_color|profile_sidebar|profile_text_color|profile_background|profile_use|default_profile|translator|contributors|is_translat|notifications|following$|follow_request|has_extended|can_dm|can_media|want_retweets|lang$|time_zone$|utc_offset$|emojis|fields\.\d+\.verified_at|updated_at|last_status_at|tagged)/i;
const CH_LABEL = {name:'Name', login:'Username', username:'Username', screen_name:'Username', acct:'Username', handle:'Username', display_name:'Display name', displayName:'Display name', description:'Bio', bio:'Bio', note:'Bio', location:'Location', blog:'Website', website:'Website', url:'Address', html_url:'Profile address', email:'Email', company:'Company',
  followers:'Followers', followers_count:'Followers', following_count:'Following', friends_count:'Following', followersCount:'Followers', followsCount:'Following', public_repos:'Public repositories', public_gists:'Public gists', statuses_count:'Posts', postsCount:'Posts', tweet_count:'Posts', listed_count:'Listed', media_count:'Media', like_count:'Likes',
  avatar_url:'Picture', avatar:'Picture', profile_image_url:'Picture', profile_image_url_https:'Picture', icon_img:'Picture', banner:'Banner', header:'Banner', profile_banner_url:'Banner', verified:'Verified', locked:'Locked', protected:'Protected', bot:'Bot', hireable:'Open to work', twitter_username:'X username', link_karma:'Post karma', comment_karma:'Comment karma', total_karma:'Karma', created_at:'Created', createdAt:'Created', created_utc:'Created'};
/* text some platforms send as HTML (a Mastodon bio) → plain text */
const chText = v => /<\/?[a-z][^>]*>/i.test(v) ? v.replace(/<br\s*\/?>|<\/p>\s*<p>/gi, '\n').replace(/<[^>]+>/g, '').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'").trim() : v;
function chFlat(o){
  const out = new Map(); if(!o || typeof o !== 'object') return out; let n = 0;
  /* the profile itself, when it is wrapped: {data:{…}} (X, Reddit), [{…}] */
  if(Array.isArray(o)) o = o[0] || {}; if(o.data && typeof o.data === 'object' && !Array.isArray(o.data) && Object.keys(o).length <= 4) o = o.data;
  const walk = (x, p, d) => { if(n > 400 || d > 3) return;
    for(const [k, v] of Object.entries(x)){ const path = p ? p + '.' + k : k; if(CH_SKIP.test(path) || (/_url$/.test(k) && !/avatar|image|banner|html_url|^url$/.test(k))) continue;
      if(v == null || v === '') continue;
      if(typeof v === 'object' && !Array.isArray(v)){ walk(v, path, d + 1); continue; }
      if(Array.isArray(v)){ if(v.every(y => y == null || typeof y !== 'object')){ out.set(path, v.filter(y => y != null).map(String).join(', ').slice(0, 2000)); n++; }
        else if(/^fields$/.test(k)) v.slice(0, 10).forEach((f, i) => { if(f && f.name) { out.set(path + '.' + String(f.name).slice(0, 40), String(f.value || '').replace(/<[^>]+>/g, '').slice(0, 500)); n++; } }); continue; }
      out.set(path, chText(String(v)).slice(0, 4000)); n++; } };
  walk(o, '', 0); return out;
}
const chLabel = path => { const k = path.split('.').pop(); if(CH_LABEL[k]) return CH_LABEL[k]; if(/^fields\./.test(path.split('.').slice(-2).join('.'))) return 'Profile field “' + k + '”'; return k.replace(/_/g, ' ').replace(/([a-z])([A-Z])/g, '$1 $2').replace(/^./, c => c.toUpperCase()); };
/* line diff: longest common run (bounded), else set difference */
function chDiff(A, B){
  const a = A.slice(0, 4000), b = B.slice(0, 4000), n = a.length, m = b.length, out = [];
  if(n * m <= 4e6){ const W = m + 1, T = new Uint16Array((n + 1) * W);
    for(let i = n - 1; i >= 0; i--) for(let j = m - 1; j >= 0; j--) T[i * W + j] = a[i] === b[j] ? T[(i + 1) * W + j + 1] + 1 : Math.max(T[(i + 1) * W + j], T[i * W + j + 1]);
    let i = 0, j = 0; while(i < n && j < m){ if(a[i] === b[j]){ out.push(['=', a[i]]); i++; j++; } else if(T[(i + 1) * W + j] >= T[i * W + j + 1]) out.push(['-', a[i++]]); else out.push(['+', b[j++]]); }
    while(i < n) out.push(['-', a[i++]]); while(j < m) out.push(['+', b[j++]]); return out; }
  const sa = new Set(a), sb = new Set(b); for(const x of a) out.push([sb.has(x) ? '=' : '-', x]); for(const x of b) if(!sa.has(x)) out.push(['+', x]); return out;
}
const chLines = t => String(t || '').split('\n').map(s => s.trim()).filter(Boolean);
/* what changed between two versions → {fields:[{label, a, b, delta}], lines:[...], links:{add, del}, mails:{add, del}, n} */
function chCompare(ra, rb){
  const out = {fields:[], lines:[], links:{add:[], del:[]}, mails:{add:[], del:[]}, kind:''};
  let ja = null, jb = null; try{ ja = /^\s*[\[{]/.test(ra.body) ? JSON.parse(ra.body) : null; jb = /^\s*[\[{]/.test(rb.body) ? JSON.parse(rb.body) : null; }catch(e){ ja = jb = null; }
  if(ja && jb){ out.kind = 'data';
    const A = chFlat(ja), B = chFlat(jb), seen = new Set();
    for(const k of new Set([...A.keys(), ...B.keys()])){ const x = A.get(k), y = B.get(k); if(x === y) continue; const lab = chLabel(k), key = lab + '|' + x + '|' + y; if(seen.has(key)) continue; seen.add(key);
      const nx = x != null && /^-?\d+(\.\d+)?$/.test(x) ? +x : null, ny = y != null && /^-?\d+(\.\d+)?$/.test(y) ? +y : null;
      out.fields.push({label:lab, path:k, a:x, b:y, delta:nx != null && ny != null && !/created|id$/i.test(k) ? ny - nx : null}); }
    out.n = out.fields.length; return out; }
  out.kind = 'page'; const A = ra.page || /^URL: /.test(ra.body || '') ? chPage(ra) : {title:ra.title, desc:'', text:ra.body, links:[], mails:[]}, B = rb.page || /^URL: /.test(rb.body || '') ? chPage(rb) : {title:rb.title, desc:'', text:rb.body, links:[], mails:[]};
  if(A.title !== B.title) out.fields.push({label:'Title', a:A.title, b:B.title}); if(A.desc !== B.desc) out.fields.push({label:'Description', a:A.desc, b:B.desc});
  out.lines = chDiff(chLines(A.text), chLines(B.text));
  const la = new Set(A.links), lb = new Set(B.links); out.links = {add:B.links.filter(x => !la.has(x)), del:A.links.filter(x => !lb.has(x))};
  const ma = new Set(A.mails), mb = new Set(B.mails); out.mails = {add:B.mails.filter(x => !ma.has(x)), del:A.mails.filter(x => !mb.has(x))};
  out.n = out.fields.length + out.lines.filter(x => x[0] !== '=').length + out.links.add.length + out.links.del.length + out.mails.add.length + out.mails.del.length; return out;
}
/* every page and account in the case saved more than once, oldest first */
function chIndex(caseId){
  const sig = caseId + ':' + rev; if(CH_C.sig === sig) return CH_C.v;
  const G = new Map(), put = (k, label, r) => { if(!G.has(k)) G.set(k, {key:k, label, recs:[]}); G.get(k).recs.push(r); };
  for(const r of DB.records){ if(r.caseId !== caseId || r.type === 'lead' || !r.body) continue;
    if(r.page && r.page.url){ const k = chUrlKey(r.page.url); if(k) put('page:' + k, k, r); continue; }
    if(/^\s*[\[{]/.test(r.body)){ const P = ftParseJson(r.body); if(P.length === 1){ const p = P[0]; put('acct:' + p.platform + ':' + (p.id || p.handle.toLowerCase()), p.platform + ' · ' + p.handle, r); } } }
  const groups = [...G.values()].filter(g => g.recs.length >= 2).map(g => { const recs = g.recs.slice().sort((a, b) => (a.ts || a.addedAt || 0) - (b.ts || b.addedAt || 0));
    const steps = []; for(let i = 1; i < recs.length; i++) steps.push({a:recs[i - 1], b:recs[i], d:chCompare(recs[i - 1], recs[i])});
    /* the latest name for an account group */
    const last = ftParseJson(recs[recs.length - 1].body)[0]; return {...g, label:last ? last.platform + ' · ' + last.handle : g.label, recs, steps, n:steps.reduce((x, s) => x + s.d.n, 0)}; }).sort((x, y) => y.n - x.n);
  const v = {groups}; CH_C.sig = sig; CH_C.v = v; return v;
}
const CH_C = {sig:'', v:null};
const chWhen = r => r.ts ? E.fmtFull(r.ts, tz()).slice(0, 16) : '—';
const chNum = n => (n > 0 ? '+' : n < 0 ? '−' : '') + Math.abs(n).toLocaleString();
function chStep(s){
  const d = s.d, v = (x, cls) => x == null ? '<span class="t3">—</span>' : `<span class="${cls || ''}">${esc(x.length > 400 ? x.slice(0, 399) + '…' : x)}</span>`;
  const head = `<div class="pc-sh"><button class="lnk small" data-act="tlxRec" data-id="${esc(s.a.id)}">${esc(chWhen(s.a))}</button> → <button class="lnk small" data-act="tlxRec" data-id="${esc(s.b.id)}">${esc(chWhen(s.b))}</button><span class="t3 small">${d.n ? d.n + ' change' + (d.n === 1 ? '' : 's') : 'no change'}</span></div>`;
  if(!d.n) return head;
  const F = d.fields.length ? `<table class="pc-f"><tbody>${d.fields.map(f => `<tr><th scope="row">${esc(f.label)}</th><td>${v(f.a, 'pc-del')}</td><td class="pc-ar" aria-hidden="true">→</td><td>${v(f.b, 'pc-add')}${f.delta ? ` <span class="chip sq${Math.abs(f.delta) >= Math.max(100, Math.abs(+f.a || 0)) ? ' amber' : ''}">${chNum(f.delta)}</span>` : ''}</td></tr>`).join('')}</tbody></table>` : '';
  const ch = d.lines.filter(x => x[0] !== '='), ctx = [];
  if(ch.length){ let last = -9; d.lines.forEach((x, i) => { if(x[0] === '=') return; for(let k = Math.max(0, i - 1, last + 1); k < i; k++) if(d.lines[k][0] === '=') ctx.push(['~', d.lines[k][1], k]); if(i - last > 2 && ctx.length) ctx.push(['…', '', i]); ctx.push([x[0], x[1], i]); last = i; }); }
  const T = ch.length ? `<div class="pc-l" role="list" aria-label="Text added and removed">${ctx.slice(0, 300).map(([k, t]) => k === '…' ? '<div class="pc-gap" aria-hidden="true">⋯</div>' : `<div role="listitem" class="${k === '+' ? 'pc-add' : k === '-' ? 'pc-del' : 'pc-ctx'}"><span class="pc-k" aria-label="${k === '+' ? 'added' : k === '-' ? 'removed' : 'unchanged'}">${k === '+' ? '+' : k === '-' ? '−' : ''}</span>${esc(t.length > 600 ? t.slice(0, 599) + '…' : t)}</div>`).join('')}${ctx.length > 300 ? `<div class="t3 small">… and ${ctx.length - 300} more lines</div>` : ''}</div>` : '';
  const LK = (lbl, o) => o.add.length || o.del.length ? `<div class="pc-k2"><b>${lbl}</b> ${o.add.map(u => `<span class="pc-add mono">+ ${esc(u)}</span>`).join(' ')} ${o.del.map(u => `<span class="pc-del mono">− ${esc(u)}</span>`).join(' ')}</div>` : '';
  return head + F + T + LK('Links', d.links) + LK('Email addresses', d.mails);
}
function chView(c){
  const X = chIndex(c.id);
  const head = `<div class="pc-top"><h3>Changes over time</h3><span class="t3 small">${X.groups.length ? X.groups.length + ' page' + (X.groups.length === 1 ? '' : 's') + ' and account' + (X.groups.length === 1 ? '' : 's') + ' saved more than once' : 'Save the same page or profile again later, and what changed shows here'}</span><span style="flex:1"></span><button class="btn sm" data-act="chPick">${ico('git-compare','sm')}Compare two records</button></div>`;
  return `<section class="card if-c pc">${head}${X.groups.map(g => `<div class="pc-g"><div class="pc-gh"><b class="mono">${esc(g.label)}</b><span class="t3 small">${g.recs.length} versions · ${esc(chWhen(g.recs[0]))} to ${esc(chWhen(g.recs[g.recs.length - 1]))}</span></div>${g.steps.map(chStep).join('')}</div>`).join('')}</section>`;
}
function chPickDlg(){
  const rs = DB.records.filter(r => r.caseId === DB.active && r.type !== 'lead' && r.body).sort((a, b) => (a.ts || 0) - (b.ts || 0)), opt = sel => rs.map(r => `<option value="${esc(r.id)}"${r.id === sel ? ' selected' : ''}>${esc(chWhen(r) + ' — ' + r.title.slice(0, 90))}</option>`).join('');
  if(rs.length < 2) return toast('The case needs two records with text to compare');
  openDlg(dhead('Compare two records') + `<form data-form="chPick"><div class="in"><div class="field"><label for="chA">Earlier</label><select id="chA" class="inp">${opt(rs[rs.length - 2].id)}</select></div><div class="field"><label for="chB">Later</label><select id="chB" class="inp">${opt(rs[rs.length - 1].id)}</select></div><div id="chOut"></div></div>
    <footer><button class="btn" type="button" data-act="dclose">Close</button><button class="btn primary" type="submit">${ico('git-compare','sm')}Compare</button></footer></form>`, true);
  $('dlg').classList.add('xwide');
}
function chPickSubmit(){ const a = recById($('chA').value), b = recById($('chB').value); if(!a || !b) return; if(a === b) return fieldErr('chB', 'Pick two different records.');
  const [x, y] = (a.ts || 0) <= (b.ts || 0) ? [a, b] : [b, a]; $('chOut').innerHTML = `<div class="pc">${chStep({a:x, b:y, d:chCompare(x, y)})}</div>`; }
const PC_ACTS = { chPick:() => chPickDlg() };
