/* ==========================================================================
   CTF section: Challenges (board + a workspace per challenge with a work log),
   Write-ups (yours and imported Markdown), Cheatsheets and First moves.
   Builds on the tracker in lab.js (CTF_CATS, ensureCTF, ctfEditor, ctfSubmit).
   ========================================================================== */
const CTF_TABS = [['board', 'Challenges', 'flag'], ['writeups', 'Write-ups', 'scroll-text'], ['cheats', 'Cheatsheets', 'book-open'], ['first', 'First moves', 'list-checks']];
const CHEATS = () => typeof CTF_CHEATS !== 'undefined' ? CTF_CHEATS : {};
const LOG_KIND = {ok:['Worked', 'check'], no:['Dead end', 'x'], idea:['Idea', 'lightbulb'], note:['Note', 'pencil']};

function ensureCTF2(){
  ensureCTF(); const C = DB.ctf;
  if(!C.writeups){ C.writeups = [];
    const rot = C.chals.find(c => c.sample && c.name === 'Rot in peace'), who = C.chals.find(c => c.sample && c.name === 'Who registered it?');
    if(rot) C.writeups.push(wuMake({title:rot.name, cat:'crypto', event:'Sample CTF 2026', points:rot.points, chalId:rot.id, flag:rot.flag, sample:true, tools:'Decoder', lesson:'Recognise the alphabet before reaching for tools: letters only means a shift; = padding means base64.',
      tldr:'The text was ROT13, and under it a base64 string. Two Decoder steps gave the flag.',
      body:'## Steps\n\n1. **Recognise the encoding.** Only letters, spaces and a `{}` pair in the right place: a Caesar shift.\n2. **Undo ROT13.** The result ends in `==`, which is base64 padding.\n\n```\nDecoder → ROT13 → Base64 decode\n```\n\n3. **Decode base64** to get the flag.\n\n## Dead ends\n\n- Tried a Vigenère solver first; no key length stood out.'}));
    if(who) C.writeups.push(wuMake({title:who.name, cat:'osint', event:'Sample CTF 2026', points:who.points, chalId:who.id, flag:who.flag, sample:true, tools:'WHOIS history, crt.sh', lesson:'Privacy protection is often switched on late; history beats the current record.',
      tldr:'Current WHOIS was redacted, but a historical record from before privacy was enabled showed the registrant e-mail.',
      body:'## Steps\n\n1. **Look up the domain now.** Redacted by a privacy service.\n2. **Check WHOIS history.** The first record, from the day it was registered, still had the registrant e-mail.\n3. **Pivot on the e-mail.** The same address registered two more look-alike domains.\n\n```\ncurl -s "https://crt.sh/?q=%25.example&output=json" | jq -r ".[].name_value" | sort -u\n```\n\n## Dead ends\n\n- The certificate logs only showed the hostnames, not the owner.'}));
  }
  for(const c of C.chals){ if(!c.log) c.log = []; if(!c.firstDone) c.firstDone = []; }
}
function wuMake(o){ const now = Date.now(); return {id:uid('wu'), title:'Untitled write-up', cat:'misc', event:'', points:0, tldr:'', body:'', flag:'', tools:'', lesson:'', chalId:null, source:'mine', created:now, updated:now, ...o}; }

/* A small, safe Markdown renderer: everything is escaped first; only headings, lists, code, bold, italics and https links come back. */
function mdLite(src){
  const out = [], lines = String(src || '').replace(/\r/g, '').split('\n'); let i = 0, list = null;
  const inline = t => esc(t).replace(/`([^`]+)`/g, '<code>$1</code>').replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>').replace(/(^|\W)_([^_]+)_(?=\W|$)/g, '$1<i>$2</i>')
    .replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, (m, l, u) => `<a href="${u}" target="_blank" rel="noopener noreferrer">${l}</a>`);
  const close = () => { if(list){ out.push(`</${list}>`); list = null; } };
  const nextReal = j => { while(j < lines.length && !lines[j].trim()) j++; return lines[j] || ''; };
  while(i < lines.length){ const l = lines[i];
    if(/^\s*```/.test(l)){ const buf = []; i++; while(i < lines.length && !/^\s*```/.test(lines[i])) buf.push(lines[i++]); i++; const pre = `<pre class="md-code"><code>${esc(buf.join('\n'))}</code></pre>`;
      if(list && /<\/li>$/.test(out[out.length - 1])) out[out.length - 1] = out[out.length - 1].replace(/<\/li>$/, pre + '</li>'); else { close(); out.push(pre); } continue; }
    let m;
    if((m = l.match(/^(#{1,4})\s+(.*)/))){ close(); const n = Math.min(4, m[1].length + 1); out.push(`<h${n}>${inline(m[2])}</h${n}>`); }
    else if((m = l.match(/^\s*(\d+)[.)]\s+(.*)/))){ if(list !== 'ol'){ close(); out.push('<ol>'); list = 'ol'; } out.push(`<li>${inline(m[2])}</li>`); }
    else if((m = l.match(/^\s*[-*]\s+(.*)/))){ if(list !== 'ul'){ close(); out.push('<ul>'); list = 'ul'; } out.push(`<li>${inline(m[1])}</li>`); }
    else if(!l.trim()){ const nx = nextReal(i + 1); if(!(list && (/^\s*```/.test(nx) || (list === 'ol' ? /^\s*\d+[.)]\s/ : /^\s*[-*]\s/).test(nx)))) close(); }
    else { close(); out.push(`<p>${inline(l)}</p>`); }
    i++; }
  close(); return out.join('');
}

function viewCTF(){
  ensureCTF2();
  const tab = CTF_TABS.some(t => t[0] === UI.ctfTab) ? UI.ctfTab : 'board', C = DB.ctf;
  const cur = C.chals.find(c => c.id === UI.ctfSel);
  if(tab === 'board' && cur) return ctfWorkspace(cur);
  const counts = {board:C.chals.length, writeups:C.writeups.length, cheats:Object.keys(CHEATS()).length, first:Object.values(CHEATS()).filter(s => (s.first || []).length).length};
  const acts = tab === 'writeups' ? `<button class="btn" data-act="wuImport">${ico('upload','sm')}Import Markdown</button><button class="btn" data-act="wuExportAll"${C.writeups.length ? '' : ' disabled'}>${ico('download','sm')}Export all</button><button class="btn primary" data-act="wuNew">${ico('plus','sm')}New write-up</button>`
    : tab === 'board' ? `<button class="btn" data-act="ctfEvNew">${ico('flag','sm')}New event</button><button class="btn primary" data-act="ctfNew">${ico('plus','sm')}New challenge</button>` : '';
  const head = `<div class="ctf2-h"><div><h1>CTF</h1><p>Solve challenges with a work log, keep write-ups, and have the right cheatsheet open while you work.</p></div><div class="ctf2-acts">${acts}</div></div>
    <nav class="ctf2-tabs" aria-label="CTF">${CTF_TABS.map(([k, l, i]) => `<button data-act="ctfTab" data-v="${k}" aria-pressed="${tab === k}">${ico(i,'sm')}${l}<small>${counts[k]}</small></button>`).join('')}</nav>`;
  const body = tab === 'writeups' ? ctfWriteupsView() : tab === 'cheats' ? ctfCheatsView() : tab === 'first' ? ctfFirstView() : ctfBoard();
  return `<div class="scroll"><div class="page wide ctf2">${head}${body}</div></div>`;
}

function ctfBoard(){
  const C = DB.ctf, evId = UI.ctfEv && C.events.some(e => e.id === UI.ctfEv) ? UI.ctfEv : 'all', q = (UI.ctfq || '').toLowerCase(), cf = UI.ctfCat || '';
  const list = C.chals.filter(c => (evId === 'all' || c.eventId === evId) && (!cf || c.cat === cf) && (!q || (c.name + ' ' + c.notes + ' ' + c.flag + ' ' + c.log.map(x => x.text + ' ' + (x.cmd || '')).join(' ')).toLowerCase().includes(q)));
  const solved = list.filter(c => c.status === 'solved'), pts = solved.reduce((s, c) => s + (+c.points || 0), 0), total = list.reduce((s, c) => s + (+c.points || 0), 0);
  const byCat = countBy(list, c => c.cat);
  const card = c => { const [cn, col, ic] = ctfCat(c.cat), ev = C.events.find(e => e.id === c.eventId), cs = c.caseId ? theCase(c.caseId) : null, last = c.log[c.log.length - 1];
    return `<article class="chal${c.status === 'solved' ? ' done' : ''}" style="--c:${col}"><button class="gcard-hit" data-act="ctfSel" data-id="${c.id}" aria-label="Open ${esc(c.name)}"></button>
      <div class="chal-h"><span class="chal-ic">${ico(ic,'sm')}</span><span class="chal-cat">${esc(cn)}</span><span class="chal-pts">${esc(c.points || 0)} pts</span></div>
      <h3>${esc(c.name)}</h3>
      ${c.status === 'solved' && c.flag ? `<code class="chal-flag">${esc(c.flag)}</code>` : last ? `<p>${ico(LOG_KIND[last.kind] ? LOG_KIND[last.kind][1] : 'pencil','sm')} ${esc(last.text.slice(0, 120))}</p>` : c.notes ? `<p>${esc(c.notes.split('\n')[0])}</p>` : ''}
      <div class="chal-f">${evId === 'all' && ev ? `<span class="t3">${esc(ev.name)}</span>` : ''}${c.log.length ? `<span class="t3">· ${c.log.length} tr${c.log.length === 1 ? 'y' : 'ies'}</span>` : ''}${cs ? `<span class="chal-case" style="--cc:${esc(cs.color)}">${esc(cs.code)}</span>` : ''}</div></article>`; };
  return `<div class="ctf-sum">
      <div class="ctf-score"><div><b>${pts}</b><span>of ${total} points</span></div><div><b>${solved.length}/${list.length}</b><span>solved</span></div></div>
      <div class="ctf-cats">${Object.entries(CTF_CATS).filter(([k]) => byCat.some(([c]) => c === k)).map(([k, [n, col]]) => { const all = list.filter(c => c.cat === k), d = all.filter(c => c.status === 'solved').length;
        return `<button class="ctf-cat" data-act="ctfCat" data-v="${cf === k ? '' : k}" aria-pressed="${cf === k}" style="--c:${col}"><span>${esc(n)}</span><b>${d}/${all.length}</b><i><u style="width:${all.length ? Math.round(d / all.length * 100) : 0}%"></u></i></button>`; }).join('')}</div>
    </div>
    <div class="toolbar ltb"><div class="search-in">${ico('search')}<label class="sr" for="ctfq">Search challenges</label><input id="ctfq" class="inp" placeholder="Search challenges, notes, work logs, flags…" value="${esc(UI.ctfq || '')}"></div>
      <label class="sr" for="ctfEvSel">Event</label><select id="ctfEvSel" class="gsel bord"><option value="all">All events</option>${C.events.map(e => `<option value="${e.id}"${evId === e.id ? ' selected' : ''}>${esc(e.name)}</option>`).join('')}</select>
      ${evId !== 'all' ? `<button class="btn sm ghost" data-act="ctfEvEdit" data-id="${evId}">${ico('pencil','sm')}Event settings</button>` : ''}</div>
    ${list.length ? `<div class="kanban">${CTF_STATUS.map(([s, l, ic]) => { const col = list.filter(c => c.status === s).sort((a, b) => (b.points || 0) - (a.points || 0));
      return `<section class="kcol"><header>${ico(ic,'sm')}<h3>${l}</h3><span>${col.length}</span></header><div class="kcards">${col.map(card).join('') || '<p class="kempty">Nothing here.</p>'}</div></section>`; }).join('')}</div>`
      : empty('flag','No challenges yet','Add the challenges from your CTF or lab and keep a work log as you solve them.', `<button class="btn primary" data-act="ctfNew">${ico('plus','sm')}New challenge</button>`)}`;
}

const fmtFlag = re => String(re).replace(/\\/g, '').replace(/\[\^\}\]\+|\.\+\??|\.\*\??/g, '…');
function flagOk(c, flag){ const ev = DB.ctf.events.find(e => e.id === c.eventId), fmt = ev && ev.flagRe; if(!flag) return null;
  try{ const r = fmt ? new RegExp('^(?:' + fmt + ')$').test(flag) : new RegExp('^' + FLAG_RE.source + '$').test(flag); return r; }catch(e){ return null; } }

function ctfWorkspace(c){
  const C = DB.ctf, [cn, col, ic] = ctfCat(c.cat), ev = C.events.find(e => e.id === c.eventId), cs = c.caseId ? theCase(c.caseId) : null, S = CHEATS()[c.cat] || {};
  const st = CTF_STATUS.find(s => s[0] === c.status) || CTF_STATUS[0], wu = C.writeups.find(w => w.chalId === c.id);
  const ents = [...new Map(E.extract([c.notes, ...c.log.map(x => x.text + '\n' + (x.cmd || ''))].join('\n')).map(e => [e.k + ':' + e.v, e])).values()].slice(0, 16);
  const kind = UI.ctfKind || 'ok', flagNow = UI.ctfFlag != null && UI.ctfFlagFor === c.id ? UI.ctfFlag : c.flag, ok = flagOk(c, flagNow);
  const logRow = (x, i) => { const [kl, ki] = LOG_KIND[x.kind] || LOG_KIND.note;
    return `<div class="att"><span class="d ${x.kind}" title="${kl}">${ico(ki,'sm')}</span><p>${esc(x.text)}</p><span class="t">${esc(E.fmtClock(x.at, tz()).slice(0, 5))}<button class="iconbtn" data-act="ctfLogDel" data-v="${i}" aria-label="Remove this entry">${ico('x','sm')}</button></span>${x.cmd ? `<div class="code"><span class="p">$</span> ${esc(x.cmd)}</div>` : ''}</div>`; };
  return `<div class="scroll"><div class="page wide ctf2 ctfws">
    <div class="ctf2-h"><div><button class="btn ghost ctf-back" data-act="ctfBack">${ico('arrow-left','sm')}All challenges</button></div>
      <div class="ctf2-acts"><button class="btn" data-act="ctfEditOpen">${ico('pencil','sm')}Edit details</button>${wu ? `<button class="btn" data-act="wuOpen" data-id="${wu.id}">${ico('scroll-text','sm')}Open write-up</button>` : `<button class="btn primary" data-act="wuFromChal" data-id="${c.id}">${ico('scroll-text','sm')}Turn into write-up</button>`}</div></div>
    <div class="ws">
      <div class="col">
        <section class="card meta" style="--c:${col}"><span class="ws-cat"><i></i>${esc(cn)}${ev ? ' · ' + esc(ev.name) : ''}</span><h2>${esc(c.name)}</h2>
          <dl class="kv"><dt>Points</dt><dd class="mono">${esc(c.points || 0)}</dd><dt>Status</dt><dd><span class="ws-st ${c.status}">${ico(st[2],'sm')}${st[1]}</span></dd>
            <dt>Flag format</dt><dd class="mono">${esc(ev && ev.flagRe ? fmtFlag(ev.flagRe) : 'FLAG{…}')}</dd>
            <dt>Case</dt><dd>${cs ? `<a href="${caseHash(cs.id)}" class="mono">${esc(cs.code)}</a>` : `<button class="linkbtn" data-act="chCase" data-id="${c.id}">Create one</button>`}</dd></dl></section>
        <section class="card ws-notes"><label for="ctfNotes" class="ws-h">${ico('sticky-note','sm')}Notes</label><textarea id="ctfNotes" rows="7" placeholder="The challenge text, hints, anything worth keeping.">${esc(c.notes)}</textarea></section>
        ${ents.length ? `<section class="card ws-ents"><div class="ws-h">${ico('fingerprint','sm')}Found in this challenge</div><div class="ents">${ents.map(e => `<button class="ent" data-act="flagCopy" data-v="${esc(e.v)}" title="${esc((E.LABEL && E.LABEL[e.k]) || e.k)} · click to copy"><i style="--cc:var(--k-${esc(e.k)},var(--accent))"></i>${esc(e.v.length > 34 ? e.v.slice(0, 32) + '…' : e.v)}</button>`).join('')}</div></section>` : ''}
      </div>
      <section class="card log">
        <div class="loghd">${ico('terminal')}<h3>Work log</h3><span class="pill">${c.log.length} ${c.log.length === 1 ? 'entry' : 'entries'}</span><span class="sp"></span>${c.log.length ? `<button class="btn sm ghost" data-act="ctfLogCopy">${ico('copy','sm')}Copy as Markdown</button>` : ''}</div>
        <div class="logs">${c.log.length ? c.log.map(logRow).join('') : `<p class="log-empty">Record what you try as you go: the command, what happened, and whether it was a dead end. It becomes your write-up.</p>`}</div>
        <div class="compose"><label class="sr" for="ctfLogIn">New log entry</label><textarea id="ctfLogIn" rows="3" placeholder="What did you try, and what happened? Put a command on its own line starting with $"></textarea>
          <div class="row"><div class="seg" role="group" aria-label="Result">${Object.entries(LOG_KIND).map(([k, [l, i]]) => `<button type="button" data-act="ctfKind" data-v="${k}" aria-pressed="${kind === k}">${ico(i,'sm')}${l}</button>`).join('')}</div><span class="sp"></span><span class="t3 small"><kbd>Ctrl</kbd> <kbd>Enter</kbd></span><button class="btn primary sm" data-act="ctfLogAdd">Add to log</button></div></div>
      </section>
      <div class="col">
        <section class="card sug"><div class="ws-h">${ico('sparkles','sm')}First moves · ${esc(cn)}</div>
          ${(S.first || []).length ? `<ol class="fm">${S.first.map((f, i) => `<li class="${c.firstDone.includes(i) ? 'done' : ''}"><button class="cb" data-act="ctfFirst" data-v="${i}" aria-pressed="${c.firstDone.includes(i)}" aria-label="Done">${c.firstDone.includes(i) ? ico('check','sm') : ''}</button><span>${esc(f)}</span></li>`).join('')}</ol>` : '<p class="t3 small">No checklist for this category yet.</p>'}
          <button class="btn sm ghost ws-cs" data-act="ctfCheat" data-v="${esc(c.cat)}">${ico('book-open','sm')}Open the ${esc(cn)} cheatsheet</button></section>
        <section class="card flagbox2"><div class="ws-h">${ico('flag','sm')}Flag</div>
          <div class="flagin${ok ? ' ok' : ok === false ? ' bad' : ''}"><label class="sr" for="ctfFlagIn">Flag</label><input id="ctfFlagIn" class="mono" value="${esc(flagNow || '')}" placeholder="${esc(ev && ev.flagRe ? fmtFlag(ev.flagRe) : 'FLAG{…}')}" autocomplete="off" spellcheck="false">${ok ? ico('check','sm') : ''}</div>
          <p class="t3 small">${ok ? 'Matches the event’s flag format.' : ok === false ? 'Does not match the event’s flag format yet.' : 'Paste the flag to check its format.'}</p>
          ${c.status === 'solved' ? `<button class="btn" data-act="ctfReopen">${ico('undo-2','sm')}Reopen</button>` : `<button class="btn primary ws-solve" data-act="ctfSolve"${flagNow ? '' : ' disabled'}>${ico('trophy','sm')}Mark solved · +${esc(c.points || 0)}</button>`}</section>
      </div>
    </div></div></div>${UI.ctfEdit ? drawer(ctfEditor(c), 'ctfClose', c.name, ico(ic,'sm') + 'Challenge details') : ''}`;
}

/* ---------- write-ups ---------- */
function wuMarkdown(w){
  return [`# ${w.title}`, '', [w.event, ctfCat(w.cat)[0], w.points ? w.points + ' pts' : ''].filter(Boolean).join(' · '), '', w.tldr ? '**TL;DR** ' + w.tldr + '\n' : '', w.body, '',
    w.tools ? '**Tools:** ' + w.tools : '', w.lesson ? '**Lesson:** ' + w.lesson : '', w.flag ? '**Flag:** `' + w.flag + '`' : ''].filter(x => x !== '').join('\n');
}
function wuFromChal(c){
  const ok = c.log.filter(x => x.kind === 'ok'), dead = c.log.filter(x => x.kind === 'no'), ideas = c.log.filter(x => x.kind === 'idea');
  const steps = ok.map((x, i) => `${i + 1}. ${x.text}${x.cmd ? '\n\n```\n' + x.cmd + '\n```\n' : ''}`).join('\n');
  const tools = [...new Set(c.log.map(x => (x.cmd || '').trim().split(/\s+/)[0]).filter(t => /^[a-z][\w.-]{1,24}$/i.test(t)))].join(', ');
  const ev = DB.ctf.events.find(e => e.id === c.eventId);
  return wuMake({title:c.name, cat:c.cat, event:ev ? ev.name : '', points:c.points, chalId:c.id, flag:c.flag, tools, tldr:(c.notes || '').split('\n')[0].slice(0, 300),
    body:(steps ? '## Steps\n\n' + steps : '## Steps\n\n1. ') + (ideas.length ? '\n\n## Ideas that led there\n\n' + ideas.map(x => '- ' + x.text).join('\n') : '') + (dead.length ? '\n\n## Dead ends\n\n' + dead.map(x => '- ' + x.text + (x.cmd ? ' (`' + x.cmd + '`)' : '')).join('\n') : '')});
}
function ctfWriteupsView(){
  const C = DB.ctf, q = (UI.wuq || '').toLowerCase(), src = UI.wuSrc || 'all', cf = UI.wuCat || '';
  const words = q.split(/\s+/).filter(Boolean);
  const list = C.writeups.filter(w => (src === 'all' || w.source === src) && (!cf || w.cat === cf) && (!words.length || words.every(x => (w.title + ' ' + w.tldr + ' ' + w.body + ' ' + w.tools + ' ' + w.event).toLowerCase().includes(x))))
    .sort((a, b) => b.updated - a.updated);
  const cur = C.writeups.find(w => w.id === UI.wuSel) || list[0];
  const n = s => C.writeups.filter(w => w.source === s).length;
  const item = w => { const [cn, col] = ctfCat(w.cat); return `<button class="wcard${cur && cur.id === w.id ? ' on' : ''}" data-act="wuOpen" data-id="${w.id}" style="--cc:${col}"><span class="ws-cat"><i></i>${esc(cn)}</span><b>${esc(w.title)}</b>${w.tldr ? `<small>${esc(w.tldr.slice(0, 140))}</small>` : ''}<span class="m">${esc([w.event, w.source === 'imported' ? 'Imported' : 'Mine'].filter(Boolean).join(' · '))}</span></button>`; };
  let reader = '';
  if(cur && UI.wuEdit === cur.id) reader = `<form class="card reader wued" data-form="wu" data-id="${cur.id}">
      <div class="frow"><div class="field" style="flex:2"><label for="wuT">Title</label><input id="wuT" value="${esc(cur.title)}" required></div>
        <div class="field"><label for="wuC">Category</label><select id="wuC">${Object.entries(CTF_CATS).map(([k, [nm]]) => `<option value="${k}"${cur.cat === k ? ' selected' : ''}>${nm}</option>`).join('')}</select></div></div>
      <div class="frow"><div class="field" style="flex:2"><label for="wuE">Event</label><input id="wuE" value="${esc(cur.event)}"></div><div class="field"><label for="wuP">Points</label><input id="wuP" type="number" min="0" value="${esc(cur.points || 0)}"></div></div>
      <div class="field"><label for="wuL">TL;DR</label><input id="wuL" value="${esc(cur.tldr)}" placeholder="One or two sentences: what the trick was."></div>
      <div class="field"><label for="wuB">Write-up (Markdown)</label><textarea id="wuB" class="mono" rows="16">${esc(cur.body)}</textarea><span class="hint">Headings with #, lists, \`code\`, **bold** and fenced code blocks with \`\`\`.</span></div>
      <div class="frow"><div class="field"><label for="wuF">Flag</label><input id="wuF" class="mono" value="${esc(cur.flag)}"></div><div class="field"><label for="wuTo">Tools</label><input id="wuTo" value="${esc(cur.tools)}"></div></div>
      <div class="field"><label for="wuLe">Lesson</label><input id="wuLe" value="${esc(cur.lesson)}" placeholder="What you'd do first next time."></div>
      <div class="rx-f"><button type="button" class="btn ghost dangerhov" data-act="wuDel" data-id="${cur.id}">${ico('trash-2','sm')}Delete</button><span style="flex:1"></span><button type="button" class="btn" data-act="wuEditX">Cancel</button><button class="btn primary" type="submit">${ico('check','sm')}Save</button></div></form>`;
  else if(cur){ const [cn, col] = ctfCat(cur.cat), ch = cur.chalId && C.chals.find(c => c.id === cur.chalId);
    reader = `<article class="card reader">
      <div class="rmeta"><span class="ws-cat" style="--cc:${col}"><i></i>${esc(cn)}</span>${cur.event ? `<span class="pill">${esc(cur.event)}</span>` : ''}${cur.points ? `<span class="pill">${esc(cur.points)} pts</span>` : ''}${ch && ch.status === 'solved' ? `<span class="pill g">${ico('check','sm')}Solved</span>` : ''}${cur.source === 'imported' ? '<span class="pill">Imported</span>' : ''}
        <span class="sp"></span>${ch ? `<button class="btn sm" data-act="ctfSel" data-id="${ch.id}">${ico('flag','sm')}Challenge</button>` : ''}<button class="btn sm" data-act="wuEdit" data-id="${cur.id}">${ico('pencil','sm')}Edit</button><button class="btn sm" data-act="wuExport" data-id="${cur.id}">${ico('download','sm')}Markdown</button></div>
      <h2>${esc(cur.title)}</h2>
      ${cur.tldr ? `<div class="tldr"><b>TL;DR</b> ${esc(cur.tldr)}</div>` : ''}
      <div class="md">${mdLite(cur.body) || '<p class="t3">Nothing written yet. Use Edit to add the steps.</p>'}</div>
      ${cur.flag || cur.tools || cur.lesson ? `<div class="rfoot">${cur.flag ? `<div><span class="caps">Flag</span><span class="mono ${UI.wuShow === cur.id ? '' : 'blur'}">${esc(cur.flag)}</span> ${UI.wuShow === cur.id ? '' : `<button class="linkbtn" data-act="wuShow" data-id="${cur.id}">Show</button>`}</div>` : ''}${cur.tools ? `<div><span class="caps">Tools</span>${esc(cur.tools)}</div>` : ''}${cur.lesson ? `<div><span class="caps">Lesson</span>${esc(cur.lesson)}</div>` : ''}</div>` : ''}
    </article>`; }
  return `<div class="wl">
    <div class="wl-list"><div class="search-in">${ico('search')}<label class="sr" for="wuq">Search write-ups</label><input id="wuq" class="inp" placeholder="Search write-ups, tools, techniques…" value="${esc(UI.wuq || '')}"></div>
      <div class="filters">${[['all', 'All', C.writeups.length], ['mine', 'Mine', n('mine')], ['imported', 'Imported', n('imported')]].map(([k, l, c]) => `<button class="pbcat${src === k ? ' on' : ''}" data-act="wuSrc" data-v="${k}">${l}<small>${c}</small></button>`).join('')}
        <label class="sr" for="wuCatSel">Category</label><select id="wuCatSel" class="gsel bord"><option value="">Any category</option>${Object.entries(CTF_CATS).map(([k, [nm]]) => `<option value="${k}"${cf === k ? ' selected' : ''}>${nm}</option>`).join('')}</select></div>
      ${list.length ? list.map(item).join('') : `<p class="t3" style="padding:12px 4px">${C.writeups.length ? 'No write-ups match.' : 'No write-ups yet. Solve a challenge and turn its work log into one, or import Markdown.'}</p>`}</div>
    ${reader || `<div class="card reader">${empty('scroll-text', 'No write-up open', 'Pick one from the list, write a new one, or import a Markdown file.', `<button class="btn primary" data-act="wuNew">${ico('plus','sm')}New write-up</button>`)}</div>`}
  </div>`;
}
function wuSubmit(f){
  const w = DB.ctf.writeups.find(x => x.id === f.dataset.id); if(!w) return;
  const t = $('wuT').value.trim(); if(!t) return fieldErr('wuT', 'Title is required.');
  if(!checkLen('wuB', $('wuB').value, 100000, 'Write-up')) return;
  Object.assign(w, {title:t.slice(0, 160), cat:$('wuC').value, event:$('wuE').value.trim().slice(0, 120), points:Math.max(0, parseInt($('wuP').value, 10) || 0), tldr:$('wuL').value.trim().slice(0, 600),
    body:$('wuB').value.slice(0, 100000), flag:$('wuF').value.trim().slice(0, 400), tools:$('wuTo').value.trim().slice(0, 300), lesson:$('wuLe').value.trim().slice(0, 600), updated:Date.now()});
  UI.wuEdit = null; mutate('saved write-up ' + w.title); renderMain(); toast('Write-up saved');
}
function wuImport(){
  const i = document.createElement('input'); i.type = 'file'; i.accept = '.md,.markdown,.txt,text/markdown,text/plain'; i.multiple = true;
  i.onchange = async () => { let n = 0;
    for(const f of [...i.files].slice(0, 50)){ if(f.size > 1e6){ toast(f.name + ' is larger than 1 MB — skipped'); continue; }
      const txt = (await f.text()).replace(/\r/g, ''), h = txt.match(/^#\s+(.+)$/m), flag = (txt.match(FLAG_RE) || [])[0] || ''; FLAG_RE.lastIndex = 0;
      const low = txt.toLowerCase(), cat = Object.keys(CTF_CATS).find(k => new RegExp('\\b' + ctfCat(k)[0].toLowerCase() + '\\b').test(low.slice(0, 600))) || 'misc';
      DB.ctf.writeups.unshift(wuMake({title:(h ? h[1] : f.name.replace(/\.\w+$/, '')).trim().slice(0, 160), body:(h ? txt.replace(h[0], '') : txt).trim().slice(0, 100000), cat, flag, source:'imported'})); n++; }
    if(n){ UI.wuSel = DB.ctf.writeups[0].id; mutate('imported ' + n + ' write-ups'); renderMain(); toast(n + ' write-up' + (n > 1 ? 's' : '') + ' imported'); } };
  i.click();
}

/* ---------- cheatsheets ---------- */
/* ---------- cheatsheets: built for looking things up mid-CTF ----------
   One search across every category, one-line commands that copy on click, your own target and file
   names filled into every command, and the first-moves checklist always beside it. */
const CS_VARS = [['target', 'Target', 'target or 10.10.10.5'], ['file', 'File', 'chal.bin'], ['wordlist', 'Wordlist', 'rockyou.txt'], ['ip', 'Your IP', '$IP'], ['port', 'Port', '$PORT']];
const CS_RE = {target:/\btarget\b/g, file:/\b(?:file\.(?:png|jpg|jpeg|pdf|doc|docx|txt|b64|b32|bin|zip|wav|gif|bmp)|chal\.bin|mem\.raw|disk\.img|img\.(?:png|jpg))\b/g, wordlist:/\b(?:rockyou\.txt|wordlist\.txt)\b/g, ip:/\$IP\b/g, port:/\$PORT\b/g};
const csVars = () => (DB.ctf.vars || (DB.ctf.vars = {}));
/* Escape, then fill in (or highlight) the placeholders the user can change. */
function csCmd(cmd){
  const V = csVars(); let h = esc(cmd);
  for(const [k, re] of Object.entries(CS_RE)) h = h.replace(re, m => V[k] ? `<b class="csv on">${esc(V[k])}</b>` : `<b class="csv">${m}</b>`);
  return h;
}
const csFill = cmd => { const V = csVars(); let t = String(cmd); for(const [k, re] of Object.entries(CS_RE)) if(V[k]) t = t.replace(re, V[k]); return t; };
const csCatOf = k => { const S = CHEATS()[k] || {}; return [S.name || ctfCat(k)[0], ctfCat(k)[1]]; };
function csBody(){
  const S = CHEATS(), keys = Object.keys(CTF_CATS).filter(k => S[k]), cat = S[UI.csCat] ? UI.csCat : keys[0], C = S[cat];
  const q = (UI.csq || '').trim().toLowerCase(), words = q.split(/\s+/).filter(Boolean), has = t => words.every(w => String(t).toLowerCase().includes(w));
  const cmdRow = (k, [g, l, cmd], tag) => `<button class="csr" data-act="csCopy" data-v="${esc(cmd)}" title="Click to copy">${tag ? `<span class="cs-tag" style="--cc:${csCatOf(k)[1]}"><i></i>${esc(csCatOf(k)[0])}</span>` : ''}<span class="csr-l">${esc(l)}</span><code>${csCmd(cmd)}</code><span class="csr-c">${ico('copy','sm')}</span></button>`;
  const recRow = (k, [a, b, c], tag) => `<div class="csrec">${tag ? `<span class="cs-tag" style="--cc:${csCatOf(k)[1]}"><i></i>${esc(csCatOf(k)[0])}</span>` : ''}<code>${esc(a)}</code><b>${esc(b)}</b><span>${esc(c)}</span></div>`;
  if(words.length){
    const cmds = [], recs = [], gots = [];
    for(const k of keys){ for(const c of S[k].cmds || []) if(has(c.join(' ') + ' ' + S[k].name)) cmds.push([k, c]); for(const r of S[k].recog || []) if(has(r.join(' '))) recs.push([k, r]); for(const g of S[k].gotchas || []) if(has(g)) gots.push([k, g]); }
    if(!cmds.length && !recs.length && !gots.length) return `<div class="hx2-empty">Nothing matches “${esc(UI.csq)}” in any cheatsheet.</div>`;
    return `${cmds.length ? `<section class="cs-blk"><h3>${ico('terminal','sm')}Commands<small>${cmds.length}</small></h3><div class="csl">${cmds.slice(0, 80).map(([k, c]) => cmdRow(k, c, true)).join('')}</div></section>` : ''}
      ${recs.length ? `<section class="cs-blk"><h3>${ico('eye','sm')}Recognise it<small>${recs.length}</small></h3><div class="csl">${recs.slice(0, 60).map(([k, r]) => recRow(k, r, true)).join('')}</div></section>` : ''}
      ${gots.length ? `<section class="cs-blk"><h3>${ico('lightbulb','sm')}Gotchas<small>${gots.length}</small></h3><ul class="cs-got">${gots.map(([k, g]) => `<li><span class="cs-tag" style="--cc:${csCatOf(k)[1]}"><i></i>${esc(csCatOf(k)[0])}</span>${esc(g)}</li>`).join('')}</ul></section>` : ''}`;
  }
  const view = ['cmds', 'recog', 'gotchas'].includes(UI.csView) ? UI.csView : 'cmds', groups = [...new Set((C.cmds || []).map(c => c[0]))], grp = groups.includes(UI.csGrp) ? UI.csGrp : '';
  const seg = `<div class="seg cs-view" role="group" aria-label="Show">${[['cmds', 'Commands', 'terminal', (C.cmds || []).length], ['recog', 'Recognise it', 'eye', (C.recog || []).length], ['gotchas', 'Gotchas', 'lightbulb', (C.gotchas || []).length]].map(([k, l, i, n]) => `<button data-act="csView" data-v="${k}" aria-pressed="${view === k}">${ico(i,'sm')}${l}<small>${n}</small></button>`).join('')}</div>`;
  let body = '';
  if(view === 'cmds') body = `<div class="cs-groups">${['', ...groups].map(g => `<button class="rf3-s${grp === g ? ' on' : ''}" data-act="csGrp" data-v="${esc(g)}">${g ? esc(g) : 'All'}<small>${g ? C.cmds.filter(c => c[0] === g).length : C.cmds.length}</small></button>`).join('')}</div>
      <div class="csl">${(grp ? [grp] : groups).map(g => `${grp ? '' : `<div class="csl-h">${esc(g)}</div>`}${C.cmds.filter(c => c[0] === g).map(c => cmdRow(cat, c)).join('')}`).join('')}</div>`;
  else if(view === 'recog') body = `<div class="csl"><div class="csrec hd"><span>You see</span><span>It is probably</span><span>Try</span></div>${(C.recog || []).map(r => recRow(cat, r)).join('')}</div>`;
  else body = `<ul class="cs-got big">${(C.gotchas || []).map(g => `<li>${esc(g)}</li>`).join('')}</ul>`;
  return `<div class="cs-bar">${seg}<p class="cs-blurb">${esc(C.blurb || '')}</p></div>${body}`;
}
function csSide(){
  const S = CHEATS(), keys = Object.keys(CTF_CATS).filter(k => S[k]), cat = S[UI.csCat] ? UI.csCat : keys[0], C = S[cat], done = (DB.ctf.fm || {})[cat] || [];
  return `<section class="card fmc"><div class="ws-h">${ico('list-checks','sm')}First moves<span class="sp"></span>${done.length ? `<button class="linkbtn" data-act="csFmReset">Reset</button>` : ''}<span class="t3 small">${done.length}/${(C.first || []).length}</span></div>
      <ol class="fm">${(C.first || []).map((f, i) => `<li class="${done.includes(i) ? 'done' : ''}"><button class="cb" data-act="csFm" data-v="${i}" aria-pressed="${done.includes(i)}" aria-label="Done">${done.includes(i) ? ico('check','sm') : ''}</button><span>${esc(f)}</span></li>`).join('')}</ol></section>`;
}
function ctfCheatsView(){
  const S = CHEATS(), keys = Object.keys(CTF_CATS).filter(k => S[k]);
  if(!keys.length) return empty('book-open', 'Cheatsheets are not loaded', 'The cheatsheet data file is missing from this copy of OSINTrix.');
  const cat = S[UI.csCat] ? UI.csCat : keys[0], V = csVars(), searching = !!(UI.csq || '').trim();
  const n = k => (S[k].cmds || []).length + (S[k].recog || []).length;
  return `<div class="cs3">
    <aside class="cs3-rail" aria-label="Categories"><div class="cs3-rh">Categories</div>${keys.map(k => `<button data-act="ctfCheat" data-v="${k}" class="${!searching && k === cat ? 'on' : ''}" style="--cc:${ctfCat(k)[1]}"><span class="cs3-ic">${ico(ctfCat(k)[2],'sm')}</span><span class="cs3-l">${esc(S[k].name || ctfCat(k)[0])}</span><small>${n(k)}</small></button>`).join('')}</aside>
    <div class="cs3-main">
      <div class="cs-tools">
        <div class="search-in cs-q">${ico('search')}<label class="sr" for="csq">Search every cheatsheet</label><input id="csq" class="inp" placeholder="Search all cheatsheets — steghide, ==, jwt, 89 50 4E 47, rop…" value="${esc(UI.csq || '')}" autocomplete="off">${UI.csq ? `<button class="iconbtn" data-act="csClear" aria-label="Clear">${ico('x','sm')}</button>` : '<kbd>/</kbd>'}</div>
        <div class="cs-vars" role="group" aria-label="Your values"><span class="t3 small">Fill in</span>${CS_VARS.map(([k, l, ph]) => `<label class="csvar${V[k] ? ' set' : ''}"><span>${l}</span><input data-csvar="${k}" value="${esc(V[k] || '')}" placeholder="${esc(ph)}" autocomplete="off" spellcheck="false"></label>`).join('')}</div>
      </div>
      <div class="cs-grid"><div class="cs-main" id="csBody">${csBody()}</div><aside class="cs-side" id="csSide">${csSide()}</aside></div>
    </div>
  </div>`;
}
function ctfFirstView(){
  const S = CHEATS(), keys = Object.keys(CTF_CATS).filter(k => S[k] && (S[k].first || []).length);
  if(!keys.length) return empty('list-checks', 'No checklists loaded', 'The cheatsheet data file is missing from this copy of OSINTrix.');
  return `<p class="t2 fm-intro">What to do in the first ten minutes of a new challenge, by category. Open a challenge to tick these off as you go.</p>
    <div class="fmgrid">${keys.map(k => `<section class="card fmc" style="--cc:${ctfCat(k)[1]}"><div class="ws-h"><span class="ws-cat"><i></i>${esc(S[k].name || ctfCat(k)[0])}</span><span class="sp"></span><button class="linkbtn" data-act="ctfCheat" data-v="${k}">Cheatsheet</button></div><ol class="fm plain">${S[k].first.map(f => `<li><span>${esc(f)}</span></li>`).join('')}</ol></section>`).join('')}</div>`;
}

/* ---------- actions ---------- */
function ctfAddLog(){
  const c = DB.ctf.chals.find(x => x.id === UI.ctfSel), t = $('ctfLogIn'); if(!c || !t) return;
  const raw = t.value.trim(); if(!raw) return toast('Write what you tried first');
  const lines = raw.split('\n'), cmd = lines.filter(l => /^\s*\$\s?/.test(l)).map(l => l.replace(/^\s*\$\s?/, '')).join('\n'), text = lines.filter(l => !/^\s*\$\s?/.test(l)).join(' ').trim();
  c.log.push({at:Date.now(), kind:UI.ctfKind || 'ok', text:(text || (cmd ? 'Ran a command' : '')).slice(0, 4000), cmd:cmd.slice(0, 4000)});
  if(c.status === 'todo') c.status = 'working';
  mutate('work log on ' + c.name); renderMain(); const n = $('ctfLogIn'); if(n) n.focus(); const l = document.querySelector('.logs'); if(l) l.scrollTop = l.scrollHeight;
}
const CTF2_ACTS = {
  ctfTab:(id, v) => { UI.ctfTab = v; if(v !== 'board') UI.ctfSel = null; renderMain(); },
  ctfBack:() => { UI.ctfSel = null; UI.ctfEdit = false; renderMain(); },
  ctfEditOpen:() => { UI.ctfEdit = true; renderMain(); },
  ctfKind:(id, v, t) => { UI.ctfKind = v; t.parentElement.querySelectorAll('button').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.v === v))); },
  ctfLogAdd:() => ctfAddLog(),
  ctfLogDel:(id, v) => { const c = DB.ctf.chals.find(x => x.id === UI.ctfSel); if(!c) return; const [x] = c.log.splice(+v, 1); mutate('removed log entry'); renderMain();
    toast('Entry removed', 'Undo', () => { c.log.splice(+v, 0, x); mutate('restored log entry'); renderMain(); }); },
  ctfLogCopy:() => { const c = DB.ctf.chals.find(x => x.id === UI.ctfSel); if(c) copyText(c.log.map(x => `- ${(LOG_KIND[x.kind] || LOG_KIND.note)[0]}: ${x.text}${x.cmd ? '\n  `' + x.cmd + '`' : ''}`).join('\n')); },
  ctfFirst:(id, v) => { const c = DB.ctf.chals.find(x => x.id === UI.ctfSel); if(!c) return; const i = +v; c.firstDone = c.firstDone.includes(i) ? c.firstDone.filter(x => x !== i) : [...c.firstDone, i]; mutate('checklist'); renderMain(); },
  csCopy:(id, v) => copyText(csFill(v)),
  csView:(id, v) => { UI.csView = v; const b = $('csBody'); if(b) b.innerHTML = csBody(); },
  csGrp:(id, v) => { UI.csGrp = v; const b = $('csBody'); if(b) b.innerHTML = csBody(); },
  csClear:() => { UI.csq = ''; renderMain(); refocus('csq'); },
  csFm:(id, v) => { const cat = CHEATS()[UI.csCat] ? UI.csCat : Object.keys(CTF_CATS).find(k => CHEATS()[k]); DB.ctf.fm = DB.ctf.fm || {}; const d = DB.ctf.fm[cat] || [], i = +v;
    DB.ctf.fm[cat] = d.includes(i) ? d.filter(x => x !== i) : [...d, i]; save(); const s2 = $('csSide'); if(s2) s2.innerHTML = csSide(); },
  csFmReset:() => { const cat = CHEATS()[UI.csCat] ? UI.csCat : Object.keys(CTF_CATS).find(k => CHEATS()[k]); if(DB.ctf.fm) delete DB.ctf.fm[cat]; save(); const s2 = $('csSide'); if(s2) s2.innerHTML = csSide(); },
  ctfCheat:(id, v) => { UI.csCat = v; UI.csq = ''; UI.csGrp = ''; UI.ctfTab = 'cheats'; UI.ctfSel = null; renderMain(); const s = document.querySelector('#main .scroll'); if(s) s.scrollTop = 0; },
  ctfSolve:() => { const c = DB.ctf.chals.find(x => x.id === UI.ctfSel), f = $('ctfFlagIn'); if(!c || !f || !f.value.trim()) return;
    c.flag = f.value.trim().slice(0, 400); c.status = 'solved'; c.solvedAt = Date.now(); UI.ctfFlag = null; mutate('solved ' + c.name); renderMain(); toast('Solved — nice work', 'Write it up', () => CTF2_ACTS.wuFromChal(c.id)); },
  ctfReopen:() => { const c = DB.ctf.chals.find(x => x.id === UI.ctfSel); if(!c) return; c.status = 'working'; c.solvedAt = 0; mutate('reopened ' + c.name); renderMain(); },
  wuFromChal:id => { const c = DB.ctf.chals.find(x => x.id === id); if(!c) return; const w = wuFromChal(c); DB.ctf.writeups.unshift(w); UI.wuSel = w.id; UI.wuEdit = w.id; UI.ctfTab = 'writeups'; UI.ctfSel = null; mutate('draft write-up ' + c.name); renderMain(); },
  wuNew:() => { const w = wuMake({}); DB.ctf.writeups.unshift(w); UI.wuSel = w.id; UI.wuEdit = w.id; UI.ctfTab = 'writeups'; mutate('new write-up'); renderMain(); setTimeout(() => { const x = $('wuT'); if(x){ x.focus(); x.select(); } }, 50); },
  wuOpen:id => { UI.wuSel = id; UI.wuEdit = null; UI.ctfTab = 'writeups'; UI.ctfSel = null; renderMain(); },
  wuEdit:id => { UI.wuEdit = id; renderMain(); },
  wuEditX:() => { UI.wuEdit = null; renderMain(); },
  wuShow:id => { UI.wuShow = id; renderMain(); },
  wuSrc:(id, v) => { UI.wuSrc = v; renderMain(); },
  wuDel:id => { const C = DB.ctf, i = C.writeups.findIndex(x => x.id === id); if(i < 0) return; const [w] = C.writeups.splice(i, 1); UI.wuEdit = null; UI.wuSel = null; mutate('deleted write-up'); renderMain();
    toast('Write-up deleted', 'Undo', () => { C.writeups.splice(i, 0, w); mutate('restored write-up'); renderMain(); }); },
  wuExport:id => { const w = DB.ctf.writeups.find(x => x.id === id); if(w) download(slug(w.title) + '.md', wuMarkdown(w), 'text/markdown'); },
  wuExportAll:() => download('ctf-writeups.md', DB.ctf.writeups.map(wuMarkdown).join('\n\n---\n\n'), 'text/markdown'),
  wuImport:() => wuImport()
};
document.addEventListener('input', ev => { const t = ev.target;
  if(t.id === 'ctfNotes'){ const c = DB.ctf && DB.ctf.chals.find(x => x.id === UI.ctfSel); if(!c) return; c.notes = t.value.slice(0, 20000); clearTimeout(t._s); t._s = setTimeout(() => mutate('notes on ' + c.name), 600); }
  else if(t.id === 'ctfFlagIn'){ const c = DB.ctf.chals.find(x => x.id === UI.ctfSel); if(!c) return; UI.ctfFlag = t.value; UI.ctfFlagFor = c.id; const ok = flagOk(c, t.value.trim()), box = t.parentElement;
    box.classList.toggle('ok', !!ok); box.classList.toggle('bad', ok === false); const p = box.nextElementSibling; if(p) p.textContent = ok ? 'Matches the event’s flag format.' : ok === false ? 'Does not match the event’s flag format yet.' : 'Paste the flag to check its format.';
    const b = document.querySelector('.ws-solve'); if(b) b.disabled = !t.value.trim(); }
  else if(t.id === 'csq'){ UI.csq = t.value; clearTimeout(ctfQT); ctfQT = setTimeout(() => { const b = $('csBody'); if(b) b.innerHTML = csBody();
      document.querySelectorAll('.cs3-rail button').forEach(x => x.classList.toggle('on', !t.value.trim() && x.dataset.v === (CHEATS()[UI.csCat] ? UI.csCat : Object.keys(CTF_CATS).find(k => CHEATS()[k])))); }, 120); }
  else if(t.dataset && t.dataset.csvar){ const V = csVars(); V[t.dataset.csvar] = t.value.trim().slice(0, 200); t.parentElement.classList.toggle('set', !!V[t.dataset.csvar]); clearTimeout(ctfQT);
    ctfQT = setTimeout(() => { save(); const b = $('csBody'); if(b) b.innerHTML = csBody(); }, 120); }
  else if(t.id === 'wuq'){ UI[t.id] = t.value; clearTimeout(ctfQT); ctfQT = setTimeout(() => { renderMain(); refocus(t.id); }, 160); }
});
let ctfQT = null;
document.addEventListener('change', ev => { if(ev.target.id === 'wuCatSel'){ UI.wuCat = ev.target.value; renderMain(); } });
document.addEventListener('keydown', ev => { if(ev.target.id === 'ctfLogIn' && ev.key === 'Enter' && (ev.ctrlKey || ev.metaKey)){ ev.preventDefault(); ctfAddLog(); } });
