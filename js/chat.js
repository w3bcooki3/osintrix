/* ==========================================================================
   Chat exports — Telegram Desktop (result.json) and DiscordChatExporter (JSON)
   Read into one record per author: their messages with times, and their
   account number — Telegram's user ID and Discord's ID stay the same when a
   name or username changes, so they tie an author across chats and cases.
   The post times go to Active hours; the texts can be compared for writing
   style; wallets, links, onions and handles in them are picked out as usual.
   ========================================================================== */
const CHAT_MAX_AUTH = 300, CHAT_MAX_CHARS = 200000;
const chatText = t => typeof t === 'string' ? t : Array.isArray(t) ? t.map(x => typeof x === 'string' ? x : x && typeof x.text === 'string' ? x.text : '').join('') : '';
function chatParse(text){
  let o; try{ o = JSON.parse(String(text).replace(/^﻿/, '')); }catch(e){ return null; } if(!o || typeof o !== 'object' || !Array.isArray(o.messages)) return null;
  const msgs = [];
  if(o.messages.some(m => m && (m.date_unixtime || m.date) && ('from' in m || 'from_id' in m))){
    for(const m of o.messages){ if(!m || m.type !== 'message') continue; const t = m.date_unixtime ? +m.date_unixtime * 1000 : Date.parse(m.date); if(!isFinite(t)) continue;
      const id = /^user(\d{1,15})$/.exec(String(m.from_id || '')), ch = /^channel(\d{1,15})$/.exec(String(m.from_id || ''));
      const fid = /^(?:channel|user|chat)(\d{1,15})$/.exec(String(m.forwarded_from_id || '')), links = (chatText(m.text).match(/\bt(?:elegram)?\.me\/(?:s\/)?([A-Za-z][\w]{3,31})/g) || []).map(x => x.replace(/^.*\//, '').toLowerCase());
      msgs.push({t, who:String(m.from || m.author || (ch ? o.name : '') || 'Deleted account').slice(0, 80), wid:id ? id[1] : '', chan:!!ch, text:chatText(m.text).slice(0, 8000), fwd:m.forwarded_from ? String(m.forwarded_from).slice(0, 120) : '', fwdId:fid ? fid[1] : '', links}); }
    return {app:'Telegram', chat:String(o.name || 'Saved chat').slice(0, 120), kind:String(o.type || '').replace(/_/g, ' '), cid:o.id != null ? String(o.id).slice(0, 20) : '', msgs};
  }
  if(o.messages.some(m => m && m.timestamp && m.author)){
    for(const m of o.messages){ if(!m || !m.author) continue; const t = Date.parse(m.timestamp); if(!isFinite(t)) continue;
      const ref = m.reference && m.reference.guildId && m.reference.guildId !== (o.guild && o.guild.id) ? 'server ' + m.reference.guildId : '';
      msgs.push({t, who:String(m.author.nickname || m.author.name || m.author.id || '?').slice(0, 80), wid:/^\d{15,20}$/.test(String(m.author.id || '')) ? String(m.author.id) : '', uname:m.author.name ? String(m.author.name).slice(0, 40) : '', text:String(m.content || '').slice(0, 8000), fwd:ref, fwdId:'', links:(String(m.content || '').match(/\bdiscord(?:\.gg|\.com\/invite)\/([\w-]{2,32})/gi) || []).map(x => 'invite/' + x.replace(/^.*\//, ''))}); }
    return {app:'Discord', chat:[o.guild && o.guild.name, o.channel && o.channel.name && '#' + o.channel.name].filter(Boolean).join(' ') || 'Saved channel', kind:o.channel && o.channel.type ? String(o.channel.type) : '', cid:o.channel && o.channel.id ? String(o.channel.id).slice(0, 20) : '', msgs};
  }
  return null;
}
/* is this file a chat export? A look at its start is enough */
async function isChatExport(f){ if(!/\.json$/i.test(f.name || '') || f.size > 200 * 1048576) return false; const head = await f.slice(0, 6000).text();
  return /"messages"\s*:/.test(head) && (/"date_unixtime"|"from_id"/.test(head) || (/"author"\s*:/.test(head) && /"timestamp"\s*:/.test(head)) || /"type"\s*:\s*"(personal_chat|private_group|public_channel|private_channel|public_supergroup|private_supergroup|saved_messages)"/.test(head)); }
/* a message's fingerprint: the same words, however spaced or capitalised, give the same value; short messages ("ok", "thanks") give none */
function chatFp(t){ const s = String(t || '').toLowerCase().replace(/https?:\/\/\S+/g, ' ').replace(/[^\p{L}\p{N}]+/gu, ' ').trim(); if(s.length < 30) return '';
  let h1 = 0x811c9dc5, h2 = 0x1000193; for(let i = 0; i < s.length; i++){ const c = s.charCodeAt(i); h1 = Math.imul(h1 ^ c, 16777619); h2 = Math.imul(h2 + c, 2246822519) ^ (h2 >>> 13); } return (h1 >>> 0).toString(36) + (h2 >>> 0).toString(36); }
const chatDay = t => new Date(t).toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
function chatRecords(P, cid, fname){
  const by = new Map(); for(const m of P.msgs){ const k = m.wid || 'name:' + m.who; if(!by.has(k)) by.set(k, []); by.get(k).push(m); }
  const authors = [...by.entries()].sort((a, b) => b[1].length - a[1].length), recs = [], idLabel = P.app === 'Telegram' ? 'Telegram user ID' : 'Discord user ID', now = Date.now();
  const base = r => ({id:uid('r'), caseId:cid, type:'evidence', tsZone:'explicit', host:'', answer:'', addedBy:'You', addedAt:now, hash:'', ...r});
  for(const [k, L] of authors.slice(0, CHAT_MAX_AUTH)){ const a = L[L.length - 1], first = L[0].t, last = L[L.length - 1].t; let body = '', n = 0;
    const nm = new Map(); for(const m of L){ const key = m.who + '\u0000' + (m.uname || ''); const x = nm.get(key); if(x) x[1] = m.t; else nm.set(key, [m.t, m.t]); }
    const names = [...nm.entries()].map(([key, [f, l]]) => ({name:key.split('\u0000')[0], uname:key.split('\u0000')[1], first:f, last:l})).sort((x, y) => x.first - y.first);
    const head = [`Chat: ${P.chat}${P.kind ? ' (' + P.app + ' ' + P.kind + ')' : ' (' + P.app + ')'}`, `Author: ${a.who}${a.uname && a.uname !== a.who ? ' (' + a.uname + ')' : ''}`, a.wid ? `${idLabel}: ${a.wid}` + (P.app === 'Discord' && typeof dcCreated === 'function' && dcCreated(a.wid) ? `\nDiscord account created: ${new Date(dcCreated(a.wid)).toISOString().slice(0, 16).replace('T', ' ')} UTC (${typeof fxAgo === 'function' ? fxAgo(first - dcCreated(a.wid)) : ''} before the first message here)` : '') : (a.chan ? 'Posted as the channel' : 'No account number in the export'), `Messages: ${L.length.toLocaleString()}, ${chatDay(first)} to ${chatDay(last)}`, ''].join('\n');
    for(const m of L){ if(!m.text.trim()) continue; const line = `[${chatDay(m.t)}]${m.fwd ? ' (forwarded from ' + m.fwd + ')' : ''} ${m.text.replace(/\s+\n/g, '\n')}\n`; if(body.length + line.length > CHAT_MAX_CHARS) break; body += line; n++; }
    const text = head + body + (n < L.length ? `\n… ${L.length - n} more messages not kept here (media only, or past ${CHAT_MAX_CHARS.toLocaleString()} characters)` : '');
    recs.push(base({title:`${P.app} posts by ${a.who} — ${P.chat}`.slice(0, 200), body:text, tsRaw:new Date(first).toISOString(), ts:first, source:P.app.toLowerCase() + ' export', tags:['chat', P.app.toLowerCase()], ents:extractRich(text),
      chatAuthor:{app:P.app, id:a.wid, chat:P.chat, cid:P.cid, n:L.length, first, last, names:names.slice(0, 40)}})); }
  /* the post times, for Active hours — the same shape the hours importer keeps */
  const who = [], at = new Map(), t = []; for(const m of P.msgs){ let i = at.get(m.who); if(i == null){ i = who.length; who.push(m.who); at.set(m.who, i); } t.push([i, m.t]); }
  const hb = `${P.app} export — ${P.chat}: ${P.msgs.length.toLocaleString()} post times from ${authors.length} author${authors.length === 1 ? '' : 's'}.`;
  /* the shape of the chat for the forward network: every message as [time, author, source, text fingerprint] — no text kept twice */
  const srcs = [], sAt = new Map(), aIds = [], aAt = new Map(), links = {};
  const net = P.msgs.slice(0, 100000).map(m => { const ak = m.wid || 'name:' + m.who; let ai = aAt.get(ak); if(ai == null){ ai = aIds.length; aIds.push([m.wid, m.who]); aAt.set(ak, ai); }
    let si = -1; if(m.fwd){ const sk = m.fwdId || 'name:' + m.fwd.toLowerCase(); si = sAt.get(sk); if(si == null){ si = srcs.length; srcs.push([m.fwdId, m.fwd]); sAt.set(sk, si); } }
    for(const l of m.links || []) links[l] = (links[l] || 0) + 1;
    return [m.t, ai, si, chatFp(m.text)]; });
  recs.push(base({title:`Post times — ${P.app} (${P.chat.slice(0, 60)})`, body:hb + (fname ? '\nFile: ' + fname : ''), tsRaw:new Date().toISOString(), ts:now, source:'posts:' + P.app + ' export', tags:['post-times'], ents:[], hours:{fmt:P.app + ' export', who, t, unzoned:0},
    chatnet:{app:P.app, chat:P.chat, cid:P.cid, kind:P.kind, authors:aIds, srcs, msgs:net, links}}));
  return {recs, authors:authors.length, skipped:Math.max(0, authors.length - CHAT_MAX_AUTH)};
}
async function importChats(files){
  const cid = capCase(); let made = [], total = 0;
  for(const f of files){ const P = chatParse(await f.text()); if(!P || !P.msgs.length){ toast('No messages could be read from ' + f.name); continue; }
    const R = chatRecords(P, cid, f.name), size = R.recs.reduce((s, r) => s + r.body.length * 2, 0);
    if(!await stoGuard(size, 'import this chat')) return; made = made.concat(R.recs); total += P.msgs.length;
    if(R.skipped) toast(`${R.skipped} authors with the fewest messages were left out (${CHAT_MAX_AUTH} kept)`); }
  if(!made.length) return;
  DB.records.push(...made); mutate('imported a chat export'); if(typeof hashRecords === 'function') await hashRecords(); closeDlg(); afterCapture(cid, made.map(r => r.id));
  const na = made.filter(r => r.chatAuthor).length, nc = made.filter(r => r.chatnet).length;
  toast(`${total.toLocaleString()} messages read from ${nc} chat${nc === 1 ? '' : 's'} — ${na} author${na === 1 ? '' : 's'}, each a record; post times in Active hours, forwards in Infrastructure → Chats`);
}
