/* ==========================================================================
   Saved web pages — import .html / .htm / .mhtml / .mht files you saved with
   the browser (Ctrl+S). The page is read with DOMParser, which never runs its
   scripts; the original file is kept as a hashed attachment and can be viewed
   in a sandbox that blocks scripts and every outside request.
   ========================================================================== */
const isWebPage = f => /\.(html?|xhtml|mhtml?|mht)$/i.test(f.name || '') || /^(text\/html|multipart\/related|application\/x-mimearchive)/i.test(f.type || '');
function qpDecode(s){ return s.replace(/=\r?\n/g, '').replace(/=([0-9A-F]{2})/gi, (m, h) => String.fromCharCode(parseInt(h, 16))); }
function utf8(bin){ try{ return new TextDecoder('utf-8').decode(Uint8Array.from(bin, c => c.charCodeAt(0) & 255)); }catch(e){ return bin; } }
function mhtmlParse(raw){
  const head = raw.slice(0, 4000), bm = head.match(/boundary="?([^";\r\n]+)"?/i); if(!bm) return null;
  const H = {url:(head.match(/^Snapshot-Content-Location:\s*(\S+)/im) || [])[1] || '', subject:(head.match(/^Subject:\s*(.+)$/im) || [])[1] || '', date:(head.match(/^Date:\s*(.+)$/im) || [])[1] || ''};
  for(const part of raw.split('--' + bm[1])){
    const i = part.search(/\r?\n\r?\n/); if(i < 0) continue; const ph = part.slice(0, i), body = part.slice(i).replace(/^\r?\n\r?\n/, '');
    if(!/Content-Type:\s*text\/html/i.test(ph)) continue;
    const enc = (ph.match(/Content-Transfer-Encoding:\s*([\w-]+)/i) || [])[1] || '';
    let html = /quoted-printable/i.test(enc) ? utf8(qpDecode(body)) : /base64/i.test(enc) ? utf8(atob(body.replace(/\s+/g, ''))) : body;
    if(!H.url) H.url = (ph.match(/Content-Location:\s*(\S+)/i) || [])[1] || '';
    return {html, ...H};
  }
  return null;
}
function pageText(doc){
  const BLOCK = /^(P|DIV|LI|TR|H[1-6]|SECTION|ARTICLE|HEADER|FOOTER|BLOCKQUOTE|PRE|BR|TD|TH|DT|DD|FIGCAPTION|NAV|ASIDE|MAIN|TABLE|UL|OL|FORM)$/;
  const out = []; const walk = n => { for(const c of n.childNodes){ if(c.nodeType === 3) out.push(c.nodeValue); else if(c.nodeType === 1 && !/^(SCRIPT|STYLE|NOSCRIPT|TEMPLATE|SVG|IFRAME|CANVAS|OBJECT|HEAD)$/.test(c.tagName)){ if(BLOCK.test(c.tagName)) out.push('\n'); walk(c); if(BLOCK.test(c.tagName)) out.push('\n'); } } };
  if(doc.body) walk(doc.body);
  return out.join('').replace(/[ \t ]+/g, ' ').replace(/ *\n */g, '\n').replace(/\n{3,}/g, '\n\n').trim();
}
function parseWebPage(raw){
  let html = raw, M = null; if(/^MIME-Version:|^From: <Saved by/im.test(raw.slice(0, 600)) || /multipart\/related/i.test(raw.slice(0, 2000))){ M = mhtmlParse(raw); if(!M) return null; html = M.html; }
  const doc = new DOMParser().parseFromString(html, 'text/html');
  const meta = n => { const el = doc.querySelector(`meta[property="${n}"],meta[name="${n}"]`); return el ? (el.getAttribute('content') || '').trim() : ''; };
  const saved = (html.match(/<!--\s*saved from url=\(\d+\)(\S+?)\s*-->/i) || [])[1] || '';
  const url = (M && M.url) || (doc.querySelector('link[rel=canonical]') || {}).href && doc.querySelector('link[rel=canonical]').getAttribute('href') || meta('og:url') || saved || '';
  const base = (() => { try{ return new URL(url); }catch(e){ return null; } })();
  const title = (doc.querySelector('title') || {}).textContent || meta('og:title') || (M && M.subject) || '';
  const links = new Map(); for(const a of doc.querySelectorAll('a[href]')){ let u; try{ u = new URL(a.getAttribute('href'), base || undefined); }catch(e){ continue; } if(!/^https?:$/.test(u.protocol)) continue; const k = u.href.split('#')[0]; if(!links.has(k)) links.set(k, (a.textContent || '').trim().replace(/\s+/g, ' ').slice(0, 80)); }
  const host = base ? base.hostname.replace(/^www\./, '') : '';
  const ext = [...links].filter(([u]) => { try{ return new URL(u).hostname.replace(/^www\./, '') !== host; }catch(e){ return false; } });
  const mails = [...new Set([...doc.querySelectorAll('a[href^="mailto:"]')].map(a => a.getAttribute('href').slice(7).split('?')[0]))];
  return {url, host, title:title.trim().replace(/\s+/g, ' '), desc:meta('description') || meta('og:description'), author:meta('author') || meta('article:author'), site:meta('og:site_name'),
    published:meta('article:published_time') || ((doc.querySelector('time[datetime]') || {}).getAttribute ? doc.querySelector('time[datetime]').getAttribute('datetime') : '') || '', saved:(M && M.date) || '', text:pageText(doc).slice(0, 40000), links:links.size, ext, mails, images:doc.images.length, html};
}
async function importWebPages(files){
  const cid = capCase(), made = [];
  for(const f of files){
    if(f.size > 30 * 1048576){ toast(f.name + ' is over 30 MB — skipped'); continue; }
    const raw = await f.text(), P = parseWebPage(raw); if(!P){ toast('Could not read ' + f.name + ' as a web page'); continue; }
    let att = null; try{ att = await storeFile(f); }catch(e){}
    const savedTs = P.saved && !isNaN(Date.parse(P.saved)) ? Date.parse(P.saved) : f.lastModified || Date.now();
    const body = [`URL: ${P.url || '(not recorded in the file)'}`, `Title: ${P.title}`, P.site ? `Site: ${P.site}` : '', P.author ? `Author: ${P.author}` : '', P.published ? `Published: ${P.published}` : '', `Saved: ${new Date(savedTs).toISOString()}`,
      P.desc ? `Description: ${P.desc}` : '', att ? `SHA-256 of saved file: ${att.sha256}` : '', '', P.text,
      P.ext.length ? `\n\nLinks to other sites (${P.ext.length}):\n` + P.ext.slice(0, 150).map(([u, t]) => (t ? t + ' — ' : '') + u).join('\n') : '', P.mails.length ? '\n\nEmail links:\n' + P.mails.join('\n') : ''].filter(x => x !== '').join('\n');
    made.push({id:uid('r'), caseId:cid, type:'evidence', title:'Web page: ' + (P.title || P.host || f.name).slice(0, 90), body, tsRaw:new Date(savedTs).toISOString(), tsZone:'explicit', ts:savedTs, source:'web page' + (P.host ? ' · ' + P.host : ''), host:'', tags:['web', 'archived'], ents:extractRich(body), answer:'', addedBy:'You', addedAt:Date.now(), hash:'', pv:1, att:att ? [att] : [], page:{url:P.url, links:P.links, images:P.images}});
  }
  if(!made.length) return;
  DB.records.push(...made); mutate('imported ' + made.length + ' web page(s)'); await hashRecords(); closeDlg(); afterCapture(cid, made.map(r => r.id)); watchNotify(made);
  UI.sel = {kind:'rec', id:made[0].id}; UI.inspOpen = true; UI.tlMode = 'events'; go(caseHash(cid, 'timeline'));
  toast(made.length === 1 ? 'Web page archived: ' + made[0].title.slice(10, 60) : made.length + ' web pages archived', 'Undo', () => { const s = new Set(made.map(r => r.id)); DB.records = DB.records.filter(r => !s.has(r.id)); mutate('undid web page import'); renderAll(); });
}
/* safe viewer: no scripts, no same-origin, and the app's policy blocks every outside request */
async function safeView(rid, fid){
  const r = recById(rid), m = r && (r.att || []).find(x => x.id === fid); if(!m) return; const b = await fileBlob(fid); if(!b) return toast('That file is missing from this browser');
  const isImg = /^image\//.test(m.type) || /\.(svg|png|jpe?g|gif|webp|bmp)$/i.test(m.name);
  let html = '';
  if(!isImg){ const raw = await b.text(); const P = /multipart|mhtml?|mht/i.test(m.type + m.name) ? mhtmlParse(raw) : null; html = P ? P.html : raw; }
  const url = isImg ? await fileURL(fid) : '';
  openDlg(dhead(esc(m.name)) + `<div class="in"><p class="t3" style="margin:0 0 10px;font-size:13px">${isImg ? 'Shown as an image, so any script inside it cannot run.' : 'Archived copy in a sandbox: scripts are off and nothing loads from the internet, so images and styles from the live site are missing. The text and links are as saved.'}</p>
    ${isImg ? `<div class="safeimg"><img src="${esc(url)}" alt=""></div>` : `<iframe class="safeframe" sandbox="" referrerpolicy="no-referrer" title="Archived page"></iframe>`}</div>
    <footer>${r.page && r.page.url && E.safeUrl(r.page.url) ? `<a class="btn" href="${esc(r.page.url)}" target="_blank" rel="noopener noreferrer" style="margin-right:auto">${ico('arrow-up-right','sm')}Live page</a>` : ''}<button class="btn" data-act="attDl" data-id="${rid}" data-v="${fid}">${ico('download','sm')}Save file</button><button class="btn primary" data-act="dclose">Close</button></footer>`, true, () => { const fr = document.querySelector('.safeframe'); if(fr) fr.srcdoc = html; });
  $('dlg').classList.add('xwide');
}
