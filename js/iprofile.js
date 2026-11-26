/* ==========================================================================
   Indicator profile: what an indicator is and what about it should worry
   you, worked out here from the value alone. Nothing is looked up.
     · domains: look-alikes of brands and of domains you marked benign
       (other scripts, punycode, digits for letters, one letter off, brand
       plus words, brand used as a subdomain); dynamic DNS, tunnels, free
       hosting, shorteners, paste and file sharing; machine-made names
     · URLs: the host, text before @, a bare IP, redirect parameters, an
       email address carried in the link, payload downloads
     · IPs: address class, public resolvers, IPv4 inside IPv6
     · emails: the mailbox and its domain
     · hashes: empty file, EICAR test file, placeholders
     · wallets: address type and, for bech32, the checksum
   And, for captured text, secrets that should not be there (API keys,
   bot tokens, webhooks, private keys, JWTs), always shown masked.
   Every flag says why; none is a verdict.
   ========================================================================== */
const IPF = {cache:new Map(), MAX:5000};

/* ---------- punycode (RFC 3492) ---------- */
function punyDecode(s){
  const adapt = (d, n, first) => { d = first ? Math.floor(d / 700) : d >> 1; d += Math.floor(d / n); let k = 0; while(d > 455){ d = Math.floor(d / 35); k += 36; } return k + Math.floor(36 * d / (d + 38)); };
  const dig = c => c >= 48 && c <= 57 ? c - 22 : c >= 65 && c <= 90 ? c - 65 : c >= 97 && c <= 122 ? c - 97 : 36;
  let n = 128, i = 0, bias = 72; const out = [], b = Math.max(0, s.lastIndexOf('-'));
  for(let j = 0; j < b; j++){ const c = s.charCodeAt(j); if(c >= 128) return null; out.push(c); }
  for(let p = b > 0 ? b + 1 : 0; p < s.length;){
    const old = i; let w = 1;
    for(let k = 36; ; k += 36){ if(p >= s.length) return null; const d = dig(s.charCodeAt(p++)); if(d >= 36) return null; i += d * w; const t = k <= bias ? 1 : k >= bias + 26 ? 26 : k - bias; if(d < t) break; w *= 36 - t; if(w > 1e9) return null; }
    const len = out.length + 1; bias = adapt(i - old, len, old === 0); n += Math.floor(i / len); i %= len; if(n > 0x10ffff) return null; out.splice(i++, 0, n);
  }
  try{ return String.fromCodePoint(...out); }catch(e){ return null; }
}
const ipfUnicode = host => host.split('.').map(l => /^xn--/i.test(l) ? (punyDecode(l.slice(4).toLowerCase()) || l) : l).join('.');
const ipfAscii = host => { if(!/[^\x00-\x7f]/.test(host)) return host; try{ return new URL('http://' + host).hostname; }catch(e){ return host; } };

/* ---------- where a host's registrable part starts ---------- */
/* platforms where anyone gets a name under the platform's domain: the user's name is the registrable part */
const IPF_PLATFORM = {
  ddns:['duckdns.org', 'no-ip.com', 'no-ip.org', 'no-ip.biz', 'no-ip.info', 'ddns.net', 'hopto.org', 'zapto.org', 'sytes.net', 'servebeer.com', 'serveftp.com', 'myftp.biz', 'myftp.org', 'redirectme.net', 'servehttp.com', 'dynu.net', 'dynu.com', 'afraid.org', 'mooo.com', 'chickenkiller.com', 'dyndns.org', 'dyndns.com', 'dynv6.net', 'freeddns.org', 'ddnsking.com', 'linkpc.net', 'publicvm.com', 'casacam.net', 'kozow.com', 'giize.com', 'gleeze.com', 'accesscam.org', 'camdvr.org', 'ooguy.com', 'theworkpc.com', 'onthewifi.com', 'hldns.ru', 'ddns.me', 'dns.army', 'dns.navy'],
  tunnel:['ngrok.io', 'ngrok-free.app', 'ngrok.app', 'ngrok-free.dev', 'ngrok.dev', 'trycloudflare.com', 'loca.lt', 'serveo.net', 'localhost.run', 'lhr.life', 'pinggy.io', 'pinggy.link', 'localtunnel.me', 'telebit.io', 'devtunnels.ms', 'portmap.io', 'bore.pub'],
  host:['github.io', 'gitlab.io', 'pages.dev', 'workers.dev', 'netlify.app', 'vercel.app', 'herokuapp.com', 'firebaseapp.com', 'web.app', 'appspot.com', 'azurewebsites.net', 'blob.core.windows.net', 'web.core.windows.net', 'azureedge.net', 's3.amazonaws.com', 'cloudfront.net', 'glitch.me', 'repl.co', 'replit.dev', 'replit.app', 'onrender.com', 'fly.dev', 'weebly.com', 'wixsite.com', 'square.site', 'godaddysites.com', 'blogspot.com', 'wordpress.com', 'storage.googleapis.com', 'r2.dev', 'ipfs.io', 'dweb.link', 'translate.goog', 'surge.sh', 'neocities.org', '000webhostapp.com', 'webflow.io', 'framer.app', 'carrd.co', 'notion.site', 'myshopify.com', 'tilda.ws', 'yolasite.com', 'jimdosite.com', 'webnode.page', 'sharepoint.com', 'my.canva.site', 'canva.site', 'typedream.app', 'mybluehost.me', 'firebasestorage.app', 'supabase.co', 'cprapid.com']};
const IPF_SHORT = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cutt.ly', 'rebrand.ly', 'ow.ly', 'buff.ly', 'rb.gy', 'shorturl.at', 'tiny.cc', 'lnkd.in', 't.ly', 'v.gd', 'qrco.de', 'shorturl.asia', 'tinyurl.is', 'bl.ink', 'short.gy', 'surl.li', 'urlz.fr', 'clck.ru', 'u.to', 's.id', 'did.li', 'han.gl'];
const IPF_SHARE = ['pastebin.com', 'paste.ee', 'ghostbin.com', 'hastebin.com', 'rentry.co', 'rentry.org', 'justpaste.it', 'controlc.com', 'privatebin.net', 'dpaste.org', 'paste.rs', 'transfer.sh', 'anonfiles.com', 'gofile.io', 'mega.nz', 'mediafire.com', 'wetransfer.com', 'we.tl', 'catbox.moe', 'litter.catbox.moe', 'file.io', 'sendspace.com', 'filebin.net', 'pixeldrain.com', 'temp.sh', 'bashupload.com', 'oshi.at', 'uguu.se', 'anonfile.la', 'krakenfiles.com'];
const IPF_EXFIL = [['cdn.discordapp.com', 'Discord’s file store — often used to host malware'], ['media.discordapp.net', 'Discord’s file store — often used to host malware'], ['api.telegram.org', 'Telegram’s bot API — phishing kits and stealers send stolen data through it'], ['discord.com/api/webhooks', ''], ['hooks.slack.com', 'Slack webhooks — sometimes used to send data out'], ['webhook.site', 'A public request catcher — used to test or receive stolen data'], ['requestbin.net', 'A public request catcher'], ['pipedream.net', 'A public request catcher'], ['interact.sh', 'Out-of-band testing domain — seen in exploitation attempts'], ['oast.fun', 'Out-of-band testing domain — seen in exploitation attempts'], ['oast.me', 'Out-of-band testing domain'], ['oast.pro', 'Out-of-band testing domain'], ['oast.live', 'Out-of-band testing domain'], ['burpcollaborator.net', 'Out-of-band testing domain — seen in exploitation attempts'], ['canarytokens.com', 'A canary token — someone opening it alerts its owner']];
const IPF_SET = {}; for(const [k, L] of Object.entries(IPF_PLATFORM)) for(const d of L) IPF_SET[d] = k;
const ipfEnds = (h, d) => h === d || h.endsWith('.' + d);
const IPF_SLD = /^(co|com|net|org|gov|ac|edu|ne|or|go|mil|nic|ltd|plc|sch|me|gob|info|biz)$/;
function ipfReg(host){
  const h = host.toLowerCase().replace(/\.$/, ''), p = h.split('.');
  for(let i = 1; i < p.length; i++){ const suf = p.slice(i).join('.'); if(IPF_SET[suf]) return {reg:p.slice(i - 1).join('.'), name:p[i - 1], suffix:suf, sub:p.slice(0, i - 1).join('.'), platform:IPF_SET[suf]}; }
  const two = p.length > 2 && IPF_SLD.test(p[p.length - 2]) && p[p.length - 1].length === 2, n = two ? 3 : 2;
  if(p.length < n) return {reg:h, name:p[0], suffix:p.slice(1).join('.'), sub:'', platform:''};
  return {reg:p.slice(-n).join('.'), name:p[p.length - n], suffix:p.slice(-n + 1).join('.'), sub:p.slice(0, -n).join('.'), platform:''};
}

/* ---------- brands people imitate ---------- */
const IPF_BRANDS = ('paypal.com apple.com icloud.com microsoft.com office.com outlook.com live.com microsoftonline.com google.com gmail.com youtube.com amazon.com netflix.com facebook.com instagram.com whatsapp.com linkedin.com twitter.com dropbox.com docusign.com adobe.com '
  + 'chase.com wellsfargo.com bankofamerica.com citibank.com hsbc.com barclays.com santander.com americanexpress.com capitalone.com usbank.com pnc.com natwest.com lloydsbank.com halifax.co.uk nationwide.co.uk monzo.com revolut.com wise.com '
  + 'dhl.com fedex.com ups.com usps.com royalmail.com dpd.com hermes.com evri.com canadapost.ca auspost.com.au '
  + 'binance.com coinbase.com kraken.com metamask.io blockchain.com ledger.com trezor.io crypto.com bybit.com okx.com kucoin.com uniswap.org opensea.io phantom.app trustwallet.com '
  + 'steamcommunity.com steampowered.com discord.com telegram.org github.com gitlab.com yahoo.com aol.com ebay.com walmart.com target.com bestbuy.com costco.com irs.gov hmrc.gov.uk '
  + 'okta.com zoom.us salesforce.com sharepoint.com onedrive.com wetransfer.com booking.com airbnb.com expedia.com spotify.com roblox.com epicgames.com stripe.com shopify.com squareup.com venmo.com cash.app zelle.com '
  + 'godaddy.com namecheap.com cloudflare.com att.com verizon.com t-mobile.com vodafone.com orange.com ing.com rabobank.com commbank.com.au westpac.com.au anz.com td.com rbc.com scotiabank.com '
  + 'tiktok.com snapchat.com x.com tesla.com samsung.com mcafee.com norton.com avast.com office365.com docs.google.com servicenow.com atlassian.com slack.com teams.microsoft.com').split(' ');
const IPF_WORDS = /^(login|logon|signin|secure|security|account|accounts|support|verify|verification|help|helpdesk|service|services|update|pay|payment|billing|online|portal|auth|wallet|app|id|mail|web|center|centre|team|official|alert|alerts|recovery|refund|care|desk|customer|unlock|confirm|access|connect|safe|check|claim|reward|rewards|gift|bonus|promo|my|get|go|now|info|net|hq|inc|corp|us|uk|ca|au)$/;
const IPF_BRAND = new Map(); for(const d of IPF_BRANDS){ const r = ipfReg(d); if(!IPF_BRAND.has(r.name)) IPF_BRAND.set(r.name, r.reg); }
/* names brands really use, so they are not flagged as imitations of themselves */
const IPF_REAL = new Set(('tmobile.com microsoftonline.com office365.com live.com outlook.com hotmail.com googleusercontent.com gstatic.com googleapis.com googlemail.com google.co.uk youtu.be ytimg.com icloud.com me.com apple.news paypalobjects.com paypal.me paypal-community.com amazonaws.com amazon.co.uk amazon.de amazon.co.jp amazon.in media-amazon.com '
  + 'facebook.net fbcdn.net fb.com messenger.com whatsapp.net linkedin.com licdn.com twimg.com githubusercontent.com githubassets.com dropboxusercontent.com docusign.net adobe.io adobelogin.com chase.com steamstatic.com discordapp.com discordapp.net discord.gg discord.media '
  + 'telegram.me t.me netflix.net nflxvideo.net nflximg.net microsoft365.com azure.com windows.net windowsupdate.com xboxlive.com skype.com bing.com msn.com sharepointonline.com yahoo.co.jp yahoodns.net ebay.co.uk ebayimg.com binance.us coinbase.us zoom.com zoomgov.com okta-emea.com oktapreview.com '
  + 'spotifycdn.com scdn.co tiktokcdn.com snapchat.com sc-cdn.net cloudflare.net cloudflare-dns.com samsungcloud.com').split(' '));
/* letters that look alike: each group reads as its first letter */
const IPF_GLYPH = (() => { const m = {}; for(const g of ['oο0оօ', 'l1iӏіιǀ|ı', 'eе3éèêëє', 'aаα4àáâäåɑ@', 'sѕ5$ś', 'tτт7', 'gɡ9ǥ', 'cсçϲć', 'pрρ', 'xхχ', 'yуγý', 'kκкḱ', 'hһ', 'jј', 'dԁ', 'vνѵ', 'wѡԝ', 'mм', 'uυüùúû', 'nոñ', 'bЬ', 'rг', 'qԛ', 'zᴢ2']) for(const ch of g) m[ch] = g[0]; return m; })();
const IPF_SCRIPT = ch => { const c = ch.codePointAt(0); if(c < 0x80) return /[a-z]/i.test(ch) ? 'Latin' : ''; if(c <= 0x024f) return 'Latin'; if(c >= 0x0370 && c <= 0x03ff) return 'Greek'; if(c >= 0x0400 && c <= 0x052f) return 'Cyrillic'; if(c >= 0x0530 && c <= 0x058f) return 'Armenian'; if(c >= 0x0590 && c <= 0x05ff) return 'Hebrew'; if(c >= 0x0600 && c <= 0x06ff) return 'Arabic'; if(c >= 0x4e00 && c <= 0x9fff) return 'Chinese'; if(c >= 0x3040 && c <= 0x30ff) return 'Japanese'; if(c >= 0xac00 && c <= 0xd7af) return 'Korean'; return 'Other'; };
const IPF_SKB = new Map();
const ipfSkel = s => [...s.normalize('NFC')].map(ch => IPF_GLYPH[ch] || ch).join('');
const ipfCharName = ch => { const c = ch.codePointAt(0), s = IPF_SCRIPT(ch); return /[0-9]/.test(ch) ? 'the digit ' + ch : (s && s !== 'Latin' ? s + ' ' : c > 0x7f ? 'accented ' : '') + '“' + ch + '” (U+' + c.toString(16).toUpperCase().padStart(4, '0') + ')'; };
/* Damerau distance, capped at 2 */
function ipfDist(a, b){ if(Math.abs(a.length - b.length) > 1) return 2; const n = a.length, m = b.length, D = []; for(let i = 0; i <= n; i++){ D[i] = [i]; } for(let j = 0; j <= m; j++) D[0][j] = j;
  for(let i = 1; i <= n; i++){ let row = 9; for(let j = 1; j <= m; j++){ const c = a[i - 1] === b[j - 1] ? 0 : 1; let v = Math.min(D[i - 1][j] + 1, D[i][j - 1] + 1, D[i - 1][j - 1] + c); if(i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) v = Math.min(v, D[i - 2][j - 2] + 1); D[i][j] = v; if(v < row) row = v; } if(row > 1) return 2; }
  return D[n][m]; }
const ipfKind = (a, b) => { if(a.length < b.length) return 'a letter missing'; if(a.length > b.length) return 'a letter added'; const d = [...a].map((c, i) => c !== b[i] ? i : -1).filter(i => i >= 0); return d.length === 2 && a[d[0]] === b[d[1]] ? 'two letters swapped' : 'one letter changed'; };
/* the domains you marked benign count as brands too: an imitation of your client's domain is exactly what to catch */
let IPF_MINE = {at:-1, map:new Map()};
function ipfMine(){
  const stamp = ipfMineStamp(); if(IPF_MINE.at === stamp) return IPF_MINE.map;
  const m = new Map(), add = d => { d = String(d || '').toLowerCase().replace(/^www\./, ''); if(!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(d)) return; const r = ipfReg(d); if(r.platform || r.name.length < 4) return; if(!m.has(r.name)) m.set(r.name, r.reg); };
  for(const [k, v] of Object.entries(DB.verdicts || {})){ const vd = typeof v === 'string' ? v : v && v.v; if(vd === 'benign' && /^domain:/.test(k)) add(k.slice(7)); }
  for(const e of DB.entries || []) if(e.type === 'domain' && typeof entryVerdict === 'function' && entryVerdict(e) === 'benign') add(primary(e));
  IPF_MINE = {at:stamp, map:m}; return m;
}

/* ---------- domains ---------- */
function ipfDomain(host, F, out){
  const asc = ipfAscii(host.toLowerCase()), uni = ipfUnicode(asc), R = ipfReg(uni), RA = ipfReg(asc), name = R.name;
  const bad = (t, why) => out.push({lvl:'bad', t, why}), warn = (t, why) => out.push({lvl:'warn', t, why}), info = (t, why) => out.push({lvl:'info', t, why});
  if(uni !== asc){ F.push(['Shown as', uni]); F.push(['Written as', asc]); }
  F.push(['Registered name', RA.reg + (R.platform ? ' — a name on ' + R.suffix : '')]); if(R.sub) F.push(['Subdomain', R.sub]);
  /* scripts */
  const scripts = new Set([...name].map(IPF_SCRIPT).filter(Boolean).sort((a, b) => (a !== 'Latin') - (b !== 'Latin')));
  if(scripts.size > 1) bad('Mixes ' + [...scripts].join(' and ') + ' letters in one name', 'Real names almost never do; it is how a look-alike hides a foreign letter among normal ones.');
  else if(scripts.size === 1 && !scripts.has('Latin')) info('Written in ' + [...scripts][0] + ' letters', 'An internationalised name. Browsers may show it as ' + asc + '.');
  /* look-alikes */
  if(!IPF_REAL.has(RA.reg) && !IPF_SET[RA.reg]){
    const mine = ipfMine(), sk = ipfSkel(name), alts = new Set([sk, sk.replace(/rn/g, 'm'), sk.replace(/vv/g, 'w'), sk.replace(/cl/g, 'd')]);
    const seen = new Set();
    const toks = name.split('-'), tsk = toks.map(ipfSkel), check = (map, whose) => { for(const [b, real] of map){ if(seen.has(real) || RA.reg === real || ipfEnds(RA.reg, real)) continue; let hit = null; const sb = IPF_SKB.get(b) || (IPF_SKB.set(b, ipfSkel(b)), IPF_SKB.get(b)), tk = toks.length > 1 ? toks.find((t, j) => t !== b && tsk[j] === sb) : null;
      if(name !== b && [...alts].includes(sb)){ const diff = [...name].map((c, i) => c !== b[i] && name.length === b.length ? c : '').filter(Boolean); hit = ['bad', 'Looks like ' + real, (diff.length ? 'Uses ' + [...new Set(diff)].slice(0, 3).map(ipfCharName).join(', ') + ' where ' + real + ' has ' + [...new Set([...name].map((c, i) => c !== b[i] ? b[i] : '').filter(Boolean))].slice(0, 3).map(x => '“' + x + '”').join(', ') : 'Letters drawn alike (rn for m, vv for w)') + '. On screen the two read the same.']; }
      else if(name === b && R.suffix !== ipfReg(real).suffix){ const cc = /^[a-z]{2}$/.test(R.suffix) || /^(co|com)\.[a-z]{2}$/.test(R.suffix); hit = cc ? ['info', 'Same name as ' + real + ', country ending .' + R.suffix, 'Often the brand’s own site for that country — but check who registered it.'] : /^(com|net|org|edu|gov|mil|int)$/.test(R.suffix) ? ['info', 'Same name as ' + real + ' on .' + R.suffix, 'Brands often own this too — check who registered it.'] : ['warn', 'Same name as ' + real + ' on another ending (.' + R.suffix + ')', 'Brands rarely use this ending; imitators often do.']; }
      else if(tk){ hit = ['bad', 'Looks like ' + real + ' with other words', '“' + tk + '” is drawn to read as ' + b + ' — ' + [...tk].filter((c, i) => c !== b[i]).slice(0, 3).map(ipfCharName).join(', ') + ' stands in.']; }
      else if(b.length >= 5 && name.length >= 5 && sk.replace(/-/g, '') !== sb.replace(/-/g, '') && ipfDist(sk, sb) === 1){ hit = [sk === sb + 's' ? 'warn' : 'bad', 'One letter off ' + real, ipfKind(sk, sb)[0].toUpperCase() + ipfKind(sk, sb).slice(1) + ' — the kind of slip a reader does not notice.']; }
      else if(name !== b && (toks.includes(b) || (b.length >= 4 && (sk.startsWith(sb) && IPF_WORDS.test(sk.slice(sb.length)) || sk.endsWith(sb) && IPF_WORDS.test(sk.slice(0, -sb.length)))))){ hit = ['warn', 'Uses the name ' + b + ' with other words', 'Brand plus words (' + name + ') is the commonest phishing pattern — though brands own some such names.']; }
      else if(R.sub && (R.sub.split(/[.-]/).includes(b) || R.sub.includes(real))){ hit = [R.sub.includes(real) ? 'bad' : 'warn', (R.sub.includes(real) ? real + ' used as a subdomain' : 'The name ' + b + ' in a subdomain') + ' of ' + RA.reg, 'The address starts like ' + real + ' but belongs to ' + RA.reg + '.']; }
      if(hit){ seen.add(real); out.push({lvl:hit[0], t:hit[1], why:hit[2] + (whose ? ' (' + real + ' is ' + whose + ')' : ''), like:real}); if(hit[0] === 'bad' || out.filter(x => x.like).length >= 3) return true; } } };
    check(mine, 'marked benign in your cases') || check(IPF_BRAND, '');
  }
  /* what kind of place it is */
  if(R.platform === 'ddns') warn('Dynamic DNS name on ' + R.suffix, 'Anyone can create one in a minute and point it anywhere — common for remote-access trojans and C2. Judge ' + RA.reg + ', not ' + R.suffix + '.');
  else if(R.platform === 'tunnel') warn('Tunnel on ' + R.suffix, 'It leads to someone’s own computer through ' + R.suffix + '. Short-lived; used for phishing pages and C2.');
  else if(R.platform === 'host') info('Free hosting on ' + R.suffix, 'The domain is the platform’s, the content is ' + (R.name || 'the user') + '’s. Mark ' + RA.reg + ' — never ' + R.suffix + ' itself.');
  const s = IPF_SHORT.find(d => ipfEnds(asc, d)); if(s) info('Link shortener', 'Expand it before judging — the real destination is hidden. Many add “+” or “-” to the link to show it.');
  const sh = IPF_SHARE.find(d => ipfEnds(asc, d)); if(sh) info('Paste or file-sharing site', 'Content is the uploader’s; such sites host payloads and leaks. Save what is there — it is often deleted.');
  const ex = IPF_EXFIL.find(([d]) => !d.includes('/') && ipfEnds(asc, d)); if(ex) warn(ex[1].split(' — ')[0], ex[1].includes(' — ') ? ex[1].split(' — ')[1][0].toUpperCase() + ex[1].split(' — ')[1].slice(1) + '.' : '');
  if(/\.onion$/.test(asc)){ ipfOnion(asc, F, out); return; }
  /* machine-made names */
  const L = (R.platform ? name : RA.name) || '', letters = L.replace(/[^a-z]/g, ''), vow = (letters.match(/[aeiouy]/g) || []).length, run = Math.max(0, ...(letters.match(/[^aeiouy]+/g) || ['']).map(x => x.length)), dig = (L.match(/\d/g) || []).length;
  const ent = (() => { const f = {}; for(const c of L) f[c] = (f[c] || 0) + 1; let e = 0; for(const c in f){ const p = f[c] / L.length; e -= p * Math.log2(p); } return e; })();
  if(!/^xn--/.test(L) && L.length >= 10 && (/^[0-9a-f]{16,}$/.test(L) || (letters.length >= 6 && vow / letters.length < 0.2 && run >= 5) || (dig >= 3 && letters.length >= 4 && (L.match(/\d[a-z]|[a-z]\d/g) || []).length >= 4 && ent > 3.2)))
    warn('Name looks machine-generated', 'Random-looking (' + L.length + ' characters, ' + (vow ? vow + ' vowel' + (vow > 1 ? 's' : '') : 'no vowels') + (dig ? ', ' + dig + ' digits' : '') + '). Malware generates names like this to find its C2 (DGA).');
  if(R.sub && R.sub.split('.').length >= 4) info('Deep subdomain (' + (R.sub.split('.').length + 2) + ' levels)', 'Long chains push the real domain out of sight in a phone’s address bar.');
  const m = E.meaning('domain', asc); if(m && m.hot) warn(m.t, 'Cheap or free endings that abuse reports show far more often than .com.');
  else if(m) info(m.t, 'Cannot exist on the internet; it appears in examples and tests.');
}

/* ---------- Tor onion services ----------
   The address is the service's public key, so a typo is caught by its checksum. A fake mirror is a real key with a
   look-alike start — scammers grind keys until the first characters match the site they copy. */
function ipfOnion(host, F, out){
  const I = E.onionInfo(host), h = host.replace(/\.onion$/, ''), sv = h.split('.').pop();
  if(!I){ out.push({lvl:'bad', t:'Not an onion address', why:'Version 3 addresses are 56 characters of a–z and 2–7; this is ' + sv.length + '.'}); return; }
  if(I.v === 2){ F.push(['Tor version', '2 — 16 characters']); out.push({lvl:'warn', t:'Version 2 onion — dead since October 2021', why:'Tor no longer reaches these. A v2 address in recent material was copied from an old list.'}); return; }
  F.push(['Tor version', '3 — ed25519 key']); if(h.includes('.')) F.push(['Subdomain', h.slice(0, h.lastIndexOf('.'))]);
  if(!I.ok){ out.push({lvl:'bad', t:'Checksum fails', why:'Not a real onion address — a typo, a truncated copy, or made up. Tor would refuse it.'}); return; }
  F.push(['Checksum', 'Valid']); F.push(['Reachable', 'Only through Tor — open it in Tor Browser, not here']);
  /* other onion addresses you hold: the same start is a vanity look-alike or a mirror; in the same text, a mirror list */
  const g = typeof globalEnts === 'function' ? globalEnts() : null; if(!g) return;
  const mine = [...g.keys()].filter(k => /^domain:[a-z2-7]{56}\.onion$/.test(k) && k !== 'domain:' + sv + '.onion').map(k => k.slice(7)).filter(o => { const x = E.onionInfo(o); return x && x.ok; });   // a broken copy is reported on its own
  let pre = 0, like = []; for(const o of mine){ let n = 0; while(n < 56 && o[n] === sv[n]) n++; if(n >= 5){ if(n > pre){ pre = n; like = [o]; } else if(n === pre) like.push(o); } }
  if(like.length) out.push({lvl:'warn', t:'Starts like ' + like.length + ' other onion' + (like.length > 1 ? 's' : '') + ' in your cases', why:'Same first ' + pre + ' characters (“' + sv.slice(0, pre) + '…”) as ' + like.slice(0, 2).map(x => x.slice(0, 12) + '…').join(', ') + '. Making that takes deliberate key grinding: the same operator’s mirror, or a phishing copy of it. Compare the full address with one you trust.'});
  const me = g.get('domain:' + sv + '.onion'); if(me){ const near = new Set(); for(const r of me.recs.slice(0, 50)) for(const o of mine) if(String(r.body || '').toLowerCase().includes(o)) near.add(o);
    if(near.size) F.push(['Listed with', near.size + ' other onion' + (near.size > 1 ? 's' : '') + ' in the same text — often a mirror list']); }
}
/* ---------- OpenPGP keys ----------
   A vendor's key is the one identity they keep across markets, forums and rebrands. What the key itself says —
   when it was made, its user IDs (names and emails) — is read from any armoured block in your evidence. */
function ipfPgpKey(fp){ const g = typeof globalEnts === 'function' ? globalEnts().get('pgp:' + fp) : null; if(!g) return null;
  for(const r of g.recs.slice(0, 40)){ const b = String(r.body || ''); if(!b.includes('BEGIN PGP PUBLIC KEY BLOCK')) continue; for(const blk of b.match(/-----BEGIN PGP PUBLIC KEY BLOCK-----[\s\S]{0,200000}?-----END PGP PUBLIC KEY BLOCK-----/g) || []){ const K = E.pgpParse(blk), i = K.findIndex(k => k.fp === fp); if(i >= 0){ const subs = []; for(let j = i + 1; j < K.length && K[j].sub; j++) subs.push(K[j]); return {...K[i], subs}; } } }
  return null; }
/* ---------- URLs ---------- */
const IPF_PHISH = /(log-?in|sign-?in|verify|verification|account|secure|update|wallet|password|passwd|auth|confirm|invoice|billing|unlock|suspend|recover|webscr|banking|kyc|2fa|mfa|ssn)/gi;
const IPF_PAYLOAD = /\.(exe|dll|scr|msi|ps1|bat|cmd|vbs|vbe|js|jse|hta|jar|lnk|iso|img|vhd|vhdx|zip|rar|7z|apk|dmg|pkg|sh|elf|bin|docm|xlsm|pptm|one|cab|appx|msix)$/i;
function ipfUrl(v, F, out){
  let u; try{ u = new URL(/^[a-z][\w+.-]*:\/\//i.test(v) ? v : 'http://' + v); }catch(e){ return; }
  const raw = String(v), auth = (/^[a-z][\w+.-]*:\/\/([^/?#]*)/i.exec(raw) || [])[1] || '';
  F.push(['Host', u.hostname]); if(u.port) F.push(['Port', u.port]); if(u.pathname && u.pathname !== '/') F.push(['Path', u.pathname.length > 80 ? u.pathname.slice(0, 78) + '…' : u.pathname]);
  if(auth.includes('@')){ const before = auth.slice(0, auth.lastIndexOf('@')); out.push({lvl:'bad', t:'Text before @ hides the real host', why:'Browsers ignore “' + (before.length > 40 ? before.slice(0, 38) + '…' : before) + '@” and go to ' + u.hostname + '.' + (before.includes(':') ? ' It also carries what looks like a password.' : '')}); }
  const h = u.hostname.replace(/^\[|\]$/g, '');
  if(/^(\d+|0x[0-9a-f]+)$/i.test(auth.replace(/^.*@/, '').replace(/:\d+$/, ''))) out.push({lvl:'bad', t:'Host written as a number', why:'The address ' + h + ' disguised as a plain number — browsers still go there.'});
  else if(/^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.includes(':')) out.push({lvl:'warn', t:'Host is a bare IP address', why:'Real services use names; links straight to an address are common for payloads and C2.'});
  else ipfDomain(h, F, out);
  if(u.port && !['80', '443'].includes(u.port)) out.push({lvl:'info', t:'Unusual port ' + u.port, why:E.meaning('hostport', '0.0.0.0:' + u.port) ? E.meaning('hostport', '0.0.0.0:' + u.port).t : 'Not the normal web ports.'});
  const file = decodeURIComponent(u.pathname.split('/').pop() || ''); if(IPF_PAYLOAD.test(file)) out.push({lvl:'warn', t:'Downloads ' + file, why:'A file type that runs or holds code — fetch it only into a sandbox.'});
  /* redirects and what the link carries */
  const vals = []; u.searchParams.forEach((x, k) => vals.push([k, x])); if(u.hash.length > 1) vals.push(['#', u.hash.slice(1)]);
  for(const [k, x] of vals.slice(0, 40)){
    let d = x; if(/^[A-Za-z0-9+/_-]{16,}={0,2}$/.test(x)) try{ const t = atob(x.replace(/-/g, '+').replace(/_/g, '/')); if(/^[\x20-\x7e]+$/.test(t)) d = t; }catch(e){}
    const to = /^(?:https?:)?\/\/([^/?#\s]+)/i.exec(d) || /^(?:https?%3a)?%2f%2f([^%/?#\s]+)/i.exec(d);
    if(to && !F.some(f => f[0] === 'Goes on to')){ F.push(['Goes on to', to[1].replace(/^.*@/, '')]); out.push({lvl:'warn', t:'Redirects to ' + to[1].replace(/^.*@/, ''), why:'The “' + k + '” parameter sends the visitor on — an open redirect lets a trusted domain front for another.'}); }
    const em = /[\w.+-]+@[\w-]+(\.[\w-]+)+/.exec(d); if(em && !out.some(f => f.em)) out.push({lvl:'warn', em:1, t:'Carries an email address', why:(d !== x ? 'Hidden in base64 in “' + k + '”: ' : 'In “' + k + '”: ') + em[0] + ' — a link made for one person, typical of targeted phishing. That person is likely a recipient.'});
  }
  const words = [...new Set((u.hostname + u.pathname).match(IPF_PHISH) || [])].map(w => w.toLowerCase());
  if(words.length >= 2 || (words.length && out.some(f => f.like))) out.push({lvl:'warn', t:'Phishing words: ' + words.slice(0, 4).join(', '), why:'Words that push someone to log in or pay, in the address itself.'});
  if(raw.length > 200) out.push({lvl:'info', t:'Very long link (' + raw.length + ' characters)', why:'Long links hide what matters at the end; tracking and phishing kits make them.'});
  if(/^http:/i.test(raw) && (words.length >= 2 || out.some(f => f.like))) out.push({lvl:'warn', t:'No encryption on a page that asks for something', why:'Cleartext HTTP — real login and payment pages always use HTTPS.'});
}

/* ---------- IP addresses ---------- */
const IPF_RESOLVERS = {'8.8.8.8':'Google Public DNS', '8.8.4.4':'Google Public DNS', '1.1.1.1':'Cloudflare DNS', '1.0.0.1':'Cloudflare DNS', '9.9.9.9':'Quad9 DNS', '149.112.112.112':'Quad9 DNS', '208.67.222.222':'OpenDNS', '208.67.220.220':'OpenDNS', '4.2.2.1':'Level 3 DNS', '4.2.2.2':'Level 3 DNS', '64.6.64.6':'Verisign DNS', '94.140.14.14':'AdGuard DNS', '76.76.2.0':'Control D DNS', '2001:4860:4860::8888':'Google Public DNS', '2001:4860:4860::8844':'Google Public DNS', '2606:4700:4700::1111':'Cloudflare DNS', '2606:4700:4700::1001':'Cloudflare DNS', '2620:fe::fe':'Quad9 DNS', '169.254.169.254':'Cloud metadata service', '168.63.129.16':'Azure platform address'};
function ipf6(v){ const s = v.toLowerCase(); let [a, b] = s.split('::'); const tail = []; let g4 = null; const p4 = x => { const m = /(\d+\.\d+\.\d+\.\d+)$/.exec(x); if(m){ g4 = m[1]; return x.slice(0, -m[1].length).replace(/:$/, ''); } return x; };
  if(b !== undefined) b = p4(b); else a = p4(a); const A = a ? a.split(':') : [], B = b ? b.split(':') : []; const n4 = g4 ? 2 : 0, fill = 8 - n4 - A.length - B.length; const G = [...A, ...Array(b !== undefined ? Math.max(0, fill) : 0).fill('0'), ...B].map(x => parseInt(x || '0', 16));
  if(g4){ const o = g4.split('.').map(Number); G.push(o[0] << 8 | o[1], o[2] << 8 | o[3]); } return G.length === 8 ? G : null; }
const ipf4 = (hi, lo) => [hi >> 8, hi & 255, lo >> 8, lo & 255].join('.');
function ipfIp(k, v, F, out){
  const c = E.meaning(k === 'hostport' ? 'ipv4' : k, k === 'hostport' ? v.slice(0, v.lastIndexOf(':')) : v); if(c) F.push(['Address', c.t]);
  const ip = k === 'hostport' ? v.slice(0, v.lastIndexOf(':')) : v;
  if(IPF_RESOLVERS[ip]) out.push({lvl:'info', t:IPF_RESOLVERS[ip], why:/metadata/.test(IPF_RESOLVERS[ip]) ? 'Requests to it from a server can leak cloud credentials (SSRF).' : 'Nearly every machine talks to it. Usually noise, not an indicator.'});
  if(c && /Private|Loopback|Link-local|Carrier|This network|Reserved|Multicast|Benchmark/.test(c.t)) out.push({lvl:'info', t:'Internal address', why:'Means something only inside that network — it names a machine there, not one on the internet. Do not look it up publicly.'});
  else if(c && /Documentation/.test(c.t)) out.push({lvl:'info', t:'Example address', why:'Reserved for documentation; it cannot be a real host.'});
  if(k === 'ipv6'){ const G = ipf6(v); if(G){
    if(G.slice(0, 5).every(x => !x) && G[5] === 0xffff){ F.push(['Holds IPv4', ipf4(G[6], G[7])]); out.push({lvl:'info', t:'IPv4 written as IPv6: ' + ipf4(G[6], G[7]), why:'Search for the IPv4 address too.'}); }
    else if(G[0] === 0x2002){ F.push(['Holds IPv4', ipf4(G[1], G[2])]); out.push({lvl:'info', t:'6to4 address of ' + ipf4(G[1], G[2]), why:'The sender’s IPv4 address is inside it.'}); }
    else if(G[0] === 0x2001 && G[1] === 0){ const x = ipf4(G[6] ^ 0xffff, G[7] ^ 0xffff); F.push(['Holds IPv4', x]); out.push({lvl:'info', t:'Teredo tunnel from ' + x, why:'The client’s public IPv4 address is in the last 32 bits.'}); }
    else if((G[4] & 0x0200) && (G[5] & 0xff) === 0xff && (G[6] >> 8) === 0xfe){ const mac = [(G[4] >> 8) ^ 2, G[4] & 255, G[5] >> 8, G[6] & 255, G[7] >> 8, G[7] & 255].map(x => x.toString(16).padStart(2, '0')).join(':'); F.push(['Built from MAC', mac]); out.push({lvl:'info', t:'Contains the device’s MAC address', why:'An EUI-64 address: ' + mac + ' identifies the network card, and its maker.'}); } } }
}

/* ---------- hashes, wallets, emails ---------- */
const IPF_HASH = {'d41d8cd98f00b204e9800998ecf8427e':'empty', 'da39a3ee5e6b4b0d3255bfef95601890afd80709':'empty', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855':'empty', 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e':'empty',
  '44d88612fea8a8f36de82e1278abb02f':'eicar', '3395856ce81f2b7382dee72602f798b642f14140':'eicar', '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f':'eicar', 'cc805d5fab1fd71a4ab352a9c533e65fb2d5b885518f4e565e68847223b8e6b85cb48f3afad842726d99239c9e36505c64b0dc9a061d9e507d833277ada336ab':'eicar'};
const IPF_B32 = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
function ipfBech(a){ a = a.toLowerCase(); const p = a.lastIndexOf('1'); if(p < 1) return null; const hrp = a.slice(0, p), data = [...a.slice(p + 1)].map(c => IPF_B32.indexOf(c)); if(data.length < 6 || data.some(x => x < 0)) return false;
  const G = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]; let chk = 1;
  for(const x of [...[...hrp].map(c => c.charCodeAt(0) >> 5), 0, ...[...hrp].map(c => c.charCodeAt(0) & 31), ...data]){ const b = chk >>> 25; chk = ((chk & 0x1ffffff) << 5) ^ x; for(let i = 0; i < 5; i++) if((b >>> i) & 1) chk ^= G[i]; }
  chk >>>= 0; const kind = chk === 1 ? 'bech32' : chk === 0x2bc830a3 ? 'bech32m' : false; if(!kind) return false; return (data[0] === 0) === (kind === 'bech32') ? kind : false; }
/* SHA-256, synchronous, for Base58Check (small inputs only) */
function ipfSha256(m){
  const K = IPF_K || (IPF_K = (() => { const k = [], p = []; for(let n = 2; p.length < 64; n++) if(p.every(q => n % q)) p.push(n); for(const q of p) k.push((Math.cbrt(q) % 1) * 2 ** 32 | 0); return k; })());
  const H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19], l = m.length, n = ((l + 9 + 63) >> 6) << 6, b = new Uint8Array(n); b.set(m); b[l] = 0x80; new DataView(b.buffer).setUint32(n - 4, l * 8); const W = new Int32Array(64), r = (x, y) => x >>> y | x << 32 - y;
  for(let o = 0; o < n; o += 64){ for(let i = 0; i < 16; i++) W[i] = b[o + i * 4] << 24 | b[o + i * 4 + 1] << 16 | b[o + i * 4 + 2] << 8 | b[o + i * 4 + 3];
    for(let i = 16; i < 64; i++){ const a = W[i - 15], c = W[i - 2]; W[i] = (r(a, 7) ^ r(a, 18) ^ a >>> 3) + W[i - 16] + (r(c, 17) ^ r(c, 19) ^ c >>> 10) + W[i - 7] | 0; }
    let [A, B, C, D, E2, F, G, X] = H;
    for(let i = 0; i < 64; i++){ const t1 = X + (r(E2, 6) ^ r(E2, 11) ^ r(E2, 25)) + (E2 & F ^ ~E2 & G) + K[i] + W[i] | 0, t2 = (r(A, 2) ^ r(A, 13) ^ r(A, 22)) + (A & B ^ A & C ^ B & C) | 0; X = G; G = F; F = E2; E2 = D + t1 | 0; D = C; C = B; B = A; A = t1 + t2 | 0; }
    H[0] = H[0] + A | 0; H[1] = H[1] + B | 0; H[2] = H[2] + C | 0; H[3] = H[3] + D | 0; H[4] = H[4] + E2 | 0; H[5] = H[5] + F | 0; H[6] = H[6] + G | 0; H[7] = H[7] + X | 0; }
  const out = new Uint8Array(32); H.forEach((h, i) => new DataView(out.buffer).setUint32(i * 4, h)); return out;
}
let IPF_K = null;
/* Base58Check: the last 4 bytes are the first 4 of a double SHA-256 of the rest */
function ipfB58(a){ const A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'; let n = 0n; for(const ch of a){ const i = A.indexOf(ch); if(i < 0) return false; n = n * 58n + BigInt(i); }
  const bytes = []; while(n > 0n){ bytes.unshift(Number(n & 255n)); n >>= 8n; } for(const ch of a){ if(ch !== '1') break; bytes.unshift(0); } if(bytes.length < 5) return false;
  const body = new Uint8Array(bytes.slice(0, -4)), sum = ipfSha256(ipfSha256(body)); return bytes.slice(-4).every((x, i) => x === sum[i]); }
function ipfMisc(k, v, F, out){
  const low = String(v).toLowerCase();
  if(/^(md5|sha1|sha256|sha512)$/.test(k)){ F.push(['Algorithm', {md5:'MD5 · 128 bits', sha1:'SHA-1 · 160 bits', sha256:'SHA-256 · 256 bits', sha512:'SHA-512 · 512 bits'}[k]]);
    if(IPF_HASH[low] === 'empty') out.push({lvl:'info', t:'Hash of an empty file', why:'Zero bytes hash to this. It shows up when a download or copy failed, and says nothing about malware.'});
    else if(IPF_HASH[low] === 'eicar') out.push({lvl:'info', t:'EICAR antivirus test file', why:'A harmless file made to test that antivirus works. Every engine flags it.'});
    else if(/^(.)\1+$/.test(low) || /^(0123456789abcdef)+/.test(low) || /^(deadbeef)+/.test(low)) out.push({lvl:'info', t:'Placeholder, not a real hash', why:'A pattern typed in examples and templates.'});
    if(k === 'md5' || k === 'sha1') F.push(['Note', (k === 'md5' ? 'MD5' : 'SHA-1') + ' collisions can be made on purpose — pivot on SHA-256 when you have it']); }
  else if(k === 'btc'){ const net = /^(tb1|bcrt1|[mn2])/.test(v) ? 'Testnet' : 'Bitcoin';
    const t = /^(bc1q|tb1q)/i.test(v) ? (v.length > 50 ? 'Native SegWit script (P2WSH) — often multisig' : 'Native SegWit (P2WPKH)') : /^(bc1p|tb1p)/i.test(v) ? 'Taproot (P2TR)' : /^[13mn2]/.test(v) ? (/^[1mn]/.test(v) ? 'Legacy (P2PKH)' : 'Script hash (P2SH) — multisig or wrapped SegWit') : 'Unknown';
    F.push(['Network', net]); F.push(['Type', t]);
    if(/^(bc|tb|bcrt)1/i.test(v)){ const c = ipfBech(v); if(c === false) out.push({lvl:'bad', t:'Checksum fails', why:'Not a valid address — a typo, a truncated copy, or made up. Funds sent to it would be refused.'}); else if(c) F.push(['Checksum', 'Valid (' + c + ')']); } else if(ipfB58(v)) F.push(['Checksum', 'Valid (Base58Check)']); else out.push({lvl:'bad', t:'Checksum fails', why:'Not a valid address — a typo, a truncated copy, or made up. Funds sent to it would be refused.'});
    if(net === 'Testnet') out.push({lvl:'info', t:'Testnet address', why:'Test coins with no value — from a developer, or a fake.'}); }
  else if(k === 'eth'){ F.push(['Type', 'Ethereum-style address (also BSC, Polygon, Arbitrum…)']); if(/^0x0{40}$/.test(low)) out.push({lvl:'info', t:'The zero address', why:'Used to burn tokens and in contract creation; nobody owns it.'}); else if(/^0x0{20,}/.test(low) || /^0x0+dead$/.test(low)) out.push({lvl:'info', t:'Burn or vanity address', why:'Long runs of zeros are made on purpose.'}); F.push(['Checksum', /[a-f]/.test(v.slice(2)) && /[A-F]/.test(v.slice(2)) ? 'Mixed case (EIP-55 checksummed form)' : 'Not in checksummed form']); }
  else if(k === 'sol'){ F.push(['Type', 'Solana address — a 32-byte public key, base58']); F.push(['Explorers', 'Solscan, Solana Explorer (links below)']);
    if(/^1{32,}$/.test(v)) out.push({lvl:'info', t:'The system program', why:'Built into Solana; nobody owns it.'}); }
  else if(k === 'ens'){ const parts = low.split('.'); F.push(['Type', 'ENS name — a readable name for an Ethereum wallet']); if(parts.length > 2) F.push(['Parent', parts.slice(1).join('.')]);
    if(/[^\x00-\x7f]/.test(v) || /xn--/.test(low)) out.push({lvl:'warn', t:'Non-Latin characters', why:'A name can look like a known one and point somewhere else — check the address it resolves to.'});
    if(/^0x[0-9a-f]{6,}/.test(parts[0])) out.push({lvl:'warn', t:'Made to look like an address', why:'A name starting with 0x… is chosen to be mistaken for a wallet address.'}); }
  else if(k === 'sshkey' && typeof IDKEYS !== 'undefined'){
    /* the full key, if any record has it: type, size, comments, the other fingerprint forms */
    const g = typeof globalEnts === 'function' ? globalEnts().get('sshkey:' + v) : null, recs = g ? g.recs : [], re = /\b(ssh-(?:ed25519|rsa|dss)|ecdsa-sha2-nistp(?:256|384|521)|sk-(?:ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)[ \t]+(AAAA[A-Za-z0-9+\/]{40,4000}={0,3})(?:[ \t]+([^\s"'<>]{1,120}))?/g;
    let K = null; const comments = new Set();
    const scan = L => { for(const r of L){ if(!/ssh-|ecdsa-/.test(r.body || '')) continue; re.lastIndex = 0; let m; while((m = re.exec(r.body || ''))){ const x = IDKEYS.sshParse(m[2], m[1]); if(x && (x.sha256 === v || x.md5 === v)){ K = x; if(m[3]) comments.add(m[3]); } } } };
    scan(recs.slice(0, 400)); if(!K && /^MD5:/.test(v)) scan(DB.records.slice(-5000));   /* an MD5 fingerprint (Shodan, old tools): the full key may be in another record */
    if(K && /^MD5:/.test(v)) out.push({lvl:'info', t:'Same key as ' + K.sha256, why:'This MD5 fingerprint belongs to a public key in your evidence. Both name one key.'});
    if(K){ const I = IDKEYS.sshInfo(K); F.push(['Type', I.label + (K.bits && !/ed25519/.test(K.type) ? ' · ' + K.bits + ' bits' : '')]); if(I.warn) out.push({lvl:'warn', t:'Weak or outdated key', why:I.warn});
      if(K.sk) out.push({lvl:'info', t:'Kept on a hardware security key', why:'Signing needs the physical key (YubiKey or similar) to be present; the private key cannot be copied off it.'});
      F.push(['SHA-256', K.sha256]); if(K.md5) F.push(['MD5 (older tools, Shodan)', K.md5.slice(4)]); F.push(['Hex SHA-256 (Censys)', K.hex]);
      if(comments.size) F.push(['Comment', [...comments].slice(0, 4).join(', ') + ' — the user and machine it was made on, unless changed']); }
    else { F.push(['Fingerprint', /^MD5:/.test(v) ? 'MD5 only (older tools and Shodan). Paste the public key to see its type and SHA-256 form' : 'Only the fingerprint is in your evidence — paste the public key to see its type and size']); const hx = IDKEYS.sshFpToHex(v); if(hx) F.push(['Hex SHA-256 (Censys)', hx]); }
    /* where it was seen: a server key on several machines, or a login key used against several, points at one operator */
    const hosts = new Set(), users = new Set(); for(const r of recs) for(const e of r.ents || []){ if(e.k === 'ipv4' || e.k === 'ipv6' || e.k === 'domain') hosts.add(e.v); if(e.k === 'handle' || e.k === 'account') users.add(e.v); }
    if(hosts.size) F.push(['Seen with', [...hosts].slice(0, 8).join(', ') + (hosts.size > 8 ? ' +' + (hosts.size - 8) : '')]);
    const ips = [...hosts].filter(h => /^[\d.]+$|:/.test(h)).length, machines = ips || hosts.size;   /* an address and its host name are one machine */
    if(machines >= 2) out.push({lvl:'info', t:'One key, ' + machines + ' machines', why:'The same SSH key turns up with several hosts. A server key copied between machines, or one login key used on all of them, usually means one operator set them up.'});
    if(g && g.cases && g.cases.size > 1) out.push({lvl:'info', t:'In ' + g.cases.size + ' cases', why:'The same key links these investigations.'}); }
  else if(k === 'fedi' && typeof IDKEYS !== 'undefined'){ const P = IDKEYS.fediParts(v); if(P){ F.push(['User', P.user]); F.push(['Server', P.host]); F.push(['Profile', P.url]);
    if(!P.big) out.push({lvl:'info', t:'A small or personal server', why:P.host + ' is not one of the large public servers. Whoever runs it may be the account’s owner: look up the domain.'});
    F.push(['Note', 'The same name on another server can be someone else; a moved account says so on its old profile']); } }
  else if(k === 'matrix' && typeof IDKEYS !== 'undefined'){ const P = IDKEYS.matrixParts(v); if(P){ F.push(['User', P.user]); F.push(['Homeserver', P.host]);
    if(!P.big) out.push({lvl:'info', t:'A self-hosted homeserver', why:P.host + ' is not a large public server; its owner may be the account’s owner, or close to them.'});
    F.push(['Note', 'Messages are often end-to-end encrypted; what is public is the account and the rooms it joins']); } }
  else if(k === 'npub' && typeof IDKEYS !== 'undefined'){ const h = IDKEYS.npubHex(v); F.push(['Type', 'Nostr public key: the account itself, kept for life; names and pictures are just profile data']); if(h) F.push(['Hex form', h + ' — how it appears in events and on relays']);
    F.push(['Checksum', h ? 'Valid' : 'Fails']); }
  else if(k === 'did' && typeof IDKEYS !== 'undefined'){ const P = IDKEYS.didParts(v); if(P){ F.push(['Method', P.method === 'plc' ? 'did:plc: Bluesky’s directory keeps every handle and server this account has had' : 'did:web: the identity is the domain ' + P.id]);
    if(P.method === 'plc') F.push(['History', 'The PLC directory link below lists each handle change with its date']);
    if(P.method === 'web') out.push({lvl:'info', t:'Tied to a domain', why:'Whoever controls ' + P.id + ' controls this identity. Look the domain up.'}); } }
  else if(k === 'vin'){ const I = TRANSPORT.vinInfo(v);
    F.push(['Maker', I.maker || 'Not in the built-in list (maker code ' + I.wmi + ')']); if(I.where) F.push(['Made in', I.where]); if(I.year) F.push(['Model year', I.year]);
    F.push(['Check digit', I.check ? 'Valid' : 'Does not match']); F.push(['Plant · serial', I.plant + ' · ' + I.serial]);
    if(!I.check && I.na) out.push({lvl:'bad', t:'Check digit fails', why:'Every North American VIN carries one. This is a typo, a misread photo, or a made-up number.'});
    else if(!I.check) out.push({lvl:'info', t:'No check digit', why:'Makers outside North America and China may leave it out, so this alone does not mean the VIN is wrong.'}); }
  else if(k === 'tail'){ const c = TRANSPORT.tailCountry(v); if(c) F.push(['Registered in', c]);
    if(/^N\d/.test(v)){ const h = TRANSPORT.nToIcao(v); if(h) F.push(['Aircraft address', h + ' (worked out from the N-number)']); F.push(['Owner', 'US registrations are public: the FAA registry link below shows the owner']); }
    F.push(['Note', 'A registration moves with the aircraft only while it stays in one country; the address and the serial number are what follow it']); }
  else if(k === 'icao24'){ const c = TRANSPORT.icaoCountry(v); F.push(['Registered in', c || 'Not in the built-in list of address blocks']);
    const n = TRANSPORT.icaoToN(v); if(n) F.push(['Registration', n + ' (worked out from the address)']);
    F.push(['Type', 'The 24-bit address the transponder sends (Mode S, ADS-B); it stays with the airframe while its country does not change']); }
  else if(k === 'imo'){ F.push(['Type', 'IMO ship number: given once and kept for the ship’s life, through new names, owners and flags']); F.push(['Check digit', 'Valid']); }
  else if(k === 'mmsi'){ const I = TRANSPORT.mmsiInfo(v); F.push(['Type', I.kind]); if(I.flag) F.push(['Flag', I.flag]); else if(I.mid) F.push(['Flag', 'Unknown country code ' + I.mid]);
    F.push(['Note', 'A ship gets a new MMSI when it changes flag; its IMO number stays the same']);
    if(I.open) out.push({lvl:'info', t:'Open-registry flag', why:I.flag + ' registers ships owned abroad, so the flag says little about who runs this one. Look for the owner and the manager instead.'}); }
  else if(k === 'tgid'){ F.push(['Type', 'Telegram account number — permanent; the name and username can change, this does not']); F.push(['Where it shows', 'from_id in a Telegram Desktop export (user' + v + ')']); }
  else if(k === 'dcid'){ const ms = Number(BigInt(String(v)) >> 22n) + 1420070400000; F.push(['Type', 'Discord ID (snowflake) — permanent']); if(ms > 1420070400000 && ms < Date.now() + 864e5){ F.push(['Created', new Date(ms).toISOString().slice(0, 19).replace('T', ' ') + ' UTC']); if(Date.now() - ms < 30 * 864e5) out.push({lvl:'warn', t:'Made in the last 30 days', why:'A new account or server — common for scams that are set up, used and abandoned.'}); } }
  else if(k === 'session'){ F.push(['Type', 'Session messenger ID — an ed25519 key; no phone number or email behind it']); F.push(['Note', 'Anyone who has it can message the owner; it never changes unless they make a new account']); }
  else if(k === 'tox'){ F.push(['Type', 'Tox ID — public key, anti-spam value and checksum']); const b = String(v).match(/../g).map(h => parseInt(h, 16)); let a = 0, c = 0; for(let i = 0; i < 36; i += 2){ a ^= b[i]; c ^= b[i + 1]; } if(a === b[36] && c === b[37]) F.push(['Checksum', 'Valid']); else out.push({lvl:'bad', t:'Checksum fails', why:'Not a working Tox ID — a typo or a truncated copy.'}); }
  else if(k === 'pgp'){ const K = ipfPgpKey(String(v).toUpperCase());
    F.push(['Key ID', String(v).slice(-16).replace(/(.{4})(?=.)/g, '$1 ')]);
    if(!K){ F.push(['Key', 'Only the fingerprint is in your evidence — paste the public key block to read its names, emails and date']); return; }
    F.push(['Algorithm', K.algo + (K.bits ? ' ' + K.bits + ' bits' : K.curve ? ' · ' + K.curve : '')]); if(K.created) F.push(['Created', new Date(K.created).toISOString().slice(0, 10)]);
    for(const u of K.uids.slice(0, 4)) F.push(['User ID', u]); if(K.uids.length > 4) F.push(['User IDs', '+' + (K.uids.length - 4) + ' more']);
    if(K.subs.length) F.push(['Subkeys', K.subs.map(x => x.algo + (x.curve ? ' ' + x.curve : x.bits ? ' ' + x.bits : '')).join(', ')]);
    if(K.algo === 'RSA' && K.bits && K.bits < 2048) out.push({lvl:'warn', t:'Weak key (' + K.bits + '-bit RSA)', why:'Below today’s minimum; old, or made by someone careless.'});
    if(K.algo === 'DSA') out.push({lvl:'info', t:'DSA key', why:'An old algorithm — the key, or its owner’s habits, date from before about 2015.'});
    if(K.uids.length > 1) out.push({lvl:'info', t:K.uids.length + ' names on one key', why:'Each user ID was added by the key’s owner — every name and email here belongs to the same person or group.'});
    if(K.created && K.created > Date.now() - 30 * 864e5) out.push({lvl:'info', t:'Made in the last 30 days', why:'A fresh key: a new identity, or a rebrand. Look for an older key under the same names.'}); }
  else if(k === 'btctx'){ F.push(['Type', 'Bitcoin transaction ID — 32 bytes, hex']); F.push(['Why not a file hash', 'It sits next to transaction words or a block-explorer link']); }
  else if(k === 'ethtx'){ F.push(['Type', 'Ethereum transaction hash (also BSC, Polygon, Arbitrum…)']); }
  else if(k === 'soltx'){ F.push(['Type', 'Solana transaction signature — 64 bytes, base58']); }
  else if(k === 'email' && typeof idEmail === 'function'){ const I = idEmail(v); if(!I) return;
    F.push(['Mailbox', I.free ? 'Free webmail' : I.disposable ? 'Throwaway' : 'Organisation or private domain']); if(I.canon !== I.e) F.push(['Same inbox as', I.canon]); if(I.tag) F.push(['Tag', '+' + I.tag + ' — the owner made this address for one site']);
    if(I.disposable) out.push({lvl:'warn', t:'Throwaway mailbox', why:'Made in seconds, gone in hours — used to avoid being traced.'});
    if(I.role) out.push({lvl:'info', t:'Role mailbox (' + I.user + ')', why:'Read by a team, not one person.'});
    ipfDomain(I.dom, [], out); }
  else if(k === 'cve'){ const y = +(/CVE-(\d{4})-/.exec(v) || [])[1]; if(y) F.push(['Year', y + (y < new Date().getFullYear() - 3 ? ' — old; still exploited where unpatched' : '')]); }
}

/* the profile of one indicator: {facts:[[label, value]], flags:[{lvl, t, why}]} */
function ipfProfile(k, v){
  const key = k + ':' + v, c = IPF.cache.get(key); if(c && c.at === ipfMineStamp()) return c.p;
  const F = [], out = [];
  try{ if(k === 'domain') ipfDomain(String(v), F, out); else if(k === 'url') ipfUrl(String(v), F, out); else if(k === 'ipv4' || k === 'ipv6' || k === 'hostport') ipfIp(k, String(v), F, out); else ipfMisc(k, String(v), F, out); }catch(e){ console.warn('[profile]', e); }
  const rank = {bad:0, warn:1, info:2}, p = {facts:F, flags:out.sort((a, b) => rank[a.lvl] - rank[b.lvl])};
  if(IPF.cache.size > IPF.MAX) IPF.cache.clear(); IPF.cache.set(key, {at:ipfMineStamp(), p}); return p;
}
let IPF_ST = {t:0, v:''};
const ipfMineStamp = () => { const n = performance.now(); if(n - IPF_ST.t > 40){ IPF_ST = {t:n, v:(DB && DB.verdicts ? Object.keys(DB.verdicts).length : 0) + ':' + (DB && DB.entries ? DB.entries.length : 0) + ':' + (DB && DB.records ? DB.records.length : 0)}; } return IPF_ST.v; };
const ipfWorst = (k, v) => { const f = ipfProfile(k, v).flags[0]; return f && f.lvl !== 'info' ? f : null; };
const IPF_ICO = {bad:'shield-alert', warn:'triangle-alert', info:'info'};
/* extracted URLs are kept in lower case; their query (a base64 email, a token) needs the case it was written in */
function ipfOrig(k, v){
  if(k !== 'url' || typeof globalEnts !== 'function') return v; const g = globalEnts().get(k + ':' + v); if(!g) return v;
  for(const r of g.recs.slice(0, 30)){ if(!r) continue; const b = E.refang ? E.refang(r.body || '') : (r.body || ''), i = b.toLowerCase().indexOf(v); if(i >= 0) return b.substr(i, v.length); }
  return v;
}
function ipfSection(k, v){
  IPF_ST.t = 0; const P = ipfProfile(k, ipfOrig(k, v)); if(!P.flags.length && !P.facts.length) return '';
  return `<div class="isec ipf"><h4>Profile <span class="t3">read from the value — nothing looked up</span></h4>
    ${P.flags.map(f => `<div class="ipf-f ${f.lvl}"><span class="ipf-i">${ico(IPF_ICO[f.lvl],'sm')}</span><div><b>${esc(f.t)}</b>${f.why ? `<small>${esc(f.why)}</small>` : ''}</div></div>`).join('')}
    ${P.facts.length ? `<dl class="kv ipf-kv">${P.facts.map(([a, b]) => `<dt>${esc(a)}</dt><dd class="${/^(Shown as|Written as|Registered name|Host|Path|Holds IPv4|Built from MAC|Same inbox as|Goes on to|Subdomain)$/.test(a) ? 'mono' : ''}">${esc(b)}</dd>`).join('')}</dl>` : ''}</div>`;
}

/* ---------- secrets in captured text ---------- */
const IPF_SECRETS = [
  ['aws', 'AWS access key', /\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b/g, 'Lets whoever holds it act in that AWS account. The owner should deactivate it.'],
  ['awssec', 'AWS secret key', /aws_?secret_?access_?key["'\s:=]+([A-Za-z0-9/+=]{40})\b/gi, 'The other half of an AWS key pair.'],
  ['gh', 'GitHub token', /\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,90})\b/g, 'Access to someone’s GitHub repositories. GitHub revokes leaked tokens it is told about.'],
  ['gl', 'GitLab token', /\b(glpat-[A-Za-z0-9_-]{20})\b/g, 'Access to GitLab projects.'],
  ['slack', 'Slack token', /\b(xox[abposr]-[0-9A-Za-z-]{10,72})\b/g, 'Reads or posts in a Slack workspace.'],
  ['slackhook', 'Slack webhook', /(https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{6,12}\/B[A-Z0-9]{6,12}\/[A-Za-z0-9]{20,32})/g, 'Posts into a Slack channel — sometimes how stolen data is sent out.'],
  ['dischook', 'Discord webhook', /(https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d{15,21}\/[\w-]{50,80})/g, 'Stealers and phishing kits post stolen data to a Discord channel this way. The webhook ID identifies the server it posts to.'],
  ['tg', 'Telegram bot token', /\b(\d{8,10}:AA[\w-]{33})\b/g, 'Phishing kits send stolen logins to a Telegram bot. With the token, getMe shows the bot’s name — and the operator’s chat may be found from it. Handle with your legal team.'],
  ['gapi', 'Google API key', /\b(AIza[0-9A-Za-z_-]{35})\b/g, 'Billed to its owner’s Google Cloud project; often restricted, sometimes not.'],
  ['stripe', 'Stripe live key', /\b((?:sk|rk)_live_[0-9a-zA-Z]{24,99})\b/g, 'Takes payments and refunds on a real Stripe account.'],
  ['openai', 'OpenAI API key', /\b(sk-(?:proj-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}|sk-proj-[A-Za-z0-9_-]{40,})\b/g, 'Billed to its owner’s OpenAI account.'],
  ['anthropic', 'Anthropic API key', /\b(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,110})\b/g, 'Billed to its owner’s Anthropic account.'],
  ['npm', 'npm token', /\b(npm_[A-Za-z0-9]{36})\b/g, 'Publishes packages as its owner — a supply-chain risk.'],
  ['sendgrid', 'SendGrid key', /\b(SG\.[\w-]{22}\.[\w-]{43})\b/g, 'Sends email as its owner — phishing from a trusted sender.'],
  ['mailgun', 'Mailgun key', /\b(key-[0-9a-f]{32})\b/g, 'Sends email as its owner.'],
  ['azure', 'Azure storage key', /AccountKey=([A-Za-z0-9+/]{86}==)/g, 'Full access to an Azure storage account.'],
  ['nsec', 'Nostr private key', /\b(nsec1[02-9ac-hj-np-z]{58})\b/g, 'Whoever holds it is this Nostr account: posts, messages and zaps in its name. It can never be changed; the owner can only abandon the account.'],
  ['pkey', 'Private key', /(-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----)/g, 'Whoever holds it can be its owner — sign, decrypt, log in.'],
  ['jwt', 'JSON Web Token', /\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{0,})/g, 'A login session or API credential while it is valid.'],
  ['urlpass', 'Password in a link', /\b((?:https?|ftp|smb|mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s:@/]{1,64}:[^\s@/]{1,64}@[^\s/]+)/gi, 'A user name and password written into an address.']];
const ipfMask = s => s.length <= 12 ? s.slice(0, 2) + '…' : s.slice(0, 6) + '…' + s.slice(-4);
function ipfJwt(t){ try{ const d = x => JSON.parse(decodeURIComponent(escape(atob(x.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((x.length + 3) % 4))))); const [h, p] = t.split('.'), H = d(h), P = d(p), out = [];
  if(H.alg && !/^none$/i.test(H.alg)) out.push('signed with ' + H.alg); if(P.iss) out.push('issued by ' + String(P.iss).slice(0, 80)); if(P.sub) out.push('for ' + String(P.sub).slice(0, 60)); if(P.aud) out.push('to ' + String(Array.isArray(P.aud) ? P.aud[0] : P.aud).slice(0, 60));
  if(P.exp){ const e = P.exp * 1000; out.push((e < Date.now() ? 'expired ' : 'expires ') + E.fmtDate(e, tz())); } return {txt:out.join(', '), none:/^none$/i.test(H.alg || ''), live:P.exp ? P.exp * 1000 > Date.now() : null}; }catch(e){ return null; } }
function ipfSecrets(text){
  const t = String(text || '').slice(0, 400000), out = [], seen = new Set();
  for(const [id, label, re, why] of IPF_SECRETS){ re.lastIndex = 0; let m; while((m = re.exec(t)) && out.length < 20){ const v = m[1]; if(seen.has(v)) continue; seen.add(v);
    if(id === 'aws' && /EXAMPLE$/.test(v)){ out.push({id, label, mask:ipfMask(v), why:'AWS’s own documentation example — not a real key.', lvl:'info'}); continue; }
    if(id === 'jwt'){ const J = ipfJwt(v); if(!J) continue; out.push({id, label, mask:ipfMask(v), why:(J.txt ? J.txt[0].toUpperCase() + J.txt.slice(1) + '. ' : '') + (J.none ? 'Unsigned (alg “none”) — anyone can forge one like it. ' : '') + why, lvl:J.live === false ? 'info' : 'bad'}); continue; }
    if(id === 'urlpass'){ const mm = /^([^:]+:\/\/)([^:]+):([^@]+)@(.+)$/.exec(v); out.push({id, label, mask:mm ? mm[1] + mm[2] + ':••••@' + mm[4] : ipfMask(v), why, lvl:'bad'}); continue; }
    if(id === 'tg'){ out.push({id, label, mask:v.split(':')[0] + ':AA…' + v.slice(-4), why:'Bot ID ' + v.split(':')[0] + '. ' + why, lvl:'bad'}); continue; }
    if(id === 'pkey'){ out.push({id, label, mask:v, why, lvl:'bad'}); continue; }
    out.push({id, label, mask:ipfMask(v), why, lvl:'bad'}); } }
  return out;
}
/* for the record inspector */
const IPF_SEC_C = new WeakMap();
function ipfRecSecrets(r){ const k = (r.title || '').length + ':' + (r.body || '').length, c = IPF_SEC_C.get(r); if(c && c.k === k) return c.v; const v = ipfSecrets((r.title || '') + '\n' + (r.body || '')); IPF_SEC_C.set(r, {k, v}); return v; }
function ipfRecSection(r){
  IPF_ST.t = 0; const S = ipfRecSecrets(r), L = [], seen = new Set();
  const body = E.refang ? E.refang(r.body || '') : (r.body || ''), low = body.toLowerCase();
  for(const e of r.ents || []){ if(!/^(domain|url|email)$/.test(e.k)) continue; const i = e.k === 'url' ? low.indexOf(e.v) : -1;
    for(const f of ipfProfile(e.k, i >= 0 ? body.substr(i, e.v.length) : e.v).flags) if((f.lvl === 'bad' || f.em) && !seen.has(f.t)){ seen.add(f.t); L.push({e, f}); }
    if(L.length >= 8) break; }
  if(!S.length && !L.length) return '';
  return `<div class="isec ipf"><h4>Worth a second look <span class="t3">read from the text — nothing looked up</span></h4>
    ${L.map(({e, f}) => `<button class="ipf-f bad li" data-act="selEnt" data-id="${esc(entKey(e))}"><span class="ipf-i">${ico(IPF_ICO.bad,'sm')}</span><div><b><span class="mono">${esc(e.v.length > 60 ? e.v.slice(0, 58) + '…' : e.v)}</span> — ${esc(f.t.toLowerCase().startsWith('looks like') || f.t.startsWith('One letter') ? f.t[0].toLowerCase() + f.t.slice(1) : f.t[0].toLowerCase() + f.t.slice(1))}</b><small>${esc(f.why)}</small></div></button>`).join('')}
    ${S.map(s => `<div class="ipf-f ${s.lvl}"><span class="ipf-i">${ico(s.lvl === 'bad' ? 'key-round' : 'info','sm')}</span><div><b>${esc(s.label)} <span class="mono ipf-m">${esc(s.mask)}</span></b><small>${esc(s.why)}</small></div></div>`).join('')}
    ${S.some(s => s.lvl === 'bad') ? `<p class="t3 small ipf-n">Secrets are shown masked. Do not try them — tell the owner or the service so they can revoke them.</p>` : ''}</div>`;
}
/* the flag a vault entry shows on its card and row: the worst look-alike or URL trick; with warn, warnings count too */
function ipfEntryFlag(e, warn){
  const k = typeof entryKey === 'function' ? entryKey(e) : null; if(!k) return null; const {k:kind, v} = entSplit(k); if(!/^(domain|url|email|btc|ipv4|ipv6)$/.test(kind)) return null;
  const f = ipfWorst(kind, v); return f && (f.lvl === 'bad' || warn) ? f : null;
}
