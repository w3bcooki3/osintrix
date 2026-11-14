/* OSINTrix relay — a small Cloudflare Worker you deploy to your own account.
   It does two things the browser cannot:
     1. reaches services that refuse cross-origin requests (VirusTotal, AbuseIPDB, abuse.ch…)
     2. keeps your API keys server-side, so they never sit in a web page
   It only forwards to the hosts and paths listed below, only for requests that carry
   your RELAY_TOKEN, and only answers the origins you allow. Nothing is logged or stored.
   Secrets (set with `wrangler secret put NAME`): RELAY_TOKEN (required), VT_KEY, ABUSEIPDB_KEY,
   GREYNOISE_KEY, URLSCAN_KEY, NVD_KEY, ABUSECH_KEY, SHODAN_KEY.
   Variable (wrangler.toml): ALLOWED_ORIGINS — comma-separated; "null" allows the app opened from a file. */

const P = {
  vt:              {base:'https://www.virustotal.com/', path:/^api\/v3\/(ip_addresses|domains|urls|files)\/[A-Za-z0-9._:%=-]{1,200}$/, key:'VT_KEY', header:'x-apikey', need:true},
  abuseipdb:       {base:'https://api.abuseipdb.com/', path:/^api\/v2\/check$/, key:'ABUSEIPDB_KEY', header:'Key', need:true},
  greynoise:       {base:'https://api.greynoise.io/', path:/^v3\/community\/[0-9.]{7,15}$/, key:'GREYNOISE_KEY', header:'key'},
  urlscan:         {base:'https://urlscan.io/', path:/^api\/v1\/search\/$/, key:'URLSCAN_KEY', header:'API-Key'},
  crtsh:           {base:'https://crt.sh/', path:/^$/},
  nvd:             {base:'https://services.nvd.nist.gov/', path:/^rest\/json\/cves\/2\.0$/, key:'NVD_KEY', header:'apiKey'},
  shodan:          {base:'https://api.shodan.io/', path:/^shodan\/host\/[0-9a-fA-F.:]{2,45}$/, key:'SHODAN_KEY', query:'key', need:true},
  threatfox:       {base:'https://threatfox-api.abuse.ch/', path:/^api\/v1\/$/, key:'ABUSECH_KEY', header:'Auth-Key', post:true},
  urlhaus:         {base:'https://urlhaus-api.abuse.ch/', path:/^v1\/(url|host)\/$/, key:'ABUSECH_KEY', header:'Auth-Key', post:true},
  malwarebazaar:   {base:'https://mb-api.abuse.ch/', path:/^api\/v1\/$/, key:'ABUSECH_KEY', header:'Auth-Key', post:true},
  'threatfox-export': {base:'https://threatfox.abuse.ch/', path:/^export\/json\/recent\/$/, key:'ABUSECH_KEY', header:'Auth-Key'},
  feodo:           {base:'https://feodotracker.abuse.ch/', path:/^downloads\/ipblocklist_recommended\.json$/, key:'ABUSECH_KEY', header:'Auth-Key'},
  'urlhaus-export':{base:'https://urlhaus.abuse.ch/', path:/^downloads\/csv_recent\/$/, key:'ABUSECH_KEY', header:'Auth-Key'},
};
const MAX_BODY = 4096, MAX_OUT = 25 * 1048576, RATE = 120;            // requests per minute per client address (best effort, per worker instance)
const hits = new Map();

function cors(origin, env){
  const allow = String(env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
  const ok = origin && allow.includes(origin);
  return ok ? {'Access-Control-Allow-Origin':origin, 'Access-Control-Allow-Methods':'GET, POST, OPTIONS', 'Access-Control-Allow-Headers':'X-Relay-Token, Content-Type', 'Access-Control-Max-Age':'600', 'Vary':'Origin'} : null;
}
const json = (o, status, h) => new Response(JSON.stringify(o), {status, headers:{'Content-Type':'application/json', 'Cache-Control':'no-store', ...(h || {})}});
function sameToken(a, b){ if(typeof a !== 'string' || typeof b !== 'string' || !b) return false; const x = new TextEncoder().encode(a), y = new TextEncoder().encode(b); let d = x.length ^ y.length; for(let i = 0; i < y.length; i++) d |= (x[i] || 0) ^ y[i]; return d === 0; }
function limited(ip){ const now = Date.now(), w = hits.get(ip) || []; const r = w.filter(t => now - t < 60000); r.push(now); hits.set(ip, r); if(hits.size > 5000) hits.clear(); return r.length > RATE; }

export default {
  async fetch(req, env){
    const origin = req.headers.get('Origin'), h = cors(origin, env);
    if(!h) return json({error:'Origin not allowed'}, 403);
    if(req.method === 'OPTIONS') return new Response(null, {status:204, headers:h});
    if(!sameToken(req.headers.get('X-Relay-Token') || '', env.RELAY_TOKEN || '')) return json({error:'Bad relay token'}, 401, h);
    if(limited(req.headers.get('CF-Connecting-IP') || 'x')) return json({error:'Slow down'}, 429, h);
    const url = new URL(req.url), parts = url.pathname.replace(/^\/+/, '').split('/'), id = decodeURIComponent(parts.shift() || ''), rest = parts.join('/');
    if(id === 'health') return json({ok:true, providers:Object.keys(P).filter(k => P[k].key && env[P[k].key])}, 200, h);
    const p = Object.prototype.hasOwnProperty.call(P, id) ? P[id] : null;
    if(!p || !p.path.test(rest)) return json({error:'Not an allowed path'}, 404, h);
    if(p.need && !env[p.key]) return json({error:'The relay has no key for ' + id}, 501, h);
    if(req.method === 'POST' && !p.post || req.method !== 'GET' && req.method !== 'POST') return json({error:'Method not allowed'}, 405, h);
    const target = new URL(p.base + rest + url.search);
    const headers = {'Accept':'application/json', 'User-Agent':'osintrix-relay/1'};
    if(p.key && env[p.key]){ if(p.query) target.searchParams.set(p.query, env[p.key]); else headers[p.header] = env[p.key]; }
    let body;
    if(req.method === 'POST'){ body = await req.text(); if(body.length > MAX_BODY) return json({error:'Request too large'}, 413, h); const ct = req.headers.get('Content-Type') || ''; headers['Content-Type'] = /x-www-form-urlencoded/.test(ct) ? 'application/x-www-form-urlencoded' : 'application/json'; }
    let r;
    try{ r = await fetch(target.toString(), {method:req.method, headers, body, redirect:'follow', cf:{cacheTtl:0}}); }
    catch(e){ return json({error:'Upstream unreachable'}, 502, h); }
    const len = +r.headers.get('content-length') || 0; if(len > MAX_OUT) return json({error:'Upstream answer too large'}, 502, h);
    const out = new Headers(h); out.set('Content-Type', r.headers.get('Content-Type') || 'application/octet-stream'); out.set('Cache-Control', 'no-store'); out.set('X-Content-Type-Options', 'nosniff');
    return new Response(r.body, {status:r.status, headers:out});                         // upstream cookies and other headers are not passed on
  }
};
