# OSINTrix relay

A tiny Cloudflare Worker you run in **your own** Cloudflare account. OSINTrix uses it for the
lookups a web page cannot make by itself:

- services that refuse requests from browsers — VirusTotal, AbuseIPDB, GreyNoise, urlscan.io,
  crt.sh, NVD and abuse.ch (ThreatFox, URLhaus, MalwareBazaar and their feeds);
- API keys, which stay in the Worker as secrets instead of in the browser.

The relay forwards only to the hosts and paths listed in `worker.js`, only for requests that carry
your relay token, and only to the origins you allow. It stores and logs nothing. The free Workers
plan (100,000 requests a day) is plenty.

## Deploy (about five minutes)

```sh
npm install -g wrangler           # Cloudflare's CLI
cd tools/relay
wrangler login
wrangler secret put RELAY_TOKEN   # make up a long random string; you will paste it into OSINTrix
# then the keys you have — each is optional:
wrangler secret put VT_KEY          # virustotal.com → your profile → API key
wrangler secret put ABUSEIPDB_KEY   # abuseipdb.com → account → API
wrangler secret put GREYNOISE_KEY   # optional; the community API works without one at a low rate
wrangler secret put URLSCAN_KEY     # optional
wrangler secret put NVD_KEY         # optional; raises the NVD rate limit
wrangler secret put ABUSECH_KEY     # auth.abuse.ch — one key for ThreatFox, URLhaus, MalwareBazaar
wrangler secret put SHODAN_KEY      # optional; or enter the key in OSINTrix instead
wrangler deploy
```

Edit `ALLOWED_ORIGINS` in `wrangler.toml` first if you open OSINTrix from anywhere other than a
local file or `localhost:8000`.

`wrangler deploy` prints the address, e.g. `https://osintrix-relay.<you>.workers.dev`. In OSINTrix open
**Threat Intel → Sources → Lookups**, paste the address and the token, and press **Test relay**.

A `*.workers.dev` address is already allowed by the app's Content Security Policy. If you put the
relay on your own domain, add it to `connect-src` in `index.html` (and `tools/bundle.py`).

## Hardening

- Keep the token secret; anyone with it and an allowed origin can spend your API quotas.
  Rotate it with `wrangler secret put RELAY_TOKEN`.
- The built-in rate limit (120 requests a minute per address) is per Worker instance. For a strict
  limit add a Cloudflare **Rate limiting rule** on the Worker's route.
- `"null"` in `ALLOWED_ORIGINS` admits any page opened from a file, sandboxed frames and `data:` pages — the token still protects the relay, but remove `"null"` if you host OSINTrix at an address.
- Failed token guesses count towards the rate limit.
- To remove a service, delete its line from `P` in `worker.js` and redeploy.
