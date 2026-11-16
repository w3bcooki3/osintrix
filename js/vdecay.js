/* ==========================================================================
   Verdicts age. An IP marked malicious two years ago has likely changed hands;
   a file hash stays bad for ever. Each verdict's date is recorded when it is
   set or changed (checked before every save, so every way of setting one is
   covered); verdicts from before this existed have no date and never fade.
   The weight halves every: 90 days for IPs, 4 months for URLs, 6 for domains,
   a year for emails, handles and wallets — hashes never fade.
   Used by Connected cases (old links count for less), the entity panel (the
   age, and a nudge to check again) and Today (stale verdicts in active cases).
   ========================================================================== */
const VDA_HALF = {ipv4:90, ipv6:90, hostport:90, cidr:90, url:120, domain:180, email:365, username:365, handle:365, phone:365, btc:365, eth:365, crypto:365, md5:0, sha1:0, sha256:0, sha512:0, hash:0};
let VDA_LAST = null;
function vdStamp(){
  if(!DB || !DB.verdicts) return; const now = Date.now(), at = DB.verdictAt && typeof DB.verdictAt === 'object' ? DB.verdictAt : (DB.verdictAt = {});
  if(VDA_LAST === null){ VDA_LAST = {...DB.verdicts}; return; }                    // the first look after loading is the baseline
  for(const [k, v] of Object.entries(DB.verdicts)) if(VDA_LAST[k] !== v) at[k] = now;
  for(const k of Object.keys(at)) if(!DB.verdicts[k]) delete at[k];
  VDA_LAST = {...DB.verdicts};
}
BEFORE_SAVE.push(vdStamp);
const verdictAt = key => { const t = DB && DB.verdictAt ? +DB.verdictAt[key] : 0; return isFinite(t) && t > 0 && t <= Date.now() + 864e5 ? t : null; };
const vdHalf = key => { const k = String(key).split(':')[0]; return VDA_HALF[k] ?? 365; };
/* 1 = as strong as when you set it; 0.5 after one half-life; unknown dates and hashes stay at 1 */
function verdictWeight(key){ const t = verdictAt(key), h = vdHalf(key); if(!t || !h) return 1; return Math.pow(0.5, (Date.now() - t) / 864e5 / h); }
const verdictStale = key => /malicious|suspicious/.test(verdictOf(key)) && verdictWeight(key) < 0.5;
function verdictAgeNote(key){ const t = verdictAt(key); if(!t) return ''; const stale = verdictStale(key);
  return `<p class="vd-age${stale ? ' stale' : ''}">${ico(stale ? 'clock-alert' : 'clock','sm')}<span>Marked ${esc(iAgo(t))}${stale ? ` — ${String(key).split(':')[0].startsWith('ip') ? 'IP addresses change hands' : 'things like this change'}; worth checking again before relying on it` : ''}.</span></p>`; }
