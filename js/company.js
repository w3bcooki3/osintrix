/* ==========================================================================
   Company footprint (Forensics kit → Company footprint) — what a company runs, read from public DNS and
   Certificate Transparency: mail provider and filtering, the SaaS it signed
   up for (verification records), who may send mail as it (SPF, DKIM
   selectors), its DMARC policy and reporters, Microsoft 365 / Entra and
   other identity hints, the CAs allowed to issue for it, and every host name
   ever put in a certificate. Queries go only through the sources you switched
   on (Google DNS, CertSpotter); nothing touches the company's own servers.
   ========================================================================== */
const FP_MX = [[/aspmx\.l\.google\.com|googlemail\.com|google\.com$/i, 'Google Workspace'], [/mail\.protection\.outlook\.com/i, 'Microsoft 365 (Exchange Online)'], [/pphosted\.com|ppe-hosted\.com/i, 'Proofpoint (mail filtering)'], [/mimecast/i, 'Mimecast (mail filtering)'],
  [/barracudanetworks|ess\.barracuda/i, 'Barracuda (mail filtering)'], [/messagelabs|symanteccloud/i, 'Broadcom / Symantec Email Security'], [/iphmx\.com/i, 'Cisco Secure Email (IronPort)'], [/trendmicro|tmes\.trendmicro/i, 'Trend Micro Email Security'], [/sophos/i, 'Sophos Email'],
  [/zoho/i, 'Zoho Mail'], [/protonmail|proton\.me/i, 'Proton Mail'], [/yandex/i, 'Yandex Mail'], [/secureserver\.net/i, 'GoDaddy mail'], [/emailsrvr\.com/i, 'Rackspace Email'], [/mx\.cloudflare\.net/i, 'Cloudflare Email Routing'], [/hornetsecurity|hornetdrive/i, 'Hornetsecurity'], [/forcepoint|mailcontrol/i, 'Forcepoint Email'], [/fireeyecloud|trellix/i, 'Trellix Email Security'], [/icloud\.com/i, 'iCloud Mail'], [/ovh\.net/i, 'OVHcloud mail'], [/mailgun/i, 'Mailgun (inbound)']];
const FP_SPF = [[/spf\.protection\.outlook\.com/i, 'Microsoft 365'], [/_spf\.google\.com/i, 'Google Workspace'], [/sendgrid\.net/i, 'SendGrid (Twilio)'], [/mailgun\.org/i, 'Mailgun'], [/amazonses\.com/i, 'Amazon SES'], [/servers\.mcsv\.net/i, 'Mailchimp'], [/mandrillapp\.com/i, 'Mailchimp Transactional (Mandrill)'],
  [/_spf\.salesforce\.com|exacttarget|cust-spf\.exacttarget/i, 'Salesforce / Marketing Cloud'], [/mail\.zendesk\.com/i, 'Zendesk'], [/freshdesk|freshemail|fresh-mail/i, 'Freshworks'], [/hubspotemail\.net|hubspot/i, 'HubSpot'], [/mtasv\.net/i, 'Postmark'], [/mktomail\.com/i, 'Adobe Marketo'], [/sparkpostmail\.com/i, 'SparkPost'],
  [/_spf\.atlassian\.net/i, 'Atlassian'], [/pphosted\.com/i, 'Proofpoint'], [/mimecast/i, 'Mimecast'], [/messagelabs/i, 'Symantec'], [/zoho/i, 'Zoho'], [/mailjet/i, 'Mailjet'], [/sendinblue|brevo/i, 'Brevo'], [/constantcontact/i, 'Constant Contact'], [/smtp\.servicenow\.com|service-now/i, 'ServiceNow'], [/docusign/i, 'DocuSign'], [/workday/i, 'Workday'], [/qualtrics/i, 'Qualtrics'], [/intercom/i, 'Intercom'], [/klaviyo/i, 'Klaviyo']];
const FP_DKIM = [['selector1', 'Microsoft 365'], ['selector2', 'Microsoft 365'], ['google', 'Google Workspace'], ['k1', 'Mailchimp'], ['k2', 'Mailchimp'], ['s1', 'SendGrid'], ['s2', 'SendGrid'], ['mandrill', 'Mandrill'], ['hs1', 'HubSpot'], ['hs2', 'HubSpot'], ['zendesk1', 'Zendesk'], ['mxvault', 'Mimecast'], ['pm', 'Postmark'], ['smtp', 'Mailgun'], ['dkim', 'generic'], ['default', 'generic']];
const FP_CNAME = [['autodiscover', 'Microsoft 365 / Exchange (mail client set-up)'], ['lyncdiscover', 'Microsoft Teams / Skype for Business'], ['sip', 'Microsoft Teams / SIP'], ['enterpriseenrollment', 'Microsoft Intune (device management)'], ['enterpriseregistration', 'Entra ID device registration'],
  ['vpn', 'VPN'], ['remote', 'Remote access'], ['owa', 'Outlook Web Access'], ['webmail', 'Webmail'], ['mail', 'Mail'], ['sso', 'Single sign-on'], ['login', 'Sign-in'], ['adfs', 'AD FS (federated sign-in)'], ['sts', 'Security token service (federation)'], ['citrix', 'Citrix'], ['gitlab', 'GitLab'], ['jira', 'Jira'], ['confluence', 'Confluence'], ['status', 'Status page'], ['support', 'Support portal'], ['helpdesk', 'Help desk']];
const fpVerif = txt => { const t = txt.replace(/^"|"$/g, '').replace(/"\s*"/g, '');
  const K = [[/^MS=ms\d+/i, 'Microsoft 365'], [/^google-site-verification=/i, 'Google (Search Console / Workspace)'], [/^facebook-domain-verification=/i, 'Meta (Facebook) business'], [/^apple-domain-verification=/i, 'Apple'], [/^atlassian-domain-verification=/i, 'Atlassian (Jira, Confluence)'], [/^docusign=/i, 'DocuSign'],
    [/^adobe-idp-site-verification=|^adobe-sign-verification=/i, 'Adobe'], [/^ZOOM_verify_/i, 'Zoom'], [/^slack-domain-verification=/i, 'Slack'], [/^stripe-verification=/i, 'Stripe'], [/^dropbox-domain-verification=/i, 'Dropbox'], [/^citrix-verification-code=/i, 'Citrix'], [/^cisco-ci-domain-verification=|^webexdomainverification/i, 'Cisco Webex'],
    [/^knowbe4-site-verification=/i, 'KnowBe4 (phishing training)'], [/^miro-verification=/i, 'Miro'], [/^onetrust-domain-verification=/i, 'OneTrust'], [/^openai-domain-verification=/i, 'OpenAI'], [/^anthropic-domain-verification/i, 'Anthropic'], [/^canva-site-verification=/i, 'Canva'], [/^twilio-domain-verification=/i, 'Twilio'], [/^postman-domain-verification=/i, 'Postman'],
    [/^mongodb-site-verification=/i, 'MongoDB Atlas'], [/^logmein-verification-code=/i, 'LogMeIn / GoTo'], [/^yandex-verification:/i, 'Yandex'], [/^pinterest-site-verification=/i, 'Pinterest'], [/^globalsign-domain-verification=/i, 'GlobalSign (certificates)'], [/^_?globalsign/i, 'GlobalSign'], [/^have-i-been-pwned-verification=/i, 'Have I Been Pwned (domain search)'],
    [/^keybase-site-verification=/i, 'Keybase'], [/^brave-ledger-verification=/i, 'Brave'], [/^amazonses:/i, 'Amazon SES'], [/^teamviewer-sso-verification=/i, 'TeamViewer'], [/^workplace-domain-verification=/i, 'Meta Workplace'], [/^asv=/i, 'Asana'], [/^hubspot-developer-verification=/i, 'HubSpot'], [/^smartsheet-site-validation=/i, 'Smartsheet'],
    [/^wrike-verification=/i, 'Wrike'], [/^klaviyo-site-verification=/i, 'Klaviyo'], [/^ahrefs-site-verification_/i, 'Ahrefs'], [/^status-page-domain-verification=/i, 'Atlassian Statuspage'], [/^cursor-domain-verification/i, 'Cursor'], [/^github-/i, 'GitHub'], [/^gitlab-/i, 'GitLab']];
  for(const [re, n] of K) if(re.test(t)) return n;
  const m = t.match(/^([a-z0-9][a-z0-9_-]{2,40}?)[-_](?:site|domain)?[-_]?verification(?:[-_]code)?[=:]/i); if(m) return m[1].replace(/[-_]/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
  return null; };
async function fpDoh(name, type){ const r = await lkFetch('https://dns.google/resolve?name=' + encodeURIComponent(name) + '&type=' + type, {timeout:12000}); const j = JSON.parse(r.text); return {status:j.Status, ans:(Array.isArray(j.Answer) ? j.Answer : []).map(a => ({type:a.type, data:String(a.data)}))}; }
async function fpRun(dom){
  dom = String(dom || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/[/:?#].*$/, '').replace(/^www\./, ''); if(!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(dom)) throw new Error('Enter a domain like company.com');
  const F = {dom, at:Date.now(), mx:[], txt:[], saas:[], spf:'', spfInc:[], spfSend:[], dmarc:'', dmarcP:'', dmarcRep:[], dkim:[], caa:[], ns:[], a:[], cnames:[], ct:null, err:[]};
  const q = async (n, t) => { try{ return await fpDoh(n, t); }catch(e){ F.err.push(n + ' ' + t + ': ' + e.message); return {status:-1, ans:[]}; } };
  const [mx, txt, dm, caa, ns, a] = await Promise.all([q(dom, 'MX'), q(dom, 'TXT'), q('_dmarc.' + dom, 'TXT'), q(dom, 'CAA'), q(dom, 'NS'), q(dom, 'A')]);
  if(mx.status === 3 && txt.status === 3) throw new Error(dom + ' does not exist in DNS');
  F.mx = mx.ans.filter(x => x.type === 15).map(x => x.data.replace(/^\d+\s+/, '').replace(/\.$/, '').toLowerCase()); F.mxProv = [...new Set(F.mx.map(m => (FP_MX.find(([re]) => re.test(m)) || [])[1]).filter(Boolean))];
  F.txt = txt.ans.filter(x => x.type === 16).map(x => x.data.replace(/^"|"$/g, '').replace(/"\s*"/g, ''));
  F.saas = [...new Set(F.txt.map(fpVerif).filter(Boolean))];
  F.spf = F.txt.find(t => /^v=spf1/i.test(t)) || ''; F.spfInc = [...F.spf.matchAll(/\b(?:include|redirect)[:=]([^\s]+)/gi)].map(m => m[1].toLowerCase()); F.spfIp = [...F.spf.matchAll(/\bip[46]:([^\s]+)/gi)].map(m => m[1]);
  F.spfSend = [...new Set(F.spfInc.map(i => (FP_SPF.find(([re]) => re.test(i)) || [])[1]).filter(Boolean))]; F.spfAll = (F.spf.match(/[~?+-]all\b/) || [''])[0];
  F.dmarc = dm.ans.filter(x => x.type === 16).map(x => x.data.replace(/^"|"$/g, '').replace(/"\s*"/g, '')).find(t => /^v=DMARC1/i.test(t)) || '';
  F.dmarcP = (F.dmarc.match(/\bp=(\w+)/i) || [])[1] || ''; F.dmarcRep = [...new Set([...F.dmarc.matchAll(/mailto:[^@,;\s]+@([^,;!\s]+)/gi)].map(m => m[1].toLowerCase()))];
  F.caa = caa.ans.filter(x => x.type === 257).map(x => x.data); F.ns = ns.ans.filter(x => x.type === 2).map(x => x.data.replace(/\.$/, '').toLowerCase()); F.a = a.ans.filter(x => x.type === 1).map(x => x.data);
  /* DKIM selectors and the well-known service names, in parallel */
  const dk = await Promise.all(FP_DKIM.map(async ([s, who]) => { const r = await q(s + '._domainkey.' + dom, 'TXT'); const ok = r.ans.some(x => /v=DKIM1|k=rsa|p=/.test(x.data)) || r.ans.some(x => x.type === 5); return ok ? [s, who, (r.ans.find(x => x.type === 5) || {}).data || ''] : null; }));
  F.dkim = dk.filter(Boolean);
  const cn = await Promise.all(FP_CNAME.map(async ([s, what]) => { const r = await q(s + '.' + dom, 'A'); if(r.status !== 0 || !r.ans.length) return null; const c = r.ans.filter(x => x.type === 5).map(x => x.data.replace(/\.$/, '')); return [s + '.' + dom, what, c[c.length - 1] || '', r.ans.filter(x => x.type === 1).map(x => x.data)]; }));
  F.cnames = cn.filter(Boolean);
  F.m365 = F.mxProv.includes('Microsoft 365 (Exchange Online)') || F.saas.includes('Microsoft 365') || F.spfSend.includes('Microsoft 365') || F.cnames.some(c => /outlook\.com|lync\.com|manage\.microsoft\.com|enterpriseregistration\.windows\.net/i.test(c[2]));
  F.gws = F.mxProv.includes('Google Workspace') || F.spfSend.includes('Google Workspace');
  F.fed = F.cnames.filter(c => /^(adfs|sts|sso|login)\./.test(c[0])).map(c => c[0]);
  return F;
}
/* every host name in the company's certificates (CertSpotter), with the first time each appeared */
async function fpCt(dom){
  const p = lkProv('cs'), spec = p.req('domain', dom, lkSettings().keys.cs || ''), w = lkWire(p, spec); await lkPace('cs');
  const r = await lkFetch(w.url, {headers:w.headers, noRedirect:w.noRedirect, timeout:25000}); const L = JSON.parse(r.text); if(!Array.isArray(L)) throw new Error('Unexpected answer');
  const H = new Map(), iss = new Map(); for(const c of L){ const nb = Date.parse(c.not_before || '') || 0; const who = c.issuer ? (c.issuer.friendly_name || c.issuer.name || '') : ''; if(who) iss.set(who, (iss.get(who) || 0) + 1);
    for(const n of c.dns_names || []){ const h = String(n).toLowerCase().replace(/^\*\./, '*.'); const x = H.get(h); if(!x) H.set(h, {h, first:nb, last:nb, n:1}); else { x.n++; if(nb && nb < x.first) x.first = nb; if(nb > x.last) x.last = nb; } } }
  return {certs:L.length, hosts:[...H.values()].sort((a, b) => b.first - a.first), issuers:[...iss.entries()].sort((a, b) => b[1] - a[1]), more:L.length >= 100};
}
const FP_HOT = /(^|\.)(dev|test|stage|staging|uat|qa|preprod|beta|old|legacy|backup|bak|admin|internal|intranet|vpn|remote|jenkins|gitlab|git|jira|grafana|kibana|elastic|sso|auth|api|portal|citrix|owa|webmail|mail|ftp|sftp|db|sql|vault|k8s|kube|argo|minio|s3)[.\d-]/i;
function labFoot(){
  const F = UI.fp, dnsOn = typeof lkProv === 'function' && lkOn(lkProv('dns')), csOn = typeof lkProv === 'function' && lkOn(lkProv('cs'));
  const form = `<section class="card"><header><h3>${ico('building-2','sm')} Company footprint</h3><span class="t3">mail, SaaS, identity and every host in its certificates — from public DNS and CT logs</span></header><div class="body">
    <form class="lk-q" data-form="fpGo"><div class="search-in">${ico('globe')}<label class="sr" for="fpD">Company domain</label><input id="fpD" class="inp mono" value="${esc(F && F.dom || UI.fpD || '')}" placeholder="company.com" autocomplete="off" spellcheck="false"></div><button class="btn primary" type="submit" ${dnsOn ? '' : 'disabled'}>${ico('radar','sm')}${F && F.busy ? 'Reading…' : 'Read the footprint'}</button></form>
    ${!dnsOn || !csOn ? `<div class="ti-relay">${ico('wifi-off','sm')}<span>This sends DNS questions about the domain to Google DNS (<span class="mono">dns.google</span>)${csOn ? '' : ' and asks CertSpotter (<span class="mono">api.certspotter.com</span>) for its certificates'}. Nothing is sent to the company itself.</span><button class="btn sm" data-act="fpOn">Allow ${dnsOn ? '' : 'Google DNS'}${!dnsOn && !csOn ? ' and ' : ''}${csOn ? '' : 'CertSpotter'}</button></div>` : ''}</div></section>`;
  if(!F || F.busy) return `<div class="labgrid one wide">${form}${F && F.busy ? `<div class="card" style="padding:30px;text-align:center">${ico('refresh-cw','sm spin')} Reading DNS for ${esc(F.dom)}…</div>` : ''}</div>`;
  if(F.error) return `<div class="labgrid one wide">${form}<div class="note red"><span class="ic">${ico('triangle-alert','sm')}</span><div>${esc(F.error)}</div></div></div>`;
  const chips = L => L.map(x => `<span class="chip sq">${esc(x)}</span>`).join('');
  const risks = [];
  if(!F.dmarc) risks.push(['red', 'No DMARC record — anyone can send mail as @' + F.dom + ' and most receivers will not reject it.']);
  else if(/^none$/i.test(F.dmarcP)) risks.push(['amber', 'DMARC is at p=none — spoofed mail is reported, not blocked.']);
  if(F.spf && /\+all|\?all/.test(F.spfAll)) risks.push(['red', 'SPF ends in ' + F.spfAll + ' — it allows any server to send as the domain.']);
  if(!F.spf) risks.push(['amber', 'No SPF record.']);
  if(F.spfInc.length > 8) risks.push(['', F.spfInc.length + ' SPF includes — every service listed can send mail that passes SPF for the domain.']);
  if(!F.caa.length) risks.push(['', 'No CAA record — any certificate authority may issue certificates for the domain.']);
  const ct = F.ct, hot = ct && ct.hosts ? ct.hosts.filter(h => FP_HOT.test(h.h + '.')) : [];
  return `<div class="labgrid one wide">${form}
    <div class="fp-grid">
      <section class="card"><header><h3>${ico('mail','sm')} Mail</h3></header><div class="body">
        ${fxKv('Mail provider', F.mxProv.join(', ') || (F.mx.length ? 'self-hosted or other' : 'none (no MX)'))}${F.mx.length ? `<div class="kv"><span>MX</span><code>${esc(F.mx.join(' '))}</code></div>` : ''}
        ${fxKv('SPF senders', F.spfSend.join(', '))}${F.spf ? `<div class="kv"><span>SPF</span><code>${esc(F.spf)}</code></div>` : ''}
        ${F.dkim.length ? fxKv('DKIM selectors', F.dkim.map(([s, w]) => s + (w !== 'generic' ? ' (' + w + ')' : '')).join(', ')) : ''}
        ${fxKv('DMARC', F.dmarc ? 'p=' + (F.dmarcP || '?') + (F.dmarcRep.length ? ' · reports to ' + F.dmarcRep.join(', ') : '') : 'none')}
        ${risks.map(([t, x]) => `<div class="fx-note ${t}">${esc(x)}</div>`).join('')}</div></section>
      <section class="card"><header><h3>${ico('layers','sm')} SaaS and identity</h3></header><div class="body">
        ${F.saas.length ? `<div class="kv"><span>Verified with</span><span class="wrap">${chips(F.saas)}</span></div>` : '<p class="t3 small" style="margin:0 0 8px">No verification records — or they were cleaned up after use.</p>'}
        ${fxKv('Microsoft 365 / Entra', F.m365 ? 'yes' : '')}${fxKv('Google Workspace', F.gws ? 'yes' : '')}${F.fed.length ? fxKv('Federated sign-in hosts', F.fed.join(', ')) : ''}
        ${F.cnames.length ? `<h5 class="fx-g">Service names that exist</h5>${F.cnames.map(([h, w, c, ips]) => `<div class="kv"><span>${esc(w)}</span><code>${esc(h)}${c ? ' → ' + esc(c) : ips.length ? ' → ' + esc(ips[0]) : ''}</code></div>`).join('')}` : ''}
        ${F.caa.length ? fxKv('Certificate authorities allowed (CAA)', F.caa.map(x => x.replace(/^\d+\s+(issue|issuewild|iodef)\s+/, '$1 ')).join(' · ')) : ''}${F.ns.length ? fxKv('Name servers', F.ns.join(', ')) : ''}
        ${F.m365 ? `<p class="t3 small" style="margin:8px 0 0">Microsoft 365: the tenant ID comes from <span class="mono">login.microsoftonline.com/${esc(F.dom)}/.well-known/openid-configuration</span> — open it in your research browser (Cloud → Field guide → Cloud OSINT).</p>` : ''}</div></section>
    </div>
    <section class="card"><header><h3>${ico('shield-check','sm')} Host names in its certificates</h3>${ct && ct.hosts ? `<span class="t3">${ct.hosts.length} names from ${ct.certs} certificates${ct.more ? ' (first page — CertSpotter returns 100 at a time)' : ''}</span>` : ''}</header><div class="body">
      ${!csOn ? '<p class="t3" style="margin:0">Allow CertSpotter above to list them.</p>' : !ct ? `<p class="t3" style="margin:0">${ico('refresh-cw','sm spin')} Asking CertSpotter…</p>` : ct.error ? `<div class="note amber" style="margin:0"><span class="ic">${ico('triangle-alert','sm')}</span><div>${esc(ct.error)}</div></div>` : `
      ${hot.length ? `<div class="fx-note amber"><b>${hot.length} names worth a look</b> — staging, admin, VPN, CI and data hosts: ${esc(hot.slice(0, 14).map(h => h.h).join(', '))}${hot.length > 14 ? ' …' : ''}</div>` : ''}
      ${ct.issuers.length ? fxKv('Issued by', ct.issuers.slice(0, 5).map(([n, c]) => n + ' (' + c + ')').join(', ')) : ''}
      <div class="tblw"><table class="tbl fp-t"><thead><tr><th>Host</th><th>First certificate</th><th class="n">Certificates</th></tr></thead><tbody>${ct.hosts.slice(0, UI.fpAll ? 2000 : 40).map(h => `<tr><td class="mono">${esc(h.h)}</td><td>${h.first ? esc(new Date(h.first).toISOString().slice(0, 10)) : ''}</td><td class="n">${h.n}</td></tr>`).join('')}</tbody></table></div>
      ${ct.hosts.length > 40 ? `<button class="lnk small" data-act="fpAll">${UI.fpAll ? 'Show fewer' : 'All ' + ct.hosts.length}</button>` : ''}`}</div></section>
    <div class="wrap"><button class="btn primary" data-act="fpSave">${ico('plus','sm')}Save to ${esc(caseNm(theCase()))}</button>${casePick()}<button class="btn" data-act="fpTwist">${ico('copy','sm')}Look-alikes of ${esc(F.dom)}</button><span class="t3 small">Read ${esc(E.fmtFull(F.at, tz()).slice(0, 16))}</span></div></div>`;
}
function fpSummary(F){ return [`Company footprint: ${F.dom} (read ${new Date(F.at).toISOString().slice(0, 16).replace('T', ' ')} UTC)`, 'Mail provider: ' + (F.mxProv.join(', ') || F.mx.join(' ') || 'none'), F.spfSend.length ? 'SPF senders: ' + F.spfSend.join(', ') : '', F.spf ? 'SPF: ' + F.spf : '', 'DMARC: ' + (F.dmarc || 'none'),
  F.dkim.length ? 'DKIM selectors: ' + F.dkim.map(d => d[0]).join(', ') : '', F.saas.length ? 'Verified SaaS: ' + F.saas.join(', ') : '', F.m365 ? 'Microsoft 365 / Entra: yes' : '', F.gws ? 'Google Workspace: yes' : '', ...F.cnames.map(([h, w, c]) => `${w}: ${h}${c ? ' -> ' + c : ''}`),
  F.ct && F.ct.hosts ? 'Hosts in certificates (' + F.ct.hosts.length + '): ' + F.ct.hosts.slice(0, 150).map(h => h.h).join(' ') : ''].filter(Boolean).join('\n'); }
const FP_ACTS = {
  fpOn:() => { const S = lkSettings(); S.on.dns = true; S.on.cs = true; mutate('turned on Google DNS and CertSpotter lookups'); renderMain(); },
  fpAll:() => { UI.fpAll = !UI.fpAll; renderMain(); },
  fpSave:() => { const F = UI.fp; if(!F || F.busy || F.error) return; draft.source = 'company footprint'; openCapture(fpSummary(F)); },
  fpTwist:() => { const F = UI.fp; if(!F) return; UI.tw = {d:F.dom, list:twGen(F.dom)}; UI.labTab = 'twist'; renderMain(); },
};
async function fpGo(dom){
  UI.fpD = dom; UI.fp = {busy:true, dom}; UI.fpAll = false; renderMain();
  try{ const F = await fpRun(dom); UI.fp = F; renderMain();
    if(lkOn(lkProv('cs'))){ try{ F.ct = await fpCt(F.dom); }catch(e){ F.ct = {error:'CertSpotter: ' + e.message + (e.code === 429 ? ' — the free tier allows a few requests an hour; add a key in Settings → Lookups' : '')}; } if(UI.fp === F) renderMain(); }
  }catch(e){ UI.fp = {dom, error:e.message}; renderMain(); }
}
