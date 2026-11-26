# The Blackbook — doctrine: how a hunter thinks, and the attacker's first checks turned into the defender's.
# Each principle: (title, body). Each mirror row: (what they look for, why it pays for them, your check).

DOCTRINE = [
  ("Hunt behaviour, not indicators",
   "Hashes, IPs and domains cost the adversary nothing to change; tools cost a little, and tradecraft costs the most (David Bianco's Pyramid of Pain). "
   "A hunt written against what the attacker has to do — dump a credential, move over SMB, call home on a timer — survives their next rebuild. Indicators are for scoping an incident you already have, not for finding one you don't."),
  ("Every hunt ends in one of three outcomes",
   "A detection that now runs on its own, a hardening ticket that removes the opportunity, or a written negative: the hypothesis, the data you searched, the time range, and why you are confident nothing was there. "
   "A hunt that ends in 'nothing found' with no record will be repeated by the next analyst."),
  ("Start from a hypothesis you can falsify",
   "Not 'look for bad things' but 'if an operator dumped LSASS on a server in the last 30 days, Sysmon event 10 with access 0x1010 or 0x1410 to lsass.exe from something other than our EDR would exist'. "
   "Name the data source, the field, the time range — then you know when you are done."),
  ("Stack, then read the long tail",
   "Count every value of one field across the estate — parent→child pairs, service image paths, scheduled task actions, autorun locations — and read the rarest. "
   "Malware is rare by nature; the thing on one host out of 4,000 is where the work is. Least-frequency analysis finds what no signature knows yet."),
  ("You will find your administrators first",
   "The first runs of any good hunt surface IT: the backup admin's PsExec, the SCCM scripts, the pentest from last spring. Baseline them by name — account, host, time of day, tool — and exclude narrowly, never by process name alone. "
   "An exclusion for 'psexec.exe' is an exclusion for every attacker who brings PsExec."),
  ("Find the choke points",
   "An intrusion needs an identity, a foothold, persistence, privilege, movement and an objective. Initial access has a thousand variants; credential access and lateral movement have dozens. "
   "Spend detection effort where every intruder has to pass: LSASS, the domain controllers, the identity provider, the admin shares, the backup console."),
  ("Know what you cannot see",
   "Map each data source to the techniques it reveals (MITRE ATT&CK data components; DeTT&CT does this as a scored matrix). No process command lines, no PowerShell 4104, no DNS logs, no cloud sign-in logs beyond 30 days — each is a technique you cannot hunt. "
   "Write the gaps down: they are findings, and they go in the risk register."),
  ("Robust detections survive renaming and obfuscation",
   "Match the PE's OriginalFileName, not only the image path (rclone renamed to svchost.exe is still rclone). Expect carets, quotes, tabs, Unicode dashes and environment-variable substrings in command lines (Sigma's windash modifier exists for this). "
   "Prefer relationships — Office spawning a script host, w3wp spawning whoami — over single strings."),
  ("Seed the estate with things only an attacker touches",
   "A honey service account with an SPN and no real use (any Kerberos ticket request for it is Kerberoasting), a fake AWS key in a config file (any API call with it is a breach), a decoy 'admin-passwords.xlsx' with a canary, a disabled Domain Admin named like a real one. "
   "Deception alerts have almost no false positives; they are the highest-fidelity signal you can build."),
  ("Prove each detection fires",
   "Run the technique in a lab or a sanctioned test (Atomic Red Team publishes a test per ATT&CK technique — T1003.001 for LSASS, T1558.003 for Kerberoasting) and watch the alert arrive. "
   "A rule that has never fired on a real test is a hope, not a detection. Re-test after every logging or agent change."),
  ("Against a capable actor, scope quietly, then evict all at once",
   "Resetting one password or reimaging one host tells an APT you have seen them, and they move to the persistence you have not found. "
   "Scope first — every account, host, cloud app and token they touched — then contain everything in one window: credentials (krbtgt twice, hours apart), tokens and sessions, app secrets, federation trusts, and the edge device they came in on."),
  ("Keep the logs for longer than they stay",
   "Dwell time for espionage actors is still counted in months; edge-device intrusions are often found a year in. Identity, VPN, DNS and cloud audit logs are small and decisive — keep 12 months or more, even if endpoint telemetry rolls over sooner. "
   "Premium audit events (Microsoft's MailItemsAccessed, AWS data events) are the ones that answered 'what did they read' in the cases that mattered."),
  ("Work in UTC and keep the evidence",
   "Every query in this book returns UTC; convert only in the report. Export the result set with the query text and time of the run, hash it, and save it to the case — a hunt that finds something becomes evidence, and evidence needs its chain."),
]

# What a penetration tester or bug-bounty hunter checks first on an organisation, and the defender's mirror of each.
MIRROR = [
  ("Every hostname your certificates ever named", "Certificate Transparency logs are public: staging, admin, vpn-old and test hosts appear the day the certificate is issued — often before anyone protects them.", "Pull your own names from crt.sh every week; anything you did not expect is either shadow IT or someone else's certificate for your brand.", "bb-surface"),
  ("DNS records pointing at cloud resources you deleted", "A CNAME to a deleted Azure app, S3 bucket or GitHub Pages site can be claimed by anyone — they then serve content, steal cookies scoped to your parent domain, and pass your SPF.", "Diff every CNAME against resources you still own; delete the record before you delete the resource, never after.", "bb-surface"),
  (".git, .env, backups and source maps on web servers", "One readable /.git/config gives the whole source history; .env files give database and API keys; .map files give the original front-end code with comments.", "Request these paths against your own sites; alert when anyone else does and gets a 200.", "bb-exposed"),
  ("API keys in JavaScript bundles and public repositories", "Bundled front-end code and old commits carry cloud keys, Slack and Stripe tokens. Automated scanners find a key pushed to GitHub within minutes.", "Secret scanning in CI and on the org's public repos; alert when a key is first used from an address you have never seen.", "bb-secrets"),
  ("The VPN, firewall and file-transfer appliance", "Edge devices run old code, have no EDR, and are internet-facing by design. They have been the most-used way in for state actors since 2021.", "Patch the KEV list first and in days, not weeks; run the vendor's integrity checker; send the appliance's own logs off-box.", "bb-edge"),
  ("Login pages without phishing-resistant MFA", "SMS, push and TOTP codes can all be relayed by a proxy phishing kit; legacy protocols (IMAP, POP, SMTP AUTH) skip MFA entirely.", "Inventory every sign-in surface; block legacy authentication; require FIDO2 or Windows Hello for admins first.", "ia-aitm"),
  ("Self-service and help-desk password resets", "If a convincing caller can get a reset or a new MFA device, every other control is decoration — the route Scattered Spider uses.", "Verify callers out of band (call back on the number in HR, video with ID); alert on MFA registration right after a reset.", "ia-mfafatigue"),
  ("Accounts that do not need Kerberos pre-authentication, and SPNs on user accounts", "Both let any domain user request material that can be cracked offline — no alert, no lockout, no admin rights needed.", "List them today (two PowerShell lines in the plays); give service accounts gMSAs or 25+ character passwords and AES only.", "ca-kerberoast"),
  ("Who can reach the domain controllers and the backups", "Flat networks let one compromised laptop talk SMB, RPC and LDAP to every server. Backup consoles hold the keys to recovery — ransomware crews go there first.", "Tier the admin model; block workstation-to-workstation SMB; put backups on separate credentials with immutability.", "lm-psexec"),
  ("OAuth apps and service principals with more permission than anyone remembers", "An old app with Mail.ReadWrite or full_access_as_app over every mailbox is an invisible back door — exactly what Midnight Blizzard used in 2024.", "Review app permissions quarterly; alert on new credentials added to any app and on new app-role grants to Graph and Exchange.", "cl-spcred"),
  ("Cloud logging that can be switched off by the account being watched", "An attacker with admin in AWS or Azure turns off CloudTrail or diagnostic settings first, then works in the dark.", "Organisation-level trails and log sinks the workload accounts cannot modify; alert on StopLogging, DeleteTrail and diagnostic-setting deletes.", "cl-aws"),
  ("Remote-management tools nobody approved", "AnyDesk, ScreenConnect and Atera are signed, trusted and allowed through most firewalls: persistent remote access that looks like IT.", "Allow-list the one RMM you use; alert on any other RMM binary or its cloud domains.", "lm-rmm"),
]
