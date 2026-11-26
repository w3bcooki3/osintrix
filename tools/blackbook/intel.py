# The Blackbook — intelligence chapters: the APT casebook, the underground, how cybercriminals were caught, OSINT tradecraft.
# Facts in the casebooks come from public reporting (government advisories, vendor reports, court filings); each entry names its source.

APT = [
  dict(id='volt', name='Volt Typhoon', who='China (state-sponsored)', when='Active since at least 2021; CISA advisory AA24-038A, February 2024',
    what="Pre-positioning in US critical infrastructure (energy, water, communications, transport) for disruption in a future crisis, not espionage. Entered through internet-facing Fortinet, Ivanti, NetScaler and Cisco devices; routed traffic through a botnet of end-of-life SOHO routers (KV-botnet) so it came from residential US addresses. "
         "Then lived off the land for years: valid accounts, ntdsutil to copy NTDS.dit, wmic and netsh portproxy, almost no malware.",
    tells=["ntdsutil 'ifm' and shadow-copy access on domain controllers", "netsh interface portproxy on compromised hosts", "Valid-account logons from SOHO-router address space at unusual hours", "Event log clearing on DCs; discovery bursts with built-in tools"],
    plays=['ca-ntds', 'lm-proxy', 'ex-lolbin', 'di-ad', 'bb-edge', 'de-logs'],
    lesson="No malware to find — only behaviour. Organisations that caught it had process command-line logging on DCs, kept logs for long enough, and looked at what admins' tools were doing."),
  dict(id='midnight', name='Midnight Blizzard (APT29)', who='Russia (SVR)', when='Microsoft disclosures, January 2024; earlier SolarWinds-era intrusions 2020',
    what="Password-sprayed a legacy, non-production Microsoft test tenant account that had no MFA, using residential proxies to spread the attempts. Found a legacy test OAuth application with elevated access to Microsoft's corporate tenant, "
         "created further malicious OAuth apps, and granted them the Exchange full_access_as_app role to read mailboxes of senior leadership and security staff. In 2020 the same service used stolen AD FS signing keys (Golden SAML) after the SolarWinds supply-chain compromise.",
    tells=["Low-and-slow spray failures across many accounts from residential IPs", "New credentials added to an old app; new app-role grants to Exchange or Graph", "Mailbox reads by an application ID (MailItemsAccessed) rather than a user"],
    plays=['ca-spray', 'cl-spcred', 'ia-consent', 'cl-fed', 'cl-roles'],
    lesson="Forgotten test tenants and legacy apps are production attack surface. Inventory every tenant and every app with application permissions, and alert on any credential added to them."),
  dict(id='spider', name='Scattered Spider (UNC3944, Octo Tempest)', who='Financially motivated, mostly young English-speakers; affiliates of ALPHV/BlackCat and later other ransomware', when='CISA advisory AA23-320A (November 2023, updated 2025); 2022 SMS phishing of Twilio, Okta and others; 2023 casino attacks; 2025 UK retail attacks reported',
    what="Phones the help desk as an employee to reset passwords and MFA, SIM-swaps, sends SMS phishing to staff, and runs MFA fatigue. Once in: Okta and Entra admin abuse, adding their own identity provider as a federated trust, remote-access tools (AnyDesk, ScreenConnect), stealing from Snowflake, SharePoint and code repositories, then ransomware on VMware ESXi.",
    tells=["Help-desk reset followed by MFA registration from a new location", "A new federated domain or identity provider in the tenant", "RMM tools appearing on hosts; ESXi shell enabled; vCenter logins from new accounts"],
    plays=['ia-mfafatigue', 'lm-rmm', 'cl-fed', 'cl-roles', 'ia-aitm'],
    lesson="Identity verification at the help desk is a security control. Most of their intrusions needed a human to say yes on the phone."),
  dict(id='storm1811', name='Storm-1811 (Black Basta access)', who='Financially motivated; access for Black Basta ransomware', when='Microsoft report, May 2024',
    what="Email-bombed users with thousands of subscription messages, then posed as IT support over voice calls and Microsoft Teams chats from external tenants, persuaded users to start Quick Assist, then installed RMM tools, Qakbot or Cobalt Strike, and deployed Black Basta.",
    tells=["Mail-bomb volume spike to one user", "External Teams chat from a new *.onmicrosoft.com tenant named like a help desk", "QuickAssist.exe, then curl/RMM within minutes"],
    plays=['ia-teams', 'lm-rmm', 'ex-pwsh', 'im-ransom'],
    lesson="Restrict Teams external access and remove Quick Assist where IT uses another tool; tell users IT never initiates from an outside organisation."),
  dict(id='storm0558', name='Storm-0558', who='China (state-sponsored)', when='Discovered July 2023; US Cyber Safety Review Board report, April 2024',
    what="Used a stolen Microsoft consumer (MSA) signing key to forge authentication tokens that, through a validation flaw, were accepted for enterprise Outlook Web Access, and read mail of US government officials. "
         "It was found by a US State Department analyst who saw unusual MailItemsAccessed events — a log that, at the time, required a premium licence.",
    tells=["MailItemsAccessed events from an unexpected application ID and client", "Token use with no matching sign-in event"],
    plays=['cl-spcred', 'ia-aitm'],
    lesson="Which logs you have decides what you can see. The detection existed only because one customer paid for detailed audit logging; Microsoft later made those logs standard."),
  dict(id='lazarus', name='Lazarus and DPRK clusters', who='North Korea (RGB): Lazarus, Famous Chollima, Sapphire Sleet and others', when='Operation Dream Job (2020 onwards); Contagious Interview (Unit 42, November 2023); IT worker schemes (US DoJ actions 2024–2025)',
    what="Fake recruiters approach developers and crypto staff with job offers, then send a 'coding test' repository or a trojanised npm package; the install script steals browser data and wallets and drops a backdoor. "
         "Separately, North Korean IT workers are hired remotely under stolen or fake identities, using laptop farms in other countries, to earn salaries and sometimes steal data or extort.",
    tells=["node or python starting shells and downloads on developer machines", "New hires whose laptops connect through consumer VPNs, use remote-KVM devices or are shipped to addresses that do not match", "Wallet extension data read by non-browser processes"],
    plays=['ia-supply', 'ca-browser', 'lm-rmm'],
    lesson="Treat developer machines as high-value targets and hiring as an attack surface: verify identity on video, ship laptops only to verified addresses, and watch for remote-control hardware."),
  dict(id='salt', name='Salt Typhoon', who='China (state-sponsored)', when='Telecom compromises reported from autumn 2024; joint advisory AA25-239A, August 2025',
    what="Compromised major telecommunications providers in the US and many other countries, reaching lawful-intercept systems and call records. Entered through network devices (Cisco IOS XE and others with known CVEs), changed router configurations, created local accounts, set up GRE tunnels and packet captures, and moved between providers' networks.",
    tells=["Configuration changes on routers outside change windows; new local accounts", "GRE or other tunnels to unknown endpoints; packet capture enabled on devices", "Admin access to network devices from non-management addresses"],
    plays=['bb-edge', 'lm-proxy'],
    lesson="Network devices need the same logging, integrity checking and configuration baselines as servers — off-box logs and config diffs are what reveal this class of intrusion."),
  dict(id='sandworm', name='Sandworm', who='Russia (GRU unit 74455)', when='NotPetya (2017); Industroyer2 against Ukrainian grid (April 2022)',
    what="Destructive operations: wipers spread through Group Policy and scheduled tasks across whole domains, attacks on industrial control systems, and supply-chain distribution (NotPetya through a Ukrainian accounting software update).",
    tells=["New GPOs or changes to GPO scheduled tasks pushing the same binary everywhere", "Mass service creation and shadow-copy deletion", "OT network access from IT"],
    plays=['im-ransom', 'pe-task', 'pe-service'],
    lesson="When the goal is destruction, minutes matter: alert on GPO changes and mass task creation, and be able to isolate the domain quickly. Offline backups are the recovery plan."),
]

# Working the underground: for authorised investigators — CTI teams, journalists, law enforcement.
UNDERGROUND = [
  dict(h='Rules of engagement', pts=[
    ("Observe; do not take part", "Read, record and analyse. Do not buy data, access or tools, offer services, or encourage a crime — in most countries that is not research, it is participation. Undercover work, test purchases and controlled buys are for law enforcement acting under its own authority (the FBI's undercover purchase is what tied IntelBroker to his wallet)."),
    ("Get it in writing", "Who authorised the collection, the scope, what you may and may not download, and who you hand findings to. Leaked personal data has legal weight even when it is already public: collect the minimum, store it encrypted, and know your data-protection basis."),
    ("Deconflict", "If you find something that suggests a crime in progress against a named victim, the route is the victim and law enforcement — not the forum, and not publishing. Your threads may overlap with an undercover operation; check before you act on a person."),
    ("Your persona is not you", "A research identity that never touches your real accounts, devices, phone number or payment details, from the research environment in Tradecraft. Never post, never reply, never boast. Forums log IPs, and forum databases leak — the RaidForums database is how the FBI started on pompompurin.", 'tradecraft'),
  ]),
  dict(h='The map', pts=[
    ("Russian-language forums", "XSS and Exploit are the long-running, invitation- or deposit-gated forums where initial access, malware, exploits and laundering services are sold, with escrow and arbitration. Deals move to Jabber, Tox or Telegram. Posting history, reputation and arbitration threads there are some of the best actor profiles that exist."),
    ("English-language forums and markets", "BreachForums and its successors (seized and relaunched repeatedly since 2023), Cracked and Nulled (both seized in Operation Talent, January 2025), and data-leak marketplaces. Lower barrier, younger actors, worse OPSEC — and frequent law-enforcement takeovers, so treat any forum as possibly monitored."),
    ("Telegram", "Combolist and stealer-log 'clouds', fraud and carding channels, ransomware and hacktivist announcements, sellers' support accounts. Public channels can be read without an account at t.me/s/<channel>. Channel and user numeric IDs never change even when the @name does — record the ID."),
    ("Markets for logs and access", "Automated shops sell infostealer logs per machine (searchable by domain — your SSO, your VPN); initial access brokers (IABs) post anonymised listings of company access with revenue, sector, country, access type and privileges."),
    ("Ransomware leak sites", "Tor sites where victims who did not pay are named and their data published; trackers like ransomware.live mirror the posts so you need not visit the onion yourself."),
  ]),
  dict(h='What to look for', pts=[
    ("Your organisation, disguised", "Access brokers anonymise: 'US manufacturer, $800M revenue, 1,500 hosts, Fortinet VPN, domain user, EDR: Defender'. Match listings against your own profile — sector, revenue band, country, VPN brand, AV — and treat a close match as an incident until proven otherwise."),
    ("Your users in stealer logs", "Your SSO, VPN, Okta, Citrix and webmail URLs with working cookies are what buyers search for. A machine in a log means a session, not just a password: revoke sessions and reimage, do not only reset. OSINTrix's stealer-log reader shows which of your accounts and sessions are in a log, passwords masked.", 'lab'),
    ("Exploits and tools for what you run", "A seller offering a pre-auth RCE for a VPN or file-transfer product you expose, or a new crypter bundled with a loader your EDR keeps flagging. The underground often discusses an exploit weeks before a patch."),
    ("Insider recruitment", "Posts offering money for employees at telecoms, banks and SaaS companies to run a tool, approve a SIM swap or provide VPN access. Search for your company and product names in these threads."),
    ("Kits aimed at your brand", "Phishing kits and 'panels' that name your bank, your login page or your customers; source code of the kit often names its author and where it sends the data (often a Telegram bot).", 'lab'),
  ]),
  dict(h='Profiling an actor', pts=[
    ("Registration date and first posts", "The first months of a handle are where people are careless: real-name emails, questions only a beginner asks, the same handle used on gaming or hobby sites. Ulbricht, Cazes and the Raccoon developer were all tied to early-days mistakes. Read an actor's history from the beginning, not the end."),
    ("Contact identifiers outlive handles", "Jabber JIDs, Tox IDs, Telegram numeric IDs, Session IDs, PGP key fingerprints and wallet addresses are reused across forums and years even when the display name changes. Collect every one, then search for each across forums, leaks and paste sites."),
    ("Activity rhythm", "Plot posting times in UTC: a working day and a sleep gap reveal a time zone; silence on 1–8 January and 7 January (Orthodox Christmas) or on Ramadan evenings is a cultural marker. One clock is evidence, not proof — operators share accounts and schedule posts.", 'case:timeline'),
    ("Language", "Transliteration habits, keyboard-layout typos (a Latin word typed on a Cyrillic layout), idioms, date formats and decimal separators. OSINTrix's writing-style comparison scores two texts for the same author; treat it as a lead, never as identification.", 'case:questions'),
    ("What screenshots leak", "Proof screenshots of 'access' or 'logs' show taskbars, clocks, desktop language, usernames in file paths, browser tabs, and sometimes the real public IP in a panel. Read every pixel; save the original file for its metadata."),
    ("Products and money", "What they sell, at what price, how they take payment, which escrow they use, and where the money goes. A wallet that receives from escrow and sends to a KYC exchange is the thread law enforcement can pull — as IntelBroker's and Buchanan's cases show."),
  ]),
  dict(h='Pivots from one handle', pts=[
    ("Every spelling, everywhere", "The handle and its variants (digits for letters, underscores, a suffix) across forums, social networks, code hosting, gaming platforms, and the WhatsMyName and Maigret checks. Same handle ≠ same person: corroborate with something else they share.", 'entities'),
    ("Old forum databases", "Many seized or leaked forum databases are circulated; commercial CTI providers and law enforcement search them lawfully. They hold registration emails and IP addresses. Whether you may handle them yourself depends on your jurisdiction and authorisation — usually, ask a provider."),
    ("PGP keys", "Search keys.openpgp.org and other keyservers for the fingerprint: user IDs, creation date, other keys created the same minute, and signatures by other keys. A key created years before the handle can name the earlier identity."),
    ("Domains and infrastructure", "Panels, shops and phishing domains registered by the actor: registrar, name servers, the first certificate, analytics IDs, and the hosting's other domains. Registrar logs tied Tyler Buchanan to Okta-themed phishing domains; only law enforcement can get those, but the public half (WHOIS history, CT logs) often already points the way.", 'case:infra'),
    ("Wallets", "Trace in and out: escrow, mixers, bridges and the first exchange. Note amounts and times to match against ransom payments or sales posts. Clustering and labels in WalletExplorer or Breadcrumbs show which service a deposit address belongs to."),
    ("Companions and lifestyle", "Cars, watches, travel and the people photographed alongside. The Raccoon developer was traced partly through his companion's Instagram posts from Amsterdam; AlphaBay's founder's lifestyle in Thailand matched the money."),
  ]),
  dict(h='Evidence from the underground', pts=[
    ("Capture the page and its context", "Full-page capture with the URL, time (UTC) and your hash, plus the HTML. Forums render times in the viewer's time zone setting — note yours. For onion sites, archive.today will not help; your own capture is the record.", 'case:timeline'),
    ("Record IDs, not only names", "Forum member ID, thread and post IDs, Telegram channel and message IDs. Names change; IDs and post URLs are what a court and another analyst can verify."),
    ("Never run what you download", "Samples, 'free logs' and cracked tools on forums are very often backdoored — criminals robbing each other. Hash first, analyse in a sandbox, and keep the archive password-protected (infected) in the case."),
    ("Write what you saw, not what you think", "'Handle X posted on 2026-03-02 offering access to a company matching our profile' — then, separately, your assessment with a confidence level. Keep the two apart in the report.", 'case:questions'),
  ]),
]

# How cybercriminals were identified — from court filings and official statements.
CAUGHT = [
  dict(name='Silk Road — Ross Ulbricht', year='2013', src='US criminal complaint (SDNY), 2013',
    how="As 'altoid', he promoted Silk Road on the Shroomery forum and Bitcointalk in early 2011; later, as altoid, he posted a job ad on Bitcointalk giving his personal Gmail address rossulbricht@gmail.com. "
        "He asked a Stack Overflow question about Tor hidden services under his real name, then changed the username to 'frosty' — and the Silk Road server's SSH key was labelled frosty@frosty. Arrested in a San Francisco public library with his laptop open.",
    lesson="Early promotion posts and one reused email outlive every later precaution. Search an actor's earliest footprint, and look for small strings (key comments, usernames) that repeat."),
  dict(name='AlphaBay — Alexandre Cazes', year='2017', src='US civil forfeiture complaint (EDCA), July 2017',
    how="Welcome and password-reset emails sent by AlphaBay in December 2014 carried his personal Hotmail address (pimp_alex_91) in the header. The same handle appeared on a French technology forum and tied to his LinkedIn and his software company. "
        "His assets in Thailand — cars, villas, accounts — matched the market's earnings. Arrested in Bangkok on 5 July 2017; he died in custody days later.",
    lesson="Infrastructure leaks its builder: email headers, server banners, default configs. Read the technical artefacts a service sends you, not just its content."),
  dict(name='LulzSec — Hector Monsegur (Sabu)', year='2011', src='Court records and widely reported FBI statements',
    how="He logged into an IRC chat server at least once without Tor, exposing his home IP address. The FBI arrested him in June 2011 and he became an informant, which led to arrests of other LulzSec and Anonymous members.",
    lesson="One connection without the anonymiser is enough, and logs keep it. Anonymity has to hold every single time; investigations only need it to fail once."),
  dict(name='Raccoon Infostealer — Mark Sokolovsky', year='2022', src='US indictment (WDTX), unsealed October 2022; KrebsOnSecurity',
    how="Early forum posts by the developer ('Photix') used a Gmail account linked to his Apple iCloud account. Investigators watched the iCloud account as he moved around Ukraine, then followed his phone into Poland, Germany and the Netherlands. "
        "His companion posted about the trip on Instagram, including a photo in Amsterdam's Dam Square. Dutch police arrested him on 20 March 2022; the Raccoon team announced core members had 'died' in the war.",
    lesson="Account recovery links (Gmail ↔ iCloud) join identities. Companions' social media are part of the footprint. A claimed death is a claim."),
  dict(name='BreachForums — Conor Fitzpatrick (pompompurin)', year='2023', src='FBI affidavit (EDVA), March 2023',
    how="Investigators started from IP addresses that connected to RaidForums (seized in 2022), where he had been active. Some of those IPs led, through Verizon records, to his phone at his parents' house. "
        "He had mentioned searching a breached database for an old email address; agents followed it to his Gmail accounts registered in his name. He used VPNs, which, as the affidavit notes, are sometimes misconfigured and expose the real IP. Phone location then matched forum activity to his home.",
    lesson="A seized or leaked forum database is a time machine. Saying which email you once used, even in passing, is an identifier."),
  dict(name='IntelBroker — Kai West', year='2025', src='US criminal complaint (SDNY), unsealed June 2025',
    how="An FBI undercover agent bought stolen data from IntelBroker and paid in bitcoin. The wallet traced back to an account at the exchange Ramp registered with his UK driving licence, and to a Coinbase account (under an alias) tied to the same licence; both used his personal email. "
        "That email had also been used to watch YouTube videos that IntelBroker posted on BreachForums.",
    lesson="Payments are the strongest thread: a seller who needs to cash out touches a regulated exchange eventually. Everyday accounts (YouTube) under the same email join the persona to the person."),
  dict(name='Scattered Spider — Tyler Buchanan', year='2024', src='US criminal complaint (CDCA); KrebsOnSecurity, April 2025',
    how="The same username and email registered several Okta-themed phishing domains used in the 2022 SMS phishing campaign. The registrar, NameCheap, found that account had logged in from a UK IP address; Scottish police said that address was leased to him. "
        "Discord records showed the same IP running an account that named a crypto wallet. He was arrested at Palma de Mallorca airport in June 2024 and extradited to the US in 2025.",
    lesson="Phishing infrastructure is registered by a person with an account somewhere. WHOIS privacy hides the registrant from you, not from the registrar's logs — note every domain so law enforcement can ask."),
  dict(name='LockBit — Dmitry Khoroshev (LockBitSupp)', year='2024', src='UK National Crime Agency, 7 May 2024',
    how="In February 2024 Operation Cronos (NCA, FBI and partners) took control of LockBit's infrastructure and leak site, and used the leak site to publish its own announcements. The seized systems gave data on more than 7,000 attacks and on 194 affiliates. "
        "On 7 May 2024 the NCA named Khoroshev as LockBitSupp; the UK, US and Australia sanctioned him, and the US offered up to $10 million.",
    lesson="A criminal service's own back end becomes the evidence against its customers. Affiliates who thought the panel protected them were listed in it."),
  dict(name='USDoD — Luan B. G.', year='2024', src='Reporting by TecMundo, SecurityWeek and KrebsOnSecurity, August–October 2024',
    how="A non-public CrowdStrike report, later corroborated by Predicta Lab, linked the USDoD personas to personal social-media profiles in his real name; he did little to separate them, and his accounts confirmed the identification. Brazil's Federal Police arrested him in October 2024.",
    lesson="Personas linked to real profiles, even indirectly (shared photos, follows, handles), unravel fast once someone looks."),
  dict(name='Conti — the leaks', year='2022', src='ContiLeaks, February–March 2022; widely analysed',
    how="After Conti publicly backed Russia's invasion of Ukraine, an insider leaked years of the group's internal Jabber and RocketChat messages, source code and infrastructure. The chats showed the group's structure, salaries, recruitment and negotiations, and fed later identifications and sanctions.",
    lesson="Criminal groups are workplaces with grudges. Leaks and rival disclosures are a major source — preserve them when they appear, and corroborate before relying on them."),
]
CAUGHT_PATTERNS = [
  ("Early-days mistakes", "The first posts, the first domain, the first email — before the operation needed hiding."),
  ("One identifier reused", "An email, handle, key comment or wallet that appears both in the criminal life and the ordinary one."),
  ("A single unprotected connection", "One login without VPN or Tor, kept in logs for years."),
  ("Cashing out", "Crypto eventually meets a KYC exchange, a car dealer or a property; the trace runs backwards from there."),
  ("Seized databases and panels", "Forums, markets and ransomware back ends are taken over; everything their users did is then evidence."),
  ("People around them", "Companions' posts, family accounts, lifestyle that does not match a declared income."),
  ("Undercover and insiders", "Test purchases by law enforcement, insiders and rivals who leak."),
]

# OSINT tradecraft beyond the basics in the Tradecraft guide: exact syntax and the gotchas.
OSINT = [
  dict(h='Infrastructure pivots that work', pts=[
    ("Favicon hash", "Shodan indexes a MurmurHash3 of the base64 favicon: http.favicon.hash:-1234567890. Phishing kits and C2 panels ship their own favicon, so one hash finds the actor's other servers. OSINTrix computes the same value from a saved page or favicon file (Forensics kit).", 'lab'),
    ("Certificates before DNS", "A certificate is usually issued before a phishing site goes live: watch CT logs for your brand (crt.sh, or the public Postgres at crt.sh:5432 user guest for bulk SQL) and you see the domain days before the first email."),
    ("Self-signed and default certificates", "C2 frameworks and panels often run with a default or self-signed certificate whose subject, issuer or serial repeats across servers — search the field in Censys or Shodan (ssl.cert.serial, ssl.cert.subject.cn)."),
    ("JARM and JA4X", "Server TLS fingerprints: the same C2 software configured the same way answers the same way. Good for clustering, too broad alone — combine with port, title or banner."),
    ("HTTP quirks", "Header order, a typo in a custom header, an ETag format, an odd 404 page body length, a unique HTML title. Kits carry their author's quirks; search the exact string in urlscan.io or PublicWWW."),
    ("Analytics and ad IDs", "A Google Analytics (UA-/G-), Tag Manager (GTM-), AdSense (pub-) or Facebook Pixel ID shared by two sites is a strong link between their operators. PublicWWW and BuiltWith 'relationships' search them, including historical ones."),
    ("SSH host keys", "A server's SSH host key fingerprint rarely changes; the same key on two IPs is the same machine or the same image. Shodan and Censys index it."),
    ("Passive DNS timing", "When a domain first resolved, to what, and what else resolved to that IP the same week. Infrastructure is set up in batches: neighbours in time are often siblings."),
  ]),
  dict(h='Archives and deleted things', pts=[
    ("Wayback CDX API", "web.archive.org/cdx/search/cdx?url=example.com/*&output=json&fl=timestamp,original,statuscode,digest&collapse=digest lists every captured URL of a site, de-duplicated by content — deleted pages, old staff lists, robots.txt history."),
    ("robots.txt history", "Old robots.txt files list paths the owner wanted hidden: admin panels, staging folders, document directories."),
    ("Several archives, not one", "archive.today captures pages the Wayback Machine cannot (scripts, some social networks); Common Crawl holds raw pages at scale; national libraries archive their country's web. Check each."),
    ("Cached search snippets", "Search engines' result snippets often outlive the page; search the exact sentence in quotes on Bing, Yandex and DuckDuckGo, which index differently from Google."),
  ]),
  dict(h='People behind infrastructure', pts=[
    ("Git commit metadata", "Every commit carries an author name and email; appending .patch to a commit URL on GitHub shows them in plain text. Actors who publish tools or kits on GitHub often committed once from their real identity."),
    ("Package and container registries", "npm, PyPI and Docker Hub profiles list maintainers, other packages and creation dates; Docker image layers (docker history) can leak usernames, internal hostnames and build paths."),
    ("PDB paths and build strings", "Compiled malware can keep the developer's build path (C:\\Users\\<name>\\source\\repos\\...); the same path in two samples is the same machine. Strings and capa find them.", 'lab'),
    ("Document metadata", "Office and PDF files carry author, company, template path, editing time and software versions; images carry camera and GPS. Telegram keeps EXIF on files sent as 'file' rather than compressed photos.", 'lab'),
    ("IDs that contain dates", "Discord, X/Twitter and Bluesky IDs encode their creation time (a Discord snowflake: (id >> 22) + 1420070400000 ms). An account created the day before the scam is a fact you can show. OSINTrix decodes these.", 'lab'),
  ]),
  dict(h='Verification and geolocation', pts=[
    ("Reverse-search more than one engine", "Google Lens for objects and text, Yandex for buildings and landscapes (especially Eastern Europe), Bing as a third index, TinEye for the oldest copy. Crop to the distinctive part; flip mirrored images."),
    ("Chronolocation", "Shadow direction and length give the sun's position; SunCalc turns that into a time window for a known place — or disproves a claimed time."),
    ("Overpass queries", "Turn what you see into a query: a mosque within 150 m of a railway line and a river. Overpass Turbo returns every match in a region; a handful of candidates beats scrolling satellite images for hours."),
    ("Satellite history", "Sentinel-2 in Copernicus Browser (10 m, every few days since 2015) shows when something appeared or burned; Google Earth Pro's history slider shows higher-resolution older images."),
    ("Ships", "Search by IMO number, which stays with the hull through name and flag changes. AIS gaps, sudden jumps and identical positions for two ships are signs of spoofing or a ship-to-ship transfer; the first three digits of an MMSI give the flag. Global Fishing Watch shows gaps and encounters for free."),
    ("Aircraft", "Search by ICAO hex code (stays with the airframe) on ADS-B Exchange, which does not hide aircraft whose owners asked to be blocked elsewhere."),
  ]),
  dict(h='Your own exposure while doing this', pts=[
    ("Scanning services publish", "Public urlscan.io scans, VirusTotal uploads and archive captures are visible to anyone — including the actor, who may monitor them. Search before you submit; scan privately; never upload a victim's document."),
    ("Short links", "Add + to a bit.ly link (bit.ly/abc+) to see where it goes and its click count without visiting; other shorteners have preview pages. Expanding it through a service avoids touching the actor's server."),
    ("Canaries in leaks", "Leaked documents and 'free' data dumps sometimes carry tracking pixels or canary tokens; open them offline, in the research VM.", 'tradecraft'),
  ]),
]
