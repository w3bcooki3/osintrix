/* Tradecraft — an investigator's field guide: operational security, research personas, and how an
   actor investigation is run, from one indicator to an attribution you can defend.
   Each point: [what, why / how, optional 'area' or 'case:tab' that opens where it is done in the app]. */
const TRADECRAFT = {
  ready:[
    ['vm', 'Research runs in a VM or a separate machine, never on my everyday computer', 'Snapshot it clean; revert after anything risky.'],
    ['egress', 'My traffic leaves from somewhere that is not my home or work address', 'VPN, Tor or a research egress — and I have checked it with a leak test.'],
    ['webrtc', 'WebRTC is off, DNS goes through the tunnel, IPv6 does not leak', 'browserleaks.com and dnsleaktest.com show the egress address only.'],
    ['accounts', 'No personal or work account is signed in, in this browser profile', 'Not Google, not Microsoft, not a password manager that syncs.'],
    ['tz', 'The VM clock, time zone and browser language fit the persona or are neutral', 'A London time zone with Russian-language headers is a fingerprint.'],
    ['files', 'Files from the subject are opened only in the VM, offline', 'Documents and PDFs can call home the moment they open.'],
    ['log', 'I am logging what I do: time, where, what I saw', 'Every finding saved with its address, time and a copy — Capture does this.'],
    ['auth', 'The work is authorised and in scope, in writing', 'Who asked, why, what is out of bounds, and the legal basis.'],
  ],
  chapters:[
    {id:'model', title:'Your threat model', icon:'shield', lead:'Before collecting anything, decide who could notice you and what you would give away. The subject is only one of them.', parts:[
      {h:'Who can see you', pts:[
        ['The subject and their infrastructure', 'Every page you open is a request in someone’s web server log: your address, time, browser, and the page you came from. Operators watch their logs — some alert on any visit that is not a victim.'],
        ['The platforms', 'Social networks link accounts by device, phone number, IP address, cookies and contacts. A research account that once shares any of these with your own is linked to you.'],
        ['Third parties you hand the indicator to', 'A public urlscan.io scan, a file uploaded to VirusTotal, or a link pasted into a chat that renders previews: each fetches or publishes the thing you are investigating — where the actor may be watching. Actors monitor VirusTotal for their own samples.'],
        ['Your own organisation', 'Corporate proxies log and sometimes block your research; security tools may quarantine the samples you collect. Agree an exception rather than working around it.'],
      ]},
      {h:'What gives you away', pts:[
        ['Your address and network', 'A visit from your company’s address range, or your home ISP, is attribution. So is a VPN whose exit is always the same.'],
        ['Your browser', 'Fingerprints from screen size, fonts, canvas, WebGL, time zone and language identify a browser across sites without cookies. A rare fingerprint is worse than a common one.'],
        ['Accounts and contacts', 'Logging into anything personal in the research browser, syncing contacts, or reusing a phone number ties a persona to you.'],
        ['Documents and links', 'Office files with remote templates, images that load from a server, Windows UNC paths that send your login hash, tracking pixels in email, canary tokens in pages — opening them reports back.'],
        ['Habits', 'Working hours, language, typing style, the order you visit things. Over months these become a pattern as identifiable as an address.'],
      ]},
      {h:'Passive before active', pts:[
        ['Read what others already collected first', 'Archives, passive DNS, certificate logs, internet-wide scan datasets and sandbox reports describe a server without you ever touching it.', 'case:infra'],
        ['Every direct touch is a decision', 'Visiting the live site, resolving a domain, or downloading a file is active. Do it from the isolated environment, once, and capture everything when you do.'],
        ['Never interact beyond viewing without authority', 'Logging into a panel you found, trying default passwords, scanning ports, buying from a market or messaging the subject can be illegal and tells them they are watched.'],
      ]},
    ]},
    {id:'env', title:'The research environment', icon:'monitor', lead:'Layers, so that one mistake does not expose you: a separate machine, a separate network exit, a separate browser — and nothing personal anywhere in it.', parts:[
      {h:'Machine', pts:[
        ['A virtual machine per kind of work, with snapshots', 'Keep a clean snapshot; revert after opening anything from a subject. Disk encryption on the host. No shared clipboard or shared folders with the host while handling hostile files.'],
        ['Whonix for Tor work', 'A gateway VM that forces every connection of a workstation VM through Tor — the workstation cannot learn your real address even if it is compromised.'],
        ['Tails when nothing should remain', 'Boots from a USB stick, sends everything through Tor and forgets the session at shutdown. Good for short dark-web checks; awkward for long investigations because nothing persists unless you choose.'],
        ['Qubes OS for strict separation', 'Every task in its own VM, and disposable VMs that are thrown away after one file is opened. Strong, but needs supported hardware.'],
        ['Managed attribution platforms', 'Commercial isolated browsers (e.g. Authentic8 Silo) give you egress points in other countries and a remote browser. Cost money; save a great deal of setup.'],
      ]},
      {h:'Network exit', pts:[
        ['VPN', 'Hides your address from the site, but the provider sees everything and many sites flag VPN ranges. Fine for low-risk passive work. Use the kill switch.'],
        ['Tor', 'Strong unlinkability, but every site knows you use Tor and many block it. Required for onion services. Use Tor Browser — not another browser pointed at Tor.'],
        ['Residential or mobile egress', 'Looks like an ordinary user; needed for platforms that block VPNs and Tor. Choose a country that fits the persona and keep it stable.'],
        ['Check for leaks every session', 'browserleaks.com and dnsleaktest.com should show only the egress address. WebRTC can reveal your real local and public address even through a VPN.'],
      ]},
      {h:'Browser', pts:[
        ['One profile per persona, never shared', 'A separate browser profile (or Firefox container) per persona and per case. Containers separate cookies; they do not hide your address or fingerprint.'],
        ['Turn off WebRTC and third-party cookies', 'In Firefox, about:config → media.peerconnection.enabled = false. Block third-party cookies. Keep extensions to a minimum — each one changes your fingerprint, some phone home.'],
        ['A common fingerprint beats a random one', 'Tor Browser makes every user look alike (and letterboxes the window size). Fingerprint randomisers make you unique and still trackable. Check with coveryourtracks.eff.org.'],
        ['Time zone and language fit the story', 'Set the VM’s clock, time zone and the browser’s Accept-Language to the persona — or to something neutral and common.'],
      ]},
      {h:'Handling what you collect', pts:[
        ['Open subject files only in the VM, offline', 'Office documents can load remote templates; PDFs and HTML load remote images; Windows follows UNC paths and sends your login hash. Disconnect the VM first, or read the file as text.', 'lab'],
        ['Upload hashes, not files', 'Search VirusTotal by SHA-256 instead of uploading. An upload is shared with every VirusTotal customer — including actors watching for their own files — and may contain a victim’s data.'],
        ['Scan URLs privately', 'urlscan.io public scans are visible to everyone. Use private scans, or fetch in your sandbox.'],
        ['Never paste a live link into a chat or ticket', 'Slack, Teams, mail clients and ticket systems fetch links to show a preview — from your company’s address, before anyone clicks. Defang it: hxxps://evil[.]example.', 'decoder'],
        ['Strip your own files', 'Screenshots and documents you share carry metadata — author, software, sometimes location. Check before anything leaves your hands.'],
        ['Capture as you go', 'Address, time, a copy of the page and its hash, at the moment you see it. Pages change and infrastructure is burned; a finding you cannot show again is a rumour.', 'case:timeline'],
      ]},
    ]},
    {id:'persona', title:'Research personas', icon:'user', lead:'An account that is not you, for seeing what is only shown to members. It is for looking, not for deceiving people — check the law, the platform’s rules and your organisation’s policy first.', parts:[
      {h:'Building one', pts:[
        ['Everything separate from you', 'Its own email (not recoverable to your phone or address), its own phone number, its own VM or browser profile, its own egress. One shared element links it to you — and to every other persona.'],
        ['Phone numbers', 'Many platforms refuse virtual numbers. A prepaid SIM bought for the purpose works; never your own number, and never one number for two personas.'],
        ['A face', 'Never a real person’s photo — it harms them and reverse image search finds it. Generated faces are spotted by other investigators too. A non-face avatar (a landscape, a pet, a logo) is the safest.'],
        ['A thin, consistent story', 'Name, age, place, interests that fit what you will look at. Less is more: every detail is something that can be checked and found false.'],
        ['Age it', 'New accounts are restricted and suspicious. Use it lightly and normally for weeks before it is needed: follow ordinary accounts, read, react rarely.'],
      ]},
      {h:'Using one', pts:[
        ['Turn off everything that announces you', 'LinkedIn shows who viewed a profile unless you set private mode. Instagram and Facebook stories show who watched. Telegram group members are visible to everyone in the group. Contact syncing suggests you to the people in your address book.'],
        ['Look, do not touch', 'No follows, likes, friend requests or messages to the subject or their circle. Every interaction is a notification and a record.'],
        ['Never trigger an account recovery', 'A password reset on a subject’s email or account reveals partial phone numbers — and sends them an alert. It is active, and in many places unlawful.'],
        ['Log what each persona did', 'Date, platform, what was viewed or saved. You will need to account for it, and it tells you when a persona is worn out.'],
      ]},
      {h:'Retiring one', pts:[
        ['Signs it is burned', 'The subject blocks it, mentions it, or posts about being watched; the platform suddenly asks for verification; content you looked at disappears right after.'],
        ['Burn it completely', 'Stop using it, and never reuse its email, number, avatar or name pattern for the next one.'],
      ]},
    ]},
    {id:'start', title:'Starting an actor investigation', icon:'crosshair', lead:'From one indicator — an IP, a domain, a hash, a wallet, a handle — to a picture of who is behind it. Work in this order; each step decides the next.', parts:[
      {h:'Before the first lookup', pts:[
        ['Write the question', 'What must this answer, for whom, by when? “Is this the same group that hit us in March?” is a question. “Find out about this IP” is not.'],
        ['Grade the seed', 'Where did the indicator come from, how reliable is that source, how sure is it? A hash from your own incident is not a domain from a feed.'],
        ['Freeze it first', 'Archive the page, record DNS, WHOIS and the certificate before you dig. Actors rotate infrastructure when they notice attention.', 'case:timeline'],
      ]},
      {h:'Enrich, cheapest and quietest first', pts:[
        ['Your own data', 'Has it been seen in your logs, your other cases, your detections? It is free, private, and the most relevant.', 'entities'],
        ['Reputation and sandboxes', 'ThreatFox, URLhaus, MalwareBazaar, VirusTotal by hash, sandbox reports. What is it, and who has already written about it?', 'feeds'],
        ['Passive DNS and history', 'Which addresses did the domain point to, and which other domains shared those addresses, and when? (SecurityTrails, Validin, DomainTools, CIRCL.)', 'case:infra'],
        ['Certificate transparency', 'crt.sh and Censys show every certificate issued for a name — sibling subdomains, and when the infrastructure was being prepared.', 'certs'],
        ['Internet-wide scans', 'Shodan and Censys: open ports, banners, certificates, HTTP responses — for the address now and in the past.'],
      ]},
      {h:'Structure as you go', pts:[
        ['Diamond model', 'Adversary, capability, infrastructure, victim. Every finding goes on one corner; empty corners show what to look for next.'],
        ['A timeline of the infrastructure', 'Registered, certificate issued, first seen, last seen. The order shows preparation and tempo; gaps show holidays and time zones.', 'case:timeline'],
        ['ATT&CK for behaviour', 'Map what they do to techniques — it makes comparison with known groups concrete, and turns into detections.', 'detections'],
      ]},
    ]},
    {id:'pivot', title:'Pivoting', icon:'git-branch', lead:'Each pivot is a feature two things share. Its value is how unique that feature is: a shared SSH host key is near-proof; a shared hosting provider is nearly nothing.', matrix:[
      ['Domain', 'Registration habits: registrar, name servers, creation time, registrant email in WHOIS history', 'Reverse WHOIS, WHOIS history', 'Strong when an email or unusual registrar/NS pair repeats; privacy services hide most'],
      ['Domain', 'Analytics and ad IDs in the page: Google Analytics (UA-, G-), Tag Manager (GTM-), AdSense (ca-pub-)', 'Reverse analytics-ID search (BuiltWith, DNSlytics)', 'Very strong: one account across sites'],
      ['Domain', 'Favicon hash, HTML title, page hash, unusual JavaScript file names', 'Shodan http.favicon.hash, http.html_hash, http.title', 'Strong for phishing kits and panels; weak for default pages'],
      ['IP address', 'TLS certificate: SHA-256, serial, odd subject or issuer, self-signed defaults', 'Censys / Shodan certificate search, crt.sh', 'Strong; default certificates of C2 frameworks are a known cluster'],
      ['IP address', 'SSH host key fingerprint', 'Censys services.ssh.server_host_key.fingerprint_sha256; Shodan full-text search', 'Near-unique: the same key means the same machine image or operator'],
      ['IP address', 'TLS and HTTP fingerprints: JARM, JA4S, JA4X, JA4H, header order, a custom 404 page', 'Shodan ssl.jarm; JA4+ where your data source has it', 'JARM alone is noisy — combine with a second feature'],
      ['IP address', 'Neighbours in passive DNS, the same ASN or small host', 'Passive DNS, ASN lookups', 'Weak on shared hosting and CDNs; better on small bulletproof hosts'],
      ['File', 'Imphash, rich header hash, TLSH / ssdeep similarity, code-signing certificate', 'VirusTotal, MalwareBazaar, your sandbox', 'Strong for builds from one toolchain; signing certificates are often stolen'],
      ['File', 'PDB path, compile time, language of resources, mutex names, embedded config (C2, keys, campaign IDs)', 'Static analysis, config extractors', 'PDB paths and configs can name a developer or campaign; times and languages can be forged'],
      ['Email', 'Domains registered with it, Gravatar hash, PGP key servers, breach records', 'Reverse WHOIS, keys.openpgp.org, breach data under legal advice', 'Strong when old — early registrations are made before an actor learns OPSEC'],
      ['Wallet', 'Common-input ownership, exchange deposit addresses, addresses reused across reports', 'Money trail, block explorers, OFAC list', 'Strong; CoinJoin and custodial exchanges break it', 'case:infra'],
      ['Handle', 'The same handle elsewhere, registration dates, avatar reuse, posting hours, writing quirks', 'Username checks, reverse image search, active hours', 'Weak alone — anyone can take a name; strong with a shared key, email or wallet', 'case:infra'],
      ['PGP key', 'The same key on other markets, forums and paste sites; the names and emails inside it', 'Key servers, search engines, your evidence', 'The identity vendors keep across rebrands — very strong', 'entities'],
      ['Onion address', 'Vanity prefix, mirror lists, the same page template or PGP-signed link list', 'Ahmia, tracker sites, saved pages', 'Mirrors share signed link lists; phishing copies share a prefix but not the key'],
    ], parts:[
      {h:'Pivot with discipline', pts:[
        ['Two independent features, or it is not a link', 'Same certificate and same unusual port; same registrar and same registration hour and same name server. One feature is a lead.'],
        ['Know the shared places', 'CDNs, shared hosting, parking pages, sinkholes, free DNS, default certificates of popular software: everything behind them looks related and is not.'],
        ['Time must overlap', 'Two domains on the same address three years apart are probably strangers. Check when, not only where.'],
        ['Write down why each indicator is in the cluster', 'Six pivots later nobody remembers. A link with its reason and confidence can be checked and challenged.', 'case:graph'],
      ]},
    ]},
    {id:'human', title:'Finding the human', icon:'fingerprint', lead:'Infrastructure is bought and burned; people repeat themselves. Most attributions rest on operators’ mistakes — and the mistakes are made early.', parts:[
      {h:'Where operators slip', pts:[
        ['Look at the oldest things', 'The first domain, the first version of the malware, the earliest forum post. Before an operation grew, the operator used real details and their own habits.'],
        ['Reuse between personal and operational life', 'A handle, an email, a password, an avatar used for gaming, freelancing or a CV — and once for the operation.'],
        ['Build artefacts', 'PDB paths with a Windows user name, code comments, language and keyboard settings, compile times that fit one time zone, test uploads of early versions.'],
        ['Money', 'Payments for servers and domains, exchange deposits, and wallets reused between a market and a personal purchase.', 'case:infra'],
        ['Working hours and holidays', 'Hundreds of timestamps show a working day, a weekend and national holidays — a time zone, sometimes a country.', 'case:infra'],
        ['Writing', 'Spelling habits, idioms, translation errors and favourite phrases repeat across personas. Corroborating evidence only — never the sole basis.'],
      ]},
      {h:'Dark-web personas', pts:[
        ['The PGP key is the identity', 'Vendors rebrand and move markets but keep their key, because buyers trust it. Read the names and emails inside it; search for the fingerprint.', 'entities'],
        ['Signed link lists name the real mirrors', 'A vendor or market publishes its addresses in a PGP-signed message. Verify the signature with GnuPG before trusting any address.'],
        ['Contacts outlive accounts', 'Session and Tox IDs, Jabber addresses and Telegram usernames are reused across markets and forums.'],
        ['Stop immediately on child abuse material', 'Do not capture or keep it. Report to the national hotline (NCMEC, IWF or your country’s) and to counsel.'],
      ]},
    ]},
    {id:'chat', title:'Telegram, Discord and other chats', icon:'message-square', lead:'Where scammers, hackers and actors talk. What each platform reveals, what it shows about you, and the lines not to cross.', parts:[
      {h:'Telegram', pts:[
        ['The user ID is the identity', 'Display names and usernames change; the numeric user ID does not. A Telegram Desktop export (result.json) carries it as from_id — import the export and each author becomes a record with their ID.', 'case:timeline'],
        ['Read public channels without an account', 't.me/s/<channel> shows a public channel in a browser. Archive it before joining anything.'],
        ['Forwards map the network', '“Forwarded from” names the source channel. Repeated sources and Telegram’s similar-channels list show the network a channel belongs to.'],
        ['Collectible usernames have an owner on a blockchain', 'Usernames bought on Fragment are tokens on the TON blockchain; the sale history and owning wallet are public. A wallet that also pays for other things is a pivot.'],
        ['What you show', 'Joining a group can put you in its member list; your phone number’s visibility depends on your privacy settings (set “Who can see my phone number” and “Who can find me by number” to Nobody on research accounts). Third-party “look-up” bots see and keep what you ask them.'],
      ]},
      {h:'Discord', pts:[
        ['Every ID carries its creation date', 'IDs are snowflakes: divide by 4,194,304 and add 1,420,070,400,000 for the time in milliseconds. A server or account made days before a scam is a finding — the profile of a Discord ID shows the date.'],
        ['Invites and widgets speak without joining', 'discord.com/api/v10/invites/<code>?with_counts=true gives the server’s name, ID and member counts; a server with its widget on lists online members at /api/guilds/<id>/widget.json.'],
        ['Connected accounts are the best pivot', 'Steam, GitHub, X, Reddit and others that the owner linked to their profile — often their real, older accounts.'],
        ['Files expire', 'Attachment links stop working after a while. Download and capture what matters when you see it.'],
        ['Automating a user account breaks the rules', 'Export tools need a token; using your own user token for automation is against Discord’s terms and can lose you the account. Use a bot where you are allowed to add one, or capture by hand.'],
      ]},
      {h:'WhatsApp, Signal and the rest', pts:[
        ['Phone numbers are exposed to groups', 'In WhatsApp groups members see each other’s numbers — yours too. Never join a subject’s WhatsApp group from a number linked to you.'],
        ['Signal hides numbers by default', 'Since usernames arrived, members see names, not numbers, unless the owner chose otherwise. Expect less to pivot on.'],
        ['Invite links leak before you join', 'A group invite preview shows the name, picture and member count. Capture the preview first.'],
      ]},
      {h:'Lines not to cross', pts:[
        ['Do not use credentials you find', 'A Telegram bot token or a Discord webhook found in malware is the actor’s key. Using it — reading updates, posting, deleting — is unauthorised access, steals evidence from the platform’s view and warns the actor. Report it for takedown.'],
        ['Do not buy, download or redistribute stolen data', 'Stealer logs, leaked databases and access sold in channels: possession can be an offence and harms the victims again. Record that it is offered; let counsel decide anything more.'],
        ['Do not bait or impersonate without authority', 'Messaging a scammer or posing as a buyer can make you part of the case and tip them off. Leave it to an authorised operation.'],
      ]},
    ]},
    {id:'tricks', title:'Tricks that save hours', icon:'zap', lead:'Small techniques that experienced investigators reach for first — on search engines, archives, identifiers, images and infrastructure history. Each says what it costs you in exposure.', parts:[
      {h:'Search engines', pts:[
        ['Bound a search by date', 'Google’s before: and after: operators (before:2023-06-01) show what a site or a name looked like before a rebrand, a takedown or a clean-up.'],
        ['Turn off Google’s rewriting', 'Quotes are no longer strictly honoured. Tools → All results → Verbatim keeps the exact words, spelling and separators you typed.'],
        ['Each engine sees a different web', 'Bing still answers ip: (sites on one address). Yandex indexes VK, OK and Russian forums far better; Baidu and Naver cover their own markets. Run the same query on three engines before saying “nothing”.', 'queries'],
        ['Search the source, not the text', 'PublicWWW and FOFA body= search HTML and JavaScript: analytics IDs, wallet addresses, Telegram links and kit comments that never show on screen.', 'queries'],
      ]},
      {h:'Archives', pts:[
        ['List every URL the archive holds', 'The Wayback CDX API lists every captured URL of a domain: web.archive.org/cdx/search/cdx?url=target.com/*&fl=timestamp,original&collapse=urlkey. Old admin pages, JS bundles and leaked files show up here.'],
        ['Old JavaScript keeps old secrets', 'Archived JS bundles carry API endpoints, keys and internal hostnames that were removed from the live site. Pull the earliest and the last capture and diff them.'],
        ['Google’s cache is gone', 'Google removed its cached-page links in 2024. Use the Wayback Machine, archive.today and Bing’s cache, and capture pages yourself as you go.'],
        ['Archiving is visible', 'Asking the Wayback Machine or archive.today to save a page leaves a public, dated copy — and the subject can see someone looked. For careful subjects, capture locally only.'],
      ]},
      {h:'Identifiers', pts:[
        ['Email to face', 'Gravatar serves the profile picture for the MD5 or SHA-256 of the lower-cased address (gravatar.com/avatar/<hash>), with no request to the person.'],
        ['Gmail to Google profile', 'GHunt reads a Gmail address’s public Google data — profile photo, Maps reviews, calendar if public. It needs a Google session: use a persona account, never your own.'],
        ['Phone to messenger profile', 'Saving a number in a persona phone’s contacts shows the WhatsApp or Telegram name and photo. Only from a persona device — the subject may get a “joined” or contact notice.'],
        ['Password reset pages leak', 'A reset form often shows a masked phone or backup email. It also sends the subject an alert — never trigger one on someone who would notice.'],
        ['Handles bend, people repeat', 'Try separators and years (j.doe, j_doe, jdoe87) and the same handle on the platforms of that person’s trade. Developers reuse handles more than anyone; check GitHub commit emails.'],
      ]},
      {h:'Images and documents', pts:[
        ['Documents keep what photos lose', 'Social networks strip photo metadata; PDFs and Office files on websites usually do not — author names, usernames, software, internal paths and printer names.', 'lab'],
        ['Crop before reverse search', 'Search the distinctive part (a sign, a logo, a building) on Google Lens, Bing, Yandex and TinEye. TinEye sorted by oldest finds the first appearance of an image.'],
        ['Shadows give the time', 'Shadow length and direction, with SunCalc for the place, narrow the date and hour a photo was taken — useful to test a claimed time.'],
      ]},
      {h:'Infrastructure history', pts:[
        ['Passive DNS is time travel', 'What an IP served before, and what a domain pointed to before. Two domains on the same IP in the same week are linked; years apart on a cloud IP, they are not.', 'case:infra'],
        ['WHOIS history beats WHOIS', 'Registrant details from before privacy was switched on. Registrar, name servers and creation minute together cluster domains registered in one batch.'],
        ['Certificates arrive before the site', 'Certificate Transparency logs a phishing domain’s certificate minutes after it is requested — often before the page is live. Watch the brand name in CT.', 'certs'],
        ['The company cloud from outside', 'Tenant IDs, buckets, SaaS verification records and origin servers behind a CDN — the Cloud field guide has the commands, and what the owner can see of each.', 'cloud'],
      ]},
    ]},
    {id:'detect', title:'From findings to detections', icon:'file-code', lead:'An investigation ends with indicators; a defence needs rules that still fire after the indicators change. Turn what you found into detections, and what the detections catch back into leads.', parts:[
      {h:'Write rules that outlive the indicators', pts:[
        ['Climb the pyramid', 'Hashes and IPs change in minutes; tools, habits and procedures take months. Prefer “a non-browser posting to the Telegram Bot API” over one bot token.', 'detections'],
        ['Network rules on lasting features', 'URL paths, user agents, JARM, certificate subjects and issuers, favicon hashes and DNS patterns of the operator’s infrastructure last longer than its addresses.', 'detections'],
        ['YARA on what is unique', 'Error messages, mutex names, PDB paths, config keys, bot tokens and kit comments — not library strings every program has. Test against clean files before trusting it.', 'detections'],
        ['Cloud rules follow the API', 'CloudTrail, Entra, Workspace and Okta events name the action exactly. Write rules on the action that matters (trust anchor created, delegation granted, logging stopped), then filter the admins who do it legitimately.', 'detections'],
      ]},
      {h:'Test before you alert', pts:[
        ['Run it over the past first', 'Zero hits can mean wrong field names; thousands mean it needs a filter. Run every rule over the cases you already have before shipping it.', 'detections'],
        ['Record where it came from', 'The report, the case and the technique each rule rests on — so coverage can be reviewed and stale rules retired.'],
      ]},
      {h:'Close the loop', pts:[
        ['A hit is a fresh lead', 'A rule that fires gives new infrastructure — a new C2, a new bot, a new wallet. Pivot it the same day, before the operator burns it.', 'feeds'],
        ['Share the behaviour, not just the list', 'Indicators expire; a description of how the operator works helps the next team for months.'],
      ]},
    ]},
    {id:'judge', title:'Attribution you can defend', icon:'scale', lead:'Attribution has levels, and each needs more evidence than the last: a cluster of activity, a named group, a sponsor, a person.', parts:[
      {h:'Hold back', pts:[
        ['False flags exist', 'Olympic Destroyer copied another group’s code features to point at them. Language strings, time zones and code reuse can all be planted.'],
        ['Shared tools are not shared actors', 'Cobalt Strike, leaked builders, commodity loaders and rented infrastructure are used by many groups. Contractors work for several.'],
        ['Vendors’ names do not line up', 'One vendor’s group is two of another’s. Record which report each alias comes from.'],
      ]},
      {h:'Weigh it', pts:[
        ['Competing hypotheses', 'Write every plausible explanation, including “a different actor with the same tools”, and look for the evidence that disproves each. The survivor is the one with least against it.', 'case:questions'],
        ['Grade every source', 'Reliability of the source and credibility of the information, separately (A–F, 1–6). A confident claim from an unknown source is still unknown.'],
        ['Say how sure you are, and why', 'Low, moderate or high confidence, the key assumptions, and the gaps. “We assess with moderate confidence…” is honest; “It was X” rarely is.'],
      ]},
      {h:'When you are seen', pts:[
        ['Signs you are burned', 'Infrastructure vanishes right after your visit, a canary fires, the subject mentions research or researchers.'],
        ['Decide: watch or act', 'Exposing or taking down infrastructure ends your visibility. Agree with the people you work for which matters more, before it happens.'],
      ]},
    ]},
  ],
};
