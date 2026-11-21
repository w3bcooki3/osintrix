# Changelog

All notable changes to OSINTrix, newest first. The format is based on [Keep a Changelog](https://keepachangelog.com); this file is generated from `js/data/changelog.js` by `tools/changelog.py`.

## [1.50] — Regex builder (2026-11-20)

_Select the parts of a log line you want and get the regular expression for them — tested on every line, checked for patterns that freeze log tools, and written for six tools. Nothing leaves the browser._

### Added
- Forensics kit → Regex builder: paste log lines or open a log file, select the parts you want and name them. The pattern uses a precise form for what it recognises (IPv4 and IPv6, ISO, syslog and web-server times, email, URL, GUID, hashes, SIDs, numbers) and “up to the next delimiter” for the rest; host names and process numbers become patterns, an empty field written as “-” matches whatever is there, and fixed words stay as anchors.
- It is tried on every line, with the fields it pulls out in a table and the lines it misses listed. Selecting the same fields on a missed line teaches it the variation: different words become alternatives, an extra phrase becomes optional.
- A safety check before anything runs: patterns that can backtrack badly — and freeze a log tool on a line that almost matches — are flagged and, when written by hand, not run at all; others are timed on hostile input.
- The same pattern for JavaScript, PCRE, Python, Grok (using Grok’s own patterns where they fit), Splunk rex and KQL extract, ready to copy — or saved as a parser so log imports read that format. Plus a library of ready-made patterns for incident response.

### Fixed
- Custom parsers: a pattern that can freeze on near-matching lines is no longer run in the test box, and cannot be saved.

## [1.49] — A sample case for the OSINT tools (2026-11-19)

_A new sample case, Harbourline refund scam, shows every Infrastructure view and an identity profile on realistic data — and the account timeline is fixed._

### Added
- Sample case “Harbourline refund scam”: WHOIS, RDAP, dig, certificate, passive DNS, Shodan and Censys results; victim payments on Bitcoin, Ethereum and TRON; profiles on X, Reddit, GitHub and Mastodon, two of them renamed; the shop’s About page saved twice; post times from a Telegram group, Reddit, Discord and a bot; and Jan Harbour in the vault, joined to J. Haven in Customer portal by a shared email. Added once to workspaces that keep the sample data; Settings → remove sample data takes it out with the others.

### Fixed
- Account timeline: it now fills its card instead of stopping at a fixed width, long account names are shortened in the middle instead of cut off on the left, and the dates along the top show months and years.
- Accounts: a profile link written without https:// is now matched to its account and platform (an old GitHub name showed as a separate account), API addresses such as api.github.com/users no longer show as accounts named “users”, the platform comes from the profile data when there is some, and what stands out is listed in the order the accounts were made.
- Domains & addresses: long values on the right of the picture no longer run past its edge, and the picture fills its card.

## [1.48] — People, hours and what changed (2026-11-19)

_When the people behind accounts are awake and where that puts them, one profile per person across cases, a complete checklist for every username, email and phone, what changed between two saves of a page, and metadata from old Office files._

### Added
- Infrastructure → Active hours: paste or import post times — Telegram and Discord chat exports, Reddit, Mastodon and X data, any JSON list or CSV with times, or one time per line — and see each person's week, their likely time zone from when they sleep, their weekend (Saturday–Sunday or Friday–Saturday), whether their clock changes for summer, and which accounts keep the same week. Accounts that post at every hour are flagged as automated or shared. Only who and when is kept, so a large chat export stays small.
- Identity profiles: open a Person in the vault, or Vault → Identity profiles. One profile per person: their identifiers with how sure each link is, how much evidence names each and when it was last seen, the same person in other cases (a shared email, phone or wallet confirms; a shared username only makes it likely), where the cases disagree, a map of how it all connects, and the gaps still to close.
- Infrastructure → Accounts → Changes over time: a page or profile saved more than once, each version against the one before — text added and removed, links and email addresses, and every profile field with how much counts such as followers moved. Compare any two records by hand too.
- Metadata from old Word, Excel and PowerPoint files (.doc, .xls, .ppt) and OpenDocument (.odt, .ods, .odp): who made it and who saved it last, when, how many times and for how long it was edited, the program, template, company, custom fields, and whether it holds macros — checked against an independent reader. Damaged or crafted files read as empty instead of hanging.

### Changed
- Forensics kit → Identity pivots is now a full checklist for a username, email address or phone number: profiles, breach and leak searches, search queries, messaging apps and archived copies. Mark each place there, not there or private, add a note, save a found profile to the case, filter what is left to check, and copy a summary. Kept per value across cases, also after a refresh.
- Help answers the new features, and the guided tour has a stop on the Infrastructure tab.

## [1.47] — Sturdier underneath (2026-11-19)

_The trash is back for everything, nothing typed is lost on a refresh, every parser was put through junk, huge and hostile input, and text files from Windows tools read correctly._

### Added
- Text files saved by Windows tools are read the way they were written: UTF-16 (PowerShell “> file”, Excel “Unicode text”, many event-log exports), UTF-8 with or without a byte-order mark, and the old Windows-1252 code page — in log imports, rule packs, notebook imports, threat-intel and cloud files.
- More time formats read exactly: Windows FILETIME, micro- and nanosecond epochs, ISO 8601 basic form (20261102T081530Z), milliseconds after a comma (log4j, Python logging), dates with dots read day-first (02.11.2026), and day-first dates whenever the first number is over 12 (25/11/2026), with AM/PM and a time zone.
- Every text field has a length cap: 4,096 characters for one-line fields, 5 million for text areas (big pasted logs and exports), 2 million for a notebook page; short notes keep their smaller caps. A paste that goes over is cut and says so. Saved names, titles and tags far past any cap are trimmed when the workspace loads.
- New checks: every parser fed empty, binary, 2 MB, deeply nested, mis-encoded, right-to-left and pathological input; hostile markup, quotes, script links, control characters and formulas put in every field and file name, then every page, case tab, panel and dialog opened before and after a refresh; and every kind of saved data through a refresh and a backup.

### Changed
- Stored data in the wrong shape — from an old version, a hand-edited backup or a damaged copy — is put right on every load and import, so no page can break on it; an entry of a kind this version does not know is kept as a document with its kind as a tag. A damaged trash item says so instead of coming back broken.

### Fixed
- The trash is always in the sidebar, and deleting a detection rule, saved query, hunt, playbook, tool or automation now puts it there too (before, only cases, records, vault entries, notes and links did). Each comes back with Restore, also after a refresh.
- A change made just before refreshing or closing the tab could be lost: a finished action is now written at once instead of a quarter-second later.
- With the workspace open in two tabs, closing the one that saves now hands saving to the other by itself — it no longer stays read-only until you click. A page opened by a refresh takes over the moment the old one lets go.
- Deleting an automation that had never run stopped with an error.
- Indicators: a link with brackets in it (Wikipedia pages) is kept whole, a trailing “…” is no longer part of a link, a link to an IPv6 address in square brackets is found along with the address, and dotted numbers with five parts are no longer read as an IP address.
- Three inputs could freeze the page for a minute or more: a very long run of digits in the coordinate reader, a very long run of spaces in a search, and a long Base58-looking string in the decoder. Each is now instant.

## [1.46] — Money, accounts, phones and pictures (2026-11-17)

_Where the money went, when each account was made, what a phone number is, and the same picture found again after it was cropped or mirrored — plus a new Infrastructure tab for all of it._

### Added
- A case tab, Infrastructure, for what a case pivots on: Domains & addresses (moved from Analysis), Money and Accounts. Analysis keeps questions, hypotheses and sources.
- Infrastructure → Money: paste transactions from Blockstream or mempool.space, blockchain.com, BlockCypher, Etherscan (JSON or CSV, coins and tokens), Tronscan or TronGrid. Who paid whom as a picture and a table; Bitcoin addresses spent together grouped as one owner (not in CoinJoin-looking transactions); change and failed transactions left out; collection points, pass-through wallets, distribution and peel chains pointed out; the case's wallets that appear in other cases.
- Infrastructure → Accounts: when each account was made (GitHub, Reddit, Mastodon, X/Twitter, YouTube and Bluesky profile data, and “Joined March 2019”-style text in pages), when it shows up in your evidence, and its earlier names — by account number across two pastes, or a page that says “formerly @…”. Accounts made shortly before they appear, and accounts made within days of each other, are pointed out.
- Phone numbers, offline: country, mobile / landline / VoIP / premium / personal number, whether the number is valid in its plan, ranges reserved for films and TV, and one standard form — so 07911 123456, +44 7911 123456 and 0044-7911-123-456 are one number, matched across cases. Set the country for numbers written without a code.

### Changed
- The same picture elsewhere is found after cropping (up to 30 %), mirroring, framing in a screenshot, text over it, greyscale and small rotations — tested on 18 real photos and their edited copies, with no false matches between different photos. Matches show in the evidence panel with how the copy was changed, with links to reverse image search sites.
- Generators: name handling for accents, apostrophes, double-barrelled and particle surnames, middle names, known handles and years; usernames and work and personal email ranked by how common the pattern is; copy each one, a group, or all; filter; choose separators; save as a text file.
- Forensics kit: the tools sit on one line in three groups — Analyse files, Decode, Investigate — each showing the tool in use — none hidden off the side of the screen.

### Fixed
- Phone numbers written as 0044-… with more groups are no longer cut short when read from text.

## [1.45] — OSINT: metadata, geolocation, infrastructure, sources (2026-11-16)

_What a file says about itself, a workbench for where a picture was taken, what domains and addresses share, and how far to trust each source — all worked out in this browser._

### Added
- File metadata, read from the bytes: HEIC, JPEG, PNG, WebP and TIFF pictures (camera, serial, the time zone it was taken in, GPS with the direction the camera faced, place names, author, the editing program and its history, AI-generation marks, Content Credentials), MP4/MOV/3GP video (recording time and GPS from iPhone and Android), MP3 tags, PDFs (including information kept in compressed object streams) and Word/Excel/PowerPoint (author, last saved by, program, revision). Shown in the evidence panel with what stands out first; GPS goes on the map, the event takes the moment it was taken, and files too big to store still have their video metadata read.
- When a picture has no time zone, the GPS clock gives it (14:05 on the camera, 13:05 UTC: UTC+01:00). iOS 8's day-of-year GPS dates are read correctly.
- Where was this taken? — a geolocation workbench for any picture or video: write down what you see, add the places it could be (coordinates in any format or a map link), mark which clues fit each place, and see the sun's direction, height and shadow length at each place at the moment the file was made. Confirmed places go on the case's map and into the vault.
- Analysis → Infrastructure: paste WHOIS (any registry), RDAP, dig output, passive DNS (VirusTotal, CIRCL, DNSDB, CSV), crt.sh, Shodan or Censys results. Each paste is kept as evidence, and what the domains and addresses share — registrant, certificate, site-verification token, favicon, TLS fingerprint, address, name servers, same-day registration — is listed by how much it means. Privacy services, big DNS providers and CDN addresses are set aside as not links.
- Analysis → Sources: rate each source A–F once (it applies in every case) and each piece of evidence 1–6, the Admiralty grading. What is backed by several independent sources, and what you marked or vaulted on the strength of one weak source, is shown; an indicator's panel says how many independent sources mention it.

### Fixed
- GPS longitudes written both negative and with W are no longer flipped back east; Windows XP author and title tags in pictures are read.

## [1.44] — Endpoint evidence, read like an analyst (2026-11-16)

_Process trees, decoded command lines, the rare things across all your evidence, and a map of how an attacker moved between hosts — built from the Windows and Sysmon logs you already import._

### Added
- Timeline → Processes: parent → child trees per host from Sysmon 1 and Windows 4688. Joined by process GUID, then process ID (hex IDs from 4688 included, reused IDs handled), then the parent's path. A parent missing from the evidence is shown with a question mark, and one started by an earlier process's own command line (cmd /c powershell …) hangs under it. Suspicious processes — Office starting a shell, a shell under services.exe, system names in the wrong folder, programs in folders anyone can write to, obfuscated command lines — are marked, and by default only the branches that lead to them are shown.
- Command lines are decoded where they sit: -EncodedCommand in any of its short forms, FromBase64String, [char] codes, joined strings, backtick obfuscation and plain Base64, several layers deep. The decoded text shows in the evidence panel and the process tree, and the addresses, domains and files it names become indicators of the event.
- Timeline → Movement: host → host from network and RDP logons (4624 types 3 and 10), explicit-credential logons (4648), PsExec-style services (7045), RDP connection records (1149), WinRM and SMB/RDP/WinRM connections. Addresses are named from logons and the hosts' own connections; a diagram in the order hosts were reached and a table with times, accounts and the events behind each move.
- Timeline → Patterns → Rare things: programs, services, scheduled tasks and domains seen on one host once or twice across all your cases. Per-user install paths count as the same program.

### Fixed
- "System binary name running from outside System32" no longer fires on every process whose parent is explorer.exe (it lives in C:\Windows); it is judged per binary, on the binary's own path.
- A LOLBin next to a loopback or link-local address is no longer called a download from an external address.

## [1.43] — Certificates: everything up front (2026-11-16)

_Expiry, the full serial and the thumbprints are now the first thing you see for a certificate or signing request — on the Certificates page and in a case's evidence._

### Added
- Certificates → Key facts, right under the header: status and days left, valid from and expires (exact UTC), lifetime, the full serial number and its size, SHA-256 and SHA-1 thumbprints (the SHA-1 is the “Thumbprint” Windows shows), public-key SHA-256 and pin, key, signature algorithm and OID, version, subject, issuer, names, key usage, extended key usage, basic constraints, key identifiers, OCSP and issuer URLs and revocation lists — each with a copy button that copies plain hex.
- Signing requests show their own SHA-256 and SHA-1, every part of the subject on its own line, the public key's SHA-256 and pin, the version, every requested extension, and the challenge password in full (it is kept in the clear inside the request) instead of cut short.
- A certificate or signing request pasted into a case is decoded in the evidence panel with the same key facts — several in one paste each get their own — and Open in Certificates takes it to the full decoder.
- Certificates in a case's evidence give the case indicators: the SHA-256 and SHA-1 thumbprints (what crt.sh, VirusTotal, Censys and Shodan search by) and the names and addresses they cover — so they show in Entities, search, hunts and connected cases. Certificates already in your cases are read once in the background.

### Fixed
- The serial number is no longer cut short in Subject and issuer.

## [1.42] — Hunts, ageing verdicts, faster at scale (2026-11-16)

_Saved hunts across every case, verdicts that fade with age, notes written from selected events, a rule at a glance — and the rule-heavy screens several times faster on big workspaces._

### Added
- Detections → Hunts: a search (the timeline filter's language) or one of your Sigma rules, run across every case. What it finds when saved counts as seen; new matches are flagged on the hunt and on Today until you mark them seen. Save a timeline filter as a hunt with the crosshair next to the filter box.
- Verdicts age. The date is kept when you set one, however it is set; its weight halves every 90 days for IPs, four months for URLs, six for domains and a year for emails, handles and wallets — hashes never fade. The entity panel says how old a verdict is and when to check it again, Connected cases count old verdicts for less, and Today lists stale ones in open cases.
- Timeline → Select → Write a note: a short summary in plain words (events, hosts, time span, attack stages, malicious indicators, what stands out) and the chronology, each line ending in a citation like [3] that opens that event. Show the cited events filters the timeline to them; citations follow the events when a case is exported and imported.
- A line at the top of every rule sums it up — tests and whether they pass, earlier versions, where it fires and whether it is noisy, look-alike rules — each opening its detail.

### Changed
- Big workspaces: with 50,000 events and 2,000 rules the attack chain went from 5.2 s to 0.6 s, Timeline → Rules from 6 s to 1.8 s and Health from 8.3 s to 2.4 s. Rules now only look at events that could hold their values (an index of three-letter pieces); a test checks this finds exactly what evaluating every rule on every event finds.
- Help and the guided tour cover the newer features: rules against a case, rule history and packs, hunts, connected cases, ageing verdicts, sessions and clock correction, and notes from events. The tour is ten stops.
- Under the hood: every feature's actions are in one registry, with a test that no two features claim the same action.

## [1.41] — Connected cases, rule history, cloud logs (2026-11-15)

_See which cases connect and why, keep every version of a rule, fix blind spots a group at a time, catch the same attack on a second host, and import cloud, identity and network logs as real events._

### Added
- Case overview → Connected cases: the other cases this one shares indicators or vault entries with (phones, wallets, handles compared the way duplicate detection does), weighted by your verdicts — malicious counts most — plus nearby infrastructure (same /24, same registered domain), said to be weaker. Private addresses, benign indicators and anything in most of your cases are left out.
- Detections → rule editor → History: every save that changes a rule keeps the version it replaces (last 25). Compare any two line by line, with title and severity changes listed; put an old version back in the editor and save — the one it replaces is kept too.
- Timeline → Rules → Not caught: blind spots of the same kind are grouped, with One rule for all and a preview of whether the draft would also match other events in your evidence.
- Timeline → Patterns → Sessions: the same run of stages on a second host, later (e.g. Logon → Discovery → Collection → Exfiltration 3 hours after the first host), is pointed out as a likely sign of lateral movement, with both sessions and what happened between one click away.
- A corrected clock now shows on every event it touched (a clock mark in the timeline; the details panel says by how much and what was recorded), and can be taken back from any of those events.
- Log import: AWS CloudTrail, Okta System Log, Microsoft 365 audit (JSON, or the CSV export with the event in AuditData), Zeek (TSV with #fields, or JSON) and Windows Event Viewer XML exports are read as real events — who, what, from where, the outcome and the time — and titled that way (“ConsoleLogin · user ops-admin · from 198.51.100.7 · failure”, “4625 Failed logon · user admin”). Firewall lines like “allow tcp 10.0.0.5:51022 -> 203.0.113.47:4444” now give rules source, destination, port and action to match on.
- Rule packs: Import takes .yml, .yar, .json or the zip that Download makes, and shows before anything changes what is new, what you already have (skipped — but tests it brings are added) and what clashes with one of yours by title: keep both, replace yours (yours stays in its history) or skip. Packs carry tests, version history and test history. One Undo takes the whole import back.

### Fixed
- The newer screens were checked at phone size: no serious accessibility problems and nothing wider than the screen.

## [1.40] — Rules against cases, works offline (2026-11-15)

_See what your rules catch in a case and what they miss, follow rule health over time, spot clocks that disagree and sessions of activity, and use the app with no connection._

### Added
- Timeline → Rules: every rule run over the case. Caught: which rules fired and on which events. Not caught: events that look suspicious (what the evidence reader recognises, technique IDs, attack-stage tags, malicious verdicts) but no rule fires on, each with Draft a rule. Noisy here: rules that fire on more than a fifth of the case. It runs again by itself when the evidence or the rules change.
- Rule health over time. Every save of a rule with tests is recorded; the Tests tab shows the last 30 as a strip and says “Was passing — failing since …” when a rule regresses. Detections → Health gains Tests failing, Your rules without tests and Look alike (rules whose detection logic is nearly the same text, found even with no evidence), and a line saying what changed since the previous check.
- Timeline → Patterns: Clocks that disagree — the same IP, domain, URL, hash or email seen by two sources at a steady offset means one clock is off (exactly whole hours: most likely a time zone read wrongly). The odd source is named once, and its times in this case can be corrected and undone. Normal seconds of jitter are not flagged.
- Timeline → Patterns: Sessions — each host's events split where it goes quiet, with the attack stages each one passes through in order (Logon → Discovery → Collection → Exfiltration in 12 minutes), most suspicious first, and Show this session.
- Works offline. When served from a website, the app keeps a copy of its own files (never your data) so repeat visits open without downloading anything and it works with no connection; a new version replaces the copy. On or off in Settings → Data.

### Changed
- The MAC vendor list, world map, enrichment data and QR reader (1.25 MB) are now fetched only when a tool needs them, not on every visit.

### Fixed
- Closing a tab right after typing in a large notebook could lose the last words: an older save finishing late removed the closing-tab backup. It now removes it only if it already holds those words.
- Preparing a very long log line for the rule engine took seconds (3.5 s for 200 KB); it is now instant. New tests feed broken versions of real log formats — cut off, unbalanced quotes, huge fields, deep nesting, mixed formats — through the importer.

## [1.39] — Starts much faster (2026-11-15)

_The app opens in a fraction of the time it took, especially on a real internet connection._

### Changed
- The big reference files — the MAC vendor list, the CISA KEV catalogue, the built-in rules and playbooks, the graph and map libraries, the reference and cloud packs, the certificate and notebook samples — are no longer on the critical path. That is half of what the app downloads. They load in the background right after the first screen, and any screen that needs one waits for it and fills in when it arrives (never while you are typing). Detections says “loading the built-in rules…” for that moment.

### Fixed
- The page's security policy was stopping the browser from fetching scripts ahead of time, so all ~90 of them downloaded one after another — each waiting a full round trip. They are now all fetched at once. On a typical connection the first screen appears in about 2 seconds instead of 6–9.
- The demo notebook's picture no longer depends on load order.

## [1.38] — Note titles (2026-11-15)

_Every note can have its own title, shown at the top of the card._

### Added
- Notes have an optional title — a line above the text when you jot a note, and a Title field when you edit one. It shows at the top of the card, and Today, search, the trash and the activity list call the note by it. A note can be just a title.
- Titles are cleaned (hidden and direction-changing characters out, spaces collapsed, up to 120 characters) and always shown as plain text. Another note with the same title in the same place (General or the same case) gets a warning; press again to keep both. Duplicating a note gives it “Title (copy)”.

### Removed
- The heading groups added in 1.37 (+ Heading in the notes filter row). Notes keep their case or General as before; any heading groups made are simply ignored.

## [1.37] — Many rules at once, and note headings (2026-11-15)

_Detections can now be picked several at a time, notes can go under headings of your own, and the rule editor says right away when a title is taken._

### Added
- Notes → headings: your own groups for notes, next to General and your cases (+ Heading in the filter row). New notes go under the selected heading, or pick one in the note bar or the edit dialog; a note can be under a heading and pinned to a case. Names are cleaned (hidden and direction-changing characters out, spaces collapsed, up to 40 characters) and must not repeat another heading, a case name or a built-in filter. Renaming and deleting are on the pencil next to the selected heading; deleting keeps the notes and can be undone. A note's ⋯ menu has Change heading.
- Detections → pick several rules with the boxes in the table or gallery (or every rule the current filters show) to star or unstar them, download them, or delete them together. One rule downloads as its .yml or .yar file; several download as a zip with each rule's file in sigma/ and yara/ folders, plus a JSON bundle that Import reads back with tests and metadata. Deleting asks first and can be undone.

### Fixed
- Every script and stylesheet address now carries a fingerprint of the file, so a browser never keeps an older copy after an update — even between two drops of the same version.
- A rule title that is already taken is flagged right under the title as you type, instead of at the very bottom of the editor after saving.
- The rule editor's “Revert” is now “Discard changes”: it stays greyed out until you edit something, then throws your unsaved edits away and puts the saved rule back. Before, it could be clicked any number of times and only showed a message.

## [1.36] — Today, the attack chain and sharper reading (2026-11-15)

_A Today page across all cases, an ATT&CK attack-chain view, duplicate finding and merging in the vault, and a much broader reading of real-world logs and command lines — checked by a new suite of real-world tests._

### Added
- Today (in the sidebar): what needs you now across every case, most urgent first — watch alerts, overdue and due notes, indicators a lookup or your indicator store flagged that you have not judged, what arrived in cases since you last opened them, open questions, cases gone quiet for a week, and a due backup. Each with the button that deals with it.
- Timeline → Attack chain: the case's events placed on the ATT&CK stages (including the new Stealth and Defense Impairment) from technique IDs, recognised behaviour, tags and your Sigma rules. Stages missing between the first and last one seen are named as where to look next, each with what to look for and the rules for it.
- Vault → possible duplicates: the same email, domain, URL, phone, handle or person entered twice — different case, defanged, www., trailing slashes, phone punctuation, accents or word order — and names one letter apart, marked “probably”. Merging fills empty fields, keeps every tag, note and link, notes differing values, and can be undone. “Not the same” is remembered.
- Windows events copied as text (Event Viewer or a SIEM message field: “New Process Name: … Process Command Line: …”) are now read into fields, so rules and the timeline understand them.

### Changed
- Behaviour recognised in command lines and logs grew from 7 patterns to more than 20: downloads with certutil, bitsadmin, PowerShell and curl | bash; cleared logs and shell history; shadow-copy deletion; scheduled tasks, services, cron and SSH keys; new admin accounts; mshta, rundll32, regsvr32 and msiexec abuse; LSASS dumps, SAM saves and /etc/shadow; domain discovery; PsExec, WMI and WinRM; disabled Defender, firewall or logging; password-protected archives; rclone and upload sites; reverse shells. Everyday admin commands are not flagged.
- A new real-world test suite: indicators in messy forms and things that must not be indicators, ten log formats reaching the same fields and rule, 30 attacker command lines and 15 everyday ones, duplicates that must and must not merge, odd timelines, broken files, every built-in rule converted to every SIEM, and random input fed to every engine.

### Fixed
- A domain written in another script (раураl.com) is kept whole and flagged as a look-alike, instead of being cut down to “l.com”.
- The graph button on vault cards opens the graph on that entry; the star is yellow everywhere; the coloured side stripes are gone from cards.

## [1.35] — Detection lab and better notes (2026-11-15)

_Build, test and harden detection rules inside OSINTrix — SIEM queries, rule tests, an evasion check and rules drafted from evidence — and a formatting bar for notes._

### Added
- Rule → Queries: any Sigma rule as Splunk SPL, Microsoft Defender XDR KQL, Microsoft Sentinel KQL (Sysmon), Elastic ES|QL and IBM QRadar AQL — including not, 1 of / all of, null, CIDR ranges and regular expressions. Field names can be remapped per product and are remembered.
- Rule → Tests: events a rule must fire on and must not fire on, kept with the rule, run as you edit and again on every save — a save that breaks a test tells you. Add tests by pasting an event or from what the rule fires on in the current case. Tests travel with rule exports and backups.
- Rule → Evasion: a matching event is changed the way attackers change it — renamed program, ^ and quotes in commands, / or en dashes for flags, shortened PowerShell parameters, extra spaces, environment variables, short paths, IPs written as numbers — and the rule is checked against each, with the fix (for example the OriginalFileName to add) and a one-click |windash.
- Timeline → Select → Draft a rule: a Sigma rule from what the selected events share, checked against all your other evidence for noise, with the selected events saved as its tests.
- Notes have a formatting bar: to-do, bullet, numbered item, heading, bold, code, today's date and a divider. Enter carries a list on, Enter on an empty item ends it, Ctrl+B makes bold. Notes now show headings, bullets, numbers, bold, italics and code.

### Changed
- The browser Sigma engine now understands |windash, |cidr, |base64 and |base64offset, and null values; regular expressions are no longer lower-cased before matching.
- Vault cards say what matters at a glance: the full value, only the fields that are filled in, your note, the verdict with its lookup score, how many records mention it and when, what it is linked to, open questions about it, whether it is watched or also in another case, and a picture for media entries. Copy, timeline and graph are one click away. A new List layout shows every entry in a sortable table.

### Fixed
- New rule from the Coverage or Health view now opens the rule editor instead of silently adding rules.
- A note's due date is marked overdue against today's date; the rule editor no longer fails when there are no cases.

## [1.34] — The engine works for you (2026-11-15)

_Timeline patterns, picture intelligence, automations, a since-you-were-last-here feed, a guided tour, faster long lists and backup reminders — all running in the browser._

### Added
- Timeline → Patterns: the likely first sign of compromise (with its reasons, the host, and the dwell time after it), bursts of activity against the case's usual rate, quiet periods, hosts that went silent early, cleared logs, time zone mix-ups and impossible dates, and the working hours the activity fits. Each finding opens just its events.
- Media → Picture insights: the same or a near-identical picture in this case or another, the same camera (by serial number, or make and model) across cases, pictures taken within 250 m of pictures in other cases, and signs of editing — an editing program, changes after capture, a future capture date, a disagreeing GPS date, or stripped metadata. Older pictures are read once, the first time the view opens.
- Automations (Playbooks → Automations): when a new indicator appears, evidence mentions something, or an indicator is judged malicious — check it against the indicator store, look it up, watch it, add it to the vault, ask a question, set a verdict or run a playbook. Five ready-made rules. They run while the app is open, act once per item, never on the demo cases, and write everything they do to a log. Automations restored from a backup arrive switched off.
- Since you were last here: a case's Overview lists what arrived while it was closed — evidence (yours and the automations'), new vault entries, lookups that came back, indicator-store and news matches, its indicators turning up in other cases, and notes that fell due.
- A guided tour of the demo case in eight stops, from Help or the setup.

### Changed
- Backup reminders after a week of your own work instead of two, on the dashboard and in the sidebar footer, offering automatic folder backup where the browser supports it; the setup offers it too.
- The indicator store, the known-exploited vulnerabilities list and the detection rules (table and editor) draw only the rows on screen: 50,000 indicators open in about 30 ms, and nothing is cut off at 200 rows any more.

### Fixed
- The indicator store no longer fails to draw when there are no cases.

## [1.33] — Media fixes (2026-11-15)

_Two fixes from using the new media features._

### Added
- The New image / video form has a file field: choose or drop the picture, video, audio or saved page, and the title, media type and resolution fill themselves in. Files over 50 MB are recorded by fingerprint.

### Fixed
- Switching between a case's tabs now closes the details panel, so a vault entry opened on the Vault tab no longer sits over the Overview. Opening a record from elsewhere still keeps it selected.
- Videos recorded by browsers and some phones, which leave their length out, now show their length.

## [1.32] — Media in every case (2026-11-15)

_Pictures, videos, audio and saved web pages can now be added to a case from anywhere — drop them, paste a screenshot, or use the new Media tab — and are kept as untouched evidence without filling the browser._

### Added
- Media tab in every case: a grid of the case's pictures, videos, audio, saved web pages and documents with previews, video length, picture size and filters. Videos and audio play inside the app.
- Drop files anywhere on a case, or paste a screenshot with Ctrl+V, and they become evidence records with their SHA-256, picture size or length, camera and GPS position when the photo has them.
- Image / video entries in the Vault can hold the file itself, not just a link; the entry fills in its title, type and resolution from the file.
- Files over 50 MB are recorded with their name, size and SHA-256 instead of being stored, so you can later prove the copy on your computer is the same file.

### Changed
- Space: the same file added twice is stored once; pictures and videos get a small preview so lists stay fast while the original is kept unchanged; you are told when browser storage is over 85% full.
- Back up everything now asks whether to include files and shows the size of each choice. A backup made without files says so when it is restored.

### Fixed
- Videos could not play inside the app because the page's security policy had no rule for media; it now allows only the app's own stored files.

## [1.31] — Big lists and nothing lost (2026-11-15)

_The timeline and the entity table now show every row of a large case, drawing only what is on screen. A data-safety review of saving, restoring, exporting and importing found eight bugs, three of which could lose data; all are fixed and covered by tests._

### Changed
- Big lists: the case timeline and the entity table draw only the rows near the screen, so a 10,000-event timeline opens in about 75 ms instead of 600 ms, and the table shows all entities instead of stopping at 400. Day headings stay pinned, the keyboard (j / k) walks every event, and opening a record scrolls straight to it.
- The share dialog remembers your last TLP, redaction and file choices.

### Fixed
- Data safety: “Remove leftover files”, freeing notebook space, emptying the trash and forgetting a recent file no longer delete files that a restore point still needs. Going back to that restore point now brings its attachments and pictures back too.
- Data safety: turning on encryption or changing the passphrase now saves the workspace first and then re-encrypts restore points and files. If the tab closes part way, OSINTrix finishes the job on the next start (asking for the previous passphrase if needed) instead of leaving files that no passphrase opens.
- Data safety: a damaged or unreadable restore-point list is rebuilt from the restore points themselves instead of being replaced by an empty one, and two restore points made at the same moment can no longer overwrite each other’s list.
- Undoing a backup import, or going back to a restore point, now also brings back the indicator store.
- Case files now carry the case’s notes and the verdicts on its indicators; competing-hypothesis evidence keeps pointing at the right records after import. An imported copy of the demo case is no longer removed by “Remove sample data”.
- Restoring an entry from the trash keeps relationships whose other end is still in the trash; they come back when that entry is restored.
- With no cases at all, Playbooks, the Decoder and New evidence no longer fail; they offer to make a case.
- Exported detection rules import back as the same rules instead of duplicates, and keep their stars, references and linked case.
- Long labels in menus (for example on a news story) stay on one line instead of overlapping.
- Hardening from the same review: imported cases, links and verdicts are checked field by field; spreadsheet formulas hidden behind spaces or full-width signs are neutralised in CSV; key strengths outside the safe range are refused; crafted Office metadata, Windows event logs and Word pictures can no longer stall the tab or fill memory.

## [1.30] — Hardened, faster, shareable, easy to start (2026-11-15)

_An independent security review of everything added since v1.24 found three medium and several low issues; all are fixed. Large cases are much faster. A share package hands a case to another team in one ZIP, and a two-minute setup gets new users from nothing to a working investigation desk._

### Added
- Share package (Report → Share): one ZIP with a read-only page, a STIX 2.1 bundle, a MISP event, the case's Sigma and YARA rules, an indicators CSV and the Markdown report. The page is a single HTML file with no scripts that loads nothing; indicators in it are defanged. Every file is marked with the chosen TLP, and MANIFEST.txt holds a SHA-256 for each file. Redaction masks people's details in the page, report and CSV and leaves them out of STIX and MISP.
- First-run setup in five steps: choose offline, free sources or free sources plus your relay; pick exactly which services may see what you investigate; connect and test the relay; switch on news, known-exploited CVEs, EPSS, CVE records and ATT&CK updates; then set a passphrase and choose where to start. Offered from the welcome screen and the dashboard, and re-runnable from Settings.
- Tests: a 10,000-record speed test, accessibility checks on every new screen in light and dark, and regression tests for each security fix (60+ end-to-end tests in all).

### Changed
- Speed on a 10,000-record case: smart search went from 500 ms to about 10 ms, editing on the Overview from 420 ms to under 100 ms, and opening the graph from 640 ms to about 65 ms. On very large cases the copilot reads the case just after the page appears instead of holding it up. Record and entry look-ups use an index, and observations and ATT&CK coverage are remembered until the data changes.

### Fixed
- Security: an imported backup can no longer change this browser's relay address or token, API keys, lookup sources, online-check schedule or per-case auto-checks. It also cannot override the address of a built-in feed; a crafted file could otherwise have sent watched indicators and the relay token to someone else's server.
- Security: downloading a restore point no longer includes API keys, the relay token or the signing key.
- Security: a crafted STIX file can no longer freeze the tab (pattern parsing is now linear and capped), and report redaction stays fast on long runs of dots.
- Security: scores and history imported from a backup are reduced to plain numbers and text before they are shown. Rule-tuning text is escaped, CVE reference links are checked like every other link, and API keys never follow a redirect.
- Relay hardening: rate-limits before checking the token, refuses encoded paths, passes on only the query parameters each service needs, caps request bodies while reading them, and does not follow upstream redirects.
- Redaction no longer masks dates and times as if they were phone numbers.

## [1.29] — Detection coverage, rule health and file triage (2026-11-15)

_Detections now shows your rules on the ATT&CK tactics next to what your cases actually show, so the gaps that matter stand out and can be drafted as rules. A health check lints every rule and runs it over all your evidence to find noisy, broken and duplicate rules, with tuning suggestions. The file inspector opens with a triage verdict, its reasons and an entropy map._

### Added
- Detections → Coverage: techniques covered on each ATT&CK tactic, highlighted where your cases show them. "Gaps that matter" lists techniques your evidence shows with no rule, and Draft a rule writes a starter Sigma rule from the evidence that showed it.
- Detections → Health: every rule is linted (undefined or unused selections, values too short or too common on their own, invalid regexes, missing level, false positives, id or technique, short YARA strings) and run over the evidence of every case.
- Health finds rules that fired, noisy rules (firing on a large share of records or mostly on benign evidence), broken rules and duplicates that fire on the same records. YARA features the browser cannot run are marked as untestable, not broken.
- Tuning suggestions: for a noisy Sigma rule, the field values most of its hits share become a ready filter block to copy into the rule.
- The case copilot points out techniques in a case that no detection rule covers.
- File triage: the file inspector opens with a score out of 100 and every reason. It weighs double extensions and hidden right-to-left names, wrong extensions, programs, shortcuts and scripts, macros and remote templates, active PDF content, packers, high-entropy sections, suspicious imports, impossible compile times, hidden appended data, programs embedded in files, near-random content, malicious strings (encoded PowerShell, download cradles, injection, shadow-copy deletion, ransom notes, Mimikatz, offensive frameworks), network addresses inside, indicators already known to be malicious, earlier verdicts and live lookups on the hash, and YARA matches.
- Entropy map: a bar for each part of the file shows where packed or encrypted data sits. Mark the file malicious or suspicious from the triage card; the downloaded report and the evidence saved to the case include the triage.

## [1.28] — Report writer and OSINT research (2026-11-15)

_Reports now write the parts analysts write last — a bottom line with a stated confidence, the attack path, recommendations with reasons, and the limitations — and export to Word. The Forensics kit gains look-alike domain hunting and identity pivots, and every indicator's details suggest the next steps worth taking._

### Added
- Report bottom line: what happened, to which hosts, when, how, what is confirmed and what is still open, drafted from the case with a stated confidence (high, moderate or low). Rewrite it in your own words or go back to the draft.
- Attack path: the ATT&CK tactics in the order the evidence shows them, each with the first record and a citation.
- Recommendations sorted into Now, Next and Later, each with its reason and the indicators it covers. They include isolating hosts, blocking network indicators, purging phishing mail, resetting credentials, hunting hashes, removing persistence, patching exploited CVEs, preserving logs, domain takedown via the registrar, detections, watching and lessons learned. Drop any one, and bring it back.
- Confidence and limitations: what the confidence rests on (findings, answers, confirmations, timeline, sources) and what weakens it (open questions, missing times, assumed time zones, unchecked indicators, disagreements, close hypotheses).
- The full report lists every malicious or suspicious indicator with its live score. Reports export to Word (.docx) with the relationship map, as well as Markdown and PDF.
- Look-alike domains (Forensics kit): over 250 imitations of a domain — typos, keyboard slips, look-alike and Unicode characters, bit flips, other endings and added words. Check which exist through Google DNS, with registration age from RDAP. Each is ranked by risk (receives mail, newly registered, hard to spot; on the original's own servers counts against). Add the risky ones to a case or export CSV.
- Identity pivots (Forensics kit): a username across more than 50 sites in seven groups, with ticks remembered; an email address taken apart (canonical Gmail form, sub-address, disposable inbox, role account, likely name and year, mail provider from its MX records, Gravatar); a phone number read into country and international format with messaging and lookup links.
- Next steps in an indicator's details: what is worth doing next given what is already known, such as checking it online, finding its registration date, hunting look-alikes, pivoting on the username or finding the abuse contact.

### Changed
- Printed reports leave out on-screen controls.

## [1.27] — Copilot, graph intelligence and smart search (2026-11-14)

_Every case gets a copilot that reads it and says what to do next, what is missing and what the story so far is. The graph now shows risk spreading from malicious entries, its key nodes and links hidden in your lookups, and can expand a node online. Search understands plain questions such as "malicious IPs last week in TN-2026-014" or "what talks to 203.0.113.47"._

### Added
- Case copilot on the Overview: ranked next steps, each with its reason and one button. Steps include indicators in your threat feeds, ones flagged by live lookups, exploited CVEs, never-checked indicators, relationships to review, entries close to malicious infrastructure, the right playbook for the kind of case, watching and detection rules for malicious indicators, and open questions.
- Copilot gaps: records without a time, times read in an assumed time zone, verdicts the live lookups disagree with, vault entries nothing supports or connects, and a missing scope.
- The story so far: a plain-language summary built only from the case covering the time span and hosts, indicators and verdicts, what the evidence shows, ATT&CK techniques, malware, feed hits, exploited CVEs and open questions. Copy it or save it as a note.
- Check new indicators online, per case and off by default. When it is on, new public indicators in that case are looked up with your switched-on sources as evidence arrives, and you are told if one looks malicious.
- Graph risk: suspicion spreads from malicious entries along your links. It weakens with every hop, with weaker links, and for people, organisations and places, which are often victims. Benign entries stop it. Each score names the malicious entry it comes from and the path. Colour by risk shades the graph.
- Graph key nodes: PageRank, bridges between groups and connections combined, with the reason for each.
- Hidden links: saved live-lookup answers are compared, without new requests. Entries sharing a certificate, IP, favicon, name servers, JARM or registration day appear as suggested relationships.
- Expand online: a node's live lookups bring back what it resolves to, its hostnames, certificate names, samples and subdomains as new linked entries, with Undo.
- Smart search: plain questions are turned into filters and shown back as chips under "Understood as". Filters cover indicator kind, verdict, flagged or unchecked, watched, in your feeds, exploited, time seen (today, last 3 days, this month, September 2026…), case, host, port, country, network ("hosted on vultr", AS numbers), registration date, Tor, related to another indicator, and riskiest, most seen or newest first. They run over every case.

## [1.26] — Live investigation engine (2026-11-14)

_Threat Intel now asks the services analysts use — Shodan, VirusTotal, AbuseIPDB, GreyNoise, OTX, urlscan, abuse.ch, RDAP, DNS, certificate logs and more — at the moment you investigate, and weighs every answer into one scored verdict with its reasons. A whole case can be checked at once and its indicators grouped by shared infrastructure. Bundled data is now only a fallback: KEV, ATT&CK and CVE records come live._

### Added
- Investigate tab: paste an IP, domain, URL, file hash, CVE or ASN and every lookup source you switched on is asked in parallel. Answers appear as they arrive, one card per source with its key facts and a link to the source's own page.
- Verdict engine: one score out of 100 (Malicious, Suspicious, Benign or Nothing found) from all sources, weighted by how much each source is trusted, how strong its evidence is and how old it is, with agreement between independent sources counting for more. Every verdict lists its reasons and a confidence level. Mark it as your verdict in one click.
- Lookup sources that work straight from the browser: Shodan InternetDB, DNS (Google DoH), RDAP registration data, ipinfo, RIPEstat, Tor relays (Onionoo), CertSpotter, HackerTarget, the Wayback Machine, AlienVault OTX, Have I Been Pwned breaches, CVE.org with CISA's exploitation assessment, and FIRST EPSS. Shodan works with your key.
- Through your own relay: VirusTotal, AbuseIPDB, GreyNoise, urlscan.io, crt.sh, NVD and abuse.ch ThreatFox, URLhaus and MalwareBazaar — services that refuse browser requests.
- The relay: a small Cloudflare Worker in tools/relay that you deploy to your own account. It keeps API keys server-side, forwards only to listed hosts and paths, checks a token, allows only your origins and rate-limits. Set its address and token, and test it, in Sources → Lookups.
- Leads: hostnames, subdomains, resolved addresses, certificate names and related samples found by the sources, each one click from its own investigation or the case.
- Investigate a whole case: every public IP, domain, URL, hash and CVE is checked in a queue with progress, ranked by score, and the flagged ones can be marked together.
- Correlation: indicators that share a TLS certificate, IP address, favicon, name servers, JARM fingerprint, registration day and registrar, page title, malware family or network are grouped, with links weighted by how rare the shared trait is. Link on the graph draws the groups as relationships in the case.
- News, For you: stories are ordered by what matters to you — indicators from your cases and watchlist, your stack, known-exploited CVEs, severity, feed hits and how many sources report it — and the order learns from what you mark relevant or dismiss. Each story says why it is near the top. Newest first is still available.
- Watchlist online checks: watched IPs, domains, URLs, hashes and CVEs can be re-checked every hour, 6 hours or day while the app is open, or with Check now. New ports and addresses, more detections, higher abuse scores, new reports and verdict changes are listed under Changes and announced.
- The indicator details panel shows the last live verdict and an Investigate button.
- MITRE ATT&CK can be refreshed live from MITRE (checked at most once a week) and kept in this browser; the bundled copy is the fallback.

### Changed
- CVE details come from the official CVE.org record, which allows browser access, with CISA's exploitation assessment shown on the CVE page. NVD scores fill in through the relay when the record has none.
- abuse.ch indicator feeds are fetched through the relay, which holds the Auth-Key, since abuse.ch does not allow browser access.
- The Content Security Policy names each lookup host; the only wildcard is *.workers.dev for your relay.
- Answers from sources are kept for a while (encrypted with the workspace) so the same indicator is not asked twice; Sources → Lookups → Clear saved answers removes them. API keys and the relay token are never put in backups.

### Fixed
- Watchlist showed "just now ago".

## [1.25] — Threat Intel, professional edition (2026-11-14)

_Threat Intel becomes a full CTI desk: news read for CVEs, actors, malware and ATT&CK techniques; known-exploited vulnerabilities with EPSS and CVSS and a My stack watchlist; an indicator store that imports and exports STIX 2.1, MISP and CSV; offline MITRE ATT&CK with actor pages and Navigator layers; and one-click threat briefs. Every live source is off until you switch it on._

### Added
- Threat Intel has five tabs: News, Vulnerabilities, Indicators, Actors & ATT&CK and Briefs.
- News: the same story from several sources is grouped into one, with +N sources. CVEs, ATT&CK technique IDs, threat actors, malware, vendors and indicators are read from every story and shown as chips you can click.
- News triage: Inbox, Relevant, Starred, All and Dismissed, with unread markers, Mark all read, actioned and undo. Filter by category, source, an extracted CVE, actor or vendor, Mentions my cases or My stack.
- News: a Needs attention panel when feed indicators appear in your cases or exploited vulnerabilities hit your stack, and a This week panel with the most mentioned CVEs, actors, techniques and vendors.
- Ten more news sources you can switch on: CISA advisories, NCSC UK, Cisco Talos, Unit 42, Securelist, Check Point Research, The DFIR Report, SecurityWeek, Dark Reading and MSRC.
- Vulnerabilities: the CISA Known Exploited Vulnerabilities catalog is bundled (1,781 entries) and can be refreshed live. See CVEs in the news, all KEV or only your stack, with ransomware use, EPSS and CVSS columns.
- My stack: watch the vendors and products you run. Stories and exploited vulnerabilities that touch them are flagged in News, Vulnerabilities and the brief.
- CVE pages: the KEV entry and due date, EPSS from FIRST and CVSS from NVD on demand, the stories that mention it, reference links, and Add to case.
- Indicators: a store of up to 50,000 indicators with TLP, confidence, first and last seen, expiry, tags and sources, kept in this browser and encrypted when encryption is on.
- Indicator import: STIX 2.1 bundles (patterns, observables, TLP markings, indicates relationships), MISP events (tags, objects, composite types), ThreatFox and Feodo exports, CSV with any common header, or plain lists. The format is detected automatically.
- Indicator feeds you can switch on: abuse.ch ThreatFox, Feodo Tracker and URLhaus, with an optional Auth-Key. They merge into the store with a 14-day expiry when you refresh.
- Indicator export: STIX 2.1, MISP or CSV of the indicators shown, every live indicator, or a whole case, with a TLP marking.
- Indicators from your feeds that also appear in a case are flagged in Threat Intel and on the indicator in the case (In your feeds), and CVEs in CISA KEV are marked Known exploited.
- Actors & ATT&CK: MITRE ATT&CK Enterprise is bundled offline (706 techniques, 178 groups, 842 malware and tools). Each actor page shows aliases, techniques, software, related groups and your stories.
- ATT&CK heatmaps by tactic for techniques in the news or for one actor, exportable as an ATT&CK Navigator layer.
- Briefs: build a threat brief for 24 hours to 30 days from starred, relevant and critical stories, new KEV entries, top actors and techniques and feed hits in your cases, with a TLP marking. Save it to the Notebook, download Markdown or copy it.
- Sources has three tabs: News feeds, Vulnerability data (KEV, EPSS, NVD) and Indicator feeds. Each source shows the one host it contacts and its last status, and is off until you switch it on.

### Changed
- The story panel adds Star, Relevant, Actioned and Dismiss, the extracted CVEs, actors, techniques and vendors, and the other sources that reported the same story.
- Backups now include the indicator store. Feed API keys are never included.
- Security: the page may connect only to named hosts, each opt-in: api.rss2json.com, raw.githubusercontent.com, api.first.org, services.nvd.nist.gov and three abuse.ch hosts. Every imported value is re-validated, text is capped and stripped of HTML, javascript: links are dropped, and CSV exports neutralise formulas.

## [1.24] — Cases board and design pass (2026-11-14)

_The Cases page gets two views you can switch between: board cards that show each case's own relationship graph, and a list built for scanning. Buttons, inputs, filters, menus and search are larger and more consistent across every page._

### Added
- Cases list view: one row per case grouped into Pinned, Active, In review and Archived, with questions answered, entries, records, malicious count, a 12-week activity chart and last update. Switch with Board and List; your choice is remembered.
- Cases: find a case by name, code, scope or owner, and sort by last activity, name, most malicious, most entries or newest. Pinned cases stay at the top.
- Nothing is lost on refresh. Certificates, crt.sh results and signed programs you open, cloud configs and logs, and Lab files (inspector, packet capture, SQLite, image) are kept in this browser and reopen after a refresh. Decoder input, Lab text tools, the log parser, the SQL console and open tabs come back too.
- History: Certificates, Cloud and each Lab tool have a History button listing what you opened. Reopen or delete each item on its own, or delete all. Certificates History also lists what is saved in the case, and each can be moved to the trash.
- Settings → Storage shows how much space recent tool inputs use, with a Manage button to delete them one by one. Files over 50 MB are not kept, and private keys never are.
- Restore points, recent searches in Ctrl+K and recent query runs can each be deleted on their own.

### Changed
- Cases page redesigned. Board view (the default): each card shows a small picture of the case's own graph with malicious entries ringed in red, entry and malicious counts, status, the top entries, questions answered and when it last changed.
- Buttons, icon buttons and inputs are taller with more padding; selects have a proper arrow; filter chips use the accent colour when on instead of black, in light and dark themes.
- The search palette (Ctrl+K) is wider with a larger input, and its scope filters wrap instead of hiding after CTF. The search bar at the top is larger.
- Toolbox: the filter row, list and grid switch and bulk bar are restyled, and the menu behind a tool's three dots no longer scrolls.
- Graph: the Map, Arrange and other tools stay visible, and the details panel opens below the toolbar instead of covering it.
- CTF cheatsheets redesigned: the categories and their command groups are one list on the left, styled like Reference. One search, then Commands, Recognise it, Gotchas and First moves as tabs, so the commands get the full width.
- CTF cheatsheets: Target, File, Wordlist, Your IP and Port moved into a Values button. Its popover fills every command as you type, and the button shows what is set.
- CTF write-ups: the list is grouped by event, each row showing category, points, solved, age and the TL;DR. Search, All, Mine and Imported, and a category filter behind one button.
- Recent tool inputs are encrypted with your passphrase when encryption is on, are re-encrypted when it changes, and are not included in backups.
- Decoder, Certificates, Cloud and CTF: cleaner focus on the input, roomier indicator and pivot tables, Test it inputs that match the rest of the app, and restyled filters and search bars.

### Fixed
- Security: decompressing data (Decoder, ZIP and Office files in the Lab, notebook .docx import, compressed HTTP bodies in packet captures) now stops at a size limit, so a small decompression bomb cannot freeze the tab.
- Security: every download gets a safe file name with no path parts, reserved names or control characters such as right-to-left overrides. The Lab image tool now refuses non-images and files over 100 MB.
- The Toolbox menu behind a tool's three dots, and every other menu, now closes when the page scrolls instead of floating away from its button.
- CTF cheatsheets: your Target value is no longer filled into email addresses such as target@example.com.

## [1.23] — Certificates, advanced (2026-11-13)

_Certificates become an investigation tool: an investigator's read of each certificate, its indicators with pivots and the records in your cases that already mention them, plus signed-program checks, a clearer comparison, key reuse, Certificate Transparency analysis, hunting queries and exports. Certificates now use the full width._

### Added
- Investigator's read: a plain-English assessment of each certificate (who it belongs to, the infrastructure it names, timing, red flags, key reuse) with next steps you can click, and Copy for a report.
- Indicators and pivots: every domain, IP address, email and organisation in the certificate with VirusTotal, urlscan, WHOIS, AbuseIPDB, Shodan and more. Each shows whether it already appears in your cases; select them to add to the case graph or copy them defanged.
- Already in your cases: records in any case that mention the certificate's names, IP addresses or fingerprints, or share a registered domain with them, one click away. The Transparency logs view marks names already in your cases and has a lookup menu per name.
- Signed Windows programs: drop an .exe, .dll or .sys file to read its Authenticode signature. The file is hashed and checked against the signature, the signer's signature is verified, and the publisher, program description, timestamp, dual signatures and data appended after the signature are shown. The file's SHA-256 links to VirusTotal.
- Compare: says how two certificates relate (same certificate, issuer and issued, renewal with or without a new key, same owner through a shared key, names moved to another CA, related domains), with both certificates side by side, their lifetimes on one timeline, names only in A, in both and only in B, and a grouped field-by-field table that shows just the differences or every field.
- Key reuse: a certificate whose public key appears in other certificates in the case is flagged, with a one-click comparison. Different names on one key tie them to the same owner.
- Transparency logs: paste or open the JSON that crt.sh returns for a domain. Precertificate and final copies are merged; you get every name with first and last issue dates, what is valid now, interesting hosts such as VPN, login and build systems, names new in the last month, lookalikes, issuers and a timeline of issuance. Filter, sort, copy, export CSV or add the names to the case.
- New guide chapter, Types of certificates and what they are for: website, client authentication, device, trusted server CA versus trusted client CA (mutual TLS), root and intermediate CAs, code signing, email (S/MIME), Windows logon, document signing and timestamping. Each covers what it is for, how to recognise it, where you meet it and how investigators and attackers use it, with a fictional example to open and a side-by-side table. The decoder labels every certificate with its type and links to the matching section, and the investigator's read explains it.
- Test it: does a certificate cover a host or URL (wildcards matched the way browsers do), and was it valid at a given moment.
- Hunt for it: ready-to-copy Shodan, Censys and crt.sh queries, Suricata rules by fingerprint and serial, a Defender and Sentinel query for code signing certificates, and a PowerShell check for planted roots.
- Export a certificate as PEM, DER, JSON or a text report, or the whole chain as PEM. Fingerprints now include the key SHA-256, with a crt.sh link to every certificate sharing the key.

### Changed
- No more input column: a bar along the top shows what is open and where it came from, with Paste (a large paste window), Open file, Examples and Saved. Paste with Ctrl+V or drop a file anywhere on the page. Certificates use the full width, and the text is larger.
- Text is a little larger everywhere by default, and Settings → Text size now scales every page and section evenly: all font sizes follow one text scale instead of fixed sizes.
- What's new redesigned: a header with release and change totals and a breakdown bar, large filter tiles by type, a search that marks matches, a release list to jump to any version, changes grouped by type in each release, and older releases folded until opened. Filtering and searching no longer redraw the page.
- Certificates: key files and PKCS#12 bundles (.pfx, .p12, .key) are refused before being read; the PGP and OpenSSH private key formats are caught too. Saved certificates record where they came from and when they were examined. Suricata rules get a stable sid per certificate, internationalised host names are matched in their xn-- form, and very large inputs no longer risk a crash when exported.

### Fixed
- Code signing and other non-website certificates are no longer labelled DV or OV.
- A button whose icon is missing no longer shows an empty gap.
- The Trash count in the sidebar could include items older than 30 days that had already expired; they are now cleared before counting, so the count matches the Trash page.
- Security: every CSV export (records, indicators, entities, graph, places, audit log, SQLite results, Transparency logs) now neutralises cells that start with = + - or @, so evidence text can never run as a spreadsheet formula when the file is opened in Excel or Sheets.

## [1.22] — Certificates (2026-11-13)

_A Certificates section: decode certificates, chains and signing requests in the browser, see what they reveal, and learn how certificates work._

### Added
- Decoder: paste PEM, base64 or hex, or open .crt, .cer, .der, .pem, .csr or .p7b files (openssl s_client output works too). Shows who a certificate is for and who issued it, its lifetime, every name it covers, each extension in plain English, SHA-256, SHA-1 and key-pin fingerprints, and the raw ASN.1 structure.
- Findings for investigators: lookalike brand names, unrelated domains on one certificate, Cobalt Strike and openssl defaults, self-signed certificates claiming a brand, weak keys and hashes, lifetimes longer than public CAs may issue (including the 200-day limit from March 2026), tiny serials, AD CS logon certificates (UPN plus client authentication) and enrollment agents.
- Chain: certificates in any order are sorted leaf to root and every signature is verified with the browser's own cryptography (RSA, RSA-PSS, ECDSA and Ed25519). A missing root is named; a broken signature is shown in red.
- CSR: what a signing request asks for, its signature, key strength, missing or mismatched names, a stored challenge password, and whether it shares a key with a certificate.
- Save a certificate to the case as evidence: its names and fingerprints become entities, and the issue date lands on the timeline. Pivot links to crt.sh, Censys, Shodan and VirusTotal.
- How certificates work: ten short chapters with diagrams, an annotated certificate, commands and flashcards that go to your Notebook in one click.
- PCAP: certificates in TLS 1.2 and older handshakes open in the decoder. Certificate files dropped on the capture dialog open there too.
- Private keys are never read: if one is pasted, it is removed from the box with a warning.

## [1.21] — Safe keeping (2026-11-08)

_Nothing lost on refresh, automatic backup to a folder, notebook pictures out of the main save, and a Storage panel that warns early and frees space._

### Added
- Settings → Storage: space used against what this browser allows, a breakdown (workspace, case attachments, notebook pictures, restore points, trash) and one-click clean-up: empty the trash, keep only the newest restore points, free deleted notebook pictures, remove leftover files.
- Early warnings: the top bar shows when storage passes 85% or under 200 MB is free, a failed save is shown in red with a prompt to free space or export, and pictures, attachments and imports that would not fit are refused before anything is written.
- Ask the browser to keep the data (persistent storage), so it is not cleared when the disk is short.
- Automatic backup to a folder (Chrome and Edge): pick a folder once, such as Documents or a OneDrive or Google Drive folder, and a full backup is written there a few minutes after changes, as osintrix-latest.json plus one dated copy per day (the last 7 are kept). Encrypted workspaces write encrypted backups. If the browser needs permission again after a restart, backup pauses and one click resumes it.
- The top bar shows Saving… while a change is still being written. Closing or refreshing the tab at that moment makes the browser ask before leaving, and the save finishes while it asks, so large and encrypted workspaces no longer lose the last change. A workspace with everything saved never asks.

### Changed
- Notebook pictures and files are stored as separate blobs in the browser, encrypted with the workspace when encryption is on. Autosaves and restore points no longer copy them, so saving stays fast with hundreds of screenshots.

### Fixed
- Export everything now includes notebook pictures and files, and importing the backup brings them back.
- Notebook data in an imported backup is checked field by field and every page is cleaned again; Word files that would unpack to an unsafe size are refused.
- Typing right before a refresh or closing the tab is kept. Pending page text, titles and sources are saved first, and when a workspace is too big for the instant localStorage copy, the last page edits go to a small journal that is merged back on the next start.
- Pictures from deleted pages are kept for 30 days, so undo and restore points bring them back. A notebook page opened in a second tab is read-only, so edits there cannot be lost.

## [1.20] — Notebook (2026-11-08)

_A notebook for what you learn from courses, labs and reading, with screenshots, code, links and flashcards, that exports to Word, Google Docs, OneNote and Markdown._

### Added
- Notebook: notebooks hold sections and pages. Pages take text, headings, lists, checklists, code blocks, tables, key takeaways, link cards and pictures. Paste a screenshot or drop a file anywhere on a page; pasted web pages and Google Docs keep their formatting, and anything unsafe is removed.
- Markdown shortcuts while typing: # and ## for headings, - or 1. for lists, [] for a checklist, > for a quote and three backticks for code. Ctrl K adds a link, Ctrl Shift H highlights.
- Flashcards from any line starting with Q: followed by a line starting with A:, or from selected text. A review panel spaces them out over days, like Anki.
- Export a page, section, notebook or everything as a Word document, a single HTML file, Markdown with images in a .zip, or a PDF, with a live preview. Copy as rich text pastes into OneNote, Docs or Word. Everything is built in the browser.
- Import Markdown, HTML, text and Word files as pages, with their pictures. A flashcard table in an exported file becomes flashcards again.
- Pages link themselves to the Reference, detection rules and CTF write-ups through their tags, ATT&CK IDs and Windows event IDs. Notebook pages show up in global search.

### Fixed
- Single-key shortcuts (n, e, /) no longer fire while typing in rich-text areas.

## [1.19] — Field kit (2026-11-03)

_A redesigned welcome page, a rebuilt CTF section, case places instead of the map, and far more detections, playbooks, reference and cloud techniques._

### Added
- CTF has four tabs. Each challenge opens a workspace with a work log of what worked and what did not, first moves for its category, entities pulled from your notes and a flag-format check. Solved challenges turn into write-ups in one click.
- Write-ups: your own and imported Markdown, with search, filters, a reader and Markdown export. Cheatsheets for nine categories: recognise-it tables, commands, gotchas and first moves, all searchable.
- Hundreds of new Sigma and YARA rules, common and advanced, across Windows, Linux, macOS, cloud, identity and the web. New platform and level filters, faster search, and long lists load in pages.
- 42 new playbooks for OSINT, incident response, threat analysis, cloud, forensics and fraud, with level and time estimates and category filters.
- The Reference page has about 1,200 entries in 40 sections, grouped by area: registry and file artefacts, SIDs, Linux and macOS, HTTP, DNS and e-mail, CloudTrail, Entra codes, M365, file signatures, timestamps, Volatility, search operators, wallets and more. Search ranks the best matches first, highlights them and moves with the arrow keys.
- Windows event logs (.evtx) can be imported from Capture. They are read in the browser, every Sigma rule runs against the events its log source covers, and the summary shows the most frequent events and the matches before anything is imported. Matched events are tagged and show the rule names on the timeline.

### Changed
- The welcome page is redesigned: it follows your light or dark theme, shows the real app, and the colour switch is gone.
- The case map is replaced by Places: every location and country in a case with an offline overview, movement in time order with impossible-travel warnings, and one-click links to Google Maps, Street View, Google Earth, OpenStreetMap, Bing, Apple Maps, Mapillary, satellite history and sun position. Export to KML or CSV.
- The Cloud field guide is now a list with a reader: each technique shows numbered commands, what to look for, how defenders see it and how to fix it. 60 new techniques, including advanced AWS, Entra, GCP, Kubernetes, CI/CD, secrets and cloud incident response, with provider and level filters.

### Fixed
- Accessibility: text meets WCAG AA contrast in light and dark, links in text are underlined, selected items use the right ARIA states, and cards no longer put buttons inside buttons. Checked on 26 screens on every test run.
- The built-in LSASS Credential Dump Attempt rule no longer fires on Windows and antivirus processes reading LSASS: it now needs the access rights dumpers use and excludes the Windows and Program Files folders. Workspaces that still have the old, unedited rule get the new one.
- Taking a workspace over from another tab no longer reloads the page.

### Removed
- Map tile servers are no longer allowed by the page's security policy, since Places opens maps in a new tab instead.

## [1.18] — Trust and scale (2026-11-03)

_The audit log and signed custody reports can no longer be forged by editing saved data, big cases save quickly, and boards with thousands of nodes open in seconds._

### Added
- Custody reports show whose key signed them. A report signed by a key you have not marked as trusted is flagged, even if its signature is valid, and you can trust a colleague's key by its fingerprint.

### Changed
- Cases with 2,000 or more records are saved in pieces and only the changed pieces are written: a save on a 20,000-record workspace takes about 45 ms and writes a few hundred KB instead of the whole workspace.

### Fixed
- The audit log is sealed with a key kept by the browser that cannot be read out, so editing, removing or reordering entries in the saved data is detected. Entries made before this version are still checked as before.
- The custody signing key is now held by the browser and is never stored in the workspace or in backups. Old keys are moved over on first start.
- Boards with thousands of nodes no longer freeze. A faster layout places large graphs, and edges hide while you pan and zoom: a 2,000-node board opens in about two seconds instead of forty.

## [1.17] — Data safety (2026-11-03)

_Your workspace can no longer be overwritten by accident: unreadable data is kept, a second tab is read-only, imports are checked and the offline copy only runs its own code._

### Fixed
- Saved data this version cannot read (damaged, or from a newer version) is no longer replaced with the demo. A recovery screen lets you download it or start fresh, and the old data is always kept aside.
- Two open tabs no longer overwrite each other. The second tab is read-only, follows the first tab's saves, and can take the workspace over with one click.
- Backup, case, tool and query imports are checked before anything changes. Files with malformed or unsafe IDs are refused with a clear reason.
- Importing a case gives its files fresh IDs, so it can never overwrite another case's evidence.
- Attachments open by what their bytes are, not the type they claim: markup always opens in the sandboxed viewer.
- Names and codes shown in menu titles are always plain text.
- The offline single-file copy only runs its own scripts (listed by hash); it no longer allows inline script.
- Pasting very long strings without spaces no longer freezes the app: 100 KB of hostile input takes about a tenth of a second instead of half a minute.

## [1.16] — New design (2026-10-27)

_A redesigned interface: cases open on their board, a collapsible sidebar, a rebuilt evidence timeline and a full light and dark colour system._

### Added
- The sidebar collapses to an icon rail with the button at its foot or the left-bracket key; the choice is remembered.

### Changed
- Cases open on their board. Picking a node puts the next actions around it: expand from evidence, connect, find a path, mark malicious, show on the timeline.
- A new design system: Geist and Geist Mono, colour for entity types, verdicts and cases, a deep-navy dark mode, and consistent buttons, tabs, tables and dialogs.
- The evidence timeline is rebuilt: a time rail with coloured event markers, event cards with host and source tags, verdict pills, readable evidence blocks and entity chips. Indicators are marked in the evidence text.
- Analysis, Report, Trash, What's new and Help use the full width of the screen; navigation is cases first with tools grouped under Kit and Intelligence.
- Cloud field guide commands show in full in code blocks that match the theme: light in light mode, dark in dark mode.

### Fixed
- The details panel closes when you move to another page from the sidebar, instead of staying open over it.
- Scratchpad, Security, Playbooks and the other pages use the full width instead of sitting in the middle of the screen.
- Search and the Notes composer no longer draw a second focus outline inside their frame.
- Selecting timeline records no longer puts the checkbox over the record title.
- The dashboard no longer labels the all-time record count as "captured this week".

## [1.15] — Cases, Reference & layout fixes (2026-10-26)

_Pin cases to the sidebar, delete down to an empty workspace, a left-rail Reference, and wider, left-aligned pages._

### Changed
- The sidebar group is now "Pinned" and shows only cases you pin, not every case. Pin from a case card or its ⋯ menu; the full list stays on the Cases page.
- Reference now has a left section rail (Windows event IDs, Logon types, Sysmon, Ports, LOLBins…) with the list and detail on the right; the search bar is unchanged. Collapses to a chip row on small screens.

### Fixed
- Deleting the last case no longer recreates an "Untitled case" — you can now clear the workspace to an empty Dashboard and Cases page.
- What's new, Reference and Cloud are left-aligned and wider, matching the rest of the app — no more empty gutter on wide screens. Re-checked responsiveness across every width.

## [1.14] — Scratchpad & field-guide redesign (2026-10-26)

_A smart notepad that detects and groups indicators as you type, a reworked Field guide, and broader coverage for bug bounty and research._

### Added
- Scratchpad (sidebar → Workspace): paste logs or notes and it detects IPs, domains, URLs, emails, hashes, ports, protocols, timestamps, CVEs, wallets and more, grouped into lanes. Select across lanes to copy, defang or send to a case. Saved in this browser.
- Field guide now covers bug bounty and security research: Recon & enumeration, Finding & triaging bugs, and Secrets & exposure — 122 commands across 10 sections.

### Changed
- Field guide is now the first Cloud tab, redesigned with a left section rail and right content, and made fully responsive.

## [1.13] — What's new (2026-10-26)

_A built-in release history, so you can always see what changed._

### Added
- "What's new" page (sidebar, by Help) showing every release as a timeline, filterable by Added / Changed / Fixed / Removed and searchable.
- A single source of truth for the history (js/data/changelog.js) that also generates CHANGELOG.md, so the in-app page and the file never drift.

## [1.12] — Cloud (2026-10-26)

_A new offline Cloud section — a misconfiguration scanner, cloud audit-log hunting, and a cloud & CTF field guide._

### Added
- Cloud section (sidebar → Lab → Cloud) with three tools, all running in the browser.
- Misconfig scanner: drop or paste AWS IAM / resource policies, Terraform (.tf and plan JSON), CloudFormation, Azure ARM, Azure roles, GCP IAM or Kubernetes manifests, and get findings with severity, location and a fix.
- Log hunting: read AWS CloudTrail, Azure Activity or GCP Audit logs, flag high-signal events (new credentials, IAM changes, logging disabled, secret reads), and send them to a case timeline.
- Field guide: 89 copyable commands across cloud enumeration, privilege escalation, Kubernetes, defence & forensics and general CTF categories, with MITRE ATT&CK links.
- 12 cloud tools in the Toolbox, a Cloud account-compromise playbook, and 5 cloud detection rules.

### Changed
- Redesigned the field guide with a segmented filter, tighter section headers and terminal-style command blocks.

### Fixed
- Removed the one-sided accent stripe on log-hunting events; they now use a clean severity badge.

## [1.11] — Toolbox and Help rebuilt (2026-10-08)

_A four-view Toolbox and a proper Help centre, plus rebuilt Reference and Security pages._

### Added
- Toolbox has four views — List, Table, Cards and Compact A–Z — switched from the toolbar and remembered.
- Toolbox tabs (All, Favourites, Quick launch, Recently used, Added by you), category chips with counts, and sorting by name, last used, most opened or recently added.
- List view opens a details panel (open, copy link, edit, look a value up, tags, use count); Table view selects many tools at once; tools remember when you last opened them.

### Changed
- Help is now a help centre: one search across questions, guides and areas, start-here guides with screenshots, a map of every area, and backup / restore / reset in one place.
- Reference rebuilt as a field-guide header with search, section tabs and a list-plus-detail layout; Security rebuilt as a protections checklist with the audit chain as a timeline.

### Removed
- The old prototype build (build.py, src/, vendor/) and the _old-single-file backup.

## [1.10] — Engineering pass

_Stripped decoration that carried no information, for a quieter, more precise interface._

### Changed
- KPIs became one hairline strip; the Dashboard got a briefing header; cases are marked by a thin colour bar instead of filled icon squares.
- Corner radius reduced to 10–12 px across cards.

### Removed
- Pastel icon tiles, sparklines, gradient art, card drop shadows and filled status pills.

## [1.9] — One visual language

_A single "case file" design language across the library pages, and a redesigned welcome screen._

### Changed
- Welcome page cycles Night / Day / Indigo themes, with screenshots switching light and dark to match; still when reduced motion is on.
- Toolbox cards redesigned as index cards; Playbooks gained Cards / List views and a per-case step thread; Help became a documentation page.
- Phone layouts for Reference, Decoder, Forensics kit, the query panel and the graph toolbar.

### Fixed
- Overlapping progress label on playbook cards.

## [1.8] — Responsive polish and redesigns

_A full responsive audit, a rebuilt Reference field guide, four new playbooks and a fixed Decoder._

### Added
- Reference became an offline field guide with 128 entries in 8 sections, each with what it means, what to look for and an ATT&CK link.
- Four playbooks (photo geolocation, packet-capture review, browser/phone artefacts, ransomware first look), each step linked to the tool that helps.

### Changed
- Full responsive audit at 360–1440 px with no sideways scrolling; quiet scrollbars; edge fades on scrolling rows; tap targets at least 32–36 px.

### Fixed
- Auto-decode now peels layered encodings (Base64 with UTF-16/gzip, hex, Base32/58, URL, JWT, Morse and more) and finds a blob inside a longer line.
- Relative times like "5 d ago" were shown as "5 d ago ago".

## [1.7] — Packets, databases and tidier input

_A PCAP reader and SQLite viewer in the Forensics kit, a rebuilt case map, and input checks everywhere._

### Added
- PCAP reader: conversations, hosts, DNS/DHCP/HTTP/TLS, cleartext logins, beacon/scan/ARP findings and follow-stream.
- SQLite viewer: browser history, phone messages, WhatsApp and any table, with decoded timestamps and recovered deleted-row text.
- Input validation across the app, with unique-name and duplicate checks and format checks for emails, IPs, hashes, dates and more.

### Changed
- Case map rebuilt on Leaflet with an offline outline map and optional street/satellite tiles; hypothesis board redesigned.

## [1.6] — Security, custody, maps and reasoning

_Workspace encryption, a tamper-evident audit log, signed chain-of-custody reports and a hypothesis board._

### Added
- AES-256-GCM encrypted workspace with a lock screen and auto-lock; encrypted backups and case exports.
- Tamper-evident audit log (hash chain) and signed chain-of-custody reports (ECDSA P-256), verifiable in the app.
- Offline case map, a hypothesis board (analysis of competing hypotheses), a research checklist and image forensics (ELA, perceptual hashes).
- Automated Playwright tests and a GitHub Actions workflow.

### Changed
- Faster: paged timelines and cached date formatting open a 5,000-row case in about a quarter of a second.

## [1.5] — Connecting the dots

_Evidence capture that routes to a case, a log parser, and a graph that builds itself from the evidence._

### Added
- Capture asks which case evidence goes to, and checks each indicator against your other cases, verdicts and watchlist.
- Log parser for JSON, CEF, LEEF, Windows XML, web logs, Zeek and more, with field mapping that powers timeline filters and Sigma.
- Graph builds from stated relations in the evidence, with suggested links, insights (hubs, bridges, clusters) and a Watchlist.

### Changed
- Much wider extraction: IPv6, MACs, phone numbers, 25 social platforms, more wallets and IBANs, coordinates and ATT&CK IDs.

## [1.4] — Evidence files, a deeper lab and a safety net

_Files as evidence, log import, a much deeper Forensics kit, and a 30-day safety net._

### Added
- Screenshots and files as evidence — stored in the browser, hashed, previewed and included in backups.
- Log import (CSV/TSV/JSON/NDJSON) with column mapping; a timeline heatmap with bulk actions; graph shortest-path and GraphML/CSV export.
- Forensics kit: Office/PDF/ZIP/PE/ELF parsing, YARA, image tools, email-header analyser and several decoders.
- Safety net: a 30-day trash, restore points before risky actions, and a backup reminder.

### Changed
- The app became a normal static site (index.html + css/ + js/) with no build step and a stricter security policy.

## [1.3] — Search everything

_One search across the whole app, with scopes, a live preview and a query syntax._

### Added
- Search over cases, vault, evidence, indicators, notes, tools, queries, rules, playbooks, CTF, news, pages and actions.
- Scope filters with counts, a live preview pane, highlighted matches, typo tolerance and a search syntax (in:, case:, "phrase", -exclude).

## [1.2] — Lab, CTF, storage and a calmer design

_A CTF tracker, the first Forensics kit, IndexedDB storage and a lighter default theme._

### Added
- CTF tracker with events, a challenge board, points and Markdown write-ups, plus a flag finder in the Decoder and File inspector.
- File inspector (magic bytes, hashes, entropy, EXIF/GPS, strings, IOCs), plus timestamp, hash and coordinate tools.

### Changed
- IndexedDB is now the main store (with a localStorage mirror), so data is no longer capped at ~5 MB.
- Light theme by default; removed gradient text, glows and sparkle icons for a calmer look.

## [1.1] — Playbooks, pivots, exports, phones and big screens

_Investigation playbooks, one-click lookups, exports, and a responsive layout._

### Added
- Eight investigation playbooks that turn each step into a tracked question on a case.
- One-click lookups for every indicator, a "Copy defanged" button, and exports (CSV, defanged list, STIX 2.1, PDF report).

### Changed
- The Decoder became a 16-operation workbench (JWT, defang/refang, hashing, IOC extraction).
- Responsive phone layouts, and content centred up to 2000 px on large screens.

## [1.0] — Tool cards, Help page, Dashboard

_The first stable release — redesigned tool cards, a full Help page and the Dashboard._

### Added
- Redesigned tool cards with selection, badges, inline actions and bulk favourite/pin/export/delete, in Directory and Compact layouts.
- A full Help page (privacy, backups, storage, getting started, module map, shortcuts and FAQ).

### Changed
- Pre-added tools stay in step with updates: deleted ones stay deleted, new ones arrive without touching your own tools, stars or pins.

### Fixed
- Scroll position is kept when you star, pin or edit something in a long list.

## [0.x] — Before 1.0 — the prototype

_The road to 1.0: renamed to OSINTrix, the editable graph, the vault model, Threat Intel, Detections, the Query library, Notes and the brand._

### Added
- Cases as colour-coded vaults with typed entries, and an editable Cytoscape graph with saved positions, labelled relationships and layouts.
- Threat Intel (offline until enabled), Detections (Sigma/YARA with a live editor), the Query library (68 dork templates) and coloured Notes with to-dos.

### Changed
- Renamed to OSINTrix with a new mark and palette; a design pass removed coloured left borders in favour of small tinted icons and pills.
- Readable type (Inter + JetBrains Mono), 4.5:1 contrast, and layouts that work from phone to desktop.

---

_Generated 2026-11-20 from `js/data/changelog.js`. Do not edit this file by hand — edit the data file and run `python tools/changelog.py`._
