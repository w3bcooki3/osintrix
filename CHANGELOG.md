# Changelog

All notable changes to OSINTrix, newest first. The format is based on [Keep a Changelog](https://keepachangelog.com); this file is generated from `js/data/changelog.js` by `tools/changelog.py`.

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

_Generated 2026-11-14 from `js/data/changelog.js`. Do not edit this file by hand — edit the data file and run `python tools/changelog.py`._
