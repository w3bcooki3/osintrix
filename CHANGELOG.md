# Changelog

How OSINTrix came together, newest first.

## v1.11 — Toolbox and Help rebuilt

- **Toolbox** has four views — List, Table, Cards and Compact A–Z — switched from the toolbar and remembered.
  - Lists across the top: All tools, Favourites, Quick launch, Recently used, Added by you.
  - Category chips with counts, sub-category chips, and sort by name, last used, most opened or recently added.
  - List view opens a details panel: open, copy link, edit, look a value up with the tool, tags, use count, favourite, quick launch, delete. On phones it is a bottom sheet.
  - Table view sorts by column and selects many tools at once for favourite, quick launch, export or delete.
  - Tools remember when you last opened them. `/` focuses the toolbox search.
- **Help** is a help centre: one search across questions, guides and areas, popular topics, three start-here guides with real screenshots, a map of every area, and backup, restore and reset in one place.
- **Reference** has a dark field-guide header with one search, section tabs and counts, and a list beside a details panel: what it means, what to look for, the ATT&CK technique, search my evidence, copy. On phones the details open as a sheet.
- **Security & audit** shows how many of four protections are in place — encryption, audit chain, signing key, a recent backup — with the action for each, the chain-of-custody report below, and the audit chain as a timeline in its own panel.
- Removed the old prototype build (`build.py`, `src/`, `vendor/`) and the `_old-single-file` backup.

## v1.10 — Engineering pass

- Removed decoration that carried no information:
  - Pastel icon tiles on stat cards and page headers.
  - Sparklines.
  - Gradient art on case cards and gradient chart bars.
  - Drop shadows on cards.
  - Filled status and chip pills.
- **KPIs:** one hairline strip, each with a monospaced label, a number and a note. Malicious counts show in red only when non-zero.
- **Dashboard:** a briefing header — date, title, and a one-line summary of the most active case — replaces the large coloured sentence and graph thumbnail.
- **Cases:** marked by a thin colour bar or tab instead of filled icon squares.
- Corner radius reduced to 10–12 px across cards.

## v1.9 — One visual language

- **Welcome page:** the launch-post look. It cycles Night, Day and Indigo themes every 3 seconds, and the screenshots switch between light and dark to match. On phones the tags drift in two rows and the app sits in a phone frame. It stays still when reduced motion is on, and clicking a theme stops the cycle.

- **"Case file" design language** across the library pages:
  - Monospaced index labels, a colour tab per category, and dashed footer rules.
  - No coloured icon blobs.
- **Toolbox cards:** redesigned as index cards — category tab, index line, name, domain, description and tags. Actions appear on hover, with a clear Open button.
- **Playbooks:**
  - Fixed the overlapping progress label on cards.
  - Added **Cards / List** views and a category picker.
  - Each playbook shows a step thread: dots fill in as steps are answered on the current case.
- **Help:** a documentation page with a numbered table of contents, numbered sections and a "Start here" row (capture, demo case, backup).
- **Phones:**
  - Reference, Decoder and Forensics kit use a single picker instead of long chip rows.
  - The query panel is a full bottom sheet with the Search button pinned at the bottom.
  - The graph has a two-button toolbar with a **More** menu (add or build from evidence, suggestions, insights, arrange, export), a pill-sized "not on the graph" banner and a slim time slider.

## v1.8 — Responsive polish and redesigns

- **Decoder:** auto-decode was broken for anything beyond plain Base64 and hex. It now detects and peels layered encodings: Base64 (including UTF-16 and gzip inside), hex, Base32, Base58, URL, HTML entities, \x / \u escapes, binary, character codes, JWT, Morse, reversed Base64 and ROT13 flags. It also finds a blob inside a longer line (e.g. `powershell -enc …`) and leaves plain text alone.
- **Welcome screen:** rebuilt as a launch page, with a clear headline, a product preview, key facts and four capabilities.
- **Dashboard:**
  - Scrollbars are thin and quiet everywhere, with no Windows arrow bars; the sidebar's shows only on hover.
  - Key entries on a case overview are a clean list instead of tiles.
- **Toolbox cards:** name and domain, a two-line description and a few tags. Actions appear on hover, with a clear Open link.
- **Reference:** now an offline field guide with 128 entries in 8 sections:
  - Sections: Windows event IDs, logon types, Sysmon, ports, LOLBins, authentication failure codes and persistence locations.
  - Each entry: what it means, what to look for, an ATT&CK link and "Search my evidence".
- **Playbooks:**
  - Four new playbooks: photo geolocation, packet capture review, browser and phone artefacts, and ransomware first look.
  - Each step has a shortcut to the part of OSINTrix that helps with it.
  - The playbook page shows which steps are answered on the current case.
- **Security & audit:** a settings-style page with a status summary (encryption, audit chain, signing key, last backup). The audit badge no longer stays on "Checking…" when the log is empty.
- **Help:** a documentation layout with a sticky table of contents and searchable questions.
- **Fixed:** times like "5 d ago" were shown as "5 d ago ago".

- **Full responsive audit** of every screen, tab, dialog and panel at 360, 390, 768, 1024 and 1440 px, with no sideways scrolling anywhere.
- **Phones:**
  - Playbook, PCAP, SQLite and file headers stack cleanly, with actions in an even row below the title.
  - The SQLite table list becomes a scrollable chip row.
  - The graph's "not on the graph yet" banner and time slider no longer cover each other or the zoom buttons.
  - The toolbox and notes toolbars use the full width.
  - Dialog footers stay clear of the home bar.
  - Opening a dialog no longer pops up the keyboard over it.
  - Tap targets are at least 32–36 px.
- **Tablets:**
  - Case titles keep a readable width, and their buttons move underneath instead of squeezing them.
  - The top bar hides the "Saved in this browser" label so search has room; the status dot stays.
- **Scrolling rows** (tabs, filters, toolbars, wide tables) fade at the edge that has more, so it's clear they scroll.

## v1.7 — Packets, databases and tidier input

- **PCAP reader** in the Forensics kit: pcap and pcapng, with conversations, hosts, DNS, DHCP, HTTP (with file export), TLS SNI / JA3, cleartext logins, beacon / scan / ARP-spoofing findings and a follow-stream view.
- **SQLite viewer:** browser history, downloads, cookies and logins; phone messages; WhatsApp; any table. Timestamps are decoded, deleted-row text is recovered from free pages, and there's a read-only SQL console. Rows go to the timeline in one click.
- **Case map rebuilt** on Leaflet: smooth zoom, a crisp offline outline map, optional street / light / satellite maps (asked first), a numbered movement path with speeds, and place popups with map links.
- **Hypothesis board redesigned:** a ranking card with evidence-for and evidence-against bars, a clear matrix with credibility and relevance, and a legend.
- **Input checks everywhere:** messages appear under the field. Names of cases, tools, queries, rules, playbooks, parsers, CTF events and challenges, and hypotheses must be unique. Likely duplicate vault entries and tool addresses trigger a warning. Formats are checked (email, domain, IP, URL, MAC, phone, CVE, hash, dates, ATT&CK IDs, regular expressions).
- **Clear copies:** duplicates are named “… (copy)”, “… (copy 2)”. New rules and challenges get distinct names. Imports that clash get “(imported)”. Case codes never repeat.
- **Saved web page** button and how-to in Capture.
- **Map tiles:** the streets map now uses CARTO (OpenStreetMap's own servers refuse apps that open from a file or send no referrer). When tiles can't load, the map says so and falls back to the offline outline. Dialogs are no longer drawn under the map, and clicked countries don't get a focus box.
- **PCAP findings** are a plain severity list (High / Medium) with a link to the table behind each one.
- **Capture dialog:** the attach bar and the web-page how-to line up with the rest of the form.

## v1.6 — Security, custody, maps and reasoning

- **Encrypted workspace:**
  - AES-256-GCM with a passphrase, covering cases, restore points and files.
  - A lock screen, auto-lock and "Lock now".
  - Change the passphrase or turn encryption off at any time.
- **Encrypted backups and case exports.**
- **Tamper-evident audit log** (hash chain) and **signed chain-of-custody reports** (ECDSA P-256) that you can verify inside the app.
- **Saved web pages** (.html / .mhtml) archived as evidence, viewed in a script-free sandbox. Images and SVGs now open as pictures, so they can never run code.
- **Case map:** an offline world map with places, shaded countries, a time-ordered movement path, and photo GPS picked up automatically from attached photos.
- **Hypothesis board** (analysis of competing hypotheses) in the new Analysis tab, with a starting board on the sample case. The ranking is included in reports.
- **Research checklist** for every indicator: ticks itself as you open lookups, with progress shown on the Entities tab.
- **Image forensics:** error level analysis, and perceptual fingerprints that find look-alike photos in your evidence.
- **Faster:**
  - Timelines draw in pages.
  - Date formatting is cached, so a 5,000-row case opens in about a quarter of a second, down from nearly a second.
- **Automated tests** (Playwright) and a GitHub Actions workflow.

## v1.5 — Connecting the dots

- **Capture asks which case the evidence goes to.** There is a case picker, including "New case…", plus an "Add to graph" switch per case. File and log imports go to the case you pick too.
- **Checked before you save:** every indicator shows whether it is already in this case or in another case, its verdict, whether you watch it, and offline context.
- **Log parser:**
  - Built-in formats: JSON, CEF, LEEF, Windows event XML, web access logs, IIS/W3C, Zeek, Cisco ASA, sshd/sudo, key=value (FortiGate, Sysmon, iptables) and syslog headers.
  - Fields are mapped to common names and power the timeline filters (`dst.port:443`), Sigma and graph relations.
  - Structured lines get readable titles, and the source, host and time are filled in from the log.
  - Your own regex parsers can be drafted from a sample line in Forensics kit → Log parser, along with field-name mappings.
- **Graph shows what is missing:** a notice counts the entities in the evidence that are not on the graph, and **Add from evidence** lets you pick them.
- **Much wider extraction:**
  - Network: IPv6, MAC addresses, ASNs.
  - Identity: phone numbers, social-profile links (25 platforms, which also give the @handle), usernames written as `username:`, `aka` and `u/`, and `[at]`/`[dot]` obfuscated emails.
  - Money: XMR, LTC, TRX and DOGE wallets, and IBANs (checksum-validated).
  - Other: SHA-512, coordinates and ATT&CK technique IDs.
- **Graph from evidence:**
  - Relations stated in the evidence become links automatically, with the reason. Everything else becomes a suggestion.
  - You can build a case's graph at any time, or turn on auto-add.
  - Right-click a node for "Expand from evidence".
  - New nodes are placed next to what they connect to.
- **Suggested links** (seen together, near in time on one host, look-alike identities, shared infrastructure), each with Accept or Dismiss.
- **Insights:** hubs, bridges, clusters (with colouring), "look at next", and unconnected nodes.
- **Watchlist:** a Watchlist page, a Dashboard card, a count in the sidebar, and notices on new sightings.
- **Offline context:** cloud provider ranges, Tor exit nodes, disposable and free email providers, dynamic DNS, URL shorteners, paste and file-sharing sites, free hosting, and phone country codes.
- **Around this time:** ±5 minutes around any record, with a filtered timeline.
- **Fix:** on phones, the welcome screen now opens at the top instead of halfway down.

## v1.4.2 — Entities per case

- **Each case now has an Entities tab.** It lists every indicator from that case's evidence and vault, with records, first and last seen, the other cases that share it, and whether it is in the vault. You can set verdicts, add to the vault, copy defanged or export CSV in bulk.
- **The global Entities page** can filter by case, and it shows which cases each indicator appears in.
- **Fix:** the page behind a query or rule drawer, or behind any dialog, no longer scrolls.

## v1.4.1 — Separate files

- **The app is now a normal static site:** `index.html`, `css/`, `js/` and `fonts/` instead of one generated 2 MB file. There is no build step: edit a file and reload.
- **Stricter security policy:** scripts can only load from the app's own files, so inline scripts are blocked.
- **Your data carries over:** it lives in the same place in the browser as before.
- **One-file copy:** `tools/bundle.py` makes one if you want it.
- **Default content** moved from `src/*.json` to `js/data/*.js`, so it still loads when the app is opened from disk.

## v1.4 — Evidence files, a deeper lab and a safety net

- **Screenshots and files as evidence:** paste or drop them into Capture, or attach them to any record. Stored in the browser, hashed, previewed, openable in the forensics kit, and included in backups.
- **Log import:** CSV, TSV, JSON and NDJSON with column mapping. Up to 5,000 rows per file.
- **Timeline:** an hour-by-day activity heatmap, multi-select with bulk tag / key evidence / CSV / delete, and a delete button on every record.
- **Graph:** shortest path between two entries, an "as of" time slider, and GraphML / CSV export.
- **Report:** full, executive, technical and CTF write-up templates, a relationship map, and redaction of personal data.
- **Toolbox:** URL templates turn any tool into a one-click lookup for matching indicators.
- **Detections:** test Sigma and YARA rules against a case, or YARA against a file.
- **Forensics kit:**
  - Office, PDF, ZIP, PE and ELF parsing; a YARA scan; C2PA detection.
  - Fewer false indicators: strings inside compressed image data are filtered out.
  - Image tools (channels, bit planes, LSB, QR codes, reverse search).
  - Email header analyser.
  - Social-media and database ID decoders.
  - Subnet calculator, MAC vendor lookup, user-agent parser.
  - Username and email permutations.
- **Safety net:** a 30-day trash, restore points before risky actions, and a backup reminder.
- **Fixes:**
  - The details panel's "Where it came from" list no longer collapses.
  - The Sigma parser handles two-space indentation.
  - An empty Sigma selection no longer matches everything.

## v1.3 — Search everything

- **One search for the whole app:** cases, vault, evidence, indicators, notes, tools, queries, rules, playbooks, CTF, news, pages and actions.
- **Scope filters with counts**, a live preview pane, highlighted matches and typo tolerance.
- **Search syntax:** `in:`, `case:`, `"phrase"`, `-exclude`, and the timeline filters.
- **Indicators:** pasting one shows where it appears, its verdict and lookup links.
- **Recent searches**, and full keyboard control.
- **Timeline filter box:** the case timeline has its own filter box again.

## v1.2 — Lab, CTF, storage and a calmer design

- **CTF tracker:** events with their own flag format, challenges on a board, points and per-category progress, linked cases, and Markdown write-up export.
- **Flag finder** in the Decoder and File inspector. One click saves a flag to a challenge and marks it solved.
- **Forensics kit:**
  - File inspector: magic bytes, hashes, entropy, EXIF and GPS, PNG chunks, appended data, embedded signatures, strings, IOCs and a hex dump.
  - Timestamp converter, hash identifier and coordinates converter.
- **Decoder:** nine more operations (Base32, Base58, binary, character codes, unescape, Caesar brute force, XOR brute force, Morse, gunzip).
- **Storage:**
  - IndexedDB is now the main store, with a localStorage mirror, so data is no longer capped at about 5 MB.
  - Data is also saved when the tab is hidden.
  - A red warning appears when the browser blocks storage.
  - Help shows how much space you are using and how much there is.
- **Sample data:** a new sample case, "Harbour photo" (an OSINT and forensics lab with EXIF GPS and a hidden flag). **Remove sample data** clears every example item and keeps your own work.
- **Design:**
  - Light theme by default.
  - Pages use the full width on large screens.
  - Removed the gradient text, glows, dotted hero, greeting badge and sparkle icons.
  - A tighter sidebar and tool cards whose names no longer break mid-word.

## v1.1 — Playbooks, pivots, exports, phones and big screens

- **Playbooks:** eight investigation checklists. Running one on a case turns every step into an open question, and you can track its progress in the Questions tab. You can also create, edit, duplicate, import and export your own.
- **Lookups:** one-click links for every indicator in the details panel (VirusTotal, AbuseIPDB, Shodan, urlscan, crt.sh, HIBP, Etherscan, NVD…), plus a "Copy defanged" button.
- **Exports:**
  - IOCs as CSV, a defanged text list or a STIX 2.1 bundle.
  - Print or save the report as PDF.
  - Import a case that someone else exported.
- **Decoder is now a workbench:** 16 operations, including JWT decoding, defang and refang, hashing and IOC extraction.
- **Entities:** search, and export to CSV.
- **Questions tab:** redesigned with a progress ring and questions grouped by playbook.
- **Phones:** compact case header and tabs, a category picker in the Toolbox, readable Reference cards, a responsive report and decoder.
- **Large screens:** content is centred and grows up to 2000 px instead of leaving empty space on the right.
- **Settings:** the design-system swatches and the prototype feature list are gone; Library is off the menu until it is built.

## v1.0 — Tool cards, Help page, Dashboard

- **Tool cards, in the style of the original ThreatNet:**
  - Each card has a selection checkbox, a letter badge, the tool name, and a **Pre-added** or **Custom** badge.
  - Below that: the full address with a link out; edit, favourite, pin, open and delete buttons; the full description; and clickable tags that filter the toolbox.
  - Select several tools to favourite, pin, export or delete them together.
  - Directory and Compact layouts are still available.
- **Pre-added tools stay in step with updates.** A pre-added tool you delete stays deleted. New tools added to `tools.json` later are added to your toolbox automatically, without changing your own tools, favourites or pins.
- **Command Center is now Dashboard.**
- **Help page:**
  - How OSINTrix keeps your data private, and the one optional network request (live threat feeds).
  - Why and how to back up.
  - How much browser storage you are using.
  - Export, import backup, start fresh and reset to demo. All of them can be undone.
  - A getting-started guide, a map of each module, keyboard shortcuts, search filters and an FAQ.
- **Scroll position is kept** when you star, pin or edit something in a long list.

## Layout options

The Toolbox, Query library and Detections each let you pick a layout, using the switch next to the page title. The app remembers your choice.

- **Toolbox:** the Quick launch strip is gone; the sidebar already covers it. Tools have a letter badge.
  - **Tiles:** name, domain, a two-line description, the sub-category, and star, pin and Open in the footer.
  - **Directory:** a full-width list with the whole description readable.
  - **Compact:** dense chips. The full description shows on hover.
- **Query library and Detections:**
  - **Table:** a sortable list, like a SIEM rule manager. Click a row and the query or rule opens in a panel that slides in from the right; Esc closes it.
  - **Gallery:** cards showing a preview of the query or rule. Click one to open a full-page editor with a Back button.
  - **IDE:** a folder tree, a list and the editor side by side. Detections are grouped by Sigma or YARA, then by category.
  - Closing a rule with unsaved edits asks first, whichever layout you use.

## Design pass

A design pass on the screens that still felt like the old app. Colour now lives in small tinted icons and pills; the coloured left borders are gone everywhere.

- **Every tool page shares one header:** an icon, a title, actions and a strip of key numbers.
- **Cases:**
  - Each card has a banner showing a mini map of that case's graph.
  - Cards show status, when the case was last updated, progress on its questions, and counts.
  - Filter cases by status.
  - A ⋯ menu on each card: open, edit, archive or reopen, export, delete.
- **Toolbox:**
  - Readable tool cards: names wrap instead of being cut off, descriptions get three lines, and each card shows its domain and sub-category.
  - The whole card opens the tool.
  - Star, pin and edit appear on hover.
  - Quick launch is a compact row of chips.
  - Tools are grouped under category headings.
- **Query library:** now a workbench, with the list on the left and the selected query on the right.
  - Work top to bottom: fill the blanks (from a vault entry if you like), check the query, pick an engine.
  - The Search button is a real link to the chosen engine. You can see where it goes before you click, and pop-up blockers don't stop it.
  - Delete asks you to confirm and can be undone.
- **Threat Intel:**
  - A top story, picked by how much it concerns your cases, how severe it is and how recent.
  - An inbox-style list grouped by day, with category icons, severity tags and the case entities each article mentions.
  - A side panel with your exposure, a category breakdown and the health of each source.
- **Detections:** redesigned editor.
  - Syntax highlighting for Sigma (YAML) and YARA, with line numbers and a live status bar.
  - Separate Rule and Details tabs.
  - An unsaved-changes marker. Switching rules asks before discarding your edits, Ctrl+S saves, and Tab and Enter indent as you'd expect.
  - The seeded Sigma rules no longer warn about a missing `title:`. The title is added back when you copy or download the rule.
- **Fixes:**
  - The Delete button in the Edit query and rule footers was out of place.
  - An old style was leaking into the empty-state icons.
  - Confirmation dialogs are now consistent.

## Threat Intel, Detections, Query library, Notes

- **Renamed to OSINTrix**, with a new mark: a lens with a thread through it. The name lives in one constant in `src/brand.js`.
- **Threat Intel:**
  - Live news from the same six sources and the same `api.rss2json.com` relay as the original.
  - Offline until you turn it on. A consent screen lists what leaves the browser and what never does.
  - The page's CSP allows only that one host.
  - Articles are cleaned to plain text, tagged by category and severity, and checked against your case entities.
  - Each article can be added to a case.
- **Delete case:** from Edit case or the case card. Shows what will be lost, offers an export first, needs the case code typed to confirm, and can be undone. Archive is the safer option.
- **Graph right-click menus** for nodes, relationships and empty canvas. Long-press on touch; the Menu key or Shift+F10 on a selected node.
- **Timeline redesign:** event-type markers, sticky day headers, host / source / entity metadata, and a small red dot for malicious events instead of a red border.
- **Toolbox redesign:** a hero summary, a Quick launch grid for pinned tools, category-coloured monograms, grid and list views, and sorting (A–Z, recent, most opened).
- **Query library** (replaces Query builder):
  - Your 68 dork templates, with `{{VARIABLES}}` filled from vault entries.
  - Runs in nine engines.
  - Each run is logged to the case.
  - Import and export.
- **Detections:**
  - Your 34 Sigma and YARA rules, with an editor, line numbers and a live structure check.
  - Import `.yml` / `.yar` / `.json` and export.
  - Link a rule to a case.
  - **Generate from case** writes starter Sigma and YARA rules from the case's malicious entities.
- **Notes:** coloured sticky notes, general or per case. `[ ]` lines become tickable to-dos, with due dates and pins. They also appear on the case overview and the Command Center.

## Brand and polish

- **Brand:** a new ThreatNet mark (a thread strung through a network, shaped like a T), a two-tone wordmark, a favicon and a restrained palette (Thread indigo, Net violet, Signal cyan). The About panel in Settings documents it.
- **First-run welcome screen** and a short start-up splash. You can see the welcome again from Settings.
- **Dashboard hero:** a live summary sentence, quick actions and a mini map of your busiest case, plus sparklines on the stat cards.
- **Case overview:** a case map preview, a vault composition donut and a case-colour header.
- **Graph:**
  - A curated demo layout.
  - A find box.
  - A legend that doubles as category filters.
  - Neighbourhood highlighting.
  - A tidier toolbar.
  - Your zoom and pan are remembered for each case.
- **Illustrated empty states**, gentle motion, and reduced-motion support.
- **Bug sweep:** every button on every screen was clicked automatically at 1440px and 390px, and no errors remained. Fixes include:
  - Label overlap in the graph.
  - The inspector hiding the Add entry button.
  - Toolbar overflow.
  - Replaying animations while typing.
  - A graph fit that went wrong when the canvas was still sizing.

## From the first prototype

- **Readable type:** Inter at 15px for text and JetBrains Mono only for machine values such as IPs, hashes and times. Labels are in sentence case, and every text colour meets 4.5:1 contrast. Theme and text size are in Settings.
- **Cases are vaults again:** each case has its own colour and icon. It holds typed entries, the same Multi-vault types (person, username, email, phone, crypto wallet, domain, IP, forum, document…), with their own fields, priority, star, tags and notes.
- **Toolbox is back:** your 94 tools from `tools.json` are grouped by category and sub-category. You can pin, star, search, add, edit, delete and import them.
- **Editable graph (Cytoscape.js):**
  - Drag nodes; positions are saved.
  - Double-click the canvas to add a node.
  - Use **Connect** to draw a labelled relationship with a confidence and its evidence.
  - Edit or delete nodes and links.
  - Use **Arrange** for automatic layouts, and export the graph as a PNG.
- **Works at every screen size:** full sidebar on wide screens, icon rail on tablets, and on phones a drawer, bottom bar and bottom-sheet details panel.
