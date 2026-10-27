# Changelog

All notable changes to OSINTrix, newest first. The format is based on [Keep a Changelog](https://keepachangelog.com); this file is generated from `js/data/changelog.js` by `tools/changelog.py`.

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

_Generated 2026-10-27 from `js/data/changelog.js`. Do not edit this file by hand — edit the data file and run `python tools/changelog.py`._
