/* Release history — the single source of truth for both the in-app "What's new"
   page and CHANGELOG.md (run tools/changelog.py to regenerate the file).
   Plain JSON after the "=", like the other data files. Newest first.
   Each change has a type: "added" | "changed" | "fixed" | "removed". */
const CHANGELOG_DATA = [
  {
    "version": "1.16",
    "name": "New design",
    "date": "2026-10-27",
    "summary": "A redesigned interface: cases open on their board, a collapsible sidebar, a rebuilt evidence timeline and a full light and dark colour system.",
    "changes": [
      {"type": "changed", "text": "Cases open on their board. Picking a node puts the next actions around it: expand from evidence, connect, find a path, mark malicious, show on the timeline."},
      {"type": "added", "text": "The sidebar collapses to an icon rail with the button at its foot or the left-bracket key; the choice is remembered."},
      {"type": "changed", "text": "A new design system: Geist and Geist Mono, colour for entity types, verdicts and cases, a deep-navy dark mode, and consistent buttons, tabs, tables and dialogs."},
      {"type": "changed", "text": "The evidence timeline is rebuilt: a time rail with coloured event markers, event cards with host and source tags, verdict pills, readable evidence blocks and entity chips. Indicators are marked in the evidence text."},
      {"type": "changed", "text": "Analysis, Report, Trash, What's new and Help use the full width of the screen; navigation is cases first with tools grouped under Kit and Intelligence."},
      {"type": "changed", "text": "Cloud field guide commands show in full in code blocks that match the theme: light in light mode, dark in dark mode."},
      {"type": "fixed", "text": "The details panel closes when you move to another page from the sidebar, instead of staying open over it."},
      {"type": "fixed", "text": "Scratchpad, Security, Playbooks and the other pages use the full width instead of sitting in the middle of the screen."},
      {"type": "fixed", "text": "Search and the Notes composer no longer draw a second focus outline inside their frame."},
      {"type": "fixed", "text": "Selecting timeline records no longer puts the checkbox over the record title."},
      {"type": "fixed", "text": "The dashboard no longer labels the all-time record count as \"captured this week\"."}
    ]
  },
  {
    "version": "1.15",
    "name": "Cases, Reference & layout fixes",
    "date": "2026-10-26",
    "summary": "Pin cases to the sidebar, delete down to an empty workspace, a left-rail Reference, and wider, left-aligned pages.",
    "changes": [
      {"type": "fixed", "text": "Deleting the last case no longer recreates an \"Untitled case\" — you can now clear the workspace to an empty Dashboard and Cases page."},
      {"type": "changed", "text": "The sidebar group is now \"Pinned\" and shows only cases you pin, not every case. Pin from a case card or its ⋯ menu; the full list stays on the Cases page."},
      {"type": "changed", "text": "Reference now has a left section rail (Windows event IDs, Logon types, Sysmon, Ports, LOLBins…) with the list and detail on the right; the search bar is unchanged. Collapses to a chip row on small screens."},
      {"type": "fixed", "text": "What's new, Reference and Cloud are left-aligned and wider, matching the rest of the app — no more empty gutter on wide screens. Re-checked responsiveness across every width."}
    ]
  },
  {
    "version": "1.14",
    "name": "Scratchpad & field-guide redesign",
    "date": "2026-10-26",
    "summary": "A smart notepad that detects and groups indicators as you type, a reworked Field guide, and broader coverage for bug bounty and research.",
    "changes": [
      {"type": "added", "text": "Scratchpad (sidebar → Workspace): paste logs or notes and it detects IPs, domains, URLs, emails, hashes, ports, protocols, timestamps, CVEs, wallets and more, grouped into lanes. Select across lanes to copy, defang or send to a case. Saved in this browser."},
      {"type": "changed", "text": "Field guide is now the first Cloud tab, redesigned with a left section rail and right content, and made fully responsive."},
      {"type": "added", "text": "Field guide now covers bug bounty and security research: Recon & enumeration, Finding & triaging bugs, and Secrets & exposure — 122 commands across 10 sections."}
    ]
  },
  {
    "version": "1.13",
    "name": "What's new",
    "date": "2026-10-26",
    "summary": "A built-in release history, so you can always see what changed.",
    "changes": [
      {"type": "added", "text": "\"What's new\" page (sidebar, by Help) showing every release as a timeline, filterable by Added / Changed / Fixed / Removed and searchable."},
      {"type": "added", "text": "A single source of truth for the history (js/data/changelog.js) that also generates CHANGELOG.md, so the in-app page and the file never drift."}
    ]
  },
  {
    "version": "1.12",
    "name": "Cloud",
    "date": "2026-10-26",
    "summary": "A new offline Cloud section — a misconfiguration scanner, cloud audit-log hunting, and a cloud & CTF field guide.",
    "changes": [
      {"type": "added", "text": "Cloud section (sidebar → Lab → Cloud) with three tools, all running in the browser."},
      {"type": "added", "text": "Misconfig scanner: drop or paste AWS IAM / resource policies, Terraform (.tf and plan JSON), CloudFormation, Azure ARM, Azure roles, GCP IAM or Kubernetes manifests, and get findings with severity, location and a fix."},
      {"type": "added", "text": "Log hunting: read AWS CloudTrail, Azure Activity or GCP Audit logs, flag high-signal events (new credentials, IAM changes, logging disabled, secret reads), and send them to a case timeline."},
      {"type": "added", "text": "Field guide: 89 copyable commands across cloud enumeration, privilege escalation, Kubernetes, defence & forensics and general CTF categories, with MITRE ATT&CK links."},
      {"type": "added", "text": "12 cloud tools in the Toolbox, a Cloud account-compromise playbook, and 5 cloud detection rules."},
      {"type": "fixed", "text": "Removed the one-sided accent stripe on log-hunting events; they now use a clean severity badge."},
      {"type": "changed", "text": "Redesigned the field guide with a segmented filter, tighter section headers and terminal-style command blocks."}
    ]
  },
  {
    "version": "1.11",
    "name": "Toolbox and Help rebuilt",
    "date": "2026-10-08",
    "summary": "A four-view Toolbox and a proper Help centre, plus rebuilt Reference and Security pages.",
    "changes": [
      {"type": "added", "text": "Toolbox has four views — List, Table, Cards and Compact A–Z — switched from the toolbar and remembered."},
      {"type": "added", "text": "Toolbox tabs (All, Favourites, Quick launch, Recently used, Added by you), category chips with counts, and sorting by name, last used, most opened or recently added."},
      {"type": "added", "text": "List view opens a details panel (open, copy link, edit, look a value up, tags, use count); Table view selects many tools at once; tools remember when you last opened them."},
      {"type": "changed", "text": "Help is now a help centre: one search across questions, guides and areas, start-here guides with screenshots, a map of every area, and backup / restore / reset in one place."},
      {"type": "changed", "text": "Reference rebuilt as a field-guide header with search, section tabs and a list-plus-detail layout; Security rebuilt as a protections checklist with the audit chain as a timeline."},
      {"type": "removed", "text": "The old prototype build (build.py, src/, vendor/) and the _old-single-file backup."}
    ]
  },
  {
    "version": "1.10",
    "name": "Engineering pass",
    "date": "",
    "summary": "Stripped decoration that carried no information, for a quieter, more precise interface.",
    "changes": [
      {"type": "removed", "text": "Pastel icon tiles, sparklines, gradient art, card drop shadows and filled status pills."},
      {"type": "changed", "text": "KPIs became one hairline strip; the Dashboard got a briefing header; cases are marked by a thin colour bar instead of filled icon squares."},
      {"type": "changed", "text": "Corner radius reduced to 10–12 px across cards."}
    ]
  },
  {
    "version": "1.9",
    "name": "One visual language",
    "date": "",
    "summary": "A single \"case file\" design language across the library pages, and a redesigned welcome screen.",
    "changes": [
      {"type": "changed", "text": "Welcome page cycles Night / Day / Indigo themes, with screenshots switching light and dark to match; still when reduced motion is on."},
      {"type": "changed", "text": "Toolbox cards redesigned as index cards; Playbooks gained Cards / List views and a per-case step thread; Help became a documentation page."},
      {"type": "changed", "text": "Phone layouts for Reference, Decoder, Forensics kit, the query panel and the graph toolbar."},
      {"type": "fixed", "text": "Overlapping progress label on playbook cards."}
    ]
  },
  {
    "version": "1.8",
    "name": "Responsive polish and redesigns",
    "date": "",
    "summary": "A full responsive audit, a rebuilt Reference field guide, four new playbooks and a fixed Decoder.",
    "changes": [
      {"type": "fixed", "text": "Auto-decode now peels layered encodings (Base64 with UTF-16/gzip, hex, Base32/58, URL, JWT, Morse and more) and finds a blob inside a longer line."},
      {"type": "added", "text": "Reference became an offline field guide with 128 entries in 8 sections, each with what it means, what to look for and an ATT&CK link."},
      {"type": "added", "text": "Four playbooks (photo geolocation, packet-capture review, browser/phone artefacts, ransomware first look), each step linked to the tool that helps."},
      {"type": "changed", "text": "Full responsive audit at 360–1440 px with no sideways scrolling; quiet scrollbars; edge fades on scrolling rows; tap targets at least 32–36 px."},
      {"type": "fixed", "text": "Relative times like \"5 d ago\" were shown as \"5 d ago ago\"."}
    ]
  },
  {
    "version": "1.7",
    "name": "Packets, databases and tidier input",
    "date": "",
    "summary": "A PCAP reader and SQLite viewer in the Forensics kit, a rebuilt case map, and input checks everywhere.",
    "changes": [
      {"type": "added", "text": "PCAP reader: conversations, hosts, DNS/DHCP/HTTP/TLS, cleartext logins, beacon/scan/ARP findings and follow-stream."},
      {"type": "added", "text": "SQLite viewer: browser history, phone messages, WhatsApp and any table, with decoded timestamps and recovered deleted-row text."},
      {"type": "added", "text": "Input validation across the app, with unique-name and duplicate checks and format checks for emails, IPs, hashes, dates and more."},
      {"type": "changed", "text": "Case map rebuilt on Leaflet with an offline outline map and optional street/satellite tiles; hypothesis board redesigned."}
    ]
  },
  {
    "version": "1.6",
    "name": "Security, custody, maps and reasoning",
    "date": "",
    "summary": "Workspace encryption, a tamper-evident audit log, signed chain-of-custody reports and a hypothesis board.",
    "changes": [
      {"type": "added", "text": "AES-256-GCM encrypted workspace with a lock screen and auto-lock; encrypted backups and case exports."},
      {"type": "added", "text": "Tamper-evident audit log (hash chain) and signed chain-of-custody reports (ECDSA P-256), verifiable in the app."},
      {"type": "added", "text": "Offline case map, a hypothesis board (analysis of competing hypotheses), a research checklist and image forensics (ELA, perceptual hashes)."},
      {"type": "changed", "text": "Faster: paged timelines and cached date formatting open a 5,000-row case in about a quarter of a second."},
      {"type": "added", "text": "Automated Playwright tests and a GitHub Actions workflow."}
    ]
  },
  {
    "version": "1.5",
    "name": "Connecting the dots",
    "date": "",
    "summary": "Evidence capture that routes to a case, a log parser, and a graph that builds itself from the evidence.",
    "changes": [
      {"type": "added", "text": "Capture asks which case evidence goes to, and checks each indicator against your other cases, verdicts and watchlist."},
      {"type": "added", "text": "Log parser for JSON, CEF, LEEF, Windows XML, web logs, Zeek and more, with field mapping that powers timeline filters and Sigma."},
      {"type": "added", "text": "Graph builds from stated relations in the evidence, with suggested links, insights (hubs, bridges, clusters) and a Watchlist."},
      {"type": "changed", "text": "Much wider extraction: IPv6, MACs, phone numbers, 25 social platforms, more wallets and IBANs, coordinates and ATT&CK IDs."}
    ]
  },
  {
    "version": "1.4",
    "name": "Evidence files, a deeper lab and a safety net",
    "date": "",
    "summary": "Files as evidence, log import, a much deeper Forensics kit, and a 30-day safety net.",
    "changes": [
      {"type": "added", "text": "Screenshots and files as evidence — stored in the browser, hashed, previewed and included in backups."},
      {"type": "added", "text": "Log import (CSV/TSV/JSON/NDJSON) with column mapping; a timeline heatmap with bulk actions; graph shortest-path and GraphML/CSV export."},
      {"type": "added", "text": "Forensics kit: Office/PDF/ZIP/PE/ELF parsing, YARA, image tools, email-header analyser and several decoders."},
      {"type": "added", "text": "Safety net: a 30-day trash, restore points before risky actions, and a backup reminder."},
      {"type": "changed", "text": "The app became a normal static site (index.html + css/ + js/) with no build step and a stricter security policy."}
    ]
  },
  {
    "version": "1.3",
    "name": "Search everything",
    "date": "",
    "summary": "One search across the whole app, with scopes, a live preview and a query syntax.",
    "changes": [
      {"type": "added", "text": "Search over cases, vault, evidence, indicators, notes, tools, queries, rules, playbooks, CTF, news, pages and actions."},
      {"type": "added", "text": "Scope filters with counts, a live preview pane, highlighted matches, typo tolerance and a search syntax (in:, case:, \"phrase\", -exclude)."}
    ]
  },
  {
    "version": "1.2",
    "name": "Lab, CTF, storage and a calmer design",
    "date": "",
    "summary": "A CTF tracker, the first Forensics kit, IndexedDB storage and a lighter default theme.",
    "changes": [
      {"type": "added", "text": "CTF tracker with events, a challenge board, points and Markdown write-ups, plus a flag finder in the Decoder and File inspector."},
      {"type": "added", "text": "File inspector (magic bytes, hashes, entropy, EXIF/GPS, strings, IOCs), plus timestamp, hash and coordinate tools."},
      {"type": "changed", "text": "IndexedDB is now the main store (with a localStorage mirror), so data is no longer capped at ~5 MB."},
      {"type": "changed", "text": "Light theme by default; removed gradient text, glows and sparkle icons for a calmer look."}
    ]
  },
  {
    "version": "1.1",
    "name": "Playbooks, pivots, exports, phones and big screens",
    "date": "",
    "summary": "Investigation playbooks, one-click lookups, exports, and a responsive layout.",
    "changes": [
      {"type": "added", "text": "Eight investigation playbooks that turn each step into a tracked question on a case."},
      {"type": "added", "text": "One-click lookups for every indicator, a \"Copy defanged\" button, and exports (CSV, defanged list, STIX 2.1, PDF report)."},
      {"type": "changed", "text": "The Decoder became a 16-operation workbench (JWT, defang/refang, hashing, IOC extraction)."},
      {"type": "changed", "text": "Responsive phone layouts, and content centred up to 2000 px on large screens."}
    ]
  },
  {
    "version": "1.0",
    "name": "Tool cards, Help page, Dashboard",
    "date": "",
    "summary": "The first stable release — redesigned tool cards, a full Help page and the Dashboard.",
    "changes": [
      {"type": "added", "text": "Redesigned tool cards with selection, badges, inline actions and bulk favourite/pin/export/delete, in Directory and Compact layouts."},
      {"type": "added", "text": "A full Help page (privacy, backups, storage, getting started, module map, shortcuts and FAQ)."},
      {"type": "changed", "text": "Pre-added tools stay in step with updates: deleted ones stay deleted, new ones arrive without touching your own tools, stars or pins."},
      {"type": "fixed", "text": "Scroll position is kept when you star, pin or edit something in a long list."}
    ]
  },
  {
    "version": "0.x",
    "name": "Before 1.0 — the prototype",
    "date": "",
    "summary": "The road to 1.0: renamed to OSINTrix, the editable graph, the vault model, Threat Intel, Detections, the Query library, Notes and the brand.",
    "changes": [
      {"type": "added", "text": "Cases as colour-coded vaults with typed entries, and an editable Cytoscape graph with saved positions, labelled relationships and layouts."},
      {"type": "added", "text": "Threat Intel (offline until enabled), Detections (Sigma/YARA with a live editor), the Query library (68 dork templates) and coloured Notes with to-dos."},
      {"type": "changed", "text": "Renamed to OSINTrix with a new mark and palette; a design pass removed coloured left borders in favour of small tinted icons and pills."},
      {"type": "changed", "text": "Readable type (Inter + JetBrains Mono), 4.5:1 contrast, and layouts that work from phone to desktop."}
    ]
  }
];
