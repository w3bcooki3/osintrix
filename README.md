<div align="center">

# OSINTrix

**Follow every thread.**

A private OSINT investigation workspace that runs entirely in your browser.
No server. No account. No tracking. Your cases never leave your machine.

[**Launch the app →**](https://YOUR-USERNAME.github.io/osintrix/) &nbsp;·&nbsp; [Features](#features) &nbsp;·&nbsp; [Privacy](#privacy-by-design) &nbsp;·&nbsp; [Run it locally](#run-it-locally)

![OSINTrix dashboard](docs/dashboard.png)

</div>

---

## What is OSINTrix?

OSINTrix is a workspace for OSINT analysts, threat researchers and blue teamers. It brings everything an investigation needs into one place:

- the people, accounts and infrastructure you are tracking;
- the evidence you collect;
- how it all connects;
- the tools and searches you rely on.

It is a plain static site: HTML, CSS and JavaScript files with no framework, no build step and no server code. Open it from GitHub Pages or straight from your disk, and it works the same, offline included. Everything you enter is stored in your browser (IndexedDB) and nowhere else.

## Features

### 🔎 Search everything
Press `Ctrl K` or `/`, or click the search bar, to search the whole app at once: cases, vault entries, evidence, indicators, notes, tools, queries, detection rules, playbooks, CTF challenges, news, pages and actions.
- **Previews:** results are grouped and highlighted, with a preview pane showing fields, evidence text, rule code, playbook steps or lookup links.
- **Typo-tolerant:** `shdoan` still finds Shodan.
- **Syntax:**
  - `in:tools` (or any other area) searches one area;
  - `case:TN-2026-014` searches one case;
  - `"exact phrase"` matches a phrase, and `-word` excludes one;
  - `host:` / `verdict:` / `after:` offer to filter the case timeline.
- **Indicators:** paste an IP, domain, hash or email to see everywhere it appears, its verdict, and one-click lookups.
- **Keyboard:** recent searches are remembered, `Tab` moves to the next area, and the arrow keys and `Enter` pick a result.

![Search](docs/search.png)

### 🗂️ Cases
- **Case vaults:** each investigation holds typed entries (people, usernames, emails, phones, domains, IPs, crypto wallets, forums, documents and more). Each type has its own fields, plus priority, verdict, tags and notes.
- **Evidence capture:** paste a log line, a post or a note. Indicators (IPs, domains, hashes, emails, handles, CVEs…) and timestamps are pulled out automatically.
  - **Screenshots and files:** paste or drop them in. Each is hashed (SHA-256), stored in the browser and shown with a preview on its record.
  - **Log import:** CSV, TSV, JSON or NDJSON exports (Sysmon, firewall, proxy, EDR…). Pick the time, title and host columns; each row becomes a record, with every column kept so detections can test it.
- **Timeline:** every record in order, with day headers, event markers and filters. Search with `host:`, `verdict:`, `type:`, `tag:`, `after:` and `before:`.
  - **Activity heatmap** (day × hour): click a cell to see just that hour.
  - **Multi-select:** tag, mark as key evidence, export to CSV or delete many records at once.
- **Link graph:**
  - Drag, add, edit and connect nodes.
  - Right-click menus on nodes, links and empty canvas.
  - Every relationship carries a confidence rating and its evidence.
  - **Shortest path** between any two entries.
  - **"As of" time slider** that replays how the picture grew.
  - Automatic layouts, and export as PNG, GraphML (Gephi, yEd, Maltego) or CSV.
- **Questions and playbooks:** track what you still don't know, or run a playbook (phishing triage, username OSINT, domain & infrastructure, malware triage, crypto tracing, IR first hour…) and every step becomes an open question.
- **Reports and exports:**
  - A cited report with four templates (full, executive, technical, CTF write-up), a relationship map, and a **redact** switch that masks emails, phones, IPs, handles and names. Print it, save it as PDF, or export it as Markdown.
  - Every indicator as CSV, a defanged text list, or a STIX 2.1 bundle.
  - A whole case as JSON, which a colleague can import on their own machine.
- **One-click pivots:** every IP, domain, URL, email, hash, wallet, handle and CVE has lookup buttons for VirusTotal, AbuseIPDB, Shodan, urlscan, crt.sh, HIBP, Etherscan, NVD and more. Each opens in a new tab; nothing is fetched by OSINTrix.

![Graph](docs/graph.png)

### 🧰 Research
- **Toolbox:** 90+ curated OSINT and security tools across 8 categories.
  - Favourites, a quick-launch list, tags and bulk actions.
  - Card, directory and compact layouts.
  - Import your own tool list.
  - **Your own lookups:** give any tool a URL template such as `https://example.com/search?q={value}`. It then appears in the lookup buttons for the matching IPs, domains, emails or hashes, and gets a Run button.
- **Query library:** 68 saved search recipes with `{{BLANKS}}` that fill from your case entries.
  - Runs in Google, Bing, DuckDuckGo, Shodan, Censys, GitHub, ZoomEye, FOFA and Intelligence X.
  - Each search can be logged to the case.
- **Reference:** Windows and Sysmon event IDs, ports, and living-off-the-land binaries.

![Toolbox](docs/toolbox.png)

![Playbooks](docs/playbooks.png)

### 🧪 Lab (CTFs, forensics, OSINT challenges)
- **CTF tracker:** events with their own flag format, and challenges on a board (to do, working, solved).
  - Each challenge has points, category, flag, notes and a linked case.
  - A progress bar per category, and write-ups exported as Markdown.
- **Flag finder:** flag-shaped strings (`FLAG{…}`, `picoCTF{…}`, `HTB{…}`, or your event's own format) are picked out automatically in the Decoder and File inspector, and saved to a challenge with one click.
- **File inspector:** drop in any file; it is read locally and never uploaded. It shows:
  - the true file type from its magic bytes, with a warning when the extension lies;
  - MD5, SHA-1 and SHA-256, and entropy;
  - EXIF metadata, including GPS converted to decimal with map links; PNG text chunks; C2PA content credentials;
  - **Office files:** author, dates and app from the metadata, VBA macros, embedded OLE objects and remote template links;
  - **PDF:** document info and XMP, JavaScript, auto-actions, launch actions, embedded files, links and incremental updates;
  - **ZIP:** the full file list, encrypted entries and dates;
  - **Windows PE and Linux ELF:** architecture, compile time, sections with entropy, imports, suspicious APIs and packer hints;
  - data appended after the end of the file, and embedded file signatures (a lightweight binwalk);
  - strings (ASCII and UTF-16) with compressed noise filtered out, indicators found in them, and a hex dump;
  - a **YARA scan** with your own rules.
  Save the findings to a case in one click.
- **Image tools:** colour channels, bit planes 0–7, LSB text extraction, QR code decoding and one-click reverse image search sites.
- **Email headers:** paste raw headers to see SPF, DKIM and DMARC results, From / Reply-To / Return-Path mismatches, the hop path with delays, and the sender's first public IP.
- **Timestamps and IDs:** paste a number and see it as Unix (seconds, ms, µs, ns), Windows FILETIME / LDAP, Chrome / WebKit, Cocoa, HFS+, GPS and DOS time, with the most likely reading flagged. Paste a post or profile ID (X, Discord, TikTok, Instagram, Mastodon, LinkedIn), a MongoDB ObjectId, UUID v1/v7, ULID or KSUID to get the time it was created.
- **Network:** subnet calculator (IPv4 and IPv6), MAC address vendor lookup from the bundled IEEE list, and a user-agent parser that flags scripts and bots.
- **Username and email generator:** likely handles and addresses from a person's name, ready to check.
- **Hash identifier:** MD5 / NTLM, SHA family, bcrypt, the Unix crypt formats, NetNTLMv1 and v2, Kerberoast / AS-REP, JWT and more, each with its hashcat mode.
- **Coordinates:** reads decimal degrees, DMS or a Google Maps link, and converts between formats. Links to Google Maps, Street View, OpenStreetMap, Google Earth, Bing and Mapillary.
- **Decoder:** 25 operations. Beyond the basics there are Base32, Base58, binary, character codes, `\x` / `\u` unescaping, all 25 Caesar shifts, single-byte XOR brute force, Morse and gunzip / inflate.

![Forensics kit](docs/lab.png)

### 🛡️ Intelligence
- **Detections:** write, keep and import Sigma and YARA rules.
  - Editor with syntax highlighting and a live structure check.
  - **Test a rule** against a case's evidence (Sigma and YARA) or against a file (YARA). The engines are subsets that run in the page; anything they cannot evaluate is reported, never silently passed.
  - Link a rule to a case, or generate starter rules from a case's malicious indicators.
- **Threat Intel:** security news from your RSS sources, classified by category and severity, and checked against every entity in your cases. It is off until you turn it on.
- **Entities:** every indicator across every case, with verdicts and cross-case matches.

![Detections](docs/detections.png)

### 📝 And also
- Sticky notes and to-dos, general or pinned to a case.
- A command palette (`Ctrl K`) for searching everything and running actions.
- Light (default) and dark themes, three text sizes, and a compact density.
- Fully responsive: sidebar on desktop, icon rail on tablet, and a bottom bar with sheets on phones.

<p align="center"><img src="docs/mobile.png" width="260" alt="OSINTrix on a phone"></p>

## Privacy by design

| | |
|---|---|
| **Where your data lives** | Only in this browser (IndexedDB, with a localStorage copy). Nothing is uploaded. There is no backend and no analytics. |
| **Network access** | The page's Content Security Policy blocks every outside connection except one: `api.rss2json.com`, used only if you turn on live Threat Intel feeds. Even then, only feed addresses are sent. |
| **Untrusted content** | Feed articles and pasted evidence are shown as plain text. Links open only when you click them, in a new tab with no referrer. |
| **Storage** | Saved in **IndexedDB**, with a localStorage copy while it fits. Every change is written within about 250 ms, and again when you switch tabs or close the page. Room depends on the browser and free disk space: usually hundreds of MB or more, compared with roughly 5 MB for localStorage alone. Help shows how much you are using. |
| **One browser, one address** | Data belongs to one browser profile *and* one address. A copy opened from disk (`file://`) and the GitHub Pages copy each keep their own data, and so do Chrome and Firefox. Private windows and embedded previews keep nothing; a red banner warns you when saving is blocked. |
| **Backups** | Clearing site data erases everything. Export regularly from **Help → Export everything** (attached files are included); the same page imports a backup. The Dashboard reminds you when your last backup is more than two weeks old. |
| **Undo, trash and restore points** | Deleted cases, entries, records, relationships and notes stay in the trash for 30 days. A full restore point is saved before every import, reset, sample-data removal or log import. |
| **Sample data** | The app starts with three example investigations, notes, news items and CTF challenges. **Remove sample data** (on the Dashboard banner, Settings or Help) deletes only those and keeps your own work. |

## Run it locally

No install, no build step, no dependencies.

```bash
git clone https://github.com/YOUR-USERNAME/osintrix.git
cd osintrix
# then open index.html in any modern browser
```

Everything is plain files, so you edit them and reload the page. The scripts are ordinary `<script>` tags loaded in order, which is why it also works when opened straight from disk (`file://`), where ES modules and `fetch()` are blocked.

```
osintrix/
├── index.html              ← page skeleton, Content Security Policy, script order
├── css/
│   ├── app.css             ← design system and every component
│   └── fonts.css           ← @font-face rules
├── fonts/                  ← Inter and JetBrains Mono (woff2)
├── js/
│   ├── data/
│   │   ├── tools.js            ← default toolbox (JSON after the "=")
│   │   ├── query-templates.js  ← default query library
│   │   └── detection-rules.js  ← default Sigma / YARA rules
│   ├── vendor/             ← cytoscape.min.js, jsqr.min.js, oui-vendors.js (IEEE MAC vendor list)
│   ├── icons.js            ← Lucide icon set
│   ├── engine.js           ← indicator extraction, time parsing, search syntax
│   ├── brand.js · model.js · demo.js   ← name and logo, entry types, sample cases
│   ├── core.js             ← state, storage (IndexedDB), routing
│   ├── views.js            ← dashboard, cases, timeline
│   ├── graph.js            ← Cytoscape graph, paths, time slider, exports
│   ├── areas.js            ← toolbox, entities, decoder, reference, settings, help
│   ├── insp.js             ← details panel, dialogs, capture
│   ├── intel.js · queries.js · detections.js · notes.js · playbooks.js
│   ├── extras.js           ← pivots, IOC export, print, case import, decoder
│   ├── lab.js · kit.js     ← CTF tracker, forensics kit, file parsers, YARA / Sigma engines
│   ├── search.js           ← search everything
│   ├── safety.js           ← trash, restore points, backups, attachments, log import
│   ├── tl.js · report.js   ← timeline heatmap and multi-select, report templates
│   └── app.js              ← events, keyboard, boot (loads last)
├── tools/bundle.py         ← optional: makes a one-file offline copy
└── docs/                   ← screenshots
```

### One-file offline copy (optional)

For emailing to a colleague, a USB stick or an air-gapped machine:

```bash
python tools/bundle.py      # Python 3, standard library only → dist/osintrix-offline.html
```

It inlines every file above into one HTML page. It is the same app, and it keeps its data in the same place.

### Adding default tools

Add entries to `js/data/tools.js` and reload. When people load the new version, the new tools are added to their toolbox automatically. Their own tools, favourites and pins are left alone, and pre-added tools they deleted stay deleted.

## Keyboard shortcuts

| Keys | Action |
|---|---|
| `Ctrl` `K` or `/` | Search everything, run actions |
| `N` | Capture evidence |
| `E` | Add a vault entry |
| `1` – `6` | Switch case tabs |
| `Ctrl` `S` | Save the rule you're editing |
| `Ctrl` `Enter` | Save a capture or note |
| `Shift` `F10` | Graph menu for the selected node |
| `Esc` | Close a panel or dialog |

## Roadmap

- [x] Playbooks: investigation checklists that run on a case
- [x] Case import and export, IOC export (CSV, text, STIX 2.1), print to PDF
- [x] CTF tracker, forensics kit, flag finder
- [x] IndexedDB storage (well beyond the ~5 MB localStorage limit)
- [ ] Optional encrypted backup files
- [ ] PCAP summary (hosts, DNS, HTTP) in the File inspector
- [ ] Library: a personal knowledge base of articles and write-ups
- [x] Evidence attachments (screenshots, files) stored locally
- [x] Bulk log import, report templates and redaction, trash and restore points

## Built with

Vanilla JavaScript and CSS, with no framework. Everything is bundled so it runs offline:

| Component | License |
|---|---|
| [Cytoscape.js](https://js.cytoscape.org/) 3.30 | MIT |
| [Inter](https://rsms.me/inter/) | SIL Open Font License 1.1 |
| [JetBrains Mono](https://www.jetbrains.com/lp/mono/) | SIL Open Font License 1.1 |
| [Lucide](https://lucide.dev/) icons | ISC |
| [jsQR](https://github.com/cozmo/jsQR) 1.4 | Apache-2.0 |
| IEEE OUI list via [oui-data](https://github.com/silverwind/oui-data) | BSD-2-Clause |

The demo case data is synthetic. The IPs and domains in it use reserved documentation ranges such as `203.0.113.0/24` and `.example`.

## Background

OSINTrix merges two of my college projects: **ThreatNet**, a toolbox and knowledge vault for security research, and **Clew**, a timeline-based investigation notebook. Together they became one privacy-first workspace. The change history is in [CHANGELOG.md](CHANGELOG.md).

## Disclaimer

OSINTrix is for lawful research, security operations and education. You are responsible for how you use it and for following the terms of any third-party site or tool you reach through it.

## License

<!-- Pick one and add a LICENSE file, e.g. MIT: https://choosealicense.com/licenses/mit/ -->
Not yet licensed. All rights reserved until a LICENSE file is added.
