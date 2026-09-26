<div align="center">

# OSINTrix

**Follow every thread.**

A private OSINT investigation workspace that runs entirely in your browser.
No server. No account. No tracking. Your cases never leave your machine.

[**Launch the app →**](https://w3bcooki3.github.io/osintrix/) &nbsp;·&nbsp; [Features](#features) &nbsp;·&nbsp; [Privacy](#privacy-by-design) &nbsp;·&nbsp; [Run it locally](#run-it-locally)

![OSINTrix dashboard](docs/dashboard.png)

</div>

---

## What is OSINTrix?

OSINTrix is a workspace for OSINT analysts, threat researchers and blue teamers. It brings everything an investigation needs into one place:

- the people, accounts and infrastructure you are tracking;
- the evidence you collect;
- how it all connects;
- the tools and searches you rely on.

It is a single HTML file. Open it from GitHub Pages or straight from your disk, and it works the same, offline included. Everything you enter is stored in your browser's local storage and nowhere else.

## Features

### 🗂️ Cases
- **Case vaults:** each investigation holds typed entries (people, usernames, emails, phones, domains, IPs, crypto wallets, forums, documents and more). Each type has its own fields, plus priority, verdict, tags and notes.
- **Evidence capture:** paste a log line, a post or a note. Indicators (IPs, domains, hashes, emails, handles, CVEs…) and timestamps are pulled out automatically.
- **Timeline:** every record in order, with day headers, event markers and filters. Search with `host:`, `verdict:`, `type:`, `tag:`, `after:` and `before:`.
- **Link graph:**
  - Drag, add, edit and connect nodes.
  - Right-click menus on nodes, links and empty canvas.
  - Every relationship carries a confidence rating and its evidence.
  - Automatic layouts and PNG export.
- **Questions and reports:** track open questions, then export a Markdown report or the whole case as JSON.

![Graph](docs/graph.png)

### 🧰 Research
- **Toolbox:** 90+ curated OSINT and security tools across 8 categories.
  - Favourites, a quick-launch list, tags and bulk actions.
  - Card, directory and compact layouts.
  - Import your own tool list.
- **Query library:** 68 saved search recipes with `{{BLANKS}}` that fill from your case entries.
  - Runs in Google, Bing, DuckDuckGo, Shodan, Censys, GitHub, ZoomEye, FOFA and Intelligence X.
  - Each search can be logged to the case.
- **Decoder:** peels Base64, hex, URL-encoding and other layers one at a time.
- **Reference:** Windows and Sysmon event IDs, ports, and living-off-the-land binaries.

![Toolbox](docs/toolbox.png)

### 🛡️ Intelligence
- **Detections:** write, keep and import Sigma and YARA rules.
  - Editor with syntax highlighting and a live structure check.
  - Link a rule to a case, or generate starter rules from a case's malicious indicators.
- **Threat Intel:** security news from your RSS sources, classified by category and severity, and checked against every entity in your cases. It is off until you turn it on.
- **Entities:** every indicator across every case, with verdicts and cross-case matches.

![Detections](docs/detections.png)

### 📝 And also
- Sticky notes and to-dos, general or pinned to a case.
- A command palette (`Ctrl K`) for searching everything and running actions.
- Dark and light themes, three text sizes, and a compact density.
- Fully responsive: sidebar on desktop, icon rail on tablet, and a bottom bar with sheets on phones.

<p align="center"><img src="docs/mobile.png" width="260" alt="OSINTrix on a phone"></p>

## Privacy by design

| | |
|---|---|
| **Where your data lives** | Only in this browser's local storage. Nothing is uploaded. There is no backend and no analytics. |
| **Network access** | The page's Content Security Policy blocks every outside connection except one: `api.rss2json.com`, used only if you turn on live Threat Intel feeds. Even then, only feed addresses are sent. |
| **Untrusted content** | Feed articles and pasted evidence are shown as plain text. Links open only when you click them, in a new tab with no referrer. |
| **Backups** | Because data is local, clearing browser data erases it. Export regularly from **Help → Export everything**; the same page imports a backup and resets data, and each of those can be undone. |

## Run it locally

No install, no build step, no dependencies.

```bash
git clone https://github.com/YOUR-USERNAME/osintrix.git
cd osintrix
# then open index.html in any modern browser
```

### Editing the source

`index.html` is generated from the readable files in `src/`. After changing anything there, rebuild:

```bash
python build.py     # Python 3, standard library only
```

```
osintrix/
├── index.html          ← the app (generated, self-contained)
├── build.py            ← inlines fonts, styles, Cytoscape and scripts into index.html
├── src/
│   ├── shell.html      ← page skeleton + Content Security Policy
│   ├── styles.css      ← design system and components
│   ├── engine.js       ← indicator extraction, time parsing, search syntax
│   ├── core.js         ← state, storage, routing
│   ├── views.js        ← dashboard, cases, timeline, report
│   ├── graph.js        ← Cytoscape graph and context menus
│   ├── areas.js        ← toolbox, entities, decoder, reference, settings, help
│   ├── queries.js      ← query library
│   ├── detections.js   ← Sigma/YARA editor
│   ├── intel.js        ← threat-intel feeds
│   ├── notes.js        ← sticky notes
│   ├── insp.js         ← details panel, dialogs, command palette
│   ├── app.js          ← events, keyboard, boot
│   └── tools.json · dork_templates.json · threat-rules.json   ← default content
├── vendor/cytoscape.min.js
└── docs/               ← screenshots
```

### Adding default tools

Add entries to `src/tools.json` and rebuild. When people load the new version, the new tools are added to their toolbox automatically. Their own tools, favourites and pins are left alone, and pre-added tools they deleted stay deleted.

## Keyboard shortcuts

| Keys | Action |
|---|---|
| `Ctrl` `K` | Command palette: search everything, run actions |
| `N` | Capture evidence |
| `E` | Add a vault entry |
| `/` | Search the current case |
| `1` – `6` | Switch case tabs |
| `Ctrl` `S` | Save the rule you're editing |
| `Ctrl` `Enter` | Save a capture or note |
| `Shift` `F10` | Graph menu for the selected node |
| `Esc` | Close a panel or dialog |

## Roadmap

- [ ] Playbooks: step-by-step investigation checklists
- [ ] Library: a personal knowledge base of articles and write-ups
- [ ] Import a single case from JSON
- [ ] Optional encrypted backup files

## Built with

Vanilla JavaScript and CSS, with no framework. Everything is bundled so it runs offline:

| Component | License |
|---|---|
| [Cytoscape.js](https://js.cytoscape.org/) 3.30 | MIT |
| [Inter](https://rsms.me/inter/) | SIL Open Font License 1.1 |
| [JetBrains Mono](https://www.jetbrains.com/lp/mono/) | SIL Open Font License 1.1 |
| [Lucide](https://lucide.dev/) icons | ISC |

The demo case data is synthetic. The IPs and domains in it use reserved documentation ranges such as `203.0.113.0/24` and `.example`.

## Background

OSINTrix merges two of my college projects: **ThreatNet**, a toolbox and knowledge vault for security research, and **Clew**, a timeline-based investigation notebook. Together they became one privacy-first workspace. The change history is in [CHANGELOG.md](CHANGELOG.md).

## Disclaimer

OSINTrix is for lawful research, security operations and education. You are responsible for how you use it and for following the terms of any third-party site or tool you reach through it.

## License

<!-- Pick one and add a LICENSE file, e.g. MIT: https://choosealicense.com/licenses/mit/ -->
Not yet licensed. All rights reserved until a LICENSE file is added.
