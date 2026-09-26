# OSINTrix — design prototype v7

**Follow every thread.**

A design prototype of OSINTrix, the merged ThreatNet + Clew app. It runs next to the current app. It doesn't read or change any data saved in your existing ThreatNet install.

## Open it

Double-click `index.html`, or visit `/poc/` on GitHub Pages. It needs no install or build step and makes no network requests: fonts, icons and the graph library are all bundled inside the page. `v1.html` is the first prototype, kept for comparison.

## New in v7

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

## New in v6: layout options

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

## New in v5

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

## Earlier (v4)

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

## Earlier (v3)

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

## What changed from v1

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

## Source

`src/` holds the readable source. Run `python build.py` (Python 3, no packages needed) to rebuild `index.html` after editing it.

## Third-party software (bundled, offline)

| Component | Licence |
| --- | --- |
| Cytoscape.js 3.30.2 | MIT, © The Cytoscape Consortium |
| Inter | SIL Open Font License 1.1 |
| JetBrains Mono | SIL Open Font License 1.1 |
| Lucide icons | ISC |

All demo case data is synthetic.
