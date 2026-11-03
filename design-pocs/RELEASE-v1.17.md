# OSINTrix v1.16 + v1.17 — New design and data safety

Commit title: `v1.16–1.17: new design, collapsible sidebar, rebuilt timeline, data-safety fixes`

## v1.17 — Data safety (the four release blockers, plus the freeze)
- **Unreadable data is never overwritten.** Damaged data, or data from a newer version, opens a recovery screen (download it, or start fresh with the old copy kept aside) instead of being replaced by the demo. (`js/core.js` `readCopy`, `js/integrity.js` `recoveryScreen`)
- **Single-writer tabs.** A Web Lock makes one tab the writer. Other tabs are read-only, show a banner, follow the writer's saves over a BroadcastChannel, and can take over. (`js/integrity.js` `claimWriter`)
- **Offline copy runs only its own code.** `tools/bundle.py` lists every script by SHA-256 hash in the CSP; there is no `'unsafe-inline'` for scripts.
- **Imports are checked.** Backups, case files, tool lists and query lists are shape-checked before anything changes, and IDs that could break out of an HTML attribute are refused (`checkImport`). Imported files always get fresh IDs (`rekeyFiles`). Menu titles are sanitised (`cleanTitle`). Attachments open by their real bytes (`sniffKind`).
- **No more freeze on hostile paste.** Runs of 400+ characters without whitespace are split before matching: 100 KB of `a.a.a…` takes about 0.13 s instead of 34 s.
- **New tests (22 total, all passing):** unreadable data is kept; the second tab is read-only and takes over; bad imports are refused; files are never overwritten; the extractor stays fast.


## What's new

**Design system** (`css/design.css`, loaded last)
- Geist and Geist Mono, bundled into `css/fonts.css`, so the app still works fully offline.
- One colour system for light mode and a deep-navy dark mode:
  - an indigo accent for actions;
  - colours that mean something: entity types, verdicts (red malicious, amber suspicious, green benign) and per-case colours.
- Consistent buttons, inputs, tabs, tables, dialogs, chips and empty states.
- Sentence-case labels instead of tracked-out capitals.
- Every page uses the full width of the screen.

**Interface** (`js/layouts.js`)
- Cases open on their **Board** (the link graph); the other tabs follow.
- Picking a node on the board puts the next actions around it: expand from evidence, connect, find a path, mark malicious, show on the timeline, and more.
- The **sidebar collapses to an icon rail**, with the button at its foot or the `[` key. The choice is remembered.
- Navigation puts cases first, and tools are grouped under Kit and Intelligence.
- Responsive:
  - desktop: full sidebar or rail;
  - tablet: rail;
  - phone: slide-out drawer and bottom tab bar, with details opening as a bottom sheet.

**Evidence timeline (rebuilt)**
- A time rail with coloured event markers. Malicious events get a red dot and the T0 event an amber marker.
- Event cards carry host and source tags, verdict pills, a readable evidence block and entity chips.
- Indicators are marked inside the raw evidence. Picking one highlights every record that mentions it.
- Time gaps are shown on the rail.
- `J`/`K` move through the timeline.

**Other screens**
- Reference: a standard page header replaces the dark banner.
- Cloud: commands show in full, in code blocks that follow the theme.
- Notes: the composer is a single clean field.
- Dashboard: the KPI tiles have tinted icons.

## Fixes
- **Timeline select mode:** the checkbox covered record titles. It now replaces the marker on the rail.
- **Narrow pages:** Analysis, Report, Trash, What's new, Help, Scratchpad, Security and Playbooks sat in a narrow centred column. They now use the full width.
- **Details panel:** it stayed open after moving to another page from the sidebar. It now closes, and stays open only within the same case or when an action opens a record on purpose.
- **Double focus rings:** the search window and the Notes composer drew a second outline inside their frame.
- **Dashboard label:** the all-time record count was labelled "captured this week".
- **Graph toolbar:** at 1440px the toolbar was cut off on the right. It now wraps.
- **Case tabs:** on narrow screens the selected tab could scroll out of view.
- **Empty dialog lists:** the "Add entities to the graph" list had no padding.
- **Brittle test:** `tests/helpers.js` didn't recognise current Chromium's CSP console wording, so a test failed.
- **Version:** `package.json` said 1.6.0 and now says 1.16.0. Static files are cache-busted with `?v=1.16.4`.

## Testing
- All 18 Playwright tests pass (`npm test`).
- Every screen was checked in light and dark at phone, tablet and desktop widths.
- `dist/osintrix-offline.html` was rebuilt with `python tools/bundle.py`.

## Known weaknesses (still open)
The four release blockers and the extractor freeze are fixed in v1.17. Still open:
- The audit chain is an unkeyed hash chain, and custody verification trusts the key embedded in the report, so both can be forged.
- Every save serialises the whole workspace, which costs about 135 ms per save at 20k records.
- Graph layout freezes the page at around 2,000 nodes.
- About 1.8 MB of vendor scripts load eagerly.
- 878 global names share one scope, and the code has very long lines.
- Dead files remain: `build.py` would overwrite `index.html` from a stale `src/` copy, and `vendor/` duplicates `js/vendor/`.
- No LICENSE file. The README's CI badge points to a workflow that isn't in the repo.
