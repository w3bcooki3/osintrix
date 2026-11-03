# OSINTrix v1.16 — New design

Commit title: `v1.16: new design, collapsible sidebar, rebuilt evidence timeline`

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

## Known weaknesses (from the audit, still open)
**Release blockers**
1. **Stored data can be reset to the demo:** data in an unrecognised format is silently replaced with demo data on load (`core.js` load path, `app.js` boot).
2. **Tabs overwrite each other:** two open tabs overwrite each other's edits. No lock or cross-tab sync yet.
3. **Offline build runs injected HTML:** the offline bundle's CSP allows `'unsafe-inline'`, so injected HTML can run script.
4. **Imports aren't validated:**
   - imports aren't schema-checked;
   - IDs in attributes and the context-menu title (`graph.js` `showMenu`) aren't escaped;
   - case imports can overwrite another case's attachment files.

**Other**
- Pasting a crafted string such as `a.a.a.…` makes the extractor regexes take quadratic time and freezes the UI (about 34 s for 100 KB).
- The audit chain is an unkeyed hash chain, and custody verification trusts the key embedded in the report, so both can be forged.
- Every save serialises the whole workspace, which costs about 135 ms per save at 20k records.
- Graph layout freezes the page at around 2,000 nodes.
- About 1.8 MB of vendor scripts load eagerly.
- 878 global names share one scope, and the code has very long lines.
- Dead files remain: `build.py` would overwrite `index.html` from a stale `src/` copy, and `vendor/` duplicates `js/vendor/`.
- No LICENSE file. The README's CI badge points to a workflow that isn't in the repo.
