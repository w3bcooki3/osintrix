# OSINTrix v1.19 — Field kit

## Commit summary
v1.19: new welcome, CTF workspace and write-ups, case Places, 366 new rules, 42 playbooks, 1,200-entry reference, cloud guide reader

## Description
- **Welcome page** is redesigned. It follows the light or dark theme, shows current screenshots of the app, and no longer has the Night/Day/Indigo colour switch.
- **CTF** has four tabs:
  - **Challenges** is the board. Each challenge opens a workspace with:
    - a work log that records what worked, dead ends and ideas, with commands;
    - first moves for its category, which you can tick off;
    - entities found in the notes;
    - a live flag-format check and a "Mark solved" button.
  - **Write-ups** are generated from the work log, can be imported or exported as Markdown, and open in a reader with the flag blurred until you show it.
  - **Cheatsheets** cover 9 categories, each with 20 recognise-it rows, 24 commands, gotchas and first moves. You can search across all of them.
  - **First moves** holds the checklists.
- **Places** replaces the case map, and the Leaflet library is no longer loaded:
  - an offline overview map;
  - place cards with 12 map services (Google Maps, Street View, Earth, OpenStreetMap, Bing, Apple, Yandex, Mapillary, Sentinel, Wikimapia, Overpass, SunCalc);
  - movement in time order, with impossible-travel warnings;
  - countries, geolocation helpers, and export to KML or CSV.
- **Detections** has 366 new rules (289 Sigma, 77 YARA), common and advanced, across Windows, Linux, macOS, AWS, Azure, GCP, Kubernetes, M365, Okta, network and web.
  - Every Sigma rule parses and every YARA rule compiles. The YARA rules were also scanned against about 1,700 harmless files, and the false positives found were fixed.
  - New platform and level filters, multi-word search, and results shown in pages. Built-in rules merge into existing workspaces without touching rules you've edited.
- **Playbooks** has 42 new entries (55 in total), with new Cloud and Forensics categories, level and time tags, and category and level filters.
- **Reference** goes from 128 to 1,216 entries in 40 sections, grouped by area:
  - Search ranks matches, highlights them, and lets you move through results with the arrow keys.
  - Entries have "also known as" chips. AADSTS codes can be searched with or without the prefix.
- **Cloud field guide** is now a list with a reader:
  - Each technique has numbered commands plus what to look for, how defenders see it, and how to fix it.
  - There are 60 new techniques (98 in total), with provider and level filters.
  - On phones the reader opens full screen.
- **Board toolbar** now fits on one row on laptop screens.
- 26 of 26 Playwright tests pass, including new tests for the CTF flow, Places, and loading the new content.

## Files changed
CHANGELOG.md, index.html, package.json, tools/bundle.py, tests/app.spec.js, css/design.css,
assets/welcome/*.jpg (6), design-pocs/ctf-poc.html,
js/app.js, js/areas.js, js/brand.js, js/cloud.js, js/core.js, js/detections.js, js/lab.js, js/map.js, js/playbooks.js,
new: js/ctf.js, js/data/detections-pack.js, js/data/playbooks-pack.js, js/data/reference-pack.js, js/data/cloudguide-pack.js, js/data/ctf-cheats.js

## Can be deleted
js/vendor/leaflet.js and css/vendor/leaflet.css are no longer used.

## Worth a review
- A few cloud Sigma rules use newer modifiers (|fieldref, |exists, |windash). Two AWS rules contain placeholder account IDs and CIDRs.
- A handful of Entra error-code descriptions and newer ATT&CK sub-technique IDs were written from memory.
