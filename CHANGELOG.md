# Changelog

All notable changes to OSINTrix, newest first. The format is based on [Keep a Changelog](https://keepachangelog.com); this file is generated from `js/data/changelog.js` by `tools/changelog.py`.

## [1.92] — Forensic files in the sample case, and a steadier timeline (2026-11-28)

_Op Lantern's sample gains a victim's browser profile, the shop's Windows event log and its CloudTrail, read by the same readers as yours; long timeline records stop jumping under the pointer; Blackbook coverage goes to the ATT&CK Navigator._

### Added
- The sample case Op Lantern now has a victim's Chrome profile (her searches, the fake refund portal, the confirmation code she typed, shown masked, and the receipt she downloaded), the Security log of the real shop's office PC (a password spray from the portal's server, then a remote desktop session that copies the customer list) and the shop's CloudTrail (the stolen backup key used from the same address, a new key made, logging nearly stopped, and the key used again from the server the portal moved to). Each is read by the browser-profile, event-log and cloud-log readers, kept as a file with its hash, and joined to the scam by its addresses.
- Browser profile: “Try an example profile” opens the sample victim's profile in one click.
- Blackbook: your coverage downloads as an ATT&CK Navigator layer, each technique coloured by the best status you gave a play for it, with the plays in its comment.

### Changed
- Cloud logs sent to the timeline are titled with what happened, the object, who and from where (“GetObject · exports/orders.csv · office-backup · 198.51.100.23”), not the event name alone.

### Fixed
- A long record on the timeline no longer opens up under a passing pointer and pushes everything below it away; it opens when you choose it or reach it with the keyboard.
- On a phone, a long line in a two-column screen (Settings' recent changes, for one) no longer makes the page wider than the screen.

## [1.91] — A sample case with everything in it, and a Blackbook you can work through (2026-11-27)

_Op Lantern's sample now holds chats, pictures, a place found by geolocation and a Word file with a past; the Blackbook was redrawn and gained sweeps, coverage and new plays._

### Added
- The sample case Op Lantern now has Telegram and Discord chats (a channel, the staff group with a renamed member, and a post pushed into several chats within minutes), a photo with camera and GPS, a picture with its metadata stripped that is geolocated in “Where was this taken?”, a screenshot, and a Word handbook whose tracked changes, comment and hidden text point back at the subject. They are read by the same importers as your own files, so Chats, Active hours, Media, Places and the File inspector all have something to show. A workspace that already has the sample gets them once.
- Blackbook: sweeps — ordered sets of plays for one situation (a new environment, a ransomware warning, an identity takeover, a leaked cloud key, a breached supplier), each step saying why it comes next.
- Blackbook: your coverage. Mark each play to do, hunted or detecting; the list, each stage of the attack and every sweep show how far you are. Kept in this browser.
- Blackbook: four new plays where it was thinnest — network scanners and share hunting, cloud discovery from a stolen identity, cloud data held to ransom, ESXi backdoors through unsigned VIBs — three more campaigns (Akira, Cl0p and MOVEit, Change Healthcare), and Microsoft Defender hunts for eight plays that only had Sigma. Every new Sigma rule is proven like the rest.

### Changed
- Blackbook redrawn: a compact header with the counts, one bar for the parts and search, the plays as a calm list grouped by stage with your coverage beside it, and each play in the order the work happens — understand, detect, hunt, triage, respond, harden, prove — with a contents list, hunts that wrap instead of running off the page, and links to the campaigns and sweeps it belongs to. Underground and OSINT read as a reference: each point beside its explanation.

## [1.90] — The Blackbook, locked and deepened (2026-11-26)

_The Blackbook's contents are encrypted with the owner's passphrase, and every play became a full dossier._

### Added
- Thirty-three new plays for today's attack surface: AD CS certificates, delegation and shadow credentials, forged tickets, the DPAPI backup key, LAPS and AdminSDHolder, DCShadow, GPO deployment and “ESX Admins”; DLL side-loading, COM hijacking, browser extensions, Office add-ins, accessibility backdoors and RDP hijacking; macOS stealers; token replay, Conditional Access tampering, cloud run-command, metadata credentials, storage, serverless and LLMjacking; Okta, Google Workspace, GitHub and CI, Snowflake; ESXi ransomware. Every new Sigma rule is proven like the rest.
- The Blackbook's Hunt view is a coverage matrix you can filter by platform, severity and proven Sigma rule; a Doctrine tab sets out a hunt from start to finish and the telemetry to switch on first.
- “Remember on this device” keeps the derived key in this browser as a key that can be used but not read back; Lock forgets it.
- Keyboard shortcuts list the graph's selection keys: Shift+drag, Ctrl+click, Space and Ctrl+A.

### Changed
- The Blackbook asks for a passphrase and decrypts in the browser (AES-256-GCM, key from PBKDF2-SHA256 with 600,000 iterations). Only the encrypted file is published; the readable source stays on the owner's machine.
- Every Blackbook play is now a dossier: where it was seen in the wild, the exact events and fields to read, what to do when the hunt fires, how to respond, and how to prove the detection works — with severity, signal quality and platforms at a glance.

## [1.89] — A curated toolbox, many nodes at once, and the Blackbook (2026-11-26)

_A toolbox cut down to what practitioners use, selecting several graph nodes to act on together, and a private page for the owner._

### Added
- The Blackbook — a private page for the owner, reached by typing its name in search or from the foot of Tradecraft.
- Graph: select many nodes — Shift or Ctrl+click, Shift+drag a box, or turn on Select and just drag. A bar marks them all malicious, suspicious or benign, sets priority, tags, stars, watches, arranges them in a circle or grid, exports CSV or deletes them, each with one undo. Drag one and they all move; right-click acts on all of them.
- Graph from the keyboard: Space adds the node in focus to the selection, Ctrl+A selects all, Esc lets go.

### Changed
- Toolbox curated: 169 maintained tools that are used in real investigations, mostly free or open source, each saying what it is actually for, with its licence first. New: CyberChef, Hayabusa, Chainsaw, Volatility 3, KAPE, Eric Zimmerman's tools, Ghidra, abuse.ch, LOLBAS and GTFOBins, Microsoft 365 response tools, ship and flight tracking, company registries and crypto explorers. 32 of them open straight on a value from your case.

### Removed
- From the toolbox: US people-search and data-broker sites, dead and retired services, and paid-only enterprise products. Tools you starred, pinned, used or edited stay; tools that moved address keep your stars and notes.

## [1.88] — Privacy, undo, keyboard and the tour (2026-11-26)

_A privacy audit, undo where it was missing, the graph by keyboard, and a tour of both sample cases._

### Added
- Security → Discreet titles and alerts: keeps case names out of the browser tab, the taskbar and your browser history, and reminder alerts outside the app say only that a reminder is due.
- Undo right after deleting a Story claim or a request for comment, deleting a case template, and removing a file from a record (the file itself goes only once Undo has had its chance).
- The graph by keyboard: Tab reaches it, the arrow keys move to the nearest entry that way with its details alongside, Enter opens it, Shift+F10 its menu, + / − zoom and 0 fits. A screen reader hears where you are.

### Changed
- The guided tour covers both sample cases: the timeline, rules, graph, related entries and the crew behind Op Lantern, then Claims, Right of reply and Protected sources on Kestrel Dawn, and new cases from templates.

### Fixed
- The browser no longer keeps what you type into OSINTrix forms for its own autofill — a subject's email, a phone number or a source's name could otherwise be offered back on other sites, outside the workspace and its encryption.
- Entity table rows and places on the map can be reached with Tab and opened with Enter.

## [1.87] — Two sample cases (2026-11-26)

_The sample data is now two cases that show everything: a cybercrime investigation and a journalism story._

### Added
- Kestrel Dawn, a journalism case: a harbour fuel contract, a councillor's family shareholding and a tanker that switched off its transponder. Claims weighed against evidence (confirmed, unverified, disputed), right of reply (answered, declined, waiting), archived pages that changed, ship tracking and a company network.
- Example notes: for each case a checklist and a written note, plus two general ones. A Case notes notebook links pages to cases, vault entries and study pages with [[ ]], tags and checklists, so the links panel and page graph have something to show.

### Changed
- Op Lantern is the cybercrime and OSINT case: the invoice LNK intrusion, and with the OSINT sample the crew behind it — a refund scam on the same server that served the intrusion's second stage, with its infrastructure, money, accounts, page changes and working hours. The link is shown as a lead with its evidence, not as proof.

### Removed
- The Customer portal and Harbour photo CTF sample cases, and the separate Harbourline case. In a workspace that still has them, they are replaced once, after a restore point — and only if nothing of yours was added to them.

## [1.86] — Cleaner panels (2026-11-26)

_Panels fit what is in them, open stories stand out, and Patterns is now Regex._

### Changed
- Threat Intel: a story panel is as tall as the story instead of running empty to the bottom of the window, and the page behind it is blurred and dimmed so the story reads on its own. Click outside it or press Esc to close; previous / next and J / K still move through the list.
- Query library, Detections and CTF: the side panel floats, is as tall as its content, and blurs the page behind it.
- Patterns is now called Regex. The Forensics kit no longer lists a log parser: log parsers are on the Regex page, and old links to the kit's tab still go there.

### Fixed
- A small scrollbar showed at the right of the case tabs on Windows at 125% and 150% display scaling, and on other strips that scroll sideways.

## [1.85] — Real-mouse fixes (2026-11-26)

_A sweep of every screen with real mouse timing: slow clicks, holds, drags that leave the window, redraws mid-action._

### Fixed
- Graph: holding the mouse on a node before dragging it no longer opens the node menu and leaves it behind. The right button opens the menu; a long press still does on a touch screen.
- Graph: a node menu now closes when you drag, pan or zoom, when you go to another page, and when the graph is rebuilt, instead of staying on screen pointing at old data.
- Graph: hovering a node and then moving straight onto the zoom buttons no longer leaves the whole graph faded.
- Graph: with Suggestions or Insights open, the zoom and fit buttons and the time slider were hidden under the panel. They now sit beside it.
- Notebook page graph: a press whose release never arrived (the browser took it for a drag) left the view panning whenever the mouse moved over it.
- Background redraws (a reminder falling due, another tab saving, monitoring results, archived copies found) now wait until you finish typing and until a click is complete. Before, they could wipe a half-typed note or swallow a click.
- Search, the @ list and menus close when you leave the page, including with the browser's Back button.

## [1.84] — Graph freeze fixed (2026-11-26)

_The graph no longer stops responding after you click a node._

### Changed
- Two redraws in quick succession no longer rebuild the graph from scratch.

### Fixed
- After clicking a node (or anything else that redrew the page around the graph), the graph could stop taking clicks, drags and zoom until a legend filter was changed. The graph library switched itself off when the graph was put back after a redraw; it now stays live.

## [1.83] — Case templates (2026-11-25)

_Start a case already set up for the kind of work it is._

### Added
- New case now starts from a template: Story, Person, Company due diligence, Phishing, Incident, Fraud or scam, Threat actor or Missing person, or Blank. Each brings its own questions, the matching playbooks' steps as open questions, a scope hint, an icon and colour, and opens on the right tab (Story, Graph, Map…).
- Before creating, untick any playbook or question you don't want.
- Save any case as your own template from the case menu. Only the structure is kept (questions, playbooks, scope, look and starting tab), never evidence, entries or answers. Your templates sit above the built-in ones and can be deleted.

### Changed
- Quick new case from Capture still goes straight to the form.

## [1.82] — SSH keys and decentralised accounts (2026-11-25)

_Two new kinds of identifier that tie servers and people together._

### Added
- SSH keys are found in authorized_keys, known_hosts, auth logs, ssh -v output and Shodan or Censys results. Every form is named by its SHA-256 fingerprint, so a pasted key, a fingerprint in a log and a scanner hit are one key. The details show its type and size, weak or outdated keys, the comment it was made with, and every machine it was seen on.
- Fediverse (@user@server), Matrix (@user:server), Nostr (npub, nprofile and signed events) and Bluesky IDs (did:plc, did:web) are found and checked, with profile links, the PLC directory's handle history, and a note when an account lives on a small or personal server.
- A Nostr private key (nsec) in evidence is flagged as a leaked secret and never kept.
- These count as strong identifiers for personas, and one name across the fediverse, Matrix and other networks shows under Related in the duplicate finder.

## [1.81] — Damaged files (2026-11-25)

_Hostile and broken files are read as far as they can be._

### Fixed
- In the Lab, a damaged part of a file no longer hides the rest. The part that could not be read is named, and hashes, strings and everything else are still shown.
- A cut-off Windows shortcut (.lnk) could stop the file from being read at all. It now shows what is left, including the target.

## [1.80] — For reporting (2026-11-25)

_A Story tab on every case, for journalists._

### Added
- Claims: each thing the story says as fact, with evidence for and against it and who it is about. “Before you publish” lists what is not ready: fewer than two independent sources, unverified pictures, no right of reply, cited pages with no archived copy.
- Protected sources: a person kept under a pseudonym, their real details encrypted with a passphrase of their own and shown only when you ask. They lock after ten idle minutes or when you leave the tab. Burning a source wipes it from the workspace and from every restore point.
- Right of reply: who was asked to comment, how, the deadline and what they said. Deadlines coming up show on Today.
- Archived pages: save each cited page to the Wayback Machine in one click, and keep the link to the copy.

## [1.79] — Vehicles, ships and aircraft (2026-11-25)

_New identifiers, a lighter offline file, and related entries found for you._

### Added
- VINs, IMO numbers, MMSIs, aircraft registrations and ICAO addresses are found in evidence. Each is checked and read offline: maker and year from a VIN, flag from an MMSI, and a US registration and its address worked out from each other.
- Vehicle, ship and aircraft entries in the vault, with lookup links (NHTSA, MarineTraffic, ADS-B Exchange, FAA registry).
- Duplicates finds the same ship or aircraft under different numbers. A new Related tab offers links for one name on several accounts and for look-alike domains, with the reason on each link.

### Changed
- The one-file copy is a quarter smaller and opens faster: big data files are packed and unpacked only when needed.

## [1.78] — URLs keep their case, one Patterns page (2026-11-25)

_Small fixes from daily use._

### Added
- The Decoder, Certificates and Cloud guide keep your recent input too, if tool history is on in Settings.
- More save buttons have the ▾ to pick any case or make a new one.
- If something on a page fails, a notice says so and has a “Copy details” button for bug reports.

### Changed
- URLs keep the case of their path and query, so share links and tokens still work when opened. Only the scheme and host are lowercased. URLs saved earlier get their case back from the record they came from.
- Patterns: the regex builder and the log parsers are now one page with two tabs.

### Fixed
- The graph could stop responding to the mouse after adding from evidence, until you clicked elsewhere. It now keeps working.

## [1.77] — Save to any case (2026-11-24)

_Pick where things go, and clear tools in one click._

### Added
- The ▾ beside a save button lists every case and “New case…”.
- Investigate and Decode tools have Clear. They can also keep your last 10 searches, which is off by default.

### Changed
- Look-alikes lists candidates at once. Page hash shows what a saved page loads and where it sends data. Hashes decodes what can be decoded.

### Fixed
- Layout fixes in Entities and Settings.

## [1.76] — WinForensicX hand-off (2026-11-24)

_Move indicators between OSINTrix and WinForensicX._

### Added
- Import the STIX file that WinForensicX exports. You can add its indicators to a case as well.
- Export a hunt list that Invoke-WfxHunt -IocFile reads.

### Fixed
- A file entry with an MD5 or SHA-1 is filed as that hash, so it joins the same hash found in records.

## [1.60–1.75] — Forensics kit and tradecraft (2026-11-24)

_Tools for the files and accounts an investigation turns up._

### Added
- Forensics kit: documents, web captures, browser profiles, stealer logs, phishing kits, chat exports. Each is read and summarised.
- Wallet trails, now with Solana, from pasted text or files.
- Personas with an OPSEC check and a log, plus onion pages and Web3 identifiers.
- Linked notebook, note reminders, and cases kept in files.

### Changed
- A design pass across every screen.

## [1.40–1.59] — Reading evidence like an analyst (2026-11-23)

_Better reading of indicators and logs, and room for big cases._

### Added
- Regex builder, plus masking for anything you share.
- Endpoint evidence, certificates, cloud logs and detection rules, each checked against your cases.
- Case snapshots, saved views and @ links in notes.

### Changed
- Large vaults and graphs stay workable.

## [1.12–1.39] — Cases, intel and the engine (2026-11-15)

_The core of the workspace._

### Added
- Threat Intel feeds, the investigation engine, Copilot and graph analysis.
- Certificates, Cloud, the Notebook, media in cases and the detection lab.

### Changed
- A new design and a cases board.

### Fixed
- Hardened storage and a faster start, so nothing is lost on reload or when space runs low.

## [0.x–1.11] — The beginning (2026-10-08)

_ThreatNet and Clew merged into one offline workspace._

### Added
- Toolbox, timeline-based cases, entity extraction, the graph and the map.
- Playbooks, pivots, exports, the Lab and a CTF area.
- Search across everything, chain of custody and a safety net for your data.

---

_Generated 2026-11-28 from `js/data/changelog.js`. Do not edit this file by hand — edit the data file and run `python tools/changelog.py`._
