/* Release history — the single source of truth for both the in-app "What's new"
   page and CHANGELOG.md (run tools/changelog.py to regenerate the file).
   Plain JSON after the "=", like the other data files. Newest first.
   Each change has a type: "added" | "changed" | "fixed" | "removed". */
const CHANGELOG_DATA = [
{
  "version": "1.90",
  "name": "The Blackbook, locked",
  "date": "2026-11-26",
  "summary": "The Blackbook's contents are now encrypted with the owner's passphrase, so the public code reveals nothing of them.",
  "changes": [
    {
      "type": "changed",
      "text": "The Blackbook asks for a passphrase and decrypts in the browser (AES-256-GCM, key from PBKDF2-SHA256 with 600,000 iterations). Only the encrypted file is published; the readable source stays on the owner's machine."
    },
    {
      "type": "added",
      "text": "“Remember on this device” keeps the derived key in this browser as a key that can be used but not read back; Lock forgets it."
    },
    {
      "type": "added",
      "text": "Keyboard shortcuts list the graph's selection keys: Shift+drag, Ctrl+click, Space and Ctrl+A."
    }
  ]
},
{
  "version": "1.89",
  "name": "A curated toolbox, many nodes at once, and the Blackbook",
  "date": "2026-11-26",
  "summary": "A toolbox cut down to what practitioners use, selecting several graph nodes to act on together, and a private page for the owner.",
  "changes": [
    {
      "type": "added",
      "text": "The Blackbook — a private page for the owner, reached by typing its name in search or from the foot of Tradecraft."
    },
    {
      "type": "added",
      "text": "Graph: select many nodes — Shift or Ctrl+click, Shift+drag a box, or turn on Select and just drag. A bar marks them all malicious, suspicious or benign, sets priority, tags, stars, watches, arranges them in a circle or grid, exports CSV or deletes them, each with one undo. Drag one and they all move; right-click acts on all of them."
    },
    {
      "type": "added",
      "text": "Graph from the keyboard: Space adds the node in focus to the selection, Ctrl+A selects all, Esc lets go."
    },
    {
      "type": "changed",
      "text": "Toolbox curated: 169 maintained tools that are used in real investigations, mostly free or open source, each saying what it is actually for, with its licence first. New: CyberChef, Hayabusa, Chainsaw, Volatility 3, KAPE, Eric Zimmerman's tools, Ghidra, abuse.ch, LOLBAS and GTFOBins, Microsoft 365 response tools, ship and flight tracking, company registries and crypto explorers. 32 of them open straight on a value from your case."
    },
    {
      "type": "removed",
      "text": "From the toolbox: US people-search and data-broker sites, dead and retired services, and paid-only enterprise products. Tools you starred, pinned, used or edited stay; tools that moved address keep your stars and notes."
    }
  ]
},

{
  "version": "1.88",
  "name": "Privacy, undo, keyboard and the tour",
  "date": "2026-11-26",
  "summary": "A privacy audit, undo where it was missing, the graph by keyboard, and a tour of both sample cases.",
  "changes": [
    {
      "type": "added",
      "text": "Security → Discreet titles and alerts: keeps case names out of the browser tab, the taskbar and your browser history, and reminder alerts outside the app say only that a reminder is due."
    },
    {
      "type": "fixed",
      "text": "The browser no longer keeps what you type into OSINTrix forms for its own autofill — a subject's email, a phone number or a source's name could otherwise be offered back on other sites, outside the workspace and its encryption."
    },
    {
      "type": "added",
      "text": "Undo right after deleting a Story claim or a request for comment, deleting a case template, and removing a file from a record (the file itself goes only once Undo has had its chance)."
    },
    {
      "type": "added",
      "text": "The graph by keyboard: Tab reaches it, the arrow keys move to the nearest entry that way with its details alongside, Enter opens it, Shift+F10 its menu, + / − zoom and 0 fits. A screen reader hears where you are."
    },
    {
      "type": "fixed",
      "text": "Entity table rows and places on the map can be reached with Tab and opened with Enter."
    },
    {
      "type": "changed",
      "text": "The guided tour covers both sample cases: the timeline, rules, graph, related entries and the crew behind Op Lantern, then Claims, Right of reply and Protected sources on Kestrel Dawn, and new cases from templates."
    }
  ]
},
{
  "version": "1.87",
  "name": "Two sample cases",
  "date": "2026-11-26",
  "summary": "The sample data is now two cases that show everything: a cybercrime investigation and a journalism story.",
  "changes": [
    {
      "type": "changed",
      "text": "Op Lantern is the cybercrime and OSINT case: the invoice LNK intrusion, and with the OSINT sample the crew behind it — a refund scam on the same server that served the intrusion's second stage, with its infrastructure, money, accounts, page changes and working hours. The link is shown as a lead with its evidence, not as proof."
    },
    {
      "type": "added",
      "text": "Kestrel Dawn, a journalism case: a harbour fuel contract, a councillor's family shareholding and a tanker that switched off its transponder. Claims weighed against evidence (confirmed, unverified, disputed), right of reply (answered, declined, waiting), archived pages that changed, ship tracking and a company network."
    },
    {
      "type": "added",
      "text": "Example notes: for each case a checklist and a written note, plus two general ones. A Case notes notebook links pages to cases, vault entries and study pages with [[ ]], tags and checklists, so the links panel and page graph have something to show."
    },
    {
      "type": "removed",
      "text": "The Customer portal and Harbour photo CTF sample cases, and the separate Harbourline case. In a workspace that still has them, they are replaced once, after a restore point — and only if nothing of yours was added to them."
    }
  ]
},
{
  "version": "1.86",
  "name": "Cleaner panels",
  "date": "2026-11-26",
  "summary": "Panels fit what is in them, open stories stand out, and Patterns is now Regex.",
  "changes": [
    {
      "type": "changed",
      "text": "Threat Intel: a story panel is as tall as the story instead of running empty to the bottom of the window, and the page behind it is blurred and dimmed so the story reads on its own. Click outside it or press Esc to close; previous / next and J / K still move through the list."
    },
    {
      "type": "changed",
      "text": "Query library, Detections and CTF: the side panel floats, is as tall as its content, and blurs the page behind it."
    },
    {
      "type": "changed",
      "text": "Patterns is now called Regex. The Forensics kit no longer lists a log parser: log parsers are on the Regex page, and old links to the kit's tab still go there."
    },
    {
      "type": "fixed",
      "text": "A small scrollbar showed at the right of the case tabs on Windows at 125% and 150% display scaling, and on other strips that scroll sideways."
    }
  ]
},
{
  "version": "1.85",
  "name": "Real-mouse fixes",
  "date": "2026-11-26",
  "summary": "A sweep of every screen with real mouse timing: slow clicks, holds, drags that leave the window, redraws mid-action.",
  "changes": [
    {
      "type": "fixed",
      "text": "Graph: holding the mouse on a node before dragging it no longer opens the node menu and leaves it behind. The right button opens the menu; a long press still does on a touch screen."
    },
    {
      "type": "fixed",
      "text": "Graph: a node menu now closes when you drag, pan or zoom, when you go to another page, and when the graph is rebuilt, instead of staying on screen pointing at old data."
    },
    {
      "type": "fixed",
      "text": "Graph: hovering a node and then moving straight onto the zoom buttons no longer leaves the whole graph faded."
    },
    {
      "type": "fixed",
      "text": "Graph: with Suggestions or Insights open, the zoom and fit buttons and the time slider were hidden under the panel. They now sit beside it."
    },
    {
      "type": "fixed",
      "text": "Notebook page graph: a press whose release never arrived (the browser took it for a drag) left the view panning whenever the mouse moved over it."
    },
    {
      "type": "fixed",
      "text": "Background redraws (a reminder falling due, another tab saving, monitoring results, archived copies found) now wait until you finish typing and until a click is complete. Before, they could wipe a half-typed note or swallow a click."
    },
    {
      "type": "fixed",
      "text": "Search, the @ list and menus close when you leave the page, including with the browser's Back button."
    }
  ]
},
{
  "version": "1.84",
  "name": "Graph freeze fixed",
  "date": "2026-11-26",
  "summary": "The graph no longer stops responding after you click a node.",
  "changes": [
    {
      "type": "fixed",
      "text": "After clicking a node (or anything else that redrew the page around the graph), the graph could stop taking clicks, drags and zoom until a legend filter was changed. The graph library switched itself off when the graph was put back after a redraw; it now stays live."
    },
    {
      "type": "changed",
      "text": "Two redraws in quick succession no longer rebuild the graph from scratch."
    }
  ]
},
{
  "version": "1.83",
  "name": "Case templates",
  "date": "2026-11-25",
  "summary": "Start a case already set up for the kind of work it is.",
  "changes": [
    {
      "type": "added",
      "text": "New case now starts from a template: Story, Person, Company due diligence, Phishing, Incident, Fraud or scam, Threat actor or Missing person, or Blank. Each brings its own questions, the matching playbooks' steps as open questions, a scope hint, an icon and colour, and opens on the right tab (Story, Graph, Map…)."
    },
    {
      "type": "added",
      "text": "Before creating, untick any playbook or question you don't want."
    },
    {
      "type": "added",
      "text": "Save any case as your own template from the case menu. Only the structure is kept (questions, playbooks, scope, look and starting tab), never evidence, entries or answers. Your templates sit above the built-in ones and can be deleted."
    },
    {
      "type": "changed",
      "text": "Quick new case from Capture still goes straight to the form."
    }
  ]
},
{
  "version": "1.82",
  "name": "SSH keys and decentralised accounts",
  "date": "2026-11-25",
  "summary": "Two new kinds of identifier that tie servers and people together.",
  "changes": [
    {
      "type": "added",
      "text": "SSH keys are found in authorized_keys, known_hosts, auth logs, ssh -v output and Shodan or Censys results. Every form is named by its SHA-256 fingerprint, so a pasted key, a fingerprint in a log and a scanner hit are one key. The details show its type and size, weak or outdated keys, the comment it was made with, and every machine it was seen on."
    },
    {
      "type": "added",
      "text": "Fediverse (@user@server), Matrix (@user:server), Nostr (npub, nprofile and signed events) and Bluesky IDs (did:plc, did:web) are found and checked, with profile links, the PLC directory's handle history, and a note when an account lives on a small or personal server."
    },
    {
      "type": "added",
      "text": "A Nostr private key (nsec) in evidence is flagged as a leaked secret and never kept."
    },
    {
      "type": "added",
      "text": "These count as strong identifiers for personas, and one name across the fediverse, Matrix and other networks shows under Related in the duplicate finder."
    }
  ]
},
{
  "version": "1.81",
  "name": "Damaged files",
  "date": "2026-11-25",
  "summary": "Hostile and broken files are read as far as they can be.",
  "changes": [
    {
      "type": "fixed",
      "text": "In the Lab, a damaged part of a file no longer hides the rest. The part that could not be read is named, and hashes, strings and everything else are still shown."
    },
    {
      "type": "fixed",
      "text": "A cut-off Windows shortcut (.lnk) could stop the file from being read at all. It now shows what is left, including the target."
    }
  ]
},
{
  "version": "1.80",
  "name": "For reporting",
  "date": "2026-11-25",
  "summary": "A Story tab on every case, for journalists.",
  "changes": [
    {
      "type": "added",
      "text": "Claims: each thing the story says as fact, with evidence for and against it and who it is about. “Before you publish” lists what is not ready: fewer than two independent sources, unverified pictures, no right of reply, cited pages with no archived copy."
    },
    {
      "type": "added",
      "text": "Protected sources: a person kept under a pseudonym, their real details encrypted with a passphrase of their own and shown only when you ask. They lock after ten idle minutes or when you leave the tab. Burning a source wipes it from the workspace and from every restore point."
    },
    {
      "type": "added",
      "text": "Right of reply: who was asked to comment, how, the deadline and what they said. Deadlines coming up show on Today."
    },
    {
      "type": "added",
      "text": "Archived pages: save each cited page to the Wayback Machine in one click, and keep the link to the copy."
    }
  ]
},
{
  "version": "1.79",
  "name": "Vehicles, ships and aircraft",
  "date": "2026-11-25",
  "summary": "New identifiers, a lighter offline file, and related entries found for you.",
  "changes": [
    {
      "type": "added",
      "text": "VINs, IMO numbers, MMSIs, aircraft registrations and ICAO addresses are found in evidence. Each is checked and read offline: maker and year from a VIN, flag from an MMSI, and a US registration and its address worked out from each other."
    },
    {
      "type": "added",
      "text": "Vehicle, ship and aircraft entries in the vault, with lookup links (NHTSA, MarineTraffic, ADS-B Exchange, FAA registry)."
    },
    {
      "type": "added",
      "text": "Duplicates finds the same ship or aircraft under different numbers. A new Related tab offers links for one name on several accounts and for look-alike domains, with the reason on each link."
    },
    {
      "type": "changed",
      "text": "The one-file copy is a quarter smaller and opens faster: big data files are packed and unpacked only when needed."
    }
  ]
},
  {
    "version": "1.78",
    "name": "URLs keep their case, one Patterns page",
    "date": "2026-11-25",
    "summary": "Small fixes from daily use.",
    "changes": [
      {
        "type": "changed",
        "text": "URLs keep the case of their path and query, so share links and tokens still work when opened. Only the scheme and host are lowercased. URLs saved earlier get their case back from the record they came from."
      },
      {
        "type": "changed",
        "text": "Patterns: the regex builder and the log parsers are now one page with two tabs."
      },
      {
        "type": "added",
        "text": "The Decoder, Certificates and Cloud guide keep your recent input too, if tool history is on in Settings."
      },
      {
        "type": "added",
        "text": "More save buttons have the ▾ to pick any case or make a new one."
      },
      {
        "type": "added",
        "text": "If something on a page fails, a notice says so and has a “Copy details” button for bug reports."
      },
      {
        "type": "fixed",
        "text": "The graph could stop responding to the mouse after adding from evidence, until you clicked elsewhere. It now keeps working."
      }
    ]
  },
  {
    "version": "1.77",
    "name": "Save to any case",
    "date": "2026-11-24",
    "summary": "Pick where things go, and clear tools in one click.",
    "changes": [
      {
        "type": "added",
        "text": "The ▾ beside a save button lists every case and “New case…”."
      },
      {
        "type": "added",
        "text": "Investigate and Decode tools have Clear. They can also keep your last 10 searches, which is off by default."
      },
      {
        "type": "changed",
        "text": "Look-alikes lists candidates at once. Page hash shows what a saved page loads and where it sends data. Hashes decodes what can be decoded."
      },
      {
        "type": "fixed",
        "text": "Layout fixes in Entities and Settings."
      }
    ]
  },
  {
    "version": "1.76",
    "name": "WinForensicX hand-off",
    "date": "2026-11-24",
    "summary": "Move indicators between OSINTrix and WinForensicX.",
    "changes": [
      {
        "type": "added",
        "text": "Import the STIX file that WinForensicX exports. You can add its indicators to a case as well."
      },
      {
        "type": "added",
        "text": "Export a hunt list that Invoke-WfxHunt -IocFile reads."
      },
      {
        "type": "fixed",
        "text": "A file entry with an MD5 or SHA-1 is filed as that hash, so it joins the same hash found in records."
      }
    ]
  },
  {
    "version": "1.60–1.75",
    "name": "Forensics kit and tradecraft",
    "date": "2026-11-24",
    "releases": 16,
    "summary": "Tools for the files and accounts an investigation turns up.",
    "changes": [
      {
        "type": "added",
        "text": "Forensics kit: documents, web captures, browser profiles, stealer logs, phishing kits, chat exports. Each is read and summarised."
      },
      {
        "type": "added",
        "text": "Wallet trails, now with Solana, from pasted text or files."
      },
      {
        "type": "added",
        "text": "Personas with an OPSEC check and a log, plus onion pages and Web3 identifiers."
      },
      {
        "type": "added",
        "text": "Linked notebook, note reminders, and cases kept in files."
      },
      {
        "type": "changed",
        "text": "A design pass across every screen."
      }
    ]
  },
  {
    "version": "1.40–1.59",
    "name": "Reading evidence like an analyst",
    "date": "2026-11-23",
    "releases": 20,
    "summary": "Better reading of indicators and logs, and room for big cases.",
    "changes": [
      {
        "type": "added",
        "text": "Regex builder, plus masking for anything you share."
      },
      {
        "type": "added",
        "text": "Endpoint evidence, certificates, cloud logs and detection rules, each checked against your cases."
      },
      {
        "type": "added",
        "text": "Case snapshots, saved views and @ links in notes."
      },
      {
        "type": "changed",
        "text": "Large vaults and graphs stay workable."
      }
    ]
  },
  {
    "version": "1.12–1.39",
    "name": "Cases, intel and the engine",
    "date": "2026-11-15",
    "releases": 28,
    "summary": "The core of the workspace.",
    "changes": [
      {
        "type": "added",
        "text": "Threat Intel feeds, the investigation engine, Copilot and graph analysis."
      },
      {
        "type": "added",
        "text": "Certificates, Cloud, the Notebook, media in cases and the detection lab."
      },
      {
        "type": "changed",
        "text": "A new design and a cases board."
      },
      {
        "type": "fixed",
        "text": "Hardened storage and a faster start, so nothing is lost on reload or when space runs low."
      }
    ]
  },
  {
    "version": "0.x–1.11",
    "name": "The beginning",
    "date": "2026-10-08",
    "releases": 13,
    "summary": "ThreatNet and Clew merged into one offline workspace.",
    "changes": [
      {
        "type": "added",
        "text": "Toolbox, timeline-based cases, entity extraction, the graph and the map."
      },
      {
        "type": "added",
        "text": "Playbooks, pivots, exports, the Lab and a CTF area."
      },
      {
        "type": "added",
        "text": "Search across everything, chain of custody and a safety net for your data."
      }
    ]
  }
];
