/* Release history — the single source of truth for both the in-app "What's new"
   page and CHANGELOG.md (run tools/changelog.py to regenerate the file).
   Plain JSON after the "=", like the other data files. Newest first.
   Each change has a type: "added" | "changed" | "fixed" | "removed". */
const CHANGELOG_DATA = [
  {
    "version": "1.77",
    "name": "Save to any case, clearer tools",
    "date": "2026-11-24",
    "summary": "Everything you save can go to any case or a new one; every Investigate and Decode tool has Clear and, if you switch it on, its last 10 searches; Look-alikes lists candidates at once; Page hash shows what a saved page sends and to whom; Hashes takes apart and decodes what can be decoded.",
    "changes": [
      {
        "type": "added",
        "text": "The ▾ beside a save button lists every case and “New case…”, which makes the case with just a name and keeps you on the tool you were using. The ▾ is now beside the save buttons that lacked it: Identity usernames, Coordinates, Page hash, Phishing kit, Stealer log, Browser profile, Detections (“Test against”), the detection lab, Entities personas, Investigate “Add all”, Cloud, Scratchpad and the money trail."
      },
      {
        "type": "changed",
        "text": "Query library: the tick box and arrow are one labelled choice, “Record the search in”: any case, nowhere, or a new case."
      },
      {
        "type": "added",
        "text": "Every Investigate and Decode tool has Clear. Settings → Data → “Search history in tools” (off unless you turn it on) lists the last 10 things you looked up in each tool above it; turning it off forgets them. A search is kept when you press Enter or leave the box, not on every keystroke."
      },
      {
        "type": "changed",
        "text": "Look-alikes: Generate shows every candidate straight away, marked not checked; after checking, switch between the ones that exist and all of them. A whole row opens Investigate (mouse or Enter). Watched domains are a list with when each was checked and how many existed, and each can be dropped."
      },
      {
        "type": "added",
        "text": "Page hash → “What the page loads and sends” reads the saved page like a kit analyst: what stands out (credentials or card details sent to another site, Telegram, Discord or form-relay drops, IP and location checks, anti-analysis, hidden code, frames), each form with where it sends and which fields it asks for, the calls in its scripts, every site it talks to with what each is, redirects, and the favicon as a picture with its Shodan hash when it is written into the page. Bot tokens and webhook keys are hidden. A page with none of this says so."
      },
      {
        "type": "fixed",
        "text": "Page hash: a favicon written into the page with quotes inside it was cut short, and the browser's own “saved from url=…” note was offered as a FOFA query — it can contain a path on your computer. It is no longer a comment or a query."
      },
      {
        "type": "added",
        "text": "Hashes: crypt and capture strings are taken apart (bcrypt cost and salt, SHA-crypt rounds, Argon2 memory and threads, phpass iterations, the user and domain of NetNTLM, the account, realm and SPN of a Kerberoast ticket, the network name in a WPA capture), base64 and LDAP {SHA}/{SSHA} digests are shown as hex with hash lookups, JWTs are decoded with their dates, and hex or base64 that is really text is shown as text. 40 more formats with their hashcat modes: Office, PDF, ZIP, 7-Zip, RAR, KeePass, WPA, DCC2, Cisco 8/9, Drupal, PostgreSQL, MSSQL, Oracle, macOS, Atlassian, wallets, DPAPI, SSH and GPG keys and others."
      },
      {
        "type": "added",
        "text": "Toolbox → Add a tool: “Something else” names your own lookup type (IBAN, Telegram ID, licence plate…). When it is something OSINTrix picks out of evidence, the tool shows up under Look up for it."
      },
      {
        "type": "fixed",
        "text": "Entities: persona cards kept the long “Make a profile in …” button inside the card and the reasons under each tie readable; Settings: no gap above Storage."
      }
    ]
  },
  {
    "version": "1.76",
    "name": "WinForensicX hand-off",
    "date": "2026-11-24",
    "summary": "Indicators you tick in a WinForensicX case report import as one batch with the finding, host and TLP they came from; any set of indicators exports as a hunt list WinForensicX runs on a host; and a hash filed in a case now joins the same hash in records.",
    "changes": [
      {
        "type": "added",
        "text": "Threat Intel → Indicators → Export: “Hunt list for WinForensicX (.txt)”. One value per line under a commented header (source, date, TLP, count, the command to run), for Invoke-WfxHunt -IocFile. Only what a Windows host can show goes in: addresses, domains, URLs, emails and hashes; CVEs, ASNs and wallets stay here. Works for the shown list, the whole library or one case."
      },
      {
        "type": "added",
        "text": "Import indicators: “Also add them to <the open case>” files the imported indicators in the case, each with its description as the note (for a WinForensicX export, the host and finding it came from). Off unless you tick it; re-importing never files anything twice."
      },
      {
        "type": "changed",
        "text": "After an import, the indicator list shows just that import (filtered by its source), so a batch can be read, exported or added to a case on its own."
      },
      {
        "type": "fixed",
        "text": "A file entry in a case holding an MD5 or SHA-1 was treated as a SHA-256, so it never joined the same hash found in records or indicator feeds, and its verdict sat on the wrong key. Hashes are now named by their length, and verdicts, watches and research notes saved under the old key move across when the app opens."
      }
    ]
  },
  {
    "version": "1.75",
    "name": "Design pass across every screen",
    "date": "2026-11-24",
    "summary": "A screen-by-screen check of the desktop app in light and dark: pages no longer scroll as a whole, a stray bold no longer spreads across a case overview, wide tables scroll instead of cutting columns off, and several pages get clearer starting points.",
    "changes": [
      {
        "type": "fixed",
        "text": "Pages could scroll as a whole, carrying the top bar away, because hidden screen-reader labels stretched the page. They are now pinned in place."
      },
      {
        "type": "fixed",
        "text": "An unclosed bold tag in the case overview's connections card, the wallet view and hunts made everything after it bold."
      },
      {
        "type": "fixed",
        "text": "Case overview: the connections card now sits after the stats and case progress instead of between them, and vault entries that match an indicator are no longer listed twice."
      },
      {
        "type": "fixed",
        "text": "The case Entities table, Watchlist and area tables scroll sideways when narrow instead of cutting off columns; long entity values wrap instead of widening the table."
      },
      {
        "type": "fixed",
        "text": "Detections IDE no longer shows a tall empty gap above the editor (a class name it shared with the regex builder)."
      },
      {
        "type": "fixed",
        "text": "Times like “last 3 d ago ago” in the Toolbox details, backup status, reference sources and saved regex patterns now read once."
      },
      {
        "type": "fixed",
        "text": "The log parser's one-line summary no longer starts a wrapped row with a stray separator."
      },
      {
        "type": "changed",
        "text": "Forensics kit → Identity offers example values to try, and Look-alikes offers the open case's domains as one-click starting points."
      },
      {
        "type": "changed",
        "text": "The Regex builder title matches every other page; the Settings buttons have room under the tagline; Toolbox rows show nothing instead of a bare dash for tools never opened; news items you wrote no longer carry a coloured edge."
      }
    ]
  },
  {
    "version": "1.74",
    "name": "Clean before sending, AI generator traces, scam playbooks",
    "date": "2026-11-24",
    "summary": "Forensics kit → Clean before sending takes your camera, location, name, company and folders out of photos and documents and proves it by reading the copy back; pictures made with AI now show the prompt, model, LoRAs and seed the generator left inside; a VIN decoder; and six new playbooks for sextortion, romance and investment scams, deepfakes and voice clones, SIM swaps, missing people and people being doxxed.",
    "changes": [
      {
        "type": "added",
        "text": "Forensics kit → Clean before sending: drop the photos and documents you are about to send. JPEG, PNG and WebP lose EXIF, GPS, XMP, IPTC, comments, Content Credentials and data hidden after the picture, while every pixel stays byte for byte the same and a turned photo keeps its turn. PDFs lose their properties, XMP packet and file IDs in place, so the document is unchanged. Word, Excel and PowerPoint files lose author, last editor, company, manager, template, editing time, custom properties, the preview thumbnail, editing-session IDs and folder paths, and comment and change authors become “Author”."
      },
      {
        "type": "added",
        "text": "Clean before sending reads each clean copy back with the same metadata reader and shows what is left, gives its SHA-256, and says what it cannot fix: tracked deletions, comments, hidden sheets, white text, speaker notes, earlier PDF versions. Clean copies can get plain names (photo-1.jpg). Videos, HEIC and other formats are refused with what to use instead. The OPSEC panel on the Tradecraft page links to it."
      },
      {
        "type": "added",
        "text": "AI generation, in the File inspector and Image tools: the prompt, negative prompt, model and model hash, VAE, LoRAs, seed, sampler, steps and size written by AUTOMATIC1111, Forge, ComfyUI (from the workflow graph), Fooocus, InvokeAI and NovelAI — in PNG text or a JPEG's EXIF comment — the Midjourney prompt, version, account and Job ID, the IPTC “made by a trained algorithm” mark and the generator named in Content Credentials. Models and LoRAs link to Civitai, by hash where the file gives one; a LoRA named after a person is called out."
      },
      {
        "type": "added",
        "text": "Forensics kit → Time & IDs reads a VIN: maker, country, the check digit (with what it should be when it is wrong), the model year, the plant code and the serial, with links to the NHTSA decoder and the NICB stolen-vehicle check."
      },
      {
        "type": "added",
        "text": "Playbooks: Sextortion (victim safety, Take It Down, StopNCII, tracing the payment demand — and never copying the images into the case), Romance and investment scam (pig butchering), Deepfake, AI image and voice-clone check, SIM swap and phone-number takeover, Missing person, and Protect someone who is being harassed or doxxed."
      }
    ]
  },
  {
    "version": "1.73",
    "name": "Web captures and browser profiles",
    "date": "2026-11-24",
    "summary": "The File inspector reads web captures — HAR recordings, WARC and WACZ web archives and saved MHTML pages — and a new Browser profile tool reads a whole Chrome, Edge, Brave, Firefox or Safari profile into one timeline, including what only its -wal files held.",
    "changes": [
      {
        "type": "added",
        "text": "File inspector → web captures: a HAR (developer tools → Network → export), a WARC or WARC.GZ, a WACZ (ArchiveWeb.page, Browsertrix) or an MHTML (Save page as → single file) shows the redirect chain the visit went through — 3xx answers, Refresh headers, meta refresh and script redirects — with each server's IP."
      },
      {
        "type": "added",
        "text": "Web captures: what the page sent and where — form posts, JSON and query strings — with passwords, card numbers, codes and bot tokens masked. Logins and card details sent to another site, Telegram bot and Discord webhook drops, form relays and Google Apps Script endpoints are called out."
      },
      {
        "type": "added",
        "text": "Web captures: every site contacted, marked as the page itself, analytics, captcha, CDN, free hosting, IP and location lookups (the checks kits use to hide from researchers) or drops, with request counts, IPs and server software; the cookies set; files the page handed out, each opened in the inspector with one click."
      },
      {
        "type": "added",
        "text": "Web captures: the landing page's Shodan page hash and the favicon's hash, analytics and ad IDs, form targets and Telegram handles, with the Shodan, FOFA, urlscan and PublicWWW queries to find sibling sites. A form that asks for a wallet recovery phrase or sends to another site is flagged."
      },
      {
        "type": "added",
        "text": "Forensics kit → Browser profile: drop a profile folder, a ZIP of it or some of its files. The signed-in account and sync address, every visit, search and text typed in the address bar, downloads with the full chain of addresses they came from and whether they were opened, saved-login sites with user names, form entries, saved names, addresses and cards, bookmarks, extensions and the sites that set cookies — on one timeline you can filter, with the hours of the day the browser was used."
      },
      {
        "type": "added",
        "text": "Browser profile: a -wal file next to a database is replayed, and the tool says what only the -wal held (for example 3 visits, 1 download and 1 search) — the newest activity, which tools that open only the main file miss."
      },
      {
        "type": "added",
        "text": "Browser profile: what stands out — searches about wiping or hiding traces, file-sharing and paste sites, private or throwaway mail, programs and archives downloaded, extensions loaded outside the store or able to read every site, and history that starts long after the profile was made."
      },
      {
        "type": "added",
        "text": "Browser profile: save it to the case as one record with its indicators (accounts, e-mails, phones, download sources), send every event to the case timeline, or download the timeline as CSV. Passwords, cookie values and card numbers stay encrypted and are never read; codes typed into forms are masked."
      },
      {
        "type": "changed",
        "text": "Playbooks: brand phishing now records the visit as a HAR or web archive and reads it back; browser and phone artefacts start with the Browser profile tool."
      },
      {
        "type": "fixed",
        "text": "Notebook graph: the zoom-out button and the “create page” suggestion had no icon."
      }
    ]
  },
  {
    "version": "1.72",
    "name": "Linked notebook and note reminders",
    "date": "2026-11-24",
    "summary": "The Notebook now links like Obsidian: type [[ to link another page, a case, evidence, an indicator, a note, a detection or a playbook, see which pages link back, turn plain mentions into links, and look at all your pages as a graph. Notes take a date, a time and a reminder when you create them.",
    "changes": [
      {
        "type": "added",
        "text": "Notebook: type [[ in a page to link another page. A list of matching pages comes up as you type; Enter or Tab picks one. Typing [[Title]] in full links it straight away, and [[Title|other words]] shows other words."
      },
      {
        "type": "added",
        "text": "Notebook: a link to a page that does not exist yet is shown dashed and creates the page when clicked. Links are kept by page, so renaming a page keeps every link and shows the new title."
      },
      {
        "type": "added",
        "text": "Notebook: the same [[ list links cases, evidence, indicators, vault entries, notes, detections and playbooks. [[case:, [[ioc:, [[note:, [[rule: and [[playbook: narrow it, and an IP, domain, hash or URL typed after [[ links even before any case has it. Clicking one opens it where it lives; an indicator no case has yet opens a lookup."
      },
      {
        "type": "added",
        "text": "Notebook side panel: “Linked from” lists the pages that link to this one with the line each link sits in, “Mentioned in” lists pages that name this page without linking it, with a Link button that makes the mention a link, and “Links on this page” lists where this page points."
      },
      {
        "type": "added",
        "text": "Notebook side panel: indicators written on a page that are already in one of your cases are listed, and open in Entities."
      },
      {
        "type": "added",
        "text": "Notebook graph: every page as a dot and every link as a line, by notebook, with or without the cases, evidence and indicators pages link to. Hover a page to see its neighbours, click to open it, drag to move around, scroll or use the buttons to zoom. Open it from the Graph button in the library or the page list."
      },
      {
        "type": "added",
        "text": "Notebook: Markdown export writes page links as [[Title]], and imported Markdown with [[Title]] or [[Title|alias]] links up to the pages with those titles, so notes move to and from Obsidian."
      },
      {
        "type": "added",
        "text": "Notes: the quick-add form takes a due date, a time and a Remind me switch, so a new note no longer has to be opened again to get a date. The edit window has the time and the switch too."
      },
      {
        "type": "added",
        "text": "Notes: at the due time a reminder shows in the app and, if you allow it, as a system notification. A reminder missed while the app was closed shows when you come back, saying when it was due."
      },
      {
        "type": "changed",
        "text": "Notes and Today: a note with a time is overdue from that time instead of from the end of the day, and its card and the Today list show the time with a bell when a reminder is set."
      }
    ]
  },
  {
    "version": "1.71",
    "name": "Documents and delivery files",
    "date": "2026-11-24",
    "summary": "The File inspector now takes documents and delivery files apart: earlier PDF versions with the text a later save removed, tracked changes and hidden text in Office files, e-mail and Outlook messages with their attachments, and ISO, OneNote and RAR files with what is inside.",
    "changes": [
      {"type": "changed", "text": "Threat Intel → Investigate: the sources that answered get the width, sources that are off are one compact list with what each would add, and lists such as name servers show one name per line instead of breaking inside a name."},
      {"type": "added", "text": "Threat Intel → Investigate: a Clear button empties the current investigation; pressing Investigate on the indicator already shown asks the sources again instead of only showing the saved answers."},
      {"type": "fixed", "text": "Threat Intel: a story panel opened on one tab now closes when you switch tab, so it no longer lingers over Overview and swallowing the next clicks — one click opens a story."},
      {"type": "fixed", "text": "Threat Intel → Sources: the dialog fits the window with one scroll — the tabs and Done stay in view instead of a second scrollbar inside a dialog cut off at the bottom."},
      {
        "type": "added",
        "text": "PDF: every earlier version kept by incremental saves opens on its own, with the lines that were in an earlier version but not the last one — text removed or “redacted” by editing; embedded files (each opens on its own), JavaScript, form fields, fonts and signatures."
      },
      {
        "type": "added",
        "text": "Word, Excel, PowerPoint: tracked deletions and insertions with who and when, hidden and white or tiny text, comments, the people list with the account behind each commenter, custom properties, editing sessions, hidden and very hidden sheets, hidden named ranges, linked workbooks on file shares, speaker notes, hidden slides, and pictures inside (each opens with its own metadata)."
      },
      {
        "type": "added",
        "text": "E-mail (.eml) and Outlook (.msg) messages: sender, reply-to and bounce address, failed SPF/DKIM/DMARC, links that show one address and go to another, the public IPs on the route, risky attachment types, and every attachment decoded to inspect on its own; the headers open in the Email headers tool."
      },
      {
        "type": "added",
        "text": "Delivery files: ISO and IMG disk images (volume, the program that made them and its time zone, hidden files, each file opens on its own), OneNote notebooks (embedded scripts and HTA files), and RAR 4 and 5 archives (entries, encrypted files or names, the system they were packed on)."
      },
      {
        "type": "fixed",
        "text": "A link followed by a pipe in a command line (iwr http://…/p.ps1|iex) no longer takes the pipe into the address."
      }
    ]
  },
  {
    "version": "1.70",
    "name": "Forensics kit, advanced",
    "date": "2026-11-24",
    "summary": "The File inspector and Image tools read far deeper — every metadata format, how a JPEG was written, the hidden thumbnail, the sun, copied areas, shortcuts, build fingerprints, who packed an archive — and five new tools: phishing kits, stealer logs, favicon and page hashes, company footprint, and dates inside IDs.",
    "changes": [
      {
        "type": "added",
        "text": "File inspector: the full metadata reader (EXIF, XMP, IPTC, HEIC, PNG, WebP, MP4/MOV, MP3, PDF, Word/Excel old and new) with what stands out on top; picture forensics — JPEG quantisation tables (quality and whether a library, a camera or Photoshop wrote it), chroma sampling, segments, colour profile, Facebook and Photoshop markers, the EXIF thumbnail compared with the picture (cropped or replaced after capture), what the file name says (WhatsApp, Telegram, Pixel, screenshots…), and where the sun was at the GPS time and place."
      },
      {
        "type": "added",
        "text": "File inspector: Windows shortcuts (target, arguments, the NetBIOS name, MAC address and its maker, volume serial of the machine that made them); Windows programs — imphash, Rich header hash, PDB path and the developer's user name, version information, resource language, exports, overlay, TLS callbacks, writable-and-executable sections, signature, with VirusTotal and MalwareBazaar pivots; Linux programs — libraries, compiler, Go version and module, build IDs; ZIP archives — the OS, Unix user and group and the time zone of whoever packed it, and any file inside opens on its own."
      },
      {
        "type": "added",
        "text": "File inspector: strings sorted by kind (links, paths, registry, commands, keys and tokens, wallets, Base64 with a decode link, build traces) and a hex viewer over the whole file with paging, go-to-offset and find (text or hex)."
      },
      {
        "type": "added",
        "text": "Image tools: noise, levels and copy-move views (pasted patches found even after JPEG saving and resizing, with no false alarm on our 18 test photos), zoom to 1:1, 2× and 4×, a histogram that shows clipping and stretched tones, and the metadata and picture-forensics cards. HEIC pictures the browser cannot draw still show everything read from the file."
      },
      {
        "type": "added",
        "text": "Forensics kit → Phishing kit: drop a kit's ZIP or files — Telegram bot IDs and chat IDs, Discord webhooks, drop emails, SMTP accounts, log files and panels it sends victims to, the brand it imitates, the anti-bot and geo-filtering tricks, obfuscated code, author credits, and every YARA rule run over every file."
      },
      {
        "type": "added",
        "text": "Forensics kit → Stealer log: RedLine, Lumma, Vidar and similar logs read into infected machines (user, computer, HWID, IP, build tag, where it ran from) and their saved logins and session cookies, with your domains and sign-in or VPN hosts marked. Passwords stay masked and are never saved to the case."
      },
      {
        "type": "added",
        "text": "Forensics kit → Favicon & page hash: the Shodan favicon and html_hash values, MD5 and SHA-256 of a favicon or saved page, plus the Google Analytics, Tag Manager, AdSense, Meta pixel and Yandex Metrica IDs, forms, scripts and kit comments in it — each with the Shodan, FOFA, ZoomEye, Censys, urlscan or PublicWWW query ready to open."
      },
      {
        "type": "added",
        "text": "Forensics kit → Company footprint: mail provider and filtering, the SaaS a company verified, who may send mail as it (SPF, DKIM selectors), DMARC policy and reporters, Microsoft 365 and federation hints, CAA, and every host name in its certificates (CertSpotter) with the staging, admin and VPN ones flagged."
      },
      {
        "type": "added",
        "text": "Look-alikes remember each domain they checked: the next check marks the ones that are new, shows certificates issued to them (CertSpotter), and lists watched domains for a one-click re-check."
      },
      {
        "type": "added",
        "text": "Dates inside IDs: Bluesky post keys, Slack message links and Discord user links are dated in Time & IDs; a Discord account imported from a chat export shows when it was made and how long before its first message, and Infrastructure → Chats lists the accounts made just before they posted."
      },
      {
        "type": "changed",
        "text": "Playbooks for stealer logs, phishing kits, drainer sites and company footprints now point to the new tools."
      }
    ]
  },
  {
    "version": "1.69",
    "name": "More queries, rules and tricks",
    "date": "2026-11-23",
    "summary": "A bigger toolbox on the OSINT, cloud and detection sides: 72 investigation queries and five more search engines, 87 new detection rules, a cloud OSINT section in the field guide, four reference tables, two Tradecraft chapters and four playbooks.",
    "changes": [
      {
        "type": "added",
        "text": "Queries: 72 investigation queries — infrastructure pivots (favicon hash, JARM, SSH host key, certificates, page body and title, analytics IDs, reverse IP), threat hunting (Cobalt Strike, GoPhish, open directories, C2 panels), cloud exposure (buckets, Firebase, SharePoint, Docker, Kubernetes, Terraform state), leaks, Telegram, Discord and WhatsApp, people and handles, wallets and onions. They are added once to existing libraries; a query you delete stays deleted."
      },
      {
        "type": "added",
        "text": "Five more engines for queries: urlscan.io, crt.sh, PublicWWW, grep.app and Yandex — and three new categories: Infrastructure pivots, Threat hunting, and Telegram, Discord & chat."
      },
      {
        "type": "added",
        "text": "Detections: 72 Sigma rules — AWS (CloudTrail stopped, Bedrock LLMjacking, Roles Anywhere, public RDS snapshots, domain transfer), Entra and Azure, Exchange, Okta (session roaming, impersonation), Google Cloud, Google Workspace (domain-wide delegation), GitHub, Kubernetes, chat-platform and blockchain C2 in proxy and DNS logs, ClickFix, WebDAV and search-ms lures, cloud metadata theft on Linux, and macOS stealers."
      },
      {
        "type": "added",
        "text": "Detections: 15 YARA rules — Discord webhook and Telegram bot exfiltration, dead-drop resolvers, Chrome app-bound key theft, ClickFix pages, EtherHiding loaders, wallet drainers, Evilginx phishlets, cloud credential harvesters, leaked AWS keys, private keys and SaaS tokens, stealer-log files and phishing kits that report to Telegram."
      },
      {
        "type": "added",
        "text": "Cloud → Field guide → Cloud OSINT, outside in: Microsoft 365 tenant from a domain, the SaaS stack from DNS, AWS account ID from a key or bucket, public snapshots, Azure and Google Cloud names, which cloud an IP belongs to, the real server behind a CDN, and identity providers — each says what the owner can see of your lookup."
      },
      {
        "type": "added",
        "text": "Reference: platform IDs and the creation time inside them (Discord, X, LinkedIn, Instagram, TikTok, Mastodon, Bluesky, GitHub and more), cloud and SaaS key formats, Okta System Log events, and Google Workspace and GitHub audit events."
      },
      {
        "type": "added",
        "text": "Tradecraft: two chapters — Tricks that save hours (search engines, archives, identifiers, images, infrastructure history) and From findings to detections."
      },
      {
        "type": "added",
        "text": "Playbooks: company cloud footprint from outside, company accounts in info-stealer logs, adversary-in-the-middle phishing and session theft, and crypto drainer sites."
      }
    ]
  },
  {
    "version": "1.68",
    "name": "Chats & forwards, and names over time",
    "date": "2026-11-23",
    "summary": "The network behind the chats you import — where they forward from, posts pushed into several chats within minutes, the same words from different accounts, clusters — and every name a Telegram or Discord account went by.",
    "changes": [
      {
        "type": "added",
        "text": "Infrastructure → Chats: a forward map (sources → your chats, width by forwards), every source with its forwards, chats reached, first and last time and whether it appears in your other cases; coordinated pushes — one post in several chats, forwarded or copy-pasted, with how far apart and which chat had it first; texts sent word for word by different accounts; clusters of chats that share sources; and which chat tends to post first."
      },
      {
        "type": "added",
        "text": "Names over time: a Telegram or Discord account's panel lists every name and username it went by in your exports, in order, with when and where — and Infrastructure → Chats lists the accounts that changed name."
      },
      {
        "type": "changed",
        "text": "Chat exports keep each message's source, links and a fingerprint of its words (not a second copy of the text) for this analysis; the Telegram channel playbook points to it."
      },
      {
        "type": "fixed",
        "text": "On a busy or slow computer a video's size and preview could be skipped because the player took over 6 seconds to open it; it now waits up to 15."
      },
      {
        "type": "changed",
        "text": "Text that cannot hold an ENS name, a Telegram or Discord number, or a long hex value skips those checks — reading indicators out of large text is back to its earlier speed."
      }
    ]
  },
  {
    "version": "1.67",
    "name": "Chat exports, and playbooks for scammers and actors on chat platforms",
    "date": "2026-11-23",
    "summary": "Telegram and Discord exports become one record per author with their permanent account number; four playbooks and a Tradecraft chapter cover scammers, Discord, actors on chat platforms, and bots or webhooks found in malware.",
    "changes": [
      {
        "type": "added",
        "text": "Drop a Telegram Desktop export (result.json) or a DiscordChatExporter JSON into Capture: each author becomes a record with their messages and their permanent account number — Telegram user ID or Discord ID, which stay the same when names change — and the post times go to Active hours. Service messages are left out; channel posts are marked as the channel's."
      },
      {
        "type": "added",
        "text": "Telegram and Discord IDs are indicators. A Discord ID's profile shows when the account, server or channel was created (read from the ID itself) and flags ones made in the last 30 days."
      },
      {
        "type": "added",
        "text": "The same Telegram or Discord account in two cases ties them as a persona; names an author mentions in their messages are not taken for the author. Writing can be compared between chat authors."
      },
      {
        "type": "added",
        "text": "Playbooks: Scammer on Telegram, Discord or WhatsApp; Discord server and user investigation; Threat actor on chat platforms; Telegram bot or Discord webhook found in malware."
      },
      {
        "type": "added",
        "text": "Tradecraft → Telegram, Discord and other chats: what each platform reveals (permanent IDs, forwards, Fragment usernames, snowflake dates, invites and widgets, connected accounts), what it shows about you, and the lines not to cross — never using a bot token or webhook found in malware, never buying or downloading stolen data, never baiting without authority."
      }
    ]
  },
  {
    "version": "1.66",
    "name": "Solana trails from files, and writing compared",
    "date": "2026-11-23",
    "summary": "Solana wallets get a money trail from transfers you export from an explorer, and two names' writing can be compared as supporting evidence — ranked against every other writer in your evidence.",
    "changes": [
      {
        "type": "added",
        "text": "Solana in the money trail: import a wallet's transfers exported as CSV (e.g. from Solscan) — raw amounts are read with their decimals column, SOL and tokens are kept apart, wallets go into the vault with Solana as their currency. Nothing is fetched: the public Solana endpoint refuses browser requests and the alternatives need an account key, so the panel says so instead of offering a button that would fail."
      },
      {
        "type": "added",
        "text": "Writing compared (a handle's panel → Compare its writing with…, or Compare writing on a persona): letter patterns, the small words a writer leans on, and habits — punctuation, capitals, British or American spelling, dropped apostrophes, misspellings, shorthand — per 1,000 words, with the phrases both use."
      },
      {
        "type": "added",
        "text": "The result is ranked against every other writer in your evidence with 250+ words (“closer than 4 of 4 others”); with fewer than three others no ranking is given. Indicators are taken out first, too little text says nothing, and the dialog says plainly it is supporting evidence only."
      }
    ]
  },
  {
    "version": "1.65",
    "name": "OPSEC you can check, and a persona log",
    "date": "2026-11-23",
    "summary": "Tradecraft now shows what this browser tells every site, read locally, and keeps a log of which research persona looked at what. A 10,000-record case was timed screen by screen; the graph no longer rebuilds itself on every change.",
    "changes": [
      {
        "type": "added",
        "text": "What this browser tells every site (Tradecraft): time zone, languages, screen and window, platform, WebRTC — and whether it gives away a local address — and a canvas fingerprint, all read here with nothing sent. A language that does not fit the time zone, many languages, and WebRTC left on are called out; the public address is left to a leak test, as it cannot be seen from inside the page."
      },
      {
        "type": "added",
        "text": "The readiness check shows what the browser itself says next to the WebRTC and time-zone points."
      },
      {
        "type": "added",
        "text": "Your research personas (Tradecraft): each persona's name, platforms and where it connects from — never passwords — and a log of each use: case, platform, what was looked at. Warns when a persona touches three or more cases, is used ten or more times on one case in a week, or wakes after two months; a burned persona is kept as a record and cannot be logged again."
      },
      {
        "type": "changed",
        "text": "The case graph keeps its drawing when the page re-renders with the same data — a 2,000-node graph re-rendered in about 0.3 s instead of 1.6 s."
      },
      {
        "type": "added",
        "text": "A 10,000-record case is built in the tests and every case tab, the main pages, saving and moving it to a file must stay within a time limit."
      }
    ]
  },
  {
    "version": "1.64",
    "name": "Tradecraft, onion pages and personas",
    "date": "2026-11-23",
    "summary": "A field guide for investigating without being seen and for running an actor investigation; pages saved from Tor Browser read as dark-web pages; and personas found across cases from the identifiers operators keep.",
    "changes": [
      {
        "type": "added",
        "text": "Tradecraft (sidebar → Kit): your threat model, the research environment (VMs, Whonix, Tails, Qubes, VPN, Tor, residential egress, leak tests, browser hardening, handling subject files), research personas from building to retiring, starting an actor investigation, a pivot table (what to pivot on, where, and how much it says), finding the human behind infrastructure, and attribution you can defend. Searchable, works offline; points done in the app open where they are done."
      },
      {
        "type": "added",
        "text": "A readiness check before each session — VM, egress, leaks, accounts, time zone, files, logging, authorisation — kept in the workspace and cleared for a new session."
      },
      {
        "type": "added",
        "text": "Four playbooks to run on a case: Investigation environment & OPSEC, Research persona lifecycle, Actor investigation from one indicator, Finding the operator behind the infrastructure."
      },
      {
        "type": "added",
        "text": "Pages saved from Tor Browser are read as dark-web pages: the onion site from where its links point (Tor Browser records no address), the profile the page is about, the profiles it links, mirrors and other onions, signed messages, prices — titled “Onion page:” and tagged darkweb."
      },
      {
        "type": "added",
        "text": "Session and Tox messenger IDs are recognised (a Tox ID's checksum is checked); neither is taken for a file hash."
      },
      {
        "type": "added",
        "text": "Personas across your evidence (Entities): names that share a PGP key, wallet, email, phone or messenger ID, across cases, with what ties them and where. A username alone never ties names, and a page that names many people ties none. Make a profile in the open case in one step: a Person linked to every identifier, the PGP key with its names and emails."
      },
      {
        "type": "added",
        "text": "A new vault type, PGP key, with its fingerprint, the names and emails on it and when it was made."
      }
    ]
  },
  {
    "version": "1.63",
    "name": "Cases kept in files",
    "date": "2026-11-23",
    "summary": "An archived case can move out of the browser into one file on your computer — checked byte for byte before anything is removed — and come back whole from it. Plus a phone and tablet pass.",
    "changes": [
      {
        "type": "added",
        "text": "Move to a file (case menu, or Settings → Storage for archived cases, biggest first): the case is saved as one file — encrypted when the workspace is — then you pick the file back, it is compared byte for byte with what was saved, and only then are its entries, records, notes, links and attached files removed here."
      },
      {
        "type": "added",
        "text": "A case kept in a file keeps its card: name, scope, counts, size, the file's name and SHA-256. Its indicators are still matched — an indicator it shares says “Also in a case kept in a file”."
      },
      {
        "type": "added",
        "text": "Bring it back from its card by picking the same file: everything returns under the same ids, attached files included. A copy that has changed since is shown as such before it is brought back."
      },
      {
        "type": "changed",
        "text": "On a phone, a case's four actions (more, edit, entry, capture) sit on one row."
      },
      {
        "type": "fixed",
        "text": "Every page and case tab is checked to fit phone and tablet widths."
      },
      {
        "type": "fixed",
        "text": "Reading key=value logs with a very long field took about half a second per line; it now takes a few milliseconds."
      }
    ]
  },
  {
    "version": "1.62",
    "name": "Web3 and dark-web identifiers",
    "date": "2026-11-23",
    "summary": "ENS names, Solana addresses and signatures, Bitcoin and Ethereum transactions, Tor onion addresses and PGP keys are recognised, checked offline, and each leads somewhere.",
    "changes": [
      {
        "type": "fixed",
        "text": "A Bitcoin transaction ID is no longer taken for a SHA-256 file hash when it sits next to “tx”, “txid”, “transaction” or a block-explorer link; a hash found next to payment words offers to be read as a transaction."
      },
      {
        "type": "added",
        "text": "New indicators: ENS names (name.eth), Solana addresses and transaction signatures (checked as base58 keys of 32 and 64 bytes), Ethereum transaction hashes and Bitcoin transaction IDs."
      },
      {
        "type": "added",
        "text": "A Bitcoin or Ethereum transaction can be fetched on its own (mempool.space, eth.blockscout.com, asking first): when, block, status, fee, every input and output with amounts, tokens moved — and its wallets go into the case in one step. The answer is kept as evidence."
      },
      {
        "type": "added",
        "text": "An ENS name resolves to its Ethereum wallet through Blockscout, with the registration expiry (an expired name can be taken by anyone); the result is kept as evidence and the wallet can be added to the case."
      },
      {
        "type": "added",
        "text": "Tor onion addresses: version, checksum (a typo or made-up address fails it), v2 addresses called out as dead, other onions in your cases that start the same way (a vanity mirror or a phishing copy), and onions listed together in one text. Ahmia is the only pivot offered; nothing is looked up."
      },
      {
        "type": "added",
        "text": "PGP keys: a pasted public key block gives its fingerprint, creation date, algorithm, subkeys and every name and email on it — the emails become indicators. Fingerprints are also recognised written with spaces or after “fingerprint”; the same key in two cases ties them."
      },
      {
        "type": "fixed",
        "text": "A URL that contained a hash or a transaction ID was saved with blanks in place of it."
      },
      {
        "type": "fixed",
        "text": "An indicator's profile could miss evidence added since it was first shown."
      }
    ]
  },
  {
    "version": "1.61",
    "name": "Threat Intel overview",
    "date": "2026-11-23",
    "summary": "Threat Intel opens on an Overview that works out what stands out from your stories, cases, stack and rules, and stories open in a wider panel that says why each one matters to you.",
    "changes": [
      {
        "type": "added",
        "text": "Threat Intel → Overview, the first tab: four findings worked out from what is stored — products you run with known-exploited flaws in the news, news indicators already in your cases, how much of each named ATT&CK group your rules cover, and the technique in the news with the fewest rules."
      },
      {
        "type": "added",
        "text": "Overview boxes: actors and malware named in your stories (groups with a rule-coverage bar), the known-exploited CVEs with their CISA due date and whether you run the product, and the techniques named against how many of your rules are tagged with each."
      },
      {
        "type": "added",
        "text": "Overview stories table with filters (unread, in my cases, my stack, known exploited, critical), stories per month by category, your cases in the news, and the sources."
      },
      {
        "type": "added",
        "text": "“Start a rule for it” makes a Sigma rule with the technique's title, description and ATT&CK tag filled in; the detection logic is yours to write."
      },
      {
        "type": "changed",
        "text": "The story panel is wider and opens with a short slide; it puts “Why it matters to you” first (indicators in your cases, known-exploited CVEs and your stack, actor coverage, rules per technique), then the source's own summary, with Add to case and Read original kept at the bottom."
      },
      {
        "type": "added",
        "text": "Previous / next in the story panel, and J / K, step through the list you opened it from."
      },
      {
        "type": "fixed",
        "text": "Star, Relevant, Actioned and Dismiss in the story panel now show their new state straight away."
      }
    ]
  },
  {
    "version": "1.60",
    "name": "Fixes from a walk through the sample case",
    "date": "2026-11-23",
    "summary": "The timeline no longer goes blank when you scroll, the details panel stays inside itself, names in Infrastructure lead somewhere, and anything a tool saves can go to the case you choose.",
    "changes": [
      {
        "type": "fixed",
        "text": "Timeline: scrolling through days could leave the screen blank below a day heading. A heading stuck at the top was measured where it was stuck instead of where it sits, which threw off every row after it. Checked at four screen sizes and on a 20,000-event timeline."
      },
      {
        "type": "fixed",
        "text": "Details panel: long flags (a phone number in a drama range, an invalid number) wrapped instead of pushing the panel sideways. Every vault entry and indicator of the sample case is now checked for this."
      },
      {
        "type": "fixed",
        "text": "Board: the legend and zoom sit at the bottom when there is no time slider under them."
      },
      {
        "type": "fixed",
        "text": "Infrastructure → What they share: a name opens its details and narrows “All facts” to it, and the list is brought into view (it used to filter a list further down the page, out of sight)."
      },
      {
        "type": "changed",
        "text": "On a wide screen the open details card takes its own room: the page beside it narrows instead of hiding under it (hypotheses, sources and other case pages)."
      },
      {
        "type": "added",
        "text": "Every “Save to <case>” and “Add to <case>” button — decoder, certificates, lookups, email and log tools, SQLite, PCAP, checklists, the query library, stories — has a ▾ to pick the case. What you were working on stays on screen."
      }
    ]
  },
  {
    "version": "1.59",
    "name": "Cases go by their names; a cleaner decoder and story view",
    "date": "2026-11-23",
    "summary": "Everywhere a case was shown as a number like TN-2026-014, it now shows its name.",
    "changes": [
      {
        "type": "changed",
        "text": "Cases are called by their names on screen — chips, breadcrumbs, lists, menus, messages, “also in” and “seen in” notes, Ctrl K, file names of snapshots and share packages. The TN-… number is kept as an internal reference: it still finds the case in Ctrl K (case:TN-2026-014) and in questions (“in TN-2026-014”), and exports carry it for other tools. To delete a case, type its name."
      },
      {
        "type": "added",
        "text": "Ctrl K: case: suggests cases by name (case:op-lantern), and the filter chip says the case’s name."
      },
      {
        "type": "changed",
        "text": "Decoder: one row instead of three — Auto-decode, then a menu each for Decode, Encode & transform and Analyse. The menu holding the operation you chose shows its name."
      },
      {
        "type": "changed",
        "text": "A news story reads like an article: the summary in paragraphs with no scroll box (a long one opens with “Read the rest”), source, date and severity on one line, the triage buttons in one row."
      }
    ]
  },
  {
    "version": "1.58",
    "name": "Follow the money",
    "date": "2026-11-23",
    "summary": "A Bitcoin or Ethereum wallet’s transactions — fetched with your say-so or imported from a file — read into who paid it, whom it paid, which wallets are probably the same owner and whether any is sanctioned, then brought into the case as linked vault entries and timeline events.",
    "changes": [
      {
        "type": "added",
        "text": "Money trail, in a wallet’s details: balance, received, sent (and fees), tokens, first and last activity, the largest counterparties with what each paid or was paid, wallets spent together with it (probably the same owner — CoinJoins left out and flagged), and labels on everything. Open the trail for every counterparty, every transaction and the same-owner list."
      },
      {
        "type": "added",
        "text": "Fetched from mempool.space (Bitcoin) or Blockscout (Ethereum, with its public name tags, ENS names and scam flags), every page of it. The first fetch asks: only the wallet address is sent, and only to that source. Both are also lookups in Settings → Lookups."
      },
      {
        "type": "added",
        "text": "Or imported, fully offline, from explorer JSON (Blockstream, mempool.space, blockchain.com, BlockCypher, Etherscan), an Etherscan transactions or token-transfers export, or any CSV with from, to and amount columns (the trail’s own export reads back). Failed transactions move nothing; rows that cannot be read are counted, not guessed."
      },
      {
        "type": "added",
        "text": "Sanctions: download the OFAC list of crypto addresses (Bitcoin, Ethereum, USDT, USDC, TRON) once, on request; every wallet and counterparty is then checked here, offline. Direct exposure to a sanctioned wallet is flagged."
      },
      {
        "type": "added",
        "text": "Into the case: pick counterparties (or same-owner wallets) and add them to the vault, linked “paid” with the amount, count and dates — they appear in the graph. Add every payment to the timeline as its own event, once. Label any wallet (exchange, mixer, victim, suspect…) and the label shows wherever it appears. Export the trail as CSV."
      },
      {
        "type": "added",
        "text": "One with Analysis → Money: whatever is fetched or imported is kept as evidence in the open case (with its SHA-256), so the case’s money flows, owner groups and patterns include it. Every explorer format Money reads imports into the trail too, and Money now also reads Blockscout."
      },
      {
        "type": "added",
        "text": "Legacy Bitcoin addresses (starting 1 or 3) now have their Base58Check checksum verified too."
      },
      {
        "type": "fixed",
        "text": "Dialogs are named by their title for screen readers."
      }
    ]
  },
  {
    "version": "1.57",
    "name": "Every indicator, read like an analyst would",
    "date": "2026-11-23",
    "summary": "An indicator’s details now say what it is and what about it should worry you — look-alikes, hosting, link tricks, broken wallets, leaked secrets — worked out from the value alone, with nothing looked up.",
    "changes": [
      {
        "type": "added",
        "text": "Profile, in an indicator’s details and a vault entry’s: look-alikes of about 125 commonly imitated brands and of every domain you marked benign — other alphabets (аррӏе.com, shown decoded from xn--), digits for letters (paypa1), rn for m, one letter off, brand plus words (micros0ft-online), a brand used as a subdomain (paypal.com.verify.top). Each says which letter stands in and why it matters; real brand domains and words that merely contain a brand stay quiet."
      },
      {
        "type": "added",
        "text": "Profile also reads where a domain lives — dynamic DNS, tunnels (ngrok, trycloudflare), free hosting (with the user’s own name as what to judge, not the platform), shorteners, paste and file sharing, exfiltration endpoints — and flags machine-generated names. URLs: text before @, hosts written as numbers or bare IPs, redirect parameters and where they go, an email address carried in the link (also in base64), payload downloads, phishing words."
      },
      {
        "type": "added",
        "text": "Profile for addresses, hashes and wallets: public resolvers and cloud metadata addresses as noise or SSRF targets, IPv4 inside IPv6 (mapped, 6to4, Teredo) and the MAC address inside EUI-64; empty-file and EICAR hashes, placeholders; Bitcoin address type and a real bech32/bech32m checksum that catches a mistyped wallet; burn addresses; for email, the same inbox behind dots and +tags."
      },
      {
        "type": "added",
        "text": "Worth a second look, in a record’s details: the look-alikes in it, links made for one person, and secrets that should not be there — Telegram bot tokens and Discord webhooks phishing kits use, AWS, GitHub, GitLab, Slack, Google, Stripe, OpenAI, Anthropic, npm, SendGrid and Azure keys, private keys, passwords in links, and JWTs read out (issuer, subject, expiry, unsigned). Secrets are only ever shown masked."
      },
      {
        "type": "added",
        "text": "Vault: a card or row whose indicator is a look-alike says so, and Show → Look-alikes and other warnings lists every such entry."
      }
    ]
  },
  {
    "version": "1.56",
    "name": "Case snapshots, saved views, @ links in notes, and a guard on space",
    "date": "2026-11-22",
    "summary": "Save a case to a file and compare or roll back to it later, name the views you come back to, link notes to entries with @, and never let an import fill the browser.",
    "changes": [
      {
        "type": "added",
        "text": "Seen over time, in an indicator’s details and in a vault entry that is one: first and last seen (and in which case), how long between, a small chart of sightings by day, week or month, how many records in each case — and Every sighting, oldest first, across every case, each one opening on its case’s timeline. Built only from your own evidence."
      },
      {
        "type": "added",
        "text": "Press ? anywhere (except while typing) for every keyboard shortcut. Help shows the same list, which now includes the newer ones: Alt+1–9 and Tab in Ctrl K, @ in notes, the Regex builder’s keys, Shift+click ranges, ← → between tabs."
      },
      {
        "type": "changed",
        "text": "Duplicates: names one digit apart (“Hana Okafor 2033” and “Hana Okafor 2433”, “user7” and “user8”) are no longer offered as probably the same — a different number usually means a different thing. A digit added or dropped still is. At most 2,000 near matches are listed."
      },
      {
        "type": "added",
        "text": "Welcome → Start with an empty workspace, for when you want to begin your own case straight away instead of looking at the sample first."
      },
      {
        "type": "changed",
        "text": "The empty “My first case” made when the sample is removed now gives way to the first case you create, which takes its number — no leftover empty case."
      },
      {
        "type": "changed",
        "text": "An empty vault whose evidence already names indicators says so, with a button to the ones found, instead of just “Nothing here yet”."
      },
      {
        "type": "fixed",
        "text": "From a walk through a whole investigation: an archived case was labelled “Closed” on its card while everything else said “Archived”; archiving now has Undo; the vault toolbar no longer drops Add entry to a second line when duplicates are found (shorter “1 duplicate?” and “Profiles”); on the graph the “not on the graph yet” note sits below the focus bar instead of under it."
      },
      {
        "type": "added",
        "text": "Case snapshots: from a case’s ⋯ menu (or Ctrl K), save the case as it is now to a file on your computer — named, with or without attached files. It takes no space in this browser. Later, Compare with a snapshot shows what was added, removed and edited since (and what changed in each edited entry); Bring back puts back only what was removed, Roll back returns the whole case to the snapshot after downloading the case as it is now, and Undo works after both. A snapshot of another case, or a file that is not one, is refused. A snapshot also imports as a case."
      },
      {
        "type": "added",
        "text": "Saved views: name a vault view (search, category, filters, sort, layout), a graph view (focus, steps, filters) or a Ctrl K search, and come back to it in one click — from the vault’s side panel, the graph bar, or Ctrl K, where typing a view’s name puts it first. Delete with undo."
      },
      {
        "type": "added",
        "text": "@ in notes: type @ in a note and pick a vault entry; it is written as @[value], links to the entry, and the entry lists the notes that mention it under Mentioned in notes. A mention whose entry is gone shows faded and offers to add it back. The suggestions are read out to screen readers."
      },
      {
        "type": "changed",
        "text": "Space is checked before anything big is added — a vault import, a case import, a backup restore, a log import — and if it would not fit, nothing changes and you are told how much is needed and how much is left. Restore points (whole copies kept in the browser) now make room by dropping their oldest copies, and are skipped with a warning rather than filling the browser."
      },
      {
        "type": "fixed",
        "text": "CSV exports that missed part of the protection against spreadsheet formulas (the whole-file regex matches, the vault’s selected entries) now get all of it; every CSV export shares one way of writing cells."
      },
      {
        "type": "changed",
        "text": "Tidier code underneath: one zip reader instead of two, one list of action maps instead of two kept in step, and fourteen functions nothing used any more removed. No change to what you see."
      }
    ]
  },
  {
    "version": "1.55",
    "name": "Focus in a big graph, imports from other tools, merge all duplicates",
    "date": "2026-11-22",
    "summary": "A big case's graph can be read a neighbourhood at a time, earlier work comes in from Maltego, GraphML, SpiderFoot or a CSV, and duplicates merge all at once.",
    "changes": [
      {
        "type": "added",
        "text": "Board → Focus on…: show only what is 1, 2 or 3 steps from one entry (pick it by typing, or right-click a node → Focus here), grow the view a node at a time with Expand, and narrow it by verdict or tag. Hide single links drops entries that hang off one link. A focused view is laid out around the focus and never moves your saved layout; each case keeps its own view, and Show all puts everything back. In a graph of over 300 entries the bar is always there; on a smaller one it appears once you focus."
      },
      {
        "type": "added",
        "text": "Vault → Import: bring earlier work into a case — a Maltego graph (.mtgx, or exported as GraphML), any GraphML (yEd, Gephi, an OSINTrix export), SpiderFoot scan results (CSV), or a CSV of values or of links (source, target, relationship). Each kind of thing in the file is matched to an entry type you can change or skip before anything is added, with a count of new entries, entries already in the case (reused, not duplicated or changed) and new links. Other properties go into the entry’s notes; SpiderFoot’s false positives are left out. The whole import can be undone."
      },
      {
        "type": "added",
        "text": "Duplicates → Merge all: every group with the same value merges into its fullest entry (or the one you picked) in one step, with one undo. The review has two tabs — same value, and probably the same (one letter apart), which stay one-by-one — and shows 40 groups at a time."
      },
      {
        "type": "changed",
        "text": "Finding names one letter apart no longer compares every pair: 4,000 names are checked in well under a second, and merging many groups re-points the links in one pass."
      }
    ]
  },
  {
    "version": "1.54",
    "name": "A big vault, workable; filters and actions in Ctrl K",
    "date": "2026-11-21",
    "summary": "A case with thousands of entries can be filtered, sorted, paged and changed in bulk, with undo. Ctrl K gains filters that are suggested as you type and actions on a result without leaving the search.",
    "changes": [
      {
        "type": "added",
        "text": "Vault → filters for a big case: verdict, type, tag, and “not linked to anything”, “also in other cases”, watched, with open questions, not seen in any record or with notes — with how many match, and Clear. Cards can now be sorted too (priority, newest, oldest, most records, last seen, value, type)."
      },
      {
        "type": "added",
        "text": "Vault → select many entries: the box on a card or row, Shift+click for a range in the order on screen, or every entry shown — then set priority or verdict, tag (or take a tag off with −tag), star, watch, export as CSV or delete them at once. Every bulk change can be undone; deleted entries go to the trash with their relationships. Esc clears the selection."
      },
      {
        "type": "changed",
        "text": "A vault of thousands of entries opens at once: the first 150 cards (400 rows) are drawn and the rest come with Show more. 3,000 entries went from about half a second to 15 ms."
      },
      {
        "type": "added",
        "text": "Ctrl K → filters that narrow every result: verdict:, type:, tag: and is: (starred, watched, open, solved), combined with each other and with case: and in:. They are suggested as you type — operator names first, then their values (your case codes, tags and types) — and Tab or Enter finishes one. The filters in force show above the results, each with a × to drop it; type:ip finds IPv4 and IPv6, not IP:port."
      },
      {
        "type": "added",
        "text": "Ctrl K → act on a result without leaving the search: copy, copy defanged, watch, star, show in the graph, find in every case, open a lookup, copy masked, open a case’s vault or timeline — listed beside the result with Alt+1…9."
      },
      {
        "type": "fixed",
        "text": "Ctrl K is announced properly to screen readers: the box owns the result list and says which result is highlighted, results come in named groups, and the scope buttons are a labelled group. Case codes on results and the red Delete button in dark mode now have enough contrast."
      }
    ]
  },
  {
    "version": "1.53",
    "name": "Polish, a menu on every indicator, masking, big files, a search builder",
    "date": "2026-11-21",
    "summary": "Every screen checked at desktop, laptop, tablet and phone widths: text that was cut off can be read, strips of tabs that do not fit scroll with a soft edge, scrollbars are thin, and nothing is wider than a phone. Right-click any indicator for copy, details, every case it is in, watch and lookups.",
    "changes": [
      {
        "type": "added",
        "text": "Query library → Build a search: pick what you want row by row — words, an exact phrase, any of several, words to leave out, a site, a file type, words in the title, address or text, a date range, a port, an organisation, a country, a product, an IP range, a certificate name, a code language or repository — and see it written for Google, Bing, DuckDuckGo, Shodan, Censys and GitHub at once. What an engine cannot search by is struck through and named, not silently dropped; a wrong value (a port over 65535, a date that is not a date) is pointed out under its row. Blanks like {{DOMAIN_NAME}} stay blanks, so it saves to the library as a template; a saved one reopens in the builder and is rewritten for whichever engine you run it on."
      },
      {
        "type": "added",
        "text": "Regex builder → My patterns: save a pattern with its sample lines, fields, types and pinned tests, with tags; saving again keeps the earlier version (up to 20, each shown as a change you can open); open any of them later, export the library as one JSON file and import it on another machine. A deleted pattern goes to the trash and can be restored."
      },
      {
        "type": "added",
        "text": "Masking: a copy of a log with its IP addresses, domains, emails, user names, host names, hashes, MAC addresses, phones and wallets replaced by placeholders of the same shape (192.0.2.1, domain-1.example, user-1) — the same value always gets the same one, private addresses stay private-looking, and system accounts like root stay as they are. In the Regex builder (Mask a copy, with the list of what was replaced kept here) and in the Decoder (Mask identifiers)."
      },
      {
        "type": "added",
        "text": "Regex builder → Export → Run on a whole file: a log of any size (up to 4 GB) is read here in 4 MB pieces with progress and a Stop button — how many lines match, each field’s coverage, distinct values and commonest ones, the matches as CSV, and the missed lines, 50 of which can go straight into the sample to teach the pattern. A 40 MB log of 400,000 lines takes a few seconds."
      },
      {
        "type": "added",
        "text": "Right-click any indicator anywhere — an IP, domain, URL, email, hash, handle, wallet or CVE in a timeline, a table, a note or a result — for Copy, Copy defanged, Details, Find in every case, Watch, and the lookups for its kind (VirusTotal, Shodan, crt.sh, Wayback, Have I Been Pwned…, opened in a new tab). Select part of a line and right-click to use just that. Anything else, or Shift + right-click, keeps the browser’s own menu."
      },
      {
        "type": "added",
        "text": "Copy masked from anywhere: on a record’s captured text (next to a plain Copy), at the top of the Scratchpad, and by selecting any text and right-clicking it, which also offers Copy defanged. Defanging there brackets only the indicators, so the sentences around them stay readable."
      },
      {
        "type": "changed",
        "text": "Text cut off with … now shows in full when you point at it, on every screen; the cloud guide’s section names, the release list in What’s new and the area descriptions in Help wrap instead of being cut."
      },
      {
        "type": "changed",
        "text": "Rows of tabs or buttons too wide for the screen (case tabs, the cloud guide, CTF, the Toolbox, Certificates, Threat Intel) scroll sideways with a soft edge that shows there is more; on a phone, the cloud guide’s provider buttons no longer push the page wider."
      },
      {
        "type": "changed",
        "text": "Scrollbars are thin and quiet everywhere."
      },
      {
        "type": "changed",
        "text": "Decoder: the 25 operations sit in labelled rows — Decode, Encode & transform, Analyse — instead of one wall of buttons."
      },
      {
        "type": "changed",
        "text": "Playbooks: Checklists and Automations sit beside the page title, as on every other page, instead of in a bar above it; Automations has the same page header."
      },
      {
        "type": "fixed",
        "text": "Dark mode: the Regex builder’s field colours stayed in their light shades, and a hovered primary button got lighter until its white text was hard to read; both now keep their contrast. Every screen was checked for low-contrast text in light and dark."
      },
      {
        "type": "fixed",
        "text": "Dashboard → Activity showed fixed September dates; it now shows the last eight days up to today (or the sample cases’ last week while only those are here), and says what to do when nothing was captured."
      },
      {
        "type": "changed",
        "text": "A workspace without the sample data says what to do next everywhere: Entities and an empty case’s Timeline explain where indicators and events come from instead of showing an empty table or “Nothing matches”, the dashboard says your case is empty, and the feed card no longer says “Sample data”."
      },
      {
        "type": "changed",
        "text": "A graph with more than 300 nodes now fits on screen whole instead of opening zoomed in on a tangle; names appear as you zoom in. Checked with 3,000 nodes (smooth) and 50,000 records (every screen in under half a second, reload with all of them in about a second)."
      },
      {
        "type": "changed",
        "text": "Keyboard and screen readers: ← → Home End move between tabs in every tab strip and open the tab reached; the Regex builder’s formats, lines and detail tabs are announced correctly, and its details panel can be scrolled by keyboard."
      }
    ]
  },
  {
    "version": "1.52",
    "name": "Regex builder for daily work",
    "date": "2026-11-21",
    "summary": "Tests pinned to a pattern, a check of which tools can run it, values that filter the lines and go straight to the case, undo, keyboard keys, and a calmer, full-height layout.",
    "changes": [
      {
        "type": "added",
        "text": "Tests: pin a line as “must match” (with its values) or “must not match”, or paste one. Every change is checked against them; the pattern bar says how many pass, and a failing test says what broke (“does not match any more”, “user is … , was …”)."
      },
      {
        "type": "added",
        "text": "Runs in: each export shows which tools can run the pattern as it is. KQL uses RE2, which has no lookahead — the export is written without it, and says whether every line still gives the same values."
      },
      {
        "type": "added",
        "text": "Pivot on values: the commonest values of each field filter the lines and the table with one click; another click adds all of a field’s values to the case as evidence, so addresses, users and hashes become indicators."
      },
      {
        "type": "added",
        "text": "Undo and redo for field changes (Ctrl+Z, Ctrl+Shift+Z), ↑ ↓ to move between lines, M for the next missed line, / to edit the pattern."
      },
      {
        "type": "changed",
        "text": "A calmer layout: a one-line header, panes that fill the screen, spaces in the pattern shown as a faint ␣, regex symbols muted so field names stand out, field rows on two lines, and a label on every highlighted value when you point at it."
      },
      {
        "type": "changed",
        "text": "Regex builder: “New lines” is now “Start over”. In table view the details panel folds to a slim rail (and opens again when you click a row or a tab); long and multi-line values stay on one line with a “+4 lines” count and the full value on hover; scrollbars are thin."
      },
      {
        "type": "changed",
        "text": "CTF cheatsheets: each category’s one-line description sits behind a ? next to the views, readable in full at any width instead of cut off."
      }
    ]
  },
  {
    "version": "1.51",
    "name": "Regex builder, rebuilt",
    "date": "2026-11-21",
    "summary": "The Regex builder becomes a workbench: the coloured pattern on top, your lines below, and a sidebar that explains the pattern, shows what each line gives and why a line is missed. It sorts mixed logs into formats, joins records over several lines, names the fields of common layouts in one click, and makes patterns faster where it can prove nothing changes.",
    "changes": [
      {
        "type": "changed",
        "text": "Regex builder layout: the pattern sits on top with its formats, match count and safety; the lines are below (or a table of what they give); a sidebar has Match, Explain, Fields, Speed and Export. The pattern is coloured, each field labelled, and long standard parts (IP addresses, timestamps) shown by name — expand to see them in full. Click it to edit by hand."
      },
      {
        "type": "added",
        "text": "Why a line is missed: the pattern shows how far it got on the line, what it expected next and what it found instead."
      },
      {
        "type": "added",
        "text": "Explain: the pattern in plain words, piece by piece — “field user — text up to a space”, “one of Failed password for [invalid user]”. Hover a field anywhere and it lights up in the lines, the pattern, the explanation and the table."
      },
      {
        "type": "added",
        "text": "Formats: mixed logs (sshd, sudo, cron, a firewall…) are sorted into groups of lines written the same way, each with its own pattern and match count. Every format can be exported at once: several Grok patterns, Splunk rex lines, a KQL case(), a JavaScript or Python lookup, most specific first."
      },
      {
        "type": "added",
        "text": "Records over several lines — Java stack traces, Windows Event Viewer text exports, pretty-printed JSON — are found and joined, with the same record-start setting for Logstash, Filebeat, Splunk and Fluent Bit."
      },
      {
        "type": "added",
        "text": "Auto-parse names the fields of key=value, JSON (nested fields too), CSV and TSV, CEF, LEEF, syslog (RFC 3164 and 5424, with firewall key=value messages and the users, addresses and ports in a message), Apache and nginx, IIS W3C and “Key: value” exports — learning variations from lines its first pattern misses."
      },
      {
        "type": "added",
        "text": "Optional fields: a field some lines lack is written as optional, in its place, with the words before it. Each field shows how often it is present, how many values it has and the commonest ones."
      },
      {
        "type": "added",
        "text": "Optimiser: up to six rewrites — tying to the line start, taking out shared words, character classes for single-character choices, one-pass quoted text, exact classes instead of wildcards, a fixed word checked first — each kept only if every line gives exactly the same values, shown with what changed and the speed before and after."
      }
    ]
  },
  {
    "version": "1.50",
    "name": "Regex builder",
    "date": "2026-11-20",
    "summary": "Select the parts of a log line you want and get the regular expression for them — tested on every line, checked for patterns that freeze log tools, and written for six tools. Nothing leaves the browser.",
    "changes": [
      {
        "type": "added",
        "text": "Regex builder, its own page in the sidebar under Kit (or type “regex” in search): paste log lines or open a log file, select the parts you want and name them. The pattern uses a precise form for what it recognises (IPv4 and IPv6, ISO, syslog and web-server times, email, URL, GUID, hashes, SIDs, numbers) and “up to the next delimiter” for the rest; host names and process numbers become patterns, an empty field written as “-” matches whatever is there, and fixed words stay as anchors."
      },
      {
        "type": "added",
        "text": "It is tried on every line, with the fields it pulls out in a table and the lines it misses listed. Selecting the same fields on a missed line teaches it the variation: different words become alternatives, an extra phrase becomes optional."
      },
      {
        "type": "added",
        "text": "A safety check before anything runs: patterns that can backtrack badly — and freeze a log tool on a line that almost matches — are flagged and, when written by hand, not run at all; others are timed on hostile input."
      },
      {
        "type": "added",
        "text": "The same pattern for JavaScript, PCRE, Python, Grok (using Grok’s own patterns where they fit), Splunk rex and KQL extract, ready to copy — or saved as a parser so log imports read that format. Plus a library of ready-made patterns for incident response."
      },
      {
        "type": "fixed",
        "text": "Custom parsers: a pattern that can freeze on near-matching lines is no longer run in the test box, and cannot be saved."
      }
    ]
  },
  {
    "version": "1.49",
    "name": "A sample case for the OSINT tools",
    "date": "2026-11-19",
    "summary": "A new sample case, Harbourline refund scam, shows every Infrastructure view and an identity profile on realistic data — and the account timeline is fixed.",
    "changes": [
      {
        "type": "added",
        "text": "Sample case “Harbourline refund scam”: WHOIS, RDAP, dig, certificate, passive DNS, Shodan and Censys results; victim payments on Bitcoin, Ethereum and TRON; profiles on X, Reddit, GitHub and Mastodon, two of them renamed; the shop’s About page saved twice; post times from a Telegram group, Reddit, Discord and a bot; and Jan Harbour in the vault, joined to J. Haven in Customer portal by a shared email. Added once to workspaces that keep the sample data; Settings → remove sample data takes it out with the others."
      },
      {
        "type": "fixed",
        "text": "Account timeline: it now fills its card instead of stopping at a fixed width, long account names are shortened in the middle instead of cut off on the left, and the dates along the top show months and years."
      },
      {
        "type": "fixed",
        "text": "Accounts: a profile link written without https:// is now matched to its account and platform (an old GitHub name showed as a separate account), API addresses such as api.github.com/users no longer show as accounts named “users”, the platform comes from the profile data when there is some, and what stands out is listed in the order the accounts were made."
      },
      {
        "type": "fixed",
        "text": "Domains & addresses: long values on the right of the picture no longer run past its edge, and the picture fills its card."
      }
    ]
  },
  {
    "version": "1.48",
    "name": "People, hours and what changed",
    "date": "2026-11-19",
    "summary": "When the people behind accounts are awake and where that puts them, one profile per person across cases, a complete checklist for every username, email and phone, what changed between two saves of a page, and metadata from old Office files.",
    "changes": [
      {
        "type": "added",
        "text": "Infrastructure → Active hours: paste or import post times — Telegram and Discord chat exports, Reddit, Mastodon and X data, any JSON list or CSV with times, or one time per line — and see each person's week, their likely time zone from when they sleep, their weekend (Saturday–Sunday or Friday–Saturday), whether their clock changes for summer, and which accounts keep the same week. Accounts that post at every hour are flagged as automated or shared. Only who and when is kept, so a large chat export stays small."
      },
      {
        "type": "added",
        "text": "Identity profiles: open a Person in the vault, or Vault → Identity profiles. One profile per person: their identifiers with how sure each link is, how much evidence names each and when it was last seen, the same person in other cases (a shared email, phone or wallet confirms; a shared username only makes it likely), where the cases disagree, a map of how it all connects, and the gaps still to close."
      },
      {
        "type": "changed",
        "text": "Forensics kit → Identity pivots is now a full checklist for a username, email address or phone number: profiles, breach and leak searches, search queries, messaging apps and archived copies. Mark each place there, not there or private, add a note, save a found profile to the case, filter what is left to check, and copy a summary. Kept per value across cases, also after a refresh."
      },
      {
        "type": "added",
        "text": "Infrastructure → Accounts → Changes over time: a page or profile saved more than once, each version against the one before — text added and removed, links and email addresses, and every profile field with how much counts such as followers moved. Compare any two records by hand too."
      },
      {
        "type": "added",
        "text": "Metadata from old Word, Excel and PowerPoint files (.doc, .xls, .ppt) and OpenDocument (.odt, .ods, .odp): who made it and who saved it last, when, how many times and for how long it was edited, the program, template, company, custom fields, and whether it holds macros — checked against an independent reader. Damaged or crafted files read as empty instead of hanging."
      },
      {
        "type": "changed",
        "text": "Help answers the new features, and the guided tour has a stop on the Infrastructure tab."
      }
    ]
  },
  {
    "version": "1.47",
    "name": "Sturdier underneath",
    "date": "2026-11-19",
    "summary": "The trash is back for everything, nothing typed is lost on a refresh, every parser was put through junk, huge and hostile input, and text files from Windows tools read correctly.",
    "changes": [
      {
        "type": "fixed",
        "text": "The trash is always in the sidebar, and deleting a detection rule, saved query, hunt, playbook, tool or automation now puts it there too (before, only cases, records, vault entries, notes and links did). Each comes back with Restore, also after a refresh."
      },
      {
        "type": "fixed",
        "text": "A change made just before refreshing or closing the tab could be lost: a finished action is now written at once instead of a quarter-second later."
      },
      {
        "type": "fixed",
        "text": "With the workspace open in two tabs, closing the one that saves now hands saving to the other by itself — it no longer stays read-only until you click. A page opened by a refresh takes over the moment the old one lets go."
      },
      {
        "type": "fixed",
        "text": "Deleting an automation that had never run stopped with an error."
      },
      {
        "type": "added",
        "text": "Text files saved by Windows tools are read the way they were written: UTF-16 (PowerShell “> file”, Excel “Unicode text”, many event-log exports), UTF-8 with or without a byte-order mark, and the old Windows-1252 code page — in log imports, rule packs, notebook imports, threat-intel and cloud files."
      },
      {
        "type": "added",
        "text": "More time formats read exactly: Windows FILETIME, micro- and nanosecond epochs, ISO 8601 basic form (20261102T081530Z), milliseconds after a comma (log4j, Python logging), dates with dots read day-first (02.11.2026), and day-first dates whenever the first number is over 12 (25/11/2026), with AM/PM and a time zone."
      },
      {
        "type": "fixed",
        "text": "Indicators: a link with brackets in it (Wikipedia pages) is kept whole, a trailing “…” is no longer part of a link, a link to an IPv6 address in square brackets is found along with the address, and dotted numbers with five parts are no longer read as an IP address."
      },
      {
        "type": "added",
        "text": "Every text field has a length cap: 4,096 characters for one-line fields, 5 million for text areas (big pasted logs and exports), 2 million for a notebook page; short notes keep their smaller caps. A paste that goes over is cut and says so. Saved names, titles and tags far past any cap are trimmed when the workspace loads."
      },
      {
        "type": "fixed",
        "text": "Three inputs could freeze the page for a minute or more: a very long run of digits in the coordinate reader, a very long run of spaces in a search, and a long Base58-looking string in the decoder. Each is now instant."
      },
      {
        "type": "changed",
        "text": "Stored data in the wrong shape — from an old version, a hand-edited backup or a damaged copy — is put right on every load and import, so no page can break on it; an entry of a kind this version does not know is kept as a document with its kind as a tag. A damaged trash item says so instead of coming back broken."
      },
      {
        "type": "added",
        "text": "New checks: every parser fed empty, binary, 2 MB, deeply nested, mis-encoded, right-to-left and pathological input; hostile markup, quotes, script links, control characters and formulas put in every field and file name, then every page, case tab, panel and dialog opened before and after a refresh; and every kind of saved data through a refresh and a backup."
      }
    ]
  },
  {
    "version": "1.46",
    "name": "Money, accounts, phones and pictures",
    "date": "2026-11-17",
    "summary": "Where the money went, when each account was made, what a phone number is, and the same picture found again after it was cropped or mirrored — plus a new Infrastructure tab for all of it.",
    "changes": [
      {
        "type": "added",
        "text": "A case tab, Infrastructure, for what a case pivots on: Domains & addresses (moved from Analysis), Money and Accounts. Analysis keeps questions, hypotheses and sources."
      },
      {
        "type": "added",
        "text": "Infrastructure → Money: paste transactions from Blockstream or mempool.space, blockchain.com, BlockCypher, Etherscan (JSON or CSV, coins and tokens), Tronscan or TronGrid. Who paid whom as a picture and a table; Bitcoin addresses spent together grouped as one owner (not in CoinJoin-looking transactions); change and failed transactions left out; collection points, pass-through wallets, distribution and peel chains pointed out; the case's wallets that appear in other cases."
      },
      {
        "type": "added",
        "text": "Infrastructure → Accounts: when each account was made (GitHub, Reddit, Mastodon, X/Twitter, YouTube and Bluesky profile data, and “Joined March 2019”-style text in pages), when it shows up in your evidence, and its earlier names — by account number across two pastes, or a page that says “formerly @…”. Accounts made shortly before they appear, and accounts made within days of each other, are pointed out."
      },
      {
        "type": "added",
        "text": "Phone numbers, offline: country, mobile / landline / VoIP / premium / personal number, whether the number is valid in its plan, ranges reserved for films and TV, and one standard form — so 07911 123456, +44 7911 123456 and 0044-7911-123-456 are one number, matched across cases. Set the country for numbers written without a code."
      },
      {
        "type": "changed",
        "text": "The same picture elsewhere is found after cropping (up to 30 %), mirroring, framing in a screenshot, text over it, greyscale and small rotations — tested on 18 real photos and their edited copies, with no false matches between different photos. Matches show in the evidence panel with how the copy was changed, with links to reverse image search sites."
      },
      {
        "type": "changed",
        "text": "Generators: name handling for accents, apostrophes, double-barrelled and particle surnames, middle names, known handles and years; usernames and work and personal email ranked by how common the pattern is; copy each one, a group, or all; filter; choose separators; save as a text file."
      },
      {
        "type": "changed",
        "text": "Forensics kit: the tools sit on one line in three groups — Analyse files, Decode, Investigate — each showing the tool in use — none hidden off the side of the screen."
      },
      {
        "type": "fixed",
        "text": "Phone numbers written as 0044-… with more groups are no longer cut short when read from text."
      }
    ]
  },
  {
    "version": "1.45",
    "name": "OSINT: metadata, geolocation, infrastructure, sources",
    "date": "2026-11-16",
    "summary": "What a file says about itself, a workbench for where a picture was taken, what domains and addresses share, and how far to trust each source — all worked out in this browser.",
    "changes": [
      {
        "type": "added",
        "text": "File metadata, read from the bytes: HEIC, JPEG, PNG, WebP and TIFF pictures (camera, serial, the time zone it was taken in, GPS with the direction the camera faced, place names, author, the editing program and its history, AI-generation marks, Content Credentials), MP4/MOV/3GP video (recording time and GPS from iPhone and Android), MP3 tags, PDFs (including information kept in compressed object streams) and Word/Excel/PowerPoint (author, last saved by, program, revision). Shown in the evidence panel with what stands out first; GPS goes on the map, the event takes the moment it was taken, and files too big to store still have their video metadata read."
      },
      {
        "type": "added",
        "text": "When a picture has no time zone, the GPS clock gives it (14:05 on the camera, 13:05 UTC: UTC+01:00). iOS 8's day-of-year GPS dates are read correctly."
      },
      {
        "type": "added",
        "text": "Where was this taken? — a geolocation workbench for any picture or video: write down what you see, add the places it could be (coordinates in any format or a map link), mark which clues fit each place, and see the sun's direction, height and shadow length at each place at the moment the file was made. Confirmed places go on the case's map and into the vault."
      },
      {
        "type": "added",
        "text": "Analysis → Infrastructure: paste WHOIS (any registry), RDAP, dig output, passive DNS (VirusTotal, CIRCL, DNSDB, CSV), crt.sh, Shodan or Censys results. Each paste is kept as evidence, and what the domains and addresses share — registrant, certificate, site-verification token, favicon, TLS fingerprint, address, name servers, same-day registration — is listed by how much it means. Privacy services, big DNS providers and CDN addresses are set aside as not links."
      },
      {
        "type": "added",
        "text": "Analysis → Sources: rate each source A–F once (it applies in every case) and each piece of evidence 1–6, the Admiralty grading. What is backed by several independent sources, and what you marked or vaulted on the strength of one weak source, is shown; an indicator's panel says how many independent sources mention it."
      },
      {
        "type": "fixed",
        "text": "GPS longitudes written both negative and with W are no longer flipped back east; Windows XP author and title tags in pictures are read."
      }
    ]
  },
  {
    "version": "1.44",
    "name": "Endpoint evidence, read like an analyst",
    "date": "2026-11-16",
    "summary": "Process trees, decoded command lines, the rare things across all your evidence, and a map of how an attacker moved between hosts — built from the Windows and Sysmon logs you already import.",
    "changes": [
      {
        "type": "added",
        "text": "Timeline → Processes: parent → child trees per host from Sysmon 1 and Windows 4688. Joined by process GUID, then process ID (hex IDs from 4688 included, reused IDs handled), then the parent's path. A parent missing from the evidence is shown with a question mark, and one started by an earlier process's own command line (cmd /c powershell …) hangs under it. Suspicious processes — Office starting a shell, a shell under services.exe, system names in the wrong folder, programs in folders anyone can write to, obfuscated command lines — are marked, and by default only the branches that lead to them are shown."
      },
      {
        "type": "added",
        "text": "Command lines are decoded where they sit: -EncodedCommand in any of its short forms, FromBase64String, [char] codes, joined strings, backtick obfuscation and plain Base64, several layers deep. The decoded text shows in the evidence panel and the process tree, and the addresses, domains and files it names become indicators of the event."
      },
      {
        "type": "added",
        "text": "Timeline → Movement: host → host from network and RDP logons (4624 types 3 and 10), explicit-credential logons (4648), PsExec-style services (7045), RDP connection records (1149), WinRM and SMB/RDP/WinRM connections. Addresses are named from logons and the hosts' own connections; a diagram in the order hosts were reached and a table with times, accounts and the events behind each move."
      },
      {
        "type": "added",
        "text": "Timeline → Patterns → Rare things: programs, services, scheduled tasks and domains seen on one host once or twice across all your cases. Per-user install paths count as the same program."
      },
      {
        "type": "fixed",
        "text": "\"System binary name running from outside System32\" no longer fires on every process whose parent is explorer.exe (it lives in C:\\Windows); it is judged per binary, on the binary's own path."
      },
      {
        "type": "fixed",
        "text": "A LOLBin next to a loopback or link-local address is no longer called a download from an external address."
      }
    ]
  },
  {
    "version": "1.43",
    "name": "Certificates: everything up front",
    "date": "2026-11-16",
    "summary": "Expiry, the full serial and the thumbprints are now the first thing you see for a certificate or signing request — on the Certificates page and in a case's evidence.",
    "changes": [
      {
        "type": "added",
        "text": "Certificates → Key facts, right under the header: status and days left, valid from and expires (exact UTC), lifetime, the full serial number and its size, SHA-256 and SHA-1 thumbprints (the SHA-1 is the “Thumbprint” Windows shows), public-key SHA-256 and pin, key, signature algorithm and OID, version, subject, issuer, names, key usage, extended key usage, basic constraints, key identifiers, OCSP and issuer URLs and revocation lists — each with a copy button that copies plain hex."
      },
      {
        "type": "added",
        "text": "Signing requests show their own SHA-256 and SHA-1, every part of the subject on its own line, the public key's SHA-256 and pin, the version, every requested extension, and the challenge password in full (it is kept in the clear inside the request) instead of cut short."
      },
      {
        "type": "added",
        "text": "A certificate or signing request pasted into a case is decoded in the evidence panel with the same key facts — several in one paste each get their own — and Open in Certificates takes it to the full decoder."
      },
      {
        "type": "added",
        "text": "Certificates in a case's evidence give the case indicators: the SHA-256 and SHA-1 thumbprints (what crt.sh, VirusTotal, Censys and Shodan search by) and the names and addresses they cover — so they show in Entities, search, hunts and connected cases. Certificates already in your cases are read once in the background."
      },
      {
        "type": "fixed",
        "text": "The serial number is no longer cut short in Subject and issuer."
      }
    ]
  },
  {
    "version": "1.42",
    "name": "Hunts, ageing verdicts, faster at scale",
    "date": "2026-11-16",
    "summary": "Saved hunts across every case, verdicts that fade with age, notes written from selected events, a rule at a glance — and the rule-heavy screens several times faster on big workspaces.",
    "changes": [
      {
        "type": "added",
        "text": "Detections → Hunts: a search (the timeline filter's language) or one of your Sigma rules, run across every case. What it finds when saved counts as seen; new matches are flagged on the hunt and on Today until you mark them seen. Save a timeline filter as a hunt with the crosshair next to the filter box."
      },
      {
        "type": "added",
        "text": "Verdicts age. The date is kept when you set one, however it is set; its weight halves every 90 days for IPs, four months for URLs, six for domains and a year for emails, handles and wallets — hashes never fade. The entity panel says how old a verdict is and when to check it again, Connected cases count old verdicts for less, and Today lists stale ones in open cases."
      },
      {
        "type": "added",
        "text": "Timeline → Select → Write a note: a short summary in plain words (events, hosts, time span, attack stages, malicious indicators, what stands out) and the chronology, each line ending in a citation like [3] that opens that event. Show the cited events filters the timeline to them; citations follow the events when a case is exported and imported."
      },
      {
        "type": "added",
        "text": "A line at the top of every rule sums it up — tests and whether they pass, earlier versions, where it fires and whether it is noisy, look-alike rules — each opening its detail."
      },
      {
        "type": "changed",
        "text": "Big workspaces: with 50,000 events and 2,000 rules the attack chain went from 5.2 s to 0.6 s, Timeline → Rules from 6 s to 1.8 s and Health from 8.3 s to 2.4 s. Rules now only look at events that could hold their values (an index of three-letter pieces); a test checks this finds exactly what evaluating every rule on every event finds."
      },
      {
        "type": "changed",
        "text": "Help and the guided tour cover the newer features: rules against a case, rule history and packs, hunts, connected cases, ageing verdicts, sessions and clock correction, and notes from events. The tour is ten stops."
      },
      {
        "type": "changed",
        "text": "Under the hood: every feature's actions are in one registry, with a test that no two features claim the same action."
      }
    ]
  },
  {
    "version": "1.41",
    "name": "Connected cases, rule history, cloud logs",
    "date": "2026-11-15",
    "summary": "See which cases connect and why, keep every version of a rule, fix blind spots a group at a time, catch the same attack on a second host, and import cloud, identity and network logs as real events.",
    "changes": [
      {
        "type": "added",
        "text": "Case overview → Connected cases: the other cases this one shares indicators or vault entries with (phones, wallets, handles compared the way duplicate detection does), weighted by your verdicts — malicious counts most — plus nearby infrastructure (same /24, same registered domain), said to be weaker. Private addresses, benign indicators and anything in most of your cases are left out."
      },
      {
        "type": "added",
        "text": "Detections → rule editor → History: every save that changes a rule keeps the version it replaces (last 25). Compare any two line by line, with title and severity changes listed; put an old version back in the editor and save — the one it replaces is kept too."
      },
      {
        "type": "added",
        "text": "Timeline → Rules → Not caught: blind spots of the same kind are grouped, with One rule for all and a preview of whether the draft would also match other events in your evidence."
      },
      {
        "type": "added",
        "text": "Timeline → Patterns → Sessions: the same run of stages on a second host, later (e.g. Logon → Discovery → Collection → Exfiltration 3 hours after the first host), is pointed out as a likely sign of lateral movement, with both sessions and what happened between one click away."
      },
      {
        "type": "added",
        "text": "A corrected clock now shows on every event it touched (a clock mark in the timeline; the details panel says by how much and what was recorded), and can be taken back from any of those events."
      },
      {
        "type": "added",
        "text": "Log import: AWS CloudTrail, Okta System Log, Microsoft 365 audit (JSON, or the CSV export with the event in AuditData), Zeek (TSV with #fields, or JSON) and Windows Event Viewer XML exports are read as real events — who, what, from where, the outcome and the time — and titled that way (“ConsoleLogin · user ops-admin · from 198.51.100.7 · failure”, “4625 Failed logon · user admin”). Firewall lines like “allow tcp 10.0.0.5:51022 -> 203.0.113.47:4444” now give rules source, destination, port and action to match on."
      },
      {
        "type": "added",
        "text": "Rule packs: Import takes .yml, .yar, .json or the zip that Download makes, and shows before anything changes what is new, what you already have (skipped — but tests it brings are added) and what clashes with one of yours by title: keep both, replace yours (yours stays in its history) or skip. Packs carry tests, version history and test history. One Undo takes the whole import back."
      },
      {
        "type": "fixed",
        "text": "The newer screens were checked at phone size: no serious accessibility problems and nothing wider than the screen."
      }
    ]
  },
  {
    "version": "1.40",
    "name": "Rules against cases, works offline",
    "date": "2026-11-15",
    "summary": "See what your rules catch in a case and what they miss, follow rule health over time, spot clocks that disagree and sessions of activity, and use the app with no connection.",
    "changes": [
      {
        "type": "added",
        "text": "Timeline → Rules: every rule run over the case. Caught: which rules fired and on which events. Not caught: events that look suspicious (what the evidence reader recognises, technique IDs, attack-stage tags, malicious verdicts) but no rule fires on, each with Draft a rule. Noisy here: rules that fire on more than a fifth of the case. It runs again by itself when the evidence or the rules change."
      },
      {
        "type": "added",
        "text": "Rule health over time. Every save of a rule with tests is recorded; the Tests tab shows the last 30 as a strip and says “Was passing — failing since …” when a rule regresses. Detections → Health gains Tests failing, Your rules without tests and Look alike (rules whose detection logic is nearly the same text, found even with no evidence), and a line saying what changed since the previous check."
      },
      {
        "type": "added",
        "text": "Timeline → Patterns: Clocks that disagree — the same IP, domain, URL, hash or email seen by two sources at a steady offset means one clock is off (exactly whole hours: most likely a time zone read wrongly). The odd source is named once, and its times in this case can be corrected and undone. Normal seconds of jitter are not flagged."
      },
      {
        "type": "added",
        "text": "Timeline → Patterns: Sessions — each host's events split where it goes quiet, with the attack stages each one passes through in order (Logon → Discovery → Collection → Exfiltration in 12 minutes), most suspicious first, and Show this session."
      },
      {
        "type": "added",
        "text": "Works offline. When served from a website, the app keeps a copy of its own files (never your data) so repeat visits open without downloading anything and it works with no connection; a new version replaces the copy. On or off in Settings → Data."
      },
      {
        "type": "changed",
        "text": "The MAC vendor list, world map, enrichment data and QR reader (1.25 MB) are now fetched only when a tool needs them, not on every visit."
      },
      {
        "type": "fixed",
        "text": "Closing a tab right after typing in a large notebook could lose the last words: an older save finishing late removed the closing-tab backup. It now removes it only if it already holds those words."
      },
      {
        "type": "fixed",
        "text": "Preparing a very long log line for the rule engine took seconds (3.5 s for 200 KB); it is now instant. New tests feed broken versions of real log formats — cut off, unbalanced quotes, huge fields, deep nesting, mixed formats — through the importer."
      }
    ]
  },
  {
    "version": "1.39",
    "name": "Starts much faster",
    "date": "2026-11-15",
    "summary": "The app opens in a fraction of the time it took, especially on a real internet connection.",
    "changes": [
      {
        "type": "fixed",
        "text": "The page's security policy was stopping the browser from fetching scripts ahead of time, so all ~90 of them downloaded one after another — each waiting a full round trip. They are now all fetched at once. On a typical connection the first screen appears in about 2 seconds instead of 6–9."
      },
      {
        "type": "changed",
        "text": "The big reference files — the MAC vendor list, the CISA KEV catalogue, the built-in rules and playbooks, the graph and map libraries, the reference and cloud packs, the certificate and notebook samples — are no longer on the critical path. That is half of what the app downloads. They load in the background right after the first screen, and any screen that needs one waits for it and fills in when it arrives (never while you are typing). Detections says “loading the built-in rules…” for that moment."
      },
      {
        "type": "fixed",
        "text": "The demo notebook's picture no longer depends on load order."
      }
    ]
  },
  {
    "version": "1.38",
    "name": "Note titles",
    "date": "2026-11-15",
    "summary": "Every note can have its own title, shown at the top of the card.",
    "changes": [
      {
        "type": "added",
        "text": "Notes have an optional title — a line above the text when you jot a note, and a Title field when you edit one. It shows at the top of the card, and Today, search, the trash and the activity list call the note by it. A note can be just a title."
      },
      {
        "type": "added",
        "text": "Titles are cleaned (hidden and direction-changing characters out, spaces collapsed, up to 120 characters) and always shown as plain text. Another note with the same title in the same place (General or the same case) gets a warning; press again to keep both. Duplicating a note gives it “Title (copy)”."
      },
      {
        "type": "removed",
        "text": "The heading groups added in 1.37 (+ Heading in the notes filter row). Notes keep their case or General as before; any heading groups made are simply ignored."
      }
    ]
  },
  {
    "version": "1.37",
    "name": "Many rules at once, and note headings",
    "date": "2026-11-15",
    "summary": "Detections can now be picked several at a time, notes can go under headings of your own, and the rule editor says right away when a title is taken.",
    "changes": [
      {"type": "fixed", "text": "Every script and stylesheet address now carries a fingerprint of the file, so a browser never keeps an older copy after an update — even between two drops of the same version."},
      {"type": "added", "text": "Notes → headings: your own groups for notes, next to General and your cases (+ Heading in the filter row). New notes go under the selected heading, or pick one in the note bar or the edit dialog; a note can be under a heading and pinned to a case. Names are cleaned (hidden and direction-changing characters out, spaces collapsed, up to 40 characters) and must not repeat another heading, a case name or a built-in filter. Renaming and deleting are on the pencil next to the selected heading; deleting keeps the notes and can be undone. A note's ⋯ menu has Change heading."},
      {"type": "fixed", "text": "A rule title that is already taken is flagged right under the title as you type, instead of at the very bottom of the editor after saving."},
      {
        "type": "added",
        "text": "Detections → pick several rules with the boxes in the table or gallery (or every rule the current filters show) to star or unstar them, download them, or delete them together. One rule downloads as its .yml or .yar file; several download as a zip with each rule's file in sigma/ and yara/ folders, plus a JSON bundle that Import reads back with tests and metadata. Deleting asks first and can be undone."
      },
      {
        "type": "fixed",
        "text": "The rule editor's “Revert” is now “Discard changes”: it stays greyed out until you edit something, then throws your unsaved edits away and puts the saved rule back. Before, it could be clicked any number of times and only showed a message."
      }
    ]
  },
  {
    "version": "1.36",
    "name": "Today, the attack chain and sharper reading",
    "date": "2026-11-15",
    "summary": "A Today page across all cases, an ATT&CK attack-chain view, duplicate finding and merging in the vault, and a much broader reading of real-world logs and command lines — checked by a new suite of real-world tests.",
    "changes": [
      {
        "type": "added",
        "text": "Today (in the sidebar): what needs you now across every case, most urgent first — watch alerts, overdue and due notes, indicators a lookup or your indicator store flagged that you have not judged, what arrived in cases since you last opened them, open questions, cases gone quiet for a week, and a due backup. Each with the button that deals with it."
      },
      {
        "type": "added",
        "text": "Timeline → Attack chain: the case's events placed on the ATT&CK stages (including the new Stealth and Defense Impairment) from technique IDs, recognised behaviour, tags and your Sigma rules. Stages missing between the first and last one seen are named as where to look next, each with what to look for and the rules for it."
      },
      {
        "type": "added",
        "text": "Vault → possible duplicates: the same email, domain, URL, phone, handle or person entered twice — different case, defanged, www., trailing slashes, phone punctuation, accents or word order — and names one letter apart, marked “probably”. Merging fills empty fields, keeps every tag, note and link, notes differing values, and can be undone. “Not the same” is remembered."
      },
      {
        "type": "changed",
        "text": "Behaviour recognised in command lines and logs grew from 7 patterns to more than 20: downloads with certutil, bitsadmin, PowerShell and curl | bash; cleared logs and shell history; shadow-copy deletion; scheduled tasks, services, cron and SSH keys; new admin accounts; mshta, rundll32, regsvr32 and msiexec abuse; LSASS dumps, SAM saves and /etc/shadow; domain discovery; PsExec, WMI and WinRM; disabled Defender, firewall or logging; password-protected archives; rclone and upload sites; reverse shells. Everyday admin commands are not flagged."
      },
      {
        "type": "added",
        "text": "Windows events copied as text (Event Viewer or a SIEM message field: “New Process Name: … Process Command Line: …”) are now read into fields, so rules and the timeline understand them."
      },
      {
        "type": "fixed",
        "text": "A domain written in another script (раураl.com) is kept whole and flagged as a look-alike, instead of being cut down to “l.com”."
      },
      {
        "type": "fixed",
        "text": "The graph button on vault cards opens the graph on that entry; the star is yellow everywhere; the coloured side stripes are gone from cards."
      },
      {
        "type": "changed",
        "text": "A new real-world test suite: indicators in messy forms and things that must not be indicators, ten log formats reaching the same fields and rule, 30 attacker command lines and 15 everyday ones, duplicates that must and must not merge, odd timelines, broken files, every built-in rule converted to every SIEM, and random input fed to every engine."
      }
    ]
  },
  {
    "version": "1.35",
    "name": "Detection lab and better notes",
    "date": "2026-11-15",
    "summary": "Build, test and harden detection rules inside OSINTrix — SIEM queries, rule tests, an evasion check and rules drafted from evidence — and a formatting bar for notes.",
    "changes": [
      {
        "type": "added",
        "text": "Rule → Queries: any Sigma rule as Splunk SPL, Microsoft Defender XDR KQL, Microsoft Sentinel KQL (Sysmon), Elastic ES|QL and IBM QRadar AQL — including not, 1 of / all of, null, CIDR ranges and regular expressions. Field names can be remapped per product and are remembered."
      },
      {
        "type": "added",
        "text": "Rule → Tests: events a rule must fire on and must not fire on, kept with the rule, run as you edit and again on every save — a save that breaks a test tells you. Add tests by pasting an event or from what the rule fires on in the current case. Tests travel with rule exports and backups."
      },
      {
        "type": "added",
        "text": "Rule → Evasion: a matching event is changed the way attackers change it — renamed program, ^ and quotes in commands, / or en dashes for flags, shortened PowerShell parameters, extra spaces, environment variables, short paths, IPs written as numbers — and the rule is checked against each, with the fix (for example the OriginalFileName to add) and a one-click |windash."
      },
      {
        "type": "added",
        "text": "Timeline → Select → Draft a rule: a Sigma rule from what the selected events share, checked against all your other evidence for noise, with the selected events saved as its tests."
      },
      {
        "type": "changed",
        "text": "The browser Sigma engine now understands |windash, |cidr, |base64 and |base64offset, and null values; regular expressions are no longer lower-cased before matching."
      },
      {
        "type": "added",
        "text": "Notes have a formatting bar: to-do, bullet, numbered item, heading, bold, code, today's date and a divider. Enter carries a list on, Enter on an empty item ends it, Ctrl+B makes bold. Notes now show headings, bullets, numbers, bold, italics and code."
      },
      {
        "type": "changed",
        "text": "Vault cards say what matters at a glance: the full value, only the fields that are filled in, your note, the verdict with its lookup score, how many records mention it and when, what it is linked to, open questions about it, whether it is watched or also in another case, and a picture for media entries. Copy, timeline and graph are one click away. A new List layout shows every entry in a sortable table."
      },
      {
        "type": "fixed",
        "text": "New rule from the Coverage or Health view now opens the rule editor instead of silently adding rules."
      },
      {
        "type": "fixed",
        "text": "A note's due date is marked overdue against today's date; the rule editor no longer fails when there are no cases."
      }
    ]
  },
  {
    "version": "1.34",
    "name": "The engine works for you",
    "date": "2026-11-15",
    "summary": "Timeline patterns, picture intelligence, automations, a since-you-were-last-here feed, a guided tour, faster long lists and backup reminders — all running in the browser.",
    "changes": [
      {
        "type": "added",
        "text": "Timeline → Patterns: the likely first sign of compromise (with its reasons, the host, and the dwell time after it), bursts of activity against the case's usual rate, quiet periods, hosts that went silent early, cleared logs, time zone mix-ups and impossible dates, and the working hours the activity fits. Each finding opens just its events."
      },
      {
        "type": "added",
        "text": "Media → Picture insights: the same or a near-identical picture in this case or another, the same camera (by serial number, or make and model) across cases, pictures taken within 250 m of pictures in other cases, and signs of editing — an editing program, changes after capture, a future capture date, a disagreeing GPS date, or stripped metadata. Older pictures are read once, the first time the view opens."
      },
      {
        "type": "added",
        "text": "Automations (Playbooks → Automations): when a new indicator appears, evidence mentions something, or an indicator is judged malicious — check it against the indicator store, look it up, watch it, add it to the vault, ask a question, set a verdict or run a playbook. Five ready-made rules. They run while the app is open, act once per item, never on the demo cases, and write everything they do to a log. Automations restored from a backup arrive switched off."
      },
      {
        "type": "added",
        "text": "Since you were last here: a case's Overview lists what arrived while it was closed — evidence (yours and the automations'), new vault entries, lookups that came back, indicator-store and news matches, its indicators turning up in other cases, and notes that fell due."
      },
      {
        "type": "added",
        "text": "A guided tour of the demo case in eight stops, from Help or the setup."
      },
      {
        "type": "changed",
        "text": "Backup reminders after a week of your own work instead of two, on the dashboard and in the sidebar footer, offering automatic folder backup where the browser supports it; the setup offers it too."
      },
      {
        "type": "changed",
        "text": "The indicator store, the known-exploited vulnerabilities list and the detection rules (table and editor) draw only the rows on screen: 50,000 indicators open in about 30 ms, and nothing is cut off at 200 rows any more."
      },
      {
        "type": "fixed",
        "text": "The indicator store no longer fails to draw when there are no cases."
      }
    ]
  },
  {
    "version": "1.33",
    "name": "Media fixes",
    "date": "2026-11-15",
    "summary": "Two fixes from using the new media features.",
    "changes": [
      {
        "type": "fixed",
        "text": "Switching between a case's tabs now closes the details panel, so a vault entry opened on the Vault tab no longer sits over the Overview. Opening a record from elsewhere still keeps it selected."
      },
      {
        "type": "added",
        "text": "The New image / video form has a file field: choose or drop the picture, video, audio or saved page, and the title, media type and resolution fill themselves in. Files over 50 MB are recorded by fingerprint."
      },
      {
        "type": "fixed",
        "text": "Videos recorded by browsers and some phones, which leave their length out, now show their length."
      }
    ]
  },
  {
    "version": "1.32",
    "name": "Media in every case",
    "date": "2026-11-15",
    "summary": "Pictures, videos, audio and saved web pages can now be added to a case from anywhere — drop them, paste a screenshot, or use the new Media tab — and are kept as untouched evidence without filling the browser.",
    "changes": [
      {
        "type": "added",
        "text": "Media tab in every case: a grid of the case's pictures, videos, audio, saved web pages and documents with previews, video length, picture size and filters. Videos and audio play inside the app."
      },
      {
        "type": "added",
        "text": "Drop files anywhere on a case, or paste a screenshot with Ctrl+V, and they become evidence records with their SHA-256, picture size or length, camera and GPS position when the photo has them."
      },
      {
        "type": "added",
        "text": "Image / video entries in the Vault can hold the file itself, not just a link; the entry fills in its title, type and resolution from the file."
      },
      {
        "type": "added",
        "text": "Files over 50 MB are recorded with their name, size and SHA-256 instead of being stored, so you can later prove the copy on your computer is the same file."
      },
      {
        "type": "changed",
        "text": "Space: the same file added twice is stored once; pictures and videos get a small preview so lists stay fast while the original is kept unchanged; you are told when browser storage is over 85% full."
      },
      {
        "type": "changed",
        "text": "Back up everything now asks whether to include files and shows the size of each choice. A backup made without files says so when it is restored."
      },
      {
        "type": "fixed",
        "text": "Videos could not play inside the app because the page's security policy had no rule for media; it now allows only the app's own stored files."
      }
    ]
  },
  {
    "version": "1.31",
    "name": "Big lists and nothing lost",
    "date": "2026-11-15",
    "summary": "The timeline and the entity table now show every row of a large case, drawing only what is on screen. A data-safety review of saving, restoring, exporting and importing found eight bugs, three of which could lose data; all are fixed and covered by tests.",
    "changes": [
      {
        "type": "changed",
        "text": "Big lists: the case timeline and the entity table draw only the rows near the screen, so a 10,000-event timeline opens in about 75 ms instead of 600 ms, and the table shows all entities instead of stopping at 400. Day headings stay pinned, the keyboard (j / k) walks every event, and opening a record scrolls straight to it."
      },
      {
        "type": "fixed",
        "text": "Data safety: “Remove leftover files”, freeing notebook space, emptying the trash and forgetting a recent file no longer delete files that a restore point still needs. Going back to that restore point now brings its attachments and pictures back too."
      },
      {
        "type": "fixed",
        "text": "Data safety: turning on encryption or changing the passphrase now saves the workspace first and then re-encrypts restore points and files. If the tab closes part way, OSINTrix finishes the job on the next start (asking for the previous passphrase if needed) instead of leaving files that no passphrase opens."
      },
      {
        "type": "fixed",
        "text": "Data safety: a damaged or unreadable restore-point list is rebuilt from the restore points themselves instead of being replaced by an empty one, and two restore points made at the same moment can no longer overwrite each other’s list."
      },
      {
        "type": "fixed",
        "text": "Undoing a backup import, or going back to a restore point, now also brings back the indicator store."
      },
      {
        "type": "fixed",
        "text": "Case files now carry the case’s notes and the verdicts on its indicators; competing-hypothesis evidence keeps pointing at the right records after import. An imported copy of the demo case is no longer removed by “Remove sample data”."
      },
      {
        "type": "fixed",
        "text": "Restoring an entry from the trash keeps relationships whose other end is still in the trash; they come back when that entry is restored."
      },
      {
        "type": "fixed",
        "text": "With no cases at all, Playbooks, the Decoder and New evidence no longer fail; they offer to make a case."
      },
      {
        "type": "fixed",
        "text": "Exported detection rules import back as the same rules instead of duplicates, and keep their stars, references and linked case."
      },
      {
        "type": "fixed",
        "text": "Long labels in menus (for example on a news story) stay on one line instead of overlapping."
      },
      {
        "type": "changed",
        "text": "The share dialog remembers your last TLP, redaction and file choices."
      },
      {
        "type": "fixed",
        "text": "Hardening from the same review: imported cases, links and verdicts are checked field by field; spreadsheet formulas hidden behind spaces or full-width signs are neutralised in CSV; key strengths outside the safe range are refused; crafted Office metadata, Windows event logs and Word pictures can no longer stall the tab or fill memory."
      }
    ]
  },
  {
    "version": "1.30",
    "name": "Hardened, faster, shareable, easy to start",
    "date": "2026-11-15",
    "summary": "An independent security review of everything added since v1.24 found three medium and several low issues; all are fixed. Large cases are much faster. A share package hands a case to another team in one ZIP, and a two-minute setup gets new users from nothing to a working investigation desk.",
    "changes": [
      {
        "type": "fixed",
        "text": "Security: an imported backup can no longer change this browser's relay address or token, API keys, lookup sources, online-check schedule or per-case auto-checks. It also cannot override the address of a built-in feed; a crafted file could otherwise have sent watched indicators and the relay token to someone else's server."
      },
      {
        "type": "fixed",
        "text": "Security: downloading a restore point no longer includes API keys, the relay token or the signing key."
      },
      {
        "type": "fixed",
        "text": "Security: a crafted STIX file can no longer freeze the tab (pattern parsing is now linear and capped), and report redaction stays fast on long runs of dots."
      },
      {
        "type": "fixed",
        "text": "Security: scores and history imported from a backup are reduced to plain numbers and text before they are shown. Rule-tuning text is escaped, CVE reference links are checked like every other link, and API keys never follow a redirect."
      },
      {
        "type": "fixed",
        "text": "Relay hardening: rate-limits before checking the token, refuses encoded paths, passes on only the query parameters each service needs, caps request bodies while reading them, and does not follow upstream redirects."
      },
      {
        "type": "fixed",
        "text": "Redaction no longer masks dates and times as if they were phone numbers."
      },
      {
        "type": "changed",
        "text": "Speed on a 10,000-record case: smart search went from 500 ms to about 10 ms, editing on the Overview from 420 ms to under 100 ms, and opening the graph from 640 ms to about 65 ms. On very large cases the copilot reads the case just after the page appears instead of holding it up. Record and entry look-ups use an index, and observations and ATT&CK coverage are remembered until the data changes."
      },
      {
        "type": "added",
        "text": "Share package (Report → Share): one ZIP with a read-only page, a STIX 2.1 bundle, a MISP event, the case's Sigma and YARA rules, an indicators CSV and the Markdown report. The page is a single HTML file with no scripts that loads nothing; indicators in it are defanged. Every file is marked with the chosen TLP, and MANIFEST.txt holds a SHA-256 for each file. Redaction masks people's details in the page, report and CSV and leaves them out of STIX and MISP."
      },
      {
        "type": "added",
        "text": "First-run setup in five steps: choose offline, free sources or free sources plus your relay; pick exactly which services may see what you investigate; connect and test the relay; switch on news, known-exploited CVEs, EPSS, CVE records and ATT&CK updates; then set a passphrase and choose where to start. Offered from the welcome screen and the dashboard, and re-runnable from Settings."
      },
      {
        "type": "added",
        "text": "Tests: a 10,000-record speed test, accessibility checks on every new screen in light and dark, and regression tests for each security fix (60+ end-to-end tests in all)."
      }
    ]
  },
  {
    "version": "1.29",
    "name": "Detection coverage, rule health and file triage",
    "date": "2026-11-15",
    "summary": "Detections now shows your rules on the ATT&CK tactics next to what your cases actually show, so the gaps that matter stand out and can be drafted as rules. A health check lints every rule and runs it over all your evidence to find noisy, broken and duplicate rules, with tuning suggestions. The file inspector opens with a triage verdict, its reasons and an entropy map.",
    "changes": [
      {
        "type": "added",
        "text": "Detections → Coverage: techniques covered on each ATT&CK tactic, highlighted where your cases show them. \"Gaps that matter\" lists techniques your evidence shows with no rule, and Draft a rule writes a starter Sigma rule from the evidence that showed it."
      },
      {
        "type": "added",
        "text": "Detections → Health: every rule is linted (undefined or unused selections, values too short or too common on their own, invalid regexes, missing level, false positives, id or technique, short YARA strings) and run over the evidence of every case."
      },
      {
        "type": "added",
        "text": "Health finds rules that fired, noisy rules (firing on a large share of records or mostly on benign evidence), broken rules and duplicates that fire on the same records. YARA features the browser cannot run are marked as untestable, not broken."
      },
      {
        "type": "added",
        "text": "Tuning suggestions: for a noisy Sigma rule, the field values most of its hits share become a ready filter block to copy into the rule."
      },
      {
        "type": "added",
        "text": "The case copilot points out techniques in a case that no detection rule covers."
      },
      {
        "type": "added",
        "text": "File triage: the file inspector opens with a score out of 100 and every reason. It weighs double extensions and hidden right-to-left names, wrong extensions, programs, shortcuts and scripts, macros and remote templates, active PDF content, packers, high-entropy sections, suspicious imports, impossible compile times, hidden appended data, programs embedded in files, near-random content, malicious strings (encoded PowerShell, download cradles, injection, shadow-copy deletion, ransom notes, Mimikatz, offensive frameworks), network addresses inside, indicators already known to be malicious, earlier verdicts and live lookups on the hash, and YARA matches."
      },
      {
        "type": "added",
        "text": "Entropy map: a bar for each part of the file shows where packed or encrypted data sits. Mark the file malicious or suspicious from the triage card; the downloaded report and the evidence saved to the case include the triage."
      }
    ]
  },
  {
    "version": "1.28",
    "name": "Report writer and OSINT research",
    "date": "2026-11-15",
    "summary": "Reports now write the parts analysts write last — a bottom line with a stated confidence, the attack path, recommendations with reasons, and the limitations — and export to Word. The Forensics kit gains look-alike domain hunting and identity pivots, and every indicator's details suggest the next steps worth taking.",
    "changes": [
      {
        "type": "added",
        "text": "Report bottom line: what happened, to which hosts, when, how, what is confirmed and what is still open, drafted from the case with a stated confidence (high, moderate or low). Rewrite it in your own words or go back to the draft."
      },
      {
        "type": "added",
        "text": "Attack path: the ATT&CK tactics in the order the evidence shows them, each with the first record and a citation."
      },
      {
        "type": "added",
        "text": "Recommendations sorted into Now, Next and Later, each with its reason and the indicators it covers. They include isolating hosts, blocking network indicators, purging phishing mail, resetting credentials, hunting hashes, removing persistence, patching exploited CVEs, preserving logs, domain takedown via the registrar, detections, watching and lessons learned. Drop any one, and bring it back."
      },
      {
        "type": "added",
        "text": "Confidence and limitations: what the confidence rests on (findings, answers, confirmations, timeline, sources) and what weakens it (open questions, missing times, assumed time zones, unchecked indicators, disagreements, close hypotheses)."
      },
      {
        "type": "added",
        "text": "The full report lists every malicious or suspicious indicator with its live score. Reports export to Word (.docx) with the relationship map, as well as Markdown and PDF."
      },
      {
        "type": "added",
        "text": "Look-alike domains (Forensics kit): over 250 imitations of a domain — typos, keyboard slips, look-alike and Unicode characters, bit flips, other endings and added words. Check which exist through Google DNS, with registration age from RDAP. Each is ranked by risk (receives mail, newly registered, hard to spot; on the original's own servers counts against). Add the risky ones to a case or export CSV."
      },
      {
        "type": "added",
        "text": "Identity pivots (Forensics kit): a username across more than 50 sites in seven groups, with ticks remembered; an email address taken apart (canonical Gmail form, sub-address, disposable inbox, role account, likely name and year, mail provider from its MX records, Gravatar); a phone number read into country and international format with messaging and lookup links."
      },
      {
        "type": "added",
        "text": "Next steps in an indicator's details: what is worth doing next given what is already known, such as checking it online, finding its registration date, hunting look-alikes, pivoting on the username or finding the abuse contact."
      },
      {
        "type": "changed",
        "text": "Printed reports leave out on-screen controls."
      }
    ]
  },
  {
    "version": "1.27",
    "name": "Copilot, graph intelligence and smart search",
    "date": "2026-11-14",
    "summary": "Every case gets a copilot that reads it and says what to do next, what is missing and what the story so far is. The graph now shows risk spreading from malicious entries, its key nodes and links hidden in your lookups, and can expand a node online. Search understands plain questions such as \"malicious IPs last week in TN-2026-014\" or \"what talks to 203.0.113.47\".",
    "changes": [
      {
        "type": "added",
        "text": "Case copilot on the Overview: ranked next steps, each with its reason and one button. Steps include indicators in your threat feeds, ones flagged by live lookups, exploited CVEs, never-checked indicators, relationships to review, entries close to malicious infrastructure, the right playbook for the kind of case, watching and detection rules for malicious indicators, and open questions."
      },
      {
        "type": "added",
        "text": "Copilot gaps: records without a time, times read in an assumed time zone, verdicts the live lookups disagree with, vault entries nothing supports or connects, and a missing scope."
      },
      {
        "type": "added",
        "text": "The story so far: a plain-language summary built only from the case covering the time span and hosts, indicators and verdicts, what the evidence shows, ATT&CK techniques, malware, feed hits, exploited CVEs and open questions. Copy it or save it as a note."
      },
      {
        "type": "added",
        "text": "Check new indicators online, per case and off by default. When it is on, new public indicators in that case are looked up with your switched-on sources as evidence arrives, and you are told if one looks malicious."
      },
      {
        "type": "added",
        "text": "Graph risk: suspicion spreads from malicious entries along your links. It weakens with every hop, with weaker links, and for people, organisations and places, which are often victims. Benign entries stop it. Each score names the malicious entry it comes from and the path. Colour by risk shades the graph."
      },
      {
        "type": "added",
        "text": "Graph key nodes: PageRank, bridges between groups and connections combined, with the reason for each."
      },
      {
        "type": "added",
        "text": "Hidden links: saved live-lookup answers are compared, without new requests. Entries sharing a certificate, IP, favicon, name servers, JARM or registration day appear as suggested relationships."
      },
      {
        "type": "added",
        "text": "Expand online: a node's live lookups bring back what it resolves to, its hostnames, certificate names, samples and subdomains as new linked entries, with Undo."
      },
      {
        "type": "added",
        "text": "Smart search: plain questions are turned into filters and shown back as chips under \"Understood as\". Filters cover indicator kind, verdict, flagged or unchecked, watched, in your feeds, exploited, time seen (today, last 3 days, this month, September 2026…), case, host, port, country, network (\"hosted on vultr\", AS numbers), registration date, Tor, related to another indicator, and riskiest, most seen or newest first. They run over every case."
      }
    ]
  },
  {
    "version": "1.26",
    "name": "Live investigation engine",
    "date": "2026-11-14",
    "summary": "Threat Intel now asks the services analysts use — Shodan, VirusTotal, AbuseIPDB, GreyNoise, OTX, urlscan, abuse.ch, RDAP, DNS, certificate logs and more — at the moment you investigate, and weighs every answer into one scored verdict with its reasons. A whole case can be checked at once and its indicators grouped by shared infrastructure. Bundled data is now only a fallback: KEV, ATT&CK and CVE records come live.",
    "changes": [
      {
        "type": "added",
        "text": "Investigate tab: paste an IP, domain, URL, file hash, CVE or ASN and every lookup source you switched on is asked in parallel. Answers appear as they arrive, one card per source with its key facts and a link to the source's own page."
      },
      {
        "type": "added",
        "text": "Verdict engine: one score out of 100 (Malicious, Suspicious, Benign or Nothing found) from all sources, weighted by how much each source is trusted, how strong its evidence is and how old it is, with agreement between independent sources counting for more. Every verdict lists its reasons and a confidence level. Mark it as your verdict in one click."
      },
      {
        "type": "added",
        "text": "Lookup sources that work straight from the browser: Shodan InternetDB, DNS (Google DoH), RDAP registration data, ipinfo, RIPEstat, Tor relays (Onionoo), CertSpotter, HackerTarget, the Wayback Machine, AlienVault OTX, Have I Been Pwned breaches, CVE.org with CISA's exploitation assessment, and FIRST EPSS. Shodan works with your key."
      },
      {
        "type": "added",
        "text": "Through your own relay: VirusTotal, AbuseIPDB, GreyNoise, urlscan.io, crt.sh, NVD and abuse.ch ThreatFox, URLhaus and MalwareBazaar — services that refuse browser requests."
      },
      {
        "type": "added",
        "text": "The relay: a small Cloudflare Worker in tools/relay that you deploy to your own account. It keeps API keys server-side, forwards only to listed hosts and paths, checks a token, allows only your origins and rate-limits. Set its address and token, and test it, in Sources → Lookups."
      },
      {
        "type": "added",
        "text": "Leads: hostnames, subdomains, resolved addresses, certificate names and related samples found by the sources, each one click from its own investigation or the case."
      },
      {
        "type": "added",
        "text": "Investigate a whole case: every public IP, domain, URL, hash and CVE is checked in a queue with progress, ranked by score, and the flagged ones can be marked together."
      },
      {
        "type": "added",
        "text": "Correlation: indicators that share a TLS certificate, IP address, favicon, name servers, JARM fingerprint, registration day and registrar, page title, malware family or network are grouped, with links weighted by how rare the shared trait is. Link on the graph draws the groups as relationships in the case."
      },
      {
        "type": "added",
        "text": "News, For you: stories are ordered by what matters to you — indicators from your cases and watchlist, your stack, known-exploited CVEs, severity, feed hits and how many sources report it — and the order learns from what you mark relevant or dismiss. Each story says why it is near the top. Newest first is still available."
      },
      {
        "type": "added",
        "text": "Watchlist online checks: watched IPs, domains, URLs, hashes and CVEs can be re-checked every hour, 6 hours or day while the app is open, or with Check now. New ports and addresses, more detections, higher abuse scores, new reports and verdict changes are listed under Changes and announced."
      },
      {
        "type": "added",
        "text": "The indicator details panel shows the last live verdict and an Investigate button."
      },
      {
        "type": "added",
        "text": "MITRE ATT&CK can be refreshed live from MITRE (checked at most once a week) and kept in this browser; the bundled copy is the fallback."
      },
      {
        "type": "changed",
        "text": "CVE details come from the official CVE.org record, which allows browser access, with CISA's exploitation assessment shown on the CVE page. NVD scores fill in through the relay when the record has none."
      },
      {
        "type": "changed",
        "text": "abuse.ch indicator feeds are fetched through the relay, which holds the Auth-Key, since abuse.ch does not allow browser access."
      },
      {
        "type": "changed",
        "text": "The Content Security Policy names each lookup host; the only wildcard is *.workers.dev for your relay."
      },
      {
        "type": "changed",
        "text": "Answers from sources are kept for a while (encrypted with the workspace) so the same indicator is not asked twice; Sources → Lookups → Clear saved answers removes them. API keys and the relay token are never put in backups."
      },
      {
        "type": "fixed",
        "text": "Watchlist showed \"just now ago\"."
      }
    ]
  },
  {
    "version": "1.25",
    "name": "Threat Intel, professional edition",
    "date": "2026-11-14",
    "summary": "Threat Intel becomes a full CTI desk: news read for CVEs, actors, malware and ATT&CK techniques; known-exploited vulnerabilities with EPSS and CVSS and a My stack watchlist; an indicator store that imports and exports STIX 2.1, MISP and CSV; offline MITRE ATT&CK with actor pages and Navigator layers; and one-click threat briefs. Every live source is off until you switch it on.",
    "changes": [
      {"type": "added", "text": "Threat Intel has five tabs: News, Vulnerabilities, Indicators, Actors & ATT&CK and Briefs."},
      {"type": "added", "text": "News: the same story from several sources is grouped into one, with +N sources. CVEs, ATT&CK technique IDs, threat actors, malware, vendors and indicators are read from every story and shown as chips you can click."},
      {"type": "added", "text": "News triage: Inbox, Relevant, Starred, All and Dismissed, with unread markers, Mark all read, actioned and undo. Filter by category, source, an extracted CVE, actor or vendor, Mentions my cases or My stack."},
      {"type": "added", "text": "News: a Needs attention panel when feed indicators appear in your cases or exploited vulnerabilities hit your stack, and a This week panel with the most mentioned CVEs, actors, techniques and vendors."},
      {"type": "added", "text": "Ten more news sources you can switch on: CISA advisories, NCSC UK, Cisco Talos, Unit 42, Securelist, Check Point Research, The DFIR Report, SecurityWeek, Dark Reading and MSRC."},
      {"type": "added", "text": "Vulnerabilities: the CISA Known Exploited Vulnerabilities catalog is bundled (1,781 entries) and can be refreshed live. See CVEs in the news, all KEV or only your stack, with ransomware use, EPSS and CVSS columns."},
      {"type": "added", "text": "My stack: watch the vendors and products you run. Stories and exploited vulnerabilities that touch them are flagged in News, Vulnerabilities and the brief."},
      {"type": "added", "text": "CVE pages: the KEV entry and due date, EPSS from FIRST and CVSS from NVD on demand, the stories that mention it, reference links, and Add to case."},
      {"type": "added", "text": "Indicators: a store of up to 50,000 indicators with TLP, confidence, first and last seen, expiry, tags and sources, kept in this browser and encrypted when encryption is on."},
      {"type": "added", "text": "Indicator import: STIX 2.1 bundles (patterns, observables, TLP markings, indicates relationships), MISP events (tags, objects, composite types), ThreatFox and Feodo exports, CSV with any common header, or plain lists. The format is detected automatically."},
      {"type": "added", "text": "Indicator feeds you can switch on: abuse.ch ThreatFox, Feodo Tracker and URLhaus, with an optional Auth-Key. They merge into the store with a 14-day expiry when you refresh."},
      {"type": "added", "text": "Indicator export: STIX 2.1, MISP or CSV of the indicators shown, every live indicator, or a whole case, with a TLP marking."},
      {"type": "added", "text": "Indicators from your feeds that also appear in a case are flagged in Threat Intel and on the indicator in the case (In your feeds), and CVEs in CISA KEV are marked Known exploited."},
      {"type": "added", "text": "Actors & ATT&CK: MITRE ATT&CK Enterprise is bundled offline (706 techniques, 178 groups, 842 malware and tools). Each actor page shows aliases, techniques, software, related groups and your stories."},
      {"type": "added", "text": "ATT&CK heatmaps by tactic for techniques in the news or for one actor, exportable as an ATT&CK Navigator layer."},
      {"type": "added", "text": "Briefs: build a threat brief for 24 hours to 30 days from starred, relevant and critical stories, new KEV entries, top actors and techniques and feed hits in your cases, with a TLP marking. Save it to the Notebook, download Markdown or copy it."},
      {"type": "added", "text": "Sources has three tabs: News feeds, Vulnerability data (KEV, EPSS, NVD) and Indicator feeds. Each source shows the one host it contacts and its last status, and is off until you switch it on."},
      {"type": "changed", "text": "The story panel adds Star, Relevant, Actioned and Dismiss, the extracted CVEs, actors, techniques and vendors, and the other sources that reported the same story."},
      {"type": "changed", "text": "Backups now include the indicator store. Feed API keys are never included."},
      {"type": "changed", "text": "Security: the page may connect only to named hosts, each opt-in: api.rss2json.com, raw.githubusercontent.com, api.first.org, services.nvd.nist.gov and three abuse.ch hosts. Every imported value is re-validated, text is capped and stripped of HTML, javascript: links are dropped, and CSV exports neutralise formulas."}
    ]
  },
  {
    "version": "1.24",
    "name": "Cases board and design pass",
    "date": "2026-11-14",
    "summary": "The Cases page gets two views you can switch between: board cards that show each case's own relationship graph, and a list built for scanning. Buttons, inputs, filters, menus and search are larger and more consistent across every page.",
    "changes": [
      {"type": "changed", "text": "Cases page redesigned. Board view (the default): each card shows a small picture of the case's own graph with malicious entries ringed in red, entry and malicious counts, status, the top entries, questions answered and when it last changed."},
      {"type": "added", "text": "Cases list view: one row per case grouped into Pinned, Active, In review and Archived, with questions answered, entries, records, malicious count, a 12-week activity chart and last update. Switch with Board and List; your choice is remembered."},
      {"type": "added", "text": "Cases: find a case by name, code, scope or owner, and sort by last activity, name, most malicious, most entries or newest. Pinned cases stay at the top."},
      {"type": "changed", "text": "Buttons, icon buttons and inputs are taller with more padding; selects have a proper arrow; filter chips use the accent colour when on instead of black, in light and dark themes."},
      {"type": "changed", "text": "The search palette (Ctrl+K) is wider with a larger input, and its scope filters wrap instead of hiding after CTF. The search bar at the top is larger."},
      {"type": "changed", "text": "Toolbox: the filter row, list and grid switch and bulk bar are restyled, and the menu behind a tool's three dots no longer scrolls."},
      {"type": "changed", "text": "Graph: the Map, Arrange and other tools stay visible, and the details panel opens below the toolbar instead of covering it."},
      {"type": "changed", "text": "CTF cheatsheets redesigned: the categories and their command groups are one list on the left, styled like Reference. One search, then Commands, Recognise it, Gotchas and First moves as tabs, so the commands get the full width."},
      {"type": "changed", "text": "CTF cheatsheets: Target, File, Wordlist, Your IP and Port moved into a Values button. Its popover fills every command as you type, and the button shows what is set."},
      {"type": "changed", "text": "CTF write-ups: the list is grouped by event, each row showing category, points, solved, age and the TL;DR. Search, All, Mine and Imported, and a category filter behind one button."},
      {"type": "added", "text": "Nothing is lost on refresh. Certificates, crt.sh results and signed programs you open, cloud configs and logs, and Lab files (inspector, packet capture, SQLite, image) are kept in this browser and reopen after a refresh. Decoder input, Lab text tools, the log parser, the SQL console and open tabs come back too."},
      {"type": "added", "text": "History: Certificates, Cloud and each Lab tool have a History button listing what you opened. Reopen or delete each item on its own, or delete all. Certificates History also lists what is saved in the case, and each can be moved to the trash."},
      {"type": "added", "text": "Settings → Storage shows how much space recent tool inputs use, with a Manage button to delete them one by one. Files over 50 MB are not kept, and private keys never are."},
      {"type": "added", "text": "Restore points, recent searches in Ctrl+K and recent query runs can each be deleted on their own."},
      {"type": "fixed", "text": "Security: decompressing data (Decoder, ZIP and Office files in the Lab, notebook .docx import, compressed HTTP bodies in packet captures) now stops at a size limit, so a small decompression bomb cannot freeze the tab."},
      {"type": "fixed", "text": "Security: every download gets a safe file name with no path parts, reserved names or control characters such as right-to-left overrides. The Lab image tool now refuses non-images and files over 100 MB."},
      {"type": "changed", "text": "Recent tool inputs are encrypted with your passphrase when encryption is on, are re-encrypted when it changes, and are not included in backups."},
      {"type": "fixed", "text": "The Toolbox menu behind a tool's three dots, and every other menu, now closes when the page scrolls instead of floating away from its button."},
      {"type": "fixed", "text": "CTF cheatsheets: your Target value is no longer filled into email addresses such as target@example.com."},
      {"type": "changed", "text": "Decoder, Certificates, Cloud and CTF: cleaner focus on the input, roomier indicator and pivot tables, Test it inputs that match the rest of the app, and restyled filters and search bars."}
    ]
  },
  {
    "version": "1.23",
    "name": "Certificates, advanced",
    "date": "2026-11-13",
    "summary": "Certificates become an investigation tool: an investigator's read of each certificate, its indicators with pivots and the records in your cases that already mention them, plus signed-program checks, a clearer comparison, key reuse, Certificate Transparency analysis, hunting queries and exports. Certificates now use the full width.",
    "changes": [
      {"type": "changed", "text": "No more input column: a bar along the top shows what is open and where it came from, with Paste (a large paste window), Open file, Examples and Saved. Paste with Ctrl+V or drop a file anywhere on the page. Certificates use the full width, and the text is larger."},
      {"type": "added", "text": "Investigator's read: a plain-English assessment of each certificate (who it belongs to, the infrastructure it names, timing, red flags, key reuse) with next steps you can click, and Copy for a report."},
      {"type": "added", "text": "Indicators and pivots: every domain, IP address, email and organisation in the certificate with VirusTotal, urlscan, WHOIS, AbuseIPDB, Shodan and more. Each shows whether it already appears in your cases; select them to add to the case graph or copy them defanged."},
      {"type": "added", "text": "Already in your cases: records in any case that mention the certificate's names, IP addresses or fingerprints, or share a registered domain with them, one click away. The Transparency logs view marks names already in your cases and has a lookup menu per name."},
      {"type": "added", "text": "Signed Windows programs: drop an .exe, .dll or .sys file to read its Authenticode signature. The file is hashed and checked against the signature, the signer's signature is verified, and the publisher, program description, timestamp, dual signatures and data appended after the signature are shown. The file's SHA-256 links to VirusTotal."},
      {"type": "added", "text": "Compare: says how two certificates relate (same certificate, issuer and issued, renewal with or without a new key, same owner through a shared key, names moved to another CA, related domains), with both certificates side by side, their lifetimes on one timeline, names only in A, in both and only in B, and a grouped field-by-field table that shows just the differences or every field."},
      {"type": "added", "text": "Key reuse: a certificate whose public key appears in other certificates in the case is flagged, with a one-click comparison. Different names on one key tie them to the same owner."},
      {"type": "added", "text": "Transparency logs: paste or open the JSON that crt.sh returns for a domain. Precertificate and final copies are merged; you get every name with first and last issue dates, what is valid now, interesting hosts such as VPN, login and build systems, names new in the last month, lookalikes, issuers and a timeline of issuance. Filter, sort, copy, export CSV or add the names to the case."},
      {"type": "added", "text": "New guide chapter, Types of certificates and what they are for: website, client authentication, device, trusted server CA versus trusted client CA (mutual TLS), root and intermediate CAs, code signing, email (S/MIME), Windows logon, document signing and timestamping. Each covers what it is for, how to recognise it, where you meet it and how investigators and attackers use it, with a fictional example to open and a side-by-side table. The decoder labels every certificate with its type and links to the matching section, and the investigator's read explains it."},
      {"type": "added", "text": "Test it: does a certificate cover a host or URL (wildcards matched the way browsers do), and was it valid at a given moment."},
      {"type": "added", "text": "Hunt for it: ready-to-copy Shodan, Censys and crt.sh queries, Suricata rules by fingerprint and serial, a Defender and Sentinel query for code signing certificates, and a PowerShell check for planted roots."},
      {"type": "added", "text": "Export a certificate as PEM, DER, JSON or a text report, or the whole chain as PEM. Fingerprints now include the key SHA-256, with a crt.sh link to every certificate sharing the key."},
      {"type": "fixed", "text": "Code signing and other non-website certificates are no longer labelled DV or OV."},
      {"type": "changed", "text": "Text is a little larger everywhere by default, and Settings → Text size now scales every page and section evenly: all font sizes follow one text scale instead of fixed sizes."},
      {"type": "changed", "text": "What's new redesigned: a header with release and change totals and a breakdown bar, large filter tiles by type, a search that marks matches, a release list to jump to any version, changes grouped by type in each release, and older releases folded until opened. Filtering and searching no longer redraw the page."},
      {"type": "fixed", "text": "A button whose icon is missing no longer shows an empty gap."},
      {"type": "fixed", "text": "The Trash count in the sidebar could include items older than 30 days that had already expired; they are now cleared before counting, so the count matches the Trash page."},
      {"type": "fixed", "text": "Security: every CSV export (records, indicators, entities, graph, places, audit log, SQLite results, Transparency logs) now neutralises cells that start with = + - or @, so evidence text can never run as a spreadsheet formula when the file is opened in Excel or Sheets."},
      {"type": "changed", "text": "Certificates: key files and PKCS#12 bundles (.pfx, .p12, .key) are refused before being read; the PGP and OpenSSH private key formats are caught too. Saved certificates record where they came from and when they were examined. Suricata rules get a stable sid per certificate, internationalised host names are matched in their xn-- form, and very large inputs no longer risk a crash when exported."}
    ]
  },
  {
    "version": "1.22",
    "name": "Certificates",
    "date": "2026-11-13",
    "summary": "A Certificates section: decode certificates, chains and signing requests in the browser, see what they reveal, and learn how certificates work.",
    "changes": [
      {"type": "added", "text": "Decoder: paste PEM, base64 or hex, or open .crt, .cer, .der, .pem, .csr or .p7b files (openssl s_client output works too). Shows who a certificate is for and who issued it, its lifetime, every name it covers, each extension in plain English, SHA-256, SHA-1 and key-pin fingerprints, and the raw ASN.1 structure."},
      {"type": "added", "text": "Findings for investigators: lookalike brand names, unrelated domains on one certificate, Cobalt Strike and openssl defaults, self-signed certificates claiming a brand, weak keys and hashes, lifetimes longer than public CAs may issue (including the 200-day limit from March 2026), tiny serials, AD CS logon certificates (UPN plus client authentication) and enrollment agents."},
      {"type": "added", "text": "Chain: certificates in any order are sorted leaf to root and every signature is verified with the browser's own cryptography (RSA, RSA-PSS, ECDSA and Ed25519). A missing root is named; a broken signature is shown in red."},
      {"type": "added", "text": "CSR: what a signing request asks for, its signature, key strength, missing or mismatched names, a stored challenge password, and whether it shares a key with a certificate."},
      {"type": "added", "text": "Save a certificate to the case as evidence: its names and fingerprints become entities, and the issue date lands on the timeline. Pivot links to crt.sh, Censys, Shodan and VirusTotal."},
      {"type": "added", "text": "How certificates work: ten short chapters with diagrams, an annotated certificate, commands and flashcards that go to your Notebook in one click."},
      {"type": "added", "text": "PCAP: certificates in TLS 1.2 and older handshakes open in the decoder. Certificate files dropped on the capture dialog open there too."},
      {"type": "added", "text": "Private keys are never read: if one is pasted, it is removed from the box with a warning."}
    ]
  },
  {
    "version": "1.21",
    "name": "Safe keeping",
    "date": "2026-11-08",
    "summary": "Nothing lost on refresh, automatic backup to a folder, notebook pictures out of the main save, and a Storage panel that warns early and frees space.",
    "changes": [
      {"type": "changed", "text": "Notebook pictures and files are stored as separate blobs in the browser, encrypted with the workspace when encryption is on. Autosaves and restore points no longer copy them, so saving stays fast with hundreds of screenshots."},
      {"type": "fixed", "text": "Export everything now includes notebook pictures and files, and importing the backup brings them back."},
      {"type": "added", "text": "Settings → Storage: space used against what this browser allows, a breakdown (workspace, case attachments, notebook pictures, restore points, trash) and one-click clean-up: empty the trash, keep only the newest restore points, free deleted notebook pictures, remove leftover files."},
      {"type": "added", "text": "Early warnings: the top bar shows when storage passes 85% or under 200 MB is free, a failed save is shown in red with a prompt to free space or export, and pictures, attachments and imports that would not fit are refused before anything is written."},
      {"type": "added", "text": "Ask the browser to keep the data (persistent storage), so it is not cleared when the disk is short."},
      {"type": "fixed", "text": "Notebook data in an imported backup is checked field by field and every page is cleaned again; Word files that would unpack to an unsafe size are refused."},
      {"type": "added", "text": "Automatic backup to a folder (Chrome and Edge): pick a folder once, such as Documents or a OneDrive or Google Drive folder, and a full backup is written there a few minutes after changes, as osintrix-latest.json plus one dated copy per day (the last 7 are kept). Encrypted workspaces write encrypted backups. If the browser needs permission again after a restart, backup pauses and one click resumes it."},
      {"type": "added", "text": "The top bar shows Saving… while a change is still being written. Closing or refreshing the tab at that moment makes the browser ask before leaving, and the save finishes while it asks, so large and encrypted workspaces no longer lose the last change. A workspace with everything saved never asks."},
      {"type": "fixed", "text": "Typing right before a refresh or closing the tab is kept. Pending page text, titles and sources are saved first, and when a workspace is too big for the instant localStorage copy, the last page edits go to a small journal that is merged back on the next start."},
      {"type": "fixed", "text": "Pictures from deleted pages are kept for 30 days, so undo and restore points bring them back. A notebook page opened in a second tab is read-only, so edits there cannot be lost."}
    ]
  },
  {
    "version": "1.20",
    "name": "Notebook",
    "date": "2026-11-08",
    "summary": "A notebook for what you learn from courses, labs and reading, with screenshots, code, links and flashcards, that exports to Word, Google Docs, OneNote and Markdown.",
    "changes": [
      {"type": "added", "text": "Notebook: notebooks hold sections and pages. Pages take text, headings, lists, checklists, code blocks, tables, key takeaways, link cards and pictures. Paste a screenshot or drop a file anywhere on a page; pasted web pages and Google Docs keep their formatting, and anything unsafe is removed."},
      {"type": "added", "text": "Markdown shortcuts while typing: # and ## for headings, - or 1. for lists, [] for a checklist, > for a quote and three backticks for code. Ctrl K adds a link, Ctrl Shift H highlights."},
      {"type": "added", "text": "Flashcards from any line starting with Q: followed by a line starting with A:, or from selected text. A review panel spaces them out over days, like Anki."},
      {"type": "added", "text": "Export a page, section, notebook or everything as a Word document, a single HTML file, Markdown with images in a .zip, or a PDF, with a live preview. Copy as rich text pastes into OneNote, Docs or Word. Everything is built in the browser."},
      {"type": "added", "text": "Import Markdown, HTML, text and Word files as pages, with their pictures. A flashcard table in an exported file becomes flashcards again."},
      {"type": "added", "text": "Pages link themselves to the Reference, detection rules and CTF write-ups through their tags, ATT&CK IDs and Windows event IDs. Notebook pages show up in global search."},
      {"type": "fixed", "text": "Single-key shortcuts (n, e, /) no longer fire while typing in rich-text areas."}
    ]
  },
  {
    "version": "1.19",
    "name": "Field kit",
    "date": "2026-11-03",
    "summary": "A redesigned welcome page, a rebuilt CTF section, case places instead of the map, and far more detections, playbooks, reference and cloud techniques.",
    "changes": [
      {"type": "changed", "text": "The welcome page is redesigned: it follows your light or dark theme, shows the real app, and the colour switch is gone."},
      {"type": "added", "text": "CTF has four tabs. Each challenge opens a workspace with a work log of what worked and what did not, first moves for its category, entities pulled from your notes and a flag-format check. Solved challenges turn into write-ups in one click."},
      {"type": "added", "text": "Write-ups: your own and imported Markdown, with search, filters, a reader and Markdown export. Cheatsheets for nine categories: recognise-it tables, commands, gotchas and first moves, all searchable."},
      {"type": "changed", "text": "The case map is replaced by Places: every location and country in a case with an offline overview, movement in time order with impossible-travel warnings, and one-click links to Google Maps, Street View, Google Earth, OpenStreetMap, Bing, Apple Maps, Mapillary, satellite history and sun position. Export to KML or CSV."},
      {"type": "added", "text": "Hundreds of new Sigma and YARA rules, common and advanced, across Windows, Linux, macOS, cloud, identity and the web. New platform and level filters, faster search, and long lists load in pages."},
      {"type": "added", "text": "42 new playbooks for OSINT, incident response, threat analysis, cloud, forensics and fraud, with level and time estimates and category filters."},
      {"type": "added", "text": "The Reference page has about 1,200 entries in 40 sections, grouped by area: registry and file artefacts, SIDs, Linux and macOS, HTTP, DNS and e-mail, CloudTrail, Entra codes, M365, file signatures, timestamps, Volatility, search operators, wallets and more. Search ranks the best matches first, highlights them and moves with the arrow keys."},
      {"type": "added", "text": "Windows event logs (.evtx) can be imported from Capture. They are read in the browser, every Sigma rule runs against the events its log source covers, and the summary shows the most frequent events and the matches before anything is imported. Matched events are tagged and show the rule names on the timeline."},
      {"type": "fixed", "text": "Accessibility: text meets WCAG AA contrast in light and dark, links in text are underlined, selected items use the right ARIA states, and cards no longer put buttons inside buttons. Checked on 26 screens on every test run."},
      {"type": "fixed", "text": "The built-in LSASS Credential Dump Attempt rule no longer fires on Windows and antivirus processes reading LSASS: it now needs the access rights dumpers use and excludes the Windows and Program Files folders. Workspaces that still have the old, unedited rule get the new one."},
      {"type": "fixed", "text": "Taking a workspace over from another tab no longer reloads the page."},
      {"type": "removed", "text": "Map tile servers are no longer allowed by the page's security policy, since Places opens maps in a new tab instead."},
      {"type": "changed", "text": "The Cloud field guide is now a list with a reader: each technique shows numbered commands, what to look for, how defenders see it and how to fix it. 60 new techniques, including advanced AWS, Entra, GCP, Kubernetes, CI/CD, secrets and cloud incident response, with provider and level filters."}
    ]
  },
  {
    "version": "1.18",
    "name": "Trust and scale",
    "date": "2026-11-03",
    "summary": "The audit log and signed custody reports can no longer be forged by editing saved data, big cases save quickly, and boards with thousands of nodes open in seconds.",
    "changes": [
      {"type": "fixed", "text": "The audit log is sealed with a key kept by the browser that cannot be read out, so editing, removing or reordering entries in the saved data is detected. Entries made before this version are still checked as before."},
      {"type": "fixed", "text": "The custody signing key is now held by the browser and is never stored in the workspace or in backups. Old keys are moved over on first start."},
      {"type": "added", "text": "Custody reports show whose key signed them. A report signed by a key you have not marked as trusted is flagged, even if its signature is valid, and you can trust a colleague's key by its fingerprint."},
      {"type": "changed", "text": "Cases with 2,000 or more records are saved in pieces and only the changed pieces are written: a save on a 20,000-record workspace takes about 45 ms and writes a few hundred KB instead of the whole workspace."},
      {"type": "fixed", "text": "Boards with thousands of nodes no longer freeze. A faster layout places large graphs, and edges hide while you pan and zoom: a 2,000-node board opens in about two seconds instead of forty."}
    ]
  },
  {
    "version": "1.17",
    "name": "Data safety",
    "date": "2026-11-03",
    "summary": "Your workspace can no longer be overwritten by accident: unreadable data is kept, a second tab is read-only, imports are checked and the offline copy only runs its own code.",
    "changes": [
      {"type": "fixed", "text": "Saved data this version cannot read (damaged, or from a newer version) is no longer replaced with the demo. A recovery screen lets you download it or start fresh, and the old data is always kept aside."},
      {"type": "fixed", "text": "Two open tabs no longer overwrite each other. The second tab is read-only, follows the first tab's saves, and can take the workspace over with one click."},
      {"type": "fixed", "text": "Backup, case, tool and query imports are checked before anything changes. Files with malformed or unsafe IDs are refused with a clear reason."},
      {"type": "fixed", "text": "Importing a case gives its files fresh IDs, so it can never overwrite another case's evidence."},
      {"type": "fixed", "text": "Attachments open by what their bytes are, not the type they claim: markup always opens in the sandboxed viewer."},
      {"type": "fixed", "text": "Names and codes shown in menu titles are always plain text."},
      {"type": "fixed", "text": "The offline single-file copy only runs its own scripts (listed by hash); it no longer allows inline script."},
      {"type": "fixed", "text": "Pasting very long strings without spaces no longer freezes the app: 100 KB of hostile input takes about a tenth of a second instead of half a minute."}
    ]
  },
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
