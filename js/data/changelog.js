/* Release history — the single source of truth for both the in-app "What's new"
   page and CHANGELOG.md (run tools/changelog.py to regenerate the file).
   Plain JSON after the "=", like the other data files. Newest first.
   Each change has a type: "added" | "changed" | "fixed" | "removed". */
const CHANGELOG_DATA = [
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
