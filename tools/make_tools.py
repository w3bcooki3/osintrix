"""Write js/data/tools.js — the curated toolbox.

    python tools/make_tools.py

Every entry earns its place: maintained, used in real investigations, and mostly free or open source
(the licence is the first tag: open-source, free, freemium or commercial). Tools that were retired from an
earlier list go in RETIRED: a copy the user never starred, pinned, opened or edited is taken out of their
toolbox once; anything they used stays. Python 3, standard library only.
"""
import json, pathlib

root = pathlib.Path(__file__).resolve().parent.parent

# (name, url, category, subcategory, licence, description, extra tags)
T = [
  # ---- general: where to start, and the one tool everyone needs
  ("CyberChef", "https://gchq.github.io/CyberChef/", "general", "all-tools", "open-source", "GCHQ's 'cyber Swiss army knife': decode, decrypt, decompress and carve data in a recipe you can save and share. Base64, XOR, gzip, timestamps, regex extraction — runs entirely in the browser.", ["decode", "transform", "offline"]),
  ("Bellingcat Online Investigations Toolkit", "https://bellingcat.gitbook.io/toolkit", "general", "all-tools", "free", "Bellingcat's own curated, maintained guide to OSINT tools, with how-to notes and limitations for each — the best second opinion on any tool in this list.", ["reference", "osint"]),
  ("OSINT Framework", "https://osintframework.com", "general", "all-tools", "free", "A tree of free OSINT resources by what you start from (username, email, domain, image). Good for finding a niche or country-specific source; check each link still works.", ["reference", "osint"]),
  ("Maltego", "https://www.maltego.com", "general", "all-tools", "commercial", "Link-analysis desktop app with data 'transforms' that pivot from one entity to related ones. A free tier exists; most data hubs are paid. OSINTrix imports Maltego graphs.", ["link-analysis", "graph"]),
  ("SpiderFoot", "https://github.com/smicallef/spiderfoot", "general", "all-tools", "open-source", "Self-hosted OSINT automation: give it a domain, IP, email or name and 200+ modules collect what is linked. Export to CSV and import into a case here.", ["automation", "recon"]),

  # ---- OSINT: search engines over the internet itself
  ("Shodan", "https://www.shodan.io", "osint", "search-engines", "freemium", "Search the internet's open ports and banners. Pivot on favicon hash (http.favicon.hash), SSL certificate fields, JARM, HTTP title and SSH key to find an actor's other servers.", ["infrastructure", "pivot"]),
  ("Censys Search", "https://search.censys.io", "osint", "search-engines", "freemium", "Internet-wide scan data with strong certificate and service search — often finds hosts Shodan missed. Free accounts get a monthly query allowance.", ["infrastructure", "certificates", "pivot"]),
  ("FOFA", "https://en.fofa.info", "osint", "search-engines", "freemium", "Chinese internet-asset search engine with broad coverage of Asian hosting; useful when Shodan and Censys come up thin.", ["infrastructure"]),
  ("urlscan.io", "https://urlscan.io", "osint", "search-engines", "freemium", "Loads a URL in a sandboxed browser and records every request, screenshot and DOM. Search past scans by domain, IP, page hash or favicon to find phishing kits that share code. Scan privately — public scans are visible to the actor.", ["phishing", "url-analysis"]),
  ("PublicWWW", "https://publicwww.com", "osint", "search-engines", "freemium", "Search websites' source code — find every site carrying the same Google Analytics, Tag Manager or AdSense ID, a kit's unique string, or a crypto wallet address.", ["source-code", "pivot"]),
  ("Intelligence X", "https://intelx.io", "osint", "search-engines", "freemium", "Search engine and archive over pastes, leaks, darknet pages and historical web data by email, domain, IP, URL or wallet.", ["leaks", "darknet", "archive"]),

  # ---- OSINT: domains and DNS
  ("crt.sh", "https://crt.sh", "osint", "domain-investigation", "free", "Certificate Transparency search: every certificate issued for a domain and its subdomains. Query %.example.com; the public Postgres (crt.sh:5432, user guest) takes SQL for bulk work.", ["certificates", "subdomains"]),
  ("ICANN Lookup", "https://lookup.icann.org", "osint", "domain-investigation", "free", "Official RDAP/WHOIS for any gTLD: registrar, dates, status, abuse contact. The authoritative answer when third-party WHOIS sites disagree.", ["whois", "rdap"]),
  ("SecurityTrails", "https://securitytrails.com", "osint", "domain-investigation", "freemium", "Historical DNS: every A, MX and NS record a domain had and when — finds the real origin IP behind a CDN and the other domains that shared it.", ["passive-dns", "history"]),
  ("Validin", "https://app.validin.com", "osint", "domain-investigation", "freemium", "Passive DNS, host responses and certificate history with pivots on page title, banner hash and registration details. Generous free tier for researchers.", ["passive-dns", "pivot"]),
  ("DNSDumpster", "https://dnsdumpster.com", "osint", "domain-investigation", "freemium", "Quick passive map of a domain's hosts, mail servers and name servers.", ["dns", "subdomains"]),
  ("ViewDNS.info", "https://viewdns.info", "osint", "domain-investigation", "freemium", "Reverse IP, reverse WHOIS (by registrant name or email), IP history and DNS tools in one place.", ["reverse-whois", "reverse-ip"]),
  ("BuiltWith", "https://builtwith.com", "osint", "domain-investigation", "freemium", "Technology profile of a site and its 'relationships' — other sites sharing the same analytics, ad or tag IDs, past and present.", ["technology", "pivot"]),
  ("Wayback Machine", "https://web.archive.org", "osint", "domain-investigation", "free", "Past copies of web pages. The CDX API lists every capture of a site (/cdx/search/cdx?url=example.com/*&collapse=digest) — deleted pages, old contact details, earlier owners.", ["archive", "history"]),
  ("archive.today", "https://archive.ph", "osint", "domain-investigation", "free", "Archives a page as rendered, including many pages the Wayback Machine cannot capture. Archives are public — your interest is visible.", ["archive", "preserve"]),
  ("OWASP Amass", "https://github.com/owasp-amass/amass", "osint", "domain-investigation", "open-source", "Attack-surface mapping: subdomains from dozens of passive sources plus DNS brute force and graph of relationships. The standard for mapping your own external footprint.", ["subdomains", "attack-surface", "cli"]),
  ("subfinder", "https://github.com/projectdiscovery/subfinder", "osint", "domain-investigation", "open-source", "Fast passive subdomain enumeration from certificate logs, search engines and DNS datasets.", ["subdomains", "cli"]),
  ("httpx", "https://github.com/projectdiscovery/httpx", "osint", "domain-investigation", "open-source", "Probe a list of hosts for live web servers: status, title, technology, TLS details, favicon hash and JARM in one pass.", ["probe", "cli", "fingerprint"]),
  ("dnstwist", "https://github.com/elceef/dnstwist", "osint", "domain-investigation", "open-source", "Generates lookalike domains (typos, homoglyphs, bit-flips) and checks which are registered, resolve or run mail — brand-impersonation monitoring.", ["typosquatting", "phishing", "cli"]),

  # ---- OSINT: usernames, email, phone
  ("WhatsMyName", "https://whatsmyname.app", "osint", "username-investigation", "open-source", "Checks a username across 600+ sites with a community-maintained detection list; fewer false positives than most.", ["username"]),
  ("Sherlock", "https://github.com/sherlock-project/sherlock", "osint", "username-investigation", "open-source", "Command-line username search across hundreds of sites.", ["username", "cli"]),
  ("Maigret", "https://github.com/soxoj/maigret", "osint", "username-investigation", "open-source", "Username search that also parses found profiles for linked accounts, names and IDs, then recurses — builds a profile, not just a hit list.", ["username", "cli", "profile"]),
  ("Epieos", "https://epieos.com", "osint", "email-investigation", "freemium", "From an email address or phone number: linked Google account details, public reviews and calendar, and registered services. Read what it shows carefully — it is a lead, not an identity.", ["email", "google"]),
  ("holehe", "https://github.com/megadose/holehe", "osint", "email-investigation", "open-source", "Checks which of 120+ services an email address is registered on, using their password-reset or sign-up responses, without alerting the address owner.", ["email", "cli"]),
  ("Google Admin Toolbox — Messageheader", "https://toolbox.googleapps.com/apps/messageheader/", "osint", "email-investigation", "free", "Paste raw email headers to see the hop-by-hop path, delays and SPF/DKIM/DMARC results. OSINTrix's own header analyser does the same offline.", ["email", "headers"]),
  ("MXToolbox", "https://mxtoolbox.com", "osint", "email-investigation", "freemium", "MX, SPF, DMARC and blacklist checks for a domain; useful for phishing infrastructure and your own mail hygiene.", ["email", "dns", "blacklist"]),
  ("PhoneInfoga", "https://github.com/sundowndev/phoneinfoga", "osint", "phone-investigation", "open-source", "Parses a phone number (country, carrier, line type) and builds search queries for its footprint. OSINTrix's phone parser covers the offline part.", ["phone", "cli"]),

  # ---- OSINT: social, chat, video
  ("TGStat", "https://tgstat.com", "osint", "social-media", "freemium", "Telegram channel and group catalogue with subscriber history, mentions and forwards — which channels repost whom. Search without an account.", ["telegram"]),
  ("yt-dlp", "https://github.com/yt-dlp/yt-dlp", "osint", "social-media", "open-source", "Downloads video and metadata from YouTube, X, TikTok, Telegram and 1,000+ sites — preserve it before it is deleted, with the upload date and description.", ["video", "preserve", "cli"]),
  ("Instaloader", "https://github.com/instaloader/instaloader", "osint", "social-media", "open-source", "Archives public Instagram profiles, posts, stories and comments with their metadata.", ["instagram", "preserve", "cli"]),

  # ---- OSINT: images, verification, geolocation
  ("Google Lens", "https://lens.google.com", "osint", "image-investigation", "free", "Reverse image search; strongest for products, landmarks and text in images.", ["reverse-image"]),
  ("Yandex Images", "https://yandex.com/images/", "osint", "image-investigation", "free", "Reverse image search that is often best for buildings, streets and landscapes, especially in Eastern Europe and Central Asia.", ["reverse-image", "geolocation"]),
  ("Bing Visual Search", "https://www.bing.com/visualsearch", "osint", "image-investigation", "free", "A third reverse-image index; crop to the part that matters for better results.", ["reverse-image"]),
  ("TinEye", "https://tineye.com", "osint", "image-investigation", "freemium", "Exact-match reverse image search sorted by oldest — finds where a photo first appeared and its edited copies.", ["reverse-image", "first-seen"]),
  ("InVID-WeVerify plugin", "https://www.invid-project.eu/tools-and-services/invid-verification-plugin/", "osint", "image-investigation", "free", "Browser plugin for verifying video and images: keyframes for reverse search, metadata, magnifier and forensic filters. Used by newsrooms worldwide.", ["verification", "video"]),
  ("Forensically", "https://29a.ch/photo-forensics/", "osint", "image-investigation", "free", "Error level analysis, clone detection, noise and metadata for spotting edits, in the browser.", ["manipulation", "verification"]),
  ("FotoForensics", "https://fotoforensics.com", "osint", "image-investigation", "free", "Error level analysis and metadata with good tutorials on reading the results without over-claiming.", ["manipulation", "verification"]),
  ("SunCalc", "https://www.suncalc.org", "osint", "geolocation", "free", "Sun position and shadow direction for any place and time — chronolocate a photo from shadow length, or test a claimed time and place.", ["chronolocation", "shadows"]),
  ("Overpass Turbo", "https://overpass-turbo.eu", "osint", "geolocation", "free", "Query OpenStreetMap: 'a church within 100 m of a bridge and a petrol station'. Turns what you see in a photo into a short list of places.", ["openstreetmap", "query"]),
  ("Copernicus Browser", "https://browser.dataspace.copernicus.eu", "osint", "geolocation", "free", "Free Sentinel-2 satellite imagery (10 m) every few days, with history back to 2015 — confirm when something was built, burned or moved.", ["satellite", "change-detection"]),
  ("Google Earth Pro", "https://www.google.com/earth/about/versions/", "osint", "geolocation", "free", "Desktop Earth with historical imagery slider, 3D terrain and measuring — still the quickest way to check a vantage point.", ["satellite", "history", "3d"]),
  ("PeakVisor", "https://peakvisor.com", "osint", "geolocation", "freemium", "Identifies mountain ridgelines from any viewpoint — match a skyline in a photo or video to a location.", ["mountains", "skyline"]),
  ("Mapillary", "https://www.mapillary.com", "osint", "geolocation", "free", "Crowd-sourced street-level imagery, often where Google Street View has none.", ["street-level"]),

  # ---- OSINT: ships, aircraft, companies, money
  ("MarineTraffic", "https://www.marinetraffic.com", "osint", "transport", "freemium", "Live and past ship positions by AIS. The IMO number stays with a hull through name and flag changes — search by it.", ["ships", "ais"]),
  ("VesselFinder", "https://www.vesselfinder.com", "osint", "transport", "freemium", "Second AIS source with vessel particulars and port calls; compare with MarineTraffic when tracks disagree.", ["ships", "ais"]),
  ("Global Fishing Watch", "https://globalfishingwatch.org/map", "osint", "transport", "free", "Free AIS map with vessel history, port visits and AIS-gap and encounter events — where a ship went dark and who it met.", ["ships", "ais-gaps", "sanctions"]),
  ("ADS-B Exchange", "https://globe.adsbexchange.com", "osint", "transport", "free", "Unfiltered flight tracking: shows aircraft other trackers hide on owner request. Search by ICAO hex, registration or callsign; history with replay.", ["aircraft", "ads-b"]),
  ("Flightradar24", "https://www.flightradar24.com", "osint", "transport", "freemium", "Flight tracking with photos and route history; free history is limited to recent days.", ["aircraft"]),
  ("OpenCorporates", "https://opencorporates.com", "osint", "companies", "freemium", "The largest open database of companies — 200+ million from 140 registries, with officers and filings. Start here for any company in any country.", ["companies", "officers"]),
  ("Companies House", "https://find-and-update.company-information.service.gov.uk", "osint", "companies", "free", "UK register: officers, persons with significant control, filings and an officer's other appointments — free, with a free API.", ["companies", "uk", "beneficial-ownership"]),
  ("ICIJ Offshore Leaks", "https://offshoreleaks.icij.org", "osint", "companies", "free", "Searchable entities and officers from the Panama, Paradise and Pandora Papers and other leaks, with their connections.", ["offshore", "leaks"]),
  ("OpenSanctions", "https://www.opensanctions.org", "osint", "companies", "freemium", "Sanctions lists, politically exposed persons and criminal watchlists merged into one searchable dataset; free for non-commercial use.", ["sanctions", "pep"]),
  ("OCCRP Aleph", "https://aleph.occrp.org", "osint", "companies", "free", "OCCRP's archive of company registries, leaks and court documents for investigative journalists (some collections need an account).", ["leaks", "journalism"]),
  ("SEC EDGAR full-text search", "https://www.sec.gov/edgar/search/", "osint", "companies", "free", "Search the full text of US company filings since 2001 — names, addresses and subsidiaries buried in exhibits.", ["companies", "usa", "filings"]),
  ("GLEIF LEI search", "https://search.gleif.org", "osint", "companies", "free", "Legal Entity Identifiers with parent and ultimate-parent relationships — ownership chains across borders.", ["companies", "ownership"]),

  # ---- OSINT: crypto
  ("mempool.space", "https://mempool.space", "osint", "crypto", "open-source", "Bitcoin explorer: transactions, addresses and fee history. Open source and self-hostable, so lookups need not leak to a third party.", ["bitcoin", "explorer"]),
  ("Etherscan", "https://etherscan.io", "osint", "crypto", "freemium", "Ethereum explorer with address labels (exchanges, scams, sanctioned addresses) and token transfers.", ["ethereum", "explorer"]),
  ("Tronscan", "https://tronscan.org", "osint", "crypto", "free", "TRON explorer — most USDT used in scams and underground payments moves on TRON.", ["tron", "usdt", "explorer"]),
  ("WalletExplorer", "https://www.walletexplorer.com", "osint", "crypto", "free", "Clusters Bitcoin addresses into wallets (common-input heuristic) and names services — shows when funds reach an exchange.", ["bitcoin", "clustering"]),
  ("Breadcrumbs", "https://www.breadcrumbs.app", "osint", "crypto", "freemium", "Visual tracing of funds across BTC, ETH and other chains with labels; free tier is enough for most cases.", ["tracing", "graph"]),
  ("Arkham Intelligence", "https://intel.arkm.com", "osint", "crypto", "freemium", "Entity labels on addresses across chains, with transfer history by entity.", ["labels", "tracing"]),

  # ---- OSINT: darknet and leaks
  ("Tor Browser", "https://www.torproject.org/download/", "osint", "dark-web", "open-source", "Needed to open .onion sites. Use it inside a research VM, never with your own accounts, and keep the security level at 'Safest' on unknown sites.", ["tor", "onion"]),
  ("Ahmia", "https://ahmia.fi", "osint", "dark-web", "open-source", "Search engine for Tor onion services that filters abuse material; also reachable on the clear web.", ["tor", "search"]),
  ("Have I Been Pwned", "https://haveibeenpwned.com", "osint", "breach-data", "freemium", "Which known breaches contain an email address, and the Pwned Passwords range API to check a password by hash prefix without sending it.", ["breach", "passwords"]),
  ("Hudson Rock free tools", "https://www.hudsonrock.com/free-tools", "osint", "breach-data", "free", "Checks whether an email or domain appears in infostealer logs (machines infected with credential-stealing malware) — a common root cause of account takeovers.", ["infostealer", "breach"]),

  # ---- forensics: disk, artefacts, timelines
  ("Autopsy", "https://www.autopsy.com", "digital-forensics", "disk-analysis", "open-source", "GUI on The Sleuth Kit: disk images, deleted files, web history, timeline, keyword search and hash sets.", ["disk", "gui"]),
  ("FTK Imager", "https://www.exterro.com/digital-forensics-software/ftk-imager", "digital-forensics", "disk-analysis", "free", "Make forensic images (E01, raw), capture memory and mount images read-only on Windows. Free download after a registration form.", ["imaging", "memory-capture"]),
  ("Arsenal Image Mounter", "https://arsenalrecon.com/products/arsenal-image-mounter", "digital-forensics", "disk-analysis", "freemium", "Mounts forensic images as real disks in Windows (read-only), so any tool can read them — including Volume Shadow Copies in free mode.", ["mount", "vss"]),
  ("KAPE", "https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape", "digital-forensics", "artifact-analysis", "free", "Collects the forensic artefacts that matter (registry hives, event logs, prefetch, browser data) in minutes, then runs parsers over them. Free for most uses.", ["triage", "collection", "windows"]),
  ("Eric Zimmerman's tools", "https://ericzimmerman.github.io", "digital-forensics", "artifact-analysis", "open-source", "The standard Windows artefact parsers: MFTECmd, PECmd (prefetch), AmcacheParser, EvtxECmd, Registry Explorer, Timeline Explorer, LECmd (LNK), JLECmd.", ["windows", "parsers", "timeline"]),
  ("RegRipper", "https://github.com/keydet89/RegRipper3.0", "digital-forensics", "registry-analysis", "open-source", "Plugins that pull forensically useful values out of registry hives — USB devices, run keys, user activity.", ["registry", "windows"]),
  ("Plaso (log2timeline)", "https://github.com/log2timeline/plaso", "digital-forensics", "timeline-analysis", "open-source", "Builds a super-timeline from a disk image or folder: every timestamp from hundreds of artefact types in one sortable list.", ["timeline", "super-timeline"]),
  ("Timesketch", "https://timesketch.org", "digital-forensics", "timeline-analysis", "open-source", "Collaborative timeline analysis for Plaso output and CSV/JSONL: search, tag, annotate and run analysers as a team.", ["timeline", "collaboration"]),
  ("Hayabusa", "https://github.com/Yamato-Security/hayabusa", "digital-forensics", "log-analysis", "open-source", "Fast Windows event log (EVTX) timeline generator and threat hunter using 4,000+ Sigma rules — run it on a triage collection first.", ["evtx", "sigma", "windows"]),
  ("Chainsaw", "https://github.com/WithSecureLabs/chainsaw", "digital-forensics", "log-analysis", "open-source", "Searches and hunts through EVTX, MFT and other artefacts with Sigma and its own rules; fast first look at a compromised host.", ["evtx", "sigma", "hunting"]),
  ("UAC (Unix-like Artifacts Collector)", "https://github.com/tclahr/uac", "digital-forensics", "artifact-analysis", "open-source", "Live-response collection for Linux, macOS, ESXi and other Unix systems: volatile data, logs, user files and hashes in one script.", ["linux", "macos", "esxi", "collection"]),
  ("bulk_extractor", "https://github.com/simsong/bulk_extractor", "digital-forensics", "file-recovery", "open-source", "Carves emails, URLs, credit card numbers, crypto addresses and more from any disk image or file, ignoring the file system.", ["carving"]),
  ("PhotoRec", "https://www.cgsecurity.org/wiki/PhotoRec", "digital-forensics", "file-recovery", "open-source", "Recovers deleted files by signature from disks and memory cards, even when the file system is damaged.", ["recovery", "carving"]),
  ("ExifTool", "https://exiftool.org", "digital-forensics", "metadata-analysis", "open-source", "Reads and writes metadata in almost every file format — camera, GPS, software, authors, embedded thumbnails. The reference tool.", ["exif", "metadata", "cli"]),

  # ---- forensics: memory and mobile
  ("Volatility 3", "https://github.com/volatilityfoundation/volatility3", "digital-forensics", "memory-analysis", "open-source", "Memory forensics framework: processes, network connections, injected code, handles and command lines from a RAM image.", ["memory", "cli"]),
  ("MemProcFS", "https://github.com/ufrisk/MemProcFS", "digital-forensics", "memory-analysis", "open-source", "Mounts a memory image as a file system — browse processes, modules and registry as folders, with built-in forensic timelines.", ["memory"]),
  ("WinPmem", "https://github.com/Velocidex/WinPmem", "digital-forensics", "memory-analysis", "open-source", "Acquires physical memory on Windows; the open-source choice for a RAM capture.", ["memory-capture", "windows"]),
  ("MVT (Mobile Verification Toolkit)", "https://github.com/mvt-project/mvt", "digital-forensics", "mobile-forensics", "open-source", "Amnesty International's tool for finding traces of Pegasus and other mercenary spyware in iOS backups and Android devices.", ["mobile", "spyware", "ios", "android"]),
  ("iLEAPP / ALEAPP", "https://github.com/abrignoni/iLEAPP", "digital-forensics", "mobile-forensics", "open-source", "Parse iOS (iLEAPP) and Android (ALEAPP) extractions into readable reports: messages, locations, app usage.", ["mobile", "ios", "android"]),

  # ---- network forensics and monitoring
  ("Wireshark", "https://www.wireshark.org", "network-security", "packet-analysis", "open-source", "The packet analyser. Follow streams, export objects, decode hundreds of protocols; tshark for the command line.", ["pcap"]),
  ("Zeek", "https://zeek.org", "network-security", "traffic-analysis", "open-source", "Turns traffic into rich logs (conn, dns, http, ssl, files) — the basis of most network threat hunting.", ["nsm", "logs"]),
  ("Suricata", "https://suricata.io", "network-security", "intrusion-detection", "open-source", "High-performance IDS/IPS and network security monitoring with Emerging Threats rules, plus protocol and file logging.", ["ids", "rules"]),
  ("Security Onion", "https://securityonion.net", "network-security", "intrusion-detection", "open-source", "A free platform bundling Suricata, Zeek, full packet capture, Elastic and case management for threat hunting and NSM.", ["nsm", "platform"]),
  ("Arkime", "https://arkime.com", "network-security", "packet-analysis", "open-source", "Indexed full packet capture at scale — search sessions and pull the pcap for any connection weeks later.", ["pcap", "full-capture"]),
  ("NetworkMiner", "https://www.netresec.com/?page=NetworkMiner", "network-security", "packet-analysis", "freemium", "Extracts files, images, credentials, hosts and sessions from a pcap in a few clicks — fast triage of a capture.", ["pcap", "carving"]),
  ("Zui (Brim)", "https://github.com/brimdata/zui", "network-security", "packet-analysis", "open-source", "Desktop app that turns a pcap into searchable Zeek and Suricata logs.", ["pcap", "zeek"]),
  ("RITA", "https://github.com/activecm/rita", "network-security", "traffic-analysis", "open-source", "Finds beaconing, long connections and DNS tunnelling in Zeek logs — call-home traffic that signatures miss.", ["beaconing", "c2", "zeek"]),
  ("Nmap", "https://nmap.org", "network-security", "port-scanning", "open-source", "Port and service discovery with scripts; the reference scanner for checking your own exposure.", ["scanning"]),
  ("Nuclei", "https://github.com/projectdiscovery/nuclei", "network-security", "vulnerability-scanning", "open-source", "Template-based scanner with thousands of community checks for exposures and known CVEs — run it against your own attack surface.", ["vulnerabilities", "templates"]),
  ("Greenbone OpenVAS", "https://www.openvas.org", "network-security", "vulnerability-scanning", "open-source", "Full network vulnerability scanner with a daily-updated feed.", ["vulnerabilities"]),
  ("testssl.sh", "https://testssl.sh", "network-security", "ssl-analysis", "open-source", "Checks a server's TLS configuration, ciphers and known vulnerabilities from the command line.", ["tls", "cli"]),
  ("IPinfo", "https://ipinfo.io", "network-security", "ip-analysis", "freemium", "IP to ASN, organisation, hosting/VPN flags and location, with a generous free API.", ["ip", "asn"]),
  ("Hurricane Electric BGP Toolkit", "https://bgp.he.net", "network-security", "ip-analysis", "free", "Which ASN announces an IP, all its prefixes, peers and the domains on an IP range.", ["asn", "bgp"]),
  ("GreyNoise", "https://viz.greynoise.io", "network-security", "ip-analysis", "freemium", "Tells you whether an IP is internet background noise (mass scanners, researchers) or something targeting you specifically.", ["ip", "noise"]),
  ("AbuseIPDB", "https://www.abuseipdb.com", "network-security", "ip-analysis", "freemium", "Community reports of abusive IPs — brute force, scanning, spam — with categories and dates.", ["ip", "reputation"]),
  ("Spur", "https://spur.us", "network-security", "ip-analysis", "freemium", "Identifies VPN, residential proxy and anonymiser exit IPs — tells you whether a 'home' sign-in came through a proxy network.", ["vpn", "proxy"]),

  # ---- malware analysis
  ("VirusTotal", "https://www.virustotal.com", "malware-analysis", "hash-lookup", "freemium", "Hash, file, URL and domain reputation from 70+ engines with relations and behaviour reports. Search by hash first — uploads are visible to every paying customer, including the actor.", ["reputation", "hash"]),
  ("MalwareBazaar", "https://bazaar.abuse.ch", "malware-analysis", "hash-lookup", "free", "Free malware sample sharing by abuse.ch: search by hash, imphash, YARA rule or tag, and download samples for analysis.", ["samples", "abuse.ch"]),
  ("ANY.RUN", "https://any.run", "malware-analysis", "sandboxes", "freemium", "Interactive sandbox — click through installers and documents while watching processes and network. Free tasks are public.", ["sandbox", "interactive"]),
  ("Triage", "https://tria.ge", "malware-analysis", "sandboxes", "freemium", "Fast sandbox with malware family configuration extraction (C2s, keys) for many families; free researcher accounts.", ["sandbox", "config-extraction"]),
  ("Hybrid Analysis", "https://www.hybrid-analysis.com", "malware-analysis", "sandboxes", "free", "Free sandbox reports with MITRE mapping and a large searchable archive of past submissions.", ["sandbox"]),
  ("CAPE Sandbox", "https://github.com/kevoreilly/CAPEv2", "malware-analysis", "sandboxes", "open-source", "Self-hosted sandbox (Cuckoo's maintained successor) with payload unpacking and config extraction; public instance at capesandbox.com.", ["sandbox", "self-hosted", "unpacking"]),
  ("UnpacMe", "https://www.unpac.me", "malware-analysis", "dynamic-analysis", "freemium", "Automated unpacking of packed malware, returning the real payloads.", ["unpacking"]),
  ("Detect It Easy", "https://github.com/horsicq/Detect-It-Easy", "malware-analysis", "static-analysis", "open-source", "Identifies compilers, packers and protectors of a file — the first thing to run on an unknown binary.", ["packer", "triage"]),
  ("capa", "https://github.com/mandiant/capa", "malware-analysis", "static-analysis", "open-source", "Tells you what a binary can do (keylogging, persistence, injection) mapped to ATT&CK, without running it.", ["capabilities", "attack"]),
  ("FLOSS", "https://github.com/mandiant/flare-floss", "malware-analysis", "static-analysis", "open-source", "Extracts obfuscated, stack and encoded strings that the plain strings tool misses.", ["strings"]),
  ("PE-bear", "https://github.com/hasherezade/pe-bear", "malware-analysis", "static-analysis", "open-source", "PE file viewer for headers, sections, imports and resources — spot tampered or packed binaries.", ["pe"]),
  ("oletools", "https://github.com/decalage2/oletools", "malware-analysis", "file-analysis", "open-source", "Analyse Office documents: macros (olevba), embedded objects, DDE, RTF exploits.", ["office", "macros"]),
  ("Ghidra", "https://ghidra-sre.org", "malware-analysis", "decompilers", "open-source", "NSA's reverse-engineering suite with a strong decompiler for most architectures.", ["reverse-engineering", "decompiler"]),
  ("dnSpyEx", "https://github.com/dnSpyEx/dnSpy", "malware-analysis", "decompilers", "open-source", ".NET decompiler and debugger — most commodity stealers and loaders are .NET.", [".net", "debugger"]),
  ("x64dbg", "https://x64dbg.com", "malware-analysis", "debuggers", "open-source", "Windows user-mode debugger for unpacking and behaviour analysis.", ["debugger", "windows"]),
  ("ImHex", "https://github.com/WerWolv/ImHex", "malware-analysis", "hex-editors", "open-source", "Hex editor with a pattern language that decodes file structures, plus entropy and diffing.", ["hex", "patterns"]),
  ("YARA", "https://virustotal.github.io/yara/", "malware-analysis", "yara-rules", "open-source", "Pattern-matching rules for files and memory — describe a malware family once, find it everywhere. OSINTrix runs YARA offline.", ["rules", "hunting"]),
  ("REMnux", "https://remnux.org", "malware-analysis", "reverse-engineering", "open-source", "Linux distribution with hundreds of malware-analysis tools ready to go.", ["distro", "linux"]),
  ("FLARE-VM", "https://github.com/mandiant/flare-vm", "malware-analysis", "reverse-engineering", "open-source", "Turns a Windows VM into a malware-analysis workstation with one install script.", ["distro", "windows"]),
  ("Malpedia", "https://malpedia.caad.fkie.fraunhofer.de", "malware-analysis", "reverse-engineering", "free", "Reference on malware families: aliases, YARA rules and every public report about each.", ["reference", "families"]),
  ("hashcat", "https://hashcat.net/hashcat/", "malware-analysis", "hash-lookup", "open-source", "GPU password recovery — for opening encrypted evidence lawfully seized, and for auditing your own password hashes.", ["passwords", "recovery"]),

  # ---- threat intelligence and hunting
  ("MISP", "https://www.misp-project.org", "threat-intelligence", "threat-sharing", "open-source", "The standard platform for sharing indicators and events between organisations and CERTs.", ["sharing", "ioc"]),
  ("OpenCTI", "https://filigran.io/solutions/open-cti/", "threat-intelligence", "threat-sharing", "open-source", "Threat intelligence knowledge base in STIX 2.1: actors, campaigns, malware and indicators as a graph with connectors to feeds.", ["stix", "graph"]),
  ("IntelOwl", "https://github.com/intelowlproject/IntelOwl", "threat-intelligence", "ioc-analysis", "open-source", "Enrich an indicator against 100+ analysers and services from one API or UI.", ["enrichment", "automation"]),
  ("AlienVault OTX", "https://otx.alienvault.com", "threat-intelligence", "threat-feeds", "free", "Community 'pulses' of indicators from reports, with a free API.", ["feeds", "ioc"]),
  ("ThreatFox", "https://threatfox.abuse.ch", "threat-intelligence", "threat-feeds", "free", "abuse.ch's free database of current malware indicators (C2s, payload URLs) by family.", ["ioc", "abuse.ch", "c2"]),
  ("URLhaus", "https://urlhaus.abuse.ch", "threat-intelligence", "threat-feeds", "free", "Malware distribution URLs, live and past, with payloads and tags.", ["url", "abuse.ch"]),
  ("Feodo Tracker", "https://feodotracker.abuse.ch", "threat-intelligence", "threat-feeds", "free", "Active botnet C2 servers (QakBot, Emotet successors and others) as a blocklist.", ["c2", "blocklist", "abuse.ch"]),
  ("CISA KEV", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "threat-intelligence", "vulnerability-research", "free", "Vulnerabilities known to be exploited in the wild — patch these first. OSINTrix ships a snapshot offline.", ["vulnerabilities", "patching"]),
  ("ransomware.live", "https://www.ransomware.live", "threat-intelligence", "campaign-tracking", "free", "Tracks ransomware leak-site posts by group, sector and country, with group profiles and negotiation chats.", ["ransomware", "leak-sites"]),
  ("MITRE ATT&CK Navigator", "https://mitre-attack.github.io/attack-navigator/", "threat-intelligence", "threat-hunting", "open-source", "Colour the ATT&CK matrix: an actor's techniques versus your detection coverage, side by side.", ["attack", "coverage"]),
  ("DeTT&CT", "https://github.com/rabobank-cdc/DeTTECT", "threat-intelligence", "threat-hunting", "open-source", "Scores your data sources and detection coverage against ATT&CK — shows what you cannot see.", ["coverage", "data-sources"]),
  ("SigmaHQ", "https://github.com/SigmaHQ/sigma", "threat-intelligence", "threat-hunting", "open-source", "The main repository of Sigma detection rules — 3,000+ community rules for SIEMs. OSINTrix ships them offline.", ["sigma", "detection"]),
  ("Uncoder.io", "https://uncoder.io", "threat-intelligence", "threat-hunting", "freemium", "Translate Sigma rules and IOCs into KQL, SPL, EQL and other query languages.", ["sigma", "translation"]),
  ("LOLBAS", "https://lolbas-project.github.io", "threat-intelligence", "threat-hunting", "open-source", "Every signed Windows binary attackers misuse (certutil, mshta, rundll32…), with what each can do and how to detect it.", ["lolbins", "windows"]),
  ("GTFOBins", "https://gtfobins.github.io", "threat-intelligence", "threat-hunting", "open-source", "The Linux counterpart to LOLBAS: Unix binaries that can be abused to escape restricted shells, escalate or transfer files.", ["linux", "lolbins"]),
  ("LOLDrivers", "https://www.loldrivers.io", "threat-intelligence", "threat-hunting", "open-source", "Vulnerable and malicious Windows drivers used to kill EDR, with hashes and Sigma/YARA rules.", ["drivers", "byovd"]),
  ("LOLRMM", "https://lolrmm.io", "threat-intelligence", "threat-hunting", "open-source", "Remote-monitoring tools abused by attackers, with their binaries, domains and detection artefacts.", ["rmm", "remote-access"]),
  ("Atomic Red Team", "https://github.com/redcanaryco/atomic-red-team", "threat-intelligence", "threat-hunting", "open-source", "Small, safe tests for each ATT&CK technique — prove your detections fire.", ["validation", "purple-team"]),
  ("BloodHound CE", "https://github.com/SpecterOps/BloodHound", "threat-intelligence", "threat-hunting", "open-source", "Maps attack paths in Active Directory and Entra ID — which user can reach Domain Admin and how. Defenders run it before attackers do.", ["active-directory", "attack-paths"]),
  ("PingCastle", "https://www.pingcastle.com", "threat-intelligence", "threat-hunting", "freemium", "Active Directory risk assessment in minutes: stale admins, weak delegation, Kerberoastable accounts, trusts. Free for internal audits.", ["active-directory", "audit"]),

  # ---- incident response
  ("Velociraptor", "https://docs.velociraptor.app", "incident-response", "evidence-collection", "open-source", "Endpoint visibility and collection at scale: hunt across thousands of hosts with VQL, collect artefacts, triage live.", ["endpoint", "dfir", "hunting"]),
  ("osquery", "https://osquery.io", "incident-response", "evidence-collection", "open-source", "Query an operating system like a database — processes, autoruns, sockets, users — on Windows, macOS and Linux.", ["endpoint", "sql"]),
  ("Fleet", "https://fleetdm.com", "incident-response", "evidence-collection", "open-source", "Manage osquery across a fleet and run live queries on every device.", ["osquery", "endpoint"]),
  ("Sysinternals Suite", "https://learn.microsoft.com/en-us/sysinternals/", "incident-response", "evidence-collection", "free", "Autoruns, Process Explorer, Process Monitor, TCPView, Sigcheck — the live-response kit every Windows responder carries.", ["windows", "live-response"]),
  ("Sysmon + sysmon-modular", "https://github.com/olafhartong/sysmon-modular", "incident-response", "evidence-collection", "free", "Microsoft Sysmon gives process, network, registry and file telemetry; sysmon-modular is a maintained configuration mapped to ATT&CK.", ["sysmon", "telemetry", "windows"]),
  ("THOR Lite", "https://www.nextron-systems.com/thor-lite/", "incident-response", "evidence-collection", "free", "Free compromise-assessment scanner with YARA and Sigma rules — sweeps a host for known attacker tools and traces.", ["scanner", "yara", "ioc"]),
  ("Microsoft Extractor Suite", "https://github.com/invictus-ir/Microsoft-Extractor-Suite", "incident-response", "evidence-collection", "open-source", "PowerShell module to acquire Microsoft 365 and Entra ID evidence: unified audit log, sign-ins, mailbox rules, OAuth grants.", ["m365", "entra", "cloud"]),
  ("Untitled Goose Tool", "https://github.com/cisagov/untitledgoosetool", "incident-response", "evidence-collection", "open-source", "CISA's tool for exporting Entra ID, M365 and Azure logs and configuration for incident response.", ["m365", "azure", "cloud"]),
  ("DFIR-IRIS", "https://dfir-iris.org", "incident-response", "case-management", "open-source", "Collaborative incident-response case management: assets, IOCs, timeline, evidence and tasks.", ["case-management"]),
  ("TheHive", "https://strangebee.com/thehive/", "incident-response", "case-management", "freemium", "Security incident response platform for SOC teams, with alert triage and case workflow; community edition is free.", ["case-management", "soc"]),
  ("Wazuh", "https://wazuh.com", "incident-response", "automation", "open-source", "Open-source SIEM and XDR: agent-based log collection, file integrity monitoring and detection rules.", ["siem", "xdr"]),
  ("Shuffle", "https://shuffler.io", "incident-response", "automation", "open-source", "Open-source SOAR: build enrichment and response workflows without code.", ["soar", "workflow"]),

  # ---- cloud
  ("Prowler", "https://github.com/prowler-cloud/prowler", "network-security", "cloud-security", "open-source", "Security assessment for AWS, Azure, GCP and Kubernetes against CIS and other benchmarks, plus incident-response checks.", ["aws", "azure", "gcp", "cspm"]),
  ("ScoutSuite", "https://github.com/nccgroup/ScoutSuite", "network-security", "cloud-security", "open-source", "Multi-cloud configuration audit with an offline HTML report.", ["aws", "azure", "gcp", "audit"]),
  ("Trivy", "https://trivy.dev", "network-security", "cloud-security", "open-source", "Scans containers, file systems, Git repos and infrastructure-as-code for vulnerabilities, misconfigurations and secrets (tfsec is now part of it).", ["containers", "iac", "secrets"]),
  ("Checkov", "https://www.checkov.io", "network-security", "cloud-security", "open-source", "Static analysis of Terraform, CloudFormation, Kubernetes and other IaC for misconfigurations before deployment.", ["iac", "terraform"]),
  ("kube-bench", "https://github.com/aquasecurity/kube-bench", "network-security", "cloud-security", "open-source", "Checks a Kubernetes cluster against the CIS Kubernetes Benchmark.", ["kubernetes", "cis"]),
  ("Cartography", "https://github.com/cartography-cncf/cartography", "network-security", "cloud-security", "open-source", "Pulls cloud, identity and SaaS assets into a graph so you can ask which identity reaches which data.", ["graph", "asset-inventory"]),
  ("ROADtools", "https://github.com/dirkjanm/ROADtools", "network-security", "cloud-security", "open-source", "Dumps an Entra ID tenant (users, apps, roles, devices) into a local database for review — used by responders to see what an attacker could see.", ["entra", "azure-ad"]),
  ("Stratus Red Team", "https://github.com/DataDog/stratus-red-team", "network-security", "cloud-security", "open-source", "Atomic attack simulations for AWS, Azure, GCP and Kubernetes to test cloud detections.", ["validation", "cloud"]),
  ("Pacu", "https://github.com/RhinoSecurityLabs/pacu", "network-security", "cloud-security", "open-source", "AWS exploitation framework for authorised testing — run it in your own account to see which IAM misconfigurations an attacker could use.", ["aws", "purple-team"]),

  # ---- language
  ("DeepL", "https://www.deepl.com/translator", "ai-automation", "llm-tools", "freemium", "The most natural machine translation for Russian, Ukrainian, Chinese and most European languages — forum posts, chats and documents. Do not paste anything confidential into the free version.", ["translation"]),
]

# entries from earlier lists that no longer earn a place (dead, retired, merged, paid-only, or data brokers)
RETIRED = [
  "https://github.com/luismayta/nrd-db", "https://github.com/Cyb3rWard0g/HELK", "https://github.com/clong/DetectionLab", "https://www.paloaltonetworks.com/cortex/xsoar",
  "https://cuckoosandbox.org/", "https://grr-doc.readthedocs.io/en/latest/", "https://www.thehive-project.org/cortex/",
  "https://opendf.io/", "https://www.perplexity.ai", "https://huggingface.co/", "https://www.snort.org/",
  "https://pimeyes.com/", "https://github.com/drfuzz0r/certgrep", "https://www.tenable.com/products/nessus",
  
  "http://10digits.us", "http://www.whitepages.com", "http://www.411.com", "http://www.zabasearch.com", "http://www.intelius.com", "http://www.yellowpages.com", "http://publicrecords.directory/",
  "http://www.411locate.com", "http://www.addresses.com", "http://www.spokeo.com", "http://www.anywho.com", "http://www.peoplefinders.com", "http://www.skipease.com", "https://www.vetfriends.com/",
  "http://radaris.com", "http://www.superpages.com", "https://nuwber.com/", "http://www.192.com", "http://webmii.com", "http://www.yasni.com", "http://www.peekyou.com/united_kingdom",
  "http://britishphonebook.com/", "http://www.canada411.ca", "http://www.freeality.com", "http://world.192.com/", "http://www.spydialer.com/", "http://www.phonevalidator.com", "http://www.fonefinder.net",
  "http://canada.numbers.tel", "http://www.numberway.com/", "https://www.google.com/advanced_search", "https://pipl.com", "http://checkusernames.com", "http://knowem.com",
  "http://exifdata.com/", "http://com.lullar.com", "http://www.emailfinder.com", "http://emailchange.com/", "http://www.criminalsearches.com", "http://www.usatrace.com", "http://www.gps-coordinates.net/",
  "http://db-ip.com/", "https://www.iplocation.net/", "https://www.whois.net", "http://www.ip-tracker.org", "http://monitter.com/", "http://socialmention.com/", "http://www.whostalkin.com/",
  "https://hashkiller.co.uk/", "https://breachalarm.com/", "http://geoimgr.com/", "https://github.com/aquasecurity/cloudsploit", "https://github.com/aquasecurity/tfsec",
  "https://github.com/aquasecurity/kube-hunter", "https://github.com/duo-labs/cloudmapper",
]

# one-click lookups: the tool opens on the value you picked in a case (the "Run" button and the entity menu)
LOOKUP = {
  "Shodan": ("https://www.shodan.io/host/{value}", ["ipv4"]),
  "urlscan.io": ("https://urlscan.io/search/#page.domain:{value}", ["domain"]),
  "PublicWWW": ("https://publicwww.com/websites/%22{value}%22/", ["any"]),
  "Intelligence X": ("https://intelx.io/?s={value}", ["any"]),
  "crt.sh": ("https://crt.sh/?q={value}", ["domain"]),
  "ICANN Lookup": ("https://lookup.icann.org/en/lookup?name={value}", ["domain"]),
  "SecurityTrails": ("https://securitytrails.com/domain/{value}/dns", ["domain"]),
  "ViewDNS.info": ("https://viewdns.info/reverseip/?host={value}&t=1", ["ipv4", "domain"]),
  "BuiltWith": ("https://builtwith.com/{value}", ["domain"]),
  "Wayback Machine": ("https://web.archive.org/web/*/{raw}*", ["domain", "url"]),
  "WhatsMyName": ("https://whatsmyname.app/?q={value}", ["handle"]),
  "IPinfo": ("https://ipinfo.io/{value}", ["ipv4"]),
  "Hurricane Electric BGP Toolkit": ("https://bgp.he.net/ip/{value}", ["ipv4"]),
  "GreyNoise": ("https://viz.greynoise.io/ip/{value}", ["ipv4"]),
  "AbuseIPDB": ("https://www.abuseipdb.com/check/{value}", ["ipv4"]),
  "Spur": ("https://spur.us/context/{value}", ["ipv4"]),
  "VirusTotal": ("https://www.virustotal.com/gui/search/{value}", ["hash", "domain", "ipv4", "url"]),
  "MalwareBazaar": ("https://bazaar.abuse.ch/browse.php?search={value}", ["hash"]),
  "Hybrid Analysis": ("https://www.hybrid-analysis.com/search?query={value}", ["hash"]),
  "Triage": ("https://tria.ge/s?q={value}", ["hash"]),
  "URLhaus": ("https://urlhaus.abuse.ch/browse.php?search={value}", ["url", "domain"]),
  "ThreatFox": ("https://threatfox.abuse.ch/browse.php?search=ioc%3A{value}", ["ipv4", "domain", "hash", "url"]),
  "Have I Been Pwned": ("https://haveibeenpwned.com/account/{value}", ["email"]),
  "mempool.space": ("https://mempool.space/address/{value}", ["btc"]),
  "WalletExplorer": ("https://www.walletexplorer.com/address/{value}", ["btc"]),
  "Etherscan": ("https://etherscan.io/address/{value}", ["btc"]),
  "Tronscan": ("https://tronscan.org/#/address/{value}", ["btc"]),
  "OpenCorporates": ("https://opencorporates.com/companies?q={value}", ["person"]),
  "Companies House": ("https://find-and-update.company-information.service.gov.uk/search?q={value}", ["person"]),
  "OpenSanctions": ("https://www.opensanctions.org/search/?q={value}", ["person"]),
  "ICIJ Offshore Leaks": ("https://offshoreleaks.icij.org/search?q={value}", ["person"]),
  "Ahmia": ("https://ahmia.fi/search/?q={value}", ["any"]),
}

MOVED = {'https://osquery.io/': 'https://osquery.io', 'https://fleetdm.com/': 'https://fleetdm.com', 'https://bazaar.abuse.ch/': 'https://bazaar.abuse.ch', 'https://uncoder.io/': 'https://uncoder.io', 'http://www.tineye.com': 'https://tineye.com', 'https://www.spiderfoot.net/': 'https://github.com/smicallef/spiderfoot', 'https://docs.velociraptor.app/': 'https://docs.velociraptor.app', 'https://securityonion.net/': 'https://securityonion.net', 'https://www.openvas.org/': 'https://www.openvas.org', 'https://shuffler.io/': 'https://shuffler.io', 'https://thehive-project.org': 'https://strangebee.com/thehive/', 'https://www.opencti.io/': 'https://filigran.io/solutions/open-cti/', 'https://capesandbox.com/': 'https://github.com/kevoreilly/CAPEv2', 'https://haveibeenpwned.com/': 'https://haveibeenpwned.com', 'https://sigmahq.io/docs/basics/rules.html': 'https://github.com/SigmaHQ/sigma', 'https://accessdata.com/product-download/ftk-imager-version-4-2-1': 'https://www.exterro.com/digital-forensics-software/ftk-imager', 'https://www.brimdata.io/': 'https://github.com/brimdata/zui', 'https://github.com/lyft/cartography': 'https://github.com/cartography-cncf/cartography', 'https://www.deepl.com': 'https://www.deepl.com/translator', 'https://images.google.com/': 'https://lens.google.com'}

def main():
  urls = [t[1] for t in T]
  assert len(urls) == len(set(urls)), 'duplicate url'
  assert not set(urls) & set(RETIRED), set(urls) & set(RETIRED)
  assert all(v in urls for v in MOVED.values()) and not set(MOVED) & set(RETIRED)
  assert set(LOOKUP) <= {t[0] for t in T}, set(LOOKUP) - {t[0] for t in T}
  out = []
  for i, (name, url, cat, sub, lic, desc, tags) in enumerate(T, 1):
    out.append({"id": 200 + i, "name": name, "url": url, "parentCategory": cat, "childCategory": sub, "description": desc,
                "tags": [lic] + [x for x in tags if x != lic], "isPinned": False, "isStarred": False, "dateAdded": "2026-11-26"})
    if name in LOOKUP: out[-1]["lookup"] = list(LOOKUP[name])
  body = ('/* Default toolbox — curated in 1.89: maintained tools that are used in real investigations, mostly free or open source.\n'
          '   The first tag is the licence (open-source, free, freemium, commercial). Generated by tools/make_tools.py — edit there.\n'
          '   New entries appear in everyone\'s toolbox on next load; deleted ones stay deleted. TOOLS_RETIRED: earlier entries taken out\n'
          '   of a workspace once, unless the user starred, pinned, used or edited them. */\n'
          'const TOOLS_SEED = ' + json.dumps(out, indent=2, ensure_ascii=False) + ';\n'
          'const TOOLS_RETIRED = ' + json.dumps(RETIRED, indent=2) + ';\n'
          '/* the same tool at a new address: a copy at the old one moves, keeping your stars, notes and use count */\n'
          'const TOOLS_MOVED = ' + json.dumps(MOVED, indent=2) + ';\n')
  (root / 'js' / 'data' / 'tools.js').write_text(body, encoding='utf-8', newline='\n')
  print(len(out), 'tools,', len(RETIRED), 'retired')

if __name__ == '__main__':
  main()
