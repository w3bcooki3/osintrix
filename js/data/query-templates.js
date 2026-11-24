/* Default query library (search recipes with {{BLANKS}}).
   Plain JSON after the "=" — edit it like a .json file. Loaded as a script so the app also works from file://. */
const QUERY_SEED = [
  {
    "id": 1,
    "name": "Exposed Database Files",
    "description": "Find exposed database files and backups on web servers.",
    "query": "filetype:sql OR filetype:db OR filetype:mdb OR filetype:sqlite",
    "category": "databases",
    "engines": [
      "google",
      "bing"
    ],
    "tags": [
      "database",
      "sql",
      "backup",
      "exposed",
      "data leak"
    ]
  },
  {
    "id": 2,
    "name": "Admin Login Panels",
    "description": "Discover publicly accessible administration and login interfaces.",
    "query": "inurl:admin OR inurl:login OR intitle:\"admin panel\" OR intitle:\"login page\"",
    "category": "login",
    "engines": [
      "google",
      "bing"
    ],
    "tags": [
      "admin",
      "login",
      "interface",
      "panel",
      "access"
    ]
  },
  {
    "id": 3,
    "name": "Open MongoDB Instances",
    "description": "Identify exposed MongoDB instances on the internet.",
    "query": "port:27017 product:MongoDB",
    "category": "databases",
    "engines": [
      "shodan"
    ],
    "tags": [
      "mongodb",
      "database",
      "exposed",
      "nosql",
      "vulnerability"
    ]
  },
  {
    "id": 4,
    "name": "SSH Servers with Specific Version",
    "description": "Locate SSH servers running a particular version, often for vulnerability assessment.",
    "query": "port:22 product:OpenSSH version:{{SSH_VERSION}}",
    "category": "vulnerabilities",
    "engines": [
      "shodan",
      "censys"
    ],
    "tags": [
      "ssh",
      "remote access",
      "server",
      "version",
      "vulnerability"
    ]
  },
  {
    "id": 5,
    "name": "Public Cloud Storage Buckets",
    "description": "Find misconfigured or exposed cloud storage buckets (AWS S3, GCP Storage).",
    "query": "site:s3.amazonaws.com OR site:storage.googleapis.com OR site:blob.core.windows.net",
    "category": "cloud",
    "engines": [
      "google",
      "bing"
    ],
    "tags": [
      "cloud",
      "storage",
      "aws",
      "gcp",
      "azure",
      "bucket",
      "misconfiguration"
    ]
  },
  {
    "id": 6,
    "name": "Exposed IP Cameras",
    "description": "Identify accessible IP cameras and surveillance systems.",
    "query": "port:554 product:\"IP Camera\" OR inurl:view/viewer.shtml",
    "category": "iot",
    "engines": [
      "shodan",
      "zoomeye"
    ],
    "tags": [
      "iot",
      "camera",
      "webcam",
      "surveillance",
      "exposed"
    ]
  },
  {
    "id": 7,
    "name": "Sensitive Configuration Files on GitHub",
    "description": "Search for common configuration files that may contain sensitive information in public GitHub repositories.",
    "query": "filename:.env OR filename:config.php OR filename:wp-config.php OR extension:yml AND in:file password",
    "category": "files",
    "engines": [
      "github"
    ],
    "tags": [
      "config",
      "credentials",
      "api key",
      "source code",
      "leak"
    ]
  },
  {
    "id": 8,
    "name": "Government Employee Emails",
    "description": "Discover email addresses of individuals within government domains.",
    "query": "site:gov filetype:pdf intext:email",
    "category": "government",
    "engines": [
      "google"
    ],
    "tags": [
      "government",
      "email",
      "contact",
      "osint"
    ]
  },
  {
    "id": 9,
    "name": "Pastebin API Keys/Credentials",
    "description": "Search Pastebin for leaked API keys, passwords, or sensitive data.",
    "query": "site:pastebin.com (api_key OR password OR \"private key\" OR credential OR token)",
    "category": "data leaks",
    "engines": [
      "google",
      "pastebin"
    ],
    "tags": [
      "pastebin",
      "leak",
      "credentials",
      "api key",
      "sensitive data"
    ]
  },
  {
    "id": 10,
    "name": "Webcams via BinaryEdge",
    "description": "Find open webcams using BinaryEdge, often misconfigured.",
    "query": "tag:webcam product:goahead",
    "category": "iot",
    "engines": [
      "binaryedge"
    ],
    "tags": [
      "webcam",
      "iot",
      "surveillance",
      "exposed",
      "binaryedge"
    ]
  },
  {
    "id": 11,
    "name": "Email Addresses via IntelX",
    "description": "Search for email addresses in IntelX database.",
    "query": "type:1 \"{{EMAIL_DOMAIN}}\"",
    "category": "osint",
    "engines": [
      "intelx"
    ],
    "tags": [
      "email",
      "osint",
      "intelx",
      "reconnaissance"
    ]
  },
  {
    "id": 12,
    "name": "Specific CVE Vulnerability on Shodan",
    "description": "Search Shodan for systems vulnerable to a particular CVE.",
    "query": "vuln:{{CVE_ID}}",
    "category": "vulnerabilities",
    "engines": [
      "shodan"
    ],
    "tags": [
      "cve",
      "vulnerability",
      "exploit",
      "shodan"
    ]
  },
  {
    "id": 13,
    "name": "HTTP Basic Auth Panels",
    "description": "Find web pages protected by HTTP Basic Authentication, often revealing exposed directories.",
    "query": "intitle:\"Restricted Area\" OR inurl:auth OR intext:\"basic authentication\"",
    "category": "login",
    "engines": [
      "google",
      "bing"
    ],
    "tags": [
      "authentication",
      "exposed",
      "http",
      "panel"
    ]
  },
  {
    "id": 14,
    "name": "SQL Injection Vulnerabilities (Generic)",
    "description": "Attempt to identify potential SQL injection points by searching for common error messages.",
    "query": "intext:\"SQL syntax\" OR intext:\"mysql_fetch_array()\" OR intext:\"Warning: mysql_num_rows()\"",
    "category": "vulnerabilities",
    "engines": [
      "google",
      "bing"
    ],
    "tags": [
      "sql injection",
      "vulnerability",
      "web security",
      "error message"
    ]
  },
  {
    "id": 15,
    "name": "Apache Struts RCE Exposure",
    "description": "Find potentially vulnerable Apache Struts instances exposed online.",
    "query": "http.title:\"Apache Struts\" product:\"Apache httpd\" port:8080",
    "category": "vulnerabilities",
    "engines": [
      "shodan",
      "fofa"
    ],
    "tags": [
      "apache",
      "struts",
      "rce",
      "vulnerability",
      "server"
    ]
  },
  {
    "id": 16,
    "name": "WordPress Vulnerabilities",
    "description": "Identify WordPress sites with known vulnerabilities",
    "query": "inurl:wp-content OR inurl:wp-includes intitle:\"WordPress\"",
    "category": "web",
    "engines": [
      "google",
      "bing"
    ],
    "tags": [
      "wordpress",
      "cms",
      "vulnerability",
      "php"
    ]
  },
  {
    "id": 17,
    "name": "IoT Devices by Manufacturer",
    "description": "Find specific IoT devices by manufacturer",
    "query": "product:\"D-Link\" port:80",
    "category": "iot",
    "engines": [
      "shodan"
    ],
    "tags": [
      "iot",
      "device",
      "manufacturer",
      "smart-home"
    ]
  },
  {
    "id": 18,
    "name": "Employee Directories",
    "description": "Search for exposed employee directories or lists",
    "query": "intitle:\"employee directory\" OR intitle:\"staff list\"",
    "category": "people",
    "engines": [
      "google",
      "bing"
    ],
    "tags": [
      "employee",
      "directory",
      "staff",
      "osint"
    ]
  },
  {
    "id": 19,
    "name": "Google Docs Public",
    "description": "Find publicly accessible Google Docs",
    "query": "site:docs.google.com inurl:edit filetype:doc",
    "category": "cloud",
    "engines": [
      "google"
    ],
    "tags": [
      "google-docs",
      "cloud",
      "public",
      "sharing"
    ]
  },
  {
    "id": 20,
    "name": "Exposed AWS S3 Buckets",
    "description": "Specific search for exposed AWS S3 buckets",
    "query": "site:.s3.amazonaws.com public",
    "category": "cloud",
    "engines": [
      "google"
    ],
    "tags": [
      "aws",
      "s3",
      "bucket",
      "cloud"
    ]
  },
  {
    "id": 21,
    "name": "Social Media OSINT",
    "description": "Find public social media profiles related to a keyword",
    "query": "site:twitter.com OR site:linkedin.com \"keyword\"",
    "category": "social",
    "engines": [
      "google"
    ],
    "tags": [
      "social-media",
      "osint",
      "profile",
      "public"
    ]
  },
  {
    "id": 22,
    "name": "Government Tender Documents",
    "description": "Locate public government tender documents",
    "query": "site:gov.au filetype:pdf tender OR bid",
    "category": "government",
    "engines": [
      "google"
    ],
    "tags": [
      "government",
      "tender",
      "procurement",
      "public-records"
    ]
  },
  {
    "id": 23,
    "name": "Exposed Log Files",
    "description": "Find publicly exposed server log files",
    "query": "filetype:log access_log OR error_log",
    "category": "files",
    "engines": [
      "google",
      "bing"
    ],
    "tags": [
      "logs",
      "server",
      "exposed",
      "debug"
    ]
  },
  {
    "id": 24,
    "name": "Vulnerable Jenkins Instances",
    "description": "Find exposed Jenkins CI/CD servers",
    "query": "product:Jenkins port:8080",
    "category": "vulnerabilities",
    "engines": [
      "shodan",
      "censys"
    ],
    "tags": [
      "jenkins",
      "ci/cd",
      "exposed",
      "devops"
    ]
  },
  {
    "id": 25,
    "name": "IoT Dashboards",
    "description": "Discover exposed IoT control panels/dashboards",
    "query": "intitle:\"dashboard\" inurl:iot",
    "category": "iot",
    "engines": [
      "google",
      "bing"
    ],
    "tags": [
      "iot",
      "dashboard",
      "control",
      "exposed"
    ]
  },
  {
    "id": 26,
    "name": "Company Contact Lists",
    "description": "Search for exposed company contact information",
    "query": "intitle:\"contact us\" OR \"our team\" filetype:xls",
    "category": "people",
    "engines": [
      "google",
      "bing"
    ],
    "tags": [
      "company",
      "contact",
      "employees",
      "osint"
    ]
  },
  {
    "id": 27,
    "name": "Git Repositories",
    "description": "Find exposed .git directories or repository leaks",
    "query": "inurl:.git/config OR inurl:.git/HEAD",
    "category": "files",
    "engines": [
      "google",
      "bing"
    ],
    "tags": [
      "git",
      "repository",
      "exposed",
      "source-code"
    ]
  },
  {
    "id": 28,
    "name": "Blockchain Explorers",
    "description": "Access public blockchain explorers for crypto investigations",
    "query": "site:etherscan.io OR site:blockchain.com bitcoin",
    "category": "crypto",
    "engines": [
      "google"
    ],
    "tags": [
      "blockchain",
      "crypto",
      "bitcoin",
      "ethereum"
    ]
  },
  {
    "id": 29,
    "name": "Dark Web Forums (via Clearnet)",
    "description": "Find mentions or links to dark web forums on clearnet",
    "query": "site:.onion link:forum OR \"darknet market\"",
    "category": "dark-web",
    "engines": [
      "google"
    ],
    "tags": [
      "darkweb",
      "forum",
      "market",
      "clearnet"
    ]
  },
  {
    "id": 30,
    "name": "Vulnerable Routers",
    "description": "Identify potentially vulnerable router interfaces",
    "query": "intitle:\"router setup\" OR \"admin login\" inurl:8080",
    "category": "network",
    "engines": [
      "google",
      "shodan"
    ],
    "tags": [
      "router",
      "vulnerability",
      "network",
      "admin"
    ]
  },
  {
    "id": 31,
    "name": "Specific SSH Version via Shodan",
    "description": "Find SSH servers running a specific version (e.g., for known vulnerabilities)",
    "query": "port:22 product:OpenSSH version:{{SSH_VERSION}}",
    "category": "vulnerabilities",
    "engines": [
      "shodan"
    ],
    "tags": [
      "ssh",
      "version",
      "vulnerability"
    ]
  },
  {
    "id": 32,
    "name": "Emails from Specific Domain (IntelX)",
    "description": "Search for email addresses from a specific domain in IntelX",
    "query": "type:1 \"{{EMAIL_DOMAIN}}\"",
    "category": "osint",
    "engines": [
      "intelx"
    ],
    "tags": [
      "email",
      "osint",
      "domain"
    ]
  },
  {
    "id": 33,
    "name": "Apache Struts CVE Search (Shodan)",
    "description": "Search Shodan for Apache Struts instances vulnerable to a specific CVE",
    "query": "product:Apache Struts vuln:{{CVE_ID}}",
    "category": "vulnerabilities",
    "engines": [
      "shodan"
    ],
    "tags": [
      "apache",
      "struts",
      "cve",
      "vulnerability"
    ]
  },
  {
    "id": 34,
    "name": "Public Trello Boards",
    "description": "Find publicly accessible Trello boards that might contain sensitive information",
    "query": "site:trello.com inurl:board intext:confidential OR password",
    "category": "cloud",
    "engines": [
      "google",
      "bing"
    ],
    "tags": [
      "trello",
      "collaboration",
      "exposed",
      "misconfiguration"
    ]
  },
  {
    "id": 35,
    "name": "Exposed ElasticSearch Instances",
    "description": "Discover publicly accessible ElasticSearch instances",
    "query": "port:9200 product:ElasticSearch",
    "category": "databases",
    "engines": [
      "shodan"
    ],
    "tags": [
      "elasticsearch",
      "database",
      "exposed",
      "nosql"
    ]
  },
  {
    "id": 36,
    "name": "Microsoft Exchange Web Access",
    "description": "Find Microsoft Exchange Web Access (OWA) portals",
    "query": "intitle:\"Outlook Web App\" inurl:owa",
    "category": "web",
    "engines": [
      "google",
      "bing"
    ],
    "tags": [
      "exchange",
      "owa",
      "webmail"
    ]
  },
  {
    "id": 37,
    "name": "Open Jenkins Servers",
    "description": "Find Jenkins servers that might be openly accessible",
    "query": "intitle:\"Jenkins\" inurl:jenkins/login",
    "category": "web",
    "engines": [
      "google",
      "bing"
    ],
    "tags": [
      "jenkins",
      "ci/cd",
      "exposed"
    ]
  },
  {
    "id": 38,
    "name": "Exposed Docker Registries",
    "description": "Identify public or misconfigured Docker registries",
    "query": "port:5000 \"Docker Registry\"",
    "category": "cloud",
    "engines": [
      "shodan"
    ],
    "tags": [
      "docker",
      "registry",
      "exposed",
      "container"
    ]
  },
  {
    "id": 39,
    "name": "Confidential PDFs",
    "description": "Search for PDF documents containing the word 'confidential'",
    "query": "filetype:pdf confidential",
    "category": "files",
    "engines": [
      "google",
      "bing"
    ],
    "tags": [
      "pdf",
      "confidential",
      "document"
    ]
  },
  {
    "id": 40,
    "name": "Public CCTV Streams",
    "description": "Find public CCTV camera streams",
    "query": "inurl:\"/view/viewer_index.shtml\" intitle:\"Live View\"",
    "category": "iot",
    "engines": [
      "google"
    ],
    "tags": [
      "cctv",
      "camera",
      "stream",
      "public"
    ]
  },
  {
    "id": 41,
    "name": "Exposed RDP Servers",
    "description": "Find systems with exposed RDP (Remote Desktop Protocol)",
    "query": "port:3389",
    "category": "remote-access",
    "engines": [
      "shodan",
      "censys",
      "zoomeye"
    ],
    "tags": [
      "rdp",
      "remote",
      "desktop",
      "access"
    ]
  },
  {
    "id": 42,
    "name": "Publicly Accessible FTP Servers",
    "description": "Find exposed FTP servers allowing anonymous login",
    "query": "port:21 \"Anonymous FTP login accepted\"",
    "category": "network",
    "engines": [
      "shodan",
      "censys"
    ],
    "tags": [
      "ftp",
      "filetransfer",
      "exposed",
      "anonymous"
    ]
  },
  {
    "id": 43,
    "name": "Cisco IOS Devices",
    "description": "Identify exposed Cisco IOS devices",
    "query": "product:\"Cisco IOS\" port:8080",
    "category": "network",
    "engines": [
      "shodan",
      "censys",
      "zoomeye"
    ],
    "tags": [
      "cisco",
      "network",
      "device",
      "router"
    ]
  },
  {
    "id": 44,
    "name": "Wayback Machine - All Snapshots for Domain",
    "description": "Find all historical snapshots of a given domain using Wayback Machine via Google.",
    "query": "site:web.archive.org/web/* {{DOMAIN_NAME}}",
    "category": "osint",
    "engines": [
      "google"
    ],
    "tags": [
      "wayback machine",
      "archive",
      "domain",
      "osint",
      "historical data"
    ]
  },
  {
    "id": 45,
    "name": "Wayback Machine - Specific File Type on Domain",
    "description": "Search for specific file types (e.g., PDF, DOCX) on a domain's historical snapshots.",
    "query": "site:web.archive.org/web/* {{DOMAIN_NAME}} filetype:{{FILE_TYPE}}",
    "category": "files",
    "engines": [
      "google"
    ],
    "tags": [
      "wayback machine",
      "archive",
      "file type",
      "osint",
      "historical data"
    ]
  },
  {
    "id": 46,
    "name": "GitHub - Private Key Exposure",
    "description": "Identify repositories containing common private key extensions that might be exposed.",
    "query": "extension:pem OR extension:key OR extension:ppk OR extension:p12 OR filename:id_rsa",
    "category": "code & files",
    "engines": [
      "github"
    ],
    "tags": [
      "github",
      "private key",
      "credentials",
      "exposed",
      "leak",
      "source code"
    ]
  },
  {
    "id": 47,
    "name": "GitHub - API Key Exposure (Generic)",
    "description": "Search for generic API key patterns in GitHub repositories.",
    "query": "github_token OR api_key OR authorization_key OR client_secret OR consumer_key",
    "category": "code & files",
    "engines": [
      "github"
    ],
    "tags": [
      "github",
      "api key",
      "token",
      "credentials",
      "exposed",
      "leak"
    ]
  },
  {
    "id": 48,
    "name": "GitHub - SQL Dump/Database Files",
    "description": "Find SQL database dumps or backup files exposed on GitHub.",
    "query": "filename:dump.sql OR extension:sql in:file database password",
    "category": "databases",
    "engines": [
      "github"
    ],
    "tags": [
      "github",
      "sql",
      "database",
      "dump",
      "exposed",
      "leak"
    ]
  },
  {
    "id": 49,
    "name": "GitHub - History of Deleted Files",
    "description": "Leverage GitHub's history to find content from deleted files (requires manual investigation of results).",
    "query": "in:history \"deleted file\" OR \"removed credentials\" OR \"secret\"",
    "category": "code & files",
    "engines": [
      "github"
    ],
    "tags": [
      "github",
      "history",
      "deleted files",
      "leak",
      "version control"
    ]
  },
  {
    "id": 50,
    "name": "Wayback Machine - Sensitive Keywords",
    "description": "Search Wayback Machine archives for specific sensitive keywords on a domain.",
    "query": "site:web.archive.org/web/* {{DOMAIN_NAME}} (password OR confidential OR secret OR private)",
    "category": "data leaks",
    "engines": [
      "google"
    ],
    "tags": [
      "wayback machine",
      "sensitive data",
      "keywords",
      "osint",
      "data leak"
    ]
  },
  {
    "id": 51,
    "name": "Publicly Exposed .git Folder",
    "description": "Find web servers with exposed .git folders containing repository information.",
    "query": "inurl:.git/HEAD OR inurl:.git/config",
    "category": "files",
    "engines": [
      "google",
      "bing"
    ],
    "tags": [
      "git",
      "exposed",
      "repository",
      "misconfiguration"
    ]
  },
  {
    "id": 52,
    "name": "Open Redirect Vulnerabilities",
    "description": "Discover potential open redirect vulnerabilities on websites.",
    "query": "inurl:redirect= OR inurl:url= OR inurl:next= site:{{TARGET_SITE}}",
    "category": "vulnerabilities",
    "engines": [
      "google",
      "bing"
    ],
    "tags": [
      "vulnerability",
      "open redirect",
      "web security"
    ]
  },
  {
    "id": 53,
    "name": "Cross-Site Scripting (XSS) - Reflected",
    "description": "Search for common reflected XSS patterns in URLs.",
    "query": "inurl:\"<script>alert\" OR inurl:\"javascript:alert\" site:{{TARGET_SITE}}",
    "category": "vulnerabilities",
    "engines": [
      "google",
      "bing"
    ],
    "tags": [
      "xss",
      "vulnerability",
      "web security",
      "injection"
    ]
  },
  {
    "id": 54,
    "name": "Exposed Nginx Configuration Files",
    "description": "Locate publicly accessible Nginx configuration files that might reveal server details.",
    "query": "filetype:conf intext:nginx version",
    "category": "files",
    "engines": [
      "google",
      "bing"
    ],
    "tags": [
      "nginx",
      "config",
      "exposed",
      "server"
    ]
  },
  {
    "id": 55,
    "name": "Open Proxy Servers",
    "description": "Identify potentially open proxy servers.",
    "query": "intitle:\"Proxy Server\" inurl:proxy.php OR intext:\"Powered by Squid\"",
    "category": "network",
    "engines": [
      "google",
      "bing"
    ],
    "tags": [
      "proxy",
      "open proxy",
      "network"
    ]
  },
  {
    "id": 56,
    "name": "OSINT - Social Media Profiles by Name",
    "description": "Find public social media profiles (Twitter, LinkedIn, Facebook, Instagram) for a given name.",
    "query": "\"{{FULL_NAME}}\" site:twitter.com OR site:linkedin.com OR site:facebook.com OR site:instagram.com",
    "category": "osint",
    "engines": [
      "google",
      "bing"
    ],
    "tags": [
      "osint",
      "social media",
      "person",
      "reconnaissance"
    ]
  },
  {
    "id": 57,
    "name": "OSINT - Company Documents/Presentations",
    "description": "Locate public documents or presentations from a specific company, often containing internal data.",
    "query": "site:{{COMPANY_DOMAIN}} filetype:ppt OR filetype:pptx OR filetype:pdf OR filetype:doc OR filetype:docx (confidential OR internal OR proprietary)",
    "category": "osint",
    "engines": [
      "google",
      "bing"
    ],
    "tags": [
      "osint",
      "company",
      "documents",
      "data leak",
      "corporate intelligence"
    ]
  },
  {
    "id": 58,
    "name": "OSINT - Email Lists/Spreadsheets",
    "description": "Find spreadsheets or documents containing lists of email addresses.",
    "query": "filetype:xls OR filetype:xlsx OR filetype:csv intext:@{{DOMAIN_NAME}}",
    "category": "osint",
    "engines": [
      "google",
      "bing"
    ],
    "tags": [
      "osint",
      "email",
      "list",
      "spreadsheet",
      "data leak"
    ]
  },
  {
    "id": 59,
    "name": "OSINT - Forum/Blog Mentions of Entity",
    "description": "Search for mentions of a specific entity (person, company, product) across forums and blogs.",
    "query": "intext:\"{{ENTITY_NAME}}\" (inurl:forum OR inurl:blog OR inurl:comment)",
    "category": "osint",
    "engines": [
      "google",
      "bing"
    ],
    "tags": [
      "osint",
      "reputation",
      "mentions",
      "forum",
      "blog"
    ]
  },
  {
    "id": 60,
    "name": "GitHub - Exposed SSH Keys",
    "description": "Find public GitHub repositories containing .ssh directories or common SSH key names.",
    "query": "inpath:.ssh id_rsa OR id_dsa OR known_hosts",
    "category": "code & files",
    "engines": [
      "github"
    ],
    "tags": [
      "github",
      "ssh key",
      "credentials",
      "exposed",
      "leak",
      "source code"
    ]
  },
  {
    "id": 61,
    "name": "GitHub - AWS Credentials Exposure",
    "description": "Search for common AWS credential patterns in GitHub repositories.",
    "query": "aws_access_key_id OR aws_secret_access_key OR \"AKIA\" OR \"ASIA\"",
    "category": "cloud",
    "engines": [
      "github"
    ],
    "tags": [
      "github",
      "aws",
      "credentials",
      "exposed",
      "cloud",
      "leak"
    ]
  },
  {
    "id": 62,
    "name": "GitHub - Google API Key Exposure",
    "description": "Find Google API keys in public GitHub repositories.",
    "query": "AIza{{GOOGLE_API_KEY_PATTERN}}",
    "category": "cloud",
    "engines": [
      "github"
    ],
    "tags": [
      "github",
      "google api",
      "api key",
      "credentials",
      "exposed",
      "cloud"
    ]
  },
  {
    "id": 63,
    "name": "Wayback Machine - Domain Whois History",
    "description": "Look for historical WHOIS records via Wayback Machine (may require external WHOIS tools, but directs to archive).",
    "query": "site:whois.domaintools.com/{{DOMAIN_NAME}} OR site:who.is/whois/{{DOMAIN_NAME}}",
    "category": "osint",
    "engines": [
      "google"
    ],
    "tags": [
      "wayback machine",
      "whois",
      "domain",
      "osint",
      "historical data"
    ]
  },
  {
    "id": 64,
    "name": "Wayback Machine - CMS Login Pages",
    "description": "Find historical login pages for common CMS (e.g., WordPress, Joomla, Drupal) on a specific domain.",
    "query": "site:web.archive.org/web/* {{DOMAIN_NAME}} (inurl:wp-admin OR inurl:administrator OR inurl:user/login)",
    "category": "login",
    "engines": [
      "google"
    ],
    "tags": [
      "wayback machine",
      "cms",
      "login",
      "vulnerability",
      "historical data"
    ]
  },
  {
    "id": 65,
    "name": "Wayback Machine - Old API Endpoints",
    "description": "Discover old or deprecated API endpoints in historical snapshots that might be vulnerable.",
    "query": "site:web.archive.org/web/* {{DOMAIN_NAME}} inurl:api/v1 OR inurl:oldapi OR intext:\"deprecated endpoint\"",
    "category": "vulnerabilities",
    "engines": [
      "google"
    ],
    "tags": [
      "wayback machine",
      "api",
      "vulnerability",
      "historical data"
    ]
  },
  {
    "id": 66,
    "name": "OSINT - Exposed Employee Resumes/CVs",
    "description": "Search for public resumes or CVs associated with a company or domain, potentially revealing sensitive information.",
    "query": "site:{{COMPANY_DOMAIN}} filetype:pdf (resume OR CV OR curriculum vitae) OR intext:\"looking for a new opportunity\" intext:{{COMPANY_NAME}}",
    "category": "osint",
    "engines": [
      "google",
      "bing"
    ],
    "tags": [
      "osint",
      "employee",
      "resume",
      "cv",
      "personal data",
      "reconnaissance"
    ]
  },
  {
    "id": 67,
    "name": "OSINT - Exposed Google Groups/Forums",
    "description": "Find publicly accessible Google Groups or other forum discussions related to a target.",
    "query": "site:groups.google.com intext:{{TARGET_KEYWORD}} (confidential OR internal OR restricted)",
    "category": "osint",
    "engines": [
      "google"
    ],
    "tags": [
      "osint",
      "forum",
      "google groups",
      "discussion",
      "data leak"
    ]
  },
  {
    "id": 68,
    "name": "GitHub - Exposed Database Connection Strings",
    "description": "Search for common database connection string patterns in public GitHub repositories.",
    "query": "jdbc:mysql:// OR postgresql:// OR mongodb:// OR sqlserver:// in:file password",
    "category": "databases",
    "engines": [
      "github"
    ],
    "tags": [
      "github",
      "database",
      "connection string",
      "credentials",
      "exposed",
      "leak"
    ]
  },
  {
    "id": 69,
    "name": "GitHub - Generic Sensitive Information (Broad)",
    "description": "A broad search for commonly exposed sensitive terms in GitHub repositories.",
    "query": "password OR credentials OR secret OR token OR api_key OR private_key OR id_rsa OR .env",
    "category": "code & files",
    "engines": [
      "github"
    ],
    "tags": [
      "github",
      "sensitive data",
      "credentials",
      "leak",
      "broad scan"
    ]
  },
  {
    "id": 70,
    "name": "Wayback Machine - Exposed Directories/Indexes",
    "description": "Discover historical snapshots of exposed directories or file indexes.",
    "query": "site:web.archive.org/web/* {{DOMAIN_NAME}} intitle:\"index of\" OR intitle:\"directory listing for\"",
    "category": "files",
    "engines": [
      "google"
    ],
    "tags": [
      "wayback machine",
      "directory listing",
      "exposed",
      "files",
      "historical data"
    ]
  }
];

/* Query pack (v1.69): investigation queries — infrastructure pivots, cloud exposure, leaks, chat platforms,
   threat hunting. Merged once into existing libraries (DB.qSeeded keeps what was offered, so a deleted query stays deleted). */
const QUERY_PACK = [
  /* ---- infrastructure pivots: one artefact of a server to every server that shares it ---- */
  {id:'p01', name:'Shodan — servers sharing a favicon', description:'Every host serving the same favicon (MurmurHash3 of the base64 icon, as Shodan computes it). Phishing kits, C2 panels and admin consoles keep their icon when they move.', query:'http.favicon.hash:{{FAVICON_HASH}}', category:'pivots', engines:['shodan'], tags:['favicon','pivot','phishing','c2']},
  {id:'p02', name:'FOFA — servers sharing a favicon', description:'The same pivot on FOFA, which often sees hosts Shodan missed (Asia-hosted especially).', query:'icon_hash="{{FAVICON_HASH}}"', category:'pivots', engines:['fofa'], tags:['favicon','pivot']},
  {id:'p03', name:'ZoomEye — servers sharing a favicon', description:'Third engine for the favicon pivot — overlap across engines raises confidence, gaps are leads.', query:'iconhash:"{{FAVICON_HASH}}"', category:'pivots', engines:['zoomeye'], tags:['favicon','pivot']},
  {id:'p04', name:'Censys — servers sharing a favicon (MD5)', description:'Censys indexes the favicon MD5, not the Shodan hash — compute both from the same icon.', query:'services.http.response.favicons.md5_hash: {{FAVICON_MD5}}', category:'pivots', engines:['censys'], tags:['favicon','pivot']},
  {id:'p05', name:'Shodan — same JARM TLS fingerprint', description:'Servers answering TLS the same way. A JARM alone is weak (shared by stock servers); combine with an ASN, port or certificate detail.', query:'ssl.jarm:{{JARM}}', category:'pivots', engines:['shodan'], tags:['jarm','tls','c2']},
  {id:'p06', name:'Censys — same JARM TLS fingerprint', description:'JARM pivot on Censys. Add a non-standard port or an issuer to cut stock-server noise.', query:'services.jarm.fingerprint: {{JARM}}', category:'pivots', engines:['censys'], tags:['jarm','tls']},
  {id:'p07', name:'FOFA — same JARM TLS fingerprint', description:'JARM pivot on FOFA.', query:'jarm="{{JARM}}"', category:'pivots', engines:['fofa'], tags:['jarm','tls']},
  {id:'p08', name:'Censys — same SSH host key', description:'An SSH host key is generated once per install. Two IPs with the same key are the same machine, or a cloned image — one of the strongest infrastructure ties.', query:'services.ssh.server_host_key.fingerprint_sha256: {{SSH_FP}}', category:'pivots', engines:['censys'], tags:['ssh','host-key','pivot']},
  {id:'p09', name:'Shodan — same SSH host key (fingerprint in banner)', description:'Shodan prints the host-key fingerprint in the SSH banner, so a quoted search finds the other IPs.', query:'"{{SSH_FP}}"', category:'pivots', engines:['shodan'], tags:['ssh','host-key','pivot']},
  {id:'p10', name:'Censys — certificates naming a domain', description:'Hosts presenting a certificate for the domain — finds origin servers behind a CDN and forgotten staging hosts.', query:'services.tls.certificates.leaf_data.subject.common_name: "{{DOMAIN_NAME}}" or services.tls.certificates.leaf_data.names: "{{DOMAIN_NAME}}"', category:'pivots', engines:['censys'], tags:['certificate','origin','cdn']},
  {id:'p11', name:'Shodan — certificates naming a domain', description:'Same origin-finding pivot on Shodan; check hosts outside the CDN ranges.', query:'ssl.cert.subject.cn:"{{DOMAIN_NAME}}"', category:'pivots', engines:['shodan'], tags:['certificate','origin']},
  {id:'p12', name:'FOFA — certificates naming a domain', description:'Certificate pivot on FOFA.', query:'cert="{{DOMAIN_NAME}}"', category:'pivots', engines:['fofa'], tags:['certificate','origin']},
  {id:'p13', name:'crt.sh — every certificate for a domain and its subdomains', description:'Certificate Transparency: all certificates ever logged for the domain. New subdomains, staging hosts, and the date each appeared.', query:'%.{{DOMAIN_NAME}}', category:'pivots', engines:['crtsh'], tags:['ct','subdomains','certificate']},
  {id:'p14', name:'crt.sh — certificates by organisation name', description:'Certificates whose subject names the organisation — finds domains the company owns that do not share its main name.', query:'{{ORG_NAME}}', category:'pivots', engines:['crtsh'], tags:['ct','organisation']},
  {id:'p15', name:'Shodan — same HTML page body', description:'Hosts serving byte-identical HTML (Shodan http.html_hash). Kit pages, parked pages and panels cluster this way.', query:'http.html_hash:{{HTML_HASH}}', category:'pivots', engines:['shodan'], tags:['html','pivot','kit']},
  {id:'p16', name:'Shodan — same page title on an ASN', description:'A page title within one network — narrows a generic title down to an operator.', query:'http.title:"{{TITLE}}" asn:AS{{ASN}}', category:'pivots', engines:['shodan'], tags:['title','asn']},
  {id:'p17', name:'Censys — same page title', description:'Title pivot on Censys.', query:'services.http.response.html_title: "{{TITLE}}"', category:'pivots', engines:['censys'], tags:['title']},
  {id:'p18', name:'Analytics or ad ID across sites', description:'A Google Analytics, Tag Manager or AdSense ID reused across sites ties them to one owner. Search the source-code engine and the web.', query:'"{{ANALYTICS_ID}}"', category:'pivots', engines:['publicwww','google','bing'], tags:['analytics','gtm','adsense','ownership']},
  {id:'p19', name:'FOFA — page body containing an ID or string', description:'Any string in the HTML body — analytics IDs, wallet addresses, Telegram links on scam pages, unique kit comments.', query:'body="{{STRING}}"', category:'pivots', engines:['fofa'], tags:['body','pivot']},
  {id:'p20', name:'Bing — every site on an IP', description:'Bing still supports the ip: operator — a quick reverse-IP of indexed sites on shared hosting.', query:'ip:{{IP}}', category:'pivots', engines:['bing'], tags:['reverse-ip','shared-hosting']},
  {id:'p21', name:'urlscan — scans of a domain', description:'Every public urlscan.io scan of the domain: screenshots, redirect chains, the IPs and the scripts each page loaded.', query:'page.domain:{{DOMAIN_NAME}}', category:'pivots', engines:['urlscan'], tags:['urlscan','phishing','history']},
  {id:'p22', name:'urlscan — pages hosted on an IP', description:'Pages other people scanned on the same IP — sibling phishing sites on one server.', query:'page.ip:"{{IP}}"', category:'pivots', engines:['urlscan'], tags:['urlscan','ip']},
  {id:'p23', name:'urlscan — pages that loaded the same file', description:'Pages that loaded a resource with this SHA-256 (a kit script, logo or favicon) — the strongest way to cluster phishing kits.', query:'hash:{{SHA256}}', category:'pivots', engines:['urlscan'], tags:['urlscan','kit','hash']},
  {id:'p24', name:'urlscan — brand look-alikes not on the brand domain', description:'Pages titled with the brand but hosted elsewhere — live phishing of the brand.', query:'page.title:"{{BRAND}}" AND NOT page.domain:{{DOMAIN_NAME}}', category:'pivots', engines:['urlscan'], tags:['urlscan','brand','phishing']},
  {id:'p25', name:'Shodan — hosts in an organisation or ASN', description:'Everything Shodan sees in the organisation’s networks — the external attack surface in one list.', query:'org:"{{ORG_NAME}}"', category:'pivots', engines:['shodan'], tags:['attack-surface','asn']},

  /* ---- adversary infrastructure hunting ---- */
  {id:'p30', name:'Cobalt Strike team servers (default certificate)', description:'The default Cobalt Strike certificate serial 146473198 — lazy operators never replace it.', query:'ssl.cert.serial:146473198', category:'threat-hunt', engines:['shodan'], tags:['cobalt-strike','c2']},
  {id:'p31', name:'Cobalt Strike beacons (Shodan fingerprint)', description:'Shodan parses beacon configs from team servers it can stage. Add an org or country to scope.', query:'product:"Cobalt Strike Beacon"', category:'threat-hunt', engines:['shodan'], tags:['cobalt-strike','c2']},
  {id:'p32', name:'GoPhish admin panels', description:'Exposed GoPhish consoles — phishing campaigns run from here; the landing-page server is usually the same host.', query:'http.title:"Gophish - Login"', category:'threat-hunt', engines:['shodan'], tags:['gophish','phishing']},
  {id:'p33', name:'Open directories with tools and payloads', description:'Exposed directory listings holding tools — attackers stage on cheap VPS with python -m http.server.', query:'http.title:"Directory listing for /" http.html:".exe"', category:'threat-hunt', engines:['shodan'], tags:['opendir','staging']},
  {id:'p34', name:'Python SimpleHTTP staging servers on odd ports', description:'SimpleHTTP servers outside 80/443/8000 — staging for loaders and exfil.', query:'"SimpleHTTP" -port:80 -port:443 -port:8000', category:'threat-hunt', engines:['shodan'], tags:['staging','python']},
  {id:'p35', name:'Exposed C2 frameworks by title', description:'Panels of common open-source C2s by page title. Confirm by certificate and port before calling it a C2.', query:'http.title:"Covenant" OR http.title:"Mythic" OR http.title:"PoshC2"', category:'threat-hunt', engines:['shodan'], tags:['c2','panel']},
  {id:'p36', name:'Malware samples and reports naming an indicator', description:'Sandbox and vendor write-ups mentioning the indicator.', query:'"{{INDICATOR}}" (site:any.run OR site:hybrid-analysis.com OR site:joesandbox.com OR site:tria.ge OR site:virustotal.com)', category:'threat-hunt', engines:['google'], tags:['sandbox','reports']},
  {id:'p37', name:'Vendor reporting naming an indicator or actor', description:'Threat-intel blogs and reports that mention it — read the context, do not just copy the attribution.', query:'"{{INDICATOR}}" (ioc OR indicators OR "threat actor" OR campaign) -site:virustotal.com', category:'threat-hunt', engines:['google','bing'], tags:['reports','ioc']},
  {id:'p38', name:'Indicator in GitHub IOC lists', description:'Public IOC repositories and detection content mentioning the indicator.', query:'"{{INDICATOR}}"', category:'threat-hunt', engines:['github','grepapp'], tags:['ioc','github']},

  /* ---- cloud exposure ---- */
  {id:'p40', name:'Open S3 buckets named after the organisation', description:'Indexed S3 listings mentioning the company. Check the bucket name, then the listing — do not download personal data.', query:'site:s3.amazonaws.com "{{ORG_NAME}}"', category:'cloud', engines:['google','bing'], tags:['s3','aws','bucket']},
  {id:'p41', name:'Open Azure blob containers for the organisation', description:'Indexed Azure Blob listings mentioning the company.', query:'site:blob.core.windows.net "{{ORG_NAME}}"', category:'cloud', engines:['google','bing'], tags:['azure','blob']},
  {id:'p42', name:'Open Google Cloud Storage for the organisation', description:'Indexed GCS objects mentioning the company.', query:'site:storage.googleapis.com "{{ORG_NAME}}"', category:'cloud', engines:['google','bing'], tags:['gcs','gcp']},
  {id:'p43', name:'Public Firebase databases', description:'Firebase realtime databases indexed with the company name — open ones answer /.json without auth.', query:'site:firebaseio.com "{{ORG_NAME}}"', category:'cloud', engines:['google'], tags:['firebase','database']},
  {id:'p44', name:'SharePoint and OneDrive links shared publicly', description:'Anonymous sharing links to the company tenant that search engines picked up.', query:'site:sharepoint.com "{{ORG_NAME}}" (confidential OR internal OR password)', category:'cloud', engines:['google','bing'], tags:['sharepoint','m365','sharing']},
  {id:'p45', name:'Google Docs, Sheets and Slides shared by link', description:'Workspace files shared "anyone with the link" that got indexed.', query:'site:docs.google.com "{{COMPANY_DOMAIN}}"', category:'cloud', engines:['google','bing'], tags:['google-docs','sharing']},
  {id:'p46', name:'Public Notion, Trello and Atlassian pages', description:'Public workspaces and boards — internal runbooks, credentials and org charts leak here.', query:'(site:notion.site OR site:trello.com OR site:atlassian.net) "{{COMPANY_DOMAIN}}"', category:'cloud', engines:['google','bing'], tags:['notion','trello','confluence']},
  {id:'p47', name:'Kubernetes API and dashboards exposed', description:'Kubernetes API servers and dashboards reachable from the internet for an organisation.', query:'(product:"Kubernetes" OR http.title:"Kubernetes Dashboard") org:"{{ORG_NAME}}"', category:'cloud', engines:['shodan'], tags:['kubernetes','exposure']},
  {id:'p48', name:'Docker API without authentication', description:'Docker Engine API on 2375 — full control of the host; cryptojackers sweep for these.', query:'port:2375 product:"Docker"', category:'cloud', engines:['shodan'], tags:['docker','exposure','cryptojacking']},
  {id:'p49', name:'Exposed Elasticsearch, Kibana and OpenSearch of an organisation', description:'Search clusters of the organisation — frequent source of breached data.', query:'(product:"Elastic" OR http.title:"Kibana") org:"{{ORG_NAME}}"', category:'cloud', engines:['shodan'], tags:['elastic','database']},
  {id:'p50', name:'Cloud keys for a domain in public code', description:'Access keys committed next to the company domain.', query:'"{{COMPANY_DOMAIN}}" (AKIA OR "aws_secret_access_key" OR "client_secret" OR "AccountKey=")', category:'cloud', engines:['github'], tags:['secrets','aws','azure']},
  {id:'p51', name:'Terraform state files in public code', description:'Terraform state holds resource IDs and often plaintext secrets.', query:'path:*.tfstate "{{COMPANY_DOMAIN}}"', category:'cloud', engines:['github'], tags:['terraform','state','secrets']},
  {id:'p52', name:'Azure tenant mentions in public code', description:'Code and config naming the tenant — client IDs, redirect URIs, connection strings.', query:'"{{TENANT}}.onmicrosoft.com"', category:'cloud', engines:['github','grepapp'], tags:['azure','entra','tenant']},

  /* ---- leaks ---- */
  {id:'p55', name:'Company domain in paste sites', description:'Pastes naming the domain — combo lists, configs, dumps and stealer-log excerpts.', query:'"{{DOMAIN_NAME}}" (site:pastebin.com OR site:rentry.co OR site:paste.ee OR site:ghostbin.site OR site:justpaste.it)', category:'data leaks', engines:['google','bing'], tags:['paste','leak']},
  {id:'p56', name:'.env files with the company domain', description:'Environment files committed to public repos.', query:'path:.env "{{COMPANY_DOMAIN}}"', category:'data leaks', engines:['github'], tags:['env','secrets']},
  {id:'p57', name:'Private keys next to a company host', description:'Private key blocks in code that also names the company.', query:'"BEGIN OPENSSH PRIVATE KEY" "{{COMPANY_DOMAIN}}"', category:'data leaks', engines:['github'], tags:['ssh','private-key']},
  {id:'p58', name:'Company email in public code', description:'Commits and config with staff addresses — reveals developers, personal repos and side projects.', query:'"@{{EMAIL_DOMAIN}}"', category:'data leaks', engines:['github','grepapp'], tags:['email','developers']},
  {id:'p59', name:'Internal hostnames in public code', description:'Internal hostnames (corp, intra, local) under the company domain — maps the internal network.', query:'"{{COMPANY_DOMAIN}}" (".corp." OR ".internal." OR ".intra." OR "vpn.")', category:'data leaks', engines:['github','grepapp'], tags:['internal','hostnames']},
  {id:'p60', name:'Domain in Intelligence X (leaks, pastes, dark web)', description:'Intelligence X archive: leaks, pastes, onion pages and stealer logs mentioning the domain.', query:'{{DOMAIN_NAME}}', category:'data leaks', engines:['intelx'], tags:['intelx','leak','darkweb']},

  /* ---- Telegram, Discord and chat ---- */
  {id:'p65', name:'Telegram channels and groups mentioning a name', description:'Public t.me pages that mention the handle or phrase. t.me/s/ pages are the readable web preview of public channels.', query:'site:t.me "{{STRING}}"', category:'messaging', engines:['google','bing','duckduckgo'], tags:['telegram','channels']},
  {id:'p66', name:'Telegram channel directories (TGStat, Telemetr)', description:'Channel catalogues with subscriber history, mentions and similar channels.', query:'"{{STRING}}" (site:tgstat.com OR site:telemetr.io OR site:tlgrm.eu)', category:'messaging', engines:['google'], tags:['telegram','directory']},
  {id:'p67', name:'Where a Telegram handle is advertised', description:'Web pages linking to the handle — shop fronts, forum signatures, scam reviews.', query:'"t.me/{{USERNAME}}" -site:t.me', category:'messaging', engines:['google','bing'], tags:['telegram','handle']},
  {id:'p68', name:'Discord invites posted with a phrase', description:'Public invite links next to a topic or a server name — scam, carding and leak servers advertise this way.', query:'("discord.gg/" OR "discord.com/invite/") "{{STRING}}"', category:'messaging', engines:['google','bing'], tags:['discord','invite']},
  {id:'p69', name:'Discord server directories', description:'Server listings (Disboard, top.gg, discords.com) with tags, member counts and descriptions.', query:'"{{STRING}}" (site:disboard.org OR site:top.gg OR site:discords.com OR site:discadia.com)', category:'messaging', engines:['google'], tags:['discord','directory']},
  {id:'p70', name:'Telegram bot tokens in public code', description:'Bot tokens committed to GitHub — tied to stealers, phishing kits and scam bots. A token in a kit leads to the operator chat.', query:'"api.telegram.org/bot" "{{STRING}}"', category:'messaging', engines:['github','grepapp'], tags:['telegram','bot-token','kit']},
  {id:'p71', name:'Discord webhooks in public code', description:'Webhook URLs in public code — stealer builders and grabbers ship them.', query:'"discord.com/api/webhooks/" "{{STRING}}"', category:'messaging', engines:['github','grepapp'], tags:['discord','webhook','stealer']},
  {id:'p72', name:'WhatsApp group invites with a phrase', description:'Public chat.whatsapp.com invites next to a topic — investment and job-scam groups recruit this way.', query:'"chat.whatsapp.com" "{{STRING}}"', category:'messaging', engines:['google','bing'], tags:['whatsapp','invite','scam']},

  /* ---- people and handles ---- */
  {id:'p75', name:'Handle across developer and hacker communities', description:'The handle on GitHub, GitLab, Keybase, HackerOne, Reddit and Medium — developers reuse handles more than anyone.', query:'"{{USERNAME}}" (site:github.com OR site:gitlab.com OR site:keybase.io OR site:hackerone.com OR site:reddit.com OR site:medium.com)', category:'people', engines:['google','bing'], tags:['username','developer']},
  {id:'p76', name:'Handle on archived pages', description:'Wayback snapshots that mention the handle — deleted profiles and old bios.', query:'site:web.archive.org "{{USERNAME}}"', category:'people', engines:['google'], tags:['username','archive']},
  {id:'p77', name:'Handle with crime-forum vocabulary', description:'Reporting and mirrors that put the handle next to forum, escrow, vouch or ransomware terms. Leads only — handles collide.', query:'"{{USERNAME}}" (forum OR escrow OR vouch OR "initial access" OR ransomware OR stealer)', category:'people', engines:['google','bing'], tags:['username','threat-actor']},
  {id:'p78', name:'Email address outside its own domain', description:'Pages that mention the address anywhere but its own domain — sign-ups, WHOIS mirrors, CVs, leaks.', query:'"{{EMAIL}}" -site:{{EMAIL_DOMAIN}}', category:'people', engines:['google','bing','duckduckgo'], tags:['email']},
  {id:'p79', name:'Person on Yandex (strong for Russian-language web)', description:'Yandex indexes VK, OK.ru and Russian forums far better than Google.', query:'"{{FULL_NAME}}"', category:'people', engines:['yandex'], tags:['yandex','russian','vk']},
  {id:'p80', name:'PGP key on keyservers and pages', description:'The key fingerprint on keyservers and pages — markets and forum profiles post the key in full.', query:'"{{PGP_FP}}"', category:'people', engines:['google','bing','github'], tags:['pgp','darkweb']},

  /* ---- crypto ---- */
  {id:'p85', name:'Wallet on abuse and scam reports', description:'Reports filed against the address on Chainabuse, ScamSniffer and forums.', query:'"{{WALLET}}" (site:chainabuse.com OR site:scamsniffer.io OR site:bitcointalk.org OR site:reddit.com)', category:'crypto', engines:['google','bing'], tags:['wallet','scam','reports']},
  {id:'p86', name:'Wallet anywhere on the web', description:'Every page that prints the address — donation pages, scam sites, ransom notes, GitHub.', query:'"{{WALLET}}"', category:'crypto', engines:['google','bing','github','publicwww'], tags:['wallet','pivot']},
  {id:'p87', name:'Wallet on web pages (source code)', description:'Pages whose HTML contains the address — finds the scam sites that use the same payment wallet.', query:'body="{{WALLET}}"', category:'crypto', engines:['fofa'], tags:['wallet','scam-site']},

  /* ---- dark web ---- */
  {id:'p90', name:'Onion address mentioned on the clear web', description:'Clear-web pages that mention the onion — directories, reporting, mirrors, the operator’s other sites.', query:'"{{ONION}}"', category:'dark-web', engines:['google','bing','intelx'], tags:['onion','tor']},
  {id:'p91', name:'Ransomware leak-site victims for a company', description:'Leak-site trackers (ransomware.live, RansomLook) listing the company.', query:'"{{ORG_NAME}}" (site:ransomware.live OR site:ransomlook.io)', category:'dark-web', engines:['google'], tags:['ransomware','leak-site']},
];
