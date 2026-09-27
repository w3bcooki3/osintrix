/* ==========================================================================
   Domain model: vault entry types, vault categories, tool categories,
   and the synthetic demo vault content.
   Entry types and categories come from OSINTrix's Multi-vault and TraceLink
   (script.js vaultTabStructure / entryTypeFields, tracelink.js node types),
   merged into one list so the vault, the graph and the extractor agree.
   ========================================================================== */
const GROUPS = [
  ['identity','Identity & social','users','--t-identity'],
  ['comms','Communication','message-square','--t-contact'],
  ['finance','Financial','bitcoin','--t-finance'],
  ['tech','Technical','server','--t-infra'],
  ['files','Media & files','file-text','--t-file'],
  ['intel','Intelligence','shield-alert','--t-threat'],
  ['places','Places','map-pin','--t-place'],
];
/* [type, label, icon, group, colourVar, extractorKind, fields]  — field: [name, label, input, options] ; first field is the primary value */
const TYPE_LIST = [
  ['person','Person','user','identity','--t-identity',null,[['name','Full name','text'],['role','Role in case','select',['Subject','Victim','Witness','Associate','Unknown']],['dob','Date of birth','date'],['nationality','Nationality','text']]],
  ['organization','Organisation','building-2','identity','--t-org',null,[['name','Organisation name','text'],['industry','Industry','text'],['website','Website','url'],['country','Country','text']]],
  ['alias','Alias','fingerprint','identity','--t-identity',null,[['alias','Alias','text'],['of','Alias of','text'],['firstSeen','First seen','date']]],
  ['username','Username / handle','at-sign','identity','--t-identity','handle',[['username','Handle','text'],['platform','Platform','text'],['availability','Status','select',['Active','Taken','Suspended','Unknown']]]],
  ['social','Social profile','users','identity','--t-identity',null,[['username','Username','text'],['platform','Platform','select',['Facebook','X / Twitter','Instagram','LinkedIn','TikTok','YouTube','Telegram','Other']],['url','Profile URL','url'],['followers','Followers','number']]],
  ['email','Email address','mail','identity','--t-contact','email',[['email','Email address','email'],['provider','Provider','text'],['verified','Verified','select',['Unverified','Verified','Bounced']]]],
  ['phone','Phone number','phone','identity','--t-contact',null,[['number','Phone number','tel'],['country','Country code','text'],['carrier','Carrier','text'],['type','Line type','select',['Mobile','Landline','VoIP','Unknown']]]],
  ['forum','Forum / market','message-square','comms','--t-contact',null,[['name','Site','text'],['url','URL','url'],['section','Section / thread','text']]],
  ['messaging','Messaging channel','message-square','comms','--t-contact',null,[['handle','Channel or handle','text'],['app','App','select',['Telegram','Signal','WhatsApp','Discord','Jabber','Other']],['members','Members','number']]],
  ['link','Web link','link','comms','--t-contact',null,[['url','URL','url'],['platform','Platform','text'],['status','Status','select',['Active','Inactive','Suspended','Unknown']]]],
  ['crypto','Crypto wallet','bitcoin','finance','--t-finance','btc',[['address','Wallet address','text'],['currency','Currency','select',['Bitcoin','Ethereum','Monero','Litecoin','Other']],['amount','Balance / volume','text'],['txid','Notable transaction','text']]],
  ['transaction','Transaction','activity','finance','--t-finance',null,[['txid','Transaction ID','text'],['amount','Amount','text'],['currency','Currency','text'],['date','Date','date']]],
  ['breach','Data breach','key-round','finance','--t-finance',null,[['name','Breach name','text'],['date','Date','date'],['records','Records exposed','text']]],
  ['domain','Domain','globe','tech','--t-infra','domain',[['domain','Domain','text'],['registrar','Registrar','text'],['created','Created','date'],['nameservers','Name servers','text']]],
  ['ip','IP address','server','tech','--t-infra','ipv4',[['ip','IP address','text'],['asn','ASN','text'],['country','Country','text'],['ports','Open ports','text']]],
  ['url','URL','link-2','tech','--t-infra','url',[['url','URL','text'],['status','Status','select',['Live','Down','Unknown']]]],
  ['document','Document','file-text','files','--t-file',null,[['title','Title','text'],['type','Type','select',['PDF','DOC','XLS','TXT','Other']],['url','Source URL','url'],['hash','SHA-256','text']]],
  ['media','Image / video','image','files','--t-file',null,[['title','Title','text'],['type','Media type','select',['Image','Video','Audio']],['url','Source URL','url'],['resolution','Resolution','text']]],
  ['file','File / hash','hash','files','--t-file','sha256',[['hash','SHA-256','text'],['filename','File name','text'],['size','Size','text'],['type','Type','text']]],
  ['threat','Threat / campaign','shield-alert','intel','--t-threat',null,[['name','Name','text'],['kind','Kind','select',['Malware family','Campaign','Actor','Technique']],['severity','Severity','select',['Low','Medium','High','Critical']],['confidence','Confidence','select',['Low','Medium','High']]]],
  ['vulnerability','Vulnerability','bug','intel','--t-threat','cve',[['cve','CVE','text'],['product','Product','text'],['cvss','CVSS','text']]],
  ['location','Location','map-pin','places','--t-place',null,[['address','Address','text'],['city','City','text'],['country','Country','text'],['coordinates','Coordinates','text']]],
];
const TYPES = Object.fromEntries(TYPE_LIST.map(([id, label, icon, group, color, kind, fields]) => [id, {id, label, icon, group, color, kind, fields}]));
const KIND_TO_TYPE = {ipv4:'ip', domain:'domain', url:'url', email:'email', handle:'username', btc:'crypto', eth:'crypto', sha256:'file', md5:'file', sha1:'file', cve:'vulnerability', hostport:'ip'};
const MONO_TYPES = new Set(['email','domain','ip','url','crypto','file','username','phone','transaction','vulnerability','link']);

const CASE_COLORS = ['#5470f5','#8b5cf6','#0ea5a4','#e8590c','#d6336c','#2f9e44','#e0a800','#64748b'];
const CASE_ICONS = ['briefcase','shield-alert','crosshair','radar','bug','users','bitcoin','globe','skull','microscope'];

const TOOL_CATS = {
  general:{name:'General', icon:'layout-dashboard', children:{'all-tools':'All tools'}},
  osint:{name:'OSINT & investigation', icon:'scan-search', children:{'search-engines':'Search engines','social-media':'Social media','people-search':'People search','email-investigation':'Email','phone-investigation':'Phone','username-investigation':'Username','domain-investigation':'Domain','image-investigation':'Image','geolocation':'Geolocation','dark-web':'Dark web','breach-data':'Breach data','public-records':'Public records'}},
  'digital-forensics':{name:'Digital forensics', icon:'microscope', children:{'disk-analysis':'Disk','memory-analysis':'Memory','mobile-forensics':'Mobile','network-forensics':'Network','timeline-analysis':'Timeline','artifact-analysis':'Artifacts','file-recovery':'File recovery','metadata-analysis':'Metadata','registry-analysis':'Registry','log-analysis':'Logs'}},
  'malware-analysis':{name:'Malware analysis', icon:'bug', children:{'file-analysis':'File analysis','dynamic-analysis':'Dynamic','static-analysis':'Static','sandboxes':'Sandboxes','reverse-engineering':'Reverse engineering','hash-lookup':'Hash lookup','yara-rules':'YARA','decompilers':'Decompilers','debuggers':'Debuggers','hex-editors':'Hex editors'}},
  'network-security':{name:'Network security', icon:'network', children:{'packet-analysis':'Packets','network-scanning':'Scanning','vulnerability-scanning':'Vuln scanning','port-scanning':'Ports','ssl-analysis':'SSL','dns-analysis':'DNS','ip-analysis':'IP analysis','url-analysis':'URL analysis','traffic-analysis':'Traffic','intrusion-detection':'Intrusion detection'}},
  'threat-intelligence':{name:'Threat intelligence', icon:'shield-alert', children:{'ioc-analysis':'IOC analysis','threat-feeds':'Feeds','threat-hunting':'Hunting','attribution':'Attribution','threat-sharing':'Sharing','vulnerability-research':'Vuln research','exploit-databases':'Exploit DBs','threat-reports':'Reports','apt-tracking':'APT tracking','campaign-tracking':'Campaigns'}},
  'incident-response':{name:'Incident response', icon:'triangle-alert', children:{'case-management':'Case management','evidence-collection':'Evidence collection','containment':'Containment','eradication':'Eradication','recovery':'Recovery','communication':'Communication','documentation':'Documentation','lessons-learned':'Lessons learned','playbooks':'Playbooks','automation':'Automation'}},
  'ai-automation':{name:'AI & automation', icon:'sparkles', children:{'llm-tools':'LLM tools','analysis-ai':'AI analysis','automation':'Automation'}},
  compliance:{name:'Compliance & legal', icon:'lock', children:{'vulnerability-assessment':'Vuln assessment','compliance-scanning':'Compliance scanning','audit-tools':'Audit','policy-management':'Policy','risk-assessment':'Risk','legal-tools':'Legal','evidence-preservation':'Evidence preservation','chain-of-custody':'Chain of custody','reporting':'Reporting','certification':'Certification'}},
};

/* Demo vault entries — synthetic. [id, case, type, fields, extras] */
const DEMO_ENTRIES = [
  ['v-victim','c-lantern','person',{name:'Jordan Okafor',role:'Victim',nationality:'—'},{priority:'medium',tags:['finance-team'],notes:'Opened the invoice LNK on WS-FIN-07.',src:'r-lnk'}],
  ['v-actor','c-lantern','person',{name:'Operator behind @n1ghtlamp',role:'Subject'},{priority:'critical',starred:true,tags:['actor'],notes:'Not yet identified. Every link below is an analyst claim with its evidence.',src:'r-forum'}],
  ['v-handle','c-lantern','username',{username:'@n1ghtlamp',platform:'forum.example',availability:'Active'},{priority:'high',starred:true,tags:['actor'],src:'r-forum',verdict:'suspicious'}],
  ['v-alias','c-lantern','alias',{alias:'lampmaker',of:'@n1ghtlamp',firstSeen:'2025-11-02'},{priority:'medium',tags:['actor'],src:'r-forum'}],
  ['v-mail','c-lantern','email',{email:'n1ghtlamp@mail.example',provider:'mail.example',verified:'Unverified'},{priority:'high',tags:['actor'],src:'r-whois',verdict:'suspicious'}],
  ['v-sender','c-lantern','email',{email:'billing@lantern-invoice.example',provider:'lantern-invoice.example',verified:'Unverified'},{priority:'high',tags:['phishing'],src:'r-mail',verdict:'malicious'}],
  ['v-forum','c-lantern','forum',{name:'forum.example',url:'https://forum.example/t/lamp-loader',section:'Loaders & crypters'},{priority:'medium',tags:['underground'],src:'r-forum'}],
  ['v-dom1','c-lantern','domain',{domain:'lantern-invoice.example',registrar:'Example Registrar Inc.',created:'2026-09-01'},{priority:'high',tags:['phishing'],src:'r-whois',verdict:'malicious'}],
  ['v-dom2','c-lantern','domain',{domain:'update-lamp.test',registrar:'—',nameservers:'ns1.update-lamp.test'},{priority:'critical',tags:['c2'],src:'r-dns',verdict:'malicious'}],
  ['v-ip1','c-lantern','ip',{ip:'203.0.113.47',asn:'AS64500 (documentation)',country:'—',ports:'4444/tcp'},{priority:'critical',starred:true,tags:['c2'],src:'r-c2a',verdict:'malicious'}],
  ['v-ip2','c-lantern','ip',{ip:'198.51.100.23',asn:'AS64501 (documentation)',ports:'80/tcp'},{priority:'high',tags:['staging'],src:'r-dns',verdict:'suspicious'}],
  ['v-url','c-lantern','url',{url:'http://update-lamp.test/s.ps1',status:'Down'},{priority:'high',tags:['payload'],src:'r-ps',verdict:'malicious'}],
  ['v-btc','c-lantern','crypto',{address:'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh',currency:'Bitcoin',amount:'0.42 BTC in',txid:'—'},{priority:'high',starred:true,tags:['finance'],src:'r-wallet'}],
  ['v-hash','c-lantern','file',{hash:'9f2c1d0b7e4a6c8f3b5d2e1a0c9b8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a',filename:'svchost.exe',size:'184 KB',type:'PE32'},{priority:'critical',tags:['payload'],src:'r-drop',verdict:'malicious'}],
  ['v-lnk','c-lantern','document',{title:'Invoice_4471.pdf.lnk',type:'Other'},{priority:'high',tags:['initial-access'],src:'r-mail'}],
  ['v-fam','c-lantern','threat',{name:'Lamp loader',kind:'Malware family',severity:'High',confidence:'Medium'},{priority:'high',tags:['malware'],src:'r-forum'}],
  ['v-reg','c-lantern','organization',{name:'Example Registrar Inc.',industry:'Domain registrar',country:'—'},{priority:'low',tags:['infrastructure'],src:'r-whois'}],
  ['v-loc','c-lantern','location',{address:'12 Sample Street',city:'Example City',country:'Exampleland'},{priority:'low',tags:['whois'],notes:'WHOIS registrant address. Almost certainly false.',src:'r-whois'}],
  ['lab-img','c-lab','media',{title:'harbour.jpg',type:'Image',resolution:'4032×3024'},{priority:'high',starred:true,tags:['ctf'],src:'lab2'}],
  ['lab-hash','c-lab','file',{hash:'4be1c0d9a8f7e6d5c4b3a2918070605040302010f0e0d0c0b0a09080706050',filename:'harbour.jpg',size:'172 KB',type:'JPEG'},{priority:'medium',tags:['ctf'],src:'lab2'}],
  ['lab-loc','c-lab','location',{address:'Harbour front',city:'Oslo',country:'Norway',coordinates:'59.910556, 10.740278'},{priority:'high',tags:['geolocation'],src:'lab5'}],
  ['lab-user','c-lab','username',{username:'@k3lpie_sails',platform:'photos.example',availability:'Active'},{priority:'high',tags:['uploader'],src:'lab4'}],
  ['lab-mail','c-lab','email',{email:'k3lpie@mail.example',provider:'mail.example',verified:'Unverified'},{priority:'medium',tags:['uploader'],src:'lab4'}],
  ['p-ip','c-portal','ip',{ip:'203.0.113.47',asn:'AS64500 (documentation)'},{priority:'critical',tags:['attacker'],src:'p1',verdict:'malicious'}],
  ['p-ip2','c-portal','ip',{ip:'192.0.2.66',asn:'AS64502 (documentation)'},{priority:'high',tags:['attacker'],src:'p4',verdict:'suspicious'}],
  ['p-acct','c-portal','email',{email:'m.silva@corp.example',provider:'corp.example',verified:'Verified'},{priority:'high',tags:['victim'],src:'p3'}],
];
/* analyst-asserted links between vault entries [from, to, label, confidence 1-3, evidence record] */
const DEMO_LINKS = [
  ['v-sender','v-lnk','sent',3,'r-mail'],['v-lnk','v-victim','opened by',3,'r-lnk'],['v-lnk','v-url','fetches',3,'r-ps'],
  ['v-url','v-dom2','hosted on',3,'r-ps'],['v-dom2','v-ip2','resolves to',3,'r-dns'],['v-url','v-hash','drops',2,'r-drop'],
  ['v-hash','v-ip1','beacons to',3,'r-find1'],['v-hash','v-fam','instance of',2,'r-forum'],['v-sender','v-dom1','sent from',3,'r-mail'],
  ['v-dom1','v-mail','registrant',2,'r-whois'],['v-dom1','v-reg','registered via',3,'r-whois'],['v-dom1','v-loc','registrant address',1,'r-whois'],
  ['v-handle','v-mail','uses email',3,'r-forum'],['v-handle','v-btc','advertises wallet',2,'r-wallet'],['v-handle','v-forum','posts on',3,'r-forum'],
  ['v-handle','v-fam','sells',2,'r-forum'],['v-alias','v-handle','alias of',2,'r-forum'],['v-actor','v-handle','operates',1,'r-forum'],
  ['p-ip','p-acct','logged in as',3,'p3'],
  ['lab-img','lab-loc','taken at',3,'lab5'],['lab-user','lab-img','uploaded',3,'lab4'],['lab-user','lab-mail','profile links to',2,'lab4'],['lab-hash','lab-img','hash of',3,'lab2'],
];
const DEMO_CASE_STYLE = {'c-lantern':['#5470f5','crosshair'],'c-portal':['#e8590c','users'],'c-lab':['#0ea5a4','flag']};
/* Curated demo layout: delivery chain left, infrastructure centre, actor cluster right */
const DEMO_POS = {'v-sender':[0,0],'v-lnk':[0,170],'v-victim':[-190,170],'v-url':[0,340],'v-dom2':[-190,470],'v-ip2':[-380,470],'v-hash':[190,470],'v-ip1':[190,640],
  'v-fam':[380,340],'v-dom1':[220,0],'v-reg':[220,-170],'v-loc':[420,-130],'v-mail':[440,90],'v-handle':[620,220],'v-alias':[800,100],'v-btc':[800,340],'v-forum':[620,420],'v-actor':[820,220],
  'p-ip':[0,0],'p-acct':[240,0],'p-ip2':[0,170],
  'lab-img':[0,0],'lab-loc':[230,-90],'lab-hash':[-230,-90],'lab-user':[0,190],'lab-mail':[230,190]};
