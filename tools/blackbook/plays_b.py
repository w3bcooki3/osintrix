# Plays, part B: persistence, defence evasion, credential access.

PLAYS_B = [
# ------------------------------------------------------------------ persistence
dict(id='pe-run', sec='persist', t='Run keys, Startup folder and Winlogon', att=['T1547.001', 'T1547.004'], sev='medium',
  lens="The oldest persistence still works because it is everywhere: a value under HKCU\\...\\Run pointing at a binary in AppData, a shortcut in the Startup folder, or a change to Winlogon's Shell or Userinit. "
       "Commodity malware and infostealers use it daily; better operators hide the payload under a name like OneDriveUpdate or a GUID.",
  sig=["A Run or RunOnce value whose data points into AppData, Temp, ProgramData, Users\\Public or a path with random characters",
       "Run values that start a script host (wscript, mshta, powershell) or rundll32 with an unusual DLL",
       "Winlogon Shell other than explorer.exe, or Userinit with anything after userinit.exe,"],
  logs="Registry value set (Sysmon 13 / EDR registry events); Autoruns snapshots over time.",
  q=dict(
    sigma=r"""title: Run key or Winlogon value points at a user-writable path or a script host
status: stable
logsource:
  category: registry_set
  product: windows
detection:
  selection_key:
    TargetObject|contains:
      - '\Software\Microsoft\Windows\CurrentVersion\Run'
      - '\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell'
      - '\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit'
  selection_data:
    Details|contains:
      - '\AppData\'
      - '\Temp\'
      - '\Users\Public\'
      - '\ProgramData\'
      - 'wscript'
      - 'mshta'
      - 'powershell'
      - 'rundll32'
  filter_known:
    Details|contains:
      - '\AppData\Local\Microsoft\OneDrive\'
      - '\AppData\Local\Microsoft\Teams\'
  condition: selection_key and selection_data and not filter_known
falsepositives:
  - Per-user installs of chat and sync clients (add them to the filter by full path)
level: medium
tags:
  - attack.persistence
  - attack.t1547.001""",
    kql=r"""DeviceRegistryEvents
| where Timestamp > ago(30d) and ActionType == "RegistryValueSet"
| where RegistryKey has_any (@"\CurrentVersion\Run", @"\Winlogon")
| where RegistryValueData has_any (@"\AppData\", @"\Temp\", @"\Users\Public\", @"\ProgramData\", "wscript", "mshta", "powershell", "rundll32")
| summarize devices = dcount(DeviceId), sample = any(DeviceName) by RegistryValueName, RegistryValueData
| order by devices asc   // one or two machines out of thousands: read those""",
    osq=r"""-- every autorun on a host, with the binary's signature state
SELECT s.name, s.path, s.source, s.username, a.result AS signed
FROM startup_items s LEFT JOIN authenticode a ON a.path = s.path
WHERE s.path LIKE '%AppData%' OR s.path LIKE '%Temp%' OR s.path LIKE '%Public%' OR a.result != 'trusted';"""),
  ev=['EventID=13 TargetObject="HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDriveUpdater" Details="C:\\Users\\j.okafor\\AppData\\Roaming\\odu\\odu.exe"', 'EventID=13 TargetObject="HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDrive" Details="C:\\Users\\j.okafor\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe /background"'],
  fp="Per-user installers: Teams, OneDrive, Zoom, Spotify, Discord. Filter by exact path, not by name.",
  fix=["Stack Run-key values across the estate weekly and read the rarest",
       "Application control that blocks execution from AppData and Temp for standard users",
       "Sysinternals Autoruns with -vt and signature checks during triage (autorunsc -a * -c -h -s -m)"]),

dict(id='pe-task', sec='persist', t='Scheduled tasks, including hidden ones', att=['T1053.005'], sev='high',
  lens="schtasks /create /sc onlogon /ru SYSTEM is the persistence of choice for operators and ransomware crews alike, and a task can also run remotely across the network. "
       "The HAFNIUM 'Tarrask' tooling went further: it deleted the task's security descriptor (the SD value under TaskCache\\Tree) so the task disappears from schtasks /query and Task Scheduler while still running.",
  sig=["schtasks /create with /ru SYSTEM, an action in AppData, Temp or Users\\Public, or an encoded PowerShell command",
       "Event 4698 (task created) with a <Command> pointing to a script host or user-writable path",
       "Deletion of the SD value under HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\<name>",
       "Tasks created remotely: 4698 on a host shortly after a type 3 logon from another workstation"],
  logs="Security 4698/4702 (Advanced Audit: Other Object Access Events), TaskScheduler Operational 106/200, process creation, registry events.",
  q=dict(
    sigma=r"""title: Scheduled task created to run from a user-writable path or as SYSTEM with a script host
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    Image|endswith: '\schtasks.exe'
    CommandLine|contains: '/create'
  selection_bad:
    CommandLine|contains:
      - '\AppData\'
      - '\Temp\'
      - '\Users\Public\'
      - 'powershell'
      - 'mshta'
      - 'wscript'
      - 'rundll32'
      - 'cmd /c'
      - 'cmd.exe /c'
  condition: selection_img and selection_bad
falsepositives:
  - Software updaters registering tasks from ProgramData (baseline by task name)
level: high
tags:
  - attack.persistence
  - attack.t1053.005""",
    kql=r"""// Hidden-task technique: the SD value of a task removed from the registry
DeviceRegistryEvents
| where Timestamp > ago(90d)
| where RegistryKey has @"\Schedule\TaskCache\Tree" and ActionType == "RegistryValueDeleted" and RegistryValueName == "SD"
| project Timestamp, DeviceName, RegistryKey, InitiatingProcessFileName, InitiatingProcessCommandLine""",
    spl=r"""index=wineventlog EventCode=4698
| rex field=TaskContent "<Command>(?<cmd>[^<]+)</Command>(?:\s*<Arguments>(?<args>[^<]*)</Arguments>)?"
| search cmd IN ("*\\AppData\\*", "*\\Temp\\*", "*\\Users\\Public\\*", "*powershell*", "*mshta*", "*wscript*", "*rundll32*")
| table _time host SubjectUserName TaskName cmd args""",
    osq=r"""SELECT name, action, path, enabled, last_run_time, next_run_time
FROM scheduled_tasks
WHERE hidden = 1 OR action LIKE '%AppData%' OR action LIKE '%powershell%' OR action LIKE '%Users\Public%';"""),
  ev=['EventID=1 Image="C:\\Windows\\System32\\schtasks.exe" CommandLine="schtasks /create /sc onlogon /tn \\Microsoft\\Windows\\UpdateCheck /tr \'powershell -w hidden -f C:\\Users\\Public\\u.ps1\' /ru SYSTEM"', 'EventID=1 Image="C:\\Windows\\System32\\schtasks.exe" CommandLine="schtasks /query /fo LIST"'],
  fp="Updaters (Google, Adobe, Zoom) create tasks with stable names and signed binaries in Program Files.",
  fix=["Enable 4698/4702 auditing and forward the TaskScheduler Operational log",
       "Compare the TaskCache\\Tree registry keys with schtasks /query output on servers — a key without a visible task is hidden",
       "Restrict who can create tasks remotely; block RPC/SMB between workstations"]),

dict(id='pe-service', sec='persist', t='New services: PsExec, implants and malicious drivers', att=['T1543.003', 'T1569.002'], sev='high',
  lens="Installing a service gives SYSTEM and survives reboots; PsExec and its clones install one on the target to run each command. "
       "Event 7045 records every new service with its ImagePath — a service whose binary is cmd /c, powershell, a file in Temp or a random 8-character name is rarely innocent. "
       "Kernel drivers installed as services are how EDR-killers load (bring-your-own-vulnerable-driver).",
  sig=["7045 with ImagePath containing cmd /c, powershell, %COMSPEC%, \\Temp\\, \\ADMIN$\\ or \\Users\\Public\\",
       "Service names that are random (8 letters) or mimic Windows names with a typo",
       "PSEXESVC or renamed equivalents; a service whose binary was written over SMB seconds earlier (5145 on ADMIN$)",
       "A kernel-mode service (type 1) loading a driver on the LOLDrivers list"],
  logs="System log 7045 (Service Control Manager), Security 4697, Sysmon 6 (driver load).",
  q=dict(
    sigma=r"""title: Suspicious service installed
status: stable
logsource:
  product: windows
  service: system
detection:
  selection_id:
    EventID: 7045
  selection_path:
    ImagePath|contains:
      - 'cmd /c'
      - 'cmd.exe /c'
      - '%COMSPEC%'
      - 'powershell'
      - '\Temp\'
      - '\ADMIN$\'
      - '\Users\Public\'
      - 'mshta'
  condition: selection_id and selection_path
falsepositives:
  - Some installers temporarily register a service with cmd /c
level: high
tags:
  - attack.persistence
  - attack.t1543.003""",
    kql=r"""// Defender for Endpoint: service installs by rarity
DeviceEvents
| where Timestamp > ago(30d) and ActionType == "ServiceInstalled"
| extend svc = tostring(parse_json(AdditionalFields).ServiceName), path = tostring(parse_json(AdditionalFields).ServiceFileName)
| summarize devices = dcount(DeviceId), first = min(Timestamp), sample = any(DeviceName) by svc, path
| where devices <= 3
| order by first desc""",
    spl=r"""index=wineventlog source=System EventCode=7045
| eval suspicious=if(match(ImagePath, "(?i)cmd(\.exe)? /c|%comspec%|powershell|\\\\temp\\\\|\\\\admin\$|\\\\users\\\\public|mshta"), 1, 0)
| eval random_name=if(match(Service_Name, "^[A-Za-z]{8}$") AND NOT match(Service_Name, "(?i)service"), 1, 0)
| where suspicious=1 OR random_name=1
| table _time host Service_Name ImagePath Service_Account"""),
  ev=['EventID=7045 ServiceName="xQzRkLmP" ImagePath="%COMSPEC% /Q /c echo cd > \\\\127.0.0.1\\C$\\__output 2^>^&1 > %TEMP%\\execute.bat" ServiceType="user mode service"', 'EventID=7045 ServiceName="Google Update Service" ImagePath="\\"C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe\\" /svc"'],
  fp="Software installs; admin use of PsExec (should be from known admin hosts and accounts).",
  fix=["Turn on the Microsoft vulnerable driver blocklist and HVCI (memory integrity)",
       "Restrict service creation remotely: no admin rights for standard users, LAPS for local admin, tiered admin accounts",
       "Alert on every 7045 on domain controllers — new services there should be change-managed"]),

dict(id='pe-wmi', sec='persist', t='WMI event subscriptions', att=['T1546.003'], sev='high',
  lens="A WMI subscription pairs a filter (an event, such as 'system up for 5 minutes') with a consumer (run this command or script) and survives reboots with no file in any autorun location. "
       "APT29 and many others have used it; few defenders look at it.",
  sig=["Sysmon 19/20/21: a new filter, consumer or binding; a CommandLineEventConsumer or ActiveScriptEventConsumer that runs powershell, cmd or a script",
       "scrcons.exe (the script consumer host) running at all",
       "WmiPrvSE spawning a process at boot with no logged-on user"],
  logs="Sysmon 19, 20, 21; WMI-Activity/Operational 5861; Defender DeviceEvents.",
  q=dict(
    sigma=r"""title: WMI consumer that runs a command or script
status: stable
logsource:
  product: windows
  category: wmi_event
detection:
  selection:
    EventID: 20
    Destination|contains:
      - 'powershell'
      - 'cmd.exe'
      - 'mshta'
      - 'wscript'
      - 'rundll32'
      - 'http'
  condition: selection
falsepositives:
  - A few management agents register consumers (SCCM uses known names)
level: high
tags:
  - attack.persistence
  - attack.t1546.003""",
    kql=r"""DeviceEvents
| where Timestamp > ago(90d)
| where ActionType in ("WmiBindEventFilterToConsumer", "WmiCreateEventConsumer", "WmiCreateEventFilter") or (ActionType == "ProcessCreated" and FileName =~ "scrcons.exe")
| project Timestamp, DeviceName, ActionType, AdditionalFields, InitiatingProcessCommandLine""",
    osq=r"""SELECT c.name, c.command_line_template, f.query, b.filter, b.consumer
FROM wmi_cli_event_consumers c
LEFT JOIN wmi_filter_consumer_binding b ON b.consumer LIKE '%' || c.name || '%'
LEFT JOIN wmi_event_filters f ON b.filter LIKE '%' || f.name || '%';""",
    cli=r"""Get-CimInstance -Namespace root/subscription -ClassName __EventFilter
Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer
Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer
Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding"""),
  ev=['EventID=20 Operation="Created" Name="SysHealth" Type="Command Line" Destination="powershell.exe -nop -w hidden -enc SQBFAFgA"', 'EventID=19 Operation="Created" Name="SCM Event Log Filter" Query="SELECT * FROM MSFT_SCMEventLogEvent"'],
  fp="SCCM's own consumers ('SCM Event Log Consumer') and some hardware vendors' agents.",
  fix=["Collect Sysmon 19–21 everywhere; there is little legitimate volume",
       "Sweep root/subscription on every host quarterly (the osquery query above, or Velociraptor's Windows.Persistence.PermanentWMIEvents)"]),

dict(id='pe-webshell', sec='persist', t='Web shells on IIS, Exchange and Java servers', att=['T1505.003', 'T1190'], sev='critical',
  lens="After exploiting a web application — Exchange (ProxyLogon, ProxyShell), SharePoint, MOVEit, Confluence — the operator drops a small script into a web folder and returns through it at will. "
       "The web server process then does things a web server never does: run whoami, net, nltest, or start PowerShell.",
  sig=["w3wp.exe, httpd, nginx, tomcat or java starting cmd, powershell, whoami, net, nltest, certutil or sh/bash",
       "New .aspx, .ashx, .asmx, .jsp or .php files in web roots written by the web server process itself",
       "POST requests to a static-looking page that returns small, varying responses; one IP hitting a single obscure file repeatedly"],
  logs="Process creation on web servers, file creation in web roots, IIS/Apache logs with POST bodies length.",
  q=dict(
    sigma=r"""title: Web server process starts a shell or reconnaissance command
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection_parent:
    ParentImage|endswith:
      - '\w3wp.exe'
      - '\httpd.exe'
      - '\nginx.exe'
      - '\tomcat.exe'
      - '\php-cgi.exe'
      - '\UMWorkerProcess.exe'
  selection_child:
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\whoami.exe'
      - '\net.exe'
      - '\net1.exe'
      - '\nltest.exe'
      - '\certutil.exe'
      - '\ipconfig.exe'
      - '\systeminfo.exe'
  condition: selection_parent and selection_child
falsepositives:
  - Web applications that legitimately shell out (rare, and stable by command line)
level: critical
tags:
  - attack.persistence
  - attack.t1505.003""",
    kql=r"""DeviceFileEvents
| where Timestamp > ago(30d) and ActionType == "FileCreated"
| where FileName endswith_cs ".aspx" or FileName endswith ".ashx" or FileName endswith ".asmx" or FileName endswith ".jsp" or FileName endswith ".php"
| where InitiatingProcessFileName in~ ("w3wp.exe", "java.exe", "httpd.exe", "php-cgi.exe", "UMWorkerProcess.exe")
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName, SHA256""",
    spl=r"""index=iis cs_method=POST
| stats count dc(c_ip) as clients values(c_ip) as ips avg(sc_bytes) as avg_bytes by s_computername cs_uri_stem
| where clients <= 2 AND count > 20
| search cs_uri_stem IN ("*.aspx", "*.ashx", "*.asmx", "*.jsp", "*.php")
| sort - count"""),
  ev=['EventID=1 ParentImage="C:\\Windows\\System32\\inetsrv\\w3wp.exe" Image="C:\\Windows\\System32\\whoami.exe" CommandLine="whoami /all" User="IIS APPPOOL\\MSExchangeOWAAppPool"', 'EventID=1 ParentImage="C:\\Windows\\System32\\inetsrv\\w3wp.exe" Image="C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe"'],
  fp="w3wp starting csc.exe to compile ASP.NET pages is normal; that is why the rule names children, not 'anything'.",
  fix=["Patch internet-facing applications on the KEV timeline; Exchange on-premises behind a pre-auth proxy",
       "File-integrity monitoring on web roots; deploy through a pipeline so any file not in it is suspect",
       "After a web-app CVE: hunt for new script files in web roots back to the CVE's disclosure date, not just since patching"]),

# ------------------------------------------------------------------ defence evasion
dict(id='de-logs', sec='evade', t='Clearing logs and blinding telemetry', att=['T1685.005', 'T1685.001'], sev='high',
  lens="Before or after the noisy part, logs go: wevtutil cl Security, Clear-EventLog, auditpol /clear, stopping the EventLog service, unloading Sysmon's driver. "
       "Clearing the Security log itself writes event 1102 — the last thing a careless operator leaves. Careful ones disable channels or kill specific ETW providers instead.",
  sig=["Security 1102 or System 104 (log cleared); wevtutil with cl / clear-log",
       "auditpol /clear or /remove; changes to audit policy (4719)",
       "fltmc unload SysmonDrv; Sysmon service stopped; EventLog service stopped (7036/7040)",
       "A host that simply stops sending logs while still answering on the network"],
  logs="Security and System logs; heartbeat/last-seen data from your SIEM per host.",
  q=dict(
    sigma=r"""title: Event log cleared or audit policy wiped from the command line
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection_wevtutil:
    Image|endswith: '\wevtutil.exe'
    CommandLine|contains:
      - ' cl '
      - 'clear-log'
  selection_auditpol:
    Image|endswith: '\auditpol.exe'
    CommandLine|contains:
      - '/clear'
      - '/remove'
  selection_ps:
    CommandLine|contains:
      - 'Clear-EventLog'
      - 'Remove-EventLog'
  selection_fltmc:
    Image|endswith: '\fltMC.exe'
    CommandLine|contains: 'unload'
  condition: 1 of selection_*
falsepositives:
  - Golden-image preparation scripts that clear logs before sysprep
level: high
tags:
  - attack.defense-impairment
  - attack.t1685.005""",
    kql=r"""// Hosts that went quiet: sent events every day for two weeks, nothing in the last 6 hours
let active = DeviceInfo | where Timestamp > ago(14d) | summarize lastSeen = max(Timestamp) by DeviceName;
active
| where lastSeen < ago(6h)
| join kind=leftouter (DeviceNetworkInfo | summarize ip = any(IPAddresses) by DeviceName) on DeviceName
| order by lastSeen asc""",
    spl=r"""index=wineventlog (EventCode=1102 OR (source=System EventCode=104) OR EventCode=4719)
| table _time host EventCode SubjectUserName Channel"""),
  ev=['EventID=1 Image="C:\\Windows\\System32\\wevtutil.exe" CommandLine="wevtutil cl Security"', 'EventID=1 Image="C:\\Windows\\System32\\wevtutil.exe" CommandLine="wevtutil qe System /c:5 /f:text"'],
  fp="Image builds before sysprep; a few admins clearing a full log by hand (they should not).",
  fix=["Forward logs in near real time so clearing the local copy loses nothing",
       "Alert on 1102 anywhere and on any host whose log volume drops to zero while it is still online",
       "Protect the agents: EDR tamper protection, Sysmon config ACLs, restricted local admin"]),

dict(id='de-defender', sec='evade', t='Turning off Defender and killing EDR', att=['T1685', 'T1687'], sev='critical',
  lens="Ransomware crews disable protection minutes before encryption: Set-MpPreference -DisableRealtimeMonitoring $true, exclusions for whole drives, "
       "or — when tamper protection blocks that — a signed but vulnerable driver loaded to kill the EDR process from the kernel (BYOVD; tools like EDRKillShifter and Terminator).",
  sig=["Set-MpPreference or Add-MpPreference with ExclusionPath, ExclusionProcess, DisableRealtimeMonitoring, DisableIOAVProtection",
       "Defender events 5001 (real-time protection disabled), 5007 (configuration changed, including new exclusions), 5013 (tamper protection blocked a change)",
       "A new kernel driver service (7045 type kernel) or driver load (Sysmon 6) of a known-vulnerable driver; EDR processes terminating"],
  logs="Microsoft-Windows-Windows Defender/Operational; process creation; Sysmon 6; EDR health.",
  q=dict(
    sigma=r"""title: Defender protection weakened from the command line
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection_cmd:
    CommandLine|contains:
      - 'Set-MpPreference'
      - 'Add-MpPreference'
  selection_what:
    CommandLine|contains:
      - 'DisableRealtimeMonitoring'
      - 'DisableIOAVProtection'
      - 'DisableBehaviorMonitoring'
      - 'ExclusionPath'
      - 'ExclusionProcess'
      - 'ExclusionExtension'
      - 'MAPSReporting 0'
  condition: selection_cmd and selection_what
falsepositives:
  - Deployment scripts that add product exclusions (should come from Intune/GPO, not a shell)
level: high
tags:
  - attack.defense-impairment
  - attack.t1685""",
    kql=r"""// Exclusions and protection changes recorded by Defender itself (5007), with what changed
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType in ("AntivirusDefinitionsUpdateFailed", "TamperingAttempt") or (ActionType == "RegistryValueSet" and RegistryKey has @"\Windows Defender\Exclusions")
| project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName, InitiatingProcessCommandLine
// and vulnerable drivers: compare DeviceEvents ActionType == "DriverLoad" SHA256 against loldrivers.io""",
    spl=r"""index=wineventlog source="XmlWinEventLog:Microsoft-Windows-Windows Defender/Operational" EventCode IN (5001, 5007, 5010, 5012, 5013)
| rex field=_raw "New Value:\s*(?<new_value>[^\r\n]+)"
| table _time host EventCode new_value"""),
  ev=['EventID=1 Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" CommandLine="powershell Set-MpPreference -DisableRealtimeMonitoring $true; Add-MpPreference -ExclusionPath C:\\"', 'EventID=1 Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" CommandLine="powershell Get-MpPreference"'],
  fp="Product installers adding narrowly-scoped exclusions; these belong in central policy.",
  fix=["Tamper protection on, managed from Intune/MDE; local admins cannot merge exclusions (DisableLocalAdminMerge)",
       "Vulnerable driver blocklist and HVCI on; block drivers not on an allow-list on servers",
       "Treat a 5001 or new drive-wide exclusion as an incident — it usually precedes encryption by minutes"]),

dict(id='de-inject', sec='evade', t='Process injection and code without a file', att=['T1055', 'T1620'], sev='high',
  lens="Implants rarely run as their own process for long: they inject into explorer, svchost or a browser, or load .NET assemblies reflectively so no file ever exists. "
       "The traces are a remote thread created across processes, memory that is executable but not backed by a file on disk, and processes making network connections they never normally make.",
  sig=["Sysmon 8 (CreateRemoteThread) from an unusual source into explorer, lsass, svchost or a browser",
       "rundll32, dllhost or svchost with no command line arguments making outbound connections (classic Cobalt Strike spawn-to targets)",
       "Notepad, calc or another GUI program with network connections"],
  logs="Sysmon 8 and 10, EDR memory and API telemetry, network connections by process.",
  q=dict(
    sigma=r"""title: Remote thread created in a sensitive process by an unusual source
status: experimental
logsource:
  category: create_remote_thread
  product: windows
detection:
  selection:
    TargetImage|endswith:
      - '\explorer.exe'
      - '\lsass.exe'
      - '\svchost.exe'
      - '\winlogon.exe'
  filter_system:
    SourceImage|startswith:
      - 'C:\Windows\System32\'
      - 'C:\Program Files\'
      - 'C:\ProgramData\Microsoft\Windows Defender\'
  condition: selection and not filter_system
falsepositives:
  - Accessibility software, some games' anti-cheat and screen readers
level: high
tags:
  - attack.stealth
  - attack.t1055""",
    kql=r"""// Spawn-to processes with an empty command line talking to the internet
DeviceNetworkEvents
| where Timestamp > ago(7d) and RemoteIPType == "Public"
| where InitiatingProcessFileName in~ ("rundll32.exe", "dllhost.exe", "svchost.exe", "werfault.exe", "searchprotocolhost.exe", "notepad.exe", "gpupdate.exe")
| where InitiatingProcessCommandLine in~ ("rundll32.exe", "\"rundll32.exe\"", "dllhost.exe", "notepad.exe", "gpupdate.exe", "werfault.exe") or isempty(InitiatingProcessCommandLine)
| summarize conns = count(), dests = make_set(RemoteIP, 10) by DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine""",
    eql=r"""sequence by host.id with maxspan=1m
  [process where event.type == "start" and process.name : ("rundll32.exe", "dllhost.exe", "gpupdate.exe", "werfault.exe") and process.args_count == 1]
  [network where process.name : ("rundll32.exe", "dllhost.exe", "gpupdate.exe", "werfault.exe") and not cidrmatch(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]"""),
  ev=['EventID=8 SourceImage="C:\\Users\\Public\\upd.exe" TargetImage="C:\\Windows\\explorer.exe" StartFunction="LoadLibraryW"', 'EventID=8 SourceImage="C:\\Windows\\System32\\csrss.exe" TargetImage="C:\\Windows\\explorer.exe"'],
  fp="Accessibility tools, input-method editors, some security products; build an allow-list by signer.",
  fix=["Credential Guard and LSA protection reduce what injection into LSASS can steal",
       "EDR in block mode with memory scanning; ASR 'Block process creations originating from PSExec and WMI commands' where possible",
       "Memory capture (WinPmem) during IR, then Volatility malfind on the suspect process"]),

# ------------------------------------------------------------------ credential access
dict(id='ca-lsass', sec='cred', t='LSASS memory dumping', att=['T1003.001'], sev='critical',
  lens="LSASS holds the credentials of everyone logged on: NTLM hashes, Kerberos tickets, sometimes cleartext. Dump it and you can move as those people. "
       "Mimikatz is detected everywhere, so operators dump with signed tools — rundll32 comsvcs.dll MiniDump, ProcDump, Task Manager, or a custom MiniDumpWriteDump — and parse the dump offline.",
  sig=["rundll32 with comsvcs.dll and MiniDump in the command line",
       "procdump -ma lsass; any process opening lsass.exe with access 0x1010, 0x1410, 0x1438 or 0x1fffff that is not your EDR or Windows Error Reporting",
       "A .dmp file created in Temp or a share by an unexpected process; lsass.dmp in a user folder"],
  logs="Process creation; Sysmon 10 (process access) filtered to lsass; Defender 'LsassProcessAccess' / ASR 1121.",
  q=dict(
    sigma=r"""title: LSASS memory dumped with a signed Windows or Sysinternals tool
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection_comsvcs:
    CommandLine|contains|all:
      - 'comsvcs'
      - 'MiniDump'
  selection_procdump:
    CommandLine|contains|all:
      - ' -ma '
      - 'lsass'
  selection_other:
    CommandLine|contains:
      - 'sekurlsa::'
      - 'lsass.dmp'
      - 'Out-Minidump'
  condition: 1 of selection_*
falsepositives:
  - Support engineers taking a dump on request (should be rare and announced)
level: critical
tags:
  - attack.credential-access
  - attack.t1003.001""",
    kql=r"""DeviceEvents
| where Timestamp > ago(30d) and ActionType == "OpenProcessApiCall" and FileName =~ "lsass.exe"
| extend access = tostring(parse_json(AdditionalFields).DesiredAccess)
| where InitiatingProcessFileName !in~ ("MsMpEng.exe", "MsSense.exe", "SenseIR.exe", "csrss.exe", "wininit.exe", "svchost.exe", "WerFault.exe", "lsm.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, access""",
    spl=r"""index=sysmon EventCode=10 TargetImage="*\\lsass.exe" GrantedAccess IN ("0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff")
| search NOT SourceImage IN ("*\\MsMpEng.exe", "*\\MsSense.exe", "*\\csrss.exe", "*\\wininit.exe", "*\\WerFault.exe")
| stats count values(GrantedAccess) as access by host SourceImage SourceUser"""),
  ev=['EventID=1 Image="C:\\Windows\\System32\\rundll32.exe" CommandLine="rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\out.dmp full"', 'EventID=1 Image="C:\\Windows\\System32\\rundll32.exe" CommandLine="rundll32.exe shell32.dll,Control_RunDLL desk.cpl"'],
  fp="EDR and backup agents opening LSASS; WER crash handling. Allow-list by signer and path.",
  fix=["Credential Guard (VBS) so LSASS secrets are isolated; LSA protection (RunAsPPL = 1)",
       "ASR 'Block credential stealing from the Windows local security authority subsystem' (9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2)",
       "Admins log on to workstations only with workstation-tier accounts, so a dumped LSASS holds no domain admin"]),

dict(id='ca-kerberoast', sec='cred', t='Kerberoasting', att=['T1558.003'], sev='high',
  lens="Any domain user can request a Kerberos service ticket for any account with an SPN. Part of the ticket is encrypted with that account's password hash — request it, take it offline, crack it. "
       "Service accounts with old, human-chosen passwords fall in hours, and many are Domain Admins. Asking for RC4 encryption (type 0x17) makes cracking far faster, and is the main tell.",
  sig=["4769 with TicketEncryptionType 0x17 (RC4) for a user account (not ending in $) in a domain where AES is normal",
       "One account requesting tickets for many different SPNs in a few minutes",
       "Any ticket request for a honey SPN account that nothing legitimately uses"],
  logs="Security 4769 on all domain controllers (Audit Kerberos Service Ticket Operations); Defender for Identity.",
  q=dict(
    sigma=r"""title: Kerberos service ticket requested with RC4 encryption for a user account
status: stable
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'
    Status: '0x0'
  filter_machine:
    ServiceName|endswith: '$'
  filter_krbtgt:
    ServiceName: 'krbtgt'
  condition: selection and not filter_machine and not filter_krbtgt
falsepositives:
  - Old applications and appliances that only support RC4 (find and fix them)
level: medium
tags:
  - attack.credential-access
  - attack.t1558.003""",
    kql=r"""SecurityEvent
| where TimeGenerated > ago(7d) and EventID == 4769
| parse EventData with * 'ServiceName">' ServiceName '<' * 'TicketEncryptionType">' EncType '<' * 'IpAddress">' Ip '<' *
| where EncType == "0x17" and not(ServiceName endswith "$") and ServiceName != "krbtgt"
| summarize spns = dcount(ServiceName), list = make_set(ServiceName, 20) by TargetUserName, Ip, bin(TimeGenerated, 10m)
| where spns >= 3
| order by spns desc""",
    spl=r"""index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17 Service_Name!="*$" Service_Name!=krbtgt
| bin _time span=10m
| stats dc(Service_Name) as spns values(Service_Name) as services by _time Account_Name Client_Address
| where spns >= 3""",
    cli=r"""# Which user accounts can be Kerberoasted today (have an SPN), with password age
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName, PasswordLastSet, AdminCount, msDS-SupportedEncryptionTypes |
  Select SamAccountName, AdminCount, PasswordLastSet, msDS-SupportedEncryptionTypes, @{n='SPNs';e={$_.ServicePrincipalName -join '; '}} | Sort PasswordLastSet"""),
  ev=['EventID=4769 TargetUserName="j.okafor@CORP.LOCAL" ServiceName="svc_sql" TicketEncryptionType=0x17 Status=0x0 IpAddress="::ffff:10.20.4.17"', 'EventID=4769 TargetUserName="j.okafor@CORP.LOCAL" ServiceName="FS01$" TicketEncryptionType=0x12 Status=0x0'],
  fp="Legacy apps using RC4; vulnerability scanners enumerating SPNs (from known hosts).",
  fix=["Group Managed Service Accounts (gMSA) — 120-character random passwords rotated automatically",
       "For service accounts that must stay: 25+ character random passwords, AES only (msDS-SupportedEncryptionTypes = 24), no Domain Admin",
       "Create a honey SPN account with a long password and alert on any ticket request for it"]),

dict(id='ca-asrep', sec='cred', t='AS-REP roasting', att=['T1558.004'], sev='medium',
  lens="Accounts with 'Do not require Kerberos preauthentication' set will hand out an encrypted blob to anyone who asks — no password, no prior access needed. "
       "It is a legacy setting that lingers on old service and test accounts.",
  sig=["4768 with PreAuthType 0 for user accounts", "Several 4768 PreAuthType 0 requests from one workstation in minutes"],
  logs="Security 4768 on domain controllers.",
  q=dict(
    sigma=r"""title: Kerberos TGT requested without pre-authentication
status: stable
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4768
    PreAuthType: '0'
    Status: '0x0'
  filter_machine:
    TargetUserName|endswith: '$'
  condition: selection and not filter_machine
falsepositives:
  - Accounts that really need it (very rare; usually old Unix integrations)
level: medium
tags:
  - attack.credential-access
  - attack.t1558.004""",
    cli=r"""# Find them, then clear the flag
Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true' -Properties DoesNotRequirePreAuth, PasswordLastSet | Select SamAccountName, Enabled, PasswordLastSet
# Set-ADAccountControl -Identity <user> -DoesNotRequirePreAuth $false""",
    spl=r"""index=wineventlog EventCode=4768 Pre_Authentication_Type=0 Result_Code=0x0 Account_Name!="*$"
| stats count by Account_Name Client_Address"""),
  ev=['EventID=4768 TargetUserName="svc_legacy" PreAuthType=0 Status=0x0 TicketEncryptionType=0x17 IpAddress="::ffff:10.20.4.17"', 'EventID=4768 TargetUserName="j.okafor" PreAuthType=2 Status=0x0'],
  fp="Almost none once the setting is cleaned up.",
  fix=["Remove DONT_REQ_PREAUTH from every account; if one must keep it, give it a 25+ character password"]),

dict(id='ca-dcsync', sec='cred', t='DCSync', att=['T1003.006'], sev='critical',
  lens="With replication rights (Domain Admins have them, and misconfigured accounts sometimes do) an attacker asks a domain controller to replicate password data as if they were another DC: "
       "the krbtgt hash, every user's hash, no code on the DC. It is the step before Golden Tickets and the end of the domain's trust.",
  sig=["4662 on a DC with the replication rights GUIDs 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 (Get-Changes) and 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 (Get-Changes-All) by an account that is not a DC computer account",
       "Replication (DRSUAPI) traffic from an IP that is not a domain controller",
       "Defender for Identity alert 'Suspected DCSync attack (replication of directory services)'"],
  logs="Security 4662 on DCs with Directory Service Access auditing and a SACL on the domain object; MDI.",
  q=dict(
    sigma=r"""title: Directory replication requested by an account that is not a domain controller
status: stable
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4662
    Properties|contains:
      - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
      - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
      - '89e95b76-444d-4c62-991a-0facbeda640c'
  filter_dc:
    SubjectUserName|endswith: '$'
  condition: selection and not filter_dc
falsepositives:
  - Azure AD Connect / Entra Connect sync account (MSOL_*) — document it and filter by exact name
level: critical
tags:
  - attack.credential-access
  - attack.t1003.006""",
    kql=r"""SecurityEvent
| where TimeGenerated > ago(30d) and EventID == 4662
| where Properties has_any ("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", "89e95b76-444d-4c62-991a-0facbeda640c")
| where not(SubjectUserName endswith "$") and SubjectUserName !startswith "MSOL_"
| project TimeGenerated, Computer, SubjectUserName, SubjectDomainName, Properties""",
    cli=r"""# Who holds replication rights on the domain object (should be DCs, Enterprise/Domain Admins, Entra Connect only)
(Get-Acl "AD:\$((Get-ADDomain).DistinguishedName)").Access |
  Where-Object { $_.ObjectType -in '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2','1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' } |
  Select IdentityReference, ActiveDirectoryRights, ObjectType"""),
  ev=['EventID=4662 SubjectUserName="j.okafor" SubjectDomainName="CORP" ObjectServer="DS" Properties="%%7688 {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2} {19195a5b-6da0-11d0-afd3-00c04fd930c9}"', 'EventID=4662 SubjectUserName="DC02$" SubjectDomainName="CORP" Properties="%%7688 {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}"'],
  fp="Entra Connect's sync account; a few backup products. Name them exactly.",
  fix=["Audit who has replication rights; remove everyone who is not a DC or the sync account",
       "If DCSync is confirmed: reset krbtgt twice (10+ hours apart) and treat every account as compromised"]),

dict(id='ca-ntds', sec='cred', t='NTDS.dit and registry hive theft', att=['T1003.003', 'T1003.002'], sev='critical',
  lens="The domain's password database is a file on every DC: NTDS.dit, locked while in use. Operators copy it from a Volume Shadow Copy or ask ntdsutil to make an 'install from media' copy, then take the SYSTEM hive for the key. "
       "On ordinary hosts, reg save of SAM, SYSTEM and SECURITY gives local hashes and cached domain credentials. Volt Typhoon used ntdsutil exactly this way.",
  sig=["ntdsutil with 'ac i ntds' and 'ifm' / 'create full'", "vssadmin create shadow, or copying from \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy",
       "reg save HKLM\\SAM, HKLM\\SYSTEM or HKLM\\SECURITY; esentutl /y /vss on ntds.dit",
       "Large archives (7z, rar) created on a DC shortly after"],
  logs="Process creation on DCs and servers; Security 4688; VSS events (8222).",
  q=dict(
    sigma=r"""title: Copy of NTDS.dit or the SAM, SYSTEM and SECURITY hives
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection_ntdsutil:
    CommandLine|contains|all:
      - 'ntdsutil'
      - 'ifm'
  selection_vss:
    CommandLine|contains:
      - 'vssadmin create shadow'
      - 'HarddiskVolumeShadowCopy'
      - 'esentutl /y /vss'
  selection_reg:
    Image|endswith: '\reg.exe'
    CommandLine|contains: 'save'
  selection_hive:
    CommandLine|contains:
      - 'hklm\sam'
      - 'hklm\system'
      - 'hklm\security'
  condition: selection_ntdsutil or selection_vss or (selection_reg and selection_hive)
falsepositives:
  - Backup software creating shadow copies (by its own service, not by vssadmin from a shell)
level: critical
tags:
  - attack.credential-access
  - attack.t1003.003""",
    kql=r"""DeviceProcessEvents
| where Timestamp > ago(30d)
| where (ProcessCommandLine has "ntdsutil" and ProcessCommandLine has "ifm")
     or ProcessCommandLine has_any ("vssadmin create shadow", "HarddiskVolumeShadowCopy", "esentutl /y /vss")
     or (FileName =~ "reg.exe" and ProcessCommandLine has "save" and ProcessCommandLine has_any (@"hklm\sam", @"hklm\system", @"hklm\security"))
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName"""),
  ev=['EventID=1 Image="C:\\Windows\\System32\\ntdsutil.exe" CommandLine="ntdsutil \'ac i ntds\' \'ifm\' \'create full C:\\Windows\\Temp\\x\' q q"', 'EventID=1 Image="C:\\Windows\\System32\\reg.exe" CommandLine="reg query HKLM\\SYSTEM\\CurrentControlSet\\Services"'],
  fp="Real IFM builds for new DCs (planned, by named admins); backup agents.",
  fix=["Tier 0: DCs reachable only from privileged access workstations; no internet from DCs",
       "Alert on any ntdsutil ifm and any shadow-copy creation from a shell on a DC",
       "If NTDS.dit left the building: full credential reset including krbtgt (twice) and service accounts"]),

dict(id='ca-spray', sec='cred', t='Password spraying', att=['T1110.003'], sev='high',
  lens="Try one or two common passwords (Winter2025!, Company123) against every account, slowly, to stay under lockout. "
       "Against cloud identity it comes from residential proxy networks so each attempt has a different IP — Midnight Blizzard sprayed Microsoft's own legacy test tenant this way in late 2023. "
       "Look across accounts, not per account.",
  sig=["Entra ResultType 50126 (bad password) for many different users with the same user agent in a short window",
       "Failures for usernames that do not exist (50034) mixed in — a list from somewhere else",
       "On-premises: 4625 or 4771 (failure code 0x18) for many accounts from one source",
       "A success after the spray for one of the targeted accounts — the one that matters"],
  logs="Entra SigninLogs; Security 4625/4771 on DCs; VPN and OWA logs.",
  q=dict(
    kql=r"""// Many accounts, few tries each, then look for the success
let window = 1h;
let spray = SigninLogs
  | where TimeGenerated > ago(7d) and ResultType in ("50126", "50034", "50053")
  | summarize users = dcount(UserPrincipalName), ips = dcount(IPAddress), tries = count() by UserAgent, bin(TimeGenerated, window)
  | where users >= 20 and tries / users <= 3;
spray
| join kind=inner (SigninLogs | where ResultType == "0" | project okAt = TimeGenerated, UserPrincipalName, UserAgent, IPAddress) on UserAgent
| where okAt between (TimeGenerated .. TimeGenerated + 2h)
| project spreeStart = TimeGenerated, users, ips, UserAgent, UserPrincipalName, okAt, IPAddress""",
    spl=r"""index=wineventlog (EventCode=4625 OR (EventCode=4771 Failure_Code=0x18))
| bin _time span=30m
| stats dc(Account_Name) as accounts count as attempts by _time src_ip
| where accounts >= 15 AND attempts/accounts <= 3
| sort - accounts""",
    sigma=r"""title: Kerberos pre-authentication failure (bad password)
status: experimental
description: Single failures are normal; aggregate this by source over 30 minutes and alert when one source fails for many accounts.
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4771
    Status: '0x18'
  condition: selection
falsepositives:
  - Users with a cached old password; count distinct accounts per source, not events
level: low
tags:
  - attack.credential-access
  - attack.t1110.003"""),
  ev=['EventID=4771 TargetUserName="m.berg" Status=0x18 IpAddress="::ffff:10.20.4.17"', 'EventID=4771 TargetUserName="m.berg" Status=0x12 IpAddress="::ffff:10.20.4.17"'],
  fp="A misconfigured service retrying an old password against one account (many tries, one account — the opposite shape).",
  fix=["Block legacy authentication; MFA everywhere, phishing-resistant for admins; Entra Password Protection with a custom banned list (company name, city, seasons)",
       "Smart lockout tuned; Conditional Access blocking sign-ins from anonymiser and hosting networks for most users",
       "Find and disable forgotten test and legacy tenants and accounts — the spray only needs one without MFA"]),

dict(id='ca-browser', sec='cred', t='Infostealers and browser credential theft', att=['T1555.003', 'T1539'], sev='high',
  lens="Infostealers (Lumma, RedLine, Vidar, StealC and their successors) take saved passwords, cookies, crypto wallets and session tokens from browsers in seconds, then delete themselves. "
       "The logs are sold on markets and Telegram; a stolen session cookie skips MFA entirely. A large share of corporate breaches now start with an employee's personal or work machine in a stealer log.",
  sig=["A process that is not the browser reading Login Data, Cookies, Web Data or Local State in Chrome/Edge/Brave profiles",
       "Processes touching wallet extension folders (Local Extension Settings\\nkbihfbeogaeaoehlefnkodbefgpgknn — MetaMask) or wallet files",
       "A short-lived unsigned executable from Downloads or Temp making an HTTPS POST to a raw IP or Telegram, then exiting",
       "Your company domain appearing in stealer-log sources (OSINTrix's stealer-log reader, Hudson Rock's free lookup)"],
  logs="File access auditing (4663 with a SACL on browser profile folders) or EDR file-read telemetry; process and network events.",
  q=dict(
    sigma=r"""title: Non-browser process reads browser credential stores
status: experimental
description: Requires object-access auditing (4663) with a SACL on browser profile folders, or EDR file-access events.
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4663
    ObjectName|contains:
      - '\User Data\Default\Login Data'
      - '\User Data\Default\Network\Cookies'
      - '\User Data\Local State'
      - '\User Data\Default\Web Data'
  filter_browsers:
    ProcessName|endswith:
      - '\chrome.exe'
      - '\msedge.exe'
      - '\brave.exe'
      - '\opera.exe'
  condition: selection and not filter_browsers
falsepositives:
  - Backup and sync agents, password-manager importers
level: high
tags:
  - attack.credential-access
  - attack.t1555.003""",
    kql=r"""// Short-lived executables from user folders that talk to the internet once and are gone
DeviceProcessEvents
| where Timestamp > ago(7d) and FolderPath has_any (@"\Downloads\", @"\AppData\Local\Temp\", @"\Users\Public\")
| join kind=inner (DeviceNetworkEvents | where RemoteIPType == "Public" | project DeviceId, InitiatingProcessId, Timestamp1 = Timestamp, RemoteIP, RemoteUrl) on $left.DeviceId == $right.DeviceId, $left.ProcessId == $right.InitiatingProcessId
| summarize conns = count(), dests = make_set(coalesce(RemoteUrl, RemoteIP), 5) by DeviceName, FileName, SHA256, AccountName
| where conns <= 5"""),
  ev=['EventID=4663 ObjectName="C:\\Users\\j.okafor\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data" ProcessName="C:\\Users\\j.okafor\\AppData\\Local\\Temp\\setup_x64.exe" AccessMask=0x1', 'EventID=4663 ObjectName="C:\\Users\\j.okafor\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data" ProcessName="C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"'],
  fp="Password managers importing from browsers; backup software; browser updaters.",
  fix=["Do not let browsers store work passwords — use a managed password manager; Chrome's app-bound encryption raises the bar but stealers adapted",
       "Short session lifetimes for sensitive apps, token protection and device-bound sessions; revoke sessions when a machine appears in a stealer log",
       "Block unsigned executables from Downloads and Temp; keep personal browsing off work profiles"]),
]
