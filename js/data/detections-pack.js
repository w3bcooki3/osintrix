/* Built-in detection pack: common and advanced Sigma and YARA rules. Plain JSON after the "=". */
const RULE_PACK = [
  {
    "id": "pk-sig-001",
    "type": "sigma",
    "title": "Certutil Used to Download a File",
    "description": "Detects certutil.exe with -urlcache or -verifyctl and a URL, a common way to pull payloads with a signed Windows binary.",
    "code": "title: 'Certutil Used to Download a File'\nid: fd137b39-a3db-5789-b7a1-b313916336bc\nstatus: test\ndescription: 'Detects certutil.exe with -urlcache or -verifyctl and a URL, a common way to pull payloads with a signed Windows binary.'\nreferences:\n    - https://lolbas-project.github.io/\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.command-and-control\n    - attack.t1105\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_img:\n        - Image|endswith: '\\certutil.exe'\n        - OriginalFileName: 'CertUtil.exe'\n    selection_flag:\n        CommandLine|contains:\n            - 'urlcache'\n            - 'verifyctl'\n    selection_url:\n        CommandLine|contains:\n            - 'http://'\n            - 'https://'\n            - 'ftp://'\n    condition: all of selection_*\nfalsepositives:\n    - 'Rare administrative certificate retrieval from internal CRL/AIA endpoints'\nlevel: high",
    "severity": "high",
    "category": "command-and-control",
    "technique": "T1105",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "lolbin",
      "certutil",
      "download"
    ],
    "references": [
      "https://lolbas-project.github.io/",
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-002",
    "type": "sigma",
    "title": "Certutil Decode of Encoded File",
    "description": "Detects certutil.exe decoding base64 or hex content to disk, often used to unpack a payload delivered as text.",
    "code": "title: 'Certutil Decode of Encoded File'\nid: 9b6ee185-5550-52ca-b963-7662c6399b0b\nstatus: test\ndescription: 'Detects certutil.exe decoding base64 or hex content to disk, often used to unpack a payload delivered as text.'\nreferences:\n    - https://lolbas-project.github.io/\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1140\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_img:\n        - Image|endswith: '\\certutil.exe'\n        - OriginalFileName: 'CertUtil.exe'\n    selection_cli:\n        CommandLine|contains:\n            - ' -decode '\n            - ' /decode '\n            - ' -decodehex '\n            - ' /decodehex '\n    condition: all of selection_*\nfalsepositives:\n    - 'Certificate administrators converting PEM files'\nlevel: medium",
    "severity": "medium",
    "category": "defense-evasion",
    "technique": "T1140",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "lolbin",
      "certutil",
      "decode"
    ],
    "references": [
      "https://lolbas-project.github.io/",
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-003",
    "type": "sigma",
    "title": "Mshta Executing Inline VBScript or JavaScript",
    "description": "Detects mshta.exe invoked with an inline vbscript: or javascript: protocol handler instead of an HTA file, typical of fileless loaders and ClickFix lures.",
    "code": "title: 'Mshta Executing Inline VBScript or JavaScript'\nid: 17a82bdc-1fa1-59ab-abd2-f81654de1243\nstatus: test\ndescription: 'Detects mshta.exe invoked with an inline vbscript: or javascript: protocol handler instead of an HTA file, typical of fileless loaders and ClickFix lures.'\nreferences:\n    - https://lolbas-project.github.io/\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1218.005\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_img:\n        - Image|endswith: '\\mshta.exe'\n        - OriginalFileName: 'MSHTA.EXE'\n    selection_cli:\n        CommandLine|contains:\n            - 'vbscript:'\n            - 'javascript:'\n            - 'about:<script'\n    condition: all of selection_*\nfalsepositives:\n    - 'Very old line-of-business tools that wrap mshta'\nlevel: high",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1218.005",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "lolbin",
      "mshta",
      "fileless"
    ],
    "references": [
      "https://lolbas-project.github.io/",
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-004",
    "type": "sigma",
    "title": "Rundll32 Loading DLL From User-Writable Directory",
    "description": "Detects rundll32.exe loading a DLL from Temp, AppData, Downloads, ProgramData or the Public profile.",
    "code": "title: 'Rundll32 Loading DLL From User-Writable Directory'\nid: 6e20dbe8-626f-5a26-880f-21cde451c478\nstatus: test\ndescription: 'Detects rundll32.exe loading a DLL from Temp, AppData, Downloads, ProgramData or the Public profile.'\nreferences:\n    - https://lolbas-project.github.io/\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1218.011\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_img:\n        - Image|endswith: '\\rundll32.exe'\n        - OriginalFileName: 'RUNDLL32.EXE'\n    selection_path:\n        CommandLine|contains:\n            - '\\AppData\\Local\\Temp\\'\n            - '\\AppData\\Roaming\\'\n            - '\\Users\\Public\\'\n            - '\\Downloads\\'\n            - '\\ProgramData\\'\n            - '\\Windows\\Temp\\'\n    filter_known:\n        CommandLine|contains:\n            - '\\AppData\\Local\\Temp\\{'\n            - 'shell32.dll,Control_RunDLL'\n    condition: all of selection_* and not filter_known\nfalsepositives:\n    - 'Some installers and updaters extract helper DLLs to Temp'\n    - 'Printer driver setup'\nlevel: medium",
    "severity": "medium",
    "category": "defense-evasion",
    "technique": "T1218.011",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "lolbin",
      "rundll32"
    ],
    "references": [
      "https://lolbas-project.github.io/",
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-005",
    "type": "sigma",
    "title": "Rundll32 Executing JavaScript via mshtml RunHTMLApplication",
    "description": "Detects the rundll32 javascript: / mshtml,RunHTMLApplication trick used to run script code without mshta.exe.",
    "code": "title: 'Rundll32 Executing JavaScript via mshtml RunHTMLApplication'\nid: 0b638822-14dd-51ea-ba1d-4e23f89d5aeb\nstatus: test\ndescription: 'Detects the rundll32 javascript: / mshtml,RunHTMLApplication trick used to run script code without mshta.exe.'\nreferences:\n    - https://lolbas-project.github.io/\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1218.011\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_img:\n        - Image|endswith: '\\rundll32.exe'\n        - OriginalFileName: 'RUNDLL32.EXE'\n    selection_cli:\n        CommandLine|contains|all:\n            - 'javascript:'\n            - 'RunHTMLApplication'\n    condition: all of selection_*\nfalsepositives:\n    - 'None expected'\nlevel: critical",
    "severity": "critical",
    "category": "defense-evasion",
    "technique": "T1218.011",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "lolbin",
      "rundll32",
      "fileless"
    ],
    "references": [
      "https://lolbas-project.github.io/",
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-006",
    "type": "sigma",
    "title": "Regsvr32 Squiblydoo Remote Scriptlet",
    "description": "Detects regsvr32.exe loading scrobj.dll with a /i: argument pointing to a remote or local scriptlet (Squiblydoo).",
    "code": "title: 'Regsvr32 Squiblydoo Remote Scriptlet'\nid: a119dfd6-3259-5ede-a09d-d7b665b4c5e3\nstatus: test\ndescription: 'Detects regsvr32.exe loading scrobj.dll with a /i: argument pointing to a remote or local scriptlet (Squiblydoo).'\nreferences:\n    - https://lolbas-project.github.io/\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1218.010\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_img:\n        - Image|endswith: '\\regsvr32.exe'\n        - OriginalFileName: 'REGSVR32.EXE'\n    selection_cli:\n        CommandLine|contains: '/i:'\n    selection_obj:\n        CommandLine|contains:\n            - 'scrobj'\n            - 'http'\n            - '.sct'\n    condition: all of selection_*\nfalsepositives:\n    - 'Legacy COM scriptlet registration by in-house software'\nlevel: high",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1218.010",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "lolbin",
      "regsvr32",
      "squiblydoo"
    ],
    "references": [
      "https://lolbas-project.github.io/",
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-007",
    "type": "sigma",
    "title": "Msiexec Installing Package From Remote URL",
    "description": "Detects msiexec.exe installing an MSI quietly from an HTTP(S) location, a common loader technique.",
    "code": "title: 'Msiexec Installing Package From Remote URL'\nid: 8cef9935-cc12-572c-af51-e5b02e88c822\nstatus: test\ndescription: 'Detects msiexec.exe installing an MSI quietly from an HTTP(S) location, a common loader technique.'\nreferences:\n    - https://lolbas-project.github.io/\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1218.007\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_img:\n        - Image|endswith: '\\msiexec.exe'\n        - OriginalFileName: 'msiexec.exe'\n    selection_inst:\n        CommandLine|contains:\n            - ' /i'\n            - ' -i'\n            - ' /package'\n            - ' -package'\n    selection_url:\n        CommandLine|contains:\n            - 'http://'\n            - 'https://'\n    condition: all of selection_*\nfalsepositives:\n    - 'Software deployment tools that install MSIs directly from internal web servers'\nlevel: medium",
    "severity": "medium",
    "category": "defense-evasion",
    "technique": "T1218.007",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "lolbin",
      "msiexec"
    ],
    "references": [
      "https://lolbas-project.github.io/",
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-008",
    "type": "sigma",
    "title": "Bitsadmin Transfer Job Created",
    "description": "Detects bitsadmin.exe creating or running a transfer job, which can download payloads or persist via job notification commands.",
    "code": "title: 'Bitsadmin Transfer Job Created'\nid: f3ed79a8-e052-5f31-aff2-ae7986a778f0\nstatus: test\ndescription: 'Detects bitsadmin.exe creating or running a transfer job, which can download payloads or persist via job notification commands.'\nreferences:\n    - https://lolbas-project.github.io/\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1197\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_img:\n        - Image|endswith: '\\bitsadmin.exe'\n        - OriginalFileName: 'bitsadmin.exe'\n    selection_cli:\n        CommandLine|contains:\n            - ' /transfer '\n            - ' /addfile '\n            - ' /SetNotifyCmdLine '\n            - ' /create '\n    condition: all of selection_*\nfalsepositives:\n    - 'Legacy software update scripts still using bitsadmin'\nlevel: medium",
    "severity": "medium",
    "category": "persistence",
    "technique": "T1197",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "lolbin",
      "bits"
    ],
    "references": [
      "https://lolbas-project.github.io/",
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-009",
    "type": "sigma",
    "title": "WMIC Remote Process Creation",
    "description": "Detects wmic.exe used with /node: and process call create to start a process on another host.",
    "code": "title: 'WMIC Remote Process Creation'\nid: 1573f4de-9937-5d1c-b0e4-86ebe02c6be4\nstatus: test\ndescription: 'Detects wmic.exe used with /node: and process call create to start a process on another host.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.lateral-movement\n    - attack.t1047\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_img:\n        - Image|endswith: '\\WMIC.exe'\n        - OriginalFileName: 'wmic.exe'\n    selection_cli:\n        CommandLine|contains|all:\n            - '/node:'\n            - 'process'\n            - 'call'\n            - 'create'\n    condition: all of selection_*\nfalsepositives:\n    - 'Administrative scripts managing remote hosts'\nlevel: medium",
    "severity": "medium",
    "category": "lateral-movement",
    "technique": "T1047",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "wmi",
      "lateral"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-010",
    "type": "sigma",
    "title": "WMIC XSL Script Processing",
    "description": "Detects wmic.exe with a /format: argument pointing at a remote or non-standard XSL stylesheet, which can execute embedded script.",
    "code": "title: 'WMIC XSL Script Processing'\nid: 9cb0d2f7-60c3-5133-bd9d-0e1ca83b2808\nstatus: test\ndescription: 'Detects wmic.exe with a /format: argument pointing at a remote or non-standard XSL stylesheet, which can execute embedded script.'\nreferences:\n    - https://lolbas-project.github.io/\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1220\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_img:\n        - Image|endswith: '\\WMIC.exe'\n        - OriginalFileName: 'wmic.exe'\n    selection_cli:\n        CommandLine|contains:\n            - '/format:http'\n            - '-format:http'\n            - '/format:\"http'\n            - '.xsl'\n    filter_builtin:\n        CommandLine|contains:\n            - '/format:list'\n            - '/format:table'\n            - '/format:csv'\n            - '/format:htable'\n            - '/format:value'\n    condition: all of selection_* and not filter_builtin\nfalsepositives:\n    - 'Administrators using custom XSL formatting for reports'\nlevel: high",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1220",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "wmi",
      "xsl",
      "squiblytwo"
    ],
    "references": [
      "https://lolbas-project.github.io/",
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-011",
    "type": "sigma",
    "title": "CMSTP Silent INF Installation",
    "description": "Detects cmstp.exe used with /s and an INF file, a known UAC bypass and proxy-execution technique.",
    "code": "title: 'CMSTP Silent INF Installation'\nid: 93526b49-494d-582c-811f-cc8bc38fcb58\nstatus: test\ndescription: 'Detects cmstp.exe used with /s and an INF file, a known UAC bypass and proxy-execution technique.'\nreferences:\n    - https://lolbas-project.github.io/\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1218.003\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_img:\n        - Image|endswith: '\\cmstp.exe'\n        - OriginalFileName: 'CMSTP.EXE'\n    selection_cli:\n        CommandLine|contains:\n            - ' /s '\n            - ' -s '\n            - ' /ni '\n            - ' -ni '\n    selection_inf:\n        CommandLine|contains: '.inf'\n    condition: all of selection_*\nfalsepositives:\n    - 'VPN connection profile deployment via Connection Manager'\nlevel: high",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1218.003",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "lolbin",
      "cmstp",
      "uac-bypass"
    ],
    "references": [
      "https://lolbas-project.github.io/",
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-012",
    "type": "sigma",
    "title": "InstallUtil Proxy Execution With Uninstall Switch",
    "description": "Detects InstallUtil.exe run with /U and logging disabled, the pattern used to execute code in an uninstall routine of a .NET assembly.",
    "code": "title: 'InstallUtil Proxy Execution With Uninstall Switch'\nid: 08d8f543-d9d0-52a7-9661-339e5087d1c2\nstatus: test\ndescription: 'Detects InstallUtil.exe run with /U and logging disabled, the pattern used to execute code in an uninstall routine of a .NET assembly.'\nreferences:\n    - https://lolbas-project.github.io/\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1218.004\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_img:\n        - Image|endswith: '\\InstallUtil.exe'\n        - OriginalFileName: 'InstallUtil.exe'\n    selection_cli:\n        CommandLine|contains:\n            - '/logfile='\n            - '/LogToConsole=false'\n    selection_u:\n        CommandLine|contains:\n            - ' /U '\n            - ' /u '\n    condition: all of selection_*\nfalsepositives:\n    - 'Developers testing .NET installer classes'\nlevel: high",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1218.004",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "lolbin",
      "installutil",
      "dotnet"
    ],
    "references": [
      "https://lolbas-project.github.io/",
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-013",
    "type": "sigma",
    "title": "Odbcconf Loading DLL via REGSVR or Response File",
    "description": "Detects odbcconf.exe being used to load an arbitrary DLL through the REGSVR action or a .rsp response file.",
    "code": "title: 'Odbcconf Loading DLL via REGSVR or Response File'\nid: 25899f41-28e0-5053-be78-7cd62d28cd6c\nstatus: test\ndescription: 'Detects odbcconf.exe being used to load an arbitrary DLL through the REGSVR action or a .rsp response file.'\nreferences:\n    - https://lolbas-project.github.io/\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1218.008\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_img:\n        - Image|endswith: '\\odbcconf.exe'\n        - OriginalFileName: 'odbcconf.exe'\n    selection_cli:\n        CommandLine|contains:\n            - 'regsvr'\n            - ' -f '\n            - ' /f '\n            - '.rsp'\n    condition: all of selection_*\nfalsepositives:\n    - 'ODBC driver installation scripts'\nlevel: high",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1218.008",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "lolbin",
      "odbcconf"
    ],
    "references": [
      "https://lolbas-project.github.io/",
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-014",
    "type": "sigma",
    "title": "Indirect Command Execution via Forfiles or Pcalua",
    "description": "Detects forfiles.exe with /c or pcalua.exe with -a being used to launch another program, breaking the usual parent-child chain.",
    "code": "title: 'Indirect Command Execution via Forfiles or Pcalua'\nid: fb8b4785-31f3-5b26-a9a8-e5a1ce49e29d\nstatus: test\ndescription: 'Detects forfiles.exe with /c or pcalua.exe with -a being used to launch another program, breaking the usual parent-child chain.'\nreferences:\n    - https://lolbas-project.github.io/\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1202\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_forfiles:\n        Image|endswith: '\\forfiles.exe'\n        CommandLine|contains:\n            - ' /c '\n            - ' -c '\n    selection_pcalua:\n        Image|endswith: '\\pcalua.exe'\n        CommandLine|contains: ' -a '\n    condition: 1 of selection_*\nfalsepositives:\n    - 'Housekeeping batch scripts using forfiles to delete old logs'\nlevel: medium",
    "severity": "medium",
    "category": "defense-evasion",
    "technique": "T1202",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "lolbin",
      "forfiles",
      "pcalua"
    ],
    "references": [
      "https://lolbas-project.github.io/",
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-015",
    "type": "sigma",
    "title": "MSBuild Spawned by Office or Script Host",
    "description": "Detects MSBuild.exe launched by an Office application or script host, used to compile and run inline C# tasks.",
    "code": "title: 'MSBuild Spawned by Office or Script Host'\nid: 2fbcef9b-56ca-553e-9f90-d37dc734a8e5\nstatus: test\ndescription: 'Detects MSBuild.exe launched by an Office application or script host, used to compile and run inline C# tasks.'\nreferences:\n    - https://lolbas-project.github.io/\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1127.001\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_img:\n        Image|endswith: '\\MSBuild.exe'\n    selection_parent:\n        ParentImage|endswith:\n            - '\\winword.exe'\n            - '\\excel.exe'\n            - '\\powerpnt.exe'\n            - '\\outlook.exe'\n            - '\\wscript.exe'\n            - '\\cscript.exe'\n            - '\\mshta.exe'\n            - '\\explorer.exe'\n    condition: all of selection_*\nfalsepositives:\n    - 'Developers launching build files directly from Explorer'\nlevel: high",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1127.001",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "lolbin",
      "msbuild"
    ],
    "references": [
      "https://lolbas-project.github.io/",
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-016",
    "type": "sigma",
    "title": "CSC Compiler Spawned by Script Host or Office",
    "description": "Detects csc.exe compiling code at run time with a script host or Office as parent, a pattern seen in loaders that compile payloads on the endpoint.",
    "code": "title: 'CSC Compiler Spawned by Script Host or Office'\nid: aa718fa5-ad5f-5817-b0b5-1fee7347ab91\nstatus: test\ndescription: 'Detects csc.exe compiling code at run time with a script host or Office as parent, a pattern seen in loaders that compile payloads on the endpoint.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1027.004\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        Image|endswith: '\\csc.exe'\n        ParentImage|endswith:\n            - '\\wscript.exe'\n            - '\\cscript.exe'\n            - '\\mshta.exe'\n            - '\\winword.exe'\n            - '\\excel.exe'\n            - '\\powerpnt.exe'\n    condition: selection\nfalsepositives:\n    - 'Legitimate scripted build steps (rare)'\nlevel: high",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1027.004",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "compile-after-delivery",
      "csc"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-017",
    "type": "sigma",
    "title": "HTML Help Executable Opening CHM From Unusual Location",
    "description": "Detects hh.exe opening a .chm file from Downloads, Temp or a remote URL, a known malware delivery vector.",
    "code": "title: 'HTML Help Executable Opening CHM From Unusual Location'\nid: ab784a85-98a7-50e2-99fe-668d81384d0a\nstatus: test\ndescription: 'Detects hh.exe opening a .chm file from Downloads, Temp or a remote URL, a known malware delivery vector.'\nreferences:\n    - https://lolbas-project.github.io/\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1218.001\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_img:\n        Image|endswith: '\\hh.exe'\n    selection_cli:\n        CommandLine|contains:\n            - '\\Downloads\\'\n            - '\\AppData\\Local\\Temp\\'\n            - '\\Users\\Public\\'\n            - 'http://'\n            - 'https://'\n    condition: all of selection_*\nfalsepositives:\n    - 'Users opening help files downloaded from vendor sites'\nlevel: medium",
    "severity": "medium",
    "category": "defense-evasion",
    "technique": "T1218.001",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "lolbin",
      "chm"
    ],
    "references": [
      "https://lolbas-project.github.io/",
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-018",
    "type": "sigma",
    "title": "Control Panel Item Loaded From Temp or AppData",
    "description": "Detects control.exe or rundll32 Control_RunDLL loading a .cpl file from a user-writable directory.",
    "code": "title: 'Control Panel Item Loaded From Temp or AppData'\nid: 8bc3c326-38b3-5dff-8530-0ea829c086d0\nstatus: test\ndescription: 'Detects control.exe or rundll32 Control_RunDLL loading a .cpl file from a user-writable directory.'\nreferences:\n    - https://lolbas-project.github.io/\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1218.002\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_img:\n        Image|endswith:\n            - '\\control.exe'\n            - '\\rundll32.exe'\n    selection_cpl:\n        CommandLine|contains: '.cpl'\n    selection_path:\n        CommandLine|contains:\n            - '\\AppData\\'\n            - '\\Temp\\'\n            - '\\Users\\Public\\'\n            - '\\Downloads\\'\n    condition: all of selection_*\nfalsepositives:\n    - 'Third-party control panel applets installed per-user'\nlevel: medium",
    "severity": "medium",
    "category": "defense-evasion",
    "technique": "T1218.002",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "lolbin",
      "cpl"
    ],
    "references": [
      "https://lolbas-project.github.io/",
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-019",
    "type": "sigma",
    "title": "Mavinject DLL Injection",
    "description": "Detects mavinject.exe /INJECTRUNNING, which injects a DLL into a running process using a signed Microsoft binary.",
    "code": "title: 'Mavinject DLL Injection'\nid: 83c30844-62fe-5b76-9792-ea8c1508624f\nstatus: test\ndescription: 'Detects mavinject.exe /INJECTRUNNING, which injects a DLL into a running process using a signed Microsoft binary.'\nreferences:\n    - https://lolbas-project.github.io/\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1218.013\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        - Image|endswith: '\\mavinject.exe'\n        - OriginalFileName: 'mavinject.exe'\n    selection_cli:\n        CommandLine|contains: '/INJECTRUNNING'\n    condition: all of selection*\nfalsepositives:\n    - 'App-V virtualisation components on systems that use App-V'\nlevel: high",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1218.013",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "lolbin",
      "injection"
    ],
    "references": [
      "https://lolbas-project.github.io/",
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-020",
    "type": "sigma",
    "title": "Defender MpCmdRun or Desktopimgdownldr Used to Download",
    "description": "Detects MpCmdRun.exe -DownloadFile or desktopimgdownldr.exe /lockscreenurl abused to fetch remote content.",
    "code": "title: 'Defender MpCmdRun or Desktopimgdownldr Used to Download'\nid: ebeb11c6-493c-5d1a-b126-50be9fd79e1e\nstatus: test\ndescription: 'Detects MpCmdRun.exe -DownloadFile or desktopimgdownldr.exe /lockscreenurl abused to fetch remote content.'\nreferences:\n    - https://lolbas-project.github.io/\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.command-and-control\n    - attack.t1105\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_mp:\n        Image|endswith: '\\MpCmdRun.exe'\n        CommandLine|contains|all:\n            - 'DownloadFile'\n            - 'url'\n    selection_dimg:\n        Image|endswith: '\\desktopimgdownldr.exe'\n        CommandLine|contains: '/lockscreenurl:'\n    filter_dimg:\n        CommandLine|contains: '.jpg'\n    condition: selection_mp or (selection_dimg and not filter_dimg)\nfalsepositives:\n    - 'None expected for MpCmdRun DownloadFile'\nlevel: high",
    "severity": "high",
    "category": "command-and-control",
    "technique": "T1105",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "lolbin",
      "download",
      "defender"
    ],
    "references": [
      "https://lolbas-project.github.io/",
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-021",
    "type": "sigma",
    "title": "Wuauclt Loading DLL via UpdateDeploymentProvider",
    "description": "Detects wuauclt.exe /UpdateDeploymentProvider with /RunHandlerComServer, used to execute an attacker DLL.",
    "code": "title: 'Wuauclt Loading DLL via UpdateDeploymentProvider'\nid: 1e572914-7638-59f1-b3db-fb0af32ab856\nstatus: test\ndescription: 'Detects wuauclt.exe /UpdateDeploymentProvider with /RunHandlerComServer, used to execute an attacker DLL.'\nreferences:\n    - https://lolbas-project.github.io/\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1218\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        Image|endswith: '\\wuauclt.exe'\n        CommandLine|contains|all:\n            - '/UpdateDeploymentProvider'\n            - '/RunHandlerComServer'\n    filter_legit:\n        CommandLine|contains: '\\UpdateDeploy.dll'\n    condition: selection and not filter_legit\nfalsepositives:\n    - 'None expected'\nlevel: high",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1218",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "lolbin",
      "wuauclt"
    ],
    "references": [
      "https://lolbas-project.github.io/",
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-022",
    "type": "sigma",
    "title": "Finger Used to Retrieve Remote Payload",
    "description": "Detects finger.exe with an @host argument, abused to download text payloads (seen in ClickFix-style campaigns).",
    "code": "title: 'Finger Used to Retrieve Remote Payload'\nid: d0160890-25bc-55d5-82b9-04e2872599f6\nstatus: test\ndescription: 'Detects finger.exe with an @host argument, abused to download text payloads (seen in ClickFix-style campaigns).'\nreferences:\n    - https://lolbas-project.github.io/\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.command-and-control\n    - attack.t1105\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        - Image|endswith: '\\finger.exe'\n        - OriginalFileName: 'finger.exe'\n    selection_cli:\n        CommandLine|contains: '@'\n    condition: all of selection*\nfalsepositives:\n    - 'Essentially none on modern networks'\nlevel: high",
    "severity": "high",
    "category": "command-and-control",
    "technique": "T1105",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "lolbin",
      "finger",
      "download"
    ],
    "references": [
      "https://lolbas-project.github.io/",
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-023",
    "type": "sigma",
    "title": "Windows Curl Downloading to User-Writable Path",
    "description": "Detects the built-in curl.exe saving a remote file into Temp, AppData, ProgramData or Public folders.",
    "code": "title: 'Windows Curl Downloading to User-Writable Path'\nid: d5af7451-3a00-5f09-aec2-239ed00d551d\nstatus: test\ndescription: 'Detects the built-in curl.exe saving a remote file into Temp, AppData, ProgramData or Public folders.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.command-and-control\n    - attack.t1105\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_img:\n        - Image|endswith: '\\curl.exe'\n        - OriginalFileName: 'curl.exe'\n    selection_out:\n        CommandLine|contains:\n            - ' -o '\n            - ' --output '\n            - ' -O '\n    selection_path:\n        CommandLine|contains:\n            - '\\AppData\\'\n            - '\\Temp\\'\n            - '\\ProgramData\\'\n            - '\\Users\\Public\\'\n            - '%TEMP%'\n            - '%APPDATA%'\n    condition: all of selection_*\nfalsepositives:\n    - 'Developer tooling and package managers that call curl'\nlevel: medium",
    "severity": "medium",
    "category": "command-and-control",
    "technique": "T1105",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "curl",
      "download"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-024",
    "type": "sigma",
    "title": "Script Host Executing Script From Download or Temp Location",
    "description": "Detects wscript/cscript running .js, .jse, .vbs, .vbe or .wsf files from Downloads, Temp or archive extraction folders.",
    "code": "title: 'Script Host Executing Script From Download or Temp Location'\nid: 9aa07e3e-901a-52c7-a8fe-7578d6b6de93\nstatus: test\ndescription: 'Detects wscript/cscript running .js, .jse, .vbs, .vbe or .wsf files from Downloads, Temp or archive extraction folders.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.execution\n    - attack.t1059.005\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_img:\n        Image|endswith:\n            - '\\wscript.exe'\n            - '\\cscript.exe'\n    selection_ext:\n        CommandLine|contains:\n            - '.js'\n            - '.jse'\n            - '.vbs'\n            - '.vbe'\n            - '.wsf'\n    selection_path:\n        CommandLine|contains:\n            - '\\Downloads\\'\n            - '\\AppData\\Local\\Temp\\'\n            - '\\Rar$'\n            - '\\7z'\n            - '.zip\\'\n    condition: all of selection_*\nfalsepositives:\n    - 'Login or helpdesk scripts run from Temp by management agents'\nlevel: high",
    "severity": "high",
    "category": "execution",
    "technique": "T1059.005",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "wscript",
      "initial-access",
      "script"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-025",
    "type": "sigma",
    "title": "Office Application Spawning Shell or Script Interpreter",
    "description": "Detects Word, Excel, PowerPoint, Outlook, Access or Publisher starting cmd, PowerShell, script hosts or common LOLBins, typical of malicious macros.",
    "code": "title: 'Office Application Spawning Shell or Script Interpreter'\nid: 576d428a-0a08-5ba0-b7bb-bea12721f1d3\nstatus: test\ndescription: 'Detects Word, Excel, PowerPoint, Outlook, Access or Publisher starting cmd, PowerShell, script hosts or common LOLBins, typical of malicious macros.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.initial-access\n    - attack.t1566.001\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_parent:\n        ParentImage|endswith:\n            - '\\WINWORD.EXE'\n            - '\\EXCEL.EXE'\n            - '\\POWERPNT.EXE'\n            - '\\OUTLOOK.EXE'\n            - '\\MSACCESS.EXE'\n            - '\\MSPUB.EXE'\n            - '\\ONENOTE.EXE'\n    selection_child:\n        Image|endswith:\n            - '\\cmd.exe'\n            - '\\powershell.exe'\n            - '\\pwsh.exe'\n            - '\\wscript.exe'\n            - '\\cscript.exe'\n            - '\\mshta.exe'\n            - '\\regsvr32.exe'\n            - '\\rundll32.exe'\n            - '\\certutil.exe'\n            - '\\bitsadmin.exe'\n            - '\\schtasks.exe'\n            - '\\msiexec.exe'\n    condition: all of selection_*\nfalsepositives:\n    - 'Approved macros or add-ins that call command-line tools'\nlevel: high",
    "severity": "high",
    "category": "initial-access",
    "technique": "T1566.001",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "office",
      "macro",
      "phishing"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-026",
    "type": "sigma",
    "title": "PDF Reader Spawning Command Interpreter",
    "description": "Detects Adobe Reader/Acrobat or Foxit launching cmd, PowerShell or script hosts, indicating a malicious PDF or exploit.",
    "code": "title: 'PDF Reader Spawning Command Interpreter'\nid: a4ca9b79-578f-55f9-923e-373c265bc7be\nstatus: test\ndescription: 'Detects Adobe Reader/Acrobat or Foxit launching cmd, PowerShell or script hosts, indicating a malicious PDF or exploit.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.execution\n    - attack.t1204.002\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_parent:\n        ParentImage|endswith:\n            - '\\AcroRd32.exe'\n            - '\\Acrobat.exe'\n            - '\\FoxitPDFReader.exe'\n            - '\\FoxitReader.exe'\n    selection_child:\n        Image|endswith:\n            - '\\cmd.exe'\n            - '\\powershell.exe'\n            - '\\wscript.exe'\n            - '\\cscript.exe'\n            - '\\mshta.exe'\n            - '\\rundll32.exe'\n    condition: all of selection_*\nfalsepositives:\n    - 'PDF workflows with approved launch actions'\nlevel: high",
    "severity": "high",
    "category": "execution",
    "technique": "T1204.002",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "pdf",
      "exploit"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-027",
    "type": "sigma",
    "title": "Script Interpreter Launched From Mounted ISO or IMG",
    "description": "Detects script hosts, cmd or rundll32 starting with a command line on a mounted disk image letter path that also shows LNK-style launch, a pattern used after ISO/IMG phishing.",
    "code": "title: 'Script Interpreter Launched From Mounted ISO or IMG'\nid: fdd96903-be1f-524f-8ec1-a9b82e9c7ac6\nstatus: test\ndescription: 'Detects script hosts, cmd or rundll32 starting with a command line on a mounted disk image letter path that also shows LNK-style launch, a pattern used after ISO/IMG phishing.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.initial-access\n    - attack.t1553.005\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_parent:\n        ParentImage|endswith: '\\explorer.exe'\n    selection_child:\n        Image|endswith:\n            - '\\cmd.exe'\n            - '\\rundll32.exe'\n            - '\\wscript.exe'\n            - '\\cscript.exe'\n            - '\\mshta.exe'\n    selection_path:\n        CurrentDirectory|re: '^[D-Z]:\\\\$'\n    filter_c:\n        CurrentDirectory|startswith: 'C:\\'\n    condition: all of selection_* and not filter_c\nfalsepositives:\n    - 'Users running tools from USB drives or legitimate mounted software media'\nlevel: medium",
    "severity": "medium",
    "category": "initial-access",
    "technique": "T1553.005",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "iso",
      "img",
      "motw-bypass"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-028",
    "type": "sigma",
    "title": "WmiPrvSE Spawning Shell or PowerShell",
    "description": "Detects WmiPrvSE.exe as the parent of cmd or PowerShell, which is how remote WMI execution and many macro loaders appear.",
    "code": "title: 'WmiPrvSE Spawning Shell or PowerShell'\nid: da25e030-7fa1-5392-9469-25c1462da0b3\nstatus: test\ndescription: 'Detects WmiPrvSE.exe as the parent of cmd or PowerShell, which is how remote WMI execution and many macro loaders appear.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.execution\n    - attack.t1047\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        ParentImage|endswith: '\\WmiPrvSE.exe'\n        Image|endswith:\n            - '\\cmd.exe'\n            - '\\powershell.exe'\n            - '\\pwsh.exe'\n            - '\\mshta.exe'\n            - '\\rundll32.exe'\n    filter_sccm:\n        CommandLine|contains: '\\CCM\\'\n    condition: selection and not filter_sccm\nfalsepositives:\n    - 'Configuration management tools such as SCCM running scripts through WMI'\nlevel: medium",
    "severity": "medium",
    "category": "execution",
    "technique": "T1047",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "wmi",
      "execution"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-029",
    "type": "sigma",
    "title": "PowerShell Web Download Cradle",
    "description": "Detects PowerShell command lines that download and immediately execute content via Net.WebClient, Invoke-WebRequest or Invoke-RestMethod with IEX.",
    "code": "title: 'PowerShell Web Download Cradle'\nid: ae0617f9-bfdd-5093-ab02-07839f5c37d4\nstatus: test\ndescription: 'Detects PowerShell command lines that download and immediately execute content via Net.WebClient, Invoke-WebRequest or Invoke-RestMethod with IEX.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.execution\n    - attack.t1059.001\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_img:\n        Image|endswith:\n            - '\\powershell.exe'\n            - '\\pwsh.exe'\n    selection_dl:\n        CommandLine|contains:\n            - 'DownloadString('\n            - 'DownloadData('\n            - 'Net.WebClient'\n            - 'Invoke-WebRequest'\n            - 'iwr '\n            - 'Invoke-RestMethod'\n            - 'irm '\n            - 'Start-BitsTransfer'\n    selection_exec:\n        CommandLine|contains:\n            - 'IEX'\n            - 'Invoke-Expression'\n            - '| iex'\n            - '|iex'\n    condition: all of selection_*\nfalsepositives:\n    - 'Some installers (for example Chocolatey bootstrap) use this pattern'\nlevel: high",
    "severity": "high",
    "category": "execution",
    "technique": "T1059.001",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "powershell",
      "download-cradle"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-030",
    "type": "sigma",
    "title": "Base64 Encoded IEX or Invoke-Expression in Command Line",
    "description": "Detects UTF-16LE base64 fragments of IEX / Invoke-Expression / DownloadString inside the command line, independent of the -enc flag.",
    "code": "title: 'Base64 Encoded IEX or Invoke-Expression in Command Line'\nid: ad99375c-167b-5ca4-840d-1ce243c78d55\nstatus: test\ndescription: 'Detects UTF-16LE base64 fragments of IEX / Invoke-Expression / DownloadString inside the command line, independent of the -enc flag.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1027\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        CommandLine|contains:\n            - 'SQBFAFgA'\n            - 'SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuA'\n            - 'aQBlAHgA'\n            - 'RABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnA'\n            - 'AE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQA'\n    condition: selection\nfalsepositives:\n    - 'Rare; some RMM tools encode their bootstrap scripts'\nlevel: high",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1027",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "powershell",
      "base64",
      "obfuscation"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-031",
    "type": "sigma",
    "title": "PowerShell Hidden Window With Execution Policy Bypass",
    "description": "Detects PowerShell launched with a hidden window, no profile and execution policy bypass, a combination favoured by loaders.",
    "code": "title: 'PowerShell Hidden Window With Execution Policy Bypass'\nid: 6977ade4-96bd-5984-8451-4e8c37492f18\nstatus: test\ndescription: 'Detects PowerShell launched with a hidden window, no profile and execution policy bypass, a combination favoured by loaders.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.execution\n    - attack.t1059.001\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_img:\n        Image|endswith:\n            - '\\powershell.exe'\n            - '\\pwsh.exe'\n    selection_hidden:\n        CommandLine|contains:\n            - '-w hidden'\n            - '-win hidden'\n            - '-windowstyle hidden'\n            - '-w 1'\n    selection_bypass:\n        CommandLine|contains:\n            - '-ep bypass'\n            - '-exec bypass'\n            - '-executionpolicy bypass'\n            - '-nop'\n    condition: all of selection_*\nfalsepositives:\n    - 'Management agents and logon scripts that run PowerShell hidden'\nlevel: medium",
    "severity": "medium",
    "category": "execution",
    "technique": "T1059.001",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "powershell",
      "hidden"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-032",
    "type": "sigma",
    "title": "Offensive PowerShell Framework Cmdlets in Command Line",
    "description": "Detects well-known function names from PowerSploit, PowerView, Empire and Nishang in a PowerShell command line.",
    "code": "title: 'Offensive PowerShell Framework Cmdlets in Command Line'\nid: ad7d3ca4-908a-5c9e-ad44-286747cf951a\nstatus: test\ndescription: 'Detects well-known function names from PowerSploit, PowerView, Empire and Nishang in a PowerShell command line.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.execution\n    - attack.t1059.001\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        CommandLine|contains:\n            - 'Invoke-Mimikatz'\n            - 'Invoke-Kerberoast'\n            - 'Invoke-ShareFinder'\n            - 'Invoke-UserHunter'\n            - 'Get-DomainUser'\n            - 'Get-NetDomainController'\n            - 'Find-LocalAdminAccess'\n            - 'Invoke-PowerShellTcp'\n            - 'Invoke-ReflectivePEInjection'\n            - 'Invoke-Shellcode'\n            - 'Get-GPPPassword'\n            - 'Invoke-SMBExec'\n            - 'Invoke-WMIExec'\n            - 'Invoke-TheHash'\n    condition: selection\nfalsepositives:\n    - 'Authorised penetration tests and red team exercises'\nlevel: high",
    "severity": "high",
    "category": "execution",
    "technique": "T1059.001",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "powershell",
      "powersploit",
      "offensive-tooling"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-033",
    "type": "sigma",
    "title": "Shadow Storage Resized to Minimum",
    "description": "Detects vssadmin resize shadowstorage with a tiny maxsize, which silently purges existing shadow copies without a delete command.",
    "code": "title: 'Shadow Storage Resized to Minimum'\nid: f8d267a2-98f5-5054-81b0-064b99e07e1c\nstatus: test\ndescription: 'Detects vssadmin resize shadowstorage with a tiny maxsize, which silently purges existing shadow copies without a delete command.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.impact\n    - attack.t1490\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        CommandLine|contains|all:\n            - 'vssadmin'\n            - 'resize'\n            - 'shadowstorage'\n    selection_size:\n        CommandLine|contains:\n            - 'maxsize=401MB'\n            - 'maxsize=320MB'\n            - 'maxsize=1MB'\n    condition: all of selection*\nfalsepositives:\n    - 'Storage administrators tuning shadow storage (rare outside change windows)'\nlevel: high",
    "severity": "high",
    "category": "impact",
    "technique": "T1490",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "ransomware",
      "vss"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-034",
    "type": "sigma",
    "title": "Backup Catalog or System State Backups Deleted With Wbadmin",
    "description": "Detects wbadmin delete catalog / delete systemstatebackup / delete backup, used by ransomware to destroy local backups.",
    "code": "title: 'Backup Catalog or System State Backups Deleted With Wbadmin'\nid: fadff1bf-431c-5864-9a87-af118185ada1\nstatus: test\ndescription: 'Detects wbadmin delete catalog / delete systemstatebackup / delete backup, used by ransomware to destroy local backups.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.impact\n    - attack.t1490\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_img:\n        - Image|endswith: '\\wbadmin.exe'\n        - OriginalFileName: 'WBADMIN.EXE'\n    selection_cli:\n        CommandLine|contains:\n            - 'delete catalog'\n            - 'delete systemstatebackup'\n            - 'delete backup'\n    condition: all of selection_*\nfalsepositives:\n    - 'Backup administrators rotating old Windows Server Backup sets'\nlevel: high",
    "severity": "high",
    "category": "impact",
    "technique": "T1490",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "ransomware",
      "backup"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-035",
    "type": "sigma",
    "title": "Bcdedit Forcing Safe Mode Boot",
    "description": "Detects bcdedit setting safeboot, used by some ransomware to reboot into Safe Mode where EDR agents do not load.",
    "code": "title: 'Bcdedit Forcing Safe Mode Boot'\nid: 26167d11-d451-5af6-8b99-56e392a4e386\nstatus: test\ndescription: 'Detects bcdedit setting safeboot, used by some ransomware to reboot into Safe Mode where EDR agents do not load.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1562.009\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_img:\n        Image|endswith: '\\bcdedit.exe'\n    selection_cli:\n        CommandLine|contains|all:\n            - '/set'\n            - 'safeboot'\n    condition: all of selection_*\nfalsepositives:\n    - 'Helpdesk troubleshooting a broken machine'\nlevel: high",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1562.009",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "ransomware",
      "safe-mode"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-036",
    "type": "sigma",
    "title": "Bcdedit Disabling Integrity Checks or Enabling Test Signing",
    "description": "Detects bcdedit turning on testsigning or nointegritychecks, allowing unsigned kernel drivers to load.",
    "code": "title: 'Bcdedit Disabling Integrity Checks or Enabling Test Signing'\nid: 986392b0-0eb4-5b11-adb5-6209301af83b\nstatus: test\ndescription: 'Detects bcdedit turning on testsigning or nointegritychecks, allowing unsigned kernel drivers to load.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1553.006\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_img:\n        Image|endswith: '\\bcdedit.exe'\n    selection_cli:\n        CommandLine|contains:\n            - 'testsigning on'\n            - 'nointegritychecks on'\n            - 'disable_integrity_checks'\n    condition: all of selection_*\nfalsepositives:\n    - 'Driver developers on test machines'\nlevel: high",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1553.006",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "driver",
      "rootkit"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-037",
    "type": "sigma",
    "title": "Shadow Copies Deleted via PowerShell or CIM",
    "description": "Detects PowerShell removing Win32_ShadowCopy instances, an alternative to vssadmin used by ransomware.",
    "code": "title: 'Shadow Copies Deleted via PowerShell or CIM'\nid: f8454721-4cab-5b48-8026-216dc8074d44\nstatus: test\ndescription: 'Detects PowerShell removing Win32_ShadowCopy instances, an alternative to vssadmin used by ransomware.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.impact\n    - attack.t1490\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        CommandLine|contains: 'Win32_ShadowCopy'\n    selection_del:\n        CommandLine|contains:\n            - 'Delete'\n            - 'Remove-CimInstance'\n            - 'Remove-WmiObject'\n    condition: all of selection*\nfalsepositives:\n    - 'Backup software cleaning its own snapshots (verify parent)'\nlevel: critical",
    "severity": "critical",
    "category": "impact",
    "technique": "T1490",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "ransomware",
      "vss",
      "powershell"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-038",
    "type": "sigma",
    "title": "Mass Stop of Backup, Database or Security Services",
    "description": "Detects net/sc stopping services associated with backups, databases or security tools, commonly done right before encryption.",
    "code": "title: 'Mass Stop of Backup, Database or Security Services'\nid: 8d66941d-bc8c-598e-a402-d034dd265d63\nstatus: test\ndescription: 'Detects net/sc stopping services associated with backups, databases or security tools, commonly done right before encryption.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.impact\n    - attack.t1489\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_img:\n        Image|endswith:\n            - '\\net.exe'\n            - '\\net1.exe'\n            - '\\sc.exe'\n    selection_cmd:\n        CommandLine|contains:\n            - ' stop '\n            - ' config '\n    selection_svc:\n        CommandLine|contains:\n            - 'veeam'\n            - 'backup'\n            - 'MSSQL'\n            - 'SQLWriter'\n            - 'vss'\n            - 'sophos'\n            - 'WinDefend'\n            - 'BackupExec'\n            - 'AcronisAgent'\n    condition: all of selection_*\nfalsepositives:\n    - 'Maintenance windows where admins stop database or backup services'\nlevel: high",
    "severity": "high",
    "category": "impact",
    "technique": "T1489",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "ransomware",
      "service-stop"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-039",
    "type": "sigma",
    "title": "Cipher Wiping Free Disk Space",
    "description": "Detects cipher.exe /w, which overwrites deallocated disk space and hinders recovery of deleted files.",
    "code": "title: 'Cipher Wiping Free Disk Space'\nid: fb62eea7-44ba-531c-bc9c-2476bbe57836\nstatus: test\ndescription: 'Detects cipher.exe /w, which overwrites deallocated disk space and hinders recovery of deleted files.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.impact\n    - attack.t1485\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        Image|endswith: '\\cipher.exe'\n        CommandLine|contains: '/w:'\n    condition: selection\nfalsepositives:\n    - 'Decommissioning procedures for disks'\nlevel: medium",
    "severity": "medium",
    "category": "impact",
    "technique": "T1485",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "wiper",
      "anti-forensics"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-040",
    "type": "sigma",
    "title": "Ransomware-Style Permission Reset With Icacls",
    "description": "Detects icacls granting Everyone full control recursively across a drive, used by ransomware to ensure it can encrypt every file.",
    "code": "title: 'Ransomware-Style Permission Reset With Icacls'\nid: 72d33aaf-d7b5-565e-80c1-d6dd272559bf\nstatus: test\ndescription: 'Detects icacls granting Everyone full control recursively across a drive, used by ransomware to ensure it can encrypt every file.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1222.001\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        Image|endswith: '\\icacls.exe'\n        CommandLine|contains|all:\n            - 'Everyone:'\n            - '/T'\n    selection_perm:\n        CommandLine|contains:\n            - ':F'\n            - ':(F)'\n            - '(OI)(CI)F'\n    condition: all of selection*\nfalsepositives:\n    - 'Mis-scoped permission fixes by administrators'\nlevel: high",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1222.001",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "ransomware",
      "permissions"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-041",
    "type": "sigma",
    "title": "BitLocker Enabled From Command Line With Recovery Password",
    "description": "Detects manage-bde turning on BitLocker with a password protector, a technique used to lock victims out of their own drives.",
    "code": "title: 'BitLocker Enabled From Command Line With Recovery Password'\nid: 3c3d49c7-56c4-582e-bdce-61e54445942e\nstatus: test\ndescription: 'Detects manage-bde turning on BitLocker with a password protector, a technique used to lock victims out of their own drives.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.impact\n    - attack.t1486\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        Image|endswith: '\\manage-bde.exe'\n        CommandLine|contains: '-on'\n    selection_prot:\n        CommandLine|contains:\n            - '-pw'\n            - '-Password'\n            - '-RecoveryPassword'\n    condition: all of selection*\nfalsepositives:\n    - 'Scripted BitLocker rollouts (normally via Intune/MBAM rather than ad-hoc commands)'\nlevel: medium",
    "severity": "medium",
    "category": "impact",
    "technique": "T1486",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "ransomware",
      "bitlocker"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-042",
    "type": "sigma",
    "title": "Procdump Dumping LSASS Memory",
    "description": "Detects Sysinternals ProcDump (or a renamed copy) with -ma and lsass as target.",
    "code": "title: 'Procdump Dumping LSASS Memory'\nid: b0518896-c905-5615-868b-8fd062a93a81\nstatus: test\ndescription: 'Detects Sysinternals ProcDump (or a renamed copy) with -ma and lsass as target.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.credential-access\n    - attack.t1003.001\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_img:\n        - Image|endswith:\n            - '\\procdump.exe'\n            - '\\procdump64.exe'\n        - OriginalFileName: 'procdump'\n    selection_cli:\n        CommandLine|contains: ' -ma '\n    selection_target:\n        CommandLine|contains: 'lsass'\n    condition: all of selection_*\nfalsepositives:\n    - 'Microsoft support cases explicitly requesting an LSASS dump'\nlevel: critical",
    "severity": "critical",
    "category": "credential-access",
    "technique": "T1003.001",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "lsass",
      "procdump"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-043",
    "type": "sigma",
    "title": "LSASS Dump via Comsvcs MiniDump",
    "description": "Detects rundll32 calling comsvcs.dll MiniDump (or ordinal #24) to write a process memory dump, the classic living-off-the-land LSASS dump.",
    "code": "title: 'LSASS Dump via Comsvcs MiniDump'\nid: 6c17a86b-0bc9-51e1-89d5-b1fe99dc3a46\nstatus: test\ndescription: 'Detects rundll32 calling comsvcs.dll MiniDump (or ordinal #24) to write a process memory dump, the classic living-off-the-land LSASS dump.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.credential-access\n    - attack.t1003.001\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_img:\n        Image|endswith: '\\rundll32.exe'\n    selection_dll:\n        CommandLine|contains: 'comsvcs'\n    selection_fn:\n        CommandLine|contains:\n            - 'MiniDump'\n            - '#24'\n            - '#+24'\n    condition: all of selection_*\nfalsepositives:\n    - 'None expected'\nlevel: critical",
    "severity": "critical",
    "category": "credential-access",
    "technique": "T1003.001",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "lsass",
      "comsvcs",
      "lolbin"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-044",
    "type": "sigma",
    "title": "Registry Hive Export of SAM SYSTEM or SECURITY",
    "description": "Detects reg.exe save/export of the SAM, SYSTEM or SECURITY hives, used for offline extraction of local hashes and LSA secrets.",
    "code": "title: 'Registry Hive Export of SAM SYSTEM or SECURITY'\nid: 810dc31a-8239-5c44-a023-0280de5d669b\nstatus: test\ndescription: 'Detects reg.exe save/export of the SAM, SYSTEM or SECURITY hives, used for offline extraction of local hashes and LSA secrets.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.credential-access\n    - attack.t1003.002\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_img:\n        Image|endswith: '\\reg.exe'\n    selection_cmd:\n        CommandLine|contains:\n            - ' save '\n            - ' export '\n    selection_hive:\n        CommandLine|contains:\n            - 'hklm\\sam'\n            - 'hklm\\system'\n            - 'hklm\\security'\n            - 'HKEY_LOCAL_MACHINE\\SAM'\n            - 'HKEY_LOCAL_MACHINE\\SYSTEM'\n            - 'HKEY_LOCAL_MACHINE\\SECURITY'\n    condition: all of selection_*\nfalsepositives:\n    - 'Backup products exporting hives (verify the account and destination)'\nlevel: high",
    "severity": "high",
    "category": "credential-access",
    "technique": "T1003.002",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "sam",
      "hive",
      "credential-dump"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-045",
    "type": "sigma",
    "title": "NTDS.dit Extraction via Ntdsutil IFM",
    "description": "Detects ntdsutil creating an Install From Media snapshot, which copies NTDS.dit and the SYSTEM hive.",
    "code": "title: 'NTDS.dit Extraction via Ntdsutil IFM'\nid: 7d8c1ea3-4083-5494-9cd0-ef50767d09ee\nstatus: test\ndescription: 'Detects ntdsutil creating an Install From Media snapshot, which copies NTDS.dit and the SYSTEM hive.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.credential-access\n    - attack.t1003.003\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        Image|endswith: '\\ntdsutil.exe'\n        CommandLine|contains:\n            - 'ifm'\n            - 'ac i ntds'\n            - 'activate instance ntds'\n    condition: selection\nfalsepositives:\n    - 'Domain controller promotion using IFM media created by administrators'\nlevel: high",
    "severity": "high",
    "category": "credential-access",
    "technique": "T1003.003",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "ntds",
      "active-directory"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-046",
    "type": "sigma",
    "title": "NTDS or SAM Copied From Volume Shadow Copy",
    "description": "Detects command lines copying ntds.dit, SAM or SYSTEM from a HarddiskVolumeShadowCopy device path, or esentutl /vss copies.",
    "code": "title: 'NTDS or SAM Copied From Volume Shadow Copy'\nid: cd657fa8-95c2-5a9d-a7de-b8dc995a4316\nstatus: test\ndescription: 'Detects command lines copying ntds.dit, SAM or SYSTEM from a HarddiskVolumeShadowCopy device path, or esentutl /vss copies.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.credential-access\n    - attack.t1003.003\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_vss:\n        CommandLine|contains: 'HarddiskVolumeShadowCopy'\n    selection_file:\n        CommandLine|contains:\n            - 'ntds.dit'\n            - '\\config\\SAM'\n            - '\\config\\SYSTEM'\n            - '\\config\\SECURITY'\n    selection_esent:\n        Image|endswith: '\\esentutl.exe'\n        CommandLine|contains|all:\n            - '/vss'\n            - '/y'\n    condition: (selection_vss and selection_file) or selection_esent\nfalsepositives:\n    - 'Backup verification scripts (rare)'\nlevel: critical",
    "severity": "critical",
    "category": "credential-access",
    "technique": "T1003.003",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "ntds",
      "vss"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-047",
    "type": "sigma",
    "title": "Diskshadow Executing Script File",
    "description": "Detects diskshadow.exe run with /s script mode, which can create shadow copies to steal NTDS.dit or proxy-execute commands.",
    "code": "title: 'Diskshadow Executing Script File'\nid: 1caf1887-595b-53ef-ba6e-e58461b2209a\nstatus: test\ndescription: 'Detects diskshadow.exe run with /s script mode, which can create shadow copies to steal NTDS.dit or proxy-execute commands.'\nreferences:\n    - https://lolbas-project.github.io/\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.credential-access\n    - attack.t1003.003\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        - Image|endswith: '\\diskshadow.exe'\n        - OriginalFileName: 'diskshadow.exe'\n    selection_cli:\n        CommandLine|contains:\n            - '/s '\n            - '-s '\n    condition: all of selection*\nfalsepositives:\n    - 'Backup administrators scripting shadow copies on servers'\nlevel: high",
    "severity": "high",
    "category": "credential-access",
    "technique": "T1003.003",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "diskshadow",
      "ntds"
    ],
    "references": [
      "https://lolbas-project.github.io/",
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-048",
    "type": "sigma",
    "title": "Mimikatz Command Line Keywords",
    "description": "Detects mimikatz module commands (sekurlsa::, lsadump::, kerberos::) on any process command line, including renamed binaries.",
    "code": "title: 'Mimikatz Command Line Keywords'\nid: 50d56dd7-9ef8-5319-8eec-3aa55689a168\nstatus: test\ndescription: 'Detects mimikatz module commands (sekurlsa::, lsadump::, kerberos::) on any process command line, including renamed binaries.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.credential-access\n    - attack.t1003\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        CommandLine|contains:\n            - 'sekurlsa::'\n            - 'lsadump::'\n            - 'kerberos::golden'\n            - 'kerberos::ptt'\n            - 'privilege::debug'\n            - 'token::elevate'\n            - 'dpapi::'\n            - 'crypto::certificates'\n    condition: selection\nfalsepositives:\n    - 'Authorised penetration testing'\nlevel: critical",
    "severity": "critical",
    "category": "credential-access",
    "technique": "T1003",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "mimikatz"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-049",
    "type": "sigma",
    "title": "Searching Files for Passwords With Findstr",
    "description": "Detects findstr recursively searching for password strings in configuration files, a typical post-compromise credential hunt.",
    "code": "title: 'Searching Files for Passwords With Findstr'\nid: 73f4ec5d-195b-5039-b2d1-bbc708fab1c1\nstatus: test\ndescription: 'Detects findstr recursively searching for password strings in configuration files, a typical post-compromise credential hunt.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.credential-access\n    - attack.t1552.001\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        Image|endswith: '\\findstr.exe'\n        CommandLine|contains:\n            - 'password'\n            - 'passwd'\n            - 'cpassword'\n    selection_recursive:\n        CommandLine|contains:\n            - ' /s'\n            - ' /si'\n            - ' -s'\n    condition: all of selection*\nfalsepositives:\n    - 'Administrators auditing configuration files for embedded secrets'\nlevel: medium",
    "severity": "medium",
    "category": "credential-access",
    "technique": "T1552.001",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "credentials-in-files"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-050",
    "type": "sigma",
    "title": "Credential Manager Vault Enumeration",
    "description": "Detects vaultcmd /listcreds or cmdkey /list being used to enumerate stored Windows credentials.",
    "code": "title: 'Credential Manager Vault Enumeration'\nid: 3d14ae6a-a73d-5ee1-ab34-c0b6ab167da0\nstatus: test\ndescription: 'Detects vaultcmd /listcreds or cmdkey /list being used to enumerate stored Windows credentials.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.credential-access\n    - attack.t1555.004\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_vault:\n        Image|endswith: '\\VaultCmd.exe'\n        CommandLine|contains: '/listcreds:'\n    selection_cmdkey:\n        Image|endswith: '\\cmdkey.exe'\n        CommandLine|contains: '/l'\n    condition: 1 of selection_*\nfalsepositives:\n    - 'Users or helpdesk checking saved credentials'\nlevel: medium",
    "severity": "medium",
    "category": "credential-access",
    "technique": "T1555.004",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "credential-manager"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-051",
    "type": "sigma",
    "title": "Rubeus Kerberos Abuse Command Line",
    "description": "Detects Rubeus-style verbs and arguments for Kerberoasting, AS-REP roasting, ticket requests and pass-the-ticket.",
    "code": "title: 'Rubeus Kerberos Abuse Command Line'\nid: 11550e79-6f9d-5eb7-8bd6-de45a078c70d\nstatus: test\ndescription: 'Detects Rubeus-style verbs and arguments for Kerberoasting, AS-REP roasting, ticket requests and pass-the-ticket.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.credential-access\n    - attack.t1558\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_verb:\n        CommandLine|contains:\n            - ' asreproast '\n            - ' kerberoast '\n            - ' asktgt '\n            - ' asktgs '\n            - ' s4u '\n            - ' ptt '\n            - ' dump /service:krbtgt'\n            - ' tgtdeleg '\n    selection_arg:\n        CommandLine|contains:\n            - '/user:'\n            - '/rc4:'\n            - '/aes256:'\n            - '/impersonateuser:'\n            - '/outfile:'\n            - '/ticket:'\n            - '/nowrap'\n            - '/format:hashcat'\n    condition: all of selection_*\nfalsepositives:\n    - 'Authorised red team activity'\nlevel: high",
    "severity": "high",
    "category": "credential-access",
    "technique": "T1558",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "kerberos",
      "rubeus"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-052",
    "type": "sigma",
    "title": "AD CS Abuse Tool Command Line",
    "description": "Detects Certify or Certipy verbs used to find and request certificates from vulnerable AD CS templates.",
    "code": "title: 'AD CS Abuse Tool Command Line'\nid: dfc0218a-3a8e-5e7b-8510-7dbaf827d07d\nstatus: test\ndescription: 'Detects Certify or Certipy verbs used to find and request certificates from vulnerable AD CS templates.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.credential-access\n    - attack.t1649\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        CommandLine|contains:\n            - 'Certify.exe find /vulnerable'\n            - 'Certify.exe request '\n            - ' /altname:'\n            - 'certipy find '\n            - 'certipy req '\n            - 'certipy auth '\n            - ' -vulnerable '\n    condition: selection\nfalsepositives:\n    - 'PKI assessments by the security team'\nlevel: high",
    "severity": "high",
    "category": "credential-access",
    "technique": "T1649",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "adcs",
      "certificates"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-053",
    "type": "sigma",
    "title": "Whoami Privilege or Group Enumeration",
    "description": "Detects whoami with /all, /priv or /groups, commonly the first command an operator runs after gaining a shell.",
    "code": "title: 'Whoami Privilege or Group Enumeration'\nid: 999c0cb4-7647-509d-9c8f-7e4edf4149ba\nstatus: test\ndescription: 'Detects whoami with /all, /priv or /groups, commonly the first command an operator runs after gaining a shell.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.discovery\n    - attack.t1033\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        Image|endswith: '\\whoami.exe'\n        CommandLine|contains:\n            - '/all'\n            - '/priv'\n            - '/groups'\n            - '-all'\n            - '-priv'\n    condition: selection\nfalsepositives:\n    - 'Administrators and support staff troubleshooting permissions'\nlevel: low",
    "severity": "low",
    "category": "discovery",
    "technique": "T1033",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "discovery",
      "whoami"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-054",
    "type": "sigma",
    "title": "Domain Trust and DC Discovery With Nltest",
    "description": "Detects nltest enumerating domain controllers or domain trusts.",
    "code": "title: 'Domain Trust and DC Discovery With Nltest'\nid: ed20ae0f-2753-5925-adda-c0d6b1ffb6f6\nstatus: test\ndescription: 'Detects nltest enumerating domain controllers or domain trusts.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.discovery\n    - attack.t1482\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        Image|endswith: '\\nltest.exe'\n        CommandLine|contains:\n            - '/dclist'\n            - '/domain_trusts'\n            - '/all_trusts'\n            - '/trusted_domains'\n            - '/dsgetdc'\n    condition: selection\nfalsepositives:\n    - 'Domain administrators verifying trusts'\nlevel: medium",
    "severity": "medium",
    "category": "discovery",
    "technique": "T1482",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "discovery",
      "active-directory"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-055",
    "type": "sigma",
    "title": "Privileged Domain Group Enumeration With Net",
    "description": "Detects net group or net localgroup queries for Domain Admins, Enterprise Admins or local Administrators.",
    "code": "title: 'Privileged Domain Group Enumeration With Net'\nid: af2a52f1-ea1a-5d60-af84-a7a819b0452e\nstatus: test\ndescription: 'Detects net group or net localgroup queries for Domain Admins, Enterprise Admins or local Administrators.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.discovery\n    - attack.t1069.002\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_img:\n        Image|endswith:\n            - '\\net.exe'\n            - '\\net1.exe'\n    selection_cli:\n        CommandLine|contains:\n            - 'domain admins'\n            - 'enterprise admins'\n            - 'schema admins'\n            - 'localgroup administrators'\n    condition: all of selection_*\nfalsepositives:\n    - 'Helpdesk and admin scripts'\nlevel: low",
    "severity": "low",
    "category": "discovery",
    "technique": "T1069.002",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "discovery",
      "net"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-056",
    "type": "sigma",
    "title": "Network Share Discovery With Net View",
    "description": "Detects net view used to list shares or hosts across the domain.",
    "code": "title: 'Network Share Discovery With Net View'\nid: a504d96e-dc39-553f-803c-1d42977ca0d4\nstatus: test\ndescription: 'Detects net view used to list shares or hosts across the domain.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.discovery\n    - attack.t1135\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_img:\n        Image|endswith:\n            - '\\net.exe'\n            - '\\net1.exe'\n    selection_cli:\n        CommandLine|contains:\n            - 'view /all'\n            - 'view /domain'\n            - 'view \\\\'\n    condition: all of selection_*\nfalsepositives:\n    - 'Users browsing file servers from the command line'\nlevel: low",
    "severity": "low",
    "category": "discovery",
    "technique": "T1135",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "discovery",
      "shares"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-057",
    "type": "sigma",
    "title": "AdFind Active Directory Reconnaissance",
    "description": "Detects AdFind command-line filters commonly used by ransomware affiliates to dump computers, users, trusts and subnets.",
    "code": "title: 'AdFind Active Directory Reconnaissance'\nid: eb03e470-829e-5cae-96df-2af12d2ec971\nstatus: test\ndescription: 'Detects AdFind command-line filters commonly used by ransomware affiliates to dump computers, users, trusts and subnets.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.discovery\n    - attack.t1087.002\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        CommandLine|contains:\n            - 'objectcategory=computer'\n            - 'objectcategory=person'\n            - 'objectcategory=subnet'\n            - 'objectcategory=organizationalUnit'\n            - '-gcb -sc trustdmp'\n            - 'trustdmp'\n            - 'dcmodes'\n            - 'domainlist'\n            - '-sc dcdmp'\n    condition: selection\nfalsepositives:\n    - 'Directory administrators using AdFind for reporting'\nlevel: high",
    "severity": "high",
    "category": "discovery",
    "technique": "T1087.002",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "adfind",
      "active-directory",
      "ransomware"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-058",
    "type": "sigma",
    "title": "BloodHound SharpHound Collection Flags",
    "description": "Detects SharpHound or BloodHound-python collection arguments such as -c All or --CollectionMethod.",
    "code": "title: 'BloodHound SharpHound Collection Flags'\nid: 2db560ef-8d3f-5d85-91c2-d1b8b1d39f90\nstatus: test\ndescription: 'Detects SharpHound or BloodHound-python collection arguments such as -c All or --CollectionMethod.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.discovery\n    - attack.t1087.002\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        CommandLine|contains:\n            - ' -c All '\n            - ' --CollectionMethod'\n            - ' --CollectionMethods'\n            - ' -c DCOnly'\n            - ' --ZipFileName '\n            - ' --Loop '\n            - 'Invoke-BloodHound'\n            - 'bloodhound-python'\n    condition: selection\nfalsepositives:\n    - 'Authorised AD security assessments'\nlevel: high",
    "severity": "high",
    "category": "discovery",
    "technique": "T1087.002",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "bloodhound",
      "active-directory"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-059",
    "type": "sigma",
    "title": "Security Product Discovery via SecurityCenter2",
    "description": "Detects queries against root\\SecurityCenter2 (AntiVirusProduct, FirewallProduct) to identify installed security tools.",
    "code": "title: 'Security Product Discovery via SecurityCenter2'\nid: 70060cf8-93ed-551e-9935-a94e26146ea2\nstatus: test\ndescription: 'Detects queries against root\\SecurityCenter2 (AntiVirusProduct, FirewallProduct) to identify installed security tools.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.discovery\n    - attack.t1518.001\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        CommandLine|contains: 'SecurityCenter2'\n    selection_class:\n        CommandLine|contains:\n            - 'AntiVirusProduct'\n            - 'FirewallProduct'\n            - 'AntiSpywareProduct'\n    condition: all of selection*\nfalsepositives:\n    - 'Inventory scripts'\nlevel: low",
    "severity": "low",
    "category": "discovery",
    "technique": "T1518.001",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "discovery",
      "av-discovery"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-060",
    "type": "sigma",
    "title": "Host Reconnaissance Tool Execution",
    "description": "Detects common post-exploitation enumeration tools such as Seatbelt, SharpUp, winPEAS and PrivescCheck by name or arguments.",
    "code": "title: 'Host Reconnaissance Tool Execution'\nid: 0f42e663-50aa-5525-8e0b-5834713708a2\nstatus: test\ndescription: 'Detects common post-exploitation enumeration tools such as Seatbelt, SharpUp, winPEAS and PrivescCheck by name or arguments.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.discovery\n    - attack.t1082\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_img:\n        Image|endswith:\n            - '\\Seatbelt.exe'\n            - '\\SharpUp.exe'\n            - '\\winPEASany.exe'\n            - '\\winPEASx64.exe'\n            - '\\winPEASx86.exe'\n    selection_cli:\n        CommandLine|contains:\n            - 'Invoke-PrivescCheck'\n            - 'Invoke-AllChecks'\n            - ' -group=all'\n            - 'PowerUp.ps1'\n    condition: 1 of selection_*\nfalsepositives:\n    - 'Security team running hardening audits'\nlevel: high",
    "severity": "high",
    "category": "discovery",
    "technique": "T1082",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "privesc",
      "enumeration"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-061",
    "type": "sigma",
    "title": "Process Spawned by PsExec Service",
    "description": "Detects child processes of PSEXESVC.exe on the target host, i.e. remote execution received via PsExec.",
    "code": "title: 'Process Spawned by PsExec Service'\nid: 74784f2b-0618-5e42-8f24-79d23a9af64d\nstatus: test\ndescription: 'Detects child processes of PSEXESVC.exe on the target host, i.e. remote execution received via PsExec.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.lateral-movement\n    - attack.t1569.002\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        ParentImage|endswith: '\\PSEXESVC.exe'\n    condition: selection\nfalsepositives:\n    - 'Administrators legitimately using PsExec'\nlevel: medium",
    "severity": "medium",
    "category": "lateral-movement",
    "technique": "T1569.002",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "psexec",
      "lateral"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-062",
    "type": "sigma",
    "title": "Renamed PsExec Execution",
    "description": "Detects PsExec executed under a different file name, identified via OriginalFileName.",
    "code": "title: 'Renamed PsExec Execution'\nid: b403830e-1a56-59ec-8830-b9e7a59e4dfc\nstatus: test\ndescription: 'Detects PsExec executed under a different file name, identified via OriginalFileName.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1036.003\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        OriginalFileName: 'psexec.c'\n    filter:\n        Image|endswith:\n            - '\\PsExec.exe'\n            - '\\PsExec64.exe'\n    condition: selection and not filter\nfalsepositives:\n    - 'Packaging tools that rename Sysinternals binaries'\nlevel: high",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1036.003",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "psexec",
      "masquerading"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-063",
    "type": "sigma",
    "title": "Impacket WmiExec Output Redirection Pattern",
    "description": "Detects cmd.exe /Q /c with output redirected to \\\\127.0.0.1\\ADMIN$\\__<timestamp>, characteristic of Impacket wmiexec.",
    "code": "title: 'Impacket WmiExec Output Redirection Pattern'\nid: 591bc83a-2ebd-5ef8-ae43-8c18121c653b\nstatus: test\ndescription: 'Detects cmd.exe /Q /c with output redirected to \\\\127.0.0.1\\ADMIN$\\__<timestamp>, characteristic of Impacket wmiexec.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.lateral-movement\n    - attack.t1047\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        ParentImage|endswith: '\\WmiPrvSE.exe'\n        Image|endswith: '\\cmd.exe'\n        CommandLine|contains|all:\n            - '/Q'\n            - '/c'\n            - '\\\\127.0.0.1\\'\n            - '2>&1'\n    condition: selection\nfalsepositives:\n    - 'None expected'\nlevel: high",
    "severity": "high",
    "category": "lateral-movement",
    "technique": "T1047",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "impacket",
      "wmiexec"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-064",
    "type": "sigma",
    "title": "Impacket SmbExec or AtExec Command Pattern",
    "description": "Detects service or task command lines that echo commands into a batch file and write output to ADMIN$ or C$, as done by Impacket smbexec/atexec.",
    "code": "title: 'Impacket SmbExec or AtExec Command Pattern'\nid: b6b1ce43-01de-51db-9b92-cc8916f59449\nstatus: test\ndescription: 'Detects service or task command lines that echo commands into a batch file and write output to ADMIN$ or C$, as done by Impacket smbexec/atexec.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.lateral-movement\n    - attack.t1569.002\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_smb:\n        CommandLine|contains|all:\n            - 'cmd.exe /Q /c echo'\n            - '\\\\%COMPUTERNAME%\\C$\\'\n    selection_out:\n        CommandLine|contains|all:\n            - 'cmd.exe /C '\n            - 'Windows\\Temp\\'\n            - '.tmp 2>&1'\n    condition: 1 of selection_*\nfalsepositives:\n    - 'None expected'\nlevel: high",
    "severity": "high",
    "category": "lateral-movement",
    "technique": "T1569.002",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "impacket",
      "smbexec",
      "atexec"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-065",
    "type": "sigma",
    "title": "Shell Spawned by WinRM Remote Session Host",
    "description": "Detects wsmprovhost.exe spawning cmd or PowerShell, i.e. commands received over WinRM / PowerShell Remoting.",
    "code": "title: 'Shell Spawned by WinRM Remote Session Host'\nid: d52aa2e6-e592-5b4d-8531-1254573e73ed\nstatus: test\ndescription: 'Detects wsmprovhost.exe spawning cmd or PowerShell, i.e. commands received over WinRM / PowerShell Remoting.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.lateral-movement\n    - attack.t1021.006\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        ParentImage|endswith: '\\wsmprovhost.exe'\n        Image|endswith:\n            - '\\cmd.exe'\n            - '\\powershell.exe'\n            - '\\whoami.exe'\n            - '\\net.exe'\n            - '\\rundll32.exe'\n    condition: selection\nfalsepositives:\n    - 'Remote administration via PowerShell Remoting'\nlevel: medium",
    "severity": "medium",
    "category": "lateral-movement",
    "technique": "T1021.006",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "winrm",
      "lateral"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-066",
    "type": "sigma",
    "title": "Scheduled Task Created on Remote Host",
    "description": "Detects schtasks /create with /s targeting another computer.",
    "code": "title: 'Scheduled Task Created on Remote Host'\nid: 5ece6140-1f3d-59f9-9bb0-197250d0a550\nstatus: test\ndescription: 'Detects schtasks /create with /s targeting another computer.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.lateral-movement\n    - attack.t1053.005\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        Image|endswith: '\\schtasks.exe'\n        CommandLine|contains|all:\n            - '/create'\n            - '/s '\n    condition: selection\nfalsepositives:\n    - 'Administrative deployment scripts'\nlevel: medium",
    "severity": "medium",
    "category": "lateral-movement",
    "technique": "T1053.005",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "schtasks",
      "lateral"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-067",
    "type": "sigma",
    "title": "DCOM MMC20 Spawning Command Shell",
    "description": "Detects mmc.exe started with -Embedding launching cmd or PowerShell, the MMC20.Application DCOM lateral movement technique.",
    "code": "title: 'DCOM MMC20 Spawning Command Shell'\nid: bbfd58f2-83d3-55b4-ae70-60a0d4bdf1ce\nstatus: test\ndescription: 'Detects mmc.exe started with -Embedding launching cmd or PowerShell, the MMC20.Application DCOM lateral movement technique.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.lateral-movement\n    - attack.t1021.003\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        ParentImage|endswith: '\\mmc.exe'\n        ParentCommandLine|contains: '-Embedding'\n        Image|endswith:\n            - '\\cmd.exe'\n            - '\\powershell.exe'\n            - '\\pwsh.exe'\n    condition: selection\nfalsepositives:\n    - 'None expected'\nlevel: high",
    "severity": "high",
    "category": "lateral-movement",
    "technique": "T1021.003",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "dcom",
      "lateral"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-068",
    "type": "sigma",
    "title": "Run Key Added With Reg.exe",
    "description": "Detects reg.exe add writing to a Run or RunOnce key, especially where the value points to scripts or user-writable paths.",
    "code": "title: 'Run Key Added With Reg.exe'\nid: 4443f8f5-e65a-5789-8fe1-ee8624a16ff8\nstatus: test\ndescription: 'Detects reg.exe add writing to a Run or RunOnce key, especially where the value points to scripts or user-writable paths.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1547.001\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_img:\n        Image|endswith: '\\reg.exe'\n    selection_cli:\n        CommandLine|contains|all:\n            - ' add '\n            - '\\CurrentVersion\\Run'\n    selection_val:\n        CommandLine|contains:\n            - 'powershell'\n            - 'mshta'\n            - 'rundll32'\n            - 'wscript'\n            - '\\AppData\\'\n            - '\\Temp\\'\n            - '\\Users\\Public\\'\n    condition: all of selection_*\nfalsepositives:\n    - 'Software installers using reg.exe in post-install scripts'\nlevel: high",
    "severity": "high",
    "category": "persistence",
    "technique": "T1547.001",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "run-key",
      "registry"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-069",
    "type": "sigma",
    "title": "Scheduled Task Created With Script or User-Writable Payload",
    "description": "Detects schtasks /create where the task action runs a script interpreter or a binary in a user-writable location.",
    "code": "title: 'Scheduled Task Created With Script or User-Writable Payload'\nid: 01db5f16-7b3c-567b-974a-56d637f6d5c1\nstatus: test\ndescription: 'Detects schtasks /create where the task action runs a script interpreter or a binary in a user-writable location.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1053.005\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_img:\n        Image|endswith: '\\schtasks.exe'\n    selection_create:\n        CommandLine|contains: '/create'\n    selection_action:\n        CommandLine|contains:\n            - 'powershell'\n            - 'mshta'\n            - 'wscript'\n            - 'cscript'\n            - 'rundll32'\n            - 'regsvr32'\n            - '\\AppData\\'\n            - '\\Users\\Public\\'\n            - '\\ProgramData\\'\n            - '%TEMP%'\n    condition: all of selection_*\nfalsepositives:\n    - 'Software that registers updater tasks under ProgramData'\nlevel: medium",
    "severity": "medium",
    "category": "persistence",
    "technique": "T1053.005",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "schtasks",
      "persistence"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-070",
    "type": "sigma",
    "title": "Service Created With Suspicious Binary Path",
    "description": "Detects sc.exe create/config with a binPath using cmd /c, PowerShell or a user-writable directory.",
    "code": "title: 'Service Created With Suspicious Binary Path'\nid: 502250ab-346b-5cb9-ac94-e9a4aa62d31f\nstatus: test\ndescription: 'Detects sc.exe create/config with a binPath using cmd /c, PowerShell or a user-writable directory.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1543.003\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_img:\n        Image|endswith: '\\sc.exe'\n    selection_cmd:\n        CommandLine|contains:\n            - ' create '\n            - ' config '\n    selection_bin:\n        CommandLine|contains|all:\n            - 'binPath'\n    selection_val:\n        CommandLine|contains:\n            - 'cmd /c'\n            - 'cmd.exe /c'\n            - 'powershell'\n            - '\\AppData\\'\n            - '\\Users\\Public\\'\n            - '\\Temp\\'\n    condition: all of selection_*\nfalsepositives:\n    - 'Poorly packaged software installing services from Temp'\nlevel: high",
    "severity": "high",
    "category": "persistence",
    "technique": "T1543.003",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "service",
      "persistence"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-071",
    "type": "sigma",
    "title": "WMI Event Subscription Created From Command Line",
    "description": "Detects creation of WMI __EventFilter, CommandLineEventConsumer or ActiveScriptEventConsumer objects via wmic or PowerShell.",
    "code": "title: 'WMI Event Subscription Created From Command Line'\nid: 0cbeb6a3-835b-58a5-b650-5b453b824d3a\nstatus: test\ndescription: 'Detects creation of WMI __EventFilter, CommandLineEventConsumer or ActiveScriptEventConsumer objects via wmic or PowerShell.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1546.003\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        CommandLine|contains:\n            - '__EventFilter'\n            - 'CommandLineEventConsumer'\n            - 'ActiveScriptEventConsumer'\n            - '__FilterToConsumerBinding'\n    selection_action:\n        CommandLine|contains:\n            - 'create'\n            - 'Set-WmiInstance'\n            - 'New-CimInstance'\n            - 'New-Object'\n    condition: all of selection*\nfalsepositives:\n    - 'Monitoring agents that register WMI consumers (rare)'\nlevel: high",
    "severity": "high",
    "category": "persistence",
    "technique": "T1546.003",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "wmi",
      "persistence"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-072",
    "type": "sigma",
    "title": "Local User Account Created With Net",
    "description": "Detects net user /add creating a new local account.",
    "code": "title: 'Local User Account Created With Net'\nid: 0cf6b576-f103-5b20-ab1b-33fbffb8ad31\nstatus: test\ndescription: 'Detects net user /add creating a new local account.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1136.001\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_img:\n        Image|endswith:\n            - '\\net.exe'\n            - '\\net1.exe'\n    selection_cli:\n        CommandLine|contains|all:\n            - 'user'\n            - '/add'\n    condition: all of selection_*\nfalsepositives:\n    - 'Administrators provisioning local accounts'\nlevel: medium",
    "severity": "medium",
    "category": "persistence",
    "technique": "T1136.001",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "account-creation"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-073",
    "type": "sigma",
    "title": "Account Hidden From Logon Screen via SpecialAccounts",
    "description": "Detects reg.exe adding a value under Winlogon\\SpecialAccounts\\UserList to hide a local account from the logon UI.",
    "code": "title: 'Account Hidden From Logon Screen via SpecialAccounts'\nid: 91187253-85c5-57c9-9d58-faea6e478331\nstatus: test\ndescription: 'Detects reg.exe adding a value under Winlogon\\SpecialAccounts\\UserList to hide a local account from the logon UI.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1564.002\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        Image|endswith: '\\reg.exe'\n        CommandLine|contains|all:\n            - 'add'\n            - '\\Winlogon\\SpecialAccounts\\UserList'\n    condition: selection\nfalsepositives:\n    - 'Kiosk or service account configuration'\nlevel: high",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1564.002",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "hidden-user"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-074",
    "type": "sigma",
    "title": "Accessibility Feature Debugger Hijack",
    "description": "Detects reg.exe setting a Debugger for sethc, utilman, osk, narrator or magnify under Image File Execution Options (sticky keys backdoor).",
    "code": "title: 'Accessibility Feature Debugger Hijack'\nid: 32dd9d2d-6263-5c87-85d2-80f59ae93a90\nstatus: test\ndescription: 'Detects reg.exe setting a Debugger for sethc, utilman, osk, narrator or magnify under Image File Execution Options (sticky keys backdoor).'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1546.008\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        CommandLine|contains|all:\n            - 'Image File Execution Options'\n            - 'Debugger'\n    selection_target:\n        CommandLine|contains:\n            - 'sethc.exe'\n            - 'utilman.exe'\n            - 'osk.exe'\n            - 'narrator.exe'\n            - 'magnify.exe'\n            - 'DisplaySwitch.exe'\n            - 'AtBroker.exe'\n    condition: all of selection*\nfalsepositives:\n    - 'None expected'\nlevel: critical",
    "severity": "critical",
    "category": "persistence",
    "technique": "T1546.008",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "sticky-keys",
      "ifeo"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-075",
    "type": "sigma",
    "title": "RDP Enabled via Registry Change",
    "description": "Detects reg.exe or PowerShell setting fDenyTSConnections to 0, enabling Remote Desktop.",
    "code": "title: 'RDP Enabled via Registry Change'\nid: 37f16311-b7bf-5e4f-9bca-ddaa8ffa14d0\nstatus: test\ndescription: 'Detects reg.exe or PowerShell setting fDenyTSConnections to 0, enabling Remote Desktop.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.lateral-movement\n    - attack.t1021.001\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        CommandLine|contains: 'fDenyTSConnections'\n    selection_val:\n        CommandLine|contains:\n            - '/d 0'\n            - '-Value 0'\n    condition: all of selection*\nfalsepositives:\n    - 'Administrators enabling RDP for support'\nlevel: medium",
    "severity": "medium",
    "category": "lateral-movement",
    "technique": "T1021.001",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "rdp"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-076",
    "type": "sigma",
    "title": "Defender Exclusion or Protection Disabled via PowerShell",
    "description": "Detects Set-MpPreference / Add-MpPreference adding exclusions or disabling real-time, behaviour or IOAV protection.",
    "code": "title: 'Defender Exclusion or Protection Disabled via PowerShell'\nid: 182ac2ac-5cf7-5101-a06c-f9ef77ec741b\nstatus: test\ndescription: 'Detects Set-MpPreference / Add-MpPreference adding exclusions or disabling real-time, behaviour or IOAV protection.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1562.001\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_cmd:\n        CommandLine|contains:\n            - 'Add-MpPreference'\n            - 'Set-MpPreference'\n    selection_opt:\n        CommandLine|contains:\n            - '-ExclusionPath'\n            - '-ExclusionProcess'\n            - '-ExclusionExtension'\n            - '-DisableRealtimeMonitoring'\n            - '-DisableBehaviorMonitoring'\n            - '-DisableIOAVProtection'\n            - '-DisableScriptScanning'\n            - '-DisableBlockAtFirstSeen'\n    condition: all of selection_*\nfalsepositives:\n    - 'Approved exclusions applied by IT through scripts (should normally come from policy)'\nlevel: high",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1562.001",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "defender",
      "exclusion"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-077",
    "type": "sigma",
    "title": "AMSI Bypass Strings in Command Line",
    "description": "Detects well-known AMSI bypass markers such as amsiInitFailed, AmsiUtils reflection or AmsiScanBuffer patching in a command line.",
    "code": "title: 'AMSI Bypass Strings in Command Line'\nid: a97a37c2-c0ed-5fdf-a4b2-f4dc40fa9ba4\nstatus: test\ndescription: 'Detects well-known AMSI bypass markers such as amsiInitFailed, AmsiUtils reflection or AmsiScanBuffer patching in a command line.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1562.001\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        CommandLine|contains:\n            - 'amsiInitFailed'\n            - 'System.Management.Automation.AmsiUtils'\n            - 'AmsiScanBuffer'\n            - 'amsiContext'\n            - 'AmsiOpenSession'\n    condition: selection\nfalsepositives:\n    - 'Security research and testing'\nlevel: high",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1562.001",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "amsi",
      "bypass"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-078",
    "type": "sigma",
    "title": "Event Log Cleared With Wevtutil or PowerShell",
    "description": "Detects wevtutil cl / clear-log and Clear-EventLog / Remove-EventLog used to wipe Windows event logs.",
    "code": "title: 'Event Log Cleared With Wevtutil or PowerShell'\nid: b30fe90c-be21-5aae-a0dd-37794a252a49\nstatus: test\ndescription: 'Detects wevtutil cl / clear-log and Clear-EventLog / Remove-EventLog used to wipe Windows event logs.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1070.001\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_wevt:\n        Image|endswith: '\\wevtutil.exe'\n        CommandLine|contains:\n            - ' cl '\n            - ' clear-log '\n    selection_ps:\n        CommandLine|contains:\n            - 'Clear-EventLog'\n            - 'Remove-EventLog'\n            - 'Limit-EventLog'\n            - '[System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog'\n    condition: 1 of selection_*\nfalsepositives:\n    - 'Imaging or decommissioning procedures'\nlevel: high",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1070.001",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "log-clearing",
      "anti-forensics"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-079",
    "type": "sigma",
    "title": "USN Journal Deleted With Fsutil",
    "description": "Detects fsutil usn deletejournal, which destroys the NTFS change journal used in forensic timelines.",
    "code": "title: 'USN Journal Deleted With Fsutil'\nid: 765df4a6-12ff-5e40-bdb5-6a0efe11a778\nstatus: test\ndescription: 'Detects fsutil usn deletejournal, which destroys the NTFS change journal used in forensic timelines.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1070\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        Image|endswith: '\\fsutil.exe'\n        CommandLine|contains|all:\n            - 'usn'\n            - 'deletejournal'\n    condition: selection\nfalsepositives:\n    - 'Disk maintenance tools (rare)'\nlevel: high",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1070",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "anti-forensics",
      "usn"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-080",
    "type": "sigma",
    "title": "File Timestamp Modification via PowerShell",
    "description": "Detects PowerShell setting CreationTime, LastWriteTime or LastAccessTime on file objects, a timestomping technique.",
    "code": "title: 'File Timestamp Modification via PowerShell'\nid: 45d01e66-6f4c-5b42-8046-87dc7d877f41\nstatus: test\ndescription: 'Detects PowerShell setting CreationTime, LastWriteTime or LastAccessTime on file objects, a timestomping technique.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1070.006\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        Image|endswith:\n            - '\\powershell.exe'\n            - '\\pwsh.exe'\n        CommandLine|contains:\n            - '.CreationTime ='\n            - '.LastWriteTime ='\n            - '.LastAccessTime ='\n            - '.CreationTime='\n            - '.LastWriteTime='\n    condition: selection\nfalsepositives:\n    - 'Backup or sync scripts that preserve timestamps'\nlevel: medium",
    "severity": "medium",
    "category": "defense-evasion",
    "technique": "T1070.006",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "timestomp",
      "anti-forensics"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-081",
    "type": "sigma",
    "title": "System Process Name Running From Unexpected Path",
    "description": "Detects processes named svchost, lsass, csrss, services, smss, winlogon or wininit running outside System32/SysWOW64, a classic masquerade.",
    "code": "title: 'System Process Name Running From Unexpected Path'\nid: 0e4b91ea-a971-57d7-8f28-b3c5cd1d009d\nstatus: test\ndescription: 'Detects processes named svchost, lsass, csrss, services, smss, winlogon or wininit running outside System32/SysWOW64, a classic masquerade.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1036.005\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        Image|endswith:\n            - '\\svchost.exe'\n            - '\\lsass.exe'\n            - '\\csrss.exe'\n            - '\\services.exe'\n            - '\\smss.exe'\n            - '\\winlogon.exe'\n            - '\\wininit.exe'\n            - '\\lsm.exe'\n    filter:\n        Image|startswith:\n            - 'C:\\Windows\\System32\\'\n            - 'C:\\Windows\\SysWOW64\\'\n            - 'C:\\Windows\\WinSxS\\'\n            - '\\SystemRoot\\System32\\'\n    condition: selection and not filter\nfalsepositives:\n    - 'Non-standard Windows installation drive or directory'\nlevel: high",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1036.005",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "masquerading"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-082",
    "type": "sigma",
    "title": "Executable With Double Extension",
    "description": "Detects processes whose image name uses a document-like double extension such as .pdf.exe or .docx.scr.",
    "code": "title: 'Executable With Double Extension'\nid: 0771335a-40a6-58a6-8108-91c05c2b9ae5\nstatus: test\ndescription: 'Detects processes whose image name uses a document-like double extension such as .pdf.exe or .docx.scr.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1036.007\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        Image|endswith:\n            - '.pdf.exe'\n            - '.doc.exe'\n            - '.docx.exe'\n            - '.xls.exe'\n            - '.xlsx.exe'\n            - '.jpg.exe'\n            - '.png.exe'\n            - '.txt.exe'\n            - '.pdf.scr'\n            - '.doc.scr'\n            - '.zip.exe'\n            - '.mp4.exe'\n    condition: selection\nfalsepositives:\n    - 'None expected'\nlevel: high",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1036.007",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "masquerading",
      "double-extension"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-083",
    "type": "sigma",
    "title": "Execution From Recycle Bin or PerfLogs",
    "description": "Detects processes launched from $Recycle.Bin, C:\\PerfLogs or System Volume Information, locations attackers use to hide tools.",
    "code": "title: 'Execution From Recycle Bin or PerfLogs'\nid: 2b790cf4-7399-56d2-b5bb-f36f7c612877\nstatus: test\ndescription: 'Detects processes launched from $Recycle.Bin, C:\\PerfLogs or System Volume Information, locations attackers use to hide tools.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1036.005\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        Image|contains:\n            - '\\$Recycle.Bin\\'\n            - ':\\PerfLogs\\'\n            - '\\System Volume Information\\'\n    condition: selection\nfalsepositives:\n    - 'None expected'\nlevel: high",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1036.005",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "masquerading",
      "staging"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-084",
    "type": "sigma",
    "title": "Firewall Disabled or Port Proxy Added With Netsh",
    "description": "Detects netsh turning off Windows Firewall profiles or creating a portproxy relay.",
    "code": "title: 'Firewall Disabled or Port Proxy Added With Netsh'\nid: 55a75bdf-10a6-58d7-9e57-d108c518e2ae\nstatus: test\ndescription: 'Detects netsh turning off Windows Firewall profiles or creating a portproxy relay.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1562.004\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_img:\n        Image|endswith: '\\netsh.exe'\n    selection_off:\n        CommandLine|contains:\n            - 'state off'\n            - 'opmode disable'\n            - 'opmode mode=disable'\n    selection_proxy:\n        CommandLine|contains|all:\n            - 'portproxy'\n            - 'add'\n    condition: selection_img and (selection_off or selection_proxy)\nfalsepositives:\n    - 'Administrators troubleshooting connectivity'\n    - 'Port forwarding used by WSL or dev tooling'\nlevel: medium",
    "severity": "medium",
    "category": "defense-evasion",
    "technique": "T1562.004",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "firewall",
      "netsh",
      "tunnel"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-085",
    "type": "sigma",
    "title": "Defender Disabled via Registry or Service Commands",
    "description": "Detects reg.exe/PowerShell setting DisableAntiSpyware or DisableRealtimeMonitoring, or sc stop/config of WinDefend.",
    "code": "title: 'Defender Disabled via Registry or Service Commands'\nid: 0315ce18-f077-5eb2-a6cd-f6ea53f348a6\nstatus: test\ndescription: 'Detects reg.exe/PowerShell setting DisableAntiSpyware or DisableRealtimeMonitoring, or sc stop/config of WinDefend.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1562.001\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_reg:\n        CommandLine|contains:\n            - 'DisableAntiSpyware'\n            - 'DisableRealtimeMonitoring'\n            - 'DisableAntiVirus'\n    selection_sc:\n        Image|endswith: '\\sc.exe'\n        CommandLine|contains: 'WinDefend'\n        CommandLine|contains|windash:\n            - ' stop'\n            - ' config'\n            - ' delete'\n    condition: 1 of selection_*\nfalsepositives:\n    - 'Deployment of third-party AV that disables Defender'\nlevel: high",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1562.001",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "defender",
      "tamper"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-086",
    "type": "sigma",
    "title": "Self-Deleting Binary via Ping Delay",
    "description": "Detects cmd.exe chains like 'ping 127.0.0.1 -n X & del' used by malware to delete itself after execution.",
    "code": "title: 'Self-Deleting Binary via Ping Delay'\nid: 476099b2-e9d1-5d70-b8ea-baa5e937284f\nstatus: test\ndescription: 'Detects cmd.exe chains like ''ping 127.0.0.1 -n X & del'' used by malware to delete itself after execution.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1070.004\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        Image|endswith: '\\cmd.exe'\n        CommandLine|contains|all:\n            - 'ping'\n            - '127.0.0.1'\n            - 'del '\n    selection_n:\n        CommandLine|contains:\n            - ' -n '\n            - ' /n '\n    condition: all of selection*\nfalsepositives:\n    - 'Some uninstallers use the same trick'\nlevel: medium",
    "severity": "medium",
    "category": "defense-evasion",
    "technique": "T1070.004",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "self-delete"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-087",
    "type": "sigma",
    "title": "Rclone Used to Copy Data to Cloud Storage",
    "description": "Detects rclone (or a renamed copy) with copy/sync verbs and remote targets typically used for bulk data theft.",
    "code": "title: 'Rclone Used to Copy Data to Cloud Storage'\nid: 1dedab43-a93e-51b6-ab73-b22d0f908de0\nstatus: test\ndescription: 'Detects rclone (or a renamed copy) with copy/sync verbs and remote targets typically used for bulk data theft.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.exfiltration\n    - attack.t1567.002\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_img:\n        - Image|endswith: '\\rclone.exe'\n        - Description: 'Rsync for cloud storage'\n    selection_cli:\n        CommandLine|contains:\n            - ' copy '\n            - ' sync '\n            - ' --config '\n            - 'mega:'\n            - 'ftp:'\n            - ' --no-check-certificate'\n            - ' --transfers '\n    condition: all of selection_*\nfalsepositives:\n    - 'IT teams using rclone for sanctioned backups'\nlevel: high",
    "severity": "high",
    "category": "exfiltration",
    "technique": "T1567.002",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "rclone",
      "exfiltration"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-088",
    "type": "sigma",
    "title": "Password-Protected Archive Creation for Staging",
    "description": "Detects 7-Zip or WinRAR creating encrypted archives (-p / -hp) which attackers use to stage stolen data.",
    "code": "title: 'Password-Protected Archive Creation for Staging'\nid: 5382a35b-4840-5e99-8df7-0b0c48fde41e\nstatus: test\ndescription: 'Detects 7-Zip or WinRAR creating encrypted archives (-p / -hp) which attackers use to stage stolen data.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.collection\n    - attack.t1560.001\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_img:\n        Image|endswith:\n            - '\\7z.exe'\n            - '\\7za.exe'\n            - '\\7zr.exe'\n            - '\\rar.exe'\n            - '\\WinRAR.exe'\n    selection_add:\n        CommandLine|contains:\n            - ' a '\n            - ' a -'\n    selection_pw:\n        CommandLine|contains:\n            - ' -p'\n            - ' -hp'\n    condition: all of selection_*\nfalsepositives:\n    - 'Users encrypting archives for legitimate transfer'\nlevel: medium",
    "severity": "medium",
    "category": "collection",
    "technique": "T1560.001",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "archive",
      "staging"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-089",
    "type": "sigma",
    "title": "Tunnelling Tool Execution (ngrok, cloudflared, chisel)",
    "description": "Detects common reverse-tunnel tools by name or arguments, used to expose internal services to the attacker.",
    "code": "title: 'Tunnelling Tool Execution (ngrok, cloudflared, chisel)'\nid: 2f0f5324-5a08-54d4-828b-c720a0e0fa8a\nstatus: test\ndescription: 'Detects common reverse-tunnel tools by name or arguments, used to expose internal services to the attacker.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.command-and-control\n    - attack.t1572\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_img:\n        Image|endswith:\n            - '\\ngrok.exe'\n            - '\\cloudflared.exe'\n            - '\\chisel.exe'\n            - '\\plink.exe'\n    selection_cli:\n        CommandLine|contains:\n            - ' tcp 3389'\n            - ' tunnel --url '\n            - ' client --fingerprint'\n            - ' R:socks'\n            - ' -R '\n            - 'authtoken '\n    condition: all of selection_*\nfalsepositives:\n    - 'Developers sharing local services'\n    - 'Sanctioned Cloudflare Tunnel deployments'\nlevel: high",
    "severity": "high",
    "category": "command-and-control",
    "technique": "T1572",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "tunnel",
      "ngrok",
      "chisel"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-090",
    "type": "sigma",
    "title": "Remote Access Software Silent Installation",
    "description": "Detects silent installation switches for AnyDesk, ScreenConnect, Atera, Splashtop or TeamViewer, often used by intruders for persistent access.",
    "code": "title: 'Remote Access Software Silent Installation'\nid: 6efcfdf3-9a08-5dcd-9d93-2cfd92d77b76\nstatus: test\ndescription: 'Detects silent installation switches for AnyDesk, ScreenConnect, Atera, Splashtop or TeamViewer, often used by intruders for persistent access.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.command-and-control\n    - attack.t1219\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_anydesk:\n        CommandLine|contains|all:\n            - 'anydesk'\n            - '--install'\n            - '--silent'\n    selection_pw:\n        CommandLine|contains: '--set-password'\n    selection_sc:\n        CommandLine|contains:\n            - 'ScreenConnect.ClientSetup'\n            - 'AteraAgent'\n            - 'TeamViewer_Host'\n    selection_quiet:\n        CommandLine|contains:\n            - '/qn'\n            - '/S '\n            - '--silent'\n    condition: selection_anydesk or selection_pw or (selection_sc and selection_quiet)\nfalsepositives:\n    - 'Approved RMM deployments by IT'\nlevel: medium",
    "severity": "medium",
    "category": "command-and-control",
    "technique": "T1219",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "rmm",
      "remote-access"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-091",
    "type": "sigma",
    "title": "Explorer RunMRU Entry With Script Command (ClickFix)",
    "description": "Detects RunMRU registry values containing PowerShell, mshta or curl, left behind when a user pastes a ClickFix command into the Run dialog.",
    "code": "title: 'Explorer RunMRU Entry With Script Command (ClickFix)'\nid: ebf624ee-9fe2-5a46-87b7-9adbcdf3392d\nstatus: test\ndescription: 'Detects RunMRU registry values containing PowerShell, mshta or curl, left behind when a user pastes a ClickFix command into the Run dialog.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.execution\n    - attack.t1204.004\nlogsource:\n    category: registry_set\n    product: windows\ndetection:\n    selection:\n        TargetObject|contains: '\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU\\'\n    selection_cmd:\n        Details|contains:\n            - 'powershell'\n            - 'mshta'\n            - 'curl'\n            - 'iex'\n            - 'http'\n            - 'cmd /c'\n    condition: all of selection*\nfalsepositives:\n    - 'Power users launching PowerShell from the Run dialog'\nlevel: high",
    "severity": "high",
    "category": "execution",
    "technique": "T1204.004",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "clickfix",
      "fakecaptcha"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-092",
    "type": "sigma",
    "title": "RDP Logon From Public IP Address",
    "description": "Detects successful RemoteInteractive (type 10) logons whose source address is not in private ranges, i.e. RDP exposed to the internet.",
    "code": "title: 'RDP Logon From Public IP Address'\nid: 3157f372-3fe4-59bf-b4ee-a03bb8557963\nstatus: test\ndescription: 'Detects successful RemoteInteractive (type 10) logons whose source address is not in private ranges, i.e. RDP exposed to the internet.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.initial-access\n    - attack.t1133\nlogsource:\n    product: windows\n    service: security\ndetection:\n    selection:\n        EventID: 4624\n        LogonType: 10\n    filter_private:\n        IpAddress|cidr:\n            - '10.0.0.0/8'\n            - '172.16.0.0/12'\n            - '192.168.0.0/16'\n            - '127.0.0.0/8'\n            - '::1/128'\n            - 'fe80::/10'\n            - 'fc00::/7'\n    filter_empty:\n        IpAddress: '-'\n    condition: selection and not 1 of filter_*\nfalsepositives:\n    - 'Remote workers with sanctioned direct RDP'\n    - 'VPN concentrators that do not NAT'\nlevel: high",
    "severity": "high",
    "category": "initial-access",
    "technique": "T1133",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "rdp",
      "external-remote-services"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-093",
    "type": "sigma",
    "title": "Pass-the-Hash Style NTLM Network Logon",
    "description": "Detects 4624 type 3 NTLM logons with KeyLength 0 and a NULL subject SID, the profile produced by pass-the-hash tools.",
    "code": "title: 'Pass-the-Hash Style NTLM Network Logon'\nid: 03353088-4fa9-55e7-9258-328f2e95bd81\nstatus: test\ndescription: 'Detects 4624 type 3 NTLM logons with KeyLength 0 and a NULL subject SID, the profile produced by pass-the-hash tools.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.lateral-movement\n    - attack.t1550.002\nlogsource:\n    product: windows\n    service: security\ndetection:\n    selection:\n        EventID: 4624\n        LogonType: 3\n        LogonProcessName: 'NtLmSsp'\n        KeyLength: 0\n        SubjectUserSid: 'S-1-0-0'\n    filter_anon:\n        TargetUserName: 'ANONYMOUS LOGON'\n    condition: selection and not filter_anon\nfalsepositives:\n    - 'Legacy applications that use NTLM without session security'\nlevel: medium",
    "severity": "medium",
    "category": "lateral-movement",
    "technique": "T1550.002",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "pass-the-hash",
      "ntlm"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-094",
    "type": "sigma",
    "title": "Overpass-the-Hash Logon With seclogo",
    "description": "Detects logon type 9 (NewCredentials) via seclogo with Negotiate, which is how sekurlsa::pth and runas /netonly style token creation appear.",
    "code": "title: 'Overpass-the-Hash Logon With seclogo'\nid: 9c87c540-60fc-57f7-9f0e-68f6880ed440\nstatus: test\ndescription: 'Detects logon type 9 (NewCredentials) via seclogo with Negotiate, which is how sekurlsa::pth and runas /netonly style token creation appear.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.lateral-movement\n    - attack.t1550.002\nlogsource:\n    product: windows\n    service: security\ndetection:\n    selection:\n        EventID: 4624\n        LogonType: 9\n        LogonProcessName: 'seclogo'\n        AuthenticationPackageName: 'Negotiate'\n    condition: selection\nfalsepositives:\n    - 'Administrators using runas /netonly'\nlevel: high",
    "severity": "high",
    "category": "lateral-movement",
    "technique": "T1550.002",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "overpass-the-hash",
      "mimikatz"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-095",
    "type": "sigma",
    "title": "Password Spray From Single Source",
    "description": "Detects one source IP failing logons (4625) for many distinct accounts in a short window.",
    "code": "title: 'Password Spray From Single Source'\nid: f9d7b1cc-362d-587d-b145-5afff503730f\nstatus: test\ndescription: 'Detects one source IP failing logons (4625) for many distinct accounts in a short window.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.credential-access\n    - attack.t1110.003\nlogsource:\n    product: windows\n    service: security\ndetection:\n    selection:\n        EventID: 4625\n    filter:\n        IpAddress: '-'\n    condition: selection and not filter | count(TargetUserName) by IpAddress > 15\n    timeframe: 30m\nfalsepositives:\n    - 'NAT gateways or terminal servers shared by many users'\n    - 'Misconfigured service with stale credentials on several accounts'\nlevel: medium",
    "severity": "medium",
    "category": "credential-access",
    "technique": "T1110.003",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "password-spray",
      "brute-force"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-096",
    "type": "sigma",
    "title": "Brute Force Against Single Account",
    "description": "Detects a high number of failed logons (4625) for the same account from one source.",
    "code": "title: 'Brute Force Against Single Account'\nid: 455c5309-db67-5795-9485-48e4aeb92310\nstatus: test\ndescription: 'Detects a high number of failed logons (4625) for the same account from one source.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.credential-access\n    - attack.t1110.001\nlogsource:\n    product: windows\n    service: security\ndetection:\n    selection:\n        EventID: 4625\n    condition: selection | count() by TargetUserName, IpAddress > 30\n    timeframe: 15m\nfalsepositives:\n    - 'Mobile devices retrying an old password'\nlevel: medium",
    "severity": "medium",
    "category": "credential-access",
    "technique": "T1110.001",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "brute-force"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-097",
    "type": "sigma",
    "title": "Kerberos Pre-Authentication Spray",
    "description": "Detects many 4771 failures with status 0x18 (bad password) for different accounts from the same client address.",
    "code": "title: 'Kerberos Pre-Authentication Spray'\nid: c303dcd6-0940-5079-9bd9-f15c6d5023f2\nstatus: test\ndescription: 'Detects many 4771 failures with status 0x18 (bad password) for different accounts from the same client address.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.credential-access\n    - attack.t1110.003\nlogsource:\n    product: windows\n    service: security\ndetection:\n    selection:\n        EventID: 4771\n        Status: '0x18'\n    condition: selection | count(TargetUserName) by IpAddress > 15\n    timeframe: 30m\nfalsepositives:\n    - 'Shared hosts with many users mistyping passwords'\nlevel: medium",
    "severity": "medium",
    "category": "credential-access",
    "technique": "T1110.003",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "kerberos",
      "password-spray"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-098",
    "type": "sigma",
    "title": "Local or Domain User Account Created",
    "description": "Detects creation of a user account (4720). Useful as a baseline; tune to alert outside provisioning processes.",
    "code": "title: 'Local or Domain User Account Created'\nid: d7d70f3e-1c36-54fb-a3d0-a465fd235002\nstatus: test\ndescription: 'Detects creation of a user account (4720). Useful as a baseline; tune to alert outside provisioning processes.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1136\nlogsource:\n    product: windows\n    service: security\ndetection:\n    selection:\n        EventID: 4720\n    condition: selection\nfalsepositives:\n    - 'Normal joiner processes run by IAM teams'\nlevel: low",
    "severity": "low",
    "category": "persistence",
    "technique": "T1136",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "account-creation"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-099",
    "type": "sigma",
    "title": "Member Added to Privileged Group",
    "description": "Detects additions to Administrators, Domain Admins, Enterprise Admins, Schema Admins or similar groups (4728/4732/4756).",
    "code": "title: 'Member Added to Privileged Group'\nid: 382c4738-b2e3-5f77-9952-6e647ea70d77\nstatus: test\ndescription: 'Detects additions to Administrators, Domain Admins, Enterprise Admins, Schema Admins or similar groups (4728/4732/4756).'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1098\nlogsource:\n    product: windows\n    service: security\ndetection:\n    selection_evt:\n        EventID:\n            - 4728\n            - 4732\n            - 4756\n    selection_grp:\n        - TargetSid|endswith:\n            - '-512'\n            - '-518'\n            - '-519'\n            - '-520'\n        - TargetSid:\n            - 'S-1-5-32-544'\n            - 'S-1-5-32-548'\n            - 'S-1-5-32-549'\n            - 'S-1-5-32-551'\n    condition: all of selection_*\nfalsepositives:\n    - 'Planned privilege changes performed by administrators'\nlevel: high",
    "severity": "high",
    "category": "persistence",
    "technique": "T1098",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "privileged-group",
      "active-directory"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-100",
    "type": "sigma",
    "title": "High Volume of RC4 Service Ticket Requests by One Account",
    "description": "Detects a single account requesting RC4-encrypted (0x17) TGS tickets for many distinct services, the volume pattern of bulk Kerberoasting.",
    "code": "title: 'High Volume of RC4 Service Ticket Requests by One Account'\nid: 59b9f98d-549c-5182-b601-606acb658417\nstatus: test\ndescription: 'Detects a single account requesting RC4-encrypted (0x17) TGS tickets for many distinct services, the volume pattern of bulk Kerberoasting.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.credential-access\n    - attack.t1558.003\nlogsource:\n    product: windows\n    service: security\ndetection:\n    selection:\n        EventID: 4769\n        TicketEncryptionType: '0x17'\n        Status: '0x0'\n    filter_machine:\n        ServiceName|endswith: '$'\n    filter_krbtgt:\n        ServiceName: 'krbtgt'\n    condition: selection and not 1 of filter_* | count(ServiceName) by TargetUserName > 10\n    timeframe: 10m\nfalsepositives:\n    - 'Legacy applications that only support RC4'\nlevel: high",
    "severity": "high",
    "category": "credential-access",
    "technique": "T1558.003",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "kerberoasting",
      "kerberos"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-101",
    "type": "sigma",
    "title": "AS-REP Roasting Ticket Request",
    "description": "Detects TGT requests (4768) without pre-authentication and with RC4 encryption, indicative of AS-REP roasting against accounts with DONT_REQ_PREAUTH.",
    "code": "title: 'AS-REP Roasting Ticket Request'\nid: 5152bbda-c136-50e2-a259-f1d05a6b03e9\nstatus: test\ndescription: 'Detects TGT requests (4768) without pre-authentication and with RC4 encryption, indicative of AS-REP roasting against accounts with DONT_REQ_PREAUTH.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.credential-access\n    - attack.t1558.004\nlogsource:\n    product: windows\n    service: security\ndetection:\n    selection:\n        EventID: 4768\n        PreAuthType: 0\n        TicketEncryptionType: '0x17'\n        Status: '0x0'\n    condition: selection\nfalsepositives:\n    - 'Legacy accounts deliberately configured without pre-authentication'\nlevel: high",
    "severity": "high",
    "category": "credential-access",
    "technique": "T1558.004",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "asrep-roasting",
      "kerberos"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-102",
    "type": "sigma",
    "title": "DCSync Replication Rights Used by Non-DC Account",
    "description": "Detects 4662 directory access using DS-Replication-Get-Changes(-All) GUIDs by an account that is not a domain controller machine account.",
    "code": "title: 'DCSync Replication Rights Used by Non-DC Account'\nid: 78aa951d-6991-528b-9fd2-243c79f13e1d\nstatus: test\ndescription: 'Detects 4662 directory access using DS-Replication-Get-Changes(-All) GUIDs by an account that is not a domain controller machine account.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.credential-access\n    - attack.t1003.006\nlogsource:\n    product: windows\n    service: security\ndetection:\n    selection:\n        EventID: 4662\n        AccessMask: '0x100'\n        Properties|contains:\n            - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'\n            - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'\n            - '89e95b76-444d-4c62-991a-0facbeda640c'\n    filter_machine:\n        SubjectUserName|endswith: '$'\n    filter_msol:\n        SubjectUserName|startswith: 'MSOL_'\n    condition: selection and not 1 of filter_*\nfalsepositives:\n    - 'Entra Connect / Azure AD Connect sync accounts'\n    - 'Some identity management products'\nlevel: critical",
    "severity": "critical",
    "category": "credential-access",
    "technique": "T1003.006",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "dcsync",
      "active-directory"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-103",
    "type": "sigma",
    "title": "Group Policy Object Modified",
    "description": "Detects 5136 directory changes on groupPolicyContainer objects, e.g. gPCFileSysPath or versionNumber edits that push new GPO content.",
    "code": "title: 'Group Policy Object Modified'\nid: c9bbee63-3bb7-5e16-ac42-fdaf3502144f\nstatus: test\ndescription: 'Detects 5136 directory changes on groupPolicyContainer objects, e.g. gPCFileSysPath or versionNumber edits that push new GPO content.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.privilege-escalation\n    - attack.t1484.001\nlogsource:\n    product: windows\n    service: security\ndetection:\n    selection:\n        EventID: 5136\n        ObjectClass: 'groupPolicyContainer'\n        AttributeLDAPDisplayName:\n            - 'gPCMachineExtensionNames'\n            - 'gPCUserExtensionNames'\n            - 'gPCFileSysPath'\n            - 'versionNumber'\n    condition: selection\nfalsepositives:\n    - 'Normal GPO administration; correlate with change tickets'\nlevel: medium",
    "severity": "medium",
    "category": "privilege-escalation",
    "technique": "T1484.001",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "gpo",
      "active-directory"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-104",
    "type": "sigma",
    "title": "Resource-Based Constrained Delegation Configured",
    "description": "Detects 5136 writes to msDS-AllowedToActOnBehalfOfOtherIdentity, the attribute abused for RBCD privilege escalation.",
    "code": "title: 'Resource-Based Constrained Delegation Configured'\nid: 7d757b11-73d0-5618-a4a8-f6a2f5842db8\nstatus: test\ndescription: 'Detects 5136 writes to msDS-AllowedToActOnBehalfOfOtherIdentity, the attribute abused for RBCD privilege escalation.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.privilege-escalation\n    - attack.t1134\nlogsource:\n    product: windows\n    service: security\ndetection:\n    selection:\n        EventID: 5136\n        AttributeLDAPDisplayName: 'msDS-AllowedToActOnBehalfOfOtherIdentity'\n    condition: selection\nfalsepositives:\n    - 'Administrators configuring delegation for applications'\nlevel: high",
    "severity": "high",
    "category": "privilege-escalation",
    "technique": "T1134",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "rbcd",
      "kerberos",
      "delegation"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-105",
    "type": "sigma",
    "title": "Computer Account Created by Non-Admin User",
    "description": "Detects machine account creation (4741) where the creating account is not a machine account, the first step in RBCD and noPac-style attacks using MachineAccountQuota.",
    "code": "title: 'Computer Account Created by Non-Admin User'\nid: 1ecbbe87-f36b-5711-b112-0db279065f77\nstatus: test\ndescription: 'Detects machine account creation (4741) where the creating account is not a machine account, the first step in RBCD and noPac-style attacks using MachineAccountQuota.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1136.002\nlogsource:\n    product: windows\n    service: security\ndetection:\n    selection:\n        EventID: 4741\n    filter:\n        SubjectUserName|endswith: '$'\n    condition: selection and not filter\nfalsepositives:\n    - 'Helpdesk staff joining machines to the domain'\nlevel: low",
    "severity": "low",
    "category": "persistence",
    "technique": "T1136.002",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "machine-account-quota",
      "active-directory"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-106",
    "type": "sigma",
    "title": "Security Event Log Cleared",
    "description": "Detects EventID 1102 indicating the Security audit log was cleared.",
    "code": "title: 'Security Event Log Cleared'\nid: 4672b1c7-f674-53b0-8891-833173f5e158\nstatus: test\ndescription: 'Detects EventID 1102 indicating the Security audit log was cleared.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1070.001\nlogsource:\n    product: windows\n    service: security\ndetection:\n    selection:\n        EventID: 1102\n    condition: selection\nfalsepositives:\n    - 'Log rotation by administrators on systems without forwarding'\nlevel: high",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1070.001",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "log-clearing"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-107",
    "type": "sigma",
    "title": "System or Application Event Log Cleared",
    "description": "Detects EventID 104 from Microsoft-Windows-Eventlog, raised when a log other than Security is cleared.",
    "code": "title: 'System or Application Event Log Cleared'\nid: 19007e73-8f4b-5fe7-b93f-d2eb7cb5eab3\nstatus: test\ndescription: 'Detects EventID 104 from Microsoft-Windows-Eventlog, raised when a log other than Security is cleared.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1070.001\nlogsource:\n    product: windows\n    service: system\ndetection:\n    selection:\n        EventID: 104\n        Provider_Name: 'Microsoft-Windows-Eventlog'\n    condition: selection\nfalsepositives:\n    - 'Administrative clean-up'\nlevel: medium",
    "severity": "medium",
    "category": "defense-evasion",
    "technique": "T1070.001",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "log-clearing"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-108",
    "type": "sigma",
    "title": "Audit Policy Changed",
    "description": "Detects 4719 system audit policy changes, which can be used to silence security logging.",
    "code": "title: 'Audit Policy Changed'\nid: 53925b05-ca75-5455-be14-c1cb59ef9e73\nstatus: test\ndescription: 'Detects 4719 system audit policy changes, which can be used to silence security logging.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1562.002\nlogsource:\n    product: windows\n    service: security\ndetection:\n    selection:\n        EventID: 4719\n    condition: selection\nfalsepositives:\n    - 'GPO-driven audit policy updates'\nlevel: medium",
    "severity": "medium",
    "category": "defense-evasion",
    "technique": "T1562.002",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "audit-policy"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-109",
    "type": "sigma",
    "title": "Directory Services Restore Mode Password Changed",
    "description": "Detects 4794, an attempt to set the DSRM administrator password, which can provide a persistent DC backdoor.",
    "code": "title: 'Directory Services Restore Mode Password Changed'\nid: 2200f16d-ab0c-5062-b66b-e9f2fe9b273e\nstatus: test\ndescription: 'Detects 4794, an attempt to set the DSRM administrator password, which can provide a persistent DC backdoor.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1098\nlogsource:\n    product: windows\n    service: security\ndetection:\n    selection:\n        EventID: 4794\n    condition: selection\nfalsepositives:\n    - 'Documented DSRM password rotation'\nlevel: high",
    "severity": "high",
    "category": "persistence",
    "technique": "T1098",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "dsrm",
      "domain-controller"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-110",
    "type": "sigma",
    "title": "Scheduled Task Registered With Suspicious Action",
    "description": "Detects 4698 task registrations whose XML content runs script interpreters or binaries from user-writable folders.",
    "code": "title: 'Scheduled Task Registered With Suspicious Action'\nid: ff9521d4-d66d-5029-a261-5fdb1a3ed0cb\nstatus: test\ndescription: 'Detects 4698 task registrations whose XML content runs script interpreters or binaries from user-writable folders.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1053.005\nlogsource:\n    product: windows\n    service: security\ndetection:\n    selection:\n        EventID: 4698\n    selection_content:\n        TaskContent|contains:\n            - 'powershell'\n            - 'mshta'\n            - 'wscript'\n            - 'cscript'\n            - 'rundll32'\n            - 'regsvr32'\n            - '\\AppData\\'\n            - '\\Users\\Public\\'\n            - 'cmd.exe /c'\n    condition: all of selection*\nfalsepositives:\n    - 'Vendor updaters registering tasks under AppData'\nlevel: medium",
    "severity": "medium",
    "category": "persistence",
    "technique": "T1053.005",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "schtasks",
      "persistence"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-111",
    "type": "sigma",
    "title": "Remote Service or Task Pipe Access over SMB",
    "description": "Detects 5145 access to the svcctl or atsvc named pipes over IPC$, used by PsExec-like tools and remote task creation.",
    "code": "title: 'Remote Service or Task Pipe Access over SMB'\nid: 47c31236-19f9-54d9-ad1f-5fe75f6675ea\nstatus: test\ndescription: 'Detects 5145 access to the svcctl or atsvc named pipes over IPC$, used by PsExec-like tools and remote task creation.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.lateral-movement\n    - attack.t1021.002\nlogsource:\n    product: windows\n    service: security\ndetection:\n    selection:\n        EventID: 5145\n        ShareName: '\\\\*\\IPC$'\n        RelativeTargetName:\n            - 'svcctl'\n            - 'atsvc'\n    condition: selection\nfalsepositives:\n    - 'Remote administration tooling and monitoring'\nlevel: low",
    "severity": "low",
    "category": "lateral-movement",
    "technique": "T1021.002",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "smb",
      "named-pipe"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-112",
    "type": "sigma",
    "title": "Service Installed With Suspicious Image Path",
    "description": "Detects 7045 service installations whose ImagePath uses cmd /c, PowerShell, %COMSPEC%, ADMIN$ shares or user-writable directories.",
    "code": "title: 'Service Installed With Suspicious Image Path'\nid: b9a00947-c71e-50b9-8df0-27216734ac19\nstatus: test\ndescription: 'Detects 7045 service installations whose ImagePath uses cmd /c, PowerShell, %COMSPEC%, ADMIN$ shares or user-writable directories.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1543.003\nlogsource:\n    product: windows\n    service: system\ndetection:\n    selection:\n        Provider_Name: 'Service Control Manager'\n        EventID: 7045\n    selection_path:\n        ImagePath|contains:\n            - 'cmd /c'\n            - 'cmd.exe /c'\n            - '%COMSPEC%'\n            - 'powershell'\n            - 'mshta'\n            - 'rundll32'\n            - '\\\\127.0.0.1\\'\n            - '\\ADMIN$\\'\n            - '\\AppData\\'\n            - '\\Users\\Public\\'\n            - '\\Temp\\'\n    condition: all of selection*\nfalsepositives:\n    - 'Badly packaged software'\n    - 'Some remote support tools'\nlevel: high",
    "severity": "high",
    "category": "persistence",
    "technique": "T1543.003",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "service",
      "lateral-movement"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-113",
    "type": "sigma",
    "title": "Remote Execution Tool Service Installed",
    "description": "Detects 7045 installations of service names used by PsExec, PAExec, RemCom and similar remote execution tools.",
    "code": "title: 'Remote Execution Tool Service Installed'\nid: 69297850-cc3b-50a1-82be-d5da67a20ded\nstatus: test\ndescription: 'Detects 7045 installations of service names used by PsExec, PAExec, RemCom and similar remote execution tools.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.lateral-movement\n    - attack.t1569.002\nlogsource:\n    product: windows\n    service: system\ndetection:\n    selection:\n        Provider_Name: 'Service Control Manager'\n        EventID: 7045\n    selection_name:\n        - ServiceName:\n            - 'PSEXESVC'\n            - 'PAExec'\n            - 'RemComSvc'\n            - 'csexecsvc'\n        - ImagePath|endswith:\n            - '\\PSEXESVC.exe'\n            - '\\RemComSvc.exe'\n            - '\\csexecsvc.exe'\n        - ImagePath|contains: '\\PAExec-'\n    condition: all of selection*\nfalsepositives:\n    - 'Administrators using PsExec for software deployment'\nlevel: medium",
    "severity": "medium",
    "category": "lateral-movement",
    "technique": "T1569.002",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "psexec",
      "service"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-114",
    "type": "sigma",
    "title": "Defender Malware Detection Event",
    "description": "Detects Microsoft Defender detections (1116) and remediation actions (1117).",
    "code": "title: 'Defender Malware Detection Event'\nid: 195e6a93-01cc-5d2c-9c5b-96498b61a7c1\nstatus: test\ndescription: 'Detects Microsoft Defender detections (1116) and remediation actions (1117).'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.execution\n    - attack.t1204\nlogsource:\n    product: windows\n    service: windefend\ndetection:\n    selection:\n        EventID:\n            - 1116\n            - 1117\n    condition: selection\nfalsepositives:\n    - 'Test files such as EICAR'\n    - 'Hacktool detections on security staff machines'\nlevel: high",
    "severity": "high",
    "category": "malware",
    "technique": "T1204",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "defender",
      "av-alert"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-115",
    "type": "sigma",
    "title": "Defender Real-Time Protection Disabled",
    "description": "Detects Defender events 5001 (real-time protection disabled), 5010/5012 (scanning disabled) and 5013 (tamper protection blocked a change).",
    "code": "title: 'Defender Real-Time Protection Disabled'\nid: baf066cb-0f65-5d6f-ae76-1cc6144f3791\nstatus: test\ndescription: 'Detects Defender events 5001 (real-time protection disabled), 5010/5012 (scanning disabled) and 5013 (tamper protection blocked a change).'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1562.001\nlogsource:\n    product: windows\n    service: windefend\ndetection:\n    selection:\n        EventID:\n            - 5001\n            - 5010\n            - 5012\n            - 5013\n    condition: selection\nfalsepositives:\n    - 'Third-party AV installation automatically disabling Defender'\nlevel: high",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1562.001",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "defender",
      "tamper"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-116",
    "type": "sigma",
    "title": "WMI Permanent Event Consumer Registered",
    "description": "Detects WMI-Activity EventID 5861, which records a permanent event filter-to-consumer binding.",
    "code": "title: 'WMI Permanent Event Consumer Registered'\nid: 40748385-68e4-5ec9-a328-e3ab036abcee\nstatus: test\ndescription: 'Detects WMI-Activity EventID 5861, which records a permanent event filter-to-consumer binding.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1546.003\nlogsource:\n    product: windows\n    service: wmi\ndetection:\n    selection:\n        EventID: 5861\n    filter_scm:\n        Destination|contains:\n            - 'SCM Event Log Consumer'\n            - 'BVTFilter'\n    condition: selection and not filter_scm\nfalsepositives:\n    - 'Monitoring agents (Dell, HP, SCCM) that use WMI consumers'\nlevel: high",
    "severity": "high",
    "category": "persistence",
    "technique": "T1546.003",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "wmi",
      "persistence"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-117",
    "type": "sigma",
    "title": "PowerShell Script Block With AMSI Bypass",
    "description": "Detects AMSI tampering markers inside PowerShell script block logs, catching bypasses that are decoded at run time.",
    "code": "title: 'PowerShell Script Block With AMSI Bypass'\nid: 8f9c780b-4076-54a7-9e03-cec05a493131\nstatus: test\ndescription: 'Detects AMSI tampering markers inside PowerShell script block logs, catching bypasses that are decoded at run time.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1562.001\nlogsource:\n    category: ps_script\n    product: windows\n    definition: 'Requires Script Block Logging (EventID 4104)'\ndetection:\n    selection:\n        ScriptBlockText|contains:\n            - 'amsiInitFailed'\n            - 'AmsiUtils'\n            - 'AmsiScanBuffer'\n            - 'amsi.dll'\n    selection_act:\n        ScriptBlockText|contains:\n            - 'GetField'\n            - 'SetValue'\n            - 'VirtualProtect'\n            - 'NonPublic,Static'\n            - 'GetProcAddress'\n    condition: all of selection*\nfalsepositives:\n    - 'Security tooling testing AMSI'\nlevel: high",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1562.001",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "amsi",
      "powershell"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-118",
    "type": "sigma",
    "title": "PowerShell Reflective Assembly Load From Base64",
    "description": "Detects script blocks that decode base64 and load a .NET assembly in memory with Reflection.Assembly::Load.",
    "code": "title: 'PowerShell Reflective Assembly Load From Base64'\nid: 4ccc012f-3e5e-5a26-9f75-d7ea0e6c09a7\nstatus: test\ndescription: 'Detects script blocks that decode base64 and load a .NET assembly in memory with Reflection.Assembly::Load.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1620\nlogsource:\n    category: ps_script\n    product: windows\n    definition: 'Requires Script Block Logging (EventID 4104)'\ndetection:\n    selection:\n        ScriptBlockText|contains|all:\n            - 'FromBase64String'\n    selection_load:\n        ScriptBlockText|contains:\n            - '[System.Reflection.Assembly]::Load('\n            - '[Reflection.Assembly]::Load('\n            - 'Assembly]::Load('\n    condition: all of selection*\nfalsepositives:\n    - 'Some legitimate modules embed assemblies'\nlevel: high",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1620",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "reflective-loading",
      "powershell"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-119",
    "type": "sigma",
    "title": "PowerShell Script Block Download and Execute",
    "description": "Detects script blocks that combine a web download primitive with Invoke-Expression.",
    "code": "title: 'PowerShell Script Block Download and Execute'\nid: 83b14c7d-8d97-5635-a257-e26ec0fb2392\nstatus: test\ndescription: 'Detects script blocks that combine a web download primitive with Invoke-Expression.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.execution\n    - attack.t1059.001\nlogsource:\n    category: ps_script\n    product: windows\n    definition: 'Requires Script Block Logging (EventID 4104)'\ndetection:\n    selection_dl:\n        ScriptBlockText|contains:\n            - 'DownloadString'\n            - 'DownloadData'\n            - 'Invoke-WebRequest'\n            - 'Invoke-RestMethod'\n            - 'Net.WebClient'\n    selection_iex:\n        ScriptBlockText|contains:\n            - 'Invoke-Expression'\n            - 'IEX '\n            - 'IEX('\n            - '| iex'\n    condition: all of selection_*\nfalsepositives:\n    - 'Installer bootstrap scripts'\nlevel: medium",
    "severity": "medium",
    "category": "execution",
    "technique": "T1059.001",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "powershell",
      "download-cradle"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-120",
    "type": "sigma",
    "title": "PowerShell Shellcode Runner APIs in Script Block",
    "description": "Detects script blocks that resolve VirtualAlloc/CreateThread and build delegates, the typical structure of in-memory shellcode runners.",
    "code": "title: 'PowerShell Shellcode Runner APIs in Script Block'\nid: 9ab5871b-3288-573a-8e9b-019bbfff3cd4\nstatus: test\ndescription: 'Detects script blocks that resolve VirtualAlloc/CreateThread and build delegates, the typical structure of in-memory shellcode runners.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.execution\n    - attack.t1059.001\nlogsource:\n    category: ps_script\n    product: windows\n    definition: 'Requires Script Block Logging (EventID 4104)'\ndetection:\n    selection_api:\n        ScriptBlockText|contains:\n            - 'VirtualAlloc'\n            - 'VirtualProtect'\n            - 'CreateThread'\n            - 'WriteProcessMemory'\n    selection_delegate:\n        ScriptBlockText|contains:\n            - 'GetDelegateForFunctionPointer'\n            - 'DefineDynamicAssembly'\n            - 'Add-Type'\n    condition: all of selection_*\nfalsepositives:\n    - 'Low-level admin modules that P/Invoke Win32 APIs'\nlevel: high",
    "severity": "high",
    "category": "execution",
    "technique": "T1059.001",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "shellcode",
      "powershell"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-121",
    "type": "sigma",
    "title": "Remote Thread Created in LSASS",
    "description": "Detects CreateRemoteThread (Sysmon 8) targeting lsass.exe, used by some credential theft and injection tools.",
    "code": "title: 'Remote Thread Created in LSASS'\nid: cca33f58-1b7d-5e04-a2d4-6a60f4ab3421\nstatus: test\ndescription: 'Detects CreateRemoteThread (Sysmon 8) targeting lsass.exe, used by some credential theft and injection tools.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.credential-access\n    - attack.t1003.001\nlogsource:\n    category: create_remote_thread\n    product: windows\ndetection:\n    selection:\n        TargetImage|endswith: '\\lsass.exe'\n    filter:\n        SourceImage|startswith:\n            - 'C:\\Windows\\System32\\'\n            - 'C:\\Program Files\\Windows Defender\\'\n            - 'C:\\ProgramData\\Microsoft\\Windows Defender\\'\n    condition: selection and not filter\nfalsepositives:\n    - 'Some EDR products'\nlevel: critical",
    "severity": "critical",
    "category": "credential-access",
    "technique": "T1003.001",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "lsass",
      "injection"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-122",
    "type": "sigma",
    "title": "Remote Thread Created by Office or Script Host",
    "description": "Detects Office applications or script hosts injecting threads into other processes (Sysmon 8).",
    "code": "title: 'Remote Thread Created by Office or Script Host'\nid: b4f5ea1d-3234-581d-8f49-4a2919d67593\nstatus: test\ndescription: 'Detects Office applications or script hosts injecting threads into other processes (Sysmon 8).'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1055\nlogsource:\n    category: create_remote_thread\n    product: windows\ndetection:\n    selection:\n        SourceImage|endswith:\n            - '\\winword.exe'\n            - '\\excel.exe'\n            - '\\powerpnt.exe'\n            - '\\wscript.exe'\n            - '\\cscript.exe'\n            - '\\mshta.exe'\n            - '\\rundll32.exe'\n            - '\\regsvr32.exe'\n    condition: selection\nfalsepositives:\n    - 'Accessibility software or add-ins that hook other processes'\nlevel: high",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1055",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "injection"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-123",
    "type": "sigma",
    "title": "LSASS Opened With Credential-Dumping Access Rights",
    "description": "Detects process access (Sysmon 10) to lsass.exe with GrantedAccess masks associated with memory reads by dumping tools.",
    "code": "title: 'LSASS Opened With Credential-Dumping Access Rights'\nid: 74e151bc-0eab-5471-8d55-ad25c2c6b6b3\nstatus: test\ndescription: 'Detects process access (Sysmon 10) to lsass.exe with GrantedAccess masks associated with memory reads by dumping tools.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.credential-access\n    - attack.t1003.001\nlogsource:\n    category: process_access\n    product: windows\ndetection:\n    selection:\n        TargetImage|endswith: '\\lsass.exe'\n        GrantedAccess:\n            - '0x1010'\n            - '0x1410'\n            - '0x1438'\n            - '0x143a'\n            - '0x1418'\n            - '0x1f0fff'\n            - '0x1f1fff'\n            - '0x1f2fff'\n            - '0x1f3fff'\n            - '0x1fffff'\n    filter_system:\n        SourceImage|startswith:\n            - 'C:\\Windows\\System32\\'\n            - 'C:\\Program Files\\'\n            - 'C:\\Program Files (x86)\\'\n            - 'C:\\ProgramData\\Microsoft\\Windows Defender\\'\n    condition: selection and not filter_system\nfalsepositives:\n    - 'AV/EDR and backup agents installed outside Program Files'\nlevel: high",
    "severity": "high",
    "category": "credential-access",
    "technique": "T1003.001",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "lsass",
      "sysmon"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-124",
    "type": "sigma",
    "title": "LSASS Access via MiniDumpWriteDump Call Trace",
    "description": "Detects LSASS process access where the CallTrace includes dbghelp.dll or dbgcore.dll, meaning a MiniDump of LSASS was being written.",
    "code": "title: 'LSASS Access via MiniDumpWriteDump Call Trace'\nid: dcb656fc-2c4e-52c7-95cb-a3cf58e654c5\nstatus: test\ndescription: 'Detects LSASS process access where the CallTrace includes dbghelp.dll or dbgcore.dll, meaning a MiniDump of LSASS was being written.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.credential-access\n    - attack.t1003.001\nlogsource:\n    category: process_access\n    product: windows\ndetection:\n    selection:\n        TargetImage|endswith: '\\lsass.exe'\n        CallTrace|contains:\n            - 'dbghelp.dll'\n            - 'dbgcore.dll'\n    filter:\n        SourceImage|endswith:\n            - '\\WerFault.exe'\n            - '\\MsMpEng.exe'\n    condition: selection and not filter\nfalsepositives:\n    - 'Crash dump collection tools'\nlevel: high",
    "severity": "high",
    "category": "credential-access",
    "technique": "T1003.001",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "lsass",
      "minidump"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-125",
    "type": "sigma",
    "title": "File Dropped in Startup Folder by Script Host or Office",
    "description": "Detects files written to a Startup folder by script hosts, Office or PowerShell, a simple persistence technique.",
    "code": "title: 'File Dropped in Startup Folder by Script Host or Office'\nid: e93b651a-a510-54f6-8aca-414bfc115569\nstatus: test\ndescription: 'Detects files written to a Startup folder by script hosts, Office or PowerShell, a simple persistence technique.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1547.001\nlogsource:\n    category: file_event\n    product: windows\ndetection:\n    selection_path:\n        TargetFilename|contains: '\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\'\n    selection_proc:\n        Image|endswith:\n            - '\\wscript.exe'\n            - '\\cscript.exe'\n            - '\\mshta.exe'\n            - '\\powershell.exe'\n            - '\\cmd.exe'\n            - '\\winword.exe'\n            - '\\excel.exe'\n            - '\\rundll32.exe'\n            - '\\regsvr32.exe'\n    condition: all of selection_*\nfalsepositives:\n    - 'Logon scripts that place shortcuts in Startup'\nlevel: high",
    "severity": "high",
    "category": "persistence",
    "technique": "T1547.001",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "startup-folder",
      "persistence"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-126",
    "type": "sigma",
    "title": "LSASS Memory Dump File Created",
    "description": "Detects creation of files whose names indicate an LSASS memory dump (lsass*.dmp, or dumps from common tools).",
    "code": "title: 'LSASS Memory Dump File Created'\nid: 7b87dad2-5cb3-515f-9a24-b21a0a2d8d01\nstatus: test\ndescription: 'Detects creation of files whose names indicate an LSASS memory dump (lsass*.dmp, or dumps from common tools).'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.credential-access\n    - attack.t1003.001\nlogsource:\n    category: file_event\n    product: windows\ndetection:\n    selection:\n        TargetFilename|contains:\n            - '\\lsass.dmp'\n            - '\\lsass_'\n            - '\\lsass.zip'\n            - '\\nanodump'\n            - '\\Andrew.dmp'\n            - '\\Coredump.dmp'\n    selection_ext:\n        TargetFilename|endswith:\n            - '.dmp'\n            - '.zip'\n            - '.bin'\n    condition: all of selection*\nfalsepositives:\n    - 'Windows Error Reporting capturing an LSASS crash'\nlevel: high",
    "severity": "high",
    "category": "credential-access",
    "technique": "T1003.001",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "lsass",
      "dump-file"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-127",
    "type": "sigma",
    "title": "Executable or Script Written to Public or PerfLogs",
    "description": "Detects creation of executables and scripts in C:\\Users\\Public or C:\\PerfLogs, popular staging folders.",
    "code": "title: 'Executable or Script Written to Public or PerfLogs'\nid: 4c7a7068-eb5b-541d-9309-eba43c353c39\nstatus: test\ndescription: 'Detects creation of executables and scripts in C:\\Users\\Public or C:\\PerfLogs, popular staging folders.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1036.005\nlogsource:\n    category: file_event\n    product: windows\ndetection:\n    selection_path:\n        TargetFilename|contains:\n            - ':\\Users\\Public\\'\n            - ':\\PerfLogs\\'\n    selection_ext:\n        TargetFilename|endswith:\n            - '.exe'\n            - '.dll'\n            - '.ps1'\n            - '.bat'\n            - '.vbs'\n            - '.hta'\n            - '.js'\n    condition: all of selection_*\nfalsepositives:\n    - 'Shared desktop shortcuts and some vendor tools'\nlevel: medium",
    "severity": "medium",
    "category": "defense-evasion",
    "technique": "T1036.005",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "staging"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-128",
    "type": "sigma",
    "title": "Winlogon Shell or Userinit Modified",
    "description": "Detects changes to Winlogon Shell or Userinit values, which run programs at every logon.",
    "code": "title: 'Winlogon Shell or Userinit Modified'\nid: a4759d31-0c51-5bcd-b6b2-d4df9df05743\nstatus: test\ndescription: 'Detects changes to Winlogon Shell or Userinit values, which run programs at every logon.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1547.004\nlogsource:\n    category: registry_set\n    product: windows\ndetection:\n    selection:\n        TargetObject|endswith:\n            - '\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell'\n            - '\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit'\n    filter_default:\n        Details:\n            - 'explorer.exe'\n            - 'C:\\Windows\\system32\\userinit.exe,'\n            - 'C:\\Windows\\system32\\userinit.exe'\n    condition: selection and not filter_default\nfalsepositives:\n    - 'Kiosk shells configured by administrators'\nlevel: high",
    "severity": "high",
    "category": "persistence",
    "technique": "T1547.004",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "winlogon",
      "registry"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-129",
    "type": "sigma",
    "title": "Image File Execution Options Debugger or SilentProcessExit Set",
    "description": "Detects registry writes setting a Debugger under IFEO or a MonitorProcess under SilentProcessExit, both of which hijack process launch/exit.",
    "code": "title: 'Image File Execution Options Debugger or SilentProcessExit Set'\nid: e4a775ce-eba8-5dcf-94cc-51036dca001f\nstatus: test\ndescription: 'Detects registry writes setting a Debugger under IFEO or a MonitorProcess under SilentProcessExit, both of which hijack process launch/exit.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1546.012\nlogsource:\n    category: registry_set\n    product: windows\ndetection:\n    selection_ifeo:\n        TargetObject|contains: '\\Image File Execution Options\\'\n        TargetObject|endswith: '\\Debugger'\n    selection_spe:\n        TargetObject|contains: '\\SilentProcessExit\\'\n        TargetObject|endswith: '\\MonitorProcess'\n    condition: 1 of selection_*\nfalsepositives:\n    - 'Developers attaching debuggers'\n    - 'Some application compatibility tools'\nlevel: high",
    "severity": "high",
    "category": "persistence",
    "technique": "T1546.012",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "ifeo",
      "registry"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-130",
    "type": "sigma",
    "title": "COM Object Hijack in User Hive",
    "description": "Detects writes to InprocServer32 or LocalServer32 under HKCU\\Software\\Classes\\CLSID, a per-user COM hijack that needs no admin rights.",
    "code": "title: 'COM Object Hijack in User Hive'\nid: 440f3336-d3ac-5831-8329-901ab4e7cc6c\nstatus: test\ndescription: 'Detects writes to InprocServer32 or LocalServer32 under HKCU\\Software\\Classes\\CLSID, a per-user COM hijack that needs no admin rights.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1546.015\nlogsource:\n    category: registry_set\n    product: windows\ndetection:\n    selection:\n        TargetObject|contains: '\\Software\\Classes\\CLSID\\'\n        TargetObject|endswith:\n            - '\\InprocServer32\\(Default)'\n            - '\\LocalServer32\\(Default)'\n        TargetObject|startswith: 'HKU\\'\n    selection_path:\n        Details|contains:\n            - '\\AppData\\'\n            - '\\Temp\\'\n            - '\\Users\\Public\\'\n            - '\\ProgramData\\'\n    condition: all of selection*\nfalsepositives:\n    - 'Per-user installs of apps such as Teams, OneDrive or Zoom'\nlevel: medium",
    "severity": "medium",
    "category": "persistence",
    "technique": "T1546.015",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "com-hijack",
      "registry"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-131",
    "type": "sigma",
    "title": "Defender Disabled via Policy Registry Values",
    "description": "Detects registry values that disable Defender (DisableAntiSpyware, DisableRealtimeMonitoring, DisableBehaviorMonitoring) set to 1.",
    "code": "title: 'Defender Disabled via Policy Registry Values'\nid: d8f30065-fc30-5249-ade6-c4865db278dd\nstatus: test\ndescription: 'Detects registry values that disable Defender (DisableAntiSpyware, DisableRealtimeMonitoring, DisableBehaviorMonitoring) set to 1.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1562.001\nlogsource:\n    category: registry_set\n    product: windows\ndetection:\n    selection:\n        TargetObject|contains: '\\Microsoft\\Windows Defender\\'\n        TargetObject|endswith:\n            - '\\DisableAntiSpyware'\n            - '\\DisableAntiVirus'\n            - '\\Real-Time Protection\\DisableRealtimeMonitoring'\n            - '\\Real-Time Protection\\DisableBehaviorMonitoring'\n            - '\\Real-Time Protection\\DisableIOAVProtection'\n        Details: 'DWORD (0x00000001)'\n    condition: selection\nfalsepositives:\n    - 'Third-party AV installers'\nlevel: high",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1562.001",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "defender",
      "registry"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-132",
    "type": "sigma",
    "title": "WDigest Plaintext Credential Caching Enabled",
    "description": "Detects UseLogonCredential set to 1 under WDigest, which makes LSASS keep cleartext passwords for later dumping.",
    "code": "title: 'WDigest Plaintext Credential Caching Enabled'\nid: 75c6bf97-c8e5-56c0-a12b-e6ed1480bc7f\nstatus: test\ndescription: 'Detects UseLogonCredential set to 1 under WDigest, which makes LSASS keep cleartext passwords for later dumping.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.credential-access\n    - attack.t1112\nlogsource:\n    category: registry_set\n    product: windows\ndetection:\n    selection:\n        TargetObject|endswith: '\\SecurityProviders\\WDigest\\UseLogonCredential'\n        Details: 'DWORD (0x00000001)'\n    condition: selection\nfalsepositives:\n    - 'Legacy applications requiring WDigest (very rare)'\nlevel: high",
    "severity": "high",
    "category": "credential-access",
    "technique": "T1112",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "wdigest",
      "registry"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-133",
    "type": "sigma",
    "title": "Security Support Provider or Authentication Package Added",
    "description": "Detects changes to LSA Security Packages or Authentication Packages, used to load a malicious SSP into LSASS.",
    "code": "title: 'Security Support Provider or Authentication Package Added'\nid: 20764eb2-3328-5fe5-9e3d-a126fb36182d\nstatus: test\ndescription: 'Detects changes to LSA Security Packages or Authentication Packages, used to load a malicious SSP into LSASS.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1547.005\nlogsource:\n    category: registry_set\n    product: windows\ndetection:\n    selection:\n        TargetObject|endswith:\n            - '\\Control\\Lsa\\Security Packages'\n            - '\\Control\\Lsa\\OSConfig\\Security Packages'\n            - '\\Control\\Lsa\\Authentication Packages'\n    filter:\n        Details:\n            - '\"\"'\n            - 'msv1_0'\n    condition: selection and not filter\nfalsepositives:\n    - 'Smart card or SSO vendors installing authentication packages'\nlevel: high",
    "severity": "high",
    "category": "persistence",
    "technique": "T1547.005",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "ssp",
      "lsass",
      "registry"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-134",
    "type": "sigma",
    "title": "Netsh Helper DLL Registered",
    "description": "Detects new values under HKLM\\SOFTWARE\\Microsoft\\NetSh, which make netsh.exe load an arbitrary DLL.",
    "code": "title: 'Netsh Helper DLL Registered'\nid: cd47ebee-296e-50c6-b30e-7459fa598e80\nstatus: test\ndescription: 'Detects new values under HKLM\\SOFTWARE\\Microsoft\\NetSh, which make netsh.exe load an arbitrary DLL.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1546.007\nlogsource:\n    category: registry_set\n    product: windows\ndetection:\n    selection:\n        TargetObject|contains: '\\SOFTWARE\\Microsoft\\NetSh\\'\n    filter:\n        Details|endswith:\n            - '\\system32\\ifmon.dll'\n            - '\\system32\\rasmontr.dll'\n            - '\\system32\\authfwcfg.dll'\n            - '\\system32\\dhcpcmonitor.dll'\n            - '\\system32\\dot3cfg.dll'\n            - '\\system32\\fwcfg.dll'\n            - '\\system32\\hnetmon.dll'\n            - '\\system32\\netiohlp.dll'\n            - '\\system32\\nettrace.dll'\n            - '\\system32\\nshhttp.dll'\n            - '\\system32\\nshipsec.dll'\n            - '\\system32\\nshwfp.dll'\n            - '\\system32\\p2pnetsh.dll'\n            - '\\system32\\rpcnsh.dll'\n            - '\\system32\\WcnNetsh.dll'\n            - '\\system32\\whhelper.dll'\n            - '\\system32\\wlancfg.dll'\n            - '\\system32\\wshelper.dll'\n            - '\\system32\\wwancfg.dll'\n            - '\\system32\\peerdistsh.dll'\n    condition: selection and not filter\nfalsepositives:\n    - 'Third-party VPN or network software adding netsh contexts'\nlevel: high",
    "severity": "high",
    "category": "persistence",
    "technique": "T1546.007",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "netsh",
      "registry"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-135",
    "type": "sigma",
    "title": "AppInit_DLLs Configured",
    "description": "Detects writes to AppInit_DLLs or LoadAppInit_DLLs, which load DLLs into every process that loads user32.dll.",
    "code": "title: 'AppInit_DLLs Configured'\nid: a6d63c29-d73d-5695-af22-03dd88e30f98\nstatus: test\ndescription: 'Detects writes to AppInit_DLLs or LoadAppInit_DLLs, which load DLLs into every process that loads user32.dll.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1546.010\nlogsource:\n    category: registry_set\n    product: windows\ndetection:\n    selection:\n        TargetObject|endswith:\n            - '\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs'\n            - '\\Windows NT\\CurrentVersion\\Windows\\LoadAppInit_DLLs'\n    filter_empty:\n        Details:\n            - '(Empty)'\n            - 'DWORD (0x00000000)'\n    condition: selection and not filter_empty\nfalsepositives:\n    - 'Legacy software hooks'\nlevel: high",
    "severity": "high",
    "category": "persistence",
    "technique": "T1546.010",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "appinit",
      "registry"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-136",
    "type": "sigma",
    "title": "Service ImagePath Changed to Script Interpreter",
    "description": "Detects registry modifications to a service ImagePath that point to cmd, PowerShell, mshta or user-writable folders.",
    "code": "title: 'Service ImagePath Changed to Script Interpreter'\nid: 19f41f84-8bed-5e73-b73c-771e1bc57274\nstatus: test\ndescription: 'Detects registry modifications to a service ImagePath that point to cmd, PowerShell, mshta or user-writable folders.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1574.011\nlogsource:\n    category: registry_set\n    product: windows\ndetection:\n    selection:\n        TargetObject|startswith: 'HKLM\\System\\CurrentControlSet\\Services\\'\n        TargetObject|endswith: '\\ImagePath'\n    selection_val:\n        Details|contains:\n            - 'powershell'\n            - 'cmd.exe /c'\n            - 'cmd /c'\n            - 'mshta'\n            - '\\AppData\\'\n            - '\\Users\\Public\\'\n            - '\\Temp\\'\n    condition: all of selection*\nfalsepositives:\n    - 'Badly packaged services'\nlevel: high",
    "severity": "high",
    "category": "persistence",
    "technique": "T1574.011",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "service",
      "registry"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-137",
    "type": "sigma",
    "title": "DNS Query to Abuse-Prone Top-Level Domain",
    "description": "Detects DNS queries for TLDs with high abuse rates, from processes that are not browsers.",
    "code": "title: 'DNS Query to Abuse-Prone Top-Level Domain'\nid: aeb0d5e0-3654-5bbf-b0ae-d723a4b86425\nstatus: test\ndescription: 'Detects DNS queries for TLDs with high abuse rates, from processes that are not browsers.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.command-and-control\n    - attack.t1071.004\nlogsource:\n    category: dns_query\n    product: windows\ndetection:\n    selection:\n        QueryName|endswith:\n            - '.top'\n            - '.xyz'\n            - '.tk'\n            - '.ml'\n            - '.ga'\n            - '.cf'\n            - '.gq'\n            - '.icu'\n            - '.cyou'\n            - '.rest'\n            - '.zip'\n            - '.mov'\n    filter_browsers:\n        Image|endswith:\n            - '\\chrome.exe'\n            - '\\msedge.exe'\n            - '\\firefox.exe'\n            - '\\brave.exe'\n            - '\\opera.exe'\n    condition: selection and not filter_browsers\nfalsepositives:\n    - 'Legitimate services hosted on these TLDs'\nlevel: low",
    "severity": "low",
    "category": "command-and-control",
    "technique": "T1071.004",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "dns",
      "suspicious-tld"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-138",
    "type": "sigma",
    "title": "DNS Query to Tunnelling or Reverse Proxy Service",
    "description": "Detects non-browser processes resolving ngrok, trycloudflare, localtunnel, serveo and similar tunnelling domains.",
    "code": "title: 'DNS Query to Tunnelling or Reverse Proxy Service'\nid: 38da400b-692b-5a87-8004-4f1438292edc\nstatus: test\ndescription: 'Detects non-browser processes resolving ngrok, trycloudflare, localtunnel, serveo and similar tunnelling domains.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.command-and-control\n    - attack.t1572\nlogsource:\n    category: dns_query\n    product: windows\ndetection:\n    selection:\n        QueryName|endswith:\n            - '.ngrok.io'\n            - '.ngrok-free.app'\n            - '.ngrok.app'\n            - '.trycloudflare.com'\n            - '.loca.lt'\n            - '.serveo.net'\n            - '.localhost.run'\n            - '.pinggy.link'\n    condition: selection\nfalsepositives:\n    - 'Developers using tunnels for testing'\nlevel: medium",
    "severity": "medium",
    "category": "command-and-control",
    "technique": "T1572",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "tunnel",
      "dns"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-139",
    "type": "sigma",
    "title": "DNS Query to Cryptocurrency Mining Pool",
    "description": "Detects DNS lookups for well-known Monero and other mining pool domains.",
    "code": "title: 'DNS Query to Cryptocurrency Mining Pool'\nid: 59e1e880-798c-5c6b-8f18-1ab523793011\nstatus: test\ndescription: 'Detects DNS lookups for well-known Monero and other mining pool domains.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.impact\n    - attack.t1496\nlogsource:\n    category: dns_query\n    product: windows\ndetection:\n    selection:\n        QueryName|contains:\n            - 'supportxmr.com'\n            - 'nanopool.org'\n            - 'minexmr.com'\n            - 'moneroocean.stream'\n            - 'hashvault.pro'\n            - '2miners.com'\n            - 'f2pool.com'\n            - 'herominers.com'\n            - 'c3pool.com'\n            - 'xmrpool.eu'\n    condition: selection\nfalsepositives:\n    - 'Sanctioned mining research'\nlevel: high",
    "severity": "high",
    "category": "impact",
    "technique": "T1496",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "cryptomining",
      "dns"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-140",
    "type": "sigma",
    "title": "Cobalt Strike Default Named Pipe Patterns",
    "description": "Detects named pipes matching Cobalt Strike default artifact and post-exploitation pipe names (MSSE-*-server, msagent_*, postex_*, status_*).",
    "code": "title: 'Cobalt Strike Default Named Pipe Patterns'\nid: 2ee7513f-07ea-5a2c-98db-45962e7bfe7d\nstatus: test\ndescription: 'Detects named pipes matching Cobalt Strike default artifact and post-exploitation pipe names (MSSE-*-server, msagent_*, postex_*, status_*).'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.command-and-control\n    - attack.t1071\nlogsource:\n    category: pipe_created\n    product: windows\n    definition: 'Requires Sysmon EventID 17/18 with pipe logging enabled'\ndetection:\n    selection_msse:\n        PipeName|startswith: '\\MSSE-'\n        PipeName|endswith: '-server'\n    selection_other:\n        PipeName|startswith:\n            - '\\msagent_'\n            - '\\postex_'\n            - '\\postex_ssh_'\n            - '\\status_'\n    condition: 1 of selection_*\nfalsepositives:\n    - 'Unlikely; some legitimate software uses status_ pipes'\nlevel: critical",
    "severity": "critical",
    "category": "command-and-control",
    "technique": "T1071",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "cobalt-strike",
      "named-pipe"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-141",
    "type": "sigma",
    "title": "Remote Execution Tool Named Pipe",
    "description": "Detects named pipes created by PsExec, PAExec, RemCom and CSExec when a remote command is executed.",
    "code": "title: 'Remote Execution Tool Named Pipe'\nid: 742bbc4b-fbaf-56af-9e22-b20d8b6477fc\nstatus: test\ndescription: 'Detects named pipes created by PsExec, PAExec, RemCom and CSExec when a remote command is executed.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.lateral-movement\n    - attack.t1569.002\nlogsource:\n    category: pipe_created\n    product: windows\n    definition: 'Requires Sysmon EventID 17/18 with pipe logging enabled'\ndetection:\n    selection:\n        - PipeName|startswith:\n            - '\\PSEXESVC'\n            - '\\RemCom_communicaton'\n            - '\\csexecsvc'\n            - '\\paexec'\n        - PipeName|contains:\n            - '-stdin'\n            - '-stdout'\n            - '-stderr'\n    condition: selection\nfalsepositives:\n    - 'Administrators using Sysinternals PsExec'\nlevel: medium",
    "severity": "medium",
    "category": "lateral-movement",
    "technique": "T1569.002",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "psexec",
      "named-pipe"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-142",
    "type": "sigma",
    "title": "LOLBin Initiating Network Connection to Public IP",
    "description": "Detects rundll32, regsvr32, mshta, msbuild or certutil making outbound connections to non-private addresses.",
    "code": "title: 'LOLBin Initiating Network Connection to Public IP'\nid: 69612315-e0d1-551a-a813-2a799e8fdbfc\nstatus: test\ndescription: 'Detects rundll32, regsvr32, mshta, msbuild or certutil making outbound connections to non-private addresses.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.command-and-control\n    - attack.t1218\nlogsource:\n    category: network_connection\n    product: windows\ndetection:\n    selection:\n        Initiated: 'true'\n        Image|endswith:\n            - '\\rundll32.exe'\n            - '\\regsvr32.exe'\n            - '\\mshta.exe'\n            - '\\msbuild.exe'\n            - '\\certutil.exe'\n            - '\\installutil.exe'\n            - '\\cmstp.exe'\n    filter_private:\n        DestinationIp|cidr:\n            - '10.0.0.0/8'\n            - '172.16.0.0/12'\n            - '192.168.0.0/16'\n            - '127.0.0.0/8'\n            - '169.254.0.0/16'\n            - '::1/128'\n            - 'fe80::/10'\n            - 'fc00::/7'\n    condition: selection and not filter_private\nfalsepositives:\n    - 'Certutil CRL retrieval'\n    - 'Some rundll32-hosted components contacting Microsoft'\nlevel: medium",
    "severity": "medium",
    "category": "command-and-control",
    "technique": "T1218",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "lolbin",
      "network"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-143",
    "type": "sigma",
    "title": "Connection to Common Tor Ports",
    "description": "Detects outbound connections to default Tor relay and SOCKS ports from Windows hosts.",
    "code": "title: 'Connection to Common Tor Ports'\nid: 9860a4b3-27bf-5d00-8a11-ea01e3b1ec09\nstatus: test\ndescription: 'Detects outbound connections to default Tor relay and SOCKS ports from Windows hosts.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.command-and-control\n    - attack.t1090.003\nlogsource:\n    category: network_connection\n    product: windows\ndetection:\n    selection:\n        Initiated: 'true'\n        DestinationPort:\n            - 9001\n            - 9030\n            - 9050\n            - 9051\n            - 9150\n    condition: selection\nfalsepositives:\n    - 'Unrelated services on these ports'\n    - 'Approved Tor Browser use'\nlevel: medium",
    "severity": "medium",
    "category": "command-and-control",
    "technique": "T1090.003",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "tor",
      "network"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-144",
    "type": "sigma",
    "title": "Process Image Tampering Detected",
    "description": "Detects Sysmon EventID 25 'Image is replaced' / 'Image is locked for access', which indicates process hollowing or herpaderping.",
    "code": "title: 'Process Image Tampering Detected'\nid: a94ebb18-d819-5f02-9626-dc7e451e16a6\nstatus: test\ndescription: 'Detects Sysmon EventID 25 ''Image is replaced'' / ''Image is locked for access'', which indicates process hollowing or herpaderping.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1055.012\nlogsource:\n    category: process_tampering\n    product: windows\ndetection:\n    selection:\n        Type:\n            - 'Image is replaced'\n            - 'Image is locked for access'\n    filter:\n        Image|startswith:\n            - 'C:\\Program Files\\'\n            - 'C:\\Program Files (x86)\\'\n    condition: selection and not filter\nfalsepositives:\n    - 'Self-updating applications and some installers'\nlevel: high",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1055.012",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "process-hollowing",
      "sysmon"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-145",
    "type": "sigma",
    "title": "Bash Reverse Shell via /dev/tcp",
    "description": "Detects shells started with an interactive bash redirected to /dev/tcp or /dev/udp, the classic bash reverse shell.",
    "code": "title: 'Bash Reverse Shell via /dev/tcp'\nid: d56bfcac-d45b-544a-9d27-88e3782a48ea\nstatus: test\ndescription: 'Detects shells started with an interactive bash redirected to /dev/tcp or /dev/udp, the classic bash reverse shell.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.execution\n    - attack.t1059.004\nlogsource:\n    category: process_creation\n    product: linux\ndetection:\n    selection:\n        CommandLine|contains:\n            - '/dev/tcp/'\n            - '/dev/udp/'\n    selection_shell:\n        CommandLine|contains:\n            - 'bash -i'\n            - 'sh -i'\n            - '0>&1'\n            - '>&'\n            - 'exec 5<>'\n    condition: all of selection*\nfalsepositives:\n    - 'Rare health-check scripts using /dev/tcp to test ports'\nlevel: critical",
    "severity": "critical",
    "category": "execution",
    "technique": "T1059.004",
    "author": "OSINTrix pack",
    "platform": "Linux",
    "tags": [
      "reverse-shell",
      "bash"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-146",
    "type": "sigma",
    "title": "Netcat Reverse or Bind Shell",
    "description": "Detects nc/ncat/netcat invoked with -e or -c to attach a shell to a network socket.",
    "code": "title: 'Netcat Reverse or Bind Shell'\nid: b33a39aa-5e81-5fa7-be2d-a55562baffe5\nstatus: test\ndescription: 'Detects nc/ncat/netcat invoked with -e or -c to attach a shell to a network socket.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.execution\n    - attack.t1059.004\nlogsource:\n    category: process_creation\n    product: linux\ndetection:\n    selection_img:\n        Image|endswith:\n            - '/nc'\n            - '/ncat'\n            - '/netcat'\n            - '/nc.traditional'\n            - '/nc.openbsd'\n    selection_exec:\n        CommandLine|contains:\n            - ' -e /bin/'\n            - ' -c /bin/'\n            - ' -e sh'\n            - ' -e bash'\n            - ' --exec '\n            - ' --sh-exec '\n    condition: all of selection_*\nfalsepositives:\n    - 'Penetration testing'\nlevel: critical",
    "severity": "critical",
    "category": "execution",
    "technique": "T1059.004",
    "author": "OSINTrix pack",
    "platform": "Linux",
    "tags": [
      "reverse-shell",
      "netcat"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-147",
    "type": "sigma",
    "title": "Python or Perl Socket Reverse Shell One-Liner",
    "description": "Detects python/perl/ruby/php one-liners that open a socket and spawn a shell or pty.",
    "code": "title: 'Python or Perl Socket Reverse Shell One-Liner'\nid: 62258733-0d1b-55d9-9019-6f30676d8218\nstatus: test\ndescription: 'Detects python/perl/ruby/php one-liners that open a socket and spawn a shell or pty.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.execution\n    - attack.t1059.006\nlogsource:\n    category: process_creation\n    product: linux\ndetection:\n    selection_img:\n        Image|contains:\n            - '/python'\n            - '/perl'\n            - '/ruby'\n            - '/php'\n    selection_inline:\n        CommandLine|contains:\n            - ' -c '\n            - ' -e '\n            - ' -r '\n    selection_sock:\n        CommandLine|contains:\n            - 'socket'\n            - 'TCPSocket'\n            - 'fsockopen'\n    selection_shell:\n        CommandLine|contains:\n            - 'pty.spawn'\n            - '/bin/sh'\n            - '/bin/bash'\n            - 'subprocess'\n            - 'dup2'\n            - 'exec('\n    condition: all of selection_*\nfalsepositives:\n    - 'Developers testing network code'\nlevel: critical",
    "severity": "critical",
    "category": "execution",
    "technique": "T1059.006",
    "author": "OSINTrix pack",
    "platform": "Linux",
    "tags": [
      "reverse-shell",
      "python"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-148",
    "type": "sigma",
    "title": "Named Pipe Reverse Shell With mkfifo",
    "description": "Detects the mkfifo + netcat/openssl reverse shell pattern that works with netcat builds lacking -e.",
    "code": "title: 'Named Pipe Reverse Shell With mkfifo'\nid: 87d93fdf-96e0-5309-a727-a7f14f916654\nstatus: test\ndescription: 'Detects the mkfifo + netcat/openssl reverse shell pattern that works with netcat builds lacking -e.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.execution\n    - attack.t1059.004\nlogsource:\n    category: process_creation\n    product: linux\ndetection:\n    selection:\n        CommandLine|contains|all:\n            - 'mkfifo'\n            - '/bin/'\n    selection_net:\n        CommandLine|contains:\n            - 'nc '\n            - 'ncat '\n            - 'openssl s_client'\n            - 'telnet '\n    condition: all of selection*\nfalsepositives:\n    - 'None expected'\nlevel: critical",
    "severity": "critical",
    "category": "execution",
    "technique": "T1059.004",
    "author": "OSINTrix pack",
    "platform": "Linux",
    "tags": [
      "reverse-shell",
      "mkfifo"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-149",
    "type": "sigma",
    "title": "Socat Reverse Shell",
    "description": "Detects socat connecting a TCP or SSL stream to exec:/system: with a shell.",
    "code": "title: 'Socat Reverse Shell'\nid: a7e3a624-bd4c-5f26-bf97-d8447d27cd77\nstatus: test\ndescription: 'Detects socat connecting a TCP or SSL stream to exec:/system: with a shell.'\nreferences:\n    - https://gtfobins.github.io/\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.execution\n    - attack.t1059.004\nlogsource:\n    category: process_creation\n    product: linux\ndetection:\n    selection:\n        Image|endswith: '/socat'\n        CommandLine|contains:\n            - 'exec:'\n            - 'system:'\n            - 'EXEC:'\n            - 'SYSTEM:'\n    selection_net:\n        CommandLine|contains:\n            - 'tcp:'\n            - 'TCP:'\n            - 'tcp-connect'\n            - 'TCP4:'\n            - 'openssl:'\n            - 'OPENSSL:'\n    condition: all of selection*\nfalsepositives:\n    - 'Engineers using socat for port relays with exec helpers'\nlevel: high",
    "severity": "high",
    "category": "execution",
    "technique": "T1059.004",
    "author": "OSINTrix pack",
    "platform": "Linux",
    "tags": [
      "reverse-shell",
      "socat"
    ],
    "references": [
      "https://gtfobins.github.io/",
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-150",
    "type": "sigma",
    "title": "Remote Script Piped Directly to Shell",
    "description": "Detects curl or wget output piped into sh/bash, which executes remote content without saving it.",
    "code": "title: 'Remote Script Piped Directly to Shell'\nid: 99ebaddb-1f2f-54f0-b28b-d08ae8ed4b7c\nstatus: test\ndescription: 'Detects curl or wget output piped into sh/bash, which executes remote content without saving it.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.execution\n    - attack.t1059.004\nlogsource:\n    category: process_creation\n    product: linux\ndetection:\n    selection_dl:\n        CommandLine|contains:\n            - 'curl '\n            - 'wget '\n    selection_pipe:\n        CommandLine|contains:\n            - '| sh'\n            - '|sh'\n            - '| bash'\n            - '|bash'\n            - '| /bin/sh'\n            - '| /bin/bash'\n            - '| sudo bash'\n            - '| python'\n    condition: all of selection_*\nfalsepositives:\n    - 'Vendor install one-liners (Docker, Homebrew, rustup) run by engineers'\nlevel: medium",
    "severity": "medium",
    "category": "execution",
    "technique": "T1059.004",
    "author": "OSINTrix pack",
    "platform": "Linux",
    "tags": [
      "curl-pipe-shell",
      "download"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-151",
    "type": "sigma",
    "title": "Base64 Decoded Payload Piped to Shell",
    "description": "Detects base64 -d / --decode output being piped into a shell interpreter.",
    "code": "title: 'Base64 Decoded Payload Piped to Shell'\nid: 8fac5ec9-ec62-56a8-8df2-57b9033c9d40\nstatus: test\ndescription: 'Detects base64 -d / --decode output being piped into a shell interpreter.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1140\nlogsource:\n    category: process_creation\n    product: linux\ndetection:\n    selection_b64:\n        CommandLine|contains:\n            - 'base64 -d'\n            - 'base64 --decode'\n            - 'base64 -D'\n    selection_pipe:\n        CommandLine|contains:\n            - '| sh'\n            - '|sh'\n            - '| bash'\n            - '|bash'\n            - '| python'\n    condition: all of selection_*\nfalsepositives:\n    - 'Configuration management templates that ship encoded scripts'\nlevel: high",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1140",
    "author": "OSINTrix pack",
    "platform": "Linux",
    "tags": [
      "base64",
      "obfuscation"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-152",
    "type": "sigma",
    "title": "Download to Temp Directory Then Made Executable",
    "description": "Detects a single command line that downloads a file into /tmp, /var/tmp or /dev/shm and marks it executable.",
    "code": "title: 'Download to Temp Directory Then Made Executable'\nid: 51eca53c-9195-5ed9-a96a-f2c4b07d8174\nstatus: test\ndescription: 'Detects a single command line that downloads a file into /tmp, /var/tmp or /dev/shm and marks it executable.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.command-and-control\n    - attack.t1105\nlogsource:\n    category: process_creation\n    product: linux\ndetection:\n    selection_dl:\n        CommandLine|contains:\n            - 'curl '\n            - 'wget '\n    selection_chmod:\n        CommandLine|contains: 'chmod +x'\n    selection_path:\n        CommandLine|contains:\n            - '/tmp/'\n            - '/var/tmp/'\n            - '/dev/shm/'\n    condition: all of selection_*\nfalsepositives:\n    - 'Build scripts on CI runners'\nlevel: high",
    "severity": "high",
    "category": "command-and-control",
    "technique": "T1105",
    "author": "OSINTrix pack",
    "platform": "Linux",
    "tags": [
      "download",
      "staging"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-153",
    "type": "sigma",
    "title": "Execution From Shared Memory or Hidden Temp Path",
    "description": "Detects processes executed from /dev/shm or hidden dot-directories in /tmp and /var/tmp.",
    "code": "title: 'Execution From Shared Memory or Hidden Temp Path'\nid: 818a8eea-5705-51a8-9c96-80d673df9a43\nstatus: test\ndescription: 'Detects processes executed from /dev/shm or hidden dot-directories in /tmp and /var/tmp.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1564.001\nlogsource:\n    category: process_creation\n    product: linux\ndetection:\n    selection:\n        - Image|startswith: '/dev/shm/'\n        - Image|contains:\n            - '/tmp/.'\n            - '/var/tmp/.'\n    condition: selection\nfalsepositives:\n    - 'Some sandboxed browsers and JIT runtimes use /dev/shm'\nlevel: high",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1564.001",
    "author": "OSINTrix pack",
    "platform": "Linux",
    "tags": [
      "hidden-files",
      "staging"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-154",
    "type": "sigma",
    "title": "Cron Job File Written",
    "description": "Detects file writes to system or per-user cron locations.",
    "code": "title: 'Cron Job File Written'\nid: 011df238-b7c6-5fd0-a205-6a44a0f09b6e\nstatus: test\ndescription: 'Detects file writes to system or per-user cron locations.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1053.003\nlogsource:\n    category: file_event\n    product: linux\ndetection:\n    selection:\n        TargetFilename|startswith:\n            - '/etc/cron.d/'\n            - '/etc/cron.daily/'\n            - '/etc/cron.hourly/'\n            - '/etc/cron.weekly/'\n            - '/etc/cron.monthly/'\n            - '/var/spool/cron/'\n            - '/etc/crontab'\n    filter_pkg:\n        Image|endswith:\n            - '/dpkg'\n            - '/rpm'\n            - '/yum'\n            - '/dnf'\n            - '/apt'\n    condition: selection and not filter_pkg\nfalsepositives:\n    - 'Administrators and configuration management adding cron jobs'\nlevel: medium",
    "severity": "medium",
    "category": "persistence",
    "technique": "T1053.003",
    "author": "OSINTrix pack",
    "platform": "Linux",
    "tags": [
      "cron",
      "persistence"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-155",
    "type": "sigma",
    "title": "SSH Authorized Keys File Modified",
    "description": "Detects writes to authorized_keys files, which grant persistent SSH access.",
    "code": "title: 'SSH Authorized Keys File Modified'\nid: 15c0eaab-f563-5bbb-b756-535b7007991c\nstatus: test\ndescription: 'Detects writes to authorized_keys files, which grant persistent SSH access.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1098.004\nlogsource:\n    category: file_event\n    product: linux\ndetection:\n    selection:\n        TargetFilename|endswith:\n            - '/.ssh/authorized_keys'\n            - '/.ssh/authorized_keys2'\n    filter:\n        Image|endswith:\n            - '/google_guest_agent'\n            - '/cloud-init'\n            - '/amazon-ssm-agent'\n    condition: selection and not filter\nfalsepositives:\n    - 'Users adding their own keys'\n    - 'Cloud agents provisioning keys'\nlevel: medium",
    "severity": "medium",
    "category": "persistence",
    "technique": "T1098.004",
    "author": "OSINTrix pack",
    "platform": "Linux",
    "tags": [
      "ssh",
      "persistence"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-156",
    "type": "sigma",
    "title": "Systemd Service Unit Created",
    "description": "Detects creation of systemd unit files in system or user directories outside package managers.",
    "code": "title: 'Systemd Service Unit Created'\nid: 4e7ffecc-6f88-50cb-ab34-06ca29a54060\nstatus: test\ndescription: 'Detects creation of systemd unit files in system or user directories outside package managers.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1543.002\nlogsource:\n    category: file_event\n    product: linux\ndetection:\n    selection:\n        TargetFilename|startswith:\n            - '/etc/systemd/system/'\n            - '/usr/lib/systemd/system/'\n            - '/lib/systemd/system/'\n        TargetFilename|endswith:\n            - '.service'\n            - '.timer'\n    selection_user:\n        TargetFilename|contains: '/.config/systemd/user/'\n    filter_pkg:\n        Image|endswith:\n            - '/dpkg'\n            - '/rpm'\n            - '/dnf'\n            - '/yum'\n            - '/systemd'\n    condition: 1 of selection* and not filter_pkg\nfalsepositives:\n    - 'Administrators deploying services manually'\nlevel: medium",
    "severity": "medium",
    "category": "persistence",
    "technique": "T1543.002",
    "author": "OSINTrix pack",
    "platform": "Linux",
    "tags": [
      "systemd",
      "persistence"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-157",
    "type": "sigma",
    "title": "Dynamic Linker Preload File Modified",
    "description": "Detects writes to /etc/ld.so.preload, used by userland rootkits to inject a shared library into every process.",
    "code": "title: 'Dynamic Linker Preload File Modified'\nid: 3f5144c3-67ab-5f7e-a450-57a83be822ea\nstatus: test\ndescription: 'Detects writes to /etc/ld.so.preload, used by userland rootkits to inject a shared library into every process.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1574.006\nlogsource:\n    category: file_event\n    product: linux\ndetection:\n    selection:\n        TargetFilename: '/etc/ld.so.preload'\n    condition: selection\nfalsepositives:\n    - 'Rare legitimate use by performance tooling'\nlevel: high",
    "severity": "high",
    "category": "persistence",
    "technique": "T1574.006",
    "author": "OSINTrix pack",
    "platform": "Linux",
    "tags": [
      "ld-preload",
      "rootkit"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-158",
    "type": "sigma",
    "title": "LD_PRELOAD Set on Command Line",
    "description": "Detects commands that set LD_PRELOAD inline, used for library injection and privilege escalation through sudo env_keep.",
    "code": "title: 'LD_PRELOAD Set on Command Line'\nid: f5f99997-a65f-5e68-ae74-07723b726e35\nstatus: test\ndescription: 'Detects commands that set LD_PRELOAD inline, used for library injection and privilege escalation through sudo env_keep.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1574.006\nlogsource:\n    category: process_creation\n    product: linux\ndetection:\n    selection:\n        CommandLine|contains: 'LD_PRELOAD='\n    filter:\n        CommandLine|contains:\n            - 'libjemalloc'\n            - 'libtcmalloc'\n            - 'libfaketime'\n    condition: selection and not filter\nfalsepositives:\n    - 'Allocator or test tooling preloads'\nlevel: medium",
    "severity": "medium",
    "category": "defense-evasion",
    "technique": "T1574.006",
    "author": "OSINTrix pack",
    "platform": "Linux",
    "tags": [
      "ld-preload",
      "injection"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-159",
    "type": "sigma",
    "title": "PAM Configuration or Module Modified",
    "description": "Detects writes to /etc/pam.d or PAM module directories, used to backdoor authentication.",
    "code": "title: 'PAM Configuration or Module Modified'\nid: 515f14af-4254-5596-99a1-345595eb3ef8\nstatus: test\ndescription: 'Detects writes to /etc/pam.d or PAM module directories, used to backdoor authentication.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.credential-access\n    - attack.t1556.003\nlogsource:\n    category: file_event\n    product: linux\ndetection:\n    selection:\n        - TargetFilename|startswith: '/etc/pam.d/'\n        - TargetFilename|contains:\n            - '/lib/security/pam_'\n            - '/lib64/security/pam_'\n            - '/lib/x86_64-linux-gnu/security/pam_'\n    filter_pkg:\n        Image|endswith:\n            - '/dpkg'\n            - '/rpm'\n            - '/dnf'\n            - '/yum'\n            - '/authselect'\n            - '/pam-auth-update'\n    condition: selection and not filter_pkg\nfalsepositives:\n    - 'Configuration management changes to PAM'\nlevel: high",
    "severity": "high",
    "category": "credential-access",
    "technique": "T1556.003",
    "author": "OSINTrix pack",
    "platform": "Linux",
    "tags": [
      "pam",
      "backdoor"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-160",
    "type": "sigma",
    "title": "Sudoers File Modified",
    "description": "Detects writes to /etc/sudoers or files in /etc/sudoers.d.",
    "code": "title: 'Sudoers File Modified'\nid: df22bc11-ef21-5283-ac9c-45d81e0eab95\nstatus: test\ndescription: 'Detects writes to /etc/sudoers or files in /etc/sudoers.d.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.privilege-escalation\n    - attack.t1548.003\nlogsource:\n    category: file_event\n    product: linux\ndetection:\n    selection:\n        - TargetFilename: '/etc/sudoers'\n        - TargetFilename|startswith: '/etc/sudoers.d/'\n    filter_pkg:\n        Image|endswith:\n            - '/dpkg'\n            - '/rpm'\n            - '/visudo'\n    condition: selection and not filter_pkg\nfalsepositives:\n    - 'Configuration management granting sudo rights'\nlevel: high",
    "severity": "high",
    "category": "privilege-escalation",
    "technique": "T1548.003",
    "author": "OSINTrix pack",
    "platform": "Linux",
    "tags": [
      "sudo",
      "privilege-escalation"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-161",
    "type": "sigma",
    "title": "NOPASSWD Sudo Rule Appended From Shell",
    "description": "Detects echo/tee commands that append a NOPASSWD rule to sudoers.",
    "code": "title: 'NOPASSWD Sudo Rule Appended From Shell'\nid: 90479148-d567-5a3c-bd49-f635c0030597\nstatus: test\ndescription: 'Detects echo/tee commands that append a NOPASSWD rule to sudoers.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.privilege-escalation\n    - attack.t1548.003\nlogsource:\n    category: process_creation\n    product: linux\ndetection:\n    selection:\n        CommandLine|contains|all:\n            - 'NOPASSWD'\n            - 'sudoers'\n    condition: selection\nfalsepositives:\n    - 'Provisioning scripts for build agents'\nlevel: high",
    "severity": "high",
    "category": "privilege-escalation",
    "technique": "T1548.003",
    "author": "OSINTrix pack",
    "platform": "Linux",
    "tags": [
      "sudo",
      "privilege-escalation"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-162",
    "type": "sigma",
    "title": "Account With UID 0 Created",
    "description": "Detects useradd/usermod creating or changing an account to UID 0, or appending a root-equivalent line to /etc/passwd.",
    "code": "title: 'Account With UID 0 Created'\nid: a0ad270c-8c36-56dc-b8cf-78a2bf3462f0\nstatus: test\ndescription: 'Detects useradd/usermod creating or changing an account to UID 0, or appending a root-equivalent line to /etc/passwd.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1136.001\nlogsource:\n    category: process_creation\n    product: linux\ndetection:\n    selection_useradd:\n        Image|endswith:\n            - '/useradd'\n            - '/usermod'\n        CommandLine|contains:\n            - '-u 0'\n            - '--uid 0'\n        CommandLine|contains|all:\n            - '-o'\n    selection_echo:\n        CommandLine|contains|all:\n            - ':0:0:'\n            - '/etc/passwd'\n    condition: 1 of selection_*\nfalsepositives:\n    - 'None expected'\nlevel: critical",
    "severity": "critical",
    "category": "persistence",
    "technique": "T1136.001",
    "author": "OSINTrix pack",
    "platform": "Linux",
    "tags": [
      "account-creation",
      "root"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-163",
    "type": "sigma",
    "title": "Kernel Module Loaded via Syscall",
    "description": "Detects init_module or finit_module syscalls recorded by auditd, i.e. a kernel module being inserted.",
    "code": "title: 'Kernel Module Loaded via Syscall'\nid: 2f5c8c2c-fdf4-5813-8c2f-887b7a9b9d45\nstatus: test\ndescription: 'Detects init_module or finit_module syscalls recorded by auditd, i.e. a kernel module being inserted.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1547.006\nlogsource:\n    product: linux\n    service: auditd\ndetection:\n    selection:\n        type: 'SYSCALL'\n        SYSCALL:\n            - 'init_module'\n            - 'finit_module'\n    condition: selection\nfalsepositives:\n    - 'Driver installation during patching (DKMS)'\nlevel: medium",
    "severity": "medium",
    "category": "persistence",
    "technique": "T1547.006",
    "author": "OSINTrix pack",
    "platform": "Linux",
    "tags": [
      "kernel-module",
      "rootkit",
      "auditd"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-164",
    "type": "sigma",
    "title": "Kernel Module Inserted From Temporary Path",
    "description": "Detects insmod or modprobe loading a .ko file from /tmp, /dev/shm or a home directory.",
    "code": "title: 'Kernel Module Inserted From Temporary Path'\nid: ee966623-ccc4-569e-9eb7-beb30d401d07\nstatus: test\ndescription: 'Detects insmod or modprobe loading a .ko file from /tmp, /dev/shm or a home directory.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1547.006\nlogsource:\n    category: process_creation\n    product: linux\ndetection:\n    selection:\n        Image|endswith:\n            - '/insmod'\n            - '/modprobe'\n        CommandLine|contains:\n            - '/tmp/'\n            - '/dev/shm/'\n            - '/home/'\n            - '/var/tmp/'\n    condition: selection\nfalsepositives:\n    - 'Developers testing their own kernel modules'\nlevel: high",
    "severity": "high",
    "category": "persistence",
    "technique": "T1547.006",
    "author": "OSINTrix pack",
    "platform": "Linux",
    "tags": [
      "kernel-module",
      "rootkit"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-165",
    "type": "sigma",
    "title": "SetUID Bit Set With Chmod",
    "description": "Detects chmod setting the setuid or setgid bit (u+s, g+s, 4xxx, 2xxx).",
    "code": "title: 'SetUID Bit Set With Chmod'\nid: 04f6318f-e810-5c3b-9158-0cd35388cde4\nstatus: test\ndescription: 'Detects chmod setting the setuid or setgid bit (u+s, g+s, 4xxx, 2xxx).'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.privilege-escalation\n    - attack.t1548.001\nlogsource:\n    category: process_creation\n    product: linux\ndetection:\n    selection:\n        Image|endswith: '/chmod'\n        CommandLine|contains:\n            - 'u+s'\n            - 'g+s'\n            - ' 4755 '\n            - ' 4777 '\n            - ' 6755 '\n            - ' 2755 '\n    condition: selection\nfalsepositives:\n    - 'Package post-install scripts'\nlevel: medium",
    "severity": "medium",
    "category": "privilege-escalation",
    "technique": "T1548.001",
    "author": "OSINTrix pack",
    "platform": "Linux",
    "tags": [
      "setuid"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-166",
    "type": "sigma",
    "title": "Dangerous File Capabilities Assigned With Setcap",
    "description": "Detects setcap granting cap_setuid, cap_sys_admin, cap_dac_read_search or cap_sys_ptrace to a binary.",
    "code": "title: 'Dangerous File Capabilities Assigned With Setcap'\nid: c2dceac5-729f-5fb5-aa36-5b25e69ce1ca\nstatus: test\ndescription: 'Detects setcap granting cap_setuid, cap_sys_admin, cap_dac_read_search or cap_sys_ptrace to a binary.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.privilege-escalation\n    - attack.t1548\nlogsource:\n    category: process_creation\n    product: linux\ndetection:\n    selection:\n        Image|endswith: '/setcap'\n        CommandLine|contains:\n            - 'cap_setuid'\n            - 'cap_sys_admin'\n            - 'cap_dac_read_search'\n            - 'cap_dac_override'\n            - 'cap_sys_ptrace'\n    condition: selection\nfalsepositives:\n    - 'Container runtimes and network tools (cap_net_raw is excluded by design)'\nlevel: high",
    "severity": "high",
    "category": "privilege-escalation",
    "technique": "T1548",
    "author": "OSINTrix pack",
    "platform": "Linux",
    "tags": [
      "capabilities"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-167",
    "type": "sigma",
    "title": "GTFOBins Shell Escape via SUID Binary",
    "description": "Detects common GTFOBins shell escapes such as find -exec /bin/sh -p, vim -c ':!/bin/sh' or awk system().",
    "code": "title: 'GTFOBins Shell Escape via SUID Binary'\nid: bc6838ee-200b-5476-a4e6-687b8d5af4b7\nstatus: test\ndescription: 'Detects common GTFOBins shell escapes such as find -exec /bin/sh -p, vim -c '':!/bin/sh'' or awk system().'\nreferences:\n    - https://gtfobins.github.io/\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.privilege-escalation\n    - attack.t1548.001\nlogsource:\n    category: process_creation\n    product: linux\ndetection:\n    selection_find:\n        Image|endswith: '/find'\n        CommandLine|contains|all:\n            - '-exec'\n            - '/bin/sh'\n    selection_p:\n        CommandLine|contains:\n            - '/bin/sh -p'\n            - '/bin/bash -p'\n    selection_vim:\n        Image|endswith:\n            - '/vim'\n            - '/vi'\n        CommandLine|contains: ':!/bin/sh'\n    selection_awk:\n        Image|endswith:\n            - '/awk'\n            - '/gawk'\n        CommandLine|contains: 'system(\"/bin/sh\")'\n    condition: 1 of selection_*\nfalsepositives:\n    - 'Administrators using find -exec in maintenance scripts'\nlevel: high",
    "severity": "high",
    "category": "privilege-escalation",
    "technique": "T1548.001",
    "author": "OSINTrix pack",
    "platform": "Linux",
    "tags": [
      "gtfobins",
      "suid"
    ],
    "references": [
      "https://gtfobins.github.io/",
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-168",
    "type": "sigma",
    "title": "Shell History Cleared or Disabled",
    "description": "Detects commands that clear history or disable history recording.",
    "code": "title: 'Shell History Cleared or Disabled'\nid: a7f4ca4e-a658-5a27-b1df-967c99d17cfc\nstatus: test\ndescription: 'Detects commands that clear history or disable history recording.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1070.003\nlogsource:\n    category: process_creation\n    product: linux\ndetection:\n    selection:\n        CommandLine|contains:\n            - 'history -c'\n            - 'rm ~/.bash_history'\n            - 'rm -f ~/.bash_history'\n            - 'rm -rf ~/.bash_history'\n            - 'unset HISTFILE'\n            - 'export HISTFILESIZE=0'\n            - 'export HISTSIZE=0'\n            - 'HISTFILE=/dev/null'\n            - 'ln -sf /dev/null ~/.bash_history'\n            - '> ~/.bash_history'\n            - 'set +o history'\n    condition: selection\nfalsepositives:\n    - 'Users with privacy-conscious shell configurations'\nlevel: medium",
    "severity": "medium",
    "category": "defense-evasion",
    "technique": "T1070.003",
    "author": "OSINTrix pack",
    "platform": "Linux",
    "tags": [
      "history",
      "anti-forensics"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-169",
    "type": "sigma",
    "title": "System Logs Truncated or Deleted",
    "description": "Detects commands that delete, truncate or shred authentication and system logs.",
    "code": "title: 'System Logs Truncated or Deleted'\nid: c2f098c0-b00a-5b82-ac1b-cb22429a7b90\nstatus: test\ndescription: 'Detects commands that delete, truncate or shred authentication and system logs.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1070.002\nlogsource:\n    category: process_creation\n    product: linux\ndetection:\n    selection_cmd:\n        CommandLine|contains:\n            - 'rm '\n            - 'shred '\n            - 'truncate '\n            - 'cat /dev/null >'\n            - '> /var/log'\n    selection_path:\n        CommandLine|contains:\n            - '/var/log/auth.log'\n            - '/var/log/secure'\n            - '/var/log/wtmp'\n            - '/var/log/btmp'\n            - '/var/log/lastlog'\n            - '/var/log/syslog'\n            - '/var/log/messages'\n            - '/var/log/audit/audit.log'\n    condition: all of selection_*\nfalsepositives:\n    - 'Log rotation scripts that do not use logrotate'\nlevel: high",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1070.002",
    "author": "OSINTrix pack",
    "platform": "Linux",
    "tags": [
      "log-clearing",
      "anti-forensics"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-170",
    "type": "sigma",
    "title": "Immutable Attribute Set With Chattr",
    "description": "Detects chattr +i or +a on files, used to lock persistence files or prevent clean-up.",
    "code": "title: 'Immutable Attribute Set With Chattr'\nid: 87f3c08b-db85-564d-8c9d-2851247870fc\nstatus: test\ndescription: 'Detects chattr +i or +a on files, used to lock persistence files or prevent clean-up.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1222.002\nlogsource:\n    category: process_creation\n    product: linux\ndetection:\n    selection:\n        Image|endswith: '/chattr'\n        CommandLine|contains:\n            - '+i'\n            - '+a'\n    condition: selection\nfalsepositives:\n    - 'Administrators protecting configuration files'\nlevel: medium",
    "severity": "medium",
    "category": "defense-evasion",
    "technique": "T1222.002",
    "author": "OSINTrix pack",
    "platform": "Linux",
    "tags": [
      "chattr",
      "persistence"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-171",
    "type": "sigma",
    "title": "File Timestamps Altered With Touch",
    "description": "Detects touch -r (copy reference timestamps) or -t/-d with explicit timestamps on system paths.",
    "code": "title: 'File Timestamps Altered With Touch'\nid: 9a043900-8b9e-59f9-ab56-49c24398d697\nstatus: test\ndescription: 'Detects touch -r (copy reference timestamps) or -t/-d with explicit timestamps on system paths.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1070.006\nlogsource:\n    category: process_creation\n    product: linux\ndetection:\n    selection:\n        Image|endswith: '/touch'\n        CommandLine|contains:\n            - ' -r '\n            - ' -t '\n            - ' --reference'\n    selection_path:\n        CommandLine|contains:\n            - '/bin/'\n            - '/sbin/'\n            - '/usr/'\n            - '/etc/'\n            - '/lib'\n    condition: all of selection*\nfalsepositives:\n    - 'Build systems normalising timestamps'\nlevel: low",
    "severity": "low",
    "category": "defense-evasion",
    "technique": "T1070.006",
    "author": "OSINTrix pack",
    "platform": "Linux",
    "tags": [
      "timestomp"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-172",
    "type": "sigma",
    "title": "Linux Firewall Disabled or Flushed",
    "description": "Detects iptables/nftables flushes and ufw/firewalld being stopped or disabled.",
    "code": "title: 'Linux Firewall Disabled or Flushed'\nid: 9b3a0fd3-6251-5156-95f0-911f699451e7\nstatus: test\ndescription: 'Detects iptables/nftables flushes and ufw/firewalld being stopped or disabled.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1562.004\nlogsource:\n    category: process_creation\n    product: linux\ndetection:\n    selection_ipt:\n        Image|endswith:\n            - '/iptables'\n            - '/ip6tables'\n            - '/nft'\n        CommandLine|contains:\n            - ' -F'\n            - ' --flush'\n            - 'flush ruleset'\n    selection_svc:\n        CommandLine|contains:\n            - 'ufw disable'\n            - 'systemctl stop firewalld'\n            - 'systemctl disable firewalld'\n            - 'service iptables stop'\n    condition: 1 of selection_*\nfalsepositives:\n    - 'Administrators reloading firewall rules'\nlevel: medium",
    "severity": "medium",
    "category": "defense-evasion",
    "technique": "T1562.004",
    "author": "OSINTrix pack",
    "platform": "Linux",
    "tags": [
      "firewall"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-173",
    "type": "sigma",
    "title": "Audit or Logging Daemon Stopped",
    "description": "Detects auditd, rsyslog, syslog-ng or journald being stopped or disabled, or audit rules deleted.",
    "code": "title: 'Audit or Logging Daemon Stopped'\nid: 9bf81c86-16ee-5af9-a6fb-6107c68ff0ee\nstatus: test\ndescription: 'Detects auditd, rsyslog, syslog-ng or journald being stopped or disabled, or audit rules deleted.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1562.001\nlogsource:\n    category: process_creation\n    product: linux\ndetection:\n    selection_svc:\n        CommandLine|contains:\n            - 'stop auditd'\n            - 'disable auditd'\n            - 'stop rsyslog'\n            - 'disable rsyslog'\n            - 'stop syslog-ng'\n            - 'stop systemd-journald'\n            - 'auditd stop'\n    selection_rules:\n        Image|endswith: '/auditctl'\n        CommandLine|contains:\n            - ' -D'\n            - ' -e 0'\n    condition: 1 of selection_*\nfalsepositives:\n    - 'Maintenance on logging infrastructure'\nlevel: high",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1562.001",
    "author": "OSINTrix pack",
    "platform": "Linux",
    "tags": [
      "auditd",
      "logging"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-174",
    "type": "sigma",
    "title": "Shadow File Read or Unshadowed",
    "description": "Detects direct reads of /etc/shadow or use of unshadow, which prepare password hashes for cracking.",
    "code": "title: 'Shadow File Read or Unshadowed'\nid: 5d6839a5-1e8a-5eb0-a4f5-47b49cdd2548\nstatus: test\ndescription: 'Detects direct reads of /etc/shadow or use of unshadow, which prepare password hashes for cracking.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.credential-access\n    - attack.t1003.008\nlogsource:\n    category: process_creation\n    product: linux\ndetection:\n    selection_read:\n        Image|endswith:\n            - '/cat'\n            - '/head'\n            - '/tail'\n            - '/less'\n            - '/more'\n            - '/cp'\n            - '/base64'\n            - '/xxd'\n        CommandLine|contains: '/etc/shadow'\n    selection_unshadow:\n        Image|endswith: '/unshadow'\n    condition: 1 of selection_*\nfalsepositives:\n    - 'Administrators auditing accounts'\nlevel: high",
    "severity": "high",
    "category": "credential-access",
    "technique": "T1003.008",
    "author": "OSINTrix pack",
    "platform": "Linux",
    "tags": [
      "shadow",
      "credential-dump"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-175",
    "type": "sigma",
    "title": "SSH Private Key Search or Access",
    "description": "Detects searches for private keys (id_rsa, id_ed25519, *.pem) or reads of key files by shell utilities.",
    "code": "title: 'SSH Private Key Search or Access'\nid: 04c84d22-825e-5cc8-a931-0b86525f8ea5\nstatus: test\ndescription: 'Detects searches for private keys (id_rsa, id_ed25519, *.pem) or reads of key files by shell utilities.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.credential-access\n    - attack.t1552.004\nlogsource:\n    category: process_creation\n    product: linux\ndetection:\n    selection_find:\n        Image|endswith:\n            - '/find'\n            - '/locate'\n            - '/grep'\n        CommandLine|contains:\n            - 'id_rsa'\n            - 'id_ed25519'\n            - 'id_ecdsa'\n            - '.pem'\n            - 'BEGIN OPENSSH PRIVATE KEY'\n            - 'BEGIN RSA PRIVATE KEY'\n    selection_cat:\n        Image|endswith:\n            - '/cat'\n            - '/base64'\n        CommandLine|contains:\n            - '/.ssh/id_'\n    condition: 1 of selection_*\nfalsepositives:\n    - 'Users inspecting their own keys'\nlevel: medium",
    "severity": "medium",
    "category": "credential-access",
    "technique": "T1552.004",
    "author": "OSINTrix pack",
    "platform": "Linux",
    "tags": [
      "ssh-keys",
      "private-keys"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-176",
    "type": "sigma",
    "title": "Linux Privilege Escalation Enumeration Script",
    "description": "Detects execution of LinPEAS, LinEnum, linux-exploit-suggester, pspy and similar enumeration helpers.",
    "code": "title: 'Linux Privilege Escalation Enumeration Script'\nid: f92fe0d0-c854-5ec2-9829-fbf8036e99e5\nstatus: test\ndescription: 'Detects execution of LinPEAS, LinEnum, linux-exploit-suggester, pspy and similar enumeration helpers.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.discovery\n    - attack.t1082\nlogsource:\n    category: process_creation\n    product: linux\ndetection:\n    selection:\n        CommandLine|contains:\n            - 'linpeas'\n            - 'LinEnum'\n            - 'linux-exploit-suggester'\n            - 'les.sh'\n            - 'pspy64'\n            - 'pspy32'\n            - 'lse.sh'\n            - 'unix-privesc-check'\n    condition: selection\nfalsepositives:\n    - 'Security assessments'\nlevel: high",
    "severity": "high",
    "category": "discovery",
    "technique": "T1082",
    "author": "OSINTrix pack",
    "platform": "Linux",
    "tags": [
      "privesc",
      "enumeration"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-177",
    "type": "sigma",
    "title": "Cryptocurrency Miner Command Line",
    "description": "Detects miner arguments such as stratum URLs, --donate-level or -a rx/0 on Linux.",
    "code": "title: 'Cryptocurrency Miner Command Line'\nid: 65fe4608-fe19-5c7e-beb1-59cac33758a9\nstatus: test\ndescription: 'Detects miner arguments such as stratum URLs, --donate-level or -a rx/0 on Linux.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.impact\n    - attack.t1496\nlogsource:\n    category: process_creation\n    product: linux\ndetection:\n    selection:\n        CommandLine|contains:\n            - 'stratum+tcp://'\n            - 'stratum+ssl://'\n            - 'stratum2+tcp://'\n            - '--donate-level'\n            - '--cpu-max-threads-hint'\n            - ' -a rx/0'\n            - '--algo=rx/0'\n            - '--coin=monero'\n    condition: selection\nfalsepositives:\n    - 'Sanctioned mining'\nlevel: high",
    "severity": "high",
    "category": "impact",
    "technique": "T1496",
    "author": "OSINTrix pack",
    "platform": "Linux",
    "tags": [
      "cryptomining",
      "xmrig"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-178",
    "type": "sigma",
    "title": "ESXi Firewall Disabled or SSH Enabled",
    "description": "Detects esxcli disabling the ESXi firewall or vim-cmd/esxcli enabling SSH, common preparation for ESXi ransomware.",
    "code": "title: 'ESXi Firewall Disabled or SSH Enabled'\nid: cfa80d5a-242a-5eef-9fc3-3a80f4ebafe5\nstatus: test\ndescription: 'Detects esxcli disabling the ESXi firewall or vim-cmd/esxcli enabling SSH, common preparation for ESXi ransomware.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1562.004\nlogsource:\n    category: process_creation\n    product: linux\ndetection:\n    selection_fw:\n        CommandLine|contains|all:\n            - 'esxcli'\n            - 'network firewall set'\n            - '--enabled false'\n    selection_ssh:\n        CommandLine|contains:\n            - 'vim-cmd hostsvc/enable_ssh'\n            - 'vim-cmd hostsvc/start_ssh'\n            - 'services.sh start ssh'\n    selection_exec:\n        CommandLine|contains|all:\n            - 'esxcli system settings'\n            - 'execInstalledOnly'\n            - 'false'\n    condition: 1 of selection_*\nfalsepositives:\n    - 'Planned ESXi maintenance requiring SSH'\nlevel: high",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1562.004",
    "author": "OSINTrix pack",
    "platform": "Linux",
    "tags": [
      "esxi",
      "ransomware"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-179",
    "type": "sigma",
    "title": "Container Escape via Nsenter or Host Mount",
    "description": "Detects nsenter into PID 1 namespaces, mounting host block devices, or chroot into a mounted host filesystem from within a container.",
    "code": "title: 'Container Escape via Nsenter or Host Mount'\nid: 95ba2d96-5780-5224-b5bf-8989aa16e94d\nstatus: test\ndescription: 'Detects nsenter into PID 1 namespaces, mounting host block devices, or chroot into a mounted host filesystem from within a container.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.privilege-escalation\n    - attack.t1611\nlogsource:\n    category: process_creation\n    product: linux\ndetection:\n    selection_nsenter:\n        Image|endswith: '/nsenter'\n        CommandLine|contains:\n            - '--target 1'\n            - '-t 1'\n    selection_mount:\n        Image|endswith: '/mount'\n        CommandLine|contains:\n            - '/dev/sda'\n            - '/dev/nvme'\n            - '/dev/xvda'\n            - '/dev/vda'\n    selection_chroot:\n        Image|endswith: '/chroot'\n        CommandLine|contains:\n            - '/host'\n            - '/mnt/host'\n    condition: 1 of selection_*\nfalsepositives:\n    - 'Node debugging by cluster administrators (kubectl debug node)'\nlevel: high",
    "severity": "high",
    "category": "privilege-escalation",
    "technique": "T1611",
    "author": "OSINTrix pack",
    "platform": "Linux",
    "tags": [
      "container-escape",
      "docker",
      "kubernetes"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-180",
    "type": "sigma",
    "title": "Privileged Docker Container Mounting Host Root",
    "description": "Detects docker/podman run with --privileged, --pid=host or a bind mount of the host root filesystem.",
    "code": "title: 'Privileged Docker Container Mounting Host Root'\nid: 485515ae-e835-5033-ad99-a71168f80681\nstatus: test\ndescription: 'Detects docker/podman run with --privileged, --pid=host or a bind mount of the host root filesystem.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.privilege-escalation\n    - attack.t1611\nlogsource:\n    category: process_creation\n    product: linux\ndetection:\n    selection_img:\n        Image|endswith:\n            - '/docker'\n            - '/podman'\n            - '/nerdctl'\n    selection_run:\n        CommandLine|contains: ' run '\n    selection_flags:\n        CommandLine|contains:\n            - '--privileged'\n            - '--pid=host'\n            - '-v /:/'\n            - '--volume /:/'\n            - '--mount type=bind,source=/,'\n            - '--cap-add=SYS_ADMIN'\n    condition: all of selection_*\nfalsepositives:\n    - 'Infrastructure containers that legitimately need privileges (monitoring agents)'\nlevel: high",
    "severity": "high",
    "category": "privilege-escalation",
    "technique": "T1611",
    "author": "OSINTrix pack",
    "platform": "Linux",
    "tags": [
      "docker",
      "container-escape"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-181",
    "type": "sigma",
    "title": "Docker Socket Accessed via Curl",
    "description": "Detects curl talking to the Docker API through /var/run/docker.sock, often from inside a container with the socket mounted.",
    "code": "title: 'Docker Socket Accessed via Curl'\nid: cd7aaf5c-8315-5475-a6f5-78a7e8151b6a\nstatus: test\ndescription: 'Detects curl talking to the Docker API through /var/run/docker.sock, often from inside a container with the socket mounted.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.privilege-escalation\n    - attack.t1611\nlogsource:\n    category: process_creation\n    product: linux\ndetection:\n    selection:\n        Image|endswith: '/curl'\n        CommandLine|contains: '--unix-socket'\n        CommandLine|contains|all:\n            - 'docker.sock'\n    condition: selection\nfalsepositives:\n    - 'Health checks in CI tooling'\nlevel: medium",
    "severity": "medium",
    "category": "privilege-escalation",
    "technique": "T1611",
    "author": "OSINTrix pack",
    "platform": "Linux",
    "tags": [
      "docker",
      "api"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-182",
    "type": "sigma",
    "title": "AppleScript Password Prompt via Osascript",
    "description": "Detects osascript showing a dialog with hidden answer, the technique used by macOS stealers to phish the login password.",
    "code": "title: 'AppleScript Password Prompt via Osascript'\nid: f4ecb5b3-0165-5556-937c-a5e531824dde\nstatus: test\ndescription: 'Detects osascript showing a dialog with hidden answer, the technique used by macOS stealers to phish the login password.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.credential-access\n    - attack.t1056.002\nlogsource:\n    category: process_creation\n    product: macos\ndetection:\n    selection:\n        Image|endswith: '/osascript'\n        CommandLine|contains: 'display dialog'\n    selection_pw:\n        CommandLine|contains:\n            - 'hidden answer'\n            - 'password'\n            - 'with icon caution'\n    condition: all of selection*\nfalsepositives:\n    - 'Enterprise scripts prompting for credentials (should use proper auth APIs)'\nlevel: high",
    "severity": "high",
    "category": "credential-access",
    "technique": "T1056.002",
    "author": "OSINTrix pack",
    "platform": "macOS",
    "tags": [
      "osascript",
      "stealer"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-183",
    "type": "sigma",
    "title": "Osascript Running Shell Commands or JXA",
    "description": "Detects osascript executing 'do shell script' or JavaScript for Automation inline, often used by macOS malware for execution.",
    "code": "title: 'Osascript Running Shell Commands or JXA'\nid: a8e40840-72bf-52b0-80d7-ab3fa661a874\nstatus: test\ndescription: 'Detects osascript executing ''do shell script'' or JavaScript for Automation inline, often used by macOS malware for execution.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.execution\n    - attack.t1059.002\nlogsource:\n    category: process_creation\n    product: macos\ndetection:\n    selection:\n        Image|endswith: '/osascript'\n    selection_cli:\n        CommandLine|contains:\n            - 'do shell script'\n            - '-l JavaScript'\n            - 'ObjC.import'\n    condition: all of selection*\nfalsepositives:\n    - 'Admin automation scripts'\nlevel: medium",
    "severity": "medium",
    "category": "execution",
    "technique": "T1059.002",
    "author": "OSINTrix pack",
    "platform": "macOS",
    "tags": [
      "osascript",
      "jxa"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-184",
    "type": "sigma",
    "title": "Launch Agent or Daemon Plist Created",
    "description": "Detects new plist files in LaunchAgents or LaunchDaemons folders.",
    "code": "title: 'Launch Agent or Daemon Plist Created'\nid: 35dcac66-f708-53ed-9cb7-479f477584f5\nstatus: test\ndescription: 'Detects new plist files in LaunchAgents or LaunchDaemons folders.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1543.001\nlogsource:\n    category: file_event\n    product: macos\ndetection:\n    selection:\n        TargetFilename|contains:\n            - '/Library/LaunchAgents/'\n            - '/Library/LaunchDaemons/'\n        TargetFilename|endswith: '.plist'\n    filter_installer:\n        Image|endswith:\n            - '/installd'\n            - '/package_script_service'\n            - '/system_installd'\n    condition: selection and not filter_installer\nfalsepositives:\n    - 'Legitimate application installers and updaters'\nlevel: medium",
    "severity": "medium",
    "category": "persistence",
    "technique": "T1543.001",
    "author": "OSINTrix pack",
    "platform": "macOS",
    "tags": [
      "launchagent",
      "persistence"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-185",
    "type": "sigma",
    "title": "Launchctl Loading Plist From Unusual Location",
    "description": "Detects launchctl load/bootstrap of plists in /tmp, /Users/Shared or Downloads.",
    "code": "title: 'Launchctl Loading Plist From Unusual Location'\nid: 8c2d9768-6fe0-5dd3-82ac-f99b8607eea3\nstatus: test\ndescription: 'Detects launchctl load/bootstrap of plists in /tmp, /Users/Shared or Downloads.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1569.001\nlogsource:\n    category: process_creation\n    product: macos\ndetection:\n    selection:\n        Image|endswith: '/launchctl'\n        CommandLine|contains:\n            - ' load '\n            - ' bootstrap '\n            - ' submit '\n    selection_path:\n        CommandLine|contains:\n            - '/tmp/'\n            - '/private/tmp/'\n            - '/Users/Shared/'\n            - '/Downloads/'\n    condition: all of selection*\nfalsepositives:\n    - 'Developer testing of launchd jobs'\nlevel: high",
    "severity": "high",
    "category": "persistence",
    "technique": "T1569.001",
    "author": "OSINTrix pack",
    "platform": "macOS",
    "tags": [
      "launchctl"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-186",
    "type": "sigma",
    "title": "Quarantine Attribute Removed With Xattr",
    "description": "Detects xattr deleting com.apple.quarantine, which bypasses Gatekeeper checks on downloaded files.",
    "code": "title: 'Quarantine Attribute Removed With Xattr'\nid: 89a08cab-6ce6-5965-91f7-18222d134364\nstatus: test\ndescription: 'Detects xattr deleting com.apple.quarantine, which bypasses Gatekeeper checks on downloaded files.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1553.001\nlogsource:\n    category: process_creation\n    product: macos\ndetection:\n    selection:\n        Image|endswith: '/xattr'\n        CommandLine|contains: 'com.apple.quarantine'\n    selection_del:\n        CommandLine|contains:\n            - ' -d '\n            - ' -c '\n            - ' -rd '\n            - ' -dr '\n    condition: all of selection*\nfalsepositives:\n    - 'Developers clearing quarantine on their own builds'\nlevel: medium",
    "severity": "medium",
    "category": "defense-evasion",
    "technique": "T1553.001",
    "author": "OSINTrix pack",
    "platform": "macOS",
    "tags": [
      "gatekeeper",
      "quarantine"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-187",
    "type": "sigma",
    "title": "Gatekeeper Disabled With Spctl",
    "description": "Detects spctl --master-disable or --global-disable, which turns off Gatekeeper assessments.",
    "code": "title: 'Gatekeeper Disabled With Spctl'\nid: 0e3280b0-4957-5943-acae-1aa6cdee8e40\nstatus: test\ndescription: 'Detects spctl --master-disable or --global-disable, which turns off Gatekeeper assessments.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1553.001\nlogsource:\n    category: process_creation\n    product: macos\ndetection:\n    selection:\n        Image|endswith: '/spctl'\n        CommandLine|contains:\n            - '--master-disable'\n            - '--global-disable'\n    condition: selection\nfalsepositives:\n    - 'Developers disabling Gatekeeper on test machines'\nlevel: high",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1553.001",
    "author": "OSINTrix pack",
    "platform": "macOS",
    "tags": [
      "gatekeeper"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-188",
    "type": "sigma",
    "title": "Keychain Credential Dumping With Security Tool",
    "description": "Detects the security CLI dumping keychains or extracting stored passwords.",
    "code": "title: 'Keychain Credential Dumping With Security Tool'\nid: 057d22fa-2319-5d32-858a-5a4c44aa07e7\nstatus: test\ndescription: 'Detects the security CLI dumping keychains or extracting stored passwords.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.credential-access\n    - attack.t1555.001\nlogsource:\n    category: process_creation\n    product: macos\ndetection:\n    selection:\n        Image|endswith: '/security'\n        CommandLine|contains:\n            - 'dump-keychain'\n            - 'find-generic-password'\n            - 'find-internet-password'\n            - 'export -k'\n    selection_flag:\n        CommandLine|contains:\n            - ' -w'\n            - ' -d'\n            - ' -g'\n            - 'login.keychain'\n    condition: all of selection*\nfalsepositives:\n    - 'Scripts that read their own keychain items'\nlevel: high",
    "severity": "high",
    "category": "credential-access",
    "technique": "T1555.001",
    "author": "OSINTrix pack",
    "platform": "macOS",
    "tags": [
      "keychain"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-189",
    "type": "sigma",
    "title": "Login Hook Configured via Defaults",
    "description": "Detects defaults write com.apple.loginwindow LoginHook/LogoutHook, a legacy macOS persistence technique.",
    "code": "title: 'Login Hook Configured via Defaults'\nid: 3a5deb11-7857-5c9a-a2f9-05181d320699\nstatus: test\ndescription: 'Detects defaults write com.apple.loginwindow LoginHook/LogoutHook, a legacy macOS persistence technique.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1037.002\nlogsource:\n    category: process_creation\n    product: macos\ndetection:\n    selection:\n        Image|endswith: '/defaults'\n        CommandLine|contains|all:\n            - 'write'\n            - 'com.apple.loginwindow'\n    selection_hook:\n        CommandLine|contains:\n            - 'LoginHook'\n            - 'LogoutHook'\n    condition: all of selection*\nfalsepositives:\n    - 'Legacy management scripts'\nlevel: high",
    "severity": "high",
    "category": "persistence",
    "technique": "T1037.002",
    "author": "OSINTrix pack",
    "platform": "macOS",
    "tags": [
      "login-hook"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-190",
    "type": "sigma",
    "title": "macOS Admin Account Created With Dscl",
    "description": "Detects dscl creating a user or adding a user to the admin group.",
    "code": "title: 'macOS Admin Account Created With Dscl'\nid: b221ef20-4f5f-55a3-b36a-293d9a06abd8\nstatus: test\ndescription: 'Detects dscl creating a user or adding a user to the admin group.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1136.001\nlogsource:\n    category: process_creation\n    product: macos\ndetection:\n    selection:\n        Image|endswith: '/dscl'\n    selection_create:\n        CommandLine|contains:\n            - ' -create /Users/'\n            - ' -append /Groups/admin GroupMembership'\n    condition: all of selection*\nfalsepositives:\n    - 'MDM provisioning scripts'\nlevel: high",
    "severity": "high",
    "category": "persistence",
    "technique": "T1136.001",
    "author": "OSINTrix pack",
    "platform": "macOS",
    "tags": [
      "dscl",
      "account-creation"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-191",
    "type": "sigma",
    "title": "Curl Download Into Temporary Path on macOS",
    "description": "Detects curl on macOS writing to /tmp, /Users/Shared or /private/tmp, common in stealer and loader droppers.",
    "code": "title: 'Curl Download Into Temporary Path on macOS'\nid: 6b805571-8827-58ec-b00b-3475776eedc2\nstatus: test\ndescription: 'Detects curl on macOS writing to /tmp, /Users/Shared or /private/tmp, common in stealer and loader droppers.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.command-and-control\n    - attack.t1105\nlogsource:\n    category: process_creation\n    product: macos\ndetection:\n    selection:\n        Image|endswith: '/curl'\n        CommandLine|contains:\n            - ' -o '\n            - ' -O'\n            - ' --output '\n    selection_path:\n        CommandLine|contains:\n            - '/tmp/'\n            - '/Users/Shared/'\n            - '/private/tmp/'\n    condition: all of selection*\nfalsepositives:\n    - 'Homebrew and developer tooling'\nlevel: medium",
    "severity": "medium",
    "category": "command-and-control",
    "technique": "T1105",
    "author": "OSINTrix pack",
    "platform": "macOS",
    "tags": [
      "download",
      "stealer"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-192",
    "type": "sigma",
    "title": "AWS Root Account Console Login",
    "description": "Detects a successful console sign-in by the AWS account root user.",
    "code": "title: 'AWS Root Account Console Login'\nid: d6ce8c4e-ca5e-5638-8150-6b6807ba8115\nstatus: test\ndescription: 'Detects a successful console sign-in by the AWS account root user.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.initial-access\n    - attack.t1078.004\nlogsource:\n    product: aws\n    service: cloudtrail\ndetection:\n    selection:\n        eventSource: 'signin.amazonaws.com'\n        eventName: 'ConsoleLogin'\n        userIdentity.type: 'Root'\n        responseElements.ConsoleLogin: 'Success'\n    condition: selection\nfalsepositives:\n    - 'Break-glass procedures and billing tasks that require root'\nlevel: high",
    "severity": "high",
    "category": "initial-access",
    "technique": "T1078.004",
    "author": "OSINTrix pack",
    "platform": "AWS",
    "tags": [
      "aws",
      "root"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-193",
    "type": "sigma",
    "title": "AWS Console Login Without MFA",
    "description": "Detects successful console sign-ins where additionalEventData.MFAUsed is No.",
    "code": "title: 'AWS Console Login Without MFA'\nid: f15f0953-cad4-59fd-b8ff-ef70bf807e70\nstatus: test\ndescription: 'Detects successful console sign-ins where additionalEventData.MFAUsed is No.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.initial-access\n    - attack.t1078.004\nlogsource:\n    product: aws\n    service: cloudtrail\ndetection:\n    selection:\n        eventName: 'ConsoleLogin'\n        responseElements.ConsoleLogin: 'Success'\n        additionalEventData.MFAUsed: 'No'\n    filter_sso:\n        userIdentity.arn|contains: ':assumed-role/AWSReservedSSO_'\n    condition: selection and not filter_sso\nfalsepositives:\n    - 'Federated logins where MFA is enforced by the IdP'\nlevel: medium",
    "severity": "medium",
    "category": "initial-access",
    "technique": "T1078.004",
    "author": "OSINTrix pack",
    "platform": "AWS",
    "tags": [
      "aws",
      "mfa"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-194",
    "type": "sigma",
    "title": "AWS Root Access Key Created",
    "description": "Detects CreateAccessKey performed by the root user, which creates long-lived root API credentials.",
    "code": "title: 'AWS Root Access Key Created'\nid: 2f209afb-d581-5211-bd8c-a008b30bdd44\nstatus: test\ndescription: 'Detects CreateAccessKey performed by the root user, which creates long-lived root API credentials.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1098.001\nlogsource:\n    product: aws\n    service: cloudtrail\ndetection:\n    selection:\n        eventSource: 'iam.amazonaws.com'\n        eventName: 'CreateAccessKey'\n        userIdentity.type: 'Root'\n    condition: selection\nfalsepositives:\n    - 'None expected under AWS best practice'\nlevel: critical",
    "severity": "critical",
    "category": "persistence",
    "technique": "T1098.001",
    "author": "OSINTrix pack",
    "platform": "AWS",
    "tags": [
      "aws",
      "root",
      "access-key"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-195",
    "type": "sigma",
    "title": "AWS MFA Device Deactivated or Deleted",
    "description": "Detects DeactivateMFADevice or DeleteVirtualMFADevice, which weaken account authentication.",
    "code": "title: 'AWS MFA Device Deactivated or Deleted'\nid: e058d60e-6524-5fd6-898c-9a7fe97641c6\nstatus: test\ndescription: 'Detects DeactivateMFADevice or DeleteVirtualMFADevice, which weaken account authentication.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1556.006\nlogsource:\n    product: aws\n    service: cloudtrail\ndetection:\n    selection:\n        eventSource: 'iam.amazonaws.com'\n        eventName:\n            - 'DeactivateMFADevice'\n            - 'DeleteVirtualMFADevice'\n    condition: selection\nfalsepositives:\n    - 'User replacing a lost MFA device'\nlevel: high",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1556.006",
    "author": "OSINTrix pack",
    "platform": "AWS",
    "tags": [
      "aws",
      "mfa"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-196",
    "type": "sigma",
    "title": "AWS Access Key Created for Another IAM User",
    "description": "Detects CreateAccessKey where the caller differs from the target user, a common persistence step after IAM compromise.",
    "code": "title: 'AWS Access Key Created for Another IAM User'\nid: 527d8a72-e028-5215-b438-7d021ba0cec7\nstatus: test\ndescription: 'Detects CreateAccessKey where the caller differs from the target user, a common persistence step after IAM compromise.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1098.001\nlogsource:\n    product: aws\n    service: cloudtrail\ndetection:\n    selection:\n        eventSource: 'iam.amazonaws.com'\n        eventName: 'CreateAccessKey'\n        requestParameters.userName|exists: true\n    filter_self:\n        userIdentity.userName|fieldref: requestParameters.userName\n    condition: selection and not filter_self\nfalsepositives:\n    - 'Administrators issuing keys to service users'\nlevel: medium",
    "severity": "medium",
    "category": "persistence",
    "technique": "T1098.001",
    "author": "OSINTrix pack",
    "platform": "AWS",
    "tags": [
      "aws",
      "access-key"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-197",
    "type": "sigma",
    "title": "AWS Login Profile Created or Updated for User",
    "description": "Detects CreateLoginProfile/UpdateLoginProfile, which can give console access to an API-only or existing user.",
    "code": "title: 'AWS Login Profile Created or Updated for User'\nid: adcd011d-171a-5932-a317-9b8b84655384\nstatus: test\ndescription: 'Detects CreateLoginProfile/UpdateLoginProfile, which can give console access to an API-only or existing user.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1098.001\nlogsource:\n    product: aws\n    service: cloudtrail\ndetection:\n    selection:\n        eventSource: 'iam.amazonaws.com'\n        eventName:\n            - 'CreateLoginProfile'\n            - 'UpdateLoginProfile'\n    condition: selection\nfalsepositives:\n    - 'Helpdesk password resets'\nlevel: medium",
    "severity": "medium",
    "category": "persistence",
    "technique": "T1098.001",
    "author": "OSINTrix pack",
    "platform": "AWS",
    "tags": [
      "aws",
      "console-access"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-198",
    "type": "sigma",
    "title": "AWS IAM User Created",
    "description": "Detects creation of new IAM users. Baseline rule; tune to alert when outside IaC pipelines.",
    "code": "title: 'AWS IAM User Created'\nid: 64b579c9-50c6-5cf3-9298-47866f71c6c6\nstatus: test\ndescription: 'Detects creation of new IAM users. Baseline rule; tune to alert when outside IaC pipelines.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1136.003\nlogsource:\n    product: aws\n    service: cloudtrail\ndetection:\n    selection:\n        eventSource: 'iam.amazonaws.com'\n        eventName: 'CreateUser'\n    condition: selection\nfalsepositives:\n    - 'Provisioning through Terraform or CloudFormation'\nlevel: low",
    "severity": "low",
    "category": "persistence",
    "technique": "T1136.003",
    "author": "OSINTrix pack",
    "platform": "AWS",
    "tags": [
      "aws",
      "account-creation"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-199",
    "type": "sigma",
    "title": "AWS AdministratorAccess Policy Attached",
    "description": "Detects the AWS managed AdministratorAccess policy being attached to a user, group or role.",
    "code": "title: 'AWS AdministratorAccess Policy Attached'\nid: f0b8cbb0-a8fc-50d0-b24e-cf692dffbc2f\nstatus: test\ndescription: 'Detects the AWS managed AdministratorAccess policy being attached to a user, group or role.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.privilege-escalation\n    - attack.t1098.003\nlogsource:\n    product: aws\n    service: cloudtrail\ndetection:\n    selection:\n        eventSource: 'iam.amazonaws.com'\n        eventName:\n            - 'AttachUserPolicy'\n            - 'AttachGroupPolicy'\n            - 'AttachRolePolicy'\n        requestParameters.policyArn: 'arn:aws:iam::aws:policy/AdministratorAccess'\n    condition: selection\nfalsepositives:\n    - 'Planned admin grants'\nlevel: high",
    "severity": "high",
    "category": "privilege-escalation",
    "technique": "T1098.003",
    "author": "OSINTrix pack",
    "platform": "AWS",
    "tags": [
      "aws",
      "iam",
      "admin"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-200",
    "type": "sigma",
    "title": "AWS GuardDuty Detector Disabled or Deleted",
    "description": "Detects GuardDuty being deleted, disabled or disassociated from the administrator account.",
    "code": "title: 'AWS GuardDuty Detector Disabled or Deleted'\nid: 481f374c-c8e9-5fa8-b053-82d3c5c9318f\nstatus: test\ndescription: 'Detects GuardDuty being deleted, disabled or disassociated from the administrator account.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1562.008\nlogsource:\n    product: aws\n    service: cloudtrail\ndetection:\n    selection:\n        eventSource: 'guardduty.amazonaws.com'\n        eventName:\n            - 'DeleteDetector'\n            - 'DisassociateFromMasterAccount'\n            - 'DisassociateFromAdministratorAccount'\n            - 'StopMonitoringMembers'\n            - 'DeleteMembers'\n            - 'UpdateDetector'\n    condition: selection\nfalsepositives:\n    - 'Account decommissioning'\n    - 'UpdateDetector used to change finding frequency'\nlevel: high",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1562.008",
    "author": "OSINTrix pack",
    "platform": "AWS",
    "tags": [
      "aws",
      "guardduty"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-201",
    "type": "sigma",
    "title": "AWS Config Recording Stopped or Deleted",
    "description": "Detects AWS Config recorder or delivery channel being stopped or deleted.",
    "code": "title: 'AWS Config Recording Stopped or Deleted'\nid: f162faab-203e-5fb6-ac8c-c2139a0de8d7\nstatus: test\ndescription: 'Detects AWS Config recorder or delivery channel being stopped or deleted.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1562.008\nlogsource:\n    product: aws\n    service: cloudtrail\ndetection:\n    selection:\n        eventSource: 'config.amazonaws.com'\n        eventName:\n            - 'StopConfigurationRecorder'\n            - 'DeleteConfigurationRecorder'\n            - 'DeleteDeliveryChannel'\n            - 'DeleteConfigRule'\n    condition: selection\nfalsepositives:\n    - 'Infrastructure tear-down'\nlevel: high",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1562.008",
    "author": "OSINTrix pack",
    "platform": "AWS",
    "tags": [
      "aws",
      "config"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-202",
    "type": "sigma",
    "title": "AWS VPC Flow Logs or CloudWatch Log Group Deleted",
    "description": "Detects deletion of VPC Flow Logs, CloudWatch log groups or log streams.",
    "code": "title: 'AWS VPC Flow Logs or CloudWatch Log Group Deleted'\nid: 490d65e4-310b-51b2-a395-968f78670573\nstatus: test\ndescription: 'Detects deletion of VPC Flow Logs, CloudWatch log groups or log streams.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1562.008\nlogsource:\n    product: aws\n    service: cloudtrail\ndetection:\n    selection:\n        eventName:\n            - 'DeleteFlowLogs'\n            - 'DeleteLogGroup'\n            - 'DeleteLogStream'\n    condition: selection\nfalsepositives:\n    - 'Log retention clean-up automation'\nlevel: medium",
    "severity": "medium",
    "category": "defense-evasion",
    "technique": "T1562.008",
    "author": "OSINTrix pack",
    "platform": "AWS",
    "tags": [
      "aws",
      "logging"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-203",
    "type": "sigma",
    "title": "AWS S3 ACL Granted to AllUsers or AuthenticatedUsers",
    "description": "Detects bucket or object ACL changes granting access to the global AllUsers or AuthenticatedUsers groups.",
    "code": "title: 'AWS S3 ACL Granted to AllUsers or AuthenticatedUsers'\nid: 169f512a-23c4-5968-b081-edd2964d59a9\nstatus: test\ndescription: 'Detects bucket or object ACL changes granting access to the global AllUsers or AuthenticatedUsers groups.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.exfiltration\n    - attack.t1537\nlogsource:\n    product: aws\n    service: cloudtrail\ndetection:\n    selection:\n        eventSource: 's3.amazonaws.com'\n        eventName:\n            - 'PutBucketAcl'\n            - 'PutObjectAcl'\n    selection_grantee:\n        requestParameters|contains:\n            - 'http://acs.amazonaws.com/groups/global/AllUsers'\n            - 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'\n    condition: all of selection*\nfalsepositives:\n    - 'Intentional public static website buckets'\nlevel: high",
    "severity": "high",
    "category": "exfiltration",
    "technique": "T1537",
    "author": "OSINTrix pack",
    "platform": "AWS",
    "tags": [
      "aws",
      "s3",
      "exposure"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-204",
    "type": "sigma",
    "title": "AWS S3 Versioning Suspended",
    "description": "Detects PutBucketVersioning setting status to Suspended, which removes protection against overwrite/deletion before destructive actions.",
    "code": "title: 'AWS S3 Versioning Suspended'\nid: b17445ca-2b2b-54de-9a8b-e3c9ebe64b97\nstatus: test\ndescription: 'Detects PutBucketVersioning setting status to Suspended, which removes protection against overwrite/deletion before destructive actions.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.impact\n    - attack.t1490\nlogsource:\n    product: aws\n    service: cloudtrail\ndetection:\n    selection:\n        eventSource: 's3.amazonaws.com'\n        eventName: 'PutBucketVersioning'\n        requestParameters.VersioningConfiguration.Status: 'Suspended'\n    condition: selection\nfalsepositives:\n    - 'Cost-optimisation changes on non-critical buckets'\nlevel: medium",
    "severity": "medium",
    "category": "impact",
    "technique": "T1490",
    "author": "OSINTrix pack",
    "platform": "AWS",
    "tags": [
      "aws",
      "s3",
      "ransomware"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-205",
    "type": "sigma",
    "title": "AWS S3 Objects Rewritten With Customer-Provided Keys",
    "description": "Detects S3 CopyObject/PutObject using SSE-C (customer-provided encryption keys), abused to encrypt victims' data with attacker-held keys.",
    "code": "title: 'AWS S3 Objects Rewritten With Customer-Provided Keys'\nid: bba32675-96b4-59ce-8b6b-718aca04b26d\nstatus: test\ndescription: 'Detects S3 CopyObject/PutObject using SSE-C (customer-provided encryption keys), abused to encrypt victims'' data with attacker-held keys.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.impact\n    - attack.t1486\nlogsource:\n    product: aws\n    service: cloudtrail\ndetection:\n    selection:\n        eventSource: 's3.amazonaws.com'\n        eventName:\n            - 'CopyObject'\n            - 'PutObject'\n    selection_ssec:\n        - additionalEventData.SSECustomerAlgorithm: 'AES256'\n        - requestParameters.x-amz-server-side-encryption-customer-algorithm: 'AES256'\n    condition: all of selection*\nfalsepositives:\n    - 'Applications that deliberately use SSE-C'\nlevel: high",
    "severity": "high",
    "category": "impact",
    "technique": "T1486",
    "author": "OSINTrix pack",
    "platform": "AWS",
    "tags": [
      "aws",
      "s3",
      "ransomware",
      "ssec"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-206",
    "type": "sigma",
    "title": "AWS KMS Key Scheduled for Deletion or Disabled",
    "description": "Detects ScheduleKeyDeletion or DisableKey on a KMS key, which can render encrypted data unrecoverable.",
    "code": "title: 'AWS KMS Key Scheduled for Deletion or Disabled'\nid: a79ea44b-523a-588b-aa2f-c1eb0bc078dc\nstatus: test\ndescription: 'Detects ScheduleKeyDeletion or DisableKey on a KMS key, which can render encrypted data unrecoverable.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.impact\n    - attack.t1485\nlogsource:\n    product: aws\n    service: cloudtrail\ndetection:\n    selection:\n        eventSource: 'kms.amazonaws.com'\n        eventName:\n            - 'ScheduleKeyDeletion'\n            - 'DisableKey'\n    condition: selection\nfalsepositives:\n    - 'Key lifecycle management'\nlevel: high",
    "severity": "high",
    "category": "impact",
    "technique": "T1485",
    "author": "OSINTrix pack",
    "platform": "AWS",
    "tags": [
      "aws",
      "kms"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-207",
    "type": "sigma",
    "title": "AWS Unusual Volume of Secrets Manager Reads",
    "description": "Detects a single principal calling GetSecretValue many times in a short period, indicating bulk secret harvesting.",
    "code": "title: 'AWS Unusual Volume of Secrets Manager Reads'\nid: 56069d4a-c0ac-5706-ad69-ab9a1f315db7\nstatus: test\ndescription: 'Detects a single principal calling GetSecretValue many times in a short period, indicating bulk secret harvesting.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.credential-access\n    - attack.t1555.006\nlogsource:\n    product: aws\n    service: cloudtrail\ndetection:\n    selection:\n        eventSource: 'secretsmanager.amazonaws.com'\n        eventName: 'GetSecretValue'\n    condition: selection | count(requestParameters.secretId) by userIdentity.arn > 20\n    timeframe: 10m\nfalsepositives:\n    - 'Applications that fetch many secrets at start-up'\nlevel: medium",
    "severity": "medium",
    "category": "credential-access",
    "technique": "T1555.006",
    "author": "OSINTrix pack",
    "platform": "AWS",
    "tags": [
      "aws",
      "secrets-manager"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-208",
    "type": "sigma",
    "title": "AWS EC2 Instance User Data Modified",
    "description": "Detects ModifyInstanceAttribute changing userData, which runs attacker code on next boot.",
    "code": "title: 'AWS EC2 Instance User Data Modified'\nid: 7fe62fd9-5ffc-5380-9086-135d24cb5c17\nstatus: test\ndescription: 'Detects ModifyInstanceAttribute changing userData, which runs attacker code on next boot.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.execution\n    - attack.t1578\nlogsource:\n    product: aws\n    service: cloudtrail\ndetection:\n    selection:\n        eventSource: 'ec2.amazonaws.com'\n        eventName: 'ModifyInstanceAttribute'\n        requestParameters.userData|exists: true\n    condition: selection\nfalsepositives:\n    - 'Infrastructure automation updating bootstrap scripts'\nlevel: high",
    "severity": "high",
    "category": "execution",
    "technique": "T1578",
    "author": "OSINTrix pack",
    "platform": "AWS",
    "tags": [
      "aws",
      "ec2",
      "user-data"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-209",
    "type": "sigma",
    "title": "AWS Lambda Function URL Created Without Authentication",
    "description": "Detects Lambda function URLs created or updated with AuthType NONE, which exposes the function publicly.",
    "code": "title: 'AWS Lambda Function URL Created Without Authentication'\nid: 9258581c-686d-5b03-b3cf-56ac6e23612c\nstatus: test\ndescription: 'Detects Lambda function URLs created or updated with AuthType NONE, which exposes the function publicly.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1648\nlogsource:\n    product: aws\n    service: cloudtrail\ndetection:\n    selection:\n        eventSource: 'lambda.amazonaws.com'\n        eventName|startswith:\n            - 'CreateFunctionUrlConfig'\n            - 'UpdateFunctionUrlConfig'\n        requestParameters.authType: 'NONE'\n    condition: selection\nfalsepositives:\n    - 'Public webhooks intentionally built on Lambda URLs'\nlevel: high",
    "severity": "high",
    "category": "persistence",
    "technique": "T1648",
    "author": "OSINTrix pack",
    "platform": "AWS",
    "tags": [
      "aws",
      "lambda",
      "exposure"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-210",
    "type": "sigma",
    "title": "AWS IAM Role Trust Policy Modified",
    "description": "Detects UpdateAssumeRolePolicy or CreateRole with a trust policy naming an AWS account principal; review for external accounts not in your organisation.",
    "code": "title: 'AWS IAM Role Trust Policy Modified'\nid: 75f9e053-30a9-52a1-9c67-6566dc7109e6\nstatus: test\ndescription: 'Detects UpdateAssumeRolePolicy or CreateRole with a trust policy naming an AWS account principal; review for external accounts not in your organisation.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1098.003\nlogsource:\n    product: aws\n    service: cloudtrail\ndetection:\n    selection:\n        eventSource: 'iam.amazonaws.com'\n        eventName:\n            - 'UpdateAssumeRolePolicy'\n            - 'CreateRole'\n    selection_principal:\n        requestParameters.policyDocument|contains: 'arn:aws:iam::'\n    filter_org:\n        requestParameters.policyDocument|contains: 'arn:aws:iam::111111111111:'\n    condition: all of selection* and not filter_org\nfalsepositives:\n    - 'Legitimate cross-account roles for vendors (replace 111111111111 with your account IDs)'\nlevel: high",
    "severity": "high",
    "category": "persistence",
    "technique": "T1098.003",
    "author": "OSINTrix pack",
    "platform": "AWS",
    "tags": [
      "aws",
      "iam",
      "cross-account"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-211",
    "type": "sigma",
    "title": "AWS Role Assumed From Unexpected Network",
    "description": "Detects AssumeRole calls by IAM users from source IPs outside your known ranges. Replace the placeholder CIDRs with corporate egress ranges.",
    "code": "title: 'AWS Role Assumed From Unexpected Network'\nid: fbf6159c-712a-5305-af74-eac9daa297d3\nstatus: test\ndescription: 'Detects AssumeRole calls by IAM users from source IPs outside your known ranges. Replace the placeholder CIDRs with corporate egress ranges.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.privilege-escalation\n    - attack.t1078.004\nlogsource:\n    product: aws\n    service: cloudtrail\ndetection:\n    selection:\n        eventSource: 'sts.amazonaws.com'\n        eventName: 'AssumeRole'\n        userIdentity.type: 'IAMUser'\n    filter_known:\n        sourceIPAddress|cidr:\n            - '198.51.100.0/24'\n            - '203.0.113.0/24'\n    filter_aws:\n        sourceIPAddress|endswith: '.amazonaws.com'\n    condition: selection and not 1 of filter_*\nfalsepositives:\n    - 'Remote staff without VPN'\n    - 'Incomplete corporate range list'\nlevel: low",
    "severity": "low",
    "category": "privilege-escalation",
    "technique": "T1078.004",
    "author": "OSINTrix pack",
    "platform": "AWS",
    "tags": [
      "aws",
      "sts"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-212",
    "type": "sigma",
    "title": "AWS EBS Snapshot or AMI Shared Publicly",
    "description": "Detects snapshots or AMIs made public via ModifySnapshotAttribute / ModifyImageAttribute with group all.",
    "code": "title: 'AWS EBS Snapshot or AMI Shared Publicly'\nid: c56e0f40-a79b-5cf6-9f9b-a5d351a1bd2b\nstatus: test\ndescription: 'Detects snapshots or AMIs made public via ModifySnapshotAttribute / ModifyImageAttribute with group all.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.exfiltration\n    - attack.t1537\nlogsource:\n    product: aws\n    service: cloudtrail\ndetection:\n    selection:\n        eventSource: 'ec2.amazonaws.com'\n        eventName:\n            - 'ModifySnapshotAttribute'\n            - 'ModifyImageAttribute'\n    selection_public:\n        requestParameters|contains: '\"group\":\"all\"'\n    condition: all of selection*\nfalsepositives:\n    - 'Publishing public AMIs intentionally'\nlevel: high",
    "severity": "high",
    "category": "exfiltration",
    "technique": "T1537",
    "author": "OSINTrix pack",
    "platform": "AWS",
    "tags": [
      "aws",
      "snapshot",
      "exposure"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-213",
    "type": "sigma",
    "title": "AWS Security Group Opened to the Internet",
    "description": "Detects AuthorizeSecurityGroupIngress with 0.0.0.0/0 or ::/0.",
    "code": "title: 'AWS Security Group Opened to the Internet'\nid: 41de4b8c-bda6-52f7-8148-cfe179443d29\nstatus: test\ndescription: 'Detects AuthorizeSecurityGroupIngress with 0.0.0.0/0 or ::/0.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1562.007\nlogsource:\n    product: aws\n    service: cloudtrail\ndetection:\n    selection:\n        eventSource: 'ec2.amazonaws.com'\n        eventName: 'AuthorizeSecurityGroupIngress'\n    selection_cidr:\n        requestParameters|contains:\n            - '0.0.0.0/0'\n            - '::/0'\n    condition: all of selection*\nfalsepositives:\n    - 'Public load balancer security groups on 80/443'\nlevel: medium",
    "severity": "medium",
    "category": "defense-evasion",
    "technique": "T1562.007",
    "author": "OSINTrix pack",
    "platform": "AWS",
    "tags": [
      "aws",
      "security-group"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-214",
    "type": "sigma",
    "title": "AWS GPU Instance Type Launched",
    "description": "Detects RunInstances for GPU families often abused for cryptomining after credential theft.",
    "code": "title: 'AWS GPU Instance Type Launched'\nid: 6827c936-270f-5a2c-9cf3-869a9ffe66cd\nstatus: test\ndescription: 'Detects RunInstances for GPU families often abused for cryptomining after credential theft.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.impact\n    - attack.t1496\nlogsource:\n    product: aws\n    service: cloudtrail\ndetection:\n    selection:\n        eventSource: 'ec2.amazonaws.com'\n        eventName: 'RunInstances'\n        requestParameters.instanceType|startswith:\n            - 'p2.'\n            - 'p3.'\n            - 'p4d.'\n            - 'p5.'\n            - 'g4dn.'\n            - 'g5.'\n            - 'g6.'\n    condition: selection\nfalsepositives:\n    - 'ML teams launching GPU instances'\nlevel: medium",
    "severity": "medium",
    "category": "impact",
    "technique": "T1496",
    "author": "OSINTrix pack",
    "platform": "AWS",
    "tags": [
      "aws",
      "cryptomining"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-215",
    "type": "sigma",
    "title": "AWS Account Leaving Organization",
    "description": "Detects LeaveOrganization, which removes the account from SCP guardrails and central logging.",
    "code": "title: 'AWS Account Leaving Organization'\nid: 946fb1c1-e326-506e-b45b-52f21e6feac1\nstatus: test\ndescription: 'Detects LeaveOrganization, which removes the account from SCP guardrails and central logging.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1562\nlogsource:\n    product: aws\n    service: cloudtrail\ndetection:\n    selection:\n        eventSource: 'organizations.amazonaws.com'\n        eventName: 'LeaveOrganization'\n    condition: selection\nfalsepositives:\n    - 'Planned divestiture'\nlevel: high",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1562",
    "author": "OSINTrix pack",
    "platform": "AWS",
    "tags": [
      "aws",
      "organizations"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-216",
    "type": "sigma",
    "title": "AWS SSM Command or Session Started",
    "description": "Detects SSM SendCommand and StartSession, which give shell-level access to managed instances.",
    "code": "title: 'AWS SSM Command or Session Started'\nid: 4d0f8622-ae84-5d70-9730-468979f8deae\nstatus: test\ndescription: 'Detects SSM SendCommand and StartSession, which give shell-level access to managed instances.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.execution\n    - attack.t1651\nlogsource:\n    product: aws\n    service: cloudtrail\ndetection:\n    selection:\n        eventSource: 'ssm.amazonaws.com'\n        eventName:\n            - 'SendCommand'\n            - 'StartSession'\n    condition: selection\nfalsepositives:\n    - 'Routine administration and patching through SSM'\nlevel: low",
    "severity": "low",
    "category": "execution",
    "technique": "T1651",
    "author": "OSINTrix pack",
    "platform": "AWS",
    "tags": [
      "aws",
      "ssm"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-217",
    "type": "sigma",
    "title": "Entra ID Risky Sign-In Succeeded",
    "description": "Detects successful sign-ins flagged with high or medium risk by Entra ID Protection.",
    "code": "title: 'Entra ID Risky Sign-In Succeeded'\nid: 30d9be15-637c-5e4c-936a-301696584dde\nstatus: test\ndescription: 'Detects successful sign-ins flagged with high or medium risk by Entra ID Protection.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.initial-access\n    - attack.t1078.004\nlogsource:\n    product: azure\n    service: signinlogs\ndetection:\n    selection:\n        ResultType: 0\n        RiskLevelDuringSignIn:\n            - 'high'\n            - 'medium'\n    condition: selection\nfalsepositives:\n    - 'VPN egress from new countries'\n    - 'Travelling users'\nlevel: medium",
    "severity": "medium",
    "category": "initial-access",
    "technique": "T1078.004",
    "author": "OSINTrix pack",
    "platform": "Azure",
    "tags": [
      "entra",
      "risky-signin"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-218",
    "type": "sigma",
    "title": "Entra ID Password Spray",
    "description": "Detects many distinct accounts failing with error 50126 (invalid credentials) from the same IP address.",
    "code": "title: 'Entra ID Password Spray'\nid: 1434ba6f-b5d6-57f5-8ab2-484863fb4cab\nstatus: test\ndescription: 'Detects many distinct accounts failing with error 50126 (invalid credentials) from the same IP address.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.credential-access\n    - attack.t1110.003\nlogsource:\n    product: azure\n    service: signinlogs\ndetection:\n    selection:\n        ResultType: 50126\n    condition: selection | count(UserPrincipalName) by IPAddress > 20\n    timeframe: 30m\nfalsepositives:\n    - 'Shared NAT for large offices'\nlevel: medium",
    "severity": "medium",
    "category": "credential-access",
    "technique": "T1110.003",
    "author": "OSINTrix pack",
    "platform": "Azure",
    "tags": [
      "entra",
      "password-spray"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-219",
    "type": "sigma",
    "title": "Entra ID Legacy Authentication Sign-In",
    "description": "Detects sign-ins using legacy protocols (IMAP, POP, SMTP AUTH, ActiveSync, other clients) that bypass MFA.",
    "code": "title: 'Entra ID Legacy Authentication Sign-In'\nid: 9ca05876-804e-5367-9824-036c327431fe\nstatus: test\ndescription: 'Detects sign-ins using legacy protocols (IMAP, POP, SMTP AUTH, ActiveSync, other clients) that bypass MFA.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.initial-access\n    - attack.t1078.004\nlogsource:\n    product: azure\n    service: signinlogs\ndetection:\n    selection:\n        ClientAppUsed:\n            - 'Exchange ActiveSync'\n            - 'IMAP4'\n            - 'POP3'\n            - 'Authenticated SMTP'\n            - 'Other clients'\n            - 'Exchange Web Services'\n            - 'MAPI Over HTTP'\n    condition: selection\nfalsepositives:\n    - 'Old multifunction printers and mail clients'\nlevel: low",
    "severity": "low",
    "category": "initial-access",
    "technique": "T1078.004",
    "author": "OSINTrix pack",
    "platform": "Azure",
    "tags": [
      "entra",
      "legacy-auth"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-220",
    "type": "sigma",
    "title": "Entra ID Device Code Flow Sign-In",
    "description": "Detects sign-ins using the device code authentication protocol, abused in device-code phishing.",
    "code": "title: 'Entra ID Device Code Flow Sign-In'\nid: 5856b2f7-d3af-5295-81d0-406eb83d1e13\nstatus: test\ndescription: 'Detects sign-ins using the device code authentication protocol, abused in device-code phishing.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.credential-access\n    - attack.t1528\nlogsource:\n    product: azure\n    service: signinlogs\ndetection:\n    selection:\n        AuthenticationProtocol: 'deviceCode'\n    condition: selection\nfalsepositives:\n    - 'Users signing into TVs, CLIs or conference room devices'\nlevel: medium",
    "severity": "medium",
    "category": "credential-access",
    "technique": "T1528",
    "author": "OSINTrix pack",
    "platform": "Azure",
    "tags": [
      "entra",
      "device-code",
      "phishing"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-221",
    "type": "sigma",
    "title": "Entra ID New MFA Method Registered",
    "description": "Detects a user registering new security info (authenticator, phone, FIDO key), which attackers do after taking over an account.",
    "code": "title: 'Entra ID New MFA Method Registered'\nid: 4ead34de-0a16-5977-8ad2-941e4442a449\nstatus: test\ndescription: 'Detects a user registering new security info (authenticator, phone, FIDO key), which attackers do after taking over an account.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1098.005\nlogsource:\n    product: azure\n    service: auditlogs\ndetection:\n    selection:\n        Category: 'UserManagement'\n        OperationName:\n            - 'User registered security info'\n            - 'User registered all required security info'\n            - 'Admin registered security info'\n    condition: selection\nfalsepositives:\n    - 'New joiners and device replacements'\nlevel: medium",
    "severity": "medium",
    "category": "persistence",
    "technique": "T1098.005",
    "author": "OSINTrix pack",
    "platform": "Azure",
    "tags": [
      "entra",
      "mfa"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-222",
    "type": "sigma",
    "title": "Entra ID Per-User MFA Disabled",
    "description": "Detects 'Disable Strong Authentication' audit events.",
    "code": "title: 'Entra ID Per-User MFA Disabled'\nid: bd5823a0-4cd5-5eb1-8e1f-d47b826fd5dc\nstatus: test\ndescription: 'Detects ''Disable Strong Authentication'' audit events.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1556.006\nlogsource:\n    product: azure\n    service: auditlogs\ndetection:\n    selection:\n        OperationName: 'Disable Strong Authentication'\n    condition: selection\nfalsepositives:\n    - 'Migrations from per-user MFA to Conditional Access'\nlevel: high",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1556.006",
    "author": "OSINTrix pack",
    "platform": "Azure",
    "tags": [
      "entra",
      "mfa"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-223",
    "type": "sigma",
    "title": "Entra ID Application Consent Granted",
    "description": "Detects user or admin consent to an application, the mechanism behind illicit consent grant attacks.",
    "code": "title: 'Entra ID Application Consent Granted'\nid: 6326ccb0-952f-5211-a837-a57d1f2c1eee\nstatus: test\ndescription: 'Detects user or admin consent to an application, the mechanism behind illicit consent grant attacks.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.credential-access\n    - attack.t1528\nlogsource:\n    product: azure\n    service: auditlogs\ndetection:\n    selection:\n        OperationName:\n            - 'Consent to application'\n            - 'Add delegated permission grant'\n            - 'Add app role assignment to service principal'\n    condition: selection\nfalsepositives:\n    - 'Users adopting new SaaS apps'\nlevel: medium",
    "severity": "medium",
    "category": "credential-access",
    "technique": "T1528",
    "author": "OSINTrix pack",
    "platform": "Azure",
    "tags": [
      "entra",
      "oauth",
      "consent-phishing"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-224",
    "type": "sigma",
    "title": "Entra ID Service Principal or App Credentials Added",
    "description": "Detects new secrets or certificates added to an application or service principal, a common cloud persistence method.",
    "code": "title: 'Entra ID Service Principal or App Credentials Added'\nid: 03f27b2b-a568-5744-8b26-37ae741dfb32\nstatus: test\ndescription: 'Detects new secrets or certificates added to an application or service principal, a common cloud persistence method.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1098.001\nlogsource:\n    product: azure\n    service: auditlogs\ndetection:\n    selection:\n        OperationName:\n            - 'Add service principal credentials'\n            - 'Update application - Certificates and secrets management'\n    condition: selection\nfalsepositives:\n    - 'Routine secret rotation by application owners'\nlevel: high",
    "severity": "high",
    "category": "persistence",
    "technique": "T1098.001",
    "author": "OSINTrix pack",
    "platform": "Azure",
    "tags": [
      "entra",
      "service-principal"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-225",
    "type": "sigma",
    "title": "Entra ID Conditional Access Policy Changed or Deleted",
    "description": "Detects updates or deletion of Conditional Access policies.",
    "code": "title: 'Entra ID Conditional Access Policy Changed or Deleted'\nid: 8c9f4191-b086-5283-9f08-1031315e9f6f\nstatus: test\ndescription: 'Detects updates or deletion of Conditional Access policies.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1556.009\nlogsource:\n    product: azure\n    service: auditlogs\ndetection:\n    selection:\n        OperationName:\n            - 'Update conditional access policy'\n            - 'Delete conditional access policy'\n    condition: selection\nfalsepositives:\n    - 'Planned policy changes by identity team'\nlevel: high",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1556.009",
    "author": "OSINTrix pack",
    "platform": "Azure",
    "tags": [
      "entra",
      "conditional-access"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-226",
    "type": "sigma",
    "title": "Entra ID Global Administrator Role Assigned",
    "description": "Detects members being added to the Global Administrator or Privileged Role Administrator roles.",
    "code": "title: 'Entra ID Global Administrator Role Assigned'\nid: 7f8fec53-d6bc-501d-a6dc-aa936c577378\nstatus: test\ndescription: 'Detects members being added to the Global Administrator or Privileged Role Administrator roles.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.privilege-escalation\n    - attack.t1098.003\nlogsource:\n    product: azure\n    service: auditlogs\ndetection:\n    selection:\n        OperationName: 'Add member to role'\n    selection_role:\n        TargetResources|contains:\n            - 'Global Administrator'\n            - 'Company Administrator'\n            - 'Privileged Role Administrator'\n            - 'Privileged Authentication Administrator'\n    condition: all of selection*\nfalsepositives:\n    - 'Approved privileged role changes'\nlevel: high",
    "severity": "high",
    "category": "privilege-escalation",
    "technique": "T1098.003",
    "author": "OSINTrix pack",
    "platform": "Azure",
    "tags": [
      "entra",
      "global-admin"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-227",
    "type": "sigma",
    "title": "Entra ID Permanent PIM Role Assignment",
    "description": "Detects permanent active or eligible role assignments made through Privileged Identity Management, bypassing time-bound access.",
    "code": "title: 'Entra ID Permanent PIM Role Assignment'\nid: 4409add6-5d30-5e34-9b89-d21f82eab953\nstatus: test\ndescription: 'Detects permanent active or eligible role assignments made through Privileged Identity Management, bypassing time-bound access.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.privilege-escalation\n    - attack.t1098.003\nlogsource:\n    product: azure\n    service: auditlogs\ndetection:\n    selection:\n        OperationName:\n            - 'Add member to role in PIM completed (permanent)'\n            - 'Add eligible member to role in PIM completed (permanent)'\n    condition: selection\nfalsepositives:\n    - 'Break-glass accounts'\nlevel: high",
    "severity": "high",
    "category": "privilege-escalation",
    "technique": "T1098.003",
    "author": "OSINTrix pack",
    "platform": "Azure",
    "tags": [
      "entra",
      "pim"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-228",
    "type": "sigma",
    "title": "Entra ID Domain Federation Settings Changed",
    "description": "Detects changes to domain authentication or federation settings, which can enable forged-token (Golden SAML style) access.",
    "code": "title: 'Entra ID Domain Federation Settings Changed'\nid: 4b433417-0ac5-51e1-995b-decbe9395cae\nstatus: test\ndescription: 'Detects changes to domain authentication or federation settings, which can enable forged-token (Golden SAML style) access.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1484.002\nlogsource:\n    product: azure\n    service: auditlogs\ndetection:\n    selection:\n        OperationName:\n            - 'Set domain authentication'\n            - 'Set federation settings on domain'\n            - 'Add unverified domain'\n            - 'Verify domain'\n    condition: selection\nfalsepositives:\n    - 'Planned federation changes and domain onboarding'\nlevel: critical",
    "severity": "critical",
    "category": "defense-evasion",
    "technique": "T1484.002",
    "author": "OSINTrix pack",
    "platform": "Azure",
    "tags": [
      "entra",
      "federation"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-229",
    "type": "sigma",
    "title": "Entra ID External Guest User Invited",
    "description": "Detects guest invitations, useful to spot attacker-created B2B accounts.",
    "code": "title: 'Entra ID External Guest User Invited'\nid: a1750737-245c-539a-9de3-73fa2dc3c808\nstatus: test\ndescription: 'Detects guest invitations, useful to spot attacker-created B2B accounts.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1136.003\nlogsource:\n    product: azure\n    service: auditlogs\ndetection:\n    selection:\n        OperationName: 'Invite external user'\n    condition: selection\nfalsepositives:\n    - 'Normal collaboration'\nlevel: low",
    "severity": "low",
    "category": "persistence",
    "technique": "T1136.003",
    "author": "OSINTrix pack",
    "platform": "Azure",
    "tags": [
      "entra",
      "guest"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-230",
    "type": "sigma",
    "title": "Azure VM Run Command Executed",
    "description": "Detects Run Command on Azure virtual machines, which executes scripts as SYSTEM/root.",
    "code": "title: 'Azure VM Run Command Executed'\nid: ce0141e1-4f9c-5177-b8bb-63a914740efd\nstatus: test\ndescription: 'Detects Run Command on Azure virtual machines, which executes scripts as SYSTEM/root.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.execution\n    - attack.t1651\nlogsource:\n    product: azure\n    service: activitylogs\ndetection:\n    selection:\n        operationName:\n            - 'Microsoft.Compute/virtualMachines/runCommand/action'\n            - 'Microsoft.Compute/virtualMachines/runCommands/write'\n    condition: selection\nfalsepositives:\n    - 'Operations teams using Run Command for maintenance'\nlevel: medium",
    "severity": "medium",
    "category": "execution",
    "technique": "T1651",
    "author": "OSINTrix pack",
    "platform": "Azure",
    "tags": [
      "azure",
      "run-command"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-231",
    "type": "sigma",
    "title": "Azure Diagnostic Settings Deleted",
    "description": "Detects deletion of diagnostic settings, which stops logs being forwarded.",
    "code": "title: 'Azure Diagnostic Settings Deleted'\nid: a35ada10-2af3-587f-b135-1bbfbc6c10ca\nstatus: test\ndescription: 'Detects deletion of diagnostic settings, which stops logs being forwarded.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1562.008\nlogsource:\n    product: azure\n    service: activitylogs\ndetection:\n    selection:\n        operationName: 'Microsoft.Insights/diagnosticSettings/delete'\n    condition: selection\nfalsepositives:\n    - 'Resource clean-up'\nlevel: high",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1562.008",
    "author": "OSINTrix pack",
    "platform": "Azure",
    "tags": [
      "azure",
      "logging"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-232",
    "type": "sigma",
    "title": "Azure Storage Account Keys Listed",
    "description": "Detects listKeys on storage accounts, which returns full-access keys.",
    "code": "title: 'Azure Storage Account Keys Listed'\nid: 348a4b10-6180-5317-8ac7-5c5cf0ff0afc\nstatus: test\ndescription: 'Detects listKeys on storage accounts, which returns full-access keys.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.credential-access\n    - attack.t1552\nlogsource:\n    product: azure\n    service: activitylogs\ndetection:\n    selection:\n        operationName: 'Microsoft.Storage/storageAccounts/listKeys/action'\n    condition: selection\nfalsepositives:\n    - 'Portal users and tools such as Storage Explorer'\nlevel: low",
    "severity": "low",
    "category": "credential-access",
    "technique": "T1552",
    "author": "OSINTrix pack",
    "platform": "Azure",
    "tags": [
      "azure",
      "storage"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-233",
    "type": "sigma",
    "title": "GCP Service Account Key Created",
    "description": "Detects creation of user-managed service account keys.",
    "code": "title: 'GCP Service Account Key Created'\nid: edf33c6a-4e58-5244-b2bb-3fbcc073c091\nstatus: test\ndescription: 'Detects creation of user-managed service account keys.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1098.001\nlogsource:\n    product: gcp\n    service: gcp.audit\ndetection:\n    selection:\n        data.protoPayload.methodName: 'google.iam.admin.v1.CreateServiceAccountKey'\n    condition: selection\nfalsepositives:\n    - 'Legacy integrations that require JSON keys'\nlevel: medium",
    "severity": "medium",
    "category": "persistence",
    "technique": "T1098.001",
    "author": "OSINTrix pack",
    "platform": "GCP",
    "tags": [
      "gcp",
      "service-account"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-234",
    "type": "sigma",
    "title": "GCP IAM Policy Grants Access to allUsers",
    "description": "Detects SetIamPolicy calls that add allUsers or allAuthenticatedUsers bindings.",
    "code": "title: 'GCP IAM Policy Grants Access to allUsers'\nid: 7665df4d-3f49-5da9-8663-85dcf1991272\nstatus: test\ndescription: 'Detects SetIamPolicy calls that add allUsers or allAuthenticatedUsers bindings.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.exfiltration\n    - attack.t1537\nlogsource:\n    product: gcp\n    service: gcp.audit\ndetection:\n    selection:\n        data.protoPayload.methodName|endswith:\n            - 'SetIamPolicy'\n            - 'setIamPermissions'\n    selection_member:\n        data.protoPayload.serviceData.policyDelta.bindingDeltas.member:\n            - 'allUsers'\n            - 'allAuthenticatedUsers'\n    condition: all of selection*\nfalsepositives:\n    - 'Public buckets for static content'\nlevel: high",
    "severity": "high",
    "category": "exfiltration",
    "technique": "T1537",
    "author": "OSINTrix pack",
    "platform": "GCP",
    "tags": [
      "gcp",
      "iam",
      "exposure"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-235",
    "type": "sigma",
    "title": "GCP Owner Role Granted",
    "description": "Detects SetIamPolicy adding a binding for roles/owner.",
    "code": "title: 'GCP Owner Role Granted'\nid: e11852d6-f3f7-5185-9fcb-0b9124b73767\nstatus: test\ndescription: 'Detects SetIamPolicy adding a binding for roles/owner.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.privilege-escalation\n    - attack.t1098.003\nlogsource:\n    product: gcp\n    service: gcp.audit\ndetection:\n    selection:\n        data.protoPayload.methodName|endswith: 'SetIamPolicy'\n        data.protoPayload.serviceData.policyDelta.bindingDeltas.action: 'ADD'\n        data.protoPayload.serviceData.policyDelta.bindingDeltas.role: 'roles/owner'\n    condition: selection\nfalsepositives:\n    - 'Project bootstrap by platform team'\nlevel: high",
    "severity": "high",
    "category": "privilege-escalation",
    "technique": "T1098.003",
    "author": "OSINTrix pack",
    "platform": "GCP",
    "tags": [
      "gcp",
      "iam"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-236",
    "type": "sigma",
    "title": "GCP Firewall Rule Allowing Any Source",
    "description": "Detects compute firewall inserts or patches with sourceRanges 0.0.0.0/0.",
    "code": "title: 'GCP Firewall Rule Allowing Any Source'\nid: 9179f2ca-21a4-5bda-80ee-adb4679ef724\nstatus: test\ndescription: 'Detects compute firewall inserts or patches with sourceRanges 0.0.0.0/0.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1562.007\nlogsource:\n    product: gcp\n    service: gcp.audit\ndetection:\n    selection:\n        data.protoPayload.methodName:\n            - 'v1.compute.firewalls.insert'\n            - 'v1.compute.firewalls.patch'\n            - 'beta.compute.firewalls.insert'\n    selection_src:\n        data.protoPayload.request.sourceRanges: '0.0.0.0/0'\n    condition: all of selection*\nfalsepositives:\n    - 'Public web front ends'\nlevel: medium",
    "severity": "medium",
    "category": "defense-evasion",
    "technique": "T1562.007",
    "author": "OSINTrix pack",
    "platform": "GCP",
    "tags": [
      "gcp",
      "firewall"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-237",
    "type": "sigma",
    "title": "GCP Logging Sink Deleted or Modified",
    "description": "Detects deletion or modification of Cloud Logging sinks.",
    "code": "title: 'GCP Logging Sink Deleted or Modified'\nid: 70943a17-c124-5d06-bb65-8fc749df3275\nstatus: test\ndescription: 'Detects deletion or modification of Cloud Logging sinks.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1562.008\nlogsource:\n    product: gcp\n    service: gcp.audit\ndetection:\n    selection:\n        data.protoPayload.methodName:\n            - 'google.logging.v2.ConfigServiceV2.DeleteSink'\n            - 'google.logging.v2.ConfigServiceV2.UpdateSink'\n    condition: selection\nfalsepositives:\n    - 'Logging architecture changes'\nlevel: high",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1562.008",
    "author": "OSINTrix pack",
    "platform": "GCP",
    "tags": [
      "gcp",
      "logging"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-238",
    "type": "sigma",
    "title": "GCP Compute Startup Script Metadata Set",
    "description": "Detects setMetadata / setCommonInstanceMetadata calls, which can inject startup scripts or SSH keys.",
    "code": "title: 'GCP Compute Startup Script Metadata Set'\nid: 999cb3c2-1658-5c06-b54a-20ab2bdb1282\nstatus: test\ndescription: 'Detects setMetadata / setCommonInstanceMetadata calls, which can inject startup scripts or SSH keys.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1098.004\nlogsource:\n    product: gcp\n    service: gcp.audit\ndetection:\n    selection:\n        data.protoPayload.methodName|endswith:\n            - 'compute.instances.setMetadata'\n            - 'compute.projects.setCommonInstanceMetadata'\n    condition: selection\nfalsepositives:\n    - 'OS Login migration and IaC deployments'\nlevel: medium",
    "severity": "medium",
    "category": "persistence",
    "technique": "T1098.004",
    "author": "OSINTrix pack",
    "platform": "GCP",
    "tags": [
      "gcp",
      "metadata",
      "ssh-keys"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-239",
    "type": "sigma",
    "title": "GCP Service Account Impersonation Token Generated",
    "description": "Detects GenerateAccessToken / SignJwt by a human user, a technique for escalating via service account impersonation.",
    "code": "title: 'GCP Service Account Impersonation Token Generated'\nid: 4bdd2cce-3bd6-5eaa-8b0e-5c0539f9e6a7\nstatus: test\ndescription: 'Detects GenerateAccessToken / SignJwt by a human user, a technique for escalating via service account impersonation.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.privilege-escalation\n    - attack.t1550.001\nlogsource:\n    product: gcp\n    service: gcp.audit\ndetection:\n    selection:\n        data.protoPayload.methodName|endswith:\n            - 'GenerateAccessToken'\n            - 'SignJwt'\n            - 'SignBlob'\n    filter_sa:\n        data.protoPayload.authenticationInfo.principalEmail|endswith: '.gserviceaccount.com'\n    condition: selection and not filter_sa\nfalsepositives:\n    - 'Engineers using gcloud --impersonate-service-account as part of normal workflows'\nlevel: medium",
    "severity": "medium",
    "category": "privilege-escalation",
    "technique": "T1550.001",
    "author": "OSINTrix pack",
    "platform": "GCP",
    "tags": [
      "gcp",
      "impersonation"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-240",
    "type": "sigma",
    "title": "Kubernetes Exec Into Pod",
    "description": "Detects creation of the exec subresource on a pod (kubectl exec).",
    "code": "title: 'Kubernetes Exec Into Pod'\nid: a153c308-1e1f-5e3d-bc82-f44cdc2eebcf\nstatus: test\ndescription: 'Detects creation of the exec subresource on a pod (kubectl exec).'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.execution\n    - attack.t1609\nlogsource:\n    product: kubernetes\n    service: audit\ndetection:\n    selection:\n        verb: 'create'\n        objectRef.resource: 'pods'\n        objectRef.subresource: 'exec'\n    condition: selection\nfalsepositives:\n    - 'Engineers debugging workloads'\nlevel: medium",
    "severity": "medium",
    "category": "execution",
    "technique": "T1609",
    "author": "OSINTrix pack",
    "platform": "Kubernetes",
    "tags": [
      "kubernetes",
      "exec"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-241",
    "type": "sigma",
    "title": "Kubernetes Privileged Pod Created",
    "description": "Detects pods created with a privileged security context.",
    "code": "title: 'Kubernetes Privileged Pod Created'\nid: cf2f0fc9-fd1a-58c1-9a4b-5740d008dfc7\nstatus: test\ndescription: 'Detects pods created with a privileged security context.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.privilege-escalation\n    - attack.t1610\nlogsource:\n    product: kubernetes\n    service: audit\ndetection:\n    selection:\n        verb: 'create'\n        objectRef.resource: 'pods'\n        requestObject.spec.containers.securityContext.privileged: 'true'\n    condition: selection\nfalsepositives:\n    - 'CNI, CSI and monitoring DaemonSets'\nlevel: high",
    "severity": "high",
    "category": "privilege-escalation",
    "technique": "T1610",
    "author": "OSINTrix pack",
    "platform": "Kubernetes",
    "tags": [
      "kubernetes",
      "privileged"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-242",
    "type": "sigma",
    "title": "Kubernetes Pod With Sensitive HostPath Mount",
    "description": "Detects pods mounting host paths such as /, /etc, /var/run/docker.sock or /proc.",
    "code": "title: 'Kubernetes Pod With Sensitive HostPath Mount'\nid: e9a5b0c6-ccae-51f2-93d3-b089d602e7a7\nstatus: test\ndescription: 'Detects pods mounting host paths such as /, /etc, /var/run/docker.sock or /proc.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.privilege-escalation\n    - attack.t1611\nlogsource:\n    product: kubernetes\n    service: audit\ndetection:\n    selection:\n        verb: 'create'\n        objectRef.resource: 'pods'\n        requestObject.spec.volumes.hostPath.path:\n            - '/'\n            - '/etc'\n            - '/proc'\n            - '/root'\n            - '/var/run/docker.sock'\n            - '/run/containerd/containerd.sock'\n            - '/var/lib/kubelet'\n    condition: selection\nfalsepositives:\n    - 'Node agents (log shippers, security agents)'\nlevel: high",
    "severity": "high",
    "category": "privilege-escalation",
    "technique": "T1611",
    "author": "OSINTrix pack",
    "platform": "Kubernetes",
    "tags": [
      "kubernetes",
      "hostpath"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-243",
    "type": "sigma",
    "title": "Kubernetes Pod Using Host Namespaces",
    "description": "Detects pods created with hostPID, hostIPC or hostNetwork.",
    "code": "title: 'Kubernetes Pod Using Host Namespaces'\nid: e6fd9751-0b0f-57b4-ac0b-d938e9a1f138\nstatus: test\ndescription: 'Detects pods created with hostPID, hostIPC or hostNetwork.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.privilege-escalation\n    - attack.t1611\nlogsource:\n    product: kubernetes\n    service: audit\ndetection:\n    selection:\n        verb: 'create'\n        objectRef.resource: 'pods'\n    selection_ns:\n        - requestObject.spec.hostPID: 'true'\n        - requestObject.spec.hostIPC: 'true'\n        - requestObject.spec.hostNetwork: 'true'\n    condition: all of selection*\nfalsepositives:\n    - 'kube-proxy, CNI plugins, node exporters'\nlevel: medium",
    "severity": "medium",
    "category": "privilege-escalation",
    "technique": "T1611",
    "author": "OSINTrix pack",
    "platform": "Kubernetes",
    "tags": [
      "kubernetes",
      "host-namespaces"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-244",
    "type": "sigma",
    "title": "Kubernetes ClusterRoleBinding to cluster-admin",
    "description": "Detects creation of a (Cluster)RoleBinding that references the cluster-admin ClusterRole.",
    "code": "title: 'Kubernetes ClusterRoleBinding to cluster-admin'\nid: 2185089f-d98e-5675-a007-3ab9a27e6b31\nstatus: test\ndescription: 'Detects creation of a (Cluster)RoleBinding that references the cluster-admin ClusterRole.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.privilege-escalation\n    - attack.t1098\nlogsource:\n    product: kubernetes\n    service: audit\ndetection:\n    selection:\n        verb: 'create'\n        objectRef.resource:\n            - 'clusterrolebindings'\n            - 'rolebindings'\n        requestObject.roleRef.name: 'cluster-admin'\n    condition: selection\nfalsepositives:\n    - 'Cluster bootstrap and operator installation'\nlevel: high",
    "severity": "high",
    "category": "privilege-escalation",
    "technique": "T1098",
    "author": "OSINTrix pack",
    "platform": "Kubernetes",
    "tags": [
      "kubernetes",
      "rbac"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-245",
    "type": "sigma",
    "title": "Kubernetes Secrets Enumerated by Non-System User",
    "description": "Detects list/get of secrets by identities that are not system components.",
    "code": "title: 'Kubernetes Secrets Enumerated by Non-System User'\nid: 58e47278-32a1-5586-9e9e-2505407e6305\nstatus: test\ndescription: 'Detects list/get of secrets by identities that are not system components.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.credential-access\n    - attack.t1552.007\nlogsource:\n    product: kubernetes\n    service: audit\ndetection:\n    selection:\n        verb:\n            - 'list'\n            - 'get'\n            - 'watch'\n        objectRef.resource: 'secrets'\n    filter_system:\n        user.username|startswith: 'system:'\n    condition: selection and not filter_system\nfalsepositives:\n    - 'CI/CD service accounts and operators reading their own secrets'\nlevel: medium",
    "severity": "medium",
    "category": "credential-access",
    "technique": "T1552.007",
    "author": "OSINTrix pack",
    "platform": "Kubernetes",
    "tags": [
      "kubernetes",
      "secrets"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-246",
    "type": "sigma",
    "title": "Kubernetes Anonymous Request Allowed",
    "description": "Detects API requests by system:anonymous that were authorised.",
    "code": "title: 'Kubernetes Anonymous Request Allowed'\nid: 78a0ddda-18ae-56ad-a132-f7689e5917b9\nstatus: test\ndescription: 'Detects API requests by system:anonymous that were authorised.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.initial-access\n    - attack.t1078\nlogsource:\n    product: kubernetes\n    service: audit\ndetection:\n    selection:\n        user.username: 'system:anonymous'\n        annotations.authorization.k8s.io/decision: 'allow'\n    filter_health:\n        requestURI:\n            - '/healthz'\n            - '/livez'\n            - '/readyz'\n            - '/version'\n    condition: selection and not filter_health\nfalsepositives:\n    - 'Clusters that intentionally allow anonymous discovery endpoints'\nlevel: high",
    "severity": "high",
    "category": "initial-access",
    "technique": "T1078",
    "author": "OSINTrix pack",
    "platform": "Kubernetes",
    "tags": [
      "kubernetes",
      "anonymous"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-247",
    "type": "sigma",
    "title": "Kubernetes CronJob Created in kube-system",
    "description": "Detects CronJobs created in kube-system, a namespace attackers use to blend persistence with system workloads.",
    "code": "title: 'Kubernetes CronJob Created in kube-system'\nid: a0493d00-7544-5887-b1f7-6f67ec3c0a1b\nstatus: test\ndescription: 'Detects CronJobs created in kube-system, a namespace attackers use to blend persistence with system workloads.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1053.007\nlogsource:\n    product: kubernetes\n    service: audit\ndetection:\n    selection:\n        verb: 'create'\n        objectRef.resource: 'cronjobs'\n        objectRef.namespace: 'kube-system'\n    condition: selection\nfalsepositives:\n    - 'Platform add-ons that schedule jobs in kube-system'\nlevel: medium",
    "severity": "medium",
    "category": "persistence",
    "technique": "T1053.007",
    "author": "OSINTrix pack",
    "platform": "Kubernetes",
    "tags": [
      "kubernetes",
      "cronjob"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-248",
    "type": "sigma",
    "title": "Kubernetes Service Account Token Requested",
    "description": "Detects creation of the token subresource for a service account by a user, e.g. kubectl create token.",
    "code": "title: 'Kubernetes Service Account Token Requested'\nid: a357ecc6-5e44-5624-865c-848addec10ec\nstatus: test\ndescription: 'Detects creation of the token subresource for a service account by a user, e.g. kubectl create token.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.credential-access\n    - attack.t1528\nlogsource:\n    product: kubernetes\n    service: audit\ndetection:\n    selection:\n        verb: 'create'\n        objectRef.resource: 'serviceaccounts'\n        objectRef.subresource: 'token'\n    filter_system:\n        user.username|startswith: 'system:'\n    condition: selection and not filter_system\nfalsepositives:\n    - 'Administrators generating tokens for automation'\nlevel: low",
    "severity": "low",
    "category": "credential-access",
    "technique": "T1528",
    "author": "OSINTrix pack",
    "platform": "Kubernetes",
    "tags": [
      "kubernetes",
      "token"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-249",
    "type": "sigma",
    "title": "Kubernetes Port Forward to Pod",
    "description": "Detects the portforward subresource, which tunnels traffic into a pod.",
    "code": "title: 'Kubernetes Port Forward to Pod'\nid: d137c386-54d5-5ddd-b312-048020b4a6b0\nstatus: test\ndescription: 'Detects the portforward subresource, which tunnels traffic into a pod.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.command-and-control\n    - attack.t1572\nlogsource:\n    product: kubernetes\n    service: audit\ndetection:\n    selection:\n        verb: 'create'\n        objectRef.resource: 'pods'\n        objectRef.subresource: 'portforward'\n    condition: selection\nfalsepositives:\n    - 'Developers accessing services locally'\nlevel: low",
    "severity": "low",
    "category": "command-and-control",
    "technique": "T1572",
    "author": "OSINTrix pack",
    "platform": "Kubernetes",
    "tags": [
      "kubernetes",
      "port-forward"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-250",
    "type": "sigma",
    "title": "Exchange Inbox Rule Forwarding, Deleting or Hiding Mail",
    "description": "Detects New-InboxRule / Set-InboxRule that forwards, redirects, deletes or moves mail to RSS/Archive folders, typical of BEC.",
    "code": "title: 'Exchange Inbox Rule Forwarding, Deleting or Hiding Mail'\nid: 2437a0cc-146f-5f99-81aa-9aa2dce51343\nstatus: test\ndescription: 'Detects New-InboxRule / Set-InboxRule that forwards, redirects, deletes or moves mail to RSS/Archive folders, typical of BEC.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.collection\n    - attack.t1564.008\nlogsource:\n    product: m365\n    service: audit\ndetection:\n    selection:\n        Operation:\n            - 'New-InboxRule'\n            - 'Set-InboxRule'\n            - 'UpdateInboxRules'\n    selection_param:\n        Parameters|contains:\n            - 'ForwardTo'\n            - 'ForwardAsAttachmentTo'\n            - 'RedirectTo'\n            - 'DeleteMessage'\n            - 'RSS Feeds'\n            - 'RSS Subscriptions'\n            - 'Conversation History'\n            - 'MarkAsRead'\n    condition: all of selection*\nfalsepositives:\n    - 'Users organising mail with legitimate rules'\nlevel: high",
    "severity": "high",
    "category": "collection",
    "technique": "T1564.008",
    "author": "OSINTrix pack",
    "platform": "M365",
    "tags": [
      "bec",
      "inbox-rule"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-251",
    "type": "sigma",
    "title": "Exchange Mailbox SMTP Forwarding Configured",
    "description": "Detects Set-Mailbox setting ForwardingSmtpAddress or ForwardingAddress.",
    "code": "title: 'Exchange Mailbox SMTP Forwarding Configured'\nid: ac2cc874-26dd-5080-a68f-b0966f1f5a23\nstatus: test\ndescription: 'Detects Set-Mailbox setting ForwardingSmtpAddress or ForwardingAddress.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.collection\n    - attack.t1114.003\nlogsource:\n    product: m365\n    service: audit\ndetection:\n    selection:\n        Operation: 'Set-Mailbox'\n        Parameters|contains:\n            - 'ForwardingSmtpAddress'\n            - 'ForwardingAddress'\n            - 'DeliverToMailboxAndForward'\n    condition: selection\nfalsepositives:\n    - 'Leavers'' mail forwarded to managers'\nlevel: high",
    "severity": "high",
    "category": "collection",
    "technique": "T1114.003",
    "author": "OSINTrix pack",
    "platform": "M365",
    "tags": [
      "bec",
      "forwarding"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-252",
    "type": "sigma",
    "title": "Exchange Transport Rule Redirecting or Copying Mail",
    "description": "Detects New-TransportRule or Set-TransportRule with BlindCopyTo, RedirectMessageTo or CopyTo actions.",
    "code": "title: 'Exchange Transport Rule Redirecting or Copying Mail'\nid: 33912f06-dbaf-537f-8d0c-fa8440171f9b\nstatus: test\ndescription: 'Detects New-TransportRule or Set-TransportRule with BlindCopyTo, RedirectMessageTo or CopyTo actions.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.collection\n    - attack.t1114.003\nlogsource:\n    product: m365\n    service: audit\ndetection:\n    selection:\n        Operation:\n            - 'New-TransportRule'\n            - 'Set-TransportRule'\n        Parameters|contains:\n            - 'BlindCopyTo'\n            - 'RedirectMessageTo'\n            - 'CopyTo'\n            - 'AddToRecipients'\n    condition: selection\nfalsepositives:\n    - 'Compliance journaling rules'\nlevel: high",
    "severity": "high",
    "category": "collection",
    "technique": "T1114.003",
    "author": "OSINTrix pack",
    "platform": "M365",
    "tags": [
      "exchange",
      "transport-rule"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-253",
    "type": "sigma",
    "title": "Microsoft Purview eDiscovery Search Created or Exported",
    "description": "Detects compliance search creation, start and export actions, which can be abused to collect mail across the tenant.",
    "code": "title: 'Microsoft Purview eDiscovery Search Created or Exported'\nid: 4644e7d7-4208-51b7-aeac-c6ce5ffd1181\nstatus: test\ndescription: 'Detects compliance search creation, start and export actions, which can be abused to collect mail across the tenant.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.collection\n    - attack.t1114.002\nlogsource:\n    product: m365\n    service: audit\ndetection:\n    selection:\n        Operation:\n            - 'New-ComplianceSearch'\n            - 'Start-ComplianceSearch'\n            - 'New-ComplianceSearchAction'\n            - 'SearchExported'\n    condition: selection\nfalsepositives:\n    - 'Legal and HR investigations'\nlevel: medium",
    "severity": "medium",
    "category": "collection",
    "technique": "T1114.002",
    "author": "OSINTrix pack",
    "platform": "M365",
    "tags": [
      "ediscovery",
      "purview"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-254",
    "type": "sigma",
    "title": "Exchange FullAccess Mailbox Permission Granted",
    "description": "Detects Add-MailboxPermission granting FullAccess to another account.",
    "code": "title: 'Exchange FullAccess Mailbox Permission Granted'\nid: 5914b0a3-83fc-5b76-abbc-fa1da5299434\nstatus: test\ndescription: 'Detects Add-MailboxPermission granting FullAccess to another account.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1098.002\nlogsource:\n    product: m365\n    service: audit\ndetection:\n    selection:\n        Operation: 'Add-MailboxPermission'\n        Parameters|contains: 'FullAccess'\n    condition: selection\nfalsepositives:\n    - 'Delegated assistant access'\nlevel: medium",
    "severity": "medium",
    "category": "persistence",
    "technique": "T1098.002",
    "author": "OSINTrix pack",
    "platform": "M365",
    "tags": [
      "exchange",
      "delegation"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-255",
    "type": "sigma",
    "title": "Exchange ApplicationImpersonation Role Assigned",
    "description": "Detects New-ManagementRoleAssignment of the ApplicationImpersonation role, which allows access to any mailbox.",
    "code": "title: 'Exchange ApplicationImpersonation Role Assigned'\nid: a8cb6818-5216-5a1b-81ac-09f73ca44501\nstatus: test\ndescription: 'Detects New-ManagementRoleAssignment of the ApplicationImpersonation role, which allows access to any mailbox.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.privilege-escalation\n    - attack.t1098\nlogsource:\n    product: m365\n    service: audit\ndetection:\n    selection:\n        Operation: 'New-ManagementRoleAssignment'\n        Parameters|contains: 'ApplicationImpersonation'\n    condition: selection\nfalsepositives:\n    - 'Migration or backup tools during onboarding'\nlevel: high",
    "severity": "high",
    "category": "privilege-escalation",
    "technique": "T1098",
    "author": "OSINTrix pack",
    "platform": "M365",
    "tags": [
      "exchange",
      "impersonation"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-256",
    "type": "sigma",
    "title": "Unified Audit Log Ingestion Disabled",
    "description": "Detects Set-AdminAuditLogConfig turning off UnifiedAuditLogIngestionEnabled.",
    "code": "title: 'Unified Audit Log Ingestion Disabled'\nid: 8f37e9be-526b-5fa3-b077-bf8d7838f6c9\nstatus: test\ndescription: 'Detects Set-AdminAuditLogConfig turning off UnifiedAuditLogIngestionEnabled.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1562.008\nlogsource:\n    product: m365\n    service: audit\ndetection:\n    selection:\n        Operation: 'Set-AdminAuditLogConfig'\n        Parameters|contains|all:\n            - 'UnifiedAuditLogIngestionEnabled'\n            - 'False'\n    condition: selection\nfalsepositives:\n    - 'None expected'\nlevel: high",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1562.008",
    "author": "OSINTrix pack",
    "platform": "M365",
    "tags": [
      "audit-log"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-257",
    "type": "sigma",
    "title": "SharePoint or OneDrive Mass File Download",
    "description": "Detects a single user downloading or syncing a large number of files in a short period.",
    "code": "title: 'SharePoint or OneDrive Mass File Download'\nid: 6164b697-5628-5f45-8acc-5f014f18f137\nstatus: test\ndescription: 'Detects a single user downloading or syncing a large number of files in a short period.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.collection\n    - attack.t1530\nlogsource:\n    product: m365\n    service: audit\ndetection:\n    selection:\n        Operation:\n            - 'FileDownloaded'\n            - 'FileSyncDownloadedFull'\n    condition: selection | count(ObjectId) by UserId > 200\n    timeframe: 15m\nfalsepositives:\n    - 'OneDrive initial sync on a new device'\nlevel: medium",
    "severity": "medium",
    "category": "collection",
    "technique": "T1530",
    "author": "OSINTrix pack",
    "platform": "M365",
    "tags": [
      "sharepoint",
      "exfiltration"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-258",
    "type": "sigma",
    "title": "SharePoint Anonymous Sharing Link Created",
    "description": "Detects creation of anyone-with-the-link sharing links.",
    "code": "title: 'SharePoint Anonymous Sharing Link Created'\nid: 5c474a2f-f323-5ed6-b11b-ad74fed83f6b\nstatus: test\ndescription: 'Detects creation of anyone-with-the-link sharing links.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.exfiltration\n    - attack.t1567\nlogsource:\n    product: m365\n    service: audit\ndetection:\n    selection:\n        Operation:\n            - 'AnonymousLinkCreated'\n            - 'AnonymousLinkUpdated'\n    condition: selection\nfalsepositives:\n    - 'Intentional public sharing'\nlevel: low",
    "severity": "low",
    "category": "exfiltration",
    "technique": "T1567",
    "author": "OSINTrix pack",
    "platform": "M365",
    "tags": [
      "sharepoint",
      "sharing"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-259",
    "type": "sigma",
    "title": "Okta MFA Factors Reset or Deactivated",
    "description": "Detects resetting or deactivating a user's MFA factors.",
    "code": "title: 'Okta MFA Factors Reset or Deactivated'\nid: 72ee1e50-b069-5a38-8e7c-aa2cd45e5998\nstatus: test\ndescription: 'Detects resetting or deactivating a user''s MFA factors.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1556.006\nlogsource:\n    product: okta\n    service: okta\ndetection:\n    selection:\n        eventType:\n            - 'user.mfa.factor.reset_all'\n            - 'user.mfa.factor.deactivate'\n    condition: selection\nfalsepositives:\n    - 'Helpdesk resets for lost devices'\nlevel: medium",
    "severity": "medium",
    "category": "defense-evasion",
    "technique": "T1556.006",
    "author": "OSINTrix pack",
    "platform": "Okta",
    "tags": [
      "okta",
      "mfa"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-260",
    "type": "sigma",
    "title": "Okta Administrator Role Assigned",
    "description": "Detects admin privileges granted to a user or group.",
    "code": "title: 'Okta Administrator Role Assigned'\nid: 0c5112e0-d233-5b77-9e6a-fc7b47ac7d04\nstatus: test\ndescription: 'Detects admin privileges granted to a user or group.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.privilege-escalation\n    - attack.t1098.003\nlogsource:\n    product: okta\n    service: okta\ndetection:\n    selection:\n        eventType:\n            - 'user.account.privilege.grant'\n            - 'group.privilege.grant'\n    condition: selection\nfalsepositives:\n    - 'Planned admin onboarding'\nlevel: high",
    "severity": "high",
    "category": "privilege-escalation",
    "technique": "T1098.003",
    "author": "OSINTrix pack",
    "platform": "Okta",
    "tags": [
      "okta",
      "admin"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-261",
    "type": "sigma",
    "title": "Okta Sign-In With Velocity Anomaly",
    "description": "Detects sessions where Okta behaviour detection flagged Velocity (impossible travel) as POSITIVE.",
    "code": "title: 'Okta Sign-In With Velocity Anomaly'\nid: 71a84510-65c0-50b3-9974-56b927b9c6b9\nstatus: test\ndescription: 'Detects sessions where Okta behaviour detection flagged Velocity (impossible travel) as POSITIVE.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.initial-access\n    - attack.t1078.004\nlogsource:\n    product: okta\n    service: okta\ndetection:\n    selection:\n        eventType: 'user.session.start'\n        debugContext.debugData.behaviors|contains: 'Velocity=POSITIVE'\n    condition: selection\nfalsepositives:\n    - 'VPN or mobile network hops'\nlevel: medium",
    "severity": "medium",
    "category": "initial-access",
    "technique": "T1078.004",
    "author": "OSINTrix pack",
    "platform": "Okta",
    "tags": [
      "okta",
      "impossible-travel"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-262",
    "type": "sigma",
    "title": "Okta Authentication Policy Deactivated or Deleted",
    "description": "Detects policies or policy rules being deactivated or deleted.",
    "code": "title: 'Okta Authentication Policy Deactivated or Deleted'\nid: 49b93ff9-75e5-5c71-983a-028f6dc8ea71\nstatus: test\ndescription: 'Detects policies or policy rules being deactivated or deleted.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1556\nlogsource:\n    product: okta\n    service: okta\ndetection:\n    selection:\n        eventType:\n            - 'policy.lifecycle.deactivate'\n            - 'policy.lifecycle.delete'\n            - 'policy.rule.deactivate'\n            - 'policy.rule.delete'\n    condition: selection\nfalsepositives:\n    - 'Policy restructuring'\nlevel: medium",
    "severity": "medium",
    "category": "defense-evasion",
    "technique": "T1556",
    "author": "OSINTrix pack",
    "platform": "Okta",
    "tags": [
      "okta",
      "policy"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-263",
    "type": "sigma",
    "title": "Okta API Token Created",
    "description": "Detects creation of Okta API tokens, which inherit the creating admin's privileges.",
    "code": "title: 'Okta API Token Created'\nid: 0a8ef38e-e666-50e6-b043-b5da10605df2\nstatus: test\ndescription: 'Detects creation of Okta API tokens, which inherit the creating admin''s privileges.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1098.001\nlogsource:\n    product: okta\n    service: okta\ndetection:\n    selection:\n        eventType: 'system.api_token.create'\n    condition: selection\nfalsepositives:\n    - 'Integration set-up by admins'\nlevel: medium",
    "severity": "medium",
    "category": "persistence",
    "technique": "T1098.001",
    "author": "OSINTrix pack",
    "platform": "Okta",
    "tags": [
      "okta",
      "api-token"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-264",
    "type": "sigma",
    "title": "Okta Push Notification Fatigue",
    "description": "Detects many Okta Verify push denials for a user, which indicates MFA bombing.",
    "code": "title: 'Okta Push Notification Fatigue'\nid: 5d78f35d-edd1-54c5-a344-01d447574472\nstatus: test\ndescription: 'Detects many Okta Verify push denials for a user, which indicates MFA bombing.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.credential-access\n    - attack.t1621\nlogsource:\n    product: okta\n    service: okta\ndetection:\n    selection:\n        eventType: 'user.mfa.okta_verify.deny_push'\n    condition: selection | count() by actor.alternateId > 3\n    timeframe: 10m\nfalsepositives:\n    - 'Users accidentally denying pushes'\nlevel: medium",
    "severity": "medium",
    "category": "credential-access",
    "technique": "T1621",
    "author": "OSINTrix pack",
    "platform": "Okta",
    "tags": [
      "okta",
      "mfa-fatigue"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-265",
    "type": "sigma",
    "title": "Okta Identity Provider Created or Modified",
    "description": "Detects creation or update of an inbound identity provider, which can allow sign-in as any user.",
    "code": "title: 'Okta Identity Provider Created or Modified'\nid: 25c82dfe-83fd-5879-8d7b-0cee7c35209e\nstatus: test\ndescription: 'Detects creation or update of an inbound identity provider, which can allow sign-in as any user.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.defense-evasion\n    - attack.t1484.002\nlogsource:\n    product: okta\n    service: okta\ndetection:\n    selection:\n        eventType:\n            - 'system.idp.lifecycle.create'\n            - 'system.idp.lifecycle.update'\n    condition: selection\nfalsepositives:\n    - 'Planned federation projects'\nlevel: high",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1484.002",
    "author": "OSINTrix pack",
    "platform": "Okta",
    "tags": [
      "okta",
      "idp",
      "federation"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-266",
    "type": "sigma",
    "title": "Okta ThreatInsight Threat Detected",
    "description": "Detects Okta ThreatInsight flagging requests from known malicious infrastructure.",
    "code": "title: 'Okta ThreatInsight Threat Detected'\nid: e07c49b9-d337-5658-92b4-a45f8e7229c9\nstatus: test\ndescription: 'Detects Okta ThreatInsight flagging requests from known malicious infrastructure.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.credential-access\n    - attack.t1110\nlogsource:\n    product: okta\n    service: okta\ndetection:\n    selection:\n        eventType: 'security.threat.detected'\n    condition: selection\nfalsepositives:\n    - 'Shared IP space with abusive tenants'\nlevel: medium",
    "severity": "medium",
    "category": "credential-access",
    "technique": "T1110",
    "author": "OSINTrix pack",
    "platform": "Okta",
    "tags": [
      "okta",
      "threatinsight"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-267",
    "type": "sigma",
    "title": "Web Server Process Spawning Command Shell on Windows",
    "description": "Detects IIS w3wp, Apache httpd, Tomcat or nginx processes spawning cmd, PowerShell or recon tools, which usually indicates a web shell.",
    "code": "title: 'Web Server Process Spawning Command Shell on Windows'\nid: f11ea9d1-7d1b-5a3e-9c91-303025b2d509\nstatus: test\ndescription: 'Detects IIS w3wp, Apache httpd, Tomcat or nginx processes spawning cmd, PowerShell or recon tools, which usually indicates a web shell.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1505.003\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_parent:\n        ParentImage|endswith:\n            - '\\w3wp.exe'\n            - '\\httpd.exe'\n            - '\\nginx.exe'\n            - '\\php-cgi.exe'\n            - '\\tomcat.exe'\n            - '\\tomcat8.exe'\n            - '\\tomcat9.exe'\n            - '\\UMWorkerProcess.exe'\n    selection_child:\n        Image|endswith:\n            - '\\cmd.exe'\n            - '\\powershell.exe'\n            - '\\pwsh.exe'\n            - '\\whoami.exe'\n            - '\\net.exe'\n            - '\\net1.exe'\n            - '\\ipconfig.exe'\n            - '\\systeminfo.exe'\n            - '\\certutil.exe'\n            - '\\nltest.exe'\n    condition: all of selection_*\nfalsepositives:\n    - 'Web applications that legitimately shell out (rare; document them)'\nlevel: critical",
    "severity": "critical",
    "category": "webshell",
    "technique": "T1505.003",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "webshell",
      "iis"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-268",
    "type": "sigma",
    "title": "Web Server Process Spawning Shell on Linux",
    "description": "Detects Apache, nginx, php-fpm or lighttpd spawning shells or reconnaissance commands.",
    "code": "title: 'Web Server Process Spawning Shell on Linux'\nid: ae49b025-9d5f-5688-9a82-9b4166f7af88\nstatus: test\ndescription: 'Detects Apache, nginx, php-fpm or lighttpd spawning shells or reconnaissance commands.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1505.003\nlogsource:\n    category: process_creation\n    product: linux\ndetection:\n    selection_parent:\n        ParentImage|endswith:\n            - '/httpd'\n            - '/apache2'\n            - '/nginx'\n            - '/php-fpm'\n            - '/lighttpd'\n            - '/caddy'\n    selection_child:\n        Image|endswith:\n            - '/sh'\n            - '/bash'\n            - '/dash'\n            - '/whoami'\n            - '/id'\n            - '/uname'\n            - '/wget'\n            - '/curl'\n            - '/nc'\n            - '/python3'\n            - '/perl'\n    condition: all of selection_*\nfalsepositives:\n    - 'CGI scripts and PHP applications calling system binaries (e.g. ImageMagick wrappers)'\nlevel: high",
    "severity": "high",
    "category": "webshell",
    "technique": "T1505.003",
    "author": "OSINTrix pack",
    "platform": "Linux",
    "tags": [
      "webshell",
      "apache",
      "nginx"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-269",
    "type": "sigma",
    "title": "Java Application Server Spawning Shell",
    "description": "Detects java processes (Tomcat, JBoss, WebLogic, Confluence) spawning shells, a common outcome of deserialisation, OGNL or JNDI exploitation.",
    "code": "title: 'Java Application Server Spawning Shell'\nid: 966dd516-a3de-5e63-bfa4-544cbad122e4\nstatus: test\ndescription: 'Detects java processes (Tomcat, JBoss, WebLogic, Confluence) spawning shells, a common outcome of deserialisation, OGNL or JNDI exploitation.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.initial-access\n    - attack.t1190\nlogsource:\n    category: process_creation\n    product: linux\ndetection:\n    selection:\n        ParentImage|endswith: '/java'\n        Image|endswith:\n            - '/sh'\n            - '/bash'\n            - '/dash'\n            - '/curl'\n            - '/wget'\n            - '/whoami'\n            - '/id'\n            - '/nc'\n    selection_cli:\n        CommandLine|contains:\n            - ' -c '\n            - 'whoami'\n            - '/dev/tcp'\n            - 'curl '\n            - 'wget '\n            - 'base64'\n    condition: all of selection*\nfalsepositives:\n    - 'Build servers such as Jenkins running shell steps'\nlevel: high",
    "severity": "high",
    "category": "initial-access",
    "technique": "T1190",
    "author": "OSINTrix pack",
    "platform": "Linux",
    "tags": [
      "java",
      "exploitation",
      "rce"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-270",
    "type": "sigma",
    "title": "Log4Shell JNDI Lookup Strings in Web Requests",
    "description": "Detects ${jndi: lookups and common obfuscations in web server logs, associated with CVE-2021-44228 exploitation attempts.",
    "code": "title: 'Log4Shell JNDI Lookup Strings in Web Requests'\nid: 305b7807-d3ee-5ce0-a9ca-2e1b17995937\nstatus: test\ndescription: 'Detects ${jndi: lookups and common obfuscations in web server logs, associated with CVE-2021-44228 exploitation attempts.'\nreferences:\n    - https://nvd.nist.gov/vuln/detail/CVE-2021-44228\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.initial-access\n    - attack.t1190\nlogsource:\n    category: webserver\ndetection:\n    keywords:\n        - '${jndi:'\n        - '%24%7Bjndi:'\n        - '%24%7Bjndi%3A'\n        - '${${::-j}'\n        - '${${lower:j}'\n        - '${${env:'\n        - '${jndi:ldap'\n        - '${jndi:rmi'\n        - '${jndi:dns'\n    condition: keywords\nfalsepositives:\n    - 'Vulnerability scanners run by your own team'\nlevel: high",
    "severity": "high",
    "category": "initial-access",
    "technique": "T1190",
    "author": "OSINTrix pack",
    "platform": "Web",
    "tags": [
      "log4shell",
      "cve-2021-44228"
    ],
    "references": [
      "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-271",
    "type": "sigma",
    "title": "SQL Injection Patterns in Request URI",
    "description": "Detects common SQL injection payload fragments in the query string.",
    "code": "title: 'SQL Injection Patterns in Request URI'\nid: b6c77812-de17-5fb6-87ce-244737c50737\nstatus: test\ndescription: 'Detects common SQL injection payload fragments in the query string.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.initial-access\n    - attack.t1190\nlogsource:\n    category: webserver\ndetection:\n    selection:\n        cs-uri-query|contains:\n            - 'UNION SELECT'\n            - 'union%20select'\n            - 'UNION+SELECT'\n            - \"' OR 1=1\"\n            - '%27%20or%201%3D1'\n            - 'information_schema'\n            - 'SLEEP('\n            - 'sleep%28'\n            - 'WAITFOR DELAY'\n            - 'benchmark('\n            - 'extractvalue('\n            - 'updatexml('\n    condition: selection\nfalsepositives:\n    - 'Security scanners'\n    - 'Search forms where users type SQL'\nlevel: medium",
    "severity": "medium",
    "category": "initial-access",
    "technique": "T1190",
    "author": "OSINTrix pack",
    "platform": "Web",
    "tags": [
      "sqli",
      "web-attack"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-272",
    "type": "sigma",
    "title": "Path Traversal Attempt in Request URI",
    "description": "Detects directory traversal sequences and requests for well-known sensitive files.",
    "code": "title: 'Path Traversal Attempt in Request URI'\nid: a8c0e994-5aa2-589c-a75a-8701b13e9343\nstatus: test\ndescription: 'Detects directory traversal sequences and requests for well-known sensitive files.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.initial-access\n    - attack.t1190\nlogsource:\n    category: webserver\ndetection:\n    selection:\n        cs-uri-query|contains:\n            - '../../'\n            - '..%2f..%2f'\n            - '%2e%2e%2f'\n            - '%2e%2e/'\n            - '..%5c..%5c'\n            - '%252e%252e%252f'\n            - '/etc/passwd'\n            - '/etc/shadow'\n            - 'win.ini'\n            - 'boot.ini'\n    condition: selection\nfalsepositives:\n    - 'Scanners'\n    - 'Badly built applications that pass relative paths'\nlevel: medium",
    "severity": "medium",
    "category": "initial-access",
    "technique": "T1190",
    "author": "OSINTrix pack",
    "platform": "Web",
    "tags": [
      "path-traversal",
      "lfi"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-273",
    "type": "sigma",
    "title": "Command Injection Patterns in Request Parameters",
    "description": "Detects shell metacharacters followed by common commands in request parameters.",
    "code": "title: 'Command Injection Patterns in Request Parameters'\nid: bb1ee84c-b43c-5b38-afb3-ab9dd37c2ebd\nstatus: test\ndescription: 'Detects shell metacharacters followed by common commands in request parameters.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.initial-access\n    - attack.t1190\nlogsource:\n    category: webserver\ndetection:\n    selection:\n        cs-uri-query|contains:\n            - ';id;'\n            - '|id'\n            - ';whoami'\n            - '|whoami'\n            - '$(whoami)'\n            - '`id`'\n            - '%3Bwget%20'\n            - ';wget '\n            - ';curl '\n            - '%7Cnc%20'\n            - '$(curl'\n            - '%24%28curl'\n    condition: selection\nfalsepositives:\n    - 'Security testing'\nlevel: high",
    "severity": "high",
    "category": "initial-access",
    "technique": "T1190",
    "author": "OSINTrix pack",
    "platform": "Web",
    "tags": [
      "command-injection",
      "rce"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-274",
    "type": "sigma",
    "title": "Web Shell Parameter or Filename in Request",
    "description": "Detects requests with common web shell parameter names executing commands, or hits on well-known shell filenames.",
    "code": "title: 'Web Shell Parameter or Filename in Request'\nid: f07f1849-1db2-56ce-b341-42c9f2267c2f\nstatus: test\ndescription: 'Detects requests with common web shell parameter names executing commands, or hits on well-known shell filenames.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.persistence\n    - attack.t1505.003\nlogsource:\n    category: webserver\ndetection:\n    selection_param:\n        cs-uri-query|contains:\n            - 'cmd=whoami'\n            - 'cmd=id'\n            - 'exec=whoami'\n            - 'command=whoami'\n            - 'cmd=ipconfig'\n            - 'cmd=cat+/etc/passwd'\n    selection_file:\n        cs-uri-stem|endswith:\n            - '/c99.php'\n            - '/r57.php'\n            - '/shell.php'\n            - '/cmd.aspx'\n            - '/cmd.jsp'\n            - '/wso.php'\n    condition: 1 of selection_*\nfalsepositives:\n    - 'Honeypot traffic'\nlevel: high",
    "severity": "high",
    "category": "webshell",
    "technique": "T1505.003",
    "author": "OSINTrix pack",
    "platform": "Web",
    "tags": [
      "webshell"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-275",
    "type": "sigma",
    "title": "Offensive Security Tool User Agent",
    "description": "Detects HTTP user agents of common scanners and exploitation tools.",
    "code": "title: 'Offensive Security Tool User Agent'\nid: b1db84a9-c267-5fcc-a448-c7b0dffca4fc\nstatus: test\ndescription: 'Detects HTTP user agents of common scanners and exploitation tools.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.reconnaissance\n    - attack.t1595.002\nlogsource:\n    category: webserver\ndetection:\n    selection:\n        cs-user-agent|contains:\n            - 'sqlmap'\n            - 'Nikto'\n            - 'Nuclei'\n            - 'masscan'\n            - 'zgrab'\n            - 'gobuster'\n            - 'WPScan'\n            - 'Hydra'\n            - 'dirbuster'\n            - 'Nmap Scripting Engine'\n            - 'ffuf'\n            - 'feroxbuster'\n            - 'Acunetix'\n            - 'Fuzz Faster U Fool'\n    condition: selection\nfalsepositives:\n    - 'Authorised vulnerability scanning'\nlevel: low",
    "severity": "low",
    "category": "reconnaissance",
    "technique": "T1595.002",
    "author": "OSINTrix pack",
    "platform": "Web",
    "tags": [
      "scanner",
      "user-agent"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-276",
    "type": "sigma",
    "title": "Probe for Exposed Secrets or Source Control Files",
    "description": "Detects requests for .env, .git/config, .aws/credentials, web.config backups and similar sensitive files.",
    "code": "title: 'Probe for Exposed Secrets or Source Control Files'\nid: 42a7011d-d0c0-5ecb-9676-df929e59750a\nstatus: test\ndescription: 'Detects requests for .env, .git/config, .aws/credentials, web.config backups and similar sensitive files.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.reconnaissance\n    - attack.t1595.003\nlogsource:\n    category: webserver\ndetection:\n    selection:\n        cs-uri-stem|endswith:\n            - '/.env'\n            - '/.git/config'\n            - '/.git/HEAD'\n            - '/.aws/credentials'\n            - '/.svn/entries'\n            - '/.DS_Store'\n            - '/web.config.bak'\n            - '/wp-config.php.bak'\n            - '/id_rsa'\n            - '/.htpasswd'\n    condition: selection\nfalsepositives:\n    - 'Internet background scanning (high volume, low signal individually)'\nlevel: low",
    "severity": "low",
    "category": "reconnaissance",
    "technique": "T1595.003",
    "author": "OSINTrix pack",
    "platform": "Web",
    "tags": [
      "recon",
      "secrets"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-277",
    "type": "sigma",
    "title": "Server-Side Request Forgery to Cloud Metadata",
    "description": "Detects request parameters referencing cloud instance metadata endpoints.",
    "code": "title: 'Server-Side Request Forgery to Cloud Metadata'\nid: 3b795e0f-68b2-5395-bdb9-e61c1475d1e0\nstatus: test\ndescription: 'Detects request parameters referencing cloud instance metadata endpoints.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.credential-access\n    - attack.t1552.005\nlogsource:\n    category: webserver\ndetection:\n    selection:\n        cs-uri-query|contains:\n            - '169.254.169.254'\n            - '%31%36%39%2e%32%35%34'\n            - 'metadata.google.internal'\n            - '169.254.170.2'\n            - '/latest/meta-data/'\n            - '/computeMetadata/v1'\n            - '[fd00:ec2::254]'\n    condition: selection\nfalsepositives:\n    - 'Applications with legitimate URL fetch features tested internally'\nlevel: high",
    "severity": "high",
    "category": "credential-access",
    "technique": "T1552.005",
    "author": "OSINTrix pack",
    "platform": "Web",
    "tags": [
      "ssrf",
      "metadata"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-278",
    "type": "sigma",
    "title": "Spring4Shell Class Loader Manipulation",
    "description": "Detects class.module.classLoader parameter abuse associated with CVE-2022-22965.",
    "code": "title: 'Spring4Shell Class Loader Manipulation'\nid: 1a022653-92c3-5431-9bdd-43cf98c88668\nstatus: test\ndescription: 'Detects class.module.classLoader parameter abuse associated with CVE-2022-22965.'\nreferences:\n    - https://nvd.nist.gov/vuln/detail/CVE-2022-22965\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.initial-access\n    - attack.t1190\nlogsource:\n    category: webserver\ndetection:\n    selection:\n        cs-uri-query|contains:\n            - 'class.module.classLoader'\n            - 'class%2Emodule%2EclassLoader'\n    condition: selection\nfalsepositives:\n    - 'Vulnerability scanners'\nlevel: high",
    "severity": "high",
    "category": "initial-access",
    "technique": "T1190",
    "author": "OSINTrix pack",
    "platform": "Web",
    "tags": [
      "spring4shell",
      "cve-2022-22965"
    ],
    "references": [
      "https://nvd.nist.gov/vuln/detail/CVE-2022-22965",
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-279",
    "type": "sigma",
    "title": "OGNL or Java Expression Injection in URI",
    "description": "Detects OGNL / EL expression fragments that call Runtime.exec or manipulate member access, seen in Struts and Confluence exploitation.",
    "code": "title: 'OGNL or Java Expression Injection in URI'\nid: 5cac23ae-ecd6-5cbf-b0a4-83372579b863\nstatus: test\ndescription: 'Detects OGNL / EL expression fragments that call Runtime.exec or manipulate member access, seen in Struts and Confluence exploitation.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.initial-access\n    - attack.t1190\nlogsource:\n    category: webserver\ndetection:\n    selection:\n        cs-uri-query|contains:\n            - '@java.lang.Runtime@getRuntime'\n            - '%40java.lang.Runtime%40getRuntime'\n            - '#_memberAccess'\n            - '%23_memberAccess'\n            - 'ognl.OgnlContext'\n            - 'javax.script.ScriptEngineManager'\n    condition: selection\nfalsepositives:\n    - 'Security scanners'\nlevel: high",
    "severity": "high",
    "category": "initial-access",
    "technique": "T1190",
    "author": "OSINTrix pack",
    "platform": "Web",
    "tags": [
      "ognl",
      "rce"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-280",
    "type": "sigma",
    "title": "Executable Downloaded From Paste or Raw Code Hosting",
    "description": "Detects proxy logs showing executables or scripts fetched from paste sites or raw code hosting.",
    "code": "title: 'Executable Downloaded From Paste or Raw Code Hosting'\nid: 7ede5760-83da-51b6-b577-14b2e42ae9fe\nstatus: test\ndescription: 'Detects proxy logs showing executables or scripts fetched from paste sites or raw code hosting.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.command-and-control\n    - attack.t1105\nlogsource:\n    category: proxy\ndetection:\n    selection_host:\n        c-uri|contains:\n            - 'pastebin.com/raw'\n            - 'paste.ee/r/'\n            - 'raw.githubusercontent.com'\n            - 'gist.githubusercontent.com'\n            - 'hastebin.com/raw'\n            - 'rentry.co/'\n            - 'ghostbin'\n    selection_ext:\n        c-uri|endswith:\n            - '.exe'\n            - '.dll'\n            - '.ps1'\n            - '.hta'\n            - '.vbs'\n            - '.bat'\n            - '.scr'\n            - '.msi'\n    condition: all of selection_*\nfalsepositives:\n    - 'Developers pulling scripts from GitHub'\nlevel: medium",
    "severity": "medium",
    "category": "command-and-control",
    "technique": "T1105",
    "author": "OSINTrix pack",
    "platform": "Network",
    "tags": [
      "paste-site",
      "download"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-281",
    "type": "sigma",
    "title": "Executable Downloaded From Discord or Telegram CDN",
    "description": "Detects executable or archive downloads from Discord attachment CDN or Telegram file links, frequently used to host malware.",
    "code": "title: 'Executable Downloaded From Discord or Telegram CDN'\nid: 0c290369-7fcd-56fa-b25a-8af870e4cc02\nstatus: test\ndescription: 'Detects executable or archive downloads from Discord attachment CDN or Telegram file links, frequently used to host malware.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.command-and-control\n    - attack.t1105\nlogsource:\n    category: proxy\ndetection:\n    selection_host:\n        c-uri|contains:\n            - 'cdn.discordapp.com/attachments/'\n            - 'media.discordapp.net/attachments/'\n            - 'api.telegram.org/file/'\n    selection_ext:\n        c-uri|contains:\n            - '.exe'\n            - '.dll'\n            - '.zip'\n            - '.rar'\n            - '.7z'\n            - '.iso'\n            - '.msi'\n            - '.scr'\n    condition: all of selection_*\nfalsepositives:\n    - 'Gaming communities sharing tools'\nlevel: medium",
    "severity": "medium",
    "category": "command-and-control",
    "technique": "T1105",
    "author": "OSINTrix pack",
    "platform": "Network",
    "tags": [
      "discord",
      "telegram",
      "download"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-282",
    "type": "sigma",
    "title": "Telegram Bot API Used by Non-Browser Client",
    "description": "Detects HTTP requests to api.telegram.org/bot endpoints using sendDocument or sendMessage, used by stealers to exfiltrate data.",
    "code": "title: 'Telegram Bot API Used by Non-Browser Client'\nid: 896f321f-7f0d-5900-b2b5-ad9c9fa19953\nstatus: test\ndescription: 'Detects HTTP requests to api.telegram.org/bot endpoints using sendDocument or sendMessage, used by stealers to exfiltrate data.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.exfiltration\n    - attack.t1567\nlogsource:\n    category: proxy\ndetection:\n    selection:\n        c-uri|contains: 'api.telegram.org/bot'\n    selection_method:\n        c-uri|contains:\n            - '/sendDocument'\n            - '/sendMessage'\n            - '/sendPhoto'\n    filter_browser:\n        c-useragent|contains:\n            - 'Mozilla/5.0'\n    condition: all of selection* and not filter_browser\nfalsepositives:\n    - 'Chat-ops bots and monitoring integrations'\nlevel: medium",
    "severity": "medium",
    "category": "exfiltration",
    "technique": "T1567",
    "author": "OSINTrix pack",
    "platform": "Network",
    "tags": [
      "telegram",
      "stealer",
      "exfiltration"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-283",
    "type": "sigma",
    "title": "Upload to Anonymous File Sharing Service",
    "description": "Detects POST/PUT requests to file sharing services commonly used for data exfiltration.",
    "code": "title: 'Upload to Anonymous File Sharing Service'\nid: c4ca4a67-9b09-5619-bf01-be2bc453fb17\nstatus: test\ndescription: 'Detects POST/PUT requests to file sharing services commonly used for data exfiltration.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.exfiltration\n    - attack.t1567.002\nlogsource:\n    category: proxy\ndetection:\n    selection_method:\n        cs-method:\n            - 'POST'\n            - 'PUT'\n    selection_host:\n        cs-host|endswith:\n            - 'transfer.sh'\n            - 'gofile.io'\n            - 'file.io'\n            - 'anonfiles.com'\n            - 'temp.sh'\n            - 'bashupload.com'\n            - 'mega.nz'\n            - 'catbox.moe'\n            - 'oshi.at'\n    condition: all of selection_*\nfalsepositives:\n    - 'Users sharing large files with partners'\nlevel: medium",
    "severity": "medium",
    "category": "exfiltration",
    "technique": "T1567.002",
    "author": "OSINTrix pack",
    "platform": "Network",
    "tags": [
      "exfiltration",
      "file-sharing"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-284",
    "type": "sigma",
    "title": "PowerShell User Agent in Proxy Logs",
    "description": "Detects HTTP requests with the default WindowsPowerShell user agent to external sites.",
    "code": "title: 'PowerShell User Agent in Proxy Logs'\nid: f1456ba9-9b4b-56c8-b092-bfe647cf7b35\nstatus: test\ndescription: 'Detects HTTP requests with the default WindowsPowerShell user agent to external sites.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.command-and-control\n    - attack.t1059.001\nlogsource:\n    category: proxy\ndetection:\n    selection:\n        c-useragent|contains: ' WindowsPowerShell/'\n    condition: selection\nfalsepositives:\n    - 'Administrative scripts and module downloads from PowerShell Gallery'\nlevel: low",
    "severity": "low",
    "category": "command-and-control",
    "technique": "T1059.001",
    "author": "OSINTrix pack",
    "platform": "Network",
    "tags": [
      "powershell",
      "user-agent"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-285",
    "type": "sigma",
    "title": "DNS Query With Unusually Long Subdomain Label",
    "description": "Detects DNS queries containing a label of 50+ alphanumeric characters, characteristic of DNS tunnelling and data encoding.",
    "code": "title: 'DNS Query With Unusually Long Subdomain Label'\nid: ccbf88d7-9166-5b56-8028-4fc685c211a0\nstatus: test\ndescription: 'Detects DNS queries containing a label of 50+ alphanumeric characters, characteristic of DNS tunnelling and data encoding.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.command-and-control\n    - attack.t1071.004\nlogsource:\n    category: dns\ndetection:\n    selection:\n        query|re: '(?i)^[a-z0-9-]{50,63}\\.'\n    filter_known:\n        query|endswith:\n            - '.akamaiedge.net'\n            - '.cloudfront.net'\n            - '.amazonaws.com'\n    condition: selection and not filter_known\nfalsepositives:\n    - 'CDN and security product lookups that encode hashes in subdomains'\nlevel: medium",
    "severity": "medium",
    "category": "command-and-control",
    "technique": "T1071.004",
    "author": "OSINTrix pack",
    "platform": "Network",
    "tags": [
      "dns-tunnelling",
      "exfiltration"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-286",
    "type": "sigma",
    "title": "High Volume of TXT Queries to Single Domain",
    "description": "Detects a host issuing many TXT queries for different subdomains of the same parent domain, a DNS tunnelling indicator.",
    "code": "title: 'High Volume of TXT Queries to Single Domain'\nid: e9f93ce9-97d2-5341-9907-7fb72c02e04e\nstatus: test\ndescription: 'Detects a host issuing many TXT queries for different subdomains of the same parent domain, a DNS tunnelling indicator.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.command-and-control\n    - attack.t1071.004\nlogsource:\n    category: dns\ndetection:\n    selection:\n        record_type: 'TXT'\n    condition: selection | count(query) by src_ip, parent_domain > 200\n    timeframe: 10m\nfalsepositives:\n    - 'Email security (SPF/DKIM) lookups on mail servers'\nlevel: medium",
    "severity": "medium",
    "category": "command-and-control",
    "technique": "T1071.004",
    "author": "OSINTrix pack",
    "platform": "Network",
    "tags": [
      "dns-tunnelling"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-sig-287",
    "type": "sigma",
    "title": "DNS Lookup for Onion or Tor2Web Domains",
    "description": "Detects queries for .onion names or Tor2Web gateway domains, used by ransomware notes and malware C2.",
    "code": "title: 'DNS Lookup for Onion or Tor2Web Domains'\nid: 2ec0b28d-fda4-5413-8d64-0b15a2be9404\nstatus: test\ndescription: 'Detects queries for .onion names or Tor2Web gateway domains, used by ransomware notes and malware C2.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.command-and-control\n    - attack.t1090.003\nlogsource:\n    category: dns\ndetection:\n    selection:\n        query|endswith:\n            - '.onion'\n            - '.onion.ws'\n            - '.onion.ly'\n            - '.onion.pet'\n            - '.tor2web.org'\n            - '.onion.to'\n    condition: selection\nfalsepositives:\n    - 'Researchers'\nlevel: high",
    "severity": "high",
    "category": "command-and-control",
    "technique": "T1090.003",
    "author": "OSINTrix pack",
    "platform": "Network",
    "tags": [
      "tor",
      "dns"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-288",
    "type": "sigma",
    "title": "Outbound Connection to Tor Relay Ports",
    "description": "Detects firewall-allowed outbound connections to default Tor ORPort/DirPort values.",
    "code": "title: 'Outbound Connection to Tor Relay Ports'\nid: 37cdd7b7-9383-5ed4-9902-ffa056a4be3a\nstatus: test\ndescription: 'Detects firewall-allowed outbound connections to default Tor ORPort/DirPort values.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.command-and-control\n    - attack.t1090.003\nlogsource:\n    category: firewall\ndetection:\n    selection:\n        dst_port:\n            - 9001\n            - 9030\n            - 9040\n            - 9050\n            - 9051\n            - 9150\n        action: 'allow'\n    filter_private:\n        dst_ip|cidr:\n            - '10.0.0.0/8'\n            - '172.16.0.0/12'\n            - '192.168.0.0/16'\n    condition: selection and not filter_private\nfalsepositives:\n    - 'Unrelated services on these ports'\nlevel: medium",
    "severity": "medium",
    "category": "command-and-control",
    "technique": "T1090.003",
    "author": "OSINTrix pack",
    "platform": "Network",
    "tags": [
      "tor",
      "firewall"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-sig-289",
    "type": "sigma",
    "title": "Outbound SMB to the Internet",
    "description": "Detects outbound TCP 445/139 to public addresses, which may leak NTLM hashes (forced authentication) or exfiltrate data.",
    "code": "title: 'Outbound SMB to the Internet'\nid: 4b411980-ae0f-51ba-91de-115d9d16e4ab\nstatus: test\ndescription: 'Detects outbound TCP 445/139 to public addresses, which may leak NTLM hashes (forced authentication) or exfiltrate data.'\nreferences:\n    - https://github.com/SigmaHQ/sigma\nauthor: OSINTrix pack\ndate: 2026-11-03\ntags:\n    - attack.credential-access\n    - attack.t1187\nlogsource:\n    category: firewall\ndetection:\n    selection:\n        dst_port:\n            - 445\n            - 139\n    filter_private:\n        dst_ip|cidr:\n            - '10.0.0.0/8'\n            - '172.16.0.0/12'\n            - '192.168.0.0/16'\n            - '127.0.0.0/8'\n    condition: selection and not filter_private\nfalsepositives:\n    - 'Azure Files or other cloud SMB shares'\nlevel: medium",
    "severity": "medium",
    "category": "credential-access",
    "technique": "T1187",
    "author": "OSINTrix pack",
    "platform": "Network",
    "tags": [
      "smb",
      "ntlm-leak"
    ],
    "references": [
      "https://github.com/SigmaHQ/sigma"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-yar-001",
    "type": "yara",
    "title": "PHP Web Shell With Eval and Decode Chain",
    "description": "PHP file that passes base64/gzip/rot13 decoded content into eval or assert, the usual wrapper of obfuscated web shells.",
    "code": "rule WEBSHELL_PHP_Eval_Decode_Chain {\n    meta:\n        description = \"PHP file that passes base64/gzip/rot13 decoded content into eval or assert, the usual wrapper of obfuscated web shells.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        reference = \"https://github.com/Neo23x0/signature-base\"\n        severity = \"high\"\n        mitre_attack = \"T1505.003\"\n    strings:\n        $tagphp = \"<?php\" nocase\n        $e1 = /eval\\s*\\(\\s*(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev)\\s*\\(/ nocase\n        $e2 = /assert\\s*\\(\\s*(base64_decode|gzinflate|str_rot13)\\s*\\(/ nocase\n        $e3 = /eval\\s*\\(\\s*gzinflate\\s*\\(\\s*base64_decode/ nocase\n    condition:\n        filesize < 2MB and $tagphp and any of ($e*)\n}",
    "severity": "high",
    "category": "webshell",
    "technique": "T1505.003",
    "author": "OSINTrix pack",
    "platform": "Web",
    "tags": [
      "webshell",
      "php",
      "obfuscation"
    ],
    "references": [
      "https://github.com/Neo23x0/signature-base"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-yar-002",
    "type": "yara",
    "title": "PHP Web Shell Passing Request Input to OS Command",
    "description": "PHP code that hands $_GET/$_POST/$_REQUEST/$_COOKIE values directly to system, exec, passthru, shell_exec or popen.",
    "code": "rule WEBSHELL_PHP_Request_To_Exec {\n    meta:\n        description = \"PHP code that hands $_GET/$_POST/$_REQUEST/$_COOKIE values directly to system, exec, passthru, shell_exec or popen.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        reference = \"https://github.com/Neo23x0/signature-base\"\n        severity = \"critical\"\n        mitre_attack = \"T1505.003\"\n    strings:\n        $tagphp = \"<?\" ascii\n        $r1 = /(system|passthru|shell_exec|exec|popen|proc_open)\\s*\\(\\s*\\$_(GET|POST|REQUEST|COOKIE|SERVER)\\s*\\[/ nocase\n        $r2 = /(system|passthru|shell_exec|exec)\\s*\\(\\s*base64_decode\\s*\\(\\s*\\$_(GET|POST|REQUEST|COOKIE)/ nocase\n        $r3 = /`\\s*\\$_(GET|POST|REQUEST)\\s*\\[[^\\]]{1,32}\\]\\s*`/ nocase\n    condition:\n        filesize < 1MB and $tagphp and any of ($r*)\n}",
    "severity": "critical",
    "category": "webshell",
    "technique": "T1505.003",
    "author": "OSINTrix pack",
    "platform": "Web",
    "tags": [
      "webshell",
      "php"
    ],
    "references": [
      "https://github.com/Neo23x0/signature-base"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-yar-003",
    "type": "yara",
    "title": "Tiny PHP One-Line Web Shell",
    "description": "Very small PHP files whose main content is eval/assert/create_function on request data, typical one-liner shells.",
    "code": "rule WEBSHELL_PHP_Tiny_Eval_Post {\n    meta:\n        description = \"Very small PHP files whose main content is eval/assert/create_function on request data, typical one-liner shells.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        reference = \"https://github.com/Neo23x0/signature-base\"\n        severity = \"critical\"\n        mitre_attack = \"T1505.003\"\n    strings:\n        $tagphp = \"<?\" ascii\n        $o1 = /@?eval\\s*\\(\\s*\\$_(POST|GET|REQUEST|COOKIE)\\s*\\[/ nocase\n        $o2 = /@?assert\\s*\\(\\s*\\$_(POST|GET|REQUEST)\\s*\\[/ nocase\n        $o3 = /\\$_(POST|GET|REQUEST)\\s*\\[[^\\]]{1,20}\\]\\s*\\(\\s*\\$_(POST|GET|REQUEST)/ nocase\n    condition:\n        filesize < 2KB and $tagphp and any of ($o*)\n}",
    "severity": "critical",
    "category": "webshell",
    "technique": "T1505.003",
    "author": "OSINTrix pack",
    "platform": "Web",
    "tags": [
      "webshell",
      "php",
      "one-liner"
    ],
    "references": [
      "https://github.com/Neo23x0/signature-base"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-yar-004",
    "type": "yara",
    "title": "PHP Web Shell via preg_replace /e or Variable Functions",
    "description": "Detects PHP execution tricks: preg_replace with the /e modifier on request data, create_function, or functions built from concatenated strings.",
    "code": "rule WEBSHELL_PHP_Preg_Replace_E_Or_Variable_Function {\n    meta:\n        description = \"Detects PHP execution tricks: preg_replace with the /e modifier on request data, create_function, or functions built from concatenated strings.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        reference = \"https://github.com/Neo23x0/signature-base\"\n        severity = \"high\"\n        mitre_attack = \"T1505.003\"\n    strings:\n        $tagphp = \"<?\" ascii\n        $p1 = /preg_replace\\s*\\(\\s*['\"].{1,40}\\/e['\"]\\s*,\\s*\\$_(POST|GET|REQUEST)/ nocase\n        $p2 = /create_function\\s*\\(\\s*['\"]{2}\\s*,\\s*\\$_(POST|GET|REQUEST)/ nocase\n        $p3 = /\\$\\w{1,12}\\s*=\\s*['\"]s['\"]\\s*\\.\\s*['\"]y['\"]\\s*\\.\\s*['\"]s['\"]/ nocase\n        $p4 = /\\$\\w{1,12}\\s*=\\s*str_replace\\s*\\(\\s*['\"][^'\"]{1,5}['\"]\\s*,\\s*['\"]['\"]\\s*,\\s*['\"][a-z_]{0,4}(b|e)[^'\"]{2,30}['\"]\\s*\\)/ nocase\n        $p5 = \"array_map(\\\"assert\\\"\" nocase\n        $p6 = \"call_user_func('assert'\" nocase\n    condition:\n        filesize < 1MB and $tagphp and any of ($p*)\n}",
    "severity": "high",
    "category": "webshell",
    "technique": "T1505.003",
    "author": "OSINTrix pack",
    "platform": "Web",
    "tags": [
      "webshell",
      "php",
      "obfuscation"
    ],
    "references": [
      "https://github.com/Neo23x0/signature-base"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-yar-005",
    "type": "yara",
    "title": "PHP File Manager Style Web Shell",
    "description": "Detects full-featured PHP shells combining command execution, file upload, server info and permission listing features.",
    "code": "rule WEBSHELL_PHP_File_Manager_Features {\n    meta:\n        description = \"Detects full-featured PHP shells combining command execution, file upload, server info and permission listing features.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        reference = \"https://github.com/Neo23x0/signature-base\"\n        severity = \"high\"\n        mitre_attack = \"T1505.003\"\n    strings:\n        $tagphp = \"<?\" ascii\n        $f1 = \"posix_getpwuid\" ascii\n        $f2 = \"move_uploaded_file\" ascii\n        $f3 = \"php_uname\" ascii\n        $f4 = \"disable_functions\" ascii\n        $f5 = \"fileperms\" ascii\n        $f6 = \"safe_mode\" ascii nocase\n        $x1 = \"shell_exec\" ascii\n        $x2 = \"passthru\" ascii\n        $x3 = \"proc_open\" ascii\n        $x4 = \"system(\" ascii\n    condition:\n        filesize < 3MB and $tagphp and 4 of ($f*) and 2 of ($x*)\n}",
    "severity": "high",
    "category": "webshell",
    "technique": "T1505.003",
    "author": "OSINTrix pack",
    "platform": "Web",
    "tags": [
      "webshell",
      "php",
      "file-manager"
    ],
    "references": [
      "https://github.com/Neo23x0/signature-base"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-yar-006",
    "type": "yara",
    "title": "ASPX China Chopper Style One-Line Shell",
    "description": "Detects the compact ASPX eval(Request.Item[...], \"unsafe\") pattern used by China Chopper style clients.",
    "code": "rule WEBSHELL_ASPX_Chopper_Style {\n    meta:\n        description = \"Detects the compact ASPX eval(Request.Item[...], 'unsafe') pattern used by China Chopper style clients.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        reference = \"https://github.com/Neo23x0/signature-base\"\n        severity = \"critical\"\n        mitre_attack = \"T1505.003\"\n    strings:\n        $s1 = /eval\\s*\\(\\s*Request(\\.Item)?\\s*\\[\\s*['\"][^'\"]{1,32}['\"]\\s*\\]\\s*,\\s*['\"]unsafe['\"]/ nocase\n        $s2 = /eval\\s*\\(\\s*Request\\.Form\\s*\\[/ nocase\n        $s3 = \"<%@ Page Language=\\\"Jscript\\\"\" nocase\n    condition:\n        filesize < 10KB and ($s1 or ($s2 and $s3))\n}",
    "severity": "critical",
    "category": "webshell",
    "technique": "T1505.003",
    "author": "OSINTrix pack",
    "platform": "Web",
    "tags": [
      "webshell",
      "aspx",
      "china-chopper"
    ],
    "references": [
      "https://github.com/Neo23x0/signature-base"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-yar-007",
    "type": "yara",
    "title": "ASPX Web Shell Starting Processes From Request Data",
    "description": "ASP.NET page that reads request parameters and launches cmd.exe/powershell via Process.Start or ProcessStartInfo.",
    "code": "rule WEBSHELL_ASPX_Process_Start_Request {\n    meta:\n        description = \"ASP.NET page that reads request parameters and launches cmd.exe/powershell via Process.Start or ProcessStartInfo.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        reference = \"https://github.com/Neo23x0/signature-base\"\n        severity = \"high\"\n        mitre_attack = \"T1505.003\"\n    strings:\n        $p1 = \"Process.Start\" ascii nocase\n        $p2 = \"ProcessStartInfo\" ascii nocase\n        $c1 = \"cmd.exe\" ascii nocase\n        $c2 = \"powershell\" ascii nocase\n        $r1 = \"Request.Form\" ascii nocase\n        $r2 = \"Request.QueryString\" ascii nocase\n        $r3 = \"Request[\" ascii nocase\n        $o1 = \"StandardOutput.ReadToEnd\" ascii nocase\n        $tag = \"<%@\" ascii\n    condition:\n        filesize < 500KB and $tag and any of ($p*) and any of ($c*) and any of ($r*) and $o1\n}",
    "severity": "high",
    "category": "webshell",
    "technique": "T1505.003",
    "author": "OSINTrix pack",
    "platform": "Web",
    "tags": [
      "webshell",
      "aspx"
    ],
    "references": [
      "https://github.com/Neo23x0/signature-base"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-yar-008",
    "type": "yara",
    "title": "Classic ASP Web Shell Executing Request Input",
    "description": "Classic ASP page that passes Request() input to Execute, Eval or ExecuteGlobal.",
    "code": "rule WEBSHELL_ASP_Classic_Execute_Request {\n    meta:\n        description = \"Classic ASP page that passes Request() input to Execute, Eval or ExecuteGlobal.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        reference = \"https://github.com/Neo23x0/signature-base\"\n        severity = \"critical\"\n        mitre_attack = \"T1505.003\"\n    strings:\n        $tag = \"<%\" ascii\n        $s1 = /Execute(Global)?\\s*\\(?\\s*Request\\s*(\\.Form|\\.QueryString)?\\s*\\(/ nocase\n        $s2 = /Eval\\s*\\(\\s*Request\\s*(\\.Form|\\.QueryString)?\\s*\\(/ nocase\n        $s3 = /CreateObject\\s*\\(\\s*\"WScript\\.Shell\"\\s*\\)\\.Exec\\s*\\(\\s*Request/ nocase\n    condition:\n        filesize < 200KB and $tag and any of ($s*)\n}",
    "severity": "critical",
    "category": "webshell",
    "technique": "T1505.003",
    "author": "OSINTrix pack",
    "platform": "Web",
    "tags": [
      "webshell",
      "asp"
    ],
    "references": [
      "https://github.com/Neo23x0/signature-base"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-yar-009",
    "type": "yara",
    "title": "JSP Web Shell Executing Request Parameter",
    "description": "JSP page that passes request.getParameter() into Runtime.getRuntime().exec or ProcessBuilder.",
    "code": "rule WEBSHELL_JSP_Runtime_Exec_Request {\n    meta:\n        description = \"JSP page that passes request.getParameter() into Runtime.getRuntime().exec or ProcessBuilder.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        reference = \"https://github.com/Neo23x0/signature-base\"\n        severity = \"critical\"\n        mitre_attack = \"T1505.003\"\n    strings:\n        $j1 = \"<%@\" ascii\n        $j2 = \"<jsp:\" ascii\n        $e1 = /Runtime\\.getRuntime\\(\\)\\.exec\\s*\\(\\s*request\\.getParameter/ nocase\n        $e2 = /new\\s+ProcessBuilder\\s*\\([^)]{0,80}request\\.getParameter/ nocase\n        $e3 = \"Runtime.getRuntime().exec(\" ascii\n        $r1 = \"request.getParameter(\" ascii\n        $o1 = \"getInputStream()\" ascii\n    condition:\n        filesize < 500KB and any of ($j*) and ($e1 or $e2 or ($e3 and $r1 and $o1))\n}",
    "severity": "critical",
    "category": "webshell",
    "technique": "T1505.003",
    "author": "OSINTrix pack",
    "platform": "Web",
    "tags": [
      "webshell",
      "jsp"
    ],
    "references": [
      "https://github.com/Neo23x0/signature-base"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-yar-010",
    "type": "yara",
    "title": "JSP Encrypted Class-Loading Web Shell",
    "description": "JSP that decrypts request bodies (AES/Base64) and defines a class at runtime, the design used by modern encrypted JSP shell families.",
    "code": "rule WEBSHELL_JSP_Classloader_Encrypted {\n    meta:\n        description = \"JSP that decrypts request bodies (AES/Base64) and defines a class at runtime, the design used by modern encrypted JSP shell families.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        reference = \"https://github.com/Neo23x0/signature-base\"\n        severity = \"critical\"\n        mitre_attack = \"T1505.003\"\n    strings:\n        $j = \"<%@\" ascii\n        $d1 = \"defineClass\" ascii\n        $d2 = \"ClassLoader\" ascii\n        $c1 = \"javax.crypto.Cipher\" ascii\n        $c2 = \"Cipher.getInstance(\\\"AES\" ascii\n        $b1 = \"Base64.getDecoder\" ascii\n        $b2 = \"BASE64Decoder\" ascii\n        $r1 = \"request.getReader()\" ascii\n        $r2 = \"request.getInputStream()\" ascii\n        $s1 = \"session.putValue\" ascii\n        $s2 = \"session.setAttribute\" ascii\n    condition:\n        filesize < 200KB and $j and all of ($d*) and any of ($c*) and any of ($b*) and any of ($r*, $s*)\n}",
    "severity": "critical",
    "category": "webshell",
    "technique": "T1505.003",
    "author": "OSINTrix pack",
    "platform": "Web",
    "tags": [
      "webshell",
      "jsp",
      "memory-shell"
    ],
    "references": [
      "https://github.com/Neo23x0/signature-base"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-yar-011",
    "type": "yara",
    "title": "PowerShell Script With Heavy Obfuscation",
    "description": "Detects combinations of PowerShell obfuscation primitives: char-code joins, -bxor decoding, string reversal, format-operator reordering and backtick splitting.",
    "code": "rule SUSP_PS1_Obfuscation_Techniques {\n    meta:\n        description = \"Detects combinations of PowerShell obfuscation primitives: char-code joins, -bxor decoding, string reversal, format-operator reordering and backtick splitting.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"medium\"\n        mitre_attack = \"T1027.010\"\n    strings:\n        $o1 = /\\[char\\]\\s*0x[0-9a-f]{2}\\s*\\+\\s*\\[char\\]/ nocase\n        $o2 = /-join\\s*\\(\\s*\\(?\\s*[0-9]{2,3}\\s*,\\s*[0-9]{2,3}\\s*,\\s*[0-9]{2,3}/ nocase\n        $o3 = \"-bxor\" ascii nocase\n        $o4 = /\\[array\\]::Reverse\\(/ nocase\n        $o5 = /\\(\"\\{[0-9]\\}\\{[0-9]\\}\\{[0-9]\\}\"\\s*-f/ nocase\n        $o6 = /i`e`x|i`ex|ie`x/ nocase\n        $o7 = /\\.\\(\\s*\\$env:ComSpec\\[4,15,25\\]|\\$\\{?env:ComSpec\\}?\\[4,24,25\\]/ nocase\n        $o8 = \"[ScriptBlock]::Create(\" ascii nocase\n    condition:\n        filesize < 5MB and 3 of them\n}",
    "severity": "medium",
    "category": "defense-evasion",
    "technique": "T1027.010",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "powershell",
      "obfuscation"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-yar-012",
    "type": "yara",
    "title": "PowerShell Download Cradle in Script",
    "description": "Script that downloads content with WebClient / Invoke-WebRequest and executes it with Invoke-Expression.",
    "code": "rule SUSP_PS1_Download_Cradle {\n    meta:\n        description = \"Script that downloads content with WebClient / Invoke-WebRequest and executes it with Invoke-Expression.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"medium\"\n        mitre_attack = \"T1059.001\"\n    strings:\n        $d1 = \"Net.WebClient\" ascii nocase\n        $d2 = \"DownloadString(\" ascii nocase\n        $d3 = \"DownloadData(\" ascii nocase\n        $d4 = \"Invoke-WebRequest\" ascii nocase\n        $d5 = \"Invoke-RestMethod\" ascii nocase\n        $x1 = \"Invoke-Expression\" ascii nocase\n        $x2 = /\\bIEX\\s*[\\(\\$]/ nocase\n        $x3 = \"| iex\" ascii nocase\n    condition:\n        filesize < 1MB and 1 of ($d*) and 1 of ($x*)\n}",
    "severity": "medium",
    "category": "execution",
    "technique": "T1059.001",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "powershell",
      "download-cradle"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-yar-013",
    "type": "yara",
    "title": "PowerShell Reflective .NET Assembly Loader",
    "description": "Script that base64-decodes data and loads it as a .NET assembly in memory, then invokes its entry point.",
    "code": "rule SUSP_PS1_Reflective_Assembly_Load {\n    meta:\n        description = \"Script that base64-decodes data and loads it as a .NET assembly in memory, then invokes its entry point.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"high\"\n        mitre_attack = \"T1620\"\n    strings:\n        $b = \"FromBase64String\" ascii nocase\n        $l1 = \"Reflection.Assembly]::Load\" ascii nocase\n        $l2 = \"[System.Reflection.Assembly]::Load(\" ascii nocase\n        $l3 = \"AppDomain]::CurrentDomain.Load(\" ascii nocase\n        $i1 = \"EntryPoint.Invoke\" ascii nocase\n        $i2 = \".GetType(\" ascii nocase\n        $i3 = \".GetMethod(\" ascii nocase\n    condition:\n        filesize < 20MB and $b and 1 of ($l*) and 1 of ($i*)\n}",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1620",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "powershell",
      "reflective-loading"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-yar-014",
    "type": "yara",
    "title": "PowerShell AMSI Bypass Script",
    "description": "Detects scripts that tamper with AMSI by flipping amsiInitFailed, patching AmsiScanBuffer or nulling the AMSI context.",
    "code": "rule SUSP_PS1_AMSI_Bypass {\n    meta:\n        description = \"Detects scripts that tamper with AMSI by flipping amsiInitFailed, patching AmsiScanBuffer or nulling the AMSI context.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"high\"\n        mitre_attack = \"T1562.001\"\n    strings:\n        $a1 = \"amsiInitFailed\" ascii wide nocase\n        $a2 = \"AmsiUtils\" ascii wide nocase\n        $a3 = \"AmsiScanBuffer\" ascii wide nocase\n        $a4 = \"amsiContext\" ascii wide nocase\n        $m1 = \"GetField\" ascii wide nocase\n        $m2 = \"NonPublic,Static\" ascii wide nocase\n        $m3 = \"VirtualProtect\" ascii wide nocase\n        $m4 = \"Marshal]::Copy\" ascii wide nocase\n        $m5 = \"SetValue($null\" ascii wide nocase\n        $patch = { B8 57 00 07 80 C3 }\n    condition:\n        filesize < 2MB and 1 of ($a*) and (1 of ($m*) or $patch)\n}",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1562.001",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "amsi",
      "powershell"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-yar-015",
    "type": "yara",
    "title": "PowerShell Compressed Base64 Payload Executed",
    "description": "Detects GzipStream/DeflateStream decompression of a base64 blob followed by execution, a common stager format.",
    "code": "rule SUSP_PS1_Compressed_Payload_IEX {\n    meta:\n        description = \"Detects GzipStream/DeflateStream decompression of a base64 blob followed by execution, a common stager format.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"high\"\n        mitre_attack = \"T1027\"\n    strings:\n        $c1 = \"IO.Compression.GzipStream\" ascii nocase\n        $c2 = \"IO.Compression.DeflateStream\" ascii nocase\n        $c3 = \"IO.Compression.CompressionMode]::Decompress\" ascii nocase\n        $b = \"FromBase64String\" ascii nocase\n        $x1 = \"Invoke-Expression\" ascii nocase\n        $x2 = \"IEX\" ascii\n        $x3 = \"ReadToEnd()\" ascii nocase\n        $blob = /[A-Za-z0-9+\\/]{400,}={0,2}/\n    condition:\n        filesize < 5MB and 1 of ($c*) and $b and 1 of ($x*) and $blob\n}",
    "severity": "high",
    "category": "execution",
    "technique": "T1027",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "powershell",
      "stager"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-yar-016",
    "type": "yara",
    "title": "PowerShell In-Memory Shellcode Runner",
    "description": "Detects scripts that allocate executable memory, copy a byte array into it and start a thread or delegate.",
    "code": "rule SUSP_PS1_Shellcode_Runner {\n    meta:\n        description = \"Detects scripts that allocate executable memory, copy a byte array into it and start a thread or delegate.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"critical\"\n        mitre_attack = \"T1059.001\"\n    strings:\n        $a1 = \"VirtualAlloc\" ascii nocase\n        $a2 = \"CreateThread\" ascii nocase\n        $a3 = \"GetDelegateForFunctionPointer\" ascii nocase\n        $a4 = \"Marshal]::Copy\" ascii nocase\n        $a5 = \"WaitForSingleObject\" ascii nocase\n        $b1 = \"[Byte[]]\" ascii nocase\n        $b2 = \"0x40\" ascii\n        $b3 = /0x[0-9a-f]{2},0x[0-9a-f]{2},0x[0-9a-f]{2},0x[0-9a-f]{2},0x[0-9a-f]{2}/ nocase\n    condition:\n        filesize < 5MB and 3 of ($a*) and 2 of ($b*)\n}",
    "severity": "critical",
    "category": "execution",
    "technique": "T1059.001",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "powershell",
      "shellcode"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-yar-017",
    "type": "yara",
    "title": "PowerShell TCP Reverse Shell",
    "description": "Detects the common PowerShell reverse shell construction using TCPClient, GetStream and iex output piping.",
    "code": "rule SUSP_PS1_Reverse_Shell {\n    meta:\n        description = \"Detects the common PowerShell reverse shell construction using TCPClient, GetStream and iex output piping.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"critical\"\n        mitre_attack = \"T1059.001\"\n    strings:\n        $t1 = \"Net.Sockets.TCPClient\" ascii wide nocase\n        $t2 = \"GetStream()\" ascii wide nocase\n        $r1 = \"iex $data\" ascii wide nocase\n        $r2 = \"Invoke-Expression\" ascii wide nocase\n        $r3 = \"Out-String\" ascii wide nocase\n        $w1 = \".Write($sendbyte\" ascii wide nocase\n        $w2 = \"PS ' + (pwd).Path\" ascii wide nocase\n        $w3 = \".Flush()\" ascii wide nocase\n    condition:\n        filesize < 1MB and all of ($t*) and 1 of ($r*) and 1 of ($w*)\n}",
    "severity": "critical",
    "category": "execution",
    "technique": "T1059.001",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "reverse-shell",
      "powershell"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-yar-018",
    "type": "yara",
    "title": "Office Macro With Auto-Exec and Shell Execution",
    "description": "Detects VBA with an auto-execution entry point combined with process execution primitives. Best run against OLE documents or extracted vbaProject.bin.",
    "code": "rule SUSP_Office_Macro_AutoExec_Shell {\n    meta:\n        description = \"Detects VBA with an auto-execution entry point combined with process execution primitives. Best run against OLE documents or extracted vbaProject.bin.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"high\"\n        mitre_attack = \"T1566.001\"\n    strings:\n        $auto1 = \"AutoOpen\" ascii nocase\n        $auto2 = \"Document_Open\" ascii nocase\n        $auto3 = \"Workbook_Open\" ascii nocase\n        $auto4 = \"Auto_Open\" ascii nocase\n        $auto5 = \"Document_Close\" ascii nocase\n        $exec1 = \"WScript.Shell\" ascii nocase\n        $exec2 = \"Shell(\" ascii nocase\n        $exec3 = \"CreateObject\" ascii nocase\n        $exec4 = \"Win32_Process\" ascii nocase\n        $exec5 = \"ShellExecute\" ascii nocase\n        $exec6 = \"powershell\" ascii nocase\n        $vba = \"Attribute VB_\" ascii\n    condition:\n        (uint32(0) == 0xE011CFD0 or $vba) and filesize < 10MB and 1 of ($auto*) and 2 of ($exec*)\n}",
    "severity": "high",
    "category": "initial-access",
    "technique": "T1566.001",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "office",
      "macro",
      "vba"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-yar-019",
    "type": "yara",
    "title": "Office Macro Downloading a Payload",
    "description": "VBA that downloads a file (URLDownloadToFile, XMLHTTP + ADODB.Stream) and saves it to disk.",
    "code": "rule SUSP_Office_Macro_Downloader {\n    meta:\n        description = \"VBA that downloads a file (URLDownloadToFile, XMLHTTP + ADODB.Stream) and saves it to disk.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"high\"\n        mitre_attack = \"T1566.001\"\n    strings:\n        $d1 = \"URLDownloadToFile\" ascii nocase\n        $d2 = \"MSXML2.XMLHTTP\" ascii nocase\n        $d3 = \"MSXML2.ServerXMLHTTP\" ascii nocase\n        $d4 = \"WinHttp.WinHttpRequest\" ascii nocase\n        $s1 = \"ADODB.Stream\" ascii nocase\n        $s2 = \"SaveToFile\" ascii nocase\n        $s3 = \"responseBody\" ascii nocase\n        $vba = \"Attribute VB_\" ascii\n    condition:\n        (uint32(0) == 0xE011CFD0 or $vba) and filesize < 10MB and 1 of ($d*) and 1 of ($s*)\n}",
    "severity": "high",
    "category": "initial-access",
    "technique": "T1566.001",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "office",
      "macro",
      "downloader"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-yar-020",
    "type": "yara",
    "title": "Excel 4.0 XLM Macro Sheet With Execution",
    "description": "Detects Excel 4.0 macro formulas such as EXEC, CALL or REGISTER combined with Auto_Open in XLS/XLSM files.",
    "code": "rule SUSP_Office_XLM_Macro {\n    meta:\n        description = \"Detects Excel 4.0 macro formulas such as EXEC, CALL or REGISTER combined with Auto_Open in XLS/XLSM files.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"high\"\n        mitre_attack = \"T1559.001\"\n    strings:\n        $auto = \"Auto_Open\" ascii nocase\n        $x1 = \"=EXEC(\" ascii nocase\n        $x2 = \"=CALL(\" ascii nocase\n        $x3 = \"=REGISTER(\" ascii nocase\n        $x4 = \"URLDownloadToFileA\" ascii nocase\n        $x5 = \"=FORMULA(\" ascii nocase\n        $sheet = \"macrosheet\" ascii nocase\n    condition:\n        (uint32(0) == 0xE011CFD0 or uint32(0) == 0x04034B50) and filesize < 10MB and ($auto or $sheet) and 2 of ($x*)\n}",
    "severity": "high",
    "category": "initial-access",
    "technique": "T1559.001",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "excel",
      "xlm",
      "macro"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-yar-021",
    "type": "yara",
    "title": "RTF Document With Embedded OLE or Equation Editor Object",
    "description": "Detects RTF files embedding objects with objupdate/objdata and Equation.3 references, typical of equation editor exploit documents.",
    "code": "rule SUSP_RTF_OLE_Equation_Exploit {\n    meta:\n        description = \"Detects RTF files embedding objects with objupdate/objdata and Equation.3 references, typical of equation editor exploit documents.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"high\"\n        mitre_attack = \"T1203\"\n    strings:\n        $o1 = \"\\\\objupdate\" ascii nocase\n        $o2 = \"\\\\objdata\" ascii nocase\n        $o3 = \"\\\\objemb\" ascii nocase\n        $e1 = \"Equation.3\" ascii nocase\n        $e2 = \"4571756174696f6e2e33\" ascii nocase\n        $e3 = \"0002CE02-0000-0000-C000-000000000046\" ascii nocase\n        $p1 = \"Package\" ascii\n    condition:\n        uint32(0) == 0x74725C7B and filesize < 20MB and 2 of ($o*) and (1 of ($e*) or $p1)\n}",
    "severity": "high",
    "category": "initial-access",
    "technique": "T1203",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "rtf",
      "exploit",
      "ole"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-yar-022",
    "type": "yara",
    "title": "Office Document With Remote Template Reference",
    "description": "Detects OOXML relationship files pointing attachedTemplate or oleObject targets at external http(s) URLs (template injection).",
    "code": "rule SUSP_Office_Remote_Template_Injection {\n    meta:\n        description = \"Detects OOXML relationship files pointing attachedTemplate or oleObject targets at external http(s) URLs (template injection).\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"high\"\n        mitre_attack = \"T1221\"\n    strings:\n        $rel = \"relationships\" ascii nocase\n        $t1 = /Type=\"[^\"]{0,120}\\/attachedTemplate\"[^>]{0,200}Target=\"https?:\\/\\// nocase\n        $t3 = /Type=\"[^\"]{0,120}\\/oleObject\"[^>]{0,200}Target=\"(https?|mhtml|file):/ nocase\n    condition:\n        filesize < 2MB and $rel and ($t1 or $t3)\n}",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1221",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "office",
      "template-injection"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-yar-023",
    "type": "yara",
    "title": "Shortcut File Launching Script Interpreter",
    "description": "Windows .lnk file whose target or arguments reference PowerShell, cmd, mshta, wscript or similar with download/encoded parameters.",
    "code": "rule SUSP_LNK_Embedded_Script_Command {\n    meta:\n        description = \"Windows .lnk file whose target or arguments reference PowerShell, cmd, mshta, wscript or similar with download/encoded parameters.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"high\"\n        mitre_attack = \"T1204.002\"\n    strings:\n        $i1 = \"powershell\" ascii wide nocase\n        $i2 = \"cmd.exe\" ascii wide nocase\n        $i3 = \"mshta\" ascii wide nocase\n        $i4 = \"wscript\" ascii wide nocase\n        $i5 = \"rundll32\" ascii wide nocase\n        $i6 = \"conhost\" ascii wide nocase\n        $i7 = \"forfiles\" ascii wide nocase\n        $p1 = \"-enc\" ascii wide nocase\n        $p2 = \"http\" ascii wide nocase\n        $p3 = \"-w hidden\" ascii wide nocase\n        $p4 = \"IEX\" ascii wide\n        $p5 = \"DownloadString\" ascii wide nocase\n        $p6 = \"/c start\" ascii wide nocase\n    condition:\n        uint32(0) == 0x0000004C and uint32(4) == 0x00021401 and filesize < 5MB and 1 of ($i*) and 1 of ($p*)\n}",
    "severity": "high",
    "category": "execution",
    "technique": "T1204.002",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "lnk",
      "phishing"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-yar-024",
    "type": "yara",
    "title": "Shortcut File With Padded or Oversized Arguments",
    "description": "LNK files with long runs of whitespace used to hide the real command line in the properties dialog, or that carry appended payload data.",
    "code": "rule SUSP_LNK_Oversized_Padded_Arguments {\n    meta:\n        description = \"LNK files with long runs of whitespace used to hide the real command line in the properties dialog, or that carry appended payload data.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"medium\"\n        mitre_attack = \"T1036\"\n    strings:\n        $pad_w = { 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 }\n        $pad_lf = { 0A 00 0A 00 0A 00 0A 00 0A 00 0A 00 0A 00 0A 00 0A 00 0A 00 }\n        $i1 = \"cmd\" ascii wide nocase\n        $i2 = \"powershell\" ascii wide nocase\n        $i3 = \"mshta\" ascii wide nocase\n    condition:\n        uint32(0) == 0x0000004C and uint32(4) == 0x00021401 and (any of ($pad*) or filesize > 250KB) and 1 of ($i*)\n}",
    "severity": "medium",
    "category": "defense-evasion",
    "technique": "T1036",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "lnk",
      "masquerading"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-yar-025",
    "type": "yara",
    "title": "Disk Image Containing Shortcut and Executable Payload",
    "description": "ISO 9660 image that contains both a .lnk file and a DLL/EXE, the common ISO-smuggling layout used to bypass Mark-of-the-Web.",
    "code": "rule SUSP_ISO_LNK_With_Payload {\n    meta:\n        description = \"ISO 9660 image that contains both a .lnk file and a DLL/EXE, the common ISO-smuggling layout used to bypass Mark-of-the-Web.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"high\"\n        mitre_attack = \"T1553.005\"\n    strings:\n        $iso = \"CD001\" ascii\n        $lnk = \".lnk\" ascii wide nocase\n        $p1 = \".dll\" ascii wide nocase\n        $p2 = \".exe\" ascii wide nocase\n        $p3 = \".cpl\" ascii wide nocase\n        $mz = { 4D 5A 90 00 }\n    condition:\n        $iso at 0x8001 and filesize < 200MB and $lnk and 1 of ($p*) and $mz\n}",
    "severity": "high",
    "category": "initial-access",
    "technique": "T1553.005",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "iso",
      "lnk",
      "motw-bypass"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-yar-026",
    "type": "yara",
    "title": "Disk Image Containing Script Launchers",
    "description": "ISO image containing a shortcut plus HTA/JS/VBS/CMD scripts, used to deliver multi-stage loaders.",
    "code": "rule SUSP_ISO_Script_Dropper {\n    meta:\n        description = \"ISO image containing a shortcut plus HTA/JS/VBS/CMD scripts, used to deliver multi-stage loaders.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"medium\"\n        mitre_attack = \"T1553.005\"\n    strings:\n        $iso = \"CD001\" ascii\n        $lnk = \".lnk\" ascii wide nocase\n        $s1 = \".hta\" ascii wide nocase\n        $s2 = \".js\" ascii wide nocase\n        $s3 = \".vbs\" ascii wide nocase\n        $s4 = \".cmd\" ascii wide nocase\n        $s5 = \".bat\" ascii wide nocase\n        $s6 = \".wsf\" ascii wide nocase\n    condition:\n        $iso at 0x8001 and filesize < 100MB and $lnk and 1 of ($s*)\n}",
    "severity": "medium",
    "category": "initial-access",
    "technique": "T1553.005",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "iso",
      "script",
      "motw-bypass"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-yar-027",
    "type": "yara",
    "title": "HTA Application Executing Commands",
    "description": "HTML Application with an HTA:APPLICATION tag and script code that creates WScript.Shell or runs PowerShell.",
    "code": "rule SUSP_HTA_Script_Execution {\n    meta:\n        description = \"HTML Application with an HTA:APPLICATION tag and script code that creates WScript.Shell or runs PowerShell.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"high\"\n        mitre_attack = \"T1218.005\"\n    strings:\n        $hta = \"<HTA:APPLICATION\" ascii nocase\n        $s1 = \"WScript.Shell\" ascii nocase\n        $s2 = \"ActiveXObject\" ascii nocase\n        $s3 = \"CreateObject\" ascii nocase\n        $x1 = \".Run\" ascii nocase\n        $x2 = \"powershell\" ascii nocase\n        $x3 = \".Exec(\" ascii nocase\n        $x4 = \"window.close\" ascii nocase\n    condition:\n        filesize < 5MB and $hta and 1 of ($s*) and 2 of ($x*)\n}",
    "severity": "high",
    "category": "execution",
    "technique": "T1218.005",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "hta",
      "mshta"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-yar-028",
    "type": "yara",
    "title": "JScript or VBScript Downloader Dropper",
    "description": "Windows Script Host file that fetches remote content via XMLHTTP and writes it to disk with ADODB.Stream before running it.",
    "code": "rule SUSP_JS_VBS_Downloader_Dropper {\n    meta:\n        description = \"Windows Script Host file that fetches remote content via XMLHTTP and writes it to disk with ADODB.Stream before running it.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"high\"\n        mitre_attack = \"T1059.005\"\n    strings:\n        $h1 = \"MSXML2.XMLHTTP\" ascii nocase\n        $h2 = \"MSXML2.ServerXMLHTTP\" ascii nocase\n        $h3 = \"WinHttp.WinHttpRequest\" ascii nocase\n        $s1 = \"ADODB.Stream\" ascii nocase\n        $s2 = \"SaveToFile\" ascii nocase\n        $e1 = \"WScript.Shell\" ascii nocase\n        $e2 = \"Shell.Application\" ascii nocase\n        $e3 = \".Run\" ascii nocase\n        $e4 = \"ShellExecute\" ascii nocase\n    condition:\n        filesize < 2MB and 1 of ($h*) and all of ($s*) and 2 of ($e*)\n}",
    "severity": "high",
    "category": "execution",
    "technique": "T1059.005",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "jscript",
      "vbscript",
      "downloader"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-yar-029",
    "type": "yara",
    "title": "VBScript Heavy Chr() Obfuscation With Execute",
    "description": "VBScript that builds code from many Chr()/ChrW() calls and runs it with Execute or ExecuteGlobal.",
    "code": "rule SUSP_VBS_Chr_Obfuscation {\n    meta:\n        description = \"VBScript that builds code from many Chr()/ChrW() calls and runs it with Execute or ExecuteGlobal.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"medium\"\n        mitre_attack = \"T1027\"\n    strings:\n        $chr = /Chr[W]?\\s*\\(\\s*[0-9]{2,3}\\s*\\)\\s*&/ nocase\n        $x1 = \"Execute\" ascii nocase\n        $x2 = \"ExecuteGlobal\" ascii nocase\n        $x3 = \"Eval(\" ascii nocase\n    condition:\n        filesize < 5MB and #chr > 50 and 1 of ($x*)\n}",
    "severity": "medium",
    "category": "defense-evasion",
    "technique": "T1027",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "vbscript",
      "obfuscation"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-yar-030",
    "type": "yara",
    "title": "Batch File With Substring Variable Obfuscation",
    "description": "Batch scripts that rebuild commands from %VAR:~n,1% substrings many times, a DOSfuscation technique used by loaders.",
    "code": "rule SUSP_BAT_Variable_Substring_Obfuscation {\n    meta:\n        description = \"Batch scripts that rebuild commands from %VAR:~n,1% substrings many times, a DOSfuscation technique used by loaders.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"medium\"\n        mitre_attack = \"T1027.010\"\n    strings:\n        $sub = /%[A-Za-z0-9_]{1,20}:~-?[0-9]{1,3},1%/\n        $set = /set\\s+[\"]?[A-Za-z0-9_]{1,20}=/ nocase\n    condition:\n        filesize < 5MB and #sub > 40 and $set\n}",
    "severity": "medium",
    "category": "defense-evasion",
    "technique": "T1027.010",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "batch",
      "dosfuscation"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-yar-031",
    "type": "yara",
    "title": "Reverse Shell One-Liners in Script Files",
    "description": "Detects bash, netcat, python, perl and php reverse shell constructions embedded in scripts.",
    "code": "rule SUSP_Script_Reverse_Shell_OneLiners {\n    meta:\n        description = \"Detects bash, netcat, python, perl and php reverse shell constructions embedded in scripts.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"high\"\n        mitre_attack = \"T1059.004\"\n    strings:\n        $b1 = /bash\\s+-i\\s+>&\\s*\\/dev\\/tcp\\/[0-9a-zA-Z.\\-]{3,64}\\/[0-9]{1,5}/\n        $b2 = /\\/dev\\/tcp\\/[0-9a-zA-Z.\\-]{3,64}\\/[0-9]{1,5}\\s+0>&1/\n        $n1 = /\\bnc(at)?\\s+(-[a-z]+\\s+)*-e\\s+\\/bin\\/(ba)?sh/\n        $n2 = /mkfifo\\s+\\/tmp\\/[a-z0-9]{1,10};\\s*(cat|nc)/\n        $p1 = \"pty.spawn(\\\"/bin/\" ascii\n        $p2 = /socket\\.socket\\(socket\\.AF_INET,\\s*socket\\.SOCK_STREAM\\)/\n        $p3 = \"os.dup2(s.fileno(),0)\" ascii\n        $pl = /perl\\s+-e\\s+['\"]use\\s+Socket;/\n        $ph = /php\\s+-r\\s+['\"]\\$sock\\s*=\\s*fsockopen\\(/\n    condition:\n        filesize < 2MB and (1 of ($b*, $n*, $pl, $ph) or ($p2 and ($p1 or $p3)))\n}",
    "severity": "high",
    "category": "execution",
    "technique": "T1059.004",
    "author": "OSINTrix pack",
    "platform": "Linux",
    "tags": [
      "reverse-shell",
      "script"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-yar-032",
    "type": "yara",
    "title": "Linux Botnet or Miner Dropper Shell Script",
    "description": "Shell script that downloads binaries into temp paths, makes them executable, adds cron persistence and kills competing miners.",
    "code": "rule SUSP_Linux_Botnet_Dropper_Script {\n    meta:\n        description = \"Shell script that downloads binaries into temp paths, makes them executable, adds cron persistence and kills competing miners.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"high\"\n        mitre_attack = \"T1059.004\"\n    strings:\n        $sh = \"#!/bin/\" ascii\n        $d1 = \"wget \" ascii\n        $d2 = \"curl \" ascii\n        $d3 = \"tftp \" ascii\n        $x1 = \"chmod +x\" ascii\n        $x2 = \"chmod 777\" ascii\n        $p1 = \"/tmp/\" ascii\n        $p2 = \"/var/tmp/\" ascii\n        $p3 = \"/dev/shm\" ascii\n        $c1 = \"crontab\" ascii\n        $c2 = \"/etc/cron\" ascii\n        $k1 = \"pkill -9\" ascii\n        $k2 = \"killall\" ascii\n        $k3 = \"kdevtmpfsi\" ascii\n        $k4 = \"kinsing\" ascii\n        $k5 = \"xmrig\" ascii nocase\n    condition:\n        filesize < 500KB and $sh at 0 and 1 of ($d*) and 1 of ($x*) and 1 of ($p*) and (1 of ($c*) or 2 of ($k*))\n}",
    "severity": "high",
    "category": "execution",
    "technique": "T1059.004",
    "author": "OSINTrix pack",
    "platform": "Linux",
    "tags": [
      "botnet",
      "miner",
      "dropper"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-yar-033",
    "type": "yara",
    "title": "Compiled AutoIt Script Executable",
    "description": "Detects PE files carrying a compiled AutoIt v3 script, a format heavily abused by commodity loaders and stealers.",
    "code": "rule SUSP_AutoIt_Compiled_Script {\n    meta:\n        description = \"Detects PE files carrying a compiled AutoIt v3 script, a format heavily abused by commodity loaders and stealers.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"low\"\n        mitre_attack = \"T1059.010\"\n    strings:\n        $a1 = \"AU3!EA06\" ascii\n        $a2 = \">>>AUTOIT SCRIPT<<<\" ascii\n        $a3 = \"AutoIt v3\" ascii wide\n        $a4 = \"#AutoIt3Wrapper\" ascii\n    condition:\n        uint16(0) == 0x5A4D and filesize < 20MB and 2 of them\n}",
    "severity": "low",
    "category": "execution",
    "technique": "T1059.010",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "autoit",
      "loader"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-yar-034",
    "type": "yara",
    "title": "UPX Packed Windows Executable",
    "description": "PE file with UPX section names. UPX alone is not malicious, but packed binaries in unexpected places deserve a closer look.",
    "code": "import \"pe\"\n\nrule PACKER_UPX_PE {\n    meta:\n        description = \"PE file with UPX section names. UPX alone is not malicious, but packed binaries in unexpected places deserve a closer look.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"low\"\n        mitre_attack = \"T1027.002\"\n    condition:\n        uint16(0) == 0x5A4D and filesize < 50MB and\n        for any i in (0 .. pe.number_of_sections - 1) : (\n            pe.sections[i].name == \"UPX0\" or pe.sections[i].name == \"UPX1\" or pe.sections[i].name == \"UPX2\"\n        )\n}",
    "severity": "low",
    "category": "defense-evasion",
    "technique": "T1027.002",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "packer",
      "upx"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-yar-035",
    "type": "yara",
    "title": "PE Packed With Commercial or Common Protector",
    "description": "PE with section names left by MPRESS, ASPack, Themida/WinLicense, VMProtect, PECompact, Petite or NsPack.",
    "code": "import \"pe\"\n\nrule PACKER_Known_Protector_Sections {\n    meta:\n        description = \"PE with section names left by MPRESS, ASPack, Themida/WinLicense, VMProtect, PECompact, Petite or NsPack.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"low\"\n        mitre_attack = \"T1027.002\"\n    condition:\n        uint16(0) == 0x5A4D and filesize < 50MB and\n        for any i in (0 .. pe.number_of_sections - 1) : (\n            pe.sections[i].name == \".MPRESS1\" or pe.sections[i].name == \".MPRESS2\" or\n            pe.sections[i].name == \".aspack\" or pe.sections[i].name == \".adata\" or\n            pe.sections[i].name == \".themida\" or pe.sections[i].name == \".winlice\" or\n            pe.sections[i].name == \".vmp0\" or pe.sections[i].name == \".vmp1\" or\n            pe.sections[i].name == \"PEC2\" or pe.sections[i].name == \".petite\" or\n            pe.sections[i].name == \".nsp0\" or pe.sections[i].name == \".nsp1\"\n        )\n}",
    "severity": "low",
    "category": "defense-evasion",
    "technique": "T1027.002",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "packer",
      "protector"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-yar-036",
    "type": "yara",
    "title": "PE With High-Entropy Section and Minimal Imports",
    "description": "PE that has a section with entropy above 7.2 and very few imports, a profile typical of packed or encrypted loaders.",
    "code": "import \"pe\"\nimport \"math\"\n\nrule SUSP_PE_High_Entropy_Few_Imports {\n    meta:\n        description = \"PE that has a section with entropy above 7.2 and very few imports, a profile typical of packed or encrypted loaders.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"medium\"\n        mitre_attack = \"T1027.002\"\n    condition:\n        uint16(0) == 0x5A4D and filesize < 20MB and\n        pe.number_of_imports < 6 and\n        for any i in (0 .. pe.number_of_sections - 1) : (\n            pe.sections[i].raw_data_size > 4096 and\n            math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) > 7.2\n        )\n}",
    "severity": "medium",
    "category": "defense-evasion",
    "technique": "T1027.002",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "packer",
      "entropy"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-yar-037",
    "type": "yara",
    "title": "PE Importing Only Dynamic Resolution APIs",
    "description": "Small PE whose import table is essentially LoadLibrary/GetProcAddress, used by loaders to hide their real API usage.",
    "code": "import \"pe\"\n\nrule SUSP_PE_Dynamic_API_Resolution_Only {\n    meta:\n        description = \"Small PE whose import table is essentially LoadLibrary/GetProcAddress, used by loaders to hide their real API usage.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"low\"\n        mitre_attack = \"T1027.007\"\n    condition:\n        uint16(0) == 0x5A4D and filesize < 2MB and\n        pe.number_of_imported_functions < 8 and\n        (pe.imports(\"kernel32.dll\", \"GetProcAddress\") and\n         (pe.imports(\"kernel32.dll\", \"LoadLibraryA\") or pe.imports(\"kernel32.dll\", \"LoadLibraryW\") or\n          pe.imports(\"kernel32.dll\", \"LoadLibraryExA\") or pe.imports(\"kernel32.dll\", \"LoadLibraryExW\"))) and\n        not pe.is_dll()\n}",
    "severity": "low",
    "category": "defense-evasion",
    "technique": "T1027.007",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "loader",
      "api-hashing"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-yar-038",
    "type": "yara",
    "title": "Cobalt Strike Beacon Default Strings",
    "description": "Detects strings present in unmodified Cobalt Strike beacon payloads and reflective loader exports.",
    "code": "rule HKTL_CobaltStrike_Beacon_Strings {\n    meta:\n        description = \"Detects strings present in unmodified Cobalt Strike beacon payloads and reflective loader exports.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        reference = \"https://github.com/elastic/protections-artifacts\"\n        severity = \"critical\"\n        mitre_attack = \"T1071.001\"\n    strings:\n        $s1 = \"%s as %s\\\\%s: %d\" ascii\n        $s2 = \"beacon.dll\" ascii\n        $s3 = \"beacon.x64.dll\" ascii\n        $s4 = \"ReflectiveLoader\" ascii\n        $s5 = \"%02d/%02d/%02d %02d:%02d:%02d\" ascii\n        $s6 = \"Started service %s on %s\" ascii\n        $s7 = \"could not run command (w/ token) because of its length of %d bytes!\" ascii\n        $s8 = \"IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/')\" ascii\n    condition:\n        filesize < 10MB and 3 of them\n}",
    "severity": "critical",
    "category": "command-and-control",
    "technique": "T1071.001",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "cobalt-strike",
      "beacon"
    ],
    "references": [
      "https://github.com/elastic/protections-artifacts"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-yar-039",
    "type": "yara",
    "title": "Cobalt Strike Encoded Beacon Configuration",
    "description": "Detects the start of a Cobalt Strike beacon configuration block XOR-encoded with the default single-byte keys 0x69 (3.x) or 0x2e (4.x).",
    "code": "rule HKTL_CobaltStrike_Beacon_Config_Encoded {\n    meta:\n        description = \"Detects the start of a Cobalt Strike beacon configuration block XOR-encoded with the default single-byte keys 0x69 (3.x) or 0x2e (4.x).\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        reference = \"https://www.elastic.co/blog/detecting-cobalt-strike-with-memory-signatures\"\n        severity = \"critical\"\n        mitre_attack = \"T1071.001\"\n    strings:\n        $cfg_v3 = { 69 68 69 68 69 6B ?? ?? 69 6B 69 68 69 6B ?? ?? 69 6A }\n        $cfg_v4 = { 2E 2F 2E 2F 2E 2C ?? ?? 2E 2C 2E 2F 2E 2C ?? ?? 2E 2D }\n    condition:\n        filesize < 10MB and any of them\n}",
    "severity": "critical",
    "category": "command-and-control",
    "technique": "T1071.001",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "cobalt-strike",
      "config"
    ],
    "references": [
      "https://www.elastic.co/blog/detecting-cobalt-strike-with-memory-signatures"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-yar-040",
    "type": "yara",
    "title": "Cobalt Strike Default PowerShell Stager",
    "description": "Detects the default Cobalt Strike PowerShell payload template with func_get_proc_address and func_get_delegate_type helpers.",
    "code": "rule HKTL_CobaltStrike_PowerShell_Stager {\n    meta:\n        description = \"Detects the default Cobalt Strike PowerShell payload template with func_get_proc_address and func_get_delegate_type helpers.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"critical\"\n        mitre_attack = \"T1059.001\"\n    strings:\n        $f1 = \"func_get_proc_address\" ascii nocase\n        $f2 = \"func_get_delegate_type\" ascii nocase\n        $s1 = \"[Byte[]]$var_code\" ascii nocase\n        $s2 = \"-bxor 35\" ascii nocase\n        $s3 = \"VirtualAlloc\" ascii nocase\n        $s4 = \"FromBase64String\" ascii nocase\n    condition:\n        filesize < 2MB and all of ($f*) and 1 of ($s*)\n}",
    "severity": "critical",
    "category": "execution",
    "technique": "T1059.001",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "cobalt-strike",
      "stager",
      "powershell"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-yar-041",
    "type": "yara",
    "title": "Cobalt Strike Default Named Pipe Format Strings",
    "description": "Detects default named pipe templates used by Cobalt Strike artifacts and post-exploitation jobs.",
    "code": "rule HKTL_CobaltStrike_Pipe_Names {\n    meta:\n        description = \"Detects default named pipe templates used by Cobalt Strike artifacts and post-exploitation jobs.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"critical\"\n        mitre_attack = \"T1071\"\n    strings:\n        $p1 = \"\\\\\\\\.\\\\pipe\\\\MSSE-%d-server\" ascii wide\n        $p2 = \"\\\\\\\\.\\\\pipe\\\\msagent_%x\" ascii wide\n        $p3 = \"\\\\\\\\.\\\\pipe\\\\postex_%04x\" ascii wide\n        $p4 = \"\\\\\\\\.\\\\pipe\\\\status_%x\" ascii wide\n        $p5 = \"%c%c%c%c%c%c%c%c%cMSSE-%d-server\" ascii\n    condition:\n        filesize < 10MB and any of them\n}",
    "severity": "critical",
    "category": "command-and-control",
    "technique": "T1071",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "cobalt-strike",
      "named-pipe"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-yar-042",
    "type": "yara",
    "title": "Metasploit-Style Shellcode Prologue",
    "description": "Detects the well-known x86 and x64 block_api prologues used by Metasploit payloads (and frameworks reusing them, including Cobalt Strike stagers).",
    "code": "rule HKTL_Metasploit_Shellcode_BlockAPI {\n    meta:\n        description = \"Detects the well-known x86 and x64 block_api prologues used by Metasploit payloads (and frameworks reusing them, including Cobalt Strike stagers).\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"high\"\n        mitre_attack = \"T1055\"\n    strings:\n        $x86 = { FC E8 82 00 00 00 60 89 E5 31 C0 64 8B 50 30 }\n        $x86b = { FC E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30 }\n        $x64 = { FC 48 83 E4 F0 E8 C0 00 00 00 41 51 41 50 52 51 56 48 31 D2 }\n        $x64b = { FC 48 83 E4 F0 E8 C8 00 00 00 41 51 41 50 52 51 56 48 31 D2 }\n    condition:\n        filesize < 20MB and any of them\n}",
    "severity": "high",
    "category": "execution",
    "technique": "T1055",
    "author": "OSINTrix pack",
    "platform": "Any",
    "tags": [
      "shellcode",
      "metasploit"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-yar-043",
    "type": "yara",
    "title": "Metasploit Meterpreter Payload Strings",
    "description": "Detects metsrv and stdapi command identifiers found in Meterpreter DLLs and memory.",
    "code": "rule HKTL_Meterpreter_Strings {\n    meta:\n        description = \"Detects metsrv and stdapi command identifiers found in Meterpreter DLLs and memory.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"high\"\n        mitre_attack = \"T1071\"\n    strings:\n        $m1 = \"metsrv.dll\" ascii\n        $m2 = \"metsrv.x64.dll\" ascii\n        $c1 = \"stdapi_sys_process_execute\" ascii\n        $c2 = \"stdapi_fs_ls\" ascii\n        $c3 = \"core_channel_open\" ascii\n        $c4 = \"priv_elevate_getsystem\" ascii\n        $c5 = \"stdapi_sys_config_getuid\" ascii\n    condition:\n        filesize < 20MB and (1 of ($m*) and 1 of ($c*) or 3 of ($c*))\n}",
    "severity": "high",
    "category": "command-and-control",
    "technique": "T1071",
    "author": "OSINTrix pack",
    "platform": "Any",
    "tags": [
      "metasploit",
      "meterpreter"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-yar-044",
    "type": "yara",
    "title": "Mimikatz Credential Dumping Tool",
    "description": "Detects mimikatz binaries and in-memory copies via module names, author strings and command keywords.",
    "code": "rule HKTL_Mimikatz_Strings {\n    meta:\n        description = \"Detects mimikatz binaries and in-memory copies via module names, author strings and command keywords.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        reference = \"https://github.com/Neo23x0/signature-base\"\n        severity = \"critical\"\n        mitre_attack = \"T1003.001\"\n    strings:\n        $a1 = \"gentilkiwi\" ascii wide\n        $a2 = \"Benjamin DELPY\" ascii wide\n        $a3 = \"mimikatz\" ascii wide nocase\n        $c1 = \"sekurlsa::logonpasswords\" ascii wide nocase\n        $c2 = \"lsadump::sam\" ascii wide nocase\n        $c3 = \"lsadump::dcsync\" ascii wide nocase\n        $c4 = \"kerberos::golden\" ascii wide nocase\n        $k1 = \"kuhl_m_sekurlsa\" ascii wide\n        $k2 = \"kull_m_process\" ascii wide\n        $k3 = \"kuhl_m_lsadump\" ascii wide\n    condition:\n        filesize < 20MB and (2 of ($a*) and 1 of ($c*, $k*) or 3 of ($c*, $k*))\n}",
    "severity": "critical",
    "category": "credential-access",
    "technique": "T1003.001",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "mimikatz",
      "credential-dump"
    ],
    "references": [
      "https://github.com/Neo23x0/signature-base"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-yar-045",
    "type": "yara",
    "title": "Mimikatz Driver or SSP Library",
    "description": "Detects mimidrv kernel driver and mimilib SSP/DLL components.",
    "code": "rule HKTL_Mimikatz_Driver_Or_SSP {\n    meta:\n        description = \"Detects mimidrv kernel driver and mimilib SSP/DLL components.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        reference = \"https://github.com/Neo23x0/signature-base\"\n        severity = \"critical\"\n        mitre_attack = \"T1547.005\"\n    strings:\n        $d1 = \"mimidrv\" ascii wide nocase\n        $d2 = \"\\\\DosDevices\\\\mimidrv\" wide\n        $l1 = \"mimilib\" ascii wide nocase\n        $l2 = \"kiwissp.log\" ascii wide\n        $l3 = \"kiwifilter.log\" ascii wide\n        $l4 = \"kiwidns.log\" ascii wide\n    condition:\n        uint16(0) == 0x5A4D and filesize < 5MB and (all of ($d*) or 2 of ($l*))\n}",
    "severity": "critical",
    "category": "credential-access",
    "technique": "T1547.005",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "mimikatz",
      "ssp",
      "driver"
    ],
    "references": [
      "https://github.com/Neo23x0/signature-base"
    ],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-yar-046",
    "type": "yara",
    "title": "Generic LSASS Memory Dumper",
    "description": "Detects small PE tools that enable SeDebugPrivilege, look up lsass.exe and call MiniDumpWriteDump.",
    "code": "rule SUSP_LSASS_Dumper_Generic {\n    meta:\n        description = \"Detects small PE tools that enable SeDebugPrivilege, look up lsass.exe and call MiniDumpWriteDump.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"high\"\n        mitre_attack = \"T1003.001\"\n    strings:\n        $l = \"lsass\" ascii wide nocase\n        $m1 = \"MiniDumpWriteDump\" ascii\n        $m2 = \"dbghelp.dll\" ascii wide nocase\n        $m3 = \"dbgcore.dll\" ascii wide nocase\n        $p1 = \"SeDebugPrivilege\" ascii wide\n        $p2 = \"OpenProcess\" ascii\n        $p3 = \"CreateToolhelp32Snapshot\" ascii\n    condition:\n        uint16(0) == 0x5A4D and filesize < 5MB and $l and $m1 and 1 of ($m2, $m3) and 2 of ($p*)\n}",
    "severity": "high",
    "category": "credential-access",
    "technique": "T1003.001",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "lsass",
      "minidump"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-yar-047",
    "type": "yara",
    "title": "Rubeus Kerberos Abuse Tool",
    "description": "Detects Rubeus .NET assemblies via module and command strings.",
    "code": "rule HKTL_Rubeus_Strings {\n    meta:\n        description = \"Detects Rubeus .NET assemblies via module and command strings.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"high\"\n        mitre_attack = \"T1558\"\n    strings:\n        $r1 = \"Rubeus\" ascii wide\n        $c1 = \"asreproast\" ascii wide\n        $c2 = \"kerberoast\" ascii wide\n        $c3 = \"asktgt\" ascii wide\n        $c4 = \"s4u\" ascii wide\n        $c5 = \"tgtdeleg\" ascii wide\n        $c6 = \"[*] Action: \" ascii wide\n        $net = \"mscoree.dll\" ascii\n    condition:\n        uint16(0) == 0x5A4D and filesize < 5MB and $net and $r1 and 3 of ($c*)\n}",
    "severity": "high",
    "category": "credential-access",
    "technique": "T1558",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "rubeus",
      "kerberos"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-yar-048",
    "type": "yara",
    "title": "SharpHound BloodHound Collector",
    "description": "Detects SharpHound collector assemblies by collection method names and output strings.",
    "code": "rule HKTL_SharpHound_Strings {\n    meta:\n        description = \"Detects SharpHound collector assemblies by collection method names and output strings.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"high\"\n        mitre_attack = \"T1087.002\"\n    strings:\n        $s1 = \"SharpHound\" ascii wide\n        $s2 = \"BloodHound\" ascii wide\n        $c1 = \"CollectionMethod\" ascii wide\n        $c2 = \"LocalAdmin\" ascii wide\n        $c3 = \"ObjectProps\" ascii wide\n        $c4 = \"SessionLoop\" ascii wide\n        $c5 = \"_BloodHound.zip\" ascii wide\n    condition:\n        uint16(0) == 0x5A4D and filesize < 10MB and 1 of ($s*) and 3 of ($c*)\n}",
    "severity": "high",
    "category": "discovery",
    "technique": "T1087.002",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "bloodhound",
      "sharphound"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-yar-049",
    "type": "yara",
    "title": "Impacket Offensive Python Scripts",
    "description": "Detects Python scripts built on Impacket for remote execution or secret dumping (secretsdump, wmiexec, smbexec, psexec style).",
    "code": "rule HKTL_Impacket_Python_Scripts {\n    meta:\n        description = \"Detects Python scripts built on Impacket for remote execution or secret dumping (secretsdump, wmiexec, smbexec, psexec style).\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"medium\"\n        mitre_attack = \"T1021.002\"\n    strings:\n        $i1 = \"from impacket\" ascii\n        $i2 = \"import impacket\" ascii\n        $u1 = \"smbconnection\" ascii\n        $u2 = \"dcerpc.v5\" ascii\n        $u3 = \"secretsdump\" ascii\n        $u4 = \"RemoteOperations\" ascii\n        $u5 = \"NTDSHashes\" ascii\n        $u6 = \"wmiexec\" ascii\n        $u7 = \"DCOMConnection\" ascii\n    condition:\n        filesize < 2MB and 1 of ($i*) and 2 of ($u*)\n}",
    "severity": "medium",
    "category": "lateral-movement",
    "technique": "T1021.002",
    "author": "OSINTrix pack",
    "platform": "Any",
    "tags": [
      "impacket",
      "python"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-yar-050",
    "type": "yara",
    "title": "Sliver C2 Implant",
    "description": "Detects Go-compiled Sliver implants through protobuf package and type names left in the binary.",
    "code": "rule HKTL_Sliver_Implant_Go {\n    meta:\n        description = \"Detects Go-compiled Sliver implants through protobuf package and type names left in the binary.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"critical\"\n        mitre_attack = \"T1071\"\n    strings:\n        $s1 = \"github.com/bishopfox/sliver\" ascii\n        $s2 = \"sliverpb\" ascii\n        $s3 = \"*sliverpb.Envelope\" ascii\n        $s4 = \"commonpb\" ascii\n        $s5 = \"/implant/sliver/\" ascii\n        $go = \"Go build ID\" ascii\n    condition:\n        filesize < 40MB and (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F or uint32(0) == 0xFEEDFACF or uint32(0) == 0xCFFAEDFE) and\n        ($go or $s1) and 2 of ($s*)\n}",
    "severity": "critical",
    "category": "command-and-control",
    "technique": "T1071",
    "author": "OSINTrix pack",
    "platform": "Any",
    "tags": [
      "sliver",
      "c2"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-yar-051",
    "type": "yara",
    "title": "Mythic C2 Go Agent",
    "description": "Detects Go-based Mythic agents (such as Poseidon or Merlin builds) via their MythicAgents module paths.",
    "code": "rule HKTL_Mythic_Agent_Go {\n    meta:\n        description = \"Detects Go-based Mythic agents (such as Poseidon or Merlin builds) via their MythicAgents module paths.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"high\"\n        mitre_attack = \"T1071\"\n    strings:\n        $m1 = \"github.com/MythicAgents/\" ascii\n        $m2 = \"Payload_Type/\" ascii\n        $m3 = \"agent_code\" ascii\n        $m4 = \"mythic\" ascii nocase\n        $go = \"Go build ID\" ascii\n    condition:\n        filesize < 40MB and (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F or uint32(0) == 0xFEEDFACF or uint32(0) == 0xCFFAEDFE) and\n        $go and $m1 and 1 of ($m2, $m3, $m4)\n}",
    "severity": "high",
    "category": "command-and-control",
    "technique": "T1071",
    "author": "OSINTrix pack",
    "platform": "Any",
    "tags": [
      "mythic",
      "c2"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-yar-052",
    "type": "yara",
    "title": "Havoc C2 Teamserver Profile",
    "description": "Detects Havoc teamserver profile (.yaotl) files that define Teamserver, Operators, Listeners and Demon blocks.",
    "code": "rule HKTL_Havoc_Teamserver_Profile {\n    meta:\n        description = \"Detects Havoc teamserver profile (.yaotl) files that define Teamserver, Operators, Listeners and Demon blocks.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"high\"\n        mitre_attack = \"T1071\"\n    strings:\n        $b1 = \"Teamserver {\" ascii\n        $b2 = \"Operators {\" ascii\n        $b3 = \"Demon {\" ascii\n        $b4 = \"Listeners {\" ascii\n        $k1 = \"Sleep\" ascii\n        $k2 = \"Jitter\" ascii\n        $k3 = \"Spawn64\" ascii\n        $k4 = \"Injection {\" ascii\n    condition:\n        filesize < 200KB and 3 of ($b*) and 2 of ($k*)\n}",
    "severity": "high",
    "category": "command-and-control",
    "technique": "T1071",
    "author": "OSINTrix pack",
    "platform": "Any",
    "tags": [
      "havoc",
      "c2",
      "config"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-yar-053",
    "type": "yara",
    "title": "Chisel or Ligolo Tunnelling Tool",
    "description": "Detects Go builds of the chisel and ligolo-ng tunnelling tools commonly used to pivot into internal networks.",
    "code": "rule HKTL_Tunnel_Tools_Go {\n    meta:\n        description = \"Detects Go builds of the chisel and ligolo-ng tunnelling tools commonly used to pivot into internal networks.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"medium\"\n        mitre_attack = \"T1572\"\n    strings:\n        $c1 = \"github.com/jpillora/chisel\" ascii\n        $c2 = \"chisel-v3\" ascii\n        $l1 = \"github.com/nicocha30/ligolo-ng\" ascii\n        $l2 = \"ligolo\" ascii\n        $go = \"Go build ID\" ascii\n    condition:\n        filesize < 40MB and $go and (1 of ($c*) or all of ($l*))\n}",
    "severity": "medium",
    "category": "command-and-control",
    "technique": "T1572",
    "author": "OSINTrix pack",
    "platform": "Any",
    "tags": [
      "tunnel",
      "chisel",
      "ligolo"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-yar-054",
    "type": "yara",
    "title": "Generic Ransomware Note With Onion Contact",
    "description": "Text/HTML ransom note combining several extortion phrases with a .onion address.",
    "code": "rule RANSOM_Note_Generic_Onion {\n    meta:\n        description = \"Text/HTML ransom note combining several extortion phrases with a .onion address.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"critical\"\n        mitre_attack = \"T1486\"\n    strings:\n        $p1 = \"your files have been encrypted\" ascii wide nocase\n        $p2 = \"all your files are encrypted\" ascii wide nocase\n        $p3 = \"do not rename\" ascii wide nocase\n        $p4 = \"do not try to decrypt\" ascii wide nocase\n        $p5 = \"decryption tool\" ascii wide nocase\n        $p6 = \"private key\" ascii wide nocase\n        $p7 = \"your data has been stolen\" ascii wide nocase\n        $p8 = \"will be published\" ascii wide nocase\n        $p9 = \"tor browser\" ascii wide nocase\n        $p10 = \"recover your files\" ascii wide nocase\n        $onion = /[a-z2-7]{56}\\.onion/ ascii wide nocase\n    condition:\n        filesize < 200KB and $onion and 3 of ($p*)\n}",
    "severity": "critical",
    "category": "impact",
    "technique": "T1486",
    "author": "OSINTrix pack",
    "platform": "Any",
    "tags": [
      "ransomware",
      "ransom-note"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-yar-055",
    "type": "yara",
    "title": "Generic Ransomware Note With Bitcoin Payment",
    "description": "Ransom note text that asks for Bitcoin payment and references file decryption.",
    "code": "rule RANSOM_Note_Generic_Bitcoin {\n    meta:\n        description = \"Ransom note text that asks for Bitcoin payment and references file decryption.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"high\"\n        mitre_attack = \"T1486\"\n    strings:\n        $b1 = /\\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\\b/ ascii wide\n        $b2 = \"bitcoin\" ascii wide nocase\n        $b3 = \"BTC\" ascii wide\n        $d1 = \"decrypt\" ascii wide nocase\n        $d2 = \"encrypted\" ascii wide nocase\n        $d3 = \"unique key\" ascii wide nocase\n        $d4 = \"within 72 hours\" ascii wide nocase\n        $d5 = \"price will be doubled\" ascii wide nocase\n    condition:\n        filesize < 100KB and $b1 and 1 of ($b2, $b3) and 2 of ($d*)\n}",
    "severity": "high",
    "category": "impact",
    "technique": "T1486",
    "author": "OSINTrix pack",
    "platform": "Any",
    "tags": [
      "ransomware",
      "ransom-note",
      "bitcoin"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-yar-056",
    "type": "yara",
    "title": "Executable Embedding Recovery Inhibition Commands",
    "description": "PE containing several commands that delete shadow copies, disable recovery or wipe backup catalogs.",
    "code": "rule RANSOM_PE_Recovery_Inhibition {\n    meta:\n        description = \"PE containing several commands that delete shadow copies, disable recovery or wipe backup catalogs.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"high\"\n        mitre_attack = \"T1490\"\n    strings:\n        $c1 = \"vssadmin delete shadows\" ascii wide nocase\n        $c2 = \"vssadmin.exe Delete Shadows\" ascii wide nocase\n        $c3 = \"shadowcopy delete\" ascii wide nocase\n        $c4 = \"recoveryenabled no\" ascii wide nocase\n        $c5 = \"bootstatuspolicy ignoreallfailures\" ascii wide nocase\n        $c6 = \"wbadmin delete catalog\" ascii wide nocase\n        $c7 = \"Win32_ShadowCopy\" ascii wide nocase\n        $c8 = \"resize shadowstorage\" ascii wide nocase\n    condition:\n        uint16(0) == 0x5A4D and filesize < 20MB and 2 of them\n}",
    "severity": "high",
    "category": "impact",
    "technique": "T1490",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "ransomware",
      "vss"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-yar-057",
    "type": "yara",
    "title": "Executable With Mass Service and Process Kill List",
    "description": "PE embedding long kill lists of database, backup and security services typical of ransomware pre-encryption routines.",
    "code": "rule RANSOM_PE_Service_And_Process_Killer {\n    meta:\n        description = \"PE embedding long kill lists of database, backup and security services typical of ransomware pre-encryption routines.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"high\"\n        mitre_attack = \"T1489\"\n    strings:\n        $s1 = \"sql\" ascii wide nocase\n        $s2 = \"veeam\" ascii wide nocase\n        $s3 = \"backup\" ascii wide nocase\n        $s4 = \"memtas\" ascii wide nocase\n        $s5 = \"mepocs\" ascii wide nocase\n        $s6 = \"sophos\" ascii wide nocase\n        $s7 = \"svc$\" ascii wide nocase\n        $s8 = \"vss\" ascii wide nocase\n        $p1 = \"msftesql.exe\" ascii wide nocase\n        $p2 = \"sqlagent.exe\" ascii wide nocase\n        $p3 = \"oracle.exe\" ascii wide nocase\n        $p4 = \"ocssd.exe\" ascii wide nocase\n        $p5 = \"dbsnmp.exe\" ascii wide nocase\n        $p6 = \"thebat.exe\" ascii wide nocase\n        $p7 = \"steam.exe\" ascii wide nocase\n    condition:\n        uint16(0) == 0x5A4D and filesize < 20MB and 6 of ($s*) and 4 of ($p*)\n}",
    "severity": "high",
    "category": "impact",
    "technique": "T1489",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "ransomware",
      "kill-list"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-yar-058",
    "type": "yara",
    "title": "Info-Stealer Browser Database Paths",
    "description": "PE referencing multiple browser credential/cookie stores (Login Data, Cookies, Local State, logins.json, key4.db) across browsers.",
    "code": "rule STEALER_Browser_Credential_Paths {\n    meta:\n        description = \"PE referencing multiple browser credential/cookie stores (Login Data, Cookies, Local State, logins.json, key4.db) across browsers.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"high\"\n        mitre_attack = \"T1555.003\"\n    strings:\n        $c1 = \"\\\\Google\\\\Chrome\\\\User Data\" ascii wide nocase\n        $c2 = \"\\\\Microsoft\\\\Edge\\\\User Data\" ascii wide nocase\n        $c3 = \"\\\\BraveSoftware\\\\Brave-Browser\\\\User Data\" ascii wide nocase\n        $c4 = \"\\\\Mozilla\\\\Firefox\\\\Profiles\" ascii wide nocase\n        $c5 = \"\\\\Opera Software\\\\Opera Stable\" ascii wide nocase\n        $f1 = \"Login Data\" ascii wide\n        $f2 = \"Web Data\" ascii wide\n        $f3 = \"Local State\" ascii wide\n        $f4 = \"logins.json\" ascii wide\n        $f5 = \"key4.db\" ascii wide\n        $f6 = \"encrypted_key\" ascii wide\n        $f7 = \"Network\\\\Cookies\" ascii wide\n    condition:\n        uint16(0) == 0x5A4D and filesize < 20MB and 3 of ($c*) and 4 of ($f*)\n}",
    "severity": "high",
    "category": "credential-access",
    "technique": "T1555.003",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "stealer",
      "browser"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-yar-059",
    "type": "yara",
    "title": "Info-Stealer Cryptocurrency Wallet Targets",
    "description": "PE referencing several desktop wallet folders and browser wallet extension IDs.",
    "code": "rule STEALER_Crypto_Wallet_Paths {\n    meta:\n        description = \"PE referencing several desktop wallet folders and browser wallet extension IDs.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"high\"\n        mitre_attack = \"T1555\"\n    strings:\n        $w1 = \"\\\\Exodus\\\\exodus.wallet\" ascii wide nocase\n        $w2 = \"\\\\Electrum\\\\wallets\" ascii wide nocase\n        $w3 = \"\\\\Ethereum\\\\keystore\" ascii wide nocase\n        $w4 = \"\\\\atomic\\\\Local Storage\\\\leveldb\" ascii wide nocase\n        $w5 = \"\\\\Armory\" ascii wide nocase\n        $w6 = \"wallet.dat\" ascii wide nocase\n        $w7 = \"\\\\Coinomi\\\\Coinomi\\\\wallets\" ascii wide nocase\n        $e1 = \"nkbihfbeogaeaoehlefnkodbefgpgknn\" ascii wide\n        $e2 = \"bfnaelmomeimhlpmgjnjophhpkkoljpa\" ascii wide\n        $e3 = \"fhbohimaelbohpjbbldcngcnapndodjp\" ascii wide\n        $e4 = \"hnfanknocfeofbddgcijnmhnfnkdnaad\" ascii wide\n    condition:\n        uint16(0) == 0x5A4D and filesize < 20MB and (4 of ($w*) or (2 of ($w*) and 2 of ($e*)))\n}",
    "severity": "high",
    "category": "credential-access",
    "technique": "T1555",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "stealer",
      "crypto-wallet"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-yar-060",
    "type": "yara",
    "title": "Discord Token or Telegram Session Stealer",
    "description": "Detects code targeting Discord token storage (leveldb) or Telegram Desktop tdata session folders.",
    "code": "rule STEALER_Discord_Telegram_Session_Theft {\n    meta:\n        description = \"Detects code targeting Discord token storage (leveldb) or Telegram Desktop tdata session folders.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"high\"\n        mitre_attack = \"T1528\"\n    strings:\n        $d1 = \"\\\\discord\\\\Local Storage\\\\leveldb\" ascii wide nocase\n        $d2 = \"\\\\discordcanary\\\\Local Storage\\\\leveldb\" ascii wide nocase\n        $d3 = \"\\\\discordptb\\\\Local Storage\\\\leveldb\" ascii wide nocase\n        $re = \"[\\\\w-]{24}\\\\.[\\\\w-]{6}\\\\.[\\\\w-]{27}\" ascii wide\n        $re2 = \"dQw4w9WgXcQ:\" ascii wide\n        $t1 = \"\\\\Telegram Desktop\\\\tdata\" ascii wide nocase\n        $t2 = \"key_datas\" ascii wide\n    condition:\n        filesize < 20MB and (2 of ($d*) or (1 of ($d*) and 1 of ($re*)) or all of ($t*))\n}",
    "severity": "high",
    "category": "credential-access",
    "technique": "T1528",
    "author": "OSINTrix pack",
    "platform": "Any",
    "tags": [
      "stealer",
      "discord",
      "telegram"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-yar-061",
    "type": "yara",
    "title": "Executable Exfiltrating via Telegram Bot API",
    "description": "PE containing the Telegram Bot API base URL and sendDocument/sendMessage methods, used by many stealers to exfiltrate data.",
    "code": "rule STEALER_Telegram_Bot_Exfil_PE {\n    meta:\n        description = \"PE containing the Telegram Bot API base URL and sendDocument/sendMessage methods, used by many stealers to exfiltrate data.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"high\"\n        mitre_attack = \"T1567\"\n    strings:\n        $t = \"api.telegram.org/bot\" ascii wide nocase\n        $m1 = \"/sendDocument\" ascii wide\n        $m2 = \"/sendMessage\" ascii wide\n        $m3 = \"chat_id\" ascii wide\n        $z1 = \"ZipFile\" ascii wide\n        $z2 = \"passwords\" ascii wide nocase\n        $z3 = \"cookies\" ascii wide nocase\n    condition:\n        uint16(0) == 0x5A4D and filesize < 20MB and $t and 2 of ($m*) and 1 of ($z*)\n}",
    "severity": "high",
    "category": "exfiltration",
    "technique": "T1567",
    "author": "OSINTrix pack",
    "platform": "Windows",
    "tags": [
      "stealer",
      "telegram"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-yar-062",
    "type": "yara",
    "title": "macOS AppleScript Credential and Data Harvester",
    "description": "AppleScript/shell payloads that fake a password dialog and collect keychain, browser and wallet data, characteristic of macOS stealers.",
    "code": "rule STEALER_macOS_AppleScript_Harvester {\n    meta:\n        description = \"AppleScript/shell payloads that fake a password dialog and collect keychain, browser and wallet data, characteristic of macOS stealers.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"high\"\n        mitre_attack = \"T1555.001\"\n    strings:\n        $o1 = \"osascript\" ascii\n        $o2 = \"display dialog\" ascii\n        $o3 = \"hidden answer\" ascii\n        $k1 = \"login.keychain-db\" ascii\n        $k2 = \"/Library/Keychains/\" ascii\n        $b1 = \"/Library/Application Support/Google/Chrome/\" ascii\n        $b2 = \"/Library/Application Support/Firefox/Profiles\" ascii\n        $b3 = \"Cookies.binarycookies\" ascii\n        $w1 = \"Exodus\" ascii\n        $w2 = \"Electrum\" ascii\n        $x1 = \"ditto -c -k\" ascii\n        $x2 = \"curl -X POST\" ascii\n    condition:\n        filesize < 10MB and 2 of ($o*) and 1 of ($k*) and 1 of ($b*) and 1 of ($w*, $x*)\n}",
    "severity": "high",
    "category": "credential-access",
    "technique": "T1555.001",
    "author": "OSINTrix pack",
    "platform": "macOS",
    "tags": [
      "stealer",
      "macos",
      "applescript"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-yar-063",
    "type": "yara",
    "title": "Cryptocurrency Miner Configuration",
    "description": "Detects XMRig-style JSON configs and command strings containing stratum URLs and miner keys.",
    "code": "rule MINER_Config_Stratum_XMRig {\n    meta:\n        description = \"Detects XMRig-style JSON configs and command strings containing stratum URLs and miner keys.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"high\"\n        mitre_attack = \"T1496\"\n    strings:\n        $s1 = \"stratum+tcp://\" ascii wide\n        $s2 = \"stratum+ssl://\" ascii wide\n        $k1 = \"\\\"donate-level\\\"\" ascii\n        $k2 = \"\\\"algo\\\"\" ascii\n        $k3 = \"\\\"pools\\\"\" ascii\n        $k4 = \"\\\"randomx\\\"\" ascii\n        $k5 = \"\\\"nicehash\\\"\" ascii\n        $k6 = \"\\\"rig-id\\\"\" ascii\n        $k7 = \"--donate-level\" ascii wide\n    condition:\n        filesize < 5MB and 1 of ($s*) and 2 of ($k*)\n}",
    "severity": "high",
    "category": "impact",
    "technique": "T1496",
    "author": "OSINTrix pack",
    "platform": "Any",
    "tags": [
      "miner",
      "xmrig"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-yar-064",
    "type": "yara",
    "title": "XMRig Miner Binary",
    "description": "Detects XMRig miner executables for Windows or Linux by banner and algorithm strings.",
    "code": "rule MINER_XMRig_Binary {\n    meta:\n        description = \"Detects XMRig miner executables for Windows or Linux by banner and algorithm strings.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"high\"\n        mitre_attack = \"T1496\"\n    strings:\n        $x1 = \"XMRig\" ascii\n        $x2 = \"xmrig\" ascii\n        $a1 = \"cryptonight\" ascii\n        $a2 = \"randomx\" ascii nocase\n        $a3 = \"rx/0\" ascii\n        $a4 = \"--donate-level\" ascii\n        $a5 = \"stratum\" ascii\n    condition:\n        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and filesize < 30MB and 1 of ($x*) and 3 of ($a*)\n}",
    "severity": "high",
    "category": "impact",
    "technique": "T1496",
    "author": "OSINTrix pack",
    "platform": "Any",
    "tags": [
      "miner",
      "xmrig"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-yar-065",
    "type": "yara",
    "title": "Mirai-Like IoT Botnet ELF",
    "description": "ELF binary with Mirai-family traits: busybox abuse, watchdog handling, scanner credentials and attack strings.",
    "code": "rule ELF_Mirai_Like_Botnet {\n    meta:\n        description = \"ELF binary with Mirai-family traits: busybox abuse, watchdog handling, scanner credentials and attack strings.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"high\"\n        mitre_attack = \"T1498\"\n    strings:\n        $b1 = \"/bin/busybox\" ascii\n        $b2 = \"/dev/watchdog\" ascii\n        $b3 = \"/dev/misc/watchdog\" ascii\n        $c1 = \"xc3511\" ascii\n        $c2 = \"vizxv\" ascii\n        $c3 = \"admin1234\" ascii\n        $c4 = \"juantech\" ascii\n        $c5 = \"Zte521\" ascii\n        $a1 = \"/proc/net/tcp\" ascii\n        $a2 = \"POST /cdn-cgi/\" ascii\n        $a3 = \"TSource Engine Query\" ascii\n        $a4 = \"/shell?cd+/tmp\" ascii\n        $a5 = \"enable\\x00system\\x00shell\\x00sh\" ascii\n    condition:\n        uint32(0) == 0x464C457F and filesize < 5MB and 1 of ($b*) and (2 of ($c*) or 2 of ($a*))\n}",
    "severity": "high",
    "category": "malware",
    "technique": "T1498",
    "author": "OSINTrix pack",
    "platform": "Linux",
    "tags": [
      "mirai",
      "iot",
      "botnet"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-yar-066",
    "type": "yara",
    "title": "ELF Backdoor With Shell and History Evasion Strings",
    "description": "ELF that spawns interactive shells and disables shell history, a profile shared by many Linux backdoors.",
    "code": "rule ELF_Backdoor_History_Evasion {\n    meta:\n        description = \"ELF that spawns interactive shells and disables shell history, a profile shared by many Linux backdoors.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"high\"\n        mitre_attack = \"T1059.004\"\n    strings:\n        $h1 = \"HISTFILE=/dev/null\" ascii\n        $h2 = \"unset HISTFILE\" ascii\n        $h3 = \"HISTSIZE=0\" ascii\n        $s1 = \"/bin/sh -i\" ascii\n        $s2 = \"/bin/bash -i\" ascii\n        $s3 = \"/bin/sh\" ascii\n        $p1 = \"PS1=\" ascii\n        $p2 = \"TERM=xterm\" ascii\n        $p3 = \"openpty\" ascii\n        $p4 = \"forkpty\" ascii\n    condition:\n        uint32(0) == 0x464C457F and filesize < 10MB and 1 of ($h*) and 1 of ($s*) and 2 of ($p*)\n}",
    "severity": "high",
    "category": "malware",
    "technique": "T1059.004",
    "author": "OSINTrix pack",
    "platform": "Linux",
    "tags": [
      "backdoor",
      "elf"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-yar-067",
    "type": "yara",
    "title": "Userland LD_PRELOAD Rootkit Library",
    "description": "ELF shared object that hooks directory listing and file functions and references /etc/ld.so.preload, the pattern of userland rootkits.",
    "code": "rule ELF_LD_PRELOAD_Rootkit {\n    meta:\n        description = \"ELF shared object that hooks directory listing and file functions and references /etc/ld.so.preload, the pattern of userland rootkits.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"critical\"\n        mitre_attack = \"T1574.006\"\n    strings:\n        $p = \"/etc/ld.so.preload\" ascii\n        $d = \"dlsym\" ascii\n        $h1 = \"readdir\" ascii\n        $h2 = \"readdir64\" ascii\n        $h3 = \"fopen\" ascii\n        $h4 = \"__lxstat\" ascii\n        $h5 = \"access\" ascii\n        $n1 = \"/proc/\" ascii\n        $n2 = \"RTLD_NEXT\" ascii\n    condition:\n        uint32(0) == 0x464C457F and uint16(0x10) == 3 and filesize < 5MB and $p and $d and 3 of ($h*) and 1 of ($n*)\n}",
    "severity": "critical",
    "category": "defense-evasion",
    "technique": "T1574.006",
    "author": "OSINTrix pack",
    "platform": "Linux",
    "tags": [
      "rootkit",
      "ld-preload"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-yar-068",
    "type": "yara",
    "title": "Credential Phishing Page HTML",
    "description": "HTML page with password input, sign-in lure text and a form/JS post to an off-site PHP or webhook endpoint.",
    "code": "rule PHISH_Credential_Harvest_HTML {\n    meta:\n        description = \"HTML page with password input, sign-in lure text and a form/JS post to an off-site PHP or webhook endpoint.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"medium\"\n        mitre_attack = \"T1566.002\"\n    strings:\n        $h = \"<html\" ascii nocase\n        $pw = /type\\s*=\\s*[\"']?password/ ascii nocase\n        $l1 = \"Sign in to your account\" ascii nocase\n        $l2 = \"Verify your identity\" ascii nocase\n        $l3 = \"session has expired\" ascii nocase\n        $l4 = \"confirm your password\" ascii nocase\n        $l5 = \"Enter password\" ascii nocase\n        $x1 = /action\\s*=\\s*[\"'][^\"']{0,200}\\.php[\"']/ ascii nocase\n        $x2 = \"api.telegram.org\" ascii nocase\n        $x3 = \"$.ajax(\" ascii\n        $x4 = \"fetch(\" ascii\n        $x5 = \"discord.com/api/webhooks\" ascii nocase\n    condition:\n        filesize < 2MB and $h and $pw and 1 of ($l*) and 1 of ($x*)\n}",
    "severity": "medium",
    "category": "initial-access",
    "technique": "T1566.002",
    "author": "OSINTrix pack",
    "platform": "Web",
    "tags": [
      "phishing",
      "credential-harvest"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-yar-069",
    "type": "yara",
    "title": "Phishing Kit PHP Credential Exfiltration",
    "description": "PHP back end of a phishing kit that collects posted credentials and sends them via mail(), Telegram or a log file.",
    "code": "rule PHISH_Kit_PHP_Exfil {\n    meta:\n        description = \"PHP back end of a phishing kit that collects posted credentials and sends them via mail(), Telegram or a log file.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"high\"\n        mitre_attack = \"T1056.003\"\n    strings:\n        $tagphp = \"<?php\" ascii nocase\n        $p1 = \"$_POST['password']\" ascii nocase\n        $p2 = \"$_POST['pass']\" ascii nocase\n        $p3 = \"$_POST['passwd']\" ascii nocase\n        $p4 = \"$_POST[\\\"password\\\"]\" ascii nocase\n        $s1 = \"api.telegram.org/bot\" ascii\n        $s2 = \"mail($\" ascii\n        $s3 = \"fwrite($\" ascii\n        $i1 = \"$_SERVER['REMOTE_ADDR']\" ascii\n        $i2 = \"HTTP_USER_AGENT\" ascii\n        $i3 = \"geoplugin\" ascii nocase\n    condition:\n        filesize < 500KB and $tagphp and 1 of ($p*) and 1 of ($s*) and 1 of ($i*)\n}",
    "severity": "high",
    "category": "collection",
    "technique": "T1056.003",
    "author": "OSINTrix pack",
    "platform": "Web",
    "tags": [
      "phishing-kit",
      "php"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-yar-070",
    "type": "yara",
    "title": "Phishing Kit Anti-Bot and Crawler Blocking",
    "description": "PHP/.htaccess logic in phishing kits that blocks security crawlers by user agent, hostname or IP before serving the lure.",
    "code": "rule PHISH_Kit_Antibot_Filter {\n    meta:\n        description = \"PHP/.htaccess logic in phishing kits that blocks security crawlers by user agent, hostname or IP before serving the lure.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"medium\"\n        mitre_attack = \"T1036\"\n    strings:\n        $a1 = \"antibot\" ascii nocase\n        $a2 = \"blocker.php\" ascii nocase\n        $b1 = \"googlebot\" ascii nocase\n        $b2 = \"phishtank\" ascii nocase\n        $b3 = \"bitdefender\" ascii nocase\n        $b4 = \"netcraft\" ascii nocase\n        $b5 = \"virustotal\" ascii nocase\n        $b6 = \"urlscan\" ascii nocase\n        $r1 = \"header(\\\"Location:\" ascii nocase\n        $r2 = \"HTTP/1.0 404 Not Found\" ascii nocase\n        $r3 = \"gethostbyaddr\" ascii nocase\n    condition:\n        filesize < 1MB and 1 of ($a*) and 3 of ($b*) and 1 of ($r*)\n}",
    "severity": "medium",
    "category": "defense-evasion",
    "technique": "T1036",
    "author": "OSINTrix pack",
    "platform": "Web",
    "tags": [
      "phishing-kit",
      "antibot"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-yar-071",
    "type": "yara",
    "title": "HTML Smuggling via Blob Download",
    "description": "HTML that decodes a large embedded base64 blob into a Blob and triggers a download through createObjectURL or msSaveOrOpenBlob.",
    "code": "rule SUSP_HTML_Smuggling_Blob {\n    meta:\n        description = \"HTML that decodes a large embedded base64 blob into a Blob and triggers a download through createObjectURL or msSaveOrOpenBlob.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"high\"\n        mitre_attack = \"T1027.006\"\n    strings:\n        $h = \"<html\" ascii nocase\n        $b1 = \"new Blob(\" ascii\n        $b2 = \"atob(\" ascii\n        $b3 = \"Uint8Array\" ascii\n        $d1 = \"createObjectURL\" ascii\n        $d2 = \"msSaveOrOpenBlob\" ascii\n        $d3 = \".download =\" ascii\n        $d4 = \".download=\" ascii\n        $payload = /[\"'][A-Za-z0-9+\\/]{2000,}={0,2}[\"']/\n    condition:\n        filesize < 20MB and $h and 2 of ($b*) and 1 of ($d*) and $payload\n}",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1027.006",
    "author": "OSINTrix pack",
    "platform": "Web",
    "tags": [
      "html-smuggling",
      "phishing"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-yar-072",
    "type": "yara",
    "title": "JavaScript Payment Card Skimmer",
    "description": "Detects client-side skimmers that read card fields on checkout pages and exfiltrate encoded data via image beacons, fetch or XHR.",
    "code": "rule SKIMMER_JS_Payment_Card {\n    meta:\n        description = \"Detects client-side skimmers that read card fields on checkout pages and exfiltrate encoded data via image beacons, fetch or XHR.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"high\"\n        mitre_attack = \"T1056.003\"\n    strings:\n        $f1 = \"checkout\" ascii nocase\n        $f2 = \"cc_number\" ascii nocase\n        $f3 = \"cardnumber\" ascii nocase\n        $f4 = \"cvv\" ascii nocase\n        $f5 = \"card_expiry\" ascii nocase\n        $f6 = \"billing\" ascii nocase\n        $e1 = \"btoa(\" ascii\n        $e2 = \"JSON.stringify\" ascii\n        $x1 = \"new Image()\" ascii\n        $x2 = \".src=\" ascii\n        $x3 = \"XMLHttpRequest\" ascii\n        $x4 = \"navigator.sendBeacon\" ascii\n        $x5 = \"WebSocket(\" ascii\n        $l = \"addEventListener\" ascii\n    condition:\n        filesize < 1MB and 3 of ($f*) and 1 of ($e*) and 1 of ($x*) and $l\n}",
    "severity": "high",
    "category": "collection",
    "technique": "T1056.003",
    "author": "OSINTrix pack",
    "platform": "Web",
    "tags": [
      "magecart",
      "skimmer",
      "javascript"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-yar-073",
    "type": "yara",
    "title": "Packed or Heavily Obfuscated JavaScript",
    "description": "Detects Dean Edwards style packers (eval(function(p,a,c,k,e,...)) or large String.fromCharCode payloads combined with eval.",
    "code": "rule SUSP_JS_Packer_Obfuscation {\n    meta:\n        description = \"Detects Dean Edwards style packers (eval(function(p,a,c,k,e,...)) or large String.fromCharCode payloads combined with eval.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"low\"\n        mitre_attack = \"T1027\"\n    strings:\n        $p1 = \"eval(function(p,a,c,k,e,\" ascii\n        $p2 = /eval\\s*\\(\\s*String\\.fromCharCode\\s*\\(\\s*([0-9]{2,3}\\s*,\\s*){50,}/\n        $p3 = /_0x[a-f0-9]{4,6}\\[_0x[a-f0-9]{4,6}\\(0x[0-9a-f]{1,4}\\)\\]/\n    condition:\n        filesize < 5MB and ($p1 or $p2 or #p3 > 20)\n}",
    "severity": "low",
    "category": "defense-evasion",
    "technique": "T1027",
    "author": "OSINTrix pack",
    "platform": "Web",
    "tags": [
      "javascript",
      "obfuscation"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-yar-074",
    "type": "yara",
    "title": "PDF With Auto-Run JavaScript",
    "description": "PDF that combines an /OpenAction or /AA trigger with embedded /JavaScript or /JS.",
    "code": "rule SUSP_PDF_OpenAction_JavaScript {\n    meta:\n        description = \"PDF that combines an /OpenAction or /AA trigger with embedded /JavaScript or /JS.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"medium\"\n        mitre_attack = \"T1204.002\"\n    strings:\n        $o1 = \"/OpenAction\" ascii\n        $o2 = \"/AA\" ascii\n        $j1 = \"/JavaScript\" ascii\n        $j2 = \"/JS\" ascii\n    condition:\n        uint32(0) == 0x46445025 and filesize < 20MB and 1 of ($o*) and 1 of ($j*)\n}",
    "severity": "medium",
    "category": "execution",
    "technique": "T1204.002",
    "author": "OSINTrix pack",
    "platform": "Any",
    "tags": [
      "pdf",
      "javascript"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-yar-075",
    "type": "yara",
    "title": "PDF With Launch Action or Auto-Opened Embedded File",
    "description": "PDF using /Launch to run a program or combining /EmbeddedFile with an automatic action.",
    "code": "rule SUSP_PDF_Launch_Or_EmbeddedFile {\n    meta:\n        description = \"PDF using /Launch to run a program or combining /EmbeddedFile with an automatic action.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"high\"\n        mitre_attack = \"T1204.002\"\n    strings:\n        $l = \"/Launch\" ascii\n        $e = \"/EmbeddedFile\" ascii\n        $o1 = \"/OpenAction\" ascii\n        $o2 = \"/AA\" ascii\n        $x1 = \"cmd.exe\" ascii nocase\n        $x2 = \"powershell\" ascii nocase\n        $x3 = \".exe\" ascii nocase\n    condition:\n        uint32(0) == 0x46445025 and filesize < 20MB and (($l and 1 of ($x*)) or ($e and 1 of ($o*)))\n}",
    "severity": "high",
    "category": "execution",
    "technique": "T1204.002",
    "author": "OSINTrix pack",
    "platform": "Any",
    "tags": [
      "pdf",
      "launch-action"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  },
  {
    "id": "pk-yar-076",
    "type": "yara",
    "title": "Base64-Encoded PE Executable in Text",
    "description": "Detects the base64 encoding of an MZ header (several common DOS stub variants) inside scripts, documents or logs.",
    "code": "rule SUSP_Base64_Encoded_PE {\n    meta:\n        description = \"Detects the base64 encoding of an MZ header (several common DOS stub variants) inside scripts, documents or logs.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"high\"\n        mitre_attack = \"T1027\"\n    strings:\n        $b1 = \"TVqQAAMAAAAEAAAA\" ascii wide\n        $b2 = \"TVpQAAIAAAAEAA8A\" ascii wide\n        $b3 = \"TVoAAAAAAAAAAAAA\" ascii wide\n        $b4 = \"TVpBUlVIieVIgewgAAAA\" ascii wide\n        $b5 = \"TVqAAAEAAAAEABAA\" ascii wide\n    condition:\n        filesize < 50MB and uint16(0) != 0x5A4D and any of them\n}",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1027",
    "author": "OSINTrix pack",
    "platform": "Any",
    "tags": [
      "base64",
      "embedded-pe"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "common"
  },
  {
    "id": "pk-yar-077",
    "type": "yara",
    "title": "Reversed Base64 or Hex-Encoded PE in Text",
    "description": "Detects PE headers hidden as reversed base64, hex strings or comma-separated byte arrays.",
    "code": "rule SUSP_Reversed_Or_Hex_Encoded_PE {\n    meta:\n        description = \"Detects PE headers hidden as reversed base64, hex strings or comma-separated byte arrays.\"\n        author = \"OSINTrix pack\"\n        date = \"2026-11-03\"\n        severity = \"high\"\n        mitre_attack = \"T1027\"\n    strings:\n        $r1 = \"AAAAEAAAAMAAQqVT\" ascii wide\n        $r2 = \"A8AAEAAAIAAQpVT\" ascii wide\n        $h1 = \"4D5A90000300000004000000FFFF0000\" ascii wide nocase\n        $h2 = \"4d 5a 90 00 03 00 00 00 04 00 00 00\" ascii wide nocase\n        $h3 = \"0x4D,0x5A,0x90,0x00,0x03,0x00\" ascii wide nocase\n        $h4 = \"77,90,144,0,3,0,0,0,4,0,0,0\" ascii wide\n    condition:\n        filesize < 50MB and uint16(0) != 0x5A4D and any of them\n}",
    "severity": "high",
    "category": "defense-evasion",
    "technique": "T1027",
    "author": "OSINTrix pack",
    "platform": "Any",
    "tags": [
      "encoded-pe",
      "obfuscation"
    ],
    "references": [],
    "created": "2026-11-03T00:00:00Z",
    "modified": "2026-11-03T00:00:00Z",
    "starred": false,
    "level": "advanced"
  }
];
