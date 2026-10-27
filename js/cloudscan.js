/* ==========================================================================
   Cloud misconfiguration scanner — a defensive linter that runs in the page.
   Reads: AWS IAM / resource policies, GCP IAM policies, Azure role definitions,
   Terraform (.tf and `terraform show -json` plans/state), CloudFormation (JSON/YAML),
   Azure ARM templates and Kubernetes manifests. It only reports weak settings and
   suggests the fix; it never changes anything. Cloud audit logs go to cloudlogs.js.
   No DOM access here, so it can be unit-tested on its own.
   ========================================================================== */
const CS = (() => {
  /* ---------------- small helpers ---------------- */
  const arr = v => v == null ? [] : Array.isArray(v) ? v : [v];
  const low = v => String(v == null ? '' : v).toLowerCase();
  const isObj = v => v && typeof v === 'object' && !Array.isArray(v);
  const truthy = v => v === true || low(v) === 'true';
  const blocks = (o, k) => arr(o && o[k]).flatMap(x => Array.isArray(x) ? x : [x]).filter(isObj);
  const lineOf = (text, ...needles) => { if(!text) return 0; for(const n of needles){ if(!n) continue; const i = text.indexOf(String(n)); if(i >= 0) return text.slice(0, i).split('\n').length; } return 0; };
  const OPEN = new Set(['0.0.0.0/0', '::/0', '*', 'internet', 'any', '0.0.0.0', '/0']);
  const isOpenCidr = c => arr(c).some(x => OPEN.has(low(x).trim()));
  const ADMIN_PORTS = {22:'SSH', 3389:'RDP', 5985:'WinRM', 5986:'WinRM', 23:'Telnet', 21:'FTP', 445:'SMB', 135:'MS RPC', 5900:'VNC'};
  const DATA_PORTS = {3306:'MySQL', 5432:'PostgreSQL', 1433:'SQL Server', 1521:'Oracle', 27017:'MongoDB', 6379:'Redis', 9200:'Elasticsearch', 5601:'Kibana', 11211:'Memcached', 9042:'Cassandra', 2379:'etcd', 5984:'CouchDB', 9092:'Kafka', 2375:'Docker API', 10250:'Kubelet', 6443:'Kubernetes API'};
  const parseRange = s => { s = String(s == null ? '' : s).trim(); if(s === '*' || s === '' || s === '-1') return [0, 65535]; const m = s.match(/^(\d+)\s*-\s*(\d+)$/); if(m) return [+m[1], +m[2]]; return isFinite(+s) ? [+s, +s] : null; };
  function portExposure(range, proto){
    if(!range) return null; const [a, b] = range, all = (a <= 0 && b >= 65535) || low(proto) === '-1' || low(proto) === 'all' || proto === '*';
    if(all) return {sev:'critical', what:'every port'};
    const adm = Object.keys(ADMIN_PORTS).filter(p => p >= a && p <= b); if(adm.length) return {sev:'critical', what:adm.map(p => ADMIN_PORTS[p] + ' (' + p + ')').join(', ')};
    const dat = Object.keys(DATA_PORTS).filter(p => p >= a && p <= b); if(dat.length) return {sev:'high', what:dat.map(p => DATA_PORTS[p] + ' (' + p + ')').join(', ')};
    if(b - a > 100) return {sev:'high', what:'ports ' + a + '–' + b};
    return {sev:'medium', what:a === b ? 'port ' + a : 'ports ' + a + '–' + b};
  }
  /* a field whose NAME says secret but whose value is a plain inline literal (not a reference / variable) */
  const SECRET_NAME = /(^|[_\-])(pass(word|wd)?|secret|client[_\-]?secret|api[_\-]?key|access[_\-]?key|private[_\-]?key|conn(ection)?[_\-]?string|sas[_\-]?token|auth[_\-]?token)([_\-]|$)/i;
  const isReference = v => typeof v !== 'string' || /^\s*(\$\{|\{\{|!Ref|!Sub|!GetAtt|data\.|var\.|module\.|local\.|aws_|arn:|secretref|valuefrom|<[^>]+>)/i.test(v) || v === '' || /^(true|false|null|\d+)$/i.test(v);
  function inlineSecrets(obj, path, out, cap){
    if(out.length >= cap) return;
    if(isObj(obj)){ for(const k in obj){ const v = obj[k]; if(typeof v === 'string' && SECRET_NAME.test(k) && !isReference(v) && v.length >= 6){ out.push({key:k, path:path.concat(k).join('.')}); if(out.length >= cap) return; } inlineSecrets(v, path.concat(k), out, cap); } }
    else if(Array.isArray(obj)) obj.forEach((v, i) => inlineSecrets(v, path.concat(i), out, cap));
  }

  const SEV = {critical:0, high:1, medium:2, low:3, info:4};
  const sevRank = f => SEV[f.sev] == null ? 5 : SEV[f.sev];

  return {arr, low, isObj, truthy, blocks, lineOf, OPEN, isOpenCidr, ADMIN_PORTS, DATA_PORTS, parseRange, portExposure, SECRET_NAME, isReference, inlineSecrets, SEV, sevRank};
})();

/* ==========================================================================
   Detection rules per input kind. Each returns findings:
   {id, sev, title, detail, fix, where, line}
   ========================================================================== */
const CSRULES = (() => {
  const {arr, low, isObj, truthy, blocks, lineOf, isOpenCidr, parseRange, portExposure, inlineSecrets} = CS;
  const F = (sev, title, detail, fix, where, line) => ({sev, title, detail, fix, where: where || '', line: line || 0});

  /* ---- AWS IAM / resource policy documents ---- */
  function awsPolicy(doc, text, where){
    const out = [], stmts = arr(doc.Statement);
    stmts.forEach((s, i) => {
      if(!isObj(s)) return;
      const eff = low(s.Effect), act = arr(s.Action).map(low), res = arr(s.Resource).map(String), notAct = arr(s.NotAction);
      const w = (where || 'policy') + ' · statement ' + (s.Sid || (i + 1)), ln = lineOf(text, s.Sid, Array.isArray(doc.Statement) ? null : null);
      if(eff !== 'allow') return;
      const star = act.includes('*') || act.some(a => a.endsWith(':*') && a.split(':')[0] === '*');
      const resStar = res.includes('*');
      if((act.includes('*') || act.some(a => a === '*')) && resStar)
        out.push(F('critical', 'Full admin: Action "*" on Resource "*"', 'This statement allows every action on every resource — effectively account administrator.', 'Scope Action to the specific services and operations needed, and Resource to specific ARNs.', w, ln));
      else {
        if(act.includes('*')) out.push(F('high', 'Wildcard Action "*"', 'Grants every API action in scope.', 'List only the actions this role needs.', w, ln));
        else { const svcStar = act.filter(a => a.endsWith(':*')); if(svcStar.length) out.push(F('medium', 'Service-wide wildcard: ' + svcStar.join(', '), 'Grants every action in those services.', 'Replace with the specific actions needed.', w, ln)); }
        if(resStar && !act.every(a => /^(cloudwatch|logs|ce|health|tag|access-analyzer|trustedadvisor):/.test(a))) out.push(F('medium', 'Resource "*"', 'Actions apply to every resource of the type.', 'Pin Resource to specific ARNs where the service supports it.', w, ln));
      }
      if(notAct.length && eff === 'allow') out.push(F('high', 'Allow with NotAction', 'Allow + NotAction grants everything except the listed actions — easy to over-grant.', 'Rewrite as an explicit Allow of the intended actions.', w, ln));
      const pr = s.Principal, anyPrin = pr === '*' || (isObj(pr) && (pr.AWS === '*' || arr(pr.AWS).includes('*')));
      if(anyPrin){
        const cond = s.Condition;
        if(!cond || !isObj(cond)) out.push(F('critical', 'Resource open to any AWS principal', 'Principal "*" with no Condition lets anyone use this resource.', 'Name specific account/role ARNs, or add a Condition (aws:PrincipalOrgID, SourceArn, etc.).', w, ln));
        else out.push(F('medium', 'Principal "*" with a condition', 'Open principal, but limited by a Condition — confirm the condition is tight.', 'Verify the Condition only matches trusted callers.', w, ln));
      }
      const prescalate = act.some(a => /^iam:(createaccesskey|createuser|createloginprofile|updateloginprofile|attach(user|role|group)policy|put(user|role|group)policy|createpolicyversion|setdefaultpolicyversion|passrole|addusertogroup|createrole|updateassumerolepolicy)$/.test(a) || a === 'iam:*' || a === 'sts:assumerole');
      if(prescalate && (resStar || res.some(r => r.includes(':role/') || r === '*'))) out.push(F('high', 'Privilege-escalation path via IAM', 'Allows IAM actions (e.g. ' + act.filter(a => a.startsWith('iam:') || a.startsWith('sts:')).slice(0, 3).join(', ') + ') that can grant the caller more access.', 'Remove these IAM write actions, or restrict Resource to a single tightly-controlled role.', w, ln));
      if(act.some(a => a === 's3:*' || a === 's3:getobject' || a === 's3:*object') && res.some(r => r === '*') && anyPrin) out.push(F('high', 'Public object access on S3', 'Anyone can read objects.', 'Remove the public principal; use pre-signed URLs or CloudFront OAC.', w, ln));
    });
    return out;
  }

  /* ---- GCP IAM policy (bindings) ---- */
  function gcpPolicy(doc, text, where){
    const out = [], PUB = new Set(['allusers', 'allauthenticatedusers']);
    const ADMIN = /(^|\.)(owner|editor|admin)$|roles\/(owner|editor)/i;
    arr(doc.bindings).forEach(b => {
      if(!isObj(b)) return; const role = String(b.role || ''), mem = arr(b.members).map(String);
      const pub = mem.filter(m => PUB.has(low(m.replace(/^user:|^serviceaccount:/, '').trim())) || PUB.has(low(m)));
      const ln = lineOf(text, role);
      if(pub.length) out.push(F(ADMIN.test(role) ? 'critical' : 'high', 'Public IAM binding: ' + role, 'Members ' + pub.join(', ') + ' make this role public to the internet.', 'Remove allUsers / allAuthenticatedUsers; grant to specific principals.', (where || 'bindings') + ' · ' + role, ln));
      else if(/roles\/owner$/.test(role)) out.push(F('medium', 'Owner role granted', role + ' granted to ' + mem.length + ' member(s).', 'Prefer least-privilege predefined or custom roles over Owner.', (where || 'bindings') + ' · ' + role, ln));
      if(role === 'roles/iam.serviceAccountTokenCreator' || role === 'roles/iam.serviceAccountUser') out.push(F('medium', 'Service-account impersonation granted: ' + role, 'Allows acting as a service account — a common privilege-escalation path.', 'Grant only to principals that must impersonate, on a specific service account.', (where || 'bindings') + ' · ' + role, ln));
    });
    return out;
  }

  /* ---- Azure role definition ---- */
  function azureRole(doc, text, where){
    const out = [], props = doc.properties || doc;
    arr(props.permissions).forEach(p => {
      const actions = arr(p.actions).map(String), data = arr(p.dataActions).map(String);
      if(actions.includes('*')) out.push(F('high', 'Azure role with Actions "*"', 'Grants every control-plane action in scope.', 'List the specific resource-provider actions needed.', where || 'role', lineOf(text, '"*"')));
      if(data.includes('*')) out.push(F('high', 'Azure role with dataActions "*"', 'Grants full data-plane access (e.g. read all blobs/secrets).', 'List specific dataActions.', where || 'role', 0));
    });
    const scopes = arr(props.assignableScopes).map(String);
    if(scopes.some(s => /^\/?$|^\/subscriptions\/[^/]+$|^\/$/.test(s)) && actions_any(props)) out.push(F('medium', 'Role assignable at subscription/root scope', 'Broad assignable scope increases blast radius.', 'Narrow assignableScopes to specific resource groups.', where || 'role', 0));
    return out;
    function actions_any(pr){ return arr(pr.permissions).some(p => arr(p.actions).length); }
  }

  return {F, awsPolicy, gcpPolicy, azureRole};
})();

/* ==========================================================================
   Terraform HCL (light parser), plan/state JSON, CloudFormation, ARM, K8s.
   ========================================================================== */
const CSIAC = (() => {
  const {arr, low, isObj, truthy, blocks, lineOf, isOpenCidr, parseRange, portExposure} = CS;
  const {F} = CSRULES;

  /* ---- a small HCL reader: enough to get resource blocks and their flat attributes ---- */
  function parseHCL(text){
    const src = text.replace(/#[^\n]*/g, '').replace(/\/\/[^\n]*/g, '');
    const res = []; const re = /resource\s+"([^"]+)"\s+"([^"]+)"\s*\{/g; let m;
    while((m = re.exec(src))){
      const type = m[1], name = m[2], start = re.lastIndex; let depth = 1, i = start;
      for(; i < src.length && depth; i++){ if(src[i] === '{') depth++; else if(src[i] === '}') depth--; }
      const body = src.slice(start, i - 1);
      res.push({type, name, body, line: text.slice(0, m.index).split('\n').length, attrs: hclAttrs(body)});
    }
    return res;
  }
  function hclAttrs(body){
    const a = {}; const re = /(^|\n)\s*([a-z0-9_]+)\s*=\s*(.+)/gi; let m;
    while((m = re.exec(body))){ const k = m[2]; let v = m[3].trim().replace(/,\s*$/, '');
      if(/^\[.*\]$/.test(v)) v = v.slice(1, -1).split(',').map(x => x.trim().replace(/^["']|["']$/g, '')).filter(x => x !== '');
      else if(/^".*"$/.test(v)) v = v.slice(1, -1);
      if(a[k] === undefined) a[k] = v; }
    const lists = {}; const lr = /(^|\n)\s*([a-z0-9_]+)\s*\{/gi; let lm;
    while((lm = lr.exec(body))){ const k = lm[2]; (lists[k] = lists[k] || []).push(subBlock(body, lr.lastIndex)); }
    for(const k in lists) a['_' + k] = lists[k];
    return a;
  }
  function subBlock(body, start){ let depth = 1, i = start; for(; i < body.length && depth; i++){ if(body[i] === '{') depth++; else if(body[i] === '}') depth--; } return hclAttrs(body.slice(start, i - 1)); }
  const yes = v => v === true || /^true$/i.test(String(v));
  const no = v => v === false || /^false$/i.test(String(v));

  /* ---- rules keyed by terraform resource type (also used for plan JSON values) ---- */
  const TF = {
    aws_security_group: (a, w, ln) => sgRules(a, w, ln),
    aws_security_group_rule: (a, w, ln) => { const out = []; if(low(a.type) !== 'egress' && isOpenCidr(a.cidr_blocks || a._cidr_blocks) || isOpenCidr(a.cidr_blocks)) { const e = portExposure(parseRange(a.from_port ?? a.to_port), a.protocol); if(e) out.push(F(e.sev, 'Security-group rule open to 0.0.0.0/0 (' + e.what + ')', 'Ingress from the whole internet.', 'Restrict cidr_blocks to known ranges.', w, ln)); } return out; },
    aws_s3_bucket: (a, w, ln) => low(a.acl) === 'public-read' || low(a.acl) === 'public-read-write' ? [F('high', 'S3 bucket ACL is ' + a.acl, 'Bucket contents are public.', 'Set acl=private and add aws_s3_bucket_public_access_block.', w, ln)] : [],
    aws_s3_bucket_public_access_block: (a, w, ln) => { const out = []; ['block_public_acls', 'block_public_policy', 'ignore_public_acls', 'restrict_public_buckets'].forEach(k => { if(no(a[k])) out.push(F('medium', 'S3 public-access block disabled: ' + k, k + ' = false weakens public-access protection.', 'Set ' + k + ' = true.', w, ln)); }); return out; },
    aws_db_instance: (a, w, ln) => { const out = []; if(yes(a.publicly_accessible)) out.push(F('high', 'RDS instance publicly accessible', 'The database is reachable from the internet.', 'Set publicly_accessible = false; use a private subnet.', w, ln)); if(no(a.storage_encrypted)) out.push(F('medium', 'RDS storage not encrypted', 'storage_encrypted is false.', 'Set storage_encrypted = true.', w, ln)); return out; },
    aws_rds_cluster: (a, w, ln) => no(a.storage_encrypted) ? [F('medium', 'RDS cluster not encrypted', 'storage_encrypted is false.', 'Set storage_encrypted = true.', w, ln)] : [],
    aws_ebs_volume: (a, w, ln) => no(a.encrypted) ? [F('medium', 'EBS volume not encrypted', 'encrypted is false.', 'Set encrypted = true.', w, ln)] : [],
    aws_instance: (a, w, ln) => { const md = (a._metadata_options || [])[0]; return md && low(md.http_tokens) === 'optional' ? [F('high', 'EC2 instance allows IMDSv1', 'http_tokens=optional leaves the instance metadata service open to SSRF credential theft.', 'Set metadata_options.http_tokens = "required" (IMDSv2).', w, ln)] : []; },
    aws_iam_policy: (a, w, ln) => a.policy ? safeJSON(a.policy, d => CSRULES.awsPolicy(d, a.policy, w)) : [],
    aws_iam_role_policy: (a, w, ln) => a.policy ? safeJSON(a.policy, d => CSRULES.awsPolicy(d, a.policy, w)) : [],
    google_storage_bucket_iam_member: (a, w, ln) => /allusers|allauthenticatedusers/i.test(String(a.member)) ? [F('high', 'Public GCS bucket binding', 'member ' + a.member + ' makes the bucket public.', 'Grant to specific principals.', w, ln)] : [],
    google_compute_firewall: (a, w, ln) => isOpenCidr(a.source_ranges || a._source_ranges) ? [F('high', 'GCP firewall open to 0.0.0.0/0', 'Ingress from the whole internet.', 'Restrict source_ranges.', w, ln)] : [],
    google_sql_database_instance: (a, w, ln) => [],
    azurerm_network_security_rule: (a, w, ln) => { if(low(a.access) === 'allow' && low(a.direction) === 'inbound' && isOpenCidr(a.source_address_prefix)){ const e = portExposure(parseRange(a.destination_port_range), a.protocol); if(e) return [F(e.sev, 'NSG rule allows Internet inbound (' + e.what + ')', 'source_address_prefix is open.', 'Restrict source_address_prefix to known ranges.', w, ln)]; } return []; },
    azurerm_storage_account: (a, w, ln) => { const out = []; if(yes(a.allow_nested_items_to_be_public) || yes(a.allow_blob_public_access)) out.push(F('high', 'Storage account allows public blobs', 'Public blob access is enabled.', 'Set allow_nested_items_to_be_public = false.', w, ln)); if(no(a.enable_https_traffic_only) || no(a.https_traffic_only_enabled)) out.push(F('medium', 'Storage account allows plain HTTP', 'HTTPS-only is disabled.', 'Set https_traffic_only_enabled = true.', w, ln)); return out; }
  };
  function sgRules(a, w, ln){
    const out = []; (a._ingress || []).forEach(ing => { if(isOpenCidr(ing.cidr_blocks || ing._cidr_blocks || ing.cidr_blocks)){ const e = portExposure(parseRange(ing.from_port ?? ing.to_port), ing.protocol); if(e) out.push(F(e.sev, 'Security group open to 0.0.0.0/0 (' + e.what + ')', 'Ingress from the whole internet in ' + a.name + '.', 'Restrict cidr_blocks.', w, ln)); } });
    return out;
  }
  const safeJSON = (s, fn) => { try{ return fn(typeof s === 'string' ? JSON.parse(s) : s); }catch(e){ return []; } };

  function scanTerraformHCL(text){
    let out = []; const res = parseHCL(text);
    res.forEach(r => { const fn = TF[r.type]; const w = r.type + '.' + r.name; if(fn) out = out.concat(fn(r.attrs, w, r.line)); });
    return {out, count: res.length};
  }
  function scanTerraformJSON(doc, text){
    let out = []; let n = 0;
    const rv = doc.values && doc.values.root_module ? collectPlan(doc.values.root_module) : (doc.planned_values && doc.planned_values.root_module ? collectPlan(doc.planned_values.root_module) : (doc.resource_changes ? doc.resource_changes.map(c => ({type:c.type, name:c.name, values:(c.change && c.change.after) || {}})) : []));
    rv.forEach(r => { n++; const fn = TF[r.type]; const w = r.type + '.' + r.name; if(fn){ const flat = flattenTf(r.values); out = out.concat(fn(flat, w, 0)); } });
    return {out, count: n};
  }
  function collectPlan(mod){ let r = arr(mod.resources).map(x => ({type:x.type, name:x.name, values:x.values || {}})); arr(mod.child_modules).forEach(c => r = r.concat(collectPlan(c))); return r; }
  function flattenTf(v){ const a = Object.assign({}, v); for(const k in v){ if(Array.isArray(v[k]) && v[k].every(isObj)) a['_' + k] = v[k].map(flattenTf); } return a; }

  /* ---- CloudFormation / ARM (resources map or list) ---- */
  function scanCfn(doc, text){
    let out = []; const resources = doc.Resources || doc.resources; let n = 0;
    const each = (name, type, props) => {
      n++; const t = String(type || ''), w = name + ' (' + t + ')';
      if(/::EC2::SecurityGroup$/.test(t)){ arr(props.SecurityGroupIngress).forEach(ing => { if(isOpenCidr(ing.CidrIp) || isOpenCidr(ing.CidrIpv6)){ const e = portExposure(parseRange((ing.FromPort ?? ing.ToPort)), ing.IpProtocol); if(e) out.push(F(e.sev, 'Security group open to the internet (' + e.what + ')', 'Ingress CidrIp is open in ' + name + '.', 'Restrict CidrIp.', w, lineOf(text, name))); } }); }
      if(/::S3::Bucket$/.test(t)){ const acl = low(props.AccessControl); if(acl === 'publicread' || acl === 'publicreadwrite') out.push(F('high', 'S3 bucket is public (' + props.AccessControl + ')', 'Bucket contents are public.', 'Remove AccessControl; add a PublicAccessBlockConfiguration.', w, lineOf(text, name))); const pab = props.PublicAccessBlockConfiguration; if(pab && [pab.BlockPublicAcls, pab.BlockPublicPolicy, pab.IgnorePublicAcls, pab.RestrictPublicBuckets].some(v => v === false)) out.push(F('medium', 'S3 public-access block partly disabled', 'One of the public-access protections is false.', 'Set all four to true.', w, lineOf(text, name))); }
      if(/::RDS::DBInstance$/.test(t)){ if(props.PubliclyAccessible === true) out.push(F('high', 'RDS instance publicly accessible', 'The database is reachable from the internet.', 'Set PubliclyAccessible: false.', w, lineOf(text, name))); if(props.StorageEncrypted === false) out.push(F('medium', 'RDS storage not encrypted', 'StorageEncrypted is false.', 'Set StorageEncrypted: true.', w, lineOf(text, name))); }
      if(/::IAM::(Policy|Role|ManagedPolicy)$/.test(t)){ const d = props.PolicyDocument || (arr(props.Policies)[0] || {}).PolicyDocument; if(d) out = out.concat(CSRULES.awsPolicy(d, text, w)); }
    };
    if(isObj(resources)) for(const name in resources){ const r = resources[name] || {}; each(name, r.Type || r.type, r.Properties || r.properties || {}); }
    else if(Array.isArray(resources)) resources.forEach(r => each(r.name || r.type, r.type, r.properties || {}));
    return {out, count: n};
  }

  return {parseHCL, scanTerraformHCL, scanTerraformJSON, scanCfn, TF};
})();

/* ==========================================================================
   Kubernetes manifests (one or many docs), format detection, main dispatcher.
   ========================================================================== */
const CSK8S = (() => {
  const {arr, low, isObj, truthy} = CS; const {F} = CSRULES;
  const PODDERS = {Deployment:'spec.template.spec', StatefulSet:'spec.template.spec', DaemonSet:'spec.template.spec', ReplicaSet:'spec.template.spec', Job:'spec.template.spec', CronJob:'spec.jobTemplate.spec.template.spec', Pod:'spec', ReplicationController:'spec.template.spec'};
  const dig = (o, path) => path.split('.').reduce((c, k) => (c == null ? c : c[k]), o);

  function scanDoc(doc){
    if(!isObj(doc)) return []; const out = [], kind = doc.kind || '', name = (doc.metadata && doc.metadata.name) || '(unnamed)', w = kind + '/' + name;
    const podPath = PODDERS[kind];
    if(podPath){ const spec = dig(doc, podPath) || {}; const containers = arr(spec.containers).concat(arr(spec.initContainers));
      if(truthy(spec.hostNetwork)) out.push(F('high', 'hostNetwork: true', 'The pod shares the node network namespace.', 'Remove hostNetwork unless strictly required.', w));
      if(truthy(spec.hostPID)) out.push(F('high', 'hostPID: true', 'The pod can see all processes on the node.', 'Remove hostPID.', w));
      if(truthy(spec.hostIPC)) out.push(F('medium', 'hostIPC: true', 'The pod shares the node IPC namespace.', 'Remove hostIPC.', w));
      arr(spec.volumes).forEach(v => { if(v && v.hostPath) out.push(F(/^\/$|^\/etc|^\/var\/run\/docker|^\/root|^\/proc|^\/sys/.test(String(v.hostPath.path || '')) ? 'critical' : 'high', 'hostPath volume: ' + (v.hostPath.path || ''), 'Mounts a node path into the pod — a container-escape risk.', 'Use a dedicated PersistentVolume instead of hostPath.', w)); });
      const psc = spec.securityContext || {};
      containers.forEach(c => { if(!isObj(c)) return; const sc = c.securityContext || {}, cw = w + ' · ' + (c.name || 'container');
        if(truthy(sc.privileged)) out.push(F('critical', 'Privileged container: ' + (c.name || ''), 'A privileged container has full access to the host.', 'Set securityContext.privileged: false.', cw));
        if(sc.allowPrivilegeEscalation === true) out.push(F('medium', 'allowPrivilegeEscalation: true', 'Process can gain more privileges than its parent.', 'Set allowPrivilegeEscalation: false.', cw));
        const runAsNonRoot = sc.runAsNonRoot ?? psc.runAsNonRoot; const runAsUser = sc.runAsUser ?? psc.runAsUser;
        if(runAsNonRoot !== true && (runAsUser === 0 || runAsUser === undefined)) out.push(F('medium', 'Container may run as root: ' + (c.name || ''), 'runAsNonRoot is not set and no non-zero runAsUser given.', 'Set runAsNonRoot: true and a runAsUser ≥ 1000.', cw));
        if(sc.readOnlyRootFilesystem !== true) out.push(F('low', 'Writable root filesystem: ' + (c.name || ''), 'readOnlyRootFilesystem is not true.', 'Set readOnlyRootFilesystem: true.', cw));
        const caps = (sc.capabilities && arr(sc.capabilities.add).map(x => String(x).toUpperCase())) || [];
        if(caps.includes('ALL') || caps.includes('SYS_ADMIN') || caps.includes('NET_ADMIN') || caps.includes('SYS_PTRACE')) out.push(F('high', 'Dangerous Linux capability added: ' + caps.join(', '), 'Added capabilities widen the container’s power on the node.', 'Drop ALL and add back only what is needed.', cw));
        const img = String(c.image || ''); if(img && (/:latest$/.test(img) || !/[:@]/.test(img))) out.push(F('low', 'Unpinned image: ' + (img || c.name), 'Image uses :latest or no tag, so the running version can change.', 'Pin to an immutable tag or digest.', cw));
        if(!c.resources || !c.resources.limits) out.push(F('low', 'No resource limits: ' + (c.name || ''), 'Container has no CPU/memory limits.', 'Set resources.limits.', cw));
      });
    }
    if(kind === 'ClusterRoleBinding' || kind === 'RoleBinding'){ const roleRef = doc.roleRef || {}; if(low(roleRef.name) === 'cluster-admin') out.push(F('high', kind + ' to cluster-admin', (doc.metadata && doc.metadata.name) + ' binds subjects to cluster-admin.', 'Bind to a least-privilege Role instead of cluster-admin.', w)); }
    if(kind === 'ClusterRole' || kind === 'Role'){ arr(doc.rules).forEach(r => { const v = arr(r.verbs).map(low), res = arr(r.resources).map(low); if(v.includes('*') && res.includes('*')) out.push(F('high', kind + ' grants *,* ', (doc.metadata && doc.metadata.name) + ' allows all verbs on all resources.', 'List only the verbs and resources needed.', w)); if(res.includes('secrets') && (v.includes('*') || v.includes('get') || v.includes('list'))) out.push(F('medium', kind + ' can read Secrets', 'Grants get/list on secrets — can expose credentials.', 'Restrict to specific secret names where possible.', w)); }); }
    if(kind === 'Service' && doc.spec && low(doc.spec.type) === 'nodeport') out.push(F('low', 'Service of type NodePort', (doc.metadata && doc.metadata.name) + ' exposes a port on every node.', 'Prefer ClusterIP + Ingress, or LoadBalancer with restrictions.', w));
    return out;
  }
  function scanK8s(docs){ let out = [], n = 0; arr(docs).forEach(d => { if(isObj(d) && (d.kind || d.apiVersion)){ n++; out = out.concat(scanDoc(d)); } }); return {out, count: n}; }
  return {scanK8s, scanDoc};
})();

/* ---------------- format detection ---------------- */
function csDetect(text, filename){
  const t = text.trim(), fn = (filename || '').toLowerCase();
  if(/\.tf$/.test(fn) || /^\s*(resource|provider|variable|module|terraform)\s+"/m.test(t)) return 'tf';
  let doc = null, multi = null;
  try{ doc = JSON.parse(t); }catch(e){}
  if(doc == null && typeof jsyaml !== 'undefined'){ try{ multi = jsyaml.loadAll(t); if(multi && multi.length === 1) doc = multi[0]; }catch(e){} }
  const d = doc || (multi && multi[0]);
  const hasK8s = (x) => CS.isObj(x) && x.apiVersion && x.kind;
  if((multi && multi.some(hasK8s)) || hasK8s(d)) return 'k8s';
  if(CS.isObj(d)){
    if(d.format_version || d.terraform_version || d.planned_values || d.resource_changes || (d.values && d.values.root_module)) return 'tfjson';
    if(d.AWSTemplateFormatVersion || (d.Resources && CS.isObj(d.Resources))) return 'cfn';
    if(d.$schema && /deploymentTemplate|schema.management.azure/i.test(String(d.$schema)) || (d.resources && Array.isArray(d.resources) && d.$schema)) return 'arm';
    if(Array.isArray(d.Statement) || (d.Version && d.Statement)) return 'awsiam';
    if(Array.isArray(d.bindings)) return 'gcpiam';
    if(d.properties && Array.isArray(d.properties.permissions) || Array.isArray(d.permissions)) return 'azrole';
  }
  return 'unknown';
}

/* ---------------- main entry ---------------- */
function cloudScan(text, filename){
  const kind = csDetect(text, filename);
  const KINDS = {tf:'Terraform (HCL)', tfjson:'Terraform plan/state (JSON)', cfn:'CloudFormation', arm:'Azure ARM template', k8s:'Kubernetes manifest', awsiam:'AWS IAM / resource policy', gcpiam:'GCP IAM policy', azrole:'Azure role definition', unknown:'Unrecognised'};
  let findings = [], count = 0, parsed = true;
  const jget = () => { try{ return JSON.parse(text); }catch(e){ try{ return typeof jsyaml !== 'undefined' ? jsyaml.load(text) : null; }catch(e2){ parsed = false; return null; } } };
  const jall = () => { try{ return [JSON.parse(text)]; }catch(e){ try{ return typeof jsyaml !== 'undefined' ? jsyaml.loadAll(text).filter(x => x != null) : []; }catch(e2){ parsed = false; return []; } } };
  try{
    if(kind === 'tf'){ const r = CSIAC.scanTerraformHCL(text); findings = r.out; count = r.count; }
    else if(kind === 'tfjson'){ const d = jget(); const r = CSIAC.scanTerraformJSON(d || {}, text); findings = r.out; count = r.count; }
    else if(kind === 'cfn' || kind === 'arm'){ const d = jget(); const r = CSIAC.scanCfn(d || {}, text); findings = r.out; count = r.count; }
    else if(kind === 'k8s'){ const docs = jall(); const r = CSK8S.scanK8s(docs); findings = r.out; count = r.count; }
    else if(kind === 'awsiam'){ const d = jget(); findings = CSRULES.awsPolicy(d || {}, text, 'policy'); count = 1; }
    else if(kind === 'gcpiam'){ const d = jget(); findings = CSRULES.gcpPolicy(d || {}, text, 'bindings'); count = 1; }
    else if(kind === 'azrole'){ const d = jget(); findings = CSRULES.azureRole(d || {}, text, 'role'); count = 1; }
  }catch(e){ parsed = false; }
  /* inline secrets across any parsed object */
  if(kind !== 'tf' && kind !== 'unknown'){ try{ const d = jget(); const sec = []; if(d) CS.inlineSecrets(d, [], sec, 10); sec.forEach(s => findings.push(CSRULES.F('high', 'Hardcoded secret in a "' + s.key + '" field', 'A field named like a secret holds an inline value instead of a reference to a secrets manager.', 'Move it to AWS Secrets Manager / Azure Key Vault / GCP Secret Manager / a K8s Secret and reference it.', s.path))); }catch(e){} }
  findings.sort((a, b) => CS.sevRank(a) - CS.sevRank(b) || (a.where > b.where ? 1 : -1));
  const counts = {critical:0, high:0, medium:0, low:0, info:0}; findings.forEach(f => counts[f.sev] = (counts[f.sev] || 0) + 1);
  return {kind, kindLabel: KINDS[kind], parsed, resources: count, findings, counts};
}
if(typeof module !== 'undefined' && module.exports) module.exports = {cloudScan, csDetect, CS, CSRULES, CSIAC, CSK8S};
