/* ==========================================================================
   Cloud audit-log hunting — defensive triage of CloudTrail, Azure Activity and
   GCP Audit logs. Parses the three formats into one row shape, flags notable
   events, and can hand rows to the case timeline (via the existing log importer).
   Everything runs in the page; nothing is fetched. No DOM here.
   ========================================================================== */
const CL = (() => {
  const arr = v => v == null ? [] : Array.isArray(v) ? v : [v];
  const low = v => String(v == null ? '' : v).toLowerCase();
  const get = (o, ...ks) => { for(const k of ks){ let c = o, ok = true; for(const p of k.split('.')){ if(c == null){ ok = false; break; } c = c[p]; } if(ok && c !== undefined && c !== null && c !== '') return c; } return undefined; };

  /* ---- notable-event rules: match on the normalised event name, return {sev, why} ---- */
  const RULES = [
    [/CreateAccessKey|CreateLoginProfile|UpdateLoginProfile|CreateUser$/i, 'high', 'New credential or user created — watch for persistence'],
    [/CreatePolicyVersion|SetDefaultPolicyVersion|PutUserPolicy|PutRolePolicy|AttachUserPolicy|AttachRolePolicy|PutGroupPolicy|AddUserToGroup|UpdateAssumeRolePolicy/i, 'high', 'IAM permissions changed — possible privilege escalation'],
    [/PassRole|AssumeRole$/i, 'medium', 'Role assumed / passed — track where the access went'],
    [/StopLogging|DeleteTrail|UpdateTrail|DeleteFlowLogs|PutEventSelectors/i, 'critical', 'Logging tampered with — defence evasion'],
    [/DeleteDetector|DisableSecurityHub|DeleteConfigRule|StopConfigurationRecorder|DisableMacie|DeleteMembers/i, 'high', 'Security service disabled'],
    [/DeleteBucketPolicy|PutBucketPolicy|PutBucketAcl|PutBucketPublicAccessBlock|DeletePublicAccessBlock|PutAccountPublicAccessBlock/i, 'high', 'Bucket exposure setting changed'],
    [/AuthorizeSecurityGroupIngress|ModifySecurityGroupRules|RevokeSecurityGroupIngress/i, 'medium', 'Network exposure changed'],
    [/ConsoleLogin/i, 'info', 'Console sign-in'],
    [/GetSecretValue|BatchGetSecretValue|Decrypt$|GetParameter|GetParameters/i, 'medium', 'Secret or key material accessed'],
    [/CreateKeyPair|ImportKeyPair|ModifyImageAttribute|ModifySnapshotAttribute|SharedSnapshot|CreateSnapshot/i, 'medium', 'Resource shared / image or snapshot touched — possible exfiltration'],
    [/RunInstances|CreateFunction|CreateInstance|Create.*VirtualMachine/i, 'low', 'Compute created'],
    [/Delete(Bucket|DBInstance|Function|Cluster|Volume|Stack)/i, 'medium', 'Resource deleted'],
    // Azure / GCP operation names
    [/Microsoft\.Authorization\/roleAssignments\/write|roles\.(create|update)|setIamPolicy/i, 'high', 'Role / IAM assignment changed'],
    [/Microsoft\.KeyVault.*(secrets|keys).*(read|get)|SecretGet|accessPolicies\/write/i, 'medium', 'Key Vault access'],
    [/Microsoft\.Security.*delete|securityContacts\/write/i, 'high', 'Security setting changed'],
    [/compute\.instances\.(insert|setMetadata)|storage\.buckets\.(setIamPolicy|update)/i, 'medium', 'GCP compute/storage change']
  ];
  function classify(name){ for(const [re, sev, why] of RULES) if(re.test(name)) return {sev, why}; return null; }

  /* ---- CloudTrail: {Records:[...]} or one event per line (JSON lines) ---- */
  function fromCloudTrail(recs){
    return arr(recs).map(e => {
      const id = get(e, 'userIdentity.arn', 'userIdentity.userName', 'userIdentity.principalId', 'userIdentity.type') || '';
      return {
        time: get(e, 'eventTime') || '', name: get(e, 'eventName') || '', service: (get(e, 'eventSource') || '').replace(/\.amazonaws\.com$/, ''),
        actor: String(id).split('/').pop() || String(id), src_ip: get(e, 'sourceIPAddress') || '', region: get(e, 'awsRegion') || '',
        user_agent: get(e, 'userAgent') || '', error: get(e, 'errorCode') || '', mfa: String(get(e, 'additionalEventData.MFAUsed') || get(e, 'userIdentity.sessionContext.attributes.mfaAuthenticated') || ''),
        request: shorten(get(e, 'requestParameters')), provider: 'aws'
      };
    });
  }
  /* ---- Azure Activity log ---- */
  function fromAzure(recs){
    return arr(recs).map(e => ({
      time: get(e, 'time', 'eventTimestamp', 'submissionTimestamp') || '',
      name: get(e, 'operationName.value', 'operationName') || '', service: get(e, 'resourceProvider.value', 'resourceProviderName.value', 'category.value') || '',
      actor: get(e, 'identity.claims.name', 'caller', 'identity.authorization.evidence.principalId') || '', src_ip: get(e, 'callerIpAddress', 'httpRequest.clientIpAddress') || '',
      region: get(e, 'location') || '', error: get(e, 'resultType') === 'Success' ? '' : (get(e, 'resultType') || ''),
      status: get(e, 'status.value', 'resultType') || '', resource: get(e, 'resourceId') || '', provider: 'azure'
    }));
  }
  /* ---- GCP audit log ---- */
  function fromGCP(recs){
    return arr(recs).map(e => { const pl = get(e, 'protoPayload') || e;
      return {
        time: get(e, 'timestamp', 'receiveTimestamp') || '', name: get(pl, 'methodName') || '', service: get(pl, 'serviceName') || '',
        actor: get(pl, 'authenticationInfo.principalEmail') || '', src_ip: get(pl, 'requestMetadata.callerIp') || '',
        region: get(e, 'resource.labels.location', 'resource.labels.zone') || '', error: get(pl, 'status.message') || '',
        resource: get(pl, 'resourceName') || '', provider: 'gcp'
      };
    });
  }
  const shorten = o => { if(o == null) return ''; try{ const s = JSON.stringify(o); return s.length > 140 ? s.slice(0, 140) + '…' : s; }catch(e){ return ''; } };

  function detect(text){
    const t = text.trim();
    let doc = null; try{ doc = JSON.parse(t); }catch(e){}
    if(doc){ if(doc.Records && Array.isArray(doc.Records)) return {fmt:'cloudtrail', recs:doc.Records};
      if(Array.isArray(doc)){ const s = doc[0] || {}; if(s.eventSource || s.eventName) return {fmt:'cloudtrail', recs:doc}; if(s.operationName || s.resourceProvider) return {fmt:'azure', recs:doc}; if(s.protoPayload || (s.logName && s.resource)) return {fmt:'gcp', recs:doc}; }
      if(doc.eventSource || doc.eventName) return {fmt:'cloudtrail', recs:[doc]};
      if(doc.protoPayload) return {fmt:'gcp', recs:[doc]};
      if(doc.operationName) return {fmt:'azure', recs:[doc]};
      if(doc.records && Array.isArray(doc.records)) return {fmt:'azure', recs:doc.records};
    }
    // JSON lines
    const lines = t.split('\n').map(l => l.trim()).filter(Boolean), objs = [];
    for(const l of lines){ try{ objs.push(JSON.parse(l)); }catch(e){} }
    if(objs.length){ const s = objs[0]; if(s.eventName || s.eventSource) return {fmt:'cloudtrail', recs:objs}; if(s.protoPayload) return {fmt:'gcp', recs:objs}; if(s.operationName) return {fmt:'azure', recs:objs}; }
    return {fmt:'unknown', recs:[]};
  }

  function parse(text){
    const d = detect(text), FMT = {cloudtrail:'AWS CloudTrail', azure:'Azure Activity log', gcp:'GCP Audit log', unknown:'Unrecognised'};
    let rows = d.fmt === 'cloudtrail' ? fromCloudTrail(d.recs) : d.fmt === 'azure' ? fromAzure(d.recs) : d.fmt === 'gcp' ? fromGCP(d.recs) : [];
    rows.forEach(r => { const c = classify(r.name); if(c){ r.sev = c.sev; r.why = c.why; } });
    rows.sort((a, b) => (a.time < b.time ? -1 : a.time > b.time ? 1 : 0));
    const flagged = rows.filter(r => r.sev && r.sev !== 'info');
    const counts = {critical:0, high:0, medium:0, low:0, info:0}; rows.forEach(r => { if(r.sev) counts[r.sev]++; });
    const actors = tally(rows, 'actor'), ips = tally(rows, 'src_ip'), errs = rows.filter(r => r.error).length;
    return {fmt:d.fmt, fmtLabel:FMT[d.fmt], rows, flagged, counts, total:rows.length, errors:errs, topActors:actors.slice(0, 6), topIps:ips.slice(0, 6)};
  }
  function tally(rows, k){ const m = new Map(); rows.forEach(r => { const v = r[k]; if(v) m.set(v, (m.get(v) || 0) + 1); }); return [...m.entries()].sort((a, b) => b[1] - a[1]).map(([v, n]) => ({v, n})); }

  return {parse, detect, classify, fromCloudTrail, fromAzure, fromGCP};
})();
if(typeof module !== 'undefined' && module.exports) module.exports = CL;
