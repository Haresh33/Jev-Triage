/**
 * Cloud, identity and SaaS events + domain routing.
 *
 * 1. `extractCloudEvents` finds audit events in any alert shape: AWS CloudTrail, Azure Activity, Entra ID
 *    audit/sign-in, Microsoft 365 unified audit, GCP audit, Okta System Log, Kubernetes audit.
 * 2. `analyzeCloud` turns known attacker actions into the same Behavior statements the endpoint analyser
 *    produces (MITRE ATT&CK technique + strength), so Jev, the guardrail and the ticket treat them alike.
 * 3. `detectDomains` decides which domain packs apply (windows, linux, macos, aws, azure, gcp, identity,
 *    kubernetes, email, network) so only relevant hypotheses and questions are asked.
 *
 * Pure code, no network.
 */

import type { Behavior, Strength } from "./behavior";

export type CloudProvider = "aws" | "azure" | "entra" | "m365" | "gcp" | "okta" | "kubernetes";
export type CloudEvent = {
  provider: CloudProvider;
  action: string; // eventName / operationName / activityDisplayName / Operation / methodName / eventType / verb+resource
  service?: string;
  principal?: string;
  sourceIp?: string;
  userAgent?: string;
  outcome?: string; // success / failure / error code
  mfa?: boolean;
  isSignIn: boolean;
  detail: string; // lower-cased compact JSON of the event, used by rules
};
export type Domain = "windows" | "linux" | "macos" | "aws" | "azure" | "gcp" | "identity" | "kubernetes" | "email" | "network" | "generic";

function isRecord(v: unknown): v is Record<string, unknown> { return typeof v === "object" && v !== null && !Array.isArray(v); }
function nk(k: string): string { return k.toLowerCase().replace(/[^a-z0-9]/g, ""); }
function lookup(obj: Record<string, unknown>, path: string): unknown {
  let cur: unknown = obj;
  for (const part of path.split(".")) {
    if (!isRecord(cur)) return undefined;
    const key = Object.keys(cur).find((k) => nk(k) === part);
    if (key === undefined) return undefined;
    cur = cur[key];
  }
  return cur;
}
function str(v: unknown): string | undefined {
  if (typeof v === "string" && v.trim()) return v.trim();
  if (typeof v === "number") return String(v);
  return undefined;
}
function first(obj: Record<string, unknown>, paths: string[]): string | undefined {
  for (const p of paths) { const v = str(lookup(obj, p)); if (v) return v; }
  return undefined;
}

function toEvent(obj: Record<string, unknown>): CloudEvent | null {
  const detail = JSON.stringify(obj).toLowerCase().slice(0, 6000);
  const eventSource = str(lookup(obj, "eventsource"));
  const eventName = str(lookup(obj, "eventname"));
  if (eventName && (eventSource?.endsWith("amazonaws.com") || lookup(obj, "useridentity") !== undefined || lookup(obj, "awsregion") !== undefined)) {
    const mfaRaw = str(lookup(obj, "additionaleventdata.mfaused")) ?? str(lookup(obj, "useridentity.sessioncontext.attributes.mfaauthenticated"));
    return { provider: "aws", action: eventName, service: eventSource, principal: first(obj, ["useridentity.arn", "useridentity.username", "useridentity.principalid", "useridentity.type"]),
      sourceIp: first(obj, ["sourceipaddress"]), userAgent: first(obj, ["useragent"]), outcome: first(obj, ["errorcode", "responseelements.consolelogin"]) ?? "success",
      mfa: mfaRaw === undefined ? undefined : /^(yes|true)$/i.test(mfaRaw), isSignIn: eventName === "ConsoleLogin", detail };
  }
  const gcpMethod = str(lookup(obj, "protopayload.methodname")) ?? (str(lookup(obj, "servicename"))?.endsWith("googleapis.com") ? str(lookup(obj, "methodname")) : undefined);
  if (gcpMethod) {
    return { provider: "gcp", action: gcpMethod, service: first(obj, ["protopayload.servicename", "servicename"]), principal: first(obj, ["protopayload.authenticationinfo.principalemail", "authenticationinfo.principalemail"]),
      sourceIp: first(obj, ["protopayload.requestmetadata.callerip", "requestmetadata.callerip"]), userAgent: first(obj, ["protopayload.requestmetadata.callersupplieduseragent"]),
      outcome: str(lookup(obj, "protopayload.status.code")) ?? "success", isSignIn: false, detail };
  }
  const oktaType = str(lookup(obj, "eventtype"));
  if (oktaType && /^[a-z_]+(\.[a-z_]+)+$/.test(oktaType) && (lookup(obj, "actor") !== undefined || lookup(obj, "displaymessage") !== undefined)) {
    return { provider: "okta", action: oktaType, principal: first(obj, ["actor.alternateid", "actor.displayname"]), sourceIp: first(obj, ["client.ipaddress"]), userAgent: first(obj, ["client.useragent.rawuseragent"]),
      outcome: first(obj, ["outcome.result"]), isSignIn: /^user\.session\.start|^user\.authentication/.test(oktaType), detail };
  }
  const verb = str(lookup(obj, "verb")); const k8sResource = str(lookup(obj, "objectref.resource"));
  if (verb && k8sResource) {
    const sub = str(lookup(obj, "objectref.subresource"));
    return { provider: "kubernetes", action: `${verb} ${k8sResource}${sub ? `/${sub}` : ""}`, principal: first(obj, ["user.username"]), sourceIp: first(obj, ["sourceips"]), userAgent: first(obj, ["useragent"]),
      outcome: first(obj, ["responsestatus.code"]), isSignIn: false, detail };
  }
  const m365Op = str(lookup(obj, "operation")); const workload = str(lookup(obj, "workload"));
  if (m365Op && (workload || lookup(obj, "recordtype") !== undefined || lookup(obj, "organizationid") !== undefined)) {
    return { provider: "m365", action: m365Op, service: workload, principal: first(obj, ["userid", "userkey"]), sourceIp: first(obj, ["clientip", "clientipaddress", "actoripaddress"]),
      outcome: first(obj, ["resultstatus"]), isSignIn: /^userlogged(in|failed)|^userloginfailed/i.test(m365Op), detail };
  }
  const azOp = str(lookup(obj, "operationname.value")) ?? str(lookup(obj, "operationname"));
  if (azOp && /^microsoft\./i.test(azOp)) {
    return { provider: "azure", action: azOp, service: first(obj, ["resourceprovidername.value", "resourceprovidername"]), principal: first(obj, ["caller", "identity.claims.name"]),
      sourceIp: first(obj, ["calleripaddress", "httprequest.clientipaddress"]), outcome: first(obj, ["status.value", "status", "resultType"]), isSignIn: false, detail };
  }
  const activity = str(lookup(obj, "activitydisplayname")) ?? (azOp && !/^microsoft\./i.test(azOp) && (lookup(obj, "targetresources") !== undefined || lookup(obj, "initiatedby") !== undefined) ? azOp : undefined);
  if (activity) {
    return { provider: "entra", action: activity, principal: first(obj, ["initiatedby.user.userprincipalname", "initiatedby.app.displayname", "properties.initiatedby.user.userprincipalname"]),
      sourceIp: first(obj, ["initiatedby.user.ipaddress"]), outcome: first(obj, ["result", "resultreason"]), isSignIn: false, detail };
  }
  const upn = str(lookup(obj, "userprincipalname")); const appName = str(lookup(obj, "appdisplayname")); const clientApp = str(lookup(obj, "clientappused"));
  if (upn && (appName || clientApp || lookup(obj, "conditionalaccessstatus") !== undefined)) {
    const err = str(lookup(obj, "status.errorcode"));
    return { provider: "entra", action: "Sign-in", service: appName, principal: upn, sourceIp: first(obj, ["ipaddress"]), userAgent: first(obj, ["useragent"]),
      outcome: err === undefined ? undefined : err === "0" ? "success" : `failure ${err}`, mfa: /mfa|multifactor/i.test(first(obj, ["authenticationrequirement"]) ?? "") ? true : undefined, isSignIn: true, detail };
  }
  return null;
}

/** All cloud/identity audit events in a JSON alert (single event, arrays, or wrappers such as {"Records": [...]}). */
export function extractCloudEvents(json: unknown, limit = 25): CloudEvent[] {
  const out: CloudEvent[] = [];
  const walk = (v: unknown, depth: number) => {
    if (out.length >= limit || depth > 6) return;
    if (Array.isArray(v)) { for (const x of v) walk(x, depth + 1); return; }
    if (!isRecord(v)) return;
    const ev = toEvent(v);
    if (ev) { out.push(ev); return; } // an event's own nested objects are part of it
    for (const x of Object.values(v)) if (typeof x === "object" && x !== null) walk(x, depth + 1);
  };
  walk(json, 0);
  return out;
}

type CloudRule = { id: string; providers: CloudProvider[]; action: RegExp; detail?: RegExp; notDetail?: RegExp; technique: string; strength: Strength; statement: (e: CloudEvent) => string; failedOk?: boolean };
const who = (e: CloudEvent) => e.principal ? ` by ${e.principal.slice(0, 120)}` : "";
const from = (e: CloudEvent) => e.sourceIp ? ` from ${e.sourceIp}` : "";

const CLOUD_RULES: CloudRule[] = [
  // ---- AWS
  { id: "aws_logging_off", providers: ["aws"], action: /^(StopLogging|DeleteTrail|UpdateTrail|PutEventSelectors|DeleteFlowLogs|DeleteConfigRule|StopConfigurationRecorder|DeleteDetector|DisassociateFromMasterAccount|UpdateDetector|DeleteMembers)$/,
    notDetail: /"enable":\s*true/, technique: "T1562.008 Disable or Modify Cloud Logs", strength: "strong",
    statement: (e) => `AWS audit logging or threat detection was stopped or changed (${e.action})${who(e)}${from(e)}.` },
  { id: "aws_admin_grant", providers: ["aws"], action: /^(AttachUserPolicy|AttachRolePolicy|AttachGroupPolicy|PutUserPolicy|PutRolePolicy|PutGroupPolicy|CreatePolicyVersion)$/,
    detail: /administratoraccess|"action":\s*"\*"|\\"action\\":\s*\\"\*\\"|iam:\*|"\*:\*"/, technique: "T1098 Account Manipulation (admin rights)", strength: "strong",
    statement: (e) => `Administrator-level permissions were granted (${e.action})${who(e)}${from(e)}.` },
  { id: "aws_new_credentials", providers: ["aws"], action: /^(CreateAccessKey|CreateLoginProfile|UpdateLoginProfile|CreateServiceSpecificCredential)$/, technique: "T1098.001 Additional Cloud Credentials", strength: "moderate",
    statement: (e) => `New long-lived credentials or a console password were created (${e.action})${who(e)}${from(e)}.` },
  { id: "aws_trust_change", providers: ["aws"], action: /^(UpdateAssumeRolePolicy|CreateRole)$/, detail: /arn:aws:iam::\d{12}:root|"principal":\s*\{\s*"aws":\s*"\*"|\\"aws\\":\s*\\"\*\\"/, technique: "T1098 Account Manipulation (role trust)", strength: "moderate",
    statement: (e) => `A role's trust policy was changed to allow another account to assume it (${e.action})${who(e)}.` },
  { id: "aws_share_external", providers: ["aws"], action: /^(ModifySnapshotAttribute|ModifyDBSnapshotAttribute|ModifyDBClusterSnapshotAttribute|ModifyImageAttribute|PutBucketPolicy|PutBucketAcl|PutObjectAcl|PutAccountPublicAccessBlock|DeletePublicAccessBlock|DeleteBucketPublicAccessBlock)$/,
    detail: /createvolumepermission|"add"|restore|allusers|"principal":\s*"\*"|\\"principal\\":\s*\\"\*\\"|public-read|"blockpublic[a-z]*":\s*false|deletepublicaccessblock/, technique: "T1537 Transfer Data to Cloud Account / T1530", strength: "strong",
    statement: (e) => `Data (snapshot, image or bucket) was shared outside the account or made public (${e.action})${who(e)}.` },
  { id: "aws_root_login", providers: ["aws"], action: /^ConsoleLogin$/, detail: /"type":\s*"root"/, technique: "T1078.004 Valid Accounts: Cloud (root)", strength: "moderate",
    statement: (e) => `The AWS root account signed in to the console${from(e)}${e.mfa === false ? " without MFA" : ""}.` },
  { id: "aws_login_no_mfa", providers: ["aws"], action: /^ConsoleLogin$/, detail: /"mfaused":\s*"no"/, notDetail: /"type":\s*"root"/, technique: "T1078.004 Valid Accounts: Cloud", strength: "weak",
    statement: (e) => `A console sign-in without MFA${who(e)}${from(e)}.` },
  { id: "aws_mfa_removed", providers: ["aws"], action: /^(DeactivateMFADevice|DeleteVirtualMFADevice)$/, technique: "T1556.006 Modify Authentication: MFA", strength: "moderate",
    statement: (e) => `An MFA device was removed (${e.action})${who(e)}.` },
  { id: "aws_destroy", providers: ["aws"], action: /^(ScheduleKeyDeletion|DisableKey|DeleteBucket|PutBucketLifecycle|PutBucketLifecycleConfiguration|DeleteDBCluster|DeleteDBInstance|DeleteBackupVault|DeleteRecoveryPoint|DeleteSnapshot)$/, technique: "T1485 Data Destruction / T1490", strength: "moderate",
    statement: (e) => `Keys, data or backups were deleted or scheduled for deletion (${e.action})${who(e)}.` },
  { id: "aws_leave_org", providers: ["aws"], action: /^(LeaveOrganization|DeleteOrganization)$/, technique: "T1562 Impair Defenses", strength: "strong",
    statement: (e) => `The account left or deleted its AWS Organization, which removes central controls (${e.action})${who(e)}.` },
  { id: "aws_secret_access", providers: ["aws"], action: /^(GetSecretValue|GetPasswordData|GetParametersByPath|BatchGetSecretValue)$/, technique: "T1552 Unsecured Credentials", strength: "weak",
    statement: (e) => `Secrets or instance passwords were read (${e.action})${who(e)}${from(e)}.` },
  { id: "aws_discovery", providers: ["aws"], action: /^(GetCallerIdentity|ListUsers|ListRoles|ListBuckets|DescribeInstances|ListAccessKeys|GetAccountAuthorizationDetails)$/, technique: "T1087.004/T1580 Cloud Discovery", strength: "weak",
    statement: (e) => `Cloud enumeration call (${e.action})${who(e)}${from(e)}.` },
  { id: "aws_compute_hijack", providers: ["aws"], action: /^RunInstances$/, detail: /"instancetype":\s*"(p[2-5]|g[3-6]|x1|x2|u-|inf|trn|dl)/, technique: "T1496 Resource Hijacking", strength: "moderate",
    statement: (e) => `GPU or very large compute instances were launched${who(e)}, a common crypto-mining pattern.` },
  // ---- Azure resource manager
  { id: "az_logging_off", providers: ["azure"], action: /microsoft\.insights\/(diagnosticsettings|logprofiles)\/delete|microsoft\.security\/.*\/(delete|write)$/i, notDetail: /"enabled":\s*true/, technique: "T1562.008 Disable or Modify Cloud Logs", strength: "strong",
    statement: (e) => `Azure diagnostic logging or Defender settings were deleted or changed (${e.action})${who(e)}.` },
  { id: "az_owner_grant", providers: ["azure"], action: /microsoft\.authorization\/roleassignments\/write/i, detail: /8e3af657-a8ff-443c-a75c-2fe8c4bcb635|owner|user access administrator|18d7d88d-d35e-4fb5-a5c3-7773c20a72d9/, technique: "T1098 Account Manipulation (Owner role)", strength: "strong",
    statement: (e) => `An Owner or User Access Administrator role was assigned${who(e)}.` },
  { id: "az_run_command", providers: ["azure"], action: /microsoft\.compute\/virtualmachines\/(runcommand\/action|extensions\/write)/i, technique: "T1651 Cloud Administration Command", strength: "moderate",
    statement: (e) => `A command or extension was run on a virtual machine through the Azure control plane (${e.action})${who(e)}.` },
  { id: "az_keys", providers: ["azure"], action: /microsoft\.storage\/storageaccounts\/listkeys\/action|microsoft\.keyvault\/vaults\/secrets\/.*read|microsoft\.web\/sites\/config\/list\/action/i, technique: "T1552 Unsecured Credentials", strength: "weak",
    statement: (e) => `Storage keys, Key Vault secrets or app settings were read (${e.action})${who(e)}.` },
  // ---- Entra ID (Azure AD)
  { id: "entra_priv_role", providers: ["entra"], action: /^add (eligible )?member to role/i, detail: /global administrator|privileged role administrator|privileged authentication administrator|application administrator|security administrator|exchange administrator/, technique: "T1098.003 Additional Cloud Roles", strength: "strong",
    statement: (e) => `A highly privileged Entra ID role was assigned (${e.action})${who(e)}.` },
  { id: "entra_consent", providers: ["entra"], action: /^consent to application/i, detail: /mail\.read|mail\.readwrite|mail\.send|files\.readwrite|full_access_as_app|directory\.readwrite|user\.readwrite\.all|offline_access/, technique: "T1528 Steal Application Access Token (consent phishing)", strength: "strong",
    statement: (e) => `Consent was granted to an application for mailbox, file or directory access${who(e)}, the pattern of consent phishing.` },
  { id: "entra_sp_creds", providers: ["entra"], action: /^(add service principal credentials|update application.*certificates and secrets|add (delegated )?permission grant|add app role assignment to service principal)/i, technique: "T1098.001 Additional Cloud Credentials", strength: "moderate",
    statement: (e) => `Credentials or permissions were added to an application or service principal (${e.action})${who(e)}.` },
  { id: "entra_federation", providers: ["entra"], action: /^(set domain authentication|set federation settings on domain|add unverified domain|verify domain)/i, technique: "T1484.002 Domain Trust Modification", strength: "strong",
    statement: (e) => `Domain federation or authentication settings were changed (${e.action})${who(e)}, which can let an attacker forge sign-ins.` },
  { id: "entra_mfa_change", providers: ["entra"], action: /^(user registered security info|user deleted security info|admin (registered|deleted) security info|disable strong authentication|reset password)/i, technique: "T1556.006 Modify Authentication: MFA", strength: "weak",
    statement: (e) => `MFA or password settings changed for an account (${e.action})${who(e)}.` },
  { id: "entra_ca_change", providers: ["entra"], action: /conditional access policy/i, detail: /delete|disabled|"state":\s*"disabled"|update/, technique: "T1556 Modify Authentication Process", strength: "moderate",
    statement: (e) => `A Conditional Access policy was changed or deleted (${e.action})${who(e)}.` },
  { id: "entra_legacy_auth", providers: ["entra"], action: /^Sign-in$/, detail: /"clientappused":\s*"(imap4?|pop3?|authenticated smtp|exchange activesync|other clients|mapi over http|exchange web services)"/, technique: "T1078.004 Valid Accounts (legacy authentication)", strength: "moderate",
    statement: (e) => `A sign-in used a legacy protocol that bypasses MFA${who(e)}${from(e)}.` },
  // ---- Microsoft 365 (Exchange / SharePoint)
  { id: "m365_inbox_rule", providers: ["m365"], action: /^(New-InboxRule|Set-InboxRule|UpdateInboxRules)$/i, detail: /forwardto|forwardasattachmentto|redirectto|deletemessage|softdeletemessage|permanentdelete|"rss|rss feeds|conversation history|"archive"|markasread[^}]*(invoice|payment|wire|bank|security|password|phish|hack|fraud)|(invoice|payment|wire|bank|security|password|phish|hack|fraud)[^}]*markasread/, technique: "T1564.008 Email Hiding Rules / T1114.003 Email Forwarding", strength: "strong",
    statement: (e) => `A mailbox rule that forwards, deletes or hides mail was created${who(e)}${from(e)}.` },
  { id: "m365_forwarding", providers: ["m365"], action: /^Set-Mailbox$/i, detail: /forwardingsmtpaddress|forwardingaddress|delivertomailboxandforward/, technique: "T1114.003 Email Forwarding Rule", strength: "strong",
    statement: (e) => `Mailbox forwarding to another address was set${who(e)}.` },
  { id: "m365_mailbox_perm", providers: ["m365"], action: /^(Add-MailboxPermission|Add-RecipientPermission|Add-MailboxFolderPermission)$/i, detail: /fullaccess|sendas|owner/, technique: "T1098.002 Additional Email Delegate Permissions", strength: "moderate",
    statement: (e) => `Full-access or send-as rights to a mailbox were granted${who(e)}.` },
  { id: "m365_mass_download", providers: ["m365"], action: /^(FileSyncDownloadedFull|FileDownloaded|MailItemsAccessed)$/i, technique: "T1530 Data from Cloud Storage / T1114.002", strength: "weak",
    statement: (e) => `Files or mail items were downloaded or accessed (${e.action})${who(e)}${from(e)}.` },
  // ---- GCP
  { id: "gcp_logging_off", providers: ["gcp"], action: /(DeleteSink|UpdateSink|DeleteLog|UpdateBucket)$/i, detail: /logging/, technique: "T1562.008 Disable or Modify Cloud Logs", strength: "strong",
    statement: (e) => `GCP log routing or storage was deleted or changed (${e.action})${who(e)}.` },
  { id: "gcp_owner_grant", providers: ["gcp"], action: /SetIamPolicy$/i, detail: /roles\/(owner|editor|iam\.securityadmin|resourcemanager\.organizationadmin|iam\.serviceaccounttokencreator)/, technique: "T1098 Account Manipulation (IAM)", strength: "strong",
    statement: (e) => `A powerful GCP role (owner, editor or IAM admin) was granted${who(e)}.` },
  { id: "gcp_sa_key", providers: ["gcp"], action: /CreateServiceAccountKey$/i, technique: "T1098.001 Additional Cloud Credentials", strength: "moderate",
    statement: (e) => `A new service-account key was created${who(e)}${from(e)}.` },
  // ---- Okta
  { id: "okta_impersonation", providers: ["okta"], action: /^user\.session\.impersonation\.(initiate|grant)$/, technique: "T1078 Valid Accounts (impersonation)", strength: "strong",
    statement: (e) => `An Okta session impersonation was started${who(e)}.` },
  { id: "okta_admin_grant", providers: ["okta"], action: /^(user\.account\.privilege\.grant|group\.privilege\.grant)$/, detail: /super|org_admin|app_admin/, technique: "T1098.003 Additional Cloud Roles", strength: "strong",
    statement: (e) => `An Okta administrator role was granted${who(e)}.` },
  { id: "okta_mfa_reset", providers: ["okta"], action: /^(user\.mfa\.factor\.(deactivate|reset_all)|user\.mfa\.factor\.update)$/, technique: "T1556.006 Modify Authentication: MFA", strength: "moderate",
    statement: (e) => `MFA factors were removed or reset (${e.action})${who(e)}.` },
  { id: "okta_policy_change", providers: ["okta"], action: /^(policy\.lifecycle\.(delete|deactivate|update)|policy\.rule\.(delete|deactivate|update)|system\.api_token\.create|zone\.(update|delete))$/, technique: "T1556 Modify Authentication Process", strength: "moderate",
    statement: (e) => `An Okta sign-on policy, network zone or API token was changed or created (${e.action})${who(e)}.` },
  { id: "okta_push_fatigue", providers: ["okta"], action: /^system\.push\.send_factor_verify_push$|^user\.mfa\.okta_verify\.deny_push$/, technique: "T1621 MFA Request Generation", strength: "weak",
    statement: (e) => `Okta Verify push prompts were sent or denied${who(e)} (repeated prompts suggest MFA fatigue).` },
  // ---- Kubernetes
  { id: "k8s_exec", providers: ["kubernetes"], action: /^(create|get) pods\/(exec|attach)$/, technique: "T1609 Container Administration Command", strength: "moderate",
    statement: (e) => `A shell or command was opened inside a pod (${e.action})${who(e)}.` },
  { id: "k8s_privileged", providers: ["kubernetes"], action: /^create (pods|deployments|daemonsets|jobs|cronjobs)$/, detail: /"privileged":\s*true|"hostpid":\s*true|"hostnetwork":\s*true|"hostpath":\s*\{\s*"path":\s*"\/"/, technique: "T1611 Escape to Host", strength: "strong",
    statement: (e) => `A privileged workload or one mounting the host's root filesystem was created${who(e)}.` },
  { id: "k8s_cluster_admin", providers: ["kubernetes"], action: /^create (clusterrolebindings|rolebindings)$/, detail: /cluster-admin/, technique: "T1098 Account Manipulation (cluster-admin)", strength: "strong",
    statement: (e) => `cluster-admin was bound to an identity${who(e)}.` },
  { id: "k8s_secrets", providers: ["kubernetes"], action: /^(list|get|watch) secrets$/, technique: "T1552.007 Container API", strength: "weak",
    statement: (e) => `Kubernetes secrets were read${who(e)}.` },
];

export function analyzeCloud(events: CloudEvent[]): Behavior[] {
  const out = new Map<string, Behavior>();
  for (const e of events) {
    const failed = !!e.outcome && /fail|denied|unauthori[sz]ed|accessdenied|error|forbidden/i.test(e.outcome) && !/^success/i.test(e.outcome);
    for (const r of CLOUD_RULES) {
      if (!r.providers.includes(e.provider) || !r.action.test(e.action)) continue;
      if (r.detail && !r.detail.test(e.detail)) continue;
      if (r.notDetail && r.notDetail.test(e.detail)) continue;
      if (out.has(r.id)) continue;
      const strength: Strength = failed && r.strength !== "weak" ? "weak" : r.strength; // attempted but refused: still worth knowing
      out.set(r.id, { id: r.id, technique: r.technique, strength, statement: r.statement(e) + (failed ? ` The call failed (${e.outcome}).` : ""),
        evidence: `${e.provider}: ${e.action}${e.principal ? ` | ${e.principal}` : ""}${e.sourceIp ? ` | ${e.sourceIp}` : ""}`.slice(0, 220) });
    }
  }
  return [...out.values()];
}

/** Which domain packs apply to this alert. */
export function detectDomains(text: string, cloud: CloudEvent[], f: { processes: string[]; commandlines: string[]; hasEmail: boolean; hasNetwork: boolean; hasLogin: boolean }): Domain[] {
  const d = new Set<Domain>();
  const procText = [...f.processes, ...f.commandlines].join("\n");
  if (/[a-z]:\\\\|[a-z]:\\|\.exe\b|\\windows\\|sysmon|winlog|microsoft-windows|powershell/i.test(procText + "\n" + text.slice(0, 20000))) d.add("windows");
  if (/(^|[\s"'=(])\/(usr|bin|sbin|etc|tmp|var|dev\/shm|home|root|opt|proc|lib)\//m.test(procText + "\n" + text) || /"(syscall|proctitle|auid|exe)":|auditd|\blinux\b|\bfalco\b|\bcrontab\b|\bsystemctl\b|\/dev\/tcp\/|\bapt(-get)?\s+install\b|\byum\s+install\b/i.test(text)) d.add("linux");
  if (/\/(Applications|Library|System\/Library|Users\/Shared)\/|\.app\/Contents|com\.apple\.|launchd|osascript|\bmacos\b|\bdarwin\b/i.test(procText + "\n" + text)) d.add("macos");
  for (const e of cloud) {
    if (e.provider === "aws") d.add("aws");
    if (e.provider === "azure") d.add("azure");
    if (e.provider === "gcp") d.add("gcp");
    if (e.provider === "kubernetes") d.add("kubernetes");
    if (e.provider === "entra" || e.provider === "okta" || e.provider === "m365" || e.isSignIn) d.add("identity");
  }
  if (f.hasLogin) d.add("identity");
  if (f.hasEmail) d.add("email");
  if (f.hasNetwork) d.add("network");
  // /Users/ paths only mean macOS when no Windows evidence exists
  if (d.has("macos") && d.has("linux")) {
    // Both use /usr, /tmp, /bin: keep the one with its own markers.
    if (!/\.app\/|com\.apple|osascript|launchd|darwin|macos|\/Library\/|\/Users\//i.test(procText + text)) d.delete("macos");
    else if (!/auditd|"syscall"|proctitle|\blinux\b|systemd|\/etc\/(shadow|passwd|cron)|\/proc\//i.test(procText + text)) d.delete("linux");
  }
  if (!d.size) d.add("generic");
  return [...d];
}
