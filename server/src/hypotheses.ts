/**
 * Hypothesis catalogue: the explanations a senior analyst would weigh, written in advance so Jev can
 * score them and answer their tests in milliseconds, with no language model in the live path.
 *
 * Each hypothesis:
 *   - applies to one or more domains (windows, linux, macos, aws, azure, gcp, identity, kubernetes, email,
 *     network, or "any"),
 *   - has a one-line meaning Jev uses when it picks the best explanation,
 *   - has tests: questions whose answer supports or undermines it, with {slots} filled from the alert.
 *     A test whose slot is not in the alert is skipped, so questions stay specific to what's there.
 *
 * Every round Jev scores the candidates (one pick-one question with a probability per hypothesis), then
 * answers the tests of the leading explanations plus the best benign one ("what's the innocent
 * explanation?"), then scores again. Add hypotheses or tests here as you meet new cases; each is data.
 */

import type { Domain } from "./cloud";

export type HypothesisTest = { id: string; text: string; supports: boolean };
export type Hypothesis = {
  id: string;
  title: string;
  kind: "benign" | "malicious";
  technique?: string;
  domains: Array<Domain | "any" | "endpoint">;
  meaning: string;
  tests: HypothesisTest[];
};
export type Slots = Partial<Record<"process" | "parent" | "user" | "host" | "cmd" | "file" | "api" | "principal" | "provider" | "src_ip" | "sender" | "dst", string>>;

const t = (id: string, text: string, supports = true): HypothesisTest => ({ id, text, supports });

export const HYPOTHESES: Hypothesis[] = [
  // ------------------------------------------------------------------ benign explanations (any domain)
  { id: "b_admin", title: "Planned administration", kind: "benign", domains: ["any"],
    meaning: "An administrator, IT tool or service account doing expected, authorised maintenance.",
    tests: [t("b_admin_1", "Is {user} an administrator, IT staff member or service account according to the alert or analyst notes?"),
      t("b_admin_2", "Do the alert or analyst notes name a change ticket, maintenance window or deployment tool for this activity?"),
      t("b_admin_3", "Does the activity match a routine administrative task (patching, inventory, backup, user management) rather than something unusual?")] },
  { id: "b_software", title: "Software install, update or developer build", kind: "benign", domains: ["endpoint", "any"],
    meaning: "A legitimate installer, auto-updater or developer build doing its normal job.",
    tests: [t("b_soft_1", "Is {process} a known vendor's installer, updater or build tool?"),
      t("b_soft_2", "Is the file {file} written by its own vendor's updater or inside a build output folder of a project?"),
      t("b_soft_3", "Do the indicators show the files involved are signed by a known software vendor?")] },
  { id: "b_security_tool", title: "Security tooling or authorised test", kind: "benign", domains: ["any"],
    meaning: "Security software, a vulnerability scanner, a red-team/pentest, or a detection test produced the activity.",
    tests: [t("b_sec_1", "Do the alert or analyst notes name security software, a scanner, a pentest, a red-team exercise or a test file (EICAR, Atomic Red Team)?")] },
  { id: "b_user_normal", title: "Ordinary user activity", kind: "benign", domains: ["any"],
    meaning: "The user doing something normal for their role that the detection over-matched.",
    tests: [t("b_user_1", "Does the evidence show {user} doing something ordinary for an employee (opening a document, browsing, syncing files, signing in from their usual place)?")] },
  { id: "b_detection_misfire", title: "Detection misfire", kind: "benign", domains: ["any"],
    meaning: "The alert's own data contradicts what the detection claims: nothing ran, it was blocked, or the match is wrong.",
    tests: [t("b_fp_1", "Does the alert's own data show the activity was blocked, failed, or never actually executed?"),
      t("b_fp_2", "Does the alert match on something harmless, such as a file name or keyword appearing in normal content?")] },
  // ------------------------------------------------------------------ endpoint (Windows, Linux, macOS)
  { id: "m_initial_exec", title: "User ran a malicious file or link", kind: "malicious", technique: "T1204 User Execution / T1566 Phishing", domains: ["endpoint", "email"],
    meaning: "Initial access: a document, attachment, download or link the user opened started attacker code.",
    tests: [t("m_ie_1", "Was {process} started by an Office application, PDF reader, browser or email client ({parent})?"),
      t("m_ie_2", "Is the program or file that ran located in Downloads, Temp, an email attachment folder or a mounted disk image?"),
      t("m_ie_3", "Does the command line fetch or run content from the internet?")] },
  { id: "m_c2", title: "Malware talking to its operator (C2)", kind: "malicious", technique: "T1071 Application Layer Protocol", domains: ["endpoint", "network"],
    meaning: "An implant or remote-access tool is communicating with attacker infrastructure.",
    tests: [t("m_c2_1", "Does a destination in the evidence ({dst}) have a malicious, newly registered or anonymising reputation in the indicators?"),
      t("m_c2_2", "Does the evidence show repeated connections to the same outside destination at regular intervals?"),
      t("m_c2_3", "Is the connecting program ({process}) one that would not normally talk to the internet?")] },
  { id: "m_cred_theft", title: "Credential theft", kind: "malicious", technique: "T1003 OS Credential Dumping / T1555", domains: ["endpoint"],
    meaning: "Passwords, hashes, tokens or keys are being dumped or stolen from the machine.",
    tests: [t("m_cred_1", "Does the evidence show access to LSASS, SAM, NTDS, /etc/shadow, the macOS keychain, browser password stores or cloud credential files?")] },
  { id: "m_persistence", title: "Persistence being set up", kind: "malicious", technique: "T1543/T1053/T1547 Persistence", domains: ["endpoint"],
    meaning: "The attacker is making sure their code survives reboot or logout.",
    tests: [t("m_per_1", "Does the evidence show a service, scheduled task, cron job, systemd unit, LaunchAgent, Run key or SSH key being added?"),
      t("m_per_2", "Does the persistence point at a program in a temporary, hidden or user-writable folder?")] },
  { id: "m_lateral", title: "Lateral movement", kind: "malicious", technique: "T1021 Remote Services / T1047 WMI", domains: ["endpoint"],
    meaning: "The attacker is moving from this machine or account to others.",
    tests: [t("m_lat_1", "Does the evidence show {process} or {user} running commands on, or connecting to, another internal host (PsExec, WMI, WinRM, SSH, RDP)?")] },
  { id: "m_evasion", title: "Hiding tracks or disabling defences", kind: "malicious", technique: "T1562 Impair Defenses / T1070 Indicator Removal", domains: ["endpoint", "aws", "azure", "gcp"],
    meaning: "Logs, security tools or history are being cleared or disabled, or files disguised as system files.",
    tests: [t("m_ev_1", "Does the evidence show logs, command history or audit settings being cleared or disabled?"),
      t("m_ev_2", "Does the evidence show a security agent, firewall, antivirus or monitoring being stopped or excluded?")] },
  { id: "m_exfil", title: "Data theft (exfiltration)", kind: "malicious", technique: "T1041/T1567 Exfiltration", domains: ["any"],
    meaning: "Data is being collected and sent to an outside destination.",
    tests: [t("m_exf_1", "Does the evidence show a large amount of data sent out, or data copied to cloud storage, file-sharing or paste sites?"),
      t("m_exf_2", "Does the evidence show files being archived or compressed before a transfer?")] },
  { id: "m_ransomware", title: "Ransomware preparation or encryption", kind: "malicious", technique: "T1486 Data Encrypted for Impact / T1490", domains: ["endpoint", "aws", "azure", "gcp"],
    meaning: "Backups are being destroyed or files encrypted for extortion.",
    tests: [t("m_ran_1", "Does the evidence show shadow copies, backups, snapshots or recovery settings being deleted or disabled?"),
      t("m_ran_2", "Does the evidence show many files being renamed, rewritten or encrypted, or a ransom note being created?")] },
  { id: "m_miner", title: "Crypto-mining", kind: "malicious", technique: "T1496 Resource Hijacking", domains: ["endpoint", "aws", "azure", "gcp", "kubernetes"],
    meaning: "Compute is being hijacked to mine cryptocurrency.",
    tests: [t("m_min_1", "Does the evidence show a mining program, a mining-pool address (stratum), or GPU/large compute being started for no business reason?")] },
  { id: "m_sideload", title: "DLL side-loading", kind: "malicious", technique: "T1574.002 DLL Side-Loading", domains: ["windows"],
    meaning: "A malicious DLL with a system library's name is placed next to a signed program so the program loads it.",
    tests: [t("m_sl_1", "Is a DLL with a Windows system library name ({file}) written or loaded outside the Windows system folders, next to a signed program?"),
      t("m_sl_2", "Is that DLL unsigned, packed (high entropy) or unknown to the indicators?")] },
  { id: "m_masquerade", title: "Program disguised as a system component", kind: "malicious", technique: "T1036 Masquerading", domains: ["endpoint"],
    meaning: "A file or process named like a trusted system component, placed where that component never lives.",
    tests: [t("m_mas_1", "Is a file or process named like a system component ({file}) running from, or created in, a folder where that component does not normally live?"),
      t("m_mas_2", "Is that file unsigned or unknown to the indicators?")] },
  { id: "m_webshell", title: "Web shell or exploited server", kind: "malicious", technique: "T1505.003 Web Shell / T1190", domains: ["windows", "linux"],
    meaning: "A web server or database process was exploited and is running attacker commands.",
    tests: [t("m_ws_1", "Did a web server or database process ({parent}) start a shell or scripting tool?"),
      t("m_ws_2", "Do the commands look like reconnaissance run by a remote attacker (whoami, id, uname, ipconfig, net user)?")] },
  { id: "m_lolbin_proxy", title: "Trusted tool abused to run code (LOLBin)", kind: "malicious", technique: "T1218 System Binary Proxy Execution", domains: ["windows", "macos", "linux"],
    meaning: "A built-in, signed tool is used to download, decode or run attacker code.",
    tests: [t("m_lol_1", "Does the command line of {process} download, decode or run code in a way its normal purpose does not require?"),
      t("m_lol_2", "Is the tool's usage here something an administrator would plausibly do?", false)] },
  { id: "m_linux_shell", title: "Remote shell on a Linux server", kind: "malicious", technique: "T1059.004 Unix Shell", domains: ["linux"],
    meaning: "An exploited service or stolen SSH access is giving an attacker an interactive shell.",
    tests: [t("m_ls_1", "Does a command line open a network shell (bash to /dev/tcp, nc -e, python socket, socat exec)?"),
      t("m_ls_2", "Was the shell started by a network-facing service ({parent}) rather than a logged-in administrator?"),
      t("m_ls_3", "Did a script get downloaded and piped straight into a shell?")] },
  { id: "m_linux_privesc", title: "Privilege escalation on Linux", kind: "malicious", technique: "T1548 Abuse Elevation Control", domains: ["linux"],
    meaning: "The attacker is trying to become root: sudo abuse, setuid binaries, sudoers edits or kernel modules.",
    tests: [t("m_lp_1", "Does the evidence show setuid files being created, sudoers or passwd being edited, or a kernel module loaded from an unusual folder?")] },
  { id: "m_mac_stealer", title: "macOS info-stealer", kind: "malicious", technique: "T1555.001 Keychain / T1056.002 GUI Input Capture", domains: ["macos"],
    meaning: "A downloaded macOS app or script is phishing the user's password and stealing keychain, browser or wallet data.",
    tests: [t("m_mac_1", "Does an osascript dialog ask for the user's password, or does a process read the keychain, browser profiles or crypto wallets?"),
      t("m_mac_2", "Did the program come from a disk image, /tmp or /Users/Shared, or had its quarantine flag removed?")] },
  // ------------------------------------------------------------------ cloud control plane
  { id: "m_cloud_stolen_creds", title: "Stolen cloud credentials in use", kind: "malicious", technique: "T1078.004 Valid Accounts: Cloud", domains: ["aws", "azure", "gcp", "kubernetes"],
    meaning: "Someone other than the owner is using an access key, token or role to call cloud APIs.",
    tests: [t("m_csc_1", "Did {principal} call {api} from an IP address, network or user agent that the evidence marks as unusual, anonymising or hosting?"),
      t("m_csc_2", "Did the call succeed without MFA, or with long-lived access keys?"),
      t("m_csc_3", "Do the alert or analyst notes say {principal} normally performs {api}?", false)] },
  { id: "m_cloud_priv", title: "Cloud privilege escalation", kind: "malicious", technique: "T1098 Account Manipulation", domains: ["aws", "azure", "gcp", "kubernetes"],
    meaning: "An identity is granting itself or another identity administrator-level rights.",
    tests: [t("m_cpr_1", "Did {principal} grant administrator, owner or cluster-admin rights to itself or another identity?"),
      t("m_cpr_2", "Was the new permission given to an identity created or modified shortly before, in the same evidence?")] },
  { id: "m_cloud_persist", title: "Cloud backdoor (new credentials or trust)", kind: "malicious", technique: "T1098.001 Additional Cloud Credentials", domains: ["aws", "azure", "gcp", "identity"],
    meaning: "New access keys, service-principal secrets, federation trusts or login profiles are created so access survives a password reset.",
    tests: [t("m_cpe_1", "Were new access keys, secrets, certificates, login profiles or federation trusts created for an identity?"),
      t("m_cpe_2", "Was the change made by an identity other than the one it benefits?")] },
  { id: "m_cloud_exfil", title: "Cloud data exposure or theft", kind: "malicious", technique: "T1537/T1530 Cloud Data", domains: ["aws", "azure", "gcp", "identity"],
    meaning: "Snapshots, buckets, storage or mail data are shared outside the organisation, made public, or bulk-downloaded.",
    tests: [t("m_cex_1", "Was a snapshot, image, bucket, storage account or database shared with an outside account or made public?"),
      t("m_cex_2", "Were large numbers of files, objects or mail items downloaded or accessed?")] },
  { id: "m_cloud_destroy", title: "Cloud destruction", kind: "malicious", technique: "T1485 Data Destruction", domains: ["aws", "azure", "gcp"],
    meaning: "Resources, keys, backups or buckets are deleted or scheduled for deletion.",
    tests: [t("m_cde_1", "Were keys, backups, snapshots, buckets or databases deleted or scheduled for deletion?")] },
  { id: "b_cloud_automation", title: "Cloud automation doing its job", kind: "benign", domains: ["aws", "azure", "gcp", "kubernetes"],
    meaning: "An infrastructure-as-code pipeline, CI/CD role or automation account making a planned change.",
    tests: [t("b_ca_1", "Is {principal} an automation, CI/CD or infrastructure-as-code identity (Terraform, CloudFormation, pipelines) according to the evidence?"),
      t("b_ca_2", "Does the user agent show an automation tool such as Terraform, an SDK used by a pipeline, or a cloud console used by an administrator?")] },
  // ------------------------------------------------------------------ identity and SaaS
  { id: "m_account_takeover", title: "Account takeover", kind: "malicious", technique: "T1078 Valid Accounts", domains: ["identity"],
    meaning: "An attacker signed in as the user with a stolen password, token or session.",
    tests: [t("m_ato_1", "Did {user} sign in from an unfamiliar country, anonymising network, hosting provider or impossible-travel location?"),
      t("m_ato_2", "Was MFA bypassed, fatigue-approved, newly registered, or avoided with a legacy protocol around the sign-in?"),
      t("m_ato_3", "Did the account do something new right after the sign-in (mailbox rules, downloads, consents, MFA changes)?")] },
  { id: "m_mailbox_abuse", title: "Mailbox rule or forwarding abuse", kind: "malicious", technique: "T1114.003 / T1564.008", domains: ["identity", "email"],
    meaning: "Mail is forwarded out or hidden from the user, typical of business-email compromise.",
    tests: [t("m_mb_1", "Was an inbox rule or forwarding created that forwards, deletes, moves or marks mail as read?"),
      t("m_mb_2", "Does the rule target words like invoice, payment, wire, bank or security?")] },
  { id: "m_oauth_consent", title: "Consent phishing (malicious app)", kind: "malicious", technique: "T1528 Steal Application Access Token", domains: ["identity"],
    meaning: "A user or admin granted an attacker's application access to mail, files or the directory.",
    tests: [t("m_oc_1", "Was consent granted to an application asking for mail, file or directory access?"),
      t("m_oc_2", "Is the application unverified, recently created, or named to look like a trusted brand?")] },
  { id: "m_priv_identity", title: "Identity admin takeover", kind: "malicious", technique: "T1098.003 Additional Cloud Roles", domains: ["identity"],
    meaning: "A directory administrator role, federation setting or sign-in policy was changed to give an attacker control.",
    tests: [t("m_pi_1", "Was a global, privileged-role or application administrator role assigned, or domain federation changed?"),
      t("m_pi_2", "Was a Conditional Access, sign-on or MFA policy weakened or removed?")] },
  { id: "b_travel", title: "Legitimate travel or VPN", kind: "benign", domains: ["identity"],
    meaning: "The user really is travelling, or connects through the corporate VPN or a known mobile network.",
    tests: [t("b_tr_1", "Do the alert or analyst notes say {user} is travelling or using the corporate VPN?"),
      t("b_tr_2", "Did the sign-in pass MFA on the user's registered device?")] },
  // ------------------------------------------------------------------ containers
  { id: "m_container_escape", title: "Container escape or cluster takeover", kind: "malicious", technique: "T1611 Escape to Host / T1609", domains: ["kubernetes", "linux"],
    meaning: "An attacker runs privileged containers, mounts the host, or execs into pods to reach the node or cluster.",
    tests: [t("m_ce_1", "Was a privileged container, host mount or host namespace used, or a shell opened inside a pod?"),
      t("m_ce_2", "Was cluster-admin or a secrets-reading role granted to a service account or user?")] },
  // ------------------------------------------------------------------ email
  { id: "m_phish", title: "Phishing email", kind: "malicious", technique: "T1566 Phishing", domains: ["email"],
    meaning: "An email impersonates someone to steal credentials, money or deliver malware.",
    tests: [t("m_ph_1", "Does the sender ({sender}) impersonate a brand, colleague, executive or internal department?"),
      t("m_ph_2", "Does the message ask for credentials, payment, gift cards or opening an attachment urgently?"),
      t("m_ph_3", "Do the links or attachments point to newly registered, look-alike or malicious destinations in the indicators?")] },
  { id: "b_bulk_mail", title: "Legitimate bulk or vendor email", kind: "benign", domains: ["email"],
    meaning: "Marketing, a newsletter or a real vendor notification that looks unusual but is genuine.",
    tests: [t("b_bm_1", "Is the sender ({sender}) a real, established organisation's own domain rather than a look-alike?"),
      t("b_bm_2", "Is the message informational with no request for credentials, payment or urgent action?")] },
  // ------------------------------------------------------------------ network
  { id: "m_scan", title: "Scanning or probing", kind: "malicious", technique: "T1046 Network Service Discovery", domains: ["network"],
    meaning: "One source is probing many hosts or ports to map the network or find a way in.",
    tests: [t("m_sc_1", "Does the evidence show one source contacting many hosts or many ports in a short time?")] },
  { id: "b_cdn", title: "Normal traffic to a big provider", kind: "benign", domains: ["network"],
    meaning: "Traffic to a major cloud, CDN, update or SaaS service that the detection over-matched.",
    tests: [t("b_cdn_1", "Is the destination ({dst}) owned by a major cloud, CDN, software-update or SaaS provider according to the indicators?")] },
];

function applies(h: Hypothesis, domains: Domain[]): boolean {
  if (h.domains.includes("any")) return true;
  const endpoint = domains.some((d) => d === "windows" || d === "linux" || d === "macos");
  return h.domains.some((d) => (d === "endpoint" ? endpoint : domains.includes(d as Domain)));
}

export function candidateHypotheses(domains: Domain[]): Hypothesis[] {
  const onlyGeneric = domains.length === 1 && domains[0] === "generic";
  return HYPOTHESES.filter((h) => onlyGeneric ? h.domains.includes("any") || h.domains.includes("endpoint") : applies(h, domains));
}

/** Fill {slots}; returns null when a slot the test needs is not in the alert (so the test is skipped). */
export function fillTest(text: string, slots: Slots): string | null {
  let missing = false;
  const out = text.replace(/\{([a-z_]+)\}/g, (_, key: keyof Slots) => {
    const v = slots[key];
    if (!v) { missing = true; return ""; }
    return v.length > 120 ? `${v.slice(0, 117)}…` : v;
  });
  return missing ? null : out;
}

/**
 * Which tests to ask this round: the leading two malicious explanations and the leading benign one
 * (a senior always asks "what's the innocent explanation?"), skipping tests already answered.
 */
export function selectTests(ranked: Array<{ h: Hypothesis; p: number }>, asked: Set<string>, slots: Slots, max = 12): Array<{ h: Hypothesis; test: HypothesisTest; text: string }> {
  const malicious = ranked.filter((r) => r.h.kind === "malicious").slice(0, 2);
  const benign = ranked.filter((r) => r.h.kind === "benign").slice(0, 1);
  const out: Array<{ h: Hypothesis; test: HypothesisTest; text: string }> = [];
  for (const { h } of [...malicious, ...benign]) {
    for (const test of h.tests) {
      if (asked.has(test.id) || out.length >= max) continue;
      const text = fillTest(test.text, slots);
      if (text) out.push({ h, test, text });
    }
  }
  return out;
}
