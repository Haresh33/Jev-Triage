"""The question library Jev draws from.

A question becomes *applicable* when the case state supports it: the alert has a command line,
an email, a sign-in; an indicator of the right type turned up; or an earlier answer opened it up
(`after=`). Each round the planner asks Jev every applicable question it has not asked yet, so the
questions change as the investigation learns things. Claude (optional) and analysts (/ask) can add
questions the library does not have.

Wording follows TypeSafe's guidance for Jev: one judgement per question, name the part of the
state the question is about (`alert`, `facts`, `indicator`, `findings`), and say what a yes and a
no look like wherever the line is subtle.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable, Literal

if TYPE_CHECKING:
    from .case import Case

Kind = Literal["yesno", "choice", "score"]


@dataclass(frozen=True)
class Question:
    qid: str
    kind: Kind
    text: str
    subject: str = "case"  # "case" or an indicator key "type:value"
    yes: str | None = None
    no: str | None = None
    options: dict[str, str] | None = None  # choice: label -> meaning; score: level name -> situation (ordered)
    origin: str = "playbook"
    why: str = ""


@dataclass(frozen=True)
class Template:
    id: str
    kind: Kind
    text: str
    yes: str | None = None
    no: str | None = None
    options: dict[str, str] | None = None
    when: Callable[["Case"], bool] = lambda c: True
    after: dict[str, frozenset[str]] = field(default_factory=dict)  # qid -> answers that open this question
    ioc_types: tuple[str, ...] = ()  # set -> asked once per indicator of these types
    reask: bool = False  # ask again when new lookup results arrive after it was answered

    def bind(self, subject: str = "case", why: str = "") -> Question:
        qid = self.id if subject == "case" else f"{self.id}@{subject}"
        origin = "indicator" if self.ioc_types else ("follow-up" if self.after else "playbook")
        return Question(qid, self.kind, self.text, subject, self.yes, self.no, self.options, origin, why)


Y = frozenset({"yes"})
YU = frozenset({"yes", "unclear"})
N = frozenset({"no"})


def _cmd(c: "Case") -> bool:
    return c.facts.has_process


def _mail(c: "Case") -> bool:
    return c.facts.has_email


def _login(c: "Case") -> bool:
    return c.facts.has_login


def _net(c: "Case") -> bool:
    return c.facts.has_network or any(i.type in ("ip", "domain") for i in c.iocs())


def _any_bad_ioc(c: "Case") -> bool:
    return any((c.ioc_p(k) or 0) >= 0.6 for k in c.evidence)


# ============================================================================ per indicator
INDICATOR = [
    Template("ioc_malicious", "yesno",
             "Is `indicator` malicious: malware, a phishing page, command-and-control, or other infrastructure run by an attacker?",
             ioc_types=("sha256", "sha1", "md5", "url", "domain", "ip"), reask=True),
    Template("file_legit_vendor", "yesno",
             "Is `indicator` a legitimate, widely used program from a known software vendor?",
             yes="Signed by a known vendor, clean with vendors, seen widely for a long time.",
             no="Unsigned, rare, recently first seen, or flagged by vendors.",
             ioc_types=("sha256", "sha1", "md5")),
    Template("dom_lookalike", "yesno",
             "Does `indicator` imitate a well-known brand or service in its name (misspellings, swapped characters, or added words such as secure, login, verify, update)?",
             yes="The name is built to be mistaken for a real brand or service.",
             no="The name is the brand's real domain, or does not resemble any brand.",
             ioc_types=("domain",)),
    Template("dom_disposable_infra", "yesno",
             "Do the `signals` show `indicator` is freshly set up infrastructure: registered in the last few weeks, not resolving, or with no reputation history?",
             ioc_types=("domain",)),
    Template("url_credential_page", "yesno",
             "Does `indicator` lead to a sign-in, password-reset, or payment page?",
             yes="The URL path or page title points at entering credentials or payment details.",
             no="Nothing in the URL or page title suggests entering credentials or payment details.",
             ioc_types=("url",)),
    Template("url_payload", "yesno",
             "Does `indicator` point straight at a downloadable file or script (for example .exe, .dll, .ps1, .hta, .zip, .iso)?",
             ioc_types=("url",)),
    Template("ip_anonymiser", "yesno",
             "Is `indicator` a Tor exit node, VPN, open proxy, or bulletproof hosting address?",
             ioc_types=("ip",)),
    Template("ip_big_provider", "yesno",
             "Is `indicator` owned by a major cloud, CDN, or internet company (Microsoft, Google, Amazon, Cloudflare, Akamai and similar)?",
             ioc_types=("ip",)),
]

# ============================================================================ case level
CASE = [
    # --- execution
    Template("proc_lolbin", "yesno",
             "Do the `commandlines` in `facts` use a built-in Windows tool (PowerShell, cmd, rundll32, regsvr32, mshta, wscript, cscript, certutil, bitsadmin, wmic) to run or load code?",
             when=_cmd),
    Template("proc_encoded", "yesno",
             "Is a command line in `facts` obfuscated or encoded (base64, -EncodedCommand, character escaping, string splitting) so that what it does is hidden?",
             when=_cmd),
    Template("proc_download", "yesno",
             "Does a command line in `facts` download content from the internet or run code from a remote address?",
             when=_cmd),
    Template("proc_office_parent", "yesno",
             "Was the process in `alert` started by an Office application, a PDF reader, a browser, or an email client?",
             when=lambda c: c.facts.has_process and bool(c.facts.parents)),
    Template("proc_user_writable_path", "yesno",
             "Does the process in `alert` run from a user-writable or temporary folder (AppData, Temp, Downloads, Users\\Public, ProgramData)?",
             when=_cmd),
    Template("proc_credential_theft", "yesno",
             "Does `alert` show credentials being dumped, read, or stolen (LSASS access, mimikatz, copying SAM, SYSTEM or NTDS.dit, browser password stores)?",
             when=lambda c: c.facts.has_process or "credential" in c.facts.keywords),
    Template("proc_persistence", "yesno",
             "Does `alert` show persistence being created (scheduled task, new service, Run key, startup folder item, WMI subscription)?",
             when=_cmd),
    Template("proc_defense_evasion", "yesno",
             "Does `alert` show security tools, logging, or backups being disabled, deleted, or tampered with?",
             when=_cmd),
    Template("proc_remote_exec", "yesno",
             "Does `alert` show code being run on another internal machine (PsExec, WMI, WinRM, remote services, remote scheduled tasks)?",
             when=_cmd),
    # follow-ups opened by earlier answers
    Template("proc_second_stage", "yesno",
             "Do the `indicators` show the downloaded content is a script or executable that would run next?",
             when=_cmd, after={"proc_download": YU}),
    Template("proc_macro_chain", "yesno",
             "Does `alert` fit a document-to-script chain: an Office document or email attachment launching a script host or a built-in tool that then reaches the internet?",
             after={"proc_office_parent": Y}),
    Template("proc_admin_authorised", "yesno",
             "Does `alert` or `analyst_notes` contain evidence the command was authorised administration (change ticket, maintenance window, a service account used for this job, a known admin tool path)?",
             yes="There is a concrete sign of authorisation in the text.",
             no="Nothing in the text shows the activity was planned or authorised.",
             when=_cmd),
    Template("proc_lateral_spread", "yesno",
             "Do `alert` or `findings` show the same activity reaching more than one host?",
             after={"proc_remote_exec": Y}),
    # --- email
    Template("mail_impersonation", "yesno",
             "Does the sender in `facts` pretend to be a well-known brand, an internal department (IT, HR, payroll, finance), or an executive?",
             when=_mail),
    Template("mail_pressure", "yesno",
             "Does the message in `alert` push urgency or a threat (account expiring, payment overdue, legal action, deadline today)?",
             when=_mail),
    Template("mail_credential_lure", "yesno",
             "Does the message in `alert` ask the reader to sign in, reset a password, or confirm account or payment details?",
             when=_mail),
    Template("mail_risky_attachment", "yesno",
             "Is an attachment in `facts` an executable, script, macro-enabled document, archive, or disk image?",
             when=lambda c: c.facts.has_attachment),
    Template("mail_user_interacted", "yesno",
             "Does `alert` or `analyst_notes` say the recipient clicked the link, opened the attachment, or entered details?",
             when=_mail),
    Template("mail_post_click_compromise", "yesno",
             "After the user interacted, does `alert` show a sign-in, process, or connection suggesting the account or device was compromised?",
             after={"mail_user_interacted": Y}),
    Template("mail_sender_domain_new", "yesno",
             "Do the `indicators` show the sender's domain is newly registered, a look-alike, or unrelated to the brand it claims to be?",
             after={"mail_impersonation": YU}),
    # --- identity / sign-in
    Template("login_impossible_travel", "yesno",
             "Does `alert` show sign-ins from places too far apart for one person to travel between in the time given?",
             when=_login),
    Template("login_password_guessing", "yesno",
             "Does `alert` show many failed sign-ins (password guessing or spraying) before a success?",
             when=_login),
    Template("login_mfa_abuse", "yesno",
             "Does `alert` show repeated MFA prompts, an unexpected MFA approval, or MFA being bypassed?",
             when=_login),
    Template("login_unfamiliar", "yesno",
             "Is the sign-in in `alert` from a country, device, or network the user does not normally use, according to `alert` or `analyst_notes`?",
             when=_login),
    Template("login_anonymous_source", "yesno",
             "Do the `indicators` show the sign-in came from Tor, a VPN, a proxy, or hosting infrastructure rather than a home or office network?",
             when=_login, after={"login_unfamiliar": YU}),
    Template("login_post_access", "yesno",
             "After the sign-in, does `alert` show mailbox rules, data downloads, MFA method changes, or new app consents?",
             after={"login_impossible_travel": Y}),
    # --- network
    Template("net_beaconing", "yesno",
             "Does `alert` show regular, repeated connections to the same outside destination (beaconing)?",
             when=_net),
    Template("net_odd_port", "yesno",
             "Does the connection in `alert` use a port or protocol that is unusual for its destination?",
             when=lambda c: bool(c.facts.ports)),
    Template("net_large_outbound", "yesno",
             "Does `alert` show a large amount of data leaving the network, or data sent to file-sharing or paste sites?",
             when=_net),
    Template("net_c2_confirmed", "yesno",
             "Do the `indicators` show an internal host talking to infrastructure judged malicious?",
             when=_net, reask=True),
    # --- context that can clear an alert
    Template("ctx_security_test", "yesno",
             "Does `alert` or `analyst_notes` show this is a security test, red-team exercise, EICAR/test file, or detection-rule check?",
             yes="The text names a test, exercise, test file, or simulation.",
             no="Nothing in the text says this is a test."),
    Template("ctx_known_admin", "yesno",
             "Is the account in `facts` a service, admin, or automation account doing its expected job?",
             when=lambda c: bool(c.facts.users)),
    # --- once something looks bad: how far did it get
    Template("impact_stage", "choice",
             "How far has the activity in `alert` progressed?",
             options={
                 "blocked": "It was attempted but blocked or quarantined before running.",
                 "delivered": "It reached the user or host but there is no sign it ran.",
                 "executed": "Malicious code ran or the user entered details, with no sign of further access.",
                 "established": "The attacker has ongoing access: persistence, a live C2 channel, or a signed-in session.",
                 "spreading": "It has moved to other hosts or accounts, or data is leaving.",
             },
             when=_any_bad_ioc, reask=True),
    Template("impact_contain", "choice",
             "What does `alert` show needs containing first?",
             options={
                 "host": "A device is compromised.",
                 "account": "A user or service account is compromised.",
                 "both": "Both a device and an account are compromised.",
                 "nothing": "Nothing is compromised yet; blocking the indicators is enough.",
             },
             when=_any_bad_ioc, reask=True),
]

LIBRARY = {t.id: t for t in INDICATOR + CASE}

# ============================================================================ asked every round
VERDICT = [
    Question("verdict_malicious", "yesno",
             "Is the activity described in `alert` malicious, meaning carried out by or for an attacker, rather than benign, authorised, or test activity?",
             origin="verdict"),
    Question("verdict_attacker_active", "yesno",
             "Do `alert`, `findings` or `indicators` show that an attacker currently has access to, or control of, the host or account in `alert`?",
             origin="verdict"),
    Question("verdict_category", "choice", "Which kind of activity does `alert` describe?", origin="verdict", options={
        "malware_execution": "Malicious code ran on, or was dropped onto, a host.",
        "phishing": "A lure email, message, link, or attachment aimed at a user.",
        "command_and_control": "A host is communicating with infrastructure an attacker controls.",
        "credential_access": "Stealing, dumping, guessing, or brute-forcing passwords, tokens, or keys.",
        "account_compromise": "Someone other than the owner is signed in to an account.",
        "lateral_movement": "Moving from one internal host or account to another.",
        "exfiltration": "Data is leaving the organisation for an outside destination.",
        "reconnaissance": "Scanning or probing to map hosts, services, or accounts.",
        "policy_violation": "Unwanted but not attacker-driven: risky software, misuse, or a misconfiguration.",
        "benign_activity": "Expected administration, software updates, security tooling, or a test.",
    }),
    Question("verdict_severity", "score", "How urgently does this alert need a response?", origin="verdict", options={
        "informational": "Nothing needs doing: the activity is expected or harmless.",
        "low": "Worth a look during business hours; nothing appears compromised.",
        "high": "Something was likely compromised or seriously attempted and needs an analyst today.",
        "critical": "An attacker is likely active right now, or data is leaving; respond immediately.",
    }),
]


def analyst_question(text: str, n: int) -> Question:
    """`/ask Is the user in finance?` -> yes/no.   `/ask Which stage? [blocked | executed | spreading]` -> pick-one."""
    text = text.strip()
    if text.endswith("]") and "[" in text:
        q, _, opts = text[:-1].rpartition("[")
        options = [o.strip() for o in opts.split("|") if o.strip()]
        if 2 <= len(options) <= 20:
            return Question(f"analyst_{n}", "choice", q.strip(), options={o: o for o in options}, origin="analyst",
                            why="asked by an analyst")
    return Question(f"analyst_{n}", "yesno", text, origin="analyst", why="asked by an analyst")
