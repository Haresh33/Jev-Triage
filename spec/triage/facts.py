"""Pull the investigable *facts* out of an alert: processes, email, sign-ins, network, accounts.

These decide which questions are worth asking Jev. Works on any JSON shape (by key names) and on
plain text (by "Key: value" lines and keywords), so Vision One, QRadar, Sentinel, email reports
and free text all work without per-product parsers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .ioc import refang

_KV_LINE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9 _./-]{1,40})\s*[:=]\s*(.+?)\s*$")


def _norm(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key.lower())


def _pairs(obj: Any, path: tuple[str, ...] = ()) -> list[tuple[tuple[str, ...], Any]]:
    out: list[tuple[tuple[str, ...], Any]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out += _pairs(v, path + (_norm(str(k)),))
    elif isinstance(obj, list):
        for v in obj:
            out += _pairs(v, path)
    elif obj is not None:
        out.append((path, obj))
    return out


def _text_pairs(text: str) -> list[tuple[tuple[str, ...], Any]]:
    pairs = []
    for line in text.splitlines():
        m = _KV_LINE.match(line)
        if m:
            pairs.append(((_norm(m.group(1)),), m.group(2)))
    return pairs


@dataclass
class Facts:
    commandlines: list[str] = field(default_factory=list)
    processes: list[str] = field(default_factory=list)
    parents: list[str] = field(default_factory=list)
    users: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    senders: list[str] = field(default_factory=list)
    subjects: list[str] = field(default_factory=list)
    attachments: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    countries: list[str] = field(default_factory=list)
    keywords: set[str] = field(default_factory=set)

    # ---- what kind of activity the alert is about (drives which questions apply)
    @property
    def has_process(self) -> bool:
        return bool(self.commandlines or self.processes)

    @property
    def has_email(self) -> bool:
        return bool(self.senders or self.subjects or self.attachments) or bool(self.keywords & {"phish", "email"})

    @property
    def has_login(self) -> bool:
        return bool(self.keywords & {"signin", "logon", "mfa", "authentication", "bruteforce", "impossibletravel"})

    @property
    def has_network(self) -> bool:
        return bool(self.ports) or bool(self.keywords & {"connection", "beacon", "dns", "exfil", "upload", "c2"})

    @property
    def has_attachment(self) -> bool:
        return bool(self.attachments)

    def for_jev(self) -> dict[str, Any]:
        d: dict[str, Any] = {}
        for name in ("commandlines", "processes", "parents", "users", "hosts", "senders", "subjects", "attachments", "countries"):
            v = getattr(self, name)
            if v:
                d[name] = v[:6]
        if self.ports:
            d["ports"] = self.ports[:10]
        return d


_KEYWORDS = {
    "signin": r"sign[\s-]?in|login|log[\s-]?in\b",
    "logon": r"\blogon\b|4624|4625",
    "mfa": r"\bmfa\b|multi[\s-]?factor|2fa|push notification",
    "authentication": r"authenticat",
    "bruteforce": r"brute|password spray|failed (sign|log)",
    "impossibletravel": r"impossible travel|atypical travel|unfamiliar (location|sign)",
    "phish": r"phish",
    "email": r"\bemail\b|\bmail\b|subject:|from:",
    "connection": r"connect|outbound|inbound",
    "beacon": r"beacon",
    "dns": r"\bdns\b",
    "exfil": r"exfil",
    "upload": r"upload|bytes[_ ]?out|sent[_ ]?bytes",
    "c2": r"\bc2\b|command[\s-]and[\s-]control|cobalt",
    "ransom": r"ransom|encrypt(ed|ion) files|vssadmin",
    "credential": r"lsass|mimikatz|credential|ntds|sam hive|sekurlsa",
}


def extract_facts(alert: dict | list | str) -> Facts:
    f = Facts()
    text = alert if isinstance(alert, str) else str(alert)
    pairs = _text_pairs(refang(text)) if isinstance(alert, str) else _pairs(alert)

    def add(lst: list, value: Any, limit: int = 400) -> None:
        v = str(value).strip()[:limit]
        if v and v not in lst:
            lst.append(v)

    for path, value in pairs:
        key = path[-1] if path else ""
        joined = ".".join(path)
        if isinstance(value, (int, float)) and "port" in key and 0 < int(value) < 65536:
            if int(value) not in f.ports:
                f.ports.append(int(value))
            continue
        if not isinstance(value, str):
            continue
        if "parent" in joined and ("cmd" in key or "command" in key or key in ("name", "image", "parent", "parentprocess", "parentimage", "parentname")):
            add(f.parents, value)
        elif "cmd" in key or "commandline" in key or key in ("command", "cmdline"):
            add(f.commandlines, value, 1000)
        elif key in ("image", "processname", "process", "exe", "executable") or (path[:-1] and "process" in path[-2] and key in ("name", "path", "image")):
            add(f.processes, value)
        elif key in ("sender", "from", "senderaddress", "mailfrom", "returnpath", "fromaddress"):
            add(f.senders, value)
        elif key in ("subject", "emailsubject"):
            add(f.subjects, value)
        elif "attachment" in key or key in ("filename",) and "mail" in joined:
            add(f.attachments, value)
        elif key in ("user", "username", "account", "accountname", "upn", "userprincipalname", "suser", "duser", "targetuser", "to", "recipient"):
            add(f.users, value)
        elif key in ("host", "hostname", "computer", "computername", "device", "devicename", "endpoint", "endpointname", "workstation"):
            add(f.hosts, value)
        elif key in ("country", "countrycode", "location", "geo", "srccountry", "city"):
            add(f.countries, value)
        elif "port" in key and value.isdigit() and 0 < int(value) < 65536 and int(value) not in f.ports:
            f.ports.append(int(value))

    low = text.lower()
    for name, rx in _KEYWORDS.items():
        if re.search(rx, low):
            f.keywords.add(name)
    # Free-text email reports: a "From:" line with an address counts as a sender.
    if not f.senders:
        m = re.search(r"^\s*from:\s*(.+)$", refang(text), re.I | re.M)
        if m and "@" in m.group(1):
            f.senders.append(m.group(1).strip()[:200])
    return f
