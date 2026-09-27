"""Turn a pasted or JSON alert into a clean, de-duplicated list of indicators."""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Literal
from urllib.parse import urlsplit

IocType = Literal["sha256", "sha1", "md5", "url", "domain", "ip"]
TYPE_PRIORITY = {"sha256": 0, "sha1": 1, "md5": 2, "url": 3, "domain": 4, "ip": 5}


@dataclass(frozen=True)
class Ioc:
    value: str
    type: IocType
    origin: str = "alert"  # "alert", or "pivot:<parent>" for ones found while investigating

    @property
    def key(self) -> str:
        return f"{self.type}:{self.value}"


_REFANG = [
    (re.compile(r"hxxp", re.I), "http"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.I), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[/\]"), "/"),
    (re.compile(r"\[@\]|\[at\]", re.I), "@"),
]

_URL_RE = re.compile(r"\bhttps?://[^\s\"'<>\\^`{|}]+", re.I)
_IPV4_RE = re.compile(
    r"(?<!\d)(?<!\d\.)(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}(?!\d|\.\d)"
)
_HASH_RES: list[tuple[IocType, re.Pattern[str]]] = [
    ("sha256", re.compile(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", re.I)),
    ("sha1", re.compile(r"(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])", re.I)),
    ("md5", re.compile(r"(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])", re.I)),
]
_DOMAIN_RE = re.compile(
    r"(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,22}[a-z](?![\w-])", re.I
)

# Endings that look like TLDs but, in alert text, are nearly always file names or internal names.
# (.zip, .mov, .sh and a few others are real TLDs; they are still caught when they appear in a URL
#  or in a field whose name says it holds a domain.)
_FILE_EXTS = set(
    "exe dll sys drv ocx cpl scr msi msp lnk ps1 psm1 psd1 bat cmd vbs vbe js jse wsf wsh hta "
    "jar class py pyc sh bash pl rb php asp aspx jsp html htm xml json yml yaml ini cfg conf config "
    "log txt csv tsv dat db sqlite bak tmp temp old evtx etl pf reg key pem crt cer pfx p12 der "
    "zip rar 7z gz tgz tar bz2 xz cab iso img vhd vhdx dmg pkg deb rpm apk ipa "
    "doc docx docm dot xls xlsx xlsm xlsb ppt pptx pptm pdf rtf odt one msg eml "
    "png jpg jpeg gif bmp ico svg webp mp3 mp4 mov avi wav "
    "local lan internal intranet corp home localdomain localhost arpa invalid test example "
    "mui manifest lock pid sock md rst".split()
)
# Official IANA list (triage/tlds.txt); refresh with:
#   curl -s https://data.iana.org/TLD/tlds-alpha-by-domain.txt -o triage/tlds.txt
_TLDS = {
    line.strip().lower()
    for line in (Path(__file__).with_name("tlds.txt")).read_text().splitlines()
    if line.strip() and not line.startswith("#")
}
_ID_KEY_RE = re.compile(r"(^|[_.\-\s])(id|uuid|guid|session|trace|span|correlation|event_?id|nonce)s?$", re.I)
_DOMAIN_KEY_RE = re.compile(r"domain|host(name)?$|fqdn|dns|query|sni|url", re.I)


def refang(text: str) -> str:
    for pattern, repl in _REFANG:
        text = pattern.sub(repl, text)
    return text


def parse_alert(raw: str | bytes | dict | list) -> dict | list | str:
    """Accept a dict/list, a JSON string, or free text. Returns JSON when it parses, else the text."""
    if isinstance(raw, (dict, list)):
        return raw
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    stripped = raw.strip()
    if stripped[:1] in "{[":
        try:
            return json.loads(stripped)
        except json.JSONDecodeError:
            pass
    return stripped


def _walk(obj: Any, path: str = "") -> Iterator[tuple[str, str]]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk(v, f"{path}.{k}" if path else str(k))
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk(v, path)
    elif isinstance(obj, str):
        yield path, obj


def _last_key(path: str) -> str:
    return path.rsplit(".", 1)[-1] if path else ""


def is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def _clean_url(url: str) -> str:
    return url.rstrip(".,;:)]}'\"")


def _valid_domain(d: str, *, trusted_field: bool) -> bool:
    d = d.lower().rstrip(".")
    labels = d.split(".")
    if len(labels) < 2 or len(d) > 253:
        return False
    tld = labels[-1]
    if tld not in _TLDS and not tld.startswith("xn--"):
        return False  # "j.alvarez", "m.chen", "host.corp"... not a real top-level domain
    if tld in _FILE_EXTS and not trusted_field:
        return False
    return True


def _allowlisted(domain: str, allowlist: tuple[str, ...]) -> bool:
    domain = domain.lower().rstrip(".")
    return any(domain == a or domain.endswith("." + a) for a in allowlist)


@dataclass
class Extraction:
    iocs: list[Ioc]
    internal_ips: list[str]
    skipped: list[str]  # allowlisted / truncated, for the report


def extract(alert: dict | list | str, *, allowlist: tuple[str, ...] = (), limit: int = 25) -> Extraction:
    found: dict[str, Ioc] = {}
    internal: dict[str, None] = {}
    skipped: dict[str, None] = {}

    def add(value: str, typ: IocType) -> None:
        ioc = Ioc(value, typ)
        found.setdefault(ioc.key, ioc)

    def add_host(host: str, trusted: bool) -> None:
        host = host.lower().strip("[]").rstrip(".")
        if not host:
            return
        try:
            ipaddress.ip_address(host)
            (add(host, "ip") if is_public_ip(host) else internal.setdefault(host, None))
            return
        except ValueError:
            pass
        if not _valid_domain(host, trusted_field=trusted):
            return
        if _allowlisted(host, allowlist):
            skipped[f"{host} (allowlisted)"] = None
            return
        add(host, "domain")

    pairs = list(_walk(alert)) if not isinstance(alert, str) else [("", alert)]
    for path, text in pairs:
        key = _last_key(path)
        text = refang(text)
        id_field = bool(key and _ID_KEY_RE.search(key))
        domain_field = bool(key and _DOMAIN_KEY_RE.search(key))

        # URLs first; blank them out so their hosts/paths are not re-read as bare domains.
        for m in _URL_RE.finditer(text):
            url = _clean_url(m.group(0))
            host = urlsplit(url).hostname or ""
            if host and _allowlisted(host, allowlist):
                skipped[f"{url} (allowlisted host)"] = None
                continue
            add(url, "url")
            add_host(host, trusted=True)
        rest = _URL_RE.sub(" ", text)

        if not id_field:
            for typ, rx in _HASH_RES:
                for m in rx.finditer(rest):
                    h = m.group(0).lower()
                    if len(set(h)) > 4:  # skip 000..0 / ffff..f placeholders
                        add(h, typ)
                rest = rx.sub(" ", rest)

        for m in _IPV4_RE.finditer(rest):
            ip = m.group(0)
            (add(ip, "ip") if is_public_ip(ip) else internal.setdefault(ip, None))
        rest = _IPV4_RE.sub(" ", rest)

        for m in _DOMAIN_RE.finditer(rest):
            candidate = m.group(0)
            # "user@evil.com" -> keep the domain; Windows paths "C:\x\y.dll" never match.
            add_host(candidate, trusted=domain_field)

    iocs = sorted(found.values(), key=lambda i: TYPE_PRIORITY[i.type])
    if len(iocs) > limit:
        for extra in iocs[limit:]:
            skipped[f"{extra.value} (over MAX_IOCS)"] = None
        iocs = iocs[:limit]
    return Extraction(iocs=iocs, internal_ips=list(internal), skipped=list(skipped))


def alert_for_model(alert: dict | list | str, max_chars: int = 16000) -> dict | list | str:
    """The alert as it goes to Jev/Claude: refanged, and cut to stay well inside Jev's 32k-token window."""
    text = alert if isinstance(alert, str) else json.dumps(alert, ensure_ascii=False, default=str)
    if len(text) <= max_chars:
        return alert
    return text[:max_chars] + " …[truncated]"


def alert_title(alert: dict | list | str) -> str:
    if isinstance(alert, dict):
        for k in ("title", "name", "rule_name", "ruleName", "alert_name", "model", "description", "summary"):
            v = alert.get(k)
            if isinstance(v, str) and v.strip():
                return v.strip()[:200]
    if isinstance(alert, str):
        return alert.strip().splitlines()[0][:200] if alert.strip() else "Alert"
    return "Alert"


def alert_id(alert: dict | list | str) -> str | None:
    if isinstance(alert, dict):
        for k in ("id", "alert_id", "alertId", "workbenchId", "offense_id", "incident_id", "uuid"):
            if alert.get(k) is not None:
                return str(alert[k])
    return None
