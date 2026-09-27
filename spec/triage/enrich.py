"""Hosted, no-deploy enrichment.

Every source is a public HTTPS API. Keyless ones (DNS-over-HTTPS, RDAP, Shodan InternetDB) always
run; the rest run when their free key is set. Each lookup is turned into short, literal *signals*
("34 of 72 engines flag it malicious", "registered 3 days ago") computed here in Python, because
Jev reads numbers and dates as text and should be asked about conclusions, not arithmetic.
"""

from __future__ import annotations

import asyncio
import base64
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import httpx

from .config import Settings
from .ioc import Ioc, is_public_ip

UA = {"User-Agent": "jev-triage/1.0 (+security alert triage)"}


@dataclass
class Evidence:
    ioc: Ioc
    signals: list[str] = field(default_factory=list)  # literal statements, shown to Jev
    labels: list[str] = field(default_factory=list)  # threat / family names seen anywhere
    strong: list[str] = field(default_factory=list)  # hard reputation hits, used by guardrails
    related: list[Ioc] = field(default_factory=list)  # pivots discovered while enriching
    sources: dict[str, dict[str, Any]] = field(default_factory=dict)  # compact raw facts, for the report
    unavailable: list[str] = field(default_factory=list)

    def for_jev(self) -> dict[str, Any]:
        return {
            "indicator": self.ioc.value,
            "type": self.ioc.type,
            "found_via": self.ioc.origin,
            "signals": self.signals or ["No enrichment source returned any information."],
            "threat_labels": sorted(set(self.labels))[:8],
        }


class _RateLimiter:
    """Spaces calls to at most `rpm` per minute (VirusTotal's free tier allows 4)."""

    def __init__(self, rpm: int):
        self.interval = 60.0 / max(rpm, 1)
        self._next = 0.0
        self._lock = asyncio.Lock()

    async def wait(self) -> None:
        async with self._lock:
            now = time.monotonic()
            delay = self._next - now
            if delay > 0:
                await asyncio.sleep(delay)
            self._next = max(now, self._next) + self.interval


def _days_since(value: Any) -> int | None:
    try:
        if isinstance(value, (int, float)):
            dt = datetime.fromtimestamp(value, tz=timezone.utc)
        else:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00").replace(" UTC", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
        return max((datetime.now(timezone.utc) - dt).days, 0)
    except (ValueError, OSError, TypeError):
        return None


def _age_phrase(days: int) -> str:
    if days < 30:
        return f"{days} days ago (newly registered, under 30 days)"
    if days < 365:
        return f"{days} days ago (under a year)"
    return f"{days // 365} years ago (established)"


def registrable_domain(domain: str) -> str:
    labels = domain.lower().rstrip(".").split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in {"co", "com", "net", "org", "gov", "ac", "edu", "or", "ne", "go"}:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


class Enricher:
    def __init__(self, settings: Settings, client: httpx.AsyncClient | None = None):
        self.s = settings
        self.client = client or httpx.AsyncClient(timeout=settings.http_timeout, headers=UA, follow_redirects=True)
        self._vt_limiter = _RateLimiter(settings.vt_rpm)
        self._cache: dict[str, Any] = {}
        self._cache_started = time.monotonic()
        self._vt_calls = 0

    async def aclose(self) -> None:
        await self.client.aclose()

    def reset_budget(self) -> None:
        self._vt_calls = 0

    # ------------------------------------------------------------------ plumbing
    async def _get_json(self, method: str, url: str, **kw: Any) -> tuple[int, Any]:
        cache_key = f"{method} {url} {sorted(kw.get('params', {}).items()) if kw.get('params') else ''} {kw.get('data') or kw.get('json') or ''}"
        # Reputation changes: drop the cache every 6 h (or at 5,000 entries) in a long-running service.
        if len(self._cache) > 5000 or time.monotonic() - self._cache_started > 6 * 3600:
            self._cache.clear()
            self._cache_started = time.monotonic()
        if cache_key in self._cache:
            return self._cache[cache_key]
        resp = await self.client.request(method, url, **kw)
        try:
            body = resp.json()
        except ValueError:
            body = None
        result = (resp.status_code, body)
        if resp.status_code < 500 and resp.status_code != 429:
            self._cache[cache_key] = result
        return result

    async def _vt(self, path: str) -> tuple[int, Any] | None:
        if not self.s.vt_api_key or self._vt_calls >= self.s.vt_max_per_alert:
            return None
        self._vt_calls += 1
        await self._vt_limiter.wait()
        return await self._get_json("GET", f"https://www.virustotal.com/api/v3/{path}", headers={"x-apikey": self.s.vt_api_key})

    # ------------------------------------------------------------------ entry point
    async def enrich(self, ioc: Ioc) -> Evidence:
        ev = Evidence(ioc=ioc)
        jobs: list[tuple[str, Any]] = []
        t = ioc.type
        if t in ("sha256", "sha1", "md5"):
            jobs = [("virustotal", self._vt_file), ("malwarebazaar", self._malwarebazaar), ("threatfox", self._threatfox)]
        elif t == "url":
            jobs = [("virustotal", self._vt_url), ("urlhaus", self._urlhaus_url), ("threatfox", self._threatfox)]
        elif t == "domain":
            jobs = [("virustotal", self._vt_domain), ("urlhaus", self._urlhaus_host), ("threatfox", self._threatfox),
                    ("rdap", self._rdap), ("dns", self._dns)]
        elif t == "ip":
            jobs = [("virustotal", self._vt_ip), ("abuseipdb", self._abuseipdb), ("urlhaus", self._urlhaus_host),
                    ("threatfox", self._threatfox), ("internetdb", self._internetdb)]

        async def run(name: str, fn: Any) -> None:
            try:
                await fn(ioc, ev)
            except _NotConfigured:
                ev.unavailable.append(f"{name}: no API key")
            except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
                ev.unavailable.append(f"{name}: {type(exc).__name__}")
                ev.sources[name] = {"status": "error", "detail": str(exc)[:200]}

        await asyncio.gather(*(run(n, f) for n, f in jobs))
        ev.labels = [l for l in dict.fromkeys(ev.labels) if l]
        return ev

    def can_expand(self, ev: Evidence) -> bool:
        """Whether VirusTotal relations are available for this indicator (costs VT quota)."""
        return bool(self.s.vt_api_key) and ev.ioc.type in ("sha256", "sha1", "md5", "ip") and self._vt_calls < self.s.vt_max_per_alert

    async def vt_relations(self, ev: Evidence) -> list[Ioc]:
        """What a file contacted, or which domains have pointed at an IP (VirusTotal)."""
        out: list[Ioc] = []
        ioc = ev.ioc
        try:
            if ioc.type in ("sha256", "sha1", "md5"):
                for rel, typ in (("contacted_domains", "domain"), ("contacted_ips", "ip")):
                    r = await self._vt(f"files/{ioc.value}/{rel}?limit=5")
                    if r and r[0] == 200:
                        for item in (r[1] or {}).get("data", []):
                            if typ == "ip" and not is_public_ip(item.get("id", "")):
                                continue
                            out.append(Ioc(item["id"], typ, origin=f"pivot:{ioc.value}"))
            elif ioc.type == "ip":
                r = await self._vt(f"ip_addresses/{ioc.value}/resolutions?limit=5")
                if r and r[0] == 200:
                    for item in (r[1] or {}).get("data", []):
                        host = (item.get("attributes") or {}).get("host_name")
                        if host:
                            out.append(Ioc(host.lower(), "domain", origin=f"pivot:{ioc.value}"))
        except httpx.HTTPError:
            pass
        seen: set[str] = set()
        return [i for i in out if not (i.key in seen or seen.add(i.key))]

    # ------------------------------------------------------------------ VirusTotal
    def _vt_stats(self, attrs: dict, ev: Evidence, what: str) -> None:
        stats = attrs.get("last_analysis_stats") or {}
        mal, sus = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
        total = sum(int(v) for v in stats.values() if isinstance(v, (int, float)))
        results = attrs.get("last_analysis_results") or {}
        names = [r.get("result") for r in results.values() if r.get("category") == "malicious" and r.get("result")]
        ev.labels += [n for n in names if n not in ("malicious", "malware", "phishing")][:5]
        ev.sources["virustotal"] = {"malicious": mal, "suspicious": sus, "engines": total, "reputation": attrs.get("reputation")}
        if total == 0:
            ev.signals.append(f"VirusTotal knows this {what} but has no scan results for it.")
        elif mal == 0 and sus == 0:
            ev.signals.append(f"VirusTotal: none of {total} security vendors flag this {what}.")
        else:
            ev.signals.append(f"VirusTotal: {mal} of {total} security vendors flag this {what} as malicious"
                              + (f" and {sus} as suspicious" if sus else "") + ".")
        if mal >= 10:
            ev.strong.append(f"VirusTotal {mal}/{total} malicious")
        elif mal >= 3:
            ev.signals.append(f"More than two independent vendors call it malicious ({mal}).")
        rep = attrs.get("reputation")
        if isinstance(rep, int) and rep <= -10:
            ev.signals.append(f"VirusTotal community reputation is negative ({rep}).")

    async def _vt_file(self, ioc: Ioc, ev: Evidence) -> None:
        r = await self._vt_required(f"files/{ioc.value}")
        if r[0] == 404:
            ev.sources["virustotal"] = {"status": "not_found"}
            ev.signals.append("VirusTotal has never seen this file (unknown / rare file).")
            return
        a = (r[1] or {}).get("data", {}).get("attributes", {})
        self._vt_stats(a, ev, "file")
        label = (a.get("popular_threat_classification") or {}).get("suggested_threat_label")
        if label:
            ev.labels.insert(0, label)
            ev.signals.append(f"VirusTotal's consensus threat label is '{label}'.")
        if a.get("type_description"):
            ev.signals.append(f"File type: {a['type_description']}; name seen as '{a.get('meaningful_name', 'unknown')}'.")
        sig = a.get("signature_info") or {}
        if sig.get("verified"):
            ev.signals.append(f"Digitally signed: {sig.get('verified')} by {str(sig.get('signers') or 'unknown signer')[:120]}.")
        elif a.get("type_description", "").startswith("Win"):
            ev.signals.append("The Windows executable carries no verified digital signature.")
        first = _days_since(a.get("first_submission_date"))
        if first is not None:
            ev.signals.append(f"First submitted to VirusTotal {_age_phrase(first).replace('newly registered, ', '')}.")
        if a.get("times_submitted"):
            ev.sources["virustotal"]["times_submitted"] = a["times_submitted"]

    async def _vt_url(self, ioc: Ioc, ev: Evidence) -> None:
        url_id = base64.urlsafe_b64encode(ioc.value.encode()).decode().strip("=")
        r = await self._vt_required(f"urls/{url_id}")
        if r[0] == 404:
            ev.sources["virustotal"] = {"status": "not_found"}
            ev.signals.append("VirusTotal has no record of this exact URL.")
            return
        a = (r[1] or {}).get("data", {}).get("attributes", {})
        self._vt_stats(a, ev, "URL")
        if a.get("title"):
            ev.signals.append(f"Page title when last fetched: '{str(a['title'])[:100]}'.")

    async def _vt_domain(self, ioc: Ioc, ev: Evidence) -> None:
        r = await self._vt_required(f"domains/{ioc.value}")
        if r[0] == 404:
            ev.sources["virustotal"] = {"status": "not_found"}
            ev.signals.append("VirusTotal has no record of this domain.")
            return
        a = (r[1] or {}).get("data", {}).get("attributes", {})
        self._vt_stats(a, ev, "domain")
        cats = sorted(set((a.get("categories") or {}).values()))[:4]
        if cats:
            ev.signals.append("Web categories assigned by vendors: " + ", ".join(cats) + ".")

    async def _vt_ip(self, ioc: Ioc, ev: Evidence) -> None:
        r = await self._vt_required(f"ip_addresses/{ioc.value}")
        if r[0] == 404:
            ev.sources["virustotal"] = {"status": "not_found"}
            return
        a = (r[1] or {}).get("data", {}).get("attributes", {})
        self._vt_stats(a, ev, "IP address")
        if a.get("as_owner"):
            ev.signals.append(f"Network owner: {a['as_owner']} (AS{a.get('asn', '?')}), country {a.get('country', '?')}.")

    async def _vt_required(self, path: str) -> tuple[int, Any]:
        if not self.s.vt_api_key:
            raise _NotConfigured()
        r = await self._vt(path)
        if r is None:
            raise _NotConfigured()  # per-alert VT budget used up
        if r[0] == 429:
            raise httpx.HTTPError("VirusTotal quota exceeded")
        if r[0] not in (200, 404):
            raise httpx.HTTPError(f"VirusTotal HTTP {r[0]}")
        return r

    # ------------------------------------------------------------------ abuse.ch (one free Auth-Key)
    def _abusech_headers(self) -> dict[str, str]:
        if not self.s.abusech_auth_key:
            raise _NotConfigured()
        return {"Auth-Key": self.s.abusech_auth_key}

    async def _malwarebazaar(self, ioc: Ioc, ev: Evidence) -> None:
        _, body = await self._get_json("POST", "https://mb-api.abuse.ch/api/v1/",
                                       data={"query": "get_info", "hash": ioc.value}, headers=self._abusech_headers())
        status = (body or {}).get("query_status")
        if status == "ok" and body.get("data"):
            d = body["data"][0]
            ev.sources["malwarebazaar"] = {"signature": d.get("signature"), "file_type": d.get("file_type"), "first_seen": d.get("first_seen")}
            ev.labels.append(d.get("signature") or "")
            ev.signals.append(f"MalwareBazaar holds this exact file as a known malware sample"
                              + (f" of family '{d['signature']}'" if d.get("signature") else "") + ".")
            ev.strong.append("known sample in MalwareBazaar")
        elif status in ("hash_not_found", "no_results"):
            ev.sources["malwarebazaar"] = {"status": "not_found"}
            ev.signals.append("MalwareBazaar has no sample with this hash.")
        else:
            raise ValueError(f"MalwareBazaar: {status}")

    async def _threatfox(self, ioc: Ioc, ev: Evidence) -> None:
        payload = ({"query": "search_hash", "hash": ioc.value} if ioc.type in ("sha256", "md5", "sha1")
                   else {"query": "search_ioc", "search_term": ioc.value, "exact_match": True})
        _, body = await self._get_json("POST", "https://threatfox-api.abuse.ch/api/v1/", json=payload, headers=self._abusech_headers())
        status = (body or {}).get("query_status")
        data = body.get("data") if status == "ok" and isinstance(body.get("data"), list) else []
        if data:
            d = max(data, key=lambda x: x.get("confidence_level") or 0)
            ev.sources["threatfox"] = {"malware": d.get("malware_printable"), "threat_type": d.get("threat_type"),
                                       "confidence": d.get("confidence_level"), "first_seen": d.get("first_seen")}
            ev.labels.append(d.get("malware_printable") or "")
            ev.signals.append(f"ThreatFox lists it as a {d.get('threat_type_desc') or d.get('threat_type') or 'threat'} indicator "
                              f"for {d.get('malware_printable') or 'unknown malware'} (confidence {d.get('confidence_level')}%).")
            if (d.get("confidence_level") or 0) >= 75:
                ev.strong.append(f"ThreatFox {d.get('malware_printable')} ({d.get('confidence_level')}%)")
        elif status in ("no_result", "no_results", "ok"):
            ev.sources["threatfox"] = {"status": "not_found"}
            ev.signals.append("ThreatFox has no record of it.")
        else:
            raise ValueError(f"ThreatFox: {status}")

    async def _urlhaus_url(self, ioc: Ioc, ev: Evidence) -> None:
        _, body = await self._get_json("POST", "https://urlhaus-api.abuse.ch/v1/url/", data={"url": ioc.value}, headers=self._abusech_headers())
        status = (body or {}).get("query_status")
        if status == "ok":
            ev.sources["urlhaus"] = {"url_status": body.get("url_status"), "threat": body.get("threat"), "tags": body.get("tags")}
            ev.labels += body.get("tags") or []
            ev.signals.append(f"URLhaus lists this exact URL as {body.get('threat') or 'malicious'} (status: {body.get('url_status')}).")
            ev.strong.append(f"URLhaus {body.get('threat')}")
        elif status == "no_results":
            ev.sources["urlhaus"] = {"status": "not_found"}
            ev.signals.append("URLhaus has no record of this URL.")
        else:
            raise ValueError(f"URLhaus: {status}")

    async def _urlhaus_host(self, ioc: Ioc, ev: Evidence) -> None:
        _, body = await self._get_json("POST", "https://urlhaus-api.abuse.ch/v1/host/", data={"host": ioc.value}, headers=self._abusech_headers())
        status = (body or {}).get("query_status")
        if status == "ok":
            urls = body.get("urls") or []
            online = sum(1 for u in urls if u.get("url_status") == "online")
            threats = sorted({u.get("threat") for u in urls if u.get("threat")})
            bl = {k: v for k, v in (body.get("blacklists") or {}).items() if v and v != "not listed"}
            ev.sources["urlhaus"] = {"url_count": body.get("url_count"), "online": online, "threats": threats, "blacklists": bl}
            ev.signals.append(f"URLhaus has {body.get('url_count')} malicious URLs on this host ({online} still online)"
                              + (f", threat types: {', '.join(threats)}" if threats else "") + ".")
            if bl:
                ev.signals.append("Listed on blocklists: " + ", ".join(f"{k} ({v})" for k, v in bl.items()) + ".")
            if online or bl:
                ev.strong.append("URLhaus host with live malware URLs" if online else "blocklisted host")
        elif status == "no_results":
            ev.sources["urlhaus"] = {"status": "not_found"}
            ev.signals.append("URLhaus has never seen malware hosted here.")
        else:
            raise ValueError(f"URLhaus: {status}")

    # ------------------------------------------------------------------ AbuseIPDB
    async def _abuseipdb(self, ioc: Ioc, ev: Evidence) -> None:
        if not self.s.abuseipdb_api_key:
            raise _NotConfigured()
        code, body = await self._get_json("GET", "https://api.abuseipdb.com/api/v2/check",
                                          params={"ipAddress": ioc.value, "maxAgeInDays": 90},
                                          headers={"Key": self.s.abuseipdb_api_key, "Accept": "application/json"})
        if code != 200:
            raise httpx.HTTPError(f"AbuseIPDB HTTP {code}")
        d = (body or {}).get("data", {})
        score, reports = d.get("abuseConfidenceScore", 0), d.get("totalReports", 0)
        ev.sources["abuseipdb"] = {"score": score, "reports": reports, "usage": d.get("usageType"), "isp": d.get("isp"), "tor": d.get("isTor")}
        ev.signals.append(f"AbuseIPDB abuse confidence {score}% from {reports} reports in 90 days"
                          + (f"; usage type {d['usageType']}" if d.get("usageType") else "") + ".")
        if d.get("isTor"):
            ev.signals.append("This IP is a Tor exit node.")
        if d.get("isWhitelisted"):
            ev.signals.append("AbuseIPDB marks this IP as allowlisted (known good infrastructure).")
        if score >= 90:
            ev.strong.append(f"AbuseIPDB {score}%")

    # ------------------------------------------------------------------ keyless sources
    async def _internetdb(self, ioc: Ioc, ev: Evidence) -> None:
        code, body = await self._get_json("GET", f"https://internetdb.shodan.io/{ioc.value}")
        if code == 404:
            ev.sources["internetdb"] = {"status": "not_found"}
            ev.signals.append("Shodan has no open ports or services on record for this IP.")
            return
        if code != 200 or not isinstance(body, dict):
            raise httpx.HTTPError(f"InternetDB HTTP {code}")
        ports, tags, vulns, hosts = body.get("ports", []), body.get("tags", []), body.get("vulns", []), body.get("hostnames", [])
        ev.sources["internetdb"] = {"ports": ports[:15], "tags": tags, "vulns": len(vulns), "hostnames": hosts[:5]}
        if ports:
            ev.signals.append(f"Shodan sees open ports: {', '.join(map(str, ports[:12]))}.")
        if tags:
            ev.signals.append(f"Shodan tags this IP: {', '.join(tags)}.")
        if vulns:
            ev.signals.append(f"Shodan associates {len(vulns)} known CVEs with services on this IP.")
        if hosts:
            ev.signals.append(f"Hostnames on this IP: {', '.join(hosts[:5])}.")

    async def _rdap(self, ioc: Ioc, ev: Evidence) -> None:
        reg = registrable_domain(ioc.value)
        code, body = await self._get_json("GET", f"https://rdap.org/domain/{reg}")
        if code == 404:
            ev.sources["rdap"] = {"status": "not_found"}
            ev.signals.append(f"No registration record found for {reg} (unregistered, or its registry has no RDAP).")
            return
        if code != 200 or not isinstance(body, dict):
            raise httpx.HTTPError(f"RDAP HTTP {code}")
        events = {e.get("eventAction"): e.get("eventDate") for e in body.get("events", [])}
        age = _days_since(events.get("registration")) if events.get("registration") else None
        registrar = next((v[3] for ent in body.get("entities", []) if "registrar" in (ent.get("roles") or [])
                          for v in (ent.get("vcardArray") or [None, []])[1] if isinstance(v, list) and v and v[0] == "fn"), None)
        ev.sources["rdap"] = {"registered": events.get("registration"), "age_days": age, "registrar": registrar}
        if age is not None:
            ev.signals.append(f"{reg} was registered {_age_phrase(age)}.")
        if registrar:
            ev.signals.append(f"Registrar: {registrar.rstrip('.')}.")

    async def _dns(self, ioc: Ioc, ev: Evidence) -> None:
        code, body = await self._get_json("GET", "https://dns.google/resolve", params={"name": ioc.value, "type": "A"})
        if code != 200 or not isinstance(body, dict):
            raise httpx.HTTPError(f"DNS HTTP {code}")
        if body.get("Status") == 3:
            ev.sources["dns"] = {"status": "NXDOMAIN"}
            ev.signals.append("The domain does not currently resolve (NXDOMAIN).")
            return
        ips = [a["data"] for a in body.get("Answer", []) if a.get("type") == 1]
        ev.sources["dns"] = {"a": ips[:8]}
        if ips:
            ev.signals.append(f"Currently resolves to {', '.join(ips[:4])}.")
            ev.related += [Ioc(ip, "ip", origin=f"pivot:{ioc.value}") for ip in ips[:3] if is_public_ip(ip)]
        else:
            ev.signals.append("The domain exists but has no A record right now.")


class _NotConfigured(Exception):
    pass
