"""Test doubles: a stand-in Jev (a real DecisionModel, answering any typed question by simple
rules over the state) and a mocked internet for the enrichment sources."""

from __future__ import annotations

import json
import re
from typing import Any

import httpx
from pydantic_ai.models.decision import (
    ChoiceAnswer, ChoiceQuestion, DecisionModel, DecisionRequest, DecisionResponse, NoulAnswer,
    NoulQuestion, ScoreAnswer, ScoreQuestion,
)

# (words in the question, words in the state that make the answer "yes")
CASE_RULES: list[tuple[tuple[str, ...], tuple[str, ...]]] = [
    (("obfuscated or encoded",), ("-enc", "base64", "frombase64")),
    (("download content from the internet",), ("http://", "https://", "downloadstring", "iwr ", "invoke-webrequest")),
    (("built-in windows tool",), ("powershell", "rundll32", "mshta", "regsvr32", "certutil")),
    (("office application",), ("winword", "excel.exe", "outlook")),
    (("user-writable or temporary",), ("appdata", "\\\\temp\\\\", "downloads")),
    (("credentials being dumped",), ("mimikatz", "lsass", "sekurlsa")),
    (("run on another internal machine",), ("psexec",)),
    (("authorised administration",), ("chg-", "patch window", "patching window", "maintenance window")),
    (("security test",), ("eicar", "red team", "red-team", "simulation")),
    (("pretend to be a well-known brand",), ("helpdesk", "micros0ft")),
    (("urgency or a threat",), ("expires today", "urgent", "action required")),
    (("ask the reader to sign in",), ("password", "login.php")),
    (("clicked the link",), ("clicked",)),
    (("after the user interacted",), ("sign-in from",)),
    (("script or executable that would run next",), (".ps1", ".exe", ".dll")),
    (("finance team",), ("finance",)),
]
BENIGN_WORDS = ("authorised", "security test", "legitimate", "service, admin", "owned by a major")


class FakeJev(DecisionModel):
    """`alert_overrides` forces the verdict p(malicious) per round, to exercise unsure / guardrail paths."""

    def __init__(self, alert_overrides: list[float] | None = None):
        super().__init__()
        self.alert_overrides = list(alert_overrides or [])
        self.requests: list[DecisionRequest] = []

    @property
    def model_name(self) -> str:
        return "fake-jev"

    @property
    def system(self) -> str:
        return "typesafe"

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def _q(q: Any) -> str:
        ins = q.instructions
        return (ins.get("question") if isinstance(ins, dict) else str(ins or "")).lower()

    @staticmethod
    def _ioc_p(state: dict) -> float:
        sig = " ".join(state.get("signals", [])).lower()
        flagged = [int(n) for n in re.findall(r"(\d+) of \d+ security vendors flag", sig)]
        if any(n >= 3 for n in flagged) or any(k in sig for k in ("urlhaus lists", "malwarebazaar holds", "threatfox lists", "abuse confidence 100%")):
            return 0.95
        if "none of" in sig or "signed: signed" in sig:
            return 0.04
        return 0.5

    def _verdict(self, state: dict, text: str) -> float:
        if self.alert_overrides:
            return self.alert_overrides.pop(0)
        judged = [i.get("judged_malicious") for i in state.get("indicators", [])]
        findings = state.get("findings", [])
        good = [f for f in findings if f["answer"] in ("yes", "probably yes") and any(w in f["question"].lower() for w in BENIGN_WORDS)]
        bad = [f for f in findings if f["answer"] in ("yes", "probably yes") and not any(w in f["question"].lower() for w in BENIGN_WORDS)]
        if any(j in ("yes", "probably yes") for j in judged) or len(bad) >= 2:
            return 0.96
        if good or (judged and all(j in ("no", "probably no") for j in judged)):
            return 0.05
        return 0.5

    # ---------------------------------------------------------------- the model
    async def decide(self, request: DecisionRequest, model_settings: Any) -> DecisionResponse:
        self.requests.append(request)
        state = request.state if isinstance(request.state, dict) else {"alert": request.state}
        text = json.dumps(state).lower()
        is_ioc = "indicator" in state
        verdict_p = None
        _vp: list[float] = []

        def vp() -> float:  # one verdict per request (overrides are consumed once per round)
            if not _vp:
                _vp.append(self._verdict(state, text))
            return _vp[0]
        answers: dict[str, Any] = {}
        for name, q in request.questions.items():
            qt = self._q(q)
            if isinstance(q, NoulQuestion):
                if is_ioc:
                    ind = state["indicator"].lower()
                    sig = " ".join(state.get("signals", [])).lower()
                    if "is `indicator` malicious" in qt:
                        p = self._ioc_p(state)
                    elif "imitate a well-known brand" in qt:
                        p = 0.9 if re.search(r"micros0ft|paypa1|-secure-|login", ind) else 0.1
                    elif "tor exit" in qt:
                        p = 0.92 if "tor" in sig else 0.08
                    elif "legitimate, widely used program" in qt:
                        p = 0.95 if "signed: signed" in sig else 0.05
                    elif "sign-in, password-reset" in qt:
                        p = 0.9 if "login" in ind else 0.1
                    else:
                        p = 0.1
                elif "is the activity described in `alert` malicious" in qt:
                    verdict_p = p = vp()
                elif "currently has access" in qt:
                    p = 0.9 if ("beacon" in text and vp() > 0.9) else 0.2
                elif "talking to infrastructure judged malicious" in qt:
                    p = 0.9 if any(i.get("judged_malicious") == "yes" for i in state.get("indicators", [])) else 0.1
                else:
                    p = 0.1
                    for qwords, swords in CASE_RULES:
                        if any(w in qt for w in qwords) and any(w in text for w in swords):
                            p = 0.92
                            break
                answers[name] = NoulAnswer(noul=p)
            elif isinstance(q, ChoiceQuestion):
                opts = list(q.criteria)
                if "which lookup" in qt:
                    non = [o for o in opts if o != "conclude"]
                    pick = non[0] if non else "conclude"
                elif "which kind of activity" in qt:
                    pick = ("phishing" if "phish" in text else "credential_access" if "mimikatz" in text
                            else "command_and_control" if vp() > 0.9 else "benign_activity")
                elif "how far" in qt:
                    pick = "executed"
                elif "needs containing" in qt:
                    pick = "host"
                else:
                    pick = opts[0]
                rest = (0.3 / (len(opts) - 1)) if len(opts) > 1 else 0
                answers[name] = ChoiceAnswer(choice=pick, confidence=0.7, probabilities={o: (0.7 if o == pick else rest) for o in opts})
            elif isinstance(q, ScoreQuestion):
                sv = 2.2 if vp() > 0.9 else 0.1
                answers[name] = ScoreAnswer(score=sv, confidence=0.7, probabilities={i: (0.7 if i == round(sv) else 0.1) for i in range(len(q.criteria))})
        return DecisionResponse(answers=answers, model_name="fake-jev-1.0")


# ------------------------------------------------------------------------------ mocked internet
EVIL_HASH = "a" * 10 + "0123456789abcdef" * 3 + "b" * 6          # 64 hex
CLEAN_HASH = "c" * 8 + "fedcba9876543210" * 3 + "d" * 8          # 64 hex
EVIL_IP = "185.220.101.45"
UNKNOWN_DOMAIN = "update-check-cdn.xyz"
CLEAN_DOMAIN = "wikipedia.org"


def _vt(stats: dict[str, int], **attrs: Any) -> dict:
    results = {f"engine{i}": {"category": "malicious", "result": "Trojan.Beacon"} for i in range(stats.get("malicious", 0))}
    return {"data": {"attributes": {"last_analysis_stats": stats, "last_analysis_results": results, **attrs}}}


def handler(request: httpx.Request) -> httpx.Response:
    url = str(request.url)
    host = request.url.host
    if host == "www.virustotal.com":
        if f"files/{EVIL_HASH}/contacted" in url:
            return httpx.Response(200, json={"data": []})
        if f"files/{EVIL_HASH}" in url:
            return httpx.Response(200, json=_vt({"malicious": 51, "undetected": 20}, type_description="Win32 EXE",
                                                meaningful_name="invoice.exe", popular_threat_classification={"suggested_threat_label": "trojan.cobaltstrike"}))
        if f"files/{CLEAN_HASH}" in url:
            return httpx.Response(200, json=_vt({"malicious": 0, "undetected": 70, "harmless": 2}, type_description="Win32 EXE",
                                                signature_info={"verified": "Signed", "signers": "Microsoft Windows"}))
        if f"domains/{CLEAN_DOMAIN}" in url:
            return httpx.Response(200, json=_vt({"malicious": 0, "harmless": 65}))
        if f"domains/{UNKNOWN_DOMAIN}" in url:
            return httpx.Response(200, json=_vt({"malicious": 0, "suspicious": 1, "undetected": 60}))
        if f"ip_addresses/{EVIL_IP}/resolutions" in url:
            return httpx.Response(200, json={"data": []})
        if f"ip_addresses/{EVIL_IP}" in url:
            return httpx.Response(200, json=_vt({"malicious": 14, "harmless": 50}, as_owner="Tor relay host", asn=60729, country="DE"))
        return httpx.Response(404, json={"error": {"code": "NotFoundError"}})
    if host == "dns.google":
        name = request.url.params.get("name")
        if name == UNKNOWN_DOMAIN:
            return httpx.Response(200, json={"Status": 0, "Answer": [{"type": 1, "data": EVIL_IP}]})
        return httpx.Response(200, json={"Status": 0, "Answer": [{"type": 1, "data": "198.35.26.96"}]})
    if host == "rdap.org":
        age = "2026-09-20T00:00:00Z" if UNKNOWN_DOMAIN in url else "2001-01-13T00:00:00Z"
        return httpx.Response(200, json={"events": [{"eventAction": "registration", "eventDate": age}], "entities": []})
    if host == "internetdb.shodan.io":
        if EVIL_IP in url:
            return httpx.Response(200, json={"ports": [22, 443, 9001], "tags": ["tor"], "vulns": [], "hostnames": []})
        return httpx.Response(404, json={"detail": "No information available"})
    if host == "api.abuseipdb.com":
        score = 100 if request.url.params.get("ipAddress") == EVIL_IP else 0
        return httpx.Response(200, json={"data": {"abuseConfidenceScore": score, "totalReports": 900 if score else 0, "isTor": bool(score)}})
    if host.endswith("abuse.ch"):
        return httpx.Response(200, json={"query_status": "no_results" if "urlhaus" in host else "hash_not_found" if "mb-api" in host else "no_result"})
    return httpx.Response(404)


def mock_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))
