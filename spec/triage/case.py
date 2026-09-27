"""The case file: everything learned so far. Jev is always asked about a view of this state,
so every new lookup result, answer or analyst note changes what Jev sees next."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .enrich import Evidence
from .facts import Facts
from .ioc import Extraction, Ioc, alert_for_model, alert_id, alert_title


def words(p: float | None) -> str:
    """How an earlier yes/no answer is shown back to Jev (Jev reads numbers as text)."""
    if p is None:
        return "not answered"
    if p >= 0.85:
        return "yes"
    if p >= 0.6:
        return "probably yes"
    if p > 0.4:
        return "unclear"
    if p > 0.15:
        return "probably no"
    return "no"


def yes_no(p: float | None) -> str:
    """Coarse answer used to trigger follow-up questions."""
    if p is None:
        return "error"
    return "yes" if p >= 0.7 else "no" if p <= 0.3 else "unclear"


@dataclass
class Finding:
    qid: str
    question: str
    kind: str  # yesno | choice | score
    subject: str  # "case" or the indicator value
    answer: str  # yes / no / unclear  |  chosen option  |  level name
    p: float | None  # p(yes) for yes/no; confidence for choice/score
    probabilities: dict[str, float] = field(default_factory=dict)
    origin: str = "playbook"  # playbook | follow-up | indicator | verdict | lead | claude | analyst
    why: str = ""
    round: int = 0
    evidence_version: int = 0


@dataclass
class Case:
    alert: dict | list | str
    facts: Facts
    extraction: Extraction
    evidence: dict[str, Evidence] = field(default_factory=dict)
    findings: dict[str, Finding] = field(default_factory=dict)
    history: list[Finding] = field(default_factory=list)  # every answer, including re-asks
    notes: list[str] = field(default_factory=list)  # analyst notes (from /note or /triage comments)
    analyst_questions: list[str] = field(default_factory=list)  # from /ask comments
    queued: list[Any] = field(default_factory=list)  # questions written mid-investigation (Claude)
    leads: list[str] = field(default_factory=list)  # which lookups Jev chose, per round
    evidence_version: int = 0  # bumps whenever new lookup results arrive
    round: int = 0

    @property
    def title(self) -> str:
        return alert_title(self.alert)

    @property
    def id(self) -> str | None:
        return alert_id(self.alert)

    # ------------------------------------------------------------------ answers
    def record(self, f: Finding) -> None:
        f.round, f.evidence_version = self.round, self.evidence_version
        self.findings[f.qid] = f
        self.history.append(f)

    def answer(self, qid: str) -> str | None:
        f = self.findings.get(qid)
        if f is None:
            return None
        return yes_no(f.p) if f.kind == "yesno" else f.answer

    def ioc_p(self, key: str) -> float | None:
        f = self.findings.get(f"ioc_malicious@{key}")
        return f.p if f else None

    def iocs(self) -> list[Ioc]:
        return [ev.ioc for ev in self.evidence.values()]

    # ------------------------------------------------------------------ what Jev sees
    def ioc_state(self, key: str) -> dict[str, Any]:
        ev = self.evidence[key]
        state = ev.for_jev()
        state["alert_title"] = self.title
        judged = [f"{f.question} -> {words(f.p) if f.kind == 'yesno' else f.answer}"
                  for f in self.findings.values() if f.subject == ev.ioc.value and not f.qid.startswith("ioc_malicious@")]
        if judged:
            state["judgements"] = judged
        return state

    def case_state(self, *, include_verdicts: bool = False) -> dict[str, Any]:
        indicators = []
        for key, ev in self.evidence.items():
            view = ev.for_jev()
            view["signals"] = view["signals"][:5]
            view["judged_malicious"] = words(self.ioc_p(key))
            extra = [f"{f.question} -> {f.answer if f.kind != 'yesno' else words(f.p)}"
                     for f in self.findings.values() if f.subject == ev.ioc.value and not f.qid.startswith("ioc_malicious@")]
            if extra:
                view["judgements"] = extra[:5]
            indicators.append(view)
        findings = [
            {"question": f.question, "answer": words(f.p) if f.kind == "yesno" else f.answer}
            for f in self.findings.values()
            if f.subject == "case" and (include_verdicts or f.origin not in ("verdict", "lead"))
        ]
        state: dict[str, Any] = {"alert": alert_for_model(self.alert, 12000)}
        facts = self.facts.for_jev()
        if facts:
            state["facts"] = facts
        if self.extraction.internal_ips:
            state["internal_ips"] = self.extraction.internal_ips[:15]
        state["indicators"] = indicators
        if findings:
            state["findings"] = findings[-40:]
        if self.notes:
            state["analyst_notes"] = self.notes[-10:]
        return state
