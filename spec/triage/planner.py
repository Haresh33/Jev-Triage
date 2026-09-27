"""Decides which questions Jev is asked next, and which leads Jev can choose to follow.

Nothing here makes a judgement; it only works out what is *askable* given the case state:
- indicator questions for every indicator that has been looked up and not yet judged
- library questions whose conditions now hold (the alert has a command line, an email, a sign-in...)
- follow-ups opened by earlier answers (e.g. "downloads from the internet?" yes -> "is it a script or executable?")
- re-asks of questions whose answer may change now that new lookup results arrived
- questions Claude wrote about what is still unclear, and questions analysts asked with /ask
"""

from __future__ import annotations

from dataclasses import dataclass

from .case import Case, words
from .enrich import Enricher
from .ioc import Ioc
from .questions import CASE, INDICATOR, LIBRARY, Question

CONCLUDE = "conclude"


def indicator_questions(case: Case, stage: str = "traits") -> dict[str, list[Question]]:
    """stage "traits": the type-specific questions (look-alike? login page? Tor? signed vendor?).
    stage "verdict": "is it malicious?", asked after the traits so Jev sees its own answers to them."""
    out: dict[str, list[Question]] = {}
    for key, ev in case.evidence.items():
        qs = []
        for t in INDICATOR:
            if (t.id == "ioc_malicious") != (stage == "verdict"):
                continue
            if ev.ioc.type in t.ioc_types and f"{t.id}@{key}" not in case.findings:
                qs.append(t.bind(key, why=f"{ev.ioc.type} found in {'the alert' if ev.ioc.origin == 'alert' else 'a lookup'}"))
        if qs:
            out[key] = qs
    return out


def _short(qid: str) -> str:
    t = LIBRARY.get(qid)
    return (t.text if t else qid)[:90]


def case_questions(case: Case) -> list[Question]:
    qs: list[Question] = []
    for t in CASE:
        if not t.when(case):
            continue
        if any(case.answer(dep) not in ok for dep, ok in t.after.items()):
            continue
        f = case.findings.get(t.id)
        if f is None:
            why = "; ".join(f"'{_short(dep)}' was {case.answer(dep)}" for dep in t.after) or "applies to this alert"
            qs.append(t.bind(why=why))
        elif t.reask and f.evidence_version < case.evidence_version:
            qs.append(t.bind(why="re-asked: new lookup results since the last answer"))
    for q in case.queued:
        if q.qid not in case.findings:
            qs.append(q)
    return qs


@dataclass
class Lead:
    label: str
    meaning: str
    kind: str  # "lookup" | "relations"
    target: Ioc


def leads(case: Case, enricher: Enricher, expanded: set[str], limit: int = 14) -> list[Lead]:
    """Lookups Jev can choose between next. Built from what the investigation has found so far."""
    out: list[Lead] = []
    seen = set(case.evidence)
    # Rank by how suspicious the parent indicator is, so the cap keeps the relevant ones.
    ranked = sorted(case.evidence.items(), key=lambda kv: -(case.ioc_p(kv[0]) or 0.5))
    for key, ev in ranked:
        p = case.ioc_p(key)
        if p is not None and p <= 0.15:
            continue  # clearly benign: following it adds noise
        for rel in ev.related:
            if rel.key not in seen:
                seen.add(rel.key)
                out.append(Lead(f"lookup {rel.value}", f"Look up {rel.value}, which {ev.ioc.value} (judged {words(p)} malicious) resolves to or points at.", "lookup", rel))
        if key not in expanded and enricher.can_expand(ev):
            what = "which domains and IPs this file contacted when run" if ev.ioc.type != "ip" else "which domains have pointed at this IP"
            out.append(Lead(f"relations {ev.ioc.value}", f"Ask VirusTotal {what} ({ev.ioc.value}, judged {words(p)} malicious).", "relations", ev.ioc))
    return out[:limit]


def lead_question(options: list[Lead]) -> Question:
    opts = {l.label: l.meaning for l in options}
    opts[CONCLUDE] = "The `findings` and `indicators` already settle whether `alert` is malicious; no further lookup is needed."
    return Question("next_lead", "choice",
                    "Which lookup would do most to settle whether `alert` is malicious, given the `findings` and `indicators` so far?",
                    options=opts, origin="lead", why="Jev chooses the next lead")
