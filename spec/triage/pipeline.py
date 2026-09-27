"""The adaptive investigation loop. Jev answers every question; the questions change as the case grows.

Each round:
  1. Jev judges every newly looked-up indicator (malicious? look-alike? credential page? Tor? ...)
  2. Jev answers every case question that now applies. Its answers unlock follow-ups, which are
     asked straight away in the same round (up to FOLLOW_UP_PASSES times).
  3. Jev gives the verdict (malicious? attacker active? category? severity?) and picks which lead
     to follow next from the lookups the investigation has made possible.
  4. Confident and no guardrail objection -> stop. Otherwise follow Jev's chosen leads, let Claude
     (optional) write new questions about what is still unclear, and go round again.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Awaitable, Callable, Literal

from pydantic import BaseModel, Field

from . import planner
from .case import Case, Finding, words
from .claude import ClaudeHelper
from .config import Settings
from .enrich import Enricher, Evidence
from .facts import extract_facts
from .ioc import alert_for_model, extract, parse_alert
from .jev import Answer, Jev, JevUnavailable
from .questions import VERDICT, Question, analyst_question

Verdict = Literal["malicious", "benign", "needs_human"]
EventHook = Callable[[str], Awaitable[None] | None]
FOLLOW_UP_PASSES = 3
GOAL_INDICATOR = "Judge one indicator from a security alert, using the lookup results in `signals`."
GOAL_CASE = "Investigate a security alert: answer about `alert`, the extracted `facts`, the looked-up `indicators`, earlier `findings` and any `analyst_notes`."
GOAL_VERDICT = "Decide the outcome of a security alert investigation from `alert`, `facts`, `indicators`, `findings` and `analyst_notes`."


class IocResult(BaseModel):
    value: str
    type: str
    found_via: str
    p_malicious: float | None
    verdict: str
    signals: list[str]
    threat_labels: list[str]
    strong_hits: list[str]
    unavailable: list[str]


class FindingOut(BaseModel):
    round: int
    subject: str
    question: str
    kind: str
    answer: str
    p: float | None
    origin: str
    why: str


class TriageResult(BaseModel):
    alert_id: str | None
    title: str
    verdict: Verdict
    decided_by: Literal["jev", "claude", "none"]
    p_malicious: float | None
    p_attacker_active: float | None
    category: str | None
    severity: str | None
    stage: str | None
    rounds: int
    stop_reason: str
    indicators: list[IocResult]
    internal_ips: list[str]
    skipped: list[str]
    conflicts: list[str]
    findings: list[FindingOut]  # every question Jev answered, in the order asked (re-asks included)
    analyst_answers: list[FindingOut]  # answers to /ask questions, surfaced separately
    leads: list[str]
    recommended_actions: list[str]
    summary: str
    jev_requests: int
    jev_questions: int
    seconds: float
    thresholds: dict[str, float] = Field(default_factory=dict)


class TriageAgent:
    def __init__(self, settings: Settings, jev: Jev, enricher: Enricher, claude: ClaudeHelper | None = None):
        self.s, self.jev, self.enricher, self.claude = settings, jev, enricher, claude

    @classmethod
    def from_settings(cls, settings: Settings | None = None) -> "TriageAgent":
        settings = settings or Settings()
        return cls(settings, Jev(settings), Enricher(settings), ClaudeHelper(settings) if settings.claude_enabled else None)

    async def aclose(self) -> None:
        await self.enricher.aclose()

    # ======================================================================== main loop
    async def triage(self, raw: str | bytes | dict | list, *, notes: list[str] | None = None,
                     questions: list[str] | None = None, on_event: EventHook | None = None) -> TriageResult:
        t0, req0, q0 = time.monotonic(), self.jev.requests, self.jev.questions_asked
        s = self.s

        async def emit(msg: str) -> None:
            if on_event:
                r = on_event(msg)
                if asyncio.iscoroutine(r):
                    await r

        alert = parse_alert(raw)
        ex = extract(alert, allowlist=s.allowlist_domains, limit=s.max_iocs)
        case = Case(alert=alert, facts=extract_facts(alert), extraction=ex, notes=list(notes or []))
        case.queued = [analyst_question(q, i + 1) for i, q in enumerate(questions or []) if q.strip()]
        self.enricher.reset_budget()
        kinds = [k for k in ("process", "email", "login", "network") if getattr(case.facts, f"has_{k}")]
        await emit(f"{len(ex.iocs)} indicators; alert involves: {', '.join(kinds) or 'no specific activity type'}.")

        await self._lookup(case, ex.iocs)
        expanded: set[str] = set()
        verdict: Verdict | None = None
        decided_by: Literal["jev", "claude", "none"] = "none"
        conflicts: list[str] = []
        stop_reason = ""

        for rnd in range(1, s.max_rounds + 1):
            case.round = rnd
            try:
                # 1. indicators (one small request per indicator: less unrelated context = better answers)
                for stage in ("traits", "verdict"):
                    per_ioc = planner.indicator_questions(case, stage)
                    results = await asyncio.gather(*(self.jev.ask(case.ioc_state(k), qs, GOAL_INDICATOR) for k, qs in per_ioc.items()))
                    for (key, qs), answers in zip(per_ioc.items(), results):
                        self._record(case, qs, answers, subject=case.evidence[key].ioc.value)

                # 2. case questions, then follow-ups the answers unlocked
                for _ in range(FOLLOW_UP_PASSES):
                    qs = planner.case_questions(case)
                    if not qs:
                        break
                    await emit(f"Round {rnd}: asking Jev {len(qs)} questions ({', '.join(sorted({q.origin for q in qs}))}).")
                    self._record(case, qs, await self.jev.ask(case.case_state(), qs, GOAL_CASE))
                    case.queued = [q for q in case.queued if q.qid not in case.findings]

                # 3. verdict + which lead to follow
                options = planner.leads(case, self.enricher, expanded)
                batch = list(VERDICT) + ([planner.lead_question(options)] if options else [])
                answers = await self.jev.ask(case.case_state(), batch, GOAL_VERDICT)
                self._record(case, batch, answers)
            except JevUnavailable as exc:
                stop_reason = f"Jev unavailable: {exc}"[:300]
                await emit(stop_reason)
                break

            p = answers["verdict_malicious"].p_yes if "verdict_malicious" in answers else None
            band = s.band(p)
            await emit(f"Round {rnd}: Jev p(malicious)={words(p)} ({p if p is None else round(p, 2)}) -> {band}.")
            conflicts = self._conflicts(band, case)
            if band != "unsure" and not conflicts:
                verdict, decided_by, stop_reason = band, "jev", f"Jev confident in round {rnd}"  # type: ignore[assignment]
                break
            if conflicts:
                await emit("Guardrail: " + "; ".join(conflicts))
            if rnd == s.max_rounds:
                stop_reason = f"still unsure after {rnd} rounds"
                break

            # 4. adapt: follow Jev's leads, and (optionally) let Claude write questions about what is unclear
            chosen = self._chosen_leads(answers.get("next_lead"), options)
            if chosen:
                case.leads.append(f"round {rnd}: " + "; ".join(l.label for l in chosen))
                await emit(f"Round {rnd}: Jev chose to follow {', '.join(l.label for l in chosen)}.")
                await self._follow(case, chosen, expanded)
            if self.claude and s.claude_questions > 0:
                await self._claude_questions(case, emit)
            if not chosen and not planner.case_questions(case) and not planner.indicator_questions(case, "verdict"):
                stop_reason = f"nothing left to ask or look up after round {rnd}"
                break

        tiebreak_note = ""
        if verdict is None:
            verdict, decided_by, tiebreak_note = await self._tiebreak(case, conflicts)
            await emit(f"Final: {verdict} ({stop_reason}).")
        return await self._result(case, verdict, decided_by, stop_reason, conflicts, tiebreak_note, t0, req0, q0)

    # ======================================================================== steps
    async def _lookup(self, case: Case, iocs: list) -> None:
        new = [i for i in iocs if i.key not in case.evidence]
        if not new:
            return
        for ev in await asyncio.gather(*(self.enricher.enrich(i) for i in new)):
            case.evidence[ev.ioc.key] = ev
        case.evidence_version += 1

    async def _follow(self, case: Case, chosen: list[planner.Lead], expanded: set[str]) -> None:
        to_lookup = [l.target for l in chosen if l.kind == "lookup"]
        for l in chosen:
            if l.kind == "relations":
                expanded.add(l.target.key)
                to_lookup += await self.enricher.vt_relations(case.evidence[l.target.key])
        await self._lookup(case, to_lookup[: self.s.max_pivots_per_round])

    def _chosen_leads(self, ans: Answer | None, options: list[planner.Lead]) -> list[planner.Lead]:
        """Jev's top pick, plus any other lead it gives at least 25 %, up to 3. 'conclude' stops lookups."""
        if not ans or not options:
            return []
        by_label = {l.label: l for l in options}
        ranked = sorted(ans.probabilities.items(), key=lambda kv: -kv[1]) or [(ans.choice or "", 1.0)]
        picked = [by_label[label] for i, (label, prob) in enumerate(ranked)
                  if label in by_label and (i == 0 or prob >= 0.25)]
        if ranked[0][0] == planner.CONCLUDE and ranked[0][1] >= 0.6:
            return []
        return picked[:3]

    async def _claude_questions(self, case: Case, emit: Callable) -> None:
        unclear = [f.question for f in case.findings.values() if f.kind == "yesno" and 0.3 < (f.p or 0.5) < 0.7][:10]
        try:
            written = await self.claude.write_questions(case.case_state(), unclear, self.s.claude_questions)  # type: ignore[union-attr]
        except Exception as exc:  # noqa: BLE001 - optional helper
            await emit(f"Claude could not write questions: {type(exc).__name__}")
            return
        case.queued += written
        if written:
            await emit(f"Claude wrote {len(written)} new questions for Jev.")

    def _record(self, case: Case, qs: list[Question], answers: dict[str, Answer], subject: str = "case") -> None:
        for q in qs:
            a = answers.get(q.qid)
            if a is None:
                continue
            if a.kind == "yesno":
                ans, p, probs = words(a.p_yes), a.p_yes, {}
            else:
                ans, p, probs = a.choice or "", a.confidence, a.probabilities
            case.record(Finding(qid=q.qid, question=q.text, kind=q.kind, subject=subject, answer=ans, p=p,
                                probabilities=probs, origin=q.origin, why=q.why))

    def _conflicts(self, band: str, case: Case) -> list[str]:
        """Deterministic checks next to Jev: never close as benign while threat intel has hard hits
        (TypeSafe advise against Jev-only guards, since attacker-written text can steer it)."""
        out: list[str] = []
        if band == "benign":
            strong = [f"{ev.ioc.value}: {', '.join(ev.strong)}" for ev in case.evidence.values() if ev.strong]
            if strong:
                out.append("Jev says benign but threat intel has hard hits -> " + " | ".join(strong[:3]))
            bad = [ev.ioc.value for k, ev in case.evidence.items() if (case.ioc_p(k) or 0) >= self.s.malicious_at]
            if bad:
                out.append("Jev says the alert is benign but judged these indicators malicious -> " + ", ".join(bad[:3]))
        return out

    async def _tiebreak(self, case: Case, conflicts: list[str]) -> tuple[Verdict, Literal["jev", "claude", "none"], str]:
        if self.s.tiebreaker == "claude" and self.claude:
            try:
                tb = await self.claude.tiebreak(case.case_state(include_verdicts=True) | {"guardrail_conflicts": conflicts})
                return tb.verdict, ("claude" if tb.verdict != "needs_human" else "none"), f"Claude tiebreak: {tb.rationale}"
            except Exception as exc:  # noqa: BLE001
                return "needs_human", "none", f"Claude tiebreak failed: {type(exc).__name__}"
        return "needs_human", "none", ""

    # ======================================================================== output
    async def _result(self, case: Case, verdict: Verdict, decided_by, stop_reason, conflicts, tiebreak_note, t0, req0, q0) -> TriageResult:
        f = case.findings

        def choice(qid: str) -> str | None:
            return f[qid].answer if qid in f else None

        def prob(qid: str) -> float | None:
            return round(f[qid].p, 3) if qid in f and f[qid].p is not None else None

        findings = [FindingOut(round=x.round, subject=x.subject, question=x.question, kind=x.kind, answer=x.answer,
                               p=None if x.p is None else round(x.p, 3), origin=x.origin, why=x.why) for x in case.history]
        stage = choice("impact_stage") if (prob("verdict_malicious") or 0) > self.s.benign_at else None
        result = TriageResult(
            alert_id=case.id, title=case.title, verdict=verdict, decided_by=decided_by,
            p_malicious=prob("verdict_malicious"), p_attacker_active=prob("verdict_attacker_active"),
            category=choice("verdict_category"), severity=choice("verdict_severity"), stage=stage,
            rounds=case.round, stop_reason=stop_reason,
            indicators=[self._ioc_result(case, k, ev) for k, ev in case.evidence.items()],
            internal_ips=case.extraction.internal_ips, skipped=case.extraction.skipped, conflicts=conflicts,
            findings=findings, analyst_answers=[x for x in findings if x.origin == "analyst"], leads=case.leads,
            recommended_actions=recommended_actions(verdict, case, self.s), summary="",
            jev_requests=self.jev.requests - req0, jev_questions=self.jev.questions_asked - q0, seconds=0.0,
            thresholds={"malicious_at": self.s.malicious_at, "benign_at": self.s.benign_at},
        )
        result.summary = await self._summary(result, case, tiebreak_note)
        result.seconds = round(time.monotonic() - t0, 2)
        return result

    def _ioc_result(self, case: Case, key: str, ev: Evidence) -> IocResult:
        p = case.ioc_p(key)
        return IocResult(value=ev.ioc.value, type=ev.ioc.type, found_via=ev.ioc.origin,
                         p_malicious=None if p is None else round(p, 3),
                         verdict="error" if p is None else self.s.band(p), signals=ev.signals,
                         threat_labels=ev.labels[:8], strong_hits=ev.strong, unavailable=ev.unavailable)

    async def _summary(self, r: TriageResult, case: Case, tiebreak_note: str) -> str:
        if self.claude:
            try:
                payload = {"alert": alert_for_model(case.alert, 8000),
                           "result": r.model_dump(exclude={"summary"}) | {"findings": [x.model_dump() for x in r.findings[-60:]]}}
                text = await self.claude.summarize(payload)
                return f"{tiebreak_note}\n\n{text}".strip() if tiebreak_note else text
            except Exception:  # noqa: BLE001 - best effort
                pass
        lines = [f"- **{r.verdict}** after {r.rounds} round(s); Jev p(malicious) = {r.p_malicious}; "
                 f"{r.jev_questions} questions answered by Jev."]
        if r.category:
            lines.append(f"- Category: {r.category}; severity: {r.severity}" + (f"; stage: {r.stage}" if r.stage else "") + ".")
        yes = [x for x in r.findings if x.kind == "yesno" and x.subject == "case" and x.origin not in ("verdict",) and (x.p or 0) >= 0.7]
        if yes:
            lines.append("- Jev said yes to: " + "; ".join(f"\"{x.question}\"" for x in yes[-6:]))
        bad = [i for i in r.indicators if i.verdict == "malicious"]
        if bad:
            lines.append("- Malicious indicators: " + ", ".join(f"`{i.value}`" for i in bad[:6]) + ".")
        if r.conflicts:
            lines.append("- Guardrail: " + "; ".join(r.conflicts))
        if r.verdict == "needs_human":
            lines.append(f"- Escalated because: {r.stop_reason}.")
        if tiebreak_note:
            lines.append(f"- {tiebreak_note}")
        return "\n".join(lines)


# ============================================================================ actions
_BY_CATEGORY: dict[str, list[str]] = {
    "malware_execution": ["Isolate the host.", "Collect the file and process tree; hunt for the hash across all hosts.", "Block the hash and every malicious domain/IP."],
    "phishing": ["Purge the message from all mailboxes.", "Block the sender domain and URLs."],
    "command_and_control": ["Block the destinations at proxy and firewall.", "Isolate the host and find the beaconing process.", "Search for other hosts talking to the same infrastructure."],
    "credential_access": ["Reset the affected accounts and revoke sessions and tokens.", "Check where those credentials were used next."],
    "account_compromise": ["Revoke all sessions and reset the password.", "Review MFA methods, inbox rules and app consents added recently."],
    "lateral_movement": ["Disable or reset the account used.", "Isolate source and destination hosts."],
    "exfiltration": ["Block the destination.", "Isolate the host and preserve evidence.", "Scope what data left and inform the data owner / legal."],
    "reconnaissance": ["Block the source if external.", "Check whether any probed service responded or was exploited."],
    "policy_violation": ["Notify the user's manager / IT per policy.", "Remove the software or fix the configuration."],
}
_BY_FINDING: list[tuple[str, str]] = [
    ("proc_credential_theft", "Treat every credential cached on the host as stolen: reset them and revoke sessions."),
    ("proc_persistence", "Remove the persistence mechanism Jev found (scheduled task / service / Run key) after collecting it."),
    ("proc_defense_evasion", "Re-enable the security tooling/logging that was tampered with and check for gaps in telemetry."),
    ("proc_lateral_spread", "Scope every host the activity reached; isolate them together."),
    ("mail_user_interacted", "Reset the recipient's password, revoke sessions, and check for new MFA methods and inbox rules."),
    ("login_mfa_abuse", "Switch the user to phishing-resistant MFA and review recent MFA approvals."),
    ("login_post_access", "Remove malicious inbox rules / app consents and review what the attacker accessed."),
    ("net_large_outbound", "Scope the data that left and preserve proxy/firewall logs for the window."),
]


def recommended_actions(verdict: str, case: Case, s: Settings) -> list[str]:
    if verdict == "benign":
        return ["Close as benign (false positive); tune the rule if this pattern repeats."]
    cat = case.findings.get("verdict_category")
    cat_name = cat.answer if cat else ""
    acts: list[str] = []
    if verdict == "needs_human":
        acts.append("Hand to an analyst: Jev could not reach a confident verdict. Add context with /note, or ask Jev specific questions with /ask, then /triage again.")
        prefix = "If confirmed: "
    else:
        prefix = ""
        active = case.findings.get("verdict_attacker_active")
        if active and (active.p or 0) >= s.malicious_at:
            acts.append("Treat as an active intrusion: open an incident and page on-call now.")
    contain = case.findings.get("impact_contain")
    if contain and contain.answer in ("host", "account", "both") and verdict != "benign":
        acts.append(prefix + {"host": "Contain the host first.", "account": "Contain the account first.",
                              "both": "Contain both the host and the account."}[contain.answer])
    acts += [prefix + a for a in _BY_CATEGORY.get(cat_name, [] if cat_name == "benign_activity" else ["Investigate and contain per playbook."])]
    acts += [prefix + a for qid, a in _BY_FINDING if case.answer(qid) == "yes"]
    return list(dict.fromkeys(acts))
