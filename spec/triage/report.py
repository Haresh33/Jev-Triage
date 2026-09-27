"""Markdown rendering of a TriageResult (GitHub issue comments, step summaries, the CLI)."""

from __future__ import annotations

from .ioc import defang
from .pipeline import TriageResult

_ICON = {"malicious": "🔴", "benign": "🟢", "needs_human": "🟡", "unsure": "🟡", "error": "⚪"}
MARKER = "<!-- jev-triage -->"


def _p(p: float | None) -> str:
    return "—" if p is None else f"{p:.2f}"


def _cell(text: str, n: int = 160) -> str:
    text = " ".join(str(text).split()).replace("|", "/")
    return text if len(text) <= n else text[: n - 1] + "…"


def to_markdown(r: TriageResult, *, max_chars: int = 60000) -> str:
    who = {"jev": "Jev", "claude": "Claude (tiebreak)", "none": "escalated to a human"}[r.decided_by]
    out = [
        MARKER,
        f"## {_ICON.get(r.verdict, '')} {r.verdict.upper().replace('_', ' ')} — {_cell(r.title, 120)}",
        "",
        f"**Decided by:** {who} · **p(malicious):** {_p(r.p_malicious)} · **p(attacker active):** {_p(r.p_attacker_active)}",
        f"**Category:** {r.category or '—'} · **Severity:** {r.severity or '—'}" + (f" · **Stage:** {r.stage}" if r.stage else ""),
        f"**Rounds:** {r.rounds} ({r.stop_reason}) · **Jev:** {r.jev_questions} questions in {r.jev_requests} requests · {r.seconds}s",
    ]
    if r.analyst_answers:
        out += ["", "### Your questions"]
        for a in r.analyst_answers:
            detail = f" (p(yes) {_p(a.p)})" if a.kind == "yesno" else f" (confidence {_p(a.p)})"
            out.append(f"- **{_cell(a.question, 200)}** → **{a.answer}**{detail}")
    out += ["", "### Summary", r.summary or "—", "", "### Recommended actions", *[f"- {a}" for a in r.recommended_actions]]
    if r.conflicts:
        out += ["", "### Guardrail", *[f"- {c}" for c in r.conflicts]]
    if r.indicators:
        out += ["", "### Indicators", "", "| | Indicator | Type | p(malicious) | Key evidence |", "|---|---|---|---|---|"]
        for i in sorted(r.indicators, key=lambda x: -(x.p_malicious or 0)):
            via = "" if i.found_via == "alert" else " *(lead)*"
            out.append(f"| {_ICON.get(i.verdict, '')} | `{_cell(i.value, 80)}`{via} | {i.type} | {_p(i.p_malicious)} | {_cell('; '.join(i.signals[:2]) or '—')} |")
    if r.leads:
        out += ["", "### Leads Jev chose to follow", *[f"- {l}" for l in r.leads]]

    rows = ["", "<details><summary><b>Everything Jev was asked</b> ({} answers)</summary>".format(len(r.findings)), "",
            "| Round | About | Question | Answer | p | Why asked |", "|---|---|---|---|---|---|"]
    for f in r.findings:
        rows.append(f"| {f.round} | `{_cell(f.subject, 40)}` | {_cell(f.question, 140)} | **{_cell(f.answer, 40)}** | {_p(f.p)} | {_cell(f.origin + (': ' + f.why if f.why else ''), 90)} |")
    rows += ["", "</details>"]
    tail = []
    if r.skipped:
        tail.append(f"_Skipped: {_cell(', '.join(r.skipped[:10]), 400)}_")
    unavailable = sorted({u for i in r.indicators for u in i.unavailable})
    if unavailable:
        tail.append(f"_Sources not used: {', '.join(unavailable)}_")
    tail.append("_Reply `/ask <question>` to put a question to Jev, `/note <context>` to add context, `/triage` to re-run._")

    # Defang before measuring: GitHub turns bare URLs, domains and emails into clickable links, and "[.]" adds length.
    text = defang("\n".join(out))
    table = defang("\n".join(rows))
    tail = [defang(t) for t in tail]
    if len(text) + len(table) > max_chars:  # GitHub comments max out at 65,536 characters
        table = table[: max(0, max_chars - len(text) - 200)] + "\n\n…(truncated; full log in the run artifact)\n\n</details>"
    return "\n".join([text, table, "", *tail])
