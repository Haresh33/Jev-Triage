"""GitHub Actions entry point:  python -m triage.gha

Handles these events (see .github/workflows/triage.yml):
- issues opened / reopened / labeled "alert"  -> triage the alert in the issue body
- issue_comment "/triage"                      -> re-triage with every /note so far
- issue_comment "/ask <question>"              -> re-triage and answer the question (plus earlier /ask)
- issue_comment "/note <context>"              -> re-triage with the new context
- workflow_dispatch (input "alert")            -> open an issue for the alert, then triage it
- repository_dispatch type "alert"             -> same, alert in client_payload.alert (for SIEM/XDR webhooks)

Posts the report as an issue comment, sets verdict/severity/category labels, writes the step
summary, and saves the full JSON as triage-result.json for the run artifact.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
from typing import Any
from urllib.parse import quote

import httpx

os.environ.setdefault("PYDANTIC_AI_NO_BANNER", "1")

from .config import Settings  # noqa: E402
from .pipeline import TriageAgent, TriageResult  # noqa: E402
from .report import MARKER, to_markdown  # noqa: E402

TRUSTED = {"OWNER", "MEMBER", "COLLABORATOR"}
COMMAND = re.compile(r"^\s*/(triage|ask|note)\b[ \t]*(.*)$", re.I | re.S)
VERDICT_LABELS = ("verdict: malicious", "verdict: benign", "verdict: needs-human")
LABEL_PREFIXES = ("verdict: ", "severity: ", "category: ")


class GitHub:
    def __init__(self, token: str, repo: str, client: httpx.AsyncClient | None = None,
                 api: str = "https://api.github.com"):
        self.repo = repo
        self.client = client or httpx.AsyncClient(timeout=30)
        self.base = f"{api}/repos/{repo}"
        self.headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": "2022-11-28"}

    async def _req(self, method: str, path: str, **kw: Any) -> Any:
        r = await self.client.request(method, self.base + path, headers=self.headers, **kw)
        if r.status_code >= 400 and not (method == "DELETE" and r.status_code == 404):
            raise RuntimeError(f"GitHub {method} {path} -> {r.status_code}: {r.text[:300]}")
        return r.json() if r.content else None

    async def comments(self, number: int) -> list[dict]:
        out, page = [], 1
        while True:
            batch = await self._req("GET", f"/issues/{number}/comments", params={"per_page": 100, "page": page})
            out += batch
            if len(batch) < 100:
                return out
            page += 1

    async def comment(self, number: int, body: str) -> None:
        await self._req("POST", f"/issues/{number}/comments", json={"body": body})

    async def create_issue(self, title: str, body: str) -> int:
        return (await self._req("POST", "/issues", json={"title": title[:250], "body": body, "labels": ["alert"]}))["number"]

    async def set_labels(self, number: int, current: list[str], wanted: list[str]) -> None:
        for name in current:
            if name.startswith(LABEL_PREFIXES) and name not in wanted:
                await self._req("DELETE", f"/issues/{number}/labels/{quote(name, safe='')}")
        await self._req("POST", f"/issues/{number}/labels", json={"labels": wanted})


# ------------------------------------------------------------------ issue body -> alert
def parse_issue(body: str | None) -> tuple[str, list[str], list[str]]:
    """Issue-form body -> (alert text, context notes, questions for Jev).

    Form bodies look like '### Alert\n\n```text\n...\n```\n\n### Source\n\nVision One\n\n### Context ...'.
    A plain issue (no form) is treated as all alert."""
    body = (body or "").strip()
    sections = {k.strip(): v.strip() for k, v in re.findall(r"^###\s+(.+?)\s*$\n(.*?)(?=^###\s|\Z)", body, re.M | re.S)}
    if not sections:
        return body, [], []

    def clean(v: str) -> str:
        v = v.strip()
        m = re.match(r"^```[\w-]*\n(.*?)\n?```$", v, re.S)
        v = m.group(1).strip() if m else v
        return "" if v == "_No response_" else v

    alert = clean(sections.get("Alert", ""))
    if sections.get("Source") and clean(sections["Source"]):
        alert += f"\n\nSource: {clean(sections['Source'])}"
    notes = [clean(sections["Context"])] if clean(sections.get("Context", "")) else []
    asks = [l.strip(" -*") for l in clean(sections.get("Questions for Jev", "")).splitlines() if l.strip(" -*")]
    return alert.strip(), notes, asks


def commands(comments: list[dict]) -> tuple[list[str], list[str]]:
    """Notes and questions from trusted people's /note and /ask comments (bot comments ignored)."""
    notes, asks = [], []
    for c in comments:
        body = c.get("body") or ""
        if MARKER in body or c.get("author_association") not in TRUSTED:
            continue
        m = COMMAND.match(body)
        if not m:
            continue
        cmd, rest = m.group(1).lower(), m.group(2).strip()
        if cmd == "ask" and rest:
            asks.append(rest)
        elif cmd in ("note", "triage") and rest:
            notes.append(rest)
    return notes, asks


def labels_for(r: TriageResult) -> list[str]:
    labels = ["alert", "verdict: " + r.verdict.replace("_", "-")]
    if r.severity:
        labels.append("severity: " + r.severity)
    if r.category:
        labels.append("category: " + r.category.replace("_", "-"))
    return labels


# ------------------------------------------------------------------ main
async def run(event_name: str, event: dict, gh: GitHub, agent: TriageAgent, out_dir: str = ".") -> TriageResult | None:
    number: int | None = None
    body: str | None = None
    current_labels: list[str] = []
    notes: list[str] = []
    asks: list[str] = []

    if event_name == "issues":
        issue = event["issue"]
        if event.get("action") == "labeled" and (event.get("label") or {}).get("name") != "alert":
            return None
        if not any(l["name"] == "alert" for l in issue.get("labels", [])):
            return None
        if issue.get("author_association") not in TRUSTED:
            print("Issue author is not a repo member; not triaging.")
            return None
        number, body, current_labels = issue["number"], issue.get("body"), [l["name"] for l in issue.get("labels", [])]
        notes, asks = commands(await gh.comments(number))
    elif event_name == "issue_comment":
        issue, comment = event["issue"], event["comment"]
        if MARKER in (comment.get("body") or "") or comment.get("author_association") not in TRUSTED:
            return None
        if not COMMAND.match(comment.get("body") or "") or issue.get("pull_request"):
            return None
        number, body, current_labels = issue["number"], issue.get("body"), [l["name"] for l in issue.get("labels", [])]
        notes, asks = commands(await gh.comments(number))
    elif event_name in ("workflow_dispatch", "repository_dispatch"):
        payload = event.get("inputs") if event_name == "workflow_dispatch" else event.get("client_payload")
        payload = payload or {}
        alert = payload.get("alert")
        if not alert:
            raise SystemExit("No alert given (workflow input 'alert' / client_payload.alert).")
        alert_text = alert if isinstance(alert, str) else json.dumps(alert, indent=2)
        notes = [payload["note"]] if payload.get("note") else list(payload.get("notes") or [])
        asks = [payload["question"]] if payload.get("question") else list(payload.get("questions") or [])
        title = payload.get("title") or _first_line(alert)
        body = f"### Alert\n\n```text\n{alert_text}\n```\n\n### Source\n\n{payload.get('source') or event_name}"
        number = await gh.create_issue(f"[alert] {title}", body)
        current_labels = ["alert"]
    else:
        print(f"Ignoring event {event_name}.")
        return None

    alert_text, form_notes, form_asks = parse_issue(body)
    notes, asks = form_notes + notes, form_asks + asks
    if not alert_text:
        await gh.comment(number, MARKER + "\nThe issue has no alert text to triage.")
        return None
    print(f"Triaging issue #{number} with {len(notes)} notes and {len(asks)} questions.")
    result = await agent.triage(alert_text, notes=notes, questions=asks, on_event=lambda m: print("·", m))
    report = to_markdown(result)
    await gh.comment(number, report)
    await gh.set_labels(number, current_labels, labels_for(result))

    with open(os.path.join(out_dir, "triage-result.json"), "w", encoding="utf-8") as fh:
        fh.write(result.model_dump_json(indent=2))
    summary = os.getenv("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(f"Issue #{number}\n\n{report}\n")
    _output("verdict", result.verdict)
    _output("issue", str(number))
    return result


def _first_line(alert: Any) -> str:
    if isinstance(alert, dict):
        for k in ("title", "name", "rule_name", "description"):
            if isinstance(alert.get(k), str):
                return alert[k][:120]
    return (str(alert).strip().splitlines() or ["alert"])[0][:120]


def _output(name: str, value: str) -> None:
    path = os.getenv("GITHUB_OUTPUT")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(f"{name}={value}\n")


async def _main() -> int:
    event_name = os.environ["GITHUB_EVENT_NAME"]
    with open(os.environ["GITHUB_EVENT_PATH"], encoding="utf-8") as fh:
        event = json.load(fh)
    gh = GitHub(os.environ["GITHUB_TOKEN"], os.environ["GITHUB_REPOSITORY"],
                api=os.getenv("GITHUB_API_URL", "https://api.github.com"))
    agent = TriageAgent.from_settings(Settings())
    try:
        await run(event_name, event, gh, agent)
    finally:
        await agent.aclose()
        await gh.client.aclose()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(_main()))
