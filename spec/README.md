# Jev alert triage

An investigation agent for security alerts that runs on **GitHub Actions**. Open an issue with an
alert and it investigates until it has a final answer, then posts a report on the issue.

**Jev (TypeSafe's decision model) answers every question in the investigation**, not only
"malicious or not". The questions adapt as the case develops: what kind of alert it is, what the
lookups return, and what Jev already answered all decide what gets asked next.

## How the investigation adapts

```
alert ─► extract indicators + facts (process? email? sign-in? network?)
      ─► look up every indicator (hosted services, nothing to deploy)
      │
      └─ round ──────────────────────────────────────────────────────────────────────┐
          1. Jev, per indicator: look-alike domain? login page? Tor exit? signed      │
             vendor file? ...then: is it malicious? (seeing its own answers)          │
          2. Jev, on the case: every question that now applies                        │
             process alert -> encoded? downloads? Office parent? credential theft?    │
             email alert   -> impersonation? pressure? credential lure? clicked?      │
             sign-in alert -> impossible travel? password spraying? MFA abuse?        │
             Each answer opens follow-ups, asked in the same round:                   │
               "downloads?" yes    -> "is the download a script or executable?"       │
               "Office parent?" yes -> "document-to-script chain?"                    │
               "user clicked?" yes -> "sign-in or process after the click?"           │
          3. Jev: malicious? attacker active? category, severity, and                 │
             WHICH LEAD TO FOLLOW NEXT (a pick-one over the lookups now possible)     │
          4. confident + guardrail agrees -> done                                     │
             otherwise follow Jev's leads -> new indicators -> questions whose answer │
             may have changed are asked again; Claude (optional) writes new questions │
             about what is still unclear; analysts add /ask and /note  ───────────────┘
      │
      └─ still unsure after MAX_ROUNDS -> "needs human" (or Claude tiebreak if you enable it)
```

Where the questions come from:

| Source | Example | When |
|---|---|---|
| Question library (`triage/questions.py`, ~40 questions) | "Is a command line in `facts` obfuscated or encoded?" | When the alert has that kind of activity |
| Follow-ups | "Is the downloaded content a script or executable?" | When an earlier answer opens them |
| Re-asks | "Do the `indicators` show a host talking to malicious infrastructure?" | When new lookup results arrive |
| Jev's lead choice | "Which lookup would do most to settle this?" | Every round |
| Claude (optional) | Anything specific to this alert that is still unclear | Rounds where the verdict is unsure |
| You (`/ask`) | "Is the user in the finance team, according to `analyst_notes`?" | Any time |

Every answer is shown in the report: the question, Jev's answer and probability, and why it was asked.
Jev only answers; it never writes text. Claude only writes (questions and the summary) and never
answers Jev's questions.

## Set it up on GitHub (10 minutes)

1. **Create a private repository.** Alerts contain hostnames, users and IPs, so keep it private.
   Push this folder to it (it already contains `.github/`).
2. **Add secrets** in *Settings → Secrets and variables → Actions → New repository secret*:

   | Secret | Required? | Where to get it |
   |---|---|---|
   | `TYPESAFE_API_KEY` | **yes** | your typesafe.ai account |
   | `VT_API_KEY` | recommended | virustotal.com → profile → API key (free) |
   | `ABUSECH_AUTH_KEY` | recommended | auth.abuse.ch (free); one key covers URLhaus, MalwareBazaar, ThreatFox |
   | `ABUSEIPDB_API_KEY` | optional | abuseipdb.com (free) |
   | `ANTHROPIC_API_KEY` | optional | lets Claude write extra questions and the summary |

   These lookups need no key: DNS, domain age (RDAP) and Shodan InternetDB.
3. **Check Actions is on** (*Settings → Actions → General → Allow all actions*). The workflow only
   needs the default `GITHUB_TOKEN`, with `issues: write`, which it requests itself.
4. **Try it:** *Issues → New issue → Security alert*, paste `samples/phishing.txt`, and submit.
   The report appears as a comment in about 1–3 minutes, and labels such as `verdict: malicious` are set.

## Using it

**Open an issue** with the *Security alert* form. There are optional fields for context
("user is travelling this week") and your own questions for Jev.

**Comment on the issue.** Each command re-runs the investigation with everything said so far:

| Comment | What happens |
|---|---|
| `/ask Did the user enter their password, according to \`alert\` or \`analyst_notes\`?` | Jev answers yes or no with a probability |
| `/ask Which stage? [blocked \| executed \| spreading]` | Jev picks one option |
| `/note The user confirmed they clicked the link at 09:14` | The note becomes part of what Jev judges |
| `/triage` | Re-runs, for example after adding notes |

Tips for `/ask`: ask one thing per question, and name the part of the case it's about
(`alert`, `facts`, `indicators`, `findings`, `analyst_notes`). Jev reads questions literally.

**From the Actions tab:** *Jev alert triage → Run workflow*, paste the alert. It opens an issue for it.

**From your SIEM or XDR** (automatic), with a GitHub token that has `repo` scope, or a fine-grained
token with *Contents: read & write*:

```bash
curl -X POST https://api.github.com/repos/OWNER/REPO/dispatches \
  -H "Authorization: Bearer $GH_TOKEN" -H "Accept: application/vnd.github+json" \
  -d '{"event_type":"alert","client_payload":{"alert":{...your alert JSON...},"source":"QRadar"}}'
```

The payload can also carry `"notes": [...]` and `"questions": [...]`.

Only repo owners, members and collaborators can trigger runs. Issues and comments from anyone
else are ignored, which protects your keys and quota from strangers and injected instructions.

## Tuning

Optional *Actions variables* (*Settings → Secrets and variables → Actions → Variables*):

| Variable | Default | Meaning |
|---|---|---|
| `MALICIOUS_AT` / `BENIGN_AT` | 0.85 / 0.15 | Jev's p(malicious) needed to decide; anything between keeps investigating |
| `MAX_ROUNDS` | 3 | investigation rounds before escalating |
| `JEV_MODEL` | jev-latest | pin (e.g. `jev-1.13.0`) once you've tuned the thresholds |
| `CLAUDE_QUESTIONS` | 5 | extra questions Claude may write per unsure round (0 = off) |
| `TIEBREAKER` | human | `claude` lets Claude decide when Jev stays unsure |
| `ALLOWLIST_DOMAINS` | — | your own domains and vendors, comma-separated, so they're not looked up |
| `VT_RPM` | 4 | VirusTotal lookups per minute (raise for a premium key) |

Before trusting automatic verdicts, run 100+ alerts you've already labelled. The full JSON result
of every run (all questions and probabilities) is saved as a run artifact, so you can choose
thresholds from real data.

To add your own questions, append to `CASE` in `triage/questions.py`. Each question is a `Template`
with a `when=` condition and/or `after={"earlier_question_id": answers}`.

## Guardrails and limits

- **Attacker-written text:** command lines, emails and page titles are written by the attacker, and
  TypeSafe say such text can steer Jev. So a deterministic guardrail refuses to close an alert as
  benign while VirusTotal, MalwareBazaar, ThreatFox, URLhaus or AbuseIPDB have a hard hit.
- **Arithmetic and dates** (detection ratios, domain age) are computed in code and given to Jev as
  plain statements, because Jev reads numbers as text.
- Jev's context is 32k tokens; alerts are cut to about 12k characters, and each indicator is judged
  in its own small request.
- **GitHub Actions costs:** about 30–60 s of startup per run, and 2,000 free minutes a month on
  private repos (roughly 700–2,000 alerts). Free VirusTotal allows 4 lookups a minute, which slows
  alerts with many indicators.
- `needs_human` is a real outcome: it means the evidence didn't settle the question.

## Other ways to run it

- **CLI:** `pip install -r requirements.txt`, then
  `python -m triage samples/c2_beacon.json --ask "Is this a test?" --note "host is a lab VM"`
- **Web service** (if you later want an always-on endpoint): `uvicorn app:app`, or use the `Dockerfile`.

## Tests

```bash
pip install pytest pytest-asyncio && python -m pytest -q
```

The 24 tests use a stand-in Jev (a real decision-model class) and mocked internet and GitHub APIs.
They cover:

- question adaptation and same-round follow-ups
- Jev choosing leads, and re-asking after new evidence
- analyst `/ask` and `/note`, and Claude-written questions
- the guardrail and escalation
- issue parsing, member-only triggers, labels, and SIEM dispatch

## Files

```
.github/workflows/triage.yml   the workflow (issues, /ask /note /triage comments, manual run, SIEM dispatch)
.github/ISSUE_TEMPLATE/        the "Security alert" issue form
triage/questions.py            the question library, follow-ups, verdict questions, /ask parsing
triage/planner.py              what is askable now, and which leads Jev can choose
triage/pipeline.py             the adaptive loop, guardrails, recommended actions
triage/jev.py                  batches of typed questions to Jev (yes/no, pick-one, rating)
triage/case.py                 the case state Jev sees
triage/facts.py, ioc.py        what the alert is about, and its indicators
triage/enrich.py               hosted lookups turned into plain statements
triage/claude.py               optional: writes questions and the summary
triage/gha.py                  GitHub glue: issue parsing, comments, labels
```
