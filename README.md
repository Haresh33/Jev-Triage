# Jev Triage

An adaptive security-alert triage agent. Paste or upload an alert (JSON, text, or file);
the agent extracts indicators and facts, enriches them, and runs rounds of typed
[Jev](https://www.typesafe.ai) (TypeSafe) questions — judging behaviour, not just reputation —
until it can conclude with a verdict, confidence, and ranked next actions.

## How it works

1. **Extract** — indicators (IPs, domains, URLs, hashes, emails), facts, command lines,
   and cloud/identity audit events are pulled from the alert.
2. **Enrich** — VirusTotal, AbuseIPDB, Shodan, plus keyless DNS-over-HTTPS, RDAP domain
   age, and Shodan InternetDB.
3. **Behaviour analysis** (`server/src/behavior.ts`) — ~45 Windows LOLBin abuse patterns,
   33 Linux/macOS rules, parent→child checks, masquerading detection, and PowerShell
   `-enc` decoding. Pure code, no network. Strong tradecraft blocks a benign close.
4. **Cloud analysis** (`server/src/cloud.ts`) — reads CloudTrail, Azure Activity, Entra
   audit/sign-in, M365 unified audit, GCP audit, Okta System Log, and Kubernetes audit
   events; 40 cloud tradecraft rules with ATT&CK techniques.
5. **Hypothesis loop** (`server/src/hypotheses.ts`) — 37 candidate explanations (26
   malicious, 11 benign). Jev ranks them each round and answers tests for the leading
   ones (yes / no / not stated). Stops at a confidence threshold, after 3 rounds, or
   when there is nothing new to ask.
6. **Verdict** — Jev's verdict is saved immediately with `decidedBy` attribution
   (`jev` / `claude` / `muse_override` / `none`). Cases Jev can't settle go to
   "needs analyst".
7. **Claude second opinion** (`server/src/claude.ts`, optional) — on "needs analyst"
   cases, Claude reviews the full case in the background and adds an advisory box to
   the ticket. It never changes the verdict. `CLAUDE_MODE` in `server/src/actions.ts`:
   `"second_opinion"` (default), `"off"`, or `"tiebreak"`.

The ticket UI shows domain chips, an "Explanations Jev weighed" panel with probability
bars, a "Behaviours observed" section with ATT&CK techniques and matching commands,
unresolved ("not stated") evidence, and the decision trail.

## Layout

- `server/src/` — triage engine (`triage.ts`), behaviour analyser (`behavior.ts`),
  cloud reader (`cloud.ts`), hypotheses (`hypotheses.ts`), Claude path (`claude.ts`),
  privileged subprocesses and lookups (`privileged.ts`), actions (`actions.ts`),
  DB schema (`schema.ts`)
- `client/src/` — React ticket UI (`App.tsx`, `api.ts`, `theme.css`)
- `drizzle/` — SQL migrations
- `spec/` — the original project specification (Python reference implementation,
  question library, samples, tests)

## Setup

```bash
bun install
bun run typecheck
bun run build
```

This project was built as a hosted TypeScript web artifact (see `AGENTS.md` and
`space.json`). Two things are platform-specific and need adapting to run elsewhere:

1. **`@hatch/space-sdk`** is referenced as a local file dependency in `package.json`.
   Replace it with the appropriate runtime/SDK for your host, or stub the small
   surface the server uses.
2. **Credentials.** The server injects API keys at request time through a
   surrogate mechanism (`dynamic_credentials` in `server/src/privileged.ts`),
   referencing named vault entries. There is deliberately no `.env` fallback.
   To run outside the host, wire these keys in yourself where the `custom.*`
   names are referenced:
   - `custom.virustotal` → VirusTotal API key (sent as `x-apikey`)
   - `custom.abuseipdb` → AbuseIPDB key (sent as `Key`)
   - `custom.shodan` → Shodan key (query param)
   - `custom.anthropic` → Anthropic API key (sent as `x-api-key`)
   - TypeSafe Jev model `jev-latest` (the decision engine; without it only the
     behaviour/cloud analysers run)

`spec/.env.example` documents the tuning knobs from the original spec
(thresholds, rounds, rate limits).

## Security notes

- **No API keys are in this repo** — and none ever should be. The `.gitignore`
  excludes `.env` files and the SQLite database.
- `app.db` (case history, may contain pasted alert content) is excluded on purpose.
- The LOLBin/cloud analysers are pure local code; only the enrichment lookups and
  the optional Claude path make network calls, each to its own allow-listed host.
