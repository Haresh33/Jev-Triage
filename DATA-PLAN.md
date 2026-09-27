# Data Plan

## Context provenance
- `can u implement this as a new artifect use Jev shodan. i don't have any other api keys yet.` (original user request; Jev and Shodan are required)
- `The user has now connected VirusTotal — the Secure Vault holds custom.virustotal` (latest authorized addition; enables server-side VirusTotal)
- `The user has now connected AbuseIPDB — the Secure Vault holds custom.abuseipdb` (latest authorized addition; enables server-side AbuseIPDB)
- `~/workspace/research/jev-triage/` (user-supplied project; its adaptive pipeline, question library, parser, samples, and reporting shape define the app)
- `The app still runs the fast Jev loop autonomously and always renders the template ticket immediately.` (accepted direction)
- `u can use yourself in place of claude` (Muse analyst handoff was the original fallback)
- `if i provide you claude api will that work? yes.` plus the connected `custom.anthropic` Secure Vault credential (latest authorized addition; Claude now writes follow-up questions and handles unresolved tiebreaks, while Muse remains fallback)
- `Private app: API keys stay server-side and never reach the browser. No NextDNS anywhere.` (scope constraint)
- Imagery not needed: this evidence workstation has no visual subject; hierarchy comes from typography, probabilities, states, and structured evidence.

## Tested sources
### TypeSafe Jev
**Used by**: `runCase`, `addQuestions`, `runCommand`
**Test command**: `python3 ~/workspace/skills/typesafe/bin/jev.py evaluate --state 'Security alert: expected monthly patching via PsExec under approved change.' --noul 'malicious:Is this malicious activity?' --json | head -120`
**Sample output**: model `jev-1.13.0`; malicious probability `0.15`.
**Processing**: compact case state and typed question batches through the server-only Jev executor; Jev never writes free text.

### Shodan keyed API
**Used by**: IP/domain enrichment
**Test command**: `python3 ~/workspace/skills/shodan/bin/shodan.py resolve example.com | head -100`
**Sample output**: `{ "example.com": "104.20.23.154" }`
**Processing**: server-only `custom.shodan`; compact service, owner, hostname, tags, and vulnerabilities into statements.

### VirusTotal v3
**Used by**: file, URL, domain, IP enrichment and optional pivots
**Test command**: `python3 /tmp/probe_vt.py` using `custom.virustotal` against `https://www.virustotal.com/api/v3/files/44d88612fea8a8f36de82e1278abb02f`
**Sample output**: HTTP `200`; `66 malicious, 0 suspicious, 2 undetected, 7 unsupported`; consensus `virus.eicar/test`.
**Processing**: server-only `x-apikey`; max 12 calls per alert and 15.1 seconds between calls. Compute ratios and ages in code. Ten or more malicious engines is a hard benign-close guardrail; three or more is an explicit signal. Pivots share the budget.

### AbuseIPDB
**Used by**: IP enrichment
**Test command**: `python3 /tmp/probe_abuseipdb.py` using `custom.abuseipdb` against `https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=90`
**Sample output**: HTTP `200`; score `0`, total reports `212`, usage `Content Delivery Network`, ISP `Google LLC`, Tor `false`, allowlisted `true`.
**Processing**: server-only `Key` header. Convert 90-day score, report count, usage, ISP, Tor, and allowlist fields into plain statements. Score 90 or more is a hard hit that blocks benign closure.

### Anthropic Messages API
**Used by**: unresolved-case follow-up question writing and final tiebreak/analyst summary
**Endpoint**: `https://api.anthropic.com/v1/messages`
**Authentication**: server-only `custom.anthropic` injected as `x-api-key`; `anthropic-version: 2023-06-01`; the key never reaches the client.
**Processing**: the full bounded case state (alert, facts, indicators, enrichment signals, Jev answers, unresolved points, and guardrail conflicts) is treated as untrusted evidence. Claude returns up to five focused questions for two extra Jev rounds. If Jev remains unsure, Claude proposes a verdict and writes the analyst summary; a benign proposal is refused when hard threat-intelligence conflicts exist. The configured `claude-sonnet-5` model is tried first, with `claude-sonnet-4-5-20250929` as the compatibility fallback.

### Shodan InternetDB
**Used by**: keyless IP enrichment
**Test command**: runtime fetch probe for `https://internetdb.shodan.io/8.8.8.8`
**Sample output**: HTTP `200`, hostnames and ports `53,443`.
**Processing**: retain hostnames, ports, tags, and CVE count.

### RDAP.org
**Used by**: domain age
**Test command**: runtime fetch probe for `https://rdap.org/domain/example.com`
**Sample output**: HTTP `200`, registration events present.
**Processing**: compute age from registration event and pass Jev a literal statement.

### Google DNS-over-HTTPS
**Used by**: domain resolution and lead discovery
**Test command**: runtime fetch probe for `https://dns.google/resolve?name=example.com&type=A`
**Sample output**: HTTP `200`, status `0`, public A answers.
**Processing**: retain public IPs; distinguish NXDOMAIN, no A record, and failures.

## Agent-task sources
### Asynchronous Muse analyst handoff
**Delivered by**: `needs_questions` -> `getCaseState` -> `addQuestions`; then `needs_summary` -> `attachSummary`
**Processing**: fallback only when Anthropic is unavailable or returns no usable questions/summary. The complete case remains persisted; Muse supplies discriminating follow-ups or a summary, and any override is explicitly analyst-attributed.

## Long-term data behavior
- **Refresh policy**: no polling or cron; enrichment runs on create or explicit rerun.
- **Growth**: user actions and analyst handoffs only; deletion is permanent. Samples remain templates until selected.
- **Ordering**: newest cases first; findings in order; indicators by malicious probability.
- **Time semantics**: instants rendered viewer-local.

## Rejected approaches
- **Tried**: direct shell fetch for keyless sources.
  **Why rejected**: shell egress timed out; runtime fetch probe succeeded.
- **Tried**: first AbuseIPDB credential probe with 30-second timeout.
  **Why rejected**: it timed out; a second 60-second probe succeeded with real data.
- **Tried**: Abuse.ch.
  **Why rejected**: it remains unavailable without its own credential and is labeled unavailable rather than broken.
- **Tried**: browser-side or database-stored Anthropic credentials.
  **Why rejected**: the connected Secure Vault credential is injected only into the server-side Anthropic request.
- **Tried**: weakened Shodan/Jev-only guardrail.
  **Why rejected**: VirusTotal and AbuseIPDB now restore hard reputation checks.
- **Tried**: terminal `needs_human` after the initial loop.
  **Why rejected**: unresolved cases use explicit Muse analyst handoffs.
- **Tried**: pre-populated sample history.
  **Why rejected**: examples are not user records.
