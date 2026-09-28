# Labelled cases

`bun run eval` scores the agent on every `.json` file here, plus every case an analyst marked
**Malicious** or **Benign** on its ticket.

A file holds one case or an array of cases:

```json
[
  {
    "id": "psexec-patch-push",
    "label": "benign",
    "why": "Approved patch push by the patch automation account (CHG-44213).",
    "alert": { "rule_name": "PsExec remote execution", "user": "CORP\\svc_patching", "...": "..." }
  }
]
```

| Field | |
|---|---|
| `label` | **Required.** `malicious` or `benign`: the right answer. |
| `alert` | **Required.** The alert as it would be pasted: text, or a JSON object. |
| `id` | A short name shown in reports. |
| `why` | Why that's the right answer. The review step shows it to Claude, so be specific. |
| `notes` | Analyst notes to include, if the case is about how notes are handled. Usually leave it out: the score is for the agent's first look. |

`edr-sample.json` has 26 invented alerts (16 malicious, 10 benign) to get started. Replace or extend it
with real alerts from your environment: those are the ones that tell you how the agent does on your
data. Keep real alerts out of Git if they contain sensitive data.
