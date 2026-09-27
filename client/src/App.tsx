import { SafeAreaTopScrim } from "@hatch/space-sdk/client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useState, type ChangeEvent } from "react";
import { api, type ApiResponse } from "./api";

type CaseSummary = ApiResponse<typeof api, "listCases">["cases"][number];
type Finding = { id: string; round: number; subject: string; question: string; kind: string; answer: string; probability: number | null; origin: string; why: string };
type Indicator = { value: string; type: string; origin: string; pMalicious: number | null; verdict: string; signals: string[]; labels: string[]; strongHits: string[]; unavailable: string[] };
type Hypothesis = { id: string; title: string; kind: "benign" | "malicious" | "other"; technique: string | null; probability: number };
type SecondOpinion = { verdict: "malicious" | "benign" | "needs_human"; summary: string; rationale: string; by: "claude"; at: string; agreesWithJev: boolean; refusedByGuardrail: boolean };
type Result = { domains?: string[]; hypotheses?: Hypothesis[]; secondOpinion?: SecondOpinion; secondOpinionStatus?: "pending" | "complete" | "failed"; secondOpinionError?: string; behaviors?: Array<{ statement: string; technique: string; strength: string; evidence: string }>; decidedBy?: "jev" | "claude" | "muse_override" | "none"; jevVerdict?: "malicious" | "benign" | "needs_human"; title: string; verdict: "malicious" | "benign" | "needs_human"; pMalicious: number | null; pAttackerActive: number | null; category: string | null; severity: string | null; stage: string | null; rounds: number; stopReason: string; status: string; indicators: Indicator[]; internalIps: string[]; findings: Finding[]; analystAnswers: Finding[]; leads: string[]; recommendedActions: string[]; templateSummary: string; analystSummary: string | null; guardrail: { conflicts: string[]; coverageNote: string }; unavailableSources: string[]; jevRequests: number; jevQuestions: number; investigatedAt: string; unresolved: string[] };

const samples = [
  { name: "Phishing", tone: "red", text: `Reported phishing email - user clicked
From: "IT Helpdesk" <support@micros0ft-secure-login[.]com>
To: m.chen@yourcompany.com
Subject: Password expires today - action required
Link in body: hxxps://micros0ft-secure-login[.]com/owa/auth/login.php?user=m.chen
User m.chen clicked the link at 09:14 from 10.1.3.77 and a sign-in from 45.155.205.233 followed at 09:21.` },
  { name: "C2 beacon", tone: "amber", text: `{
  "id": "WB-00917",
  "title": "Possible Cobalt Strike beacon",
  "severity": "high",
  "host": "WS-FIN-042",
  "user": "CORP\\j.alvarez",
  "process": {
    "name": "rundll32.exe",
    "cmdline": "rundll32.exe C:\\Users\\j.alvarez\\AppData\\Local\\Temp\\upd.dll,StartW",
    "parent": "winword.exe",
    "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
  },
  "network": [{"src_ip":"10.20.4.42","dst_ip":"185.220.101.45","dst_port":443,"sni":"cdn-update-check[.]xyz"}]
}` },
  { name: "Admin activity", tone: "green", text: `EDR alert: PsExec used for remote execution
Host: SRV-APP-07   User: CORP\\svc_patching
Command: PsExec.exe \\SRV-APP-08 -s C:\\Tools\\patch_agent.exe /install
Scheduled change CHG-44213 (monthly patching window, 02:00-04:00). Signed by Microsoft Corporation (Sysinternals).` },
];

function parseResult(value: string | null | undefined): Result | null { if (!value) return null; try { return JSON.parse(value) as Result; } catch { return null; } }
function pct(value: number | null): string { return value === null ? "—" : `${Math.round(value * 100)}%`; }
function dateTime(value: string): string { return new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" }).format(new Date(value)); }
function verdictLabel(value: string | null): string { if (!value) return "Not run"; return value === "needs_human" ? "Needs analyst" : value.charAt(0).toUpperCase() + value.slice(1); }
function currentSummary(item: CaseSummary | null | undefined): string | null {
  return item?.analystSummary && item.analystSummaryRunVersion === item.runVersion ? item.analystSummary : null;
}
function decisionSource(item: CaseSummary, result: Result): "jev" | "claude" | "muse_override" | "none" {
  return result.decidedBy ?? (item.verdictOverride ? "muse_override" : result.verdict === "needs_human" ? "none" : "jev");
}
function statusCopy(item: CaseSummary): string {
  if (item.status === "completed" && item.stage === "second_opinion") return "Claude review pending";
  if (item.status === "completed" && item.verdict === "needs_human") return currentSummary(item) ? "Analyst review complete" : "Review required";
  if (item.status === "completed") return currentSummary(item) ? "Complete" : "Ticket ready";
  return ({ queued: "Ready to run", running: "Investigating", needs_questions: "Waiting on analyst", needs_summary: "Waiting on analyst", error: "Run failed" } as Record<string, string>)[item.status] ?? item.status;
}
function statusDetail(item: CaseSummary): string {
  if (item.status === "queued") return "Ready to begin adaptive triage.";
  if (item.status === "running" && item.stage === "claude_guided_rounds") return "Claude wrote focused follow-up questions; Jev is testing them against the full case state.";
  if (item.status === "running") return "Jev is enriching evidence and testing the current assessment.";
  if (item.status === "needs_questions") return "An analyst is preparing focused questions for the unresolved evidence.";
  if (item.status === "needs_summary") return "The guided rounds are complete; an analyst is preparing the final interpretation.";
  if (item.status === "error") return item.error ?? "The investigation stopped before it could finish.";
  if (item.status === "completed" && item.stage === "second_opinion" && Date.now() - new Date(item.updatedAt).getTime() < 15 * 60_000) return "Jev could not settle this case. Claude is adding a second opinion in the background; Jev's result below is final unless new evidence arrives.";
  if (item.status === "completed" && item.verdict === "needs_human") return currentSummary(item) ? "The analyst interpretation is attached, but no final disposition was selected." : "The case still needs an analyst decision.";
  return currentSummary(item) ? "The analyst interpretation is attached and the case is complete." : "The investigation is complete and the ticket is ready.";
}

export function App() {
  const queryClient = useQueryClient();
  const [activeId, setActiveId] = useState<string | null>(null);
  const [composerOpen, setComposerOpen] = useState(true);
  const [alertText, setAlertText] = useState("");
  const [command, setCommand] = useState("");
  const [zipPassword, setZipPassword] = useState("");
  const [uploadProgress, setUploadProgress] = useState<number | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);
  const initialSelectionDone = useRef(false);

  const cases = useQuery({ queryKey: ["cases"], queryFn: () => api.listCases({ limit: 30 }), refetchInterval: 8_000 });
  const selected = useQuery({ queryKey: ["case", activeId], queryFn: () => api.getCase({ id: activeId ?? "" }), enabled: Boolean(activeId), refetchInterval: (q) => q.state.data?.case?.status === "running" || q.state.data?.case?.status === "needs_questions" || q.state.data?.case?.status === "needs_summary" || q.state.data?.case?.stage === "second_opinion" ? 5_000 : false });
  const result = useMemo(() => parseResult(selected.data?.case?.resultJson), [selected.data?.case?.resultJson]);

  useEffect(() => { if (!initialSelectionDone.current && cases.data) { initialSelectionDone.current = true; const first = cases.data.cases[0]; if (first) { setActiveId(first.id); setComposerOpen(false); } } }, [cases.data]);

  const runNewCase = useMutation({
    mutationFn: async (text: string) => { const created = await api.createCase({ alertText: text }); if (!created.ok || !created.id) throw new Error(created.error ?? "The case could not be created."); setActiveId(created.id); setComposerOpen(false); await queryClient.invalidateQueries({ queryKey: ["cases"] }); const run = await api.runCase({ id: created.id }); if (!run.ok) throw new Error(run.error ?? "The investigation could not complete."); return created.id; },
    onSuccess: async (id) => { setAlertText(""); setNotice("Investigation started. You can leave this case open while it runs."); await Promise.all([queryClient.invalidateQueries({ queryKey: ["cases"] }), queryClient.invalidateQueries({ queryKey: ["case", id] })]); },
    onError: (error) => setNotice(error instanceof Error ? error.message : "The investigation failed."),
  });
  const runCommand = useMutation({
    mutationFn: async () => { if (!activeId) throw new Error("Open a case first."); const response = await api.runCommand({ caseId: activeId, command }); if (!response.ok) throw new Error(response.error ?? "The command failed."); return activeId; },
    onSuccess: async (id) => { setCommand(""); setNotice("Analyst input applied."); await Promise.all([queryClient.invalidateQueries({ queryKey: ["case", id] }), queryClient.invalidateQueries({ queryKey: ["cases"] })]); },
    onError: (error) => setNotice(error instanceof Error ? error.message : "The command failed."),
  });
  const retryCase = useMutation({
    mutationFn: async () => { if (!activeId) throw new Error("Open a case first."); const response = await api.runCase({ id: activeId }); if (!response.ok) throw new Error(response.error ?? "The investigation could not restart."); return activeId; },
    onSuccess: async (id) => { setNotice("Investigation restarted with a fresh background worker."); await Promise.all([queryClient.invalidateQueries({ queryKey: ["case", id] }), queryClient.invalidateQueries({ queryKey: ["cases"] })]); },
    onError: (error) => setNotice(error instanceof Error ? error.message : "The investigation could not restart."),
  });
  const deleteCase = useMutation({
    mutationFn: async () => { if (!activeId) return; const response = await api.deleteCase({ id: activeId }); if (!response.ok) throw new Error(response.error ?? "Could not delete case."); },
    onSuccess: async () => { setActiveId(null); setConfirmDelete(false); setComposerOpen(true); await queryClient.invalidateQueries({ queryKey: ["cases"] }); },
    onError: (error) => setNotice(error instanceof Error ? error.message : "Could not delete case."),
  });

  async function uploadFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0]; if (!file) return; setNotice(null); setUploadProgress(0);
    try {
      const begin = await api.beginFileUpload({ fileName: file.name, fileSize: file.size }); if (!begin.ok || !begin.uploadId) throw new Error(begin.error ?? "Upload could not start.");
      const chunkSize = 256 * 1024; let offset = 0;
      while (offset < file.size) { const chunk = file.slice(offset, Math.min(offset + chunkSize, file.size)); const bytes = new Uint8Array(await chunk.arrayBuffer()); let binary = ""; for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i] ?? 0); const written = await api.writeFileUploadChunk({ uploadId: begin.uploadId, chunkBase64: btoa(binary), reset: offset === 0 }); if (!written.ok) throw new Error(written.error ?? "Upload was interrupted."); offset += chunk.size; setUploadProgress(Math.round((offset / file.size) * 100)); }
      const finished = await api.finishFileUpload({ uploadId: begin.uploadId, zipPassword: zipPassword || undefined }); if (!finished.ok || !finished.id) throw new Error(finished.error ?? "The file could not be read."); setActiveId(finished.id); setComposerOpen(false); await queryClient.invalidateQueries({ queryKey: ["cases"] }); const run = await api.runCase({ id: finished.id }); if (!run.ok) throw new Error(run.error ?? "The investigation could not start."); await Promise.all([queryClient.invalidateQueries({ queryKey: ["cases"] }), queryClient.invalidateQueries({ queryKey: ["case", finished.id] })]); setNotice("File investigation started. You can leave this case open while it runs.");
    } catch (error) { setNotice(error instanceof Error ? error.message : "The upload failed."); } finally { setUploadProgress(null); if (fileRef.current) fileRef.current.value = ""; }
  }

  const busy = runNewCase.isPending || runCommand.isPending || uploadProgress !== null;
  const activeCase = selected.data?.case;
  const canRetryStalled = Boolean(activeCase?.status === "running" && Date.now() - new Date(activeCase.updatedAt).getTime() >= 15 * 60_000);

  return (
    <div className="app-shell">
      <SafeAreaTopScrim backgroundColor="var(--bg)" />
      <aside className="case-rail" aria-label="Case history">
        <div className="rail-head">
          <div><p className="eyebrow">Private workspace</p><h2>Case history</h2></div>
          <button className="new-case-button" onClick={() => { setComposerOpen(true); setActiveId(null); setConfirmDelete(false); }} aria-label="Open new case">New case</button>
        </div>
        <div className="case-list">
          {cases.isPending ? <p className="muted pad">Loading cases…</p> : null}
          {!cases.isPending && !cases.data?.cases.length ? <p className="empty-copy">No cases yet. Start with an alert or one of the examples.</p> : null}
          {cases.data?.cases.map((item: CaseSummary) => <button key={item.id} className={`case-row ${activeId === item.id ? "active" : ""}`} onClick={() => { setActiveId(item.id); setComposerOpen(false); setConfirmDelete(false); }}>
            <span className={`status-dot ${item.verdict ?? item.status}`} aria-hidden="true" />
            <span className="case-row-copy"><strong>{item.title}</strong><span>{statusCopy(item)} · {dateTime(item.updatedAt)}</span></span>
          </button>)}
        </div>
      </aside>

      <main className="workspace">
        {composerOpen || !activeId ? <section className="intake" aria-labelledby="intake-title">
          <div className="intake-heading"><p className="eyebrow">Adaptive investigation</p><h1 id="intake-title">Open a case</h1><p>Paste alert text or JSON. Jev decides what to ask next while Shodan, DNS, and registration data add outside context.</p></div>
          <div className="intake-console">
            <label htmlFor="alert-input">Alert evidence</label>
            <textarea id="alert-input" value={alertText} onChange={(e) => setAlertText(e.target.value)} placeholder="Paste a SIEM, EDR, email, identity, or network alert…" spellCheck={false} />
            <div className="sample-row" aria-label="Sample alerts">{samples.map((sample) => <button key={sample.name} className={`sample sample-${sample.tone}`} onClick={() => setAlertText(sample.text)}>{sample.name}</button>)}</div>
            <div className="intake-actions">
              <button className="primary" disabled={busy || !alertText.trim()} onClick={() => runNewCase.mutate(alertText)}>{runNewCase.isPending ? "Investigating…" : "Run adaptive triage"}</button>
              <span className="or">or</span>
              <button className="secondary" disabled={busy} onClick={() => fileRef.current?.click()}>Upload alert file</button>
              <input ref={fileRef} type="file" className="visually-hidden" aria-label="Upload alert file" onChange={uploadFile} />
            </div>
            <div className="upload-options"><label htmlFor="zip-password">ZIP password <span>(optional; “infected” is also tried)</span></label><input id="zip-password" type="password" value={zipPassword} onChange={(e) => setZipPassword(e.target.value)} /></div>
            {uploadProgress !== null ? <div className="progress-line"><span style={{ width: `${uploadProgress}%` }} /><b>{uploadProgress}%</b></div> : null}
          </div>
          <div className="method-strip"><div><b>01</b><span>Extract facts + indicators</span></div><div><b>02</b><span>Enrich every lead</span></div><div><b>03</b><span>Rank explanations, test the leaders</span></div><div><b>04</b><span>Conclude or escalate</span></div></div>
        </section> : null}

        {!composerOpen && activeId ? <section className="case-view">
          {selected.isPending ? <div className="loading-block">Loading case…</div> : null}
          {activeCase ? <>
            <header className="case-header"><div><p className="eyebrow">Case</p><h1>{activeCase.title}</h1><p>{activeCase.sourceName ? `Uploaded from ${activeCase.sourceName}` : "Pasted alert"} · opened {dateTime(activeCase.createdAt)}</p></div><button className="quiet" onClick={() => setComposerOpen(true)}>Open another</button></header>
            <div className={`case-status status-${activeCase.status}`} role="status"><span className={activeCase.status === "running" ? "pulse" : "status-dot"} aria-hidden="true" /><div><strong>{statusCopy(activeCase)}</strong><p>{canRetryStalled ? "The background worker has not reported progress. Restarting is safe and supersedes the stalled run." : statusDetail(activeCase)}</p></div>{canRetryStalled ? <button className="quiet" disabled={retryCase.isPending} onClick={() => retryCase.mutate()}>{retryCase.isPending ? "Restarting…" : "Retry stalled run"}</button> : null}</div>
            {result && activeCase.status !== "running" ? <>
              <section className={`ticket verdict-${result.verdict}`}>
                <div className="verdict-band"><div><p>Disposition</p><h2>{verdictLabel(activeCase.verdictOverride ?? result.verdict)}</h2>{decisionSource(activeCase, result) === "muse_override" ? <small className="override-note">Muse analyst override · Jev said: {verdictLabel(result.jevVerdict ?? "needs_human")}</small> : decisionSource(activeCase, result) === "claude" ? <small className="override-note">Claude tiebreak · Jev remained unsure</small> : <small className="override-note">{decisionSource(activeCase, result) === "jev" ? "Decided by Jev" : "Not decided: needs an analyst"}</small>}</div><div className="confidence"><span>{pct(result.pMalicious)}</span><small>Jev malicious probability</small></div></div>
                <div className="ticket-meta"><span><b>{result.severity ?? "—"}</b> severity</span><span><b>{result.category?.replaceAll("_", " ") ?? "—"}</b> category</span><span><b>{result.rounds}</b> rounds</span><span><b>{result.jevQuestions}</b> Jev answers</span></div>
                {currentSummary(activeCase) ? <div className="analyst-summary"><h3>Analyst summary</h3><p>{currentSummary(activeCase)}</p></div> : <div className="template-summary"><h3>Ticket summary</h3>{result.templateSummary.split("\n").map((line) => <p key={line}>{line}</p>)}</div>}
                {result.domains?.length ? <div className="domains" aria-label="Domains">{result.domains.map((domain) => <span key={domain}>{domain}</span>)}</div> : null}
                {result.hypotheses?.length ? <div className="hypotheses"><h3>Explanations Jev weighed</h3><ul>{result.hypotheses.slice(0, 6).map((h) => <li key={h.id} className={`hyp-${h.kind}`}><div className="hyp-bar"><span style={{ width: `${Math.max(2, Math.round(h.probability * 100))}%` }} /></div><div className="hyp-text"><b>{h.title}</b><small>{h.kind === "other" ? "not in the catalogue" : h.kind}{h.technique ? ` · ${h.technique}` : ""}</small></div><em>{pct(h.probability)}</em></li>)}</ul></div> : null}
                {result.secondOpinion ? <div className="second-opinion"><h3>Claude second opinion <small>advisory; Jev's verdict stands</small></h3><p><b>{verdictLabel(result.secondOpinion.verdict)}</b>{result.secondOpinion.agreesWithJev ? " · agrees with Jev" : " · differs from Jev"}{result.secondOpinion.refusedByGuardrail ? " · a benign close would be blocked by the guardrail" : ""}</p><p>{result.secondOpinion.summary}</p>{result.secondOpinion.rationale ? <p className="muted">{result.secondOpinion.rationale}</p> : null}</div> : result.secondOpinionStatus === "pending" ? <div className="second-opinion" role="status"><h3>Claude second opinion <small>advisory; Jev's verdict stands</small></h3><p>Reviewing the complete case and writing focused follow-up questions.</p></div> : result.secondOpinionStatus === "failed" ? <div className="second-opinion second-opinion-failed" role="status"><h3>Claude second opinion <small>not completed</small></h3><p>{result.secondOpinionError ?? "Claude second opinion failed for an unknown reason."}</p></div> : null}
                {result.behaviors?.length ? <div className="behaviors"><h3>Behaviours observed</h3><ul>{result.behaviors.map((behavior, index) => <li key={`${behavior.technique}-${index}`} className={`behavior-${behavior.strength}`}><div><span className="behavior-strength">{behavior.strength}</span><small>{behavior.technique}</small></div><p>{behavior.statement}</p><code>{behavior.evidence}</code></li>)}</ul></div> : null}
                <div className="ticket-grid"><div><h3>Recommended actions</h3><ol>{result.recommendedActions.map((action) => <li key={action}>{action}</li>)}</ol></div><div><h3>Why it stopped</h3><p>{result.stopReason}</p>{result.stage ? <p><b>Observed stage:</b> {result.stage}</p> : null}</div></div>
              </section>

              <section className="evidence-section"><div className="section-head"><div><p className="eyebrow">Outside context</p><h2>Indicators</h2></div><span>{result.indicators.length} found</span></div>
                {!result.indicators.length ? <p className="empty-copy">No public indicators were extracted. Jev used the alert facts and analyst notes.</p> : <div className="indicator-list">{result.indicators.map((indicator) => <details key={`${indicator.type}:${indicator.value}`} className="indicator"><summary><span className={`status-dot ${indicator.verdict}`} /><code>{indicator.value}</code><span className="indicator-type">{indicator.type}</span><b>{pct(indicator.pMalicious)}</b></summary><div className="indicator-body"><ul>{indicator.signals.map((signal) => <li key={signal}>{signal}</li>)}</ul>{indicator.strongHits.length ? <p className="strong-hit">Guardrail signal: {indicator.strongHits.join("; ")}</p> : null}{indicator.unavailable.length ? <p className="muted">{indicator.unavailable.join(" · ")}</p> : null}</div></details>)}</div>}
              </section>

              <section className="evidence-section"><div className="section-head"><div><p className="eyebrow">Decision trail</p><h2>Everything Jev was asked</h2></div><span>{result.findings.length} answers</span></div><div className="finding-list">{result.findings.slice().reverse().map((finding, index) => <div className="finding" key={`${finding.id}-${finding.round}-${index}`}><div className="finding-top"><span>R{finding.round} · {finding.origin.replaceAll("_", " ")}</span><b>{finding.answer}</b><em>{pct(finding.probability)}</em></div><p>{finding.question}</p><small>{finding.subject === "case" ? finding.why : finding.subject}</small></div>)}</div></section>

              <details className="coverage"><summary>Coverage and guardrail</summary><p>{result.guardrail.coverageNote}</p>{result.guardrail.conflicts.map((conflict) => <p className="strong-hit" key={conflict}>{conflict}</p>)}<p className="muted">Unavailable: {result.unavailableSources.join(" · ")}</p></details>

              <section className="command-box"><label htmlFor="case-command">Ask or add context</label><div className="command-help"><button onClick={() => setCommand("/ask ")}>/ask Jev one question</button><button onClick={() => setCommand("/note ")}>/note and rerun</button></div><textarea id="case-command" value={command} onChange={(e) => setCommand(e.target.value)} placeholder="/ask Is the sign-in sequence consistent with account takeover?" /><button className="primary" disabled={runCommand.isPending || !command.trim()} onClick={() => runCommand.mutate()}>{runCommand.isPending ? "Applying…" : "Apply to case"}</button></section>
            </> : null}
            <footer className="case-footer">{confirmDelete ? <div className="delete-confirm"><span>Delete this case and its notes permanently?</span><button className="danger" onClick={() => deleteCase.mutate()} disabled={deleteCase.isPending}>Delete case</button><button className="quiet" onClick={() => setConfirmDelete(false)}>Cancel</button></div> : <button className="danger-link" onClick={() => setConfirmDelete(true)}>Delete case</button>}</footer>
          </> : <p className="empty-copy">Case not found.</p>}
        </section> : null}
        {notice ? <button className="toast" onClick={() => setNotice(null)} aria-label="Dismiss message">{notice}</button> : null}
      </main>
    </div>
  );
}
