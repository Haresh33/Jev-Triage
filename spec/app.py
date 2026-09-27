"""Web service: POST an alert (JSON or plain text) to /triage, or paste one at /.

    uvicorn app:app --host 0.0.0.0 --port 8080
"""

from __future__ import annotations

import hmac
import os
from contextlib import asynccontextmanager

os.environ.setdefault("PYDANTIC_AI_NO_BANNER", "1")

from fastapi import FastAPI, HTTPException, Request  # noqa: E402
from fastapi.responses import HTMLResponse, PlainTextResponse  # noqa: E402

from triage import Settings, TriageAgent, to_markdown  # noqa: E402
from triage.ioc import parse_alert  # noqa: E402

settings = Settings()
state: dict[str, TriageAgent] = {}


@asynccontextmanager
async def lifespan(_: FastAPI):
    state["agent"] = TriageAgent.from_settings(settings)
    yield
    await state["agent"].aclose()


app = FastAPI(title="Jev alert triage", lifespan=lifespan)


def _check_auth(request: Request) -> None:
    if not settings.api_token:
        if settings.allow_unauthenticated:
            return
        raise HTTPException(status_code=503, detail="TRIAGE_API_TOKEN is not set; refusing unauthenticated requests")
    supplied = request.headers.get("x-api-key") or request.headers.get("authorization", "").removeprefix("Bearer ").strip()
    if not hmac.compare_digest(supplied.encode(), settings.api_token.encode()):
        raise HTTPException(status_code=401, detail="missing or wrong API token")


@app.get("/health")
async def health() -> dict:
    s = settings
    return {
        "ok": True,
        "jev_model": s.jev_model,
        "thresholds": {"malicious_at": s.malicious_at, "benign_at": s.benign_at},
        "sources": {
            "virustotal": bool(s.vt_api_key), "abuse.ch": bool(s.abusech_auth_key), "abuseipdb": bool(s.abuseipdb_api_key),
            "rdap": True, "dns": True, "shodan_internetdb": True,
        },
        "claude_summary": s.claude_enabled,
        "tiebreaker": s.tiebreaker,
        "auth_required": bool(s.api_token),
    }


@app.post("/triage")
async def triage(request: Request, format: str = "json"):
    _check_auth(request)
    body = await request.body()
    if not body.strip():
        raise HTTPException(status_code=400, detail="empty alert")
    if len(body) > 2_000_000:
        raise HTTPException(status_code=413, detail="alert larger than 2 MB")
    alert = parse_alert(body)
    notes: list[str] = []
    asks: list[str] = []
    # Optional envelope: {"alert": {...}, "notes": ["..."], "questions": ["..."]}
    if isinstance(alert, dict) and "alert" in alert and set(alert) <= {"alert", "notes", "questions"}:
        notes, asks, alert = list(alert.get("notes") or []), list(alert.get("questions") or []), alert["alert"]
    result = await state["agent"].triage(alert, notes=notes, questions=asks)
    if format in ("md", "markdown"):
        return PlainTextResponse(to_markdown(result), media_type="text/markdown")
    return result.model_dump(mode="json")


@app.get("/", response_class=HTMLResponse)
async def page() -> str:
    return PAGE


PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Jev Alert Triage</title>
<style>
:root{--bg:#f7f7f5;--card:#fff;--ink:#1c1c1a;--mut:#6b6b66;--line:#e2e1dc;--acc:#2f5bd3;--red:#c0392b;--grn:#1e8449;--amb:#b9770e}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--card:#1f1f1d;--ink:#ecebe7;--mut:#a3a29c;--line:#34332f;--acc:#7c9cff;--red:#ff6b5b;--grn:#4cc38a;--amb:#f0b44c}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:980px;margin:0 auto;padding:24px 16px 64px}h1{font-size:22px;margin:0 0 4px}p.sub{color:var(--mut);margin:0 0 18px}
textarea,input{width:100%;background:var(--card);color:var(--ink);border:1px solid var(--line);border-radius:10px;padding:12px;font:13px/1.45 ui-monospace,Menlo,Consolas,monospace}
textarea{min-height:220px;resize:vertical}.row{display:flex;gap:10px;margin:10px 0;flex-wrap:wrap}.row input{flex:1;min-width:200px}
button{background:var(--acc);color:#fff;border:0;border-radius:10px;padding:10px 18px;font-weight:600;cursor:pointer}button:disabled{opacity:.5}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;margin-top:16px;overflow-x:auto}
.verdict{font-size:20px;font-weight:700}.malicious{color:var(--red)}.benign{color:var(--grn)}.needs_human,.unsure{color:var(--amb)}
table{border-collapse:collapse;width:100%;font-size:13px}td,th{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
code{font-size:12px;word-break:break-all}.mut{color:var(--mut)}ul{margin:6px 0 0 18px;padding:0}
</style></head><body><main>
<h1>Jev alert triage</h1><p class="sub">Paste an alert (JSON or text). Jev makes every malicious / not-malicious call; the agent keeps gathering evidence until Jev is confident or it escalates.</p>
<textarea id="alert" placeholder='{"title":"Suspicious PowerShell download","host":"WS-042","cmdline":"powershell -enc ...","url":"hxxp://bad[.]example/p.ps1"}'></textarea>
<div class="row"><input id="token" type="password" placeholder="API token (TRIAGE_API_TOKEN)"><button id="go">Triage</button></div>
<div id="out"></div>
<script>
const $=s=>document.querySelector(s);const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const p=v=>v==null?'—':Number(v).toFixed(2);
$('#go').onclick=async()=>{const b=$('#go');b.disabled=true;$('#out').innerHTML='<div class="card mut">Working… enriching and asking Jev (VirusTotal free tier is slow: 4 lookups/min).</div>';
try{const r=await fetch('/triage',{method:'POST',headers:{'x-api-key':$('#token').value},body:$('#alert').value});
if(!r.ok){throw new Error((await r.text()))}const d=await r.json();render(d)}catch(e){$('#out').innerHTML='<div class="card malicious">'+esc(e.message)+'</div>'}b.disabled=false};
function render(d){const iocs=(d.indicators||[]).sort((a,b)=>(b.p_malicious||0)-(a.p_malicious||0));
$('#out').innerHTML=`<div class="card"><div class="verdict ${d.verdict}">${esc(d.verdict.replace('_',' ').toUpperCase())}</div>
<div class="mut">${esc(d.title)} · decided by ${esc(d.decided_by)} · p(malicious) ${p(d.p_malicious)} · p(attacker active) ${p(d.p_attacker_active)} · ${esc(d.category||'—')} · severity ${esc(d.severity||'—')} · ${d.rounds} round(s), ${d.jev_questions} Jev answers, ${d.seconds}s</div>
${(d.analyst_answers||[]).length?'<h3>Your questions</h3><ul>'+d.analyst_answers.map(a=>'<li>'+esc(a.question)+' → <b>'+esc(a.answer)+'</b></li>').join('')+'</ul>':''}<h3>Summary</h3><div style="white-space:pre-wrap">${esc(d.summary)}</div>
<h3>Recommended actions</h3><ul>${d.recommended_actions.map(a=>'<li>'+esc(a)+'</li>').join('')}</ul>
${d.conflicts.length?'<h3>Guardrail conflicts</h3><ul>'+d.conflicts.map(c=>'<li>'+esc(c)+'</li>').join('')+'</ul>':''}</div>
<div class="card"><h3 style="margin-top:0">Indicators</h3><table><tr><th>Indicator</th><th>Type</th><th>p(mal)</th><th>Evidence</th></tr>
${iocs.map(i=>`<tr><td><code>${esc(i.value)}</code>${i.found_via!=='alert'?' <span class="mut">(pivot)</span>':''}</td><td>${esc(i.type)}</td><td class="${i.verdict}">${p(i.p_malicious)}</td><td>${i.signals.map(esc).join('<br>')}</td></tr>`).join('')||'<tr><td colspan=4 class="mut">No external indicators found.</td></tr>'}</table></div>
<div class="card"><h3 style="margin-top:0">Everything Jev was asked</h3><table><tr><th>Round</th><th>About</th><th>Question</th><th>Answer</th><th>p</th><th>Why</th></tr>
${d.findings.map(x=>`<tr><td>${x.round}</td><td><code>${esc(x.subject)}</code></td><td>${esc(x.question)}</td><td><b>${esc(x.answer)}</b></td><td>${p(x.p)}</td><td class="mut">${esc(x.origin)}${x.why?': '+esc(x.why):''}</td></tr>`).join('')}</table></div>`}
</script></main></body></html>"""
