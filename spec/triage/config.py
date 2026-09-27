"""Settings, read from environment variables so the same image runs anywhere."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env(name: str, default: str | None = None) -> str | None:
    value = os.getenv(name, default)
    return value.strip() if isinstance(value, str) and value.strip() else default


def _float(name: str, default: float) -> float:
    return float(_env(name, str(default)))  # type: ignore[arg-type]


def _int(name: str, default: int) -> int:
    return int(_env(name, str(default)))  # type: ignore[arg-type]


DEFAULT_ALLOWLIST = (
    # Domains that show up in almost every endpoint alert and are not worth a lookup.
    # Deliberately excludes shared hosting (amazonaws, azurewebsites, blob.core, github.io,
    # googleusercontent, workers.dev ...) because attackers host payloads there.
    "microsoft.com", "windows.com", "windowsupdate.com", "office.com", "office365.com",
    "live.com", "msftconnecttest.com", "digicert.com", "verisign.com", "google.com",
    "gstatic.com", "apple.com", "icloud.com", "mozilla.org", "trendmicro.com",
)


@dataclass
class Settings:
    # --- Jev (TypeSafe): makes every malicious / not-malicious call -------------------------
    typesafe_api_key: str | None = field(default_factory=lambda: _env("TYPESAFE_API_KEY"))
    # Pin a version (e.g. jev-1.13.0) once you have tuned the thresholds below on your data.
    jev_model: str = field(default_factory=lambda: _env("JEV_MODEL", "jev-latest"))  # type: ignore[arg-type]
    # Jev probability at or above this = malicious, at or below BENIGN_AT = benign, between = unsure.
    malicious_at: float = field(default_factory=lambda: _float("MALICIOUS_AT", 0.85))
    benign_at: float = field(default_factory=lambda: _float("BENIGN_AT", 0.15))

    # --- Auto loop ------------------------------------------------------------------------
    max_rounds: int = field(default_factory=lambda: _int("MAX_ROUNDS", 3))
    max_iocs: int = field(default_factory=lambda: _int("MAX_IOCS", 25))
    max_pivots_per_round: int = field(default_factory=lambda: _int("MAX_PIVOTS_PER_ROUND", 8))
    # What happens when Jev is still unsure after every round: "human" (default, the verdict
    # stays with Jev and the alert is escalated) or "claude" (Claude breaks the tie).
    tiebreaker: str = field(default_factory=lambda: (_env("TIEBREAKER", "human") or "human").lower())

    # --- Claude (optional): writes the analyst summary, and tiebreaks if TIEBREAKER=claude ---
    anthropic_api_key: str | None = field(default_factory=lambda: _env("ANTHROPIC_API_KEY"))
    claude_model: str = field(default_factory=lambda: _env("CLAUDE_MODEL", "anthropic:claude-sonnet-5"))  # type: ignore[arg-type]
    # How many new questions Claude may write for Jev per round while the verdict is unsure (0 = off).
    claude_questions: int = field(default_factory=lambda: _int("CLAUDE_QUESTIONS", 5))

    # --- Hosted enrichment (all optional; free keys) --------------------------------------
    vt_api_key: str | None = field(default_factory=lambda: _env("VT_API_KEY"))
    vt_rpm: int = field(default_factory=lambda: _int("VT_RPM", 4))  # free tier = 4 lookups/min
    vt_max_per_alert: int = field(default_factory=lambda: _int("VT_MAX_PER_ALERT", 12))
    abusech_auth_key: str | None = field(default_factory=lambda: _env("ABUSECH_AUTH_KEY"))
    abuseipdb_api_key: str | None = field(default_factory=lambda: _env("ABUSEIPDB_API_KEY"))
    http_timeout: float = field(default_factory=lambda: _float("HTTP_TIMEOUT", 15.0))

    allowlist_domains: tuple[str, ...] = field(
        default_factory=lambda: DEFAULT_ALLOWLIST
        + tuple(d.strip().lower() for d in (_env("ALLOWLIST_DOMAINS", "") or "").split(",") if d.strip())
    )

    # --- Web service ----------------------------------------------------------------------
    api_token: str | None = field(default_factory=lambda: _env("TRIAGE_API_TOKEN"))
    # Without a token the service refuses /triage unless this is explicitly turned on (local dev only).
    allow_unauthenticated: bool = field(
        default_factory=lambda: (_env("TRIAGE_ALLOW_UNAUTHENTICATED", "") or "").lower() in ("1", "true", "yes"))

    @property
    def claude_enabled(self) -> bool:
        return bool(self.anthropic_api_key)

    def band(self, p: float | None) -> str:
        if p is None:
            return "unsure"
        if p >= self.malicious_at:
            return "malicious"
        if p <= self.benign_at:
            return "benign"
        return "unsure"
