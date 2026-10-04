"""
backend/models/schemas.py
--------------------------------------------------------------------------
PURPOSE
    Explicit request/response shapes, documented in one place.

WHY NOT A HEAVY VALIDATION FRAMEWORK
    The project brief asks for beginner-friendly, dependency-light code that a
    student can read end to end. These dataclasses document the contract and
    provide `to_dict()` for JSON serialisation; validation logic lives in
    backend/utils/validators.py so the rules are testable in isolation.

SECURITY RELEVANT DECISIONS
    * `AnalyzeRequest` has no `__repr__` that could print a password. We
      override repr to mask the value, so an accidental `print(request)` in a
      debugger or a logged exception cannot leak it.
    * `AnalyzeResponse` has no field for the submitted password.
--------------------------------------------------------------------------
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------
@dataclass
class AnalyzeRequest:
    """Body of POST /api/analyze."""
    password: str
    context: Optional[Dict[str, str]] = None       # optional, in-memory only
    policy: Optional[Dict[str, Any]] = None        # optional policy override
    include_hygiene: bool = True

    def __repr__(self) -> str:                     # pragma: no cover
        # Never render the password, even in tracebacks or debuggers.
        return (f"AnalyzeRequest(password=<masked len={len(self.password)}>, "
                f"context_fields={list((self.context or {}).keys())}, "
                f"policy={'set' if self.policy else 'default'})")

    __str__ = __repr__


@dataclass
class GenerateRequest:
    """Body of POST /api/generate-password."""
    mode: str = "password"
    length: int = 16
    words: int = 4
    separator: str = "-"
    use_uppercase: bool = True
    use_lowercase: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    avoid_ambiguous: bool = True
    capitalise: bool = False
    append_number: bool = False


@dataclass
class PolicyRequest:
    """Administrator policy configuration."""
    minimum_length: int = 12
    common_password_check: bool = True
    personal_info_check: bool = True
    require_uppercase: bool = False
    require_lowercase: bool = False
    require_digit: bool = False
    require_symbol: bool = False
    allow_spaces: bool = True
    min_unique_characters: int = 6
    reject_breached: bool = True
    password_expiry_days: int = 0
    minimum_strength_score: int = 0


# ---------------------------------------------------------------------------
# Responses
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    """One detected weakness (evidence is always masked)."""
    type: str
    severity: str
    title: str
    description: str
    evidence: str = ""
    positions: List[int] = field(default_factory=list)
    penalty_bits: float = 0.0


@dataclass
class Suggestion:
    """One actionable recommendation."""
    priority: str
    weakness: str
    title: str
    risk: str
    action: str
    detected: str = ""


@dataclass
class AnalyzeResponse:
    """
    Response of POST /api/analyze.

    Note the required contract fields -- score, classification, findings,
    suggestions, metrics -- plus the extended sections. There is deliberately
    NO field that could carry the password back to the client.
    """
    analysis_id: str
    version: str
    score: int
    classification: str
    classification_summary: str = ""
    findings: List[Dict[str, Any]] = field(default_factory=list)
    suggestions: List[Dict[str, Any]] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)
    entropy: Dict[str, Any] = field(default_factory=dict)
    score_breakdown: Dict[str, Any] = field(default_factory=dict)
    guess_resistance: Dict[str, Any] = field(default_factory=dict)
    policy: Dict[str, Any] = field(default_factory=dict)
    privacy: Dict[str, Any] = field(default_factory=dict)
    disclaimer: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def __repr__(self) -> str:                     # pragma: no cover
        return (f"AnalyzeResponse(id={self.analysis_id}, score={self.score}, "
                f"classification={self.classification}, findings={len(self.findings)})")

    __str__ = __repr__


@dataclass
class DashboardStats:
    """Aggregate, non-secret analytics for the dashboard."""
    total_analyses: int = 0
    average_score: float = 0.0
    median_score: float = 0.0
    distribution: Dict[str, int] = field(default_factory=dict)
    score_histogram: List[Dict[str, Any]] = field(default_factory=list)
    length_distribution: List[Dict[str, Any]] = field(default_factory=list)
    weakness_frequency: List[Dict[str, Any]] = field(default_factory=list)
    privacy_note: str = ("Aggregate metadata only: no password, no password hash, "
                         "no personal data.")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ErrorResponse:
    """Uniform error shape. `message` never contains user input."""
    error: str
    code: str
    details: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Documentation helper used by GET /api/schema
# ---------------------------------------------------------------------------
def api_schema() -> Dict[str, Any]:
    """Machine-readable summary of every endpoint and its contract."""
    return {
        "version": "1.0",
        "endpoints": [
            {
                "method": "POST", "path": "/api/analyze",
                "purpose": "Analyze one password in memory and return score, findings and advice.",
                "request": {"password": "string (required)", "context": "object (optional)",
                            "policy": "object (optional)", "include_hygiene": "boolean (optional)"},
                "response": "AnalyzeResponse",
                "privacy": "Password is never logged, stored or returned.",
                "status_codes": {"200": "analyzed", "400": "validation error",
                                 "413": "payload too large", "429": "rate limited"},
            },
            {
                "method": "POST", "path": "/api/generate-password",
                "purpose": "Generate a random password or passphrase with secrets.SystemRandom.",
                "request": {"mode": "password|passphrase", "length": "8-128",
                            "words": "3-10", "use_uppercase": "boolean", "..." : "see validators"},
                "privacy": "Generated value is returned once and never stored.",
                "status_codes": {"200": "generated", "400": "validation error", "429": "rate limited"},
            },
            {
                "method": "GET", "path": "/api/dashboard/stats",
                "purpose": "Aggregate counters, distributions and weakness frequency.",
                "privacy": "Aggregates of non-secret metadata only.",
                "status_codes": {"200": "ok"},
            },
            {
                "method": "GET", "path": "/api/analytics/weaknesses",
                "purpose": "Weakness-type frequency table used by the charts.",
                "privacy": "Counts only.",
                "status_codes": {"200": "ok"},
            },
            {
                "method": "GET", "path": "/api/analytics/recent",
                "purpose": "Recent analyses as metadata rows (id, score, length, time).",
                "privacy": "No password, no hash, no context.",
                "status_codes": {"200": "ok"},
            },
            {
                "method": "POST", "path": "/api/analytics/reset",
                "purpose": "Clear analytics rows (demo convenience).",
                "privacy": "Deletes metadata only.",
                "status_codes": {"200": "cleared"},
            },
            {"method": "GET", "path": "/api/health", "purpose": "Liveness + config summary.",
             "privacy": "Reports whether analytics storage is enabled; no secrets.",
             "status_codes": {"200": "ok"}},
            {"method": "GET", "path": "/api/policy/presets",
             "purpose": "Available administrator policy presets.", "status_codes": {"200": "ok"}},
            {"method": "GET", "path": "/api/education/hashing-demo",
             "purpose": "Synthetic password-hashing walk-through (separate teaching module).",
             "privacy": "Uses only a hard-coded synthetic demo value.",
             "status_codes": {"200": "ok"}},
        ],
        "privacy_summary": [
            "Passwords are processed in memory and discarded.",
            "No password, hash or personal context is written to the database or to logs.",
            "Evidence strings shown in findings are masked with bullet characters.",
            "The GitHub Pages build has no backend at all, so nothing can be transmitted.",
        ],
    }
