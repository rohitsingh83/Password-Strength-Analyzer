"""
backend/main.py
--------------------------------------------------------------------------
PURPOSE
    OPTIONAL FastAPI variant of the same service (Technology Stack Option B
    in the project brief).

WHY BOTH?
    The brief asked for a beginner option (Flask) and a modern option
    (FastAPI). Both are provided so you can compare them in your report:

        Flask    - minimal, one obvious way to do things, huge beginner
                   ecosystem, easy to read top-to-bottom.
        FastAPI  - automatic OpenAPI docs (/docs), request validation via
                   type hints and Pydantic, async support, better suited to
                   a service that other teams consume.

    The ENGINE is identical in both: the same backend/services modules are
    imported, so a password is analyzed exactly the same way.

RUN IT
    pip install fastapi uvicorn
    uvicorn backend.main:app --reload --port 8000
    open http://127.0.0.1:8000/docs

PRIVACY
    Same guarantees as the Flask app: in-memory analysis, no logging of the
    submitted value, no storage of it, no external calls.
--------------------------------------------------------------------------
"""

from __future__ import annotations

import pathlib
import sys
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.models.schemas import api_schema                      # noqa: E402
from backend.services.audit_store import (                         # noqa: E402
    ANALYTICS_ENABLED,
    get_dashboard_stats,
    get_recent_analyses,
    init_db,
    record_analysis,
    reset_analytics,
)
from backend.services.password_analyzer import analyze_password     # noqa: E402
from backend.services.password_generator import (                   # noqa: E402
    generate_passphrase,
    generate_password,
)
from backend.services.password_hashing_demo import demonstration    # noqa: E402
from backend.services.policy_checker import PRESET_POLICIES, PasswordPolicy  # noqa: E402
from backend.utils.logging_config import log_analysis_metadata      # noqa: E402
from backend.utils.rate_limiter import analyze_limiter, generate_limiter  # noqa: E402

MAX_PASSWORD_LENGTH = 256

app = FastAPI(
    title="Password Strength Analyzer & Security Suggestion Tool",
    description=(
        "Privacy-focused API that scores password strength using length, predictability, "
        "common-password checks, pattern analysis, entropy concepts and personalised "
        "security recommendations.\n\n"
        "**Privacy contract:** passwords are analyzed in memory, never logged, never stored, "
        "never returned and never sent to an external service."
    ),
    version="1.0.0",
)

# The front-end is same-origin in the default deployment. CORS is only opened
# for local development ports; in production you would list your own origin.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

if ANALYTICS_ENABLED:
    init_db()


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------
class AnalyzeRequestModel(BaseModel):
    password: str = Field(..., description="The password to analyze (never stored)")
    context: Optional[Dict[str, str]] = Field(
        default=None,
        description="Optional personal context for overlap checks (first_name, birth_year, "
                    "organisation...). Kept in memory only.",
    )
    policy: Optional[Dict[str, Any]] = None
    include_hygiene: bool = True

    @field_validator("password")
    @classmethod
    def check_length(cls, value: str) -> str:
        if len(value) > MAX_PASSWORD_LENGTH:
            # The message contains a limit, not the value.
            raise ValueError(f"password must be at most {MAX_PASSWORD_LENGTH} characters")
        return value


class GenerateRequestModel(BaseModel):
    mode: str = Field(default="password", pattern="^(password|passphrase)$")
    length: int = Field(default=16, ge=8, le=128)
    words: int = Field(default=4, ge=3, le=10)
    separator: str = "-"
    use_uppercase: bool = True
    use_lowercase: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    avoid_ambiguous: bool = True
    capitalise: bool = False
    append_number: bool = False


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.post("/api/analyze", tags=["analysis"], summary="Analyze a password in memory")
def api_analyze(payload: AnalyzeRequestModel, request: Request):
    client_key = request.client.host if request.client else "unknown"
    allowed, retry_after = analyze_limiter.check(client_key)
    if not allowed:
        raise HTTPException(status_code=429, detail=f"Too many requests. Retry in {retry_after:.1f}s.",
                            headers={"Retry-After": str(int(retry_after) + 1)})

    policy = PasswordPolicy.from_dict(payload.policy) if payload.policy else None
    result = analyze_password(payload.password, context=payload.context, policy=policy,
                              include_hygiene=payload.include_hygiene)
    if ANALYTICS_ENABLED:
        record_analysis(result)
    log_analysis_metadata(
        __import__("backend.utils.logging_config", fromlist=["x"]).get_logger(),
        analysis_id=result["analysis_id"], score=result["score"],
        classification=result["classification"], length=result["metrics"]["length"],
        duration_ms=result["duration_ms"],
    )
    return result


@app.post("/api/generate-password", tags=["generation"],
          summary="Generate a random password or passphrase (secrets module)")
def api_generate(payload: GenerateRequestModel, request: Request):
    client_key = request.client.host if request.client else "unknown"
    allowed, retry_after = generate_limiter.check(client_key, cost=2.0)
    if not allowed:
        raise HTTPException(status_code=429, detail=f"Too many requests. Retry in {retry_after:.1f}s.")

    if payload.mode == "passphrase":
        return generate_passphrase(words=payload.words, separator=payload.separator,
                                   capitalise=payload.capitalise,
                                   append_number=payload.append_number)
    return generate_password(
        length=payload.length, use_uppercase=payload.use_uppercase,
        use_lowercase=payload.use_lowercase, use_digits=payload.use_digits,
        use_symbols=payload.use_symbols, avoid_ambiguous=payload.avoid_ambiguous,
    )


@app.get("/api/dashboard/stats", tags=["analytics"], summary="Aggregate demo statistics")
def api_stats():
    return get_dashboard_stats()


@app.get("/api/analytics/weaknesses", tags=["analytics"], summary="Weakness frequency table")
def api_weaknesses():
    stats = get_dashboard_stats()
    return {"weakness_frequency": stats.get("weakness_frequency", []),
            "pattern_frequency": stats.get("pattern_frequency", []),
            "total_analyses": stats.get("total_analyses", 0)}


@app.get("/api/analytics/recent", tags=["analytics"], summary="Recent metadata rows")
def api_recent(limit: int = 20):
    limit = max(1, min(limit, 100))
    return {"recent": get_recent_analyses(limit=limit), "limit": limit}


@app.post("/api/analytics/reset", tags=["analytics"], summary="Clear aggregate metadata")
def api_reset():
    reset_analytics()
    return {"status": "cleared"}


@app.get("/api/policy/presets", tags=["policy"], summary="Administrator policy presets")
def api_policy_presets():
    return {"presets": {key: policy.to_dict() for key, policy in PRESET_POLICIES.items()}}


@app.get("/api/education/hashing-demo", tags=["education"],
         summary="Synthetic password-hashing walk-through")
def api_hashing_demo():
    return demonstration()


@app.get("/api/schema", tags=["meta"], summary="Machine-readable API contract")
def api_schema_endpoint():
    return api_schema()


@app.get("/api/health", tags=["meta"])
def api_health():
    return {"status": "ok", "version": "1.0.0", "analytics_storage_enabled": ANALYTICS_ENABLED,
            "stores_passwords": False, "logs_passwords": False,
            "sends_passwords_externally": False}


@app.exception_handler(Exception)
async def unhandled_exception_handler(_request: Request, exc: Exception):   # pragma: no cover
    # Never include exception details that could contain user input.
    return JSONResponse(status_code=500,
                        content={"error": "Internal error.", "code": "internal_error",
                                 "type": type(exc).__name__})
