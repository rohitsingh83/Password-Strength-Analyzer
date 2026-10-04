"""
backend/routes/analyze.py
--------------------------------------------------------------------------
PURPOSE
    POST /api/analyze -- the main endpoint.

SECURITY BEHAVIOUR OF THIS ROUTE
    * The request body is validated before any analysis runs.
    * The password is handled in memory only, is never logged, is never
      written to the database, never placed in a URL and never returned.
    * Rate limited per client.
    * Errors return a structured JSON error object that contains NO user input.
--------------------------------------------------------------------------
"""

from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request

from ..services.audit_store import ANALYTICS_ENABLED, record_analysis
from ..services.password_analyzer import analyze_password
from ..services.policy_checker import PasswordPolicy
from ..utils.logging_config import log_analysis_metadata
from ..utils.rate_limiter import analyze_limiter
from ..utils.validators import MAX_PASSWORD_LENGTH, validate_password_payload, validate_policy_payload

analyze_bp = Blueprint("analyze", __name__, url_prefix="/api")


@analyze_bp.post("/analyze")
def api_analyze():
    """
    Analyze a password and return score, classification, findings, suggestions,
    metrics, entropy, scoring breakdown, policy verdict and guess-resistance
    estimate.

    Request:
        {"password": "...", "context": {...}, "policy": {...}, "include_hygiene": true}

    Response 200:
        {"score": 74, "classification": "STRONG", "findings": [...],
         "suggestions": [...], "metrics": {...}, ...}
    """
    logger = current_app.config["PSA_LOGGER"]

    # ---- rate limit ------------------------------------------------------
    client_key = request.remote_addr or "unknown"
    allowed, retry_after = analyze_limiter.check(client_key)
    if not allowed:
        logger.warning("rate_limited endpoint=/api/analyze client=%s", client_key)
        response = jsonify({
            "error": "Too many requests.",
            "code": "rate_limited",
            "details": [{"field": "request", "code": "rate_limited",
                         "message": f"Try again in about {retry_after:.1f} seconds."}],
        })
        response.status_code = 429
        response.headers["Retry-After"] = str(int(retry_after) + 1)
        return response

    # ---- parse & validate ------------------------------------------------
    payload = request.get_json(silent=True)
    if payload is None:
        return jsonify({
            "error": "Request body must be valid JSON.",
            "code": "invalid_json",
            "details": [],
        }), 400

    validation = validate_password_payload(payload)
    if not validation["ok"]:
        # Note: validation messages quote only field names and limits, never values.
        return jsonify({"error": "Validation failed.", "code": "validation_error",
                        "details": validation["errors"]}), 400

    policy_validation = validate_policy_payload(payload.get("policy"))
    if not policy_validation["ok"]:
        return jsonify({"error": "Policy validation failed.", "code": "validation_error",
                        "details": policy_validation["errors"]}), 400

    policy = PasswordPolicy.from_dict(policy_validation["policy"]) if policy_validation["policy"] else None

    # ---- analyze (the password lives only inside this call) --------------
    result = analyze_password(
        password=validation["password"],
        context=validation["context"],
        policy=policy,
        include_hygiene=bool(payload.get("include_hygiene", True)),
    )

    # ---- optional aggregate analytics (metadata only) --------------------
    if ANALYTICS_ENABLED and current_app.config.get("PSA_STORE_ANALYTICS", True):
        try:
            record_analysis(result)
        except Exception as exc:                 # analytics must never break analysis
            logger.warning("analytics_write_failed error_type=%s", type(exc).__name__)

    # ---- log metadata only (never the password) --------------------------
    log_analysis_metadata(
        logger,
        analysis_id=result["analysis_id"],
        score=result["score"],
        classification=result["classification"],
        length=result["metrics"].get("length", 0),
        duration_ms=result["duration_ms"],
    )

    return jsonify(result), 200
