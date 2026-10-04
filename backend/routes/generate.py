"""
backend/routes/generate.py
--------------------------------------------------------------------------
PURPOSE
    POST /api/generate-password and GET /api/education/hashing-demo.

PRIVACY BEHAVIOUR
    * The generated password is returned to the caller and then forgotten.
      It is not cached, not stored, not logged and not included in analytics.
    * Only *properties* of the generation (length, entropy estimate, class
      count) may be recorded, and only when analytics are enabled.
--------------------------------------------------------------------------
"""

from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request

from ..services.audit_store import ANALYTICS_ENABLED, record_generation
from ..services.password_generator import generate_passphrase, generate_password
from ..services.password_hashing_demo import demonstration, argon2id_guidance
from ..utils.rate_limiter import generate_limiter
from ..utils.validators import validate_generation_request

generate_bp = Blueprint("generate", __name__, url_prefix="/api")


@generate_bp.post("/generate-password")
def api_generate_password():
    """
    Generate a password or passphrase with Python's `secrets` module.

    Request (password mode):
        {"mode": "password", "length": 20, "use_uppercase": true, ...}
    Request (passphrase mode):
        {"mode": "passphrase", "words": 5, "separator": "-"}

    Response:
        {"password": "...", "length": 20, "entropy_bits": 131.1, ...}
    """
    logger = current_app.config["PSA_LOGGER"]
    client_key = request.remote_addr or "unknown"
    allowed, retry_after = generate_limiter.check(client_key, cost=2.0)
    if not allowed:
        response = jsonify({
            "error": "Too many generation requests.",
            "code": "rate_limited",
            "details": [{"field": "request", "code": "rate_limited",
                         "message": f"Try again in about {retry_after:.1f} seconds."}],
        })
        response.status_code = 429
        response.headers["Retry-After"] = str(int(retry_after) + 1)
        return response

    payload = request.get_json(silent=True)
    validation = validate_generation_request(payload)
    if not validation["ok"]:
        return jsonify({"error": "Validation failed.", "code": "validation_error",
                        "details": validation["errors"]}), 400

    spec = validation["request"]
    if spec["mode"] == "passphrase":
        result = generate_passphrase(
            words=spec["words"], separator=spec["separator"],
            capitalise=spec["capitalise"], append_number=spec["append_number"],
        )
    else:
        result = generate_password(
            length=spec["length"], use_uppercase=spec["use_uppercase"],
            use_lowercase=spec["use_lowercase"], use_digits=spec["use_digits"],
            use_symbols=spec["use_symbols"], avoid_ambiguous=spec["avoid_ambiguous"],
        )

    # Record only the SHAPE of what was produced -- never the value itself.
    if ANALYTICS_ENABLED:
        try:
            record_generation({
                "generator": result.get("generator", "unknown"),
                "length": result.get("length", 0),
                "entropy_bits": result.get("entropy_bits", 0.0),
                "classes_used": result.get("classes_used", []),
            })
        except Exception as exc:                 # never break generation for analytics
            logger.warning("generation_analytics_failed error_type=%s", type(exc).__name__)

    # Log the shape, not the secret.
    logger.info(
        "generated mode=%s length=%s entropy_bits=%s",
        spec["mode"], result.get("length", 0), result.get("entropy_bits", 0.0),
    )

    return jsonify(result), 200


@generate_bp.get("/education/hashing-demo")
def api_hashing_demo():
    """
    Return the SEPARATE password-hashing teaching demonstration.

    It uses a hard-coded synthetic value only, and it is never fed by the
    analyzer, so a real user's password cannot reach it.
    """
    algorithms = request.args.get("algorithms")
    chosen = [a for a in (algorithms.split(",") if algorithms else [])
              if a in ("scrypt", "pbkdf2", "sha256_fast", "md5_fast")] or None
    return jsonify({
        "demonstration": demonstration(algorithms=chosen),
        "recommended_modern_option": argon2id_guidance(),
        "isolation_note": (
            "This demonstration is completely separate from the analyzer and accepts only "
            "synthetic demo values. Nothing typed into the analyzer is ever passed here."
        ),
    }), 200
