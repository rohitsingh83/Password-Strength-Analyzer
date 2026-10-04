"""
backend/routes/pages.py
--------------------------------------------------------------------------
PURPOSE
    Serve the front-end and provide read-only informational endpoints
    (health, policy presets, API schema, education content).

SECURITY HEADERS
    The HTML/CSS/JS build is a single-page app. We set a small set of headers
    that matter for a security project:
        Content-Security-Policy  -- no inline script execution except what we ship
        X-Content-Type-Options   -- stop MIME sniffing
        X-Frame-Options          -- clickjacking protection
        Referrer-Policy          -- do not leak URLs to third parties
        Cache-Control            -- never cache an analysis response
    Note: the password never appears in a URL, so there is no query string to
    leak -- but the headers are still good practice for the pages themselves.
--------------------------------------------------------------------------
"""

from __future__ import annotations

from flask import Blueprint, current_app, jsonify, send_from_directory

from ..models.schemas import api_schema
from ..services.audit_store import ANALYTICS_ENABLED
from ..services.policy_checker import PRESET_POLICIES

pages_bp = Blueprint("pages", __name__)


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------
@pages_bp.after_app_request
def add_security_headers(response):       # pragma: no cover - exercised via tests
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault(
        "Permissions-Policy", "geolocation=(), microphone=(), camera=()"
    )
    # 'unsafe-inline' for styles only: the UI ships a small amount of inline
    # style for the live meter, and there is no third-party content at all.
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; form-action 'none'; "
        "base-uri 'none'; frame-ancestors 'none'",
    )
    if response.mimetype == "text/html":
        response.headers.setdefault("Cache-Control", "no-store")
    return response


# ---------------------------------------------------------------------------
# Static front-end
# ---------------------------------------------------------------------------
@pages_bp.get("/")
def index():
    """Serve the single-page front-end."""
    return send_from_directory(current_app.config["PSA_FRONTEND_DIR"], "index.html")


@pages_bp.get("/<path:filename>")
def static_files(filename: str):
    """Serve CSS/JS/assets from the frontend directory."""
    return send_from_directory(current_app.config["PSA_FRONTEND_DIR"], filename)


# ---------------------------------------------------------------------------
# Informational endpoints
# ---------------------------------------------------------------------------
@pages_bp.get("/api/health")
def api_health():
    """
    Liveness probe plus a summary of privacy-relevant configuration.

    Reports whether analytics storage is on -- never any secret.
    """
    return jsonify({
        "status": "ok",
        "version": "1.0.0",
        "analytics_storage_enabled": ANALYTICS_ENABLED,
        "stores_passwords": False,
        "logs_passwords": False,
        "sends_passwords_externally": False,
        "endpoints": ["/api/analyze", "/api/generate-password", "/api/dashboard/stats",
                      "/api/analytics/weaknesses", "/api/analytics/recent",
                      "/api/analytics/reset", "/api/policy/presets",
                      "/api/education/hashing-demo", "/api/schema"],
    }), 200


@pages_bp.get("/api/policy/presets")
def api_policy_presets():
    """Return the administrator policy presets (no user data involved)."""
    return jsonify({
        "presets": {key: policy.to_dict() for key, policy in PRESET_POLICIES.items()},
        "guidance": [
            "Prefer minimum length over mandatory composition rules (NIST SP 800-63B).",
            "Allow long passwords and spaces; do not truncate.",
            "Block known-common and known-breached passwords at registration.",
            "Avoid forced periodic expiry unless a policy or incident requires it.",
            "Report POLICY PASS/FAIL separately from the strength score.",
        ],
    }), 200


@pages_bp.get("/api/schema")
def api_schema_endpoint():
    """Machine-readable API contract, including the privacy summary."""
    return jsonify(api_schema()), 200


@pages_bp.get("/api/education/content")
def api_education_content():
    """
    Static educational content for the awareness section.

    Kept server-side so the front-end can render it without hard-coding prose,
    and so the same text can be reused in the report.
    """
    return jsonify({
        "rules": [
            {"title": "Use a unique password for every account",
             "why": "Reuse turns one breach into many compromised accounts through credential stuffing."},
            {"title": "Prefer length over clever substitutions",
             "why": "Each extra character multiplies the work; '@' for 'a' does almost nothing."},
            {"title": "Avoid personal information",
             "why": "Names, birth years and organisations are discoverable and are tried first."},
            {"title": "Avoid common passwords and phrases",
             "why": "They occupy the first few thousand entries of every attack wordlist."},
            {"title": "Never reuse a password across sites",
             "why": "A single leaked database becomes a master key for your other accounts."},
            {"title": "Use a password manager",
             "why": "It generates and stores unique passwords so you only memorise one strong secret."},
            {"title": "Enable MFA wherever it is offered",
             "why": "MFA keeps an account safe even when the password leaks."},
            {"title": "Never share a password",
             "why": "Sharing destroys accountability and usually spreads via insecure channels."},
            {"title": "Be sceptical of links and login pages",
             "why": "Phishing bypasses strength entirely by asking you to type into a fake page."},
            {"title": "Change a password when compromise is suspected",
             "why": "Modern guidance: rotate on evidence of compromise, not on a calendar."},
        ],
        "mfa_note": (
            "Password strength is one layer of authentication security. Rate limiting, secure "
            "password hashing, account lockout, session protection, phishing defence and "
            "monitoring are equally part of a real login system."
        ),
    }), 200
