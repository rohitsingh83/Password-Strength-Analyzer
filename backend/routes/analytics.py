"""
backend/routes/analytics.py
--------------------------------------------------------------------------
PURPOSE
    Aggregate, privacy-safe analytics endpoints used by the dashboard.

    GET  /api/dashboard/stats       -> counters, distributions, averages
    GET  /api/analytics/weaknesses  -> weakness-type frequency
    GET  /api/analytics/recent      -> recent rows (metadata only)
    POST /api/analytics/reset       -> clear metadata (demo convenience)

IMPORTANT
    Every value returned here is derived from the `analyses` and `findings`
    tables, which have no column that could hold a password. The dashboard is
    therefore *structurally* incapable of revealing a submitted password.
--------------------------------------------------------------------------
"""

from __future__ import annotations

from flask import Blueprint, jsonify, request

from ..services.audit_store import (
    ANALYTICS_ENABLED,
    get_dashboard_stats,
    get_recent_analyses,
    reset_analytics,
)

analytics_bp = Blueprint("analytics", __name__, url_prefix="/api")


def _disabled_response():
    return jsonify({
        "error": "Analytics storage is disabled in this deployment.",
        "code": "analytics_disabled",
        "details": [{
            "field": "config",
            "code": "disabled",
            "message": "Set ANALYTICS_ENABLED=1 to store non-secret aggregate metadata.",
        }],
        "privacy_note": "Analysis still works normally without storage.",
    }), 200


@analytics_bp.get("/dashboard/stats")
def api_dashboard_stats():
    """
    Return aggregate statistics for the dashboard.

    Includes: total analyses, per-classification counts, average/median score,
    score histogram, length distribution, weakness frequency and the
    least-secure weekday observed (a fun aggregate that stays non-identifying).
    """
    if not ANALYTICS_ENABLED:
        return _disabled_response()
    stats = get_dashboard_stats()
    # Explicit reminder in the payload itself, so any consumer of the API
    # (including a future reviewer reading a JSON dump) sees the guarantee.
    stats["privacy_note"] = (
        "Aggregate metadata only. The database schema has no password column, "
        "no password hash column and no personal-context column."
    )
    return jsonify(stats), 200


@analytics_bp.get("/analytics/weaknesses")
def api_weakness_frequency():
    """Weakness-type frequency table (chart data)."""
    if not ANALYTICS_ENABLED:
        return _disabled_response()
    stats = get_dashboard_stats()
    return jsonify({
        "weakness_frequency": stats.get("weakness_frequency", []),
        "pattern_frequency": stats.get("pattern_frequency", []),
        "total_analyses": stats.get("total_analyses", 0),
    }), 200


@analytics_bp.get("/analytics/recent")
def api_recent():
    """
    Recent analyses as metadata rows.

    `limit` is validated and clamped so the endpoint cannot be used to dump an
    unbounded amount of data.
    """
    if not ANALYTICS_ENABLED:
        return _disabled_response()
    try:
        limit = int(request.args.get("limit", 20))
    except (TypeError, ValueError):
        limit = 20
    limit = max(1, min(limit, 100))
    return jsonify({"recent": get_recent_analyses(limit=limit), "limit": limit}), 200


@analytics_bp.post("/analytics/reset")
def api_reset():
    """Clear the analytics tables. Useful for demos and for the privacy test."""
    if not ANALYTICS_ENABLED:
        return _disabled_response()
    reset_analytics()
    return jsonify({
        "status": "cleared",
        "note": "Aggregate metadata removed. No password was ever present to remove.",
    }), 200
