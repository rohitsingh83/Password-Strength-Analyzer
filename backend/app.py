"""
backend/app.py
--------------------------------------------------------------------------
PURPOSE
    Flask application factory and entry point.

RUN IT
    python backend/app.py                    (development, http://127.0.0.1:5000)
    flask --app backend.app run --debug      (alternative)
    gunicorn "backend.app:create_app()"      (production-style)

WHAT THIS FILE DELIBERATELY DOES NOT DO
    * It does not configure request logging of bodies. Flask's default
      development logger prints the request line (method + path + status),
      and our routes never put a password in the path or query string.
    * It does not enable a debug toolbar, an ORM auto-log, or anything that
      could echo request payloads.
--------------------------------------------------------------------------
"""

from __future__ import annotations

import os
import pathlib
import sys

# Allow `python backend/app.py` and `python -m backend.app` to both work by
# making the project root importable regardless of the current directory.
PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    from flask import Flask, jsonify
except ModuleNotFoundError as exc:                # pragma: no cover
    raise SystemExit(
        "Flask is not installed.\n"
        "Install the project dependencies first:\n\n"
        "    pip install -r requirements.txt\n"
    ) from exc

from backend.routes.analytics import analytics_bp
from backend.routes.analyze import analyze_bp
from backend.routes.generate import generate_bp
from backend.routes.pages import pages_bp
from backend.services.audit_store import ANALYTICS_ENABLED, init_db
from backend.utils.logging_config import configure_logging


def create_app(config: dict | None = None) -> Flask:
    """Build and configure the Flask application."""
    app = Flask(__name__, static_folder=None)     # we serve the front-end ourselves
    app.config.update(
        MAX_CONTENT_LENGTH=int(os.environ.get("MAX_CONTENT_LENGTH", 64 * 1024)),  # 64 KB
        JSON_SORT_KEYS=False,
        PSA_FRONTEND_DIR=str(PROJECT_ROOT / "frontend"),
        PSA_LOGGER=configure_logging(),
        PSA_STORE_ANALYTICS=os.environ.get("STORE_ANALYTICS", "1") not in ("0", "false"),
        PROPAGATE_EXCEPTIONS=False,
    )
    if config:
        app.config.update(config)

    if ANALYTICS_ENABLED and app.config["PSA_STORE_ANALYTICS"]:
        init_db()

    # ---- blueprints ------------------------------------------------------
    app.register_blueprint(pages_bp)
    app.register_blueprint(analyze_bp)
    app.register_blueprint(generate_bp)
    app.register_blueprint(analytics_bp)

    # ---- error handlers: JSON only, and never echo user input ------------
    @app.errorhandler(400)
    def bad_request(_error):
        return jsonify({"error": "Bad request.", "code": "bad_request", "details": []}), 400

    @app.errorhandler(404)
    def not_found(_error):
        return jsonify({"error": "Not found.", "code": "not_found", "details": []}), 404

    @app.errorhandler(405)
    def method_not_allowed(_error):
        return jsonify({"error": "Method not allowed.", "code": "method_not_allowed",
                        "details": []}), 405

    @app.errorhandler(413)
    def payload_too_large(_error):
        return jsonify({
            "error": "Request body too large.",
            "code": "payload_too_large",
            "details": [{"field": "body", "code": "too_large",
                         "message": "The request body exceeded the allowed size."}],
        }), 413

    @app.errorhandler(Exception)
    def unhandled(error):                          # pragma: no cover - safety net
        # Log the exception TYPE only. Exception messages can contain values,
        # so we never log str(error) for this endpoint.
        app.config["PSA_LOGGER"].error("unhandled_exception type=%s", type(error).__name__)
        return jsonify({
            "error": "Internal error.",
            "code": "internal_error",
            "details": [{"field": "server", "code": "internal_error",
                         "message": "Something went wrong while processing the request."}],
        }), 500

    return app


app = create_app()


if __name__ == "__main__":       # pragma: no cover
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "0.0.0.0")
    print("=" * 78)
    print("Password Strength Analyzer & Security Suggestion Tool")
    print("=" * 78)
    print(f"  URL                : http://127.0.0.1:{port}")
    print(f"  Analytics storage  : {'enabled (metadata only)' if ANALYTICS_ENABLED else 'disabled'}")
    print("  Passwords stored   : no")
    print("  Passwords logged   : no")
    print("  External calls     : none")
    print("  Try the API        : curl -s -X POST http://127.0.0.1:%d/api/analyze \\" % port)
    print('                         -H "Content-Type: application/json" \\')
    print('                         -d \'{"password":"Demo-Pattern-123!"}\' | head -40')
    print("=" * 78)
    app.run(host=host, port=port, debug=os.environ.get("FLASK_DEBUG", "0") == "1")
