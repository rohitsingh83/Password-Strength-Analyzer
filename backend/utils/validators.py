"""
backend/utils/validators.py
--------------------------------------------------------------------------
PURPOSE
    Request validation helpers that never echo the submitted value and never
    put it into an error message, an exception, or a URL.

DESIGN
    * Validation returns structured errors ({"field": ..., "code": ...}) rather
      than strings built from user input.
    * The maximum accepted length protects the service from having to do
      expensive work on a 10 MB "password" (a denial-of-service vector), not
      because long passwords are insecure.
    * Length is measured in Unicode code points, which is what every modern
      password-hashing library and policy framework does.
--------------------------------------------------------------------------
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------
MAX_PASSWORD_LENGTH = 256        # generous; NIST requires support for at least 64
MIN_PASSWORD_LENGTH = 0          # 0 is allowed so the UI can show a "start typing" state
MAX_CONTEXT_FIELD_LENGTH = 64    # first name, birth year, org name
MAX_CONTEXT_FIELDS = 8
ALLOWED_CONTEXT_FIELDS = {
    "first_name", "last_name", "username", "email",
    "birth_year", "organisation", "company", "college",
}
ALLOWED_POLICY_FIELDS = {
    "name", "minimum_length", "maximum_supported_length", "common_password_check",
    "personal_info_check", "require_uppercase", "require_lowercase", "require_digit",
    "require_symbol", "allow_spaces", "min_unique_characters", "reject_breached",
    "password_expiry_days", "minimum_strength_score",
}


def validate_password_payload(payload: Any) -> Dict:
    """
    Validate the body of POST /api/analyze.

    Returns:
        {
          "ok": bool,
          "password": str,          # only present when ok
          "context": dict|None,
          "errors": [ {field, code, message}, ... ]
        }
    """
    errors: List[Dict[str, str]] = []

    if not isinstance(payload, dict):
        return {
            "ok": False,
            "errors": [{"field": "body", "code": "not_an_object",
                        "message": "Request body must be a JSON object."}],
        }

    password = payload.get("password")
    if password is None:
        errors.append({"field": "password", "code": "missing",
                       "message": "Field 'password' is required."})
    elif not isinstance(password, str):
        errors.append({"field": "password", "code": "wrong_type",
                       "message": "Field 'password' must be a string."})
    elif len(password) > MAX_PASSWORD_LENGTH:
        errors.append({
            "field": "password", "code": "too_long",
            "message": f"Field 'password' must be at most {MAX_PASSWORD_LENGTH} characters "
                       f"(received {len(password)}).",
        })

    context = payload.get("context")
    clean_context: Optional[Dict[str, str]] = None
    if context is not None:
        if not isinstance(context, dict):
            errors.append({"field": "context", "code": "wrong_type",
                           "message": "Field 'context' must be an object."})
        elif len(context) > MAX_CONTEXT_FIELDS:
            errors.append({"field": "context", "code": "too_many_fields",
                           "message": f"At most {MAX_CONTEXT_FIELDS} context fields are accepted."})
        else:
            clean_context = {}
            for key, value in context.items():
                if key not in ALLOWED_CONTEXT_FIELDS:
                    continue                     # ignore unknown keys instead of failing
                if value is None:
                    continue
                if not isinstance(value, (str, int)):
                    errors.append({"field": f"context.{key}", "code": "wrong_type",
                                   "message": "Context values must be text or numbers."})
                    continue
                text = str(value).strip()
                if len(text) > MAX_CONTEXT_FIELD_LENGTH:
                    errors.append({
                        "field": f"context.{key}", "code": "too_long",
                        "message": f"Context field '{key}' must be at most "
                                   f"{MAX_CONTEXT_FIELD_LENGTH} characters.",
                    })
                    continue
                if text:
                    clean_context[key] = text

    if errors:
        return {"ok": False, "errors": errors}

    return {"ok": True, "password": password, "context": clean_context, "errors": []}


def validate_policy_payload(payload: Any) -> Dict:
    """
    Validate an optional policy override. Unknown fields are ignored so a
    client can pass back a policy object it previously received.
    """
    if payload is None:
        return {"ok": True, "policy": None, "errors": []}
    if not isinstance(payload, dict):
        return {"ok": False, "errors": [{"field": "policy", "code": "wrong_type",
                                         "message": "Field 'policy' must be an object."}],
                "policy": None}

    int_fields = {
        "minimum_length": (1, 256),
        "maximum_supported_length": (8, 1024),
        "min_unique_characters": (1, 64),
        "password_expiry_days": (0, 3650),
        "minimum_strength_score": (0, 100),
    }
    bool_fields = {
        "common_password_check", "personal_info_check", "require_uppercase",
        "require_lowercase", "require_digit", "require_symbol", "allow_spaces",
        "reject_breached",
    }

    errors: List[Dict[str, str]] = []
    clean: Dict[str, Any] = {}

    for key, value in payload.items():
        if key not in ALLOWED_POLICY_FIELDS:
            continue
        if key == "name":
            clean["name"] = str(value)[:120]
        elif key in bool_fields:
            if isinstance(value, bool):
                clean[key] = value
            else:
                errors.append({"field": f"policy.{key}", "code": "wrong_type",
                               "message": f"Policy field '{key}' must be true or false."})
        elif key in int_fields:
            low, high = int_fields[key]
            try:
                number = int(value)
            except (TypeError, ValueError):
                errors.append({"field": f"policy.{key}", "code": "wrong_type",
                               "message": f"Policy field '{key}' must be a whole number."})
                continue
            if not low <= number <= high:
                errors.append({"field": f"policy.{key}", "code": "out_of_range",
                               "message": f"Policy field '{key}' must be between {low} and {high}."})
                continue
            clean[key] = number

    if errors:
        return {"ok": False, "errors": errors, "policy": None}
    return {"ok": True, "policy": clean, "errors": []}


def validate_generation_request(payload: Any) -> Dict:
    """Validate POST /api/generate-password."""
    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        return {"ok": False, "errors": [{"field": "body", "code": "not_an_object",
                                         "message": "Request body must be a JSON object."}]}

    mode = str(payload.get("mode", "password")).lower()
    if mode not in ("password", "passphrase"):
        return {"ok": False, "errors": [{"field": "mode", "code": "invalid",
                                         "message": "Mode must be 'password' or 'passphrase'."}]}

    def as_int(value: Any, default: int) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    if mode == "passphrase":
        words = as_int(payload.get("words", 4), 4)
        if not 3 <= words <= 10:
            return {"ok": False, "errors": [{"field": "words", "code": "out_of_range",
                                             "message": "Words must be between 3 and 10."}]}
        separator = str(payload.get("separator", "-"))[:3] or "-"
        return {
            "ok": True,
            "request": {
                "mode": "passphrase", "words": words, "separator": separator,
                "capitalise": bool(payload.get("capitalise", False)),
                "append_number": bool(payload.get("append_number", False)),
            },
            "errors": [],
        }

    length = as_int(payload.get("length", 16), 16)
    if not 8 <= length <= 128:
        return {"ok": False, "errors": [{"field": "length", "code": "out_of_range",
                                         "message": "Length must be between 8 and 128."}]}
    return {
        "ok": True,
        "request": {
            "mode": "password", "length": length,
            "use_uppercase": bool(payload.get("use_uppercase", True)),
            "use_lowercase": bool(payload.get("use_lowercase", True)),
            "use_digits": bool(payload.get("use_digits", True)),
            "use_symbols": bool(payload.get("use_symbols", True)),
            "avoid_ambiguous": bool(payload.get("avoid_ambiguous", True)),
        },
        "errors": [],
    }
