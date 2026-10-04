"""
backend/utils/logging_config.py
--------------------------------------------------------------------------
PURPOSE
    Configure application logging with an explicit *secret redaction* filter.

THE PROBLEM THIS SOLVES
    "We promise not to log passwords" is a promise. This module turns the
    promise into a control:

      1. A logging.Filter walks every record's message and arguments.
      2. Anything that looks like a password field (password=, "password":,
         pwd=, passphrase=, token=, secret=) is replaced with [REDACTED].
      3. A test in tests/test_security_privacy.py asserts that a password
         passed through the logger never appears in the captured output.

    It is defence in depth: the code paths are written so that passwords never
    reach the logger, and the filter catches us if a future edit changes that.
--------------------------------------------------------------------------
"""

from __future__ import annotations

import logging
import re
import sys
from typing import Any, Iterable

# ---------------------------------------------------------------------------
# Patterns that indicate a secret is about to be written to a log
# ---------------------------------------------------------------------------
SECRET_PATTERNS: Iterable[re.Pattern] = [
    re.compile(r"(?i)\b(password|passwd|pwd|passphrase|secret|token|api[_-]?key)\b\s*[=:]\s*(\"[^\"]*\"|'[^']*'|\S+)"),
    re.compile(r"(?i)(\"(?:password|passphrase|secret|token)\"\s*:\s*\")([^\"]*)(\")"),
    re.compile(r"(?i)\b(Bearer)\s+[A-Za-z0-9\-._~+/]+=*"),
]

REDACTED = "[REDACTED]"


def redact(text: str) -> str:
    """Return `text` with anything that looks like a secret replaced."""
    if not isinstance(text, str):
        return text
    cleaned = text
    for pattern in SECRET_PATTERNS:
        if pattern.groups >= 3:
            # key/value pair inside JSON: keep the key, drop the value
            cleaned = pattern.sub(lambda m: f"{m.group(1)}{REDACTED}{m.group(3)}", cleaned)
        elif pattern.groups == 2:
            cleaned = pattern.sub(lambda m: f"{m.group(1)}={REDACTED}", cleaned)
        else:
            cleaned = pattern.sub(lambda m: f"{m.group(1)} {REDACTED}", cleaned)
    return cleaned


class SecretRedactionFilter(logging.Filter):
    """
    A logging.Filter that scrubs secrets out of `record.msg` and
    `record.args` before the record is formatted.
    """

    def filter(self, record: logging.LogRecord) -> bool:       # noqa: A003
        try:
            if isinstance(record.msg, str):
                record.msg = redact(record.msg)
            if record.args:
                if isinstance(record.args, dict):
                    record.args = {k: redact(v) if isinstance(v, str) else v
                                   for k, v in record.args.items()}
                elif isinstance(record.args, tuple):
                    record.args = tuple(redact(a) if isinstance(a, str) else a for a in record.args)
        except Exception:            # never let logging break the request
            pass
        return True


def configure_logging(level: int = logging.INFO) -> logging.Logger:
    """
    Configure and return the project logger.

    Details that matter for this project:
      * Passwords are never passed as attributes via `extra=` in our code.
      * The redaction filter is attached to the handler, so it applies to
        everything the app logs.
      * `logging.raiseExceptions = False` keeps a logging failure from
        surfacing to the user as an error page.
    """
    logger = logging.getLogger("psa")           # Password Strength Analyzer
    if logger.handlers:                          # already configured
        return logger

    logger.setLevel(level)
    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(logging.Formatter(
        fmt="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    ))
    handler.addFilter(SecretRedactionFilter())
    logger.addFilter(SecretRedactionFilter())
    logger.addHandler(handler)
    logger.propagate = False
    logging.raiseExceptions = False
    return logger


def get_logger() -> logging.Logger:
    """Convenience accessor used across the backend modules."""
    return configure_logging()


# A deliberately narrow audit helper: it can only log METADATA, because the
# signature does not accept a password at all.
def log_analysis_metadata(logger: logging.Logger, analysis_id: str, score: int,
                          classification: str, length: int, duration_ms: float) -> None:
    """
    Log only non-secret aggregate values about one analysis.

    Notice: there is no parameter for the password, so a future developer
    cannot accidentally log it through this function.
    """
    logger.info(
        "analysis id=%s score=%s classification=%s length=%s duration_ms=%s",
        analysis_id, score, classification, length, duration_ms,
    )
