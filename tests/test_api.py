"""
tests/test_api.py
--------------------------------------------------------------------------
REST API tests: contract, validation, status codes, error handling and the
response guarantees (no password is ever echoed, and never in a URL).
"""

from __future__ import annotations

import json


def test_analyze_endpoint_contract(flask_client):
    """POST /api/analyze returns score, classification, findings, suggestions, metrics."""
    response = flask_client.post("/api/analyze",
                                 json={"password": "Demo-Pattern-2026!"})
    assert response.status_code == 200
    payload = response.get_json()
    assert set(payload) >= {"score", "classification", "findings", "suggestions", "metrics"}
    assert isinstance(payload["score"], int)
    assert payload["classification"] in {"VERY WEAK", "WEAK", "MODERATE", "STRONG", "VERY STRONG"}


def test_response_never_echoes_password(flask_client, demo):
    """A high-entropy probe value must not appear anywhere in the response body."""
    probe = demo["probe"]
    response = flask_client.post("/api/analyze", json={"password": probe})
    body = response.get_data(as_text=True)
    assert probe not in body
    assert response.get_json()["privacy"]["password_returned_in_response"] is False


def test_evidence_is_masked_in_api(flask_client):
    """All finding evidence in the API response is bullet-masked."""
    response = flask_client.post("/api/analyze", json={"password": "qwerty2026!"})
    for finding in response.get_json()["findings"]:
        evidence = finding.get("evidence", "")
        assert set(evidence) <= {"\u2022"}, evidence


def test_password_never_in_url(flask_client, demo):
    """The password travels in the JSON body, never in the path or query string."""
    probe = demo["probe"]
    response = flask_client.post("/api/analyze", json={"password": probe})
    assert probe not in response.request.path
    assert probe not in (response.request.query_string or b"").decode()


def test_missing_password_field(flask_client):
    """A body without a password returns 400 with a structured error."""
    response = flask_client.post("/api/analyze", json={})
    assert response.status_code == 400
    payload = response.get_json()
    assert payload["code"] == "validation_error"
    assert payload["details"][0]["field"] == "password"


def test_wrong_type_is_rejected(flask_client):
    """Non-string values are rejected instead of coerced."""
    response = flask_client.post("/api/analyze", json={"password": 12345})
    assert response.status_code == 400
    assert response.get_json()["details"][0]["code"] == "wrong_type"


def test_invalid_json_is_rejected(flask_client):
    """Malformed JSON returns 400, not a stack trace."""
    response = flask_client.post("/api/analyze", data="not json",
                                 content_type="application/json")
    assert response.status_code == 400
    assert response.get_json()["code"] in ("invalid_json", "bad_request")


def test_over_length_is_rejected_without_echoing(flask_client, demo):
    """Too-long values are refused politely, and the value is not repeated back."""
    over = demo["over_length"]
    response = flask_client.post("/api/analyze", json={"password": over})
    assert response.status_code == 400
    body = response.get_data(as_text=True)
    assert "too_long" in body
    assert over not in body


def test_empty_password_is_accepted_as_a_state(flask_client):
    """An empty value returns a helpful 200 state so the live meter can render."""
    response = flask_client.post("/api/analyze", json={"password": ""})
    assert response.status_code == 200
    assert response.get_json()["classification"] == "VERY WEAK"


def test_policy_override_is_validated(flask_client):
    """An out-of-range policy value is rejected with a field-level error."""
    response = flask_client.post("/api/analyze", json={
        "password": "Demo-Pattern-2026!",
        "policy": {"minimum_length": 9999},
    })
    assert response.status_code == 400
    assert response.get_json()["details"][0]["field"] == "policy.minimum_length"


def test_policy_override_is_applied(flask_client):
    """A valid policy override changes the policy verdict in the response."""
    response = flask_client.post("/api/analyze", json={
        "password": "Demo-Pattern-2026!",
        "policy": {"minimum_length": 64, "min_unique_characters": 20},
    })
    assert response.status_code == 200
    assert response.get_json()["policy"]["policy_pass"] is False


def test_context_is_used_but_not_returned(flask_client, demo_context):
    """Context influences findings while only field names/lengths are reported."""
    response = flask_client.post("/api/analyze",
                                 json={"password": "Demo@1234", "context": demo_context})
    payload = response.get_json()
    assert payload["metrics"]["has_personal_info"] is True
    fingerprints = payload["privacy"]["context_fingerprint_lengths"]
    assert set(fingerprints) == set(demo_context)
    assert demo_context["first_name"] not in response.get_data(as_text=True)
    assert payload["privacy"]["context_stored"] is False


def test_generate_endpoint(flask_client):
    """POST /api/generate-password returns a value plus its properties."""
    response = flask_client.post("/api/generate-password", json={"length": 24})
    payload = response.get_json()
    assert response.status_code == 200
    assert len(payload["password"]) == 24
    assert payload["entropy_bits"] > 100
    note = payload["note"].lower()
    assert "not stored" in note or "never stored" in note or "nothing is stored" in note


def test_generate_passphrase_endpoint(flask_client):
    """Passphrase mode returns a multi-word value."""
    response = flask_client.post("/api/generate-password",
                                 json={"mode": "passphrase", "words": 6})
    payload = response.get_json()
    assert payload["word_count"] == 6
    assert len(payload["password"].split("-")) == 6


def test_generate_validation(flask_client):
    """Bad generation parameters are rejected."""
    assert flask_client.post("/api/generate-password",
                             json={"length": 4}).status_code == 400
    assert flask_client.post("/api/generate-password",
                             json={"mode": "crack"}).status_code == 400


def test_generated_value_not_returned_twice(flask_client):
    """Two consecutive calls must not return the same value."""
    first = flask_client.post("/api/generate-password", json={"length": 20}).get_json()["password"]
    second = flask_client.post("/api/generate-password", json={"length": 20}).get_json()["password"]
    assert first != second


def test_dashboard_stats_endpoint(flask_client):
    """GET /api/dashboard/stats returns aggregates and states the privacy guarantee."""
    flask_client.post("/api/analyze", json={"password": "Demo-Pattern-2026!"})
    response = flask_client.get("/api/dashboard/stats")
    payload = response.get_json()
    assert response.status_code == 200
    assert payload["total_analyses"] >= 1
    assert "distribution" in payload and "score_histogram" in payload
    assert payload["privacy_note"]


def test_weaknesses_endpoint(flask_client):
    """GET /api/analytics/weaknesses returns chart-ready frequency data."""
    flask_client.post("/api/analyze", json={"password": "qwerty123"})
    payload = flask_client.get("/api/analytics/weaknesses").get_json()
    assert "weakness_frequency" in payload
    assert payload["total_analyses"] >= 1


def test_recent_endpoint_limit_is_clamped(flask_client):
    """An absurd limit is clamped instead of dumping everything."""
    payload = flask_client.get("/api/analytics/recent?limit=99999").get_json()
    assert payload["limit"] == 100


def test_recent_rows_contain_no_secret_material(flask_client, demo):
    """Recent metadata rows must not include the value or a hash of it."""
    probe = demo["probe"]
    flask_client.post("/api/analyze", json={"password": probe})
    body = flask_client.get("/api/analytics/recent").get_data(as_text=True)
    assert probe not in body
    for row in flask_client.get("/api/analytics/recent").get_json()["recent"]:
        assert set(row) == {"analysis_id", "score", "classification", "password_length",
                            "weakness_count", "top_weakness", "analyzed_at"}


def test_rate_limiter_returns_429(flask_client):
    """Exceeding the analysis budget returns 429 with Retry-After."""
    from backend.utils.rate_limiter import analyze_limiter
    analyze_limiter.reset()
    analyze_limiter.capacity = 3.0
    analyze_limiter._buckets.clear()

    statuses = [flask_client.post("/api/analyze", json={"password": "Demo-Pattern-2026!"}).status_code
                for _ in range(8)]
    assert 429 in statuses
    blocked = flask_client.post("/api/analyze", json={"password": "Demo-Pattern-2026!"})
    assert blocked.headers.get("Retry-After")

    analyze_limiter.capacity = 120.0
    analyze_limiter.reset()


def test_unknown_route_returns_json_404(flask_client):
    """A missing route returns structured JSON rather than an HTML error page."""
    response = flask_client.get("/api/does-not-exist")
    assert response.status_code == 404
    assert response.get_json()["code"] == "not_found"


def test_health_endpoint_states_privacy_flags(flask_client):
    """GET /api/health advertises the privacy guarantees of the deployment."""
    payload = flask_client.get("/api/health").get_json()
    assert payload["stores_passwords"] is False
    assert payload["logs_passwords"] is False
    assert payload["sends_passwords_externally"] is False


def test_schema_endpoint_documents_every_route(flask_client):
    """GET /api/schema lists the documented endpoints and privacy summary."""
    payload = flask_client.get("/api/schema").get_json()
    paths = {endpoint["path"] for endpoint in payload["endpoints"]}
    assert {"/api/analyze", "/api/generate-password", "/api/dashboard/stats",
            "/api/analytics/weaknesses"} <= paths
    assert len(payload["privacy_summary"]) >= 3


def test_policy_presets_endpoint(flask_client):
    """GET /api/policy/presets exposes the administrator presets."""
    payload = flask_client.get("/api/policy/presets").get_json()
    assert "standard_account" in payload["presets"]
    assert payload["guidance"]


def test_security_headers_present(flask_client):
    """Responses carry the protective headers a security project should set."""
    response = flask_client.get("/api/health")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert "Content-Security-Policy" in response.headers
    assert response.headers["Content-Security-Policy"].startswith("default-src 'self'")


def test_hashing_demo_endpoint_is_isolated(flask_client):
    """The hashing demonstration uses synthetic values and is clearly labelled."""
    payload = flask_client.get("/api/education/hashing-demo").get_json()
    assert "SYNTHETIC" in payload["demonstration"]["demo_password_label"]
    assert payload["demonstration"]["steps"]
    assert "separate" in payload["isolation_note"].lower()


def test_json_body_only_never_form_encoded(flask_client, demo):
    """Form-encoded submissions are rejected so the value cannot leak into logs."""
    response = flask_client.post("/api/analyze", data={"password": demo["probe"]})
    assert response.status_code in (400, 415)
    assert demo["probe"] not in response.get_data(as_text=True)
