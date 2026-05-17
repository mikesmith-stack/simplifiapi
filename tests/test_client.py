"""Phase 3 Plan 2 — Client regression tests.

Each test is a regression net for a specific CRITICAL or HIGH finding in
AUDIT.md. Reverting any Phase 1 / Phase 2 fix must fail the corresponding test.

Tests use the `mock_simplifi` and `client` fixtures from `tests/conftest.py`.
The mock fixture is a `responses.RequestsMock` that raises ConnectionError on
any unregistered URL — the live-HTTP guard required by the threat model.
"""

import json

import pytest
import responses

from simplifiapi.client import Client, SIMPLIFI_ENDPOINT
from simplifiapi.exceptions import AuthenticationError, SimplifiAPIError
from tests.conftest import (
    STUB_CLIENT_SECRET,
    STUB_EMAIL,
    STUB_PASSWORD,
    STUB_TOKEN,
)


# ---------------------------------------------------------------------------
# TEST-02 — OAuth token success path returns non-empty bearer (AUDIT M6 / C1)
# ---------------------------------------------------------------------------
def test_get_token_success_returns_bearer(mock_simplifi, client):
    """Happy-path OAuth: authorize -> token returns the bearer string AND
    proves the client-secret was sourced from SIMPLIFI_CLIENT_SECRET (the
    Phase 1 / SEC-01 / C1 fix that removed the literal from source)."""
    mock_simplifi.add(
        responses.POST,
        "https://services.quicken.com/oauth/authorize",
        json={"code": "auth-code-xyz"},
        status=200,
    )
    mock_simplifi.add(
        responses.POST,
        "https://services.quicken.com/oauth/token",
        json={"accessToken": "tok-abc"},
        status=200,
    )

    token = client.get_token(STUB_EMAIL, STUB_PASSWORD)

    assert token == "tok-abc"

    # The second call (index 1) is /oauth/token — body must carry the env-var
    # secret. Confirms the audited real OAuth literal (see AUDIT.md C1) is
    # no longer sourced from a constant in client.py.
    token_call = mock_simplifi.calls[1]
    assert token_call.request.url.endswith("/oauth/token")
    body = json.loads(token_call.request.body)
    assert body["clientSecret"] == STUB_CLIENT_SECRET, (
        "clientSecret must come from SIMPLIFI_CLIENT_SECRET env var (post-Phase-1)"
    )


# ---------------------------------------------------------------------------
# TEST-03 — OAuth MFA challenge succeeds; second authorize POST carries mfaCode
# (AUDIT H2 / NET-02 / M6 "token MFA path")
# ---------------------------------------------------------------------------
def test_get_token_mfa_path_succeeds(mock_simplifi, client, monkeypatch):
    """MFA challenge -> retry -> token-exchange flow.

    Phase 2 kept the original `input("MFA Code: ")` prompt rather than moving
    MFA to a `mfa_code` keyword argument. The plan permits the
    `monkeypatch.setattr("builtins.input", ...)` fallback in that case, which
    is what we use here. The intent of the test — proving the MFA retry was
    wired through `self.session.post` (not bare `requests.post`) AND carried
    the MFA code on the wire — is unchanged.
    """
    # Stub the MFA-code prompt
    monkeypatch.setattr("simplifiapi.client.getpass.getpass", lambda *_a, **_k: "123456")

    # First authorize: MFA challenge
    mock_simplifi.add(
        responses.POST,
        "https://services.quicken.com/oauth/authorize",
        json={"status": "MFA code sent", "mfaChannel": "sms"},
        status=200,
    )
    # Second authorize: MFA accepted, returns code
    mock_simplifi.add(
        responses.POST,
        "https://services.quicken.com/oauth/authorize",
        json={"status": "User passed MFA", "code": "auth-code-mfa"},
        status=200,
    )
    # Token exchange
    mock_simplifi.add(
        responses.POST,
        "https://services.quicken.com/oauth/token",
        json={"accessToken": "tok-mfa"},
        status=200,
    )

    token = client.get_token(STUB_EMAIL, STUB_PASSWORD)

    assert token == "tok-mfa"

    authorize_calls = [
        c for c in mock_simplifi.calls
        if c.request.url.endswith("/oauth/authorize")
    ]
    assert len(authorize_calls) == 2, (
        f"expected 2 authorize POSTs, got {len(authorize_calls)}"
    )

    # The second authorize body carries the MFA code (proves the retry was
    # wired through, not a copy of the first POST).
    second_body = json.loads(authorize_calls[1].request.body)
    assert second_body.get("mfaCode") == "123456"


# ---------------------------------------------------------------------------
# TEST-04 — OAuth failure raises AuthenticationError (AUDIT H6 / ERR-01 / M6)
# ---------------------------------------------------------------------------
def test_get_token_failure_raises_authentication_error(mock_simplifi, client):
    """Auth failure must raise typed `AuthenticationError`, never return None.

    Phase 2 ERR-01 contract: Client methods raise the typed exception
    hierarchy. A silent None return on a 401 would let the CLI think
    auth succeeded.
    """
    mock_simplifi.add(
        responses.POST,
        "https://services.quicken.com/oauth/authorize",
        json={"code": "auth-code"},
        status=200,
    )
    mock_simplifi.add(
        responses.POST,
        "https://services.quicken.com/oauth/token",
        json={"error": "invalid_grant", "errorDescription": "bad credentials"},
        status=401,
    )

    with pytest.raises(AuthenticationError):
        client.get_token(STUB_EMAIL, STUB_PASSWORD)


# ---------------------------------------------------------------------------
# TEST-05 — Pagination across two pages concatenates resources in order
# (AUDIT H1 / NET-01 / M6 "pagination across two pages")
# ---------------------------------------------------------------------------
def test_pagination_follows_nextlink_and_concatenates(mock_simplifi, client):
    """Page 1 + page 2 via nextLink must concatenate in order; exactly two
    requests are issued, and the dataset-id header rides on page 1."""
    client.session.headers["Authorization"] = f"Bearer {STUB_TOKEN}"

    # Page 1: two rows + nextLink
    mock_simplifi.add(
        responses.GET,
        "https://services.quicken.com/transactions",
        json={
            "resources": [{"id": "t1"}, {"id": "t2"}],
            "metaData": {"nextLink": "/transactions?cursor=p2"},
        },
        status=200,
        match_querystring=False,
    )
    # Page 2: one row, no nextLink
    mock_simplifi.add(
        responses.GET,
        "https://services.quicken.com/transactions",
        json={
            "resources": [{"id": "t3"}],
            "metaData": {},
        },
        status=200,
        match_querystring=False,
    )

    results = client.get_transactions("ds-1")

    assert results == [{"id": "t1"}, {"id": "t2"}, {"id": "t3"}]

    transactions_calls = [
        c for c in mock_simplifi.calls if "/transactions" in c.request.url
    ]
    assert len(transactions_calls) == 2, (
        f"expected exactly 2 requests (page 1 + page 2), got {len(transactions_calls)}"
    )

    # Page 1 must carry the Qcs-Dataset-Id header (proves dataset id wired through)
    assert transactions_calls[0].request.headers.get("Qcs-Dataset-Id") == "ds-1"


# ---------------------------------------------------------------------------
# TEST-07 — Forged absolute nextLink to attacker host is rejected before request
# (AUDIT H4 / NET-04, CRITICAL anti-SSRF gate)
# ---------------------------------------------------------------------------
def test_forged_nextlink_to_attacker_host_is_rejected(mock_simplifi, client):
    """A forged absolute `nextLink` pointing at a non-Quicken host must
    raise SimplifiAPIError and the second request must NEVER be issued.

    The fixture deliberately does NOT register a mock for the attacker host
    — if the SSRF mitigation were broken, responses.RequestsMock would raise
    ConnectionError because the URL is unregistered, which is also a fail
    signal.
    """
    client.session.headers["Authorization"] = f"Bearer {STUB_TOKEN}"

    # Page 1 returns a forged absolute nextLink pointing at an attacker host.
    mock_simplifi.add(
        responses.GET,
        "https://services.quicken.com/accounts",
        json={
            "resources": [{"id": "a1"}],
            "metaData": {"nextLink": "https://attacker.example.com/leak?token=stolen"},
        },
        status=200,
        match_querystring=False,
    )

    with pytest.raises(SimplifiAPIError):
        client.get_accounts("ds-1")

    # Exactly ONE request should have been issued (the legitimate page 1).
    # If the validation is broken and the client tried to follow the forged
    # link, the call count would be 2 OR the test would fail with ConnectionError.
    assert len(mock_simplifi.calls) == 1, (
        f"expected exactly 1 call (no forged-link follow), got {len(mock_simplifi.calls)}"
    )

    # Affirmatively assert no call went to the attacker host.
    for call in mock_simplifi.calls:
        assert "attacker.example.com" not in call.request.url


# ---------------------------------------------------------------------------
# TEST-10 — Malformed JSON body raises typed SimplifiAPIError (AUDIT H5 / NET-05)
# ---------------------------------------------------------------------------
def test_malformed_json_raises_simplifi_api_error(mock_simplifi, client):
    """A 200 response with `Content-Type: text/html` and an HTML body must
    raise typed `SimplifiAPIError`, never let a raw `JSONDecodeError` leak
    through the boundary."""
    client.session.headers["Authorization"] = f"Bearer {STUB_TOKEN}"

    mock_simplifi.add(
        responses.GET,
        "https://services.quicken.com/accounts",
        body="<html>Cloudflare error</html>",
        content_type="text/html",
        status=200,
        match_querystring=False,
    )

    with pytest.raises(SimplifiAPIError) as excinfo:
        client.get_accounts("ds-1")

    # Belt-and-suspenders: ensure raw JSONDecodeError did not leak as the
    # primary exception. SimplifiAPIError inherits from Exception, so this
    # would only fail if a future refactor accidentally derived it from
    # JSONDecodeError — which would silently widen the boundary.
    import json as _json
    assert not isinstance(excinfo.value, _json.JSONDecodeError), (
        "JSONDecodeError leaked through the boundary — Phase 2 NET-05 fix reverted"
    )


# ---------------------------------------------------------------------------
# TEST-11 — Every HTTP call has a positive numeric timeout (AUDIT H8 / NET-03)
# ---------------------------------------------------------------------------
def test_every_http_call_has_timeout(mock_simplifi, client, monkeypatch):
    """Wrap requests.Session.request and record every outbound call's timeout
    kwarg. After a representative happy-path run (get_token + verify_token +
    get_datasets), every recorded request must have `timeout` set to a
    positive numeric value."""
    recorded_timeouts = []

    import requests as _requests
    real_request = _requests.Session.request

    def recording_request(self, method, url, **kwargs):
        recorded_timeouts.append((method, url, kwargs.get("timeout")))
        return real_request(self, method, url, **kwargs)

    monkeypatch.setattr(_requests.Session, "request", recording_request)

    # Wire mocks for a representative end-to-end happy path
    mock_simplifi.add(
        responses.POST,
        "https://services.quicken.com/oauth/authorize",
        json={"code": "auth-code"},
        status=200,
    )
    mock_simplifi.add(
        responses.POST,
        "https://services.quicken.com/oauth/token",
        json={"accessToken": STUB_TOKEN},
        status=200,
    )
    mock_simplifi.add(
        responses.GET,
        "https://services.quicken.com/userprofiles/me",
        json={"id": "user-stub"},
        status=200,
    )
    mock_simplifi.add(
        responses.GET,
        "https://services.quicken.com/datasets",
        json={"resources": [{"id": "ds-1"}], "metaData": {}},
        status=200,
        match_querystring=False,
    )

    # Exercise the three paths that issue HTTP calls
    token = client.get_token(STUB_EMAIL, STUB_PASSWORD)
    assert token == STUB_TOKEN

    # verify_token now raises on failure and returns None on success
    # (Phase 2 contract). Just call it — no return-value assertion.
    client.verify_token(token)

    assert client.get_datasets() == [{"id": "ds-1"}]

    # Every recorded call must have a positive numeric timeout
    assert recorded_timeouts, (
        "no HTTP calls were recorded — fixture wiring is broken"
    )
    for method, url, timeout in recorded_timeouts:
        assert timeout is not None, (
            f"missing timeout on {method} {url} — Phase 2 NET-03 fix reverted"
        )
        assert isinstance(timeout, (int, float)) and timeout > 0, (
            f"non-positive timeout {timeout!r} on {method} {url}"
        )


# ===========================================================================
# Filler tests (Task 2.11) — close uncovered branches to reach >=80% combined.
# Each test targets specific line ranges flagged by --cov-report=term-missing.
# ===========================================================================


# ---------------------------------------------------------------------------
# Filler: _is_safe_next_link explicit branch coverage
# Covers client.py lines 30, 36, 39 — non-string / non-https / non-quicken host
# ---------------------------------------------------------------------------
def test_is_safe_next_link_rejects_unsafe_inputs():
    """_is_safe_next_link is the security gate for SSRF. Exercise the three
    rejection branches directly so coverage hits the falsy-isinstance, the
    non-https scheme, and the foreign-host paths."""
    from simplifiapi.client import _is_safe_next_link

    # Branch: not a string / empty
    assert _is_safe_next_link(None) is False
    assert _is_safe_next_link("") is False
    assert _is_safe_next_link(123) is False  # type: ignore[arg-type]

    # Branch: relative path -> safe
    assert _is_safe_next_link("/accounts?cursor=2") is True

    # Branch: absolute https on quicken host -> safe
    assert _is_safe_next_link("https://services.quicken.com/x") is True

    # Branch: absolute http (wrong scheme) -> unsafe
    assert _is_safe_next_link("http://services.quicken.com/x") is False

    # Branch: absolute https on attacker host -> unsafe
    assert _is_safe_next_link("https://attacker.example.com/leak") is False


# ---------------------------------------------------------------------------
# Filler: verify_token raises AuthenticationError on 401
# Covers client.py lines 163-164 (HTTPError -> AuthenticationError)
# ---------------------------------------------------------------------------
def test_verify_token_raises_on_non_2xx(mock_simplifi, client):
    mock_simplifi.add(
        responses.GET,
        "https://services.quicken.com/userprofiles/me",
        json={"error": "unauthorized"},
        status=401,
    )
    with pytest.raises(AuthenticationError):
        client.verify_token("bad-token")


# ---------------------------------------------------------------------------
# Filler: verify_token raises AuthenticationError on missing user id
# Covers client.py line 175 ("Token verification response had no user id")
# ---------------------------------------------------------------------------
def test_verify_token_raises_when_user_id_missing(mock_simplifi, client):
    mock_simplifi.add(
        responses.GET,
        "https://services.quicken.com/userprofiles/me",
        json={"someOtherField": "x"},
        status=200,
    )
    with pytest.raises(AuthenticationError):
        client.verify_token(STUB_TOKEN)


# ---------------------------------------------------------------------------
# Filler: each resource getter hits its expected URL
# Covers client.py lines 239, 248 (get_tags, get_categories — the four wrappers)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "method_name,path",
    [
        ("get_accounts", "accounts"),
        ("get_transactions", "transactions"),
        ("get_tags", "tags"),
        ("get_categories", "categories"),
    ],
)
def test_each_resource_getter_hits_expected_path(mock_simplifi, client, method_name, path):
    client.session.headers["Authorization"] = f"Bearer {STUB_TOKEN}"
    mock_simplifi.add(
        responses.GET,
        f"https://services.quicken.com/{path}",
        json={"resources": [{"id": "x"}], "metaData": {}},
        status=200,
        match_querystring=False,
    )
    result = getattr(client, method_name)("ds-1")
    assert result == [{"id": "x"}]
    assert any(f"/{path}" in c.request.url for c in mock_simplifi.calls)


# ---------------------------------------------------------------------------
# Filler: get_token raises AuthenticationError on missing accessToken
# Covers client.py line 141 ("OAuth token response had no accessToken")
# ---------------------------------------------------------------------------
def test_get_token_raises_when_access_token_missing(mock_simplifi, client):
    mock_simplifi.add(
        responses.POST,
        "https://services.quicken.com/oauth/authorize",
        json={"code": "auth-code"},
        status=200,
    )
    mock_simplifi.add(
        responses.POST,
        "https://services.quicken.com/oauth/token",
        json={"notAccessToken": "x"},
        status=200,
    )
    with pytest.raises(AuthenticationError):
        client.get_token(STUB_EMAIL, STUB_PASSWORD)


# ---------------------------------------------------------------------------
# Filler: get_token raises AuthenticationError when authorize returns no code
# Covers client.py line 106 ("OAuth authorize did not return a code")
# ---------------------------------------------------------------------------
def test_get_token_raises_when_authorize_returns_no_code(mock_simplifi, client):
    mock_simplifi.add(
        responses.POST,
        "https://services.quicken.com/oauth/authorize",
        json={"someField": "no-code-here"},
        status=200,
    )
    with pytest.raises(AuthenticationError):
        client.get_token(STUB_EMAIL, STUB_PASSWORD)


# ---------------------------------------------------------------------------
# Filler: get_token raises RuntimeError when SIMPLIFI_CLIENT_SECRET missing
# Covers client.py lines 111-115 (env-var unset path, SEC-01)
# ---------------------------------------------------------------------------
def test_get_token_raises_runtime_error_when_client_secret_unset(
    mock_simplifi, client, monkeypatch
):
    monkeypatch.delenv("SIMPLIFI_CLIENT_SECRET", raising=False)
    mock_simplifi.add(
        responses.POST,
        "https://services.quicken.com/oauth/authorize",
        json={"code": "auth-code"},
        status=200,
    )
    with pytest.raises(RuntimeError, match="SIMPLIFI_CLIENT_SECRET"):
        client.get_token(STUB_EMAIL, STUB_PASSWORD)


# ---------------------------------------------------------------------------
# Filler: MFA failure (status != "User passed MFA") raises AuthenticationError
# Covers client.py line 103 ("MFA challenge failed")
# ---------------------------------------------------------------------------
def test_get_token_mfa_failure_raises_authentication_error(
    mock_simplifi, client, monkeypatch
):
    monkeypatch.setattr("simplifiapi.client.getpass.getpass", lambda *_a, **_k: "999999")
    mock_simplifi.add(
        responses.POST,
        "https://services.quicken.com/oauth/authorize",
        json={"status": "MFA code sent", "mfaChannel": "sms"},
        status=200,
    )
    mock_simplifi.add(
        responses.POST,
        "https://services.quicken.com/oauth/authorize",
        json={"status": "MFA code expired"},
        status=200,
    )
    with pytest.raises(AuthenticationError):
        client.get_token(STUB_EMAIL, STUB_PASSWORD)


# ---------------------------------------------------------------------------
# QUAL-04 — Each public resource getter must delegate through _get_resource
# (Plan 03-03 / Task 3.2; AUDIT M3 regression net)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "method_name,expected_path",
    [
        ("get_accounts", "/accounts"),
        ("get_transactions", "/transactions"),
        ("get_tags", "/tags"),
        ("get_categories", "/categories"),
    ],
)
def test_get_resource_delegated_by_each_wrapper(
    client, monkeypatch, method_name, expected_path
):
    """Every public resource getter must route through _get_resource.

    This is the QUAL-04 regression net. If a wrapper bypasses _get_resource
    (e.g. duplicates the _unpaginate call inline again), this test fails.
    """
    captured = []

    def fake_get_resource(self, path, dataset_id, limit=1000):
        captured.append((path, dataset_id, limit))
        return []  # behavior is irrelevant to this test; we assert the call shape

    # Use monkeypatch.setattr so the wrapper-delegation is verified at the
    # class level (every Client instance sees the spy).
    from simplifiapi.client import Client as _Client
    monkeypatch.setattr(_Client, "_get_resource", fake_get_resource)

    # Invoke the wrapper by name with a stub dataset id.
    result = getattr(client, method_name)("ds-1")

    assert result == [], "wrapper must return whatever _get_resource returns"
    assert len(captured) == 1, (
        f"{method_name} must call _get_resource exactly once, got {len(captured)}"
    )
    path, dataset_id, limit = captured[0]
    assert path == expected_path, f"{method_name} called with wrong path: {path}"
    assert dataset_id == "ds-1", f"{method_name} did not forward dataset_id"
    assert limit == 1000, f"{method_name} did not forward default limit"
