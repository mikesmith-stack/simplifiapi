"""Shared pytest fixtures for the simplifiapi test suite.

Two fixtures are exposed:
  * mock_simplifi - a `responses.RequestsMock` activated for the test, configured
    so that any HTTP request not explicitly registered raises ConnectionError.
    This prevents accidental live calls to services.quicken.com in CI.
  * client - a freshly constructed `simplifiapi.client.Client` instance. The
    underlying `requests.Session` is per-instance, so no test state leaks.

Test fixtures intentionally use stub credentials only. No real bearer token,
no real OAuth client secret, no real Simplifi password appears in any fixture
here or in any tests/test_*.py file.
"""

import os

import pytest
import responses

from simplifiapi.client import Client

SIMPLIFI_BASE = "https://services.quicken.com"

# Stub values used across the suite. None of these are real credentials.
STUB_CLIENT_SECRET = "stub-client-secret-not-real"
STUB_PASSWORD = "stub-password-not-real"
STUB_EMAIL = "stub@example.test"
STUB_TOKEN = "stub-bearer-token-not-real"


@pytest.fixture(autouse=True)
def _set_stub_client_secret(monkeypatch):
    """Ensure SIMPLIFI_CLIENT_SECRET is always set during tests.

    Phase 1 (SEC-01) made `Client.get_token` read this env var at call time
    and raise RuntimeError if it is missing. Tests must not depend on the
    host environment - set a stub for every test, individual tests can
    override via monkeypatch.delenv if they want to assert the unset path.
    """
    monkeypatch.setenv("SIMPLIFI_CLIENT_SECRET", STUB_CLIENT_SECRET)


@pytest.fixture
def mock_simplifi():
    """A responses.RequestsMock that blocks any unregistered HTTP call.

    Usage:
        def test_x(mock_simplifi):
            mock_simplifi.add(responses.GET, "https://services.quicken.com/datasets",
                              json={"resources": [...], "metaData": {}})
            ...

    Any request to a URL not registered with `.add(...)` raises
    ConnectionError. This is the live-HTTP guard required by the threat model.
    """
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        yield rsps


@pytest.fixture
def client():
    """A fresh `Client()` with no pre-set Authorization header.

    Tests that need an authenticated session can set
        client.session.headers["Authorization"] = f"Bearer {STUB_TOKEN}"
    explicitly.
    """
    return Client()
