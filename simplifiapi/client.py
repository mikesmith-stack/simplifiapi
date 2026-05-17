import getpass
import json
import logging
import os
import uuid

import requests
from urllib.parse import urljoin, urlparse

from simplifiapi.exceptions import AuthenticationError, SimplifiAPIError

logger = logging.getLogger("simplifiapi")

SIMPLIFI_ENDPOINT = "https://services.quicken.com"
REQUEST_TIMEOUT = 30  # seconds; AUDIT NET-03 / H8 — every HTTP call must pass timeout=REQUEST_TIMEOUT


def _is_safe_next_link(url) -> bool:
    """Return True iff `url` is safe to send the bearer token to.

    Safe nextLink:
      - relative path (no scheme, no netloc) - joined to SIMPLIFI_ENDPOINT, OR
      - absolute URL with scheme=https AND host matching SIMPLIFI_ENDPOINT
        (case-insensitive).

    Anything else (different host, http://, javascript:, file://, opaque
    data:..., absolute URL with a different port) is rejected.
    AUDIT NET-04 / H4.
    """
    if not isinstance(url, str) or not url:
        return False
    parsed = urlparse(url)
    if not parsed.scheme and not parsed.netloc:
        return True
    expected = urlparse(SIMPLIFI_ENDPOINT)
    if parsed.scheme.lower() != "https":
        return False
    if parsed.netloc.lower() != expected.netloc.lower():
        return False
    return True


class Client:

    def __init__(self):
        self.session = requests.Session()

    def get_token(self, email, password):
        # Step 1: Oauth authorize
        body = {
            "clientId": "acme_web",
            "mfaChannel": None,
            "mfaCode": None,
            "password": password,
            "redirectUri": "https://app.simplifimoney.com/login",
            "responseType": "code",
            "threatMetrixRequestId": None,
            "threatMetrixSessionId": str(uuid.uuid4()),
            "username": email,
        }
        r = self.session.post(
            url="https://services.quicken.com/oauth/authorize",
            json=body,
            timeout=REQUEST_TIMEOUT,
        )
        try:
            r.raise_for_status()
        except requests.exceptions.HTTPError as exc:
            raise AuthenticationError(
                f"OAuth authorize POST returned HTTP {r.status_code}"
            ) from exc
        try:
            data = r.json()
        except json.JSONDecodeError as exc:
            raise SimplifiAPIError(
                "OAuth authorize response was not valid JSON"
            ) from exc
        status = data.get("status")
        if status == "MFA code sent":
            mfaChannel = data.get("mfaChannel")
            # Do NOT log mfaChannel — Phase 1 SEC-03 invariant: no user identifier
            # in logs. The mfaChannel value is the masked destination of the MFA
            # challenge (e.g. "***-***-1234"), which is still a user identifier.
            logger.warning("MFA challenge required; prompting for code")
            # getpass to match the credential-hygiene posture established in
            # Phase 1 (resolve_password) — keeps the MFA code out of terminal
            # echo and shell readline history.
            mfaCode = getpass.getpass("MFA Code: ")
            body["mfaChannel"] = mfaChannel
            body["mfaCode"] = mfaCode
            r = self.session.post(
                url="https://services.quicken.com/oauth/authorize",
                json=body,
                timeout=REQUEST_TIMEOUT,
            )
            try:
                r.raise_for_status()
            except requests.exceptions.HTTPError as exc:
                raise AuthenticationError(
                    f"OAuth MFA retry returned HTTP {r.status_code}"
                ) from exc
            try:
                data = r.json()
            except json.JSONDecodeError as exc:
                raise SimplifiAPIError(
                    "OAuth MFA retry response was not valid JSON"
                ) from exc
            status = data.get("status")
            if status != "User passed MFA":
                raise AuthenticationError("MFA challenge failed")
        code = data.get("code")
        if not code:
            raise AuthenticationError("OAuth authorize did not return a code")

        # Step 2: Get token
        client_secret = os.environ.get("SIMPLIFI_CLIENT_SECRET")
        if not client_secret:
            raise RuntimeError(
                "SIMPLIFI_CLIENT_SECRET environment variable is not set. "
                "Set it before running simplifiapi (this fork no longer embeds the OAuth client secret in source). "
                "See README.md > Security & Trust Model for details."
            )
        r = self.session.post(
            url="https://services.quicken.com/oauth/token",
            json={
                "clientId": "acme_web",
                "clientSecret": client_secret,
                "grantType": "authorization_code",
                "code": code,
                "redirectUri": "https://app.simplifimoney.com/login",
            },
            timeout=REQUEST_TIMEOUT,
        )
        try:
            r.raise_for_status()
        except requests.exceptions.HTTPError as exc:
            raise AuthenticationError(
                f"OAuth token POST returned HTTP {r.status_code}"
            ) from exc
        try:
            token_payload = r.json()
        except json.JSONDecodeError as exc:
            raise SimplifiAPIError(
                "OAuth token response was not valid JSON"
            ) from exc
        token = token_payload.get("accessToken")
        if not token:
            raise AuthenticationError("OAuth token response had no accessToken")
        return token

    def verify_token(self, token) -> None:
        """Verify the bearer token and install it on the session.

        Raises:
            AuthenticationError: if the verify endpoint returns non-2xx or
                an unexpected payload.
            SimplifiAPIError: if the response body is not valid JSON.

        On success the bearer token is installed as the default Authorization
        header on `self.session`; no value is returned.
        """
        headers = {"Authorization": "Bearer {}".format(token)}
        r = self.session.get(
            url="https://services.quicken.com/userprofiles/me",
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )
        try:
            r.raise_for_status()
        except requests.exceptions.HTTPError as exc:
            raise AuthenticationError(
                f"Token verification returned HTTP {r.status_code}"
            ) from exc
        try:
            data = r.json()
        except json.JSONDecodeError as exc:
            raise SimplifiAPIError(
                "Token verification response was not valid JSON"
            ) from exc
        userId = data.get("id")
        if not userId:
            raise AuthenticationError(
                "Token verification response had no user id"
            )
        # Do NOT log userId — Phase 1 SEC-03 invariant: no user identifier in logs.
        # Install the bearer header on the session so subsequent calls authenticate.
        self.session.headers.update(headers)

    def _unpaginate(self, path: str, **kargs):
        nextLink = path
        data = []
        while nextLink:
            if not _is_safe_next_link(nextLink):
                raise SimplifiAPIError(
                    "Refusing to follow nextLink that is not a relative path "
                    "or under https://services.quicken.com/: {!r}".format(nextLink)
                )
            logger.info("Fetching %s", nextLink)
            r = self.session.get(
                url=urljoin(SIMPLIFI_ENDPOINT, nextLink),
                timeout=REQUEST_TIMEOUT,
                **kargs,
            )
            try:
                r.raise_for_status()
            except requests.exceptions.HTTPError as exc:
                raise SimplifiAPIError(
                    "Resource request to {!r} returned HTTP {}".format(nextLink, r.status_code)
                ) from exc
            try:
                payload = r.json()
            except json.JSONDecodeError as exc:
                raise SimplifiAPIError(
                    "Resource response from {!r} was not valid JSON".format(nextLink)
                ) from exc
            data.extend(payload.get("resources", []))
            metadata = payload.get("metaData") or {}
            nextLink = metadata.get("nextLink")
        return data

    def get_datasets(self, limit: int = 1000):
        return self._unpaginate(path="/datasets",
                                params={
                                    "limit": limit,
                                })

    def _get_resource(self, path: str, dataset_id: str, limit: int = 1000) -> list[dict]:
        """Fetch a paginated resource scoped to a dataset.

        All four account/transaction/tag/category endpoints share the same
        shape: a path under https://services.quicken.com, a Qcs-Dataset-Id
        header, and a paginated GET with limit=1000. Centralising the call
        here lets the four public getters be one-liners and gives any future
        per-resource cross-cut (retry, backoff, logging) exactly one place
        to land.

        `path` must be a leading-slash absolute path on the Simplifi API
        (e.g. "/accounts"). `dataset_id` is sent as the Qcs-Dataset-Id
        header. Pagination is handled by self._unpaginate, which already
        validates the upstream-supplied nextLink against the configured
        host (Phase 2 NET-04) and applies the explicit timeout (NET-03).
        """
        return self._unpaginate(
            path=path,
            headers={"Qcs-Dataset-Id": dataset_id},
            params={"limit": limit},
        )

    def get_accounts(self, datasetId: str) -> list[dict]:
        return self._get_resource("/accounts", datasetId)

    def get_transactions(self, datasetId: str) -> list[dict]:
        return self._get_resource("/transactions", datasetId)

    def get_tags(self, datasetId: str) -> list[dict]:
        return self._get_resource("/tags", datasetId)

    def get_categories(self, datasetId: str) -> list[dict]:
        return self._get_resource("/categories", datasetId)
