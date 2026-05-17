"""Phase 3 Plan 2 — CLI regression tests.

Each test is a regression net for a specific HIGH / MEDIUM finding in
AUDIT.md (path traversal, empty-dataset friendly exit, CSV formula injection).

Tests drive `cli.main()` end-to-end (or `cli.write_data` directly for the
CSV-sanitisation parametrised test) and use the `mock_simplifi` fixture for
the live-HTTP guard.
"""

import json
import sys
import types

import pytest
import responses

from simplifiapi import cli
from tests.conftest import STUB_TOKEN


# ---------------------------------------------------------------------------
# TEST-06 — Empty dataset list raises friendly SystemExit (no IndexError)
# (AUDIT H7 / ERR-03 / M6 "empty dataset")
# ---------------------------------------------------------------------------
def test_empty_datasets_raises_friendly_systemexit(mock_simplifi, monkeypatch, tmp_path):
    """When /datasets returns an empty resources array, cli.main() must
    raise SystemExit with a user-friendly message rather than IndexError on
    `datasets[0]`."""
    monkeypatch.setattr(
        sys,
        "argv",
        ["simplifiapi", "--token", STUB_TOKEN, "--accounts"],
    )
    monkeypatch.chdir(tmp_path)

    mock_simplifi.add(
        responses.GET,
        "https://services.quicken.com/userprofiles/me",
        json={"id": "user-stub"},
        status=200,
    )
    mock_simplifi.add(
        responses.GET,
        "https://services.quicken.com/datasets",
        json={"resources": [], "metaData": {}},
        status=200,
        match_querystring=False,
    )

    with pytest.raises(SystemExit) as excinfo:
        cli.main()

    assert "No datasets found" in str(excinfo.value), (
        f"SystemExit message must mention 'No datasets found', got: {excinfo.value!r}"
    )


# ---------------------------------------------------------------------------
# TEST-08 — --filename="../evil" writes evil_accounts.json in CWD only
# (AUDIT H3 / OUT-01)
# ---------------------------------------------------------------------------
def test_filename_traversal_writes_basename_in_cwd(mock_simplifi, monkeypatch, tmp_path):
    """`--filename="../evil"` must be neutralised by os.path.basename to
    `evil` before being formatted into the output path. Output file lives in
    CWD and never escapes to the parent directory."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        ["simplifiapi", "--token", STUB_TOKEN, "--filename", "../evil", "--accounts"],
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
    mock_simplifi.add(
        responses.GET,
        "https://services.quicken.com/accounts",
        json={"resources": [{"id": "a1", "name": "Checking"}], "metaData": {}},
        status=200,
        match_querystring=False,
    )

    cli.main()

    # Must exist in tmp_path (CWD) under the basename
    written_in_cwd = tmp_path / "evil_accounts.json"
    assert written_in_cwd.is_file(), (
        f"expected {written_in_cwd} to exist; tmp_path contents: {list(tmp_path.iterdir())}"
    )

    # Must NOT exist in the parent directory (path traversal must be blocked)
    leaked_to_parent = tmp_path.parent / "evil_accounts.json"
    assert not leaked_to_parent.exists(), (
        f"path traversal leaked: {leaked_to_parent} should not exist"
    )

    # Content sanity check: the row we mocked is in the file
    body = json.loads(written_in_cwd.read_text())
    assert body == [{"id": "a1", "name": "Checking"}]


# ---------------------------------------------------------------------------
# TEST-09 — CSV cells starting with =, +, -, @ are escaped with leading '
# (AUDIT M2 / OUT-02) — parameterised across all four formula-prefix chars
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("leading_char", ["=", "+", "-", "@"])
def test_csv_formula_prefix_is_escaped(leading_char, monkeypatch, tmp_path):
    """write_data with format=csv must prefix dangerous cells with a single
    quote. Tested across all four formula-prefix characters per OUT-02 / M2.
    Asserts behaviour, not the internal function name."""
    payee = f"{leading_char}SUM(A1:A10)"
    row = {"id": "t1", "payee": payee, "amount": "1.00"}

    options = types.SimpleNamespace(filename="output", format="csv")

    monkeypatch.chdir(tmp_path)
    cli.write_data(options, [row], "transactions")

    out = tmp_path / "output_transactions.csv"
    assert out.is_file(), (
        f"expected {out} to exist; tmp_path contents: {list(tmp_path.iterdir())}"
    )

    content = out.read_text()
    # The escaped cell starts with a single quote then the dangerous char.
    # Don't pin whether pandas wraps the cell in double quotes — assert the
    # marker `'<char>SUM` exists somewhere.
    escaped_marker = f"'{leading_char}SUM"
    assert escaped_marker in content, (
        f"expected escaped marker {escaped_marker!r} in CSV output, got:\n{content}"
    )

    # And the raw unescaped form must NOT appear at the start of a cell
    # (preceded by a comma). If sanitisation was reverted, the cell would
    # look like ,=SUM(A1:A10), which is the formula-injection vector.
    unescaped_at_cell_start = f",{leading_char}SUM"
    assert unescaped_at_cell_start not in content, (
        f"unescaped {leading_char}SUM appears at cell start in CSV — "
        f"formula injection is open:\n{content}"
    )


# ===========================================================================
# Filler tests (Task 2.11) — close uncovered cli.py branches to reach >=80%.
# ===========================================================================


# ---------------------------------------------------------------------------
# Filler: resolve_password reads SIMPLIFI_PASSWORD env var
# Covers cli.py lines 100-101 (env-var branch)
# ---------------------------------------------------------------------------
def test_resolve_password_reads_env(monkeypatch):
    monkeypatch.setenv("SIMPLIFI_PASSWORD", "from-env-not-real")
    assert cli.resolve_password() == "from-env-not-real"


# ---------------------------------------------------------------------------
# Filler: resolve_password raises SystemExit when env unset and stdin not a TTY
# Covers cli.py lines 105-108 (no-TTY rejection branch)
# ---------------------------------------------------------------------------
def test_resolve_password_raises_when_no_env_and_no_tty(monkeypatch):
    monkeypatch.delenv("SIMPLIFI_PASSWORD", raising=False)
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    with pytest.raises(SystemExit, match="SIMPLIFI_PASSWORD"):
        cli.resolve_password()


# ---------------------------------------------------------------------------
# Filler: cli.main() runs all four resource flags (transactions, tags, categories)
# Covers cli.py lines 179-189 (the three optional resource branches not hit by
# the existing --accounts tests)
# ---------------------------------------------------------------------------
def test_main_runs_all_resource_flags(mock_simplifi, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "simplifiapi",
            "--token", STUB_TOKEN,
            "--accounts",
            "--transactions",
            "--tags",
            "--categories",
        ],
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
    for path in ("accounts", "transactions", "tags", "categories"):
        mock_simplifi.add(
            responses.GET,
            f"https://services.quicken.com/{path}",
            json={"resources": [{"id": f"{path}-1"}], "metaData": {}},
            status=200,
            match_querystring=False,
        )

    cli.main()

    # All four files were written
    for name in ("accounts", "transactions", "tags", "categories"):
        assert (tmp_path / f"output_{name}.json").is_file()


# ---------------------------------------------------------------------------
# Filler: cli.main() boundary catches SimplifiAPIError -> SystemExit
# Covers cli.py lines 190-191 (the except SimplifiAPIError handler)
# ---------------------------------------------------------------------------
def test_main_converts_simplifi_error_to_systemexit(mock_simplifi, monkeypatch, tmp_path):
    """If verify_token raises AuthenticationError (a SimplifiAPIError subclass),
    cli.main() must catch it at the boundary and raise SystemExit with the
    'simplifiapi: ' prefix (ERR-05 + the cli.py boundary handler)."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        ["simplifiapi", "--token", "bad-token", "--accounts"],
    )

    mock_simplifi.add(
        responses.GET,
        "https://services.quicken.com/userprofiles/me",
        json={"error": "unauthorized"},
        status=401,
    )

    with pytest.raises(SystemExit) as excinfo:
        cli.main()

    assert "simplifiapi:" in str(excinfo.value), (
        f"boundary should prefix message with 'simplifiapi:', got {excinfo.value!r}"
    )


# ---------------------------------------------------------------------------
# Filler: _escape_csv_cell passes non-string and empty values through unchanged
# Covers cli.py line 35 (the `not isinstance / not value` early return)
# ---------------------------------------------------------------------------
def test_escape_csv_cell_passes_non_string_through():
    from simplifiapi.cli import _escape_csv_cell

    # Non-string values round-trip unchanged
    assert _escape_csv_cell(123) == 123
    assert _escape_csv_cell(None) is None
    assert _escape_csv_cell(1.5) == 1.5

    # Empty string round-trips unchanged (no leading quote prepended)
    assert _escape_csv_cell("") == ""

    # Safe string round-trips unchanged
    assert _escape_csv_cell("Coffee Shop") == "Coffee Shop"
