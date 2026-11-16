"""Tests for the compiled `binfera` extension.

Not run by `cargo test` (the crate opts its lib target out of that --
`binfera-python/Cargo.toml`'s `[lib] test = false`):
this is the pytest suite that proves the actual `.so`/`.pyd` behaves,
against a real `maturin develop` build. Run with:

    maturin develop
    pytest binfera-python/tests/

Everything here exercises the *binding*, not analysis correctness --
`binfera`'s own test suites (`cargo test -p binfera`,
`scripts/difftest.py`) already own that. What's checked here is the binding
contract: malformed input/missing rules/unparseable rule each raise a typed
exception with context, `jobs=1` reproduces the CLI's rule names, and the GIL
is actually released during `analyze()`.
"""

import json
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

import binfera

REPO_ROOT = Path(__file__).resolve().parents[2]
RULES_DIR = REPO_ROOT / "rules"
SAMPLE = REPO_ROOT / "tests" / "testfiles" / "c335a9d41185a32ad918c5389ee54235.exe_"

pytestmark = pytest.mark.skipif(
    not RULES_DIR.is_dir(), reason="capa-rules submodule not checked out"
)


@pytest.fixture(scope="module")
def rules() -> binfera.Rules:
    return binfera.Rules.from_directory(str(RULES_DIR))


def test_version_and_rules_pin() -> None:
    assert binfera.__version__
    assert binfera.RULES_PIN.startswith("v")


def test_rules_from_directory_missing_dir() -> None:
    with pytest.raises(binfera.InvalidRuleError):
        binfera.Rules.from_directory("/no/such/directory")


def test_rules_from_directory_unparseable_rule(tmp_path: Path) -> None:
    (tmp_path / "bad.yml").write_text("not: valid: capa: rule:\n  - [")
    with pytest.raises(binfera.InvalidRuleError) as excinfo:
        binfera.Rules.from_directory(str(tmp_path))
    # context, not just a bare exception: the message names the file.
    assert "bad.yml" in str(excinfo.value)


def test_analyze_bytes(rules: binfera.Rules) -> None:
    data = SAMPLE.read_bytes()
    doc = binfera.analyze(data, rules, jobs=1)
    assert isinstance(doc, dict)
    assert doc["meta"]["analysis"]["format"] == "pe"
    assert doc["meta"]["sample"]["sha256"]
    assert "rules" in doc


def test_meta_argv_is_empty_list_not_null(rules: binfera.Rules) -> None:
    # regression: upstream's `ResultDocument.meta.argv` is a required
    # `list[str]`, not `Optional` -- `null` fails `model_validate_json`
    # (J14 caught this; see binfera/src/api.rs's `Input::argv` doc).
    doc = binfera.analyze(SAMPLE, rules, jobs=1)
    assert doc["meta"]["argv"] == []


def test_analyze_path(rules: binfera.Rules) -> None:
    doc = binfera.analyze(str(SAMPLE), rules, jobs=1)
    assert doc["meta"]["sample"]["path"] == str(SAMPLE)


def test_analyze_pathlike(rules: binfera.Rules) -> None:
    doc = binfera.analyze(SAMPLE, rules, jobs=1)
    assert doc["meta"]["analysis"]["format"] == "pe"


def test_analyze_bad_type(rules: binfera.Rules) -> None:
    with pytest.raises(TypeError):
        binfera.analyze(12345, rules)  # type: ignore[arg-type]


def test_analyze_missing_file(rules: binfera.Rules) -> None:
    with pytest.raises(FileNotFoundError):
        binfera.analyze("/no/such/file.exe_", rules)


def test_analyze_malformed_input(rules: binfera.Rules) -> None:
    with pytest.raises(binfera.UnsupportedFormatError):
        binfera.analyze(b"not a real sample" * 4, rules)


def test_analyze_unknown_format(rules: binfera.Rules) -> None:
    with pytest.raises(binfera.UnsupportedFormatError):
        binfera.analyze(SAMPLE, rules, format="not-a-format")


def test_analyze_zero_jobs(rules: binfera.Rules) -> None:
    with pytest.raises(binfera.CapaError):
        binfera.analyze(SAMPLE, rules, jobs=0)


def test_analyze_never_returns_none_or_empty_on_error(rules: binfera.Rules) -> None:
    # "a hard error must never become None, an empty result, or a warning"
    # A malformed sample must raise, never silently produce a document with no
    # rules.
    with pytest.raises(binfera.CapaError):
        binfera.analyze(b"\x00" * 16, rules)


@pytest.mark.skipif(sys.platform == "win32", reason="binfera-cli release binary path differs")
def test_jobs_1_matches_cli_rule_names(rules: binfera.Rules) -> None:
    """`jobs=1` reproduces the CLI's `--jobs 1` rule-name set exactly --
    the same binding parity claim made at difftest scale, here pinned to one
    sample so the binding's own test suite doesn't depend on
    a release build being present in CI."""
    cli = REPO_ROOT / "target" / "release" / "binfera"
    if not cli.is_file():
        pytest.skip("target/release/binfera not built")
    out = subprocess.run(
        [str(cli), "--rules", str(RULES_DIR), "--jobs", "1", "-j", str(SAMPLE)],
        capture_output=True,
        check=True,
        text=True,
    )
    cli_doc = json.loads(out.stdout)
    py_doc = binfera.analyze(SAMPLE, rules, jobs=1)
    assert set(py_doc["rules"].keys()) == set(cli_doc["rules"].keys())


def test_analyze_releases_the_gil(rules: binfera.Rules) -> None:
    """Another Python thread keeps running while `analyze()` does, proving
    the GIL is released for the CPU-bound part -- the roadmap's proof
    requirement that Python threads overlap with analysis.

    This watches the other thread's longest stall rather than comparing
    concurrent and sequential wall time: a ~0.1 s analysis left that ratio
    at the mercy of runner noise, and it failed CI by 2%."""
    stop = threading.Event()
    longest_gap = 0.0

    def ticker() -> None:
        nonlocal longest_gap
        last = time.monotonic()
        while not stop.is_set():
            now = time.monotonic()
            longest_gap = max(longest_gap, now - last)
            last = now

    thread = threading.Thread(target=ticker)
    thread.start()
    try:
        t0 = time.monotonic()
        for _ in range(3):
            binfera.analyze(SAMPLE, rules, jobs=1)
        elapsed = time.monotonic() - t0
    finally:
        stop.set()
        thread.join()

    # Holding the GIL would freeze the ticker for a whole call, a gap of about
    # elapsed / 3. Released, its gaps stay at the 5 ms switch-interval scale.
    assert longest_gap < elapsed / 6


def test_fetch_rules_rejects_existing_directory(tmp_path: Path) -> None:
    with pytest.raises(binfera.CapaError):
        binfera.fetch_rules(str(tmp_path))


def test_fetch_rules_never_runs_at_import(tmp_path: Path) -> None:
    # re-importing must never touch the network or the filesystem beyond
    # what Python's own import machinery does -- fetch_rules is opt-in
    # only, matching the CLI's own `binfera fetch-rules` subcommand.
    marker = tmp_path / "should-not-exist"
    import importlib

    importlib.reload(binfera)
    assert not marker.exists()


def test_diff_of_a_file_with_itself(rules: binfera.Rules) -> None:
    document = binfera.diff(SAMPLE, SAMPLE, rules, jobs=1)
    assert document["verdict"] == "identical"
    assert document["unmatched_a"] == []
    assert document["capability_delta"]["added"] == []


def test_diff_pair_compares_one_function() -> None:
    document = binfera.diff(SAMPLE, SAMPLE)
    assert document["capability_delta"] is None
    match = document["matches"][0]
    pair = binfera.diff(SAMPLE, SAMPLE, pair=(match["a_addr"], match["b_addr"]))
    assert pair["similarity"] == 1.0
