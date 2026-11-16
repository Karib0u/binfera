"""Tests for `inspect()`, `Decompiler` and `decompile_all()`.

They need no rules and no submodule: the sample is `tests/decompiler/fixtures.dll`, a small
committed PE whose functions (`arithmetic`, ...) are the decompiler's own fixtures.
"""

from pathlib import Path

import pytest

import binfera

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE = REPO_ROOT / "tests" / "decompiler" / "fixtures.dll"

needs_decompiler = pytest.mark.skipif(
    not binfera.HAS_DECOMPILER, reason="wheel built without the native decompiler"
)


def test_inspect_reads_headers_from_path_and_bytes():
    from_path = binfera.inspect(FIXTURE)
    from_bytes = binfera.inspect(FIXTURE.read_bytes())
    assert from_path == from_bytes
    assert from_path["format"] == "pe"
    assert from_path["arch"] == "x64"
    assert from_path["sections"] and from_path["exports"]
    assert {"name", "va", "perms"} <= set(from_path["sections"][0])


def test_inspect_rejects_garbage_with_a_typed_error():
    with pytest.raises(binfera.CapaError):
        binfera.inspect(b"not an executable")


def test_inspect_refuses_formats_it_cannot_read():
    with pytest.raises(binfera.UnsupportedFormatError):
        binfera.inspect(FIXTURE, format="freeze")


def test_inspect_reads_raw_shellcode():
    info = binfera.inspect(b"\x31\xc0\xc3", format="sc32")
    assert info["format"] == "sc32"


@needs_decompiler
def test_decompiler_decompiles_a_function():
    session = binfera.Decompiler(FIXTURE)
    assert session.functions == sorted(session.functions) and session.functions
    result = session.decompile(session.functions[0])
    assert "arithmetic" in result["text"]
    assert len(result["lines"]) == len(result["text"].split("\n"))
    assert result["frame"] and result["frame"][0]["parameter"] is True
    assert result["file_warnings"] == session.warnings


@needs_decompiler
def test_decompiler_unit_is_self_contained_c():
    session = binfera.Decompiler(FIXTURE)
    unit = session.unit(session.functions[:2])
    assert "arithmetic" in unit["text"]
    assert len(unit["functions"]) == 2


@needs_decompiler
def test_decompiler_reports_an_address_outside_the_image():
    session = binfera.Decompiler(FIXTURE)
    with pytest.raises(binfera.CapaError, match="executable"):
        session.decompile(0x1)


@needs_decompiler
def test_decompiler_limits_are_validated():
    session = binfera.Decompiler(FIXTURE)
    session.set_limits(timeout_ms=5000)
    with pytest.raises(binfera.CapaError):
        session.set_limits(timeout_ms=0)


@needs_decompiler
def test_decompile_all_returns_events_and_streams_the_same_ones():
    events = binfera.decompile_all(FIXTURE)
    assert events[0]["type"] == "start" and events[-1]["type"] == "done"
    assert sum(e["type"] == "settled" for e in events) == 1
    assert events[0]["names"]
    assert all(isinstance(name, str) for name in events[0]["names"].values())
    functions = [e for e in events if e["type"] == "function"]
    assert {f["address"] for f in functions} >= set(events[0]["functions"])

    streamed = []
    assert binfera.decompile_all(FIXTURE, on_event=streamed.append) is None
    # Per-function timings differ run to run; everything else is the same record.
    def stable(records):
        return [
            {k: v for k, v in e.items() if k not in ("ms", "timings")} for e in records
        ]

    assert stable(streamed) == stable(events)


@needs_decompiler
def test_decompile_all_stops_on_a_callback_error():
    def fail(_event):
        raise ZeroDivisionError

    with pytest.raises(ZeroDivisionError):
        binfera.decompile_all(FIXTURE, on_event=fail)


@needs_decompiler
def test_decompile_all_shards_cover_every_function_once():
    covered = []
    for index in range(2):
        events = binfera.decompile_all(FIXTURE, shard=(index, 2))
        covered += [
            e["address"] for e in events if e["type"] == "function" and not e.get("extra")
        ]
    assert sorted(covered) == sorted(binfera.decompile_all(FIXTURE)[0]["functions"])


@pytest.mark.skipif(binfera.HAS_DECOMPILER, reason="build includes the decompiler")
def test_without_the_decompiler_the_names_raise_capa_error():
    with pytest.raises(binfera.CapaError):
        binfera.Decompiler(FIXTURE)
    with pytest.raises(binfera.CapaError):
        binfera.decompile_all(FIXTURE)
