"""Cancellation, typed errors, look-ahead and the documented memory bounds."""

from __future__ import annotations

import io
from pathlib import Path

import pytest

import spillgate
from helpers import LOOSE, Trickle, gz
from spillgate import (
    CanceledError,
    Decoder,
    Kind,
    Limits,
    SpillgateError,
    decode_all,
    reader,
)
from spillgate._guard import MAX_STEP
from spillgate._meter import BUFFER_SIZE

DOCS = Path(__file__).resolve().parent.parent / "docs"


def test_cancellation_is_observed_per_read_and_sticky() -> None:
    """Covers: SG-R-API-04 SG-R-LAY-05"""
    calls = {"n": 0}

    def cancel() -> bool:
        calls["n"] += 1
        return calls["n"] > 3

    chain = Decoder(LOOSE).reader(gz(bytes(2_000_000)), "gzip", cancel=cancel)
    with pytest.raises(CanceledError) as caught:
        while chain.read(100):
            pass
    assert caught.value.kind is Kind.CANCELED
    for _ in range(3):
        with pytest.raises(CanceledError):
            chain.read(1)


def test_cancellation_is_observed_at_least_once_per_64_kib_of_input() -> None:
    """Covers: SG-R-API-04"""
    seen = {"bytes": 0, "polls": 0}
    payload = bytes(range(256)) * 2000
    source = Trickle(payload, step=10**6)

    def cancel() -> bool:
        seen["polls"] += 1
        seen["bytes"] = source.total
        return False

    Decoder(LOOSE).read_all(source, "identity", cancel=cancel)
    assert seen["polls"] >= len(payload) // (64 * 1024)
    assert seen["polls"] >= len(payload) // BUFFER_SIZE  # in fact once per refill


def test_cancel_before_the_first_read_never_touches_the_source() -> None:
    """Covers: SG-R-API-04"""
    source = Trickle(gz(b"abc"))
    chain = Decoder(LOOSE).reader(source, "gzip", cancel=lambda: True)
    with pytest.raises(CanceledError):
        chain.read(10)
    assert source.total == 0


def test_every_failure_has_a_machine_checkable_class_layer_and_limit() -> None:
    """Covers: SG-R-API-05"""
    with pytest.raises(spillgate.OutputLimitError) as caught:
        decode_all(gz(bytes(1000)), "gzip", Limits(max_output=10, disable_ratio_limit=True))
    error = caught.value
    assert isinstance(error, SpillgateError)
    assert (error.kind, error.layer, error.limit) == (Kind.OUTPUT_LIMIT, 1, 10)
    assert Kind.OUTPUT_LIMIT.value == "output_limit"
    assert {k.value for k in Kind} == {
        "invalid_limits", "output_limit", "ratio_limit", "layer_limit", "input_limit",
        "memory_limit", "unsupported_encoding", "malformed_encoding", "corrupt", "internal",
        "canceled", "source_error",
    }  # fmt: skip
    for cls in (
        spillgate.InvalidLimitsError, spillgate.RatioLimitError, spillgate.LayerLimitError,
        spillgate.InputLimitError, spillgate.MemoryLimitError, spillgate.CorruptError,
        spillgate.UnsupportedEncodingError, spillgate.MalformedEncodingError,
        spillgate.InternalError, spillgate.CanceledError, spillgate.SourceError,
    ):  # fmt: skip
        assert issubclass(cls, SpillgateError) and cls.kind in Kind


def test_after_a_terminal_condition_the_source_is_not_read_again() -> None:
    """Covers: SG-R-LAY-09"""
    source = Trickle(gz(bytes(100_000)) + b"x" * 1000, step=50)
    chain = reader(source, "gzip", Limits(max_output=100, disable_ratio_limit=True))
    with pytest.raises(spillgate.OutputLimitError):
        while chain.read(64):
            pass
    taken = source.total
    for _ in range(5):
        with pytest.raises(spillgate.OutputLimitError):
            chain.read(64)
    assert source.total == taken


def test_look_ahead_beyond_what_the_codec_needed_is_bounded() -> None:
    """Covers: SG-R-LAY-09 SG-R-RAT-02"""
    stream = gz(b"short")
    source = Trickle(stream + b"\0" * 1_000_000, step=10**6)
    with pytest.raises(spillgate.CorruptError):
        decode_all(source, "gzip", LOOSE)
    assert source.total <= len(stream) + 64 * 1024


def test_documented_memory_bounds_match_the_code() -> None:
    """Covers: SG-R-MEM-03 SG-R-MEM-02"""
    text = (DOCS / "memory.md").read_text(encoding="utf-8")
    assert f"{BUFFER_SIZE // 1024} KiB" in text and f"{MAX_STEP // 1024} KiB" in text
    assert BUFFER_SIZE <= 4 * 1024 * 1024 and MAX_STEP <= 4 * 1024 * 1024


def test_a_source_that_is_a_file_on_disk(tmp_path: Path) -> None:
    """Covers: SG-R-API-01 SG-R-RDR-06"""
    path = tmp_path / "body.gz"
    path.write_bytes(gz(b"from disk" * 100))
    with path.open("rb") as handle:
        assert decode_all(handle, "gzip", LOOSE) == b"from disk" * 100
        assert not handle.closed  # spillgate does not close the caller's source
    with path.open("rb", buffering=0) as raw_handle:
        assert decode_all(raw_handle, "gzip", LOOSE) == b"from disk" * 100
    assert isinstance(io.BytesIO(), io.IOBase)
