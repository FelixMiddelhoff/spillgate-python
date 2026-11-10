"""Regression tests for the findings of the independent security review."""

from __future__ import annotations

import io
from array import array
from typing import Any

import pytest

from helpers import LOOSE, gz
from spillgate import (
    CanceledError,
    Decoder,
    InternalError,
    InvalidLimitsError,
    Limits,
    MalformedEncodingError,
    RatioLimitError,
    SpillgateError,
    reader,
)
from spillgate.limits import EffectiveLimits

# -- a codec or source must not hide bytes behind a multi-byte-item memoryview ---------------


class _ItemsCodec:
    """read(n) returns n *items* of 4 bytes: len() says n, nbytes says 4n."""

    def new_reader(self, source: Any) -> Any:
        return self

    def read(self, n: int) -> memoryview:
        return memoryview(array("I", [65]) * n)


def test_codec_cannot_exceed_max_output_with_a_multi_byte_item_memoryview() -> None:
    """Covers: SG-I-01 SG-R-LAY-02 SG-R-CDC-08"""
    decoder = Decoder(
        Limits(max_output=100, disable_ratio_limit=True), codecs={"evil": _ItemsCodec()}
    )
    chain = decoder.reader(b"x", "evil")
    delivered = 0
    with pytest.raises(InternalError):
        while chunk := chain.read(65536):
            delivered += len(chunk)
    assert delivered == 0


class _ExactCodec:
    """Returns exactly n + 1 bytes: one more than allowed."""

    def new_reader(self, source: Any) -> Any:
        return self

    def read(self, n: int) -> bytes:
        return b"x" * (n + 1)


def test_codec_returning_exactly_one_byte_too_many_is_internal() -> None:
    """Covers: SG-R-CDC-08 SG-I-05"""
    chain = Decoder(LOOSE, codecs={"one": _ExactCodec()}).reader(b"x", "one")
    with pytest.raises(InternalError):
        chain.read(10)


def test_source_with_multi_byte_items_is_a_contract_violation() -> None:
    """Covers: SG-R-RDR-04"""

    class Items:
        def read(self, n: int) -> memoryview:
            return memoryview(array("I", [1]) * n)

    with pytest.raises(InternalError):
        Decoder(LOOSE).read_all(Items(), "identity")


# -- limits cannot be fooled by int subclasses or tampering ---------------------------------


class _LyingInt(int):
    """An int whose comparisons always say "in range"."""

    def __ge__(self, other: object) -> bool:
        return True

    def __le__(self, other: object) -> bool:
        return True

    def __gt__(self, other: object) -> bool:
        return True

    def __lt__(self, other: object) -> bool:
        return True


def test_int_subclass_with_lying_comparisons_is_checked_by_its_value() -> None:
    """Covers: SG-R-LIM-01 SG-R-LIM-02 SG-R-LIM-07"""
    with pytest.raises(InvalidLimitsError):
        Limits(max_output=_LyingInt(2**200))
    with pytest.raises(InvalidLimitsError):
        Limits(max_output=_LyingInt(-5))
    limits = Limits(max_output=_LyingInt(50))
    assert type(limits.max_output) is int and limits.max_output == 50


def test_limits_changed_behind_the_back_are_checked_again_by_the_decoder() -> None:
    """Covers: SG-R-LIM-08 SG-R-LIM-09"""
    limits = Limits(max_output=10)
    object.__setattr__(limits, "max_output", -5)
    with pytest.raises(InvalidLimitsError):
        Decoder(limits)
    with pytest.raises(InvalidLimitsError):
        EffectiveLimits.of(limits)


def test_subclass_that_skips_validation_is_still_checked() -> None:
    """Covers: SG-R-LIM-08"""

    class Sloppy(Limits):
        def __post_init__(self) -> None:  # skips every check
            pass

    with pytest.raises(InvalidLimitsError):
        Decoder(Sloppy(max_output=0))


# -- header strings cannot lie about their own size -----------------------------------------


class _ShortStr(str):
    def encode(self, *args: Any, **kwargs: Any) -> bytes:  # type: ignore[override]
        return b"gzip"

    def __len__(self) -> int:
        return 4


def test_str_subclass_cannot_evade_the_header_length_cap() -> None:
    """Covers: SG-R-HDR-02"""
    big = _ShortStr("," * 5000 + "gzip")
    with pytest.raises(MalformedEncodingError):
        Decoder(LOOSE).reader(b"", big)
    with pytest.raises(MalformedEncodingError):
        Decoder(LOOSE).reader(b"", [big])


# -- the cancel callable is contained ------------------------------------------------------


def test_cancel_callable_that_raises_becomes_a_sticky_internal_error() -> None:
    """Covers: SG-I-05 SG-R-API-04"""

    def broken() -> bool:
        raise ValueError("boom")

    chain = Decoder(LOOSE).reader(gz(b"x" * 100), "gzip", cancel=broken)
    for _ in range(3):
        with pytest.raises(InternalError) as caught:
            chain.read(10)
        assert isinstance(caught.value.__cause__, ValueError)


def test_cancel_raising_inside_the_input_meter_is_attributed_to_cancel() -> None:
    """Covers: SG-I-05 SG-R-API-04"""
    calls = {"n": 0}

    def flaky() -> bool:
        calls["n"] += 1
        if calls["n"] >= 2:
            raise RuntimeError("late failure")
        return False

    chain = Decoder(LOOSE).reader(bytes(100_000), "identity", cancel=flaky)
    with pytest.raises(InternalError) as caught:
        while chain.read(4096):
            pass
    assert "cancel" in str(caught.value) and "codec raised" not in str(caught.value)


def test_cancel_returning_a_truthy_non_bool_cancels() -> None:
    """Covers: SG-R-API-04"""
    chain = Decoder(LOOSE).reader(gz(b"abc"), "gzip", cancel=lambda: "yes")  # type: ignore[arg-type,return-value]
    with pytest.raises(CanceledError):
        chain.read(1)


# -- error layer attribution of the ratio error -----------------------------------------------


def test_a_single_layer_ratio_error_names_layer_one_not_the_chain() -> None:
    """Covers: SG-R-RAT-01 SG-R-RAT-03 SG-I-02"""
    bomb = gz(bytes(5_000_000))
    limits = Limits(max_output=10**9, max_ratio=100, ratio_grace=1000)
    chain = reader(bomb, "gzip", limits)
    with pytest.raises(RatioLimitError) as caught:
        while chain.read(100_000):
            pass
    assert caught.value.layer == 1


def test_an_end_to_end_only_ratio_error_has_no_layer() -> None:
    """Covers: SG-R-RAT-03"""
    # Layer 1 expands about 109:1, layer 2 about 1027:1, the whole chain about 111,000:1.
    # With max_ratio 2000 no single layer fires, only the end-to-end check can.
    inner = gz(bytes(20_000_000))
    outer = gz(inner)
    limits = Limits(max_output=10**9, max_ratio=2000, ratio_grace=1000)
    chain = reader(outer, "gzip, gzip", limits)
    with pytest.raises(RatioLimitError) as caught:
        while chain.read(100_000):
            pass
    assert caught.value.layer == 0
    assert "end-to-end" in str(caught.value)
    # And no layer fires on its own: the same chain passes with the check off.
    ok = Limits(max_output=10**9, disable_ratio_limit=True)
    assert len(reader(outer, "gzip, gzip", ok).readall()) == 20_000_000


# -- the file-object protocol ----------------------------------------------------------------


def test_chain_works_with_buffered_text_and_line_readers() -> None:
    """Covers: SG-R-RDR-01 SG-R-RDR-06"""
    payload = b"line one\nline two\r\nline three\n" * 50
    stream = gz(payload)
    assert io.BufferedReader(reader(stream, "gzip", LOOSE)).read() == payload  # type: ignore[arg-type]
    text = io.TextIOWrapper(io.BufferedReader(reader(stream, "gzip", LOOSE)), encoding="ascii")  # type: ignore[arg-type]
    assert text.read() == payload.decode().replace("\r\n", "\n")
    chain = reader(stream, "gzip", LOOSE)
    assert chain.readline() == b"line one\n"
    assert chain.readlines()[0] == b"line two\r\n"
    assert list(reader(stream, "gzip", LOOSE)) == payload.splitlines(keepends=True)


def test_read_with_zero_none_and_negative_sizes() -> None:
    """Covers: SG-R-RDR-02"""
    chain = reader(gz(b"abcdef"), "gzip", LOOSE)
    assert chain.read(0) == b""
    assert chain.read(None) == b"abcdef"
    assert chain.read(-1) == b""
    assert chain.readinto(bytearray(0)) == 0


def test_bounded_errors_through_buffered_reader_are_still_typed() -> None:
    """Covers: SG-I-02 SG-I-05"""
    chain = reader(gz(bytes(1_000_000)), "gzip", Limits(max_output=1000, disable_ratio_limit=True))
    buffered = io.BufferedReader(chain)  # type: ignore[arg-type]
    with pytest.raises(SpillgateError):
        buffered.read()


# -- sticky errors must not keep the reader alive ---------------------------------------------


def test_a_failed_reader_is_freed_without_the_cyclic_collector() -> None:
    """Covers: SG-I-10 SG-R-RDR-06

    A stored terminal error that carries a traceback refers back to the reader's frames. The
    readers store a traceback-free copy and raise a new one on each read, so dropping the last
    reference frees the decoder state at once, even for a reader that was never closed.
    """
    import gc
    import weakref

    gc.disable()
    try:
        chain = reader(
            gz(bytes(1_000_000)), "gzip", Limits(max_output=10, disable_ratio_limit=True)
        )
        probe = weakref.ref(chain)
        with pytest.raises(SpillgateError):
            while chain.read(100):
                pass
        for _ in range(3):
            with pytest.raises(SpillgateError):
                chain.read(1)
        del chain
        assert probe() is None
    finally:
        gc.enable()


def test_repeated_reads_of_a_sticky_error_do_not_grow_the_traceback() -> None:
    """Covers: SG-R-LAY-05"""
    chain = reader(gz(bytes(100_000)), "gzip", Limits(max_output=10, disable_ratio_limit=True))
    chain.read(100)
    depths = []
    for _ in range(50):
        try:
            chain.read(1)
        except SpillgateError as error:
            depth, tb = 0, error.__traceback__
            while tb is not None:
                depth, tb = depth + 1, tb.tb_next
            depths.append(depth)
    # The first read after the terminal condition still runs through the layers; from the
    # second on the chain replays its stored copy. The depth never grows.
    assert len(set(depths[1:])) == 1 and max(depths) <= 8
