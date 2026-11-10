"""Layers, limits and the reader contract with hostile sources and codecs (SPEC sections 5-9, 11)."""

from __future__ import annotations

import io
import threading
from typing import Any

import pytest

from helpers import LOOSE, Trickle, gz, kind_of, outcome, zl
from spillgate import (
    ClosedError,
    CorruptError,
    Decoder,
    InputLimitError,
    InternalError,
    InvalidOptionError,
    Limits,
    OutputLimitError,
    RatioLimitError,
    SourceError,
    SpillgateError,
    decode_all,
    reader,
)

# -- limits at the boundary -----------------------------------------------------


@pytest.mark.parametrize("codec", ["gzip", "deflate"])
def test_output_limit_boundary_minus_equal_plus(codec: str) -> None:
    """Covers: SG-R-LAY-02 SG-R-LAY-03 SG-I-01"""
    payload = bytes(range(256)) * 4
    stream = gz(payload) if codec == "gzip" else zl(payload)
    n = len(payload)
    assert outcome(stream, codec, Limits(max_output=n + 1, disable_ratio_limit=True)) == (
        "ok",
        payload,
    )
    assert outcome(stream, codec, Limits(max_output=n, disable_ratio_limit=True)) == ("ok", payload)
    kind, got = outcome(stream, codec, Limits(max_output=n - 1, disable_ratio_limit=True))
    assert kind == "output_limit" and got == payload[: n - 1]


def test_intermediate_layers_have_their_own_budget() -> None:
    """Covers: SG-R-LAY-01"""
    inner = gz(b"tiny")  # 24 bytes; the final output is only 4 bytes
    outer = gz(inner)
    limits = Limits(max_output=10, disable_ratio_limit=True)
    with pytest.raises(OutputLimitError) as caught:
        decode_all(outer, "gzip, gzip", limits)
    assert caught.value.layer == 1


def test_identity_is_bounded_too() -> None:
    """Covers: SG-R-CDC-10 SG-R-LAY-01"""
    assert outcome(b"x" * 10, "", Limits(max_output=10)) == ("ok", b"x" * 10)
    assert outcome(b"x" * 11, "identity", Limits(max_output=10))[0] == "output_limit"
    assert outcome(b"", [], Limits(max_output=1)) == ("ok", b"")


def test_ratio_limit_fires_and_names_the_layer() -> None:
    """Covers: SG-R-RAT-01 SG-I-02"""
    bomb = gz(bytes(5_000_000))
    limits = Limits(max_output=10**9, max_ratio=100, ratio_grace=1000)
    with pytest.raises(RatioLimitError) as caught:
        decode_all(bomb, "gzip", limits)
    assert caught.value.layer == 1 and caught.value.limit == 100


def test_ratio_opt_out_leaves_the_output_limit_in_force() -> None:
    """Covers: SG-R-RAT-04"""
    bomb = gz(bytes(5_000_000))
    assert (
        outcome(bomb, "gzip", Limits(max_output=1000, disable_ratio_limit=True))[0]
        == "output_limit"
    )


def test_ratio_grace_is_respected() -> None:
    """Covers: SG-R-RAT-01"""
    bomb = gz(bytes(60_000))  # ratio about 1000, below the 64 KiB default grace
    assert outcome(bomb, "gzip", Limits(max_output=10**6, max_ratio=2))[0] == "ok"
    assert (
        outcome(bomb, "gzip", Limits(max_output=10**6, max_ratio=2, ratio_grace=100))[0]
        == "ratio_limit"
    )


def test_end_to_end_ratio_across_layers() -> None:
    """Covers: SG-R-RAT-03"""
    inner = gz(bytes(3_000_000))
    outer = gz(inner)
    limits = Limits(max_output=10**9, max_ratio=300, ratio_grace=1000)
    assert outcome(outer, "gzip, gzip", limits)[0] == "ratio_limit"


def test_input_limit_is_exact_and_counts_the_source() -> None:
    """Covers: SG-R-INP-01 SG-R-INP-02"""
    stream = gz(b"hello world" * 50)
    n = len(stream)
    assert outcome(stream, "gzip", Limits(max_output=10**6, max_input=n))[0] == "ok"
    assert outcome(stream, "gzip", Limits(max_output=10**6, max_input=n - 1))[0] == "input_limit"
    source = Trickle(stream + b"extra bytes behind the stream", step=7)
    outcome(source, "gzip", Limits(max_output=10**6, max_input=n))
    assert source.total <= n + 1


def test_input_limit_applies_to_identity_chains() -> None:
    """Covers: SG-R-INP-01"""
    assert outcome(b"x" * 100, "identity", Limits(max_output=1000, max_input=100))[0] == "ok"
    assert (
        outcome(b"x" * 101, "identity", Limits(max_output=1000, max_input=100))[0] == "input_limit"
    )


# -- reader contract -----------------------------------------------------------


def test_result_does_not_depend_on_read_sizes() -> None:
    """Covers: SG-R-RDR-01 SG-I-09"""
    payload = bytes(range(251)) * 400
    stream = gz(payload)
    for sizes in ([1], [3], [4096], [1 << 20], [1, 7, 4096, 1], [0, 2]):
        chain = reader(stream, "gzip", LOOSE)
        got = bytearray()
        i = 0
        while True:
            chunk = chain.read(sizes[i % len(sizes)])
            i += 1
            if sizes[(i - 1) % len(sizes)] == 0:
                assert chunk == b""
                if i > 3 * len(payload):
                    break
                continue
            if not chunk:
                break
            got += chunk
        assert bytes(got) == payload, sizes


def test_source_chunking_does_not_matter() -> None:
    """Covers: SG-R-RDR-01 SG-I-09"""
    payload = b"chunky" * 5000
    for step in (1, 2, 3, 100, 4096, 70000):
        assert decode_all(Trickle(gz(payload), step), "gzip", LOOSE) == payload


def test_errors_are_sticky_and_a_clean_end_is_sticky() -> None:
    """Covers: SG-R-LAY-05 SG-I-03"""
    chain = reader(gz(bytes(100_000)), "gzip", Limits(max_output=10, disable_ratio_limit=True))
    assert chain.read(100) == bytes(10)  # the allowed bytes arrive first
    with pytest.raises(OutputLimitError):
        chain.read(100)
    for _ in range(3):
        with pytest.raises(OutputLimitError):
            chain.read(1)
    ok = reader(gz(b"abc"), "gzip", LOOSE)
    assert ok.readall() == b"abc"
    assert ok.read(10) == b"" and ok.read(10) == b""


def test_zero_length_read_changes_nothing() -> None:
    """Covers: SG-R-RDR-02"""
    chain = reader(gz(b"abc"), "gzip", LOOSE)
    assert chain.read(0) == b""
    assert chain.read(10) == b"abc"
    assert chain.read(0) == b""


def test_limit_hit_never_looks_like_end_of_stream() -> None:
    """Covers: SG-R-LAY-04 SG-I-02"""
    for read_size in (1, 100, 1 << 20):
        chain = reader(
            gz(bytes(100_000)), "gzip", Limits(max_output=1000, disable_ratio_limit=True)
        )
        total = 0
        with pytest.raises(OutputLimitError):
            while chunk := chain.read(read_size):
                total += len(chunk)
        assert total == 1000


def test_read_all_returns_no_data_on_error() -> None:
    """Covers: SG-R-API-02 SG-R-LAY-06"""
    with pytest.raises(OutputLimitError):
        decode_all(gz(bytes(100_000)), "gzip", Limits(max_output=1000, disable_ratio_limit=True))


def test_streaming_may_deliver_bytes_before_a_later_error() -> None:
    """Covers: SG-R-LAY-06"""
    stream = bytearray(gz(bytes(range(256)) * 100))
    stream[-6] ^= 0xFF  # damage the CRC
    chain = reader(bytes(stream), "gzip", LOOSE)
    delivered = 0
    with pytest.raises(CorruptError):
        while chunk := chain.read(64):
            delivered += len(chunk)
    assert delivered == 25600


# -- close ----------------------------------------------------------------------


def test_close_is_idempotent_and_leaves_the_source_open() -> None:
    """Covers: SG-R-RDR-06 SG-I-10"""
    source = io.BytesIO(gz(b"abc"))
    chain = reader(source, "gzip", LOOSE)
    chain.read(1)
    chain.close()
    chain.close()
    assert chain.closed and not source.closed
    with pytest.raises(ClosedError):
        chain.read(1)
    with pytest.raises(ClosedError):
        chain.readall()


def test_context_manager_closes() -> None:
    """Covers: SG-R-RDR-06"""
    with reader(gz(b"abc"), "gzip", LOOSE) as chain:
        assert chain.read() == b"abc"
    assert chain.closed


# -- hostile sources ----------------------------------------------------------------


class Raises:
    def __init__(self, error: BaseException, after: bytes = b"") -> None:
        self._error, self._after = error, after

    def read(self, n: int) -> bytes:
        if self._after:
            data, self._after = self._after[:n], self._after[n:]
            return data
        raise self._error


def test_source_exception_is_source_error_with_the_original_as_cause() -> None:
    """Covers: SG-R-RDR-05"""
    boom = OSError("connection reset")
    for encoding in ("gzip", "deflate", "identity"):
        with pytest.raises(SourceError) as caught:
            decode_all(
                Raises(boom, gz(b"abc")[:10] if encoding == "gzip" else b""), encoding, LOOSE
            )
        assert caught.value.__cause__ is boom
        assert caught.value.layer == 1


def test_source_exception_is_sticky() -> None:
    """Covers: SG-R-RDR-05 SG-R-LAY-05"""
    chain = reader(Raises(OSError("x")), "gzip", LOOSE)
    for _ in range(3):
        with pytest.raises(SourceError):
            chain.read(10)


def test_truncated_source_is_corrupt_not_source_error() -> None:
    """Covers: SG-R-CDC-06 SG-R-RDR-05"""
    stream = gz(b"abc" * 1000)
    for cut in (0, 1, 5, 10, 12, len(stream) // 2, len(stream) - 1):
        assert outcome(stream[:cut], "gzip")[0] == "corrupt", cut


class NoProgress:
    def __init__(self) -> None:
        self.calls = 0

    def read(self, n: int) -> None:
        self.calls += 1


def test_source_that_makes_no_progress_is_internal() -> None:
    """Covers: SG-R-RDR-03"""
    source = NoProgress()
    with pytest.raises(InternalError):
        decode_all(source, "gzip", LOOSE)
    assert source.calls == 100


def test_source_that_returns_too_much_or_the_wrong_type_is_internal() -> None:
    """Covers: SG-R-RDR-04"""

    class TooMuch:
        def read(self, n: int) -> bytes:
            return b"x" * (n + 1)

    class WrongType:
        def read(self, n: int) -> str:
            return "text"

    for source in (TooMuch(), WrongType()):
        with pytest.raises(InternalError):
            decode_all(source, "identity", LOOSE)


def test_source_accepts_bytes_bytearray_memoryview_and_files() -> None:
    """Covers: SG-R-API-01"""
    stream = gz(b"data")
    for source in (stream, bytearray(stream), memoryview(stream), io.BytesIO(stream)):
        assert decode_all(source, "gzip", LOOSE) == b"data"
    with pytest.raises(TypeError):
        decode_all(object(), "gzip", LOOSE)
    with pytest.raises(TypeError):
        decode_all("not bytes", "gzip", LOOSE)


# -- extension codecs -----------------------------------------------------------------


class ForeverZeros:
    """A codec that never ends: the guard alone must bound it."""

    def new_reader(self, source: Any) -> Any:
        return self

    def read(self, n: int) -> bytes:
        return bytes(n)


class Misbehaving:
    def __init__(self, behavior: str) -> None:
        self.behavior = behavior
        self.closed = 0

    def new_reader(self, source: Any) -> Any:
        if self.behavior == "new":
            raise RuntimeError("new_reader failed")
        return self

    def read(self, n: int) -> Any:
        if self.behavior == "raise":
            raise ValueError("secret attacker data")
        if self.behavior == "too_much":
            return b"x" * (n + 5)
        if self.behavior == "none":
            return None
        if self.behavior == "str":
            return "abc"
        if self.behavior == "recursion":
            return self.read(n)
        raise AssertionError(self.behavior)

    def close(self) -> None:
        self.closed += 1
        raise RuntimeError("close failed")


def test_extension_codec_is_bounded_by_the_same_limiter() -> None:
    """Covers: SG-R-CDC-01 SG-R-CDC-09 SG-I-01"""
    decoder = Decoder(
        Limits(max_output=1000, disable_ratio_limit=True), codecs={"zeros": ForeverZeros()}
    )
    with pytest.raises(OutputLimitError):
        decoder.read_all(b"a", "zeros")
    ratio = Decoder(
        Limits(max_output=10**9, max_ratio=10, ratio_grace=0), codecs={"zeros": ForeverZeros()}
    )
    with pytest.raises(RatioLimitError):
        ratio.read_all(b"abc", "zeros")


@pytest.mark.parametrize("behavior", ["raise", "too_much", "none", "str", "recursion"])
def test_misbehaving_codec_is_internal_and_leaks_no_data(behavior: str) -> None:
    """Covers: SG-R-CDC-08 SG-I-05"""
    decoder = Decoder(LOOSE, codecs={"bad": Misbehaving(behavior)})
    with pytest.raises(InternalError) as caught:
        decoder.read_all(b"abc", "bad")
    assert "secret" not in str(caught.value)


def test_codec_that_fails_to_construct_or_close_is_contained() -> None:
    """Covers: SG-R-CDC-08 SG-I-05"""
    with pytest.raises(InternalError):
        Decoder(LOOSE, codecs={"bad": Misbehaving("new")}).reader(b"abc", "bad")
    bad = Misbehaving("raise")
    chain = Decoder(LOOSE, codecs={"bad": bad}).reader(b"abc", "bad")
    chain.close()  # must not raise
    assert bad.closed == 1


def test_codec_can_raise_its_own_spillgate_error() -> None:
    """Covers: SG-R-CDC-04 SG-R-CDC-09"""

    class Refuses:
        def new_reader(self, source: Any) -> Any:
            return self

        def read(self, n: int) -> bytes:
            raise CorruptError("my format is broken")

    with pytest.raises(CorruptError) as caught:
        Decoder(LOOSE, codecs={"mine": Refuses()}).read_all(b"x", "mine")
    assert caught.value.layer == 1


@pytest.mark.parametrize(
    "name", ["identity", "gzip", "deflate", "x-gzip", "GZIP", "Has Space", "", "x" * 40, "a;b"]
)
def test_codec_names_are_checked(name: str) -> None:
    """Covers: SG-R-CDC-09"""
    with pytest.raises(InvalidOptionError):
        Decoder(LOOSE, codecs={name: ForeverZeros()})


def test_registered_codec_is_per_decoder_not_global() -> None:
    """Covers: SG-R-CDC-09"""
    Decoder(LOOSE, codecs={"zeros": ForeverZeros()})
    with pytest.raises(SpillgateError) as caught:
        Decoder(LOOSE).reader(b"", "zeros")
    assert kind_of(caught.value) == "unsupported_encoding"


# -- decoder object -----------------------------------------------------------------


def test_decoder_is_immutable_and_shared_across_threads() -> None:
    """Covers: SG-R-RDR-07"""
    decoder = Decoder(LOOSE)
    payload = [bytes([i]) * (2000 + i) for i in range(16)]
    results: list[bytes | None] = [None] * 16

    def work(i: int) -> None:
        for _ in range(20):
            results[i] = decoder.read_all(gz(payload[i]), "gzip")

    threads = [threading.Thread(target=work, args=(i,)) for i in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results == payload
    with pytest.raises(TypeError):
        decoder._codecs["x"] = ForeverZeros()  # type: ignore[index]


def test_decoder_needs_limits() -> None:
    """Covers: SG-R-API-01"""
    with pytest.raises(TypeError):
        Decoder()  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        Decoder({"max_output": 10})  # type: ignore[arg-type]


def test_distinct_readers_are_independent() -> None:
    """Covers: SG-R-RDR-07"""
    decoder = Decoder(LOOSE)
    a = decoder.reader(gz(b"A" * 1000), "gzip")
    b = decoder.reader(gz(b"B" * 1000), "gzip")
    assert a.read(10) == b"A" * 10 and b.read(10) == b"B" * 10
    a.close()
    assert b.readall() == b"B" * 990


def test_input_cap_pass_through_errors_from_lower_layers() -> None:
    """Covers: SG-R-INP-01 SG-R-LAY-01"""
    with pytest.raises(InputLimitError) as caught:
        decode_all(gz(gz(b"x" * 1000)), "gzip, gzip", Limits(max_output=10**6, max_input=20))
    assert caught.value.layer == 1
