"""Property tests (Hypothesis): invariants that must hold for any input."""

from __future__ import annotations

import io
import os

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from helpers import LOOSE, gz, raw, zl
from spillgate import Decoder, Kind, Limits, SpillgateError

PERMITTED = set(Kind) - {Kind.CANCELED}
ENCODINGS = ["gzip", "deflate", "identity", "gzip, gzip", "deflate, gzip", "x-gzip"]
FAST = settings(
    max_examples=int(os.environ.get("SPILLGATE_HYPOTHESIS_EXAMPLES", "300")),
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)


def run(
    source: bytes, encodings: str, limits: Limits, sizes: list[int]
) -> tuple[bytes, Kind | None]:
    """Decode with a cyclic read pattern; return the bytes and the error kind (None = clean end)."""
    out = bytearray()
    try:
        chain = Decoder(limits).reader(io.BytesIO(source), encodings)
    except SpillgateError as error:
        return b"", error.kind
    i = 0
    with chain:
        while True:
            try:
                chunk = chain.read(sizes[i % len(sizes)])
            except SpillgateError as error:
                return bytes(out), error.kind
            i += 1
            if not chunk and sizes[(i - 1) % len(sizes)] != 0:
                return bytes(out), None
            out += chunk
            if i > 5_000_000:  # a zero-size-only pattern would never finish
                return bytes(out), None


@FAST
@given(
    source=st.binary(max_size=600),
    encodings=st.sampled_from(ENCODINGS),
    max_output=st.integers(1, 3000),
    sizes=st.lists(st.integers(1, 5000), min_size=1, max_size=4),
)
def test_random_bytes_never_break_an_invariant(
    source: bytes, encodings: str, max_output: int, sizes: list[int]
) -> None:
    """Covers: SG-I-01 SG-I-02 SG-I-05 SG-R-CDC-08

    Whatever the bytes are: no foreign exception, never more than max_output, and the outcome
    is one of the typed classes.
    """
    out, error = run(source, encodings, Limits(max_output=max_output), sizes)
    assert len(out) <= max_output
    assert error is None or error in PERMITTED


@FAST
@given(
    payload=st.binary(max_size=3000),
    pick=st.sampled_from(["gzip", "deflate", "raw"]),
    sizes_a=st.lists(st.integers(1, 700), min_size=1, max_size=3),
    sizes_b=st.lists(st.integers(1, 70000), min_size=1, max_size=3),
)
def test_valid_data_round_trips_whatever_the_read_sizes(
    payload: bytes, pick: str, sizes_a: list[int], sizes_b: list[int]
) -> None:
    """Covers: SG-R-RDR-01 SG-I-09"""
    stream = {"gzip": gz, "deflate": zl, "raw": raw}[pick](payload)
    encoding = "gzip" if pick == "gzip" else "deflate"
    limits = Limits(max_output=len(payload) + 10, disable_ratio_limit=True)
    first = run(stream, encoding, limits, sizes_a)
    assert first == (payload, None)
    assert run(stream, encoding, limits, sizes_b) == first


@FAST
@given(
    payload=st.binary(min_size=1, max_size=2000),
    pick=st.sampled_from(["gzip", "deflate", "raw"]),
    slack=st.integers(0, 3),
)
def test_the_output_limit_is_exact_for_any_payload(payload: bytes, pick: str, slack: int) -> None:
    """Covers: SG-R-LAY-03 SG-I-01"""
    stream = {"gzip": gz, "deflate": zl, "raw": raw}[pick](payload)
    encoding = "gzip" if pick == "gzip" else "deflate"
    n = len(payload)
    at = run(stream, encoding, Limits(max_output=n + slack, disable_ratio_limit=True), [97])
    assert at == (payload, None)
    if n > 1:
        under, error = run(
            stream, encoding, Limits(max_output=n - 1, disable_ratio_limit=True), [97]
        )
        assert error is Kind.OUTPUT_LIMIT and under == payload[: n - 1]


@FAST
@given(
    payload=st.binary(min_size=1, max_size=800),
    flips=st.lists(st.tuples(st.integers(0, 10**6), st.integers(0, 7)), min_size=1, max_size=4),
    pick=st.sampled_from(["gzip", "deflate", "raw"]),
)
def test_damaged_streams_are_ok_or_corrupt_never_other(
    payload: bytes, flips: list[tuple[int, int]], pick: str
) -> None:
    """Covers: SG-I-05 SG-R-CDC-02 SG-R-CDC-03 SG-R-CDC-06"""
    stream = bytearray({"gzip": gz, "deflate": zl, "raw": raw}[pick](payload))
    for position, bit in flips:
        stream[position % len(stream)] ^= 1 << bit
    encoding = "gzip" if pick == "gzip" else "deflate"
    _, error = run(bytes(stream), encoding, LOOSE, [4096])
    assert error in {None, Kind.CORRUPT}


@FAST
@given(
    payload=st.binary(max_size=1500),
    cut=st.integers(0, 10**6),
    pick=st.sampled_from(["gzip", "deflate", "raw"]),
)
def test_truncation_is_corrupt(payload: bytes, cut: int, pick: str) -> None:
    """Covers: SG-R-CDC-06"""
    stream = {"gzip": gz, "deflate": zl, "raw": raw}[pick](payload)
    if len(stream) < 2:
        return
    encoding = "gzip" if pick == "gzip" else "deflate"
    _, error = run(stream[: cut % len(stream)], encoding, LOOSE, [4096])
    assert error is Kind.CORRUPT


@FAST
@given(
    header=st.lists(st.text(max_size=80), max_size=6),
    max_output=st.integers(1, 100),
)
def test_arbitrary_header_text_gives_a_typed_error_or_a_decoder(
    header: list[str], max_output: int
) -> None:
    """Covers: SG-I-05 SG-I-06 SG-R-HDR-13"""
    try:
        Decoder(Limits(max_output=max_output)).reader(b"", header)
    except SpillgateError as error:
        assert error.kind in {
            Kind.MALFORMED_ENCODING,
            Kind.UNSUPPORTED_ENCODING,
            Kind.LAYER_LIMIT,
        }
        message = str(error)
        assert "\n" not in message and "\r" not in message and len(message) < 400
