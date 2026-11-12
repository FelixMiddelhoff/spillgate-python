"""F1 (found in the Java port): a source error late in the stream must not make the delivered prefix depend on the caller's read size or the source's chunking.

Covers: SG-R-RDR-01, SG-R-RDR-05, SG-R-LAY-05, SG-I-09
"""

from __future__ import annotations

import gzip as _gzip
import io
import random
import zlib

import pytest

from helpers import kind_of
from spillgate import Decoder, Limits, SourceError, SpillgateError

LIMITS = Limits(max_output=1 << 30, disable_ratio_limit=True)
SIZES = [1, 7, 4096, 1 << 20]
STEPS = [1, 997, 1 << 20]
_MIX = random.Random(11)
MODES = ["read", "readinto", "mixed"]


def _payload(size: int) -> bytes:
    rng = random.Random(7)
    words = [bytes(rng.randrange(97, 123) for _ in range(rng.randrange(3, 9))) for _ in range(300)]
    out = bytearray()
    while len(out) < size:
        out += rng.choice(words) + (b"\n" if rng.random() < 0.05 else b" ")
    return bytes(out[:size])


class Failing:
    """Hands out ``data`` in chunks of at most ``step``, then raises OSError instead of ending."""

    def __init__(self, data: bytes, step: int) -> None:
        self._inner = io.BytesIO(data)
        self._step = step

    def read(self, n: int) -> bytes:
        chunk = self._inner.read(min(n, self._step))
        if not chunk:
            raise OSError("boom")
        return chunk


def _once(chain: io.RawIOBase, mode: str, size: int) -> bytes:
    if mode == "read":
        return chain.read(size)
    if mode == "mixed":  # alternate the requested size so every call differs
        return chain.read(size if _MIX.random() < 0.5 else 1 + size // 3)
    buf = bytearray(size)
    return bytes(buf[: chain.readinto(buf)])


def _run(data: bytes, encodings: str, step: int, mode: str, size: int) -> tuple[str, bytes]:
    delivered = bytearray()
    with Decoder(LIMITS).reader(Failing(data, step), encodings) as chain:
        while True:
            try:
                part = _once(chain, mode, size)
            except SpillgateError as error:
                # sticky: the same class again, and no further bytes
                with pytest.raises(SpillgateError) as again:
                    _once(chain, mode, size)
                assert kind_of(again.value) == kind_of(error)
                return kind_of(error), bytes(delivered)
            if not part:
                return "ok", bytes(delivered)
            delivered += part


def _chain_data(layers: int, payload: bytes, cut: float) -> tuple[bytes, str]:
    data = payload
    for _ in range(layers):
        data = _gzip.compress(data, mtime=0)
    return data[: int(len(data) * cut)], ", ".join(["gzip"] * layers)


def _deflate_then_gzip(payload: bytes, cut: float) -> tuple[bytes, str]:
    data = _gzip.compress(zlib.compress(payload), mtime=0)
    return data[: int(len(data) * cut)], "deflate, gzip"


PAYLOAD = _payload(60_000)
CASES = {
    "gzip-late": lambda: _chain_data(1, PAYLOAD, 0.97),
    "gzip-early": lambda: _chain_data(1, PAYLOAD, 0.5),
    "gzip-gzip": lambda: _chain_data(2, PAYLOAD, 0.9),
    "gzip3": lambda: _chain_data(3, PAYLOAD, 0.9),
    "deflate-gzip": lambda: _deflate_then_gzip(PAYLOAD, 0.9),
}


@pytest.mark.parametrize("case", sorted(CASES))
def test_source_error_prefix_independent_of_read_size_and_chunking(case: str) -> None:
    """The source fails late; every read size, mode and source chunking delivers the same bytes."""
    data, encodings = CASES[case]()
    reference = _run(data, encodings, 1 << 20, "read", 1 << 20)
    assert reference[0] == "source_error"
    assert len(reference[1]) > 0
    for step in STEPS:
        for mode in MODES:
            for size in SIZES:
                got = _run(data, encodings, step, mode, size)
                assert got == reference, (case, step, mode, size, len(got[1]), len(reference[1]))


def test_source_error_in_lower_layer_keeps_original_cause() -> None:
    """A source failure under an inner layer surfaces as source_error with the original error."""
    data, encodings = _chain_data(2, PAYLOAD, 0.9)
    with (
        Decoder(LIMITS).reader(Failing(data, 4096), encodings) as chain,
        pytest.raises(SourceError) as info,
    ):
        while chain.read(4096):
            pass
    assert isinstance(info.value.__cause__, OSError) or isinstance(info.value.__context__, OSError)


def test_corrupt_lower_layer_prefix_independent_of_read_size() -> None:
    """A corrupt tail of a lower layer: same outcome class and same bytes for every read size."""
    inner = _gzip.compress(PAYLOAD, mtime=0)
    inner = inner[:-8] + bytes(8)  # bad CRC/ISIZE trailer
    data = _gzip.compress(inner, mtime=0)
    results = set()
    for step in STEPS:
        for mode in MODES:
            for size in SIZES:
                results.add(_run(data, "gzip, gzip", step, mode, size))
    assert len(results) == 1
    assert next(iter(results))[0] == "corrupt"
