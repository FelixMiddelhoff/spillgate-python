"""Shared helpers for the unit tests."""

from __future__ import annotations

import gzip as _gzip
import io
import zlib
from typing import Any

from spillgate import Decoder, Kind, Limits, SpillgateError

LOOSE = Limits(max_output=1 << 30, disable_ratio_limit=True)


def gz(payload: bytes) -> bytes:
    return _gzip.compress(payload, mtime=0)


def zl(payload: bytes) -> bytes:
    return zlib.compress(payload)


def raw(payload: bytes) -> bytes:
    compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    return compressor.compress(payload) + compressor.flush()


def kind_of(error: BaseException | None) -> str:
    if error is None:
        return "ok"
    assert isinstance(error, SpillgateError), f"not a spillgate error: {error!r}"
    return error.kind.value


def outcome(
    source: Any, encodings: Any, limits: Limits = LOOSE, **options: Any
) -> tuple[str, bytes]:
    """Decode completely; return the outcome class and the bytes delivered before it."""
    delivered = bytearray()
    try:
        chain = Decoder(limits, **options).reader(source, encodings)
    except SpillgateError as error:
        return error.kind.value, b""
    with chain:
        while True:
            try:
                chunk = chain.read(4096)
            except SpillgateError as error:
                return error.kind.value, bytes(delivered)
            if not chunk:
                return "ok", bytes(delivered)
            delivered += chunk


def stream(payload: bytes) -> io.BytesIO:
    return io.BytesIO(payload)


class Trickle:
    """A source that hands out at most ``step`` bytes per read."""

    def __init__(self, payload: bytes, step: int = 1) -> None:
        self._inner = io.BytesIO(payload)
        self._step = step
        self.total = 0

    def read(self, n: int) -> bytes:
        chunk = self._inner.read(min(n, self._step))
        self.total += len(chunk)
        return chunk


def kinds() -> set[str]:
    return {k.value for k in Kind}
