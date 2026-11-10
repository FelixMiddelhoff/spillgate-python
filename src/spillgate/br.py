"""Brotli (RFC 7932) as an optional codec: ``pip install "spillgate[brotli]"``.

    from spillgate import Decoder, Limits
    from spillgate import br

    decoder = Decoder(Limits(max_output=8 * 2**20), codecs={"br": br.codec()})

The decoder is the C library behind the ``brotli`` package, treated as untrusted code:

* The window size is read from the first byte of the stream and checked against the cap
  *before* anything is decoded (SG-R-CDC-04). The default cap is 2**24 bytes (the RFC
  maximum); a lower cap (``max_window_bits``) saves memory on busy servers.
* The reserved large-window marker is refused as ``memory_limit`` whatever the cap is.
* Output is taken in steps of at most about 32 KiB (the library's ``output_buffer_limit`` is a
  soft limit that is compared with its allocated block size, so the first block is the
  smallest possible step), so memory per step is constant.
* Bytes after the last meta-block are ``corrupt``.

Versions of the ``brotli`` package before 1.2.1 are refused at import time: 1.2.0 added the
output limit that makes bounded decoding possible, and 1.2.1 fixed an out-of-bounds write in
the C decoder (CVE-2026-111497).
"""

from __future__ import annotations

import importlib.metadata
import re
from typing import Any

from ._meter import InputMeter
from .errors import CorruptError, InternalError, InvalidOptionError, MemoryLimitError

__all__ = ["DEFAULT_MAX_WINDOW_BITS", "MIN_WINDOW_BITS", "BrotliCodec", "codec"]

DEFAULT_MAX_WINDOW_BITS = 24
MIN_WINDOW_BITS = 10
MIN_BROTLI_VERSION = (1, 2, 1)

_FEED = 4096  # compressed bytes offered per step
_STEP = 16 * 1024  # output_buffer_limit; the library returns at most its first 32 KiB block
_STALL_LIMIT = 1000  # consecutive calls without progress before giving up


def _load_brotli() -> Any:
    try:
        import brotli  # type: ignore[import-untyped, unused-ignore]  # optional dependency
    except ImportError as error:
        raise ImportError(
            'brotli support needs the optional dependency: pip install "spillgate[brotli]"'
        ) from error
    versions = [
        _parse_version(getattr(brotli, "__version__", None)),
        _parse_version(_distribution_version("brotli")),
    ]
    # Both the loaded module and the installed distribution must be new enough: a shadowed or
    # stale module is not accepted because the metadata says otherwise, or the reverse.
    if any(v < MIN_BROTLI_VERSION for v in versions) or not hasattr(
        brotli.Decompressor, "can_accept_more_data"
    ):
        raise ImportError(
            "spillgate needs brotli >= 1.2.1 (bounded output and the CVE-2026-111497 fix); "
            "upgrade the 'brotli' package"
        )
    return brotli


def _distribution_version(name: str) -> str | None:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def _parse_version(text: object) -> tuple[int, ...]:
    """The leading ``major.minor.patch`` of a version string; unparseable means too old."""
    match = re.match(r"(\d+)\.(\d+)\.(\d+)", text) if isinstance(text, str) else None
    return tuple(int(part) for part in match.groups()) if match else (0, 0, 0)


def window_bits(first: int) -> tuple[int, bool]:
    """RFC 7932 section 9.1: the window bits announced by the first byte, and whether the
    stream uses the reserved large-window marker (WBITS pattern 1000001)."""
    if first & 1 == 0:
        return 16, False
    n = (first >> 1) & 7
    if n:
        return 17 + n, False
    m = (first >> 4) & 7
    if m == 0:
        return 17, False
    if m == 1:
        return 0, True
    return 8 + m, False


class BrotliCodec:
    """The ``br`` codec. Create it with :func:`codec`."""

    def __init__(self, max_window_bits: int = DEFAULT_MAX_WINDOW_BITS) -> None:
        if (
            isinstance(max_window_bits, bool)
            or not isinstance(max_window_bits, int)
            or not MIN_WINDOW_BITS <= max_window_bits <= DEFAULT_MAX_WINDOW_BITS
        ):
            raise InvalidOptionError(
                "max_window_bits must be an integer in "
                f"{MIN_WINDOW_BITS}..{DEFAULT_MAX_WINDOW_BITS}"
            )
        self._max_window_bits = int(max_window_bits)
        self._brotli = _load_brotli()

    def new_reader(self, source: InputMeter) -> BrotliReader:
        return BrotliReader(source, self._brotli, self._max_window_bits)


def codec(max_window_bits: int = DEFAULT_MAX_WINDOW_BITS) -> BrotliCodec:
    """Return the brotli codec; streams needing a larger window than ``2**max_window_bits - 16``
    bytes are refused as ``memory_limit``."""
    return BrotliCodec(max_window_bits)


class BrotliReader:
    """Decodes one brotli stream."""

    def __init__(self, source: InputMeter, brotli: Any, max_window_bits: int) -> None:
        self._source = source
        self._brotli = brotli
        self._max_window_bits = max_window_bits
        self._decoder: Any = None
        self._buffer = b""
        self._pos = 0
        self._ended = False
        self._draining = False  # decoded output may still be pending inside the library

    def read(self, n: int) -> bytes:
        if self._pos == len(self._buffer) and not self._refill():
            return b""
        chunk = self._buffer[self._pos : self._pos + n]
        self._pos += len(chunk)
        return chunk

    def close(self) -> None:
        self._decoder = None
        self._buffer = b""

    def _start(self) -> None:
        first = self._source.take(1)
        if not first:
            raise CorruptError("brotli: an empty input is not a brotli stream")
        bits, large = window_bits(first[0])
        if large:
            raise MemoryLimitError("brotli stream asks for a large window (not supported)")
        if bits > self._max_window_bits:
            raise MemoryLimitError(
                f"brotli stream asks for a window of 2**{bits} bytes "
                f"(the cap is 2**{self._max_window_bits})"
            )
        self._source.unread(first)  # the decoder must see the byte itself
        self._decoder = self._brotli.Decompressor()

    def _refill(self) -> bool:
        """Decode the next piece into the buffer. False means a clean end of the stream.

        The library keeps decoded output it has not handed out yet, even after it has taken all
        input, and ``can_accept_more_data()`` does not say whether such output is pending. So
        after every chunk of input the decoder is drained with empty ``process`` calls until it
        returns nothing; only then is the next chunk fed. A stream that ends while the decoder
        still wants input is truncated.
        """
        if self._ended:
            return False
        if self._decoder is None:
            self._start()
        decoder = self._decoder
        stalled = 0
        while not decoder.is_finished():
            out = b""
            try:
                if self._draining:
                    out = decoder.process(b"", output_buffer_limit=_STEP)
                    self._draining = bool(out)
                elif decoder.can_accept_more_data():
                    data = self._source.take(_FEED)
                    if not data:
                        raise CorruptError("brotli: the stream ends too early")
                    out = decoder.process(data, output_buffer_limit=_STEP)
                    self._draining = True
                    stalled = 0  # input was consumed: the stream is moving, even without output
                else:
                    self._draining = True
            except self._brotli.error:
                raise CorruptError("brotli: invalid data") from None
            if out:
                self._buffer, self._pos = bytes(out), 0
                return True
            stalled += 1
            if stalled > _STALL_LIMIT:
                raise InternalError("brotli: the decoder makes no progress")
        # The final meta-block is complete: nothing may follow it.
        self._ended = True
        if not self._source.at_end():
            raise CorruptError("brotli: unexpected data after the end of the stream")
        return False
