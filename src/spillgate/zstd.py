"""Zstandard (RFC 8878, RFC 9659) as an optional codec: ``pip install "spillgate[zstd]"``.

    from spillgate import Decoder, Limits
    from spillgate import zstd

    decoder = Decoder(Limits(max_output=8 * 2**20), codecs={"zstd": zstd.codec()})

The decoder is the C library behind the ``zstandard`` package, treated as untrusted code.
spillgate reads the frame structure itself and gives the library one block at a time:

* The frame header is validated before the library sees it: the reserved bit, a dictionary
  (refused as ``corrupt``), and the window size, including the window that a single-segment
  frame gets from its declared content size, checked against the cap (SG-R-CDC-05). The default
  cap is 8 MiB (the 8 MB that RFC 9659 requires decoders to support).
* A block larger than 128 KiB and the reserved block type are ``corrupt``. A block decodes to at
  most 128 KiB, so one step of the library has a constant memory bound without relying on an
  output limit of the library (``zstandard`` has none for streaming).
* Skippable frames are skipped by spillgate and count as consumed input only. Bytes that do
  not start a frame are ``corrupt``.
* Declared content sizes are never used for any decision (SG-R-CDC-07).
"""

from __future__ import annotations

import importlib.metadata
import struct
from typing import Any

from ._meter import InputMeter
from .errors import (
    CorruptError,
    InternalError,
    InvalidOptionError,
    MemoryLimitError,
    SpillgateError,
)

__all__ = ["DEFAULT_MAX_WINDOW", "MAX_WINDOW", "MIN_WINDOW", "ZstdCodec", "codec"]

DEFAULT_MAX_WINDOW = 8 * 2**20
MIN_WINDOW = 1 << 10
MAX_WINDOW = 1 << 30
MIN_ZSTANDARD_VERSION = (0, 25, 0)

_FRAME_MAGIC = 0xFD2FB528
_SKIPPABLE_MAGIC = 0x184D2A50
_SKIPPABLE_MASK = 0xFFFFFFF0
_MAX_BLOCK = 128 * 1024
_BLOCK_RAW, _BLOCK_RLE, _BLOCK_COMPRESSED, _BLOCK_RESERVED = 0, 1, 2, 3
_SKIP_STEP = 4096


def _load_zstandard() -> Any:
    try:
        import zstandard  # type: ignore[import-untyped, unused-ignore]  # optional dependency
    except ImportError as error:
        raise ImportError(
            'zstd support needs the optional dependency: pip install "spillgate[zstd]"'
        ) from error
    try:
        version = tuple(int(p) for p in importlib.metadata.version("zstandard").split(".")[:3])
    except (importlib.metadata.PackageNotFoundError, ValueError):
        version = ()
    if version < MIN_ZSTANDARD_VERSION:
        raise ImportError("spillgate needs zstandard >= 0.25.0 (libzstd 1.5.7); upgrade it")
    return zstandard


class ZstdCodec:
    """The ``zstd`` codec. Create it with :func:`codec`."""

    def __init__(self, max_window_bytes: int = DEFAULT_MAX_WINDOW) -> None:
        if (
            isinstance(max_window_bytes, bool)
            or not isinstance(max_window_bytes, int)
            or not MIN_WINDOW <= max_window_bytes <= MAX_WINDOW
        ):
            raise InvalidOptionError(
                f"max_window_bytes must be an integer in {MIN_WINDOW}..{MAX_WINDOW}"
            )
        self._max_window = int(max_window_bytes)
        self._zstandard = _load_zstandard()

    def new_reader(self, source: InputMeter) -> ZstdReader:
        return ZstdReader(source, self._zstandard, self._max_window)


def codec(max_window_bytes: int = DEFAULT_MAX_WINDOW) -> ZstdCodec:
    """Return the zstd codec; frames whose window exceeds ``max_window_bytes`` are refused as
    ``memory_limit``."""
    return ZstdCodec(max_window_bytes)


def _little_endian(data: bytes) -> int:
    return int.from_bytes(data, "little")


class ZstdReader:
    """Decodes a sequence of zstd frames and skippable frames."""

    def __init__(self, source: InputMeter, zstandard: Any, max_window: int) -> None:
        self._source = source
        self._zstandard = zstandard
        self._max_window = max_window
        self._frames = 0
        self._decoder: Any = None  # the library's decompressor for the frame being decoded
        self._checksum = False
        self._buffer = b""
        self._pos = 0
        self._deferred: SpillgateError | None = None  # a failure found after the last block

    def read(self, n: int) -> bytes:
        while self._pos == len(self._buffer):
            if self._deferred is not None:
                raise self._deferred
            if not self._step():
                return b""
        chunk = self._buffer[self._pos : self._pos + n]
        self._pos += len(chunk)
        return chunk

    def close(self) -> None:
        self._decoder = None
        self._buffer = b""

    # -- frames ---------------------------------------------------------------------

    def _step(self) -> bool:
        """Advance by one block (or frame boundary). False means a clean end of the input."""
        if self._decoder is None:
            return self._next_frame()
        self._block()
        return True

    def _next_frame(self) -> bool:
        first = self._source.take(1)
        if not first:
            if self._frames > 0:
                return False
            raise CorruptError("zstd: an empty input is not a zstd stream")
        magic = _little_endian(first + self._source.take_exact(3, "zstd magic number"))
        if magic == _FRAME_MAGIC:
            self._start_frame(magic)
        elif magic & _SKIPPABLE_MASK == _SKIPPABLE_MAGIC:
            self._skip_frame()
        else:
            raise CorruptError("zstd: data that is not a zstd frame follows the stream")
        return True

    def _skip_frame(self) -> None:
        size = _little_endian(self._source.take_exact(4, "zstd skippable frame"))
        while size > 0:
            chunk = self._source.take(min(size, _SKIP_STEP))
            if not chunk:
                raise CorruptError("zstd: a skippable frame ends too early")
            size -= len(chunk)
        self._frames += 1  # a skippable frame is a frame: the input may end after it

    def _start_frame(self, magic: int) -> None:
        header = self._read_header(magic)
        decompressor = self._zstandard.ZstdDecompressor(max_window_size=self._max_window)
        self._decoder = decompressor.decompressobj()
        self._feed(header)  # produces no output; the library validates its own copy as well

    def _read_header(self, magic: int) -> bytes:
        source = self._source
        raw = bytearray(struct.pack("<I", magic))
        descriptor = source.take_exact(1, "zstd frame header")
        raw += descriptor
        d = descriptor[0]
        single_segment = bool(d & (1 << 5))
        self._checksum = bool(d & (1 << 2))
        if d & (1 << 3):
            raise CorruptError("zstd: reserved bit set in the frame header")

        window = 0
        if not single_segment:
            window_descriptor = source.take_exact(1, "zstd frame header")
            raw += window_descriptor
            exponent, mantissa = window_descriptor[0] >> 3, window_descriptor[0] & 7
            base = 1 << (10 + exponent)
            window = base + base // 8 * mantissa

        dictionary = source.take_exact((0, 1, 2, 4)[d & 3], "zstd frame header")
        raw += dictionary
        if any(dictionary):
            raise CorruptError("zstd: the frame needs a dictionary")

        fcs_size = (0, 2, 4, 8)[d >> 6]
        if d >> 6 == 0 and single_segment:
            fcs_size = 1
        fcs = source.take_exact(fcs_size, "zstd frame header")
        raw += fcs
        if single_segment:
            window = _little_endian(fcs) + (256 if len(fcs) == 2 else 0)

        if window > self._max_window:
            raise MemoryLimitError(
                f"zstd frame asks for a window of {window} bytes (the cap is {self._max_window})"
            )
        return bytes(raw)

    # -- blocks ---------------------------------------------------------------------

    def _block(self) -> None:
        header = self._source.take_exact(3, "zstd block header")
        value = _little_endian(header)
        last = bool(value & 1)
        block_type = value >> 1 & 3
        size = value >> 3
        if block_type == _BLOCK_RESERVED:
            raise CorruptError("zstd: reserved block type")
        if size > _MAX_BLOCK:
            raise CorruptError(f"zstd: block of {size} bytes, the maximum is {_MAX_BLOCK}")
        stored = 1 if block_type == _BLOCK_RLE else size  # an RLE block stores one byte
        body = self._source.take_exact(stored, "zstd block")
        out = self._feed(header + body)
        if last:
            # The bytes of the last block were produced before the checksum is checked, so
            # they are delivered first and a failure follows them (SG-R-LAY-07).
            try:
                if self._checksum:
                    self._feed(self._source.take_exact(4, "zstd content checksum"))
                if not self._decoder.eof:
                    raise CorruptError("zstd: the frame is incomplete after its last block")
            except SpillgateError as error:
                self._deferred = error
            self._decoder = None  # the frame is complete; look for the next one
            self._frames += 1
        self._buffer, self._pos = out, 0

    def _feed(self, data: bytes) -> bytes:
        try:
            out = self._decoder.decompress(data)
        except self._zstandard.ZstdError:
            raise CorruptError("zstd: invalid data") from None
        if len(out) > _MAX_BLOCK + 4:
            # A block decodes to at most 128 KiB; more means the library broke that promise.
            raise InternalError("zstd: the decoder produced more than one block of output")
        return bytes(out)
