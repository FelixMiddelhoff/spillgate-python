"""gzip (RFC 1952), SG-R-CDC-02.

The framing is parsed here, not by the ``gzip`` module, so every size is bounded
and every rule of the specification is explicit: the DEFLATE body is decoded by
:class:`~spillgate._inflate.RawInflater`.
"""

from __future__ import annotations

import zlib

from ._inflate import RawInflater
from ._meter import InputMeter
from .errors import CorruptError

_ID1, _ID2, _CM_DEFLATE = 0x1F, 0x8B, 8
_FLAG_HCRC, _FLAG_EXTRA, _FLAG_NAME, _FLAG_COMMENT = 1 << 1, 1 << 2, 1 << 3, 1 << 4
_RESERVED_FLAGS = 0xE0  # RFC 1952 requires an error if any is set
_FIXED_HEADER = 10
_TRAILER = 8
_MAX_STRING = 512  # FNAME and FCOMMENT, terminator included (SG-R-CDC-02)
_MASK32 = 0xFFFFFFFF


class GzipCodec:
    """The built-in ``gzip`` codec."""

    def new_reader(self, source: InputMeter) -> GzipReader:
        return GzipReader(source)


class GzipReader:
    """Decodes a sequence of gzip members that share one output budget."""

    def __init__(self, source: InputMeter) -> None:
        self._source = source
        self._body: RawInflater | None = None
        self._crc = 0
        self._size = 0  # modulo 2**32
        self._pending_trailer = False  # the body ended; its trailer is checked on the next read

    def read(self, n: int) -> bytes:
        if self._body is None:
            self._start_member(first=True)  # the first member is mandatory
        while True:
            if self._pending_trailer:
                self._pending_trailer = False
                if not self._finish_member():
                    return b""  # clean end after the last member
            assert self._body is not None
            data = self._body.read(n)
            if data:
                self._crc = zlib.crc32(data, self._crc)
                self._size = (self._size + len(data)) & _MASK32
                return data
            # The DEFLATE body ended. Its trailer is checked now, but bytes already
            # produced were delivered first, as in the reference implementation.
            self._pending_trailer = True

    def close(self) -> None:
        self._body = None

    # -- members ---------------------------------------------------------------

    def _finish_member(self) -> bool:
        """Check the trailer; start the next member. False means a clean end."""
        trailer = self._source.take_exact(_TRAILER, "gzip trailer")
        if int.from_bytes(trailer[:4], "little") != self._crc:
            raise CorruptError("gzip: checksum mismatch")
        if int.from_bytes(trailer[4:], "little") != self._size:
            raise CorruptError("gzip: size mismatch")  # ISIZE is checked, never trusted
        self._crc = self._size = 0
        return self._start_member(first=False)

    def _start_member(self, *, first: bool) -> bool:
        """Parse a member header. False means no further member (clean end)."""
        if not first:
            probe = self._source.take(1)
            if not probe:
                return False
            self._source.unread(probe)
        fixed = self._source.take_exact(_FIXED_HEADER, "gzip header")
        if fixed[0] != _ID1 or fixed[1] != _ID2 or fixed[2] != _CM_DEFLATE:
            raise CorruptError("gzip: invalid header")
        flags = fixed[3]
        if flags & _RESERVED_FLAGS:
            raise CorruptError("gzip: reserved header flags are set")

        header_crc = zlib.crc32(fixed)
        if flags & _FLAG_EXTRA:
            header_crc = self._skip_extra(header_crc)
        if flags & _FLAG_NAME:
            header_crc = self._skip_string(header_crc, "name")
        if flags & _FLAG_COMMENT:
            header_crc = self._skip_string(header_crc, "comment")
        if flags & _FLAG_HCRC:
            stored = int.from_bytes(self._source.take_exact(2, "gzip header checksum"), "little")
            if stored != header_crc & 0xFFFF:
                raise CorruptError("gzip: header checksum mismatch")

        self._body = RawInflater(self._source, "gzip")
        return True

    def _skip_extra(self, header_crc: int) -> int:
        """FEXTRA: at most 65535 bytes by format, read in small pieces (SG-R-MEM-01)."""
        length_bytes = self._source.take_exact(2, "gzip extra field")
        header_crc = zlib.crc32(length_bytes, header_crc)
        remaining = int.from_bytes(length_bytes, "little")
        while remaining > 0:
            chunk = self._source.take_exact(min(remaining, _MAX_STRING), "gzip extra field")
            header_crc = zlib.crc32(chunk, header_crc)
            remaining -= len(chunk)
        return header_crc

    def _skip_string(self, header_crc: int, what: str) -> int:
        """FNAME / FCOMMENT: zero-terminated, at most 512 bytes including the terminator."""
        collected = bytearray()
        while len(collected) < _MAX_STRING:
            chunk = self._source.take(_MAX_STRING - len(collected))
            if not chunk:
                raise CorruptError(f"gzip: header {what} ends too early")
            end = chunk.find(b"\0")
            if end >= 0:
                self._source.unread(chunk[end + 1 :])
                collected += chunk[: end + 1]
                return zlib.crc32(bytes(collected), header_crc)
            collected += chunk
        raise CorruptError(f"gzip: header {what} is longer than {_MAX_STRING - 1} bytes")
