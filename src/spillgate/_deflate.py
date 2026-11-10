"""HTTP ``deflate`` (RFC 9110 section 8.4.1.2), SG-R-CDC-03.

``deflate`` in HTTP means the zlib format (RFC 1950 around RFC 1951 data), but some
senders omit the wrapper. The first two bytes decide: a valid zlib header means zlib,
anything else is raw DEFLATE, unless ``strict_zlib`` forbids the fallback.
"""

from __future__ import annotations

import zlib

from ._inflate import RawInflater
from ._meter import InputMeter
from .errors import CorruptError

_CM_DEFLATE = 8
_MAX_CINFO = 7
_FLAG_DICT = 1 << 5
_CHECK_MODULUS = 31
_TRAILER = 4  # Adler-32, big-endian


def is_zlib_header(cmf: int, flg: int) -> bool:
    """RFC 1950: CM = 8, CINFO <= 7 and (CMF * 256 + FLG) divisible by 31."""
    return (
        cmf & 0x0F == _CM_DEFLATE
        and cmf >> 4 <= _MAX_CINFO
        and (cmf << 8 | flg) % _CHECK_MODULUS == 0
    )


class DeflateCodec:
    """The built-in ``deflate`` codec."""

    def __init__(self, *, strict_zlib: bool = False) -> None:
        self._strict = strict_zlib

    def new_reader(self, source: InputMeter) -> DeflateReader:
        return DeflateReader(source, strict=self._strict)


class DeflateReader:
    """Decodes one zlib or raw DEFLATE stream and checks that nothing follows it."""

    def __init__(self, source: InputMeter, *, strict: bool) -> None:
        self._source = source
        self._strict = strict
        self._body: RawInflater | None = None
        self._adler: int | None = None  # None for raw DEFLATE
        self._ended = False

    def read(self, n: int) -> bytes:
        if self._ended:
            return b""
        if self._body is None:
            self._start()
        assert self._body is not None
        data = self._body.read(n)
        if data:
            if self._adler is not None:
                self._adler = zlib.adler32(data, self._adler)
            return data
        self._finish()
        self._ended = True
        return b""

    def close(self) -> None:
        self._body = None

    def _start(self) -> None:
        header = self._source.take_exact(2, "deflate header")
        if is_zlib_header(header[0], header[1]):
            if header[1] & _FLAG_DICT:
                raise CorruptError("deflate: preset dictionaries are not supported")
            self._adler = 1  # the Adler-32 of no data
        elif self._strict:
            raise CorruptError("deflate: not a zlib stream")
        else:
            self._source.unread(header)  # raw DEFLATE: the two bytes are data
        self._body = RawInflater(self._source, "deflate")

    def _finish(self) -> None:
        """The DEFLATE data ended: verify the Adler-32 and that nothing follows."""
        if self._adler is not None:
            trailer = self._source.take_exact(_TRAILER, "deflate trailer")
            if int.from_bytes(trailer, "big") != self._adler:
                raise CorruptError("deflate: checksum mismatch")
        if not self._source.at_end():
            raise CorruptError("deflate: unexpected data after the end of the stream")
