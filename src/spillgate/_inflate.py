"""A bounded raw-DEFLATE decoder on top of ``zlib.decompressobj``.

The classic Python trap is ``decompressobj().decompress(data)`` without
``max_length``: it expands the whole input at once. Here every call passes a
``max_length`` greater than zero (``0`` would mean *unlimited*), and input the
decoder did not use is handed back to the :class:`~spillgate._meter.InputMeter`, so
the meter counts only what the decoder really consumed.
"""

from __future__ import annotations

import zlib

from ._meter import InputMeter
from .errors import CorruptError

_FEED = 4096  # compressed bytes offered per step; the rest is handed back


class RawInflater:
    """Decodes one raw DEFLATE stream (RFC 1951) from a meter.

    ``read(n)`` returns 1..n bytes, or ``b""`` once the final block was decoded.
    After that the bytes behind the stream are back in the meter, exactly where a
    trailer (gzip, zlib) or the next member starts.
    """

    def __init__(self, source: InputMeter, what: str) -> None:
        self._source = source
        self._what = what
        self._decoder = zlib.decompressobj(-zlib.MAX_WBITS)
        self._may_have_output = False  # the last call filled its buffer completely

    @property
    def finished(self) -> bool:
        return self._decoder.eof

    def read(self, n: int) -> bytes:
        """Return decoded bytes; ``b""`` means the stream has ended (its trailer is next).

        Raises:
            CorruptError: invalid DEFLATE data, or the input ends before the final block.
        """
        if n < 1:
            raise ValueError("n must be at least 1")  # max_length 0 would mean unlimited
        decoder = self._decoder
        while not decoder.eof:
            # A full buffer last time means output may still be pending inside zlib
            # even though all input was used, so ask again before taking more input.
            data = b"" if self._may_have_output else self._source.take(_FEED)
            if not data and not self._may_have_output:
                raise CorruptError(f"{self._what}: the stream ends too early")
            out = self._decompress(data, n)
            self._may_have_output = len(out) == n
            if out:
                return out
        return b""

    def _decompress(self, data: bytes, n: int) -> bytes:
        decoder = self._decoder
        try:
            out = decoder.decompress(data, n)
        except zlib.error as error:
            raise CorruptError(f"{self._what}: invalid DEFLATE data ({error})") from None
        # Bytes zlib has not used go back, so "consumed" stays exact: after the
        # final block that is the trailer, before it the input held back by max_length.
        leftover = decoder.unused_data if decoder.eof else decoder.unconsumed_tail
        if leftover:
            # zlib has not seen the unconsumed tail yet; it is taken from the meter again.
            self._source.unread(bytes(leftover))
        return out
