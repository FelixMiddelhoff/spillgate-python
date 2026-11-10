"""The codec interface, for extension codecs such as brotli and zstd (SG-R-CDC-09).

A codec is registered on one decoder instance (``Decoder(codecs={"snappy": ...})``);
there is no global registry. Every codec, built in or not, runs behind the same
limiter, ratio meter and input meter (SG-R-CDC-01), so a sloppy codec is still
bounded.

Contract for the object returned by :meth:`Codec.new_reader`:

* ``read(n)`` returns between 1 and ``n`` bytes of decoded data, or ``b""`` at the
  clean end of the stream. It must not return more than ``n`` bytes; it must not
  return ``None``.
* It takes its compressed input only from the :class:`Source` it was given.
* To report a broken stream it raises :class:`~spillgate.CorruptError`, or another
  :class:`~spillgate.SpillgateError` for a limit of its own (a window cap raises
  :class:`~spillgate.MemoryLimitError`). Any other exception is treated as a bug in
  the codec and becomes :class:`~spillgate.InternalError` (SG-R-CDC-08).
* ``close()`` is optional; it releases the decoder state.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ._meter import InputMeter as Source

__all__ = ["Codec", "CodecReader", "Source"]


@runtime_checkable
class CodecReader(Protocol):
    """A decoder for one stream."""

    def read(self, n: int, /) -> bytes:
        """Return 1..n decoded bytes, or ``b""`` at the clean end of the stream."""
        ...


class Codec(Protocol):
    """A factory for stream decoders; one instance may serve many streams."""

    def new_reader(self, source: Source, /) -> CodecReader:
        """Return a decoder that takes its compressed input from ``source``."""
        ...
