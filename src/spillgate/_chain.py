"""The reader returned to the caller: the last layer plus the end-to-end ratio check."""

from __future__ import annotations

import contextlib
import io
from typing import Any

from ._guard import MAX_STEP, LayerGuard
from ._meter import InputMeter
from .errors import ClosedError, RatioLimitError, SpillgateError
from .limits import EffectiveLimits

_END = object()


class ChainReader(io.RawIOBase):
    """A binary stream of the decoded bytes. Use it like any other raw file object.

    Reading can deliver bytes and then fail: treat any
    :class:`~spillgate.SpillgateError` as failure of the whole body (SG-R-LAY-06).
    Errors are sticky: every later read raises the same error (SG-R-LAY-05).
    Closing does not close the caller's source. Not safe for concurrent use.
    """

    def __init__(
        self,
        top: LayerGuard,
        source: InputMeter,
        limits: EffectiveLimits,
        codecs: list[Any],
    ) -> None:
        super().__init__()
        self._top = top
        self._source = source  # the meter of layer 1: what was taken from the caller's source
        self._limits = limits
        self._codecs = codecs  # codec readers that need releasing
        self._produced = 0
        self._done: object | SpillgateError | None = None

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        view = memoryview(buffer).cast("B")
        if self.closed:
            raise ClosedError("I/O operation on a closed spillgate reader")
        if self._done is not None:
            return self._replay()
        if len(view) == 0:
            return 0
        try:
            data = self._top.read(len(view))
        except SpillgateError as error:
            self._done = error
            raise
        if not data:
            self._done = _END
            return 0
        view[: len(data)] = data
        self._produced += len(data)
        # SG-R-RAT-03: the same ratio test, end to end. The error follows these bytes.
        # A layer that already failed has the more specific error, so it wins.
        if not self._top.failed and self._limits.ratio_exceeded(
            self._produced, self._source.consumed
        ):
            self._done = RatioLimitError(
                "end-to-end expansion over the whole chain", limit=self._limits.max_ratio
            )
        return len(data)

    def read(self, size: int | None = -1) -> bytes:
        """Read up to ``size`` bytes (at most one step); ``-1`` or ``None`` reads to the end.

        The buffer is never larger than one step, whatever ``size`` is, so a huge
        ``size`` does not allocate a huge buffer (SG-R-MEM-02).
        """
        if size is None or size < 0:
            return self.readall()
        buffer = bytearray(min(size, MAX_STEP))
        count = self.readinto(buffer)
        return bytes(buffer[:count])

    def readall(self) -> bytes:
        """Read to the end. Memory grows with the bytes produced, never with a limit."""
        out = bytearray()
        while True:
            chunk = self.read(MAX_STEP)
            if not chunk:
                return bytes(out)
            out += chunk

    def _replay(self) -> int:
        if self._done is _END:
            return 0
        assert isinstance(self._done, SpillgateError)
        raise self._done

    def close(self) -> None:
        """Release codec state. Idempotent; the caller's source is left open (SG-R-RDR-06)."""
        if self.closed:
            return
        codecs, self._codecs = self._codecs, []
        try:
            for codec in codecs:
                _close_contained(codec)
        finally:
            super().close()


def _close_contained(codec: Any) -> None:
    """Close a codec reader; a failing ``close`` must not stop the others (SG-R-CDC-08)."""
    close = getattr(codec, "close", None)
    if close is None:
        return
    with contextlib.suppress(Exception):  # contained on purpose
        close()
