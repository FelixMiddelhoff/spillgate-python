"""The layer guard: everything the specification demands of one layer.

Whatever the codec does, the guard never hands out more than ``max_output`` bytes
in total (SG-I-01), never turns a limit hit into a clean end (SG-I-02), and keeps
raising the same terminal condition once one occurred (SG-I-03).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ._cancel import poll
from ._meter import InputMeter
from .errors import (
    InternalError,
    OutputLimitError,
    RatioLimitError,
    SpillgateError,
    fresh,
)
from .limits import EffectiveLimits

# The most a guard asks a codec for in one call. It bounds the memory of one step
# (SG-R-MEM-02) whatever size of buffer the caller reads with; callers get short
# reads, which every reader contract allows.
MAX_STEP = 256 * 1024

_END = object()  # sticky "clean end" marker, as opposed to an error


class LayerGuard:
    """Wraps the output of one decoding layer. Not safe for concurrent use."""

    def __init__(
        self,
        codec: Any,
        meter: InputMeter,
        layer: int,
        limits: EffectiveLimits,
        cancel: Callable[[], bool] | None = None,
    ) -> None:
        self._codec = codec  # has read(n) -> bytes
        self._cancel = cancel
        self._meter = meter
        self._layer = layer
        self._limits = limits
        self._produced = 0
        self._done: object | SpillgateError | None = None  # None, _END or the error

    @property
    def failed(self) -> bool:
        """True once the layer has a terminal error (a clean end is not a failure)."""
        return isinstance(self._done, SpillgateError)

    def read(self, n: int) -> bytes:
        """Return up to ``n`` bytes; ``b""`` is the clean end.

        Raises:
            SpillgateError: the layer failed. The same error is raised on every
                later call (SG-R-LAY-05).
        """
        if self._done is not None:
            return self._replay()
        if n <= 0:
            return b""  # SG-R-RDR-02: a zero-length read changes nothing
        stop = poll(self._cancel, self._layer)
        if stop is not None:
            self._done = stop
            return self._replay()
        remaining = self._limits.max_output - self._produced
        if remaining <= 0:
            return self._probe()
        data = self._call_codec(min(n, remaining, MAX_STEP))
        if not data:
            self._done = _END
            return b""
        self._produced += len(data)
        # The bytes that broke the ratio were produced first, so they are still
        # delivered; the error follows on the next read (SG-R-LAY-07).
        if self._limits.ratio_exceeded(self._produced, self._meter.consumed):
            self._done = RatioLimitError(
                f"output of {self._produced} bytes from {self._meter.consumed} input bytes",
                layer=self._layer,
                limit=self._limits.max_ratio,
            )
        return data

    def _replay(self) -> bytes:
        if self._done is _END:
            return b""
        assert isinstance(self._done, SpillgateError)
        raise fresh(self._done)

    def _probe(self) -> bytes:
        """The budget is used up: is there one more byte? (SG-R-LAY-03)

        If the codec yields a byte, the limit is exceeded and the byte is thrown
        away. If the stream ends cleanly the output was exactly at the limit and
        all is well. The codec's own validation, such as a trailer checksum, still
        runs inside this call and can still report corruption.
        """
        data = self._call_codec(1)
        if data:
            self._done = OutputLimitError(
                f"the layer would produce more than {self._limits.max_output} bytes",
                layer=self._layer,
                limit=self._limits.max_output,
            )
        else:
            self._done = _END
        return self._replay()

    def _call_codec(self, n: int) -> bytes:
        """One codec read, with its failures contained (SG-R-CDC-08)."""
        try:
            data = self._as_bytes(self._codec.read(n), n)
        except SpillgateError as error:
            failure = error.with_layer(self._layer)
            self._done = fresh(failure)
            try:
                raise failure from failure.__cause__
            finally:
                del failure  # the traceback would otherwise keep this frame, and the guard, alive
        except Exception as error:
            failure = self._classify(error)
            self._done = fresh(failure)
            try:
                raise failure from (failure.__cause__ or error)
            finally:
                del failure
        return data

    def _as_bytes(self, data: object, n: int) -> bytes:
        """Check the codec's return value once, by its size in *bytes* (SG-R-CDC-08).

        ``len()`` of a ``memoryview`` counts items, not bytes, so the size is taken from
        ``nbytes`` of a byte view; the delivered value is a plain ``bytes`` copy.
        """
        if not isinstance(data, bytes | bytearray | memoryview):
            raise InternalError(
                f"codec returned {type(data).__name__}, not bytes", layer=self._layer
            )
        view = memoryview(data)
        if view.nbytes > n:
            raise InternalError("codec returned more bytes than requested", layer=self._layer)
        return view.tobytes()

    def _classify(self, error: Exception) -> SpillgateError:
        """An unexpected exception is a codec bug, unless the source caused it."""
        source_failure = self._meter.source_failure()
        if source_failure is not None:
            return source_failure.with_layer(self._layer)
        return InternalError(f"codec raised {type(error).__name__}", layer=self._layer)
