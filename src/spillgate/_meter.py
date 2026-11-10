"""The input meter: counts what a codec takes, and guards the source.

A codec never talks to the caller's source directly. It takes its compressed bytes
from an :class:`InputMeter`, which

* counts the bytes the codec actually *takes* (not the bytes it fetched from the
  source), so a read-ahead buffer never gives free ratio credit (SG-R-RAT-02);
* lets a codec hand back bytes it fetched but did not need (:meth:`unread`), which
  also lowers the count again;
* enforces the optional ``max_input`` cap (SG-R-INP-01, INP-02);
* defends against misbehaving sources: a source that makes no progress or returns
  more than asked is ``internal`` (SG-R-RDR-03, RDR-04), one that raises is
  ``source_error`` (SG-R-RDR-05).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ._cancel import poll
from .errors import (
    CorruptError,
    InputLimitError,
    InternalError,
    SourceError,
    SpillgateError,
    fresh,
)

BUFFER_SIZE = 4096  # well below the 64 KiB look-ahead tolerance of SG-R-RAT-02
MAX_EMPTY_READS = 100  # SG-R-RDR-03


class InputMeter:
    """The only way a codec reads its input. Not safe for concurrent use."""

    def __init__(
        self,
        source: Any,
        max_input: int,
        layer: int,
        cancel: Callable[[], bool] | None = None,
    ) -> None:
        """``source`` has ``read(n)``; ``max_input`` 0 means no cap.

        ``cancel`` is polled before every refill (4 KiB), well within SG-R-API-04.
        """
        self._cancel = cancel
        self._source = source
        self._max_input = max_input
        self._layer = layer

        self._pending = b""  # fetched (or handed back) and not yet taken
        self._pos = 0
        self._fetched = 0  # bytes obtained from the source, probe included
        self._consumed = 0  # bytes taken by the codec
        self._source_eof = False
        self._failure: SpillgateError | None = None  # sticky: input limit, source, contract
        self.source_error: BaseException | None = None  # the source's own exception, if any

    @property
    def consumed(self) -> int:
        """Bytes the codec has taken so far (the ``C(k)`` of the specification)."""
        return self._consumed

    def source_failure(self) -> SourceError | None:
        """The ``source_error`` this meter raised, if the source failed."""
        failure = self._failure
        return failure if isinstance(failure, SourceError) else None

    def take(self, n: int) -> bytes:
        """Return up to ``n`` bytes; ``b""`` means the source has ended cleanly.

        Raises:
            InputLimitError: the codec asks for byte number ``max_input + 1``.
            SourceError: the source raised.
            InternalError: the source broke its contract.
        """
        if self._failure is not None:
            raise fresh(self._failure)
        if n <= 0:
            return b""
        if self._pos == len(self._pending) and not self._fill():
            return b""
        if self._max_input and self._consumed >= self._max_input:
            self._failure = InputLimitError(
                f"the stream needs more than {self._max_input} input bytes",
                layer=self._layer,
                limit=self._max_input,
            )
            raise fresh(self._failure)
        count = min(n, len(self._pending) - self._pos)
        if self._max_input:
            count = min(count, self._max_input - self._consumed)
        chunk = self._pending[self._pos : self._pos + count]
        self._pos += count
        self._consumed += count
        return chunk

    def take_exact(self, n: int, what: str) -> bytes:
        """Return exactly ``n`` bytes or raise :class:`CorruptError` if the input ends.

        ``what`` names the thing being read, for the error message.
        """
        parts: list[bytes] = []
        missing = n
        while missing > 0:
            chunk = self.take(missing)
            if not chunk:
                raise CorruptError(f"{what}: the stream ends too early", layer=self._layer)
            parts.append(chunk)
            missing -= len(chunk)
        return b"".join(parts)

    def at_end(self) -> bool:
        """True if no byte is left. Takes nothing: a byte found is handed back."""
        chunk = self.take(1)
        if not chunk:
            return True
        self.unread(chunk)
        return False

    def unread(self, data: bytes) -> None:
        """Hand back bytes just taken, in order, so the next take returns them first."""
        if not data:
            return
        if len(data) > self._consumed:
            raise InternalError("unread of more bytes than were taken", layer=self._layer)
        self._pending = data + self._pending[self._pos :]
        self._pos = 0
        self._consumed -= len(data)

    def _fill(self) -> bool:
        """Refill the empty buffer. False means a clean end of the source."""
        if self._source_eof:
            return False
        stop = poll(self._cancel, self._layer)
        if stop is not None:
            self._failure = stop
            raise fresh(stop)
        want = self._fetch_size()
        if want < 1:
            # Everything allowed, probe included, was fetched already.
            self._failure = InputLimitError(
                f"the stream needs more than {self._max_input} input bytes",
                layer=self._layer,
                limit=self._max_input,
            )
            raise fresh(self._failure)
        for _ in range(MAX_EMPTY_READS):
            chunk = self._read_source(want)
            if chunk is None:
                continue  # no progress yet, try again (bounded)
            if not chunk:
                self._source_eof = True
                return False
            self._pending, self._pos = chunk, 0
            self._fetched += len(chunk)
            return True
        self._failure = InternalError("the source made no progress", layer=self._layer)
        raise fresh(self._failure)

    def _fetch_size(self) -> int:
        """With a cap, never ask for more than ``max_input + 1`` bytes in total (SG-R-INP-02)."""
        if not self._max_input:
            return BUFFER_SIZE
        room = self._max_input - self._fetched  # still allowed before the probe byte
        return BUFFER_SIZE if room >= BUFFER_SIZE else room + 1

    def _read_source(self, want: int) -> bytes | None:
        """One read from the source; None means it returned nothing at all."""
        try:
            chunk = self._source.read(want)
        except SpillgateError as error:
            # The source is the previous layer of a chain: its error passes through.
            self._failure = fresh(error)
            raise
        except Exception as error:
            # Keep the source's own frames for debugging, but drop ours: a traceback that
            # reaches back into this meter would make a reference cycle (meter -> failure ->
            # cause -> traceback -> frame -> meter).
            if error.__traceback__ is not None:
                error.__traceback__ = error.__traceback__.tb_next
            self.source_error = error
            self._failure = SourceError(
                f"the source raised {type(error).__name__}", layer=self._layer
            )
            self._failure.__cause__ = error
            raise fresh(self._failure) from error
        if chunk is None:
            return None
        if not isinstance(chunk, bytes | bytearray | memoryview):
            self._failure = InternalError(
                f"the source returned {type(chunk).__name__}, not bytes", layer=self._layer
            )
            raise fresh(self._failure)
        data = memoryview(chunk)  # nbytes, not len(): a multi-byte-item view counts items
        if data.nbytes > want:
            self._failure = InternalError(
                "the source returned more bytes than requested", layer=self._layer
            )
            raise fresh(self._failure)
        return data.tobytes()
