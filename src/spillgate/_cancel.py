"""Polling the caller's ``cancel`` callable, with its failures contained."""

from __future__ import annotations

from collections.abc import Callable

from .errors import CanceledError, InternalError, SpillgateError


def poll(cancel: Callable[[], bool] | None, layer: int) -> SpillgateError | None:
    """Return the error to make sticky if the caller wants to stop, else ``None``.

    A callable that raises is a bug in the caller's code, not a reason to let a foreign
    exception escape half-way through a read: it becomes a sticky ``internal`` error
    (SG-I-05). ``KeyboardInterrupt`` and ``SystemExit`` are not ``Exception`` and pass.
    """
    if cancel is None:
        return None
    try:
        wanted = bool(cancel())
    except Exception as error:
        failure = InternalError(f"the cancel callable raised {type(error).__name__}", layer=layer)
        failure.__cause__ = error
        return failure
    return CanceledError("canceled by the caller", layer=layer) if wanted else None
