"""Errors raised by spillgate.

Every refusal is a :class:`SpillgateError` whose :attr:`~SpillgateError.kind` is one
of the outcome classes of the specification (section 2). There is one exception
class per kind, so callers can use either ``except OutputLimitError`` or
``error.kind is Kind.OUTPUT_LIMIT``.

Error messages never contain more than 32 bytes of attacker-controlled data, and
that data is quoted and escaped (SG-R-HDR-13).
"""

from __future__ import annotations

import enum

__all__ = [
    "CanceledError",
    "ClosedError",
    "CorruptError",
    "InputLimitError",
    "InternalError",
    "InvalidLimitsError",
    "InvalidOptionError",
    "Kind",
    "LayerLimitError",
    "MalformedEncodingError",
    "MemoryLimitError",
    "OutputLimitError",
    "RatioLimitError",
    "SourceError",
    "SpillgateError",
    "UnsupportedEncodingError",
]


class Kind(enum.Enum):
    """The outcome classes of SPEC section 2 (the value is the name used there)."""

    INVALID_LIMITS = "invalid_limits"
    OUTPUT_LIMIT = "output_limit"
    RATIO_LIMIT = "ratio_limit"
    LAYER_LIMIT = "layer_limit"
    INPUT_LIMIT = "input_limit"
    MEMORY_LIMIT = "memory_limit"
    UNSUPPORTED_ENCODING = "unsupported_encoding"
    MALFORMED_ENCODING = "malformed_encoding"
    CORRUPT = "corrupt"
    INTERNAL = "internal"
    CANCELED = "canceled"
    SOURCE_ERROR = "source_error"


class SpillgateError(Exception):
    """Base class of every error that spillgate raises about the data.

    Attributes:
        kind: the outcome class.
        layer: 1-based index of the layer that failed (layer 1 reads from the
            source), or 0 if the error is not tied to a layer.
        limit: the limit that was exceeded, or 0 if the kind has none.
    """

    kind: Kind

    def __init__(self, message: str = "", *, layer: int = 0, limit: int = 0) -> None:
        super().__init__(message)
        self.layer = layer
        self.limit = limit

    def __str__(self) -> str:
        text = f"spillgate: {self.kind.value}"
        if self.layer > 0:
            text += f" in layer {self.layer}"
        if self.limit > 0:
            text += f" (limit {self.limit})"
        detail = super().__str__()
        return f"{text}: {detail}" if detail else text

    def with_layer(self, layer: int) -> SpillgateError:
        """Return this error with ``layer`` set, unless it already names a layer."""
        if self.layer > 0 or layer <= 0:
            return self
        self.layer = layer
        return self


class InvalidLimitsError(SpillgateError, ValueError):
    """A limit parameter is missing, out of range or contradicts another one."""

    kind = Kind.INVALID_LIMITS


class OutputLimitError(SpillgateError):
    """A layer would have produced more than ``max_output`` bytes."""

    kind = Kind.OUTPUT_LIMIT


class RatioLimitError(SpillgateError):
    """A layer (or the whole chain) expanded its input by more than ``max_ratio``."""

    kind = Kind.RATIO_LIMIT


class LayerLimitError(SpillgateError):
    """The Content-Encoding chain has too many layers or elements."""

    kind = Kind.LAYER_LIMIT


class InputLimitError(SpillgateError):
    """The codec asked for more than ``max_input`` bytes of the source."""

    kind = Kind.INPUT_LIMIT


class MemoryLimitError(SpillgateError):
    """The stream needs a decoder window larger than the configured cap."""

    kind = Kind.MEMORY_LIMIT


class UnsupportedEncodingError(SpillgateError):
    """A Content-Encoding token is well formed but not supported (fail closed)."""

    kind = Kind.UNSUPPORTED_ENCODING


class MalformedEncodingError(SpillgateError):
    """The Content-Encoding header is not valid under the strict grammar."""

    kind = Kind.MALFORMED_ENCODING


class CorruptError(SpillgateError):
    """The compressed stream is invalid, truncated or has trailing data."""

    kind = Kind.CORRUPT


class InternalError(SpillgateError):
    """A codec or a source broke its contract, or a codec raised unexpectedly."""

    kind = Kind.INTERNAL


class CanceledError(SpillgateError):
    """Decoding was canceled."""

    kind = Kind.CANCELED


class SourceError(SpillgateError):
    """The caller's source failed. The original exception is ``__cause__``."""

    kind = Kind.SOURCE_ERROR


class InvalidOptionError(ValueError):
    """A decoder option is invalid, such as a bad extension-codec name."""


class ClosedError(ValueError):
    """The reader was used after :meth:`close` (SG-R-RDR-06)."""


_BY_KIND: dict[Kind, type[SpillgateError]] = {
    cls.kind: cls
    for cls in (
        InvalidLimitsError,
        OutputLimitError,
        RatioLimitError,
        LayerLimitError,
        InputLimitError,
        MemoryLimitError,
        UnsupportedEncodingError,
        MalformedEncodingError,
        CorruptError,
        InternalError,
        CanceledError,
        SourceError,
    )
}

MAX_QUOTED_BYTES = 32


def error_for(kind: Kind, message: str = "", *, layer: int = 0, limit: int = 0) -> SpillgateError:
    """Build the exception class that belongs to ``kind``."""
    return _BY_KIND[kind](message, layer=layer, limit=limit)


def fresh(error: SpillgateError) -> SpillgateError:
    """Return a new exception equal to ``error``, without a traceback.

    Terminal errors are sticky, so readers keep them and raise them again on every later read.
    Raising the stored object itself would attach a traceback whose frames refer back to the
    reader (a reference cycle that keeps decoder memory alive until the cyclic garbage
    collector runs) and would let the traceback grow with every read. Readers therefore store
    one copy and raise a fresh one each time.

    The copy keeps the class, the arguments, the attributes and the cause. Subclasses with their
    own ``__init__`` signature are copied without calling it, so this never raises.
    """
    cls = type(error)
    copy = cls.__new__(cls)
    copy.__dict__.update(error.__dict__)
    copy.args = error.args
    copy.__cause__ = error.__cause__
    copy.__traceback__ = None
    return copy


def quote_untrusted(text: str) -> str:
    """Render attacker-controlled text for an error message (SG-R-HDR-13).

    At most :data:`MAX_QUOTED_BYTES` bytes of the UTF-8 form are shown, and the
    result is quoted with every non-ASCII or control character escaped, so it
    cannot forge log lines.
    """
    raw = text.encode("utf-8", "surrogatepass")
    shown = raw[:MAX_QUOTED_BYTES].decode("utf-8", "replace")
    quoted = ascii(shown)
    return quoted + "..." if len(raw) > MAX_QUOTED_BYTES else quoted
