"""spillgate: decode untrusted compressed data under mandatory limits.

A decompression bomb is a small input that expands to an enormous output. spillgate
stops it at the gate: every decoding layer has a hard output limit, an expansion
ratio limit and a bounded chain length, and anything that exceeds a limit ends in
a typed error, never in silent truncation.

>>> from spillgate import Limits, decode_all
>>> import gzip
>>> decode_all(gzip.compress(b"hello"), "gzip", Limits(max_output=1 << 20))
b'hello'

The normative rules are in ``spec/SPEC.md``; rule IDs such as ``SG-R-LAY-03`` in
comments and docstrings point there. Design principle: when in doubt, refuse.
"""

from __future__ import annotations

from .codec import Codec, CodecReader, Source
from .decoder import Decoder, decode_all, reader
from .errors import (
    CanceledError,
    ClosedError,
    CorruptError,
    InputLimitError,
    InternalError,
    InvalidLimitsError,
    InvalidOptionError,
    Kind,
    LayerLimitError,
    MalformedEncodingError,
    MemoryLimitError,
    OutputLimitError,
    RatioLimitError,
    SourceError,
    SpillgateError,
    UnsupportedEncodingError,
)
from .limits import (
    DEFAULT_MAX_LAYERS,
    DEFAULT_MAX_RATIO,
    DEFAULT_RATIO_GRACE,
    HARD_MAX_LAYERS,
    HARD_MAX_RATIO,
    Limits,
)

__all__ = [
    "DEFAULT_MAX_LAYERS",
    "DEFAULT_MAX_RATIO",
    "DEFAULT_RATIO_GRACE",
    "HARD_MAX_LAYERS",
    "HARD_MAX_RATIO",
    "CanceledError",
    "ClosedError",
    "Codec",
    "CodecReader",
    "CorruptError",
    "Decoder",
    "InputLimitError",
    "InternalError",
    "InvalidLimitsError",
    "InvalidOptionError",
    "Kind",
    "LayerLimitError",
    "Limits",
    "MalformedEncodingError",
    "MemoryLimitError",
    "OutputLimitError",
    "RatioLimitError",
    "Source",
    "SourceError",
    "SpillgateError",
    "UnsupportedEncodingError",
    "decode_all",
    "reader",
]
