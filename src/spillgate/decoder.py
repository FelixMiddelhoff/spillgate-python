"""The public entry points: :class:`Decoder`, :func:`reader` and :func:`decode_all`."""

from __future__ import annotations

import io
import re
from collections.abc import Mapping, Sequence
from types import MappingProxyType
from typing import Any

from ._chain import ChainReader
from ._deflate import DeflateCodec
from ._guard import LayerGuard
from ._gzip import GzipCodec
from ._meter import InputMeter
from .codec import Codec
from .errors import (
    InternalError,
    InvalidOptionError,
    SpillgateError,
    quote_untrusted,
)
from .header import IDENTITY, parse_content_encoding
from .limits import EffectiveLimits, Limits

__all__ = ["Decoder", "decode_all", "reader"]

_RESERVED_NAMES = frozenset({IDENTITY, "gzip", "deflate", "x-gzip"})
_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,31}", re.ASCII)


class Decoder:
    """Turns ``Content-Encoding`` chains into bounded readers.

    A decoder is immutable after construction and safe for concurrent use; the
    readers it returns are not (SG-R-RDR-07). All checks that depend only on the
    limits and options happen here, before any byte is read (SG-R-LIM-08).

    Args:
        limits: the limits to enforce. Copied by value; ``Limits`` is immutable.
        strict_zlib: refuse ``deflate`` data that has no zlib header instead of
            trying raw DEFLATE (SG-R-CDC-03).
        codecs: extension codecs by name, for example brotli and zstd (SG-R-CDC-09).
            Names must be lower case tokens and must not replace ``identity``,
            ``gzip``, ``deflate`` or ``x-gzip``.

    Raises:
        InvalidOptionError: an extension codec name is invalid or reserved.
        TypeError: ``limits`` is not a :class:`Limits`.
    """

    def __init__(
        self,
        limits: Limits,
        *,
        strict_zlib: bool = False,
        codecs: Mapping[str, Codec] | None = None,
    ) -> None:
        if not isinstance(limits, Limits):
            raise TypeError("limits must be a spillgate.Limits")
        self._limits = EffectiveLimits.of(limits)
        table: dict[str, Codec] = {
            "gzip": GzipCodec(),
            "deflate": DeflateCodec(strict_zlib=strict_zlib),
        }
        for name, codec in (codecs or {}).items():
            _check_codec_name(name)
            table[name] = codec
        self._codecs: Mapping[str, Codec] = MappingProxyType(table)

    def reader(self, source: Any, encodings: str | Sequence[str] = ()) -> ChainReader:
        """Return a reader of the decoded bytes of ``source``.

        Args:
            source: ``bytes`` or an object with ``read(n)`` (a file, a socket file,
                ``io.BytesIO``). It is not closed by spillgate.
            encodings: the ``Content-Encoding`` field values as received; one string,
                or a sequence of strings for repeated header lines.

        Every check that depends only on the header happens here, before the
        source is touched (SG-R-HDR-09, SG-R-API-03).

        Raises:
            MalformedEncodingError, LayerLimitError, UnsupportedEncodingError:
                the header is refused.
        """
        if isinstance(source, bytes | bytearray | memoryview):
            source = io.BytesIO(bytes(source))
        if not callable(getattr(source, "read", None)):
            raise TypeError("source must be bytes or have a read(n) method")
        layers = parse_content_encoding(
            encodings, lambda name: name in self._codecs, self._limits.max_layers
        )
        return self._build_chain(source, layers)

    def read_all(self, source: Any, encodings: str | Sequence[str] = ()) -> bytes:
        """Decode ``source`` completely: the whole body, or an error and no data.

        Memory grows with the bytes actually produced, never from declared sizes or
        from ``max_output`` (SG-R-API-02, SG-R-MEM-02).
        """
        with self.reader(source, encodings) as chain:
            return chain.readall()

    def _build_chain(self, source: Any, layers: list[str]) -> ChainReader:
        current: Any = source
        first_meter: InputMeter | None = None
        guard: LayerGuard | None = None
        codec_readers: list[Any] = []
        try:
            for index in range(1, max(len(layers), 1) + 1):
                # The input cap applies to the chain's source only.
                cap = self._limits.max_input if index == 1 else 0
                meter = InputMeter(current, cap, index)
                first_meter = first_meter or meter
                codec_reader: Any = _Passthrough(meter)  # identity: bytes pass through the guard
                if layers:
                    codec_reader = self._new_codec_reader(layers[index - 1], meter, index)
                    codec_readers.append(codec_reader)
                guard = LayerGuard(codec_reader, meter, index, self._limits)
                current = guard
        except BaseException:
            ChainReader(guard, first_meter, self._limits, codec_readers).close()  # type: ignore[arg-type]
            raise
        assert guard is not None and first_meter is not None
        return ChainReader(guard, first_meter, self._limits, codec_readers)

    def _new_codec_reader(self, name: str, meter: InputMeter, layer: int) -> Any:
        try:
            return self._codecs[name].new_reader(meter)
        except SpillgateError as error:
            raise error.with_layer(layer) from None
        except Exception as error:
            raise InternalError(
                f"creating the {quote_untrusted(name)} decoder failed ({type(error).__name__})",
                layer=layer,
            ) from error


class _Passthrough:
    """The codec of an identity-only chain: the input is the output."""

    def __init__(self, meter: InputMeter) -> None:
        self._meter = meter

    def read(self, n: int) -> bytes:
        return self._meter.take(n)


def _check_codec_name(name: object) -> None:
    if not isinstance(name, str) or _NAME.fullmatch(name) is None:
        raise InvalidOptionError(
            f"codec name {quote_untrusted(str(name))} must be a lower-case token (SG-R-HDR-04)"
        )
    if name in _RESERVED_NAMES:
        raise InvalidOptionError(f"codec name {name!r} is reserved for a built-in encoding")


def reader(
    source: Any,
    encodings: str | Sequence[str],
    limits: Limits,
    *,
    strict_zlib: bool = False,
    codecs: Mapping[str, Codec] | None = None,
) -> ChainReader:
    """Shorthand for ``Decoder(limits, ...).reader(source, encodings)``."""
    return Decoder(limits, strict_zlib=strict_zlib, codecs=codecs).reader(source, encodings)


def decode_all(
    source: Any,
    encodings: str | Sequence[str],
    limits: Limits,
    *,
    strict_zlib: bool = False,
    codecs: Mapping[str, Codec] | None = None,
) -> bytes:
    """Decode ``source`` completely under ``limits``: the whole body, or an error.

    There is no way to call this without ``limits`` (SG-R-API-01).
    """
    return Decoder(limits, strict_zlib=strict_zlib, codecs=codecs).read_all(source, encodings)
