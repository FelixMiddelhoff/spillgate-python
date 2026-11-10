"""Strict parsing of ``Content-Encoding`` field values (SPEC section 4).

The evaluation order is normative because it decides the outcome class when
several faults are present: total length, then per-element grammar left to
right, then element count, then support, then layer count.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence

from .errors import (
    LayerLimitError,
    MalformedEncodingError,
    UnsupportedEncodingError,
    quote_untrusted,
)

MAX_HEADER_LENGTH = 1024  # SG-R-HDR-02, in bytes of the joined list
MAX_ELEMENTS = 16  # SG-R-HDR-06, counting identity
IDENTITY = "identity"

# SG-R-HDR-04. fullmatch + ASCII flag: no trailing newline, no Unicode digits.
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}", re.ASCII)


def parse_content_encoding(
    values: str | Sequence[str],
    supported: Callable[[str], bool],
    max_layers: int,
) -> list[str]:
    """Return the layers to decode, in decoding order (layer 1 first).

    Args:
        values: the field values as received. A single string is one field value.
        supported: tells whether a (lower-case, alias-resolved) token has a codec.
        max_layers: the ``max_layers`` limit.

    Raises:
        MalformedEncodingError: the list is too long or an element breaks the grammar.
        LayerLimitError: more than 16 elements, or more than ``max_layers`` layers.
        UnsupportedEncodingError: a well-formed token has no codec.
        TypeError: ``values`` is not a string or a sequence of strings.
    """
    fields = _as_fields(values)
    _check_length(fields)
    elements = _split(fields)
    if len(elements) > MAX_ELEMENTS:
        raise LayerLimitError(
            f"{len(elements)} encodings listed, at most {MAX_ELEMENTS} are accepted",
            limit=MAX_ELEMENTS,
        )
    names = [_resolve(name, supported) for name in elements]
    layers = [name for name in names if name != IDENTITY]
    if len(layers) > max_layers:
        raise LayerLimitError(
            f"{len(layers)} encoding layers, at most {max_layers} are accepted", limit=max_layers
        )
    layers.reverse()  # SG-R-HDR-12: the last listed token is layer 1
    return layers


def _as_fields(values: str | Sequence[str]) -> list[str]:
    if isinstance(values, str):
        return [values]
    fields = list(values)
    for value in fields:
        if not isinstance(value, str):
            raise TypeError(f"Content-Encoding values must be str, got {type(value).__name__}")
    return fields


def _check_length(fields: list[str]) -> None:
    """SG-R-HDR-02: the joined list may be at most 1024 bytes long."""
    total = sum(len(f.encode("utf-8", "surrogatepass")) for f in fields)
    total += max(len(fields) - 1, 0)  # the joining commas
    if total > MAX_HEADER_LENGTH:
        raise MalformedEncodingError(
            f"Content-Encoding is {total} bytes long, at most {MAX_HEADER_LENGTH} are accepted",
            limit=MAX_HEADER_LENGTH,
        )


def _split(fields: list[str]) -> list[str]:
    """SG-R-HDR-01, HDR-03, HDR-04, HDR-05: join, split, trim, validate, lower-case."""
    elements: list[str] = []
    for part in ",".join(fields).split(","):
        part = part.strip(" \t")  # only SP and HTAB, never other Unicode whitespace
        if not part:
            continue  # empty elements are ignored (RFC 9110 section 5.6.1.2)
        if _TOKEN.fullmatch(part) is None:
            raise MalformedEncodingError(f"invalid encoding name {quote_untrusted(part)}")
        elements.append(part.lower())  # safe: only ASCII passed the grammar
    return elements


def _resolve(name: str, supported: Callable[[str], bool]) -> str:
    """SG-R-HDR-07, HDR-08: apply the x-gzip alias and require support."""
    if name == "x-gzip":
        name = "gzip"
    if name != IDENTITY and not supported(name):
        raise UnsupportedEncodingError(f"encoding {quote_untrusted(name)} is not supported")
    return name
