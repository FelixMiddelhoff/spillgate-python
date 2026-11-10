"""Builds the generated conformance inputs (spec/generators.md) without a compressor.

Every construction here is the one written down in ``spec/generators.md``; the SHA-256
of each generated stream in the manifest proves that this implementation builds the
same bytes as the reference. Only gzip, zlib and raw DEFLATE are implemented: brotli
and zstd generators belong to the optional codec packages.
"""

from __future__ import annotations

import hashlib
import struct
import zlib
from typing import Any

MASK64 = (1 << 64) - 1
MAX_MATCH = 258
STORED_BLOCK_LIMIT = 65535


def data(seed: int, size: int) -> bytes:
    """Data(seed, size): xorshift64 bytes that do not compress."""
    state = (seed * 0x9E3779B97F4A7C15 + 1) & MASK64
    out = bytearray(size)
    for i in range(size):
        state ^= (state << 13) & MASK64
        state ^= state >> 7
        state ^= (state << 17) & MASK64
        out[i] = (state >> 24) & 0xFF
    return bytes(out)


class BitWriter:
    """Writes DEFLATE fields: least significant bit first; Huffman codes most significant first."""

    def __init__(self) -> None:
        self.out = bytearray()
        self._acc = 0
        self._count = 0

    def bits(self, value: int, n: int) -> None:
        self._acc |= value << self._count
        self._count += n
        while self._count >= 8:
            self.out.append(self._acc & 0xFF)
            self._acc >>= 8
            self._count -= 8

    def code(self, code: int, n: int) -> None:
        reversed_code = 0
        for i in range(n):
            reversed_code = reversed_code << 1 | (code >> i) & 1
        self.bits(reversed_code, n)

    def zero_bits(self, n: int) -> None:
        """Write ``n`` zero bits; whole bytes in bulk, so billions of bits stay cheap."""
        head = min(n, (8 - self._count) % 8)
        self.bits(0, head)
        n -= head
        self.out += bytes(n // 8)
        self.bits(0, n % 8)

    def align(self) -> None:
        """Pad with zero bits to the next byte boundary."""
        if self._count:
            self.out.append(self._acc & 0xFF)
            self._acc = self._count = 0

    def finish(self) -> bytes:
        if self._count:
            self.out.append(self._acc & 0xFF)
            self._acc = self._count = 0
        return bytes(self.out)


def stored_deflate(payload: bytes) -> bytes:
    """StoredDeflate: stored blocks of at most 65535 bytes; empty data is one empty final block."""
    out = bytearray()
    view = memoryview(payload)
    first = True
    while first or len(view):
        first = False
        n = min(len(view), STORED_BLOCK_LIMIT)
        final = 1 if n == len(view) else 0
        out += bytes([final]) + struct.pack("<HH", n, n ^ 0xFFFF)
        out += view[:n]
        view = view[n:]
    return bytes(out)


def zeros_deflate(matches: int) -> bytes:
    """ZerosDeflate: one dynamic Huffman block decoding to ``1 + 258 * matches`` zero bytes."""
    w = BitWriter()
    w.bits(1, 1)  # BFINAL
    w.bits(2, 2)  # BTYPE 10: dynamic Huffman codes
    w.bits(29, 5)  # HLIT: 286 literal/length symbols
    w.bits(1, 5)  # HDIST: 2 distance symbols
    w.bits(14, 4)  # HCLEN: 18 code-length code lengths
    for length in (0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 2):
        w.bits(length, 3)

    def length_is_1() -> None:
        w.code(0b10, 2)

    def length_is_2() -> None:
        w.code(0b11, 2)

    def zero_run(count: int) -> None:
        w.code(0b0, 1)
        w.bits(count - 11, 7)

    length_is_2()  # literal 0
    zero_run(138)  # symbols 1..138 unused
    zero_run(117)  # symbols 139..255 unused
    length_is_2()  # symbol 256, end of block
    zero_run(28)  # symbols 257..284 unused
    length_is_1()  # symbol 285 (length 258)
    length_is_1()  # distance symbol 0
    length_is_1()  # distance symbol 1

    w.code(0b10, 2)  # literal 0
    w.zero_bits(2 * matches)  # per match: length symbol 285 = '0', distance symbol 0 = '0'
    w.code(0b11, 2)  # end of block
    return w.finish()


def zeros_decoded_size(matches: int) -> int:
    return 1 + MAX_MATCH * matches


def _crc_of_zeros(n: int) -> int:
    crc, chunk = 0, bytes(1 << 20)
    while n > 0:
        take = min(n, len(chunk))
        crc = zlib.crc32(chunk[:take] if take < len(chunk) else chunk, crc)
        n -= take
    return crc


def _adler_of_zeros(n: int) -> int:
    value, chunk = 1, bytes(1 << 20)
    while n > 0:
        take = min(n, len(chunk))
        value = zlib.adler32(chunk[:take] if take < len(chunk) else chunk, value)
        n -= take
    return value


def gzip_member(deflate: bytes, crc: int, size: int) -> bytes:
    header = bytes([0x1F, 0x8B, 8, 0, 0, 0, 0, 0, 0, 255])
    return header + deflate + struct.pack("<II", crc, size & 0xFFFFFFFF)


def zlib_wrap(deflate: bytes, adler: int) -> bytes:
    return b"\x78\x01" + deflate + struct.pack(">I", adler)


def gzip_stored(payload: bytes) -> bytes:
    return gzip_member(stored_deflate(payload), zlib.crc32(payload), len(payload))


def zlib_stored(payload: bytes) -> bytes:
    return zlib_wrap(stored_deflate(payload), zlib.adler32(payload))


def zeros_stream(codec: str, matches: int) -> bytes:
    size = zeros_decoded_size(matches)
    deflate = zeros_deflate(matches)
    if codec == "gzip":
        return gzip_member(deflate, _crc_of_zeros(size), size)
    if codec == "zlib":
        return zlib_wrap(deflate, _adler_of_zeros(size))
    if codec == "raw":
        return deflate
    raise NotImplementedError(f"zeros generator for codec {codec!r}")


def wrap_once(codec: str, payload: bytes, window: int = 0) -> bytes:
    """Wrap ``payload`` in one stored stream. ``window`` is the brotli window bits."""
    if codec == "gzip":
        return gzip_stored(payload)
    if codec == "zlib":
        return zlib_stored(payload)
    if codec == "raw":
        return stored_deflate(payload)
    if codec == "br":
        return brotli_stored(payload, window)
    raise NotImplementedError(f"wrap generator for codec {codec!r}")


# -- brotli (RFC 7932), spec/generators.md ---------------------------------------------

BROTLI_METABLOCK_MAX = 1 << 24
BROTLI_MIN_COMMAND_BYTES = 4 + 2118


def _brotli_window_bits(w: BitWriter, wbits: int) -> None:
    if wbits == 16:
        w.bits(0, 1)
    elif wbits == 17:
        w.bits(1, 1)
        w.bits(0, 3)
        w.bits(0, 3)
    elif 18 <= wbits <= 24:
        w.bits(1, 1)
        w.bits(wbits - 17, 3)
    elif 10 <= wbits <= 15:
        w.bits(1, 1)
        w.bits(0, 3)
        w.bits(wbits - 8, 3)
    else:
        raise ValueError("brotli window bits must be in 10..24")


def _brotli_mlen(w: BitWriter, mlen: int) -> None:
    value = mlen - 1
    w.bits(0, 1)  # ISLAST
    if value < 1 << 16:
        w.bits(0, 2)
        w.bits(value, 16)
    elif value < 1 << 20:
        w.bits(1, 2)
        w.bits(value, 20)
    else:
        w.bits(2, 2)
        w.bits(value, 24)


def _brotli_end(w: BitWriter) -> None:
    w.bits(1, 1)  # ISLAST
    w.bits(1, 1)  # ISLASTEMPTY


def _brotli_zeros_metablock(w: BitWriter, mlen: int) -> None:
    _brotli_mlen(w, mlen)
    w.bits(0, 1)  # ISUNCOMPRESSED
    w.bits(0, 3)  # NBLTYPESL, NBLTYPESI, NBLTYPESD = 1
    w.bits(0, 2)  # NPOSTFIX
    w.bits(0, 4)  # NDIRECT
    w.bits(0, 2)  # context mode of the one literal block type
    w.bits(0, 2)  # NTREESL = 1, NTREESD = 1
    for symbol, symbol_bits in ((0, 8), (423, 10), (0, 6)):  # three single-symbol prefix codes
        w.bits(1, 2)  # HSKIP = 1: simple prefix code
        w.bits(0, 2)  # NSYM - 1
        w.bits(symbol, symbol_bits)
    w.bits(mlen - 4 - 2118, 24)  # extra bits of copy length code 23


def brotli_zeros(size: int, wbits: int) -> bytes:
    """BrotliZeros: ``size`` zero bytes in a few bytes per 16 MiB meta-block."""
    w = BitWriter()
    _brotli_window_bits(w, wbits)
    while size > 0:
        chunk = min(size, BROTLI_METABLOCK_MAX)
        remainder = size - chunk
        if 0 < remainder < BROTLI_MIN_COMMAND_BYTES:
            chunk -= BROTLI_MIN_COMMAND_BYTES  # leave a final meta-block that is big enough
        _brotli_zeros_metablock(w, chunk)
        size -= chunk
    _brotli_end(w)
    return w.finish()


def brotli_stored(payload: bytes, wbits: int) -> bytes:
    """BrotliStored: uncompressed meta-blocks around ``payload``."""
    w = BitWriter()
    _brotli_window_bits(w, wbits)
    view = memoryview(payload)
    while len(view):
        chunk = view[:BROTLI_METABLOCK_MAX]
        _brotli_mlen(w, len(chunk))
        w.bits(1, 1)  # ISUNCOMPRESSED
        w.align()
        w.out += chunk
        view = view[len(chunk) :]
    _brotli_end(w)
    return w.finish()


def brotli_large_window_prefix() -> bytes:
    """The reserved WBITS pattern 1000001 that announces a large-window stream."""
    return bytes([0x11, 0x00, 0x00, 0x00])


def generate(spec: dict[str, Any]) -> bytes:
    """Build the compressed stream a generator spec describes.

    Raises:
        NotImplementedError: the spec needs the zstd generator.
    """
    kind, params = spec["kind"], spec["params"]
    if kind == "zeros":
        if params["codec"] == "br":
            return brotli_zeros(params["size"], params["window"])
        return zeros_stream(params["codec"], params.get("matches", 0))
    if kind == "data":
        payload = data(params["seed"], params["size"])
        return wrap_once(params["codec"], payload, params.get("window", 0))
    if kind == "wrap":
        stream = generate(params["inner"])
        for _ in range(params["times"]):
            stream = wrap_once(params["codec"], stream, params.get("window", 0))
        return stream
    raise ValueError(f"unknown generator kind {kind!r}")


def sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def zeros_sha256_hex(n: int) -> str:
    digest, chunk = hashlib.sha256(), bytes(1 << 20)
    while n > 0:
        take = min(n, len(chunk))
        digest.update(chunk if take == len(chunk) else chunk[:take])
        n -= take
    return digest.hexdigest()
