"""Regression tests for the second security review (br, zstd, sticky errors)."""

import io

import pytest

brotli = pytest.importorskip("brotli")
zstandard = pytest.importorskip("zstandard")

from spillgate import Decoder, Limits, br, zstd  # noqa: E402


def _bits(*fields):
    bits = []
    for value, width in fields:
        bits += [(value >> i) & 1 for i in range(width)]
    bits += [0] * (-len(bits) % 8)
    return bytes(sum(bits[i + j] << j for j in range(8)) for i in range(0, len(bits), 8))


def test_valid_brotli_with_a_large_metadata_block_decodes() -> None:
    """Covers: SG-R-CDC-04 SG-R-CDC-05 SG-R-CDC-06"""
    n = 3 << 20  # valid: brotli.decompress() accepts it
    head = _bits((0, 1), (0, 1), (3, 2), (0, 1), (3, 2), (n - 1, 24))
    stream = head + bytes(n) + _bits((1, 1), (1, 1))
    assert brotli.decompress(stream) == b""
    dec = Decoder(Limits(max_output=1 << 20, disable_ratio_limit=True), codecs={"br": br.codec()})
    assert dec.read_all(io.BytesIO(stream), "br") == b""


def test_zstd_empty_last_block_cannot_hide_a_content_size_mismatch() -> None:
    """Covers: SG-R-CDC-04 SG-R-CDC-05 SG-R-CDC-06"""
    # single segment, declared content size 128, but the only block is an empty last raw block
    frame = bytes.fromhex("28b52ffd2080") + bytes.fromhex("010000")
    with pytest.raises(zstandard.ZstdError):
        zstandard.ZstdDecompressor().stream_reader(io.BytesIO(frame)).read()
    dec = Decoder(Limits(max_output=1 << 20), codecs={"zstd": zstd.codec()})
    with pytest.raises(Exception) as info:
        dec.read_all(io.BytesIO(frame), "zstd")
    assert "corrupt" in str(info.value)


def test_brotli_trailing_byte_after_a_chunk_aligned_stream_is_refused() -> None:
    """Gap proof: passes today, but survives the mutant that drops the at_end() check."""
    import sys

    sys.path.insert(0, "tests")
    import corpus

    for size in range(4000, 4100):
        stream = corpus.brotli_stored(bytes(size), 16)
        if len(stream) % 4096 == 0:
            break
    else:
        pytest.skip("no aligned size found")
    dec = Decoder(Limits(max_output=1 << 20, disable_ratio_limit=True), codecs={"br": br.codec()})
    assert dec.read_all(io.BytesIO(stream), "br") == bytes(size)
    with pytest.raises(Exception) as info:
        dec.read_all(io.BytesIO(stream + b"X"), "br")
    assert "corrupt" in str(info.value)
