"""The optional brotli codec (SG-R-CDC-04)."""

from __future__ import annotations

import tracemalloc

import pytest

import corpus
from helpers import LOOSE, gz, outcome

brotli = pytest.importorskip("brotli")

from spillgate import Decoder, InvalidOptionError, Limits, OutputLimitError, br  # noqa: E402


def decoder(limits: Limits = LOOSE, **kwargs: int) -> Decoder:
    return Decoder(limits, codecs={"br": br.codec(**kwargs)})


def run(stream: bytes, encodings: str = "br", limits: Limits = LOOSE, **kwargs: int):
    return outcome_with(decoder(limits, **kwargs), stream, encodings)


def outcome_with(dec: Decoder, stream: bytes, encodings: str = "br") -> tuple[str, bytes]:
    from spillgate import SpillgateError

    delivered = bytearray()
    try:
        chain = dec.reader(stream, encodings)
    except SpillgateError as error:
        return error.kind.value, b""
    with chain:
        while True:
            try:
                chunk = chain.read(4096)
            except SpillgateError as error:
                return error.kind.value, bytes(delivered)
            if not chunk:
                return "ok", bytes(delivered)
            delivered += chunk


DATA = bytes(range(256)) * 40


def test_round_trip_with_the_reference_encoder() -> None:
    """Covers: SG-R-CDC-04 SG-R-RDR-01"""
    for quality in (0, 1, 5, 9, 11):
        for payload in (b"", b"a", DATA, bytes(100_000), corpus.data(5, 70_000)):
            stream = brotli.compress(payload, quality=quality)
            assert run(stream) == ("ok", payload), (quality, len(payload))


def test_window_bits_table() -> None:
    """Covers: SG-R-CDC-04"""
    assert br.window_bits(0b0) == (16, False)
    for n in range(1, 8):
        assert br.window_bits(1 | n << 1) == (17 + n, False)
    assert br.window_bits(0b0000_0001) == (17, False)
    assert br.window_bits(0b0001_0001) == (0, True)  # the reserved large-window pattern
    for m in range(2, 8):
        assert br.window_bits(1 | m << 4) == (8 + m, False)


@pytest.mark.parametrize("wbits", range(10, 25))
def test_window_cap_is_exact_for_every_size(wbits: int) -> None:
    """Covers: SG-R-CDC-04 SG-R-CDC-07"""
    stream = corpus.brotli_stored(DATA[:300], wbits)
    assert run(stream, max_window_bits=wbits) == ("ok", DATA[:300])
    if wbits > br.MIN_WINDOW_BITS:
        assert run(stream, max_window_bits=wbits - 1)[0] == "memory_limit"


def test_large_window_marker_is_memory_limit_whatever_the_cap() -> None:
    """Covers: SG-R-CDC-04"""
    marker = corpus.brotli_large_window_prefix()
    for cap in (10, 17, 24):
        assert run(marker + bytes(50), max_window_bits=cap)[0] == "memory_limit"


def test_hostile_window_is_refused_before_anything_is_decoded() -> None:
    """Covers: SG-R-CDC-04 SG-R-CDC-07 SG-I-04"""
    stream = corpus.brotli_zeros(1 << 30, 24)

    def work() -> None:
        assert run(stream, max_window_bits=16)[0] == "memory_limit"

    tracemalloc.start()
    try:
        work()
        assert tracemalloc.get_traced_memory()[1] < 200_000
    finally:
        tracemalloc.stop()


def test_cap_settings_are_validated() -> None:
    """Covers: SG-R-CDC-09"""
    for bad in (9, 25, 0, -1, True, 16.0, "16"):
        with pytest.raises(InvalidOptionError):
            br.codec(bad)  # type: ignore[arg-type]
    assert br.codec(10) and br.codec(24)


def test_bomb_ends_in_output_limit_with_constant_memory() -> None:
    """Covers: SG-R-LAY-02 SG-R-MEM-02 SG-I-08"""
    bomb = corpus.brotli_zeros(1 << 30, 24)  # 1 GiB of zeros in 809 bytes
    limits = Limits(max_output=64 * 2**20, disable_ratio_limit=True)

    chain = decoder(limits).reader(bomb, "br")
    delivered = 0
    tracemalloc.start()
    try:
        with pytest.raises(OutputLimitError):
            while chunk := chain.read(1 << 20):
                delivered += len(chunk)  # discarded: only the decoder's own memory is measured
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert delivered == 64 * 2**20
    assert peak < 2**20  # the C decoder's own window is allocated by C, not seen by tracemalloc


def test_ratio_limit_fires_on_a_brotli_bomb() -> None:
    """Covers: SG-R-RAT-01 SG-R-CDC-01"""
    bomb = corpus.brotli_zeros(1 << 30, 24)
    assert run(bomb, limits=Limits(max_output=2**31))[0] == "ratio_limit"


def test_every_truncation_is_corrupt() -> None:
    """Covers: SG-R-CDC-06"""
    stream = brotli.compress(DATA, quality=5)
    for cut in range(len(stream)):
        assert run(stream[:cut])[0] == "corrupt", cut


def test_every_bit_flip_is_ok_or_a_typed_error() -> None:
    """Covers: SG-I-05 SG-R-CDC-08"""
    stream = brotli.compress(b"flip every bit of this brotli stream " * 8, quality=5)
    for position in range(len(stream)):
        for bit in range(8):
            damaged = bytearray(stream)
            damaged[position] ^= 1 << bit
            kind, _ = run(bytes(damaged))
            assert kind in {"ok", "corrupt", "memory_limit"}, (position, bit, kind)


def test_bytes_after_the_last_meta_block_are_corrupt() -> None:
    """Covers: SG-R-CDC-04"""
    stream = brotli.compress(DATA)
    for tail in (b"\0", b"x" * 100, b"\x00" * 5000):
        assert run(stream + tail)[0] == "corrupt"


def test_chains_with_brotli() -> None:
    """Covers: SG-R-LAY-01 SG-R-HDR-12"""
    inner = brotli.compress(DATA)
    assert run(gz(inner), "br, gzip") == ("ok", DATA)  # gzip applied last, so gzip is layer 1
    assert run(brotli.compress(gz(DATA)), "gzip, br") == ("ok", DATA)


def test_read_size_does_not_change_the_result() -> None:
    """Covers: SG-R-RDR-01 SG-I-09"""
    stream = brotli.compress(DATA * 20, quality=4)
    dec = decoder()
    for size in (1, 7, 4096, 1 << 20):
        chain = dec.reader(stream, "br")
        out = bytearray()
        while chunk := chain.read(size):
            out += chunk
        assert bytes(out) == DATA * 20


def test_source_chunking_does_not_matter() -> None:
    """Covers: SG-R-RDR-01"""
    from helpers import Trickle

    stream = brotli.compress(DATA * 5)
    for step in (1, 3, 100, 4096):
        assert decoder().read_all(Trickle(stream, step), "br") == DATA * 5


def test_input_limit_counts_what_the_codec_takes() -> None:
    """Covers: SG-R-INP-01 SG-R-INP-02"""
    stream = brotli.compress(DATA)
    n = len(stream)
    assert run(stream, limits=Limits(max_output=10**7, max_input=n))[0] == "ok"
    assert run(stream, limits=Limits(max_output=10**7, max_input=n - 1))[0] == "input_limit"


def test_old_brotli_versions_are_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """Covers: SG-R-CDC-04"""
    monkeypatch.setattr("importlib.metadata.version", lambda name: "1.2.0")
    with pytest.raises(ImportError, match=r"1\.2\.1"):
        br.codec()
    monkeypatch.setattr("importlib.metadata.version", lambda name: "1.1.0")
    with pytest.raises(ImportError):
        br.codec()


def test_missing_brotli_gives_a_helpful_message(monkeypatch: pytest.MonkeyPatch) -> None:
    """Covers: SG-R-CDC-09"""
    import sys

    monkeypatch.setitem(sys.modules, "brotli", None)
    with pytest.raises(ImportError, match=r"spillgate\[brotli\]"):
        br.codec()


def test_decoder_without_the_codec_refuses_br_as_unsupported() -> None:
    """Covers: SG-R-HDR-08 SG-I-06"""
    assert outcome(brotli.compress(b"x"), "br")[0] == "unsupported_encoding"
