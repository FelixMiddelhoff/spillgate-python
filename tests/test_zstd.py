"""The optional zstd codec (SG-R-CDC-05)."""

from __future__ import annotations

import time
import tracemalloc

import pytest

import corpus
from helpers import LOOSE, Trickle, gz

zstandard = pytest.importorskip("zstandard")

from spillgate import (  # noqa: E402
    Decoder,
    InvalidOptionError,
    Limits,
    OutputLimitError,
    SpillgateError,
    zstd,
)

DATA = bytes(range(256)) * 40
MIB = 2**20


def decoder(limits: Limits = LOOSE, **kwargs: int) -> Decoder:
    return Decoder(limits, codecs={"zstd": zstd.codec(**kwargs)})


def run(stream: bytes, encodings: str = "zstd", limits: Limits = LOOSE, **kwargs: int):
    delivered = bytearray()
    try:
        chain = decoder(limits, **kwargs).reader(stream, encodings)
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


def compress(payload: bytes, **kwargs: object) -> bytes:
    return zstandard.ZstdCompressor(**kwargs).compress(payload)


def test_round_trip_with_the_reference_encoder() -> None:
    """Covers: SG-R-CDC-05 SG-R-RDR-01"""
    for level in (1, 3, 9, 19):
        for payload in (b"", b"a", DATA, bytes(300_000), corpus.data(5, 200_000)):
            assert run(compress(payload, level=level)) == ("ok", payload), (level, len(payload))


def test_content_checksum_is_verified() -> None:
    """Covers: SG-R-CDC-05"""
    stream = compress(DATA, write_checksum=True)
    assert run(stream) == ("ok", DATA)
    damaged = bytearray(stream)
    damaged[-1] ^= 1
    assert run(bytes(damaged))[0] == "corrupt"
    assert run(stream[:-2])[0] == "corrupt"


@pytest.mark.parametrize("window_log", range(10, 31))
def test_window_cap_is_exact_at_every_power_of_two(window_log: int) -> None:
    """Covers: SG-R-CDC-05 SG-R-CDC-07"""
    cap = 1 << window_log
    frame = corpus.zstd_zeros(1000, window_log) if window_log < 28 else b""
    if frame:
        assert run(frame, max_window_bytes=cap)[0] == "ok"
        if window_log > 10:
            assert run(frame, max_window_bytes=cap - 1)[0] == "memory_limit"


def test_mantissa_windows_are_checked_too() -> None:
    """Covers: SG-R-CDC-05"""
    # window = 2**20 + 2**20 / 8 * 3 with mantissa 3
    header = corpus.zstd_header(window_log=20, mantissa=3)
    frame = header + corpus.zstd_raw_blocks(b"abc", 3, True)
    window = 2**20 + 2**20 // 8 * 3
    assert run(frame, max_window_bytes=window)[0] == "ok"
    assert run(frame, max_window_bytes=window - 1)[0] == "memory_limit"


@pytest.mark.parametrize(
    "size", [0, 1, 255, 256, 300, 65791, 65792, 70_000, 2**32 - 1, 2**32, 2**40]
)
def test_single_segment_window_is_the_declared_content_size(size: int) -> None:
    """Covers: SG-R-CDC-05 SG-R-CDC-07 SG-I-04"""
    header = corpus.zstd_header(single_segment=True, content_size=size)
    frame = header + corpus.zstd_raw_blocks(b"x", 1, True)
    assert run(frame, max_window_bytes=min(max(size, zstd.MIN_WINDOW), zstd.MAX_WINDOW))[0] in {
        "ok",
        "corrupt",
        "memory_limit",
    }
    if size >= 2 * zstd.MIN_WINDOW and size <= zstd.MAX_WINDOW:
        assert run(frame, max_window_bytes=size - 1)[0] == "memory_limit"
    if size > zstd.DEFAULT_MAX_WINDOW:
        assert run(frame)[0] == "memory_limit"


def test_hostile_header_allocates_nothing_before_refusal() -> None:
    """Covers: SG-R-CDC-05 SG-I-04 SG-R-MEM-01"""
    frame = corpus.zstd_header(single_segment=True, content_size=2**40) + b"\0" * 20

    tracemalloc.start()
    try:
        assert run(frame)[0] == "memory_limit"
        assert tracemalloc.get_traced_memory()[1] < 200_000
    finally:
        tracemalloc.stop()


def test_dictionary_reserved_bit_and_bad_blocks_are_corrupt() -> None:
    """Covers: SG-R-CDC-05"""
    body = corpus.zstd_raw_blocks(b"abc", 3, True)
    base = {"window_log": 17}
    assert run(corpus.zstd_header(**base, dictionary_id=1) + body)[0] == "corrupt"
    assert run(corpus.zstd_header(**base, dictionary_id=0) + body)[0] in {"ok", "corrupt"}
    assert run(corpus.zstd_header(**base, reserved_bit=True) + body)[0] == "corrupt"
    reserved_block = corpus.zstd_header(**base) + bytes([0b0000_0111, 0, 0])
    assert run(reserved_block)[0] == "corrupt"
    too_big = (
        corpus.zstd_header(**base) + bytes([(129 * 1024 << 3 | 1) & 0xFF, 0x04, 0x10]) + b"\0" * 10
    )
    assert run(too_big)[0] == "corrupt"


def test_bad_checksum_after_more_than_max_output_is_output_limit() -> None:
    """Covers: SG-R-LAY-07 SG-R-CDC-05"""
    stream = bytearray(compress(DATA, write_checksum=True))
    stream[-1] ^= 1
    # the output limit is reached first in stream order; the trailer is never looked at
    kind, got = run(bytes(stream), limits=Limits(max_output=100, disable_ratio_limit=True))
    assert (kind, len(got)) == ("output_limit", 100)
    # exactly max_output bytes followed by a bad checksum is corrupt
    kind, got = run(bytes(stream), limits=Limits(max_output=len(DATA), disable_ratio_limit=True))
    assert kind == "corrupt" and got == DATA


def test_bomb_ends_in_output_limit_with_constant_memory() -> None:
    """Covers: SG-R-LAY-02 SG-R-MEM-02 SG-I-08"""
    bomb = corpus.zstd_zeros(1 << 30, 23)  # 1 GiB of zeros in 32 KiB
    chain = decoder(Limits(max_output=64 * MIB, disable_ratio_limit=True)).reader(bomb, "zstd")
    delivered = 0
    tracemalloc.start()
    try:
        with pytest.raises(OutputLimitError):
            while chunk := chain.read(1 << 20):
                delivered += len(chunk)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert delivered == 64 * MIB
    assert peak < MIB


def test_ratio_limit_fires_on_a_zstd_bomb() -> None:
    """Covers: SG-R-RAT-01"""
    bomb = corpus.zstd_zeros(1 << 30, 23)
    assert run(bomb, limits=Limits(max_output=2**31))[0] == "ratio_limit"


def test_every_truncation_is_corrupt() -> None:
    """Covers: SG-R-CDC-06"""
    stream = compress(DATA * 3, write_checksum=True)
    for cut in range(len(stream)):
        assert run(stream[:cut])[0] == "corrupt", cut
    raw_frame = corpus.zstd_stored(DATA, 17)
    for cut in range(len(raw_frame)):
        assert run(raw_frame[:cut])[0] == "corrupt", cut


def test_every_bit_flip_is_ok_or_a_typed_error() -> None:
    """Covers: SG-I-05 SG-R-CDC-08"""
    stream = compress(b"flip every bit of this zstd frame " * 6, write_checksum=True)
    for position in range(len(stream)):
        for bit in range(8):
            damaged = bytearray(stream)
            damaged[position] ^= 1 << bit
            kind, _ = run(bytes(damaged))
            assert kind in {"ok", "corrupt", "memory_limit", "output_limit"}, (position, bit, kind)


def test_concatenated_and_skippable_frames() -> None:
    """Covers: SG-R-CDC-05"""
    a, b = compress(b"first "), compress(b"second")
    assert run(a + b) == ("ok", b"first second")
    skip = corpus.zstd_skippable(5)
    assert run(skip + a + skip + b + skip) == ("ok", b"first second")
    assert run(skip)[0] in {"ok", "corrupt"}
    assert run(skip + b"") == run(skip)
    # frames share one output budget
    kind, got = run(a + b, limits=Limits(max_output=8, disable_ratio_limit=True))
    assert kind == "output_limit" and got == b"first se"


def test_many_skippable_frames_are_cheap() -> None:
    """Covers: SG-R-CDC-05 SG-R-RAT-02"""
    stream = corpus.zstd_skippable(0) * 20_000 + compress(b"end")
    started = time.monotonic()
    kind, got = run(stream, limits=Limits(max_output=100, disable_ratio_limit=True))
    assert (kind, got) == ("ok", b"end")
    assert time.monotonic() - started < 10


def test_data_after_the_last_frame_is_corrupt() -> None:
    """Covers: SG-R-CDC-05"""
    stream = compress(DATA)
    for tail in (b"\0", b"abc", b"\x28\xb5\x2f", b"\x50\x2a\x4d\x18", b"\x00" * 100):
        assert run(stream + tail)[0] == "corrupt", tail
    assert run(b"")[0] == "corrupt"


def test_lying_content_size_never_raises_an_allowance() -> None:
    """Covers: SG-R-CDC-07 SG-I-04"""
    real = b"x" * 1000
    big = corpus.zstd_header(window_log=17, content_size=2**40) + corpus.zstd_raw_blocks(
        real, 1000, True
    )
    # SG-R-CDC-05: either refusal is correct, and never more than max_output bytes arrive.
    kind, got = run(big, limits=Limits(max_output=100, disable_ratio_limit=True))
    assert kind in {"output_limit", "corrupt"} and len(got) <= 100
    small = corpus.zstd_header(single_segment=True, content_size=10) + corpus.zstd_raw_blocks(
        real, 1000, True
    )
    assert run(small)[0] in {"corrupt", "ok", "output_limit"}
    assert run(small, limits=Limits(max_output=100, disable_ratio_limit=True))[0] in {
        "output_limit",
        "corrupt",
    }


def test_read_sizes_and_source_chunking_do_not_matter() -> None:
    """Covers: SG-R-RDR-01 SG-I-09"""
    stream = compress(DATA * 20, write_checksum=True)
    dec = decoder()
    for size in (1, 7, 4096, 1 << 20):
        chain = dec.reader(stream, "zstd")
        out = bytearray()
        while chunk := chain.read(size):
            out += chunk
        assert bytes(out) == DATA * 20
    for step in (1, 5, 4096):
        assert dec.read_all(Trickle(stream, step), "zstd") == DATA * 20


def test_chains_with_zstd() -> None:
    """Covers: SG-R-LAY-01 SG-R-HDR-12"""
    dec = Decoder(LOOSE, codecs={"zstd": zstd.codec()})
    assert dec.read_all(gz(compress(DATA)), "zstd, gzip") == DATA
    assert dec.read_all(compress(gz(DATA)), "gzip, zstd") == DATA


def test_input_limit_counts_what_the_codec_takes() -> None:
    """Covers: SG-R-INP-01 SG-R-INP-02"""
    stream = compress(DATA)
    n = len(stream)
    assert run(stream, limits=Limits(max_output=10**7, max_input=n))[0] == "ok"
    assert run(stream, limits=Limits(max_output=10**7, max_input=n - 1))[0] == "input_limit"


def test_cap_settings_are_validated() -> None:
    """Covers: SG-R-CDC-09"""
    for bad in (0, 1023, 2**30 + 1, -1, True, 1.5, "8"):
        with pytest.raises(InvalidOptionError):
            zstd.codec(bad)  # type: ignore[arg-type]
    assert zstd.codec(1024) and zstd.codec(2**30)


def test_old_zstandard_versions_are_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """Covers: SG-R-CDC-05"""
    monkeypatch.setattr("importlib.metadata.version", lambda name: "0.24.0")
    with pytest.raises(ImportError, match=r"0\.25"):
        zstd.codec()


def test_missing_zstandard_gives_a_helpful_message(monkeypatch: pytest.MonkeyPatch) -> None:
    """Covers: SG-R-CDC-09"""
    import sys

    monkeypatch.setitem(sys.modules, "zstandard", None)
    with pytest.raises(ImportError, match=r"spillgate\[zstd\]"):
        zstd.codec()


def test_empty_frames_cost_bounded_cpu_per_input_byte() -> None:
    """Covers: SG-R-RAT-02 SG-R-MEM-02

    Frames without output are invisible to the output and ratio limits; only `max_input` bounds
    them. The cost per input byte is measured so a regression (a new DCtx per frame cost 9x
    more) shows up.
    """
    frame = corpus.zstd_header(window_log=23) + corpus.zstd_raw_blocks(b"", 1024, True)
    data = frame * 20_000  # 180 KB
    limits = Limits(max_output=100, disable_ratio_limit=True)
    started = time.monotonic()
    assert decoder(limits).read_all(data, "zstd") == b""
    assert time.monotonic() - started < 5
    kind, _ = run(data, limits=Limits(max_output=100, max_input=len(data) // 2))
    assert kind == "input_limit"
