"""SG-R-INP-01 as written: taking byte MaxInput+1 is ``input_limit``, looking at it is not.

Every case runs against several source shapes (whole, one byte at a time, halves, odd chunks,
a tiny first read followed by large ones) and several read patterns. Ported from the Go
reference tests (input_probe_test.go, testsuite/input_probe_test.go).
"""

from __future__ import annotations

import gzip as _gzip
import io
import itertools
import zlib
from collections.abc import Callable
from typing import Any

import pytest

import corpus
from helpers import gz, kind_of, raw, zl
from spillgate import CorruptError, Decoder, Limits, SpillgateError, br, zstd


class Counting:
    """A source that counts what it handed out, in the given shape."""

    def __init__(self, payload: bytes, step: Callable[[int, int], int]) -> None:
        self._inner = io.BytesIO(payload)
        self._step = step
        self._calls = 0
        self.handed = 0

    def read(self, n: int) -> bytes:
        chunk = self._inner.read(self._step(n, self._calls))
        self._calls += 1
        self.handed += len(chunk)
        return chunk


SHAPES: dict[str, Callable[[int, int], int]] = {
    "whole": lambda n, call: n,
    "one-byte": lambda n, call: 1,
    "half": lambda n, call: max(1, n // 2),
    "chunks-of-7": lambda n, call: min(n, 7),
    "tiny-first": lambda n, call: 1 if call == 0 else n,
}
PATTERNS = [(1,), (3,), (4096,), (1 << 20,), (1, 7, 4096, 1)]
RUNS = [(s, p) for s in SHAPES for p in PATTERNS]
RUN_IDS = [f"{s}-{'_'.join(map(str, p))}" for s, p in RUNS]


def decode_probe(
    stream: bytes, max_input: int, shape: str, pattern: tuple[int, ...], *encodings: str
) -> tuple[str, bytes, int]:
    """Return (outcome class, delivered bytes, bytes the source handed out)."""
    limits = Limits(max_output=1 << 30, disable_ratio_limit=True, max_input=max_input)
    codecs: dict[str, Any] = {}
    if "br" in encodings:
        codecs["br"] = br.codec()
    if "zstd" in encodings:
        codecs["zstd"] = zstd.codec()
    source = Counting(stream, SHAPES[shape])
    delivered = bytearray()
    chain = Decoder(limits, codecs=codecs).reader(source, list(encodings))
    with chain:
        for i in itertools.count():
            try:
                chunk = chain.read(pattern[i % len(pattern)])
            except SpillgateError as error:
                with pytest.raises(SpillgateError) as again:
                    chain.read(1)
                assert kind_of(again.value) == kind_of(error), "terminal condition is sticky"
                return kind_of(error), bytes(delivered), source.handed
            if not chunk:
                return "ok", bytes(delivered), source.handed
            delivered += chunk
    raise AssertionError("unreachable")


def _optional(name: str) -> bool:
    try:
        (br if name == "br" else zstd).codec()
    except ImportError:
        return False
    return True


TEXT = b"probe the byte after the limit. " * 300
RANDOM = corpus.data(5, 700)

STREAMS: list[tuple[str, str, bytes, bytes]] = [
    ("gzip", "gzip", TEXT, gz(TEXT)),
    ("gzip stored", "gzip", RANDOM, corpus.gzip_stored(RANDOM)),
    ("gzip two members", "gzip", TEXT + RANDOM, gz(TEXT) + gz(RANDOM)),
    ("zlib", "deflate", TEXT, zl(TEXT)),
    ("zlib stored", "deflate", RANDOM, corpus.zlib_stored(RANDOM)),
    ("raw deflate", "deflate", TEXT, raw(TEXT)),
    ("raw deflate stored", "deflate", RANDOM, corpus.stored_deflate(RANDOM)),
]
if _optional("br"):
    import brotli

    STREAMS += [
        ("brotli", "br", TEXT, brotli.compress(TEXT)),
        ("brotli stored", "br", RANDOM, corpus.brotli_stored(RANDOM, 16)),
    ]
if _optional("zstd"):
    import zstandard

    STREAMS += [
        ("zstd", "zstd", TEXT, zstandard.ZstdCompressor(write_checksum=True).compress(TEXT)),
        ("zstd stored", "zstd", RANDOM, corpus.zstd_stored(RANDOM, 17)),
        (
            "zstd two frames",
            "zstd",
            RANDOM * 2,
            corpus.zstd_stored(RANDOM, 17) + corpus.zstd_stored(RANDOM, 17),
        ),
        (
            "zstd skippable",
            "zstd",
            RANDOM,
            corpus.zstd_stored(RANDOM, 17) + corpus.zstd_skippable(5),
        ),
    ]

STREAM_IDS = [s[0] for s in STREAMS]
TAILS = {
    "one zero byte": b"\x00",
    "1000 zero bytes": bytes(1000),
    "text": b"trailing garbage that is longer than the probe",
}


@pytest.mark.parametrize(("shape", "pattern"), RUNS, ids=RUN_IDS)
@pytest.mark.parametrize("tail", TAILS.values(), ids=TAILS.keys())
@pytest.mark.parametrize(("name", "enc", "plain", "data"), STREAMS, ids=STREAM_IDS)
def test_probe_after_complete_stream_is_corrupt(
    name: str,
    enc: str,
    plain: bytes,
    data: bytes,
    tail: bytes,
    shape: str,
    pattern: tuple[int, ...],
) -> None:
    length = len(data)
    for max_input in (length, length + 1, length + 5):
        kind, _, handed = decode_probe(data + tail, max_input, shape, pattern, enc)
        assert kind == "corrupt", f"{name}: MaxInput {max_input}, stream {length}: {kind}"
        assert handed <= max_input + 1


@pytest.mark.parametrize(("shape", "pattern"), RUNS, ids=RUN_IDS)
@pytest.mark.parametrize(("name", "enc", "plain", "data"), STREAMS, ids=STREAM_IDS)
def test_exact_stream_with_nothing_after_is_ok(
    name: str, enc: str, plain: bytes, data: bytes, shape: str, pattern: tuple[int, ...]
) -> None:
    for max_input in (len(data), len(data) + 1):
        kind, got, _ = decode_probe(data, max_input, shape, pattern, enc)
        assert (kind, got) == ("ok", plain), f"{name}: MaxInput {max_input}: {kind}"


@pytest.mark.parametrize(("shape", "pattern"), RUNS, ids=RUN_IDS)
@pytest.mark.parametrize(("name", "enc", "plain", "data"), STREAMS, ids=STREAM_IDS)
def test_cut_at_the_limit_depends_on_the_source(
    name: str, enc: str, plain: bytes, data: bytes, shape: str, pattern: tuple[int, ...]
) -> None:
    length = len(data)
    for k in sorted(
        {1, 5, 9, 10, 11, length // 3, length // 2, length - 9, length - 5, length - 1}
    ):
        if not 0 < k < length:
            continue
        if decode_probe(data[:k], 1 << 40, "whole", (4096,), enc)[0] == "ok":
            continue  # a cut at a member or frame boundary is a complete stream
        # The source really ends at k: truncated.
        kind, _, _ = decode_probe(data[:k], k, shape, pattern, enc)
        assert kind == "corrupt", f"{name}: source ends at {k} = MaxInput: {kind}"
        # The source goes on: the byte after the limit is needed and taken.
        kind, _, handed = decode_probe(data + bytes(50), k, shape, pattern, enc)
        assert kind == "input_limit", f"{name}: cut at MaxInput {k} of {length}: {kind}"
        assert handed <= k + 1
        # Garbage instead of the rest: the stream cannot finish either.
        kind, _, _ = decode_probe(data[:k] + b"\xa5" * 50, k, shape, pattern, enc)
        assert kind == "input_limit", f"{name}: garbage after MaxInput {k}: {kind}"


@pytest.mark.parametrize(("shape", "pattern"), RUNS, ids=RUN_IDS)
def test_probe_that_could_start_another_member_is_taken(
    shape: str, pattern: tuple[int, ...]
) -> None:
    data = gz(TEXT)
    stream = data + b"\x1f"
    assert decode_probe(stream, len(data), shape, pattern, "gzip")[0] == "input_limit"
    assert decode_probe(stream, len(data) + 1, shape, pattern, "gzip")[0] == "corrupt"


@pytest.mark.skipif(not _optional("zstd"), reason="zstandard not installed")
@pytest.mark.parametrize(("shape", "pattern"), RUNS, ids=RUN_IDS)
@pytest.mark.parametrize("probe", [0x28, 0x50, 0x5F])
def test_probe_that_could_start_another_zstd_frame_is_taken(
    probe: int, shape: str, pattern: tuple[int, ...]
) -> None:
    data = corpus.zstd_stored(RANDOM, 17)
    stream = data + bytes([probe])
    assert decode_probe(stream, len(data), shape, pattern, "zstd")[0] == "input_limit"
    assert decode_probe(stream, len(data) + 1, shape, pattern, "zstd")[0] == "corrupt"
    # a byte that cannot start a frame is only looked at
    assert decode_probe(data + b"\x27", len(data), shape, pattern, "zstd")[0] == "corrupt"
    assert decode_probe(data + b"\x60", len(data), shape, pattern, "zstd")[0] == "corrupt"


@pytest.mark.parametrize(("shape", "pattern"), RUNS, ids=RUN_IDS)
@pytest.mark.parametrize("encodings", [(), ("identity",)])
def test_identity_still_stops_at_the_limit(
    encodings: tuple[str, ...], shape: str, pattern: tuple[int, ...]
) -> None:
    body = corpus.data(9, 300)
    limit = len(body) - 1
    kind, got, handed = decode_probe(body, limit, shape, pattern, *encodings)
    assert (kind, got) == ("input_limit", body[:limit])
    assert handed <= limit + 1
    kind, got, _ = decode_probe(body + bytes(1000), len(body), shape, pattern, *encodings)
    assert (kind, got) == ("input_limit", body)
    kind, got, _ = decode_probe(body, len(body), shape, pattern, *encodings)
    assert (kind, got) == ("ok", body)


@pytest.mark.parametrize(("shape", "pattern"), RUNS, ids=RUN_IDS)
def test_only_layer_one_carries_max_input(shape: str, pattern: tuple[int, ...]) -> None:
    zeros = bytes(100000)
    inner = corpus.gzip_stored(zeros)
    outer = _gzip.compress(inner, mtime=0)
    assert len(outer) * 10 < len(inner)
    length = len(outer)
    kind, got, _ = decode_probe(outer, length, shape, pattern, "gzip", "gzip")
    assert (kind, len(got)) == ("ok", len(zeros))
    for tail in (b"\x00", bytes(500)):
        for max_input in (length, length + 1):
            kind, _, handed = decode_probe(outer + tail, max_input, shape, pattern, "gzip", "gzip")
            assert kind == "corrupt"
            assert handed <= max_input + 1
    assert decode_probe(outer, length - 1, shape, pattern, "gzip", "gzip")[0] == "input_limit"
    assert (
        decode_probe(outer + b"\x00", length, "whole", (4096,), "identity", "gzip", "gzip")[0]
        == "corrupt"
    )


# -- the end-of-step check, with a custom codec ------------------------------------------

MAX = 5


class StepCodec:
    """A codec whose single step is a function of the source."""

    def __init__(self, step: Callable[[Any], bytes]) -> None:
        self._step = step

    def new_reader(self, source: Any) -> Any:
        step = self._step

        class Reader:
            def read(self, n: int) -> bytes:
                return step(source)

        return Reader()


def _take(source: Any, n: int) -> None:
    for _ in range(n):
        assert source.take(1)


def _take_bulk(source: Any, size: int) -> int:
    total = 0
    while total < size:
        chunk = source.take(size - total)
        if not chunk:
            break
        total += len(chunk)
    return total


def _eof_after(count: int) -> Callable[[Any], bytes]:
    def step(source: Any) -> bytes:
        _take(source, count)
        return b""

    return step


def _data_after(source: Any) -> bytes:
    _take(source, MAX + 1)
    return b"x"


def _corrupt_after(source: Any) -> bytes:
    _take(source, MAX + 1)
    raise CorruptError("made up")


def _bulk_keeps(source: Any) -> bytes:
    assert _take_bulk(source, 64) == MAX + 1
    return b""


def _look_and_give_back(source: Any) -> bytes:
    _take(source, MAX)
    probe = source.take(1)
    assert len(probe) == 1
    source.unread(probe)
    return b""


def _bulk_look_and_give_back(source: Any) -> bytes:
    assert _take_bulk(source, MAX + 1) == MAX + 1
    source.unread(b"\x00")  # the one byte just taken, the probe
    return b""


def _trailing_reported(source: Any) -> bytes:
    _take(source, MAX)
    source.unread(source.take(1))
    raise CorruptError("trailing data")


def _asks_for_more(source: Any) -> bytes:
    _take(source, MAX + 1)
    source.take(1)  # byte MAX+2: never available
    return b""


STEPS = {
    "takes MaxInput+1 bytes and returns data": (_data_after, "input_limit"),
    "takes MaxInput+1 bytes and ends cleanly": (_eof_after(MAX + 1), "input_limit"),
    "takes MaxInput+1 bytes and reports corrupt": (_corrupt_after, "input_limit"),
    "asks for a buffer much larger than MaxInput and keeps it": (_bulk_keeps, "input_limit"),
    "takes MaxInput bytes and ends cleanly": (_eof_after(MAX), "ok"),
    "looks at the probe and gives it back": (_look_and_give_back, "ok"),
    "bulk read, gives the probe back": (_bulk_look_and_give_back, "ok"),
    "finds trailing data behind the probe and reports it": (_trailing_reported, "corrupt"),
    "cannot go on without the probe and asks for more": (_asks_for_more, "input_limit"),
}


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("name", STEPS)
def test_taking_is_checked_at_the_end_of_the_codec_step(name: str, shape: str) -> None:
    step, want = STEPS[name]
    limits = Limits(max_output=1 << 20, disable_ratio_limit=True, max_input=MAX)
    decoder = Decoder(limits, codecs={"x": StepCodec(step)})
    source = Counting(corpus.data(3, 100), SHAPES[shape])
    with decoder.reader(source, "x") as chain:
        try:
            chain.readall()
            kind = "ok"
        except SpillgateError as error:
            kind = kind_of(error)
    assert kind == want
    assert source.handed <= MAX + 1


def test_zlib_module_is_unaffected_by_probe_byte_shape() -> None:
    """A zlib stream followed by a byte that is not the stream end stays corrupt."""
    data = zlib.compress(b"abc")
    assert decode_probe(data + b"\x00", len(data), "whole", (4096,), "deflate")[0] == "corrupt"
