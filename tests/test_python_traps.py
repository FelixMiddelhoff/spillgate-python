"""Python-specific traps (planning: spillgate-languages.md) and resource bounds (SPEC section 10)."""

from __future__ import annotations

import ast
import threading
import tracemalloc
import zlib
from pathlib import Path
from typing import Any

import pytest

import spillgate
from helpers import LOOSE, gz, outcome, raw, zl
from spillgate import Limits, reader

SRC = Path(spillgate.__file__).parent


# -- static scan: the unbounded stdlib APIs are not used ------------------------------


def calls_in_source() -> list[tuple[str, str, ast.Call]]:
    found = []
    for path in SRC.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                found.append((path.name, ast.unparse(node.func), node))
    return found


def test_no_unbounded_stdlib_decompression_api_is_used() -> None:
    """Covers: SG-I-04 SG-R-CDC-07

    `zlib.decompress`, `gzip.decompress`, `gzip.GzipFile`, `Decompress.flush` and the one-shot
    `decompress(data)` without `max_length` all expand without a bound.
    """
    banned = {
        "zlib.decompress",
        "gzip.decompress",
        "gzip.GzipFile",
        "gzip.open",
        "zlib.decompressobj().flush",
    }
    for name, func, node in calls_in_source():
        assert func not in banned, f"{name}: {func}"
        assert not func.endswith(".flush"), f"{name}: unbounded flush() in {func}"
        if func.endswith(".decompress") and func != "zlib.decompress":
            assert len(node.args) + len(node.keywords) >= 2, (
                f"{name}: decompress() without max_length ({ast.unparse(node)})"
            )


def test_max_length_is_never_zero_at_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    """Covers: SG-I-04 SG-R-LAY-02

    `max_length=0` means *unlimited* in zlib. Record every call on a bomb and a trickle read.
    """
    seen: list[int] = []
    real = zlib.decompressobj

    class Spy:
        def __init__(self, *args: Any) -> None:
            self._inner = real(*args)

        def decompress(self, data: bytes, max_length: int = 0) -> bytes:
            seen.append(max_length)
            return self._inner.decompress(data, max_length)

        def __getattr__(self, name: str) -> Any:
            return getattr(self._inner, name)

    monkeypatch.setattr("spillgate._inflate.zlib.decompressobj", Spy)
    bomb = gz(bytes(5_000_000))
    outcome(bomb, "gzip", Limits(max_output=100_000, disable_ratio_limit=True))
    chain = reader(zl(b"abc" * 1000), "deflate", LOOSE)
    while chain.read(1):
        pass
    assert seen and min(seen) >= 1


def test_unconsumed_tail_is_not_lost_or_counted_twice() -> None:
    """Covers: SG-R-RDR-01 SG-R-RAT-02

    Stop the decoder at the output cap with lots of unused input, then continue: the data
    must match the reference and the consumed count must never exceed the stream length.
    """
    payload = bytes(range(256)) * 3000
    stream = raw(payload)
    for step in (1, 2, 5, 4096, 100_000):
        chain = reader(stream, "deflate", LOOSE)
        out = bytearray()
        while chunk := chain.read(step):
            out += chunk
            assert chain._source.consumed <= len(stream)
            if len(out) > 20_000 and step == 1:
                break
        if step != 1:
            assert bytes(out) == payload


def test_consumption_is_counted_where_the_codec_takes_not_where_the_source_is_read() -> None:
    """Covers: SG-R-RAT-02"""
    stream = gz(bytes(3_000_000))
    chain = reader(stream + b"\0" * 100_000, "gzip", Limits(max_output=10**9, ratio_grace=0))
    with pytest.raises(spillgate.SpillgateError):
        chain.readall()  # trailing garbage: corrupt, after the full stream was consumed
    assert chain._source.consumed <= len(stream) + 1


# -- memory and threads ----------------------------------------------------------------


def peak_bytes(work: Any) -> int:
    tracemalloc.start()
    try:
        work()
        return tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


def test_memory_stays_bounded_while_the_bomb_is_far_larger() -> None:
    """Covers: SG-R-MEM-02 SG-I-08"""
    bomb = gz(bytes(200_000_000))  # 200 MB decoded, 200 KB compressed

    def work() -> None:
        chain = reader(bomb, "gzip", Limits(max_output=100_000_000, disable_ratio_limit=True))
        with pytest.raises(spillgate.OutputLimitError):
            while chain.read(1 << 30):  # an absurd buffer size must not allocate that much
                pass

    assert peak_bytes(work) < 4 * 1024 * 1024


def test_one_byte_reads_cost_constant_memory() -> None:
    """Covers: SG-R-MEM-02 SG-I-08 SG-R-RDR-01"""
    stream = gz(bytes(300_000))

    def work() -> None:
        chain = reader(stream, "gzip", LOOSE)
        while chain.read(1):
            pass

    assert peak_bytes(work) < 2 * 1024 * 1024


def test_declared_sizes_do_not_size_allocations() -> None:
    """Covers: SG-R-CDC-07 SG-R-MEM-01 SG-I-04"""
    liar = bytearray(gz(b"small"))
    liar[-4:] = (2**32 - 1).to_bytes(4, "little")  # ISIZE claims 4 GiB

    def work() -> None:
        assert outcome(bytes(liar), "gzip", LOOSE)[0] == "corrupt"

    assert peak_bytes(work) < 1024 * 1024


def test_read_all_grows_with_the_output_not_with_max_output() -> None:
    """Covers: SG-R-MEM-02"""
    stream = gz(b"tiny")

    def work() -> None:
        assert spillgate.decode_all(stream, "gzip", Limits(max_output=2**62)) == b"tiny"

    assert peak_bytes(work) < 1024 * 1024


def test_no_threads_are_started_and_close_releases_the_codec() -> None:
    """Covers: SG-I-10 SG-R-RDR-06"""
    before = threading.active_count()
    chain = reader(gz(bytes(1_000_000)), "gzip", LOOSE)
    chain.read(10)
    assert threading.active_count() == before
    chain.close()
    assert chain._codecs == []
    assert threading.active_count() == before


def test_huge_read_size_is_capped_to_one_step() -> None:
    """Covers: SG-R-MEM-02"""
    chain = reader(gz(bytes(1_000_000)), "gzip", LOOSE)
    chunk = chain.read(2**40)
    assert 0 < len(chunk) <= 256 * 1024
    assert len(chain.readall()) == 1_000_000 - len(chunk)
