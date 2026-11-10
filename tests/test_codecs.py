"""gzip (SG-R-CDC-02) and deflate (SG-R-CDC-03) framing, one rule at a time."""

from __future__ import annotations

import struct
import zlib

import pytest

import corpus
from helpers import LOOSE, gz, outcome, raw, zl
from spillgate import Limits

DATA = bytes(range(256)) * 20


def member(
    payload: bytes,
    *,
    flags: int = 0,
    extra: bytes | None = None,
    name: bytes | None = None,
    comment: bytes | None = None,
    hcrc: bool | int = False,
    crc: int | None = None,
    isize: int | None = None,
    magic: bytes = b"\x1f\x8b\x08",
) -> bytes:
    """Build one gzip member with the requested header fields (stored DEFLATE body)."""
    header = bytearray(magic + bytes([flags, 0, 0, 0, 0, 0, 255]))
    if extra is not None:
        header[3] |= 4
        header += struct.pack("<H", len(extra)) + extra
    if name is not None:
        header[3] |= 8
        header += name + b"\0"
    if comment is not None:
        header[3] |= 16
        header += comment + b"\0"
    if hcrc is not False:
        header[3] |= 2
        value = zlib.crc32(bytes(header)) & 0xFFFF if hcrc is True else int(hcrc)
        header += struct.pack("<H", value)
    crc = zlib.crc32(payload) if crc is None else crc
    isize = len(payload) if isize is None else isize
    return (
        bytes(header) + corpus.stored_deflate(payload) + struct.pack("<II", crc, isize & 0xFFFFFFFF)
    )


# -- gzip ---------------------------------------------------------------------------


def test_plain_and_library_made_gzip_decode() -> None:
    """Covers: SG-R-CDC-02"""
    assert outcome(member(DATA), "gzip") == ("ok", DATA)
    assert outcome(gz(DATA), "gzip") == ("ok", DATA)
    assert outcome(gz(b""), "gzip") == ("ok", b"")
    assert outcome(member(b""), "x-gzip") == ("ok", b"")


@pytest.mark.parametrize(
    "stream",
    [b"", b"\x1f", b"\x1f\x8b", b"\x1f\x8b\x08", b"\x1f\x8c" + bytes(30), b"\x1e\x8b\x08" + bytes(30),
     b"\x1f\x8b\x07" + bytes(30), b"\x1f\x8b\x09" + bytes(30), b"PK\x03\x04" + bytes(30)],
)  # fmt: skip
def test_bad_magic_or_method_is_corrupt(stream: bytes) -> None:
    """Covers: SG-R-CDC-02"""
    assert outcome(stream, "gzip")[0] == "corrupt"


@pytest.mark.parametrize("bit", [5, 6, 7])
def test_reserved_flag_bits_are_corrupt(bit: int) -> None:
    """Covers: SG-R-CDC-02"""
    assert outcome(member(DATA, flags=1 << bit), "gzip")[0] == "corrupt"


def test_ftext_flag_is_harmless() -> None:
    """Covers: SG-R-CDC-02"""
    assert outcome(member(DATA, flags=1), "gzip") == ("ok", DATA)


def test_header_crc_is_verified() -> None:
    """Covers: SG-R-CDC-02"""
    assert outcome(member(DATA, hcrc=True, name=b"n"), "gzip") == ("ok", DATA)
    assert outcome(member(DATA, hcrc=0x1234, name=b"n"), "gzip")[0] == "corrupt"
    assert outcome(member(DATA, hcrc=True, extra=b"x" * 10, comment=b"c"), "gzip") == ("ok", DATA)


def test_extra_field_sizes() -> None:
    """Covers: SG-R-CDC-02 SG-R-MEM-01"""
    for size in (0, 1, 511, 512, 513, 65535):
        assert outcome(member(DATA, extra=b"e" * size), "gzip") == ("ok", DATA), size
    truncated = member(DATA, extra=b"e" * 1000)[:600]
    assert outcome(truncated, "gzip")[0] == "corrupt"


@pytest.mark.parametrize("field", ["name", "comment"])
def test_name_and_comment_are_bounded_at_512_bytes_with_the_terminator(field: str) -> None:
    """Covers: SG-R-CDC-02 SG-R-MEM-01"""
    assert outcome(member(DATA, **{field: b"n" * 511}), "gzip") == ("ok", DATA)  # type: ignore[arg-type]
    assert outcome(member(DATA, **{field: b"n" * 512}), "gzip")[0] == "corrupt"  # type: ignore[arg-type]
    assert outcome(member(DATA, **{field: b"n" * 100_000}), "gzip")[0] == "corrupt"  # type: ignore[arg-type]
    assert outcome(member(DATA, **{field: b""}), "gzip") == ("ok", DATA)  # type: ignore[arg-type]


def test_endless_name_without_terminator_stops_early() -> None:
    """Covers: SG-R-CDC-02 SG-R-MEM-01 SG-I-04"""
    from helpers import Trickle

    source = Trickle(b"\x1f\x8b\x08\x08" + bytes(6) + b"n" * 10_000_000, step=4096)
    assert outcome(source, "gzip")[0] == "corrupt"
    assert source.total < 5000


def test_crc_and_isize_are_checked_and_isize_is_modulo_2_32() -> None:
    """Covers: SG-R-CDC-02 SG-R-CDC-07"""
    assert outcome(member(DATA, crc=0), "gzip")[0] == "corrupt"
    assert outcome(member(DATA, isize=len(DATA) + 1), "gzip")[0] == "corrupt"
    assert outcome(member(DATA, isize=0), "gzip")[0] == "corrupt"
    assert outcome(member(DATA, isize=len(DATA) + 2**32), "gzip") == ("ok", DATA)  # modulo 2**32


def test_wrong_isize_is_never_an_allowance_or_early_rejection() -> None:
    """Covers: SG-R-CDC-07 SG-I-04"""
    lying = member(DATA, isize=2**32 - 1)
    assert (
        outcome(lying, "gzip", Limits(max_output=10))[0] == "output_limit"
    )  # produced bytes decide
    assert outcome(member(b"x" * 1000, isize=1), "gzip", Limits(max_output=5000))[0] == "corrupt"


def test_trailing_bytes_after_a_member_are_corrupt() -> None:
    """Covers: SG-R-CDC-02"""
    good = member(DATA)
    for tail in (b"\0", b"\0" * 16, b"garbage", b"\x1f", b"\x1f\x8b", b"\x1f\x8b\x08"):
        assert outcome(good + tail, "gzip")[0] == "corrupt", tail


def test_multiple_members_share_one_budget() -> None:
    """Covers: SG-R-CDC-02 SG-R-LAY-02"""
    two = member(DATA) + member(DATA)
    assert outcome(two, "gzip") == ("ok", DATA + DATA)
    kind, got = outcome(two, "gzip", Limits(max_output=len(DATA) + 5, disable_ratio_limit=True))
    assert kind == "output_limit" and len(got) == len(DATA) + 5
    assert outcome(member(b"") * 50 + member(DATA), "gzip") == ("ok", DATA)


def test_second_member_errors_are_reported_too() -> None:
    """Covers: SG-R-CDC-02"""
    assert outcome(member(DATA) + member(DATA, crc=1), "gzip")[0] == "corrupt"
    assert outcome(member(DATA) + member(DATA)[:20], "gzip")[0] == "corrupt"


def test_every_truncation_of_a_gzip_stream_is_corrupt() -> None:
    """Covers: SG-R-CDC-06"""
    stream = member(b"hello truncation", name=b"f", comment=b"c", extra=b"xy", hcrc=True)
    for cut in range(len(stream)):
        assert outcome(stream[:cut], "gzip")[0] == "corrupt", cut
    real = gz(b"hello world " * 100)
    for cut in range(len(real)):
        assert outcome(real[:cut], "gzip")[0] == "corrupt", cut


def test_every_bit_flip_gives_ok_or_corrupt_never_something_else() -> None:
    """Covers: SG-I-05 SG-R-CDC-08"""
    stream = gz(b"flip every bit " * 20)
    for position in range(len(stream)):
        for bit in range(8):
            damaged = bytearray(stream)
            damaged[position] ^= 1 << bit
            kind, _ = outcome(bytes(damaged), "gzip")
            assert kind in {"ok", "corrupt"}, (position, bit, kind)
            if 4 <= position <= 9 and kind != "ok":
                pytest.fail(f"MTIME/XFL/OS flip {position}:{bit} must be harmless")


# -- deflate (zlib and raw) --------------------------------------------------------------


def test_zlib_and_raw_deflate_decode() -> None:
    """Covers: SG-R-CDC-03"""
    for stream in (zl(DATA), raw(DATA), corpus.zlib_stored(DATA), corpus.stored_deflate(DATA)):
        assert outcome(stream, "deflate") == ("ok", DATA)
    assert outcome(zl(b""), "deflate") == ("ok", b"")
    assert outcome(raw(b""), "deflate") == ("ok", b"")


def test_zlib_header_detection_table() -> None:
    """Covers: SG-R-CDC-03"""
    from spillgate._deflate import is_zlib_header

    assert is_zlib_header(0x78, 0x01) and is_zlib_header(0x78, 0x9C) and is_zlib_header(0x78, 0xDA)
    assert is_zlib_header(0x08, 0x1D)  # CINFO 0 is allowed
    assert not is_zlib_header(0x78, 0x00)  # not a multiple of 31
    assert not is_zlib_header(0x79, 0x01)  # CM 9
    assert not is_zlib_header(0x88, 0x1C)  # CINFO 8


def test_preset_dictionary_flag_is_corrupt_not_retried_as_raw() -> None:
    """Covers: SG-R-CDC-03"""
    fdict = bytes([0x78, 0xBB])  # FDICT set, valid check bits
    assert (0x78 << 8 | 0xBB) % 31 == 0
    assert outcome(fdict + bytes(20), "deflate")[0] == "corrupt"


def test_adler_trailer_and_trailing_bytes() -> None:
    """Covers: SG-R-CDC-03"""
    good = corpus.zlib_stored(DATA)
    assert outcome(good[:-1] + bytes([good[-1] ^ 1]), "deflate")[0] == "corrupt"
    assert outcome(good + b"\0", "deflate")[0] == "corrupt"
    assert outcome(good[:-2], "deflate")[0] == "corrupt"
    assert outcome(raw(DATA) + b"\0", "deflate")[0] == "corrupt"
    assert outcome(raw(DATA) + b"\x78\x9c", "deflate")[0] == "corrupt"


def test_raw_stream_that_looks_like_a_zlib_header_fails_closed() -> None:
    """Covers: SG-R-CDC-03"""
    # A stored block "00 00 00 ff ff"? Build a raw stream whose first two bytes form a valid zlib header.
    candidate = bytes([0x78, 0x01]) + b"\x01\x00\x00\xff\xff"  # not decodable as zlib body+adler
    assert outcome(candidate, "deflate")[0] == "corrupt"


def test_strict_zlib_disables_the_raw_fallback() -> None:
    """Covers: SG-R-CDC-03"""
    assert outcome(raw(DATA), "deflate", LOOSE, strict_zlib=True)[0] == "corrupt"
    assert outcome(zl(DATA), "deflate", LOOSE, strict_zlib=True) == ("ok", DATA)


def test_deflate_truncations_are_corrupt() -> None:
    """Covers: SG-R-CDC-06"""
    for stream in (zl(b"zlib truncation " * 50), raw(b"raw truncation " * 50)):
        for cut in range(len(stream)):
            assert outcome(stream[:cut], "deflate")[0] == "corrupt", cut


def test_invalid_deflate_blocks_are_corrupt() -> None:
    """Covers: SG-R-CDC-08"""
    for body in (b"\x07", b"\x06", b"\x01\x01\x00\x00\x00", b"\xff" * 30, b"\x05\xff\xff"):
        assert outcome(body, "deflate")[0] == "corrupt", body


def test_deflate_every_bit_flip_gives_ok_or_corrupt() -> None:
    """Covers: SG-I-05 SG-R-CDC-08"""
    for stream in (zl(b"flip the bits " * 15), raw(b"flip the bits " * 15)):
        for position in range(len(stream)):
            for bit in range(8):
                damaged = bytearray(stream)
                damaged[position] ^= 1 << bit
                assert outcome(bytes(damaged), "deflate")[0] in {"ok", "corrupt"}


def test_zlib_pending_output_is_not_lost_when_the_buffer_fills() -> None:
    """Covers: SG-R-RDR-01 SG-I-09"""
    payload = b"a" * 100_000 + b"b" * 100_000  # long matches span many small reads
    for stream in (zl(payload), raw(payload), gz(payload)):
        for size in (1, 7, 100, 4096):
            from spillgate import reader

            chain = reader(
                stream,
                "gzip" if stream is not None and stream[:2] == b"\x1f\x8b" else "deflate",
                LOOSE,
            )
            out = bytearray()
            while chunk := chain.read(size):
                out += chunk
                if len(out) > 3000 and size == 1:
                    break
            assert payload.startswith(bytes(out))
