"""Limits (SPEC section 3) and Content-Encoding parsing (section 4)."""

from __future__ import annotations

import dataclasses

import pytest

from spillgate import (
    DEFAULT_MAX_LAYERS,
    DEFAULT_MAX_RATIO,
    DEFAULT_RATIO_GRACE,
    HARD_MAX_LAYERS,
    HARD_MAX_RATIO,
    Decoder,
    InvalidLimitsError,
    LayerLimitError,
    Limits,
    MalformedEncodingError,
    UnsupportedEncodingError,
)
from spillgate.errors import quote_untrusted
from spillgate.header import parse_content_encoding
from spillgate.limits import EffectiveLimits

INT64 = 2**63 - 1


# -- limits ------------------------------------------------------------------


def test_max_output_is_required() -> None:
    """Covers: SG-R-LIM-01 SG-R-API-01"""
    with pytest.raises(InvalidLimitsError):
        Limits()
    with pytest.raises(InvalidLimitsError):
        Limits(max_output=None)


@pytest.mark.parametrize(
    "bad", [0, -1, -INT64, INT64 + 1, 1.0, 1.5, "1", None, True, False, float("nan")]
)
def test_max_output_rejects_everything_but_a_positive_int64(bad: object) -> None:
    """Covers: SG-R-LIM-01 SG-R-LIM-02 SG-R-LIM-07"""
    with pytest.raises(InvalidLimitsError):
        Limits(max_output=bad)  # type: ignore[arg-type]


@pytest.mark.parametrize("good", [1, 2, 1 << 20, INT64])
def test_max_output_accepts_up_to_int64(good: int) -> None:
    """Covers: SG-R-LIM-02"""
    assert Limits(max_output=good).max_output == good


@pytest.mark.parametrize("bad", [0, -1, HARD_MAX_LAYERS + 1, 1.5, True, "5"])
def test_max_layers_outside_range_is_invalid(bad: object) -> None:
    """Covers: SG-R-LIM-03 SG-R-LIM-07"""
    with pytest.raises(InvalidLimitsError):
        Limits(max_output=1, max_layers=bad)  # type: ignore[arg-type]


@pytest.mark.parametrize("good", [1, 5, HARD_MAX_LAYERS])
def test_max_layers_edges(good: int) -> None:
    """Covers: SG-R-LIM-03"""
    assert Limits(max_output=1, max_layers=good).max_layers == good


@pytest.mark.parametrize("bad", [0, -1, HARD_MAX_RATIO + 1, 1.5, True, "1000", float("inf")])
def test_no_numeric_max_ratio_disables_the_check(bad: object) -> None:
    """Covers: SG-R-LIM-04 SG-R-LIM-07"""
    with pytest.raises(InvalidLimitsError):
        Limits(max_output=1, max_ratio=bad)  # type: ignore[arg-type]


def test_ratio_opt_out_is_distinct_and_cannot_be_combined() -> None:
    """Covers: SG-R-LIM-04 SG-R-RAT-04"""
    assert EffectiveLimits.of(Limits(max_output=1, disable_ratio_limit=True)).max_ratio == 0
    with pytest.raises(InvalidLimitsError):
        Limits(max_output=1, max_ratio=10, disable_ratio_limit=True)
    with pytest.raises(InvalidLimitsError):
        Limits(max_output=1, disable_ratio_limit=1)  # type: ignore[arg-type]


@pytest.mark.parametrize("bad", [-1, INT64 + 1, 1.5, True])
def test_ratio_grace_must_not_be_negative(bad: object) -> None:
    """Covers: SG-R-LIM-05"""
    with pytest.raises(InvalidLimitsError):
        Limits(max_output=1, ratio_grace=bad)  # type: ignore[arg-type]


def test_ratio_grace_zero_checks_from_the_first_byte() -> None:
    """Covers: SG-R-LIM-05 SG-R-RAT-01"""
    effective = EffectiveLimits.of(Limits(max_output=10, max_ratio=2, ratio_grace=0))
    assert effective.ratio_exceeded(produced=3, consumed=1)
    assert not effective.ratio_exceeded(produced=2, consumed=1)


@pytest.mark.parametrize("bad", [0, -1, INT64 + 1, 1.5, True])
def test_max_input_zero_does_not_mean_unlimited(bad: object) -> None:
    """Covers: SG-R-LIM-06"""
    with pytest.raises(InvalidLimitsError):
        Limits(max_output=1, max_input=bad)  # type: ignore[arg-type]


def test_defaults() -> None:
    """Covers: SG-R-LIM-03 SG-R-LIM-04 SG-R-LIM-05 SG-R-LIM-06"""
    effective = EffectiveLimits.of(Limits(max_output=7))
    assert (
        effective.max_layers,
        effective.max_ratio,
        effective.ratio_grace,
        effective.max_input,
    ) == (
        DEFAULT_MAX_LAYERS,
        DEFAULT_MAX_RATIO,
        DEFAULT_RATIO_GRACE,
        0,
    )
    assert (DEFAULT_MAX_LAYERS, DEFAULT_MAX_RATIO, DEFAULT_RATIO_GRACE) == (5, 1000, 65536)


def test_limits_are_captured_by_value() -> None:
    """Covers: SG-R-LIM-09"""
    limits = Limits(max_output=100)
    with pytest.raises(dataclasses.FrozenInstanceError):
        limits.max_output = 10**9  # type: ignore[misc]
    decoder = Decoder(limits)
    assert decoder._limits.max_output == 100


def test_ratio_boundary_is_exact() -> None:
    """Covers: SG-R-RAT-01"""
    e = EffectiveLimits.of(Limits(max_output=10**9, max_ratio=10, ratio_grace=100))
    assert not e.ratio_exceeded(100, 1)  # inside the grace
    assert not e.ratio_exceeded(10 * 50, 50)  # exactly at the ratio
    assert e.ratio_exceeded(10 * 50 + 1, 50)  # one byte over
    assert e.ratio_exceeded(101, 0)  # consumed counts as at least 1
    assert not e.ratio_exceeded(10 * 2**70, 2**70)  # no overflow with huge numbers


# -- header -------------------------------------------------------------------

ALL = {"gzip", "deflate", "br", "zstd"}


def parse(values: object, maxl: int = 5) -> list[str]:
    return parse_content_encoding(values, lambda n: n in ALL, maxl)  # type: ignore[arg-type]


def test_decoding_order_is_the_reverse_of_the_list() -> None:
    """Covers: SG-R-HDR-12"""
    assert parse("gzip, deflate") == ["deflate", "gzip"]
    assert parse(["gzip", "br"]) == ["br", "gzip"]


def test_equivalent_presentations_give_the_same_result() -> None:
    """Covers: SG-R-HDR-01 SG-R-HDR-03 SG-R-HDR-05 SG-R-HDR-14"""
    expected = ["br", "gzip"]
    for presentation in (
        "gzip,br",
        "GZIP, BR",
        ["gzip", "br"],
        [" gzip ", "\tbr\t"],
        ",,gzip,,br,,",
        ["", "gzip", " ", "br", ""],
        "gzip,\t,br",
    ):
        assert parse(presentation) == expected, presentation


def test_empty_header_is_the_empty_chain() -> None:
    """Covers: SG-R-HDR-01 SG-R-HDR-03 SG-R-HDR-10"""
    for value in ("", " ", ",", ", ,\t,", [], [""], ["", " "]):
        assert parse(value) == []
    assert parse("identity, identity") == []


def test_x_gzip_is_the_only_alias() -> None:
    """Covers: SG-R-HDR-07"""
    assert parse("x-gzip") == ["gzip"]
    assert parse("X-GZIP") == ["gzip"]
    for name in ("x-compress", "x-deflate", "x-br"):
        with pytest.raises(UnsupportedEncodingError):
            parse(name)


@pytest.mark.parametrize(
    "token", ["compress", "dcb", "dcz", "aes128gcm", "snappy", "deflate64", "bzip2"]
)
def test_unknown_but_well_formed_tokens_are_unsupported(token: str) -> None:
    """Covers: SG-R-HDR-08 SG-R-HDR-09 SG-I-06"""
    with pytest.raises(UnsupportedEncodingError):
        parse(f"gzip, {token}")


@pytest.mark.parametrize(
    "bad",
    [
        "gzip;q=1.0", "gzip;", '"gzip"', "gz ip", "gzip br", "gzip\n", "gzip\r\n", "\x00gzip",
        "gzip\x00", "gézip", "gzip​", "-gzip", ".gzip", "_gzip", "gzip/br", "gzip:",
        "g" * 33, "gzip ", " gzip", "gzip\x0b", "gzip\x0c", "gzip\x85", "\ud800",
        "gzip, br;x", "ﬁ", "ｇzip",
    ],
)  # fmt: skip
def test_malformed_elements_are_refused(bad: str) -> None:
    """Covers: SG-R-HDR-04 SG-R-HDR-05"""
    with pytest.raises(MalformedEncodingError):
        parse(bad)


def test_token_length_boundary() -> None:
    """Covers: SG-R-HDR-04"""
    assert parse_content_encoding("a" * 32, lambda n: True, 5) == ["a" * 32]
    with pytest.raises(MalformedEncodingError):
        parse_content_encoding("a" * 33, lambda n: True, 5)


def test_token_alphabet_edges() -> None:
    """Covers: SG-R-HDR-04"""
    for token in ("a", "z", "A", "Z", "0", "9", "a.b_c-d", "9z"):
        assert parse_content_encoding(token, lambda n: True, 5) == [token.lower()]
    for first in "`{@[/:.-_":
        with pytest.raises(MalformedEncodingError):
            parse_content_encoding(f"{first}x", lambda n: True, 5)


def test_header_length_cap_counts_bytes() -> None:
    """Covers: SG-R-HDR-02 SG-I-07"""
    ok = "gzip" + "," * 1020  # exactly 1024 bytes
    assert len(ok) == 1024 and parse(ok) == ["gzip"]
    with pytest.raises(MalformedEncodingError):
        parse(ok + ",")
    with pytest.raises(MalformedEncodingError):
        parse(["," * 512, "," * 512, "gzip"])  # the joining commas count
    with pytest.raises(MalformedEncodingError):
        parse("é" * 600)  # 600 characters, 1200 bytes


def test_evaluation_order_decides_the_outcome_class() -> None:
    """Covers: SG-R-HDR-02 SG-R-HDR-04 SG-R-HDR-06 SG-R-HDR-08 SG-R-HDR-11"""
    # length beats grammar
    with pytest.raises(MalformedEncodingError, match="long"):
        parse("x;" * 600)
    # grammar (left to right) beats element count
    with pytest.raises(MalformedEncodingError):
        parse(", ".join(["gzip"] * 20) + ", bad;")
    # element count beats support
    with pytest.raises(LayerLimitError):
        parse(", ".join(["compress"] * 17))
    # support beats layer count
    with pytest.raises(UnsupportedEncodingError):
        parse(", ".join(["gzip"] * 6 + ["compress"]))


def test_sixteen_elements_including_identity() -> None:
    """Covers: SG-R-HDR-06 SG-R-HDR-10 SG-I-07"""
    assert parse(", ".join(["identity"] * 16), maxl=1) == []
    with pytest.raises(LayerLimitError):
        parse(", ".join(["identity"] * 17), maxl=16)
    with pytest.raises(LayerLimitError):
        parse(", ".join(["gzip"] * 16 + ["identity"]), maxl=16)


def test_layer_count_ignores_identity() -> None:
    """Covers: SG-R-HDR-10 SG-R-HDR-11"""
    assert parse("identity, gzip, identity, gzip", maxl=2) == ["gzip", "gzip"]
    with pytest.raises(LayerLimitError):
        parse("gzip, gzip, gzip", maxl=2)


def test_support_is_checked_for_the_whole_list_before_any_read() -> None:
    """Covers: SG-R-HDR-09 SG-R-API-03 SG-I-06"""
    reads: list[int] = []

    class Source:
        def read(self, n: int) -> bytes:
            reads.append(n)
            return b""

    decoder = Decoder(Limits(max_output=10))
    with pytest.raises(UnsupportedEncodingError):
        decoder.reader(Source(), "gzip, compress")
    assert reads == []


def test_error_messages_quote_and_bound_attacker_data() -> None:
    """Covers: SG-R-HDR-13"""
    text = quote_untrusted("a\nb\r\x00\x1b[31m" + "x" * 100)
    assert "\n" not in text and "\r" not in text and "\x00" not in text and "\x1b" not in text
    assert text.count("x") <= 32
    assert quote_untrusted("é") == "'\\xe9'"
    for evil in ("evil\nSEVERITY=ALERT;", "x" * 5000, "\x1b]0;title\x07"):
        try:
            parse(evil)
        except MalformedEncodingError as error:
            assert "\n" not in str(error) and "\x1b" not in str(error)
            assert len(str(error)) < 300


def test_wrong_value_types_are_a_programming_error() -> None:
    """Covers: SG-R-API-03"""
    with pytest.raises(TypeError):
        parse([b"gzip"])
    with pytest.raises(TypeError):
        parse([None])
