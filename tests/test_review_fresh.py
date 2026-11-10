"""Regression tests for the second security review: fresh() and sticky errors."""

import gc
import gzip
import weakref

from spillgate import CorruptError, Decoder, Limits, SpillgateError


class OddError(CorruptError):
    def __init__(self, code: int, detail: str) -> None:  # different signature than the base
        super().__init__(f"code {code}")


class _Codec:
    def new_reader(self, source):
        return _Reader()


class _Reader:
    def read(self, n):
        raise OddError(5, "x")


def test_codec_raising_spillgate_subclass_with_custom_init_stays_contained() -> None:
    """Covers: SG-I-05 SG-I-10 SG-R-CDC-08"""
    dec = Decoder(Limits(max_output=1000), codecs={"x": _Codec()})
    chain = dec.reader(b"abc", "x")
    for _ in range(2):
        try:
            chain.read(10)
        except SpillgateError:
            pass
        except Exception as error:
            raise AssertionError(f"escaped containment as {type(error).__name__}") from error
        else:
            raise AssertionError("no error")


def test_codec_origin_error_does_not_leave_a_reference_cycle() -> None:
    """Covers: SG-I-05 SG-I-10 SG-R-CDC-08"""
    bad = bytearray(gzip.compress(b"x" * 1000))
    bad[-5] ^= 1
    gc.disable()
    try:
        chain = Decoder(Limits(max_output=1 << 20)).reader(bytes(bad), "gzip")
        probe = weakref.ref(chain)
        try:
            while chain.read(100):
                pass
        except SpillgateError:
            pass
        del chain
        assert probe() is None
    finally:
        gc.enable()
