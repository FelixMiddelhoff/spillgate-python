"""Runs the shared conformance corpus (conformance/SCHEMA.md) against this implementation."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
from pathlib import Path
from typing import Any

import pytest

import corpus
from spillgate import Decoder, Kind, Limits, SpillgateError, br

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = json.loads((ROOT / "conformance" / "manifest.json").read_text(encoding="utf-8"))
VECTORS: list[dict[str, Any]] = MANIFEST["vectors"]


def optional_codecs() -> set[str]:
    """The optional codecs that can be used here. Vectors tagged needs-<codec> need them."""
    available = set()
    try:
        br.codec()
        available.add("br")
    except ImportError:
        pass
    return available


AVAILABLE_CODECS = optional_codecs()
STRICT = bool(os.environ.get("SPILLGATE_NO_SKIPS"))  # the full-codec run: a missing codec fails


def window_bits_within(limit: int) -> int:
    """The largest brotli window bits (10..24) whose window, 2**n - 16 bytes, fits ``limit``."""
    bits = br.MIN_WINDOW_BITS
    while bits < br.DEFAULT_MAX_WINDOW_BITS and 2 ** (bits + 1) - 16 <= limit:
        bits += 1
    return bits


def build_codecs(vector: dict[str, Any]) -> dict[str, Any]:
    cap = int(vector.get("options", {}).get("memory_cap", 0))
    codecs: dict[str, Any] = {}
    if "br" in needed_codecs(vector):
        codecs["br"] = br.codec(window_bits_within(cap)) if cap else br.codec()
    return codecs


# Every vector must give the same result for these read sizes (SG-R-RDR-01).
ALTERNATIVE_PATTERNS = [[1], [3], [4096], [-1], [1, 7, 4096, 1]]
ERROR_OUTCOMES = {k.value for k in Kind} - {"source_error", "canceled"}


def needed_codecs(vector: dict[str, Any]) -> list[str]:
    return [t[len("needs-") :] for t in vector.get("tags", []) if t.startswith("needs-")]


def build_input(vector: dict[str, Any]) -> bytes:
    spec = vector["input"]
    if "file" in spec:
        stream = (ROOT / "conformance" / spec["file"]).read_bytes()
    else:
        stream = corpus.generate(spec["generator"])
    assert corpus.sha256_hex(stream) == spec["sha256"], (
        f"{vector['id']}: the input differs from the manifest (generator or file drift)"
    )
    return stream


def build_limits(vector: dict[str, Any]) -> Limits:
    """Translate the manifest's limits. Limits above 2**53 are written as decimal strings."""
    raw = vector["limits"]
    args: dict[str, Any] = {}
    for key in ("max_output", "max_layers", "ratio_grace", "max_input"):
        if key in raw:
            args[key] = int(raw[key])
    if "max_ratio" in raw:
        if raw["max_ratio"] == "none":
            args["disable_ratio_limit"] = True
        else:
            args["max_ratio"] = int(raw["max_ratio"])
    return Limits(**args)


class SpySource:
    """A source that counts reads and bytes, to prove what was taken (SG-R-INP-02, HDR-09)."""

    def __init__(self, payload: bytes) -> None:
        self._inner = io.BytesIO(payload)
        self.reads = 0
        self.total = 0

    def read(self, n: int) -> bytes:
        chunk = self._inner.read(n)
        self.reads += 1
        self.total += len(chunk)
        return chunk


def outcome_of(error: BaseException | None) -> str:
    if error is None:
        return "ok"
    if isinstance(error, SpillgateError):
        return error.kind.value
    return f"other: {type(error).__name__}: {error}"


def read_with_pattern(
    chain: Any, pattern: list[int], max_output: int
) -> tuple[int, str, BaseException | None]:
    digest = hashlib.sha256()
    delivered = 0
    i = 0
    while True:
        size = pattern[i % len(pattern)]
        i += 1
        if size < 0:
            size = min(max_output, 32 * 2**20 - 1) + 1
        try:
            chunk = chain.read(size)
        except Exception as error:
            return delivered, digest.hexdigest(), error
        if not chunk:
            return delivered, digest.hexdigest(), None
        digest.update(chunk)
        delivered += len(chunk)


def skip_tiny(vector: dict[str, Any], pattern: list[int]) -> bool:
    """Leave out byte-at-a-time patterns for vectors that deliver many megabytes."""
    expect = vector["expect"]
    expected = (
        expect.get("length")
        or expect.get("delivered_exactly")
        or expect.get("delivered_at_most")
        or 0
    )
    return expected > 4 * 2**20 and any(0 <= size < 64 for size in pattern)


def run_pattern(vector: dict[str, Any], stream: bytes, pattern: list[int]) -> None:
    expect = vector["expect"]
    label = f"{vector['id']} read pattern {pattern}"
    source = SpySource(stream)
    options = vector.get("options", {})

    construction_error: BaseException | None = None
    chain = None
    limits = None
    try:
        limits = build_limits(vector)
        decoder = Decoder(
            limits, strict_zlib=bool(options.get("strict_zlib")), codecs=build_codecs(vector)
        )
        chain = decoder.reader(source, vector["encodings"])
    except SpillgateError as error:
        construction_error = error

    if construction_error is not None or expect.get("phase") == "construct":
        assert expect.get("phase") == "construct", (
            f"{label}: unexpected construction error {construction_error}"
        )
        assert construction_error is not None, (
            f"{label}: expected {expect['outcome']} at construction"
        )
        assert outcome_of(construction_error) == expect["outcome"], f"{label}: {construction_error}"
        assert source.reads == 0, f"{label}: the source was read before the construction error"
        return

    assert chain is not None and limits is not None
    with chain:
        delivered, digest, error = read_with_pattern(chain, pattern, limits.max_output)
        assert delivered <= limits.max_output, f"{label}: delivered {delivered} > max_output"
        check_outcome(vector, label, delivered, digest, error)
        # Sticky (SG-R-LAY-05): further reads return the same outcome and no data.
        for _ in range(3):
            try:
                again, failure = chain.read(16), None
            except Exception as exc:
                again, failure = b"", exc
            assert again == b"" and outcome_of(failure) == outcome_of(error), f"{label}: not sticky"
    if limits.max_input is not None:
        assert source.total <= limits.max_input + 1, (
            f"{label}: took {source.total} bytes from the source (SG-R-INP-02)"
        )


def check_outcome(
    vector: dict[str, Any], label: str, delivered: int, digest: str, error: BaseException | None
) -> None:
    expect = vector["expect"]
    got = outcome_of(error)
    assert got == expect["outcome"], (
        f"{label}: outcome {got!r}, want {expect['outcome']!r} (delivered {delivered})"
    )
    if expect["outcome"] == "ok":
        assert delivered == expect["length"], (
            f"{label}: delivered {delivered}, want {expect['length']}"
        )
        assert digest == expect["sha256"], f"{label}: wrong data"
        return
    assert expect["phase"] == "read", f"{label}: a read error but a construction error was expected"
    if "delivered_exactly" in expect:
        assert delivered == expect["delivered_exactly"], (
            f"{label}: delivered {delivered}, want exactly {expect['delivered_exactly']}"
        )
    if "delivered_at_most" in expect:
        assert delivered <= expect["delivered_at_most"], (
            f"{label}: delivered {delivered}, want at most {expect['delivered_at_most']}"
        )
    if expect.get("layer") and isinstance(error, SpillgateError):
        assert error.layer == expect["layer"], (
            f"{label}: error in layer {error.layer}, want {expect['layer']}"
        )


def vector_params() -> list[Any]:
    params = []
    for vector in VECTORS:
        marks = [pytest.mark.large] if vector["tier"] == "large" else []
        params.append(pytest.param(vector, id=vector["id"], marks=marks))
    return params


@pytest.mark.parametrize("vector", vector_params())
def test_vector(vector: dict[str, Any]) -> None:
    missing = [c for c in needed_codecs(vector) if c not in AVAILABLE_CODECS]
    if missing and STRICT:
        pytest.fail(f"needs the optional codec {missing[0]!r}, which is not installed")
    if missing:
        pytest.skip(f"needs the optional codec {missing[0]!r}")
    stream = build_input(vector)
    first = vector.get("read_pattern") or [4096]
    for pattern in [first, *ALTERNATIVE_PATTERNS]:
        if not skip_tiny(vector, pattern):
            run_pattern(vector, stream, pattern)


def test_manifest_is_well_formed() -> None:
    spec_text = (ROOT / "spec" / "SPEC.md").read_text(encoding="utf-8")
    pattern = r"(?m)^(?:- )?\*\*(SG-(?:R-[A-Z]+-[0-9]{2}|I-[0-9]{2}))\*\*"
    rules = set(re.findall(pattern, spec_text))
    assert MANIFEST["schema_version"] == 1
    assert len(VECTORS) >= 200
    seen: set[str] = set()
    for vector in VECTORS:
        assert re.fullmatch(r"SG-V-[A-Z]+-[0-9]{4}", vector["id"]), vector["id"]
        assert vector["id"] not in seen, f"duplicate {vector['id']}"
        seen.add(vector["id"])
        assert vector["description"] and vector["rules"]
        assert set(vector["rules"]) <= rules, f"{vector['id']} names an undefined rule"
        assert re.fullmatch(r"[0-9a-f]{64}", vector["input"]["sha256"])
        expect = vector["expect"]
        if expect["outcome"] != "ok":
            assert expect["outcome"] in ERROR_OUTCOMES
            assert expect["phase"] in {"construct", "read"}
