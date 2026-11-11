# Changelog

Versions below 1.0 may still change the API.

## Unreleased

- `max_input` (SG-R-INP-01, corpus 0.2.0): taking byte `max_input + 1` is `input_limit`, looking at it is not. Trailing data after a complete stream whose size equals `max_input` is now `corrupt` (it was `input_limit`); a stream that needs the next byte is `input_limit`; the take count is checked at the end of every codec step. Identity keeps the strict behaviour. Known edge: a probe byte that could start another gzip member or zstd frame is taken (`input_limit` for `max_input` = stream size).
- Conformance corpus 0.2.0 (370 vectors, adds SG-V-BND-0041..0057).

## 0.1.0 - 2026-11-11

First version. The Python implementation of the spillgate specification.

- `Limits` with a required `max_output`, ratio, layer, input limits; typed, sticky errors (one exception class per outcome kind).
- gzip, deflate and identity in the standard-library-only core; own gzip and zlib framing over `zlib.decompressobj` with `max_length` always greater than zero.
- Optional extras `spillgate[brotli]` (brotli >= 1.2.1) and `spillgate[zstd]` (zstandard >= 0.25.0) with window caps and bounded steps.
- Passes the full conformance corpus (354 vectors) of the reference implementation.
- Integration guide in `docs/how-to.md`.
