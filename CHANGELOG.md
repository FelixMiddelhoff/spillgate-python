# Changelog

Versions below 1.0 may still change the API.

## Unreleased (intended as 0.1.0)

First version. The Python implementation of the spillgate specification.

- `Limits` with a required `max_output`, ratio, layer, input limits; typed, sticky errors (one exception class per outcome kind).
- gzip, deflate and identity in the standard-library-only core; own gzip and zlib framing over `zlib.decompressobj` with `max_length` always greater than zero.
- Optional extras `spillgate[brotli]` (brotli >= 1.2.1) and `spillgate[zstd]` (zstandard >= 0.25.0) with window caps and bounded steps.
- Passes the full conformance corpus (354 vectors) of the reference implementation.
- Integration guide in `docs/how-to.md`.
