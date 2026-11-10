# spillgate (Python)

Decode untrusted compressed data in Python with mandatory limits. A decompression bomb
ends in a typed exception instead of exhausting memory.

```python
from spillgate import Limits, OutputLimitError, decode_all

try:
    body = decode_all(response_bytes, "gzip", Limits(max_output=8 * 2**20))
except OutputLimitError:
    ...  # refuse the response
```

- `Content-Encoding` chains: `gzip` (and `x-gzip`), `deflate`, `identity`; `br` and `zstd` as
  optional extras (see below).
- `max_output` is required. There is no unlimited setting.
- Every layer is limited, including the intermediate layers of a chain.
- Expansion ratio and chain length are limited by default.
- Unknown, malformed or too deep `Content-Encoding` headers are refused, never passed through.
- The core has no dependencies and starts no threads.

This is the Python implementation of the language-neutral
[spillgate specification](https://github.com/FelixMiddelhoff/spillgate/blob/main/spec/SPEC.md).
It passes the same conformance corpus as the Go reference implementation.

Python 3.11 or newer. **Integrating it into your service: [docs/how-to.md](docs/how-to.md).**

## Use

```python
from spillgate import Decoder, Limits

decoder = Decoder(Limits(max_output=8 * 2**20))  # build once, share between threads

with decoder.reader(resp.raw, resp.headers.get_all("Content-Encoding", [])) as body:
    for chunk in iter(lambda: body.read(65536), b""):
        handle(chunk)  # any exception: discard everything
```

`decode_all` / `Decoder.read_all` return the whole body or raise, never partial data.
`Decoder.reader` streams; bytes can arrive before a later error, so treat any
`SpillgateError` as failure of the whole body.

`source` is `bytes` or any object with `read(n)`. It is not closed by spillgate.

### Brotli and zstd

```
pip install "spillgate[brotli]"   # brotli >= 1.2.1
pip install "spillgate[zstd]"     # zstandard >= 0.25.0
```

```python
from spillgate import Decoder, Limits, br, zstd

decoder = Decoder(
    Limits(max_output=8 * 2**20),
    codecs={"br": br.codec(), "zstd": zstd.codec()},   # offer only what you installed
)
```

Both decoders are C libraries and are treated as untrusted: spillgate reads the window size
(brotli) or the whole frame structure (zstd) itself, refuses oversized windows as `memory_limit`
before anything is decoded, and gives the library bounded steps. The window costs memory per
request: up to 16 MiB for brotli and 8 MiB for zstd by default. Lower them with
`br.codec(max_window_bits=22)` and `zstd.codec(max_window_bytes=2**21)` when a server decodes
many requests at once. Older `brotli` versions are refused at import time: before 1.2.1 they
had no output limit and a memory-corruption bug in the decoder (CVE-2026-111497).
Always close readers (`with ... as body`) so the decoder state is released.

### Limits

| Field | Meaning | Default |
| --- | --- | --- |
| `max_output` | bytes one layer may produce, `1 .. 2**63-1` (required) | none |
| `max_layers` | longest chain, `1 .. 16` | 5 |
| `max_ratio` | output bytes per input byte the codec consumed | 1000 |
| `ratio_grace` | output below which the ratio is not checked | 64 KiB |
| `max_input` | cap on compressed bytes taken from the source | none |
| `disable_ratio_limit` | the one named opt-out of the ratio check | `False` |

`Limits` is immutable and validated when created. No number disables a limit: `0`, negative
values, floats, strings and `bool` are all refused with `InvalidLimitsError`.

### Errors

Every refusal is a `SpillgateError` with a `kind` (`spillgate.Kind`), a `layer` and a
`limit`; there is one subclass per kind: `OutputLimitError`, `RatioLimitError`,
`LayerLimitError`, `InputLimitError`, `MemoryLimitError`, `UnsupportedEncodingError`,
`MalformedEncodingError`, `CorruptError`, `InternalError`, `CanceledError`, `SourceError`,
`InvalidLimitsError`. Errors are sticky: after one, every later read raises the same error.
Error messages never contain more than 32 bytes of attacker data, and that data is escaped.

`cancel=callable` on `reader` / `read_all` is polled before every read and every 4 KiB of
input. It cannot interrupt one step inside the decoder; the limits bound the work there.

### Why not `zlib.decompress` or `gzip.GzipFile`?

Because they have no bound. The traps this library avoids: `decompressobj().decompress(data)`
without `max_length` (and `max_length=0`, which means *unlimited*), `flush()`, one-shot
`gzip.decompress`, and `GzipFile.read()` without a size. `tests/test_python_traps.py` scans the
source for them.

## What it does not cover

Archives (zip, tar), bounding the compressed input (use `max_input` or limit the request body
size), connection timeouts, encrypted content, and memory-safety bugs in the C libraries
behind `zlib` and the optional codecs beyond what the limits contain. See
[docs/memory.md](docs/memory.md) for the memory bounds.

## Specification and tests

`spec/SPEC.md` and `conformance/` are copies of the reference repository at the release named
in `conformance/SOURCE`. The suite runs all vectors (bombs, malformed streams, header attacks,
lying size fields), property tests, a scan for unbounded standard-library calls, and memory
measurements with `tracemalloc`. `python tools/spectrace.py` checks that every rule of the
specification is covered.

## License

MIT, see [LICENSE](LICENSE). Report vulnerabilities as described in [SECURITY.md](SECURITY.md).
