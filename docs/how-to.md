# How to use spillgate in your Python service

This guide is for the developers who build the service: where to put spillgate, how to choose
the limits, how to wire it into HTTP clients, web frameworks and other data paths, and what to
do with the results. The rules behind the library are in
[spec/SPEC.md](../spec/SPEC.md); the API is documented in the docstrings.

## 1. What spillgate protects you from

Any code that decompresses bytes someone else controls can be made to allocate gigabytes from a
few kilobytes (a decompression bomb): by one layer, by a chain of encodings
(`Content-Encoding: gzip, gzip, gzip, ...`), by lying size fields, or by exotic codecs.
spillgate sits in front of the decompressor and turns each of those into a typed exception
with bounded memory. It does not replace limits on the compressed size, timeouts or
authentication.

The rule of thumb: **every place where your service turns compressed bytes into plain bytes must
go through spillgate**. Section 6 shows how to find those places.

Python makes this easy to get wrong. `zlib.decompress(data)`, `gzip.decompress(data)`,
`gzip.GzipFile(...).read()` without a size, `decompressobj().decompress(data)` without
`max_length`, and `max_length=0` (which means *unlimited*) all expand without a bound. HTTP
libraries decode for you by default (`requests`, `httpx`, `aiohttp`, `urllib3`), and several
of them add brotli and zstd to `Accept-Encoding` as soon as those packages are installed.

## 2. Choose the limits

```python
from spillgate import Limits

limits = Limits(
    max_output=8 * 2**20,  # required: bytes each layer may produce
    max_layers=3,  # default 5, range 1..16
    max_ratio=1000,  # default 1000
    ratio_grace=64 * 1024,  # default 64 KiB
    max_input=2 * 2**20,  # optional: compressed bytes taken from the source
)
```

| Field | What it bounds | Default |
| --- | --- | --- |
| `max_output` | bytes **each layer** may produce (required) | none |
| `max_layers` | non-identity encodings in one chain (1..16) | 5 |
| `max_ratio` | output bytes per input byte the decoder consumed | 1000 |
| `ratio_grace` | output size below which the ratio is not checked | 64 KiB |
| `max_input` | compressed bytes taken from the source | none |
| `disable_ratio_limit` | named opt-out of the ratio check | `False` |

`Limits` is immutable and validated when you create it: `max_output` missing, zero, negative,
a float, a string or a `bool` raises `InvalidLimitsError` at that moment.

### max_output: the memory you are willing to spend

Think of it as "the largest legitimate body this endpoint should ever see, after
decompression". Do not use one global number:

| Data path | Starting point |
| --- | --- |
| JSON API request bodies | 1 to 10 MiB |
| HTML or JSON fetched from third parties | 8 to 32 MiB |
| File upload processed in memory (`decode_all`) | the largest file you accept, and no more |
| File upload streamed to disk | your storage quota per object |
| Message queue payloads | the broker's maximum message size times a small factor |

Look at the 99.9th percentile of real decoded sizes in production and add headroom. A limit
100 times larger than anything legitimate only helps the attacker. `decode_all` and
`Decoder.read_all` hold the whole body in memory, so `max_output` is also their peak memory per
call; multiply by your concurrency (threads, workers, async tasks).

### max_ratio and ratio_grace

The ratio is checked per layer and end to end. The default of 1000 stops the classic bombs
(zeros compress to about 1030:1 in DEFLATE at best) while ordinary data stays far below it
(typical JSON about 350:1 at the extreme). Raise it only if a measured, legitimate data type
needs it. Brotli and zstd can reach much higher ratios on sparse data, so an endpoint that
accepts, for example, large sparse arrays or logs full of repeated lines may need a higher
`max_ratio`. Prefer raising it for one endpoint over `disable_ratio_limit=True`, which leaves
only `max_output` between you and a bomb. Leave `ratio_grace` alone; it keeps tiny messages
from being refused.

### max_layers

Real traffic uses one layer, rarely two. The default of 5 is generous; use 2 or 3 for public
endpoints. Chains of more than 16 elements are refused whatever you set.

### max_input

If the compressed size is not already bounded by your web server, framework or broker, add
`max_input`. spillgate bounds the output; it is not a substitute for limiting how many bytes
you accept. Do both.

## 3. Wire it in

Create one `Decoder` at start-up and share it. It is immutable and safe to use from many
threads; the readers it returns are not.

```python
from spillgate import Decoder, Limits

DECODER = Decoder(Limits(max_output=8 * 2**20, max_layers=3, max_input=2 * 2**20))
```

Constructing the decoder validates the limits and reads no data. Let a misconfiguration crash
at start-up, not on the first request.

`source` is `bytes` or any object with `read(n)` (a file, `io.BytesIO`, a socket file, a
`werkzeug` stream). spillgate never closes it. The encodings are the `Content-Encoding` values
as received: one string, or a list of strings when the header was sent several times.

### 3.1 `requests`

`requests` and `urllib3` decode `Content-Encoding` for you unless you read the raw stream. Set
`Accept-Encoding` yourself (so you only ask for what the decoder supports), stream the
response, and read the still-compressed bytes with `decode_content=False`:

```python
import requests
from spillgate import Decoder, Limits, SpillgateError

DECODER = Decoder(Limits(max_output=8 * 2**20))


class RawBody:
    """The still-compressed bytes of a streamed `requests` response."""

    def __init__(self, response):
        self._raw = response.raw

    def read(self, n):
        return self._raw.read(n, decode_content=False)


def fetch(url):
    headers = {"Accept-Encoding": "gzip, deflate"}
    with requests.get(url, stream=True, headers=headers, timeout=10) as resp:
        resp.raise_for_status()
        encodings = resp.raw.headers.getlist("Content-Encoding")
        with DECODER.reader(RawBody(resp), encodings) as body:
            return body.readall()  # SpillgateError on any refusal
```

Never call `resp.content`, `resp.text` or `resp.json()` on a response whose body has not gone
through spillgate: they decode with no limit.

### 3.2 `httpx` (sync)

`iter_raw()` yields the still-compressed bytes. A small adapter turns the iterator into the
`read(n)` that spillgate expects:

```python
import httpx


class IterSource:
    """Adapts an iterator of byte chunks to read(n)."""

    def __init__(self, chunks):
        self._it, self._buf = iter(chunks), b""

    def read(self, n):
        while not self._buf:
            try:
                self._buf = next(self._it)
            except StopIteration:
                return b""
        out, self._buf = self._buf[:n], self._buf[n:]
        return out


def fetch(url):
    with httpx.Client(headers={"Accept-Encoding": "gzip, deflate"}) as client:
        with client.stream("GET", url) as resp:
            encodings = resp.headers.get_list("content-encoding")
            with DECODER.reader(IterSource(resp.iter_raw()), encodings) as body:
                return body.readall()
```

### 3.3 `aiohttp` and other async code

The spillgate reader is synchronous. In async code, bound the compressed size first (it is
small and you read it anyway), then decode in a worker thread so the event loop is not
blocked:

```python
import asyncio
import aiohttp

MAX_COMPRESSED = 4 * 2**20


async def fetch(url):
    # auto_decompress=False: aiohttp must not decode before spillgate does.
    async with aiohttp.ClientSession(
        auto_decompress=False, headers={"Accept-Encoding": "gzip, deflate"}
    ) as session:
        async with session.get(url) as resp:
            encodings = resp.headers.getall("Content-Encoding", [])
            compressed = await resp.content.read(MAX_COMPRESSED + 1)
            if len(compressed) > MAX_COMPRESSED:
                raise ValueError("compressed body too large")
            return await asyncio.to_thread(DECODER.read_all, compressed, encodings)
```

The same pattern fits Starlette or FastAPI request bodies: `compressed = await request.body()`
(with a body-size limit in your server or middleware), then `await asyncio.to_thread(...)`.
Starlette does not decode request bodies by itself.

### 3.4 Web frameworks: request bodies

Flask (Werkzeug does not decode `Content-Encoding` on requests):

```python
from flask import Flask, request
from spillgate import SpillgateError

app = Flask(__name__)

STATUS = {
    "output_limit": 413,
    "ratio_limit": 413,
    "layer_limit": 413,
    "input_limit": 413,
    "memory_limit": 413,
    "unsupported_encoding": 415,
}


@app.post("/ingest")
def ingest():
    try:
        data = DECODER.read_all(request.stream, request.headers.getlist("Content-Encoding"))
    except SpillgateError as error:
        log_refusal(error)
        return {"error": error.kind.value}, STATUS.get(error.kind.value, 400)
    return process(data)
```

Django: read `request` as a file (`request.read`) or `request.body` after a
`DATA_UPLOAD_MAX_MEMORY_SIZE` check, and pass `request.META.get("HTTP_CONTENT_ENCODING", "")`.
Whatever the framework, set a limit on the compressed request size in the web server or
framework as well.

### 3.5 Any other source: files, S3 objects, queues

```python
with open(path, "rb") as f, DECODER.reader(f, "gzip") as body:
    with open(tmp_path, "wb") as out:
        for chunk in iter(lambda: body.read(65536), b""):
            out.write(chunk)
os.replace(tmp_path, final_path)  # only reached if no exception came
```

For content stored with a known encoding pass it yourself (`"gzip"`). Pass `""` or `()` for
plain data that should still be bounded.

### 3.6 Whole body versus streaming

- `decode_all` / `Decoder.read_all`: simplest. You get the complete body or an exception and
  **no data**. Peak memory is the decoded size, at most `max_output`.
- `Decoder.reader`: streaming, a normal binary file object (`read`, `readinto`, `readall`,
  context manager). **Bytes can be delivered before a later exception.** Whatever you did with
  them (wrote to a file, fed a parser, stored in a database) must be undone when an exception
  comes. Write to a temporary file and move it on success; never commit a partial body.

A single `read(n)` returns at most 64 KiB whatever `n` is, so a huge buffer size does not
allocate a huge buffer. Loop until `b""`.

### 3.7 Cancellation

`Decoder.reader(..., cancel=callable)` polls the callable before every read and every 4 KiB of
input; when it returns true the reader raises `CanceledError`, sticky. It cannot interrupt
one step inside the decoder (the limits bound that), and it does not interrupt a blocking
`read` of your source; use socket timeouts for that.

### 3.8 Brotli and zstd

Install the extras and register the codecs; offer in `Accept-Encoding` only what you
registered:

```python
from spillgate import Decoder, Limits, br, zstd

DECODER = Decoder(
    Limits(max_output=8 * 2**20),
    codecs={"br": br.codec(max_window_bits=22), "zstd": zstd.codec(max_window_bytes=2**22)},
)
HEADERS = {"Accept-Encoding": "gzip, deflate, br, zstd"}
```

A stream that asks for a larger window than the cap fails with `MemoryLimitError` before a
byte is decoded. The window is memory per in-flight request (see `docs/memory.md`): lower the
caps on busy servers. Always close readers so the C decoder state is released at once.

Zstd has one more cost the output limits cannot see: frames and blocks that produce no output
(empty frames, skippable frames) take about a second of CPU per MB of input. Always set
`max_input` (or a body size limit) for endpoints that accept zstd.

### 3.9 Your own codec

Register it on the decoder: `Decoder(limits, codecs={"snappy": MyCodec()})`. It runs behind the
same limiter, so even a careless codec cannot exceed `max_output`. See `spillgate.Codec` for
the contract. Names must be lower-case tokens and must not reuse the built-in names.

## 4. Handle the results

Every refusal is a `SpillgateError` with a `kind` (`spillgate.Kind`), the `layer` that failed
(1 reads from the source) and the `limit` that was exceeded. There is one subclass per kind, so
you can catch the specific one or the base class.

```python
import logging
from spillgate import Kind, SpillgateError

log = logging.getLogger("ingest")


def log_refusal(error: SpillgateError) -> None:
    if error.kind in (Kind.INTERNAL, Kind.MEMORY_LIMIT):
        log.error("decoder problem: %s", error.kind.value, extra={"layer": error.layer})
    elif error.kind in (Kind.SOURCE_ERROR, Kind.CANCELED):
        log.debug("decode interrupted: %s", error.kind.value)  # not an attack signal
    else:
        log.warning("refused: %s layer=%s limit=%s", error.kind.value, error.layer, error.limit)
    REFUSALS.labels(kind=error.kind.value).inc()  # your metrics
```

### What each outcome means and what to do

| Kind | Meaning | Server answers | Client side | Log / metric |
| --- | --- | --- | --- | --- |
| `output_limit` | the data decodes to more than `max_output` | 413 | treat the response as failed, do not retry | warn, count; a spike is an attack or a limit that is too low |
| `ratio_limit` | expansion over `max_ratio` | 413 | failed, do not retry | warn, count; check if a legitimate data type needs a higher ratio |
| `layer_limit` | more layers or elements than allowed | 413 (or 400) | failed, do not retry | warn, count |
| `input_limit` | more compressed bytes than `max_input` | 413 | failed, do not retry | warn, count |
| `unsupported_encoding` | a valid token the decoder cannot handle (`compress`, `dcz`, `aes128gcm`, ...) | 415 | failed; nothing was decoded | info; shows clients using something you do not offer |
| `malformed_encoding` | the header breaks the strict grammar | 400 | failed | info, bounded text only |
| `corrupt` | the stream is invalid, truncated or has trailing data | 400 | may retry once if the connection was cut; a repeat is a bad server | info |
| `memory_limit` | a brotli or zstd stream needs a larger window than the cap | 413 | failed, do not retry | warn; check the cap if legitimate traffic hits it |
| `source_error` | your source (network, disk) raised; the original exception is `__cause__` | 5xx or 400 | retry by your usual policy | the cause is in `__cause__` |
| `canceled` | your `cancel` callable returned true | no response needed | no retry by itself | debug |
| `internal` | a codec or source broke its contract | 500 | failed | **error and alert**: please report it (see `SECURITY.md`) |
| `invalid_limits` | bad configuration | - | - | raised when you create `Limits`, never during traffic |

A closed reader raises `ClosedError` (a `ValueError`); a bad extension-codec name raises
`InvalidOptionError`. Both are programming errors, not data errors.

General rules:

1. **Any exception means the whole body is unusable**, including the bytes you already received.
2. **Never retry a limit error.** The same input gives the same result and costs the same work.
3. **Catch `SpillgateError`, not `Exception`.** Anything else that escapes is a bug in your code
   or in a codec you registered; do not hide it behind a blanket handler.
4. **Do not echo error details to the caller.** Return a fixed message and the status code.
   The library's own messages contain at most 32 bytes of attacker data, quoted and escaped,
   but your logs and responses are your decision; log the kind, layer, limit and a request ID,
   not the body.
5. **Treat repeated limit errors from one client as abuse**: rate-limit or block like other
   malformed input. One `ratio_limit` can be an accident; thousands from one address are not.
6. **Alert on `internal` and `memory_limit`** rather than on the limit errors you expect.

### Tuning after launch

Run for a few days with the limits at their intended values and count refusals per endpoint. If
legitimate traffic is refused, raise the specific limit for that endpoint by the smallest
amount that fixes it and write down why. Do not switch limits off to make an alert go away.

## 5. Test your integration

1. **Build a bomb and see it refused.** 50 MB of zeros compress to about 50 KB:

   ```python
   import gzip


   def gzip_bomb(size: int) -> bytes:
       return gzip.compress(bytes(size), compresslevel=9)


   def test_endpoint_refuses_bombs(client):
       resp = client.post("/ingest", data=gzip_bomb(50_000_000), headers={"Content-Encoding": "gzip"})
       assert resp.status_code == 413
   ```

   For larger or exotic cases use the generated inputs of the conformance corpus
   ([conformance/](../conformance), built by `tests/corpus.py`).
2. **Test every ingress.** Each endpoint and background consumer gets a bomb test, a test with
   `Content-Encoding: gzip, gzip, gzip, gzip, gzip, gzip, gzip`, one with an unknown encoding
   (`Content-Encoding: compress`) and one with a truncated body.
3. **Check memory.** Run the bomb test under `tracemalloc` and assert on the peak, or in a
   subprocess with `resource.setrlimit(RLIMIT_AS, ...)` on Linux.
4. **Test the partial-data rule.** Make the downstream step fail midway and check that nothing
   from the failed body is committed.

## 6. Find and fix the places that decompress today

Search your code and your dependencies:

```
grep -rnE "zlib\.(decompress|decompressobj)|gzip\.(decompress|GzipFile|open)|brotli\.decompress|zstandard|\.decompress\(|decode_content|\.content\b|\.json\(\)" src/
```

Then look at what decodes without you asking:

- HTTP clients: `requests`/`urllib3` (and `.content`, `.text`, `.json()`), `httpx`
  (`.read()`, `.text`, `.json()`, `iter_bytes`), `aiohttp` (`auto_decompress` defaults to
  true), SDKs that wrap them (cloud SDKs, API clients). Pass them a session or transport that
  uses the pattern from section 3, or read the raw body yourself.
- Web servers and frameworks: gzip request middleware, reverse proxies that decompress for
  you, gRPC (`compression=`), message-queue clients with automatic decompression.
- Object storage and file helpers: `smart_open`, `fsspec` with compression, `pandas.read_csv`
  with `compression="infer"`, `tarfile`/`zipfile` (archives are out of scope for spillgate;
  bound them separately).

For each, replace the decoder with spillgate or make sure it never sees unbounded data.

## 7. Pitfalls

- **Decoding in two places.** If a proxy, middleware or client library decodes before
  spillgate, spillgate only bounds the plain data and the bomb has already been expanded.
  Make sure spillgate is the first decoder in the path.
- **Reading the body twice.** After an exception the reader is spent. Do not fall back to
  "just read it plainly".
- **A huge `max_output` "to be safe".** It makes the guard useless. Size it from data.
- **`disable_ratio_limit=True` as a first reaction.** See the tuning section.
- **Unbounded concurrency.** Each in-flight `decode_all` may hold up to `max_output` bytes;
  size worker pools accordingly.
- **Blocking the event loop.** The reader is synchronous. Use `asyncio.to_thread` for bodies
  of more than a few hundred KiB.
- **Treating `identity` as safe.** An unencoded body is bounded as well; that is deliberate.
- **Catching `Exception` around the decoder.** It hides `internal` errors and real bugs.

## 8. Checklist before you ship

- [ ] One shared `Decoder`, created at start-up, limits chosen per data path from real sizes.
- [ ] Every ingress (HTTP client, web endpoint, queue consumer, file or object reader) goes through spillgate; no other decoder runs before it.
- [ ] HTTP libraries are told not to decode (`decode_content=False`, `iter_raw`, `auto_decompress=False`), and `Accept-Encoding` is set explicitly (no `br`/`zstd` unless you registered them).
- [ ] The compressed size is bounded separately (server body limit, `max_input`).
- [ ] Streaming consumers discard or roll back partial data on any exception.
- [ ] Limit errors map to 413, unsupported encodings to 415, malformed or corrupt data to 400.
- [ ] Metrics per `Kind`; alerts on `internal` and `memory_limit`; refusals visible per endpoint.
- [ ] No retries of limit errors; no echoing of attacker-supplied text.
- [ ] Bomb, deep-chain, unknown-encoding and truncation tests exist for every ingress and run in CI.
- [ ] You know who gets the report if `internal` appears (see [SECURITY.md](../SECURITY.md)).
