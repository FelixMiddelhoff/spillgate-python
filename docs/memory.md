# Memory bounds (SG-R-MEM-03)

spillgate never sizes an allocation from a value in the data (declared sizes, header
fields, lengths in the stream). What it does allocate is bounded by constants:

| Part | Bound |
| --- | --- |
| Input meter buffer, per layer | 4 KiB |
| One decode step, per layer | 64 KiB (`MAX_STEP`), whatever buffer size the caller reads with |
| zlib decoder state (gzip, deflate), per layer | about 40 KiB (32 KiB window plus tables) |
| gzip header fields | read in pieces of at most 512 bytes; FNAME and FCOMMENT are refused above 512 bytes |
| Whole-body functions (`decode_all`, `read_all`) | grow with the bytes actually produced; never preallocated from `max_output` |

Per layer that is well under 1 MiB; a chain of 16 layers stays under 16 MiB plus the
output. The tests (`tests/test_python_traps.py`) measure the peak with `tracemalloc`:
decoding a 200 MB bomb against a 100 MB limit peaks below 4 MiB, and reading one byte at
a time costs constant memory.

The optional codecs add their decoder window, which is bounded by the window cap of the codec,
not by `max_output`:

| Codec | Step | Window (default cap) | Measured peak, 1 GiB bomb at the largest window (Windows, CPython 3.13) |
| --- | --- | --- | --- |
| brotli | about 32 KiB output per library call | 2**24 - 16 bytes (16 MiB) | about +18 MiB over the idle process |
| zstd | one block, at most 128 KiB in and 128 KiB out | 8 MiB | about +11 MiB over the idle process |

The C libraries allocate their windows outside Python, so `tracemalloc` does not see them;
the figures above are the peak working set of a process that decoded the bomb five times and
closed each reader. Lower the caps for servers that decode many requests at once.
