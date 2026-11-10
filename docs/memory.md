# Memory bounds (SG-R-MEM-03)

spillgate never sizes an allocation from a value in the data (declared sizes, header
fields, lengths in the stream). What it does allocate is bounded by constants:

| Part | Bound |
| --- | --- |
| Input meter buffer, per layer | 4 KiB |
| One decode step, per layer | 256 KiB (`MAX_STEP`), whatever buffer size the caller reads with |
| zlib decoder state (gzip, deflate), per layer | about 40 KiB (32 KiB window plus tables) |
| gzip header fields | read in pieces of at most 512 bytes; FNAME and FCOMMENT are refused above 512 bytes |
| Whole-body functions (`decode_all`, `read_all`) | grow with the bytes actually produced; never preallocated from `max_output` |

Per layer that is well under 1 MiB; a chain of 16 layers stays under 16 MiB plus the
output. The tests (`tests/test_python_traps.py`) measure the peak with `tracemalloc`:
decoding a 200 MB bomb against a 100 MB limit peaks below 4 MiB, and reading one byte at
a time costs constant memory.

The optional brotli and zstd codecs add their decoder window, which is bounded by the
window cap of the codec, not by `max_output`.
