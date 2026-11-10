# Contributing

## Run the checks

```
python -m pip install pytest hypothesis ruff mypy
python -m pytest                    # everything, including the large generated vectors (about 40 s)
python -m pytest -m "not large"     # without the GiB-scale vectors
python tools/spectrace.py           # every rule of the specification is named by a test or vector
SPILLGATE_NO_SKIPS=1 python -m pytest   # with brotli and zstandard installed: no vector may be skipped
python -m ruff check . && python -m ruff format --check .
python -m mypy
```

## Rules

- The specification comes first. Behavior that the spec does not describe is not added here: change `spec/SPEC.md` in the reference repository, add vectors there, then sync.
- `spectrace` counts a rule as covered when a test docstring or a vector names it; that is a checklist, not proof that the test asserts everything the rule says. Review the assertions too.
- Test first for every bug. A test names the rules it protects in its docstring (`Covers: SG-R-...`); `tools/spectrace.py` reads that line.
- Never weaken a test or a conformance vector to make code pass.
- `conformance/` and `spec/` are copies. Do not edit them here; update them from the reference repository and record the release in `conformance/SOURCE`.
- The core has no dependencies and starts no threads. Optional codecs are extras.
- Never call an unbounded standard-library API (`zlib.decompress`, `gzip.decompress`, `GzipFile`, `decompress()` without `max_length`, `flush()`); `tests/test_python_traps.py` fails if the source does.
- Code is read by people: short functions, a docstring that explains why, rule IDs where a rule applies.
