# Security policy

## Reporting a vulnerability

Use GitHub private vulnerability reporting: the repository's **Security** tab,
**Report a vulnerability**. Please do not open a public issue for a bypass.

A bypass is any input that makes the library deliver more than the configured limits, pass an
unsupported or malformed encoding through, raise an exception that is not a `SpillgateError`,
or use memory that grows with the output instead of staying bounded.

What to expect:

- acknowledgment within 3 business days
- coordinated disclosure, up to 90 days from the report
- credit in the advisory if you want it
- no bug bounty

Every fixed bypass becomes a permanent conformance vector in the reference repository
([spillgate](https://github.com/FelixMiddelhoff/spillgate)), so all language implementations
get it.

## Supported versions

The latest release only.

## Scope

The limits, header parsing, gzip and deflate framing and the reader contract are in scope.
Memory-safety bugs inside CPython's `zlib` or third-party codec libraries are reported
upstream; tell us as well if the limiter should have contained them.
