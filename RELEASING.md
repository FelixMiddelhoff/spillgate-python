# Releasing to PyPI

Releases use PyPI **Trusted Publishing**: the workflow `.github/workflows/release.yml` proves its
identity to PyPI with a short-lived OpenID Connect token. No password or API token exists in the
repository, in GitHub secrets or on a developer machine.

## One-time setup (maintainer)

1. **GitHub environment.** Repository **Settings → Environments → New environment**, name `pypi`.
   Add yourself under *Required reviewers* so that every publish needs an explicit approval.
   Optionally restrict *Deployment branches and tags* to the pattern `v*`.
2. **PyPI pending publisher.** On <https://pypi.org/manage/account/publishing/> add a *pending
   publisher* (this creates the project name `spillgate` on the first publish):
   - PyPI project name: `spillgate`
   - Owner: `FelixMiddelhoff`
   - Repository name: `spillgate-python`
   - Workflow name: `release.yml`
   - Environment name: `pypi`
3. Turn on two-factor authentication for the PyPI account and keep the recovery codes safe.

The PyPI name is reserved only when the first release is published, so do step 2 and the first
release close together.

## Each release

1. Update `CHANGELOG.md` and set `version` in `pyproject.toml` (for example `0.1.0`). Commit to `main` and wait for a green CI.
2. Tag exactly that version and push the tag:
   ```
   git tag -a v0.1.0 -m "v0.1.0"
   git push origin v0.1.0
   ```
3. The `release` workflow builds once, checks that the tag equals the version, runs the whole suite
   with brotli and zstd installed and nothing skipped, checks the wheel in a clean environment, and
   waits for your approval in the `pypi` environment. After the approval it publishes the same
   files, with build attestations, to PyPI.
4. Check from a clean directory:
   ```
   python -m venv t && t/bin/python -m pip install "spillgate[brotli,zstd]==0.1.0"
   ```
5. Create the GitHub release from the tag with the changelog text.

## Never

Never delete or move a published tag, and never re-upload a version: PyPI refuses it. A wrong
release is yanked on PyPI and fixed with the next patch version. Versions at or above 1.0 need
separate, explicit consent.
