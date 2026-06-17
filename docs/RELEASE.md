# Release Guide

How to cut a release of secrets-scanner. **Read this whole file before tagging.**
A release is CI-only and irreversible (crates.io and npm publishes cannot be
re-published under the same version), so the cost of getting it wrong is high.

## TL;DR checklist

1. Pick `vX.Y.Z`. Bump **every** version location (see [Version locations](#version-locations)).
2. Update `CHANGELOG.md` (move `Unreleased` items under a new `vX.Y.Z` section).
3. Run the [pre-release gate](#pre-release-gate) locally (incl. dry-runs).
4. **Validate the npm matrix** with the `publish.yml` `workflow_dispatch` dry-run
   on a branch (see [npm / node binding](#npm--node-binding)). Do not skip this.
5. Commit the version bump to `main`, push.
6. Tag and push the tag. This fires **both** release workflows.
7. [Watch CI](#watch--verify) to completion and verify each published artifact.

## What a tag publishes

Pushing a tag matching `v[0-9]*` triggers **two** workflows in parallel:

| Workflow | Publishes | Key secrets |
|---|---|---|
| `.github/workflows/release.yml` | crates.io crate, 4 prebuilt binaries + GitHub Release, Docker Hub image, Homebrew cask | `CARGO_REGISTRY_TOKEN`, `DOCKERHUB_USERNAME`/`DOCKERHUB_TOKEN`, `HOMEBREW_TAP_TOKEN` |
| `.github/workflows/publish.yml` | npm package `@whit3rabbit/rsecrets-scanner` (5 per-platform packages + thin main) | `NPM_TOKEN` |

Both fire on the **same tag**, so a release is only "done" when both are green.
Pre-conditions:
- The GitHub repo must be **public** for normal Homebrew installs to fetch
  release assets (a private repo can still publish crates.io + GitHub Release).
- `release.yml` updates `whit3rabbit/homebrew-tap` only when the repo is public.

## Version locations

`vX.Y.Z` must be applied to **all** of these or CI fails / a publish is rejected:

| File | Field | Notes |
|---|---|---|
| `Cargo.toml` | `[package].version` | `release.yml` `check-version` asserts `tag == vCargo.toml`. |
| `Dockerfile` | `LABEL version="…"` | `release.yml` `check-version` asserts `tag == vDockerfile`. |
| `Cargo.lock` | `secrets_scanner` package entry | Refresh with `cargo check` (do not hand-edit if avoidable). |
| `bindings/node/package.json` | `version` | A stale node version makes npm **republish an existing version and fail**. |
| `bindings/node/Cargo.toml` | `version` | Keep in lockstep (crate is `publish = false`, but keep consistent). |
| `bindings/node/package-lock.json` | root `version` (two places) | npm here may not auto-sync it; verify by reading the file. |
| `CHANGELOG.md` | new `## vX.Y.Z (DATE)` section | Use an absolute date. |

The node binding is a separate crate and a separate npm package; the root
`make ci` / `cargo` commands do **not** cover it. It is easy to forget — the
0.2.0 npm publish failed precisely because the node version was stale.

## Pre-release gate

Run from a clean working tree, ideally from the prospective release commit:

```bash
make ci                              # fmt, clippy, tests, rule drift, full build
cargo publish --dry-run --locked     # crates.io packaging (needs a CLEAN commit; commit first)

# Node binding (NOT covered by make ci) — run inside bindings/node/:
npm install
npm run build && npm run typecheck && npm test
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
```

`cargo publish --dry-run` refuses a dirty tree; commit the version bump first,
then dry-run (use `--allow-dirty` only for a throwaway check).

## npm / node binding

The node binding publishes as a single **"fat" package**
(`@whit3rabbit/rsecrets-scanner`) bundling **all** platform binaries
(`secrets_scanner_core.<platform>-<arch>[-abi].node`). `publish.yml` builds each
target on a native runner, uploads each `.node`, then the publish job downloads
them all into the package root and runs ONE `npm publish`. `lib/loader.js` picks
the matching binary at runtime. One npm package = one trusted publisher, no
per-platform packages. See `bindings/node/CLAUDE.md` for internals.

**Auth: npm trusted publishing (OIDC), no token.** Configure a trusted publisher
on npmjs.com for `@whit3rabbit/rsecrets-scanner` (GitHub Actions, repo
`whit3rabbit/secrets-scanner`, workflow `publish.yml`). The job needs
`id-token: write` (set) and npm >= 11.5.1 — `setup-node` pins node 24 and the job
runs `npm install -g npm@latest`. Provenance is automatic (public repo + public
package). Do **not** set `NODE_AUTH_TOKEN`. **Renaming `publish.yml` breaks the
trusted-publisher config.**

Gotchas (each one broke a publish at least once):

- **Run the dry-run first.** `publish.yml`'s `workflow_dispatch` is fail-safe:
  any dispatch is a dry run unless it is a tag push (or `dry-run=false`). Confirm
  all 5 targets build before tagging:
  ```bash
  gh workflow run publish.yml --ref <branch>   # no inputs; defaults to dry-run
  ```
  The dry-run does **not** exercise the real OIDC publish (it skips `npm
  publish`), so a trusted-publisher/registry problem only surfaces on the real
  run. Also: `workflow_dispatch` inputs are read from the **default branch**, so
  a new input on a feature branch isn't accepted via `-f` until it's on `main`.
- **`os`/`cpu` must list every shipped platform** in `package.json`
  (darwin/linux/win32, x64/arm64), or npm rejects the install elsewhere
  (`EBADPLATFORM`).
- **`x86_64-apple-darwin` is cross-built on the arm64 mac** (macos-14); its
  self-test is skipped (an x86_64 binary can't load in arm64 node). Avoids the
  scarce macos-13 Intel runner.
- **`--ignore-scripts` on publish** skips the host-only `prepack` rebuild (the
  publish runner has no Rust), so only the downloaded matrix `.node` files ship.

## Updating GitHub Actions versions

Keep the pinned `uses:` versions current across **all** workflows (`ci.yml`,
`release.yml`, `publish.yml`, `secrets-scan.yml`) — e.g. `actions/checkout`,
`actions/setup-node`, `actions/upload-artifact`, `actions/download-artifact`,
`softprops/action-gh-release`, `github/codeql-action`, `docker/*-action`. Bump
them together so behavior stays consistent. A stale action version is a slow
source of CI breakage.

## Updating rules before a release (optional)

Rules are embedded at **compile time**, so a release ships whatever is committed.
To refresh: `make update-rules` (gitleaks) / `make update-kingfisher`, then
`make merge-rules` and bump the `tests/scan_integration.rs` snapshot counts.
See the "Gitleaks Rules" / "Custom Rules" sections in `AGENTS.md`.

## Release steps

```bash
# 1. Bump all version locations + CHANGELOG (see tables above), refresh lockfiles:
cargo check                                  # syncs root Cargo.lock
( cd bindings/node && cargo check )          # syncs node Cargo.lock

# 2. Pre-release gate (above), including the npm dry-run on a branch.

# 3. Commit to main and push:
git commit -am "Release vX.Y.Z: …"
git push <remote> main

# 4. Tag and push (this publishes — irreversible):
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push <remote> vX.Y.Z
```

(`<remote>` is whatever this clone uses, e.g. `origin` or `upstream` — check
`git remote -v`.)

## Watch & verify

A release is multi-artifact; verify each one, not just the overall run status:

```bash
gh run list --limit 5                         # find the Release + Publish runs
gh run view <id> --json jobs --jq '.jobs[] | "\(.conclusion)\t\(.name)"'
```

Confirm:
- `release.yml`: every job `success` (crates.io, GitHub Release, Docker, Homebrew).
- `publish.yml`: every target built and the npm packages published.
- `gh release view vX.Y.Z`
- crates.io: `cargo search secrets_scanner --limit 3`
- npm: the new version shows on the registry with all platform binaries bundled.
- Homebrew (public repo): `gh api 'repos/whit3rabbit/homebrew-tap/contents/Casks/secrets-scanner.rb?ref=main'`

A run can be `failure` overall while most artifacts succeeded (e.g. only the
Docker job failed on a missing secret). Inspect **per-job** conclusions and fix
the specific gap; do not assume a red run means nothing published.

## Prior failures (so they aren't repeated)

- **v0.1.0**: Docker job failed at *Login to Docker Hub* (missing Docker Hub
  secrets); the npm publish shipped a broken darwin/arm64-only package.
- **v0.2.0**: npm publish failed `EBADPLATFORM` — the node `package.json` pinned
  `os/cpu` to darwin/arm64 while building/publishing on Linux, and the node
  version was not bumped. Fixed by the multi-platform `publish.yml` + lockstep
  node version bump in v0.2.1.
