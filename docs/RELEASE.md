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
| `bindings/node/package.json` | `version` **and** every `optionalDependencies` pin | A stale node version makes npm **republish an existing version and fail**. |
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
npm install --no-workspaces          # see npm gotchas below
npm run build && npm run typecheck && npm test
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
```

`cargo publish --dry-run` refuses a dirty tree; commit the version bump first,
then dry-run (use `--allow-dirty` only for a throwaway check).

## npm / node binding

The node binding publishes as a **multi-platform NAPI-RS package**: a thin main
package (`@whit3rabbit/rsecrets-scanner`, ships no binary) plus one
`optionalDependency` per platform (`-darwin-arm64`, `-darwin-x64`,
`-linux-x64-gnu`, `-linux-arm64-gnu`, `-win32-x64-msvc`). `publish.yml` builds
each target on a native runner, then `napi create-npm-dirs` / `napi artifacts` /
`napi pre-publish` publish the platform packages and the main package. See
`bindings/node/CLAUDE.md` for the loader and packaging internals.

Hard-won gotchas (each one broke a publish):

- **Always run the dry-run first.** `publish.yml` has a `workflow_dispatch` mode
  that is **fail-safe**: any dispatch is a dry run unless it is a tag push (or an
  explicit `dry-run=false`). Trigger it on your branch and confirm **all 5
  targets** build before tagging:
  ```bash
  gh workflow run publish.yml --ref <branch>     # no inputs needed; defaults to dry-run
  ```
  Note: `workflow_dispatch` inputs are read from the **default branch**, so a new
  input you added on a feature branch won't be accepted via `-f` until it's on
  `main` — rely on the fail-safe default instead.
- **`npm install`, not `npm ci`.** The per-platform `optionalDependencies` do not
  exist on the registry until the first publish, so npm cannot record them in the
  lockfile and `npm ci` fails the sync check.
- **`--no-workspaces`.** `bindings/` is an npm workspace root
  (`workspaces: ["node", "node-mcp"]`). Without `--no-workspaces`, an install in
  `bindings/node` pulls in the sibling `node-mcp`, which depends on the published
  `@whit3rabbit/rsecrets-scanner@<old>` — `EBADPLATFORM` on any runner whose
  platform doesn't match that old package's `os`/`cpu`.
- **`EBADPLATFORM` on the main package** means the main `package.json` `os`/`cpu`
  is too narrow for the publish/build runner. The main package should allow all
  shipped platforms; only the per-platform sub-packages pin `os`/`cpu`.
- **Provenance** needs `id-token: write` (set) and `NPM_CONFIG_PROVENANCE=true`
  (set on the publish job). The main package publishes with `--ignore-scripts`
  (the publish runner has no Rust toolchain, so skip the `prepack` rebuild).

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
- npm: the new version + its `optionalDependencies` show on the registry.
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
