# Multi-stage build producing a lean, static (musl) secrets-scanner image.
# Default build: no `updater` feature (the runtime rule-updater is for binary
# deployments; rebuild the image to refresh rules). build.rs embeds the ruleset
# at compile time, so `assets/` must be present in the build context.

# ── build stage ───────────────────────────────────────────────────────────────
FROM rust:1-alpine AS build
# musl-dev covers any C shims a transitive build script might need; all direct
# deps are pure Rust.
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . .
RUN cargo build --release --bin secrets-scanner \
    && strip target/release/secrets-scanner

# ── runtime stage ─────────────────────────────────────────────────────────────
# Pin must be a published Alpine tag when the release `publish-docker` job runs;
# an unpublished pin fails the runtime stage with "manifest unknown". Bump in
# lockstep with the build base above.
FROM alpine:3.24
LABEL version="0.1.0"
LABEL org.opencontainers.image.source="https://github.com/whit3rabbit/secrets-scanner"
LABEL org.opencontainers.image.description="A high-performance secrets scanner using Aho-Corasick, regex, and entropy gating"
LABEL org.opencontainers.image.licenses="MIT"
# git: required for the safe-default `--git-tracked` scan mode (the scanner shells out).
# ca-certificates: TLS roots for any HTTPS use.
RUN apk add --no-cache git ca-certificates
COPY --from=build /src/target/release/secrets-scanner /usr/local/bin/secrets-scanner
WORKDIR /repo
ENTRYPOINT ["secrets-scanner"]
CMD ["--help"]

# Usage:
#   docker build -t secrets-scanner:dev .
#   docker run --rm -v "$PWD:/repo" secrets-scanner:dev scan /repo --git-tracked
