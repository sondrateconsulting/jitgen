# jitgen container image — "the container IS the sandbox" CI model.
#
# This image bundles jitgen together with git and the first-class language toolchains (Rust, Node/npm,
# JDK+Maven, Python+pytest — ADR-0009) so a CI job can run jitgen *inside* an ephemeral, jitgen-owned
# container and pass `--unsafe-local-execution`: the throwaway container is the isolation boundary
# (no Docker-in-Docker, no mounted Docker socket). This is distinct from jitgen's own `--docker-image`
# sandbox tier, where jitgen spawns containers itself (that tier needs a Docker socket / DinD).
#
# Base images are digest-pinned (never a floating tag) per ADR-0009. Refresh the digests with a single
# explicit, trusted update (`docker buildx imagetools inspect <ref> --format '{{.Manifest.Digest}}'`).

# ---- builder: compile the jitgen binary natively for the build arch ----
# rust:1.95.0-bookworm matches rust-toolchain.toml (1.95.0) and ships gcc + git, so the C-heavy deps
# (vendored libgit2, static zlib, bundled rusqlite, tree-sitter grammars, ring) build with no extras.
FROM rust:1.95.0-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1 AS builder
WORKDIR /build
# Copy only the build inputs (not docs / .git / CI), so the compile layer caches independently of doc
# edits and the build context stays small.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
# --locked: build exactly the committed Cargo.lock (reproducible). Only the CLI binary is needed.
RUN cargo build --locked --release --bin jitgen -p jitgen-cli

# ---- demo: slim, demo-only image for `jitgen demo` (offline real-catch, no toolchains) ----
# The first-contact image. `docker run ghcr.io/sondrateconsulting/jitgen-demo` runs `jitgen demo`:
# the offline proof that catch mode catches a real regression (recorded LLM, constrained-local
# sandbox, no API key, no network). It needs only the jitgen binary + a POSIX /bin/sh — the demo
# builds its two-commit fixture via vendored libgit2 IN-PROCESS (no `git` CLI) and runs the generated
# test under /bin/sh. `jitgen demo --lang rust` is unsupported here (no cargo) and fails fast with a
# pointer to the default demo: that is the documented slim-image limitation (docs/ci.md); the fat
# `runtime` image below carries the toolchains. debian:bookworm-slim shares the builder's bookworm
# glibc userland, so the dynamically-linked jitgen binary runs as-is. Digest-pinned per ADR-0009
# (multi-arch manifest list — covers linux/amd64 + linux/arm64).
FROM debian:bookworm-slim@sha256:0104b334637a5f19aa9c983a91b54c89887c0984081f2068983107a6f6c21eeb AS demo
LABEL org.opencontainers.image.source="https://github.com/sondrateconsulting/jitgen" \
      org.opencontainers.image.description="jitgen demo — offline, one-command proof that catch mode catches a real regression (no API key)." \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=builder /build/target/release/jitgen /usr/local/bin/jitgen
# Non-root by default (defense in depth — the demo writes only to per-run temp dirs under $HOME).
RUN useradd --create-home --uid 1000 --user-group jitgen
USER jitgen
WORKDIR /home/jitgen
# `docker run <demo-image>` → the demo, no args needed (the launch one-liner). Override with e.g.
# `docker run <demo-image> --version` or `... analyze ...`.
ENTRYPOINT ["jitgen"]
CMD ["demo"]

# ---- runtime: jitgen + git + the four first-class toolchains, non-root ----
# Same rust base => cargo/rustc/gcc/git already on PATH and layer-shared with the builder; apt adds the
# other three languages. The build intermediates in the builder's target/ are left behind. This is the
# DEFAULT build target (last stage) — `docker build .` yields the fat "container IS the sandbox" image.
FROM rust:1.95.0-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1 AS runtime

LABEL org.opencontainers.image.source="https://github.com/sondrateconsulting/jitgen" \
      org.opencontainers.image.description="jitgen — Just-in-Time test generation; run it inside this container as the CI sandbox boundary." \
      org.opencontainers.image.licenses="Apache-2.0"

ENV DEBIAN_FRONTEND=noninteractive
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      git \
      default-jdk maven \
      nodejs npm \
      python3 python3-pip python3-venv; \
    rm -rf /var/lib/apt/lists/*
# pytest for the Python adapter. Bookworm's system Python is externally managed (PEP 668); this image
# IS the environment, so a system-wide install is intended. Pinned to a minor line for build
# reproducibility (the digest-pinned base + cargo --locked are the only other build inputs).
RUN pip3 install --no-cache-dir --break-system-packages 'pytest==9.0.*'

# The rust base ships cargo/rustc as rustup PROXIES that need $RUSTUP_HOME to locate the toolchain.
# jitgen runs tools under a hardened env that strips RUSTUP_HOME (the sandbox env allowlist and the
# `doctor` probe both keep only PATH/HOME/locale), so the proxies fail and Rust looks absent. Replace
# them with the REAL toolchain binaries — they find their sysroot from their own path and need no env,
# so Rust behaves like the other languages (a real binary on the standard PATH). The build-time
# `env -u` assertion fails the image if that ever stops holding.
RUN set -eux; \
    tc="$(rustup toolchain list | head -1 | cut -d' ' -f1)"; \
    tcbin="/usr/local/rustup/toolchains/${tc}/bin"; \
    for b in cargo rustc rustdoc; do \
      ln -sf "${tcbin}/${b}" "/usr/local/cargo/bin/${b}"; \
      ln -sf "${tcbin}/${b}" "/usr/local/bin/${b}"; \
    done; \
    env -u RUSTUP_HOME -u CARGO_HOME cargo --version; \
    env -u RUSTUP_HOME -u CARGO_HOME rustc --version

COPY --from=builder /build/target/release/jitgen /usr/local/bin/jitgen

# Non-root by default (defense in depth — the ephemeral container is the boundary, but jitgen need not
# run as root inside it). cargo/rustc resolve via /usr/local/bin and /usr/local/cargo/bin (on PATH).
RUN useradd --create-home --uid 1000 --user-group jitgen
USER jitgen
WORKDIR /home/jitgen
# The base bakes CARGO_HOME=/usr/local/cargo (root-owned AND world-writable); re-point it at the user's
# own home so any direct `cargo` use writes to a user-owned dir. (jitgen's own runs strip CARGO_HOME and
# already fall back to $HOME/.cargo, so this only matters for cargo invoked outside jitgen.)
ENV CARGO_HOME=/home/jitgen/.cargo

# `docker run <image> --version` / `... analyze ...` / `... run ... --unsafe-local-execution`.
# (GitHub Actions `container:` jobs ignore ENTRYPOINT and call `jitgen` from PATH instead — both work.)
ENTRYPOINT ["jitgen"]
CMD ["--help"]
