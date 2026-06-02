# ADR-0012: HTTP client for real LLM providers (ureq + rustls/ring + webpki-roots)

- **Status:** Accepted
- **Date:** 2026-06-01

## Context

[ADR-0008](0008-llm-provider-abstraction.md) specified real providers (Anthropic Messages,
OpenAI-compatible incl. local servers) behind a **synchronous** trait using **blocking HTTP**, with
TLS always on and the API key read only from a trusted-named env var. F5–F10 shipped the abstraction
with a deterministic mock; the real providers were deferred. **F11 wires them**, which requires
choosing an HTTP client. Constraints particular to this repo:

- **Blocking, no async runtime** — the trait is sync; pulling `tokio` for one batch call is wrong.
- **Lean + Bazel-friendly** — every transitive crate must re-pin in `crate_universe` (rules_rust);
  build-script/C crates are tolerated (we already vendor libgit2/rusqlite/tree-sitter) but heavyweight
  TLS build systems are a liability.
- **Hermetic** — the project vendors its trust anchors rather than depending on the host (no system
  OpenSSL; static zlib). TLS root certs should follow suit.
- **MSRV 1.80** — the declared workspace `rust-version` _at the time of this ADR_ (later raised to
  1.85 when the clap 4.6 line, which requires rustc 1.85, was adopted).

## Decision

Use **`ureq` 3.2.x** with its **default features**, which select **rustls + `ring` + bundled
`webpki-roots`**.

- **Blocking + pure-Rust API**, `http`-crate based; no `tokio`.
- **`ring`** (not `aws-lc-rs`): ring ships pregenerated assembly and builds via `cc` under Bazel
  `crate_universe` exactly like the existing C-building deps; `aws-lc-rs` needs cmake/bindgen and is
  Bazel-hostile.
- **`webpki-roots`** bundles the Mozilla CA set → **hermetic**, identical across platforms, no system
  trust store (consistent with vendoring libgit2/zlib). TLS verification is always on.
- **Pinned to the 3.2.x line** (`~3.2.1`): ureq ≥ 3.3 raised its MSRV to rustc 1.85, above the 1.80
  MSRV in force when this ADR was written. (The workspace MSRV is now 1.85; the pin remains for build
  stability and can be revisited separately.)
- **`serde_json`** (already a workspace dep) builds request bodies and parses responses.
- A small `HttpTransport` **trait seam** isolates the one socket-opening type (`UreqTransport`) so each
  provider's body-building / response-parsing / error-mapping is unit-tested **offline** with a fake.
- **HTTPS enforced**; a plain `http://` endpoint is refused unless the host is loopback (local servers).
  The key goes in a single request header, never logged/persisted/returned in an error.

## Consequences

- Real generation works behind trusted config + `--real-llm`; the offline mock remains the default and
  CI/tests never touch the network (transport is faked).
- The new transitive tree (rustls, ring, webpki-roots, http, …) is added to the supply-chain gate:
  `deny.toml` allows the licenses it introduces (notably `webpki-roots` is **MPL-2.0**). `audit.sh`
  covers it.
- ureq is pinned to 3.2.x until the workspace MSRV is raised; revisit when bumping `rust-version`.

## Alternatives considered

- **`reqwest` (blocking feature):** rejected — still pulls `tokio` and a large tree for one sync call.
- **`rustls` + `aws-lc-rs`:** rejected — cmake/bindgen build is fragile under Bazel `crate_universe`.
- **`native-tls`:** rejected — uses system OpenSSL on Linux, breaking the hermetic, no-system-TLS
  posture and cross-platform reproducibility.
- **`rustls-platform-verifier`:** rejected — depends on the host trust store; `webpki-roots` is more
  hermetic and matches how the rest of the project vendors its dependencies.
