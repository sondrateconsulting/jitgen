# jitgen Security: Threat Model & Mitigations

`jitgen` **opens hostile repositories**, sends **bounded context** to LLM providers, **writes**
generated tests, and **executes untrusted test commands**. We treat every input repository, its
files, its paths/symlinks, its build/test configuration **including `.jitgen.yaml`**, its git
config/attributes/hooks, and any LLM output as **untrusted**.

This document is **normative**: the listed controls are requirements that bind later phases.
Security-critical controls have **conformance tests** (see the final section) that gate F7/F10.

## Configuration trust tiers (foundational — [ADR-0010](decisions/0010-config-trust-and-fail-closed.md))

There are two tiers, enforced at the **type level** (`TrustedConfig` vs `RepoConfig`), never merged
into a single authority:

- **TRUSTED** — CLI flags, `JITGEN_*` process env vars (validated like CLI flags), and a user/system
  config file **outside the repo** (`~/.config/jitgen/…`). ONLY trusted config may set
  security-relevant settings: LLM **provider / base URL / key-env /
  real-LLM enablement**; `shell: true`; the **env allowlist**; sandbox backend + `--unsafe-local-
  execution`; the **state root**.
- **UNTRUSTED** — the repo's `.jitgen.yaml`. May ONLY influence a fixed non-security allowlist:
  `extensions`, include/exclude globs, a **constrained `argv` template** (placeholders only), a
  tree-sitter grammar **name** checked against a **compiled-in allowlist**, and **prompt hints
  treated as fenced data**. Any security-relevant key in repo config is **ignored with a warning**.

## Assets, trust boundaries

Assets: the host and the user's files outside the repo/overlay; secrets (API keys, tokens, SSH,
package-manager creds); target-repo integrity (no unintended mutation); run-state integrity and trust
in reported results.

| Boundary | Untrusted side | Control |
|---|---|---|
| Repo files / diff | content, paths, symlinks, refs | read **blobs** (not worktree); peel refs to **immutable OIDs**; canonical allowed-root checks |
| Repo config | `.jitgen.yaml` | untrusted tier only (above); typed split; security keys ignored |
| Build/test config | `package.json` scripts, `pom.xml`, `build.rs`, `.jitgen.yaml` argv | argv-only; sandbox; no install/lifecycle by default |
| Git config/attributes | filters, textconv, credential helpers, includes | overlays from blobs **without filters**; inert HOME/config for any CLI |
| LLM prompt | repo content in prompts/hints | fenced/labeled as **data**; injection-resistant templates |
| LLM response | generated test source / commands | parse as candidate; static-validate; sandbox; **never execute LLM commands** |
| Execution | test process, build scripts, hooks | **fail-closed** isolating sandbox; no network; rlimits; timeouts; output caps; env allowlist |
| Persistence/logs | everything above | redact + cap before write; private `0700` state dir outside repo |

## Threats and mitigations

### 1. Sandbox escape / arbitrary code execution — **fail closed**
Test commands and build scripts are attacker-controlled.
- **Isolating backend REQUIRED.** `run`/e2e execute untrusted commands ONLY under an OS sandbox
  (bwrap/firejail/`sandbox-exec`) or container (Docker/Podman). If none is available, execution is
  **refused** (clear error). The **constrained-local** tier is **never auto-selected**; it runs only
  with the trusted `--unsafe-local-execution` flag, which warns loudly and is recorded.
  ([ADR-0003](decisions/0003-sandbox-strategy.md), [ADR-0010](decisions/0010-config-trust-and-fail-closed.md))
- No network by default (enforced + **conformance-tested per backend**); cwd pinned to overlay;
  rlimits (CPU/AS/NOFILE/NPROC/FSIZE); whole-process-group timeout kill; output caps.
- **Environment is a jitgen-owned hardcoded allowlist**, NOT inherited: a **synthetic `HOME`**, no
  `GITHUB_TOKEN`/`AWS_*`/`SSH_AUTH_SOCK`/`*_TOKEN`/`*_API_KEY`/npm·pip·cargo creds; deny-patterns
  applied even to trusted additions. argv-only execution; shell only via trusted `shell: true`.

### 2. Prompt injection (repo content & hints steering the model)
Repo code/comments/README/diff text and `.jitgen.yaml` "prompt hints" may say "ignore instructions /
exfiltrate env".
- Untrusted content (including **repo prompt hints**) is **fenced and labeled as data, never
  instructions**, with explicit precedence rules; the model is granted **no tool-use/function calls**.
- LLM output is a **candidate only** — statically validated and sandboxed; it can never cause network,
  out-of-overlay writes, or command execution.
- **Assessor (LLM-as-judge) injection:** assessor inputs are fenced/redacted; a **rule-based gate must
  pass** AND **deterministic execution evidence** (the observed base-pass/head-fail) is required
  before a `WeakCatch` can be decided `StrongCatch`; uncertainty is capped (default `Uncertain`).
  Adversarial assessor-injection fixtures are part of the conformance suite.

### 3. Secret leakage (to prompts, logs, reports, or the provider)
- **Redact + cap EVERY field** that can carry secrets: prompt context, **stdout/stderr**, **stack
  traces**, repair feedback, **assessor rationale**, **reproduction commands**, report bodies, and
  terminal output. Redaction runs before any send/log/persist.
- Files matching secret/credential patterns are **excluded from context** entirely. Context is the
  **minimum** needed.
- API keys come **only** from an env var **named by trusted config**, never logged or persisted.
  **Provider, base URL, and real-LLM enablement are trusted-config only** — a repo cannot redirect
  egress to an attacker endpoint. TLS verification always on.

### 4. Path traversal / symlink attacks (intake AND materialization)
- Reads use repo **blobs** at pinned OIDs, not the working tree (avoids symlink/TOCTOU on intake).
- **Materialization, F6 current guarantee** ([ADR-0011](decisions/0011-overlay-materialization.md)):
  writes are confined to the overlay with pure-`std` (no `unsafe`) — lexical path validation (no
  absolute/`..`/`\`/drive prefix; length & nesting caps), **per-component symlink rejection** when
  creating parent dirs, an `O_CREAT|O_EXCL` temp write (refuses a final-component symlink per POSIX,
  never overwrites), and an atomic `rename` into place (replaces a destination symlink without
  following it). A non-regular destination (dir/FIFO/device) is refused; idempotency compares length
  then sha256, never reading an oversized file. We do **not** canonicalize-then-write. **Residual
  (deferred to F7):** the parent symlink check → final open and the existing-file stat → read are
  TOCTOU windows that require a *concurrent local attacker* with overlay write access (out of the
  threat model: the overlay is a private, single-process, sequentially-built dir).
- **Materialization, F7 conformance requirement:** full `openat`-style dirfd traversal with
  `O_NOFOLLOW` on every component and post-open `fstat` (regular-file + within the overlay
  device/inode root), closing the above TOCTOU windows, plus preflight resource budgets.
- The **state root** is a private `0700` directory **outside the repo** with **no symlink ancestors**;
  artifacts are addressed by **relative IDs**, not attacker-influenced absolute paths.

### 5. Command injection
- **argv arrays only.** The generic command is an explicit `argv` list with a fixed allowlist of
  `{…}` placeholders substituted as **individual argv elements** (never re-split, never shell-parsed).
- A free-form **string** command is accepted **only** behind `shell: true`, which is **trusted-config
  only** (a hostile `.jitgen.yaml` cannot set it), is flagged high-risk, and still runs sandboxed.
  Commands are never derived from LLM output.

### 6. Malicious build scripts / lifecycle / git config
- **Mandatory install policy:** no dependency install by default; when needed, frozen lockfiles +
  offline cache **inside the sandbox**; **lifecycle scripts disabled** (`--ignore-scripts`, test-only
  goals, documented `build.rs`/pytest-plugin caveats) unless trusted opt-in; executions recorded.
- **Git is neutered:** overlays are built **from blobs without filters**; any unavoidable `git` CLI
  runs with an **inert HOME**, `-c core.hooksPath=`, and filters/smudge/LFS/**textconv**/external
  diff/credential helpers/pager/includes/remote protocols disabled. Malicious-filter/attribute
  fixtures are in the conformance suite. ([ADR-0006](decisions/0006-git-intake-libgit2.md))

### 7. Malicious generated tests
- Run only inside the fail-closed sandbox (no network, confined writes, rlimits); static validation
  rejects obviously dangerous constructs before execution.

### 8. Supply chain
- Ours: pinned `Cargo.lock` + `.bazelversion`; `cargo audit` + `cargo deny` (F10); vendored where
  practical.
- Toolchain images: **digest-pinned** (not floating `node`/`python` tags); frozen lockfiles; offline
  caches. Any dependency fetch is a **single explicit, trusted fetch phase** — not implicit during
  sandboxed execution (which stays no-network). ([ADR-0009](decisions/0009-hermetic-toolchains-ci.md))

### 9. Denial of service / resource exhaustion (incl. **pre-sandbox**)
- **Preflight budgets BEFORE any heavy work or sandboxing:** caps on repo/pack/object/blob/file sizes,
  path counts, diff size, tree depth, **tree-sitter parse time/memory**, and context bytes/tokens;
  operations are cancelable/streaming. Plus in-sandbox rlimits (NPROC/CPU/AS/FSIZE), timeouts, output
  caps, bounded retries/candidates, and overall run budgets.

### 10. Unsafe persistence / logging / report injection
- State DB + overlays live under the private `0700` state root **outside** the repo; resume/report
  **validate** stored paths (relative IDs, no symlink ancestors) before reading/writing.
- **Report/log injection:** test names, failures, rationale, and paths are **escaped per output
  format** (Markdown/HTML, XML for JUnit, JSON for SARIF), **control/ANSI characters stripped**, and
  length-capped; untrusted content is always rendered as **data**, never markup/markup-controls.
- Redaction (threat #3) is applied before any persistence; logs never dump the environment.

### TOCTOU / mutable refs
- `base`/`head` are **peeled to immutable commit OIDs** at run start; OIDs + tree hashes are stored
  and **re-verified before every resumed step**, so a moving ref cannot swap content mid-run.

## Secure defaults (summary)

Fail-closed execution (isolating sandbox required); non-destructive (patch unless `--write`); no
network in sandbox (conformance-tested); jitgen-owned env allowlist + synthetic HOME; argv-only;
`shell`/provider/real-LLM/state-root are **trusted-config only**; keys from a trusted-named env var;
redaction + caps everywhere; blob-based intake with git filters disabled; immutable OIDs; private
`0700` state dir; preflight resource budgets; per-format report escaping.

## Security conformance tests (required gates)

These MUST exist and pass before the relevant phase is complete (built security-review-first at F7):

1. **Sandbox network denial** — per backend (bwrap/firejail/`sandbox-exec`/Docker/Podman): DNS,
   TCP/loopback, IPv6, unix-socket egress all blocked; **fail closed** if a backend cannot prove it.
2. **No write outside overlay** — symlinked `tests/ -> ~/.ssh`, ancestor-swap races, `..`/absolute
   paths all rejected; `O_NOFOLLOW`/`O_EXCL`/`fstat` enforced.
3. **Env allowlist** — token/socket/credential vars absent; synthetic HOME; trusted additions only.
4. **Git neutering** — malicious `.gitattributes` filter/textconv/external-diff/credential-helper
   fixtures execute nothing; overlays match blob contents.
5. **Repo-config trust** — a `.jitgen.yaml` attempting `shell:true`, provider/base-URL/key-env, env
   expansion, or a non-allowlisted grammar is ignored with a warning.
6. **Redaction** — seeded secrets in source/stdout/stderr/stack/rationale/repro never reach
   prompts/logs/reports.
7. **Prompt + assessor injection** — fixtures cannot flip a strictly-weak catch to `StrongCatch`
   without rule-gate + deterministic evidence.
8. **Report injection** — ANSI/Markdown/HTML/XML/SARIF payloads in test names/paths are neutralized.
9. **Preflight DoS** — oversized repo/blob/diff/parse inputs are rejected before sandboxing.
10. **Resource limits** — timeout, output cap, and rlimit enforcement (fork bomb, infinite loop,
    output flood) all contained.

## Residual risks

- **Git intake boundary (F3):** `open_repo` opens exactly the requested root (`NO_SEARCH`) and
  verifies the gitdir, commondir, object store are under it, **refuses object alternates** entirely,
  and **rejects symlinked critical git-storage entries** (`objects`/`refs`/`packed-refs`/`HEAD`).
  Exhaustively mirroring every internal path libgit2 may traverse (e.g. a symlink inside an individual
  loose-object fanout dir) is **not** fully validated at `open()`. Bounded because intake is
  **read-only** — it reads git objects only, never executes hooks/filters/commands (verified in
  F3/S1) — so the worst case is reading git objects already present on the host; code execution is
  contained by the F7 sandbox.
- `--unsafe-local-execution` exists for hosts without any sandbox; it is **off by default**, loud,
  and recorded. macOS `sandbox-exec` is Apple-deprecated though functional. Redaction is heuristic
  (minimize context + exclude secret files; cannot guarantee zero leakage of novel secret formats).
  Real-LLM mode is opt-in and off by default.
- **Sandbox resource limits (F7) are backend-dependent.** Docker/Podman (`--memory` / `--pids-limit`
  / `--cpus`) and firejail (`--rlimit-*`) enforce CPU/memory/process caps in-kernel. **bwrap** and
  macOS **`sandbox-exec`** have no flag-level rlimit primitive, and a `setrlimit` pre-exec would
  require `unsafe` (forbidden crate-wide); on those backends the **wall-clock timeout is currently the
  only fork-bomb/resource backstop**. Network egress, write-confinement, and the env allowlist are
  unaffected. Planned hardening: a `ulimit` shell preamble (`sh -c 'ulimit …; exec "$@"'`) for the
  non-container tiers — tracked for F7 finalization / F10. Relatedly, the OS-sandbox tiers allow broad
  `file-read*` (so toolchains load), so a sandboxed process can read host files its uid permits; the
  primary mitigation is no-network + output redaction + synthetic `HOME` (see `sbpl.rs`).
- **Secret redaction heuristic (F5, `jitgen-context::redact`):** runs before any prompt/log/report
  on a **size-bounded** input window (256 KiB/item, with a fail-closed drop of a window-split
  trailing token), using the linear-time `regex` engine (no catastrophic backtracking). It covers
  known token formats (AWS, GitHub classic/`github_pat_`, GitLab, Slack token/app/webhook, Google
  key/OAuth, OpenAI `sk-`, npm, JWT, PEM, bearer, basic-auth), `scheme://user:pass@` URL
  credentials, quoted secret-key assignments, unquoted high-confidence env assignments
  (`API_KEY=…`), and line-anchored config assignments (`password=…`, `api_key: …`, `secret.key=…`,
  CRLF, base64 padding). For *unquoted* config assignments the value-shape gate (`looks_like_secret`)
  redacts a value (≥12 chars) that has a digit or base64 special, or is an all-lowercase run with no
  `_`/`-` separators and ≥16 chars (passphrase). **Residual:** an unquoted value that has uppercase
  but no digit/base64 (looks CamelCase), or contains `_`/`-` separators with no digit/base64 (looks
  snake/kebab), or is an all-lowercase run shorter than 16 chars, is indistinguishable from a code
  identifier and is **not** redacted via the unquoted path — the dual being that a real secret of
  those exact shapes is not caught. Relatedly, the *unanchored* matcher that scans mid-line text
  (logs/feedback) is restricted to uppercase-style keys (`API_KEY=…`), so a **mid-line, lowercase
  compound-key** secret (`… api_key=secret123 …` not at line start) is a documented false-negative;
  line-start config assignments of those keys are still caught. This is the irreducible
  false-positive/false-negative tradeoff of a regex heuristic, chosen to avoid corrupting the ordinary
  code the model must read. Quoted values and all known token formats are unaffected, and the primary
  guarantees stand independently — **API keys are read only from the trusted-named env var (never repo
  config/logs), model output is never executed, and execution is sandboxed** (threats #1/#3,
  ADR-0008/0010). Reviewed across F5/S1·T2·T3·T4·T5·T6·T7.
