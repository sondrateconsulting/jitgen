# ADR-0010: Configuration trust tiers & fail-closed execution

- **Status:** Accepted
- **Date:** 2026-05-30
- **Driven by:** F0 security review S1 (findings #1, #2, #3, #5, #9, #15).

## Context

`.jitgen.yaml` lives **inside the target repository**, which we treat as **hostile**. Earlier drafts
merged it into a single `ResolvedConfig` and let it influence behavior (provider selection, `shell:
true`, grammar names, prompt hints). That hands an attacker control over LLM egress, command
execution, native-code loading, and prompt content. Separately, the constrained-local sandbox tier
offered *no real isolation*, yet could be selected automatically.

## Decision

### 1. Two configuration trust tiers, never merged into one authority
- **TRUSTED config** — CLI flags, **jitgen-scoped process environment variables** (`JITGEN_*`, e.g.
  `JITGEN_STATE_DIR`, set by the invoking user and validated exactly like CLI flags — the state root
  is canonicalized, `0700`, and refused if it resolves inside the repo, incl. via a repo-planted
  symlink ancestor), and a **user/system config file located OUTSIDE the
  target repo** (e.g. `~/.config/jitgen/config.toml`). These share the user's ambient trust; none are
  ever sourced from the repo. Only trusted config may set **security-relevant** settings:
  - LLM provider, base URL, API-key env var name, and **real-LLM enablement**;
  - `shell: true` for any command;
  - the **environment allowlist** (additions to the hardcoded baseline);
  - sandbox backend overrides and `--unsafe-local-execution`;
  - the state root / `--state-dir`.
- **UNTRUSTED config** — the repo's `.jitgen.yaml`. It may ONLY influence a fixed allowlist of
  *non-security* settings: file `extensions`, include/exclude **globs**, the test command as a
  **constrained `argv` template** (placeholders only, see ADR/­security §5), a tree-sitter grammar
  **name validated against a compiled-in allowlist** (ADR-0007), and **prompt hints treated as fenced
  untrusted data** (never as instructions). Any security-relevant key appearing in repo config is
  **ignored with a warning**, never honored.

`ResolvedConfig` is built as `trusted ⊕ untrusted` where untrusted can only set keys on the
non-security allowlist; a typed split (`TrustedConfig` vs `RepoConfig`) enforces this at the type
level so a repo value can never reach a security-relevant field.

### 2. Fail-closed execution
- Running untrusted tests/build commands **requires** an isolating backend (OS sandbox or
  container). If none is available, `jitgen run`/e2e **refuses to execute** and exits with a clear
  error.
- The **constrained-local** tier is **never auto-selected** for untrusted execution. It runs only
  when the trusted user explicitly passes `--unsafe-local-execution`, which prints a prominent
  warning and is recorded in run state and reports.
- `jitgen analyze` (no execution) and unit tests are unaffected.

### 3. Mandatory dependency/lifecycle policy (finding #9)
- **No dependency installation by default.** When needed, installs use frozen lockfiles and the
  offline cache inside the sandbox. **Lifecycle scripts are disabled** (`npm --ignore-scripts`,
  no Maven/Gradle plugin goals beyond test, `build.rs`/pytest-plugin caveats noted) unless a trusted
  user opts in, inside a strong sandbox, with the execution recorded.

## Consequences

- A hostile repo cannot redirect LLM egress, execute shell payloads, load native parser code, expand
  the env, or inject privileged-looking prompt instructions.
- The system never silently runs hostile code without real isolation.
- Slightly less "convenient" auto-config from the repo — the correct trade-off for a tool that opens
  hostile repositories.

## Alternatives considered

- **Single merged config (status quo ante):** rejected — the root cause of findings #2/#3/#5/#15.
- **Auto-fallback to local execution with warnings:** rejected — warnings do not stop code that has
  already run; fail-closed is the only safe default.
