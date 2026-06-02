# TODOS

Deferred work captured during reviews. Each item has enough context to pick up cold.

## CLI: global broken-pipe handling for all stdout commands

- **What:** Reset SIGPIPE to default at process start (`unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) }` in `crates/jitgen-cli/src/main.rs`, or the `sigpipe` crate) so every stdout command (`analyze`, `report`, `run` patch/json/sarif output) exits cleanly when piped to `head`/`grep -q`, instead of panicking (exit 101).
- **Why:** Rust ignores SIGPIPE by default and `print!`/`println!` panic on EPIPE. The `/plan-eng-review` of PR #13 fixed broken-pipe for `jitgen completions` only (via `try_generate` + a `BrokenPipe` arm in `write_completions`); the other stdout commands still panic on a closed pipe, which is now an inconsistency.
- **Pros:** Uniform, correct pipe behavior CLI-wide; removes the completions-vs-rest asymmetry.
- **Cons:** One `unsafe` block + a process-wide signal change + a `libc` dependency; deserves its own test (assert `analyze | head` exits 0/141, not 101).
- **Context:** Surfaced by Codex during the eng review of PR #13. `completions` already exits cleanly on EPIPE; a global SIGPIPE reset would also cover it (the signal fires before `try_generate`'s error).
- **Depends on / blocked by:** none.
