#!/usr/bin/env bash
# Fail-closed remote test-cache policy enforcement (T1).
#
# Every Bazel rust_test MUST be non-remote-cacheable (tag "no-remote-cache", the
# fail-closed default set by jitgen_rust_*() in //bazel:defs.bzl) UNLESS it has been
# through a per-crate hermeticity audit (Phase 3 / T6) and is BOTH marked
# test_cache="remote_ok" in its BUILD.bazel AND listed in the allowlist below. This
# stops a new crate, or a hand-authored raw rust_test() that bypasses the macro, from
# silently serving a false-PASS test result out of the remote cache.
#
# Run from anywhere; resolves the repo root itself. Exits non-zero on a violation.
#
# Scope: rust_test-scoped (the only test rule kind jitgen uses today; the macro emits only
# rust_test, and tests(//...) == kind(rust_test,//...) here). If a new test rule kind is ever
# added (sh_test, cc_test, rust_test_suite, ...), widen the query below from kind("rust_test", ...)
# to tests("//...") so it stays covered. Do NOT add --keep_going to the query: the implicit
# --nokeep_going is what makes a BUILD load error abort with a nonzero exit (the fail-closed property).
set -euo pipefail

# Pin the C locale so `sort` and `comm` agree on byte-order collation regardless of the
# caller's LANG/LC_*. Labels are ASCII; this only makes the set comparison invariant.
export LC_ALL=C

cd "$(dirname "$0")/.."

BAZEL="$(command -v bazel || command -v bazelisk || true)"
if [ -z "$BAZEL" ]; then
  echo "test-cache policy: neither bazel nor bazelisk on PATH; skipped." >&2
  exit 0
fi
if ! command -v jq >/dev/null 2>&1; then
  # Hard-fail (not skip): we only reach here when bazel IS present, i.e. the enforcing path.
  # A missing jq means the gate cannot evaluate the policy — fail closed, never silently pass.
  echo "test-cache policy: jq not on PATH but bazel is — cannot enforce; failing closed. Install jq." >&2
  exit 1
fi

ALLOWLIST="bazel/remote_cacheable_tests.txt"

# Eligible-for-remote-cache = rust_tests whose `tags` list does NOT contain the EXACT element
# "no-remote-cache". We read the STRUCTURED query output (streamed_jsonproto: one Target JSON per
# line) and test exact list membership with jq. This is correct by construction: regex-matching
# Bazel's STRINGIFIED tag list is ambiguous (a single pathological tag value like "a, no-remote-cache"
# stringifies identically to the two tags "a","no-remote-cache"), whereas jq's index() on the actual
# string array is exact equality. A rust_test with no tags (e.g. a raw, macro-bypassing target) has
# tags=[] -> not a member -> correctly eligible -> flagged.
#
# The query runs with --noworkspace_rc --nohome_rc --nosystem_rc so it ignores ALL rc files,
# including the workspace .bazelrc's try-import of the (PR-controllable, gitignored) user.bazelrc.
# Otherwise a committed/local user.bazelrc could feed the gate `query --deleted_packages=...` (or
# similar) to hide a remote-cacheable target from enumeration, subverting the gate. bzlmod is the
# default in Bazel 7+, so dropping the rc's `common --enable_bzlmod` does not change resolution.
qerr="$(mktemp)"
trap 'rm -f "$qerr"' EXIT

# Fail-closed on query/parse error: a failed `bazel query | jq` must STOP the gate, never be read
# as "0 eligible tests" (a silent pass). pipefail (set above) makes the pipeline exit reflect the
# first failing stage; capture it explicitly around `set +e`.
set +e
eligible="$("$BAZEL" --noworkspace_rc --nohome_rc --nosystem_rc query --output=streamed_jsonproto --noshow_progress 'kind("rust_test", "//...")' 2>"$qerr" \
  | jq -r 'select(.type == "RULE") | .rule
           | {name: .name, tags: [(.attribute[]? | select(.name == "tags") | .stringListValue[]?)]}
           | select((.tags | index("no-remote-cache")) | not)
           | .name')"
qrc=$?
set -e
if [ "$qrc" -ne 0 ]; then
  echo "test-cache policy: 'bazel query | jq' failed — refusing to pass (fail-closed):" >&2
  cat "$qerr" >&2
  exit 1
fi

eligible="$(printf '%s\n' "$eligible" | sed '/^[[:space:]]*$/d' | sort)"

if [ -z "$eligible" ]; then
  echo "test-cache policy OK: every rust_test is fail-closed (no remote-cacheable tests)."
  exit 0
fi

# Audited + allowlisted labels (strip comment and blank lines; take the label field only).
allow=""
if [ -f "$ALLOWLIST" ]; then
  allow="$(grep -vE '^[[:space:]]*(#|$)' "$ALLOWLIST" | awk '{print $1}' | sort || true)"
fi

# Any remote-eligible target that is NOT audited+allowlisted is a violation.
violations="$(comm -23 <(printf '%s\n' "$eligible") <(printf '%s\n' "$allow"))"
if [ -n "$violations" ]; then
  echo "FAIL: remote-cacheable rust_test(s) without a hermeticity-audit allowlist entry:" >&2
  printf '%s\n' "$violations" | sed 's/^/  - /' >&2
  echo "Fix: keep it local_only (the default), OR audit it (Phase 3 / T6) and add the" >&2
  echo "label to $ALLOWLIST with test_cache=\"remote_ok\" in its BUILD.bazel." >&2
  exit 1
fi

echo "test-cache policy OK: all remote-cacheable rust_tests are audited + allowlisted."
