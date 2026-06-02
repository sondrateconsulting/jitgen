# Security Policy

`jitgen` is a security tool: it **opens repositories it treats as hostile**, executes untrusted test
commands in a **fail-closed sandbox**, and sends bounded, redacted context to an LLM provider only when
you explicitly opt in. Its threat model and the controls that enforce it are documented in
[docs/security.md](docs/security.md). We take vulnerabilities in those controls seriously and
appreciate reports that help keep the boundary sound.

> **Status: the repository is private (pre-public).** Reporting today is available to users with access
> to the repository; the channel below stays the same once the project is public.

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Report it through **GitHub's private vulnerability reporting**:

1. Open the repository's **Security** tab → **Report a vulnerability** ("Privately report a
   vulnerability"), or go to the repository's `/security/advisories/new` page.
2. Include the impact, a reproduction (a minimal repo/diff, the exact `jitgen` command, and the version
   from `jitgen --version`), and — if a sandbox tier is involved — which one (`jitgen doctor` reports
   it).

This opens a private advisory only the maintainers can see, so we can triage and coordinate a fix
before any public disclosure.

## What's in scope

Reports that break one of jitgen's stated security boundaries are the most valuable — for example:

- **Sandbox escape:** untrusted test code reaching the network, writing outside the overlay, or
  executing on the host **without** the trusted `--unsafe-local-execution` flag.
- **Trust-tier bypass:** a repository's `.jitgen.yaml` (untrusted) influencing a security-relevant
  setting reserved for trusted config — the provider / base URL / key-env, `shell: true`, the env
  allowlist, the sandbox backend, or the state root.
- **Secret leakage:** an API key, token, or credential reaching a prompt, log, report, or the provider;
  or egress redirected to an attacker-controlled endpoint.
- **Intake boundary escape:** reading git objects from outside the repository you pointed `--repo` at
  (object alternates, a foreign object/ref store, or symlinked git storage).
- **Report / terminal injection:** untrusted strings escaping per-format escaping into markup or
  terminal control sequences.

## What's not a vulnerability

These are documented, intentional behaviors — please don't file them as vulnerabilities (a regular
issue or discussion is welcome):

- Anything that requires the trusted, off-by-default **`--unsafe-local-execution`** flag. It removes
  isolation by design and is loud and recorded; it is not a sandbox escape.
- The **documented residual risks** in [docs/security.md](docs/security.md#residual-risks) (e.g. a
  *local* attacker who can already plant symlinks under your own trusted state root, or the
  secret-redaction heuristic's documented false-negative shapes). A **new** way to reach one of them
  from a hostile **repository** *is* in scope.
- Findings that require a malicious **trusted** config file, a compromised host, or a provider you
  configured — these fall outside the model (the repository is hostile; the host and trusted config are
  not).

## Coordinated disclosure

We work on a coordinated-disclosure basis: please give us a reasonable chance to ship a fix before
disclosing publicly. We aim to acknowledge a report within a few business days, keep you updated as we
triage and fix, and credit reporters who'd like to be named. Because the project is pre-1.0, fixes land
on the latest release and `main` (there is no back-port stream yet).
