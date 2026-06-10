# GP6b spike — versioned docs site: Fumadocs vs Docusaurus

- **Status:** spike complete; recommendation below. No site is stood up by this document.
- **Date:** 2026-06-09
- **Task:** GP6b (P2) from the going-public DX plan — evaluate **Fumadocs vs Docusaurus** (the two
  candidates were mandated up front) for a public, **versioned** docs site, then stand it up in a
  follow-up.

## Requirements

1. **Versioned docs** — a reader on `v0.2.2` must be able to read the docs *for* `v0.2.2` after
   `main` has moved on. This is the requirement that created GP6 in the first place: while the repo
   README/blob links track `main`, released users have no stable docs surface.
2. **Low operational burden** — jitgen is a Rust project; a docs site must not become a second
   product. One deployment, one build, boring upgrades.
3. **Reuse the existing corpus unmodified (or nearly).** 25 Markdown files under `docs/`
   (user guide, CI guide, security model, architecture, ADRs, design docs) are the product docs
   today. They are plain CommonMark with GitHub-flavored tables, code fences, and relative links —
   not MDX.
4. **Static hosting on GitHub Pages** (pure OSS, no SaaS dependency), deployed from a pinned-action
   GitHub workflow like every other workflow in this repo.

## Hands-on evidence (Docusaurus 3.10.1)

The spike scaffolded `create-docusaurus@latest` (classic, TypeScript) and dropped the repo's
`docs/` tree in **unmodified**:

- **All 25 files compiled with zero MDX/build errors** using one config line:
  `markdown: { format: 'detect' }` (`.md` parses as CommonMark, so prose like `<digest>` or
  `<bash|zsh|fish>` never hits the MDX parser).
- **Versioning worked out of the box:** `docusaurus docs:version 0.2.2` snapshotted the tree into
  `versioned_docs/version-0.2.2/`; one build then serves `/docs/` (latest release) and `/docs/next/`
  (working tree) from a single static output. This is exactly the release model jitgen needs: cut a
  snapshot per `vX.Y.Z` tag, `main`'s docs stay visible as "next".
- **Migration cost is four links.** The only genuine breakages are links that point *outside*
  `docs/` and so cannot resolve on a docs site: `../LICENSE`, `../deny.toml`,
  `../.github/workflows/release.yml`, `../.github/workflows/jitgen-advisory.yml`. Rewrite those as
  absolute GitHub blob URLs and `onBrokenLinks: 'throw'` can stay on as a CI gate. (Everything else
  flagged in the spike build was scaffold noise — the template homepage and navbar.)

## Fumadocs (vendor-docs evidence)

Fumadocs' own versioning page is explicit that it **does not offer built-in version
snapshotting** — it "provides the primitives for you to implement versioning on your own way", and
recommends either (a) folder-per-version with sidebar tabs, or (b) **a Git branch per version
deployed as a separate app on its own subdomain** (their own site runs `v14.fumadocs.dev` next to
`fumadocs.dev`).

For jitgen that means, respectively: (a) hand-rolled snapshot copying, link rewriting, and a
"latest/next" routing convention — i.e. re-implementing the exact machinery Docusaurus ships; or
(b) N live Next.js deployments, one per supported version, each with its own dependency upgrades —
the opposite of requirement 2. Fumadocs is also MDX-first (a Next.js app you own and program),
which is attractive for a *product* site with custom React surfaces, but jitgen's corpus is plain
Markdown and its maintainers are not signing up to own a Next.js app.

## Decision matrix

| | Docusaurus 3 | Fumadocs |
|---|---|---|
| Built-in version snapshots | **Yes** (`docs:version`, validated in spike) | **No** (DIY: folders or branch-per-subdomain) |
| Existing 25 `.md` files build unmodified | **Yes** (validated; `format: 'detect'`) | Needs an MDX-leaning content pipeline; unvalidated |
| Deployments to operate | 1 static site | 1 per version (their full-versioning model) or DIY |
| GitHub Pages static export | First-class | Possible (Next.js static export), more moving parts |
| Search | Algolia DocSearch (free for OSS) or local plugin | DIY/Orama integrations |
| Look/feel, React flexibility | Conventional docs look | Nicer default UI, full Next.js control |
| Long-term fit | Built for versioned OSS docs programs | Built for product docs teams living in Next.js |

## Recommendation

**Docusaurus 3.** Versioning is the one hard requirement, and it is the precise feature Fumadocs
delegates to the user. The spike proved the entire existing corpus builds unmodified and versions
correctly in under an hour of setup; choosing Fumadocs means hand-building snapshotting or
operating one deployment per version, with no compensating benefit jitgen needs. Fumadocs remains
the right tool for a future *product/marketing* site with custom React, which is not GP6b.

## Implementation plan (follow-up PR, ~half day)

1. `site/` directory at the repo root: `create-docusaurus` classic TS scaffold; delete the blog;
   `markdown: { format: 'detect' }`; `onBrokenLinks: 'throw'`; `url:
   https://sondrateconsulting.github.io`, `baseUrl: /jitgen/`; `editUrl` → GitHub `main`.
   Point the docs plugin at the existing `../docs` (`path: '../docs'`) so the corpus stays
   single-sourced where it lives today — no copy step, no drift.
2. Fix the four out-of-tree links in `docs/` (GitHub blob URLs) — harmless for repo readers,
   required for the site.
3. A minimal landing page (the README's demo one-liner + links), sidebar from
   `sidebars.ts` (curate the top level: user guide / CI / security / architecture / ADRs; design
   docs and research notes can stay unlisted or under a "internals" category).
4. `.github/workflows/docs-site.yml`: build + deploy to GitHub Pages via the official
   `actions/deploy-pages` chain, every action SHA-pinned (zizmor gate applies), `on: push` to
   `main` paths `docs/**`/`site/**`. Pages source must be set to "GitHub Actions"
   (maintainer UI step).
5. Version cuts: a documented release-process step — run `docusaurus docs:version X.Y.Z` in the
   release PR (alongside the existing CHANGELOG/Cargo bump ritual). Keep only minor-version
   snapshots (prune patch snapshots) to bound repo growth; the corpus is text, so growth is slow.
6. Search: start with `@easyops-cn/docusaurus-search-local` (no external service); apply for
   Algolia DocSearch once the site is live, swap if granted.
7. Out of scope for the first cut: custom domain, landing-page design, docs reorganization.

### Risks / notes

- A Node toolchain enters the repo, isolated under `site/` — it is **not** part of
  `scripts/check.sh` or the Bazel build; only the Pages workflow runs it. Renovate/Dependabot
  should be scoped accordingly (not yet configured for the repo at all — separate concern).
- `format: 'detect'` is the load-bearing config line; new docs stay plain `.md` unless someone
  deliberately writes `.mdx`.
- The README stays the canonical front door; the site serves the *versioned* reading surface.
  Repo-relative links inside `docs/` keep working in both renderers (GitHub and the site), which
  the spike confirmed — only out-of-tree links diverge.
