# advisory-action

Reports dependency advisories against the merge base, so a change is judged on
what it introduces rather than on what the branch already carried.

## Why

A dependency audit is a function of your lockfile *and* the wall-clock date. The
advisory database moves daily; your lockfile does not. So an audit run as a
merge gate fails commits that changed nothing, and every branch inherits
whatever the base branch was already carrying. Red stops meaning anything.

This action separates the two questions. *What does this change introduce?* is
answered by scanning the merge base in a detached worktree and diffing the
advisory sets. *What is this repository carrying?* is reported alongside, as
warnings, without failing anything.

## Tiers

What may block depends on how much the ecosystem's scanner can actually prove:

| Ecosystem | Scanner | Tier | Blocks on |
| --- | --- | --- | --- |
| Go | `govulncheck` | `blocking` | anything introduced |
| Rust | `cargo-audit` | `vulnerability-only` | introduced vulnerabilities with a fix |
| JavaScript | `bun audit --prod` | `report-only` | nothing |

Go earns a gate because govulncheck resolves vulnerable *symbols* against a call
graph and discards what your code cannot reach. Rust has no reachability
analysis, but cargo-audit does separate real vulnerabilities from `unsound`,
`unmaintained` and `yanked`, so the vulnerability class alone is worth gating.
JavaScript has neither: `bun audit --prod` filters to the production dependency
graph, which is a large improvement over nothing and still not a claim about
reachability. So it reports.

## Usage

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0 # the baseline is scanned from a worktree
- uses: Xevion/advisory-action@v1
```

`@v1` is a moving tag on the latest compatible release. Pin it rather than
`@master`, so a change here reaches your repositories when you move the tag
instead of the moment it is pushed.

Ecosystems are detected by looking for `bun.lock`, `Cargo.lock` and `go.mod` up
to two directories deep, so a repository with a frontend under `web/` beside a
root `go.mod` is scanned as both. Results are merged per ecosystem.

The action installs `govulncheck` and `cargo-audit` when it finds an ecosystem
that needs them, but the language toolchain itself is yours to set up: run
`actions/setup-go` before this action in a Go repository, and make sure a Rust
toolchain is on PATH in a Cargo one. A Go module with no Go toolchain is an
error rather than a silent skip.

Without full history there is no baseline, and the action reports everything as
pre-existing and blocks nothing. That is deliberate: an unknown baseline is a
reason to under-report, never to fail a change that cannot be attributed.

### Inputs

| Input | Default | Meaning |
| --- | --- | --- |
| `base-ref` | merge base with the PR target | Commit treated as the baseline |
| `ignore-file` | `.github/advisories.json` | Advisory suppression list |
| `bun-version` | `latest` | Bun used to run the scanner and audit JS |
| `govulncheck-version` | `latest` | govulncheck installed when a Go module is present |

### Outputs

| Output | Meaning |
| --- | --- |
| `introduced` | Present at HEAD, absent at the baseline |
| `resolved` | Present at the baseline, gone at HEAD |
| `total` | Everything at HEAD, after the ignore list |
| `blocking` | Severe enough to fail, given each ecosystem's tier |

`resolved` is what makes a security bump legible. Without it a PR that clears
four advisories reports identically to one that clears none, which is most of
why dependency PRs became unreadable in the first place.

## Ignore file

```json
[
  {
    "id": "GHSA-xxxx-xxxx-xxxx",
    "reason": "transitive via layerchart; no patched release exists",
    "expires": "2026-12-01"
  }
]
```

`reason` is required and the action fails without one. `expires` is optional;
past that date the entry stops suppressing and is reported as stale, so the list
cannot quietly rot.

## Known limits

- `bun audit --prod` does not apply the production filter at a workspace root,
  so the scanner audits each workspace package separately instead. Fixed in Bun
  1.4; the workaround is harmless once that lands.
- Production reachability is a dependency-graph property, not a runtime one.
  Build tooling reached through a peer dependency (`vite`, `rollup`, `esbuild`)
  still surfaces on framework projects even though it never ships.
- Go advisories carry no CVSS, and cargo-audit publishes one on only some
  advisories and none at all for `unmaintained` or `yanked`. Where a section
  cannot rank, the severity breakdown is omitted rather than filled with
  "unknown", and class is reported instead. govulncheck ranks by reachability,
  which is the stronger signal anyway.
- Only advisories govulncheck traces to a called symbol are reported. Modules
  merely required and packages merely imported are dropped, matching what
  govulncheck's own summary sets aside.
