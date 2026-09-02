#!/usr/bin/env bun
import { mkdtempSync, rmSync, appendFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { scanGo } from "./go.ts";
import { scanJs, JS_LOCKFILES } from "./js.ts";
import { scanRust } from "./rust.ts";
import { compare, type Verdict } from "./diff.ts";
import { discover } from "./discover.ts";
import {
  loadIgnores,
  resolveIgnorePath,
  unusedIgnores,
  type IgnoreSet,
} from "./ignore.ts";
import {
  SEVERITY_ORDER,
  TIERS,
  type Advisory,
  type Ecosystem,
  type ScanResult,
} from "./types.ts";

const ANNOTATION_LIMIT = 10;

const SCANNERS: {
  ecosystem: Ecosystem;
  markers: string[];
  scan: (dir: string) => Promise<ScanResult | null>;
}[] = [
  { ecosystem: "js", markers: JS_LOCKFILES, scan: scanJs },
  { ecosystem: "rust", markers: ["Cargo.lock"], scan: scanRust },
  { ecosystem: "go", markers: ["go.mod"], scan: scanGo },
];

async function git(args: string[], cwd = "."): Promise<string> {
  const p = Bun.spawn(["git", ...args], { cwd, stdout: "pipe", stderr: "pipe" });
  const out = await new Response(p.stdout).text();
  if ((await p.exited) !== 0) {
    throw new Error(`git ${args.join(" ")} failed: ${await new Response(p.stderr).text()}`);
  }
  return out.trim();
}

/**
 * Manifests whose ecosystem has no lockfile, and so was never scanned.
 *
 * A crate that gitignores Cargo.lock is normal for a library and fatal for a
 * report, since nothing here would say the tree went unaudited.
 */
function unlockedManifests(dir: string): string[] {
  const pairs: [string, string[]][] = [
    ["Cargo.toml", ["Cargo.lock"]],
    ["package.json", JS_LOCKFILES],
  ];

  // A workspace member carries no lockfile of its own, so the search walks up
  // to the scan root before calling a manifest unlocked.
  const covered = (root: string, lockfiles: string[]): boolean => {
    for (let at = root; ; at = join(at, "..")) {
      if (lockfiles.some((f) => existsSync(join(at, f)))) return true;
      if (resolve(at) === resolve(dir)) return false;
    }
  };

  return pairs.flatMap(([manifest, lockfiles]) =>
    discover(dir, [manifest])
      .filter((root) => !covered(root, lockfiles))
      .map((root) => `${root}/${manifest}`),
  );
}

async function scanTree(dir: string): Promise<ScanResult[]> {
  // govulncheck builds a call graph and cargo-audit resolves a lockfile, so the
  // slowest scanner sets the wall clock rather than the sum of all of them.
  const jobs = SCANNERS.flatMap(({ ecosystem, markers, scan }) =>
    discover(dir, markers).map(async (root): Promise<ScanResult> => {
      try {
        return (await scan(root)) ?? { ecosystem, advisories: [] };
      } catch (e) {
        return { ecosystem, advisories: [], error: String(e) };
      }
    }),
  );

  const settled = await Promise.all(jobs);

  // One result per ecosystem, so a repository with a frontend beside a backend
  // reads as two sections rather than four.
  const merged = new Map<Ecosystem, ScanResult>();
  for (const r of settled) {
    const prev = merged.get(r.ecosystem);
    if (!prev) merged.set(r.ecosystem, { ...r });
    else {
      prev.advisories.push(...r.advisories);
      prev.error ??= r.error;
    }
  }
  for (const r of merged.values()) {
    const seen = new Map(r.advisories.map((a) => [`${a.id}:${a.package}`, a]));
    r.advisories = [...seen.values()];
  }
  return [...merged.values()];
}

/** Scan a historical commit in a detached worktree, leaving the checkout untouched. */
async function scanBase(sha: string): Promise<ScanResult[] | null> {
  const dir = mkdtempSync(join(tmpdir(), "advisory-base-"));
  try {
    await git(["worktree", "add", "--detach", "--quiet", dir, sha]);
  } catch {
    rmSync(dir, { recursive: true, force: true });
    return null;
  }
  try {
    return await scanTree(dir);
  } finally {
    await git(["worktree", "remove", "--force", dir]).catch(() => {});
    rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * Severity counts, or nothing when the scanner does not rank.
 *
 * cargo-audit publishes a CVSS vector on only some advisories and none at all
 * for the unmaintained and yanked classes, so a Rust section would otherwise
 * read "35 (35 unknown)". Where severity says nothing, class is the real axis.
 */
function bySeverity(list: Advisory[]): string | null {
  const counts = SEVERITY_ORDER.map(
    (s) => [s, list.filter((a) => a.severity === s).length] as const,
  ).filter(([, n]) => n > 0);
  if (!counts.length) return null;
  if (counts.every(([s]) => s === "unknown")) return null;
  return counts.map(([s, n]) => `${n} ${s}`).join(", ");
}

/** `12 (3 high, 9 moderate)`, or a bare count where severity is unavailable. */
function countWithSeverity(list: Advisory[]): string {
  const severity = bySeverity(list);
  return severity ? `${list.length} (${severity})` : `${list.length}`;
}

function renderRow(a: Advisory): string {
  const fix = a.fixAvailable === null ? "?" : a.fixAvailable ? "yes" : "no";
  return `| \`${a.id}\` | ${a.package} | ${a.klass} | ${a.severity} | ${fix} | ${a.title.slice(0, 90)} |`;
}

/** Class counts, which is what decides whether a Rust finding can block at all. */
function byClass(list: Advisory[]): string {
  const counts = new Map<string, number>();
  for (const a of list) counts.set(a.klass, (counts.get(a.klass) ?? 0) + 1);
  return counts.size
    ? [...counts].map(([k, n]) => `${n} ${k}`).join(", ")
    : "none";
}

/** `RUSTSEC-1 (transitive via x)`, keeping any stated justification attached. */
function renderIgnore(e: { id: string; reason?: string }): string {
  return e.reason ? `\`${e.id}\` — ${e.reason}` : `\`${e.id}\``;
}

function summarize(verdicts: Verdict[], ignores: IgnoreSet): string {
  const lines: string[] = ["## Dependency advisories", ""];

  for (const v of verdicts) {
    const tier = TIERS[v.ecosystem];
    lines.push(`### ${v.ecosystem} (${tier})`);
    if (v.error) {
      lines.push("", `Scanner failed: \`${v.error}\``, "");
      continue;
    }
    lines.push(
      "",
      `- introduced by this change: **${countWithSeverity(v.introduced)}**`,
      ...(v.resolved.length > 0
        ? [`- resolved by this change: **${countWithSeverity(v.resolved)}**`]
        : []),
      `- pre-existing on the base branch: ${countWithSeverity(v.inherited)}`,
      `- by class: ${byClass([...v.introduced, ...v.inherited])}`,
      v.baselineKnown ? "" : "- baseline unavailable, so nothing is attributed to this change",
    );
    if (v.introduced.length > 0) {
      lines.push(
        "",
        "| Advisory | Package | Class | Severity | Fix | Title |",
        "| --- | --- | --- | --- | --- | --- |",
        ...v.introduced.map(renderRow),
      );
    }
    if (v.suppressed.length > 0) {
      lines.push(
        "",
        "<details><summary>Suppressed by the ignore file</summary>",
        "",
        ...v.suppressed.map(
          (a) =>
            `- ${renderIgnore(ignores.active.get(a.id.toUpperCase()) ?? a)} ${a.package}`,
        ),
        "",
        "</details>",
      );
    }
    if (v.resolved.length > 0) {
      lines.push(
        "",
        "<details><summary>Resolved</summary>",
        "",
        ...v.resolved.map((a) => `- \`${a.id}\` ${a.package}: ${a.title.slice(0, 90)}`),
        "",
        "</details>",
      );
    }
    lines.push("");
  }

  if (ignores.expired.length > 0) {
    lines.push(
      "### Expired ignores",
      "",
      ...ignores.expired.map((e) => `- ${renderIgnore(e)}`),
      "",
    );
  }

  // A failed scan reports no advisories, which would make live ignores look dead.
  const unused = verdicts.some((v) => v.error) ? [] : unusedIgnores(ignores);
  if (unused.length > 0) {
    lines.push(
      "### Unused ignores",
      "",
      ...unused.map((e) => `- ${renderIgnore(e)}`),
      "",
    );
  }
  return lines.join("\n");
}

interface Options {
  baseRef: string;
  ignoreFile: string;
  useBase: boolean;
  annotate: boolean;
}

const USAGE = `advisory-scan — report dependency advisories against a baseline

  --base-ref <ref>      Baseline to diff against. Defaults to the merge base
                        with the pull request target, or with the default
                        branch when run locally.
  --no-base             Skip the baseline. Reports the current tree and blocks
                        nothing, at roughly half the runtime.
  --ignore-file <path>  Ignore list. Defaults to .github/advisories.json5,
                        then .github/advisories.json.
  -h, --help            Show this message.`;

function parseArgs(argv: string[]): Options {
  const o: Options = {
    baseRef: process.env.ADVISORY_BASE_REF ?? "",
    ignoreFile: process.env.ADVISORY_IGNORE_FILE ?? "",
    useBase: true,
    annotate: Boolean(process.env.GITHUB_ACTIONS),
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--base-ref") o.baseRef = argv[++i] ?? "";
    else if (arg === "--ignore-file") o.ignoreFile = argv[++i] ?? "";
    else if (arg === "--no-base") o.useBase = false;
    else if (arg === "-h" || arg === "--help") {
      console.log(USAGE);
      process.exit(0);
    } else throw new Error(`unknown argument ${arg}`);
  }
  return o;
}

/**
 * The commit to judge this tree against.
 *
 * A pull request has its target; locally the default branch stands in, which on
 * the default branch itself resolves to HEAD and attributes nothing.
 */
async function resolveBase(o: Options): Promise<string> {
  if (!o.useBase) return "";
  if (o.baseRef) return o.baseRef;
  if (process.env.GITHUB_BASE_REF) {
    return git(["merge-base", "HEAD", `origin/${process.env.GITHUB_BASE_REF}`]).catch(
      () => "",
    );
  }
  const head = await git(["rev-parse", "--abbrev-ref", "origin/HEAD"]).catch(() => "");
  if (!head) return "";
  return git(["merge-base", "HEAD", head]).catch(() => "");
}

async function main() {
  const o = parseArgs(Bun.argv.slice(2));
  const ignores = loadIgnores(resolveIgnorePath(o.ignoreFile), new Date());

  const head = await scanTree(".");
  if (head.length === 0) {
    console.log("no supported ecosystems detected");
    return;
  }

  const baseSha = await resolveBase(o);
  const base = baseSha ? await scanBase(baseSha) : null;

  const verdicts = compare(head, base, ignores);
  const summary = summarize(verdicts, ignores);
  console.log(summary);

  if (process.env.GITHUB_STEP_SUMMARY) {
    appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${summary}\n`);
  }

  for (const manifest of unlockedManifests(".")) {
    const text = `${manifest} has no lockfile; its dependencies were not scanned.`;
    console.log(o.annotate ? `::warning::${text}` : `warning: ${text}`);
  }

  const failed = verdicts.filter((v) => v.error);
  for (const v of failed) {
    const text = `${v.ecosystem} could not be scanned: ${v.error}`;
    console.log(o.annotate ? `::error title=Scanner failed::${text}` : `error: ${text}`);
  }

  const blocking = verdicts.flatMap((v) => v.blocking);
  for (const a of blocking) {
    const text = `${a.package}: ${a.title}`;
    console.log(o.annotate ? `::error title=${a.id}::${text}` : `error: ${a.id} ${text}`);
  }

  // GitHub shows ten annotations per step, and the summary already lists them all.
  const inherited = verdicts.flatMap((v) => v.inherited);
  if (o.annotate) {
    for (const a of inherited.slice(0, ANNOTATION_LIMIT)) {
      console.log(`::warning title=${a.id}::${a.package}: ${a.title} (pre-existing)`);
    }
    const hidden = inherited.length - ANNOTATION_LIMIT;
    if (hidden > 0) {
      console.log(`::notice::${hidden} more pre-existing advisories; see the job summary`);
    }
  }

  if (process.env.GITHUB_OUTPUT) {
    const totals = verdicts.reduce(
      (n, v) => n + v.introduced.length + v.inherited.length,
      0,
    );
    appendFileSync(
      process.env.GITHUB_OUTPUT,
      `introduced=${verdicts.reduce((n, v) => n + v.introduced.length, 0)}\n` +
        `resolved=${verdicts.reduce((n, v) => n + v.resolved.length, 0)}\n` +
        `total=${totals}\nblocking=${blocking.length}\nfailed=${failed.length}\n`,
    );
  }

  process.exit(blocking.length > 0 || failed.length > 0 ? 1 : 0);
}

try {
  await main();
} catch (e) {
  // A malformed ignore file or an unusable repository is a configuration fault,
  // not an advisory. Say so plainly rather than dumping a stack trace into CI.
  const text = e instanceof Error ? e.message : String(e);
  console.log(
    process.env.GITHUB_ACTIONS
      ? `::error title=Advisory scan failed::${text}`
      : `error: ${text}`,
  );
  process.exit(1);
}
