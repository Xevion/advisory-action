import { mkdtempSync, rmSync, appendFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanGo } from "./go.ts";
import { scanJs } from "./js.ts";
import { scanRust } from "./rust.ts";
import { compare, type Verdict } from "./diff.ts";
import { discover } from "./discover.ts";
import { loadIgnores, type IgnoreSet } from "./ignore.ts";
import {
  SEVERITY_ORDER,
  TIERS,
  type Advisory,
  type Ecosystem,
  type ScanResult,
} from "./types.ts";

const SCANNERS: {
  ecosystem: Ecosystem;
  markers: string[];
  scan: (dir: string) => Promise<ScanResult | null>;
}[] = [
  { ecosystem: "js", markers: ["bun.lock", "bun.lockb"], scan: scanJs },
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
      `- suppressed by ignore file: ${v.suppressed.length}`,
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
      "These no longer suppress anything and should be removed or renewed.",
      "",
      ...ignores.expired.map((e) => `- \`${e.id}\` — ${e.reason}`),
      "",
    );
  }
  return lines.join("\n");
}

async function main() {
  const ignorePath = process.env.ADVISORY_IGNORE_FILE ?? ".github/advisories.json";
  const ignores = loadIgnores(ignorePath, new Date());

  const head = await scanTree(".");
  if (head.length === 0) {
    console.log("no supported ecosystems detected");
    return;
  }

  let baseSha = process.env.ADVISORY_BASE_REF ?? "";
  if (!baseSha && process.env.GITHUB_BASE_REF) {
    baseSha = await git(["merge-base", "HEAD", `origin/${process.env.GITHUB_BASE_REF}`]).catch(
      () => "",
    );
  }
  const base = baseSha ? await scanBase(baseSha) : null;

  const verdicts = compare(head, base, ignores);
  const summary = summarize(verdicts, ignores);
  console.log(summary);

  if (process.env.GITHUB_STEP_SUMMARY) {
    appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${summary}\n`);
  }

  const blocking = verdicts.flatMap((v) => v.blocking);
  for (const a of blocking) {
    console.log(`::error title=${a.id}::${a.package}: ${a.title}`);
  }
  for (const v of verdicts) {
    for (const a of v.inherited) {
      console.log(`::warning title=${a.id}::${a.package}: ${a.title} (pre-existing)`);
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
        `total=${totals}\nblocking=${blocking.length}\n`,
    );
  }

  process.exit(blocking.length > 0 ? 1 : 0);
}

try {
  await main();
} catch (e) {
  // A malformed ignore file or an unusable repository is a configuration fault,
  // not an advisory. Say so plainly rather than dumping a stack trace into CI.
  console.log(
    `::error title=Advisory scan failed::${e instanceof Error ? e.message : String(e)}`,
  );
  process.exit(1);
}
