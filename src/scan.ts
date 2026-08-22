import { mkdtempSync, rmSync, appendFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanJs } from "./js.ts";
import { loadIgnores, isIgnored, type IgnoreSet } from "./ignore.ts";
import {
  key,
  SEVERITY_ORDER,
  TIERS,
  type Advisory,
  type Ecosystem,
  type ScanResult,
} from "./types.ts";

const SCANNERS = [scanJs];

async function git(args: string[], cwd = "."): Promise<string> {
  const p = Bun.spawn(["git", ...args], { cwd, stdout: "pipe", stderr: "pipe" });
  const out = await new Response(p.stdout).text();
  if ((await p.exited) !== 0) {
    throw new Error(`git ${args.join(" ")} failed: ${await new Response(p.stderr).text()}`);
  }
  return out.trim();
}

async function scanTree(dir: string): Promise<ScanResult[]> {
  const results: ScanResult[] = [];
  for (const scanner of SCANNERS) {
    try {
      const r = await scanner(dir);
      if (r) results.push(r);
    } catch (e) {
      results.push({ ecosystem: "js", advisories: [], error: String(e) });
    }
  }
  return results;
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

interface Verdict {
  ecosystem: Ecosystem;
  introduced: Advisory[];
  inherited: Advisory[];
  suppressed: Advisory[];
  blocking: Advisory[];
  baselineKnown: boolean;
  error?: string;
}

/**
 * Which advisories are severe enough to fail the run, given the ecosystem's tier.
 *
 * Only ever drawn from `introduced`: an advisory the base branch already carries
 * is not this change's doing, and failing on it makes every unrelated PR red.
 */
function selectBlocking(eco: Ecosystem, introduced: Advisory[]): Advisory[] {
  switch (TIERS[eco]) {
    case "blocking":
      return introduced;
    case "vulnerability-only":
      return introduced.filter(
        (a) => a.klass === "vulnerability" && a.fixAvailable !== false,
      );
    case "report-only":
      return [];
  }
}

function compare(
  head: ScanResult[],
  base: ScanResult[] | null,
  ignores: IgnoreSet,
): Verdict[] {
  return head.map((h) => {
    const kept = h.advisories.filter((a) => !isIgnored(a, ignores));
    const suppressed = h.advisories.filter((a) => isIgnored(a, ignores));

    if (!base) {
      // No baseline: attribute nothing, block nothing. A missing base is a
      // reason to under-report, never to fail a change we cannot attribute.
      return {
        ecosystem: h.ecosystem,
        introduced: [],
        inherited: kept,
        suppressed,
        blocking: [],
        baselineKnown: false,
        error: h.error,
      };
    }

    const baseKeys = new Set(
      (base.find((b) => b.ecosystem === h.ecosystem)?.advisories ?? []).map(key),
    );
    const introduced = kept.filter((a) => !baseKeys.has(key(a)));
    const inherited = kept.filter((a) => baseKeys.has(key(a)));
    return {
      ecosystem: h.ecosystem,
      introduced,
      inherited,
      suppressed,
      blocking: selectBlocking(h.ecosystem, introduced),
      baselineKnown: true,
      error: h.error,
    };
  });
}

function bySeverity(list: Advisory[]): string {
  const counts = SEVERITY_ORDER.map(
    (s) => [s, list.filter((a) => a.severity === s).length] as const,
  ).filter(([, n]) => n > 0);
  return counts.length ? counts.map(([s, n]) => `${n} ${s}`).join(", ") : "none";
}

function renderRow(a: Advisory): string {
  return `| \`${a.id}\` | ${a.package} | ${a.severity} | ${a.title.slice(0, 110)} |`;
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
      `- introduced by this change: **${v.introduced.length}** (${bySeverity(v.introduced)})`,
      `- pre-existing on the base branch: ${v.inherited.length} (${bySeverity(v.inherited)})`,
      `- suppressed by ignore file: ${v.suppressed.length}`,
      v.baselineKnown ? "" : "- baseline unavailable, so nothing is attributed to this change",
    );
    if (v.introduced.length > 0) {
      lines.push(
        "",
        "| Advisory | Package | Severity | Title |",
        "| --- | --- | --- | --- |",
        ...v.introduced.map(renderRow),
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
