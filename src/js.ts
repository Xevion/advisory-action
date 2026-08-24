import { readdirSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { Advisory, ScanResult, Severity } from "./types.ts";

export type PackageManager = "bun" | "pnpm" | "yarn" | "npm";

/**
 * Lockfile that identifies each manager, in preference order.
 *
 * Repositories here routinely carry a stale `package-lock.json` beside the
 * lockfile actually in use, so the first match wins rather than the last.
 */
const MANAGERS: { pm: PackageManager; lockfiles: string[] }[] = [
  { pm: "bun", lockfiles: ["bun.lock", "bun.lockb"] },
  { pm: "pnpm", lockfiles: ["pnpm-lock.yaml"] },
  { pm: "yarn", lockfiles: ["yarn.lock"] },
  { pm: "npm", lockfiles: ["package-lock.json"] },
];

export const JS_LOCKFILES = MANAGERS.flatMap((m) => m.lockfiles);

/** Each manager's production-only audit, emitting JSON on stdout. */
const AUDIT_ARGV: Record<PackageManager, string[]> = {
  bun: ["bun", "audit", "--prod", "--json"],
  pnpm: ["pnpm", "audit", "--prod", "--json"],
  yarn: ["yarn", "npm", "audit", "--environment", "production", "--json"],
  npm: ["npm", "audit", "--omit=dev", "--package-lock-only", "--json"],
};

const GHSA = /GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}/i;

/** npm spells "there is no patched release" as a range nothing satisfies. */
const NO_PATCH = "<0.0.0";

export function detectManager(dir: string): PackageManager | null {
  for (const { pm, lockfiles } of MANAGERS) {
    if (lockfiles.some((f) => existsSync(join(dir, f)))) return pm;
  }
  return null;
}

function normalizeSeverity(s: unknown): Severity {
  const v = String(s ?? "").toLowerCase();
  return ["critical", "high", "moderate", "low"].includes(v) ? (v as Severity) : "unknown";
}

/** The GHSA identifies a finding; the registry's numeric id is reindexed. */
function advisoryId(url: unknown, ghsa: unknown, fallback: unknown): string {
  const direct = typeof ghsa === "string" ? ghsa.match(GHSA)?.[0] : undefined;
  const fromUrl = typeof url === "string" ? url.match(GHSA)?.[0] : undefined;
  return (direct ?? fromUrl)?.toUpperCase() ?? `NPM-${fallback}`;
}

/** The npm v6 envelope, shared by pnpm, Yarn Berry and Yarn classic. */
function parseAdvisoryMap(map: Record<string, any>): Advisory[] {
  return Object.values(map).map((a) => ({
    ecosystem: "js" as const,
    id: advisoryId(a.url, a.github_advisory_id, a.id),
    package: a.module_name ?? "unknown",
    severity: normalizeSeverity(a.severity),
    klass: "vulnerability" as const,
    title: a.title ?? "",
    fixAvailable:
      typeof a.patched_versions === "string" ? a.patched_versions !== NO_PATCH : null,
  }));
}

/**
 * npm 7+ groups by package, not by advisory.
 *
 * One entry's `via` can list several advisories, and a string in `via` is a
 * link to the package that pulled this one in rather than a finding of its
 * own. Emitting per advisory keeps the diff keyed the way every other scanner
 * is; emitting per package would collapse two GHSAs into one.
 */
function parseNpmVulnerabilities(vulns: Record<string, any>): Advisory[] {
  const out: Advisory[] = [];
  for (const [pkg, v] of Object.entries(vulns)) {
    const fix = v.fixAvailable === false ? false : v.fixAvailable ? true : null;
    for (const via of Array.isArray(v.via) ? v.via : []) {
      if (typeof via === "string") continue;
      out.push({
        ecosystem: "js",
        id: advisoryId(via.url, undefined, via.source),
        package: via.name ?? pkg,
        severity: normalizeSeverity(via.severity),
        klass: "vulnerability",
        title: via.title ?? "",
        fixAvailable: fix,
      });
    }
  }
  return out;
}

/** Bun keys by package name, with the advisories for each beneath it. */
function parseBunMap(map: Record<string, any>): Advisory[] {
  const out: Advisory[] = [];
  for (const [pkg, list] of Object.entries(map)) {
    if (!Array.isArray(list)) continue;
    for (const a of list) {
      out.push({
        ecosystem: "js",
        id: advisoryId(a.url, undefined, a.id),
        package: pkg,
        severity: normalizeSeverity(a.severity),
        klass: "vulnerability",
        title: a.title ?? "",
        fixAvailable: null,
      });
    }
  }
  return out;
}

/** Yarn classic streams one JSON object per line rather than one document. */
function parseNdjson(raw: string): Advisory[] {
  const found: Record<string, any> = {};
  for (const line of raw.split("\n")) {
    const t = line.trim();
    if (!t.startsWith("{")) continue;
    let obj: any;
    try {
      obj = JSON.parse(t);
    } catch {
      continue;
    }
    const a = obj?.type === "auditAdvisory" ? obj.data?.advisory : undefined;
    if (a) found[String(a.id)] = a;
  }
  return parseAdvisoryMap(found);
}

/**
 * Normalize whatever the manager printed, dispatching on shape rather than on
 * which binary produced it, so a manager changing envelope between versions
 * does not silently report a clean tree.
 *
 * Throws when the output is unintelligible. A scan that cannot be read is a
 * fault to surface, never an empty result to report as "no advisories".
 */
export function parseAudit(raw: string): Advisory[] {
  const t = raw.trim();
  if (!t) return [];
  if (!t.startsWith("{")) return parseNdjson(t);

  let root: any;
  try {
    root = JSON.parse(t);
  } catch {
    // A stream of objects rather than one document, which is still readable.
    const ndjson = parseNdjson(t);
    if (ndjson.length > 0) return ndjson;
    throw new Error(`audit output was not JSON: ${t.slice(0, 200)}`);
  }

  if (root.error) {
    const e = root.error;
    throw new Error(`audit failed: ${e.summary ?? e.code ?? JSON.stringify(e).slice(0, 200)}`);
  }
  if (root.advisories && typeof root.advisories === "object") {
    return parseAdvisoryMap(root.advisories);
  }
  if (root.vulnerabilities && typeof root.vulnerabilities === "object") {
    return parseNpmVulnerabilities(root.vulnerabilities);
  }
  return parseBunMap(root);
}

/**
 * Directories to audit: the root, or every workspace package.
 *
 * `bun audit --prod` does not apply the production filter at a workspace root,
 * so a monorepo audited from the top reports its devDependencies as if they
 * shipped. Auditing each package separately is what actually filters.
 */
function auditRoots(dir: string): string[] {
  const manifest = join(dir, "package.json");
  if (!existsSync(manifest)) return [];
  let globs: string[] = [];
  try {
    const pkg = JSON.parse(readFileSync(manifest, "utf8"));
    globs = Array.isArray(pkg.workspaces) ? pkg.workspaces : (pkg.workspaces?.packages ?? []);
  } catch {
    return [dir];
  }
  if (globs.length === 0) return [dir];

  const roots: string[] = [];
  for (const g of globs) {
    const base = g.endsWith("/*") ? g.slice(0, -2) : g;
    const full = join(dir, base);
    if (!existsSync(full)) continue;
    if (g.endsWith("/*")) {
      for (const entry of readdirSync(full, { withFileTypes: true })) {
        if (entry.isDirectory() && existsSync(join(full, entry.name, "package.json"))) {
          roots.push(join(full, entry.name));
        }
      }
    } else if (existsSync(join(full, "package.json"))) {
      roots.push(full);
    }
  }
  return roots.length > 0 ? roots : [dir];
}

async function auditOne(cwd: string, pm: PackageManager): Promise<Advisory[]> {
  let proc;
  try {
    proc = Bun.spawn(AUDIT_ARGV[pm], { cwd, stdout: "pipe", stderr: "pipe" });
  } catch {
    throw new Error(`${pm} is not installed, but its lockfile is present`);
  }
  const [raw, err] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
  ]);
  await proc.exited;
  if (!raw.trim() && err.trim()) {
    throw new Error(`${pm} audit produced no output: ${err.trim().slice(0, 200)}`);
  }
  return parseAudit(raw);
}

export async function scanJs(dir: string): Promise<ScanResult | null> {
  const pm = detectManager(dir);
  if (!pm) return null;

  // Only bun needs the per-package walk; the others filter correctly at a root.
  const roots = pm === "bun" ? auditRoots(dir) : [dir];
  const seen = new Map<string, Advisory>();
  for (const root of roots) {
    for (const a of await auditOne(root, pm)) {
      seen.set(`${a.id}:${a.package}`, a);
    }
  }
  return { ecosystem: "js", advisories: [...seen.values()] };
}
