import { readdirSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { Advisory, ScanResult, Severity } from "./types.ts";

interface BunAdvisory {
  id: number;
  url: string;
  title: string;
  severity: string;
  vulnerable_versions: string;
}

const GHSA = /GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}/i;

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

function normalizeSeverity(s: string): Severity {
  const v = s.toLowerCase();
  return ["critical", "high", "moderate", "low"].includes(v) ? (v as Severity) : "unknown";
}

async function auditOne(cwd: string): Promise<Advisory[]> {
  const proc = Bun.spawn(["bun", "audit", "--prod", "--json"], {
    cwd,
    stdout: "pipe",
    stderr: "ignore",
  });
  const raw = await new Response(proc.stdout).text();
  await proc.exited;
  if (!raw.trim()) return [];

  let parsed: Record<string, BunAdvisory[]>;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return [];
  }

  const out: Advisory[] = [];
  for (const [pkg, list] of Object.entries(parsed)) {
    for (const a of list) {
      out.push({
        ecosystem: "js",
        // The numeric id is not stable across advisory-db reindexes; the GHSA is.
        id: a.url?.match(GHSA)?.[0]?.toUpperCase() ?? `BUN-${a.id}`,
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

export async function scanJs(dir: string): Promise<ScanResult | null> {
  if (!existsSync(join(dir, "bun.lock")) && !existsSync(join(dir, "bun.lockb"))) {
    return null;
  }
  const seen = new Map<string, Advisory>();
  for (const root of auditRoots(dir)) {
    for (const a of await auditOne(root)) {
      seen.set(`${a.id}:${a.package}`, a);
    }
  }
  return { ecosystem: "js", advisories: [...seen.values()] };
}
