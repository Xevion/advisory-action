import { existsSync } from "node:fs";
import { join } from "node:path";
import type { Advisory, AdvisoryClass, ScanResult, Severity } from "./types.ts";

interface CargoAdvisory {
  id: string;
  title?: string;
  severity?: string | null;
}

interface Entry {
  kind?: string;
  package?: { name?: string };
  advisory?: CargoAdvisory | null;
  versions?: { patched?: string[] } | null;
}

interface AuditJson {
  vulnerabilities?: { list?: Entry[] };
  warnings?: Record<string, Entry[]>;
}

const WARNING_CLASSES: Record<string, AdvisoryClass> = {
  unmaintained: "unmaintained",
  unsound: "unsound",
  yanked: "yanked",
  notice: "notice",
};

function toAdvisory(e: Entry, klass: AdvisoryClass): Advisory {
  const pkg = e.package?.name ?? "unknown";
  const patched = e.versions?.patched ?? [];
  const sev = e.advisory?.severity?.toLowerCase();
  return {
    ecosystem: "rust",
    // A yanked crate has no advisory of its own, so the package identifies it.
    id: e.advisory?.id ?? `YANKED-${pkg}`,
    package: pkg,
    severity: (["critical", "high", "moderate", "low"].includes(sev ?? "")
      ? sev
      : "unknown") as Severity,
    klass,
    title: e.advisory?.title ?? (klass === "yanked" ? `${pkg} was yanked` : klass),
    fixAvailable: patched.length > 0,
  };
}

export async function scanRust(dir: string): Promise<ScanResult | null> {
  if (!existsSync(join(dir, "Cargo.lock"))) return null;

  const proc = Bun.spawn(["cargo", "audit", "--json"], {
    cwd: dir,
    stdout: "pipe",
    stderr: "pipe",
  });
  const [raw, err] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
  ]);
  await proc.exited;

  // cargo-audit exits 1 whenever it finds a vulnerability, so the exit code says
  // nothing about whether it ran. Empty stdout is what a real failure looks like.
  if (!raw.trim()) {
    return {
      ecosystem: "rust",
      advisories: [],
      error: err.trim().split("\n").pop() ?? "cargo audit produced no output",
    };
  }

  let parsed: AuditJson;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    return { ecosystem: "rust", advisories: [], error: `unparseable cargo audit output: ${e}` };
  }

  const advisories = [
    ...(parsed.vulnerabilities?.list ?? []).map((e) => toAdvisory(e, "vulnerability")),
    ...Object.entries(parsed.warnings ?? {}).flatMap(([kind, list]) =>
      (list ?? []).map((e) => toAdvisory(e, WARNING_CLASSES[kind] ?? "notice")),
    ),
  ];

  const seen = new Map<string, Advisory>();
  for (const a of advisories) seen.set(`${a.id}:${a.package}`, a);
  return { ecosystem: "rust", advisories: [...seen.values()] };
}
