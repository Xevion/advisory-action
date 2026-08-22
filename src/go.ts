import { existsSync } from "node:fs";
import { join } from "node:path";
import type { Advisory, ScanResult } from "./types.ts";

interface Frame {
  module?: string;
  package?: string;
  function?: string;
}

interface Finding {
  osv: string;
  fixed_version?: string;
  trace?: Frame[];
}

interface Osv {
  id: string;
  summary?: string;
}

/**
 * Findings whose innermost frame names a function.
 *
 * govulncheck also emits findings for modules merely required and packages
 * merely imported. Those are what its own summary sets aside as "your code
 * doesn't appear to call these", and reporting them throws away the single
 * thing that makes this scanner worth gating on.
 */
function isReachable(f: Finding): boolean {
  return Boolean(f.trace?.[0]?.function);
}

/**
 * Split govulncheck's output into its top-level JSON values.
 *
 * The stream is pretty-printed objects written back to back, not one per line,
 * so it has to be walked by brace depth rather than split on newlines.
 */
export function* parseStream<T>(raw: string): Generator<T> {
  let depth = 0;
  let start = -1;
  let inString = false;
  let escaped = false;

  for (let i = 0; i < raw.length; i++) {
    const c = raw[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (c === "\\") escaped = true;
      else if (c === '"') inString = false;
      continue;
    }
    if (c === '"') inString = true;
    else if (c === "{") {
      if (depth === 0) start = i;
      depth++;
    } else if (c === "}") {
      depth--;
      if (depth === 0 && start >= 0) {
        try {
          yield JSON.parse(raw.slice(start, i + 1)) as T;
        } catch {
          // A truncated tail is not worth failing the whole scan over.
        }
        start = -1;
      }
    }
  }
}

export async function scanGo(dir: string): Promise<ScanResult | null> {
  if (!existsSync(join(dir, "go.mod"))) return null;

  const proc = Bun.spawn(["govulncheck", "-format", "json", "./..."], {
    cwd: dir,
    stdout: "pipe",
    stderr: "pipe",
  });
  const [raw, err, code] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ]);

  // JSON mode reports findings in the stream, never through the exit code, so a
  // non-zero status here means govulncheck itself could not run.
  if (code !== 0) {
    return {
      ecosystem: "go",
      advisories: [],
      error: err.trim().split("\n").pop() ?? `govulncheck exited ${code}`,
    };
  }

  const summaries = new Map<string, string>();
  const findings = new Map<string, Finding>();
  for (const msg of parseStream<{ osv?: Osv; finding?: Finding }>(raw)) {
    if (msg.osv?.id) summaries.set(msg.osv.id, msg.osv.summary ?? "");
    // One finding per call path, so many share an id; the first reachable wins.
    if (msg.finding && isReachable(msg.finding) && !findings.has(msg.finding.osv)) {
      findings.set(msg.finding.osv, msg.finding);
    }
  }

  const advisories: Advisory[] = [...findings.values()].map((f) => ({
    ecosystem: "go",
    id: f.osv,
    package: f.trace?.[0]?.module ?? f.trace?.[0]?.package ?? "unknown",
    // Go's OSV records carry no CVSS, and inventing one would be worse than
    // admitting the scanner does not rank.
    severity: "unknown",
    klass: "vulnerability",
    title: summaries.get(f.osv) ?? f.osv,
    fixAvailable: Boolean(f.fixed_version),
  }));

  return { ecosystem: "go", advisories };
}
