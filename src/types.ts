export type Ecosystem = "js" | "rust" | "go";

/** Advisory classes, ordered loosely by how much they say about your program. */
export type AdvisoryClass =
  | "vulnerability"
  | "unsound"
  | "unmaintained"
  | "yanked"
  | "notice";

export type Severity = "critical" | "high" | "moderate" | "low" | "unknown";

export interface Advisory {
  ecosystem: Ecosystem;
  /** GHSA-…, RUSTSEC-…, or GO-… . Stable across runs, so it is the diff key. */
  id: string;
  package: string;
  severity: Severity;
  klass: AdvisoryClass;
  title: string;
  /** null when the scanner does not report patched versions. */
  fixAvailable: boolean | null;
}

export interface ScanResult {
  ecosystem: Ecosystem;
  advisories: Advisory[];
  /** Set when the scanner could not run; the ecosystem is then reported unknown, not clean. */
  error?: string;
}

/**
 * How much a given ecosystem's signal is trusted, which decides what can block.
 *
 * Go earns `blocking` because govulncheck proves reachability against a call
 * graph. Rust gates on the vulnerability class alone. JS has no reachability
 * analysis available at any price we accept, so it only ever reports.
 */
export type Tier = "blocking" | "vulnerability-only" | "report-only";

export const TIERS: Record<Ecosystem, Tier> = {
  go: "blocking",
  rust: "vulnerability-only",
  js: "report-only",
};

export const SEVERITY_ORDER: Severity[] = [
  "critical",
  "high",
  "moderate",
  "low",
  "unknown",
];

export function key(a: Advisory): string {
  return `${a.ecosystem}:${a.id}:${a.package}`;
}
