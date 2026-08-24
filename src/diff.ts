import { key, TIERS, type Advisory, type Ecosystem, type ScanResult } from "./types.ts";
import { isIgnored, type IgnoreSet } from "./ignore.ts";

export interface Verdict {
  ecosystem: Ecosystem;
  introduced: Advisory[];
  inherited: Advisory[];
  resolved: Advisory[];
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
export function selectBlocking(eco: Ecosystem, introduced: Advisory[]): Advisory[] {
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

export function compare(
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
        resolved: [],
        suppressed,
        blocking: [],
        baselineKnown: false,
        error: h.error,
      };
    }

    const baseAdvisories =
      base.find((b) => b.ecosystem === h.ecosystem)?.advisories ?? [];
    const baseKeys = new Set(baseAdvisories.map(key));
    const headKeys = new Set(kept.map(key));
    const introduced = kept.filter((a) => !baseKeys.has(key(a)));
    const inherited = kept.filter((a) => baseKeys.has(key(a)));
    // Credit for advisories a change clears. Without it a security bump reads
    // exactly like an unrelated one, which is what made them unevaluable.
    const resolved = baseAdvisories.filter(
      (a) => !headKeys.has(key(a)) && !isIgnored(a, ignores),
    );
    return {
      ecosystem: h.ecosystem,
      introduced,
      inherited,
      resolved,
      suppressed,
      blocking: selectBlocking(h.ecosystem, introduced),
      baselineKnown: true,
      error: h.error,
    };
  });
}

