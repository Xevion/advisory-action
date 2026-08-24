import { describe, expect, test } from "bun:test";
import { compare, selectBlocking } from "../src/diff.ts";
import type { Advisory, AdvisoryClass, Ecosystem, ScanResult } from "../src/types.ts";

function adv(
  ecosystem: Ecosystem,
  id: string,
  klass: AdvisoryClass = "vulnerability",
  fixAvailable: boolean | null = true,
): Advisory {
  return { ecosystem, id, package: "pkg", severity: "high", klass, title: id, fixAvailable };
}

const noIgnores = { active: new Map(), expired: [] };
const result = (ecosystem: Ecosystem, advisories: Advisory[]): ScanResult => ({
  ecosystem,
  advisories,
});

describe("selectBlocking", () => {
  test("go blocks on anything introduced, since govulncheck proved reachability", () => {
    const found = [adv("go", "GO-1"), adv("go", "GO-2", "vulnerability", false)];
    expect(selectBlocking("go", found)).toHaveLength(2);
  });

  test("rust blocks on vulnerabilities but not on unsound, unmaintained or yanked", () => {
    const found = [
      adv("rust", "RUSTSEC-1", "vulnerability"),
      adv("rust", "RUSTSEC-2", "unsound"),
      adv("rust", "RUSTSEC-3", "unmaintained"),
      adv("rust", "YANKED-spin", "yanked"),
    ];
    expect(selectBlocking("rust", found).map((a) => a.id)).toEqual(["RUSTSEC-1"]);
  });

  test("rust does not block on a vulnerability with no published fix", () => {
    const found = [adv("rust", "RUSTSEC-1", "vulnerability", false)];
    expect(selectBlocking("rust", found)).toHaveLength(0);
  });

  test("js never blocks, whatever the severity", () => {
    const found = [adv("js", "GHSA-1"), adv("js", "GHSA-2")];
    expect(selectBlocking("js", found)).toHaveLength(0);
  });
});

describe("compare", () => {
  test("attributes only what the base branch lacks", () => {
    const head = [result("go", [adv("go", "GO-1"), adv("go", "GO-2")])];
    const base = [result("go", [adv("go", "GO-1")])];
    const [v] = compare(head, base, noIgnores);
    expect(v!.introduced.map((a) => a.id)).toEqual(["GO-2"]);
    expect(v!.inherited.map((a) => a.id)).toEqual(["GO-1"]);
    expect(v!.blocking.map((a) => a.id)).toEqual(["GO-2"]);
  });

  test("an advisory the base already carried never blocks", () => {
    const shared = [adv("go", "GO-1")];
    const [v] = compare([result("go", shared)], [result("go", shared)], noIgnores);
    expect(v!.introduced).toHaveLength(0);
    expect(v!.blocking).toHaveLength(0);
  });

  test("without a baseline nothing is attributed and nothing blocks", () => {
    const [v] = compare([result("go", [adv("go", "GO-1")])], null, noIgnores);
    expect(v!.baselineKnown).toBe(false);
    expect(v!.introduced).toHaveLength(0);
    expect(v!.blocking).toHaveLength(0);
    expect(v!.inherited).toHaveLength(1);
  });

  test("an ignored advisory cannot block even when newly introduced", () => {
    const ignores = {
      active: new Map([["GO-2", { id: "GO-2", reason: "upstream fix pending" }]]),
      expired: [],
    };
    const [v] = compare(
      [result("go", [adv("go", "GO-1"), adv("go", "GO-2")])],
      [result("go", [adv("go", "GO-1")])],
      ignores,
    );
    expect(v!.blocking).toHaveLength(0);
    expect(v!.suppressed.map((a) => a.id)).toEqual(["GO-2"]);
  });

  test("an ecosystem missing from the base is treated as all-new", () => {
    const [v] = compare([result("rust", [adv("rust", "RUSTSEC-1")])], [], noIgnores);
    expect(v!.introduced).toHaveLength(1);
    expect(v!.blocking).toHaveLength(1);
  });
});

describe("resolved", () => {
  test("credits advisories the change clears without counting them as introduced", () => {
    const base = [result("js", [adv("js", "GHSA-1"), adv("js", "GHSA-2")])];
    const head = [result("js", [adv("js", "GHSA-2")])];
    const [v] = compare(head, base, noIgnores);
    expect(v.resolved.map((a) => a.id)).toEqual(["GHSA-1"]);
    expect(v.introduced).toHaveLength(0);
    expect(v.inherited.map((a) => a.id)).toEqual(["GHSA-2"]);
  });

  test("a change can resolve and introduce at once", () => {
    const base = [result("go", [adv("go", "GO-1")])];
    const head = [result("go", [adv("go", "GO-2")])];
    const [v] = compare(head, base, noIgnores);
    expect(v.resolved.map((a) => a.id)).toEqual(["GO-1"]);
    expect(v.blocking.map((a) => a.id)).toEqual(["GO-2"]);
  });

  test("nothing is resolved without a baseline to compare against", () => {
    const head = [result("js", [adv("js", "GHSA-1")])];
    const [v] = compare(head, null, noIgnores);
    expect(v.resolved).toHaveLength(0);
    expect(v.baselineKnown).toBe(false);
  });
});
