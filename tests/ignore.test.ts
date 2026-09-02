import { describe, expect, test } from "bun:test";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  isIgnored,
  loadIgnores,
  resolveIgnorePath,
  unusedIgnores,
} from "../src/ignore.ts";
import type { Advisory } from "../src/types.ts";

const NOW = new Date("2026-01-01T00:00:00Z");

function adv(id: string): Advisory {
  return {
    ecosystem: "rust",
    id,
    package: "pkg",
    severity: "high",
    klass: "vulnerability",
    title: id,
    fixAvailable: true,
  };
}

/** Write `files` into a throwaway directory and run `fn` with it as cwd. */
function inRepo<T>(files: Record<string, string>, fn: () => T): T {
  const dir = mkdtempSync(join(tmpdir(), "advisory-ignore-"));
  const cwd = process.cwd();
  try {
    for (const [name, body] of Object.entries(files)) {
      mkdirSync(join(dir, ".github"), { recursive: true });
      writeFileSync(join(dir, name), body);
    }
    process.chdir(dir);
    return fn();
  } finally {
    process.chdir(cwd);
    rmSync(dir, { recursive: true, force: true });
  }
}

describe("loadIgnores", () => {
  test("reads JSON5 comments and trailing commas", () => {
    const set = inRepo(
      {
        ".github/advisories.json5":
          '{\n  // transitive via gpui, upstream tracked\n  ignore: [{ id: "RUSTSEC-1" },],\n}\n',
      },
      () => loadIgnores(resolveIgnorePath(""), NOW),
    );
    expect([...set.active.keys()]).toEqual(["RUSTSEC-1"]);
  });

  test("accepts an entry with no reason", () => {
    const set = inRepo(
      { ".github/advisories.json5": '[{ id: "RUSTSEC-1" }]' },
      () => loadIgnores(resolveIgnorePath(""), NOW),
    );
    expect(set.active.get("RUSTSEC-1")?.reason).toBeUndefined();
    expect(isIgnored(adv("RUSTSEC-1"), set)).toBe(true);
  });

  test("a past expiry stops suppressing and is reported", () => {
    const set = inRepo(
      { ".github/advisories.json5": '[{ id: "RUSTSEC-1", expires: "2025-06-01" }]' },
      () => loadIgnores(resolveIgnorePath(""), NOW),
    );
    expect(set.active.size).toBe(0);
    expect(set.expired.map((e) => e.id)).toEqual(["RUSTSEC-1"]);
    expect(isIgnored(adv("RUSTSEC-1"), set)).toBe(false);
  });
});

describe("resolveIgnorePath", () => {
  test("prefers json5 and rejects a repository carrying both", () => {
    expect(
      inRepo({ ".github/advisories.json": "[]" }, () => resolveIgnorePath("")),
    ).toBe(".github/advisories.json");

    expect(() =>
      inRepo(
        { ".github/advisories.json5": "[]", ".github/advisories.json": "[]" },
        () => resolveIgnorePath(""),
      ),
    ).toThrow(/both exist/);
  });

  test("no ignore file is not an error", () => {
    expect(inRepo({}, () => resolveIgnorePath(""))).toBeNull();
  });
});

describe("unusedIgnores", () => {
  test("reports only entries that suppressed nothing", () => {
    const set = inRepo(
      { ".github/advisories.json5": '[{ id: "RUSTSEC-1" }, { id: "RUSTSEC-2" }]' },
      () => loadIgnores(resolveIgnorePath(""), NOW),
    );
    isIgnored(adv("RUSTSEC-1"), set);
    expect(unusedIgnores(set).map((e) => e.id)).toEqual(["RUSTSEC-2"]);
  });
});
