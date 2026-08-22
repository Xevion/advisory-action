import { describe, expect, test } from "bun:test";
import { parseStream } from "../src/go.ts";

describe("parseStream", () => {
  // govulncheck pretty-prints concatenated objects, so a line-based parser
  // silently yields nothing rather than failing. That is the bug this guards.
  test("reads pretty-printed objects written back to back", () => {
    const raw = '{\n  "config": {\n    "a": 1\n  }\n}\n{\n  "finding": {\n    "osv": "GO-1"\n  }\n}\n';
    const out = [...parseStream<Record<string, unknown>>(raw)];
    expect(out).toHaveLength(2);
    expect(out[1]).toEqual({ finding: { osv: "GO-1" } });
  });

  test("reads compact one-per-line objects too", () => {
    const out = [...parseStream<{ a: number }>('{"a":1}\n{"a":2}\n')];
    expect(out.map((o) => o.a)).toEqual([1, 2]);
  });

  test("does not split on braces inside strings", () => {
    const out = [...parseStream<{ s: string }>('{"s":"a{b}c"}')];
    expect(out[0]!.s).toBe("a{b}c");
  });

  test("does not split on escaped quotes", () => {
    const out = [...parseStream<{ s: string }>('{"s":"he said \\"{\\" ok"}')];
    expect(out).toHaveLength(1);
    expect(out[0]!.s).toBe('he said "{" ok');
  });

  test("drops a truncated trailing object without losing earlier ones", () => {
    const out = [...parseStream<{ a: number }>('{"a":1}\n{"a":2')];
    expect(out.map((o) => o.a)).toEqual([1]);
  });
});
