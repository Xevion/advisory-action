import { describe, expect, test } from "bun:test";
import { parseAudit } from "../src/js.ts";

// Trimmed from real `pnpm audit --prod --json` output in a Tauri project.
const PNPM = JSON.stringify({
  advisories: {
    "1130709": {
      id: 1130709,
      title: "PostCSS: attacker-controlled sourceMappingURL reads arbitrary .map files",
      module_name: "postcss",
      vulnerable_versions: "<8.5.16",
      patched_versions: ">=8.5.16",
      severity: "moderate",
      github_advisory_id: "GHSA-6g55-p6wh-862q",
      url: "https://github.com/advisories/GHSA-6g55-p6wh-862q",
    },
  },
  metadata: {},
});

// Trimmed from real `npm audit --omit=dev --package-lock-only --json` output.
const NPM_V2 = JSON.stringify({
  auditReportVersion: 2,
  vulnerabilities: {
    minimist: {
      name: "minimist",
      severity: "critical",
      isDirect: true,
      via: [
        {
          source: 1096465,
          name: "minimist",
          title: "Prototype Pollution in minimist",
          url: "https://github.com/advisories/GHSA-vh95-rmgr-6w4m",
          severity: "moderate",
          range: ">=1.0.0 <1.2.3",
        },
        {
          source: 1097678,
          name: "minimist",
          title: "Prototype Pollution in minimist",
          url: "https://github.com/advisories/GHSA-xvch-5gv4-984h",
          severity: "critical",
          range: ">=1.0.0 <1.2.6",
        },
      ],
      fixAvailable: { name: "minimist", version: "1.2.8", isSemVerMajor: false },
    },
  },
});

const YARN_CLASSIC = [
  JSON.stringify({ type: "auditSummary", data: { vulnerabilities: {} } }),
  JSON.stringify({
    type: "auditAdvisory",
    data: {
      advisory: {
        id: 1234,
        title: "Denial of service in ws",
        module_name: "ws",
        severity: "high",
        patched_versions: ">=8.17.1",
        github_advisory_id: "GHSA-3h5v-q93c-6h6q",
        url: "https://github.com/advisories/GHSA-3h5v-q93c-6h6q",
      },
    },
  }),
].join("\n");

describe("parseAudit", () => {
  test("reads the npm v6 envelope that pnpm and Yarn Berry share", () => {
    const [a] = parseAudit(PNPM);
    expect(a.id).toBe("GHSA-6G55-P6WH-862Q");
    expect(a.package).toBe("postcss");
    expect(a.severity).toBe("moderate");
    expect(a.fixAvailable).toBe(true);
  });

  test("emits one advisory per via entry, not one per package", () => {
    const found = parseAudit(NPM_V2);
    expect(found.map((a) => a.id).sort()).toEqual([
      "GHSA-VH95-RMGR-6W4M",
      "GHSA-XVCH-5GV4-984H",
    ]);
    expect(found.every((a) => a.package === "minimist")).toBe(true);
    expect(found.every((a) => a.fixAvailable === true)).toBe(true);
  });

  test("keeps per-advisory severity rather than the package's aggregate", () => {
    const found = parseAudit(NPM_V2);
    expect(found.map((a) => a.severity).sort()).toEqual(["critical", "moderate"]);
  });

  test("skips string via entries, which name a dependant not an advisory", () => {
    const raw = JSON.stringify({
      vulnerabilities: {
        vite: { name: "vite", via: ["esbuild"], fixAvailable: false },
      },
    });
    expect(parseAudit(raw)).toHaveLength(0);
  });

  test("reads Yarn classic's line-delimited stream", () => {
    const [a] = parseAudit(YARN_CLASSIC);
    expect(a.id).toBe("GHSA-3H5V-Q93C-6H6Q");
    expect(a.package).toBe("ws");
  });

  test("reads bun's package-keyed map", () => {
    const raw = JSON.stringify({
      svelte: [
        {
          id: 7,
          url: "https://github.com/advisories/GHSA-2q3v-9r32-9prf",
          title: "Svelte SSR XSS",
          severity: "high",
        },
      ],
    });
    const [a] = parseAudit(raw);
    expect(a.id).toBe("GHSA-2Q3V-9R32-9PRF");
    expect(a.package).toBe("svelte");
  });

  test("reports no patched release as no fix, rather than as unknown", () => {
    const raw = JSON.stringify({
      advisories: {
        "1": { id: 1, module_name: "left-pad", severity: "low", patched_versions: "<0.0.0" },
      },
    });
    expect(parseAudit(raw)[0].fixAvailable).toBe(false);
  });

  test("an empty audit is clean, not a fault", () => {
    expect(parseAudit("")).toEqual([]);
    expect(parseAudit(JSON.stringify({ advisories: {}, metadata: {} }))).toEqual([]);
    expect(parseAudit(JSON.stringify({ auditReportVersion: 2, vulnerabilities: {} }))).toEqual([]);
  });

  test("throws on a manager error rather than reporting a clean tree", () => {
    const raw = JSON.stringify({
      error: { code: "ENOLOCK", summary: "This command requires an existing lockfile." },
    });
    expect(() => parseAudit(raw)).toThrow(/ENOLOCK|lockfile/);
  });

  test("throws on unintelligible output rather than swallowing it", () => {
    expect(() => parseAudit("{not json at all")).toThrow(/not JSON/);
  });
});
