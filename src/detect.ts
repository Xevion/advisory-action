import { appendFileSync } from "node:fs";
import { discover } from "./discover.ts";

/**
 * Which toolchains the scan will actually need, written as step outputs.
 *
 * This shares `discover` with the scanner on purpose: checking only the
 * repository root here would skip cargo-audit for a Tauri app whose manifest
 * lives in `src-tauri/`, and the scan would then report that crate as clean.
 */
const present = {
  go: discover(".", ["go.mod"]).length > 0,
  rust: discover(".", ["Cargo.lock"]).length > 0,
};

const out = Object.entries(present)
  .map(([k, v]) => `${k}=${v}`)
  .join("\n");

console.log(out);
if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `${out}\n`);
