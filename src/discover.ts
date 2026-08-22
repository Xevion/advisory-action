import { readdirSync } from "node:fs";
import { join } from "node:path";

/** Never worth descending into: vendored trees and build output. */
const SKIP = new Set([
  "node_modules", "target", "vendor", "dist", "build", ".git",
  ".svelte-kit", ".next", ".venv", "coverage",
]);

/**
 * Directories containing any of `markers`, searched to a bounded depth.
 *
 * Repositories here routinely put a frontend under `web/` beside a root
 * `go.mod` or `Cargo.toml`, and scanning only the root silently reports that
 * frontend as clean.
 */
export function discover(root: string, markers: string[], maxDepth = 2): string[] {
  const found: string[] = [];

  const walk = (dir: string, depth: number) => {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    if (entries.some((e) => e.isFile() && markers.includes(e.name))) found.push(dir);
    if (depth >= maxDepth) return;
    for (const e of entries) {
      if (e.isDirectory() && !SKIP.has(e.name) && !e.name.startsWith(".")) {
        walk(join(dir, e.name), depth + 1);
      }
    }
  };

  walk(root, 0);
  return found;
}
