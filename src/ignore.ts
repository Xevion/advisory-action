import { existsSync, readFileSync } from "node:fs";
import type { Advisory } from "./types.ts";

export interface IgnoreEntry {
  id: string;
  /** Optional. The file is JSON5, so a comment beside the entry says this better. */
  reason?: string;
  /** ISO date. Past this, the entry stops suppressing and is reported as stale. */
  expires?: string;
}

export interface IgnoreSet {
  active: Map<string, IgnoreEntry>;
  expired: IgnoreEntry[];
  /** Ids that suppressed something, so the remainder can be reported as dead. */
  used: Set<string>;
  path: string | null;
}

/** Both spellings parse the same; two files would only disagree silently. */
const CANDIDATES = [".github/advisories.json5", ".github/advisories.json"];

export function resolveIgnorePath(explicit: string): string | null {
  if (explicit) return existsSync(explicit) ? explicit : null;
  const found = CANDIDATES.filter((p) => existsSync(p));
  if (found.length > 1) throw new Error(`${found.join(" and ")} both exist; keep one`);
  return found[0] ?? null;
}

export function loadIgnores(path: string | null, now: Date): IgnoreSet {
  const set: IgnoreSet = { active: new Map(), expired: [], used: new Set(), path };
  if (!path) return set;

  let entries: IgnoreEntry[];
  try {
    const parsed = Bun.JSON5.parse(readFileSync(path, "utf8")) as
      | IgnoreEntry[]
      | { ignore?: IgnoreEntry[] };
    entries = Array.isArray(parsed) ? parsed : (parsed?.ignore ?? []);
  } catch (e) {
    throw new Error(`could not parse ignore file ${path}: ${e}`);
  }

  for (const e of entries) {
    if (!e?.id) continue;
    if (e.expires && new Date(e.expires) < now) set.expired.push(e);
    else set.active.set(e.id.toUpperCase(), e);
  }
  return set;
}

export function isIgnored(a: Advisory, ignores: IgnoreSet): boolean {
  const id = a.id.toUpperCase();
  if (!ignores.active.has(id)) return false;
  ignores.used.add(id);
  return true;
}

/** Entries that suppressed nothing, and so can go. */
export function unusedIgnores(ignores: IgnoreSet): IgnoreEntry[] {
  return [...ignores.active]
    .filter(([id]) => !ignores.used.has(id))
    .map(([, entry]) => entry);
}
