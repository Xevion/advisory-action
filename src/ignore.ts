import { existsSync, readFileSync } from "node:fs";
import type { Advisory } from "./types.ts";

export interface IgnoreEntry {
  id: string;
  reason: string;
  /** ISO date. Past this, the entry stops suppressing and is reported as stale. */
  expires?: string;
}

export interface IgnoreSet {
  active: Map<string, IgnoreEntry>;
  expired: IgnoreEntry[];
}

export function loadIgnores(path: string, now: Date): IgnoreSet {
  const active = new Map<string, IgnoreEntry>();
  const expired: IgnoreEntry[] = [];
  if (!existsSync(path)) return { active, expired };

  let entries: IgnoreEntry[];
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8"));
    entries = Array.isArray(parsed) ? parsed : (parsed.ignore ?? []);
  } catch (e) {
    throw new Error(`could not parse ignore file ${path}: ${e}`);
  }

  for (const e of entries) {
    if (!e?.id) continue;
    if (!e.reason?.trim()) {
      throw new Error(`ignore entry ${e.id} has no reason`);
    }
    if (e.expires && new Date(e.expires) < now) expired.push(e);
    else active.set(e.id.toUpperCase(), e);
  }
  return { active, expired };
}

export function isIgnored(a: Advisory, ignores: IgnoreSet): boolean {
  return ignores.active.has(a.id.toUpperCase());
}
