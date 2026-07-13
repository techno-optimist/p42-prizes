import snapshotJson from "@/data/erdos-frontier-atlas.v1.json";
import { createHash } from "node:crypto";
import {
  ATLAS_BOARDABILITIES,
  ATLAS_LANES,
  ATLAS_REACHES,
  ATLAS_SORTS,
  type AtlasBoardability,
  type AtlasEntry,
  type AtlasEntrySource,
  type AtlasFrontier,
  type AtlasLane,
  type AtlasListQuery,
  type AtlasMeta,
  type AtlasReach,
  type AtlasSort,
} from "@/lib/atlas-types";

const snapshot = snapshotJson as unknown as {
  snapshot_schema: string;
  provenance: {
    repository: string;
    commit: string;
    source_path: string;
    source_sha256: string;
    license: "MIT";
    attribution: string;
  };
  atlas_version: string;
  generated: string;
  source: string;
  board_class_rule: Record<AtlasBoardability, string>;
  problems: AtlasEntrySource[];
};

const DEFAULT_LIMIT = 20;
const MAX_LIMIT = 51;
const CURSOR_PREFIX = "atlas-v1:";

export class AtlasQueryError extends Error {}

export function normalizeFrontier(frontier: AtlasEntrySource["frontier"]): AtlasFrontier | undefined {
  if (frontier == null) return undefined;
  if (typeof frontier === "string") {
    const summary = frontier.trim();
    return summary ? { summary } : undefined;
  }
  const summary = frontier.value.trim();
  if (!summary) return undefined;
  return {
    summary,
    value: frontier.value,
    holder: frontier.holder,
    year: frontier.year,
    ...(frontier.note ? { note: frontier.note } : {}),
  };
}

function normalizeEntry(source: AtlasEntrySource): AtlasEntry {
  const { frontier, p42_slug, ...entry } = source;
  const normalizedFrontier = normalizeFrontier(frontier);
  return {
    ...entry,
    ...(normalizedFrontier ? { frontier: normalizedFrontier } : {}),
    ...(p42_slug ? { p42_slug } : {}),
  };
}

export const atlasEntries: readonly AtlasEntry[] = Object.freeze(
  snapshot.problems.map((problem) => Object.freeze(normalizeEntry(problem))),
);

const byId = new Map(atlasEntries.map((entry) => [entry.id, entry]));

export function getAtlasEntry(id: number): AtlasEntry | undefined {
  return byId.get(id);
}

function parseEnum<T extends string>(name: string, value: string | null, allowed: readonly T[]): T | undefined {
  if (value === null || value === "") return undefined;
  if (!allowed.includes(value as T)) throw new AtlasQueryError(`invalid ${name}`);
  return value as T;
}

function parseBoolean(value: string | null): boolean | undefined {
  if (value === null || value === "") return undefined;
  if (value === "true") return true;
  if (value === "false") return false;
  throw new AtlasQueryError("invalid p42");
}

function parseLimit(value: string | null): number | undefined {
  if (value === null || value === "") return undefined;
  if (!/^\d+$/.test(value)) throw new AtlasQueryError("invalid limit");
  const limit = Number(value);
  if (limit < 1 || limit > MAX_LIMIT) throw new AtlasQueryError(`limit must be between 1 and ${MAX_LIMIT}`);
  return limit;
}

export function parseAtlasListQuery(params: URLSearchParams): AtlasListQuery {
  for (const name of ["q", "boardability", "reach", "lane", "p42", "sort", "limit", "cursor"]) {
    if (params.getAll(name).length > 1) throw new AtlasQueryError(`${name} may only be supplied once`);
  }
  const q = params.get("q")?.trim();
  if (q && q.length > 200) throw new AtlasQueryError("q must be at most 200 characters");
  return {
    ...(q ? { q } : {}),
    boardability: parseEnum("boardability", params.get("boardability"), ATLAS_BOARDABILITIES),
    reach: parseEnum("reach", params.get("reach"), ATLAS_REACHES),
    lane: parseEnum("lane", params.get("lane"), ATLAS_LANES),
    p42: parseBoolean(params.get("p42")),
    sort: parseEnum("sort", params.get("sort"), ATLAS_SORTS),
    limit: parseLimit(params.get("limit")),
    ...(params.get("cursor") ? { cursor: params.get("cursor")! } : {}),
  };
}

function queryFingerprint(query: AtlasListQuery): string {
  const canonical = JSON.stringify({
    q: query.q?.trim().toLocaleLowerCase("en") ?? "",
    boardability: query.boardability ?? null,
    reach: query.reach ?? null,
    lane: query.lane ?? null,
    p42: query.p42 ?? null,
    sort: query.sort ?? "id",
    limit: query.limit ?? DEFAULT_LIMIT,
  });
  return createHash("sha256").update(canonical).digest("base64url").slice(0, 16);
}

function decodeCursor(cursor: string | undefined, fingerprint: string): number {
  if (!cursor) return 0;
  try {
    const decoded = Buffer.from(cursor, "base64url").toString("utf8");
    if (!decoded.startsWith(CURSOR_PREFIX)) throw new Error();
    const [cursorFingerprint, offsetText, extra] = decoded.slice(CURSOR_PREFIX.length).split(":");
    if (extra !== undefined || cursorFingerprint !== fingerprint) throw new Error();
    if (!/^\d+$/.test(offsetText)) throw new Error();
    return Number(offsetText);
  } catch {
    throw new AtlasQueryError("invalid cursor");
  }
}

function encodeCursor(offset: number, fingerprint: string): string {
  return Buffer.from(`${CURSOR_PREFIX}${fingerprint}:${offset}`, "utf8").toString("base64url");
}

function compareEntries(sort: AtlasSort) {
  return (left: AtlasEntry, right: AtlasEntry) => {
    let comparison = 0;
    if (sort === "title") comparison = left.title.localeCompare(right.title, "en");
    if (sort === "fit") comparison = right.fit_score - left.fit_score;
    if (sort === "impact") comparison = right.impact_score - left.impact_score;
    return comparison || left.id - right.id;
  };
}

export function listAtlasEntries(query: AtlasListQuery = {}) {
  const needle = query.q?.toLocaleLowerCase("en");
  const filtered = atlasEntries.filter((entry) => {
    if (query.boardability && entry.board_class !== query.boardability) return false;
    if (query.reach && entry.beatable !== query.reach) return false;
    if (query.lane && entry.lane !== query.lane) return false;
    if (query.p42 !== undefined && Boolean(entry.p42_slug) !== query.p42) return false;
    if (!needle) return true;
    return [
      entry.title,
      entry.statement,
      entry.finite_object,
      entry.current_record,
      entry.frontier?.summary,
      entry.verifier,
      entry.attack,
    ].some((value) => value?.toLocaleLowerCase("en").includes(needle));
  }).sort(compareEntries(query.sort ?? "id"));

  const fingerprint = queryFingerprint(query);
  const offset = decodeCursor(query.cursor, fingerprint);
  if (offset > filtered.length) throw new AtlasQueryError("cursor is past the result set");
  const limit = query.limit ?? DEFAULT_LIMIT;
  const items = filtered.slice(offset, offset + limit);
  const nextOffset = offset + items.length;
  return {
    items,
    total: filtered.length,
    limit,
    next_cursor: nextOffset < filtered.length ? encodeCursor(nextOffset, fingerprint) : null,
  };
}

function countBy<T extends string>(values: readonly T[], select: (entry: AtlasEntry) => T): Record<T, number> {
  return Object.fromEntries(values.map((value) => [value, atlasEntries.filter((entry) => select(entry) === value).length])) as Record<T, number>;
}

export function getAtlasMeta(): AtlasMeta {
  const p42Count = atlasEntries.filter((entry) => entry.p42_slug).length;
  return {
    snapshot_schema: snapshot.snapshot_schema,
    atlas_version: snapshot.atlas_version,
    generated: snapshot.generated,
    source: snapshot.source,
    total: atlasEntries.length,
    facets: {
      boardability: countBy(ATLAS_BOARDABILITIES, (entry) => entry.board_class),
      reach: countBy(ATLAS_REACHES, (entry) => entry.beatable),
      lane: countBy(ATLAS_LANES, (entry) => entry.lane),
      p42: { true: p42Count, false: atlasEntries.length - p42Count },
    },
    board_class_rule: snapshot.board_class_rule,
    provenance: {
      repository: snapshot.provenance.repository,
      commit: snapshot.provenance.commit,
      path: snapshot.provenance.source_path,
      sha256: snapshot.provenance.source_sha256,
      license: snapshot.provenance.license,
      copyright: snapshot.provenance.attribution,
    },
    settlement_authority: false,
  };
}
