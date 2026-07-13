export const ATLAS_BOARDABILITIES = ["READY", "HEAVY", "NONE"] as const;
export const ATLAS_REACHES = ["MOVABLE", "UNKNOWN", "WALL"] as const;
export const ATLAS_LANES = [
  "SAT+DRAT-nonexistence",
  "exact-backtracking",
  "witness-local-search",
  "LP/SDP-certificate",
  "wall",
] as const;
export const ATLAS_SORTS = ["id", "title", "fit", "impact"] as const;

export type AtlasBoardability = (typeof ATLAS_BOARDABILITIES)[number];
export type AtlasReach = (typeof ATLAS_REACHES)[number];
export type AtlasLane = (typeof ATLAS_LANES)[number];
export type AtlasSort = (typeof ATLAS_SORTS)[number];

export interface AtlasFrontierObject {
  value: string;
  holder: string;
  year: number;
  note?: string;
}

export type AtlasSourceFrontier = string | AtlasFrontierObject | null;

export interface AtlasFrontier {
  summary: string;
  value?: string;
  holder?: string;
  year?: number;
  note?: string;
}

export interface AtlasLinks {
  oeis?: string[];
  arxiv?: string[];
}

export interface AtlasEntrySource {
  id: number;
  title: string;
  prize?: string | null;
  statement: string;
  finite_object: string;
  current_record: string;
  frontier?: AtlasSourceFrontier;
  beatable: AtlasReach;
  beatable_reason?: string;
  fit_score: number;
  impact_score: number;
  impact_reason?: string;
  verifier: string;
  attack: string;
  our_edge?: string;
  campaign_finding?: string;
  verdict?: string;
  lane: AtlasLane;
  board_class: AtlasBoardability;
  board_class_reason: string;
  wall_reason?: string | null;
  p42_slug?: string | null;
  erdos_url: string;
  links: AtlasLinks;
  evidence?: unknown;
  compute?: unknown;
}

export interface AtlasEntry extends Omit<AtlasEntrySource, "frontier"> {
  frontier?: AtlasFrontier;
  /** Join hint only. This is never evidence of funding, eligibility, or settlement state. */
  p42_slug?: string;
  /** Explicit upstream evidence only. Never inferred from prose. */
  evidence?: unknown;
  /** Explicit upstream compute coverage only. Never inferred from prose. */
  compute?: unknown;
}

export interface AtlasProvenance {
  repository: string;
  commit: string;
  path: string;
  sha256: string;
  license: "MIT";
  copyright: string;
}

export interface AtlasListQuery {
  q?: string;
  boardability?: AtlasBoardability;
  reach?: AtlasReach;
  lane?: AtlasLane;
  p42?: boolean;
  sort?: AtlasSort;
  limit?: number;
  cursor?: string;
}

export interface AtlasMeta {
  snapshot_schema: string;
  atlas_version: string;
  generated: string;
  source: string;
  total: number;
  facets: {
    boardability: Record<AtlasBoardability, number>;
    reach: Record<AtlasReach, number>;
    lane: Record<AtlasLane, number>;
    p42: { true: number; false: number };
  };
  board_class_rule: Record<AtlasBoardability, string>;
  provenance: AtlasProvenance;
  settlement_authority: false;
}
