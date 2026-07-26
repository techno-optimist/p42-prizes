import { createHash } from "node:crypto";

import { atlasEntries, getAtlasEntry, getAtlasMeta } from "@/lib/atlas";
import type { AtlasEntry, AtlasMeta } from "@/lib/atlas-types";

export const ATLAS_PREFLIGHT_MAX_BODY_BYTES = 16_384;
/**
 * A bundled Atlas snapshot may route compute for seven days after its pinned
 * generated date. At the next UTC midnight it expires fail-closed until a new
 * reviewed snapshot is committed and deployed.
 */
export const ATLAS_PREFLIGHT_MAX_AGE_DAYS = 7;

const MAX_PROBLEM_ID = 1_000_000_000;
const MAX_TEXT_LENGTH = 256;
const MAX_REGION_KEYS = 32;
const MAX_REGION_DEPTH = 3;
const MAX_REGION_ARRAY_LENGTH = 32;
const MAX_REGION_VALUES = 128;
const SHA256_PATTERN = /^[a-f0-9]{64}$/;

const REQUEST_FIELDS = new Set([
  "problem_id",
  "parameter_region",
  "method",
  "hardware_profile",
  "compute_budget",
]);

export const ATLAS_PREFLIGHT_DECISIONS = ["GO", "STOP", "REVIEW", "UNKNOWN"] as const;
export type AtlasPreflightDecision = (typeof ATLAS_PREFLIGHT_DECISIONS)[number];

export const ATLAS_PREFLIGHT_REASON_CODES = [
  "UNKNOWN_UNMAPPED",
  "STALE_ATLAS",
  "UNSUPPORTED_NONE",
  "SCOPED_WALL",
  "REVIEW_HEAVY_VERIFICATION",
  "REVIEW_UNKNOWN_REACH",
  "REVIEW_MISSING_STRUCTURED_EVIDENCE",
  "CERTIFIED_REGION",
  "CERTIFIED_EXCLUSION",
  "REVIEW_PARTIAL_COVERAGE",
  "REVIEW_CONFLICTING_COVERAGE",
  "REVIEW_ACTIVE_CAMPAIGN",
  "REVIEW_UNKNOWN_COVERAGE",
  "REVIEW_NO_CAMPAIGN_REGISTRY",
  "REVIEW_UNSUPPORTED_CLASSIFICATION",
] as const;
export type AtlasPreflightReasonCode = (typeof ATLAS_PREFLIGHT_REASON_CODES)[number];

type JsonScalar = string | number | boolean | null;
export type AtlasParameterValue = JsonScalar | JsonScalar[] | { [key: string]: AtlasParameterValue };

export interface AtlasPreflightRequest {
  problem_id: number;
  parameter_region?: Record<string, AtlasParameterValue>;
  method?: string;
  hardware_profile?: string;
  compute_budget?: string;
}

export interface AtlasPreflightResponse {
  decision: AtlasPreflightDecision;
  reason_code: AtlasPreflightReasonCode;
  go: boolean;
  reason: string;
  checked_at: string;
  valid_until: string;
  snapshot: {
    schema: string;
    atlas_version: string;
    generated: string;
    digest: `sha256:${string}`;
    max_age_days: number;
    provenance: AtlasMeta["provenance"];
  };
  entry: null | {
    id: number;
    title: string;
    boardability: AtlasEntry["board_class"];
    reach: AtlasEntry["beatable"];
    lane: AtlasEntry["lane"];
    finite_object: string;
    current_record: string;
    p42_slug: string | null;
  };
  coverage_matches: Array<{
    axis: string;
    start: number;
    end: number;
    status: "CERTIFIED" | "EXCLUDED" | "UNKNOWN" | "ACTIVE";
    result: string;
    artifact_sha256?: string;
    where?: Record<string, JsonScalar>;
  }>;
  limitations: {
    immutable_evidence: {
      available: boolean;
      detail: string;
    };
    compute_coverage: {
      available: boolean;
      detail: string;
    };
    campaigns: {
      available: false;
      overlap_checked: false;
      detail: string;
    };
    scope: string;
  };
}

export class AtlasPreflightInputError extends Error {
  constructor(
    message: string,
    readonly status = 400,
  ) {
    super(message);
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function validateText(name: string, value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string") throw new AtlasPreflightInputError(`${name} must be a string`);
  const normalized = value.trim();
  if (!normalized) throw new AtlasPreflightInputError(`${name} must not be empty`);
  if (normalized.length > MAX_TEXT_LENGTH) {
    throw new AtlasPreflightInputError(`${name} must be at most ${MAX_TEXT_LENGTH} characters`);
  }
  if (/\p{Cc}/u.test(normalized)) throw new AtlasPreflightInputError(`${name} contains control characters`);
  return normalized;
}

function validateParameterValue(value: unknown, path: string, depth: number, counter: { count: number }): AtlasParameterValue {
  counter.count += 1;
  if (counter.count > MAX_REGION_VALUES) {
    throw new AtlasPreflightInputError(`parameter_region must contain at most ${MAX_REGION_VALUES} values`);
  }
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value) || !Number.isSafeInteger(value)) {
      throw new AtlasPreflightInputError(`${path} must be a safe integer`);
    }
    return value;
  }
  if (typeof value === "string") {
    if (value.length > MAX_TEXT_LENGTH) {
      throw new AtlasPreflightInputError(`${path} must be at most ${MAX_TEXT_LENGTH} characters`);
    }
    if (/\p{Cc}/u.test(value)) throw new AtlasPreflightInputError(`${path} contains control characters`);
    return value;
  }
  if (Array.isArray(value)) {
    if (depth >= MAX_REGION_DEPTH) throw new AtlasPreflightInputError(`parameter_region exceeds maximum depth ${MAX_REGION_DEPTH}`);
    if (value.length > MAX_REGION_ARRAY_LENGTH) {
      throw new AtlasPreflightInputError(`${path} must contain at most ${MAX_REGION_ARRAY_LENGTH} items`);
    }
    return value.map((item, index) => {
      if (Array.isArray(item) || isPlainObject(item)) {
        throw new AtlasPreflightInputError(`${path}[${index}] must be a scalar`);
      }
      return validateParameterValue(item, `${path}[${index}]`, depth + 1, counter) as JsonScalar;
    });
  }
  if (isPlainObject(value)) {
    if (depth >= MAX_REGION_DEPTH) throw new AtlasPreflightInputError(`parameter_region exceeds maximum depth ${MAX_REGION_DEPTH}`);
    const entries = Object.entries(value);
    if (entries.length > MAX_REGION_KEYS) {
      throw new AtlasPreflightInputError(`${path} must contain at most ${MAX_REGION_KEYS} keys`);
    }
    const output: Record<string, AtlasParameterValue> = {};
    for (const [key, child] of entries) {
      if (!key || key.length > 64 || !/^[A-Za-z][A-Za-z0-9_.-]*$/.test(key)) {
        throw new AtlasPreflightInputError(`${path} contains an invalid key`);
      }
      output[key] = validateParameterValue(child, `${path}.${key}`, depth + 1, counter);
    }
    return output;
  }
  throw new AtlasPreflightInputError(`${path} contains an unsupported value`);
}

export function parseAtlasPreflightRequest(value: unknown): AtlasPreflightRequest {
  if (!isPlainObject(value)) throw new AtlasPreflightInputError("request body must be a JSON object");
  for (const field of Object.keys(value)) {
    if (!REQUEST_FIELDS.has(field)) throw new AtlasPreflightInputError(`unknown field: ${field}`);
  }
  if (!Object.hasOwn(value, "problem_id")) throw new AtlasPreflightInputError("problem_id is required");
  if (!Number.isSafeInteger(value.problem_id) || (value.problem_id as number) < 1 || (value.problem_id as number) > MAX_PROBLEM_ID) {
    throw new AtlasPreflightInputError(`problem_id must be an integer between 1 and ${MAX_PROBLEM_ID}`);
  }

  let parameterRegion: Record<string, AtlasParameterValue> | undefined;
  if (value.parameter_region !== undefined) {
    if (!isPlainObject(value.parameter_region)) {
      throw new AtlasPreflightInputError("parameter_region must be a JSON object");
    }
    parameterRegion = validateParameterValue(value.parameter_region, "parameter_region", 0, { count: 0 }) as Record<string, AtlasParameterValue>;
    if (Object.keys(parameterRegion).length === 0) throw new AtlasPreflightInputError("parameter_region must not be empty");
  }
  const method = validateText("method", value.method);
  const hardwareProfile = validateText("hardware_profile", value.hardware_profile);
  const computeBudget = validateText("compute_budget", value.compute_budget);

  return {
    problem_id: value.problem_id as number,
    ...(parameterRegion ? { parameter_region: parameterRegion } : {}),
    ...(method ? { method } : {}),
    ...(hardwareProfile ? { hardware_profile: hardwareProfile } : {}),
    ...(computeBudget ? { compute_budget: computeBudget } : {}),
  };
}

function parseGeneratedDate(generated: string): number {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(generated)) throw new Error("Atlas generated date must use YYYY-MM-DD");
  const timestamp = Date.parse(`${generated}T00:00:00.000Z`);
  if (!Number.isFinite(timestamp)) throw new Error("Atlas generated date is invalid");
  return timestamp;
}

function snapshotDescriptor() {
  const meta = getAtlasMeta();
  const payload = JSON.stringify({ meta, entries: atlasEntries });
  const digest = createHash("sha256").update(payload).digest("hex");
  if (!SHA256_PATTERN.test(digest)) throw new Error("failed to derive Atlas digest");
  const validUntil = new Date(parseGeneratedDate(meta.generated) + ATLAS_PREFLIGHT_MAX_AGE_DAYS * 86_400_000);
  return {
    validUntil,
    snapshot: {
      schema: meta.snapshot_schema,
      atlas_version: meta.atlas_version,
      generated: meta.generated,
      digest: `sha256:${digest}` as const,
      max_age_days: ATLAS_PREFLIGHT_MAX_AGE_DAYS,
      provenance: meta.provenance,
    },
  };
}

function hasImmutableEvidence(entry: AtlasEntry): boolean {
  if (!isPlainObject(entry.evidence)) return false;
  const digest = entry.evidence.digest;
  return typeof digest === "string" && /^sha256:[a-f0-9]{64}$/.test(digest);
}

function hasStructuredCompute(entry: AtlasEntry): boolean {
  if (!isPlainObject(entry.compute)) return false;
  return entry.compute.schema === "p42-atlas-compute-v1" && Array.isArray(entry.compute.coverage) && entry.compute.coverage.length > 0;
}

type CoverageRecord = AtlasPreflightResponse["coverage_matches"][number];

function structuredCoverage(entry: AtlasEntry | undefined): CoverageRecord[] {
  if (!entry || !isPlainObject(entry.compute) || entry.compute.schema !== "p42-atlas-compute-v1") return [];
  if (!Array.isArray(entry.compute.coverage)) return [];
  const records: CoverageRecord[] = [];
  for (const value of entry.compute.coverage) {
    if (!isPlainObject(value)) continue;
    if (typeof value.axis !== "string" || !Number.isSafeInteger(value.start) || !Number.isSafeInteger(value.end)) continue;
    if (typeof value.result !== "string" || !["CERTIFIED", "EXCLUDED", "UNKNOWN", "ACTIVE"].includes(String(value.status))) continue;
    const start = value.start as number;
    const end = value.end as number;
    if (start > end) continue;
    const artifact = typeof value.artifact_sha256 === "string" && SHA256_PATTERN.test(value.artifact_sha256)
      ? { artifact_sha256: value.artifact_sha256 }
      : {};
    let where: Record<string, JsonScalar> | undefined;
    if (value.where !== undefined) {
      if (!isPlainObject(value.where)) continue;
      where = {};
      let valid = true;
      for (const [key, constraint] of Object.entries(value.where)) {
        if (!/^[A-Za-z][A-Za-z0-9_.-]*$/.test(key)
            || (constraint !== null && typeof constraint !== "string" && typeof constraint !== "boolean"
              && !(typeof constraint === "number" && Number.isSafeInteger(constraint)))) {
          valid = false;
          break;
        }
        where[key] = constraint as JsonScalar;
      }
      if (!valid || Object.keys(where).length === 0) continue;
    }
    records.push({
      axis: value.axis,
      start,
      end,
      status: value.status as CoverageRecord["status"],
      result: value.result,
      ...artifact,
      ...(where ? { where } : {}),
    });
  }
  return records;
}

export function coverageRecordMatches(
  record: CoverageRecord,
  input: AtlasPreflightRequest,
): boolean {
  const requested = requestedInterval(input, record.axis);
  if (!requested || requested.end < record.start || requested.start > record.end) return false;
  if (!record.where) return true;
  return Object.entries(record.where).every(([key, expected]) => {
    if (typeof expected === "number") {
      const constrained = requestedInterval(input, key);
      return constrained?.start === expected && constrained.end === expected;
    }
    return input.parameter_region?.[key] === expected;
  });
}

function requestedInterval(input: AtlasPreflightRequest, axis: string): { start: number; end: number } | undefined {
  const value = input.parameter_region?.[axis];
  if (typeof value === "number" && Number.isSafeInteger(value)) return { start: value, end: value };
  if (Array.isArray(value) && value.length === 2 && value.every((item) => typeof item === "number" && Number.isSafeInteger(item))) {
    const [start, end] = value as [number, number];
    if (start <= end) return { start, end };
  }
  return undefined;
}

function limitations(entry: AtlasEntry | undefined): AtlasPreflightResponse["limitations"] {
  const evidenceAvailable = entry ? hasImmutableEvidence(entry) : false;
  const computeAvailable = entry ? hasStructuredCompute(entry) : false;
  return {
    immutable_evidence: {
      available: evidenceAvailable,
      detail: evidenceAvailable
        ? "The entry carries a syntactically valid immutable SHA-256 evidence reference; independent replay is still required."
        : "No structured immutable evidence digest is present; prose, links, and record claims are not admissible evidence.",
    },
    compute_coverage: {
      available: computeAvailable,
      detail: computeAvailable
        ? "The entry declares structured compute coverage; this response does not infer coverage outside those records."
        : "No structured parameter ranges, solver version, hardware, elapsed compute, termination receipt, or result digest are present.",
    },
    campaigns: {
      available: false,
      overlap_checked: false,
      detail: "This pinned snapshot has no authoritative active-campaign registry or lease service, so overlapping work cannot be ruled out.",
    },
    scope: "Atlas classifications describe the pinned P42 assessor/toolchain snapshot, not a universal mathematical or computational impossibility claim.",
  };
}

function entrySummary(entry: AtlasEntry): NonNullable<AtlasPreflightResponse["entry"]> {
  return {
    id: entry.id,
    title: entry.title,
    boardability: entry.board_class,
    reach: entry.beatable,
    lane: entry.lane,
    finite_object: entry.finite_object,
    current_record: entry.current_record,
    p42_slug: entry.p42_slug ?? null,
  };
}

export function computeAtlasPreflight(input: AtlasPreflightRequest, now = new Date()): AtlasPreflightResponse {
  if (!Number.isFinite(now.getTime())) throw new Error("preflight clock is invalid");
  const checkedAt = now.toISOString();
  const { validUntil, snapshot } = snapshotDescriptor();
  const entry = getAtlasEntry(input.problem_id);
  // Coverage is descriptive, not authorization. Surface a matching known region
  // even after snapshot expiry so agents can avoid an obvious duplicate run,
  // while the stale snapshot remains the fail-closed decision.
  const coverage = structuredCoverage(entry);
  const matches = coverage.filter((record) => coverageRecordMatches(record, input));
  const base = {
    checked_at: checkedAt,
    valid_until: validUntil.toISOString(),
    snapshot,
    entry: entry ? entrySummary(entry) : null,
    coverage_matches: matches,
    limitations: limitations(entry),
  };

  if (now.getTime() >= validUntil.getTime()) {
    const recordedStop = matches.some((record) => record.status === "CERTIFIED" || record.status === "EXCLUDED");
    return {
      decision: "STOP",
      reason_code: "STALE_ATLAS",
      go: false,
      reason: recordedStop
        ? "The pinned Atlas snapshot has exceeded its seven-day routing lifetime. It records matching certified or exclusion coverage, but refresh and review the snapshot before relying on it."
        : "The pinned Atlas snapshot has exceeded its seven-day routing lifetime. Refresh and review the snapshot before allocating compute.",
      ...base,
    };
  }
  if (!entry) {
    return {
      decision: "UNKNOWN",
      reason_code: "UNKNOWN_UNMAPPED",
      go: false,
      reason: "This Erdős problem is not mapped in the pinned Atlas snapshot. Absence is not evidence that compute is useful or futile.",
      ...base,
    };
  }
  if (matches.some((record) => record.status === "ACTIVE")) {
    return {
      decision: "REVIEW",
      reason_code: "REVIEW_ACTIVE_CAMPAIGN",
      go: false,
      reason: "The requested parameter region overlaps a recorded active campaign. Coordinate ownership before allocating compute.",
      ...base,
    };
  }
  const fullyCovered = matches.every((record) => {
    const requested = requestedInterval(input, record.axis)!;
    return record.start <= requested.start && record.end >= requested.end;
  });
  if (matches.length > 0 && !fullyCovered) {
    return {
      decision: "REVIEW",
      reason_code: "REVIEW_PARTIAL_COVERAGE",
      go: false,
      reason: "The requested parameter region partially overlaps charted compute. Split or review the scope before allocating resources.",
      ...base,
    };
  }
  const statuses = new Set(matches.map((record) => record.status));
  if (statuses.size > 1) {
    return {
      decision: "REVIEW",
      reason_code: "REVIEW_CONFLICTING_COVERAGE",
      go: false,
      reason: "The requested parameter region has conflicting coverage records. Reconcile the evidence before allocating compute.",
      ...base,
    };
  }
  const status = matches[0]?.status;
  if (status === "CERTIFIED") {
    return {
      decision: "STOP",
      reason_code: "CERTIFIED_REGION",
      go: false,
      reason: "The requested parameter region is already covered by an exact certificate. Re-run the pinned artifact instead of repeating the search.",
      ...base,
    };
  }
  if (status === "EXCLUDED") {
    return {
      decision: "STOP",
      reason_code: "CERTIFIED_EXCLUSION",
      go: false,
      reason: "The requested parameter region is closed by pinned exclusion evidence. Review the cited result before proposing new compute.",
      ...base,
    };
  }
  if (status === "UNKNOWN") {
    return {
      decision: "REVIEW",
      reason_code: "REVIEW_UNKNOWN_COVERAGE",
      go: false,
      reason: "The requested parameter region has a recorded inconclusive campaign. Review its solver, limits, and termination evidence before repeating it.",
      ...base,
    };
  }
  if (entry.board_class === "NONE") {
    return {
      decision: "STOP",
      reason_code: "UNSUPPORTED_NONE",
      go: false,
      reason: "This entry has no settlement-grade finite verifier direction in the pinned Atlas. The stop is scoped to the recorded target and assessor.",
      ...base,
    };
  }
  if (entry.beatable === "WALL") {
    return {
      decision: "STOP",
      reason_code: "SCOPED_WALL",
      go: false,
      reason: "The pinned P42 toolchain assessment marks this target as a wall. This is a scoped compute-routing stop, not a universal impossibility claim.",
      ...base,
    };
  }
  if (entry.board_class === "HEAVY") {
    return {
      decision: "REVIEW",
      reason_code: "REVIEW_HEAVY_VERIFICATION",
      go: false,
      reason: "Adjudication requires a heavy certificate or verifier lane and must be reviewed before compute is allocated.",
      ...base,
    };
  }
  if (entry.beatable === "UNKNOWN") {
    return {
      decision: "REVIEW",
      reason_code: "REVIEW_UNKNOWN_REACH",
      go: false,
      reason: "The entry has an exact witness verifier, but compute reach is unknown and no authoritative overlap check is available.",
      ...base,
    };
  }
  if (entry.board_class === "READY" && entry.beatable === "MOVABLE") {
    const structured = hasImmutableEvidence(entry) && hasStructuredCompute(entry);
    return {
      decision: "REVIEW",
      reason_code: structured ? "REVIEW_NO_CAMPAIGN_REGISTRY" : "REVIEW_MISSING_STRUCTURED_EVIDENCE",
      go: false,
      reason: structured
        ? "Immutable evidence and compute coverage are present, but no authoritative active-campaign overlap or lease registry is available. Coordinate before allocating compute."
        : "READY and MOVABLE prose classifications are insufficient: immutable evidence, structured compute coverage, and campaign-overlap data are required before GO.",
      ...base,
    };
  }
  return {
    decision: "REVIEW",
    reason_code: "REVIEW_UNSUPPORTED_CLASSIFICATION",
    go: false,
    reason: "The Atlas classification does not map to an automatic compute authorization.",
    ...base,
  };
}

class DuplicateJsonKeyError extends Error {}

/** Reject duplicate keys before JSON.parse discards their earlier values. */
export function assertNoDuplicateJsonKeys(raw: string): void {
  let index = 0;
  const whitespace = /\s/;
  const skipWhitespace = () => {
    while (index < raw.length && whitespace.test(raw[index]!)) index += 1;
  };
  const parseString = (): string => {
    const start = index;
    index += 1;
    while (index < raw.length) {
      const character = raw[index++];
      if (character === "\\") {
        index += 1;
        continue;
      }
      if (character === '"') return JSON.parse(raw.slice(start, index)) as string;
    }
    throw new SyntaxError("unterminated JSON string");
  };
  const parseValue = (): void => {
    skipWhitespace();
    if (raw[index] === "{") return parseObject();
    if (raw[index] === "[") return parseArray();
    if (raw[index] === '"') {
      parseString();
      return;
    }
    while (index < raw.length && !/[\s,\]}]/.test(raw[index]!)) index += 1;
  };
  const parseObject = (): void => {
    index += 1;
    const keys = new Set<string>();
    skipWhitespace();
    if (raw[index] === "}") {
      index += 1;
      return;
    }
    for (;;) {
      skipWhitespace();
      if (raw[index] !== '"') throw new SyntaxError("invalid JSON object key");
      const key = parseString();
      if (keys.has(key)) throw new DuplicateJsonKeyError(`duplicate field: ${key}`);
      keys.add(key);
      skipWhitespace();
      if (raw[index] !== ":") throw new SyntaxError("invalid JSON object");
      index += 1;
      parseValue();
      skipWhitespace();
      if (raw[index] === "}") {
        index += 1;
        return;
      }
      if (raw[index] !== ",") throw new SyntaxError("invalid JSON object");
      index += 1;
    }
  };
  const parseArray = (): void => {
    index += 1;
    skipWhitespace();
    if (raw[index] === "]") {
      index += 1;
      return;
    }
    for (;;) {
      parseValue();
      skipWhitespace();
      if (raw[index] === "]") {
        index += 1;
        return;
      }
      if (raw[index] !== ",") throw new SyntaxError("invalid JSON array");
      index += 1;
    }
  };

  try {
    skipWhitespace();
    parseValue();
  } catch (error) {
    if (error instanceof DuplicateJsonKeyError) throw new AtlasPreflightInputError(error.message);
    throw error;
  }
}
