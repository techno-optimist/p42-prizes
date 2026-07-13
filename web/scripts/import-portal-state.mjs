import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import pg from "pg";

const connectionString = process.env.P42_PORTAL_DATABASE_URL?.trim();
if (!connectionString) throw new Error("P42_PORTAL_DATABASE_URL is required for portal state import");
const sourcePath = process.argv[2] ? path.resolve(process.argv[2]) : undefined;
if (!sourcePath) throw new Error("usage: npm run db:import-state -- /absolute/path/to/portal-state.json");

const sourceBytes = await readFile(sourcePath);
const sourceSha256 = `sha256:${createHash("sha256").update(sourceBytes).digest("hex")}`;
const expectedSha256 = process.env.P42_PORTAL_IMPORT_SHA256?.trim();
if (!/^sha256:[0-9a-f]{64}$/.test(expectedSha256 ?? "")) {
  throw new Error("P42_PORTAL_IMPORT_SHA256 must be the reviewed sha256:<hex> of the source file");
}
if (sourceSha256 !== expectedSha256) {
  throw new Error(`portal import checksum mismatch: expected ${expectedSha256}, received ${sourceSha256}`);
}

const state = JSON.parse(sourceBytes.toString("utf8"));
validateState(state, sourceBytes.byteLength);
const canonicalSource = canonicalJson(state);
const pool = new pg.Pool({ connectionString, max: 1, connectionTimeoutMillis: 10_000 });
const client = await pool.connect();
try {
  await client.query("BEGIN");
  await client.query("LOCK TABLE p42_portal_state IN ACCESS EXCLUSIVE MODE");
  const existing = await client.query("SELECT revision, import_sha256 FROM p42_portal_state WHERE singleton = true");
  if (existing.rowCount !== 0) {
    throw new Error(`portal database already initialized at revision ${existing.rows[0].revision}; refusing overwrite`);
  }
  await client.query(
    `INSERT INTO p42_portal_state (singleton, schema_version, revision, state, import_sha256)
     VALUES (true, 1, 0, $1::jsonb, $2)`,
    [JSON.stringify(state), sourceSha256],
  );
  const readback = await client.query("SELECT state, import_sha256 FROM p42_portal_state WHERE singleton = true");
  if (readback.rowCount !== 1 || readback.rows[0].import_sha256 !== sourceSha256) {
    throw new Error("portal database import readback metadata mismatch");
  }
  if (canonicalJson(readback.rows[0].state) !== canonicalSource) {
    throw new Error("portal database import readback state mismatch");
  }
  await client.query("COMMIT");
  process.stdout.write(`imported ${sourcePath}\nsource ${sourceSha256}\nrevision 0\n`);
} catch (error) {
  await client.query("ROLLBACK").catch(() => {});
  throw error;
} finally {
  client.release();
  await pool.end();
}

function validateState(value, byteLength) {
  if (!value || Array.isArray(value) || typeof value !== "object" || value.schemaVersion !== 1) {
    throw new Error("portal import source must be a schemaVersion 1 object");
  }
  for (const key of ["commits", "submissions", "idempotency", "events"]) {
    if (!Array.isArray(value[key])) throw new Error(`portal import source ${key} must be an array`);
  }
  if (!Number.isInteger(value.eventOffset) || value.eventOffset < 0) {
    throw new Error("portal import source eventOffset must be a non-negative integer");
  }
  if (typeof value.eventAnchorHash !== "string") {
    throw new Error("portal import source eventAnchorHash must be a string");
  }
  const limits = {
    bytes: envInteger("P42_PORTAL_STATE_MAX_BYTES", 16 * 1024 * 1024, 1024, 64 * 1024 * 1024),
    commits: envInteger("P42_PORTAL_MAX_COMMITS", 1_000, 10, 5_000),
    submissions: envInteger("P42_PORTAL_MAX_SUBMISSIONS", 1_000, 10, 5_000),
    idempotency: envInteger("P42_PORTAL_MAX_IDEMPOTENCY", 1_000, 10, 5_000),
    events: envInteger("P42_PORTAL_MAX_EVENTS", 2_000, 10, 10_000),
  };
  if (byteLength > limits.bytes) throw new Error("portal import source exceeds configured byte capacity");
  for (const [key, maximum] of Object.entries(limits)) {
    if (key !== "bytes" && value[key].length > maximum) {
      throw new Error(`portal import source ${key} exceeds configured capacity`);
    }
  }
  if ((value.eventOffset === 0 && value.eventAnchorHash !== "genesis")
    || (value.eventOffset > 0 && !/^sha256:[a-f0-9]{64}$/.test(value.eventAnchorHash))) {
    throw new Error("portal import source event anchor is invalid");
  }
  let previousHash = value.eventAnchorHash;
  value.events.forEach((event, index) => {
    if (!event || Array.isArray(event) || typeof event !== "object") throw new Error("portal import event is invalid");
    const { eventHash, ...withoutHash } = event;
    const expected = `sha256:${createHash("sha256").update(canonicalJson(withoutHash)).digest("hex")}`;
    if (event.sequence !== value.eventOffset + index + 1 || event.prevHash !== previousHash || eventHash !== expected) {
      throw new Error("portal import event hash chain is invalid");
    }
    previousHash = eventHash;
  });
  for (const commit of value.commits) {
    if (commit?.commitAlgorithm !== "keccak256-p42-local-v0" || !validIso(commit.createdAt) || !validIso(commit.expiresAt)) {
      throw new Error("portal import commit is not in canonical runtime form");
    }
  }
  for (const submission of value.submissions) {
    if (!submission?.source || !submission?.settlementState) {
      throw new Error("portal import submission is not in canonical runtime form");
    }
    if (submission.source === "local-phase-0"
      && (submission.improvement !== "0/1" || submission.credit !== "0/1" || submission.payoutEth !== "0.000")) {
      throw new Error("portal import local submission would be normalized after import");
    }
    if (submission.source === "local-phase-0"
      && (submission.state === "finalized"
        || submission.settlementState !== (submission.state === "rejected" ? "ineligible" : "unsettled"))) {
      throw new Error("portal import local submission state would be normalized after import");
    }
    if (submission.source === "chain-p42-v1"
      && submission.settlementState !== (submission.state === "finalized" ? "finalized" : "unsettled")) {
      throw new Error("portal import chain submission state would be normalized after import");
    }
  }
  for (const record of value.idempotency) {
    if (!record || !["pending", "completed"].includes(record.state)) {
      throw new Error("portal import idempotency record is not in canonical runtime form");
    }
  }
  if (canonicalJson(normalizeRuntimeShape(value)) !== canonicalJson(value)) {
    throw new Error("portal import source would be rewritten by runtime normalization");
  }
}

function normalizeRuntimeShape(value) {
  const commitTtlMs = envInteger("P42_COMMIT_TTL_MS", 24 * 60 * 60 * 1000, 60_000, 7 * 24 * 60 * 60 * 1000);
  return {
    schemaVersion: 1,
    commits: value.commits.map((commit) => ({
      ...commit,
      commitAlgorithm: "keccak256-p42-local-v0",
      expiresAt: commit.expiresAt ?? new Date(Date.parse(String(commit.createdAt)) + commitTtlMs).toISOString(),
    })),
    submissions: value.submissions.map((submission) => {
      const source = submission.source ?? "local-phase-0";
      if (source === "local-phase-0") {
        const priorImprovement = submission.provisionalImprovement ?? submission.improvement;
        const localState = submission.state === "finalized" ? "revealed" : submission.state;
        return {
          ...submission,
          source,
          state: localState,
          settlementState: localState === "rejected" ? "ineligible" : "unsettled",
          improvement: "0/1",
          provisionalImprovement: priorImprovement,
          credit: "0/1",
          payoutEth: "0.000",
        };
      }
      return {
        ...submission,
        source,
        settlementState: submission.state === "finalized" ? "finalized" : "unsettled",
      };
    }),
    idempotency: value.idempotency.map((record) => ({ ...record, state: record.state ?? "completed" })),
    events: value.events.map((event) => ({ ...event })),
    eventOffset: value.eventOffset,
    eventAnchorHash: value.eventAnchorHash,
  };
}

function envInteger(name, fallback, minimum, maximum) {
  const parsed = Number(process.env[name]);
  if (!Number.isInteger(parsed)) return fallback;
  return Math.min(maximum, Math.max(minimum, parsed));
}

function validIso(value) {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}
