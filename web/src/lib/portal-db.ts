import { Pool, type QueryResult, type QueryResultRow } from "pg";

const globalPortalDb = globalThis as typeof globalThis & {
  __p42PortalPool?: Pool;
  __p42PortalPoolOverride?: PortalDatabasePool;
};

export interface PortalDatabasePool {
  connect(): Promise<PortalDatabaseClient>;
  query<R extends QueryResultRow = QueryResultRow>(text: string, values?: unknown[]): Promise<QueryResult<R>>;
}

export interface PortalDatabaseClient {
  query<R extends QueryResultRow = QueryResultRow>(text: string, values?: unknown[]): Promise<QueryResult<R>>;
  release(): void;
}

export function portalDatabaseConfigured(): boolean {
  const configured = Boolean(process.env.P42_PORTAL_DATABASE_URL?.trim() || globalPortalDb.__p42PortalPoolOverride);
  if (!configured && process.env.P42_PORTAL_DATABASE_REQUIRED === "1") {
    throw new Error("P42_PORTAL_DATABASE_REQUIRED=1 but P42_PORTAL_DATABASE_URL is not configured");
  }
  return configured;
}

export function portalDatabasePool(): PortalDatabasePool {
  if (globalPortalDb.__p42PortalPoolOverride) return globalPortalDb.__p42PortalPoolOverride;
  const connectionString = process.env.P42_PORTAL_DATABASE_URL?.trim();
  if (!connectionString) throw new Error("P42_PORTAL_DATABASE_URL is not configured");
  const schema = portalDatabaseSchema();
  globalPortalDb.__p42PortalPool ??= new Pool({
    connectionString,
    options: `-c search_path=${schema},pg_catalog`,
    max: boundedInteger("P42_PORTAL_DATABASE_POOL_SIZE", 10, 1, 50),
    connectionTimeoutMillis: boundedInteger("P42_PORTAL_DATABASE_CONNECT_TIMEOUT_MS", 5_000, 500, 30_000),
    idleTimeoutMillis: boundedInteger("P42_PORTAL_DATABASE_IDLE_TIMEOUT_MS", 30_000, 1_000, 300_000),
    allowExitOnIdle: false,
  });
  return globalPortalDb.__p42PortalPool;
}

export function portalDatabaseSchema(): string {
  const schema = process.env.P42_PORTAL_DATABASE_SCHEMA?.trim();
  if (!schema || !/^[a-z][a-z0-9_]{0,62}$/.test(schema)) {
    throw new Error("P42_PORTAL_DATABASE_SCHEMA must name the validated portal schema");
  }
  return schema;
}

export function portalDatabaseTimeouts() {
  return {
    lockMs: boundedInteger("P42_PORTAL_DATABASE_LOCK_TIMEOUT_MS", 5_000, 100, 30_000),
    statementMs: boundedInteger("P42_PORTAL_DATABASE_STATEMENT_TIMEOUT_MS", 15_000, 500, 60_000),
  };
}

function boundedInteger(name: string, fallback: number, minimum: number, maximum: number): number {
  const raw = process.env[name];
  const parsed = raw === undefined ? Number.NaN : Number(raw);
  if (!Number.isInteger(parsed)) return fallback;
  return Math.min(maximum, Math.max(minimum, parsed));
}

export function setPortalDatabasePoolForTests(pool?: PortalDatabasePool): void {
  globalPortalDb.__p42PortalPoolOverride = pool;
}
