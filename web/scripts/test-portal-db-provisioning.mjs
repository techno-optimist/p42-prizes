import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import pg from "pg";

const pgBin = process.env.P42_TEST_POSTGRES_BIN || [
  "/opt/homebrew/opt/postgresql@18/bin",
  "/opt/homebrew/opt/postgresql@16/bin",
].find((candidate) => exists(path.join(candidate, "initdb")));

const root = mkdtempSync(path.join(tmpdir(), "p42-db-provisioning-"));
const data = path.join(root, "data");
const socket = path.join(root, "socket");
const port = 55432 + Math.floor(Math.random() * 800);
const container = `p42-db-provisioning-${process.pid}`;
if (pgBin) {
  execFileSync("mkdir", [socket]);
  execFileSync(path.join(pgBin, "initdb"), ["-D", data, "-U", "postgres", "-A", "trust", "--no-locale", "--encoding=UTF8"], { stdio: "ignore" });
  execFileSync(path.join(pgBin, "pg_ctl"), ["-D", data, "-o", `-F -p ${port} -k ${socket}`, "-w", "start"], { stdio: "ignore" });
} else {
  execFileSync("docker", ["run", "--name", container, "--rm", "-e", "POSTGRES_HOST_AUTH_METHOD=trust", "-p", `127.0.0.1:${port}:5432`, "-d", "postgres:18-alpine"], { stdio: "ignore" });
}

const adminUrl = `postgresql://postgres@127.0.0.1:${port}/postgres`;
try {
  await waitForPostgres(adminUrl);
} catch (error) {
  stopHarness();
  rmSync(root, { recursive: true, force: true });
  throw error;
}
const admin = new pg.Client({ connectionString: adminUrl });
admin.on("error", () => undefined);
await admin.connect();
const createdRoles = new Set();
const createdDatabases = new Set();

try {
  await testCleanAndIdempotent();
  await testHostileRole();
  await testHostileSchemaAndObject();
  await testMembership();
  await testPublicCreateRevocation();
  await testSecretRedactionAndRollback();
  process.stdout.write(JSON.stringify({ schemaVersion: "p42-portal-db-provisioning-tests/v1", postgres: await serverVersion(), tests: 7, status: "passed" }) + "\n");
} finally {
  await admin.query("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = ANY($1) AND pid<>pg_backend_pid()", [[...createdDatabases]]).catch(() => undefined);
  for (const database of createdDatabases) await admin.query(`DROP DATABASE IF EXISTS ${q(database)}`).catch(() => undefined);
  for (const role of [...createdRoles].reverse()) await admin.query(`DROP ROLE IF EXISTS ${q(role)}`).catch(() => undefined);
  await admin.end();
  stopHarness();
  rmSync(root, { recursive: true, force: true });
}

async function testCleanAndIdempotent() {
  const fixture = await makeFixture("clean");
  const plan = run(fixture, "--plan");
  assert.equal(plan.status, 0);
  assert.equal(json(plan.stdout).mode, "plan");
  assert.equal(json(plan.stdout).runtimeRole.willCreate, true);
  const first = run(fixture, "--apply");
  assert.equal(first.status, 0, first.stderr);
  verifyDigest(json(first.stdout));
  const second = run(fixture, "--apply");
  assert.equal(second.status, 0, second.stderr);
  assert.equal(json(second.stdout).runtimeRole.existedBefore, true);
  const db = await connect(fixture.ownerUrl);
  const role = (await db.query("SELECT rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,rolinherit,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=$1", [fixture.runtime])).rows[0];
  assert.deepEqual(role, { rolcanlogin: true, rolsuper: false, rolcreatedb: false, rolcreaterole: false, rolinherit: false, rolreplication: false, rolbypassrls: false });
  assert.equal((await db.query("SELECT has_database_privilege($1,current_database(),'CREATE') AS db_create,has_schema_privilege($1,'public','CREATE') AS public_create,has_schema_privilege($1,$2,'CREATE') AS schema_create", [fixture.runtime, fixture.schema])).rows[0].db_create, false);
  await db.end();
}

async function testHostileRole() {
  const fixture = await makeFixture("role");
  await admin.query(`CREATE ROLE ${q(fixture.runtime)} LOGIN CREATEDB`); createdRoles.add(fixture.runtime);
  const result = run(fixture, "--apply");
  assert.equal(result.status, 1);
  assert.equal(json(result.stderr).code, "runtime_role_drift");
}

async function testHostileSchemaAndObject() {
  const fixture = await makeFixture("schema");
  const hostile = `${fixture.runtime}_owner`; await admin.query(`CREATE ROLE ${q(hostile)}`); createdRoles.add(hostile);
  const db = await connect(fixture.ownerUrl);
  await db.query(`CREATE SCHEMA ${q(fixture.schema)}`);
  await db.query(`CREATE TABLE ${q(fixture.schema)}.hostile(value integer)`);
  await db.end();
  const superuser = await connect(`postgresql://postgres@127.0.0.1:${port}/${fixture.database}`);
  await superuser.query(`ALTER TABLE ${q(fixture.schema)}.hostile OWNER TO ${q(hostile)}`);
  await superuser.end();
  const result = run(fixture, "--apply");
  assert.equal(result.status, 1);
  assert.equal(json(result.stderr).code, "schema_ownership_drift");
}

async function testMembership() {
  const fixture = await makeFixture("member");
  await admin.query(`CREATE ROLE ${q(fixture.runtime)} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS`); createdRoles.add(fixture.runtime);
  const elevated = `${fixture.runtime}_elevated`; await admin.query(`CREATE ROLE ${q(elevated)} CREATEDB`); createdRoles.add(elevated);
  await admin.query(`GRANT ${q(elevated)} TO ${q(fixture.runtime)}`);
  const result = run(fixture, "--apply");
  assert.equal(result.status, 1);
  assert.equal(json(result.stderr).code, "runtime_role_drift");
}

async function testPublicCreateRevocation() {
  const fixture = await makeFixture("public");
  const db = await connect(fixture.ownerUrl);
  await db.query("GRANT CREATE ON DATABASE " + q(fixture.database) + " TO PUBLIC");
  await db.query("GRANT CREATE ON SCHEMA public TO PUBLIC");
  await db.end();
  const result = run(fixture, "--apply");
  assert.equal(result.status, 0, result.stderr);
  const verify = await connect(fixture.ownerUrl);
  const hazards = (await verify.query("SELECT has_database_privilege('public',current_database(),'CREATE') AS db,has_schema_privilege('public','public','CREATE') AS schema")).rows[0];
  assert.deepEqual(hazards, { db: false, schema: false });
  await verify.end();
}

async function testSecretRedactionAndRollback() {
  const fixture = await makeFixture("rollback");
  const secret = "never-print-runtime-password";
  const db = await connect(`postgresql://postgres@127.0.0.1:${port}/${fixture.database}`);
  await db.query(`CREATE FUNCTION public.fail_provisioning() RETURNS event_trigger LANGUAGE plpgsql AS $$ BEGIN
    IF tg_tag='CREATE SCHEMA' THEN RAISE EXCEPTION '${secret}'; END IF; END $$`);
  await db.query("CREATE EVENT TRIGGER fail_provisioning ON ddl_command_end EXECUTE FUNCTION public.fail_provisioning()");
  await db.end();
  const result = run({ ...fixture, password: secret }, "--apply");
  assert.equal(result.status, 1);
  assert.equal(result.stdout.includes(secret) || result.stderr.includes(secret), false);
  assert.equal(json(result.stderr).message.includes("[redacted]"), true);
  const verify = await connect(fixture.ownerUrl);
  assert.equal((await verify.query("SELECT count(*)::integer AS n FROM pg_roles WHERE rolname=$1", [fixture.runtime])).rows[0].n, 0);
  assert.equal((await verify.query("SELECT count(*)::integer AS n FROM pg_namespace WHERE nspname=$1", [fixture.schema])).rows[0].n, 0);
  await verify.end();
  const cleanup = await connect(`postgresql://postgres@127.0.0.1:${port}/${fixture.database}`);
  await cleanup.query("DROP EVENT TRIGGER fail_provisioning");
  await cleanup.query("DROP FUNCTION public.fail_provisioning()");
  await cleanup.end();

  const urlSecret = "url-password-must-not-print";
  const bad = run({ ...fixture, ownerUrl: `postgresql://owner:${urlSecret}@127.0.0.1:1/missing`, password: secret }, "--apply");
  assert.equal(bad.status, 1);
  assert.equal(`${bad.stdout}${bad.stderr}`.includes(urlSecret), false);
  assert.equal(`${bad.stdout}${bad.stderr}`.includes("postgresql://"), false);
}

async function makeFixture(label) {
  const suffix = createHash("sha256").update(`${label}-${Math.random()}`).digest("hex").slice(0, 8);
  const owner = `p42_owner_${suffix}`; const runtime = `p42_runtime_${suffix}`; const database = `p42_db_${suffix}`; const schema = `p42_portal_${suffix}`;
  await admin.query(`CREATE ROLE ${q(owner)} LOGIN CREATEROLE CREATEDB PASSWORD 'owner-test-password'`); createdRoles.add(owner);
  await admin.query(`CREATE DATABASE ${q(database)} OWNER ${q(owner)}`); createdDatabases.add(database);
  return { ownerUrl: `postgresql://${owner}:owner-test-password@127.0.0.1:${port}/${database}`, runtime, database, schema, password: `runtime-${suffix}-password` };
}

function run(fixture, flag) {
  return spawnSync(process.execPath, ["scripts/provision-portal-db.mjs", flag], {
    cwd: path.resolve("."), encoding: "utf8",
    env: { ...process.env, P42_PORTAL_MIGRATION_DATABASE_URL: fixture.ownerUrl, P42_PORTAL_RUNTIME_ROLE: fixture.runtime, P42_PORTAL_DATABASE_SCHEMA: fixture.schema, P42_PORTAL_RUNTIME_PASSWORD: fixture.password },
  });
}

function json(value) { return JSON.parse(value.trim()); }
function verifyDigest(value) {
  const { resultSha256, ...body } = value;
  const canonical = canonicalJson(body);
  assert.equal(resultSha256, `sha256:${createHash("sha256").update(canonical).digest("hex")}`);
}
function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
}
async function connect(connectionString) { const client = new pg.Client({ connectionString }); client.on("error", () => undefined); await client.connect(); return client; }
async function serverVersion() { return (await admin.query("SHOW server_version")).rows[0].server_version; }
function q(value) { return `"${value.replaceAll('"', '""')}"`; }
function exists(file) { try { execFileSync("test", ["-x", file]); return true; } catch { return false; } }
function stopHarness() {
  if (pgBin) spawnSync(path.join(pgBin, "pg_ctl"), ["-D", data, "-m", "fast", "-w", "stop"], { stdio: "ignore" });
  else spawnSync("docker", ["stop", container], { stdio: "ignore" });
}
async function waitForPostgres(connectionString) {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    const probe = new pg.Client({ connectionString, connectionTimeoutMillis: 500 });
    try { await probe.connect(); await probe.end(); return; } catch { await probe.end().catch(() => undefined); }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error("local PostgreSQL harness did not become ready");
}
