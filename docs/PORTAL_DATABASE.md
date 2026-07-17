# Portal database cutover

Production uses two PostgreSQL identities. `P42_PORTAL_MIGRATION_DATABASE_URL`
authenticates as the schema owner and runs only during migration. The web
process uses `P42_PORTAL_DATABASE_URL`. `P42_PORTAL_DATABASE_SCHEMA` pins the
preprovisioned schema by name and the migration records its database, schema,
owner, relation, and function OIDs. In required mode, missing schema identity,
same-role credentials, catalog drift, or authority overlap fails closed.
`P42_PORTAL_RUNTIME_ROLE` and `P42_PORTAL_DATABASE_NAME` pin the authenticated
runtime identity and database. Startup verifies both plus the untouched
role/database default `search_path` through its exact `pg_db_role_setting`
catalog row before any migration or ACL mutation. It separately checks the
session's effective `current_setting`, so connection-level overrides cannot
mask a missing or drifted role default.
Application pools also pass an explicit `search_path=<schema>,pg_catalog`
connection option, so ambient role-default drift cannot redirect unqualified
store queries.

Only the migration-owner-controlled `SECURITY DEFINER` transition function may
change checkpoint authority. A separately pinned read-only function handles an
exact unchanged checkpoint with a compatible `FOR SHARE` lock and indexed
maximum lookups. On a miss, the app rolls that transaction back, re-attests all
authority in a new transaction, and calls the exclusive transition function.
Both force `search_path=pg_catalog`, use fully qualified pinned relations, and
return the exact persisted tuple for validation before commit. Runtime has
`SELECT` and only those function `EXECUTE` grants, with no direct high-water
`INSERT`, `UPDATE`, `DELETE`, `TRUNCATE`, or `TRIGGER`. Any database, role graph,
schema/OID, function/ACL/source, trigger, history, or readback mismatch
suppresses every funding target.

## Provision and import

1. Pause mutable traffic and preserve/checksum any current state export.
2. From `web/`, inspect the read-only provisioning plan while authenticated as
   the existing exact database owner. Pass the URL only through secret
   environment injection, never command arguments:

   ```sh
   P42_PORTAL_MIGRATION_DATABASE_URL="$OWNER_SECRET_URL" \
   P42_PORTAL_RUNTIME_ROLE=p42_portal_runtime \
   P42_PORTAL_DATABASE_SCHEMA=p42_portal \
   npm run db:provision -- --plan
   ```

   The canonical self-hashed JSON plan contains no URL or password. Review the
   database, owner, runtime-role, schema, and `PUBLIC CREATE` fields. Then add
   `P42_PORTAL_RUNTIME_PASSWORD="$GENERATED_SECRET"` through secret environment
   injection and rerun with `--apply`. Apply is one transaction: it creates or
   exactly verifies the distinct runtime `LOGIN`, rotates its password,
   precreates the empty owner schema,
   revokes ambient creation paths, pins default privileges and search path, and
   verifies the committed catalog state. Any preexisting identity, attributes,
   membership, settings, explicit `CREATE`, schema object, or ownership drift
   aborts.
   An exact rerun is allowed. The runtime is `NOSUPERUSER NOCREATEDB
   NOCREATEROLE NOBYPASSRLS NOINHERIT NOREPLICATION`, owns nothing, and has no
   outbound role memberships or `SET ROLE` path. Runtime passwords must be at
   least 24 characters, use at least three character classes, and consist only
   of printable non-space ASCII bytes (`0x21` through `0x7e`). This conservative
   alphabet prevents the custom verifier from disagreeing with PostgreSQL
   clients that apply SASLprep. Plaintext is converted client-side to a
   fresh-salt PostgreSQL SCRAM-SHA-256 verifier before connecting; only the
   verifier enters SQL. The receipt is provisioning evidence, not a
   production-completion claim. Run `npm run db:provision-integration` against
   the disposable local harness before the operator ceremony.

   PostgreSQL 16 and later automatically give a non-superuser `CREATEROLE`
   creator an inbound ADMIN membership in a role it creates; PostgreSQL records
   the bootstrap superuser as grantor, so the creator cannot revoke that edge.
   This does not make the runtime a member and grants it no `SET ROLE` path.
   The ceremony rejects every outbound edge and pins the sole permitted inbound
   edge exactly: runtime role, migration-owner member, bootstrap-superuser
   grantor OID 10, `ADMIN TRUE`, `INHERIT FALSE`, and `SET FALSE`. That complete
   row is emitted in the JSON receipt; every additional or changed inbound edge
   fails closed. The Render audit observed OID 10 as role `postgres` with
   `rolsuper=true`; that provider identity is a provisioning precondition and
   must be reconfirmed after a provider, restore, or PostgreSQL environment
   change. Password equality and plaintext cannot be read back from
   PostgreSQL; an exact pre-migration rerun rotates the stored verifier and
   re-verifies every exposed catalog property.
3. The ceremony precreates one durable schema owned exactly by the migration
   role, revokes `CREATE` from runtime and public roles, and sets its name in
   `P42_PORTAL_DATABASE_SCHEMA`. Configure the runtime connection's default
   search path to that schema for the general portal store; checkpoint authority
   additionally forces `pg_catalog` and fully qualifies every object. Set the
   owner URL only as `P42_PORTAL_MIGRATION_DATABASE_URL` and runtime URL as
   `P42_PORTAL_DATABASE_URL`. Keep all three out of `NEXT_PUBLIC_*` values.
4. Separately, from `web/`, run:

   ```sh
   P42_PORTAL_MIGRATION_DATABASE_URL=postgresql://<owner>@... \
   P42_PORTAL_DATABASE_URL=postgresql://<runtime>@... \
   P42_PORTAL_DATABASE_SCHEMA=p42_portal \
   P42_PORTAL_RUNTIME_ROLE=p42_portal_runtime \
   P42_PORTAL_DATABASE_NAME=<database> \
   npm run db:migrate
   ```

   The runner applies migrations as the owner, verifies ownership, grants only
   the declared runtime operations, reconnects as runtime, and verifies exact
   function owner/source/config/ACL, pinned OIDs, privileges, and role-graph
   closure. Before creating objects it removes non-owner global and schema-local
   default privileges and closes database/public/target-schema `CREATE`. After
   migration it removes every non-owner table, column, and function grant, then
   grants the documented runtime matrix and proves the resulting ACLs exactly:
   state `SELECT/INSERT/UPDATE`, rate-limit `SELECT/INSERT/UPDATE/DELETE`,
   migration and checkpoint tables `SELECT`, and the two pinned functions
   `EXECUTE`. `PUBLIC` and unrelated roles retain no portal DML, function
   execution, or creation path. Every outbound runtime membership and every
   inbound edge except the audited PostgreSQL 18 creator-admin row fails closed,
   including nested effective access. The migration integration must also reject
   contiguous block/time regression and nonadjacent full-identity replay in
   preexisting history.

   Before its first mutation the runner performs a read-only check of the exact
   runtime identity, database, exact role/database settings row, effective search
   path, role attributes, and complete inbound/outbound membership graph. A
   hostile initial graph therefore leaves migration rows and ACLs untouched. A
   session advisory lock serializes
   cooperating P42 migration runners, and the full graph is checked again after
   grants. PostgreSQL does not let this database-owner ceremony permanently lock
   the cluster-wide role graph against a provider superuser or another concurrent
   role administrator; production provisioning must run under an exclusive
   operator window, and later privileged drift remains outside the transaction's
   guarantee. Runtime pool schema pinning prevents such drift from becoming a
   false-ready schema selection, while checkpoint operations continue to re-attest
   their authority on use.

   PostgreSQL superusers, including the provider-controlled audited OID 10 role,
   bypass ordinary ACL checks and cannot be constrained by this ceremony. That
   provider authority remains an explicit operational precondition; the exact
   application owner/runtime ACL closure does not claim to remove superuser
   access.
5. Import state through the runtime URL exactly once with
   `P42_PORTAL_IMPORT_SHA256`; compare JSONB readback before commit.
6. Run `npm run db:migration-integration` with the migration URL, then run
   `npm run db:rehearse` with both URLs. Save the JSON tail. It must show two
   checkpoint connections, lock attribution, accepted block `101`, stale block
   `100`, direct mutation and truncate denial, and
   `staleCheckpointRejectedAfterLock: true`. The current bounded-read fixture
   also requires `largeHistoryAcceptances: 10000`, concurrent exact readers,
   `exactReadersObservedInFlight: 6`, `exactReadBlockingPids: 0`, and
   `transitionBlockedByExactReaders` of at least one. PostgreSQL may report only
   a subset of a row-lock MultiXact through `pg_blocking_pids`; every reported
   transition blocker must be one of the six held readers. After the barrier is
   released, all exact reads must finish within the enforced conservative
   `exactReadReleaseLatencyCeilingMilliseconds: 2000` bound.
7. Configure both secret URLs and `P42_PORTAL_DATABASE_REQUIRED=1` on Render.
   The blueprint runs migration first and unsets the owner URL before starting
   Next.js. Confirm the running process cannot read the owner credential.
8. Re-run the runtime privilege query after provisioning, restore, role change,
   or PostgreSQL upgrade. Confirm no non-internal trigger exists on authority,
   control, epoch, or acceptance tables.

The provisioning ceremony is intentionally pre-migration only. Once migration
has populated the target schema, rerunning it fails closed even when every
object is owner-owned, because an unexpected owner-controlled object can change
`IF NOT EXISTS` migration behavior. Any later runtime-password rotation needs a
separate reviewed operation that derives and applies a client-side SCRAM
verifier without rerunning schema provisioning.

## Epoch policy

- First validated checkpoint creates epoch 1 and acceptance 1.
- The current identity permits an exact same-height replay or a higher block;
  higher checkpoints append acceptance rows.
- A new identity is rejected if that exact identity appeared in any prior
  epoch. On the same chain it requires a strictly newer timestamp and block.
- A chain transition is deliberately conservative: the destination chain must
  be historically unseen, timestamp must strictly advance, and release,
  authorization, and deployment-configuration identities must all change.
  Block heights are not compared across chains.
- Runtime cannot directly mutate control or history. The owner function rejects
  a control pointer that differs from immutable history maxima, gaps, orphaned
  epochs, adjacent semantic regression, nonadjacent historical identity replay,
  and forged high history. Exact unchanged reads do not scan full history;
  actual transitions retain the serialized full-history integrity check.

## External tail

Source and local PostgreSQL rehearsal do not provision Render roles. Before any
funding activation, an operator must provision the production schema and two
roles with the reviewed ceremony, independently inspect the membership graph,
apply migration/rehearsal against the production private database, retain
redacted OID/function/ACL/role evidence plus the provisioning/rehearsal JSON,
remove the owner credential from the web child, deploy the reviewed commit, and
probe the live funding route. Until that tail is complete, funding remains
fail-closed.

## Rollback

Do not roll database identity backward. Restore must retain all epoch and
acceptance rows and the matching control pointer. A normal outage is not a
rollback signal: configured-database failures never fall back to file state or
publish a funding target.
