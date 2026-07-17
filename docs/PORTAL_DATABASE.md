# Portal database cutover

Production uses two PostgreSQL identities. `P42_PORTAL_MIGRATION_DATABASE_URL`
authenticates as the schema owner and runs only during migration. The web
process uses `P42_PORTAL_DATABASE_URL`. `P42_PORTAL_DATABASE_SCHEMA` pins the
preprovisioned schema by name and the migration records its database, schema,
owner, relation, and function OIDs. In required mode, missing schema identity,
same-role credentials, catalog drift, or authority overlap fails closed.

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
2. In the same PostgreSQL database, provision a dedicated migration-owner
   login and a distinct runtime login. The runtime must be `NOSUPERUSER
   NOCREATEDB NOCREATEROLE NOBYPASSRLS NOINHERIT`, must not own the database,
   schema, tables, or function, and must have no direct or indirect `SET ROLE`
   path to the migration owner or any role with dangerous attributes,
   ownership, `CREATE`, high-water DML, or `TRIGGER`.
3. Precreate one durable schema owned exactly by the migration role, revoke
   `CREATE` from runtime and public roles, and set its name in
   `P42_PORTAL_DATABASE_SCHEMA`. Configure the runtime connection's default
   search path to that schema for the general portal store; checkpoint authority
   additionally forces `pg_catalog` and fully qualifies every object. Set the
   owner URL only as `P42_PORTAL_MIGRATION_DATABASE_URL` and runtime URL as
   `P42_PORTAL_DATABASE_URL`. Keep all three out of `NEXT_PUBLIC_*` values.
4. From `web/`, run:

   ```sh
   P42_PORTAL_MIGRATION_DATABASE_URL=postgresql://<owner>@... \
   P42_PORTAL_DATABASE_URL=postgresql://<runtime>@... \
   P42_PORTAL_DATABASE_SCHEMA=p42_portal \
   npm run db:migrate
   ```

   The runner applies migrations as the owner, verifies ownership, grants only
   the declared runtime operations, reconnects as runtime, and verifies exact
   function owner/source/config/ACL, pinned OIDs, privileges, and `SET ROLE`
   closure. The migration integration must also reject contiguous block/time
   regression and nonadjacent full-identity replay in preexisting history.
5. Import state through the runtime URL exactly once with
   `P42_PORTAL_IMPORT_SHA256`; compare JSONB readback before commit.
6. Run `npm run db:migration-integration` with the migration URL, then run
   `npm run db:rehearse` with both URLs. Save the JSON tail. It must show two
   checkpoint connections, lock attribution, accepted block `101`, stale block
   `100`, direct mutation and truncate denial, and
   `staleCheckpointRejectedAfterLock: true`. The current bounded-read fixture
   also requires `largeHistoryAcceptances: 10000`, concurrent exact readers,
   and `exactReadBlockingPids: 0`.
7. Configure both secret URLs and `P42_PORTAL_DATABASE_REQUIRED=1` on Render.
   The blueprint runs migration first and unsets the owner URL before starting
   Next.js. Confirm the running process cannot read the owner credential.
8. Re-run the runtime privilege query after provisioning, restore, role change,
   or PostgreSQL upgrade. Confirm no non-internal trigger exists on authority,
   control, epoch, or acceptance tables.

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
roles, independently inspect the membership graph, apply migration/rehearsal
against the production private database, retain redacted OID/function/ACL/role
evidence and the rehearsal JSON, remove the owner credential from the web
child, deploy the reviewed commit, and probe the live funding route. Until that
tail is complete, funding remains fail-closed.

## Rollback

Do not roll database identity backward. Restore must retain all epoch and
acceptance rows and the matching control pointer. A normal outage is not a
rollback signal: configured-database failures never fall back to file state or
publish a funding target.
