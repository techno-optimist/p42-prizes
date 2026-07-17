# Portal database cutover

Production uses two PostgreSQL identities. `P42_PORTAL_MIGRATION_DATABASE_URL`
authenticates as the schema owner and runs only during migration. The web
process uses `P42_PORTAL_DATABASE_URL`, whose role has no table ownership,
schema `CREATE`, table `TRIGGER`, or non-internal trigger path. In required
mode the migration refuses missing, identical, or same-role credentials.

The checkpoint publication gate locks the preseeded
`p42_indexer_checkpoint_control` row. Identity epochs and accepted checkpoint
watermarks are append-only tables: the runtime role has `SELECT, INSERT` but no
`UPDATE` or `DELETE` on either history table. Every insert and control update is
checked through `RETURNING` before commit. A database, privilege, trigger,
history, or readback failure returns a local-only portal model with no funding
target.

## Provision and import

1. Pause mutable traffic and preserve/checksum any current state export.
2. In the same PostgreSQL database, provision a non-login-equivalent schema
   owner and a distinct runtime login. The runtime must be `NOSUPERUSER
   NOCREATEDB NOCREATEROLE`, must not own the database/schema/tables, and must
   not inherit a role with `CREATE` or `TRIGGER`.
3. Set the owner URL only as `P42_PORTAL_MIGRATION_DATABASE_URL`; set the runtime
   URL as `P42_PORTAL_DATABASE_URL`. Keep both out of `NEXT_PUBLIC_*` values.
4. From `web/`, run:

   ```sh
   P42_PORTAL_MIGRATION_DATABASE_URL=postgresql://<owner>@... \
   P42_PORTAL_DATABASE_URL=postgresql://<runtime>@... \
   npm run db:migrate
   ```

   The runner applies migrations as the owner, verifies ownership, grants only
   the declared runtime operations, reconnects as runtime, and rejects role or
   privilege overlap.
5. Import state through the runtime URL exactly once with
   `P42_PORTAL_IMPORT_SHA256`; compare JSONB readback before commit.
6. Run `npm run db:migration-integration` with the migration URL, then run
   `npm run db:rehearse` with both URLs. Save the JSON tail. It must show two
   checkpoint connections, lock attribution, accepted block `101`, stale block
   `100`, and `staleCheckpointRejectedAfterLock: true`.
7. Configure both secret URLs and `P42_PORTAL_DATABASE_REQUIRED=1` on Render.
   The blueprint runs migration first and unsets the owner URL before starting
   Next.js. Confirm the running process cannot read the owner credential.
8. Re-run the runtime privilege query after provisioning, restore, role change,
   or PostgreSQL upgrade. Confirm no non-internal trigger exists on control,
   epoch, or acceptance tables.

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
- Prior epoch and acceptance rows are never updated or deleted by runtime.

## External tail

Source and local PostgreSQL rehearsal do not provision Render roles. Before any
funding activation, an operator must provision the two production roles, run
migration/rehearsal against the production private database, retain redacted
role/privilege/catalog evidence and the rehearsal JSON, deploy the reviewed
commit, and probe the live funding route. Until that tail is complete, funding
remains fail-closed.

## Rollback

Do not roll database identity backward. Restore must retain all epoch and
acceptance rows and the matching control pointer. A normal outage is not a
rollback signal: configured-database failures never fall back to file state or
publish a funding target.
