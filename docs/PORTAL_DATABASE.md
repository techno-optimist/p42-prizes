# Portal database cutover

Production portal mutations require one shared PostgreSQL authority. When
`P42_PORTAL_DATABASE_URL` is configured, reads, writes, idempotency, events,
and rate limits fail closed on database errors and never fall back to the local
JSON file.

## Provision and import

1. Pause mutable portal traffic and copy the current `portal-state.json` from
   the persistent disk into a restricted operator workspace.
2. Record its checksum with `shasum -a 256 portal-state.json` and review the
   state counts and final event-chain hash.
3. Provision Render PostgreSQL in the same region as `p42-prizes`. Keep the
   internal URL secret and do not expose it through a `NEXT_PUBLIC_*` variable.
4. From `web/`, run `P42_PORTAL_DATABASE_URL=... npm run db:migrate`.
5. Import exactly once:

   ```sh
   P42_PORTAL_DATABASE_URL=... \
   P42_PORTAL_IMPORT_SHA256=sha256:<reviewed-file-digest> \
   npm run db:import-state -- /absolute/path/to/portal-state.json
   ```

   The importer locks the table, refuses an existing singleton, verifies the
   source checksum, and compares the JSONB readback before committing revision
   zero.
6. Configure both `P42_PORTAL_DATABASE_URL` and
   `P42_PORTAL_DATABASE_REQUIRED=1` on the Render web service, deploy the
   reviewed commit, and exercise two concurrent application connections against
   commit, reveal, idempotency replay, event reads, and rate-limit exhaustion.
7. Compare the database counts, revision, and final event hash with the import
   record. Keep the old disk read-only through the rollback window.

## Rollback

Pause mutations before rollback. Remove database-required mode only when the
disk state has been reconciled from the database under an explicit operator
procedure; otherwise an old local file would become authoritative. A normal
database outage is not a rollback signal: configured-database failures return
errors and do not use the file.

This source change does not itself close the live distributed-state gate. That
gate closes only after provisioning, checksum evidence, multi-connection
rehearsal, production configuration, and post-deploy reconciliation are saved.
