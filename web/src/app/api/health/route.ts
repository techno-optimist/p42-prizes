import { json } from "@/lib/api";
import { portalDatabasePool, portalDatabaseSchema } from "@/lib/portal-db";

export const dynamic = "force-dynamic";

type HealthRow = {
  schema_name: string;
  singleton_count: number;
};

export async function GET() {
  try {
    const expectedSchema = portalDatabaseSchema();
    const result = await portalDatabasePool().query<HealthRow>(`
      SELECT
        current_schema() AS schema_name,
        (SELECT count(*)::integer FROM p42_portal_state WHERE singleton = true) AS singleton_count
    `);
    const row = result.rows[0];
    if (result.rowCount !== 1 || row?.schema_name !== expectedSchema || row.singleton_count !== 1) {
      throw new Error("portal database readiness invariant failed");
    }
    return json({ status: "ok", database: "ready" });
  } catch {
    return json({ status: "unavailable", database: "unavailable" }, { status: 503 });
  }
}
