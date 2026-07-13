import { createHash } from "node:crypto";
import { atlasEntries, getAtlasMeta } from "@/lib/atlas";

export async function GET() {
  const payload = JSON.stringify({ meta: getAtlasMeta(), entries: atlasEntries });
  const digest = createHash("sha256").update(payload).digest("hex");

  return new Response(`${payload}\n`, {
    headers: {
      "cache-control": "public, max-age=31536000, immutable",
      "content-disposition": 'attachment; filename="p42-erdos-atlas-v1.json"',
      "content-type": "application/json; charset=utf-8",
      etag: `"sha256-${digest}"`,
      "x-content-sha256": digest,
    },
  });
}
