import { getAtlasMeta } from "@/lib/atlas";
import { json } from "@/lib/api";

export async function GET() {
  return json(getAtlasMeta(), {
    headers: { "Cache-Control": "public, max-age=300, s-maxage=86400, immutable" },
  });
}
