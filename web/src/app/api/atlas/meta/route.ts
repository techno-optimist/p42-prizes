import { getAtlasMeta } from "@/lib/atlas";
import { json } from "@/lib/api";

export async function GET() {
  return json(getAtlasMeta(), {
    headers: { "Cache-Control": "public, max-age=60, s-maxage=300, must-revalidate" },
  });
}
