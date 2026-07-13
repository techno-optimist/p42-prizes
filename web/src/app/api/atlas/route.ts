import { AtlasQueryError, listAtlasEntries, parseAtlasListQuery } from "@/lib/atlas";
import { json } from "@/lib/api";

const IMMUTABLE = { "Cache-Control": "public, max-age=300, s-maxage=86400, immutable" };

export async function GET(request: Request) {
  try {
    const query = parseAtlasListQuery(new URL(request.url).searchParams);
    return json(listAtlasEntries(query), { headers: IMMUTABLE });
  } catch (error) {
    if (error instanceof AtlasQueryError) return json({ error: error.message }, { status: 400 });
    throw error;
  }
}
