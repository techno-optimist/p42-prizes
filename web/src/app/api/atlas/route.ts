import { AtlasQueryError, listAtlasEntries, parseAtlasListQuery } from "@/lib/atlas";
import { json } from "@/lib/api";

const REVALIDATED = { "Cache-Control": "public, max-age=60, s-maxage=300, must-revalidate" };

export async function GET(request: Request) {
  try {
    const query = parseAtlasListQuery(new URL(request.url).searchParams);
    return json(listAtlasEntries(query), { headers: REVALIDATED });
  } catch (error) {
    if (error instanceof AtlasQueryError) return json({ error: error.message }, { status: 400 });
    throw error;
  }
}
