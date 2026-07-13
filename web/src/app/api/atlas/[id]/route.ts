import { getAtlasEntry } from "@/lib/atlas";
import { json } from "@/lib/api";

export async function GET(_request: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id: rawId } = await params;
  if (!/^[1-9]\d*$/.test(rawId)) return json({ error: "invalid Erdős id" }, { status: 400 });
  const entry = getAtlasEntry(Number(rawId));
  if (!entry) return json({ error: "Atlas entry not found" }, { status: 404 });
  return json(entry, {
    headers: { "Cache-Control": "public, max-age=60, s-maxage=300, must-revalidate" },
  });
}
