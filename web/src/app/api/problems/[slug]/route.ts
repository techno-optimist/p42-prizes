import { json } from "@/lib/api";
import { chainProvenanceForProblem } from "@/lib/chain-provenance";
import { getProblemBySlug } from "@/lib/data";

export async function GET(_req: Request, { params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const problem = getProblemBySlug(slug);
  if (!problem) return json({ error: "Problem not found" }, { status: 404 });
  return json({ ...problem, chainProvenance: chainProvenanceForProblem(problem) });
}
