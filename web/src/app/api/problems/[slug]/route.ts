import { json } from "@/lib/api";
import { chainProvenanceForProblem } from "@/lib/chain-provenance";
import { getProblemBySlug } from "@/lib/data";
import { loadPortalReadModel } from "@/lib/indexer-read-model";
import { publicProblemDetail } from "@/lib/public-problem";

export async function GET(_req: Request, { params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const catalogProblem = getProblemBySlug(slug);
  if (!catalogProblem) return json({ error: "Problem not found" }, { status: 404 });
  const model = await loadPortalReadModel();
  const problem = model.problems.find((entry) => entry.slug === slug) ?? {
    ...catalogProblem,
    source: "local-phase-0" as const,
    pool: null,
    funding: null,
    claimants: [],
    chainProvenance: chainProvenanceForProblem(catalogProblem),
  };
  return json(publicProblemDetail(problem), { headers: { "X-P42-Data-Source": problem.source } });
}
