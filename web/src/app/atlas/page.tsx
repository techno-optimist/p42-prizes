import type { Metadata } from "next";
import { Suspense } from "react";
import { AtlasExplorer } from "@/components/AtlasExplorer";
import { atlasEntries, getAtlasMeta } from "@/lib/atlas";
import { sitePath } from "@/lib/site-paths";
import "./atlas.css";

export const metadata: Metadata = {
  title: "Erdős Atlas - P42 Prizes",
  description: "A filterable research map of finite, verifiable Erdős problem frontiers.",
  alternates: { canonical: sitePath("/atlas") },
};

export default function AtlasPage() {
  const atlasMeta = getAtlasMeta();
  const provenance = atlasMeta.provenance as unknown as Record<string, string>;
  const provenanceHash = provenance.sha256 ?? provenance.source_sha256 ?? "unavailable";
  return (
    <div className="atlas-page">
      <div className="running-head">
        <span>P42 Prizes · Research atlas</span>
        <span>snapshot, not a claim of completeness</span>
      </div>
      <header className="atlas-header">
        <p className="atlas-kicker">Erdős problem survey · finite-verifier view</p>
        <h1>Erdős Atlas</h1>
        <p className="atlas-deck">
          A working map of open frontiers, organized by verifier fit and mathematical impact. It records where a
          finite object can carry a meaningful claim, and where the reduction to one remains the hard part.
        </p>
        <div className="atlas-provenance" aria-label="Atlas provenance">
          <span><b>{atlasMeta.survey.triaged}</b> triaged · <b>{atlasMeta.survey.deep_audited}</b> deep-audited</span>
          <span><b>{atlasMeta.queue.ready_interfaces}</b> exact interfaces · <b>{atlasMeta.queue.p42_packages}</b> P42 packages</span>
          <span><b>{atlasMeta.queue.reserve_unpacked}</b> reserve candidates · <b>{atlasMeta.queue.recommended_unpacked}</b> recommended now</span>
          <span>Snapshot <b>v{atlasMeta.atlas_version} · {atlasMeta.generated}</b></span>
          <span>Source commit <b>{atlasMeta.provenance.commit.slice(0, 12)}</b></span>
          <span>sha256 <b>{provenanceHash === "unavailable" ? provenanceHash : `${provenanceHash.slice(0, 12)}…`}</b></span>
        </div>
        <p className="atlas-scope">
          Scores are comparative research judgments, not theorem status or prize eligibility. “Boardable” means a
          plausible exact finite-object interface was identified; admission still requires a reviewed specification,
          reduction argument where applicable, immutable verifier, and adversarial testing.
        </p>
        <div className="atlas-machine-links" aria-label="Machine-readable Atlas resources">
          <span>For agents</span>
          <a href={sitePath("/api/atlas/export")}>Full snapshot · JSON</a>
          <a href={sitePath("/api/atlas?boardability=READY&p42=false&limit=51")}>Reserve candidates · JSON</a>
          <a href={sitePath("/api/atlas?boardability=NONE&limit=51")}>Known walls · JSON</a>
          <a href={sitePath("/api/atlas/meta")}>Schema and facets · JSON</a>
        </div>
      </header>
      <Suspense fallback={<p className="atlas-loading">Preparing the 51-entry research index…</p>}>
        <AtlasExplorer entries={[...atlasEntries]} />
      </Suspense>
    </div>
  );
}
