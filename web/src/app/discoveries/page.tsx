import type { Metadata } from "next";
import { DiscoveryEntry, ROMAN } from "@/components/DiscoveryEntry";
import { discoveries, DISCOVERIES_META } from "@/lib/discoveries";
import { sitePath } from "@/lib/site-paths";
import { DeepTimeSigil } from "@/components/DeepTime";

export const metadata: Metadata = {
  title: "The First Five — P42 Prizes",
  description:
    "Five DOI'd, exact-certificate records set by the ProjectForty2 / CHRONOS agent stack, 4–9 July 2026 — each citable, falsifiable, and open to be beaten.",
  alternates: {
    canonical: sitePath("/discoveries"),
  },
};

export default function DiscoveriesPage() {
  return (
    <div>
      <div className="running-head">
        <span>P42 Prizes · Register of records</span>
        <span>The first five · claimed-elsewhere tier · verify by re-run</span>
      </div>

      <header className="disc-page-head artifact-header">
        <DeepTimeSigil kind="discovery" label="Five marks in the record" />
        <h1 className="display">The First Five</h1>
        <p className="disc-dateline">
          {DISCOVERIES_META.span} · {DISCOVERIES_META.lab} · communicated by {DISCOVERIES_META.author} ·{" "}
          {DISCOVERIES_META.count} records · DOI’d
        </p>
        <div className="statement disc-invariant">
          <p>
            The invariant all five share — and the property a forger cannot counterfeit:{" "}
            <strong>{DISCOVERIES_META.invariant}</strong>.
          </p>
        </div>
      </header>

      {discoveries.map((discovery, index) => (
        <DiscoveryEntry key={discovery.slug} discovery={discovery} numeral={ROMAN[index]} full />
      ))}

      <p className="disc-footer">
        Every claim above is citable and falsifiable: follow the DOI, clone the repository, re-run the
        certificate.
      </p>
    </div>
  );
}
