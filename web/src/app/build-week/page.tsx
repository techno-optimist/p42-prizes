import type { Metadata } from "next";
import Link from "next/link";

import { BuildWeekVerifierLab } from "@/components/BuildWeekVerifierLab";
import { sitePath } from "@/lib/site-paths";

export const metadata: Metadata = {
  title: "Build Week Verifier Lab — P42 Prizes",
  description: "Run, tamper with, and independently inspect a P42 exact verifier in the browser.",
  alternates: { canonical: sitePath("/build-week") },
};

export default function BuildWeekPage() {
  return <article className="build-week-page">
    <header className="build-week-hero">
      <p className="kicker">OpenAI Build Week · submission-period extension</p>
      <h1>Don’t trust the score.<br/>Run the proof.</h1>
      <p className="build-week-deck">P42 Prizes is an open protocol for math bounties. This Build Week extension turns its verifier-first principle into a zero-setup judge experience: inspect a certificate, corrupt it, and watch exact recomputation decide.</p>
      <div className="build-week-actions"><a className="button" href="#verifier-lab-title">Open the lab</a><Link className="link" href="/journey">Why P42 exists</Link></div>
    </header>

    <section className="build-week-boundary">
      <div><span>Before July 13</span><h2>The protocol</h2><p>Problem format, verifier runner, testnet mechanism, agent API, and public register already existed.</p></div>
      <div><span>Built during Build Week</span><h2>The judge path</h2><p>This interactive, client-side exact verifier lab; adversarial fixtures; tests; and a dated evidence packet distinguishing prior work from the eligible extension.</p></div>
    </section>

    <BuildWeekVerifierLab/>

    <section className="build-week-how">
      <p className="kicker">What the interaction proves</p>
      <h2>Acceptance is a computation, not a claim.</h2>
      <ol>
        <li><strong>Load a witness.</strong><span>The four rows are the only mathematical input.</span></li>
        <li><strong>Recompute.</strong><span>Six integer dot products determine the defect exactly.</span></li>
        <li><strong>Attack it.</strong><span>The lying fixture announces a perfect score and still fails.</span></li>
        <li><strong>Inspect the boundary.</strong><span>This is a Phase 0/testnet demonstration. Real funding remains gated.</span></li>
      </ol>
      <p><a className="link" href="https://github.com/techno-optimist/p42-prizes">Source and setup instructions</a></p>
    </section>
  </article>;
}
