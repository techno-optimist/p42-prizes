"use client";

import { useMemo, useState } from "react";

import { BUILD_WEEK_FIXTURES, verifyHadamardMini, type BuildWeekVerdict } from "@/lib/build-week-verifier";

type FixtureName = keyof typeof BUILD_WEEK_FIXTURES;

function fixtureText(name: FixtureName): string {
  return JSON.stringify(BUILD_WEEK_FIXTURES[name].solution, null, 2);
}

export function BuildWeekVerifierLab() {
  const [candidate, setCandidate] = useState(() => fixtureText("exact"));
  const [verdict, setVerdict] = useState<BuildWeekVerdict | null>(null);
  const [error, setError] = useState("");
  const verdictJson = useMemo(() => verdict ? JSON.stringify(verdict, null, 2) : "", [verdict]);

  function loadFixture(name: FixtureName) {
    setCandidate(fixtureText(name));
    setVerdict(null);
    setError("");
  }

  function runVerifier() {
    try {
      setVerdict(verifyHadamardMini(candidate));
      setError("");
    } catch (caught) {
      setVerdict(null);
      setError(caught instanceof Error ? caught.message : "INTERNAL: verifier failed closed");
    }
  }

  return <section className="build-week-lab" aria-labelledby="verifier-lab-title">
    <header className="build-week-lab-head">
      <div>
        <p className="kicker">Interactive judge path · no wallet required</p>
        <h2 id="verifier-lab-title">Try to fool the verifier.</h2>
      </div>
      <p>The checker reads only <code>n</code> and <code>rows</code>, recomputes all six row-pair dot products with integers, and ignores every claimed score.</p>
    </header>
    <div className="build-week-fixtures" aria-label="Candidate fixtures">
      {(Object.keys(BUILD_WEEK_FIXTURES) as FixtureName[]).map((name) =>
        <button key={name} type="button" onClick={() => loadFixture(name)}>{BUILD_WEEK_FIXTURES[name].label}</button>
      )}
    </div>
    <div className="build-week-workbench">
      <label>
        <span>Candidate solution.json</span>
        <textarea value={candidate} onChange={(event) => setCandidate(event.target.value)} spellCheck={false}/>
      </label>
      <div className="build-week-run">
        <button className="button" type="button" onClick={runVerifier}>Run exact verifier</button>
        <span>integer arithmetic · deterministic · recompute-don’t-echo</span>
      </div>
      <section className={`build-week-verdict ${verdict?.valid ? "is-valid" : verdict ? "is-invalid" : ""}`} aria-live="polite">
        <span className="smallcaps">Lab verdict</span>
        {error ? <><strong>REJECTED</strong><pre>{error}</pre></> : verdict ? <><strong>{verdict.valid ? "ACCEPTED" : "REJECTED"}</strong><pre>{verdictJson}</pre></> : <><strong>WAITING</strong><p>Load a fixture, edit it if you like, then run the verifier.</p></>}
      </section>
    </div>
  </section>;
}
