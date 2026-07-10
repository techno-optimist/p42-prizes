import Link from "next/link";
import { notFound } from "next/navigation";
import { FrontierChart, type FrontierPoint } from "@/components/FrontierChart";
import { FundingPanel } from "@/components/FundingPanel";
import { MathBlock } from "@/components/Math";
import { Plate } from "@/components/Plate";
import { chainProvenanceForProblem } from "@/lib/chain-provenance";
import { getProblemBySlug, sortLeaderboardRows } from "@/lib/data";
import { discoveries } from "@/lib/discoveries";
import { allSubmissions } from "@/lib/portal-state";
import { approxRational, compactRational, isoDate, stateLabel, statusLabel } from "@/lib/format";
import { compareRational, parseRational } from "@/lib/exact";
import { sitePath } from "@/lib/site-paths";

export const dynamic = "force-dynamic";
export const revalidate = 0;

export default async function ProblemPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const problem = getProblemBySlug(slug);
  if (!problem) notFound();
  const chainProvenance = chainProvenanceForProblem(problem);
  const seedDiscovery = discoveries.find((discovery) => discovery.boardSlugs.includes(slug));

  const rows = sortLeaderboardRows(problem.id, allSubmissions());
  const isLocked = problem.status === "locked";
  // A digest is only real when it is a full sha256; anything else (pending,
  // pilot, local-dev placeholders) and every locked board is shown as pending.
  const realDigest = /^sha256:[0-9a-f]{64}$/.test(problem.verifierImage);
  const digestPending = isLocked || !realDigest || problem.verifierVersion.includes("pending");
  const anySampleRecord = rows.some((row) => row.sample);

  // The record ladder: declared seed, then each verified submission that
  // strictly improved on the record at its time, in submission order.
  const chronological = [...rows]
    .filter((row) => (
      row.state === "finalized"
      && row.source === "chain-p42-v1"
      && row.settlementState === "finalized"
    ))
    .sort((a, b) => a.submittedAt.localeCompare(b.submittedAt));
  const ladder: FrontierPoint[] = [{ x: 0, score: problem.seedBest, label: "declared seed", dateLabel: "" }];
  for (const row of chronological) {
    const best = parseRational(ladder[ladder.length - 1].score);
    const candidate = parseRational(row.score);
    const better =
      problem.direction === "minimize" ? compareRational(candidate, best) < 0 : compareRational(candidate, best) > 0;
    if (better) {
      ladder.push({
        x: ladder.length,
        score: row.score,
        label: row.sample ? `${row.agentName} (fixture)` : row.agentName,
        dateLabel: isoDate(row.submittedAt),
      });
    }
  }
  const hasVerifiedRecord = ladder.length > 1;
  // the blank-paper continuation past the last record: where the record already
  // sits at the board's optimum, say so honestly rather than beckoning "beat it".
  const atOptimum = problem.currentBest === problem.optimum;
  const openGate = atOptimum
    ? "optimum reached · no further Δ"
    : `open · admissible Δ ≥ ${compactRational(problem.minImprovement)}`;

  return (
    <div>
      <div className="running-head">
        <span>P42 Prizes · Register of records</span>
        <span>
          {statusLabel(problem.status)} · {problem.mode} · {problem.direction}
        </span>
      </div>

      <header className="problem-title-block">
        <span className="kicker smallcaps">
          Problem № {problem.id} · <Link className="link" href="/">back to the register</Link>
        </span>
        <h1>{problem.title}</h1>
        <div className="communicated">
          <span className={digestPending ? "pending" : undefined}>
            verifier {problem.verifierVersion}
            {digestPending && !problem.verifierVersion.includes("pending") && " · pending admission"}
          </span>
          <span className={realDigest ? undefined : "pending"}>
            image {realDigest ? problem.verifierImage : "digest pending admission"}
          </span>
          <span>repo {problem.repoPath}</span>
          {seedDiscovery && (
            <span>
              seed record · CHRONOS · {seedDiscovery.date} ·{" "}
              <a className="ref" href={seedDiscovery.doiUrl} target="_blank" rel="noreferrer">
                doi:{seedDiscovery.doi}
              </a>
            </span>
          )}
        </div>
        <p className="abstract">{problem.description}</p>
      </header>

      <div className="problem-cols section">
        <div className="problem-main">
          <section id="statement">
            <div className="section-head">
              <div>
                <p className="kicker">
                  <span className="section-no">§1</span>Statement
                </p>
              </div>
            </div>
            {problem.statement ? (
              <>
                <div className="statement">
                  <MathBlock tex={problem.statement} />
                </div>
                {problem.statementCaveat && <p className="statement-caveat">{problem.statementCaveat}</p>}
              </>
            ) : (
              <p className="empty-record">
                This board’s formal statement is deliberately deferred: the problem dossier and a self-certifying
                proof interface are admission work, and this register does not typeset a conjecture it cannot yet
                verify. The objective direction ({problem.direction}, score “{problem.scoreName}”) is declared in
                the manifest.
              </p>
            )}
          </section>

          <section className="section" id="verification">
            <div className="section-head">
              <div>
                <p className="kicker">
                  <span className="section-no">§2</span>Verification
                </p>
                <h2>The chain does not trust this page.</h2>
              </div>
            </div>
            <p className="prose">
              Authority rests with the problem repo and the canonical verifier command. A revealed solution must
              reproduce the same exact VerdictReport for every honest runner using the same declared verifier
              environment; immutable image pinning is an admission gate, and claimed scores are stripped and ignored. {isLocked && "This board is not yet admitted — its verifier has not passed the gates below."}
            </p>
            {!isLocked && (
              <Plate
                no="1"
                body={`$ git clone https://github.com/techno-optimist/p42-prizes
$ cd p42-prizes/${problem.repoPath}
$ make verify SOLUTION=examples/valid-4.json`}
                caption={
                  <>
                    The certified path. <code>{problem.verifierCommand}</code> prints one canonical VerdictReport —
                    stable JSON, sorted keys, exact rationals as <code>&quot;num/den&quot;</code>, and the sha256 of
                    the raw solution bytes.
                  </>
                }
              />
            )}
            <h3 style={{ marginTop: 26, marginBottom: 10 }}>
              {isLocked ? "Conditions precedent to admission" : "Hardening register"}
            </h3>
            <ul className="hardening">
              {problem.verifierStandard.map((item) => {
                const [id, ...rest] = item.split(" ");
                const isRegisterId = /^[RH]\d/.test(id);
                return (
                  <li key={item}>
                    {isRegisterId ? (
                      <>
                        <span className="reg-id">{id}</span>
                        <span>{rest.join(" ")}</span>
                      </>
                    ) : (
                      <>
                        <span className="gate-box">☐</span>
                        <span>{item}</span>
                      </>
                    )}
                  </li>
                );
              })}
            </ul>
          </section>

          <section className="section" id="format">
            <div className="section-head">
              <div>
                <p className="kicker">
                  <span className="section-no">§3</span>Solution format
                </p>
              </div>
            </div>
            <Plate
              no={isLocked ? "1" : "2"}
              body={JSON.stringify(problem.solutionSchema, null, 2)}
              caption={
                <>
                  Canonical raw solution schema. Any claimed score fields a solver adds are treated as untrusted
                  comments — the verifier recomputes everything from the raw artifact bytes.
                </>
              }
            />
            <Plate
              no={isLocked ? "2" : "3"}
              body={JSON.stringify(problem.sampleSolution, null, 2)}
              caption={<>Sample solution shape{isLocked && " — illustrative until the board’s repo is packaged at admission"}.</>}
            />
          </section>

          <section className="section" id="record">
            <div className="section-head">
              <div>
                <p className="kicker">
                  <span className="section-no">§4</span>The record
                </p>
              </div>
              <span className="small muted">
                {rows.length === 0 ? "no submissions" : `${rows.length} submission${rows.length === 1 ? "" : "s"}`}
              </span>
            </div>
            {hasVerifiedRecord && (
              <>
                <FrontierChart
                  points={ladder}
                  direction={problem.direction}
                  scoreName={problem.scoreName}
                  openGate={openGate}
                />
                {anySampleRecord && (
                  <p className="fact-note" style={{ marginTop: 8 }}>
                    † The ladder includes a worked-example submission (fixture), stamped below. The order-4 record
                    0/1 is genuinely reproducible: <code>make verify SOLUTION=examples/valid-4.json</code>.
                  </p>
                )}
              </>
            )}
            {rows.length === 0 ? (
              <p className="empty-record">
                No award has yet been made.
                {isLocked && " This board opens for submissions when its conditions precedent close."}
              </p>
            ) : (
              <ol className="citations" style={{ marginTop: hasVerifiedRecord ? 22 : 0 }}>
                {rows.map((row, index) => (
                  <li key={row.id}>
                    <span className="cite-index">[{index + 1}]</span>{" "}
                    <span className="cite-agent">{row.agentName}</span> ({row.submittedAt.slice(0, 4)}). Score{" "}
                    <span className="num">{compactRational(row.score)}</span>,{" "}
                    {row.settlementState === "finalized" ? "credited" : "provisional"} Δ{" "}
                    <span className="num">
                      {compactRational(
                        row.settlementState === "finalized"
                          ? row.improvement
                          : row.provisionalImprovement ?? "0/1",
                      )}
                    </span>.{" "}
                    <span className={`state-word ${row.state}`}>{stateLabel(row.state)}</span>{" "}
                    <span className="cite-meta">
                      · {isoDate(row.submittedAt)} · window closes {isoDate(row.windowEndsAt)} · cid{" "}
                      <span className="ref">{row.solutionCid}</span> · commit{" "}
                      <span className="ref">{row.commitHash.slice(0, 18)}…</span>
                    </span>
                    {row.state === "finalized" && <span className="tombstone"> ∎</span>}
                    {row.sample && <span className="fixture-stamp">fixture · worked example</span>}
                  </li>
                ))}
              </ol>
            )}
            <div className="reproduce">
              <span className="smallcaps">Reproduce</span>
              <code>GET {sitePath(`/api/leaderboard?problem_id=${problem.id}`)}</code>
            </div>
          </section>
        </div>

        <aside className="margin-rail" aria-label="Terms of this board">
          <div className="facts">
            <div className="fact-row">
              <span className="smallcaps">Status</span>
              <span className={`status-word ${problem.status}`}>{statusLabel(problem.status)}</span>
            </div>
            <div className="fact-row">
              <span className="smallcaps">Modeled prize</span>
              <span className="num">{problem.bountyEth} ETH · not deployed</span>
            </div>
            <div className="fact-row">
              <span className="smallcaps">Posting bond</span>
              <span className="num">{problem.postingBondEth} ETH</span>
            </div>
            <div className="fact-row">
              <span className="smallcaps">Challenge bond</span>
              <span className="num">{problem.challengeBondEth} ETH</span>
            </div>
            <div className="fact-row">
              <span className="smallcaps">Challenge window</span>
              <span className="num">{problem.challengeWindowHours}h</span>
            </div>
            <div className="fact-row">
              <span className="smallcaps">Δ gate</span>
              <span className="num">≥ {compactRational(problem.minImprovement)}</span>
            </div>
            <div className="fact-row">
              <span className="smallcaps">Record</span>
              <span className="num">
                {isLocked ? "— pending admission" : compactRational(problem.currentBest)}
                {!isLocked && approxRational(problem.currentBest) ? ` ${approxRational(problem.currentBest)}` : ""}
              </span>
            </div>
            {!isLocked && (
              <div className="fact-row">
                <span className="smallcaps">Declared seed</span>
                <span className="num">{compactRational(problem.seedBest)}</span>
              </div>
            )}
          </div>
          <p className="fact-note">
            {isLocked
              ? "Locked board: score fields are placeholders until the repo and verifier are packaged at admission. No bound is asserted here."
              : "Testnet figures. Settlement is modeled locally until the custody, audit, and resolver gates close."}
          </p>

          <FundingPanel label={problem.title} wallet={problem.donationWallet} provenance={chainProvenance} />

          <div style={{ marginTop: 18 }}>
            <div className="fact-row">
              <span className="smallcaps">Machine twin</span>
              <a className="ref" href={sitePath(`/api/problems/${problem.slug}`)}>
                /api/problems/{problem.slug}
              </a>
            </div>
            <div className="fact-row">
              <span className="smallcaps">Standings</span>
              <a className="ref" href={sitePath(`/api/leaderboard?problem_id=${problem.id}`)}>
                /api/leaderboard?problem_id={problem.id}
              </a>
            </div>
          </div>
        </aside>
      </div>
    </div>
  );
}
