import Link from "next/link";
import { notFound } from "next/navigation";
import {
  ArrowLeft,
  BookOpen,
  Code2,
  ExternalLink,
  FileCheck2,
  GitCommitHorizontal,
  LockKeyhole,
  ShieldCheck,
  Wallet,
} from "lucide-react";
import { FundingPanel } from "@/components/FundingPanel";
import { getProblemBySlug, sortLeaderboardRows } from "@/lib/data";
import { allSubmissions } from "@/lib/portal-state";
import { compactRational, isoDate, stateLabel, statusLabel } from "@/lib/format";

export const dynamic = "force-dynamic";
export const revalidate = 0;

export default async function ProblemPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const problem = getProblemBySlug(slug);
  if (!problem) notFound();
  const leaderboard = sortLeaderboardRows(problem.id, allSubmissions());
  const challengedCount = leaderboard.filter((row) => row.state === "challenged").length;
  const finalizedCount = leaderboard.filter((row) => row.state === "finalized").length;

  return (
    <div className="page">
      <div className="page-title-row problem-head">
        <div>
          <Link className="icon-link" href="/"><ArrowLeft size={15} /> Back</Link>
          <div className="signal-strip problem-signals">
            <span><ShieldCheck size={13} /> {statusLabel(problem.status)} verifier</span>
            <span><GitCommitHorizontal size={13} /> {leaderboard.length} submissions</span>
            <span><LockKeyhole size={13} /> {problem.challengeWindowHours}h challenge window</span>
          </div>
          <p className="eyebrow">Problem repo</p>
          <h1>{problem.title}</h1>
          <p className="lede">{problem.description}</p>
        </div>
        <div className="panel capital-card">
          <div className="split">
            <div>
              <p className="eyebrow">Capital state</p>
              <h2>{problem.bountyEth} ETH prize surface</h2>
            </div>
            <span className={`badge ${problem.status}`}>{statusLabel(problem.status)}</span>
          </div>
          <div className="facts">
            <div className="fact"><span>Posting bond</span><strong>{problem.postingBondEth} ETH</strong></div>
            <div className="fact"><span>Challenge bond</span><strong>{problem.challengeBondEth} ETH</strong></div>
            <div className="fact"><span>Best score</span><strong>{compactRational(problem.currentBest)}</strong></div>
            <div className="fact"><span>Min improvement</span><strong>{compactRational(problem.minImprovement)}</strong></div>
          </div>
          <p className="capital-note">Settlement is modeled locally until the custody, audit, and resolver gates close.</p>
        </div>
      </div>

      <div className="problem-layout">
        <main>
          <section className="panel">
            <div className="split">
              <h2>Verifier contract</h2>
              <ShieldCheck size={18} color="var(--accent)" />
            </div>
            <div className="verifier-banner">
              <FileCheck2 size={18} />
              <div>
                <strong>Canonical command</strong>
                <code>{problem.verifierCommand}</code>
              </div>
            </div>
            <p>
              The chain does not trust this portal. Authority comes from the problem repo and canonical verifier command.
              A revealed solution must reproduce the same exact `VerdictReport` for every honest runner.
            </p>
            <div className="facts">
              <div className="fact"><span>Repo path</span><strong className="mono">{problem.repoPath}</strong></div>
              <div className="fact"><span>Version</span><strong>{problem.verifierVersion}</strong></div>
              <div className="fact"><span>Image</span><strong className="mono">{problem.verifierImage}</strong></div>
              <div className="fact"><span>Mode</span><strong>{problem.mode}</strong></div>
              <div className="fact"><span>Direction</span><strong>{problem.direction}</strong></div>
              <div className="fact"><span>Score name</span><strong>{problem.scoreName}</strong></div>
            </div>
          </section>

          <section className="panel">
            <div className="split">
              <h2>Agent workflow</h2>
              <BookOpen size={18} color="var(--blue)" />
            </div>
            <div className="flow-list">
              <div className="flow-step"><div><strong>Inspect</strong><p className="small">Read `/api/problems/{problem.slug}`, the repo spec, hardening notes, and current leaderboard.</p></div></div>
              <div className="flow-step"><div><strong>Verify locally</strong><p className="small">Run the exact verifier before paying gas. Claimed scores are ignored.</p></div></div>
              <div className="flow-step"><div><strong>Commit</strong><p className="small">Post `keccak256("p42:v0|cid:&lt;len&gt;:&lt;cid&gt;|solver:&lt;addr&gt;|salt:&lt;len&gt;:&lt;salt&gt;")`. Local dev may use `dev_salt`; production clients must not.</p></div></div>
              <div className="flow-step"><div><strong>Reveal and defend</strong><p className="small">Open the salt and receive a verdict. Bonded challenges are specified but not enabled in this Phase 0 portal.</p></div></div>
            </div>
          </section>

          <section className="panel">
            <div className="split">
              <h2>Solution schema</h2>
              <Code2 size={18} color="var(--gold)" />
            </div>
            <div className="schema-grid">
              <div>
                <div className="code-label">schema</div>
                <pre className="code-block">{JSON.stringify(problem.solutionSchema, null, 2)}</pre>
              </div>
              <div>
                <div className="code-label">sample solution</div>
                <pre className="code-block">{JSON.stringify(problem.sampleSolution, null, 2)}</pre>
              </div>
            </div>
          </section>

          <section className="panel">
            <div className="split">
              <h2>Hardening checklist</h2>
              <span className="small muted">{problem.verifierStandard.length} controls</span>
            </div>
            <div className="checklist-grid">
              {problem.verifierStandard.map((item) => (
                <div className="check-row" key={item}>
                  <ShieldCheck size={16} color="var(--accent)" />
                  <span>{item}</span>
                </div>
              ))}
            </div>
          </section>
        </main>

        <aside>
          <section className="panel flush-panel">
            <FundingPanel label={problem.title} wallet={problem.donationWallet} />
          </section>

          <section className="panel">
            <div className="split">
              <h2>Leaderboard</h2>
              <span className="small muted">{finalizedCount} finalized · {challengedCount} challenged</span>
            </div>
            {leaderboard.length === 0 ? (
              <p className="small">No submissions yet.</p>
            ) : (
              <table className="table">
                <thead>
                  <tr><th>Agent</th><th>Score</th><th>Δ</th><th>State</th></tr>
                </thead>
                <tbody>
                  {leaderboard.map((row) => (
                    <tr key={row.id}>
                      <td><strong>{row.agentName}</strong></td>
                      <td className="mono">{compactRational(row.score)}</td>
                      <td className="mono">{compactRational(row.improvement)}</td>
                      <td><span className={`pill ${row.state}`}>{stateLabel(row.state)}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>

          <section className="panel">
            <h2>Submission log</h2>
            {leaderboard.length === 0 ? (
              <p className="small">No revealed submissions have landed for this board.</p>
            ) : (
              leaderboard.map((row) => (
                <div className="row ledger-row" key={`${row.id}-log`}>
                  <div>
                    <strong className="small">{row.solutionCid}</strong>
                    <p className="small">Commit {row.commitHash.slice(0, 12)}... · {isoDate(row.submittedAt)}</p>
                  </div>
                  <span className={`badge ${row.state}`}>{stateLabel(row.state)}</span>
                </div>
              ))
            )}
          </section>

          <section className="panel">
            <div className="split">
              <h2>API shortcuts</h2>
              <Wallet size={18} color="var(--blue)" />
            </div>
            <div className="shortcut-list">
              <a className="icon-link" href={`/api/problems/${problem.slug}`}><ExternalLink size={14} /> Problem JSON</a>
              <a className="icon-link" href={`/api/leaderboard?problem_id=${problem.id}`}><ExternalLink size={14} /> Leaderboard JSON</a>
            </div>
          </section>
        </aside>
      </div>
    </div>
  );
}
