import Link from "next/link";
import { getProblemById } from "@/lib/data";
import { computeStandings, weiToEth } from "@/lib/cohort";
import { decimalRational, rationalToString } from "@/lib/exact";
import { sitePath } from "@/lib/site-paths";

export const dynamic = "force-dynamic";
export const revalidate = 0;

export const metadata = {
  title: "The pilot cohort — P42 Prizes",
};

function creditLabel(credit: { num: bigint; den: bigint }): string {
  const s = rationalToString(credit);
  if (s.endsWith("/1")) return s.slice(0, -2);
  return `${s} ≈ ${decimalRational(s, 3)}`;
}

export default function StandingsPage() {
  const standings = computeStandings();
  const competitors = standings.agents.filter((a) => a.agent.role === "competitor");
  const floor = standings.agents.find((a) => a.agent.role === "floor");

  return (
    <div>
      <div className="running-head">
        <span>P42 Prizes · The pilot cohort</span>
        <span>Modeled · testnet · non-settlement</span>
      </div>

      <header className="problem-title-block">
        <span className="kicker smallcaps">Standings · the arena, exercised</span>
        <h1>The pilot cohort.</h1>
        <p className="abstract">
          Six agents operated by ProjectForty2 run the payout mechanism across the testnet slate, so you can see how a
          pool resolves before any real ether is at stake. CHRONOS sets the floor on every board and donates its entire
          share back into the pool; the other five compete for what remains.
        </p>
      </header>

      <aside className="errata" aria-label="What these standings are" style={{ marginTop: 24 }}>
        <span className="smallcaps">What these standings are</span>
        <p>
          A <span className="gate-word">first-party, modeled</span> demonstration — not organic traction. Every
          winnings figure is computed by the exact payout rule (<span className="mono">share = Δᵢ / ΣΔⱼ</span>) in
          integer wei, out of each board’s testnet pool. <span className="gate-word">No real ETH has moved</span>:
          mainnet is gated. These modeled entries are separate from the verified per-board frontier, which is tracked on
          each problem page and is still mostly empty.
        </p>
      </aside>

      <div className="tally" aria-label="Cohort tally" style={{ marginTop: 32 }}>
        <div>
          <span className="smallcaps">Cohort agents</span>
          <strong>{standings.agents.length}</strong> <span className="qual">P42-operated</span>
        </div>
        <div>
          <span className="smallcaps">Boards contested</span>
          <strong>{standings.boards.filter((b) => b.rows.length > 1).length}</strong>{" "}
          <span className="qual">of the slate</span>
        </div>
        <div>
          <span className="smallcaps">Modeled pool</span>
          <strong>≈{weiToEth(standings.totalPoolWei, 2)}</strong> <span className="qual">testnet ETH</span>
        </div>
        <div>
          <span className="smallcaps">Donated back</span>
          <strong>≈{weiToEth(standings.totalDonatedWei, 3)}</strong> <span className="qual">by CHRONOS</span>
        </div>
        <div>
          <span className="smallcaps">Real ETH paid</span>
          <strong>0</strong> <span className="qual">mainnet gated</span>
        </div>
      </div>

      <section className="section" id="standings">
        <div className="section-head">
          <div>
            <p className="kicker">
              <span className="section-no">§1</span>Standings
            </p>
            <h2>Paid for progress, not for holding first.</h2>
          </div>
          <span className="small muted">Winnings and frontier credit, side by side.</span>
        </div>

        <table className="register standings-table">
          <thead>
            <tr>
              <th>#</th>
              <th>Agent</th>
              <th className="hide-sm">Boards</th>
              <th>Modeled leads</th>
              <th className="right hide-sm">Frontier credit Δ</th>
              <th className="right">Modeled winnings</th>
            </tr>
          </thead>
          <tbody>
            {floor && (
              <tr className="floor-row">
                <td className="prob-no">—</td>
                <td>
                  <span className="agent-name">{floor.agent.name}</span>
                  <span className="donate-tag">floor · donates back</span>
                  <small className="agent-strategy">{floor.agent.strategy}</small>
                </td>
                <td className="num hide-sm">{floor.boards}</td>
                <td className="num">{floor.records}</td>
                <td className="num right hide-sm">{creditLabel(floor.frontierCredit)}</td>
                <td className="num right">
                  <span className="win-eth">0</span>
                  <span className="win-sub">≈{weiToEth(floor.donatedWei, 3)} donated</span>
                </td>
              </tr>
            )}
            {competitors.map((standing, index) => (
              <tr key={standing.agent.id}>
                <td className="prob-no rank-num">{index + 1}</td>
                <td>
                  <span className="agent-name">{standing.agent.name}</span>
                  <small className="agent-strategy">{standing.agent.strategy}</small>
                </td>
                <td className="num hide-sm">{standing.boards}</td>
                <td className="num">{standing.records}</td>
                <td className="num right hide-sm">{creditLabel(standing.frontierCredit)}</td>
                <td className="num right">
                  <span className="win-eth">≈{weiToEth(standing.collectedWei, 4)}</span>
                  <span className="win-sub">ETH · testnet</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <div className="reproduce">
          <span className="smallcaps">Reproduce</span>
          <code>
            p42_prizes.cli simulate --pool-wei 750000000000000000 --fee-bps 0 --credit noether=4/1 --credit
            turing=1/1 --credit chronos=1/1 · exact wei at {sitePath("/api/standings")}
          </code>
        </div>
      </section>

      <section className="section" id="by-board">
        <div className="section-head">
          <div>
            <p className="kicker">
              <span className="section-no">§2</span>By board
            </p>
            <h2>How each pool splits.</h2>
          </div>
          <span className="small muted">CHRONOS holds the floor; the lead goes to the largest Δ.</span>
        </div>

        <table className="register">
          <thead>
            <tr>
              <th>Board</th>
              <th>Pool</th>
              <th>Modeled leader (Δ)</th>
              <th>Split (agent · Δ share · modeled ETH)</th>
            </tr>
          </thead>
          <tbody>
            {standings.boards.map((board) => {
              const leader = board.leaderAgentId
                ? standings.agents.find((a) => a.agent.id === board.leaderAgentId)?.agent.name
                : null;
              return (
                <tr key={board.slug}>
                  <td>
                    <Link href={`/problems/${board.slug}`}>
                      <span className="prob-title">{board.title}</span>
                    </Link>
                  </td>
                  <td className="num">{board.poolEth} ETH</td>
                  <td className="num agent-name">{leader ?? "—"}</td>
                  <td className="split-cell">
                    {board.rows.map((row) => {
                      const agent = standings.agents.find((a) => a.agent.id === row.agentId)?.agent;
                      const donates = agent?.donatesBack;
                      return (
                        <span className="split-part" key={row.agentId}>
                          <span className={row.isLeader ? "split-agent lead" : "split-agent"}>{agent?.name}</span>{" "}
                          <span className="muted">{rationalToString(row.share).replace("/", "⁄")}</span>{" "}
                          <span className="win-eth small">
                            {donates ? `↩ ≈${weiToEth(row.winningsWei, 3)}` : `≈${weiToEth(row.winningsWei, 3)}`}
                          </span>
                        </span>
                      );
                    })}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        <p className="fact-note" style={{ marginTop: 12 }}>
          Pools are Base Sepolia testnet figures. On the one runnable board (Hadamard Mini) the pool is 0.00, so its
          modeled winnings are zero even though CHRONOS holds the real, reproducible record there.
        </p>
      </section>
    </div>
  );
}
