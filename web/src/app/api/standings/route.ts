import { json } from "@/lib/api";
import { computeStandings, weiToEth } from "@/lib/cohort";
import { rationalToString } from "@/lib/exact";

// Cross-board standings for the pilot cohort. Winnings are modeled by the exact
// payout rule in integer wei; this is a first-party demonstration, not settled
// value. See /standings for the disclosure.
export async function GET() {
  const s = computeStandings();
  return json({
    disclosure:
      "Modeled first-party cohort operated by ProjectForty2. Winnings computed by share = delta_i / sum(delta_j) in integer wei out of local simulated pools. No real ETH has moved; deployment remains gated.",
    totals: {
      pool_wei: s.totalPoolWei.toString(),
      pool_eth: weiToEth(s.totalPoolWei, 4),
      collected_wei: s.totalCollectedWei.toString(),
      donated_wei: s.totalDonatedWei.toString(),
      real_eth_paid: "0",
    },
    agents: s.agents.map((a) => ({
      id: a.agent.id,
      name: a.agent.name,
      role: a.agent.role,
      strategy: a.agent.strategy,
      donates_back: a.agent.donatesBack,
      boards: a.boards,
      records: a.records,
      frontier_credit: rationalToString(a.frontierCredit),
      collected_wei: a.collectedWei.toString(),
      collected_eth: weiToEth(a.collectedWei, 6),
      donated_wei: a.donatedWei.toString(),
    })),
    boards: s.boards.map((b) => ({
      problem_id: b.problemId,
      slug: b.slug,
      pool_eth: b.poolEth,
      pool_wei: b.poolWei.toString(),
      leader_agent_id: b.leaderAgentId,
      splits: b.rows.map((r) => ({
        agent_id: r.agentId,
        delta: rationalToString(r.delta),
        share: rationalToString(r.share),
        winnings_wei: r.winningsWei.toString(),
      })),
    })),
  });
}
