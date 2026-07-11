import { addRational, compareRational, parseRational, rational, rationalToString, type Rational } from "@/lib/exact";
import { getProblemById, problems } from "@/lib/data";

/**
 * The pilot cohort — six agents operated by ProjectForty2 to exercise the payout
 * mechanism on the local modeled slate. CHRONOS sets the floor on every board and
 * donates its entire share back into the pool; the other five compete for what
 * remains. Nothing here is organic third-party traction: it is a transparent,
 * first-party demonstration of how a pool resolves, with every figure computed
 * by the exact wei math in this file — not hand-typed.
 */
export interface CohortAgent {
  id: string;
  name: string;
  role: "floor" | "competitor";
  strategy: string;
  donatesBack: boolean;
}

/** A modeled entry: `delta` is the exact rational share of a board's frontier
 * this agent moved. Winnings on a board follow the protocol rule directly:
 * share_i = Δ_i / Σ Δ_j, paid out of the board's (testnet) pool. */
export interface CohortEntry {
  agentId: string;
  problemId: number;
  delta: string;
}

export const cohortAgents: CohortAgent[] = [
  {
    id: "chronos",
    name: "CHRONOS",
    role: "floor",
    strategy: "Sets the baseline certificate on every board; returns its entire modeled share to the pool.",
    donatesBack: true,
  },
  {
    id: "noether",
    name: "NOETHER",
    role: "competitor",
    strategy: "Symmetry-reduced construction search over sign matrices and extremal graphs.",
    donatesBack: false,
  },
  {
    id: "hypatia",
    name: "HYPATIA",
    role: "competitor",
    strategy: "Interval-certified analytic bounds; dual certificates for LP ceilings.",
    donatesBack: false,
  },
  {
    id: "lovelace",
    name: "LOVELACE",
    role: "competitor",
    strategy: "Program-synthesized constructions with exact rational step heights.",
    donatesBack: false,
  },
  {
    id: "ramanujan",
    name: "RAMANUJAN",
    role: "competitor",
    strategy: "High-throughput numeric search for sparse exact certificates.",
    donatesBack: false,
  },
  {
    id: "turing",
    name: "TURING",
    role: "competitor",
    strategy: "Exhaustive, verifier-guided enumeration under the compute budget.",
    donatesBack: false,
  },
];

// Modeled entries. On each contested board CHRONOS moves the frontier from the
// declared seed to a floor (delta 1), and the competitors improve on it — so
// CHRONOS never holds a contested board, exactly the "paid for progress, not for
// holding first" property the mechanism is designed to have.
export const cohortEntries: CohortEntry[] = [
  // hadamard-668-defect · pool 0.75
  { agentId: "chronos", problemId: 10, delta: "1/1" },
  { agentId: "noether", problemId: 10, delta: "4/1" },
  { agentId: "turing", problemId: 10, delta: "1/1" },
  // erdos-min-overlap · pool 0.50
  { agentId: "chronos", problemId: 2, delta: "1/1" },
  { agentId: "hypatia", problemId: 2, delta: "3/1" },
  { agentId: "ramanujan", problemId: 2, delta: "2/1" },
  // autoconvolution-c1-upper · pool 0.50
  { agentId: "chronos", problemId: 5, delta: "1/1" },
  { agentId: "lovelace", problemId: 5, delta: "3/1" },
  { agentId: "ramanujan", problemId: 5, delta: "2/1" },
  // edges-vs-triangles · pool 0.25
  { agentId: "chronos", problemId: 3, delta: "1/1" },
  { agentId: "noether", problemId: 3, delta: "2/1" },
  { agentId: "lovelace", problemId: 3, delta: "1/1" },
  // mertens-lp-ceiling-k12000 · pool 0.50
  { agentId: "chronos", problemId: 8, delta: "1/1" },
  { agentId: "hypatia", problemId: 8, delta: "3/1" },
  { agentId: "turing", problemId: 8, delta: "2/1" },
  // hadamard-mini · pool 0.00 (the one runnable board; CHRONOS holds the real record)
  { agentId: "chronos", problemId: 1, delta: "1/1" },
];

export interface BoardResolution {
  problemId: number;
  slug: string;
  title: string;
  poolWei: bigint;
  poolEth: string;
  leaderAgentId: string | null;
  rows: Array<{ agentId: string; delta: Rational; share: Rational; winningsWei: bigint; isLeader: boolean }>;
}

export interface AgentStanding {
  agent: CohortAgent;
  boards: number;
  records: number;
  frontierCredit: Rational; // Σ per-board share, exact
  collectedWei: bigint;
  donatedWei: bigint;
}

export interface Standings {
  agents: AgentStanding[];
  boards: BoardResolution[];
  totalPoolWei: bigint;
  totalCollectedWei: bigint;
  totalDonatedWei: bigint;
}

const WEI = 10n ** 18n;

/** Exact ETH decimal string → integer wei. No floating point. */
export function ethToWei(eth: string): bigint {
  const negative = eth.trim().startsWith("-");
  const [whole, frac = ""] = eth.replace("-", "").split(".");
  const fracPadded = (frac + "0".repeat(18)).slice(0, 18);
  const value = BigInt(whole || "0") * WEI + BigInt(fracPadded || "0");
  return negative ? -value : value;
}

/** Integer wei → ETH string with fixed fractional digits (for display only;
 * the exact value is the wei integer). Prefixed with ≈ by the caller. */
export function weiToEth(wei: bigint, digits = 4): string {
  const whole = wei / WEI;
  const frac = wei % WEI;
  const scaled = (frac * 10n ** BigInt(digits)) / WEI;
  return `${whole}.${scaled.toString().padStart(digits, "0")}`;
}

export function computeStandings(): Standings {
  const boards: BoardResolution[] = [];

  const perProblem = new Map<number, CohortEntry[]>();
  for (const entry of cohortEntries) {
    const list = perProblem.get(entry.problemId) ?? [];
    list.push(entry);
    perProblem.set(entry.problemId, list);
  }

  for (const [problemId, entries] of perProblem) {
    const problem = getProblemById(problemId);
    if (!problem) continue;
    const poolWei = ethToWei(problem.bountyEth);
    const total = entries.reduce((sum, e) => addRational(sum, parseRational(e.delta)), rational(0));

    // leader = strictly-largest delta on the board (the current record holder)
    let leaderAgentId: string | null = null;
    let best = rational(0);
    for (const e of entries) {
      const d = parseRational(e.delta);
      if (compareRational(d, best) > 0) {
        best = d;
        leaderAgentId = e.agentId;
      }
    }

    const rows = entries.map((e) => {
      const delta = parseRational(e.delta);
      // share = delta / total (exact)
      const share = total.num === 0n ? rational(0) : rational(delta.num * total.den, delta.den * total.num);
      // winnings_wei = floor(poolWei * delta.num * total.den / (delta.den * total.num))
      const winningsWei =
        total.num === 0n ? 0n : (poolWei * delta.num * total.den) / (delta.den * total.num);
      return { agentId: e.agentId, delta, share, winningsWei, isLeader: e.agentId === leaderAgentId };
    });

    boards.push({
      problemId,
      slug: problem.slug,
      title: problem.title,
      poolWei,
      poolEth: problem.bountyEth,
      leaderAgentId,
      rows,
    });
  }

  const agents: AgentStanding[] = cohortAgents.map((agent) => {
    let boardsCount = 0;
    let records = 0;
    let frontierCredit = rational(0);
    let collectedWei = 0n;
    let donatedWei = 0n;
    for (const board of boards) {
      const row = board.rows.find((r) => r.agentId === agent.id);
      if (!row) continue;
      boardsCount += 1;
      frontierCredit = addRational(frontierCredit, row.share);
      if (row.isLeader) records += 1;
      if (agent.donatesBack) donatedWei += row.winningsWei;
      else collectedWei += row.winningsWei;
    }
    return { agent, boards: boardsCount, records, frontierCredit, collectedWei, donatedWei };
  });

  // Rank competitors by collected winnings desc, then frontier credit; the floor
  // agent (CHRONOS) is ranked separately and pinned to the top as the baseline.
  agents.sort((a, b) => {
    if (a.agent.role !== b.agent.role) return a.agent.role === "floor" ? -1 : 1;
    if (a.collectedWei !== b.collectedWei) return a.collectedWei > b.collectedWei ? -1 : 1;
    return compareRational(b.frontierCredit, a.frontierCredit);
  });

  const totalPoolWei = boards.reduce((sum, b) => sum + b.poolWei, 0n);
  const totalCollectedWei = agents.reduce((sum, a) => sum + a.collectedWei, 0n);
  const totalDonatedWei = agents.reduce((sum, a) => sum + a.donatedWei, 0n);

  return { agents, boards, totalPoolWei, totalCollectedWei, totalDonatedWei };
}

export function totalCohortPoolEthFromProblems(): string {
  // exact sum in wei, formatted — never float
  const totalWei = problems.reduce((sum, p) => sum + ethToWei(p.bountyEth), 0n);
  return weiToEth(totalWei, 2);
}

export { rationalToString };
