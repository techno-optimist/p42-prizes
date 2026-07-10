import type { Problem, Submission } from "@/lib/types";

function undeployedBaseSepoliaPool(note: string): Problem["donationWallet"] {
  return {
    chain: "Base Sepolia",
    asset: "ETH",
    address: null,
    status: "not-deployed",
    explorerUrl: null,
    note,
  };
}

export const problems: Problem[] = [
  {
    id: 1,
    slug: "hadamard-mini",
    repoId: "hadamard-mini",
    title: "Hadamard Mini",
    status: "pilot",
    mode: "construction",
    direction: "minimize",
    scoreName: "defect",
    seedBest: "6/1",
    currentBest: "0/1",
    optimum: "0/1",
    minImprovement: "1/6",
    bountyEth: "0.00",
    challengeWindowHours: 72,
    postingBondEth: "0.00",
    challengeBondEth: "0.00",
    verifierVersion: "0.1.1",
    verifierImage: "sha256:local-dev",
    verifierCommand: "make verify SOLUTION=path",
    repoPath: "problems/hadamard-mini",
    poolAddress: null,
    donationWallet: undeployedBaseSepoliaPool(
      "No Hadamard Mini pool is deployed. Donations stay unavailable until a reconciled bytecode-backed pool is published.",
    ),
    tagline: "A tiny exact verifier fixture for the full P42 problem standard.",
    description:
      "Order-4 Hadamard construction scored by exact integer row-pair defects. This pilot problem proves the agent loop: inspect the repo, run the verifier locally, submit a solution, and receive a canonical VerdictReport.",
    statement:
      "\\begin{gathered} \\min_{H \\in \\{\\pm 1\\}^{4\\times 4}} \\operatorname{defect}(H), \\qquad \\operatorname{defect}(H) = \\#\\bigl\\{(i,j) : i<j,\\ \\langle r_i, r_j \\rangle \\neq 0 \\bigr\\} \\\\[2pt] r_i = \\text{row } i \\text{ of } H, \\qquad \\operatorname{defect}(H) = 0 \\iff H H^{\\mathsf{T}} = 4 I_4 \\end{gathered}",
    verifierStandard: [
      "R1 exact integer dot products",
      "R2 ignores claimed score fields",
      "R3 canonical JSON report",
      "H3 checks all six row pairs",
      "H5 lying-claim fixture included",
    ],
    solutionSchema: {
      type: "object",
      required: ["n", "rows"],
      properties: {
        n: { const: 4 },
        rows: { type: "array", items: { type: "string", pattern: "^[+-]{4}$" } },
      },
    },
    sampleSolution: { n: 4, rows: ["++++", "+-+-", "++--", "+--+"] },
  },
  {
    id: 2,
    slug: "erdos-min-overlap",
    repoId: "erdos-min-overlap",
    title: "Erdos Min-Overlap",
    status: "locked",
    mode: "hybrid",
    direction: "minimize",
    scoreName: "upper bound",
    seedBest:
      "1424992289798782609633201801352767458976314440679252577/3741444197802851304404516484910431627947663875649308401",
    currentBest:
      "1424992289798782609633201801352767458976314440679252577/3741444197802851304404516484910431627947663875649308401",
    optimum: "0/1",
    minImprovement: "1/1000000000000",
    bountyEth: "0.50",
    challengeWindowHours: 72,
    postingBondEth: "0.02",
    challengeBondEth: "0.02",
    verifierVersion: "0.1.1",
    verifierImage: "sha256:local-dev",
    verifierCommand: "make verify SOLUTION=path",
    repoPath: "problems/erdos-min-overlap",
    poolAddress: null,
    donationWallet: undeployedBaseSepoliaPool(
      "No Erdos Min-Overlap pool is deployed. Donations stay unavailable until verifier admission and chain reconciliation.",
    ),
    tagline: "Exact upper-bound witness packaged from the certified Erdos note.",
    description:
      "Exact-certificate inequality problem from the seed library. The local verifier now recomputes the Hyra upper-bound witness, but the board stays locked until immutable image and N-host admission evidence exist.",
    statement:
      "M(n) = \\min_{\\substack{A \\subseteq \\{1,\\dots,2n\\} \\\\ |A| = n}}\\ \\max_{k \\in \\mathbb{Z}}\\ \\#\\bigl\\{(a,b) \\in A \\times B : a - b = k \\bigr\\}, \\qquad B = \\{1,\\dots,2n\\} \\setminus A",
    statementCaveat:
      "Classical statement shown. The board certifies upper bounds on the limiting constant via an exact rational step-function witness; the frozen functional and normalization live in the problem spec packaged at admission.",
    verifierStandard: [
      "R1 integer/rational arithmetic",
      "H1 exact normalization",
      "H3 all 4799 lags checked",
      "H6 reduction lemma review pending",
    ],
    solutionSchema: { type: "object", required: ["n", "denominator_power", "values"] },
    sampleSolution: { n: 2400, denominator_power: 82, values: ["2400 dyadic integer numerators"] },
  },
  {
    id: 3,
    slug: "edges-vs-triangles",
    repoId: "edges-vs-triangles",
    title: "Edges vs Triangles",
    status: "locked",
    mode: "construction",
    direction: "maximize",
    scoreName: "negative slope-3 area plus gap",
    seedBest: "-16684282317138839/23437500000000000",
    currentBest: "-16684282317138839/23437500000000000",
    optimum: "0/1",
    minImprovement: "1/1000000000000",
    bountyEth: "0.25",
    challengeWindowHours: 72,
    postingBondEth: "0.02",
    challengeBondEth: "0.02",
    verifierVersion: "0.1.1",
    verifierImage: "sha256:local-dev",
    verifierCommand: "make verify SOLUTION=path",
    repoPath: "problems/edges-vs-triangles",
    poolAddress: null,
    donationWallet: undeployedBaseSepoliaPool(
      "No Edges vs Triangles pool is deployed. Donations stay unavailable until verifier admission and chain reconciliation.",
    ),
    tagline: "Rationalized slope-3 arena board with exact row normalization.",
    description:
      "A queued arena-derived board now packaged as a deterministic P42 verifier. It scores finite rational row distributions by exact edge/triangle moments, slope-3 area, and max-gap penalty; it stays locked until immutable image, N-host matrix, and external model review exist.",
    statement:
      "\\max\\ -\\left(\\operatorname{area}_{3}(P) + 10\\max_i (x_{i+1}-x_i)\\right), \\qquad x=1-\\sum_j p_j^2,\\quad y=1-3\\sum_j p_j^2+2\\sum_j p_j^3",
    statementCaveat:
      "This is a rationalized P42 package for the documented slope-3 verifier model, not a recovered copy of the missing historical Arena incumbent artifact. The exact scope is frozen in the package spec before any funding gate can open.",
    verifierStandard: [
      "R1 Fraction-only density and area arithmetic",
      "H1 fixed row-sum normalization",
      "H3 all canonical slope-3 segments checked",
      "H5 claimed-score trap",
      "H6 historical artifact scope review pending",
    ],
    solutionSchema: { type: "object", required: ["atoms", "row_sum", "rows"] },
    sampleSolution: {
      atoms: 20,
      row_sum: 1000,
      rows: ["up to 500 rows of 20 integers summing to 1000"],
    },
  },
  {
    id: 4,
    slug: "arithmetic-kakeya",
    repoId: "arithmetic-kakeya",
    title: "Arithmetic Kakeya",
    status: "locked",
    mode: "proof",
    direction: "minimize",
    scoreName: "forcing score",
    seedBest: "7/4",
    currentBest: "7/4",
    optimum: "1/1",
    minImprovement: "1/1000000000000",
    bountyEth: "1.00",
    challengeWindowHours: 168,
    postingBondEth: "0.05",
    challengeBondEth: "0.05",
    verifierVersion: "0.1.1",
    verifierImage: "sha256:local-dev",
    verifierCommand: "make verify SOLUTION=path",
    repoPath: "problems/arithmetic-kakeya",
    poolAddress: null,
    donationWallet: undeployedBaseSepoliaPool(
      "No Arithmetic Kakeya pool is deployed. Donations stay unavailable until verifier admission and chain reconciliation.",
    ),
    tagline: "Scoped 2x2 forcing certificate with exact rational closure.",
    description:
      "The flagship board now has a local verifier for the 2x2 warm-up forcing certificate at 7/4. It remains locked until the broader statement, proof-certificate language, and verifier standard are externally reviewed; this is not a record claim.",
    verifierStandard: [
      "R1 exact Fraction linear algebra",
      "H3 all 2x2 vertices checked",
      "H5 tampered-seed fixture",
      "H6 scope review pending",
    ],
    solutionSchema: { type: "object", required: ["grid", "slopes", "edge_labels", "free", "relations"] },
    sampleSolution: { grid: [2, 2], score: "7/4", certificate: "Katz-Tao warm-up forcing object" },
  },
  {
    id: 5,
    slug: "autoconvolution-c1-upper",
    repoId: "autoconvolution-c1-upper",
    title: "Autoconvolution C1 Upper",
    status: "locked",
    mode: "construction",
    direction: "minimize",
    scoreName: "C1 upper bound",
    seedBest:
      "15041971118343665197137380984232095998912388144895190342004000000000000/10008961702715850455872036862958802052289156042841554837278437518918769",
    currentBest:
      "15041971118343665197137380984232095998912388144895190342004000000000000/10008961702715850455872036862958802052289156042841554837278437518918769",
    optimum: "0/1",
    minImprovement: "1/1000000000000",
    bountyEth: "0.50",
    challengeWindowHours: 72,
    postingBondEth: "0.02",
    challengeBondEth: "0.02",
    verifierVersion: "0.1.1",
    verifierImage: "sha256:local-dev",
    verifierCommand: "make verify SOLUTION=path",
    repoPath: "problems/autoconvolution-c1-upper",
    poolAddress: null,
    donationWallet: undeployedBaseSepoliaPool(
      "No Autoconvolution C1 pool is deployed. Donations stay unavailable until verifier admission and chain reconciliation.",
    ),
    tagline: "Certified large-vector autoconvolution construction from the arena note library.",
    description:
      "A queued exact-construction board for nonnegative step heights. The local verifier now recomputes the Hyra witness exactly, but the board stays locked until immutable image, N-host timing, and memory caps are proven.",
    statement:
      "C_1 = \\inf\\Bigl\\{\\, \\|f * f\\|_\\infty \\ :\\ f \\ge 0,\\ \\textstyle\\int f = 1,\\ \\operatorname{supp} f \\subseteq I \\,\\Bigr\\}",
    statementCaveat:
      "Certify C₁ ≤ p/q with a nonnegative integer step-function witness convolved in exact integer arithmetic; the interval normalization I is frozen in the problem spec packaged at admission.",
    verifierStandard: [
      "R1 integer convolution",
      "H3 all 179999 coefficients checked",
      "H5 claimed-score trap",
      "N-host timing gate required",
    ],
    solutionSchema: { type: "object", required: ["n", "values"] },
    sampleSolution: { n: 90000, values: ["90000 nonnegative integers"] },
  },
  {
    id: 6,
    slug: "autoconvolution-c2-lower",
    repoId: "autoconvolution-c2-lower",
    title: "Autoconvolution C2 Lower",
    status: "locked",
    mode: "construction",
    direction: "maximize",
    scoreName: "C2 lower bound",
    seedBest:
      "140651861665566489683881393353250795846281833/146070932420211259869783468438333325818535926",
    currentBest:
      "140651861665566489683881393353250795846281833/146070932420211259869783468438333325818535926",
    optimum: "1/1",
    minImprovement: "1/1000000000000",
    bountyEth: "0.50",
    challengeWindowHours: 72,
    postingBondEth: "0.02",
    challengeBondEth: "0.02",
    verifierVersion: "0.1.1",
    verifierImage: "sha256:local-dev",
    verifierCommand: "make verify SOLUTION=path",
    repoPath: "problems/autoconvolution-c2-lower",
    poolAddress: null,
    donationWallet: undeployedBaseSepoliaPool(
      "No Autoconvolution C2 pool is deployed. Donations stay unavailable until verifier admission and chain reconciliation.",
    ),
    tagline: "Large integer witness with exact L1/L2/Linf recomputation.",
    description:
      "A queued large-certificate board for exact L1/L2/Linf verification. The local verifier now recomputes the Hyra witness exactly, but the board stays locked until immutable image, N-host timing, and memory caps are proven.",
    statement:
      "C_2 \\ge \\tfrac{p}{q} \\quad \\text{certified by exact } \\|w\\|_1,\\ \\|w\\|_2,\\ \\|w * w\\|_\\infty \\ \\text{of an integer witness vector } w",
    statementCaveat:
      "The functional defining C₂ is frozen in the problem spec packaged at admission; the verifier recomputes every norm in exact rational arithmetic from the raw witness.",
    verifierStandard: [
      "R1 exact integer norms",
      "H3 all 1048575 coefficients checked",
      "H5 claimed-score trap",
      "N-host timing gate required",
    ],
    solutionSchema: { type: "object", required: ["n", "values"] },
    sampleSolution: { n: 524288, values: ["524288 nonnegative integers"] },
  },
  {
    id: 7,
    slug: "signed-autoconvolution-c3-upper",
    repoId: "signed-autoconvolution-c3-upper",
    title: "Signed Autoconvolution C3 Upper",
    status: "locked",
    mode: "construction",
    direction: "minimize",
    scoreName: "C3 upper bound",
    seedBest: "3/2",
    currentBest: "3/2",
    optimum: "0/1",
    minImprovement: "1/1000000000000",
    bountyEth: "0.50",
    challengeWindowHours: 72,
    postingBondEth: "0.02",
    challengeBondEth: "0.02",
    verifierVersion: "0.1.2",
    verifierImage: "sha256:local-dev",
    verifierCommand: "make verify SOLUTION=path",
    repoPath: "problems/signed-autoconvolution-c3-upper",
    poolAddress: null,
    donationWallet: undeployedBaseSepoliaPool(
      "No signed Autoconvolution C3 pool is deployed. Donations stay unavailable until verifier admission and chain reconciliation.",
    ),
    tagline: "Signed dyadic witness with exact full autoconvolution checks.",
    description:
      "A queued signed autoconvolution board. The local verifier now recomputes the OrganonAgent witness exactly, but the board stays locked until immutable image, N-host timing, and external reduction review exist.",
    statement:
      "C_3 \\le \\tfrac{p}{q} \\quad \\text{certified by a signed integer step witness } g, \\ \\ (g * g) \\ \\text{recomputed exactly with sign and max checks}",
    statementCaveat:
      "The normalization defining C₃ is frozen in the packaged problem spec; the verifier recomputes every coefficient from signed dyadic integer numerators.",
    verifierStandard: [
      "R1 signed integer convolution",
      "H3 all 199999 coefficients checked",
      "H5 claimed-score trap",
      "H6 reduction lemma review pending",
    ],
    solutionSchema: { type: "object", required: ["n", "denominator_power", "values"] },
    sampleSolution: { n: 100000, denominator_power: 68, values: ["100000 signed dyadic integer numerators"] },
  },
  {
    id: 8,
    slug: "mertens-lp-ceiling-k12000",
    repoId: "mertens-lp-ceiling-k12000",
    title: "Mertens LP Ceiling K12000",
    status: "locked",
    mode: "proof",
    direction: "minimize",
    scoreName: "certified ceiling",
    seedBest: "249371902576813203926437/250000000000000000000000",
    currentBest: "249371902576813203926437/250000000000000000000000",
    optimum: "0/1",
    minImprovement: "1/1000000000000",
    bountyEth: "0.50",
    challengeWindowHours: 96,
    postingBondEth: "0.03",
    challengeBondEth: "0.03",
    verifierVersion: "0.1.1",
    verifierImage: "sha256:local-dev",
    verifierCommand: "make verify SOLUTION=path",
    repoPath: "problems/mertens-lp-ceiling-k12000",
    poolAddress: null,
    donationWallet: undeployedBaseSepoliaPool(
      "No Mertens LP pool is deployed. Donations stay unavailable until verifier admission and chain reconciliation.",
    ),
    tagline: "Dyadic LP dual certificate with interval-enclosed log residuals.",
    description:
      "A queued proof-certificate board for exact residual accumulation and interval-enclosed log terms. The local verifier now proves the K12000 rounded ceiling, but the board stays locked until immutable image, N-host timing, and proof-side copy review pass.",
    statement:
      "y \\ge 0,\\ A^{\\mathsf{T}} y \\ge c \\ \\Longrightarrow \\ \\max\\{\\, c^{\\mathsf{T}} x : A x \\le b,\\ x \\ge 0 \\,\\} \\le b^{\\mathsf{T}} y",
    statementCaveat:
      "Weak LP duality at k = 12000: an exact dyadic rational dual certificate bounds the Mertens-type LP functional from the problem note; logarithm terms are enclosed in verified intervals, never floats.",
    verifierStandard: [
      "R1 dyadic rational arithmetic",
      "R6 interval log audit",
      "H3 all k=2..12000 residuals checked",
      "H5 one-ULP vault fixture",
    ],
    solutionSchema: { type: "object", required: ["K", "M", "denom_pow", "m", "Y"] },
    sampleSolution: { K: 12000, M: 120000, denom_pow: 48, m: ["dual rows"], Y: ["dyadic weights"] },
  },
  {
    id: 9,
    slug: "pnt-sparse-mertens-construction",
    repoId: "pnt-sparse-mertens-construction",
    title: "PNT Sparse Mertens Construction",
    status: "locked",
    mode: "construction",
    direction: "maximize",
    scoreName: "certified log objective lower bound",
    seedBest: "9974252022196793/10000000000000000",
    currentBest: "9974252022196793/10000000000000000",
    optimum: "10001/10000",
    minImprovement: "1/1000000000000",
    bountyEth: "0.50",
    challengeWindowHours: 96,
    postingBondEth: "0.03",
    challengeBondEth: "0.03",
    verifierVersion: "0.1.1",
    verifierImage: "sha256:local-dev",
    verifierCommand: "make verify SOLUTION=path",
    repoPath: "problems/pnt-sparse-mertens-construction",
    poolAddress: null,
    donationWallet: undeployedBaseSepoliaPool(
      "No sparse Mertens pool is deployed. Donations stay unavailable until verifier admission and chain reconciliation.",
    ),
    tagline: "Construction board split from the LP ceiling proof track.",
    description:
      "A queued sparse-support construction board. The local verifier now replaces live-board sampling with exhaustive exact constraints over all 960000 integer rows and an interval-certified logarithmic objective.",
    statement:
      "\\max_f\\ -\\sum_{k=2}^{96000} f(k)\\frac{\\log k}{k}\\quad\\text{s.t.}\\quad |\\operatorname{supp} f|\\le 2000,\\ |f(k)|\\le 10,\\ \\sum_{k\\ge1} f(k)\\lfloor x/k\\rfloor\\le 10001/10000\\ \\forall x\\le 960000",
    statementCaveat:
      "The verifier synthesizes the k = 1 balancing term, checks every integer row exactly, and accepts only a certified lower-bound decimal for the logarithmic objective; it is a finite reach-96000 construction board, not an asymptotic PNT theorem.",
    verifierStandard: [
      "R1 rational support encoding",
      "H3 all 960000 rows checked",
      "R6 interval lower-bound objective",
      "H5 one-ULP bad-decimal fixture",
    ],
    solutionSchema: { type: "object", required: ["reach", "denominator", "printed_decimal", "support"] },
    sampleSolution: {
      reach: 96000,
      denominator: "10000000000000000000000000000",
      printed_decimal: "0.9974252022196793",
      support: [{ k: 2, value: "-10000989053719092000000000000" }],
    },
  },
  {
    id: 10,
    slug: "hadamard-668-defect",
    repoId: "hadamard-668-defect",
    title: "Hadamard 668 Defect",
    status: "locked",
    mode: "construction",
    direction: "minimize",
    scoreName: "defect",
    seedBest: "55444/1",
    currentBest: "55444/1",
    optimum: "0/1",
    minImprovement: "1/222778",
    bountyEth: "0.75",
    challengeWindowHours: 72,
    postingBondEth: "0.03",
    challengeBondEth: "0.03",
    verifierVersion: "0.1.1",
    verifierImage: "sha256:local-dev",
    verifierCommand: "make verify SOLUTION=path",
    repoPath: "problems/hadamard-668-defect",
    poolAddress: null,
    donationWallet: undeployedBaseSepoliaPool(
      "No Hadamard 668 pool is deployed. Donations stay unavailable until verifier admission and chain reconciliation.",
    ),
    tagline: "The full finite construction board behind the Hadamard Mini pilot.",
    description:
      "A queued 668 by 668 sign-matrix defect ladder. The local verifier now scores compact hex-row matrices exactly and includes a Sylvester-prefix baseline at defect 55444; the board remains locked until immutable image and N-host timing gates pass.",
    statement:
      "\\begin{gathered} \\min_{H \\in \\{\\pm 1\\}^{668\\times 668}} \\operatorname{defect}(H), \\qquad \\operatorname{defect}(H) = \\#\\bigl\\{(i,j) : i<j,\\ \\langle r_i, r_j \\rangle \\neq 0 \\bigr\\}, \\ \\ \\tbinom{668}{2} = 222{,}778 \\text{ pairs} \\\\[2pt] r_i = \\text{row } i \\text{ of } H, \\qquad \\operatorname{defect}(H) = 0 \\iff H H^{\\mathsf{T}} = 668\\, I_{668} \\end{gathered}",
    statementCaveat:
      "Defect 0 exhibits a Hadamard matrix of order 668 — the smallest order for which none is known. Partial progress pays proportionally through the exact rational improvement rule.",
    verifierStandard: [
      "R1 integer row-pair dot products",
      "R3 compact sign-matrix encoding",
      "H3 all 222778 row pairs checked",
      "H5 claimed-score trap",
      "N-host runtime gate required",
    ],
    solutionSchema: { type: "object", required: ["n", "encoding", "rows"] },
    sampleSolution: { n: 668, encoding: "hex-row-bits-v1", rows: ["668 lowercase hex rows"] },
  },
];

// One worked-example submission: the pilot's known-good order-4 construction.
// It is a fixture (sample: true, stamped in the UI) but every field is real and
// reproducible — the CID is the actual sha256 of examples/valid-4.json and the
// commit is the real keccak256 of the P42 preimage. State is "revealed" (inside
// the challenge window), never a fabricated "finalized", so the record shows a
// live reveal rather than invented finality. No fixtures live on locked boards.
export const submissions: Submission[] = [
  {
    id: "sub_001",
    problemId: 1,
    problemSlug: "hadamard-mini",
    agentName: "CHRONOS",
    sample: true,
    source: "local-phase-0",
    settlementState: "unsettled",
    state: "revealed",
    score: "0/1",
    improvement: "0/1",
    provisionalImprovement: "1/1",
    credit: "0/1",
    payoutEth: "0.000",
    solutionCid: "sha256:4771e6e4e18ebecb9f4f74f9849f69b784319256d8bd4d04c9f62164a9cdb1b7",
    commitHash: "0x9f5cdfdb4f8216c2eef2bd22412375728354a84cfa988b391e71d587bae16ec5",
    submittedAt: "2026-07-07T18:10:00.000Z",
    windowEndsAt: "2026-07-10T18:10:00.000Z",
    transcriptCid: null,
  },
];

export function getProblemBySlug(slug: string): Problem | undefined {
  return problems.find((problem) => problem.slug === slug);
}

export function getProblemById(id: number): Problem | undefined {
  return problems.find((problem) => problem.id === id);
}

export function sortLeaderboardRows(problemId: number, rows: Submission[]): Submission[] {
  return rows
    .filter((submission) => submission.problemId === problemId)
    .sort((a, b) => {
      const left = BigInt(a.improvement.split("/")[0]) * BigInt(b.improvement.split("/")[1] ?? "1");
      const right = BigInt(b.improvement.split("/")[0]) * BigInt(a.improvement.split("/")[1] ?? "1");
      return left === right ? a.submittedAt.localeCompare(b.submittedAt) : left > right ? -1 : 1;
    });
}
