// Lean demo deployer for battle-testing the on-chain-at-reveal DA path.
//
// Deploys Pool + Ledger + SubmissionManager (with the DA-mode immutables) +
// ChallengeManager, wires them, and writes an agent-compatible manifest. Uses
// tiny demo bonds and a short challenge window so a full lifecycle runs in
// seconds. Env:
//   P42_OUT                       (required) manifest output path
//   P42_SEED_SCORE_ATOMS          (required*) frontier seed as int256 atoms
//                                 (ceil(true_best_known_minimization_score * 1e18))
//   P42_SEED_SCORE                (*alternative) exact rational "num/den"
//                                 minimization score; atoms computed as ceil(num*1e18/den)
//   P42_MIN_IMPROVEMENT_ATOMS     (default 1) min marginal in score atoms
//   P42_CHALLENGE_WINDOW_SECONDS  (default 90)
//   P42_ONCHAIN_DA                (default "true")
//   P42_MAX_SOLUTION_BYTES        (default 524288)
//   P42_RESOLVER_ADDRESS          (default deployer)
//   P42_TREASURY_ADDRESS          (default deployer)
import { writeFile, mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { network } from "hardhat";

const env = (k, d) => (process.env[k] && process.env[k].trim() !== "" ? process.env[k].trim() : d);

// SHARED FIXED-POINT CONVENTION — keep in sync with agent/lib.mjs and
// P42SubmissionManager.SCORE_ATOM_SCALE: score_atoms = ceil(score * 1e18).
const SCORE_SCALE = 1_000_000_000_000_000_000n;
function atomsFromScoreRational(text) {
  const [numStr, denStr = "1"] = String(text).trim().split("/");
  let num = BigInt(numStr);
  let den = BigInt(denStr);
  if (den === 0n) throw new Error(`seed score ${text} has a zero denominator`);
  if (den < 0n) { num = -num; den = -den; }
  const scaled = num * SCORE_SCALE;
  let q = scaled / den; // BigInt division truncates toward zero == ceil for negatives
  if (scaled % den !== 0n && scaled > 0n) q += 1n;
  return q;
}
// Frontier seed (audit F1): initializes the on-chain bestScoreAtoms — the
// TRUE best-known absolute score, never a trivial bound, or resubmitting a
// known construction mints a false prize. Required, no default.
function resolveSeedScoreAtoms() {
  const direct = env("P42_SEED_SCORE_ATOMS", null);
  if (direct !== null) return BigInt(direct);
  const rational = env("P42_SEED_SCORE", null);
  if (rational !== null) return atomsFromScoreRational(rational);
  throw new Error("set P42_SEED_SCORE_ATOMS (int256 atoms) or P42_SEED_SCORE (exact rational minimization score)");
}

const DEMO = {
  alphaBps: 200n,
  betaBps: 500n,
  feeBps: 0n,
  minPostingBondWei: 100_000_000_000_000n,      // 0.0001 ETH
  minCounterBondWei: 100_000_000_000_000n,       // 0.0001 ETH
  rerunCostWei: 10_000_000_000_000n,             // 0.00001 ETH
  rerunCostMultiplierBps: 30_000n,
  resolverDecisionBondWei: 10_000_000_000_000n,  // 0.00001 ETH
  resolverFraudWindowSeconds: 30n,
};

const connection = await network.create("baseSepolia");
const { ethers } = connection;
const [deployer] = await ethers.getSigners();
if (!deployer) throw new Error("no deployer signer (set BASE_SEPOLIA_PRIVATE_KEY)");

const OUT = env("P42_OUT", null);
if (!OUT) throw new Error("set P42_OUT (manifest output path)");
const challengeWindow = BigInt(env("P42_CHALLENGE_WINDOW_SECONDS", "90"));
const onchainDa = env("P42_ONCHAIN_DA", "true") === "true";
const maxSolutionBytes = BigInt(env("P42_MAX_SOLUTION_BYTES", String(512 * 1024)));
const seedScoreAtoms = resolveSeedScoreAtoms();
const minImprovementAtoms = BigInt(env("P42_MIN_IMPROVEMENT_ATOMS", "1"));
const owner = deployer.address;
const treasury = env("P42_TREASURY_ADDRESS", owner);
const resolver = env("P42_RESOLVER_ADDRESS", owner);

console.log(`deployer/owner: ${owner}`);
console.log(`DA mode: ${onchainDa ? `on-chain (maxSolutionBytes=${maxSolutionBytes})` : "off-chain"}  window=${challengeWindow}s`);
console.log(`frontier seed: seedScoreAtoms=${seedScoreAtoms}  minImprovementAtoms=${minImprovementAtoms}`);

async function deploy(name, args) {
  const f = await ethers.getContractFactory(name);
  const c = await f.deploy(...args);
  await c.waitForDeployment();
  const addr = await c.getAddress();
  console.log(`  ${name}: ${addr}`);
  return { c, addr };
}

const pool = await deploy("P42BountyPool", [owner]);
const ledger = await deploy("P42PayoutLedger", [pool.addr, owner, treasury, DEMO.feeBps]);
await (await pool.c.setLedger(ledger.addr)).wait();
const subs = await deploy("P42SubmissionManager", [
  pool.addr, ledger.addr, owner, treasury,
  DEMO.alphaBps, DEMO.minPostingBondWei, challengeWindow,
  onchainDa, maxSolutionBytes,
  seedScoreAtoms, minImprovementAtoms,
]);
await (await ledger.c.setCreditRecorder(subs.addr)).wait();
const chal = await deploy("P42ChallengeManager", [
  owner, resolver, treasury, subs.addr,
  challengeWindow, DEMO.betaBps, DEMO.minCounterBondWei,
  DEMO.rerunCostWei, DEMO.rerunCostMultiplierBps,
  DEMO.resolverDecisionBondWei, DEMO.resolverFraudWindowSeconds,
]);
await (await subs.c.setChallengeManager(chal.addr)).wait();

const chain = await ethers.provider.getNetwork();
const startBlock = await ethers.provider.getBlockNumber();
const manifest = {
  schema: "p42-prizes/deployment-manifest/v1",
  status: "base-sepolia-testnet-demo",
  deployedAt: new Date().toISOString(),
  network: { name: "baseSepolia", chainId: Number(chain.chainId), explorerBaseUrl: "https://sepolia.basescan.org" },
  // Scanners (operator/indexer) start here so a from-block-0 getLogs never hits
  // the public RPC's range cap.
  indexer: { startBlock },
  roles: { deployer: deployer.address, owner, treasury, resolver },
  da: { onchainDa, maxSolutionBytes: Number(maxSolutionBytes) },
  // The frontier seed this SubmissionManager was constructed with:
  // bestScoreAtoms starts here and only strictly lower scores can earn credit.
  frontier: {
    seedScoreAtoms: seedScoreAtoms.toString(),
    minImprovementAtoms: minImprovementAtoms.toString(),
    scoreAtomScale: SCORE_SCALE.toString(),
  },
  parameters: {
    alphaBps: Number(DEMO.alphaBps), betaBps: Number(DEMO.betaBps), feeBps: Number(DEMO.feeBps),
    challengeWindowSeconds: Number(challengeWindow),
    minPostingBondWei: DEMO.minPostingBondWei.toString(),
    minCounterBondWei: DEMO.minCounterBondWei.toString(),
    resolverDecisionBondWei: DEMO.resolverDecisionBondWei.toString(),
    resolverFraudWindowSeconds: Number(DEMO.resolverFraudWindowSeconds),
  },
  contracts: {
    pool: { address: pool.addr },
    ledger: { address: ledger.addr },
    submissions: { address: subs.addr },
    challenges: { address: chal.addr },
  },
};
await mkdir(dirname(resolve(OUT)), { recursive: true });
await writeFile(resolve(OUT), JSON.stringify(manifest, null, 2) + "\n");
console.log(`\nmanifest -> ${OUT}`);
await connection.close?.();
