// Lean demo deployer for battle-testing the on-chain-at-reveal DA path.
//
// Deploys Pool + Ledger + SubmissionManager (with the DA-mode immutables) +
// ChallengeManager, wires them, and writes an agent-compatible manifest. Uses
// tiny demo bonds and a short challenge window so a full lifecycle runs in
// seconds. Env:
//   P42_OUT                       (required) manifest output path
//   P42_CHALLENGE_WINDOW_SECONDS  (default 90)
//   P42_ONCHAIN_DA                (default "true")
//   P42_MAX_SOLUTION_BYTES        (default 524288)
//   P42_RESOLVER_ADDRESS          (default deployer)
//   P42_TREASURY_ADDRESS          (default deployer)
import { writeFile, mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { network } from "hardhat";

const env = (k, d) => (process.env[k] && process.env[k].trim() !== "" ? process.env[k].trim() : d);

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
const owner = deployer.address;
const treasury = env("P42_TREASURY_ADDRESS", owner);
const resolver = env("P42_RESOLVER_ADDRESS", owner);

console.log(`deployer/owner: ${owner}`);
console.log(`DA mode: ${onchainDa ? `on-chain (maxSolutionBytes=${maxSolutionBytes})` : "off-chain"}  window=${challengeWindow}s`);

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
