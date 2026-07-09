import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

import { network } from "hardhat";

const BASE_SEPOLIA_CHAIN_ID = 84532n;
const DEFAULTS = {
  alphaBps: 200n,
  betaBps: 500n,
  challengeWindowSeconds: 72n * 60n * 60n,
  feeBps: 0n,
  minCounterBondWei: 20_000_000_000_000_000n,
  minPostingBondWei: 10_000_000_000_000_000n,
  rerunCostMultiplierBps: 30_000n,
  rerunCostWei: 10_000_000_000_000_000n,
  resolverDecisionBondWei: 5_000_000_000_000_000n,
  resolverFraudWindowSeconds: 24n * 60n * 60n
};

const REQUIRED_ENV = [
  "BASE_SEPOLIA_RPC_URL",
  "BASE_SEPOLIA_PRIVATE_KEY",
  "P42_TREASURY_ADDRESS",
  "P42_RESOLVER_ADDRESS",
  "P42_PROBLEM_SPEC_HASH",
  "P42_VERIFIER_SOURCE_HASH",
  "P42_VERIFIER_IMAGE_HASH",
  "P42_ADMISSION_MATRIX_HASH",
  "P42_METADATA_URI"
];

function requiredEnv(name) {
  const value = process.env[name];
  if (value === undefined || value.trim() === "") {
    throw new Error(`Missing required env var: ${name}`);
  }
  return value.trim();
}

function uintEnv(name, fallback) {
  const value = process.env[name];
  if (value === undefined || value.trim() === "") return fallback;
  const parsed = BigInt(value.trim());
  if (parsed < 0n) throw new Error(`${name} must be non-negative`);
  return parsed;
}

function bpsEnv(name, fallback) {
  const parsed = uintEnv(name, fallback);
  if (parsed > 10_000n && name !== "P42_RERUN_COST_MULTIPLIER_BPS") {
    throw new Error(`${name} must be <= 10000`);
  }
  return parsed;
}

// SHARED FIXED-POINT CONVENTION — keep in sync with agent/lib.mjs and
// P42SubmissionManager.SCORE_ATOM_SCALE: score_atoms = ceil(score * 1e18),
// exact rational ceiling (CEIL: the seed/score is never under-reported, so the
// on-chain marginal credit is never over-stated).
const SCORE_SCALE = 1_000_000_000_000_000_000n;

function parseRational(text, label) {
  const match = /^(-?\d+)(?:\/(\d+))?$/.exec(String(text).trim());
  if (!match) throw new Error(`${label} must be an exact rational "num/den", got: ${text}`);
  const num = BigInt(match[1]);
  const den = BigInt(match[2] ?? "1");
  if (den === 0n) throw new Error(`${label} has a zero denominator`);
  return { num, den };
}

function ceilAtoms({ num, den }) {
  const scaled = num * SCORE_SCALE;
  let q = scaled / den; // BigInt division truncates toward zero == ceil for negatives
  if (scaled % den !== 0n && scaled > 0n) q += 1n;
  return q;
}

// Extracts a top-level `NAME = Fraction(num, den)` literal from verifier
// source. \s matches newlines: tolerates multi-line Fraction( num, den, )
// literals. Returns null when the constant is absent or not a plain literal
// (e.g. Fraction(1, TOTAL_PAIRS)) — callers must then fail loudly, never
// guess.
function fractionLiteral(source, name) {
  const pattern = new RegExp(`^${name}\\s*=\\s*Fraction\\(\\s*(-?\\d+)\\s*,\\s*(\\d+)\\s*,?\\s*\\)`, "m");
  const match = pattern.exec(source);
  if (!match) return null;
  return { num: BigInt(match[1]), den: BigInt(match[2]) };
}

// Frontier seed (audit F1): seedScoreAtoms initializes the on-chain
// bestScoreAtoms and MUST encode the TRUE best-known absolute score for the
// problem — never a trivial bound, or resubmitting a known construction mints
// a false prize. Sources, in precedence order:
//   1. P42_SEED_SCORE_ATOMS   — int256 atoms, used verbatim
//   2. P42_SEED_SCORE         — exact rational MINIMIZATION score, ceil'd to atoms
//   3. P42_PROBLEM_DIR        — read from the problem package itself:
//        a. problem.yaml `seed_score:` (native objective direction)
//        b. verifier/verify.py literal `SEED_BEST = Fraction(num, den)`
//        c. problem.yaml `objective.seed_best:` — may be stale, so this
//           fallback is a HARD ERROR unless P42_ALLOW_YAML_SEED=1 (audit F1)
//      For (3), problem.yaml `objective.direction: maximize` maps the seed onto
//      the minimization frontier by negation.
function resolveSeedScoreAtoms() {
  const direct = process.env.P42_SEED_SCORE_ATOMS;
  if (direct !== undefined && direct.trim() !== "") return BigInt(direct.trim());
  const rational = process.env.P42_SEED_SCORE;
  if (rational !== undefined && rational.trim() !== "") {
    return ceilAtoms(parseRational(rational, "P42_SEED_SCORE"));
  }
  const problemDir = process.env.P42_PROBLEM_DIR;
  if (problemDir === undefined || problemDir.trim() === "") {
    throw new Error(
      "Missing frontier seed: set P42_SEED_SCORE_ATOMS, P42_SEED_SCORE, or P42_PROBLEM_DIR (problem package to read the seed from)"
    );
  }
  const dir = resolve(problemDir.trim());
  const yaml = readFileSync(resolve(dir, "problem.yaml"), "utf8");
  const direction = /^\s*direction:\s*(minimize|maximize)\s*$/m.exec(yaml)?.[1] ?? "minimize";
  let seed =
    /^\s*seed_score:\s*"?(-?\d+(?:\/\d+)?)"?\s*$/m.exec(yaml)?.[1] ?? null;
  if (seed === null) {
    // The verifier source is the seed's source of truth; problem.yaml
    // seed_best is only a fallback (it can go stale relative to verify.py).
    try {
      const verifier = readFileSync(resolve(dir, "verifier", "verify.py"), "utf8");
      const literal = fractionLiteral(verifier, "SEED_BEST");
      if (literal) seed = `${literal.num}/${literal.den}`;
    } catch {
      // fall through to problem.yaml seed_best (explicitly gated below)
    }
  }
  if (seed === null) {
    // AUDIT F1 hardening: a stale problem.yaml seed_best must never deploy
    // silently — a renamed/refactored SEED_BEST would otherwise re-open the
    // false-prize hole by seeding the old loose frontier. Require an explicit
    // operator acknowledgement to use the yaml value.
    const yamlSeed = /^\s*seed_best:\s*"?(-?\d+(?:\/\d+)?)"?\s*$/m.exec(yaml)?.[1] ?? null;
    if (yamlSeed !== null && process.env.P42_ALLOW_YAML_SEED !== "1") {
      throw new Error(
        `refusing problem.yaml seed_best fallback in ${dir}: verify.py SEED_BEST literal was not found ` +
          "(renamed/refactored/missing?) and yaml seed_best may be stale (audit F1). Fix the verifier, set " +
          "P42_SEED_SCORE / P42_SEED_SCORE_ATOMS explicitly, or set P42_ALLOW_YAML_SEED=1 to accept the yaml value."
      );
    }
    if (yamlSeed !== null) {
      console.warn(`WARNING: seeding from problem.yaml seed_best in ${dir} (P42_ALLOW_YAML_SEED=1); verify it matches verify.py`);
      seed = yamlSeed;
    }
  }
  if (seed === null) {
    throw new Error(`could not resolve a frontier seed from ${dir} (no seed_score, verify.py SEED_BEST literal, or seed_best)`);
  }
  const parsed = parseRational(seed, `${dir} seed`);
  if (direction === "maximize") parsed.num = -parsed.num;
  return ceilAtoms(parsed);
}

// On-chain marginal floor (deploy hardening): minImprovementAtoms must mirror
// the verifier's MIN_IMPROVEMENT policy floor for the problem, never a flat
// default (a floor looser than the verifier's would let on-chain credit
// finalize improvements the verifier itself rejects). Sources, in precedence
// order:
//   1. P42_MIN_IMPROVEMENT_ATOMS — uint atoms, used verbatim
//   2. P42_PROBLEM_DIR verifier/verify.py `MIN_IMPROVEMENT = Fraction(num, den)`
//      literal, ceil'd to atoms (CEIL: the on-chain floor is never looser than
//      the verifier's policy floor)
// A non-literal MIN_IMPROVEMENT (e.g. Fraction(1, TOTAL_PAIRS)) is a hard
// error: compute the atoms and pass them explicitly.
function resolveMinImprovementAtoms() {
  const direct = process.env.P42_MIN_IMPROVEMENT_ATOMS;
  if (direct !== undefined && direct.trim() !== "") {
    const parsed = BigInt(direct.trim());
    if (parsed < 0n) throw new Error("P42_MIN_IMPROVEMENT_ATOMS must be non-negative");
    return parsed;
  }
  const problemDir = process.env.P42_PROBLEM_DIR;
  if (problemDir === undefined || problemDir.trim() === "") {
    throw new Error(
      "Missing marginal floor: set P42_MIN_IMPROVEMENT_ATOMS, or P42_PROBLEM_DIR (verifier to read MIN_IMPROVEMENT from)"
    );
  }
  const dir = resolve(problemDir.trim());
  const verifier = readFileSync(resolve(dir, "verifier", "verify.py"), "utf8");
  const literal = fractionLiteral(verifier, "MIN_IMPROVEMENT");
  if (literal === null) {
    throw new Error(
      `could not resolve a MIN_IMPROVEMENT Fraction literal from ${dir}/verifier/verify.py ` +
        "(renamed, refactored, or not a plain literal?); set P42_MIN_IMPROVEMENT_ATOMS explicitly"
    );
  }
  const atoms = ceilAtoms(literal);
  if (atoms <= 0n) {
    throw new Error(`MIN_IMPROVEMENT from ${dir} must be a positive floor, got ${atoms} atoms`);
  }
  return atoms;
}

function manifestPath() {
  return process.env.P42_DEPLOYMENT_MANIFEST
    ? resolve(process.env.P42_DEPLOYMENT_MANIFEST)
    : resolve(process.cwd(), "../deployments/base-sepolia/p42-prizes.json");
}

function gitCommit(repoRoot) {
  try {
    return execFileSync("git", ["rev-parse", "HEAD"], {
      cwd: repoRoot,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"]
    }).trim();
  } catch {
    return "unknown";
  }
}

function assertAddress(ethers, label, value) {
  if (!ethers.isAddress(value)) throw new Error(`${label} must be an EVM address`);
  return ethers.getAddress(value);
}

function assertBytes32(ethers, label, value) {
  if (!ethers.isHexString(value, 32)) throw new Error(`${label} must be bytes32 hex`);
  return value;
}

function stringifyJson(value) {
  return JSON.stringify(
    value,
    (_key, item) => (typeof item === "bigint" ? item.toString() : item),
    2
  );
}

async function waitForDeployment(contract) {
  await contract.waitForDeployment();
  const tx = contract.deploymentTransaction();
  const receipt = tx === null ? null : await tx.wait();
  return {
    address: await contract.getAddress(),
    txHash: tx?.hash ?? null,
    blockNumber: receipt?.blockNumber ?? null
  };
}

async function sendSetupTx(label, txPromise) {
  const tx = await txPromise;
  const receipt = await tx.wait();
  return {
    label,
    txHash: tx.hash,
    blockNumber: receipt.blockNumber
  };
}

async function deployContract(ethers, name, args) {
  const factory = await ethers.getContractFactory(name);
  const contract = await factory.deploy(...args);
  const deployment = await waitForDeployment(contract);
  // ABI/code pins (audit F10): reconciliation decodes events with an ABI, and
  // a later HEAD refactor can silently change event shapes so queryFilter
  // matches nothing while still reporting ok. Record (a) the hash of the code
  // actually deployed on-chain and (b) the hash of the exact ABI used here, so
  // reconcile can assert it is decoding the deployed contracts with the
  // deployed ABI.
  const deployedCodeHash = ethers.keccak256(await ethers.provider.getCode(deployment.address));
  const abiHash = ethers.keccak256(ethers.toUtf8Bytes(factory.interface.formatJson()));
  return {
    contract,
    manifest: {
      name,
      ...deployment,
      deployedCodeHash,
      abiHash,
      constructorArgs: args
    }
  };
}

for (const name of REQUIRED_ENV) requiredEnv(name);

const connection = await network.create("baseSepolia");

try {
  const { ethers } = connection;
  const [deployer] = await ethers.getSigners();
  if (deployer === undefined) throw new Error("No deployer signer available");

  const chain = await ethers.provider.getNetwork();
  if (chain.chainId !== BASE_SEPOLIA_CHAIN_ID) {
    throw new Error(`Expected Base Sepolia chainId 84532, got ${chain.chainId}`);
  }

  const owner = process.env.P42_OWNER_ADDRESS
    ? assertAddress(ethers, "P42_OWNER_ADDRESS", process.env.P42_OWNER_ADDRESS)
    : deployer.address;
  if (owner !== deployer.address) {
    throw new Error("P42_OWNER_ADDRESS must equal the deployer for this immutable-owner scaffold");
  }

  const treasury = assertAddress(ethers, "P42_TREASURY_ADDRESS", requiredEnv("P42_TREASURY_ADDRESS"));
  const resolver = assertAddress(ethers, "P42_RESOLVER_ADDRESS", requiredEnv("P42_RESOLVER_ADDRESS"));
  const params = {
    alphaBps: bpsEnv("P42_ALPHA_BPS", DEFAULTS.alphaBps),
    betaBps: bpsEnv("P42_BETA_BPS", DEFAULTS.betaBps),
    challengeWindowSeconds: uintEnv("P42_CHALLENGE_WINDOW_SECONDS", DEFAULTS.challengeWindowSeconds),
    feeBps: bpsEnv("P42_FEE_BPS", DEFAULTS.feeBps),
    minCounterBondWei: uintEnv("P42_MIN_COUNTER_BOND_WEI", DEFAULTS.minCounterBondWei),
    minPostingBondWei: uintEnv("P42_MIN_POSTING_BOND_WEI", DEFAULTS.minPostingBondWei),
    rerunCostMultiplierBps: bpsEnv("P42_RERUN_COST_MULTIPLIER_BPS", DEFAULTS.rerunCostMultiplierBps),
    rerunCostWei: uintEnv("P42_RERUN_COST_WEI", DEFAULTS.rerunCostWei),
    resolverDecisionBondWei: uintEnv("P42_RESOLVER_DECISION_BOND_WEI", DEFAULTS.resolverDecisionBondWei),
    resolverFraudWindowSeconds: uintEnv(
      "P42_RESOLVER_FRAUD_WINDOW_SECONDS",
      DEFAULTS.resolverFraudWindowSeconds
    )
  };
  const problem = {
    specHash: assertBytes32(ethers, "P42_PROBLEM_SPEC_HASH", requiredEnv("P42_PROBLEM_SPEC_HASH")),
    verifierSourceHash: assertBytes32(
      ethers,
      "P42_VERIFIER_SOURCE_HASH",
      requiredEnv("P42_VERIFIER_SOURCE_HASH")
    ),
    verifierImageHash: assertBytes32(
      ethers,
      "P42_VERIFIER_IMAGE_HASH",
      requiredEnv("P42_VERIFIER_IMAGE_HASH")
    ),
    admissionMatrixHash: assertBytes32(
      ethers,
      "P42_ADMISSION_MATRIX_HASH",
      requiredEnv("P42_ADMISSION_MATRIX_HASH")
    ),
    metadataURI: requiredEnv("P42_METADATA_URI"),
    minImprovementAtoms: resolveMinImprovementAtoms(),
    seedScoreAtoms: resolveSeedScoreAtoms()
  };

  const setupTransactions = [];
  const pool = await deployContract(ethers, "P42BountyPool", [owner]);
  const ledger = await deployContract(ethers, "P42PayoutLedger", [
    pool.manifest.address,
    owner,
    treasury,
    params.feeBps
  ]);
  setupTransactions.push(
    await sendSetupTx("pool.setLedger", pool.contract.setLedger(ledger.manifest.address))
  );

  const submissions = await deployContract(ethers, "P42SubmissionManager", [
    pool.manifest.address,
    ledger.manifest.address,
    owner,
    treasury,
    params.alphaBps,
    params.minPostingBondWei,
    params.challengeWindowSeconds,
    // On-chain DA: solution bytes ride the reveal tx and are bound to the
    // commit anchor. Default on with a 512 KiB cap; large-certificate problems
    // (autoconvolution) deploy with onchainDa=false + off-chain store.
    params.onchainDa ?? true,
    params.maxSolutionBytes ?? 512 * 1024,
    // Frontier seed (audit F1): bestScoreAtoms starts at the TRUE best-known
    // score; credit is the marginal reduction below it.
    problem.seedScoreAtoms,
    problem.minImprovementAtoms
  ]);
  setupTransactions.push(
    await sendSetupTx("ledger.setCreditRecorder", ledger.contract.setCreditRecorder(submissions.manifest.address))
  );

  const challenges = await deployContract(ethers, "P42ChallengeManager", [
    owner,
    resolver,
    treasury,
    submissions.manifest.address,
    params.challengeWindowSeconds,
    params.betaBps,
    params.minCounterBondWei,
    params.rerunCostWei,
    params.rerunCostMultiplierBps,
    params.resolverDecisionBondWei,
    params.resolverFraudWindowSeconds
  ]);
  setupTransactions.push(
    await sendSetupTx(
      "submissions.setChallengeManager",
      submissions.contract.setChallengeManager(challenges.manifest.address)
    )
  );

  const registry = await deployContract(ethers, "P42ProblemRegistry", [owner]);
  const registerTx = await registry.contract.register({
    specHash: problem.specHash,
    verifierSourceHash: problem.verifierSourceHash,
    verifierImageHash: problem.verifierImageHash,
    admissionMatrixHash: problem.admissionMatrixHash,
    metadataURI: problem.metadataURI,
    pool: pool.manifest.address,
    ledger: ledger.manifest.address,
    submissionManager: submissions.manifest.address,
    challengeManager: challenges.manifest.address,
    challengeWindowSeconds: params.challengeWindowSeconds,
    minImprovementAtoms: problem.minImprovementAtoms
  });
  const registerReceipt = await registerTx.wait();

  const repoRoot = resolve(process.cwd(), "..");
  const manifest = {
    schema: "p42-prizes/deployment-manifest/v1",
    status: "base-sepolia-testnet",
    deployedAt: new Date().toISOString(),
    deploymentCommit: gitCommit(repoRoot),
    network: {
      name: "baseSepolia",
      chainId: Number(chain.chainId),
      explorerBaseUrl: "https://sepolia.basescan.org"
    },
    roles: {
      deployer: deployer.address,
      owner,
      treasury,
      resolver
    },
    parameters: params,
    contracts: {
      pool: pool.manifest,
      ledger: ledger.manifest,
      submissions: submissions.manifest,
      challenges: challenges.manifest,
      registry: registry.manifest
    },
    setupTransactions,
    problems: [
      {
        problemId: "1",
        metadataURI: problem.metadataURI,
        specHash: problem.specHash,
        verifierSourceHash: problem.verifierSourceHash,
        verifierImageHash: problem.verifierImageHash,
        admissionMatrixHash: problem.admissionMatrixHash,
        minImprovementAtoms: problem.minImprovementAtoms,
        // Frontier seed this SubmissionManager was constructed with (audit F1):
        // score atoms at the shared ceil(score * 1e18) convention.
        seedScoreAtoms: problem.seedScoreAtoms.toString(),
        scoreAtomScale: SCORE_SCALE.toString(),
        registerTxHash: registerTx.hash,
        registerBlockNumber: registerReceipt.blockNumber,
        pool: pool.manifest.address,
        ledger: ledger.manifest.address,
        submissionManager: submissions.manifest.address,
        challengeManager: challenges.manifest.address
      }
    ],
    sourceVerification: {
      status: "pending",
      requiredExplorer: "https://sepolia.basescan.org"
    }
  };

  const firstBlock = [
    ...Object.values(manifest.contracts).map((entry) => entry.blockNumber),
    ...manifest.setupTransactions.map((entry) => entry.blockNumber),
    registerReceipt.blockNumber
  ].filter((block) => block !== null);
  manifest.indexer = {
    startBlock: Math.min(...firstBlock),
    indexedThroughBlock: null,
    reconciliationReport: null
  };

  const output = manifestPath();
  await mkdir(dirname(output), { recursive: true });
  await writeFile(output, `${stringifyJson(manifest)}\n`);
  console.log(`Wrote deployment manifest: ${output}`);
  console.log(`Registry: ${registry.manifest.address}`);
  console.log(`Problem 1 pool: ${pool.manifest.address}`);
} finally {
  await connection.close();
}
