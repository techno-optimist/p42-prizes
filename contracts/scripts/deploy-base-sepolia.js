import { execFileSync } from "node:child_process";
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
  minImprovementAtoms: 1n,
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
  return {
    contract,
    manifest: {
      name,
      ...deployment,
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
    minImprovementAtoms: uintEnv("P42_MIN_IMPROVEMENT_ATOMS", DEFAULTS.minImprovementAtoms)
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
    params.maxSolutionBytes ?? 512 * 1024
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
