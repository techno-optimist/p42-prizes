import { readFile, mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

import { network } from "hardhat";

const BASE_SEPOLIA_CHAIN_ID = 84532n;

function requiredEnv(name) {
  const value = process.env[name];
  if (value === undefined || value.trim() === "") {
    throw new Error(`Missing required env var: ${name}`);
  }
  return value.trim();
}

function manifestPath() {
  return process.env.P42_DEPLOYMENT_MANIFEST
    ? resolve(process.env.P42_DEPLOYMENT_MANIFEST)
    : resolve(process.cwd(), "../deployments/base-sepolia/p42-prizes.json");
}

function reportPath() {
  return process.env.P42_RECONCILIATION_REPORT
    ? resolve(process.env.P42_RECONCILIATION_REPORT)
    : resolve(process.cwd(), "../deployments/base-sepolia/reconciliation/latest.json");
}

function stringifyJson(value) {
  return JSON.stringify(
    value,
    (_key, item) => (typeof item === "bigint" ? item.toString() : item),
    2
  );
}

function sumArgs(events, argName) {
  return events.reduce((total, event) => total + BigInt(event.args[argName]), 0n);
}

function unique(values) {
  return [...new Set(values.map((value) => value.toString()))];
}

function check(name, expected, actual) {
  const ok = expected === actual;
  return {
    name,
    ok,
    expected,
    actual
  };
}

async function loadManifest() {
  const path = manifestPath();
  try {
    return {
      path,
      data: JSON.parse(await readFile(path, "utf8"))
    };
  } catch (error) {
    throw new Error(`Unable to read deployment manifest at ${path}: ${error.message}`);
  }
}

function requireContract(manifest, key) {
  const entry = manifest.contracts?.[key];
  if (entry?.address === undefined) throw new Error(`Manifest missing contracts.${key}.address`);
  return entry.address;
}

requiredEnv("BASE_SEPOLIA_RPC_URL");

const manifest = await loadManifest();
const connection = await network.create("baseSepolia");

try {
  const { ethers } = connection;
  const chain = await ethers.provider.getNetwork();
  if (chain.chainId !== BASE_SEPOLIA_CHAIN_ID) {
    throw new Error(`Expected Base Sepolia chainId 84532, got ${chain.chainId}`);
  }

  const fromBlock = BigInt(manifest.data.indexer?.startBlock ?? 0);
  const latestBlock = BigInt(await ethers.provider.getBlockNumber());
  if (latestBlock < fromBlock) {
    throw new Error(`Latest block ${latestBlock} is before manifest start block ${fromBlock}`);
  }

  const pool = await ethers.getContractAt("P42BountyPool", requireContract(manifest.data, "pool"));
  const ledger = await ethers.getContractAt("P42PayoutLedger", requireContract(manifest.data, "ledger"));
  const submissions = await ethers.getContractAt(
    "P42SubmissionManager",
    requireContract(manifest.data, "submissions")
  );
  const challenges = await ethers.getContractAt(
    "P42ChallengeManager",
    requireContract(manifest.data, "challenges")
  );
  const registry = await ethers.getContractAt("P42ProblemRegistry", requireContract(manifest.data, "registry"));

  const [
    fundedEvents,
    claimedEvents,
    creditEvents,
    commitEvents,
    revealEvents,
    finalizedEvents,
    submissionChallengedEvents,
    submissionResolvedEvents,
    challengeEvents,
    resolverTranscriptEvents,
    challengeResolvedEvents,
    poolBalance,
    poolTotalFunded,
    poolTotalClaimed,
    ledgerTotalCreditAtoms,
    ledgerClosed,
    ledgerClosedPoolBalance,
    ledgerFeeReserve,
    submissionCount,
    registryProblemCount
  ] = await Promise.all([
    pool.queryFilter(pool.filters.Funded(), Number(fromBlock), Number(latestBlock)),
    pool.queryFilter(pool.filters.Claimed(), Number(fromBlock), Number(latestBlock)),
    ledger.queryFilter(ledger.filters.CreditRecorded(), Number(fromBlock), Number(latestBlock)),
    submissions.queryFilter(submissions.filters.Committed(), Number(fromBlock), Number(latestBlock)),
    submissions.queryFilter(submissions.filters.Revealed(), Number(fromBlock), Number(latestBlock)),
    submissions.queryFilter(submissions.filters.Finalized(), Number(fromBlock), Number(latestBlock)),
    submissions.queryFilter(submissions.filters.SubmissionChallenged(), Number(fromBlock), Number(latestBlock)),
    submissions.queryFilter(
      submissions.filters.SubmissionChallengeResolved(),
      Number(fromBlock),
      Number(latestBlock)
    ),
    challenges.queryFilter(challenges.filters.Challenged(), Number(fromBlock), Number(latestBlock)),
    challenges.queryFilter(challenges.filters.ResolverTranscriptPosted(), Number(fromBlock), Number(latestBlock)),
    challenges.queryFilter(challenges.filters.Resolved(), Number(fromBlock), Number(latestBlock)),
    ethers.provider.getBalance(await pool.getAddress()),
    pool.totalFunded(),
    pool.totalClaimed(),
    ledger.totalCreditAtoms(),
    ledger.closed(),
    ledger.closedPoolBalance(),
    ledger.feeReserve(),
    submissions.submissionCount(),
    registry.problemCount()
  ]);

  const submissionIds = Array.from(
    { length: Number(submissionCount) },
    (_item, index) => BigInt(index + 1)
  );
  const submissionStates = [];
  for (const submissionId of submissionIds) {
    const submission = await submissions.submissions(submissionId);
    submissionStates.push({
      submissionId,
      solver: submission.solver,
      status: submission.status,
      bondWei: submission.bondWei,
      poolAtSubmissionWei: submission.poolAtSubmissionWei,
      requiredBondWei: submission.requiredBondWei,
      improvementAtoms: submission.improvementAtoms,
      challengeEndsAt: submission.challengeEndsAt,
      permanenceHash: submission.permanenceHash
    });
  }

  const challengedSubmissionIds = unique(challengeEvents.map((event) => event.args.submissionId));
  const challengeStates = [];
  for (const submissionId of challengedSubmissionIds) {
    // The resolver decision bond lives in the separate `resolverBonds` mapping,
    // not on the Challenge struct; read both so the report reflects real bonds.
    const [challenge, resolverBond] = await Promise.all([
      challenges.challenges(submissionId),
      challenges.resolverBonds(submissionId)
    ]);
    challengeStates.push({
      submissionId,
      challenger: challenge.challenger,
      challengeBondWei: challenge.challengeBondWei,
      disputeEndsAt: challenge.disputeEndsAt,
      resolved: challenge.resolved,
      challengerWins: challenge.challengerWins,
      transcriptHash: challenge.transcriptHash,
      transcriptURI: challenge.transcriptURI,
      verdictHash: challenge.verdictHash,
      resolverBondWei: resolverBond.amountWei,
      resolverBondReleaseAt: resolverBond.releaseAt,
      resolverBondSlashProofHash: resolverBond.slashProofHash
    });
  }

  const eventSums = {
    fundedWei: sumArgs(fundedEvents, "amount"),
    claimedWei: sumArgs(claimedEvents, "amount"),
    creditAtoms: sumArgs(creditEvents, "atoms"),
    finalizedImprovementAtoms: sumArgs(finalizedEvents, "improvementAtoms")
  };
  const checks = [
    check("pool.totalFunded == Funded events", eventSums.fundedWei, poolTotalFunded),
    check("pool.totalClaimed == Claimed events", eventSums.claimedWei, poolTotalClaimed),
    check("ledger.totalCreditAtoms == CreditRecorded events", eventSums.creditAtoms, ledgerTotalCreditAtoms),
    check("submissions.submissionCount == Committed events", BigInt(commitEvents.length), submissionCount),
    check(
      "challenge manager Challenged events == submission challenged hooks",
      BigInt(challengeEvents.length),
      BigInt(submissionChallengedEvents.length)
    ),
    check(
      "challenge manager Resolved events == submission resolved hooks",
      BigInt(challengeResolvedEvents.length),
      BigInt(submissionResolvedEvents.length)
    ),
    check(
      "registry.problemCount >= manifest problems",
      true,
      registryProblemCount >= BigInt(manifest.data.problems?.length ?? 0)
    )
  ];

  const report = {
    schema: "p42-prizes/reconciliation-report/v1",
    generatedAt: new Date().toISOString(),
    ok: checks.every((entry) => entry.ok),
    manifestPath: manifest.path,
    deploymentCommit: manifest.data.deploymentCommit ?? null,
    network: {
      name: "baseSepolia",
      chainId: Number(chain.chainId),
      fromBlock,
      toBlock: latestBlock
    },
    contracts: {
      pool: await pool.getAddress(),
      ledger: await ledger.getAddress(),
      submissions: await submissions.getAddress(),
      challenges: await challenges.getAddress(),
      registry: await registry.getAddress()
    },
    eventCounts: {
      funded: fundedEvents.length,
      claimed: claimedEvents.length,
      creditRecorded: creditEvents.length,
      committed: commitEvents.length,
      revealed: revealEvents.length,
      finalized: finalizedEvents.length,
      submissionChallenged: submissionChallengedEvents.length,
      submissionResolved: submissionResolvedEvents.length,
      challenged: challengeEvents.length,
      resolverTranscriptPosted: resolverTranscriptEvents.length,
      challengeResolved: challengeResolvedEvents.length
    },
    eventSums,
    onchain: {
      poolBalance,
      poolTotalFunded,
      poolTotalClaimed,
      ledgerTotalCreditAtoms,
      ledgerClosed,
      ledgerClosedPoolBalance,
      ledgerFeeReserve,
      submissionCount,
      registryProblemCount
    },
    submissionStates,
    challengeStates,
    checks
  };

  const output = reportPath();
  await mkdir(dirname(output), { recursive: true });
  await writeFile(output, `${stringifyJson(report)}\n`);
  console.log(`Wrote reconciliation report: ${output}`);
  console.log(`ok=${report.ok} fromBlock=${fromBlock} toBlock=${latestBlock}`);
  if (!report.ok) {
    process.exitCode = 1;
  }
} finally {
  await connection.close();
}
