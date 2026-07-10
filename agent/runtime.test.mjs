import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { ethers } from "ethers";

import {
  assertRegistryBindingStable,
  buildRegistryBinding,
  buildChallengeCallPolicy,
  classifyReceiptFinality,
  exactCallRequestFromPolicy,
  buildOperatorCursor,
  buildSignedTransactionRecord,
  canonicalJson,
  nextOperatorScanRange,
  operatorCursorBinding,
  localProblemRuntimeIdentity,
  recoverRevealCalldata,
  runtimePythonExecutable,
  resolveOperatorFinality,
  sha256Canonical,
  solverLifecycleDecision,
  submissionIdFromCommittedReceipt,
  validateRegistryBinding,
  validateOperatorCursor,
  validateOperatorExecutionMode,
  verifierImageHashForDigest,
  verifierSourceHashForDigest,
} from "./lib.mjs";


const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..");

const submissionInterface = new ethers.Interface([
  "function reveal(uint256 submissionId,string solutionCid,int256 claimedScoreAtoms,uint256 improvementAtoms,string salt,bytes solution)",
  "event Committed(uint256 indexed submissionId,address indexed solver,bytes32 indexed commitment,bytes32 commitDaHash,uint256 bondWei,uint256 poolAtSubmissionWei,uint256 requiredBondWei,bool paidAtCommit,uint64 committedBlock)",
]);
const walletInterface = new ethers.Interface([
  "function execute(address target,uint256 value,bytes data) returns (bytes)",
]);
const entryPointLike = new ethers.Interface([
  "function handle(bytes accountCallData,address beneficiary)",
]);

const solution = ethers.toUtf8Bytes('{"answer":42}');
const reveal = submissionInterface.encodeFunctionData("reveal", [
  17n,
  `sha256:${ethers.sha256(solution).slice(2)}`,
  -123n,
  9n,
  "salt",
  solution,
]);
const expected = {
  submissionId: 17n,
  solutionCid: `sha256:${ethers.sha256(solution).slice(2)}`,
  claimedScoreAtoms: -123n,
  improvementAtoms: 9n,
  solutionBytesLength: solution.length,
};
const anchoredExpected = { ...expected, commitDaHash: ethers.sha256(solution) };

const RUNTIME_BINDING_ADDRESSES = {
  registry: "0x1111111111111111111111111111111111111111",
  pool: "0x2222222222222222222222222222222222222222",
  ledger: "0x3333333333333333333333333333333333333333",
  submissions: "0x4444444444444444444444444444444444444444",
  challenges: "0x5555555555555555555555555555555555555555",
};
const RUNTIME_IMAGE = `sha256:${"a".repeat(64)}`;
const RUNTIME_SOURCE = `sha256:${"b".repeat(64)}`;

test("runtime bridge interpreter selection requires an absolute configured path", () => {
  assert.equal(runtimePythonExecutable({}), "python3");
  assert.equal(runtimePythonExecutable({ P42_RUNTIME_PYTHON: "/opt/p42/bin/python3" }), "/opt/p42/bin/python3");
  assert.throws(
    () => runtimePythonExecutable({ P42_RUNTIME_PYTHON: "python3" }),
    /must be an absolute interpreter path/,
  );
  assert.throws(
    () => runtimePythonExecutable({ P42_RUNTIME_PYTHON: " /opt/p42/bin/python3" }),
    /must be an absolute interpreter path/,
  );
});

function runtimeBindingFixture(overrides = {}) {
  return {
    schema_version: "p42-registry-binding/v1",
    image_hash_algorithm: "keccak256-utf8/v1",
    source_digest_algorithm: "p42-source-tree-sha256/v1",
    source_hash_algorithm: "keccak256-utf8/v1",
    chain_id: 84532,
    registry_address: RUNTIME_BINDING_ADDRESSES.registry,
    problem_id: "1",
    problem_slug: "hadamard-mini",
    verifier_version: "0.1.1",
    observation_block_number: 100,
    observation_block_hash: `0x${"1".repeat(64)}`,
    verifier_image: RUNTIME_IMAGE,
    verifier_image_hash: verifierImageHashForDigest(RUNTIME_IMAGE),
    verifier_source_digest: RUNTIME_SOURCE,
    verifier_source_hash: verifierSourceHashForDigest(RUNTIME_SOURCE),
    spec_hash: `0x${"2".repeat(64)}`,
    admission_hash: `0x${"3".repeat(64)}`,
    metadata_uri: "ipfs://runtime-fixture",
    pool: RUNTIME_BINDING_ADDRESSES.pool,
    ledger: RUNTIME_BINDING_ADDRESSES.ledger,
    submission_manager: RUNTIME_BINDING_ADDRESSES.submissions,
    challenge_manager: RUNTIME_BINDING_ADDRESSES.challenges,
    challenge_window_seconds: "259200",
    min_improvement_atoms: "1",
    frozen: true,
    explicitly_frozen: true,
    ...overrides,
  };
}

test("registry bindings bind explicit source/image preimages and remain stable across observations", () => {
  const first = validateRegistryBinding(runtimeBindingFixture(), {
    chain_id: 84532,
    registry_address: RUNTIME_BINDING_ADDRESSES.registry,
    problem_id: "1",
    problem_slug: "hadamard-mini",
  });
  const later = validateRegistryBinding(runtimeBindingFixture({
    observation_block_number: 101,
    observation_block_hash: `0x${"4".repeat(64)}`,
  }));
  assert.doesNotThrow(() => assertRegistryBindingStable(first, later));

  const changed = runtimeBindingFixture({
    verifier_source_digest: `sha256:${"c".repeat(64)}`,
    verifier_source_hash: verifierSourceHashForDigest(`sha256:${"c".repeat(64)}`),
  });
  assert.throws(() => assertRegistryBindingStable(first, changed), /changed after transcript creation/);

  const localDev = runtimeBindingFixture({ verifier_image: "sha256:local-dev" });
  assert.throws(() => validateRegistryBinding(localDev), /canonical bare sha256/);

  assert.throws(
    () => validateRegistryBinding(runtimeBindingFixture({ chain_id: 0 })),
    /registry binding chain_id must be a positive safe integer/,
  );

  assert.throws(
    () => validateRegistryBinding(
      runtimeBindingFixture({ verifier_version: "0.1.1-ALPHA" }),
      { verifier_version: "0.1.1-alpha" },
    ),
    /registry binding verifier_version mismatch/,
  );
});

test("registry binding builder rejects the local phase-0 placeholder before any chain action", () => {
  assert.throws(
    () => localProblemRuntimeIdentity(resolve(REPO_ROOT, "problems/hadamard-mini"), REPO_ROOT),
    /problem.yaml verifier.image must be a canonical bare sha256/,
  );
});

test("registry binding builder cross-checks every frozen manifest and registry anchor", () => {
  const localProblem = {
    problem_slug: "hadamard-mini",
    verifier_version: "0.1.1",
    verifier_image: RUNTIME_IMAGE,
    verifier_source_digest: RUNTIME_SOURCE,
  };
  const manifestProblem = {
    problemId: "1",
    registrationStatus: "registered-and-frozen",
    immutablePins: true,
    explicitlyFrozen: true,
    problemSlug: localProblem.problem_slug,
    verifierVersion: localProblem.verifier_version,
    verifierImageDigest: localProblem.verifier_image,
    verifierImageHashAlgorithm: "keccak256-utf8/v1",
    verifierImageHash: verifierImageHashForDigest(localProblem.verifier_image),
    verifierSourceDigest: localProblem.verifier_source_digest,
    verifierSourceDigestAlgorithm: "p42-source-tree-sha256/v1",
    verifierSourceHash: verifierSourceHashForDigest(localProblem.verifier_source_digest),
    verifierSourceHashAlgorithm: "keccak256-utf8/v1",
    specHash: `0x${"2".repeat(64)}`,
    admissionMatrixHash: `0x${"3".repeat(64)}`,
    metadataURI: "ipfs://runtime-fixture",
    pool: RUNTIME_BINDING_ADDRESSES.pool,
    ledger: RUNTIME_BINDING_ADDRESSES.ledger,
    submissionManager: RUNTIME_BINDING_ADDRESSES.submissions,
    challengeManager: RUNTIME_BINDING_ADDRESSES.challenges,
    minImprovementAtoms: "1",
  };
  const built = buildRegistryBinding({
    manifest: {
      network: { chainId: 84532 },
      parameters: { challengeWindowSeconds: "259200" },
      problems: [manifestProblem],
    },
    localProblem,
    registryAddress: RUNTIME_BINDING_ADDRESSES.registry,
    registryProblemId: "1",
    chainId: 84532,
    observationBlockNumber: 100,
    observationBlockHash: `0x${"1".repeat(64)}`,
    registryProblem: {
      specHash: manifestProblem.specHash,
      verifierSourceHash: manifestProblem.verifierSourceHash,
      verifierImageHash: manifestProblem.verifierImageHash,
      admissionMatrixHash: manifestProblem.admissionMatrixHash,
      metadataURI: manifestProblem.metadataURI,
      pool: manifestProblem.pool,
      ledger: manifestProblem.ledger,
      submissionManager: manifestProblem.submissionManager,
      challengeManager: manifestProblem.challengeManager,
      challengeWindowSeconds: 259200n,
      minImprovementAtoms: 1n,
    },
    registryIsFrozen: true,
    registryExplicitlyFrozen: true,
  });
  assert.equal(built.verifier_image, RUNTIME_IMAGE);
  assert.equal(built.verifier_source_digest, RUNTIME_SOURCE);
  assert.throws(
    () => buildRegistryBinding({
      manifest: { network: { chainId: 84532 }, parameters: { challengeWindowSeconds: "259200" }, problems: [manifestProblem] },
      localProblem: { ...localProblem, verifier_source_digest: `sha256:${"c".repeat(64)}` },
      registryAddress: RUNTIME_BINDING_ADDRESSES.registry,
      registryProblemId: "1",
      chainId: 84532,
      observationBlockNumber: 100,
      observationBlockHash: `0x${"1".repeat(64)}`,
      registryProblem: {
        specHash: manifestProblem.specHash,
        verifierSourceHash: manifestProblem.verifierSourceHash,
        verifierImageHash: manifestProblem.verifierImageHash,
        admissionMatrixHash: manifestProblem.admissionMatrixHash,
        metadataURI: manifestProblem.metadataURI,
        pool: manifestProblem.pool,
        ledger: manifestProblem.ledger,
        submissionManager: manifestProblem.submissionManager,
        challengeManager: manifestProblem.challengeManager,
        challengeWindowSeconds: 259200n,
        minImprovementAtoms: 1n,
      },
      registryIsFrozen: true,
      registryExplicitlyFrozen: true,
    }),
    /local verifier source digest mismatch/,
  );
});


test("recoverRevealCalldata decodes a direct reveal", () => {
  const recovered = recoverRevealCalldata(reveal, submissionInterface, expected);
  assert.equal(recovered.nested, false);
  assert.equal(recovered.calldataOffsetBytes, 0);
  assert.equal(recovered.solution, ethers.hexlify(solution));
});


test("recoverRevealCalldata finds reveal inside smart-wallet and ERC-4337-style wrappers", () => {
  const walletCall = walletInterface.encodeFunctionData("execute", [
    "0x1111111111111111111111111111111111111111",
    0n,
    reveal,
  ]);
  const topLevel = entryPointLike.encodeFunctionData("handle", [
    walletCall,
    "0x2222222222222222222222222222222222222222",
  ]);

  const recovered = recoverRevealCalldata(topLevel, submissionInterface, anchoredExpected);

  assert.equal(recovered.nested, true);
  assert.ok(recovered.calldataOffsetBytes > 0);
  assert.equal(recovered.callData, reveal.toLowerCase());
});




test("recoverRevealCalldata rejects decoy and ambiguous reveal candidates", () => {
  const badSolution = ethers.toUtf8Bytes('{"answer":43}');
  const decoy = submissionInterface.encodeFunctionData("reveal", [
    17n,
    expected.solutionCid,
    -123n,
    9n,
    "salt",
    badSolution,
  ]);

  assert.throws(
    () => recoverRevealCalldata(ethers.concat([decoy, reveal]), submissionInterface, anchoredExpected),
    /decoy matched/,
  );
  assert.throws(
    () => recoverRevealCalldata(ethers.concat([reveal, reveal]), submissionInterface, anchoredExpected),
    /ambiguous reveal calldata/,
  );
});


test("recoverRevealCalldata rejects a selector hit that does not match the reveal log", () => {
  assert.throws(
    () => recoverRevealCalldata(reveal, submissionInterface, { ...expected, submissionId: 18n }),
    /no reveal calldata matched/,
  );
});


test("submission id comes from the matching Committed receipt log", () => {
  const solver = "0x3333333333333333333333333333333333333333";
  const submissions = "0x4444444444444444444444444444444444444444";
  const encoded = submissionInterface.encodeEventLog(
    submissionInterface.getEvent("Committed"),
    [23n, solver, ethers.ZeroHash, `0x${"1".repeat(64)}`, 1n, 2n, 3n, true, 99n],
  );
  const receipt = {
    logs: [
      { address: "0x5555555555555555555555555555555555555555", topics: encoded.topics, data: encoded.data },
      { address: submissions, topics: encoded.topics, data: encoded.data },
    ],
  };

  assert.equal(submissionIdFromCommittedReceipt(receipt, submissionInterface, solver, submissions), 23n);
  assert.throws(
    () => submissionIdFromCommittedReceipt(receipt, submissionInterface, ethers.ZeroAddress, submissions),
    /found 0/,
  );
});


test("canonical challenge inputs have stable hashes", () => {
  const value = { z: [3, 2, 1], a: { y: "x", b: true } };
  assert.equal(canonicalJson(value), '{"a":{"b":true,"y":"x"},"z":[3,2,1]}');
  assert.equal(sha256Canonical(value), sha256Canonical({ a: { b: true, y: "x" }, z: [3, 2, 1] }));
});


test("solver lifecycle follows challenge, rearm, top-up, finalize, close, and claims", () => {
  assert.deepEqual(solverLifecycleDecision({ status: 1 }), { action: "reveal" });
  assert.deepEqual(
    solverLifecycleDecision({ status: 2, now: 10n, challengeEndsAt: 20n }),
    { action: "wait_challenge_window", wakeAt: 20n },
  );
  assert.deepEqual(
    solverLifecycleDecision({ status: 3, now: 10n, disputeEndsAt: 20n, challengeResolved: false }),
    { action: "wait_resolution", wakeAt: 20n },
  );
  assert.deepEqual(
    solverLifecycleDecision({ status: 3, now: 20n, disputeEndsAt: 20n, challengeResolved: false }),
    { action: "expire_challenge" },
  );
  assert.deepEqual(
    solverLifecycleDecision({ status: 3, now: 20n, decisionPending: true, resolverBondReleaseAt: 30n }),
    { action: "wait_resolution_finality", wakeAt: 30n },
  );
  assert.deepEqual(
    solverLifecycleDecision({ status: 3, now: 30n, decisionPending: true, resolverBondReleaseAt: 30n }),
    { action: "finalize_resolution" },
  );
  assert.deepEqual(
    solverLifecycleDecision({ status: 2, now: 30n, challengeEndsAt: 30n, bondShortfallWei: 7n }),
    { action: "top_up_bond", valueWei: 7n },
  );
  assert.deepEqual(
    solverLifecycleDecision({ status: 2, now: 30n, challengeEndsAt: 30n, bondShortfallWei: 0n }),
    { action: "finalize" },
  );
  assert.deepEqual(
    solverLifecycleDecision({ status: 4, bondClaimableWei: 5n }),
    { action: "claim_bond", valueWei: 5n },
  );
  assert.deepEqual(
    solverLifecycleDecision({ status: 4, ledgerClosed: false, closeRequested: true, openSubmissionCount: 0n }),
    { action: "close" },
  );
  assert.deepEqual(
    solverLifecycleDecision({ status: 4, ledgerClosed: true, payoutClaimableWei: 11n }),
    { action: "claim_payout", valueWei: 11n },
  );
  assert.deepEqual(
    solverLifecycleDecision({ status: 4, ledgerClosed: true, payoutClaimableWei: 0n }),
    { action: "done" },
  );
});


test("challenge action emits exact chain/expiry/calldata/scope session policy", () => {
  const challengeInterface = new ethers.Interface([
    "function challenge(uint256 submissionId,bytes32 revealInstanceHash,bytes32 reasonHash) payable",
  ]);
  const reasonHash = `0x${"6".repeat(64)}`;
  const revealInstanceHash = `0x${"7".repeat(64)}`;
  const policy = buildChallengeCallPolicy({
    challengeInterface,
    challengeContract: "0x7777777777777777777777777777777777777777",
    chainId: 84532,
    problemId: "hadamard-mini",
    submissionId: 19n,
    revealInstanceHash,
    reasonHash,
    candidateHash: `sha256:${"8".repeat(64)}`,
    sourceEventHash: `sha256:${"9".repeat(64)}`,
    expiresAt: 2000000000n,
    valueWei: 1234n,
  });
  const expectedCalldata = challengeInterface.encodeFunctionData("challenge", [19n, revealInstanceHash, reasonHash]);

  assert.equal(policy.calldata, expectedCalldata);
  assert.equal(policy.calldata_hash, ethers.keccak256(expectedCalldata));
  assert.equal(policy.scope_hash, ethers.id(policy.scope));
  assert.match(policy.scope, /problem:hadamard-mini\|submission:19\|reveal:0x777/);
  assert.equal(policy.chain_id, 84532);
  assert.equal(policy.expires_at, "2000000000");
  assert.equal(policy.max_calls, 1);
  assert.equal(policy.call_value_wei, "1234");
  assert.deepEqual(policy.set_call_policy.arguments.slice(0, 3), [
    "0x7777777777777777777777777777777777777777",
    challengeInterface.getFunction("challenge").selector,
    true,
  ]);
  assert.deepEqual(policy.execute.arguments, [policy.target, "1234", expectedCalldata]);
  assert.deepEqual(exactCallRequestFromPolicy(policy), {
    to: ethers.getAddress(policy.target),
    data: expectedCalldata,
    value: 1234n,
  });
  assert.throws(() => exactCallRequestFromPolicy(policy, 1235n), /bound call value/);
  const unsigned = { ...policy };
  delete unsigned.policy_hash;
  assert.equal(policy.policy_hash, sha256Canonical(unsigned));
});


test("receipt finality classifies canonical, pending, and reorged challenge transactions", () => {
  const canonical = `0x${"a".repeat(64)}`;
  assert.equal(
    classifyReceiptFinality({
      receiptBlockNumber: 100,
      receiptBlockHash: canonical,
      canonicalBlockHash: canonical,
      latestBlockNumber: 101,
      confirmations: 3,
    }),
    "submitted",
  );
  assert.equal(
    classifyReceiptFinality({
      receiptBlockNumber: 100,
      receiptBlockHash: canonical,
      canonicalBlockHash: canonical,
      latestBlockNumber: 102,
      confirmations: 3,
    }),
    "confirmed",
  );
  assert.equal(
    classifyReceiptFinality({
      receiptBlockNumber: 100,
      receiptBlockHash: canonical,
      canonicalBlockHash: `0x${"b".repeat(64)}`,
      latestBlockNumber: 102,
      confirmations: 3,
    }),
    "reorged",
  );
});


test("operator finality, execution mode, and cursor helpers fail closed", () => {
  const manifest = {
    status: "governance-setup-complete",
    deploymentCommit: "a".repeat(40),
    deploymentConfigHash: `0x${"b".repeat(64)}`,
    indexer: { startBlock: 100, finalityPolicy: { confirmations: 64, reorgOverlapBlocks: 8 } },
  };
  assert.deepEqual(
    resolveOperatorFinality({ manifest, confirmations: null, reorgOverlapBlocks: null }),
    { confirmations: 64, reorgOverlapBlocks: 8 },
  );
  assert.throws(
    () => resolveOperatorFinality({ manifest, confirmations: 0, reorgOverlapBlocks: 1 }),
    /production operator requires/,
  );
  assert.deepEqual(
    resolveOperatorFinality({ manifest, confirmations: 0, reorgOverlapBlocks: 1, localTest: true }),
    { confirmations: 0, reorgOverlapBlocks: 1 },
  );
  assert.throws(
    () => validateOperatorExecutionMode({ manifest, chainId: 84532 }),
    /requires --agent-wallet/,
  );
  assert.throws(
    () => validateOperatorExecutionMode({ manifest, chainId: 84532, localTest: true }),
    /only allowed on local chain ids/,
  );
  assert.equal(
    validateOperatorExecutionMode({ manifest, chainId: 31337, localTest: true }).mode,
    "direct-eoa-local-test",
  );

  const binding = operatorCursorBinding({
    manifest,
    chainId: 84532,
    submissionContract: "0x1111111111111111111111111111111111111111",
    challengeContract: "0x2222222222222222222222222222222222222222",
    problemId: "hadamard-mini",
  });
  const cursor = buildOperatorCursor({
    binding,
    nextBlock: 110,
    overlapBlocks: 3,
    anchors: [
      { block_number: 104, block_hash: `0x${"1".repeat(64)}` },
      { block_number: 107, block_hash: `0x${"2".repeat(64)}` },
      { block_number: 109, block_hash: `0x${"3".repeat(64)}` },
    ],
  });
  assert.deepEqual(cursor.anchors.map((anchor) => anchor.block_number), [107, 109]);
  assert.deepEqual(
    nextOperatorScanRange({ cursor, startBlock: 100, safeLatest: 120, overlapBlocks: 3 }),
    { fromBlock: 107, toBlock: 120 },
  );
  assert.equal(nextOperatorScanRange({ cursor, startBlock: 100, safeLatest: 106, overlapBlocks: 3 }), null);
  validateOperatorCursor(cursor, binding);
  assert.throws(
    () => validateOperatorCursor(cursor, { ...binding, problem_id: "other" }),
    /different deployment binding/,
  );
});

test("signed transaction journal records raw bytes before broadcast", async () => {
  const signingWallet = ethers.Wallet.createRandom();
  const request = {
    to: "0x9999999999999999999999999999999999999999",
    value: 123n,
    data: "0x",
    nonce: 0,
    gasLimit: 21000n,
    gasPrice: 1n,
    chainId: 31337,
    type: 0,
  };
  const record = await buildSignedTransactionRecord({ wallet: signingWallet, request, label: "unit" });
  assert.equal(record.schema_version, "p42-signed-transaction/v1");
  assert.equal(record.hash, ethers.keccak256(record.raw_tx));
  assert.equal(record.signer, signingWallet.address.toLowerCase());
  assert.equal(record.nonce, 0);
  assert.equal(record.value, "123");
});


test("runtime bridge quarantines orphaned canonical jobs under the queue lock", () => {
  const dir = mkdtempSync(join(tmpdir(), "p42-bridge-"));
  const queue = join(dir, "queue.json");
  const job = {
    job_id: "84532:submission:block:tx:0",
    status: "queued",
    required_memory_mb: 128,
    source_event_hash: `sha256:${"1".repeat(64)}`,
    challenge_candidate_hash: `sha256:${"4".repeat(64)}`,
    action: {
      candidate_hash: `sha256:${"4".repeat(64)}`,
      status: "broadcast",
      transaction_hash: `0x${"5".repeat(64)}`,
    },
  };
  writeFileSync(queue, `${canonicalJson({ schema_version: "p42-runner-queue/v1", jobs: [job] })}\n`, "utf8");

  const out = execFileSync("python3", [
    join(REPO_ROOT, "agent", "runtime_bridge.py"),
    "quarantine-canonical",
    "--queue", queue,
    "--job-id", job.job_id,
    "--reason", "reorg orphaned reveal",
  ], { cwd: REPO_ROOT, encoding: "utf8" });
  assert.deepEqual(JSON.parse(out).invalidated_job_ids, [job.job_id]);
  const updated = JSON.parse(readFileSync(queue, "utf8")).jobs[0];
  assert.equal(updated.status, "cancelled");
  assert.equal(updated.canonical_status, "orphaned_reorg");
  assert.equal(updated.action.status, "canonical_invalidated");
  assert.equal(updated.action.transaction_hash, `0x${"5".repeat(64)}`);
  assert.equal(updated.previous_action.status, "broadcast");
});


test("operator retries transient calldata retrieval until the canonical deadline", async () => {
  const directory = mkdtempSync(join(tmpdir(), "p42-operator-retry-"));
  const submissions = "0x1111111111111111111111111111111111111111";
  const challenges = "0x2222222222222222222222222222222222222222";
  const transactionHash = `0x${"a".repeat(64)}`;
  const sender = "0x3333333333333333333333333333333333333333";
  const bytes = ethers.toUtf8Bytes('{"answer":42}');
  const cid = `sha256:${ethers.sha256(bytes).slice(2)}`;
  const calldata = submissionInterface.encodeFunctionData("reveal", [
    7n,
    cid,
    0n,
    0n,
    "salt",
    bytes,
  ]);
  let transactionReads = 0;
  const rpc = createServer((request, response) => {
    let body = "";
    request.on("data", (chunk) => { body += chunk; });
    request.on("end", () => {
      const calls = JSON.parse(body);
      const requests = Array.isArray(calls) ? calls : [calls];
      const replies = requests.map((call) => {
        if (call.method === "eth_chainId") return { jsonrpc: "2.0", id: call.id, result: "0x7a69" };
        if (call.method === "eth_getTransactionByHash") {
          transactionReads += 1;
          if (transactionReads === 1) return { jsonrpc: "2.0", id: call.id, result: null };
          return {
            jsonrpc: "2.0",
            id: call.id,
            result: {
              hash: transactionHash,
              type: "0x2",
              accessList: [],
              blockHash: null,
              blockNumber: null,
              chainId: "0x7a69",
              from: sender,
              gas: "0x5208",
              gasPrice: "0x1",
              input: calldata,
              maxFeePerGas: "0x1",
              maxPriorityFeePerGas: "0x1",
              nonce: "0x0",
              r: `0x${"1".repeat(64)}`,
              s: `0x${"2".repeat(64)}`,
              to: submissions,
              transactionIndex: null,
              v: "0x1",
              value: "0x0",
            },
          };
        }
        return { jsonrpc: "2.0", id: call.id, result: null };
      });
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify(Array.isArray(calls) ? replies : replies[0]));
    });
  });
  await new Promise((done) => rpc.listen(0, "127.0.0.1", done));
  const address = rpc.address();
  const endpoint = `http://127.0.0.1:${address.port}`;
  const manifestPath = join(directory, "manifest.json");
  const submissionsArtifact = join(
    directory,
    "contracts",
    "artifacts",
    "src",
    "P42SubmissionManager.sol",
    "P42SubmissionManager.json",
  );
  const challengesArtifact = join(
    directory,
    "contracts",
    "artifacts",
    "src",
    "P42ChallengeManager.sol",
    "P42ChallengeManager.json",
  );
  const registryArtifact = join(
    directory,
    "contracts",
    "artifacts",
    "src",
    "P42ProblemRegistry.sol",
    "P42ProblemRegistry.json",
  );
  mkdirSync(dirname(submissionsArtifact), { recursive: true });
  mkdirSync(dirname(challengesArtifact), { recursive: true });
  mkdirSync(dirname(registryArtifact), { recursive: true });
  writeFileSync(submissionsArtifact, JSON.stringify({
    abi: ["function reveal(uint256 submissionId,string solutionCid,int256 claimedScoreAtoms,uint256 improvementAtoms,string salt,bytes solution)"],
  }), "utf8");
  writeFileSync(challengesArtifact, JSON.stringify({ abi: [] }), "utf8");
  writeFileSync(registryArtifact, JSON.stringify({ abi: [] }), "utf8");
  writeFileSync(manifestPath, JSON.stringify({
    contracts: {
      submissions: { address: submissions },
      challenges: { address: challenges },
      registry: { address: "0x6666666666666666666666666666666666666666" },
    },
  }), "utf8");

  const originalArgv = process.argv;
  const originalKey = process.env.OPERATOR_PRIVATE_KEY;
  process.argv = [
    process.execPath,
    join(HERE, "operator.mjs"),
    "--manifest", manifestPath,
    "--problem", join(REPO_ROOT, "problems", "hadamard-mini"),
    "--registry-problem-id", "1",
    "--runtime", join(directory, "runtime"),
    "--rpc", endpoint,
    "--repo-root", directory,
    "--local-test",
  ];
  process.env.OPERATOR_PRIVATE_KEY = `0x${"4".repeat(64)}`;

  try {
    const operatorUrl = `${pathToFileURL(join(HERE, "operator.mjs")).href}?retry-test=${Date.now()}`;
    const {
      isExplicitRetryableDaFailure,
      recoverPayload,
      retryableJobIsEligible,
    } = await import(operatorUrl);
    const event = {
      transactionHash,
      args: {
        submissionId: 7n,
        solutionCid: cid,
        claimedScoreAtoms: 0n,
        improvementAtoms: 0n,
        solutionBytesLength: BigInt(bytes.length),
      },
    };
    const submission = { commitDaHash: ethers.sha256(bytes) };

    const first = await recoverPayload(event, submission);
    assert.equal(first.daFailure.kind, "calldata_unavailable");
    assert.equal(first.daFailure.retryable, true);
    assert.equal(isExplicitRetryableDaFailure(first.daFailure), true);
    assert.equal(isExplicitRetryableDaFailure({
      kind: "arweave_retrieval_unavailable",
      error: "gateway timeout",
      retryable: true,
    }), true);
    assert.equal(retryableJobIsEligible({
      status: "queued",
      da_failure: first.daFailure,
      chain_claim: { challenge_ends_at: "200" },
    }, 199n), true);
    assert.equal(retryableJobIsEligible({
      status: "queued",
      da_failure: first.daFailure,
      chain_claim: { challenge_ends_at: "200" },
    }, 200n), false);
    const deferredRetry = {
      status: "queued",
      da_failure: first.daFailure,
      chain_claim: { challenge_ends_at: "200" },
      retry_not_before_utc: "2030-01-01T00:00:15Z",
    };
    assert.equal(
      retryableJobIsEligible(deferredRetry, 199n, Date.parse("2030-01-01T00:00:00Z")),
      false,
    );
    assert.equal(
      retryableJobIsEligible(deferredRetry, 199n, Date.parse("2030-01-01T00:00:15Z")),
      true,
    );

    // JsonRpcProvider briefly caches a null transaction lookup; the operator's
    // poll cadence is far longer than this cache window.
    await new Promise((done) => setTimeout(done, 300));
    const second = await recoverPayload(event, submission);
    assert.equal(second.daFailure, undefined);
    assert.deepEqual(Buffer.from(second.blob), Buffer.from(bytes));
  } finally {
    process.argv = originalArgv;
    if (originalKey === undefined) delete process.env.OPERATOR_PRIVATE_KEY;
    else process.env.OPERATOR_PRIVATE_KEY = originalKey;
    await new Promise((done) => rpc.close(done));
  }
});
