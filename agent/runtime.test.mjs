import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { ethers } from "ethers";

import {
  buildChallengeCallPolicy,
  buildOperatorCursor,
  buildSignedTransactionRecord,
  canonicalJson,
  nextOperatorScanRange,
  operatorCursorBinding,
  recoverRevealCalldata,
  resolveOperatorFinality,
  sha256Canonical,
  solverLifecycleDecision,
  submissionIdFromCommittedReceipt,
  validateOperatorCursor,
  validateOperatorExecutionMode,
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
    "function challenge(uint256 submissionId,bytes32 reasonHash) payable",
  ]);
  const reasonHash = `0x${"6".repeat(64)}`;
  const policy = buildChallengeCallPolicy({
    challengeInterface,
    challengeContract: "0x7777777777777777777777777777777777777777",
    chainId: 84532,
    problemId: "hadamard-mini",
    submissionId: 19n,
    reasonHash,
    candidateHash: `sha256:${"8".repeat(64)}`,
    sourceEventHash: `sha256:${"9".repeat(64)}`,
    expiresAt: 2000000000n,
    valueWei: 1234n,
  });
  const expectedCalldata = challengeInterface.encodeFunctionData("challenge", [19n, reasonHash]);

  assert.equal(policy.calldata, expectedCalldata);
  assert.equal(policy.calldata_hash, ethers.keccak256(expectedCalldata));
  assert.equal(policy.scope_hash, ethers.id(policy.scope));
  assert.match(policy.scope, /problem:hadamard-mini\|submission:19/);
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
  const unsigned = { ...policy };
  delete unsigned.policy_hash;
  assert.equal(policy.policy_hash, sha256Canonical(unsigned));
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
