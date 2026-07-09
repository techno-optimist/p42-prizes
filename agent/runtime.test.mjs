import assert from "node:assert/strict";
import test from "node:test";
import { ethers } from "ethers";

import {
  buildChallengeCallPolicy,
  canonicalJson,
  recoverRevealCalldata,
  sha256Canonical,
  solverLifecycleDecision,
  submissionIdFromCommittedReceipt,
} from "./lib.mjs";


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

  const recovered = recoverRevealCalldata(topLevel, submissionInterface, expected);

  assert.equal(recovered.nested, true);
  assert.ok(recovered.calldataOffsetBytes > 0);
  assert.equal(recovered.callData, reveal.toLowerCase());
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
