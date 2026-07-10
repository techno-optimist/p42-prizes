import assert from "node:assert/strict";
import test from "node:test";
import { ethers } from "ethers";

import { canonicalJson, sha256Canonical } from "./lib.mjs";
import {
  buildResolveCallPolicy,
  buildResolverTransportRequest,
  buildResolverVerdictHash,
  expandTranscriptUri,
  resolverEventHashFor,
  validateTranscriptUriTemplate,
  verifyResolverTranscript,
} from "./resolver.mjs";

const ADDR = {
  submissions: "0x1111111111111111111111111111111111111111",
  challenges: "0x2222222222222222222222222222222222222222",
  challenger: "0x3333333333333333333333333333333333333333",
};
const HASH = (digit) => `0x${digit.repeat(64)}`;
const SHA = (digit) => `sha256:${digit.repeat(64)}`;
const expected = {
  chain_id: 84532,
  problem_id: "hadamard-mini",
  submission_contract: ADDR.submissions,
  challenge_contract: ADDR.challenges,
  submission_id: "17",
  reveal_instance_hash: HASH("a"),
};

function report({ valid = true } = {}) {
  return {
    problem_id: "hadamard-mini",
    verifier_version: "1.0.0",
    verifier_image: "sha256:local-dev",
    solution_hash: SHA("b"),
    valid,
    improvement: "1/1",
    score: "3/1",
    reason: valid ? "verified" : "rejected",
    recomputed_at_commit: "deadbeef",
    details: {},
  };
}

function candidate({ action = "challenge", reasonCode = "score_underclaimed" } = {}) {
  const value = {
    schema_version: "p42-challenge-candidate/v1",
    action,
    reason_code: reasonCode,
    chain_id: expected.chain_id,
    problem_id: expected.problem_id,
    submission_contract: expected.submission_contract,
    challenge_contract: expected.challenge_contract,
    submission_id: expected.submission_id,
    reveal_instance_hash: expected.reveal_instance_hash,
    source_event_hash: SHA("c"),
    evidence_hash: SHA("d"),
    challenge_ends_at: "2000000000",
    max_bond_wei: "5000000000000000",
  };
  return { ...value, candidate_hash: sha256Canonical(value) };
}

function transcript({ candidateValue = candidate(), reportValue = report() } = {}) {
  const value = {
    schema_version: "p42-runner-transcript/v1",
    job_id: "84532:submission:block:tx:0",
    generated_at_utc: "2026-07-10T00:00:00Z",
    started_at_utc: "2026-07-10T00:00:00Z",
    problem: "/repo/problems/hadamard-mini",
    solution: "/runtime/inputs/fixture.json",
    da: { ok: true },
    resource_limits: {
      required_memory_mb: 128,
      memory_safety_factor: 2,
      child_address_space_limit_mb: 256,
      address_space_limit_supported: true,
    },
    verifier: {
      ok: true,
      valid: true,
      elapsed_ms: 15,
      sandbox: "docker",
      report: reportValue,
      report_hash: sha256Canonical(reportValue),
      chain_claim: {
        schema_version: "p42-chain-claim/v1",
        ...expected,
        claimed_score_atoms: "2",
        challenge_ends_at: "2000000000",
      },
      claim_comparison: {
        relation: "claimed_better_than_verified",
        verifier_score_atoms: "3",
      },
      challenge_candidate: candidateValue,
    },
  };
  return { ...value, transcript_hash: sha256Canonical(value) };
}

test("resolver accepts a self-hashed Docker transcript bound to its chain claim", () => {
  const checked = verifyResolverTranscript(transcript(), expected);

  assert.equal(checked.challengerWins, true);
  assert.equal(checked.claim.submission_id, "17");
  assert.equal(checked.transcriptHashBytes32, `0x${checked.transcript.transcript_hash.slice(7)}`);
  assert.equal(checked.candidate.action, "challenge");
});

test("resolver rejects tampered transcript, report, candidate, and mismatched claim evidence", () => {
  const tamperedTranscript = transcript();
  tamperedTranscript.verifier.elapsed_ms = 99;
  assert.throws(() => verifyResolverTranscript(tamperedTranscript, expected), /self-hash mismatch/);

  const tamperedReport = transcript();
  tamperedReport.verifier.report_hash = SHA("f");
  delete tamperedReport.transcript_hash;
  tamperedReport.transcript_hash = sha256Canonical(Object.fromEntries(
    Object.entries(tamperedReport).filter(([key]) => key !== "transcript_hash"),
  ));
  assert.throws(() => verifyResolverTranscript(tamperedReport, expected), /report hash mismatch/);

  const malformedCandidate = candidate();
  malformedCandidate.candidate_hash = SHA("e");
  const candidateTranscript = transcript({ candidateValue: malformedCandidate });
  assert.throws(() => verifyResolverTranscript(candidateTranscript, expected), /candidate self-hash mismatch/);

  assert.throws(
    () => verifyResolverTranscript(transcript(), { ...expected, reveal_instance_hash: HASH("f") }),
    /does not match the finalized challenge/,
  );
});

test("resolver refuses unresolved/quarantined evidence and grants a solver win only from accepted evidence", () => {
  const quarantined = candidate({ action: "quarantine", reasonCode: "report_shape_invalid" });
  assert.throws(
    () => verifyResolverTranscript(transcript({ candidateValue: quarantined }), expected),
    /refuses quarantined/,
  );

  const accepted = candidate({ action: "none", reasonCode: "verified_claim" });
  const solverTranscript = transcript({ candidateValue: accepted });
  solverTranscript.verifier.claim_comparison = { relation: "exact" };
  delete solverTranscript.transcript_hash;
  solverTranscript.transcript_hash = sha256Canonical(solverTranscript);
  assert.equal(verifyResolverTranscript(solverTranscript, expected).challengerWins, false);
});

test("resolver transcript URIs require a durable ar:// or ipfs:// template", () => {
  const template = "ar://p42-transcripts/{transcript_hash}.json";
  assert.equal(validateTranscriptUriTemplate(template), template);
  assert.equal(
    expandTranscriptUri(template, SHA("1")),
    `ar://p42-transcripts/${SHA("1")}.json`,
  );
  assert.throws(() => validateTranscriptUriTemplate("file:///tmp/{transcript_hash}.json"), /ar:\/\/ or ipfs:\/\//);
  assert.throws(() => validateTranscriptUriTemplate("https://example/{transcript_hash}"), /ar:\/\/ or ipfs:\/\//);
  assert.throws(() => validateTranscriptUriTemplate("ar://missing-placeholder"), /exactly one/);
  assert.throws(() => validateTranscriptUriTemplate("ipfs://x/{transcript_hash}/{transcript_hash}"), /exactly one/);
});

test("resolver exact-call policy binds the full decision, transcript URI, and instance hashes", () => {
  const challengeInterface = new ethers.Interface([
    "function resolve(uint256 submissionId,bytes32 expectedChallengeInstanceHash,bool challengerWins,bytes32 transcriptHash,string transcriptURI,bytes32 verdictHash) payable",
  ]);
  const transcriptHash = SHA("7");
  const candidateHash = SHA("8");
  const challengeInstanceHash = HASH("9");
  const transcriptURI = expandTranscriptUri("ipfs://bafyresolver/{transcript_hash}", transcriptHash);
  const verdictHash = buildResolverVerdictHash({
    transcriptHash,
    candidateHash,
    challengerWins: true,
    revealInstanceHash: expected.reveal_instance_hash,
    challengeInstanceHash,
  });
  const policy = buildResolveCallPolicy({
    challengeInterface,
    challengeContract: ADDR.challenges,
    chainId: expected.chain_id,
    problemId: expected.problem_id,
    submissionId: expected.submission_id,
    revealInstanceHash: expected.reveal_instance_hash,
    challengeInstanceHash,
    challengerWins: true,
    transcriptHash,
    transcriptURI,
    verdictHash,
    candidateHash,
    sourceEventHash: SHA("6"),
    expiresAt: "2000000000",
    valueWei: 5000000000000000n,
  });
  const expectedCalldata = challengeInterface.encodeFunctionData("resolve", [
    17n,
    challengeInstanceHash,
    true,
    `0x${transcriptHash.slice(7)}`,
    transcriptURI,
    verdictHash,
  ]);

  assert.equal(policy.calldata, expectedCalldata);
  assert.equal(policy.calldata_hash, ethers.keccak256(expectedCalldata));
  assert.equal(policy.scope_hash, ethers.id(policy.scope));
  assert.match(policy.scope, /challenge:0x999/);
  assert.match(policy.scope, /decision:challenger/);
  assert.equal(policy.call_value_wei, "5000000000000000");
  assert.deepEqual(policy.execute.arguments, [ADDR.challenges, "5000000000000000", expectedCalldata]);

  const agentWalletAddress = "0x4444444444444444444444444444444444444444";
  const agentWalletInterface = new ethers.Interface([
    "function execute(address target,uint256 value,bytes data) returns (bytes)",
  ]);
  const walletTransport = buildResolverTransportRequest({
    callPolicy: policy,
    executionMode: { mode: "agent-wallet" },
    agentWalletInterface,
    agentWalletAddress,
  });
  assert.equal(walletTransport.to, agentWalletAddress);
  assert.equal(walletTransport.value, 0n);
  assert.equal(
    walletTransport.data,
    agentWalletInterface.encodeFunctionData("execute", [ADDR.challenges, 5000000000000000n, expectedCalldata]),
  );
  assert.deepEqual(
    buildResolverTransportRequest({ callPolicy: policy, executionMode: "direct-eoa-local-test" }),
    { to: ADDR.challenges, data: expectedCalldata, value: 5000000000000000n },
  );

  const solverVerdict = buildResolverVerdictHash({
    transcriptHash,
    candidateHash,
    challengerWins: false,
    revealInstanceHash: expected.reveal_instance_hash,
    challengeInstanceHash,
  });
  assert.notEqual(verdictHash, solverVerdict);
});

test("resolver event identities bind all dispute instance fields", () => {
  const event = {
    blockNumber: 123,
    blockHash: HASH("1"),
    transactionHash: HASH("2"),
    transactionIndex: 4,
    index: 5,
    args: {
      submissionId: 17n,
      challenger: ADDR.challenger,
      reasonHash: HASH("3"),
      bondWei: 100n,
      disputeEndsAt: 2000000000n,
      revealInstanceHash: expected.reveal_instance_hash,
      challengeInstanceHash: HASH("4"),
    },
  };
  const context = { chainId: 84532, challengeContract: ADDR.challenges, problemId: "hadamard-mini" };
  const first = resolverEventHashFor(event, context);
  event.args.challengeInstanceHash = HASH("5");
  assert.notEqual(first, resolverEventHashFor(event, context));
});

test("fixture transcript is canonical JSON for the same bytes its hashes bind", () => {
  const value = transcript();
  assert.equal(JSON.parse(canonicalJson(value)).transcript_hash, value.transcript_hash);
});
