import assert from "node:assert/strict";
import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import test from "node:test";
import { ethers } from "ethers";

import {
  canonicalJson,
  buildSignedTransactionRecord,
  sha256Canonical,
  verifierImageHashForDigest,
  verifierSourceHashForDigest,
} from "./lib.mjs";
import {
  buildResolveCallPolicy,
  buildResolverTransportRequest,
  buildResolverVerdictHash,
  configureResolverPublication,
  expandTranscriptUri,
  resolverEventHashFor,
  assertResolverActionPaths,
  assertResolverSignedRecord,
  validateTranscriptUriTemplate,
  verifyResolverTranscript,
} from "./resolver.mjs";

const ADDR = {
  submissions: "0x1111111111111111111111111111111111111111",
  challenges: "0x2222222222222222222222222222222222222222",
  challenger: "0x3333333333333333333333333333333333333333",
  registry: "0x4444444444444444444444444444444444444444",
  pool: "0x5555555555555555555555555555555555555555",
  ledger: "0x6666666666666666666666666666666666666666",
};
const HASH = (digit) => `0x${digit.repeat(64)}`;
const SHA = (digit) => `sha256:${digit.repeat(64)}`;
const VERIFIER_IMAGE = SHA("e");
const VERIFIER_SOURCE = SHA("f");
const expected = {
  chain_id: 84532,
  problem_id: "hadamard-mini",
  submission_contract: ADDR.submissions,
  challenge_contract: ADDR.challenges,
  submission_id: "17",
  reveal_instance_hash: HASH("a"),
  registry_address: ADDR.registry,
  registry_problem_id: "1",
  registry_problem_slug: "hadamard-mini",
};

function registryBinding() {
  return {
    schema_version: "p42-registry-binding/v1",
    image_hash_algorithm: "keccak256-utf8/v1",
    source_digest_algorithm: "p42-source-tree-sha256/v1",
    source_hash_algorithm: "keccak256-utf8/v1",
    chain_id: expected.chain_id,
    registry_address: ADDR.registry,
    problem_id: "1",
    problem_slug: "hadamard-mini",
    verifier_version: "1.0.0",
    observation_block_number: 100,
    observation_block_hash: HASH("1"),
    verifier_image: VERIFIER_IMAGE,
    verifier_image_hash: verifierImageHashForDigest(VERIFIER_IMAGE),
    verifier_source_digest: VERIFIER_SOURCE,
    verifier_source_hash: verifierSourceHashForDigest(VERIFIER_SOURCE),
    spec_hash: HASH("2"),
    admission_hash: HASH("3"),
    metadata_uri: "ipfs://p42-fixture",
    pool: ADDR.pool,
    ledger: ADDR.ledger,
    submission_manager: ADDR.submissions,
    challenge_manager: ADDR.challenges,
    challenge_window_seconds: "259200",
    min_improvement_atoms: "1",
    frozen: true,
    explicitly_frozen: true,
  };
}

function report({ valid = true } = {}) {
  return {
    problem_id: "hadamard-mini",
    verifier_version: "1.0.0",
    verifier_image: VERIFIER_IMAGE,
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
        registry_binding: registryBinding(),
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

  const mismatchedBinding = transcript();
  mismatchedBinding.verifier.chain_claim.registry_binding.verifier_image = SHA("9");
  delete mismatchedBinding.transcript_hash;
  mismatchedBinding.transcript_hash = sha256Canonical(mismatchedBinding);
  assert.throws(
    () => verifyResolverTranscript(mismatchedBinding, expected),
    /verifier_image_hash mismatch/,
  );

  const missingBinding = transcript();
  delete missingBinding.verifier.chain_claim.registry_binding;
  delete missingBinding.transcript_hash;
  missingBinding.transcript_hash = sha256Canonical(missingBinding);
  assert.throws(
    () => verifyResolverTranscript(missingBinding, expected),
    /registry binding must be an object/,
  );
});

test("resolver preserves a DA challenge without a verifier report but still requires the registry binding", () => {
  const daCandidate = candidate({ reasonCode: "da_payload_missing" });
  const daTranscript = transcript({ candidateValue: daCandidate });
  daTranscript.da = { ok: false, challengeable: true };
  daTranscript.verifier.ok = false;
  daTranscript.verifier.valid = false;
  delete daTranscript.verifier.report;
  delete daTranscript.verifier.report_hash;
  delete daTranscript.transcript_hash;
  daTranscript.transcript_hash = sha256Canonical(daTranscript);

  const checked = verifyResolverTranscript(daTranscript, expected);
  assert.equal(checked.challengerWins, true);
  assert.equal(checked.report, null);
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
  const template = "ar://{transcript_hash}";
  assert.equal(validateTranscriptUriTemplate(template), template);
  assert.equal(
    expandTranscriptUri(template, SHA("1")),
    `ar://${SHA("1")}`,
  );
  assert.throws(() => validateTranscriptUriTemplate("file:///tmp/{transcript_hash}.json"), /ar:\/\/ or ipfs:\/\//);
  assert.throws(() => validateTranscriptUriTemplate("https://example/{transcript_hash}"), /ar:\/\/ or ipfs:\/\//);
  assert.throws(() => validateTranscriptUriTemplate("ar://missing-placeholder"), /exactly one/);
  assert.throws(() => validateTranscriptUriTemplate("ipfs://x/{transcript_hash}/{transcript_hash}"), /exactly one/);
});

test("resolver production configuration requires receipts and trusted retrieval endpoints", () => {
  const endpoints = ["https://one.example", "https://two.test"];
  const publisher = { publishTranscript: async () => ({}) };
  const fetchClient = { fetchTranscript: async () => Buffer.alloc(0) };
  assert.deepEqual(configureResolverPublication([], {}, { endpoints, publisher, fetchClient }), {
    endpoints, publisher, fetchClient,
  });
  assert.throws(
    () => configureResolverPublication(["--transcript-uri-template", "ar://{transcript_hash}"], {
      P42_TRANSCRIPT_ENDPOINTS: endpoints.join(","),
    }),
    /URI templates cannot publish transcripts/,
  );
  const spool = mkdtempSync(join(tmpdir(), "p42-resolver-receipts-"));
  const configured = configureResolverPublication(
    ["--publication-receipts", spool],
    { P42_TRANSCRIPT_ENDPOINTS: endpoints.join(",") },
    { fetchClient },
  );
  assert.equal(typeof configured.publisher.publishTranscript, "function");
  assert.deepEqual(configured.endpoints, endpoints);
});

test("resolver exact-call policy binds the full decision, transcript URI, and instance hashes", () => {
  const challengeInterface = new ethers.Interface([
    "function resolve(uint256 submissionId,bytes32 expectedChallengeInstanceHash,bool challengerWins,bytes32 transcriptHash,string transcriptURI,bytes32 verdictHash) payable",
  ]);
  const transcriptHash = SHA("7");
  const candidateHash = SHA("8");
  const challengeInstanceHash = HASH("9");
  const transcriptURI = "ipfs://bafybeigdyrzt5sfp7udm7hu76uh7y26nf3pte3dr2l7w4qv3q2x4x5b5ha/transcript.json";
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

async function resolverRestartFixture() {
  const actionsPath = mkdtempSync(join(tmpdir(), "p42-resolver-restart-"));
  const wallet = ethers.Wallet.createRandom();
  const challengeInterface = new ethers.Interface([
    "function resolve(uint256,bytes32,bool,bytes32,string,bytes32) payable",
  ]);
  const transcriptHash = SHA("7");
  const challengeInstanceHash = HASH("9");
  const verdictHash = HASH("8");
  const policy = buildResolveCallPolicy({
    challengeInterface, challengeContract: ADDR.challenges, chainId: 31337,
    problemId: expected.problem_id, submissionId: expected.submission_id,
    revealInstanceHash: expected.reveal_instance_hash, challengeInstanceHash,
    challengerWins: true, transcriptHash,
    transcriptURI: `ar://${"a".repeat(43)}`, verdictHash,
    candidateHash: SHA("8"), sourceEventHash: SHA("6"),
    expiresAt: "2000000000", valueWei: 5n,
  });
  const eventHash = SHA("5");
  const prefix = `${eventHash.slice(7)}-${policy.policy_hash.slice(7, 23)}`;
  const policyPath = join(actionsPath, `${prefix}.policy.json`);
  const signedPath = join(actionsPath, `${prefix}.signed-tx.json`);
  writeFileSync(policyPath, `${canonicalJson(policy)}\n`);
  const action = {
    event_hash: eventHash, call_policy_hash: policy.policy_hash,
    call_policy_path: policyPath, signed_tx_path: signedPath, call_policy: policy,
    submission_id: expected.submission_id, challenge_instance_hash: challengeInstanceHash,
    transcript_hash: transcriptHash,
  };
  const request = buildResolverTransportRequest({ callPolicy: policy, executionMode: "direct-eoa-local-test" });
  const record = await buildSignedTransactionRecord({
    wallet,
    request: { ...request, nonce: 3, gasLimit: 500000n, gasPrice: 1n, chainId: 31337, type: 0 },
    label: `resolve:${action.submission_id}:${action.challenge_instance_hash}:${action.transcript_hash}`,
  });
  const context = {
    actionsPath, wallet, chainId: 31337,
    executionMode: { mode: "direct-eoa-local-test" },
    chal: { interface: challengeInterface, target: ADDR.challenges }, agentWallet: null,
  };
  return { action, context, record, policyPath, signedPath };
}

test("resolver restart uses the complete shared transaction journal validator", async () => {
  const { action, context, record } = await resolverRestartFixture();
  assert.equal(assertResolverSignedRecord(record, action, context).hash, record.hash);
  for (const [field, value, pattern] of [
    ["chain_id", 1, /chain mismatch/],
    ["to", ADDR.submissions, /destination mismatch/],
    ["data_hash", ethers.ZeroHash, /declared calldata hash mismatch/],
    ["value", "6", /value mismatch/],
    ["nonce", 4, /nonce mismatch/],
    ["label", "resolve:conflict", /label binding mismatch/],
    ["hash", ethers.ZeroHash, /raw transaction hash mismatch/],
  ]) assert.throws(() => assertResolverSignedRecord({ ...record, [field]: value }, action, context), pattern, field);
  assert.throws(
    () => assertResolverSignedRecord(record, { ...action, transaction_hash: ethers.ZeroHash }, context),
    /hash does not match persisted transaction hash/,
  );
  assert.throws(
    () => assertResolverSignedRecord(record, { ...action, transaction_nonce: 4 }, context),
    /nonce does not match persisted nonce/,
  );
});

test("resolver restart paths are deterministic regular files under actions root", async () => {
  const { action, context, record, signedPath } = await resolverRestartFixture();
  writeFileSync(signedPath, `${canonicalJson(record)}\n`);
  assert.equal(basename(assertResolverActionPaths(action, context, { signedMustExist: true }).signedPath), basename(signedPath));
  assert.throws(
    () => assertResolverActionPaths({ ...action, signed_tx_path: join(context.actionsPath, "..", "outside.json") }, context),
    /deterministic action path/,
  );
  const outside = join(tmpdir(), `p42-resolver-outside-${Date.now()}.json`);
  writeFileSync(outside, "{}\n");
  rmSync(signedPath);
  symlinkSync(outside, signedPath);
  assert.throws(
    () => assertResolverActionPaths(action, context, { signedMustExist: true }),
    /non-symlink/,
  );
});
