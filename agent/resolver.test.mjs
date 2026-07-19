import assert from "node:assert/strict";
import { mkdtempSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
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
  buildQuorumResolveCallPolicy,
  buildResolveCallPolicy,
  buildResolverTransportRequest,
  buildResolverVerdictHash,
  configureResolverPublication,
  resolverEventHashFor,
  publishResolverTranscript,
  reservedResolverStakeWei,
  resolverCoordinationPaths,
  sharedReservedStakeWei,
  assertResolverActionPaths,
  assertActionPublication,
  assertResolverSignedRecord,
  verifyResolverTranscript,
} from "./resolver.mjs";
import {
  buildResolverQuorumDecisionPacket,
  buildResolverQuorumSignatureArtifact,
} from "./resolver-quorum.mjs";

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
const BOARD_MEMORY_MB = 128;
const BOARD_WALL_SECONDS = 60;
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
    schema_version: "p42-registry-binding/v2",
    image_hash_algorithm: "keccak256-utf8/v1",
    source_digest_algorithm: "p42-source-tree-sha256/v2",
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
  const boardResources = { memory_mb: BOARD_MEMORY_MB, wall_seconds: BOARD_WALL_SECONDS };
  const value = {
    schema_version: "p42-runner-transcript/v1",
    job_id: "84532:submission:block:tx:0",
    generated_at_utc: "2026-07-10T00:00:00Z",
    started_at_utc: "2026-07-10T00:00:00Z",
    problem: "/repo/problems/hadamard-mini",
    board_identity: {
      problem_slug: "hadamard-mini",
      problem_path: "/repo/problems/hadamard-mini",
      verifier_command: "python3 verifier/verify.py --solution {solution}",
      verifier_image: `ghcr.io/p42/hadamard-mini@${VERIFIER_IMAGE}`,
      verifier_source_sha256: VERIFIER_SOURCE,
      resource_identity: sha256Canonical(boardResources),
      ...boardResources,
    },
    solution: "/runtime/inputs/fixture.json",
    da: { ok: true },
    resource_limits: {
      required_memory_mb: BOARD_MEMORY_MB,
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
  assert.equal(checked.boardIdentity.problem_slug, expected.problem_id);
});

test("resolver requires board identity and binds it to the canonical claim, registry, and resources", () => {
  const missing = transcript();
  delete missing.board_identity;
  delete missing.transcript_hash;
  missing.transcript_hash = sha256Canonical(missing);
  assert.throws(() => verifyResolverTranscript(missing, expected), /missing: board_identity/);

  for (const [field, value, message] of [
    ["problem_slug", "other-problem", /problem_slug does not match the canonical claim binding/],
    ["problem_path", "/repo/problems/other", /problem_path does not match the transcript problem/],
    ["verifier_image", `ghcr.io/p42/hadamard-mini@${SHA("9")}`, /verifier_image does not match the canonical registry binding/],
    ["verifier_source_sha256", SHA("9"), /verifier_source_sha256 does not match the canonical registry binding/],
    ["memory_mb", 129, /memory_mb does not match the enforced resource limits/],
    ["resource_identity", SHA("9"), /resource_identity does not match its canonical resources/],
  ]) {
    const drifted = transcript();
    drifted.board_identity[field] = value;
    delete drifted.transcript_hash;
    drifted.transcript_hash = sha256Canonical(drifted);
    assert.throws(() => verifyResolverTranscript(drifted, expected), message);
  }
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
  const jwkFile = join(mkdtempSync(join(tmpdir(), "p42-resolver-jwk-")), "arweave-jwk.json");
  writeFileSync(jwkFile, '{"kty":"RSA","n":"n","e":"AQAB"}\n', { mode: 0o600 });
  const configured = configureResolverPublication(
    ["--publication-receipts", spool, "--transcript-endpoint", endpoints[0], "--transcript-endpoint", endpoints[1]],
    {},
    { fetchClient },
  );
  assert.equal(typeof configured.publisher.publishTranscript, "function");
  assert.deepEqual(configured.endpoints, endpoints);
  const arweave = configureResolverPublication(
    ["--transcript-store", "arweave", "--arweave-jwk-file", jwkFile, "--transcript-endpoint", endpoints[0], "--transcript-endpoint", endpoints[1]],
    {},
    {
      fetchClient,
      arweaveOptions: {
        owner: "w".repeat(43),
        findTxidsByCidImpl: async () => ["a".repeat(43)],
        fetchFromArweaveImpl: async () => Buffer.alloc(0),
        uploadToArweaveImpl: async () => { throw new Error("must not upload"); },
      },
    },
  );
  assert.equal(typeof arweave.publisher.publishTranscript, "function");
  assert.throws(
    () => configureResolverPublication(
      ["--transcript-store", "arweave", "--publication-receipts", spool, "--transcript-endpoint", endpoints[0], "--transcript-endpoint", endpoints[1]],
      {},
      { fetchClient },
    ),
    /exactly one transcript publisher mode/,
  );
  assert.throws(
    () => configureResolverPublication(
      ["--transcript-store", "arweave", "--transcript-endpoint", endpoints[0], "--transcript-endpoint", endpoints[1]],
      { P42_TRANSCRIPT_RECEIPT_SPOOL: spool },
      { fetchClient, arweaveOptions: { owner: "w".repeat(43) } },
    ),
    /P42_TRANSCRIPT_RECEIPT_SPOOL conflicts with explicit transcript publisher CLI/,
  );
  assert.throws(
    () => configureResolverPublication(
      ["--transcript-store", "arweave", "--transcript-endpoint", endpoints[0], "--transcript-endpoint", endpoints[1]],
      { P42_TRANSCRIPT_ENDPOINTS: endpoints.join(",") },
      { fetchClient, arweaveOptions: { owner: "w".repeat(43) } },
    ),
    /P42_TRANSCRIPT_ENDPOINTS conflicts with explicit --transcript-endpoint values/,
  );
});

test("resolver journals one publication receipt and re-verifies it after restart", async () => {
  const value = transcript();
  const actionsPath = mkdtempSync(join(tmpdir(), "p42-resolver-publication-"));
  let publishes = 0;
  let retrievals = 0;
  const context = {
    actionsPath,
    transcriptEndpoints: ["https://one.example", "https://two.test"],
    transcriptPublisher: {
      publishTranscript: async (_bytes, metadata) => {
        publishes += 1;
        return { uri: `ar://${"p".repeat(43)}`, artifact_sha256: metadata.artifact_sha256, length: metadata.length };
      },
    },
    transcriptFetchClient: {
      fetchTranscript: async () => {
        retrievals += 1;
        return Buffer.from(`${canonicalJson(value)}\n`);
      },
    },
  };
  const first = await publishResolverTranscript(context, SHA("a"), value);
  assert.equal(first.status, "published");
  assert.equal(publishes, 1);
  assert.equal(retrievals, 2);
  assert.equal(readdirSync(actionsPath).filter((name) => name.endsWith(".publication-receipt.json")).length, 1);

  context.transcriptPublisher = { publishTranscript: async () => { throw new Error("restart must reuse receipt"); } };
  const restarted = await publishResolverTranscript(context, SHA("a"), value);
  assert.equal(restarted.publication.uri, first.publication.uri);
  assert.equal(publishes, 1);
  assert.equal(retrievals, 4);
});

test("resolver recovers a journaled upload after partial gateway replication", async () => {
  const value = transcript();
  const actionsPath = mkdtempSync(join(tmpdir(), "p42-resolver-replication-"));
  let publishes = 0;
  let replicated = false;
  const context = {
    actionsPath,
    transcriptEndpoints: ["https://one.example", "https://two.test"],
    transcriptPublisher: {
      publishTranscript: async (_bytes, metadata) => {
        publishes += 1;
        return { uri: `ar://${"r".repeat(43)}`, artifact_sha256: metadata.artifact_sha256, length: metadata.length };
      },
    },
    transcriptFetchClient: {
      fetchTranscript: async ({ endpoint }) => endpoint.includes("two") && !replicated
        ? Buffer.from("not replicated\n")
        : Buffer.from(`${canonicalJson(value)}\n`),
    },
  };
  await assert.rejects(
    publishResolverTranscript(context, SHA("b"), value),
    /non-canonical transcript bytes/,
  );
  assert.equal(publishes, 1);

  replicated = true;
  context.transcriptPublisher = { publishTranscript: async () => { throw new Error("must not republish"); } };
  assert.equal((await publishResolverTranscript(context, SHA("b"), value)).status, "published");
  assert.equal(publishes, 1);
});

test("resolver rejects a replaced publication receipt journal", async () => {
  const value = transcript();
  const actionsPath = mkdtempSync(join(tmpdir(), "p42-resolver-publication-path-"));
  const context = {
    actionsPath,
    transcriptEndpoints: ["https://one.example", "https://two.test"],
    transcriptPublisher: {
      publishTranscript: async (_bytes, metadata) => ({
        uri: `ar://${"s".repeat(43)}`,
        artifact_sha256: metadata.artifact_sha256,
        length: metadata.length,
      }),
    },
    transcriptFetchClient: { fetchTranscript: async () => Buffer.from(`${canonicalJson(value)}\n`) },
  };
  const published = await publishResolverTranscript(context, SHA("c"), value);
  const replacement = join(actionsPath, "attacker.json");
  writeFileSync(replacement, `${canonicalJson(published.publication.receipt)}\n`);
  rmSync(published.receiptPath);
  symlinkSync(replacement, published.receiptPath);
  await assert.rejects(
    publishResolverTranscript(context, SHA("c"), value),
    /regular non-symlink file/,
  );
});

test("resolver re-verifies persisted publication evidence once per process before signing", async () => {
  const value = transcript();
  const actionsPath = mkdtempSync(join(tmpdir(), "p42-resolver-publication-restart-"));
  const transcriptPath = join(actionsPath, "transcript.json");
  writeFileSync(transcriptPath, `${canonicalJson(value)}\n`);
  let retrievals = 0;
  let confirmations = 0;
  const context = {
    actionsPath,
    transcriptEndpoints: ["https://one.example", "https://two.test"],
    transcriptPublisher: {
      publishTranscript: async (_bytes, metadata) => ({
        uri: `ar://${"v".repeat(43)}`,
        artifact_sha256: metadata.artifact_sha256,
        length: metadata.length,
      }),
      confirmReceipt: async () => { confirmations += 1; },
    },
    transcriptFetchClient: {
      fetchTranscript: async () => {
        retrievals += 1;
        return Buffer.from(`${canonicalJson(value)}\n`);
      },
    },
  };
  const published = await publishResolverTranscript(context, SHA("d"), value);
  assert.equal(confirmations, 1);
  const action = {
    event_hash: SHA("d"),
    transcript_hash: value.transcript_hash,
    transcript_path: transcriptPath,
    transcript_uri: published.publication.uri,
    publication_receipt_path: published.receiptPath,
    publication: published.publication,
    artifact_sha256: published.artifact.artifact_sha256,
    artifact_length: published.artifact.length,
  };
  retrievals = 0;
  await assertActionPublication(context, action);
  assert.equal(retrievals, 2);
  assert.equal(confirmations, 2);
  await assertActionPublication(context, action);
  assert.equal(retrievals, 2);
  assert.equal(confirmations, 2);

  const restarted = { ...context, verifiedPublications: new Set() };
  await assertActionPublication(restarted, action);
  assert.equal(retrievals, 4);
  assert.equal(confirmations, 3);
});

test("concurrent publishers fence on the signed upload journal before POST", async () => {
  const value = transcript();
  const actionsPath = mkdtempSync(join(tmpdir(), "p42-resolver-publication-race-"));
  let entered = 0;
  let release;
  const barrier = new Promise((resolve) => { release = resolve; });
  const context = {
    actionsPath,
    transcriptEndpoints: ["https://one.example", "https://two.test"],
    transcriptPublisher: {
      publishTranscript: async (_bytes, metadata) => {
        const ordinal = ++entered;
        if (entered === 2) release();
        await barrier;
        const txid = ordinal === 1 ? "x".repeat(43) : "y".repeat(43);
        await metadata.onPrepared({
          schema_version: "p42-arweave-signed-upload/v1",
          cid: metadata.artifact_sha256,
          length: metadata.length,
          txid,
          transaction: { id: txid },
        });
        const receipt = { uri: `ar://${txid}`, artifact_sha256: metadata.artifact_sha256, length: metadata.length };
        await metadata.onReceipt(receipt);
        return receipt;
      },
    },
    transcriptFetchClient: { fetchTranscript: async () => Buffer.from(`${canonicalJson(value)}\n`) },
  };
  const results = await Promise.allSettled([
    publishResolverTranscript(context, SHA("e"), value),
    publishResolverTranscript(context, SHA("e"), value),
  ]);
  assert.equal(results.filter((result) => result.status === "fulfilled").length, 1);
  assert.equal(results.filter((result) => result.status === "rejected").length, 1);
  assert.match(results.find((result) => result.status === "rejected").reason.message, /conflicts|EEXIST/);
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

test("production resolver policy relays an exact current-epoch quorum decision with zero value", async () => {
  const quorumInterface = new ethers.Interface([
    "function resolve((uint256 chainId,address adapter,address manager,uint256 submissionId,bytes32 challengeInstanceHash,bool challengerWins,bytes32 transcriptHash,bytes32 transcriptURIHash,bytes32 verdictHash,address bondBeneficiary,uint256 nonce,uint64 expiry,uint64 signerEpoch) decision,string transcriptURI,bytes[] signatures) payable",
  ]);
  const adapter = "0x7777777777777777777777777777777777777777";
  const packet = buildResolverQuorumDecisionPacket({
    chainId: expected.chain_id,
    adapter,
    manager: ADDR.challenges,
    submissionId: expected.submission_id,
    challengeInstanceHash: HASH("9"),
    challengerWins: true,
    transcriptHash: HASH("7"),
    transcriptURI: "ipfs://canonical-quorum-transcript",
    verdictHash: HASH("8"),
    expiry: "2000000000",
    signerEpoch: "4",
  });
  const signers = [ethers.Wallet.createRandom(), ethers.Wallet.createRandom()];
  const signatures = (await Promise.all(signers.map((signer) => buildResolverQuorumSignatureArtifact(packet, signer))))
    .sort((left, right) => left.signer.localeCompare(right.signer))
    .map(({ signature }) => signature);
  const policy = buildQuorumResolveCallPolicy({
    quorumInterface,
    packet,
    signatures,
    problemId: expected.problem_id,
    revealInstanceHash: expected.reveal_instance_hash,
    candidateHash: SHA("8"),
    sourceEventHash: SHA("6"),
  });
  const decoded = quorumInterface.decodeFunctionData("resolve", policy.calldata);
  assert.equal(decoded[0].adapter.toLowerCase(), adapter);
  assert.equal(decoded[0].manager.toLowerCase(), ADDR.challenges);
  assert.equal(decoded[0].submissionId, 17n);
  assert.equal(decoded[1], packet.transcript_uri);
  assert.deepEqual([...decoded[2]], signatures);
  assert.equal(policy.target, adapter);
  assert.equal(policy.call_value_wei, "0");
  assert.equal(policy.required_per_call_value_cap_wei, "0");
  assert.equal(policy.decision_digest, packet.decision_digest);
  assert.match(policy.scope, /resolver-quorum-relay/);
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

test("resolver stake reservations cover all unmined canonical quorum decisions", () => {
  const actions = {
    first: {
      event_hash: SHA("1"), transport: "quorum", canonical_status: "canonical",
      status: "awaiting_quorum_signatures", bond_wei: "50",
    },
    second: {
      event_hash: SHA("2"), transport: "quorum", canonical_status: "canonical",
      status: "broadcast", bond_wei: "75",
    },
    mined: {
      event_hash: SHA("3"), transport: "quorum", canonical_status: "canonical",
      status: "submitted", bond_wei: "100",
    },
    orphaned: {
      event_hash: SHA("4"), transport: "quorum", canonical_status: "orphaned_reorg",
      status: "orphaned_reorg", bond_wei: "200",
    },
  };
  assert.equal(reservedResolverStakeWei(actions), 125n);
  assert.equal(reservedResolverStakeWei(actions, SHA("1")), 75n);
});

test("resolver coordination identity is shared across board runtimes", () => {
  const root = "/var/lib/p42/resolver-coordination";
  const quorumAddress = "0x7777777777777777777777777777777777777777";
  const first = resolverCoordinationPaths({ coordinationRoot: root, chainId: 84532, quorumAddress });
  const second = resolverCoordinationPaths({ coordinationRoot: root, chainId: 84532, quorumAddress });
  assert.deepEqual(first, second);
  assert.match(first.lockPath, /84532-777777/);
  const context = { quorumReservations: { reservations: {
    [SHA("1")]: { event_hash: SHA("1"), phase: "reserved", bond_wei: "50" },
    [SHA("2")]: { event_hash: SHA("2"), phase: "onchain", bond_wei: "75" },
  } } };
  assert.equal(sharedReservedStakeWei(context), 50n);
  assert.equal(sharedReservedStakeWei(context, SHA("1")), 0n);
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
