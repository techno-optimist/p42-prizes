import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { generateKeyPairSync, sign as signEd25519 } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { ethers } from "ethers";

import { canonicalJson, sha256Canonical, verifierImageHashForDigest, verifierSourceHashForDigest } from "./lib.mjs";
import { buildResolverVerdictHash } from "./resolver.mjs";
import { buildResolverQuorumDecisionPacket } from "./resolver-quorum.mjs";
import { buildResolverRerunRequest } from "./resolver-rerun-executor.mjs";
import {
  bindResolverRerunReceipt,
  issueResolverRerunChallenge,
  markResolverRerunAuthorization,
  markResolverRerunSignature,
  persistResolverRerunRequest,
  resolverRerunReceiptSigningMessage,
} from "./resolver-rerun-attestation.mjs";
import { persistSignerAuthorization, verifyIndependentResolverDecision } from "./resolver-signer.mjs";

const ADDR = {
  submissions: "0x1111111111111111111111111111111111111111",
  challenges: "0x2222222222222222222222222222222222222222",
  registry: "0x3333333333333333333333333333333333333333",
  pool: "0x4444444444444444444444444444444444444444",
  ledger: "0x5555555555555555555555555555555555555555",
  quorum: "0x6666666666666666666666666666666666666666",
};
const HASH = (digit) => `0x${digit.repeat(64)}`;
const SHA = (digit) => `sha256:${digit.repeat(64)}`;
const IMAGE = SHA("e");
const SOURCE = SHA("f");
const BOARD_MEMORY_MB = 128;
const BOARD_WALL_SECONDS = 60;
const VERIFY_NOW = Date.parse("2026-07-10T00:05:00Z");
const EXECUTOR_KEYS = generateKeyPairSync("ed25519");
const EXECUTOR_PUBLIC = `ed25519:${EXECUTOR_KEYS.publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("hex")}`;
const EXECUTOR_TRUST = Object.freeze({
  schema_version: "p42-resolver-rerun-executor-trust/v1",
  key_id: "resolver-executor-fixture",
  purpose: "resolver-rerun",
  algorithm: "ed25519",
  public_key: EXECUTOR_PUBLIC,
});

function registryBinding() {
  return {
    schema_version: "p42-registry-binding/v2",
    image_hash_algorithm: "keccak256-utf8/v1",
    source_digest_algorithm: "p42-source-tree-sha256/v2",
    source_hash_algorithm: "keccak256-utf8/v1",
    chain_id: 84532,
    registry_address: ADDR.registry,
    problem_id: "1",
    problem_slug: "hadamard-mini",
    verifier_version: "1.0.0",
    observation_block_number: 100,
    observation_block_hash: HASH("1"),
    verifier_image: IMAGE,
    verifier_image_hash: verifierImageHashForDigest(IMAGE),
    verifier_source_digest: SOURCE,
    verifier_source_hash: verifierSourceHashForDigest(SOURCE),
    spec_hash: HASH("2"),
    admission_hash: HASH("3"),
    metadata_uri: "ipfs://bafkreibm6jg3ux5qu6x6q6l5vfvbhrcbfcxg3d4ud3bzv4wq4vm5xw7h7u",
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

function report(overrides = {}) {
  return {
    problem_id: "hadamard-mini",
    verifier_version: "1.0.0",
    verifier_image: IMAGE,
    solution_hash: SHA("b"),
    valid: true,
    improvement: "1/1",
    score: "3/1",
    reason: "verified",
    recomputed_at_commit: "deadbeef",
    details: {},
    ...overrides,
  };
}

function candidate(overrides = {}) {
  const value = {
    schema_version: "p42-challenge-candidate/v1",
    action: "challenge",
    reason_code: "score_underclaimed",
    chain_id: 84532,
    problem_id: "hadamard-mini",
    submission_contract: ADDR.submissions,
    challenge_contract: ADDR.challenges,
    submission_id: "17",
    reveal_instance_hash: HASH("a"),
    source_event_hash: SHA("c"),
    evidence_hash: null,
    challenge_ends_at: "2000000000",
    max_bond_wei: "5000000000000000",
    ...overrides,
  };
  value.evidence_hash ??= SHA("d");
  value.candidate_hash = sha256Canonical(value);
  return value;
}

function transcript({ generated = "2026-07-10T00:00:00Z", elapsedMs = 15, candidateValue = candidate(), reportValue = report() } = {}) {
  const boardResources = { memory_mb: BOARD_MEMORY_MB, wall_seconds: BOARD_WALL_SECONDS };
  const value = {
    schema_version: "p42-runner-transcript/v1",
    job_id: `independent-${generated}`,
    generated_at_utc: generated,
    started_at_utc: generated,
    problem: "/repo/problems/hadamard-mini",
    board_identity: {
      problem_slug: "hadamard-mini",
      problem_path: "/repo/problems/hadamard-mini",
      verifier_command: "python3 verifier/verify.py --solution {solution}",
      verifier_image: `ghcr.io/p42/hadamard-mini@${IMAGE}`,
      verifier_source_sha256: SOURCE,
      resource_identity: sha256Canonical(boardResources),
      ...boardResources,
    },
    solution: "/runtime/inputs/fixture.json",
    da: {
      ok: true,
      mode: "offchain-store",
      expected_hash: SHA("b"),
      observed_hash: SHA("b"),
      challengeable: false,
    },
    resource_limits: {
      required_memory_mb: BOARD_MEMORY_MB,
      memory_safety_factor: 2,
      child_address_space_limit_mb: 256,
      address_space_limit_supported: true,
    },
    verifier: {
      ok: true,
      valid: true,
      elapsed_ms: elapsedMs,
      sandbox: "docker",
      report: reportValue,
      report_hash: sha256Canonical(reportValue),
      chain_claim: {
        schema_version: "p42-chain-claim/v1",
        chain_id: 84532,
        problem_id: "hadamard-mini",
        submission_contract: ADDR.submissions,
        challenge_contract: ADDR.challenges,
        submission_id: "17",
        claimed_score_atoms: "2",
        reveal_instance_hash: HASH("a"),
        challenge_ends_at: "2000000000",
        registry_binding: registryBinding(),
      },
      claim_comparison: { relation: "claimed_better_than_verified", verifier_score_atoms: "3" },
      challenge_candidate: candidateValue,
    },
  };
  return { ...value, transcript_hash: sha256Canonical(value) };
}

function rerunChallenge(packet, overrides = {}) {
  return {
    schema_version: "p42-resolver-rerun-challenge/v1",
    packet_hash: packet.packet_hash,
    decision_digest: packet.decision_digest,
    challenge_instance_hash: packet.decision.challengeInstanceHash,
    orchestrator_nonce: HASH("6"),
    issued_at_utc: "2026-07-10T00:00:00Z",
    expires_at_utc: "2026-07-10T00:15:00Z",
    ...overrides,
  };
}

function signedRerunReceipt({ packet, publishedTranscript, localTranscript, challenge, keys = EXECUTOR_KEYS, trust = EXECUTOR_TRUST }) {
  const unsigned = {
    schema_version: "p42-resolver-rerun/v1",
    executor_key_id: trust.key_id,
    algorithm: "ed25519",
    packet_hash: packet.packet_hash,
    decision_digest: packet.decision_digest,
    chain_id: packet.decision.chainId,
    quorum: packet.decision.adapter,
    manager: packet.decision.manager,
    submission_id: packet.decision.submissionId,
    challenge_instance_hash: packet.decision.challengeInstanceHash,
    reveal_instance_hash: localTranscript.verifier.chain_claim.reveal_instance_hash,
    published_transcript_hash: publishedTranscript.transcript_hash,
    solution_hash: localTranscript.verifier.report.solution_hash,
    da_expected_hash: localTranscript.da.expected_hash,
    da_observed_hash: localTranscript.da.observed_hash,
    verifier_image: localTranscript.verifier.chain_claim.registry_binding.verifier_image,
    verifier_source_digest: localTranscript.verifier.chain_claim.registry_binding.verifier_source_digest,
    resource_identity: localTranscript.board_identity.resource_identity,
    orchestrator_nonce: challenge.orchestrator_nonce,
    local_transcript_hash: localTranscript.transcript_hash,
  };
  const receiptHash = sha256Canonical(unsigned);
  return {
    ...unsigned,
    receipt_hash: receiptHash,
    signature: {
      algorithm: "ed25519",
      key_id: trust.key_id,
      signature: `ed25519:${signEd25519(null, resolverRerunReceiptSigningMessage(receiptHash), keys.privateKey).toString("hex")}`,
    },
  };
}

function fixture({ challengeInstanceHash = HASH("9"), localTranscript = null } = {}) {
  const publishedTranscript = transcript();
  const verdictHash = buildResolverVerdictHash({
    transcriptHash: publishedTranscript.transcript_hash,
    candidateHash: publishedTranscript.verifier.challenge_candidate.candidate_hash,
    challengerWins: true,
    revealInstanceHash: HASH("a"),
    challengeInstanceHash,
  });
  const packet = buildResolverQuorumDecisionPacket({
    chainId: 84532,
    adapter: ADDR.quorum,
    manager: ADDR.challenges,
    submissionId: 17,
    challengeInstanceHash,
    challengerWins: true,
    transcriptHash: `0x${publishedTranscript.transcript_hash.slice(7)}`,
    transcriptURI: "ipfs://bafkreibm6jg3ux5qu6x6q6l5vfvbhrcbfcxg3d4ud3bzv4wq4vm5xw7h7u",
    verdictHash,
    expiry: 2_000_000_000,
    signerEpoch: 3,
  });
  const live = {
    finalizedBlockNumber: 200,
    finalizedBlockHash: HASH("8"),
    finalizedTimestamp: 1_999_999_000,
    quorum: ADDR.quorum,
    manager: ADDR.challenges,
    managerResolver: ADDR.quorum,
    submissionId: "17",
    challengeSubmissionId: "17",
    submissionStatus: "3",
    revealInstanceHash: HASH("a"),
    challengeRevealInstanceHash: HASH("a"),
    challengeInstanceHash,
    disputeEndsAt: "2000000000",
    resolved: false,
    decisionPending: false,
    quorumPaused: false,
    isManager: true,
    signerEpoch: "3",
    threshold: "2",
    signerMember: true,
    nonceUsed: false,
    resolverDecisionBondWei: "5000000000000000",
    quorumBalanceWei: "10000000000000000",
  };
  const rerunTranscript = localTranscript ?? transcript({ generated: "2026-07-10T00:00:01Z", elapsedMs: 16 });
  const rerunChallengeValue = rerunChallenge(packet);
  const rerunReceipt = signedRerunReceipt({
    packet,
    publishedTranscript,
    localTranscript: rerunTranscript,
    challenge: rerunChallengeValue,
  });
  return {
    packet,
    publishedTranscript,
    localTranscript: rerunTranscript,
    live,
    rerunReceipt,
    rerunChallenge: rerunChallengeValue,
    executorTrust: EXECUTOR_TRUST,
    now: VERIFY_NOW,
  };
}

function verify(overrides = {}) {
  const value = { ...fixture(), ...overrides };
  return verifyIndependentResolverDecision({
    ...value,
    registryAddress: ADDR.registry,
    registryProblemId: "1",
    problemSlug: "hadamard-mini",
  });
}

test("independent signer accepts a valid independently attested rerun", () => {
  const checked = verify();
  assert.notEqual(checked.local.transcript.transcript_hash, checked.published.transcript.transcript_hash);
  assert.equal(checked.rerunReceipt.executor_key_id, EXECUTOR_TRUST.key_id);
  assert.equal(checked.packet.decision.challengerWins, true);
});

test("independent signer rejects exact copies and timestamp-only transcript rewraps", () => {
  const exact = fixture();
  const exactCopy = structuredClone(exact.publishedTranscript);
  const exactReceipt = signedRerunReceipt({
    packet: exact.packet,
    publishedTranscript: exact.publishedTranscript,
    localTranscript: exactCopy,
    challenge: exact.rerunChallenge,
  });
  assert.throws(
    () => verify({ localTranscript: exactCopy, rerunReceipt: exactReceipt }),
    /exact copy of the published transcript/,
  );

  const rewrapped = transcript({ generated: "2026-07-10T00:00:02Z", elapsedMs: 15 });
  const rewrappedReceipt = signedRerunReceipt({
    packet: exact.packet,
    publishedTranscript: exact.publishedTranscript,
    localTranscript: rewrapped,
    challenge: exact.rerunChallenge,
  });
  assert.throws(
    () => verify({ localTranscript: rewrapped, rerunReceipt: rewrappedReceipt }),
    /timestamp-only transcript rewrap/,
  );
});

test("independent signer rejects a forged executor key", () => {
  const base = fixture();
  const forgedKeys = generateKeyPairSync("ed25519");
  const forged = signedRerunReceipt({
    packet: base.packet,
    publishedTranscript: base.publishedTranscript,
    localTranscript: base.localTranscript,
    challenge: base.rerunChallenge,
    keys: forgedKeys,
  });
  assert.throws(() => verify({ rerunReceipt: forged }), /executor signature is invalid/);
});

test("independent signer rejects stale nonces and cross-packet receipt replay", () => {
  const base = fixture();
  const staleChallenge = { ...base.rerunChallenge, expires_at_utc: "2026-07-10T00:04:59Z" };
  const staleReceipt = signedRerunReceipt({
    packet: base.packet,
    publishedTranscript: base.publishedTranscript,
    localTranscript: base.localTranscript,
    challenge: staleChallenge,
  });
  assert.throws(
    () => verify({ rerunChallenge: staleChallenge, rerunReceipt: staleReceipt }),
    /challenge nonce is stale/,
  );
  assert.equal(
    verify({ rerunChallenge: staleChallenge, rerunReceipt: staleReceipt, allowExpiredRerunReceipt: true }).rerunReceipt.receipt_hash,
    staleReceipt.receipt_hash,
  );

  const other = fixture({ challengeInstanceHash: HASH("7") });
  assert.throws(
    () => verify({ ...other, rerunReceipt: base.rerunReceipt }),
    /receipt packet_hash binding mismatch/,
  );
});

test("signer-issued attempts resume identical receipts and reject substitutions", () => {
  const root = mkdtempSync(join(tmpdir(), "p42-resolver-rerun-"));
  try {
    const base = fixture();
    const issued = issueResolverRerunChallenge(root, base.packet, {
      now: VERIFY_NOW - 1_000,
      ttlMs: 60_000,
      randomBytes: () => Buffer.alloc(32, 0x66),
    });
    assert.equal(issued.challenge.orchestrator_nonce, HASH("6"));
    assert.throws(
      () => issueResolverRerunChallenge(root, base.packet, {
        now: VERIFY_NOW,
        randomBytes: () => Buffer.alloc(32, 0x77),
      }),
      /already active for this packet/,
    );
    const receipt = signedRerunReceipt({
      packet: base.packet,
      publishedTranscript: base.publishedTranscript,
      localTranscript: base.localTranscript,
      challenge: issued.challenge,
    });
    const receiptPath = bindResolverRerunReceipt(root, base.packet, receipt);
    assert.equal(bindResolverRerunReceipt(root, base.packet, receipt), receiptPath);
    const changed = { ...receipt, receipt_hash: SHA("1") };
    assert.throws(
      () => bindResolverRerunReceipt(root, base.packet, changed),
      /different receipt content/,
    );
    const authorization = markResolverRerunAuthorization(root, base.packet, receipt, "/private/authorization.json");
    assert.equal(markResolverRerunAuthorization(root, base.packet, receipt, "/private/authorization.json"), authorization);
    const artifact = { signer: ADDR.pool, decision_digest: base.packet.decision_digest };
    const signature = markResolverRerunSignature(root, base.packet, receipt, "/private/signature.json", artifact);
    assert.equal(markResolverRerunSignature(root, base.packet, receipt, "/private/signature.json", artifact), signature);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("expired empty attempts renew with tombstones but accepted attempts cannot renew", () => {
  const root = mkdtempSync(join(tmpdir(), "p42-resolver-renew-"));
  try {
    const base = fixture();
    const first = issueResolverRerunChallenge(root, base.packet, {
      now: VERIFY_NOW - 120_000, ttlMs: 60_000, randomBytes: () => Buffer.alloc(32, 0x11),
    });
    const renewed = issueResolverRerunChallenge(root, base.packet, {
      now: VERIFY_NOW, ttlMs: 60_000, randomBytes: () => Buffer.alloc(32, 0x22),
    });
    assert.notEqual(renewed.challenge.orchestrator_nonce, first.challenge.orchestrator_nonce);
    assert.equal(
      readFileSync(join(root, "rerun-tombstones", `${base.packet.packet_hash.slice(7)}-${first.challenge.orchestrator_nonce.slice(2)}.json`), "utf8").includes("expired-without-receipt"),
      true,
    );
    const receipt = signedRerunReceipt({
      packet: base.packet, publishedTranscript: base.publishedTranscript,
      localTranscript: base.localTranscript, challenge: renewed.challenge,
    });
    bindResolverRerunReceipt(root, base.packet, receipt);
    assert.throws(
      () => issueResolverRerunChallenge(root, base.packet, {
        now: VERIFY_NOW + 120_000, randomBytes: () => Buffer.alloc(32, 0x33),
      }),
      /cannot renew after receipt/,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("active preparation resumes the exact nonce and durable request after crashes", () => {
  const root = mkdtempSync(join(tmpdir(), "p42-resolver-prepare-resume-"));
  try {
    const base = fixture();
    const first = issueResolverRerunChallenge(root, base.packet, {
      now: VERIFY_NOW, ttlMs: 60_000, randomBytes: () => Buffer.alloc(32, 0x44),
      resumeActive: true,
    });
    const resumed = issueResolverRerunChallenge(root, base.packet, {
      now: VERIFY_NOW + 1_000, randomBytes: () => Buffer.alloc(32, 0x55),
      resumeActive: true,
    });
    assert.equal(resumed.resumed, true);
    assert.deepEqual(resumed.challenge, first.challenge);

    const requestValues = {
      packet: base.packet, challenge: first.challenge,
      boardId: "84532:1:hadamard-mini", manifestPath: "/opt/p42/release.json",
      publishedTranscript: base.publishedTranscript, manifestRoot: "/opt/p42",
      requestSignerPrivateKey: `0x${"42".repeat(32)}`,
    };
    const request = buildResolverRerunRequest({ ...requestValues, manifestBytes: Buffer.from("release-a") });
    const requestPath = persistResolverRerunRequest(root, base.packet, first.challenge, request);
    assert.equal(persistResolverRerunRequest(root, base.packet, resumed.challenge, request), requestPath);
    const substituted = buildResolverRerunRequest({ ...requestValues, manifestBytes: Buffer.from("release-b") });
    assert.throws(
      () => persistResolverRerunRequest(root, base.packet, resumed.challenge, substituted),
      /different content/,
    );
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("renewal resumes after a tombstone crash with one deterministic replacement intent", () => {
  const root = mkdtempSync(join(tmpdir(), "p42-resolver-renew-crash-"));
  try {
    const base = fixture();
    const first = issueResolverRerunChallenge(root, base.packet, {
      now: VERIFY_NOW - 120_000, ttlMs: 60_000, randomBytes: () => Buffer.alloc(32, 0x11),
    });
    assert.throws(() => issueResolverRerunChallenge(root, base.packet, {
      now: VERIFY_NOW, ttlMs: 60_000, randomBytes: () => Buffer.alloc(32, 0x22),
      crash(point) { if (point === "after-renewal-tombstone") throw new Error("injected tombstone crash"); },
    }), /injected tombstone crash/);
    const suffix = `${base.packet.packet_hash.slice(7)}-${first.challenge.orchestrator_nonce.slice(2)}.json`;
    const tombstonePath = join(root, "rerun-tombstones", suffix);
    const intentPath = join(root, "rerun-renewals", suffix);
    const tombstone = readFileSync(tombstonePath, "utf8");
    const intent = JSON.parse(readFileSync(intentPath, "utf8"));
    const resumed = issueResolverRerunChallenge(root, base.packet, {
      now: VERIFY_NOW + 30_000, ttlMs: 60_000, randomBytes: () => Buffer.alloc(32, 0x33),
    });
    assert.equal(resumed.challenge.orchestrator_nonce, intent.replacement_nonce);
    assert.equal(resumed.challenge.issued_at_utc, intent.replacement_issued_at_utc);
    assert.equal(readFileSync(tombstonePath, "utf8"), tombstone);
    assert.equal(JSON.parse(tombstone).superseded_at_utc, intent.superseded_at_utc);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("independent signer rejects a copied outcome whose local rerun report differs", () => {
  const { localTranscript } = fixture();
  const changed = report({ score: "4/1" });
  localTranscript.verifier.report = changed;
  localTranscript.verifier.report_hash = sha256Canonical(changed);
  delete localTranscript.transcript_hash;
  localTranscript.transcript_hash = sha256Canonical(localTranscript);
  assert.throws(() => verify({ localTranscript }), /VerdictReport does not match/);
});

test("independent signer binds the full chain claim and committed solution bytes", () => {
  const base = fixture();
  const changedClaim = structuredClone(base.localTranscript);
  changedClaim.verifier.chain_claim.solution_cid = "sha256:other";
  delete changedClaim.transcript_hash;
  changedClaim.transcript_hash = sha256Canonical(changedClaim);
  assert.throws(() => verify({ localTranscript: changedClaim }), /full chain claim does not match/);

  const changedDa = structuredClone(base.localTranscript);
  changedDa.da.observed_hash = SHA("6");
  delete changedDa.transcript_hash;
  changedDa.transcript_hash = sha256Canonical(changedDa);
  assert.throws(() => verify({ localTranscript: changedDa }), /DA observed_hash does not match/);
});

test("independent signer rejects packet, epoch, instance, and terminal-state substitution", () => {
  const base = fixture();
  const wrongOutcome = buildResolverQuorumDecisionPacket({
    ...base.packet.decision,
    transcriptURI: base.packet.transcript_uri,
    challengerWins: false,
  });
  assert.throws(() => verify({ packet: wrongOutcome }), /outcome does not match/);
  assert.throws(() => verify({ live: { ...base.live, signerEpoch: "4" } }), /epoch or threshold changed/);
  assert.throws(() => verify({ live: { ...base.live, challengeInstanceHash: HASH("7") } }), /challenge instance/);
  assert.throws(() => verify({ live: { ...base.live, decisionPending: true } }), /not signable/);
  assert.throws(() => verify({ live: { ...base.live, nonceUsed: true } }), /not signable/);
  assert.throws(
    () => verify({ live: { ...base.live, quorumBalanceWei: "4999999999999999" } }),
    /cannot cover the live decision bond/,
  );
  assert.throws(() => verify({ live: { ...base.live, finalizedTimestamp: 2_000_000_000 } }), /expired/);
});

test("independent signer comparison is stable under canonical serialization", () => {
  const checked = verify();
  assert.equal(canonicalJson(checked.local.report), canonicalJson(checked.published.report));
});

test("anti-equivocation journal permits identical retries and rejects changed semantics", () => {
  const root = mkdtempSync(join(tmpdir(), "p42-resolver-signer-"));
  try {
    const { packet, live, rerunReceipt } = fixture();
    const path = persistSignerAuthorization(root, packet, live, rerunReceipt);
    const original = readFileSync(path, "utf8");
    persistSignerAuthorization(root, packet, {
      ...live,
      finalizedBlockNumber: live.finalizedBlockNumber + 1,
      finalizedBlockHash: HASH("7"),
    }, rerunReceipt);
    assert.equal(readFileSync(path, "utf8"), original);

    const conflicting = buildResolverQuorumDecisionPacket({
      chainId: packet.decision.chainId,
      adapter: packet.decision.adapter,
      manager: packet.decision.manager,
      submissionId: packet.decision.submissionId,
      challengeInstanceHash: packet.decision.challengeInstanceHash,
      challengerWins: false,
      transcriptHash: packet.decision.transcriptHash,
      transcriptURI: packet.transcript_uri,
      verdictHash: packet.decision.verdictHash,
      expiry: packet.decision.expiry,
      signerEpoch: packet.decision.signerEpoch,
    });
    assert.throws(() => persistSignerAuthorization(root, conflicting, live, rerunReceipt), /different decision content/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("anti-equivocation journal atomically chooses one semantic decision across processes", async () => {
  const root = mkdtempSync(join(tmpdir(), "p42-resolver-signer-race-"));
  try {
    const { packet, live, rerunReceipt } = fixture();
    const conflicting = buildResolverQuorumDecisionPacket({
      chainId: packet.decision.chainId,
      adapter: packet.decision.adapter,
      manager: packet.decision.manager,
      submissionId: packet.decision.submissionId,
      challengeInstanceHash: packet.decision.challengeInstanceHash,
      challengerWins: false,
      transcriptHash: packet.decision.transcriptHash,
      transcriptURI: packet.transcript_uri,
      verdictHash: packet.decision.verdictHash,
      expiry: packet.decision.expiry,
      signerEpoch: packet.decision.signerEpoch,
    });
    const moduleUrl = new URL("./resolver-signer.mjs", import.meta.url).href;
    const script = `
      const { persistSignerAuthorization } = await import(${JSON.stringify(moduleUrl)});
      try {
        persistSignerAuthorization(process.argv[1], JSON.parse(Buffer.from(process.argv[2], "base64url")), JSON.parse(Buffer.from(process.argv[3], "base64url")), JSON.parse(Buffer.from(process.argv[4], "base64url")));
      } catch (error) {
        console.error(error.message);
        process.exitCode = 2;
      }
    `;
    const encode = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
    const run = (value) => new Promise((done) => {
      const child = spawn(process.execPath, ["--input-type=module", "-e", script, root, encode(value), encode(live), encode(rerunReceipt)], {
        stdio: ["ignore", "ignore", "pipe"],
      });
      let stderr = "";
      child.stderr.on("data", (chunk) => { stderr += chunk; });
      child.on("close", (status) => done({ status, stderr }));
    });
    const attempts = await Promise.all(Array.from({ length: 12 }, (_value, index) => run(index % 2 ? packet : conflicting)));
    assert.equal(attempts.filter(({ status }) => status === 0).length, 6);
    assert.equal(attempts.filter(({ status }) => status === 2).length, 6);
    for (const failed of attempts.filter(({ status }) => status === 2)) {
      assert.match(failed.stderr, /different decision content/);
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
