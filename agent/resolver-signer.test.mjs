import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { ethers } from "ethers";

import { canonicalJson, sha256Canonical, verifierImageHashForDigest, verifierSourceHashForDigest } from "./lib.mjs";
import { buildResolverVerdictHash } from "./resolver.mjs";
import { buildResolverQuorumDecisionPacket } from "./resolver-quorum.mjs";
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

function transcript({ generated = "2026-07-10T00:00:00Z", candidateValue = candidate(), reportValue = report() } = {}) {
  const value = {
    schema_version: "p42-runner-transcript/v1",
    job_id: `independent-${generated}`,
    generated_at_utc: generated,
    started_at_utc: generated,
    problem: "/repo/problems/hadamard-mini",
    solution: "/runtime/inputs/fixture.json",
    da: {
      ok: true,
      mode: "offchain-store",
      expected_hash: SHA("b"),
      observed_hash: SHA("b"),
      challengeable: false,
    },
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

function fixture() {
  const publishedTranscript = transcript();
  const challengeInstanceHash = HASH("9");
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
  return { packet, publishedTranscript, localTranscript: transcript({ generated: "2026-07-10T00:00:01Z" }), live };
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

test("independent signer accepts distinct transcript envelopes with identical exact evidence", () => {
  const checked = verify();
  assert.notEqual(checked.local.transcript.transcript_hash, checked.published.transcript.transcript_hash);
  assert.equal(checked.packet.decision.challengerWins, true);
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
    const { packet, live } = fixture();
    const path = persistSignerAuthorization(root, packet, live);
    const original = readFileSync(path, "utf8");
    persistSignerAuthorization(root, packet, {
      ...live,
      finalizedBlockNumber: live.finalizedBlockNumber + 1,
      finalizedBlockHash: HASH("7"),
    });
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
    assert.throws(() => persistSignerAuthorization(root, conflicting, live), /different decision content/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("anti-equivocation journal atomically chooses one semantic decision across processes", async () => {
  const root = mkdtempSync(join(tmpdir(), "p42-resolver-signer-race-"));
  try {
    const { packet, live } = fixture();
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
        persistSignerAuthorization(process.argv[1], JSON.parse(Buffer.from(process.argv[2], "base64url")), JSON.parse(Buffer.from(process.argv[3], "base64url")));
      } catch (error) {
        console.error(error.message);
        process.exitCode = 2;
      }
    `;
    const encode = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
    const run = (value) => new Promise((done) => {
      const child = spawn(process.execPath, ["--input-type=module", "-e", script, root, encode(value), encode(live)], {
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
