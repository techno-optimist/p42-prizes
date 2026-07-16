import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import Ajv2020 from "ajv/dist/2020.js";

const load = (name) => JSON.parse(readFileSync(new URL(`../schemas/${name}`, import.meta.url), "utf8"));
const digest = (character = "a") => `sha256:${character.repeat(64)}`;
const address = (value) => `0x${value.toString(16).padStart(40, "0")}`;
const artifact = (name = "artifact") => ({
  uri: `ipfs://${name}`, local_path: `evidence/${name}.json`, sha256: digest("a"), created_at_utc: "2026-07-14T00:00:00Z",
});
const receipt = (value) => ({
  transaction_hash: `0x${value.repeat(64)}`, block_number: 10, block_hash: `0x${"b".repeat(64)}`, transaction_index: 0, status: 1,
});
const signature = (role = "engineering-owner") => ({
  algorithm: "ed25519", signer_role: role, public_key: `ed25519:${"c".repeat(64)}`,
  signed_hash: digest("d"), signed_at_utc: "2026-07-14T00:00:00Z", signature: `ed25519:${"e".repeat(128)}`,
});

function canonicalContracts() {
  const shared = [
    ["timelock", "P42MultisigTimelock"], ["registry", "P42ProblemRegistry"],
    ["rolloverVault", "P42RolloverVault"], ["submissionManagerFactory", "P42SubmissionManagerFactory"],
    ["challengeManagerFactory", "P42ChallengeManagerFactory"], ["objectiveVerifier", "P42SP1VerifierGateway"],
    ["resolverQuorum", "P42ResolverQuorum"],
  ].map(([key, name]) => [`shared.${key}`, name]);
  const boardNames = { pool: "P42BountyPool", ledger: "P42PayoutLedger", submissions: "P42SubmissionManager", challenges: "P42ChallengeManager" };
  const boards = Array.from({ length: 10 }, (_, index) => Object.entries(boardNames).map(([key, name]) => [`board.${index + 1}.${key}`, name])).flat();
  return [...shared, ...boards].map(([topology_key, name], index) => ({
    topology_key, name, address: address(index + 1), runtime_bytecode_hash: digest("f"),
    manifest_runtime_code_hash: `0x${"1".repeat(64)}`, source_artifact: artifact(`source-${index}`),
    runtime_bytecode_artifact: artifact(`runtime-${index}`), chain_bytecode_artifact: artifact(`chain-${index}`),
  }));
}

function launchV2() {
  return {
    schema_version: "p42-open-witness-launch/v2", evidence_id: "open-1", observed_at_utc: "2026-07-14T00:00:00Z",
    release_binding: {
      binding_version: "p42-release-binding/v2", repository_uri: "https://example.com/p42.git",
      git_commit: "1".repeat(40), deployment_commit: "2".repeat(40), network: "base-sepolia", chain_id: 84532,
      canonical_topology: artifact("topology"), release_capsule: artifact("release-capsule"),
      deployment_manifest: artifact("manifest"), configuration_artifact: artifact("configuration"),
      contracts: canonicalContracts(),
    },
    board: {
      registry_problem_id: "1", slug: "hadamard-mini", problem_registry: address(2), bounty_pool: address(8),
      payout_ledger: address(9), submission_manager: address(10), challenge_manager: address(11),
    },
    artifacts: {
      verifier_image: artifact("verifier"), admission_matrix: artifact("admission"), solution_payload: artifact("solution"),
      canonical_transcript: artifact("transcript"), canonical_report: artifact("report"),
    },
    witness: {
      witness_id: digest("1"), submission_id: 1, solver: address(100), solution_cid: "ipfs://solution",
      da_hash: digest("2"), verifier_image_hash: digest("3"), admission_matrix_hash: digest("4"),
      transcript_hash: digest("5"), report_hash: digest("6"), commit_receipt: receipt("1"),
      reveal_receipt: receipt("2"), finalize_receipt: receipt("3"), pre_frontier_atoms: 1,
      post_frontier_atoms: 1, credit_atoms: 0, funding_armed_at_commit: false,
    },
    funding: { arm_receipt: receipt("4"), paid_credit_atoms_before_arm: 0, pool_balance_before_arm_wei: 0 },
    reviewers: [{ name: "reviewer-a" }, { name: "reviewer-b" }],
    attestations: [signature("independent-reviewer"), signature()], evidence_hash: digest("7"),
    evidence_valid: true, attestation_valid: true, gate_passed: false,
  };
}

function historicalV1() {
  const legacyNames = ["P42BountyPool", "P42PayoutLedger", "P42SubmissionManager", "P42ChallengeManager", "P42ProblemRegistry"];
  const value = launchV2();
  value.schema_version = "p42-open-witness-launch/v1";
  value.release_binding = {
    repository_uri: "https://example.com/p42.git", git_commit: "1".repeat(40), network: "base-sepolia", chain_id: 84532,
    deployment_manifest: artifact("manifest"), configuration_artifact: artifact("configuration"),
    contracts: legacyNames.map((name, index) => ({
      name, address: address(index + 1), runtime_bytecode_hash: digest("f"), source_artifact: artifact(`legacy-source-${index}`),
      runtime_bytecode_artifact: artifact(`legacy-runtime-${index}`), chain_bytecode_artifact: artifact(`legacy-chain-${index}`),
    })),
  };
  value.board = {
    registry_problem_id: "1", slug: "hadamard-mini", problem_registry: address(5), bounty_pool: address(1), submission_manager: address(3),
  };
  return value;
}

function promotionV2() {
  const value = { ...launchV2(), gate_passed: true, collector_authoritative: true };
  const finalized = { blockNumber: 100, blockHash: `0x${"a".repeat(64)}` };
  const observations = ["a", "b", "c"].map((provider_id) => ({ provider_id, evidence_digest: digest("8"), evidence: {} }));
  const quorum = {
    schema_version: "p42-open-witness-quorum/v1", environment: "production", policy_digest: digest("1"),
    manifest_digest: digest("2"), launch_evidence_hash: digest("3"), evidence_digest: digest("4"),
    provider_ids: ["a", "b"], observation_transcript_digest: digest("5"), provider_observations: observations,
    finalized_evidence: finalized, evidence: {},
  };
  const authority_envelope = {
    schema_version: "p42-open-witness-collector-authority/v1", policy_digest: digest("1"), manifest_digest: digest("2"),
    launch_evidence_hash: digest("3"), evidence_digest: digest("4"), provider_ids: ["a", "b"],
    observation_transcript_digest: digest("5"), finalized_evidence: finalized, key_id: "collector-1",
    signed_at_utc: "2026-07-14T00:00:00Z", signature: `ed25519:${"e".repeat(128)}`,
  };
  value.collector_authority = {
    policy_digest: digest("1"), manifest_digest: digest("2"), quorum_digest: digest("6"), quorum,
    authority_envelope, registration_key_id: "collector-1",
  };
  return value;
}

describe("open-witness operational v2 schemas", () => {
  it("preserves historical v1 while preventing v1 launch evidence from satisfying operational v2", () => {
    const ajv = new Ajv2020({ strict: false, validateFormats: false });
    const adversarial = load("adversarial-campaign.schema.json");
    const historicalLaunch = load("open-witness-launch-v1.schema.json");
    const operationalLaunch = load("open-witness-launch.schema.json");
    const operationalPromotion = load("open-witness-promotion.schema.json");
    for (const schema of [adversarial, historicalLaunch, operationalLaunch, operationalPromotion]) ajv.addSchema(schema);

    const v1 = historicalV1();
    assert.equal(ajv.validate(historicalLaunch.$id, v1), true, JSON.stringify(ajv.errors));
    assert.equal(ajv.validate(operationalLaunch.$id, v1), false);
    assert.equal(ajv.validate(operationalPromotion.$id, { ...v1, collector_authoritative: true, gate_passed: true }), false);
    assert.equal(ajv.validate(operationalLaunch.$id, launchV2()), true, JSON.stringify(ajv.errors));
    assert.equal(ajv.validate(operationalPromotion.$id, promotionV2()), true, JSON.stringify(ajv.errors));
  });

  it("requires every canonical board slot in launch and promotion evidence", () => {
    const ajv = new Ajv2020({ strict: false, validateFormats: false });
    for (const name of ["adversarial-campaign.schema.json", "open-witness-launch.schema.json", "open-witness-promotion.schema.json"]) ajv.addSchema(load(name));
    for (const field of ["problem_registry", "bounty_pool", "payout_ledger", "submission_manager", "challenge_manager"]) {
      const launch = launchV2();
      delete launch.board[field];
      assert.equal(ajv.validate("https://p42.xyz/schemas/open-witness-launch-v2.json", launch), false, `${field} must be required by launch v2`);
      const promotion = promotionV2();
      delete promotion.board[field];
      assert.equal(ajv.validate("https://p42.xyz/schemas/open-witness-promotion-v2.json", promotion), false, `${field} must be required by promotion v2`);
    }
  });
});
