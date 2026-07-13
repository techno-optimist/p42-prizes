import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { ethers } from "ethers";

import {
  ROLE_ACCEPTANCE_POLICY_VERSION,
  ROLE_ACCEPTANCE_SCHEMA,
  ROLE_ACCEPTANCE_TYPES,
  deploymentTopologyDigest,
  expectedRoleAcceptances,
  roleAcceptanceDomain,
  roleAcceptanceMessage,
  roleAcceptancePacketDigest,
  validateDeploymentRoleAcceptances,
  validateDurableRoleAcceptanceTimestamp,
} from "../scripts/role-acceptance-helper.js";

const digest = (character) => `sha256:${character.repeat(64)}`;
const wallets = [1, 2, 3, 4, 5, 6].map((value) => new ethers.Wallet(`0x${value.toString(16).padStart(64, "0")}`));

function deployment(name, address, seed) {
  return { name, address, runtimeCodeHash: `0x${seed.toString(16).padStart(64, "0")}` };
}

function manifest() {
  const root = {
    timelock: deployment("P42MultisigTimelock", wallets[0].address, 1),
    registry: deployment("P42ProblemRegistry", "0x0000000000000000000000000000000000000102", 2),
    rolloverVault: deployment("P42RolloverVault", "0x0000000000000000000000000000000000000103", 3),
    submissionManagerFactory: deployment("P42SubmissionManagerFactory", "0x0000000000000000000000000000000000000104", 4),
    challengeManagerFactory: deployment("P42ChallengeManagerFactory", "0x0000000000000000000000000000000000000105", 5),
    objectiveVerifier: deployment("P42SP1VerifierGateway", "0x0000000000000000000000000000000000000106", 6),
    resolverQuorum: deployment("P42ResolverQuorum", "0x0000000000000000000000000000000000000107", 7),
  };
  return {
    schema: "p42-prizes/deployment-manifest/v2",
    releaseMode: "production",
    deploymentCommit: "a".repeat(40),
    network: { chainId: 84532 },
    governance: { signers: wallets.slice(0, 3).map((wallet) => wallet.address), guardian: wallets[3].address },
    roles: { treasury: wallets[4].address, resolver: wallets[5].address },
    contracts: root,
    releaseEvidence: { releaseBindingDigest: digest("1"), capsuleDigest: digest("2"), slateDigest: digest("3"), configDigest: digest("4") },
    problems: Array.from({ length: 10 }, (_, index) => {
      const problemId = String(index + 1);
      const base = 8 + index * 4;
      const names = { pool: "P42BountyPool", ledger: "P42PayoutLedger", submissions: "P42SubmissionManager", challenges: "P42ChallengeManager" };
      return {
        problemId,
        contracts: Object.fromEntries(["pool", "ledger", "submissions", "challenges"].map((key, offset) => [key, deployment(names[key], `0x${(1000 + base + offset).toString(16).padStart(40, "0")}`, base + offset)])),
      };
    }),
  };
}

async function signedPacket(source = manifest(), overrides = {}) {
  const packet = {
    schema: ROLE_ACCEPTANCE_SCHEMA,
    policyVersion: ROLE_ACCEPTANCE_POLICY_VERSION,
    chainId: source.network.chainId,
    releaseBindingDigest: source.releaseEvidence.releaseBindingDigest,
    capsuleDigest: source.releaseEvidence.capsuleDigest,
    slateDigest: source.releaseEvidence.slateDigest,
    configDigest: source.releaseEvidence.configDigest,
    deploymentCommit: source.deploymentCommit,
    timelock: source.contracts.timelock.address,
    topologyDigest: deploymentTopologyDigest(source),
    contractCount: 47,
    expiresAt: 2_000_000_000,
    acceptances: expectedRoleAcceptances(ethers, source).map((entry, index) => ({ ...entry, nonce: `0x${(index + 1).toString(16).padStart(64, "0")}`, riskAccepted: true, roleAccepted: true, signature: "" })),
    ...overrides,
  };
  for (const acceptance of packet.acceptances) {
    const wallet = wallets.find((candidate) => candidate.address === acceptance.address);
    acceptance.signature = await wallet.signTypedData(roleAcceptanceDomain(source), ROLE_ACCEPTANCE_TYPES, roleAcceptanceMessage(packet, acceptance));
  }
  packet.packetDigest = roleAcceptancePacketDigest(packet);
  return packet;
}

describe("deployment role acceptance", () => {
  it("verifies possession and explicit acceptance for the canonical 47-contract deployment", async () => {
    const source = manifest();
    const packet = await signedPacket(source);
    assert.equal(packet.acceptances.filter(({ role }) => role === "resolver-quorum-signer").length, 3);
    assert.equal(packet.acceptances.some(({ address }) => address.toLowerCase() === source.contracts.resolverQuorum.address.toLowerCase()), false);
    assert.equal(deploymentTopologyDigest(source), packet.topologyDigest);
    assert.equal(validateDeploymentRoleAcceptances(ethers, source, packet, { validationTime: 1_900_000_000 }), packet);
  });

  it("rejects omission, substitution, ordering changes, duplicate nonce, and expired packets", async () => {
    const source = manifest();
    const cases = [
      ["omitted", (packet) => packet.acceptances.pop(), /roster is incomplete/],
      ["substituted", (packet) => { packet.acceptances[0].role = "guardian"; }, /omitted, substituted, or out of canonical order/],
      ["reordered", (packet) => packet.acceptances.reverse(), /omitted, substituted, or out of canonical order/],
      ["replayed nonce", (packet) => { packet.acceptances[1].nonce = packet.acceptances[0].nonce; }, /nonce is invalid or replayed/],
    ];
    for (const [name, mutate, pattern] of cases) {
      const packet = await signedPacket(source);
      mutate(packet);
      packet.packetDigest = roleAcceptancePacketDigest(packet);
      assert.throws(() => validateDeploymentRoleAcceptances(ethers, source, packet, { validationTime: 1_900_000_000 }), pattern, name);
    }
    const expired = await signedPacket(source);
    assert.throws(() => validateDeploymentRoleAcceptances(ethers, source, expired, { validationTime: expired.expiresAt }), /expired or malformed at validation time/);
  });

  it("rejects replay across chain, release, config, timelock, and topology", async () => {
    const source = manifest();
    const packet = await signedPacket(source);
    const mutations = [
      ["chainId", (next) => { next.network.chainId += 1; }],
      ["release", (next) => { next.releaseEvidence.releaseBindingDigest = digest("5"); }],
      ["config", (next) => { next.releaseEvidence.configDigest = digest("6"); }],
      ["commit", (next) => { next.deploymentCommit = "b".repeat(40); }],
      ["timelock", (next) => { next.contracts.timelock.address = wallets[5].address; }],
      ["topology", (next) => { next.problems[0].contracts.pool.address = wallets[5].address; }],
    ];
    for (const [name, mutate] of mutations) {
      const next = structuredClone(source);
      mutate(next);
      assert.throws(() => validateDeploymentRoleAcceptances(ethers, next, packet, { validationTime: 1_900_000_000 }), /does not match deployment/, name);
    }
  });

  it("rejects a signature from an address that does not possess the configured key", async () => {
    const source = manifest();
    const packet = await signedPacket(source);
    packet.acceptances[0].signature = await wallets[5].signTypedData(roleAcceptanceDomain(source), ROLE_ACCEPTANCE_TYPES, roleAcceptanceMessage(packet, packet.acceptances[0]));
    packet.packetDigest = roleAcceptancePacketDigest(packet);
    assert.throws(() => validateDeploymentRoleAcceptances(ethers, source, packet, { validationTime: 1_900_000_000 }), /does not prove address possession/);
  });

  it("keeps a post-completion-expired packet valid at its durable validation time", async () => {
    const source = manifest();
    const packet = await signedPacket(source, { expiresAt: 1_900_000_100 });
    assert.equal(validateDeploymentRoleAcceptances(ethers, source, packet, { validationTime: 1_900_000_000 }), packet);
    assert.throws(() => validateDeploymentRoleAcceptances(ethers, source, packet, { validationTime: 2_100_000_000 }), /expired or malformed at validation time/);
  });

  it("rejects expiry at completion and a backdated durable validation timestamp", async () => {
    const source = manifest();
    const completionTime = 1_900_000_000;
    const packet = await signedPacket(source, { expiresAt: completionTime });
    assert.throws(() => validateDeploymentRoleAcceptances(ethers, source, packet, { validationTime: completionTime }), /expired or malformed at validation time/);
    assert.throws(
      () => validateDurableRoleAcceptanceTimestamp({ acceptanceValidatedAt: new Date((completionTime - 1) * 1000).toISOString(), completionBlockTimestamp: completionTime }, completionTime),
      /backdated or after finalized completion/,
    );
    assert.equal(validateDurableRoleAcceptanceTimestamp({ acceptanceValidatedAt: new Date(completionTime * 1000).toISOString(), completionBlockTimestamp: completionTime }, completionTime), completionTime);
  });
});
