import assert from "node:assert/strict";
import { test } from "node:test";
import { ethers } from "ethers";

import {
  AUTHORIZATION_ROLE_SIGNATURE_SCHEMA,
  MANAGER_NONCE_EVIDENCE_SCHEMA,
  assembleFundingActivationSignatures,
  buildFundingAuthorizationRequestSet,
} from "./funding-authorization-signatures.mjs";

const hash = (char) => `sha256:${char.repeat(64)}`;
const address = (value) => ethers.getAddress(`0x${value.toString(16).padStart(40, "0")}`);
const authorityWallets = ["1", "2", "3"].map((char) => new ethers.Wallet(`0x${char.repeat(64)}`));

function manifest() {
  return {
    schema: "p42-prizes/deployment-manifest/v2",
    releaseMode: "production",
    status: "governance-setup-complete",
    network: { name: "baseSepolia", chainId: 84532 },
    deploymentCommit: "a".repeat(40),
    deploymentConfigHash: `0x${"b".repeat(64)}`,
    roles: {
      owner: address(1), treasury: address(2), productionLaunchAuthority: authorityWallets[0].address,
      independentSecurityAuthority: authorityWallets[1].address, governanceAuthority: authorityWallets[2].address,
    },
    governance: {
      signers: [address(3), address(4), address(5)], threshold: "2",
      delaySeconds: "3600", operationGracePeriodSeconds: "604800",
    },
    contracts: {
      timelock: { address: address(1), runtimeCodeHash: `0x${"1".repeat(64)}` },
      registry: { address: address(6) }, rolloverVault: { address: address(7) },
      submissionManagerFactory: { address: address(8) }, challengeManagerFactory: { address: address(9) },
      objectiveVerifier: { address: address(10) }, resolverQuorum: { address: address(11) },
    },
    releaseEvidence: {
      releaseBindingDigest: hash("1"), boardSetDigest: hash("0"), capsuleDigest: hash("2"),
      slateDigest: hash("3"), releaseIndexDigest: hash("4"),
    },
    problems: Array.from({ length: 10 }, (_, index) => ({
      problemId: index + 1,
      problemSlug: `problem-${index + 1}`,
      contracts: {
        pool: { address: address(100 + index * 4), runtimeCodeHash: `0x${"2".repeat(64)}` },
        ledger: { address: address(101 + index * 4) },
        submissions: { address: address(102 + index * 4), runtimeCodeHash: `0x${"3".repeat(64)}` },
        challenges: { address: address(103 + index * 4) },
      },
    })),
  };
}

function authorization(inputManifest) {
  return {
    schema_version: "p42-production-launch-authorization/v1",
    status: "authorized",
    authorization_digest: hash("a"),
    expires_at_utc: "2030-01-01T00:00:00Z",
    release_binding: { network: "base-sepolia", chain_id: 84532, git_commit: inputManifest.deploymentCommit },
    artifacts: { deployment_manifest: { sha256: hash("e") } },
  };
}

function nonceEvidence(inputManifest, { blockNumber = 100, timestamp = 1_800_000_000, nonce = 7n } = {}) {
  return {
    schema: MANAGER_NONCE_EVIDENCE_SCHEMA,
    chainId: inputManifest.network.chainId,
    finalizedBlockNumber: blockNumber,
    finalizedBlockHash: `0x${"f".repeat(64)}`,
    finalizedBlockTimestamp: timestamp,
    boards: inputManifest.problems.map((problem, boardIndex) => ({
      boardIndex,
      problemId: problem.problemId,
      submissionManager: problem.contracts.submissions.address,
      nonce: (nonce + BigInt(boardIndex)).toString(),
    })),
  };
}

function fixture() {
  const deployment = manifest();
  const validatedAuthorization = { value: authorization(deployment), validatedBytesDigest: hash("d") };
  const evidence = nonceEvidence(deployment);
  const requestSet = buildFundingAuthorizationRequestSet({
    manifest: deployment,
    manifestBytesDigest: hash("e"),
    validatedAuthorization,
    nonceEvidence: evidence,
    generation: evidence.finalizedBlockNumber,
    manifestValidator: () => ({}),
  });
  const artifacts = requestSet.requests.map((request, index) => ({
    schema: AUTHORIZATION_ROLE_SIGNATURE_SCHEMA,
    requestSetDigest: requestSet.requestSetDigest,
    requestId: request.requestId,
    generation: request.generation,
    requestExpiresAt: request.requestExpiresAt,
    boardIndex: request.boardIndex,
    submissionManager: request.submissionManager,
    role: request.role,
    signer: request.signer,
    signature: ethers.Signature.from(authorityWallets[index % 3].signingKey.sign(request.typedDataDigest)).serialized,
  }));
  const freshEvidence = nonceEvidence(deployment, { blockNumber: 101, timestamp: evidence.finalizedBlockTimestamp + 60 });
  return { deployment, validatedAuthorization, requestSet, artifacts, freshEvidence };
}

function assemble(input) {
  return assembleFundingActivationSignatures({
    manifest: input.deployment,
    manifestBytesDigest: hash("e"),
    validatedAuthorization: input.validatedAuthorization,
    requestSet: input.requestSet,
    roleArtifacts: input.artifacts,
    freshNonceEvidence: input.freshEvidence,
    manifestValidator: () => ({}),
  });
}

test("assembles the canonical ten-board 30-signature v2 bundle", () => {
  const input = fixture();
  const bundle = assemble(input);
  assert.equal(bundle.schema, "p42-funding-activation-signatures/v2");
  assert.equal(bundle.boards.length, 10);
  assert.equal(bundle.boards.flatMap((board) => board.signatures).length, 30);
  assert.deepEqual(bundle.boards.map((board) => board.nonce), input.requestSet.nonceEvidence.boards.map((board) => board.nonce));
});

test("rejects a substituted detached signature request", () => {
  const input = fixture();
  input.artifacts[0] = { ...input.artifacts[1], requestId: input.artifacts[0].requestId };
  assert.throws(() => assemble(input), /exact request identity/);
});

test("rejects a role swap even when the signature bytes are valid elsewhere", () => {
  const input = fixture();
  input.artifacts[0] = {
    ...input.artifacts[0],
    role: input.artifacts[1].role,
    signer: input.artifacts[1].signer,
    signature: input.artifacts[1].signature,
  };
  assert.throws(() => assemble(input), /exact request identity/);
});

test("rejects a request set after any manager nonce advances", () => {
  const input = fixture();
  input.freshEvidence.boards[6].nonce = (BigInt(input.freshEvidence.boards[6].nonce) + 1n).toString();
  assert.throws(() => assemble(input), /stale nonce for board 6/);
});

test("rejects a partial authority bundle", () => {
  const input = fixture();
  input.artifacts.pop();
  assert.throws(() => assemble(input), /exactly 30 role artifacts/);
});
