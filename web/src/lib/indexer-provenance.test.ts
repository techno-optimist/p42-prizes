import { mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { launchProblems, problems } from "@/lib/data";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import {
  activatedIndexerSnapshotFromArtifacts,
  activatedProvenanceFromArtifacts,
  computePortalDeploymentConfigHash,
  configuredIndexerArtifactPaths,
  loadIndexerProvenance,
} from "@/lib/indexer-provenance";

const root = resolve(process.cwd(), "..");
const boardKeys = ["pool", "ledger", "submissions", "challenges"] as const;
const created: string[] = [];

function clone<T>(value: T): T { return JSON.parse(JSON.stringify(value)) as T; }
function hash(char: string): string { return `0x${char.repeat(64)}`; }
function digest(char: string): string { return `sha256:${char.repeat(64)}`; }
function canonical(value: any): any { if (Array.isArray(value)) return value.map(canonical); if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])])); return value; }
function canonicalDigest(value: any): string { return `sha256:${createHash("sha256").update(JSON.stringify(canonical(value))).digest("hex")}`; }
function bytesDigest(value: any): string { return `sha256:${createHash("sha256").update(JSON.stringify(value)).digest("hex")}`; }

function artifacts() {
  // The v1 example supplies canonical contract/setup shapes; this promotes its
  // one board to the v2 topology without weakening either production schema.
  const base = JSON.parse(require("node:fs").readFileSync(
    join(root, "deployments/base-sepolia/p42-prizes.example.json"), "utf8",
  )) as Record<string, any>;
  const problem = clone(base.problems[0]);
  problem.contracts = Object.fromEntries(boardKeys.map((key) => [key, clone(base.contracts[key])]));
  problem.pool = problem.contracts.pool.address;
  problem.ledger = problem.contracts.ledger.address;
  problem.submissionManager = problem.contracts.submissions.address;
  problem.challengeManager = problem.contracts.challenges.address;
  for (const key of ["fundingCapWei", "onchainDa", "maxSolutionBytes", "earliestCloseTimestamp", "closeByTimestamp"]) problem[key] = base.parameters[key];
  problem.admissionMatrixDigest = `sha256:${"a".repeat(64)}`;
  problem.admissionMatrixHashAlgorithm = "keccak256-utf8/v1";
  problem.admissionMatrixHash = hash("a");
  problem.admissionMatrixURI = "ipfs://admission-matrix";
  problem.certifiedObjective = { seedBest: "1", direction: "minimize", minImprovement: "1" };
  problem.objectiveProgramVKey = hash("d");
  problem.objectiveGuestElfPath = "release/objective-program.bin";
  problem.objectiveGuestElfDigest = `sha256:${createHash("sha256").update("objective-program").digest("hex")}`;
  problem.objectiveGuestElfSha256 = `0x${problem.objectiveGuestElfDigest.slice("sha256:".length)}`;
  problem.objectivePackageHash = hash("e");
  base.schema = "p42-prizes/deployment-manifest/v2";
  base.roles.productionLaunchAuthority = `0x${"55".repeat(20)}`;
  base.roles.independentSecurityAuthority = `0x${"66".repeat(20)}`;
  base.roles.governanceAuthority = `0x${"77".repeat(20)}`;
  base.roles.objectiveVerifier = `0x${"44".repeat(20)}`;
  base.roles.objectiveVerifierCodehash = hash("f");
  base.releaseMode = "fixture";
  base.releaseEvidence = null;
  const sharedFixture = (entry: Record<string, any>, name: string, addressSuffix: string) => ({
    ...clone(entry), name, address: `0x${addressSuffix.padStart(40, "0")}`,
  });
  base.contracts = {
    timelock: base.contracts.timelock,
    registry: base.contracts.registry,
    rolloverVault: sharedFixture(base.contracts.registry, "P42RolloverVault", "f1"),
    submissionManagerFactory: sharedFixture(base.contracts.registry, "P42SubmissionManagerFactory", "f2"),
    challengeManagerFactory: sharedFixture(base.contracts.registry, "P42ChallengeManagerFactory", "f3"),
    objectiveVerifier: {
      ...sharedFixture(base.contracts.registry, "P42SP1VerifierGateway", "44".repeat(20)),
      runtimeCodeHash: base.roles.objectiveVerifierCodehash,
      deployedCodeHash: base.roles.objectiveVerifierCodehash,
      constructorArgs: [],
    },
    resolverQuorum: sharedFixture(base.contracts.registry, "P42ResolverQuorum", "f4"),
  };
  const allowedParameters = ["alphaBps", "betaBps", "challengeWindowSeconds", "feeBps", "minCounterBondWei", "minPostingBondWei", "rerunCostMultiplierBps", "rerunCostWei", "resolverDecisionBondWei", "resolverFraudWindowSeconds"];
  base.parameters = Object.fromEntries(allowedParameters.map((key) => [key, base.parameters[key]]));
  base.problems = [problem];
  base.sourceVerification.contracts = { timelock: null, registry: null, rolloverVault: null, submissionManagerFactory: null, challengeManagerFactory: null, objectiveVerifier: null, resolverQuorum: null, boards: [{ problemId: "1", pool: null, ledger: null, submissions: null, challenges: null }] };
  base.indexer.indexedThroughBlock = 100;
  base.deploymentConfigHash = computePortalDeploymentConfigHash(base);
  const contractBinding = (entry: Record<string, any>) => ({ address: entry.address, deployedCodeHash: entry.deployedCodeHash, abiHash: entry.abiHash });
  const checks = [{ name: "complete", ok: true, expected: true, actual: true }];
  const checkpoint = {
    schema: "p42-prizes/indexer-checkpoint/v2",
    manifestBinding: {
      deploymentCommit: base.deploymentCommit.toLowerCase(), deploymentConfigHash: base.deploymentConfigHash,
      chainId: 84532, startBlock: base.indexer.startBlock,
      contracts: Object.fromEntries(
        Object.keys(base.contracts).map((key) => [key, contractBinding(base.contracts[key])]),
      ),
      boards: { "1": Object.fromEntries(boardKeys.map((key) => [key, contractBinding(problem.contracts[key])])) },
    },
    finalityPolicy: clone(base.indexer.finalityPolicy),
    range: { fromBlock: base.indexer.startBlock, toBlock: 100, toBlockHash: hash("b"), toBlockTimestamp: Math.floor(Date.now() / 1000) },
    boards: [{
      problemId: "1", problemSlug: "hadamard-mini",
      events: { digest: hash("c"), total: 0, counts: { SubmissionCommitted: 0 }, lifecycleCountsComplete: true },
      onchain: { submissionCount: "0", openSubmissionCount: "0", bestScoreAtoms: "0", poolFirstFundedAt: "0", poolAcceptingFunds: false, fundingArmed: false, authorizedFundingDigest: hash("0"), fundingAuthorizationDigest: hash("0"), fundingAuthorizationExpiresAt: "0", ledgerPausedNewActions: false, submissionsPausedNewActions: false, submissionsPausedAll: false, submissionExpiryGraceUntil: "0", challengePausedNewActions: false, registryProblemCount: "1", registryFrozen: { "1": true } },
      state: {}, reconstruction: { ok: true, complete: true, lifecycleSnapshotComplete: true, checks },
    }],
    reconstruction: { ok: true, complete: true, checks: [{ ...checks[0], name: "board/1.complete" }] },
  };
  return { manifest: base, checkpoint };
}

function writeArtifacts(manifest: unknown, checkpoint: unknown) {
  const dir = mkdtempSync(join(tmpdir(), "p42-indexer-provenance-")); created.push(dir);
  const deploymentManifestPath = join(dir, "manifest.json");
  const indexerCheckpointPath = join(dir, "checkpoint.json");
  writeFileSync(deploymentManifestPath, JSON.stringify(manifest));
  writeFileSync(indexerCheckpointPath, JSON.stringify(checkpoint));
  return { deploymentManifestPath, indexerCheckpointPath };
}

function expectLocalOnly(result: ReturnType<typeof loadIndexerProvenance>) {
  expect(result).toMatchObject({ settlementState: "local-only", source: "static-portal-data", reconciliationOk: false, indexedThroughBlock: null, poolAddress: null });
}

afterEach(() => { for (const path of created.splice(0)) require("node:fs").rmSync(path, { recursive: true, force: true }); });

describe("indexer provenance v2", () => {
  it("reproduces the protocol deployment-config hash", () => {
    const manifest = JSON.parse(require("node:fs").readFileSync(
      join(root, "deployments/base-sepolia/p42-prizes.example.json"), "utf8",
    ));
    expect(computePortalDeploymentConfigHash(manifest)).toBe(manifest.deploymentConfigHash);
  });

  it("binds canonical release evidence and role acceptances into the deployment-config hash", () => {
    const { manifest } = artifacts();
    manifest.releaseMode = "production";
    manifest.releaseEvidence = { boardSetDigest: digest("1"), releaseBindingDigest: digest("2") };
    manifest.roleAcceptances = { packetDigest: digest("3") };
    const expected = computePortalDeploymentConfigHash(manifest);
    for (const field of ["releaseMode", "releaseEvidence", "roleAcceptances"]) {
      const changed = clone(manifest);
      changed[field] = field === "releaseMode" ? "fixture" : null;
      expect(computePortalDeploymentConfigHash(changed)).not.toBe(expected);
    }
  });

  it("keeps Render-bundled schemas byte-equivalent to canonical protocol schemas", () => {
    for (const name of ["deployment-manifest-v2.schema.json", "indexer-checkpoint-v2.schema.json", "indexer-checkpoint-v3.schema.json", "funding-activation-completion.schema.json"]) {
      const canonical = JSON.parse(require("node:fs").readFileSync(join(root, "schemas", name), "utf8"));
      const bundled = JSON.parse(require("node:fs").readFileSync(join(process.cwd(), "src", "schemas", name), "utf8"));
      expect(bundled).toEqual(canonical);
    }
  });

  it("loads only a fully bound, completely reconstructed board and keeps funding disabled", () => {
    const { manifest, checkpoint } = artifacts();
    const result = loadIndexerProvenance(problems[0], writeArtifacts(manifest, checkpoint));
    expect(result).toMatchObject({ source: "indexer-artifacts-v2", reconciliationOk: true, indexedFrontierAtoms: "0", checkpointBlock: 100, poolAddress: null, donationWalletAddress: null, deploymentTransactionHash: null });
  });

  it.each([
    ["commit", (m: any, c: any) => { c.manifestBinding.deploymentCommit = "f".repeat(40); }],
    ["config hash", (m: any, c: any) => { c.manifestBinding.deploymentConfigHash = hash("f"); }],
    ["finality", (m: any, c: any) => { c.finalityPolicy.confirmations += 1; }],
    ["board slug", (m: any, c: any) => { c.boards[0].problemSlug = "wrong"; }],
    ["contract ABI", (m: any, c: any) => { c.manifestBinding.boards["1"].pool.abiHash = hash("f"); }],
    ["manifest content with stale digest", (m: any) => { m.problems[0].metadataURI = "ipfs://relabeled"; }],
    ["impossible RFC 3339 date", (m: any) => { m.generatedAt = "2024-02-30T12:00:00Z"; }],
    ["frontier", (m: any) => { m.indexer.indexedThroughBlock = 99; }],
    ["malformed frontier atoms", (_m: any, c: any) => { c.boards[0].onchain.bestScoreAtoms = "1.5"; }],
  ])("fails closed on %s mismatch", (_name, mutate) => {
    const { manifest, checkpoint } = artifacts(); mutate(manifest, checkpoint);
    expectLocalOnly(loadIndexerProvenance(problems[0], writeArtifacts(manifest, checkpoint)));
  });

  it.each(["ok", "complete", "lifecycleSnapshotComplete"])("requires board reconstruction %s", (field) => {
    const { manifest, checkpoint } = artifacts(); (checkpoint.boards[0].reconstruction as any)[field] = false;
    expectLocalOnly(loadIndexerProvenance(problems[0], writeArtifacts(manifest, checkpoint)));
  });

  it("rejects malformed, oversized, extra-property, and symlink artifacts", () => {
    const { manifest, checkpoint } = artifacts();
    const malformed = writeArtifacts(manifest, checkpoint); writeFileSync(malformed.indexerCheckpointPath, "{");
    expectLocalOnly(loadIndexerProvenance(problems[0], malformed));
    const extra = artifacts(); (extra.checkpoint as Record<string, unknown>).unexpected = true;
    expectLocalOnly(loadIndexerProvenance(problems[0], writeArtifacts(extra.manifest, extra.checkpoint)));
    const large = writeArtifacts(manifest, checkpoint); writeFileSync(large.indexerCheckpointPath, " ".repeat(4 * 1024 * 1024 + 1));
    expectLocalOnly(loadIndexerProvenance(problems[0], large));
    const linked = writeArtifacts(manifest, checkpoint); const link = `${linked.indexerCheckpointPath}.link`; symlinkSync(linked.indexerCheckpointPath, link);
    expectLocalOnly(loadIndexerProvenance(problems[0], { ...linked, indexerCheckpointPath: link }));
  });

  it("requires both configured paths", () => {
    expect(configuredIndexerArtifactPaths({})).toBeNull();
    expect(configuredIndexerArtifactPaths({ P42_DEPLOYMENT_MANIFEST_PATH: "/m" })).toBeNull();
    expect(configuredIndexerArtifactPaths({ P42_DEPLOYMENT_MANIFEST_PATH: " /m ", P42_INDEXER_CHECKPOINT_PATH: " /c " })).toEqual({ deploymentManifestPath: "/m", indexerCheckpointPath: "/c" });
    expect(configuredIndexerArtifactPaths({
      P42_DEPLOYMENT_MANIFEST_PATH: "/m", P42_INDEXER_CHECKPOINT_PATH: "/c",
      P42_LAUNCH_AUTHORIZATION_PATH: "/a", P42_INDEXER_CHECKPOINT_ATTESTATION_PATH: "/ca",
      P42_FUNDING_ACTIVATION_PLAN_PATH: "/p", P42_FUNDING_ACTIVATION_COMPLETION_PATH: "/fc",
      P42_PORTAL_CHECKPOINT_MAX_AGE_SECONDS: "300",
      P42_ATTESTATION_TRUST_REGISTRY_PATH: "/caller/registry.json",
      P42_ATTESTATION_TRUST_REGISTRY_SHA256: digest("f"),
    })).toEqual({
      deploymentManifestPath: "/m", indexerCheckpointPath: "/c",
      launchAuthorizationPath: "/a", indexerCheckpointAttestationPath: "/ca",
      fundingActivationPlanPath: "/p", fundingActivationCompletionPath: "/fc",
      checkpointMaxAgeSeconds: 300,
    });
  });

  it("publishes a pool only when authorization, activation, and checkpoint agree", () => {
    const base = artifacts();
    const templateProblem = base.manifest.problems[0];
    const templateBoard = base.checkpoint.boards[0];
    const manifestProblems = launchProblems.map((portalProblem, index) => {
      const item = clone(templateProblem);
      item.problemId = String(index + 1); item.problemSlug = portalProblem.slug;
      for (const [offset, key] of boardKeys.entries()) {
        const address = `0x${(1000 + index * 4 + offset).toString(16).padStart(40, "0")}`;
        item.contracts[key].address = address;
      }
      item.pool = item.contracts.pool.address; item.ledger = item.contracts.ledger.address;
      item.submissionManager = item.contracts.submissions.address; item.challengeManager = item.contracts.challenges.address;
      return item;
    });
    expect(manifestProblems.map((item) => item.problemId)).toEqual(Array.from({ length: 10 }, (_, index) => String(index + 1)));
    expect(manifestProblems[0].problemSlug).toBe("q6-intersecting-hypergraph");
    expect(manifestProblems[6].problemSlug).toBe("distinct-subset-sums-a11");
    base.manifest.releaseMode = "production"; base.manifest.status = "governance-setup-complete";
    base.manifest.releaseEvidence = { releaseBindingDigest: digest("1") };
    base.manifest.problems = manifestProblems;
    base.manifest.deploymentConfigHash = computePortalDeploymentConfigHash(base.manifest);
    base.checkpoint.manifestBinding.deploymentConfigHash = base.manifest.deploymentConfigHash;
    base.checkpoint.manifestBinding.boards = Object.fromEntries(manifestProblems.map((item) => [item.problemId, Object.fromEntries(boardKeys.map((key) => [key, { address: item.contracts[key].address, deployedCodeHash: item.contracts[key].deployedCodeHash, abiHash: item.contracts[key].abiHash }]))]));
    const expires = 2_000_000_000; const issuedAt = new Date((expires - 1000) * 1000).toISOString();
    const roles = ["production-launch-authority", "independent-security-authority", "governance-authority"];
    const signers = roles.map((role, index) => {
      const pair = generateKeyPairSync("ed25519");
      const raw = pair.publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("hex");
      return { role, index, privateKey: pair.privateKey, publicKey: `ed25519:${raw}` };
    });
    const unsignedAuthorization = {
      schema_version: "p42-production-launch-authorization/v1", status: "authorized", issued_at_utc: issuedAt,
      expires_at_utc: new Date(expires * 1000).toISOString(), release_binding: { network: "base-sepolia", chain_id: 84532 },
      artifacts: { deployment_manifest: { sha256: bytesDigest(base.manifest) } },
      authorizers: signers.map(({ role, index, publicKey }) => ({ role, public_key: publicKey, name: `Signer ${index}`, organization: "P42 Test", professional_email: `signer${index}@example.org` })),
    };
    const authorizationDigest = canonicalDigest(unsignedAuthorization); const digestHex = `0x${authorizationDigest.slice(7)}`;
    base.checkpoint.boards = manifestProblems.map((item) => ({
      ...clone(templateBoard), problemId: item.problemId, problemSlug: item.problemSlug,
      onchain: { ...clone(templateBoard.onchain), poolAcceptingFunds: true, fundingArmed: true, authorizedFundingDigest: digestHex, fundingAuthorizationDigest: digestHex, fundingAuthorizationExpiresAt: String(expires) },
    }));
    base.checkpoint.schema = "p42-prizes/indexer-checkpoint/v3";
    const manifestBytes = Buffer.from(JSON.stringify(base.manifest));
    const authorization = { ...unsignedAuthorization, authorization_digest: authorizationDigest, authorization_signatures: signers.map(({ role, privateKey, publicKey }) => {
      const message = Buffer.from(`P42-ATTESTATION-V2\np42-production-launch-authorization/v1\n${role}\n${authorizationDigest}\n${issuedAt}`, "ascii");
      return { algorithm: "ed25519", signer_role: role, public_key: publicKey, signed_hash: authorizationDigest, signed_at_utc: issuedAt, signature: `ed25519:${sign(null, message, privateKey).toString("hex")}` };
    }) };
    const checkpointSigner = generateKeyPairSync("ed25519");
    const checkpointPublicKey = `ed25519:${checkpointSigner.publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("hex")}`;
    const checkpointSignedAt = new Date().toISOString();
    const trustRegistry = { schema_version: "p42-attestation-trust-registry/v1", environment: "production", registry_id: "portal-test", created_at_utc: "2026-01-01T00:00:00.000Z", registrations: [
      ...signers.map(({ role, index, publicKey }) => ({ attestation_class: "p42-production-launch-authorization/v1", signer_role: role, public_key: publicKey, identity: { name: `Signer ${index}`, organization: "P42 Test", professional_email: `signer${index}@example.org` }, valid_from_utc: new Date((expires - 1500) * 1000).toISOString(), valid_until_utc: null })),
      { attestation_class: "p42-indexer-checkpoint-attestation/v1", signer_role: "indexer-checkpoint-authority", public_key: checkpointPublicKey, identity: { name: "Indexer Signer", organization: "P42 Test", professional_email: "indexer@example.org" }, valid_from_utc: "2026-01-01T00:00:00.000Z", valid_until_utc: null },
    ] };
    const authorizationBytes = Buffer.from(JSON.stringify(authorization));
    const planBody = { schema: "p42-funding-activation-plan/v2", chainId: 84532, manifestBytesDigest: bytesDigest(base.manifest), authorizationDigest, authorizationBytesDigest: `sha256:${createHash("sha256").update(authorizationBytes).digest("hex")}`, authorizationExpiresAt: expires, activationSignaturesDigest: digest("7") };
    const plan = { ...planBody, planDigest: canonicalDigest(planBody) };
    const completionBody = {
      schema: "p42-funding-activation-completion/v1", chainId: 84532, network: "base-sepolia", planDigest: plan.planDigest,
      manifestBytesDigest: plan.manifestBytesDigest, deploymentCommit: base.manifest.deploymentCommit,
      deploymentConfigHash: base.manifest.deploymentConfigHash, releaseBindingDigest: digest("1"),
      authorizationDigest, authorizationBytesDigest: planBody.authorizationBytesDigest, authorizationExpiresAt: expires, finalizedBlockNumber: 99,
      finalizedBlockTimestamp: expires - 10,
      boards: manifestProblems.map((item) => ({ problemId: item.problemId, pool: item.contracts.pool.address, submissionManager: item.contracts.submissions.address, poolRuntimeCodeHash: item.contracts.pool.runtimeCodeHash, authorizedFundingDigest: digestHex, fundingAuthorizationDigest: digestHex, fundingAuthorizationExpiresAt: expires, fundingArmed: true, acceptingFunds: true })),
    };
    const completion = { ...completionBody, completionDigest: canonicalDigest(completionBody) };
    const trustRegistryDigest = canonicalDigest(trustRegistry);
    const productionPolicy = {
      schema_version: "p42-portal-production-trust-policy/v1", environment: "production",
      deployment_manifest: { sha256: `sha256:${createHash("sha256").update(manifestBytes).digest("hex")}` },
      launch_authorization: {
        sha256: `sha256:${createHash("sha256").update(authorizationBytes).digest("hex")}`,
        authorization_digest: authorizationDigest,
      },
      trust_registry: { path: "/etc/p42/attestation-trust-registry.json", sha256: trustRegistryDigest },
    };
    const checkpointBytes = Buffer.from(JSON.stringify(base.checkpoint));
    const checkpointDigest = `sha256:${createHash("sha256").update(checkpointBytes).digest("hex")}`;
    const checkpointMessage = Buffer.from(`P42-ATTESTATION-V2\np42-indexer-checkpoint-attestation/v1\nindexer-checkpoint-authority\n${checkpointDigest}\n${checkpointSignedAt}`, "ascii");
    const checkpointAttestation = { schema: "p42-indexer-checkpoint-attestation/v1", signerRole: "indexer-checkpoint-authority", publicKey: checkpointPublicKey, checkpointDigest, signedAtUtc: checkpointSignedAt, signature: `ed25519:${sign(null, checkpointMessage, checkpointSigner.privateKey).toString("hex")}` };
    const activatedArtifacts = {
      manifest: base.manifest, manifestBytes, checkpoint: base.checkpoint, checkpointBytes,
      authorization, authorizationBytes, productionPolicy, trustRegistry, checkpointAttestation, plan, completion,
    };
    const activatedSnapshot = activatedIndexerSnapshotFromArtifacts(launchProblems, activatedArtifacts);
    expect(activatedSnapshot.provenance).toHaveLength(10);
    const legacyPlan = clone(plan);
    legacyPlan.schema = "p42-funding-activation-plan/v1";
    const { planDigest: _legacyDigest, ...legacyPlanBody } = legacyPlan;
    legacyPlan.planDigest = canonicalDigest(legacyPlanBody);
    expect(() => activatedIndexerSnapshotFromArtifacts(launchProblems, {
      ...activatedArtifacts,
      plan: legacyPlan,
    })).toThrow();
    expect(() => activatedIndexerSnapshotFromArtifacts(launchProblems, {
      ...activatedArtifacts,
      nowSeconds: Number(base.checkpoint.range.toBlockTimestamp) + 301,
      checkpointMaxAgeSeconds: 300,
    })).toThrow();
    const partialCompletion = clone(completion);
    partialCompletion.boards.pop();
    expect(() => activatedIndexerSnapshotFromArtifacts(launchProblems, {
      ...activatedArtifacts,
      completion: partialCompletion,
    })).toThrow();
    const result = activatedProvenanceFromArtifacts(launchProblems[0], base.manifest, manifestBytes, base.checkpoint, checkpointBytes, authorization, authorizationBytes, productionPolicy, trustRegistry, checkpointAttestation, plan, completion);
    expect(result).toMatchObject({ settlementState: "testnet-indexed", poolAddress: manifestProblems[0].pool, fundingAuthorizationDigest: authorizationDigest, activationFinalizedBlock: 99 });
    const subsetSums = activatedProvenanceFromArtifacts(launchProblems[6], base.manifest, manifestBytes, base.checkpoint, checkpointBytes, authorization, authorizationBytes, productionPolicy, trustRegistry, checkpointAttestation, plan, completion);
    expect(subsetSums).toMatchObject({ settlementState: "testnet-indexed", poolAddress: manifestProblems[6].pool, problemRegistryId: "7" });
    for (const mutate of [
      (policy: any) => { policy.deployment_manifest.sha256 = digest("8"); },
      (policy: any) => { policy.launch_authorization.sha256 = digest("8"); },
      (policy: any) => { policy.launch_authorization.authorization_digest = digest("8"); },
      (policy: any) => { policy.trust_registry.sha256 = digest("8"); },
      (policy: any) => { policy.trust_registry.path = "/tmp/caller-registry.json"; },
    ]) {
      const changedPolicy = clone(productionPolicy); mutate(changedPolicy);
      expect(() => activatedProvenanceFromArtifacts(launchProblems[0], base.manifest, manifestBytes, base.checkpoint, checkpointBytes, authorization, authorizationBytes, changedPolicy, trustRegistry, checkpointAttestation, plan, completion)).toThrow();
    }
    base.checkpoint.boards[0].onchain.fundingAuthorizationDigest = hash("9");
    expect(() => activatedProvenanceFromArtifacts(launchProblems[0], base.manifest, manifestBytes, base.checkpoint, checkpointBytes, authorization, authorizationBytes, productionPolicy, trustRegistry, checkpointAttestation, plan, completion)).toThrow();
  });
});
