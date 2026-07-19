import { chmodSync, linkSync, mkdtempSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { launchProblems, problems } from "@/lib/data";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { AbiCoder, Interface, Signature, TypedDataEncoder, Wallet, getAddress, keccak256, toUtf8Bytes } from "ethers";
import {
  activatedIndexerSnapshotFromArtifacts,
  activatedProvenanceFromArtifacts,
  canonicalActivationRpcOrigin,
  computePortalDeploymentConfigHash,
  configuredIndexerArtifactPaths,
  loadProtectedActivationRpcOperatorRegistry,
  loadIndexerProvenance,
  portalRoleManifestBinding,
  portalRoleTopologyDigest,
  replayPortalRoleAcceptances,
  verifyPortalRoleArtifactBytes,
} from "@/lib/indexer-provenance";

const root = resolve(process.cwd(), "..");
const boardKeys = ["pool", "ledger", "submissions", "challenges"] as const;
const created: string[] = [];
const MAX_DNS_HOST = `${"a".repeat(63)}.${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(61)}`;
const OVERLONG_DNS_HOST = `${"a".repeat(63)}.${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(62)}`;
const WHATWG_IPV4_ALIASES = [
  ["127.0.0.1", "127.0.0.1"], ["127.1", "127.0.0.1"], ["127.0.1", "127.0.0.1"],
  ["2130706433", "127.0.0.1"], ["0x7f000001", "127.0.0.1"], ["017700000001", "127.0.0.1"],
  ["0x7f.0.0.1", "127.0.0.1"], ["127.0x0.0.1", "127.0.0.1"], ["0177.0.0.1", "127.0.0.1"],
  ["127.0.65535", "127.0.255.255"], ["127.16777215", "127.255.255.255"],
  ["1.2.65535", "1.2.255.255"], ["0xffffffff", "255.255.255.255"],
  ["0300.0250.0001.0001", "192.168.1.1"],
] as const;
const SAFE_DNS_HOSTS = ["127.0.0.1.example", "0x7f.rpc.example", "127.0x0.0.1.example", "123.example"] as const;

function clone<T>(value: T): T { return JSON.parse(JSON.stringify(value)) as T; }
function hash(char: string): string { return `0x${char.repeat(64)}`; }
function digest(char: string): string { return `sha256:${char.repeat(64)}`; }
function canonical(value: any): any { if (Array.isArray(value)) return value.map(canonical); if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])])); return value; }
function canonicalDigest(value: any): string { return `sha256:${createHash("sha256").update(JSON.stringify(canonical(value))).digest("hex")}`; }
function bytesDigest(value: any): string { return `sha256:${createHash("sha256").update(JSON.stringify(value)).digest("hex")}`; }

const roleTypes = { RoleAcceptance: [
  { name: "requestSetDigest", type: "string" }, { name: "requestSetNonce", type: "bytes32" }, { name: "pendingManifestBytesDigest", type: "string" }, { name: "manifestBindingDigest", type: "string" }, { name: "releaseBindingDigest", type: "string" }, { name: "capsuleBytesDigest", type: "string" }, { name: "capsuleDigest", type: "string" }, { name: "expectedExplorerDossierDigest", type: "string" }, { name: "slateDigest", type: "string" }, { name: "configDigest", type: "string" }, { name: "deploymentCommit", type: "string" }, { name: "topologyDigest", type: "string" }, { name: "role", type: "string" }, { name: "account", type: "address" }, { name: "policyVersion", type: "string" }, { name: "expiresAt", type: "uint64" }, { name: "nonce", type: "bytes32" }, { name: "riskAccepted", type: "bool" }, { name: "roleAccepted", type: "bool" },
] };

function attachCompletedRolePacket(manifest: Record<string, any>, options: {
  fundingWallets?: any[];
  pendingManifestBytesDigest?: string;
  capsuleBytesDigest?: string;
  capsuleDigest?: string;
} = {}): { wallets: any[] } {
  const baseWallets = Array.from({ length: 10 }, (_, index) => new Wallet(`0x${(index + 1).toString(16).padStart(64, "0")}`));
  const fundingWallets = options.fundingWallets ?? baseWallets.slice(7, 10);
  const wallets = [...baseWallets.slice(0, 7), ...fundingWallets];
  manifest.releaseMode = "production"; manifest.status = "governance-setup-complete";
  manifest.governance.signers = wallets.slice(0, 5).map(({ address }) => address); manifest.governance.guardian = wallets[5].address;
  manifest.roles.treasury = wallets[6].address; manifest.roles.productionLaunchAuthority = wallets[7].address; manifest.roles.independentSecurityAuthority = wallets[8].address; manifest.roles.governanceAuthority = wallets[9].address;
  manifest.releaseEvidence = { ...(manifest.releaseEvidence ?? {}), releaseBindingDigest: digest("1"), capsuleDigest: options.capsuleDigest ?? digest("2"), slateDigest: digest("3"), configDigest: digest("4") };
  manifest.sourceVerification = { ...(manifest.sourceVerification ?? {}), status: "verified", dossierDigest: digest("5") };
  const completion = 1_900_000_000; manifest.governanceSetup = { ...(manifest.governanceSetup ?? {}), status: "complete", acceptanceValidatedAt: new Date(completion * 1000).toISOString(), completionBlockTimestamp: completion, roleAcceptancePacketBytesDigest: digest("6") };
  const common = { policyVersion: "p42-governance-role-policy/v2", chainId: 84532, requestSetNonce: hash("a"), requestSetDigest: digest("7"), pendingManifestBytesDigest: options.pendingManifestBytesDigest ?? digest("8"), manifestBindingDigest: portalRoleManifestBinding(manifest), releaseBindingDigest: manifest.releaseEvidence.releaseBindingDigest, capsuleBytesDigest: options.capsuleBytesDigest ?? digest("9"), capsuleDigest: manifest.releaseEvidence.capsuleDigest, expectedExplorerDossierDigest: manifest.sourceVerification.dossierDigest, slateDigest: manifest.releaseEvidence.slateDigest, configDigest: manifest.releaseEvidence.configDigest, deploymentCommit: manifest.deploymentCommit, timelock: getAddress(manifest.contracts.timelock.address), topologyDigest: portalRoleTopologyDigest(manifest), contractCount: 47, expiresAt: completion + 1000 };
  const roster = [...wallets.slice(0, 5).map((wallet) => ({ role: "timelock-signer", wallet })), { role: "guardian", wallet: wallets[5] }, { role: "treasury", wallet: wallets[6] }, { role: "production-launch-authority", wallet: wallets[7] }, { role: "independent-security-authority", wallet: wallets[8] }, { role: "governance-authority", wallet: wallets[9] }, ...wallets.slice(0, 5).map((wallet) => ({ role: "resolver-quorum-signer", wallet }))].sort((a, b) => ["timelock-signer", "guardian", "treasury", "production-launch-authority", "independent-security-authority", "governance-authority", "resolver-quorum-signer"].indexOf(a.role) - ["timelock-signer", "guardian", "treasury", "production-launch-authority", "independent-security-authority", "governance-authority", "resolver-quorum-signer"].indexOf(b.role) || a.wallet.address.toLowerCase().localeCompare(b.wallet.address.toLowerCase()));
  const domain = { name: "P42 Deployment Role Acceptance", version: "2", chainId: 84532, verifyingContract: common.timelock };
  const acceptances = roster.map(({ role, wallet }, index) => {
    const acceptance = { role, address: wallet.address, nonce: `0x${(index + 1).toString(16).padStart(64, "0")}`, riskAccepted: true, roleAccepted: true };
    const message = { requestSetDigest: common.requestSetDigest, requestSetNonce: common.requestSetNonce, pendingManifestBytesDigest: common.pendingManifestBytesDigest, manifestBindingDigest: common.manifestBindingDigest, releaseBindingDigest: common.releaseBindingDigest, capsuleBytesDigest: common.capsuleBytesDigest, capsuleDigest: common.capsuleDigest, expectedExplorerDossierDigest: common.expectedExplorerDossierDigest, slateDigest: common.slateDigest, configDigest: common.configDigest, deploymentCommit: common.deploymentCommit, topologyDigest: common.topologyDigest, role, account: wallet.address, policyVersion: common.policyVersion, expiresAt: common.expiresAt, nonce: acceptance.nonce, riskAccepted: true, roleAccepted: true };
    return { ...acceptance, signature: wallet.signingKey.sign(TypedDataEncoder.hash(domain, roleTypes, message)).serialized };
  });
  const body = { schema: "p42-prizes/deployment-role-acceptance/v2", ...common, acceptances }; manifest.roleAcceptances = { ...body, packetDigest: canonicalDigest(body) };
  return { wallets };
}

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

function roleArtifactFixture({ capsuleDigestOverride }: { capsuleDigestOverride?: string } = {}) {
  const { manifest } = artifacts();
  manifest.problems = Array.from({ length: 10 }, (_, index) => {
    const problem = clone(manifest.problems[0]); problem.problemId = String(index + 1);
    for (const [offset, key] of boardKeys.entries()) problem.contracts[key].address = `0x${(1000 + index * 4 + offset).toString(16).padStart(40, "0")}`;
    return problem;
  });
  attachCompletedRolePacket(manifest);
  const pending = clone(manifest);
  pending.status = "pending-governance-setup";
  pending.governanceSetup = { status: "pending", completedAt: null, completionBlock: null, checks: [] };
  delete pending.roleAcceptances;
  pending.sourceVerification = { ...pending.sourceVerification, status: "pending", dossierDigest: null };

  const capsuleBody = { schema: "p42-prizes/release-capsule/v1", gitCommit: manifest.deploymentCommit, contracts: [] };
  const capsuleDigest = capsuleDigestOverride ?? canonicalDigest(capsuleBody);
  const capsule = { ...capsuleBody, capsuleDigest };
  const capsuleBytes = Buffer.from(`${JSON.stringify(capsule)}\n`);
  pending.releaseEvidence.capsuleDigest = capsuleDigest;
  const pendingBytes = Buffer.from(`${JSON.stringify(pending)}\n`);
  attachCompletedRolePacket(manifest, {
    pendingManifestBytesDigest: `sha256:${createHash("sha256").update(pendingBytes).digest("hex")}`,
    capsuleBytesDigest: `sha256:${createHash("sha256").update(capsuleBytes).digest("hex")}`,
    capsuleDigest,
  });

  const directory = realpathSync(mkdtempSync(join(tmpdir(), "p42-role-artifacts-"))); created.push(directory); chmodSync(directory, 0o700);
  const writeProtected = (name: string, bytes: Buffer) => {
    const path = join(directory, name); writeFileSync(path, bytes); chmodSync(path, 0o400);
    return { path, sha256: `sha256:${createHash("sha256").update(bytes).digest("hex")}` };
  };
  const packetBytes = Buffer.from(`${JSON.stringify(manifest.roleAcceptances)}\n`);
  const packetFile = writeProtected("packet.json", packetBytes);
  const pendingFile = writeProtected("pending.json", pendingBytes);
  const capsuleFile = writeProtected("capsule.json", capsuleBytes);
  manifest.governanceSetup.roleAcceptancePacketBytesDigest = packetFile.sha256;
  const paths = {
    deploymentManifestPath: "/unused/manifest.json", indexerCheckpointPath: "/unused/checkpoint.json",
    roleAcceptancePacketPath: packetFile.path, roleAcceptancePacketSha256: packetFile.sha256,
    roleAcceptancePendingManifestPath: pendingFile.path, roleAcceptancePendingManifestSha256: pendingFile.sha256,
    roleAcceptanceCapsulePath: capsuleFile.path, roleAcceptanceCapsuleSha256: capsuleFile.sha256,
  };
  return { manifest, pending, capsule, paths, directory };
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

describe("activation RPC authority primitives", () => {
  it.each([
    "https://rpc.example/", "https://RPC.example", "https://rpc.example:443",
    "https://rpc.example:0", "https://rpc.example:65536", "https://rpc.example:99999",
    "https://rpc.example:01", "https://127.0.0.1", "https://127.1", "https://2130706433",
    "https://0x7f000001", "https://0177.0.0.1", "https://%72pc.example",
    "https://user@rpc.example", "https://rpc.example?x=1", "https://rpc.example#x",
    `https://${OVERLONG_DNS_HOST}`, `https://${"a".repeat(64)}.example`,
    `https://${Array(5).fill("a".repeat(63)).join(".")}`,
  ])("rejects noncanonical origin %s", (origin) => {
    expect(() => canonicalActivationRpcOrigin(origin)).toThrow();
  });

  it.each(["https://rpc.example", "https://rpc.example:1", "https://rpc.example:65535", `https://${MAX_DNS_HOST}:65535`])(
    "accepts canonical origin %s", (origin) => expect(canonicalActivationRpcOrigin(origin)).toBe(origin),
  );

  it("rejects the WHATWG IPv4 numeric-alias corpus while preserving numeric-looking DNS names", () => {
    for (const [rawHost, normalizedHost] of WHATWG_IPV4_ALIASES) {
      expect(new URL(`https://${rawHost}`).hostname).toBe(normalizedHost);
      expect(() => canonicalActivationRpcOrigin(`https://${rawHost}`)).toThrow();
    }
    for (const host of SAFE_DNS_HOSTS) {
      expect(new URL(`https://${host}`).hostname).toBe(host);
      expect(canonicalActivationRpcOrigin(`https://${host}`)).toBe(`https://${host}`);
    }
  });

  it("keeps registry schema hostname and port boundaries aligned with runtime", () => {
    const schema = JSON.parse(require("node:fs").readFileSync(
      join(root, "schemas", "activation-rpc-operator-registry.schema.json"), "utf8",
    ));
    const endpoint = schema.properties.profiles.items.properties.endpointOrigin;
    const pattern = new RegExp(endpoint.pattern);
    const accepts = (value: string) => value.length <= endpoint.maxLength && pattern.test(value);
    for (const value of ["https://rpc.example", "https://rpc.example:1", `https://${MAX_DNS_HOST}:65535`, ...SAFE_DNS_HOSTS.map((host) => `https://${host}`)]) expect(accepts(value)).toBe(true);
    for (const value of [
      "https://127.0.0.1", "https://127.1", "https://0177.0.0.1",
      `https://${OVERLONG_DNS_HOST}`, `https://${"a".repeat(64)}.example`,
      `https://${Array(5).fill("a".repeat(63)).join(".")}`,
      "https://rpc.example:0", "https://rpc.example:443", "https://rpc.example:65536",
      ...WHATWG_IPV4_ALIASES.map(([host]) => `https://${host}`),
    ]) expect(accepts(value)).toBe(false);
  });

  it("loads only an exact private protected registry", () => {
    const profile = (operatorId: string, endpointOrigin: string) => ({
      operatorId, endpointOrigin, endpointProfileDigest: canonicalDigest({ operatorId, endpointOrigin }),
    });
    const registry = { schema: "p42-activation-rpc-operator-registry/v1", profiles: [
      profile("operator-primary", "https://primary.example"),
      profile("operator-secondary", "https://secondary.example"),
    ] };
    const bytes = Buffer.from(`${JSON.stringify(canonical(registry))}\n`);
    const registryDigest = `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
    const make = (name: string, mode = 0o400, content = bytes) => {
      const root = mkdtempSync(join(tmpdir(), `p42-web-rpc-${name}-`)); created.push(root); chmodSync(root, 0o700);
      const path = join(root, "registry.json"); writeFileSync(path, content); chmodSync(path, mode);
      return { root, path, digest: `sha256:${createHash("sha256").update(content).digest("hex")}` };
    };
    for (const mode of [0o400, 0o444]) {
      const good = make(`good-${mode}`, mode);
      expect(loadProtectedActivationRpcOperatorRegistry(good.path, good.root, registryDigest)).toEqual(registry);
    }
    const good = make("good");
    expect(() => loadProtectedActivationRpcOperatorRegistry(join(good.root, "missing.json"), good.root, registryDigest)).toThrow();
    const writableFile = make("writable-file", 0o600);
    expect(() => loadProtectedActivationRpcOperatorRegistry(writableFile.path, writableFile.root, writableFile.digest)).toThrow();
    for (const [name, content] of [
      ["pretty", Buffer.from(`${JSON.stringify(registry, null, 2)}\n`)],
      ["key-order", Buffer.from(`${JSON.stringify(registry)}\n`)],
      ["no-newline", Buffer.from(JSON.stringify(canonical(registry)))],
      ["double-newline", Buffer.from(`${JSON.stringify(canonical(registry))}\n\n`)],
      ["trailing-space", Buffer.from(`${JSON.stringify(canonical(registry))} \n`)],
    ] as const) {
      const noncanonical = make(name, 0o400, content);
      expect(() => loadProtectedActivationRpcOperatorRegistry(noncanonical.path, noncanonical.root, noncanonical.digest)).toThrow();
    }
    const writable = make("writable"); chmodSync(writable.root, 0o720);
    expect(() => loadProtectedActivationRpcOperatorRegistry(writable.path, writable.root, registryDigest)).toThrow();
    const hard = make("hard"); linkSync(hard.path, join(hard.root, "alias.json"));
    expect(() => loadProtectedActivationRpcOperatorRegistry(hard.path, hard.root, registryDigest)).toThrow();
    const linked = make("symlink"); const link = join(linked.root, "link.json"); symlinkSync(linked.path, link);
    expect(() => loadProtectedActivationRpcOperatorRegistry(link, linked.root, registryDigest)).toThrow();
    expect(() => loadProtectedActivationRpcOperatorRegistry(good.path, good.root, digest("0"))).toThrow();
  });
});

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
    for (const name of ["activation-rpc-operator-registry.schema.json", "deployment-manifest-v2.schema.json", "indexer-checkpoint-v2.schema.json", "indexer-checkpoint-v3.schema.json", "indexer-checkpoint-v4.schema.json", "funding-activation-completion.schema.json"]) {
      const canonical = require("node:fs").readFileSync(join(root, "schemas", name));
      const bundled = require("node:fs").readFileSync(join(process.cwd(), "src", "schemas", name));
      expect(bundled.equals(canonical)).toBe(true);
    }
  });

  it("cryptographically replays a completed v2 role packet and rejects schema-valid forgery", () => {
    const { manifest } = artifacts();
    manifest.problems = Array.from({ length: 10 }, (_, index) => { const problem = clone(manifest.problems[0]); problem.problemId = String(index + 1); for (const [offset, key] of boardKeys.entries()) problem.contracts[key].address = `0x${(1000 + index * 4 + offset).toString(16).padStart(40, "0")}`; return problem; });
    attachCompletedRolePacket(manifest);
    expect(() => replayPortalRoleAcceptances(manifest)).not.toThrow();
    const forged = clone(manifest); forged.roleAcceptances.acceptances[0].signature = forged.roleAcceptances.acceptances[1].signature;
    const { packetDigest: _ignored, ...forgedBody } = forged.roleAcceptances; forged.roleAcceptances.packetDigest = canonicalDigest(forgedBody);
    expect(() => replayPortalRoleAcceptances(forged)).toThrow();
    const crossRole = clone(manifest); [crossRole.roleAcceptances.acceptances[0], crossRole.roleAcceptances.acceptances[5]] = [crossRole.roleAcceptances.acceptances[5], crossRole.roleAcceptances.acceptances[0]];
    const { packetDigest: _crossIgnored, ...crossBody } = crossRole.roleAcceptances; crossRole.roleAcceptances.packetDigest = canonicalDigest(crossBody);
    expect(() => replayPortalRoleAcceptances(crossRole)).toThrow();
  });

  it("requires protected independently pinned role artifacts for completed production manifests", () => {
    const { manifest, paths } = roleArtifactFixture();
    expect(() => verifyPortalRoleArtifactBytes(manifest, paths)).not.toThrow();
    expect(() => verifyPortalRoleArtifactBytes(manifest, {
      deploymentManifestPath: paths.deploymentManifestPath,
      indexerCheckpointPath: paths.indexerCheckpointPath,
    })).toThrow();

    const fixture = artifacts();
    expect(() => verifyPortalRoleArtifactBytes(fixture.manifest, {
      deploymentManifestPath: "/fixture/manifest.json", indexerCheckpointPath: "/fixture/checkpoint.json",
    })).not.toThrow();
  });

  it("rejects reserialized and substituted exact role artifacts", () => {
    const { manifest, pending, capsule, paths, directory } = roleArtifactFixture();
    const variant = (name: string, value: unknown, pretty = false) => {
      const bytes = Buffer.from(`${JSON.stringify(value, null, pretty ? 2 : undefined)}\n`);
      const path = join(directory, name); writeFileSync(path, bytes); chmodSync(path, 0o400);
      return { path, sha256: `sha256:${createHash("sha256").update(bytes).digest("hex")}` };
    };

    const reserializedPacket = variant("packet-pretty.json", manifest.roleAcceptances, true);
    expect(() => verifyPortalRoleArtifactBytes(manifest, {
      ...paths, roleAcceptancePacketPath: reserializedPacket.path,
    })).toThrow();

    const substitutedPacketValue = clone(manifest.roleAcceptances);
    substitutedPacketValue.requestSetDigest = digest("f");
    const substitutedPacket = variant("packet-substituted.json", substitutedPacketValue);
    const substitutedManifest = clone(manifest);
    substitutedManifest.governanceSetup.roleAcceptancePacketBytesDigest = substitutedPacket.sha256;
    expect(() => verifyPortalRoleArtifactBytes(substitutedManifest, {
      ...paths, roleAcceptancePacketPath: substitutedPacket.path, roleAcceptancePacketSha256: substitutedPacket.sha256,
    })).toThrow();

    const substitutedPending = variant("pending-substituted.json", { ...pending, deploymentCommit: "f".repeat(40) });
    expect(() => verifyPortalRoleArtifactBytes(manifest, {
      ...paths, roleAcceptancePendingManifestPath: substitutedPending.path, roleAcceptancePendingManifestSha256: substitutedPending.sha256,
    })).toThrow();

    const reserializedCapsule = variant("capsule-pretty.json", capsule, true);
    expect(() => verifyPortalRoleArtifactBytes(manifest, {
      ...paths, roleAcceptanceCapsulePath: reserializedCapsule.path, roleAcceptanceCapsuleSha256: reserializedCapsule.sha256,
    })).toThrow();
  });

  it("rejects a byte-pinned capsule with a false canonical digest and unsafe artifact paths", () => {
    const invalid = roleArtifactFixture({ capsuleDigestOverride: digest("f") });
    expect(() => verifyPortalRoleArtifactBytes(invalid.manifest, invalid.paths)).toThrow();

    const valid = roleArtifactFixture();
    expect(() => verifyPortalRoleArtifactBytes(valid.manifest, {
      ...valid.paths, roleAcceptancePacketPath: "relative-packet.json",
    })).toThrow();
    chmodSync(valid.paths.roleAcceptancePacketPath, 0o600);
    expect(() => verifyPortalRoleArtifactBytes(valid.manifest, valid.paths)).toThrow();
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
      P42_ROLE_ACCEPTANCE_PACKET_PATH: " /role/packet.json ", P42_ROLE_ACCEPTANCE_PACKET_SHA256: digest("1"),
      P42_ROLE_ACCEPTANCE_PENDING_MANIFEST_PATH: "/role/pending.json", P42_ROLE_ACCEPTANCE_PENDING_MANIFEST_SHA256: digest("2"),
      P42_ROLE_ACCEPTANCE_CAPSULE_PATH: "/role/capsule.json", P42_ROLE_ACCEPTANCE_CAPSULE_SHA256: digest("3"),
    })).toEqual({
      deploymentManifestPath: "/m", indexerCheckpointPath: "/c",
      roleAcceptancePacketPath: "/role/packet.json", roleAcceptancePacketSha256: digest("1"),
      roleAcceptancePendingManifestPath: "/role/pending.json", roleAcceptancePendingManifestSha256: digest("2"),
      roleAcceptanceCapsulePath: "/role/capsule.json", roleAcceptanceCapsuleSha256: digest("3"),
    });
    expect(configuredIndexerArtifactPaths({
      P42_DEPLOYMENT_MANIFEST_PATH: "/m", P42_INDEXER_CHECKPOINT_PATH: "/c",
      P42_LAUNCH_AUTHORIZATION_PATH: "/a", P42_INDEXER_CHECKPOINT_ATTESTATION_PATH: "/ca",
      P42_FUNDING_ACTIVATION_PLAN_PATH: "/p", P42_FUNDING_ACTIVATION_SIGNATURES_PATH: "/fs", P42_FUNDING_ACTIVATION_COMPLETION_PATH: "/fc",
      P42_ACTIVATION_RPC_OPERATOR_REGISTRY_PATH: "/r/registry.json", P42_ACTIVATION_RPC_OPERATOR_REGISTRY_TRUSTED_ROOT: "/r",
      P42_PORTAL_CHECKPOINT_MAX_AGE_SECONDS: "300",
      P42_ATTESTATION_TRUST_REGISTRY_PATH: "/caller/registry.json",
      P42_ATTESTATION_TRUST_REGISTRY_SHA256: digest("f"),
    })).toEqual({
      deploymentManifestPath: "/m", indexerCheckpointPath: "/c",
      launchAuthorizationPath: "/a", indexerCheckpointAttestationPath: "/ca",
      fundingActivationPlanPath: "/p", fundingActivationSignaturesPath: "/fs", fundingActivationCompletionPath: "/fc",
      activationRpcOperatorRegistryPath: "/r/registry.json", activationRpcOperatorRegistryTrustedRoot: "/r",
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
    base.manifest.releaseEvidence = {
      boardSetDigest: digest("2"), releaseBindingDigest: digest("1"), capsuleDigest: digest("3"),
      slateDigest: digest("4"), releaseIndexDigest: digest("5"),
    };
    const fundingRoles = [
      ["production-launch-authority", "productionLaunchAuthority"],
      ["independent-security-authority", "independentSecurityAuthority"],
      ["governance-authority", "governanceAuthority"],
    ] as const;
    const fundingWallets = fundingRoles.map(() => Wallet.createRandom());
    fundingRoles.forEach(([, field], index) => { base.manifest.roles[field] = fundingWallets[index].address; });
    base.manifest.problems = manifestProblems;
    attachCompletedRolePacket(base.manifest, { fundingWallets });
    base.manifest.deploymentConfigHash = computePortalDeploymentConfigHash(base.manifest);
    base.checkpoint.manifestBinding.deploymentConfigHash = base.manifest.deploymentConfigHash;
    base.checkpoint.manifestBinding.boards = Object.fromEntries(manifestProblems.map((item) => [item.problemId, Object.fromEntries(boardKeys.map((key) => [key, { address: item.contracts[key].address, deployedCodeHash: item.contracts[key].deployedCodeHash, abiHash: item.contracts[key].abiHash }]))]));
    const expires = Number(base.checkpoint.range.toBlockTimestamp) + 1_000;
    const issuedAt = new Date((Number(base.checkpoint.range.toBlockTimestamp) - 1_000) * 1000).toISOString();
    const roles = ["production-launch-authority", "independent-security-authority", "governance-authority"];
    const signers = roles.map((role, index) => {
      const pair = generateKeyPairSync("ed25519");
      const raw = pair.publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("hex");
      return { role, index, privateKey: pair.privateKey, publicKey: `ed25519:${raw}` };
    });
    const rpcProfiles = [
      { operatorId: "operator-primary", endpointOrigin: "https://primary.example" },
      { operatorId: "operator-secondary", endpointOrigin: "https://secondary.example" },
    ].map((profile) => ({ ...profile, endpointProfileDigest: canonicalDigest(profile) }));
    const rpcRegistry = { schema: "p42-activation-rpc-operator-registry/v1", profiles: rpcProfiles };
    const rpcRegistryDigest = bytesDigest(rpcRegistry);
    const rpcAuthority = {
      schema: "p42-activation-rpc-authority/v1", registryDigest: rpcRegistryDigest,
      primary: rpcProfiles[0],
      secondary: rpcProfiles[1],
    };
    const observedRpcAuthority = {
      ...rpcAuthority,
      primary: { ...rpcAuthority.primary, observedRawChainId: "0x14a34" },
      secondary: { ...rpcAuthority.secondary, observedRawChainId: "0x14a34" },
    };
    const unsignedAuthorization = {
      schema_version: "p42-production-launch-authorization/v1", status: "authorized", issued_at_utc: issuedAt,
      expires_at_utc: new Date(expires * 1000).toISOString(), release_binding: { network: "base-sepolia", chain_id: 84532, git_commit: base.manifest.deploymentCommit },
      artifacts: { deployment_manifest: { sha256: bytesDigest(base.manifest) }, activation_rpc_operator_registry: { sha256: rpcRegistryDigest } },
      authorizers: signers.map(({ role, index, publicKey }) => ({ role, public_key: publicKey, name: `Signer ${index}`, organization: "P42 Test", professional_email: `signer${index}@example.org` })),
    };
    const authorizationDigest = canonicalDigest(unsignedAuthorization); const digestHex = `0x${authorizationDigest.slice(7)}`;
    base.checkpoint.boards = manifestProblems.map((item) => ({
      ...clone(templateBoard), problemId: item.problemId, problemSlug: item.problemSlug,
      onchain: { ...clone(templateBoard.onchain), poolAcceptingFunds: true, fundingArmed: true, authorizedFundingDigest: digestHex, fundingAuthorizationDigest: digestHex, fundingAuthorizationExpiresAt: String(expires) },
    }));
    base.checkpoint.schema = "p42-prizes/indexer-checkpoint/v4";
    const manifestBytes = Buffer.from(JSON.stringify(base.manifest));
    const authorization = { ...unsignedAuthorization, authorization_digest: authorizationDigest, authorization_signatures: signers.map(({ role, privateKey, publicKey }) => {
      const message = Buffer.from(`P42-ATTESTATION-V2\np42-production-launch-authorization/v1\n${role}\n${authorizationDigest}\n${issuedAt}`, "ascii");
      return { algorithm: "ed25519", signer_role: role, public_key: publicKey, signed_hash: authorizationDigest, signed_at_utc: issuedAt, signature: `ed25519:${sign(null, message, privateKey).toString("hex")}` };
    }) };
    const checkpointSigner = generateKeyPairSync("ed25519");
    const checkpointPublicKey = `ed25519:${checkpointSigner.publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("hex")}`;
    const checkpointSignedAt = new Date().toISOString();
    const trustRegistry = { schema_version: "p42-attestation-trust-registry/v1", environment: "production", registry_id: "portal-test", created_at_utc: "2026-01-01T00:00:00.000Z", registrations: [
      ...signers.map(({ role, index, publicKey }) => ({ attestation_class: "p42-production-launch-authorization/v1", signer_role: role, public_key: publicKey, identity: { name: `Signer ${index}`, organization: "P42 Test", professional_email: `signer${index}@example.org` }, valid_from_utc: new Date((expires - 2500) * 1000).toISOString(), valid_until_utc: null })),
      { attestation_class: "p42-indexer-checkpoint-attestation/v1", signer_role: "indexer-checkpoint-authority", public_key: checkpointPublicKey, identity: { name: "Indexer Signer", organization: "P42 Test", professional_email: "indexer@example.org" }, valid_from_utc: "2026-01-01T00:00:00.000Z", valid_until_utc: null },
    ] };
    const authorizationBytes = Buffer.from(JSON.stringify(authorization));
    const activationSignatures = {
      schema: "p42-funding-activation-signatures/v2", chainId: 84532,
      boardSetDigest: base.manifest.releaseEvidence.boardSetDigest,
      releaseBindingDigest: base.manifest.releaseEvidence.releaseBindingDigest,
      authorizationDigest, expiresAt: String(expires),
      authorities: Object.fromEntries(fundingRoles.map(([, field], index) => [field, fundingWallets[index].address])),
      boards: manifestProblems.map((item, boardIndex) => {
        const nonce = 0n;
        const common = {
          boardSetDigest: `0x${base.manifest.releaseEvidence.boardSetDigest.slice(7)}`,
          releaseBindingDigest: `0x${base.manifest.releaseEvidence.releaseBindingDigest.slice(7)}`,
          authorizationDigest: digestHex, expiresAt: BigInt(expires), nonce,
        };
        return {
          boardIndex, problemId: item.problemId, submissionManager: item.contracts.submissions.address, nonce: nonce.toString(),
          signatures: fundingRoles.map(([role], roleIndex) => ({
            role, signer: fundingWallets[roleIndex].address,
            signature: fundingWallets[roleIndex].signingKey.sign(TypedDataEncoder.hash(
              { name: "P42SubmissionManager", version: "2", chainId: 84532, verifyingContract: item.contracts.submissions.address },
              { FundingAuthorization: [
                { name: "role", type: "bytes32" }, { name: "boardSetDigest", type: "bytes32" },
                { name: "releaseBindingDigest", type: "bytes32" }, { name: "authorizationDigest", type: "bytes32" },
                { name: "expiresAt", type: "uint64" }, { name: "nonce", type: "uint256" },
              ] },
              { ...common, role: keccak256(toUtf8Bytes(role)) },
            )).serialized,
          })),
        };
      }),
    };
    const submissionsInterface = new Interface([
      "function authorizeFunding(bytes32 authorizationDigest,uint64 expiresAt,uint256 nonce,bytes[3] signatures)",
      "function armFunding(bytes32 authorizationDigest)",
    ]);
    const poolInterface = new Interface(["function setAcceptingFunds(bool accepting)"]);
    const authorizationLabels = manifestProblems.map((item) => `board.${item.problemId}.authorizeFunding`);
    const armLabels = manifestProblems.map((item) => `board.${item.problemId}.armFunding`);
    const activationOperations: any[] = [
      ...manifestProblems.map((item, boardIndex) => ({
        sequence: boardIndex + 1, authority: "treasury", label: authorizationLabels[boardIndex], boardIndex,
        problemId: item.problemId, to: getAddress(item.contracts.submissions.address), expectedRuntimeCodeHash: item.contracts.submissions.runtimeCodeHash,
        value: "0", authorizationNonce: "0", verifiedSignatureCount: 3,
        data: submissionsInterface.encodeFunctionData("authorizeFunding", [digestHex, expires, 0n, activationSignatures.boards[boardIndex].signatures.map((record) => record.signature)]), dependsOn: [],
      })),
      ...manifestProblems.map((item, boardIndex) => {
        const label = armLabels[boardIndex]; const to = getAddress(item.contracts.submissions.address);
        const data = submissionsInterface.encodeFunctionData("armFunding", [digestHex]);
        const salt = keccak256(toUtf8Bytes(`${authorizationDigest}:${label}`));
        return { sequence: boardIndex + 11, authority: "governance", label, boardIndex, problemId: item.problemId, to, expectedRuntimeCodeHash: item.contracts.submissions.runtimeCodeHash, value: "0", data, salt, operationId: keccak256(AbiCoder.defaultAbiCoder().encode(["address", "uint256", "bytes", "bytes32"], [to, 0n, data, salt])), dependsOn: authorizationLabels };
      }),
      ...manifestProblems.map((item, boardIndex) => {
        const label = `board.${item.problemId}.setAcceptingFunds`; const to = getAddress(item.contracts.pool.address);
        const data = poolInterface.encodeFunctionData("setAcceptingFunds", [true]);
        const salt = keccak256(toUtf8Bytes(`${authorizationDigest}:${label}`));
        return { sequence: boardIndex + 21, authority: "governance", label, boardIndex, problemId: item.problemId, to, expectedRuntimeCodeHash: item.contracts.pool.runtimeCodeHash, value: "0", data, salt, operationId: keccak256(AbiCoder.defaultAbiCoder().encode(["address", "uint256", "bytes", "bytes32"], [to, 0n, data, salt])), dependsOn: armLabels };
      }),
    ];
    const planBody = {
      schema: "p42-funding-activation-plan/v2", chainId: 84532, network: "base-sepolia",
      deploymentCommit: base.manifest.deploymentCommit, deploymentConfigHash: base.manifest.deploymentConfigHash,
      manifestBytesDigest: bytesDigest(base.manifest), releaseBindingDigest: base.manifest.releaseEvidence.releaseBindingDigest,
      capsuleDigest: base.manifest.releaseEvidence.capsuleDigest, slateDigest: base.manifest.releaseEvidence.slateDigest,
      releaseIndexDigest: base.manifest.releaseEvidence.releaseIndexDigest, authorizationDigest, authorizationExpiresAt: expires,
      authorizationBytesDigest: `sha256:${createHash("sha256").update(authorizationBytes).digest("hex")}`,
      dependencySecurityReportDigest: digest("8"),
      rpcAuthority,
      activationSignaturesDigest: canonicalDigest(activationSignatures), timelock: getAddress(base.manifest.contracts.timelock.address),
      timelockRuntimeCodeHash: base.manifest.contracts.timelock.runtimeCodeHash, treasury: getAddress(base.manifest.roles.treasury),
      governanceSigners: base.manifest.governance.signers.map(getAddress), governanceThreshold: Number(base.manifest.governance.threshold),
      governanceDelaySeconds: Number(base.manifest.governance.delaySeconds), governanceOperationGraceSeconds: Number(base.manifest.governance.operationGracePeriodSeconds),
      boardCount: 10, operations: activationOperations,
    };
    const plan = { ...planBody, planDigest: canonicalDigest(planBody) };
    (base.checkpoint as any).activationEvidence = {
      schema: "p42-funding-activation-checkpoint/v1",
      planDigest: plan.planDigest,
      finalizedBlockNumber: base.checkpoint.range.toBlock,
      finalizedBlockHash: base.checkpoint.range.toBlockHash,
      rpcAuthority: observedRpcAuthority,
      operations: activationOperations.slice(10).map((operation) => ({
        sequence: operation.sequence, label: operation.label, problemId: String(operation.problemId),
        operationId: operation.operationId, state: 2,
      })),
    };
    const completionBody = {
      schema: "p42-funding-activation-completion/v2", chainId: 84532, network: "base-sepolia", planDigest: plan.planDigest,
      manifestBytesDigest: plan.manifestBytesDigest, deploymentCommit: base.manifest.deploymentCommit,
      deploymentConfigHash: base.manifest.deploymentConfigHash, releaseBindingDigest: digest("1"),
      authorizationDigest, authorizationBytesDigest: planBody.authorizationBytesDigest, authorizationExpiresAt: expires,
      rpcAuthority: observedRpcAuthority,
      finalizedBlockNumber: base.checkpoint.range.toBlock - 5,
      finalizedBlockHash: hash("7"),
      finalizedBlockTimestamp: base.checkpoint.range.toBlockTimestamp - 60,
      boards: manifestProblems.map((item, index) => ({ problemId: item.problemId, pool: item.contracts.pool.address, submissionManager: item.contracts.submissions.address, poolRuntimeCodeHash: item.contracts.pool.runtimeCodeHash, authorizedFundingDigest: digestHex, fundingAuthorizationDigest: digestHex, fundingAuthorizationExpiresAt: expires, fundingArmed: true, acceptingFunds: true, armOperation: { operationId: activationOperations[index + 10].operationId, state: 2 }, openOperation: { operationId: activationOperations[index + 20].operationId, state: 2 } })),
    };
    const completion = { ...completionBody, completionDigest: canonicalDigest(completionBody) };
    (base.checkpoint as any).activationEvidence.completionAnchor = {
      completionDigest: completion.completionDigest,
      blockNumber: completion.finalizedBlockNumber,
      blockHash: completion.finalizedBlockHash,
      blockTimestamp: completion.finalizedBlockTimestamp,
    };
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
      authorization, authorizationBytes, productionPolicy, trustRegistry, checkpointAttestation, activationSignatures, plan, completion, rpcRegistry,
    };
    const withSignedCheckpoint = (mutate: (value: any) => void, signedAtSeconds?: number) => {
      const checkpoint = clone(base.checkpoint); mutate(checkpoint);
      const checkpointBytes = Buffer.from(JSON.stringify(checkpoint));
      const checkpointDigest = `sha256:${createHash("sha256").update(checkpointBytes).digest("hex")}`;
      const signedAtUtc = signedAtSeconds === undefined ? checkpointSignedAt : new Date(signedAtSeconds * 1000).toISOString();
      const message = Buffer.from(`P42-ATTESTATION-V2\np42-indexer-checkpoint-attestation/v1\nindexer-checkpoint-authority\n${checkpointDigest}\n${signedAtUtc}`, "ascii");
      const checkpointAttestation = {
        schema: "p42-indexer-checkpoint-attestation/v1", signerRole: "indexer-checkpoint-authority",
        publicKey: checkpointPublicKey, checkpointDigest, signedAtUtc,
        signature: `ed25519:${sign(null, message, checkpointSigner.privateKey).toString("hex")}`,
      };
      return { ...activatedArtifacts, checkpoint, checkpointBytes, checkpointAttestation };
    };
    const activatedSnapshot = activatedIndexerSnapshotFromArtifacts(launchProblems, activatedArtifacts);
    expect(activatedSnapshot.provenance).toHaveLength(10);
    expect(activatedSnapshot.highWaterIdentity).toEqual({
      checkpointDigest,
      releaseBindingDigest: base.manifest.releaseEvidence.releaseBindingDigest,
      authorizationDigest,
      chainId: base.manifest.network.chainId,
      chainName: base.manifest.network.name,
      deploymentCommit: base.manifest.deploymentCommit,
      deploymentConfigHash: base.manifest.deploymentConfigHash,
    });
    expect(activatedIndexerSnapshotFromArtifacts(launchProblems, {
      ...activatedArtifacts,
      nowSeconds: expires + 1,
      checkpointMaxAgeSeconds: 2_000,
    }).provenance).toHaveLength(10);

    const lateCompletion = clone(completion);
    lateCompletion.finalizedBlockTimestamp = expires + 1;
    const { completionDigest: _lateDigest, ...lateCompletionBody } = lateCompletion;
    lateCompletion.completionDigest = canonicalDigest(lateCompletionBody);
    const lateCheckpoint = withSignedCheckpoint((value) => {
      value.range.toBlockTimestamp = expires + 2;
      value.activationEvidence.completionAnchor.blockTimestamp = lateCompletion.finalizedBlockTimestamp;
      value.activationEvidence.completionAnchor.completionDigest = lateCompletion.completionDigest;
    }, expires + 2);
    expect(() => activatedIndexerSnapshotFromArtifacts(launchProblems, {
      ...lateCheckpoint,
      completion: lateCompletion,
      nowSeconds: expires + 2,
      checkpointMaxAgeSeconds: 300,
    })).toThrow();
    const substitutedRegistry = clone(rpcRegistry);
    substitutedRegistry.profiles[0].endpointOrigin = "https://substitute.example";
    substitutedRegistry.profiles[0].endpointProfileDigest = canonicalDigest({
      operatorId: substitutedRegistry.profiles[0].operatorId,
      endpointOrigin: substitutedRegistry.profiles[0].endpointOrigin,
    });
    expect(() => activatedIndexerSnapshotFromArtifacts(launchProblems, {
      ...activatedArtifacts, rpcRegistry: substitutedRegistry,
    })).toThrow();
    expect(() => activatedIndexerSnapshotFromArtifacts(launchProblems, withSignedCheckpoint((value) => {
      value.schema = "p42-prizes/indexer-checkpoint/v3"; delete value.activationEvidence;
    }))).toThrow();
    for (const mutate of [
      (value: any) => { value.activationEvidence.operations[0].operationId = hash("8"); },
      (value: any) => { value.activationEvidence.finalizedBlockNumber -= 1; },
      (value: any) => { value.activationEvidence.finalizedBlockHash = hash("8"); },
      (value: any) => { value.activationEvidence.completionAnchor.completionDigest = digest("8"); },
      (value: any) => { value.activationEvidence.completionAnchor.blockHash = hash("8"); },
      (value: any) => { value.activationEvidence.completionAnchor.blockNumber = value.range.toBlock + 1; },
      (value: any) => { [value.activationEvidence.operations[0], value.activationEvidence.operations[1]] = [value.activationEvidence.operations[1], value.activationEvidence.operations[0]]; },
      (value: any) => { value.activationEvidence.operations.pop(); },
      (value: any) => { value.activationEvidence.operations[1] = clone(value.activationEvidence.operations[0]); },
      (value: any) => { value.activationEvidence.operations[0].state = 1; },
    ]) {
      expect(() => activatedIndexerSnapshotFromArtifacts(launchProblems, withSignedCheckpoint(mutate))).toThrow();
    }
    const unsignedEvidenceTamper = clone(base.checkpoint);
    (unsignedEvidenceTamper as any).activationEvidence.operations[0].operationId = hash("8");
    expect(() => activatedIndexerSnapshotFromArtifacts(launchProblems, {
      ...activatedArtifacts, checkpoint: unsignedEvidenceTamper,
      checkpointBytes: Buffer.from(JSON.stringify(unsignedEvidenceTamper)),
    })).toThrow();
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
    for (const mutate of [
      (value: any) => { value.finalizedBlockNumber -= 1; },
      (value: any) => { value.finalizedBlockHash = hash("8"); },
      (value: any) => { value.finalizedBlockTimestamp -= 1; },
    ]) {
      const wrongAnchorCompletion = clone(completion); mutate(wrongAnchorCompletion);
      const { completionDigest: _digest, ...body } = wrongAnchorCompletion;
      wrongAnchorCompletion.completionDigest = canonicalDigest(body);
      expect(() => activatedIndexerSnapshotFromArtifacts(launchProblems, {
        ...activatedArtifacts, completion: wrongAnchorCompletion,
      })).toThrow();
    }
    const legacyCompletion = clone(completion);
    legacyCompletion.schema = "p42-funding-activation-completion/v1";
    const { completionDigest: _legacyCompletionDigest, ...legacyCompletionBody } = legacyCompletion;
    legacyCompletion.completionDigest = canonicalDigest(legacyCompletionBody);
    expect(() => activatedIndexerSnapshotFromArtifacts(launchProblems, {
      ...activatedArtifacts,
      completion: legacyCompletion,
    })).toThrow();
    for (const mutate of [
      (value: any) => { value.boards[0].armOperation.operationId = hash("8"); },
      (value: any) => { value.boards[0].openOperation.state = 1; },
    ]) {
      const substitutedCompletion = clone(completion);
      mutate(substitutedCompletion);
      const { completionDigest: _completionDigest, ...substitutedBody } = substitutedCompletion;
      substitutedCompletion.completionDigest = canonicalDigest(substitutedBody);
      expect(() => activatedIndexerSnapshotFromArtifacts(launchProblems, {
        ...activatedArtifacts,
        completion: substitutedCompletion,
      })).toThrow();
    }
    for (const mutate of [
      (value: any) => { value.operations[0].label = `prefix.${value.operations[0].label}`; },
      (value: any) => { value.operations[1] = { ...value.operations[0], sequence: 2, boardIndex: 1 }; },
      (value: any) => { value.operations[10].operationId = hash("8"); },
    ]) {
      const substitutedPlan = clone(plan); mutate(substitutedPlan);
      const { planDigest: _substitutedPlanDigest, ...substitutedPlanBody } = substitutedPlan;
      substitutedPlan.planDigest = canonicalDigest(substitutedPlanBody);
      const substitutedCompletion = clone(completion);
      substitutedCompletion.planDigest = substitutedPlan.planDigest;
      if (substitutedPlan.operations[10].operationId !== plan.operations[10].operationId) {
        substitutedCompletion.boards[0].armOperation.operationId = substitutedPlan.operations[10].operationId;
      }
      const { completionDigest: _substitutedCompletionDigest, ...substitutedCompletionBody } = substitutedCompletion;
      substitutedCompletion.completionDigest = canonicalDigest(substitutedCompletionBody);
      expect(() => activatedIndexerSnapshotFromArtifacts(launchProblems, {
        ...activatedArtifacts, plan: substitutedPlan, completion: substitutedCompletion,
      })).toThrow();
    }
    const substitutedSignatures = clone(activationSignatures);
    substitutedSignatures.boards[0].signatures[0].signature = substitutedSignatures.boards[1].signatures[0].signature;
    const resealedSignaturePlan = clone(plan);
    resealedSignaturePlan.activationSignaturesDigest = canonicalDigest(substitutedSignatures);
    const { planDigest: _resealedSignaturePlanDigest, ...resealedSignaturePlanBody } = resealedSignaturePlan;
    resealedSignaturePlan.planDigest = canonicalDigest(resealedSignaturePlanBody);
    const resealedSignatureCompletion = clone(completion);
    resealedSignatureCompletion.planDigest = resealedSignaturePlan.planDigest;
    const { completionDigest: _resealedSignatureCompletionDigest, ...resealedSignatureCompletionBody } = resealedSignatureCompletion;
    resealedSignatureCompletion.completionDigest = canonicalDigest(resealedSignatureCompletionBody);
    expect(() => activatedIndexerSnapshotFromArtifacts(launchProblems, {
      ...activatedArtifacts, activationSignatures: substitutedSignatures,
      plan: resealedSignaturePlan, completion: resealedSignatureCompletion,
    })).toThrow();
    const resealWireSignature = (replacement: string) => {
      const signatures = clone(activationSignatures);
      signatures.boards[0].signatures[0].signature = replacement;
      const substitutedPlan = clone(plan);
      substitutedPlan.activationSignaturesDigest = canonicalDigest(signatures);
      substitutedPlan.operations[0].data = submissionsInterface.encodeFunctionData("authorizeFunding", [
        digestHex, expires, 0n, signatures.boards[0].signatures.map((record: any) => record.signature),
      ]);
      const { planDigest: _planDigest, ...substitutedPlanBody } = substitutedPlan;
      substitutedPlan.planDigest = canonicalDigest(substitutedPlanBody);
      const substitutedCompletion = clone(completion);
      substitutedCompletion.planDigest = substitutedPlan.planDigest;
      const { completionDigest: _completionDigest, ...substitutedCompletionBody } = substitutedCompletion;
      substitutedCompletion.completionDigest = canonicalDigest(substitutedCompletionBody);
      return { signatures, substitutedPlan, substitutedCompletion };
    };
    const canonicalWireSignature = activationSignatures.boards[0].signatures[0].signature;
    const compact = resealWireSignature(Signature.from(canonicalWireSignature).compactSerialized);
    expect(() => activatedIndexerSnapshotFromArtifacts(launchProblems, {
      ...activatedArtifacts, activationSignatures: compact.signatures,
      plan: compact.substitutedPlan, completion: compact.substitutedCompletion,
    })).toThrow();
    const normalizedV = `${canonicalWireSignature.slice(0, -2)}${(
      Number.parseInt(canonicalWireSignature.slice(-2), 16) - 27
    ).toString(16).padStart(2, "0")}`;
    const normalized = resealWireSignature(normalizedV);
    expect(() => activatedIndexerSnapshotFromArtifacts(launchProblems, {
      ...activatedArtifacts, activationSignatures: normalized.signatures,
      plan: normalized.substitutedPlan, completion: normalized.substitutedCompletion,
    })).toThrow();
    expect(() => (activatedProvenanceFromArtifacts as any)(
      launchProblems[0], base.manifest, manifestBytes, base.checkpoint, checkpointBytes,
      authorization, authorizationBytes, productionPolicy, trustRegistry, checkpointAttestation,
      compact.signatures, compact.substitutedPlan, compact.substitutedCompletion,
      rpcRegistry, 300, undefined, compact.substitutedPlan,
    )).toThrow();
    const result = activatedProvenanceFromArtifacts(launchProblems[0], base.manifest, manifestBytes, base.checkpoint, checkpointBytes, authorization, authorizationBytes, productionPolicy, trustRegistry, checkpointAttestation, activationSignatures, plan, completion, rpcRegistry);
    expect(result).toMatchObject({ settlementState: "testnet-indexed", poolAddress: manifestProblems[0].pool, fundingAuthorizationDigest: authorizationDigest, activationFinalizedBlock: 95 });
    const subsetSums = activatedProvenanceFromArtifacts(launchProblems[6], base.manifest, manifestBytes, base.checkpoint, checkpointBytes, authorization, authorizationBytes, productionPolicy, trustRegistry, checkpointAttestation, activationSignatures, plan, completion, rpcRegistry);
    expect(subsetSums).toMatchObject({ settlementState: "testnet-indexed", poolAddress: manifestProblems[6].pool, problemRegistryId: "7" });
    for (const mutate of [
      (policy: any) => { policy.deployment_manifest.sha256 = digest("8"); },
      (policy: any) => { policy.launch_authorization.sha256 = digest("8"); },
      (policy: any) => { policy.launch_authorization.authorization_digest = digest("8"); },
      (policy: any) => { policy.trust_registry.sha256 = digest("8"); },
      (policy: any) => { policy.trust_registry.path = "/tmp/caller-registry.json"; },
    ]) {
      const changedPolicy = clone(productionPolicy); mutate(changedPolicy);
      expect(() => activatedProvenanceFromArtifacts(launchProblems[0], base.manifest, manifestBytes, base.checkpoint, checkpointBytes, authorization, authorizationBytes, changedPolicy, trustRegistry, checkpointAttestation, activationSignatures, plan, completion, rpcRegistry)).toThrow();
    }
    base.checkpoint.boards[0].onchain.fundingAuthorizationDigest = hash("9");
    expect(() => activatedProvenanceFromArtifacts(launchProblems[0], base.manifest, manifestBytes, base.checkpoint, checkpointBytes, authorization, authorizationBytes, productionPolicy, trustRegistry, checkpointAttestation, activationSignatures, plan, completion, rpcRegistry)).toThrow();
  }, 15_000);
});
